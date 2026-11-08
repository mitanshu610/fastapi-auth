import json
from typing import Optional
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta, timezone
from jose import jwt, JWTError
from datetime import datetime
from pydantic import ValidationError

from config.settings import settings
from auth.models import RefreshToken
from auth.schemas import UserCreate, UserRead
from auth.utils import get_password_hash, authenticate_user
from auth.dao import AuthDAO
from organizations.dao import OrganizationDAO
from utils.custom_logger import logger
from db.redis_connection import RedisClient
from utils.serializers import ResponseData
from utils.exceptions import (
    NotFoundError, ValidationError as CustomValidationError, UnauthorizedError, 
    ConflictError, InternalServerError
)


class AuthService:
    """Facade service for authentication operations containing all business logic"""
    
    def __init__(self, db: AsyncSession, redis_client: RedisClient):
        self.db = db
        self.auth_dao = AuthDAO(db=db)
        self.org_dao = OrganizationDAO(db=db)
        self.redis_client = redis_client

    async def register_user(self, user: UserCreate, code: Optional[str]):
        """Complete user registration process with business logic"""
        try:
            # Check if user already exists
            existing_user = await self.auth_dao.get_user_by_email(user.email)
            if existing_user:
                logger.warning(f"User registration attempt with existing email: {user.email}")
                raise ConflictError("User with this email already exists", "USER_EXISTS")

            # Local-password registration does not depend on an email delivery service.
            hashed_password = await get_password_hash(user.password)

            # Create user data
            user_data = {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "hashed_password": hashed_password,
                "verified": True,
                "phone_number": user.phone_number
            }

            # Create user
            db_user = await self.auth_dao.create_user(user_data)
            
            if code:
                # Handle organization invitation
                try:
                    redis_code_value = await self.redis_client.get("invitation_email:" + code)
                    if not redis_code_value:
                        raise NotFoundError("Invalid invitation code", "INVALID_INVITATION")
                    
                    json_object = json.loads(redis_code_value)
                    result = await self.org_dao.add_user_to_organization(json_object.organization_id, db_user.id, json_object.role_id)
                    
                    return ResponseData(
                        success=True,
                        message="User registered and added to organization successfully",
                        data=result
                    ).model_dump()
                except Exception as e:
                    logger.error(f"Organization invitation processing error: {str(e)}")
                    raise InternalServerError("Failed to process organization invitation", "INVITATION_PROCESSING_ERROR")

            logger.info(f"User {db_user.email} registered successfully.")
            return ResponseData(
                success=True,
                message="User registered successfully.",
                data=UserRead.model_validate(db_user)
            ).model_dump()

        except ValidationError as e:
            logger.error(f"Validation error during registration: {e.errors()}")
            await self.db.rollback()
            raise CustomValidationError(f"Validation failed: {e.errors()}", "VALIDATION_ERROR")
        except Exception as e:
            await self.db.rollback()
            if not isinstance(e, (ConflictError, NotFoundError, CustomValidationError, InternalServerError)):
                logger.error(f"Unexpected error during user registration: {str(e)}")
                raise InternalServerError("User registration failed", "REGISTRATION_ERROR")
            raise

    async def authenticate_and_create_tokens(self, form_data: OAuth2PasswordRequestForm):
        """Authenticate user and create access/refresh tokens"""
        try:
            user = await authenticate_user(self.auth_dao.db, form_data.username, form_data.password)
            if not user:
                logger.warning(f"Failed login attempt for email: {form_data.username}")
                raise UnauthorizedError("Invalid email or password", "INVALID_CREDENTIALS")
            
            # Create tokens
            access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
            access_token = await settings.auth_instance.create_access_token(
                data={"sub": form_data.username}, expires_delta=access_token_expires
            )
            refresh_token_expires = timedelta(days=settings.refresh_token_expire_days)
            refresh_token = await settings.auth_instance.create_refresh_token(
                data={"sub": form_data.username}, expires_delta=refresh_token_expires, db=self.auth_dao.db
            )
            
            logger.info(f"User {form_data.username} logged in successfully.")
            
            return ResponseData(
                success=True,
                message="Login successful",
                data={
                    "access_token": access_token, 
                    "refresh_token": refresh_token, 
                    "token_type": "bearer"
                }
            ).model_dump()
            
        except UnauthorizedError:
            await self.db.rollback()
            raise
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Token creation error: {str(e)}")
            raise InternalServerError("Authentication service temporarily unavailable", "TOKEN_CREATION_ERROR")

    async def refresh_user_token(self, refresh_token: str):
        """Refresh user access token using refresh token"""
        try:
            payload = jwt.decode(refresh_token, settings.secret_key, algorithms=[settings.algorithm])
            username: str = payload.get("sub")
            if username is None:
                logger.warning("Token refresh attempt with invalid payload")
                raise UnauthorizedError("Invalid token payload", "INVALID_TOKEN_PAYLOAD")
        except JWTError:
            logger.warning("Token refresh attempt with invalid JWT")
            raise UnauthorizedError("Invalid or expired token", "INVALID_JWT")

        # Validate refresh token
        db_refresh_token = await self.auth_dao.get_refresh_token(refresh_token)
        if not db_refresh_token or db_refresh_token.expires_at < datetime.now(timezone.utc):
            logger.warning(f"Token refresh attempt with expired token for user: {username}")
            raise UnauthorizedError("Refresh token has expired", "EXPIRED_TOKEN")

        try:
            # Generate new access token
            access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
            access_token = await settings.auth_instance.create_access_token(
                data={"sub": username}, expires_delta=access_token_expires
            )

            logger.info(f"Access token refreshed for user {username}.")
            
            return ResponseData(
                success=True,
                message="Token refreshed successfully",
                data={
                    "access_token": access_token, 
                    "refresh_token": refresh_token, 
                    "token_type": "bearer"
                }
            ).model_dump()
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Token refresh error: {str(e)}")
            raise InternalServerError("Token refresh failed", "TOKEN_REFRESH_ERROR")

    async def revoke_user_token(self, refresh_token: str):
        """Revoke user refresh token"""
        try:
            success = await self.auth_dao.delete_refresh_token(refresh_token)
            if success:
                logger.info("Refresh token revoked successfully.")
                return ResponseData(
                    success=True,
                    message="Token revoked successfully"
                ).model_dump()
            else:
                logger.warning("Token revocation attempt with non-existent token")
                raise NotFoundError("Token not found", "TOKEN_NOT_FOUND")
        except NotFoundError:
            await self.db.rollback()
            raise
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Token revocation error: {str(e)}")
            raise InternalServerError("Token revocation failed", "TOKEN_REVOCATION_ERROR")
