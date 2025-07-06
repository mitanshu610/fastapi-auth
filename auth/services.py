import json
from typing import Optional
from fastapi import Request, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta, timezone
from jose import jwt, JWTError
from datetime import datetime
from sqlalchemy import update
from pydantic import ValidationError
from authlib.integrations.starlette_client import OAuth
from auth.oauth_providers import (
    GoogleOAuthProvider,
    MicrosoftOAuthProvider,
    GithubOAuthProvider,
)

google_provider = GoogleOAuthProvider()
microsoft_provider = MicrosoftOAuthProvider()
github_provider = GithubOAuthProvider()

from config.settings import settings
from auth.models import User, RefreshToken, AuthType
from auth.schemas import UserCreate, UserRead, Token
from auth.utils import get_password_hash, authenticate_user, send_email_verification, send_forgot_password_email
from auth.dao import AuthDAO
from organizations.dao import OrganizationDAO
from utils.custom_logger import logger
from db.redis_connection import RedisClient
from utils.serializers import ResponseData
from utils.exceptions import (
    NotFoundError, ValidationError as CustomValidationError, UnauthorizedError, 
    ConflictError, InternalServerError, DatabaseError
)


class AuthService:
    """Facade service for authentication operations containing all business logic"""
    
    def __init__(self, db: AsyncSession, redis_client: RedisClient):
        self.db = db
        self.auth_dao = AuthDAO(db=db)
        self.org_dao = OrganizationDAO(db=db)
        self.redis_client = redis_client

    @staticmethod
    async def handle_microsoft_login(request: Request):
        """Handle Microsoft OAuth login with business logic"""
        try:
            return await microsoft_provider.login(request, 'microsoft_auth_callback')
        except Exception as e:
            logger.error(f"Microsoft OAuth setup error: {str(e)}")
            raise InternalServerError("Microsoft OAuth service is temporarily unavailable", "OAUTH_SETUP_ERROR")

    @staticmethod
    async def handle_google_login(request: Request):
        """Handle Google OAuth login with business logic"""
        try:
            return await google_provider.login(request, 'google_auth_callback')
        except Exception as e:
            logger.error(f"Google OAuth setup error: {str(e)}")
            raise InternalServerError("Google OAuth service is temporarily unavailable", "OAUTH_SETUP_ERROR")

    @staticmethod
    async def handle_github_login(request: Request):
        """Handle GitHub OAuth login with business logic"""
        try:
            return await github_provider.login(request, 'github_callback')
        except Exception as e:
            logger.error(f"GitHub OAuth setup error: {str(e)}")
            raise InternalServerError("GitHub OAuth service is temporarily unavailable", "OAUTH_SETUP_ERROR")

    async def register_user(self, user: UserCreate, background_tasks: BackgroundTasks, code: Optional[str]):
        """Complete user registration process with business logic"""
        try:
            # Check if user already exists
            existing_user = await self.auth_dao.get_user_by_email(user.email)
            if existing_user:
                logger.warning(f"User registration attempt with existing email: {user.email}")
                raise ConflictError("User with this email already exists", "USER_EXISTS")

            # Hash password and determine verification status
            hashed_password = await get_password_hash(user.password)
            verification_required = not bool(code)

            # Create user data
            user_data = {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "hashed_password": hashed_password,
                "verified": not verification_required,
                "phone_number": user.phone_number
            }

            # Create user
            db_user = await self.auth_dao.create_user(user_data)
            
            if not code:
                # Send verification email
                background_tasks.add_task(
                    send_email_verification,
                    redis_client=self.redis_client,
                    email=db_user.email,
                    first_name=db_user.first_name,
                    title="email_verification"
                )
                logger.info(f"User {db_user.email} registered successfully. Verification email sent.")
                
                return ResponseData(
                    success=True,
                    message="User registered successfully. Please check your email for verification link.",
                    data=UserRead.model_validate(db_user)
                ).model_dump()
            else:
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

    async def handle_google_callback(self, request: Request):
        """Handle Google OAuth callback with user creation/authentication logic"""
        try:
            user_info = await google_provider.callback(request)

            if not user_info or not user_info.get('email'):
                raise UnauthorizedError("Failed to retrieve user information from Google", "OAUTH_USER_INFO_ERROR")

            email = user_info['email']
            first_name = user_info.get('first_name', '')
            last_name = user_info.get('last_name', '')
            
            # Get or create user
            user_in_db = await self.auth_dao.get_user_by_email(email)
            if not user_in_db:
                user_data = {
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "verified": True,
                    "auth_type": AuthType.GOOGLE
                }
                user_in_db = await self.auth_dao.create_user(user_data)
                logger.info(f"New user created via Google OAuth: {email}")
            
            # Generate tokens
            tokens = await self._create_oauth_tokens(email)
            
            return ResponseData(
                success=True,
                message="Google authentication successful",
                data=tokens
            ).model_dump()
            
        except (UnauthorizedError, InternalServerError):
            await self.db.rollback()
            raise
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Google OAuth callback error: {str(e)}")
            raise InternalServerError("Google authentication failed", "GOOGLE_OAUTH_ERROR")

    async def handle_microsoft_callback(self, request: Request):
        """Handle Microsoft OAuth callback with user creation/authentication logic"""
        try:
            user_info = await microsoft_provider.callback(request)

            if not user_info or not user_info.get('email'):
                raise UnauthorizedError("Failed to retrieve user information from Microsoft", "OAUTH_USER_INFO_ERROR")

            email = user_info['email']
            first_name = user_info.get('first_name', '')
            last_name = user_info.get('last_name', '')
            
            # Get or create user
            user_in_db = await self.auth_dao.get_user_by_email(email)
            if not user_in_db:
                user_data = {
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "verified": True,
                    "auth_type": AuthType.MICROSOFT
                }
                user_in_db = await self.auth_dao.create_user(user_data)
                logger.info(f"New user created via Microsoft OAuth: {email}")
            
            # Generate tokens
            tokens = await self._create_oauth_tokens(email)
            
            return ResponseData(
                success=True,
                message="Microsoft authentication successful",
                data=tokens
            ).model_dump()
            
        except (UnauthorizedError, InternalServerError):
            await self.db.rollback()
            raise
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Microsoft OAuth callback error: {str(e)}")
            raise InternalServerError("Microsoft authentication failed", "MICROSOFT_OAUTH_ERROR")

    async def handle_github_callback(self, request: Request):
        """Handle GitHub OAuth callback with user creation/authentication logic"""
        try:
            user_info = await github_provider.callback(request)

            if not user_info or not user_info.get('email'):
                raise UnauthorizedError("Failed to retrieve email from GitHub", "GITHUB_EMAIL_ERROR")

            email = user_info['email']
            first_name = user_info.get('first_name', '')
            last_name = user_info.get('last_name', '')
            
            # Get or create user
            user_in_db = await self.auth_dao.get_user_by_email(email)
            if not user_in_db:
                user_data = {
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "verified": True,
                    "auth_type": AuthType.GITHUB
                }
                user_in_db = await self.auth_dao.create_user(user_data)
                logger.info(f"New user created via GitHub OAuth: {email}")
            
            # Generate tokens
            tokens = await self._create_oauth_tokens(email)
            
            return ResponseData(
                success=True,
                message="GitHub authentication successful",
                data=tokens
            ).model_dump()
            
        except (UnauthorizedError, InternalServerError):
            raise
        except Exception as e:
            logger.error(f"GitHub OAuth callback error: {str(e)}")
            raise InternalServerError("GitHub authentication failed", "GITHUB_OAUTH_ERROR")

    async def verify_user_email(self, code: str):
        """Verify user email with business logic"""
        try:
            redis_code_value = await self.redis_client.get("email_verification:" + code)
            if not redis_code_value:
                logger.warning(f"Email verification attempt with invalid code: {code}")
                raise UnauthorizedError("Invalid or expired verification code", "INVALID_VERIFICATION_CODE")
            
            json_object = json.loads(redis_code_value)
            email = json_object.get("email")
            
            if not email:
                raise InternalServerError("Invalid verification data", "VERIFICATION_DATA_ERROR")
            
            # Update user verification status
            success = await self.auth_dao.update_user_verification_status(email, True)
            if not success:
                raise NotFoundError("User not found", "USER_NOT_FOUND")
            
            # Delete the verification code from Redis
            await self.redis_client.delete("email_verification:" + code)
            
            logger.info(f"Email {email} verified successfully.")
            
            return ResponseData(
                success=True,
                message="Email verified successfully"
            ).model_dump()
            
        except (UnauthorizedError, NotFoundError, InternalServerError):
            raise
        except Exception as e:
            logger.error(f"Email verification error: {str(e)}")
            raise InternalServerError("Email verification failed", "EMAIL_VERIFICATION_ERROR")

    async def initiate_password_reset(self, user_id: int, background_tasks: BackgroundTasks):
        """Initiate password reset process"""
        try:
            user = await self.auth_dao.get_user_by_id(user_id)
            if not user:
                logger.warning(f"Password reset attempt for non-existent email: {user_id}")
                raise NotFoundError("User with this email does not exist", "USER_NOT_FOUND")
            
            background_tasks.add_task(
                send_forgot_password_email,
                redis_client=self.redis_client,
                email=user.email,
                first_name=user.first_name,
                title="forgot_password"
            )
            
            logger.info(f"Password reset email sent to {user_id}.")
            
            return ResponseData(
                success=True,
                message="Password reset email sent successfully"
            ).model_dump()
            
        except NotFoundError:
            raise
        except Exception as e:
            logger.error(f"Password reset initiation error: {str(e)}")
            raise InternalServerError("Failed to initiate password reset", "PASSWORD_RESET_INITIATION_ERROR")

    async def reset_user_password(self, code: str, new_password: str):
        """Reset user password with business logic"""
        try:
            redis_code_value = await self.redis_client.get("forgot_password:" + code)
            if not redis_code_value:
                logger.warning(f"Password reset attempt with invalid code: {code}")
                raise UnauthorizedError("Invalid or expired reset code", "INVALID_RESET_CODE")
            
            json_object = json.loads(redis_code_value)
            email = json_object.get("email")
            
            if not email:
                raise InternalServerError("Invalid reset data", "RESET_DATA_ERROR")
            
            # Hash the new password
            hashed_password = await get_password_hash(new_password)
            
            # Update user password
            success = await self.auth_dao.update_user_password(email, hashed_password)
            if not success:
                raise NotFoundError("User not found", "USER_NOT_FOUND")
            
            # Delete the reset code from Redis
            await self.redis_client.delete("forgot_password:" + code)
            
            logger.info(f"Password reset successfully for {email}.")
            
            return ResponseData(
                success=True,
                message="Password reset successfully"
            ).model_dump()
            
        except (UnauthorizedError, NotFoundError, InternalServerError):
            raise
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            raise InternalServerError("Password reset failed", "PASSWORD_RESET_ERROR")

    async def _create_oauth_tokens(self, email: str):
        """Helper method to create OAuth tokens"""
        try:
            access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
            access_token = await settings.auth_instance.create_access_token(
                data={"sub": email}, expires_delta=access_token_expires
            )
            refresh_token_expires = timedelta(days=settings.refresh_token_expire_days)
            refresh_token = await settings.auth_instance.create_refresh_token(
                data={"sub": email}, expires_delta=refresh_token_expires, db=self.auth_dao.db
            )
            
            return {
                "access_token": access_token, 
                "refresh_token": refresh_token, 
                "token_type": "bearer"
            }
        except Exception as e:
            logger.error(f"OAuth token creation error: {str(e)}")
            raise InternalServerError("Failed to create authentication tokens", "OAUTH_TOKEN_ERROR") 