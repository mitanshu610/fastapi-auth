from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from jose import jwt
from sqlalchemy import select
from config.settings import settings
from utils.custom_logger import logger
from auth.models import RefreshToken, TokenType, User
from sqlalchemy.ext.asyncio import AsyncSession
from utils.base_auth import BaseAuth
from context.services import ContextService

class JWTAuth(BaseAuth):
    async def create_access_token(self, data: dict, expires_delta: timedelta):
        """
        Creates a JSON Web Token (JWT) for access control.

        Parameters:
        - data (dict): A dictionary containing the payload data to be encoded in the token.
        - expires_delta (timedelta): A timedelta object representing the duration until the token expires.

        Returns:
        - str: The encoded JWT as a string.

        Raises:
        - jwt.exceptions.PyJWTError: If there is an error in encoding the JWT.
        """
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire.isoformat()})
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
        return encoded_jwt

    async def create_context_enriched_token(
        self, 
        user_email: str,
        db: AsyncSession,
        expires_delta: timedelta,
        active_organization_id: Optional[int] = None,
        active_team_id: Optional[int] = None,
        custom_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Creates a JWT access token enriched with user's current context (active org/team).

        Parameters:
        - user_email (str): User's email address
        - db (AsyncSession): Database session for querying user context
        - expires_delta (timedelta): Token expiration duration
        - active_organization_id (int, optional): ID of the active organization
        - active_team_id (int, optional): ID of the active team
        - custom_claims (dict, optional): Additional custom claims

        Returns:
        - str: The encoded JWT as a string.
        """
        context_service = ContextService(db)
        
        # Create enriched payload with context
        payload_data = await context_service.create_context_enriched_payload(
            user_email=user_email,
            active_organization_id=active_organization_id,
            active_team_id=active_team_id,
            custom_claims=custom_claims
        )
        
        # Add expiration
        expire = datetime.now(timezone.utc) + expires_delta
        payload_data.update({"exp": expire.isoformat()})
        
        encoded_jwt = jwt.encode(payload_data, settings.secret_key, algorithm=settings.algorithm)
        return encoded_jwt

    async def create_refresh_token(self, data: dict, expires_delta: timedelta, db: AsyncSession):
        """
        Creates a new refresh token and stores it in the database.

        Parameters:
        - data (dict): A dictionary containing the payload for the token, typically including user information.
        - expires_delta (timedelta): The duration after which the token will expire.
        - db (AsyncSession): The asynchronous database session used to commit the new token to the database.

        Returns:
        - str: The encoded JWT refresh token.

        Raises:
        - jwt.PyJWTError: If there is an error encoding the JWT token.
        - sqlalchemy.exc.SQLAlchemyError: If there is an error committing the token to the database.
        """
        expire = datetime.now(timezone.utc) + expires_delta
        token = jwt.encode(data, settings.secret_key, algorithm=settings.algorithm)
        user_id = await db.scalar(select(User.id).where(User.email == data["sub"]))
        if user_id is None:
            raise ValueError("Cannot store a refresh token for an unknown user")

        db_refresh_token = RefreshToken(
            user_id=user_id,
            token=token,
            token_type=TokenType(settings.auth_mode),
            nonce=None,
            # The existing PostgreSQL column is TIMESTAMP WITHOUT TIME ZONE;
            # store UTC as a naive timestamp to match its schema.
            expires_at=expire.replace(tzinfo=None),
            revoked=False
        )
        db.add(db_refresh_token)
        await db.commit()
        return token

    async def verify_token(self, token: str):
        """
        Verifies a JWT token and returns its payload if valid.

        Parameters:
        token (str): The JWT token to be verified.

        Returns:
        dict or None: Returns the payload of the token as a dictionary if the token is valid and not expired.
                      Returns None if the token is invalid or expired.

        Raises:
        jwt.JWTError: If there is an error decoding the token.
        """
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
            if "exp" in payload:
                exp = datetime.fromisoformat(payload["exp"])
                if exp < datetime.now(timezone.utc):
                    logger.error("Token has expired.")
                    return None
            return payload
        except jwt.JWTError:
            return None
