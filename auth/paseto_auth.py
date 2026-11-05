import json
import secrets
from datetime import timedelta, datetime, timezone
from typing import Dict, Any, Optional
from pyseto import Key, encode, decode
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import settings
from utils.custom_logger import logger
from auth.models import RefreshToken, TokenType, User
from utils.base_auth import BaseAuth
from context.services import ContextService

class PasetoAuth(BaseAuth):
    async def create_access_token(self, data: dict, expires_delta: timedelta):
        """
        Asynchronously creates an access token using the PASETO (Platform-Agnostic Security Tokens) standard.

        Parameters:
        - data (dict): A dictionary containing the payload data to be included in the token.
        - expires_delta (timedelta): A timedelta object representing the duration after which the token will expire.

        Returns:
        - str: A string representing the encoded access token.

        Raises:
        - Any exceptions related to key creation or token encoding will be propagated.
        """
        key = Key.new(version=2, key=settings.paseto_private_key, type="public")
        expire = datetime.now(timezone.utc) + expires_delta
        data.update({"exp": expire.isoformat()})
        token = encode(key, json.dumps(data)).decode('utf-8')
        return token

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
        Creates a PASETO access token enriched with user's current context (active org/team).

        Parameters:
        - user_email (str): User's email address
        - db (AsyncSession): Database session for querying user context
        - expires_delta (timedelta): Token expiration duration
        - active_organization_id (int, optional): ID of the active organization
        - active_team_id (int, optional): ID of the active team
        - custom_claims (dict, optional): Additional custom claims

        Returns:
        - str: The encoded PASETO token as a string.
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
        
        key = Key.new(version=2, key=settings.paseto_private_key, type="public")
        token = encode(key, json.dumps(payload_data)).decode('utf-8')
        return token

    async def create_refresh_token(self, data: dict, expires_delta: timedelta, db: AsyncSession):
        """
        Asynchronously creates a refresh token for a user and stores it in the database.

        Parameters:
        - data (dict): A dictionary containing user data, including the subject ('sub') which is the user's email.
        - expires_delta (timedelta): The time duration after which the token will expire.
        - db (AsyncSession): The asynchronous database session used to add and commit the refresh token.

        Returns:
        - str: The generated refresh token as a string.

        Raises:
        - Any exceptions related to database operations or encoding issues may be raised during the execution.
        """
        key = Key.new(version=2, type="public", key=settings.paseto_private_key)
        nonce = secrets.token_hex(32)
        data.update({"nonce": nonce})
        token = encode(key, json.dumps(data)).decode('utf-8')
        user_id = await db.scalar(select(User.id).where(User.email == data["sub"]))
        if user_id is None:
            raise ValueError("Cannot store a refresh token for an unknown user")

        db_refresh_token = RefreshToken(
            user_id=user_id,
            token=token,
            token_type=TokenType(settings.auth_mode),
            nonce=nonce,
            expires_at=(datetime.now(timezone.utc) + expires_delta).replace(tzinfo=None),
            revoked=False
        )
        db.add(db_refresh_token)
        await db.commit()
        return token

    async def verify_token(self, token: str):
        """
        Verifies a given token using a public key and checks its expiration.

        Parameters:
        - token (str): The token string that needs to be verified.

        Returns:
        - dict: A dictionary containing the decoded payload if the token is valid and not expired.
        - None: If the token is invalid or expired.

        Raises:
        - Exception: Logs an error and returns None if token verification fails for any reason.
        """
        try:
            key = Key.new(version=2, type="public", key=settings.paseto_public_key)
            payload = decode(key, token)
            payload_json = json.loads(payload.payload.decode('utf-8'))
            if "exp" in payload_json:
                exp = datetime.fromisoformat(payload_json["exp"])
                if exp < datetime.now(timezone.utc):
                    logger.error("Token has expired.")
                    return None
            return payload_json
        except Exception:
            logger.error(f"Token verification for {settings.auth_mode} failed!")
            return None
