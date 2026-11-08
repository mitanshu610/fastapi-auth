from fastapi import Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from auth.models import User
from auth.services import AuthService
from auth.schemas import UserCreate
from db.pg_connection import get_db
from auth.dependencies import get_redis_client
from db.redis_connection import RedisClient


def get_auth_service(
    redis_client: RedisClient = Depends(get_redis_client),
    db: AsyncSession = Depends(get_db)
) -> AuthService:
    return AuthService(db=db, redis_client=redis_client)


async def register_user(
    user: UserCreate,
    code: Optional[str] = None,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register new user"""
    result = await auth_service.register_user(user, code)
    return result


async def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Authenticate user and return tokens"""
    result = await auth_service.authenticate_and_create_tokens(form_data)
    return result


async def refresh_token(
    refresh_token: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh access token"""
    result = await auth_service.refresh_user_token(refresh_token)
    return result


async def revoke_token(
    refresh_token: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Revoke refresh token"""
    result = await auth_service.revoke_user_token(refresh_token)
    return result
