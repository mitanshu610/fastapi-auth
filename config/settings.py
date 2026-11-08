from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional, Dict
from utils.base_auth import BaseAuth

from db.redis_connection import RedisClient


class Settings(BaseSettings):
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    secret_key: str
    algorithm: str
    database_url: str
    auth_mode: str
    paseto_private_key: Optional[str] = None
    paseto_public_key: Optional[str] = None
    auth_instance: Optional[BaseAuth] = None
    redis_database_url: Optional[str] = None
    
    roles: Optional[Dict] = None
    
    redis_client: Optional[RedisClient] = None
    
    permissions: Optional[Dict] = None

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()
