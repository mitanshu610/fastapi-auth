from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional, Dict
from utils.base_auth import BaseAuth

from authlib.integrations.starlette_client import OAuth
from db.redis_connection import RedisClient


class Settings(BaseSettings):
    app_env: str = "dev"
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    secret_key: str
    algorithm: str
    database_url: str
    auth_mode: str
    paseto_private_key: Optional[str] = None
    paseto_public_key: Optional[str] = None
    auth_instance: Optional[BaseAuth] = None
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    microsoft_client_id: Optional[str] = None
    microsoft_client_secret: Optional[str] = None
    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    
    oauth_google: Optional[OAuth] = None
    oauth_microsoft: Optional[OAuth] = None
    oauth_github: Optional[OAuth] = None
    redis_database_url: Optional[str] = None
    hinata_host: str = None
    email_provider: str = "netcore"
    smtp_from_email: str = "no-reply@gofynd.com"
    smtp_netcore: Optional[str] = None
    
    roles: Optional[Dict] = None
    
    redis_client: Optional[RedisClient] = None
    
    permissions: Optional[Dict] = None

    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() in {"prod", "production"}

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()
