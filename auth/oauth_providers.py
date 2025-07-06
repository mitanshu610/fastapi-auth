from abc import ABC, abstractmethod
from fastapi import Request
from authlib.integrations.starlette_client import OAuth

from config.settings import settings
from utils.custom_logger import logger

class OAuthProvider(ABC):
    """Abstract base class for OAuth providers."""

    name: str
    oauth: OAuth | None = None

    def __init__(self, name: str):
        self.name = name

    async def _get_oauth(self) -> OAuth:
        if not self.oauth:
            self.oauth = OAuth()
            self.register(self.oauth)
        return self.oauth

    @abstractmethod
    def register(self, oauth: OAuth) -> None:
        """Register provider with the OAuth client."""

    async def login(self, request: Request, callback_name: str):
        oauth = await self._get_oauth()
        redirect_uri = request.url_for(callback_name)
        return await getattr(oauth, self.name).authorize_redirect(request, redirect_uri)

    @abstractmethod
    async def callback(self, request: Request) -> dict:
        """Handle provider callback and return user info."""
        raise NotImplementedError


class GoogleOAuthProvider(OAuthProvider):
    def __init__(self):
        super().__init__("google")

    def register(self, oauth: OAuth) -> None:
        oauth.register(
            name="google",
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "email openid profile"},
        )

    async def callback(self, request: Request) -> dict:
        oauth = await self._get_oauth()
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")
        if not user_info:
            logger.error("Failed to retrieve user info from Google")
            return {}
        return {
            "email": user_info.get("email"),
            "first_name": user_info.get("given_name", ""),
            "last_name": user_info.get("family_name", ""),
        }


class MicrosoftOAuthProvider(OAuthProvider):
    def __init__(self):
        super().__init__("microsoft")

    def register(self, oauth: OAuth) -> None:
        oauth.register(
            name="microsoft",
            client_id=settings.microsoft_client_id,
            client_secret=settings.microsoft_client_secret,
            server_metadata_url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    async def callback(self, request: Request) -> dict:
        oauth = await self._get_oauth()
        token = await oauth.microsoft.authorize_access_token(request)
        user_info = token.get("userinfo")
        if not user_info:
            logger.error("Failed to retrieve user info from Microsoft")
            return {}
        return {
            "email": user_info.get("email"),
            "first_name": user_info.get("given_name", ""),
            "last_name": user_info.get("family_name", ""),
        }


class GithubOAuthProvider(OAuthProvider):
    def __init__(self):
        super().__init__("github")

    def register(self, oauth: OAuth) -> None:
        oauth.register(
            name="github",
            client_id=settings.github_client_id,
            client_secret=settings.github_client_secret,
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "user:email"},
        )

    async def callback(self, request: Request) -> dict:
        oauth = await self._get_oauth()
        token = await oauth.github.authorize_access_token(request)
        resp = await oauth.github.get("user", token=token)
        user_info = resp.json()
        if not user_info.get("email"):
            resp = await oauth.github.get("user/emails", token=token)
            emails = resp.json()
            primary = next((e["email"] for e in emails if e.get("primary")), None)
            user_info["email"] = primary
        if not user_info.get("email"):
            logger.error("Failed to retrieve email from GitHub")
            return {}
        name_parts = user_info.get("name", "").split(" ", 1)
        return {
            "email": user_info.get("email"),
            "first_name": name_parts[0] if name_parts else "",
            "last_name": name_parts[1] if len(name_parts) > 1 else "",
        }
