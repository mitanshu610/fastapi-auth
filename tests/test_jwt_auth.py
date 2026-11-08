from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

from auth.jwt_auth import JWTAuth
from config.settings import settings


@pytest.mark.asyncio
async def test_created_access_token_round_trips_with_numeric_expiration():
    auth = JWTAuth()

    token = await auth.create_access_token(
        data={"sub": "reviewer@example.com"},
        expires_delta=timedelta(minutes=5),
    )

    payload = await auth.verify_token(token)

    assert payload is not None
    assert payload["sub"] == "reviewer@example.com"
    assert isinstance(payload["exp"], int)


@pytest.mark.asyncio
async def test_verifies_unexpired_legacy_iso_expiration():
    auth = JWTAuth()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    token = jwt.encode(
        {"sub": "reviewer@example.com", "exp": expires_at.isoformat()},
        settings.secret_key,
        algorithm=settings.algorithm,
    )

    payload = await auth.verify_token(token)

    assert payload is not None
    assert payload["sub"] == "reviewer@example.com"


@pytest.mark.asyncio
async def test_rejects_expired_jwt():
    auth = JWTAuth()
    token = jwt.encode(
        {"sub": "reviewer@example.com", "exp": int(datetime.now(timezone.utc).timestamp()) - 1},
        settings.secret_key,
        algorithm=settings.algorithm,
    )

    assert await auth.verify_token(token) is None
