from fastapi import APIRouter

from auth.views import (
    register_user, login_user, refresh_token, revoke_token
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# User authentication routes
router.add_api_route("/register", endpoint=register_user, methods=["POST"])
router.add_api_route("/login", endpoint=login_user, methods=["POST"])
router.add_api_route("/refresh", endpoint=refresh_token, methods=["POST"])
router.add_api_route("/revoke", endpoint=revoke_token, methods=["POST"])
