import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import AsyncMock, patch, MagicMock
import json

from app.server import app


class TestAuthEndpoints:
    """Test suite for authentication endpoints"""

    @pytest.fixture
    def client(self):
        """Test client fixture"""
        return TestClient(app)

    def test_register_user_success(self, client):
        """Test successful user registration"""
        user_data = {
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "phone_number": "+1234567890",
            "password": "SecurePass123!"
        }
        
        with patch('auth.services.AuthService.register_user') as mock_register:
            mock_register.return_value = {
                "success": True,
                "message": "User registered successfully",
                "data": {"user_id": 1}
            }
            
            response = client.post("/auth/register", json=user_data)
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "User registered successfully" in result["message"]

    def test_register_user_invalid_email(self, client):
        """Test user registration with invalid email"""
        user_data = {
            "email": "invalid-email",
            "first_name": "Test",
            "last_name": "User", 
            "phone_number": "+1234567890",
            "password": "SecurePass123!"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_register_user_weak_password(self, client):
        """Test user registration with weak password"""
        user_data = {
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "phone_number": "+1234567890", 
            "password": "weak"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_register_user_existing_email(self, client):
        """Test user registration with existing email"""
        user_data = {
            "email": "existing@example.com",
            "first_name": "Test",
            "last_name": "User",
            "phone_number": "+1234567890",
            "password": "SecurePass123!"
        }
        
        with patch('auth.services.AuthService.register_user') as mock_register:
            mock_register.side_effect = Exception("User already exists")
            
            response = client.post("/auth/register", json=user_data)
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_login_user_success(self, client):
        """Test successful user login"""
        login_data = {
            "username": "test@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('auth.services.AuthService.authenticate_and_create_tokens') as mock_auth:
            mock_auth.return_value = {
                "success": True,
                "message": "Login successful",
                "data": {
                    "access_token": "fake_access_token",
                    "refresh_token": "fake_refresh_token",
                    "token_type": "bearer"
                }
            }
            
            response = client.post("/auth/login", data=login_data)
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "access_token" in result["data"]
            assert "refresh_token" in result["data"]

    def test_login_user_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        login_data = {
            "username": "test@example.com",
            "password": "wrong_password"
        }
        
        with patch('auth.services.AuthService.authenticate_and_create_tokens') as mock_auth:
            mock_auth.side_effect = Exception("Invalid credentials")
            
            response = client.post("/auth/login", data=login_data)
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_refresh_token_success(self, client):
        """Test successful token refresh"""
        with patch('auth.services.AuthService.refresh_user_token') as mock_refresh:
            mock_refresh.return_value = {
                "success": True,
                "message": "Token refreshed successfully",
                "data": {
                    "access_token": "new_access_token",
                    "refresh_token": "same_refresh_token",
                    "token_type": "bearer"
                }
            }
            
            response = client.post("/auth/refresh?refresh_token=valid_refresh_token")
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "access_token" in result["data"]

    def test_refresh_token_invalid(self, client):
        """Test token refresh with invalid token"""
        with patch('auth.services.AuthService.refresh_user_token') as mock_refresh:
            mock_refresh.side_effect = Exception("Invalid token")
            
            response = client.post("/auth/refresh?refresh_token=invalid_token")
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_revoke_token_success(self, client):
        """Test successful token revocation"""
        with patch('auth.services.AuthService.revoke_user_token') as mock_revoke:
            mock_revoke.return_value = {
                "success": True,
                "message": "Token revoked successfully"
            }
            
            response = client.post("/auth/revoke?refresh_token=valid_refresh_token")
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "revoked successfully" in result["message"]
