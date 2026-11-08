import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import AsyncMock, patch, MagicMock
import json

from app.server import app


class TestTeamsEndpoints:
    """Test suite for teams endpoints"""

    @pytest.fixture
    def client(self):
        """Test client fixture"""
        with TestClient(app) as test_client:
            yield test_client

    @pytest.fixture
    def mock_auth_headers(self):
        """Mock authentication headers"""
        return {"Authorization": "Bearer fake_jwt_token"}

    def test_create_team_success(self, client, mock_auth_headers):
        """Test successful team creation"""
        team_data = {
            "name": "Test Team",
            "description": "A test team",
            "organization_id": 1
        }
        
        with patch('teams.services.TeamService.create_team') as mock_create:
            mock_create.return_value = {
                "success": True,
                "message": "Team created successfully",
                "data": {
                    "id": 1,
                    "name": "Test Team",
                    "description": "A test team",
                    "organization": {
                        "id": 1,
                        "name": "Test Organization",
                        "creation_date": 1640995200
                    }
                }
            }
            
            response = client.post(
                "/rbac/teams/", 
                json=team_data,
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["name"] == "Test Team"

    def test_create_team_missing_required_fields(self, client, mock_auth_headers):
        """Test team creation with missing required fields"""
        team_data = {"description": "A test team"}  # Missing name and organization_id
        
        response = client.post(
            "/rbac/teams/", 
            json=team_data,
            headers=mock_auth_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_team_unauthorized(self, client):
        """Test team creation without authentication"""
        team_data = {
            "name": "Test Team",
            "organization_id": 1
        }
        
        response = client.post("/rbac/teams/", json=team_data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_assign_user_to_team_success(self, client, mock_auth_headers):
        """Test successful user assignment to team"""
        team_id = 1
        assign_data = {
            "user_email": "newuser@example.com",
            "role_id": 2
        }
        
        with patch('teams.services.TeamService.assign_user_to_team') as mock_assign:
            mock_assign.return_value = {
                "success": True,
                "message": "User assigned to team successfully",
                "data": {
                    "id": 3,
                    "team": {
                        "id": 1,
                        "name": "Test Team"
                    },
                    "user": {
                        "email": "newuser@example.com",
                        "first_name": "New",
                        "last_name": "User"
                    },
                    "role": {
                        "id": 2,
                        "name": "Team Member"
                    }
                }
            }
            
            response = client.post(
                f"/rbac/teams/{team_id}/members",
                json=assign_data,
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["user"]["email"] == "newuser@example.com"

    def test_assign_user_to_team_invalid_email(self, client, mock_auth_headers):
        """Test user assignment with invalid email"""
        team_id = 1
        assign_data = {
            "user_email": "invalid-email",
            "role_id": 2
        }
        
        response = client.post(
            f"/rbac/teams/{team_id}/members",
            json=assign_data,
            headers=mock_auth_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_assign_user_to_team_user_not_found(self, client, mock_auth_headers):
        """Test user assignment with non-existent user"""
        team_id = 1
        assign_data = {
            "user_email": "nonexistent@example.com",
            "role_id": 2
        }
        
        with patch('teams.services.TeamService.assign_user_to_team') as mock_assign:
            mock_assign.side_effect = Exception("User not found")
            
            response = client.post(
                f"/rbac/teams/{team_id}/members",
                json=assign_data,
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_remove_user_from_team_success(self, client, mock_auth_headers):
        """Test successful user removal from team"""
        team_id = 1
        user_email = "user@example.com"
        
        with patch('teams.services.TeamService.remove_user_from_team') as mock_remove:
            mock_remove.return_value = {
                "success": True,
                "message": "User removed from team successfully"
            }
            
            response = client.delete(
                f"/rbac/teams/{team_id}/members/{user_email}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "removed" in result["message"]

    def test_remove_user_from_team_not_found(self, client, mock_auth_headers):
        """Test removal of user not in team"""
        team_id = 1
        user_email = "nonexistent@example.com"
        
        with patch('teams.services.TeamService.remove_user_from_team') as mock_remove:
            mock_remove.side_effect = Exception("User not found in team")
            
            response = client.delete(
                f"/rbac/teams/{team_id}/members/{user_email}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_team_endpoints_without_auth(self, client):
        """Test that all team endpoints require authentication"""
        endpoints = [
            ("POST", "/rbac/teams/"),
            ("GET", "/rbac/teams/1"),
            ("PUT", "/rbac/teams/1"),
            ("DELETE", "/rbac/teams/1"),
            ("GET", "/rbac/teams/my-teams"),
            ("GET", "/rbac/teams/organization/1"),
            ("GET", "/rbac/teams/1/members"),
            ("POST", "/rbac/teams/1/members"),
            ("DELETE", "/rbac/teams/1/members/test@example.com")
        ]
        
        for method, endpoint in endpoints:
            if method == "GET":
                response = client.get(endpoint)
            elif method == "POST":
                response = client.post(endpoint, json={})
            elif method == "PUT":
                response = client.put(endpoint, json={})
            elif method == "DELETE":
                response = client.delete(endpoint)
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
