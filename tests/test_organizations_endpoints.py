import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import AsyncMock, patch, MagicMock
import json

from app.server import app


class TestOrganizationsEndpoints:
    """Test suite for organizations endpoints"""

    @pytest.fixture
    def client(self):
        """Test client fixture"""
        with TestClient(app) as test_client:
            yield test_client

    @pytest.fixture
    def mock_auth_headers(self):
        """Mock authentication headers"""
        return {"Authorization": "Bearer fake_jwt_token"}

    def test_create_organization_success(self, client, mock_auth_headers):
        """Test successful organization creation"""
        org_data = {
            "name": "Test Organization"
        }
        
        with patch('organizations.services.OrganizationService.create_organization') as mock_create:
            mock_create.return_value = {
                "success": True,
                "message": "Organization created successfully",
                "data": {
                    "id": 1,
                    "name": "Test Organization",
                    "creation_date": 1640995200
                }
            }
            
            response = client.post(
                "/rbac/organizations/", 
                json=org_data,
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["name"] == "Test Organization"

    def test_create_organization_missing_name(self, client, mock_auth_headers):
        """Test organization creation with missing name"""
        org_data = {}
        
        response = client.post(
            "/rbac/organizations/", 
            json=org_data,
            headers=mock_auth_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_organization_unauthorized(self, client):
        """Test organization creation without authentication"""
        org_data = {"name": "Test Organization"}
        
        response = client.post("/rbac/organizations/", json=org_data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_organization_by_id_success(self, client, mock_auth_headers):
        """Test successful retrieval of organization by ID"""
        organization_id = 1
        
        with patch('organizations.services.OrganizationService.get_organization_by_id') as mock_get:
            mock_get.return_value = {
                "success": True,
                "data": {
                    "id": 1,
                    "name": "Test Organization",
                    "creation_date": 1640995200
                }
            }
            
            response = client.get(
                f"/rbac/organizations/{organization_id}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["id"] == organization_id

    def test_get_organization_by_id_not_found(self, client, mock_auth_headers):
        """Test retrieval of non-existent organization"""
        organization_id = 999
        
        with patch('organizations.services.OrganizationService.get_organization_by_id') as mock_get:
            mock_get.side_effect = Exception("Organization not found")
            
            response = client.get(
                f"/rbac/organizations/{organization_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_update_organization_success(self, client, mock_auth_headers):
        """Test successful organization update"""
        organization_id = 1
        update_data = {
            "name": "Updated Organization",
            "description": "Updated description"
        }
        
        with patch('organizations.services.OrganizationService.update_organization') as mock_update:
            mock_update.return_value = {
                "success": True,
                "message": "Organization updated successfully",
                "data": {
                    "id": 1,
                    "name": "Updated Organization",
                    "creation_date": 1640995200
                }
            }
            
            response = client.put(
                f"/rbac/organizations/{organization_id}",
                json=update_data,
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["name"] == "Updated Organization"

    def test_update_organization_not_found(self, client, mock_auth_headers):
        """Test update of non-existent organization"""
        organization_id = 999
        update_data = {"name": "Updated Organization"}
        
        with patch('organizations.services.OrganizationService.update_organization') as mock_update:
            mock_update.side_effect = Exception("Organization not found")
            
            response = client.put(
                f"/rbac/organizations/{organization_id}",
                json=update_data,
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_get_user_organizations_success(self, client, mock_auth_headers):
        """Test successful retrieval of user's organizations"""
        with patch('organizations.services.OrganizationService.get_user_organizations') as mock_get:
            mock_get.return_value = {
                "success": True,
                "data": [
                    {
                        "id": 1,
                        "organization": {
                            "id": 1,
                            "name": "Org 1",
                            "creation_date": 1640995200
                        },
                        "user": {
                            "email": "test@example.com",
                            "first_name": "Test",
                            "last_name": "User",
                            "phone_number": "+1234567890"
                        },
                        "role": {
                            "id": 1,
                            "name": "Admin"
                        }
                    }
                ]
            }
            
            response = client.get(
                "/rbac/organizations/my-organizations",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert len(result["data"]) == 1

    def test_get_organization_members_success(self, client, mock_auth_headers):
        """Test successful retrieval of organization members"""
        organization_id = 1
        
        with patch('organizations.services.OrganizationService.get_organization_members') as mock_get:
            mock_get.return_value = {
                "success": True,
                "data": [
                    {
                        "id": 1,
                        "user": {
                            "email": "user1@example.com",
                            "first_name": "User",
                            "last_name": "One",
                            "phone_number": "+1234567890"
                        },
                        "role": {
                            "id": 1,
                            "name": "Admin"
                        }
                    },
                    {
                        "id": 2,
                        "user": {
                            "email": "user2@example.com",
                            "first_name": "User",
                            "last_name": "Two",
                            "phone_number": "+0987654321"
                        },
                        "role": {
                            "id": 2,
                            "name": "Member"
                        }
                    }
                ]
            }
            
            response = client.get(
                f"/rbac/organizations/{organization_id}/members",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert len(result["data"]) == 2

    def test_assign_user_to_organization_success(self, client, mock_auth_headers):
        """Test successful user assignment to organization"""
        organization_id = 1
        assign_data = {
            "user_email": "newuser@example.com",
            "role_id": 2
        }
        
        with patch('organizations.services.OrganizationService.assign_user_to_organization') as mock_assign:
            mock_assign.return_value = {
                "success": True,
                "message": "User assigned to organization successfully",
                "data": {
                    "id": 3,
                    "organization": {
                        "id": 1,
                        "name": "Test Organization"
                    },
                    "user": {
                        "email": "newuser@example.com",
                        "first_name": "New",
                        "last_name": "User"
                    },
                    "role": {
                        "id": 2,
                        "name": "Member"
                    }
                }
            }
            
            response = client.post(
                f"/rbac/organizations/{organization_id}/members",
                json=assign_data,
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["user"]["email"] == "newuser@example.com"

    def test_assign_user_to_organization_invalid_email(self, client, mock_auth_headers):
        """Test user assignment with invalid email"""
        organization_id = 1
        assign_data = {
            "user_email": "invalid-email",
            "role_id": 2
        }
        
        response = client.post(
            f"/rbac/organizations/{organization_id}/members",
            json=assign_data,
            headers=mock_auth_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_assign_user_to_organization_user_not_found(self, client, mock_auth_headers):
        """Test user assignment with non-existent user"""
        organization_id = 1
        assign_data = {
            "user_email": "nonexistent@example.com",
            "role_id": 2
        }
        
        with patch('organizations.services.OrganizationService.assign_user_to_organization') as mock_assign:
            mock_assign.side_effect = Exception("User not found")
            
            response = client.post(
                f"/rbac/organizations/{organization_id}/members",
                json=assign_data,
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_remove_user_from_organization_success(self, client, mock_auth_headers):
        """Test successful user removal from organization"""
        organization_id = 1
        user_id = 2
        
        with patch('organizations.services.OrganizationService.remove_user_from_organization') as mock_remove:
            mock_remove.return_value = {
                "success": True,
                "message": "User removed from organization successfully"
            }
            
            response = client.delete(
                f"/rbac/organizations/{organization_id}/members/{user_id}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "removed" in result["message"]

    def test_remove_user_from_organization_not_found(self, client, mock_auth_headers):
        """Test removal of user not in organization"""
        organization_id = 1
        user_id = 999
        
        with patch('organizations.services.OrganizationService.remove_user_from_organization') as mock_remove:
            mock_remove.side_effect = Exception("User not found in organization")
            
            response = client.delete(
                f"/rbac/organizations/{organization_id}/members/{user_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_organization_endpoints_without_auth(self, client):
        """Test that all organization endpoints require authentication"""
        endpoints = [
            ("GET", "/rbac/organizations/1"),
            ("PUT", "/rbac/organizations/1"),
            ("GET", "/rbac/organizations/my-organizations"),
            ("GET", "/rbac/organizations/1/members"),
            ("POST", "/rbac/organizations/1/members"),
            ("DELETE", "/rbac/organizations/1/members/1")
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
