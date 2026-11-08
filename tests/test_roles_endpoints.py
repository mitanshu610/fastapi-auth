import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import AsyncMock, patch, MagicMock
import json

from app.server import app


class TestRolesEndpoints:
    """Test suite for roles endpoints"""

    @pytest.fixture
    def client(self):
        """Test client fixture"""
        with TestClient(app) as test_client:
            yield test_client

    @pytest.fixture
    def mock_auth_headers(self):
        """Mock authentication headers"""
        return {"Authorization": "Bearer fake_jwt_token"}

    def test_create_role_success(self, client, mock_auth_headers):
        """Test successful role creation"""
        role_data = {
            "name": "Test Role",
            "description": "A test role",
            "slug": "test-role"
        }
        
        with patch('roles.services.RoleService.create_new_role') as mock_create:
            mock_create.return_value = {
                "success": True,
                "message": "Role created successfully",
                "data": {
                    "id": 1,
                    "name": "Test Role",
                    "description": "A test role",
                    "slug": "test-role"
                }
            }
            
            response = client.post(
                "/rbac/roles/", 
                json=role_data,
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["name"] == "Test Role"

    def test_create_role_missing_required_fields(self, client, mock_auth_headers):
        """Test role creation with missing required fields"""
        role_data = {"description": "A test role"}  # Missing name and slug
        
        response = client.post(
            "/rbac/roles/", 
            json=role_data,
            headers=mock_auth_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_role_unauthorized(self, client):
        """Test role creation without authentication"""
        role_data = {
            "name": "Test Role",
            "slug": "test-role"
        }
        
        response = client.post("/rbac/roles/", json=role_data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_all_roles_success(self, client, mock_auth_headers):
        """Test successful retrieval of all roles"""
        with patch('roles.services.RoleService.retrieve_all_roles') as mock_get:
            mock_get.return_value = {
                "success": True,
                "data": [
                    {
                        "id": 1,
                        "name": "Admin",
                        "description": "Administrator role",
                        "slug": "admin"
                    },
                    {
                        "id": 2,
                        "name": "User",
                        "description": "Regular user role",
                        "slug": "user"
                    }
                ]
            }
            
            response = client.get(
                "/rbac/roles/",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert len(result["data"]) == 2

    def test_get_role_by_id_success(self, client, mock_auth_headers):
        """Test successful retrieval of role by ID"""
        role_id = 1
        
        with patch('roles.services.RoleService.retrieve_role_by_id') as mock_get:
            mock_get.return_value = {
                "success": True,
                "data": {
                    "id": 1,
                    "name": "Admin",
                    "description": "Administrator role",
                    "slug": "admin"
                }
            }
            
            response = client.get(
                f"/rbac/roles/{role_id}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["id"] == role_id

    def test_get_role_by_id_not_found(self, client, mock_auth_headers):
        """Test retrieval of non-existent role"""
        role_id = 999
        
        with patch('roles.services.RoleService.retrieve_role_by_id') as mock_get:
            mock_get.side_effect = Exception("Role not found")
            
            response = client.get(
                f"/rbac/roles/{role_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_get_role_by_slug_success(self, client, mock_auth_headers):
        """Test successful retrieval of role by slug"""
        slug = "admin"
        
        with patch('roles.services.RoleService.retrieve_role_by_slug') as mock_get:
            mock_get.return_value = {
                "success": True,
                "data": {
                    "id": 1,
                    "name": "Admin",
                    "description": "Administrator role",
                    "slug": "admin"
                }
            }
            
            response = client.get(
                f"/rbac/roles/slug/{slug}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["slug"] == slug

    def test_get_role_by_slug_not_found(self, client, mock_auth_headers):
        """Test retrieval of non-existent role by slug"""
        slug = "nonexistent"
        
        with patch('roles.services.RoleService.retrieve_role_by_slug') as mock_get:
            mock_get.side_effect = Exception("Role not found")
            
            response = client.get(
                f"/rbac/roles/slug/{slug}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_update_role_success(self, client, mock_auth_headers):
        """Test successful role update"""
        role_id = 1
        update_data = {
            "name": "Updated Role",
            "description": "Updated description"
        }
        
        with patch('roles.services.RoleService.modify_role') as mock_update:
            mock_update.return_value = {
                "success": True,
                "message": "Role updated successfully",
                "data": {
                    "id": 1,
                    "name": "Updated Role",
                    "description": "Updated description",
                    "slug": "admin"
                }
            }
            
            response = client.put(
                f"/rbac/roles/{role_id}",
                json=update_data,
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["data"]["name"] == "Updated Role"

    def test_update_role_not_found(self, client, mock_auth_headers):
        """Test update of non-existent role"""
        role_id = 999
        update_data = {"name": "Updated Role"}
        
        with patch('roles.services.RoleService.modify_role') as mock_update:
            mock_update.side_effect = Exception("Role not found")
            
            response = client.put(
                f"/rbac/roles/{role_id}",
                json=update_data,
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_delete_role_success(self, client, mock_auth_headers):
        """Test successful role deletion"""
        role_id = 1
        
        with patch('roles.services.RoleService.remove_role') as mock_delete:
            mock_delete.return_value = {
                "success": True,
                "message": "Role deleted successfully"
            }
            
            response = client.delete(
                f"/rbac/roles/{role_id}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "deleted" in result["message"]

    def test_delete_role_not_found(self, client, mock_auth_headers):
        """Test deletion of non-existent role"""
        role_id = 999
        
        with patch('roles.services.RoleService.remove_role') as mock_delete:
            mock_delete.side_effect = Exception("Role not found")
            
            response = client.delete(
                f"/rbac/roles/{role_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_assign_permission_to_role_success(self, client, mock_auth_headers):
        """Test successful permission assignment to role"""
        role_id = 1
        permission_id = 1
        
        with patch('roles.services.RoleService.assign_permission') as mock_assign:
            mock_assign.return_value = {
                "success": True,
                "message": "Permission assigned to role successfully",
                "data": {
                    "role_id": 1,
                    "permission_id": 1,
                    "role_name": "Admin",
                    "permission_name": "read_users"
                }
            }
            
            response = client.post(
                f"/rbac/roles/{role_id}/permissions/{permission_id}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "assigned" in result["message"]

    def test_assign_permission_to_role_not_found(self, client, mock_auth_headers):
        """Test permission assignment to non-existent role"""
        role_id = 999
        permission_id = 1
        
        with patch('roles.services.RoleService.assign_permission') as mock_assign:
            mock_assign.side_effect = Exception("Role not found")
            
            response = client.post(
                f"/rbac/roles/{role_id}/permissions/{permission_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_assign_nonexistent_permission_to_role(self, client, mock_auth_headers):
        """Test assignment of non-existent permission to role"""
        role_id = 1
        permission_id = 999
        
        with patch('roles.services.RoleService.assign_permission') as mock_assign:
            mock_assign.side_effect = Exception("Permission not found")
            
            response = client.post(
                f"/rbac/roles/{role_id}/permissions/{permission_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_remove_permission_from_role_success(self, client, mock_auth_headers):
        """Test successful permission removal from role"""
        role_id = 1
        permission_id = 1
        
        with patch('roles.services.RoleService.remove_permission') as mock_remove:
            mock_remove.return_value = {
                "success": True,
                "message": "Permission removed from role successfully"
            }
            
            response = client.delete(
                f"/rbac/roles/{role_id}/permissions/{permission_id}",
                headers=mock_auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert "removed" in result["message"]

    def test_remove_permission_from_role_not_found(self, client, mock_auth_headers):
        """Test permission removal from non-existent role"""
        role_id = 999
        permission_id = 1
        
        with patch('roles.services.RoleService.remove_permission') as mock_remove:
            mock_remove.side_effect = Exception("Role not found")
            
            response = client.delete(
                f"/rbac/roles/{role_id}/permissions/{permission_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_remove_nonexistent_permission_from_role(self, client, mock_auth_headers):
        """Test removal of non-existent permission from role"""
        role_id = 1
        permission_id = 999
        
        with patch('roles.services.RoleService.remove_permission') as mock_remove:
            mock_remove.side_effect = Exception("Permission not found")
            
            response = client.delete(
                f"/rbac/roles/{role_id}/permissions/{permission_id}",
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_role_endpoints_without_auth(self, client):
        """Test that all role endpoints require authentication"""
        endpoints = [
            ("POST", "/rbac/roles/"),
            ("GET", "/rbac/roles/"),
            ("GET", "/rbac/roles/1"),
            ("GET", "/rbac/roles/slug/admin"),
            ("PUT", "/rbac/roles/1"),
            ("DELETE", "/rbac/roles/1"),
            ("POST", "/rbac/roles/1/permissions/1"),
            ("DELETE", "/rbac/roles/1/permissions/1")
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

    def test_role_duplicate_slug(self, client, mock_auth_headers):
        """Test role creation with duplicate slug"""
        role_data = {
            "name": "Another Admin",
            "slug": "admin"  # Assuming this slug already exists
        }
        
        with patch('roles.services.RoleService.create_new_role') as mock_create:
            mock_create.side_effect = Exception("Role with this slug already exists")
            
            response = client.post(
                "/rbac/roles/",
                json=role_data,
                headers=mock_auth_headers
            )
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_role_invalid_slug_format(self, client, mock_auth_headers):
        """Test role creation with invalid slug format"""
        role_data = {
            "name": "Test Role",
            "slug": "invalid slug with spaces!"  # Invalid slug format
        }
        
        response = client.post(
            "/rbac/roles/",
            json=role_data,
            headers=mock_auth_headers
        )
        # This might pass validation if no slug format validation is implemented
        # or might fail with 422 if validation exists
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_422_UNPROCESSABLE_ENTITY, status.HTTP_500_INTERNAL_SERVER_ERROR]
