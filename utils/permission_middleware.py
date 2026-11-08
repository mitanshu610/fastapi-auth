from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from auth.dependencies import get_current_user, oauth2_scheme
from organizations.models import OrganizationUser
from teams.models import TeamMember
from utils.custom_logger import logger
from config.settings import settings

from collections import defaultdict

from sqlalchemy.orm import Session
from roles.models import Role
from permissions.models import Permission, RolePermission
from db.pg_connection import get_db

def get_effective_permissions(role: str, scope: str) -> dict:
    """
    Get the effective permissions for a role, including inherited permissions.
    Handles wildcard routes for roles like Admin or Super Admin.
    Uses cached permissions for better performance.
    """
    try:
        # Use cache utility function for consistency
        from utils.permission_cache import get_user_permissions
        
        # Get permissions from cache
        permissions = get_user_permissions(role, scope)
        
        # If permissions found in cache, return them
        if permissions:
            logger.debug(f"Retrieved effective permissions for role {role}, scope {scope} from cache")
            return permissions
        
        # Fallback to original logic if cache is empty
        logger.warning(f"Cache miss for role {role}, scope {scope}, using fallback permissions")
        
        permissions = {}
        current_role = role

        while current_role:
            role_data = settings.permissions.get(scope, {}).get(current_role)
            if role_data:
                # Check for wildcard permissions
                if "*" in role_data["routes"]:
                    # Add wildcard routes with all HTTP methods
                    permissions["*"] = set(role_data["routes"]["*"])
                
                # Merge current role's permissions for specific routes
                for route, methods in role_data["routes"].items():
                    if route != "*":  # Skip wildcard during normal route addition
                        permissions.setdefault(route, set()).update(methods)
                
                # Move to inherited role
                current_role = role_data["inherits"]
            else:
                break

        # Convert sets to lists for final output
        return {route: list(methods) for route, methods in permissions.items()}
        
    except Exception as e:
        logger.error(f"Error getting effective permissions for role {role}, scope {scope}: {e}")
        return {}

def get_permissions_from_cache() -> dict:
    """
    Get permissions from the cached dictionary instead of making database calls.
    """
    if not settings.permissions:
        logger.warning("Permissions cache is empty. Consider calling build_permissions() or refresh_permissions_cache()")
        return {}
    return settings.permissions

def get_role_permissions_from_cache(role_name: str, scope: str) -> dict:
    """
    Get specific role permissions from cache for a given scope.
    
    Args:
        role_name: Name of the role (e.g., 'Admin', 'Member')
        scope: Permission scope (e.g., 'organization', 'team')
    
    Returns:
        Dictionary containing role permissions or empty dict if not found
    """
    permissions = get_permissions_from_cache()
    return permissions.get(scope, {}).get(role_name, {})

async def refresh_permissions_cache():
    """
    Refresh the permissions cache by reloading from database.
    This can be called when permissions are updated without restarting the application.
    """
    logger.info("Refreshing permissions cache from database...")
    await build_permissions()
    logger.info("Permissions cache refreshed successfully")

def clear_permissions_cache():
    """
    Clear the permissions cache. Useful for testing or forced reload scenarios.
    """
    settings.permissions = {}
    logger.info("Permissions cache cleared")

class PermissionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if "/auth" in request.url.path or "/docs" in request.url.path:
                return await call_next(request)
        try:
            # Extract database session
            db: AsyncSession = request.state.db

            # Resolve the bearer token as FastAPI would for a route dependency.
            # Calling get_current_user(request) directly passes the Request object
            # as its token argument and fails during token verification.
            token = await oauth2_scheme(request)
            current_user = await get_current_user(token=token, db=db)

            # Parse endpoint, HTTP method, and identify scope/context
            endpoint = request.url.path
            method = request.method
            scope, context_id = self.get_scope_and_context(endpoint)

            # Get user's role in the current context
            role = await self.get_user_role_in_context(current_user.id, scope, context_id, db)

            # Resolve effective permissions for the role
            effective_permissions = get_effective_permissions(role, scope)

            # Check if the user has access to the route and method
            if endpoint not in effective_permissions or method not in effective_permissions[endpoint]:
                raise HTTPException(status_code=403, detail="Permission denied")

            # Proceed with the request
            response = await call_next(request)
            return response

        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
        except Exception as e:
            logger.error(f"Middleware error: {e}")
            return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    async def get_user_role_in_context(self, user_id: int, scope: str, context_id: int, db: AsyncSession) -> str:
        """
        Fetch the user's role in the specified context (organization or team).
        """
        if scope == "organization":
            org_user = await db.execute(
                select(OrganizationUser).where(
                    OrganizationUser.user_id == user_id, OrganizationUser.organization_id == context_id
                )
            )
            org_user = org_user.scalars().first()
            if not org_user:
                raise HTTPException(status_code=403, detail="User not part of the organization")
            return org_user.role.name

        elif scope == "team":
            team_member = await db.execute(
                select(TeamMember).where(
                    TeamMember.user_id == user_id, TeamMember.team_id == context_id
                )
            )
            team_member = team_member.scalars().first()
            if not team_member:
                raise HTTPException(status_code=403, detail="User not part of the team")
            return team_member.role.name

        raise HTTPException(status_code=400, detail="Invalid scope")

    def get_scope_and_context(self, endpoint: str) -> tuple:
        """
        Determine the scope (organization/team) and context ID (e.g., org_id, team_id) based on the endpoint.
        """
        if "/rbac/teams" in endpoint:
            return "team", self.extract_context_id_from_endpoint(endpoint, "teams")
        elif "/organizations" in endpoint:
            return "organization", self.extract_context_id_from_endpoint(endpoint, "organizations")
        raise HTTPException(status_code=403, detail="Invalid endpoint or insufficient scope")

    @staticmethod
    def extract_context_id_from_endpoint(endpoint: str, context_type: str) -> int:
        """
        Extract context ID (organization or team) from the endpoint.
        """
        import re
        match = re.search(f"/{context_type}/(\d+)", endpoint)
        if match:
            return int(match.group(1))
        raise HTTPException(status_code=400, detail=f"{context_type.capitalize()} ID not found in the endpoint")
    
    
async def initialize_roles():
    """
    Fetch roles from the database and store them in a global dictionary on server startup.
    """
    db_gen = get_db()
    db = await anext(db_gen)
    try:
        result = await db.execute(select(Role))
        roles = result.scalars().all()
        settings.roles = [
            {
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "scope": role.scope,
            }
            for role in roles
        ]
    finally:
        await db.close()

async def build_permissions():
    """
    Build permissions from database and cache them in settings.
    This replaces the hardcoded permissions with dynamic database-driven permissions.
    """
    db_gen = get_db()
    db = await anext(db_gen)
    try:
        # Get all roles with their permissions
        result = await db.execute(
            select(Role, Permission, RolePermission)
            .join(RolePermission, Role.id == RolePermission.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
        )
        
        role_permission_data = result.fetchall()
        
        # Build permissions structure
        permissions_dict = defaultdict(lambda: defaultdict(lambda: {"routes": {}, "inherits": None}))
        
        for role, permission, role_permission in role_permission_data:
            scope = role.scope
            role_name = role.name
            
            # Parse permission name to extract route and methods
            # Assuming permission names follow pattern like "teams:create:POST" or "teams:view:GET"
            permission_parts = permission.name.split(":")
            if len(permission_parts) >= 3:
                resource = permission_parts[0]
                action = permission_parts[1]
                methods = permission_parts[2].split(",") if "," in permission_parts[2] else [permission_parts[2]]
                
                # Construct route path
                route = f"/rbac/{resource}"
                if action != "view":  # view is typically GET on base route
                    route += f"/{action}"
                
                # Add methods to role permissions
                if route not in permissions_dict[scope][role_name]["routes"]:
                    permissions_dict[scope][role_name]["routes"][route] = []
                
                for method in methods:
                    if method.upper() not in permissions_dict[scope][role_name]["routes"][route]:
                        permissions_dict[scope][role_name]["routes"][route].append(method.upper())
            
            # Handle special super admin case
            elif permission.name == "super_admin" or role.name == "super_admin":
                permissions_dict["super_admin"]["routes"]["*"] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        
        # Convert defaultdict to regular dict for JSON serialization
        settings.permissions = {
            scope: {
                role: dict(role_data) for role, role_data in roles.items()
            } for scope, roles in permissions_dict.items()
        }
        
        # Add fallback hardcoded permissions if no database permissions found
        if not settings.permissions:
            logger.warning("No permissions found in database, using fallback hardcoded permissions")
            settings.permissions = {
                "organization": {
                    "Admin": {
                        "routes": {
                            "/rbac/teams/create": ["POST"],
                            "/rbac/teams/assign-user": ["POST"],
                            "/rbac/teams/remove-user": ["DELETE"],
                            "/rbac/teams": ["GET"]
                        },
                        "inherits": None,
                    },
                    "Member": {
                        "routes": {
                            "/rbac/teams": ["GET"]
                        },
                        "inherits": None,
                    },
                },
                "team": {
                    "Lead": {
                        "routes": {
                            "/rbac/teams/assign-user": ["POST"],
                            "/rbac/teams/remove-user": ["DELETE"],
                            "/rbac/teams": ["GET"]
                        },
                        "inherits": None,
                    },
                    "Team_Member": {
                        "routes": {
                            "/rbac/teams": ["GET"]
                        },
                        "inherits": None
                    },
                },
                "super_admin": {
                    "routes": {
                        "*": ["GET", "POST", "PUT", "DELETE", "PATCH"]
                    },
                    "inherits": None
                }
            }
        
        logger.info(f"Permissions cache built successfully with {len(settings.permissions)} scopes")
        
    except Exception as e:
        logger.error(f"Error building permissions from database: {str(e)}")
        # Fallback to hardcoded permissions on error
        settings.permissions = {
            "organization": {
                "Admin": {
                    "routes": {
                        "/rbac/teams/create": ["POST"],
                        "/rbac/teams/assign-user": ["POST"],
                        "/rbac/teams/remove-user": ["DELETE"],
                        "/rbac/teams": ["GET"]
                    },
                    "inherits": None,
                },
                "Member": {
                    "routes": {
                        "/rbac/teams": ["GET"]
                    },
                    "inherits": None,
                },
            },
            "team": {
                "Lead": {
                    "routes": {
                        "/rbac/teams/assign-user": ["POST"],
                        "/rbac/teams/remove-user": ["DELETE"],
                        "/rbac/teams": ["GET"]
                    },
                    "inherits": None,
                },
                "Team_Member": {
                    "routes": {
                        "/rbac/teams": ["GET"]
                    },
                    "inherits": None
                },
            },
            "super_admin": {
                "routes": {
                    "*": ["GET", "POST", "PUT", "DELETE", "PATCH"]
                },
                "inherits": None
            }
        }
        logger.info("Using fallback hardcoded permissions due to database error")
    finally:
        await db.close()
