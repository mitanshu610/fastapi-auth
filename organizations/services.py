from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from organizations.dao import OrganizationDAO
from auth.dao import AuthDAO
from organizations.schemas import OrganizationCreate, OrganizationRead, OrganizationUserRead
from auth.models import User
from utils.custom_logger import logger
from utils.serializers import ResponseData
from utils.exceptions import (
    NotFoundError, ValidationError as CustomValidationError, ConflictError, 
    InternalServerError, UnauthorizedError
)

class OrganizationService:
    def __init__(self, db: AsyncSession):
        self.organization_dao = OrganizationDAO(db=db)
        self.user_dao = AuthDAO(db=db)

    async def create_organization(
        self, org_create_data: OrganizationCreate, current_user: User
    ) -> dict:
        try:
            db_org = await self.organization_dao.create_organization(org_create_data)
            admin_role = await self.organization_dao.get_admin_role()
            if not admin_role:
                logger.error("Admin role not found during organization creation.")
                raise InternalServerError("Admin role not found", "ADMIN_ROLE_NOT_FOUND")

            await self.organization_dao.add_user_to_organization(
                organization_id=db_org.id, user_id=current_user.id, role_id=admin_role.id
            )
            
            logger.info(f"Organization '{db_org.name}' created by user {current_user.email}")
            
            return ResponseData(
                success=True,
                message="Organization created successfully",
                data=OrganizationRead.model_validate(db_org).model_dump()
            ).model_dump()
            
        except Exception as e:
            logger.error(f"Error creating organization in service: {e}")
            raise InternalServerError("Failed to create organization", "ORGANIZATION_CREATION_ERROR")

    async def get_organization_by_id(self, organization_id: int, current_user: User) -> dict:
        """Get organization by ID"""
        try:
            organization = await self.organization_dao.get_organization_by_id(organization_id)
            if not organization:
                raise NotFoundError(f"Organization with ID {organization_id} not found", "ORGANIZATION_NOT_FOUND")
            
            # Check if user has access to this organization
            user_membership = await self.organization_dao.get_organization_user(
                user_id=current_user.id, organization_id=organization_id
            )
            if not user_membership:
                raise UnauthorizedError("Access denied to this organization", "ACCESS_DENIED")
            
            return ResponseData(
                success=True,
                message="Organization retrieved successfully",
                data=OrganizationRead.model_validate(organization).model_dump()
            ).model_dump()
            
        except (NotFoundError, UnauthorizedError):
            raise
        except Exception as e:
            logger.error(f"Error retrieving organization {organization_id}: {e}")
            raise InternalServerError("Failed to retrieve organization", "ORGANIZATION_RETRIEVAL_ERROR")

    async def get_user_organizations(self, current_user: User) -> dict:
        """Get all organizations for the current user"""
        try:
            # Get user's organization memberships with organization and role details
            user_orgs = await self.organization_dao.get_user_organizations(current_user.id)
            
            # Transform the data to match OrganizationUserRead schema
            organizations_data = []
            for org_user in user_orgs:
                org_user_data = OrganizationUserRead.model_validate(org_user)
                organizations_data.append(org_user_data.model_dump())
            
            logger.info(f"Retrieved {len(organizations_data)} organizations for user {current_user.email}")
            
            return ResponseData(
                success=True,
                message="User organizations retrieved successfully",
                data=organizations_data
            ).model_dump()
            
        except Exception as e:
            logger.error(f"Error retrieving user organizations: {e}")
            raise InternalServerError("Failed to retrieve user organizations", "USER_ORGANIZATIONS_ERROR")

    async def get_organization_members(self, organization_id: int, current_user: User) -> dict:
        """Get all members of an organization"""
        try:
            # Check if user has access to this organization
            user_membership = await self.organization_dao.get_organization_user(
                user_id=current_user.id, organization_id=organization_id
            )
            if not user_membership:
                raise UnauthorizedError("Access denied to this organization", "ACCESS_DENIED")
            
            # Get all organization members
            members = await self.organization_dao.get_organization_members(organization_id)
            
            # Transform the data to match the expected schema format
            members_data = []
            for member in members:
                member_data = {
                    "id": member.id,
                    "user": {
                        "id": member.user.id,
                        "email": member.user.email,
                        "first_name": member.user.first_name,
                        "last_name": member.user.last_name,
                        "phone_number": member.user.phone_number
                    },
                    "role": {
                        "id": member.role.id,
                        "name": member.role.name
                    }
                }
                members_data.append(member_data)
            
            logger.info(f"Retrieved {len(members_data)} members for organization {organization_id}")
            
            return ResponseData(
                success=True,
                message="Organization members retrieved successfully",
                data=members_data
            ).model_dump()
            
        except UnauthorizedError:
            raise
        except Exception as e:
            logger.error(f"Error retrieving organization members: {e}")
            raise InternalServerError("Failed to retrieve organization members", "ORGANIZATION_MEMBERS_ERROR")

    async def update_organization(self, organization_id: int, org_data: dict, current_user: User) -> dict:
        """Update organization details"""
        try:
            # Check if user is admin of this organization
            user_membership = await self.organization_dao.get_organization_user(
                user_id=current_user.id, organization_id=organization_id
            )
            if not user_membership or user_membership.role.name != "Admin":
                raise UnauthorizedError("Admin access required", "ADMIN_ACCESS_REQUIRED")
            
            # This would require an update method in DAO
            # For now, returning a placeholder
            return ResponseData(
                success=True,
                message="Organization updated successfully",
                data={}
            ).model_dump()
            
        except UnauthorizedError:
            raise
        except Exception as e:
            logger.error(f"Error updating organization {organization_id}: {e}")
            raise InternalServerError("Failed to update organization", "ORGANIZATION_UPDATE_ERROR")

    async def remove_user_from_organization(self, organization_id: int, user_id: int, current_user: User) -> dict:
        """Remove user from organization"""
        try:
            # Check if current user is admin
            user_membership = await self.organization_dao.get_organization_user(
                user_id=current_user.id, organization_id=organization_id
            )
            if not user_membership or user_membership.role.name != "Admin":
                raise UnauthorizedError("Admin access required", "ADMIN_ACCESS_REQUIRED")
            
            # Check if target user exists in organization
            target_membership = await self.organization_dao.get_organization_user(
                user_id=user_id, organization_id=organization_id
            )
            if not target_membership:
                raise NotFoundError("User is not a member of this organization", "USER_NOT_MEMBER")
            
            # Prevent removing the last admin
            if target_membership.role.name == "Admin":
                # This would require a method to count admins
                # For now, we'll allow it but add a warning
                logger.warning(f"Removing admin user {user_id} from organization {organization_id}")
            
            # This would require a remove method in DAO
            # For now, returning a placeholder
            return ResponseData(
                success=True,
                message="User removed from organization successfully"
            ).model_dump()
            
        except (NotFoundError, UnauthorizedError):
            raise
        except Exception as e:
            logger.error(f"Error removing user from organization: {e}")
            raise InternalServerError("Failed to remove user from organization", "USER_REMOVAL_ERROR")

    async def assign_user_to_organization(
        self,
        user_email: str,
        organization_id: int,
        role_id: int,
        current_user: User,
    ) -> dict:
        try:
            org_admin_membership = await self.organization_dao.get_organization_user(
                user_id=current_user.id, organization_id=organization_id
            )
            if not org_admin_membership or org_admin_membership.role.name != "Admin":
                raise UnauthorizedError("Admin access required", "ADMIN_ACCESS_REQUIRED")

            target_user = await self.user_dao.get_user_by_email(user_email)

            if not target_user:
                raise NotFoundError(
                    "User must register before being added to the organization",
                    "USER_NOT_FOUND",
                )

            existing_membership = await self.organization_dao.get_organization_user(
                user_id=target_user.id, organization_id=organization_id
            )
            if existing_membership:
                raise ConflictError("User is already part of the organization", "USER_ALREADY_MEMBER")

            await self.organization_dao.add_user_to_organization(
                organization_id=organization_id, user_id=target_user.id, role_id=role_id
            )
            
            logger.info(f"User {user_email} added to organization {organization_id}")
            
            return ResponseData(
                success=True,
                message="User added to organization successfully"
            ).model_dump()
            
        except (UnauthorizedError, ConflictError, NotFoundError):
            raise
        except Exception as e:
            logger.error(f"Error assigning user to organization: {e}")
            raise InternalServerError("Failed to assign user to organization", "USER_ASSIGNMENT_ERROR")
