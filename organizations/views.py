from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from auth.models import User
from db.pg_connection import get_db
from auth.dependencies import get_current_user

from organizations.services import OrganizationService
from organizations.schemas import OrganizationCreate, OrganizationUpdate
from utils.serializers import ResponseData


def get_organization_service(
    db: AsyncSession = Depends(get_db)
) -> OrganizationService:
    return OrganizationService(db=db)


async def create_organization(
    org: OrganizationCreate,
    current_user: User = Depends(get_current_user),
    organization_service: OrganizationService = Depends(get_organization_service)
):
    """Create new organization"""
    result = await organization_service.create_organization(org, current_user)
    return result


async def get_organization_by_id(
    organization_id: int,
    current_user: User = Depends(get_current_user),
    organization_service: OrganizationService = Depends(get_organization_service)
):
    """Get organization by ID"""
    result = await organization_service.get_organization_by_id(organization_id, current_user)
    return result


async def get_user_organizations(
    current_user: User = Depends(get_current_user),
    organization_service: OrganizationService = Depends(get_organization_service)
):
    """Get all organizations for current user"""
    result = await organization_service.get_user_organizations(current_user)
    return result


async def get_organization_members(
    organization_id: int,
    current_user: User = Depends(get_current_user),
    organization_service: OrganizationService = Depends(get_organization_service)
):
    """Get all members of an organization"""
    result = await organization_service.get_organization_members(organization_id, current_user)
    return result


async def update_organization(
    organization_id: int,
    org_data: OrganizationUpdate,
    current_user: User = Depends(get_current_user),
    organization_service: OrganizationService = Depends(get_organization_service)
):
    """Update organization details"""
    org_dict = org_data.model_dump(exclude_unset=True)
    result = await organization_service.update_organization(organization_id, org_dict, current_user)
    return result


async def assign_user_to_organization(
    user_email: str,
    organization_id: int,
    role_id: int,
    current_user: User = Depends(get_current_user),
    organization_service: OrganizationService = Depends(get_organization_service)
):
    """Assign user to organization"""
    result = await organization_service.assign_user_to_organization(
        user_email, organization_id, role_id, current_user
    )
    return result


async def remove_user_from_organization(
    organization_id: int,
    user_id: int,
    current_user: User = Depends(get_current_user),
    organization_service: OrganizationService = Depends(get_organization_service)
):
    """Remove user from organization"""
    result = await organization_service.remove_user_from_organization(organization_id, user_id, current_user)
    return result
