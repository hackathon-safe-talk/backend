"""Tag management endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db, get_current_user
from app.models.admin_user import AdminUser
from app.services.dashboard_service import get_tag_distribution

router = APIRouter()


@router.get("")
async def list_tags(
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """List all tags with their counts."""
    return await get_tag_distribution(db)
