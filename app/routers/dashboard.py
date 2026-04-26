"""Dashboard analytics endpoints — requires JWT auth."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db, get_current_user
from app.models.admin_user import AdminUser
from app.schemas.dashboard import (
    DashboardStats,
    ThreatTrendPoint,
    TopSender,
    TopUrl,
    TagDistribution,
    SourceBreakdown,
)
from app.services.dashboard_service import (
    get_dashboard_stats,
    get_threat_trends,
    get_top_senders,
    get_top_urls,
    get_tag_distribution,
    get_source_breakdown,
)

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def stats(
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    return await get_dashboard_stats(db)


@router.get("/trends", response_model=list[ThreatTrendPoint])
async def trends(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    return await get_threat_trends(db, days)


@router.get("/top-senders", response_model=list[TopSender])
async def top_senders(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    return await get_top_senders(db, limit)


@router.get("/top-urls", response_model=list[TopUrl])
async def top_urls(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    return await get_top_urls(db, limit)


@router.get("/tag-distribution", response_model=list[TagDistribution])
async def tag_distribution(
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    return await get_tag_distribution(db)


@router.get("/source-breakdown", response_model=list[SourceBreakdown])
async def source_breakdown(
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    return await get_source_breakdown(db)
