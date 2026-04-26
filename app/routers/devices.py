"""Device management endpoints — requires JWT auth."""

import math

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.deps import get_db, get_current_user
from app.models.admin_user import AdminUser
from app.models.device import Device
from app.models.threat import Threat

router = APIRouter()


@router.get("")
async def list_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    count_result = await db.execute(select(func.count(Device.id)))
    total = count_result.scalar()

    result = await db.execute(
        select(Device)
        .order_by(desc(Device.last_seen_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    devices = result.scalars().all()

    return {
        "items": [
            {
                "id": str(d.id),
                "device_hash": d.device_hash[:12] + "...",  # Truncated for display
                "app_version": d.app_version,
                "first_seen_at": d.first_seen_at.isoformat(),
                "last_seen_at": d.last_seen_at.isoformat(),
                "total_threats_reported": d.total_threats_reported,
            }
            for d in devices
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": math.ceil(total / page_size) if total else 0,
    }


@router.get("/{device_id}")
async def get_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    result = await db.execute(
        select(Device).options(selectinload(Device.threats)).where(Device.id == device_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    recent_threats = sorted(device.threats, key=lambda t: t.received_at, reverse=True)[:10]

    return {
        "id": str(device.id),
        "device_hash": device.device_hash[:12] + "...",
        "app_version": device.app_version,
        "first_seen_at": device.first_seen_at.isoformat(),
        "last_seen_at": device.last_seen_at.isoformat(),
        "total_threats_reported": device.total_threats_reported,
        "recent_threats": [
            {
                "id": str(t.id),
                "source": t.source.value,
                "risk_score": t.risk_score,
                "label": t.label.value,
                "status": t.status.value,
                "received_at": t.received_at.isoformat(),
                "sender_name": t.sender_name,
            }
            for t in recent_threats
        ],
    }
