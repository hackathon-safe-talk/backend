"""Threat management endpoints — requires JWT auth."""

import math
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, or_, desc, asc, any_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.deps import get_db, get_current_user, require_role
from app.models.admin_user import AdminUser, AdminRole
from app.models.threat import Threat, ThreatStatus, ThreatLabel, ThreatSource
from app.models.audit_log import AuditLog
from app.schemas.threat import ThreatResponse, ThreatListResponse, ThreatUpdateRequest
from app.services.audit_service import write_audit_log

router = APIRouter()


def _threat_to_response(t: Threat) -> ThreatResponse:
    return ThreatResponse(
        id=str(t.id),
        mobile_id=t.mobile_id,
        source=t.source.value,
        message_truncated=t.message_truncated,
        risk_score=t.risk_score,
        confidence=t.confidence,
        label=t.label.value,
        status=t.status.value,
        reasons=t.reasons or [],
        recommendations=t.recommendations or [],
        sender_name=t.sender_name,
        source_app=t.source_app,
        detected_file_name=t.detected_file_name,
        detected_file_type=t.detected_file_type,
        detected_url=t.detected_url,
        screenshot_key=t.screenshot_key,
        auto_tags=t.auto_tags or [],
        manual_tags=t.manual_tags or [],
        analyst_notes=t.analyst_notes,
        device_id=str(t.device_id),
        received_at=t.received_at,
        analyzed_at_device=t.analyzed_at_device,
        has_ai_analysis=bool(t.ai_analyses),
    )


@router.get("", response_model=ThreatListResponse)
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    label: Optional[str] = None,
    source: Optional[str] = None,
    risk_min: Optional[int] = None,
    risk_max: Optional[int] = None,
    sender: Optional[str] = None,
    url: Optional[str] = None,
    tag: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: str = Query("received_at", pattern="^(received_at|risk_score|updated_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    query = select(Threat).options(selectinload(Threat.ai_analyses))
    count_query = select(func.count(Threat.id))

    # Filters
    if status:
        try:
            status_enum = ThreatStatus(status)
            query = query.where(Threat.status == status_enum)
            count_query = count_query.where(Threat.status == status_enum)
        except ValueError:
            query = query.where(False)
            count_query = count_query.where(False)
    if label:
        try:
            label_enum = ThreatLabel(label)
            query = query.where(Threat.label == label_enum)
            count_query = count_query.where(Threat.label == label_enum)
        except ValueError:
            # Unknown label value — return empty result set
            query = query.where(False)
            count_query = count_query.where(False)
    if source:
        try:
            source_enum = ThreatSource(source)
            query = query.where(Threat.source == source_enum)
            count_query = count_query.where(Threat.source == source_enum)
        except ValueError:
            query = query.where(False)
            count_query = count_query.where(False)
    if risk_min is not None:
        query = query.where(Threat.risk_score >= risk_min)
        count_query = count_query.where(Threat.risk_score >= risk_min)
    if risk_max is not None:
        query = query.where(Threat.risk_score <= risk_max)
        count_query = count_query.where(Threat.risk_score <= risk_max)
    if sender:
        query = query.where(Threat.sender_name.ilike(f"%{sender}%"))
        count_query = count_query.where(Threat.sender_name.ilike(f"%{sender}%"))
    if url:
        query = query.where(Threat.detected_url.ilike(f"%{url}%"))
        count_query = count_query.where(Threat.detected_url.ilike(f"%{url}%"))
    if tag:
        tag_filter = or_(
            Threat.auto_tags.any(tag),
            Threat.manual_tags.any(tag),
        )
        query = query.where(tag_filter)
        count_query = count_query.where(tag_filter)
    if date_from:
        query = query.where(Threat.received_at >= date_from)
        count_query = count_query.where(Threat.received_at >= date_from)
    if date_to:
        query = query.where(Threat.received_at <= date_to)
        count_query = count_query.where(Threat.received_at <= date_to)
    if search:
        search_filter = or_(
            Threat.message_truncated.ilike(f"%{search}%"),
            Threat.sender_name.ilike(f"%{search}%"),
            Threat.detected_url.ilike(f"%{search}%"),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    # Sorting
    sort_col = getattr(Threat, sort_by)
    order_fn = desc if sort_order == "desc" else asc
    query = query.order_by(order_fn(sort_col))

    # Pagination
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    threats = result.scalars().unique().all()

    return ThreatListResponse(
        items=[_threat_to_response(t) for t in threats],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total else 0,
    )


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    result = await db.execute(
        select(Threat).options(selectinload(Threat.ai_analyses)).where(Threat.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return _threat_to_response(threat)


@router.patch("/{threat_id}", response_model=ThreatResponse)
async def update_threat(
    threat_id: str,
    body: ThreatUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(require_role(AdminRole.ANALYST, AdminRole.SUPER_ADMIN)),
):
    result = await db.execute(
        select(Threat).options(selectinload(Threat.ai_analyses)).where(Threat.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    if body.status:
        old_status = threat.status.value
        threat.status = ThreatStatus(body.status)

        if body.status in ("confirmed", "actioned"):
            threat.actioned_by = current_user.id
            threat.actioned_at = datetime.utcnow()

        await write_audit_log(
            db,
            action=f"threat.{body.status}",
            entity_type="threat",
            entity_id=threat.id,
            user_id=current_user.id,
            details={"old_status": old_status, "new_status": body.status},
        )

    if body.manual_tags is not None:
        threat.manual_tags = body.manual_tags

    if body.analyst_notes is not None:
        threat.analyst_notes = body.analyst_notes

    threat.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(threat)

    return _threat_to_response(threat)


@router.get("/{threat_id}/timeline")
async def get_threat_timeline(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Get audit log entries for a specific threat."""
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.entity_id == threat_id, AuditLog.entity_type == "threat")
        .order_by(AuditLog.created_at.desc())
    )
    entries = result.scalars().all()
    return [
        {
            "id": str(e.id),
            "action": e.action,
            "user_id": str(e.user_id) if e.user_id else None,
            "details": e.details,
            "created_at": e.created_at.isoformat(),
        }
        for e in entries
    ]
