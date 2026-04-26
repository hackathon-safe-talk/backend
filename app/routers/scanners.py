"""Scanner management endpoints — status, trigger, history, stats, discovered domains."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db, get_current_user
from app.models.admin_user import AdminUser
from app.models.discovered_domain import DiscoveredDomain, DomainStatus
from app.schemas.scanner import (
    ScannerOverview, ScanRunHistory, TriggerResponse,
    DiscoveredDomainResponse, DiscoveredDomainList, DiscoveredDomainUpdate,
)
from app.services.scanner_stats_service import get_scanner_overview, get_scanner_history

router = APIRouter()

# Map scanner types to their Celery tasks
SCANNER_TASKS = {
    "domain": "app.scanners.domain_scanner.run_domain_scan",
    "phishing": "app.scanners.phishing_scanner.run_phishing_scan",
    "app_store": "app.scanners.app_store_scanner.run_app_store_scan",
    "social": "app.scanners.social_scanner.run_social_scan",
    "paste": "app.scanners.paste_scanner.run_paste_scan",
}


@router.get("/status", response_model=ScannerOverview)
async def scanner_status(
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Get overview status of all scanners."""
    overview = await get_scanner_overview(db)
    return overview


@router.post("/{scanner_type}/run", response_model=TriggerResponse)
async def trigger_scanner(
    scanner_type: str,
    user: AdminUser = Depends(get_current_user),
):
    """Manually trigger a scanner via Celery."""
    if scanner_type not in SCANNER_TASKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scanner type: {scanner_type}. Available: {list(SCANNER_TASKS.keys())}",
        )

    from app.celery_app import celery
    task = celery.send_task(SCANNER_TASKS[scanner_type])

    return TriggerResponse(
        task_id=task.id,
        message=f"Scanner '{scanner_type}' triggered successfully",
    )


@router.get("/history", response_model=ScanRunHistory)
async def scanner_history(
    scanner_type: str | None = Query(None, description="Filter by scanner type"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Get paginated scan run history."""
    result = await get_scanner_history(db, scanner_type=scanner_type, limit=limit, offset=offset)
    return result


@router.get("/stats")
async def scanner_stats(
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Get aggregated scanner statistics."""
    overview = await get_scanner_overview(db)
    return overview["overall"]


# ── Discovered Domains ──────────────────────────────────────────


@router.get("/domains", response_model=DiscoveredDomainList)
async def list_discovered_domains(
    status: str | None = Query(None, description="Filter by status: live, down, blocked, whitelisted"),
    dns_resolved: bool | None = Query(None, description="Filter by DNS resolution"),
    source: str | None = Query(None, description="Filter by source: typosquat, homoglyph, ct_log, urlhaus, manual"),
    search: str | None = Query(None, description="Search domain name"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """List all discovered domains with filtering."""
    query = select(DiscoveredDomain).order_by(DiscoveredDomain.last_checked_at.desc())

    if status:
        query = query.where(DiscoveredDomain.status == status)
    if dns_resolved is not None:
        query = query.where(DiscoveredDomain.dns_resolved == dns_resolved)
    if source:
        query = query.where(DiscoveredDomain.source == source)
    if search:
        query = query.where(DiscoveredDomain.domain.ilike(f"%{search}%"))

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    # Paginate
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    domains = result.scalars().all()

    items = [
        DiscoveredDomainResponse(
            id=str(d.id),
            domain=d.domain,
            status=d.status.value,
            source=d.source.value,
            ip_address=d.ip_address,
            dns_resolved=d.dns_resolved,
            risk_score=d.risk_score,
            matched_brand=d.matched_brand,
            matched_pattern=d.matched_pattern,
            similarity_score=d.similarity_score,
            ssl_issuer=d.ssl_issuer,
            ssl_issued_at=d.ssl_issued_at,
            first_seen_at=d.first_seen_at,
            last_checked_at=d.last_checked_at,
            check_count=d.check_count,
            threat_id=str(d.threat_id) if d.threat_id else None,
            notes=d.notes,
            reviewed_by=str(d.reviewed_by) if d.reviewed_by else None,
            reviewed_at=d.reviewed_at,
        )
        for d in domains
    ]

    return DiscoveredDomainList(items=items, total=total)


@router.patch("/domains/{domain_id}")
async def update_discovered_domain(
    domain_id: str,
    body: DiscoveredDomainUpdate,
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Update a discovered domain's status or notes."""
    from datetime import datetime

    domain = await db.get(DiscoveredDomain, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    if body.status:
        domain.status = DomainStatus(body.status)
    if body.notes is not None:
        domain.notes = body.notes
    domain.reviewed_by = user.id
    domain.reviewed_at = datetime.utcnow()

    await db.commit()
    await db.refresh(domain)

    return DiscoveredDomainResponse(
        id=str(domain.id),
        domain=domain.domain,
        status=domain.status.value,
        source=domain.source.value,
        ip_address=domain.ip_address,
        dns_resolved=domain.dns_resolved,
        risk_score=domain.risk_score,
        matched_brand=domain.matched_brand,
        matched_pattern=domain.matched_pattern,
        similarity_score=domain.similarity_score,
        ssl_issuer=domain.ssl_issuer,
        ssl_issued_at=domain.ssl_issued_at,
        first_seen_at=domain.first_seen_at,
        last_checked_at=domain.last_checked_at,
        check_count=domain.check_count,
        threat_id=str(domain.threat_id) if domain.threat_id else None,
        notes=domain.notes,
        reviewed_by=str(domain.reviewed_by) if domain.reviewed_by else None,
        reviewed_at=domain.reviewed_at,
    )
