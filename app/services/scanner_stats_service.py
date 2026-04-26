"""Scanner statistics service — async queries for scanner dashboard."""

from datetime import datetime, timedelta

from sqlalchemy import func, select, case, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_run import ScanRun, ScannerType, ScanRunStatus

# NOTE: avg() import comes from func.avg via sqlalchemy func

# Scanner metadata: display names and schedules
SCANNER_META = {
    ScannerType.DOMAIN: {"display_name": "Domain Scanner", "schedule": "Har 30 daqiqada"},
    ScannerType.PHISHING: {"display_name": "Phishing Scanner", "schedule": "Har 15 daqiqada"},
    ScannerType.APP_STORE: {"display_name": "App Store Scanner", "schedule": "Har 2 soatda"},
    ScannerType.SOCIAL: {"display_name": "Social Media Scanner", "schedule": "Har 1 soatda"},
    ScannerType.PASTE: {"display_name": "Paste/Code Scanner", "schedule": "Har 3 soatda"},
}


async def get_scanner_overview(db: AsyncSession) -> dict:
    """Build scanner status overview for all 5 scanner types."""
    scanners = []
    total_threats = 0
    total_scans = 0
    total_errors = 0

    for scanner_type, meta in SCANNER_META.items():
        # Get the latest scan run for this scanner type
        last_run_q = await db.execute(
            select(ScanRun)
            .where(ScanRun.scanner_type == scanner_type)
            .order_by(desc(ScanRun.started_at))
            .limit(1)
        )
        last_run = last_run_q.scalar_one_or_none()

        # Get aggregate stats for this scanner type
        stats_q = await db.execute(
            select(
                func.count(ScanRun.id).label("total_scans"),
                func.coalesce(func.sum(ScanRun.threats_found), 0).label("total_threats"),
                func.count(case((ScanRun.status == ScanRunStatus.COMPLETED, 1))).label("completed"),
                func.count(case((ScanRun.status == ScanRunStatus.FAILED, 1))).label("failed"),
            )
            .where(ScanRun.scanner_type == scanner_type)
        )
        stats = stats_q.one()

        scanner_total_scans = stats.total_scans
        scanner_total_threats = stats.total_threats
        completed = stats.completed
        failed = stats.failed

        success_rate = (completed / scanner_total_scans * 100) if scanner_total_scans > 0 else 0.0

        # Determine health
        if scanner_total_scans == 0:
            health = "unknown"
        elif last_run and last_run.status == ScanRunStatus.FAILED:
            health = "failed"
        elif success_rate >= 80:
            health = "healthy"
        elif success_rate >= 50:
            health = "degraded"
        else:
            health = "failed"

        scanners.append({
            "type": scanner_type.value,
            "display_name": meta["display_name"],
            "schedule": meta["schedule"],
            "last_run": last_run.started_at if last_run else None,
            "last_status": last_run.status.value if last_run else None,
            "last_duration_seconds": last_run.duration_seconds if last_run else None,
            "last_threats_found": last_run.threats_found if last_run else 0,
            "last_items_scanned": last_run.items_scanned if last_run else 0,
            "total_threats_found": scanner_total_threats,
            "total_scans": scanner_total_scans,
            "success_rate": round(success_rate, 1),
            "health": health,
        })

        total_threats += scanner_total_threats
        total_scans += scanner_total_scans
        total_errors += failed

    # Compute average scan duration across all completed runs
    avg_dur_q = await db.execute(
        select(func.avg(ScanRun.duration_seconds)).where(
            ScanRun.status == ScanRunStatus.COMPLETED,
            ScanRun.duration_seconds.isnot(None),
        )
    )
    avg_duration = avg_dur_q.scalar() or 0.0

    overall = {
        "total_scans_all_time": total_scans,
        "total_threats_found_all_time": total_threats,
        "avg_scan_duration_seconds": round(float(avg_duration), 1),
        "scanners_healthy": sum(1 for s in scanners if s["health"] == "healthy"),
        "scanners_degraded": sum(1 for s in scanners if s["health"] == "degraded"),
        "scanners_failed": sum(1 for s in scanners if s["health"] == "failed"),
    }

    return {"scanners": scanners, "overall": overall}


async def get_scanner_history(
    db: AsyncSession,
    scanner_type: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    """Get paginated scan run history, optionally filtered by scanner type."""
    query = select(ScanRun).order_by(desc(ScanRun.started_at))
    count_query = select(func.count(ScanRun.id))

    if scanner_type:
        try:
            st = ScannerType(scanner_type)
            query = query.where(ScanRun.scanner_type == st)
            count_query = count_query.where(ScanRun.scanner_type == st)
        except ValueError:
            pass

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Get paginated results
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    runs = result.scalars().all()

    items = []
    for run in runs:
        items.append({
            "id": str(run.id),
            "scanner_type": run.scanner_type.value,
            "status": run.status.value,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "duration_seconds": run.duration_seconds,
            "threats_found": run.threats_found,
            "items_scanned": run.items_scanned,
            "errors": run.errors,
            "details": run.details,
        })

    return {"items": items, "total": total}
