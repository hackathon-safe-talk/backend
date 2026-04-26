"""Dashboard aggregation queries — all use SQL-level aggregation for performance."""

from datetime import datetime, timedelta

from sqlalchemy import func, select, case, distinct, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat import Threat, ThreatStatus, ThreatLabel, ThreatSource
from app.models.device import Device
from app.models.scan_run import ScanRun, ScanRunStatus
from app.models.brand_asset import BrandAsset
from app.models.scanner_pattern import ScannerPattern
from app.schemas.dashboard import (
    DashboardStats,
    ThreatTrendPoint,
    TopSender,
    TopUrl,
    TagDistribution,
    SourceBreakdown,
)


async def get_dashboard_stats(db: AsyncSession) -> DashboardStats:
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=today_start.weekday())

    result = await db.execute(
        select(
            func.count(Threat.id).label("total"),
            func.count(case((Threat.received_at >= today_start, 1))).label("today"),
            func.count(case((Threat.received_at >= week_start, 1))).label("week"),
            func.count(case((Threat.status == ThreatStatus.NEW, 1))).label("new_count"),
            func.count(case((Threat.status == ThreatStatus.CONFIRMED, 1))).label("confirmed"),
            func.count(case((Threat.status == ThreatStatus.FALSE_POSITIVE, 1))).label("fp"),
            func.count(case((Threat.status == ThreatStatus.ACTIONED, 1))).label("actioned"),
            func.count(distinct(Threat.device_id)).label("devices"),
            func.coalesce(func.max(Threat.risk_score), 0).label("top_risk"),
            func.coalesce(func.avg(Threat.risk_score), 0).label("avg_risk"),
        )
    )
    row = result.one()

    # Scanner metrics
    scanner_sources = [
        ThreatSource.SCANNER_DOMAIN,
        ThreatSource.SCANNER_PHISHING,
        ThreatSource.SCANNER_APP_STORE,
        ThreatSource.SCANNER_SOCIAL,
        ThreatSource.SCANNER_PASTE,
    ]

    scanner_result = await db.execute(
        select(
            func.count(Threat.id).label("scanner_total"),
            func.count(case((Threat.received_at >= today_start, 1))).label("scanner_today"),
        ).where(Threat.source.in_(scanner_sources))
    )
    scanner_row = scanner_result.one()

    brand_assets_result = await db.execute(
        select(func.count(BrandAsset.id)).where(BrandAsset.is_active == True)
    )
    brand_assets_count = brand_assets_result.scalar() or 0

    patterns_result = await db.execute(
        select(func.count(ScannerPattern.id)).where(ScannerPattern.is_active == True)
    )
    patterns_count = patterns_result.scalar() or 0

    scans_today_result = await db.execute(
        select(func.count(ScanRun.id)).where(ScanRun.started_at >= today_start)
    )
    scans_today = scans_today_result.scalar() or 0

    return DashboardStats(
        total_threats=row.total,
        threats_today=row.today,
        threats_this_week=row.week,
        new_count=row.new_count,
        confirmed_count=row.confirmed,
        false_positive_count=row.fp,
        actioned_count=row.actioned,
        unique_devices=row.devices,
        top_risk_score=row.top_risk,
        avg_risk_score=round(float(row.avg_risk), 1),
        scanner_threats_total=scanner_row.scanner_total,
        scanner_threats_today=scanner_row.scanner_today,
        brand_assets_monitored=brand_assets_count,
        custom_patterns_active=patterns_count,
        total_scans_today=scans_today,
    )


async def get_threat_trends(db: AsyncSession, days: int = 30) -> list[ThreatTrendPoint]:
    since = datetime.utcnow() - timedelta(days=days)
    date_col = func.date(Threat.received_at)

    result = await db.execute(
        select(
            date_col.label("d"),
            func.count(Threat.id).label("count"),
            func.count(case((Threat.label == ThreatLabel.DANGEROUS, 1))).label("dangerous"),
            func.count(case((Threat.label == ThreatLabel.SUSPICIOUS, 1))).label("suspicious"),
        )
        .where(Threat.received_at >= since)
        .group_by(date_col)
        .order_by(date_col)
    )
    return [
        ThreatTrendPoint(date=str(r.d), count=r.count, dangerous=r.dangerous, suspicious=r.suspicious)
        for r in result.all()
    ]


async def get_top_senders(db: AsyncSession, limit: int = 10) -> list[TopSender]:
    result = await db.execute(
        select(
            Threat.sender_name,
            func.count(Threat.id).label("cnt"),
            func.avg(Threat.risk_score).label("avg_rs"),
            func.max(Threat.received_at).label("latest"),
        )
        .where(Threat.sender_name.isnot(None))
        .group_by(Threat.sender_name)
        .order_by(desc("cnt"))
        .limit(limit)
    )
    return [
        TopSender(
            sender_name=r.sender_name,
            threat_count=r.cnt,
            avg_risk_score=round(float(r.avg_rs), 1),
            latest_at=r.latest,
        )
        for r in result.all()
    ]


async def get_top_urls(db: AsyncSession, limit: int = 10) -> list[TopUrl]:
    result = await db.execute(
        select(
            Threat.detected_url,
            func.count(Threat.id).label("cnt"),
            func.min(Threat.received_at).label("first"),
            func.max(Threat.received_at).label("latest"),
        )
        .where(Threat.detected_url.isnot(None))
        .group_by(Threat.detected_url)
        .order_by(desc("cnt"))
        .limit(limit)
    )
    return [
        TopUrl(url=r.detected_url, threat_count=r.cnt, first_seen=r.first, latest_seen=r.latest)
        for r in result.all()
    ]


async def get_tag_distribution(db: AsyncSession) -> list[TagDistribution]:
    """Get frequency of each auto_tag using unnest."""
    result = await db.execute(
        text("""
            SELECT tag, COUNT(*) as cnt
            FROM threats, unnest(auto_tags) AS tag
            GROUP BY tag
            ORDER BY cnt DESC
        """)
    )
    return [TagDistribution(tag=r.tag, count=r.cnt) for r in result.all()]


async def get_source_breakdown(db: AsyncSession) -> list[SourceBreakdown]:
    result = await db.execute(
        select(
            Threat.source,
            func.count(Threat.id).label("cnt"),
        )
        .group_by(Threat.source)
        .order_by(desc("cnt"))
    )
    return [SourceBreakdown(source=r.source.value, count=r.cnt) for r in result.all()]
