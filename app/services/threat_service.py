"""Threat ingestion, deduplication, and storage service."""

import hashlib
import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat import Threat, ThreatSource, ThreatLabel, ThreatStatus
from app.models.device import Device
from app.schemas.threat import BulkSyncRequest, BulkSyncResponse, SyncItem
from app.services.tagging_service import apply_auto_tags
from app.services.audit_service import write_audit_log


async def get_or_create_device(
    db: AsyncSession,
    device_id_raw: str,
    app_version: str,
) -> Device:
    """Find existing device by hash or create a new one."""
    device_hash = hashlib.sha256(device_id_raw.encode()).hexdigest()

    result = await db.execute(
        select(Device).where(Device.device_hash == device_hash)
    )
    device = result.scalar_one_or_none()

    if device:
        device.last_seen_at = datetime.utcnow()
        device.app_version = app_version
        return device

    device = Device(
        device_hash=device_hash,
        app_version=app_version,
    )
    db.add(device)
    await db.flush()  # get the generated ID
    return device


def _millis_to_datetime(millis: int) -> datetime | None:
    if millis and millis > 0:
        return datetime.utcfromtimestamp(millis / 1000)
    return None


def _map_source(source_str: str) -> ThreatSource:
    try:
        return ThreatSource(source_str)
    except ValueError:
        return ThreatSource.MANUAL


def _map_label(label_str: str) -> ThreatLabel:
    try:
        return ThreatLabel(label_str)
    except ValueError:
        return ThreatLabel.DANGEROUS


async def ingest_bulk(
    db: AsyncSession,
    request: BulkSyncRequest,
    client_ip: str | None = None,
) -> BulkSyncResponse:
    """Process a batch of threats from a mobile device."""
    device = await get_or_create_device(db, request.deviceId, request.appVersion)

    accepted = 0
    duplicates = 0

    for item in request.items:
        # Deduplication: check if mobile_id already exists
        existing = await db.execute(
            select(Threat.id).where(Threat.mobile_id == item.id)
        )
        if existing.scalar_one_or_none() is not None:
            duplicates += 1
            continue

        threat = Threat(
            mobile_id=item.id,
            source=_map_source(item.source),
            message_truncated=item.messageTruncated or None,
            risk_score=item.riskScore,
            confidence=item.confidence,
            label=_map_label(item.label),
            reasons=item.reasons,
            recommendations=item.recommendations,
            analyzed_at_device=_millis_to_datetime(item.analyzedAt),
            sender_name=item.senderName,
            source_app=item.sourceApp,
            detected_file_name=item.detectedFileName,
            detected_file_type=item.detectedFileType,
            detected_url=item.detectedUrl,
            device_id=device.id,
            status=ThreatStatus.NEW,
        )
        db.add(threat)
        await db.flush()

        # Apply rule-based auto-tags
        tags = apply_auto_tags(threat)
        threat.auto_tags = tags

        # Audit log
        await write_audit_log(
            db,
            action="threat.received",
            entity_type="threat",
            entity_id=threat.id,
            details={
                "mobile_id": item.id,
                "source": item.source,
                "risk_score": item.riskScore,
                "auto_tags": tags,
            },
            ip_address=client_ip,
        )

        accepted += 1

    # Update device counters
    device.total_threats_reported += accepted

    await db.commit()

    return BulkSyncResponse(
        accepted=accepted,
        duplicates=duplicates,
        batchId=request.batchId,
    )
