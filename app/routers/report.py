"""Central Bank incident report endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.deps import get_db, require_role
from app.models.admin_user import AdminUser, AdminRole
from app.models.threat import Threat
from app.models.ai_analysis import AIAnalysis
from app.services.report_service import generate_and_send_report, generate_incident_report
from app.services.storage_service import download_file
from app.services.audit_service import write_audit_log

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/threats/{threat_id}/report")
async def send_report_to_central_bank(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(require_role(AdminRole.ANALYST, AdminRole.SUPER_ADMIN)),
):
    """Generate PDF incident report and send to Central Bank of Uzbekistan."""
    result = await db.execute(
        select(Threat)
        .options(selectinload(Threat.ai_analyses))
        .where(Threat.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Get latest AI analysis if available
    latest_analysis = threat.ai_analyses[0] if threat.ai_analyses else None

    # Update threat status to actioned
    threat.status = "actioned"
    threat.actioned_by = current_user.id
    from datetime import datetime
    threat.actioned_at = datetime.utcnow()

    report_result = await generate_and_send_report(
        threat=threat,
        analysis=latest_analysis,
        requested_by_name=current_user.full_name,
    )

    await write_audit_log(
        db,
        action="threat.report_sent",
        entity_type="threat",
        entity_id=threat.id,
        user_id=current_user.id,
        details={
            "report_key": report_result["report_key"],
            "email_sent": report_result["email_sent"],
            "recipient": report_result["recipient"],
        },
    )

    await db.commit()

    return report_result


@router.get("/threats/{threat_id}/report/download")
async def download_report(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(require_role(AdminRole.ANALYST, AdminRole.SUPER_ADMIN)),
):
    """Download the PDF incident report for a threat."""
    result = await db.execute(
        select(Threat)
        .options(selectinload(Threat.ai_analyses))
        .where(Threat.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    latest_analysis = threat.ai_analyses[0] if threat.ai_analyses else None

    # Load screenshot
    screenshot_bytes = None
    if threat.screenshot_key:
        try:
            screenshot_bytes = download_file(threat.screenshot_key)
        except Exception:
            pass

    pdf_bytes = generate_incident_report(threat, latest_analysis, screenshot_bytes)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="SafeTalk_Incident_{str(threat.id)[:8]}.pdf"'
        },
    )
