"""AI analysis endpoints — requires JWT, analyst+ role."""

import logging
import traceback

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

from app.deps import get_db, require_role
from app.models.admin_user import AdminUser, AdminRole
from app.models.threat import Threat
from app.models.ai_analysis import AIAnalysis
from app.schemas.ai_analysis import AIAnalysisRequest, AIAnalysisResponse
from app.services.ai_service import analyze_threat_with_ai
from app.services.audit_service import write_audit_log

router = APIRouter()


@router.post("/analyze", response_model=AIAnalysisResponse)
async def trigger_analysis(
    body: AIAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(require_role(AdminRole.ANALYST, AdminRole.SUPER_ADMIN)),
):
    """Trigger Claude AI analysis for a specific threat."""
    threat = await db.get(Threat, body.threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    try:
        analysis = await analyze_threat_with_ai(
            threat=threat,
            additional_context=body.additional_context,
            requested_by=str(current_user.id),
        )
    except Exception as e:
        logger.error(f"AI analysis failed:\n{traceback.format_exc()}")
        raise HTTPException(status_code=502, detail=f"AI analysis failed: {str(e)}")

    db.add(analysis)

    await write_audit_log(
        db,
        action="ai.analysis_requested",
        entity_type="threat",
        entity_id=threat.id,
        user_id=current_user.id,
        details={"analysis_id": str(analysis.id)},
    )

    await db.commit()
    await db.refresh(analysis)

    return AIAnalysisResponse(
        id=str(analysis.id),
        threat_id=str(analysis.threat_id),
        severity_assessment=analysis.severity_assessment,
        threat_type=analysis.threat_type,
        analysis_text=analysis.analysis_text,
        recommended_actions=analysis.recommended_actions or [],
        ioc_indicators=analysis.ioc_indicators,
        similar_pattern_description=analysis.similar_pattern_description,
        confidence_score=analysis.confidence_score,
        model_used=analysis.model_used,
        created_at=analysis.created_at,
    )


@router.get("/analyses/{threat_id}", response_model=list[AIAnalysisResponse])
async def get_analyses(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(require_role(AdminRole.ANALYST, AdminRole.SUPER_ADMIN)),
):
    """Get all AI analyses for a specific threat."""
    result = await db.execute(
        select(AIAnalysis)
        .where(AIAnalysis.threat_id == threat_id)
        .order_by(AIAnalysis.created_at.desc())
    )
    analyses = result.scalars().all()
    return [
        AIAnalysisResponse(
            id=str(a.id),
            threat_id=str(a.threat_id),
            severity_assessment=a.severity_assessment,
            threat_type=a.threat_type,
            analysis_text=a.analysis_text,
            recommended_actions=a.recommended_actions or [],
            ioc_indicators=a.ioc_indicators,
            similar_pattern_description=a.similar_pattern_description,
            confidence_score=a.confidence_score,
            model_used=a.model_used,
            created_at=a.created_at,
        )
        for a in analyses
    ]
