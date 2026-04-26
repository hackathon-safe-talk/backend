from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AIAnalysisRequest(BaseModel):
    """Admin triggers Claude AI analysis for a specific threat."""
    threat_id: str
    additional_context: Optional[str] = None


class AIAnalysisResponse(BaseModel):
    id: str
    threat_id: str
    severity_assessment: Optional[str] = None
    threat_type: Optional[str] = None
    analysis_text: str
    recommended_actions: list[str] = []
    ioc_indicators: Optional[dict] = None
    similar_pattern_description: Optional[str] = None
    confidence_score: Optional[int] = None
    model_used: str
    created_at: datetime

    model_config = {"from_attributes": True}
