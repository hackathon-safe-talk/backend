import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship

from app.database import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_id = Column(UUID(as_uuid=True), ForeignKey("threats.id"), nullable=False)

    # ── Claude's analysis output ──────────────────────────────────
    severity_assessment = Column(String(20), nullable=True)
    threat_type = Column(String(100), nullable=True)
    analysis_text = Column(Text, nullable=False)
    recommended_actions = Column(ARRAY(Text), nullable=True)
    ioc_indicators = Column(JSONB, nullable=True)
    similar_pattern_description = Column(Text, nullable=True)
    confidence_score = Column(Integer, nullable=True)

    # ── Metadata ──────────────────────────────────────────────────
    model_used = Column(String(50), nullable=False, default="claude-sonnet-4-20250514")
    requested_by = Column(UUID(as_uuid=True), ForeignKey("admin_users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    threat = relationship("Threat", back_populates="ai_analyses")
