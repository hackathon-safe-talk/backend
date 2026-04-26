import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Text, DateTime, Boolean,
    Enum as SAEnum, Index, ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship

from app.database import Base


class ThreatSource(str, enum.Enum):
    MANUAL = "MANUAL"
    AUTO_SMS = "AUTO_SMS"
    AUTO_TELEGRAM = "AUTO_TELEGRAM"
    SCANNER_DOMAIN = "SCANNER_DOMAIN"
    SCANNER_PHISHING = "SCANNER_PHISHING"
    SCANNER_APP_STORE = "SCANNER_APP_STORE"
    SCANNER_SOCIAL = "SCANNER_SOCIAL"
    SCANNER_PASTE = "SCANNER_PASTE"


class ThreatLabel(str, enum.Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"


class ThreatStatus(str, enum.Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACTIONED = "actioned"
    ARCHIVED = "archived"


class Threat(Base):
    __tablename__ = "threats"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # ── From mobile app (SyncItem fields) ─────────────────────────
    mobile_id = Column(String(64), unique=True, nullable=False, index=True)
    source = Column(SAEnum(ThreatSource), nullable=False)
    message_truncated = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=False)
    confidence = Column(Integer, nullable=True)
    label = Column(SAEnum(ThreatLabel), nullable=False, default=ThreatLabel.DANGEROUS)
    reasons = Column(ARRAY(Text), nullable=True, default=list)
    recommendations = Column(ARRAY(Text), nullable=True, default=list)
    analyzed_at_device = Column(DateTime, nullable=True)
    sender_name = Column(String(255), nullable=True, index=True)
    source_app = Column(String(100), nullable=True)
    detected_file_name = Column(String(500), nullable=True)
    detected_file_type = Column(String(200), nullable=True)
    detected_url = Column(Text, nullable=True, index=True)
    screenshot_key = Column(String(500), nullable=True)  # MinIO object key for website screenshot

    # ── Server-side metadata ──────────────────────────────────────
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=True)
    status = Column(SAEnum(ThreatStatus), nullable=False, default=ThreatStatus.NEW)
    auto_tags = Column(ARRAY(Text), nullable=True, default=list)
    manual_tags = Column(ARRAY(Text), nullable=True, default=list)
    analyst_notes = Column(Text, nullable=True)
    actioned_by = Column(UUID(as_uuid=True), ForeignKey("admin_users.id"), nullable=True)
    actioned_at = Column(DateTime, nullable=True)

    # ── Timestamps ────────────────────────────────────────────────
    received_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ── Relationships ─────────────────────────────────────────────
    device = relationship("Device", back_populates="threats")
    ai_analyses = relationship("AIAnalysis", back_populates="threat", order_by="AIAnalysis.created_at.desc()")

    __table_args__ = (
        Index("idx_threats_status", "status"),
        Index("idx_threats_label", "label"),
        Index("idx_threats_received_at", "received_at"),
        Index("idx_threats_risk_score", "risk_score"),
        Index("idx_threats_source", "source"),
        Index("idx_threats_sender", "sender_name"),
        Index("idx_threats_url", "detected_url"),
    )
