import enum
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class ScannerType(str, enum.Enum):
    DOMAIN = "domain"
    PHISHING = "phishing"
    APP_STORE = "app_store"
    SOCIAL = "social"
    PASTE = "paste"


class ScanRunStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scanner_type = Column(SAEnum(ScannerType), nullable=False)
    status = Column(SAEnum(ScanRunStatus), nullable=False, default=ScanRunStatus.RUNNING)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    threats_found = Column(Integer, nullable=False, default=0)
    items_scanned = Column(Integer, nullable=False, default=0)
    errors = Column(JSONB, nullable=True)
    details = Column(JSONB, nullable=True)
