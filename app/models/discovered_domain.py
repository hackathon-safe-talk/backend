"""Discovered domains — tracks every domain the scanners have checked."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, Enum as SAEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class DomainStatus(str, enum.Enum):
    LIVE = "live"           # DNS resolved, domain is active
    DOWN = "down"           # DNS did not resolve
    BLOCKED = "blocked"     # Takedown requested / confirmed blocked
    WHITELISTED = "whitelisted"  # Known legitimate, ignore


class DomainSource(str, enum.Enum):
    TYPOSQUAT = "typosquat"
    HOMOGLYPH = "homoglyph"
    CT_LOG = "ct_log"
    URLHAUS = "urlhaus"
    MANUAL = "manual"


class DiscoveredDomain(Base):
    __tablename__ = "discovered_domains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(500), nullable=False, unique=True, index=True)
    status = Column(SAEnum(DomainStatus), nullable=False, default=DomainStatus.LIVE)
    source = Column(SAEnum(DomainSource), nullable=False, default=DomainSource.TYPOSQUAT)

    # DNS / resolution info
    ip_address = Column(String(45), nullable=True)
    dns_resolved = Column(Boolean, nullable=False, default=False)

    # Risk assessment
    risk_score = Column(Integer, nullable=True)
    matched_brand = Column(String(200), nullable=True)  # Which brand domain it looks like
    matched_pattern = Column(String(500), nullable=True)  # Which regex pattern matched
    similarity_score = Column(Float, nullable=True)  # Levenshtein or other similarity

    # SSL / CT log info
    ssl_issuer = Column(String(500), nullable=True)
    ssl_issued_at = Column(DateTime, nullable=True)

    # Tracking
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_checked_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    check_count = Column(Integer, nullable=False, default=1)
    threat_id = Column(UUID(as_uuid=True), ForeignKey("threats.id"), nullable=True)  # Link to created threat

    # Admin actions
    notes = Column(Text, nullable=True)
    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("admin_users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
