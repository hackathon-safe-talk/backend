from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ── Mobile App → Backend (Ingest) ─────────────────────────────────


class SyncItem(BaseModel):
    """Single threat item from the SafeTalk Android app."""
    id: str = Field(..., description="UUID generated on-device")
    source: str = Field(..., description="MANUAL | AUTO_SMS | AUTO_TELEGRAM")
    messageTruncated: str = Field("", description="First 200 chars of message")
    riskScore: int = Field(..., ge=0, le=100)
    confidence: int = Field(0, ge=0, le=100)
    label: str = Field(..., description="SAFE | SUSPICIOUS | DANGEROUS")
    reasons: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    analyzedAt: int = Field(..., description="Unix timestamp millis from device")
    senderName: Optional[str] = None
    sourceApp: Optional[str] = None
    detectedFileName: Optional[str] = None
    detectedFileType: Optional[str] = None
    detectedUrl: Optional[str] = None


class BulkSyncRequest(BaseModel):
    """Batch of threats from one device."""
    deviceId: str = Field(..., description="Anonymous UUID from device")
    appVersion: str = Field("1.0")
    batchId: str = Field(..., description="Unique batch identifier")
    items: list[SyncItem] = Field(..., min_length=1, max_length=100)


class BulkSyncResponse(BaseModel):
    accepted: int
    duplicates: int = 0
    batchId: str


# ── Backend → Dashboard (Read) ────────────────────────────────────


class ThreatResponse(BaseModel):
    id: str
    mobile_id: str
    source: str
    message_truncated: Optional[str] = None
    risk_score: int
    confidence: int | None = 0
    label: str
    status: str
    reasons: list[str] = []
    recommendations: list[str] = []
    sender_name: Optional[str] = None
    source_app: Optional[str] = None
    detected_file_name: Optional[str] = None
    detected_file_type: Optional[str] = None
    detected_url: Optional[str] = None
    screenshot_key: Optional[str] = None
    auto_tags: list[str] = []
    manual_tags: list[str] = []
    analyst_notes: Optional[str] = None
    device_id: str
    received_at: datetime
    analyzed_at_device: Optional[datetime] = None
    has_ai_analysis: bool = False

    model_config = {"from_attributes": True}


class ThreatListResponse(BaseModel):
    items: list[ThreatResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ThreatUpdateRequest(BaseModel):
    """Admin updates a threat's status, tags, or notes."""
    status: Optional[str] = None
    manual_tags: Optional[list[str]] = None
    analyst_notes: Optional[str] = None
