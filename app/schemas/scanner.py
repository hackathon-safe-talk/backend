from pydantic import BaseModel
from datetime import datetime


class ScannerStatusItem(BaseModel):
    type: str
    display_name: str
    schedule: str
    last_run: datetime | None = None
    last_status: str | None = None
    last_duration_seconds: float | None = None
    last_threats_found: int = 0
    last_items_scanned: int = 0
    total_threats_found: int = 0
    total_scans: int = 0
    success_rate: float = 0.0
    health: str = "unknown"


class ScannerOverview(BaseModel):
    scanners: list[ScannerStatusItem]
    overall: dict


class ScanRunResponse(BaseModel):
    id: str
    scanner_type: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    threats_found: int = 0
    items_scanned: int = 0
    errors: list | dict | None = None
    details: dict | None = None


class ScanRunHistory(BaseModel):
    items: list[ScanRunResponse]
    total: int


class TriggerResponse(BaseModel):
    task_id: str
    message: str


class DiscoveredDomainResponse(BaseModel):
    id: str
    domain: str
    status: str
    source: str
    ip_address: str | None = None
    dns_resolved: bool = False
    risk_score: int | None = None
    matched_brand: str | None = None
    matched_pattern: str | None = None
    similarity_score: float | None = None
    ssl_issuer: str | None = None
    ssl_issued_at: datetime | None = None
    first_seen_at: datetime
    last_checked_at: datetime
    check_count: int = 1
    threat_id: str | None = None
    notes: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None


class DiscoveredDomainList(BaseModel):
    items: list[DiscoveredDomainResponse]
    total: int


class DiscoveredDomainUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None
