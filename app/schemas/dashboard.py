from pydantic import BaseModel
from datetime import datetime


class DashboardStats(BaseModel):
    total_threats: int
    threats_today: int
    threats_this_week: int
    new_count: int
    confirmed_count: int
    false_positive_count: int
    actioned_count: int
    unique_devices: int
    top_risk_score: int
    avg_risk_score: float
    scanner_threats_total: int = 0
    scanner_threats_today: int = 0
    brand_assets_monitored: int = 0
    custom_patterns_active: int = 0
    total_scans_today: int = 0


class ThreatTrendPoint(BaseModel):
    date: str
    count: int
    dangerous: int
    suspicious: int


class TopSender(BaseModel):
    sender_name: str
    threat_count: int
    avg_risk_score: float
    latest_at: datetime


class TopUrl(BaseModel):
    url: str
    threat_count: int
    first_seen: datetime
    latest_seen: datetime


class TagDistribution(BaseModel):
    tag: str
    count: int


class SourceBreakdown(BaseModel):
    source: str
    count: int
