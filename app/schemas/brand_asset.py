from pydantic import BaseModel
from datetime import datetime


class BrandAssetCreate(BaseModel):
    asset_type: str
    value: str


class BrandAssetResponse(BaseModel):
    id: str
    asset_type: str
    value: str
    is_active: bool
    created_at: datetime


class ScannerPatternCreate(BaseModel):
    pattern_type: str
    regex_pattern: str
    description: str | None = None


class ScannerPatternUpdate(BaseModel):
    regex_pattern: str | None = None
    description: str | None = None
    is_active: bool | None = None


class ScannerPatternResponse(BaseModel):
    id: str
    pattern_type: str
    regex_pattern: str
    description: str | None = None
    is_active: bool
    created_at: datetime
    matches_found: int = 0
    last_matched_at: datetime | None = None
