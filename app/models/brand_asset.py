import enum
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Enum as SAEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class BrandAssetType(str, enum.Enum):
    DOMAIN = "domain"
    APP_NAME = "app_name"
    APP_PACKAGE = "app_package"
    SOCIAL_HANDLE = "social_handle"
    KEYWORD = "keyword"


class BrandAsset(Base):
    __tablename__ = "brand_assets"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_type = Column(SAEnum(BrandAssetType), nullable=False)
    value = Column(String(500), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("admin_users.id"), nullable=True)
