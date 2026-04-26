"""Base scanner with lifecycle management, sync SQLAlchemy session, and threat creation."""

import logging
import uuid
from datetime import datetime
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.config import settings
from app.models.scan_run import ScanRun, ScannerType, ScanRunStatus
from app.models.threat import Threat, ThreatSource, ThreatLabel, ThreatStatus
from app.services.tagging_service import apply_auto_tags

logger = logging.getLogger(__name__)

# Lazy sync engine for Celery workers (cannot use async in Celery tasks)
_sync_engine = None
_SyncSessionFactory = None


def _get_sync_engine():
    global _sync_engine, _SyncSessionFactory
    if _sync_engine is None:
        _sync_engine = create_engine(settings.DATABASE_URL_SYNC, echo=False)
        _SyncSessionFactory = sessionmaker(bind=_sync_engine, expire_on_commit=False)
    return _sync_engine


@contextmanager
def get_sync_session():
    """Provide a transactional sync session scope."""
    _get_sync_engine()
    session = _SyncSessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


class BaseScanner:
    """Base class for all scanners — handles ScanRun lifecycle and threat creation."""

    scanner_type: ScannerType = None
    threat_source: ThreatSource = None

    def __init__(self):
        self.scan_run: ScanRun | None = None
        self.session: Session | None = None
        self.threats_found = 0
        self.items_scanned = 0
        self.errors: list[str] = []

    def run(self):
        """Execute the scanner with full lifecycle management."""
        started_at = datetime.utcnow()
        with get_sync_session() as session:
            self.session = session

            # Create ScanRun record
            self.scan_run = ScanRun(
                id=uuid.uuid4(),
                scanner_type=self.scanner_type,
                status=ScanRunStatus.RUNNING,
                started_at=started_at,
            )
            session.add(self.scan_run)
            session.flush()

            try:
                self.execute(session)

                completed_at = datetime.utcnow()
                self.scan_run.status = ScanRunStatus.COMPLETED
                self.scan_run.completed_at = completed_at
                self.scan_run.duration_seconds = (completed_at - started_at).total_seconds()
                self.scan_run.threats_found = self.threats_found
                self.scan_run.items_scanned = self.items_scanned
                self.scan_run.errors = self.errors if self.errors else None

                logger.info(
                    f"[{self.scanner_type.value}] Completed: "
                    f"{self.items_scanned} scanned, {self.threats_found} threats found, "
                    f"{len(self.errors)} errors in {self.scan_run.duration_seconds:.1f}s"
                )

            except Exception as exc:
                completed_at = datetime.utcnow()
                self.scan_run.status = ScanRunStatus.FAILED
                self.scan_run.completed_at = completed_at
                self.scan_run.duration_seconds = (completed_at - started_at).total_seconds()
                self.scan_run.threats_found = self.threats_found
                self.scan_run.items_scanned = self.items_scanned
                self.errors.append(str(exc))
                self.scan_run.errors = self.errors
                logger.exception(f"[{self.scanner_type.value}] Failed: {exc}")

    def execute(self, session: Session):
        """Override in subclasses — perform the actual scanning logic."""
        raise NotImplementedError

    def create_scanner_threat(
        self,
        session: Session,
        *,
        message: str,
        risk_score: int,
        confidence: int = 80,
        label: ThreatLabel = ThreatLabel.DANGEROUS,
        detected_url: str | None = None,
        sender_name: str | None = None,
        source_app: str | None = None,
        detected_file_name: str | None = None,
        detected_file_type: str | None = None,
        reasons: list[str] | None = None,
        recommendations: list[str] | None = None,
        mobile_id: str | None = None,
    ) -> Threat:
        """Create a threat record from scanner findings with auto-tagging."""
        if mobile_id is None:
            mobile_id = f"scanner-{self.scanner_type.value}-{uuid.uuid4().hex[:12]}"

        threat = Threat(
            mobile_id=mobile_id,
            source=self.threat_source,
            message_truncated=message[:2000] if message else None,
            risk_score=risk_score,
            confidence=confidence,
            label=label,
            reasons=reasons or [],
            recommendations=recommendations or ["Domen/URL ni bloklang", "Xavfsizlik jamoasiga xabar bering"],
            detected_url=detected_url,
            sender_name=sender_name,
            source_app=source_app,
            detected_file_name=detected_file_name,
            detected_file_type=detected_file_type,
            device_id=None,
            status=ThreatStatus.NEW,
            received_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        session.add(threat)
        session.flush()

        # Apply auto-tags
        tags = apply_auto_tags(threat)
        threat.auto_tags = tags

        self.threats_found += 1
        return threat

    def get_brand_domains(self, session: Session) -> list[str]:
        """Get active brand domains from brand_assets table."""
        from app.models.brand_asset import BrandAsset, BrandAssetType
        results = session.query(BrandAsset).filter(
            BrandAsset.asset_type == BrandAssetType.DOMAIN,
            BrandAsset.is_active == True,
        ).all()
        return [r.value for r in results]

    def get_brand_keywords(self, session: Session) -> list[str]:
        """Get active brand keywords from brand_assets table."""
        from app.models.brand_asset import BrandAsset, BrandAssetType
        results = session.query(BrandAsset).filter(
            BrandAsset.asset_type == BrandAssetType.KEYWORD,
            BrandAsset.is_active == True,
        ).all()
        return [r.value for r in results]

    def get_custom_patterns(self, session: Session) -> list[tuple[str, str]]:
        """Get active scanner patterns: list of (regex_pattern, description)."""
        from app.models.scanner_pattern import ScannerPattern
        results = session.query(ScannerPattern).filter(
            ScannerPattern.is_active == True,
        ).all()
        return [(r.regex_pattern, r.description or r.pattern_type) for r in results]
