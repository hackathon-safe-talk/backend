"""Shared fixtures and factory helpers for all tests."""

import types
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.deps import get_db
from app.models.admin_user import AdminRole
from app.models.threat import ThreatSource, ThreatLabel, ThreatStatus
from app.services.auth_service import hash_password, create_access_token

TEST_PASSWORD = "TestPass123!"


def make_admin_user(
    role: AdminRole = AdminRole.SUPER_ADMIN,
    email: str = "admin@test.uz",
    is_active: bool = True,
) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=uuid.uuid4(),
        email=email,
        full_name="Test Admin",
        role=role,
        is_active=is_active,
        password_hash=hash_password(TEST_PASSWORD),
        created_at=datetime.utcnow(),
        last_login_at=None,
    )


def make_threat(
    mobile_id: str | None = None,
    risk_score: int = 85,
    label: ThreatLabel = ThreatLabel.DANGEROUS,
    source: ThreatSource = ThreatSource.AUTO_SMS,
    status: ThreatStatus = ThreatStatus.NEW,
    device_id: uuid.UUID | None = None,
) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=uuid.uuid4(),
        mobile_id=mobile_id or str(uuid.uuid4()),
        source=source,
        message_truncated="Sizning kartangiz bloklandi! https://fake-sqb.xyz/login",
        risk_score=risk_score,
        confidence=90,
        label=label,
        status=status,
        reasons=["suspicious_url"],
        recommendations=["block_sender"],
        sender_name="+998901234567",
        source_app="SMS",
        detected_file_name=None,
        detected_file_type=None,
        detected_url="https://fake-sqb.xyz/login",
        screenshot_key=None,
        auto_tags=["suspicious_tld", "phishing_keywords_in_url"],
        manual_tags=[],
        analyst_notes=None,
        device_id=device_id or uuid.uuid4(),
        actioned_by=None,
        actioned_at=None,
        received_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        analyzed_at_device=None,
        ai_analyses=[],
    )


def make_ai_analysis(
    threat_id: uuid.UUID,
    user_id: uuid.UUID,
) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=uuid.uuid4(),
        threat_id=threat_id,
        severity_assessment="high",
        threat_type="credential_phishing",
        analysis_text="This is a phishing site targeting SQB bank users.",
        recommended_actions=["block_url", "notify_users"],
        ioc_indicators={"urls": ["https://fake-sqb.xyz"], "domains": ["fake-sqb.xyz"]},
        similar_pattern_description="Classic Uzbek bank phishing",
        confidence_score=92,
        model_used="gemini-2.0-flash",
        requested_by=user_id,
        created_at=datetime.utcnow(),
    )


def make_token(user: types.SimpleNamespace) -> str:
    return create_access_token({
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
    })


def make_mock_db() -> AsyncMock:
    """Return a pre-wired async SQLAlchemy session mock."""
    session = AsyncMock()
    session.commit = AsyncMock(return_value=None)
    session.flush = AsyncMock(return_value=None)
    session.add = MagicMock(return_value=None)
    session.get = AsyncMock(return_value=None)

    default_scalars = MagicMock()
    default_scalars.unique.return_value.all.return_value = []
    default_scalars.all.return_value = []

    default_result = MagicMock()
    default_result.scalar_one_or_none.return_value = None
    default_result.scalar.return_value = 0
    default_result.scalars.return_value = default_scalars

    session.execute = AsyncMock(return_value=default_result)

    async def noop_refresh(obj):
        pass

    session.refresh = AsyncMock(side_effect=noop_refresh)
    return session


def make_execute_result(value) -> MagicMock:
    """Build a mock db.execute() result for scalar_one_or_none, scalar, or scalars."""
    scalars = MagicMock()
    scalars.unique.return_value.all.return_value = value if isinstance(value, list) else []
    scalars.all.return_value = value if isinstance(value, list) else []

    result = MagicMock()
    result.scalar_one_or_none.return_value = None if isinstance(value, list) else value
    result.scalar.return_value = value if isinstance(value, int) else 0
    result.scalars.return_value = scalars
    return result


@pytest.fixture
def mock_db():
    return make_mock_db()


@pytest_asyncio.fixture
async def client(mock_db):
    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user():
    return make_admin_user(role=AdminRole.SUPER_ADMIN)


@pytest.fixture
def analyst_user():
    return make_admin_user(role=AdminRole.ANALYST, email="analyst@test.uz")


@pytest.fixture
def viewer_user():
    return make_admin_user(role=AdminRole.VIEWER, email="viewer@test.uz")


@pytest.fixture
def admin_token(admin_user):
    return make_token(admin_user)


@pytest.fixture
def analyst_token(analyst_user):
    return make_token(analyst_user)


@pytest.fixture
def viewer_token(viewer_user):
    return make_token(viewer_user)
