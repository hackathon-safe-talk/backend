"""Integration tests for /api/v1/auth endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.admin_user import AdminRole
from app.services.auth_service import create_refresh_token
from tests.conftest import make_admin_user, make_execute_result, TEST_PASSWORD


@pytest.fixture(autouse=True)
def bypass_rate_limiter():
    """Patch Redis rate-limit calls so tests are not blocked by quota checks."""
    with patch("app.routers.auth.get_event_count", new_callable=AsyncMock, return_value=0), \
         patch("app.routers.auth.record_event", new_callable=AsyncMock), \
         patch("app.services.rate_limit_service.is_rate_limited", new_callable=AsyncMock, return_value=False):
        yield


class TestLogin:
    async def test_success_returns_tokens(self, client, mock_db, admin_user):
        mock_db.execute.return_value = make_execute_result(admin_user)

        resp = await client.post("/api/v1/auth/login", json={
            "email": admin_user.email,
            "password": TEST_PASSWORD,
        })

        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    async def test_wrong_password_returns_401(self, client, mock_db, admin_user):
        mock_db.execute.return_value = make_execute_result(admin_user)

        resp = await client.post("/api/v1/auth/login", json={
            "email": admin_user.email,
            "password": "completely_wrong_password",
        })

        assert resp.status_code == 401

    async def test_nonexistent_user_returns_401(self, client, mock_db):
        mock_db.execute.return_value = make_execute_result(None)

        resp = await client.post("/api/v1/auth/login", json={
            "email": "nobody@test.uz",
            "password": "somepassword",
        })

        assert resp.status_code == 401

    async def test_inactive_user_returns_403(self, client, mock_db):
        inactive = make_admin_user(is_active=False)
        mock_db.execute.return_value = make_execute_result(inactive)

        resp = await client.post("/api/v1/auth/login", json={
            "email": inactive.email,
            "password": TEST_PASSWORD,
        })

        assert resp.status_code == 403

    async def test_missing_password_field_returns_422(self, client, mock_db):
        resp = await client.post("/api/v1/auth/login", json={"email": "x@y.uz"})
        assert resp.status_code == 422

    async def test_missing_email_field_returns_422(self, client, mock_db):
        resp = await client.post("/api/v1/auth/login", json={"password": "test"})
        assert resp.status_code == 422

    async def test_rate_limit_triggered_returns_429(self, client, mock_db):
        # Simulate Redis reporting the failure count is already at the limit
        with patch("app.routers.auth.get_event_count", new_callable=AsyncMock, return_value=5):
            resp = await client.post("/api/v1/auth/login", json={
                "email": "x@y.uz",
                "password": "wrong",
            })
        assert resp.status_code == 429
        assert "Too many failed login attempts" in resp.json()["detail"]


class TestRefresh:
    async def test_valid_refresh_token_returns_new_tokens(self, client, mock_db, admin_user):
        refresh_token = create_refresh_token({
            "sub": str(admin_user.id),
            "email": admin_user.email,
            "role": admin_user.role.value,
        })
        mock_db.get.return_value = admin_user

        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

        assert resp.status_code == 200
        assert "access_token" in resp.json()
        assert "refresh_token" in resp.json()

    async def test_access_token_as_refresh_returns_401(self, client, mock_db, admin_token):
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": admin_token})
        assert resp.status_code == 401

    async def test_invalid_token_returns_401(self, client, mock_db):
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": "not.a.real.token"})
        assert resp.status_code == 401

    async def test_inactive_user_returns_401(self, client, mock_db):
        inactive = make_admin_user(is_active=False)
        refresh_token = create_refresh_token({
            "sub": str(inactive.id),
            "email": inactive.email,
            "role": inactive.role.value,
        })
        mock_db.get.return_value = inactive

        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 401


class TestMe:
    async def test_authenticated_returns_user_info(self, client, mock_db, admin_user, admin_token):
        mock_db.get.return_value = admin_user

        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == admin_user.email
        assert data["role"] == admin_user.role.value
        assert data["is_active"] is True

    async def test_no_token_returns_401(self, client, mock_db):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_invalid_token_returns_401(self, client, mock_db):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid.token.value"},
        )
        assert resp.status_code == 401

    async def test_analyst_role_is_returned(self, client, mock_db, analyst_user, analyst_token):
        mock_db.get.return_value = analyst_user

        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 200
        assert resp.json()["role"] == "analyst"
