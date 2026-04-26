"""Integration tests for /api/v1/threats endpoints."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.threat import ThreatStatus
from tests.conftest import make_threat, make_execute_result


@pytest.fixture(autouse=True)
def bypass_rate_limiter():
    with patch("app.services.rate_limit_service.is_rate_limited", new_callable=AsyncMock, return_value=False):
        yield


class TestListThreats:
    async def test_authenticated_returns_200(self, client, mock_db, admin_user, admin_token):
        mock_db.get.return_value = admin_user
        mock_db.execute.side_effect = [
            make_execute_result(0),   # COUNT query
            make_execute_result([]),  # items query
        ]

        resp = await client.get(
            "/api/v1/threats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert data["total"] == 0
        assert data["items"] == []

    async def test_unauthenticated_returns_401(self, client, mock_db):
        resp = await client.get("/api/v1/threats")
        assert resp.status_code == 401

    async def test_returns_threat_list(self, client, mock_db, admin_user, admin_token):
        threat = make_threat()
        mock_db.get.return_value = admin_user
        mock_db.execute.side_effect = [
            make_execute_result(1),
            make_execute_result([threat]),
        ]

        resp = await client.get(
            "/api/v1/threats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["mobile_id"] == threat.mobile_id
        assert data["items"][0]["risk_score"] == threat.risk_score

    async def test_pagination_defaults(self, client, mock_db, admin_user, admin_token):
        mock_db.get.return_value = admin_user
        mock_db.execute.side_effect = [make_execute_result(0), make_execute_result([])]

        resp = await client.get(
            "/api/v1/threats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        data = resp.json()
        assert data["page"] == 1
        assert data["page_size"] == 20

    async def test_custom_pagination(self, client, mock_db, admin_user, admin_token):
        mock_db.get.return_value = admin_user
        mock_db.execute.side_effect = [make_execute_result(0), make_execute_result([])]

        resp = await client.get(
            "/api/v1/threats?page=3&page_size=5",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        data = resp.json()
        assert data["page"] == 3
        assert data["page_size"] == 5

    async def test_invalid_sort_by_returns_422(self, client, mock_db, admin_user, admin_token):
        mock_db.get.return_value = admin_user

        resp = await client.get(
            "/api/v1/threats?sort_by=not_a_real_column",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 422

    async def test_viewer_can_list(self, client, mock_db, viewer_user, viewer_token):
        mock_db.get.return_value = viewer_user
        mock_db.execute.side_effect = [make_execute_result(0), make_execute_result([])]

        resp = await client.get(
            "/api/v1/threats",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )

        assert resp.status_code == 200

    async def test_total_pages_calculated(self, client, mock_db, admin_user, admin_token):
        mock_db.get.return_value = admin_user
        mock_db.execute.side_effect = [make_execute_result(45), make_execute_result([])]

        resp = await client.get(
            "/api/v1/threats?page_size=10",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.json()["total_pages"] == 5


class TestGetThreat:
    async def test_found_returns_threat(self, client, mock_db, admin_user, admin_token):
        threat = make_threat()
        mock_db.get.return_value = admin_user
        mock_db.execute.return_value = make_execute_result(threat)

        resp = await client.get(
            f"/api/v1/threats/{threat.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(threat.id)
        assert data["label"] == threat.label.value
        assert data["status"] == threat.status.value

    async def test_not_found_returns_404(self, client, mock_db, admin_user, admin_token):
        mock_db.get.return_value = admin_user
        mock_db.execute.return_value = make_execute_result(None)

        resp = await client.get(
            f"/api/v1/threats/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 404

    async def test_unauthenticated_returns_401(self, client, mock_db):
        resp = await client.get(f"/api/v1/threats/{uuid.uuid4()}")
        assert resp.status_code == 401


class TestUpdateThreat:
    async def test_analyst_can_update_status(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        mock_db.get.return_value = analyst_user
        mock_db.execute.return_value = make_execute_result(threat)

        resp = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"status": "confirmed"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 200
        assert threat.status == ThreatStatus.CONFIRMED

    async def test_super_admin_can_update_status(self, client, mock_db, admin_user, admin_token):
        threat = make_threat()
        mock_db.get.return_value = admin_user
        mock_db.execute.return_value = make_execute_result(threat)

        resp = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"status": "false_positive"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert resp.status_code == 200
        assert threat.status == ThreatStatus.FALSE_POSITIVE

    async def test_viewer_cannot_update_returns_403(self, client, mock_db, viewer_user, viewer_token):
        mock_db.get.return_value = viewer_user

        resp = await client.patch(
            f"/api/v1/threats/{uuid.uuid4()}",
            json={"status": "confirmed"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )

        assert resp.status_code == 403

    async def test_update_manual_tags(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        mock_db.get.return_value = analyst_user
        mock_db.execute.return_value = make_execute_result(threat)

        resp = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"manual_tags": ["confirmed_phishing", "high_priority"]},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 200
        assert threat.manual_tags == ["confirmed_phishing", "high_priority"]

    async def test_update_analyst_notes(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        mock_db.get.return_value = analyst_user
        mock_db.execute.return_value = make_execute_result(threat)

        notes = "Confirmed phishing page impersonating SQB bank login"
        resp = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"analyst_notes": notes},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 200
        assert threat.analyst_notes == notes

    async def test_threat_not_found_returns_404(self, client, mock_db, analyst_user, analyst_token):
        mock_db.get.return_value = analyst_user
        mock_db.execute.return_value = make_execute_result(None)

        resp = await client.patch(
            f"/api/v1/threats/{uuid.uuid4()}",
            json={"status": "confirmed"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 404

    async def test_actioned_status_sets_actioned_by(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        mock_db.get.return_value = analyst_user
        mock_db.execute.return_value = make_execute_result(threat)

        await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"status": "actioned"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert threat.actioned_by == analyst_user.id

    async def test_unauthenticated_returns_401(self, client, mock_db):
        resp = await client.patch(
            f"/api/v1/threats/{uuid.uuid4()}",
            json={"status": "confirmed"},
        )
        assert resp.status_code == 401
