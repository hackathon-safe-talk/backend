"""Integration tests for /api/v1/ai endpoints."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest import make_threat, make_ai_analysis, make_execute_result


@pytest.fixture(autouse=True)
def bypass_rate_limiter():
    with patch("app.services.rate_limit_service.is_rate_limited", new_callable=AsyncMock, return_value=False):
        yield


class TestTriggerAnalysis:
    async def test_success(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        analysis = make_ai_analysis(threat.id, analyst_user.id)
        mock_db.get.side_effect = [analyst_user, threat]

        with patch(
            "app.routers.ai.analyze_threat_with_ai",
            new_callable=AsyncMock,
            return_value=analysis,
        ):
            resp = await client.post(
                "/api/v1/ai/analyze",
                json={"threat_id": str(threat.id)},
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_id"] == str(threat.id)
        assert data["severity_assessment"] == "high"
        assert data["threat_type"] == "credential_phishing"
        assert data["confidence_score"] == 92
        assert data["model_used"] == "gemini-2.0-flash"

    async def test_super_admin_can_trigger(self, client, mock_db, admin_user, admin_token):
        threat = make_threat()
        analysis = make_ai_analysis(threat.id, admin_user.id)
        mock_db.get.side_effect = [admin_user, threat]

        with patch(
            "app.routers.ai.analyze_threat_with_ai",
            new_callable=AsyncMock,
            return_value=analysis,
        ):
            resp = await client.post(
                "/api/v1/ai/analyze",
                json={"threat_id": str(threat.id)},
                headers={"Authorization": f"Bearer {admin_token}"},
            )

        assert resp.status_code == 200

    async def test_threat_not_found_returns_404(self, client, mock_db, analyst_user, analyst_token):
        mock_db.get.side_effect = [analyst_user, None]

        resp = await client.post(
            "/api/v1/ai/analyze",
            json={"threat_id": str(uuid.uuid4())},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 404

    async def test_gemini_quota_exceeded_returns_502(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        mock_db.get.side_effect = [analyst_user, threat]

        with patch(
            "app.routers.ai.analyze_threat_with_ai",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Gemini API error 429: quota exceeded"),
        ):
            resp = await client.post(
                "/api/v1/ai/analyze",
                json={"threat_id": str(threat.id)},
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert resp.status_code == 502
        assert "AI analysis failed" in resp.json()["detail"]

    async def test_generic_ai_failure_returns_502(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        mock_db.get.side_effect = [analyst_user, threat]

        with patch(
            "app.routers.ai.analyze_threat_with_ai",
            new_callable=AsyncMock,
            side_effect=Exception("Connection timeout"),
        ):
            resp = await client.post(
                "/api/v1/ai/analyze",
                json={"threat_id": str(threat.id)},
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert resp.status_code == 502

    async def test_viewer_cannot_trigger_returns_403(self, client, mock_db, viewer_user, viewer_token):
        mock_db.get.return_value = viewer_user

        resp = await client.post(
            "/api/v1/ai/analyze",
            json={"threat_id": str(uuid.uuid4())},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )

        assert resp.status_code == 403

    async def test_unauthenticated_returns_401(self, client, mock_db):
        resp = await client.post(
            "/api/v1/ai/analyze",
            json={"threat_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 401

    async def test_missing_threat_id_returns_422(self, client, mock_db, analyst_user, analyst_token):
        mock_db.get.return_value = analyst_user

        resp = await client.post(
            "/api/v1/ai/analyze",
            json={},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 422

    async def test_analysis_includes_additional_context(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        analysis = make_ai_analysis(threat.id, analyst_user.id)
        mock_db.get.side_effect = [analyst_user, threat]

        captured_kwargs = {}

        async def capture_call(threat, additional_context=None, requested_by=""):
            captured_kwargs["additional_context"] = additional_context
            return analysis

        with patch("app.routers.ai.analyze_threat_with_ai", side_effect=capture_call):
            await client.post(
                "/api/v1/ai/analyze",
                json={"threat_id": str(threat.id), "additional_context": "Analyst note: looks like SQB fake"},
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert captured_kwargs["additional_context"] == "Analyst note: looks like SQB fake"


class TestGetAnalyses:
    async def test_returns_analysis_list(self, client, mock_db, analyst_user, analyst_token):
        threat = make_threat()
        analysis = make_ai_analysis(threat.id, analyst_user.id)
        mock_db.get.return_value = analyst_user

        result = MagicMock()
        scalars = MagicMock()
        scalars.all.return_value = [analysis]
        result.scalars.return_value = scalars
        mock_db.execute.return_value = result

        resp = await client.get(
            f"/api/v1/ai/analyses/{threat.id}",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["threat_id"] == str(threat.id)
        assert data[0]["severity_assessment"] == "high"

    async def test_returns_empty_list_when_no_analyses(self, client, mock_db, analyst_user, analyst_token):
        mock_db.get.return_value = analyst_user

        result = MagicMock()
        scalars = MagicMock()
        scalars.all.return_value = []
        result.scalars.return_value = scalars
        mock_db.execute.return_value = result

        resp = await client.get(
            f"/api/v1/ai/analyses/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )

        assert resp.status_code == 200
        assert resp.json() == []

    async def test_viewer_cannot_read_analyses_returns_403(self, client, mock_db, viewer_user, viewer_token):
        mock_db.get.return_value = viewer_user

        resp = await client.get(
            f"/api/v1/ai/analyses/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )

        assert resp.status_code == 403

    async def test_unauthenticated_returns_401(self, client, mock_db):
        resp = await client.get(f"/api/v1/ai/analyses/{uuid.uuid4()}")
        assert resp.status_code == 401
