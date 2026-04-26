"""Integration tests for POST /api/v1/threats/bulk (mobile SDK ingest)."""

import time
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.threat import BulkSyncResponse


@pytest.fixture(autouse=True)
def bypass_rate_limiter():
    with patch("app.services.rate_limit_service.is_rate_limited", new_callable=AsyncMock, return_value=False):
        yield

DEVICE_HEADER = {"X-Device-Id": "test-device-uuid-001"}


def _item(mobile_id=None, risk_score=85, label="DANGEROUS", source="AUTO_SMS"):
    return {
        "id": mobile_id or str(uuid.uuid4()),
        "source": source,
        "messageTruncated": "Sizning kartangiz bloklandi! Havola: http://fake.xyz",
        "riskScore": risk_score,
        "confidence": 90,
        "label": label,
        "reasons": ["suspicious_url"],
        "recommendations": ["block"],
        "analyzedAt": int(time.time() * 1000),
        "senderName": "+998901234567",
        "sourceApp": "SMS",
        "detectedUrl": "http://fake-sqb.xyz/login",
    }


def _bulk_body(items=None, device_id=None, batch_id=None):
    return {
        "deviceId": device_id or str(uuid.uuid4()),
        "appVersion": "1.2.0",
        "batchId": batch_id or str(uuid.uuid4()),
        "items": items if items is not None else [_item()],
    }


class TestBulkIngest:
    async def test_success_accepted_count(self, client, mock_db):
        with patch(
            "app.routers.ingest.ingest_bulk",
            new_callable=AsyncMock,
            return_value=BulkSyncResponse(accepted=2, duplicates=0, batchId="b-1"),
        ):
            resp = await client.post(
                "/api/v1/threats/bulk",
                json=_bulk_body(items=[_item(), _item()]),
                headers=DEVICE_HEADER,
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 2
        assert data["duplicates"] == 0
        assert data["batchId"] == "b-1"

    async def test_deduplication_reported(self, client, mock_db):
        with patch(
            "app.routers.ingest.ingest_bulk",
            new_callable=AsyncMock,
            return_value=BulkSyncResponse(accepted=0, duplicates=1, batchId="b-2"),
        ):
            resp = await client.post(
                "/api/v1/threats/bulk",
                json=_bulk_body(),
                headers=DEVICE_HEADER,
            )

        assert resp.status_code == 200
        assert resp.json()["duplicates"] == 1

    async def test_missing_device_id_header_returns_422(self, client, mock_db):
        resp = await client.post("/api/v1/threats/bulk", json=_bulk_body())
        assert resp.status_code == 422

    async def test_empty_items_list_returns_422(self, client, mock_db):
        resp = await client.post(
            "/api/v1/threats/bulk",
            json=_bulk_body(items=[]),
            headers=DEVICE_HEADER,
        )
        assert resp.status_code == 422

    async def test_too_many_items_returns_422(self, client, mock_db):
        items = [_item() for _ in range(101)]
        resp = await client.post(
            "/api/v1/threats/bulk",
            json=_bulk_body(items=items),
            headers=DEVICE_HEADER,
        )
        assert resp.status_code == 422

    async def test_risk_score_above_100_returns_422(self, client, mock_db):
        resp = await client.post(
            "/api/v1/threats/bulk",
            json=_bulk_body(items=[_item(risk_score=150)]),
            headers=DEVICE_HEADER,
        )
        assert resp.status_code == 422

    async def test_risk_score_below_0_returns_422(self, client, mock_db):
        resp = await client.post(
            "/api/v1/threats/bulk",
            json=_bulk_body(items=[_item(risk_score=-1)]),
            headers=DEVICE_HEADER,
        )
        assert resp.status_code == 422

    async def test_mixed_accepted_and_duplicates(self, client, mock_db):
        with patch(
            "app.routers.ingest.ingest_bulk",
            new_callable=AsyncMock,
            return_value=BulkSyncResponse(accepted=3, duplicates=2, batchId="b-3"),
        ):
            resp = await client.post(
                "/api/v1/threats/bulk",
                json=_bulk_body(items=[_item() for _ in range(5)]),
                headers=DEVICE_HEADER,
            )

        data = resp.json()
        assert data["accepted"] == 3
        assert data["duplicates"] == 2

    async def test_no_auth_required(self, client, mock_db):
        """Ingest endpoint is intentionally public — no JWT needed."""
        with patch(
            "app.routers.ingest.ingest_bulk",
            new_callable=AsyncMock,
            return_value=BulkSyncResponse(accepted=1, duplicates=0, batchId="b-4"),
        ):
            resp = await client.post(
                "/api/v1/threats/bulk",
                json=_bulk_body(),
                headers=DEVICE_HEADER,
                # No Authorization header
            )
        assert resp.status_code == 200
