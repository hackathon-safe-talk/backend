"""Unit tests for the Redis sliding-window rate limiter."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import rate_limit_service


def _make_redis_mock(zcard_result: int = 0):
    """Return a mock Redis client whose pipeline executes cleanly."""
    pipe = AsyncMock()
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=False)
    pipe.zremrangebyscore = MagicMock()
    pipe.zcard = MagicMock()
    pipe.zadd = MagicMock()
    pipe.expire = MagicMock()
    # pipeline.execute() returns [removed_count, zcard_result, zadd_result, expire_result]
    pipe.execute = AsyncMock(return_value=[0, zcard_result, 1, True])

    redis = AsyncMock()
    redis.pipeline = MagicMock(return_value=pipe)
    redis.zremrangebyscore = AsyncMock(return_value=0)
    redis.zcard = AsyncMock(return_value=zcard_result)
    return redis


class TestIsRateLimited:
    async def test_allows_request_below_limit(self):
        redis = _make_redis_mock(zcard_result=3)
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            result = await rate_limit_service.is_rate_limited("test:key", limit=5, window_seconds=60)
        assert result is False

    async def test_blocks_request_at_limit(self):
        redis = _make_redis_mock(zcard_result=5)
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            result = await rate_limit_service.is_rate_limited("test:key", limit=5, window_seconds=60)
        assert result is True

    async def test_blocks_request_above_limit(self):
        redis = _make_redis_mock(zcard_result=10)
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            result = await rate_limit_service.is_rate_limited("test:key", limit=5, window_seconds=60)
        assert result is True

    async def test_fails_open_on_redis_error(self):
        redis = AsyncMock()
        redis.pipeline = MagicMock(side_effect=Exception("Redis connection refused"))
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            result = await rate_limit_service.is_rate_limited("test:key", limit=5, window_seconds=60)
        assert result is False  # fail open — don't block users when Redis is down


class TestGetEventCount:
    async def test_returns_current_count(self):
        redis = _make_redis_mock(zcard_result=3)
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            count = await rate_limit_service.get_event_count("test:key", window_seconds=300)
        assert count == 3

    async def test_returns_zero_on_redis_error(self):
        redis = AsyncMock()
        redis.pipeline = MagicMock(side_effect=Exception("timeout"))
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            count = await rate_limit_service.get_event_count("test:key", window_seconds=300)
        assert count == 0


class TestRecordEvent:
    async def test_records_without_raising(self):
        redis = _make_redis_mock()
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            # Should complete without raising
            await rate_limit_service.record_event("test:login_fail:1.2.3.4", window_seconds=300)

    async def test_silently_ignores_redis_error(self):
        redis = AsyncMock()
        redis.pipeline = MagicMock(side_effect=Exception("connection reset"))
        with patch.object(rate_limit_service, "get_redis_client", return_value=redis):
            # Should not raise even when Redis is down
            await rate_limit_service.record_event("test:key", window_seconds=300)


class TestGetRedisClient:
    def test_returns_singleton(self):
        # Reset singleton for clean test
        rate_limit_service._client = None
        client1 = rate_limit_service.get_redis_client()
        client2 = rate_limit_service.get_redis_client()
        assert client1 is client2
        rate_limit_service._client = None  # clean up
