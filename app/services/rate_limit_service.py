"""Redis-based sliding window rate limiter.

Uses a sorted set per key: members are request timestamps, score = timestamp.
Fails open (allows the request) if Redis is unreachable so a Redis outage
cannot lock out all users.
"""

import logging
import time

from redis.asyncio import Redis

from app.config import settings

logger = logging.getLogger(__name__)

_client: Redis | None = None


def get_redis_client() -> Redis:
    global _client
    if _client is None:
        _client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _client


async def _pipeline_sliding_window(
    key: str,
    window_seconds: int,
) -> int:
    """Remove stale entries and return the current count. Does NOT add a new entry."""
    redis = get_redis_client()
    cutoff = time.time() - window_seconds
    async with redis.pipeline(transaction=True) as pipe:
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zcard(key)
        results = await pipe.execute()
    return results[1]


async def get_event_count(key: str, window_seconds: int) -> int:
    """Return the number of recorded events in the sliding window (read-only)."""
    try:
        return await _pipeline_sliding_window(key, window_seconds)
    except Exception as e:
        logger.warning("rate_limit get_event_count error (failing open): %s", e)
        return 0


async def record_event(key: str, window_seconds: int) -> None:
    """Append one event timestamp to the sorted set and refresh the TTL."""
    try:
        redis = get_redis_client()
        now = time.time()
        cutoff = now - window_seconds
        async with redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, 0, cutoff)
            # Use a unique member so simultaneous requests don't collide
            pipe.zadd(key, {f"{now}:{id(pipe)}": now})
            pipe.expire(key, window_seconds + 1)
            await pipe.execute()
    except Exception as e:
        logger.warning("rate_limit record_event error: %s", e)


async def is_rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    """
    Check whether the key has reached its limit, then record this request.
    Returns True (blocked) or False (allowed).
    Fails open on Redis errors.
    """
    try:
        redis = get_redis_client()
        now = time.time()
        cutoff = now - window_seconds
        async with redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, 0, cutoff)
            pipe.zcard(key)
            pipe.zadd(key, {f"{now}:{id(pipe)}": now})
            pipe.expire(key, window_seconds + 1)
            results = await pipe.execute()
        count_before = results[1]
        return count_before >= limit
    except Exception as e:
        logger.warning("rate_limit is_rate_limited error (failing open): %s", e)
        return False
