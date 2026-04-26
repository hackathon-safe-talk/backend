"""Dependency injection — DB sessions, auth guards, and rate limiting."""

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.services.auth_service import decode_token
from app.services.rate_limit_service import is_rate_limited
from app.models.admin_user import AdminUser, AdminRole

security = HTTPBearer(auto_error=False)


async def get_db():
    async with async_session_factory() as session:
        yield session


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await db.get(AdminUser, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def require_role(*roles: AdminRole):
    """Dependency factory that checks the admin user has one of the required roles."""
    async def checker(user: AdminUser = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker


def rate_limit(limit: int, window_seconds: int, key_prefix: str = "api"):
    """
    Dependency factory — sliding window rate limit keyed by client IP.

    Usage:
        @router.post("/path", dependencies=[Depends(rate_limit(20, 60, "ai"))])
    """
    async def _check(request: Request):
        ip = request.client.host if request.client else "unknown"
        key = f"rl:{key_prefix}:{ip}"
        if await is_rate_limited(key, limit, window_seconds):
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(window_seconds)},
            )
    return _check
