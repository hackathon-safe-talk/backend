"""Admin authentication — login, refresh, profile."""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db, get_current_user
from app.models.admin_user import AdminUser
from app.schemas.auth import LoginRequest, TokenResponse, RefreshRequest, AdminUserResponse
from app.services.auth_service import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.services.audit_service import write_audit_log
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    logger.info(f"Login attempt for email: {body.email}")

    result = await db.execute(
        select(AdminUser).where(AdminUser.email == body.email)
    )
    user = result.scalar_one_or_none()
    logger.info(f"User found: {user is not None}")

    if not user:
        logger.warning(f"No user found for email: {body.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    logger.info(f"Password hash from DB: {user.password_hash[:30]}...")
    password_ok = verify_password(body.password, user.password_hash)
    logger.info(f"Password verification result: {password_ok}")

    if not password_ok:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Update last login
    user.last_login_at = datetime.utcnow()

    # Audit log
    client_ip = request.client.host if request.client else None
    await write_audit_log(
        db,
        action="user.login",
        entity_type="user",
        entity_id=user.id,
        user_id=user.id,
        ip_address=client_ip,
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_id = payload.get("sub")
    user = await db.get(AdminUser, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
    }

    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=AdminUserResponse)
async def me(current_user: AdminUser = Depends(get_current_user)):
    return AdminUserResponse(
        id=str(current_user.id),
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role.value,
        is_active=current_user.is_active,
        last_login_at=current_user.last_login_at,
    )
