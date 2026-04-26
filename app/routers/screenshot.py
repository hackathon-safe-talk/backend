"""Screenshot capture and retrieval endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db, require_role
from app.models.admin_user import AdminUser, AdminRole
from app.models.threat import Threat
from app.services.screenshot_service import capture_screenshot
from app.services.storage_service import get_presigned_url, download_file
from app.services.audit_service import write_audit_log

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/threats/{threat_id}/check")
async def check_threat_url(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: AdminUser = Depends(require_role(AdminRole.ANALYST, AdminRole.SUPER_ADMIN)),
):
    """
    'Tekshirish' (Check) — navigate to the threat URL, take a screenshot,
    store in MinIO, and save the key on the threat record.
    """
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    url = threat.detected_url
    if not url:
        raise HTTPException(status_code=400, detail="Bu tahdidda URL mavjud emas")

    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    result = await capture_screenshot(url)

    if result["error"] and not result["screenshot_key"]:
        raise HTTPException(status_code=502, detail=result["error"])

    # Save screenshot key on the threat
    threat.screenshot_key = result["screenshot_key"]

    await write_audit_log(
        db,
        action="threat.screenshot_captured",
        entity_type="threat",
        entity_id=threat.id,
        user_id=current_user.id,
        details={
            "url": result["url"],
            "final_url": result["final_url"],
            "page_title": result["page_title"],
            "screenshot_key": result["screenshot_key"],
        },
    )

    await db.commit()

    # Generate presigned URL for immediate display
    screenshot_url = None
    if result["screenshot_key"]:
        try:
            screenshot_url = get_presigned_url(result["screenshot_key"])
        except Exception:
            pass

    return {
        "status": "ok",
        "url": result["url"],
        "final_url": result["final_url"],
        "page_title": result["page_title"],
        "screenshot_key": result["screenshot_key"],
        "screenshot_url": screenshot_url,
        "captured_at": result["captured_at"],
        "error": result["error"],
    }


# NOTE: This endpoint is intentionally public (no JWT auth) for two reasons:
# 1. Object keys contain random UUIDs, making URLs unguessable.
# 2. These images are rendered in <img> tags in the admin panel; browsers
#    cannot attach Authorization headers to <img src="...">, so requiring
#    JWT auth would break image display without a more complex token-in-URL
#    or cookie-based scheme.  The security trade-off is acceptable given the
#    UUID-based unguessability of the keys.
@router.get("/screenshot-image/{object_key:path}")
async def get_screenshot_image(object_key: str):
    """Proxy the screenshot image directly from MinIO.

    No auth required — object keys are random UUIDs so they are
    not guessable, and this avoids blob/CORS issues in the browser.
    """
    try:
        data = download_file(object_key)
        content_type = "image/png" if object_key.endswith(".png") else "image/jpeg"
        return Response(
            content=data,
            media_type=content_type,
            headers={"Cache-Control": "public, max-age=86400"},
        )
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Screenshot not found: {str(e)}")


@router.get("/screenshots/{object_key:path}")
async def get_screenshot_url(
    object_key: str,
    current_user: AdminUser = Depends(require_role(AdminRole.ANALYST, AdminRole.SUPER_ADMIN)),
):
    """Get a presigned URL to view a screenshot."""
    try:
        url = get_presigned_url(object_key)
        return {"url": url}
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Screenshot not found: {str(e)}")
