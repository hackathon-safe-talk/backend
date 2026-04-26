"""Mobile app ingestion endpoint — NO JWT auth, uses X-Device-Id header."""

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import Depends
from app.deps import get_db, rate_limit
from app.schemas.threat import BulkSyncRequest, BulkSyncResponse
from app.services.threat_service import ingest_bulk

router = APIRouter()


@router.post("/threats/bulk", response_model=BulkSyncResponse, dependencies=[Depends(rate_limit(120, 60, "ingest"))])
async def bulk_sync(
    body: BulkSyncRequest,
    request: Request,
    x_device_id: str = Header(..., alias="X-Device-Id"),
    db: AsyncSession = Depends(get_db),
):
    """
    Receive a batch of threats from a SafeTalk Android device.

    - No JWT auth — identified by X-Device-Id header
    - Deduplicates by mobile_id
    - Runs rule-based auto-tagging (no AI)
    """
    client_ip = request.client.host if request.client else None
    result = await ingest_bulk(db, body, client_ip=client_ip)
    return result
