"""Brand asset and scanner pattern management endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db, get_current_user
from app.models.admin_user import AdminUser
from app.models.brand_asset import BrandAsset, BrandAssetType
from app.models.scanner_pattern import ScannerPattern
from app.schemas.brand_asset import (
    BrandAssetCreate,
    BrandAssetResponse,
    ScannerPatternCreate,
    ScannerPatternUpdate,
    ScannerPatternResponse,
)

router = APIRouter()


# ── Brand Assets ──────────────────────────────────────────────────────────


@router.get("/", response_model=list[BrandAssetResponse])
async def list_brand_assets(
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """List all brand assets."""
    result = await db.execute(
        select(BrandAsset).order_by(BrandAsset.created_at.desc())
    )
    assets = result.scalars().all()
    return [
        BrandAssetResponse(
            id=str(a.id),
            asset_type=a.asset_type.value,
            value=a.value,
            is_active=a.is_active,
            created_at=a.created_at,
        )
        for a in assets
    ]


@router.post("/", response_model=BrandAssetResponse, status_code=201)
async def create_brand_asset(
    data: BrandAssetCreate,
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Create a new brand asset."""
    try:
        asset_type = BrandAssetType(data.asset_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid asset_type: {data.asset_type}. Valid: {[t.value for t in BrandAssetType]}",
        )

    asset = BrandAsset(
        asset_type=asset_type,
        value=data.value,
        created_by=user.id,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    return BrandAssetResponse(
        id=str(asset.id),
        asset_type=asset.asset_type.value,
        value=asset.value,
        is_active=asset.is_active,
        created_at=asset.created_at,
    )


@router.delete("/{asset_id}", status_code=204)
async def delete_brand_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Delete a brand asset."""
    result = await db.execute(select(BrandAsset).where(BrandAsset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Brand asset not found")

    await db.delete(asset)
    await db.commit()


# ── Scanner Patterns ──────────────────────────────────────────────────────


@router.get("/patterns", response_model=list[ScannerPatternResponse])
async def list_patterns(
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """List all scanner patterns."""
    result = await db.execute(
        select(ScannerPattern).order_by(ScannerPattern.created_at.desc())
    )
    patterns = result.scalars().all()
    return [
        ScannerPatternResponse(
            id=str(p.id),
            pattern_type=p.pattern_type,
            regex_pattern=p.regex_pattern,
            description=p.description,
            is_active=p.is_active,
            created_at=p.created_at,
            matches_found=p.matches_found,
            last_matched_at=p.last_matched_at,
        )
        for p in patterns
    ]


@router.post("/patterns", response_model=ScannerPatternResponse, status_code=201)
async def create_pattern(
    data: ScannerPatternCreate,
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Create a new scanner pattern."""
    # Validate regex
    import re
    try:
        re.compile(data.regex_pattern)
    except re.error as exc:
        raise HTTPException(status_code=400, detail=f"Invalid regex: {exc}")

    pattern = ScannerPattern(
        pattern_type=data.pattern_type,
        regex_pattern=data.regex_pattern,
        description=data.description,
        created_by=user.id,
    )
    db.add(pattern)
    await db.commit()
    await db.refresh(pattern)

    return ScannerPatternResponse(
        id=str(pattern.id),
        pattern_type=pattern.pattern_type,
        regex_pattern=pattern.regex_pattern,
        description=pattern.description,
        is_active=pattern.is_active,
        created_at=pattern.created_at,
        matches_found=pattern.matches_found,
        last_matched_at=pattern.last_matched_at,
    )


@router.patch("/patterns/{pattern_id}", response_model=ScannerPatternResponse)
async def update_pattern(
    pattern_id: str,
    data: ScannerPatternUpdate,
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Update a scanner pattern."""
    result = await db.execute(select(ScannerPattern).where(ScannerPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    if data.regex_pattern is not None:
        import re
        try:
            re.compile(data.regex_pattern)
        except re.error as exc:
            raise HTTPException(status_code=400, detail=f"Invalid regex: {exc}")
        pattern.regex_pattern = data.regex_pattern

    if data.description is not None:
        pattern.description = data.description

    if data.is_active is not None:
        pattern.is_active = data.is_active

    await db.commit()
    await db.refresh(pattern)

    return ScannerPatternResponse(
        id=str(pattern.id),
        pattern_type=pattern.pattern_type,
        regex_pattern=pattern.regex_pattern,
        description=pattern.description,
        is_active=pattern.is_active,
        created_at=pattern.created_at,
        matches_found=pattern.matches_found,
        last_matched_at=pattern.last_matched_at,
    )


@router.delete("/patterns/{pattern_id}", status_code=204)
async def delete_pattern(
    pattern_id: str,
    db: AsyncSession = Depends(get_db),
    user: AdminUser = Depends(get_current_user),
):
    """Delete a scanner pattern."""
    result = await db.execute(select(ScannerPattern).where(ScannerPattern.id == pattern_id))
    pattern = result.scalar_one_or_none()
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    await db.delete(pattern)
    await db.commit()
