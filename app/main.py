"""SafeTalk DRP Backend — FastAPI application entry point."""

import logging
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.config import settings
from app.database import engine, Base, async_session_factory
from app.routers import ingest, threats, auth, ai, dashboard, devices, audit, tags, scanners, brand_assets, screenshot, report
from app.services.rate_limit_service import is_rate_limited

# Import all models so Base.metadata knows about them
from app.models import Threat, Device, AdminUser, AIAnalysis, AuditLog  # noqa: F401
from app.models import ScanRun, BrandAsset, ScannerPattern, DiscoveredDomain  # noqa: F401
from app.models.admin_user import AdminRole
from app.services.auth_service import hash_password

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Silence noisy HTTP client loggers (they dump full request bodies incl. base64 images)
logging.getLogger("anthropic").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


async def _seed_admin():
    """Create default admin user if none exists; fix stale hash if needed."""
    async with async_session_factory() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.email == "admin@sqb.uz")
        )
        existing = result.scalar_one_or_none()
        if existing:
            # Fix stale password hash (e.g. bcrypt from a previous run)
            if not existing.password_hash.startswith("$pbkdf2-sha256$"):
                logger.warning("[seed] Admin has stale hash format, re-hashing password.")
                existing.password_hash = hash_password("SafeTalk2026!")
                await session.commit()
                logger.info("[seed] Admin password re-hashed to pbkdf2_sha256.")
            else:
                logger.info("[seed] Admin user already exists, skipping.")
            return

        admin = AdminUser(
            email="admin@sqb.uz",
            password_hash=hash_password("SafeTalk2026!"),
            full_name="SQB Admin",
            role=AdminRole.SUPER_ADMIN,
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        logger.info("[seed] Created default admin user")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables if not exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Seed default admin
    await _seed_admin()
    yield
    # Shutdown
    await engine.dispose()


app = FastAPI(
    title="SafeTalk DRP API",
    description="Digital Risk Protection backend for SafeTalk mobile SDK",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def global_rate_limit_middleware(request: Request, call_next):
    """300 requests / minute per IP across all /api/v1/* routes."""
    if request.url.path.startswith("/api/v1/"):
        ip = request.client.host if request.client else "unknown"
        if await is_rate_limited(f"rl:global:{ip}", 300, 60):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."},
                headers={"Retry-After": "60"},
            )
    return await call_next(request)

# Public routes (no auth)
app.include_router(ingest.router, prefix="/api/v1", tags=["Ingest"])

# Protected routes (JWT required)
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["Threats"])
app.include_router(ai.router, prefix="/api/v1/ai", tags=["AI Analysis"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(devices.router, prefix="/api/v1/devices", tags=["Devices"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["Audit"])
app.include_router(tags.router, prefix="/api/v1/tags", tags=["Tags"])
app.include_router(scanners.router, prefix="/api/v1/scanners", tags=["Scanners"])
app.include_router(brand_assets.router, prefix="/api/v1/brand-assets", tags=["Brand Assets"])
app.include_router(screenshot.router, prefix="/api/v1", tags=["Screenshots"])
app.include_router(report.router, prefix="/api/v1", tags=["Reports"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error(f"Unhandled error on {request.method} {request.url.path}:\n{tb}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {type(exc).__name__}: {str(exc)}"},
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "safetalk-drp"}
