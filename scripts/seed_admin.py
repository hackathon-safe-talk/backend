"""Create the default admin user (idempotent — skips if exists). Async version."""

import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select

from app.database import engine, Base, async_session_factory
from app.models.admin_user import AdminUser, AdminRole
from app.services.auth_service import hash_password


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.email == "admin@sqb.uz")
        )
        if result.scalar_one_or_none():
            print("[seed_admin] Admin user already exists, skipping.")
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
        print("[seed_admin] Created admin user: admin@sqb.uz / SafeTalk2026!")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed())
