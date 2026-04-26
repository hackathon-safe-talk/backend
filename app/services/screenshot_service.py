"""Website screenshot capture service using Playwright."""

import asyncio
import logging
import uuid
from datetime import datetime

from app.services.storage_service import upload_file

logger = logging.getLogger(__name__)


async def capture_screenshot(url: str) -> dict:
    """
    Navigate to a URL with Playwright, take a full-page screenshot,
    upload to MinIO, and return metadata.
    """
    from playwright.async_api import async_playwright

    object_name = f"screenshots/{uuid.uuid4()}.png"
    screenshot_data = None
    page_title = ""
    final_url = url
    error_msg = None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
            page = await context.new_page()

            # Navigate with timeout
            try:
                await page.goto(url, wait_until="networkidle", timeout=15000)
            except Exception:
                # Fallback: try with just domcontentloaded
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                except Exception as nav_err:
                    error_msg = f"Navigation failed: {str(nav_err)}"
                    logger.warning(f"Screenshot navigation failed for {url}: {nav_err}")

            if not error_msg:
                # Wait a bit for any remaining JS rendering
                await asyncio.sleep(1)

                page_title = await page.title()
                final_url = page.url

                # Take screenshot
                screenshot_data = await page.screenshot(
                    full_page=False,
                    type="png",
                )

            await browser.close()

    except Exception as e:
        error_msg = f"Screenshot capture failed: {str(e)}"
        logger.error(f"Screenshot error for {url}: {e}")

    result = {
        "url": url,
        "final_url": final_url,
        "page_title": page_title,
        "captured_at": datetime.utcnow().isoformat(),
        "error": error_msg,
        "screenshot_key": None,
        "screenshot_size": 0,
    }

    if screenshot_data:
        # Upload to MinIO
        upload_file(object_name, screenshot_data, content_type="image/png")
        result["screenshot_key"] = object_name
        result["screenshot_size"] = len(screenshot_data)

    return result
