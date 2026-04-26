"""Social media scanner — detects fake accounts and impersonation (simulated for hackathon)."""

import logging
import re
from datetime import datetime, timedelta

from app.celery_app import celery
from app.models.scan_run import ScannerType
from app.models.threat import ThreatSource, ThreatLabel
from app.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Simulated social media findings for hackathon demo
SIMULATED_FINDINGS = [
    {
        "platform": "Telegram",
        "account": "@sqb_support_bot",
        "display_name": "SQB Bank Yordam",
        "url": "https://t.me/sqb_support_bot",
        "description": "Telegram bot SQB Bank qo'llab-quvvatlash xizmatini taqlid qilmoqda",
        "risk_score": 88,
        "reasons": [
            "Rasmiy bo'lmagan Telegram bot",
            "SQB brend nomini ishlatmoqda",
            "Shaxsiy ma'lumotlarni so'rashi mumkin",
        ],
    },
    {
        "platform": "Telegram",
        "account": "@sqb_mobile_free",
        "display_name": "SQB Mobile Bepul",
        "url": "https://t.me/sqb_mobile_free",
        "description": "Telegram kanal SQB Mobile ilovasining 'bepul versiyasini' tarqatmoqda",
        "risk_score": 92,
        "reasons": [
            "Soxta kanal — SQB Mobile bepul versiyasi mavjud emas",
            "APK fayl tarqatishi mumkin",
            "Zararli dastur tarqatish xavfi",
        ],
    },
    {
        "platform": "Instagram",
        "account": "@sqb_bank_official",
        "display_name": "SQB Bank Official",
        "url": "https://instagram.com/sqb_bank_official",
        "description": "Instagram sahifa SQB Bank rasmiy sahifasini taqlid qilmoqda",
        "risk_score": 78,
        "reasons": [
            "Rasmiy bo'lmagan Instagram sahifa",
            "Brend logosini ishlatmoqda",
            "Mijozlarni aldashi mumkin",
        ],
    },
    {
        "platform": "Facebook",
        "account": "SQB Bank Uzbekistan",
        "display_name": "SQB Bank Uzbekistan",
        "url": "https://facebook.com/sqbbankuz",
        "description": "Facebook sahifa SQB nomidan fishing havolalarini tarqatmoqda",
        "risk_score": 85,
        "reasons": [
            "Soxta Facebook sahifa",
            "Fishing havolalarini tarqatmoqda",
            "Brend taqlidi",
        ],
    },
]


class SocialScanner(BaseScanner):
    scanner_type = ScannerType.SOCIAL
    threat_source = ThreatSource.SCANNER_SOCIAL

    def execute(self, session):
        # Get brand social handles from brand_assets
        from app.models.brand_asset import BrandAsset, BrandAssetType
        handles = session.query(BrandAsset).filter(
            BrandAsset.asset_type == BrandAssetType.SOCIAL_HANDLE,
            BrandAsset.is_active == True,
        ).all()

        brand_handles = [h.value for h in handles] if handles else ["@sqb_bank"]
        brand_keywords = self.get_brand_keywords(session) or ["sqb"]

        # In production, this would use actual social media APIs
        # For hackathon, we use simulated findings
        self._scan_simulated(session, brand_keywords, brand_handles)

    def _scan_simulated(self, session, keywords: list[str], brand_handles: list[str]):
        """Simulated social media scan for hackathon demo."""
        self.items_scanned = len(SIMULATED_FINDINGS)

        for finding in SIMULATED_FINDINGS:
            # Check if any brand keyword is in the account name
            account_lower = finding["account"].lower()
            is_match = any(kw.lower() in account_lower for kw in keywords)

            if not is_match:
                continue

            # Skip if it's a known legitimate handle
            if finding["account"] in brand_handles:
                continue

            self.create_scanner_threat(
                session,
                message=f"{finding['platform']} da shubhali akkaunt aniqlandi: {finding['account']}. {finding['description']}",
                risk_score=finding["risk_score"],
                confidence=72,
                label=ThreatLabel.DANGEROUS if finding["risk_score"] >= 85 else ThreatLabel.SUSPICIOUS,
                detected_url=finding["url"],
                sender_name=finding["display_name"],
                source_app=finding["platform"],
                reasons=finding["reasons"],
                recommendations=[
                    f"{finding['platform']} ga shikoyat yuboring",
                    "Mijozlarni rasmiy akkauntlar haqida xabardor qiling",
                    "Akkaunt faoliyatini kuzatishda davom eting",
                ],
            )


@celery.task(name="app.scanners.social_scanner.run_social_scan")
def run_social_scan():
    """Celery task: run social media impersonation scanner."""
    scanner = SocialScanner()
    scanner.run()
    return {
        "scanner": "social",
        "threats_found": scanner.threats_found,
        "items_scanned": scanner.items_scanned,
        "errors": len(scanner.errors),
    }
