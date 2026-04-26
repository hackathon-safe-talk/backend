"""App store scanner — detects fake/impersonating apps on Google Play."""

import logging

from app.celery_app import celery
from app.models.scan_run import ScannerType
from app.models.threat import ThreatSource, ThreatLabel
from app.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Try to import google-play-scraper (optional dependency)
try:
    from google_play_scraper import search as gplay_search
    from google_play_scraper import app as gplay_app
    HAS_GPLAY = True
except ImportError:
    HAS_GPLAY = False
    logger.warning("[app_store] google-play-scraper not available, using simulated data")


# Known legitimate app IDs (whitelist)
LEGITIMATE_APP_IDS = {
    "uz.sqb.mobile",
    "uz.sqb.business",
    "uz.sqb.token",
}


class AppStoreScanner(BaseScanner):
    scanner_type = ScannerType.APP_STORE
    threat_source = ThreatSource.SCANNER_APP_STORE

    def execute(self, session):
        # Get brand app names/packages from brand_assets
        from app.models.brand_asset import BrandAsset, BrandAssetType
        app_names = session.query(BrandAsset).filter(
            BrandAsset.asset_type.in_([BrandAssetType.APP_NAME, BrandAssetType.APP_PACKAGE]),
            BrandAsset.is_active == True,
        ).all()

        search_terms = [a.value for a in app_names] if app_names else ["SQB Mobile", "SQB Bank"]
        keywords = self.get_brand_keywords(session) or ["sqb"]

        if HAS_GPLAY:
            self._scan_google_play(session, search_terms, keywords)
        else:
            self._scan_simulated(session, search_terms, keywords)

    def _scan_google_play(self, session, search_terms: list[str], keywords: list[str]):
        """Search Google Play for apps matching brand terms."""
        for term in search_terms:
            try:
                results = gplay_search(term, lang="uz", country="uz", n_hits=30)
                self.items_scanned += len(results)

                for app_info in results:
                    app_id = app_info.get("appId", "")

                    # Skip legitimate apps
                    if app_id in LEGITIMATE_APP_IDS:
                        continue

                    title = app_info.get("title", "")
                    developer = app_info.get("developer", "")
                    score = app_info.get("score", 0)
                    installs = app_info.get("installs", "0")

                    # Check if app title or developer matches brand keywords
                    title_lower = title.lower()
                    is_match = any(kw.lower() in title_lower for kw in keywords)

                    if is_match:
                        risk_score = 80
                        reasons = [
                            f"Google Play'da brend nomiga o'xshash ilova: '{title}'",
                            f"Dasturchi: {developer}",
                            f"Reyting: {score}, O'rnatishlar: {installs}",
                        ]

                        # Higher risk for low-rated or new apps
                        if score and score < 3.0:
                            risk_score = 90
                            reasons.append("Past reyting — shubhali ilova")
                        if installs and installs in ("0", "1+", "5+", "10+"):
                            risk_score = min(95, risk_score + 5)
                            reasons.append("Juda kam o'rnatishlar — yangi/soxta ilova ehtimoli")

                        self.create_scanner_threat(
                            session,
                            message=f"Google Play'da shubhali ilova: '{title}' ({app_id}). Bu ilova SQB brendini taqlid qilishi mumkin.",
                            risk_score=risk_score,
                            confidence=75,
                            label=ThreatLabel.SUSPICIOUS,
                            detected_url=f"https://play.google.com/store/apps/details?id={app_id}",
                            sender_name=developer,
                            source_app="Google Play",
                            reasons=reasons,
                            recommendations=[
                                "Ilovani tekshiring va Google Play'ga shikoyat yuboring",
                                "Agar soxta bo'lsa, Google'ga takedown so'rovi yuboring",
                                "Mijozlarni rasmiy ilova haqida xabardor qiling",
                            ],
                        )

            except Exception as exc:
                self.errors.append(f"Google Play search error for '{term}': {exc}")

    def _scan_simulated(self, session, search_terms: list[str], keywords: list[str]):
        """Simulated scan for when google-play-scraper is not available."""
        # Simulate checking a list of apps
        simulated_apps = [
            {
                "title": "SQB Mobile Banking - Unofficial",
                "appId": "com.fake.sqb.banking",
                "developer": "Unknown Dev",
                "score": 2.1,
                "installs": "100+",
            },
            {
                "title": "SQB Card Manager",
                "appId": "io.sqb.cardmgr.fake",
                "developer": "CardApps LLC",
                "score": 1.8,
                "installs": "50+",
            },
            {
                "title": "Online SQB Wallet",
                "appId": "net.sqbwallet.app",
                "developer": "WalletDev",
                "score": 3.5,
                "installs": "500+",
            },
        ]

        self.items_scanned = len(simulated_apps)

        for app_info in simulated_apps:
            app_id = app_info["appId"]
            if app_id in LEGITIMATE_APP_IDS:
                continue

            title = app_info["title"]
            developer = app_info["developer"]
            score = app_info["score"]

            risk_score = 80
            reasons = [
                f"Google Play'da brend nomiga o'xshash ilova: '{title}'",
                f"Dasturchi: {developer}",
                f"Reyting: {score}",
            ]

            if score < 3.0:
                risk_score = 90
                reasons.append("Past reyting — shubhali ilova")

            self.create_scanner_threat(
                session,
                message=f"Google Play'da shubhali ilova: '{title}' ({app_id}). Bu ilova SQB brendini taqlid qilishi mumkin.",
                risk_score=risk_score,
                confidence=70,
                label=ThreatLabel.SUSPICIOUS,
                detected_url=f"https://play.google.com/store/apps/details?id={app_id}",
                sender_name=developer,
                source_app="Google Play",
                reasons=reasons,
                recommendations=[
                    "Ilovani tekshiring va Google Play'ga shikoyat yuboring",
                    "Agar soxta bo'lsa, Google'ga takedown so'rovi yuboring",
                    "Mijozlarni rasmiy ilova haqida xabardor qiling",
                ],
            )


@celery.task(name="app.scanners.app_store_scanner.run_app_store_scan")
def run_app_store_scan():
    """Celery task: run Google Play app store scanner."""
    scanner = AppStoreScanner()
    scanner.run()
    return {
        "scanner": "app_store",
        "threats_found": scanner.threats_found,
        "items_scanned": scanner.items_scanned,
        "errors": len(scanner.errors),
    }
