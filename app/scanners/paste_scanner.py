"""Paste/code scanner — searches GitHub for leaked credentials and brand mentions."""

import logging
import re
from datetime import datetime

import requests

from app.celery_app import celery
from app.models.scan_run import ScannerType
from app.models.threat import ThreatSource, ThreatLabel
from app.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_SEARCH_REPOS_URL = "https://api.github.com/search/repositories"


class PasteScanner(BaseScanner):
    scanner_type = ScannerType.PASTE
    threat_source = ThreatSource.SCANNER_PASTE

    def execute(self, session):
        brand_keywords = self.get_brand_keywords(session) or ["sqb"]
        brand_domains = self.get_brand_domains(session) or ["sqb.uz"]

        # Search for sensitive patterns on GitHub
        search_queries = []
        for domain in brand_domains:
            search_queries.append(f'"{domain}" password')
            search_queries.append(f'"{domain}" api_key')
            search_queries.append(f'"{domain}" secret')

        for keyword in brand_keywords:
            search_queries.append(f'"{keyword}" credentials')
            search_queries.append(f'"{keyword}" database password')

        for query in search_queries:
            self._search_github(session, query)

    def _search_github(self, session, query: str):
        """Search GitHub code for sensitive information."""
        try:
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "SafeTalk-DRP/1.0",
            }

            # Use code search API
            resp = requests.get(
                GITHUB_SEARCH_URL,
                params={"q": query, "per_page": 10},
                headers=headers,
                timeout=15,
            )

            if resp.status_code == 403:
                # Rate limited — common for unauthenticated requests
                self.errors.append(f"GitHub rate limit hit for query: {query}")
                return
            if resp.status_code != 200:
                self.errors.append(f"GitHub returned {resp.status_code} for query: {query}")
                return

            try:
                data = resp.json()
            except Exception:
                self.errors.append(f"GitHub returned invalid JSON for query: {query}")
                return

            items = data.get("items", [])
            self.items_scanned += len(items)

            for item in items:
                repo_name = item.get("repository", {}).get("full_name", "unknown")
                file_path = item.get("path", "unknown")
                html_url = item.get("html_url", "")

                # Determine risk based on what was found
                risk_score = 75
                reasons = [
                    f"GitHub'da brend bilan bog'liq maxfiy ma'lumot topildi",
                    f"Repozitoriy: {repo_name}",
                    f"Fayl: {file_path}",
                    f"Qidiruv so'rovi: {query}",
                ]

                # Higher risk for certain file types
                if any(ext in file_path.lower() for ext in [".env", ".cfg", ".conf", ".yml", ".yaml", ".json"]):
                    risk_score = 90
                    reasons.append("Konfiguratsiya fayli — maxfiy ma'lumot sizib chiqishi ehtimoli yuqori")

                if any(word in file_path.lower() for word in ["password", "secret", "credential", "key"]):
                    risk_score = 95
                    reasons.append("Fayl nomi maxfiy ma'lumot mavjudligini ko'rsatadi")

                self.create_scanner_threat(
                    session,
                    message=f"GitHub'da SQB ga tegishli maxfiy ma'lumot topildi: {repo_name}/{file_path}. Ma'lumot sizib chiqishi ehtimoli.",
                    risk_score=risk_score,
                    confidence=70,
                    label=ThreatLabel.DANGEROUS if risk_score >= 85 else ThreatLabel.SUSPICIOUS,
                    detected_url=html_url,
                    sender_name=repo_name,
                    source_app="GitHub",
                    reasons=reasons,
                    recommendations=[
                        "Repozitoriy egasi bilan bog'laning",
                        "GitHub'ga maxfiy ma'lumotni olib tashlash so'rovi yuboring",
                        "Sizib chiqqan ma'lumotlarni (parollar, kalitlar) darhol o'zgartiring",
                        "Xavfsizlik auditini o'tkazing",
                    ],
                )

        except requests.RequestException as exc:
            self.errors.append(f"GitHub request failed for '{query}': {exc}")
        except Exception as exc:
            self.errors.append(f"GitHub scan error for '{query}': {exc}")


@celery.task(name="app.scanners.paste_scanner.run_paste_scan")
def run_paste_scan():
    """Celery task: run GitHub code/paste scanner."""
    scanner = PasteScanner()
    scanner.run()
    return {
        "scanner": "paste",
        "threats_found": scanner.threats_found,
        "items_scanned": scanner.items_scanned,
        "errors": len(scanner.errors),
    }
