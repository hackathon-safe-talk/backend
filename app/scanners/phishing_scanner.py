"""Phishing scanner — monitors CT logs (crt.sh) and URLhaus for brand-related threats."""

import logging
import re

import requests

from app.celery_app import celery
from app.models.scan_run import ScannerType
from app.models.threat import ThreatSource, ThreatLabel
from app.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q={query}&output=json"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
URLHAUS_SEARCH_URL = "https://urlhaus-api.abuse.ch/v1/url/"


class PhishingScanner(BaseScanner):
    scanner_type = ScannerType.PHISHING
    threat_source = ThreatSource.SCANNER_PHISHING

    def execute(self, session):
        brand_keywords = self.get_brand_keywords(session)
        brand_domains = self.get_brand_domains(session)

        if not brand_keywords:
            brand_keywords = ["sqb", "sqbank", "uzcard", "humo"]
        if not brand_domains:
            brand_domains = ["sqb.uz"]

        # Phase 1: Check Certificate Transparency logs via crt.sh
        self._scan_ct_logs(session, brand_keywords, brand_domains)

        # Phase 2: Check URLhaus for malicious URLs mentioning brand
        self._scan_urlhaus(session, brand_keywords)

    def _scan_ct_logs(self, session, keywords: list[str], brand_domains: list[str]):
        """Search crt.sh for certificates issued to domains similar to brand."""
        from app.models.discovered_domain import DiscoveredDomain, DomainStatus, DomainSource
        from datetime import datetime

        for keyword in keywords:
            try:
                url = CRTSH_URL.format(query=f"%25{keyword}%25")
                resp = requests.get(url, timeout=15, headers={"User-Agent": "SafeTalk-DRP/1.0"})
                if resp.status_code != 200:
                    self.errors.append(f"crt.sh returned {resp.status_code} for '{keyword}'")
                    continue

                try:
                    certs = resp.json()
                except Exception:
                    self.errors.append(f"crt.sh returned invalid JSON for '{keyword}'")
                    continue

                self.items_scanned += len(certs)

                # Deduplicate by common name
                seen_domains = set()
                for cert in certs:
                    common_name = cert.get("common_name", "")
                    if not common_name or common_name in seen_domains:
                        continue
                    # Skip wildcard certs
                    if common_name.startswith("*."):
                        common_name = common_name[2:]
                    seen_domains.add(common_name)

                    # Skip if it's our own brand domain
                    is_own = False
                    for bd in brand_domains:
                        if common_name == bd or common_name.endswith(f".{bd}"):
                            is_own = True
                            break
                    if is_own:
                        continue

                    # Check if already tracked in discovered_domains
                    existing = session.query(DiscoveredDomain).filter(
                        DiscoveredDomain.domain == common_name
                    ).first()
                    if existing:
                        existing.last_checked_at = datetime.utcnow()
                        existing.check_count += 1
                        continue

                    # Parse cert dates
                    ssl_issued = None
                    not_before = cert.get("not_before", "")
                    issuer = cert.get("issuer_name", "")

                    # Check if it looks suspicious
                    if any(kw in common_name.lower() for kw in keywords):
                        risk_score = 85
                        reasons = [
                            f"CT logda brend bilan bog'liq sertifikat topildi: {common_name}",
                            f"Sertifikat sanasi: {not_before or 'noma'}",
                        ]

                        # Higher risk for suspicious TLDs
                        from app.scanners.domain_scanner import SUSPICIOUS_TLDS
                        import tldextract
                        extracted = tldextract.extract(common_name)
                        if extracted.suffix in SUSPICIOUS_TLDS:
                            risk_score = 92
                            reasons.append(f"Shubhali TLD (.{extracted.suffix}) ishlatilgan")

                        # Save to discovered_domains
                        dd = DiscoveredDomain(
                            domain=common_name,
                            status=DomainStatus.LIVE,
                            source=DomainSource.CT_LOG,
                            dns_resolved=True,  # Has SSL cert = likely live
                            risk_score=risk_score,
                            matched_brand=brand_domains[0] if brand_domains else None,
                            ssl_issuer=issuer[:500] if issuer else None,
                            first_seen_at=datetime.utcnow(),
                            last_checked_at=datetime.utcnow(),
                        )
                        session.add(dd)
                        session.flush()

                        threat = self.create_scanner_threat(
                            session,
                            message=f"Fishing sertifikati aniqlandi: {common_name}. CT logda SQB brendiga o'xshash domen uchun SSL sertifikat chiqarilgan.",
                            risk_score=risk_score,
                            confidence=78,
                            label=ThreatLabel.DANGEROUS if risk_score >= 90 else ThreatLabel.SUSPICIOUS,
                            detected_url=f"https://{common_name}",
                            reasons=reasons,
                            recommendations=[
                                f"'{common_name}' domenini tekshiring",
                                "Domen registratoriga takedown so'rovi yuboring",
                                "Mijozlar uchun ogohlantirish chiqaring",
                            ],
                        )
                        dd.threat_id = threat.id

            except requests.RequestException as exc:
                self.errors.append(f"crt.sh request failed for '{keyword}': {exc}")
            except Exception as exc:
                self.errors.append(f"CT log scan error for '{keyword}': {exc}")

    def _scan_urlhaus(self, session, keywords: list[str]):
        """Check URLhaus for recently reported malicious URLs mentioning brand."""
        try:
            resp = requests.get(URLHAUS_RECENT_URL, timeout=15, headers={"User-Agent": "SafeTalk-DRP/1.0"})
            if resp.status_code != 200:
                self.errors.append(f"URLhaus returned {resp.status_code}")
                return

            try:
                data = resp.json()
            except Exception:
                self.errors.append("URLhaus returned invalid JSON")
                return

            urls = data.get("urls", [])
            self.items_scanned += len(urls)

            for url_entry in urls:
                url = url_entry.get("url", "")
                url_lower = url.lower()

                for keyword in keywords:
                    if keyword.lower() in url_lower:
                        threat_type = url_entry.get("threat", "unknown")
                        tags = url_entry.get("tags", [])

                        self.create_scanner_threat(
                            session,
                            message=f"URLhaus'da zararli URL topildi: {url}. Tur: {threat_type}. Bu URL SQB brendiga bog'liq bo'lishi mumkin.",
                            risk_score=90,
                            confidence=85,
                            label=ThreatLabel.DANGEROUS,
                            detected_url=url,
                            reasons=[
                                f"URLhaus zararli URL bazasida topildi",
                                f"Xavf turi: {threat_type}",
                                "Teglar: " + (", ".join(tags) if tags else "yoq"),
                            ],
                            recommendations=[
                                "URL ni darhol bloklang",
                                "Xavfsizlik jamoasiga xabar bering",
                                "Abuse.ch ga hisobot yuboring",
                            ],
                        )
                        break  # Don't duplicate for same URL

        except requests.RequestException as exc:
            self.errors.append(f"URLhaus request failed: {exc}")
        except Exception as exc:
            self.errors.append(f"URLhaus scan error: {exc}")


@celery.task(name="app.scanners.phishing_scanner.run_phishing_scan")
def run_phishing_scan():
    """Celery task: run phishing CT log + URLhaus scanner."""
    scanner = PhishingScanner()
    scanner.run()
    return {
        "scanner": "phishing",
        "threats_found": scanner.threats_found,
        "items_scanned": scanner.items_scanned,
        "errors": len(scanner.errors),
    }
