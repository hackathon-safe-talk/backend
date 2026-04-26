"""Domain scanner — detects typosquatting, homoglyph, and lookalike domains."""

import logging
import re
import uuid
from itertools import product

import dns.resolver
import tldextract

from app.celery_app import celery
from app.models.scan_run import ScannerType
from app.models.threat import ThreatSource, ThreatLabel
from app.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Homoglyph map for common substitutions
HOMOGLYPHS = {
    "a": ["@", "4", "a"],
    "b": ["8", "6", "b"],
    "c": ["(", "c"],
    "e": ["3", "e"],
    "g": ["9", "q", "g"],
    "i": ["1", "l", "!", "i"],
    "l": ["1", "i", "|", "l"],
    "o": ["0", "o"],
    "q": ["9", "g", "q"],
    "s": ["5", "$", "s"],
    "t": ["7", "+", "t"],
    "z": ["2", "z"],
}

# Common typosquat TLDs
SUSPICIOUS_TLDS = [
    "xyz", "top", "club", "icu", "buzz", "ml", "ga", "cf", "tk",
    "cam", "click", "link", "info", "online", "site", "website",
]


def generate_typosquats(domain: str) -> list[str]:
    """Generate common typosquat variants of a domain."""
    extracted = tldextract.extract(domain)
    name = extracted.domain
    suffix = extracted.suffix or "uz"
    variants = set()

    # Character omission
    for i in range(len(name)):
        variant = name[:i] + name[i + 1:]
        if variant and variant != name:
            variants.add(f"{variant}.{suffix}")

    # Adjacent character swap
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        variant = "".join(swapped)
        if variant != name:
            variants.add(f"{variant}.{suffix}")

    # Character duplication
    for i in range(len(name)):
        variant = name[:i] + name[i] + name[i:]
        if variant != name:
            variants.add(f"{variant}.{suffix}")

    # Common prefix/suffix additions
    for affix in ["login", "secure", "bank", "mobile", "app", "online", "my"]:
        variants.add(f"{name}-{affix}.{suffix}")
        variants.add(f"{affix}-{name}.{suffix}")
        variants.add(f"{name}{affix}.{suffix}")
        variants.add(f"{affix}{name}.{suffix}")

    # Suspicious TLD variants
    for tld in SUSPICIOUS_TLDS:
        variants.add(f"{name}.{tld}")

    return list(variants)


def generate_homoglyphs(domain: str) -> list[str]:
    """Generate homoglyph variants of a domain name."""
    extracted = tldextract.extract(domain)
    name = extracted.domain
    suffix = extracted.suffix or "uz"
    variants = set()

    # For each character, if it has homoglyphs, try single substitutions
    for i, char in enumerate(name.lower()):
        if char in HOMOGLYPHS:
            for replacement in HOMOGLYPHS[char]:
                if replacement != char:
                    variant = name[:i] + replacement + name[i + 1:]
                    variants.add(f"{variant}.{suffix}")
                    # Also with suspicious TLDs
                    for tld in SUSPICIOUS_TLDS[:5]:
                        variants.add(f"{variant}.{tld}")

    return list(variants)


def batch_dns_resolve(domains: list[str], timeout: float = 2.0) -> dict[str, str | None]:
    """Resolve a batch of domains. Returns {domain: ip_or_None} for ALL domains."""
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for domain in domains:
        try:
            answers = resolver.resolve(domain, "A")
            if answers:
                results[domain] = str(answers[0])
            else:
                results[domain] = None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout,
                dns.exception.DNSException):
            results[domain] = None
        except Exception:
            results[domain] = None

    return results


class DomainScanner(BaseScanner):
    scanner_type = ScannerType.DOMAIN
    threat_source = ThreatSource.SCANNER_DOMAIN

    def execute(self, session):
        from app.models.discovered_domain import DiscoveredDomain, DomainStatus, DomainSource
        from datetime import datetime

        # Get brand domains to protect
        brand_domains = self.get_brand_domains(session)
        if not brand_domains:
            brand_domains = ["sqb.uz", "online.sqb.uz"]
            logger.info("[domain] No brand domains configured, using defaults")

        all_candidates = set()

        for domain in brand_domains:
            typosquats = generate_typosquats(domain)
            homoglyph_variants = generate_homoglyphs(domain)
            all_candidates.update(typosquats)
            all_candidates.update(homoglyph_variants)

        self.items_scanned = len(all_candidates)
        logger.info(f"[domain] Generated {len(all_candidates)} candidate domains to check")

        # Batch DNS resolution — returns {domain: ip_or_None} for ALL
        try:
            dns_results = batch_dns_resolve(list(all_candidates))
        except Exception as exc:
            self.errors.append(f"DNS resolution batch error: {exc}")
            dns_results = {}

        live_count = sum(1 for ip in dns_results.values() if ip is not None)
        logger.info(f"[domain] {live_count} domains resolved successfully out of {len(dns_results)}")

        # Load custom patterns
        patterns = self.get_custom_patterns(session)

        # Save EVERY checked domain to discovered_domains
        for domain, ip in dns_results.items():
            try:
                dns_resolved = ip is not None

                # Check if already tracked
                existing = session.query(DiscoveredDomain).filter(
                    DiscoveredDomain.domain == domain
                ).first()

                if existing:
                    # Update existing record
                    existing.last_checked_at = datetime.utcnow()
                    existing.check_count += 1
                    existing.dns_resolved = dns_resolved
                    existing.ip_address = ip
                    if dns_resolved and existing.status == DomainStatus.DOWN:
                        existing.status = DomainStatus.LIVE
                    elif not dns_resolved and existing.status == DomainStatus.LIVE:
                        existing.status = DomainStatus.DOWN
                    continue  # Don't create duplicate threats

                # Determine similarity to brand
                try:
                    import Levenshtein
                    distances = [
                        (Levenshtein.distance(domain.split(".")[0], bd.split(".")[0]), bd)
                        for bd in brand_domains
                    ]
                    min_distance, closest_brand = min(distances, key=lambda x: x[0])
                    risk_score = max(70, 100 - min_distance * 5)
                    similarity = 1.0 - (min_distance / max(len(domain.split(".")[0]), len(closest_brand.split(".")[0]), 1))
                except ImportError:
                    risk_score = 85
                    closest_brand = brand_domains[0]
                    similarity = 0.8

                extracted = tldextract.extract(domain)
                tld = extracted.suffix

                if tld in SUSPICIOUS_TLDS:
                    risk_score = min(100, risk_score + 10)

                # Check custom regex patterns
                matched_pattern = None
                for regex, desc in patterns:
                    try:
                        if re.search(regex, domain, re.IGNORECASE):
                            matched_pattern = regex
                            break
                    except re.error:
                        pass

                # Determine source type
                source_type = DomainSource.TYPOSQUAT

                # Save to discovered_domains
                dd = DiscoveredDomain(
                    domain=domain,
                    status=DomainStatus.LIVE if dns_resolved else DomainStatus.DOWN,
                    source=source_type,
                    ip_address=ip,
                    dns_resolved=dns_resolved,
                    risk_score=risk_score if dns_resolved else None,
                    matched_brand=closest_brand,
                    matched_pattern=matched_pattern,
                    similarity_score=round(similarity, 3),
                    first_seen_at=datetime.utcnow(),
                    last_checked_at=datetime.utcnow(),
                    check_count=1,
                )
                session.add(dd)
                session.flush()

                # Only create a threat for LIVE domains
                if dns_resolved:
                    reasons = [
                        f"Domen '{domain}' brend domeniga o'xshash",
                        f"DNS resolve muvaffaqiyatli — IP: {ip}",
                    ]
                    if tld in SUSPICIOUS_TLDS:
                        reasons.append(f"Shubhali TLD (.{tld}) ishlatilgan")
                    if matched_pattern:
                        reasons.append(f"Regex pattern mos keldi: {matched_pattern}")

                    threat = self.create_scanner_threat(
                        session,
                        message=f"Typosquat domen aniqlandi: {domain} (IP: {ip}). Bu domen SQB brendiga o'xshash va fishing hujumi uchun ishlatilishi mumkin.",
                        risk_score=risk_score,
                        confidence=80,
                        label=ThreatLabel.DANGEROUS if risk_score >= 85 else ThreatLabel.SUSPICIOUS,
                        detected_url=f"https://{domain}",
                        reasons=reasons,
                        recommendations=[
                            f"Domen '{domain}' ni bloklang",
                            "Domen registratoriga shikoyat yuboring",
                            "Xodimlar va mijozlarni ogohlantiring",
                        ],
                    )
                    # Link domain to threat
                    dd.threat_id = threat.id

            except Exception as exc:
                self.errors.append(f"Error processing {domain}: {exc}")


@celery.task(name="app.scanners.domain_scanner.run_domain_scan")
def run_domain_scan():
    """Celery task: run domain typosquat/homoglyph scanner."""
    scanner = DomainScanner()
    scanner.run()
    return {
        "scanner": "domain",
        "threats_found": scanner.threats_found,
        "items_scanned": scanner.items_scanned,
        "errors": len(scanner.errors),
    }
