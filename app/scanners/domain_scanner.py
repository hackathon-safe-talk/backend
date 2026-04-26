"""Domain scanner — detects typosquatting, homoglyph, and lookalike domains.

Includes TLS certificate probing to detect self-signed and private CA certs
that don't appear in public Certificate Transparency logs.
"""

import logging
import re
import ssl
import socket
import uuid
from datetime import datetime, timezone
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


# Well-known public Certificate Authorities — if issuer org is NOT in this list,
# the cert is likely self-signed or from a private/internal CA.
KNOWN_PUBLIC_CAS = {
    "let's encrypt", "letsencrypt", "isrg",
    "digicert", "geotrust", "thawte", "rapidssl",
    "comodo", "sectigo",
    "globalsign",
    "godaddy", "starfield",
    "amazon", "aws",
    "google trust services", "google",
    "microsoft", "azure",
    "cloudflare",
    "entrust",
    "buypass",
    "certum",
    "ssl.com",
    "zerossl",
    "actalis",
    "trustwave",
    "symantec",  # legacy, still seen in some certs
    "baltimore",  # CyberTrust, often in chains
    "usertrust",
    "verisign",
}


def probe_tls_certificate(domain: str, port: int = 443, timeout: float = 4.0) -> dict | None:
    """Connect to a domain on port 443 and extract TLS certificate details.

    Returns a dict with:
        - issuer_org: str — the issuing CA organization name
        - issuer_cn: str — the issuer common name
        - subject_cn: str — the cert's subject common name
        - not_before: datetime — cert valid-from date
        - not_after: datetime — cert valid-to date
        - is_self_signed: bool — True if subject == issuer
        - is_private_ca: bool — True if issuer is not a known public CA
        - serial_number: int

    Returns None if connection fails or no cert is available.
    """
    import tempfile
    import os

    try:
        # Use CERT_NONE so we can grab certs from self-signed / private CA sites
        # that would fail normal verification.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                if not der_cert:
                    return None

        # getpeercert() only returns the parsed dict when verify_mode != CERT_NONE,
        # so we decode the DER binary using CPython's _test_decode_cert helper.
        # Write DER to a temp file so _ssl._test_decode_cert can read it.
        import ssl as _ssl

        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
            f.write(der_cert)
            tmp_path = f.name
        try:
            cert_dict = _ssl._test_decode_cert(tmp_path)
        finally:
            os.unlink(tmp_path)

        return _parse_cert_dict(cert_dict)

    except (socket.timeout, socket.gaierror, ConnectionRefusedError,
            ConnectionResetError, OSError, ssl.SSLError) as e:
        logger.debug(f"[tls-probe] Could not probe {domain}:443 — {e}")
        return None
    except Exception as e:
        logger.debug(f"[tls-probe] Unexpected error probing {domain}: {e}")
        return None


def _parse_cert_dict(cert: dict) -> dict:
    """Extract structured info from a parsed certificate dict."""
    def _get_field(rdns: tuple, field: str) -> str:
        """Extract a field from an RDN tuple-of-tuples structure."""
        for rdn in rdns:
            for attr_type, attr_value in rdn:
                if attr_type == field:
                    return attr_value
        return ""

    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    subject_cn = _get_field(subject, "commonName")
    subject_org = _get_field(subject, "organizationName")
    issuer_cn = _get_field(issuer, "commonName")
    issuer_org = _get_field(issuer, "organizationName")

    # Parse dates
    not_before = None
    not_after = None
    try:
        from ssl import cert_time_to_seconds
        import time
        if cert.get("notBefore"):
            nb_ts = cert_time_to_seconds(cert["notBefore"])
            not_before = datetime.fromtimestamp(nb_ts, tz=timezone.utc)
        if cert.get("notAfter"):
            na_ts = cert_time_to_seconds(cert["notAfter"])
            not_after = datetime.fromtimestamp(na_ts, tz=timezone.utc)
    except Exception:
        pass

    # Determine if self-signed (subject == issuer)
    is_self_signed = (subject_cn == issuer_cn and subject_org == issuer_org)

    # Determine if private CA — check issuer org against known public CAs
    issuer_lower = (issuer_org or issuer_cn or "").lower()
    is_private_ca = not any(ca in issuer_lower for ca in KNOWN_PUBLIC_CAS)

    return {
        "issuer_org": issuer_org or issuer_cn or "Unknown",
        "issuer_cn": issuer_cn,
        "subject_cn": subject_cn,
        "not_before": not_before,
        "not_after": not_after,
        "is_self_signed": is_self_signed,
        "is_private_ca": is_private_ca,
        "serial_number": cert.get("serialNumber"),
    }


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
                    # Update cert info on re-check
                    if dns_resolved:
                        re_cert = probe_tls_certificate(domain, timeout=4.0)
                        if re_cert:
                            existing.ssl_issuer = re_cert["issuer_org"]
                            existing.ssl_issued_at = re_cert.get("not_before")
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

                # ── TLS Certificate Probing ──────────────────────────
                # Connect to port 443, grab the cert, check if it's from
                # a known public CA. Self-signed and private CA certs
                # don't appear in CT logs and are extra suspicious.
                cert_info = None
                if dns_resolved:
                    cert_info = probe_tls_certificate(domain, timeout=4.0)

                ssl_issuer_str = None
                ssl_issued_at = None

                if cert_info:
                    ssl_issuer_str = cert_info["issuer_org"]
                    ssl_issued_at = cert_info.get("not_before")

                    if cert_info["is_self_signed"]:
                        # Self-signed cert on a brand-lookalike domain = very suspicious
                        risk_score = min(100, risk_score + 15)
                        logger.info(f"[domain] {domain} has SELF-SIGNED cert — risk +15")
                    elif cert_info["is_private_ca"]:
                        # Private/unknown CA — not in CT logs
                        risk_score = min(100, risk_score + 10)
                        logger.info(f"[domain] {domain} has PRIVATE CA cert ({ssl_issuer_str}) — risk +10")
                    else:
                        logger.debug(f"[domain] {domain} cert issued by {ssl_issuer_str} (known public CA)")

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
                    ssl_issuer=ssl_issuer_str,
                    ssl_issued_at=ssl_issued_at,
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
                    if cert_info and cert_info["is_self_signed"]:
                        reasons.append("TLS sertifikat o'z-o'zidan imzolangan (self-signed) — CT loglarida ko'rinmaydi")
                    elif cert_info and cert_info["is_private_ca"]:
                        reasons.append(f"TLS sertifikat noma'lum/xususiy CA tomonidan berilgan: {cert_info['issuer_org']}")
                    elif cert_info:
                        reasons.append(f"TLS sertifikat: {cert_info['issuer_org']}")

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
