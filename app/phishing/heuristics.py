from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import whois
import ssl
import dns.resolver
import OpenSSL

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "bank", "update", "confirm", "account",
    "password", "paypal", "signin", "wallet", "auth"
}
PHISHING_TLDS = {".xyz", ".top", ".club", ".info", ".work", ".click", ".pw", ".gq", ".tk"}

TOP_BRANDS = {
    "google", "amazon", "microsoft", "apple", "facebook",
    "paypal", "netflix", "linkedin", "twitter", "instagram",
    "whatsapp", "youtube", "adobe", "dropbox", "salesforce",
    "chase", "bankofamerica", "wellsfargo", "citi", "yahoo",
    "tanishq", "tata", "fairplay", "sbiyono", "hdfc",
    "icici", "axis", "kotak", "yesbank", "paytm",
    "phonepe", "gpay", "amazonpay", "mobikwik", "freecharge",
    "flipkart", "myntra", "ajio", "meesho", "nykaa",
    "swiggy", "zomato", "ola", "uber", "rapido",
    "byju", "unacademy", "coursera", "udemy",
    "github", "bitbucket", "gitlab",
    "stripe", "square", "venmo", "zelle",
    "dhl", "fedex", "ups", "usps", "bluedart",
}


class AnalysisInputError(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message
        self.error_type = "invalid_url"


@dataclass
class ReachabilityError(Exception):
    message: str
    error_type: str


def sanitize_url(raw_url: str) -> str:
    return (raw_url or "").strip().replace("\x00", "")


def normalize_url(raw_url: str) -> str:
    cleaned = sanitize_url(raw_url)
    if "://" not in cleaned and cleaned:
        cleaned = f"https://{cleaned}"
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"}:
        raise AnalysisInputError("Only http/https URLs are allowed")
    if not parsed.netloc:
        raise AnalysisInputError("URL must include a valid domain")
    hostname = parsed.hostname
    if not hostname:
        raise AnalysisInputError("URL must include a valid domain")
    try:
        hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AnalysisInputError("URL domain is invalid") from exc
    return parsed.geturl()


def url_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sanitized_domain(value: str) -> str:
    parsed = urlparse(normalize_url(value))
    return (parsed.hostname or "").strip(".").lower().encode("idna").decode("ascii")


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _is_public_host(host: str | None) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
        except socket.gaierror:
            return True


def validate_url(raw_url: str) -> tuple[bool, str]:
    try:
        normalized = normalize_url(raw_url)
    except AnalysisInputError as exc:
        return False, exc.message
    if not _is_public_host(urlparse(normalized).hostname):
        return False, "URL points to a private or local network address"
    return True, ""


def validate_redirect_target(current_url: str, location: str) -> tuple[bool, str, str]:
    next_url = urljoin(current_url, location)
    ok, message = validate_url(next_url)
    return ok, message, next_url


def _check_brand_in_domain(host_no_tld: str, host: str) -> tuple[float, list[str], list[str]]:
    """Check for brand impersonation using token matching, appended digits, appended words.
    Returns (impersonation_score, brand_hits, brand_reasons)."""
    hits: list[str] = []
    reasons: list[str] = []
    score = 0.0

    for brand in TOP_BRANDS:
        if brand in host_no_tld and host_no_tld != brand:
            hits.append(brand)

            appended = host_no_tld.replace(brand, "", 1)
            has_digits = bool(re.search(r"\d", appended))
            has_appended_words = len(appended) > 0 and not has_digits

            reasons.append(
                f"Domain contains known brand token '{brand}' "
                f"({'with appended digits' if has_digits else 'with appended text' if has_appended_words else 'embedded'})"
            )
            score = 1.0

    for brand in TOP_BRANDS:
        for part in host.split("."):
            dist = levenshtein_distance(part, brand)
            if 0 < dist <= 2:
                reasons.append(f"Domain is close to brand '{brand}' (edit distance {dist})")
                score = max(score, 1.0)
                break

    return score, hits, reasons


def check_ssl_certificate(host: str) -> tuple[float, list[str]]:
    reasons = []
    ssl_issues = 0.0

    if not host:
        return ssl_issues, reasons

    try:
        cert = ssl.get_server_certificate((host, 443), timeout=3)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        # Check expiration
        not_after_bytes = x509.get_notAfter()
        if not_after_bytes:
            not_after_str = not_after_bytes.decode('utf-8')
            expiration_date = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
            if expiration_date < datetime.now(timezone.utc):
                ssl_issues = 1.0
                reasons.append("SSL certificate is expired")

        # Basic check for Let's Encrypt (often used by phishers for quick certs, but not inherently malicious)
        issuer_components = x509.get_issuer().get_components()
        issuer_str = str(issuer_components)
        if "Let's Encrypt" in issuer_str or "ZeroSSL" in issuer_str:
             reasons.append("SSL certificate is from a free issuer (common in phishing)")

    except Exception:
        # Don't add a reason if it's just a timeout/connection issue which is caught elsewhere
        pass

    return ssl_issues, reasons

def check_dns_records(host: str) -> tuple[float, list[str]]:
    reasons = []
    dns_issues = 0.0

    if not host:
        return dns_issues, reasons

    try:
        # Check MX records
        try:
            dns.resolver.resolve(host, 'MX', lifetime=2.0)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dns_issues = 1.0
            reasons.append("Domain has no MX records (cannot receive email, unusual for legit businesses)")

    except Exception:
        pass

    return dns_issues, reasons

def extract_url_features(url: str) -> tuple[dict[str, float], list[str]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    reasons: list[str] = []
    subdomain_count = max(host.count(".") - 1, 0)

    has_ip = 0.0
    try:
        ipaddress.ip_address(host)
        has_ip = 1.0
        reasons.append("Contains IP address instead of domain")
    except ValueError:
        pass

    ip_address = None
    if not has_ip:
        try:
            ip_address = socket.gethostbyname(host)
        except Exception:
            pass
    else:
        ip_address = host

    suspicious_char_count = sum(url.count(ch) for ch in ["@", "-", "%", "="])
    if suspicious_char_count:
        reasons.append(f"Contains suspicious characters ({suspicious_char_count})")

    keyword_matches = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in url.lower()]
    if keyword_matches:
        reasons.append(f"Uses known phishing keywords: {', '.join(sorted(keyword_matches))}")

    phishing_tld = float(any(host.endswith(tld) for tld in PHISHING_TLDS))
    if phishing_tld:
        reasons.append("Uses a TLD commonly seen in phishing campaigns")

    is_shortener = float(host in SHORTENERS)
    if is_shortener:
        reasons.append("Uses a known URL shortener")

    uses_https = float(parsed.scheme == "https")
    if not uses_https:
        reasons.append("Does not use HTTPS")

    if len(url) > 75:
        reasons.append(f"URL length is unusually long ({len(url)} chars)")

    host_no_tld = host.split(".")[0].lower() if "." in host else host.lower()
    brand_impersonation, brand_hits, brand_reasons = _check_brand_in_domain(host_no_tld, host)
    reasons.extend(brand_reasons)

    is_typosquatting = 0.0
    for brand in TOP_BRANDS:
        for part in host.split('.'):
            dist = levenshtein_distance(part, brand)
            if 0 < dist <= 2:
                is_typosquatting = 1.0
                break
        if is_typosquatting:
            break

    features = {
        "url_length": float(len(url)),
        "is_typosquatting": is_typosquatting,
        "brand_impersonation": brand_impersonation,
        "brand_hits": brand_hits,
        "raw_domain": host,
        "subdomain_count": float(subdomain_count),
        "has_ip": has_ip,
        "ip_address": ip_address,
        "suspicious_chars": float(suspicious_char_count),
        "keyword_hits": float(len(keyword_matches)),
        "is_shortener": is_shortener,
        "phishing_tld": phishing_tld,
        "uses_https": uses_https,
        "path_length": float(len(path)),
    }

    # Optional SSL/DNS checks
    ssl_issues, ssl_reasons = check_ssl_certificate(host)
    if ssl_reasons:
        features["ssl_issues"] = ssl_issues
        reasons.extend(ssl_reasons)

    dns_issues, dns_reasons = check_dns_records(host)
    if dns_reasons:
        features["dns_issues"] = dns_issues
        reasons.extend(dns_reasons)

    return features, reasons


def get_domain_intelligence(
    host: str,
    *,
    whois_api_key: str = "",
) -> tuple[dict[str, Any], list[str]]:
    info: dict[str, Any] = {
        "domain": host,
        "domain_age_days": -1,
        "registrar": "unknown",
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
    }
    reasons: list[str] = []

    whois_available = False
    verdict = "unknown"
    severity = "low"
    confidence = "low"
    reason = "WHOIS lookup unavailable (no data returned)"

    try:
        w = whois.whois(host)
        whois_available = True
        confidence = "high"

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            if isinstance(creation, str):
                creation = datetime.fromisoformat(creation)
            creation_utc = (
                creation.astimezone(timezone.utc)
                if creation.tzinfo
                else creation.replace(tzinfo=timezone.utc)
            )
            age_days = max((datetime.now(timezone.utc) - creation_utc).days, 0)
            info["domain_age_days"] = age_days
            info["creation_date"] = creation_utc.strftime("%Y-%m-%d")

            config = {}
            try:
                from flask import current_app
                if current_app:
                    config = current_app.config
            except Exception:
                pass

            age_30 = config.get("DOMAIN_AGE_EXTREME_RISK_DAYS", 30)
            age_90 = config.get("DOMAIN_AGE_VERY_HIGH_RISK_DAYS", 90)
            age_180 = config.get("DOMAIN_AGE_HIGH_RISK_DAYS", 180)
            age_365 = config.get("DOMAIN_AGE_MODERATE_RISK_DAYS", 365)

            if age_days < age_30:
                reasons.append(f"Domain registered less than {age_30} days ago (Extremely high risk factor)")
                info["domain_age_bucket"] = "< 30 days"
                verdict = "suspicious"
                severity = "high"
                reason = f"Domain is extremely young ({age_days} days old)."
            elif age_days < age_90:
                reasons.append(f"Domain registered less than {age_90} days ago (Very high risk factor)")
                info["domain_age_bucket"] = "< 90 days"
                verdict = "suspicious"
                severity = "medium"
                reason = f"Domain is very young ({age_days} days old)."
            elif age_days < age_180:
                reasons.append(f"Domain registered less than {age_180} days ago (High risk factor)")
                info["domain_age_bucket"] = "< 180 days"
                verdict = "suspicious"
                severity = "medium"
                reason = f"Domain is relatively young ({age_days} days old)."
            elif age_days < age_365:
                reasons.append(f"Domain registered less than {age_365} days ago (Moderate risk factor)")
                info["domain_age_bucket"] = "< 365 days"
                verdict = "suspicious"
                severity = "low"
                reason = f"Domain is moderately young ({age_days} days old)."
            else:
                info["domain_age_bucket"] = ">= 365 days"
                verdict = "clean"
                severity = "low"
                reason = f"Domain is well-established ({age_days} days old)."
        else:
            verdict = "unknown"
            severity = "low"
            reason = "WHOIS record exists but creation date is missing"

        if w.registrar:
            info["registrar"] = str(w.registrar)

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            if isinstance(expiry, str):
                try:
                    expiry = datetime.fromisoformat(expiry)
                except ValueError:
                    pass
            if hasattr(expiry, "strftime"):
                expiry_utc = (
                    expiry.astimezone(timezone.utc)
                    if expiry.tzinfo
                    else expiry.replace(tzinfo=timezone.utc)
                )
                info["expiration_date"] = expiry_utc.strftime("%Y-%m-%d")
            else:
                info["expiration_date"] = str(expiry)

        ns = w.name_servers
        if ns:
            info["name_servers"] = [str(n).lower() for n in ns]

    except Exception as e:
        reasons.append("WHOIS lookup unavailable (no data returned)")
        reason = f"WHOIS lookup failed: {e}"

    info["domain_trust"] = {
        "whois_available": whois_available,
        "verdict": verdict,
        "severity": severity,
        "confidence": confidence,
        "reason": reason,
        "age_days": info.get("domain_age_days", -1),
        "age_bucket": info.get("domain_age_bucket", "unknown"),
        "registrar": info.get("registrar", "unknown"),
        "name_servers": info.get("name_servers", [])
    }

    return info, reasons
