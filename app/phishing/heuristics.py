from __future__ import annotations

import hashlib
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import whois

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "bank", "update", "confirm", "account", "password"}
PHISHING_TLDS = {".xyz", ".top", ".club", ".info", ".work", ".click"}

# Shared executor for blocking WHOIS lookups — keeps the gunicorn worker thread free
_whois_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")
_WHOIS_TIMEOUT = 8.0  # seconds


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

    features = {
        "url_length": float(len(url)),
        "subdomain_count": float(subdomain_count),
        "has_ip": has_ip,
        "suspicious_chars": float(suspicious_char_count),
        "keyword_hits": float(len(keyword_matches)),
        "is_shortener": is_shortener,
        "phishing_tld": phishing_tld,
        "uses_https": uses_https,
        "path_length": float(len(path)),
    }
    return features, reasons


def _whois_lookup(host: str) -> Any:
    """Run whois in a thread-pool future — raises on timeout."""
    future = _whois_executor.submit(whois.whois, host)
    return future.result(timeout=_WHOIS_TIMEOUT)


def get_domain_intelligence(
    host: str,
    cache_get,
    cache_set,
    ttl_seconds: int,
    *,
    new_domain_days: int,
    young_domain_days: int,
) -> tuple[dict[str, Any], list[str]]:
    cache_key = f"domain-intel:{host}"
    cached = cache_get(cache_key)
    if cached:
        return cached["info"], cached["reasons"]

    info: dict[str, Any] = {"domain": host, "domain_age_days": 0, "registrar": "unknown"}
    reasons: list[str] = []
    try:
        data = _whois_lookup(host)
        creation = data.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            creation_utc = (
                creation.astimezone(timezone.utc) if creation.tzinfo else creation.replace(tzinfo=timezone.utc)
            )
            age_days = max((datetime.now(timezone.utc) - creation_utc).days, 0)
            info["domain_age_days"] = age_days
            if age_days < new_domain_days:
                reasons.append(f"Domain registered less than {new_domain_days} days ago")
            elif age_days < young_domain_days:
                reasons.append(f"Domain registered less than {young_domain_days} days ago")
        registrar = getattr(data, "registrar", None)
        if registrar:
            info["registrar"] = str(registrar)
    except (FuturesTimeoutError, Exception):
        reasons.append("WHOIS lookup unavailable")

    cache_set(cache_key, {"info": info, "reasons": reasons}, ttl_seconds)
    return info, reasons
