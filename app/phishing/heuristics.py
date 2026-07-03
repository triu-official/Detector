from __future__ import annotations

import hashlib
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

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
    "chase", "bankofamerica", "wellsfargo", "citi", "yahoo"
}

_whois_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")
_WHOIS_TIMEOUT = 10.0


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

    is_typosquatting = 0.0
    for part in host.split('.'):
        for brand in TOP_BRANDS:
            dist = levenshtein_distance(part, brand)
            if 0 < dist <= 2:
                is_typosquatting = 1.0
                reasons.append(f"Domain appears to be typosquatting a known brand ({brand})")
                break
        if is_typosquatting:
            break

    features = {
        "url_length": float(len(url)),
        "is_typosquatting": is_typosquatting,
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


def _whoisxml_lookup(host: str, api_key: str) -> dict[str, Any] | None:
    """Query WhoisXML API for domain intelligence."""
    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    params = {
        "apiKey": api_key,
        "domainName": host,
        "outputFormat": "JSON",
        "preferFresh": "1",
    }
    try:
        response = requests.get(url, params=params, timeout=_WHOIS_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        whois_record = data.get("WhoisRecord", {})
        return whois_record
    except Exception:
        return None


def get_domain_intelligence(
    host: str,
    *,
    new_domain_days: int,
    young_domain_days: int,
    whois_api_key: str = "",
) -> tuple[dict[str, Any], list[str]]:
    info: dict[str, Any] = {"domain": host, "domain_age_days": 0, "registrar": "unknown"}
    reasons: list[str] = []

    if whois_api_key:
        whois_data = _whoisxml_lookup(host, whois_api_key)
        if whois_data:
            creation_date_str = whois_data.get("createdDate") or whois_data.get("registryData", {}).get("createdDate")
            if creation_date_str:
                try:
                    creation = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
                    creation_utc = creation.astimezone(timezone.utc) if creation.tzinfo else creation.replace(tzinfo=timezone.utc)
                    age_days = max((datetime.now(timezone.utc) - creation_utc).days, 0)
                    info["domain_age_days"] = age_days
                    if age_days < new_domain_days:
                        reasons.append(f"Domain registered less than {new_domain_days} days ago")
                    elif age_days < young_domain_days:
                        reasons.append(f"Domain registered less than {young_domain_days} days ago")
                except Exception:
                    pass

            registrar = whois_data.get("registrarName") or whois_data.get("registryData", {}).get("registrarName")
            if registrar:
                info["registrar"] = str(registrar)

            expires_date_str = whois_data.get("expiresDate") or whois_data.get("registryData", {}).get("expiresDate")
            if expires_date_str:
                info["expires_date"] = expires_date_str

            name_servers = whois_data.get("nameServers", {}).get("hostNames", [])
            if name_servers:
                info["name_servers"] = name_servers
        else:
            reasons.append("WHOIS lookup unavailable (API)")
    else:
        reasons.append("WHOIS lookup skipped (no API key)")

    return info, reasons