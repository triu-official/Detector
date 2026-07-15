from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import current_app
from requests import Response
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout, RequestException, SSLError
from requests.exceptions import Timeout as RequestsTimeout
from urllib3.util.retry import Retry

from app.extensions import db
from app.models import Analysis

from .heuristics import (
    AnalysisInputError,
    ReachabilityError,
    extract_url_features,
    get_domain_intelligence,
    normalize_url,
    sanitized_domain,
    url_hash,
    validate_redirect_target,
    validate_url,
)


@dataclass
class AnalysisResult:
    raw_url: str
    normalized_url: str
    domain: str
    url_hash: str
    risk_score: int
    label: str
    reasons: list[str]
    reachability: str
    redirect_chain: list[str]
    status_code: int | None
    features_summary: dict[str, Any]
    explanations: list[dict[str, str]]
    error_type: str | None = None
    error_message: str | None = None
    analysis_id: int | None = None
    json_file: str | None = None


@dataclass
class PageFetchResult:
    response: Response | None
    final_url: str
    redirect_chain: list[str]
    reasons: list[str]
    reachability: str
    error_type: str | None = None
    error_message: str | None = None


def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=1,
        backoff_factor=0.2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    })
    return session


def _is_text_content_type(content_type: str) -> bool:
    """Check if Content-Type header indicates text-like content."""
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    text_types = {"text/html", "text/plain", "text/xml", "application/xhtml+xml", "application/xml"}
    return ct in text_types


def _is_garbled_content(raw_bytes: bytes) -> bool:
    """Detect if raw bytes look like binary/compressed data rather than readable text."""
    if not raw_bytes:
        return False
    sample = raw_bytes[:4096]
    if len(sample) == 0:
        return False
    null_count = sample.count(b'\x00')
    if null_count > len(sample) * 0.05:
        return True
    non_printable = sum(1 for b in sample if b < 9 or (b > 13 and b < 32 and b != 27))
    if non_printable > len(sample) * 0.15:
        return True
    return False


def _is_text_readable(text: str) -> bool:
    """Post-decode check: verify decoded text is human-readable, not decoded garbage.
    Uses ASCII alphanumeric ratio because latin-1 can decode any byte sequence
    and many control/foreign chars register as 'printable' in Unicode."""
    if not text:
        return False
    sample = text[:4096]
    total = len(sample)
    if total == 0:
        return False
    ascii_alnum = sum(1 for ch in sample if ch.isascii() and ch.isalnum())
    ascii_punct = sum(1 for ch in sample if ch.isascii() and ch.isprintable() and not ch.isalnum())
    text_ratio = (ascii_alnum + ascii_punct) / total
    has_html_structure = any(tag in sample.lower() for tag in ("<html", "<head", "<body", "<!doctype", "<div", "<title"))
    if has_html_structure:
        return text_ratio >= 0.25
    return text_ratio >= 0.45


def _safe_decode_response(response) -> tuple[str, str, bool]:
    """Safely decode response content. Returns (text, encoding_used, is_garbled)."""
    content_type = response.headers.get("Content-Type", "")
    if not _is_text_content_type(content_type):
        return "", content_type, True

    raw = response.content
    if not raw:
        return "", content_type, False

    if _is_garbled_content(raw):
        return "", content_type, True

    charset = ""
    ct_lower = content_type.lower()
    for part in ct_lower.split(";"):
        part = part.strip()
        if part.startswith("charset="):
            charset = part[len("charset="):].strip().strip('"').strip("'")
            break

    encodings = [charset, response.apparent_encoding, "utf-8", "latin-1"] if charset else [response.apparent_encoding, "utf-8", "latin-1"]
    for enc in encodings:
        if not enc:
            continue
        try:
            text = raw.decode(enc, errors="strict")
            if _is_garbled_content(text.encode("utf-8", errors="replace")):
                continue
            if not _is_text_readable(text):
                return "", f"{content_type} (charset={enc}, unreadable)", True
            return text, f"{content_type} (charset={enc})", False
        except (UnicodeDecodeError, LookupError):
            continue

    text = raw.decode("utf-8", errors="replace")
    if _is_garbled_content(text.encode("utf-8", errors="replace")):
        return "", content_type, True
    if not _is_text_readable(text):
        return "", f"{content_type} (fallback, unreadable)", True
    return text, f"{content_type} (fallback utf-8 replace)", False


def _is_bot_blocked(text: str) -> bool:
    """Detect if the response is a bot-detection page (reCAPTCHA, Cloudflare, etc.)."""
    if not text:
        return False
    lower = text.lower()
    strong_indicators = [
        "recaptcha",
        "please verify you are human",
        "please verify you are not a robot",
        "checking your browser",
        "just a moment",
        "verify you are not a robot",
        "cf-browser-verification",
        "captcha-container",
        "g-recaptcha",
    ]
    if any(indicator in lower for indicator in strong_indicators):
        return True
    if 'meta http-equiv="refresh"' in lower and "bm-verify" in lower:
        return True
    return False


def fetch_page(url: str, timeout: int, max_redirect_depth: int, retry_count: int) -> PageFetchResult:
    session = _build_session()
    last_exception: Exception | None = None
    error_type: str = "unreachable"
    message: str = "The target website could not be fetched"

    for _attempt in range(retry_count + 1):
        current_url = url
        redirect_chain = [url]
        try:
            response = None
            for _hop in range(max_redirect_depth + 1):
                response = session.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                )
                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get("Location")
                    if not location:
                        raise ReachabilityError(
                            message="Redirect response did not include a location header",
                            error_type="invalid_redirect",
                        )
                    ok, msg, next_url = validate_redirect_target(current_url, location)
                    if not ok:
                        raise ReachabilityError(
                            message=msg or "Redirect target was blocked by network policy",
                            error_type="blocked_redirect",
                        )
                    current_url = next_url
                    redirect_chain.append(current_url)
                    continue
                break
            if response is None:
                raise ReachabilityError(
                    message="The target website could not be fetched",
                    error_type="unreachable",
                )
            if response.is_redirect or response.is_permanent_redirect:
                raise ReachabilityError(
                    message="The target website redirected too many times",
                    error_type="too_many_redirects",
                )

            content_type = response.headers.get("Content-Type", "unknown")
            content_length = len(response.content)
            reasons: list[str] = []
            reachability = "reachable"

            safe_text, decode_info, is_garbled = _safe_decode_response(response)
            response._safe_text = safe_text
            response._is_garbled = is_garbled
            response._decode_info = decode_info

            try:
                current_app.logger.info(
                    f"[CONTENT AUDIT] Content-Type: {content_type} | "
                    f"Content-Length: {content_length} | "
                    f"Decoded-as-text: {not is_garbled} | "
                    f"Decode-info: {decode_info}"
                )
            except RuntimeError:
                pass

            if is_garbled and content_length > 0:
                reachability = "partially_reachable"
                reasons.append(
                    f"Response content is binary/compressed/unreadable (Content-Type: {content_type})"
                )

            if len(redirect_chain) > 1:
                reachability = "partially_reachable"
                reasons.append(f"Redirect chain observed ({len(redirect_chain) - 1} redirects)")
            if response.status_code >= 400:
                reachability = "partially_reachable"
                reasons.append(f"Page returned HTTP {response.status_code}")

            if not is_garbled and safe_text and _is_bot_blocked(safe_text):
                reachability = "partially_reachable"
                reasons.append("Page returned bot-detection challenge (reCAPTCHA/Cloudflare)")

            return PageFetchResult(response, response.url, redirect_chain, reasons, reachability)
        except ReachabilityError:
            raise
        except (RequestsTimeout, ReadTimeout) as exc:
            last_exception = exc
            error_type = "timeout"
            message = "The target website timed out during analysis"
        except SSLError as exc:
            last_exception = exc
            error_type = "tls_error"
            message = "The target website failed TLS validation"
        except RequestsConnectionError as exc:
            last_exception = exc
            error_type = "dns_error"
            message = "The target website could not be reached over the network"
        except requests.TooManyRedirects as exc:
            last_exception = exc
            error_type = "too_many_redirects"
            message = "The target website redirected too many times"
        except RequestException as exc:
            last_exception = exc
            error_type = "unreachable"
            message = "The target website could not be fetched"

    raise ReachabilityError(message=message, error_type=error_type) from last_exception


def _reason_code(message: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", message.lower()).strip("_")
    return normalized[:64] or "unspecified_signal"


def _build_explanations(reasons: list[str]) -> list[dict[str, str]]:
    return [{"code": _reason_code(reason), "message": reason} for reason in reasons]


def _crawl_page(url: str, base_domain: str, session: requests.Session, timeout: int, crawled: set[str]) -> tuple[str, list[str]]:
    """Crawl a single page and return its text content and reasons."""
    reasons: list[str] = []
    try:
        resp = session.get(url, timeout=timeout, headers={"User-Agent": "Detector/1.0"})
        if resp.status_code != 200 or not resp.text:
            return "", reasons
        return resp.text, reasons
    except Exception:
        return "", reasons


def crawl_website(base_url: str, max_pages: int = 5, timeout: int = 5) -> tuple[str, list[str]]:
    """Crawl multiple pages within the same domain to gather comprehensive content."""
    session = _build_session()
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.hostname or ""
    to_visit = [base_url]
    visited: set[str] = set()
    all_text_parts: list[str] = []
    all_reasons: list[str] = []
    same_domain_links = 0
    external_links = 0
    suspicious_links = 0

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            page_text, _reasons = _crawl_page(current_url, base_domain, session, timeout, visited)
            if not page_text:
                continue
            all_text_parts.append(page_text)

            soup = BeautifulSoup(page_text, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if not href or href.startswith("#") or href.startswith("javascript:"):
                    continue
                full_url = urljoin(current_url, href)
                parsed_link = urlparse(full_url)
                if parsed_link.hostname == base_domain and full_url not in visited:
                    if full_url not in to_visit and len(visited) + len(to_visit) < max_pages:
                        to_visit.append(full_url)
                    same_domain_links += 1
                elif parsed_link.hostname and parsed_link.hostname != base_domain:
                    external_links += 1
                    suspicious_keywords = ["login", "verify", "account", "update", "confirm"]
                    if any(kw in href.lower() for kw in suspicious_keywords):
                        suspicious_links += 1
        except Exception:
            continue

    if same_domain_links > 0:
        all_reasons.append(f"Website has {same_domain_links} internal page(s) linked")
    if external_links > 5:
        all_reasons.append(f"Website links to {external_links} external domains")
    if suspicious_links > 0:
        all_reasons.append(f"Found {suspicious_links} suspicious external link(s)")

    return "\n\n".join(all_text_parts), all_reasons


def deep_content_inspection(response: Response, final_url: str) -> tuple[dict[str, float], list[str]]:
    signals = {
        "has_password_field": 0.0,
        "external_form_action": 0.0,
        "iframe_count": 0.0,
        "external_script_count": 0.0,
        "redirect_count": 0.0,
        "missing_favicon": 1.0,
        "no_contact_info": 1.0,
        "no_privacy_policy_link": 1.0,
        "copyright_year_outdated": 0.0,
        "too_many_ads": 0.0,
        "mailto_links": 0.0,
        "tel_links": 0.0,
        "suspicious_external_links": 0.0,
        "login_form_detected": 0.0,
        "ssl_cert_issues": 0.0,
        "meta_tags_missing": 0.0,
        "hidden_elements": 0.0,
    }
    reasons: list[str] = []

    page_text = getattr(response, "_safe_text", None)
    if not page_text:
        try:
            page_text = response.text
        except Exception:
            return signals, reasons

    if not page_text:
        return signals, reasons

    soup = BeautifulSoup(page_text, "html.parser")

    password_fields = soup.find_all("input", type="password")
    if password_fields:
        signals["has_password_field"] = float(len(password_fields))
        reasons.append(f"Page contains {len(password_fields)} password field(s)")

    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            parsed_action = urlparse(action)
            parsed_final = urlparse(final_url)
            if parsed_action.netloc and parsed_action.netloc != parsed_final.netloc:
                signals["external_form_action"] = 1.0
                reasons.append("Form submits to external domain")
                break

    iframes = soup.find_all("iframe")
    if iframes:
        signals["iframe_count"] = float(len(iframes))
        reasons.append(f"Page contains {len(iframes)} iframe(s)")

    script_srcs = soup.find_all("script", src=True)
    external_scripts = 0
    ad_domains = 0
    ad_keywords = ["ads", "advert", "doubleclick", "googlesyndication", "adsystem", "adnxs", "criteo", "rubiconproject"]
    for script in script_srcs:
        src = script.get("src", "")
        if src.startswith("http://") or src.startswith("https://"):
            parsed_src = urlparse(src)
            parsed_final = urlparse(final_url)
            if parsed_src.netloc != parsed_final.netloc:
                external_scripts += 1
                if any(kw in parsed_src.netloc.lower() for kw in ad_keywords):
                    ad_domains += 1
    if external_scripts:
        signals["external_script_count"] = float(external_scripts)
        reasons.append(f"Page loads {external_scripts} external script(s)")
    if ad_domains >= 3:
        signals["too_many_ads"] = 1.0
        reasons.append("Page loads scripts from multiple ad networks")

    favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    if favicon:
        signals["missing_favicon"] = 0.0

    text = soup.get_text(" ", strip=True).lower()
    contact_keywords = ["contact", "email", "phone", "address", "support", "help"]
    if not any(kw in text for kw in contact_keywords):
        signals["no_contact_info"] = 1.0
        reasons.append("No contact information found")
    else:
        signals["no_contact_info"] = 0.0

    privacy_links = soup.find_all("a", href=True)
    has_privacy = any("privacy" in link.get("href", "").lower() or "privacy" in link.get_text().lower() for link in privacy_links)
    if not has_privacy:
        signals["no_privacy_policy_link"] = 1.0
        reasons.append("No privacy policy link found")
    else:
        signals["no_privacy_policy_link"] = 0.0

    current_year = datetime.now().year
    copyright_matches = re.findall(r"©|copyright|\(c\)\s*(\d{4})", text, re.IGNORECASE)
    if copyright_matches:
        try:
            years = [int(y) for y in copyright_matches]
            max_year = max(years)
            if current_year - max_year > 3:
                signals["copyright_year_outdated"] = 1.0
                reasons.append(f"Copyright year outdated ({max_year})")
        except ValueError:
            pass

    mailto_links = soup.find_all("a", href=lambda x: x and x.startswith("mailto:"))
    if mailto_links:
        signals["mailto_links"] = float(len(mailto_links))

    tel_links = soup.find_all("a", href=lambda x: x and x.startswith("tel:"))
    if tel_links:
        signals["tel_links"] = float(len(tel_links))

    login_forms = soup.find_all("form")
    login_form_count = 0
    for form in login_forms:
        if form.find("input", type="password") or form.find("input", {"name": re.compile(r"(login|username|email)", re.I)}):
            login_form_count += 1
    if login_form_count:
        signals["login_form_detected"] = float(login_form_count)
        reasons.append(f"Page contains {login_form_count} login form(s)")

    hidden_inputs = soup.find_all("input", type="hidden")
    if len(hidden_inputs) > 5:
        signals["hidden_elements"] = 1.0
        reasons.append(f"Page contains {len(hidden_inputs)} hidden input fields")

    meta_description = soup.find("meta", attrs={"name": "description"})
    meta_keywords = soup.find("meta", attrs={"name": "keywords"})
    if not meta_description or not meta_keywords:
        signals["meta_tags_missing"] = 1.0
        reasons.append("Missing important meta tags (description/keywords)")

    # Zero-Connection Content Similarity Check
    suspicious_words = ['login', 'verify', 'password', 'security', 'suspended', 'banking', 'wallet', 'account']
    page_text = text
    found_words = [word for word in suspicious_words if word in page_text]

    parsed_final = urlparse(final_url)
    domain_parts = parsed_final.netloc.split('.')
    is_domain_mismatched = True
    for word in found_words:
        if any(word in part for part in domain_parts):
            is_domain_mismatched = False
            break

    if len(found_words) >= 3 and is_domain_mismatched:
        signals["content_domain_mismatch"] = 1.0
        reasons.append(f"Page uses multiple high-urgency keywords ({', '.join(found_words)}) but domain is mismatched")

    return signals, reasons


def score_analysis(features: dict[str, float], page_signals: dict[str, float], reasons: list[str], config: dict[str, Any]) -> tuple[int, str]:
    from app.config import compute_label_from_score

    score = 0

    # URL-level signals
    if features.get("url_length", 0) > 75:
        score += 8
    if features.get("is_typosquatting", 0):
        score += 30
    if features.get("subdomain_count", 0) > 2:
        score += int((features["subdomain_count"] - 2) * 6)
    if features.get("has_ip", 0):
        score += 20
    suspicious_chars = int(features.get("suspicious_chars", 0))
    score += min(suspicious_chars * 2, 12)
    keyword_hits = int(features.get("keyword_hits", 0))
    score += min(keyword_hits * 6, 24)
    if features.get("is_shortener", 0):
        score += 15
    if features.get("phishing_tld", 0):
        score += 12
    if not features.get("uses_https", 1):
        score += 10

    domain_age = features.get("domain_age_days", -1)

    # Brand impersonation — strong penalty regardless of domain age
    brand_hits = features.get("brand_hits", [])
    if features.get("brand_impersonation", 0) and brand_hits:
        score += 10

        # Compound: brand + suspicious TLD (always penalize)
        if features.get("phishing_tld", 0):
            score += 10
            reasons.append("Brand name combined with suspicious TLD")

        # Compound: brand + appended digits (typosquatting pattern)
        domain_str = features.get("raw_domain", "")
        for brand in brand_hits:
            if re.search(rf"{re.escape(brand)}\d", domain_str, re.IGNORECASE):
                score += 10
                reasons.append(f"Brand '{brand}' with appended digits (typosquatting pattern)")
                break

        # Compound: brand + appended text (brand impersonation with extra keywords)
        for brand in brand_hits:
            remaining = re.sub(rf"{re.escape(brand)}", "", domain_str, flags=re.IGNORECASE)
            remaining = re.sub(r"[.\-]", "", remaining)
            if len(remaining) >= 3:
                score += 8
                reasons.append(f"Brand '{brand}' with appended text '{remaining}'")
                break

        # Compound: brand + young domain (existing rule, kept)
        if domain_age > 0 and domain_age < config.get("DOMAIN_AGE_MODERATE_RISK_DAYS", 365):
            score += 15
            reasons.append("High risk compound: Domain contains a brand name and is newly registered")

    # Domain intelligence base penalties based on age buckets
    if domain_age >= 0 and not features.get("whois_unavailable", 0):
        if domain_age < config.get("DOMAIN_AGE_EXTREME_RISK_DAYS", 30):
            score += 35
            reasons.append(f"Domain is extremely young ({domain_age} days)")
        elif domain_age < config.get("DOMAIN_AGE_VERY_HIGH_RISK_DAYS", 90):
            score += 25
            reasons.append(f"Domain is very young ({domain_age} days)")
        elif domain_age < config.get("DOMAIN_AGE_HIGH_RISK_DAYS", 180):
            score += 15
            reasons.append(f"Domain is relatively young ({domain_age} days)")
        elif domain_age < config.get("DOMAIN_AGE_MODERATE_RISK_DAYS", 365):
            score += 8
            reasons.append(f"Domain is moderately young ({domain_age} days)")

    if features.get("whois_unavailable", 0):
        score += 5

    # Page-level signals - only apply if page was successfully fetched and not bot-blocked
    page_fetched = not page_signals.get("page_unreachable", 0)
    bot_blocked = page_signals.get("bot_detection", 0)
    binary_response = page_signals.get("binary_response", 0)

    # Compound risks (TLD + Young Age)
    if domain_age > 0 and domain_age < config.get("DOMAIN_AGE_MODERATE_RISK_DAYS", 365):
        if features.get("phishing_tld", 0):
            score += 10
            reasons.append("High risk compound: Suspicious TLD combined with recently registered domain")

    if page_fetched and not bot_blocked and not binary_response:
        if page_signals.get("has_password_field", 0) and not features.get("uses_https", 1):
            score += 15
        if page_signals.get("external_form_action", 0):
            score += 12
        iframe_count = int(page_signals.get("iframe_count", 0))
        score += min(iframe_count * 5, 15)
        external_script_count = int(page_signals.get("external_script_count", 0))
        score += min(external_script_count * 3, 9)
        redirect_count = int(page_signals.get("redirect_count", 0))
        if redirect_count > 1:
            score += min((redirect_count - 1) * 3, 12)
        if page_signals.get("http_error_status", 0):
            score += 8
        if page_signals.get("missing_favicon", 1):
            score += 4
        if page_signals.get("no_contact_info", 1):
            score += 5
        if page_signals.get("no_privacy_policy_link", 1):
            score += 4
        if page_signals.get("copyright_year_outdated", 0):
            score += 6
        if page_signals.get("too_many_ads", 0):
            score += 8
        if page_signals.get("content_domain_mismatch", 0):
            score += 20

    # Bot detection handling
    if bot_blocked:
        score += 5
    elif binary_response:
        score += 15
    elif page_signals.get("page_unreachable", 0):
        if domain_age > config.get("YOUNG_DOMAIN_DAYS", 30):
            score += 10
        else:
            score += 20

    # Optional VirusTotal bump using configurable values
    vt_summary = page_signals.get("vt_summary", {})
    if vt_summary and vt_summary.get("status") == "success":
        malicious = vt_summary.get("malicious_count", 0)
        suspicious = vt_summary.get("suspicious_count", 0)
        vt_bump_per_malicious = config.get("VT_SCORE_BUMP_MALICIOUS", 15)
        vt_bump_per_suspicious = config.get("VT_SCORE_BUMP_SUSPICIOUS", 5)
        vt_max_malicious = config.get("VT_MAX_BUMP_MALICIOUS", 30)
        vt_max_suspicious = config.get("VT_MAX_BUMP_SUSPICIOUS", 10)
        if malicious > 0:
            bump = min(malicious * vt_bump_per_malicious, vt_max_malicious)
            score += bump
            reasons.append(f"VirusTotal: {malicious} engine(s) detecting URL as malicious (+{bump})")
        if suspicious > 0:
            bump = min(suspicious * vt_bump_per_suspicious, vt_max_suspicious)
            score += bump
            reasons.append(f"VirusTotal: {suspicious} engine(s) detecting URL as suspicious (+{bump})")

    sb_summary = page_signals.get("sb_summary", {})
    if sb_summary and sb_summary.get("status") == "success" and not sb_summary.get("safe"):
        score += 20
        matches = sb_summary.get("matches", [])
        reasons.append(f"Google Safe Browsing flagged this URL. Threats: {', '.join(matches)} (+20)")

    abuseipdb_summary = page_signals.get("abuseipdb_summary", {})
    if abuseipdb_summary and abuseipdb_summary.get("status") == "success":
        confidence = abuseipdb_summary.get("abuseConfidenceScore", 0)
        if confidence > 0:
            bump = min(int(confidence / 5), 15)
            score += bump
            reasons.append(f"AbuseIPDB flagged IP with {confidence}% confidence (+{bump})")

    score = max(0, min(score, 100))
    label = compute_label_from_score(score, config)

    return score, label


def run_analysis(raw_url: str, config: dict[str, Any], *, persist: bool = True) -> AnalysisResult:
    timeout = max(int(config.get("REQUEST_TIMEOUT_SECONDS", 10)), 1)
    retry_count = max(int(config.get("REQUEST_RETRY_COUNT", 1)), 0)
    normalized = normalize_url(raw_url)

    try:
        current_app.logger.info("================ STARTING DETECTION PIPELINE ================")
        current_app.logger.info(f"Targeting URL: {normalized}")
    except RuntimeError:
        pass

    ok, message = validate_url(normalized)
    if not ok:
        raise AnalysisInputError(message)
    domain = sanitized_domain(normalized)
    hashed = url_hash(normalized)

    # Extract URL features
    features, reasons = extract_url_features(normalized)

    # Initialize page fetch result variables
    reachability: str = "unreachable"
    redirect_chain: list[str] = [normalized]
    status_code: int | None = None
    error_type: str | None = None
    error_message: str | None = None
    page_signals: dict[str, Any] = {
        "has_password_field": 0.0,
        "external_form_action": 0.0,
        "iframe_count": 0.0,
        "external_script_count": 0.0,
        "redirect_count": 0.0,
        "http_error_status": 0.0,
        "missing_favicon": 1.0,
        "no_contact_info": 1.0,
        "no_privacy_policy_link": 1.0,
        "copyright_year_outdated": 0.0,
        "too_many_ads": 0.0,
        "page_unreachable": 0.0,
        "bot_detection": 0.0,
        "binary_response": 0.0,
    }

    # Fetch page and do deep content inspection
    try:
        try:
            current_app.logger.info("[STEP 1/2] Initializing BeautifulSoup Parser...")
        except RuntimeError:
            pass
        bs_start_time = time.perf_counter()

        page_result = fetch_page(
            normalized,
            timeout=timeout,
            max_redirect_depth=config["MAX_REDIRECT_DEPTH"],
            retry_count=retry_count,
        )
        response = page_result.response
        if response:
            reachability = page_result.reachability
            redirect_chain = page_result.redirect_chain
            status_code = response.status_code
            error_type = page_result.error_type
            error_message = page_result.error_message
            reasons.extend(page_result.reasons)

            page_signals["redirect_count"] = float(max(len(redirect_chain) - 1, 0))

            if status_code and status_code >= 400:
                page_signals["http_error_status"] = 1.0

            safe_text = getattr(response, "_safe_text", "")
            is_garbled = getattr(response, "_is_garbled", True)
            content_type = response.headers.get("Content-Type", "unknown")

            if is_garbled and len(response.content) > 0:
                page_signals["binary_response"] = 1.0
                reasons.append(
                    f"Fetched content is binary/unreadable (Content-Type: {content_type}). Skipping deep content inspection."
                )
                try:
                    current_app.logger.warning(
                        f"[CONTENT AUDIT] Skipping content parsing. Binary or garbled response detected. "
                        f"Content-Type: {content_type} | Content-Length: {len(response.content)}"
                    )
                except RuntimeError:
                    pass
            else:
                bot_blocked = _is_bot_blocked(safe_text or "")
                if bot_blocked:
                    page_signals["bot_detection"] = 1.0
                else:
                    content_signals, content_reasons = deep_content_inspection(response, response.url)
                    page_signals.update(content_signals)
                    reasons.extend(content_reasons)

            try:
                bs_duration = time.perf_counter() - bs_start_time
                current_app.logger.info(f"[SUCCESS] BeautifulSoup parsing completed in {bs_duration:.4f}s.")
                form_count = int(page_signals.get("has_password_field", 0))
                iframe_count = int(page_signals.get("iframe_count", 0))
                script_count = int(page_signals.get("external_script_count", 0))
                if page_signals.get("bot_detection", 0):
                    current_app.logger.info("[CONTENT AUDIT] Bot-detection page detected. Skipping content analysis.")
                elif page_signals.get("binary_response", 0):
                    current_app.logger.info("[CONTENT AUDIT] Binary/non-HTML content detected. Skipping content analysis.")
                else:
                    current_app.logger.info(
                        f"[SCRAPER AUDIT DATA] Issues: {form_count} password fields, "
                        f"{iframe_count} iframes, {script_count} scripts."
                    )
            except RuntimeError:
                pass
        else:
            page_signals["page_unreachable"] = 1.0
            reasons.append("Page could not be fetched")
            try:
                current_app.logger.error("[FAILURE] Page could not be fetched.")
            except RuntimeError:
                pass
    except ReachabilityError as exc:
        reachability = "unreachable"
        redirect_chain = [normalized]
        status_code = None
        error_type = exc.error_type
        error_message = exc.message
        reasons.append(exc.message)
        page_signals["page_unreachable"] = 1.0

    # Domain intelligence (WHOIS)
    try:
        current_app.logger.info("[STEP 2/2] Executing Local Heuristic Rule-Engine...")
    except RuntimeError:
        pass

    domain_info, domain_reasons = get_domain_intelligence(
        domain,
        whois_api_key=config.get("WHOIS_API_KEY", ""),
    )
    features["domain_age_days"] = float(domain_info.get("domain_age_days", -1))
    features["domain_age_bucket"] = domain_info.get("domain_age_bucket")
    features["whois_unavailable"] = 1.0 if domain_info.get("domain_age_days", -1) == -1 and "WHOIS lookup unavailable" in domain_reasons else 0.0
    reasons.extend(domain_reasons)

    # VirusTotal Integration
    vt_enabled = config.get("VT_ENABLED", False) and bool(config.get("VT_API_KEY"))
    if vt_enabled:
        try:
            current_app.logger.info("[VT AUDIT] Starting VirusTotal URL lookup...")
        except RuntimeError:
            pass
        from app.phishing.virustotal import get_virustotal_report
        vt_data = get_virustotal_report(normalized, config)
        if vt_data:
            page_signals["vt_summary"] = vt_data
            vt_status = vt_data.get("status", "unknown")
            if vt_status == "success":
                try:
                    current_app.logger.info(
                        f"[VT AUDIT] Lookup successful: {vt_data.get('malicious_count', 0)} malicious, "
                        f"{vt_data.get('suspicious_count', 0)} suspicious"
                    )
                except RuntimeError:
                    pass
            elif vt_status == "rate_limited":
                try:
                    current_app.logger.warning("[VT AUDIT] Rate limited by VirusTotal API.")
                except RuntimeError:
                    pass
            elif vt_status == "not_found":
                try:
                    current_app.logger.info("[VT AUDIT] URL not found in VirusTotal database.")
                except RuntimeError:
                    pass
            else:
                try:
                    current_app.logger.warning(f"[VT AUDIT] Lookup returned status: {vt_status}")
                except RuntimeError:
                    pass
    else:
        try:
            current_app.logger.info("[VT AUDIT] VirusTotal lookup skipped (not enabled or no API key).")
        except RuntimeError:
            pass

    # SafeBrowsing Integration
    sb_enabled = bool(config.get("SAFEBROWSING_API_KEY"))
    if sb_enabled:
        try:
            current_app.logger.info("[SB AUDIT] Starting Safe Browsing URL lookup...")
        except RuntimeError:
            pass
        from app.phishing.safebrowsing import get_safebrowsing_report
        sb_data = get_safebrowsing_report(normalized, config)
        if sb_data:
            page_signals["sb_summary"] = sb_data
            sb_status = sb_data.get("status", "unknown")
            if sb_status == "success":
                try:
                    current_app.logger.info(f"[SB AUDIT] Lookup successful, safe: {sb_data.get('safe')}")
                except RuntimeError:
                    pass

    # Urlscan Integration
    us_enabled = bool(config.get("URLSCAN_API_KEY"))
    if us_enabled:
        try:
            current_app.logger.info("[URLSCAN AUDIT] Starting URLScan submission...")
        except RuntimeError:
            pass
        from app.phishing.urlscan import get_urlscan_report
        us_data = get_urlscan_report(normalized, config)
        if us_data:
            page_signals["us_summary"] = us_data

    # AbuseIPDB Integration
    ip = features.get("ip_address")
    abuseipdb_enabled = bool(config.get("ABUSEIPDB_API_KEY")) and ip
    if abuseipdb_enabled:
        try:
            current_app.logger.info("[ABUSEIPDB AUDIT] Starting AbuseIPDB lookup...")
        except RuntimeError:
            pass
        from app.phishing.abuseipdb import get_abuseipdb_report
        abuseipdb_data = get_abuseipdb_report(ip, config)
        if abuseipdb_data:
            page_signals["abuseipdb_summary"] = abuseipdb_data

    # Score the analysis
    risk_score, label = score_analysis(features, page_signals, reasons, config)

    try:
        from app.config import compute_label_from_score
        canonical_label = compute_label_from_score(risk_score, config)
        if canonical_label != label:
            current_app.logger.warning(
                f"[LABEL MISMATCH DETECTED] score_analysis returned '{label}' but "
                f"canonical compute_label_from_score returned '{canonical_label}' for score {risk_score}"
            )
            label = canonical_label
    except Exception:
        pass

    try:
        current_app.logger.info("[SUCCESS] Heuristic Execution Complete.")
        current_app.logger.info(
            f"[HEURISTIC AUDIT DATA] Score: {risk_score} | Label: {label} | "
            f"Age bucket: {domain_info.get('domain_age_bucket', 'unknown')} | "
            f"Brand hits: {features.get('brand_hits', [])} | "
            f"Binary: {bool(page_signals.get('binary_response', 0))} | "
            f"VT enabled: {vt_enabled}"
        )
    except RuntimeError:
        pass

    # Crawl additional pages within the same domain (skip if binary)
    all_page_texts: list[str] = []
    if response is not None and not page_signals.get("binary_response", 0):
        safe_text = getattr(response, "_safe_text", "")
        if safe_text:
            all_page_texts.append(safe_text)

    if status_code == 200 and not page_signals.get("binary_response", 0):
        crawl_text, crawl_reasons = crawl_website(normalized, max_pages=5, timeout=min(timeout, 5))
        if crawl_text:
            all_page_texts.append(crawl_text)
        reasons.extend(crawl_reasons)

    features_summary = {
        "url_features": {k: v for k, v in features.items() if k != "path_length"},
        "page_signals": page_signals,
        "reachability": reachability,
        "status_code": status_code,
        "domain_age_days": features.get("domain_age_days", 0),
        "domain_info": {
            "creation_date": domain_info.get("creation_date"),
            "expiration_date": domain_info.get("expiration_date"),
            "registrar": domain_info.get("registrar", "unknown"),
            "name_servers": domain_info.get("name_servers", []),
            "domain_age_bucket": domain_info.get("domain_age_bucket", ""),
        },
        "brand_token_hits": features.get("brand_hits", []),
    }
    explanations = _build_explanations(list(dict.fromkeys(reasons)))

    result = AnalysisResult(
        raw_url=raw_url,
        normalized_url=normalized,
        domain=domain,
        url_hash=hashed,
        risk_score=risk_score,
        label=label,
        reasons=list(dict.fromkeys(reasons)),
        reachability=reachability,
        redirect_chain=redirect_chain,
        status_code=status_code,
        features_summary=features_summary,
        explanations=explanations,
        error_type=error_type,
        error_message=error_message,
    )

    if persist:
        analysis = save_analysis(result)
        result.analysis_id = analysis.id

    json_file = _save_result_json(result)
    result.json_file = json_file

    try:
        current_app.logger.info("================ PIPELINE PROCESSING COMPLETE ================\n")
    except RuntimeError:
        pass
    return result


def save_analysis(result: AnalysisResult) -> Analysis:
    analysis = Analysis(
        raw_url=result.raw_url,
        normalized_url=result.normalized_url,
        domain=result.domain,
        risk_score=result.risk_score,
        label=result.label,
        reachability=result.reachability,
        reasons=result.reasons,
        redirect_chain=result.redirect_chain,
        features_summary=result.features_summary,
        status_code=result.status_code,
        error_type=result.error_type,
        error_message=result.error_message,
    )
    db.session.add(analysis)
    db.session.commit()
    return analysis


def serialize_analysis(analysis: Analysis) -> dict[str, Any]:
    features_summary = analysis.features_summary or {}
    return {
        "analysis_id": analysis.id,
        "url": analysis.normalized_url,
        "domain": analysis.domain,
        "risk_score": analysis.risk_score,
        "label": analysis.label,
        "reasons": analysis.reasons,
        "reachability": analysis.reachability,
        "redirect_chain": analysis.redirect_chain,
        "features_summary": features_summary,
        "explanations": features_summary.get("explanations", []),
        "status_code": analysis.status_code,
        "error": (
            {"type": analysis.error_type, "message": analysis.error_message}
            if analysis.error_type
            else None
        ),
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "feedback": analysis.feedback,
        "feedback_note": analysis.feedback_note,
        "json_file": f"/api/report/{analysis.id}",
        "report_url": f"/report/{analysis.id}",
    }


def _save_result_json(result: AnalysisResult) -> str | None:
    if result.analysis_id is None:
        return None
    results_dir = Path(current_app.config.get("RESULTS_DIR", "results"))
    results_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "analysis_id": result.analysis_id,
        "url": result.normalized_url,
        "raw_url": result.raw_url,
        "domain": result.domain,
        "url_hash": result.url_hash,
        "risk_score": result.risk_score,
        "label": result.label,
        "reasons": result.reasons,
        "reachability": result.reachability,
        "redirect_chain": result.redirect_chain,
        "status_code": result.status_code,
        "features_summary": result.features_summary,
        "explanations": result.explanations,
        "error_type": result.error_type,
        "error_message": result.error_message,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    file_path = results_dir / f"{result.analysis_id}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, default=str, sort_keys=True)
    return str(file_path)


def recent_analyses(limit: int = 10) -> list[Analysis]:
    return Analysis.query.order_by(Analysis.created_at.desc()).limit(limit).all()