from __future__ import annotations

import hashlib
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import whois
from bs4 import BeautifulSoup
from flask import current_app
from requests import Response
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout, RequestException, SSLError
from requests.exceptions import Timeout as RequestsTimeout
from sqlalchemy import func
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
    return session


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
                    headers={"User-Agent": "Detector/1.0"},
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
            reasons: list[str] = []
            reachability = "reachable"
            if len(redirect_chain) > 1:
                reachability = "partially_reachable"
                reasons.append(f"Redirect chain observed ({len(redirect_chain) - 1} redirects)")
            if response.status_code >= 400:
                reachability = "partially_reachable"
                reasons.append(f"Page returned HTTP {response.status_code}")
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


def deep_content_inspection(response: Response, final_url: str) -> tuple[dict[str, float], list[str]]:
    """Perform deep content inspection using BeautifulSoup."""
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
    }
    reasons: list[str] = []

    if not response or not response.text:
        return signals, reasons

    soup = BeautifulSoup(response.text, "html.parser")

    # Check for password fields
    password_fields = soup.find_all("input", type="password")
    if password_fields:
        signals["has_password_field"] = float(len(password_fields))
        reasons.append(f"Page contains {len(password_fields)} password field(s)")

    # Check forms with external actions
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action and (action.startswith("http://") or action.startswith("https://")):
            parsed_action = urlparse(action)
            parsed_final = urlparse(final_url)
            if parsed_action.netloc != parsed_final.netloc:
                signals["external_form_action"] = 1.0
                reasons.append("Form submits to external domain")
                break

    # Check iframes
    iframes = soup.find_all("iframe")
    if iframes:
        signals["iframe_count"] = float(len(iframes))
        reasons.append(f"Page contains {len(iframes)} iframe(s)")

    # Check external scripts
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
                # Check for ad-related domains
                if any(kw in parsed_src.netloc.lower() for kw in ad_keywords):
                    ad_domains += 1
    if external_scripts:
        signals["external_script_count"] = float(external_scripts)
        reasons.append(f"Page loads {external_scripts} external script(s)")
    if ad_domains >= 3:
        signals["too_many_ads"] = 1.0
        reasons.append("Page loads scripts from multiple ad networks")

    # Check for favicon
    favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    if favicon:
        signals["missing_favicon"] = 0.0

    # Check for contact info
    text = soup.get_text(" ", strip=True).lower()
    contact_keywords = ["contact", "email", "phone", "address", "support", "help"]
    if not any(kw in text for kw in contact_keywords):
        signals["no_contact_info"] = 1.0
        reasons.append("No contact information found")
    else:
        signals["no_contact_info"] = 0.0

    # Check for privacy policy link
    privacy_links = soup.find_all("a", href=True)
    has_privacy = any("privacy" in link.get("href", "").lower() or "privacy" in link.get_text().lower() for link in privacy_links)
    if not has_privacy:
        signals["no_privacy_policy_link"] = 1.0
        reasons.append("No privacy policy link found")
    else:
        signals["no_privacy_policy_link"] = 0.0

    # Check copyright year
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

    return signals, reasons


def score_analysis(features: dict[str, float], page_signals: dict[str, float], reasons: list[str], config: dict[str, Any]) -> tuple[int, str]:
    score = 0

    # URL-level signals
    if features.get("url_length", 0) > 75:
        score += 8
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

    # Domain intelligence
    domain_age = features.get("domain_age_days", 0)
    if 0 < domain_age < config.get("NEW_DOMAIN_DAYS", 7):
        score += config.get("NEW_DOMAIN_PENALTY", 20)
    elif 0 < domain_age < config.get("YOUNG_DOMAIN_DAYS", 30):
        score += config.get("YOUNG_DOMAIN_PENALTY", 10)
    if features.get("whois_unavailable", 0):
        score += 5

    # Page-level signals
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
    if page_signals.get("page_unreachable", 0):
        score += 30

    score = max(0, min(score, 100))

    if score >= config.get("PHISHING_THRESHOLD", 80):
        label = "phishing"
    elif score >= config.get("SUSPICIOUS_THRESHOLD", 60):
        label = "suspicious"
    elif score < config.get("SAFE_THRESHOLD", 30):
        label = "safe"
    else:
        label = "suspicious"  # medium risk

    return score, label


def run_analysis(raw_url: str, config: dict[str, Any], *, persist: bool = True) -> AnalysisResult:
    started_at = time.perf_counter()
    timeout = max(int(config.get("REQUEST_TIMEOUT_SECONDS", 10)), 1)
    retry_count = max(int(config.get("REQUEST_RETRY_COUNT", 1)), 0)
    normalized = normalize_url(raw_url)
    try:
        current_app.logger.info("analysis_started", extra={"raw_url": raw_url})
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
    page_signals: dict[str, float] = {
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
    }

    # Fetch page and do deep content inspection
    try:
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

            # Track redirect count
            page_signals["redirect_count"] = float(max(len(redirect_chain) - 1, 0))

            # Track HTTP error status
            if status_code and status_code >= 400:
                page_signals["http_error_status"] = 1.0

            # Deep content inspection
            content_signals, content_reasons = deep_content_inspection(response, response.url)
            page_signals.update(content_signals)
            reasons.extend(content_reasons)
        else:
            page_signals["page_unreachable"] = 1.0
            reasons.append("Page could not be fetched")
    except ReachabilityError as exc:
        reachability = "unreachable"
        redirect_chain = [normalized]
        status_code = None
        error_type = exc.error_type
        error_message = exc.message
        reasons.append(exc.message)
        page_signals["page_unreachable"] = 1.0

    # Domain intelligence (WHOIS)
    domain_info, domain_reasons = get_domain_intelligence(
        domain,
        new_domain_days=config.get("NEW_DOMAIN_DAYS", 7),
        young_domain_days=config.get("YOUNG_DOMAIN_DAYS", 30),
    )
    features["domain_age_days"] = float(domain_info.get("domain_age_days", 0))
    features["whois_unavailable"] = 1.0 if domain_info.get("domain_age_days", 0) == 0 and "WHOIS lookup unavailable" in domain_reasons else 0.0
    reasons.extend(domain_reasons)

    # Score the analysis
    risk_score, label = score_analysis(features, page_signals, reasons, config)

    # Build features_summary
    features_summary = {
        "url_features": {k: v for k, v in features.items() if k != "path_length"},
        "page_signals": page_signals,
        "reachability": reachability,
        "status_code": status_code,
        "domain_age_days": features.get("domain_age_days", 0),
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

    try:
        current_app.logger.info(
            "analysis_completed",
            extra={
                "domain": result.domain,
                "label": result.label,
                "risk_score": result.risk_score,
                "latency_ms": int((time.perf_counter() - started_at) * 1000),
            },
        )
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
    }


def recent_analyses(limit: int = 10) -> list[Analysis]:
    return Analysis.query.order_by(Analysis.created_at.desc()).limit(limit).all()