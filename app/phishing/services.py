from __future__ import annotations

import csv
import json
import os
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass
from io import StringIO
from typing import Any

import requests
from flask import current_app
from requests import Response
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout, RequestException, SSLError
from requests.exceptions import Timeout as RequestsTimeout
from sqlalchemy import func
from urllib3.util.retry import Retry

from app.extensions import redis_client, runtime_state
from app.models import Analysis, Blacklist, db

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
from .ml_model import load_model, predict


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
    confidence: float
    model_metadata: dict[str, Any]
    error_type: str | None = None
    error_message: str | None = None
    cache_hit: bool = False
    latency_ms: int = 0
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


def _cache_get(key: str) -> dict[str, Any] | None:
    payload = redis_client.get(key)
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def _cache_set(key: str, payload: dict[str, Any], ttl_seconds: int) -> None:
    try:
        redis_client.setex(key, ttl_seconds, json.dumps(payload, default=str))
    except (TypeError, ValueError):
        pass  # Never crash the request because of a cache write failure


def blacklist_lookup(url_or_domain: str) -> tuple[bool, str | None]:
    try:
        domain = sanitized_domain(url_or_domain)
    except AnalysisInputError:
        domain = url_or_domain.strip().lower()
    entry = Blacklist.query.filter_by(domain=domain).first()
    if not entry:
        return False, None
    source = entry.source.strip().lower() if entry.source else "manual"
    return True, f"local:{source}"


def _threat_intel_hit(domain: str, config: dict[str, Any]) -> str | None:
    raw = (config.get("THREAT_INTEL_STATIC_DOMAINS") or "").strip()
    if not raw:
        return None
    for item in raw.split(","):
        payload = item.strip()
        if not payload:
            continue
        item_domain, _, item_source = payload.partition(":")
        normalized = item_domain.strip().lower()
        if normalized and normalized == domain.lower():
            source = item_source.strip() or "static-feed"
            return f"intel:{source}"
    return None


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
    # Initialize so they are always bound even if the loop never raises
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


def _compute_confidence(score: int, label: str, config: dict[str, Any], *, ml_used: bool) -> float:
    if label == "phishing":
        boundary = config["PHISHING_THRESHOLD"]
    elif label == "suspicious":
        boundary = config["SUSPICIOUS_THRESHOLD"]
    else:
        boundary = config["SAFE_THRESHOLD"]
    distance = abs(score - boundary)
    base = min(0.45 + (distance / 100), 0.95)
    if ml_used:
        base = min(base + 0.03, 0.98)
    return round(max(base, 0.35), 2)


def analyze_page(
    url: str, timeout: int, max_redirect_depth: int, retry_count: int
) -> tuple[dict[str, float], PageFetchResult]:
    fetch_result = fetch_page(url, timeout, max_redirect_depth, retry_count)
    response = fetch_result.response
    if response is None:
        raise ReachabilityError(
            message="The target website could not be fetched",
            error_type="unreachable",
        )
    signals = {
        "form_count": 0.0,
        "password_fields": 0.0,
        "iframe_count": 0.0,
        "external_form_action": 0.0,
        "external_script_count": 0.0,
        "redirect_count": float(max(len(fetch_result.redirect_chain) - 1, 0)),
    }
    reasons = list(fetch_result.reasons)
    text = response.text.lower()
    signals["form_count"] = float(text.count("<form"))
    signals["password_fields"] = float(text.count('type="password"') + text.count("type='password'"))
    signals["iframe_count"] = float(text.count("<iframe"))
    signals["external_script_count"] = float(text.count('<script src="http')) + float(text.count("<script src='http"))
    signals["external_form_action"] = float('action="http' in text or "action='http" in text)
    if signals["password_fields"] and not url.startswith("https://"):
        reasons.append("Page contains password form with no HTTPS")
    if signals["iframe_count"]:
        reasons.append(f'Page contains iframe elements ({int(signals["iframe_count"])})')
    if signals["external_script_count"]:
        reasons.append("Page loads external scripts")
    fetch_result.reasons = reasons
    return signals, fetch_result


def score_analysis(features: dict[str, float], reasons: list[str], config: dict[str, Any]) -> tuple[int, str]:
    score = 0
    score += min(int(features["url_length"] / 7), 18)
    score += int(features["subdomain_count"] * 6)
    score += int(features["has_ip"] * 20)
    score += min(int(features["suspicious_chars"] * 2), 12)
    score += int(features["keyword_hits"] * 6)
    score += int(features["is_shortener"] * 15)
    score += int(features["phishing_tld"] * 12)
    score += int((1 - features["uses_https"]) * 10)
    score += int(features["password_fields"] * 10)
    score += int(features["external_form_action"] * 12)
    score += min(int(features["external_script_count"] * 3), 9)
    score += min(int(features["redirect_count"] * 3), 12)
    if 0 < features["domain_age_days"] < config["NEW_DOMAIN_DAYS"]:
        score += config["NEW_DOMAIN_PENALTY"]
    elif 0 < features["domain_age_days"] < config["YOUNG_DOMAIN_DAYS"]:
        score += config["YOUNG_DOMAIN_PENALTY"]
    if features["blacklisted"]:
        score = max(score, 95)
    if any("HTTP 4" in reason or "HTTP 5" in reason for reason in reasons):
        score += 4
    score = max(0, min(score, 100))
    if score >= config["PHISHING_THRESHOLD"]:
        label = "phishing"
    elif score >= config["SUSPICIOUS_THRESHOLD"]:
        label = "suspicious"
    else:
        label = "safe"
    return score, label


def _safe_cache_payload(result: "AnalysisResult") -> dict[str, Any]:
    """Build a JSON-serializable dict from AnalysisResult for Redis caching.
    Uses serialize_analysis shape so reconstruction is consistent."""
    return {
        "raw_url": result.raw_url,
        "normalized_url": result.normalized_url,
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
        "confidence": result.confidence,
        "model_metadata": result.model_metadata,
        "error_type": result.error_type,
        "error_message": result.error_message,
        "cache_hit": result.cache_hit,
        "latency_ms": result.latency_ms,
        "analysis_id": result.analysis_id,
    }


def run_analysis(raw_url: str, config: dict[str, Any], *, persist: bool = True) -> AnalysisResult:
    started_at = time.perf_counter()
    timeout = min(
        max(int(config["REQUEST_TIMEOUT_SECONDS"]), 1),
        max(int(config.get("MAX_REQUEST_TIMEOUT_SECONDS", 30)), 1),
    )
    retry_count = min(
        max(int(config["REQUEST_RETRY_COUNT"]), 0),
        max(int(config.get("MAX_REQUEST_RETRY_COUNT", 3)), 0),
    )
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
    cache_key = f"analysis:{hashed}"
    cached = _cache_get(cache_key)
    if cached:
        cached.setdefault("explanations", _build_explanations(cached.get("reasons", [])))
        cached.setdefault("confidence", 0.5)
        cached.setdefault(
            "model_metadata",
            {"enabled": False, "used": False, "source": "heuristic", "model_name": ""},
        )
        # Remove Response object fields that cannot be in cache
        cached.pop("response", None)
        cached_result = AnalysisResult(**{k: v for k, v in cached.items() if k in AnalysisResult.__dataclass_fields__})
        cached_result.cache_hit = True
        if persist:
            analysis = save_analysis(cached_result)
            cached_result.analysis_id = analysis.id
        return cached_result

    features, reasons = extract_url_features(normalized)
    ml_used = False

    # Initialize page fetch result variables so they are always bound
    reachability: str = "unreachable"
    redirect_chain: list[str] = [normalized]
    status_code: int | None = None
    error_type: str | None = None
    error_message: str | None = None

    try:
        page_features, page_result = analyze_page(
            normalized,
            timeout=timeout,
            max_redirect_depth=config["MAX_REDIRECT_DEPTH"],
            retry_count=retry_count,
        )
        features.update(page_features)
        reasons.extend(page_result.reasons)
        reachability = page_result.reachability
        redirect_chain = page_result.redirect_chain
        status_code = page_result.response.status_code if page_result.response else None
        error_type = page_result.error_type
        error_message = page_result.error_message
    except ReachabilityError as exc:
        reachability = "unreachable"
        redirect_chain = [normalized]
        status_code = None
        error_type = exc.error_type
        error_message = exc.message
        reasons.append(exc.message)
        features.update(
            {
                "form_count": 0.0,
                "password_fields": 0.0,
                "iframe_count": 0.0,
                "external_form_action": 0.0,
                "external_script_count": 0.0,
                "redirect_count": 0.0,
            }
        )

    domain_info, domain_reasons = get_domain_intelligence(
        domain,
        cache_get=_cache_get,
        cache_set=_cache_set,
        ttl_seconds=config["DOMAIN_CACHE_TTL_SECONDS"],
        new_domain_days=config["NEW_DOMAIN_DAYS"],
        young_domain_days=config["YOUNG_DOMAIN_DAYS"],
    )
    features["domain_age_days"] = float(domain_info.get("domain_age_days", 0))
    reasons.extend(domain_reasons)
    blacklisted, blacklist_source = blacklist_lookup(domain)
    intel_source = _threat_intel_hit(domain, config)
    if intel_source:
        blacklisted = True
        blacklist_source = intel_source
    features["blacklisted"] = 1.0 if blacklisted else 0.0
    if features["blacklisted"]:
        reasons.append("Domain appears on the local blacklist")
        if blacklist_source:
            reasons.append(f"Blacklist source: {blacklist_source}")

    base_score, label = score_analysis(features, reasons, config)
    ml_score, ml_reason = predict(features, config["MODEL_PATH"])
    if ml_score is not None:
        ml_used = True
        base_score = int(
            (base_score * config["HEURISTIC_BLEND_WEIGHT"])
            + (ml_score * config["ML_BLEND_WEIGHT"])
        )
        if ml_reason:
            reasons.append(ml_reason)
        if base_score >= config["PHISHING_THRESHOLD"]:
            label = "phishing"
        elif base_score >= config["SUSPICIOUS_THRESHOLD"]:
            label = "suspicious"
        else:
            label = "safe"

    summary = {
        "top_reasons": reasons[:8],
        "feature_counts": {key: value for key, value in features.items() if key != "path_length"},
        "reachability": reachability,
        "status_code": status_code,
        "domain_age_days": features.get("domain_age_days", 0),
        "blacklist_source": blacklist_source,
        "explanations": [],
        "confidence": None,
        "model": {},
    }
    explanations = _build_explanations(list(dict.fromkeys(reasons)))
    confidence = _compute_confidence(base_score, label, config, ml_used=ml_used)
    model_metadata = {
        "enabled": bool(config["MODEL_PATH"]),
        "used": ml_used,
        "source": "hybrid" if ml_used else "heuristic",
        "model_name": os.path.basename(config["MODEL_PATH"]) if config["MODEL_PATH"] else "",
    }
    summary["explanations"] = explanations
    summary["confidence"] = confidence
    summary["model"] = model_metadata
    result = AnalysisResult(
        raw_url=raw_url,
        normalized_url=normalized,
        domain=domain,
        url_hash=hashed,
        risk_score=max(0, min(base_score, 100)),
        label=label,
        reasons=list(dict.fromkeys(reasons)),
        reachability=reachability,
        redirect_chain=redirect_chain,
        status_code=status_code,
        features_summary=summary,
        explanations=explanations,
        confidence=confidence,
        model_metadata=model_metadata,
        error_type=error_type,
        error_message=error_message,
        cache_hit=False,
        latency_ms=int((time.perf_counter() - started_at) * 1000),
    )
    # Cache a safe JSON-serializable payload, not the raw dataclass __dict__
    _cache_set(cache_key, _safe_cache_payload(result), config["RESULT_CACHE_TTL_SECONDS"])
    runtime_state.model_loaded = load_model(config["MODEL_PATH"]) is not None
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
                "latency_ms": result.latency_ms,
            },
        )
    except RuntimeError:
        pass
    return result


def save_analysis(result: AnalysisResult) -> Analysis:
    analysis = Analysis(
        url_hash=result.url_hash,
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
        cache_hit=result.cache_hit,
        latency_ms=result.latency_ms,
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
        "confidence": features_summary.get("confidence"),
        "model": features_summary.get("model", {}),
        "blacklist_source": features_summary.get("blacklist_source"),
        "status_code": analysis.status_code,
        "error": (
            {"type": analysis.error_type, "message": analysis.error_message}
            if analysis.error_type
            else None
        ),
        "cache_hit": analysis.cache_hit,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
    }


def recent_analyses(limit: int = 10) -> list[Analysis]:
    return Analysis.query.order_by(Analysis.created_at.desc()).limit(limit).all()


def filtered_reports(
    *,
    page: int,
    per_page: int,
    label: str | None,
    domain: str | None,
    date_from: str | None,
    date_to: str | None,
):
    query = Analysis.query.order_by(Analysis.created_at.desc())
    if label:
        query = query.filter(Analysis.label == label)
    if domain:
        query = query.filter(Analysis.domain.ilike(f"%{domain.lower()}%"))
    if date_from:
        query = query.filter(Analysis.created_at >= date_from)
    if date_to:
        query = query.filter(Analysis.created_at <= date_to)
    return query.paginate(page=page, per_page=per_page, error_out=False)


def label_counts_by_day(limit_days: int = 7) -> list[dict[str, Any]]:
    """Use a SQL GROUP BY query instead of loading all rows into memory."""
    from datetime import timedelta
    from datetime import timezone
    from datetime import datetime as dt
    from sqlalchemy import cast, Date

    rows = (
        db.session.query(
            cast(Analysis.created_at, Date).label("day"),
            Analysis.label,
            func.count(Analysis.id).label("cnt"),
        )
        .group_by(cast(Analysis.created_at, Date), Analysis.label)
        .order_by(cast(Analysis.created_at, Date).asc())
        .all()
    )

    buckets: dict[str, Counter] = {}
    for row in rows:
        day_str = str(row.day)
        buckets.setdefault(day_str, Counter())
        buckets[day_str][row.label] += row.cnt

    result = []
    for day in list(sorted(buckets))[-limit_days:]:
        counter = buckets[day]
        result.append(
            {
                "day": day,
                "safe": counter.get("safe", 0),
                "suspicious": counter.get("suspicious", 0),
                "phishing": counter.get("phishing", 0),
            }
        )
    return result


def top_phishing_domains(limit: int = 5) -> list[tuple[str, int]]:
    rows = (
        db.session.query(Analysis.domain, func.count(Analysis.id))
        .filter(Analysis.label == "phishing")
        .group_by(Analysis.domain)
        .order_by(func.count(Analysis.id).desc())
        .limit(limit)
        .all()
    )
    return [(row[0], row[1]) for row in rows]


def analyses_to_csv(rows: list[Analysis]) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["analysis_id", "url", "domain", "score", "label", "reachability", "created_at"])
    for row in rows:
        writer.writerow(
            [
                row.id,
                row.normalized_url,
                row.domain,
                row.risk_score,
                row.label,
                row.reachability,
                row.created_at.isoformat() if row.created_at else "",
            ]
        )
    return output.getvalue()
