from __future__ import annotations

import csv
import json
import time
from collections import Counter
from dataclasses import dataclass
from io import StringIO
from typing import Any

import requests
from requests import Response
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout, RequestException, SSLError
from requests.exceptions import Timeout as RequestsTimeout
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
    redis_client.setex(key, ttl_seconds, json.dumps(payload))


def is_blacklisted(url_or_domain: str) -> bool:
    try:
        domain = sanitized_domain(url_or_domain)
    except AnalysisInputError:
        domain = url_or_domain.strip().lower()
    return Blacklist.query.filter_by(domain=domain).first() is not None


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
    session.max_redirects = max_redirect_depth
    last_exception: Exception | None = None
    for _attempt in range(retry_count + 1):
        try:
            response = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "Detector/1.0"},
            )
            redirect_chain = [url, *[item.url for item in response.history]]
            if response.url not in redirect_chain:
                redirect_chain.append(response.url)
            redirect_chain = redirect_chain[: max_redirect_depth + 1]
            reasons: list[str] = []
            reachability = "reachable"
            if len(redirect_chain) > 1:
                reachability = "partially_reachable"
                reasons.append(f"Redirect chain observed ({len(redirect_chain) - 1} redirects)")
            if response.status_code >= 400:
                reachability = "partially_reachable"
                reasons.append(f"Page returned HTTP {response.status_code}")
            return PageFetchResult(response, response.url, redirect_chain, reasons, reachability)
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
    elif score >= config["SAFE_THRESHOLD"]:
        label = "safe"
    else:
        label = "safe"
    return score, label


def run_analysis(raw_url: str, config: dict[str, Any], *, persist: bool = True) -> AnalysisResult:
    started_at = time.perf_counter()
    normalized = normalize_url(raw_url)
    ok, message = validate_url(normalized)
    if not ok:
        raise AnalysisInputError(message)
    domain = sanitized_domain(normalized)
    hashed = url_hash(normalized)
    cache_key = f"analysis:{hashed}"
    cached = _cache_get(cache_key)
    if cached:
        cached_result = AnalysisResult(**cached)
        cached_result.cache_hit = True
        if persist:
            analysis = save_analysis(cached_result)
            cached_result.analysis_id = analysis.id
        return cached_result

    features, reasons = extract_url_features(normalized)
    try:
        page_features, page_result = analyze_page(
            normalized,
            timeout=config["REQUEST_TIMEOUT_SECONDS"],
            max_redirect_depth=config["MAX_REDIRECT_DEPTH"],
            retry_count=config["REQUEST_RETRY_COUNT"],
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
    features["blacklisted"] = 1.0 if is_blacklisted(domain) else 0.0
    if features["blacklisted"]:
        reasons.append("Domain appears on the local blacklist")

    base_score, label = score_analysis(features, reasons, config)
    ml_score, ml_reason = predict(features, config["MODEL_PATH"])
    if ml_score is not None:
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
    }
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
        error_type=error_type,
        error_message=error_message,
        cache_hit=False,
        latency_ms=int((time.perf_counter() - started_at) * 1000),
    )
    _cache_set(cache_key, result.__dict__, config["RESULT_CACHE_TTL_SECONDS"])
    runtime_state.model_loaded = load_model(config["MODEL_PATH"]) is not None
    if persist:
        analysis = save_analysis(result)
        result.analysis_id = analysis.id
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
    return {
        "analysis_id": analysis.id,
        "url": analysis.normalized_url,
        "domain": analysis.domain,
        "risk_score": analysis.risk_score,
        "label": analysis.label,
        "reasons": analysis.reasons,
        "reachability": analysis.reachability,
        "redirect_chain": analysis.redirect_chain,
        "features_summary": analysis.features_summary,
        "status_code": analysis.status_code,
        "error": (
            {"type": analysis.error_type, "message": analysis.error_message}
            if analysis.error_type
            else None
        ),
        "cache_hit": analysis.cache_hit,
        "created_at": analysis.created_at.isoformat(),
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
    analyses = Analysis.query.order_by(Analysis.created_at.asc()).all()
    buckets: dict[str, Counter[str]] = {}
    for analysis in analyses:
        day = analysis.created_at.strftime("%Y-%m-%d")
        buckets.setdefault(day, Counter())
        buckets[day][analysis.label] += 1
    rows = []
    for day in list(sorted(buckets))[-limit_days:]:
        counter = buckets[day]
        rows.append(
            {
                "day": day,
                "safe": counter.get("safe", 0),
                "suspicious": counter.get("suspicious", 0),
                "phishing": counter.get("phishing", 0),
            }
        )
    return rows


def top_phishing_domains(limit: int = 5) -> list[tuple[str, int]]:
    rows = (
        db.session.query(Analysis.domain, db.func.count(Analysis.id))
        .filter(Analysis.label == "phishing")
        .group_by(Analysis.domain)
        .order_by(db.func.count(Analysis.id).desc())
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
                row.created_at.isoformat(),
            ]
        )
    return output.getvalue()
