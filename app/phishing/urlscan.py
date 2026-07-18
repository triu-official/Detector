from __future__ import annotations

import logging
import time
from typing import Any

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"

_POLL_INTERVAL = 5
_POLL_TIMEOUT = 60


def get_urlscan_report(url: str, config: dict[str, Any]) -> dict[str, Any] | None:
    api_key = config.get("URLSCAN_API_KEY")
    if not api_key:
        return None

    timeout = config.get("REQUEST_TIMEOUT_SECONDS", 10)

    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }

    payload = {
        "url": url,
        "visibility": "public",
    }

    try:
        logger.info(f"[Urlscan] Submitting URL: {url}")

        submit_resp = requests.post(
            URLSCAN_SUBMIT_URL,
            headers=headers,
            json=payload,
            timeout=timeout,
        )

        if submit_resp.status_code == 429:
            logger.warning("[Urlscan] Rate limit exceeded.")
            return {"status": "rate_limited", "message": "urlscan.io rate limit exceeded"}

        if submit_resp.status_code == 400:
            logger.warning(f"[Urlscan] Bad Request: {submit_resp.text[:200]}")
            return {"status": "error", "message": "Bad Request to urlscan.io"}

        if submit_resp.status_code in (401, 403):
            logger.warning("[Urlscan] Invalid API Key.")
            return {"status": "error", "message": "Invalid urlscan.io API key"}

        submit_resp.raise_for_status()
        submit_data = submit_resp.json()

        uuid = submit_data.get("uuid")
        result_url = submit_data.get("result")
        api_url = submit_data.get("api")

        if not uuid:
            return {"status": "error", "message": "No UUID returned from urlscan.io"}

        logger.info(f"[Urlscan] Scan submitted, uuid={uuid}. Polling for results...")

        poll_url = api_url or result_url or URLSCAN_RESULT_URL.format(uuid=uuid)
        full_result = _poll_for_result(poll_url, api_key, timeout)

        if full_result is None:
            return {
                "status": "error",
                "message": "Scan timed out or results not available",
                "uuid": uuid,
                "result_url": f"https://urlscan.io/result/{uuid}/",
                "api_url": api_url,
            }

        return _normalize_result(full_result, uuid)

    except RequestException as e:
        logger.warning(f"[Urlscan] Network/API error: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        logger.warning(f"[Urlscan] Unexpected error: {e}", exc_info=True)
        return {"status": "error", "message": "Internal error during Urlscan lookup"}


def _poll_for_result(result_url: str, api_key: str, timeout: int) -> dict | None:
    elapsed = 0
    while elapsed < _POLL_TIMEOUT:
        time.sleep(_POLL_INTERVAL)
        elapsed += _POLL_INTERVAL
        try:
            resp = requests.get(result_url, headers={"API-Key": api_key}, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("task", {}).get("finishedAt") or data.get("verdicts"):
                    logger.info(f"[Urlscan] Results ready after {elapsed}s")
                    return data
            elif resp.status_code == 404:
                continue
        except RequestException:
            continue
    logger.warning(f"[Urlscan] Polling timed out after {_POLL_TIMEOUT}s")
    return None


def _normalize_result(data: dict, uuid: str) -> dict[str, Any]:
    page = data.get("page", {})
    verdicts = data.get("verdicts", {})
    overall = verdicts.get("overall", {})
    community = verdicts.get("community", {})
    raw_data = data.get("data", {})
    lists = data.get("lists", {})
    meta = data.get("meta", {})
    scanner = data.get("scanner", {})
    task = data.get("task", {})

    overall_score = overall.get("score", 0)
    overall_malicious = overall.get("malicious", False)
    overall_categories = overall.get("categories", [])
    overall_tags = overall.get("tags", [])

    community_score = community.get("score", 0)
    community_malicious = community.get("malicious", False)
    community_votes_total = community.get("votesTotal", 0)
    community_votes_malicious = community.get("votesMalicious", 0)

    certificates = lists.get("certificates", [])
    cert_info = None
    if certificates:
        cert = certificates[0]
        cert_info = {
            "subject": cert.get("subjectName", ""),
            "issuer": cert.get("issuer", ""),
            "valid_from": cert.get("validFrom"),
            "valid_to": cert.get("validTo"),
        }

    tls_valid_days = page.get("tlsValidDays")
    tls_age_days = page.get("tlsAgeDays")
    tls_issuer = page.get("tlsIssuer", "")
    tls_valid = None
    if tls_valid_days is not None:
        tls_valid = tls_valid_days > 0

    redirect_chain = raw_data.get("redirects", [])
    if not redirect_chain:
        task_url = task.get("url", "")
        page_url = page.get("url", "")
        if task_url and page_url and task_url != page_url:
            redirect_chain = [task_url, page_url]

    link_domains = lists.get("linkDomains", [])
    external_resources = []
    for ext in link_domains[:20]:
        if isinstance(ext, dict):
            external_resources.append({"domain": ext.get("domain", "")})
        elif isinstance(ext, str):
            external_resources.append({"domain": ext})

    cookies = raw_data.get("cookies", [])

    result = {
        "status": "success",
        "uuid": uuid,
        "result_url": f"https://urlscan.io/result/{uuid}/",
        "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
        "dom_url": f"https://urlscan.io/dom/{uuid}/",

        "overall_score": overall_score,
        "overall_malicious": overall_malicious,
        "overall_categories": overall_categories,
        "overall_tags": overall_tags,

        "community_score": community_score,
        "community_malicious": community_malicious,
        "community_votes_total": community_votes_total,
        "community_votes_malicious": community_votes_malicious,

        "page_url": page.get("url", ""),
        "final_url": page.get("url", ""),
        "domain": page.get("domain", ""),
        "apex_domain": page.get("apexDomain", ""),
        "ip": page.get("ip", ""),
        "country": scanner.get("country", page.get("country", "")),
        "asn": page.get("asn", ""),
        "asn_name": page.get("asnname", ""),
        "server": page.get("server", ""),
        "page_title": page.get("title", ""),
        "mime_type": page.get("mimeType", ""),
        "language": page.get("language", ""),
        "domain_age_days": page.get("domainAgeDays"),
        "apex_domain_age_days": page.get("apexDomainAgeDays"),

        "tls_valid": tls_valid,
        "tls_valid_days": tls_valid_days,
        "tls_issuer": tls_issuer,
        "tls_age_days": tls_age_days,
        "cert_info": cert_info,

        "http_status": page.get("status"),
        "response_headers": {},

        "redirect_chain": redirect_chain,
        "has_redirects": len(redirect_chain) > 1,
        "redirect_count": max(0, len(redirect_chain) - 1),

        "external_resources": external_resources,
        "external_resources_count": len(link_domains),
        "cookie_count": len(cookies),

        "verdict": _build_verdict(overall_score, overall_malicious, overall_categories),

        "scan_time": meta.get("time", ""),
    }


    return result


def _build_verdict(score: int, malicious: bool, categories: list) -> dict:
    if malicious or score >= 70:
        label = "Malicious"
        severity = "high"
        reason = f"Community score {score}/100 with {len(categories)} category tag(s)"
    elif score >= 40:
        label = "Suspicious"
        severity = "moderate"
        reason = f"Moderate risk score {score}/100"
    elif score > 0:
        label = "Low Risk"
        severity = "low"
        reason = f"Low risk score {score}/100"
    else:
        label = "Clean"
        severity = "none"
        reason = "No risk signals detected"

    cat_context = ", ".join(categories[:5]) if categories else "No categories assigned"

    return {
        "label": label,
        "severity": severity,
        "score": score,
        "reason": reason,
        "category_context": cat_context,
        "malicious": malicious,
    }
