from __future__ import annotations

import base64
import logging
import time
from typing import Any

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

_last_vt_call_time: float = 0.0
_VT_MIN_INTERVAL = 15.0


def _ts_to_iso(ts) -> str | None:
    from datetime import datetime, timezone
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat()
    except Exception:
        return None


def _vt_rate_limit_guard():
    global _last_vt_call_time
    elapsed = time.monotonic() - _last_vt_call_time
    if elapsed < _VT_MIN_INTERVAL:
        wait = _VT_MIN_INTERVAL - elapsed
        logger.info(f"[VT] Rate-limit guard: waiting {wait:.1f}s since last VT call.")
        time.sleep(wait)
    _last_vt_call_time = time.monotonic()


def _curate_meta(meta: dict) -> dict:
    """Extract useful meta tags from VT html_info, discard bloated/irrelevant ones."""
    if not meta:
        return {}
    curated = {}
    keep_keys = {"description", "keywords", "author", "generator", "viewport",
                 "og:title", "og:description", "og:type", "og:image",
                 "twitter:card", "twitter:title", "twitter:description"}
    for key, val in meta.items():
        key_lower = key.lower()
        if key_lower in keep_keys:
            curated[key] = val
        elif any(key_lower.startswith(prefix) for prefix in ("og:", "twitter:")):
            curated[key] = val
    return curated


def normalize_vt_summary(vt: dict) -> dict:
    """Normalize a VT summary dict so it always has the current schema.

    Old cached VT data stored in the DB may lack nested keys like `stats`
    or the newer fields (verdict, serving_ip, etc.). This function
    backfills them from flat backward-compat keys so the template
    always gets a consistent structure.
    """
    if not vt or vt.get("status") != "success":
        return vt

    # Wrap old format flat report into url_report
    if "url_report" not in vt:
        url_report_keys = {
            "stats", "reputation", "votes", "categories", "dates", "final_url",
            "redirection_chain", "http_response", "top_engine_hits",
            "additional_flagged_engines", "tags", "html_info", "serving_ip",
            "outgoing_links", "outgoing_links_count", "favicon", "jarm",
            "category_vendors", "permalink", "verdict", "malicious_count", "suspicious_count"
        }
        url_report = {k: v for k, v in vt.items() if k in url_report_keys}
        for k in list(vt.keys()):
            if k in url_report_keys:
                del vt[k]
        vt["url_report"] = url_report

    url_rep = vt.get("url_report")
    if not isinstance(url_rep, dict):
        vt["url_report"] = {}
        url_rep = vt["url_report"]

    # Normalize url_rep fields
    if "stats" not in url_rep or not isinstance(url_rep.get("stats"), dict):
        malicious = url_rep.get("malicious_count", 0)
        suspicious = url_rep.get("suspicious_count", 0)
        harmless = url_rep.get("harmless_count", 0)
        undetected = url_rep.get("undetected_count", 0)
        timeout_count = url_rep.get("timeout_count", 0)
        total = malicious + suspicious + harmless + undetected + timeout_count
        url_rep["stats"] = {
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "timeout_count": timeout_count,
            "total_engines": total,
        }

    # Populate dates
    if "dates" not in url_rep:
        url_rep["dates"] = {}

    # Populate http_response
    if "http_response" not in url_rep:
        url_rep["http_response"] = {}

    # Populate html_info
    if "html_info" not in url_rep:
        url_rep["html_info"] = {}
    if "title" not in url_rep["html_info"]:
        url_rep["html_info"]["title"] = None
    if "meta" not in url_rep["html_info"]:
        url_rep["html_info"]["meta"] = {}

    # Populate categories
    if "categories" not in url_rep:
        url_rep["categories"] = []
    elif isinstance(url_rep["categories"], dict):
        url_rep["categories"] = list(set(url_rep["categories"].values()))

    # Normalize defaults for new fields in url_report
    for field, default in (
        ("reputation", 0),
        ("votes", {"harmless": 0, "malicious": 0}),
        ("final_url", None),
        ("redirection_chain", []),
        ("top_engine_hits", []),
        ("additional_flagged_engines", 0),
        ("tags", []),
        ("serving_ip", None),
        ("outgoing_links", []),
        ("outgoing_links_count", 0),
        ("favicon", None),
        ("jarm", None),
        ("category_vendors", {}),
        ("permalink", ""),
        ("verdict", {}),
        ("malicious_count", 0),
        ("suspicious_count", 0),
    ):
        if field not in url_rep:
            url_rep[field] = default

    if not url_rep.get("verdict"):
        url_rep["verdict"] = _build_verdict_label(url_rep)

    # Copy URL report fields to the root for backward compatibility with existing templates/code
    for k in [
        "stats", "reputation", "votes", "categories", "dates", "final_url",
        "redirection_chain", "http_response", "top_engine_hits",
        "additional_flagged_engines", "tags", "html_info", "serving_ip",
        "outgoing_links", "outgoing_links_count", "favicon", "jarm",
        "category_vendors", "permalink", "verdict", "malicious_count", "suspicious_count"
    ]:
        vt[k] = url_rep.get(k)

    # Initialize domain and IP reports
    if "domain_report" not in vt:
        vt["domain_report"] = None
    if "ip_report" not in vt:
        vt["ip_report"] = None

    # Availability block
    if "availability" not in vt:
        vt["availability"] = {}
    vt["availability"]["url_report"] = True
    vt["availability"]["domain_report"] = vt["domain_report"] is not None
    vt["availability"]["ip_report"] = vt["ip_report"] is not None

    if "fetched_from_cache" not in vt:
        vt["fetched_from_cache"] = False
    if "fetched_at" not in vt:
        from datetime import datetime, timezone
        vt["fetched_at"] = datetime.now(timezone.utc).isoformat()
    if "limitations" not in vt:
        vt["limitations"] = []

    # Calculate combined_vt_signal
    url_flagged = vt.get("malicious_count", 0) > 0 or vt.get("suspicious_count", 0) > 0
    dom_flagged = False
    if vt.get("domain_report"):
        dom_stats = vt["domain_report"].get("last_analysis_stats", {})
        dom_flagged = dom_stats.get("malicious", 0) > 0 or dom_stats.get("suspicious", 0) > 0
    ip_flagged = False
    if vt.get("ip_report"):
        ip_stats = vt["ip_report"].get("last_analysis_stats", {})
        ip_flagged = ip_stats.get("malicious", 0) > 0 or ip_stats.get("suspicious", 0) > 0
        
    vt["combined_vt_signal"] = "flagged" if (url_flagged or dom_flagged or ip_flagged) else "clean"

    return vt


def _build_verdict_label(vt_summary: dict) -> dict:
    """Build a richer VT verdict than just 'Clean'/'Flagged'."""
    stats = vt_summary.get("stats", {})
    malicious = stats.get("malicious_count", 0)
    suspicious = stats.get("suspicious_count", 0)
    categories = vt_summary.get("categories", [])
    reputation = vt_summary.get("reputation", 0)

    if malicious > 0:
        detection_verdict = f"{malicious} engine(s) flagged as malicious"
    elif suspicious > 0:
        detection_verdict = f"{suspicious} engine(s) flagged as suspicious"
    else:
        detection_verdict = "No malicious detections"

    category_context = ""
    if categories:
        category_context = f"Classified as: {', '.join(categories[:5])}"

    if reputation < -20:
        rep_context = f"Negative reputation ({reputation})"
    elif reputation < 0:
        rep_context = f"Slightly negative reputation ({reputation})"
    elif reputation > 50:
        rep_context = f"Strong positive reputation ({reputation})"
    else:
        rep_context = f"Reputation: {reputation}"

    return {
        "detection_verdict": detection_verdict,
        "category_context": category_context,
        "reputation_context": rep_context,
    }


def _vt_request(method: str, url: str, headers: dict, data: dict | None, timeout: int):
    if method == "POST":
        return requests.post(url, headers=headers, data=data, timeout=timeout)
    return requests.get(url, headers=headers, timeout=timeout)


def get_virustotal_report(url: str, config: dict[str, Any]) -> dict[str, Any] | None:
    """
    Full VT enrichment: POST to scan URL, then poll GET for report.
    Public API: 4 requests/minute. We enforce a local 15s minimum interval.
    """
    global _last_vt_call_time

    if not config.get("VT_ENABLED", False):
        return None

    api_key = config.get("VT_API_KEY")
    if not api_key:
        logger.warning("[VT] VT_ENABLED=true but VT_API_KEY not set. Skipping lookup.")
        return None

    timeout = config.get("VT_TIMEOUT", 10)

    elapsed = time.monotonic() - _last_vt_call_time
    if elapsed < _VT_MIN_INTERVAL:
        wait = _VT_MIN_INTERVAL - elapsed
        logger.info(f"[VT] Rate-limit guard: waiting {wait:.1f}s since last VT call.")
        time.sleep(wait)

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers_json = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded",
    }

    headers_get = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        logger.info(f"[VT] Submitting URL for scan: {url}")
        _last_vt_call_time = time.monotonic()
        scan_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers_json,
            data={"url": url},
            timeout=timeout,
        )

        if scan_resp.status_code == 429:
            logger.warning("[VT] Rate limit exceeded on scan (429).")
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded during scan submission"}

        if scan_resp.status_code == 401:
            logger.warning("[VT] Invalid API key (401). Check VT_API_KEY.")
            return {"status": "error", "message": "VirusTotal authentication failed (invalid API key)"}

        if scan_resp.status_code == 400:
            logger.warning("[VT] Bad request (400). URL may be malformed.")
            return {"status": "error", "message": "VirusTotal rejected the URL (bad request)"}

        scan_resp.raise_for_status()
        logger.info("[VT] Scan submitted. Polling for report...")

        time.sleep(3)

        _last_vt_call_time = time.monotonic()
        report_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers_get,
            timeout=timeout,
        )

        if report_resp.status_code == 429:
            logger.warning("[VT] Rate limit exceeded on report retrieval (429).")
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded during report retrieval"}

        if report_resp.status_code == 404:
            logger.info("[VT] URL not found in VT database after scan (404).")
            return {"status": "not_found", "message": "URL not found in VirusTotal database"}

        report_resp.raise_for_status()
        data = report_resp.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        timeout_count = stats.get("timeout", 0)
        total = malicious + suspicious + harmless + undetected + timeout_count

        total_votes = attributes.get("total_votes", {})

        # Format dates
        def _ts_to_iso(ts):
            from datetime import datetime, timezone
            if not ts: return None
            try: return datetime.fromtimestamp(ts, timezone.utc).isoformat()
            except Exception: return None

        # Redirection chain
        redirection_chain = attributes.get("redirection_chain", [])

        # Categories (vendor -> category mapping, deduplicated values)
        categories = attributes.get("categories", {})
        unique_categories = list(set(categories.values()))
        # Keep vendor-to-category mapping for richer display
        category_vendors = {k: v for k, v in categories.items()}

        # Serving IP address
        serving_ip = attributes.get("serving_ip_address")

        # Outgoing / external links (capped to prevent huge payloads)
        outgoing_links = attributes.get("outgoing_links", [])
        outgoing_links = outgoing_links[:20]

        # Favicon hashes
        favicon = attributes.get("favicon", {})

        # JARM TLS fingerprint
        jarm = attributes.get("jarm")

        # Top flagged engines
        analysis_results = attributes.get("last_analysis_results", {})
        flagged_engines = []
        for engine_name, result in analysis_results.items():
            category = result.get("category", "")
            if category in ("malicious", "suspicious"):
                flagged_engines.append({
                    "engine_name": engine_name,
                    "category": category,
                    "result": result.get("result", "")
                })

        # Sort: malicious first, suspicious second, then alphabetical
        def sort_engine(e):
            cat_order = 0 if e["category"] == "malicious" else 1
            return (cat_order, e["engine_name"].lower())

        flagged_engines.sort(key=sort_engine)

        # Deduplicate by engine_name
        seen_engines = set()
        dedup_engines = []
        for e in flagged_engines:
            if e["engine_name"] not in seen_engines:
                seen_engines.add(e["engine_name"])
                dedup_engines.append(e)

        top_engines = dedup_engines[:15]
        additional_engines = max(0, len(dedup_engines) - 15)

        # HTTP response metadata
        headers = attributes.get("last_http_response_headers", {})
        curated_headers = {}
        for key in ["server", "content-type", "x-powered-by", "set-cookie", "via"]:
            for hk, hv in headers.items():
                if hk.lower() == key:
                    if key == "set-cookie":
                        curated_headers[hk] = "present (redacted)" # Don't dump raw cookies
                    else:
                        curated_headers[hk] = hv
                    break

        summary = {
            "status": "success",
            "stats": {
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "timeout_count": timeout_count,
                "total_engines": total,
            },
            "reputation": attributes.get("reputation", 0),
            "votes": {
                "harmless": total_votes.get("harmless", 0),
                "malicious": total_votes.get("malicious", 0)
            },
            "categories": unique_categories,
            "dates": {
                "first_submission_date": _ts_to_iso(attributes.get("first_submission_date")),
                "last_submission_date": _ts_to_iso(attributes.get("last_submission_date")),
                "last_analysis_date": _ts_to_iso(attributes.get("last_analysis_date")),
            },
            "final_url": attributes.get("last_final_url"),
            "redirection_chain": redirection_chain[:10], # cap just in case
            "http_response": {
                "status_code": attributes.get("last_http_response_code"),
                "content_length": attributes.get("last_http_response_content_length"),
                "content_sha256": attributes.get("last_http_response_content_sha256"),
                "headers": curated_headers
            },
            "top_engine_hits": top_engines,
            "additional_flagged_engines": additional_engines,
            "tags": attributes.get("tags", []),
            "html_info": {
                "title": attributes.get("html_info", {}).get("title"),
                "meta": _curate_meta(attributes.get("html_info", {}).get("meta", {})),
            },
            "serving_ip": serving_ip,
            "outgoing_links": outgoing_links,
            "outgoing_links_count": len(outgoing_links),
            "favicon": favicon or None,
            "jarm": jarm,
            "category_vendors": category_vendors,
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
            # Rich verdict for UI (replaces coarse 'Clean'/'Flagged')
            "verdict": _build_verdict_label({
                "stats": {"malicious_count": malicious, "suspicious_count": suspicious},
                "categories": unique_categories,
                "reputation": attributes.get("reputation", 0),
            }),
            # Keep flat stats for backward compatibility with existing code during transition,
            # will remove in score_analysis refactor if needed.
            "malicious_count": malicious,
            "suspicious_count": suspicious,
        }

        logger.info(
            f"[VT] Report retrieved: {malicious} malicious, {suspicious} suspicious, "
            f"{harmless} harmless, {undetected} undetected (out of {total} engines)"
        )
        return summary

    except RequestException as e:
        logger.warning(f"[VT] Network/API error: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        logger.warning(f"[VT] Unexpected error: {e}")
        return {"status": "error", "message": "Internal error during VT lookup"}


def get_vt_domain_report(domain: str, config: dict[str, Any]) -> dict[str, Any] | None:
    """Retrieve domain report from VirusTotal API v3."""
    if not config.get("VT_ENABLED", False):
        return None

    api_key = config.get("VT_API_KEY")
    if not api_key:
        return None

    timeout = config.get("VT_TIMEOUT", 10)

    # Apply rate-limit guard
    _vt_rate_limit_guard()

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        logger.info(f"[VT] Querying domain report: {domain}")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers,
            timeout=timeout,
        )

        if resp.status_code == 429:
            logger.warning(f"[VT] Rate limit exceeded on domain check ({domain}).")
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded during domain lookup"}

        if resp.status_code == 404:
            logger.info(f"[VT] Domain {domain} not found in VirusTotal database.")
            return {"status": "not_found", "message": "Domain not found in VirusTotal database"}

        resp.raise_for_status()
        data = resp.json().get("data", {})
        attributes = data.get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        votes = attributes.get("total_votes", {})
        categories = attributes.get("categories", {})
        unique_categories = list(set(categories.values()))

        # Extract resolved IPs / last resolved IPs from last_dns_records if present
        resolved_ips = []
        dns_records = attributes.get("last_dns_records", [])
        for record in dns_records:
            if record.get("type") == "A" and record.get("value"):
                resolved_ips.append(record.get("value"))
        
        # Bounded resolved IPs
        resolved_ips = list(set(resolved_ips))[:10]

        summary = {
            "status": "success",
            "reputation": attributes.get("reputation", 0),
            "votes": {
                "harmless": votes.get("harmless", 0),
                "malicious": votes.get("malicious", 0),
            },
            "last_analysis_stats": {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
            },
            "categories": unique_categories,
            "category_vendors": categories,
            "creation_date": _ts_to_iso(attributes.get("creation_date")),
            "last_update_date": _ts_to_iso(attributes.get("last_update_date")),
            "registrar": attributes.get("registrar"),
            "tags": attributes.get("tags", [])[:10],
            "popularity_ranks": attributes.get("popularity_ranks", {}),
            "resolved_ips": resolved_ips,
            "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
        }
        return summary

    except RequestException as e:
        logger.warning(f"[VT] Domain API check error: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        logger.warning(f"[VT] Unexpected error in domain check: {e}")
        return {"status": "error", "message": "Internal error during VT domain lookup"}


def get_vt_ip_report(ip: str, config: dict[str, Any]) -> dict[str, Any] | None:
    """Retrieve IP address report from VirusTotal API v3."""
    if not config.get("VT_ENABLED", False):
        return None

    api_key = config.get("VT_API_KEY")
    if not api_key:
        return None

    if not ip:
        return None

    timeout = config.get("VT_TIMEOUT", 10)

    # Apply rate-limit guard
    _vt_rate_limit_guard()

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        logger.info(f"[VT] Querying IP report: {ip}")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=timeout,
        )

        if resp.status_code == 429:
            logger.warning(f"[VT] Rate limit exceeded on IP check ({ip}).")
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded during IP lookup"}

        if resp.status_code == 404:
            logger.info(f"[VT] IP {ip} not found in VirusTotal database.")
            return {"status": "not_found", "message": "IP not found in VirusTotal database"}

        resp.raise_for_status()
        data = resp.json().get("data", {})
        attributes = data.get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        votes = attributes.get("total_votes", {})
        
        cert = attributes.get("last_https_certificate", {})
        cert_subject = cert.get("subject", {}).get("CN") if cert else None
        cert_issuer = cert.get("issuer", {}).get("O") if cert else None

        summary = {
            "status": "success",
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "country": attributes.get("country"),
            "continent": attributes.get("continent"),
            "network": attributes.get("network"),
            "regional_registry": attributes.get("regional_registry"),
            "reputation": attributes.get("reputation", 0),
            "votes": {
                "harmless": votes.get("harmless", 0),
                "malicious": votes.get("malicious", 0),
            },
            "last_analysis_stats": {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
            },
            "tags": attributes.get("tags", [])[:10],
            "last_https_certificate_date": _ts_to_iso(attributes.get("last_https_certificate_date")),
            "cert_subject": cert_subject,
            "cert_issuer": cert_issuer,
            "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
        }
        return summary

    except RequestException as e:
        logger.warning(f"[VT] IP API check error: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        logger.warning(f"[VT] Unexpected error in IP check: {e}")
        return {"status": "error", "message": "Internal error during VT IP lookup"}

