from __future__ import annotations

import logging
from typing import Any
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

def get_abuseipdb_report(ip: str, config: dict[str, Any]) -> dict[str, Any] | None:
    api_key = config.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None

    if not ip:
        return {"status": "error", "message": "No IP address provided"}

    timeout = config.get("REQUEST_TIMEOUT_SECONDS", 10)

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    try:
        logger.info(f"[AbuseIPDB] Checking IP: {ip}")
        resp = requests.get(url, headers=headers, params=querystring, timeout=timeout)

        if resp.status_code == 429:
            logger.warning("[AbuseIPDB] Rate limit exceeded.")
            return {"status": "rate_limited", "message": "AbuseIPDB rate limit exceeded"}

        if resp.status_code == 401 or resp.status_code == 403:
            logger.warning("[AbuseIPDB] Invalid API Key.")
            return {"status": "error", "message": "Invalid AbuseIPDB API key"}

        resp.raise_for_status()
        data = resp.json().get('data', {})

        score = data.get("abuseConfidenceScore", 0)
        verdict_band = "clean"
        if score > 0:
            if score <= 25:
                verdict_band = "low confidence of abuse"
            elif score <= 50:
                verdict_band = "moderate concern"
            elif score <= 75:
                verdict_band = "high concern"
            else:
                verdict_band = "very high concern"

        # Capped verbose reports if requested (not requested by default, but let's parse if present)
        reports = data.get("reports", [])
        top_reports = []
        for r in reports[:10]:
            top_reports.append({
                "reportedAt": r.get("reportedAt"),
                "categories": r.get("categories", []),
                "comment": r.get("comment", "")[:100] + ("..." if len(r.get("comment", "")) > 100 else ""),
                "reporterCountryCode": r.get("reporterCountryCode")
            })

        # Determine normalized values
        verdict = "flagged" if score > 25 else "clean"
        severity = "low"
        if score > 50:
            severity = "high"
        elif score > 0:
            severity = "medium"

        reason = f"IP address is clean with 0% abuse confidence."
        if score > 0:
            reason = f"IP address has {score}% abuse confidence score ({verdict_band}) with {data.get('totalReports', 0)} total report(s)."

        return {
            "status": "success",
            "available": True,
            "resolved_ip": data.get("ipAddress"),
            "ipAddress": data.get("ipAddress"),  # backward compatibility
            "isPublic": data.get("isPublic"),
            "ipVersion": data.get("ipVersion"),
            "isWhitelisted": data.get("isWhitelisted"),
            "isTor": data.get("isTor", False),
            "abuseConfidenceScore": score,
            "verdict_band": verdict_band,
            "countryCode": data.get("countryCode"),
            "usageType": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "totalReports": data.get("totalReports"),
            "numDistinctUsers": data.get("numDistinctUsers"),
            "lastReportedAt": data.get("lastReportedAt"),
            "top_reports": top_reports[:5],  # capped list
            "verdict": verdict,
            "severity": severity,
            "confidence": "high",
            "reason": reason
        }

    except RequestException as e:
        logger.warning(f"[AbuseIPDB] Network/API error: {e}")
        return {
            "status": "error",
            "available": False,
            "verdict": "unknown",
            "severity": "low",
            "confidence": "low",
            "reason": f"AbuseIPDB check failed: Network error: {e}",
            "message": f"Network error: {e}"
        }
    except Exception as e:
        logger.warning(f"[AbuseIPDB] Unexpected error: {e}")
        return {
            "status": "error",
            "available": False,
            "verdict": "unknown",
            "severity": "low",
            "confidence": "low",
            "reason": f"AbuseIPDB check failed: Internal error: {e}",
            "message": "Internal error during AbuseIPDB lookup"
        }
