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

        return {
            "status": "success",
            "ipAddress": data.get("ipAddress"),
            "isPublic": data.get("isPublic"),
            "ipVersion": data.get("ipVersion"),
            "isWhitelisted": data.get("isWhitelisted"),
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "countryCode": data.get("countryCode"),
            "usageType": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "totalReports": data.get("totalReports"),
            "numDistinctUsers": data.get("numDistinctUsers"),
            "lastReportedAt": data.get("lastReportedAt")
        }

    except RequestException as e:
        logger.warning(f"[AbuseIPDB] Network/API error: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        logger.warning(f"[AbuseIPDB] Unexpected error: {e}")
        return {"status": "error", "message": "Internal error during AbuseIPDB lookup"}
