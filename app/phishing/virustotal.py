from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

def get_virustotal_report(url: str, config: dict[str, Any]) -> dict[str, Any] | None:
    """
    Fetch a URL report from VirusTotal's public API.
    Uses the /api/v3/urls/{id} endpoint where ID is a base64url encoded URL.
    Returns None if VT is disabled, missing key, or API fails (respecting optional constraint).
    """
    if not config.get("VT_ENABLED", False):
        return None

    api_key = config.get("VT_API_KEY")
    if not api_key:
        logger.warning("VT_ENABLED is true but VT_API_KEY is not set. Skipping VirusTotal lookup.")
        return None

    timeout = config.get("VT_TIMEOUT", 10)

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        logger.info(f"Querying VirusTotal API for {url}...")
        response = requests.get(api_url, headers=headers, timeout=timeout)

        # VT returns 404 if the URL has never been scanned before
        if response.status_code == 404:
            logger.info("VirusTotal returned 404 (URL not found in VT database).")
            return {"status": "not_found", "message": "URL not found in VirusTotal database"}

        # Handle rate limiting or quotas gracefully
        if response.status_code == 429:
            logger.warning("VirusTotal API rate limit exceeded.")
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded"}

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        # Extract meaningful insights
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)

        # Only return the data we need to keep storage small and clean
        summary = {
            "status": "success",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_engines": malicious + suspicious + harmless + undetected,
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation", 0)
        }

        permalink = data.get("data", {}).get("links", {}).get("self")
        if permalink:
            # We want the GUI permalink, not the API self link. We can construct it.
            # Convert api link to gui link if possible. Or just provide the ID
            summary["permalink"] = f"https://www.virustotal.com/gui/url/{url_id}"

        logger.info(f"VirusTotal lookup successful: {malicious} malicious, {suspicious} suspicious")
        return summary

    except RequestException as e:
        logger.warning(f"VirusTotal lookup failed due to network/API error: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.warning(f"VirusTotal lookup failed with unexpected error: {e}")
        return {"status": "error", "message": "Internal error during lookup"}
