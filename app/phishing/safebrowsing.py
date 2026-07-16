from __future__ import annotations

import logging
from typing import Any
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

def get_safebrowsing_report(url: str, config: dict[str, Any]) -> dict[str, Any] | None:
    api_key = config.get("SAFEBROWSING_API_KEY")
    if not api_key:
        return None

    timeout = config.get("REQUEST_TIMEOUT_SECONDS", 10)

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "local-phishing-detector",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        logger.info(f"[SafeBrowsing] Checking URL: {url}")
        resp = requests.post(endpoint, json=payload, timeout=timeout)

        if resp.status_code == 429:
            logger.warning("[SafeBrowsing] Rate limit exceeded.")
            return {"status": "rate_limited", "message": "Google Safe Browsing rate limit exceeded"}

        if resp.status_code == 400:
            logger.warning("[SafeBrowsing] Bad Request. URL might be invalid.")
            return {"status": "error", "message": "Bad Request to Google Safe Browsing"}

        if resp.status_code == 403:
            logger.warning("[SafeBrowsing] API key invalid or unauthorized.")
            return {"status": "error", "message": "Unauthorized/Invalid API key for Safe Browsing"}

        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])

        if not matches:
            return {
                "status": "success",
                "available": True,
                "safe": True,
                "no_threats_found": True,
                "threats_found": False,
                "threat_count": 0,
                "threat_types": [],
                "platform_types": [],
                "platforms_flagged": [],
                "threat_entry_types": [],
                "matches": [],
                "cache_duration": None,
                "verdict": "clean",
                "severity": "low",
                "confidence": "high",
                "reason": "No threats found on Google Safe Browsing threat lists."
            }

        threat_types = list(set([match.get("threatType") for match in matches if match.get("threatType")]))
        platform_types = list(set([match.get("platformType") for match in matches if match.get("platformType")]))
        threat_entry_types = list(set([match.get("threatEntryType") for match in matches if match.get("threatEntryType")]))
        
        cache_duration = None
        for match in matches:
            if match.get("cacheDuration"):
                cache_duration = match.get("cacheDuration")
                break

        extracted_matches = []
        for match in matches:
            extracted_matches.append({
                "threatType": match.get("threatType"),
                "platformType": match.get("platformType"),
                "threatEntryType": match.get("threatEntryType"),
                "cacheDuration": match.get("cacheDuration"),
                "url": match.get("threat", {}).get("url"),
                "metadata": match.get("threatEntryMetadata", {}).get("entries", [])
            })

        return {
            "status": "success",
            "available": True,
            "safe": False,
            "no_threats_found": False,
            "threats_found": True,
            "threat_count": len(matches),
            "threat_types": threat_types,
            "platform_types": platform_types,
            "platforms_flagged": platform_types,  # backward compatibility
            "threat_entry_types": threat_entry_types,
            "matches": extracted_matches[:10],  # bounded list
            "cache_duration": cache_duration,
            "verdict": "flagged",
            "severity": "critical",
            "confidence": "high",
            "reason": f"Flagged by Google Safe Browsing for: {', '.join(threat_types)}."
        }

    except RequestException as e:
        logger.warning(f"[SafeBrowsing] Network/API error: {e}")
        return {
            "status": "error",
            "available": False,
            "threats_found": False,
            "verdict": "unknown",
            "severity": "low",
            "confidence": "low",
            "reason": f"Safe Browsing API check failed: Network error: {e}",
            "message": f"Network error: {e}"
        }
    except Exception as e:
        logger.warning(f"[SafeBrowsing] Unexpected error: {e}")
        return {
            "status": "error",
            "available": False,
            "threats_found": False,
            "verdict": "unknown",
            "severity": "low",
            "confidence": "low",
            "reason": f"Safe Browsing API check failed: Internal error: {e}",
            "message": "Internal error during Safe Browsing lookup"
        }
