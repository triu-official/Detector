from __future__ import annotations

import logging
from typing import Any
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

def get_urlscan_report(url: str, config: dict[str, Any]) -> dict[str, Any] | None:
    api_key = config.get("URLSCAN_API_KEY")
    if not api_key:
        return None

    timeout = config.get("REQUEST_TIMEOUT_SECONDS", 10)

    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json'
    }

    payload = {
        "url": url,
        "visibility": "public"
    }

    try:
        logger.info(f"[Urlscan] Submitting URL: {url}")

        # Submit the scan
        submit_resp = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=payload, timeout=timeout)

        if submit_resp.status_code == 429:
            logger.warning("[Urlscan] Rate limit exceeded.")
            return {"status": "rate_limited", "message": "urlscan.io rate limit exceeded"}

        if submit_resp.status_code == 400:
             logger.warning(f"[Urlscan] Bad Request. {submit_resp.text}")
             return {"status": "error", "message": "Bad Request to urlscan.io"}

        if submit_resp.status_code == 403 or submit_resp.status_code == 401:
             logger.warning("[Urlscan] Invalid API Key.")
             return {"status": "error", "message": "Invalid urlscan.io API key"}

        submit_resp.raise_for_status()
        submit_data = submit_resp.json()

        return {
            "status": "success",
            "message": "Scan submitted successfully",
            "uuid": submit_data.get("uuid"),
            "api_url": submit_data.get("api"),
            "visibility": submit_data.get("visibility"),
            "options": submit_data.get("options"),
            "result_url": submit_data.get("result")
        }
    except RequestException as e:
        logger.warning(f"[Urlscan] Network/API error: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        logger.warning(f"[Urlscan] Unexpected error: {e}")
        return {"status": "error", "message": "Internal error during Urlscan lookup"}
