from __future__ import annotations

import json
import logging
from typing import Any

from flask import current_app

logger = logging.getLogger(__name__)


def analyze_with_ai(url: str, page_content: str, features_summary: dict[str, Any]) -> dict[str, Any]:
    api_key = current_app.config.get("GOOGLE_API_KEY", "")
    if not api_key:
        return {"available": False, "message": "AI analysis unavailable: no API key configured"}

    try:
        from google import genai

        client = genai.Client(api_key=api_key)

        prompt = _build_master_prompt(url, page_content, features_summary)

        from google.genai import types

        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )

        if not response.text:
            return {"available": True, "reasoning": "AI returned no analysis text."}

        return _parse_ai_response(response.text)

    except Exception as exc:
        logger.warning("AI analysis failed for %s: %s", url, exc)
        return {"available": False, "message": f"AI analysis error: {exc}"}


def _build_master_prompt(url: str, page_content: str, features: dict[str, Any]) -> str:
    content_preview = (page_content or "")[:1500]

    return f"""
    You are an expert Cybersecurity Phishing Analyst.
    Analyze this website data and determine if it is a FAKE/PHISHING website.

    Website URL: {url}
    Scraped Text Content from Webpage: {content_preview} (truncated)

    Provide your response strictly in the following JSON format:
    {{
        "is_fake": true/false,
        "confidence_score": 0-100,
        "reasoning": "A short 2-sentence explanation of why it is safe or fake."
    }}
    """


def _parse_ai_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        text = text.rsplit("```", 1)[0]
    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"available": True, "reasoning": text[:500]}

    return {
        "available": True,
        "is_fake": data.get("is_fake", False),
        "confidence_score": data.get("confidence_score", 0),
        "reasoning": data.get("reasoning", "No reasoning provided.")
    }