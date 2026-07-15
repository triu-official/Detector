from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def compute_label_from_score(score: int, config: dict | None = None) -> str:
    """Canonical score-to-label mapping. Every layer must use this."""
    cfg = config or {}
    phishing_threshold = int(cfg.get("PHISHING_THRESHOLD", 50))
    suspicious_threshold = int(cfg.get("SUSPICIOUS_THRESHOLD", 25))
    if score >= phishing_threshold:
        return "phishing"
    elif score >= suspicious_threshold:
        return "suspicious"
    else:
        return "safe"


class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/instance/detector.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    ANALYZE_RATE_LIMIT = os.getenv("ANALYZE_RATE_LIMIT", "30/hour")
    REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
    MAX_REDIRECT_DEPTH = int(os.getenv("MAX_REDIRECT_DEPTH", "5"))

    # Label thresholds: score < SUSPICIOUS_THRESHOLD = safe, >= SUSPICIOUS_THRESHOLD = suspicious, >= PHISHING_THRESHOLD = phishing
    SUSPICIOUS_THRESHOLD = int(os.getenv("SUSPICIOUS_THRESHOLD", "25"))
    PHISHING_THRESHOLD = int(os.getenv("PHISHING_THRESHOLD", "50"))

    # Domain age buckets
    DOMAIN_AGE_EXTREME_RISK_DAYS = 30
    DOMAIN_AGE_VERY_HIGH_RISK_DAYS = 90
    DOMAIN_AGE_HIGH_RISK_DAYS = 180
    DOMAIN_AGE_MODERATE_RISK_DAYS = 365

    NEW_DOMAIN_DAYS = 7
    YOUNG_DOMAIN_DAYS = 30
    NEW_DOMAIN_PENALTY = 20
    YOUNG_DOMAIN_PENALTY = 10

    # VirusTotal Integration (optional enrichment, disabled by default)
    VT_ENABLED = os.getenv("VT_ENABLED", "false").lower() == "true"
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    VT_TIMEOUT = int(os.getenv("VT_TIMEOUT", "10"))
    VT_SCORE_BUMP_MALICIOUS = int(os.getenv("VT_SCORE_BUMP_MALICIOUS", "15"))
    VT_SCORE_BUMP_SUSPICIOUS = int(os.getenv("VT_SCORE_BUMP_SUSPICIOUS", "5"))
    VT_MAX_BUMP_MALICIOUS = int(os.getenv("VT_MAX_BUMP_MALICIOUS", "30"))
    VT_MAX_BUMP_SUSPICIOUS = int(os.getenv("VT_MAX_BUMP_SUSPICIOUS", "10"))

    # Optional Enrichment APIs
    SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY", "")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")
    RESULTS_DIR = os.getenv("RESULTS_DIR", "results")
    CSP = {
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self'",
        "img-src": "'self' data:",
        "connect-src": "'self'",
        "object-src": "'none'",
        "frame-ancestors": "'none'",
    }
