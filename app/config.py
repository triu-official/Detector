from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


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

    # Label thresholds: 0-24 safe, 25-49 suspicious, 50+ phishing
    SAFE_THRESHOLD = int(os.getenv("SAFE_THRESHOLD", "25"))
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

    # VirusTotal Integration
    VT_ENABLED = os.getenv("VT_ENABLED", "false").lower() == "true"
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    VT_TIMEOUT = int(os.getenv("VT_TIMEOUT", "10"))

    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
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
