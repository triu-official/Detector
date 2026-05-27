from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class BaseConfig:
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///detector.db").replace(
        "postgres://", "postgresql://", 1
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RATELIMIT_STORAGE_URI = os.getenv("REDIS_URL", "memory://")
    REDIS_URL = os.getenv("REDIS_URL", "")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    WTF_CSRF_TIME_LIMIT = None
    REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
    REQUEST_RETRY_COUNT = int(os.getenv("REQUEST_RETRY_COUNT", "1"))
    MAX_REDIRECT_DEPTH = int(os.getenv("MAX_REDIRECT_DEPTH", "5"))
    ANALYZE_RATE_LIMIT = os.getenv("ANALYZE_RATE_LIMIT", "30/hour")
    ADMIN_RATE_LIMIT = os.getenv("ADMIN_RATE_LIMIT", "10/minute")
    REPORTS_RATE_LIMIT = os.getenv("REPORTS_RATE_LIMIT", "20/minute")
    RESULT_CACHE_TTL_SECONDS = int(os.getenv("RESULT_CACHE_TTL_SECONDS", "1800"))
    DOMAIN_CACHE_TTL_SECONDS = int(os.getenv("DOMAIN_CACHE_TTL_SECONDS", "259200"))
    SAFE_THRESHOLD = int(os.getenv("SAFE_THRESHOLD", "30"))
    SUSPICIOUS_THRESHOLD = int(os.getenv("SUSPICIOUS_THRESHOLD", "60"))
    PHISHING_THRESHOLD = int(os.getenv("PHISHING_THRESHOLD", "80"))
    NEW_DOMAIN_DAYS = int(os.getenv("NEW_DOMAIN_DAYS", "7"))
    YOUNG_DOMAIN_DAYS = int(os.getenv("YOUNG_DOMAIN_DAYS", "30"))
    NEW_DOMAIN_PENALTY = int(os.getenv("NEW_DOMAIN_PENALTY", "20"))
    YOUNG_DOMAIN_PENALTY = int(os.getenv("YOUNG_DOMAIN_PENALTY", "10"))
    HEURISTIC_BLEND_WEIGHT = float(os.getenv("HEURISTIC_BLEND_WEIGHT", "0.6"))
    ML_BLEND_WEIGHT = float(os.getenv("ML_BLEND_WEIGHT", "0.4"))
    MODEL_PATH = os.getenv("MODEL_PATH", "")
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
    ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
    CORS_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
    SENTRY_DSN = os.getenv("SENTRY_DSN", "")
    BATCH_ANALYSIS_LIMIT = int(os.getenv("BATCH_ANALYSIS_LIMIT", "50"))
    CSP = {
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self'",
        "img-src": "'self' data:",
        "font-src": "'self'",
        "connect-src": "'self'",
        "object-src": "'none'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    }


class DevelopmentConfig(BaseConfig):
    SESSION_COOKIE_SECURE = False


class ProductionConfig(BaseConfig):
    SESSION_COOKIE_SECURE = True


class TestingConfig(BaseConfig):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False
    REDIS_URL = ""
    ANALYZE_RATE_LIMIT = "1000/hour"
    ADMIN_RATE_LIMIT = "1000/hour"
    REPORTS_RATE_LIMIT = "1000/hour"
    REQUEST_TIMEOUT_SECONDS = 1
    REQUEST_RETRY_COUNT = 0


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
