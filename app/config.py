from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _celery_default(key: str, redis_url: str, fallback: str) -> str:
    val = os.getenv(key, "")
    if val:
        return val
    if redis_url:
        return redis_url
    return fallback


class BaseConfig:
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    # SECRET_KEY MUST be set via environment in production — never rely on a random default
    # that changes on every restart (invalidates all sessions).
    SECRET_KEY: str
    _secret_key_env = os.getenv("SECRET_KEY", "")
    if _secret_key_env:
        SECRET_KEY = _secret_key_env
    else:
        # Development fallback: generate once per process (sessions survive restarts only in dev)
        SECRET_KEY = secrets.token_urlsafe(32)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///detector.db").replace(
        "postgres://", "postgresql://", 1
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.getenv("REDIS_URL", "")
    RATELIMIT_STORAGE_URI = REDIS_URL if REDIS_URL else "memory://"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    WTF_CSRF_TIME_LIMIT = None
    REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
    REQUEST_RETRY_COUNT = int(os.getenv("REQUEST_RETRY_COUNT", "1"))
    MAX_REQUEST_TIMEOUT_SECONDS = int(os.getenv("MAX_REQUEST_TIMEOUT_SECONDS", "30"))
    MAX_REQUEST_RETRY_COUNT = int(os.getenv("MAX_REQUEST_RETRY_COUNT", "3"))
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
    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    SENTRY_DSN = os.getenv("SENTRY_DSN", "")
    BATCH_ANALYSIS_LIMIT = int(os.getenv("BATCH_ANALYSIS_LIMIT", "50"))
    MAX_BATCH_ANALYSIS_LIMIT = int(os.getenv("MAX_BATCH_ANALYSIS_LIMIT", "500"))
    REQUEST_LOG_RETENTION_DAYS = int(os.getenv("REQUEST_LOG_RETENTION_DAYS", "30"))
    REPORT_RETENTION_DAYS = int(os.getenv("REPORT_RETENTION_DAYS", "90"))
    CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "3600"))
    THREAT_INTEL_STATIC_DOMAINS = os.getenv("THREAT_INTEL_STATIC_DOMAINS", "")
    _redis_url = REDIS_URL
    CELERY_BROKER_URL = _celery_default("CELERY_BROKER_URL", _redis_url, "memory://")
    CELERY_RESULT_BACKEND = _celery_default("CELERY_RESULT_BACKEND", _redis_url, "cache+memory://")
    CELERY_TASK_ALWAYS_EAGER = os.getenv("CELERY_TASK_ALWAYS_EAGER", "true" if not REDIS_URL else "false").lower() == "true"
    CELERY_TASK_EAGER_PROPAGATES = os.getenv("CELERY_TASK_EAGER_PROPAGATES", "true").lower() == "true"
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
    WTF_CSRF_ENABLED = False


class ProductionConfig(BaseConfig):
    SESSION_COOKIE_SECURE = True

    @classmethod
    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

    def __init_production_checks(self) -> None:
        if not os.getenv("SECRET_KEY"):
            raise RuntimeError("SECRET_KEY environment variable must be set in production.")


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
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_BROKER_URL = "memory://"
    CELERY_RESULT_BACKEND = "cache+memory://"


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
