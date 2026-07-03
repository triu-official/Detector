from __future__ import annotations

import json
import logging
import sys
import time
from logging.handlers import RotatingFileHandler

from flask import Flask, g, request
from flask_talisman import Talisman


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "time": self.formatTime(record, self.datefmt),
        }
        for attribute in ("path", "method", "status_code", "duration_ms"):
            if hasattr(record, attribute):
                payload[attribute] = getattr(record, attribute)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_security(app: Flask) -> None:
    Talisman(
        app,
        content_security_policy=app.config["CSP"],
        content_security_policy_nonce_in=[],
        force_https=app.config["FLASK_ENV"] == "production",
        frame_options="DENY",
        strict_transport_security=app.config["FLASK_ENV"] == "production",
        strict_transport_security_max_age=31536000,
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy={"geolocation": "()", "microphone": "()", "camera": "()"},
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_http_only=True,
        session_cookie_samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )


def configure_logging(app: Flask) -> None:
    formatter: logging.Formatter = (
        JsonFormatter()
        if app.config["FLASK_ENV"] == "production"
        else logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    file_handler = RotatingFileHandler("backend_audit.log", maxBytes=5_000_000, backupCount=3)
    file_handler.setFormatter(formatter)
    app.logger.handlers.clear()
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(stream_handler)
    app.logger.addHandler(file_handler)

    @app.before_request
    def start_request_timer() -> None:
        g.started_at = time.perf_counter()

    @app.after_request
    def log_request(response):
        duration_ms = round(
            (time.perf_counter() - getattr(g, "started_at", time.perf_counter()))
            * 1000,
            2,
        )
        app.logger.info(
            "request_complete",
            extra={
                "method": request.method,
                "path": request.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response
