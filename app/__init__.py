from __future__ import annotations

import os
import time
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

from .admin import bp as admin_bp
from .config import CONFIG_MAP, BaseConfig
from .extensions import (
    configure_redis,
    csrf,
    db,
    error_buffer,
    limiter,
    login_manager,
    migrate,
    record_error,
    redis_client,
    runtime_state,
)
from .models import RequestLog, User, prune_old_data
from .phishing import bp as phishing_bp
from .security import configure_logging, configure_security


def create_app(config_class: type[BaseConfig] | None = None):
    app = Flask(__name__)
    config_source = config_class or CONFIG_MAP.get(
        os.getenv("FLASK_ENV", "development"),
        CONFIG_MAP["development"],
    )
    app.config.from_object(config_source)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    configure_redis(app.config["REDIS_URL"])
    configure_logging(app)
    configure_security(app)

    login_manager.login_view = "admin.login"
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id: str):
        return db.session.get(User, int(user_id))

    app.register_blueprint(phishing_bp)
    app.register_blueprint(admin_bp)

    # Initialise Celery with this app so tasks share the same context
    from .celery_app import init_celery
    init_celery(app)

    with app.app_context():
        _validate_runtime_config(app)
        try:
            if inspect(db.engine).has_table("users"):
                _sync_admin_user(app)
        except SQLAlchemyError:
            app.logger.debug("admin_user_sync_skipped", exc_info=True)
        runtime_state.model_loaded = bool(app.config["MODEL_PATH"])

    @app.context_processor
    def inject_shell_context():
        return {"app_name": "Detector PWA"}

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html", page_title="Page not found"), 404

    @app.errorhandler(500)
    def server_error(error):
        record_error(str(error), path=request.path, error_type="server_error")
        return render_template("errors/500.html", page_title="Server error"), 500

    @app.errorhandler(503)
    def unavailable(_error):
        return render_template("errors/503.html", page_title="Unavailable"), 503

    @app.route("/health")
    def health():
        return jsonify(gather_health_snapshot())

    @app.route("/metrics")
    def metrics():
        from .models import Analysis

        total = Analysis.query.count()
        safe = Analysis.query.filter_by(label="safe").count()
        suspicious = Analysis.query.filter_by(label="suspicious").count()
        phishing = Analysis.query.filter_by(label="phishing").count()
        cache_hits = Analysis.query.filter_by(cache_hit=True).count()
        unreachable = Analysis.query.filter(Analysis.reachability == "unreachable").count()
        avg_latency = db.session.query(db.func.avg(Analysis.latency_ms)).scalar() or 0
        body = [
            f"detector_total_analyses {total}",
            f"detector_safe_analyses {safe}",
            f"detector_suspicious_analyses {suspicious}",
            f"detector_phishing_analyses {phishing}",
            f"detector_cache_hits {cache_hits}",
            f"detector_unreachable_analyses {unreachable}",
            f"detector_recent_error_count {len(error_buffer)}",
            f"detector_avg_latency_ms {avg_latency:.2f}",
        ]
        return "\n".join(body) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}

    @app.after_request
    def store_request_log(response):
        try:
            duration_ms = int(
                (time.perf_counter() - getattr(g, "started_at", time.perf_counter()))
                * 1000
            )
            db.session.add(
                RequestLog(
                    method=request.method,
                    path=request.path,
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                )
            )
            db.session.commit()
            if time.time() - runtime_state.last_cleanup_at >= app.config["CLEANUP_INTERVAL_SECONDS"]:
                deleted = prune_old_data(
                    request_log_retention_days=app.config["REQUEST_LOG_RETENTION_DAYS"],
                    report_retention_days=app.config["REPORT_RETENTION_DAYS"],
                )
                if deleted["request_logs"] or deleted["reports"]:
                    app.logger.info("retention_cleanup", extra={"deleted": deleted})
                db.session.commit()
                runtime_state.last_cleanup_at = time.time()
        except Exception as exc:
            app.logger.warning(
                "request_log_failed",
                extra={"path": request.path, "method": request.method},
            )
            record_error(
                str(exc),
                path=request.path,
                error_type="request_log_failed",
            )
            db.session.rollback()
        return response

    return app


def _sync_admin_user(app: Flask) -> None:
    password_hash = app.config["ADMIN_PASSWORD_HASH"] or generate_password_hash(
        app.config["ADMIN_PASSWORD"] or "change-me-now"
    )
    User.sync_admin_user(app.config["ADMIN_USERNAME"], password_hash)


def _validate_runtime_config(app: Flask) -> None:
    """Warn if no admin password or SECRET_KEY is configured; never crash in dev."""
    if not app.config.get("SECRET_KEY"):
        env = app.config.get("FLASK_ENV", "development")
        if env == "production":
            raise RuntimeError("SECRET_KEY must be set in production.")
        app.logger.warning(
            "No SECRET_KEY set. Using a random key; sessions will be invalidated on restart. "
            "Set SECRET_KEY in your .env for persistent sessions."
        )
        import secrets
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)
    if not (app.config["ADMIN_PASSWORD_HASH"] or app.config["ADMIN_PASSWORD"]):
        # Use a safe default in development; warn but don't block startup
        env = app.config.get("FLASK_ENV", "development")
        if env == "production":
            raise RuntimeError(
                "ADMIN_PASSWORD_HASH or ADMIN_PASSWORD must be set in production."
            )
        app.logger.warning(
            "No ADMIN_PASSWORD or ADMIN_PASSWORD_HASH set. "
            "Admin will use default password 'change-me-now'. "
            "Set ADMIN_PASSWORD in your .env for real security."
        )
        # Inject a default so _sync_admin_user works without crashing
        app.config["ADMIN_PASSWORD"] = "change-me-now"


def gather_health_snapshot() -> dict:
    from .models import Analysis

    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    try:
        redis_ok = bool(redis_client.ping())
    except Exception:
        redis_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
        "redis": redis_ok,
        "model_loaded": runtime_state.model_loaded,
        "last_error": runtime_state.last_error,
        "recent_errors": list(error_buffer),
        "total_analyses": Analysis.query.count() if db_ok else 0,
    }
