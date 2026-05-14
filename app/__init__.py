import logging
from logging.handlers import RotatingFileHandler
import os

from flask import Flask
from flask_cors import CORS
import sentry_sdk

from .config import Config
from .extensions import csrf, db, limiter
from .models import User
from .routes import bp


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    _validate_security_config(app)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    if os.getenv("SENTRY_DSN"):
        sentry_sdk.init(dsn=os.getenv("SENTRY_DSN"), traces_sample_rate=0.1)

    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()
        User.create_admin_if_missing(app.config["ADMIN_USERNAME"], app.config["ADMIN_PASSWORD"])

    _configure_logging(app)
    _configure_security_headers(app)
    _configure_optional_monitoring(app)

    return app


def _configure_logging(app: Flask) -> None:
    os.makedirs("instance", exist_ok=True)
    handler = RotatingFileHandler("instance/detector.log", maxBytes=5_000_000, backupCount=3)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(handler)



def _configure_security_headers(app: Flask) -> None:
    @app.after_request
    def set_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net"
        return response



def _configure_optional_monitoring(app: Flask) -> None:
    if os.getenv("ENABLE_FLASK_MONITORING", "false").lower() == "true":
        import flask_monitoringdashboard as dashboard

        dashboard.bind(app)


def _validate_security_config(app: Flask) -> None:
    is_testing = app.config.get("TESTING", False)
    is_production = app.config.get("FLASK_ENV") == "production"
    if is_production and not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY must be set in production.")
    if is_production and not app.config.get("ADMIN_PASSWORD"):
        raise RuntimeError("ADMIN_PASSWORD must be set.")
