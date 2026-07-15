from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, render_template

from .config import BaseConfig
from .extensions import db, csrf, limiter
from .phishing import bp as phishing_bp
from .security import configure_logging, configure_security


def create_app():
    app = Flask(__name__)
    app.config.from_object(BaseConfig)

    vt_enabled = app.config.get("VT_ENABLED", False)
    vt_key_present = bool(app.config.get("VT_API_KEY"))
    app.logger.info(
        f"[STARTUP] VT_ENABLED={vt_enabled} | VT_API_KEY={'set' if vt_key_present else 'missing'}"
    )
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config.get("RESULTS_DIR", "results")).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    configure_logging(app)
    configure_security(app)
    app.register_blueprint(phishing_bp)

    with app.app_context():
        db.create_all()

    @app.context_processor
    def inject_globals():
        return {"app_name": "Detector"}

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("errors/404.html", page_title="Not found"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html", page_title="Error"), 500

    @app.route("/health")
    def health():
        try:
            db.session.execute(db.text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"status": "ok" if db_ok else "degraded", "database": db_ok})

    return app
