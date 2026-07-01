from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request,
    send_from_directory,
)

from app.extensions import db, limiter
from app.forms import URLForm
from app.models import Analysis
from .heuristics import AnalysisInputError
from .services import recent_analyses, run_analysis, serialize_analysis

bp = Blueprint("phishing", __name__)


@bp.route("/")
def index():
    return render_template("index.html", form=URLForm(), recent=recent_analyses(20), page_title="Detector")


@bp.route("/api/analyze", methods=["POST"])
@limiter.limit(lambda: current_app.config["ANALYZE_RATE_LIMIT"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    try:
        result = run_analysis(url, current_app.config)
    except AnalysisInputError as exc:
        return jsonify({"error": {"type": "invalid_url", "message": exc.message}}), 400
    analysis = db.session.get(Analysis, result.analysis_id)
    return jsonify(serialize_analysis(analysis))


@bp.route("/api/feedback", methods=["POST"])
def api_feedback():
    payload = request.get_json(silent=True) or {}
    analysis_id = payload.get("analysis_id")
    verdict = payload.get("verdict")
    note = (payload.get("note") or "")[:500]
    if not analysis_id or verdict not in ("satisfied", "not_satisfied"):
        return jsonify({"error": "invalid payload"}), 400
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return jsonify({"error": "not found"}), 404
    analysis.feedback = verdict
    analysis.feedback_note = note
    db.session.commit()
    return jsonify({"status": "recorded"})


@bp.route("/offline")
def offline():
    return render_template("offline.html", page_title="Offline")


@bp.route("/manifest.json")
def manifest():
    return send_from_directory(current_app.static_folder, "manifest.json", mimetype="application/manifest+json")


@bp.route("/sw.js")
def service_worker():
    r = send_from_directory(current_app.static_folder, "sw.js", mimetype="application/javascript")
    r.headers["Service-Worker-Allowed"] = "/"
    r.headers["Cache-Control"] = "no-cache"
    return r