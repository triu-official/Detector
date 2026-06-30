from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from app.extensions import db, limiter
from app.forms import URLForm
from app.models import Analysis, Feedback

from .heuristics import AnalysisInputError, validate_url
from .services import _build_explanations, filtered_reports, recent_analyses, run_analysis, serialize_analysis

bp = Blueprint("phishing", __name__)


@bp.route("/")
def index():
    return render_template(
        "index.html",
        form=URLForm(),
        recent=recent_analyses(),
        page_title="Analyze suspicious websites",
    )


@bp.route("/analyze", methods=["POST"])
def analyze():
    form = URLForm()
    if not form.validate_on_submit():
        flash("Please enter a valid URL or domain.", "error")
        return redirect(url_for("phishing.index"))
    try:
        result = run_analysis(form.url.data, current_app.config)
    except AnalysisInputError as exc:
        flash(exc.message, "error")
        return redirect(url_for("phishing.index"))
    return redirect(url_for("phishing.result_detail", analysis_id=result.analysis_id))


@bp.route("/result/<int:analysis_id>")
def result_detail(analysis_id: int):
    # Use db.get_or_404 — Query.get() is deprecated in SQLAlchemy 2.x
    analysis = db.get_or_404(Analysis, analysis_id)
    return render_template(
        "result.html",
        analysis=analysis,
        serialized=serialize_analysis(analysis),
        page_title="Analysis result",
    )


@bp.route("/offline")
def offline():
    return render_template("offline.html", page_title="Offline")


@bp.route("/manifest.json")
def manifest():
    return send_from_directory(current_app.static_folder, "manifest.json", mimetype="application/manifest+json")


@bp.route("/sw.js")
def service_worker():
    response = send_from_directory(current_app.static_folder, "sw.js", mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@bp.route("/api/analyze", methods=["POST"])
@limiter.limit(lambda: current_app.config["ANALYZE_RATE_LIMIT"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    try:
        result = run_analysis(url, current_app.config)
    except AnalysisInputError as exc:
        current_app.logger.warning("invalid_analysis_input", extra={"path": request.path, "method": request.method})
        return jsonify({"error": {"type": exc.error_type, "message": exc.message}}), 400
    analysis = db.session.get(Analysis, result.analysis_id)
    return jsonify(serialize_analysis(analysis))


@bp.route("/api/analyze/async", methods=["POST"])
@limiter.limit(lambda: current_app.config["ANALYZE_RATE_LIMIT"])
def api_analyze_async():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"error": {"type": "invalid_url", "message": "URL is required"}}), 400
    ok, message = validate_url(url)
    if not ok:
        return jsonify({"error": {"type": "invalid_url", "message": message}}), 400

    try:
        from app.celery_app import analyze_url_task
        task_result = analyze_url_task.delay(url)
        return (
            jsonify({
                "job_id": task_result.id,
                "status": "queued",
                "status_url": url_for("phishing.api_job_status", job_id=task_result.id),
                "async": True,
            }),
            202,
        )
    except Exception as broker_err:  # noqa: BLE001
        current_app.logger.warning(
            "celery_broker_unavailable_falling_back_to_sync",
            extra={"error": str(broker_err)},
        )

    try:
        result = run_analysis(url, current_app.config)
    except AnalysisInputError as exc:
        return jsonify({"error": {"type": exc.error_type, "message": exc.message}}), 400

    analysis = db.session.get(Analysis, result.analysis_id)
    serialized = serialize_analysis(analysis)
    return jsonify({
        "job_id": None,
        "status": "completed",
        "result": serialized,
        "async": False,
    }), 200


@bp.route("/api/jobs/<string:job_id>")
@limiter.limit(lambda: current_app.config["ANALYZE_RATE_LIMIT"])
def api_job_status(job_id: str):
    from app.celery_app import get_job_state

    task = get_job_state(job_id)
    state = (task.state or "PENDING").upper()
    if state in {"PENDING", "RETRY"}:
        return jsonify({"job_id": job_id, "status": "queued"})
    if state == "STARTED":
        return jsonify({"job_id": job_id, "status": "running"})
    if state == "FAILURE":
        exc = task.result
        if isinstance(exc, AnalysisInputError):
            return (
                jsonify({
                    "job_id": job_id,
                    "status": "failed",
                    "error": {"type": exc.error_type, "message": exc.message},
                }),
                400,
            )
        current_app.logger.error("analysis_job_failed", extra={"job_id": job_id})
        return (
            jsonify({
                "job_id": job_id,
                "status": "failed",
                "error": {"type": "analysis_failed", "message": "Analysis job failed unexpectedly"},
            }),
            500,
        )
    payload = task.result or {}
    analysis_id = payload.get("analysis_id")
    if not analysis_id:
        return (
            jsonify({
                "job_id": job_id,
                "status": "failed",
                "error": {"type": "missing_result", "message": "Analysis result missing"},
            }),
            500,
        )
    analysis = db.session.get(Analysis, analysis_id)
    if analysis is None:
        return (
            jsonify({
                "job_id": job_id,
                "status": "failed",
                "error": {"type": "missing_result", "message": "Analysis record missing"},
            }),
            500,
        )
    result = serialize_analysis(analysis)
    if not result.get("explanations"):
        result["explanations"] = _build_explanations(result.get("reasons", []))
    return jsonify({"job_id": job_id, "status": "completed", "result": result})


@bp.route("/api/reports")
@limiter.limit(lambda: current_app.config["REPORTS_RATE_LIMIT"])
def api_reports():
    pagination = filtered_reports(
        page=max(int(request.args.get("page", 1)), 1),
        per_page=min(max(int(request.args.get("per_page", 20)), 1), 100),
        label=request.args.get("label") or None,
        domain=request.args.get("domain") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
    )
    return jsonify({
        "items": [serialize_analysis(item) for item in pagination.items],
        "pagination": {
            "page": pagination.page,
            "pages": pagination.pages,
            "per_page": pagination.per_page,
            "total": pagination.total,
        },
    })


@bp.route("/api/export/json")
@limiter.limit(lambda: current_app.config["REPORTS_RATE_LIMIT"])
def api_export_json():
    pagination = filtered_reports(
        page=1,
        per_page=min(max(int(request.args.get("per_page", 100)), 1), 500),
        label=request.args.get("label") or None,
        domain=request.args.get("domain") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
    )
    return jsonify({"items": [serialize_analysis(item) for item in pagination.items]})


@bp.route("/feedback/<int:analysis_id>", methods=["POST"])
def feedback(analysis_id: int):
    analysis = db.get_or_404(Analysis, analysis_id)
    db.session.add(Feedback(analysis_id=analysis.id))
    db.session.commit()
    return jsonify({"status": "recorded"})


@bp.route("/disclaimer")
def disclaimer():
    return render_template("disclaimer.html", page_title="Disclaimer")


@bp.route("/privacy")
def privacy():
    return render_template("privacy.html", page_title="Privacy")


@bp.route("/terms")
def terms():
    return render_template("terms.html", page_title="Terms")
