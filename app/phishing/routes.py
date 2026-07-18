from __future__ import annotations

from pathlib import Path

import io
from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request,
    send_from_directory,
    send_file,
)

from app.extensions import db, limiter, csrf
from app.forms import URLForm
from app.models import Analysis
from .heuristics import AnalysisInputError
from .services import recent_analyses, run_analysis, serialize_analysis

bp = Blueprint("phishing", __name__)


@bp.route("/")
def index():
    return render_template("index.html", form=URLForm(), recent=recent_analyses(20), page_title="Detector")


@bp.route("/api/analyze", methods=["POST"])
@csrf.exempt
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
@csrf.exempt
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


@bp.route("/report/<int:analysis_id>")
def report_detail(analysis_id):
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return render_template("errors/404.html", page_title="Not found"), 404
    data = serialize_analysis(analysis)
    # Normalize VT summary from DB so old cached data matches current schema
    vt = (data.get("features_summary", {})
               .get("page_signals", {})
               .get("vt_summary"))
    if vt and vt.get("status") == "success":
        from app.phishing.virustotal import normalize_vt_summary
        data["features_summary"]["page_signals"]["vt_summary"] = normalize_vt_summary(vt)
    return render_template("report.html", data=data, page_title=f"Report #{analysis_id}")


@bp.route("/report/<int:analysis_id>/pdf/standard")
def report_pdf_standard(analysis_id):
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return render_template("errors/404.html", page_title="Not found"), 404
    data = serialize_analysis(analysis)
    vt = (data.get("features_summary", {})
               .get("page_signals", {})
               .get("vt_summary"))
    if vt and vt.get("status") == "success":
        from app.phishing.virustotal import normalize_vt_summary
        data["features_summary"]["page_signals"]["vt_summary"] = normalize_vt_summary(vt)

    html_content = render_template("pdf_report.html", data=data, include_footprint=False)
    import weasyprint
    pdf_bytes = weasyprint.HTML(string=html_content, base_url=request.base_url).write_pdf()

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"analysis_report_{analysis_id}.pdf"
    )

@bp.route("/report/<int:analysis_id>/pdf/footprint")
def report_pdf_footprint(analysis_id):
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return render_template("errors/404.html", page_title="Not found"), 404
    data = serialize_analysis(analysis)
    vt = (data.get("features_summary", {})
               .get("page_signals", {})
               .get("vt_summary"))
    if vt and vt.get("status") == "success":
        from app.phishing.virustotal import normalize_vt_summary
        data["features_summary"]["page_signals"]["vt_summary"] = normalize_vt_summary(vt)

    html_content = render_template("pdf_report.html", data=data, include_footprint=True)
    import weasyprint
    pdf_bytes = weasyprint.HTML(string=html_content, base_url=request.base_url).write_pdf()

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"analysis_report_with_footprint_{analysis_id}.pdf"
    )


@bp.route("/api/report/<int:analysis_id>")
def api_report(analysis_id):
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return jsonify({"error": "not found"}), 404
    data = serialize_analysis(analysis)
    vt = (data.get("features_summary", {})
               .get("page_signals", {})
               .get("vt_summary"))
    if vt and vt.get("status") == "success":
        from app.phishing.virustotal import normalize_vt_summary
        data["features_summary"]["page_signals"]["vt_summary"] = normalize_vt_summary(vt)
    return jsonify(data)


@bp.route("/api/report/<int:analysis_id>/delete", methods=["POST"])
@csrf.exempt
def api_report_delete(analysis_id):
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        return jsonify({"error": "not found"}), 404
    results_dir = Path(current_app.config.get("RESULTS_DIR", "results"))
    json_path = results_dir / f"{analysis_id}.json"
    if json_path.exists():
        try:
            json_path.unlink()
        except OSError:
            pass
    db.session.delete(analysis)
    db.session.commit()
    return jsonify({"status": "deleted"})


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