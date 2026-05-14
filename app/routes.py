from __future__ import annotations

import csv
import io
from functools import wraps

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from weasyprint import HTML

from .analyzer import analyze_url
from .extensions import csrf, db, limiter
from .forms import LoginForm, URLForm
from .models import Analysis, Blacklist, History, Report, User

bp = Blueprint("main", __name__)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("main.login"))
        return view_func(*args, **kwargs)

    return wrapped


def _blacklist_domains() -> set[str]:
    return {b.domain.lower() for b in Blacklist.query.all()}


def _persist_analysis(result, user_id: int | None = None) -> Analysis:
    analysis = Analysis(
        url=result.url,
        risk_score=result.score,
        verdict=result.verdict,
        reasons="\n".join(result.reasons),
        redirect_chain="\n".join(result.redirect_chain),
        user_id=user_id,
    )
    db.session.add(analysis)
    db.session.flush()
    db.session.add(History(analysis_id=analysis.id))
    db.session.commit()
    return analysis


@bp.route("/")
def index():
    form = URLForm()
    return render_template("index.html", form=form)


@bp.route("/analyze", methods=["POST"])
@limiter.limit("20/minute")
def analyze():
    form = URLForm()
    if not form.validate_on_submit():
        flash("Please provide a valid URL.", "danger")
        return redirect(url_for("main.index"))

    url = form.url.data.strip()
    try:
        result = analyze_url(
            url,
            timeout=current_app.config["REQUEST_TIMEOUT_SECONDS"],
            max_redirect_depth=current_app.config["MAX_REDIRECT_DEPTH"],
            blacklist_domains=_blacklist_domains(),
            model_path=current_app.config["MODEL_PATH"],
        )
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("main.index"))

    analysis = _persist_analysis(result, session.get("user_id"))
    return render_template("result.html", result=result, analysis=analysis)


@bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session["user_id"] = user.id
            session["role"] = user.role
            return redirect(url_for("main.dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.index"))


@bp.route("/dashboard")
@login_required
def dashboard():
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).limit(20).all()
    chart_labels = [a.created_at.strftime("%Y-%m-%d %H:%M") for a in reversed(analyses)]
    chart_scores = [a.risk_score for a in reversed(analyses)]
    point_count = len(chart_scores)
    points: list[str] = []
    if point_count == 1:
        points = [f"0,{100 - chart_scores[0]}"]
    elif point_count > 1:
        for idx, score in enumerate(chart_scores):
            x = int((idx / (point_count - 1)) * 100)
            y = 100 - score
            points.append(f"{x},{y}")
    return render_template(
        "dashboard.html",
        analyses=analyses,
        chart_labels=chart_labels,
        chart_scores=chart_scores,
        chart_points=" ".join(points),
    )


@bp.route("/reports/export.csv")
@login_required
def export_csv():
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "url", "score", "verdict"])
    for a in analyses:
        writer.writerow([a.created_at.isoformat(), a.url, a.risk_score, a.verdict])
    db.session.add(Report(title="CSV export", content=f"Exported {len(analyses)} analysis rows"))
    db.session.commit()
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=detector-report.csv"},
    )


@bp.route("/reports/export.pdf")
@login_required
def export_pdf():
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).limit(100).all()
    html = render_template("report_pdf.html", analyses=analyses)
    pdf_bytes = HTML(string=html).write_pdf()
    db.session.add(Report(title="PDF export", content=f"Exported {len(analyses)} analysis rows"))
    db.session.commit()
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=detector-report.pdf"},
    )


@bp.route("/api/analyze", methods=["POST"])
@csrf.exempt
@limiter.limit("30/minute")
def api_analyze():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    try:
        result = analyze_url(
            url,
            timeout=current_app.config["REQUEST_TIMEOUT_SECONDS"],
            max_redirect_depth=current_app.config["MAX_REDIRECT_DEPTH"],
            blacklist_domains=_blacklist_domains(),
            model_path=current_app.config["MODEL_PATH"],
        )
    except ValueError:
        return jsonify({"error": "Invalid URL input"}), 400
    except Exception:
        current_app.logger.exception("Unexpected analysis failure")
        return jsonify({"error": "Unable to process the URL"}), 500

    analysis = _persist_analysis(result, session.get("user_id"))
    return jsonify(
        {
            "id": analysis.id,
            "url": result.url,
            "score": result.score,
            "verdict": result.verdict,
            "reasons": result.reasons,
            "features": result.features,
            "redirect_chain": result.redirect_chain,
        }
    )


@bp.route("/api/reports")
@csrf.exempt
@login_required
@limiter.limit("20/minute")
def api_reports():
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).limit(50).all()
    return jsonify(
        [
            {
                "id": a.id,
                "url": a.url,
                "score": a.risk_score,
                "verdict": a.verdict,
                "created_at": a.created_at.isoformat(),
            }
            for a in analyses
        ]
    )


@bp.route("/health")
def health():
    return jsonify({"status": "ok"})


@bp.route("/metrics")
def metrics():
    total = Analysis.query.count()
    high_risk = Analysis.query.filter(Analysis.risk_score >= 70).count()
    return Response(
        f"detector_total_scans {total}\n" f"detector_high_risk_scans {high_risk}\n",
        mimetype="text/plain",
    )


@bp.route("/disclaimer")
def disclaimer():
    return render_template("disclaimer.html")


@bp.route("/privacy")
def privacy():
    return render_template("privacy.html")


@bp.route("/terms")
def terms():
    return render_template("terms.html")
