from __future__ import annotations

import csv
import io

from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required, login_user, logout_user
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash

from app.extensions import db, limiter
from app.forms import BatchUploadForm, BlacklistForm, LoginForm
from app.models import Analysis, Blacklist, Report, db, summary_counts
from app.phishing.heuristics import AnalysisInputError
from app.phishing.services import (
    analyses_to_csv,
    filtered_reports,
    label_counts_by_day,
    recent_analyses,
    run_analysis,
    serialize_analysis,
    top_phishing_domains,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        from app.models import User

        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for("admin.dashboard"))
        flash("Invalid credentials", "error")
    return render_template("admin/login.html", form=form, page_title="Admin login")


@bp.route("/logout")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def logout():
    logout_user()
    return redirect(url_for("phishing.index"))


@bp.route("/")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def dashboard():
    reports = filtered_reports(
        page=max(int(request.args.get("page", 1)), 1),
        per_page=20,
        label=request.args.get("label") or None,
        domain=request.args.get("domain") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
    )
    counts = summary_counts()
    total = sum(counts.values())
    phishing_pct = round((counts.get("phishing", 0) / total) * 100, 1) if total else 0.0
    return render_template(
        "admin/dashboard.html",
        page_title="Admin dashboard",
        reports=reports,
        counts=counts,
        total=total,
        phishing_pct=phishing_pct,
        trends=label_counts_by_day(),
        top_domains=top_phishing_domains(),
        blacklist=Blacklist.query.order_by(Blacklist.created_at.desc()).all(),
        blacklist_form=BlacklistForm(),
        batch_form=BatchUploadForm(),
        recent=recent_analyses(),
    )


@bp.route("/blacklist", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def add_blacklist_entry():
    form = BlacklistForm()
    if form.validate_on_submit():
        domain = form.domain.data.strip().lower()
        entry = Blacklist.query.filter_by(domain=domain).first()
        if entry is None:
            db.session.add(Blacklist(domain=domain, reason=(form.reason.data or "").strip()))
            db.session.commit()
            current_app.logger.info("blacklist_added", extra={"domain": domain, "actor": current_user.username})
            flash("Domain added to blacklist", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/blacklist/<int:entry_id>/delete", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def delete_blacklist_entry(entry_id: int):
    # Use db.get_or_404 — Query.get() is deprecated in SQLAlchemy 2.x
    entry = db.get_or_404(Blacklist, entry_id)
    domain = entry.domain
    db.session.delete(entry)
    db.session.commit()
    current_app.logger.info("blacklist_removed", extra={"domain": domain, "actor": current_user.username})
    flash("Blacklist entry removed", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/batch", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def batch_analyze():
    form = BatchUploadForm()
    if not form.validate_on_submit():
        flash("Upload a CSV file with a url column.", "error")
        return redirect(url_for("admin.dashboard"))

    data = io.StringIO(form.file.data.stream.read().decode("utf-8"))
    reader = csv.DictReader(data)
    rows = []
    max_allowed = min(current_app.config["BATCH_ANALYSIS_LIMIT"], current_app.config["MAX_BATCH_ANALYSIS_LIMIT"])
    for idx, row in enumerate(reader, start=1):
        if idx > max_allowed:
            break
        url = (row.get("url") or "").strip()
        if not url:
            continue
        try:
            result = run_analysis(url, current_app.config)
            analysis = db.session.get(Analysis, result.analysis_id)
            rows.append(serialize_analysis(analysis))
        except (AnalysisInputError, ValueError) as exc:
            current_app.logger.exception("batch_analysis_failed")
            rows.append({"analysis_id": "", "url": url, "risk_score": "", "label": "", "reasons": [str(exc)]})

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["analysis_id", "url", "risk_score", "label", "reasons"])
    for row in rows:
        writer.writerow(
            [
                row.get("analysis_id", ""),
                row.get("url", ""),
                row.get("risk_score", ""),
                row.get("label", ""),
                "; ".join(row.get("reasons", [])),
            ]
        )
    db.session.add(Report(title="Batch CSV analysis", content=f"Processed {len(rows)} URLs"))
    db.session.commit()
    current_app.logger.info("batch_analysis_completed", extra={"count": len(rows), "actor": current_user.username})
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=batch-analysis-results.csv"},
    )


@bp.route("/export.csv")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def export_csv():
    rows = Analysis.query.order_by(Analysis.created_at.desc()).limit(500).all()
    db.session.add(Report(title="CSV export", content=f"Exported {len(rows)} rows"))
    db.session.commit()
    current_app.logger.info("csv_exported", extra={"count": len(rows), "actor": current_user.username})
    return Response(
        analyses_to_csv(rows),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=detector-report.csv"},
    )


@bp.route("/export.pdf")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def export_pdf():
    rows = Analysis.query.order_by(Analysis.created_at.desc()).limit(100).all()
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    _width, height = letter
    y = height - inch
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(inch, y, "Detector Report")
    y -= 0.4 * inch
    pdf.setFont("Helvetica", 10)
    for row in rows:
        # Guard against None created_at to avoid TypeError in f-string formatting
        ts = row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else "N/A"
        line = f"{ts} | {row.label.upper():<10} | {row.risk_score:>3} | {row.domain}"
        pdf.drawString(inch, y, line[:110])
        y -= 0.25 * inch
        if y < inch:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - inch
    pdf.save()
    buffer.seek(0)
    db.session.add(Report(title="PDF export", content=f"Exported {len(rows)} rows"))
    db.session.commit()
    current_app.logger.info("pdf_exported", extra={"count": len(rows), "actor": current_user.username})
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="detector-report.pdf")


@bp.route("/health")
@login_required
@limiter.limit(lambda: current_app.config["ADMIN_RATE_LIMIT"])
def health_page():
    from app import gather_health_snapshot

    return render_template("admin/health.html", health=gather_health_snapshot(), page_title="System health")
