from __future__ import annotations

from datetime import datetime, timezone

from .extensions import db


def _utcnow():
    return datetime.now(timezone.utc)


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)
    raw_url = db.Column(db.String(2048), nullable=False)
    normalized_url = db.Column(db.String(2048), nullable=False)
    domain = db.Column(db.String(255), index=True, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    label = db.Column(db.String(30), nullable=False)
    reachability = db.Column(db.String(30), default="reachable")
    reasons = db.Column(db.JSON, default=list)
    redirect_chain = db.Column(db.JSON, default=list)
    features_summary = db.Column(db.JSON, default=dict)
    status_code = db.Column(db.Integer, nullable=True)
    error_type = db.Column(db.String(50), nullable=True)
    error_message = db.Column(db.String(255), nullable=True)
    feedback = db.Column(db.String(20), nullable=True)
    feedback_note = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)
