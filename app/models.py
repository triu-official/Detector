from __future__ import annotations

from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import func
from werkzeug.security import generate_password_hash

from .extensions import db


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='admin', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    @classmethod
    def sync_admin_user(cls, username: str, password_hash: str) -> None:
        existing = cls.query.filter_by(username=username).first()
        if existing:
            if existing.password_hash != password_hash:
                existing.password_hash = password_hash
                db.session.commit()
            return
        db.session.add(cls(username=username, password_hash=password_hash, role='admin'))
        db.session.commit()

    @classmethod
    def ensure_from_password(cls, username: str, password: str) -> None:
        cls.sync_admin_user(username, generate_password_hash(password))


class Analysis(db.Model):
    __tablename__ = 'analyses'

    id = db.Column(db.Integer, primary_key=True)
    url_hash = db.Column(db.String(64), index=True, nullable=False)
    raw_url = db.Column(db.String(2048), nullable=False)
    normalized_url = db.Column(db.String(2048), nullable=False)
    domain = db.Column(db.String(255), index=True, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    label = db.Column(db.String(30), index=True, nullable=False)
    reachability = db.Column(db.String(30), default='reachable', nullable=False)
    reasons = db.Column(db.JSON, default=list, nullable=False)
    redirect_chain = db.Column(db.JSON, default=list, nullable=False)
    features_summary = db.Column(db.JSON, default=dict, nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    error_type = db.Column(db.String(50), nullable=True)
    error_message = db.Column(db.String(255), nullable=True)
    cache_hit = db.Column(db.Boolean, default=False, nullable=False)
    latency_ms = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Blacklist(db.Model):
    __tablename__ = 'blacklists'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    reason = db.Column(db.String(500), default='', nullable=False)
    source = db.Column(db.String(255), default='manual', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Feedback(db.Model):
    __tablename__ = 'feedback'

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False)
    message = db.Column(db.String(255), default='This result seems wrong', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class RequestLog(db.Model):
    __tablename__ = 'request_logs'

    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    duration_ms = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)



def summary_counts() -> dict[str, int]:
    return {
        row[0]: row[1]
        for row in db.session.query(Analysis.label, func.count(Analysis.id)).group_by(Analysis.label).all()
    }
