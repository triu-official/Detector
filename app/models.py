from datetime import datetime
from werkzeug.security import generate_password_hash

from .extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="viewer", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    @classmethod
    def create_admin_if_missing(cls, username: str, password: str) -> None:
        existing = cls.query.filter_by(username=username).first()
        if existing:
            return
        db.session.add(
            cls(
                username=username,
                password_hash=generate_password_hash(password),
                role="admin",
            )
        )
        db.session.commit()


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(30), nullable=False)
    reasons = db.Column(db.Text, nullable=False)
    redirect_chain = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class History(db.Model):
    __tablename__ = "history"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analyses.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Blacklist(db.Model):
    __tablename__ = "blacklists"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    source = db.Column(db.String(255), default="manual", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
