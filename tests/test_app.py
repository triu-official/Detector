from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import Analysis, Blacklist, User
from app.phishing.services import AnalysisResult


class AppConfig(TestingConfig):
    SECRET_KEY = "test"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"


def make_result(url="https://example.com", label="safe", score=18, analysis_id=1):
    return AnalysisResult(
        raw_url=url,
        normalized_url=url,
        domain="example.com",
        url_hash="hash",
        risk_score=score,
        label=label,
        reasons=["No major indicators"],
        reachability="reachable",
        redirect_chain=[url],
        status_code=200,
        features_summary={"feature_counts": {"url_length": 18.0, "blacklisted": 0.0}},
        explanations=[{"code": "no_major_indicators", "message": "No major indicators"}],
        confidence=0.8,
        model_metadata={"enabled": False, "used": False, "source": "heuristic", "model_name": ""},
        cache_hit=False,
        latency_ms=10,
        analysis_id=analysis_id,
    )


def create_client():
    app = create_app(AppConfig)
    with app.app_context():
        db.drop_all()
        db.create_all()
        User.ensure_from_password(AppConfig.ADMIN_USERNAME, AppConfig.ADMIN_PASSWORD)
    return app, app.test_client()


def test_health_endpoint_returns_detailed_status():
    app, client = create_client()
    response = client.get("/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] in {"ok", "degraded"}
    assert "database" in body
    assert "redis" in body


def test_api_analyze_bad_url_returns_400():
    app, client = create_client()
    response = client.post("/api/analyze", json={"url": "ftp://bad"})
    assert response.status_code == 400
    assert response.get_json()["error"]["type"] == "invalid_url"


def test_api_analyze_success_returns_saved_analysis(monkeypatch):
    app, client = create_client()

    def fake_run_analysis(_url, _config):
        with app.app_context():
            analysis = Analysis(
                url_hash="hash",
                raw_url="https://example.com",
                normalized_url="https://example.com",
                domain="example.com",
                risk_score=18,
                label="safe",
                reachability="reachable",
                reasons=["No major indicators"],
                redirect_chain=["https://example.com"],
                features_summary={"feature_counts": {"url_length": 18.0}},
                status_code=200,
                latency_ms=5,
            )
            db.session.add(analysis)
            db.session.commit()
            return make_result(analysis_id=analysis.id)

    monkeypatch.setattr("app.phishing.routes.run_analysis", fake_run_analysis)
    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["label"] == "safe"
    assert body["analysis_id"] >= 1


def test_admin_login_and_dashboard(monkeypatch):
    app, client = create_client()
    response = client.post("/admin/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Total analyses" in response.data


def test_admin_blacklist_add_and_delete():
    app, client = create_client()
    client.post("/admin/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
    add_response = client.post(
        "/admin/blacklist",
        data={"domain": "blocked.example", "reason": "test"},
        follow_redirects=True,
    )
    assert add_response.status_code == 200
    with app.app_context():
        entry = Blacklist.query.filter_by(domain="blocked.example").first()
        assert entry is not None
        delete_response = client.post(f"/admin/blacklist/{entry.id}/delete", follow_redirects=True)
        assert delete_response.status_code == 200
        assert Blacklist.query.filter_by(domain="blocked.example").first() is None


def test_manifest_and_service_worker_routes():
    _app, client = create_client()
    manifest = client.get("/manifest.json")
    worker = client.get("/sw.js")
    assert manifest.status_code == 200
    assert worker.status_code == 200
    assert b"Detector PWA" in manifest.data
    assert b"CACHE_NAME" in worker.data


def test_api_analyze_async_returns_queued(monkeypatch):
    _app, client = create_client()

    class DummyTaskResult:
        id = "job-123"

    monkeypatch.setattr("app.celery_app.analyze_url_task.delay", lambda _url: DummyTaskResult())
    response = client.post("/api/analyze/async", json={"url": "https://example.com"})
    assert response.status_code == 202
    body = response.get_json()
    assert body["status"] == "queued"
    assert body["job_id"] == "job-123"


def test_api_job_status_completed_returns_result(monkeypatch):
    app, client = create_client()
    with app.app_context():
        analysis = Analysis(
            url_hash="hash",
            raw_url="https://example.com",
            normalized_url="https://example.com",
            domain="example.com",
            risk_score=18,
            label="safe",
            reachability="reachable",
            reasons=["No major indicators"],
            redirect_chain=["https://example.com"],
            features_summary={"feature_counts": {"url_length": 18.0}, "confidence": 0.8, "model": {}},
            status_code=200,
            latency_ms=5,
        )
        db.session.add(analysis)
        db.session.commit()
        analysis_id = analysis.id

    class DummyState:
        state = "SUCCESS"
        result = {"analysis_id": analysis_id}

    monkeypatch.setattr("app.celery_app.get_job_state", lambda _job_id: DummyState())
    response = client.get("/api/jobs/job-123")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "completed"
    assert body["result"]["analysis_id"] == analysis_id
