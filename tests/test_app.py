from app import create_app


class TestConfig:
    TESTING = True
    SECRET_KEY = "test"
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RATELIMIT_ENABLED = False
    REQUEST_TIMEOUT_SECONDS = 1
    MAX_REDIRECT_DEPTH = 2
    MODEL_PATH = ""
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"
    CORS_ORIGINS = "*"


def test_health_endpoint():
    app = create_app(TestConfig)
    client = app.test_client()

    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_api_analyze_bad_url_returns_400():
    app = create_app(TestConfig)
    client = app.test_client()

    response = client.post("/api/analyze", json={"url": "invalid-url"})
    assert response.status_code == 400
