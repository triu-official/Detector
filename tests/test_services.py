from app.phishing.heuristics import ReachabilityError
from app.phishing.services import fetch_page, run_analysis


class DummyResponse:
    def __init__(self, url, status_code=200, headers=None, text="<html></html>", is_redirect=False):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.is_redirect = is_redirect
        self.is_permanent_redirect = is_redirect


class DummySession:
    def __init__(self, responses):
        self._responses = list(responses)

    def get(self, *_args, **_kwargs):
        return self._responses.pop(0)


def test_fetch_page_blocks_redirect_to_localhost(monkeypatch):
    redirect = DummyResponse(
        "https://example.com",
        status_code=302,
        headers={"Location": "http://127.0.0.1/admin"},
        is_redirect=True,
    )
    monkeypatch.setattr("app.phishing.services._build_session", lambda: DummySession([redirect]))
    try:
        fetch_page("https://example.com", timeout=1, max_redirect_depth=5, retry_count=0)
    except ReachabilityError as exc:
        assert exc.error_type == "blocked_redirect"
    else:
        raise AssertionError("Expected blocked_redirect error")


def test_run_analysis_includes_confidence_and_model_metadata(monkeypatch):
    page_result = type(
        "PageResult",
        (),
        {
            "reasons": [],
            "reachability": "reachable",
            "redirect_chain": ["https://example.com"],
            "response": type("R", (), {"status_code": 200})(),
            "error_type": None,
            "error_message": None,
        },
    )()
    monkeypatch.setattr(
        "app.phishing.services.analyze_page",
        lambda *_args, **_kwargs: (
            {
                "form_count": 0.0,
                "password_fields": 0.0,
                "iframe_count": 0.0,
                "external_form_action": 0.0,
                "external_script_count": 0.0,
                "redirect_count": 0.0,
            },
            page_result,
        ),
    )
    monkeypatch.setattr(
        "app.phishing.services.get_domain_intelligence",
        lambda *_args, **_kwargs: ({"domain_age_days": 365}, []),
    )
    monkeypatch.setattr("app.phishing.services.blacklist_lookup", lambda _domain: (False, None))
    monkeypatch.setattr("app.phishing.services._threat_intel_hit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "app.phishing.services.predict",
        lambda *_args, **_kwargs: (72.0, "ML probability score blended with heuristic score"),
    )
    config = {
        "REQUEST_TIMEOUT_SECONDS": 1,
        "MAX_REQUEST_TIMEOUT_SECONDS": 5,
        "REQUEST_RETRY_COUNT": 0,
        "MAX_REQUEST_RETRY_COUNT": 1,
        "MAX_REDIRECT_DEPTH": 3,
        "DOMAIN_CACHE_TTL_SECONDS": 60,
        "NEW_DOMAIN_DAYS": 7,
        "YOUNG_DOMAIN_DAYS": 30,
        "SAFE_THRESHOLD": 30,
        "SUSPICIOUS_THRESHOLD": 60,
        "PHISHING_THRESHOLD": 80,
        "NEW_DOMAIN_PENALTY": 20,
        "YOUNG_DOMAIN_PENALTY": 10,
        "HEURISTIC_BLEND_WEIGHT": 0.6,
        "ML_BLEND_WEIGHT": 0.4,
        "MODEL_PATH": "/tmp/mock-model.joblib",
        "RESULT_CACHE_TTL_SECONDS": 60,
        "THREAT_INTEL_STATIC_DOMAINS": "",
    }
    result = run_analysis("https://example.com", config, persist=False)
    assert 0.35 <= result.confidence <= 0.98
    assert result.model_metadata["source"] in {"heuristic", "hybrid"}
    assert isinstance(result.explanations, list)
