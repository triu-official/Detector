from app.analyzer import analyze_url, extract_url_features, validate_url


def test_validate_url_rejects_non_http():
    ok, msg = validate_url("ftp://example.com")
    assert ok is False
    assert "http/https" in msg


def test_extract_url_features_detects_keywords_and_ip():
    features, reasons = extract_url_features("http://192.168.1.1/login/verify-account")
    assert features["has_ip"] == 1.0
    assert features["keyword_hits"] >= 1
    assert reasons


def test_analyze_url_generates_score_and_verdict():
    result = analyze_url(
        "https://example.com",
        timeout=1,
        max_redirect_depth=2,
        blacklist_domains=set(),
        model_path="",
    )
    assert 0 <= result.score <= 100
    assert result.verdict in {"likely-safe", "suspicious", "high-risk"}
