from app.phishing.heuristics import extract_url_features, normalize_url, validate_url


def test_normalize_url_accepts_domain_only_input():
    assert normalize_url('example.com') == 'https://example.com'



def test_validate_url_rejects_non_http_scheme():
    ok, message = validate_url('ftp://example.com')
    assert ok is False
    assert 'http/https' in message



def test_extract_url_features_detects_keywords_and_ip():
    features, reasons = extract_url_features('http://192.168.1.1/login/verify-account')
    assert features['has_ip'] == 1.0
    assert features['keyword_hits'] >= 1
    assert any('IP address' in reason or 'phishing keywords' in reason for reason in reasons)
