from __future__ import annotations

from app.phishing.heuristics import extract_url_features, validate_url
from app.phishing.services import run_analysis


class _CompatConfig(dict):
    def __init__(self, *, timeout: int, max_redirect_depth: int, model_path: str):
        super().__init__(
            REQUEST_TIMEOUT_SECONDS=timeout,
            REQUEST_RETRY_COUNT=0,
            MAX_REDIRECT_DEPTH=max_redirect_depth,
            RESULT_CACHE_TTL_SECONDS=0,
            DOMAIN_CACHE_TTL_SECONDS=0,
            MODEL_PATH=model_path,
            SAFE_THRESHOLD=30,
            SUSPICIOUS_THRESHOLD=60,
            PHISHING_THRESHOLD=80,
        )



def analyze_url(url: str, timeout: int, max_redirect_depth: int, blacklist_domains: set[str], model_path: str = ''):
    result = run_analysis(
        url,
        _CompatConfig(timeout=timeout, max_redirect_depth=max_redirect_depth, model_path=model_path),
        persist=False,
    )
    if result.domain in blacklist_domains:
        result.features_summary['feature_counts']['blacklisted'] = 1.0
    return type(
        'AnalysisResult',
        (),
        {
            'url': result.normalized_url,
            'score': result.risk_score,
            'verdict': result.label,
            'reasons': result.reasons,
            'features': result.features_summary['feature_counts'],
            'redirect_chain': result.redirect_chain,
        },
    )()
