from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import joblib

FEATURE_ORDER = [
    'url_length',
    'subdomain_count',
    'has_ip',
    'suspicious_chars',
    'keyword_hits',
    'is_shortener',
    'phishing_tld',
    'uses_https',
    'domain_age_days',
    'form_count',
    'password_fields',
    'iframe_count',
    'external_form_action',
    'external_script_count',
    'redirect_count',
    'blacklisted',
]


@lru_cache(maxsize=1)
def load_model(path: str) -> Any | None:
    if not path or not os.path.exists(path):
        return None
    try:
        return joblib.load(path)
    except Exception:
        return None



def predict(features: dict[str, float], model_path: str) -> tuple[float | None, str | None]:
    model = load_model(model_path)
    if model is None:
        return None, None
    ordered = [float(features.get(name, 0.0)) for name in FEATURE_ORDER]
    try:
        if hasattr(model, 'predict_proba'):
            probability = float(model.predict_proba([ordered])[0][1])
            return probability * 100.0, 'ML probability score blended with heuristic score'
    except Exception:
        return None, None
    return None, None
