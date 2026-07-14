import json
import os
from app import create_app
from app.phishing.services import run_analysis
from app.config import BaseConfig

app = create_app()

def test_url(url):
    with app.app_context():
        # Temporarily mock the db to not save
        res = run_analysis(url, app.config, persist=False)
        print(f"\n--- Results for {url} ---")
        print(f"Risk Score: {res.risk_score}")
        print(f"Label: {res.label}")
        print(f"Reasons: {res.reasons}")

        # Checking compound warnings
        page_signals = res.features_summary.get("page_signals", {})
        binary = page_signals.get("binary_response", 0.0)
        print(f"Binary Payload Detected: {bool(binary)}")
        print(f"Domain age buckets UI variable: {res.features_summary.get('domain_info', {}).get('domain_age_bucket')}")

test_url("http://tatabook.club")
