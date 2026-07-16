import json
import os
import time
from app import create_app
from app.phishing.services import run_analysis
from app.config import BaseConfig

app = create_app()

def verify_url(url):
    with app.app_context():
        start_time = time.perf_counter()
        res = run_analysis(url, app.config, persist=True)
        duration = time.perf_counter() - start_time
        
        print(f"\n==================================================")
        print(f"VERIFICATION FOR: {url} (Took {duration:.2f}s)")
        print(f"==================================================")
        print(f"Final Unified Risk Score: {res.risk_score}/100 ({res.label.upper()})")
        
        fusion = res.features_summary.get("page_signals", {}).get("fusion_assessment", {})
        if fusion:
            print(f"  - Local Risk Score: {fusion.get('local_risk_score')}")
            print(f"  - Domain Risk Score: {fusion.get('domain_risk_score')}")
            print(f"  - External Threat Score: {fusion.get('external_risk_score')}")
            print(f"  - Positive Trust Offset: -{fusion.get('positive_trust_offset')}")
            print(f"  - Confidence Level: {fusion.get('confidence_level').upper()} ({fusion.get('confidence_reason')})")
            
            print(f"\nContributing Factors:")
            for f in fusion.get("contributing_factors", []):
                print(f"  [+] {f}")
                
            print(f"\nMitigating Factors:")
            for m in fusion.get("mitigating_factors", []):
                print(f"  [-] {m}")
        else:
            print("  Warning: No fusion assessment available in features_summary.")
        print(f"==================================================\n")

if __name__ == "__main__":
    # Test benign domain (Google)
    print("--- FIRST RUN (Should hit APIs and take time) ---")
    verify_url("https://www.google.com")
    verify_url("http://tanishq777.club")
    
    print("--- SECOND RUN (Should hit cache and be instant) ---")
    verify_url("https://www.google.com")
    verify_url("http://tanishq777.club")
