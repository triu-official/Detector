# Detector

Local-first suspicious website detector built as a Flask backend with an installable PWA frontend.

Analyzes URLs using local heuristics (URL patterns, domain age, brand impersonation, content signals) with optional enrichment from VirusTotal, Google Safe Browsing, urlscan.io, and AbuseIPDB. No paid AI dependency.

## Quick start

```bash
cp .env.example .env
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
python run.py
```

The app runs at http://127.0.0.1:5000

## How it works

1. Enter a URL in the search bar
2. The app fetches the page, parses content, and scores it against local heuristic rules
3. Optional external APIs enrich the analysis when keys are configured
4. A full report with score breakdown, signals, and enrichment results is displayed

## Environment variables

All variables have sensible local defaults. Only `SECRET_KEY` should be changed for production.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | random | Flask session and CSRF secret |
| `DATABASE_URL` | sqlite | SQLAlchemy connection string |
| `ANALYZE_RATE_LIMIT` | 30/hour | Public analyze rate limit |
| `SUSPICIOUS_THRESHOLD` | 25 | Score >= this = suspicious |
| `PHISHING_THRESHOLD` | 50 | Score >= this = phishing |
| `VT_ENABLED` | false | Enable VirusTotal enrichment |
| `VT_API_KEY` | empty | VirusTotal API key |
| `SAFEBROWSING_API_KEY` | empty | Google Safe Browsing API key |
| `URLSCAN_API_KEY` | empty | urlscan.io API key |
| `ABUSEIPDB_API_KEY` | empty | AbuseIPDB API key |

## Optional enrichment APIs

All external APIs are optional. If a key is not set, that enrichment is silently skipped. The core local analysis always runs.

| API | What it adds | Free tier |
| --- | --- | --- |
| VirusTotal | Multi-engine URL reputation | ~4 req/min |
| Google Safe Browsing | Known unsafe URL list | Non-commercial free |
| urlscan.io | Live page scan and capture | Free tier available |
| AbuseIPDB | IP abuse reputation | ~1000 checks/day |

## Running checks

```bash
python -m ruff check .
```

## License

Internal project.
