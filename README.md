# Detector

Production-oriented suspicious website detector built with Flask.

## Features
- URL phishing heuristics (length, subdomains, IP usage, suspicious chars, keywords, shorteners)
- Domain intelligence (WHOIS age and registrar checks)
- Page analysis (forms, iframes, redirects)
- Redirect-chain tracing with loop/depth limits
- Local blacklist checks
- Explainable result reasons + optional ML model (`MODEL_PATH` via joblib)
- Admin dashboard with trend chart + CSV/PDF export
- API endpoints: `/api/analyze`, `/api/reports`
- Health/metrics endpoints: `/health`, `/metrics`
- Security essentials: CSRF, rate limiting, CORS for API, security headers, env-based secrets, ORM-backed persistence
- Legal pages: disclaimer, privacy, terms

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

## Production run
```bash
gunicorn -c gunicorn.conf.py run:app
```

## Docker
```bash
docker compose up --build
```

## Environment variables
- `SECRET_KEY`
- `DATABASE_URL`
- `REDIS_URL`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `POSTGRES_PASSWORD` (required for docker-compose)
- `MODEL_PATH`
- `SENTRY_DSN`
- `CORS_ORIGINS`

## Demo notes
Use `/disclaimer`, `/privacy`, and `/terms` pages for compliance coverage in demos.
Set strong `SECRET_KEY` and `ADMIN_PASSWORD` values before production deployment.
