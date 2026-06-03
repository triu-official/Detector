# Detector

Production-ready suspicious website detector built as a Flask backend with an installable PWA frontend.

## Quick start

```bash
cp .env.example .env
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

## Docker quick start

```bash
docker compose up --build
```

## Default local admin credentials

- Username: `admin`
- Password: value from `ADMIN_PASSWORD` in `.env`

Change these before production use, or set `ADMIN_PASSWORD_HASH` instead.

## Access URLs

- App: http://localhost:5000
- Admin dashboard: http://localhost:5000/admin
- Health: http://localhost:5000/health
- Metrics: http://localhost:5000/metrics

## Environment variables

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Flask session and CSRF secret |
| `DATABASE_URL` | SQLAlchemy connection string |
| `REDIS_URL` | Redis cache and Celery broker URL |
| `ADMIN_USERNAME` | Admin account username |
| `ADMIN_PASSWORD` | Local/dev admin password |
| `ADMIN_PASSWORD_HASH` | Preferred production password hash |
| `MODEL_PATH` | Optional joblib model path |
| `SENTRY_DSN` | Optional Sentry DSN |
| `ANALYZE_RATE_LIMIT` | Public analyze rate limit |
| `ADMIN_RATE_LIMIT` | Admin route rate limit |
| `REPORTS_RATE_LIMIT` | Public reports/export rate limit |
| `SAFE_THRESHOLD` | Safe label threshold |
| `SUSPICIOUS_THRESHOLD` | Suspicious label threshold |
| `PHISHING_THRESHOLD` | Phishing label threshold |
| `NEW_DOMAIN_DAYS` | Day threshold for a very new domain |
| `YOUNG_DOMAIN_DAYS` | Day threshold for a recently registered domain |
| `NEW_DOMAIN_PENALTY` | Score penalty for very new domains |
| `YOUNG_DOMAIN_PENALTY` | Score penalty for recently registered domains |
| `HEURISTIC_BLEND_WEIGHT` | Weight applied to rule-based scoring when ML is enabled |
| `ML_BLEND_WEIGHT` | Weight applied to model scoring when ML is enabled |

## Running tests and checks

```bash
python -m pytest -q
python -m bandit -q -r app
python -m pip_audit -r requirements.txt --ignore-vuln GHSA-gc5v-m9x4-r6x2 --ignore-vuln PYSEC-2024-277
python -m ruff check .
```

Or run:

```bash
./scripts/security-audit.sh
```

## Model integration

Point `MODEL_PATH` at a joblib-serialized classifier that exposes `predict_proba`. The app blends heuristic scoring with the model probability when available.

## Security scan note

`pip-audit` is configured to ignore `GHSA-gc5v-m9x4-r6x2` (`requests`) and `PYSEC-2024-277` (`joblib`) because pip-audit currently reports them without a practical drop-in fixed release for this stack. Keep reviewing upstream fixes and remove the ignores once safe versions are available.

## Migrations

The app is wired with Flask-Migrate/Alembic-ready configuration. For a first migration workflow:

```bash
flask db init
flask db migrate -m "initial schema"
flask db upgrade
```

Do not rely on runtime `db.create_all()` in production; run `flask db upgrade` during deploy/startup.

## Async scan workflow

- `POST /api/analyze/async` enqueues a Celery job and returns `job_id`.
- `GET /api/jobs/<job_id>` returns queued/running/completed/failed status.
- Frontend polling now uses the async API by default.

## Documentation

- `docs/architecture.md`
- `docs/deployment.md`
- `docs/security.md`
- `docs/api.md`
