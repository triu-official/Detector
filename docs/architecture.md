# Architecture

Detector uses a Flask application factory, SQLAlchemy models, Redis-backed caching, and a PWA shell served from server-rendered templates.

## Flow

1. The browser submits a URL from the PWA shell.
2. `/api/analyze` validates and normalizes the input.
3. Heuristics, page fetch analysis, WHOIS enrichment, blacklist checks, and optional ML inference produce a score and label.
4. Results are cached in Redis and persisted in PostgreSQL/SQLite.
5. Admin pages surface metrics, blacklist controls, exports, and batch analysis.

## Components

- `app/phishing/heuristics.py`: normalization, validation, static URL signals, WHOIS lookup
- `app/phishing/services.py`: page fetch, caching, scoring, persistence, analytics helpers
- `app/phishing/ml_model.py`: joblib inference wrapper
- `app/admin/routes.py`: dashboard, auth, exports, health, batch upload
- `app/static/sw.js`: offline shell + result-page cache
