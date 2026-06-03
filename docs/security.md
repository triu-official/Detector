# Security

## Implemented controls

- Strict CSP via Flask-Talisman with self-only scripts and styles
- Secure cookies in production, HTTPOnly sessions, SameSite support
- CSRF protection for forms and API requests
- Redis-backed rate limiting for public and admin routes
- Structured request logging plus recent error summaries
- Input normalization and validation before network fetches or blacklist comparisons
- Redirect target validation to block private/local-network pivots during outbound fetches
- Operational caps for timeout/retry/batch sizes and periodic retention cleanup for request logs/reports
- No secrets committed to the repository; use env vars or local `.env`

## Audit workflow

Run:

```bash
./scripts/security-audit.sh
```

That executes pip-audit, Bandit, Ruff, and pytest via `python -m`.

At the moment the pip-audit command explicitly ignores `GHSA-gc5v-m9x4-r6x2` (`requests`) and `PYSEC-2024-277` (`joblib`) because the advisory database flags them without a practical fixed replacement for this stack yet. Revisit those ignores regularly.
