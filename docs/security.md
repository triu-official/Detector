# Security

## Implemented controls

- Strict CSP via Flask-Talisman with self-only scripts and styles
- Secure cookies in production, HTTPOnly sessions, SameSite support
- CSRF protection for forms and API requests
- Redis-backed rate limiting for public and admin routes
- Structured request logging plus recent error summaries
- Input normalization and validation before network fetches or blacklist comparisons
- No secrets committed to the repository; use env vars or local `.env`

## Audit workflow

Run:

```bash
./scripts/security-audit.sh
```

That executes pip-audit, Bandit, Ruff, and pytest.
