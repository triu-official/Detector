# Deployment

## Recommended path

1. Copy `.env.example` to `.env` and set production secrets.
2. Put the app behind Nginx or another reverse proxy with HTTPS.
3. Set `FLASK_ENV=production` and `SESSION_COOKIE_SECURE=true`.
4. Run `docker compose up --build -d`.
5. Terminate TLS at the reverse proxy and forward traffic to the Flask web service.

## HTTPS

Use Let's Encrypt or another certificate provider at the reverse proxy. Keep HSTS enabled only once HTTPS is live.

## Background work

The compose stack includes a Celery worker container. The app currently runs analysis inline but the worker is ready for future async offloading.
