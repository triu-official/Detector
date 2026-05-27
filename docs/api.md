# API

## `POST /api/analyze`

Request:

```json
{"url": "https://example.com"}
```

Success response fields:

- `analysis_id`
- `url`
- `domain`
- `risk_score`
- `label`
- `reasons`
- `reachability`
- `redirect_chain`
- `features_summary`
- `status_code`
- `cache_hit`

Validation failure returns:

```json
{"error": {"type": "invalid_url", "message": "Only http/https URLs are allowed"}}
```

## `GET /api/reports`

Supports `page`, `per_page`, `label`, `domain`, `date_from`, `date_to`.

## `GET /api/export/json`

Returns filtered analyses in a JSON envelope.

## `GET /health`

Returns database, Redis, and model health details.

## `GET /metrics`

Prometheus-style counters for total analyses, label counts, and average latency.
