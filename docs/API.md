# API Guide

Base URL: `http://localhost:8000/api/v1`

## Authentication

- `POST /auth/register` creates a user with `email`, `full_name`, `password`, and `role`.
- `POST /auth/login` returns a bearer token.
- `GET /auth/me` returns the active authenticated user.

Include the token as:

```http
Authorization: Bearer <token>
```

## Scans

- `POST /scans` queues and starts a scan.
- `GET /scans` lists scans for the current user.
- `GET /scans/{scan_id}` returns scan status and risk score.
- `GET /scans/{scan_id}/vulnerabilities` returns findings.
- `GET /scans/{scan_id}/logs` returns structured scan logs.
- `WS /scans/{scan_id}/ws` streams progress messages.

Example scan request:

```json
{
  "target_url": "http://localhost:5000/search?q=test",
  "max_depth": 2,
  "respect_robots": true
}
```

## Dashboard

- `GET /dashboard/stats` returns total scans, vulnerability count, active scans, and recent activity.

