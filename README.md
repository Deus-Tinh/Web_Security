# SentinelAI Security Scanner

SentinelAI is a production-inspired, AI-ready automated web vulnerability scanner built for authorized educational testing and portfolio demonstration. It combines a FastAPI backend, async crawler, custom detection engine, PostgreSQL persistence, realtime WebSocket scan updates, report generation, and a modern React security operations dashboard.

The original coursework lab is preserved in `lab_appsec/`. The new enterprise-style platform lives in `backend/`, `frontend/`, `docker/`, `docs/`, and `scripts/`.

## Features

- JWT authentication with Admin and Analyst roles
- Async crawler for links, forms, parameters, and login-page discovery
- SQL injection checks: error-based, response differential, and time-delay heuristics
- Reflected XSS checks with Playwright-ready browser validation hooks
- Security header analyzer for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy
- Sensitive path discovery using a focused wordlist
- AI analysis adapter for severity, risk explanation, and remediation enrichment
- PostgreSQL schema with SQLAlchemy models and Alembic migration
- JSON and PDF report generation
- Realtime scan progress and logs over WebSockets
- Dark cybersecurity React dashboard with charts, loading states, empty states, and responsive pages
- Docker Compose setup for backend, frontend, and Postgres

## Project Structure

```text
backend/
  app/
    api/           FastAPI routers and dependencies
    core/          settings, JWT, logging, security helpers
    crawler/       async crawler and discovery models
    database/      async SQLAlchemy session
    models/        users, scans, vulnerabilities, logs, reports
    reports/       report-related extension point
    scanners/      SQLi, XSS, headers, directory discovery
    schemas/       Pydantic request/response models
    services/      orchestration, auth, AI analysis, WebSockets
  alembic/         database migrations
frontend/
  src/
    components/    reusable UI components
    layouts/       auth and app layouts
    pages/         landing, auth, dashboard, scan, report, settings
    services/      API client
docker/
docs/
scripts/
```

## Quick Start With Docker

```powershell
Copy-Item backend\.env.example backend\.env
docker compose up --build
```

Open:

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

By default, scans are restricted to `localhost` and `127.0.0.1`. Update `ALLOWED_TARGET_HOSTS` only for systems you own or are explicitly authorized to test.

## Local Development

Backend:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

## Security Notice

This scanner is designed for authorized lab and portfolio use. Do not scan third-party systems without written permission. Keep secrets in `.env`, rotate `JWT_SECRET_KEY` in real deployments, and scope `ALLOWED_TARGET_HOSTS` tightly.

