# Developer Setup

## Prerequisites

- Python 3.12+
- Node.js 22+
- Docker Desktop
- PostgreSQL, if running without Docker

## Backend Workflow

```powershell
cd backend
Copy-Item .env.example .env
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Run checks:

```powershell
python -m compileall app
```

## Frontend Workflow

```powershell
cd frontend
npm install
npm run dev
npm run build
```

## Scanning Scope

`ALLOWED_TARGET_HOSTS` is intentionally restrictive. Add only lab targets or systems where you have explicit permission.

