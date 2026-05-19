# Docker Setup

Start all services:

```powershell
docker compose up --build
```

Apply migrations inside the backend container:

```powershell
docker compose exec backend alembic upgrade head
```

Useful URLs:

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- PostgreSQL: `localhost:5432`

