# SafeTalk DRP Backend

Digital Risk Protection backend API for the SafeTalk mobile SDK. Receives threat data from Android devices, provides rule-based auto-tagging, Claude AI analysis, and a REST API for the bank admin dashboard.

## Quick Start

```bash
# Copy env and set your keys
cp .env.example .env

# Start PostgreSQL + API
docker compose up --build

# Seed demo data (run once)
docker compose exec api python -m scripts.seed_demo_data
```

The API is at **http://localhost:8000** and Swagger docs at **http://localhost:8000/docs**.

## Default Credentials

| User | Email | Password | Role |
|------|-------|----------|------|
| Admin | admin@sqb.uz | SafeTalk2026! | super_admin |
| Analyst | analyst@sqb.uz | Analyst2026! | analyst |

## API Overview

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/threats/bulk` | X-Device-Id header | Mobile app threat ingestion |
| `POST /api/v1/auth/login` | None | Admin login → JWT |
| `GET /api/v1/threats` | JWT | List/filter threats |
| `PATCH /api/v1/threats/{id}` | JWT (analyst+) | Update threat status/tags |
| `POST /api/v1/ai/analyze` | JWT (analyst+) | Trigger Claude AI analysis |
| `GET /api/v1/dashboard/stats` | JWT | Dashboard statistics |
| `GET /api/v1/dashboard/trends` | JWT | Threat trends (last 30 days) |

Full Swagger documentation available at `/docs`.
