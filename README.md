# SafeTalk DRP — Backend

**Digital Risk Protection platform for SQB Bank, Uzbekistan.**

SafeTalk DRP is a cybersecurity threat intelligence system that receives flagged SMS and Telegram messages from the SafeTalk on-device ML model, performs AI-powered deep analysis using Google Gemini, captures phishing website screenshots via headless Chromium, and provides a unified dashboard for the bank's security operations team.

## Architecture

| Service | Technology | Port |
|---------|-----------|------|
| API | FastAPI + Uvicorn | 8000 |
| Database | PostgreSQL 16 | 5433 (host) → 5432 (container) |
| Cache & Broker | Redis 7 | 6379 |
| Task Queue | Celery (worker + beat) | — |
| Object Storage | MinIO | 9000 (API), 9001 (Console) |

## Tech Stack

- **Framework:** FastAPI 0.115 with async SQLAlchemy 2.0 + asyncpg
- **AI Analysis:** Google Gemini REST API (configurable, Claude as fallback)
- **Screenshot Capture:** Playwright headless Chromium
- **Task Queue:** Celery with Redis broker
- **Object Storage:** MinIO (S3-compatible) for screenshots
- **PDF Reports:** ReportLab for Central Bank incident reports
- **Scanners:** Domain typosquat, phishing URL, App Store, social media, paste site

## Prerequisites

- Docker & Docker Compose
- (Optional) Google Gemini API key from [aistudio.google.com](https://aistudio.google.com)

## Setup

1. **Clone the repository:**

```bash
git clone https://github.com/hackathon-safe-talk/backend.git
cd backend
```

2. **Create the environment file:**

```bash
cp .env.example .env
```

Edit `.env` and set the required values:

```env
# Required
DATABASE_URL=postgresql+asyncpg://safetalk:safetalk@postgres:5432/safetalk_drp
DATABASE_URL_SYNC=postgresql://safetalk:safetalk@postgres:5432/safetalk_drp
JWT_SECRET=your-secure-random-secret

# AI Provider (gemini or claude)
AI_PROVIDER=gemini
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-2.5-pro

# Optional: Claude fallback
ANTHROPIC_API_KEY=your-anthropic-key
```

3. **Build and start all services:**

```bash
docker compose build
docker compose up -d
```

4. **Verify the API is running:**

```bash
curl http://localhost:8000/health
# {"status":"ok","service":"safetalk-drp"}
```

Swagger documentation is available at **http://localhost:8000/docs**.

## Default Credentials

On first startup, an admin user is automatically seeded:

| User | Email | Password | Role |
|------|-------|----------|------|
| Admin | admin@sqb.uz | SafeTalk2026! | super_admin |
| Analyst | analyst@sqb.uz | Analyst2026! | analyst |

## API Overview

All endpoints are under `/api/v1`. Authentication is via JWT Bearer token.

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/threats/bulk` | X-Device-Id header | Mobile SDK threat ingestion |
| `POST /api/v1/auth/login` | — | Admin login → JWT |
| `POST /api/v1/auth/refresh` | Refresh token | Token refresh |
| `GET /api/v1/threats` | JWT | List threats (paginated, filterable) |
| `GET /api/v1/threats/{id}` | JWT | Threat detail |
| `PATCH /api/v1/threats/{id}` | JWT (analyst+) | Update threat status/tags |
| `POST /api/v1/ai/analyze` | JWT (analyst+) | Trigger Gemini AI analysis |
| `GET /api/v1/dashboard/stats` | JWT | Dashboard statistics |
| `GET /api/v1/dashboard/trends` | JWT | Threat trends |
| `POST /api/v1/screenshots/{url}/check` | JWT | Capture website screenshot |
| `GET /api/v1/scanners/overview` | JWT | Scanner status overview |
| `POST /api/v1/reports/{id}/generate` | JWT | Generate Central Bank PDF report |
| `GET /health` | — | Health check |

## Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── config.py             # Pydantic settings
│   ├── database.py           # Async SQLAlchemy engine
│   ├── deps.py               # Dependency injection (DB, JWT auth)
│   ├── celery_app.py         # Celery configuration
│   ├── models/               # SQLAlchemy ORM models
│   ├── schemas/              # Pydantic request/response schemas
│   ├── routers/              # API route handlers
│   ├── services/             # Business logic layer
│   ├── scanners/             # Scanner modules (domain, phishing, app store, social, paste)
│   └── rules/                # Auto-tagging rules engine
├── alembic/                  # Database migrations
├── scripts/                  # Seed & utility scripts
├── docker-compose.yml        # All services (API, DB, Redis, Celery, MinIO)
├── Dockerfile
├── requirements.txt
└── .env
```

## Useful Commands

```bash
# View API logs
docker compose logs api -f

# Restart API after .env changes
docker compose restart api

# Rebuild after requirements.txt changes
docker compose build --no-cache api celery-worker celery-beat

# Seed demo data
docker compose exec api python -m scripts.seed_demo_data

# Access PostgreSQL
docker compose exec postgres psql -U safetalk -d safetalk_drp

# Access MinIO Console (login: safetalk / safetalk123)
open http://localhost:9001
```

## Team

| Name | Role |
|------|------|
| **Sukhrob Tokhirov** | Backend Developer & Group Leader |
| **Makhmedov Asilkhan** | Data Analyst |
| **Anorov Rasulberdi** | Cyber Security & Developer |
| **Sevinch Abdivaitova** | Communications Manager |

## License

This project was built for the SQB Bank Hackathon 2026.
