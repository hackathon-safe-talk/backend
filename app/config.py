from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://safetalk:safetalk@localhost:5432/safetalk_drp"
    DATABASE_URL_SYNC: str = "postgresql+psycopg://safetalk:safetalk@localhost:5432/safetalk_drp"

    # JWT
    JWT_SECRET: str = "change-me-in-production-use-a-real-secret"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # AI provider: "gemini" or "claude"
    AI_PROVIDER: str = "gemini"

    # Claude AI (used when AI_PROVIDER=claude)
    ANTHROPIC_API_KEY: str = ""

    # Gemini (used when AI_PROVIDER=gemini) — uses REST API, no gRPC
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"

    # MinIO
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_PUBLIC_ENDPOINT: str = ""  # browser-reachable host, e.g. "localhost:9000"
    MINIO_ACCESS_KEY: str = "safetalk"
    MINIO_SECRET_KEY: str = "safetalk123"
    MINIO_BUCKET: str = "screenshots"
    MINIO_USE_SSL: bool = False

    # SMTP (for Central Bank reports)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    CB_EMAIL: str = "cybersecurity@cbu.uz"

    # App
    APP_NAME: str = "SafeTalk DRP"
    DEBUG: bool = True
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173", "https://uneccentrically-flagrant-nelson.ngrok-free.dev"]

    model_config = {"env_file": ".env"}


settings = Settings()
