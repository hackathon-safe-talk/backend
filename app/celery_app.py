from celery import Celery
from celery.schedules import crontab
from app.config import settings

celery = Celery(
    "safetalk_drp",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.scanners.domain_scanner",
        "app.scanners.phishing_scanner",
        "app.scanners.app_store_scanner",
        "app.scanners.social_scanner",
        "app.scanners.paste_scanner",
    ]
)

celery.conf.beat_schedule = {
    "scan-domains-every-30min": {
        "task": "app.scanners.domain_scanner.run_domain_scan",
        "schedule": 30 * 60,
    },
    "scan-phishing-feeds-every-15min": {
        "task": "app.scanners.phishing_scanner.run_phishing_scan",
        "schedule": 15 * 60,
    },
    "scan-app-stores-every-2h": {
        "task": "app.scanners.app_store_scanner.run_app_store_scan",
        "schedule": 2 * 60 * 60,
    },
    "scan-social-every-1h": {
        "task": "app.scanners.social_scanner.run_social_scan",
        "schedule": 60 * 60,
    },
    "scan-pastes-every-3h": {
        "task": "app.scanners.paste_scanner.run_paste_scan",
        "schedule": 3 * 60 * 60,
    },
}

celery.conf.timezone = "Asia/Tashkent"
