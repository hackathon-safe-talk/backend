"""MinIO object storage service for screenshots and reports."""

import io
import logging
from datetime import timedelta

from minio import Minio
from minio.error import S3Error

from app.config import settings

logger = logging.getLogger(__name__)

_client: Minio | None = None


def get_minio_client() -> Minio:
    global _client
    if _client is None:
        _client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_USE_SSL,
        )
        # Ensure bucket exists
        if not _client.bucket_exists(settings.MINIO_BUCKET):
            _client.make_bucket(settings.MINIO_BUCKET)
            logger.info(f"Created MinIO bucket: {settings.MINIO_BUCKET}")
    return _client


def upload_file(object_name: str, data: bytes, content_type: str = "image/png") -> str:
    """Upload a file to MinIO and return the object name."""
    client = get_minio_client()
    client.put_object(
        settings.MINIO_BUCKET,
        object_name,
        io.BytesIO(data),
        length=len(data),
        content_type=content_type,
    )
    logger.info(f"Uploaded {object_name} to MinIO ({len(data)} bytes)")
    return object_name


def get_presigned_url(object_name: str, expires: int = 3600) -> str:
    """Get a presigned URL for downloading a file.

    When MINIO_PUBLIC_ENDPOINT is set, the internal hostname in the presigned
    URL is replaced so the browser can reach MinIO directly.
    """
    client = get_minio_client()
    url = client.presigned_get_object(
        settings.MINIO_BUCKET,
        object_name,
        expires=timedelta(seconds=expires),
    )
    # Replace internal Docker hostname with public one for the browser
    public = settings.MINIO_PUBLIC_ENDPOINT
    if public and settings.MINIO_ENDPOINT != public:
        url = url.replace(settings.MINIO_ENDPOINT, public, 1)
    return url


def download_file(object_name: str) -> bytes:
    """Download a file from MinIO."""
    client = get_minio_client()
    response = client.get_object(settings.MINIO_BUCKET, object_name)
    data = response.read()
    response.close()
    response.release_conn()
    return data
