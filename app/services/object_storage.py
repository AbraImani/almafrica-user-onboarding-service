"""Private MinIO object storage for profile images."""

from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
from urllib.parse import urlsplit

from minio import Minio

from app.core.config import Settings, get_settings


class ObjectStorageError(Exception):
    """Raised when the private object store cannot complete an operation."""


@dataclass(frozen=True)
class StoredObject:
    """Downloaded private object data and its persisted media type."""

    data: bytes
    content_type: str


class ObjectStorageService:
    """Small MinIO adapter scoped to one private profile-image bucket."""

    def __init__(self, settings: Settings) -> None:
        endpoint, secure = self._parse_endpoint(settings.minio_endpoint)
        self._bucket_name = settings.minio_bucket_name
        self._client = Minio(
            endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key.get_secret_value(),
            secure=secure,
        )

    def ensure_bucket_exists(self) -> None:
        """Create the private bucket when it does not already exist."""
        try:
            if not self._client.bucket_exists(self._bucket_name):
                self._client.make_bucket(self._bucket_name)
        except Exception as exc:
            raise ObjectStorageError("Unable to prepare object storage") from exc

    def upload_object(self, key: str, data: bytes, content_type: str) -> None:
        """Upload a complete in-memory object under an application-generated key."""
        self.ensure_bucket_exists()
        try:
            self._client.put_object(
                self._bucket_name,
                key,
                BytesIO(data),
                length=len(data),
                content_type=content_type,
            )
        except Exception as exc:
            raise ObjectStorageError("Unable to upload object") from exc

    def delete_object(self, key: str) -> None:
        """Delete an object from the private bucket."""
        try:
            self._client.remove_object(self._bucket_name, key)
        except Exception as exc:
            raise ObjectStorageError("Unable to delete object") from exc

    def get_object(self, key: str) -> StoredObject:
        """Download an object for authenticated application delivery."""
        response = None
        try:
            response = self._client.get_object(self._bucket_name, key)
            return StoredObject(
                data=response.read(),
                content_type=response.headers.get(
                    "content-type", "application/octet-stream"
                ),
            )
        except Exception as exc:
            raise ObjectStorageError("Unable to retrieve object") from exc
        finally:
            if response is not None:
                response.close()
                response.release_conn()

    @staticmethod
    def _parse_endpoint(endpoint: str) -> tuple[str, bool]:
        """Accept host:port or an explicit HTTP(S) MinIO endpoint."""
        normalized = endpoint.strip()
        if not normalized:
            raise ValueError("MinIO endpoint must not be empty")
        if "://" not in normalized:
            return normalized.rstrip("/"), False

        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("MinIO endpoint must use HTTP or HTTPS")
        if parsed.path not in {"", "/"}:
            raise ValueError("MinIO endpoint must not include a path")
        return parsed.netloc, parsed.scheme == "https"


@lru_cache
def get_object_storage_service() -> ObjectStorageService:
    """Build the process-wide MinIO adapter from application settings."""
    return ObjectStorageService(get_settings())
