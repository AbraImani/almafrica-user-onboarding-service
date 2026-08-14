"""Routes exposed by API version 1."""

from fastapi import APIRouter, HTTPException, status

from app.core.database import database_is_reachable

router = APIRouter()


@router.get("/health", tags=["health"], summary="Health check")
def health_check() -> dict[str, str]:
    if not database_is_reachable():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        )

    return {"status": "ok", "database": "reachable"}
