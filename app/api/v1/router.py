"""Routes exposed by API version 1."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health", tags=["health"], summary="Health check")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}
