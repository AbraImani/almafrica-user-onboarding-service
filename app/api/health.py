"""Operational health-check endpoint."""

from typing import Literal

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.database import database_is_reachable

router = APIRouter()


class HealthResponse(BaseModel):
    """Health state for the application and its required dependencies."""

    status: Literal["healthy", "unhealthy"]
    dependencies: dict[str, dict[str, Literal["healthy", "unhealthy"]]]


@router.get(
    "/health",
    tags=["health"],
    summary="Health check",
    response_model=HealthResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse}},
)
def health_check() -> JSONResponse:
    """Report readiness based on PostgreSQL connectivity."""
    database_status = "healthy" if database_is_reachable() else "unhealthy"
    application_status = "healthy" if database_status == "healthy" else "unhealthy"
    response = HealthResponse(
        status=application_status,
        dependencies={"database": {"status": database_status}},
    )
    response_status = (
        status.HTTP_200_OK
        if application_status == "healthy"
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return JSONResponse(
        status_code=response_status,
        content=response.model_dump(),
    )
