"""Administrator-only routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.dependencies import require_administrator
from app.core.database import get_database_session
from app.models.user import User, UserRole
from app.schemas.admin import PaginatedUsersResponse, SortOrder, UserSortField
from app.schemas.auth import ErrorResponse

router = APIRouter(prefix="/admin", tags=["admin"])

_SORTABLE_USER_COLUMNS = {
    UserSortField.CREATED_AT: User.created_at,
    UserSortField.FULL_NAME: User.full_name,
}


@router.get(
    "/access-check",
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
    },
)
def check_administrator_access(
    _administrator: User = Depends(require_administrator),
) -> dict[str, str]:
    """Confirm that authentication and administrator authorization succeeded."""
    return {"message": "Administrator access granted."}


@router.get(
    "/users",
    response_model=PaginatedUsersResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
    },
)
def list_users(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    role: UserRole | None = None,
    is_verified: bool | None = None,
    sort_by: UserSortField = UserSortField.CREATED_AT,
    sort_order: SortOrder = SortOrder.DESC,
    _administrator: User = Depends(require_administrator),
    session: Session = Depends(get_database_session),
) -> PaginatedUsersResponse:
    """List safe user profiles using constrained filtering and sorting."""
    filters = []
    if role is not None:
        filters.append(User.role == role)
    if is_verified is not None:
        filters.append(User.is_verified == is_verified)

    sort_column = _SORTABLE_USER_COLUMNS[sort_by]
    order_expression = (
        sort_column.asc() if sort_order == SortOrder.ASC else sort_column.desc()
    )

    try:
        total = session.scalar(
            select(func.count(User.id)).where(*filters)
        ) or 0
        users = session.scalars(
            select(User)
            .where(*filters)
            .order_by(order_expression, User.id.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "user_list_unavailable",
                "message": "The user list is temporarily unavailable.",
            },
        ) from exc

    return PaginatedUsersResponse(
        items=list(users),
        page=page,
        page_size=page_size,
        total=total,
        total_pages=(total + page_size - 1) // page_size,
    )
