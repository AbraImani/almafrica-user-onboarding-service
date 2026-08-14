"""Schemas for administrator-only operations."""

from enum import Enum

from pydantic import BaseModel

from app.schemas.auth import CurrentUserResponse


class UserSortField(str, Enum):
    """User fields explicitly permitted for administrator list sorting."""

    CREATED_AT = "created_at"
    FULL_NAME = "full_name"


class SortOrder(str, Enum):
    """Permitted sort directions."""

    ASC = "asc"
    DESC = "desc"


class PaginatedUsersResponse(BaseModel):
    """Safe paginated administrator view of users."""

    items: list[CurrentUserResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
