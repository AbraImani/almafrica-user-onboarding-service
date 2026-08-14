# Almafrica User Onboarding Service

A secure user onboarding and profile management backend developed as part of the Almafrica Take-Home Engineering Challenge.

## Status

Work in progress.

## Current scope

- FastAPI
- Environment-based configuration
- Versioned API routing
- OpenAPI documentation
- PostgreSQL connectivity through SQLAlchemy 2
- User registration with Argon2id password hashing
- Local verification-email delivery through Mailpit
- Login with short-lived JWT access tokens
- Persisted seven-day refresh-token sessions

Refresh-token rotation and object storage are not implemented yet.

## Local setup

Python 3.10 or newer is required.

```bash
python -m venv .venv
```

Activate the virtual environment, then install the project with development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Optionally copy `.env.example` to `.env` and adjust the `ALMAFRICA_`-prefixed
application settings.

## Run the API

```bash
uvicorn app.main:app --reload
```

The service is available at `http://127.0.0.1:8000`. Useful endpoints:

- Service information: `GET /`
- Health check: `GET /health`
- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI schema: `/openapi.json`

The health endpoint verifies that PostgreSQL accepts queries and returns `503` while
the database is unavailable.

## Register a user

Create an unverified user with `POST /api/v1/auth/register`:

```json
{
  "full_name": "Ada Lovelace",
  "email": "ada@example.com",
  "password": "a-practical-password-123"
}
```

Passwords must contain 12–128 characters, including at least one letter and one
number. The API normalizes email addresses, stores only an Argon2id password hash,
creates a verification token that expires after 24 hours, and sends its raw value
only in the verification email. It returns `201` when registration succeeds and
`409` for an existing email.

## Verify an email address

Copy the token from the Mailpit message and submit it to
`POST /api/v1/auth/verify-email`:

```json
{
  "token": "the-token-from-the-email"
}
```

A valid token verifies the user and becomes unusable in one database transaction.
Unknown tokens return `400`, already-used tokens return `409`, and expired tokens
return `410`.

## Login and authenticated user

Set `ALMAFRICA_JWT_SECRET` to a cryptographically random value of at least 32
characters. Then authenticate a verified user with `POST /api/v1/auth/login`:

```json
{
  "email": "ada@example.com",
  "password": "a-practical-password-123"
}
```

The response contains an HS256 Bearer access token valid for 15 minutes and an
opaque refresh token valid for seven days. In Swagger, use **Authorize** and paste
the access token, then call `GET /api/v1/users/me`. Outside Swagger, send it in the
`Authorization: Bearer <token>` header.

Unknown emails and incorrect passwords both return the same `401` response. A
regular user whose email is not verified receives `403`.

Obtain a new access token with `POST /api/v1/auth/refresh`:

```json
{
  "refresh_token": "the-refresh-token-returned-by-login"
}
```

Only a SHA-256 digest of each refresh token is stored. Unknown, expired, and revoked
refresh sessions return `401`. Refresh-token rotation is intentionally outside the
current scope.

End a refresh session with `POST /api/v1/auth/logout`, using the same request body
as `/refresh`. Logout is idempotent: unknown or already-revoked tokens receive the
same `200` response, while the persisted session remains unusable for refresh.

## Run with Docker Compose

Optionally copy `.env.example` to `.env`, then build and start all services:

```bash
docker compose up --build
```

The API is available at `http://127.0.0.1:8000`, and the Mailpit inbox is available
at `http://127.0.0.1:8025`. Inside the Compose network, the API connects to
PostgreSQL through `postgres` and to SMTP through `mailpit`. PostgreSQL data is kept
in the named `postgres_data` volume between container restarts.

## Database migrations

Alembic reads the same `ALMAFRICA_DATABASE_*` settings as the application. With
PostgreSQL running, apply all pending migrations from the project directory:

```bash
python -m alembic upgrade head
```

Create a migration after changing SQLAlchemy model metadata:

```bash
python -m alembic revision --autogenerate -m "describe the schema change"
```

Revert the latest migration:

```bash
python -m alembic downgrade -1
```

## Seed the administrator

Set `ADMIN_FULL_NAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` in `.env`. Use a strong,
unique password of at least 12 characters, then run:

```bash
python -m app.scripts.seed_admin
```

The command normalizes the email, hashes the password with Argon2id, and creates a
verified `ADMIN`. It is safe to run repeatedly: an existing email is reported and
left unchanged.

## Email verification tokens

Verification tokens use 256 bits of cryptographically secure randomness and expire
24 hours after generation. Only a SHA-256 digest is persisted; the raw token exists
only in memory until the SMTP service includes it in the verification link. Token
records are single-use through `used_at`, and deleting a user automatically deletes
their verification tokens through the database foreign key.
