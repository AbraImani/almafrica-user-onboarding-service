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

Login, JWT authentication, and object storage are not implemented yet.

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
