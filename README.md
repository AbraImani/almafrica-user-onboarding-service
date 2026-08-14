# Almafrica User Onboarding Service

Backend submission for the Almafrica Take-Home Engineering Challenge. The service
covers user onboarding, email verification, session-based authentication,
self-service profile management, private profile images, and a read-only
administrator user list.

The code is organized as a small modular monolith: FastAPI owns the HTTP boundary,
SQLAlchemy models own persistence, and focused services handle SMTP and MinIO.
There is no framework layer or repository abstraction beyond what the current scope
needs.

## Implemented scope

- User registration with normalized, unique email addresses
- Argon2id password hashing and a shared password policy
- Single-use email verification tokens delivered locally through Mailpit
- JWT access tokens with a 15-minute lifetime
- Persisted, revocable refresh sessions with a seven-day lifetime
- Immediate access-token invalidation after logout through the JWT `sid` claim
- Login rate limiting by client IP
- Authenticated self-profile reading and name updates
- Secure password changes with revocation of all existing sessions
- Private JPEG, PNG, and WebP profile images stored in MinIO
- `USER` and `ADMIN` role-based authorization
- Paginated and filtered administrator user listing
- PostgreSQL-backed health checking
- Alembic migrations and an idempotent administrator seed
- Focused pytest coverage for authentication and authorization boundaries

## Technology

- Python 3.10+
- FastAPI and Pydantic
- PostgreSQL 16
- SQLAlchemy 2 and Alembic
- Argon2id password hashing
- HS256 JWT access tokens
- MinIO object storage
- Mailpit local SMTP inbox
- pytest
- Docker Compose

## Quick start with Docker Compose

Docker Compose is the recommended way to review the project. It starts the API,
PostgreSQL, Mailpit, and MinIO with health checks and persistent volumes for database
and object-storage data.

### 1. Create the local environment file

On macOS or Linux:

```bash
cp .env.example .env
```

On PowerShell:

```powershell
Copy-Item .env.example .env
```

Before starting the stack, replace these placeholders in `.env`:

- `ALMAFRICA_JWT_SECRET`: at least 32 cryptographically random characters
- `ADMIN_PASSWORD`: a strong local seed password

The PostgreSQL and MinIO credentials in `.env.example` are deliberately simple
local-development values. They are not production credentials.

### 2. Build and start the services

```bash
docker compose up -d --build
```

Check their status:

```bash
docker compose ps
```

The `api`, `postgres`, `mailpit`, and `minio` services should all become healthy.

### 3. Apply the database migrations

Compose does not run migrations automatically. Apply them explicitly after the
database is healthy:

```bash
docker compose exec api python -m alembic upgrade head
```

### 4. Seed the administrator

This step is optional for the regular onboarding flow, but required to exercise the
administrator endpoints:

```bash
docker compose exec api python -m app.scripts.seed_admin
```

The seed reads `ADMIN_FULL_NAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`, normalizes
the email, hashes the password with Argon2id, and creates a verified `ADMIN`.
Running the command again is safe; an existing email is reported and left unchanged.

### 5. Open the local services

| Service | URL |
| --- | --- |
| Swagger UI | <http://localhost:8000/docs> |
| ReDoc | <http://localhost:8000/redoc> |
| OpenAPI JSON | <http://localhost:8000/openapi.json> |
| API health | <http://localhost:8000/health> |
| Mailpit inbox | <http://localhost:8025> |
| MinIO console | <http://localhost:9001> |

The MinIO console uses `MINIO_ACCESS_KEY` and `MINIO_SECRET_KEY` from `.env`.

To stop the services without deleting persisted PostgreSQL or MinIO data:

```bash
docker compose down
```

## Walkthrough: register, verify, and sign in

The complete flow can be exercised from Swagger.

### Register

Call `POST /api/v1/auth/register`:

```json
{
  "full_name": "Ada Musane",
  "email": "ada@example.com",
  "password": "PracticalPassword24"
}
```

Registration returns `201 Created`. The email is trimmed and lowercased, the
password is stored only as an Argon2id hash, and the new `USER` starts with
`is_verified: false`.

Passwords must contain 12 to 128 characters, including at least one letter and one
number. Names are trimmed, limited to 255 characters, and must contain a letter.
Registering the same normalized email again returns `409 Conflict`.

### Verify the email address

Open Mailpit at <http://localhost:8025> and inspect the verification message. The
API contract is a POST request, so copy the value after `token=` from the message
and send it to `POST /api/v1/auth/verify-email`:

```json
{
  "token": "token-copied-from-mailpit"
}
```

Verification tokens contain 256 bits of cryptographically secure randomness and
expire after 24 hours. Only their SHA-256 hashes are stored. A successful
verification marks both the user and token in one database transaction.

Unknown tokens return `400`, used tokens return `409`, and expired tokens return
`410`.

### Login

Call `POST /api/v1/auth/login` after verification:

```json
{
  "email": "ada@example.com",
  "password": "PracticalPassword24"
}
```

The response contains:

- a Bearer access token valid for 15 minutes;
- an opaque refresh token valid for seven days.

Unknown emails and incorrect passwords return the same `401` response. A regular
user whose email is not verified receives `403`.

In Swagger, select **Authorize** and paste the access token. Outside Swagger, use:

```text
Authorization: Bearer <access_token>
```

The login endpoint allows five attempts per 60-second sliding window for each
directly connected client IP. Further attempts return `429` with a `Retry-After`
header.

### Refresh and logout

Obtain another short-lived access token with `POST /api/v1/auth/refresh`:

```json
{
  "refresh_token": "refresh-token-returned-by-login"
}
```

End the session with `POST /api/v1/auth/logout` using the same body. Logout is
idempotent.

Only a SHA-256 hash of the refresh token is persisted. Each access token contains
the persisted session UUID as `sid`. Protected endpoints check that session in
PostgreSQL, so logout immediately invalidates both the refresh token and access
tokens issued for that session.

## API endpoints

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/` | Public | Service name, version, environment, and docs path |
| `GET` | `/health` | Public | PostgreSQL readiness check |
| `POST` | `/api/v1/auth/register` | Public | Register an unverified user |
| `POST` | `/api/v1/auth/verify-email` | Public token | Consume an email verification token |
| `POST` | `/api/v1/auth/login` | Public credentials | Create an access token and refresh session |
| `POST` | `/api/v1/auth/refresh` | Refresh token | Create a new access token |
| `POST` | `/api/v1/auth/logout` | Refresh token | Revoke a session |
| `GET` | `/api/v1/users/me` | Bearer token | Read the authenticated user's profile |
| `PATCH` | `/api/v1/users/me` | Bearer token | Update only `full_name` |
| `POST` | `/api/v1/users/me/change-password` | Bearer token | Change password and revoke all sessions |
| `POST` | `/api/v1/users/me/profile-image` | Bearer token | Upload or replace a profile image |
| `GET` | `/api/v1/users/me/profile-image` | Bearer token | Serve the private profile image |
| `GET` | `/api/v1/admin/access-check` | ADMIN | Confirm administrator authorization |
| `GET` | `/api/v1/admin/users` | ADMIN | List users safely |

FastAPI documents the request and response schemas, validation failures, and
supported query values in Swagger.

## Self-profile and object-level authorization

`GET /api/v1/users/me` returns:

- `id`
- `full_name`
- `email`
- `role`
- `is_verified`
- profile-image key and authenticated URL when present
- `created_at` and `updated_at`

The profile routes never accept a caller-supplied user ID. The authenticated user
is resolved from the access token, which avoids an object-level authorization path
where one user could request another user's profile. PATCH accepts only
`full_name`; attempts to assign `id`, `email`, `role`, `is_verified`, or unknown
fields return `422`.

Changing a password requires the current password, applies the registration
password policy to the new value, stores a new Argon2id hash, and revokes every
active session for the user. The user must sign in again after success.

## Profile images

Upload an image as multipart form data with the field name `image`:

```bash
curl -X POST http://localhost:8000/api/v1/users/me/profile-image \
  -H "Authorization: Bearer <access_token>" \
  -F "image=@avatar.png"
```

The endpoint accepts JPEG, PNG, and WebP files up to 5 MB. It compares the declared
MIME type with the file signature and never uses the original filename as an object
key. Objects follow this structure:

```text
users/{user_uuid}/{generated_uuid}.{extension}
```

The bucket is private. `GET /api/v1/users/me` exposes the authenticated application
URL `/api/v1/users/me/profile-image`, and the image itself is served only after the
same Bearer-token checks as the rest of the profile.

When replacing an image, the service uploads the new object first, commits the new
database association, and then removes the old object. If the database update
fails, it attempts to remove the newly uploaded object.

## Administrator user listing

`GET /api/v1/admin/users` is protected by the reusable ADMIN authorization guard.
An authenticated `USER` receives `403 Forbidden`; an anonymous caller receives the
normal `401` authentication response.

Supported query parameters:

| Parameter | Default | Accepted values |
| --- | --- | --- |
| `page` | `1` | Integer greater than or equal to 1 |
| `page_size` | `20` | Integer from 1 to 100 |
| `role` | none | `USER`, `ADMIN` |
| `is_verified` | none | `true`, `false` |
| `sort_by` | `created_at` | `created_at`, `full_name` |
| `sort_order` | `desc` | `asc`, `desc` |

Sorting uses a fixed mapping from validated enum values to SQLAlchemy columns. User
input is never treated as an arbitrary SQL column name. Responses use the same safe
profile representation and never include password hashes or token records.

No administrator modification or deletion endpoint is implemented.

## Security decisions

- Passwords are hashed with Argon2id and are never returned by the API.
- Verification and refresh tokens are generated with `secrets` and stored only as
  SHA-256 hashes.
- JWT secrets come from environment configuration and have no source-code fallback.
- Access tokens require `sub`, `sid`, `iat`, and `exp` claims.
- Protected requests validate the JWT, user, persisted session, revocation state,
  and session expiration.
- Login failures do not disclose whether the email or password was incorrect.
- Administrator authorization is separate from authentication and returns `403`
  for an authenticated user with insufficient permissions.
- Pydantic request schemas reject unexpected profile fields to prevent mass
  assignment.
- Profile-image buckets remain private and object names are application-generated.

## Database migrations

Alembic uses the same environment-backed database settings as the application. The
repository contains migrations for:

1. users and the PostgreSQL `user_role` enum;
2. email verification tokens;
3. refresh-token sessions.

Useful commands inside the API container:

```bash
docker compose exec api python -m alembic current
docker compose exec api python -m alembic upgrade head
docker compose exec api python -m alembic downgrade -1
```

For model changes during development:

```bash
docker compose exec api python -m alembic revision --autogenerate -m "describe the change"
```

## Running tests

Create a Python environment and install the development dependencies:

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

Activate the virtual environment using the command appropriate for your shell, then
run:

```bash
python -m pytest -q
```

The suite is organized by domain and currently covers registration, verification,
login, rate limiting, access-token resolution, refresh sessions, logout, profile
authorization, password changes, MinIO upload behavior, administrator authorization,
pagination, and health checks.

Security-focused tests explicitly demonstrate that:

- a regular user cannot access administrator endpoints;
- profile operations apply only to the authenticated user;
- protected profile fields cannot be mass-assigned;
- registration creates an unverified user;
- verification enables login;
- invalid credentials and invalid tokens are rejected;
- valid access and refresh tokens work;
- logout revokes both refresh and access-token use for the session;
- API response schemas do not expose `password_hash`.

The tests use focused dependency overrides for external boundaries, so the full
suite does not require live PostgreSQL, Mailpit, or MinIO services.

## Running the API outside Docker

Python 3.10 or newer is required. After installing the project, copy `.env.example`
to `.env` and keep the default host values (`localhost`) for PostgreSQL, Mailpit,
and MinIO. Start those dependencies separately, apply migrations, then run:

```bash
uvicorn app.main:app --reload
```

The Docker image itself uses Python 3.12 and runs the application as a non-root
system user.

## Project structure

```text
app/
  api/              FastAPI routers and reusable dependencies
  core/             Configuration, database, security, and rate limiting
  models/           SQLAlchemy persistence models
  schemas/          Pydantic request and response models
  scripts/          Idempotent administrator seed
  services/         SMTP, verification-token, and MinIO adapters
alembic/             Database migration environment and revisions
tests/               Domain-focused automated tests
docker-compose.yml   Local API and infrastructure stack
Dockerfile           Production-style API image
```

## Configuration

Configuration is read from environment variables and `.env`. The main groups are:

- `ALMAFRICA_DATABASE_*`: PostgreSQL connection and timeout
- `ALMAFRICA_SMTP_*`: Mailpit or SMTP connection and sender identity
- `ALMAFRICA_JWT_*`: signing secret, algorithm, and access-token lifetime
- `ALMAFRICA_REFRESH_TOKEN_EXPIRE_DAYS`: refresh-session lifetime
- `ALMAFRICA_LOGIN_RATE_LIMIT_*`: login attempt policy
- `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`,
  `MINIO_BUCKET_NAME`: private object storage
- `ADMIN_FULL_NAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`: administrator seed

See `.env.example` for the complete local configuration.

## Known limitations

This submission intentionally stays within the challenge scope:

- Mailpit captures messages locally; it does not deliver email to real inboxes.
- The verification API is POST-only. For local testing, copy the token from the
  Mailpit message into Swagger rather than opening the link as a browser GET.
- Login rate limiting is process-local memory. Counters reset on restart and are
  not shared across multiple API replicas.
- Refresh-token rotation and reuse detection are not implemented.
- PostgreSQL and MinIO cannot share one atomic transaction. Compensation handles
  normal failures, but a process crash at the wrong moment could leave an orphaned
  object.
- Image validation checks MIME type and binary signatures; it does not resize,
  decode, or sanitize image pixels.
- The Compose MinIO service is a single local node without redundancy.
- The health endpoint checks PostgreSQL connectivity only.
- There are no administrator mutation/deletion endpoints, thumbnails, CDN,
  external email provider, or production deployment configuration.
