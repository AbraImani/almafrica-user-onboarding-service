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

Database models, authentication, object storage, and email are not implemented yet.

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
- Health check: `GET /api/v1/health`
- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI schema: `/openapi.json`

The health endpoint verifies that PostgreSQL accepts queries and returns `503` while
the database is unavailable.

## Run with Docker Compose

Optionally copy `.env.example` to `.env`, then build and start the API and PostgreSQL:

```bash
docker compose up --build
```

The API is available at `http://127.0.0.1:8000`. Inside the Compose network it
connects to PostgreSQL using the `postgres` service name. PostgreSQL data is kept
in the named `postgres_data` volume between container restarts.
