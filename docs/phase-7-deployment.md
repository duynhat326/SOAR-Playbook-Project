# Phase 7 Deployment Slice

This document tracks the deployment assets added for the Phase 7 slice.

## What is included

- Docker images for:
  - FastAPI API
  - async remediation worker
  - React dashboard served by Nginx
- Docker Compose runtime for local validation
- image-based release Compose manifests for staging and production rollouts
- optional Postgres-backed Compose override
- environment profile separation under `config/environments/`
- Postgres migration runner with ordered SQL files
- GitHub Actions pipeline for validation, tests, frontend build, and image build/publish
- GitHub Actions deployment workflow for remote Compose rollouts over SSH

## Local Docker runtime

SQLite-backed local stack:

```bash
docker compose up --build
```

Services:

- API: `http://127.0.0.1:8000`
- Dashboard: `http://127.0.0.1:8080`
- Worker: consumes queued remediation jobs against the shared `/app/output/soar-local.db`

Default local credentials come from `config/environments/development.env`:

- bearer token: `dev-incident-operator-token`

## Postgres-backed local validation

Start the stack with the Postgres override:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml --profile postgres up --build -d
```

Apply schema migrations:

```bash
python scripts/apply_postgres_migrations.py
```

Preview pending migrations without applying them:

```bash
python scripts/apply_postgres_migrations.py --dry-run
```

## Environment separation

Profiles live under `config/environments/`:

- `development.env`
- `staging.env.example`
- `production.env.example`

Validate any profile file before rollout:

```bash
python scripts/validate_env.py config/environments/production.env.example
```

## CI/CD scope

The current slice includes:

- static backend validation via `compileall`
- backend regression suite
- frontend build
- Docker Compose rendering
- Docker image builds
- tag-based image publish to GHCR
- manual deployment workflow for `staging` and `production` GitHub environments
- image-based release manifests for remote hosts that pull from GHCR

The deployment workflow expects these GitHub environment secrets:

- `DEPLOY_HOST`
- `DEPLOY_USER`
- `DEPLOY_PATH`
- `DEPLOY_SSH_KEY`
- `SOAR_DEPLOY_ENV_FILE`
- `GHCR_READ_TOKEN`
- optional `GHCR_USERNAME` if the runtime should not use `${{ github.actor }}`

Not included yet:

- infrastructure provisioning beyond Docker Compose

## Verification snapshot

Validated in this repository:

- `python -m pytest -q` -> passed (`118 passed`)
- `python -m pytest -q tests/test_deployment_assets.py` -> passed
- `python scripts/validate_env.py ...` against all environment profiles -> passed
- `python scripts/apply_postgres_migrations.py --help` -> passed
- `npm.cmd run build` in `dashboard/` -> passed
- `docker compose -f docker-compose.yml -f docker-compose.postgres.yml --profile postgres config` -> passed

Not validated in this session:

- live Docker image builds
- container startup and health checks

Reason:

- local Docker daemon was unavailable (`//./pipe/dockerDesktopLinuxEngine` not found), so runtime verification is still pending on a machine with Docker Desktop or another active daemon

## Known limitation

The most complete analyst workflow parity today still exists on the SQLite repository path.
Postgres persistence and migration assets are now packaged for deployment discipline, but some Phase 5 write-path features remain SQLite-first until the Postgres repository reaches feature parity.
