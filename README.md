# SOAR Playbook - Automated Malware Alert Response on Endpoints

<div align="center">

![Python](https://img.shields.io/badge/Python-3.13%20validated-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-API%20Layer-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Primary%20Dashboard-61DAFB?style=for-the-badge&logo=react&logoColor=0B1020)
![Supabase](https://img.shields.io/badge/Supabase-Postgres%20Persistence-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Live%20Hash%20Intel-394EFF?style=for-the-badge)
![pytest](https://img.shields.io/badge/pytest-71%20tests%20passing-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![Security](https://img.shields.io/badge/RBAC-Enabled-8B5CF6?style=for-the-badge)

**Blue Team CV Project for SOC analyst workflow automation**

*An end-to-end SOAR playbook for malware alerts, from intake and enrichment to policy response, persistence, and analyst review.*

</div>

---

## Table of Contents

- [Background and Goals](#background-and-goals)
- [What Is Implemented](#what-is-implemented)
- [End-to-End Workflow](#end-to-end-workflow)
- [Current Architecture](#current-architecture)
- [React Dashboard](#react-dashboard)
- [Security and Sensitive Data Handling](#security-and-sensitive-data-handling)
- [Persistence Model](#persistence-model)
- [Setup and Run](#setup-and-run)
- [Main API Routes](#main-api-routes)
- [Project Structure](#project-structure)
- [Verification Snapshot](#verification-snapshot)

---

## Background and Goals

This project models how a SOC or Blue Team automation flow handles a malware alert from intake to analyst follow-up instead of stopping at a single detection or enrichment step.

The current repository is structured around a shared orchestration service that powers CLI runs, HTTP processing, dashboard operations, and queued remediation execution. The goal is to show end-to-end incident workflow design, not just isolated scripts.

## What Is Implemented

- Shared orchestration through `services/workflow_service.py`
- FastAPI-backed alert processing and incident APIs in `api/app.py`
- React dashboard as the primary analyst UI in `dashboard/src/`
- Queue-capable remediation execution via `scripts/run_remediation_worker.py`
- Threat enrichment for file hashes, IPs, asset criticality, and MITRE ATT&CK mappings
- Policy-as-data evaluation through `policies/response_rules.yaml`
- Incident correlation, reporting, persistence, replay, notes, approvals, and saved filters
- Runtime-selectable SQLite and Postgres persistence paths
- Docker, GitHub Actions CI, and release-compose deployment assets

## End-to-End Workflow

1. Alerts enter through the CLI, FastAPI, or normalized source payloads.
2. `SoarWorkflowService` resolves workspace context and checks for replay by `alert_id`.
3. `EnrichmentPipeline` performs hash, IP, CMDB, MITRE, and risk-scoring steps.
4. `PolicyEngine` evaluates YAML policy rules and either executes actions immediately or queues them.
5. `IncidentCorrelationService` decides whether the alert creates a new incident or attaches to an existing one.
6. `ReportGenerator` writes Markdown, HTML, and optional PDF artifacts.
7. The incident repository persists alerts, incidents, actions, queue jobs, reports, notes, audit data, and filters.
8. In queued mode, `AsyncRemediationWorker` claims queue jobs and executes deferred remediation actions.

## Current Architecture

![SOAR System Architecture](docs/SOAR%20Architecture.png)

More detailed diagrams are in `docs/architecture.md`.

The main runtime entrypoints are:

- `main.py`
- `api/app.py`
- `dashboard/src/main.tsx`
- `scripts/run_remediation_worker.py`

`dashboard/app.py` still exists as a legacy Streamlit UI, but it is not the primary frontend, not part of the Docker build, and not used by CI.

## React Dashboard

- Primary frontend: `dashboard/src/`
- Dev path: Vite server with `/soar-api` proxying to FastAPI
- Hosted proxy path: `dashboard/api/` for Vercel-style deployments
- Docker path: static Vite build served by Nginx
- Analyst capabilities: intake, incident queue review, case updates, notes, approvals, reopen, report viewing, and saved filters
- Auth model: bearer token stored in browser `sessionStorage` and forwarded by the proxy

## Security and Sensitive Data Handling

- Bearer authentication is configured through `SOAR_AUTH_TOKENS_JSON`.
- API routes enforce RBAC through `incident_read` and `incident_process` roles.
- Workspace scoping is enforced in `security/auth.py` and `workspace_utils.py`.
- Incident detail is redacted by default; operator-capable principals can request `include_sensitive=true`.
- HTML reports are served from the repository `output/` tree through a constrained path check in `api/app.py`.
- The frontend no longer injects a shared service credential; it forwards the browser session token instead.

## Persistence Model

- If `SOAR_DB_TARGET` points to a file path, the app uses SQLite.
- If `SOAR_DB_TARGET` is a Postgres DSN, the app uses Postgres.
- If `SOAR_DB_TARGET` is unset, the app tries `SOAR_DATABASE_URL`, then `SUPABASE_DB_URL`, then falls back to `SOAR_SQLITE_FALLBACK_PATH`.
- SQLite currently has the most complete analyst workflow support.
- The Postgres repository currently supports ingestion, read/list flows, and queue persistence, but several analyst mutation methods are still not implemented.

## Features

- Canonical malware-alert intake for CLI, API, and normalized external source payloads
- Threat enrichment for file hashes and IPs, including optional VirusTotal-backed lookups
- Asset criticality and CMDB context enrichment
- MITRE ATT&CK mapping and weighted risk scoring
- Policy-as-data evaluation from `policies/response_rules.yaml`
- Synchronous, queued, and dry-run execution modes
- Approval-aware remediation queue with retry and dead-letter behavior
- Incident correlation and incident re-open/attach logic
- Markdown, HTML, and optional PDF report generation
- SQLite and Postgres persistence paths
- Full analyst mutation workflow on SQLite, with a partial Postgres implementation
- Role-based API access with workspace scoping
- React dashboard for intake, queue review, incident detail, notes, approvals, and saved filters
- Docker, GitHub Actions CI, and remote release-compose deployment assets

## Technology Stack

- Backend: Python 3.13, FastAPI, Pydantic v2, Loguru
- Frontend: React 18, TypeScript, Vite
- Persistence: SQLite and Postgres via `psycopg`
- Reporting: `markdown2`, optional `weasyprint`
- Testing: `pytest`, Playwright smoke tests
- Deployment: Docker, Docker Compose, GitHub Actions
- Security model: bearer-token RBAC with workspace scoping

## Project Structure

```text
.
├── actions/                Local mock remediation and ticketing adapters
├── alert_generator/        Synthetic alert generation for scenarios and tests
├── api/                    FastAPI application and response schemas
├── config/environments/    Docker and deployment env profiles
├── dashboard/              React frontend, Vercel proxy handlers, legacy Streamlit app
├── data/                   Sample alerts, mock intel/CMDB data, source replay fixtures
├── docker/                 Backend and dashboard Dockerfiles plus Nginx config
├── docs/                   Design notes, deployment notes, security notes, architecture docs
├── engine/                 Policy loader, policy engine, dispatcher, risk scoring, replay helpers
├── enrichment/             Threat-intel, asset, MITRE, and enrichment orchestration
├── integrations/           Connector protocols and provider factories
├── migrations/postgres/    Ordered SQL migrations for Postgres deployments
├── observability/          Metrics, traces, resilience, connector wrappers
├── policies/               YAML policy config and replay fixtures
├── reporting/              Incident report generation
├── schemas/                Domain schemas for alerts, responses, queue items, and incidents
├── scripts/                Worker, migrations, replay, pentest, validation, deployment helpers
├── security/               Authentication and authorization helpers
├── services/               Workflow orchestration, readiness, queue worker, incident correlation
├── storage/                Repository implementations for SQLite and Postgres
├── tests/                  Backend test suite
├── main.py                 CLI entrypoint
├── start-local.sh          Local dev stack launcher (Linux/macOS)
└── stop-local.sh           Local dev stack shutdown helper
```

## System Architecture

### Request flow

1. An alert enters through the CLI, FastAPI, or a source connector.
2. `SoarWorkflowService` normalizes workspace context and checks for replay/idempotency by `alert_id`.
3. `EnrichmentPipeline` resolves hash intel, IP intel, asset criticality, asset metadata, MITRE mappings, and risk scoring.
4. `PolicyEngine` evaluates YAML policy rules and either executes actions immediately or queues them.
5. `IncidentCorrelationService` decides whether the alert becomes a new incident or is attached to an existing one.
6. `ReportGenerator` writes Markdown, HTML, and optionally PDF artifacts.
7. `IncidentRepository` persists alerts, incidents, actions, notes, audit data, reports, queue jobs, and saved filters.
8. In queued mode, `AsyncRemediationWorker` claims jobs from the repository and executes queued remediation actions.

### Repository selection

- If `SOAR_DB_TARGET` is a filesystem path, the app uses SQLite.
- If `SOAR_DB_TARGET` is a Postgres DSN, the app uses Postgres.
- If `SOAR_DB_TARGET` is unset, the app first tries `SOAR_DATABASE_URL`, then `SUPABASE_DB_URL`, and finally falls back to `SOAR_SQLITE_FALLBACK_PATH`.

### Current persistence limitation

SQLite currently has the most complete analyst workflow support. The Postgres repository implementation supports workflow ingestion, listing, readback, and queue persistence, but case mutations, notes, approvals, reopen, bulk update, and saved-filter writes are still marked `NotImplemented` in `storage/incident_repository.py`.

### Frontend model

- Development mode uses the Vite dev server with `/soar-api` proxying.
- Vercel deployments use `dashboard/api/*` handlers as proxy functions.
- Docker dashboard builds a static Vite bundle and serves it through Nginx.
- The dashboard stores the bearer token in `sessionStorage` for the current browser tab.

## Setup and Run

### Backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Frontend

```bash
npm --prefix dashboard install
```

### Environment

Choose one of these approaches:

- Local quick start: create `.env.local` at the repo root
- Docker local profile: use `config/environments/development.env`
- Staging or production template: copy the matching file from `config/environments/`

You can validate env profiles with:

```bash
python3 scripts/validate_env.py config/environments/development.env
```

## Environment Variables

### Core runtime

| Variable | Purpose | Required when |
| --- | --- | --- |
| `SOAR_ENVIRONMENT` | Environment label used by profiles and docs | Profile-based deployments |
| `SOAR_DB_TARGET` | Explicit SQLite path or Postgres DSN | Required if you do not want repository auto-selection |
| `SOAR_DATABASE_URL` | Preferred Postgres DSN | Postgres runtime |
| `SUPABASE_DB_URL` | Fallback Postgres DSN | Postgres runtime if `SOAR_DATABASE_URL` is unset |
| `SOAR_SQLITE_FALLBACK_PATH` | SQLite fallback path | Optional, defaults to `output/soar-local.db` |

### Connectors and providers

| Variable | Purpose |
| --- | --- |
| `SOAR_SOURCE_PROVIDER` or `SOAR_SOURCE_CONNECTOR` | Source normalization provider (`passthrough`, `wazuh`, `microsoft_defender`) |
| `SOAR_ACTION_PROVIDER` | Remediation action provider |
| `SOAR_TICKETING_CONNECTOR` | Ticketing connector factory selector |
| `SOAR_TICKETING_PROVIDER` | Local ticket backend (`json`, `webhook`) |
| `SOAR_TICKETING_WEBHOOK_URL` | Ticketing webhook endpoint |
| `SOAR_TICKETING_WEBHOOK_TOKEN` | Ticketing webhook credential |
| `SOAR_TICKETING_JSON_PATH` | Local JSON ticket store path |
| `SOAR_ASSET_PROVIDER` | Asset provider (`mock`, `file`, `http`) |
| `SOAR_ASSET_DB_PATH` | Asset file path for the file-backed provider |
| `SOAR_ASSET_API_URL` | HTTP CMDB endpoint |
| `SOAR_ASSET_API_TOKEN` | HTTP CMDB credential |
| `SOAR_INTEL_PROVIDER` | Threat-intel provider (`mock`, `virustotal`) |
| `VIRUSTOTAL_API_KEY` | VirusTotal credential |

### API, auth, and frontend

| Variable | Purpose |
| --- | --- |
| `SOAR_API_CORS_ORIGINS` | Comma-separated CORS allowlist |
| `SOAR_AUTH_TOKENS_JSON` | Bearer token map with roles and workspaces |
| `SOAR_AUTH_TOKEN` | CLI auth token helper for auth-aware scripts |
| `SOAR_API_PROXY_TARGET` | Upstream API base for Vite or Vercel proxy handlers |
| `VITE_SOAR_API_BASE_URL` | Explicit frontend API base path or URL |

### Queue and observability tuning

| Variable | Purpose |
| --- | --- |
| `SOAR_POLICY_EXECUTION_MODE` | `sync`, `queued`, or `dry_run` |
| `SOAR_APPROVAL_REQUIRED_ACTIONS` | Comma-separated actions that require approval |
| `SOAR_POLICY_QUEUE_NAME` | Queue name override |
| `SOAR_POLICY_CORRELATION_PREFIX` | Queue correlation prefix override |
| `SOAR_POLICY_QUEUE_FALLBACK_TO_SYNC` | Whether queue mode falls back to sync execution |
| `SOAR_REMEDIATION_MAX_ATTEMPTS` | Worker retry limit |
| `SOAR_REMEDIATION_POLL_INTERVAL_SEC` | Worker polling interval |
| `SOAR_REMEDIATION_RETRY_BASE_SEC` | Base retry backoff |
| `SOAR_REMEDIATION_RETRY_MAX_SEC` | Max retry backoff |
| `SOAR_OBSERVABILITY_LOG_PATH` | Structured observability log path |

## Development

### One-command local startup

```bash
./start-local.sh
```

This script:

- checks ports
- starts FastAPI with queued policy execution
- starts the remediation worker
- starts the Vite dashboard
- probes backend and dashboard health

Stop the local stack with:

```bash
./stop-local.sh
```

### Manual development

Backend:

```bash
python3 -m uvicorn api.app:app --reload
```

Worker:

```bash
python3 scripts/run_remediation_worker.py
```

Dashboard:

```bash
npm --prefix dashboard run dev
```

CLI:

```bash
python3 main.py --scenario mixed
python3 main.py --alert data/sample_alerts/alert_04_full_critical.json
```

## Verification Snapshot

Current validation status from the latest repository audit:

- Backend static validation: PASS
- Backend tests: PASS (`131 passed`)
- Frontend build: PASS
- Frontend smoke tests: PASS
- API startup smoke: PASS
- Lint: N/A (no dedicated lint command is defined in the repo)
- Typecheck: PASS (covered by the dashboard build script)

Commands used for verification:

Backend tests:

```bash
pytest -q
```

Static validation:

```bash
python3 -m compileall api actions alert_generator engine enrichment integrations observability reporting schemas security services storage scripts
```

Dashboard build and smoke tests:

```bash
npm --prefix dashboard run build
npm --prefix dashboard run test:smoke
```

## Build

Frontend production bundle:

```bash
npm --prefix dashboard run build
```

Backend Docker image:

```bash
docker build --target api -f docker/Dockerfile.backend -t soar-api:test .
```

Worker Docker image:

```bash
docker build --target worker -f docker/Dockerfile.backend -t soar-worker:test .
```

Dashboard Docker image:

```bash
docker build -f docker/Dockerfile.dashboard --build-arg VITE_SOAR_API_BASE_URL=/soar-api -t soar-dashboard:test .
```

## Deployment

### Local Compose

SQLite-backed default profile:

```bash
docker compose up --build
```

Bundled-Postgres profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml --profile postgres up --build -d
python3 scripts/apply_postgres_migrations.py
```

### Release Compose

Release rollout is driven by:

- `docker-compose.release.yml`
- optional `docker-compose.release.postgres.yml`
- `scripts/deploy_remote_compose.sh`
- `.github/workflows/deploy.yml`

The release compose profile pulls prebuilt GHCR images for API, worker, and dashboard. Optional Postgres migration runs happen through the `migrate` service.

## Main API Routes

### Base URL

- Local backend: `http://127.0.0.1:8000`
- Local dashboard proxy: `http://127.0.0.1:5173/soar-api`

### Authentication

Protected routes require:

```text
Authorization: Bearer <token>
```

Roles used by the API:

- `incident_read`
- `incident_process`

### Main endpoints

- `GET /health`
- `GET /api/v1/ready`
- `GET /api/v1/observability`
- `GET /api/v1/dashboard/bootstrap`
- `POST /api/v1/incidents/process`
- `POST /api/v1/incidents/process-scenario`
- `GET /api/v1/incidents`
- `POST /api/v1/incidents/bulk-update`
- `GET /api/v1/incidents/saved-filters`
- `POST /api/v1/incidents/saved-filters`
- `GET /api/v1/incidents/by-alert/{alert_id}`
- `PATCH /api/v1/incidents/by-alert/{alert_id}`
- `POST /api/v1/incidents/by-alert/{alert_id}/notes`
- `POST /api/v1/incidents/by-alert/{alert_id}/actions/{correlation_id}/approve`
- `POST /api/v1/incidents/by-alert/{alert_id}/actions/{correlation_id}/reject`
- `POST /api/v1/incidents/by-alert/{alert_id}/actions/{correlation_id}/rollback`
- `POST /api/v1/incidents/by-alert/{alert_id}/reopen`
- `POST /api/v1/approvals/escalate-overdue`
- `GET /api/v1/incidents/by-alert/{alert_id}/report/html`
- `GET /api/v1/incidents/by-ticket/{ticket_id}`

## Security

- Authentication is bearer-token based and configured from `SOAR_AUTH_TOKENS_JSON`.
- Authorization is role-based and workspace-scoped through `security/auth.py` and `workspace_utils.py`.
- Sensitive incident detail is redacted by default and only returned in full when `include_sensitive=true` is requested by a principal with `incident_process`.
- Report artifact paths are constrained to the repository `output/` tree before FastAPI serves them.
- The dashboard no longer injects a shared backend credential; it forwards the browser session token through the proxy.
- `dashboard/vercel.json` applies CSP, frame protection, referrer policy, and permissions policy headers for Vercel-hosted frontend deployments.

## Troubleshooting

- `SOAR_AUTH_TOKENS_JSON is not configured`: add a token map before using protected API routes.
- Dashboard loads but API calls fail: verify the bearer token, backend startup, and `SOAR_API_PROXY_TARGET` or `VITE_SOAR_API_BASE_URL`.
- Queue-based actions never complete: start `scripts/run_remediation_worker.py` or switch `SOAR_POLICY_EXECUTION_MODE` back to `sync`.
- Postgres runtime fails to initialize: confirm `SOAR_DATABASE_URL` or `SUPABASE_DB_URL`, then run `python3 scripts/apply_postgres_migrations.py`.
- Readiness shows degraded threat intel: set `VIRUSTOTAL_API_KEY` or switch `SOAR_INTEL_PROVIDER=mock`.
