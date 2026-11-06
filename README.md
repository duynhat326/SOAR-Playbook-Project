# SOAR Playbook - Automated Malware Alert Response on Endpoints

<div align="center">

![Python](https://img.shields.io/badge/Python-3.13%20validated-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-API%20Layer-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Primary%20Dashboard-61DAFB?style=for-the-badge&logo=react&logoColor=0B1020)
![Supabase](https://img.shields.io/badge/Supabase-Postgres%20Persistence-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Live%20Hash%20Intel-394EFF?style=for-the-badge)
![pytest](https://img.shields.io/badge/pytest-131%20tests%20passing-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
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
- Approval-gated remediation: risky actions wait for an analyst, and every analyst step lands in a hash-chained audit trail
- Dark SOC-style dashboard with KPI row, risk distribution, priority queue, and a tabbed incident deep dive

## End-to-End Workflow

1. Alerts enter through the CLI, FastAPI, or normalized source payloads.
2. `SoarWorkflowService` resolves workspace context and checks for replay by `alert_id`.
3. `EnrichmentPipeline` performs hash, IP, CMDB, MITRE, and risk-scoring steps.
4. `PolicyEngine` evaluates YAML policy rules and either executes actions immediately or queues them.
5. `IncidentCorrelationService` decides whether the alert creates a new incident or attaches to an existing one.
6. `ReportGenerator` writes Markdown, HTML, and optional PDF artifacts.
7. The incident repository persists alerts, incidents, actions, queue jobs, reports, notes, audit data, and filters.
8. In queued mode, `AsyncRemediationWorker` claims queue jobs and executes deferred remediation actions.

### Risk scoring and default policy rules

The risk score (0-100) is a weighted sum of five normalized signals (`engine/risk_scoring.py`):

| Signal | Weight |
| --- | --- |
| File hash reputation | 30% |
| Destination IP / C2 reputation | 25% |
| Asset criticality (CMDB) | 20% |
| EDR severity | 15% |
| MITRE ATT&CK technique weight | 10% |

Bands: `0-25` low, `26-50` medium, `51-75` high, `76-100` critical. The per-signal breakdown is stored with the incident and shown in the report and dashboard.

Default rules in `policies/response_rules.yaml` (thresholds, allowlists, canary rollout, and approval rules are configurable there):

| Rule | Condition | Action |
| --- | --- | --- |
| 1 | File hash reputation is `malicious` | `isolate_host` |
| 2 | Process is in the dangerous-process blacklist | `kill_process` |
| 3 | Asset criticality is `critical` | `escalate` |
| 4 | Destination IP is flagged as C2 | `block_ip` |

`create_ticket` and `notify_soc` run for every processed alert. The shipped policy defaults to `sync` execution; set `SOAR_POLICY_EXECUTION_MODE=queued` (plus `SOAR_APPROVAL_REQUIRED_ACTIONS`) to put actions behind the worker and analyst approval.

### Alert payload

An alert is a JSON object with: `alert_id`, `hostname`, `username`, `process_name`, `file_path`, `file_hash`, `parent_process`, `command_line`, `destination_ip`, `severity` (`low|medium|high|critical`) and `detection_name`. Samples live in `data/sample_alerts/` (`alert_04_full_critical.json` triggers all four rules, `alert_05_benign.json` triggers none). Payloads that already look redacted (for example `username` set to `[redacted]`) are rejected, because sanitized dashboard output is not a raw alert.

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
- Layout: sticky top bar (backend and dependency health, pending approvals, session menu), KPI row with risk distribution, priority queue, then Incident stream next to a tabbed Deep dive (Response & approvals, Case, Threat intel, Trace & report, Audit, Raw data)
- Intake: the `+ New alert` button opens a side drawer (scenario, sample, or raw JSON); `Esc` closes it
- Auth model: bearer token stored in browser `sessionStorage` and forwarded by the proxy
- Analyst identity (approver, note author, filter owner) is never sent by the browser; the API takes it from the bearer token

## Security and Sensitive Data Handling

- Bearer authentication is configured through `SOAR_AUTH_TOKENS_JSON`.
- API routes enforce RBAC through `incident_read` and `incident_process` roles.
- Workspace scoping is enforced in `security/auth.py` and `workspace_utils.py`.
- Incident detail is redacted by default; operator-capable principals can request `include_sensitive=true`.
- HTML reports are served from the repository `output/` tree through a constrained path check in `api/app.py`.
- The frontend no longer injects a shared service credential; it forwards the browser session token instead.
- Analyst actions (approve, reject, rollback, notes, case updates, saved filters) record the identity of the authenticated token (`principal_id`); a mismatching `actor`/`author` in the request is rejected with `403`.
- Audit events are hash-chained per incident (each event stores the previous event's hash).
- Secrets stay out of git: `.env`, `.env.local`, and every `config/environments/*.env` except `development.env` are ignored.

## Persistence Model

- If `SOAR_DB_TARGET` points to a file path, the app uses SQLite.
- If `SOAR_DB_TARGET` is a Postgres DSN, the app uses Postgres.
- If `SOAR_DB_TARGET` is unset, the app tries `SOAR_DATABASE_URL`, then `SUPABASE_DB_URL`, then falls back to `SOAR_SQLITE_FALLBACK_PATH`.
- SQLite and Postgres both support the full analyst workflow (notes, approvals, rollback, reopen, bulk update, saved filters, audit trail).
- Postgres schema comes from `migrations/postgres/`; run `python3 scripts/apply_postgres_migrations.py` after pulling new migrations (`0001` baseline, `0002` workspace-scoped saved filters).
- Main tables: `alerts`, `incidents`, `incident_alerts`, `incident_fingerprints` (correlation), `action_results`, `queue_jobs` (approval and retry state), `reports`, `case_notes`, `audit_events`, `saved_filters`, `schema_migrations`.
- Supabase: use the Postgres connection string from the project's **Connect** dialog (the Session pooler works over IPv4) with `?sslmode=require`, and set it as `SUPABASE_DB_URL` or `SOAR_DATABASE_URL`. Leave `SOAR_DB_TARGET` empty, otherwise a SQLite path wins.

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
- Full analyst mutation workflow on SQLite and Postgres
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
├── docker-compose*.yml     Local, Postgres, and release Compose stacks
├── main.py                 CLI entrypoint
├── start-local.sh          Local dev stack launcher (Linux/macOS)
├── stop-local.sh           Local dev stack shutdown helper
└── CLAUDE.md               Guidance for AI coding assistants working in this repo
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

### Persistence parity

Both repositories implement the full analyst workflow. Postgres tests are opt-in: set `SOAR_TEST_POSTGRES_URL` to a throwaway database (never production) and run `pytest tests/test_workflow_service.py -k postgres`.

### Frontend model

- Development mode uses the Vite dev server with `/soar-api` proxying.
- Vercel deployments use `dashboard/api/*` handlers as proxy functions.
- Docker dashboard builds a static Vite bundle and serves it through Nginx.
- The dashboard stores the bearer token in `sessionStorage` for the current browser tab.

## Setup and Run

Prerequisites: Python 3.13, Node.js 20+ (for the dashboard), and optionally Docker. PDF reports additionally need WeasyPrint's system libraries (Cairo/Pango); Markdown and HTML reports work without them.

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

Quick start with real values:

```bash
cp .env.example .env.local
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # use as the token in SOAR_AUTH_TOKENS_JSON
```

Edit `.env.local`: set the token, `SOAR_INTEL_PROVIDER` (`mock` or `virustotal` plus `VIRUSTOTAL_API_KEY`), and optionally `SUPABASE_DB_URL`. Paste the same token into the dashboard's **Sign in** menu.

Notes:

- `.env.local` and `.env` are loaded without overriding variables that already exist in your shell. A leftover `export SUPABASE_DB_URL=` or `export SOAR_INTEL_PROVIDER=mock` silently beats the file (an empty value still counts as set), so `unset` them or open a fresh terminal.
- `GET /api/v1/ready` shows which providers are actually active (`sqlite` vs `postgres`, `mock` vs `virustotal`).
- For Docker, put real credentials in `config/environments/local.env` (git-ignored, loaded after `development.env`).

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

### Running tests

```bash
pytest -q                                      # full backend suite
pytest tests/test_policy_engine.py -k mimikatz # one file or one test
```

`tests/conftest.py` forces the mock intel provider and blanks `SUPABASE_DB_URL` and `VIRUSTOTAL_API_KEY`, so tests never touch live services even when `.env.local` has real keys. Two Postgres tests in `tests/test_workflow_service.py` are skipped unless `SOAR_TEST_POSTGRES_URL` points at a throwaway database.

Dashboard smoke tests use Playwright and need a one-time `npx --prefix dashboard playwright install chromium` and a build (`npm --prefix dashboard run build`) before `npm --prefix dashboard run test:smoke`.

## Verification Snapshot

Current validation status from the latest repository audit:

- Backend static validation: PASS
- Backend tests: PASS (`131 passed`, 2 opt-in Postgres tests skipped)
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

SQLite-backed default profile (mock intel and CMDB; the dashboard is on `http://localhost:8080`, the API on `http://localhost:8000`):

```bash
docker compose up --build
```

If `config/environments/local.env` exists it is loaded after `development.env`, so the same command runs against real Supabase and VirusTotal. Code is baked into the images: rebuild with `docker compose up --build` after changing code, while env-only changes just need `docker compose up -d`. `development.env` contains a placeholder `dev-` token for local use only; never expose that stack to a network.

Bundled-Postgres profile:

```bash
SOAR_POSTGRES_PASSWORD=<choose-a-password> docker compose -f docker-compose.yml -f docker-compose.postgres.yml --profile postgres up --build -d
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

### Example request

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/incidents/process \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"alert\": $(python3 -c 'import json; print(json.dumps({k: v for k, v in json.load(open("data/sample_alerts/alert_04_full_critical.json")).items() if not k.startswith("_")}))')}"
```

The alert is wrapped in an `alert` field. Reuse of an existing `alert_id` replays the stored incident instead of re-running side effects.

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
- `/api/v1/ready` still shows `sqlite` or `mock` after editing `.env.local`: a variable exported in your shell overrides the file; `unset SOAR_INTEL_PROVIDER SUPABASE_DB_URL SOAR_DB_TARGET SOAR_DATABASE_URL` and restart the API and worker.
- Approve, reject, or note requests return `403`: the `actor`/`author` in the request does not match the token's `principal_id`. The dashboard sends none; custom clients should omit these fields.
- Docker build hangs for minutes on `npm ci` or `apt-get`, or fails with `npm error Exit handler never called!`: containers cannot resolve DNS. Add `"dns": ["8.8.8.8", "1.1.1.1"]` in Docker Desktop's Docker Engine settings and restart it.
- The Docker dashboard still shows the old UI after a code change: rebuild with `docker compose up --build` and hard-refresh the browser.
