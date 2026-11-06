# System Architecture

This document describes the repository as implemented today. It reflects the real entrypoints, connector boundaries, persistence selection logic, and deployment assets present in the codebase.

## High-Level Architecture

![SOAR System Architecture](SOAR%20Architecture.png)

## Backend Request Flow

1. A client submits `POST /api/v1/incidents/process` or another incident route to `api/app.py`.
2. FastAPI enforces bearer authentication, role checks, and workspace scoping before calling `SoarWorkflowService`.
3. `SoarWorkflowService` checks the repository for an existing incident with the same `alert_id`.
4. For new alerts, `EnrichmentPipeline` performs hash, IP, CMDB, MITRE, and risk-scoring work.
5. `PolicyEngine` evaluates `policies/response_rules.yaml` and either executes actions immediately or queues them.
6. `IncidentCorrelationService` determines whether the alert opens a new incident or attaches to an existing one.
7. `ReportGenerator` writes Markdown, HTML, and optional PDF artifacts.
8. The incident repository persists the final workflow result and the API returns the hydrated response payload.

## Queued Remediation Flow

Queued remediation is optional and activated by policy execution mode.

1. `PolicyEngine` passes triggered actions to `ActionDispatcher`.
2. In `sync` mode, the dispatcher executes actions immediately through the action connector.
3. In `queued` mode, the dispatcher builds `QueuedActionRequest` objects and hands them to `RepositoryQueuePublisher`.
4. The publisher writes queue jobs into the incident repository.
5. `AsyncRemediationWorker` polls the repository, claims jobs, and executes them through the action connector.
6. The worker either completes the job, retries it with backoff, or moves it to dead-letter state.

## Authentication and Authorization Flow

Key implementation details:

- Tokens come from `SOAR_AUTH_TOKENS_JSON`.
- Roles are checked through `require_roles(...)`.
- Workspace access is enforced via `AuthenticatedPrincipal.resolve_workspace(...)` and incident workspace checks in `api/app.py`.
- The dashboard stores the current token in browser `sessionStorage` and forwards it through the Vite or Vercel proxy.
- Route handlers only return sensitive incident fields when an operator-capable principal explicitly requests `include_sensitive=true`.

## Persistence Selection

Repository selection in `create_incident_repository(...)` works like this:

1. If `SOAR_DB_TARGET` is set to a Postgres DSN, the app uses `SupabaseIncidentRepository`.
2. If `SOAR_DB_TARGET` is set to a filesystem path, the app uses `SQLiteIncidentRepository`.
3. If `SOAR_DB_TARGET` is unset, the app tries `SOAR_DATABASE_URL`, then `SUPABASE_DB_URL`.
4. If no Postgres DSN is available, the app falls back to SQLite at `SOAR_SQLITE_FALLBACK_PATH` or `output/soar-local.db`.

Current implementation note:

- SQLite supports the full analyst mutation workflow.
- The Postgres repository covers ingestion, read/list operations, queue persistence, and the analyst workflow (notes, approvals, rollback, reopen, bulk update, saved filters, audit trail).

## Deployment Architecture

The deployment model implemented in the repo has two concrete paths:

1. Local development via `docker-compose.yml`, optionally overlaid with `docker-compose.postgres.yml`.
2. Release rollout via prebuilt GHCR images, `docker-compose.release.yml`, optional `docker-compose.release.postgres.yml`, and `scripts/deploy_remote_compose.sh`.

Current deployment paths implemented in the repo:

- local Docker Compose with SQLite-backed development profile
- local Docker Compose with Postgres overlay
- image publishing through `.github/workflows/ci.yml`
- remote rollout through `.github/workflows/deploy.yml` and `scripts/deploy_remote_compose.sh`
- Vercel-friendly frontend proxy handlers in `dashboard/api/`

## Component Notes

- `main.py`: CLI banner, scenario generation, report writing, and terminal-friendly pipeline execution
- `api/app.py`: FastAPI route layer, auth enforcement, workspace scoping, report serving, and dashboard bootstrap payloads
- `services/workflow_service.py`: shared orchestration across CLI, API, tests, and source replay
- `enrichment/pipeline.py`: provider-driven enrichment and risk calculation
- `engine/policy_engine.py`: policy evaluation, action dispatch, unconditional ticket creation, and SOC notification
- `services/remediation_queue.py`: repository-backed queue publisher and worker
- `storage/incident_repository.py`: runtime repository selector plus Postgres implementation
- `storage/sqlite_repository.py`: SQLite implementation plus analyst-facing mutation support
- `dashboard/src/`: main frontend application
- `dashboard/api/`: Vercel proxy endpoints
- `dashboard/app.py`: legacy Streamlit app retained for reference only
