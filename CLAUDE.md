# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SOAR playbook for malware endpoint alerts: FastAPI backend + background remediation worker + React/Vite dashboard. Python 3.13, Pydantic v2. `README.md` has the full env-var tables and deployment notes; `docs/architecture.md` has diagrams.

## Commands

Backend (run from repo root):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                                   # full suite (tests/ only; cache goes to output/.pytest_cache)
pytest tests/test_policy_engine.py -k name  # single file / single test
python3 -m uvicorn api.app:app --reload      # API
python3 scripts/run_remediation_worker.py    # queue worker (needed when execution mode is queued)
python3 main.py --scenario mixed             # CLI; or --alert data/sample_alerts/alert_04_full_critical.json
python3 scripts/validate_env.py config/environments/development.env
python3 -m compileall api actions alert_generator engine enrichment integrations observability reporting schemas security services storage scripts   # CI "static validation"
```

Dashboard:

```bash
npm --prefix dashboard install
npm --prefix dashboard run dev      # Vite on :5173, proxies /soar-api -> SOAR_API_PROXY_TARGET (default 127.0.0.1:8000)
npm --prefix dashboard run build    # tsc typecheck (app + node configs) + vite build; this is the only "lint/typecheck"
```

There is no linter configured. `./start-local.sh` / `./stop-local.sh` run the whole local stack in the background (pidfiles in `output/run/`, logs in `output/logs/`; needs `.env.local`); `npm --prefix dashboard run test:smoke` runs Playwright via `dashboard/run-playwright-smoke.sh` after a build. CI (`.github/workflows/ci.yml`) runs env validation, compileall, pytest, dashboard build, compose render, and three Docker builds (api / worker targets of `docker/Dockerfile.backend`, plus dashboard).

## Architecture

All entrypoints (`main.py` CLI, `api/app.py` HTTP, `scripts/run_remediation_worker.py`) funnel into **`services/workflow_service.py` (`SoarWorkflowService`)**, which orchestrates:

1. Workspace normalization (`workspace_utils.py`) and replay/idempotency check by `alert_id`.
2. `enrichment/` `EnrichmentPipeline`: hash intel, IP intel, asset (CMDB) lookup, MITRE mapping, then `engine/risk_scoring.py`. Providers are swappable (`mock` / `virustotal` / `file` / `http`) via env.
3. `engine/policy_engine.py` evaluates rules from `policies/response_rules.yaml` (loaded/validated by `engine/policy_loader.py`) — policy is data, not code. Execution mode is `sync`, `queued`, or `dry_run`; approval rules and canary gating live in the same YAML. `engine/policy_replay.py` + `policies/` fixtures + `scripts/replay_policy_fixtures.py` replay policy changes against fixtures.
4. `engine/action_dispatcher.py` runs actions immediately or publishes to the queue; `actions/` holds the local mock remediation/ticketing adapters.
5. `services/incident_correlation.py` decides new incident vs. attach/reopen (strategies configured under `correlation:` in the policy YAML).
6. `reporting/` writes Markdown/HTML/optional PDF into `output/`.
7. `storage/incident_repository.py` persists everything; `services/remediation_queue.py` (`AsyncRemediationWorker`) claims queued jobs with retry/dead-letter.

Cross-cutting: `integrations/` (source connectors: passthrough / wazuh / microsoft_defender; connector factories chosen by `SOAR_*_PROVIDER/CONNECTOR` env vars), `observability/` (metrics, traces, resilience guards wrapping connectors), `security/auth.py` (bearer tokens from `SOAR_AUTH_TOKENS_JSON`, roles `incident_read` / `incident_process`, workspace scoping).

### Persistence backends (important gotcha)

Repo selection is by `SOAR_DB_TARGET` (file path → SQLite, DSN → Postgres), falling back to `SOAR_DATABASE_URL`, `SUPABASE_DB_URL`, then `SOAR_SQLITE_FALLBACK_PATH` (`output/soar-local.db`). `storage/sqlite_repository.py` and the Postgres `SupabaseIncidentRepository` (`storage/incident_repository.py`) implement the same `IncidentRepositoryProtocol` and are meant to stay in parity — port any change to both. Postgres schema changes go in ordered SQL under `migrations/postgres/` (applied by `scripts/apply_postgres_migrations.py`); `PostgresDatabase` also runs idempotent `CREATE/ALTER ... IF NOT EXISTS` on startup. Postgres tests in `tests/test_workflow_service.py` skip unless `SOAR_TEST_POSTGRES_URL` points at a throwaway DB.

### API and dashboard

- API routes live in `api/app.py` under `/api/v1/...` (incident process, list, by-alert detail/notes/approve/reject/rollback/reopen/report, saved filters, readiness, observability); schemas in `api/schemas.py`. Incident responses are redacted unless an operator requests `include_sensitive=true`. HTML reports are served only via a path-constrained lookup under `output/`.
- `api/app.py` caches the workflow service via `get_workflow_service` (`lru_cache`); tests must call `cache_clear()` after changing env.
- Dashboard (`dashboard/src/`): token held in `sessionStorage`; never embed a shared service credential. Dev uses the Vite proxy, Vercel uses `dashboard/api/*` proxy handlers, Docker serves the static build through Nginx. `dashboard/app.py` is a legacy Streamlit UI — not built, not tested, not primary.

## Testing notes

`tests/conftest.py` has autouse fixtures that force `SOAR_INTEL_PROVIDER=mock`, blank `SUPABASE_DB_URL`/`VIRUSTOTAL_API_KEY`, clear the cached service/auth, and reset observability — so local `.env.local` values never leak into tests. Keep new tests behind those fixtures rather than touching live services. `tests/test_security_regressions.py` guards the auth/redaction/report-escaping fixes; extend it when touching those areas.

## Stale references

`.agents/a2a-playbook.md` describes an `a2a` CLI that was deleted from the repo; ignore it. README test counts/badges are out of sync with each other.
