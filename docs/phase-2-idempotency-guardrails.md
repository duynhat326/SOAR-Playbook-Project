# Phase 2 Idempotency and Incident Query Guardrails

## Scope

Close the remaining Phase 2 gaps without changing the existing incident read or list response contracts.

## Replay / idempotency strategy

- `alert_id` is now the replay key for persisted incident processing.
- When `SoarWorkflowService` receives an alert whose incident already exists in SQLite, it returns the stored workflow result instead of rerunning enrichment, policy evaluation, or downstream actions.
- This keeps repeated processing requests from creating duplicate tickets, duplicate SOC notifications, or duplicate remediation side effects.

## Incident list guardrails

- `GET /api/v1/incidents` now validates `limit` at the API boundary with:
  - minimum: `1`
  - maximum: `200`
  - default: `50`
- `storage/sqlite_repository.py` enforces the same range for non-HTTP callers.
- Recent-first ordering and the existing summary-row response shape are unchanged.
- Existing `by-alert` and `by-ticket` contracts are unchanged.

## Files changed

- `services/workflow_service.py`
- `storage/sqlite_repository.py`
- `api/app.py`
- `tests/test_workflow_service.py`
- `tests/test_sqlite_repository.py`
- `tests/test_api_app.py`

## Verification

Command run:

```text
python -m pytest tests/test_sqlite_repository.py tests/test_workflow_service.py tests/test_api_app.py
```

Exact result:

- `16 passed`
- `209 warnings`

## Notes

- API limit validation was verified through the generated OpenAPI schema because the local Starlette `TestClient` import requires an unavailable `httpx2` package in this environment.
