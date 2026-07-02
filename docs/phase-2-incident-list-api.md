# Phase 2 Incident List API

## Scope

Expose recent incident summaries for analyst workflows without changing the existing by-alert or by-ticket contracts.

## API

- Added `GET /api/v1/incidents`
- Supported query params:
  - `limit`
  - `status`
  - `risk_level`
  - `hostname`
  - `ticket_id`

## Behavior

- Returns summary rows only, not the full hydrated incident payload.
- Ordering remains newest first by incident id.
- Existing read endpoints remain unchanged:
  - `GET /api/v1/incidents/by-alert/{alert_id}`
  - `GET /api/v1/incidents/by-ticket/{ticket_id}`

## Files changed

- `storage/sqlite_repository.py`
- `services/workflow_service.py`
- `api/schemas.py`
- `api/app.py`
- `tests/test_sqlite_repository.py`
- `tests/test_api_app.py`

## Verification

Command run:

```text
python -m pytest tests/test_sqlite_repository.py tests/test_api_app.py
```

Exact result:

- `11 passed`
- `180 warnings`
