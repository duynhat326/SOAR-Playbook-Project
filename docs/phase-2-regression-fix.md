# Phase 2 Incident Read Regression Fix

## Scope

Repair the incident read path regression in `storage/sqlite_repository.py` without changing process endpoint behavior.

## Files changed

- `storage/sqlite_repository.py`
  - `_get_incident(...)` now executes an interpolated SQL string so `WHERE incidents.alert_id = ?` and `WHERE incidents.ticket_id = ?` are applied instead of a literal `{where_clause}` token.
  - `get_incident_by_alert_id(...)` and `get_incident_by_ticket_id(...)` both use the shared read path.
- `api/app.py`
  - Read endpoints remain `GET /api/v1/incidents/by-alert/{alert_id}` and `GET /api/v1/incidents/by-ticket/{ticket_id}`.
- `api/schemas.py`
  - Typed incident read response remains aligned with hydrated repository payloads.
- `tests/test_sqlite_repository.py`
  - Covers by-ticket incident lookup and persisted payload hydration.
- `tests/test_api_app.py`
  - Covers by-alert read, by-ticket read, and missing ticket 404 behavior.

## Verification

Command run:

```text
python -m pytest tests/test_sqlite_repository.py tests/test_api_app.py
```

Exact result:

- `8 passed`
- `99 warnings`

## Notes

- Process endpoints were left unchanged.
- Warnings are pre-existing deprecation warnings around `datetime.utcnow()` and a pytest cache permission warning.
