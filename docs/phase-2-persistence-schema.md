# Phase 2 Persistence Notes

- No destructive migration was required. The existing `alerts`, `incidents`, `action_results`, and `reports` tables already covered the Phase 2 storage contract.
- Added `idx_incidents_ticket_id` to support incident lookup by `ticket_id` without changing write semantics.
- Repository reads now hydrate the stored alert payload, normalized action results, persisted response payload, and report artifact metadata from one lookup path.
- API surface added:
  - `GET /api/v1/incidents/by-alert/{alert_id}`
  - `GET /api/v1/incidents/by-ticket/{ticket_id}`
- Existing process endpoints and `alert_id` upsert behavior remain unchanged.
