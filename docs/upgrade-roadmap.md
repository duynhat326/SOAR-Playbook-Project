# SOAR Playbook upgrade roadmap

This file tracks what is already done in the repo and what should come next.

## Current position

The project is no longer only a local malware-playbook demo.

It now has:

- shared orchestration across CLI, API, and dashboard
- FastAPI incident processing and incident history APIs
- React dashboard as the main UI
- Supabase/Postgres default persistence
- SQLite-backed local/test flows when explicitly requested
- policy-as-data through YAML
- queue-ready execution trace and correlation hooks
- RBAC and security regression tests
- live VirusTotal-backed hash enrichment path
- persisted Markdown/HTML report artifacts with dashboard preview

## Completed phases

### Phase 0 - shared orchestration

Status: done

Delivered:

- central workflow service
- CLI, API, and dashboard aligned on the same orchestration path
- idempotent replay behavior

### Phase 1 - API surface

Status: done

Delivered:

- health route
- dashboard bootstrap route
- incident process routes
- incident list/detail routes
- report HTML artifact route

### Phase 2 - persistence

Status: done for current scope

Delivered:

- structured incident persistence
- report artifact persistence
- incident lookup by `alert_id`
- incident lookup by `ticket_id`
- list APIs for incident stream views
- Supabase/Postgres default runtime target

Still open:

- stronger migration/versioning discipline
- longer-lived audit/report retention strategy

### Phase 3 - policy as data

Status: done for current scope

Delivered:

- YAML-backed rule loading
- thresholds and guards support
- execution mode config
- correlation field config
- fallback behavior for invalid policy files

### Phase 4 - real integrations

Status: partial

Delivered:

- live VirusTotal hash enrichment path
- fallback-safe runtime behavior when live intel is unavailable

Still open:

- richer real IP intel provider
- real CMDB adapter
- real ticketing adapter
- more robust timeout/retry/rate-limit handling

### Phase 5 - analyst experience

Status: baseline done

Delivered:

- React dashboard is now the main UI
- connected intake against FastAPI
- incident stream
- priority queue/watchlist
- incident detail deep dive
- Markdown report preview
- HTML report open action
- execution trace panel
- enrichment source visibility

Still open:

- analyst approval flows
- richer filtering and saved views
- browser automation coverage

### Phase 6 - queue and async boundary

Status: partial foundation done

Delivered:

- execution trace in incident responses
- correlation hooks in queue-ready metadata
- queue-mode aware policy execution model

Still open:

- real queue publisher
- worker processes
- retry and dead-letter handling
- analyst-visible async action lifecycle

## Recently completed work

These items were finished in the latest dashboard/API hardening pass:

- React dashboard became the primary supported UI
- old dashboard links/docs were redirected toward React-first usage
- Supabase alert persistence path was re-verified
- live VirusTotal enrichment path was exercised
- Vite dev proxy now reads repo-root env and injects auth server-side
- detail view now shows report preview, report HTML link, and execution trace
- priority queue updates immediately after `Process Alert`
- operator-only incident detail reads can include sensitive fields
- sanitized/redacted payloads are rejected at intake instead of being re-processed

## Recommended next phases

### 1. Real async remediation

Priority: high

Build:

- queue publisher abstraction backed by a real queue
- worker execution service
- action retry policy
- failure recovery and dead-letter handling

### 2. Better analyst workflow

Priority: high

Build:

- action approval/rejection flow
- host/user/history drilldowns
- incident notes and case-state tracking
- bulk triage operations

### 3. Stronger external integrations

Priority: medium

Build:

- real IP reputation provider
- real CMDB asset adapter
- real ticketing/case management adapter
- environment-specific adapter selection

### 4. UI and browser regression coverage

Priority: medium

Build:

- Playwright smoke tests
- dashboard workflow regression checks
- report rendering checks through browser automation

### 5. Observability and operations

Priority: medium

Build:

- structured request tracing
- richer audit logging
- health/readiness checks for external dependencies
- production-style configuration validation

## Do not regress

Any new work should preserve:

- idempotent incident replay
- report artifact hydration
- React-first dashboard flow
- RBAC enforcement
- read-only redaction defaults
- operator-only sensitive field access
- intake rejection for redacted payloads
