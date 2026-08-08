# SOAR Playbook Production Roadmap

This roadmap is the active delivery plan for turning the repo into a production-ready SOAR platform.

## Tracking model

- `Now`: work that should start next
- `Next`: work that should follow after the current slice is stable
- `Later`: work that depends on earlier platform hardening

## Guiding principles

- Keep `services/workflow_service.py` as the orchestration center.
- Keep `engine/` focused on policy and decisioning, not vendor APIs.
- Move vendor-specific behavior into `integrations/`.
- Prefer small vertical slices over broad scaffolding with no runtime value.
- Do not couple the core workflow to any single SIEM.

## Phase 0: Repo simplification

Status: `Now`

Goals:

- remove deprecated `a2a` collaboration code
- reduce dead code and stale docs
- make the repo easier to reason about before adding production features

Deliverables:

- [x] remove `a2a` API routes and auth roles
- [x] remove `a2a` package, tests, and docs
- [x] add this roadmap document
- [x] run full regression suite after cleanup

Definition of done:

- no runtime code depends on `a2a`
- no docs tell contributors to use `a2a`
- the test suite passes after removal

## Phase 1: Integration layer

Status: `Now`

Goals:

- isolate all external-system behavior behind explicit provider contracts
- stop mixing orchestration logic with vendor logic

Deliverables:

- [ ] create `integrations/` package
- [ ] define contracts for:
- source connector
- action connector
- ticketing connector
- CMDB connector
- threat-intel connector
- [ ] add provider registry/factory driven by config
- [ ] move current mock actions and intel adapters behind the new contracts
- [ ] add one end-to-end mocked integration test through the new layer

Suggested structure:

```text
integrations/
|-- contracts.py
|-- registry.py
|-- sources/
|-- actions/
|-- ticketing/
|-- cmdb/
`-- intel/
```

Definition of done:

- `engine/` no longer imports vendor-specific implementations directly
- provider selection is config-driven
- current behavior still works with mock/default providers

## Phase 2: Policy lifecycle and governance

Status: `Next`

Goals:

- make policy changes safe to ship
- support production rollout discipline

Deliverables:

- [ ] add policy metadata:
- `version`
- `status`
- `owner`
- `change_reason`
- `created_at`
- [ ] add `dry_run` execution mode
- [ ] add approval matrix by `action`, `risk_level`, and `asset_criticality`
- [ ] add canary rollout controls:
- hostname pattern
- asset tag
- workspace or environment
- percentage-based rollout
- [ ] add rule test fixtures and replay command
- [ ] store policy version on incident and action records

Definition of done:

- policy can be evaluated without live execution
- rollout can be limited to a subset of traffic
- incidents record which policy version decided them

## Phase 3: Incident correlation and deduplication

Status: `Next`

Goals:

- stop using only `alert_id` as the dedup key
- group related alerts into a shared incident timeline

Deliverables:

- [ ] add correlation service
- [ ] define fingerprints using:
- hostname
- username
- file hash
- process name
- destination IP
- [ ] add configurable correlation windows such as `15m`, `1h`, `24h`
- [ ] support outcomes:
- create new incident
- attach alert to existing incident
- reopen closed incident
- [ ] add persistence for related alerts and correlation evidence
- [ ] expose correlation details in API and dashboard

Definition of done:

- repeated related alerts can consolidate into one incident
- analysts can see why alerts were correlated

## Phase 4: Observability and operational safety

Status: `Next`

Goals:

- make the platform operable under failure
- make downstream issues diagnosable

Deliverables:

- [ ] structured JSON logging with:
- `alert_id`
- `incident_id`
- `correlation_id`
- `policy_version`
- `provider`
- [ ] metrics for:
- request rate and latency
- action latency
- queue depth
- retry count
- dead-letter count
- approval backlog
- [ ] tracing across:
- ingest
- enrichment
- policy evaluation
- dispatch
- worker execution
- [ ] timeout, retry, rate-limit, and circuit breaker wrappers for downstream APIs

Definition of done:

- failed action paths are observable without reading raw logs manually
- downstream dependency failures do not cascade silently

## Phase 5: Human-in-the-loop workflow

Status: `Later`

Goals:

- support safe analyst intervention for impactful actions

Deliverables:

- [ ] approval SLA tracking
- [ ] escalation path for overdue approvals
- [ ] comment history and operator rationale
- [ ] reopen and rollback workflow
- [ ] chat or ticket synchronization hooks
- [ ] append-only audit trail for approvals and case state changes

Definition of done:

- every manual intervention is attributable and reviewable
- pending approvals can be monitored and escalated

## Phase 6: Integration test strategy

Status: `Later`

Goals:

- validate adapters against realistic data and provider behavior

Deliverables:

- [ ] contract tests for inbound webhook payloads
- [ ] sanitized replay datasets from SIEM and EDR sources
- [ ] sandbox integration tests per vendor connector
- [ ] deterministic replay tests for policy and correlation logic
- [ ] browser smoke tests for analyst approval and incident review flows

Definition of done:

- provider regressions are caught before deployment
- sanitized real-world payloads can be replayed locally

## Phase 7: Deployment and platform operations

Status: `Later`

Goals:

- make the project deployable across dev, staging, and production

Deliverables:

- [ ] Docker images for API, worker, and dashboard
- [ ] environment-specific config separation
- [ ] CI pipeline for lint, test, build, and image publish
- [ ] CD pipeline for staging and production rollout
- [ ] Postgres migration workflow
- [ ] IaC for runtime dependencies

Definition of done:

- the system can be promoted across environments predictably
- database changes are versioned and reversible

## Phase 8: Wazuh integration

Status: `Later`

Goals:

- connect the repo to your current SIEM without making SIEM the core of the design

Deliverables:

- [ ] build `WazuhSourceConnector`
- [ ] support webhook or polling ingest path
- [ ] normalize Wazuh alerts into the canonical alert schema
- [ ] map Wazuh rule metadata, MITRE fields, host context, and IOC fields
- [ ] add sanitized Wazuh replay fixtures

Definition of done:

- Wazuh alerts can enter the workflow without custom logic leaking into `engine/` or `services/`

## Recommended implementation order

1. Finish Phase 0 and verify the repo is stable.
2. Deliver Phase 1 with mock providers first.
3. Add Phase 2 `dry_run` before any real destructive integration.
4. Add Phase 3 correlation before scaling ingest volume.
5. Add Phase 4 observability before production pilots.
6. Add Wazuh only after the integration contracts are stable.

## First sprint backlog

- [ ] scaffold `integrations/contracts.py`
- [ ] scaffold `integrations/registry.py`
- [ ] wrap current hash/IP intel implementations behind contracts
- [ ] wrap current actions behind action connector contracts
- [ ] add `dry_run` config path to policy execution
- [ ] add structured logging helper
- [ ] write a design note for correlation fingerprint rules
