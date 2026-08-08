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

Status: `Complete for current slice`

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

Status: `Complete for current slice`

Goals:

- isolate all external-system behavior behind explicit provider contracts
- stop mixing orchestration logic with vendor logic

Deliverables:

- [x] create `integrations/` package
- [x] define contracts for:
- source connector
- action connector
- ticketing connector
- CMDB connector
- threat-intel connector
- [x] add provider registry/factory driven by config
- [x] move current mock actions and intel adapters behind the new contracts
- [x] add one end-to-end mocked integration test through the new layer

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

Status: `Complete for current slice`

Goals:

- make policy changes safe to ship
- support production rollout discipline

Deliverables:

- [x] add policy metadata:
- `version`
- `status`
- `owner`
- `change_reason`
- `created_at`
- [x] add `dry_run` execution mode
- [x] add approval matrix by `action`, `risk_level`, and `asset_criticality`
- [x] add canary rollout controls:
- hostname pattern
- asset tag
- workspace or environment
- percentage-based rollout
- [x] add rule test fixtures and replay command
- [x] store policy version on incident and action records

Definition of done:

- policy can be evaluated without live execution
- rollout can be limited to a subset of traffic
- incidents record which policy version decided them

## Phase 3: Incident correlation and deduplication

Status: `Complete for current slice`

Goals:

- stop using only `alert_id` as the dedup key
- group related alerts into a shared incident timeline

Deliverables:

- [x] add correlation service
- [x] define fingerprints using:
- hostname
- username
- file hash
- process name
- destination IP
- [x] add configurable correlation windows such as `15m`, `1h`, `24h`
- [x] support outcomes:
- create new incident
- attach alert to existing incident
- reopen closed incident
- [x] add persistence for related alerts and correlation evidence
- [x] expose correlation details in API and dashboard
- [x] add regression coverage for grouped, reopened, and out-of-window alerts

Definition of done:

- repeated related alerts can consolidate into one incident
- analysts can see why alerts were correlated
- full `pytest` suite passes with correlation enabled

## Phase 4: Observability and operational safety

Status: `Complete for current slice`

Goals:

- make the platform operable under failure
- make downstream issues diagnosable

Deliverables:

- [x] structured JSON logging with:
- `alert_id`
- `incident_id`
- `correlation_id`
- `policy_version`
- `provider`
- [x] metrics for:
- request rate and latency
- action latency
- queue depth
- retry count
- dead-letter count
- approval backlog
- [x] tracing across:
- ingest
- enrichment
- policy evaluation
- dispatch
- worker execution
- [x] timeout, retry, rate-limit, and circuit breaker wrappers for downstream APIs
- [x] expose readiness and observability snapshots through API and dashboard runtime views
- [x] add regression tests for readiness payloads, queue metrics, and downstream guard behavior

Definition of done:

- failed action paths are observable without reading raw logs manually
- downstream dependency failures do not cascade silently

## Phase 5: Human-in-the-loop workflow

Status: `Complete for current slice`

Goals:

- support safe analyst intervention for impactful actions

Deliverables:

- [x] approval SLA tracking
- [x] escalation path for overdue approvals
- [x] comment history and operator rationale
- [x] reopen and rollback workflow
- [x] chat or ticket synchronization hooks
- [x] append-only audit trail for approvals and case state changes

Definition of done:

- every manual intervention is attributable and reviewable
- pending approvals can be monitored and escalated

## Phase 6: Integration test strategy

Status: `Complete for current slice`

Current slice:

- sanitized source replay fixtures now cover Wazuh-like SIEM payloads and Microsoft Defender-like EDR payloads
- local replay harness validates normalization, policy evaluation, and correlation without calling live vendors
- connector sandbox tests now cover:
- local action connector side effects
- local ticketing JSON adapter
- local ticketing webhook adapter
- HTTP CMDB adapter
- mock threat-intel adapter
- dashboard Playwright smoke tests are present and passing for incident review and report access flows

Goals:

- validate adapters against realistic data and provider behavior

Deliverables:

- [x] contract tests for inbound webhook payloads
- [x] sanitized replay datasets from SIEM and EDR sources
- [x] sandbox integration tests per vendor connector
- [x] deterministic replay tests for policy and correlation logic
- [x] browser smoke tests for analyst approval and incident review flows

Definition of done:

- provider regressions are caught before deployment
- sanitized real-world payloads can be replayed locally

## Phase 7: Deployment and platform operations

Status: `In progress`

Current slice:

- Docker packaging exists for API, worker, and dashboard, with Compose manifests for both local build-based runs and GHCR image-based release rollouts
- environment profiles under `config/environments/` are validated by test and CLI
- CI now covers env validation, backend regression, frontend build, Compose rendering, and Docker image build steps
- CD workflow exists for manual `staging` or `production` rollout over SSH using GitHub environment approvals and GHCR images
- ordered Postgres migrations are packaged and executable from the repository or API image
- local runtime image builds were not verified in this session because the Docker daemon was unavailable

Goals:

- make the project deployable across dev, staging, and production

Deliverables:

- [x] Docker images for API, worker, and dashboard
- [x] environment-specific config separation
- [x] CI pipeline for lint, test, build, and image publish
- [x] CD pipeline for staging and production rollout
- [x] Postgres migration workflow
- [ ] IaC for runtime dependencies

Definition of done:

- the system can be promoted across environments predictably
- database changes are versioned and reversible

## Phase 8: Wazuh integration

Status: `Partial foundation done`

Current slice:

- `WazuhSourceConnector` exists for local normalization and replay coverage
- sanitized Wazuh fixtures are bundled for deterministic offline validation

Goals:

- connect the repo to your current SIEM without making SIEM the core of the design

Deliverables:

- [x] build `WazuhSourceConnector`
- [ ] support webhook or polling ingest path
- [x] normalize Wazuh alerts into the canonical alert schema
- [ ] map Wazuh rule metadata, MITRE fields, host context, and IOC fields
- [x] add sanitized Wazuh replay fixtures

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

- [x] scaffold `integrations/contracts.py`
- [x] scaffold `integrations/registry.py`
- [x] wrap current hash/IP intel implementations behind contracts
- [x] wrap current actions behind action connector contracts
- [x] add `dry_run` config path to policy execution
- [x] add policy metadata/version snapshot to incident responses
- [x] add approval matrix and canary rollout governance to policy execution
- [x] add replayable policy fixture suite and command
- [x] add structured logging helper
- [ ] write a design note for correlation fingerprint rules
