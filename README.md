# SOAR Playbook - Automated Malware Alert Response on Endpoints

<div align="center">

![Python](https://img.shields.io/badge/Python-3.13%20validated-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-API%20Layer-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Primary%20Dashboard-61DAFB?style=for-the-badge&logo=react&logoColor=0B1020)
![Supabase](https://img.shields.io/badge/Supabase-Postgres%20Persistence-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Live%20Hash%20Intel-394EFF?style=for-the-badge)
![pytest](https://img.shields.io/badge/pytest-63%20tests%20passing-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
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

This project simulates how a Blue Team or SOC automation flow would handle an endpoint malware alert in a structured, explainable way.

Instead of stopping at a single detection rule or a standalone enrichment script, the repo now models a fuller incident-response path:

1. accept an alert from CLI, API, or dashboard
2. enrich the alert with threat intelligence and asset context
3. map behavior to MITRE ATT&CK
4. calculate a normalized risk score
5. apply policy-driven response actions
6. generate analyst-readable reports
7. persist the incident for replay, history, and investigation

The main goal of the project is to show system design, security awareness, and analyst workflow thinking, not just isolated automation snippets.

---

## What Is Implemented

The current repo is already beyond a local-only demo. The following areas are working in the project today:

- Shared orchestration through `services/workflow_service.py`
- FastAPI incident processing and incident history API
- React dashboard as the primary UI
- Supabase Postgres as the default runtime persistence target
- SQLite-backed explicit local/test flows
- VirusTotal-backed live hash enrichment path
- Policy-as-data with YAML-backed rule loading
- Queue-ready execution trace and correlation metadata
- Idempotent replay for repeated `alert_id` processing
- Report artifact storage for Markdown, HTML, and optional PDF
- A2A collaboration bus for multi-agent workflows
- RBAC-protected incident and A2A APIs
- Security regression coverage for auth, redaction, spoofing, and HTML report escaping

Recent dashboard improvements completed in this repo:

- real FastAPI-backed alert intake
- live incident stream and priority queue refresh after `Process Alert`
- Markdown report preview in incident detail
- `Open HTML report` action in the detail panel
- execution trace rendering in the UI
- enrichment source visibility for hash and IP intel
- operator-only sensitive detail reads
- rejection of sanitized/redacted payload re-processing

---

## End-to-End Workflow

The pipeline currently works like this:

### 1. Alert intake

The system accepts a malware alert payload with fields such as:

- `alert_id`
- `hostname`
- `username`
- `process_name`
- `file_path`
- `file_hash`
- `parent_process`
- `command_line`
- `destination_ip`
- `severity`
- `detection_name`

### 2. Threat enrichment

The workflow enriches:

- file hash intelligence
- destination IP intelligence
- asset criticality
- MITRE ATT&CK mappings

Hash enrichment can run against VirusTotal when:

```env
SOAR_INTEL_PROVIDER=virustotal
VIRUSTOTAL_API_KEY=...
```

### 3. Risk scoring

The enriched alert is scored and normalized into a risk level such as:

- `low`
- `medium`
- `high`
- `critical`

### 4. Policy evaluation

The policy engine evaluates response rules and produces:

- triggered actions
- action results
- policy reasoning
- execution trace

### 5. Response actions

Depending on the scenario, the flow can:

- isolate host
- kill process
- block IP
- escalate
- create ticket
- notify SOC

### 6. Report generation

The system can generate:

- Markdown report
- HTML report
- PDF report when supported

### 7. Persistence and replay

The incident, action results, and report metadata are stored so the analyst can reopen them later from the dashboard or API.

---

## Current Architecture

```text
+--------------------------------------------------------------------------------------+
|                               SOAR Playbook Architecture                             |
+--------------------------------------------------------------------------------------+
| Entry points                                                                         |
|                                                                                      |
|   main.py                     api/app.py                   dashboard/src              |
|   CLI                         FastAPI                      React analyst console      |
|      \                           |                                /                  |
|       \                          |                               /                   |
|        +-------------------------+------------------------------+                    |
|                                  |                                                   |
|                     services/workflow_service.py                                      |
|                     Shared orchestration layer                                        |
|                                  |                                                   |
+----------------------------------+---------------------------------------------------+
| Enrichment and analysis          | Policy and response       | Output and storage     |
|                                  |                           |                        |
| enrichment/hash_intel.py         | engine/policy_loader.py   | reporting/report_      |
| enrichment/ip_intel.py           | engine/policy_engine.py   | generator.py           |
| enrichment/asset_db.py           | engine/action_dispatcher  | storage/incident_      |
| enrichment/mitre_mapping.py      | actions/*                 | repository.py          |
| engine/risk_scoring.py           |                           | storage/postgres.py    |
|                                  |                           | storage/sqlite_        |
|                                  |                           | repository.py          |
+----------------------------------+---------------------------+------------------------+
| Security and collaboration                                                            |
|                                                                                      |
| security/auth.py                 RBAC, bearer auth, redaction defaults               |
| a2a/*                            workspace, task, message, artifact coordination     |
+--------------------------------------------------------------------------------------+
| Primary UI: React dashboard                                                           |
| Legacy UI kept only for reference: dashboard/app.py                                   |
| Default runtime persistence: Supabase/Postgres                                        |
| Explicit local/test persistence: SQLite                                               |
+--------------------------------------------------------------------------------------+
```

### Entry points

- `main.py`
- `api/app.py`
- `dashboard/src/`
- `a2a/cli.py`

### Shared orchestration

- `services/workflow_service.py`

This service is the main coordination layer reused by CLI, API, and dashboard flows.

### Main backend domains

- `enrichment/` for threat intel, MITRE mapping, and asset context
- `engine/` for scoring, policy loading, and policy evaluation
- `actions/` for response execution
- `reporting/` for report generation
- `storage/` for repositories and persistence adapters
- `security/` for auth and RBAC
- `a2a/` for collaboration bus workflows

### Persistence path

- default runtime: Supabase/Postgres
- explicit local/test path: SQLite when a local database target is passed on purpose

### UI model

- primary UI: `dashboard/src/`
- legacy UI: `dashboard/app.py`

`dashboard/app.py` is kept only as a legacy reference and is no longer the main dashboard experience.

---

## React Dashboard

The React dashboard is now the main analyst console for the project.

### Main panels

- Alert Intake
- Priority Queue
- Incident Stream
- Incident Detail

### Incident detail view

The detail panel currently shows:

- risk summary
- host and process context
- threat telemetry
- automated response results
- policy reasoning
- MITRE ATT&CK coverage
- execution trace
- report artifact paths
- Markdown report preview
- HTML report link
- raw alert payload

### Dev proxy model

The dashboard uses the FastAPI backend through the Vite proxy in `dashboard/vite.config.ts`.

That local proxy:

- reads repo-root `.env.local`
- forwards `/soar-api/*` to FastAPI
- forwards the browser's `Authorization` header unchanged

The dashboard now expects each browser tab to carry its own bearer token in `sessionStorage`, so the proxy no longer injects a shared operator credential.

---

## Security and Sensitive Data Handling

Bearer-token auth is required for protected API routes.

### Incident roles

- `incident_process`
- `incident_read`

### A2A roles

- `a2a_admin`
- `a2a_read`
- `a2a_agent`

### Redaction behavior

Sensitive incident fields are still redacted by default in API-facing incident detail responses:

- `username`
- `command_line`
- `file_hash`
- `file_path`

### Operator-only access

The React dashboard now reads incident detail with `include_sensitive=true`, but only principals with `incident_process` are allowed to access that path. Read-only principals still receive redacted values.

### Intake guardrail

Sanitized dashboard/API output is now rejected if someone tries to process it again as a fresh alert.

This prevents incorrect re-processing of payloads that already contain values such as:

- `[redacted]`
- `[redacted-path]`
- zeroed hashes like `0000...`

To get correct enrichment and policy results, the intake form must receive the original raw alert JSON.

---

## Persistence Model

Default runtime persistence expects Supabase/Postgres.

Stored entities include:

- alerts
- incidents
- action results
- reports
- A2A workspaces
- agents
- tasks
- messages
- artifacts
- timeline data

Important behavior already implemented:

- repeated processing of the same `alert_id` is idempotent
- missing report artifacts can be materialized on replay
- incident detail reads can hydrate Markdown content from stored report paths

---

## Setup and Run

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install dashboard dependencies

```bash
npm --prefix dashboard install
```

### 3. Configure environment

Create a local `.env.local` from `.env.example` and set at least:

```env
SUPABASE_DB_URL=postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require
SOAR_INTEL_PROVIDER=virustotal
VIRUSTOTAL_API_KEY=
SOAR_AUTH_TOKENS_JSON={"tokens":[{"token":"<generate-a-long-random-token>","principal_id":"incident-operator","principal_type":"user","roles":["incident_process","incident_read"],"workspaces":["*"]}]}
SOAR_API_PROXY_TARGET=http://127.0.0.1:8000
```

### 4. Run FastAPI

```bash
python -m uvicorn api.app:app --reload
```

### 5. Run the React dashboard

```bash
npm --prefix dashboard run dev
```

When the dashboard opens, paste the operator bearer token into the session prompt shown in the UI. The token is stored only in that browser tab's `sessionStorage`.

### 6. Optional CLI smoke run

```bash
python main.py --scenario mixed --no-report
```

### 7. Run tests

```bash
pytest tests -q
```

---

## Main API Routes

Core incident routes:

- `GET /health`
- `GET /api/v1/dashboard/bootstrap`
- `POST /api/v1/incidents/process`
- `POST /api/v1/incidents/process-scenario`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/by-alert/{alert_id}`
- `GET /api/v1/incidents/by-alert/{alert_id}/report/html`
- `GET /api/v1/incidents/by-ticket/{ticket_id}`

Important route behavior:

- `GET /api/v1/incidents/by-alert/{alert_id}?include_sensitive=true`
  - allowed for `incident_process`
  - denied for read-only principals
- `POST /api/v1/incidents/process`
  - rejects sanitized/redacted payloads with HTTP `422`

A2A collaboration routes are also available under `/api/v1/a2a/*`.

---

## Project Structure

```text
SOAR Playbook/
|-- actions/
|-- a2a/
|-- alert_generator/
|-- api/
|-- dashboard/
|   |-- app.py
|   |-- src/
|   `-- vite.config.ts
|-- data/
|   `-- sample_alerts/
|-- docs/
|-- engine/
|-- enrichment/
|-- output/
|-- policies/
|-- reporting/
|-- schemas/
|-- security/
|-- services/
|-- storage/
|-- tests/
|-- .env.example
|-- main.py
`-- README.md
```

---

## Verification Snapshot

Latest verified in this repo on 2026-07-02:

- `pytest tests -q` -> `63 passed`
- `cmd /c npm run build` in `dashboard/` -> passed
- live Supabase persistence path verified through incident processing
- live VirusTotal-backed enrichment path exercised in the workflow

Recommended companion docs:

- `docs/supabase-setup.md`
- `docs/upgrade-roadmap.md`
- `docs/three-codex-team.md`
- `docs/a2a-collaboration.md`
- `docs/pentest-report-2026-07-02.md`

---

## Notes Before Adding New Work

If you are about to process a custom alert through the dashboard:

- use the original raw alert JSON
- do not paste incident detail output that already shows `[redacted]` fields or a zeroed hash
- if you need to re-test an existing incident, clone the original source payload instead of copying the redacted detail view
