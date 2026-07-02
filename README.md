# 🛡️ SOAR Playbook — Automated Malware Alert Response on Endpoints

<div align="center">

![Python](https://img.shields.io/badge/Python-3.13%20validated-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-API%20Layer-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Persistence-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![pytest](https://img.shields.io/badge/pytest-55%20tests%20passing-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Project-0078D4?style=for-the-badge)

**Blue Team CV Project — SOC Analyst Automation**

*An end-to-end SOAR playbook simulation for malware alerts:*
*from EDR alert → threat intel enrichment → MITRE mapping → risk scoring → policy evaluation → incident report*

</div>

---

## 📌 Table of Contents

- [Background & Goals](#-background--goals)
- [Quick Demo](#-quick-demo)
- [System Architecture](#-system-architecture)
- [7-Step Workflow](#-7-step-workflow)
- [Policy Engine — 4 Response Rules](#-policy-engine--4-response-rules)
- [Setup & Run](#-setup--run)
- [Project Structure](#-project-structure)
- [Tech Stack & Why It Was Chosen](#-tech-stack--why-it-was-chosen)
- [Sample Alerts — Test Cases](#-sample-alerts--test-cases)
- [Unit Tests](#-unit-tests)
- [Incident Report Output](#-incident-report-output)
- [Future Improvements](#-future-improvements)

---

## 🎯 Background & Goals

### The problem

In a real SOC environment, analysts spend a large amount of time repeating the same steps for every endpoint malware alert:

1. Receive the alert from EDR or SIEM.
2. Look up the file hash in VirusTotal or an equivalent threat intel source.
3. Check the destination IP in AbuseIPDB or a C2 feed.
4. Query the CMDB to understand how critical the host is.
5. Map the behavior to MITRE ATT&CK to understand tactics and techniques.
6. Decide whether to isolate, kill, block, or escalate.
7. Create a ticket, preserve evidence, and write an incident report.

**SOAR Playbook** simulates that entire response chain with a structured Python codebase that is easy to explain, easy to demo, and realistic enough to serve as a Blue Team / SOC portfolio project.

### Technical goals

- Show how to design a structured **SOAR workflow**, not just a collection of scripts.
- Use **Pydantic** to define stable data contracts between pipeline stages.
- Cleanly separate **enrichment**, **risk scoring**, **policy evaluation**, **action execution**, **reporting**, **persistence**, and **API**.
- Support multiple entry points: **CLI**, **FastAPI**, **Streamlit dashboard**, and an **A2A collaboration bus**.
- Provide **persistence + idempotent replay**, so the same `alert_id` does not repeat side effects unnecessarily.
- Support **policy-as-data** through YAML instead of hard-coding all rule behavior.
- Include **auth/RBAC and security regression coverage** for both the incident API and the A2A API.

### Current scope

This project is no longer only a policy-engine demo. It now includes:

- A **FastAPI layer** for incident processing and incident history lookup.
- **SQLite persistence** for incidents, action results, and report artifacts.
- A **local A2A collaboration bus** so multiple agents or tabs can coordinate work.
- **Auth + RBAC** for the incident API and A2A API using bearer tokens.
- **Sanitized report generation** to prevent stored HTML injection in analyst-facing reports.
- A **security regression pentest runner** to confirm those fixes stay in place.

---

## 🚀 Quick Demo

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the default scenario
python main.py --scenario mixed --no-report

# 3. Run the full critical sample alert
python main.py --alert data/sample_alerts/alert_04_full_critical.json

# 4. Start the API
python -m uvicorn api.app:app --reload

# 5. Start the dashboard
streamlit run dashboard/app.py

# 6. Run the test suite
pytest tests -q

# 7. Run the security regression pentest
python scripts/run_pentest.py
```

The following smoke checks were re-run on Windows on **2026-07-02**:

- `python main.py --scenario mixed --seed 2024 --no-report`
- `python main.py --alert data/sample_alerts/alert_04_full_critical.json --output-dir output\smoke-readme`
- `python -m a2a.cli ...` lifecycle smoke with authenticated tokens
- `pytest tests -q` → **55 passed**
- `python scripts/run_pentest.py` → **0 findings**

---

## 🏗️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                          SOAR Malware Playbook                            │
├────────────────────────────────────────────────────────────────────────────┤
│ Entry Points                                                               │
│                                                                            │
│   CLI (main.py)   FastAPI (api/app.py)   Streamlit (dashboard/app.py)     │
│          │                 │                        │                      │
│          └─────────────────┴──────────────┬─────────┘                      │
│                                           │                                 │
│                           services/workflow_service.py                      │
│                                           │                                 │
├───────────────────────────────────────────┼────────────────────────────────┤
│ Core Pipeline                             │ Collaboration                  │
│                                           │                                │
│  Step 1  Alert ingest / validate          │  a2a/cli.py                    │
│  Step 2  Hash enrichment                  │  a2a/service.py                │
│  Step 3  IP enrichment                    │  a2a/storage.py                │
│  Step 4  Asset criticality lookup         │  Workspace / Agent / Task      │
│  Step 5  MITRE ATT&CK mapping             │  Message / Artifact / Timeline │
│  Step 6  Risk scoring                     │                                │
│  Step 7  Policy evaluation + actions      │                                │
│                                           │                                │
├───────────────────────────────────────────┼────────────────────────────────┤
│ Output & Storage                          │ Security                       │
│                                           │                                │
│  Markdown / HTML / optional PDF report    │  security/auth.py              │
│  Ticket + action results                  │  Bearer auth                   │
│  SQLite incident repository               │  Role-based access control     │
│  Incident list / detail APIs              │  Agent identity binding        │
│  Replay / artifact materialization        │  Redaction + output sanitizing │
└────────────────────────────────────────────────────────────────────────────┘
```

### Main flow

1. An alert enters from JSON, the generator, the dashboard, or an HTTP request.
2. `EnrichmentPipeline` performs hash/IP/asset/MITRE enrichment.
3. `RiskScoringEngine` computes a normalized 0-100 risk score.
4. `PolicyEngine` applies built-in logic and YAML-configured rule behavior.
5. Mock response actions execute and return `ActionResult` records.
6. `ReportGenerator` creates Markdown + HTML, with optional PDF export.
7. `SQLiteIncidentRepository` persists the result for replay and API lookups.

### Collaboration layer

Besides the alert-processing workflow, the project includes an **internal A2A bus** for multi-agent coordination:

- Workspaces for sprint or scope isolation.
- Agent registration and heartbeat tracking.
- Task lifecycle: create / claim / complete.
- Agent-specific inbox polling.
- Artifact handoff for docs, notes, evidence, or patches.
- Timeline views so a lead agent can audit the full collaboration trail.

### Security boundary

After the hardening and pentest remediation pass:

- The incident API requires `incident_process` or `incident_read`.
- The A2A API requires `a2a_admin`, `a2a_read`, or `a2a_agent`.
- A2A write operations are **bound to the authenticated agent identity**, not just a caller-supplied `agent_id`.
- Incident responses **redact sensitive fields** such as `username`, `command_line`, `file_hash`, and `file_path`.
- HTML reports escape alert-controlled values before rendering.

---

## 🔄 7-Step Workflow

| Step | Name | Main Module | Description |
|------|------|-------------|-------------|
| **1** | Alert Intake | `schemas/alert.py` | Parse and validate the payload with Pydantic |
| **2** | Hash Enrichment | `enrichment/hash_intel.py` | Look up the file hash in a mock threat-intel database |
| **3** | IP Enrichment | `enrichment/ip_intel.py` | Look up destination IP reputation, confidence, and C2 flags |
| **4** | Asset Criticality | `enrichment/asset_db.py` | Query a mock CMDB to estimate business impact |
| **5** | MITRE ATT&CK Mapping | `enrichment/mitre_mapping.py` | Map process name and command line to ATT&CK techniques |
| **6** | Risk Scoring | `engine/risk_scoring.py` | Compute weighted risk score and risk level |
| **7** | Policy + Actions | `engine/policy_engine.py` | Evaluate rules, execute actions, create a ticket, notify SOC |

### Risk scoring formula

```text
Risk Score (0-100) =
    Hash Reputation    × 30%
  + IP / C2 Signal     × 25%
  + Asset Criticality  × 20%
  + Alert Severity     × 15%
  + MITRE Context      × 10%
```

### Risk level mapping

| Score | Risk Level |
|-------|------------|
| `0 - 25` | Low |
| `26 - 50` | Medium |
| `51 - 75` | High |
| `76 - 100` | Critical |

### Important behavior in the current version

- **Idempotent replay**: the same persisted `alert_id` does not repeat side effects unless needed.
- **Artifact materialization**: if an older record is missing HTML or PDF artifacts, replay can generate the missing files and persist them.
- **Queue-ready boundary**: the policy engine already emits execution trace and correlation hook scaffolding for future async or queued remediation.

---

## ⚖️ Policy Engine — 4 Response Rules

The current system ships with four core response rules:

| Rule | Condition | Action | Operational meaning |
|------|-----------|--------|---------------------|
| **Rule 1** | Hash reputation = `MALICIOUS` | `ISOLATE_HOST` | The hash is confirmed malicious and the host should be contained immediately |
| **Rule 2** | Process is in the dangerous process blacklist | `KILL_PROCESS` | Tools such as `mimikatz.exe`, `wce.exe`, or `psexec.exe` should not be running on normal endpoints |
| **Rule 3** | Asset criticality = `CRITICAL` | `ESCALATE` | High-value systems such as finance workstations or domain controllers require manual analyst review |
| **Rule 4** | Destination IP has `is_c2 = true` | `BLOCK_IP` | The system sees a likely beaconing or command-and-control path |
| **Always** | Every alert | `CREATE_TICKET` + `NOTIFY_SOC` | Always maintain auditability and SOC awareness |

### Policy-as-data

Rules are not locked into code. Configuration lives in:

```text
policies/response_rules.yaml
```

The YAML layer currently supports:

- `enabled` flags per rule
- structured `matches`
- `thresholds.min_risk_score`
- `thresholds.min_severity`
- `guards.username_allowlist`
- `execution.mode` values like `sync` or `queued`
- correlation fields for future async remediation

### Why this matters

- It is easy to explain in interviews: the rule logic is explicit and auditable.
- It is easy to tune without rewriting the policy engine.
- It scales well when adding richer rules such as sandbox-first flows, server-specific guardrails, or approval gates.

---

## 🛠️ Setup & Run

### 1. Prerequisites

- **Recommended:** Python **3.13.x**
- **Validated in practice:** Python **3.13.0** on Windows
- **Target compatibility:** Python `3.11+`
- `pip`

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Current dependency coverage includes:

- `pydantic` for schemas and contracts
- `fastapi` + `uvicorn` for the API
- `streamlit` for the dashboard
- `markdown2` for Markdown → HTML rendering
- `weasyprint` for optional HTML → PDF export
- `PyYAML` for policy-as-data
- `pytest` + `pytest-cov` for automated testing

### 3. Run the CLI workflow

```bash
# Default scenario
python main.py --scenario mixed

# Fast run without report generation
python main.py --scenario mixed --seed 2024 --no-report

# Use a bundled sample alert
python main.py --alert data/sample_alerts/alert_04_full_critical.json

# Write reports to a dedicated output folder
python main.py --alert data/sample_alerts/alert_04_full_critical.json --output-dir output\smoke-readme
```

### 4. Run FastAPI

```bash
python -m uvicorn api.app:app --reload
```

Primary endpoints:

- `GET /health`
- `POST /api/v1/incidents/process`
- `POST /api/v1/incidents/process-scenario`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/by-alert/{alert_id}`
- `GET /api/v1/incidents/by-ticket/{ticket_id}`
- `GET /api/v1/a2a/health`
- `POST /api/v1/a2a/workspaces`
- `POST /api/v1/a2a/agents/register`
- `POST /api/v1/a2a/tasks`
- `GET /api/v1/a2a/messages`

### 5. Auth / RBAC for the API and A2A

The current project uses bearer tokens defined through an environment variable:

```powershell
$env:SOAR_AUTH_TOKENS_JSON = '{"tokens":[
  {"token":"incident-process-token","principal_id":"incident-processor","principal_type":"user","roles":["incident_process"],"workspaces":["*"]},
  {"token":"incident-read-token","principal_id":"incident-reader","principal_type":"user","roles":["incident_read"],"workspaces":["*"]},
  {"token":"a2a-admin-token","principal_id":"a2a-admin","principal_type":"user","roles":["a2a_admin","a2a_read"],"workspaces":["*"]}
]}'
```

Available roles:

- `incident_process`
- `incident_read`
- `a2a_admin`
- `a2a_read`
- `a2a_agent`

For A2A agent principals:

- the token must use `principal_type = "agent"`
- it must bind to the correct `agent_id`
- it cannot impersonate another agent to claim tasks, post messages, poll inboxes, or publish artifacts

### 6. Run the dashboard

```bash
streamlit run dashboard/app.py
```

The dashboard shares the same `SoarWorkflowService` as the CLI and API, so behavior remains consistent across all entry points.

### 7. Run the A2A bus for a multi-agent team

A2A CLI help:

```bash
python -m a2a.cli --help
```

Minimal example:

```powershell
$env:SOAR_AUTH_TOKEN = "a2a-admin-token"
python -m a2a.cli ensure-workspace --workspace soar-sprint-01

python -m a2a.cli register-agent --workspace soar-sprint-01 --agent-id codex-lead --platform codex --role leader --capability plan
python -m a2a.cli register-agent --workspace soar-sprint-01 --agent-id codex-worker-1 --platform codex --role worker --capability implementation
python -m a2a.cli register-agent --workspace soar-sprint-01 --agent-id codex-worker-2 --platform codex --role worker --capability testing
```

To bootstrap a three-Codex team quickly:

```powershell
.\scripts\bootstrap-3-codex-team.ps1
```

Or:

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\scripts\bootstrap-3-codex-team.ps1 -Workspace soar-sprint-01
```

Collaboration docs:

- `docs/a2a-collaboration.md`
- `docs/three-codex-team.md`
- `.agents/a2a-playbook.md`

---

## 📁 Project Structure

```text
SOAR Playbook/
├── main.py
├── terminal_compat.py
├── time_utils.py
├── actions/
├── a2a/
│   ├── cli.py
│   ├── schemas.py
│   ├── service.py
│   └── storage.py
├── alert_generator/
├── api/
│   ├── app.py
│   └── schemas.py
├── dashboard/
├── data/
│   ├── mock_hash_db.json
│   ├── mock_ip_db.json
│   ├── mock_asset_db.json
│   ├── mitre_technique_map.json
│   └── sample_alerts/
├── docs/
├── engine/
│   ├── action_dispatcher.py
│   ├── policy_engine.py
│   ├── policy_loader.py
│   └── risk_scoring.py
├── enrichment/
├── output/
├── policies/
│   └── response_rules.yaml
├── reporting/
│   └── report_generator.py
├── schemas/
├── scripts/
│   ├── bootstrap-3-codex-team.ps1
│   └── run_pentest.py
├── security/
│   └── auth.py
├── services/
│   └── workflow_service.py
├── storage/
│   └── sqlite_repository.py
└── tests/
```

### Notable directories

- `services/` contains the orchestration layer shared by CLI, API, and dashboard.
- `storage/` contains the read-side and persistence layer for incident history.
- `security/` contains auth/RBAC shared by the API and A2A flows.
- `scripts/` contains tooling for multi-agent bootstrap and security regression checks.
- `docs/` contains the roadmap, handoff notes, pentest reports, and collaboration docs.

---

## 🔧 Tech Stack & Why It Was Chosen

| Technology | Role | Why it fits |
|------------|------|-------------|
| **Python 3.13** | Main runtime | Modern Python with strong typing support and a good fit for automation-heavy code |
| **Pydantic v2** | Schema validation | Stabilizes alert, response, persistence, and OpenAPI contracts |
| **FastAPI** | API layer | Fast typed HTTP API with clean dependency injection and built-in OpenAPI docs |
| **SQLite** | Persistence | Lightweight and local-first, but still good enough for replay and incident history APIs |
| **Streamlit** | Dashboard | Fast way to build a useful analyst-facing demo UI |
| **Rich + Loguru** | CLI UX + logging | Clear terminal output and detailed step-by-step logs |
| **PyYAML** | Policy-as-data | Keeps rule configuration outside the engine code |
| **markdown2** | Report rendering | Light and good enough for Markdown → HTML without a separate frontend stack |
| **WeasyPrint** | PDF export | Enables PDF generation from HTML when needed |
| **pytest** | Test automation | Strong regression coverage for policy, persistence, API, A2A, and security |

### Why Python 3.13 is worth calling out

The project was re-validated on **Python 3.13.0**. That matters because:

- it proves the codebase is not only running on older "safe" environments
- it surfaces modern compatibility issues early
- it makes the project more credible when presented as a current engineering sample

### Current security stack

In addition to the functional stack, the project now includes:

- bearer-token authentication
- role-based authorization
- agent identity binding
- API field redaction
- HTML report escaping
- a security regression pentest script

---

## 🧪 Sample Alerts — Test Cases

The five bundled alerts in `data/sample_alerts/` cover the main policy branches:

| File | Scenario | Expected behavior |
|------|----------|-------------------|
| `alert_01_malicious_hash.json` | Malicious hash | Triggers `ISOLATE_HOST` |
| `alert_02_c2_communication.json` | C2 communication | Triggers `BLOCK_IP` |
| `alert_03_critical_asset.json` | Critical asset | Triggers `ESCALATE` |
| `alert_04_full_critical.json` | Full critical chain | Triggers all four core rules |
| `alert_05_benign.json` | Benign / low-risk alert | No automated remediation, but still creates a ticket and notifies SOC |

### Run all sample alerts

PowerShell:

```powershell
Get-ChildItem data\sample_alerts\*.json | ForEach-Object {
  python main.py --alert $_.FullName --no-report
}
```

---

## ✅ Unit Tests

### Current result

```bash
pytest tests -q
```

Latest result:

- **55 tests passed**
- no failing tests after the hardening and pentest remediation pass

### Covered test groups

- `tests/test_policy_engine.py`
  - rule behavior
  - queue mode
  - correlation hooks
- `tests/test_policy_loader.py`
  - YAML config validation
  - fallback defaults
  - thresholds / guards
- `tests/test_sqlite_repository.py`
  - persistence
  - upsert / lookup
  - list filters
- `tests/test_workflow_service.py`
  - orchestration
  - idempotent replay
  - artifact materialization
- `tests/test_api_app.py`
  - process / list / read API
  - auth-aware route usage
- `tests/test_a2a_service.py`
  - workspace / task / message / artifact lifecycle
- `tests/test_a2a_api.py`
  - API-facing A2A integration
- `tests/test_security_regressions.py`
  - auth enforcement
  - inbox isolation
  - spoofing rejection
  - report escaping

### Latest pentest result

```bash
python scripts/run_pentest.py
```

Result on **2026-07-02**:

- `finding_count = 0`
- official report: `docs/pentest-report-2026-07-02.md`
- latest machine-readable evidence: `output/pentest/20260702T055951Z/pentest-results.json`

---

## 📄 Incident Report Output

Each alert can generate up to three artifacts:

- **Markdown** `.md`
- **HTML** `.html`
- **PDF** `.pdf` when `weasyprint` is available

### Report sections

The current report includes:

1. Executive Summary
2. Alert Details
3. Processing Timeline
4. IOC Summary
5. Enrichment Results
6. Risk Assessment
7. Response Actions
8. Recommendations

### Important details in the current version

- HTML reports now **escape alert-controlled data** before rendering.
- HTML metadata outside the body is also escaped, not only the Markdown body.
- Incident replay can materialize missing reports without re-running the entire workflow.

### PDF note

- If `weasyprint` is not installed, Markdown + HTML still work normally.
- On Windows, the HTML report is good enough to open in a browser and export to PDF with `Ctrl+P`.

---

## 🚀 Future Improvements

### 1. Real external integrations

The current mocks can later be replaced with:

- VirusTotal API
- AbuseIPDB API
- a real CMDB
- real EDR isolate / containment calls
- real firewall block operations
- Jira / ServiceNow / TheHive

### 2. True async remediation

The codebase already has a queue-ready boundary, but a fuller implementation should add:

- background workers
- retry policies
- dead-letter queues
- delivery guarantees

### 3. Additional security hardening

The latest hardening pass fixed the major findings, but a production-oriented version should still consider:

- rate limiting
- immutable audit logs
- request tracing
- token rotation / secret management
- encryption at rest for sensitive incident storage

### 4. Dashboard automation

The dashboard now smoke-loads successfully, but it still lacks dedicated browser automation. Good next steps would be:

- Playwright smoke coverage
- screenshot diffs
- dashboard scenario regressions

---

## 📚 Recommended Reading

- `docs/upgrade-roadmap.md`
- `docs/a2a-collaboration.md`
- `docs/three-codex-team.md`
- `docs/phase-2-persistence-schema.md`
- `docs/phase-2-idempotency-guardrails.md`
- `docs/phase-3-policy-queue-boundaries.md`
- `docs/phase-6-correlation-hooks.md`
- `docs/pentest-report-2026-07-02.md`

---

*Built as a Blue Team / SOC portfolio project — SOAR Malware Playbook v2.0*
