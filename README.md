# 🛡️ SOAR Playbook — Tự động xử lý cảnh báo Malware trên Endpoint

<div align="center">

![Python](https://img.shields.io/badge/Python-3.13%20validated-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-API%20Layer-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Persistence-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![pytest](https://img.shields.io/badge/pytest-55%20tests%20passing-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC%20Project-0078D4?style=for-the-badge)

**Blue Team CV Project — SOC Analyst tự động hoá**

*Mô phỏng SOAR Playbook xử lý cảnh báo malware end-to-end:*
*từ alert EDR → enrich threat intel → MITRE map → risk score → policy → incident report*

</div>

---

## 📌 Mục lục

- [Bối cảnh & Mục tiêu](#-bối-cảnh--mục-tiêu)
- [Demo nhanh](#-demo-nhanh)
- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống)
- [Workflow 7 bước](#-workflow-7-bước)
- [Policy Engine — 4 Response Rules](#-policy-engine--4-response-rules)
- [Cài đặt & Chạy](#-cài-đặt--chạy)
- [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
- [Tech Stack & Lý do chọn](#-tech-stack--lý-do-chọn)
- [Sample Alerts — Test Cases](#-sample-alerts--test-cases)
- [Unit Tests](#-unit-tests)
- [Incident Report Output](#-incident-report-output)
- [Định hướng mở rộng](#-định-hướng-mở-rộng)

---

## 🎯 Bối cảnh & Mục tiêu

### Bài toán

Trong môi trường SOC thực tế, analyst thường phải lặp lại các bước rất tốn thời gian:

1. Nhận alert từ EDR hoặc SIEM.
2. Tra hash trên VirusTotal hoặc nguồn threat intel tương tự.
3. Kiểm tra destination IP trên AbuseIPDB hoặc feed C2.
4. Tra CMDB để biết host đó có phải tài sản quan trọng không.
5. Map hành vi sang MITRE ATT&CK để hiểu tactic/technique.
6. Tính mức độ ưu tiên, quyết định isolate / kill / block / escalate.
7. Tạo ticket, ghi nhận evidence, viết incident report.

**SOAR Playbook** mô phỏng toàn bộ chuỗi xử lý này bằng một pipeline Python rõ ràng, dễ đọc, dễ demo, và đủ thực tế để dùng như một project Blue Team / SOC CV.

### Mục tiêu kỹ thuật

- Thể hiện cách thiết kế một **SOAR workflow** có cấu trúc, không phải script rời rạc.
- Dùng **Pydantic** để chuẩn hoá alert schema và contract giữa các bước.
- Tách rõ **enrichment**, **risk scoring**, **policy engine**, **action execution**, **reporting**, **persistence**, **API**.
- Hỗ trợ nhiều entrypoint: **CLI**, **FastAPI**, **Streamlit dashboard**, **A2A collaboration bus**.
- Có **persistence + idempotent replay** để cùng một `alert_id` không re-run side effects không cần thiết.
- Có **policy-as-data** qua YAML, không hard-code mọi rule trong logic.
- Có **auth/RBAC và security regression coverage** cho incident API và A2A API.

### Trạng thái hiện tại

Project hiện không còn là bản demo policy engine đơn thuần. Nó đã có thêm:

- **FastAPI layer** cho xử lý incident và tra cứu incident history.
- **SQLite persistence** cho incidents, action results, report artifacts.
- **A2A local collaboration bus** để nhiều agent/tab phối hợp làm việc.
- **Auth + RBAC** cho incident API và A2A API bằng bearer token.
- **Sanitized reporting** để chặn stored HTML injection trong report HTML.
- **Regression pentest runner** để kiểm tra security fixes không bị bật ngược trở lại.

---

## 🚀 Demo nhanh

```bash
# 1. Cài dependencies
pip install -r requirements.txt

# 2. Chạy workflow với scenario mặc định
python main.py --scenario mixed --no-report

# 3. Chạy với sample alert "full critical"
python main.py --alert data/sample_alerts/alert_04_full_critical.json

# 4. Chạy API
python -m uvicorn api.app:app --reload

# 5. Chạy dashboard
streamlit run dashboard/app.py

# 6. Chạy test suite
pytest tests -q

# 7. Chạy pentest regression
python scripts/run_pentest.py
```

Các lệnh smoke-test đã được chạy lại trên Windows ngày **2026-07-02**:

- `python main.py --scenario mixed --seed 2024 --no-report`
- `python main.py --alert data/sample_alerts/alert_04_full_critical.json --output-dir output\smoke-readme`
- `python -m a2a.cli ...` lifecycle smoke với auth token
- `pytest tests -q` → **55 passed**
- `python scripts/run_pentest.py` → **0 findings**

---

## 🏗️ Kiến trúc hệ thống

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

### Luồng chính

1. Alert đi vào từ file JSON, generator, dashboard, hoặc HTTP request.
2. `EnrichmentPipeline` chạy hash/IP/asset/MITRE mapping.
3. `RiskScoringEngine` tính điểm tổng hợp 0-100.
4. `PolicyEngine` áp rule mặc định hoặc rule YAML đã cấu hình.
5. Mock actions chạy và trả về `ActionResult`.
6. `ReportGenerator` sinh Markdown + HTML, optional PDF.
7. `SQLiteIncidentRepository` persist kết quả để phục vụ replay và API lookup.

### Collaboration layer

Ngoài workflow xử lý alert, project còn có **A2A bus nội bộ** cho nhiều agent/tab phối hợp:

- Workspace để gom sprint hoặc scope công việc.
- Agent registration và heartbeat.
- Task lifecycle: create / claim / complete.
- Message inbox theo `agent_id`.
- Artifact handoff để đính kèm docs, patch notes, evidence.
- Timeline để lead theo dõi toàn bộ diễn biến.

### Security boundary

Sau vòng hardening và pentest remediation:

- Incident API yêu cầu role `incident_process` hoặc `incident_read`.
- A2A API yêu cầu `a2a_admin`, `a2a_read`, hoặc `a2a_agent`.
- A2A write operations được **bind với authenticated agent identity**, không còn tin `agent_id` do caller tự khai.
- Incident responses mặc định **redact** các field nhạy cảm như `username`, `command_line`, `file_hash`, `file_path`.
- HTML report escape dữ liệu alert trước khi render.

---

## 🔄 Workflow 7 bước

| Bước | Tên | Module chính | Mô tả |
|------|-----|--------------|-------|
| **1** | Nhận Alert | `schemas/alert.py` | Parse & validate payload bằng Pydantic |
| **2** | Enrich Hash | `enrichment/hash_intel.py` | Lookup hash từ mock threat intel database |
| **3** | Enrich IP | `enrichment/ip_intel.py` | Lookup destination IP, reputation, confidence, C2 flag |
| **4** | Asset Criticality | `enrichment/asset_db.py` | Tra hostname trong mock CMDB để xác định business impact |
| **5** | MITRE ATT&CK Mapping | `enrichment/mitre_mapping.py` | Map process name và command line sang technique/tactic |
| **6** | Risk Scoring | `engine/risk_scoring.py` | Tính weighted risk score và risk level |
| **7** | Policy + Actions | `engine/policy_engine.py` | Evaluate rules, thực thi actions, tạo ticket, notify SOC |

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

### Điểm quan trọng trong version hiện tại

- **Idempotent replay**: cùng một `alert_id` đã persist sẽ không chạy lại side effects nếu không cần.
- **Artifact materialization**: nếu record cũ chưa có HTML/PDF, replay có thể sinh bổ sung report rồi persist lại.
- **Queue-ready boundary**: policy engine đã có execution trace và correlation hook scaffold cho async/queued execution sau này.

---

## ⚖️ Policy Engine — 4 Response Rules

Mặc định hệ thống đang có 4 response rules cốt lõi:

| Rule | Điều kiện | Action | Ý nghĩa vận hành |
|------|-----------|--------|------------------|
| **Rule 1** | Hash reputation = `MALICIOUS` | `ISOLATE_HOST` | Hash đã bị threat intel xác nhận là độc hại, cần cắt host ra khỏi mạng |
| **Rule 2** | Process thuộc dangerous process blacklist | `KILL_PROCESS` | Tool như `mimikatz.exe`, `wce.exe`, `psexec.exe` không nên tồn tại trên endpoint bình thường |
| **Rule 3** | Asset criticality = `CRITICAL` | `ESCALATE` | Tài sản quan trọng như finance workstation / domain controller cần analyst xử lý thủ công |
| **Rule 4** | Destination IP bị đánh dấu `is_c2 = true` | `BLOCK_IP` | Có tín hiệu beaconing hoặc điều khiển từ C2 |
| **Always** | Mọi alert | `CREATE_TICKET` + `NOTIFY_SOC` | Luôn giữ audit trail và SOC visibility |

### Policy-as-data

Rules không còn bị khóa chặt trong code. Phần cấu hình nằm tại:

```text
policies/response_rules.yaml
```

YAML hiện hỗ trợ:

- `enabled` để bật/tắt từng rule
- `matches` theo type điều kiện
- `thresholds.min_risk_score`
- `thresholds.min_severity`
- `guards.username_allowlist`
- `execution.mode` kiểu `sync` hoặc `queued`
- correlation fields để chuẩn bị cho async remediation

### Tại sao cách này đáng giá

- Dễ explain trong interview: rule logic rõ ràng, audit được.
- Dễ nâng cấp: đổi threshold hoặc guard mà không phải sửa code policy engine.
- Dễ mở rộng: sau này thêm rule “sandbox first”, “quarantine only if host is not server”, hoặc “do not auto-kill domain controller process” sẽ sạch hơn nhiều.

---

## 🛠️ Cài đặt & Chạy

### 1. Prerequisites

- **Khuyến nghị:** Python **3.13.x**
- **Đã test thực tế:** Python **3.13.0** trên Windows
- **Tương thích mục tiêu:** Python `3.11+`
- `pip`

### 2. Cài dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` hiện bao gồm:

- `pydantic` cho schema và data contract
- `fastapi` + `uvicorn` cho API
- `streamlit` cho dashboard
- `markdown2` cho render Markdown → HTML
- `weasyprint` cho HTML → PDF (optional)
- `PyYAML` cho policy-as-data
- `pytest` + `pytest-cov` cho test

### 3. Chạy CLI workflow

```bash
# Scenario mặc định
python main.py --scenario mixed

# Chạy nhanh, bỏ report generation
python main.py --scenario mixed --seed 2024 --no-report

# Chạy bằng alert JSON có sẵn
python main.py --alert data/sample_alerts/alert_04_full_critical.json

# Ghi report vào thư mục riêng
python main.py --alert data/sample_alerts/alert_04_full_critical.json --output-dir output\smoke-readme
```

### 4. Chạy FastAPI

```bash
python -m uvicorn api.app:app --reload
```

Các endpoint chính:

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

### 5. Auth / RBAC cho API và A2A

Project hiện dùng bearer token cấu hình qua biến môi trường:

```powershell
$env:SOAR_AUTH_TOKENS_JSON = '{"tokens":[
  {"token":"incident-process-token","principal_id":"incident-processor","principal_type":"user","roles":["incident_process"],"workspaces":["*"]},
  {"token":"incident-read-token","principal_id":"incident-reader","principal_type":"user","roles":["incident_read"],"workspaces":["*"]},
  {"token":"a2a-admin-token","principal_id":"a2a-admin","principal_type":"user","roles":["a2a_admin","a2a_read"],"workspaces":["*"]}
]}'
```

Role hiện có:

- `incident_process`
- `incident_read`
- `a2a_admin`
- `a2a_read`
- `a2a_agent`

Với A2A agent principal:

- token phải có `principal_type = "agent"`
- phải bind với đúng `agent_id`
- không thể giả danh agent khác khi claim task, post message, poll inbox, publish artifact

### 6. Chạy dashboard

```bash
streamlit run dashboard/app.py
```

Dashboard dùng chung `SoarWorkflowService`, nên logic xử lý giữa CLI, API và dashboard là nhất quán.

### 7. Chạy A2A bus cho team nhiều agent

CLI A2A:

```bash
python -m a2a.cli --help
```

Ví dụ tối giản:

```powershell
$env:SOAR_AUTH_TOKEN = "a2a-admin-token"
python -m a2a.cli ensure-workspace --workspace soar-sprint-01

python -m a2a.cli register-agent --workspace soar-sprint-01 --agent-id codex-lead --platform codex --role leader --capability plan
python -m a2a.cli register-agent --workspace soar-sprint-01 --agent-id codex-worker-1 --platform codex --role worker --capability implementation
python -m a2a.cli register-agent --workspace soar-sprint-01 --agent-id codex-worker-2 --platform codex --role worker --capability testing
```

Nếu muốn bootstrap nhanh team 3 Codex tabs:

```powershell
.\scripts\bootstrap-3-codex-team.ps1
```

Hoặc:

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\scripts\bootstrap-3-codex-team.ps1 -Workspace soar-sprint-01
```

Tài liệu phối hợp agent:

- `docs/a2a-collaboration.md`
- `docs/three-codex-team.md`
- `.agents/a2a-playbook.md`

---

## 📁 Cấu trúc thư mục

```text
SOAR Playbook/
├── main.py
├── terminal_compat.py
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

### Một vài thư mục đáng chú ý

- `services/` là lớp orchestration dùng chung cho CLI, API, dashboard.
- `storage/` chứa read-side và persistence cho incident history.
- `security/` chứa auth/RBAC dùng chung giữa API và A2A.
- `scripts/` chứa tooling để bootstrap multi-agent và chạy pentest regression.
- `docs/` chứa roadmap, handoff notes, pentest report, tài liệu teamwork.

---

## 🔧 Tech Stack & Lý do chọn

| Công nghệ | Vai trò | Lý do chọn |
|-----------|---------|------------|
| **Python 3.13** | Runtime chính | Bản Python mới, type hints tốt, phù hợp codebase automation + data processing |
| **Pydantic v2** | Schema validation | Chuẩn hoá alert, response, persistence payload, OpenAPI schema |
| **FastAPI** | API layer | Tạo HTTP API nhanh, typed, có OpenAPI docs và dependency injection rõ ràng |
| **SQLite** | Persistence | Nhẹ, local-first, phù hợp demo project nhưng vẫn đủ cho read-side API và replay |
| **Streamlit** | Dashboard | Dựng analyst UI nhanh, dễ demo trực tiếp trong portfolio |
| **Rich + Loguru** | CLI UX + logging | Output terminal rõ, có log chi tiết theo từng bước pipeline |
| **PyYAML** | Policy-as-data | Cho phép tách rule config ra khỏi code, dễ chỉnh threshold/guard |
| **markdown2** | Report render | Đủ nhẹ để convert Markdown sang HTML đẹp, không cần stack frontend riêng |
| **WeasyPrint** | PDF export | Có thể xuất PDF từ HTML khi muốn report gửi mail hoặc đính kèm artifact |
| **pytest** | Test automation | Dễ giữ regression coverage cho policy, persistence, API, A2A, security |

### Vì sao Python 3.13 đáng nói ở đây

Project đã được chạy thật trên **Python 3.13.0**. Điều này quan trọng vì:

- Nó xác nhận codebase không chỉ chạy trên môi trường “an toàn” cũ.
- Nó giúp lộ các cảnh báo `datetime.utcnow()` deprecated cần cleanup dần.
- Nó làm README và CV đáng tin hơn khi nói “đã test trên Python mới”.

### Security stack hiện tại

Ngoài functional stack, phần security hiện có:

- bearer token auth
- role-based authorization
- agent identity binding
- API redaction
- report HTML escaping
- pentest regression script

---

## 🧪 Sample Alerts — Test Cases

5 alert mẫu trong `data/sample_alerts/` hiện cover các nhánh policy phổ biến:

| File | Scenario | Kỳ vọng |
|------|----------|---------|
| `alert_01_malicious_hash.json` | Hash độc hại | Trigger `ISOLATE_HOST` |
| `alert_02_c2_communication.json` | Kết nối tới IP C2 | Trigger `BLOCK_IP` |
| `alert_03_critical_asset.json` | Host critical asset | Trigger `ESCALATE` |
| `alert_04_full_critical.json` | Full critical chain | Trigger cả 4 rule chính |
| `alert_05_benign.json` | Alert benign / low risk | Không auto-remediate, vẫn tạo ticket + notify |

### Chạy lần lượt các sample alert

PowerShell:

```powershell
Get-ChildItem data\sample_alerts\*.json | ForEach-Object {
  python main.py --alert $_.FullName --no-report
}
```

---

## ✅ Unit Tests

### Kết quả hiện tại

```bash
pytest tests -q
```

Kết quả mới nhất:

- **55 tests passed**
- Không có test fail sau đợt hardening và pentest remediation

### Nhóm test đang có

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

### Pentest kết quả mới nhất

```bash
python scripts/run_pentest.py
```

Kết quả ngày **2026-07-02**:

- `finding_count = 0`
- report chính thức: `docs/pentest-report-2026-07-02.md`
- evidence machine-readable mới nhất: `output/pentest/20260702T055951Z/pentest-results.json`

---

## 📄 Incident Report Output

Mỗi alert có thể sinh ra 3 artifact:

- **Markdown** `.md`
- **HTML** `.html`
- **PDF** `.pdf` nếu môi trường có `weasyprint`

### Nội dung report

Report hiện gồm:

1. Executive Summary
2. Alert Details
3. Processing Timeline
4. IOC Summary
5. Enrichment Results
6. Risk Assessment
7. Response Actions
8. Recommendations

### Điểm đáng chú ý của bản hiện tại

- HTML report đã được **escape dữ liệu alert-controlled** trước khi render.
- Metadata ngoài body HTML cũng được escape, không chỉ riêng phần Markdown body.
- Replay incident có thể materialize report còn thiếu mà không cần chạy lại toàn pipeline.

### Lưu ý về PDF

- Nếu chưa cài `weasyprint`, hệ thống vẫn sinh Markdown + HTML bình thường.
- Với Windows, HTML report đủ đẹp để mở browser và `Ctrl+P` ra PDF nếu chưa muốn setup GTK runtime.

---

## 🚀 Định hướng mở rộng

### 1. Tích hợp external services thật

Mock hiện tại hoàn toàn có thể thay bằng:

- VirusTotal API
- AbuseIPDB API
- CMDB thật
- EDR isolate thật
- firewall block thật
- Jira / ServiceNow / TheHive

### 2. Async remediation thật sự

Codebase đã có queue-ready boundary, nhưng vẫn nên bổ sung:

- background worker
- retry policy
- dead-letter queue
- delivery guarantee

### 3. Security hardening tiếp

Đợt hardening vừa qua đã fix các finding chính, nhưng nếu muốn productionize hơn nữa thì nên thêm:

- rate limiting
- immutable audit log
- request tracing
- token rotation / secret management
- encryption-at-rest cho incident storage nếu chứa dữ liệu nhạy cảm thật

### 4. Code quality cleanup

Một việc nên làm tiếp ngay:

- thay dần `datetime.utcnow()` bằng timezone-aware UTC datetime để dọn warning trên Python 3.13

### 5. Dashboard automation

Hiện dashboard đã smoke-load tốt, nhưng chưa có test automation riêng. Có thể bổ sung:

- Playwright smoke
- screenshot diff
- dashboard scenario regression

---

## 📚 Tài liệu nên đọc tiếp

- `docs/upgrade-roadmap.md`
- `docs/a2a-collaboration.md`
- `docs/three-codex-team.md`
- `docs/phase-2-persistence-schema.md`
- `docs/phase-2-idempotency-guardrails.md`
- `docs/phase-3-policy-queue-boundaries.md`
- `docs/phase-6-correlation-hooks.md`
- `docs/pentest-report-2026-07-02.md`

---

*Built for Blue Team / SOC portfolio work — SOAR Malware Playbook v2.0*
