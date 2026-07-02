# 🛡️ SOAR Playbook — Tự động xử lý cảnh báo Malware trên Endpoint

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![pytest](https://img.shields.io/badge/pytest-14%20test%20cases-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
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

Trong môi trường SOC thực tế, một analyst có thể nhận **hàng trăm alert mỗi ngày** từ các EDR/SIEM. Hầu hết thời gian bị tiêu tốn vào các bước thủ công lặp lại:

1. Tìm kiếm hash trên VirusTotal
2. Check IP trên AbuseIPDB
3. Tra CMDB xem máy có quan trọng không
4. Map sang MITRE ATT&CK để hiểu tactic
5. Quyết định có cần isolate/block/escalate không
6. Viết incident ticket và báo cáo

**SOAR Playbook** tự động hóa toàn bộ quy trình này, giúp analyst tập trung vào các quyết định phức tạp hơn.

### Mục tiêu kỹ thuật (CV)

- ✅ Thể hiện tư duy thiết kế **SOAR Playbook thực tế**
- ✅ Khả năng viết **detection/policy engine** với rule-based logic
- ✅ Tích hợp **threat intelligence** (mock, có thể upgrade lên API thật)
- ✅ **MITRE ATT&CK** framework awareness
- ✅ **Clean code, modular design** — dễ đọc khi phỏng vấn hỏi về logic
- ✅ Kết quả chuyên nghiệp: **Streamlit dashboard + PDF report**

---

## 🚀 Demo nhanh

```bash
# 1. Clone & cài dependencies
git clone <repo-url>
cd "SOAR Playbook"
pip install -r requirements.txt

# 2. Chạy pipeline với alert ngẫu nhiên
python main.py --scenario mixed

# 3. Chạy với sample alert có sẵn
python main.py --alert data/sample_alerts/alert_04_full_critical.json

# 4. Mở Streamlit dashboard
streamlit run dashboard/app.py

# 5. Chạy unit tests
pytest tests/ -v
```

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOAR Malware Playbook                         │
│                                                                  │
│  ┌──────────────┐    ┌─────────────────────────────────────┐    │
│  │ Alert Input  │    │        Enrichment Pipeline           │    │
│  │              │    │                                      │    │
│  │ • JSON file  │───▶│  Step 2: Hash Intel (mock VT)       │    │
│  │ • Generator  │    │  Step 3: IP Intel   (mock AbuseIPDB)│    │
│  │ • Streamlit  │    │  Step 4: Asset DB   (mock CMDB)     │    │
│  │ • CLI arg    │    │  Step 5: MITRE Mapping              │    │
│  └──────────────┘    │  Step 6: Risk Scoring               │    │
│                      └──────────────────┬────────────────┘    │
│                                         │ EnrichedAlert         │
│                      ┌──────────────────▼────────────────┐    │
│                      │         Policy Engine (Step 7)     │    │
│                      │                                    │    │
│                      │  Rule 1: Hash MALICIOUS?           │    │
│                      │    → ISOLATE HOST                  │    │
│                      │  Rule 2: Dangerous Process?        │    │
│                      │    → KILL PROCESS                  │    │
│                      │  Rule 3: Asset CRITICAL?           │    │
│                      │    → ESCALATE                      │    │
│                      │  Rule 4: IP is C2?                 │    │
│                      │    → BLOCK IP                      │    │
│                      │  Always: CREATE TICKET + NOTIFY    │    │
│                      └──────────────────┬────────────────┘    │
│                                         │ IncidentResponse      │
│                      ┌──────────────────▼────────────────┐    │
│                      │         Output Layer               │    │
│                      │                                    │    │
│                      │  • Markdown Report (.md)           │    │
│                      │  • HTML Report    (.html)          │    │
│                      │  • PDF Report     (.pdf)           │    │
│                      │  • Ticket JSON    (mock)           │    │
│                      │  • Streamlit Dashboard             │    │
│                      └────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Interface Design (dễ upgrade lên API thật)

```python
# Thiết kế theo Abstract Base Class — swap mock ↔ API thật chỉ cần 1 dòng

class BaseHashIntel(ABC):
    @abstractmethod
    def lookup(self, file_hash: str) -> HashEnrichment: ...

# Mock (hiện tại):
hash_intel = MockHashIntel()          # Đọc từ mock_hash_db.json

# Upgrade lên VirusTotal thật:
hash_intel = VirusTotalHashIntel(api_key="VT_API_KEY")  # Chỉ cần thêm class này
```

---

## 🔄 Workflow 7 bước

| Bước | Tên | Module | Mô tả |
|------|-----|--------|-------|
| **1** | Nhận Alert | `schemas/alert.py` | Parse & validate JSON alert bằng Pydantic |
| **2** | Enrich Hash | `enrichment/hash_intel.py` | Lookup SHA256 hash (mock VirusTotal) |
| **3** | Enrich IP | `enrichment/ip_intel.py` | Lookup destination IP (mock AbuseIPDB), detect C2 |
| **4** | Asset Criticality | `enrichment/asset_db.py` | Lookup hostname → criticality (mock CMDB) |
| **5** | MITRE ATT&CK | `enrichment/mitre_mapping.py` | Map process/cmdline → Technique ID + Tactic |
| **6** | Risk Scoring | `engine/risk_scoring.py` | Weighted sum 5 components → score 0-100 |
| **7** | Policy + Actions | `engine/policy_engine.py` | Evaluate 4 rules → execute actions → ticket |

### Risk Scoring Formula

```
Risk Score (0-100) =
    Hash Reputation    × 30%   (Malicious=1.0, Suspicious=0.5+ratio, Clean=0)
  + IP / C2 Flag       × 25%   (C2 bonus +0.4, confidence normalized)
  + Asset Criticality  × 20%   (Critical=1.0, Normal=0.45, Low=0.1)
  + Alert Severity     × 15%   (Critical=1.0, High=0.75, Medium=0.45, Low=0.2)
  + MITRE Techniques   × 10%   (max weight + count bonus)
```

| Score | Risk Level |
|-------|-----------|
| 0 – 25 | 🟢 Low |
| 26 – 50 | 🟡 Medium |
| 51 – 75 | 🔴 High |
| 76 – 100 | 🔴🔴 Critical |

---

## ⚖️ Policy Engine — 4 Response Rules

| Rule | Điều kiện | Action | Lý do |
|------|-----------|--------|-------|
| **Rule 1** | Hash reputation = **MALICIOUS** | `ISOLATE_HOST` | Hash confirmed malicious = active malware, cần cách ly ngay để ngăn lateral movement |
| **Rule 2** | Process nằm trong **dangerous process blacklist** | `KILL_PROCESS` | Tools như mimikatz, psexec không bao giờ nên chạy trên production host |
| **Rule 3** | Asset criticality = **CRITICAL** | `ESCALATE` | DC/Finance server compromise = business impact cao, cần analyst xử lý thủ công |
| **Rule 4** | Destination IP được gắn cờ **C2** | `BLOCK_IP` | Active C2 beaconing → block để cắt kênh điều khiển malware |
| *Always* | Mọi alert | `CREATE_TICKET` + `NOTIFY_SOC` | Đảm bảo audit trail và SOC awareness |

> **Edge case được xử lý:** IP malicious nhưng **không phải C2** → không auto-block (tránh block nhầm CDN), chỉ ghi vào reasoning để SOC review thủ công.

---

## 🛠️ Cài đặt & Chạy

### Prerequisites

- Python 3.11+
- pip

### Cài đặt

```bash
# Clone repo
git clone <repo-url>
cd "SOAR Playbook"

# Cài tất cả dependencies
pip install -r requirements.txt

# (Optional) PDF export — cần GTK runtime trên Windows
pip install weasyprint
# Windows: xem https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows
```

### Chạy Pipeline (CLI)

```bash
# Scenario mặc định (mixed — tất cả 4 trigger)
python main.py

# Chọn scenario cụ thể
python main.py --scenario malicious_hash
python main.py --scenario c2_communication
python main.py --scenario critical_asset
python main.py --scenario dangerous_process
python main.py --scenario benign

# Dùng alert từ file JSON
python main.py --alert data/sample_alerts/alert_04_full_critical.json
python main.py --alert data/sample_alerts/alert_01_malicious_hash.json

# Custom seed để reproduce kết quả
python main.py --scenario mixed --seed 42

# Không sinh report (chạy nhanh hơn)
python main.py --no-report
```

### Streamlit Dashboard

```bash
streamlit run dashboard/app.py
```

Truy cập: http://localhost:8501

**Tính năng dashboard:**
- 🎲 Generate alert theo scenario hoặc load từ file JSON
- 📊 Xem KPI: Risk Score, Actions triggered, MITRE techniques
- 🔍 Enrichment details: hash/IP/asset/MITRE với progress bars
- 📋 Đọc Incident Report trực tiếp trong browser + download Markdown
- 📁 Alert history trong session

### Unit Tests

```bash
# Chạy tất cả tests
pytest tests/ -v

# Chạy với coverage report
pytest tests/ -v --cov=engine --cov-report=term-missing

# Chạy 1 test cụ thể
pytest tests/test_policy_engine.py::test_mixed_scenario_triggers_all_four_actions -v
```

---

## 📁 Cấu trúc thư mục

```
SOAR Playbook/
│
├── main.py                          # Entrypoint CLI — chạy full pipeline
│
├── schemas/
│   └── alert.py                     # Pydantic models: MalwareAlert, EnrichedAlert, IncidentResponse
│
├── alert_generator/
│   └── generator.py                 # Faker-based alert generator (7 scenarios)
│
├── enrichment/
│   ├── base.py                      # Abstract base classes (interface cho swap API thật)
│   ├── hash_intel.py                # Mock VirusTotal hash lookup
│   ├── ip_intel.py                  # Mock AbuseIPDB IP lookup
│   ├── asset_db.py                  # Mock CMDB asset criticality
│   ├── mitre_mapping.py             # MITRE ATT&CK pattern matching engine
│   └── pipeline.py                  # Orchestrator bước 2-6 với Rich trace
│
├── engine/
│   ├── risk_scoring.py              # Weighted risk score (5 components)
│   └── policy_engine.py             # 4 response rules + action execution
│
├── actions/
│   ├── isolate_host.py              # Mock EDR isolation
│   ├── kill_process.py              # Mock process termination
│   ├── block_ip.py                  # Mock firewall block
│   ├── ticketing.py                 # Mock ticket creation (TheHive/Jira-like)
│   └── notify_soc.py                # Mock SOC notification (Slack-like)
│
├── reporting/
│   └── report_generator.py          # Sinh Markdown + HTML + PDF report
│
├── dashboard/
│   └── app.py                       # Streamlit dashboard (4 tabs)
│
├── data/
│   ├── mock_hash_db.json            # Hash reputation DB (7 records)
│   ├── mock_ip_db.json              # IP reputation DB (7 records, 3 C2)
│   ├── mock_asset_db.json           # CMDB (8 hosts: critical/normal/low)
│   ├── mitre_technique_map.json     # 8 process + 16 cmdline patterns → ATT&CK
│   └── sample_alerts/
│       ├── alert_01_malicious_hash.json    # → Rule 1: ISOLATE
│       ├── alert_02_c2_communication.json  # → Rule 4: BLOCK IP
│       ├── alert_03_critical_asset.json    # → Rule 3: ESCALATE
│       ├── alert_04_full_critical.json     # → Tất cả 4 rules
│       └── alert_05_benign.json            # → No action (ticket only)
│
├── tests/
│   └── test_policy_engine.py        # 14 pytest test cases
│
├── output/                          # Auto-generated khi chạy pipeline
│   ├── reports/                     # Incident reports (.md, .html, .pdf)
│   ├── tickets.json                 # Mock ticket database
│   ├── isolated_hosts.json          # Mock EDR isolation log
│   ├── killed_processes.json        # Mock process kill log
│   ├── blocked_ips.json             # Mock firewall block list
│   └── pipeline.log                 # Debug log file
│
├── requirements.txt
├── pytest.ini
└── README.md
```

---

## 🔧 Tech Stack & Lý do chọn

| Library | Vai trò | Lý do chọn |
|---------|---------|-----------|
| **Pydantic v2** | Alert schema validation | Type-safe, auto validation, dễ serialize JSON, standard trong production code |
| **Faker** | Sinh alert test | Tạo data đa dạng, realistic — giúp test nhiều scenario mà không cần dữ liệu thật |
| **Rich** | Console output | Trace từng bước đẹp, màu sắc → dễ demo khi phỏng vấn và debug |
| **Loguru** | Structured logging | Log ra file với rotation, không cần config phức tạp như logging stdlib |
| **Streamlit** | Dashboard | Code nhanh (≤300 dòng), đẹp sẵn, không cần frontend skill |
| **markdown2** | Markdown → HTML | Nhẹ, không dependency ngoài, support tables và code blocks |
| **weasyprint** | HTML → PDF | CSS-based PDF — report giống in từ browser, không phải layout code |
| **pytest** | Unit testing | Standard Python testing, fixture system giúp test isolation tốt |
| **Abstract Base Class** | Interface design | Đảm bảo tất cả enrichment module có cùng interface → swap API thật dễ dàng |

---

## 🧪 Sample Alerts — Test Cases

5 alert mẫu trong `data/sample_alerts/` cover tất cả nhánh policy:

| File | Scenario | Expected Actions |
|------|----------|-----------------|
| `alert_01_malicious_hash.json` | Hash Cobalt Strike (65/72 vendors) | `ISOLATE_HOST` |
| `alert_02_c2_communication.json` | Kết nối tới Tor exit node (C2) | `BLOCK_IP` |
| `alert_03_critical_asset.json` | PowerShell trên Domain Controller | `ESCALATE` |
| `alert_04_full_critical.json` | BlackCat ransomware + mimikatz + finance server + RU C2 | `ISOLATE` + `KILL` + `ESCALATE` + `BLOCK` |
| `alert_05_benign.json` | Backup script hợp lệ | *No action* (ticket only) |

```bash
# Chạy tất cả 5 sample alerts
for f in data/sample_alerts/*.json; do
    python main.py --alert "$f" --no-report
done
```

---

## ✅ Unit Tests

14 test cases trong `tests/test_policy_engine.py`:

```
tests/test_policy_engine.py::test_rule1_hash_malicious_triggers_isolate    PASSED
tests/test_policy_engine.py::test_rule1_hash_suspicious_does_not_isolate   PASSED  ← boundary
tests/test_policy_engine.py::test_rule1_hash_clean_no_isolate              PASSED
tests/test_policy_engine.py::test_rule2_dangerous_process_triggers_kill    PASSED
tests/test_policy_engine.py::test_rule2_normal_process_no_kill             PASSED
tests/test_policy_engine.py::test_rule2_other_dangerous_processes          PASSED  ← parametric
tests/test_policy_engine.py::test_rule3_critical_asset_triggers_escalate   PASSED
tests/test_policy_engine.py::test_rule3_normal_asset_no_escalate           PASSED
tests/test_policy_engine.py::test_rule3_low_asset_no_escalate              PASSED
tests/test_policy_engine.py::test_rule4_c2_ip_triggers_block               PASSED
tests/test_policy_engine.py::test_rule4_malicious_ip_not_c2_no_block       PASSED  ← edge case
tests/test_policy_engine.py::test_rule4_clean_ip_no_block                  PASSED
tests/test_policy_engine.py::test_mixed_scenario_triggers_all_four_actions PASSED
tests/test_policy_engine.py::test_benign_alert_no_remediation_actions      PASSED
tests/test_policy_engine.py::test_always_creates_ticket                    PASSED
tests/test_policy_engine.py::test_always_notifies_soc                      PASSED
```

---

## 📄 Incident Report Output

Mỗi alert được xử lý sinh ra 3 file trong `output/reports/`:

### Markdown (`.md`)
Dễ xem trên GitHub, kiểm tra bằng text editor.

### HTML (`.html`)
Styled với CSS professional: dark header banner, colored tables, print-ready layout.
Mở trong browser → Ctrl+P để in PDF.

### Report sections
1. **Executive Summary** — tóm tắt tự động bằng ngôn ngữ tự nhiên
2. **Alert Details** — toàn bộ fields + command line
3. **Processing Timeline** — 7 bước với timestamp
4. **IOC Summary** — hash/IP/process với reputation badge
5. **Enrichment Results** — hash/IP/asset/MITRE table (link tới attack.mitre.org)
6. **Risk Assessment** — breakdown 5 component với reasoning text
7. **Response Actions** — bảng action + policy reasoning
8. **Recommendations** — Immediate/Short-term/Long-term theo context

---

## 🚀 Định hướng mở rộng

### Upgrade Enrichment (thay mock bằng API thật)

```python
# Thay 1 dòng, không sửa logic còn lại:
hash_intel = VirusTotalHashIntel(api_key=os.getenv("VT_API_KEY"))
ip_intel   = AbuseIPDBIntel(api_key=os.getenv("ABUSEIPDB_KEY"))
asset_db   = ServiceNowCMDB(instance="company.service-now.com", ...)
```

### Upgrade Ticketing (TheHive thật)

```python
# actions/ticketing.py: thêm TheHiveTicketing class
# TheHive API: POST /api/case với thông tin từ ticket dict
```

### Docker Compose

```yaml
# docker-compose.yml
services:
  soar-pipeline:
    build: .
    command: python main.py --scenario mixed
  soar-dashboard:
    build: .
    command: streamlit run dashboard/app.py --server.port 8501
    ports: ["8501:8501"]
```

### SOAR Platform Integration

Thay Python script bằng **n8n** hoặc **Shuffle** workflow:
- Mỗi node trong workflow = 1 bước enrichment
- Visual pipeline editor → dễ demo hơn cho non-technical stakeholders
- Webhook trigger từ EDR thật (CrowdStrike, SentinelOne...)

---

## 👤 About

**Project type:** Blue Team / SOC CV Project  
**Tech focus:** SOAR Automation, Threat Intelligence, MITRE ATT&CK, Python  
**Timeline:** ~1 tháng (solo project)

---

*Built with ❤️ for Blue Team — SOAR Malware Playbook v1.0*
