"""
dashboard/app.py
================
Streamlit Dashboard — Demo trực quan toàn bộ SOAR pipeline.

Giao diện gồm 4 tab:
  1. 🚀 Run Pipeline   — nhập alert hoặc chọn scenario → chạy pipeline
  2. 📊 Results        — enrichment details, risk score breakdown, actions
  3. 📋 Incident Report— xem report Markdown trực tiếp trong dashboard
  4. 📁 Alert History  — xem tất cả alert đã xử lý trong session

Chạy: streamlit run dashboard/app.py
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Đảm bảo import được các module trong project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

# ── Cấu hình trang ────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOAR Malware Playbook",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* Font */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

  /* Ẩn Streamlit default elements */
  #MainMenu { visibility: hidden; }
  footer    { visibility: hidden; }
  header    { visibility: hidden; }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 16px;
  }

  /* Tabs */
  .stTabs [data-baseweb="tab-list"] { gap: 8px; }
  .stTabs [data-baseweb="tab"] {
    border-radius: 6px 6px 0 0;
    padding: 8px 20px;
    font-weight: 600;
  }

  /* Code blocks */
  .stCode { font-family: 'JetBrains Mono', monospace; }

  /* Divider */
  hr { border-color: #334155; }
</style>
""", unsafe_allow_html=True)


# ── Imports pipeline ──────────────────────────────────────────────────
@st.cache_resource
def load_pipeline_components():
    """Load các component một lần, cache lại."""
    from alert_generator.generator import generate_alert
    from services.workflow_service import SoarWorkflowService

    return {
        "generate_alert": generate_alert,
        "workflow": SoarWorkflowService(verbose=False),
    }


components = load_pipeline_components()


# ── Session state ─────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []
if "last_response" not in st.session_state:
    st.session_state.last_response = None
if "last_md_report" not in st.session_state:
    st.session_state.last_md_report = None


# ── Helper functions ──────────────────────────────────────────────────
def risk_color(level: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(level, "⚪")


def rep_badge(rep: str) -> str:
    badges = {
        "malicious":  "🔴 MALICIOUS",
        "suspicious": "🟡 SUSPICIOUS",
        "clean":      "🟢 CLEAN",
        "unknown":    "⚪ UNKNOWN",
    }
    return badges.get(rep, rep.upper())


def run_pipeline(alert_data: dict):
    """Chạy full pipeline và lưu vào session state."""
    with st.spinner("🔄 Running SOAR Pipeline..."):
        result = components["workflow"].process_alert_payload(
            alert_data,
            generate_report=True,
            export_pdf=False,
            include_markdown_content=True,
        )
        alert = result.alert
        enriched = result.enriched_alert
        response = result.response

        # Lưu vào session
        st.session_state.last_response = response
        st.session_state.last_md_report = result.artifacts.markdown_content

        # Thêm vào history
        st.session_state.history.append({
            "alert_id":   alert.alert_id,
            "hostname":   alert.hostname,
            "detection":  alert.detection_name,
            "risk_score": enriched.risk_score,
            "risk_level": enriched.risk_level,
            "actions":    [a.value for a in response.triggered_actions],
            "ticket_id":  response.ticket_id,
            "timestamp":  datetime.utcnow().strftime("%H:%M:%S"),
        })

    return response


# ═════════════════════════════════════════════════════════════════════
# HEADER
# ═════════════════════════════════════════════════════════════════════
col_logo, col_title = st.columns([1, 10])
with col_logo:
    st.markdown("## 🛡️")
with col_title:
    st.markdown(
        "<h1 style='margin:0;font-size:28px;font-weight:700;'>SOAR Malware Playbook</h1>"
        "<p style='margin:0;color:#64748b;font-size:14px;'>Automated Malware Alert Response System — Blue Team CV Project</p>",
        unsafe_allow_html=True
    )

st.divider()

# ═════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("### ⚙️ Pipeline Control")

    input_mode = st.radio(
        "Input Mode",
        ["🎲 Generate by Scenario", "📂 Load Sample Alert", "✏️ Custom JSON"],
        label_visibility="collapsed",
    )

    scenario_map = {
        "🔴 Mixed (all triggers)":    "mixed",
        "🔴 Malicious Hash":          "malicious_hash",
        "🔴 C2 Communication":        "c2_communication",
        "🔴 Critical Asset":          "critical_asset",
        "🟠 Dangerous Process":       "dangerous_process",
        "🟢 Benign Alert":            "benign",
        "🎲 Random":                  "random",
    }

    selected_alert_data = None

    if input_mode == "🎲 Generate by Scenario":
        selected_label = st.selectbox("Scenario", list(scenario_map.keys()))
        seed = st.number_input("Random Seed", value=2024, min_value=0, max_value=9999)

        if st.button("▶️ Run Pipeline", type="primary", use_container_width=True):
            scenario = scenario_map[selected_label]
            alert = components["generate_alert"](scenario=scenario, seed=int(seed))
            selected_alert_data = alert.model_dump(mode="json")
            # Xử lý datetime fields
            selected_alert_data["received_at"] = alert.received_at.isoformat()
            run_pipeline(selected_alert_data)

    elif input_mode == "📂 Load Sample Alert":
        sample_dir = Path("data/sample_alerts")
        sample_files = list(sample_dir.glob("*.json")) if sample_dir.exists() else []

        if sample_files:
            selected_file = st.selectbox(
                "Sample Alert",
                sample_files,
                format_func=lambda p: p.name
            )
            if st.button("▶️ Run Pipeline", type="primary", use_container_width=True):
                with open(selected_file, "r", encoding="utf-8") as f:
                    selected_alert_data = json.load(f)
                run_pipeline(selected_alert_data)
        else:
            st.warning("Chưa có sample alerts. Chạy bước (f) để tạo.")

    else:  # Custom JSON
        default_json = """{
  "alert_id": "test-alert-001",
  "hostname": "SRV-DC01",
  "username": "admin",
  "process_name": "mimikatz.exe",
  "file_path": "C:\\\\Windows\\\\Temp\\\\mimikatz.exe",
  "file_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "parent_process": "explorer.exe",
  "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
  "destination_ip": "185.220.101.45",
  "severity": "critical",
  "detection_name": "HackTool.Mimikatz"
}"""
        json_input = st.text_area("Alert JSON", default_json, height=280)

        if st.button("▶️ Run Pipeline", type="primary", use_container_width=True):
            try:
                selected_alert_data = json.loads(json_input)
                run_pipeline(selected_alert_data)
            except json.JSONDecodeError as e:
                st.error(f"JSON parse error: {e}")

    st.divider()

    # Session stats
    st.markdown("### 📈 Session Stats")
    history = st.session_state.history
    if history:
        total    = len(history)
        critical = sum(1 for h in history if h["risk_level"] == "critical")
        high_cnt = sum(1 for h in history if h["risk_level"] == "high")
        st.metric("Alerts Processed", total)
        col1, col2 = st.columns(2)
        col1.metric("🔴 Critical", critical)
        col2.metric("🟠 High", high_cnt)
    else:
        st.info("Chưa có alert nào được xử lý.")


# ═════════════════════════════════════════════════════════════════════
# MAIN TABS
# ═════════════════════════════════════════════════════════════════════
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Results", "🔍 Enrichment Details", "📋 Incident Report", "📁 Alert History"
])

response = st.session_state.last_response

# ─────────────────────────────────────────────────────────────────────
# TAB 1: Results Overview
# ─────────────────────────────────────────────────────────────────────
with tab1:
    if response is None:
        st.info("👈 Chọn scenario và nhấn **Run Pipeline** ở sidebar để bắt đầu.")
        st.markdown("""
        ### Cách sử dụng:
        1. **Sidebar** → chọn input mode (Generate / Load File / Custom JSON)
        2. Chọn scenario (ví dụ: *Mixed — all triggers*)
        3. Nhấn **▶️ Run Pipeline**
        4. Xem kết quả ở các tab bên dưới

        ### Workflow 7 bước:
        ```
        1. Nhận alert  →  2. Enrich Hash  →  3. Enrich IP
        4. Asset Crit  →  5. MITRE Map    →  6. Risk Score
        7. Policy Engine → Actions → Ticket → Report
        ```
        """)
    else:
        enriched = response.enriched_alert
        alert    = enriched.original_alert

        # ── Top KPI row ───────────────────────────────────────────────
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("🎯 Risk Score", f"{enriched.risk_score:.1f}/100")
        c2.metric(
            "⚠️ Risk Level",
            f"{risk_color(enriched.risk_level)} {enriched.risk_level.upper()}"
        )
        c3.metric("🏥 Asset Criticality", enriched.asset_criticality.value.upper())
        c4.metric("🎯 MITRE Techniques", len(enriched.mitre_mappings))
        c5.metric("🎫 Ticket", response.ticket_id or "—")

        st.divider()

        # ── Alert summary + Actions ───────────────────────────────────
        col_left, col_right = st.columns([1.2, 1])

        with col_left:
            st.markdown("#### 📋 Alert Summary")
            info_data = {
                "Alert ID":      alert.alert_id,
                "Hostname":      alert.hostname,
                "Username":      alert.username,
                "Process":       alert.process_name,
                "Parent":        alert.parent_process,
                "Detection":     alert.detection_name,
                "EDR Severity":  alert.severity.value.upper(),
                "Destination IP":alert.destination_ip,
            }
            for k, v in info_data.items():
                st.markdown(f"**{k}:** `{v}`")

            st.markdown("**Command Line:**")
            st.code(alert.command_line, language="bash")

        with col_right:
            st.markdown("#### ⚡ Actions Triggered")
            from schemas.alert import ResponseAction
            main_actions = [
                a for a in response.triggered_actions
                if a not in (ResponseAction.CREATE_TICKET, ResponseAction.NOTIFY_SOC)
            ]

            action_icons = {
                "isolate_host": "🔴 ISOLATE HOST",
                "kill_process": "🛑 KILL PROCESS",
                "block_ip":     "🚫 BLOCK IP",
                "escalate":     "⬆️ ESCALATE",
            }

            if main_actions:
                for a in main_actions:
                    label = action_icons.get(a.value, a.value.upper())
                    st.error(label)
            else:
                st.success("✅ NO ACTION REQUIRED")

            st.markdown("**Always executed:**")
            st.info("🎫 CREATE TICKET")
            st.info("📢 NOTIFY SOC")

            st.divider()
            st.markdown("#### 🔍 Policy Reasoning")
            for reason in response.policy_reasoning:
                if "TRIGGERED" in reason:
                    st.error(f"🔴 {reason}")
                elif "PASS" in reason:
                    st.success(f"🟢 {reason}")
                else:
                    st.warning(f"🟡 {reason}")


# ─────────────────────────────────────────────────────────────────────
# TAB 2: Enrichment Details
# ─────────────────────────────────────────────────────────────────────
with tab2:
    if response is None:
        st.info("Chạy pipeline trước để xem enrichment details.")
    else:
        enriched = response.enriched_alert
        alert    = enriched.original_alert

        col_a, col_b = st.columns(2)

        # Hash enrichment
        with col_a:
            st.markdown("#### 🔍 Hash Reputation")
            if enriched.hash_enrichment:
                h = enriched.hash_enrichment
                st.markdown(f"**Hash:** `{alert.file_hash[:32]}...`")
                rep_val = h.reputation.value
                if rep_val == "malicious":
                    st.error(f"🔴 MALICIOUS — {h.malicious_vendors}/{h.total_vendors} vendors")
                elif rep_val == "suspicious":
                    st.warning(f"🟡 SUSPICIOUS — {h.malicious_vendors}/{h.total_vendors} vendors")
                else:
                    st.success(f"🟢 {rep_val.upper()}")

                st.markdown(f"**Threat Name:** {h.threat_name or '—'}")
                st.markdown(f"**Source:** `{h.source}`")

                # Detection rate bar
                if h.total_vendors > 0:
                    ratio = h.malicious_vendors / h.total_vendors
                    st.progress(ratio, text=f"Detection Rate: {ratio:.0%}")

            # Asset info
            st.divider()
            st.markdown("#### 🏢 Asset Criticality (CMDB)")
            crit = enriched.asset_criticality.value
            if crit == "critical":
                st.error(f"🔴 CRITICAL — {alert.hostname}")
            elif crit == "normal":
                st.warning(f"🟡 NORMAL — {alert.hostname}")
            else:
                st.success(f"🟢 LOW — {alert.hostname}")

        # IP enrichment
        with col_b:
            st.markdown("#### 🌐 IP Reputation")
            if enriched.ip_enrichment:
                ip = enriched.ip_enrichment
                rep_val = ip.reputation.value
                c2_badge = " 🚨 [C2]" if ip.is_c2 else ""
                if rep_val == "malicious":
                    st.error(f"🔴 MALICIOUS{c2_badge} — {alert.destination_ip}")
                else:
                    st.success(f"🟢 CLEAN — {alert.destination_ip}")

                st.markdown(f"**Confidence:** {ip.confidence_score}/100")
                st.progress(ip.confidence_score / 100, text=f"Abuse Confidence: {ip.confidence_score}%")
                st.markdown(f"**Is C2:** {'⚠️ YES' if ip.is_c2 else 'No'}")
                st.markdown(f"**Country:** {ip.country or '—'}")
                st.markdown(f"**ISP:** {ip.isp or '—'}")
                st.markdown(f"**Source:** `{ip.source}`")

            st.divider()
            # Risk score breakdown
            st.markdown("#### 📊 Risk Score Breakdown")
            st.markdown(f"### {risk_color(enriched.risk_level)} **{enriched.risk_score:.1f} / 100** — {enriched.risk_level.upper()}")

            score = enriched.risk_score
            st.progress(score / 100, text=f"Risk Score: {score:.1f}/100")

        # MITRE mappings
        st.divider()
        st.markdown("#### 🎯 MITRE ATT&CK Techniques")
        if enriched.mitre_mappings:
            mitre_data = [
                {
                    "Technique ID":   m.technique_id,
                    "Technique Name": m.technique_name,
                    "Tactic":         m.tactic,
                    "Confidence":     f"{m.confidence:.0%}",
                    "Matched Pattern": m.matched_pattern,
                }
                for m in enriched.mitre_mappings
            ]
            st.dataframe(mitre_data, use_container_width=True)
        else:
            st.info("Không có MITRE ATT&CK technique nào được mapping cho alert này.")


# ─────────────────────────────────────────────────────────────────────
# TAB 3: Incident Report
# ─────────────────────────────────────────────────────────────────────
with tab3:
    if st.session_state.last_md_report is None:
        st.info("Chạy pipeline trước để xem incident report.")
    else:
        md_content = st.session_state.last_md_report

        col_btn1, col_btn2, col_spacer = st.columns([1, 1, 5])
        with col_btn1:
            st.download_button(
                "⬇️ Download Markdown",
                data=md_content.encode("utf-8"),
                file_name=f"incident_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
            )

        # Render report
        st.markdown(md_content)


# ─────────────────────────────────────────────────────────────────────
# TAB 4: Alert History
# ─────────────────────────────────────────────────────────────────────
with tab4:
    history = st.session_state.history

    if not history:
        st.info("Chưa có alert nào được xử lý trong session này.")
    else:
        st.markdown(f"### {len(history)} Alert(s) Processed This Session")

        for i, item in enumerate(reversed(history), 1):
            level = item["risk_level"]
            icon  = risk_color(level)
            with st.expander(
                f"{icon} [{item['timestamp']}] {item['alert_id'][:16]}... — "
                f"{item['hostname']} — {level.upper()} ({item['risk_score']:.1f})",
                expanded=(i == 1)
            ):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Alert ID:** `{item['alert_id']}`")
                    st.markdown(f"**Hostname:** `{item['hostname']}`")
                    st.markdown(f"**Detection:** {item['detection']}")
                with col2:
                    st.markdown(f"**Risk Score:** {item['risk_score']:.1f}/100")
                    st.markdown(f"**Risk Level:** {level.upper()}")
                    st.markdown(f"**Ticket:** `{item['ticket_id'] or 'N/A'}`")

                if item["actions"]:
                    st.markdown("**Actions:** " + " | ".join(f"`{a}`" for a in item["actions"]))

        if st.button("🗑️ Clear History"):
            st.session_state.history = []
            st.session_state.last_response = None
            st.session_state.last_md_report = None
            st.rerun()
