"""
Legacy Streamlit dashboard.

The primary analyst UI now lives in `dashboard/src/` and runs through the
React/Vite app. Keep this file only as historical reference while the team
finishes the React migration.
"""

from __future__ import annotations

import json
import html as html_lib
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

# ═══════════════════════════════════════════════════════════════════════
# Page config — must be first Streamlit call
# ═══════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SOAR Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════
# Global CSS — dark SOC theme
# ═══════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
  /* ── Fonts ── */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg-primary:    #0a0e17;
    --bg-secondary:  #111827;
    --bg-card:       rgba(17, 24, 39, 0.85);
    --bg-card-hover: rgba(30, 41, 59, 0.95);
    --bg-glass:      rgba(255, 255, 255, 0.03);
    --border:        rgba(255, 255, 255, 0.06);
    --border-hover:  rgba(255, 255, 255, 0.12);
    --text-primary:  #f1f5f9;
    --text-secondary:#94a3b8;
    --text-muted:    #64748b;
    --accent-blue:   #3b82f6;
    --accent-cyan:   #06b6d4;
    --critical:      #ef4444;
    --critical-glow: rgba(239, 68, 68, 0.25);
    --high:          #f97316;
    --high-glow:     rgba(249, 115, 22, 0.20);
    --medium:        #eab308;
    --medium-glow:   rgba(234, 179, 8, 0.18);
    --low:           #22c55e;
    --low-glow:      rgba(34, 197, 94, 0.18);
    --success:       #10b981;
    --radius-sm:     8px;
    --radius-md:     12px;
    --radius-lg:     16px;
    --radius-xl:     20px;
    --shadow:        0 4px 24px rgba(0, 0, 0, 0.3);
    --shadow-glow:   0 0 32px rgba(59, 130, 246, 0.08);
    --transition:    all 0.2s ease;
  }

  /* ── Global ── */
  html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, sans-serif !important;
    color: var(--text-primary);
  }
  code, pre, .stCode {
    font-family: 'JetBrains Mono', monospace !important;
  }
  .stApp {
    background: var(--bg-primary);
    background-image:
      radial-gradient(ellipse at 10% 0%, rgba(59,130,246,0.07) 0%, transparent 50%),
      radial-gradient(ellipse at 90% 0%, rgba(6,182,212,0.05) 0%, transparent 50%),
      radial-gradient(ellipse at 50% 100%, rgba(139,92,246,0.04) 0%, transparent 50%);
  }

  /* ── Hide Streamlit chrome ── */
  #MainMenu, footer, header { visibility: hidden; }
  .block-container { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1400px; }

  /* ── Sidebar ── */
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1320 0%, #111827 100%);
    border-right: 1px solid var(--border);
  }
  [data-testid="stSidebar"] * {
    color: var(--text-primary) !important;
  }
  [data-testid="stSidebar"] .stSelectbox label,
  [data-testid="stSidebar"] .stRadio label,
  [data-testid="stSidebar"] .stNumberInput label,
  [data-testid="stSidebar"] .stTextArea label {
    color: var(--text-secondary) !important;
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
  }

  /* ── Tab bar ── */
  .stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: rgba(255,255,255,0.02);
    border-radius: var(--radius-lg);
    padding: 4px;
    border: 1px solid var(--border);
  }
  .stTabs [data-baseweb="tab"] {
    height: 44px;
    border-radius: var(--radius-md);
    padding: 0 20px;
    font-weight: 600;
    font-size: 0.88rem;
    color: var(--text-secondary);
    background: transparent;
    border: none;
    transition: var(--transition);
  }
  .stTabs [aria-selected="true"] {
    background: rgba(59,130,246,0.15) !important;
    color: var(--accent-blue) !important;
    border: 1px solid rgba(59,130,246,0.25) !important;
  }
  .stTabs [data-baseweb="tab-highlight"] { display: none; }
  .stTabs [data-baseweb="tab-border"] { display: none; }

  /* ── DataFrame ── */
  [data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  /* ── Custom blocks ── */
  .soar-hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0f2744 100%);
    border: 1px solid rgba(59,130,246,0.15);
    border-radius: var(--radius-xl);
    padding: 32px 36px 28px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow), var(--shadow-glow);
  }
  .soar-hero::before {
    content: '';
    position: absolute;
    top: 0; right: 0;
    width: 340px; height: 340px;
    background: radial-gradient(circle, rgba(6,182,212,0.12) 0%, transparent 70%);
    pointer-events: none;
  }
  .soar-hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(59,130,246,0.15);
    border: 1px solid rgba(59,130,246,0.25);
    border-radius: 999px;
    padding: 5px 14px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--accent-blue);
  }
  .soar-hero h1 {
    margin: 12px 0 6px;
    font-size: 1.75rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: white;
    line-height: 1.15;
  }
  .soar-hero p {
    margin: 0;
    color: rgba(255,255,255,0.55);
    font-size: 0.92rem;
    max-width: 700px;
  }

  .soar-metric {
    background: linear-gradient(135deg, rgba(17,24,39,0.9) 0%, rgba(30,41,59,0.7) 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 20px 22px;
    min-height: 120px;
    box-shadow: var(--shadow);
    transition: var(--transition);
    position: relative;
    overflow: hidden;
  }
  .soar-metric::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
  }
  .soar-metric.accent-critical::after { background: var(--critical); box-shadow: 0 0 12px var(--critical-glow); }
  .soar-metric.accent-high::after     { background: var(--high);     box-shadow: 0 0 12px var(--high-glow); }
  .soar-metric.accent-medium::after   { background: var(--medium);   box-shadow: 0 0 12px var(--medium-glow); }
  .soar-metric.accent-low::after      { background: var(--low);      box-shadow: 0 0 12px var(--low-glow); }
  .soar-metric.accent-blue::after     { background: var(--accent-blue); box-shadow: 0 0 12px rgba(59,130,246,0.2); }
  .soar-metric.accent-cyan::after     { background: var(--accent-cyan); box-shadow: 0 0 12px rgba(6,182,212,0.2); }
  .soar-metric-label {
    color: var(--text-muted);
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 10px;
  }
  .soar-metric-value {
    font-size: 2rem;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -0.02em;
  }
  .soar-metric-foot {
    margin-top: 8px;
    color: var(--text-muted);
    font-size: 0.78rem;
    line-height: 1.4;
  }
  .val-critical { color: var(--critical); }
  .val-high     { color: var(--high); }
  .val-medium   { color: var(--medium); }
  .val-low      { color: var(--low); }
  .val-blue     { color: var(--accent-blue); }
  .val-cyan     { color: var(--accent-cyan); }
  .val-white    { color: var(--text-primary); }

  .soar-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 24px;
    box-shadow: var(--shadow);
    backdrop-filter: blur(8px);
  }
  .soar-card-title {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-primary);
    font-size: 0.95rem;
    font-weight: 700;
    margin-bottom: 4px;
  }
  .soar-card-subtitle {
    color: var(--text-muted);
    font-size: 0.82rem;
    margin-bottom: 16px;
    line-height: 1.5;
  }

  .soar-kv {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 10px;
  }
  .soar-kv-item {
    background: rgba(255,255,255,0.02);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 12px 14px;
  }
  .soar-kv-label {
    color: var(--text-muted);
    font-size: 0.68rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 4px;
  }
  .soar-kv-value {
    color: var(--text-primary);
    font-weight: 600;
    font-size: 0.88rem;
    word-break: break-all;
  }

  .soar-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border-radius: 999px;
    padding: 5px 14px;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid transparent;
    margin: 0 6px 6px 0;
    letter-spacing: 0.03em;
  }
  .pill-critical { background: rgba(239,68,68,0.12);  color: var(--critical); border-color: rgba(239,68,68,0.25); }
  .pill-high     { background: rgba(249,115,22,0.12); color: var(--high);     border-color: rgba(249,115,22,0.25); }
  .pill-medium   { background: rgba(234,179,8,0.12);  color: var(--medium);   border-color: rgba(234,179,8,0.25); }
  .pill-low      { background: rgba(34,197,94,0.12);  color: var(--low);      border-color: rgba(34,197,94,0.25); }
  .pill-blue     { background: rgba(59,130,246,0.12); color: var(--accent-blue); border-color: rgba(59,130,246,0.25); }
  .pill-neutral  { background: rgba(255,255,255,0.04); color: var(--text-secondary); border-color: var(--border); }

  .soar-rule {
    background: rgba(255,255,255,0.02);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 14px 16px;
    margin-bottom: 8px;
    transition: var(--transition);
  }
  .soar-rule:hover { border-color: var(--border-hover); }
  .soar-rule-header {
    font-weight: 700;
    font-size: 0.85rem;
    margin-bottom: 4px;
  }
  .soar-rule-body {
    color: var(--text-secondary);
    font-size: 0.82rem;
    line-height: 1.5;
  }

  .soar-action-item {
    background: rgba(255,255,255,0.02);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 14px 16px;
    margin-bottom: 8px;
  }
  .soar-action-header {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
    font-size: 0.85rem;
    margin-bottom: 4px;
  }
  .soar-action-detail {
    color: var(--text-secondary);
    font-size: 0.80rem;
    line-height: 1.5;
  }
  .soar-action-time {
    color: var(--text-muted);
    font-size: 0.75rem;
    margin-top: 4px;
  }

  .soar-queue-item {
    display: flex;
    align-items: center;
    gap: 14px;
    background: rgba(255,255,255,0.02);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 12px 14px;
    margin-bottom: 6px;
    cursor: default;
    transition: var(--transition);
  }
  .soar-queue-item:hover { border-color: var(--border-hover); background: rgba(255,255,255,0.04); }
  .soar-queue-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot-critical { background: var(--critical); box-shadow: 0 0 6px var(--critical-glow); }
  .dot-high     { background: var(--high);     box-shadow: 0 0 6px var(--high-glow); }
  .dot-medium   { background: var(--medium);   box-shadow: 0 0 6px var(--medium-glow); }
  .dot-low      { background: var(--low);      box-shadow: 0 0 6px var(--low-glow); }
  .soar-queue-main {
    flex: 1;
    min-width: 0;
  }
  .soar-queue-host {
    font-weight: 600;
    font-size: 0.85rem;
    color: var(--text-primary);
  }
  .soar-queue-detection {
    color: var(--text-muted);
    font-size: 0.78rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .soar-queue-score {
    font-weight: 700;
    font-size: 0.82rem;
    flex-shrink: 0;
  }

  .soar-section-gap { margin-top: 20px; }

  /* ── Narrative panel ── */
  .soar-narrative {
    background: rgba(59,130,246,0.04);
    border: 1px solid rgba(59,130,246,0.12);
    border-radius: var(--radius-lg);
    padding: 24px;
  }
  .soar-narrative h3 { color: var(--accent-blue); margin: 0 0 12px; font-size: 1rem; }
  .soar-narrative p, .soar-narrative li {
    color: var(--text-secondary);
    line-height: 1.7;
    font-size: 0.88rem;
  }
  .soar-narrative code {
    background: rgba(255,255,255,0.06);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 0.82rem;
  }

  /* ── Risk bar ── */
  .soar-risk-bar-track {
    width: 100%;
    height: 8px;
    background: rgba(255,255,255,0.06);
    border-radius: 4px;
    overflow: hidden;
    margin: 8px 0;
  }
  .soar-risk-bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.8s ease;
  }
  .bar-critical { background: linear-gradient(90deg, var(--critical), #f87171); }
  .bar-high     { background: linear-gradient(90deg, var(--high), #fb923c); }
  .bar-medium   { background: linear-gradient(90deg, var(--medium), #facc15); }
  .bar-low      { background: linear-gradient(90deg, var(--low), #4ade80); }
  .bar-blue     { background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan)); }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════
# Pipeline components (cached)
# ═══════════════════════════════════════════════════════════════════════
@st.cache_resource
def load_components() -> dict[str, Any]:
    from alert_generator.generator import generate_alert
    from services.workflow_service import SoarWorkflowService
    workflow = SoarWorkflowService(verbose=False)
    return {"generate_alert": generate_alert, "workflow": workflow}


components = load_components()
workflow = components["workflow"]


# ═══════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════
def esc(text: Any) -> str:
    """HTML-escape a value for safe embedding."""
    return html_lib.escape(str(text)) if text else "—"


def fmt_ts(raw: str | None) -> str:
    if not raw:
        return "—"
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(raw)


def short(value: str | None, n: int = 20) -> str:
    if not value:
        return "—"
    return value if len(value) <= n else f"{value[:n-3]}…"


def risk_tone(level: str | None) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
        (level or "").lower(), "blue"
    )


def risk_icon(level: str | None) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
        (level or "").lower(), "⚪"
    )


def pill(label: str, tone: str = "neutral") -> str:
    return f"<span class='soar-pill pill-{tone}'>{esc(label)}</span>"


def metric_card(title: str, value: str, foot: str, tone: str = "blue") -> str:
    return f"""
    <div class="soar-metric accent-{tone}">
      <div class="soar-metric-label">{esc(title)}</div>
      <div class="soar-metric-value val-{tone}">{value}</div>
      <div class="soar-metric-foot">{esc(foot)}</div>
    </div>"""


def kv_grid(items: list[tuple[str, Any]]) -> str:
    cells = "".join(
        f"""<div class="soar-kv-item">
              <div class="soar-kv-label">{esc(label)}</div>
              <div class="soar-kv-value">{esc(value)}</div>
            </div>"""
        for label, value in items
    )
    return f"<div class='soar-kv'>{cells}</div>"


def risk_bar(score: float, level: str) -> str:
    pct = min(max(score, 0), 100)
    tone = risk_tone(level)
    return f"""
    <div class="soar-risk-bar-track">
      <div class="soar-risk-bar-fill bar-{tone}" style="width: {pct}%"></div>
    </div>"""


def db_label(raw: str | Path) -> str:
    v = str(raw)
    if "supabase.com" in v:
        return "☁️ Supabase Postgres"
    if v.startswith("postgresql://") or v.startswith("postgres://"):
        return "🐘 Postgres"
    return "💾 SQLite (local)"


def remediation_actions(record: dict) -> list[str]:
    actions = record["response"].get("triggered_actions", [])
    return [a for a in actions if a not in {"create_ticket", "notify_soc"}]


# ═══════════════════════════════════════════════════════════════════════
# Data loading
# ═══════════════════════════════════════════════════════════════════════
incidents = workflow.list_incidents(limit=200)
metrics = workflow.get_incident_metrics()
db_src = db_label(workflow.db_path)

if "sel_alert" not in st.session_state:
    st.session_state.sel_alert = incidents[0]["alert_id"] if incidents else None
elif incidents and st.session_state.sel_alert not in {i["alert_id"] for i in incidents}:
    st.session_state.sel_alert = incidents[0]["alert_id"]


def get_detail(alert_id: str | None) -> dict | None:
    if not alert_id:
        return None
    return workflow.get_incident_by_alert_id(alert_id)


# ═══════════════════════════════════════════════════════════════════════
# HERO HEADER
# ═══════════════════════════════════════════════════════════════════════
st.markdown(f"""
<div class="soar-hero">
  <span class="soar-hero-badge">🛡️ SOAR Malware Playbook · {esc(db_src)}</span>
  <h1>Command Center</h1>
  <p>Automated endpoint malware alert triage, threat enrichment, MITRE ATT&CK mapping, risk scoring, and policy-driven response — all from a single interface.</p>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════
# SIDEBAR — Alert intake
# ═══════════════════════════════════════════════════════════════════════
SCENARIOS = {
    "🔴 Mixed (all triggers)": "mixed",
    "🔴 Malicious Hash": "malicious_hash",
    "🔴 C2 Communication": "c2_communication",
    "🟠 Critical Asset": "critical_asset",
    "🟠 Dangerous Process": "dangerous_process",
    "🟢 Benign Alert": "benign",
    "🎲 Random": "random",
}

sample_dir = Path("data/sample_alerts")
sample_files = sorted(sample_dir.glob("*.json")) if sample_dir.exists() else []

with st.sidebar:
    st.markdown("### ⚡ Alert Intake")
    st.caption("Process a new alert through the SOAR pipeline.")

    with st.form("intake_form", clear_on_submit=False):
        mode = st.radio(
            "Source",
            ["scenario", "sample", "json"],
            format_func={"scenario": "Generate scenario", "sample": "Load sample file", "json": "Paste JSON"}.get,
            horizontal=True,
        )
        scenario_name = st.selectbox("Scenario", list(SCENARIOS.keys()))
        seed = st.number_input("Seed", min_value=0, max_value=999999, value=2024)

        sample_file = None
        if sample_files:
            sample_file = st.selectbox("Sample file", sample_files, format_func=lambda p: p.name, disabled=mode != "sample")
        else:
            st.caption("No sample alerts in `data/sample_alerts/`.")

        json_input = st.text_area("Custom JSON", value='{"alert_id":"demo-001","hostname":"SRV-DC01","username":"admin","process_name":"mimikatz.exe","file_path":"C:\\\\Temp\\\\m.exe","file_hash":"' + "a1b2c3d4" * 8 + '","parent_process":"explorer.exe","command_line":"mimikatz.exe sekurlsa::logonpasswords","destination_ip":"185.220.101.45","severity":"critical","detection_name":"HackTool.Mimikatz"}', height=180, disabled=mode != "json")

        go = st.form_submit_button("▶ Process Alert", use_container_width=True, type="primary")

        if go:
            try:
                if mode == "scenario":
                    alert_obj = components["generate_alert"](scenario=SCENARIOS[scenario_name], seed=int(seed))
                    payload = alert_obj.model_dump(mode="json")
                    payload["received_at"] = alert_obj.received_at.isoformat()
                elif mode == "sample" and sample_file:
                    with open(sample_file, "r", encoding="utf-8") as f:
                        payload = json.load(f)
                else:
                    payload = json.loads(json_input)

                result = workflow.process_alert_payload(payload, generate_report=False, export_pdf=False, include_markdown_content=False)
                st.session_state.sel_alert = result.alert.alert_id
                st.session_state.last_run_info = {
                    "alert_id": result.alert.alert_id,
                    "risk_level": result.enriched_alert.risk_level,
                    "ticket_id": result.response.ticket_id,
                }
                st.success(f"✅ Incident persisted")
                st.rerun()
            except Exception as exc:
                st.error(f"❌ {exc}")

    st.divider()

    # ── Sidebar: DB info ──
    st.markdown("### 💾 Database")
    st.caption(f"Source: {db_src}")
    if st.button("🔄 Refresh", use_container_width=True):
        st.rerun()

    # ── Sidebar: Last run badge ──
    if st.session_state.get("last_run_info"):
        info = st.session_state.last_run_info
        t = risk_tone(info["risk_level"])
        st.markdown("### 📌 Last Processed")
        st.markdown(
            pill(info["risk_level"].upper(), t) + pill(info.get("ticket_id") or "—", "neutral"),
            unsafe_allow_html=True,
        )
        st.caption(f"Alert: {short(info['alert_id'], 24)}")


# ═══════════════════════════════════════════════════════════════════════
# METRIC CARDS — top row
# ═══════════════════════════════════════════════════════════════════════
c1, c2, c3, c4 = st.columns(4, gap="medium")

with c1:
    st.markdown(metric_card(
        "Total Incidents", str(metrics["total_incidents"]),
        "All persisted workflow executions", "blue"
    ), unsafe_allow_html=True)

with c2:
    crit = metrics["critical_incidents"]
    high = metrics["high_incidents"]
    t = "critical" if crit > 0 else ("high" if high > 0 else "low")
    st.markdown(metric_card(
        "Critical / High", f"{crit} <span style='opacity:0.4;font-size:1.2rem'>/</span> {high}",
        "Priority triage queue", t
    ), unsafe_allow_html=True)

with c3:
    avg = float(metrics["average_risk_score"])
    avg_t = "critical" if avg >= 76 else "high" if avg >= 51 else "medium" if avg >= 26 else "low"
    st.markdown(metric_card(
        "Avg. Risk Score", f"{avg:.1f}",
        "Mean across all incidents", avg_t
    ), unsafe_allow_html=True)

with c4:
    latest = fmt_ts(metrics.get("latest_completed_at"))
    st.markdown(metric_card(
        "Latest Incident", latest.split(" ")[0] if latest != "—" else "—",
        "Most recently processed", "cyan"
    ), unsafe_allow_html=True)

st.markdown("<div class='soar-section-gap'></div>", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════════
tab_overview, tab_history, tab_detail = st.tabs([
    "📊  Overview", "📁  Incident History", "🔍  Deep Dive"
])


# ─────────────────────────────────────────────────────────────────────
# TAB 1: OVERVIEW
# ─────────────────────────────────────────────────────────────────────
with tab_overview:
    col_main, col_side = st.columns([1.4, 1], gap="medium")

    # ── Left: Current focus ──
    with col_main:
        st.markdown("""<div class="soar-card">
          <div class="soar-card-title">📋 Current Focus</div>
          <div class="soar-card-subtitle">Latest selected incident from the database. Use the sidebar to process new alerts.</div>
        """, unsafe_allow_html=True)

        record = get_detail(st.session_state.sel_alert)

        if record is None:
            st.info("No incidents yet. Process an alert using the sidebar to get started.")
        else:
            alert = record["alert"]
            enriched = record["enriched_alert"]
            response = record["response"]
            rl = enriched["risk_level"]

            st.markdown(
                pill(f"{risk_icon(rl)} {rl.upper()}", risk_tone(rl))
                + pill(f"Score: {enriched['risk_score']:.1f}/100", risk_tone(rl))
                + pill(f"🎫 {response.get('ticket_id') or '—'}", "neutral"),
                unsafe_allow_html=True,
            )
            st.markdown(risk_bar(enriched["risk_score"], rl), unsafe_allow_html=True)

            st.markdown(kv_grid([
                ("Alert ID", alert["alert_id"]),
                ("Hostname", alert["hostname"]),
                ("Detection", alert["detection_name"]),
                ("Severity", alert["severity"].upper()),
                ("Process", alert["process_name"]),
                ("Destination IP", alert["destination_ip"]),
                ("Parent Process", alert["parent_process"]),
                ("Completed", fmt_ts(response.get("completed_at"))),
            ]), unsafe_allow_html=True)

            st.markdown("<div style='margin-top:14px'></div>", unsafe_allow_html=True)
            st.markdown("**Command Line**")
            st.code(alert["command_line"], language="powershell")

        st.markdown("</div>", unsafe_allow_html=True)

    # ── Right: Risk posture + Recent queue ──
    with col_side:
        # Risk posture card
        st.markdown("""<div class="soar-card">
          <div class="soar-card-title">📊 Risk Posture</div>
          <div class="soar-card-subtitle">Distribution of risk levels across all persisted incidents.</div>
        """, unsafe_allow_html=True)

        st.markdown(
            pill(f"🔴 Critical {metrics['critical_incidents']}", "critical")
            + pill(f"🟠 High {metrics['high_incidents']}", "high")
            + pill(f"🟡 Medium {metrics['medium_incidents']}", "medium")
            + pill(f"🟢 Low {metrics['low_incidents']}", "low"),
            unsafe_allow_html=True,
        )
        avg = float(metrics["average_risk_score"])
        st.markdown(risk_bar(avg, risk_tone(
            "critical" if avg >= 76 else "high" if avg >= 51 else "medium" if avg >= 26 else "low"
        )), unsafe_allow_html=True)
        st.caption(f"Average risk: {avg:.1f}/100 · {metrics.get('ticketed_incidents', 0)} ticketed")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div style='margin-top:12px'></div>", unsafe_allow_html=True)

        # Recent incidents queue
        st.markdown("""<div class="soar-card">
          <div class="soar-card-title">⏱️ Recent Queue</div>
          <div class="soar-card-subtitle">Last 5 processed incidents.</div>
        """, unsafe_allow_html=True)

        if incidents:
            for item in incidents[:5]:
                tone = risk_tone(item["risk_level"])
                st.markdown(f"""
                <div class="soar-queue-item">
                  <div class="soar-queue-dot dot-{tone}"></div>
                  <div class="soar-queue-main">
                    <div class="soar-queue-host">{esc(item['hostname'])}</div>
                    <div class="soar-queue-detection">{esc(item['detection_name'])}</div>
                  </div>
                  <div class="soar-queue-score val-{tone}">{float(item['risk_score']):.0f}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No incidents in queue.")
        st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────
# TAB 2: INCIDENT HISTORY
# ─────────────────────────────────────────────────────────────────────
with tab_history:
    filter_col, table_col = st.columns([0.3, 0.7], gap="medium")

    with filter_col:
        st.markdown("""<div class="soar-card">
          <div class="soar-card-title">🔎 Filters</div>
          <div class="soar-card-subtitle">Narrow down the incident list, then select one for deep dive.</div>
        """, unsafe_allow_html=True)

        f_risk = st.selectbox("Risk Level", ["all", "critical", "high", "medium", "low"],
                              format_func=lambda v: v.upper() if v != "all" else "ALL LEVELS")
        f_ticket = st.selectbox("Ticket State", ["all", "with_ticket", "without_ticket"],
                                format_func={"all": "ALL", "with_ticket": "WITH TICKET", "without_ticket": "WITHOUT TICKET"}.get)
        f_search = st.text_input("🔍 Search", placeholder="Alert ID, hostname, detection…")

        # Apply filters
        filtered = incidents
        if f_risk != "all":
            filtered = [i for i in filtered if i["risk_level"] == f_risk]
        if f_ticket == "with_ticket":
            filtered = [i for i in filtered if i.get("ticket_id")]
        elif f_ticket == "without_ticket":
            filtered = [i for i in filtered if not i.get("ticket_id")]
        if f_search:
            q = f_search.casefold()
            filtered = [i for i in filtered if
                        q in i["alert_id"].casefold() or
                        q in i["hostname"].casefold() or
                        q in i["detection_name"].casefold() or
                        q in (i.get("ticket_id") or "").casefold()]

        f_crit = sum(1 for i in filtered if i["risk_level"] == "critical")
        f_high = sum(1 for i in filtered if i["risk_level"] == "high")
        st.markdown(
            pill(f"{len(filtered)} visible", "neutral")
            + pill(f"{f_crit} critical", "critical")
            + pill(f"{f_high} high", "high"),
            unsafe_allow_html=True,
        )

        # Incident selector
        ids = [i["alert_id"] for i in filtered]
        if ids:
            sel = st.selectbox(
                "Select Incident",
                ids,
                index=ids.index(st.session_state.sel_alert) if st.session_state.sel_alert in ids else 0,
                format_func=lambda aid: next(
                    (f"{risk_icon(i['risk_level'])} {short(i['alert_id'],14)} | {i['hostname']}" for i in filtered if i["alert_id"] == aid),
                    aid
                ),
            )
            if sel != st.session_state.sel_alert:
                st.session_state.sel_alert = sel
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    with table_col:
        st.markdown("""<div class="soar-card">
          <div class="soar-card-title">📋 Incident Table</div>
          <div class="soar-card-subtitle">All persisted workflow executions, loaded from the database.</div>
        """, unsafe_allow_html=True)

        if filtered:
            rows = [
                {
                    "Alert ID": short(i["alert_id"], 18),
                    "Hostname": i["hostname"],
                    "Detection": i["detection_name"],
                    "Risk": i["risk_level"].upper(),
                    "Score": round(float(i["risk_score"]), 1),
                    "Ticket": i.get("ticket_id") or "—",
                    "Completed": fmt_ts(i.get("completed_at")),
                }
                for i in filtered
            ]
            st.dataframe(rows, use_container_width=True, hide_index=True, height=460)
            st.caption(f"Showing {len(filtered)} incident(s) from {db_src}")
        else:
            st.info("No incidents match the current filters.")
        st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────
# TAB 3: DEEP DIVE
# ─────────────────────────────────────────────────────────────────────
with tab_detail:
    record = get_detail(st.session_state.sel_alert)

    if record is None:
        st.info("Select or process an incident to inspect its full details.")
    else:
        alert = record["alert"]
        enriched = record["enriched_alert"]
        response = record["response"]
        actions = remediation_actions(record)
        techniques = enriched.get("mitre_mappings", [])

        # ── Row 1: Summary + Response Actions ──
        summary_col, action_col = st.columns([1.3, 0.7], gap="medium")

        with summary_col:
            st.markdown("""<div class="soar-card">
              <div class="soar-card-title">🔬 Incident Summary</div>
              <div class="soar-card-subtitle">Full enrichment and telemetry data for this alert.</div>
            """, unsafe_allow_html=True)

            rl = enriched["risk_level"]
            st.markdown(
                pill(f"{risk_icon(rl)} {rl.upper()} — {enriched['risk_score']:.1f}/100", risk_tone(rl))
                + pill(f"🎫 {response.get('ticket_id') or '—'}", "neutral")
                + pill(f"Asset: {enriched.get('asset_criticality', '—').upper()}", "blue"),
                unsafe_allow_html=True,
            )
            st.markdown(risk_bar(enriched["risk_score"], rl), unsafe_allow_html=True)

            st.markdown(kv_grid([
                ("Alert ID", alert["alert_id"]),
                ("Hostname", alert["hostname"]),
                ("Username", alert["username"]),
                ("Process", alert["process_name"]),
                ("Parent Process", alert["parent_process"]),
                ("File Path", alert["file_path"]),
                ("Detection", alert["detection_name"]),
                ("Severity", alert["severity"].upper()),
                ("Destination IP", alert["destination_ip"]),
                ("Received At", fmt_ts(alert.get("received_at"))),
            ]), unsafe_allow_html=True)

            # Enrichment indicators
            st.markdown("<div style='margin-top:16px'></div>", unsafe_allow_html=True)
            st.markdown("""<div class="soar-card-title">🔍 Enrichment Indicators</div>""", unsafe_allow_html=True)

            he = enriched.get("hash_enrichment") or {}
            ie = enriched.get("ip_enrichment") or {}
            st.markdown(kv_grid([
                ("Hash Reputation", (he.get("reputation") or "—").upper()),
                ("Threat Name", he.get("threat_name") or "—"),
                ("Vendors", f"{he.get('malicious_vendors', 0)}/{he.get('total_vendors', 0)}" if he.get("total_vendors") else "—"),
                ("IP Reputation", (ie.get("reputation") or "—").upper()),
                ("C2 Flag", "⚠️ YES" if ie.get("is_c2") else "No"),
                ("IP Confidence", f"{ie.get('confidence_score', 0)}/100" if ie.get("confidence_score") else "—"),
                ("Country", ie.get("country") or "—"),
                ("MITRE Techniques", str(len(techniques))),
            ]), unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        with action_col:
            st.markdown("""<div class="soar-card">
              <div class="soar-card-title">⚡ Response Actions</div>
              <div class="soar-card-subtitle">Policy-driven remediation and mandatory bookkeeping steps.</div>
            """, unsafe_allow_html=True)

            if actions:
                action_icons = {
                    "isolate_host": "🔴", "kill_process": "🛑",
                    "block_ip": "🚫", "escalate": "⬆️",
                }
                st.markdown(
                    "".join(pill(f"{action_icons.get(a, '⚡')} {a.replace('_',' ').upper()}", "critical") for a in actions),
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(pill("✅ OBSERVE ONLY — No automated remediation", "low"), unsafe_allow_html=True)

            st.markdown("<div style='margin-top:12px'></div>", unsafe_allow_html=True)

            for ar in record.get("action_results", []):
                status_tone = {"success": "low", "queued": "medium", "failed": "critical"}.get(ar["status"], "neutral")
                status_icon = {"success": "✅", "queued": "⏳", "failed": "❌"}.get(ar["status"], "•")
                st.markdown(f"""
                <div class="soar-action-item">
                  <div class="soar-action-header">
                    <span>{status_icon}</span>
                    <span class="val-{status_tone}">{esc(ar['action'])} · {esc(ar['status'])}</span>
                  </div>
                  <div class="soar-action-detail">{esc(ar['details'][:120])}</div>
                  <div class="soar-action-time">{fmt_ts(ar.get('executed_at'))}</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='soar-section-gap'></div>", unsafe_allow_html=True)

        # ── Row 2: Policy Reasoning + MITRE ATT&CK ──
        policy_col, mitre_col = st.columns([1, 1], gap="medium")

        with policy_col:
            st.markdown("""<div class="soar-card">
              <div class="soar-card-title">⚖️ Policy Reasoning</div>
              <div class="soar-card-subtitle">Per-rule trace captured during policy evaluation.</div>
            """, unsafe_allow_html=True)

            reasoning = record.get("policy_reasoning", [])
            if reasoning:
                for r in reasoning:
                    if "TRIGGERED" in r:
                        tone, icon = "critical", "🔴"
                    elif "PASS" in r:
                        tone, icon = "low", "🟢"
                    elif "SKIP" in r or "DISABLED" in r:
                        tone, icon = "medium", "🟡"
                    else:
                        tone, icon = "neutral", "⚪"
                    header = r.split(":", 1)[0] if ":" in r else r[:30]
                    st.markdown(f"""
                    <div class="soar-rule">
                      <div class="soar-rule-header val-{tone}">{icon} {esc(header)}</div>
                      <div class="soar-rule-body">{esc(r)}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No policy reasoning captured for this incident.")
            st.markdown("</div>", unsafe_allow_html=True)

        with mitre_col:
            st.markdown("""<div class="soar-card">
              <div class="soar-card-title">🎯 MITRE ATT&CK Mapping</div>
              <div class="soar-card-subtitle">Technique evidence generated during enrichment.</div>
            """, unsafe_allow_html=True)

            if techniques:
                tech_rows = [
                    {
                        "ID": t["technique_id"],
                        "Name": t["technique_name"],
                        "Tactic": t["tactic"],
                        "Confidence": f"{t['confidence']:.0%}",
                        "Pattern": t["matched_pattern"],
                    }
                    for t in techniques
                ]
                st.dataframe(tech_rows, use_container_width=True, hide_index=True)
            else:
                st.info("No MITRE ATT&CK techniques were mapped for this incident.")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='soar-section-gap'></div>", unsafe_allow_html=True)

        # ── Row 3: Analyst Narrative ──
        # Build narrative
        indicator_lines = []
        he = enriched.get("hash_enrichment") or {}
        ie = enriched.get("ip_enrichment") or {}
        if he.get("reputation") == "malicious":
            indicator_lines.append("The file hash is confirmed **malicious** by threat intelligence.")
        if ie.get("is_c2"):
            indicator_lines.append(f"Destination IP `{alert['destination_ip']}` is flagged as **C2 server**.")
        if enriched.get("asset_criticality") == "critical":
            indicator_lines.append(f"Host `{alert['hostname']}` is a **critical asset** (high business impact).")
        if not indicator_lines:
            indicator_lines.append("No single high-confidence indicator dominated the risk score.")

        action_text = ", ".join(f"`{a}`" for a in actions) if actions else "`observe_only`"
        tech_text = ", ".join(f"`{t['technique_id']}` {t['technique_name']}" for t in techniques) or "No ATT&CK techniques mapped."

        narrative_md = "\n".join([
            "### 📝 Analyst Narrative",
            "",
            f"This incident was processed from the database record for alert `{alert['alert_id']}`.",
            f"The pipeline classified the event as **{enriched['risk_level'].upper()}** with a risk score of **{enriched['risk_score']:.1f}/100** on host `{alert['hostname']}`.",
            "",
            "**Key indicators:**",
            *(f"- {line}" for line in indicator_lines),
            "",
            f"**Automated response:** {action_text}",
            f"**Ticket reference:** `{response.get('ticket_id') or 'N/A'}`",
            f"**ATT&CK coverage:** {tech_text}",
            "",
            "**Recommended follow-up:**",
            "- Validate if this alert is part of a known campaign or false positive cluster.",
            "- Review lateral movement and credential abuse telemetry around the alert timestamp.",
            "- Preserve the ticket, reasoning trace, and action results in the incident database.",
        ])

        st.markdown("<div class='soar-narrative'>", unsafe_allow_html=True)
        st.markdown(narrative_md)
        st.markdown("</div>", unsafe_allow_html=True)
