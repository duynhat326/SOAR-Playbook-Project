"""
dashboard/app.py
================
Database-first Streamlit dashboard for the SOAR malware playbook.

Run:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st


st.set_page_config(
    page_title="SOAR Command Center",
    page_icon="SOC",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

:root {
  --bg: #f4f1e8;
  --panel: rgba(255, 255, 255, 0.78);
  --panel-strong: rgba(255, 255, 255, 0.92);
  --ink: #17212b;
  --muted: #5a6674;
  --line: rgba(23, 33, 43, 0.12);
  --accent: #c5532f;
  --accent-soft: rgba(197, 83, 47, 0.14);
  --navy: #14324a;
  --olive: #52644f;
  --danger: #b33d2f;
  --warn: #bb7a19;
  --ok: #2f7d57;
  --shadow: 0 18px 42px rgba(20, 50, 74, 0.10);
}

.stApp {
  background:
    radial-gradient(circle at top left, rgba(197, 83, 47, 0.14), transparent 28%),
    radial-gradient(circle at top right, rgba(20, 50, 74, 0.14), transparent 24%),
    linear-gradient(180deg, #efe8d7 0%, #f7f4ec 46%, #f4f1e8 100%);
  color: var(--ink);
}

html, body, [class*="css"] {
  font-family: "IBM Plex Sans", sans-serif;
}

code, pre {
  font-family: "IBM Plex Mono", monospace !important;
}

#MainMenu, footer, header {
  visibility: hidden;
}

[data-testid="stSidebar"] {
  background: rgba(20, 50, 74, 0.96);
  border-right: 1px solid rgba(255,255,255,0.08);
}

[data-testid="stSidebar"] * {
  color: #f4f1e8;
}

.hero {
  background: linear-gradient(135deg, rgba(20, 50, 74, 0.96), rgba(55, 87, 109, 0.90));
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 28px;
  padding: 28px 30px;
  color: #f4f1e8;
  box-shadow: var(--shadow);
}

.hero-kicker {
  display: inline-block;
  border: 1px solid rgba(255,255,255,0.16);
  background: rgba(255,255,255,0.08);
  border-radius: 999px;
  padding: 6px 12px;
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.hero h1 {
  margin: 14px 0 8px;
  font-size: 2.2rem;
  line-height: 1.08;
}

.hero p {
  margin: 0;
  max-width: 920px;
  color: rgba(244, 241, 232, 0.82);
  font-size: 1rem;
}

.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 24px;
  padding: 20px 22px;
  box-shadow: var(--shadow);
  backdrop-filter: blur(10px);
}

.panel-strong {
  background: var(--panel-strong);
}

.section-title {
  margin: 0 0 8px;
  color: var(--navy);
  font-size: 1.05rem;
  font-weight: 700;
}

.section-copy {
  margin: 0 0 14px;
  color: var(--muted);
  font-size: 0.95rem;
}

.metric-card {
  background: var(--panel-strong);
  border: 1px solid var(--line);
  border-radius: 22px;
  padding: 18px 20px;
  min-height: 134px;
  box-shadow: var(--shadow);
}

.metric-label {
  color: var(--muted);
  font-size: 0.80rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.metric-value {
  margin-top: 10px;
  color: var(--ink);
  font-size: 2rem;
  font-weight: 700;
  line-height: 1;
}

.metric-foot {
  margin-top: 10px;
  color: var(--muted);
  font-size: 0.92rem;
}

.tone-critical { color: var(--danger); }
.tone-high { color: var(--accent); }
.tone-medium { color: var(--warn); }
.tone-low { color: var(--ok); }

.pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border-radius: 999px;
  padding: 7px 12px;
  font-size: 0.82rem;
  font-weight: 600;
  border: 1px solid transparent;
  margin: 0 8px 8px 0;
}

.pill-critical { background: rgba(179, 61, 47, 0.12); color: var(--danger); border-color: rgba(179, 61, 47, 0.18); }
.pill-high { background: rgba(197, 83, 47, 0.12); color: var(--accent); border-color: rgba(197, 83, 47, 0.18); }
.pill-medium { background: rgba(187, 122, 25, 0.12); color: var(--warn); border-color: rgba(187, 122, 25, 0.18); }
.pill-low { background: rgba(47, 125, 87, 0.12); color: var(--ok); border-color: rgba(47, 125, 87, 0.18); }
.pill-neutral { background: rgba(20, 50, 74, 0.08); color: var(--navy); border-color: rgba(20, 50, 74, 0.12); }

.kv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 12px;
}

.kv-item {
  background: rgba(20, 50, 74, 0.04);
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 14px 16px;
}

.kv-label {
  color: var(--muted);
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.kv-value {
  margin-top: 6px;
  color: var(--ink);
  font-weight: 600;
  word-break: break-word;
}

.narrative {
  background: rgba(255,255,255,0.72);
  border: 1px solid var(--line);
  border-radius: 22px;
  padding: 20px 22px;
}

.narrative h3 {
  margin: 0 0 10px;
  color: var(--navy);
}

.narrative p,
.narrative li {
  color: var(--ink);
  line-height: 1.7;
}

.rule-list {
  display: grid;
  gap: 10px;
}

.rule-item {
  background: rgba(255,255,255,0.76);
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 14px 16px;
}

.rule-item strong {
  display: block;
  margin-bottom: 6px;
}

[data-testid="stDataFrame"] {
  border: 1px solid var(--line);
  border-radius: 18px;
  overflow: hidden;
}

.stTabs [data-baseweb="tab-list"] {
  gap: 10px;
}

.stTabs [data-baseweb="tab"] {
  height: 46px;
  border-radius: 16px 16px 0 0;
  padding: 0 18px;
  background: rgba(255,255,255,0.38);
  border: 1px solid transparent;
}

.stTabs [aria-selected="true"] {
  background: rgba(255,255,255,0.92) !important;
  border-color: var(--line) !important;
}

.block-container {
  padding-top: 2rem;
  padding-bottom: 2rem;
}
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_resource
def load_components() -> dict[str, Any]:
    from alert_generator.generator import generate_alert
    from services.workflow_service import SoarWorkflowService

    workflow = SoarWorkflowService(verbose=False)
    return {
        "generate_alert": generate_alert,
        "workflow": workflow,
    }


components = load_components()
workflow = components["workflow"]


def format_ts(raw: str | None) -> str:
    if not raw:
        return "-"
    normalized = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw


def short_text(value: str | None, max_len: int = 22) -> str:
    if not value:
        return "-"
    return value if len(value) <= max_len else f"{value[:max_len - 3]}..."


def database_label(raw_target: str | Path) -> str:
    value = str(raw_target)
    if "supabase.com" in value:
        return "Supabase Postgres"
    if value.startswith("postgresql://") or value.startswith("postgres://"):
        return "Postgres"
    return "Local database"


def risk_tone(level: str | None) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get((level or "").lower(), "neutral")


def pill(label: str, tone: str) -> str:
    return f"<span class='pill pill-{tone}'>{label}</span>"


def render_metric_card(title: str, value: str, foot: str, tone: str = "neutral") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
          <div class="metric-label">{title}</div>
          <div class="metric-value tone-{tone}">{value}</div>
          <div class="metric-foot">{foot}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def load_incident_metrics() -> dict[str, Any]:
    return workflow.get_incident_metrics()


def load_incident_summaries(limit: int = 100) -> list[dict[str, Any]]:
    return workflow.list_incidents(limit=limit)


def load_incident_detail(alert_id: str | None) -> dict[str, Any] | None:
    if not alert_id:
        return None
    return workflow.get_incident_by_alert_id(alert_id)


def ensure_selected_alert_id(incidents: list[dict[str, Any]]) -> None:
    if not incidents:
        st.session_state.selected_alert_id = None
        return

    selected_alert_id = st.session_state.get("selected_alert_id")
    valid_ids = {item["alert_id"] for item in incidents}
    if selected_alert_id not in valid_ids:
        st.session_state.selected_alert_id = incidents[0]["alert_id"]


def build_alert_payload(source_mode: str, scenario: str, seed: int, sample_path: Path | None, json_input: str) -> dict[str, Any]:
    if source_mode == "scenario":
        alert = components["generate_alert"](scenario=scenario, seed=seed)
        payload = alert.model_dump(mode="json")
        payload["received_at"] = alert.received_at.isoformat()
        return payload

    if source_mode == "sample":
        if sample_path is None:
            raise ValueError("No sample alert was selected.")
        with open(sample_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    return json.loads(json_input)


def run_pipeline(alert_payload: dict[str, Any]) -> str:
    result = workflow.process_alert_payload(
        alert_payload,
        generate_report=False,
        export_pdf=False,
        include_markdown_content=False,
    )
    st.session_state.selected_alert_id = result.alert.alert_id
    st.session_state.last_run = {
        "alert_id": result.alert.alert_id,
        "risk_level": result.enriched_alert.risk_level,
        "ticket_id": result.response.ticket_id,
        "completed_at": format_ts(result.response.completed_at.isoformat()),
    }
    return result.alert.alert_id


def incident_table_rows(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in incidents:
        rows.append(
            {
                "Alert ID": item["alert_id"],
                "Host": item["hostname"],
                "Detection": item["detection_name"],
                "Risk": item["risk_level"].upper(),
                "Score": round(float(item["risk_score"]), 1),
                "Ticket": item["ticket_id"] or "-",
                "Completed": format_ts(item["completed_at"]),
            }
        )
    return rows


def filter_incidents(
    incidents: list[dict[str, Any]],
    risk_filter: str,
    status_filter: str,
    ticket_filter: str,
    search_term: str,
) -> list[dict[str, Any]]:
    filtered = incidents
    if risk_filter != "all":
        filtered = [item for item in filtered if item["risk_level"] == risk_filter]
    if status_filter != "all":
        filtered = [item for item in filtered if item["status"] == status_filter]
    if ticket_filter == "with_ticket":
        filtered = [item for item in filtered if item["ticket_id"]]
    elif ticket_filter == "without_ticket":
        filtered = [item for item in filtered if not item["ticket_id"]]

    if search_term:
        query = search_term.casefold()
        filtered = [
            item
            for item in filtered
            if query in item["alert_id"].casefold()
            or query in item["hostname"].casefold()
            or query in item["detection_name"].casefold()
            or query in (item["ticket_id"] or "").casefold()
        ]
    return filtered


def build_action_labels(record: dict[str, Any]) -> list[str]:
    actions = record["response"].get("triggered_actions", [])
    return [action for action in actions if action not in {"create_ticket", "notify_soc"}]


def build_narrative(record: dict[str, Any]) -> str:
    alert = record["alert"]
    enriched = record["enriched_alert"]
    response = record["response"]
    actions = build_action_labels(record)
    techniques = enriched.get("mitre_mappings", [])

    indicator_lines: list[str] = []
    hash_enrichment = enriched.get("hash_enrichment")
    ip_enrichment = enriched.get("ip_enrichment")
    if hash_enrichment and hash_enrichment.get("reputation") == "malicious":
        indicator_lines.append("The file hash is marked malicious in threat intelligence.")
    if ip_enrichment and ip_enrichment.get("is_c2"):
        indicator_lines.append(
            f"Destination IP `{alert['destination_ip']}` is tagged as command-and-control."
        )
    if enriched.get("asset_criticality") == "critical":
        indicator_lines.append(
            f"Host `{alert['hostname']}` is classified as a critical asset."
        )
    if not indicator_lines:
        indicator_lines.append("No single high-confidence indicator dominated the score.")

    action_line = ", ".join(f"`{action}`" for action in actions) if actions else "`observe_only`"
    technique_line = ", ".join(
        f"`{item['technique_id']}` {item['technique_name']}" for item in techniques
    ) or "No ATT&CK techniques were mapped."

    return "\n".join(
        [
            "### Analyst Narrative",
            "",
            f"This incident was processed directly from the database-backed workflow record for alert `{alert['alert_id']}`.",
            f"The pipeline classified the event as **{enriched['risk_level'].upper()}** with a score of **{enriched['risk_score']:.1f}/100** on host `{alert['hostname']}`.",
            "",
            "Primary indicators:",
            *(f"- {line}" for line in indicator_lines),
            "",
            f"Automated response selected: {action_line}.",
            f"Ticket reference: `{response.get('ticket_id') or 'N/A'}`.",
            f"Mapped ATT&CK coverage: {technique_line}",
            "",
            "Recommended analyst follow-up:",
            "- Validate whether the alert belongs to a known campaign or false positive cluster.",
            "- Review lateral movement, credential abuse, and adjacent host telemetry around the alert timestamp.",
            "- Preserve the ticket, reasoning trace, and action results already captured in the incident database.",
        ]
    )


def render_key_value_grid(items: list[tuple[str, Any]]) -> None:
    html_items = []
    for label, value in items:
        html_items.append(
            f"""
            <div class="kv-item">
              <div class="kv-label">{label}</div>
              <div class="kv-value">{value or '-'}</div>
            </div>
            """
        )
    st.markdown(f"<div class='kv-grid'>{''.join(html_items)}</div>", unsafe_allow_html=True)


def render_rule_reasoning(reasoning: list[str]) -> None:
    if not reasoning:
        st.info("No policy reasoning captured for this incident.")
        return

    tone_map = {
        "TRIGGERED": "critical",
        "PASS": "low",
        "SKIP": "medium",
        "PARTIAL": "medium",
        "DISABLED": "neutral",
    }
    html_items = []
    for item in reasoning:
        matched_tone = "neutral"
        for marker, tone in tone_map.items():
            if marker in item:
                matched_tone = tone
                break
        html_items.append(
            f"""
            <div class="rule-item">
              <strong class="tone-{matched_tone}">{item.split(':', 1)[0]}</strong>
              <div>{item}</div>
            </div>
            """
        )
    st.markdown(f"<div class='rule-list'>{''.join(html_items)}</div>", unsafe_allow_html=True)


incident_summaries = load_incident_summaries(limit=200)
ensure_selected_alert_id(incident_summaries)
selected_record = load_incident_detail(st.session_state.get("selected_alert_id"))
metrics = load_incident_metrics()
db_source_label = database_label(workflow.db_path)


st.markdown(
    f"""
    <div class="hero">
      <span class="hero-kicker">SOAR Malware Playbook · {db_source_label}</span>
      <h1>Command Center for alert processing, incident review, and analyst handoff.</h1>
      <p>
        This interface is database-first: incidents are written to Supabase/Postgres, then explored from persisted
        records instead of depending on generated Markdown or HTML files in <code>output/</code>.
      </p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.write("")

sample_dir = Path("data/sample_alerts")
sample_files = sorted(sample_dir.glob("*.json")) if sample_dir.exists() else []
scenario_options = {
    "Mixed triage set": "mixed",
    "Malicious hash": "malicious_hash",
    "C2 communication": "c2_communication",
    "Critical asset": "critical_asset",
    "Dangerous process": "dangerous_process",
    "Benign": "benign",
    "Randomized": "random",
}

with st.sidebar:
    st.markdown("## Intake")
    with st.form("run_pipeline_form", clear_on_submit=False):
        source_mode = st.radio(
            "Alert source",
            options=["scenario", "sample", "json"],
            format_func=lambda value: {
                "scenario": "Generate scenario",
                "sample": "Load bundled sample",
                "json": "Paste custom JSON",
            }[value],
        )
        scenario_name = st.selectbox("Scenario", list(scenario_options.keys()))
        scenario_seed = st.number_input("Seed", min_value=0, max_value=999999, value=2024)
        if sample_files:
            sample_file = st.selectbox(
                "Sample alert",
                options=sample_files,
                index=0,
                format_func=lambda path: path.name,
                disabled=source_mode != "sample",
            )
        else:
            sample_file = None
            st.caption("No bundled sample alerts were found in `data/sample_alerts`.")
        default_json = json.dumps(
            {
                "alert_id": "demo-alert-001",
                "hostname": "SRV-DC01",
                "username": "admin",
                "process_name": "mimikatz.exe",
                "file_path": "C:\\Windows\\Temp\\mimikatz.exe",
                "file_hash": "a1b2c3d4e5f6" * 5 + "a1b2",
                "parent_process": "explorer.exe",
                "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
                "destination_ip": "185.220.101.45",
                "severity": "critical",
                "detection_name": "HackTool.Mimikatz",
            },
            indent=2,
        )
        json_input = st.text_area(
            "Custom JSON",
            value=default_json,
            height=260,
            disabled=source_mode != "json",
        )
        submitted = st.form_submit_button("Process alert", use_container_width=True, type="primary")

        if submitted:
            try:
                payload = build_alert_payload(
                    source_mode=source_mode,
                    scenario=scenario_options[scenario_name],
                    seed=int(scenario_seed),
                    sample_path=sample_file if source_mode == "sample" else None,
                    json_input=json_input,
                )
                alert_id = run_pipeline(payload)
                st.success(f"Persisted incident for `{alert_id}`.")
                st.rerun()
            except Exception as exc:
                st.error(str(exc))

    st.divider()
    st.markdown("## Database")
    st.caption(f"Source: `{db_source_label}`")
    st.caption(f"Incident DB: `{workflow.db_path}`")
    if st.button("Refresh dashboard", use_container_width=True):
        st.rerun()

    st.divider()
    st.markdown("## Status")
    st.caption(
        "Default processing now avoids report-file generation. Persisted incident data is read back from the database for review."
    )
    if st.session_state.get("last_run"):
        last_run = st.session_state["last_run"]
        st.markdown(
            f"""
            <div class="panel">
              <div class="section-title">Latest run</div>
              <div class="section-copy">Most recent processed alert in this session.</div>
              {pill(last_run['risk_level'].upper(), risk_tone(last_run['risk_level']))}
              <div><strong>Alert:</strong> {last_run['alert_id']}</div>
              <div><strong>Ticket:</strong> {last_run['ticket_id'] or '-'}</div>
              <div><strong>Completed:</strong> {last_run['completed_at']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


metric_columns = st.columns(4)
with metric_columns[0]:
    render_metric_card(
        "Total incidents",
        str(metrics["total_incidents"]),
        "All persisted workflow executions",
        "neutral",
    )
with metric_columns[1]:
    render_metric_card(
        "Critical / high",
        f"{metrics['critical_incidents']} / {metrics['high_incidents']}",
        "Priority triage load from the incident database",
        "critical" if metrics["critical_incidents"] else "high",
    )
with metric_columns[2]:
    render_metric_card(
        "Average risk",
        f"{float(metrics['average_risk_score']):.1f}",
        "Mean risk score across persisted incidents",
        "medium",
    )
with metric_columns[3]:
    render_metric_card(
        "Latest completion",
        format_ts(metrics["latest_completed_at"]).split(" ")[0] if metrics["latest_completed_at"] else "-",
        "Most recent completed incident date",
        "low",
    )


tab_command, tab_history, tab_detail = st.tabs(
    ["Command center", "History & filters", "Deep dive"]
)

with tab_command:
    left_col, right_col = st.columns([1.3, 1])

    with left_col:
        st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>Current focus</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-copy'>Use the intake controls in the sidebar to process a new alert, then review the latest persisted incident here.</div>",
            unsafe_allow_html=True,
        )
        if selected_record is None:
            st.info("No persisted incidents yet. Process an alert to populate the database.")
        else:
            alert = selected_record["alert"]
            enriched = selected_record["enriched_alert"]
            response = selected_record["response"]
            st.markdown(
                pill(enriched["risk_level"].upper(), risk_tone(enriched["risk_level"]))
                + pill(f"Ticket {response.get('ticket_id') or '-'}", "neutral"),
                unsafe_allow_html=True,
            )
            render_key_value_grid(
                [
                    ("Alert ID", alert["alert_id"]),
                    ("Hostname", alert["hostname"]),
                    ("Detection", alert["detection_name"]),
                    ("Severity", alert["severity"].upper()),
                    ("Process", alert["process_name"]),
                    ("Destination IP", alert["destination_ip"]),
                    ("Completed", format_ts(response["completed_at"])),
                    ("Stored status", selected_record["status"]),
                ]
            )
            st.write("")
            st.markdown("**Command line**")
            st.code(alert["command_line"], language="powershell")
        st.markdown("</div>", unsafe_allow_html=True)

    with right_col:
        st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>Risk posture</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-copy'>Distribution of risk levels from the incident database.</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "".join(
                [
                    pill(f"Critical {metrics['critical_incidents']}", "critical"),
                    pill(f"High {metrics['high_incidents']}", "high"),
                    pill(f"Medium {metrics['medium_incidents']}", "medium"),
                    pill(f"Low {metrics['low_incidents']}", "low"),
                    pill(f"Ticketed {metrics['ticketed_incidents']}", "neutral"),
                ]
            ),
            unsafe_allow_html=True,
        )
        st.progress(
            min(float(metrics["average_risk_score"]) / 100.0, 1.0),
            text=f"Average persisted risk score: {float(metrics['average_risk_score']):.1f}/100",
        )

        st.write("")
        st.markdown("**Recent incident queue**")
        if incident_summaries:
            for item in incident_summaries[:5]:
                st.markdown(
                    f"""
                    <div class="rule-item">
                      <strong>{short_text(item['alert_id'], 18)} · {item['hostname']}</strong>
                      <div>{item['detection_name']}</div>
                      <div style="margin-top:8px;">
                        {pill(item['risk_level'].upper(), risk_tone(item['risk_level']))}
                        {pill(short_text(item['ticket_id'] or '-', 20), 'neutral')}
                      </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No persisted incidents available.")
        st.markdown("</div>", unsafe_allow_html=True)


with tab_history:
    filter_col, table_col = st.columns([0.32, 0.68])

    with filter_col:
        st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>History filters</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-copy'>Slice the Supabase-backed incident history, then pick one record for deeper analysis.</div>",
            unsafe_allow_html=True,
        )
        risk_filter = st.selectbox(
            "Risk level",
            options=["all", "critical", "high", "medium", "low"],
            format_func=lambda value: value.upper() if value != "all" else "ALL",
        )
        status_filter = st.selectbox(
            "Workflow status",
            options=["all", "completed"],
            format_func=lambda value: value.upper() if value != "all" else "ALL",
        )
        ticket_filter = st.selectbox(
            "Ticket state",
            options=["all", "with_ticket", "without_ticket"],
            format_func=lambda value: {
                "all": "ALL",
                "with_ticket": "WITH TICKET",
                "without_ticket": "WITHOUT TICKET",
            }[value],
        )
        search_term = st.text_input("Search by alert, host, detection, or ticket")
        filtered_incidents = filter_incidents(
            incident_summaries,
            risk_filter,
            status_filter,
            ticket_filter,
            search_term,
        )

        filtered_critical = sum(1 for item in filtered_incidents if item["risk_level"] == "critical")
        filtered_high = sum(1 for item in filtered_incidents if item["risk_level"] == "high")
        st.markdown(
            "".join(
                [
                    pill(f"{len(filtered_incidents)} visible", "neutral"),
                    pill(f"{filtered_critical} critical", "critical"),
                    pill(f"{filtered_high} high", "high"),
                ]
            ),
            unsafe_allow_html=True,
        )

        incident_ids = [item["alert_id"] for item in filtered_incidents]
        if incident_ids:
            selected_from_filter = st.selectbox(
                "Selected incident",
                options=incident_ids,
                index=incident_ids.index(st.session_state["selected_alert_id"])
                if st.session_state.get("selected_alert_id") in incident_ids
                else 0,
                format_func=lambda alert_id: next(
                    (
                        f"{short_text(item['alert_id'], 16)} | {item['hostname']} | {item['risk_level'].upper()}"
                        for item in filtered_incidents
                        if item["alert_id"] == alert_id
                    ),
                    alert_id,
                ),
            )
            if selected_from_filter != st.session_state.get("selected_alert_id"):
                st.session_state.selected_alert_id = selected_from_filter
                st.rerun()
        else:
            st.info("No incidents match the current filters.")
        st.markdown("</div>", unsafe_allow_html=True)

    with table_col:
        st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>Persisted incident history</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-copy'>Every row below is loaded from Supabase, not from session-only dashboard state or report files.</div>",
            unsafe_allow_html=True,
        )
        if filtered_incidents:
            st.dataframe(
                incident_table_rows(filtered_incidents),
                use_container_width=True,
                hide_index=True,
            )
            st.caption(f"Showing {len(filtered_incidents)} incident(s) from `{db_source_label}`.")
        else:
            st.info("No incidents match the current filters.")
        st.markdown("</div>", unsafe_allow_html=True)


with tab_detail:
    selected_record = load_incident_detail(st.session_state.get("selected_alert_id"))

    if selected_record is None:
        st.info("Select or process an incident to inspect its details.")
    else:
        alert = selected_record["alert"]
        enriched = selected_record["enriched_alert"]
        response = selected_record["response"]
        actions = build_action_labels(selected_record)
        technique_rows = [
            {
                "Technique ID": item["technique_id"],
                "Technique Name": item["technique_name"],
                "Tactic": item["tactic"],
                "Confidence": f"{item['confidence']:.0%}",
                "Matched Pattern": item["matched_pattern"],
            }
            for item in enriched.get("mitre_mappings", [])
        ]

        summary_col, action_col = st.columns([1.2, 0.8])

        with summary_col:
            st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
            st.markdown("<div class='section-title'>Incident summary</div>", unsafe_allow_html=True)
            st.markdown(
                f"<div class='section-copy'>Persisted detail for alert <code>{alert['alert_id']}</code>.</div>",
                unsafe_allow_html=True,
            )
            render_key_value_grid(
                [
                    ("Risk score", f"{enriched['risk_score']:.1f}/100"),
                    ("Risk level", enriched["risk_level"].upper()),
                    ("Asset criticality", enriched["asset_criticality"].upper()),
                    ("Ticket", response.get("ticket_id") or "-"),
                    ("Username", alert["username"]),
                    ("Parent process", alert["parent_process"]),
                    ("File path", alert["file_path"]),
                    ("Received at", format_ts(alert.get("received_at"))),
                ]
            )
            st.write("")
            st.markdown("**Indicators and telemetry**")
            render_key_value_grid(
                [
                    ("Hash reputation", (enriched.get("hash_enrichment") or {}).get("reputation", "-").upper()),
                    ("Threat name", (enriched.get("hash_enrichment") or {}).get("threat_name") or "-"),
                    ("IP reputation", (enriched.get("ip_enrichment") or {}).get("reputation", "-").upper()),
                    ("C2 flag", "YES" if (enriched.get("ip_enrichment") or {}).get("is_c2") else "NO"),
                    ("Confidence", (enriched.get("ip_enrichment") or {}).get("confidence_score") or "-"),
                    ("MITRE techniques", len(enriched.get("mitre_mappings", []))),
                ]
            )
            st.markdown("</div>", unsafe_allow_html=True)

        with action_col:
            st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
            st.markdown("<div class='section-title'>Response actions</div>", unsafe_allow_html=True)
            st.markdown(
                "<div class='section-copy'>Action results captured from policy execution and mandatory ticket/notification steps.</div>",
                unsafe_allow_html=True,
            )
            if actions:
                st.markdown(
                    "".join(pill(action.replace("_", " ").upper(), "critical") for action in actions),
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(pill("OBSERVE ONLY", "low"), unsafe_allow_html=True)

            st.write("")
            for item in selected_record["action_results"]:
                status_tone = {
                    "success": "low",
                    "queued": "medium",
                    "failed": "critical",
                    "skipped": "neutral",
                }.get(item["status"], "neutral")
                st.markdown(
                    f"""
                    <div class="rule-item">
                      <strong class="tone-{status_tone}">{item['action']} · {item['status']}</strong>
                      <div>{item['details']}</div>
                      <div style="margin-top:6px; color: var(--muted);">{format_ts(item['executed_at'])}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            st.markdown("</div>", unsafe_allow_html=True)

        lower_left, lower_right = st.columns([1, 1])

        with lower_left:
            st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
            st.markdown("<div class='section-title'>Policy reasoning</div>", unsafe_allow_html=True)
            st.markdown(
                "<div class='section-copy'>Per-rule trace captured during policy evaluation.</div>",
                unsafe_allow_html=True,
            )
            render_rule_reasoning(selected_record["policy_reasoning"])
            st.markdown("</div>", unsafe_allow_html=True)

        with lower_right:
            st.markdown("<div class='panel panel-strong'>", unsafe_allow_html=True)
            st.markdown("<div class='section-title'>ATT&CK mapping</div>", unsafe_allow_html=True)
            st.markdown(
                "<div class='section-copy'>Technique evidence generated during enrichment.</div>",
                unsafe_allow_html=True,
            )
            if technique_rows:
                st.dataframe(technique_rows, use_container_width=True, hide_index=True)
            else:
                st.info("No ATT&CK techniques were mapped for this incident.")
            st.markdown("</div>", unsafe_allow_html=True)

        st.write("")
        st.markdown("<div class='narrative'>", unsafe_allow_html=True)
        st.markdown(build_narrative(selected_record))
        st.markdown("</div>", unsafe_allow_html=True)
