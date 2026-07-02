from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from loguru import logger

from schemas.alert import IncidentResponse, ResponseAction

_DEFAULT_OUTPUT_DIR = Path("output") / "reports"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_utc(dt: Optional[datetime], pattern: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(pattern)


def _safe_text(value: object) -> str:
    return html.escape(str(value), quote=True)


def _safe_inline(value: object) -> str:
    return _safe_text(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _safe_code(value: object) -> str:
    return _safe_text(value).replace("\r", "")


class ReportGenerator:
    """Generate Markdown, HTML, and optional PDF incident reports."""

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self._output_dir = output_dir or _DEFAULT_OUTPUT_DIR
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        response: IncidentResponse,
        export_pdf: bool = True,
    ) -> tuple[Path, Path, Optional[Path]]:
        alert = response.enriched_alert.original_alert
        safe_id = "".join(ch for ch in alert.alert_id if ch.isalnum())[:16] or "incident"
        timestamp = _utc_now().strftime("%Y%m%d_%H%M%S")
        base_name = f"incident_{safe_id}_{timestamp}"

        logger.info(f"[Report] Generating report for alert {alert.alert_id[:8]}...")

        markdown_content = self._build_markdown(response)
        markdown_path = self._output_dir / f"{base_name}.md"
        markdown_path.write_text(markdown_content, encoding="utf-8")
        logger.success(f"[Report] Markdown saved: {markdown_path}")

        html_content = self._build_html(markdown_content, response)
        html_path = self._output_dir / f"{base_name}.html"
        html_path.write_text(html_content, encoding="utf-8")
        logger.success(f"[Report] HTML saved: {html_path}")

        pdf_path: Optional[Path] = None
        if export_pdf:
            pdf_path = self._export_pdf(html_content, self._output_dir / f"{base_name}.pdf")

        return markdown_path, html_path, pdf_path

    def _build_markdown(self, response: IncidentResponse) -> str:
        enriched = response.enriched_alert
        alert = enriched.original_alert
        risk_level = enriched.risk_level.upper()
        ticket_id = _safe_inline(response.ticket_id or "N/A")
        generated_at = _format_utc(_utc_now())

        severity_badge = {
            "low": "LOW",
            "medium": "MEDIUM",
            "high": "HIGH",
            "critical": "CRITICAL",
        }.get(enriched.risk_level, risk_level)

        sections = [
            "\n".join(
                [
                    "# Incident Report - Malware Alert on Endpoint",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| **Report Generated** | {generated_at} |",
                    f"| **Alert ID** | `{_safe_inline(alert.alert_id)}` |",
                    f"| **Ticket ID** | `{ticket_id}` |",
                    f"| **Risk Level** | **{severity_badge}** |",
                    f"| **Risk Score** | **{enriched.risk_score:.1f} / 100** |",
                    f"| **Detection** | {_safe_inline(alert.detection_name)} |",
                    "| **Analyst** | SOAR Automated Response |",
                    "",
                    "---",
                    "",
                    "## 1. Executive Summary",
                    "",
                    self._generate_executive_summary(response),
                    "",
                    "---",
                    "",
                    "## 2. Alert Details",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| **Alert ID** | `{_safe_inline(alert.alert_id)}` |",
                    f"| **Received At** | {_format_utc(alert.received_at)} |",
                    f"| **Hostname** | `{_safe_inline(alert.hostname)}` |",
                    f"| **Username** | `{_safe_inline(alert.username)}` |",
                    f"| **Process Name** | `{_safe_inline(alert.process_name)}` |",
                    f"| **Parent Process** | `{_safe_inline(alert.parent_process)}` |",
                    f"| **File Path** | `{_safe_inline(alert.file_path)}` |",
                    f"| **Detection Name** | {_safe_inline(alert.detection_name)} |",
                    f"| **EDR Severity** | {_safe_inline(alert.severity.value.upper())} |",
                    "",
                    "**Command Line:**",
                    "```text",
                    _safe_code(alert.command_line),
                    "```",
                    "",
                    "---",
                    "",
                    self._build_timeline_section(response),
                    self._build_ioc_section(response),
                    self._build_enrichment_section(response),
                    self._build_risk_section(response),
                    self._build_actions_section(response),
                    self._build_recommendations_section(response),
                    "---",
                    "",
                    "*Report generated automatically by SOAR Malware Playbook v2.0*",
                    f"*Ticket: `{ticket_id}` | Alert ID: `{_safe_inline(alert.alert_id)}`*",
                    f"*{generated_at}*",
                    "",
                ]
            )
        ]
        return "\n".join(sections)

    def _build_timeline_section(self, response: IncidentResponse) -> str:
        enriched = response.enriched_alert
        alert = enriched.original_alert
        completed_at = response.completed_at
        lines = [
            "## 3. Processing Timeline",
            "",
            "| Step | Description | Time | Status |",
            "|------|-------------|------|--------|",
            f"| **Step 1** | Alert received from EDR | {_format_utc(alert.received_at, '%H:%M:%S UTC')} | Done |",
            f"| **Step 2** | Hash enrichment | {_format_utc(alert.received_at, '%H:%M:%S UTC')} | Done |",
            f"| **Step 3** | IP enrichment | {_format_utc(alert.received_at, '%H:%M:%S UTC')} | Done |",
            f"| **Step 4** | Asset criticality lookup | {_format_utc(alert.received_at, '%H:%M:%S UTC')} | Done |",
            f"| **Step 5** | MITRE ATT&CK mapping | {_format_utc(alert.received_at, '%H:%M:%S UTC')} | Done ({len(enriched.mitre_mappings)} techniques) |",
            f"| **Step 6** | Risk score calculation | {_format_utc(alert.received_at, '%H:%M:%S UTC')} | Done ({enriched.risk_score:.1f}/100) |",
            f"| **Step 7** | Policy evaluation and actions | {_format_utc(completed_at, '%H:%M:%S UTC')} | Done |",
            "",
            "> Total processing time: mock pipeline, typically under one second.",
            "",
            "---",
            "",
        ]
        return "\n".join(lines)

    def _build_ioc_section(self, response: IncidentResponse) -> str:
        enriched = response.enriched_alert
        alert = enriched.original_alert
        hash_rep = enriched.hash_enrichment.reputation.value.upper() if enriched.hash_enrichment else "UNKNOWN"
        hash_threat = (
            enriched.hash_enrichment.threat_name if enriched.hash_enrichment and enriched.hash_enrichment.threat_name else "N/A"
        )
        ip_rep = (
            "C2 SERVER"
            if enriched.ip_enrichment and enriched.ip_enrichment.is_c2
            else enriched.ip_enrichment.reputation.value.upper()
            if enriched.ip_enrichment
            else "UNKNOWN"
        )
        ip_country = enriched.ip_enrichment.country if enriched.ip_enrichment and enriched.ip_enrichment.country else "N/A"
        process_reputation = "DANGEROUS" if self._is_dangerous_name(alert.process_name) else "Normal"
        lines = [
            "## 4. IOC Summary",
            "",
            "| IOC Type | Value | Reputation |",
            "|----------|-------|------------|",
            f"| **File Hash (SHA256)** | `{_safe_inline(alert.file_hash)}` | {_safe_inline(hash_rep)} |",
            f"| **Threat Name** | {_safe_inline(hash_threat)} | - |",
            f"| **Destination IP** | `{_safe_inline(alert.destination_ip)}` | {_safe_inline(ip_rep)} |",
            f"| **IP Country** | {_safe_inline(ip_country)} | - |",
            f"| **Process Name** | `{_safe_inline(alert.process_name)}` | {_safe_inline(process_reputation)} |",
            f"| **File Path** | `{_safe_inline(alert.file_path)}` | - |",
            f"| **Parent Process** | `{_safe_inline(alert.parent_process)}` | - |",
            "",
            "---",
            "",
        ]
        return "\n".join(lines)

    def _build_enrichment_section(self, response: IncidentResponse) -> str:
        enriched = response.enriched_alert
        alert = enriched.original_alert
        lines = ["## 5. Enrichment Results", ""]

        if enriched.hash_enrichment:
            hash_enrichment = enriched.hash_enrichment
            lines.extend(
                [
                    "### 5.1 Hash Analysis",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| Hash | `{_safe_inline(alert.file_hash)}` |",
                    f"| Reputation | **{_safe_inline(hash_enrichment.reputation.value.upper())}** |",
                    f"| Detection Rate | {hash_enrichment.malicious_vendors}/{hash_enrichment.total_vendors} vendors |",
                    f"| Threat Name | {_safe_inline(hash_enrichment.threat_name or 'N/A')} |",
                    f"| Source | {_safe_inline(hash_enrichment.source)} |",
                    "",
                ]
            )

        if enriched.ip_enrichment:
            ip_enrichment = enriched.ip_enrichment
            lines.extend(
                [
                    "### 5.2 IP Analysis",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| IP Address | `{_safe_inline(alert.destination_ip)}` |",
                    f"| Reputation | **{_safe_inline(ip_enrichment.reputation.value.upper())}** |",
                    f"| Confidence Score | {ip_enrichment.confidence_score}/100 |",
                    f"| Is C2 Server | {'YES' if ip_enrichment.is_c2 else 'No'} |",
                    f"| Country | {_safe_inline(ip_enrichment.country or 'Unknown')} |",
                    f"| ISP | {_safe_inline(ip_enrichment.isp or 'Unknown')} |",
                    f"| Source | {_safe_inline(ip_enrichment.source)} |",
                    "",
                ]
            )

        lines.extend(
            [
                "### 5.3 Asset Criticality",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Hostname | `{_safe_inline(alert.hostname)}` |",
                f"| Criticality | **{_safe_inline(enriched.asset_criticality.value.upper())}** |",
                "",
                "### 5.4 MITRE ATT&CK Mapping",
                "",
            ]
        )

        if enriched.mitre_mappings:
            lines.extend(
                [
                    "| Technique ID | Technique Name | Tactic | Confidence | Matched Pattern |",
                    "|-------------|---------------|--------|-----------|----------------|",
                ]
            )
            for mapping in enriched.mitre_mappings:
                technique_id = _safe_inline(mapping.technique_id)
                technique_path = mapping.technique_id.replace(".", "/")
                lines.append(
                    f"| [{technique_id}](https://attack.mitre.org/techniques/{technique_path}) | "
                    f"{_safe_inline(mapping.technique_name)} | {_safe_inline(mapping.tactic)} | "
                    f"{mapping.confidence:.0%} | `{_safe_inline(mapping.matched_pattern)}` |"
                )
            lines.append("")
        else:
            lines.extend(["*No MITRE ATT&CK techniques matched for this alert.*", ""])

        lines.extend(["---", ""])
        return "\n".join(lines)

    def _build_risk_section(self, response: IncidentResponse) -> str:
        enriched = response.enriched_alert
        alert = enriched.original_alert
        ip_rep = (
            "C2 DETECTED"
            if enriched.ip_enrichment and enriched.ip_enrichment.is_c2
            else enriched.ip_enrichment.reputation.value.upper()
            if enriched.ip_enrichment
            else "N/A"
        )
        hash_rep = (
            enriched.hash_enrichment.reputation.value.upper()
            if enriched.hash_enrichment
            else "N/A"
        )
        reasoning = response.policy_reasoning or ["No policy reasoning captured."]
        lines = [
            "## 6. Risk Assessment",
            "",
            f"### Overall Risk Score: **{enriched.risk_score:.1f}/100** - {_safe_inline(enriched.risk_level.upper())}",
            "",
            "| Component | Raw Score | Weight | Contribution |",
            "|-----------|-----------|--------|-------------|",
            f"| Hash Reputation | {_safe_inline(hash_rep)} | 30% | - |",
            f"| IP Reputation | {_safe_inline(ip_rep)} | 25% | - |",
            f"| Asset Criticality | {_safe_inline(enriched.asset_criticality.value.upper())} | 20% | - |",
            f"| Alert Severity | {_safe_inline(alert.severity.value.upper())} | 15% | - |",
            f"| MITRE Techniques | {len(enriched.mitre_mappings)} matched | 10% | - |",
            "",
            "### Scoring Reasoning",
            "",
        ]
        lines.extend(f"- {_safe_inline(item)}" for item in reasoning)
        lines.extend(["", "---", ""])
        return "\n".join(lines)

    def _build_actions_section(self, response: IncidentResponse) -> str:
        lines = ["## 7. Response Actions Taken", ""]
        action_results = [item for item in response.action_results if item.action != ResponseAction.NOTIFY_SOC]

        if action_results:
            lines.extend(
                [
                    "| Action | Status | Time | Details |",
                    "|--------|--------|------|---------|",
                ]
            )
            for result in action_results:
                details = result.details
                if len(details) > 120:
                    details = f"{details[:117]}..."
                lines.append(
                    f"| `{_safe_inline(result.action.value)}` | {_safe_inline(result.status)} | "
                    f"{_format_utc(result.executed_at, '%H:%M:%S UTC')} | {_safe_inline(details)} |"
                )
            lines.append("")
        else:
            lines.extend(["*No automated actions were taken for this alert.*", ""])

        lines.append("### Policy Engine Reasoning")
        lines.append("")
        if response.policy_reasoning:
            lines.extend(f"- {_safe_inline(item)}" for item in response.policy_reasoning)
        else:
            lines.append("- No policy reasoning captured.")
        lines.extend(
            [
                "",
                f"**Ticket Created:** `{_safe_inline(response.ticket_id or 'N/A')}`",
                "",
                "---",
                "",
            ]
        )
        return "\n".join(lines)

    def _build_recommendations_section(self, response: IncidentResponse) -> str:
        enriched = response.enriched_alert
        alert = enriched.original_alert
        actions_taken = {item.value for item in response.triggered_actions}
        recommendations: list[str] = []

        if ResponseAction.ISOLATE_HOST.value in actions_taken:
            recommendations.extend(
                [
                    "Immediate: investigate the isolated host before restoring network access.",
                    "Immediate: capture memory and disk evidence from the affected endpoint.",
                    f"Short-term: rotate credentials associated with `{_safe_inline(alert.username)}`.",
                ]
            )
        if ResponseAction.KILL_PROCESS.value in actions_taken:
            recommendations.extend(
                [
                    f"Immediate: inspect child processes spawned by `{_safe_inline(alert.process_name)}`.",
                    "Short-term: review process creation telemetry around the alert timestamp.",
                ]
            )
        if ResponseAction.BLOCK_IP.value in actions_taken:
            recommendations.extend(
                [
                    f"Immediate: search for additional hosts communicating with `{_safe_inline(alert.destination_ip)}`.",
                    "Short-term: review network flow logs for the last 24 hours.",
                ]
            )
        if ResponseAction.ESCALATE.value in actions_taken:
            recommendations.extend(
                [
                    f"Immediate: escalate host `{_safe_inline(alert.hostname)}` to the SOC lead.",
                    "Immediate: notify the asset owner and incident commander.",
                ]
            )

        recommendations.extend(
            [
                "Short-term: review EDR detections for tuning opportunities and false positives.",
                "Short-term: verify patch and hardening status on the affected endpoint.",
                "Long-term: update playbooks if this incident exposed automation gaps.",
                "Long-term: run a tabletop exercise for this attack path.",
            ]
        )

        if enriched.mitre_mappings:
            tactics = sorted({mapping.tactic for mapping in enriched.mitre_mappings})
            recommendations.append(
                f"Long-term: review defensive coverage for MITRE tactics {', '.join(_safe_inline(tactic) for tactic in tactics)}."
            )

        lines = ["## 8. Recommendations", ""]
        for index, item in enumerate(recommendations, start=1):
            lines.append(f"{index}. {item}")
        lines.extend(["", "---", ""])
        return "\n".join(lines)

    def _build_html(self, markdown_content: str, response: IncidentResponse) -> str:
        try:
            import markdown2

            body_html = markdown2.markdown(
                markdown_content,
                extras=["tables", "fenced-code-blocks", "header-ids", "break-on-newline"],
            )
        except ImportError:
            body_html = f"<pre>{html.escape(markdown_content, quote=True)}</pre>"

        alert = response.enriched_alert.original_alert
        level = _safe_text(response.enriched_alert.risk_level.upper())
        score = response.enriched_alert.risk_score
        accent = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#16a34a",
        }.get(response.enriched_alert.risk_level, "#6b7280")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Incident Report - {_safe_text(alert.alert_id[:8])} - {level}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      color: #1e293b;
      background: #f8fafc;
      padding: 24px;
    }}
    .page {{
      max-width: 960px;
      margin: 0 auto;
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
      overflow: hidden;
    }}
    .header-banner {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
      color: #ffffff;
      padding: 32px 40px;
      border-bottom: 4px solid {accent};
    }}
    .header-banner h1 {{
      margin: 0 0 8px;
      font-size: 22px;
      font-weight: 700;
    }}
    .badge {{
      display: inline-block;
      background: {accent};
      color: #ffffff;
      font-size: 13px;
      font-weight: 700;
      padding: 4px 14px;
      border-radius: 20px;
      letter-spacing: 0.5px;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }}
    .meta-item {{
      color: rgba(255, 255, 255, 0.88);
      font-size: 13px;
    }}
    .meta-item strong {{
      display: block;
      margin-bottom: 2px;
      font-size: 11px;
      letter-spacing: 0.5px;
      opacity: 0.75;
      text-transform: uppercase;
    }}
    .content {{ padding: 40px; }}
    h1, h2, h3, h4 {{ color: #0f172a; line-height: 1.3; }}
    h2 {{
      margin-top: 36px;
      padding-bottom: 8px;
      border-bottom: 2px solid {accent};
    }}
    h3 {{ margin-top: 24px; color: #334155; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
      font-size: 13px;
      border: 1px solid #e2e8f0;
    }}
    th, td {{
      padding: 9px 14px;
      border-bottom: 1px solid #e2e8f0;
      text-align: left;
      vertical-align: top;
    }}
    thead tr, tbody tr:first-child th {{ background: #0f172a; color: #ffffff; }}
    tr:nth-child(even) {{ background: #f8fafc; }}
    code {{
      background: #1e293b;
      color: #7dd3fc;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: "Cascadia Code", "Consolas", monospace;
      font-size: 12px;
    }}
    pre {{
      background: #1e293b;
      color: #e2e8f0;
      padding: 16px 20px;
      border-radius: 8px;
      overflow-x: auto;
      border-left: 4px solid {accent};
    }}
    pre code {{ background: none; color: inherit; padding: 0; }}
    blockquote {{
      margin: 12px 0;
      padding: 12px 16px;
      background: #f0f9ff;
      border-left: 4px solid #0ea5e9;
    }}
    hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 32px 0; }}
    .footer {{
      background: #f8fafc;
      border-top: 1px solid #e2e8f0;
      padding: 16px 40px;
      font-size: 12px;
      color: #64748b;
      text-align: center;
    }}
    @media print {{
      body {{ background: #ffffff; padding: 0; }}
      .page {{ box-shadow: none; border-radius: 0; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="header-banner">
      <h1>Incident Report - Malware Alert</h1>
      <span class="badge">{level} RISK - {score:.1f}/100</span>
      <div class="meta-grid">
        <div class="meta-item"><strong>Alert ID</strong>{_safe_text(alert.alert_id)}</div>
        <div class="meta-item"><strong>Ticket</strong>{_safe_text(response.ticket_id or "N/A")}</div>
        <div class="meta-item"><strong>Hostname</strong>{_safe_text(alert.hostname)}</div>
        <div class="meta-item"><strong>Detection</strong>{_safe_text(alert.detection_name)}</div>
        <div class="meta-item"><strong>Generated</strong>{_safe_text(_format_utc(_utc_now(), '%Y-%m-%d %H:%M UTC'))}</div>
      </div>
    </div>
    <div class="content">
      {body_html}
    </div>
    <div class="footer">
      Generated by <strong>SOAR Malware Playbook v2.0</strong>
      &nbsp;|&nbsp; Ticket: <code>{_safe_text(response.ticket_id or "N/A")}</code>
      &nbsp;|&nbsp; {_safe_text(_format_utc(_utc_now()))}
    </div>
  </div>
</body>
</html>
"""

    def _export_pdf(self, html_content: str, pdf_path: Path) -> Optional[Path]:
        try:
            from weasyprint import HTML

            HTML(string=html_content).write_pdf(str(pdf_path))
            logger.success(f"[Report] PDF saved: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning(
                "[Report] weasyprint is not installed. PDF export skipped; HTML report is still available."
            )
            return None
        except Exception as exc:
            logger.error(f"[Report] PDF export failed: {exc}")
            return None

    @staticmethod
    def _generate_executive_summary(response: IncidentResponse) -> str:
        alert = response.enriched_alert.original_alert
        enriched = response.enriched_alert
        indicators: list[str] = []
        if enriched.hash_enrichment and enriched.hash_enrichment.reputation.value == "malicious":
            indicators.append("hash reputation is malicious")
        if enriched.ip_enrichment and enriched.ip_enrichment.is_c2:
            indicators.append(f"destination IP `{_safe_inline(alert.destination_ip)}` is tagged as C2")
        if enriched.asset_criticality.value == "critical":
            indicators.append(f"host `{_safe_inline(alert.hostname)}` is a critical asset")

        indicator_text = "; ".join(indicators) if indicators else "no high-confidence malicious indicators were present"
        actions_taken = [item.value for item in response.triggered_actions if item != ResponseAction.NOTIFY_SOC]
        action_text = ", ".join(f"`{_safe_inline(item)}`" for item in actions_taken) if actions_taken else "`no_action`"

        return (
            f"EDR generated alert `{_safe_inline(alert.detection_name)}` on host "
            f"`{_safe_inline(alert.hostname)}` for user `{_safe_inline(alert.username)}`. "
            f"The SOAR pipeline classified the incident as **{_safe_inline(enriched.risk_level.upper())}** "
            f"with risk score **{enriched.risk_score:.1f}/100**.\n\n"
            f"Primary risk indicators: {indicator_text}.\n\n"
            f"Automated actions taken: {action_text}."
        )

    @staticmethod
    def _is_dangerous_name(process_name: str) -> bool:
        dangerous_names = {
            "mimikatz.exe",
            "wce.exe",
            "procdump.exe",
            "psexec.exe",
            "nc.exe",
            "ncat.exe",
            "netcat.exe",
            "beacon.exe",
        }
        return process_name.lower() in dangerous_names
