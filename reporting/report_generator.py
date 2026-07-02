"""
reporting/report_generator.py
==============================
Incident Report Generator — sinh báo cáo chuyên nghiệp cho mỗi alert.

Output formats:
  1. Markdown  (.md)  — luôn sinh, dùng để review trong terminal/GitHub
  2. HTML      (.html) — dùng markdown2 + CSS, đẹp để open trong browser
  3. PDF       (.pdf)  — dùng weasyprint (HTML→PDF), optional

Report sections (theo spec mục 6):
  - Executive Summary
  - Alert & Detection Details
  - Timeline xử lý (7 bước)
  - IOC Summary (hash, IP, process, file path)
  - Enrichment Results (hash/IP/asset/MITRE)
  - Risk Assessment với breakdown
  - Response Actions đã thực hiện
  - Recommendations
"""

import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from loguru import logger

from schemas.alert import (
    AssetCriticality,
    HashReputation,
    IPReputation,
    IncidentResponse,
    ResponseAction,
)

# Thư mục output mặc định
_DEFAULT_OUTPUT_DIR = Path("output") / "reports"


class ReportGenerator:
    """
    Sinh incident report đầy đủ từ IncidentResponse.

    Sử dụng:
        generator = ReportGenerator()
        md_path, html_path, pdf_path = generator.generate(response)
    """

    def __init__(self, output_dir: Optional[Path] = None):
        self._output_dir = output_dir or _DEFAULT_OUTPUT_DIR
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        response: IncidentResponse,
        export_pdf: bool = True,
    ) -> tuple[Path, Path, Optional[Path]]:
        """
        Sinh đầy đủ report cho 1 incident.

        Args:
            response   : IncidentResponse từ policy engine
            export_pdf : Có thử export PDF không (cần weasyprint)

        Returns:
            Tuple (md_path, html_path, pdf_path or None)
        """
        alert = response.enriched_alert.original_alert
        safe_id = alert.alert_id.replace("-", "")[:16]
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_name = f"incident_{safe_id}_{ts}"

        logger.info(f"[Report] Generating report for alert {alert.alert_id[:8]}...")

        # ── 1. Sinh Markdown ──────────────────────────────────────────
        md_content = self._build_markdown(response)
        md_path = self._output_dir / f"{base_name}.md"
        md_path.write_text(md_content, encoding="utf-8")
        logger.success(f"[Report] Markdown saved: {md_path}")

        # ── 2. Sinh HTML ──────────────────────────────────────────────
        html_content = self._build_html(md_content, response)
        html_path = self._output_dir / f"{base_name}.html"
        html_path.write_text(html_content, encoding="utf-8")
        logger.success(f"[Report] HTML saved: {html_path}")

        # ── 3. Export PDF (optional) ──────────────────────────────────
        pdf_path: Optional[Path] = None
        if export_pdf:
            pdf_path = self._export_pdf(html_content, self._output_dir / f"{base_name}.pdf")

        return md_path, html_path, pdf_path

    # ──────────────────────────────────────────────────────────────────
    # Markdown builder
    # ──────────────────────────────────────────────────────────────────

    def _build_markdown(self, response: IncidentResponse) -> str:
        """Sinh nội dung Markdown đầy đủ từ IncidentResponse."""
        enriched = response.enriched_alert
        alert    = enriched.original_alert
        now_str  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        risk_level  = enriched.risk_level.upper()
        risk_score  = enriched.risk_score
        ticket_id   = response.ticket_id or "N/A"

        # Emoji badges
        severity_badge = {
            "low": "🟢 LOW", "medium": "🟡 MEDIUM",
            "high": "🔴 HIGH", "critical": "🔴🔴 CRITICAL"
        }.get(enriched.risk_level, enriched.risk_level.upper())

        sections = []

        # ── Header ────────────────────────────────────────────────────
        sections.append(f"""\
# 🛡️ Incident Report — Malware Alert on Endpoint

| Field | Value |
|-------|-------|
| **Report Generated** | {now_str} |
| **Alert ID** | `{alert.alert_id}` |
| **Ticket ID** | `{ticket_id}` |
| **Risk Level** | **{severity_badge}** |
| **Risk Score** | **{risk_score:.1f} / 100** |
| **Detection** | {alert.detection_name} |
| **Analyst** | SOAR Automated Response |

---
""")

        # ── 1. Executive Summary ──────────────────────────────────────
        actions_taken = [
            a.value for a in response.triggered_actions
            if a not in (ResponseAction.CREATE_TICKET, ResponseAction.NOTIFY_SOC)
        ]
        actions_str = ", ".join(f"`{a}`" for a in actions_taken) if actions_taken else "`no_action`"

        hash_rep  = enriched.hash_enrichment.reputation.value if enriched.hash_enrichment else "unknown"
        ip_is_c2  = enriched.ip_enrichment.is_c2 if enriched.ip_enrichment else False
        asset_crit = enriched.asset_criticality.value

        summary = self._generate_executive_summary(
            alert, enriched.risk_level, risk_score, hash_rep, ip_is_c2,
            asset_crit, actions_taken
        )
        sections.append(f"""\
## 1. Executive Summary

{summary}

---
""")

        # ── 2. Alert Details ──────────────────────────────────────────
        sections.append(f"""\
## 2. Alert Details

| Field | Value |
|-------|-------|
| **Alert ID** | `{alert.alert_id}` |
| **Received At** | {alert.received_at.strftime('%Y-%m-%d %H:%M:%S UTC')} |
| **Hostname** | `{alert.hostname}` |
| **Username** | `{alert.username}` |
| **Process Name** | `{alert.process_name}` |
| **Parent Process** | `{alert.parent_process}` |
| **File Path** | `{alert.file_path}` |
| **Detection Name** | {alert.detection_name} |
| **EDR Severity** | {alert.severity.value.upper()} |

**Command Line:**
```
{alert.command_line}
```

---
""")

        # ── 3. Timeline ───────────────────────────────────────────────
        sections.append(self._build_timeline_section(response))

        # ── 4. IOC Summary ────────────────────────────────────────────
        hash_threat = (
            enriched.hash_enrichment.threat_name
            if enriched.hash_enrichment and enriched.hash_enrichment.threat_name
            else "N/A"
        )
        ip_country = (
            enriched.ip_enrichment.country
            if enriched.ip_enrichment else "N/A"
        )
        sections.append(f"""\
## 4. IOC Summary

| IOC Type | Value | Reputation |
|----------|-------|------------|
| **File Hash (SHA256)** | `{alert.file_hash}` | {hash_rep.upper()} |
| **Threat Name** | {hash_threat} | — |
| **Destination IP** | `{alert.destination_ip}` | {'⚠️ C2 SERVER' if ip_is_c2 else enriched.ip_enrichment.reputation.value.upper() if enriched.ip_enrichment else 'UNKNOWN'} |
| **IP Country** | {ip_country} | — |
| **Process Name** | `{alert.process_name}` | {'⚠️ DANGEROUS' if self._is_dangerous_name(alert.process_name) else 'Normal'} |
| **File Path** | `{alert.file_path}` | — |
| **Parent Process** | `{alert.parent_process}` | — |

---
""")

        # ── 5. Enrichment Results ─────────────────────────────────────
        sections.append(self._build_enrichment_section(enriched))

        # ── 6. Risk Assessment ────────────────────────────────────────
        sections.append(f"""\
## 6. Risk Assessment

### Overall Risk Score: **{risk_score:.1f}/100** — {risk_level}

| Component | Raw Score | Weight | Contribution |
|-----------|-----------|--------|-------------|
| Hash Reputation | {enriched.hash_enrichment.reputation.value.upper() if enriched.hash_enrichment else 'N/A'} | 30% | — |
| IP Reputation | {'C2 DETECTED' if ip_is_c2 else enriched.ip_enrichment.reputation.value.upper() if enriched.ip_enrichment else 'N/A'} | 25% | — |
| Asset Criticality | {asset_crit.upper()} | 20% | — |
| Alert Severity | {alert.severity.value.upper()} | 15% | — |
| MITRE Techniques | {len(enriched.mitre_mappings)} matched | 10% | — |

### Scoring Reasoning:
""" + "\n".join(f"- {r}" for r in (response.policy_reasoning if hasattr(response, 'policy_reasoning') else [])) + "\n\n---\n")

        # ── 7. Response Actions ───────────────────────────────────────
        sections.append(self._build_actions_section(response))

        # ── 8. Recommendations ───────────────────────────────────────
        sections.append(self._build_recommendations_section(
            enriched, actions_taken
        ))

        # ── Footer ────────────────────────────────────────────────────
        sections.append(f"""\
---

*Report generated automatically by SOAR Malware Playbook v1.0*
*Ticket: `{ticket_id}` | Alert ID: `{alert.alert_id}`*
*{now_str}*
""")

        return "\n".join(sections)

    def _build_timeline_section(self, response: IncidentResponse) -> str:
        """Sinh section Timeline 7 bước."""
        enriched = response.enriched_alert
        alert    = enriched.original_alert
        t0       = alert.received_at

        def fmt_time(dt: datetime) -> str:
            return dt.strftime("%H:%M:%S UTC") if dt else "—"

        completed = response.completed_at

        lines = [
            "## 3. Processing Timeline\n",
            "| Step | Description | Time | Status |",
            "|------|-------------|------|--------|",
            f"| **Step 1** | Alert Received from EDR | {fmt_time(t0)} | ✅ Done |",
            f"| **Step 2** | Hash Enrichment (mock VirusTotal) | {fmt_time(t0)} | ✅ Done |",
            f"| **Step 3** | IP Enrichment (mock AbuseIPDB) | {fmt_time(t0)} | ✅ Done |",
            f"| **Step 4** | Asset Criticality Lookup (mock CMDB) | {fmt_time(t0)} | ✅ Done |",
            f"| **Step 5** | MITRE ATT&CK Mapping | {fmt_time(t0)} | ✅ Done ({len(enriched.mitre_mappings)} techniques) |",
            f"| **Step 6** | Risk Score Calculation | {fmt_time(t0)} | ✅ Done ({enriched.risk_score:.1f}/100) |",
            f"| **Step 7** | Policy Engine + Actions | {fmt_time(completed)} | ✅ Done |",
            "",
            f"> **Total Processing Time:** < 1 second (mock pipeline)",
            "",
            "---",
            "",
        ]
        return "\n".join(lines)

    def _build_enrichment_section(self, enriched) -> str:
        """Sinh section Enrichment Results."""
        alert = enriched.original_alert
        lines = ["## 5. Enrichment Results\n"]

        # Hash enrichment
        if enriched.hash_enrichment:
            h = enriched.hash_enrichment
            status_icon = {"malicious": "🔴", "suspicious": "🟡", "clean": "🟢"}.get(
                h.reputation.value, "⚪"
            )
            lines += [
                "### 5.1 Hash Analysis (VirusTotal-like)\n",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Hash  | `{alert.file_hash}` |",
                f"| Reputation | {status_icon} **{h.reputation.value.upper()}** |",
                f"| Detection Rate | {h.malicious_vendors}/{h.total_vendors} vendors |",
                f"| Threat Name | {h.threat_name or 'N/A'} |",
                f"| Source | {h.source} |",
                "",
            ]

        # IP enrichment
        if enriched.ip_enrichment:
            ip = enriched.ip_enrichment
            c2_badge = " 🚨 **[C2 SERVER]**" if ip.is_c2 else ""
            status_icon = {"malicious": "🔴", "clean": "🟢"}.get(ip.reputation.value, "⚪")
            lines += [
                "### 5.2 IP Analysis (AbuseIPDB-like)\n",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| IP Address | `{alert.destination_ip}`{c2_badge} |",
                f"| Reputation | {status_icon} **{ip.reputation.value.upper()}** |",
                f"| Confidence Score | {ip.confidence_score}/100 |",
                f"| Is C2 Server | {'⚠️ YES' if ip.is_c2 else 'No'} |",
                f"| Country | {ip.country or 'Unknown'} |",
                f"| ISP | {ip.isp or 'Unknown'} |",
                f"| Source | {ip.source} |",
                "",
            ]

        # Asset criticality
        crit_icon = {"critical": "🔴", "normal": "🟡", "low": "🟢"}.get(
            enriched.asset_criticality.value, "⚪"
        )
        lines += [
            "### 5.3 Asset Criticality (CMDB)\n",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Hostname | `{alert.hostname}` |",
            f"| Criticality | {crit_icon} **{enriched.asset_criticality.value.upper()}** |",
            "",
        ]

        # MITRE mappings
        lines += ["### 5.4 MITRE ATT&CK Mapping\n"]
        if enriched.mitre_mappings:
            lines += [
                "| Technique ID | Technique Name | Tactic | Confidence | Matched Pattern |",
                "|-------------|---------------|--------|-----------|----------------|",
            ]
            for m in enriched.mitre_mappings:
                lines.append(
                    f"| [{m.technique_id}](https://attack.mitre.org/techniques/"
                    f"{m.technique_id.replace('.', '/')}) "
                    f"| {m.technique_name} | {m.tactic} "
                    f"| {m.confidence:.0%} | `{m.matched_pattern}` |"
                )
            lines.append("")
        else:
            lines += ["*No MITRE ATT&CK techniques matched for this alert.*\n"]

        lines.append("---\n")
        return "\n".join(lines)

    def _build_actions_section(self, response: IncidentResponse) -> str:
        """Sinh section Response Actions."""
        lines = ["## 7. Response Actions Taken\n"]

        main_actions = [
            r for r in response.action_results
            if r.action not in (ResponseAction.NOTIFY_SOC,)
        ]

        if not main_actions:
            lines.append("*No automated actions were taken for this alert.*\n")
        else:
            lines += [
                "| Action | Status | Time | Details |",
                "|--------|--------|------|---------|",
            ]
            for result in main_actions:
                status_icon = "✅" if result.status == "success" else "❌"
                time_str = result.executed_at.strftime("%H:%M:%S UTC")
                # Truncate details for table
                details_short = result.details[:80] + "..." if len(result.details) > 80 else result.details
                lines.append(
                    f"| `{result.action.value}` | {status_icon} {result.status} "
                    f"| {time_str} | {details_short} |"
                )
            lines.append("")

        # Policy reasoning
        lines += [
            "### Policy Engine Reasoning\n",
        ]
        for r in response.policy_reasoning:
            icon = "🔴" if "TRIGGERED" in r else "🟢" if "PASS" in r else "⚪"
            lines.append(f"- {icon} {r}")

        lines += ["", f"**Ticket Created:** `{response.ticket_id or 'N/A'}`", "", "---", ""]
        return "\n".join(lines)

    def _build_recommendations_section(self, enriched, actions_taken: list) -> str:
        """Sinh recommendations dựa trên kết quả enrichment + actions."""
        alert = enriched.original_alert
        recs  = []

        # Recommendations dựa trên actions đã thực hiện
        if ResponseAction.ISOLATE_HOST.value in actions_taken:
            recs += [
                "**[Immediate]** Host đã bị isolate. Tiến hành forensic investigation "
                "trước khi restore network access.",
                "**[Immediate]** Thu thập memory dump và disk image từ host bị compromise.",
                "**[Short-term]** Reset credentials của user `{}` và tất cả shared accounts.".format(
                    alert.username
                ),
            ]

        if ResponseAction.KILL_PROCESS.value in actions_taken:
            recs += [
                f"**[Immediate]** Kiểm tra xem process `{alert.process_name}` đã spawn child processes nào chưa.",
                "**[Short-term]** Review audit logs để tìm lateral movement từ thời điểm process khởi chạy.",
            ]

        if ResponseAction.BLOCK_IP.value in actions_taken:
            recs += [
                f"**[Immediate]** Kiểm tra tất cả hosts khác có kết nối tới IP `{alert.destination_ip}` không.",
                "**[Short-term]** Review network flow logs 24h trước thời điểm alert.",
                "**[Long-term]** Thêm IP này vào threat intel feed nội bộ.",
            ]

        if ResponseAction.ESCALATE.value in actions_taken:
            recs += [
                f"**[Immediate]** Host `{alert.hostname}` là critical asset — escalate lên SOC Lead ngay.",
                "**[Immediate]** Thông báo cho business owner và management về potential breach.",
            ]

        # General recommendations
        recs += [
            "**[Short-term]** Review EDR detection rules để giảm false positive rate.",
            "**[Short-term]** Kiểm tra patch level của host bị ảnh hưởng.",
            "**[Long-term]** Update SOAR playbook nếu phát hiện gap trong response.",
            "**[Long-term]** Conduct tabletop exercise để validate incident response procedure.",
        ]

        if enriched.mitre_mappings:
            tactics = list({m.tactic for m in enriched.mitre_mappings})
            recs.append(
                f"**[Long-term]** Review defensive controls cho MITRE tactics: "
                f"{', '.join(tactics)}."
            )

        lines = ["## 8. Recommendations\n"]
        for i, rec in enumerate(recs, 1):
            lines.append(f"{i}. {rec}")
        lines += ["", "---", ""]
        return "\n".join(lines)

    # ──────────────────────────────────────────────────────────────────
    # HTML builder (với CSS styling)
    # ──────────────────────────────────────────────────────────────────

    def _build_html(self, md_content: str, response: IncidentResponse) -> str:
        """Convert Markdown → styled HTML."""
        try:
            import markdown2
            body_html = markdown2.markdown(
                md_content,
                extras=["tables", "fenced-code-blocks", "header-ids", "break-on-newline"]
            )
        except ImportError:
            # Fallback: wrap markdown in <pre> nếu markdown2 chưa cài
            body_html = f"<pre>{md_content}</pre>"

        alert   = response.enriched_alert.original_alert
        level   = response.enriched_alert.risk_level
        score   = response.enriched_alert.risk_score
        ticket  = response.ticket_id or "N/A"

        # Color scheme theo risk level
        accent = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706", "low": "#16a34a"
        }.get(level, "#6b7280")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Incident Report — {alert.alert_id[:8]} — {level.upper()}</title>
  <style>
    /* ── Reset & Base ── */
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      color: #1e293b;
      background: #f8fafc;
      padding: 24px;
    }}

    /* ── Page wrapper ── */
    .page {{
      max-width: 960px;
      margin: 0 auto;
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      overflow: hidden;
    }}

    /* ── Header banner ── */
    .header-banner {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
      color: white;
      padding: 32px 40px;
      border-bottom: 4px solid {accent};
    }}
    .header-banner h1 {{
      font-size: 22px;
      font-weight: 700;
      margin-bottom: 8px;
      color: white;
      border: none;
    }}
    .badge {{
      display: inline-block;
      background: {accent};
      color: white;
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
    .meta-item {{ color: rgba(255,255,255,0.85); font-size: 13px; }}
    .meta-item strong {{ color: white; display: block; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; margin-bottom: 2px; }}

    /* ── Content body ── */
    .content {{ padding: 40px; }}

    /* ── Typography ── */
    h1, h2, h3, h4 {{
      color: #0f172a;
      font-weight: 700;
      line-height: 1.3;
    }}
    h2 {{
      font-size: 18px;
      margin: 36px 0 16px;
      padding-bottom: 8px;
      border-bottom: 2px solid {accent};
      color: #0f172a;
    }}
    h3 {{
      font-size: 15px;
      margin: 24px 0 12px;
      color: #334155;
    }}
    p {{ margin-bottom: 12px; color: #374151; }}

    /* ── Tables ── */
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
      font-size: 13px;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid #e2e8f0;
    }}
    thead tr {{ background: #0f172a; color: white; }}
    thead th {{
      padding: 10px 14px;
      text-align: left;
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    tbody tr {{ transition: background 0.15s; }}
    tbody tr:nth-child(even) {{ background: #f8fafc; }}
    tbody tr:hover {{ background: #f1f5f9; }}
    td {{ padding: 9px 14px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}

    /* ── Code blocks ── */
    code {{
      background: #1e293b;
      color: #7dd3fc;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
      font-size: 12px;
    }}
    pre {{
      background: #1e293b;
      color: #e2e8f0;
      padding: 16px 20px;
      border-radius: 8px;
      overflow-x: auto;
      margin: 12px 0;
      border-left: 4px solid {accent};
    }}
    pre code {{ background: none; color: inherit; padding: 0; }}

    /* ── Blockquotes / callouts ── */
    blockquote {{
      background: #f0f9ff;
      border-left: 4px solid #0ea5e9;
      padding: 12px 16px;
      margin: 12px 0;
      border-radius: 0 6px 6px 0;
    }}
    blockquote p {{ color: #0369a1; margin: 0; font-style: italic; }}

    /* ── Lists ── */
    ul, ol {{ padding-left: 24px; margin: 12px 0; }}
    li {{ margin-bottom: 6px; color: #374151; }}

    /* ── HR ── */
    hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 32px 0; }}

    /* ── Risk badge in content ── */
    strong {{ color: #0f172a; }}

    /* ── Footer ── */
    .footer {{
      background: #f8fafc;
      border-top: 1px solid #e2e8f0;
      padding: 16px 40px;
      font-size: 12px;
      color: #64748b;
      text-align: center;
    }}

    /* ── Print styles ── */
    @media print {{
      body {{ background: white; padding: 0; }}
      .page {{ box-shadow: none; border-radius: 0; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <!-- Header Banner -->
    <div class="header-banner">
      <h1>🛡️ Incident Report — Malware Alert</h1>
      <span class="badge">{level.upper()} RISK — {score:.1f}/100</span>
      <div class="meta-grid">
        <div class="meta-item">
          <strong>Alert ID</strong>
          {alert.alert_id[:16]}...
        </div>
        <div class="meta-item">
          <strong>Ticket</strong>
          {ticket}
        </div>
        <div class="meta-item">
          <strong>Hostname</strong>
          {alert.hostname}
        </div>
        <div class="meta-item">
          <strong>Detection</strong>
          {alert.detection_name}
        </div>
        <div class="meta-item">
          <strong>Generated</strong>
          {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
        </div>
      </div>
    </div>

    <!-- Main Content -->
    <div class="content">
      {body_html}
    </div>

    <!-- Footer -->
    <div class="footer">
      Generated by <strong>SOAR Malware Playbook v1.0</strong> —
      Automated Incident Response System &nbsp;|&nbsp;
      Ticket: <code>{ticket}</code> &nbsp;|&nbsp;
      {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
    </div>
  </div>
</body>
</html>
"""

    # ──────────────────────────────────────────────────────────────────
    # PDF export
    # ──────────────────────────────────────────────────────────────────

    def _export_pdf(self, html_content: str, pdf_path: Path) -> Optional[Path]:
        """Export HTML → PDF dùng weasyprint (nếu available)."""
        try:
            from weasyprint import HTML, CSS
            HTML(string=html_content).write_pdf(str(pdf_path))
            logger.success(f"[Report] PDF saved: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning(
                "[Report] weasyprint chưa cài — PDF không được tạo. "
                "Chạy: pip install weasyprint để enable PDF export. "
                "HTML report đã sẵn sàng để print-to-PDF từ browser."
            )
            return None
        except Exception as e:
            logger.error(f"[Report] PDF export failed: {e}")
            logger.info("[Report] Mở file HTML trong browser và dùng Ctrl+P để in PDF.")
            return None

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _generate_executive_summary(
        alert, risk_level: str, risk_score: float,
        hash_rep: str, ip_is_c2: bool, asset_crit: str,
        actions_taken: list,
    ) -> str:
        """Sinh đoạn tóm tắt executive bằng ngôn ngữ tự nhiên."""
        severity_desc = {
            "critical": "**CRITICAL** — yêu cầu phản ứng khẩn cấp ngay lập tức",
            "high":     "**HIGH** — yêu cầu điều tra và phản ứng trong vòng 4 giờ",
            "medium":   "**MEDIUM** — cần review và xử lý trong ngày làm việc",
            "low":      "**LOW** — theo dõi và log lại, review định kỳ",
        }.get(risk_level, risk_level)

        indicators = []
        if hash_rep == "malicious":
            indicators.append("hash file được xác nhận là **malicious** bởi threat intelligence")
        if ip_is_c2:
            indicators.append(f"IP đích `{alert.destination_ip}` được gắn cờ là **C2 server**")
        if asset_crit == "critical":
            indicators.append(f"host `{alert.hostname}` là **critical asset** (high business impact)")

        indicator_str = "; ".join(indicators) if indicators else "các chỉ số đáng ngờ"

        actions_str = (
            ", ".join(f"`{a}`" for a in actions_taken)
            if actions_taken else "không có hành động tự động"
        )

        return (
            f"Hệ thống EDR phát hiện và gửi alert malware `{alert.detection_name}` "
            f"trên host `{alert.hostname}` (user: `{alert.username}`). "
            f"Sau khi SOAR pipeline phân tích, alert được đánh giá là {severity_desc} "
            f"với Risk Score **{risk_score:.1f}/100**.\n\n"
            f"Các chỉ số rủi ro chính: {indicator_str}.\n\n"
            f"Hành động đã tự động thực hiện: {actions_str}."
        )

    @staticmethod
    def _is_dangerous_name(process_name: str) -> bool:
        """Quick check xem process có trong dangerous list không."""
        dangerous = {
            "mimikatz.exe", "wce.exe", "procdump.exe", "psexec.exe",
            "nc.exe", "ncat.exe", "netcat.exe", "beacon.exe",
        }
        return process_name.lower() in dangerous
