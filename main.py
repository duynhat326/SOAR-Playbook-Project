"""
main.py
=======
Entrypoint chính của SOAR Malware Playbook pipeline.

Chạy toàn bộ 7 bước workflow cho một alert JSON đầu vào,
với trace đẹp từng bước bằng Rich.

Cách chạy:
  # Dùng alert ngẫu nhiên theo scenario
  python main.py --scenario mixed

  # Dùng alert từ file JSON
  python main.py --alert data/sample_alerts/alert_04_full_critical.json

  # Xem tất cả options
  python main.py --help
"""

import argparse
import json
import sys
from pathlib import Path

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

# ── Logger config — log ra file + console ─────────────────────────────
logger.remove()  # Xóa default handler
logger.add(
    "output/pipeline.log",
    format="{time:HH:mm:ss} | {level:<8} | {message}",
    level="DEBUG",
    rotation="10 MB",
    retention="7 days",
)
# Console handler: chỉ WARNING trở lên (để không spam Rich panels)
logger.add(sys.stderr, format="{time:HH:mm:ss} | {level} | {message}", level="WARNING")

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "SOAR Malware Playbook — Automated Malware Alert Response\n"
            "Chạy 7-bước workflow: parse → enrich → MITRE map → risk score → policy → report"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--alert", "-a",
        type=str,
        metavar="FILE",
        help="Đường dẫn đến file JSON alert (ví dụ: data/sample_alerts/alert_01.json)",
    )
    group.add_argument(
        "--scenario", "-s",
        type=str,
        choices=["malicious_hash", "c2_communication", "critical_asset",
                 "dangerous_process", "mixed", "benign", "random"],
        default="mixed",
        help="Sinh alert ngẫu nhiên theo scenario (mặc định: mixed)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=2024,
        help="Random seed để sinh alert reproducible (mặc định: 2024)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Bỏ qua bước sinh incident report",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="output",
        help="Thư mục lưu output (mặc định: ./output)",
    )
    return parser.parse_args()


def load_alert_from_file(path: str):
    """Load và parse alert từ file JSON."""
    alert_path = Path(path)
    if not alert_path.exists():
        console.print(f"[red]❌ File không tìm thấy: {alert_path}[/red]")
        sys.exit(1)

    with open(alert_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Xóa field bắt đầu bằng '_' (metadata fields trong sample files)
    data = {k: v for k, v in data.items() if not k.startswith("_")}
    return data


def main():
    args = parse_args()

    # ── Banner ────────────────────────────────────────────────────────
    console.print()
    console.print(Panel.fit(
        "[bold cyan]SOAR Malware Playbook[/bold cyan] [dim]v1.0[/dim]\n"
        "[dim]Automated Malware Alert Response System — Blue Team CV Project[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))
    console.print()

    # ── Import app services ───────────────────────────────────────────
    from alert_generator.generator import generate_alert
    from schemas.alert import MalwareAlert
    from services.workflow_service import SoarWorkflowService

    # ── Bước 1: Nhận alert ────────────────────────────────────────────
    console.print(Rule("[bold]Pipeline Start[/bold]"))

    if args.alert:
        console.print(f"[cyan]📂 Loading alert from:[/cyan] {args.alert}")
        alert_data = load_alert_from_file(args.alert)
        alert = MalwareAlert(**alert_data)
        console.print(f"[green]✓ Alert loaded:[/green] {alert.alert_id}")
    else:
        console.print(f"[cyan]🎲 Generating alert:[/cyan] scenario='{args.scenario}' seed={args.seed}")
        alert = generate_alert(scenario=args.scenario, seed=args.seed)
        console.print(f"[green]✓ Alert generated:[/green] {alert.alert_id}")

    console.print()

    workflow = SoarWorkflowService(
        verbose=True,
        report_output_dir=Path(args.output_dir) / "reports",
    )
    result = workflow.process_alert(
        alert,
        generate_report=not args.no_report,
        export_pdf=not args.no_report,
    )
    enriched = result.enriched_alert
    response = result.response
    console.print()

    if not args.no_report:
        console.print(Rule("[bold]Incident Report Ready[/bold]"))
        console.print(Panel(
            f"[bold green]✓ Incident Report Generated[/bold green]\n\n"
            f"  [bold]Markdown:[/bold] {result.artifacts.markdown_path}\n"
            f"  [bold]HTML:[/bold]     {result.artifacts.html_path}\n"
            f"  [bold]PDF:[/bold]      {result.artifacts.pdf_path or '[dim]N/A (pip install weasyprint để enable)[/dim]'}\n\n"
            f"  [dim]Mở file HTML trong browser để xem report đẹp.[/dim]",
            border_style="green",
        ))

    # ── Final Summary ─────────────────────────────────────────────────
    console.print(Rule("[bold]Pipeline Complete[/bold]"))

    from schemas.alert import ResponseAction
    remediation = [
        a for a in response.triggered_actions
        if a not in (ResponseAction.CREATE_TICKET, ResponseAction.NOTIFY_SOC)
    ]

    risk_color = {
        "critical": "bold red", "high": "red", "medium": "yellow", "low": "green"
    }.get(enriched.risk_level, "white")

    console.print(Panel(
        f"[bold]Alert ID:[/bold]    {alert.alert_id}\n"
        f"[bold]Host:[/bold]        {alert.hostname}  (user: {alert.username})\n"
        f"[bold]Detection:[/bold]   {alert.detection_name}\n"
        f"[bold]Risk Score:[/bold]  [{risk_color}]{enriched.risk_score:.1f}/100 ({enriched.risk_level.upper()})[/{risk_color}]\n"
        f"[bold]MITRE:[/bold]       {len(enriched.mitre_mappings)} technique(s) mapped\n"
        f"[bold]Actions:[/bold]     {', '.join(a.value for a in remediation) or 'no action'}\n"
        f"[bold]Ticket:[/bold]      {response.ticket_id or 'N/A'}\n"
        f"[bold]Log file:[/bold]    output/pipeline.log",
        title="[bold green]✅ SOAR Pipeline Complete[/bold green]",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
