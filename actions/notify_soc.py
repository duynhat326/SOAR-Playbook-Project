"""
actions/notify_soc.py
=====================
Mock action: Gửi thông báo tới SOC team.

Trong thực tế:
  - Slack webhook (POST JSON payload)
  - Microsoft Teams webhook
  - Email (SMTP)
  - PagerDuty alert

Ở đây: in ra console + log file (mock notification).
"""

from loguru import logger
from rich.panel import Panel

from schemas.alert import ActionResult, ResponseAction
from terminal_compat import build_console
from time_utils import utc_now

console = build_console()


def execute(
    alert_id: str,
    hostname: str,
    risk_score: float,
    risk_level: str,
    triggered_actions: list,
    ticket_id: str = "",
    channel: str = "#soc-alerts",
    operator: str = "SOAR_AUTO",
) -> ActionResult:
    """
    Gửi SOC notification (mock).

    Args:
        alert_id         : Alert ID
        hostname         : Host bị ảnh hưởng
        risk_score       : Risk score để SOC nắm mức độ
        risk_level       : Risk level (low/medium/high/critical)
        triggered_actions: Actions đã thực hiện
        ticket_id        : Ticket ID liên quan (nếu có)
        channel          : Slack/Teams channel mock
        operator         : Người gửi

    Returns:
        ActionResult
    """
    logger.info(
        f"[ACTION] 📢 NOTIFY SOC: channel={channel} | "
        f"alert={alert_id[:8]} | risk={risk_level.upper()} ({risk_score:.1f})"
    )

    # Mô phỏng Slack message format
    actions_text = ", ".join(triggered_actions) if triggered_actions else "NONE"
    color = _risk_color(risk_level)

    # Mock Slack-style message in console
    message = (
        f"🚨 [bold {color}][SOAR ALERT — {risk_level.upper()}][/bold {color}]\n"
        f"  Alert ID : {alert_id}\n"
        f"  Host     : {hostname}\n"
        f"  Risk     : [{color}]{risk_score:.1f}/100 ({risk_level.upper()})[/{color}]\n"
        f"  Actions  : {actions_text}\n"
        f"  Ticket   : {ticket_id or 'N/A'}\n"
        f"  Time     : {utc_now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"  [dim]Sent to {channel} by {operator}[/dim]"
    )

    console.print(Panel(
        message,
        title=f"[bold]📢 SOC Notification → {channel}[/bold]",
        border_style=color,
    ))

    details = (
        f"SOC notification sent to channel '{channel}'. "
        f"Risk: {risk_level.upper()} ({risk_score:.1f}/100). "
        f"Actions taken: {actions_text}. "
        f"Ticket: {ticket_id or 'N/A'}."
    )

    logger.success(f"[ACTION] ✓ SOC notified via {channel} (mock)")

    return ActionResult(
        action=ResponseAction.NOTIFY_SOC,
        status="succeeded",
        executed_at=utc_now(),
        details=details,
    )


def _risk_color(level: str) -> str:
    return {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "green",
    }.get(level, "white")
