"""
actions/kill_process.py
=======================
Mock action: Kill tiến trình độc hại trên endpoint.

Trong thực tế: gọi EDR API để terminate process theo PID hoặc process name.
Ví dụ CrowdStrike: POST /real-time-response/combined/batch-active-responder-command/v1
với body: {"command_string": "kill <pid>"}
"""

import json
from datetime import datetime
from pathlib import Path

from loguru import logger

from schemas.alert import ActionResult, ResponseAction

_KILL_LOG = Path("output") / "killed_processes.json"


def execute(
    process_name: str,
    hostname: str,
    alert_id: str,
    command_line: str = "",
    reason: str = "Dangerous process detected",
    operator: str = "SOAR_AUTO",
) -> ActionResult:
    """
    Thực hiện kill process (mock).

    Args:
        process_name : Tên tiến trình cần kill
        hostname     : Máy chứa tiến trình
        alert_id     : Alert ID để trace
        command_line : Command line của process (để log đầy đủ)
        reason       : Lý do kill
        operator     : Ai ra lệnh

    Returns:
        ActionResult
    """
    logger.warning(
        f"[ACTION] 🛑 KILL PROCESS: '{process_name}' on '{hostname}' | "
        f"alert={alert_id[:8]} | reason={reason}"
    )

    _record_kill(process_name, hostname, alert_id, command_line, reason, operator)

    details = (
        f"Process '{process_name}' trên host '{hostname}' đã bị TERMINATE. "
        f"Command line: [{command_line[:100]}{'...' if len(command_line) > 100 else ''}]. "
        f"Operator: {operator}. Reason: {reason}."
    )

    logger.success(f"[ACTION] ✓ Process '{process_name}' killed on '{hostname}' (mock)")

    return ActionResult(
        action=ResponseAction.KILL_PROCESS,
        status="success",
        executed_at=datetime.utcnow(),
        details=details,
    )


def _record_kill(
    process_name: str,
    hostname: str,
    alert_id: str,
    command_line: str,
    reason: str,
    operator: str,
) -> None:
    """Ghi kill event vào file JSON."""
    _KILL_LOG.parent.mkdir(parents=True, exist_ok=True)

    existing: list = []
    if _KILL_LOG.exists():
        try:
            with open(_KILL_LOG, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []

    existing.append({
        "process_name": process_name,
        "hostname"    : hostname,
        "alert_id"    : alert_id,
        "command_line": command_line,
        "reason"      : reason,
        "operator"    : operator,
        "killed_at"   : datetime.utcnow().isoformat() + "Z",
        "mock"        : True,
    })

    with open(_KILL_LOG, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
