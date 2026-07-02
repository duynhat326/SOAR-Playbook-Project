"""
actions/isolate_host.py
=======================
Mock action: Isolate endpoint khỏi network.

Trong môi trường thật, đây sẽ gọi API của EDR (CrowdStrike, SentinelOne,
Microsoft Defender for Endpoint...) để cách ly host.

Ở đây: log lại action + cập nhật file JSON tracking (mock EDR response).
"""

import json
from pathlib import Path
from typing import Optional

from loguru import logger

from schemas.alert import ActionResult, ResponseAction
from time_utils import utc_isoformat_z, utc_now

# File theo dõi các host đã bị isolate (mock EDR state)
_ISOLATION_LOG = Path("output") / "isolated_hosts.json"


def execute(
    hostname: str,
    alert_id: str,
    reason: str = "Malicious hash detected",
    operator: str = "SOAR_AUTO",
) -> ActionResult:
    """
    Thực hiện isolate endpoint (mock).

    Trong thực tế: POST /api/devices/actions?action_name=contain
    (CrowdStrike Falcon API example)

    Args:
        hostname : Tên máy cần isolate
        alert_id : Alert ID để ghi vào audit log
        reason   : Lý do isolate (cho audit trail)
        operator : Ai ra lệnh isolate

    Returns:
        ActionResult với status và details
    """
    logger.warning(
        f"[ACTION] 🔴 ISOLATE HOST: '{hostname}' | "
        f"alert={alert_id[:8]} | reason={reason}"
    )

    # Mô phỏng ghi vào EDR (thực tế là gọi API)
    _record_isolation(hostname, alert_id, reason, operator)

    details = (
        f"Host '{hostname}' đã bị ISOLATE khỏi network. "
        f"Tất cả kết nối bị cắt (trừ kết nối tới EDR agent). "
        f"Operator: {operator}. Reason: {reason}."
    )

    logger.success(f"[ACTION] ✓ Host '{hostname}' isolated successfully (mock)")

    return ActionResult(
        action=ResponseAction.ISOLATE_HOST,
        status="success",
        executed_at=utc_now(),
        details=details,
    )


def _record_isolation(
    hostname: str,
    alert_id: str,
    reason: str,
    operator: str,
) -> None:
    """Ghi lại isolation event vào file JSON (mock EDR state store)."""
    _ISOLATION_LOG.parent.mkdir(parents=True, exist_ok=True)

    # Đọc log hiện tại (nếu có)
    existing: list = []
    if _ISOLATION_LOG.exists():
        try:
            with open(_ISOLATION_LOG, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []

    # Thêm record mới
    existing.append({
        "hostname"  : hostname,
        "alert_id"  : alert_id,
        "reason"    : reason,
        "operator"  : operator,
        "isolated_at": utc_isoformat_z(),
        "status"    : "isolated",
        "mock"      : True,
    })

    with open(_ISOLATION_LOG, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
