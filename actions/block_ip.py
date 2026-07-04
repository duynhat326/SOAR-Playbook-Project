"""
actions/block_ip.py
===================
Mock action: Block IP address trên firewall/proxy.

Trong thực tế:
  - Gọi Palo Alto API để thêm IP vào Dynamic Address Group
  - Hoặc gọi Cisco FMC để tạo Host Object + gắn vào Block policy
  - Hoặc update EDR network containment rules

Ở đây: log + ghi vào block list file (mock firewall state).
"""

import json
from pathlib import Path

from loguru import logger

from schemas.alert import ActionResult, ResponseAction
from time_utils import utc_isoformat_z, utc_now

_BLOCK_LOG = Path("output") / "blocked_ips.json"


def execute(
    ip_address: str,
    alert_id: str,
    hostname: str = "",
    reason: str = "C2 IP detected",
    confidence: int = 0,
    operator: str = "SOAR_AUTO",
) -> ActionResult:
    """
    Block IP trên firewall/proxy (mock).

    Args:
        ip_address : IP cần block
        alert_id   : Alert ID để trace
        hostname   : Host đã communicate với IP này
        reason     : Lý do block
        confidence : Confidence score từ threat intel (0–100)
        operator   : Ai ra lệnh

    Returns:
        ActionResult
    """
    logger.warning(
        f"[ACTION] 🚫 BLOCK IP: '{ip_address}' | "
        f"alert={alert_id[:8]} | confidence={confidence} | reason={reason}"
    )

    _record_block(ip_address, alert_id, hostname, reason, confidence, operator)

    details = (
        f"IP '{ip_address}' đã được thêm vào BLOCK LIST trên firewall. "
        f"Confidence score: {confidence}/100. "
        f"Host liên quan: {hostname or 'N/A'}. "
        f"Operator: {operator}. Reason: {reason}."
    )

    logger.success(f"[ACTION] ✓ IP '{ip_address}' blocked on firewall (mock)")

    return ActionResult(
        action=ResponseAction.BLOCK_IP,
        status="succeeded",
        executed_at=utc_now(),
        details=details,
    )


def _record_block(
    ip_address: str,
    alert_id: str,
    hostname: str,
    reason: str,
    confidence: int,
    operator: str,
) -> None:
    """Ghi block event vào file JSON (mock firewall block list)."""
    _BLOCK_LOG.parent.mkdir(parents=True, exist_ok=True)

    existing: list = []
    if _BLOCK_LOG.exists():
        try:
            with open(_BLOCK_LOG, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []

    # Kiểm tra duplicate — không block cùng IP 2 lần
    already_blocked = any(r.get("ip_address") == ip_address for r in existing)
    if already_blocked:
        logger.info(f"[ACTION] IP '{ip_address}' already in block list, skipping duplicate")

    existing.append({
        "ip_address"  : ip_address,
        "alert_id"    : alert_id,
        "hostname"    : hostname,
        "reason"      : reason,
        "confidence"  : confidence,
        "operator"    : operator,
        "blocked_at"  : utc_isoformat_z(),
        "duplicate"   : already_blocked,
        "mock"        : True,
    })

    with open(_BLOCK_LOG, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
