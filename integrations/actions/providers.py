from __future__ import annotations

import os

import actions.block_ip as block_ip_action
import actions.isolate_host as isolate_host_action
import actions.kill_process as kill_process_action
import actions.notify_soc as notify_soc_action
from loguru import logger

from env_utils import load_local_env_files
from integrations.contracts import ActionConnector
from schemas.alert import ActionResult, ResponseAction
from time_utils import utc_now


class LocalActionConnector(ActionConnector):
    """Default connector that delegates to the repo's local mock action modules."""

    def isolate_host(
        self,
        *,
        hostname: str,
        alert_id: str,
        reason: str,
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        return isolate_host_action.execute(
            hostname=hostname,
            alert_id=alert_id,
            reason=reason,
            operator=operator,
        )

    def kill_process(
        self,
        *,
        process_name: str,
        hostname: str,
        alert_id: str,
        command_line: str = "",
        reason: str = "Dangerous process detected",
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        return kill_process_action.execute(
            process_name=process_name,
            hostname=hostname,
            alert_id=alert_id,
            command_line=command_line,
            reason=reason,
            operator=operator,
        )

    def block_ip(
        self,
        *,
        ip_address: str,
        alert_id: str,
        hostname: str = "",
        reason: str = "C2 IP detected",
        confidence: int = 0,
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        return block_ip_action.execute(
            ip_address=ip_address,
            alert_id=alert_id,
            hostname=hostname,
            reason=reason,
            confidence=confidence,
            operator=operator,
        )

    def escalate(
        self,
        *,
        hostname: str,
        reason: str,
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        logger.warning(
            "[ACTION] ⬆️  ESCALATE: Host '{}' (critical asset) — Alert escalated to HIGH priority for manual SOC review",
            hostname,
        )
        return ActionResult(
            action=ResponseAction.ESCALATE,
            status="succeeded",
            executed_at=utc_now(),
            details=(
                f"Alert escalated: Host '{hostname}' là critical asset. "
                f"Incident priority nâng lên HIGH. "
                f"SOC Lead được notify để xử lý thủ công. Reason: {reason}"
            ),
            operator=operator,
        )

    def notify_soc(
        self,
        *,
        alert_id: str,
        hostname: str,
        risk_score: float,
        risk_level: str,
        triggered_actions,
        ticket_id: str = "",
        channel: str = "#soc-alerts",
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        return notify_soc_action.execute(
            alert_id=alert_id,
            hostname=hostname,
            risk_score=risk_score,
            risk_level=risk_level,
            triggered_actions=list(triggered_actions),
            ticket_id=ticket_id,
            channel=channel,
            operator=operator,
        )


def build_action_connector_from_env() -> ActionConnector:
    load_local_env_files()
    provider = os.getenv("SOAR_ACTION_PROVIDER", "local").strip().lower()
    if provider in {"", "local", "mock"}:
        return LocalActionConnector()
    raise RuntimeError(f"Unsupported action connector '{provider}'.")
