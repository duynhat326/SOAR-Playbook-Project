from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Sequence

from loguru import logger

from engine.policy_loader import PolicyCorrelationField, PolicyExecutionConfig, PolicyExecutionMode
from schemas.alert import (
    ActionResult,
    CorrelationHook,
    EnrichedAlert,
    PolicyExecutionTrace,
    QueuedActionRequest,
    ResponseAction,
)
from time_utils import utc_now

ActionExecutor = Callable[[ResponseAction, EnrichedAlert], Optional[ActionResult]]


class QueuePublisher(Protocol):
    def publish(self, request: QueuedActionRequest) -> None:
        """Publish a queued action request to the backing queue."""


@dataclass
class DispatchOutcome:
    action_results: list[ActionResult]
    execution_trace: PolicyExecutionTrace


class ActionDispatcher:
    """Dispatch remediation actions either synchronously or through a queue boundary."""

    def __init__(
        self,
        *,
        config: PolicyExecutionConfig,
        action_executor: ActionExecutor,
        queue_publisher: QueuePublisher | None = None,
    ) -> None:
        self._config = config
        self._action_executor = action_executor
        self._queue_publisher = queue_publisher
        self._approval_required_actions = self._load_approval_required_actions()

    def dispatch(
        self,
        actions: Sequence[ResponseAction],
        enriched: EnrichedAlert,
    ) -> DispatchOutcome:
        if self._config.mode == PolicyExecutionMode.SYNC:
            return DispatchOutcome(
                action_results=self._execute_sync(actions, enriched),
                execution_trace=PolicyExecutionTrace(
                    configured_mode=self._config.mode.value,
                    effective_mode=self._config.mode.value,
                ),
            )

        queued_actions = [self._build_queue_request(action, enriched) for action in actions]
        if not queued_actions:
            return DispatchOutcome(
                action_results=[],
                execution_trace=PolicyExecutionTrace(
                    configured_mode=self._config.mode.value,
                    effective_mode=self._config.mode.value,
                    queue_name=self._config.queue.queue_name,
                ),
            )

        if self._queue_publisher is None:
            fallback_reason = "Queue mode was configured but no queue publisher is registered."
            if self._config.queue.fallback_to_sync:
                logger.warning(
                    "[PolicyEngine] {} Falling back to synchronous execution.",
                    fallback_reason,
                )
                return DispatchOutcome(
                    action_results=self._execute_sync(actions, enriched),
                    execution_trace=PolicyExecutionTrace(
                        configured_mode=self._config.mode.value,
                        effective_mode="sync_fallback",
                        queue_name=self._config.queue.queue_name,
                        fallback_reason=fallback_reason,
                        queued_actions=queued_actions,
                    ),
                )

            logger.warning("[PolicyEngine] {} Actions will remain undispatched.", fallback_reason)
            skipped_results = [
                ActionResult(
                    action=action,
                    status="skipped",
                    executed_at=utc_now(),
                    details=(
                        f"Queue dispatch not available for '{action.value}' in "
                        f"queue '{self._config.queue.queue_name}'."
                    ),
                )
                for action in actions
            ]
            return DispatchOutcome(
                action_results=skipped_results,
                execution_trace=PolicyExecutionTrace(
                    configured_mode=self._config.mode.value,
                    effective_mode="queued_unavailable",
                    queue_name=self._config.queue.queue_name,
                    fallback_reason=fallback_reason,
                    queued_actions=queued_actions,
                ),
            )

        for request in queued_actions:
            self._queue_publisher.publish(request)

        return DispatchOutcome(
            action_results=[
                ActionResult(
                    action=request.action,
                    status="waiting_approval" if request.requires_approval else "queued",
                    executed_at=utc_now(),
                    correlation_id=request.correlation_id,
                    requires_approval=request.requires_approval,
                    approval_state=request.approval_state,
                    approval_reason=request.approval_reason,
                    details=(
                        (
                            f"Queued '{request.action.value}' to '{request.queue_name}' "
                            f"pending analyst approval (correlation_id={request.correlation_id})."
                        )
                        if request.requires_approval
                        else (
                            f"Queued '{request.action.value}' to '{request.queue_name}' "
                            f"(correlation_id={request.correlation_id})."
                        )
                    ),
                )
                for request in queued_actions
            ],
            execution_trace=PolicyExecutionTrace(
                configured_mode=self._config.mode.value,
                effective_mode=self._config.mode.value,
                queue_name=self._config.queue.queue_name,
                queued_actions=queued_actions,
            ),
        )

    def _execute_sync(
        self,
        actions: Sequence[ResponseAction],
        enriched: EnrichedAlert,
    ) -> list[ActionResult]:
        action_results: list[ActionResult] = []
        for action in actions:
            result = self._action_executor(action, enriched)
            if result is not None:
                action_results.append(result)
        return action_results

    def _build_queue_request(
        self,
        action: ResponseAction,
        enriched: EnrichedAlert,
    ) -> QueuedActionRequest:
        alert = enriched.original_alert
        correlation_root = f"{self._config.queue.correlation_prefix}:{alert.alert_id}:{action.value}"
        return QueuedActionRequest(
            action=action,
            queue_name=self._config.queue.queue_name,
            correlation_id=correlation_root,
            deduplication_key=correlation_root,
            correlation_hooks=self._build_correlation_hooks(enriched),
            payload=self._build_payload(action, enriched),
            requires_approval=action in self._approval_required_actions,
            approval_state=(
                "pending"
                if action in self._approval_required_actions
                else "not_required"
            ),
            approval_reason=self._approval_reason(action, enriched),
        )

    def _build_correlation_hooks(
        self,
        enriched: EnrichedAlert,
    ) -> list[CorrelationHook]:
        alert = enriched.original_alert
        hook_values = {
            PolicyCorrelationField.HOSTNAME: alert.hostname,
            PolicyCorrelationField.USERNAME: alert.username,
            PolicyCorrelationField.FILE_HASH: alert.file_hash,
            PolicyCorrelationField.DESTINATION_IP: alert.destination_ip,
        }
        return [
            CorrelationHook(field=field.value, value=hook_values[field])
            for field in self._config.queue.correlation_fields
        ]

    @staticmethod
    def _build_payload(
        action: ResponseAction,
        enriched: EnrichedAlert,
    ) -> dict[str, object]:
        alert = enriched.original_alert
        payload: dict[str, object] = {
            "alert_id": alert.alert_id,
            "hostname": alert.hostname,
            "risk_level": enriched.risk_level,
            "risk_score": enriched.risk_score,
            "action": action.value,
        }

        if action == ResponseAction.ISOLATE_HOST:
            payload["reason"] = (
                f"Hash MALICIOUS: {enriched.hash_enrichment.threat_name or 'Unknown'}"
                if enriched.hash_enrichment
                else "Malicious hash detected"
            )
        elif action == ResponseAction.KILL_PROCESS:
            payload["process_name"] = alert.process_name
            payload["command_line"] = alert.command_line
            payload["reason"] = f"Process '{alert.process_name}' in dangerous process blacklist"
        elif action == ResponseAction.BLOCK_IP:
            payload["ip_address"] = alert.destination_ip
            payload["confidence"] = (
                enriched.ip_enrichment.confidence_score
                if enriched.ip_enrichment
                else 0
            )
            payload["reason"] = "C2 server detected in threat intel"
        elif action == ResponseAction.ESCALATE:
            payload["reason"] = (
                f"Host '{alert.hostname}' marked as critical asset requires manual review"
            )

        return payload

    @staticmethod
    def _load_approval_required_actions() -> set[ResponseAction]:
        raw_actions = os.getenv(
            "SOAR_APPROVAL_REQUIRED_ACTIONS",
            "",
        )
        actions: set[ResponseAction] = set()
        for raw_action in raw_actions.split(","):
            candidate = raw_action.strip().lower()
            if not candidate:
                continue
            try:
                actions.add(ResponseAction(candidate))
            except ValueError:
                logger.warning("[PolicyEngine] Ignoring unknown approval-gated action '{}'.", candidate)
        return actions

    @staticmethod
    def _approval_reason(
        action: ResponseAction,
        enriched: EnrichedAlert,
    ) -> str | None:
        if action == ResponseAction.ISOLATE_HOST:
            return (
                f"Host isolation impacts endpoint connectivity on '{enriched.original_alert.hostname}'."
            )
        if action == ResponseAction.KILL_PROCESS:
            return (
                f"Process termination may disrupt user workflow for '{enriched.original_alert.process_name}'."
            )
        if action == ResponseAction.BLOCK_IP:
            return f"Blocking '{enriched.original_alert.destination_ip}' changes outbound network policy."
        return None
