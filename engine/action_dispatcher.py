from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from time import perf_counter
from typing import Callable, Optional, Protocol, Sequence

from loguru import logger

from engine.policy_loader import PolicyCorrelationField, PolicyExecutionConfig, PolicyExecutionMode
from observability.runtime import observability
from schemas.alert import (
    ActionApprovalState,
    ActionResult,
    AssetCriticality,
    CorrelationHook,
    EnrichedAlert,
    PolicyExecutionTrace,
    QueuedActionRequest,
    ResponseAction,
    Severity,
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


@dataclass(frozen=True)
class ApprovalDecision:
    requires_approval: bool
    reason: str | None = None
    approval_due_at: object | None = None
    approval_escalates_at: object | None = None
    escalation_targets: tuple[str, ...] = ()


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
        self._legacy_approval_required_actions = self._load_approval_required_actions()

    def dispatch(
        self,
        actions: Sequence[ResponseAction],
        enriched: EnrichedAlert,
    ) -> DispatchOutcome:
        with observability.span(
            "dispatch.actions",
            configured_mode=self._config.mode.value,
            queue_name=self._config.queue.queue_name,
            action_count=len(actions),
        ):
            observability.metrics.incr(
                "dispatch.requests_total",
                mode=self._config.mode.value,
            )
            if self._config.mode == PolicyExecutionMode.DRY_RUN:
                observability.metrics.incr("dispatch.dry_run_total")
                return DispatchOutcome(
                    action_results=[],
                    execution_trace=PolicyExecutionTrace(
                        configured_mode=self._config.mode.value,
                        effective_mode=self._config.mode.value,
                    ),
                )

            requests = [self._build_queue_request(action, enriched) for action in actions]
            approval_requests = [request for request in requests if request.requires_approval]
            immediate_actions = [request.action for request in requests if not request.requires_approval]

            if self._config.mode == PolicyExecutionMode.SYNC:
                with observability.span("dispatch.sync_path", approval_count=len(approval_requests)):
                    action_results = self._execute_sync(immediate_actions, enriched)
                    approval_results, fallback_reason = self._dispatch_approval_requests(approval_requests)
                effective_mode = (
                    "sync_with_approval"
                    if approval_requests and self._queue_publisher is not None
                    else (
                        "sync_approval_unavailable"
                        if approval_requests
                        else self._config.mode.value
                    )
                )
                observability.metrics.incr(
                    "dispatch.sync_total",
                    effective_mode=effective_mode,
                )
                return DispatchOutcome(
                    action_results=[*action_results, *approval_results],
                    execution_trace=PolicyExecutionTrace(
                        configured_mode=self._config.mode.value,
                        effective_mode=effective_mode,
                        queue_name=self._config.queue.queue_name if approval_requests else None,
                        fallback_reason=fallback_reason,
                        queued_actions=approval_requests,
                    ),
                )

            if not requests:
                observability.metrics.incr("dispatch.empty_total", mode=self._config.mode.value)
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
                    observability.metrics.incr("dispatch.fallback_total", fallback="sync_fallback")
                    return DispatchOutcome(
                        action_results=[
                            *self._execute_sync(immediate_actions, enriched),
                            *self._build_manual_approval_results(
                                approval_requests,
                                dispatched=False,
                                queue_available=False,
                            ),
                        ],
                        execution_trace=PolicyExecutionTrace(
                            configured_mode=self._config.mode.value,
                            effective_mode="sync_fallback",
                            queue_name=self._config.queue.queue_name,
                            fallback_reason=fallback_reason,
                            queued_actions=requests,
                        ),
                    )

                logger.warning("[PolicyEngine] {} Actions will remain undispatched.", fallback_reason)
                observability.metrics.incr("dispatch.fallback_total", fallback="queued_unavailable")
                skipped_results = [
                    self._build_unavailable_queue_result(request)
                    for request in requests
                ]
                return DispatchOutcome(
                    action_results=skipped_results,
                    execution_trace=PolicyExecutionTrace(
                        configured_mode=self._config.mode.value,
                        effective_mode="queued_unavailable",
                        queue_name=self._config.queue.queue_name,
                        fallback_reason=fallback_reason,
                        queued_actions=requests,
                    ),
                )

            with observability.span("dispatch.queue_publish", queued_count=len(requests)):
                for request in requests:
                    self._queue_publisher.publish(request)
                    observability.metrics.incr(
                        "dispatch.queued_total",
                        action=request.action.value,
                        requires_approval=request.requires_approval,
                    )

            return DispatchOutcome(
                action_results=[
                    self._build_dispatched_queue_result(request)
                    for request in requests
                ],
                execution_trace=PolicyExecutionTrace(
                    configured_mode=self._config.mode.value,
                    effective_mode=self._config.mode.value,
                    queue_name=self._config.queue.queue_name,
                    queued_actions=requests,
                ),
            )

    def _execute_sync(
        self,
        actions: Sequence[ResponseAction],
        enriched: EnrichedAlert,
    ) -> list[ActionResult]:
        action_results: list[ActionResult] = []
        for action in actions:
            started = perf_counter()
            with observability.span("dispatch.sync_action", action=action.value):
                result = self._action_executor(action, enriched)
            elapsed_ms = (perf_counter() - started) * 1000
            observability.metrics.observe(
                "dispatch.action_latency_ms",
                elapsed_ms,
                mode="sync",
                action=action.value,
            )
            if result is not None:
                observability.metrics.incr(
                    "dispatch.action_results_total",
                    mode="sync",
                    action=action.value,
                    status=result.status,
                )
                action_results.append(result)
        return action_results

    def _build_queue_request(
        self,
        action: ResponseAction,
        enriched: EnrichedAlert,
    ) -> QueuedActionRequest:
        alert = enriched.original_alert
        correlation_root = f"{self._config.queue.correlation_prefix}:{alert.alert_id}:{action.value}"
        requested_at = utc_now()
        approval = self._approval_decision(action, enriched, requested_at=requested_at)
        return QueuedActionRequest(
            action=action,
            queue_name=self._config.queue.queue_name,
            correlation_id=correlation_root,
            deduplication_key=correlation_root,
            correlation_hooks=self._build_correlation_hooks(enriched),
            payload=self._build_payload(action, enriched),
            requires_approval=approval.requires_approval,
            approval_state=(
                ActionApprovalState.PENDING
                if approval.requires_approval
                else "not_required"
            ),
            approval_reason=approval.reason,
            approval_due_at=approval.approval_due_at,
            approval_escalates_at=approval.approval_escalates_at,
            escalation_targets=list(approval.escalation_targets),
            requested_at=requested_at,
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

    def _dispatch_approval_requests(
        self,
        approval_requests: Sequence[QueuedActionRequest],
    ) -> tuple[list[ActionResult], str | None]:
        if not approval_requests:
            return [], None
        if self._queue_publisher is None:
            observability.metrics.incr(
                "dispatch.approval_unavailable_total",
                queue_name=self._config.queue.queue_name,
            )
            return (
                self._build_manual_approval_results(
                    approval_requests,
                    dispatched=False,
                    queue_available=False,
                ),
                "Approval was required but no queue publisher is registered.",
            )
        with observability.span("dispatch.approval_queue_publish", approval_count=len(approval_requests)):
            for request in approval_requests:
                self._queue_publisher.publish(request)
                observability.metrics.incr(
                    "dispatch.approval_queued_total",
                    action=request.action.value,
                    queue_name=request.queue_name,
                )
        return (
            self._build_manual_approval_results(
                approval_requests,
                dispatched=True,
                queue_available=True,
            ),
            None,
        )

    def _approval_decision(
        self,
        action: ResponseAction,
        enriched: EnrichedAlert,
        *,
        requested_at,
    ) -> ApprovalDecision:
        for rule in self._config.approval.rules:
            if rule.action != action:
                continue
            if rule.risk_levels:
                try:
                    current_risk = Severity(str(enriched.risk_level).strip().lower())
                except ValueError:
                    current_risk = None
                if current_risk not in rule.risk_levels:
                    continue
            if rule.asset_criticalities and enriched.asset_criticality not in rule.asset_criticalities:
                continue
            due_at, escalates_at, escalation_targets = self._approval_schedule(
                requested_at=requested_at,
                sla_minutes=rule.sla_minutes,
                escalation_minutes=rule.escalation_minutes,
                escalation_targets=rule.escalation_targets,
            )
            return ApprovalDecision(
                requires_approval=True,
                reason=rule.reason or self._approval_reason(action, enriched),
                approval_due_at=due_at,
                approval_escalates_at=escalates_at,
                escalation_targets=escalation_targets,
            )

        if action in self._legacy_approval_required_actions:
            due_at, escalates_at, escalation_targets = self._approval_schedule(requested_at=requested_at)
            return ApprovalDecision(
                requires_approval=True,
                reason=self._approval_reason(action, enriched),
                approval_due_at=due_at,
                approval_escalates_at=escalates_at,
                escalation_targets=escalation_targets,
            )
        return ApprovalDecision(requires_approval=False)

    def _approval_schedule(
        self,
        *,
        requested_at,
        sla_minutes: int | None = None,
        escalation_minutes: int | None = None,
        escalation_targets: Sequence[str] | None = None,
    ) -> tuple[object, object, tuple[str, ...]]:
        approval_config = self._config.approval
        resolved_sla_minutes = sla_minutes or approval_config.default_sla_minutes
        resolved_escalation_minutes = escalation_minutes or approval_config.default_escalation_minutes
        resolved_targets = tuple(escalation_targets or approval_config.default_escalation_targets)
        approval_due_at = requested_at + timedelta(minutes=resolved_sla_minutes)
        approval_escalates_at = requested_at + timedelta(minutes=resolved_escalation_minutes)
        return approval_due_at, approval_escalates_at, resolved_targets

    def _build_manual_approval_results(
        self,
        approval_requests: Sequence[QueuedActionRequest],
        *,
        dispatched: bool,
        queue_available: bool,
    ) -> list[ActionResult]:
        if not approval_requests:
            return []
        if dispatched:
            return [self._build_dispatched_queue_result(request) for request in approval_requests]

        return [
            ActionResult(
                action=request.action,
                status="skipped" if not queue_available else "waiting_approval",
                executed_at=utc_now(),
                correlation_id=request.correlation_id,
                requires_approval=request.requires_approval,
                approval_state=request.approval_state,
                approval_reason=request.approval_reason,
                approval_due_at=request.approval_due_at,
                approval_escalates_at=request.approval_escalates_at,
                escalation_targets=request.escalation_targets,
                details=(
                    f"Approval required for '{request.action.value}', but queue publisher is unavailable "
                    f"for '{request.queue_name}'."
                ),
            )
            for request in approval_requests
        ]

    @staticmethod
    def _build_dispatched_queue_result(request: QueuedActionRequest) -> ActionResult:
        return ActionResult(
            action=request.action,
            status="waiting_approval" if request.requires_approval else "queued",
            executed_at=utc_now(),
            correlation_id=request.correlation_id,
            requires_approval=request.requires_approval,
            approval_state=request.approval_state,
            approval_reason=request.approval_reason,
            approval_due_at=request.approval_due_at,
            approval_escalates_at=request.approval_escalates_at,
            escalation_targets=request.escalation_targets,
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

    @staticmethod
    def _build_unavailable_queue_result(request: QueuedActionRequest) -> ActionResult:
        if request.requires_approval:
            details = (
                f"Approval required for '{request.action.value}', but queue dispatch is unavailable "
                f"for '{request.queue_name}'."
            )
        else:
            details = (
                f"Queue dispatch not available for '{request.action.value}' in "
                f"queue '{request.queue_name}'."
            )
        return ActionResult(
            action=request.action,
            status="skipped",
            executed_at=utc_now(),
            correlation_id=request.correlation_id,
            requires_approval=request.requires_approval,
            approval_state=request.approval_state,
            approval_reason=request.approval_reason,
            approval_due_at=request.approval_due_at,
            approval_escalates_at=request.approval_escalates_at,
            escalation_targets=request.escalation_targets,
            details=details,
        )

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
        if action == ResponseAction.ESCALATE and enriched.asset_criticality == AssetCriticality.CRITICAL:
            return (
                f"Escalation for critical asset '{enriched.original_alert.hostname}' requires analyst confirmation."
            )
        return None
