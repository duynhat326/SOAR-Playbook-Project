from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from integrations.contracts import ActionConnector
from integrations.registry import build_default_integrations
from observability import observability, wrap_action_connector
from schemas.alert import ActionExecutionStatus, ActionResult, QueuedActionRequest, ResponseAction
from storage.incident_repository import IncidentRepositoryProtocol, create_incident_repository
from time_utils import utc_now


@dataclass(frozen=True)
class RemediationQueueSettings:
    max_attempts: int = 3
    poll_interval_seconds: float = 1.5
    base_retry_delay_seconds: float = 2.0
    max_retry_delay_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "RemediationQueueSettings":
        return cls(
            max_attempts=max(1, int(os.getenv("SOAR_REMEDIATION_MAX_ATTEMPTS", "3"))),
            poll_interval_seconds=max(0.2, float(os.getenv("SOAR_REMEDIATION_POLL_INTERVAL_SEC", "1.5"))),
            base_retry_delay_seconds=max(0.5, float(os.getenv("SOAR_REMEDIATION_RETRY_BASE_SEC", "2"))),
            max_retry_delay_seconds=max(1.0, float(os.getenv("SOAR_REMEDIATION_RETRY_MAX_SEC", "30"))),
        )


class RepositoryQueuePublisher:
    def __init__(
        self,
        repository: IncidentRepositoryProtocol,
        *,
        settings: Optional[RemediationQueueSettings] = None,
    ) -> None:
        self._repository = repository
        self._settings = settings or RemediationQueueSettings.from_env()
        self._pending_requests: list[QueuedActionRequest] = []

    def publish(self, request: QueuedActionRequest) -> None:
        observability.metrics.incr(
            "queue.publish_requested_total",
            queue_name=request.queue_name,
            action=request.action.value,
        )
        self._pending_requests.append(request)

    def flush(self) -> None:
        while self._pending_requests:
            request = self._pending_requests.pop(0)
            with observability.span(
                "queue.enqueue",
                queue_name=request.queue_name,
                action=request.action.value,
                correlation_id=request.correlation_id,
            ):
                observability.emit_event(
                    "info",
                    "queue.enqueued",
                    message=f"Queued {request.action.value}",
                    queue_name=request.queue_name,
                    correlation_id=request.correlation_id,
                    alert_id=request.payload.get("alert_id"),
                )
            self._repository.enqueue_action_job(
                request,
                available_at=utc_now(),
                max_attempts=self._settings.max_attempts,
            )
            observability.metrics.incr(
                "queue.enqueued_total",
                queue_name=request.queue_name,
                action=request.action.value,
            )


class AsyncRemediationWorker:
    def __init__(
        self,
        repository: IncidentRepositoryProtocol,
        *,
        queue_name: Optional[str] = None,
        worker_id: Optional[str] = None,
        settings: Optional[RemediationQueueSettings] = None,
        action_connector: ActionConnector | None = None,
    ) -> None:
        self._repository = repository
        self._queue_name = queue_name
        self._settings = settings or RemediationQueueSettings.from_env()
        self._worker_id = worker_id or f"worker-{socket.gethostname().lower()}"
        self._action_connector = wrap_action_connector(action_connector or build_default_integrations().action)

    @property
    def worker_id(self) -> str:
        return self._worker_id

    def run_once(self) -> bool:
        with observability.trace(
            "worker.run_once",
            worker_id=self._worker_id,
            queue_name=self._queue_name or "<all>",
        ):
            with observability.span("worker.claim_job"):
                job = self._repository.claim_next_action_job(
                    worker_id=self._worker_id,
                    queue_name=self._queue_name,
                )
            if job is None:
                observability.metrics.incr("queue.empty_polls_total", worker_id=self._worker_id)
                return False

            request = QueuedActionRequest.model_validate(_coerce_json_payload(job.get("request_json")))
            correlation_id = str(job["correlation_id"])
            attempt_count = int(job.get("attempt_count") or 0)
            max_attempts = int(job.get("max_attempts") or self._settings.max_attempts)

            with observability.bind_context(
                correlation_id=correlation_id,
                alert_id=request.payload.get("alert_id"),
                action=request.action.value,
            ):
                try:
                    with observability.span("worker.execute_action", attempt=attempt_count):
                        result = execute_queued_action(
                            request,
                            operator=self._worker_id,
                            action_connector=self._action_connector,
                        )
                    finalized = result.model_copy(
                        update={
                            "status": ActionExecutionStatus.SUCCEEDED,
                            "correlation_id": correlation_id,
                            "attempt_count": attempt_count,
                            "updated_at": utc_now(),
                            "requires_approval": request.requires_approval,
                            "approval_state": request.approval_state,
                            "approval_reason": request.approval_reason,
                            "approved_by": request.approved_by,
                            "approved_at": request.approved_at,
                            "operator": self._worker_id,
                        }
                    )
                    with observability.span("worker.complete_job"):
                        self._repository.complete_action_job(correlation_id, finalized)
                    observability.metrics.incr(
                        "queue.completed_total",
                        worker_id=self._worker_id,
                        action=request.action.value,
                    )
                    logger.info(
                        "[RemediationWorker] Completed {} (correlation_id={}, attempt={}/{})",
                        request.action.value,
                        correlation_id,
                        attempt_count,
                        max_attempts,
                    )
                except Exception as exc:
                    observability.emit_event(
                        "error",
                        "queue.execution_failed",
                        message=f"Queued action failed: {request.action.value}",
                        correlation_id=correlation_id,
                        worker_id=self._worker_id,
                        error=exc.__class__.__name__,
                    )
                    logger.exception(
                        "[RemediationWorker] Failed {} (correlation_id={}, attempt={}/{})",
                        request.action.value,
                        correlation_id,
                        attempt_count,
                        max_attempts,
                    )
                    error_text = str(exc) or exc.__class__.__name__
                    if attempt_count < max_attempts:
                        retry_delay = self._retry_delay_seconds(attempt_count)
                        next_available_at = utc_now() + timedelta(seconds=retry_delay)
                        with observability.span("worker.retry_job", retry_delay_seconds=retry_delay):
                            self._repository.retry_action_job(
                                correlation_id,
                                ActionResult(
                                    action=request.action,
                                    status="queued",
                                    executed_at=utc_now(),
                                    details=(
                                        f"Retry scheduled for '{request.action.value}' after worker failure "
                                        f"(attempt {attempt_count}/{max_attempts}): {error_text}"
                                    ),
                                    correlation_id=correlation_id,
                                    attempt_count=attempt_count,
                                    updated_at=utc_now(),
                                    requires_approval=request.requires_approval,
                                    approval_state=request.approval_state,
                                    approval_reason=request.approval_reason,
                                    approved_by=request.approved_by,
                                    approved_at=request.approved_at,
                                    operator=self._worker_id,
                                ),
                                next_available_at=next_available_at,
                                last_error=error_text,
                            )
                        observability.metrics.incr(
                            "queue.retry_scheduled_total",
                            worker_id=self._worker_id,
                            action=request.action.value,
                        )
                    else:
                        with observability.span("worker.dead_letter_job"):
                            self._repository.dead_letter_action_job(
                                correlation_id,
                                ActionResult(
                                    action=request.action,
                                    status="failed",
                                    executed_at=utc_now(),
                                    details=(
                                        f"Action '{request.action.value}' moved to dead-letter after "
                                        f"{attempt_count} attempts: {error_text}"
                                    ),
                                    correlation_id=correlation_id,
                                    attempt_count=attempt_count,
                                    updated_at=utc_now(),
                                    requires_approval=request.requires_approval,
                                    approval_state=request.approval_state,
                                    approval_reason=request.approval_reason,
                                    approved_by=request.approved_by,
                                    approved_at=request.approved_at,
                                    operator=self._worker_id,
                                ),
                                last_error=error_text,
                            )
                        observability.metrics.incr(
                            "queue.dead_lettered_total",
                            worker_id=self._worker_id,
                            action=request.action.value,
                        )

            return True

    def run_forever(self) -> None:
        logger.info(
            "[RemediationWorker] Starting worker_id={} queue_name={}",
            self._worker_id,
            self._queue_name or "<all>",
        )
        while True:
            processed = self.run_once()
            if not processed:
                time.sleep(self._settings.poll_interval_seconds)

    def _retry_delay_seconds(self, attempt_count: int) -> float:
        delay = self._settings.base_retry_delay_seconds * max(1, 2 ** max(attempt_count - 1, 0))
        return min(delay, self._settings.max_retry_delay_seconds)


def execute_queued_action(
    request: QueuedActionRequest,
    *,
    operator: str = "SOAR_WORKER",
    action_connector: ActionConnector | None = None,
) -> ActionResult:
    connector = action_connector or build_default_integrations().action
    payload = request.payload
    alert_id = str(payload.get("alert_id") or "")
    hostname = str(payload.get("hostname") or "")

    if request.action == ResponseAction.ISOLATE_HOST:
        return connector.isolate_host(
            hostname=hostname,
            alert_id=alert_id,
            reason=str(payload.get("reason") or "Malicious activity detected"),
            operator=operator,
        )

    if request.action == ResponseAction.KILL_PROCESS:
        return connector.kill_process(
            process_name=str(payload.get("process_name") or ""),
            hostname=hostname,
            alert_id=alert_id,
            command_line=str(payload.get("command_line") or ""),
            reason=str(payload.get("reason") or "Dangerous process detected"),
            operator=operator,
        )

    if request.action == ResponseAction.BLOCK_IP:
        return connector.block_ip(
            ip_address=str(payload.get("ip_address") or ""),
            alert_id=alert_id,
            hostname=hostname,
            reason=str(payload.get("reason") or "C2 IP detected"),
            confidence=int(payload.get("confidence") or 0),
            operator=operator,
        )

    if request.action == ResponseAction.ESCALATE:
        return connector.escalate(
            hostname=hostname,
            reason=str(payload.get("reason") or "Manual SOC review required"),
            operator=operator,
        )

    raise ValueError(f"Unsupported queued action '{request.action.value}'")


def build_async_worker(
    *,
    db_target: Optional[str | Path] = None,
    queue_name: Optional[str] = None,
    worker_id: Optional[str] = None,
    action_connector: ActionConnector | None = None,
) -> AsyncRemediationWorker:
    repository = create_incident_repository(db_target)
    return AsyncRemediationWorker(
        repository,
        queue_name=queue_name,
        worker_id=worker_id,
        action_connector=action_connector,
    )


def _coerce_json_payload(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    return {} if value is None else json.loads(value)
