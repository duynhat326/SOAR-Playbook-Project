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

import actions.block_ip as block_ip_action
import actions.isolate_host as isolate_host_action
import actions.kill_process as kill_process_action
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
        self._pending_requests.append(request)

    def flush(self) -> None:
        while self._pending_requests:
            request = self._pending_requests.pop(0)
            self._repository.enqueue_action_job(
                request,
                available_at=utc_now(),
                max_attempts=self._settings.max_attempts,
            )


class AsyncRemediationWorker:
    def __init__(
        self,
        repository: IncidentRepositoryProtocol,
        *,
        queue_name: Optional[str] = None,
        worker_id: Optional[str] = None,
        settings: Optional[RemediationQueueSettings] = None,
    ) -> None:
        self._repository = repository
        self._queue_name = queue_name
        self._settings = settings or RemediationQueueSettings.from_env()
        self._worker_id = worker_id or f"worker-{socket.gethostname().lower()}"

    @property
    def worker_id(self) -> str:
        return self._worker_id

    def run_once(self) -> bool:
        job = self._repository.claim_next_action_job(
            worker_id=self._worker_id,
            queue_name=self._queue_name,
        )
        if job is None:
            return False

        request = QueuedActionRequest.model_validate(_coerce_json_payload(job.get("request_json")))
        correlation_id = str(job["correlation_id"])
        attempt_count = int(job.get("attempt_count") or 0)
        max_attempts = int(job.get("max_attempts") or self._settings.max_attempts)

        try:
            result = execute_queued_action(request, operator=self._worker_id)
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
            self._repository.complete_action_job(correlation_id, finalized)
            logger.info(
                "[RemediationWorker] Completed {} (correlation_id={}, attempt={}/{})",
                request.action.value,
                correlation_id,
                attempt_count,
                max_attempts,
            )
        except Exception as exc:
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
            else:
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
) -> ActionResult:
    payload = request.payload
    alert_id = str(payload.get("alert_id") or "")
    hostname = str(payload.get("hostname") or "")

    if request.action == ResponseAction.ISOLATE_HOST:
        return isolate_host_action.execute(
            hostname=hostname,
            alert_id=alert_id,
            reason=str(payload.get("reason") or "Malicious activity detected"),
            operator=operator,
        )

    if request.action == ResponseAction.KILL_PROCESS:
        return kill_process_action.execute(
            process_name=str(payload.get("process_name") or ""),
            hostname=hostname,
            alert_id=alert_id,
            command_line=str(payload.get("command_line") or ""),
            reason=str(payload.get("reason") or "Dangerous process detected"),
            operator=operator,
        )

    if request.action == ResponseAction.BLOCK_IP:
        return block_ip_action.execute(
            ip_address=str(payload.get("ip_address") or ""),
            alert_id=alert_id,
            hostname=hostname,
            reason=str(payload.get("reason") or "C2 IP detected"),
            confidence=int(payload.get("confidence") or 0),
            operator=operator,
        )

    if request.action == ResponseAction.ESCALATE:
        reason = str(payload.get("reason") or "Manual SOC review required")
        return ActionResult(
            action=ResponseAction.ESCALATE,
            status="succeeded",
            executed_at=utc_now(),
            details=f"Escalation acknowledged by async worker. {reason}",
            operator=operator,
        )

    raise ValueError(f"Unsupported queued action '{request.action.value}'")


def build_async_worker(
    *,
    db_target: Optional[str | Path] = None,
    queue_name: Optional[str] = None,
    worker_id: Optional[str] = None,
) -> AsyncRemediationWorker:
    repository = create_incident_repository(db_target)
    return AsyncRemediationWorker(
        repository,
        queue_name=queue_name,
        worker_id=worker_id,
    )


def _coerce_json_payload(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    return {} if value is None else json.loads(value)
