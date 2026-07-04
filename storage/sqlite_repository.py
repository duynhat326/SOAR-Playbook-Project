from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from uuid import uuid4

from schemas.alert import (
    ActionApprovalState,
    ActionResult,
    IncidentAuditEvent,
    IncidentCaseStatus,
    IncidentNote,
    QueuedActionRequest,
    ResponseAction,
)
from time_utils import utc_now

if TYPE_CHECKING:
    from services.workflow_service import WorkflowResult

MAX_INCIDENT_LIST_LIMIT = 200

_ACTION_STATUS_ACTIVE = {"queued", "running"}
_ACTION_STATUS_SUCCESS = {"succeeded", "success"}
_ACTION_STATUS_WAITING_APPROVAL = {"waiting_approval"}


class SQLiteIncidentRepository:
    """SQLite-backed persistence for workflow executions, cases, and async remediation jobs."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = Path(db_path or Path("output") / "soar.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._audit_log_path = self._db_path.parent / "audit.log"
        self._init_db()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    username TEXT NOT NULL,
                    process_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    parent_process TEXT NOT NULL,
                    command_line TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detection_name TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL UNIQUE,
                    hostname TEXT NOT NULL,
                    detection_name TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    ticket_id TEXT,
                    status TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    report_path TEXT,
                    case_status TEXT NOT NULL DEFAULT 'new',
                    case_owner TEXT,
                    triggered_actions_json TEXT NOT NULL,
                    policy_reasoning_json TEXT NOT NULL,
                    enriched_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS action_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    details TEXT NOT NULL,
                    correlation_id TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT '',
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL UNIQUE,
                    markdown_path TEXT,
                    html_path TEXT,
                    pdf_path TEXT,
                    markdown_content TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS queue_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    queue_name TEXT NOT NULL,
                    correlation_id TEXT NOT NULL UNIQUE,
                    deduplication_key TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    available_at TEXT NOT NULL,
                    locked_at TEXT,
                    worker_id TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    requires_approval INTEGER NOT NULL DEFAULT 0,
                    approval_state TEXT NOT NULL DEFAULT 'not_required',
                    approval_reason TEXT,
                    approved_by TEXT,
                    approved_at TEXT,
                    approval_comment TEXT,
                    last_error TEXT,
                    dead_lettered_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS case_notes (
                    note_id TEXT PRIMARY KEY,
                    incident_id INTEGER NOT NULL,
                    alert_id TEXT NOT NULL,
                    author TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    incident_id INTEGER NOT NULL,
                    alert_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    message TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS saved_filters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    filters_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            self._ensure_column(conn, "incidents", "case_status", "TEXT NOT NULL DEFAULT 'new'")
            self._ensure_column(conn, "incidents", "case_owner", "TEXT")
            self._ensure_column(conn, "action_results", "correlation_id", "TEXT")
            self._ensure_column(conn, "action_results", "attempt_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "action_results", "updated_at", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "queue_jobs", "requires_approval", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "queue_jobs", "approval_state", "TEXT NOT NULL DEFAULT 'not_required'")
            self._ensure_column(conn, "queue_jobs", "approval_reason", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approved_by", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approved_at", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approval_comment", "TEXT")
            conn.execute(
                "UPDATE action_results SET updated_at = executed_at WHERE updated_at IS NULL OR updated_at = ''"
            )
            conn.execute(
                "UPDATE incidents SET case_status = 'new' WHERE case_status IS NULL OR case_status = ''"
            )
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_incidents_ticket_id
                ON incidents(ticket_id);

                CREATE INDEX IF NOT EXISTS idx_incidents_case_status
                ON incidents(case_status);

                CREATE INDEX IF NOT EXISTS idx_action_results_incident_action
                ON action_results(incident_id, action);

                CREATE INDEX IF NOT EXISTS idx_action_results_correlation
                ON action_results(correlation_id);

                CREATE INDEX IF NOT EXISTS idx_queue_jobs_available
                ON queue_jobs(status, queue_name, available_at);

                CREATE INDEX IF NOT EXISTS idx_case_notes_alert_id
                ON case_notes(alert_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_audit_events_alert_id
                ON audit_events(alert_id, created_at DESC);
                """
            )
            conn.commit()

    def save_workflow_result(self, result: "WorkflowResult") -> int:
        alert = result.alert
        enriched = result.enriched_alert
        response = result.response
        timestamp = self._utc_now()
        incident_status = self._derive_incident_status(response.action_results)

        with self._connect() as conn:
            existing_incident = conn.execute(
                "SELECT id FROM incidents WHERE alert_id = ?",
                (alert.alert_id,),
            ).fetchone()

            conn.execute(
                """
                INSERT INTO alerts (
                    alert_id, hostname, username, process_name, file_path, file_hash,
                    parent_process, command_line, destination_ip, severity,
                    detection_name, received_at, raw_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    username=excluded.username,
                    process_name=excluded.process_name,
                    file_path=excluded.file_path,
                    file_hash=excluded.file_hash,
                    parent_process=excluded.parent_process,
                    command_line=excluded.command_line,
                    destination_ip=excluded.destination_ip,
                    severity=excluded.severity,
                    detection_name=excluded.detection_name,
                    received_at=excluded.received_at,
                    raw_json=excluded.raw_json,
                    updated_at=excluded.updated_at
                """,
                (
                    alert.alert_id,
                    alert.hostname,
                    alert.username,
                    alert.process_name,
                    alert.file_path,
                    alert.file_hash,
                    alert.parent_process,
                    alert.command_line,
                    alert.destination_ip,
                    alert.severity.value,
                    alert.detection_name,
                    alert.received_at.isoformat(),
                    self._dump_model(alert),
                    timestamp,
                    timestamp,
                ),
            )

            conn.execute(
                """
                INSERT INTO incidents (
                    alert_id, hostname, detection_name, risk_score, risk_level,
                    ticket_id, status, completed_at, report_path, case_status,
                    case_owner, triggered_actions_json, policy_reasoning_json,
                    enriched_json, response_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    detection_name=excluded.detection_name,
                    risk_score=excluded.risk_score,
                    risk_level=excluded.risk_level,
                    ticket_id=excluded.ticket_id,
                    status=excluded.status,
                    completed_at=excluded.completed_at,
                    report_path=excluded.report_path,
                    case_status=incidents.case_status,
                    case_owner=incidents.case_owner,
                    triggered_actions_json=excluded.triggered_actions_json,
                    policy_reasoning_json=excluded.policy_reasoning_json,
                    enriched_json=excluded.enriched_json,
                    response_json=excluded.response_json,
                    updated_at=excluded.updated_at
                """,
                (
                    alert.alert_id,
                    alert.hostname,
                    alert.detection_name,
                    enriched.risk_score,
                    enriched.risk_level,
                    response.ticket_id,
                    incident_status,
                    response.completed_at.isoformat(),
                    response.report_path,
                    IncidentCaseStatus.NEW.value,
                    None,
                    json.dumps([action.value for action in response.triggered_actions], ensure_ascii=False),
                    json.dumps(response.policy_reasoning, ensure_ascii=False),
                    self._dump_model(enriched),
                    self._dump_model(response),
                    timestamp,
                    timestamp,
                ),
            )

            incident_id = int(
                conn.execute(
                    "SELECT id FROM incidents WHERE alert_id = ?",
                    (alert.alert_id,),
                ).fetchone()["id"]
            )

            conn.execute(
                "DELETE FROM action_results WHERE incident_id = ?",
                (incident_id,),
            )
            for action_result in response.action_results:
                serialized = action_result.model_dump(mode="json")
                conn.execute(
                    """
                    INSERT INTO action_results (
                        incident_id, action, status, executed_at, details,
                        correlation_id, attempt_count, updated_at, raw_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        action_result.action.value,
                        serialized["status"],
                        action_result.executed_at.isoformat(),
                        action_result.details,
                        action_result.correlation_id,
                        action_result.attempt_count,
                        action_result.updated_at.isoformat(),
                        json.dumps(serialized, ensure_ascii=False),
                        timestamp,
                    ),
                )

            conn.execute(
                "DELETE FROM reports WHERE incident_id = ?",
                (incident_id,),
            )
            if any(
                (
                    result.artifacts.markdown_path,
                    result.artifacts.html_path,
                    result.artifacts.pdf_path,
                    result.artifacts.markdown_content,
                )
            ):
                conn.execute(
                    """
                    INSERT INTO reports (
                        incident_id, markdown_path, html_path, pdf_path,
                        markdown_content, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        self._path_to_str(result.artifacts.markdown_path),
                        self._path_to_str(result.artifacts.html_path),
                        self._path_to_str(result.artifacts.pdf_path),
                        result.artifacts.markdown_content,
                        timestamp,
                        timestamp,
                    ),
                )

            if existing_incident is None or not self._has_audit_events(conn, incident_id):
                self._append_audit_event(
                    conn,
                    incident_id=incident_id,
                    alert_id=alert.alert_id,
                    category="workflow.ingested",
                    actor="soar-workflow",
                    message=(
                        f"Incident processed for host '{alert.hostname}' with risk "
                        f"{enriched.risk_level} ({enriched.risk_score:.1f})."
                    ),
                    payload={
                        "risk_level": enriched.risk_level,
                        "risk_score": enriched.risk_score,
                        "ticket_id": response.ticket_id,
                    },
                )
                for action_result in response.action_results:
                    self._append_audit_event(
                        conn,
                        incident_id=incident_id,
                        alert_id=alert.alert_id,
                        category=f"action.{self._normalize_action_status(action_result.status)}",
                        actor="policy-engine",
                        message=f"Action '{action_result.action.value}' recorded as '{action_result.status}'.",
                        payload=action_result.model_dump(mode="json"),
                    )

            conn.commit()

        return incident_id

    def enqueue_action_job(
        self,
        request: QueuedActionRequest,
        *,
        available_at: datetime,
        max_attempts: int,
    ) -> None:
        alert_id = str(request.payload.get("alert_id") or "")
        if not alert_id:
            raise ValueError("Queued action payload must include alert_id.")

        timestamp = self._utc_now()
        queue_status = (
            "waiting_approval"
            if request.requires_approval and request.approval_state != ActionApprovalState.APPROVED
            else "queued"
        )
        approval_state = request.approval_state.value

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO queue_jobs (
                    alert_id, action, queue_name, correlation_id, deduplication_key,
                    request_json, payload_json, status, available_at, locked_at,
                    worker_id, attempt_count, max_attempts, requires_approval,
                    approval_state, approval_reason, approved_by, approved_at,
                    approval_comment, last_error, dead_lettered_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    alert_id,
                    request.action.value,
                    request.queue_name,
                    request.correlation_id,
                    request.deduplication_key,
                    self._dump_model(request),
                    json.dumps(request.payload, ensure_ascii=False),
                    queue_status,
                    available_at.isoformat(),
                    max_attempts,
                    1 if request.requires_approval else 0,
                    approval_state,
                    request.approval_reason,
                    request.approved_by,
                    request.approved_at.isoformat() if request.approved_at else None,
                    None,
                    timestamp,
                    timestamp,
                ),
            )

            incident_row = conn.execute(
                "SELECT id FROM incidents WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            if incident_row is not None:
                category = "approval.waiting" if queue_status == "waiting_approval" else "queue.enqueued"
                message = (
                    f"Action '{request.action.value}' is waiting for analyst approval."
                    if queue_status == "waiting_approval"
                    else f"Action '{request.action.value}' queued to '{request.queue_name}'."
                )
                self._append_audit_event(
                    conn,
                    incident_id=int(incident_row["id"]),
                    alert_id=alert_id,
                    category=category,
                    actor="queue-publisher",
                    message=message,
                    payload=request.model_dump(mode="json"),
                )
            conn.commit()

    def claim_next_action_job(
        self,
        *,
        worker_id: str,
        queue_name: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        timestamp = self._utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if queue_name:
                row = conn.execute(
                    """
                    SELECT *
                    FROM queue_jobs
                    WHERE status IN ('queued', 'retry_pending')
                      AND queue_name = ?
                      AND available_at <= ?
                    ORDER BY available_at ASC, id ASC
                    LIMIT 1
                    """,
                    (queue_name, timestamp),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT *
                    FROM queue_jobs
                    WHERE status IN ('queued', 'retry_pending')
                      AND available_at <= ?
                    ORDER BY available_at ASC, id ASC
                    LIMIT 1
                    """,
                    (timestamp,),
                ).fetchone()
            if row is None:
                conn.commit()
                return None

            next_attempt = int(row["attempt_count"]) + 1
            conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'running',
                    locked_at = ?,
                    worker_id = ?,
                    attempt_count = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    timestamp,
                    worker_id,
                    next_attempt,
                    timestamp,
                    row["id"],
                ),
            )
            updated = conn.execute(
                "SELECT * FROM queue_jobs WHERE id = ?",
                (row["id"],),
            ).fetchone()
            request = QueuedActionRequest.model_validate(json.loads(row["request_json"])).model_copy(
                update={
                    "requires_approval": bool(row["requires_approval"]),
                    "approval_state": row["approval_state"],
                    "approval_reason": row["approval_reason"],
                    "approved_by": row["approved_by"],
                    "approved_at": self._parse_datetime(row["approved_at"]),
                }
            )
            running_result = ActionResult(
                action=ResponseAction(request.action),
                status="running",
                executed_at=utc_now(),
                details=(
                    f"Worker '{worker_id}' started '{request.action.value}' "
                    f"from queue '{row['queue_name']}'."
                ),
                correlation_id=row["correlation_id"],
                attempt_count=next_attempt,
                updated_at=utc_now(),
                requires_approval=bool(row["requires_approval"]),
                approval_state=row["approval_state"],
                approval_reason=row["approval_reason"],
                approved_by=row["approved_by"],
                approved_at=self._parse_datetime(row["approved_at"]),
                operator=worker_id,
            )
            self._upsert_action_result_for_alert(conn, row["alert_id"], running_result)
            self._append_queue_audit_event(
                conn,
                row=row,
                category="queue.running",
                actor=worker_id,
                message=(
                    f"Worker '{worker_id}' started '{request.action.value}' "
                    f"(attempt {next_attempt}/{int(row['max_attempts'])})."
                ),
                payload=running_result.model_dump(mode="json"),
            )
            conn.commit()
            return dict(updated) if updated is not None else None

    def complete_action_job(
        self,
        correlation_id: str,
        result: ActionResult,
    ) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM queue_jobs WHERE correlation_id = ?",
                (correlation_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Unknown queue job correlation_id={correlation_id}")

            timestamp = self._utc_now()
            finalized = self._ensure_action_result_defaults(result, correlation_id=correlation_id)
            conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'succeeded',
                    locked_at = NULL,
                    worker_id = NULL,
                    updated_at = ?
                WHERE correlation_id = ?
                """,
                (timestamp, correlation_id),
            )
            self._upsert_action_result_for_alert(conn, row["alert_id"], finalized)
            self._append_queue_audit_event(
                conn,
                row=row,
                category="queue.succeeded",
                actor=finalized.operator or row["worker_id"] or "remediation-worker",
                message=f"Action '{row['action']}' completed successfully.",
                payload=finalized.model_dump(mode="json"),
            )
            conn.commit()

    def retry_action_job(
        self,
        correlation_id: str,
        result: ActionResult,
        *,
        next_available_at: datetime,
        last_error: str,
    ) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM queue_jobs WHERE correlation_id = ?",
                (correlation_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Unknown queue job correlation_id={correlation_id}")

            timestamp = self._utc_now()
            queued_result = self._ensure_action_result_defaults(result, correlation_id=correlation_id)
            conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'retry_pending',
                    available_at = ?,
                    locked_at = NULL,
                    worker_id = NULL,
                    last_error = ?,
                    updated_at = ?
                WHERE correlation_id = ?
                """,
                (
                    next_available_at.isoformat(),
                    last_error,
                    timestamp,
                    correlation_id,
                ),
            )
            self._upsert_action_result_for_alert(conn, row["alert_id"], queued_result)
            self._append_queue_audit_event(
                conn,
                row=row,
                category="queue.retry_pending",
                actor=queued_result.operator or "remediation-worker",
                message=f"Action '{row['action']}' scheduled for retry: {last_error}",
                payload={
                    **queued_result.model_dump(mode="json"),
                    "next_available_at": next_available_at.isoformat(),
                    "last_error": last_error,
                },
            )
            conn.commit()

    def dead_letter_action_job(
        self,
        correlation_id: str,
        result: ActionResult,
        *,
        last_error: str,
    ) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM queue_jobs WHERE correlation_id = ?",
                (correlation_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Unknown queue job correlation_id={correlation_id}")

            timestamp = self._utc_now()
            failed_result = self._ensure_action_result_defaults(result, correlation_id=correlation_id)
            conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'dead_letter',
                    locked_at = NULL,
                    worker_id = NULL,
                    last_error = ?,
                    dead_lettered_at = ?,
                    updated_at = ?
                WHERE correlation_id = ?
                """,
                (
                    last_error,
                    timestamp,
                    timestamp,
                    correlation_id,
                ),
            )
            self._upsert_action_result_for_alert(conn, row["alert_id"], failed_result)
            self._append_queue_audit_event(
                conn,
                row=row,
                category="queue.dead_letter",
                actor=failed_result.operator or "remediation-worker",
                message=f"Action '{row['action']}' moved to dead-letter: {last_error}",
                payload={**failed_result.model_dump(mode="json"), "last_error": last_error},
            )
            conn.commit()

    def approve_action_job(
        self,
        alert_id: str,
        correlation_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        decision_time = utc_now()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM queue_jobs
                WHERE alert_id = ? AND correlation_id = ?
                """,
                (alert_id, correlation_id),
            ).fetchone()
            if row is None:
                return None
            self._ensure_action_job_can_transition(
                row,
                expected_status="waiting_approval",
                decision="approve",
            )

            conn.execute(
                """
                UPDATE queue_jobs
                SET status = CASE WHEN status = 'waiting_approval' THEN 'queued' ELSE status END,
                    approval_state = ?,
                    approved_by = ?,
                    approved_at = ?,
                    approval_comment = ?,
                    updated_at = ?
                WHERE correlation_id = ?
                """,
                (
                    ActionApprovalState.APPROVED.value,
                    actor,
                    decision_time.isoformat(),
                    comment,
                    self._utc_now(),
                    correlation_id,
                ),
            )
            updated_request = QueuedActionRequest.model_validate(json.loads(row["request_json"])).model_copy(
                update={
                    "approval_state": ActionApprovalState.APPROVED,
                    "approved_by": actor,
                    "approved_at": decision_time,
                }
            )
            conn.execute(
                "UPDATE queue_jobs SET request_json = ? WHERE correlation_id = ?",
                (self._dump_model(updated_request), correlation_id),
            )
            approved_result = ActionResult(
                action=ResponseAction(str(row["action"])),
                status="queued",
                executed_at=decision_time,
                details=comment or f"Action '{row['action']}' approved and returned to queue.",
                correlation_id=correlation_id,
                attempt_count=int(row["attempt_count"] or 0),
                updated_at=decision_time,
                requires_approval=bool(row["requires_approval"]),
                approval_state=ActionApprovalState.APPROVED,
                approval_reason=row["approval_reason"],
                approved_by=actor,
                approved_at=decision_time,
                operator=actor,
            )
            self._upsert_action_result_for_alert(conn, alert_id, approved_result)
            self._append_queue_audit_event(
                conn,
                row=row,
                category="approval.approved",
                actor=actor,
                message=f"Action '{row['action']}' approved by analyst.",
                payload={**approved_result.model_dump(mode="json"), "comment": comment},
            )
            conn.commit()
        return self.get_incident_by_alert_id(alert_id)

    def reject_action_job(
        self,
        alert_id: str,
        correlation_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        decision_time = utc_now()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM queue_jobs
                WHERE alert_id = ? AND correlation_id = ?
                """,
                (alert_id, correlation_id),
            ).fetchone()
            if row is None:
                return None
            self._ensure_action_job_can_transition(
                row,
                expected_status="waiting_approval",
                decision="reject",
            )

            conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'rejected',
                    approval_state = ?,
                    approved_by = ?,
                    approved_at = ?,
                    approval_comment = ?,
                    updated_at = ?
                WHERE correlation_id = ?
                """,
                (
                    ActionApprovalState.REJECTED.value,
                    actor,
                    decision_time.isoformat(),
                    comment,
                    self._utc_now(),
                    correlation_id,
                ),
            )
            updated_request = QueuedActionRequest.model_validate(json.loads(row["request_json"])).model_copy(
                update={
                    "approval_state": ActionApprovalState.REJECTED,
                    "approved_by": actor,
                    "approved_at": decision_time,
                }
            )
            conn.execute(
                "UPDATE queue_jobs SET request_json = ? WHERE correlation_id = ?",
                (self._dump_model(updated_request), correlation_id),
            )
            rejected_result = ActionResult(
                action=ResponseAction(str(row["action"])),
                status="failed",
                executed_at=decision_time,
                details=comment or f"Action '{row['action']}' was rejected by analyst approval.",
                correlation_id=correlation_id,
                attempt_count=int(row["attempt_count"] or 0),
                updated_at=decision_time,
                requires_approval=bool(row["requires_approval"]),
                approval_state=ActionApprovalState.REJECTED,
                approval_reason=row["approval_reason"],
                approved_by=actor,
                approved_at=decision_time,
                operator=actor,
            )
            self._upsert_action_result_for_alert(conn, alert_id, rejected_result)
            self._append_queue_audit_event(
                conn,
                row=row,
                category="approval.rejected",
                actor=actor,
                message=f"Action '{row['action']}' rejected by analyst.",
                payload={**rejected_result.model_dump(mode="json"), "comment": comment},
            )
            conn.commit()
        return self.get_incident_by_alert_id(alert_id)

    def update_incident_case(
        self,
        alert_id: str,
        *,
        case_status: Optional[str] = None,
        case_owner: Optional[str] = None,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, case_status, case_owner FROM incidents WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            if row is None:
                return None

            next_status = case_status or row["case_status"] or IncidentCaseStatus.NEW.value
            next_owner = case_owner if case_owner is not None else row["case_owner"]
            timestamp = self._utc_now()
            conn.execute(
                """
                UPDATE incidents
                SET case_status = ?,
                    case_owner = ?,
                    updated_at = ?
                WHERE alert_id = ?
                """,
                (next_status, next_owner, timestamp, alert_id),
            )
            self._append_audit_event(
                conn,
                incident_id=int(row["id"]),
                alert_id=alert_id,
                category="case.updated",
                actor=actor,
                message=comment or "Case metadata updated.",
                payload={
                    "case_status": next_status,
                    "case_owner": next_owner,
                    "comment": comment,
                },
            )
            conn.commit()
        return self.get_incident_by_alert_id(alert_id)

    def add_incident_note(
        self,
        alert_id: str,
        *,
        author: str,
        body: str,
    ) -> Optional[dict[str, Any]]:
        note = IncidentNote(author=author, body=body)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM incidents WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            if row is None:
                return None

            conn.execute(
                """
                INSERT INTO case_notes (
                    note_id, incident_id, alert_id, author, body, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    note.note_id,
                    int(row["id"]),
                    alert_id,
                    note.author,
                    note.body,
                    note.created_at.isoformat(),
                    note.updated_at.isoformat(),
                ),
            )
            self._append_audit_event(
                conn,
                incident_id=int(row["id"]),
                alert_id=alert_id,
                category="case.note_added",
                actor=author,
                message="Analyst note added to incident case.",
                payload=note.model_dump(mode="json"),
            )
            conn.commit()
        return note.model_dump(mode="json")

    def bulk_update_incidents(
        self,
        alert_ids: list[str],
        *,
        case_status: Optional[str] = None,
        case_owner: Optional[str] = None,
        actor: str,
        comment: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        updated_alert_ids: list[str] = []
        with self._connect() as conn:
            for alert_id in alert_ids:
                row = conn.execute(
                    "SELECT id, case_status, case_owner FROM incidents WHERE alert_id = ?",
                    (alert_id,),
                ).fetchone()
                if row is None:
                    continue
                next_status = case_status or row["case_status"] or IncidentCaseStatus.NEW.value
                next_owner = case_owner if case_owner is not None else row["case_owner"]
                conn.execute(
                    """
                    UPDATE incidents
                    SET case_status = ?,
                        case_owner = ?,
                        updated_at = ?
                    WHERE alert_id = ?
                    """,
                    (next_status, next_owner, self._utc_now(), alert_id),
                )
                self._append_audit_event(
                    conn,
                    incident_id=int(row["id"]),
                    alert_id=alert_id,
                    category="case.bulk_updated",
                    actor=actor,
                    message=comment or "Incident case updated through bulk triage.",
                    payload={
                        "case_status": next_status,
                        "case_owner": next_owner,
                    },
                )
                updated_alert_ids.append(alert_id)
            conn.commit()
        return [
            incident
            for alert_id in updated_alert_ids
            if (incident := self.get_incident_by_alert_id(alert_id)) is not None
        ]

    def save_filter(
        self,
        *,
        name: str,
        filters: dict[str, Any],
        created_by: str,
    ) -> dict[str, Any]:
        timestamp = self._utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO saved_filters (name, filters_json, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    filters_json = excluded.filters_json,
                    created_by = excluded.created_by,
                    updated_at = excluded.updated_at
                """,
                (
                    name,
                    json.dumps(filters, ensure_ascii=False),
                    created_by,
                    timestamp,
                    timestamp,
                ),
            )
            row = conn.execute(
                """
                SELECT id, name, filters_json, created_by, created_at, updated_at
                FROM saved_filters
                WHERE name = ?
                """,
                (name,),
            ).fetchone()
            conn.commit()
        return self._deserialize_saved_filter(dict(row))

    def list_saved_filters(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, filters_json, created_by, created_at, updated_at
                FROM saved_filters
                ORDER BY updated_at DESC, id DESC
                """
            ).fetchall()
        return [self._deserialize_saved_filter(dict(row)) for row in rows]

    def get_queue_metrics(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_jobs,
                    SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued_jobs,
                    SUM(CASE WHEN status = 'waiting_approval' THEN 1 ELSE 0 END) AS waiting_approval_jobs,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running_jobs,
                    SUM(CASE WHEN status = 'retry_pending' THEN 1 ELSE 0 END) AS retry_pending_jobs,
                    SUM(CASE WHEN status = 'dead_letter' THEN 1 ELSE 0 END) AS dead_letter_jobs,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected_jobs,
                    MAX(updated_at) AS last_job_update_at
                FROM queue_jobs
                """
            ).fetchone()
        return dict(row)

    def get_incident_by_alert_id(self, alert_id: str) -> Optional[dict[str, Any]]:
        return self._get_incident(
            "WHERE incidents.alert_id = ?",
            (alert_id,),
        )

    def get_incident_by_ticket_id(self, ticket_id: str) -> Optional[dict[str, Any]]:
        return self._get_incident(
            "WHERE incidents.ticket_id = ?",
            (ticket_id,),
        )

    def _get_incident(
        self,
        where_clause: str,
        params: tuple[Any, ...],
    ) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT
                    incidents.id,
                    incidents.alert_id,
                    incidents.hostname,
                    incidents.detection_name,
                    incidents.risk_score,
                    incidents.risk_level,
                    incidents.ticket_id,
                    incidents.status,
                    incidents.completed_at,
                    incidents.report_path,
                    incidents.case_status,
                    incidents.case_owner,
                    incidents.triggered_actions_json,
                    incidents.policy_reasoning_json,
                    incidents.enriched_json,
                    incidents.response_json,
                    incidents.created_at,
                    incidents.updated_at,
                    alerts.raw_json AS alert_json,
                    reports.markdown_path,
                    reports.html_path,
                    reports.pdf_path,
                    reports.markdown_content
                FROM incidents
                JOIN alerts ON alerts.alert_id = incidents.alert_id
                LEFT JOIN reports ON reports.incident_id = incidents.id
                {where_clause}
                ORDER BY incidents.id DESC
                LIMIT 1
                """,
                params,
            ).fetchone()
            if row is None:
                return None
            return self._deserialize_incident(conn, row)

    def list_incidents(
        self,
        limit: int = 100,
        *,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        hostname: Optional[str] = None,
        ticket_id: Optional[str] = None,
        case_status: Optional[str] = None,
        case_owner: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > MAX_INCIDENT_LIST_LIMIT:
            raise ValueError(
                f"limit must be between 1 and {MAX_INCIDENT_LIST_LIMIT} inclusive"
            )

        with self._connect() as conn:
            where_clauses: list[str] = []
            params: list[Any] = []

            if status is not None:
                where_clauses.append("incidents.status = ?")
                params.append(status)
            if risk_level is not None:
                where_clauses.append("incidents.risk_level = ?")
                params.append(risk_level)
            if hostname is not None:
                where_clauses.append("incidents.hostname = ?")
                params.append(hostname)
            if ticket_id is not None:
                where_clauses.append("incidents.ticket_id = ?")
                params.append(ticket_id)
            if case_status is not None:
                where_clauses.append("incidents.case_status = ?")
                params.append(case_status)
            if case_owner is not None:
                where_clauses.append("incidents.case_owner = ?")
                params.append(case_owner)

            where_sql = ""
            if where_clauses:
                where_sql = "WHERE " + " AND ".join(where_clauses)

            rows = conn.execute(
                f"""
                SELECT
                    incidents.id,
                    incidents.alert_id,
                    incidents.hostname,
                    incidents.detection_name,
                    incidents.risk_score,
                    incidents.risk_level,
                    incidents.ticket_id,
                    incidents.status,
                    incidents.completed_at,
                    incidents.report_path,
                    incidents.case_status,
                    incidents.case_owner,
                    COALESCE(action_summary.queued_action_count, 0) AS queued_action_count,
                    COALESCE(action_summary.waiting_approval_count, 0) AS pending_approval_count,
                    COALESCE(action_summary.running_action_count, 0) AS running_action_count,
                    COALESCE(action_summary.failed_action_count, 0) AS failed_action_count,
                    COALESCE(action_summary.succeeded_action_count, 0) AS succeeded_action_count,
                    COALESCE(action_summary.active_action_count, 0) AS active_action_count,
                    COALESCE(note_summary.note_count, 0) AS note_count
                FROM incidents
                LEFT JOIN (
                    SELECT
                        incident_id,
                        SUM(CASE WHEN lower(status) = 'queued' THEN 1 ELSE 0 END) AS queued_action_count,
                        SUM(CASE WHEN lower(status) = 'waiting_approval' THEN 1 ELSE 0 END) AS waiting_approval_count,
                        SUM(CASE WHEN lower(status) = 'running' THEN 1 ELSE 0 END) AS running_action_count,
                        SUM(CASE WHEN lower(status) = 'failed' THEN 1 ELSE 0 END) AS failed_action_count,
                        SUM(CASE WHEN lower(status) IN ('succeeded', 'success') THEN 1 ELSE 0 END) AS succeeded_action_count,
                        SUM(CASE WHEN lower(status) IN ('queued', 'running', 'waiting_approval') THEN 1 ELSE 0 END) AS active_action_count
                    FROM action_results
                    GROUP BY incident_id
                ) AS action_summary ON action_summary.incident_id = incidents.id
                LEFT JOIN (
                    SELECT incident_id, COUNT(*) AS note_count
                    FROM case_notes
                    GROUP BY incident_id
                ) AS note_summary ON note_summary.incident_id = incidents.id
                {where_sql}
                ORDER BY incidents.updated_at DESC, incidents.id DESC
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_incident_metrics(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_incidents,
                    COALESCE(AVG(risk_score), 0) AS average_risk_score,
                    SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) AS critical_incidents,
                    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) AS high_incidents,
                    SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) AS medium_incidents,
                    SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END) AS low_incidents,
                    SUM(CASE WHEN ticket_id IS NOT NULL AND ticket_id != '' THEN 1 ELSE 0 END) AS ticketed_incidents,
                    SUM(CASE WHEN status = 'pending_approval' THEN 1 ELSE 0 END) AS approval_backlog,
                    SUM(CASE WHEN status = 'attention' THEN 1 ELSE 0 END) AS attention_required_incidents,
                    MAX(completed_at) AS latest_completed_at
                FROM incidents
                """
            ).fetchone()
        return dict(row)

    def _deserialize_incident(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        result = dict(row)
        result["triggered_actions"] = json.loads(result.pop("triggered_actions_json"))
        result["policy_reasoning"] = json.loads(result.pop("policy_reasoning_json"))
        result["alert"] = json.loads(result.pop("alert_json"))
        result["enriched_alert"] = json.loads(result.pop("enriched_json"))
        result["response"] = json.loads(result.pop("response_json"))
        result["action_results"] = [
            json.loads(action_row["raw_json"])
            for action_row in conn.execute(
                """
                SELECT raw_json
                FROM action_results
                WHERE incident_id = ?
                ORDER BY id ASC
                """,
                (result["id"],),
            ).fetchall()
        ]
        result["report"] = {
            "markdown_path": result["markdown_path"],
            "html_path": result["html_path"],
            "pdf_path": result["pdf_path"],
            "markdown_content": result["markdown_content"],
        }
        result["notes"] = [
            dict(note_row)
            for note_row in conn.execute(
                """
                SELECT note_id, author, body, created_at, updated_at
                FROM case_notes
                WHERE incident_id = ?
                ORDER BY created_at DESC
                """,
                (result["id"],),
            ).fetchall()
        ]
        result["audit_events"] = [
            {
                **dict(event_row),
                "payload": json.loads(event_row["payload_json"]),
            }
            for event_row in conn.execute(
                """
                SELECT event_id, category, actor, message, payload_json, created_at
                FROM audit_events
                WHERE incident_id = ?
                ORDER BY created_at DESC
                """,
                (result["id"],),
            ).fetchall()
        ]
        result["note_count"] = len(result["notes"])
        result["pending_approval_count"] = sum(
            1
            for action in result["action_results"]
            if self._normalize_action_status(action.get("status")) == "waiting_approval"
        )
        result["queued_action_count"] = sum(
            1
            for action in result["action_results"]
            if self._normalize_action_status(action.get("status")) == "queued"
        )
        result["running_action_count"] = sum(
            1
            for action in result["action_results"]
            if self._normalize_action_status(action.get("status")) == "running"
        )
        result["failed_action_count"] = sum(
            1
            for action in result["action_results"]
            if self._normalize_action_status(action.get("status")) == "failed"
        )
        result["succeeded_action_count"] = sum(
            1
            for action in result["action_results"]
            if self._normalize_action_status(action.get("status")) in _ACTION_STATUS_SUCCESS
        )
        result["active_action_count"] = (
            result["queued_action_count"] + result["running_action_count"] + result["pending_approval_count"]
        )
        return result

    def _upsert_action_result_for_alert(
        self,
        conn: sqlite3.Connection,
        alert_id: str,
        action_result: ActionResult,
    ) -> None:
        incident_row = conn.execute(
            "SELECT id, response_json FROM incidents WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
        if incident_row is None:
            return

        timestamp = self._utc_now()
        serialized = action_result.model_dump(mode="json")
        existing = None
        if action_result.correlation_id:
            existing = conn.execute(
                """
                SELECT id
                FROM action_results
                WHERE incident_id = ? AND correlation_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (incident_row["id"], action_result.correlation_id),
            ).fetchone()
        if existing is None:
            existing = conn.execute(
                """
                SELECT id
                FROM action_results
                WHERE incident_id = ? AND action = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (incident_row["id"], action_result.action.value),
            ).fetchone()

        if existing is None:
            conn.execute(
                """
                INSERT INTO action_results (
                    incident_id, action, status, executed_at, details,
                    correlation_id, attempt_count, updated_at, raw_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_row["id"],
                    action_result.action.value,
                    serialized["status"],
                    action_result.executed_at.isoformat(),
                    action_result.details,
                    action_result.correlation_id,
                    action_result.attempt_count,
                    action_result.updated_at.isoformat(),
                    json.dumps(serialized, ensure_ascii=False),
                    timestamp,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE action_results
                SET status = ?,
                    executed_at = ?,
                    details = ?,
                    correlation_id = ?,
                    attempt_count = ?,
                    updated_at = ?,
                    raw_json = ?
                WHERE id = ?
                """,
                (
                    serialized["status"],
                    action_result.executed_at.isoformat(),
                    action_result.details,
                    action_result.correlation_id,
                    action_result.attempt_count,
                    action_result.updated_at.isoformat(),
                    json.dumps(serialized, ensure_ascii=False),
                    existing["id"],
                ),
            )

        response_payload = json.loads(incident_row["response_json"])
        action_results_payload = list(response_payload.get("action_results") or [])
        serialized_payload = dict(serialized)
        match_index = None
        for index, current in enumerate(action_results_payload):
            current_correlation_id = current.get("correlation_id")
            if action_result.correlation_id and current_correlation_id == action_result.correlation_id:
                match_index = index
                break
            if (
                not action_result.correlation_id
                and not current_correlation_id
                and current.get("action") == action_result.action.value
            ):
                match_index = index
                break
        if match_index is None:
            action_results_payload.append(serialized_payload)
        else:
            action_results_payload[match_index] = serialized_payload
        response_payload["action_results"] = action_results_payload

        incident_status = self._derive_incident_status_from_payloads(action_results_payload)
        conn.execute(
            """
            UPDATE incidents
            SET status = ?,
                response_json = ?,
                updated_at = ?
            WHERE alert_id = ?
            """,
            (
                incident_status,
                json.dumps(response_payload, ensure_ascii=False),
                timestamp,
                alert_id,
            ),
        )

    def _append_queue_audit_event(
        self,
        conn: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        category: str,
        actor: str,
        message: str,
        payload: dict[str, Any],
    ) -> None:
        incident_row = conn.execute(
            "SELECT id FROM incidents WHERE alert_id = ?",
            (row["alert_id"],),
        ).fetchone()
        if incident_row is None:
            return
        self._append_audit_event(
            conn,
            incident_id=int(incident_row["id"]),
            alert_id=row["alert_id"],
            category=category,
            actor=actor,
            message=message,
            payload=payload,
        )

    def _append_audit_event(
        self,
        conn: sqlite3.Connection,
        *,
        incident_id: int,
        alert_id: str,
        category: str,
        actor: str,
        message: str,
        payload: dict[str, Any],
    ) -> None:
        event = IncidentAuditEvent(
            event_id=f"audit-{uuid4().hex}",
            category=category,
            actor=actor,
            message=message,
            payload=payload,
        )
        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, incident_id, alert_id, category, actor, message, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                incident_id,
                alert_id,
                event.category,
                event.actor,
                event.message,
                json.dumps(event.payload, ensure_ascii=False),
                event.created_at.isoformat(),
            ),
        )
        self._write_audit_log(event, alert_id=alert_id, incident_id=incident_id)

    def _has_audit_events(self, conn: sqlite3.Connection, incident_id: int) -> bool:
        row = conn.execute(
            "SELECT 1 FROM audit_events WHERE incident_id = ? LIMIT 1",
            (incident_id,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _ensure_action_result_defaults(
        action_result: ActionResult,
        *,
        correlation_id: str,
    ) -> ActionResult:
        return action_result.model_copy(
            update={
                "correlation_id": action_result.correlation_id or correlation_id,
                "updated_at": action_result.updated_at or utc_now(),
            }
        )

    @staticmethod
    def _derive_incident_status(action_results: list[ActionResult]) -> str:
        statuses = {
            SQLiteIncidentRepository._normalize_action_status(result.status)
            for result in action_results
        }
        if statuses & _ACTION_STATUS_WAITING_APPROVAL:
            return "pending_approval"
        if statuses & _ACTION_STATUS_ACTIVE:
            return "remediating"
        if "failed" in statuses:
            return "attention"
        return "completed"

    @staticmethod
    def _derive_incident_status_from_payloads(action_results: list[dict[str, Any]]) -> str:
        statuses = {
            SQLiteIncidentRepository._normalize_action_status(result.get("status"))
            for result in action_results
        }
        if statuses & _ACTION_STATUS_WAITING_APPROVAL:
            return "pending_approval"
        if statuses & _ACTION_STATUS_ACTIVE:
            return "remediating"
        if "failed" in statuses:
            return "attention"
        return "completed"

    @staticmethod
    def _normalize_action_status(value: Any) -> str:
        candidate = str(value or "").strip().lower()
        if candidate == "success":
            return "succeeded"
        if candidate in {"pending_approval", "blocked_on_approval"}:
            return "waiting_approval"
        return candidate

    @staticmethod
    def _ensure_column(
        conn: sqlite3.Connection,
        table_name: str,
        column_name: str,
        column_sql: str,
    ) -> None:
        columns = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name in columns:
            return
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")

    @staticmethod
    def _dump_model(model: Any) -> str:
        return json.dumps(model.model_dump(mode="json"), ensure_ascii=False)

    @staticmethod
    def _path_to_str(path: Optional[Path]) -> Optional[str]:
        return str(path) if path is not None else None

    @staticmethod
    def _parse_datetime(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value.strip():
            return datetime.fromisoformat(value)
        return None

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _ensure_action_job_can_transition(
        row: sqlite3.Row,
        *,
        expected_status: str,
        decision: str,
    ) -> None:
        current_status = str(row["status"] or "")
        if current_status != expected_status:
            decision_label = "approved" if decision == "approve" else "rejected"
            raise ValueError(
                "Queued action "
                f"{row['correlation_id']} cannot be {decision_label} from status '{current_status}'."
            )

    @staticmethod
    def _deserialize_saved_filter(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "filters": json.loads(row["filters_json"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _write_audit_log(
        self,
        event: IncidentAuditEvent,
        *,
        alert_id: str,
        incident_id: int,
    ) -> None:
        payload = {
            "event_id": event.event_id,
            "alert_id": alert_id,
            "incident_id": incident_id,
            "category": event.category,
            "actor": event.actor,
            "message": event.message,
            "payload": event.payload,
            "created_at": event.created_at.isoformat(),
        }
        with self._audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
