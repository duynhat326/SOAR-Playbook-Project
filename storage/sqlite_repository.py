from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Optional, Sequence
from uuid import uuid4

from schemas.alert import (
    ActionApprovalState,
    ActionResult,
    CorrelationOutcome,
    IncidentAuditEvent,
    IncidentCaseStatus,
    IncidentNote,
    QueuedActionRequest,
    ResponseAction,
)
from time_utils import utc_now
from workspace_utils import effective_workspaces, normalize_workspace

if TYPE_CHECKING:
    from services.incident_correlation import CorrelationFingerprint
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

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL DEFAULT 'default',
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
                    incident_key TEXT,
                    latest_alert_id TEXT,
                    workspace TEXT NOT NULL DEFAULT 'default',
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

                CREATE TABLE IF NOT EXISTS incident_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    alert_id TEXT NOT NULL UNIQUE,
                    linked_at TEXT NOT NULL,
                    correlation_outcome TEXT NOT NULL,
                    correlation_strategy TEXT,
                    correlation_fingerprint TEXT,
                    correlation_values_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS incident_fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    alert_id TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    fingerprint_fields_json TEXT NOT NULL,
                    values_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS action_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    alert_id TEXT,
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
                    approval_due_at TEXT,
                    approval_escalates_at TEXT,
                    escalation_targets_json TEXT,
                    approval_escalated_at TEXT,
                    approval_comment TEXT,
                    rollback_requested_by TEXT,
                    rollback_requested_at TEXT,
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
                    previous_event_hash TEXT,
                    event_hash TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS saved_filters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL DEFAULT 'default',
                    name TEXT NOT NULL,
                    filters_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(workspace, name)
                );
                """
            )
            self._ensure_column(conn, "alerts", "workspace", "TEXT NOT NULL DEFAULT 'default'")
            self._ensure_column(conn, "incidents", "case_status", "TEXT NOT NULL DEFAULT 'new'")
            self._ensure_column(conn, "incidents", "case_owner", "TEXT")
            self._ensure_column(conn, "incidents", "incident_key", "TEXT")
            self._ensure_column(conn, "incidents", "latest_alert_id", "TEXT")
            self._ensure_column(conn, "incidents", "workspace", "TEXT NOT NULL DEFAULT 'default'")
            self._ensure_column(conn, "action_results", "alert_id", "TEXT")
            self._ensure_column(conn, "action_results", "correlation_id", "TEXT")
            self._ensure_column(conn, "action_results", "attempt_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "action_results", "updated_at", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "queue_jobs", "requires_approval", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "queue_jobs", "approval_state", "TEXT NOT NULL DEFAULT 'not_required'")
            self._ensure_column(conn, "queue_jobs", "approval_reason", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approved_by", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approved_at", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approval_due_at", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approval_escalates_at", "TEXT")
            self._ensure_column(conn, "queue_jobs", "escalation_targets_json", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approval_escalated_at", "TEXT")
            self._ensure_column(conn, "queue_jobs", "approval_comment", "TEXT")
            self._ensure_column(conn, "queue_jobs", "rollback_requested_by", "TEXT")
            self._ensure_column(conn, "queue_jobs", "rollback_requested_at", "TEXT")
            self._ensure_column(conn, "audit_events", "previous_event_hash", "TEXT")
            self._ensure_column(conn, "audit_events", "event_hash", "TEXT")
            self._migrate_saved_filters_table(conn)
            conn.execute(
                "UPDATE action_results SET updated_at = executed_at WHERE updated_at IS NULL OR updated_at = ''"
            )
            conn.execute(
                """
                UPDATE action_results
                SET alert_id = COALESCE(
                    alert_id,
                    (
                        SELECT incidents.alert_id
                        FROM incidents
                        WHERE incidents.id = action_results.incident_id
                    )
                )
                WHERE alert_id IS NULL OR alert_id = ''
                """
            )
            conn.execute(
                "UPDATE incidents SET case_status = 'new' WHERE case_status IS NULL OR case_status = ''"
            )
            conn.execute(
                "UPDATE incidents SET incident_key = COALESCE(incident_key, 'incident-' || alert_id)"
            )
            conn.execute(
                "UPDATE incidents SET latest_alert_id = COALESCE(latest_alert_id, alert_id)"
            )
            default_workspace = normalize_workspace(None)
            conn.execute(
                "UPDATE alerts SET workspace = ? WHERE workspace IS NULL OR trim(workspace) = ''",
                (default_workspace,),
            )
            conn.execute(
                """
                UPDATE incidents
                SET workspace = COALESCE(
                    NULLIF(workspace, ''),
                    (
                        SELECT alerts.workspace
                        FROM alerts
                        WHERE alerts.alert_id = incidents.alert_id
                    ),
                    ?
                )
                WHERE workspace IS NULL OR trim(workspace) = ''
                """,
                (default_workspace,),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO incident_alerts (
                    incident_id, alert_id, linked_at, correlation_outcome,
                    correlation_strategy, correlation_fingerprint, correlation_values_json, created_at
                )
                SELECT
                    incidents.id,
                    incidents.alert_id,
                    incidents.created_at,
                    'new_incident',
                    NULL,
                    NULL,
                    '{}',
                    incidents.created_at
                FROM incidents
                """
            )
            conn.executescript(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_incident_key
                ON incidents(incident_key);

                CREATE INDEX IF NOT EXISTS idx_incidents_ticket_id
                ON incidents(ticket_id);

                CREATE INDEX IF NOT EXISTS idx_incidents_case_status
                ON incidents(case_status);

                CREATE INDEX IF NOT EXISTS idx_incidents_workspace
                ON incidents(workspace);

                CREATE INDEX IF NOT EXISTS idx_incidents_latest_alert_id
                ON incidents(latest_alert_id);

                CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident
                ON incident_alerts(incident_id, linked_at DESC);

                CREATE INDEX IF NOT EXISTS idx_incident_fingerprints_lookup
                ON incident_fingerprints(fingerprint, observed_at DESC);

                CREATE INDEX IF NOT EXISTS idx_action_results_incident_action
                ON action_results(incident_id, alert_id, action);

                CREATE INDEX IF NOT EXISTS idx_action_results_correlation
                ON action_results(correlation_id);

                CREATE INDEX IF NOT EXISTS idx_queue_jobs_available
                ON queue_jobs(status, queue_name, available_at);

                CREATE INDEX IF NOT EXISTS idx_case_notes_alert_id
                ON case_notes(alert_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_audit_events_alert_id
                ON audit_events(alert_id, created_at DESC);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_filters_workspace_name
                ON saved_filters(workspace, name);

                CREATE INDEX IF NOT EXISTS idx_saved_filters_workspace_updated
                ON saved_filters(workspace, updated_at DESC, id DESC);
                """
            )
            conn.commit()

    def save_workflow_result(self, result: "WorkflowResult") -> int:
        alert = result.alert
        enriched = result.enriched_alert
        response = result.response
        workspace = normalize_workspace(result.workspace)
        timestamp = self._utc_now()
        incident_status = self._derive_incident_status(response.action_results)
        correlation_trace = response.correlation_trace
        incident_key = correlation_trace.incident_key or f"incident-{alert.alert_id}"
        outcome = correlation_trace.outcome.value
        has_report_artifacts = any(
            (
                result.artifacts.markdown_path,
                result.artifacts.html_path,
                result.artifacts.pdf_path,
                result.artifacts.markdown_content,
            )
        )

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO alerts (
                    alert_id, workspace, hostname, username, process_name, file_path, file_hash,
                    parent_process, command_line, destination_ip, severity,
                    detection_name, received_at, raw_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    workspace=excluded.workspace,
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
                    workspace,
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

            existing_incident = self._resolve_incident_row(
                conn,
                alert_id=alert.alert_id,
                incident_key=incident_key,
                workspace=workspace,
            )
            stored_ticket_id = response.ticket_id
            stored_report_path = response.report_path
            if existing_incident is not None:
                stored_ticket_id = stored_ticket_id or existing_incident["ticket_id"]
                if not has_report_artifacts:
                    stored_report_path = stored_report_path or existing_incident["report_path"]
            stored_response = response.model_copy(
                update={
                    "ticket_id": stored_ticket_id,
                    "report_path": stored_report_path,
                }
            )
            if existing_incident is None:
                conn.execute(
                    """
                    INSERT INTO incidents (
                        alert_id, incident_key, latest_alert_id, workspace, hostname, detection_name, risk_score, risk_level,
                        ticket_id, status, completed_at, report_path, case_status,
                        case_owner, triggered_actions_json, policy_reasoning_json,
                        enriched_json, response_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        incident_key,
                        alert.alert_id,
                        workspace,
                        alert.hostname,
                        alert.detection_name,
                        enriched.risk_score,
                        enriched.risk_level,
                        stored_ticket_id,
                        incident_status,
                        response.completed_at.isoformat(),
                        stored_report_path,
                        IncidentCaseStatus.NEW.value,
                        None,
                        json.dumps([action.value for action in response.triggered_actions], ensure_ascii=False),
                        json.dumps(response.policy_reasoning, ensure_ascii=False),
                        self._dump_model(enriched),
                        self._dump_model(stored_response),
                        timestamp,
                        timestamp,
                    ),
                )
                incident_row = conn.execute(
                    "SELECT * FROM incidents WHERE incident_key = ?",
                    (incident_key,),
                ).fetchone()
            else:
                next_case_status = existing_incident["case_status"] or IncidentCaseStatus.NEW.value
                if outcome == CorrelationOutcome.REOPENED_INCIDENT.value:
                    next_case_status = IncidentCaseStatus.IN_PROGRESS.value
                conn.execute(
                    """
                    UPDATE incidents
                    SET latest_alert_id = ?,
                        workspace = ?,
                        hostname = ?,
                        detection_name = ?,
                        risk_score = ?,
                        risk_level = ?,
                        ticket_id = ?,
                        status = ?,
                        completed_at = ?,
                        report_path = ?,
                        case_status = ?,
                        case_owner = case_owner,
                        triggered_actions_json = ?,
                        policy_reasoning_json = ?,
                        enriched_json = ?,
                        response_json = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        alert.alert_id,
                        workspace,
                        alert.hostname,
                        alert.detection_name,
                        enriched.risk_score,
                        enriched.risk_level,
                        stored_ticket_id,
                        incident_status,
                        response.completed_at.isoformat(),
                        stored_report_path,
                        next_case_status,
                        json.dumps([action.value for action in response.triggered_actions], ensure_ascii=False),
                        json.dumps(response.policy_reasoning, ensure_ascii=False),
                        self._dump_model(enriched),
                        self._dump_model(stored_response),
                        timestamp,
                        int(existing_incident["id"]),
                    ),
                )
                incident_row = conn.execute(
                    "SELECT * FROM incidents WHERE id = ?",
                    (int(existing_incident["id"]),),
                ).fetchone()

            incident_id = int(incident_row["id"])

            conn.execute(
                """
                INSERT INTO incident_alerts (
                    incident_id, alert_id, linked_at, correlation_outcome, correlation_strategy,
                    correlation_fingerprint, correlation_values_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    incident_id = excluded.incident_id,
                    linked_at = excluded.linked_at,
                    correlation_outcome = excluded.correlation_outcome,
                    correlation_strategy = excluded.correlation_strategy,
                    correlation_fingerprint = excluded.correlation_fingerprint,
                    correlation_values_json = excluded.correlation_values_json
                """,
                (
                    incident_id,
                    alert.alert_id,
                    alert.received_at.isoformat(),
                    outcome,
                    (
                        response.correlation_trace.evidence[0].strategy
                        if response.correlation_trace.evidence
                        else None
                    ),
                    (
                        response.correlation_trace.evidence[0].fingerprint
                        if response.correlation_trace.evidence
                        else None
                    ),
                    json.dumps(
                        (
                            response.correlation_trace.evidence[0].values
                            if response.correlation_trace.evidence
                            else {}
                        ),
                        ensure_ascii=False,
                    ),
                    timestamp,
                ),
            )

            conn.execute(
                "DELETE FROM incident_fingerprints WHERE alert_id = ?",
                (alert.alert_id,),
            )
            for fingerprint in response.correlation_trace.candidate_fingerprints:
                conn.execute(
                    """
                    INSERT INTO incident_fingerprints (
                        incident_id, alert_id, strategy, fingerprint, fingerprint_fields_json,
                        values_json, observed_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        alert.alert_id,
                        fingerprint.strategy,
                        fingerprint.fingerprint,
                        json.dumps(fingerprint.fields, ensure_ascii=False),
                        json.dumps(fingerprint.values, ensure_ascii=False),
                        alert.received_at.isoformat(),
                        timestamp,
                    ),
                )

            conn.execute(
                "DELETE FROM action_results WHERE incident_id = ? AND COALESCE(alert_id, '') = ?",
                (incident_id, alert.alert_id),
            )
            for action_result in response.action_results:
                serialized = action_result.model_dump(mode="json")
                conn.execute(
                    """
                    INSERT INTO action_results (
                        incident_id, alert_id, action, status, executed_at, details,
                        correlation_id, attempt_count, updated_at, raw_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        alert.alert_id,
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

            final_incident_status = self._derive_incident_status_from_payloads(
                [
                    {"status": row["status"]}
                    for row in conn.execute(
                        """
                        SELECT status
                        FROM action_results
                        WHERE incident_id = ?
                        """,
                        (incident_id,),
                    ).fetchall()
                ]
            )
            conn.execute(
                """
                UPDATE incidents
                SET status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (final_incident_status, timestamp, incident_id),
            )

            conn.execute(
                "UPDATE incidents SET report_path = ? WHERE id = ?",
                (stored_report_path, incident_id),
            )
            if has_report_artifacts:
                conn.execute(
                    "DELETE FROM reports WHERE incident_id = ?",
                    (incident_id,),
                )
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
                    category="correlation.new_incident",
                    actor="soar-workflow",
                    message=(
                        f"New incident created for host '{alert.hostname}' with risk "
                        f"{enriched.risk_level} ({enriched.risk_score:.1f})."
                    ),
                    payload={
                        "risk_level": enriched.risk_level,
                        "risk_score": enriched.risk_score,
                        "ticket_id": stored_ticket_id,
                        "incident_key": incident_key,
                    },
                )
            elif outcome in {
                CorrelationOutcome.ATTACHED_TO_EXISTING.value,
                CorrelationOutcome.REOPENED_INCIDENT.value,
            }:
                self._append_audit_event(
                    conn,
                    incident_id=incident_id,
                    alert_id=alert.alert_id,
                    category=f"correlation.{outcome}",
                    actor="soar-workflow",
                    message=(
                        f"Alert '{alert.alert_id}' correlated into incident '{incident_key}' "
                        f"using window {response.correlation_trace.window}."
                    ),
                    payload=response.correlation_trace.model_dump(mode="json"),
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

        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO queue_jobs (
                    alert_id, action, queue_name, correlation_id, deduplication_key,
                    request_json, payload_json, status, available_at, locked_at,
                    worker_id, attempt_count, max_attempts, requires_approval,
                    approval_state, approval_reason, approved_by, approved_at,
                    approval_due_at, approval_escalates_at, escalation_targets_json,
                    approval_escalated_at, approval_comment, rollback_requested_by,
                    rollback_requested_at, last_error, dead_lettered_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
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
                    request.approval_due_at.isoformat() if request.approval_due_at else None,
                    request.approval_escalates_at.isoformat() if request.approval_escalates_at else None,
                    json.dumps(list(request.escalation_targets), ensure_ascii=False),
                    request.approval_escalated_at.isoformat() if request.approval_escalated_at else None,
                    request.approval_comment,
                    request.rollback_requested_by,
                    request.rollback_requested_at.isoformat() if request.rollback_requested_at else None,
                    timestamp,
                    timestamp,
                ),
            )

            incident_row = self._resolve_incident_row(conn, alert_id=alert_id)
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
        with self._connection() as conn:
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
            request = self._queue_request_from_row(row)
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
                approval_comment=row["approval_comment"],
                approved_by=row["approved_by"],
                approved_at=self._parse_datetime(row["approved_at"]),
                approval_due_at=self._parse_datetime(row["approval_due_at"]),
                approval_escalates_at=self._parse_datetime(row["approval_escalates_at"]),
                escalation_targets=self._parse_string_list(row["escalation_targets_json"]),
                approval_escalated_at=self._parse_datetime(row["approval_escalated_at"]),
                rollback_requested_by=row["rollback_requested_by"],
                rollback_requested_at=self._parse_datetime(row["rollback_requested_at"]),
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
        with self._connection() as conn:
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
        with self._connection() as conn:
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
        with self._connection() as conn:
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
        with self._connection() as conn:
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
            updated_request = self._queue_request_from_row(row).model_copy(
                update={
                    "approval_state": ActionApprovalState.APPROVED,
                    "approval_comment": comment,
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
                approval_comment=comment,
                approved_by=actor,
                approved_at=decision_time,
                approval_due_at=self._parse_datetime(row["approval_due_at"]),
                approval_escalates_at=self._parse_datetime(row["approval_escalates_at"]),
                escalation_targets=self._parse_string_list(row["escalation_targets_json"]),
                approval_escalated_at=self._parse_datetime(row["approval_escalated_at"]),
                rollback_requested_by=row["rollback_requested_by"],
                rollback_requested_at=self._parse_datetime(row["rollback_requested_at"]),
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
        with self._connection() as conn:
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
            updated_request = self._queue_request_from_row(row).model_copy(
                update={
                    "approval_state": ActionApprovalState.REJECTED,
                    "approval_comment": comment,
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
                approval_comment=comment,
                approved_by=actor,
                approved_at=decision_time,
                approval_due_at=self._parse_datetime(row["approval_due_at"]),
                approval_escalates_at=self._parse_datetime(row["approval_escalates_at"]),
                escalation_targets=self._parse_string_list(row["escalation_targets_json"]),
                approval_escalated_at=self._parse_datetime(row["approval_escalated_at"]),
                rollback_requested_by=row["rollback_requested_by"],
                rollback_requested_at=self._parse_datetime(row["rollback_requested_at"]),
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

    def rollback_action_job(
        self,
        alert_id: str,
        correlation_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        decision_time = utc_now()
        with self._connection() as conn:
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

            current_status = str(row["status"] or "")
            if current_status not in {"queued", "waiting_approval", "retry_pending"}:
                raise ValueError(
                    "Queued action "
                    f"{row['correlation_id']} cannot be rolled back from status '{current_status}'."
                )

            next_approval_state = (
                ActionApprovalState.REJECTED
                if current_status == "waiting_approval" and bool(row["requires_approval"])
                else self._parse_approval_state(row["approval_state"])
            )
            next_comment = comment if comment is not None else row["approval_comment"]

            conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'cancelled',
                    approval_state = ?,
                    approval_comment = ?,
                    rollback_requested_by = ?,
                    rollback_requested_at = ?,
                    updated_at = ?
                WHERE correlation_id = ?
                """,
                (
                    next_approval_state.value,
                    next_comment,
                    actor,
                    decision_time.isoformat(),
                    self._utc_now(),
                    correlation_id,
                ),
            )
            updated_request = self._queue_request_from_row(row).model_copy(
                update={
                    "approval_state": next_approval_state,
                    "approval_comment": next_comment,
                    "rollback_requested_by": actor,
                    "rollback_requested_at": decision_time,
                }
            )
            conn.execute(
                "UPDATE queue_jobs SET request_json = ? WHERE correlation_id = ?",
                (self._dump_model(updated_request), correlation_id),
            )
            rollback_result = ActionResult(
                action=ResponseAction(str(row["action"])),
                status="skipped",
                executed_at=decision_time,
                details=comment or f"Action '{row['action']}' was cancelled before execution.",
                correlation_id=correlation_id,
                attempt_count=int(row["attempt_count"] or 0),
                updated_at=decision_time,
                requires_approval=bool(row["requires_approval"]),
                approval_state=next_approval_state,
                approval_reason=row["approval_reason"],
                approval_comment=next_comment,
                approved_by=row["approved_by"],
                approved_at=self._parse_datetime(row["approved_at"]),
                approval_due_at=self._parse_datetime(row["approval_due_at"]),
                approval_escalates_at=self._parse_datetime(row["approval_escalates_at"]),
                escalation_targets=self._parse_string_list(row["escalation_targets_json"]),
                approval_escalated_at=self._parse_datetime(row["approval_escalated_at"]),
                rollback_requested_by=actor,
                rollback_requested_at=decision_time,
                operator=actor,
            )
            self._upsert_action_result_for_alert(conn, alert_id, rollback_result)
            self._append_queue_audit_event(
                conn,
                row=row,
                category="queue.cancelled",
                actor=actor,
                message=f"Action '{row['action']}' cancelled before execution.",
                payload={**rollback_result.model_dump(mode="json"), "comment": comment},
            )
            conn.commit()
        return self.get_incident_by_alert_id(alert_id)

    def reopen_incident(
        self,
        alert_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        with self._connection() as conn:
            row = self._resolve_incident_row(conn, alert_id=alert_id)
            if row is None:
                return None

            current_case_status = str(row["case_status"] or IncidentCaseStatus.NEW.value)
            if current_case_status not in {IncidentCaseStatus.RESOLVED.value, IncidentCaseStatus.CLOSED.value}:
                raise ValueError(
                    f"Incident '{alert_id}' cannot be reopened from case status '{current_case_status}'."
                )

            timestamp = self._utc_now()
            next_case_status = IncidentCaseStatus.IN_PROGRESS.value
            conn.execute(
                """
                UPDATE incidents
                SET case_status = ?,
                    status = CASE WHEN status = 'completed' THEN 'attention' ELSE status END,
                    updated_at = ?
                WHERE id = ?
                """,
                (next_case_status, timestamp, int(row["id"])),
            )
            self._append_audit_event(
                conn,
                incident_id=int(row["id"]),
                alert_id=alert_id,
                category="case.reopened",
                actor=actor,
                message=comment or "Incident reopened for analyst follow-up.",
                payload={
                    "previous_case_status": current_case_status,
                    "case_status": next_case_status,
                    "case_owner": row["case_owner"],
                    "comment": comment,
                },
            )
            conn.commit()
        return self.get_incident_by_alert_id(alert_id)

    def escalate_overdue_approvals(
        self,
        *,
        actor: str,
        workspaces: Optional[Sequence[str]] = None,
    ) -> list[dict[str, Any]]:
        escalation_time = utc_now()
        escalation_time_iso = escalation_time.isoformat()
        affected_alert_ids: list[str] = []
        # None = system caller (all workspaces); API callers always pass the principal's workspaces.
        scoped = [] if workspaces is None else [w for w in effective_workspaces(workspaces) if w != "*"]
        workspace_filter = (
            f"AND alert_id IN (SELECT alert_id FROM alerts WHERE workspace IN ({', '.join('?' for _ in scoped)}))"
            if scoped
            else ""
        )

        with self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT *
                FROM queue_jobs
                WHERE status = 'waiting_approval'
                  AND approval_escalates_at IS NOT NULL
                  AND approval_escalates_at <= ?
                  AND approval_escalated_at IS NULL
                  {workspace_filter}
                ORDER BY approval_escalates_at ASC, id ASC
                """,
                (escalation_time_iso, *scoped),
            ).fetchall()

            for row in rows:
                escalation_targets = self._parse_string_list(row["escalation_targets_json"])
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET approval_escalated_at = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (escalation_time_iso, self._utc_now(), int(row["id"])),
                )
                updated_request = self._queue_request_from_row(row).model_copy(
                    update={"approval_escalated_at": escalation_time}
                )
                conn.execute(
                    "UPDATE queue_jobs SET request_json = ? WHERE correlation_id = ?",
                    (self._dump_model(updated_request), row["correlation_id"]),
                )
                escalated_result = ActionResult(
                    action=ResponseAction(str(row["action"])),
                    status="waiting_approval",
                    executed_at=self._parse_datetime(row["created_at"]) or escalation_time,
                    details=(
                        f"Approval SLA breached for '{row['action']}'. "
                        f"Escalated to {', '.join(escalation_targets) if escalation_targets else 'configured escalation path'}."
                    ),
                    correlation_id=row["correlation_id"],
                    attempt_count=int(row["attempt_count"] or 0),
                    updated_at=escalation_time,
                    requires_approval=bool(row["requires_approval"]),
                    approval_state=row["approval_state"],
                    approval_reason=row["approval_reason"],
                    approval_comment=row["approval_comment"],
                    approved_by=row["approved_by"],
                    approved_at=self._parse_datetime(row["approved_at"]),
                    approval_due_at=self._parse_datetime(row["approval_due_at"]),
                    approval_escalates_at=self._parse_datetime(row["approval_escalates_at"]),
                    escalation_targets=escalation_targets,
                    approval_escalated_at=escalation_time,
                    rollback_requested_by=row["rollback_requested_by"],
                    rollback_requested_at=self._parse_datetime(row["rollback_requested_at"]),
                    operator=actor,
                )
                self._upsert_action_result_for_alert(conn, row["alert_id"], escalated_result)
                self._append_queue_audit_event(
                    conn,
                    row=row,
                    category="approval.escalated",
                    actor=actor,
                    message=f"Approval for '{row['action']}' exceeded SLA and was escalated.",
                    payload={
                        **escalated_result.model_dump(mode="json"),
                        "escalation_targets": escalation_targets,
                    },
                )
                if row["alert_id"] not in affected_alert_ids:
                    affected_alert_ids.append(str(row["alert_id"]))
            conn.commit()

        return [
            incident
            for affected_alert_id in affected_alert_ids
            if (incident := self.get_incident_by_alert_id(affected_alert_id)) is not None
        ]

    def update_incident_case(
        self,
        alert_id: str,
        *,
        case_status: Optional[str] = None,
        case_owner: Optional[str] = None,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        with self._connection() as conn:
            row = self._resolve_incident_row(conn, alert_id=alert_id)
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
                WHERE id = ?
                """,
                (next_status, next_owner, timestamp, int(row["id"])),
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
        with self._connection() as conn:
            row = self._resolve_incident_row(conn, alert_id=alert_id)
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
        with self._connection() as conn:
            for alert_id in alert_ids:
                row = self._resolve_incident_row(conn, alert_id=alert_id)
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
                    WHERE id = ?
                    """,
                    (next_status, next_owner, self._utc_now(), int(row["id"])),
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
        workspace: str,
    ) -> dict[str, Any]:
        timestamp = self._utc_now()
        resolved_workspace = normalize_workspace(workspace)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO saved_filters (workspace, name, filters_json, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace, name) DO UPDATE SET
                    filters_json = excluded.filters_json,
                    created_by = excluded.created_by,
                    updated_at = excluded.updated_at
                """,
                (
                    resolved_workspace,
                    name,
                    json.dumps(filters, ensure_ascii=False),
                    created_by,
                    timestamp,
                    timestamp,
                ),
            )
            row = conn.execute(
                """
                SELECT id, workspace, name, filters_json, created_by, created_at, updated_at
                FROM saved_filters
                WHERE workspace = ? AND name = ?
                """,
                (resolved_workspace, name),
            ).fetchone()
            conn.commit()
        return self._deserialize_saved_filter(dict(row))

    def list_saved_filters(self, *, workspaces: Optional[Sequence[str]] = None) -> list[dict[str, Any]]:
        scoped_workspaces = tuple(
            workspace
            for workspace in effective_workspaces(workspaces)
            if workspace != "*"
        )
        with self._connection() as conn:
            if scoped_workspaces:
                placeholders = ", ".join("?" for _ in scoped_workspaces)
                rows = conn.execute(
                    f"""
                    SELECT id, workspace, name, filters_json, created_by, created_at, updated_at
                    FROM saved_filters
                    WHERE workspace IN ({placeholders})
                    ORDER BY updated_at DESC, id DESC
                    """,
                    scoped_workspaces,
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, workspace, name, filters_json, created_by, created_at, updated_at
                    FROM saved_filters
                    ORDER BY updated_at DESC, id DESC
                    """
                ).fetchall()
        return [self._deserialize_saved_filter(dict(row)) for row in rows]

    def get_queue_metrics(self) -> dict[str, Any]:
        timestamp = self._utc_now()
        with self._connection() as conn:
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
                    SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_jobs,
                    SUM(
                        CASE
                            WHEN status = 'waiting_approval'
                             AND approval_due_at IS NOT NULL
                             AND approval_due_at <= ?
                            THEN 1
                            ELSE 0
                        END
                    ) AS overdue_approval_jobs,
                    SUM(
                        CASE
                            WHEN status = 'waiting_approval'
                             AND approval_escalates_at IS NOT NULL
                             AND approval_escalates_at <= ?
                             AND approval_escalated_at IS NULL
                            THEN 1
                            ELSE 0
                        END
                    ) AS escalation_due_jobs,
                    SUM(
                        CASE
                            WHEN status = 'waiting_approval'
                             AND approval_escalated_at IS NOT NULL
                            THEN 1
                            ELSE 0
                        END
                    ) AS escalated_approval_jobs,
                    MAX(updated_at) AS last_job_update_at
                FROM queue_jobs
                """
                ,
                (timestamp, timestamp),
            ).fetchone()
        return dict(row)

    def find_correlated_incident(
        self,
        fingerprints: list["CorrelationFingerprint"],
        *,
        observed_at: datetime,
        window: timedelta,
        workspace: str,
    ) -> Optional[dict[str, Any]]:
        if not fingerprints:
            return None

        window_start = observed_at - window
        window_start_iso = window_start.isoformat()
        observed_at_iso = observed_at.isoformat()

        with self._connection() as conn:
            for fingerprint in fingerprints:
                row = conn.execute(
                    """
                    SELECT
                        incidents.id AS incident_id,
                        incidents.incident_key,
                        incidents.case_status,
                        incident_fingerprints.strategy,
                        incident_fingerprints.fingerprint,
                        incident_fingerprints.values_json
                    FROM incident_fingerprints
                    JOIN incidents ON incidents.id = incident_fingerprints.incident_id
                    WHERE incident_fingerprints.fingerprint = ?
                      AND incidents.workspace = ?
                      AND incident_fingerprints.observed_at BETWEEN ? AND ?
                    ORDER BY incident_fingerprints.observed_at DESC, incident_fingerprints.id DESC
                    LIMIT 1
                    """,
                    (
                        fingerprint.fingerprint,
                        normalize_workspace(workspace),
                        window_start_iso,
                        observed_at_iso,
                    ),
                ).fetchone()
                if row is None:
                    continue

                incident_id = int(row["incident_id"])
                related_alert_ids = self._collect_related_alert_ids(conn, incident_id)
                matched_alert_ids = [
                    matched_row["alert_id"]
                    for matched_row in conn.execute(
                        """
                        SELECT DISTINCT alert_id, observed_at, id
                        FROM incident_fingerprints
                        WHERE incident_id = ?
                          AND fingerprint = ?
                          AND observed_at BETWEEN ? AND ?
                        ORDER BY observed_at ASC, id ASC
                        """,
                        (
                            incident_id,
                            row["fingerprint"],
                            window_start_iso,
                            observed_at_iso,
                        ),
                    ).fetchall()
                ]
                return {
                    "incident_id": incident_id,
                    "incident_key": row["incident_key"] or f"incident-{related_alert_ids[0]}",
                    "case_status": row["case_status"],
                    "related_alert_ids": related_alert_ids,
                    "matched_alert_ids": matched_alert_ids,
                    "strategy": row["strategy"],
                    "fingerprint": row["fingerprint"],
                    "values": json.loads(row["values_json"]),
                }

        return None

    def get_incident_by_alert_id(self, alert_id: str) -> Optional[dict[str, Any]]:
        return self._get_incident(
            "WHERE (incident_lookup.alert_id = ? OR incidents.alert_id = ? OR incidents.latest_alert_id = ?)",
            (alert_id, alert_id, alert_id),
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
        with self._connection() as conn:
            row = conn.execute(
                f"""
                SELECT
                    incidents.id,
                    incidents.alert_id,
                    incidents.incident_key,
                    COALESCE(incidents.latest_alert_id, incidents.alert_id) AS latest_alert_id,
                    incidents.workspace,
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
                JOIN alerts ON alerts.alert_id = COALESCE(incidents.latest_alert_id, incidents.alert_id)
                LEFT JOIN incident_alerts AS incident_lookup ON incident_lookup.incident_id = incidents.id
                LEFT JOIN reports ON reports.incident_id = incidents.id
                {where_clause}
                GROUP BY incidents.id
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
        workspaces: Optional[Sequence[str]] = None,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > MAX_INCIDENT_LIST_LIMIT:
            raise ValueError(
                f"limit must be between 1 and {MAX_INCIDENT_LIST_LIMIT} inclusive"
            )

        with self._connection() as conn:
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
            scoped_workspaces = tuple(
                workspace
                for workspace in effective_workspaces(workspaces)
                if workspace != "*"
            )
            if scoped_workspaces:
                placeholders = ", ".join("?" for _ in scoped_workspaces)
                where_clauses.append(f"incidents.workspace IN ({placeholders})")
                params.extend(scoped_workspaces)

            where_sql = ""
            if where_clauses:
                where_sql = "WHERE " + " AND ".join(where_clauses)

            rows = conn.execute(
                f"""
                SELECT
                    incidents.id,
                    incidents.alert_id,
                    incidents.incident_key,
                    COALESCE(incidents.latest_alert_id, incidents.alert_id) AS latest_alert_id,
                    incidents.workspace,
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
                    COALESCE(note_summary.note_count, 0) AS note_count,
                    COALESCE(alert_summary.related_alert_count, 1) AS related_alert_count
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
                LEFT JOIN (
                    SELECT incident_id, COUNT(*) AS related_alert_count
                    FROM incident_alerts
                    GROUP BY incident_id
                ) AS alert_summary ON alert_summary.incident_id = incidents.id
                {where_sql}
                ORDER BY incidents.updated_at DESC, incidents.id DESC
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_incident_metrics(self) -> dict[str, Any]:
        with self._connection() as conn:
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
        result["workspace"] = normalize_workspace(result.get("workspace"))
        result["latest_alert_id"] = result.get("latest_alert_id") or result["alert_id"]
        result["triggered_actions"] = json.loads(result.pop("triggered_actions_json"))
        result["policy_reasoning"] = json.loads(result.pop("policy_reasoning_json"))
        result["alert"] = json.loads(result.pop("alert_json"))
        result["enriched_alert"] = json.loads(result.pop("enriched_json"))
        result["response"] = json.loads(result.pop("response_json"))
        result["related_alert_ids"] = self._collect_related_alert_ids(conn, int(result["id"]))
        if not result["related_alert_ids"]:
            result["related_alert_ids"] = [result["alert_id"]]
        result["related_alert_count"] = len(result["related_alert_ids"])
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
                SELECT event_id, category, actor, message, payload_json, previous_event_hash, event_hash, created_at
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
        incident_row = self._resolve_incident_row(conn, alert_id=alert_id)
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
                WHERE incident_id = ?
                  AND COALESCE(alert_id, '') = ?
                  AND correlation_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (incident_row["id"], alert_id, action_result.correlation_id),
            ).fetchone()
        if existing is None:
            existing = conn.execute(
                """
                SELECT id
                FROM action_results
                WHERE incident_id = ?
                  AND COALESCE(alert_id, '') = ?
                  AND action = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (incident_row["id"], alert_id, action_result.action.value),
            ).fetchone()

        if existing is None:
            conn.execute(
                """
                INSERT INTO action_results (
                    incident_id, alert_id, action, status, executed_at, details,
                    correlation_id, attempt_count, updated_at, raw_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_row["id"],
                    alert_id,
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
                SET alert_id = ?,
                    status = ?,
                    executed_at = ?,
                    details = ?,
                    correlation_id = ?,
                    attempt_count = ?,
                    updated_at = ?,
                    raw_json = ?
                WHERE id = ?
                """,
                (
                    alert_id,
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

        incident_status = self._derive_incident_status_from_payloads(
            [
                {"status": row["status"]}
                for row in conn.execute(
                    """
                    SELECT status
                    FROM action_results
                    WHERE incident_id = ?
                    """,
                    (incident_row["id"],),
                ).fetchall()
            ]
        )
        response_json = incident_row["response_json"]
        if str(incident_row["latest_alert_id"] or incident_row["alert_id"]) == alert_id:
            response_payload = json.loads(response_json)
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
            response_json = json.dumps(response_payload, ensure_ascii=False)

        conn.execute(
            """
            UPDATE incidents
            SET status = ?,
                response_json = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                incident_status,
                response_json,
                timestamp,
                int(incident_row["id"]),
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
        incident_row = self._resolve_incident_row(conn, alert_id=row["alert_id"])
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
        previous_event_hash = self._get_previous_audit_hash(conn, incident_id)
        event = IncidentAuditEvent(
            event_id=f"audit-{uuid4().hex}",
            category=category,
            actor=actor,
            message=message,
            payload=payload,
            previous_event_hash=previous_event_hash,
        )
        event = event.model_copy(
            update={
                "event_hash": self._build_audit_event_hash(
                    event,
                    alert_id=alert_id,
                    incident_id=incident_id,
                )
            }
        )
        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, incident_id, alert_id, category, actor, message, payload_json,
                previous_event_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                incident_id,
                alert_id,
                event.category,
                event.actor,
                event.message,
                json.dumps(event.payload, ensure_ascii=False),
                event.previous_event_hash,
                event.event_hash,
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

    @classmethod
    def _migrate_saved_filters_table(cls, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(saved_filters)").fetchall()
        }
        if "workspace" in columns:
            return

        default_workspace = normalize_workspace(None)
        conn.execute("ALTER TABLE saved_filters RENAME TO saved_filters_legacy")
        conn.execute(
            """
            CREATE TABLE saved_filters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace TEXT NOT NULL DEFAULT 'default',
                name TEXT NOT NULL,
                filters_json TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(workspace, name)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO saved_filters (id, workspace, name, filters_json, created_by, created_at, updated_at)
            SELECT id, ?, name, filters_json, created_by, created_at, updated_at
            FROM saved_filters_legacy
            """,
            (default_workspace,),
        )
        conn.execute("DROP TABLE saved_filters_legacy")

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
    def _parse_approval_state(value: Any) -> ActionApprovalState:
        if isinstance(value, ActionApprovalState):
            return value
        candidate = str(value or ActionApprovalState.NOT_REQUIRED.value).strip().lower()
        return ActionApprovalState(candidate)

    @staticmethod
    def _parse_string_list(value: Any) -> list[str]:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            try:
                loaded = json.loads(stripped)
            except json.JSONDecodeError:
                return [stripped]
        elif isinstance(value, list):
            loaded = value
        else:
            return []
        if not isinstance(loaded, list):
            return []
        return [str(item) for item in loaded if str(item).strip()]

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
            "workspace": normalize_workspace(row.get("workspace")),
            "filters": json.loads(row["filters_json"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _resolve_incident_row(
        self,
        conn: sqlite3.Connection,
        *,
        incident_id: Optional[int] = None,
        alert_id: Optional[str] = None,
        incident_key: Optional[str] = None,
        ticket_id: Optional[str] = None,
        workspace: Optional[str] = None,
    ) -> Optional[sqlite3.Row]:
        selector_conditions: list[str] = []
        prefix_conditions: list[str] = []
        selector_params: list[Any] = []
        prefix_params: list[Any] = []

        if incident_id is not None:
            selector_conditions.append("incidents.id = ?")
            selector_params.append(int(incident_id))
        if incident_key:
            selector_conditions.append("incidents.incident_key = ?")
            selector_params.append(incident_key)
        if ticket_id:
            selector_conditions.append("incidents.ticket_id = ?")
            selector_params.append(ticket_id)
        if workspace is not None:
            prefix_conditions.append("incidents.workspace = ?")
            prefix_params.append(normalize_workspace(workspace))
        if alert_id:
            selector_conditions.append(
                "(incidents.alert_id = ? OR incidents.latest_alert_id = ? OR incident_lookup.alert_id = ?)"
            )
            selector_params.extend((alert_id, alert_id, alert_id))

        if not selector_conditions:
            raise ValueError("At least one incident lookup selector is required.")

        where_clauses = [*prefix_conditions, f"({' OR '.join(selector_conditions)})"]

        return conn.execute(
            f"""
            SELECT incidents.*
            FROM incidents
            LEFT JOIN incident_alerts AS incident_lookup ON incident_lookup.incident_id = incidents.id
            WHERE {' AND '.join(where_clauses)}
                GROUP BY incidents.id
                ORDER BY incidents.updated_at DESC, incidents.id DESC
                LIMIT 1
                """,
            (*prefix_params, *selector_params),
        ).fetchone()

    def _collect_related_alert_ids(
        self,
        conn: sqlite3.Connection,
        incident_id: int,
    ) -> list[str]:
        rows = conn.execute(
            """
            SELECT alert_id
            FROM incident_alerts
            WHERE incident_id = ?
            ORDER BY linked_at ASC, id ASC
            """,
            (incident_id,),
        ).fetchall()
        return [row["alert_id"] for row in rows]

    def _queue_request_from_row(self, row: sqlite3.Row) -> QueuedActionRequest:
        request = QueuedActionRequest.model_validate(json.loads(row["request_json"]))
        return request.model_copy(
            update={
                "requires_approval": bool(row["requires_approval"]),
                "approval_state": self._parse_approval_state(row["approval_state"]),
                "approval_reason": row["approval_reason"],
                "approval_comment": row["approval_comment"],
                "approved_by": row["approved_by"],
                "approved_at": self._parse_datetime(row["approved_at"]),
                "approval_due_at": self._parse_datetime(row["approval_due_at"]),
                "approval_escalates_at": self._parse_datetime(row["approval_escalates_at"]),
                "escalation_targets": self._parse_string_list(row["escalation_targets_json"]),
                "approval_escalated_at": self._parse_datetime(row["approval_escalated_at"]),
                "rollback_requested_by": row["rollback_requested_by"],
                "rollback_requested_at": self._parse_datetime(row["rollback_requested_at"]),
            }
        )

    def _get_previous_audit_hash(self, conn: sqlite3.Connection, incident_id: int) -> Optional[str]:
        row = conn.execute(
            """
            SELECT event_hash
            FROM audit_events
            WHERE incident_id = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        return row["event_hash"]

    @staticmethod
    def _build_audit_event_hash(
        event: IncidentAuditEvent,
        *,
        alert_id: str,
        incident_id: int,
    ) -> str:
        payload = {
            "event_id": event.event_id,
            "alert_id": alert_id,
            "incident_id": incident_id,
            "category": event.category,
            "actor": event.actor,
            "message": event.message,
            "payload": event.payload,
            "previous_event_hash": event.previous_event_hash,
            "created_at": event.created_at.isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        return digest.hexdigest()

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
            "previous_event_hash": event.previous_event_hash,
            "event_hash": event.event_hash,
            "created_at": event.created_at.isoformat(),
        }
        with self._audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
