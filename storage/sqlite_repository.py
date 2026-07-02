from __future__ import annotations

import json
import sqlite3
from datetime import datetime, UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from services.workflow_service import WorkflowResult

MAX_INCIDENT_LIST_LIMIT = 200


class SQLiteIncidentRepository:
    """SQLite-backed persistence for workflow executions."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = Path(db_path or Path("output") / "soar.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
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

                CREATE INDEX IF NOT EXISTS idx_incidents_ticket_id
                ON incidents(ticket_id);
                """
            )

    def save_workflow_result(self, result: "WorkflowResult") -> int:
        alert = result.alert
        enriched = result.enriched_alert
        response = result.response
        timestamp = self._utc_now()

        with self._connect() as conn:
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
                    ticket_id, status, completed_at, report_path,
                    triggered_actions_json, policy_reasoning_json, enriched_json,
                    response_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    detection_name=excluded.detection_name,
                    risk_score=excluded.risk_score,
                    risk_level=excluded.risk_level,
                    ticket_id=excluded.ticket_id,
                    status=excluded.status,
                    completed_at=excluded.completed_at,
                    report_path=excluded.report_path,
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
                    "completed",
                    response.completed_at.isoformat(),
                    response.report_path,
                    json.dumps(
                        [action.value for action in response.triggered_actions],
                        ensure_ascii=False,
                    ),
                    json.dumps(response.policy_reasoning, ensure_ascii=False),
                    self._dump_model(enriched),
                    self._dump_model(response),
                    timestamp,
                    timestamp,
                ),
            )

            incident_id = conn.execute(
                "SELECT id FROM incidents WHERE alert_id = ?",
                (alert.alert_id,),
            ).fetchone()["id"]

            conn.execute(
                "DELETE FROM action_results WHERE incident_id = ?",
                (incident_id,),
            )
            for action_result in response.action_results:
                conn.execute(
                    """
                    INSERT INTO action_results (
                        incident_id, action, status, executed_at, details, raw_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        action_result.action.value,
                        action_result.status,
                        action_result.executed_at.isoformat(),
                        action_result.details,
                        self._dump_model(action_result),
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

            conn.commit()

        return incident_id

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
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > MAX_INCIDENT_LIST_LIMIT:
            raise ValueError(
                f"limit must be between 1 and {MAX_INCIDENT_LIST_LIMIT} inclusive"
            )

        with self._connect() as conn:
            where_clauses: list[str] = []
            params: list[Any] = []

            if status is not None:
                where_clauses.append("status = ?")
                params.append(status)
            if risk_level is not None:
                where_clauses.append("risk_level = ?")
                params.append(risk_level)
            if hostname is not None:
                where_clauses.append("hostname = ?")
                params.append(hostname)
            if ticket_id is not None:
                where_clauses.append("ticket_id = ?")
                params.append(ticket_id)

            where_sql = ""
            if where_clauses:
                where_sql = "WHERE " + " AND ".join(where_clauses)

            rows = conn.execute(
                f"""
                SELECT
                    id, alert_id, hostname, detection_name, risk_score,
                    risk_level, ticket_id, status, completed_at, report_path
                FROM incidents
                {where_sql}
                ORDER BY id DESC
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
            return [dict(row) for row in rows]

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
            dict(action_row)
            for action_row in conn.execute(
                """
                SELECT action, status, executed_at, details
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
        return result

    @staticmethod
    def _dump_model(model: Any) -> str:
        return json.dumps(model.model_dump(mode="json"), ensure_ascii=False)

    @staticmethod
    def _path_to_str(path: Optional[Path]) -> Optional[str]:
        return str(path) if path is not None else None

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(UTC).isoformat()
