from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Optional

from psycopg.types.json import Jsonb

from storage.postgres import PostgresDatabase, resolve_database_url

_A2A_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS workspaces (
        workspace TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        workspace TEXT NOT NULL REFERENCES workspaces(workspace) ON DELETE CASCADE,
        platform TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        capabilities_json JSONB NOT NULL,
        metadata_json JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        heartbeat_at TIMESTAMPTZ NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        workspace TEXT NOT NULL REFERENCES workspaces(workspace) ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        assigned_to TEXT,
        status TEXT NOT NULL,
        priority TEXT NOT NULL,
        labels_json JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        claimed_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        result_summary TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT PRIMARY KEY,
        workspace TEXT NOT NULL REFERENCES workspaces(workspace) ON DELETE CASCADE,
        task_id TEXT REFERENCES tasks(task_id) ON DELETE SET NULL,
        sender_agent TEXT NOT NULL,
        recipient_agent TEXT NOT NULL,
        kind TEXT NOT NULL,
        content TEXT NOT NULL,
        metadata_json JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        artifact_id TEXT PRIMARY KEY,
        workspace TEXT NOT NULL REFERENCES workspaces(workspace) ON DELETE CASCADE,
        task_id TEXT REFERENCES tasks(task_id) ON DELETE SET NULL,
        message_id TEXT REFERENCES messages(message_id) ON DELETE SET NULL,
        author_agent TEXT NOT NULL,
        kind TEXT NOT NULL,
        uri TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline_events (
        event_id TEXT PRIMARY KEY,
        workspace TEXT NOT NULL REFERENCES workspaces(workspace) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        actor_agent TEXT,
        task_id TEXT,
        message_id TEXT,
        artifact_id TEXT,
        payload_json JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_agents_workspace ON agents(workspace, status)",
    "CREATE INDEX IF NOT EXISTS idx_tasks_workspace ON tasks(workspace, status, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_messages_workspace ON messages(workspace, recipient_agent, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_timeline_workspace ON timeline_events(workspace, created_at DESC)",
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class A2APostgresRepository:
    def __init__(self, db_url: Optional[str] = None) -> None:
        self.db_url = resolve_database_url(db_url, preferred_env="SOAR_A2A_DB_URL")
        self.db_path = self.db_url
        self._db = PostgresDatabase(self.db_url, _A2A_SCHEMA)

    @staticmethod
    def _dump_json(payload: Any) -> Jsonb:
        normalized = payload if payload is not None else {}
        return Jsonb(json.loads(json.dumps(normalized, ensure_ascii=True, sort_keys=True)))

    @staticmethod
    def _load_json(payload: Any, default: Any) -> Any:
        if payload is None:
            return default
        if isinstance(payload, (dict, list)):
            return payload
        return json.loads(payload)

    @staticmethod
    def _serialize_value(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
        return value

    def _ensure_workspace_conn(self, connection: Any, workspace: str) -> None:
        connection.execute(
            """
            INSERT INTO workspaces(workspace, created_at)
            VALUES(%s, %s)
            ON CONFLICT(workspace) DO NOTHING
            """,
            (workspace, utc_now()),
        )

    def _record_event(
        self,
        connection: Any,
        *,
        workspace: str,
        event_type: str,
        actor_agent: Optional[str] = None,
        task_id: Optional[str] = None,
        message_id: Optional[str] = None,
        artifact_id: Optional[str] = None,
        payload: Optional[dict[str, Any]] = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO timeline_events(
                event_id, workspace, event_type, actor_agent, task_id,
                message_id, artifact_id, payload_json, created_at
            )
            VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                f"evt-{uuid.uuid4().hex[:12]}",
                workspace,
                event_type,
                actor_agent,
                task_id,
                message_id,
                artifact_id,
                self._dump_json(payload or {}),
                utc_now(),
            ),
        )

    def _get_one(
        self,
        connection: Any,
        query: str,
        params: tuple[Any, ...],
    ) -> dict[str, Any]:
        row = connection.execute(query, params).fetchone()
        if row is None:
            raise ValueError("Requested record was not found.")
        return dict(row)

    def _deserialize_workspace(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "workspace": row["workspace"],
            "created_at": self._serialize_value(row["created_at"]),
        }

    def _deserialize_agent(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "agent_id": row["agent_id"],
            "workspace": row["workspace"],
            "platform": row["platform"],
            "role": row["role"],
            "status": row["status"],
            "capabilities": self._load_json(row["capabilities_json"], []),
            "metadata": self._load_json(row["metadata_json"], {}),
            "created_at": self._serialize_value(row["created_at"]),
            "heartbeat_at": self._serialize_value(row["heartbeat_at"]),
        }

    def _deserialize_task(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "task_id": row["task_id"],
            "workspace": row["workspace"],
            "title": row["title"],
            "description": row["description"],
            "requested_by": row["requested_by"],
            "assigned_to": row["assigned_to"],
            "status": row["status"],
            "priority": row["priority"],
            "labels": self._load_json(row["labels_json"], []),
            "created_at": self._serialize_value(row["created_at"]),
            "claimed_at": self._serialize_value(row["claimed_at"]),
            "completed_at": self._serialize_value(row["completed_at"]),
            "result_summary": row["result_summary"],
        }

    def _deserialize_message(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "message_id": row["message_id"],
            "workspace": row["workspace"],
            "task_id": row["task_id"],
            "sender_agent": row["sender_agent"],
            "recipient_agent": None if row["recipient_agent"] == "*" else row["recipient_agent"],
            "kind": row["kind"],
            "content": row["content"],
            "metadata": self._load_json(row["metadata_json"], {}),
            "created_at": self._serialize_value(row["created_at"]),
        }

    def _deserialize_artifact(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "artifact_id": row["artifact_id"],
            "workspace": row["workspace"],
            "task_id": row["task_id"],
            "message_id": row["message_id"],
            "author_agent": row["author_agent"],
            "kind": row["kind"],
            "uri": row["uri"],
            "summary": row["summary"],
            "created_at": self._serialize_value(row["created_at"]),
        }

    def _deserialize_event(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": row["event_id"],
            "workspace": row["workspace"],
            "event_type": row["event_type"],
            "actor_agent": row["actor_agent"],
            "task_id": row["task_id"],
            "message_id": row["message_id"],
            "artifact_id": row["artifact_id"],
            "payload": self._load_json(row["payload_json"], {}),
            "created_at": self._serialize_value(row["created_at"]),
        }

    def ensure_workspace(self, workspace: str) -> dict[str, Any]:
        with self._db.connect() as connection:
            self._ensure_workspace_conn(connection, workspace)
            self._record_event(
                connection,
                workspace=workspace,
                event_type="workspace.ready",
                payload={"workspace": workspace},
            )
            row = self._get_one(
                connection,
                "SELECT workspace, created_at FROM workspaces WHERE workspace = %s",
                (workspace,),
            )
            return self._deserialize_workspace(row)

    def register_agent(
        self,
        *,
        workspace: str,
        platform: str,
        role: str,
        status: str,
        capabilities: list[str],
        metadata: dict[str, Any],
        agent_id: Optional[str] = None,
    ) -> dict[str, Any]:
        agent_id = agent_id or f"{platform}-{uuid.uuid4().hex[:8]}"
        now = utc_now()
        with self._db.connect() as connection:
            self._ensure_workspace_conn(connection, workspace)
            connection.execute(
                """
                INSERT INTO agents(
                    agent_id, workspace, platform, role, status,
                    capabilities_json, metadata_json, created_at, heartbeat_at
                )
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(agent_id) DO UPDATE SET
                    workspace = EXCLUDED.workspace,
                    platform = EXCLUDED.platform,
                    role = EXCLUDED.role,
                    status = EXCLUDED.status,
                    capabilities_json = EXCLUDED.capabilities_json,
                    metadata_json = EXCLUDED.metadata_json,
                    heartbeat_at = EXCLUDED.heartbeat_at
                """,
                (
                    agent_id,
                    workspace,
                    platform,
                    role,
                    status,
                    self._dump_json(capabilities),
                    self._dump_json(metadata),
                    now,
                    now,
                ),
            )
            self._record_event(
                connection,
                workspace=workspace,
                event_type="agent.registered",
                actor_agent=agent_id,
                payload={"platform": platform, "role": role},
            )
            row = self._get_one(
                connection,
                "SELECT * FROM agents WHERE agent_id = %s",
                (agent_id,),
            )
            return self._deserialize_agent(row)

    def heartbeat_agent(self, agent_id: str, status: str) -> dict[str, Any]:
        with self._db.connect() as connection:
            row = self._get_one(
                connection,
                "SELECT * FROM agents WHERE agent_id = %s",
                (agent_id,),
            )
            connection.execute(
                """
                UPDATE agents
                SET status = %s, heartbeat_at = %s
                WHERE agent_id = %s
                """,
                (status, utc_now(), agent_id),
            )
            self._record_event(
                connection,
                workspace=row["workspace"],
                event_type="agent.heartbeat",
                actor_agent=agent_id,
                payload={"status": status},
            )
            updated = self._get_one(
                connection,
                "SELECT * FROM agents WHERE agent_id = %s",
                (agent_id,),
            )
            return self._deserialize_agent(updated)

    def list_agents(self, workspace: str) -> list[dict[str, Any]]:
        with self._db.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM agents
                WHERE workspace = %s
                ORDER BY heartbeat_at DESC, agent_id ASC
                """,
                (workspace,),
            ).fetchall()
            return [self._deserialize_agent(dict(row)) for row in rows]

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        with self._db.connect() as connection:
            row = self._get_one(
                connection,
                "SELECT * FROM agents WHERE agent_id = %s",
                (agent_id,),
            )
            return self._deserialize_agent(row)

    def create_task(
        self,
        *,
        workspace: str,
        title: str,
        description: str,
        requested_by: str,
        assigned_to: Optional[str],
        priority: str,
        labels: list[str],
    ) -> dict[str, Any]:
        task_id = f"task-{uuid.uuid4().hex[:10]}"
        with self._db.connect() as connection:
            self._ensure_workspace_conn(connection, workspace)
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, workspace, title, description, requested_by,
                    assigned_to, status, priority, labels_json, created_at
                )
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    task_id,
                    workspace,
                    title,
                    description,
                    requested_by,
                    assigned_to,
                    "in_progress" if assigned_to else "open",
                    priority,
                    self._dump_json(labels),
                    utc_now(),
                ),
            )
            self._record_event(
                connection,
                workspace=workspace,
                event_type="task.created",
                actor_agent=requested_by,
                task_id=task_id,
                payload={"title": title, "assigned_to": assigned_to, "priority": priority},
            )
            row = self._get_one(
                connection,
                "SELECT * FROM tasks WHERE task_id = %s",
                (task_id,),
            )
            return self._deserialize_task(row)

    def list_tasks(self, workspace: str, status: Optional[str] = None) -> list[dict[str, Any]]:
        with self._db.connect() as connection:
            if status:
                rows = connection.execute(
                    """
                    SELECT * FROM tasks
                    WHERE workspace = %s AND status = %s
                    ORDER BY created_at DESC
                    """,
                    (workspace, status),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM tasks
                    WHERE workspace = %s
                    ORDER BY created_at DESC
                    """,
                    (workspace,),
                ).fetchall()
            return [self._deserialize_task(dict(row)) for row in rows]

    def get_task(self, task_id: str) -> dict[str, Any]:
        with self._db.connect() as connection:
            row = self._get_one(
                connection,
                "SELECT * FROM tasks WHERE task_id = %s",
                (task_id,),
            )
            return self._deserialize_task(row)

    def claim_task(self, task_id: str, agent_id: str) -> dict[str, Any]:
        with self._db.connect() as connection:
            row = self._get_one(
                connection,
                "SELECT * FROM tasks WHERE task_id = %s",
                (task_id,),
            )
            task = self._deserialize_task(row)
            if task["status"] == "completed":
                raise ValueError(f"Task {task_id} is already completed.")
            if task["assigned_to"] and task["assigned_to"] != agent_id:
                raise ValueError(f"Task {task_id} is already claimed by {task['assigned_to']}.")

            connection.execute(
                """
                UPDATE tasks
                SET assigned_to = %s, status = 'in_progress', claimed_at = COALESCE(claimed_at, %s)
                WHERE task_id = %s
                """,
                (agent_id, utc_now(), task_id),
            )
            self._record_event(
                connection,
                workspace=task["workspace"],
                event_type="task.claimed",
                actor_agent=agent_id,
                task_id=task_id,
                payload={"task_id": task_id},
            )
            updated = self._get_one(
                connection,
                "SELECT * FROM tasks WHERE task_id = %s",
                (task_id,),
            )
            return self._deserialize_task(updated)

    def complete_task(self, task_id: str, agent_id: str, result_summary: Optional[str]) -> dict[str, Any]:
        with self._db.connect() as connection:
            row = self._get_one(
                connection,
                "SELECT * FROM tasks WHERE task_id = %s",
                (task_id,),
            )
            task = self._deserialize_task(row)
            if task["assigned_to"] != agent_id:
                raise ValueError(f"Task {task_id} is not assigned to {agent_id}.")

            connection.execute(
                """
                UPDATE tasks
                SET status = 'completed', completed_at = %s, result_summary = %s
                WHERE task_id = %s
                """,
                (utc_now(), result_summary, task_id),
            )
            self._record_event(
                connection,
                workspace=task["workspace"],
                event_type="task.completed",
                actor_agent=agent_id,
                task_id=task_id,
                payload={"result_summary": result_summary},
            )
            updated = self._get_one(
                connection,
                "SELECT * FROM tasks WHERE task_id = %s",
                (task_id,),
            )
            return self._deserialize_task(updated)

    def post_message(
        self,
        *,
        workspace: str,
        sender_agent: str,
        recipient_agent: Optional[str],
        task_id: Optional[str],
        kind: str,
        content: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        message_id = f"msg-{uuid.uuid4().hex[:10]}"
        recipient_value = recipient_agent or "*"
        with self._db.connect() as connection:
            self._ensure_workspace_conn(connection, workspace)
            connection.execute(
                """
                INSERT INTO messages(
                    message_id, workspace, task_id, sender_agent,
                    recipient_agent, kind, content, metadata_json, created_at
                )
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    message_id,
                    workspace,
                    task_id,
                    sender_agent,
                    recipient_value,
                    kind,
                    content,
                    self._dump_json(metadata),
                    utc_now(),
                ),
            )
            self._record_event(
                connection,
                workspace=workspace,
                event_type="message.posted",
                actor_agent=sender_agent,
                task_id=task_id,
                message_id=message_id,
                payload={"recipient_agent": recipient_agent, "kind": kind},
            )
            row = self._get_one(
                connection,
                "SELECT * FROM messages WHERE message_id = %s",
                (message_id,),
            )
            return self._deserialize_message(row)

    def poll_messages(
        self,
        *,
        workspace: str,
        agent_id: str,
        limit: int,
        after: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT * FROM messages
            WHERE workspace = %s
              AND recipient_agent IN (%s, '*')
              AND sender_agent != %s
        """
        params: list[Any] = [workspace, agent_id, agent_id]
        if after:
            query += " AND created_at > %s"
            params.append(after)
        query += " ORDER BY created_at ASC LIMIT %s"
        params.append(limit)

        with self._db.connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
            return [self._deserialize_message(dict(row)) for row in rows]

    def create_artifact(
        self,
        *,
        workspace: str,
        author_agent: str,
        task_id: Optional[str],
        message_id: Optional[str],
        kind: str,
        uri: str,
        summary: str,
    ) -> dict[str, Any]:
        artifact_id = f"art-{uuid.uuid4().hex[:10]}"
        with self._db.connect() as connection:
            self._ensure_workspace_conn(connection, workspace)
            connection.execute(
                """
                INSERT INTO artifacts(
                    artifact_id, workspace, task_id, message_id,
                    author_agent, kind, uri, summary, created_at
                )
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    artifact_id,
                    workspace,
                    task_id,
                    message_id,
                    author_agent,
                    kind,
                    uri,
                    summary,
                    utc_now(),
                ),
            )
            self._record_event(
                connection,
                workspace=workspace,
                event_type="artifact.published",
                actor_agent=author_agent,
                task_id=task_id,
                message_id=message_id,
                artifact_id=artifact_id,
                payload={"kind": kind, "uri": uri},
            )
            row = self._get_one(
                connection,
                "SELECT * FROM artifacts WHERE artifact_id = %s",
                (artifact_id,),
            )
            return self._deserialize_artifact(row)

    def timeline(self, workspace: str, limit: int) -> list[dict[str, Any]]:
        with self._db.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM timeline_events
                WHERE workspace = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (workspace, limit),
            ).fetchall()
            return [self._deserialize_event(dict(row)) for row in rows]
