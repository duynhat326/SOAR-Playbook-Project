from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from a2a.schemas import (
    AgentRecord,
    AgentRegistrationRequest,
    ArtifactCreateRequest,
    ArtifactRecord,
    MessageCreateRequest,
    MessageRecord,
    TaskClaimRequest,
    TaskCompleteRequest,
    TaskCreateRequest,
    TaskRecord,
    TimelineEvent,
    WorkspaceCreateRequest,
    WorkspaceRecord,
)
from a2a.storage import A2ARepository

DEFAULT_DB_PATH = Path("output") / "a2a" / "a2a_bus.db"


def resolve_db_path(raw_path: Optional[str | Path] = None) -> Path:
    if raw_path is not None:
        return Path(raw_path)
    env_path = os.getenv("SOAR_A2A_DB_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


class A2AService:
    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        self.db_path = resolve_db_path(db_path)
        self._repo = A2ARepository(self.db_path)

    def ensure_workspace(self, request: WorkspaceCreateRequest) -> WorkspaceRecord:
        return WorkspaceRecord.model_validate(self._repo.ensure_workspace(request.workspace))

    def register_agent(self, request: AgentRegistrationRequest) -> AgentRecord:
        return AgentRecord.model_validate(
            self._repo.register_agent(
                workspace=request.workspace,
                agent_id=request.agent_id,
                platform=request.platform,
                role=request.role,
                status=request.status,
                capabilities=request.capabilities,
                metadata=request.metadata,
            )
        )

    def heartbeat_agent(self, agent_id: str, status: str) -> AgentRecord:
        return AgentRecord.model_validate(self._repo.heartbeat_agent(agent_id, status))

    def list_agents(self, workspace: str) -> list[AgentRecord]:
        return [AgentRecord.model_validate(item) for item in self._repo.list_agents(workspace)]

    def create_task(self, request: TaskCreateRequest) -> TaskRecord:
        return TaskRecord.model_validate(
            self._repo.create_task(
                workspace=request.workspace,
                title=request.title,
                description=request.description,
                requested_by=request.requested_by,
                assigned_to=request.assigned_to,
                priority=request.priority,
                labels=request.labels,
            )
        )

    def list_tasks(self, workspace: str, status: Optional[str] = None) -> list[TaskRecord]:
        return [TaskRecord.model_validate(item) for item in self._repo.list_tasks(workspace, status)]

    def claim_task(self, task_id: str, request: TaskClaimRequest) -> TaskRecord:
        return TaskRecord.model_validate(self._repo.claim_task(task_id, request.agent_id))

    def complete_task(self, task_id: str, request: TaskCompleteRequest) -> TaskRecord:
        return TaskRecord.model_validate(
            self._repo.complete_task(task_id, request.agent_id, request.result_summary)
        )

    def post_message(self, request: MessageCreateRequest) -> MessageRecord:
        return MessageRecord.model_validate(
            self._repo.post_message(
                workspace=request.workspace,
                sender_agent=request.sender_agent,
                recipient_agent=request.recipient_agent,
                task_id=request.task_id,
                kind=request.kind,
                content=request.content,
                metadata=request.metadata,
            )
        )

    def poll_messages(
        self,
        *,
        workspace: str,
        agent_id: str,
        limit: int = 20,
        after: Optional[str] = None,
    ) -> list[MessageRecord]:
        return [
            MessageRecord.model_validate(item)
            for item in self._repo.poll_messages(
                workspace=workspace,
                agent_id=agent_id,
                limit=limit,
                after=after,
            )
        ]

    def publish_artifact(self, request: ArtifactCreateRequest) -> ArtifactRecord:
        return ArtifactRecord.model_validate(
            self._repo.create_artifact(
                workspace=request.workspace,
                author_agent=request.author_agent,
                task_id=request.task_id,
                message_id=request.message_id,
                kind=request.kind,
                uri=request.uri,
                summary=request.summary,
            )
        )

    def timeline(self, workspace: str, limit: int = 50) -> list[TimelineEvent]:
        return [TimelineEvent.model_validate(item) for item in self._repo.timeline(workspace, limit)]
