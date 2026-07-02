from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from a2a.postgres_storage import A2APostgresRepository
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
from security import (
    ROLE_A2A_ADMIN,
    ROLE_A2A_AGENT,
    ROLE_A2A_READ,
    AuthenticatedPrincipal,
    AuthorizationError,
    ensure_agent_binding,
    ensure_roles,
    ensure_workspace_access,
)
from storage.postgres import is_postgres_target, resolve_database_url

DEFAULT_DB_PATH = Path("output") / "a2a" / "a2a_bus.db"


def resolve_db_target(raw_path: Optional[str | Path] = None) -> str | Path:
    if raw_path is not None:
        return raw_path

    explicit_postgres = os.getenv("SOAR_A2A_DB_URL") or os.getenv("SUPABASE_DB_URL")
    if explicit_postgres:
        return resolve_database_url(explicit_postgres, preferred_env="SOAR_A2A_DB_URL")

    env_path = os.getenv("SOAR_A2A_DB_PATH")
    if env_path:
        return Path(env_path)

    raise RuntimeError(
        "A2A persistence now expects Supabase Postgres. Set SOAR_A2A_DB_URL or SUPABASE_DB_URL."
    )


def resolve_db_path(raw_path: Optional[str | Path] = None) -> str | Path:
    return resolve_db_target(raw_path)


class A2AService:
    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        self.db_path = resolve_db_target(db_path)
        if is_postgres_target(self.db_path):
            self._repo = A2APostgresRepository(str(self.db_path))
        else:
            self._repo = A2ARepository(Path(self.db_path))

    def ensure_workspace(
        self,
        request: WorkspaceCreateRequest,
        *,
        principal: AuthenticatedPrincipal,
    ) -> WorkspaceRecord:
        ensure_roles(principal, ROLE_A2A_ADMIN)
        return WorkspaceRecord.model_validate(self._repo.ensure_workspace(request.workspace))

    def register_agent(
        self,
        request: AgentRegistrationRequest,
        *,
        principal: AuthenticatedPrincipal,
    ) -> AgentRecord:
        ensure_roles(principal, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, request.workspace)
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

    def heartbeat_agent(
        self,
        agent_id: str,
        status: str,
        *,
        principal: AuthenticatedPrincipal,
    ) -> AgentRecord:
        self._ensure_agent_actor(principal, agent_id)
        return AgentRecord.model_validate(self._repo.heartbeat_agent(agent_id, status))

    def list_agents(
        self,
        workspace: str,
        *,
        principal: AuthenticatedPrincipal,
    ) -> list[AgentRecord]:
        ensure_roles(principal, ROLE_A2A_READ, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, workspace)
        return [AgentRecord.model_validate(item) for item in self._repo.list_agents(workspace)]

    def create_task(
        self,
        request: TaskCreateRequest,
        *,
        principal: AuthenticatedPrincipal,
    ) -> TaskRecord:
        ensure_roles(principal, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, request.workspace)
        self._ensure_registered_agent(request.requested_by, request.workspace)
        if request.assigned_to is not None:
            self._ensure_registered_agent(request.assigned_to, request.workspace)
        if not principal.has_role(ROLE_A2A_ADMIN):
            self._ensure_agent_actor(principal, request.requested_by)
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

    def list_tasks(
        self,
        workspace: str,
        status: Optional[str] = None,
        *,
        principal: AuthenticatedPrincipal,
    ) -> list[TaskRecord]:
        ensure_roles(principal, ROLE_A2A_READ, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, workspace)
        return [TaskRecord.model_validate(item) for item in self._repo.list_tasks(workspace, status)]

    def claim_task(
        self,
        task_id: str,
        request: TaskClaimRequest,
        *,
        principal: AuthenticatedPrincipal,
    ) -> TaskRecord:
        ensure_roles(principal, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        task = self._repo.get_task(task_id)
        ensure_workspace_access(principal, task["workspace"])
        self._ensure_registered_agent(request.agent_id, task["workspace"])
        self._ensure_agent_actor(principal, request.agent_id)
        return TaskRecord.model_validate(self._repo.claim_task(task_id, request.agent_id))

    def complete_task(
        self,
        task_id: str,
        request: TaskCompleteRequest,
        *,
        principal: AuthenticatedPrincipal,
    ) -> TaskRecord:
        ensure_roles(principal, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        task = self._repo.get_task(task_id)
        ensure_workspace_access(principal, task["workspace"])
        self._ensure_registered_agent(request.agent_id, task["workspace"])
        self._ensure_agent_actor(principal, request.agent_id)
        return TaskRecord.model_validate(
            self._repo.complete_task(task_id, request.agent_id, request.result_summary)
        )

    def post_message(
        self,
        request: MessageCreateRequest,
        *,
        principal: AuthenticatedPrincipal,
    ) -> MessageRecord:
        ensure_roles(principal, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, request.workspace)
        self._ensure_registered_agent(request.sender_agent, request.workspace)
        if request.recipient_agent is not None:
            self._ensure_registered_agent(request.recipient_agent, request.workspace)
        if request.task_id is not None:
            task = self._repo.get_task(request.task_id)
            if task["workspace"] != request.workspace:
                raise ValueError(f"Task {request.task_id} does not belong to workspace {request.workspace}.")
        self._ensure_agent_actor(principal, request.sender_agent)
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
        principal: AuthenticatedPrincipal,
    ) -> list[MessageRecord]:
        ensure_roles(principal, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, workspace)
        self._ensure_registered_agent(agent_id, workspace)
        self._ensure_agent_actor(principal, agent_id)
        return [
            MessageRecord.model_validate(item)
            for item in self._repo.poll_messages(
                workspace=workspace,
                agent_id=agent_id,
                limit=limit,
                after=after,
            )
        ]

    def publish_artifact(
        self,
        request: ArtifactCreateRequest,
        *,
        principal: AuthenticatedPrincipal,
    ) -> ArtifactRecord:
        ensure_roles(principal, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, request.workspace)
        self._ensure_registered_agent(request.author_agent, request.workspace)
        if request.task_id is not None:
            task = self._repo.get_task(request.task_id)
            if task["workspace"] != request.workspace:
                raise ValueError(f"Task {request.task_id} does not belong to workspace {request.workspace}.")
        self._ensure_agent_actor(principal, request.author_agent)
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

    def timeline(
        self,
        workspace: str,
        limit: int = 50,
        *,
        principal: AuthenticatedPrincipal,
    ) -> list[TimelineEvent]:
        ensure_roles(principal, ROLE_A2A_READ, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)
        ensure_workspace_access(principal, workspace)
        return [TimelineEvent.model_validate(item) for item in self._repo.timeline(workspace, limit)]

    def _ensure_registered_agent(self, agent_id: str, workspace: str) -> None:
        agent = self._repo.get_agent(agent_id)
        if agent["workspace"] != workspace:
            raise ValueError(f"Agent {agent_id} does not belong to workspace {workspace}.")

    @staticmethod
    def _ensure_agent_actor(principal: AuthenticatedPrincipal, agent_id: str) -> None:
        if principal.has_role(ROLE_A2A_ADMIN):
            return
        ensure_roles(principal, ROLE_A2A_AGENT)
        if principal.principal_type != "agent":
            raise AuthorizationError("A2A agent operations require an authenticated agent principal.")
        ensure_agent_binding(principal, agent_id)
