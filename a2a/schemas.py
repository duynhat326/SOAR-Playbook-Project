from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


AgentStatus = Literal["online", "busy", "offline"]
TaskStatus = Literal["open", "in_progress", "completed"]
PriorityLevel = Literal["low", "normal", "high", "critical"]


class WorkspaceCreateRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=100)


class WorkspaceRecord(BaseModel):
    workspace: str
    created_at: str


class AgentRegistrationRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=100)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=40)
    role: str = Field(default="worker", min_length=1, max_length=80)
    status: AgentStatus = "online"
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentHeartbeatRequest(BaseModel):
    status: AgentStatus = "online"


class AgentRecord(BaseModel):
    agent_id: str
    workspace: str
    platform: str
    role: str
    status: AgentStatus
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    heartbeat_at: str


class TaskCreateRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    requested_by: str = Field(min_length=1, max_length=120)
    assigned_to: Optional[str] = Field(default=None, min_length=1, max_length=120)
    priority: PriorityLevel = "normal"
    labels: list[str] = Field(default_factory=list)


class TaskClaimRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=120)


class TaskCompleteRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=120)
    result_summary: Optional[str] = Field(default=None, max_length=4000)


class TaskRecord(BaseModel):
    task_id: str
    workspace: str
    title: str
    description: str
    requested_by: str
    assigned_to: Optional[str] = None
    status: TaskStatus
    priority: PriorityLevel
    labels: list[str] = Field(default_factory=list)
    created_at: str
    claimed_at: Optional[str] = None
    completed_at: Optional[str] = None
    result_summary: Optional[str] = None


class MessageCreateRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=100)
    sender_agent: str = Field(min_length=1, max_length=120)
    recipient_agent: Optional[str] = Field(default=None, min_length=1, max_length=120)
    task_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    kind: str = Field(default="note", min_length=1, max_length=40)
    content: str = Field(min_length=1, max_length=12000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MessageRecord(BaseModel):
    message_id: str
    workspace: str
    task_id: Optional[str] = None
    sender_agent: str
    recipient_agent: Optional[str] = None
    kind: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class ArtifactCreateRequest(BaseModel):
    workspace: str = Field(min_length=1, max_length=100)
    author_agent: str = Field(min_length=1, max_length=120)
    task_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    message_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    kind: str = Field(default="file", min_length=1, max_length=40)
    uri: str = Field(min_length=1, max_length=1000)
    summary: str = Field(default="", max_length=4000)


class ArtifactRecord(BaseModel):
    artifact_id: str
    workspace: str
    task_id: Optional[str] = None
    message_id: Optional[str] = None
    author_agent: str
    kind: str
    uri: str
    summary: str
    created_at: str


class TimelineEvent(BaseModel):
    event_id: str
    workspace: str
    event_type: str
    actor_agent: Optional[str] = None
    task_id: Optional[str] = None
    message_id: Optional[str] = None
    artifact_id: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str
