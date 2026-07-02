from pathlib import Path

import pytest

from a2a.schemas import (
    AgentRegistrationRequest,
    ArtifactCreateRequest,
    MessageCreateRequest,
    TaskClaimRequest,
    TaskCompleteRequest,
    TaskCreateRequest,
    WorkspaceCreateRequest,
)
from a2a.service import A2AService


def make_service(tmp_path: Path) -> A2AService:
    return A2AService(tmp_path / "a2a-test.db")


def test_a2a_service_supports_multi_agent_lifecycle(tmp_path: Path):
    service = make_service(tmp_path)
    workspace = service.ensure_workspace(WorkspaceCreateRequest(workspace="soc-war-room"))
    assert workspace.workspace == "soc-war-room"

    codex = service.register_agent(
        AgentRegistrationRequest(
            workspace="soc-war-room",
            agent_id="codex-lead",
            platform="codex",
            role="coordinator",
            capabilities=["plan", "review"],
        )
    )
    gemini = service.register_agent(
        AgentRegistrationRequest(
            workspace="soc-war-room",
            agent_id="gemini-worker",
            platform="gemini",
            role="worker",
            capabilities=["research"],
        )
    )

    task = service.create_task(
        TaskCreateRequest(
            workspace="soc-war-room",
            title="Map the enrichment pipeline",
            description="Document the flow and propose integration points.",
            requested_by=codex.agent_id,
            priority="high",
            labels=["architecture", "a2a"],
        )
    )
    assert task.status == "open"

    claimed = service.claim_task(task.task_id, TaskClaimRequest(agent_id=gemini.agent_id))
    assert claimed.status == "in_progress"
    assert claimed.assigned_to == gemini.agent_id

    note = service.post_message(
        MessageCreateRequest(
            workspace="soc-war-room",
            sender_agent=codex.agent_id,
            recipient_agent=gemini.agent_id,
            task_id=task.task_id,
            kind="brief",
            content="Focus on API extension points and keep the existing workflow unchanged.",
        )
    )
    assert note.task_id == task.task_id

    inbox = service.poll_messages(
        workspace="soc-war-room",
        agent_id=gemini.agent_id,
        limit=10,
    )
    assert len(inbox) == 1
    assert inbox[0].content.startswith("Focus on API extension points")

    artifact = service.publish_artifact(
        ArtifactCreateRequest(
            workspace="soc-war-room",
            author_agent=gemini.agent_id,
            task_id=task.task_id,
            kind="patch",
            uri="docs/a2a-collaboration.md",
            summary="Initial collaboration setup notes.",
        )
    )
    assert artifact.uri == "docs/a2a-collaboration.md"

    completed = service.complete_task(
        task.task_id,
        TaskCompleteRequest(
            agent_id=gemini.agent_id,
            result_summary="Integration points documented and handed back.",
        ),
    )
    assert completed.status == "completed"
    assert completed.result_summary is not None

    events = service.timeline("soc-war-room", 20)
    event_types = {event.event_type for event in events}
    assert "agent.registered" in event_types
    assert "task.created" in event_types
    assert "task.completed" in event_types
    assert "artifact.published" in event_types


def test_a2a_service_prevents_second_agent_from_stealing_claimed_task(tmp_path: Path):
    service = make_service(tmp_path)
    service.ensure_workspace(WorkspaceCreateRequest(workspace="shared"))
    owner = service.register_agent(
        AgentRegistrationRequest(workspace="shared", agent_id="codex-1", platform="codex")
    )
    other = service.register_agent(
        AgentRegistrationRequest(workspace="shared", agent_id="claude-1", platform="claude")
    )
    task = service.create_task(
        TaskCreateRequest(
            workspace="shared",
            title="Own the ticket",
            requested_by=owner.agent_id,
        )
    )

    service.claim_task(task.task_id, TaskClaimRequest(agent_id=owner.agent_id))

    with pytest.raises(ValueError, match="already claimed"):
        service.claim_task(task.task_id, TaskClaimRequest(agent_id=other.agent_id))
