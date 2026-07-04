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
from a2a.service import A2AService, resolve_db_target
from security import ROLE_A2A_AGENT


def make_service(tmp_path: Path) -> A2AService:
    return A2AService(tmp_path / "a2a-test.db")


def test_a2a_service_supports_multi_agent_lifecycle(
    tmp_path: Path,
    a2a_admin_principal,
    principal_factory,
):
    service = make_service(tmp_path)
    workspace = service.ensure_workspace(
        WorkspaceCreateRequest(workspace="soc-war-room"),
        principal=a2a_admin_principal,
    )
    assert workspace.workspace == "soc-war-room"

    codex = service.register_agent(
        AgentRegistrationRequest(
            workspace="soc-war-room",
            agent_id="codex-lead",
            platform="codex",
            role="coordinator",
            capabilities=["plan", "review"],
        ),
        principal=a2a_admin_principal,
    )
    gemini = service.register_agent(
        AgentRegistrationRequest(
            workspace="soc-war-room",
            agent_id="gemini-worker",
            platform="gemini",
            role="worker",
            capabilities=["research"],
        ),
        principal=a2a_admin_principal,
    )
    codex_principal = principal_factory(
        "codex-lead",
        principal_type="agent",
        agent_id=codex.agent_id,
        roles=[ROLE_A2A_AGENT],
        workspaces=["soc-war-room"],
    )
    gemini_principal = principal_factory(
        "gemini-worker",
        principal_type="agent",
        agent_id=gemini.agent_id,
        roles=[ROLE_A2A_AGENT],
        workspaces=["soc-war-room"],
    )

    task = service.create_task(
        TaskCreateRequest(
            workspace="soc-war-room",
            title="Map the enrichment pipeline",
            description="Document the flow and propose integration points.",
            requested_by=codex.agent_id,
            priority="high",
            labels=["architecture", "a2a"],
        ),
        principal=codex_principal,
    )
    assert task.status == "open"

    claimed = service.claim_task(
        task.task_id,
        TaskClaimRequest(agent_id=gemini.agent_id),
        principal=gemini_principal,
    )
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
        ),
        principal=codex_principal,
    )
    assert note.task_id == task.task_id

    inbox = service.poll_messages(
        workspace="soc-war-room",
        agent_id=gemini.agent_id,
        limit=10,
        principal=gemini_principal,
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
        ),
        principal=gemini_principal,
    )
    assert artifact.uri == "docs/a2a-collaboration.md"

    completed = service.complete_task(
        task.task_id,
        TaskCompleteRequest(
            agent_id=gemini.agent_id,
            result_summary="Integration points documented and handed back.",
        ),
        principal=gemini_principal,
    )
    assert completed.status == "completed"
    assert completed.result_summary is not None

    events = service.timeline("soc-war-room", 20, principal=a2a_admin_principal)
    event_types = {event.event_type for event in events}
    assert "agent.registered" in event_types
    assert "task.created" in event_types
    assert "task.completed" in event_types
    assert "artifact.published" in event_types


def test_a2a_service_prevents_second_agent_from_stealing_claimed_task(
    tmp_path: Path,
    a2a_admin_principal,
    principal_factory,
):
    service = make_service(tmp_path)
    service.ensure_workspace(
        WorkspaceCreateRequest(workspace="shared"),
        principal=a2a_admin_principal,
    )
    owner = service.register_agent(
        AgentRegistrationRequest(workspace="shared", agent_id="codex-1", platform="codex"),
        principal=a2a_admin_principal,
    )
    other = service.register_agent(
        AgentRegistrationRequest(workspace="shared", agent_id="claude-1", platform="claude"),
        principal=a2a_admin_principal,
    )
    owner_principal = principal_factory(
        "codex-1",
        principal_type="agent",
        agent_id=owner.agent_id,
        roles=[ROLE_A2A_AGENT],
        workspaces=["shared"],
    )
    other_principal = principal_factory(
        "claude-1",
        principal_type="agent",
        agent_id=other.agent_id,
        roles=[ROLE_A2A_AGENT],
        workspaces=["shared"],
    )
    task = service.create_task(
        TaskCreateRequest(
            workspace="shared",
            title="Own the ticket",
            requested_by=owner.agent_id,
        ),
        principal=owner_principal,
    )

    service.claim_task(
        task.task_id,
        TaskClaimRequest(agent_id=owner.agent_id),
        principal=owner_principal,
    )

    with pytest.raises(ValueError, match="already claimed"):
        service.claim_task(
            task.task_id,
            TaskClaimRequest(agent_id=other.agent_id),
            principal=other_principal,
        )


def test_resolve_db_target_prefers_local_a2a_path_over_shared_supabase_env(monkeypatch, tmp_path: Path):
    local_path = tmp_path / "a2a-local.db"
    monkeypatch.setenv("SOAR_A2A_DB_PATH", str(local_path))
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://shared.example.test/postgres")
    monkeypatch.delenv("SOAR_A2A_DB_URL", raising=False)

    assert resolve_db_target() == local_path
