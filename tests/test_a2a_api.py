from pathlib import Path

from a2a.schemas import (
    AgentRegistrationRequest,
    ArtifactCreateRequest,
    MessageCreateRequest,
    TaskClaimRequest,
    TaskCompleteRequest,
    TaskCreateRequest,
    WorkspaceCreateRequest,
)
from api.app import (
    a2a_health,
    claim_task,
    complete_task,
    create_task,
    ensure_workspace,
    get_a2a_service,
    list_agents,
    poll_messages,
    post_message,
    publish_artifact,
    register_agent,
    timeline,
)
from security import ROLE_A2A_AGENT


def test_a2a_api_end_to_end(tmp_path: Path, monkeypatch, a2a_admin_principal, principal_factory):
    monkeypatch.setenv("SOAR_A2A_DB_PATH", str(tmp_path / "a2a-api.db"))
    get_a2a_service.cache_clear()

    try:
        workspace = ensure_workspace(
            WorkspaceCreateRequest(workspace="triage-room"),
            principal=a2a_admin_principal,
        )
        assert workspace.workspace == "triage-room"

        codex = register_agent(
            AgentRegistrationRequest(
                workspace="triage-room",
                agent_id="codex-tab-1",
                platform="codex",
                role="lead",
                capabilities=["plan", "review"],
            ),
            principal=a2a_admin_principal,
        )
        claude = register_agent(
            AgentRegistrationRequest(
                workspace="triage-room",
                agent_id="claude-tab-1",
                platform="claude",
                role="worker",
                capabilities=["analysis"],
            ),
            principal=a2a_admin_principal,
        )
        codex_principal = principal_factory(
            "codex-tab-1",
            principal_type="agent",
            agent_id="codex-tab-1",
            roles=[ROLE_A2A_AGENT],
            workspaces=["triage-room"],
        )
        claude_principal = principal_factory(
            "claude-tab-1",
            principal_type="agent",
            agent_id="claude-tab-1",
            roles=[ROLE_A2A_AGENT],
            workspaces=["triage-room"],
        )
        assert codex.agent_id == "codex-tab-1"
        assert claude.agent_id == "claude-tab-1"

        task = create_task(
            TaskCreateRequest(
                workspace="triage-room",
                title="Review response policy",
                description="Check if A2A changes affect the workflow engine.",
                requested_by="codex-tab-1",
                priority="high",
                labels=["review"],
            ),
            principal=codex_principal,
        )
        claim = claim_task(
            task.task_id,
            TaskClaimRequest(agent_id="claude-tab-1"),
            principal=claude_principal,
        )
        assert claim.status == "in_progress"

        message = post_message(
            MessageCreateRequest(
                workspace="triage-room",
                sender_agent="codex-tab-1",
                recipient_agent="claude-tab-1",
                task_id=task.task_id,
                kind="brief",
                content="Keep the SOAR pipeline stable. Touch only the collaboration layer.",
            ),
            principal=codex_principal,
        )
        assert message.kind == "brief"

        inbox = poll_messages(
            workspace="triage-room",
            agent_id="claude-tab-1",
            limit=10,
            principal=claude_principal,
        )
        assert len(inbox) == 1

        artifact = publish_artifact(
            ArtifactCreateRequest(
                workspace="triage-room",
                author_agent="claude-tab-1",
                task_id=task.task_id,
                kind="report",
                uri="output/review.txt",
                summary="Behavioral review notes.",
            ),
            principal=claude_principal,
        )
        assert artifact.kind == "report"

        done = complete_task(
            task.task_id,
            TaskCompleteRequest(
                agent_id="claude-tab-1",
                result_summary="Reviewed and handed back to Codex.",
            ),
            principal=claude_principal,
        )
        assert done.status == "completed"

        event_types = {
            item.event_type
            for item in timeline(
                workspace="triage-room",
                limit=20,
                principal=a2a_admin_principal,
            )
        }
        assert "task.created" in event_types
        assert "message.posted" in event_types
        assert "artifact.published" in event_types

        agents = list_agents(workspace="triage-room", principal=a2a_admin_principal)
        assert len(agents) == 2
        health = a2a_health(principal=a2a_admin_principal)
        assert "db_path" not in health
    finally:
        get_a2a_service.cache_clear()
