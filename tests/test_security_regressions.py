from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

import api.app as api_app
from a2a.schemas import (
    AgentRegistrationRequest,
    MessageCreateRequest,
    TaskClaimRequest,
    TaskCreateRequest,
    WorkspaceCreateRequest,
)
from alert_generator.generator import generate_alert
from security import (
    ROLE_A2A_ADMIN,
    ROLE_A2A_AGENT,
    ROLE_A2A_READ,
    ROLE_INCIDENT_PROCESS,
    ROLE_INCIDENT_READ,
    authenticate_token,
)
from api.schemas import ProcessAlertRequest
from services.workflow_service import SoarWorkflowService


def _build_default_auth_tokens() -> list[dict]:
    return [
        {
            "token": "incident-process-token",
            "principal_id": "incident-processor",
            "principal_type": "user",
            "roles": [ROLE_INCIDENT_PROCESS],
            "workspaces": ["*"],
        },
        {
            "token": "incident-read-token",
            "principal_id": "incident-reader",
            "principal_type": "user",
            "roles": [ROLE_INCIDENT_READ],
            "workspaces": ["*"],
        },
        {
            "token": "a2a-admin-token",
            "principal_id": "a2a-admin",
            "principal_type": "user",
            "roles": [ROLE_A2A_ADMIN, ROLE_A2A_READ],
            "workspaces": ["*"],
        },
        {
            "token": "leader-agent-token",
            "principal_id": "leader-agent",
            "principal_type": "agent",
            "roles": [ROLE_A2A_AGENT],
            "workspaces": ["triage-room"],
            "agent_id": "leader-agent",
        },
        {
            "token": "worker-agent-token",
            "principal_id": "worker-agent",
            "principal_type": "agent",
            "roles": [ROLE_A2A_AGENT],
            "workspaces": ["triage-room"],
            "agent_id": "worker-agent",
        },
        {
            "token": "ghost-agent-token",
            "principal_id": "ghost-agent",
            "principal_type": "agent",
            "roles": [ROLE_A2A_AGENT],
            "workspaces": ["triage-room"],
            "agent_id": "ghost-agent",
        },
    ]


def test_incident_api_requires_auth_and_redacts_sensitive_fields(
    tmp_path: Path,
    monkeypatch,
    auth_token_config_factory,
):
    auth_token_config_factory(_build_default_auth_tokens())
    workflow = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "incident-api.db",
        report_output_dir=tmp_path / "reports",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: workflow)
    alert = generate_alert(scenario="mixed", seed=4242)
    payload = ProcessAlertRequest(alert=alert, generate_report=False, export_pdf=False)

    with pytest.raises(HTTPException) as exc_info:
        api_app.process_incident(payload)
    assert exc_info.value.status_code == 401

    created = api_app.process_incident(
        payload,
        principal=authenticate_token("incident-process-token"),
    )
    assert created.response.enriched_alert.original_alert.username == "[redacted]"
    assert created.response.enriched_alert.original_alert.command_line == "[redacted]"
    assert created.response.enriched_alert.original_alert.file_hash == "0" * len(alert.file_hash)

    incident = api_app.get_incident_by_alert_id(
        alert.alert_id,
        principal=authenticate_token("incident-read-token"),
    )
    assert incident.alert.username == "[redacted]"
    assert incident.alert.command_line == "[redacted]"
    assert incident.alert.file_hash == "0" * len(alert.file_hash)


def test_a2a_api_blocks_spoofing_cross_inbox_access_and_health_leaks(
    tmp_path: Path,
    monkeypatch,
    auth_token_config_factory,
):
    auth_token_config_factory(_build_default_auth_tokens())
    monkeypatch.setenv("SOAR_A2A_DB_PATH", str(tmp_path / "a2a-security.db"))
    api_app.get_a2a_service.cache_clear()

    admin_principal = authenticate_token("a2a-admin-token")
    leader_principal = authenticate_token("leader-agent-token")
    worker_principal = authenticate_token("worker-agent-token")
    ghost_principal = authenticate_token("ghost-agent-token")

    workspace = api_app.ensure_workspace(
        WorkspaceCreateRequest(workspace="triage-room"),
        principal=admin_principal,
    )
    assert workspace.workspace == "triage-room"

    for agent_id, platform in (("leader-agent", "codex"), ("worker-agent", "claude")):
        registered = api_app.register_agent(
            AgentRegistrationRequest(
                workspace="triage-room",
                agent_id=agent_id,
                platform=platform,
                role="worker",
                capabilities=["analysis"],
            ),
            principal=admin_principal,
        )
        assert registered.agent_id == agent_id

    task = api_app.create_task(
        TaskCreateRequest(
            workspace="triage-room",
            title="Investigate alert",
            description="Security regression test",
            requested_by="leader-agent",
            priority="high",
            labels=["security"],
        ),
        principal=leader_principal,
    )
    task_id = task.task_id

    message = api_app.post_message(
        MessageCreateRequest(
            workspace="triage-room",
            sender_agent="leader-agent",
            recipient_agent="worker-agent",
            task_id=task_id,
            kind="brief",
            content="Only the assigned worker should read this.",
        ),
        principal=leader_principal,
    )
    assert message.task_id == task_id

    with pytest.raises(HTTPException) as exc_info:
        api_app.poll_messages(workspace="triage-room", agent_id="worker-agent", limit=10)
    assert exc_info.value.status_code == 401

    with pytest.raises(HTTPException) as exc_info:
        api_app.poll_messages(
            workspace="triage-room",
            agent_id="worker-agent",
            limit=10,
            principal=leader_principal,
        )
    assert exc_info.value.status_code == 403

    with pytest.raises(HTTPException) as exc_info:
        api_app.post_message(
            MessageCreateRequest(
                workspace="triage-room",
                sender_agent="worker-agent",
                recipient_agent="leader-agent",
                task_id=task_id,
                kind="brief",
                content="spoof",
            ),
            principal=leader_principal,
        )
    assert exc_info.value.status_code == 403

    with pytest.raises(HTTPException) as exc_info:
        api_app.post_message(
            MessageCreateRequest(
                workspace="triage-room",
                sender_agent="ghost-agent",
                recipient_agent="leader-agent",
                task_id=task_id,
                kind="brief",
                content="ghost",
            ),
            principal=ghost_principal,
        )
    assert exc_info.value.status_code == 409

    with pytest.raises(HTTPException) as exc_info:
        api_app.claim_task(
            task_id,
            TaskClaimRequest(agent_id="ghost-agent"),
            principal=ghost_principal,
        )
    assert exc_info.value.status_code == 409

    worker_inbox = api_app.poll_messages(
        workspace="triage-room",
        agent_id="worker-agent",
        limit=10,
        principal=worker_principal,
    )
    assert len(worker_inbox) == 1

    with pytest.raises(HTTPException) as exc_info:
        api_app.a2a_health()
    assert exc_info.value.status_code == 401

    health = api_app.a2a_health(principal=admin_principal)
    assert "db_path" not in health


def test_report_generator_escapes_alert_controlled_html_payloads(tmp_path: Path):
    payload = '<img src=x onerror="alert(1)">'
    workflow = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "report-xss.db",
        report_output_dir=tmp_path / "reports",
    )
    alert = generate_alert(scenario="benign", seed=999)
    alert.detection_name = payload
    alert.command_line = payload

    result = workflow.process_alert(alert, generate_report=True, export_pdf=False)
    markdown_content = result.artifacts.markdown_path.read_text(encoding="utf-8")
    html_content = result.artifacts.html_path.read_text(encoding="utf-8")

    assert payload not in markdown_content
    assert payload not in html_content
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in markdown_content
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html_content
