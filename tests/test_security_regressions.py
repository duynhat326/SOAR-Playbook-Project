from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

import api.app as api_app
from alert_generator.generator import generate_alert
from api.schemas import ProcessAlertRequest
from security import ROLE_INCIDENT_PROCESS, ROLE_INCIDENT_READ, authenticate_token
from services.readiness_service import build_readiness_report
from services.workflow_service import SoarWorkflowService
from scripts.run_pentest import run_pentest


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

    with pytest.raises(HTTPException) as exc_info:
        api_app.get_incident_by_alert_id(
            alert.alert_id,
            include_sensitive=True,
            principal=authenticate_token("incident-read-token"),
        )
    assert exc_info.value.status_code == 403

    operator_incident = api_app.get_incident_by_alert_id(
        alert.alert_id,
        include_sensitive=True,
        principal=authenticate_token("incident-process-token"),
    )
    assert operator_incident.alert.username == alert.username
    assert operator_incident.alert.command_line == alert.command_line
    assert operator_incident.alert.file_hash == alert.file_hash


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


def test_pentest_runner_forces_mock_integrations(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SOAR_INTEL_PROVIDER", "virustotal")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    summary = run_pentest(
        tmp_path / "pentest-output",
        tmp_path / "pentest-report.md",
    )

    assert summary["finding_count"] == 0
    assert summary["check_count"] >= 4


def test_readiness_never_returns_database_password():
    class Repo:
        db_path = "postgresql://postgres.abc:S3cretPassw0rd@aws-0-x.pooler.supabase.com:5432/postgres"

    report = build_readiness_report(repository=Repo())
    repository_dependency = next(d for d in report["dependencies"] if d["name"] == "incident_repository")

    assert "S3cretPassw0rd" not in str(repository_dependency)
    assert "aws-0-x.pooler.supabase.com:5432/postgres" in repository_dependency["detail"]


def test_api_rejects_oversized_request_body():
    import asyncio

    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/incidents/process",
        "raw_path": b"/api/v1/incidents/process",
        "query_string": b"",
        "headers": [(b"content-length", str(api_app._MAX_BODY_BYTES + 1).encode())],
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
        "scheme": "http",
    }
    asyncio.run(api_app.app(scope, receive, send))

    assert sent[0]["status"] == 413
