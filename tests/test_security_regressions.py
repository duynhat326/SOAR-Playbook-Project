from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

import api.app as api_app
from alert_generator.generator import generate_alert
from api.schemas import ProcessAlertRequest
from security import ROLE_INCIDENT_PROCESS, ROLE_INCIDENT_READ, authenticate_token
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
