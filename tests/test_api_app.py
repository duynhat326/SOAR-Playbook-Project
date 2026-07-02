import api.app as api_app
import pytest
from alert_generator.generator import generate_alert
from api.schemas import ProcessAlertRequest, ProcessScenarioRequest
from fastapi import HTTPException
from services.workflow_service import SoarWorkflowService


def test_health_endpoint_returns_ok():
    payload = api_app.health()

    assert payload["status"] == "ok"


def test_dashboard_bootstrap_returns_sample_metadata_and_default_json(incident_operator_principal):
    payload = api_app.dashboard_bootstrap(principal=incident_operator_principal)

    assert payload.default_scenario == "mixed"
    assert payload.default_sample_id is not None
    assert payload.default_sample_id in payload.sample_alerts
    assert payload.sample_options
    assert payload.scenario_options
    assert '"alert_id"' in payload.default_json


def test_process_scenario_endpoint_runs_pipeline_without_report(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=2024,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    assert response.response.ticket_id is not None
    assert response.report.html_path is None


def test_process_incident_rejects_redacted_payload(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    alert = generate_alert(scenario="mixed", seed=4545)
    alert.username = "[redacted]"
    alert.file_path = "[redacted-path]"
    alert.command_line = "[redacted]"
    alert.file_hash = "0" * len(alert.file_hash)

    with pytest.raises(HTTPException) as exc_info:
        api_app.process_incident(
            ProcessAlertRequest(
                alert=alert,
                generate_report=False,
                export_pdf=False,
            ),
            principal=incident_operator_principal,
        )

    assert exc_info.value.status_code == 422
    assert "sanitized/redacted" in str(exc_info.value.detail)


def test_get_incident_by_alert_id_returns_persisted_record(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=2025,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    incident = api_app.get_incident_by_alert_id(
        response.response.alert_id,
        principal=incident_operator_principal,
    )

    assert incident.alert_id == response.response.alert_id
    assert incident.ticket_id == response.response.ticket_id
    assert incident.response.ticket_id == response.response.ticket_id
    assert incident.alert.username == "[redacted]"
    assert incident.alert.command_line == "[redacted]"
    assert set(incident.alert.file_hash) == {"0"}
    assert len(incident.alert.file_hash) in (32, 40, 64)


def test_get_incident_by_alert_id_can_include_sensitive_fields_for_operator(
    tmp_path,
    monkeypatch,
    incident_operator_principal,
):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    alert = generate_alert(scenario="mixed", seed=2525)
    api_app.process_incident(
        ProcessAlertRequest(
            alert=alert,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    incident = api_app.get_incident_by_alert_id(
        alert.alert_id,
        include_sensitive=True,
        principal=incident_operator_principal,
    )

    assert incident.alert.username == alert.username
    assert incident.alert.command_line == alert.command_line
    assert incident.alert.file_hash == alert.file_hash
    assert incident.alert.file_path == alert.file_path


def test_get_incident_by_alert_id_hydrates_markdown_report_content(
    tmp_path,
    monkeypatch,
    incident_operator_principal,
):
    test_service = SoarWorkflowService(
        verbose=False,
        report_output_dir=api_app._REPORT_ARTIFACT_ROOT / "pytest-api-app",
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=3030,
            generate_report=True,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    incident = api_app.get_incident_by_alert_id(
        response.response.alert_id,
        principal=incident_operator_principal,
    )

    assert incident.report.markdown_path is not None
    assert incident.report.html_path is not None
    assert incident.report.markdown_content is not None
    assert incident.report.markdown_content.strip() != ""
    assert incident.response.execution_trace.effective_mode == "sync"


def test_get_incident_by_ticket_id_returns_persisted_record(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=2026,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    assert response.response.ticket_id is not None

    incident = api_app.get_incident_by_ticket_id(
        response.response.ticket_id,
        principal=incident_operator_principal,
    )

    assert incident.alert_id == response.response.alert_id
    assert incident.ticket_id == response.response.ticket_id
    assert incident.report.html_path is None
    assert incident.response.enriched_alert.original_alert.command_line == "[redacted]"


def test_get_incident_report_html_returns_generated_artifact(
    tmp_path,
    monkeypatch,
    incident_operator_principal,
):
    test_service = SoarWorkflowService(
        verbose=False,
        report_output_dir=api_app._REPORT_ARTIFACT_ROOT / "pytest-api-app",
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=4040,
            generate_report=True,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    report_response = api_app.get_incident_report_html(
        response.response.alert_id,
        principal=incident_operator_principal,
    )

    assert report_response.media_type == "text/html"
    assert str(report_response.path).endswith(".html")
    assert "incident_" in report_response.filename


def test_get_incident_report_html_raises_404_when_report_missing(
    tmp_path,
    monkeypatch,
    incident_operator_principal,
):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=4141,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    with pytest.raises(HTTPException) as exc_info:
        api_app.get_incident_report_html(
            response.response.alert_id,
            principal=incident_operator_principal,
        )

    assert exc_info.value.status_code == 404


def test_get_incident_by_ticket_id_raises_404_when_missing(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    with pytest.raises(HTTPException) as exc_info:
        api_app.get_incident_by_ticket_id(
            "ticket-missing",
            principal=incident_operator_principal,
        )

    assert exc_info.value.status_code == 404


def test_list_incidents_returns_recent_summaries_with_limit(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    first = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=5050,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )
    second = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=6060,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    incidents = api_app.list_incidents(limit=1, principal=incident_operator_principal)

    assert len(incidents) == 1
    assert incidents[0].alert_id == second.response.alert_id
    assert incidents[0].alert_id != first.response.alert_id


def test_list_incidents_applies_optional_filters(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    benign = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=7070,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )
    mixed = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=8080,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    incidents = api_app.list_incidents(
        limit=10,
        hostname=mixed.response.hostname,
        risk_level=mixed.response.enriched_alert.risk_level,
        status="completed",
        ticket_id=mixed.response.ticket_id,
        principal=incident_operator_principal,
    )

    assert len(incidents) == 1
    assert incidents[0].alert_id == mixed.response.alert_id
    assert incidents[0].alert_id != benign.response.alert_id


def test_process_scenario_replays_existing_incident_without_new_side_effects(
    tmp_path,
    monkeypatch,
    incident_operator_principal,
):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    alert = generate_alert(scenario="mixed", seed=9090)
    request = ProcessAlertRequest(
        alert=alert,
        generate_report=False,
        export_pdf=False,
    )

    first = api_app.process_incident(request, principal=incident_operator_principal)
    second = api_app.process_incident(request, principal=incident_operator_principal)

    assert first.response.ticket_id == second.response.ticket_id
    assert first.response.completed_at == second.response.completed_at


def test_list_incidents_openapi_exposes_limit_validation():
    schema = api_app.app.openapi()
    parameters = schema["paths"]["/api/v1/incidents"]["get"]["parameters"]
    limit_parameter = next(item for item in parameters if item["name"] == "limit")

    assert limit_parameter["schema"]["default"] == 50
    assert limit_parameter["schema"]["minimum"] == 1
    assert limit_parameter["schema"]["maximum"] == 200
    assert "HTTPBearer" in schema["components"]["securitySchemes"]
