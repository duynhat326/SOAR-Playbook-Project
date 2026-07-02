import api.app as api_app
import pytest
from api.schemas import ProcessScenarioRequest
from fastapi import HTTPException
from services.workflow_service import SoarWorkflowService


def test_health_endpoint_returns_ok():
    payload = api_app.health()

    assert payload["status"] == "ok"


def test_process_scenario_endpoint_runs_pipeline_without_report(tmp_path, monkeypatch):
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
        )
    )

    assert response.response.ticket_id is not None
    assert response.report.html_path is None


def test_get_incident_by_alert_id_returns_persisted_record(tmp_path, monkeypatch):
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
        )
    )

    incident = api_app.get_incident_by_alert_id(response.response.alert_id)

    assert incident.alert_id == response.response.alert_id
    assert incident.ticket_id == response.response.ticket_id
    assert incident.response.ticket_id == response.response.ticket_id


def test_get_incident_by_ticket_id_returns_persisted_record(tmp_path, monkeypatch):
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
        )
    )

    assert response.response.ticket_id is not None

    incident = api_app.get_incident_by_ticket_id(response.response.ticket_id)

    assert incident.alert_id == response.response.alert_id
    assert incident.ticket_id == response.response.ticket_id
    assert incident.report.html_path is None


def test_get_incident_by_ticket_id_raises_404_when_missing(tmp_path, monkeypatch):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    with pytest.raises(HTTPException) as exc_info:
        api_app.get_incident_by_ticket_id("ticket-missing")

    assert exc_info.value.status_code == 404


def test_list_incidents_returns_recent_summaries_with_limit(tmp_path, monkeypatch):
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
        )
    )
    second = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=6060,
            generate_report=False,
            export_pdf=False,
        )
    )

    incidents = api_app.list_incidents(limit=1)

    assert len(incidents) == 1
    assert incidents[0].alert_id == second.response.alert_id
    assert incidents[0].alert_id != first.response.alert_id


def test_list_incidents_applies_optional_filters(tmp_path, monkeypatch):
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
        )
    )
    mixed = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=8080,
            generate_report=False,
            export_pdf=False,
        )
    )

    incidents = api_app.list_incidents(
        limit=10,
        hostname=mixed.response.hostname,
        risk_level=mixed.response.enriched_alert.risk_level,
        status="completed",
        ticket_id=mixed.response.ticket_id,
    )

    assert len(incidents) == 1
    assert incidents[0].alert_id == mixed.response.alert_id
    assert incidents[0].alert_id != benign.response.alert_id
