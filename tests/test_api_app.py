import api.app as api_app
import pytest
import yaml
from alert_generator.generator import generate_alert
from api.schemas import (
    ActionApprovalRequest,
    BulkIncidentUpdateRequest,
    IncidentCaseUpdateRequest,
    IncidentNoteCreateRequest,
    ProcessAlertRequest,
    ProcessScenarioRequest,
    SavedFilterCreateRequest,
)
from fastapi import HTTPException
from engine.policy_engine import PolicyEngine
from engine.policy_loader import DEFAULT_POLICY_CONFIG
from services.remediation_queue import RepositoryQueuePublisher
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import SQLiteIncidentRepository


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


def test_case_update_note_and_saved_filter_endpoints(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=9191,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    updated = api_app.update_incident_case(
        response.response.alert_id,
        IncidentCaseUpdateRequest(case_status="triaged", case_owner="SOC Team", comment="Owner assigned"),
        principal=incident_operator_principal,
    )
    assert updated.case_status == "triaged"
    assert updated.case_owner == "SOC Team"

    note = api_app.add_incident_note(
        response.response.alert_id,
        IncidentNoteCreateRequest(author="incident-operator", body="Collected triage context."),
        principal=incident_operator_principal,
    )
    assert note["author"] == "incident-operator"

    saved_filter = api_app.save_filter(
        SavedFilterCreateRequest(
            name="triaged-soc",
            created_by="incident-operator",
            filters={"case_status": "triaged", "search": "SOC"},
        ),
        principal=incident_operator_principal,
    )
    assert saved_filter.name == "triaged-soc"

    filters = api_app.list_saved_filters(principal=incident_operator_principal)
    assert filters[0].name == "triaged-soc"

    incident = api_app.get_incident_by_alert_id(
        response.response.alert_id,
        include_sensitive=True,
        principal=incident_operator_principal,
    )
    assert incident.note_count == 1
    assert incident.notes[0].body == "Collected triage context."
    assert any(event.category == "case.updated" for event in incident.audit_events)
    assert any(event.category == "case.note_added" for event in incident.audit_events)


def test_bulk_update_and_readiness_endpoints(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    first = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=9292,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )
    second = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=9393,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    updated = api_app.bulk_update_incidents(
        BulkIncidentUpdateRequest(
            alert_ids=[first.response.alert_id, second.response.alert_id],
            case_status="in_progress",
            case_owner="Tier 2",
        ),
        principal=incident_operator_principal,
    )

    assert len(updated) == 2
    assert {incident.case_owner for incident in updated} == {"Tier 2"}
    assert {incident.case_status for incident in updated} == {"in_progress"}

    readiness = api_app.readiness(principal=incident_operator_principal)
    assert readiness.status in {"ready", "degraded"}
    assert any(dep.name == "incident_repository" for dep in readiness.dependencies)
    assert "total_jobs" in readiness.queue_metrics


def test_approve_and_reject_action_endpoints(tmp_path, monkeypatch, incident_operator_principal):
    monkeypatch.setenv("SOAR_APPROVAL_REQUIRED_ACTIONS", "isolate_host")
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")
    repository = SQLiteIncidentRepository(tmp_path / "soar.db")
    publisher = RepositoryQueuePublisher(repository)
    test_service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=config_path,
            queue_publisher=publisher,
        ),
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    alert = generate_alert(scenario="malicious_hash", seed=9494)
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
    pending_action = next(action for action in incident.action_results if action.action == "isolate_host")
    assert pending_action.status == "waiting_approval"

    approved = api_app.approve_action(
        alert.alert_id,
        pending_action.correlation_id,
        ActionApprovalRequest(actor="incident-operator", comment="Proceed with isolation"),
        principal=incident_operator_principal,
    )
    approved_action = next(action for action in approved.action_results if action.action == "isolate_host")
    assert approved_action.approval_state == "approved"
    assert approved_action.status == "queued"

    alert_reject = generate_alert(scenario="malicious_hash", seed=9595)
    api_app.process_incident(
        ProcessAlertRequest(
            alert=alert_reject,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )
    reject_target = api_app.get_incident_by_alert_id(
        alert_reject.alert_id,
        include_sensitive=True,
        principal=incident_operator_principal,
    )
    reject_action_result = next(action for action in reject_target.action_results if action.action == "isolate_host")

    rejected = api_app.reject_action(
        alert_reject.alert_id,
        reject_action_result.correlation_id,
        ActionApprovalRequest(actor="incident-operator", comment="Containment deferred"),
        principal=incident_operator_principal,
    )
    rejected_action = next(action for action in rejected.action_results if action.action == "isolate_host")
    assert rejected_action.approval_state == "rejected"
    assert rejected_action.status == "failed"


def test_approval_endpoints_reject_invalid_state_transitions(tmp_path, monkeypatch, incident_operator_principal):
    monkeypatch.setenv("SOAR_APPROVAL_REQUIRED_ACTIONS", "isolate_host")
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")
    repository = SQLiteIncidentRepository(tmp_path / "soar.db")
    publisher = RepositoryQueuePublisher(repository)
    test_service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=config_path,
            queue_publisher=publisher,
        ),
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    alert = generate_alert(scenario="malicious_hash", seed=9696)
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
    pending_action = next(action for action in incident.action_results if action.action == "isolate_host")

    api_app.reject_action(
        alert.alert_id,
        pending_action.correlation_id,
        ActionApprovalRequest(actor="incident-operator", comment="Containment deferred"),
        principal=incident_operator_principal,
    )

    with pytest.raises(HTTPException) as excinfo:
        api_app.approve_action(
            alert.alert_id,
            pending_action.correlation_id,
            ActionApprovalRequest(actor="incident-operator", comment="Reversing the decision"),
            principal=incident_operator_principal,
        )

    assert excinfo.value.status_code == 409
    assert "cannot be approved from status 'rejected'" in str(excinfo.value.detail)
