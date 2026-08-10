import api.app as api_app
import pytest
import sqlite3
import yaml
from datetime import timedelta
from alert_generator.generator import generate_alert
from observability import observability
from api.schemas import (
    ActionApprovalRequest,
    ActionRollbackRequest,
    BulkIncidentUpdateRequest,
    IncidentCaseUpdateRequest,
    IncidentNoteCreateRequest,
    IncidentReopenRequest,
    ProcessAlertRequest,
    ProcessScenarioRequest,
    SavedFilterCreateRequest,
)
from fastapi import HTTPException
from pydantic import ValidationError
from engine.policy_engine import PolicyEngine
from engine.policy_loader import DEFAULT_POLICY_CONFIG
from services.remediation_queue import RepositoryQueuePublisher
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import SQLiteIncidentRepository


def _counter_value(name: str, **labels: str) -> float:
    snapshot = observability.snapshot()
    for counter in snapshot["metrics"]["counters"]:
        if counter["name"] != name:
            continue
        if all(counter["labels"].get(key) == str(value) for key, value in labels.items()):
            return float(counter["value"])
    return 0.0


def _clone_alert(alert, *, alert_id: str, minutes_offset: int):
    return alert.model_copy(
        update={
            "alert_id": alert_id,
            "received_at": alert.received_at + timedelta(minutes=minutes_offset),
        }
    )


def _build_queued_test_service(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_data["execution"]["approval"]["default_sla_minutes"] = 5
    config_data["execution"]["approval"]["default_escalation_minutes"] = 10
    config_data["execution"]["approval"]["default_escalation_targets"] = ["soc.lead", "irt.manager"]
    config_data["execution"]["approval"]["rules"] = [
        {
            "action": "isolate_host",
            "risk_levels": ["high", "critical"],
            "reason": "Critical isolation requires approval",
        }
    ]
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")
    repository = SQLiteIncidentRepository(tmp_path / "soar.db")
    publisher = RepositoryQueuePublisher(repository)
    return SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=config_path,
            queue_publisher=publisher,
        ),
    )


def test_health_endpoint_returns_ok():
    payload = api_app.health()

    assert payload["status"] == "ok"
    assert _counter_value("api.requests_total", route_name="health", status="ok") == 1.0


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


def test_api_incident_detail_exposes_correlation_fields_for_grouped_alerts(
    tmp_path,
    monkeypatch,
    incident_operator_principal,
):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    first_alert = generate_alert(scenario="mixed", seed=9191)
    second_alert = _clone_alert(first_alert, alert_id=f"{first_alert.alert_id}-api", minutes_offset=8)

    api_app.process_incident(
        ProcessAlertRequest(
            alert=first_alert,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )
    api_app.process_incident(
        ProcessAlertRequest(
            alert=second_alert,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    incident = api_app.get_incident_by_alert_id(
        second_alert.alert_id,
        principal=incident_operator_principal,
    )
    summaries = api_app.list_incidents(limit=10, principal=incident_operator_principal)

    assert incident.latest_alert_id == second_alert.alert_id
    assert incident.related_alert_count == 2
    assert set(incident.related_alert_ids) == {first_alert.alert_id, second_alert.alert_id}
    assert incident.response.correlation_trace.outcome.value == "attached_to_existing"
    assert summaries[0].related_alert_count == 2


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
    assert saved_filter.workspace == "default"

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
    assert "metrics" in readiness.observability
    assert "traces" in readiness.observability

    snapshot = api_app.observability_snapshot(principal=incident_operator_principal)
    assert "metrics" in snapshot
    assert "structured_log_path" in snapshot


def test_add_incident_note_rejects_spoofed_author(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="benign",
            seed=9401,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )

    with pytest.raises(HTTPException) as excinfo:
        api_app.add_incident_note(
            response.response.alert_id,
            IncidentNoteCreateRequest(author="spoofed-analyst", body="Forged note"),
            principal=incident_operator_principal,
        )

    assert excinfo.value.status_code == 403
    assert "must match the authenticated principal" in str(excinfo.value.detail)


def test_save_filter_rejects_spoofed_created_by(tmp_path, monkeypatch, incident_operator_principal):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    with pytest.raises(HTTPException) as excinfo:
        api_app.save_filter(
            SavedFilterCreateRequest(
                name="spoofed-filter",
                created_by="spoofed-analyst",
                filters={"case_status": "new"},
            ),
            principal=incident_operator_principal,
        )

    assert excinfo.value.status_code == 403
    assert "must match the authenticated principal" in str(excinfo.value.detail)


def test_workspace_scoping_hides_cross_workspace_incidents_and_filters(
    tmp_path,
    monkeypatch,
    principal_factory,
):
    test_service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)
    alpha_principal = principal_factory(
        "alpha-operator",
        roles=[api_app.ROLE_INCIDENT_PROCESS, api_app.ROLE_INCIDENT_READ],
        workspaces=["alpha"],
    )
    bravo_principal = principal_factory(
        "bravo-operator",
        roles=[api_app.ROLE_INCIDENT_PROCESS, api_app.ROLE_INCIDENT_READ],
        workspaces=["bravo"],
    )

    response = api_app.process_scenario(
        ProcessScenarioRequest(
            scenario="mixed",
            seed=9420,
            generate_report=False,
            export_pdf=False,
            workspace="alpha",
        ),
        principal=alpha_principal,
    )

    alpha_incidents = api_app.list_incidents(limit=50, principal=alpha_principal)
    bravo_incidents = api_app.list_incidents(limit=50, principal=bravo_principal)

    assert alpha_incidents
    assert alpha_incidents[0].workspace == "alpha"
    assert bravo_incidents == []

    with pytest.raises(HTTPException) as excinfo:
        api_app.get_incident_by_alert_id(
            response.response.alert_id,
            principal=bravo_principal,
        )

    assert excinfo.value.status_code == 404

    saved_filter = api_app.save_filter(
        SavedFilterCreateRequest(
            name="alpha-only",
            filters={"case_status": "new"},
            workspace="alpha",
        ),
        principal=alpha_principal,
    )

    assert saved_filter.workspace == "alpha"
    assert api_app.list_saved_filters(principal=bravo_principal) == []


@pytest.mark.parametrize(
    "builder",
    [
        lambda: IncidentCaseUpdateRequest(comment="x" * 2001),
        lambda: ActionApprovalRequest(comment="x" * 2001),
        lambda: ActionRollbackRequest(comment="x" * 2001),
        lambda: IncidentReopenRequest(comment="x" * 2001),
    ],
)
def test_comment_request_models_reject_oversized_values(builder):
    with pytest.raises(ValidationError):
        builder()


def test_incident_note_request_rejects_oversized_body():
    with pytest.raises(ValidationError):
        IncidentNoteCreateRequest(body="x" * 4001)


def test_saved_filter_request_rejects_oversized_payload():
    with pytest.raises(ValidationError):
        SavedFilterCreateRequest(
            name="oversized-filter",
            filters={"query": "x" * 5000},
        )


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


def test_approval_endpoints_reject_spoofed_actor(tmp_path, monkeypatch, incident_operator_principal):
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

    alert = generate_alert(scenario="malicious_hash", seed=9501)
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

    with pytest.raises(HTTPException) as excinfo:
        api_app.approve_action(
            alert.alert_id,
            pending_action.correlation_id,
            ActionApprovalRequest(actor="spoofed-analyst", comment="Forged approval"),
            principal=incident_operator_principal,
        )

    assert excinfo.value.status_code == 403
    assert "must match the authenticated principal" in str(excinfo.value.detail)


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


def test_rollback_reopen_and_escalation_endpoints(tmp_path, monkeypatch, incident_operator_principal):
    test_service = _build_queued_test_service(tmp_path)
    monkeypatch.setattr(api_app, "get_workflow_service", lambda: test_service)

    rollback_alert = generate_alert(scenario="malicious_hash", seed=9797)
    api_app.process_incident(
        ProcessAlertRequest(
            alert=rollback_alert,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )
    rollback_incident = api_app.get_incident_by_alert_id(
        rollback_alert.alert_id,
        include_sensitive=True,
        principal=incident_operator_principal,
    )
    rollback_target = next(action for action in rollback_incident.action_results if action.action == "isolate_host")

    rolled_back = api_app.rollback_action(
        rollback_alert.alert_id,
        rollback_target.correlation_id,
        ActionRollbackRequest(actor="incident-operator", comment="Cancel before execution"),
        principal=incident_operator_principal,
    )
    rolled_back_action = next(action for action in rolled_back.action_results if action.action == "isolate_host")
    assert rolled_back_action.status == "skipped"
    assert rolled_back_action.rollback_requested_by == "incident-operator"

    reopened = api_app.update_incident_case(
        rollback_alert.alert_id,
        IncidentCaseUpdateRequest(case_status="closed", comment="Case closed after rollback"),
        principal=incident_operator_principal,
    )
    assert reopened.case_status == "closed"

    reopened = api_app.reopen_incident(
        rollback_alert.alert_id,
        IncidentReopenRequest(comment="Need another analyst pass"),
        principal=incident_operator_principal,
    )
    assert reopened.case_status == "in_progress"

    escalation_alert = generate_alert(scenario="malicious_hash", seed=9898)
    api_app.process_incident(
        ProcessAlertRequest(
            alert=escalation_alert,
            generate_report=False,
            export_pdf=False,
        ),
        principal=incident_operator_principal,
    )
    repository = test_service._repository
    with sqlite3.connect(test_service.db_path) as conn:
        escalation_target = conn.execute(
            """
            SELECT correlation_id
            FROM queue_jobs
            WHERE alert_id = ?
              AND action = 'isolate_host'
              AND status = 'waiting_approval'
            ORDER BY id DESC
            LIMIT 1
            """,
            (escalation_alert.alert_id,),
        ).fetchone()
        assert escalation_target is not None
        conn.execute(
            """
            UPDATE queue_jobs
            SET approval_due_at = '2026-01-01T00:00:00+00:00',
                approval_escalates_at = '2026-01-01T00:05:00+00:00'
            WHERE correlation_id = ?
            """,
            (escalation_target[0],),
        )
        conn.commit()

    escalated = api_app.escalate_overdue_approvals(principal=incident_operator_principal)
    escalated_action = next(
        action
        for incident in escalated
        for action in incident.action_results
        if action.action == "isolate_host" and action.approval_escalated_at is not None
    )
    assert escalated_action.approval_escalated_at is not None
