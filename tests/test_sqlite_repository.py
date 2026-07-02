import sqlite3

from alert_generator.generator import generate_alert
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import SQLiteIncidentRepository


def test_sqlite_repository_persists_alert_incident_actions_and_report(tmp_path):
    db_path = tmp_path / "soar.db"
    report_dir = tmp_path / "reports"
    repository = SQLiteIncidentRepository(db_path=db_path)
    service = SoarWorkflowService(
        verbose=False,
        report_output_dir=report_dir,
        repository=repository,
    )

    alert = generate_alert(scenario="mixed", seed=2024)
    result = service.process_alert(
        alert,
        generate_report=True,
        export_pdf=False,
        include_markdown_content=True,
    )

    incident = repository.get_incident_by_alert_id(alert.alert_id)

    assert incident is not None
    assert incident["ticket_id"] == result.response.ticket_id
    assert incident["risk_level"] == result.enriched_alert.risk_level
    assert incident["html_path"] == str(result.artifacts.html_path)
    assert len(incident["action_results"]) == len(result.response.action_results)

    with sqlite3.connect(db_path) as conn:
        alerts_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        incidents_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        reports_count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    assert alerts_count == 1
    assert incidents_count == 1
    assert reports_count == 1


def test_sqlite_repository_upserts_same_alert_id_without_duplicate_incident(tmp_path):
    db_path = tmp_path / "soar.db"
    repository = SQLiteIncidentRepository(db_path=db_path)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
    )

    alert = generate_alert(scenario="benign", seed=2024)
    service.process_alert(alert, generate_report=False, export_pdf=False)
    service.process_alert(alert, generate_report=False, export_pdf=False)

    incidents = repository.list_incidents()
    incident = repository.get_incident_by_alert_id(alert.alert_id)

    assert len(incidents) == 1
    assert incident is not None
    assert len(incident["action_results"]) >= 1


def test_sqlite_repository_fetches_incident_by_ticket_id(tmp_path):
    db_path = tmp_path / "soar.db"
    report_dir = tmp_path / "reports"
    repository = SQLiteIncidentRepository(db_path=db_path)
    service = SoarWorkflowService(
        verbose=False,
        report_output_dir=report_dir,
        repository=repository,
    )

    alert = generate_alert(scenario="mixed", seed=2025)
    result = service.process_alert(
        alert,
        generate_report=True,
        export_pdf=False,
        include_markdown_content=True,
    )

    assert result.response.ticket_id is not None

    incident = repository.get_incident_by_ticket_id(result.response.ticket_id)

    assert incident is not None
    assert incident["alert"]["alert_id"] == alert.alert_id
    assert incident["response"]["ticket_id"] == result.response.ticket_id
    assert incident["report"]["html_path"] == str(result.artifacts.html_path)


def test_sqlite_repository_lists_recent_incidents_with_filters(tmp_path):
    db_path = tmp_path / "soar.db"
    repository = SQLiteIncidentRepository(db_path=db_path)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
    )

    mixed_alert = generate_alert(scenario="mixed", seed=3030)
    benign_alert = generate_alert(scenario="benign", seed=4040)

    mixed_result = service.process_alert(mixed_alert, generate_report=False, export_pdf=False)
    service.process_alert(benign_alert, generate_report=False, export_pdf=False)

    incidents = repository.list_incidents(limit=1)
    filtered = repository.list_incidents(
        status="completed",
        risk_level=mixed_result.enriched_alert.risk_level,
        hostname=mixed_alert.hostname,
        ticket_id=mixed_result.response.ticket_id,
    )

    assert len(incidents) == 1
    assert len(filtered) == 1
    assert filtered[0]["alert_id"] == mixed_alert.alert_id
