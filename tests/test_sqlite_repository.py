import sqlite3

import pytest

from alert_generator.generator import generate_alert
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import MAX_INCIDENT_LIST_LIMIT, SQLiteIncidentRepository


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


def test_sqlite_repository_rejects_invalid_incident_list_limit(tmp_path):
    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")

    with pytest.raises(ValueError) as zero_limit:
        repository.list_incidents(limit=0)
    assert str(MAX_INCIDENT_LIST_LIMIT) in str(zero_limit.value)

    with pytest.raises(ValueError) as oversized_limit:
        repository.list_incidents(limit=MAX_INCIDENT_LIST_LIMIT + 1)
    assert str(MAX_INCIDENT_LIST_LIMIT) in str(oversized_limit.value)


def test_sqlite_repository_migrates_legacy_incident_table_before_creating_indexes(tmp_path):
    db_path = tmp_path / "legacy.db"

    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                username TEXT NOT NULL,
                process_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                parent_process TEXT NOT NULL,
                command_line TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                detection_name TEXT NOT NULL,
                received_at TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL UNIQUE,
                hostname TEXT NOT NULL,
                detection_name TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                ticket_id TEXT,
                status TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                report_path TEXT,
                triggered_actions_json TEXT NOT NULL,
                policy_reasoning_json TEXT NOT NULL,
                enriched_json TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
            );
            """
        )

    repository = SQLiteIncidentRepository(db_path=db_path)

    with sqlite3.connect(db_path) as conn:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(incidents)").fetchall()
        }
        indexes = {
            row[1]
            for row in conn.execute("PRAGMA index_list(incidents)").fetchall()
        }

    assert repository.db_path == db_path
    assert "case_status" in columns
    assert "case_owner" in columns
    assert "idx_incidents_case_status" in indexes
