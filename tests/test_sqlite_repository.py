import sqlite3
from datetime import timedelta

import pytest
import yaml

from alert_generator.generator import generate_alert
from engine.policy_engine import PolicyEngine
from engine.policy_loader import DEFAULT_POLICY_CONFIG
from services.remediation_queue import RepositoryQueuePublisher
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import MAX_INCIDENT_LIST_LIMIT, SQLiteIncidentRepository


def _clone_alert(alert, *, alert_id: str, minutes_offset: int):
    return alert.model_copy(
        update={
            "alert_id": alert_id,
            "received_at": alert.received_at + timedelta(minutes=minutes_offset),
        }
    )


def _build_queued_service(tmp_path):
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

    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")
    publisher = RepositoryQueuePublisher(repository)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=config_path,
            queue_publisher=publisher,
        ),
    )
    return repository, service


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


def test_sqlite_repository_groups_correlated_alerts_into_one_incident(tmp_path):
    db_path = tmp_path / "soar.db"
    repository = SQLiteIncidentRepository(db_path=db_path)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
    )

    first_alert = generate_alert(scenario="mixed", seed=5151)
    second_alert = _clone_alert(first_alert, alert_id=f"{first_alert.alert_id}-grouped", minutes_offset=10)

    service.process_alert(first_alert, generate_report=False, export_pdf=False)
    second_result = service.process_alert(second_alert, generate_report=False, export_pdf=False)

    incidents = repository.list_incidents()
    first_incident = repository.get_incident_by_alert_id(first_alert.alert_id)
    second_incident = repository.get_incident_by_alert_id(second_alert.alert_id)

    assert len(incidents) == 1
    assert first_incident is not None
    assert second_incident is not None
    assert first_incident["id"] == second_incident["id"]
    assert second_incident["latest_alert_id"] == second_alert.alert_id
    assert second_incident["related_alert_count"] == 2
    assert set(second_incident["related_alert_ids"]) == {first_alert.alert_id, second_alert.alert_id}
    assert second_result.response.correlation_trace.outcome.value == "attached_to_existing"
    assert second_incident["response"]["correlation_trace"]["outcome"] == "attached_to_existing"


def test_sqlite_repository_reopens_closed_incident_when_correlated_alert_arrives(tmp_path):
    db_path = tmp_path / "soar.db"
    repository = SQLiteIncidentRepository(db_path=db_path)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
    )

    first_alert = generate_alert(scenario="mixed", seed=6262)
    reopened_alert = _clone_alert(first_alert, alert_id=f"{first_alert.alert_id}-reopen", minutes_offset=15)

    service.process_alert(first_alert, generate_report=False, export_pdf=False)
    repository.update_incident_case(
        first_alert.alert_id,
        case_status="closed",
        actor="pytest",
        comment="Close before correlation replay.",
    )

    reopened_result = service.process_alert(reopened_alert, generate_report=False, export_pdf=False)
    incident = repository.get_incident_by_alert_id(reopened_alert.alert_id)

    assert incident is not None
    assert incident["case_status"] == "in_progress"
    assert incident["related_alert_count"] == 2
    assert reopened_result.response.correlation_trace.outcome.value == "reopened_incident"
    assert incident["response"]["correlation_trace"]["outcome"] == "reopened_incident"


def test_sqlite_repository_rolls_back_queued_action_and_hashes_audit_chain(tmp_path):
    repository, service = _build_queued_service(tmp_path)
    alert = generate_alert(scenario="malicious_hash", seed=2828)

    service.process_alert(alert, generate_report=False, export_pdf=False)
    incident = repository.get_incident_by_alert_id(alert.alert_id)

    pending_action = next(action for action in incident["action_results"] if action["action"] == "isolate_host")
    assert pending_action["status"] == "waiting_approval"

    rolled_back = repository.rollback_action_job(
        alert.alert_id,
        pending_action["correlation_id"],
        actor="pytest-analyst",
        comment="Cancel before containment",
    )

    assert rolled_back is not None
    action = next(action for action in rolled_back["action_results"] if action["action"] == "isolate_host")
    assert action["status"] == "skipped"
    assert action["rollback_requested_by"] == "pytest-analyst"
    assert action["approval_comment"] == "Cancel before containment"

    with sqlite3.connect(tmp_path / "soar.db") as conn:
        conn.row_factory = sqlite3.Row
        queue_row = conn.execute(
            "SELECT status, approval_state, rollback_requested_by FROM queue_jobs WHERE correlation_id = ?",
            (pending_action["correlation_id"],),
        ).fetchone()
        audit_rows = conn.execute(
            """
            SELECT previous_event_hash, event_hash
            FROM audit_events
            ORDER BY created_at ASC, rowid ASC
            """
        ).fetchall()

    assert queue_row["status"] == "cancelled"
    assert queue_row["approval_state"] == "rejected"
    assert queue_row["rollback_requested_by"] == "pytest-analyst"
    assert audit_rows[0]["previous_event_hash"] is None
    assert audit_rows[0]["event_hash"]
    for previous, current in zip(audit_rows, audit_rows[1:]):
        assert current["previous_event_hash"] == previous["event_hash"]
        assert current["event_hash"]


def test_sqlite_repository_reopens_incident_for_manual_follow_up(tmp_path):
    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
    )
    alert = generate_alert(scenario="mixed", seed=4747)

    service.process_alert(alert, generate_report=False, export_pdf=False)
    repository.update_incident_case(
        alert.alert_id,
        case_status="closed",
        actor="pytest",
        comment="Case closed after containment.",
    )

    reopened = repository.reopen_incident(
        alert.alert_id,
        actor="pytest-reviewer",
        comment="Need another analyst pass.",
    )

    assert reopened is not None
    assert reopened["case_status"] == "in_progress"
    assert reopened["status"] == "attention"
    assert reopened["audit_events"][0]["category"] == "case.reopened"
    assert reopened["audit_events"][0]["payload"]["previous_case_status"] == "closed"


def test_sqlite_repository_escalates_overdue_approvals_and_reports_metrics(tmp_path):
    repository, service = _build_queued_service(tmp_path)
    alert = generate_alert(scenario="malicious_hash", seed=5858)

    service.process_alert(alert, generate_report=False, export_pdf=False)
    incident = repository.get_incident_by_alert_id(alert.alert_id)
    pending_action = next(action for action in incident["action_results"] if action["action"] == "isolate_host")

    with sqlite3.connect(tmp_path / "soar.db") as conn:
        conn.execute(
            """
            UPDATE queue_jobs
            SET approval_due_at = '2026-01-01T00:00:00+00:00',
                approval_escalates_at = '2026-01-01T00:05:00+00:00'
            WHERE correlation_id = ?
            """,
            (pending_action["correlation_id"],),
        )
        conn.commit()

    escalated = repository.escalate_overdue_approvals(actor="sla-bot")
    metrics = repository.get_queue_metrics()

    assert len(escalated) == 1
    action = next(action for action in escalated[0]["action_results"] if action["action"] == "isolate_host")
    assert action["approval_escalated_at"] is not None
    assert action["escalation_targets"] == ["soc.lead", "irt.manager"]
    assert metrics["overdue_approval_jobs"] == 1
    assert metrics["escalation_due_jobs"] == 0
    assert metrics["escalated_approval_jobs"] == 1


def test_sqlite_repository_creates_new_incident_when_alert_is_outside_correlation_window(tmp_path):
    db_path = tmp_path / "soar.db"
    repository = SQLiteIncidentRepository(db_path=db_path)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
    )

    first_alert = generate_alert(scenario="mixed", seed=7373)
    second_alert = _clone_alert(first_alert, alert_id=f"{first_alert.alert_id}-fresh", minutes_offset=121)

    service.process_alert(first_alert, generate_report=False, export_pdf=False)
    second_result = service.process_alert(second_alert, generate_report=False, export_pdf=False)

    incidents = repository.list_incidents()
    second_incident = repository.get_incident_by_alert_id(second_alert.alert_id)

    assert len(incidents) == 2
    assert second_incident is not None
    assert second_incident["related_alert_count"] == 1
    assert second_incident["incident_key"] != f"incident-{first_alert.alert_id}"
    assert second_result.response.correlation_trace.outcome.value == "new_incident"


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
