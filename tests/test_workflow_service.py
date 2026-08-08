from datetime import timedelta

import yaml

from schemas.alert import ActionResult, EnrichedAlert, IncidentResponse, ResponseAction
from alert_generator.generator import generate_alert
from engine.policy_engine import PolicyEngine
from engine.policy_loader import DEFAULT_POLICY_CONFIG
from services.remediation_queue import RepositoryQueuePublisher
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import SQLiteIncidentRepository


def _clone_alert(alert, *, alert_id: str, minutes_offset: int):
    return alert.model_copy(
        update={
            "alert_id": alert_id,
            "received_at": alert.received_at + timedelta(minutes=minutes_offset),
        }
    )


def test_workflow_service_processes_generated_alert_without_report(tmp_path):
    service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )
    alert = generate_alert(scenario="mixed", seed=2024)

    result = service.process_alert(
        alert,
        generate_report=False,
        export_pdf=False,
    )

    assert result.alert.alert_id == alert.alert_id
    assert result.enriched_alert.risk_score >= 0.0
    assert result.response.ticket_id is not None
    assert result.response.report_path is None
    assert result.response.execution_trace.effective_mode == "sync"
    assert result.artifacts.html_path is None


def test_workflow_service_replays_existing_incident_without_rerunning_side_effects(tmp_path):
    class StubPipeline:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, alert):
            self.calls += 1
            return EnrichedAlert(
                original_alert=alert,
                risk_score=42.0,
                risk_level="medium",
            )

    class StubPolicyEngine:
        def __init__(self) -> None:
            self.calls = 0

        def evaluate(self, enriched):
            self.calls += 1
            return IncidentResponse(
                enriched_alert=enriched,
                triggered_actions=[ResponseAction.CREATE_TICKET],
                policy_reasoning=["stub"],
                action_results=[
                    ActionResult(
                        action=ResponseAction.CREATE_TICKET,
                        status="success",
                        details="stub ticket",
                    )
                ],
                ticket_id="INC-TEST-0001",
            )

    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")
    pipeline = StubPipeline()
    policy_engine = StubPolicyEngine()
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        pipeline=pipeline,
        policy_engine=policy_engine,
    )
    alert = generate_alert(scenario="mixed", seed=2024)

    first = service.process_alert(
        alert,
        generate_report=False,
        export_pdf=False,
    )
    second = service.process_alert(
        alert,
        generate_report=False,
        export_pdf=False,
    )

    assert pipeline.calls == 1
    assert policy_engine.calls == 1
    assert first.response.ticket_id == "INC-TEST-0001"
    assert second.response.ticket_id == "INC-TEST-0001"
    assert second.alert.alert_id == alert.alert_id


def test_workflow_service_replay_can_materialize_missing_report_artifacts(tmp_path):
    class StubPipeline:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, alert):
            self.calls += 1
            return EnrichedAlert(
                original_alert=alert,
                risk_score=42.0,
                risk_level="medium",
            )

    class StubPolicyEngine:
        def __init__(self) -> None:
            self.calls = 0

        def evaluate(self, enriched):
            self.calls += 1
            return IncidentResponse(
                enriched_alert=enriched,
                triggered_actions=[ResponseAction.CREATE_TICKET],
                policy_reasoning=["stub"],
                action_results=[
                    ActionResult(
                        action=ResponseAction.CREATE_TICKET,
                        status="success",
                        details="stub ticket",
                    )
                ],
                ticket_id="INC-TEST-0002",
            )

    class StubReportGenerator:
        def __init__(self, root):
            self.calls: list[bool] = []
            self.root = root

        def generate(self, response, *, export_pdf=False):
            self.calls.append(export_pdf)
            markdown_path = self.root / "incident.md"
            html_path = self.root / "incident.html"
            pdf_path = self.root / "incident.pdf" if export_pdf else None
            markdown_path.write_text("# replay report\n", encoding="utf-8")
            html_path.write_text("<h1>replay report</h1>", encoding="utf-8")
            if pdf_path is not None:
                pdf_path.write_text("pdf", encoding="utf-8")
            return markdown_path, html_path, pdf_path

    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")
    pipeline = StubPipeline()
    policy_engine = StubPolicyEngine()
    report_generator = StubReportGenerator(tmp_path)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        pipeline=pipeline,
        policy_engine=policy_engine,
        report_generator=report_generator,
    )
    alert = generate_alert(scenario="mixed", seed=2121)

    first = service.process_alert(
        alert,
        generate_report=False,
        export_pdf=False,
    )
    second = service.process_alert(
        alert,
        generate_report=True,
        export_pdf=True,
    )
    third = service.process_alert(
        alert,
        generate_report=True,
        export_pdf=True,
        include_markdown_content=True,
    )

    assert first.artifacts.html_path is None
    assert pipeline.calls == 1
    assert policy_engine.calls == 1
    assert report_generator.calls == [True]
    assert second.response.ticket_id == "INC-TEST-0002"
    assert second.artifacts.html_path is not None
    assert second.artifacts.html_path.exists()
    assert second.artifacts.pdf_path is not None
    assert second.artifacts.pdf_path.exists()
    assert third.artifacts.markdown_content == "# replay report\n"


def test_workflow_service_sets_correlation_trace_for_grouped_alerts(tmp_path):
    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
    )
    first_alert = generate_alert(scenario="mixed", seed=8181)
    second_alert = _clone_alert(first_alert, alert_id=f"{first_alert.alert_id}-corr", minutes_offset=5)

    first_result = service.process_alert(
        first_alert,
        generate_report=False,
        export_pdf=False,
    )
    second_result = service.process_alert(
        second_alert,
        generate_report=False,
        export_pdf=False,
    )

    assert first_result.response.correlation_trace.outcome.value == "new_incident"
    assert second_result.response.correlation_trace.outcome.value == "attached_to_existing"
    assert second_result.response.correlation_trace.related_alert_count == 2
    assert set(second_result.response.correlation_trace.related_alert_ids) == {
        first_alert.alert_id,
        second_alert.alert_id,
    }


class RecordingTicketingConnector:
    def __init__(self) -> None:
        self.comments: list[dict[str, object]] = []
        self.state_syncs: list[dict[str, object]] = []
        self.created_tickets: list[str] = []

    def create_ticket(
        self,
        *,
        enriched_alert,
        triggered_actions,
        risk_score,
        risk_level,
        operator: str = "SOAR_AUTO",
    ):
        ticket_id = f"INC-{len(self.created_tickets) + 1:04d}"
        self.created_tickets.append(ticket_id)
        return (
            ActionResult(
                action=ResponseAction.CREATE_TICKET,
                status="succeeded",
                details=f"Ticket {ticket_id} created.",
                operator=operator,
            ),
            ticket_id,
        )

    def append_case_comment(
        self,
        *,
        ticket_id: str,
        comment: str,
        author: str = "SOAR_AUTO",
        metadata=None,
    ):
        self.comments.append(
            {
                "ticket_id": ticket_id,
                "comment": comment,
                "author": author,
                "metadata": dict(metadata or {}),
            }
        )
        return None

    def sync_case_state(
        self,
        *,
        ticket_id: str,
        case_status: str,
        case_owner: str | None = None,
        comment: str | None = None,
        actor: str = "SOAR_AUTO",
        metadata=None,
    ):
        self.state_syncs.append(
            {
                "ticket_id": ticket_id,
                "case_status": case_status,
                "case_owner": case_owner,
                "comment": comment,
                "actor": actor,
                "metadata": dict(metadata or {}),
            }
        )
        return None


def _queued_policy_config_path(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_data["execution"]["approval"]["rules"] = [
        {
            "action": "isolate_host",
            "risk_levels": ["high", "critical"],
            "reason": "Containment requires approval",
        }
    ]
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")
    return config_path


def test_workflow_service_syncs_ticket_state_and_notes(tmp_path):
    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")
    ticketing = RecordingTicketingConnector()
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            ticketing_connector=ticketing,
        ),
    )
    alert = generate_alert(scenario="mixed", seed=5152)

    service.process_alert(alert, generate_report=False, export_pdf=False)
    service.add_incident_note(alert.alert_id, author="analyst.one", body="Triage note for the case.")
    service.update_incident_case(
        alert.alert_id,
        case_status="resolved",
        case_owner="Tier 2",
        actor="analyst.one",
        comment="Containment complete.",
    )
    service.reopen_incident(
        alert.alert_id,
        actor="analyst.one",
        comment="Need another validation cycle.",
    )

    assert ticketing.comments
    assert ticketing.comments[0]["comment"] == "Triage note for the case."
    assert ticketing.comments[0]["metadata"]["category"] == "case.note_added"
    assert [sync["case_status"] for sync in ticketing.state_syncs] == ["resolved", "in_progress"]
    assert ticketing.state_syncs[-1]["metadata"]["category"] == "case.reopened"


def test_workflow_service_syncs_approval_and_rollback_comments(tmp_path):
    repository = SQLiteIncidentRepository(db_path=tmp_path / "soar.db")
    ticketing = RecordingTicketingConnector()
    config_path = _queued_policy_config_path(tmp_path)
    publisher = RepositoryQueuePublisher(repository)
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=config_path,
            queue_publisher=publisher,
            ticketing_connector=ticketing,
        ),
    )

    approve_alert = generate_alert(scenario="malicious_hash", seed=5153)
    service.process_alert(approve_alert, generate_report=False, export_pdf=False)
    approve_incident = repository.get_incident_by_alert_id(approve_alert.alert_id)
    approve_action = next(action for action in approve_incident["action_results"] if action["action"] == "isolate_host")
    service.approve_action(
        approve_alert.alert_id,
        approve_action["correlation_id"],
        actor="analyst.two",
        comment="Approved after review.",
    )

    rollback_alert = generate_alert(scenario="malicious_hash", seed=5154)
    service.process_alert(rollback_alert, generate_report=False, export_pdf=False)
    rollback_incident = repository.get_incident_by_alert_id(rollback_alert.alert_id)
    rollback_action = next(action for action in rollback_incident["action_results"] if action["action"] == "isolate_host")
    service.rollback_action(
        rollback_alert.alert_id,
        rollback_action["correlation_id"],
        actor="analyst.two",
        comment="Cancel before endpoint isolation.",
    )

    categories = [comment["metadata"]["category"] for comment in ticketing.comments]
    assert "approval.approved" in categories
    assert "queue.cancelled" in categories
    assert any("Approved after review." in str(comment["comment"]) for comment in ticketing.comments)
    assert any("Cancel before endpoint isolation." in str(comment["comment"]) for comment in ticketing.comments)
