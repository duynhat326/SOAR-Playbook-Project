from schemas.alert import ActionResult, EnrichedAlert, IncidentResponse, ResponseAction
from alert_generator.generator import generate_alert
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import SQLiteIncidentRepository


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
