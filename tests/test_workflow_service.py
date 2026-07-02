from alert_generator.generator import generate_alert
from services.workflow_service import SoarWorkflowService


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
