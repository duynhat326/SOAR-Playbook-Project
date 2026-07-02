import api.app as api_app
from api.schemas import ProcessScenarioRequest
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
