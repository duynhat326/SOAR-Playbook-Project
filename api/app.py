from __future__ import annotations

from functools import lru_cache

from fastapi import FastAPI

from alert_generator.generator import generate_alert
from api.schemas import (
    ProcessAlertRequest,
    ProcessIncidentResponse,
    ProcessScenarioRequest,
)
from services.workflow_service import SoarWorkflowService

app = FastAPI(
    title="SOAR Malware Playbook API",
    version="2.0.0",
    summary="HTTP API for malware alert processing and response orchestration.",
)


@lru_cache
def get_workflow_service() -> SoarWorkflowService:
    return SoarWorkflowService(verbose=False)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "soar-playbook-api",
        "version": app.version,
    }


@app.post("/api/v1/incidents/process", response_model=ProcessIncidentResponse)
def process_incident(request: ProcessAlertRequest) -> ProcessIncidentResponse:
    result = get_workflow_service().process_alert(
        request.alert,
        generate_report=request.generate_report,
        export_pdf=request.export_pdf,
    )
    return ProcessIncidentResponse.from_workflow_result(result)


@app.post("/api/v1/incidents/process-scenario", response_model=ProcessIncidentResponse)
def process_scenario(request: ProcessScenarioRequest) -> ProcessIncidentResponse:
    alert = generate_alert(
        scenario=request.scenario,
        seed=request.seed,
    )
    result = get_workflow_service().process_alert(
        alert,
        generate_report=request.generate_report,
        export_pdf=request.export_pdf,
    )
    return ProcessIncidentResponse.from_workflow_result(result)
