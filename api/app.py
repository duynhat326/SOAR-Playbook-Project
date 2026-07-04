from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from alert_generator.generator import generate_alert
from a2a.schemas import (
    AgentHeartbeatRequest,
    AgentRecord,
    AgentRegistrationRequest,
    ArtifactCreateRequest,
    ArtifactRecord,
    MessageCreateRequest,
    MessageRecord,
    TaskClaimRequest,
    TaskCompleteRequest,
    TaskCreateRequest,
    TaskRecord,
    TimelineEvent,
    WorkspaceCreateRequest,
    WorkspaceRecord,
)
from a2a.service import A2AService
from api.schemas import (
    ActionApprovalRequest,
    BulkIncidentUpdateRequest,
    DashboardBootstrapResponse,
    DashboardSampleOptionResponse,
    DashboardScenarioOptionResponse,
    IncidentCaseUpdateRequest,
    IncidentNoteCreateRequest,
    IncidentRecordResponse,
    ReadinessResponse,
    SavedFilterCreateRequest,
    SavedFilterResponse,
    IncidentSummaryResponse,
    ProcessAlertRequest,
    ProcessIncidentResponse,
    ProcessScenarioRequest,
    redact_incident_record,
)
from env_utils import load_local_env_files
from security import (
    ROLE_A2A_ADMIN,
    ROLE_A2A_AGENT,
    ROLE_A2A_READ,
    ROLE_INCIDENT_PROCESS,
    ROLE_INCIDENT_READ,
    AuthenticatedPrincipal,
    AuthorizationError,
    ensure_roles,
    require_roles,
)
from services.workflow_service import SoarWorkflowService
from storage.incident_repository import MAX_INCIDENT_LIST_LIMIT

load_local_env_files()

_REPO_ROOT = Path(__file__).resolve().parent.parent
_REPORT_ARTIFACT_ROOT = (_REPO_ROOT / "output").resolve()
_SAMPLE_ALERT_DIR = _REPO_ROOT / "data" / "sample_alerts"
_DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
)
_SCENARIO_OPTIONS = (
    ("malicious_hash", "Malicious hash", "Confirmed malicious file hash with strong vendor consensus."),
    ("c2_communication", "C2 communication", "Outbound connection shows command-and-control characteristics."),
    ("critical_asset", "Critical asset", "High-value host requires analyst attention even before containment."),
    ("dangerous_process", "Dangerous process", "Known offensive tooling is executing on the endpoint."),
    ("mixed", "Mixed chain", "Multiple policy branches fire together for a full critical-path exercise."),
    ("benign", "Benign", "Low-risk baseline for smoke tests and report verification."),
    ("random", "Random", "Generate a reproducible scenario mix using the provided seed."),
)
_SAMPLE_LABELS = {
    "alert_01_malicious_hash": "Malicious hash confirmed",
    "alert_02_c2_communication": "C2 communication",
    "alert_03_critical_asset": "Critical asset escalation",
    "alert_04_full_critical": "Full critical chain",
    "alert_05_benign": "Benign baseline",
}

app = FastAPI(
    title="SOAR Malware Playbook API",
    version="2.0.0",
    summary="HTTP API for malware alert processing and response orchestration.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv("SOAR_API_CORS_ORIGINS", ",".join(_DEFAULT_CORS_ORIGINS)).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _require_bound_principal(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal:
    if not isinstance(principal, AuthenticatedPrincipal):
        raise HTTPException(status_code=401, detail="Authenticated principal is required.")
    return principal


def _principal_actor(principal: AuthenticatedPrincipal) -> str:
    return principal.agent_id or principal.principal_id


def _get_incident_or_404(alert_id: str) -> dict[str, Any]:
    incident = get_workflow_service().get_incident_by_alert_id(alert_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found for alert_id={alert_id}")
    return incident


def _serialize_incident_record_for_principal(
    incident: dict[str, Any],
    *,
    principal: AuthenticatedPrincipal,
    include_sensitive: bool,
) -> IncidentRecordResponse:
    if include_sensitive:
        try:
            ensure_roles(principal, ROLE_INCIDENT_PROCESS)
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return IncidentRecordResponse.model_validate(incident)

    return IncidentRecordResponse.model_validate(redact_incident_record(incident))


def _alert_contains_redacted_markers(alert: Any) -> bool:
    username = str(getattr(alert, "username", "") or "")
    file_path = str(getattr(alert, "file_path", "") or "")
    command_line = str(getattr(alert, "command_line", "") or "")
    file_hash = str(getattr(alert, "file_hash", "") or "")
    return (
        username == "[redacted]"
        or file_path == "[redacted-path]"
        or command_line == "[redacted]"
        or (len(file_hash) in (32, 40, 64) and set(file_hash) == {"0"})
    )


def _assert_processable_alert_payload(alert: Any) -> None:
    if _alert_contains_redacted_markers(alert):
        raise HTTPException(
            status_code=422,
            detail=(
                "The submitted alert payload appears to be sanitized/redacted. "
                "Use the original raw alert JSON with the real file_hash, file_path, command_line, and username."
            ),
        )


def _resolve_report_artifact_path(raw_path: Optional[str]) -> Path:
    if not raw_path:
        raise HTTPException(status_code=404, detail="Report artifact is unavailable for this incident.")

    candidate = Path(raw_path)
    resolved = candidate.resolve() if candidate.is_absolute() else (_REPO_ROOT / candidate).resolve()

    try:
        resolved.relative_to(_REPORT_ARTIFACT_ROOT)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Report artifact path is invalid.") from exc

    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="Report artifact not found.")
    return resolved


def _resolve_incident_html_report_path(incident: dict[str, Any]) -> Path:
    report = incident.get("report") or {}
    response = incident.get("response") or {}
    raw_path = (
        report.get("html_path")
        or incident.get("report_path")
        or response.get("report_path")
    )
    return _resolve_report_artifact_path(raw_path)


@lru_cache
def get_workflow_service() -> SoarWorkflowService:
    return SoarWorkflowService(verbose=False)


@lru_cache
def get_a2a_service() -> A2AService:
    return A2AService()


@lru_cache
def get_dashboard_bootstrap() -> DashboardBootstrapResponse:
    sample_options: list[DashboardSampleOptionResponse] = []
    sample_alerts: dict[str, Any] = {}

    for sample_path in sorted(_SAMPLE_ALERT_DIR.glob("*.json")):
        if sample_path.name.startswith("."):
            continue

        payload = json.loads(sample_path.read_text(encoding="utf-8"))
        sample_id = sample_path.stem
        scenario = str(payload.get("_scenario") or "mixed").strip().lower()
        description = str(
            payload.get("_description") or f"Bundled sample alert from {sample_path.name}."
        ).strip()
        alert_payload = {
            key: value
            for key, value in payload.items()
            if not str(key).startswith("_")
        }
        sample_alerts[sample_id] = alert_payload
        sample_options.append(
            DashboardSampleOptionResponse(
                value=sample_id,
                label=_SAMPLE_LABELS.get(sample_id, sample_id.replace("_", " ").title()),
                scenario=scenario,
                description=description,
            )
        )

    default_sample_id = sample_options[0].value if sample_options else None
    default_alert = sample_alerts.get(default_sample_id, {})
    return DashboardBootstrapResponse(
        scenario_options=[
            DashboardScenarioOptionResponse(
                value=value,
                label=label,
                description=description,
            )
            for value, label, description in _SCENARIO_OPTIONS
        ],
        sample_options=sample_options,
        sample_alerts=sample_alerts,
        default_sample_id=default_sample_id,
        default_scenario="mixed",
        default_json=json.dumps(default_alert, indent=2, ensure_ascii=False),
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "soar-playbook-api",
        "version": app.version,
    }


@app.get("/api/v1/ready", response_model=ReadinessResponse)
def readiness(
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ, ROLE_INCIDENT_PROCESS)),
) -> ReadinessResponse:
    principal = _require_bound_principal(principal)
    return ReadinessResponse.model_validate(get_workflow_service().get_readiness())


@app.get("/api/v1/dashboard/bootstrap", response_model=DashboardBootstrapResponse)
def dashboard_bootstrap(
    principal: AuthenticatedPrincipal = Depends(
        require_roles(ROLE_INCIDENT_READ, ROLE_INCIDENT_PROCESS)
    ),
) -> DashboardBootstrapResponse:
    principal = _require_bound_principal(principal)
    return get_dashboard_bootstrap()


@app.post("/api/v1/incidents/process", response_model=ProcessIncidentResponse)
def process_incident(
    request: ProcessAlertRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> ProcessIncidentResponse:
    principal = _require_bound_principal(principal)
    _assert_processable_alert_payload(request.alert)
    result = get_workflow_service().process_alert(
        request.alert,
        generate_report=request.generate_report,
        export_pdf=request.export_pdf,
    )
    return ProcessIncidentResponse.from_workflow_result(result)


@app.post("/api/v1/incidents/process-scenario", response_model=ProcessIncidentResponse)
def process_scenario(
    request: ProcessScenarioRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> ProcessIncidentResponse:
    principal = _require_bound_principal(principal)
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


@app.get("/api/v1/incidents", response_model=list[IncidentSummaryResponse])
def list_incidents(
    limit: int = Query(default=50, ge=1, le=MAX_INCIDENT_LIST_LIMIT),
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    hostname: Optional[str] = None,
    ticket_id: Optional[str] = None,
    case_status: Optional[str] = None,
    case_owner: Optional[str] = None,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> list[IncidentSummaryResponse]:
    principal = _require_bound_principal(principal)
    incidents = get_workflow_service().list_incidents(
        limit=limit,
        status=status,
        risk_level=risk_level,
        hostname=hostname,
        ticket_id=ticket_id,
        case_status=case_status,
        case_owner=case_owner,
    )
    return [IncidentSummaryResponse.model_validate(item) for item in incidents]


@app.post("/api/v1/incidents/bulk-update", response_model=list[IncidentRecordResponse])
def bulk_update_incidents(
    request: BulkIncidentUpdateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> list[IncidentRecordResponse]:
    principal = _require_bound_principal(principal)
    incidents = get_workflow_service().bulk_update_incidents(
        request.alert_ids,
        case_status=request.case_status,
        case_owner=request.case_owner,
        actor=_principal_actor(principal),
        comment=request.comment,
    )
    return [IncidentRecordResponse.model_validate(incident) for incident in incidents]


@app.get("/api/v1/incidents/saved-filters", response_model=list[SavedFilterResponse])
def list_saved_filters(
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> list[SavedFilterResponse]:
    principal = _require_bound_principal(principal)
    return [SavedFilterResponse.model_validate(item) for item in get_workflow_service().list_saved_filters()]


@app.post("/api/v1/incidents/saved-filters", response_model=SavedFilterResponse)
def save_filter(
    request: SavedFilterCreateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> SavedFilterResponse:
    principal = _require_bound_principal(principal)
    saved = get_workflow_service().save_filter(
        name=request.name,
        filters=request.filters,
        created_by=request.created_by or _principal_actor(principal),
    )
    return SavedFilterResponse.model_validate(saved)


@app.get("/api/v1/incidents/by-alert/{alert_id}", response_model=IncidentRecordResponse)
def get_incident_by_alert_id(
    alert_id: str,
    include_sensitive: bool = False,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    incident = _get_incident_or_404(alert_id)
    return _serialize_incident_record_for_principal(
        incident,
        principal=principal,
        include_sensitive=include_sensitive,
    )


@app.patch("/api/v1/incidents/by-alert/{alert_id}", response_model=IncidentRecordResponse)
def update_incident_case(
    alert_id: str,
    request: IncidentCaseUpdateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    incident = get_workflow_service().update_incident_case(
        alert_id,
        case_status=request.case_status,
        case_owner=request.case_owner,
        actor=_principal_actor(principal),
        comment=request.comment,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found for alert_id={alert_id}")
    return IncidentRecordResponse.model_validate(incident)


@app.post("/api/v1/incidents/by-alert/{alert_id}/notes")
def add_incident_note(
    alert_id: str,
    request: IncidentNoteCreateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> dict[str, Any]:
    principal = _require_bound_principal(principal)
    note = get_workflow_service().add_incident_note(
        alert_id,
        author=request.author or _principal_actor(principal),
        body=request.body,
    )
    if note is None:
        raise HTTPException(status_code=404, detail=f"Incident not found for alert_id={alert_id}")
    return note


@app.post("/api/v1/incidents/by-alert/{alert_id}/actions/{correlation_id}/approve", response_model=IncidentRecordResponse)
def approve_action(
    alert_id: str,
    correlation_id: str,
    request: ActionApprovalRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    try:
        incident = get_workflow_service().approve_action(
            alert_id,
            correlation_id,
            actor=request.actor or _principal_actor(principal),
            comment=request.comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Queued action not found for alert_id={alert_id} correlation_id={correlation_id}",
        )
    return IncidentRecordResponse.model_validate(incident)


@app.post("/api/v1/incidents/by-alert/{alert_id}/actions/{correlation_id}/reject", response_model=IncidentRecordResponse)
def reject_action(
    alert_id: str,
    correlation_id: str,
    request: ActionApprovalRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    try:
        incident = get_workflow_service().reject_action(
            alert_id,
            correlation_id,
            actor=request.actor or _principal_actor(principal),
            comment=request.comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Queued action not found for alert_id={alert_id} correlation_id={correlation_id}",
        )
    return IncidentRecordResponse.model_validate(incident)


@app.get("/api/v1/incidents/by-alert/{alert_id}/report/html")
def get_incident_report_html(
    alert_id: str,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> FileResponse:
    principal = _require_bound_principal(principal)
    incident = _get_incident_or_404(alert_id)
    report_path = _resolve_incident_html_report_path(incident)
    return FileResponse(
        path=report_path,
        media_type="text/html",
        filename=report_path.name,
    )


@app.get("/api/v1/incidents/by-ticket/{ticket_id}", response_model=IncidentRecordResponse)
def get_incident_by_ticket_id(
    ticket_id: str,
    include_sensitive: bool = False,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    incident = get_workflow_service().get_incident_by_ticket_id(ticket_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found for ticket_id={ticket_id}")
    return _serialize_incident_record_for_principal(
        incident,
        principal=principal,
        include_sensitive=include_sensitive,
    )


@app.get("/api/v1/a2a/health")
def a2a_health(
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_READ, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> dict[str, str]:
    principal = _require_bound_principal(principal)
    return {
        "status": "ok",
        "service": "soar-a2a-bus",
        "version": app.version,
    }


@app.post("/api/v1/a2a/workspaces", response_model=WorkspaceRecord)
def ensure_workspace(
    request: WorkspaceCreateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_ADMIN)),
) -> WorkspaceRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().ensure_workspace(request, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/v1/a2a/agents/register", response_model=AgentRecord)
def register_agent(
    request: AgentRegistrationRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_ADMIN)),
) -> AgentRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().register_agent(request, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/v1/a2a/agents/{agent_id}/heartbeat", response_model=AgentRecord)
def heartbeat_agent(
    agent_id: str,
    request: AgentHeartbeatRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> AgentRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().heartbeat_agent(agent_id, request.status, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/v1/a2a/agents", response_model=list[AgentRecord])
def list_agents(
    workspace: str,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_READ, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> list[AgentRecord]:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().list_agents(workspace, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/v1/a2a/tasks", response_model=TaskRecord)
def create_task(
    request: TaskCreateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> TaskRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().create_task(request, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/a2a/tasks", response_model=list[TaskRecord])
def list_tasks(
    workspace: str,
    status: Optional[str] = None,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_READ, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> list[TaskRecord]:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().list_tasks(workspace, status, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/v1/a2a/tasks/{task_id}/claim", response_model=TaskRecord)
def claim_task(
    task_id: str,
    request: TaskClaimRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> TaskRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().claim_task(task_id, request, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/v1/a2a/tasks/{task_id}/complete", response_model=TaskRecord)
def complete_task(
    task_id: str,
    request: TaskCompleteRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> TaskRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().complete_task(task_id, request, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/v1/a2a/messages", response_model=MessageRecord)
def post_message(
    request: MessageCreateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> MessageRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().post_message(request, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/a2a/messages", response_model=list[MessageRecord])
def poll_messages(
    workspace: str,
    agent_id: str,
    limit: int = 20,
    after: Optional[str] = None,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> list[MessageRecord]:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().poll_messages(
            workspace=workspace,
            agent_id=agent_id,
            limit=limit,
            after=after,
            principal=principal,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v1/a2a/artifacts", response_model=ArtifactRecord)
def publish_artifact(
    request: ArtifactCreateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> ArtifactRecord:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().publish_artifact(request, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/a2a/timeline", response_model=list[TimelineEvent])
def timeline(
    workspace: str,
    limit: int = 50,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_A2A_READ, ROLE_A2A_AGENT, ROLE_A2A_ADMIN)),
) -> list[TimelineEvent]:
    principal = _require_bound_principal(principal)
    try:
        return get_a2a_service().timeline(workspace, limit, principal=principal)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
