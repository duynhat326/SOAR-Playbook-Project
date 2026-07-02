from __future__ import annotations

from functools import lru_cache
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query

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
    IncidentRecordResponse,
    IncidentSummaryResponse,
    ProcessAlertRequest,
    ProcessIncidentResponse,
    ProcessScenarioRequest,
    redact_incident_record,
)
from security import (
    ROLE_A2A_ADMIN,
    ROLE_A2A_AGENT,
    ROLE_A2A_READ,
    ROLE_INCIDENT_PROCESS,
    ROLE_INCIDENT_READ,
    AuthenticatedPrincipal,
    AuthorizationError,
    require_roles,
)
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import MAX_INCIDENT_LIST_LIMIT

app = FastAPI(
    title="SOAR Malware Playbook API",
    version="2.0.0",
    summary="HTTP API for malware alert processing and response orchestration.",
)


def _require_bound_principal(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal:
    if not isinstance(principal, AuthenticatedPrincipal):
        raise HTTPException(status_code=401, detail="Authenticated principal is required.")
    return principal


@lru_cache
def get_workflow_service() -> SoarWorkflowService:
    return SoarWorkflowService(verbose=False)


@lru_cache
def get_a2a_service() -> A2AService:
    return A2AService()


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "soar-playbook-api",
        "version": app.version,
    }


@app.post("/api/v1/incidents/process", response_model=ProcessIncidentResponse)
def process_incident(
    request: ProcessAlertRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> ProcessIncidentResponse:
    principal = _require_bound_principal(principal)
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
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> list[IncidentSummaryResponse]:
    principal = _require_bound_principal(principal)
    incidents = get_workflow_service().list_incidents(
        limit=limit,
        status=status,
        risk_level=risk_level,
        hostname=hostname,
        ticket_id=ticket_id,
    )
    return [IncidentSummaryResponse.model_validate(item) for item in incidents]


@app.get("/api/v1/incidents/by-alert/{alert_id}", response_model=IncidentRecordResponse)
def get_incident_by_alert_id(
    alert_id: str,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    incident = get_workflow_service().get_incident_by_alert_id(alert_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found for alert_id={alert_id}")
    return IncidentRecordResponse.model_validate(redact_incident_record(incident))


@app.get("/api/v1/incidents/by-ticket/{ticket_id}", response_model=IncidentRecordResponse)
def get_incident_by_ticket_id(
    ticket_id: str,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    incident = get_workflow_service().get_incident_by_ticket_id(ticket_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found for ticket_id={ticket_id}")
    return IncidentRecordResponse.model_validate(redact_incident_record(incident))


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
