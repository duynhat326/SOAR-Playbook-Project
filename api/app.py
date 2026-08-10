from __future__ import annotations

import json
import os
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from alert_generator.generator import generate_alert
from api.schemas import (
    ActionApprovalRequest,
    ActionRollbackRequest,
    BulkIncidentUpdateRequest,
    DashboardBootstrapResponse,
    DashboardSampleOptionResponse,
    DashboardScenarioOptionResponse,
    IncidentCaseUpdateRequest,
    IncidentNoteCreateRequest,
    IncidentReopenRequest,
    IncidentRecordResponse,
    IncidentSummaryResponse,
    ProcessAlertRequest,
    ProcessIncidentResponse,
    ProcessScenarioRequest,
    ReadinessResponse,
    SavedFilterCreateRequest,
    SavedFilterResponse,
    redact_incident_record,
)
from env_utils import load_local_env_files
from observability import observability
from security import (
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


def _resolve_authenticated_actor(
    principal: AuthenticatedPrincipal,
    claimed_actor: Optional[str],
    *,
    field_name: str,
) -> str:
    expected_actor = _principal_actor(principal)
    candidate = (claimed_actor or "").strip()
    if candidate and candidate != expected_actor:
        raise HTTPException(
            status_code=403,
            detail=f"Request field '{field_name}' must match the authenticated principal.",
        )
    return expected_actor


def _resolve_workspace_for_principal(
    principal: AuthenticatedPrincipal,
    requested_workspace: Optional[str],
) -> str:
    try:
        return principal.resolve_workspace(requested_workspace)
    except ValueError as exc:
        detail = str(exc)
        status_code = 403 if "not authorized" in detail else 400
        raise HTTPException(status_code=status_code, detail=detail) from exc


def _ensure_incident_workspace_access(
    incident: dict[str, Any],
    *,
    principal: AuthenticatedPrincipal,
    selector: str,
) -> dict[str, Any]:
    if principal.can_access_workspace(incident.get("workspace")):
        return incident
    raise HTTPException(status_code=404, detail=f"Incident not found for {selector}")


@contextmanager
def _route_context(
    route_name: str,
    *,
    principal: AuthenticatedPrincipal | None = None,
    **fields: Any,
) -> Iterator[AuthenticatedPrincipal | None]:
    bound_principal = _require_bound_principal(principal) if principal is not None else None
    status = "ok"
    with observability.trace(
        f"api.{route_name}",
        route_name=route_name,
        actor=_principal_actor(bound_principal) if bound_principal is not None else None,
        **fields,
    ):
        try:
            yield bound_principal
        except HTTPException as exc:
            status = str(exc.status_code)
            observability.emit_event(
                "warning",
                "api.request_failed",
                message=f"{route_name} failed",
                route_name=route_name,
                status_code=exc.status_code,
            )
            raise
        except Exception as exc:
            status = "error"
            observability.emit_event(
                "error",
                "api.request_failed",
                message=f"{route_name} failed",
                route_name=route_name,
                error=exc.__class__.__name__,
            )
            raise
        finally:
            observability.metrics.incr(
                "api.requests_total",
                route_name=route_name,
                status=status,
            )


def _get_incident_or_404(alert_id: str) -> dict[str, Any]:
    incident = get_workflow_service().get_incident_by_alert_id(alert_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found for alert_id={alert_id}")
    return incident


def _get_scoped_incident_or_404(
    alert_id: str,
    *,
    principal: AuthenticatedPrincipal,
) -> dict[str, Any]:
    return _ensure_incident_workspace_access(
        _get_incident_or_404(alert_id),
        principal=principal,
        selector=f"alert_id={alert_id}",
    )


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
    with _route_context("health"):
        return {
            "status": "ok",
            "service": "soar-playbook-api",
            "version": app.version,
        }


@app.get("/api/v1/ready", response_model=ReadinessResponse)
def readiness(
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ, ROLE_INCIDENT_PROCESS)),
) -> ReadinessResponse:
    with _route_context("ready", principal=principal) as bound_principal:
        assert bound_principal is not None
        return ReadinessResponse.model_validate(get_workflow_service().get_readiness())


@app.get("/api/v1/observability", response_model=dict[str, Any])
def observability_snapshot(
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ, ROLE_INCIDENT_PROCESS)),
) -> dict[str, Any]:
    with _route_context("observability", principal=principal) as bound_principal:
        assert bound_principal is not None
        return get_workflow_service().get_observability_snapshot()


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
    with _route_context(
        "process_incident",
        principal=principal,
        alert_id=request.alert.alert_id,
        hostname=request.alert.hostname,
    ) as bound_principal:
        assert bound_principal is not None
        _assert_processable_alert_payload(request.alert)
        workspace = _resolve_workspace_for_principal(bound_principal, request.workspace)
        alert = request.alert.model_copy(update={"workspace": workspace})
        result = get_workflow_service().process_alert(
            alert,
            generate_report=request.generate_report,
            export_pdf=request.export_pdf,
            workspace=workspace,
        )
        return ProcessIncidentResponse.from_workflow_result(result)


@app.post("/api/v1/incidents/process-scenario", response_model=ProcessIncidentResponse)
def process_scenario(
    request: ProcessScenarioRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> ProcessIncidentResponse:
    with _route_context(
        "process_scenario",
        principal=principal,
        scenario=request.scenario,
        seed=request.seed,
    ) as bound_principal:
        assert bound_principal is not None
        workspace = _resolve_workspace_for_principal(bound_principal, request.workspace)
        alert = generate_alert(
            scenario=request.scenario,
            seed=request.seed,
        ).model_copy(update={"workspace": workspace})
        result = get_workflow_service().process_alert(
            alert,
            generate_report=request.generate_report,
            export_pdf=request.export_pdf,
            workspace=workspace,
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
    with _route_context(
        "list_incidents",
        principal=principal,
        limit=limit,
        status_filter=status,
        risk_level=risk_level,
        hostname=hostname,
        ticket_id=ticket_id,
        case_status=case_status,
        case_owner=case_owner,
    ) as bound_principal:
        assert bound_principal is not None
        incidents = get_workflow_service().list_incidents(
            limit=limit,
            status=status,
            risk_level=risk_level,
            hostname=hostname,
            ticket_id=ticket_id,
            case_status=case_status,
            case_owner=case_owner,
            workspaces=bound_principal.effective_workspaces(),
        )
        return [IncidentSummaryResponse.model_validate(item) for item in incidents]


@app.post("/api/v1/incidents/bulk-update", response_model=list[IncidentRecordResponse])
def bulk_update_incidents(
    request: BulkIncidentUpdateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> list[IncidentRecordResponse]:
    principal = _require_bound_principal(principal)
    for alert_id in request.alert_ids:
        _get_scoped_incident_or_404(alert_id, principal=principal)
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
    return [
        SavedFilterResponse.model_validate(item)
        for item in get_workflow_service().list_saved_filters(
            workspaces=principal.effective_workspaces()
        )
    ]


@app.post("/api/v1/incidents/saved-filters", response_model=SavedFilterResponse)
def save_filter(
    request: SavedFilterCreateRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> SavedFilterResponse:
    principal = _require_bound_principal(principal)
    created_by = _resolve_authenticated_actor(
        principal,
        request.created_by,
        field_name="created_by",
    )
    workspace = _resolve_workspace_for_principal(principal, request.workspace)
    saved = get_workflow_service().save_filter(
        name=request.name,
        filters=request.filters,
        created_by=created_by,
        workspace=workspace,
    )
    return SavedFilterResponse.model_validate(saved)


@app.get("/api/v1/incidents/by-alert/{alert_id}", response_model=IncidentRecordResponse)
def get_incident_by_alert_id(
    alert_id: str,
    include_sensitive: bool = False,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> IncidentRecordResponse:
    principal = _require_bound_principal(principal)
    incident = _get_scoped_incident_or_404(alert_id, principal=principal)
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
    with _route_context("update_incident_case", principal=principal, alert_id=alert_id) as bound_principal:
        _get_scoped_incident_or_404(alert_id, principal=bound_principal)
        incident = get_workflow_service().update_incident_case(
            alert_id,
            case_status=request.case_status,
            case_owner=request.case_owner,
            actor=_principal_actor(bound_principal),
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
    with _route_context("add_incident_note", principal=principal, alert_id=alert_id) as bound_principal:
        _get_scoped_incident_or_404(alert_id, principal=bound_principal)
        author = _resolve_authenticated_actor(
            bound_principal,
            request.author,
            field_name="author",
        )
        note = get_workflow_service().add_incident_note(
            alert_id,
            author=author,
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
    with _route_context(
        "approve_action",
        principal=principal,
        alert_id=alert_id,
        correlation_id=correlation_id,
    ) as bound_principal:
        _get_scoped_incident_or_404(alert_id, principal=bound_principal)
        try:
            actor = _resolve_authenticated_actor(
                bound_principal,
                request.actor,
                field_name="actor",
            )
            incident = get_workflow_service().approve_action(
                alert_id,
                correlation_id,
                actor=actor,
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
    with _route_context(
        "reject_action",
        principal=principal,
        alert_id=alert_id,
        correlation_id=correlation_id,
    ) as bound_principal:
        _get_scoped_incident_or_404(alert_id, principal=bound_principal)
        try:
            actor = _resolve_authenticated_actor(
                bound_principal,
                request.actor,
                field_name="actor",
            )
            incident = get_workflow_service().reject_action(
                alert_id,
                correlation_id,
                actor=actor,
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


@app.post("/api/v1/incidents/by-alert/{alert_id}/actions/{correlation_id}/rollback", response_model=IncidentRecordResponse)
def rollback_action(
    alert_id: str,
    correlation_id: str,
    request: ActionRollbackRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> IncidentRecordResponse:
    with _route_context(
        "rollback_action",
        principal=principal,
        alert_id=alert_id,
        correlation_id=correlation_id,
    ) as bound_principal:
        _get_scoped_incident_or_404(alert_id, principal=bound_principal)
        try:
            actor = _resolve_authenticated_actor(
                bound_principal,
                request.actor,
                field_name="actor",
            )
            incident = get_workflow_service().rollback_action(
                alert_id,
                correlation_id,
                actor=actor,
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


@app.post("/api/v1/incidents/by-alert/{alert_id}/reopen", response_model=IncidentRecordResponse)
def reopen_incident(
    alert_id: str,
    request: IncidentReopenRequest,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> IncidentRecordResponse:
    with _route_context("reopen_incident", principal=principal, alert_id=alert_id) as bound_principal:
        _get_scoped_incident_or_404(alert_id, principal=bound_principal)
        try:
            incident = get_workflow_service().reopen_incident(
                alert_id,
                actor=_principal_actor(bound_principal),
                comment=request.comment,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if incident is None:
            raise HTTPException(status_code=404, detail=f"Incident not found for alert_id={alert_id}")
        return IncidentRecordResponse.model_validate(incident)


@app.post("/api/v1/approvals/escalate-overdue", response_model=list[IncidentRecordResponse])
def escalate_overdue_approvals(
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_PROCESS)),
) -> list[IncidentRecordResponse]:
    with _route_context("escalate_overdue_approvals", principal=principal) as bound_principal:
        incidents = get_workflow_service().escalate_overdue_approvals(
            actor=_principal_actor(bound_principal),
        )
        return [IncidentRecordResponse.model_validate(incident) for incident in incidents]


@app.get("/api/v1/incidents/by-alert/{alert_id}/report/html")
def get_incident_report_html(
    alert_id: str,
    principal: AuthenticatedPrincipal = Depends(require_roles(ROLE_INCIDENT_READ)),
) -> FileResponse:
    principal = _require_bound_principal(principal)
    incident = _get_scoped_incident_or_404(alert_id, principal=principal)
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
    incident = _ensure_incident_workspace_access(
        incident,
        principal=principal,
        selector=f"ticket_id={ticket_id}",
    )
    return _serialize_incident_record_for_principal(
        incident,
        principal=principal,
        include_sensitive=include_sensitive,
    )
