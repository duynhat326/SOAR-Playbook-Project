from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from schemas.alert import IncidentAuditEvent, IncidentNote, IncidentResponse, MalwareAlert
from services.workflow_service import WorkflowResult


ScenarioName = Literal[
    "malicious_hash",
    "c2_communication",
    "critical_asset",
    "dangerous_process",
    "mixed",
    "benign",
    "random",
]


class ProcessAlertRequest(BaseModel):
    alert: MalwareAlert
    generate_report: bool = Field(default=False)
    export_pdf: bool = Field(default=False)


class ProcessScenarioRequest(BaseModel):
    scenario: ScenarioName = Field(default="mixed")
    seed: int = Field(default=2024, ge=0)
    generate_report: bool = Field(default=False)
    export_pdf: bool = Field(default=False)


class DashboardScenarioOptionResponse(BaseModel):
    value: ScenarioName
    label: str
    description: str


class DashboardSampleOptionResponse(BaseModel):
    value: str
    label: str
    scenario: ScenarioName
    description: str


class DashboardBootstrapResponse(BaseModel):
    scenario_options: list[DashboardScenarioOptionResponse] = Field(default_factory=list)
    sample_options: list[DashboardSampleOptionResponse] = Field(default_factory=list)
    sample_alerts: dict[str, MalwareAlert] = Field(default_factory=dict)
    default_sample_id: Optional[str] = None
    default_scenario: ScenarioName = "mixed"
    default_json: str


class ReportArtifactsResponse(BaseModel):
    markdown_path: Optional[str] = None
    html_path: Optional[str] = None
    pdf_path: Optional[str] = None

    @staticmethod
    def _as_str(path: Optional[Path]) -> Optional[str]:
        return str(path) if path is not None else None

    @classmethod
    def from_workflow_result(cls, result: WorkflowResult) -> "ReportArtifactsResponse":
        return cls(
            markdown_path=cls._as_str(result.artifacts.markdown_path),
            html_path=cls._as_str(result.artifacts.html_path),
            pdf_path=cls._as_str(result.artifacts.pdf_path),
        )


class ProcessIncidentResponse(BaseModel):
    response: IncidentResponse
    report: ReportArtifactsResponse

    @classmethod
    def from_workflow_result(cls, result: WorkflowResult) -> "ProcessIncidentResponse":
        return cls(
            response=redact_incident_response(result.response),
            report=ReportArtifactsResponse.from_workflow_result(result),
        )


class IncidentActionResultResponse(BaseModel):
    action: str
    status: str
    executed_at: str
    details: str
    correlation_id: Optional[str] = None
    attempt_count: int = 0
    updated_at: Optional[str] = None
    requires_approval: bool = False
    approval_state: str = "not_required"
    approval_reason: Optional[str] = None
    approval_comment: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    approval_due_at: Optional[str] = None
    approval_escalates_at: Optional[str] = None
    escalation_targets: list[str] = Field(default_factory=list)
    approval_escalated_at: Optional[str] = None
    rollback_requested_by: Optional[str] = None
    rollback_requested_at: Optional[str] = None
    operator: Optional[str] = None
    policy_version: Optional[int] = None


class StoredReportResponse(ReportArtifactsResponse):
    markdown_content: Optional[str] = None


class IncidentSummaryResponse(BaseModel):
    id: int
    alert_id: str
    incident_key: str
    latest_alert_id: str
    hostname: str
    detection_name: str
    risk_score: float
    risk_level: str
    ticket_id: Optional[str] = None
    status: str
    completed_at: str
    report_path: Optional[str] = None
    case_status: str = "new"
    case_owner: Optional[str] = None
    queued_action_count: int = 0
    pending_approval_count: int = 0
    running_action_count: int = 0
    failed_action_count: int = 0
    succeeded_action_count: int = 0
    active_action_count: int = 0
    note_count: int = 0
    related_alert_count: int = 1


class IncidentRecordResponse(BaseModel):
    id: int
    alert_id: str
    incident_key: str
    latest_alert_id: str
    hostname: str
    detection_name: str
    risk_score: float
    risk_level: str
    ticket_id: Optional[str] = None
    status: str
    completed_at: str
    report_path: Optional[str] = None
    case_status: str = "new"
    case_owner: Optional[str] = None
    queued_action_count: int = 0
    pending_approval_count: int = 0
    running_action_count: int = 0
    failed_action_count: int = 0
    succeeded_action_count: int = 0
    active_action_count: int = 0
    note_count: int = 0
    triggered_actions: list[str] = Field(default_factory=list)
    policy_reasoning: list[str] = Field(default_factory=list)
    action_results: list[IncidentActionResultResponse] = Field(default_factory=list)
    created_at: str
    updated_at: str
    alert: MalwareAlert
    response: IncidentResponse
    report: StoredReportResponse
    notes: list[IncidentNote] = Field(default_factory=list)
    audit_events: list[IncidentAuditEvent] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    related_alert_count: int = 1


class IncidentCaseUpdateRequest(BaseModel):
    case_status: Optional[str] = None
    case_owner: Optional[str] = None
    comment: Optional[str] = None


class IncidentNoteCreateRequest(BaseModel):
    author: str
    body: str


class BulkIncidentUpdateRequest(BaseModel):
    alert_ids: list[str] = Field(default_factory=list)
    case_status: Optional[str] = None
    case_owner: Optional[str] = None
    comment: Optional[str] = None


class ActionApprovalRequest(BaseModel):
    actor: str
    comment: Optional[str] = None


class ActionRollbackRequest(BaseModel):
    actor: str
    comment: Optional[str] = None


class IncidentReopenRequest(BaseModel):
    comment: Optional[str] = None


class SavedFilterCreateRequest(BaseModel):
    name: str
    created_by: str
    filters: dict[str, Any] = Field(default_factory=dict)


class SavedFilterResponse(BaseModel):
    id: int
    name: str
    filters: dict[str, Any] = Field(default_factory=dict)
    created_by: str
    created_at: str
    updated_at: str


class DependencyReadinessResponse(BaseModel):
    name: str
    provider: str
    status: str
    detail: str
    meta: dict[str, Any] = Field(default_factory=dict)


class ReadinessResponse(BaseModel):
    status: str
    dependencies: list[DependencyReadinessResponse] = Field(default_factory=list)
    queue_metrics: dict[str, Any] = Field(default_factory=dict)
    observability: dict[str, Any] = Field(default_factory=dict)


_REDACTED_FIELDS = {
    "username",
    "command_line",
    "file_hash",
    "file_path",
}


def redact_incident_response(response: IncidentResponse) -> IncidentResponse:
    payload = response.model_dump(mode="json")
    _redact_alert_payload(payload.get("enriched_alert", {}).get("original_alert", {}))
    return IncidentResponse.model_validate(payload)


def redact_incident_record(record: dict) -> dict:
    sanitized = dict(record)
    _redact_alert_payload(sanitized.get("alert", {}))
    _redact_alert_payload(
        sanitized.get("response", {}).get("enriched_alert", {}).get("original_alert", {})
    )
    return sanitized


def _redact_alert_payload(payload: dict) -> None:
    for field in _REDACTED_FIELDS:
        if field in payload:
            payload[field] = _redacted_value(field, payload[field])


def _redacted_value(field: str, current_value: object) -> str:
    if field == "file_hash":
        raw = str(current_value)
        if len(raw) in (32, 40, 64):
            return "0" * len(raw)
        return "0" * 64
    if field == "file_path":
        return "[redacted-path]"
    return "[redacted]"
