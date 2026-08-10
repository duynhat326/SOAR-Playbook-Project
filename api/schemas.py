from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from schemas.alert import IncidentAuditEvent, IncidentNote, IncidentResponse, MalwareAlert
from services.workflow_service import WorkflowResult
from workspace_utils import normalize_workspace


ScenarioName = Literal[
    "malicious_hash",
    "c2_communication",
    "critical_asset",
    "dangerous_process",
    "mixed",
    "benign",
    "random",
]

MAX_COMMENT_LENGTH = 2000
MAX_CASE_OWNER_LENGTH = 128
MAX_IDENTITY_LENGTH = 128
MAX_NOTE_BODY_LENGTH = 4000
MAX_SAVED_FILTER_NAME_LENGTH = 128
MAX_SAVED_FILTER_BYTES = 4096
MAX_SAVED_FILTER_DEPTH = 4
MAX_SAVED_FILTER_COLLECTION_ITEMS = 50
MAX_SAVED_FILTER_SCALAR_LENGTH = 512
MAX_SAVED_FILTER_TOTAL_NODES = 128
MAX_TOP_LEVEL_FILTER_KEYS = 16
MAX_WORKSPACE_LENGTH = 64
MAX_BULK_UPDATE_ALERT_IDS = 200


def _validate_saved_filter_payload(filters: dict[str, Any]) -> dict[str, Any]:
    total_nodes = 0

    def walk(value: Any, *, depth: int) -> None:
        nonlocal total_nodes
        if depth > MAX_SAVED_FILTER_DEPTH:
            raise ValueError(
                f"Saved filters cannot be nested deeper than {MAX_SAVED_FILTER_DEPTH} levels."
            )

        if isinstance(value, dict):
            max_items = MAX_TOP_LEVEL_FILTER_KEYS if depth == 1 else MAX_SAVED_FILTER_COLLECTION_ITEMS
            if len(value) > max_items:
                raise ValueError(f"Saved filters cannot contain more than {max_items} items at this level.")
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValueError("Saved filter keys must be strings.")
                if len(key) > MAX_SAVED_FILTER_SCALAR_LENGTH:
                    raise ValueError(
                        f"Saved filter keys cannot exceed {MAX_SAVED_FILTER_SCALAR_LENGTH} characters."
                    )
                total_nodes += 1
                if total_nodes > MAX_SAVED_FILTER_TOTAL_NODES:
                    raise ValueError(
                        f"Saved filters cannot contain more than {MAX_SAVED_FILTER_TOTAL_NODES} values."
                    )
                walk(child, depth=depth + 1)
            return

        if isinstance(value, list):
            if len(value) > MAX_SAVED_FILTER_COLLECTION_ITEMS:
                raise ValueError(
                    f"Saved filter lists cannot contain more than {MAX_SAVED_FILTER_COLLECTION_ITEMS} items."
                )
            for child in value:
                total_nodes += 1
                if total_nodes > MAX_SAVED_FILTER_TOTAL_NODES:
                    raise ValueError(
                        f"Saved filters cannot contain more than {MAX_SAVED_FILTER_TOTAL_NODES} values."
                    )
                walk(child, depth=depth + 1)
            return

        if value is None or isinstance(value, (bool, int, float)):
            return

        if isinstance(value, str):
            if len(value) > MAX_SAVED_FILTER_SCALAR_LENGTH:
                raise ValueError(
                    f"Saved filter values cannot exceed {MAX_SAVED_FILTER_SCALAR_LENGTH} characters."
                )
            return

        raise ValueError("Saved filters must contain only JSON-compatible scalar, list, or object values.")

    walk(filters, depth=1)
    serialized = json.dumps(filters, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_SAVED_FILTER_BYTES:
        raise ValueError(f"Saved filters cannot exceed {MAX_SAVED_FILTER_BYTES} bytes when serialized.")
    return filters


class ProcessAlertRequest(BaseModel):
    alert: MalwareAlert
    generate_report: bool = Field(default=False)
    export_pdf: bool = Field(default=False)
    workspace: Optional[str] = Field(default=None, max_length=MAX_WORKSPACE_LENGTH)

    @field_validator("workspace")
    @classmethod
    def validate_workspace(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return normalize_workspace(value)


class ProcessScenarioRequest(BaseModel):
    scenario: ScenarioName = Field(default="mixed")
    seed: int = Field(default=2024, ge=0)
    generate_report: bool = Field(default=False)
    export_pdf: bool = Field(default=False)
    workspace: Optional[str] = Field(default=None, max_length=MAX_WORKSPACE_LENGTH)

    @field_validator("workspace")
    @classmethod
    def validate_workspace(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return normalize_workspace(value)


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
    workspace: str
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
    workspace: str
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
    case_status: Optional[str] = Field(default=None, max_length=64)
    case_owner: Optional[str] = Field(default=None, max_length=MAX_CASE_OWNER_LENGTH)
    comment: Optional[str] = Field(default=None, max_length=MAX_COMMENT_LENGTH)


class IncidentNoteCreateRequest(BaseModel):
    author: Optional[str] = Field(default=None, max_length=MAX_IDENTITY_LENGTH)
    body: str = Field(min_length=1, max_length=MAX_NOTE_BODY_LENGTH)


class BulkIncidentUpdateRequest(BaseModel):
    alert_ids: list[str] = Field(default_factory=list, min_length=1, max_length=MAX_BULK_UPDATE_ALERT_IDS)
    case_status: Optional[str] = Field(default=None, max_length=64)
    case_owner: Optional[str] = Field(default=None, max_length=MAX_CASE_OWNER_LENGTH)
    comment: Optional[str] = Field(default=None, max_length=MAX_COMMENT_LENGTH)


class ActionApprovalRequest(BaseModel):
    actor: Optional[str] = Field(default=None, max_length=MAX_IDENTITY_LENGTH)
    comment: Optional[str] = Field(default=None, max_length=MAX_COMMENT_LENGTH)


class ActionRollbackRequest(BaseModel):
    actor: Optional[str] = Field(default=None, max_length=MAX_IDENTITY_LENGTH)
    comment: Optional[str] = Field(default=None, max_length=MAX_COMMENT_LENGTH)


class IncidentReopenRequest(BaseModel):
    comment: Optional[str] = Field(default=None, max_length=MAX_COMMENT_LENGTH)


class SavedFilterCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=MAX_SAVED_FILTER_NAME_LENGTH)
    created_by: Optional[str] = Field(default=None, max_length=MAX_IDENTITY_LENGTH)
    workspace: Optional[str] = Field(default=None, max_length=MAX_WORKSPACE_LENGTH)
    filters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("workspace")
    @classmethod
    def validate_workspace(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return normalize_workspace(value)

    @field_validator("filters")
    @classmethod
    def validate_filters(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_saved_filter_payload(value)


class SavedFilterResponse(BaseModel):
    id: int
    name: str
    workspace: str
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
