"""
schemas/alert.py
================
Pydantic schemas shared across the SOAR workflow.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from time_utils import utc_now


class Severity(str, Enum):
    """Alert severity values from the input spec."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HashReputation(str, Enum):
    """Hash reputation from the mock threat intel source."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class IPReputation(str, Enum):
    """IP reputation from the mock threat intel source."""

    MALICIOUS = "malicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class AssetCriticality(str, Enum):
    """Criticality classification from the mock CMDB source."""

    CRITICAL = "critical"
    NORMAL = "normal"
    LOW = "low"


class PolicyStatus(str, Enum):
    """Governance state for a response policy version."""

    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class ResponseAction(str, Enum):
    """Response actions the policy engine can request."""

    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    ESCALATE = "escalate"
    CREATE_TICKET = "create_ticket"
    NOTIFY_SOC = "notify_soc"
    NO_ACTION = "no_action"


class ActionExecutionStatus(str, Enum):
    """Lifecycle state for synchronous and asynchronous remediation actions."""

    QUEUED = "queued"
    WAITING_APPROVAL = "waiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class ActionApprovalState(str, Enum):
    """Approval lifecycle for queued remediation actions."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class IncidentCaseStatus(str, Enum):
    """Case-management lifecycle for analyst workflow."""

    NEW = "new"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CorrelationOutcome(str, Enum):
    """Lifecycle outcome for alert-to-incident correlation."""

    NEW_INCIDENT = "new_incident"
    ATTACHED_TO_EXISTING = "attached_to_existing"
    REOPENED_INCIDENT = "reopened_incident"


class MalwareAlert(BaseModel):
    """Canonical malware alert payload from EDR/SIEM."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "hostname": "DESKTOP-FIN01",
                "username": "jane.smith",
                "process_name": "powershell.exe",
                "file_path": "C:\\Windows\\Temp\\beacon.ps1",
                "file_hash": "a" * 64,
                "parent_process": "winword.exe",
                "command_line": "powershell.exe -enc SGVsbG8=",
                "destination_ip": "185.220.101.45",
                "severity": "high",
                "detection_name": "Malware.Powershell.Encoded",
            }
        }
    )

    alert_id: str = Field(
        ...,
        description="Unique alert identifier",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    )
    hostname: str = Field(
        ...,
        description="Impacted host",
        examples=["DESKTOP-ABC123", "WS-FINANCE-01"],
    )
    username: str = Field(
        ...,
        description="User running the process",
        examples=["john.doe", "SYSTEM"],
    )
    process_name: str = Field(
        ...,
        description="Process name",
        examples=["powershell.exe", "cmd.exe", "mimikatz.exe"],
    )
    file_path: str = Field(
        ...,
        description="Full path to the executable",
        examples=["C:\\Users\\john\\AppData\\Local\\Temp\\payload.exe"],
    )
    file_hash: str = Field(
        ...,
        description="File hash",
        examples=["d41d8cd98f00b204e9800998ecf8427e"],
    )
    parent_process: str = Field(
        ...,
        description="Parent process name",
        examples=["explorer.exe", "winword.exe"],
    )
    command_line: str = Field(
        ...,
        description="Process command line",
        examples=["powershell.exe -enc SGVsbG8gV29ybGQ="],
    )
    destination_ip: str = Field(
        ...,
        description="Destination IPv4 address",
        examples=["185.220.101.45", "10.0.0.1"],
    )
    severity: Severity = Field(
        ...,
        description="Severity level: low | medium | high | critical",
    )
    detection_name: str = Field(
        ...,
        description="Triggered detection name",
        examples=["Trojan.Generic", "Malware.Powershell.Encoded"],
    )
    received_at: datetime = Field(
        default_factory=utc_now,
        description="Time the alert entered the SOAR pipeline (UTC)",
    )

    @field_validator("file_hash")
    @classmethod
    def validate_hash_format(cls, value: str) -> str:
        if len(value) not in (32, 40, 64):
            raise ValueError(
                f"Hash '{value}' has an invalid length. Expected MD5 (32), SHA1 (40), or SHA256 (64)."
            )
        return value.lower()

    @field_validator("destination_ip")
    @classmethod
    def validate_ip_format(cls, value: str) -> str:
        parts = value.split(".")
        if len(parts) != 4:
            raise ValueError(f"IP '{value}' is not a valid IPv4 address.")
        for part in parts:
            if not part.isdigit() or not (0 <= int(part) <= 255):
                raise ValueError(f"IP '{value}' is not a valid IPv4 address.")
        return value

class HashEnrichment(BaseModel):
    """Hash enrichment result."""

    hash_value: str
    reputation: HashReputation
    malicious_vendors: int = Field(default=0, description="Number of malicious detections")
    suspicious_vendors: int = Field(default=0, description="Number of suspicious detections")
    harmless_vendors: int = Field(default=0, description="Number of harmless detections")
    undetected_vendors: int = Field(default=0, description="Number of undetected vendor results")
    total_vendors: int = Field(default=0, description="Total number of vendors")
    threat_name: Optional[str] = Field(default=None, description="Threat family name if known")
    meaningful_name: Optional[str] = Field(default=None, description="Human-friendly file name if known")
    community_reputation: Optional[int] = Field(default=None, description="VirusTotal community reputation score")
    tags: List[str] = Field(default_factory=list, description="Tags returned by the intel source")
    analysis_stats: dict[str, int] = Field(default_factory=dict, description="Raw last_analysis_stats values")
    last_analysis_date: Optional[datetime] = Field(default=None, description="Time of the latest analysis event")
    permalink: Optional[str] = Field(default=None, description="Direct URL to the intel provider object")
    source: str = Field(default="mock_vt", description="Enrichment source")


class IPEnrichment(BaseModel):
    """IP enrichment result."""

    ip_address: str
    reputation: IPReputation
    confidence_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Confidence score from 0 to 100",
    )
    is_c2: bool = Field(default=False, description="Whether the IP is a C2 server")
    country: Optional[str] = Field(default=None, description="Country for the IP")
    isp: Optional[str] = Field(default=None, description="ISP for the IP")
    asn: Optional[int] = Field(default=None, description="Autonomous system number")
    network: Optional[str] = Field(default=None, description="Network CIDR or range if known")
    malicious_vendors: int = Field(default=0, description="Number of malicious detections")
    suspicious_vendors: int = Field(default=0, description="Number of suspicious detections")
    harmless_vendors: int = Field(default=0, description="Number of harmless detections")
    undetected_vendors: int = Field(default=0, description="Number of undetected vendor results")
    tags: List[str] = Field(default_factory=list, description="Tags returned by the intel source")
    analysis_stats: dict[str, int] = Field(default_factory=dict, description="Raw last_analysis_stats values")
    community_reputation: Optional[int] = Field(default=None, description="VirusTotal community reputation score")
    last_analysis_date: Optional[datetime] = Field(default=None, description="Time of the latest analysis event")
    permalink: Optional[str] = Field(default=None, description="Direct URL to the intel provider object")
    source: str = Field(default="mock_abuseipdb", description="Enrichment source")


class MITREMapping(BaseModel):
    """MITRE ATT&CK mapping result."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID", examples=["T1059.001", "T1055"])
    technique_name: str = Field(..., description="Technique name", examples=["PowerShell", "Process Injection"])
    tactic: str = Field(..., description="MITRE tactic", examples=["Execution", "Defense Evasion"])
    matched_pattern: str = Field(..., description="Alert pattern matched by the rule")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence from 0.0 to 1.0")


class EnrichedAlert(BaseModel):
    """Alert after the enrichment and scoring pipeline."""

    original_alert: MalwareAlert
    hash_enrichment: Optional[HashEnrichment] = None
    ip_enrichment: Optional[IPEnrichment] = None
    asset_criticality: AssetCriticality = AssetCriticality.NORMAL
    asset_info: dict[str, Any] = Field(default_factory=dict, description="CMDB metadata for the asset if available")
    mitre_mappings: List[MITREMapping] = Field(
        default_factory=list,
        description="Mapped MITRE ATT&CK techniques",
    )
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Aggregate risk score")
    risk_level: str = Field(default="unknown", description="Risk level: low | medium | high | critical")
    risk_breakdown: dict[str, Any] = Field(default_factory=dict, description="Detailed scoring breakdown")
    enriched_at: datetime = Field(default_factory=utc_now)


class ActionResult(BaseModel):
    """Result of executing or dispatching a single action."""

    action: ResponseAction
    status: ActionExecutionStatus = Field(
        default=ActionExecutionStatus.SUCCEEDED,
        description="'queued' | 'waiting_approval' | 'running' | 'succeeded' | 'failed' | 'skipped'",
    )
    executed_at: datetime = Field(default_factory=utc_now)
    details: str = Field(default="", description="Execution details")
    correlation_id: Optional[str] = Field(default=None, description="Correlation ID for queued actions")
    attempt_count: int = Field(default=0, ge=0, description="Number of worker attempts recorded for this action")
    updated_at: datetime = Field(default_factory=utc_now, description="Last time the action state changed")
    requires_approval: bool = Field(default=False, description="Whether analyst approval is required before execution")
    approval_state: ActionApprovalState = Field(default=ActionApprovalState.NOT_REQUIRED)
    approval_reason: Optional[str] = Field(default=None, description="Why this action requires analyst approval")
    approval_comment: Optional[str] = Field(default=None, description="Latest analyst approval or rollback comment")
    approved_by: Optional[str] = Field(default=None, description="Approver or rejecting analyst")
    approved_at: Optional[datetime] = Field(default=None, description="Last approval decision timestamp")
    approval_due_at: Optional[datetime] = Field(default=None, description="When analyst approval is due")
    approval_escalates_at: Optional[datetime] = Field(default=None, description="When the pending approval should escalate")
    escalation_targets: List[str] = Field(default_factory=list, description="Escalation recipients for overdue approvals")
    approval_escalated_at: Optional[datetime] = Field(default=None, description="When the approval was escalated")
    rollback_requested_by: Optional[str] = Field(default=None, description="Operator that rolled back a queued action")
    rollback_requested_at: Optional[datetime] = Field(default=None, description="When the queued action was rolled back")
    operator: Optional[str] = Field(default=None, description="Worker or analyst that last handled the action")
    policy_version: Optional[int] = Field(default=None, description="Policy version that decided this action")

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, value: Any) -> str:
        if isinstance(value, ActionExecutionStatus):
            return value.value
        if isinstance(value, Enum):
            return str(value.value).strip().lower()
        candidate = str(value or ActionExecutionStatus.SUCCEEDED.value).strip().lower()
        if candidate == "success":
            return ActionExecutionStatus.SUCCEEDED.value
        if candidate in {"pending_approval", "blocked_on_approval"}:
            return ActionExecutionStatus.WAITING_APPROVAL.value
        return candidate

    @field_validator("approval_state", mode="before")
    @classmethod
    def normalize_approval_state(cls, value: Any) -> str:
        if isinstance(value, ActionApprovalState):
            return value.value
        if isinstance(value, Enum):
            return str(value.value).strip().lower()
        candidate = str(value or ActionApprovalState.NOT_REQUIRED.value).strip().lower()
        if candidate in {"none", "", "n/a"}:
            return ActionApprovalState.NOT_REQUIRED.value
        return candidate


class CorrelationHook(BaseModel):
    """Explicit correlation metadata emitted for queued actions."""

    field: str
    value: str


class QueuedActionRequest(BaseModel):
    """Queue-ready envelope for deferred remediation execution."""

    action: ResponseAction
    queue_name: str
    correlation_id: str
    deduplication_key: str
    correlation_hooks: List[CorrelationHook] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = Field(default=False)
    approval_state: ActionApprovalState = Field(default=ActionApprovalState.NOT_REQUIRED)
    approval_reason: Optional[str] = Field(default=None)
    approval_comment: Optional[str] = Field(default=None)
    approved_by: Optional[str] = Field(default=None)
    approved_at: Optional[datetime] = Field(default=None)
    approval_due_at: Optional[datetime] = Field(default=None)
    approval_escalates_at: Optional[datetime] = Field(default=None)
    escalation_targets: List[str] = Field(default_factory=list)
    approval_escalated_at: Optional[datetime] = Field(default=None)
    rollback_requested_by: Optional[str] = Field(default=None)
    rollback_requested_at: Optional[datetime] = Field(default=None)
    requested_at: datetime = Field(default_factory=utc_now)


class IncidentNote(BaseModel):
    """Analyst-authored note attached to an incident case."""

    note_id: str = Field(default_factory=lambda: f"note-{uuid4().hex}")
    author: str
    body: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class IncidentAuditEvent(BaseModel):
    """Structured audit trail emitted by workflow, queue, and analyst actions."""

    event_id: str = Field(default_factory=lambda: f"audit-{uuid4().hex}")
    category: str
    actor: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: Optional[str] = Field(default=None)
    event_hash: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now)


class CorrelationEvidence(BaseModel):
    """Correlation fingerprint evidence that linked an alert to an incident."""

    strategy: str
    fields: List[str] = Field(default_factory=list)
    fingerprint: str
    values: dict[str, str] = Field(default_factory=dict)
    matched_alert_ids: List[str] = Field(default_factory=list)


class IncidentCorrelationTrace(BaseModel):
    """Correlation decision attached to the latest alert processed for an incident."""

    enabled: bool = Field(default=False)
    window: Optional[str] = Field(default=None)
    outcome: CorrelationOutcome = Field(default=CorrelationOutcome.NEW_INCIDENT)
    incident_key: Optional[str] = Field(default=None)
    matched_incident_id: Optional[int] = Field(default=None)
    matched_alert_ids: List[str] = Field(default_factory=list)
    related_alert_ids: List[str] = Field(default_factory=list)
    related_alert_count: int = Field(default=1, ge=0)
    evidence: List[CorrelationEvidence] = Field(default_factory=list)
    candidate_fingerprints: List[CorrelationEvidence] = Field(default_factory=list)


class PolicyMetadataSnapshot(BaseModel):
    """Immutable policy metadata attached to incident decisions."""

    version: int
    status: PolicyStatus
    owner: str
    change_reason: str
    created_at: datetime


class PolicyExecutionTrace(BaseModel):
    """Execution metadata used for queue-ready dispatch boundaries."""

    configured_mode: str = Field(default="sync")
    effective_mode: str = Field(default="sync")
    queue_name: Optional[str] = Field(default=None)
    fallback_reason: Optional[str] = Field(default=None)
    queued_actions: List[QueuedActionRequest] = Field(default_factory=list)
    policy_version: Optional[int] = Field(default=None)
    policy_status: Optional[PolicyStatus] = Field(default=None)
    canary_enabled: bool = Field(default=False)
    canary_targeted: Optional[bool] = Field(default=None)
    canary_reason: Optional[str] = Field(default=None)
    canary_percentage: Optional[int] = Field(default=None)
    canary_bucket: Optional[int] = Field(default=None)


class IncidentResponse(BaseModel):
    """Final workflow response."""

    enriched_alert: EnrichedAlert
    triggered_actions: List[ResponseAction] = Field(
        default_factory=list,
        description="Actions requested by the policy engine",
    )
    policy_reasoning: List[str] = Field(
        default_factory=list,
        description="Per-rule reasoning from the policy engine",
    )
    action_results: List[ActionResult] = Field(
        default_factory=list,
        description="Execution or dispatch results for each action",
    )
    ticket_id: Optional[str] = Field(
        default=None,
        description="Ticket ID created by the mock ticketing system",
    )
    completed_at: datetime = Field(default_factory=utc_now)
    report_path: Optional[str] = Field(
        default=None,
        description="Path to the generated incident report",
    )
    policy_version: Optional[int] = Field(
        default=None,
        description="Policy version that produced this incident response",
    )
    policy_metadata: Optional[PolicyMetadataSnapshot] = Field(default=None)
    correlation_trace: IncidentCorrelationTrace = Field(default_factory=IncidentCorrelationTrace)
    execution_trace: PolicyExecutionTrace = Field(default_factory=PolicyExecutionTrace)

    @property
    def alert_id(self) -> str:
        return self.enriched_alert.original_alert.alert_id

    @property
    def hostname(self) -> str:
        return self.enriched_alert.original_alert.hostname
