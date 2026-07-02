"""
schemas/alert.py
================
Pydantic schemas shared across the SOAR workflow.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class ResponseAction(str, Enum):
    """Response actions the policy engine can request."""

    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    ESCALATE = "escalate"
    CREATE_TICKET = "create_ticket"
    NOTIFY_SOC = "notify_soc"
    NO_ACTION = "no_action"


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
        default_factory=datetime.utcnow,
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
    total_vendors: int = Field(default=0, description="Total number of vendors")
    threat_name: Optional[str] = Field(default=None, description="Threat family name if known")
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
    mitre_mappings: List[MITREMapping] = Field(
        default_factory=list,
        description="Mapped MITRE ATT&CK techniques",
    )
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Aggregate risk score")
    risk_level: str = Field(default="unknown", description="Risk level: low | medium | high | critical")
    enriched_at: datetime = Field(default_factory=datetime.utcnow)


class ActionResult(BaseModel):
    """Result of executing or dispatching a single action."""

    action: ResponseAction
    status: str = Field(..., description="'success' | 'failed' | 'skipped' | 'queued'")
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    details: str = Field(default="", description="Execution details")


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


class PolicyExecutionTrace(BaseModel):
    """Execution metadata used for queue-ready dispatch boundaries."""

    configured_mode: str = Field(default="sync")
    effective_mode: str = Field(default="sync")
    queue_name: Optional[str] = Field(default=None)
    fallback_reason: Optional[str] = Field(default=None)
    queued_actions: List[QueuedActionRequest] = Field(default_factory=list)


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
    completed_at: datetime = Field(default_factory=datetime.utcnow)
    report_path: Optional[str] = Field(
        default=None,
        description="Path to the generated incident report",
    )
    execution_trace: PolicyExecutionTrace = Field(default_factory=PolicyExecutionTrace)

    @property
    def alert_id(self) -> str:
        return self.enriched_alert.original_alert.alert_id

    @property
    def hostname(self) -> str:
        return self.enriched_alert.original_alert.hostname
