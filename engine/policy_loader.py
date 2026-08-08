from __future__ import annotations

from datetime import datetime
import os
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml
from loguru import logger
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from schemas.alert import AssetCriticality, PolicyStatus, ResponseAction, Severity
from time_utils import utc_now

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "response_rules.yaml"

DEFAULT_POLICY_CONFIG: dict[str, Any] = {
    "version": 1,
    "metadata": {
        "version": 1,
        "status": "active",
        "owner": "soc.platform",
        "change_reason": "Initial production hardening baseline",
        "created_at": "2026-08-08T00:00:00Z",
    },
    "correlation": {
        "enabled": True,
        "window": "1h",
        "reopen_closed_incidents": True,
        "strategies": [
            {
                "name": "host_user_hash",
                "fields": ["hostname", "username", "file_hash"],
            },
            {
                "name": "host_user_process",
                "fields": ["hostname", "username", "process_name"],
            },
            {
                "name": "host_destination_ip",
                "fields": ["hostname", "destination_ip"],
            },
            {
                "name": "user_file_hash",
                "fields": ["username", "file_hash"],
            },
        ],
    },
    "execution": {
        "mode": "sync",
        "approval": {
            "default_sla_minutes": 30,
            "default_escalation_minutes": 60,
            "default_escalation_targets": [],
            "rules": [],
        },
        "canary": {
            "enabled": False,
            "hostname_patterns": [],
            "asset_tags": [],
            "environments": [],
            "workspaces": [],
            "percentage": 100,
        },
        "queue": {
            "queue_name": "policy-actions",
            "correlation_prefix": "policy",
            "fallback_to_sync": True,
            "correlation_fields": [
                "hostname",
                "username",
                "file_hash",
                "destination_ip",
            ],
        },
    },
    "rules": [
        {
            "rule_id": "rule_1_hash_malicious",
            "label": "Rule 1",
            "enabled": True,
            "condition_label": "Hash MALICIOUS?",
            "condition_type": "hash_reputation_equals",
            "action": "isolate_host",
            "thresholds": {"min_risk_score": 0.0, "min_severity": "low"},
            "matches": {"value": "malicious"},
            "messages": {
                "skipped": "Rule 1 [SKIP]: Hash enrichment không có dữ liệu.",
                "passed": "Rule 1 [PASS]: Hash reputation = {hash_reputation} → no action",
                "triggered": "Rule 1 [TRIGGERED]: Hash MALICIOUS ({hash_vendor_ratio} vendors) → Threat: '{hash_threat}' → ACTION: ISOLATE_HOST",
                "disabled": "Rule 1 [DISABLED]: Hash malicious auto-isolation đang tắt.",
            },
        },
        {
            "rule_id": "rule_2_dangerous_process",
            "label": "Rule 2",
            "enabled": True,
            "condition_label": "Dangerous process blacklist?",
            "condition_type": "dangerous_process_blacklist",
            "action": "kill_process",
            "guards": {"username_allowlist": []},
            "messages": {
                "passed": "Rule 2 [PASS]: Process '{process_name}' không trong blacklist → no action",
                "triggered": "Rule 2 [TRIGGERED]: Process '{process_name}' nằm trong dangerous process blacklist (MITRE ATT&CK mapped) → ACTION: KILL_PROCESS",
                "disabled": "Rule 2 [DISABLED]: Dangerous process auto-kill đang tắt.",
            },
        },
        {
            "rule_id": "rule_3_critical_asset",
            "label": "Rule 3",
            "enabled": True,
            "condition_label": "Asset CRITICAL?",
            "condition_type": "asset_criticality_equals",
            "action": "escalate",
            "thresholds": {"min_risk_score": 0.0, "min_severity": "low"},
            "matches": {"value": "critical"},
            "messages": {
                "passed": "Rule 3 [PASS]: Asset criticality = {asset_criticality} (not critical) → no action",
                "triggered": "Rule 3 [TRIGGERED]: Host '{hostname}' có criticality = CRITICAL (high-value asset) → ACTION: ESCALATE",
                "disabled": "Rule 3 [DISABLED]: Critical asset auto-escalation đang tắt.",
            },
        },
        {
            "rule_id": "rule_4_c2_ip",
            "label": "Rule 4",
            "enabled": True,
            "condition_label": "IP is C2?",
            "condition_type": "ip_is_c2",
            "action": "block_ip",
            "thresholds": {"min_risk_score": 0.0, "min_severity": "low"},
            "matches": {"value": True},
            "messages": {
                "skipped": "Rule 4 [SKIP]: IP enrichment không có dữ liệu.",
                "passed": "Rule 4 [PASS]: IP '{destination_ip}' reputation = {ip_reputation} → no action",
                "partial": "Rule 4 [PARTIAL]: IP '{destination_ip}' là MALICIOUS nhưng chưa xác nhận C2 (confidence={ip_confidence}) → no auto-block, SOC review needed",
                "triggered": "Rule 4 [TRIGGERED]: IP '{destination_ip}' được gắn cờ C2 (confidence={ip_confidence}/100) → ACTION: BLOCK_IP",
                "disabled": "Rule 4 [DISABLED]: C2 auto-block đang tắt.",
            },
        },
    ],
}


class PolicyConditionType(str, Enum):
    HASH_REPUTATION_EQUALS = "hash_reputation_equals"
    DANGEROUS_PROCESS_BLACKLIST = "dangerous_process_blacklist"
    ASSET_CRITICALITY_EQUALS = "asset_criticality_equals"
    IP_IS_C2 = "ip_is_c2"


class PolicyExecutionMode(str, Enum):
    SYNC = "sync"
    QUEUED = "queued"
    DRY_RUN = "dry_run"


class PolicyCorrelationField(str, Enum):
    HOSTNAME = "hostname"
    USERNAME = "username"
    FILE_HASH = "file_hash"
    DESTINATION_IP = "destination_ip"


class PolicyFingerprintField(str, Enum):
    HOSTNAME = "hostname"
    USERNAME = "username"
    FILE_HASH = "file_hash"
    PROCESS_NAME = "process_name"
    DESTINATION_IP = "destination_ip"


class PolicyQueueConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    queue_name: str = "policy-actions"
    correlation_prefix: str = "policy"
    fallback_to_sync: bool = True
    correlation_fields: list[PolicyCorrelationField] = Field(
        default_factory=lambda: [
            PolicyCorrelationField.HOSTNAME,
            PolicyCorrelationField.USERNAME,
            PolicyCorrelationField.FILE_HASH,
            PolicyCorrelationField.DESTINATION_IP,
        ]
    )

    @field_validator("queue_name", "correlation_prefix")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Queue settings must not be empty")
        return normalized

    @field_validator("correlation_fields")
    @classmethod
    def validate_correlation_fields(
        cls,
        values: list[PolicyCorrelationField],
    ) -> list[PolicyCorrelationField]:
        if not values:
            raise ValueError("Queue correlation_fields must include at least one field")

        seen: set[PolicyCorrelationField] = set()
        duplicates: set[str] = set()
        for value in values:
            if value in seen:
                duplicates.add(value.value)
            seen.add(value)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate correlation_fields are not allowed: {duplicate_list}")
        return values


class PolicyExecutionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: PolicyExecutionMode = PolicyExecutionMode.SYNC
    approval: "PolicyApprovalConfig" = Field(default_factory=lambda: PolicyApprovalConfig())
    canary: "PolicyCanaryConfig" = Field(default_factory=lambda: PolicyCanaryConfig())
    queue: PolicyQueueConfig = Field(default_factory=PolicyQueueConfig)


class PolicyApprovalRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: ResponseAction
    risk_levels: list[Severity] = Field(default_factory=list)
    asset_criticalities: list[AssetCriticality] = Field(default_factory=list)
    reason: Optional[str] = None
    sla_minutes: Optional[int] = Field(default=None, ge=1, le=10080)
    escalation_minutes: Optional[int] = Field(default=None, ge=1, le=20160)
    escalation_targets: list[str] = Field(default_factory=list)

    @field_validator("risk_levels", "asset_criticalities")
    @classmethod
    def validate_unique_enums(cls, values: list[Any]) -> list[Any]:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for value in values:
            candidate = value.value if isinstance(value, Enum) else str(value)
            if candidate in seen:
                duplicates.add(candidate)
            seen.add(candidate)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate approval rule values are not allowed: {duplicate_list}")
        return values

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Approval rule reason must not be empty")
        return normalized

    @field_validator("escalation_targets")
    @classmethod
    def validate_escalation_targets(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        duplicates: set[str] = set()
        for value in values:
            candidate = value.strip()
            if not candidate:
                raise ValueError("Escalation target values must not be empty")
            lowered = candidate.casefold()
            if lowered in seen:
                duplicates.add(candidate)
            seen.add(lowered)
            normalized.append(candidate)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate escalation target values are not allowed: {duplicate_list}")
        return normalized

    @model_validator(mode="after")
    def validate_escalation_thresholds(self) -> "PolicyApprovalRule":
        if (
            self.sla_minutes is not None
            and self.escalation_minutes is not None
            and self.escalation_minutes < self.sla_minutes
        ):
            raise ValueError("Approval rule escalation_minutes must be greater than or equal to sla_minutes")
        return self


class PolicyApprovalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_sla_minutes: int = Field(default=30, ge=1, le=10080)
    default_escalation_minutes: int = Field(default=60, ge=1, le=20160)
    default_escalation_targets: list[str] = Field(default_factory=list)
    rules: list[PolicyApprovalRule] = Field(default_factory=list)

    @field_validator("default_escalation_targets")
    @classmethod
    def validate_default_escalation_targets(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        duplicates: set[str] = set()
        for value in values:
            candidate = value.strip()
            if not candidate:
                raise ValueError("Default escalation target values must not be empty")
            lowered = candidate.casefold()
            if lowered in seen:
                duplicates.add(candidate)
            seen.add(lowered)
            normalized.append(candidate)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate default escalation target values are not allowed: {duplicate_list}")
        return normalized

    @model_validator(mode="after")
    def validate_default_escalation_minutes(self) -> "PolicyApprovalConfig":
        if self.default_escalation_minutes < self.default_sla_minutes:
            raise ValueError("default_escalation_minutes must be greater than or equal to default_sla_minutes")
        return self


class PolicyCanaryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    hostname_patterns: list[str] = Field(default_factory=list)
    asset_tags: list[str] = Field(default_factory=list)
    environments: list[str] = Field(default_factory=list)
    workspaces: list[str] = Field(default_factory=list)
    percentage: int = Field(default=100, ge=0, le=100)

    @field_validator("hostname_patterns", "asset_tags", "environments", "workspaces")
    @classmethod
    def validate_selector_values(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        duplicates: set[str] = set()
        for value in values:
            candidate = value.strip()
            if not candidate:
                raise ValueError("Canary selector values must not be empty")
            lowered = candidate.casefold()
            if lowered in seen:
                duplicates.add(candidate)
            seen.add(lowered)
            normalized.append(candidate)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate canary selector values are not allowed: {duplicate_list}")
        return normalized


class PolicyThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    min_severity: Severity = Severity.LOW


class PolicyGuards(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username_allowlist: list[str] = Field(default_factory=list)

    @field_validator("username_allowlist")
    @classmethod
    def validate_username_allowlist(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        duplicates: set[str] = set()

        for value in values:
            candidate = value.strip()
            if not candidate:
                raise ValueError("Guard username_allowlist entries must not be empty")
            lowered = candidate.casefold()
            if lowered in seen:
                duplicates.add(candidate)
            seen.add(lowered)
            normalized.append(candidate)

        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate username_allowlist entries are not allowed: {duplicate_list}")
        return normalized


class PolicyMessages(BaseModel):
    model_config = ConfigDict(extra="forbid")

    triggered: str
    passed: Optional[str] = None
    skipped: Optional[str] = None
    partial: Optional[str] = None
    disabled: Optional[str] = None


class PolicyCorrelationStrategy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    fields: list[PolicyFingerprintField]

    @field_validator("name")
    @classmethod
    def validate_strategy_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Correlation strategy name must not be empty")
        return normalized

    @field_validator("fields")
    @classmethod
    def validate_fields(cls, values: list[PolicyFingerprintField]) -> list[PolicyFingerprintField]:
        if not values:
            raise ValueError("Correlation strategy must declare at least one field")
        seen: set[PolicyFingerprintField] = set()
        duplicates: set[str] = set()
        for value in values:
            if value in seen:
                duplicates.add(value.value)
            seen.add(value)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate correlation strategy fields are not allowed: {duplicate_list}")
        return values


class PolicyIncidentCorrelationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    window: str = "1h"
    reopen_closed_incidents: bool = True
    strategies: list[PolicyCorrelationStrategy] = Field(default_factory=list)

    @field_validator("window")
    @classmethod
    def validate_window(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("Correlation window must not be empty")
        if normalized[-1:] not in {"m", "h", "d"} or not normalized[:-1].isdigit():
            raise ValueError("Correlation window must use a positive duration such as '15m', '1h', or '24h'")
        amount = int(normalized[:-1])
        if amount <= 0:
            raise ValueError("Correlation window must be greater than zero")
        return normalized


class PolicyMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1)
    status: PolicyStatus = PolicyStatus.ACTIVE
    owner: str = "soc.platform"
    change_reason: str = "Baseline response policy"
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("owner", "change_reason")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Policy metadata values must not be empty")
        return normalized


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    label: str
    enabled: bool = True
    condition_label: str
    condition_type: PolicyConditionType
    action: ResponseAction
    thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)
    guards: PolicyGuards = Field(default_factory=PolicyGuards)
    matches: dict[str, Any] = Field(default_factory=dict)
    messages: PolicyMessages

    @model_validator(mode="after")
    def validate_matches(self) -> "PolicyRule":
        if self.condition_type in {
            PolicyConditionType.HASH_REPUTATION_EQUALS,
            PolicyConditionType.ASSET_CRITICALITY_EQUALS,
            PolicyConditionType.IP_IS_C2,
        } and "value" not in self.matches:
            raise ValueError(
                f"Rule '{self.rule_id}' requires matches.value for condition_type "
                f"'{self.condition_type.value}'"
            )
        return self


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1)
    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    correlation: PolicyIncidentCorrelationConfig = Field(default_factory=PolicyIncidentCorrelationConfig)
    execution: PolicyExecutionConfig = Field(default_factory=PolicyExecutionConfig)
    rules: list[PolicyRule]

    @model_validator(mode="before")
    @classmethod
    def backfill_metadata(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        version = normalized.get("version", 1)
        metadata = normalized.get("metadata")

        if metadata is None:
            normalized["metadata"] = {"version": version}
            return normalized

        if isinstance(metadata, dict) and "version" not in metadata:
            merged = dict(metadata)
            merged["version"] = version
            normalized["metadata"] = merged
        return normalized

    @model_validator(mode="after")
    def validate_rules(self) -> "PolicyConfig":
        if not self.rules:
            raise ValueError("Policy config must define at least one rule")

        seen: set[str] = set()
        duplicates: set[str] = set()
        for rule in self.rules:
            if rule.rule_id in seen:
                duplicates.add(rule.rule_id)
            seen.add(rule.rule_id)
        if duplicates:
            duplicate_list = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate rule_id values are not allowed: {duplicate_list}")
        if self.metadata.version != self.version:
            raise ValueError("Policy metadata.version must match the top-level version")
        return self


def load_policy_config(path: Optional[Path] = None) -> PolicyConfig:
    config_path = Path(path or DEFAULT_POLICY_PATH)

    try:
        raw_data = _apply_environment_overrides(_read_policy_file(config_path))
        config = PolicyConfig.model_validate(raw_data)
        logger.debug(f"[PolicyConfig] Loaded {len(config.rules)} rule(s) from {config_path}")
        return config
    except (FileNotFoundError, yaml.YAMLError, ValidationError) as exc:
        logger.warning(
            f"[PolicyConfig] Failed to load policy config from {config_path}: {exc}. "
            "Falling back to built-in defaults."
        )
        return PolicyConfig.model_validate(_apply_environment_overrides(DEFAULT_POLICY_CONFIG))


def _read_policy_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValidationError.from_exception_data(
            "PolicyConfig",
            [{"type": "model_type", "loc": (), "msg": "Policy config must be a mapping", "input": data}],
        )
    return data


def _apply_environment_overrides(raw_data: dict[str, Any]) -> dict[str, Any]:
    data = yaml.safe_load(yaml.safe_dump(raw_data, sort_keys=False)) or {}
    execution = data.setdefault("execution", {})
    queue = execution.setdefault("queue", {})

    mode = os.getenv("SOAR_POLICY_EXECUTION_MODE")
    if mode:
        execution["mode"] = mode.strip().lower()

    queue_name = os.getenv("SOAR_POLICY_QUEUE_NAME")
    if queue_name:
        queue["queue_name"] = queue_name.strip()

    correlation_prefix = os.getenv("SOAR_POLICY_CORRELATION_PREFIX")
    if correlation_prefix:
        queue["correlation_prefix"] = correlation_prefix.strip()

    fallback_to_sync = os.getenv("SOAR_POLICY_QUEUE_FALLBACK_TO_SYNC")
    if fallback_to_sync:
        queue["fallback_to_sync"] = fallback_to_sync.strip().lower() in {"1", "true", "yes", "on"}

    return data
