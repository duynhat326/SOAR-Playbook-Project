from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from enrichment.asset_db import MockAssetDB
from enrichment.hash_intel import MockHashIntel
from enrichment.ip_intel import MockIPIntel
from enrichment.mitre_mapping import MITREMapper
from enrichment.pipeline import EnrichmentPipeline
from engine.policy_engine import PolicyEngine
from engine.policy_loader import load_policy_config
from schemas.alert import (
    ActionExecutionStatus,
    ActionResult,
    AssetCriticality,
    EnrichedAlert,
    HashEnrichment,
    IPEnrichment,
    MITREMapping,
    MalwareAlert,
    ResponseAction,
)
from time_utils import utc_now


class ReplayEnrichmentOverrides(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash_enrichment: Optional[HashEnrichment] = None
    ip_enrichment: Optional[IPEnrichment] = None
    asset_criticality: Optional[AssetCriticality] = None
    asset_info: dict[str, Any] = Field(default_factory=dict)
    mitre_mappings: Optional[list[MITREMapping]] = None
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    risk_level: Optional[str] = None


class ReplayExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    triggered_actions: list[ResponseAction] = Field(default_factory=list)
    action_statuses: dict[ResponseAction, ActionExecutionStatus] = Field(default_factory=dict)
    policy_reasoning_contains: list[str] = Field(default_factory=list)
    effective_mode: Optional[str] = None
    canary_targeted: Optional[bool] = None
    queued_action_count: Optional[int] = Field(default=None, ge=0)
    ticket_expected: Optional[bool] = None
    policy_version: Optional[int] = Field(default=None, ge=1)


class PolicyReplayFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str
    description: Optional[str] = None
    alert: MalwareAlert
    enrichment_overrides: ReplayEnrichmentOverrides = Field(default_factory=ReplayEnrichmentOverrides)
    expect: ReplayExpectation


class PolicyReplaySuite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suite_name: str = "policy-replay"
    fixtures: list[PolicyReplayFixture]


@dataclass(frozen=True)
class PolicyReplayResult:
    fixture_id: str
    passed: bool
    failures: list[str]
    response: Any


class ReplayQueuePublisher:
    def __init__(self) -> None:
        self.requests = []

    def publish(self, request) -> None:
        self.requests.append(request)


class SafeReplayActionConnector:
    def isolate_host(self, **kwargs) -> ActionResult:
        return ActionResult(
            action=ResponseAction.ISOLATE_HOST,
            status="succeeded",
            executed_at=utc_now(),
            details=f"Replay simulated host isolation for '{kwargs.get('hostname')}'.",
            operator="POLICY_REPLAY",
        )

    def kill_process(self, **kwargs) -> ActionResult:
        return ActionResult(
            action=ResponseAction.KILL_PROCESS,
            status="succeeded",
            executed_at=utc_now(),
            details=f"Replay simulated process termination for '{kwargs.get('process_name')}'.",
            operator="POLICY_REPLAY",
        )

    def block_ip(self, **kwargs) -> ActionResult:
        return ActionResult(
            action=ResponseAction.BLOCK_IP,
            status="succeeded",
            executed_at=utc_now(),
            details=f"Replay simulated IP block for '{kwargs.get('ip_address')}'.",
            operator="POLICY_REPLAY",
        )

    def escalate(self, **kwargs) -> ActionResult:
        return ActionResult(
            action=ResponseAction.ESCALATE,
            status="succeeded",
            executed_at=utc_now(),
            details=f"Replay simulated escalation for '{kwargs.get('hostname')}'.",
            operator="POLICY_REPLAY",
        )

    def notify_soc(self, **kwargs) -> ActionResult:
        return ActionResult(
            action=ResponseAction.NOTIFY_SOC,
            status="succeeded",
            executed_at=utc_now(),
            details=f"Replay simulated SOC notification for '{kwargs.get('alert_id')}'.",
            operator="POLICY_REPLAY",
        )


class SafeReplayTicketingConnector:
    def create_ticket(self, **kwargs):
        alert = kwargs.get("enriched_alert")
        alert_id = alert.original_alert.alert_id if alert is not None else "unknown"
        ticket_id = f"REPLAY-{alert_id[-6:]}".upper()
        return (
            ActionResult(
                action=ResponseAction.CREATE_TICKET,
                status="succeeded",
                executed_at=utc_now(),
                details=f"Replay simulated ticket creation for '{alert_id}'.",
                operator="POLICY_REPLAY",
            ),
            ticket_id,
        )


def load_policy_fixture_suite(path: str | Path) -> PolicyReplaySuite:
    fixture_path = Path(path)
    raw_data = yaml.safe_load(fixture_path.read_text(encoding="utf-8")) or {}
    if isinstance(raw_data, list):
        raw_data = {"fixtures": raw_data}
    return PolicyReplaySuite.model_validate(raw_data)


def run_policy_fixture_suite(
    fixture_path: str | Path,
    *,
    policy_config_path: str | Path | None = None,
    fail_fast: bool = False,
) -> list[PolicyReplayResult]:
    suite = load_policy_fixture_suite(fixture_path)
    results: list[PolicyReplayResult] = []
    for fixture in suite.fixtures:
        result = replay_policy_fixture(
            fixture,
            policy_config_path=policy_config_path,
        )
        results.append(result)
        if fail_fast and not result.passed:
            break
    return results


def replay_policy_fixture(
    fixture: PolicyReplayFixture,
    *,
    policy_config_path: str | Path | None = None,
) -> PolicyReplayResult:
    enriched = _build_enriched_alert(fixture)
    queue_publisher = ReplayQueuePublisher()
    policy_engine = PolicyEngine(
        verbose=False,
        policy_config_path=Path(policy_config_path) if policy_config_path is not None else None,
        queue_publisher=queue_publisher,
        action_connector=SafeReplayActionConnector(),
        ticketing_connector=SafeReplayTicketingConnector(),
    )
    response = policy_engine.evaluate(enriched)
    failures = _validate_expectations(fixture.expect, response)
    return PolicyReplayResult(
        fixture_id=fixture.fixture_id,
        passed=not failures,
        failures=failures,
        response=response,
    )


def _build_enriched_alert(fixture: PolicyReplayFixture) -> EnrichedAlert:
    pipeline = EnrichmentPipeline(
        hash_intel=MockHashIntel(),
        ip_intel=MockIPIntel(),
        asset_db=MockAssetDB(),
        mitre_mapper=MITREMapper(),
        verbose=False,
    )
    enriched = pipeline.run(fixture.alert)
    return _apply_enrichment_overrides(enriched, fixture.enrichment_overrides)


def _apply_enrichment_overrides(
    enriched: EnrichedAlert,
    overrides: ReplayEnrichmentOverrides,
) -> EnrichedAlert:
    updates: dict[str, Any] = {}
    if overrides.hash_enrichment is not None:
        updates["hash_enrichment"] = overrides.hash_enrichment
    if overrides.ip_enrichment is not None:
        updates["ip_enrichment"] = overrides.ip_enrichment
    if overrides.asset_criticality is not None:
        updates["asset_criticality"] = overrides.asset_criticality
    if overrides.asset_info:
        updates["asset_info"] = {**(enriched.asset_info or {}), **overrides.asset_info}
    if overrides.mitre_mappings is not None:
        updates["mitre_mappings"] = overrides.mitre_mappings
    if overrides.risk_score is not None:
        updates["risk_score"] = overrides.risk_score
    if overrides.risk_level is not None:
        updates["risk_level"] = overrides.risk_level
    return enriched.model_copy(update=updates)


def _validate_expectations(expect: ReplayExpectation, response) -> list[str]:
    failures: list[str] = []
    actual_actions = [action.value for action in response.triggered_actions]
    expected_actions = [action.value for action in expect.triggered_actions]
    if actual_actions != expected_actions:
        failures.append(
            f"triggered_actions mismatch: expected {expected_actions}, got {actual_actions}"
        )

    results_by_action = {result.action.value: result for result in response.action_results}
    for action, status in expect.action_statuses.items():
        result = results_by_action.get(action.value)
        if result is None:
            failures.append(f"missing action result for '{action.value}'")
            continue
        if result.status != status:
            failures.append(
                f"action '{action.value}' status mismatch: expected {status.value}, got {result.status}"
            )

    if expect.effective_mode is not None and response.execution_trace.effective_mode != expect.effective_mode:
        failures.append(
            f"effective_mode mismatch: expected {expect.effective_mode}, "
            f"got {response.execution_trace.effective_mode}"
        )

    if expect.canary_targeted is not None and response.execution_trace.canary_targeted != expect.canary_targeted:
        failures.append(
            f"canary_targeted mismatch: expected {expect.canary_targeted}, "
            f"got {response.execution_trace.canary_targeted}"
        )

    if expect.queued_action_count is not None:
        actual_count = len(response.execution_trace.queued_actions)
        if actual_count != expect.queued_action_count:
            failures.append(
                f"queued_action_count mismatch: expected {expect.queued_action_count}, got {actual_count}"
            )

    if expect.ticket_expected is not None:
        actual_has_ticket = response.ticket_id is not None
        if actual_has_ticket != expect.ticket_expected:
            failures.append(
                f"ticket expectation mismatch: expected ticket={expect.ticket_expected}, got {actual_has_ticket}"
            )

    if expect.policy_version is not None and response.policy_version != expect.policy_version:
        failures.append(
            f"policy_version mismatch: expected {expect.policy_version}, got {response.policy_version}"
        )

    for fragment in expect.policy_reasoning_contains:
        if not any(fragment in entry for entry in response.policy_reasoning):
            failures.append(f"policy reasoning did not contain '{fragment}'")

    return failures

