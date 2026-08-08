from __future__ import annotations

from dataclasses import dataclass
import gc
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from enrichment.asset_db import MockAssetDB
from enrichment.hash_intel import MockHashIntel
from enrichment.ip_intel import MockIPIntel
from enrichment.mitre_mapping import MITREMapper
from enrichment.pipeline import EnrichmentPipeline
from engine.policy_engine import PolicyEngine
from engine.policy_replay import SafeReplayActionConnector, SafeReplayTicketingConnector
from integrations.sources import build_source_connector
from schemas.alert import CorrelationOutcome, MalwareAlert, ResponseAction, Severity
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import SQLiteIncidentRepository


class SourceAlertExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    parent_process: Optional[str] = None
    destination_ip: Optional[str] = None
    severity: Optional[Severity] = None
    command_line_contains: list[str] = Field(default_factory=list)
    detection_name_contains: list[str] = Field(default_factory=list)


class SourceWorkflowExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    triggered_actions: Optional[list[ResponseAction]] = None
    ticket_expected: Optional[bool] = None
    correlation_outcome: Optional[CorrelationOutcome] = None
    related_alert_count: Optional[int] = Field(default=None, ge=1)
    policy_reasoning_contains: list[str] = Field(default_factory=list)


class SourceReplayFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str
    provider: str
    payload_path: str
    description: Optional[str] = None
    expect_alert: SourceAlertExpectation = Field(default_factory=SourceAlertExpectation)
    expect_workflow: SourceWorkflowExpectation = Field(default_factory=SourceWorkflowExpectation)


class SourceReplaySuite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suite_name: str = "source-replay"
    fixtures: list[SourceReplayFixture]


@dataclass(frozen=True)
class SourceReplayResult:
    fixture_id: str
    passed: bool
    failures: list[str]
    normalized_alert: MalwareAlert
    response: Any


def load_source_fixture_suite(path: str | Path) -> SourceReplaySuite:
    fixture_path = Path(path)
    raw_data = yaml.safe_load(fixture_path.read_text(encoding="utf-8")) or {}
    if isinstance(raw_data, list):
        raw_data = {"fixtures": raw_data}
    return SourceReplaySuite.model_validate(raw_data)


def run_source_fixture_suite(
    fixture_path: str | Path,
    *,
    policy_config_path: str | Path | None = None,
    fail_fast: bool = False,
) -> list[SourceReplayResult]:
    suite_path = Path(fixture_path)
    suite = load_source_fixture_suite(suite_path)
    results: list[SourceReplayResult] = []
    with TemporaryDirectory(prefix="soar-source-replay-") as replay_dir:
        service = _build_replay_service(
            db_path=Path(replay_dir) / "source-replay.db",
            policy_config_path=policy_config_path,
        )
        for fixture in suite.fixtures:
            result = replay_source_fixture(
                fixture,
                payload_base_path=suite_path.parent,
                service=service,
            )
            results.append(result)
            if fail_fast and not result.passed:
                break
        service = None
        gc.collect()
    return results


def replay_source_fixture(
    fixture: SourceReplayFixture,
    *,
    payload_base_path: str | Path,
    service: SoarWorkflowService,
) -> SourceReplayResult:
    payload = _load_payload(Path(payload_base_path), fixture.payload_path)
    connector = build_source_connector(provider=fixture.provider)
    workflow_result = service.process_source_payload(
        payload,
        source_connector=connector,
        generate_report=False,
        export_pdf=False,
    )
    normalized_alert = workflow_result.alert
    response = workflow_result.response
    failures = _validate_alert_expectations(fixture.expect_alert, normalized_alert)
    failures.extend(_validate_workflow_expectations(fixture.expect_workflow, response))
    return SourceReplayResult(
        fixture_id=fixture.fixture_id,
        passed=not failures,
        failures=failures,
        normalized_alert=normalized_alert,
        response=response,
    )


def _build_replay_service(
    *,
    db_path: Path,
    policy_config_path: str | Path | None,
) -> SoarWorkflowService:
    repository = SQLiteIncidentRepository(db_path=db_path)
    policy_engine = PolicyEngine(
        verbose=False,
        policy_config_path=Path(policy_config_path) if policy_config_path is not None else None,
        action_connector=SafeReplayActionConnector(),
        ticketing_connector=SafeReplayTicketingConnector(),
    )
    pipeline = EnrichmentPipeline(
        hash_intel=MockHashIntel(),
        ip_intel=MockIPIntel(),
        asset_db=MockAssetDB(),
        mitre_mapper=MITREMapper(),
        verbose=False,
    )
    return SoarWorkflowService(
        verbose=False,
        repository=repository,
        pipeline=pipeline,
        policy_engine=policy_engine,
    )


def _load_payload(base_path: Path, payload_path: str) -> dict[str, Any]:
    resolved = _resolve_payload_path(base_path, payload_path)
    if resolved.suffix.lower() in {".yaml", ".yml"}:
        return dict(yaml.safe_load(resolved.read_text(encoding="utf-8")) or {})
    return dict(json.loads(resolved.read_text(encoding="utf-8")))


def _resolve_payload_path(base_path: Path, payload_path: str) -> Path:
    candidate = Path(payload_path)
    return candidate if candidate.is_absolute() else (base_path / candidate).resolve()


def _validate_alert_expectations(expect: SourceAlertExpectation, alert: MalwareAlert) -> list[str]:
    failures: list[str] = []
    comparisons = (
        ("alert_id", expect.alert_id, alert.alert_id),
        ("hostname", expect.hostname, alert.hostname),
        ("username", expect.username, alert.username),
        ("process_name", expect.process_name, alert.process_name),
        ("file_path", expect.file_path, alert.file_path),
        ("file_hash", expect.file_hash, alert.file_hash),
        ("parent_process", expect.parent_process, alert.parent_process),
        ("destination_ip", expect.destination_ip, alert.destination_ip),
        ("severity", expect.severity.value if expect.severity is not None else None, alert.severity.value),
    )
    for field_name, expected, actual in comparisons:
        if expected is not None and expected != actual:
            failures.append(f"{field_name} mismatch: expected {expected!r}, got {actual!r}")

    for fragment in expect.command_line_contains:
        if fragment not in alert.command_line:
            failures.append(f"command_line did not contain {fragment!r}")

    for fragment in expect.detection_name_contains:
        if fragment not in alert.detection_name:
            failures.append(f"detection_name did not contain {fragment!r}")

    return failures


def _validate_workflow_expectations(expect: SourceWorkflowExpectation, response: Any) -> list[str]:
    failures: list[str] = []
    if expect.triggered_actions is not None:
        actual_actions = [action.value for action in response.triggered_actions]
        expected_actions = [action.value for action in expect.triggered_actions]
        if actual_actions != expected_actions:
            failures.append(
                f"triggered_actions mismatch: expected {expected_actions}, got {actual_actions}"
            )

    if expect.ticket_expected is not None:
        actual_has_ticket = response.ticket_id is not None
        if actual_has_ticket != expect.ticket_expected:
            failures.append(
                f"ticket expectation mismatch: expected ticket={expect.ticket_expected}, got {actual_has_ticket}"
            )

    if (
        expect.correlation_outcome is not None
        and response.correlation_trace.outcome != expect.correlation_outcome
    ):
        failures.append(
            "correlation_outcome mismatch: "
            f"expected {expect.correlation_outcome.value}, got {response.correlation_trace.outcome.value}"
        )

    if (
        expect.related_alert_count is not None
        and response.correlation_trace.related_alert_count != expect.related_alert_count
    ):
        failures.append(
            "related_alert_count mismatch: "
            f"expected {expect.related_alert_count}, got {response.correlation_trace.related_alert_count}"
        )

    for fragment in expect.policy_reasoning_contains:
        if not any(fragment in entry for entry in response.policy_reasoning):
            failures.append(f"policy reasoning did not contain {fragment!r}")

    return failures
