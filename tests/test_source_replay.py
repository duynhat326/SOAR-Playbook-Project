from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from integrations.source_replay import run_source_fixture_suite
from integrations.sources import (
    MicrosoftDefenderSourceConnector,
    WazuhSourceConnector,
    build_source_connector_from_env,
)
from services.workflow_service import SoarWorkflowService


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_build_source_connector_from_env_supports_replay_providers(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SOAR_SOURCE_PROVIDER", "wazuh")
    assert isinstance(build_source_connector_from_env(), WazuhSourceConnector)

    monkeypatch.setenv("SOAR_SOURCE_PROVIDER", "defender")
    assert isinstance(build_source_connector_from_env(), MicrosoftDefenderSourceConnector)


def test_wazuh_source_connector_normalizes_sanitized_payload():
    repo_root = Path(__file__).resolve().parent.parent
    payload = _load_json(repo_root / "data" / "replay_sources" / "wazuh" / "alert_01_encoded_powershell.json")
    connector = WazuhSourceConnector()

    alert = connector.normalize_alert(payload)

    assert alert.alert_id == "wazuh-evt-001"
    assert alert.hostname == "DESKTOP-ABC123"
    assert alert.username == "jane.smith"
    assert alert.process_name == "powershell.exe"
    assert alert.parent_process == "explorer.exe"
    assert alert.destination_ip == "203.0.113.5"
    assert alert.severity.value == "high"
    assert "Suspicious PowerShell" in alert.detection_name


def test_microsoft_defender_source_connector_normalizes_sanitized_payload():
    repo_root = Path(__file__).resolve().parent.parent
    payload = _load_json(
        repo_root / "data" / "replay_sources" / "microsoft_defender" / "alert_01_critical_c2.json"
    )
    connector = MicrosoftDefenderSourceConnector()

    alert = connector.normalize_alert(payload)

    assert alert.alert_id == "defender-alert-001"
    assert alert.hostname == "WS-FINANCE-01"
    assert alert.username == "cfo"
    assert alert.process_name == "mimikatz.exe"
    assert alert.parent_process == "explorer.exe"
    assert alert.destination_ip == "185.220.101.45"
    assert alert.severity.value == "high"
    assert "Microsoft Defender" in alert.detection_name


def test_workflow_service_can_process_source_payload(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    payload = _load_json(repo_root / "data" / "replay_sources" / "wazuh" / "alert_01_encoded_powershell.json")
    service = SoarWorkflowService(
        verbose=False,
        db_path=tmp_path / "soar.db",
    )

    result = service.process_source_payload(
        payload,
        source_connector=WazuhSourceConnector(),
        generate_report=False,
        export_pdf=False,
    )

    assert result.alert.alert_id == "wazuh-evt-001"
    assert result.response.ticket_id is not None
    assert result.response.correlation_trace.outcome.value == "new_incident"


def test_source_replay_sample_suite_passes():
    repo_root = Path(__file__).resolve().parent.parent
    fixture_path = repo_root / "data" / "replay_sources" / "source_replay_suite.yaml"
    policy_path = repo_root / "policies" / "response_rules.yaml"

    results = run_source_fixture_suite(fixture_path, policy_config_path=policy_path)

    assert results
    assert all(result.passed for result in results)


def test_source_replay_reports_expectation_failures(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    payload_path = repo_root / "data" / "replay_sources" / "wazuh" / "alert_01_encoded_powershell.json"
    fixture_path = tmp_path / "fixture.yaml"
    fixture_data = {
        "fixtures": [
            {
                "fixture_id": "bad-source-expectation",
                "provider": "wazuh",
                "payload_path": str(payload_path),
                "expect_alert": {
                    "hostname": "WS-BAD-EXPECTATION-01",
                },
                "expect_workflow": {
                    "triggered_actions": ["create_ticket"],
                    "correlation_outcome": "attached_to_existing",
                },
            }
        ]
    }
    fixture_path.write_text(yaml.safe_dump(fixture_data, sort_keys=False), encoding="utf-8")

    results = run_source_fixture_suite(
        fixture_path,
        policy_config_path=repo_root / "policies" / "response_rules.yaml",
    )

    assert len(results) == 1
    assert results[0].passed is False
    assert any("hostname mismatch" in failure for failure in results[0].failures)
    assert any("triggered_actions mismatch" in failure for failure in results[0].failures)
    assert any("correlation_outcome mismatch" in failure for failure in results[0].failures)


def test_replay_source_fixtures_entrypoint_help():
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "scripts/replay_source_fixtures.py", "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Replay sanitized source payload fixtures" in result.stdout
