from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

from engine.policy_replay import run_policy_fixture_suite


def test_policy_replay_sample_suite_passes():
    repo_root = Path(__file__).resolve().parent.parent
    fixture_path = repo_root / "policies" / "fixtures" / "rule_regression.yaml"
    policy_path = repo_root / "policies" / "response_rules.yaml"

    results = run_policy_fixture_suite(fixture_path, policy_config_path=policy_path)

    assert results
    assert all(result.passed for result in results)


def test_policy_replay_reports_expectation_failures(tmp_path):
    fixture_path = tmp_path / "fixture.yaml"
    fixture_data = {
        "fixtures": [
            {
                "fixture_id": "bad-expectation",
                "alert": {
                    "alert_id": "replay-bad-001",
                    "hostname": "DESKTOP-ABC123",
                    "username": "test.user",
                    "process_name": "powershell.exe",
                    "file_path": "C:\\Temp\\payload.exe",
                    "file_hash": "0" * 64,
                    "parent_process": "explorer.exe",
                    "command_line": "powershell.exe -enc U29ja2V0",
                    "destination_ip": "198.51.100.10",
                    "severity": "high",
                    "detection_name": "Replay.BadExpectation",
                },
                "enrichment_overrides": {
                    "hash_enrichment": {
                        "hash_value": "0" * 64,
                        "reputation": "malicious",
                        "malicious_vendors": 58,
                        "total_vendors": 72,
                        "threat_name": "Trojan.GenericKD.48756123",
                        "source": "replay_fixture",
                    },
                    "risk_score": 72.0,
                    "risk_level": "high",
                },
                "expect": {
                    "triggered_actions": ["create_ticket", "notify_soc"],
                    "effective_mode": "queued",
                },
            }
        ]
    }
    fixture_path.write_text(yaml.safe_dump(fixture_data, sort_keys=False), encoding="utf-8")

    results = run_policy_fixture_suite(
        fixture_path,
        policy_config_path=Path(__file__).resolve().parent.parent / "policies" / "response_rules.yaml",
    )

    assert len(results) == 1
    assert results[0].passed is False
    assert any("triggered_actions mismatch" in failure for failure in results[0].failures)
    assert any("effective_mode mismatch" in failure for failure in results[0].failures)


def test_replay_policy_fixtures_entrypoint_help():
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "scripts/replay_policy_fixtures.py", "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Replay sanitized policy fixtures" in result.stdout
