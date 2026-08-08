import yaml

from engine.policy_loader import DEFAULT_POLICY_CONFIG, load_policy_config


def test_policy_loader_falls_back_to_defaults_on_invalid_yaml(tmp_path):
    config_path = tmp_path / "broken.yaml"
    config_path.write_text("rules: [invalid", encoding="utf-8")

    config = load_policy_config(config_path)

    assert len(config.rules) == len(DEFAULT_POLICY_CONFIG["rules"])


def test_policy_loader_reads_custom_yaml(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = {
        "version": 1,
        "rules": [
            {
                "rule_id": "rule_test",
                "label": "Rule X",
                "enabled": True,
                "condition_label": "Hash MALICIOUS?",
                "condition_type": "hash_reputation_equals",
                "action": "isolate_host",
                "matches": {"value": "malicious"},
                "messages": {
                    "skipped": "skip",
                    "passed": "pass",
                    "triggered": "triggered",
                },
            }
        ],
    }
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert len(config.rules) == 1
    assert config.rules[0].rule_id == "rule_test"
    assert config.execution.mode.value == "sync"


def test_policy_loader_reads_execution_config(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = {
        "version": 1,
        "execution": {
            "mode": "queued",
            "queue": {
                "queue_name": "remediation-jobs",
                "correlation_prefix": "incident",
                "fallback_to_sync": False,
                "correlation_fields": ["file_hash", "destination_ip"],
            },
        },
        "rules": DEFAULT_POLICY_CONFIG["rules"],
    }
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert config.execution.mode.value == "queued"
    assert config.execution.queue.queue_name == "remediation-jobs"
    assert config.execution.queue.correlation_prefix == "incident"
    assert config.execution.queue.fallback_to_sync is False
    assert [field.value for field in config.execution.queue.correlation_fields] == [
        "file_hash",
        "destination_ip",
    ]
    assert config.rules[0].thresholds.min_risk_score == 0.0
    assert config.rules[0].thresholds.min_severity.value == "low"
    assert config.rules[1].guards.username_allowlist == []


def test_policy_loader_backfills_metadata_from_legacy_version(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = {
        "version": 7,
        "rules": DEFAULT_POLICY_CONFIG["rules"],
    }
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert config.version == 7
    assert config.metadata.version == 7
    assert config.metadata.status.value == "active"
    assert config.metadata.owner == "soc.platform"


def test_policy_loader_reads_metadata_and_dry_run_mode(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["version"] = 3
    custom["metadata"] = {
        "version": 3,
        "status": "draft",
        "owner": "soc.oncall",
        "change_reason": "Validate new policy branch before activation",
        "created_at": "2026-08-08T10:15:00Z",
    }
    custom["execution"]["mode"] = "dry_run"
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert config.execution.mode.value == "dry_run"
    assert config.metadata.version == 3
    assert config.metadata.status.value == "draft"
    assert config.metadata.owner == "soc.oncall"
    assert config.metadata.change_reason == "Validate new policy branch before activation"


def test_policy_loader_reads_approval_matrix_and_canary_config(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["execution"]["approval"]["rules"] = [
        {
            "action": "isolate_host",
            "risk_levels": ["high", "critical"],
            "asset_criticalities": ["critical"],
            "reason": "Critical asset isolation requires analyst approval",
        }
    ]
    custom["execution"]["canary"] = {
        "enabled": True,
        "hostname_patterns": ["SRV-*"],
        "asset_tags": ["tier0"],
        "environments": ["prod"],
        "workspaces": ["hq"],
        "percentage": 25,
    }
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert len(config.execution.approval.rules) == 1
    assert config.execution.approval.rules[0].action.value == "isolate_host"
    assert [value.value for value in config.execution.approval.rules[0].risk_levels] == ["high", "critical"]
    assert [value.value for value in config.execution.approval.rules[0].asset_criticalities] == ["critical"]
    assert config.execution.approval.rules[0].reason == "Critical asset isolation requires analyst approval"
    assert config.execution.canary.enabled is True
    assert config.execution.canary.hostname_patterns == ["SRV-*"]
    assert config.execution.canary.asset_tags == ["tier0"]
    assert config.execution.canary.environments == ["prod"]
    assert config.execution.canary.workspaces == ["hq"]
    assert config.execution.canary.percentage == 25


def test_policy_loader_reads_approval_sla_defaults_and_escalation_targets(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["execution"]["approval"]["default_sla_minutes"] = 15
    custom["execution"]["approval"]["default_escalation_minutes"] = 45
    custom["execution"]["approval"]["default_escalation_targets"] = ["soc.lead", "irt.manager"]
    custom["execution"]["approval"]["rules"] = [
        {
            "action": "isolate_host",
            "risk_levels": ["critical"],
            "reason": "Critical containment needs approval",
            "sla_minutes": 10,
            "escalation_minutes": 20,
            "escalation_targets": ["secops.oncall"],
        }
    ]
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert config.execution.approval.default_sla_minutes == 15
    assert config.execution.approval.default_escalation_minutes == 45
    assert config.execution.approval.default_escalation_targets == ["soc.lead", "irt.manager"]
    assert config.execution.approval.rules[0].sla_minutes == 10
    assert config.execution.approval.rules[0].escalation_minutes == 20
    assert config.execution.approval.rules[0].escalation_targets == ["secops.oncall"]


def test_policy_loader_falls_back_when_approval_escalation_precedes_sla(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["execution"]["approval"]["default_sla_minutes"] = 30
    custom["execution"]["approval"]["default_escalation_minutes"] = 10
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert config.execution.approval.default_sla_minutes == DEFAULT_POLICY_CONFIG["execution"]["approval"]["default_sla_minutes"]
    assert (
        config.execution.approval.default_escalation_minutes
        == DEFAULT_POLICY_CONFIG["execution"]["approval"]["default_escalation_minutes"]
    )


def test_policy_loader_environment_override_supports_dry_run(tmp_path, monkeypatch):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    monkeypatch.setenv("SOAR_POLICY_EXECUTION_MODE", "dry_run")

    config = load_policy_config(config_path)

    assert config.execution.mode.value == "dry_run"


def test_policy_loader_falls_back_to_defaults_on_invalid_rule_shape(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["rules"][0]["condition_type"] = "not_a_real_condition"
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert len(config.rules) == len(DEFAULT_POLICY_CONFIG["rules"])
    assert config.rules[0].condition_type.value == DEFAULT_POLICY_CONFIG["rules"][0]["condition_type"]


def test_policy_loader_falls_back_to_defaults_on_duplicate_rule_ids(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["rules"][1]["rule_id"] = custom["rules"][0]["rule_id"]
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert len(config.rules) == len(DEFAULT_POLICY_CONFIG["rules"])
    assert [rule.rule_id for rule in config.rules] == [
        rule_data["rule_id"] for rule_data in DEFAULT_POLICY_CONFIG["rules"]
    ]


def test_policy_loader_falls_back_to_defaults_on_duplicate_correlation_fields(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["execution"]["queue"]["correlation_fields"] = ["hostname", "hostname"]
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert [field.value for field in config.execution.queue.correlation_fields] == [
        "hostname",
        "username",
        "file_hash",
        "destination_ip",
    ]


def test_policy_loader_reads_thresholds_and_guards(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["rules"][0]["thresholds"] = {"min_risk_score": 80.0, "min_severity": "high"}
    custom["rules"][1]["guards"] = {"username_allowlist": ["svc.backup", "SYSTEM"]}
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert config.rules[0].thresholds.min_risk_score == 80.0
    assert config.rules[0].thresholds.min_severity.value == "high"
    assert config.rules[1].guards.username_allowlist == ["svc.backup", "SYSTEM"]


def test_policy_loader_falls_back_to_defaults_on_duplicate_username_allowlist(tmp_path):
    config_path = tmp_path / "policy.yaml"
    custom = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    custom["rules"][1]["guards"] = {"username_allowlist": ["SYSTEM", "system"]}
    config_path.write_text(yaml.safe_dump(custom, sort_keys=False), encoding="utf-8")

    config = load_policy_config(config_path)

    assert config.rules[1].guards.username_allowlist == []
