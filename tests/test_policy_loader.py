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
