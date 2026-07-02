"""
tests/test_policy_engine.py
============================
pytest test cases cho Policy Engine — đảm bảo 4 rule hoạt động đúng.

Mỗi test case tương ứng 1 rule từ spec mục 4:
  - test_rule1_hash_malicious_triggers_isolate
  - test_rule2_dangerous_process_triggers_kill
  - test_rule3_critical_asset_triggers_escalate
  - test_rule4_c2_ip_triggers_block
  - test_mixed_scenario_triggers_all_actions
  - test_benign_alert_no_action
  - test_suspicious_hash_no_isolate          (chỉ malicious mới isolate, suspicious thì không)
  - test_malicious_ip_not_c2_no_block        (malicious IP nhưng không phải C2 → không auto-block)

Triết lý:
  - Test policy logic ĐỘC LẬP với EnrichmentPipeline (dùng mock enrichment)
  - Mỗi test tạo EnrichedAlert thủ công để control chính xác điều kiện
  - Không test side effects (ghi file JSON) — chỉ test quyết định
"""

import pytest
from datetime import datetime

import yaml

from engine.policy_engine import PolicyEngine
from engine.policy_loader import DEFAULT_POLICY_CONFIG
from schemas.alert import (
    AssetCriticality,
    EnrichedAlert,
    HashEnrichment,
    HashReputation,
    IPEnrichment,
    IPReputation,
    MalwareAlert,
    MITREMapping,
    ResponseAction,
    Severity,
)


# ──────────────────────────────────────────────────────────────────────
# Fixtures & Helpers
# ──────────────────────────────────────────────────────────────────────

def make_alert(**overrides) -> MalwareAlert:
    """
    Tạo MalwareAlert với giá trị mặc định 'safe', override theo nhu cầu.
    
    Default: clean hash, clean IP, normal host, low severity
    → dùng làm baseline, override để test từng rule riêng lẻ
    """
    defaults = {
        "alert_id"       : "test-alert-uuid-001",
        "hostname"       : "DESKTOP-ABC123",       # Normal asset (not critical)
        "username"       : "test.user",
        "process_name"   : "powershell.exe",       # Not in dangerous process blacklist
        "file_path"      : "C:\\Temp\\test.exe",
        "file_hash"      : "0" * 64,               # Not in hash DB → UNKNOWN
        "parent_process" : "explorer.exe",
        "command_line"   : "powershell.exe -File C:\\scripts\\backup.ps1",
        "destination_ip" : "198.51.100.10",        # Clean IP
        "severity"       : Severity.LOW,
        "detection_name" : "Test.Detection",
    }
    defaults.update(overrides)
    return MalwareAlert(**defaults)


def make_enriched(
    alert: MalwareAlert,
    hash_reputation: HashReputation = HashReputation.CLEAN,
    hash_malicious_vendors: int = 0,
    hash_threat_name: str = None,
    ip_reputation: IPReputation = IPReputation.CLEAN,
    ip_confidence: int = 0,
    ip_is_c2: bool = False,
    asset_criticality: AssetCriticality = AssetCriticality.NORMAL,
    mitre_mappings: list = None,
    risk_score: float = 20.0,
    risk_level: str = "low",
) -> EnrichedAlert:
    """Tạo EnrichedAlert thủ công với các enrichment parameters tùy chỉnh."""
    return EnrichedAlert(
        original_alert=alert,
        hash_enrichment=HashEnrichment(
            hash_value=alert.file_hash,
            reputation=hash_reputation,
            malicious_vendors=hash_malicious_vendors,
            total_vendors=72,
            threat_name=hash_threat_name,
            source="mock_test",
        ),
        ip_enrichment=IPEnrichment(
            ip_address=alert.destination_ip,
            reputation=ip_reputation,
            confidence_score=ip_confidence,
            is_c2=ip_is_c2,
            source="mock_test",
        ),
        asset_criticality=asset_criticality,
        mitre_mappings=mitre_mappings or [],
        risk_score=risk_score,
        risk_level=risk_level,
    )


# Engine chạy silent (verbose=False) để output sạch trong pytest
@pytest.fixture
def engine():
    return PolicyEngine(verbose=False)


# ──────────────────────────────────────────────────────────────────────
# RULE 1: Hash Malicious → Isolate Host
# ──────────────────────────────────────────────────────────────────────

def test_rule1_hash_malicious_triggers_isolate(engine):
    """
    Rule 1: Hash MALICIOUS → phải trigger ISOLATE_HOST.
    Scenario: hash được VT confirm malicious, 58/72 vendors, Trojan.Generic
    """
    alert    = make_alert(severity=Severity.HIGH)
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.MALICIOUS,
        hash_malicious_vendors=58,
        hash_threat_name="Trojan.GenericKD.48756123",
        risk_score=72.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.ISOLATE_HOST in response.triggered_actions, (
        "Rule 1: Hash MALICIOUS phải trigger ISOLATE_HOST"
    )


def test_rule1_hash_suspicious_does_not_isolate(engine):
    """
    Rule 1 boundary: Hash SUSPICIOUS (không phải MALICIOUS) → KHÔNG isolate.
    Chỉ xác nhận malicious 100% mới isolate, suspicious cần analyst review.
    """
    alert    = make_alert()
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.SUSPICIOUS,
        hash_malicious_vendors=8,
        risk_score=35.0,
        risk_level="medium",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.ISOLATE_HOST not in response.triggered_actions, (
        "Rule 1: Hash SUSPICIOUS không được trigger ISOLATE_HOST"
    )


def test_rule1_hash_clean_no_isolate(engine):
    """Rule 1: Hash CLEAN → KHÔNG isolate (happy path)."""
    alert    = make_alert()
    enriched = make_enriched(alert, hash_reputation=HashReputation.CLEAN)

    response = engine.evaluate(enriched)

    assert ResponseAction.ISOLATE_HOST not in response.triggered_actions


# ──────────────────────────────────────────────────────────────────────
# RULE 2: Dangerous Process → Kill Process
# ──────────────────────────────────────────────────────────────────────

def test_rule2_dangerous_process_triggers_kill(engine):
    """
    Rule 2: Process 'mimikatz.exe' nằm trong blacklist → phải trigger KILL_PROCESS.
    mimikatz là credential dumping tool, không bao giờ nên chạy trên production.
    """
    alert    = make_alert(
        process_name="mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        severity=Severity.HIGH,
    )
    enriched = make_enriched(alert, risk_score=65.0, risk_level="high")

    response = engine.evaluate(enriched)

    assert ResponseAction.KILL_PROCESS in response.triggered_actions, (
        "Rule 2: 'mimikatz.exe' phải trigger KILL_PROCESS"
    )


def test_rule2_normal_process_no_kill(engine):
    """Rule 2: Process thông thường (powershell.exe) → KHÔNG kill."""
    alert    = make_alert(process_name="powershell.exe")
    enriched = make_enriched(alert)

    response = engine.evaluate(enriched)

    assert ResponseAction.KILL_PROCESS not in response.triggered_actions, (
        "Rule 2: 'powershell.exe' không phải dangerous process → không KILL"
    )


def test_rule2_other_dangerous_processes(engine):
    """Rule 2: Các dangerous process khác trong blacklist."""
    dangerous_processes = ["nc.exe", "psexec.exe", "wce.exe", "procdump.exe"]

    for proc in dangerous_processes:
        alert    = make_alert(process_name=proc)
        enriched = make_enriched(alert, risk_score=60.0, risk_level="high")
        response = engine.evaluate(enriched)

        assert ResponseAction.KILL_PROCESS in response.triggered_actions, (
            f"Rule 2: '{proc}' phải trigger KILL_PROCESS"
        )


# ──────────────────────────────────────────────────────────────────────
# RULE 3: Asset Critical → Escalate
# ──────────────────────────────────────────────────────────────────────

def test_rule3_critical_asset_triggers_escalate(engine):
    """
    Rule 3: Host có criticality=CRITICAL → phải trigger ESCALATE.
    Domain Controller bị compromise = incident nghiêm trọng nhất.
    """
    alert    = make_alert(hostname="SRV-DC01", severity=Severity.HIGH)
    enriched = make_enriched(
        alert,
        asset_criticality=AssetCriticality.CRITICAL,
        risk_score=60.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.ESCALATE in response.triggered_actions, (
        "Rule 3: Asset CRITICAL phải trigger ESCALATE"
    )


def test_rule3_normal_asset_no_escalate(engine):
    """Rule 3: Asset NORMAL → KHÔNG escalate tự động."""
    alert    = make_alert(hostname="DESKTOP-ABC123")
    enriched = make_enriched(alert, asset_criticality=AssetCriticality.NORMAL)

    response = engine.evaluate(enriched)

    assert ResponseAction.ESCALATE not in response.triggered_actions, (
        "Rule 3: Asset NORMAL không trigger ESCALATE"
    )


def test_rule3_low_asset_no_escalate(engine):
    """Rule 3: Asset LOW → KHÔNG escalate."""
    alert    = make_alert(hostname="DESKTOP-GUEST01")
    enriched = make_enriched(alert, asset_criticality=AssetCriticality.LOW)

    response = engine.evaluate(enriched)

    assert ResponseAction.ESCALATE not in response.triggered_actions


# ──────────────────────────────────────────────────────────────────────
# RULE 4: C2 IP → Block IP
# ──────────────────────────────────────────────────────────────────────

def test_rule4_c2_ip_triggers_block(engine):
    """
    Rule 4: IP được gắn cờ C2 → phải trigger BLOCK_IP.
    Kết nối tới C2 server = active beaconing, cần block ngay.
    """
    alert    = make_alert(
        destination_ip="185.220.101.45",
        severity=Severity.HIGH,
    )
    enriched = make_enriched(
        alert,
        ip_reputation=IPReputation.MALICIOUS,
        ip_confidence=100,
        ip_is_c2=True,
        risk_score=70.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.BLOCK_IP in response.triggered_actions, (
        "Rule 4: IP là C2 server phải trigger BLOCK_IP"
    )


def test_rule4_malicious_ip_not_c2_no_block(engine):
    """
    Rule 4 edge case: IP MALICIOUS nhưng chưa xác nhận C2 → KHÔNG auto-block.
    
    Lý do: auto-block IP malicious không phải C2 có thể block nhầm
    CDN/hosting server chia sẻ với nhiều site khác. Cần analyst review.
    """
    alert    = make_alert(destination_ip="45.142.212.100")
    enriched = make_enriched(
        alert,
        ip_reputation=IPReputation.MALICIOUS,
        ip_confidence=72,
        ip_is_c2=False,   # Malicious nhưng KHÔNG phải C2
        risk_score=45.0,
        risk_level="medium",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.BLOCK_IP not in response.triggered_actions, (
        "Rule 4: IP MALICIOUS nhưng chưa confirm C2 → không auto-block"
    )


def test_rule4_clean_ip_no_block(engine):
    """Rule 4: IP CLEAN → KHÔNG block."""
    alert    = make_alert(destination_ip="198.51.100.10")
    enriched = make_enriched(
        alert,
        ip_reputation=IPReputation.CLEAN,
        ip_is_c2=False,
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.BLOCK_IP not in response.triggered_actions


# ──────────────────────────────────────────────────────────────────────
# MIXED & BENIGN SCENARIOS
# ──────────────────────────────────────────────────────────────────────

def test_mixed_scenario_triggers_all_four_actions(engine):
    """
    Mixed scenario: khi tất cả 4 conditions đều thỏa mãn cùng lúc.
    Tất cả 4 rule phải được trigger: isolate + kill + escalate + block.
    """
    alert = make_alert(
        hostname="SRV-DC01",                    # Critical asset → Rule 3
        process_name="mimikatz.exe",             # Dangerous process → Rule 2
        destination_ip="185.220.101.45",
        severity=Severity.CRITICAL,
    )
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.MALICIOUS,    # Rule 1
        hash_malicious_vendors=65,
        hash_threat_name="Backdoor.Cobalt.Strike",
        ip_reputation=IPReputation.MALICIOUS,
        ip_confidence=100,
        ip_is_c2=True,                               # Rule 4
        asset_criticality=AssetCriticality.CRITICAL, # Rule 3
        risk_score=95.0,
        risk_level="critical",
    )

    response = engine.evaluate(enriched)

    expected = {
        ResponseAction.ISOLATE_HOST,
        ResponseAction.KILL_PROCESS,
        ResponseAction.ESCALATE,
        ResponseAction.BLOCK_IP,
    }
    triggered_set = set(response.triggered_actions)

    assert expected.issubset(triggered_set), (
        f"Mixed: thiếu actions. Expected {expected}, got {triggered_set}"
    )


def test_benign_alert_no_remediation_actions(engine):
    """
    Benign alert: clean hash, clean IP, normal asset, không phải dangerous process.
    Không trigger bất kỳ remediation action nào (chỉ có ticket + notify).
    """
    alert    = make_alert(
        process_name="powershell.exe",
        destination_ip="198.51.100.10",
        severity=Severity.LOW,
    )
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.CLEAN,
        ip_reputation=IPReputation.CLEAN,
        ip_is_c2=False,
        asset_criticality=AssetCriticality.NORMAL,
        risk_score=10.0,
        risk_level="low",
    )

    response = engine.evaluate(enriched)

    remediation_actions = {
        ResponseAction.ISOLATE_HOST,
        ResponseAction.KILL_PROCESS,
        ResponseAction.ESCALATE,
        ResponseAction.BLOCK_IP,
    }
    triggered_remediation = set(response.triggered_actions) & remediation_actions

    assert len(triggered_remediation) == 0, (
        f"Benign alert không được trigger remediation. Got: {triggered_remediation}"
    )


def test_always_creates_ticket(engine):
    """Mọi alert (kể cả benign) đều phải tạo ticket."""
    alert    = make_alert()
    enriched = make_enriched(alert)

    response = engine.evaluate(enriched)

    assert ResponseAction.CREATE_TICKET in response.triggered_actions, (
        "Mọi alert đều phải CREATE_TICKET"
    )
    assert response.ticket_id is not None, (
        "ticket_id phải được set sau khi CREATE_TICKET"
    )


def test_always_notifies_soc(engine):
    """Mọi alert đều phải notify SOC."""
    alert    = make_alert()
    enriched = make_enriched(alert)

    response = engine.evaluate(enriched)

    assert ResponseAction.NOTIFY_SOC in response.triggered_actions, (
        "Mọi alert đều phải NOTIFY_SOC"
    )


def test_policy_reasoning_populated(engine):
    """Policy reasoning phải có ít nhất 4 entries (1 per rule)."""
    alert    = make_alert()
    enriched = make_enriched(alert)

    response = engine.evaluate(enriched)

    assert len(response.policy_reasoning) >= 4, (
        f"Phải có ít nhất 4 reasoning entries, got {len(response.policy_reasoning)}"
    )


def test_policy_config_can_disable_specific_rule(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["rules"][0]["enabled"] = False
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")

    engine = PolicyEngine(verbose=False, policy_config_path=config_path)
    alert = make_alert(severity=Severity.HIGH)
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.MALICIOUS,
        hash_malicious_vendors=58,
        hash_threat_name="Trojan.GenericKD.48756123",
        risk_score=72.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.ISOLATE_HOST not in response.triggered_actions
    assert any("[DISABLED]" in reason for reason in response.policy_reasoning)


def test_policy_config_can_require_min_risk_score_before_triggering_rule(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["rules"][0]["thresholds"]["min_risk_score"] = 80.0
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")

    engine = PolicyEngine(verbose=False, policy_config_path=config_path)
    alert = make_alert(severity=Severity.HIGH)
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.MALICIOUS,
        hash_malicious_vendors=58,
        hash_threat_name="Trojan.GenericKD.48756123",
        risk_score=72.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.ISOLATE_HOST not in response.triggered_actions
    assert any("below minimum 80.0" in reason for reason in response.policy_reasoning)


def test_policy_config_can_require_min_severity_before_triggering_rule(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["rules"][2]["thresholds"]["min_severity"] = "critical"
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")

    engine = PolicyEngine(verbose=False, policy_config_path=config_path)
    alert = make_alert(hostname="SRV-DC01", severity=Severity.HIGH)
    enriched = make_enriched(
        alert,
        asset_criticality=AssetCriticality.CRITICAL,
        risk_score=60.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    assert ResponseAction.ESCALATE not in response.triggered_actions
    assert any("Severity high below minimum critical" in reason for reason in response.policy_reasoning)


def test_policy_config_username_allowlist_suppresses_rule(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["rules"][1]["guards"]["username_allowlist"] = ["svc.backup"]
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")

    engine = PolicyEngine(verbose=False, policy_config_path=config_path)
    alert = make_alert(
        process_name="mimikatz.exe",
        username="svc.backup",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        severity=Severity.HIGH,
    )
    enriched = make_enriched(alert, risk_score=65.0, risk_level="high")

    response = engine.evaluate(enriched)

    assert ResponseAction.KILL_PROCESS not in response.triggered_actions
    assert any("allowlisted for 'kill_process'" in reason for reason in response.policy_reasoning)


def test_queue_mode_without_publisher_falls_back_to_sync(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")

    engine = PolicyEngine(verbose=False, policy_config_path=config_path)
    alert = make_alert(severity=Severity.HIGH)
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.MALICIOUS,
        hash_malicious_vendors=58,
        hash_threat_name="Trojan.GenericKD.48756123",
        risk_score=72.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    isolate_result = next(
        result for result in response.action_results if result.action == ResponseAction.ISOLATE_HOST
    )
    assert isolate_result.status == "success"
    assert response.execution_trace.configured_mode == "queued"
    assert response.execution_trace.effective_mode == "sync_fallback"
    assert response.execution_trace.queue_name == "policy-actions"
    assert response.execution_trace.fallback_reason is not None
    assert response.execution_trace.queued_actions[0].correlation_id.endswith(":isolate_host")
    assert [hook.field for hook in response.execution_trace.queued_actions[0].correlation_hooks] == [
        "hostname",
        "username",
        "file_hash",
        "destination_ip",
    ]


def test_queue_mode_with_publisher_queues_remediation_actions(tmp_path):
    class MemoryPublisher:
        def __init__(self) -> None:
            self.requests = []

        def publish(self, request) -> None:
            self.requests.append(request)

    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_data["execution"]["queue"]["queue_name"] = "remediation-jobs"
    config_data["execution"]["queue"]["correlation_prefix"] = "incident"
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")

    publisher = MemoryPublisher()
    engine = PolicyEngine(
        verbose=False,
        policy_config_path=config_path,
        queue_publisher=publisher,
    )
    alert = make_alert(severity=Severity.HIGH)
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.MALICIOUS,
        hash_malicious_vendors=58,
        hash_threat_name="Trojan.GenericKD.48756123",
        risk_score=72.0,
        risk_level="high",
    )

    response = engine.evaluate(enriched)

    isolate_result = next(
        result for result in response.action_results if result.action == ResponseAction.ISOLATE_HOST
    )
    assert isolate_result.status == "queued"
    assert ResponseAction.CREATE_TICKET in response.triggered_actions
    assert response.execution_trace.effective_mode == "queued"
    assert response.execution_trace.queue_name == "remediation-jobs"
    assert len(response.execution_trace.queued_actions) == 1
    assert publisher.requests[0].queue_name == "remediation-jobs"
    assert publisher.requests[0].correlation_id == "incident:test-alert-uuid-001:isolate_host"
    assert [(hook.field, hook.value) for hook in publisher.requests[0].correlation_hooks] == [
        ("hostname", "DESKTOP-ABC123"),
        ("username", "test.user"),
        ("file_hash", "0" * 64),
        ("destination_ip", "198.51.100.10"),
    ]


def test_queue_mode_respects_configured_correlation_fields(tmp_path):
    class MemoryPublisher:
        def __init__(self) -> None:
            self.requests = []

        def publish(self, request) -> None:
            self.requests.append(request)

    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_data["execution"]["queue"]["correlation_fields"] = ["file_hash", "destination_ip"]
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")

    publisher = MemoryPublisher()
    engine = PolicyEngine(
        verbose=False,
        policy_config_path=config_path,
        queue_publisher=publisher,
    )
    alert = make_alert(destination_ip="203.0.113.45")
    enriched = make_enriched(
        alert,
        hash_reputation=HashReputation.MALICIOUS,
        hash_malicious_vendors=10,
        risk_score=55.0,
        risk_level="medium",
    )

    response = engine.evaluate(enriched)

    assert response.execution_trace.effective_mode == "queued"
    assert [hook.field for hook in publisher.requests[0].correlation_hooks] == [
        "file_hash",
        "destination_ip",
    ]
    assert [(hook.field, hook.value) for hook in response.execution_trace.queued_actions[0].correlation_hooks] == [
        ("file_hash", "0" * 64),
        ("destination_ip", "203.0.113.45"),
    ]
