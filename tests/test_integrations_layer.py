from __future__ import annotations

from alert_generator.generator import generate_alert
from engine.policy_engine import PolicyEngine
from enrichment.pipeline import EnrichmentPipeline
from integrations.sources.default import PassthroughSourceConnector
from schemas.alert import (
    ActionResult,
    AssetCriticality,
    EnrichedAlert,
    HashEnrichment,
    HashReputation,
    IPEnrichment,
    IPReputation,
    ResponseAction,
)
from services.workflow_service import SoarWorkflowService
from time_utils import utc_now


class StubThreatIntelConnector:
    def __init__(self) -> None:
        self.hash_lookups: list[str] = []
        self.ip_lookups: list[str] = []

    def lookup_hash(self, file_hash: str) -> HashEnrichment:
        self.hash_lookups.append(file_hash)
        return HashEnrichment(
            hash_value=file_hash,
            reputation=HashReputation.MALICIOUS,
            malicious_vendors=12,
            suspicious_vendors=1,
            harmless_vendors=0,
            undetected_vendors=0,
            total_vendors=13,
            threat_name="Stub.Test.Sample",
            source="stub-threat-intel",
        )

    def lookup_ip(self, ip_address: str) -> IPEnrichment:
        self.ip_lookups.append(ip_address)
        return IPEnrichment(
            ip_address=ip_address,
            reputation=IPReputation.CLEAN,
            confidence_score=0,
            is_c2=False,
            malicious_vendors=0,
            suspicious_vendors=0,
            harmless_vendors=1,
            undetected_vendors=0,
            tags=[],
            analysis_stats={},
            source="stub-threat-intel",
        )


class StubCMDBConnector:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def lookup_criticality(self, hostname: str) -> AssetCriticality:
        self.queries.append(hostname)
        return AssetCriticality.NORMAL

    def get_asset_info(self, hostname: str) -> dict[str, str]:
        return {"hostname": hostname, "owner": "stub-owner", "asset_type": "workstation"}


class StubActionConnector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def isolate_host(self, *, hostname: str, alert_id: str, reason: str, operator: str = "SOAR_AUTO") -> ActionResult:
        self.calls.append(("isolate_host", hostname))
        return ActionResult(
            action=ResponseAction.ISOLATE_HOST,
            status="succeeded",
            executed_at=utc_now(),
            details=f"isolated {hostname}: {reason}",
            operator=operator,
        )

    def kill_process(
        self,
        *,
        process_name: str,
        hostname: str,
        alert_id: str,
        command_line: str = "",
        reason: str = "Dangerous process detected",
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        raise AssertionError("kill_process should not be called in this test")

    def block_ip(
        self,
        *,
        ip_address: str,
        alert_id: str,
        hostname: str = "",
        reason: str = "C2 IP detected",
        confidence: int = 0,
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        raise AssertionError("block_ip should not be called in this test")

    def escalate(self, *, hostname: str, reason: str, operator: str = "SOAR_AUTO") -> ActionResult:
        raise AssertionError("escalate should not be called in this test")

    def notify_soc(
        self,
        *,
        alert_id: str,
        hostname: str,
        risk_score: float,
        risk_level: str,
        triggered_actions,
        ticket_id: str = "",
        channel: str = "#soc-alerts",
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        self.calls.append(("notify_soc", hostname))
        return ActionResult(
            action=ResponseAction.NOTIFY_SOC,
            status="succeeded",
            executed_at=utc_now(),
            details=f"notified {channel} for {hostname}",
            operator=operator,
        )


class StubTicketingConnector:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def create_ticket(
        self,
        *,
        enriched_alert: EnrichedAlert,
        triggered_actions,
        risk_score: float,
        risk_level: str,
        operator: str = "SOAR_AUTO",
    ) -> tuple[ActionResult, str]:
        self.calls.append(enriched_alert.original_alert.alert_id)
        return (
            ActionResult(
                action=ResponseAction.CREATE_TICKET,
                status="succeeded",
                executed_at=utc_now(),
                details="stub ticket created",
                operator=operator,
            ),
            "INC-STUB-0001",
        )


def test_workflow_service_can_run_through_integration_contracts():
    source = PassthroughSourceConnector()
    threat_intel = StubThreatIntelConnector()
    cmdb = StubCMDBConnector()
    action = StubActionConnector()
    ticketing = StubTicketingConnector()

    raw_alert = generate_alert(scenario="benign", seed=4242).model_dump()
    raw_alert["hostname"] = "WS-STUB-01"
    raw_alert["process_name"] = "chrome.exe"
    raw_alert["destination_ip"] = "8.8.8.8"
    alert = source.normalize_alert(raw_alert)

    service = SoarWorkflowService(
        verbose=False,
        persist_results=False,
        pipeline=EnrichmentPipeline(
            threat_intel=threat_intel,
            cmdb_connector=cmdb,
            verbose=False,
        ),
        policy_engine=PolicyEngine(
            verbose=False,
            action_connector=action,
            ticketing_connector=ticketing,
        ),
    )

    result = service.process_alert(alert, generate_report=False, export_pdf=False)

    assert threat_intel.hash_lookups == [alert.file_hash]
    assert threat_intel.ip_lookups == [alert.destination_ip]
    assert cmdb.queries == [alert.hostname]
    assert ticketing.calls == [alert.alert_id]
    assert ("isolate_host", alert.hostname) in action.calls
    assert ("notify_soc", alert.hostname) in action.calls
    assert result.response.ticket_id == "INC-STUB-0001"
    assert ResponseAction.ISOLATE_HOST in result.response.triggered_actions
    assert result.enriched_alert.hash_enrichment is not None
    assert result.enriched_alert.hash_enrichment.source == "stub-threat-intel"
