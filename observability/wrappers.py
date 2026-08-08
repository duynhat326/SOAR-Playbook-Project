from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from integrations.contracts import (
    ActionConnector,
    CMDBConnector,
    SourceConnector,
    ThreatIntelConnector,
    TicketingConnector,
)
from observability.resilience import DownstreamGuard, downstream_guard
from observability.runtime import observability
from schemas.alert import ActionResult, AssetCriticality, EnrichedAlert, HashEnrichment, IPEnrichment, MalwareAlert


@dataclass(frozen=True)
class InstrumentedSourceConnector(SourceConnector):
    inner: SourceConnector
    provider: str
    guard: DownstreamGuard = downstream_guard

    def normalize_alert(self, payload):
        with observability.span("connector.source.normalize_alert", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="source.normalize_alert",
                func=lambda: self.inner.normalize_alert(payload),
            )


@dataclass(frozen=True)
class InstrumentedThreatIntelConnector(ThreatIntelConnector):
    inner: ThreatIntelConnector
    provider: str
    guard: DownstreamGuard = downstream_guard

    def lookup_hash(self, file_hash: str) -> HashEnrichment:
        with observability.span("connector.intel.lookup_hash", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="threat_intel.lookup_hash",
                func=lambda: self.inner.lookup_hash(file_hash),
            )

    def lookup_ip(self, ip_address: str) -> IPEnrichment:
        with observability.span("connector.intel.lookup_ip", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="threat_intel.lookup_ip",
                func=lambda: self.inner.lookup_ip(ip_address),
            )


@dataclass(frozen=True)
class InstrumentedCMDBConnector(CMDBConnector):
    inner: CMDBConnector
    provider: str
    guard: DownstreamGuard = downstream_guard

    def lookup_criticality(self, hostname: str) -> AssetCriticality:
        with observability.span("connector.cmdb.lookup_criticality", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="cmdb.lookup_criticality",
                func=lambda: self.inner.lookup_criticality(hostname),
            )

    def get_asset_info(self, hostname: str) -> dict[str, Any] | None:
        with observability.span("connector.cmdb.get_asset_info", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="cmdb.get_asset_info",
                func=lambda: self.inner.get_asset_info(hostname),
            )


@dataclass(frozen=True)
class InstrumentedActionConnector(ActionConnector):
    inner: ActionConnector
    provider: str
    guard: DownstreamGuard = downstream_guard

    def isolate_host(self, *, hostname: str, alert_id: str, reason: str, operator: str = "SOAR_AUTO") -> ActionResult:
        with observability.span("connector.action.isolate_host", provider=self.provider, action="isolate_host"):
            return self.guard.call(
                provider=self.provider,
                operation="action.isolate_host",
                func=lambda: self.inner.isolate_host(
                    hostname=hostname,
                    alert_id=alert_id,
                    reason=reason,
                    operator=operator,
                ),
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
        with observability.span("connector.action.kill_process", provider=self.provider, action="kill_process"):
            return self.guard.call(
                provider=self.provider,
                operation="action.kill_process",
                func=lambda: self.inner.kill_process(
                    process_name=process_name,
                    hostname=hostname,
                    alert_id=alert_id,
                    command_line=command_line,
                    reason=reason,
                    operator=operator,
                ),
            )

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
        with observability.span("connector.action.block_ip", provider=self.provider, action="block_ip"):
            return self.guard.call(
                provider=self.provider,
                operation="action.block_ip",
                func=lambda: self.inner.block_ip(
                    ip_address=ip_address,
                    alert_id=alert_id,
                    hostname=hostname,
                    reason=reason,
                    confidence=confidence,
                    operator=operator,
                ),
            )

    def escalate(self, *, hostname: str, reason: str, operator: str = "SOAR_AUTO") -> ActionResult:
        with observability.span("connector.action.escalate", provider=self.provider, action="escalate"):
            return self.guard.call(
                provider=self.provider,
                operation="action.escalate",
                func=lambda: self.inner.escalate(
                    hostname=hostname,
                    reason=reason,
                    operator=operator,
                ),
            )

    def notify_soc(
        self,
        *,
        alert_id: str,
        hostname: str,
        risk_score: float,
        risk_level: str,
        triggered_actions: Sequence[str],
        ticket_id: str = "",
        channel: str = "#soc-alerts",
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        with observability.span("connector.action.notify_soc", provider=self.provider, action="notify_soc"):
            return self.guard.call(
                provider=self.provider,
                operation="action.notify_soc",
                func=lambda: self.inner.notify_soc(
                    alert_id=alert_id,
                    hostname=hostname,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    triggered_actions=triggered_actions,
                    ticket_id=ticket_id,
                    channel=channel,
                    operator=operator,
                ),
            )


@dataclass(frozen=True)
class InstrumentedTicketingConnector(TicketingConnector):
    inner: TicketingConnector
    provider: str
    guard: DownstreamGuard = downstream_guard

    def create_ticket(
        self,
        *,
        enriched_alert: EnrichedAlert,
        triggered_actions: Sequence[str],
        risk_score: float,
        risk_level: str,
        operator: str = "SOAR_AUTO",
    ) -> tuple[ActionResult, str]:
        with observability.span("connector.ticketing.create_ticket", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="ticketing.create_ticket",
                func=lambda: self.inner.create_ticket(
                    enriched_alert=enriched_alert,
                    triggered_actions=triggered_actions,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    operator=operator,
                ),
            )

    def append_case_comment(
        self,
        *,
        ticket_id: str,
        comment: str,
        author: str = "SOAR_AUTO",
        metadata: dict[str, Any] | None = None,
    ) -> ActionResult | None:
        with observability.span("connector.ticketing.append_case_comment", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="ticketing.append_case_comment",
                func=lambda: self.inner.append_case_comment(
                    ticket_id=ticket_id,
                    comment=comment,
                    author=author,
                    metadata=metadata,
                ),
            )

    def sync_case_state(
        self,
        *,
        ticket_id: str,
        case_status: str,
        case_owner: str | None = None,
        comment: str | None = None,
        actor: str = "SOAR_AUTO",
        metadata: dict[str, Any] | None = None,
    ) -> ActionResult | None:
        with observability.span("connector.ticketing.sync_case_state", provider=self.provider):
            return self.guard.call(
                provider=self.provider,
                operation="ticketing.sync_case_state",
                func=lambda: self.inner.sync_case_state(
                    ticket_id=ticket_id,
                    case_status=case_status,
                    case_owner=case_owner,
                    comment=comment,
                    actor=actor,
                    metadata=metadata,
                ),
            )


def wrap_source_connector(connector: SourceConnector, *, provider: str | None = None) -> SourceConnector:
    if isinstance(connector, InstrumentedSourceConnector):
        return connector
    return InstrumentedSourceConnector(inner=connector, provider=provider or connector.__class__.__name__)


def wrap_threat_intel_connector(
    connector: ThreatIntelConnector,
    *,
    provider: str | None = None,
) -> ThreatIntelConnector:
    if isinstance(connector, InstrumentedThreatIntelConnector):
        return connector
    return InstrumentedThreatIntelConnector(inner=connector, provider=provider or connector.__class__.__name__)


def wrap_cmdb_connector(connector: CMDBConnector, *, provider: str | None = None) -> CMDBConnector:
    if isinstance(connector, InstrumentedCMDBConnector):
        return connector
    return InstrumentedCMDBConnector(inner=connector, provider=provider or connector.__class__.__name__)


def wrap_action_connector(connector: ActionConnector, *, provider: str | None = None) -> ActionConnector:
    if isinstance(connector, InstrumentedActionConnector):
        return connector
    return InstrumentedActionConnector(inner=connector, provider=provider or connector.__class__.__name__)


def wrap_ticketing_connector(
    connector: TicketingConnector,
    *,
    provider: str | None = None,
) -> TicketingConnector:
    if isinstance(connector, InstrumentedTicketingConnector):
        return connector
    return InstrumentedTicketingConnector(inner=connector, provider=provider or connector.__class__.__name__)
