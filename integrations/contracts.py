from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from schemas.alert import (
    ActionResult,
    AssetCriticality,
    EnrichedAlert,
    HashEnrichment,
    IPEnrichment,
    MalwareAlert,
)


@runtime_checkable
class SourceConnector(Protocol):
    """Normalize an inbound payload into the canonical malware alert schema."""

    def normalize_alert(self, payload: Mapping[str, Any]) -> MalwareAlert:
        ...


@runtime_checkable
class ThreatIntelConnector(Protocol):
    """Resolve threat-intel context for hashes and IP addresses."""

    def lookup_hash(self, file_hash: str) -> HashEnrichment:
        ...

    def lookup_ip(self, ip_address: str) -> IPEnrichment:
        ...


@runtime_checkable
class CMDBConnector(Protocol):
    """Resolve asset criticality and metadata."""

    def lookup_criticality(self, hostname: str) -> AssetCriticality:
        ...

    def get_asset_info(self, hostname: str) -> dict[str, Any] | None:
        ...


@runtime_checkable
class ActionConnector(Protocol):
    """Execute remediation and analyst-facing response actions."""

    def isolate_host(
        self,
        *,
        hostname: str,
        alert_id: str,
        reason: str,
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        ...

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
        ...

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
        ...

    def escalate(
        self,
        *,
        hostname: str,
        reason: str,
        operator: str = "SOAR_AUTO",
    ) -> ActionResult:
        ...

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
        ...


@runtime_checkable
class TicketingConnector(Protocol):
    """Create or synchronize case records in ticketing systems."""

    def create_ticket(
        self,
        *,
        enriched_alert: EnrichedAlert,
        triggered_actions: Sequence[str],
        risk_score: float,
        risk_level: str,
        operator: str = "SOAR_AUTO",
    ) -> tuple[ActionResult, str]:
        ...

    def append_case_comment(
        self,
        *,
        ticket_id: str,
        comment: str,
        author: str = "SOAR_AUTO",
        metadata: Mapping[str, Any] | None = None,
    ) -> ActionResult | None:
        ...

    def sync_case_state(
        self,
        *,
        ticket_id: str,
        case_status: str,
        case_owner: str | None = None,
        comment: str | None = None,
        actor: str = "SOAR_AUTO",
        metadata: Mapping[str, Any] | None = None,
    ) -> ActionResult | None:
        ...
