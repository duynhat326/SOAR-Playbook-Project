from __future__ import annotations

from dataclasses import dataclass
import os

from integrations.actions.providers import build_action_connector_from_env
from integrations.cmdb.providers import build_cmdb_connector_from_env
from integrations.contracts import (
    ActionConnector,
    CMDBConnector,
    SourceConnector,
    ThreatIntelConnector,
    TicketingConnector,
)
from integrations.intel.providers import build_threat_intel_connector_from_env
from integrations.sources import build_source_connector
from integrations.ticketing.providers import build_ticketing_connector_from_env
from observability.wrappers import (
    wrap_action_connector,
    wrap_cmdb_connector,
    wrap_source_connector,
    wrap_threat_intel_connector,
    wrap_ticketing_connector,
)


@dataclass(frozen=True)
class IntegrationProviders:
    source: SourceConnector
    threat_intel: ThreatIntelConnector
    cmdb: CMDBConnector
    action: ActionConnector
    ticketing: TicketingConnector


def build_default_integrations() -> IntegrationProviders:
    source_provider = os.getenv("SOAR_SOURCE_PROVIDER", "passthrough").strip().lower() or "passthrough"
    intel_provider = os.getenv("SOAR_INTEL_PROVIDER", "mock").strip().lower() or "mock"
    cmdb_provider = os.getenv("SOAR_ASSET_PROVIDER", "mock").strip().lower() or "mock"
    action_provider = os.getenv("SOAR_ACTION_PROVIDER", "local").strip().lower() or "local"
    ticketing_provider = os.getenv("SOAR_TICKETING_CONNECTOR", "local").strip().lower() or "local"
    return IntegrationProviders(
        source=wrap_source_connector(
            build_source_connector(source_provider),
            provider=source_provider,
        ),
        threat_intel=wrap_threat_intel_connector(
            build_threat_intel_connector_from_env(),
            provider=intel_provider,
        ),
        cmdb=wrap_cmdb_connector(
            build_cmdb_connector_from_env(),
            provider=cmdb_provider,
        ),
        action=wrap_action_connector(
            build_action_connector_from_env(),
            provider=action_provider,
        ),
        ticketing=wrap_ticketing_connector(
            build_ticketing_connector_from_env(),
            provider=ticketing_provider,
        ),
    )


def build_integration_providers(
    *,
    source: SourceConnector | None = None,
    threat_intel: ThreatIntelConnector | None = None,
    cmdb: CMDBConnector | None = None,
    action: ActionConnector | None = None,
    ticketing: TicketingConnector | None = None,
) -> IntegrationProviders:
    defaults = build_default_integrations()
    return IntegrationProviders(
        source=source or defaults.source,
        threat_intel=threat_intel or defaults.threat_intel,
        cmdb=cmdb or defaults.cmdb,
        action=action or defaults.action,
        ticketing=ticketing or defaults.ticketing,
    )
