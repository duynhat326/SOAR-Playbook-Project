from __future__ import annotations

from typing import TYPE_CHECKING, Any

from integrations.contracts import (
    ActionConnector,
    CMDBConnector,
    SourceConnector,
    ThreatIntelConnector,
    TicketingConnector,
)

if TYPE_CHECKING:
    from integrations.registry import (
        IntegrationProviders,
        build_default_integrations,
        build_integration_providers,
    )


def __getattr__(name: str) -> Any:
    if name in {"IntegrationProviders", "build_default_integrations", "build_integration_providers"}:
        from integrations import registry

        return getattr(registry, name)
    raise AttributeError(f"module 'integrations' has no attribute {name!r}")


__all__ = [
    "ActionConnector",
    "CMDBConnector",
    "IntegrationProviders",
    "SourceConnector",
    "ThreatIntelConnector",
    "TicketingConnector",
    "build_default_integrations",
    "build_integration_providers",
]
