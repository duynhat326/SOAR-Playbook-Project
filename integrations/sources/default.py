from __future__ import annotations

import os
from typing import Any, Mapping

from env_utils import load_local_env_files
from integrations.contracts import SourceConnector
from integrations.sources.microsoft_defender import MicrosoftDefenderSourceConnector
from integrations.sources.wazuh import WazuhSourceConnector
from schemas.alert import MalwareAlert


class PassthroughSourceConnector(SourceConnector):
    """Normalize already-shaped payloads into the canonical alert model."""

    def normalize_alert(self, payload: Mapping[str, Any]) -> MalwareAlert:
        return MalwareAlert(**dict(payload))


def build_source_connector(provider: str | None = None) -> SourceConnector:
    load_local_env_files()
    resolved_provider = (
        provider
        or os.getenv("SOAR_SOURCE_PROVIDER")
        or os.getenv("SOAR_SOURCE_CONNECTOR")
        or "passthrough"
    ).strip().lower()
    if resolved_provider in {"", "passthrough", "canonical"}:
        return PassthroughSourceConnector()
    if resolved_provider == "wazuh":
        return WazuhSourceConnector()
    if resolved_provider in {"defender", "microsoft_defender", "microsoft-defender", "mdatp"}:
        return MicrosoftDefenderSourceConnector()
    raise RuntimeError(f"Unsupported source connector '{resolved_provider}'.")


def build_source_connector_from_env() -> SourceConnector:
    return build_source_connector()
