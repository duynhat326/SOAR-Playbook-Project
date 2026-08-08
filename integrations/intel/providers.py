from __future__ import annotations

import os

from env_utils import load_local_env_files
from enrichment.base import BaseHashIntel, BaseIPIntel
from enrichment.hash_intel import MockHashIntel, VirusTotalHashIntel
from enrichment.ip_intel import MockIPIntel, VirusTotalIPIntel
from integrations.contracts import ThreatIntelConnector
from schemas.alert import HashEnrichment, IPEnrichment


class DelegatingThreatIntelConnector(ThreatIntelConnector):
    """Threat-intel connector backed by explicit hash and IP providers."""

    def __init__(self, *, hash_provider: BaseHashIntel, ip_provider: BaseIPIntel) -> None:
        self._hash_provider = hash_provider
        self._ip_provider = ip_provider

    def lookup_hash(self, file_hash: str) -> HashEnrichment:
        return self._hash_provider.lookup(file_hash)

    def lookup_ip(self, ip_address: str) -> IPEnrichment:
        return self._ip_provider.lookup(ip_address)


def build_threat_intel_provider_pair_from_env() -> tuple[BaseHashIntel, BaseIPIntel]:
    load_local_env_files()
    provider = os.getenv("SOAR_INTEL_PROVIDER", "mock").strip().lower()
    if provider == "virustotal":
        return VirusTotalHashIntel(), VirusTotalIPIntel()
    return MockHashIntel(), MockIPIntel()


def build_threat_intel_connector_from_env() -> ThreatIntelConnector:
    hash_provider, ip_provider = build_threat_intel_provider_pair_from_env()
    return DelegatingThreatIntelConnector(
        hash_provider=hash_provider,
        ip_provider=ip_provider,
    )
