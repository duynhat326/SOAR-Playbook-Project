from enrichment.hash_intel import VirusTotalHashIntel
from enrichment.ip_intel import VirusTotalIPIntel
from enrichment.virustotal_client import VirusTotalNotFoundError
from schemas.alert import HashReputation, IPReputation


def test_virustotal_hash_intel_maps_malicious_response(monkeypatch):
    intel = VirusTotalHashIntel(api_key="test-key")

    def fake_get_attributes(path: str) -> dict:
        assert path == "/files/44d88612fea8a8f36de82e1278abb02f"
        return {
            "last_analysis_stats": {
                "malicious": 61,
                "suspicious": 2,
                "harmless": 0,
                "undetected": 12,
                "timeout": 0,
            },
            "popular_threat_classification": {
                "suggested_threat_label": "eicar.test.file"
            },
        }

    monkeypatch.setattr(intel._client, "get_attributes", fake_get_attributes)
    result = intel.lookup("44d88612fea8a8f36de82e1278abb02f")

    assert result.reputation == HashReputation.MALICIOUS
    assert result.malicious_vendors == 61
    assert result.total_vendors == 75
    assert result.threat_name == "eicar.test.file"
    assert result.source == "virustotal_api_v3"


def test_virustotal_hash_intel_maps_missing_hash_to_unknown(monkeypatch):
    intel = VirusTotalHashIntel(api_key="test-key")

    def fake_get_attributes(path: str) -> dict:
        raise VirusTotalNotFoundError(path)

    monkeypatch.setattr(intel._client, "get_attributes", fake_get_attributes)
    result = intel.lookup("deadbeefdeadbeefdeadbeefdeadbeef")

    assert result.reputation == HashReputation.UNKNOWN
    assert result.total_vendors == 0
    assert result.threat_name is None


def test_virustotal_ip_intel_keeps_private_ip_local():
    intel = VirusTotalIPIntel(api_key="test-key")
    result = intel.lookup("10.10.10.10")

    assert result.reputation == IPReputation.CLEAN
    assert result.country == "PRIVATE"
    assert result.source == "private_network"


def test_virustotal_ip_intel_infers_c2_from_tags(monkeypatch):
    intel = VirusTotalIPIntel(api_key="test-key")

    def fake_get_attributes(path: str) -> dict:
        assert path == "/ip_addresses/185.220.101.45"
        return {
            "country": "DE",
            "as_owner": "Example Transit",
            "tags": ["c2", "tor"],
            "last_analysis_stats": {
                "malicious": 14,
                "suspicious": 2,
                "harmless": 4,
                "undetected": 18,
                "timeout": 0,
            },
            "last_analysis_results": {
                "engine-a": {
                    "result": "malicious",
                    "category": "malicious",
                    "method": "blacklist",
                }
            },
        }

    monkeypatch.setattr(intel._client, "get_attributes", fake_get_attributes)
    result = intel.lookup("185.220.101.45")

    assert result.reputation == IPReputation.MALICIOUS
    assert result.is_c2 is True
    assert result.country == "DE"
    assert result.isp == "Example Transit"
    assert result.confidence_score == 39
    assert result.source == "virustotal_api_v3"
