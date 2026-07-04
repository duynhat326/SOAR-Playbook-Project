"""
enrichment/ip_intel.py
======================
IP reputation providers.

- MockIPIntel        : static JSON for demo / offline tests
- VirusTotalIPIntel  : live VirusTotal API v3 IP lookup
"""

import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

from loguru import logger

from enrichment.base import BaseIPIntel
from enrichment.virustotal_client import VirusTotalClient, VirusTotalNotFoundError
from schemas.alert import IPEnrichment, IPReputation


_DB_PATH = Path(__file__).parent.parent / "data" / "mock_ip_db.json"


def _map_ip_reputation(
    malicious: int,
    suspicious: int,
    total: int,
) -> IPReputation:
    if malicious > 0:
        return IPReputation.MALICIOUS
    if suspicious > 0:
        return IPReputation.UNKNOWN
    if total > 0:
        return IPReputation.CLEAN
    return IPReputation.UNKNOWN


def _vt_confidence_score(stats: dict) -> int:
    total = sum(int(value or 0) for value in stats.values() if isinstance(value, int))
    if total <= 0:
        return 0
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    weighted = malicious + (0.5 * suspicious)
    return max(0, min(100, round((weighted / total) * 100)))


def _infer_c2_signal(attributes: dict) -> bool:
    keywords = ("c2", "command-and-control", "command_and_control", "botnet")
    tags = [str(tag).lower() for tag in (attributes.get("tags") or [])]
    if any(any(keyword in tag for keyword in keywords) for tag in tags):
        return True

    analysis_results = attributes.get("last_analysis_results") or {}
    for result in analysis_results.values():
        if not isinstance(result, dict):
            continue
        raw_value = " ".join(
            str(part).lower()
            for part in (
                result.get("result"),
                result.get("category"),
                result.get("method"),
            )
            if part
        )
        if any(keyword in raw_value for keyword in keywords):
            return True
    return False


def _extract_analysis_date(attributes: dict) -> Optional[datetime]:
    raw_timestamp = attributes.get("last_analysis_date")
    if isinstance(raw_timestamp, int) and raw_timestamp > 0:
        return datetime.fromtimestamp(raw_timestamp, UTC)
    return None


class VirusTotalIPIntel(BaseIPIntel):
    """Live IP reputation lookup using VirusTotal API v3."""

    _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127.", "169.254.")

    def __init__(self, api_key: Optional[str] = None, *, timeout: float = 15.0):
        self._client = VirusTotalClient(api_key=api_key, timeout=timeout)

    def _is_private_ip(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self._PRIVATE_PREFIXES)

    def lookup(self, ip_address: str) -> IPEnrichment:
        logger.debug(f"[IPIntel] VirusTotal lookup for IP: {ip_address}")

        if self._is_private_ip(ip_address):
            return IPEnrichment(
                ip_address=ip_address,
                reputation=IPReputation.CLEAN,
                confidence_score=0,
                is_c2=False,
                country="PRIVATE",
                isp="Internal Network",
                malicious_vendors=0,
                suspicious_vendors=0,
                harmless_vendors=0,
                undetected_vendors=0,
                tags=[],
                analysis_stats={},
                community_reputation=None,
                last_analysis_date=None,
                permalink=None,
                source="private_network",
            )

        try:
            attributes = self._client.get_attributes(f"/ip_addresses/{ip_address}")
        except VirusTotalNotFoundError:
            logger.debug("[IPIntel] VirusTotal has no IP object for this address.")
            return IPEnrichment(
                ip_address=ip_address,
                reputation=IPReputation.UNKNOWN,
                confidence_score=0,
                is_c2=False,
                malicious_vendors=0,
                suspicious_vendors=0,
                harmless_vendors=0,
                undetected_vendors=0,
                tags=[],
                analysis_stats={},
                community_reputation=None,
                last_analysis_date=None,
                permalink=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                source="virustotal_api_v3",
            )

        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(value or 0) for value in stats.values() if isinstance(value, int))

        result = IPEnrichment(
            ip_address=ip_address,
            reputation=_map_ip_reputation(malicious, suspicious, total),
            confidence_score=_vt_confidence_score(stats),
            # VT IP objects expose tags/results/stats, not a first-class is_c2 boolean.
            is_c2=_infer_c2_signal(attributes),
            country=attributes.get("country"),
            isp=attributes.get("as_owner"),
            asn=(
                int(attributes.get("asn"))
                if isinstance(attributes.get("asn"), int)
                else None
            ),
            network=(
                str(attributes.get("network"))
                if attributes.get("network")
                else None
            ),
            malicious_vendors=malicious,
            suspicious_vendors=suspicious,
            harmless_vendors=int(stats.get("harmless", 0) or 0),
            undetected_vendors=int(stats.get("undetected", 0) or 0),
            tags=[str(tag) for tag in (attributes.get("tags") or [])],
            analysis_stats={
                str(key): int(value or 0)
                for key, value in stats.items()
                if isinstance(value, int)
            },
            community_reputation=(
                int(attributes.get("reputation"))
                if isinstance(attributes.get("reputation"), int)
                else None
            ),
            last_analysis_date=_extract_analysis_date(attributes),
            permalink=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
            source="virustotal_api_v3",
        )
        logger.debug(
            f"[IPIntel] VT result: {result.reputation.value} | "
            f"confidence={result.confidence_score} | is_c2={result.is_c2} | "
            f"country={result.country}"
        )
        return result


class MockIPIntel(BaseIPIntel):
    """
    Mock IP reputation service — đọc từ JSON DB tĩnh.
    
    Logic tra cứu:
      1. Tìm IP trong mock DB → trả về reputation thật
      2. Không tìm thấy → trả về "unknown"
      3. Private/RFC1918 addresses → tự động CLEAN (không gởi ra ngoài tra)
    """

    # RFC 1918 private ranges (simplified check)
    _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127.", "169.254.")

    def __init__(self, db_path: Optional[Path] = None):
        """
        Args:
            db_path: Đường dẫn đến mock DB JSON.
        """
        self._db_path = db_path or _DB_PATH
        self._db = self._load_db()
        logger.debug(f"[IPIntel] Loaded {len(self._db)} IP records from {self._db_path.name}")

    def _load_db(self) -> dict:
        """Load mock DB từ JSON file vào memory."""
        try:
            with open(self._db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("ips", {})
        except FileNotFoundError:
            logger.warning(f"[IPIntel] DB file not found: {self._db_path}. Using empty DB.")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"[IPIntel] JSON parse error: {e}")
            return {}

    def _is_private_ip(self, ip: str) -> bool:
        """Kiểm tra IP có phải private/internal không."""
        return any(ip.startswith(prefix) for prefix in self._PRIVATE_PREFIXES)

    def lookup(self, ip_address: str) -> IPEnrichment:
        """
        Tra cứu IP trong mock DB.
        
        Args:
            ip_address: IPv4 address
            
        Returns:
            IPEnrichment với reputation, confidence score, C2 flag
        """
        logger.debug(f"[IPIntel] Looking up IP: {ip_address}")

        # Private IP → auto CLEAN, không cần tra
        if self._is_private_ip(ip_address):
            logger.debug(f"[IPIntel] {ip_address} is private IP → CLEAN (auto)")
            return IPEnrichment(
                ip_address=ip_address,
                reputation=IPReputation.CLEAN,
                confidence_score=0,
                is_c2=False,
                country="PRIVATE",
                isp="Internal Network",
                malicious_vendors=0,
                suspicious_vendors=0,
                harmless_vendors=0,
                undetected_vendors=0,
                tags=[],
                analysis_stats={},
                community_reputation=None,
                last_analysis_date=None,
                permalink=None,
                source="mock_abuseipdb"
            )

        record = self._db.get(ip_address)

        if record is None:
            logger.debug(f"[IPIntel] IP not found in DB → UNKNOWN")
            return IPEnrichment(
                ip_address=ip_address,
                reputation=IPReputation.UNKNOWN,
                confidence_score=0,
                is_c2=False,
                malicious_vendors=0,
                suspicious_vendors=0,
                harmless_vendors=0,
                undetected_vendors=0,
                tags=[],
                analysis_stats={},
                community_reputation=None,
                last_analysis_date=None,
                permalink=None,
                source="mock_abuseipdb"
            )

        reputation_map = {
            "malicious": IPReputation.MALICIOUS,
            "clean": IPReputation.CLEAN,
        }
        reputation = reputation_map.get(record["reputation"], IPReputation.UNKNOWN)

        result = IPEnrichment(
            ip_address=ip_address,
            reputation=reputation,
            confidence_score=record.get("confidence_score", 0),
            is_c2=record.get("is_c2", False),
            country=record.get("country"),
            isp=record.get("isp"),
            asn=record.get("asn"),
            network=record.get("network"),
            malicious_vendors=record.get("malicious_vendors", 0),
            suspicious_vendors=record.get("suspicious_vendors", 0),
            harmless_vendors=record.get("harmless_vendors", 0),
            undetected_vendors=record.get("undetected_vendors", 0),
            tags=[str(tag) for tag in record.get("tags", [])],
            analysis_stats={
                "malicious": int(record.get("malicious_vendors", 0) or 0),
                "suspicious": int(record.get("suspicious_vendors", 0) or 0),
                "harmless": int(record.get("harmless_vendors", 0) or 0),
                "undetected": int(record.get("undetected_vendors", 0) or 0),
            },
            community_reputation=record.get("community_reputation"),
            last_analysis_date=None,
            permalink=record.get("permalink"),
            source="mock_abuseipdb"
        )

        logger.debug(
            f"[IPIntel] Result: {reputation.value} | "
            f"confidence={result.confidence_score} | "
            f"is_c2={result.is_c2} | country={result.country}"
        )
        return result


class RandomIPIntel(BaseIPIntel):
    """
    Enrichment ngẫu nhiên cho alert generator — test đa dạng scenario.
    
    Phân phối:
      - 25% malicious + is_c2=True
      - 15% malicious + is_c2=False
      - 60% clean
    """

    # Danh sách IP C2 giả để random pick
    _FAKE_C2_IPS = [
        "185.220.101.45", "194.165.16.11", "91.219.216.55",
        "45.142.212.100", "178.32.117.56"
    ]
    _FAKE_COUNTRIES = ["RU", "CN", "DE", "NL", "UA", "BY", "IR"]

    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)

    def lookup(self, ip_address: str) -> IPEnrichment:
        roll = random.random()
        if roll < 0.25:
            return IPEnrichment(
                ip_address=ip_address,
                reputation=IPReputation.MALICIOUS,
                confidence_score=random.randint(70, 100),
                is_c2=True,
                country=random.choice(self._FAKE_COUNTRIES),
                isp="Bulletproof Hosting LLC",
                asn=64512,
                network="185.220.101.0/24",
                malicious_vendors=random.randint(10, 20),
                suspicious_vendors=random.randint(0, 4),
                harmless_vendors=random.randint(0, 2),
                undetected_vendors=random.randint(10, 20),
                tags=["c2", "botnet"],
                analysis_stats={},
                community_reputation=random.randint(-20, -1),
                last_analysis_date=None,
                permalink=None,
                source="mock_abuseipdb_random"
            )
        elif roll < 0.40:
            return IPEnrichment(
                ip_address=ip_address,
                reputation=IPReputation.MALICIOUS,
                confidence_score=random.randint(40, 70),
                is_c2=False,
                country=random.choice(self._FAKE_COUNTRIES),
                isp="Unknown ISP",
                asn=64513,
                network="45.142.212.0/24",
                malicious_vendors=random.randint(5, 15),
                suspicious_vendors=random.randint(2, 5),
                harmless_vendors=random.randint(0, 2),
                undetected_vendors=random.randint(10, 25),
                tags=["malicious"],
                analysis_stats={},
                community_reputation=random.randint(-8, 2),
                last_analysis_date=None,
                permalink=None,
                source="mock_abuseipdb_random"
            )
        else:
            return IPEnrichment(
                ip_address=ip_address,
                reputation=IPReputation.CLEAN,
                confidence_score=0,
                is_c2=False,
                country="US",
                isp="Cloudflare Inc.",
                asn=13335,
                network="104.16.0.0/12",
                malicious_vendors=0,
                suspicious_vendors=0,
                harmless_vendors=random.randint(20, 40),
                undetected_vendors=random.randint(10, 25),
                tags=[],
                analysis_stats={},
                community_reputation=random.randint(0, 10),
                last_analysis_date=None,
                permalink=None,
                source="mock_abuseipdb_random"
            )
