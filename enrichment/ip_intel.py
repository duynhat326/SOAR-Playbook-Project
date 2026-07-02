"""
enrichment/ip_intel.py
======================
Mock implementation của IP Reputation lookup (AbuseIPDB-like).

Interface: BaseIPIntel
Mock DB  : data/mock_ip_db.json

Cách upgrade lên AbuseIPDB API thật:
    class AbuseIPDBIntel(BaseIPIntel):
        def __init__(self, api_key: str): ...
        def lookup(self, ip_address: str) -> IPEnrichment:
            # gọi requests.get("https://api.abuseipdb.com/api/v2/check",
            #                  params={"ipAddress": ip_address, "maxAgeInDays": 90},
            #                  headers={"Key": api_key})
            ...
"""

import json
import random
from pathlib import Path
from typing import Optional

from loguru import logger

from enrichment.base import BaseIPIntel
from schemas.alert import IPEnrichment, IPReputation


_DB_PATH = Path(__file__).parent.parent / "data" / "mock_ip_db.json"


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
                source="mock_abuseipdb_random"
            )
