"""
enrichment/hash_intel.py
========================
Mock implementation của Hash Reputation lookup (VirusTotal-like).

Interface: BaseHashIntel
Mock DB  : data/mock_hash_db.json

Cách upgrade lên VirusTotal API thật:
    class VirusTotalHashIntel(BaseHashIntel):
        def __init__(self, api_key: str): ...
        def lookup(self, file_hash: str) -> HashEnrichment:
            # gọi requests.get("https://www.virustotal.com/api/v3/files/{hash}")
            ...
"""

import json
import random
from pathlib import Path
from typing import Optional

from loguru import logger

from enrichment.base import BaseHashIntel
from schemas.alert import HashEnrichment, HashReputation


# Đường dẫn đến mock DB (relative từ project root)
_DB_PATH = Path(__file__).parent.parent / "data" / "mock_hash_db.json"


class MockHashIntel(BaseHashIntel):
    """
    Mock hash reputation service — đọc từ JSON DB tĩnh.
    
    Logic tra cứu:
      1. Tìm hash trong mock DB → trả về reputation thật
      2. Không tìm thấy → trả về "unknown"
      
    Lý do dùng dict lookup thay vì regex:
      - Hash là string cố định → O(1) lookup
      - Dễ maintain khi thêm hash mới vào DB
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        Args:
            db_path: Đường dẫn đến mock DB JSON. 
                     Mặc định dùng data/mock_hash_db.json
        """
        self._db_path = db_path or _DB_PATH
        self._db = self._load_db()
        logger.debug(f"[HashIntel] Loaded {len(self._db)} hash records from {self._db_path.name}")

    def _load_db(self) -> dict:
        """Load mock DB từ JSON file vào memory."""
        try:
            with open(self._db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("hashes", {})
        except FileNotFoundError:
            logger.warning(f"[HashIntel] DB file not found: {self._db_path}. Using empty DB.")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"[HashIntel] JSON parse error: {e}")
            return {}

    def lookup(self, file_hash: str) -> HashEnrichment:
        """
        Tra cứu hash trong mock DB.
        
        Args:
            file_hash: SHA256 hash (lowercase)
            
        Returns:
            HashEnrichment với reputation, vendor counts, threat name
        """
        normalized = file_hash.lower().strip()
        logger.debug(f"[HashIntel] Looking up hash: {normalized[:16]}...")

        record = self._db.get(normalized)

        if record is None:
            # Hash không có trong DB → trả về UNKNOWN
            logger.debug(f"[HashIntel] Hash not found in DB → UNKNOWN")
            return HashEnrichment(
                hash_value=normalized,
                reputation=HashReputation.UNKNOWN,
                malicious_vendors=0,
                total_vendors=0,
                threat_name=None,
                source="mock_virustotal"
            )

        reputation_map = {
            "malicious": HashReputation.MALICIOUS,
            "suspicious": HashReputation.SUSPICIOUS,
            "clean": HashReputation.CLEAN,
        }
        reputation = reputation_map.get(record["reputation"], HashReputation.UNKNOWN)

        result = HashEnrichment(
            hash_value=normalized,
            reputation=reputation,
            malicious_vendors=record.get("malicious_vendors", 0),
            total_vendors=record.get("total_vendors", 0),
            threat_name=record.get("threat_name"),
            source="mock_virustotal"
        )

        logger.debug(
            f"[HashIntel] Result: {reputation.value} | "
            f"{result.malicious_vendors}/{result.total_vendors} vendors | "
            f"threat='{result.threat_name}'"
        )
        return result


class RandomHashIntel(BaseHashIntel):
    """
    Enrichment ngẫu nhiên cho alert generator — dùng khi test đa dạng scenario.
    
    Phân phối xác suất:
      - 30% malicious (để có đủ case test policy engine)
      - 20% suspicious
      - 50% clean
    """

    def __init__(self, seed: Optional[int] = None):
        """Args: seed — set seed để có kết quả reproducible khi test."""
        if seed is not None:
            random.seed(seed)

    def lookup(self, file_hash: str) -> HashEnrichment:
        roll = random.random()
        if roll < 0.30:
            return HashEnrichment(
                hash_value=file_hash,
                reputation=HashReputation.MALICIOUS,
                malicious_vendors=random.randint(30, 72),
                total_vendors=72,
                threat_name=random.choice([
                    "Trojan.GenericKD", "Backdoor.Cobalt.Strike",
                    "Ransomware.BlackCat", "Stealer.RedLine"
                ]),
                source="mock_virustotal_random"
            )
        elif roll < 0.50:
            return HashEnrichment(
                hash_value=file_hash,
                reputation=HashReputation.SUSPICIOUS,
                malicious_vendors=random.randint(5, 15),
                total_vendors=72,
                threat_name="Suspicious.Generic.Packer",
                source="mock_virustotal_random"
            )
        else:
            return HashEnrichment(
                hash_value=file_hash,
                reputation=HashReputation.CLEAN,
                malicious_vendors=0,
                total_vendors=72,
                threat_name=None,
                source="mock_virustotal_random"
            )
