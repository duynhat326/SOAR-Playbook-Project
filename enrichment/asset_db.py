"""
enrichment/asset_db.py
======================
Mock implementation của Asset Criticality lookup (CMDB-like).

Interface: BaseAssetDB
Mock DB  : data/mock_asset_db.json

Cách upgrade lên ServiceNow CMDB thật:
    class ServiceNowCMDB(BaseAssetDB):
        def __init__(self, instance_url: str, username: str, password: str): ...
        def lookup(self, hostname: str) -> AssetCriticality:
            # gọi ServiceNow REST API
            ...
"""

import json
from pathlib import Path
from typing import Optional

from loguru import logger

from enrichment.base import BaseAssetDB
from schemas.alert import AssetCriticality


_DB_PATH = Path(__file__).parent.parent / "data" / "mock_asset_db.json"


class MockAssetDB(BaseAssetDB):
    """
    Mock CMDB — tra cứu hostname → asset criticality từ JSON file tĩnh.
    
    Logic:
      1. Tìm hostname (case-insensitive) trong DB
      2. Không tìm thấy → dùng default criticality = "normal"
         (giả định host chưa được inventoried)
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        Args:
            db_path: Đường dẫn đến mock DB JSON.
        """
        self._db_path = db_path or _DB_PATH
        self._db, self._default_criticality = self._load_db()
        logger.debug(
            f"[AssetDB] Loaded {len(self._db)} asset records from {self._db_path.name}. "
            f"Default criticality for unknown hosts: '{self._default_criticality}'"
        )

    def _load_db(self) -> tuple[dict, str]:
        """Load DB và đọc default criticality cho unknown hosts."""
        try:
            with open(self._db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assets = data.get("assets", {})
            # Normalize keys về uppercase để case-insensitive lookup
            normalized = {k.upper(): v for k, v in assets.items()}
            default = data.get("_defaults", {}).get("unknown_host_criticality", "normal")
            return normalized, default
        except FileNotFoundError:
            logger.warning(f"[AssetDB] DB file not found: {self._db_path}. Using empty DB.")
            return {}, "normal"
        except json.JSONDecodeError as e:
            logger.error(f"[AssetDB] JSON parse error: {e}")
            return {}, "normal"

    def lookup(self, hostname: str) -> AssetCriticality:
        """
        Tra cứu mức criticality của hostname.
        
        Args:
            hostname: Tên máy (case-insensitive)
            
        Returns:
            AssetCriticality: critical | normal | low
        """
        key = hostname.upper()
        logger.debug(f"[AssetDB] Looking up hostname: {hostname}")

        record = self._db.get(key)

        if record is None:
            default_enum = AssetCriticality(self._default_criticality)
            logger.debug(
                f"[AssetDB] '{hostname}' not found in CMDB → "
                f"using default: {default_enum.value}"
            )
            return default_enum

        criticality_str = record.get("criticality", "normal")
        criticality = AssetCriticality(criticality_str)

        logger.debug(
            f"[AssetDB] '{hostname}' → {criticality.value} | "
            f"type={record.get('asset_type', 'unknown')} | "
            f"dept={record.get('department', 'unknown')}"
        )
        return criticality

    def get_asset_info(self, hostname: str) -> Optional[dict]:
        """
        Lấy toàn bộ metadata của asset.
        
        Returns:
            Dict với các field: criticality, asset_type, department, owner, os, ...
            None nếu hostname không có trong DB.
        """
        key = hostname.upper()
        record = self._db.get(key)
        if record:
            return {**record, "hostname": hostname}
        return None
