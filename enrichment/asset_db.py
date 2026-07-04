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
import os
from pathlib import Path
from typing import Optional
from urllib import error, parse, request

from loguru import logger

from env_utils import load_local_env_files
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


class FileAssetDB(MockAssetDB):
    """CMDB adapter backed by an explicit JSON file path."""

    def __init__(self, db_path: Optional[Path] = None):
        super().__init__(db_path=db_path or Path(os.getenv("SOAR_ASSET_DB_PATH", str(_DB_PATH))))


class HttpAssetDB(BaseAssetDB):
    """Lightweight HTTP CMDB adapter for simple inventory services."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        *,
        token: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        load_local_env_files()
        self._base_url = (base_url or os.getenv("SOAR_ASSET_API_URL", "")).strip().rstrip("/")
        self._token = (token or os.getenv("SOAR_ASSET_API_TOKEN", "")).strip()
        self._timeout = timeout
        if not self._base_url:
            raise RuntimeError("SOAR_ASSET_API_URL is required for the HTTP asset provider.")

    def lookup(self, hostname: str) -> AssetCriticality:
        info = self.get_asset_info(hostname) or {}
        raw_value = str(info.get("criticality") or "normal").strip().lower()
        try:
            return AssetCriticality(raw_value)
        except ValueError:
            return AssetCriticality.NORMAL

    def get_asset_info(self, hostname: str) -> Optional[dict]:
        query = parse.quote(hostname, safe="")
        url = f"{self._base_url}/assets/{query}"
        request_headers = {"accept": "application/json"}
        if self._token:
            request_headers["authorization"] = f"Bearer {self._token}"

        http_request = request.Request(url, headers=request_headers, method="GET")
        try:
            with request.urlopen(http_request, timeout=self._timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            if exc.code == 404:
                logger.debug("[AssetDB] HTTP CMDB returned 404 for hostname '{}'.", hostname)
                return None
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP CMDB lookup failed with HTTP {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"HTTP CMDB lookup failed: {exc.reason}") from exc

        if isinstance(payload, dict) and "asset" in payload and isinstance(payload["asset"], dict):
            payload = payload["asset"]
        if not isinstance(payload, dict):
            raise RuntimeError("HTTP CMDB lookup returned an invalid payload.")
        return {**payload, "hostname": hostname}


def build_asset_db_from_env() -> BaseAssetDB:
    load_local_env_files()
    provider = os.getenv("SOAR_ASSET_PROVIDER", "mock").strip().lower()
    if provider == "file":
        return FileAssetDB()
    if provider == "http":
        return HttpAssetDB()
    return MockAssetDB()
