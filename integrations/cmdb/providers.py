from __future__ import annotations

from enrichment.asset_db import build_asset_db_from_env
from enrichment.base import BaseAssetDB
from integrations.contracts import CMDBConnector
from schemas.alert import AssetCriticality


class AssetDBConnector(CMDBConnector):
    """CMDB connector backed by an existing asset database provider."""

    def __init__(self, asset_db: BaseAssetDB) -> None:
        self._asset_db = asset_db

    def lookup_criticality(self, hostname: str) -> AssetCriticality:
        return self._asset_db.lookup(hostname)

    def get_asset_info(self, hostname: str) -> dict | None:
        return self._asset_db.get_asset_info(hostname)


def build_cmdb_connector_from_env() -> CMDBConnector:
    return AssetDBConnector(build_asset_db_from_env())
