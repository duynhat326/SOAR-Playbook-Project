"""
enrichment/base.py
==================
Abstract Base Classes (Interface) cho tất cả enrichment modules.

Thiết kế theo Pattern: Strategy + Interface
  → Dễ dàng swap mock bằng API thật (VirusTotal, AbuseIPDB, v.v.) sau này
  → Chỉ cần implement abstract methods, không thay đổi phần còn lại của pipeline

Ví dụ upgrade:
  MockHashIntel  → VirusTotalHashIntel  (chỉ cần implement _lookup_api)
  MockIPIntel    → AbuseIPDBIntel       (chỉ cần implement _lookup_api)
  MockAssetDB    → ServiceNowCMDB       (chỉ cần implement _lookup_api)
"""

from abc import ABC, abstractmethod
from typing import Optional

from schemas.alert import HashEnrichment, IPEnrichment, AssetCriticality


class BaseHashIntel(ABC):
    """
    Interface cho Hash Reputation lookup.
    
    Implement class này để tích hợp với bất kỳ threat intel source nào:
    - MockHashIntel      : đọc từ mock_hash_db.json (dùng cho dev/demo)
    - VirusTotalHashIntel: gọi VT API thật (cần API key)
    - HybridHashIntel    : kết hợp multiple sources
    """

    @abstractmethod
    def lookup(self, file_hash: str) -> HashEnrichment:
        """
        Tra cứu reputation của một file hash.
        
        Args:
            file_hash: SHA256 hash của file cần kiểm tra
            
        Returns:
            HashEnrichment object với reputation, vendor count, threat name, v.v.
        """
        ...

    def is_malicious(self, file_hash: str) -> bool:
        """Helper: True nếu hash được đánh giá là malicious."""
        result = self.lookup(file_hash)
        return result.reputation.value == "malicious"


class BaseIPIntel(ABC):
    """
    Interface cho IP Reputation lookup.
    
    Implement class này để tích hợp với:
    - MockIPIntel       : đọc từ mock_ip_db.json (dùng cho dev/demo)
    - AbuseIPDBIntel    : gọi AbuseIPDB API thật (cần API key)
    - ThreatFoxIPIntel  : gọi ThreatFox API thật (miễn phí nhưng cần đăng ký)
    """

    @abstractmethod
    def lookup(self, ip_address: str) -> IPEnrichment:
        """
        Tra cứu reputation của một địa chỉ IP.
        
        Args:
            ip_address: IPv4 address cần kiểm tra
            
        Returns:
            IPEnrichment object với reputation, confidence score, C2 flag, v.v.
        """
        ...

    def is_c2(self, ip_address: str) -> bool:
        """Helper: True nếu IP được đánh giá là C2 server."""
        result = self.lookup(ip_address)
        return result.is_c2


class BaseAssetDB(ABC):
    """
    Interface cho Asset Criticality lookup (CMDB).
    
    Implement class này để tích hợp với:
    - MockAssetDB         : đọc từ mock_asset_db.json
    - ServiceNowCMDB      : gọi ServiceNow API
    - LansweepAssetDB     : gọi Lansweeper API
    """

    @abstractmethod
    def lookup(self, hostname: str) -> AssetCriticality:
        """
        Tra cứu mức độ quan trọng của một asset/host.
        
        Args:
            hostname: Tên máy cần tra cứu
            
        Returns:
            AssetCriticality enum: critical | normal | low
        """
        ...

    @abstractmethod
    def get_asset_info(self, hostname: str) -> Optional[dict]:
        """
        Lấy toàn bộ thông tin của asset (owner, department, OS...).
        
        Args:
            hostname: Tên máy cần tra cứu
            
        Returns:
            Dict với asset metadata, hoặc None nếu không tìm thấy
        """
        ...
