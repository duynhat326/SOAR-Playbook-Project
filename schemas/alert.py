"""
schemas/alert.py
================
Định nghĩa toàn bộ Pydantic schema cho dữ liệu đi qua SOAR pipeline.

Gồm 3 lớp chính:
  1. MalwareAlert      — Input schema từ EDR/SIEM (giữ đúng field name theo spec)
  2. EnrichedAlert     — Alert sau khi qua enrichment pipeline
  3. IncidentResponse  — Output cuối cùng sau khi policy engine ra quyết định
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class Severity(str, Enum):
    """Mức độ nghiêm trọng của alert — giữ đúng giá trị lowercase theo spec."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HashReputation(str, Enum):
    """Kết quả kiểm tra hash từ mock threat intel (VirusTotal-like)."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class IPReputation(str, Enum):
    """Kết quả kiểm tra IP từ mock threat intel (AbuseIPDB-like)."""
    MALICIOUS = "malicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class AssetCriticality(str, Enum):
    """Mức độ quan trọng của tài sản (từ mock CMDB)."""
    CRITICAL = "critical"
    NORMAL = "normal"
    LOW = "low"


class ResponseAction(str, Enum):
    """Các hành động phản ứng mà policy engine có thể ra lệnh."""
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    ESCALATE = "escalate"
    CREATE_TICKET = "create_ticket"
    NOTIFY_SOC = "notify_soc"
    NO_ACTION = "no_action"


# ─────────────────────────────────────────────
# Input Schema (từ EDR/SIEM)
# ─────────────────────────────────────────────

class MalwareAlert(BaseModel):
    """
    Schema chuẩn cho alert malware đến từ EDR/SIEM.
    
    QUAN TRỌNG: Tên các field phải giữ nguyên đúng theo spec mục 2,
    không được đổi tên khi parse hoặc lưu trữ.
    """
    alert_id: str = Field(
        ...,
        description="UUID định danh duy nhất cho alert",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
    )
    hostname: str = Field(
        ...,
        description="Tên máy bị ảnh hưởng",
        examples=["DESKTOP-ABC123", "WS-FINANCE-01"]
    )
    username: str = Field(
        ...,
        description="Tên user đang chạy tiến trình",
        examples=["john.doe", "SYSTEM"]
    )
    process_name: str = Field(
        ...,
        description="Tên tiến trình độc hại",
        examples=["powershell.exe", "cmd.exe", "mimikatz.exe"]
    )
    file_path: str = Field(
        ...,
        description="Đường dẫn đầy đủ đến file thực thi",
        examples=["C:\\Users\\john\\AppData\\Local\\Temp\\payload.exe"]
    )
    file_hash: str = Field(
        ...,
        description="SHA256 hash của file",
        examples=["d41d8cd98f00b204e9800998ecf8427e"]
    )
    parent_process: str = Field(
        ...,
        description="Tiến trình cha đã spawn ra process độc hại",
        examples=["explorer.exe", "winword.exe"]
    )
    command_line: str = Field(
        ...,
        description="Command line đầy đủ khi tiến trình được khởi chạy",
        examples=["powershell.exe -enc SGVsbG8gV29ybGQ="]
    )
    destination_ip: str = Field(
        ...,
        description="IP đích mà tiến trình kết nối ra ngoài (IPv4)",
        examples=["185.220.101.45", "10.0.0.1"]
    )
    severity: Severity = Field(
        ...,
        description="Mức độ nghiêm trọng: low | medium | high | critical"
    )
    detection_name: str = Field(
        ...,
        description="Tên detection rule đã kích hoạt",
        examples=["Trojan.Generic", "Malware.Powershell.Encoded"]
    )
    # Timestamp tự động gắn khi alert được nhận vào pipeline
    received_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Thời điểm alert được nhận vào SOAR pipeline (UTC)"
    )

    @field_validator("file_hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        """Kiểm tra sơ bộ độ dài hash (SHA256 = 64 hex chars)."""
        if len(v) not in (32, 40, 64):  # MD5, SHA1, SHA256
            raise ValueError(
                f"Hash '{v}' có độ dài không hợp lệ. "
                f"Mong đợi MD5 (32), SHA1 (40) hoặc SHA256 (64) ký tự hex."
            )
        return v.lower()  # Normalize về lowercase

    @field_validator("destination_ip")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        """Kiểm tra định dạng IPv4 cơ bản."""
        parts = v.split(".")
        if len(parts) != 4:
            raise ValueError(f"IP '{v}' không đúng định dạng IPv4.")
        for part in parts:
            if not part.isdigit() or not (0 <= int(part) <= 255):
                raise ValueError(f"IP '{v}' không đúng định dạng IPv4.")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "hostname": "DESKTOP-FIN01",
                "username": "jane.smith",
                "process_name": "powershell.exe",
                "file_path": "C:\\Windows\\Temp\\beacon.ps1",
                "file_hash": "a" * 64,
                "parent_process": "winword.exe",
                "command_line": "powershell.exe -enc SGVsbG8=",
                "destination_ip": "185.220.101.45",
                "severity": "high",
                "detection_name": "Malware.Powershell.Encoded"
            }
        }


# ─────────────────────────────────────────────
# Enrichment Result Schemas
# ─────────────────────────────────────────────

class HashEnrichment(BaseModel):
    """Kết quả enrichment hash từ mock VirusTotal-like service."""
    hash_value: str
    reputation: HashReputation
    malicious_vendors: int = Field(
        default=0,
        description="Số vendor phát hiện là malicious"
    )
    total_vendors: int = Field(
        default=0,
        description="Tổng số vendor scan"
    )
    threat_name: Optional[str] = Field(
        default=None,
        description="Tên threat (nếu malicious)"
    )
    source: str = Field(
        default="mock_vt",
        description="Nguồn enrichment (để dễ swap sang API thật)"
    )


class IPEnrichment(BaseModel):
    """Kết quả enrichment IP từ mock AbuseIPDB-like service."""
    ip_address: str
    reputation: IPReputation
    confidence_score: int = Field(
        default=0,
        ge=0, le=100,
        description="Confidence score 0-100 (100 = chắc chắn malicious)"
    )
    is_c2: bool = Field(
        default=False,
        description="Có phải là C2 server không"
    )
    country: Optional[str] = Field(
        default=None,
        description="Quốc gia của IP"
    )
    isp: Optional[str] = Field(
        default=None,
        description="ISP của IP"
    )
    source: str = Field(
        default="mock_abuseipdb",
        description="Nguồn enrichment"
    )


class MITREMapping(BaseModel):
    """Kết quả mapping hành vi sang MITRE ATT&CK framework."""
    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK Technique ID",
        examples=["T1059.001", "T1055"]
    )
    technique_name: str = Field(
        ...,
        description="Tên technique",
        examples=["PowerShell", "Process Injection"]
    )
    tactic: str = Field(
        ...,
        description="MITRE Tactic",
        examples=["Execution", "Defense Evasion"]
    )
    matched_pattern: str = Field(
        ...,
        description="Pattern trong alert đã khớp với rule mapping"
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0, le=1.0,
        description="Độ tin cậy của mapping (0.0 - 1.0)"
    )


# ─────────────────────────────────────────────
# Enriched Alert (sau khi qua enrichment pipeline)
# ─────────────────────────────────────────────

class EnrichedAlert(BaseModel):
    """
    Alert sau khi đã qua toàn bộ enrichment pipeline (bước 2-5 của workflow).
    Kế thừa toàn bộ dữ liệu từ MalwareAlert và thêm enrichment results.
    """
    # Dữ liệu gốc từ alert
    original_alert: MalwareAlert

    # Kết quả enrichment
    hash_enrichment: Optional[HashEnrichment] = None
    ip_enrichment: Optional[IPEnrichment] = None
    asset_criticality: AssetCriticality = AssetCriticality.NORMAL
    mitre_mappings: List[MITREMapping] = Field(
        default_factory=list,
        description="Danh sách các MITRE ATT&CK technique được mapping"
    )

    # Risk Score (bước 6)
    risk_score: float = Field(
        default=0.0,
        ge=0.0, le=100.0,
        description="Điểm rủi ro tổng hợp (0-100)"
    )
    risk_level: str = Field(
        default="unknown",
        description="Mức rủi ro: low | medium | high | critical"
    )

    # Enrichment metadata
    enriched_at: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────
# Action Result Schema
# ─────────────────────────────────────────────

class ActionResult(BaseModel):
    """Kết quả thực hiện một action cụ thể (mock)."""
    action: ResponseAction
    status: str = Field(
        ...,
        description="'success' | 'failed' | 'skipped'"
    )
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    details: str = Field(
        default="",
        description="Mô tả chi tiết về action đã thực hiện"
    )


# ─────────────────────────────────────────────
# Incident Response (Output cuối cùng)
# ─────────────────────────────────────────────

class IncidentResponse(BaseModel):
    """
    Output cuối cùng của toàn bộ SOAR pipeline.
    Chứa enriched alert + decisions + action results.
    """
    # Input đã được enrich
    enriched_alert: EnrichedAlert

    # Quyết định từ policy engine
    triggered_actions: List[ResponseAction] = Field(
        default_factory=list,
        description="Danh sách action được policy engine quyết định"
    )
    policy_reasoning: List[str] = Field(
        default_factory=list,
        description="Giải thích tại sao từng action được trigger"
    )

    # Kết quả thực thi action
    action_results: List[ActionResult] = Field(
        default_factory=list,
        description="Kết quả thực thi từng action"
    )

    # Ticket ID (mock)
    ticket_id: Optional[str] = Field(
        default=None,
        description="ID ticket được tạo trong mock ticketing system"
    )

    # Thời gian hoàn tất pipeline
    completed_at: datetime = Field(default_factory=datetime.utcnow)

    # Đường dẫn đến report được sinh ra
    report_path: Optional[str] = Field(
        default=None,
        description="Đường dẫn đến file incident report (Markdown/PDF)"
    )

    @property
    def alert_id(self) -> str:
        """Shortcut lấy alert_id từ nested object."""
        return self.enriched_alert.original_alert.alert_id

    @property
    def hostname(self) -> str:
        """Shortcut lấy hostname."""
        return self.enriched_alert.original_alert.hostname
