"""
actions/ticketing.py
====================
Mock action: Tạo incident ticket trong ticketing system.

Trong thực tế, có thể integrate với:
  - Jira Service Management (REST API)
  - TheHive (Case Management)
  - ServiceNow Incident Management

Ở đây: tạo ticket JSON và ghi vào file (mock ticket DB).
Ticket ID format: INC-YYYYMMDD-XXXX
"""

import json
import random
import string
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from loguru import logger

from schemas.alert import ActionResult, EnrichedAlert, ResponseAction

_TICKET_DB = Path("output") / "tickets.json"


def execute(
    enriched_alert: EnrichedAlert,
    triggered_actions: List[str],
    risk_score: float,
    risk_level: str,
    operator: str = "SOAR_AUTO",
) -> ActionResult:
    """
    Tạo incident ticket (mock).

    Args:
        enriched_alert    : Alert đã được enrich
        triggered_actions : List tên action đã thực hiện
        risk_score        : Điểm rủi ro (để set ticket priority)
        risk_level        : Mức rủi ro (low/medium/high/critical)
        operator          : Người tạo ticket

    Returns:
        ActionResult chứa ticket_id trong details
    """
    alert = enriched_alert.original_alert
    ticket_id = _generate_ticket_id()

    # Map risk level → ticket priority
    priority_map = {
        "critical": "P1 - Critical",
        "high":     "P2 - High",
        "medium":   "P3 - Medium",
        "low":      "P4 - Low",
    }
    priority = priority_map.get(risk_level, "P3 - Medium")

    logger.info(
        f"[ACTION] 🎫 CREATE TICKET: {ticket_id} | "
        f"priority={priority} | alert={alert.alert_id[:8]}"
    )

    # Build ticket payload (giống structure của TheHive Case)
    ticket = {
        "ticket_id"  : ticket_id,
        "title"      : f"[{risk_level.upper()}] Malware Alert on {alert.hostname} — {alert.detection_name}",
        "priority"   : priority,
        "status"     : "Open",
        "alert_id"   : alert.alert_id,
        "hostname"   : alert.hostname,
        "username"   : alert.username,
        "detection"  : alert.detection_name,
        "severity"   : alert.severity.value,
        "risk_score" : round(risk_score, 1),
        "risk_level" : risk_level,
        "iocs": {
            "file_hash"      : alert.file_hash,
            "process_name"   : alert.process_name,
            "destination_ip" : alert.destination_ip,
            "file_path"      : alert.file_path,
        },
        "enrichment": {
            "hash_reputation" : (
                enriched_alert.hash_enrichment.reputation.value
                if enriched_alert.hash_enrichment else "unknown"
            ),
            "ip_is_c2"        : (
                enriched_alert.ip_enrichment.is_c2
                if enriched_alert.ip_enrichment else False
            ),
            "asset_criticality": enriched_alert.asset_criticality.value,
            "mitre_techniques" : [
                m.technique_id for m in enriched_alert.mitre_mappings
            ],
        },
        "actions_taken"  : triggered_actions,
        "created_by"     : operator,
        "created_at"     : datetime.utcnow().isoformat() + "Z",
        "sla_deadline"   : _calculate_sla(risk_level),
        "mock"           : True,
    }

    _save_ticket(ticket)

    details = (
        f"Ticket [{ticket_id}] created with priority {priority}. "
        f"SLA deadline: {ticket['sla_deadline']}. "
        f"Assignee: SOC-Team."
    )

    logger.success(f"[ACTION] ✓ Ticket {ticket_id} created (mock)")

    return ActionResult(
        action=ResponseAction.CREATE_TICKET,
        status="success",
        executed_at=datetime.utcnow(),
        details=details,
    ), ticket_id


def _generate_ticket_id() -> str:
    """Sinh Ticket ID format: INC-YYYYMMDD-XXXX"""
    date_str = datetime.utcnow().strftime("%Y%m%d")
    suffix = "".join(random.choices(string.digits, k=4))
    return f"INC-{date_str}-{suffix}"


def _calculate_sla(risk_level: str) -> str:
    """
    Tính SLA deadline dựa trên mức rủi ro.
    
    P1 Critical → 1 giờ
    P2 High     → 4 giờ
    P3 Medium   → 24 giờ
    P4 Low      → 72 giờ
    """
    from datetime import timedelta
    sla_hours = {"critical": 1, "high": 4, "medium": 24, "low": 72}
    hours = sla_hours.get(risk_level, 24)
    deadline = datetime.utcnow() + timedelta(hours=hours)
    return deadline.strftime("%Y-%m-%dT%H:%M:%SZ") + f" (+{hours}h)"


def _save_ticket(ticket: dict) -> None:
    """Ghi ticket vào mock ticket DB (JSON file)."""
    _TICKET_DB.parent.mkdir(parents=True, exist_ok=True)

    existing: list = []
    if _TICKET_DB.exists():
        try:
            with open(_TICKET_DB, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []

    existing.append(ticket)

    with open(_TICKET_DB, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
