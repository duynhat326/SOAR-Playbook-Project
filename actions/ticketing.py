"""
actions/ticketing.py
====================
Ticketing action with pluggable local JSON or webhook adapters.
"""

from __future__ import annotations

import json
import os
import random
import string
from abc import ABC, abstractmethod
from datetime import timedelta
from pathlib import Path
from typing import List, Optional
from urllib import error, request

from loguru import logger

from env_utils import load_local_env_files
from schemas.alert import ActionResult, EnrichedAlert, ResponseAction
from time_utils import utc_isoformat_z, utc_now

_TICKET_DB = Path("output") / "tickets.json"


class BaseTicketingAdapter(ABC):
    @abstractmethod
    def create_ticket(self, ticket: dict) -> None:
        """Persist or publish the ticket payload."""


class JsonTicketingAdapter(BaseTicketingAdapter):
    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or Path(os.getenv("SOAR_TICKETING_JSON_PATH", str(_TICKET_DB)))

    def create_ticket(self, ticket: dict) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        existing: list = []
        if self._db_path.exists():
            try:
                with self._db_path.open("r", encoding="utf-8") as handle:
                    existing = json.load(handle)
            except (json.JSONDecodeError, IOError):
                existing = []

        existing.append(ticket)

        with self._db_path.open("w", encoding="utf-8") as handle:
            json.dump(existing, handle, indent=2, ensure_ascii=False)


class WebhookTicketingAdapter(BaseTicketingAdapter):
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        *,
        token: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        load_local_env_files()
        self._webhook_url = (webhook_url or os.getenv("SOAR_TICKETING_WEBHOOK_URL", "")).strip()
        self._token = (token or os.getenv("SOAR_TICKETING_WEBHOOK_TOKEN", "")).strip()
        self._timeout = timeout
        if not self._webhook_url:
            raise RuntimeError("SOAR_TICKETING_WEBHOOK_URL is required for webhook ticketing.")

    def create_ticket(self, ticket: dict) -> None:
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"

        http_request = request.Request(
            self._webhook_url,
            data=json.dumps(ticket, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=self._timeout):
                return
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ticket webhook failed with HTTP {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ticket webhook failed: {exc.reason}") from exc


def build_ticketing_adapter() -> BaseTicketingAdapter:
    load_local_env_files()
    provider = os.getenv("SOAR_TICKETING_PROVIDER", "json").strip().lower()
    if provider == "webhook":
        return WebhookTicketingAdapter()
    return JsonTicketingAdapter()


def execute(
    enriched_alert: EnrichedAlert,
    triggered_actions: List[str],
    risk_score: float,
    risk_level: str,
    operator: str = "SOAR_AUTO",
) -> ActionResult:
    """Create a case ticket through the configured adapter."""

    alert = enriched_alert.original_alert
    ticket_id = _generate_ticket_id()

    priority_map = {
        "critical": "P1 - Critical",
        "high": "P2 - High",
        "medium": "P3 - Medium",
        "low": "P4 - Low",
    }
    priority = priority_map.get(risk_level, "P3 - Medium")

    provider = os.getenv("SOAR_TICKETING_PROVIDER", "json").strip().lower() or "json"
    adapter = build_ticketing_adapter()

    logger.info(
        f"[ACTION] CREATE TICKET: {ticket_id} | provider={provider} | "
        f"priority={priority} | alert={alert.alert_id[:8]}"
    )

    ticket = {
        "ticket_id": ticket_id,
        "title": f"[{risk_level.upper()}] Malware Alert on {alert.hostname} - {alert.detection_name}",
        "priority": priority,
        "status": "Open",
        "alert_id": alert.alert_id,
        "hostname": alert.hostname,
        "username": alert.username,
        "detection": alert.detection_name,
        "severity": alert.severity.value,
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "iocs": {
            "file_hash": alert.file_hash,
            "process_name": alert.process_name,
            "destination_ip": alert.destination_ip,
            "file_path": alert.file_path,
        },
        "enrichment": {
            "hash_reputation": (
                enriched_alert.hash_enrichment.reputation.value
                if enriched_alert.hash_enrichment
                else "unknown"
            ),
            "ip_is_c2": (
                enriched_alert.ip_enrichment.is_c2
                if enriched_alert.ip_enrichment
                else False
            ),
            "asset_criticality": enriched_alert.asset_criticality.value,
            "asset_info": enriched_alert.asset_info,
            "mitre_techniques": [mapping.technique_id for mapping in enriched_alert.mitre_mappings],
        },
        "actions_taken": triggered_actions,
        "created_by": operator,
        "created_at": utc_isoformat_z(),
        "sla_deadline": _calculate_sla(risk_level),
        "provider": provider,
    }

    adapter.create_ticket(ticket)

    details = (
        f"Ticket [{ticket_id}] created with priority {priority} via {provider}. "
        f"SLA deadline: {ticket['sla_deadline']}. Assignee: SOC-Team."
    )

    return (
        ActionResult(
            action=ResponseAction.CREATE_TICKET,
            status="succeeded",
            executed_at=utc_now(),
            details=details,
            operator=operator,
        ),
        ticket_id,
    )


def _generate_ticket_id() -> str:
    date_str = utc_now().strftime("%Y%m%d")
    suffix = "".join(random.choices(string.digits, k=4))
    return f"INC-{date_str}-{suffix}"


def _calculate_sla(risk_level: str) -> str:
    sla_hours = {"critical": 1, "high": 4, "medium": 24, "low": 72}
    hours = sla_hours.get(risk_level, 24)
    deadline = utc_now() + timedelta(hours=hours)
    return deadline.strftime("%Y-%m-%dT%H:%M:%SZ") + f" (+{hours}h)"
