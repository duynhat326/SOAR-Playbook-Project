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
from typing import Any, List, Optional
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

    @abstractmethod
    def append_comment(self, ticket_id: str, comment: dict[str, Any]) -> None:
        """Append an analyst or automation comment to the ticket."""

    @abstractmethod
    def sync_state(self, ticket_id: str, update: dict[str, Any]) -> None:
        """Synchronize case state metadata back to the ticket."""


class JsonTicketingAdapter(BaseTicketingAdapter):
    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or Path(os.getenv("SOAR_TICKETING_JSON_PATH", str(_TICKET_DB)))

    def create_ticket(self, ticket: dict) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        existing = self._read_tickets()
        ticket = {
            **ticket,
            "comments": list(ticket.get("comments") or []),
            "sync_history": list(ticket.get("sync_history") or []),
            "updated_at": ticket.get("created_at") or utc_isoformat_z(),
        }
        existing.append(ticket)
        self._write_tickets(existing)

    def append_comment(self, ticket_id: str, comment: dict[str, Any]) -> None:
        tickets = self._read_tickets()
        ticket = self._find_ticket(tickets, ticket_id)
        comments = list(ticket.get("comments") or [])
        comments.append(comment)
        ticket["comments"] = comments
        ticket["updated_at"] = comment.get("created_at") or utc_isoformat_z()
        self._write_tickets(tickets)

    def sync_state(self, ticket_id: str, update: dict[str, Any]) -> None:
        tickets = self._read_tickets()
        ticket = self._find_ticket(tickets, ticket_id)
        if update.get("case_status"):
            ticket["status"] = update["case_status"]
        if "case_owner" in update:
            ticket["owner"] = update["case_owner"]
        history = list(ticket.get("sync_history") or [])
        history.append(update)
        ticket["sync_history"] = history
        ticket["updated_at"] = update.get("updated_at") or utc_isoformat_z()
        self._write_tickets(tickets)

    def _read_tickets(self) -> list[dict[str, Any]]:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        if self._db_path.exists():
            try:
                with self._db_path.open("r", encoding="utf-8") as handle:
                    data = json.load(handle)
                    if isinstance(data, list):
                        return data
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _write_tickets(self, tickets: list[dict[str, Any]]) -> None:
        with self._db_path.open("w", encoding="utf-8") as handle:
            json.dump(tickets, handle, indent=2, ensure_ascii=False)

    @staticmethod
    def _find_ticket(tickets: list[dict[str, Any]], ticket_id: str) -> dict[str, Any]:
        for ticket in tickets:
            if str(ticket.get("ticket_id") or "") == ticket_id:
                return ticket
        raise RuntimeError(f"Ticket '{ticket_id}' was not found in the local ticket store.")


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
        self._post_event("ticket.created", ticket)

    def append_comment(self, ticket_id: str, comment: dict[str, Any]) -> None:
        self._post_event(
            "ticket.comment_added",
            {
                "ticket_id": ticket_id,
                "comment": comment,
            },
        )

    def sync_state(self, ticket_id: str, update: dict[str, Any]) -> None:
        self._post_event(
            "ticket.state_synced",
            {
                "ticket_id": ticket_id,
                "update": update,
            },
        )

    def _post_event(self, event_type: str, payload: dict[str, Any]) -> None:
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"

        http_request = request.Request(
            self._webhook_url,
            data=json.dumps({"event_type": event_type, "payload": payload}, ensure_ascii=False).encode("utf-8"),
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
        "comments": [],
        "sync_history": [],
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


def append_comment(
    *,
    ticket_id: str,
    comment: str,
    author: str = "SOAR_AUTO",
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    adapter = build_ticketing_adapter()
    adapter.append_comment(
        ticket_id,
        {
            "author": author,
            "comment": comment,
            "metadata": metadata or {},
            "created_at": utc_isoformat_z(),
        },
    )


def sync_state(
    *,
    ticket_id: str,
    case_status: str,
    case_owner: Optional[str] = None,
    comment: Optional[str] = None,
    actor: str = "SOAR_AUTO",
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    adapter = build_ticketing_adapter()
    adapter.sync_state(
        ticket_id,
        {
            "case_status": case_status,
            "case_owner": case_owner,
            "comment": comment,
            "actor": actor,
            "metadata": metadata or {},
            "updated_at": utc_isoformat_z(),
        },
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
