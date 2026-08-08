from __future__ import annotations

import os

import actions.ticketing as ticketing_action

from env_utils import load_local_env_files
from integrations.contracts import TicketingConnector
from schemas.alert import ActionResult, EnrichedAlert


class LocalTicketingConnector(TicketingConnector):
    """Default ticketing connector backed by the local JSON/webhook adapter flow."""

    def create_ticket(
        self,
        *,
        enriched_alert: EnrichedAlert,
        triggered_actions,
        risk_score: float,
        risk_level: str,
        operator: str = "SOAR_AUTO",
    ) -> tuple[ActionResult, str]:
        return ticketing_action.execute(
            enriched_alert=enriched_alert,
            triggered_actions=list(triggered_actions),
            risk_score=risk_score,
            risk_level=risk_level,
            operator=operator,
        )

    def append_case_comment(
        self,
        *,
        ticket_id: str,
        comment: str,
        author: str = "SOAR_AUTO",
        metadata: dict | None = None,
    ) -> ActionResult | None:
        ticketing_action.append_comment(
            ticket_id=ticket_id,
            comment=comment,
            author=author,
            metadata=metadata,
        )
        return None

    def sync_case_state(
        self,
        *,
        ticket_id: str,
        case_status: str,
        case_owner: str | None = None,
        comment: str | None = None,
        actor: str = "SOAR_AUTO",
        metadata: dict | None = None,
    ) -> ActionResult | None:
        ticketing_action.sync_state(
            ticket_id=ticket_id,
            case_status=case_status,
            case_owner=case_owner,
            comment=comment,
            actor=actor,
            metadata=metadata,
        )
        return None


def build_ticketing_connector_from_env() -> TicketingConnector:
    load_local_env_files()
    provider = os.getenv("SOAR_TICKETING_CONNECTOR", "local").strip().lower()
    if provider in {"", "local", "mock"}:
        return LocalTicketingConnector()
    raise RuntimeError(f"Unsupported ticketing connector '{provider}'.")
