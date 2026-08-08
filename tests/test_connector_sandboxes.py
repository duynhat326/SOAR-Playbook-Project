from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import actions.block_ip as block_ip_action
import actions.isolate_host as isolate_host_action
import actions.kill_process as kill_process_action
from alert_generator.generator import generate_alert
from enrichment.asset_db import MockAssetDB
from enrichment.hash_intel import MockHashIntel
from enrichment.ip_intel import MockIPIntel
from enrichment.mitre_mapping import MITREMapper
from enrichment.pipeline import EnrichmentPipeline
from integrations.actions.providers import LocalActionConnector, build_action_connector_from_env
from integrations.cmdb.providers import build_cmdb_connector_from_env
from integrations.intel.providers import build_threat_intel_connector_from_env
from integrations.ticketing.providers import build_ticketing_connector_from_env


def _build_enriched_alert():
    alert = generate_alert(scenario="mixed", seed=6161)
    pipeline = EnrichmentPipeline(
        hash_intel=MockHashIntel(),
        ip_intel=MockIPIntel(),
        asset_db=MockAssetDB(),
        mitre_mapper=MITREMapper(),
        verbose=False,
    )
    return pipeline.run(alert)


@contextmanager
def _http_capture_server(
    *,
    get_payloads: dict[str, tuple[int, dict[str, Any]]] | None = None,
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def _write_json(self, status_code: int, payload: dict[str, Any]) -> None:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            requests.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                }
            )
            payloads = get_payloads or {}
            response = payloads.get(self.path)
            if response is None:
                self._write_json(404, {"error": "not_found"})
                return
            status_code, body = response
            self._write_json(status_code, body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
            parsed_body = json.loads(body) if body else {}
            requests.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "body": parsed_body,
                }
            )
            self._write_json(202, {"ok": True})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        yield base_url, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_local_action_connector_sandbox_writes_expected_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("SOAR_ACTION_PROVIDER", "local")
    monkeypatch.setattr(isolate_host_action, "_ISOLATION_LOG", tmp_path / "isolated_hosts.json")
    monkeypatch.setattr(kill_process_action, "_KILL_LOG", tmp_path / "killed_processes.json")
    monkeypatch.setattr(block_ip_action, "_BLOCK_LOG", tmp_path / "blocked_ips.json")

    connector = build_action_connector_from_env()

    isolate_result = connector.isolate_host(
        hostname="WS-SANDBOX-01",
        alert_id="sandbox-action-001",
        reason="Malicious hash detected",
        operator="sandbox-tester",
    )
    kill_result = connector.kill_process(
        process_name="mimikatz.exe",
        hostname="WS-SANDBOX-01",
        alert_id="sandbox-action-001",
        command_line="mimikatz.exe sekurlsa::logonpasswords",
        reason="Dangerous process detected",
        operator="sandbox-tester",
    )
    block_result = connector.block_ip(
        ip_address="185.220.101.45",
        alert_id="sandbox-action-001",
        hostname="WS-SANDBOX-01",
        reason="C2 communication detected",
        confidence=100,
        operator="sandbox-tester",
    )
    notify_result = connector.notify_soc(
        alert_id="sandbox-action-001",
        hostname="WS-SANDBOX-01",
        risk_score=92.5,
        risk_level="critical",
        triggered_actions=["isolate_host", "block_ip"],
        ticket_id="INC-SANDBOX-0001",
        operator="sandbox-tester",
    )
    escalate_result = connector.escalate(
        hostname="WS-SANDBOX-01",
        reason="Critical asset requires analyst review",
        operator="sandbox-tester",
    )

    isolated = json.loads((tmp_path / "isolated_hosts.json").read_text(encoding="utf-8"))
    killed = json.loads((tmp_path / "killed_processes.json").read_text(encoding="utf-8"))
    blocked = json.loads((tmp_path / "blocked_ips.json").read_text(encoding="utf-8"))

    assert isinstance(connector, LocalActionConnector)
    assert isolate_result.status.value == "succeeded"
    assert kill_result.status.value == "succeeded"
    assert block_result.status.value == "succeeded"
    assert notify_result.status.value == "succeeded"
    assert escalate_result.status.value == "succeeded"
    assert isolated[-1]["hostname"] == "WS-SANDBOX-01"
    assert killed[-1]["process_name"] == "mimikatz.exe"
    assert blocked[-1]["ip_address"] == "185.220.101.45"
    assert "INC-SANDBOX-0001" in notify_result.details
    assert "WS-SANDBOX-01" in escalate_result.details


def test_ticketing_connector_json_sandbox_persists_ticket_comments_and_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SOAR_TICKETING_CONNECTOR", "local")
    monkeypatch.setenv("SOAR_TICKETING_PROVIDER", "json")
    monkeypatch.setenv("SOAR_TICKETING_JSON_PATH", str(tmp_path / "tickets.json"))

    connector = build_ticketing_connector_from_env()
    enriched_alert = _build_enriched_alert()

    result, ticket_id = connector.create_ticket(
        enriched_alert=enriched_alert,
        triggered_actions=["isolate_host", "create_ticket", "notify_soc"],
        risk_score=enriched_alert.risk_score,
        risk_level=enriched_alert.risk_level,
        operator="sandbox-tester",
    )
    connector.append_case_comment(
        ticket_id=ticket_id,
        comment="Sandbox validation comment.",
        author="sandbox-tester",
        metadata={"category": "sandbox.comment"},
    )
    connector.sync_case_state(
        ticket_id=ticket_id,
        case_status="in_progress",
        case_owner="SOC Sandbox",
        comment="Sandbox state sync.",
        actor="sandbox-tester",
        metadata={"category": "sandbox.sync"},
    )

    stored = json.loads((tmp_path / "tickets.json").read_text(encoding="utf-8"))
    ticket = next(item for item in stored if item["ticket_id"] == ticket_id)

    assert result.status.value == "succeeded"
    assert ticket["provider"] == "json"
    assert ticket["comments"][-1]["comment"] == "Sandbox validation comment."
    assert ticket["comments"][-1]["metadata"]["category"] == "sandbox.comment"
    assert ticket["status"] == "in_progress"
    assert ticket["owner"] == "SOC Sandbox"
    assert ticket["sync_history"][-1]["metadata"]["category"] == "sandbox.sync"


def test_ticketing_connector_webhook_sandbox_emits_expected_events(monkeypatch):
    with _http_capture_server() as (base_url, requests):
        monkeypatch.setenv("SOAR_TICKETING_CONNECTOR", "local")
        monkeypatch.setenv("SOAR_TICKETING_PROVIDER", "webhook")
        monkeypatch.setenv("SOAR_TICKETING_WEBHOOK_URL", f"{base_url}/ticket-events")
        monkeypatch.setenv("SOAR_TICKETING_WEBHOOK_TOKEN", "sandbox-token")

        connector = build_ticketing_connector_from_env()
        enriched_alert = _build_enriched_alert()

        _, ticket_id = connector.create_ticket(
            enriched_alert=enriched_alert,
            triggered_actions=["create_ticket", "notify_soc"],
            risk_score=enriched_alert.risk_score,
            risk_level=enriched_alert.risk_level,
            operator="sandbox-tester",
        )
        connector.append_case_comment(
            ticket_id=ticket_id,
            comment="Webhook sandbox comment.",
            author="sandbox-tester",
            metadata={"category": "sandbox.comment"},
        )
        connector.sync_case_state(
            ticket_id=ticket_id,
            case_status="triaged",
            case_owner="SOC Sandbox",
            comment="Webhook sandbox state sync.",
            actor="sandbox-tester",
            metadata={"category": "sandbox.sync"},
        )

    assert [item["body"]["event_type"] for item in requests] == [
        "ticket.created",
        "ticket.comment_added",
        "ticket.state_synced",
    ]
    assert all(item["headers"]["authorization"] == "Bearer sandbox-token" for item in requests)
    assert requests[0]["body"]["payload"]["ticket_id"] == ticket_id
    assert requests[1]["body"]["payload"]["comment"]["metadata"]["category"] == "sandbox.comment"
    assert requests[2]["body"]["payload"]["update"]["case_status"] == "triaged"


def test_cmdb_connector_http_sandbox_returns_asset_metadata(monkeypatch):
    with _http_capture_server(
        get_payloads={
            "/assets/WS-FINANCE-01": (
                200,
                {
                    "asset": {
                        "criticality": "critical",
                        "asset_type": "Finance Workstation",
                        "owner": "cfo@company.com",
                    }
                },
            )
        }
    ) as (base_url, requests):
        monkeypatch.setenv("SOAR_ASSET_PROVIDER", "http")
        monkeypatch.setenv("SOAR_ASSET_API_URL", base_url)
        monkeypatch.setenv("SOAR_ASSET_API_TOKEN", "cmdb-sandbox-token")

        connector = build_cmdb_connector_from_env()
        criticality = connector.lookup_criticality("WS-FINANCE-01")
        asset_info = connector.get_asset_info("WS-FINANCE-01")

    assert criticality.value == "critical"
    assert asset_info is not None
    assert asset_info["owner"] == "cfo@company.com"
    assert requests[0]["headers"]["authorization"] == "Bearer cmdb-sandbox-token"
    assert requests[0]["path"] == "/assets/WS-FINANCE-01"


def test_threat_intel_connector_mock_sandbox_resolves_sanitized_indicators(monkeypatch):
    monkeypatch.setenv("SOAR_INTEL_PROVIDER", "mock")
    connector = build_threat_intel_connector_from_env()

    hash_enrichment = connector.lookup_hash(
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    )
    ip_enrichment = connector.lookup_ip("185.220.101.45")

    assert hash_enrichment.reputation.value == "malicious"
    assert hash_enrichment.threat_name == "Trojan.GenericKD.48756123"
    assert ip_enrichment.reputation.value == "malicious"
    assert ip_enrichment.is_c2 is True
