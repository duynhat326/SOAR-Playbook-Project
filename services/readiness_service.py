from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from env_utils import load_local_env_files


def build_readiness_report(*, repository: Any) -> dict[str, Any]:
    """Summarize whether configured local dependencies are usable."""

    load_local_env_files()

    intel_provider = os.getenv("SOAR_INTEL_PROVIDER", "mock").strip().lower() or "mock"
    asset_provider = os.getenv("SOAR_ASSET_PROVIDER", "mock").strip().lower() or "mock"
    ticket_provider = os.getenv("SOAR_TICKETING_PROVIDER", "json").strip().lower() or "json"
    queue_mode = os.getenv("SOAR_POLICY_EXECUTION_MODE", "sync").strip().lower() or "sync"

    dependencies: list[dict[str, Any]] = []

    db_target = str(getattr(repository, "db_path", "unknown"))
    dependencies.append(
        {
            "name": "incident_repository",
            "provider": "sqlite" if db_target.endswith(".db") else "postgres",
            "status": "ready",
            "detail": f"Persistence target is '{db_target}'.",
            "meta": {"db_target": db_target},
        }
    )

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if intel_provider == "virustotal":
        dependencies.append(
            {
                "name": "threat_intel",
                "provider": intel_provider,
                "status": "ready" if vt_key else "degraded",
                "detail": (
                    "VirusTotal provider is configured."
                    if vt_key
                    else "VirusTotal provider selected but VIRUSTOTAL_API_KEY is missing."
                ),
                "meta": {"api_key_present": bool(vt_key)},
            }
        )
    else:
        dependencies.append(
            {
                "name": "threat_intel",
                "provider": intel_provider,
                "status": "ready",
                "detail": f"Threat intel provider '{intel_provider}' is available.",
                "meta": {},
            }
        )

    if asset_provider == "file":
        asset_path = Path(os.getenv("SOAR_ASSET_DB_PATH", "data/mock_asset_db.json"))
        asset_exists = asset_path.exists()
        dependencies.append(
            {
                "name": "asset_cmdb",
                "provider": asset_provider,
                "status": "ready" if asset_exists else "degraded",
                "detail": (
                    f"Asset provider is reading '{asset_path}'."
                    if asset_exists
                    else f"Configured asset file '{asset_path}' was not found."
                ),
                "meta": {"path": str(asset_path)},
            }
        )
    elif asset_provider == "http":
        asset_url = os.getenv("SOAR_ASSET_API_URL", "").strip()
        dependencies.append(
            {
                "name": "asset_cmdb",
                "provider": asset_provider,
                "status": "ready" if asset_url else "degraded",
                "detail": (
                    f"HTTP CMDB endpoint configured at '{asset_url}'."
                    if asset_url
                    else "SOAR_ASSET_API_URL is required for the HTTP CMDB provider."
                ),
                "meta": {"url": asset_url},
            }
        )
    else:
        dependencies.append(
            {
                "name": "asset_cmdb",
                "provider": asset_provider,
                "status": "ready",
                "detail": "Mock CMDB provider is available for local simulation.",
                "meta": {},
            }
        )

    if ticket_provider == "webhook":
        ticket_url = os.getenv("SOAR_TICKETING_WEBHOOK_URL", "").strip()
        dependencies.append(
            {
                "name": "ticketing",
                "provider": ticket_provider,
                "status": "ready" if ticket_url else "degraded",
                "detail": (
                    f"Webhook ticketing is configured at '{ticket_url}'."
                    if ticket_url
                    else "SOAR_TICKETING_WEBHOOK_URL is required for webhook ticketing."
                ),
                "meta": {"url": ticket_url},
            }
        )
    else:
        ticket_path = Path(os.getenv("SOAR_TICKETING_JSON_PATH", str(Path("output") / "tickets.json")))
        dependencies.append(
            {
                "name": "ticketing",
                "provider": ticket_provider,
                "status": "ready",
                "detail": f"JSON ticket store is available at '{ticket_path}'.",
                "meta": {"path": str(ticket_path)},
            }
        )

    queue_metrics = repository.get_queue_metrics() if hasattr(repository, "get_queue_metrics") else {}
    dependencies.append(
        {
            "name": "remediation_queue",
            "provider": queue_mode,
            "status": "ready",
            "detail": (
                "Queue-backed remediation is enabled."
                if queue_mode == "queued"
                else "Synchronous remediation is enabled."
            ),
            "meta": queue_metrics,
        }
    )

    overall_status = "ready" if all(dep["status"] == "ready" for dep in dependencies) else "degraded"
    return {
        "status": overall_status,
        "dependencies": dependencies,
        "queue_metrics": queue_metrics,
    }
