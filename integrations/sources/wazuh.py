from __future__ import annotations

from typing import Any, Mapping

from integrations.contracts import SourceConnector
from integrations.sources._common import (
    basename,
    first_present,
    normalize_hostname,
    normalize_username,
    require_string,
)
from schemas.alert import MalwareAlert, Severity


class WazuhSourceConnector(SourceConnector):
    """Normalize Wazuh event payloads into the canonical malware alert schema."""

    def normalize_alert(self, payload: Mapping[str, Any]) -> MalwareAlert:
        provider = "Wazuh"
        process_path = require_string(
            provider,
            "process image",
            first_present(payload, "data.win.eventdata.image", "data.win.eventdata.processPath"),
        )
        parent_path = require_string(
            provider,
            "parent process image",
            first_present(
                payload,
                "data.win.eventdata.parentImage",
                "data.win.eventdata.parentProcessName",
            ),
        )
        hashes = require_string(provider, "event hashes", first_present(payload, "data.win.eventdata.hashes"))
        destination_ip = require_string(
            provider,
            "destination IP",
            first_present(payload, "data.win.eventdata.destinationIp", "data.win.eventdata.destination.ip"),
        )
        username = require_string(
            provider,
            "username",
            first_present(payload, "data.win.eventdata.user", "data.win.eventdata.targetUserName"),
        )
        hostname = require_string(provider, "agent hostname", first_present(payload, "agent.name"))
        alert_id = require_string(provider, "alert ID", first_present(payload, "id"))
        timestamp = require_string(
            provider,
            "timestamp",
            first_present(payload, "timestamp", "data.win.system.systemTime"),
        )
        command_line = require_string(
            provider,
            "command line",
            first_present(payload, "data.win.eventdata.commandLine", "full_log"),
        )
        description = require_string(provider, "rule description", first_present(payload, "rule.description"))
        level = int(require_string(provider, "rule level", first_present(payload, "rule.level")))

        return MalwareAlert(
            alert_id=alert_id,
            hostname=normalize_hostname(hostname),
            username=normalize_username(username),
            process_name=basename(process_path),
            file_path=process_path,
            file_hash=_extract_preferred_hash(hashes),
            parent_process=basename(parent_path),
            command_line=command_line,
            destination_ip=destination_ip,
            severity=_severity_from_level(level),
            detection_name=f"Wazuh: {description}",
            received_at=timestamp,
        )


def _extract_preferred_hash(raw_hashes: str) -> str:
    values: dict[str, str] = {}
    for chunk in raw_hashes.replace(",", ";").split(";"):
        name, separator, value = chunk.partition("=")
        if not separator:
            continue
        key = name.strip().upper()
        candidate = value.strip().lower()
        if candidate:
            values[key] = candidate
    for algorithm in ("SHA256", "SHA1", "MD5"):
        if algorithm in values:
            return values[algorithm]
    raise ValueError("Wazuh payload missing a supported MD5, SHA1, or SHA256 hash.")


def _severity_from_level(level: int) -> Severity:
    if level >= 14:
        return Severity.CRITICAL
    if level >= 11:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    return Severity.LOW
