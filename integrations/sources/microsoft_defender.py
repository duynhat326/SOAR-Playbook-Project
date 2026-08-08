from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from integrations.contracts import SourceConnector
from integrations.sources._common import basename, first_present, normalize_hostname, normalize_username, require_string
from schemas.alert import MalwareAlert, Severity


class MicrosoftDefenderSourceConnector(SourceConnector):
    """Normalize Microsoft Defender XDR style alerts into the canonical malware alert schema."""

    def normalize_alert(self, payload: Mapping[str, Any]) -> MalwareAlert:
        provider = "Microsoft Defender"
        process_evidence = _find_evidence(payload.get("evidence"), "Process")
        file_evidence = _find_evidence(payload.get("evidence"), "File")
        ip_evidence = _find_evidence(payload.get("evidence"), "Ip")

        process_name = require_string(
            provider,
            "process name",
            first_present(process_evidence, "fileName", "processName"),
        )
        file_path = require_string(
            provider,
            "file path",
            first_present(file_evidence, "filePath", "folderPath"),
        )
        file_hash = require_string(
            provider,
            "file hash",
            first_present(file_evidence, "sha256", "fileHashes.sha256", "fileDetails.sha256"),
        )
        parent_process = require_string(
            provider,
            "parent process",
            first_present(process_evidence, "parentProcessFileName", "parentProcessName"),
        )
        destination_ip = require_string(
            provider,
            "destination IP",
            first_present(ip_evidence, "ipAddress", "address"),
        )
        username = require_string(
            provider,
            "username",
            first_present(payload, "userStates.0.accountName", "loggedOnUsers.0.accountName"),
        )
        hostname = require_string(
            provider,
            "device hostname",
            first_present(payload, "machine.computerDnsName", "deviceDnsName", "machine.name"),
        )
        alert_id = require_string(provider, "alert ID", first_present(payload, "alertId", "id"))
        title = require_string(provider, "alert title", first_present(payload, "title"))
        severity = require_string(provider, "severity", first_present(payload, "severity"))
        created_time = require_string(
            provider,
            "created timestamp",
            first_present(payload, "createdTime", "alertCreationTime"),
        )
        command_line = require_string(
            provider,
            "process command line",
            first_present(process_evidence, "processCommandLine", "commandLine"),
        )

        return MalwareAlert(
            alert_id=alert_id,
            hostname=normalize_hostname(hostname),
            username=normalize_username(username),
            process_name=basename(process_name),
            file_path=file_path,
            file_hash=file_hash.lower(),
            parent_process=basename(parent_process),
            command_line=command_line,
            destination_ip=destination_ip,
            severity=_severity_from_string(severity),
            detection_name=f"Microsoft Defender: {title}",
            received_at=created_time,
        )


def _find_evidence(raw_evidence: Any, entity_type: str) -> Mapping[str, Any]:
    if not isinstance(raw_evidence, Sequence) or isinstance(raw_evidence, (str, bytes, bytearray)):
        raise ValueError("Microsoft Defender payload missing evidence records.")
    normalized_type = entity_type.casefold()
    for item in raw_evidence:
        if not isinstance(item, Mapping):
            continue
        current_type = str(item.get("entityType") or "").casefold()
        if current_type == normalized_type:
            return item
    raise ValueError(f"Microsoft Defender payload missing '{entity_type}' evidence.")


def _severity_from_string(raw_value: str) -> Severity:
    normalized = raw_value.strip().lower()
    mapping = {
        "informational": Severity.LOW,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    try:
        return mapping[normalized]
    except KeyError as exc:
        raise ValueError(f"Unsupported Microsoft Defender severity '{raw_value}'.") from exc
