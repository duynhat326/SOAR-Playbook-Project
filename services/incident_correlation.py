from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional, Protocol, Sequence

from engine.policy_loader import (
    PolicyFingerprintField,
    PolicyIncidentCorrelationConfig,
)
from schemas.alert import (
    CorrelationEvidence,
    CorrelationOutcome,
    EnrichedAlert,
    IncidentCaseStatus,
    IncidentCorrelationTrace,
    MalwareAlert,
)


@dataclass(frozen=True)
class CorrelationFingerprint:
    strategy: str
    fields: tuple[str, ...]
    fingerprint: str
    values: dict[str, str]


@dataclass(frozen=True)
class CorrelationMatch:
    incident_id: int
    incident_key: str
    case_status: str
    related_alert_ids: tuple[str, ...]
    matched_alert_ids: tuple[str, ...]
    strategy: str
    fingerprint: str
    values: dict[str, str]


@dataclass(frozen=True)
class CorrelationResolution:
    enabled: bool
    window: str
    outcome: CorrelationOutcome
    incident_key: str
    matched_incident_id: Optional[int]
    related_alert_ids: tuple[str, ...]
    matched_alert_ids: tuple[str, ...]
    evidence: tuple[CorrelationEvidence, ...]
    fingerprints: tuple[CorrelationFingerprint, ...]

    @property
    def related_alert_count(self) -> int:
        return len(self.related_alert_ids)

    def to_trace(self) -> IncidentCorrelationTrace:
        return IncidentCorrelationTrace(
            enabled=self.enabled,
            window=self.window,
            outcome=self.outcome,
            incident_key=self.incident_key,
            matched_incident_id=self.matched_incident_id,
            matched_alert_ids=list(self.matched_alert_ids),
            related_alert_ids=list(self.related_alert_ids),
            related_alert_count=self.related_alert_count,
            evidence=list(self.evidence),
            candidate_fingerprints=[
                CorrelationEvidence(
                    strategy=fingerprint.strategy,
                    fields=list(fingerprint.fields),
                    fingerprint=fingerprint.fingerprint,
                    values=fingerprint.values,
                    matched_alert_ids=[],
                )
                for fingerprint in self.fingerprints
            ],
        )


class CorrelationLookupProtocol(Protocol):
    def find_correlated_incident(
        self,
        fingerprints: Sequence[CorrelationFingerprint],
        *,
        observed_at: datetime,
        window: timedelta,
        workspace: str,
    ) -> Optional[dict[str, Any]]: ...


class IncidentCorrelationService:
    def __init__(self, config: PolicyIncidentCorrelationConfig) -> None:
        self._config = config

    @property
    def config(self) -> PolicyIncidentCorrelationConfig:
        return self._config

    def resolve(
        self,
        alert: MalwareAlert,
        enriched: EnrichedAlert,
        *,
        repository: CorrelationLookupProtocol | None = None,
    ) -> CorrelationResolution:
        window = self._parse_window(self._config.window)
        fingerprints = tuple(self.build_fingerprints(alert))
        default_key = self._new_incident_key(alert.alert_id)

        if not self._config.enabled or repository is None or not fingerprints:
            return CorrelationResolution(
                enabled=self._config.enabled,
                window=self._config.window,
                outcome=CorrelationOutcome.NEW_INCIDENT,
                incident_key=default_key,
                matched_incident_id=None,
                related_alert_ids=(alert.alert_id,),
                matched_alert_ids=(),
                evidence=(),
                fingerprints=fingerprints,
            )

        match_payload = repository.find_correlated_incident(
            fingerprints,
            observed_at=alert.received_at,
            window=window,
            workspace=alert.workspace,
        )
        if not match_payload:
            return CorrelationResolution(
                enabled=True,
                window=self._config.window,
                outcome=CorrelationOutcome.NEW_INCIDENT,
                incident_key=default_key,
                matched_incident_id=None,
                related_alert_ids=(alert.alert_id,),
                matched_alert_ids=(),
                evidence=(),
                fingerprints=fingerprints,
            )

        match = CorrelationMatch(
            incident_id=int(match_payload["incident_id"]),
            incident_key=str(match_payload["incident_key"]),
            case_status=str(match_payload["case_status"] or IncidentCaseStatus.NEW.value),
            related_alert_ids=tuple(match_payload.get("related_alert_ids") or ()),
            matched_alert_ids=tuple(match_payload.get("matched_alert_ids") or ()),
            strategy=str(match_payload["strategy"]),
            fingerprint=str(match_payload["fingerprint"]),
            values={
                str(key): str(value)
                for key, value in (match_payload.get("values") or {}).items()
            },
        )
        is_reopened = (
            self._config.reopen_closed_incidents
            and match.case_status in {IncidentCaseStatus.CLOSED.value, IncidentCaseStatus.RESOLVED.value}
        )
        related_alert_ids = tuple(dict.fromkeys([*match.related_alert_ids, alert.alert_id]))
        evidence = (
            CorrelationEvidence(
                strategy=match.strategy,
                fields=list(match.values.keys()),
                fingerprint=match.fingerprint,
                values=match.values,
                matched_alert_ids=list(match.matched_alert_ids),
            ),
        )
        return CorrelationResolution(
            enabled=True,
            window=self._config.window,
            outcome=(
                CorrelationOutcome.REOPENED_INCIDENT
                if is_reopened
                else CorrelationOutcome.ATTACHED_TO_EXISTING
            ),
            incident_key=match.incident_key,
            matched_incident_id=match.incident_id,
            related_alert_ids=related_alert_ids,
            matched_alert_ids=match.matched_alert_ids,
            evidence=evidence,
            fingerprints=fingerprints,
        )

    def build_fingerprints(self, alert: MalwareAlert) -> list[CorrelationFingerprint]:
        candidates = {
            PolicyFingerprintField.HOSTNAME: alert.hostname,
            PolicyFingerprintField.USERNAME: alert.username,
            PolicyFingerprintField.FILE_HASH: alert.file_hash,
            PolicyFingerprintField.PROCESS_NAME: alert.process_name,
            PolicyFingerprintField.DESTINATION_IP: alert.destination_ip,
        }
        fingerprints: list[CorrelationFingerprint] = []
        for strategy in self._config.strategies:
            values: dict[str, str] = {}
            for field in strategy.fields:
                raw_value = str(candidates.get(field) or "").strip()
                if not raw_value:
                    values = {}
                    break
                values[field.value] = raw_value.casefold()
            if not values:
                continue
            fingerprint = "|".join(
                [strategy.name, *[f"{name}={values[name]}" for name in values]]
            )
            fingerprints.append(
                CorrelationFingerprint(
                    strategy=strategy.name,
                    fields=tuple(field.value for field in strategy.fields),
                    fingerprint=fingerprint,
                    values=values,
                )
            )
        return fingerprints

    @staticmethod
    def _parse_window(window: str) -> timedelta:
        amount = int(window[:-1])
        unit = window[-1]
        if unit == "m":
            return timedelta(minutes=amount)
        if unit == "h":
            return timedelta(hours=amount)
        if unit == "d":
            return timedelta(days=amount)
        raise ValueError(f"Unsupported correlation window '{window}'")

    @staticmethod
    def _new_incident_key(alert_id: str) -> str:
        return f"incident-{alert_id}"
