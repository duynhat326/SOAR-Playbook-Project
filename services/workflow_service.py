from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from engine.policy_engine import PolicyEngine
from engine.policy_loader import load_policy_config
from enrichment.pipeline import EnrichmentPipeline
from integrations.contracts import SourceConnector, TicketingConnector
from observability import observability
from reporting.report_generator import ReportGenerator
from schemas.alert import EnrichedAlert, IncidentResponse, MalwareAlert
from services.incident_correlation import IncidentCorrelationService
from services.remediation_queue import RepositoryQueuePublisher
from services.readiness_service import build_readiness_report
from storage.incident_repository import (
    IncidentRepositoryProtocol,
    create_incident_repository,
)
from workspace_utils import normalize_workspace


@dataclass
class ReportArtifacts:
    markdown_path: Optional[Path] = None
    html_path: Optional[Path] = None
    pdf_path: Optional[Path] = None
    markdown_content: Optional[str] = None


@dataclass
class WorkflowResult:
    alert: MalwareAlert
    enriched_alert: EnrichedAlert
    response: IncidentResponse
    artifacts: ReportArtifacts
    workspace: str


class SoarWorkflowService:
    """Reusable orchestration layer shared by CLI, dashboard, and API."""

    def __init__(
        self,
        *,
        verbose: bool = False,
        report_output_dir: Optional[Path] = None,
        db_path: Optional[str | Path] = None,
        persist_results: bool = True,
        pipeline: Optional[EnrichmentPipeline] = None,
        policy_engine: Optional[PolicyEngine] = None,
        report_generator: Optional[ReportGenerator] = None,
        repository: Optional[IncidentRepositoryProtocol] = None,
    ) -> None:
        self._pipeline = pipeline or EnrichmentPipeline(verbose=verbose)
        self._queue_publisher: Optional[RepositoryQueuePublisher] = None
        self._ticketing_connector: Optional[TicketingConnector] = None
        if repository is not None:
            self._repository = repository
        elif persist_results:
            resolved_db_path = db_path
            self._repository = create_incident_repository(resolved_db_path)
        else:
            self._repository = None
        if policy_engine is not None:
            self._policy_engine = policy_engine
            self._queue_publisher = self._extract_queue_publisher(policy_engine)
        else:
            queue_publisher = (
                RepositoryQueuePublisher(self._repository)
                if self._repository is not None
                else None
            )
            self._queue_publisher = queue_publisher
            self._policy_engine = PolicyEngine(
                verbose=verbose,
                queue_publisher=queue_publisher,
            )
        self._ticketing_connector = self._extract_ticketing_connector(self._policy_engine)
        if report_generator is not None:
            self._report_generator = report_generator
        elif report_output_dir is not None:
            self._report_generator = ReportGenerator(output_dir=report_output_dir)
        else:
            self._report_generator = ReportGenerator()
        self._correlation_service = IncidentCorrelationService(
            self._resolve_policy_correlation_config(self._policy_engine)
        )

    @property
    def db_path(self) -> str | Path:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.db_path

    def process_alert(
        self,
        alert: MalwareAlert,
        *,
        generate_report: bool = True,
        export_pdf: bool = False,
        include_markdown_content: bool = False,
        workspace: str | None = None,
    ) -> WorkflowResult:
        resolved_workspace = normalize_workspace(workspace or alert.workspace)
        alert = alert.model_copy(update={"workspace": resolved_workspace})
        with observability.trace(
            "workflow.process_alert",
            alert_id=alert.alert_id,
            hostname=alert.hostname,
            detection_name=alert.detection_name,
            workspace=resolved_workspace,
        ):
            if self._repository is not None:
                with observability.span("workflow.lookup_existing_incident"):
                    existing_incident = self._repository.get_incident_by_alert_id(alert.alert_id)
                if existing_incident is not None:
                    observability.metrics.incr("workflow.replay_total")
                    workflow_result = self._workflow_result_from_record(
                        existing_incident,
                        include_markdown_content=include_markdown_content,
                    )
                    return self._ensure_replay_artifacts(
                        workflow_result,
                        generate_report=generate_report,
                        export_pdf=export_pdf,
                        include_markdown_content=include_markdown_content,
                    )

            with observability.span("workflow.enrichment"):
                enriched = self._pipeline.run(alert)
            with observability.span(
                "workflow.policy_evaluation",
                policy_version=getattr(
                    getattr(getattr(self._policy_engine, "policy_config", None), "metadata", None),
                    "version",
                    None,
                ),
            ):
                response = self._policy_engine.evaluate(enriched)
            with observability.span("workflow.correlation"):
                correlation_resolution = self._correlation_service.resolve(
                    alert,
                    enriched,
                    repository=self._repository,
                )
            response.correlation_trace = correlation_resolution.to_trace()
            artifacts = ReportArtifacts()

            if generate_report:
                with observability.span("workflow.report_generation", export_pdf=export_pdf):
                    md_path, html_path, pdf_path = self._report_generator.generate(
                        response,
                        export_pdf=export_pdf,
                    )
                response.report_path = str(html_path)
                artifacts = ReportArtifacts(
                    markdown_path=md_path,
                    html_path=html_path,
                    pdf_path=pdf_path,
                    markdown_content=(
                        md_path.read_text(encoding="utf-8")
                        if include_markdown_content
                        else None
                    ),
                )

            workflow_result = WorkflowResult(
                alert=alert,
                enriched_alert=enriched,
                response=response,
                artifacts=artifacts,
                workspace=resolved_workspace,
            )
            if self._repository is not None:
                with observability.span("workflow.persist_incident"):
                    self._repository.save_workflow_result(workflow_result)
                if self._queue_publisher is not None:
                    with observability.span("workflow.flush_queue"):
                        self._queue_publisher.flush()
            observability.metrics.incr(
                "workflow.processed_total",
                risk_level=enriched.risk_level,
                outcome=response.correlation_trace.outcome.value,
            )
            observability.emit_event(
                "info",
                "workflow.processed",
                message=f"Processed alert {alert.alert_id}",
                alert_id=alert.alert_id,
                incident_key=response.correlation_trace.incident_key,
                policy_version=response.policy_version,
            )
            return workflow_result

    def process_alert_payload(
        self,
        alert_data: dict,
        *,
        generate_report: bool = True,
        export_pdf: bool = False,
        include_markdown_content: bool = False,
        workspace: str | None = None,
    ) -> WorkflowResult:
        alert = MalwareAlert(**alert_data)
        return self.process_alert(
            alert,
            generate_report=generate_report,
            export_pdf=export_pdf,
            include_markdown_content=include_markdown_content,
            workspace=workspace,
        )

    def process_source_payload(
        self,
        payload: Mapping[str, Any],
        *,
        source_connector: SourceConnector,
        generate_report: bool = True,
        export_pdf: bool = False,
        include_markdown_content: bool = False,
        workspace: str | None = None,
    ) -> WorkflowResult:
        alert = source_connector.normalize_alert(payload)
        return self.process_alert(
            alert,
            generate_report=generate_report,
            export_pdf=export_pdf,
            include_markdown_content=include_markdown_content,
            workspace=workspace,
        )

    def get_incident_by_alert_id(self, alert_id: str) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        record = self._repository.get_incident_by_alert_id(alert_id)
        return self._hydrate_incident_record(
            record,
            include_markdown_content=True,
        )

    def get_incident_by_ticket_id(self, ticket_id: str) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        record = self._repository.get_incident_by_ticket_id(ticket_id)
        return self._hydrate_incident_record(
            record,
            include_markdown_content=True,
        )

    def list_incidents(
        self,
        limit: int = 100,
        *,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        hostname: Optional[str] = None,
        ticket_id: Optional[str] = None,
        case_status: Optional[str] = None,
        case_owner: Optional[str] = None,
        workspaces: Optional[list[str] | tuple[str, ...] | frozenset[str]] = None,
    ) -> list[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.list_incidents(
            limit=limit,
            status=status,
            risk_level=risk_level,
            hostname=hostname,
            ticket_id=ticket_id,
            case_status=case_status,
            case_owner=case_owner,
            workspaces=workspaces,
        )

    def get_incident_metrics(self) -> dict[str, Any]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.get_incident_metrics()

    def get_queue_metrics(self) -> dict[str, Any]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.get_queue_metrics()

    def update_incident_case(
        self,
        alert_id: str,
        *,
        case_status: Optional[str] = None,
        case_owner: Optional[str] = None,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        record = self._repository.update_incident_case(
            alert_id,
            case_status=case_status,
            case_owner=case_owner,
            actor=actor,
            comment=comment,
        )
        incident = self._hydrate_incident_record(record, include_markdown_content=True)
        self._sync_ticket_case_state(
            incident,
            actor=actor,
            comment=comment,
            category="case.updated",
        )
        return incident

    def add_incident_note(
        self,
        alert_id: str,
        *,
        author: str,
        body: str,
    ) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        note = self._repository.add_incident_note(alert_id, author=author, body=body)
        if note is not None:
            incident = self._hydrate_incident_record(
                self._repository.get_incident_by_alert_id(alert_id),
                include_markdown_content=False,
            )
            self._append_ticket_comment(
                incident,
                author=author,
                comment=body,
                category="case.note_added",
                extra_metadata={"note_id": note.get("note_id")},
            )
        return note

    def bulk_update_incidents(
        self,
        alert_ids: list[str],
        *,
        case_status: Optional[str] = None,
        case_owner: Optional[str] = None,
        actor: str,
        comment: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        records = self._repository.bulk_update_incidents(
            alert_ids,
            case_status=case_status,
            case_owner=case_owner,
            actor=actor,
            comment=comment,
        )
        incidents = [
            hydrated
            for record in records
            if (hydrated := self._hydrate_incident_record(record, include_markdown_content=False)) is not None
        ]
        for incident in incidents:
            self._sync_ticket_case_state(
                incident,
                actor=actor,
                comment=comment,
                category="case.bulk_updated",
            )
        return incidents

    def approve_action(
        self,
        alert_id: str,
        correlation_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        record = self._repository.approve_action_job(
            alert_id,
            correlation_id,
            actor=actor,
            comment=comment,
        )
        incident = self._hydrate_incident_record(record, include_markdown_content=True)
        self._sync_action_comment(
            incident,
            correlation_id=correlation_id,
            author=actor,
            category="approval.approved",
            fallback_comment=comment,
        )
        return incident

    def reject_action(
        self,
        alert_id: str,
        correlation_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        record = self._repository.reject_action_job(
            alert_id,
            correlation_id,
            actor=actor,
            comment=comment,
        )
        incident = self._hydrate_incident_record(record, include_markdown_content=True)
        self._sync_action_comment(
            incident,
            correlation_id=correlation_id,
            author=actor,
            category="approval.rejected",
            fallback_comment=comment,
        )
        return incident

    def rollback_action(
        self,
        alert_id: str,
        correlation_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        record = self._repository.rollback_action_job(
            alert_id,
            correlation_id,
            actor=actor,
            comment=comment,
        )
        incident = self._hydrate_incident_record(record, include_markdown_content=True)
        self._sync_action_comment(
            incident,
            correlation_id=correlation_id,
            author=actor,
            category="queue.cancelled",
            fallback_comment=comment,
        )
        return incident

    def reopen_incident(
        self,
        alert_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        record = self._repository.reopen_incident(
            alert_id,
            actor=actor,
            comment=comment,
        )
        incident = self._hydrate_incident_record(record, include_markdown_content=True)
        self._sync_ticket_case_state(
            incident,
            actor=actor,
            comment=comment,
            category="case.reopened",
        )
        return incident

    def escalate_overdue_approvals(
        self,
        *,
        actor: str,
    ) -> list[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        records = self._repository.escalate_overdue_approvals(actor=actor)
        incidents = [
            hydrated
            for record in records
            if (hydrated := self._hydrate_incident_record(record, include_markdown_content=False)) is not None
        ]
        for incident in incidents:
            self._sync_action_comment(
                incident,
                correlation_id=None,
                author=actor,
                category="approval.escalated",
                fallback_comment=None,
            )
        return incidents

    def save_filter(
        self,
        *,
        name: str,
        filters: dict[str, Any],
        created_by: str,
        workspace: str,
    ) -> dict[str, Any]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.save_filter(
            name=name,
            filters=filters,
            created_by=created_by,
            workspace=workspace,
        )

    def list_saved_filters(
        self,
        *,
        workspaces: Optional[list[str] | tuple[str, ...] | frozenset[str]] = None,
    ) -> list[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.list_saved_filters(workspaces=workspaces)

    def get_readiness(self) -> dict[str, Any]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return build_readiness_report(repository=self._repository)

    def get_observability_snapshot(self) -> dict[str, Any]:
        return observability.snapshot()

    @staticmethod
    def _workflow_result_from_record(
        record: dict[str, Any],
        *,
        include_markdown_content: bool,
    ) -> WorkflowResult:
        alert = MalwareAlert.model_validate(record["alert"])
        enriched_alert = EnrichedAlert.model_validate(record["enriched_alert"])
        response = IncidentResponse.model_validate(record["response"])
        report = record.get("report", {})

        return WorkflowResult(
            alert=alert,
            enriched_alert=enriched_alert,
            response=response,
            artifacts=ReportArtifacts(
                markdown_path=SoarWorkflowService._as_path(report.get("markdown_path")),
                html_path=SoarWorkflowService._as_path(report.get("html_path")),
                pdf_path=SoarWorkflowService._as_path(report.get("pdf_path")),
                markdown_content=(
                    report.get("markdown_content") if include_markdown_content else None
                ),
            ),
            workspace=normalize_workspace(record.get("workspace")),
        )

    @staticmethod
    def _as_path(raw_path: Optional[str]) -> Optional[Path]:
        return Path(raw_path) if raw_path else None

    def _ensure_replay_artifacts(
        self,
        workflow_result: WorkflowResult,
        *,
        generate_report: bool,
        export_pdf: bool,
        include_markdown_content: bool,
    ) -> WorkflowResult:
        artifacts = workflow_result.artifacts
        needs_report = generate_report and (
            self._path_missing(artifacts.markdown_path)
            or self._path_missing(artifacts.html_path)
            or (export_pdf and self._path_missing(artifacts.pdf_path))
        )

        if needs_report:
            with observability.span("workflow.replay_report_generation", export_pdf=export_pdf):
                md_path, html_path, pdf_path = self._report_generator.generate(
                    workflow_result.response,
                    export_pdf=export_pdf,
                )
            workflow_result.response.report_path = str(html_path)
            workflow_result.artifacts = ReportArtifacts(
                markdown_path=md_path,
                html_path=html_path,
                pdf_path=pdf_path,
                markdown_content=(
                    md_path.read_text(encoding="utf-8")
                    if include_markdown_content
                    else None
                ),
            )
            if self._repository is not None:
                with observability.span("workflow.persist_replay_artifacts"):
                    self._repository.save_workflow_result(workflow_result)
            return workflow_result

        if (
            include_markdown_content
            and artifacts.markdown_content is None
            and artifacts.markdown_path is not None
            and artifacts.markdown_path.exists()
        ):
            artifacts.markdown_content = artifacts.markdown_path.read_text(encoding="utf-8")

        return workflow_result

    @staticmethod
    def _path_missing(path: Optional[Path]) -> bool:
        return path is None or not path.exists()

    @staticmethod
    def _extract_queue_publisher(policy_engine: PolicyEngine) -> Optional[RepositoryQueuePublisher]:
        dispatcher = getattr(policy_engine, "_action_dispatcher", None)
        publisher = getattr(dispatcher, "_queue_publisher", None)
        return publisher if isinstance(publisher, RepositoryQueuePublisher) else None

    @staticmethod
    def _extract_ticketing_connector(policy_engine: Any) -> Optional[TicketingConnector]:
        connector = getattr(policy_engine, "_ticketing_connector", None)
        return connector if isinstance(connector, TicketingConnector) else None

    @staticmethod
    def _resolve_policy_correlation_config(policy_engine: Any):
        policy_config = getattr(policy_engine, "policy_config", None)
        if policy_config is not None and getattr(policy_config, "correlation", None) is not None:
            return policy_config.correlation
        return load_policy_config().correlation

    @staticmethod
    def _hydrate_incident_record(
        record: Optional[dict[str, Any]],
        *,
        include_markdown_content: bool,
    ) -> Optional[dict[str, Any]]:
        if record is None:
            return None

        hydrated = dict(record)
        report = dict(hydrated.get("report") or {})

        if (
            include_markdown_content
            and report.get("markdown_content") is None
            and report.get("markdown_path")
        ):
            markdown_path = Path(str(report["markdown_path"]))
            if markdown_path.exists():
                report["markdown_content"] = markdown_path.read_text(encoding="utf-8")

        hydrated["report"] = report
        return hydrated

    @staticmethod
    def _latest_audit_event(
        record: Optional[dict[str, Any]],
        *,
        category: str,
    ) -> Optional[dict[str, Any]]:
        if record is None:
            return None
        for event in list(record.get("audit_events") or []):
            if str(event.get("category") or "") == category:
                return event
        return None

    @staticmethod
    def _ticket_sync_metadata(
        record: Optional[dict[str, Any]],
        *,
        category: str,
        event: Optional[dict[str, Any]] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "category": category,
        }
        if record is not None:
            metadata.update(
                {
                    "alert_id": record.get("alert_id"),
                    "incident_key": record.get("incident_key"),
                    "case_status": record.get("case_status"),
                    "case_owner": record.get("case_owner"),
                }
            )
        if event is not None:
            metadata["audit_event_id"] = event.get("event_id")
            metadata["audit_event_hash"] = event.get("event_hash")
            metadata["audit_previous_hash"] = event.get("previous_event_hash")
            metadata["audit_payload"] = event.get("payload") or {}
        if extra:
            metadata.update(extra)
        return metadata

    @staticmethod
    def _format_action_comment(
        event: Optional[dict[str, Any]],
        *,
        fallback_comment: Optional[str],
    ) -> str:
        payload = dict((event or {}).get("payload") or {})
        lines = [str((event or {}).get("message") or "Manual analyst action recorded.")]
        analyst_comment = payload.get("comment") or payload.get("approval_comment") or fallback_comment
        if analyst_comment:
            lines.append(f"Analyst comment: {analyst_comment}")
        escalation_targets = payload.get("escalation_targets")
        if isinstance(escalation_targets, list) and escalation_targets:
            lines.append(f"Escalation targets: {', '.join(str(item) for item in escalation_targets)}")
        if payload.get("approval_due_at"):
            lines.append(f"Approval due at: {payload['approval_due_at']}")
        if payload.get("approval_escalated_at"):
            lines.append(f"Escalated at: {payload['approval_escalated_at']}")
        if payload.get("rollback_requested_at"):
            lines.append(f"Cancelled at: {payload['rollback_requested_at']}")
        return "\n".join(lines)

    def _safe_ticket_comment(
        self,
        *,
        ticket_id: str,
        author: str,
        comment: str,
        metadata: dict[str, Any],
    ) -> None:
        if self._ticketing_connector is None:
            return
        try:
            self._ticketing_connector.append_case_comment(
                ticket_id=ticket_id,
                comment=comment,
                author=author,
                metadata=metadata,
            )
        except Exception as exc:
            observability.emit_event(
                "error",
                "workflow.ticket_sync_failed",
                message=f"Ticket comment sync failed for {ticket_id}",
                ticket_id=ticket_id,
                error=exc.__class__.__name__,
            )

    def _safe_ticket_state_sync(
        self,
        *,
        ticket_id: str,
        case_status: str,
        case_owner: Optional[str],
        comment: Optional[str],
        actor: str,
        metadata: dict[str, Any],
    ) -> None:
        if self._ticketing_connector is None:
            return
        try:
            self._ticketing_connector.sync_case_state(
                ticket_id=ticket_id,
                case_status=case_status,
                case_owner=case_owner,
                comment=comment,
                actor=actor,
                metadata=metadata,
            )
        except Exception as exc:
            observability.emit_event(
                "error",
                "workflow.ticket_sync_failed",
                message=f"Ticket state sync failed for {ticket_id}",
                ticket_id=ticket_id,
                error=exc.__class__.__name__,
            )

    def _append_ticket_comment(
        self,
        record: Optional[dict[str, Any]],
        *,
        author: str,
        comment: str,
        category: str,
        extra_metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        ticket_id = str((record or {}).get("ticket_id") or "").strip()
        if not ticket_id:
            return
        event = self._latest_audit_event(record, category=category)
        self._safe_ticket_comment(
            ticket_id=ticket_id,
            author=author,
            comment=comment,
            metadata=self._ticket_sync_metadata(record, category=category, event=event, extra=extra_metadata),
        )

    def _sync_action_comment(
        self,
        record: Optional[dict[str, Any]],
        *,
        correlation_id: Optional[str],
        author: str,
        category: str,
        fallback_comment: Optional[str],
    ) -> None:
        ticket_id = str((record or {}).get("ticket_id") or "").strip()
        if not ticket_id:
            return
        event = self._latest_audit_event(record, category=category)
        event_payload = dict((event or {}).get("payload") or {})
        if correlation_id and event_payload.get("correlation_id") not in {None, correlation_id}:
            matching_events = [
                candidate
                for candidate in list((record or {}).get("audit_events") or [])
                if str(candidate.get("category") or "") == category
                and dict(candidate.get("payload") or {}).get("correlation_id") == correlation_id
            ]
            if matching_events:
                event = matching_events[0]
        self._safe_ticket_comment(
            ticket_id=ticket_id,
            author=author,
            comment=self._format_action_comment(event, fallback_comment=fallback_comment),
            metadata=self._ticket_sync_metadata(
                record,
                category=category,
                event=event,
                extra={"correlation_id": correlation_id},
            ),
        )

    def _sync_ticket_case_state(
        self,
        record: Optional[dict[str, Any]],
        *,
        actor: str,
        comment: Optional[str],
        category: str,
    ) -> None:
        ticket_id = str((record or {}).get("ticket_id") or "").strip()
        if not ticket_id:
            return
        event = self._latest_audit_event(record, category=category)
        self._safe_ticket_state_sync(
            ticket_id=ticket_id,
            case_status=str((record or {}).get("case_status") or "new"),
            case_owner=(record or {}).get("case_owner"),
            comment=comment or str((event or {}).get("message") or ""),
            actor=actor,
            metadata=self._ticket_sync_metadata(record, category=category, event=event),
        )
