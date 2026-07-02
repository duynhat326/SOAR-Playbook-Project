from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from engine.policy_engine import PolicyEngine
from enrichment.pipeline import EnrichmentPipeline
from reporting.report_generator import ReportGenerator
from schemas.alert import EnrichedAlert, IncidentResponse, MalwareAlert
from storage.incident_repository import (
    IncidentRepositoryProtocol,
    create_incident_repository,
)


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
        self._policy_engine = policy_engine or PolicyEngine(verbose=verbose)
        if report_generator is not None:
            self._report_generator = report_generator
        elif report_output_dir is not None:
            self._report_generator = ReportGenerator(output_dir=report_output_dir)
        else:
            self._report_generator = ReportGenerator()
        if repository is not None:
            self._repository = repository
        elif persist_results:
            resolved_db_path = db_path
            self._repository = create_incident_repository(resolved_db_path)
        else:
            self._repository = None

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
    ) -> WorkflowResult:
        if self._repository is not None:
            existing_incident = self._repository.get_incident_by_alert_id(alert.alert_id)
            if existing_incident is not None:
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

        enriched = self._pipeline.run(alert)
        response = self._policy_engine.evaluate(enriched)
        artifacts = ReportArtifacts()

        if generate_report:
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
        )
        if self._repository is not None:
            self._repository.save_workflow_result(workflow_result)
        return workflow_result

    def process_alert_payload(
        self,
        alert_data: dict,
        *,
        generate_report: bool = True,
        export_pdf: bool = False,
        include_markdown_content: bool = False,
    ) -> WorkflowResult:
        alert = MalwareAlert(**alert_data)
        return self.process_alert(
            alert,
            generate_report=generate_report,
            export_pdf=export_pdf,
            include_markdown_content=include_markdown_content,
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
    ) -> list[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.list_incidents(
            limit=limit,
            status=status,
            risk_level=risk_level,
            hostname=hostname,
            ticket_id=ticket_id,
        )

    def get_incident_metrics(self) -> dict[str, Any]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.get_incident_metrics()

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
