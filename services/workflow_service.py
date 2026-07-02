from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from engine.policy_engine import PolicyEngine
from enrichment.pipeline import EnrichmentPipeline
from reporting.report_generator import ReportGenerator
from schemas.alert import EnrichedAlert, IncidentResponse, MalwareAlert
from storage.sqlite_repository import SQLiteIncidentRepository


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
        db_path: Optional[Path] = None,
        persist_results: bool = True,
        pipeline: Optional[EnrichmentPipeline] = None,
        policy_engine: Optional[PolicyEngine] = None,
        report_generator: Optional[ReportGenerator] = None,
        repository: Optional[SQLiteIncidentRepository] = None,
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
            if resolved_db_path is None and report_output_dir is not None:
                resolved_db_path = report_output_dir.parent / "soar.db"
            self._repository = SQLiteIncidentRepository(db_path=resolved_db_path)
        else:
            self._repository = None

    def process_alert(
        self,
        alert: MalwareAlert,
        *,
        generate_report: bool = True,
        export_pdf: bool = False,
        include_markdown_content: bool = False,
    ) -> WorkflowResult:
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
        return self._repository.get_incident_by_alert_id(alert_id)

    def get_incident_by_ticket_id(self, ticket_id: str) -> Optional[dict[str, Any]]:
        if self._repository is None:
            raise RuntimeError("Persistence is disabled for this workflow service.")
        return self._repository.get_incident_by_ticket_id(ticket_id)

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
