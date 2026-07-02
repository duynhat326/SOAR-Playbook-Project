from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field

from schemas.alert import IncidentResponse, MalwareAlert
from services.workflow_service import WorkflowResult


ScenarioName = Literal[
    "malicious_hash",
    "c2_communication",
    "critical_asset",
    "dangerous_process",
    "mixed",
    "benign",
    "random",
]


class ProcessAlertRequest(BaseModel):
    alert: MalwareAlert
    generate_report: bool = Field(default=True)
    export_pdf: bool = Field(default=False)


class ProcessScenarioRequest(BaseModel):
    scenario: ScenarioName = Field(default="mixed")
    seed: int = Field(default=2024, ge=0)
    generate_report: bool = Field(default=True)
    export_pdf: bool = Field(default=False)


class ReportArtifactsResponse(BaseModel):
    markdown_path: Optional[str] = None
    html_path: Optional[str] = None
    pdf_path: Optional[str] = None

    @staticmethod
    def _as_str(path: Optional[Path]) -> Optional[str]:
        return str(path) if path is not None else None

    @classmethod
    def from_workflow_result(cls, result: WorkflowResult) -> "ReportArtifactsResponse":
        return cls(
            markdown_path=cls._as_str(result.artifacts.markdown_path),
            html_path=cls._as_str(result.artifacts.html_path),
            pdf_path=cls._as_str(result.artifacts.pdf_path),
        )


class ProcessIncidentResponse(BaseModel):
    response: IncidentResponse
    report: ReportArtifactsResponse

    @classmethod
    def from_workflow_result(cls, result: WorkflowResult) -> "ProcessIncidentResponse":
        return cls(
            response=result.response,
            report=ReportArtifactsResponse.from_workflow_result(result),
        )
