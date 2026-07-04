"""
enrichment/pipeline.py
======================
Enrichment Pipeline — orchestrate tất cả bước enrichment (bước 2–6 trong workflow).

Workflow chạy tuần tự với log/trace rõ ràng từng bước:
  Bước 2: Enrich hash       → HashEnrichment
  Bước 3: Enrich IP         → IPEnrichment
  Bước 4: Asset criticality → AssetCriticality
  Bước 5: MITRE mapping     → List[MITREMapping]
  Bước 6: Risk scoring      → (score, level, breakdown)

Output: EnrichedAlert đầy đủ, sẵn sàng để policy engine xử lý.
"""

from datetime import datetime
import os

from loguru import logger
from rich.panel import Panel
from rich.text import Text

from env_utils import load_local_env_files
from engine.risk_scoring import RiskScoringEngine
from enrichment.asset_db import build_asset_db_from_env
from enrichment.base import BaseAssetDB, BaseHashIntel, BaseIPIntel
from enrichment.hash_intel import MockHashIntel, VirusTotalHashIntel
from enrichment.ip_intel import MockIPIntel, VirusTotalIPIntel
from enrichment.mitre_mapping import MITREMapper
from schemas.alert import EnrichedAlert, MalwareAlert
from terminal_compat import build_console
from time_utils import utc_now

console = build_console()


class EnrichmentPipeline:
    """
    Orchestrator cho toàn bộ enrichment workflow (bước 2–6).

    Có thể inject bất kỳ implementation nào của BaseHashIntel,
    BaseIPIntel, BaseAssetDB — dễ swap mock ↔ API thật.

    Args:
        hash_intel  : Hash reputation service (mặc định: MockHashIntel)
        ip_intel    : IP reputation service (mặc định: MockIPIntel)
        asset_db    : Asset criticality service (mặc định: MockAssetDB)
        mitre_mapper: MITRE ATT&CK mapper (mặc định: MITREMapper)
        risk_engine : Risk scoring engine (mặc định: RiskScoringEngine)
        verbose     : In trace đẹp bằng Rich ra console
    """

    def __init__(
        self,
        hash_intel:   BaseHashIntel  = None,
        ip_intel:     BaseIPIntel    = None,
        asset_db:     BaseAssetDB    = None,
        mitre_mapper: MITREMapper    = None,
        risk_engine:  RiskScoringEngine = None,
        verbose:      bool           = True,
    ):
        load_local_env_files()
        intel_provider = os.getenv("SOAR_INTEL_PROVIDER", "mock").strip().lower()

        if hash_intel is not None:
            self._hash_intel = hash_intel
        elif intel_provider == "virustotal":
            self._hash_intel = VirusTotalHashIntel()
        else:
            self._hash_intel = MockHashIntel()

        if ip_intel is not None:
            self._ip_intel = ip_intel
        elif intel_provider == "virustotal":
            self._ip_intel = VirusTotalIPIntel()
        else:
            self._ip_intel = MockIPIntel()
        self._asset_db     = asset_db     or build_asset_db_from_env()
        self._mitre_mapper = mitre_mapper or MITREMapper()
        self._risk_engine  = risk_engine  or RiskScoringEngine()
        self._verbose      = verbose

    def run(self, alert: MalwareAlert) -> EnrichedAlert:
        """
        Chạy toàn bộ enrichment pipeline cho 1 alert.

        Args:
            alert: Alert đã parse và validate bằng Pydantic

        Returns:
            EnrichedAlert chứa đầy đủ kết quả enrichment + risk score
        """
        if self._verbose:
            console.print(Panel(
                f"[bold]Alert ID:[/bold] {alert.alert_id}\n"
                f"[bold]Host:[/bold]     {alert.hostname}  "
                f"[bold]User:[/bold] {alert.username}\n"
                f"[bold]Process:[/bold]  {alert.process_name}\n"
                f"[bold]Detection:[/bold] {alert.detection_name}  "
                f"[bold]Severity:[/bold] [{self._severity_color(alert.severity.value)}]{alert.severity.value.upper()}[/{self._severity_color(alert.severity.value)}]",
                title="[cyan]📋 Bước 1 — Nhận Alert Malware[/cyan]",
                border_style="cyan"
            ))

        # Khởi tạo object kết quả
        enriched = EnrichedAlert(original_alert=alert)

        # ── Bước 2: Enrich Hash ───────────────────────────────────────
        enriched.hash_enrichment = self._step_enrich_hash(alert)

        # ── Bước 3: Enrich IP ─────────────────────────────────────────
        enriched.ip_enrichment = self._step_enrich_ip(alert)

        # ── Bước 4: Asset Criticality ─────────────────────────────────
        enriched.asset_criticality = self._step_check_asset(alert)
        enriched.asset_info = self._asset_db.get_asset_info(alert.hostname) or {}

        # ── Bước 5: MITRE Mapping ─────────────────────────────────────
        enriched.mitre_mappings = self._step_mitre_mapping(alert)

        # ── Bước 6: Risk Scoring ──────────────────────────────────────
        score, level, breakdown = self._step_risk_scoring(enriched)
        enriched.risk_score = score
        enriched.risk_level = level
        enriched.risk_breakdown = breakdown.to_dict()

        enriched.enriched_at = utc_now()

        if self._verbose:
            self._print_risk_summary(score, level, breakdown)

        return enriched

    # ──────────────────────────────────────────────
    # Private step methods — mỗi bước 1 method riêng
    # ──────────────────────────────────────────────

    def _step_enrich_hash(self, alert: MalwareAlert):
        """Bước 2: Tra cứu hash reputation."""
        logger.info(f"[Step 2] Enriching hash: {alert.file_hash[:16]}...")

        result = self._hash_intel.lookup(alert.file_hash)

        if self._verbose:
            color = self._rep_color(result.reputation.value)
            details = (
                f"[bold]Hash:[/bold]       {alert.file_hash[:32]}...\n"
                f"[bold]Reputation:[/bold] [{color}]{result.reputation.value.upper()}[/{color}]\n"
                f"[bold]Vendors:[/bold]    {result.malicious_vendors}/{result.total_vendors} detected\n"
                f"[bold]Threat:[/bold]     {result.threat_name or '—'}\n"
                f"[bold]Source:[/bold]     {result.source}"
            )
            console.print(Panel(details, title="[yellow]🔍 Bước 2 — Enrich Hash[/yellow]", border_style="yellow"))

        return result

    def _step_enrich_ip(self, alert: MalwareAlert):
        """Bước 3: Tra cứu IP reputation."""
        logger.info(f"[Step 3] Enriching IP: {alert.destination_ip}")

        result = self._ip_intel.lookup(alert.destination_ip)

        if self._verbose:
            color = self._rep_color(result.reputation.value)
            c2_badge = " [red bold][C2][/red bold]" if result.is_c2 else ""
            details = (
                f"[bold]IP:[/bold]          {alert.destination_ip}{c2_badge}\n"
                f"[bold]Reputation:[/bold]  [{color}]{result.reputation.value.upper()}[/{color}]\n"
                f"[bold]Confidence:[/bold]  {result.confidence_score}/100\n"
                f"[bold]Country/ISP:[/bold] {result.country or '—'} / {result.isp or '—'}\n"
                f"[bold]Source:[/bold]      {result.source}"
            )
            console.print(Panel(details, title="[yellow]🌐 Bước 3 — Enrich IP[/yellow]", border_style="yellow"))

        return result

    def _step_check_asset(self, alert: MalwareAlert):
        """Bước 4: Kiểm tra asset criticality từ CMDB."""
        logger.info(f"[Step 4] Checking asset criticality: {alert.hostname}")

        criticality = self._asset_db.lookup(alert.hostname)
        info = self._asset_db.get_asset_info(alert.hostname)

        if self._verbose:
            color = self._criticality_color(criticality.value)
            asset_type = info.get("asset_type", "Unknown") if info else "Unknown (not in CMDB)"
            dept       = info.get("department", "—") if info else "—"
            owner      = info.get("owner", "—") if info else "—"
            details = (
                f"[bold]Hostname:[/bold]     {alert.hostname}\n"
                f"[bold]Criticality:[/bold]  [{color}]{criticality.value.upper()}[/{color}]\n"
                f"[bold]Asset Type:[/bold]   {asset_type}\n"
                f"[bold]Department:[/bold]   {dept}\n"
                f"[bold]Owner:[/bold]        {owner}"
            )
            console.print(Panel(details, title="[yellow]🏢 Bước 4 — Asset Criticality[/yellow]", border_style="yellow"))

        return criticality

    def _step_mitre_mapping(self, alert: MalwareAlert):
        """Bước 5: Mapping sang MITRE ATT&CK framework."""
        logger.info(f"[Step 5] Mapping MITRE ATT&CK for process='{alert.process_name}'")

        mappings = self._mitre_mapper.map_alert(alert)

        if self._verbose:
            if mappings:
                lines = []
                for m in mappings:
                    lines.append(
                        f"  [cyan]{m.technique_id}[/cyan] — {m.technique_name} "
                        f"([dim]{m.tactic}[/dim]) "
                        f"[dim]confidence={m.confidence:.0%} | pattern: {m.matched_pattern}[/dim]"
                    )
                details = "\n".join(lines)
            else:
                details = "[dim]Không tìm thấy technique nào khớp với alert này.[/dim]"

            console.print(Panel(
                details,
                title=f"[yellow]🎯 Bước 5 — MITRE ATT&CK Mapping ({len(mappings)} techniques)[/yellow]",
                border_style="yellow"
            ))

        return mappings

    def _step_risk_scoring(self, enriched: EnrichedAlert):
        """Bước 6: Tính điểm rủi ro tổng hợp."""
        alert = enriched.original_alert
        logger.info(f"[Step 6] Calculating risk score for alert: {alert.alert_id[:8]}...")

        score, level, breakdown = self._risk_engine.score(enriched)

        return score, level, breakdown

    # ──────────────────────────────────────────────
    # Display helpers
    # ──────────────────────────────────────────────

    def _print_risk_summary(self, score: float, level: str, breakdown) -> None:
        """In bảng tóm tắt risk score sau bước 6."""
        color = self._risk_color(level)
        bar_filled = int(score / 5)    # 0–20 blocks
        bar = "█" * bar_filled + "░" * (20 - bar_filled)

        details = (
            f"[bold]Risk Score:[/bold]  [{color}]{score:.1f}/100[/{color}]  {bar}\n"
            f"[bold]Risk Level:[/bold]  [{color}]{level.upper()}[/{color}]\n\n"
            f"[bold]Breakdown:[/bold]\n"
            f"  Hash        {breakdown.hash_contribution:>5.2f}  (weight {WEIGHT_HASH:.0%})\n"
            f"  IP          {breakdown.ip_contribution:>5.2f}  (weight {WEIGHT_IP:.0%})\n"
            f"  Asset       {breakdown.asset_contribution:>5.2f}  (weight {WEIGHT_ASSET:.0%})\n"
            f"  Severity    {breakdown.severity_contribution:>5.2f}  (weight {WEIGHT_SEVERITY:.0%})\n"
            f"  MITRE       {breakdown.mitre_contribution:>5.2f}  (weight {WEIGHT_MITRE:.0%})\n\n"
            f"[bold]Reasoning:[/bold]\n" +
            "\n".join(f"  • {r}" for r in breakdown.reasoning)
        )
        console.print(Panel(
            details,
            title=f"[yellow]📊 Bước 6 — Risk Score: [{color}]{score:.1f}[/{color}] ({level.upper()})[/yellow]",
            border_style=color
        ))

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(severity, "white")

    @staticmethod
    def _rep_color(reputation: str) -> str:
        return {"malicious": "red", "suspicious": "yellow", "clean": "green", "unknown": "dim"}.get(reputation, "white")

    @staticmethod
    def _criticality_color(criticality: str) -> str:
        return {"critical": "red", "normal": "yellow", "low": "green"}.get(criticality, "white")

    @staticmethod
    def _risk_color(level: str) -> str:
        return {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(level, "white")


# Import trọng số để pipeline.py có thể dùng trong display
from engine.risk_scoring import WEIGHT_HASH, WEIGHT_IP, WEIGHT_ASSET, WEIGHT_SEVERITY, WEIGHT_MITRE
