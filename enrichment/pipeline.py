"""
enrichment/pipeline.py
======================
Enrichment pipeline orchestration for the malware workflow.
"""

from loguru import logger
from rich.panel import Panel

from env_utils import load_local_env_files
from engine.risk_scoring import (
    WEIGHT_ASSET,
    WEIGHT_HASH,
    WEIGHT_IP,
    WEIGHT_MITRE,
    WEIGHT_SEVERITY,
    RiskScoringEngine,
)
from enrichment.base import BaseAssetDB, BaseHashIntel, BaseIPIntel
from enrichment.mitre_mapping import MITREMapper
from integrations.cmdb.providers import AssetDBConnector
from integrations.contracts import CMDBConnector, ThreatIntelConnector
from integrations.intel.providers import (
    DelegatingThreatIntelConnector,
    build_threat_intel_provider_pair_from_env,
)
from integrations.registry import build_default_integrations
from observability import observability, wrap_cmdb_connector, wrap_threat_intel_connector
from schemas.alert import EnrichedAlert, MalwareAlert
from terminal_compat import build_console
from time_utils import utc_now

console = build_console()


class EnrichmentPipeline:
    """Orchestrate the enrichment workflow for a single malware alert."""

    def __init__(
        self,
        hash_intel: BaseHashIntel = None,
        ip_intel: BaseIPIntel = None,
        asset_db: BaseAssetDB = None,
        threat_intel: ThreatIntelConnector | None = None,
        cmdb_connector: CMDBConnector | None = None,
        mitre_mapper: MITREMapper = None,
        risk_engine: RiskScoringEngine = None,
        verbose: bool = True,
    ):
        load_local_env_files()
        defaults = build_default_integrations()

        if threat_intel is not None:
            self._threat_intel = wrap_threat_intel_connector(threat_intel)
        elif hash_intel is not None or ip_intel is not None:
            default_hash_provider, default_ip_provider = build_threat_intel_provider_pair_from_env()
            self._threat_intel = wrap_threat_intel_connector(
                DelegatingThreatIntelConnector(
                    hash_provider=hash_intel or default_hash_provider,
                    ip_provider=ip_intel or default_ip_provider,
                )
            )
        else:
            self._threat_intel = defaults.threat_intel

        if cmdb_connector is not None:
            self._cmdb_connector = wrap_cmdb_connector(cmdb_connector)
        elif asset_db is not None:
            self._cmdb_connector = wrap_cmdb_connector(AssetDBConnector(asset_db))
        else:
            self._cmdb_connector = defaults.cmdb

        self._mitre_mapper = mitre_mapper or MITREMapper()
        self._risk_engine = risk_engine or RiskScoringEngine()
        self._verbose = verbose

    def run(self, alert: MalwareAlert) -> EnrichedAlert:
        """Run the full enrichment pipeline for a single alert."""
        with observability.span("enrichment.run", alert_id=alert.alert_id, hostname=alert.hostname):
            if self._verbose:
                console.print(
                    Panel(
                        f"[bold]Alert ID:[/bold] {alert.alert_id}\n"
                        f"[bold]Host:[/bold]     {alert.hostname}  "
                        f"[bold]User:[/bold] {alert.username}\n"
                        f"[bold]Process:[/bold]  {alert.process_name}\n"
                        f"[bold]Detection:[/bold] {alert.detection_name}  "
                        f"[bold]Severity:[/bold] "
                        f"[{self._severity_color(alert.severity.value)}]"
                        f"{alert.severity.value.upper()}"
                        f"[/{self._severity_color(alert.severity.value)}]",
                        title="[cyan]Alert intake[/cyan]",
                        border_style="cyan",
                    )
                )

            enriched = EnrichedAlert(original_alert=alert)

            with observability.span("enrichment.hash_lookup"):
                enriched.hash_enrichment = self._step_enrich_hash(alert)

            with observability.span("enrichment.ip_lookup"):
                enriched.ip_enrichment = self._step_enrich_ip(alert)

            with observability.span("enrichment.cmdb_lookup"):
                enriched.asset_criticality = self._step_check_asset(alert)
                enriched.asset_info = self._cmdb_connector.get_asset_info(alert.hostname) or {}

            with observability.span("enrichment.mitre_mapping"):
                enriched.mitre_mappings = self._step_mitre_mapping(alert)

            with observability.span("enrichment.risk_scoring"):
                score, level, breakdown = self._step_risk_scoring(enriched)
                enriched.risk_score = score
                enriched.risk_level = level
                enriched.risk_breakdown = breakdown.to_dict()

            enriched.enriched_at = utc_now()

            if self._verbose:
                self._print_risk_summary(score, level, breakdown)

            observability.metrics.incr(
                "enrichment.completed_total",
                risk_level=enriched.risk_level,
            )
            return enriched

    def _step_enrich_hash(self, alert: MalwareAlert):
        """Step 2: look up file hash reputation."""
        logger.info(f"[Step 2] Enriching hash: {alert.file_hash[:16]}...")

        result = self._threat_intel.lookup_hash(alert.file_hash)

        if self._verbose:
            color = self._rep_color(result.reputation.value)
            details = (
                f"[bold]Hash:[/bold]       {alert.file_hash[:32]}...\n"
                f"[bold]Reputation:[/bold] [{color}]{result.reputation.value.upper()}[/{color}]\n"
                f"[bold]Vendors:[/bold]    {result.malicious_vendors}/{result.total_vendors} detected\n"
                f"[bold]Threat:[/bold]     {result.threat_name or '-'}\n"
                f"[bold]Source:[/bold]     {result.source}"
            )
            console.print(Panel(details, title="[yellow]Hash enrichment[/yellow]", border_style="yellow"))

        return result

    def _step_enrich_ip(self, alert: MalwareAlert):
        """Step 3: look up IP reputation."""
        logger.info(f"[Step 3] Enriching IP: {alert.destination_ip}")

        result = self._threat_intel.lookup_ip(alert.destination_ip)

        if self._verbose:
            color = self._rep_color(result.reputation.value)
            c2_badge = " [red bold][C2][/red bold]" if result.is_c2 else ""
            details = (
                f"[bold]IP:[/bold]          {alert.destination_ip}{c2_badge}\n"
                f"[bold]Reputation:[/bold]  [{color}]{result.reputation.value.upper()}[/{color}]\n"
                f"[bold]Confidence:[/bold]  {result.confidence_score}/100\n"
                f"[bold]Country/ISP:[/bold] {result.country or '-'} / {result.isp or '-'}\n"
                f"[bold]Source:[/bold]      {result.source}"
            )
            console.print(Panel(details, title="[yellow]IP enrichment[/yellow]", border_style="yellow"))

        return result

    def _step_check_asset(self, alert: MalwareAlert):
        """Step 4: resolve asset criticality from the CMDB."""
        logger.info(f"[Step 4] Checking asset criticality: {alert.hostname}")

        criticality = self._cmdb_connector.lookup_criticality(alert.hostname)
        info = self._cmdb_connector.get_asset_info(alert.hostname)

        if self._verbose:
            color = self._criticality_color(criticality.value)
            asset_type = info.get("asset_type", "Unknown") if info else "Unknown (not in CMDB)"
            dept = info.get("department", "-") if info else "-"
            owner = info.get("owner", "-") if info else "-"
            details = (
                f"[bold]Hostname:[/bold]     {alert.hostname}\n"
                f"[bold]Criticality:[/bold]  [{color}]{criticality.value.upper()}[/{color}]\n"
                f"[bold]Asset Type:[/bold]   {asset_type}\n"
                f"[bold]Department:[/bold]   {dept}\n"
                f"[bold]Owner:[/bold]        {owner}"
            )
            console.print(Panel(details, title="[yellow]Asset criticality[/yellow]", border_style="yellow"))

        return criticality

    def _step_mitre_mapping(self, alert: MalwareAlert):
        """Step 5: map the alert to MITRE ATT&CK techniques."""
        logger.info(f"[Step 5] Mapping MITRE ATT&CK for process='{alert.process_name}'")

        mappings = self._mitre_mapper.map_alert(alert)

        if self._verbose:
            if mappings:
                lines = []
                for mapping in mappings:
                    lines.append(
                        f"  [cyan]{mapping.technique_id}[/cyan] - {mapping.technique_name} "
                        f"([dim]{mapping.tactic}[/dim]) "
                        f"[dim]confidence={mapping.confidence:.0%} | pattern: {mapping.matched_pattern}[/dim]"
                    )
                details = "\n".join(lines)
            else:
                details = "[dim]No MITRE technique matched this alert.[/dim]"

            console.print(
                Panel(
                    details,
                    title=f"[yellow]MITRE mapping ({len(mappings)} techniques)[/yellow]",
                    border_style="yellow",
                )
            )

        return mappings

    def _step_risk_scoring(self, enriched: EnrichedAlert):
        """Step 6: compute the aggregate risk score."""
        alert = enriched.original_alert
        logger.info(f"[Step 6] Calculating risk score for alert: {alert.alert_id[:8]}...")

        score, level, breakdown = self._risk_engine.score(enriched)
        return score, level, breakdown

    def _print_risk_summary(self, score: float, level: str, breakdown) -> None:
        """Render a compact risk summary in verbose mode."""
        color = self._risk_color(level)
        bar_filled = int(score / 5)
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
            f"[bold]Reasoning:[/bold]\n" + "\n".join(f"  • {reason}" for reason in breakdown.reasoning)
        )
        console.print(
            Panel(
                details,
                title=f"[yellow]Risk score: [{color}]{score:.1f}[/{color}] ({level.upper()})[/yellow]",
                border_style=color,
            )
        )

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
