"""
engine/policy_engine.py
=======================
Policy Engine — áp dụng response policy và thực thi actions.

Phase 3 chuyển 4 remediation rules sang file config bên ngoài để
cho phép bật/tắt hoặc chỉnh logic theo dữ liệu thay vì sửa code.
"""

from dataclasses import dataclass
import hashlib
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

from loguru import logger
from rich.panel import Panel
from rich.table import Table

from enrichment.mitre_mapping import MITREMapper
from engine.action_dispatcher import ActionDispatcher, QueuePublisher
from engine.policy_loader import (
    PolicyConditionType,
    PolicyConfig,
    PolicyExecutionMode,
    PolicyRule,
    load_policy_config,
)
from integrations.contracts import ActionConnector, TicketingConnector
from integrations.registry import build_default_integrations
from observability import observability, wrap_action_connector, wrap_ticketing_connector
from schemas.alert import (
    ActionResult,
    EnrichedAlert,
    IPReputation,
    IncidentResponse,
    PolicyExecutionTrace,
    PolicyMetadataSnapshot,
    ResponseAction,
    Severity,
)
from terminal_compat import build_console
from time_utils import utc_now

console = build_console()


@dataclass
class RuleEvaluation:
    rule: PolicyRule
    status: str
    reasoning: str
    triggered_action: Optional[ResponseAction] = None

    @property
    def is_triggered(self) -> bool:
        return self.status == "triggered" and self.triggered_action is not None


@dataclass(frozen=True)
class CanaryDecision:
    enabled: bool
    targeted: Optional[bool]
    reason: Optional[str]
    percentage: Optional[int] = None
    bucket: Optional[int] = None


class PolicyEngine:
    """
    Áp dụng 4 response rule và thực thi các action tương ứng.

    Args:
        mitre_mapper: Dùng để kiểm tra dangerous process blacklist
        verbose     : In trace đẹp ra console
    """

    def __init__(
        self,
        mitre_mapper: MITREMapper = None,
        verbose: bool = True,
        policy_config_path: Optional[Path] = None,
        policy_config: Optional[PolicyConfig] = None,
        queue_publisher: QueuePublisher | None = None,
        action_connector: ActionConnector | None = None,
        ticketing_connector: TicketingConnector | None = None,
    ) -> None:
        defaults = build_default_integrations()
        self._mitre_mapper = mitre_mapper or MITREMapper()
        self._verbose = verbose
        self._policy_config = policy_config or load_policy_config(policy_config_path)
        self._action_connector = wrap_action_connector(action_connector or defaults.action)
        self._ticketing_connector = wrap_ticketing_connector(ticketing_connector or defaults.ticketing)
        self._action_dispatcher = ActionDispatcher(
            config=self._policy_config.execution,
            action_executor=self._execute_action,
            queue_publisher=queue_publisher,
        )

    @property
    def policy_config(self) -> PolicyConfig:
        return self._policy_config

    def evaluate(self, enriched: EnrichedAlert) -> IncidentResponse:
        """
        Đánh giá enriched alert và thực thi policy.

        Workflow bước 7:
          1. Evaluate tất cả rule (không execute ngay)
          2. Log/print kết quả evaluation
          3. Execute các action được trigger
          4. Luôn tạo ticket + notify SOC
          5. Build IncidentResponse

        Args:
            enriched: EnrichedAlert đã có risk score

        Returns:
            IncidentResponse với đầy đủ action results và reasoning
        """
        alert = enriched.original_alert

        if self._verbose:
            console.print(Panel(
                f"[bold]Đánh giá policy cho alert:[/bold] {alert.alert_id[:16]}...\n"
                f"[bold]Risk Score:[/bold] {enriched.risk_score:.1f} ({enriched.risk_level.upper()})\n"
                f"[bold]Host:[/bold] {alert.hostname}  "
                f"[bold]Process:[/bold] {alert.process_name}",
                title="[magenta]⚖️  Bước 7 — Policy Engine[/magenta]",
                border_style="magenta",
            ))

        # ── Phase 1: Evaluate all rules ───────────────────────────────
        triggered_actions: list[ResponseAction] = []
        reasoning: list[str] = []
        evaluations: list[RuleEvaluation] = []

        with observability.span(
            "policy.rule_evaluation",
            alert_id=alert.alert_id,
            policy_version=self._policy_config.metadata.version,
            rule_count=len(self._policy_config.rules),
        ):
            for rule in self._policy_config.rules:
                evaluation = self._evaluate_rule(rule, enriched)
                evaluations.append(evaluation)
                reasoning.append(evaluation.reasoning)
                if evaluation.is_triggered and evaluation.triggered_action not in triggered_actions:
                    triggered_actions.append(evaluation.triggered_action)

        # ── Phase 2: In kết quả evaluation ───────────────────────────
        if self._verbose:
            self._print_evaluation_table(evaluations)

        # ── Phase 3: Execute actions ──────────────────────────────────
        action_names = [a.value for a in triggered_actions]
        canary_decision = self._evaluate_canary(enriched)
        if canary_decision.enabled and canary_decision.targeted is False and triggered_actions:
            reasoning.append(f"Canary rollout [SKIP]: {canary_decision.reason}")

        if self._policy_config.execution.mode == PolicyExecutionMode.DRY_RUN:
            action_results = self._build_dry_run_action_results(triggered_actions, enriched)
            ticket_id = None
            execution_trace = PolicyExecutionTrace(
                configured_mode=self._policy_config.execution.mode.value,
                effective_mode=self._policy_config.execution.mode.value,
            )
        elif canary_decision.enabled and canary_decision.targeted is False:
            action_results = self._build_canary_skip_action_results(
                triggered_actions,
                enriched,
                canary_decision.reason or "Alert did not match the canary rollout selectors.",
            )
            execution_trace = PolicyExecutionTrace(
                configured_mode=self._policy_config.execution.mode.value,
                effective_mode=f"{self._policy_config.execution.mode.value}_canary_skip",
            )
            ticket_id = None
        else:
            with observability.span(
                "policy.dispatch_actions",
                alert_id=alert.alert_id,
                action_count=len(triggered_actions),
                mode=self._policy_config.execution.mode.value,
            ):
                dispatch_outcome = self._action_dispatcher.dispatch(triggered_actions, enriched)
            action_results = list(dispatch_outcome.action_results)
            execution_trace = dispatch_outcome.execution_trace

            # ── Phase 4: Unconditional — Ticket + Notify SOC ──────────
            ticket_id = None

        if self._policy_config.execution.mode != PolicyExecutionMode.DRY_RUN:
            with observability.span("policy.create_ticket", alert_id=alert.alert_id):
                ticket_result, ticket_id = self._ticketing_connector.create_ticket(
                    enriched_alert=enriched,
                    triggered_actions=action_names,
                    risk_score=enriched.risk_score,
                    risk_level=enriched.risk_level,
                )
            action_results.append(ticket_result)

            with observability.span("policy.notify_soc", alert_id=alert.alert_id):
                notify_result = self._action_connector.notify_soc(
                    alert_id=alert.alert_id,
                    hostname=alert.hostname,
                    risk_score=enriched.risk_score,
                    risk_level=enriched.risk_level,
                    triggered_actions=action_names,
                    ticket_id=ticket_id,
                )
            action_results.append(notify_result)

        response_actions = [
            *triggered_actions,
            ResponseAction.CREATE_TICKET,
            ResponseAction.NOTIFY_SOC,
        ]
        action_results = self._annotate_action_results(action_results)
        execution_trace = self._annotate_execution_trace(execution_trace, canary_decision)

        # ── Phase 5: Build IncidentResponse ───────────────────────────
        response = IncidentResponse(
            enriched_alert=enriched,
            triggered_actions=response_actions,
            policy_reasoning=reasoning,
            action_results=action_results,
            ticket_id=ticket_id,
            completed_at=utc_now(),
            policy_version=self._policy_config.metadata.version,
            policy_metadata=self._policy_metadata_snapshot(),
            execution_trace=execution_trace,
        )

        if self._verbose:
            self._print_summary(response)

        observability.metrics.incr(
            "policy.evaluations_total",
            mode=self._policy_config.execution.mode.value,
            risk_level=enriched.risk_level,
        )
        return response

    # ──────────────────────────────────────────────────────────────────
    # Rule evaluation
    # ──────────────────────────────────────────────────────────────────

    def _evaluate_rule(self, rule: PolicyRule, enriched: EnrichedAlert) -> RuleEvaluation:
        logger.debug(f"[PolicyEngine] Evaluating {rule.label}: {rule.condition_label}")
        context = self._build_context(enriched, rule)

        if not rule.enabled:
            return RuleEvaluation(
                rule=rule,
                status="disabled",
                reasoning=self._render_message(rule.messages.disabled, context),
            )

        guard_result = self._apply_rule_guards(rule, enriched)
        if guard_result is not None:
            return guard_result

        threshold_result = self._apply_rule_thresholds(rule, enriched)
        if threshold_result is not None:
            return threshold_result

        evaluator_map = {
            PolicyConditionType.HASH_REPUTATION_EQUALS: self._eval_hash_reputation,
            PolicyConditionType.DANGEROUS_PROCESS_BLACKLIST: self._eval_dangerous_process,
            PolicyConditionType.ASSET_CRITICALITY_EQUALS: self._eval_asset_criticality,
            PolicyConditionType.IP_IS_C2: self._eval_ip_is_c2,
        }
        evaluator = evaluator_map.get(rule.condition_type)
        if evaluator is None:
            logger.warning(f"[PolicyEngine] Unsupported condition_type='{rule.condition_type}'")
            return RuleEvaluation(
                rule=rule,
                status="disabled",
                reasoning=f"{rule.label} [DISABLED]: Unsupported condition_type '{rule.condition_type}'.",
            )
        return evaluator(rule, enriched, context)

    def _apply_rule_guards(
        self,
        rule: PolicyRule,
        enriched: EnrichedAlert,
    ) -> RuleEvaluation | None:
        username = enriched.original_alert.username
        normalized_allowlist = {value.casefold() for value in rule.guards.username_allowlist}
        if username.casefold() in normalized_allowlist:
            return RuleEvaluation(
                rule=rule,
                status="passed",
                reasoning=(
                    f"{rule.label} [PASS]: Username '{username}' is allowlisted for "
                    f"'{rule.action.value}' → no action"
                ),
            )
        return None

    def _apply_rule_thresholds(
        self,
        rule: PolicyRule,
        enriched: EnrichedAlert,
    ) -> RuleEvaluation | None:
        threshold = rule.thresholds
        alert = enriched.original_alert

        if enriched.risk_score < threshold.min_risk_score:
            return RuleEvaluation(
                rule=rule,
                status="passed",
                reasoning=(
                    f"{rule.label} [PASS]: Risk score {enriched.risk_score:.1f} below minimum "
                    f"{threshold.min_risk_score:.1f} → no action"
                ),
            )

        if self._severity_rank(alert.severity) < self._severity_rank(threshold.min_severity):
            return RuleEvaluation(
                rule=rule,
                status="passed",
                reasoning=(
                    f"{rule.label} [PASS]: Severity {alert.severity.value} below minimum "
                    f"{threshold.min_severity.value} → no action"
                ),
            )

        return None

    def _eval_hash_reputation(
        self,
        rule: PolicyRule,
        enriched: EnrichedAlert,
        context: dict[str, object],
    ) -> RuleEvaluation:
        if enriched.hash_enrichment is None:
            return RuleEvaluation(
                rule=rule,
                status="skipped",
                reasoning=self._render_message(rule.messages.skipped, context),
            )

        expected = str(rule.matches.get("value", "")).lower()
        actual = enriched.hash_enrichment.reputation.value
        if actual == expected:
            return RuleEvaluation(
                rule=rule,
                status="triggered",
                triggered_action=rule.action,
                reasoning=self._render_message(rule.messages.triggered, context),
            )
        return RuleEvaluation(
            rule=rule,
            status="passed",
            reasoning=self._render_message(rule.messages.passed, context),
        )

    def _eval_dangerous_process(
        self,
        rule: PolicyRule,
        enriched: EnrichedAlert,
        context: dict[str, object],
    ) -> RuleEvaluation:
        process = enriched.original_alert.process_name
        if self._mitre_mapper.is_dangerous_process(process):
            return RuleEvaluation(
                rule=rule,
                status="triggered",
                triggered_action=rule.action,
                reasoning=self._render_message(rule.messages.triggered, context),
            )
        return RuleEvaluation(
            rule=rule,
            status="passed",
            reasoning=self._render_message(rule.messages.passed, context),
        )

    def _eval_asset_criticality(
        self,
        rule: PolicyRule,
        enriched: EnrichedAlert,
        context: dict[str, object],
    ) -> RuleEvaluation:
        expected = str(rule.matches.get("value", "")).lower()
        actual = enriched.asset_criticality.value
        if actual == expected:
            return RuleEvaluation(
                rule=rule,
                status="triggered",
                triggered_action=rule.action,
                reasoning=self._render_message(rule.messages.triggered, context),
            )
        return RuleEvaluation(
            rule=rule,
            status="passed",
            reasoning=self._render_message(rule.messages.passed, context),
        )

    def _eval_ip_is_c2(
        self,
        rule: PolicyRule,
        enriched: EnrichedAlert,
        context: dict[str, object],
    ) -> RuleEvaluation:
        if enriched.ip_enrichment is None:
            return RuleEvaluation(
                rule=rule,
                status="skipped",
                reasoning=self._render_message(rule.messages.skipped, context),
            )

        expected = bool(rule.matches.get("value", True))
        actual = enriched.ip_enrichment.is_c2
        if actual == expected:
            return RuleEvaluation(
                rule=rule,
                status="triggered",
                triggered_action=rule.action,
                reasoning=self._render_message(rule.messages.triggered, context),
            )
        if enriched.ip_enrichment.reputation == IPReputation.MALICIOUS and rule.messages.partial:
            return RuleEvaluation(
                rule=rule,
                status="partial",
                reasoning=self._render_message(rule.messages.partial, context),
            )
        return RuleEvaluation(
            rule=rule,
            status="passed",
            reasoning=self._render_message(rule.messages.passed, context),
        )

    @staticmethod
    def _render_message(template: Optional[str], context: dict[str, object]) -> str:
        if not template:
            return ""
        return template.format(**context)

    def _build_context(
        self,
        enriched: EnrichedAlert,
        rule: PolicyRule,
    ) -> dict[str, object]:
        alert = enriched.original_alert
        hash_result = enriched.hash_enrichment
        ip_result = enriched.ip_enrichment
        return {
            "rule_id": rule.rule_id,
            "rule_label": rule.label,
            "hostname": alert.hostname,
            "username": alert.username,
            "process_name": alert.process_name,
            "destination_ip": alert.destination_ip,
            "severity": alert.severity.value,
            "risk_score": enriched.risk_score,
            "hash_reputation": hash_result.reputation.value if hash_result else "unknown",
            "hash_vendor_ratio": (
                f"{hash_result.malicious_vendors}/{hash_result.total_vendors}"
                if hash_result else "0/0"
            ),
            "hash_threat": (
                hash_result.threat_name or "Unknown threat"
                if hash_result else "Unknown threat"
            ),
            "asset_criticality": enriched.asset_criticality.value,
            "ip_reputation": ip_result.reputation.value if ip_result else "unknown",
            "ip_confidence": ip_result.confidence_score if ip_result else 0,
            "action": rule.action.value,
        }

    @staticmethod
    def _severity_rank(severity: Severity) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[severity]

    # ──────────────────────────────────────────────────────────────────
    # Action executor — dispatch từng action type
    # ──────────────────────────────────────────────────────────────────

    def _execute_action(
        self,
        action: ResponseAction,
        enriched: EnrichedAlert,
    ) -> ActionResult:
        """Dispatch action tới module tương ứng."""
        alert = enriched.original_alert

        if action == ResponseAction.ISOLATE_HOST:
            return self._action_connector.isolate_host(
                hostname=alert.hostname,
                alert_id=alert.alert_id,
                reason=(
                    f"Hash MALICIOUS: {enriched.hash_enrichment.threat_name or 'Unknown'} "
                    if enriched.hash_enrichment else "Malicious hash detected"
                ),
            )

        elif action == ResponseAction.KILL_PROCESS:
            return self._action_connector.kill_process(
                process_name=alert.process_name,
                hostname=alert.hostname,
                alert_id=alert.alert_id,
                command_line=alert.command_line,
                reason=f"Process '{alert.process_name}' in dangerous process blacklist",
            )

        elif action == ResponseAction.BLOCK_IP:
            return self._action_connector.block_ip(
                ip_address=alert.destination_ip,
                alert_id=alert.alert_id,
                hostname=alert.hostname,
                reason="C2 server detected in threat intel",
                confidence=(
                    enriched.ip_enrichment.confidence_score
                    if enriched.ip_enrichment else 0
                ),
            )

        elif action == ResponseAction.ESCALATE:
            return self._action_connector.escalate(
                hostname=alert.hostname,
                reason=f"Host '{alert.hostname}' marked as critical asset requires manual review",
            )

        # Action không được nhận diện (không nên xảy ra)
        logger.error(f"[PolicyEngine] Unknown action: {action}")
        return None

    def _build_dry_run_action_results(
        self,
        triggered_actions: list[ResponseAction],
        enriched: EnrichedAlert,
    ) -> list[ActionResult]:
        alert = enriched.original_alert
        action_results = [
            ActionResult(
                action=action,
                status="skipped",
                details=(
                    f"Dry-run: '{action.value}' would have executed for alert "
                    f"'{alert.alert_id}' on host '{alert.hostname}'."
                ),
            )
            for action in triggered_actions
        ]
        action_results.append(
            ActionResult(
                action=ResponseAction.CREATE_TICKET,
                status="skipped",
                details=f"Dry-run: ticket would have been created for alert '{alert.alert_id}'.",
            )
        )
        action_results.append(
            ActionResult(
                action=ResponseAction.NOTIFY_SOC,
                status="skipped",
                details=f"Dry-run: SOC notification would have been sent for alert '{alert.alert_id}'.",
            )
        )
        return action_results

    def _build_canary_skip_action_results(
        self,
        triggered_actions: list[ResponseAction],
        enriched: EnrichedAlert,
        reason: str,
    ) -> list[ActionResult]:
        alert = enriched.original_alert
        return [
            ActionResult(
                action=action,
                status="skipped",
                details=(
                    f"Canary rollout blocked '{action.value}' for alert '{alert.alert_id}' "
                    f"on host '{alert.hostname}'. {reason}"
                ),
            )
            for action in triggered_actions
        ]

    def _evaluate_canary(self, enriched: EnrichedAlert) -> CanaryDecision:
        config = self._policy_config.execution.canary
        if not config.enabled:
            return CanaryDecision(
                enabled=False,
                targeted=None,
                reason=None,
                percentage=config.percentage,
                bucket=None,
            )

        alert = enriched.original_alert
        asset_info = enriched.asset_info or {}
        hostname = alert.hostname
        normalized_tags = self._normalize_casefold_set(
            asset_info.get("tags") or asset_info.get("asset_tags")
        )
        environment = self._normalize_scalar(
            asset_info.get("environment") or asset_info.get("env")
        )
        workspace = self._normalize_scalar(
            asset_info.get("workspace") or asset_info.get("workspace_id")
        )
        bucket = self._canary_bucket(hostname)

        hostname_match = (
            any(fnmatch(hostname.casefold(), pattern.casefold()) for pattern in config.hostname_patterns)
            if config.hostname_patterns
            else True
        )
        tag_match = (
            bool(normalized_tags & {tag.casefold() for tag in config.asset_tags})
            if config.asset_tags
            else True
        )
        environment_match = (
            environment in {value.casefold() for value in config.environments}
            if config.environments
            else True
        )
        workspace_match = (
            workspace in {value.casefold() for value in config.workspaces}
            if config.workspaces
            else True
        )
        percentage_match = bucket < config.percentage if config.percentage < 100 else True

        targeted = all([hostname_match, tag_match, environment_match, workspace_match, percentage_match])
        reasons: list[str] = []
        if config.hostname_patterns:
            reasons.append(
                "hostname matched"
                if hostname_match
                else f"hostname '{hostname}' did not match any configured canary pattern"
            )
        if config.asset_tags:
            reasons.append(
                "asset tag matched"
                if tag_match
                else f"asset tags {sorted(normalized_tags) or ['<none>']} did not match canary tags"
            )
        if config.environments:
            reasons.append(
                f"environment '{environment or '<none>'}' matched"
                if environment_match
                else f"environment '{environment or '<none>'}' is outside canary scope"
            )
        if config.workspaces:
            reasons.append(
                f"workspace '{workspace or '<none>'}' matched"
                if workspace_match
                else f"workspace '{workspace or '<none>'}' is outside canary scope"
            )
        reasons.append(
            f"bucket {bucket}/100 is within rollout percentage {config.percentage}"
            if percentage_match
            else f"bucket {bucket}/100 exceeds rollout percentage {config.percentage}"
        )
        reason = "; ".join(reasons) if reasons else "Canary rollout matched all selectors."
        return CanaryDecision(
            enabled=True,
            targeted=targeted,
            reason=reason,
            percentage=config.percentage,
            bucket=bucket,
        )

    @staticmethod
    def _normalize_casefold_set(value: object) -> set[str]:
        if value is None:
            return set()
        if isinstance(value, str):
            return {item.strip().casefold() for item in value.split(",") if item.strip()}
        if isinstance(value, (list, tuple, set)):
            return {str(item).strip().casefold() for item in value if str(item).strip()}
        return {str(value).strip().casefold()} if str(value).strip() else set()

    @staticmethod
    def _normalize_scalar(value: object) -> str | None:
        if value is None:
            return None
        candidate = str(value).strip()
        return candidate.casefold() if candidate else None

    def _canary_bucket(self, hostname: str) -> int:
        key = f"{self._policy_config.metadata.version}:{hostname.casefold()}"
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return int(digest[:8], 16) % 100

    def _policy_metadata_snapshot(self) -> PolicyMetadataSnapshot:
        metadata = self._policy_config.metadata
        return PolicyMetadataSnapshot(
            version=metadata.version,
            status=metadata.status,
            owner=metadata.owner,
            change_reason=metadata.change_reason,
            created_at=metadata.created_at,
        )

    def _annotate_action_results(self, action_results: list[ActionResult]) -> list[ActionResult]:
        policy_version = self._policy_config.metadata.version
        return [
            result.model_copy(update={"policy_version": policy_version})
            for result in action_results
        ]

    def _annotate_execution_trace(
        self,
        execution_trace: PolicyExecutionTrace,
        canary_decision: CanaryDecision,
    ) -> PolicyExecutionTrace:
        return execution_trace.model_copy(
            update={
                "policy_version": self._policy_config.metadata.version,
                "policy_status": self._policy_config.metadata.status,
                "canary_enabled": canary_decision.enabled,
                "canary_targeted": canary_decision.targeted,
                "canary_reason": canary_decision.reason,
                "canary_percentage": canary_decision.percentage,
                "canary_bucket": canary_decision.bucket,
            }
        )

    # ──────────────────────────────────────────────────────────────────
    # Display helpers
    # ──────────────────────────────────────────────────────────────────

    def _print_evaluation_table(
        self,
        evaluations: list[RuleEvaluation],
    ) -> None:
        """In bảng tóm tắt kết quả evaluation của rule config."""
        table = Table(
            title="Policy Evaluation Results",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Rule", width=8)
        table.add_column("Condition", width=32)
        table.add_column("Result", width=10)
        table.add_column("Action", width=18)

        status_map = {
            "triggered": "[red]TRIGGERED[/red]",
            "passed": "[green]PASS[/green]",
            "partial": "[yellow]PARTIAL[/yellow]",
            "skipped": "[dim]SKIP[/dim]",
            "disabled": "[dim]DISABLED[/dim]",
        }

        triggered_actions = []
        for evaluation in evaluations:
            if evaluation.is_triggered:
                triggered_actions.append(evaluation.triggered_action)
            table.add_row(
                evaluation.rule.label,
                evaluation.rule.condition_label,
                status_map.get(evaluation.status, evaluation.status.upper()),
                (
                    f"[red]{evaluation.rule.action.value}[/red]"
                    if evaluation.is_triggered
                    else "[dim]—[/dim]"
                ),
            )

        console.print(table)

        if triggered_actions:
            verb = (
                "Simulating"
                if self._policy_config.execution.mode == PolicyExecutionMode.DRY_RUN
                else (
                "Queueing"
                if self._policy_config.execution.mode == PolicyExecutionMode.QUEUED
                else "Executing"
                )
            )
            console.print(
                f"\n[bold red]⚡ {len(triggered_actions)} rule(s) triggered → "
                f"{verb}: {', '.join(a.value for a in triggered_actions)}[/bold red]"
            )
        else:
            console.print("\n[bold green]✓ No rules triggered — no automated action[/bold green]")

    def _print_summary(self, response: IncidentResponse) -> None:
        """In tóm tắt cuối sau khi tất cả actions đã thực hiện."""
        alert = response.enriched_alert.original_alert
        executed = [r for r in response.action_results if r.status == "succeeded"]
        in_flight = [r for r in response.action_results if r.status in {"queued", "running"}]

        console.print(Panel(
            f"[bold]Alert ID:[/bold]  {alert.alert_id}\n"
            f"[bold]Ticket:[/bold]    {response.ticket_id or '—'}\n"
            f"[bold]Actions:[/bold]   {len(executed)} completed, {len(in_flight)} in-flight\n"
            f"[bold]Completed:[/bold] {response.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"[bold]Reasoning:[/bold]\n" +
            "\n".join(f"  • {r}" for r in response.policy_reasoning),
            title="[magenta]✅ Bước 7 — Policy Engine Complete[/magenta]",
            border_style="green",
        ))
