"""
engine/policy_engine.py
=======================
Policy Engine — áp dụng response policy và thực thi actions.

Phase 3 chuyển 4 remediation rules sang file config bên ngoài để
cho phép bật/tắt hoặc chỉnh logic theo dữ liệu thay vì sửa code.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import actions.block_ip as block_ip_action
import actions.isolate_host as isolate_host_action
import actions.kill_process as kill_process_action
import actions.notify_soc as notify_soc_action
import actions.ticketing as ticketing_action
from enrichment.mitre_mapping import MITREMapper
from engine.action_dispatcher import ActionDispatcher, QueuePublisher
from engine.policy_loader import (
    PolicyConditionType,
    PolicyConfig,
    PolicyExecutionMode,
    PolicyRule,
    load_policy_config,
)
from schemas.alert import (
    ActionResult,
    EnrichedAlert,
    IPReputation,
    IncidentResponse,
    ResponseAction,
    Severity,
)

console = Console()


@dataclass
class RuleEvaluation:
    rule: PolicyRule
    status: str
    reasoning: str
    triggered_action: Optional[ResponseAction] = None

    @property
    def is_triggered(self) -> bool:
        return self.status == "triggered" and self.triggered_action is not None


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
    ) -> None:
        self._mitre_mapper = mitre_mapper or MITREMapper()
        self._verbose = verbose
        self._policy_config = policy_config or load_policy_config(policy_config_path)
        self._action_dispatcher = ActionDispatcher(
            config=self._policy_config.execution,
            action_executor=self._execute_action,
            queue_publisher=queue_publisher,
        )

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
        dispatch_outcome = self._action_dispatcher.dispatch(triggered_actions, enriched)
        action_results: list[ActionResult] = list(dispatch_outcome.action_results)

        # ── Phase 4: Unconditional — Ticket + Notify SOC ──────────────
        action_names = [a.value for a in triggered_actions]
        ticket_result, ticket_id = ticketing_action.execute(
            enriched_alert=enriched,
            triggered_actions=action_names,
            risk_score=enriched.risk_score,
            risk_level=enriched.risk_level,
        )
        action_results.append(ticket_result)

        notify_result = notify_soc_action.execute(
            alert_id=alert.alert_id,
            hostname=alert.hostname,
            risk_score=enriched.risk_score,
            risk_level=enriched.risk_level,
            triggered_actions=action_names,
            ticket_id=ticket_id,
        )
        action_results.append(notify_result)

        triggered_actions.append(ResponseAction.CREATE_TICKET)
        triggered_actions.append(ResponseAction.NOTIFY_SOC)

        # ── Phase 5: Build IncidentResponse ───────────────────────────
        response = IncidentResponse(
            enriched_alert=enriched,
            triggered_actions=triggered_actions,
            policy_reasoning=reasoning,
            action_results=action_results,
            ticket_id=ticket_id,
            completed_at=datetime.utcnow(),
            execution_trace=dispatch_outcome.execution_trace,
        )

        if self._verbose:
            self._print_summary(response)

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
            return isolate_host_action.execute(
                hostname=alert.hostname,
                alert_id=alert.alert_id,
                reason=(
                    f"Hash MALICIOUS: {enriched.hash_enrichment.threat_name or 'Unknown'} "
                    if enriched.hash_enrichment else "Malicious hash detected"
                ),
            )

        elif action == ResponseAction.KILL_PROCESS:
            return kill_process_action.execute(
                process_name=alert.process_name,
                hostname=alert.hostname,
                alert_id=alert.alert_id,
                command_line=alert.command_line,
                reason=f"Process '{alert.process_name}' in dangerous process blacklist",
            )

        elif action == ResponseAction.BLOCK_IP:
            return block_ip_action.execute(
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
            # Escalate không phải là call external action —
            # chỉ log và đánh dấu trong response
            logger.warning(
                f"[ACTION] ⬆️  ESCALATE: Host '{alert.hostname}' (critical asset) — "
                f"Alert escalated to HIGH priority for manual SOC review"
            )
            return ActionResult(
                action=ResponseAction.ESCALATE,
                status="success",
                executed_at=datetime.utcnow(),
                details=(
                    f"Alert escalated: Host '{alert.hostname}' là critical asset. "
                    f"Incident priority nâng lên HIGH. "
                    f"SOC Lead được notify để xử lý thủ công."
                ),
            )

        # Action không được nhận diện (không nên xảy ra)
        logger.error(f"[PolicyEngine] Unknown action: {action}")
        return None

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
                "Queueing"
                if self._policy_config.execution.mode == PolicyExecutionMode.QUEUED
                else "Executing"
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
        executed = [r for r in response.action_results if r.status == "success"]

        console.print(Panel(
            f"[bold]Alert ID:[/bold]  {alert.alert_id}\n"
            f"[bold]Ticket:[/bold]    {response.ticket_id or '—'}\n"
            f"[bold]Actions:[/bold]   {len(executed)} executed successfully\n"
            f"[bold]Completed:[/bold] {response.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"[bold]Reasoning:[/bold]\n" +
            "\n".join(f"  • {r}" for r in response.policy_reasoning),
            title="[magenta]✅ Bước 7 — Policy Engine Complete[/magenta]",
            border_style="green",
        ))
