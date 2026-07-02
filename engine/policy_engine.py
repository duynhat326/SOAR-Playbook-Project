"""
engine/policy_engine.py
=======================
Policy Engine — áp dụng response policy và thực thi actions.

Đây là bước 7 (bước cuối) trong workflow SOAR.

4 Rule gốc (từ spec mục 4, KHÔNG thay đổi):
  Rule 1: Hash malicious         → Isolate host
  Rule 2: Process nguy hiểm      → Kill process
  Rule 3: Asset criticality = critical → Escalate (High severity)
  Rule 4: IP đích gắn cờ C2     → Block IP

Ngoài ra luôn chạy (unconditional):
  - Create ticket (mọi alert đều tạo ticket)
  - Notify SOC   (mọi alert đều notify, level tùy risk)

Thiết kế:
  - Mỗi rule là 1 method riêng → dễ add/remove/modify rule
  - Rule có thể override nhau (policy precedence)
  - Trả về IncidentResponse đầy đủ với reasoning giải thích
"""

from datetime import datetime
from typing import List, Tuple

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
from schemas.alert import (
    ActionResult,
    AssetCriticality,
    EnrichedAlert,
    HashReputation,
    IPReputation,
    IncidentResponse,
    ResponseAction,
)

console = Console()


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
    ):
        self._mitre_mapper = mitre_mapper or MITREMapper()
        self._verbose = verbose

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
        triggered_actions: List[ResponseAction] = []
        reasoning: List[str] = []

        self._rule_1_hash_malicious(enriched, triggered_actions, reasoning)
        self._rule_2_dangerous_process(enriched, triggered_actions, reasoning)
        self._rule_3_critical_asset(enriched, triggered_actions, reasoning)
        self._rule_4_c2_ip(enriched, triggered_actions, reasoning)

        # ── Phase 2: In kết quả evaluation ───────────────────────────
        if self._verbose:
            self._print_evaluation_table(triggered_actions, reasoning, enriched)

        # ── Phase 3: Execute actions ──────────────────────────────────
        action_results: List[ActionResult] = []

        for action in triggered_actions:
            result = self._execute_action(action, enriched)
            if result:
                action_results.append(result)

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
        )

        if self._verbose:
            self._print_summary(response)

        return response

    # ──────────────────────────────────────────────────────────────────
    # Rule definitions — mỗi rule 1 method riêng để dễ đọc/test
    # ──────────────────────────────────────────────────────────────────

    def _rule_1_hash_malicious(
        self,
        enriched: EnrichedAlert,
        actions: List[ResponseAction],
        reasoning: List[str],
    ) -> None:
        """
        Rule 1: Nếu hash được đánh giá là MALICIOUS → Isolate host.

        Đây là rule nghiêm trọng nhất: hash malicious = confirmed malware,
        cần isolate ngay để ngăn lateral movement.
        """
        logger.debug("[PolicyEngine] Evaluating Rule 1: Hash malicious?")

        if enriched.hash_enrichment is None:
            reasoning.append("Rule 1 [SKIP]: Hash enrichment không có dữ liệu.")
            return

        if enriched.hash_enrichment.reputation == HashReputation.MALICIOUS:
            threat = enriched.hash_enrichment.threat_name or "Unknown threat"
            vendors = (f"{enriched.hash_enrichment.malicious_vendors}/"
                       f"{enriched.hash_enrichment.total_vendors}")
            actions.append(ResponseAction.ISOLATE_HOST)
            reasoning.append(
                f"Rule 1 [TRIGGERED]: Hash MALICIOUS ({vendors} vendors) → "
                f"Threat: '{threat}' → ACTION: ISOLATE_HOST"
            )
            logger.info("[PolicyEngine] Rule 1 TRIGGERED → ISOLATE_HOST")
        else:
            reasoning.append(
                f"Rule 1 [PASS]: Hash reputation = "
                f"{enriched.hash_enrichment.reputation.value} → no action"
            )

    def _rule_2_dangerous_process(
        self,
        enriched: EnrichedAlert,
        actions: List[ResponseAction],
        reasoning: List[str],
    ) -> None:
        """
        Rule 2: Nếu process_name nằm trong dangerous process blacklist → Kill process.

        Các process như mimikatz, psexec, nc.exe... không bao giờ nên
        chạy trên production host → kill ngay không cần hỏi.
        """
        logger.debug("[PolicyEngine] Evaluating Rule 2: Dangerous process?")

        process = enriched.original_alert.process_name
        if self._mitre_mapper.is_dangerous_process(process):
            actions.append(ResponseAction.KILL_PROCESS)
            reasoning.append(
                f"Rule 2 [TRIGGERED]: Process '{process}' nằm trong "
                f"dangerous process blacklist (MITRE ATT&CK mapped) → "
                f"ACTION: KILL_PROCESS"
            )
            logger.info(f"[PolicyEngine] Rule 2 TRIGGERED → KILL_PROCESS ({process})")
        else:
            reasoning.append(
                f"Rule 2 [PASS]: Process '{process}' không trong blacklist → no action"
            )

    def _rule_3_critical_asset(
        self,
        enriched: EnrichedAlert,
        actions: List[ResponseAction],
        reasoning: List[str],
    ) -> None:
        """
        Rule 3: Nếu asset criticality = CRITICAL → Escalate.

        Host critical (Domain Controller, Finance Server...) bị compromise
        là incident nghiêm trọng → cần escalate lên cấp cao hơn.
        """
        logger.debug("[PolicyEngine] Evaluating Rule 3: Critical asset?")

        if enriched.asset_criticality == AssetCriticality.CRITICAL:
            actions.append(ResponseAction.ESCALATE)
            reasoning.append(
                f"Rule 3 [TRIGGERED]: Host '{enriched.original_alert.hostname}' "
                f"có criticality = CRITICAL (high-value asset) → "
                f"ACTION: ESCALATE"
            )
            logger.info(
                f"[PolicyEngine] Rule 3 TRIGGERED → ESCALATE "
                f"(host={enriched.original_alert.hostname})"
            )
        else:
            reasoning.append(
                f"Rule 3 [PASS]: Asset criticality = "
                f"{enriched.asset_criticality.value} (not critical) → no action"
            )

    def _rule_4_c2_ip(
        self,
        enriched: EnrichedAlert,
        actions: List[ResponseAction],
        reasoning: List[str],
    ) -> None:
        """
        Rule 4: Nếu destination_ip được gắn cờ C2 → Block IP.

        Kết nối tới C2 server = active infection hoặc beaconing.
        Block ngay trên firewall để cắt kênh điều khiển.
        """
        logger.debug("[PolicyEngine] Evaluating Rule 4: C2 IP?")

        if enriched.ip_enrichment is None:
            reasoning.append("Rule 4 [SKIP]: IP enrichment không có dữ liệu.")
            return

        ip = enriched.original_alert.destination_ip
        if enriched.ip_enrichment.is_c2:
            confidence = enriched.ip_enrichment.confidence_score
            actions.append(ResponseAction.BLOCK_IP)
            reasoning.append(
                f"Rule 4 [TRIGGERED]: IP '{ip}' được gắn cờ C2 "
                f"(confidence={confidence}/100) → ACTION: BLOCK_IP"
            )
            logger.info(
                f"[PolicyEngine] Rule 4 TRIGGERED → BLOCK_IP ({ip})"
            )
        elif enriched.ip_enrichment.reputation == IPReputation.MALICIOUS:
            # Malicious nhưng không phải C2 → không block tự động,
            # chỉ ghi vào reasoning để SOC review
            reasoning.append(
                f"Rule 4 [PARTIAL]: IP '{ip}' là MALICIOUS nhưng chưa xác nhận C2 "
                f"(confidence={enriched.ip_enrichment.confidence_score}) → "
                f"no auto-block, SOC review needed"
            )
        else:
            reasoning.append(
                f"Rule 4 [PASS]: IP '{ip}' reputation = "
                f"{enriched.ip_enrichment.reputation.value} → no action"
            )

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
        triggered: List[ResponseAction],
        reasoning: List[str],
        enriched: EnrichedAlert,
    ) -> None:
        """In bảng tóm tắt kết quả evaluation 4 rules."""
        table = Table(
            title="Policy Evaluation Results",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Rule", width=8)
        table.add_column("Condition", width=32)
        table.add_column("Result", width=10)
        table.add_column("Action", width=18)

        rules_info = [
            ("Rule 1", "Hash MALICIOUS?",             ResponseAction.ISOLATE_HOST),
            ("Rule 2", "Dangerous process blacklist?", ResponseAction.KILL_PROCESS),
            ("Rule 3", "Asset CRITICAL?",             ResponseAction.ESCALATE),
            ("Rule 4", "IP is C2?",                   ResponseAction.BLOCK_IP),
        ]

        for rule_label, condition, action in rules_info:
            fired = action in triggered
            status = "[green]PASS[/green]" if not fired else "[red]TRIGGERED[/red]"
            action_text = (
                f"[red]{action.value}[/red]" if fired
                else "[dim]—[/dim]"
            )
            table.add_row(rule_label, condition, status, action_text)

        console.print(table)

        if triggered:
            console.print(
                f"\n[bold red]⚡ {len(triggered)} rule(s) triggered → "
                f"Executing: {', '.join(a.value for a in triggered)}[/bold red]"
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
