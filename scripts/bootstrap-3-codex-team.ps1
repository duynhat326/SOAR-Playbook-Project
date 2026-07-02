param(
    [string]$Workspace = ("soar-dev-" + (Get-Date -Format "yyyyMMdd-HHmmss")),
    [string]$LeaderAgent = "codex-lead",
    [string]$PersistenceAgent = "codex-persistence",
    [string]$PolicyAgent = "codex-policy",
    [switch]$SkipTasks
)

$ErrorActionPreference = "Stop"

function Invoke-A2A {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    & python -m a2a.cli @Args
    if ($LASTEXITCODE -ne 0) {
        throw "A2A command failed with exit code ${LASTEXITCODE}: python -m a2a.cli $($Args -join ' ')"
    }
}

Write-Host ""
Write-Host "Bootstrapping 3-agent Codex workspace: $Workspace" -ForegroundColor Cyan
Write-Host ""

Invoke-A2A -Args @("ensure-workspace", "--workspace", $Workspace) | Out-Host

Invoke-A2A -Args @(
    "register-agent",
    "--workspace", $Workspace,
    "--agent-id", $LeaderAgent,
    "--platform", "codex",
    "--role", "leader",
    "--capability", "architecture",
    "--capability", "integration",
    "--capability", "review"
) | Out-Host

Invoke-A2A -Args @(
    "register-agent",
    "--workspace", $Workspace,
    "--agent-id", $PersistenceAgent,
    "--platform", "codex",
    "--role", "persistence-engineer",
    "--capability", "sqlite",
    "--capability", "repositories",
    "--capability", "fastapi"
) | Out-Host

Invoke-A2A -Args @(
    "register-agent",
    "--workspace", $Workspace,
    "--agent-id", $PolicyAgent,
    "--platform", "codex",
    "--role", "automation-engineer",
    "--capability", "policy",
    "--capability", "yaml-config",
    "--capability", "background-workers"
) | Out-Host

if (-not $SkipTasks) {
    Invoke-A2A -Args @(
        "create-task",
        "--workspace", $Workspace,
        "--title", "Lead sprint: architecture, integration guardrails, and final merge",
        "--description", "Own the sprint board. Keep CLI/dashboard/API stable while other agents change persistence and policy layers. Review interfaces, integrate branches, close regressions, and run the final test sweep.",
        "--requested-by", $LeaderAgent,
        "--assigned-to", $LeaderAgent,
        "--priority", "critical",
        "--label", "lead",
        "--label", "integration",
        "--label", "review"
    ) | Out-Host

    Invoke-A2A -Args @(
        "create-task",
        "--workspace", $Workspace,
        "--title", "Phase 2: persistence layer and incident query APIs",
        "--description", "Add storage or repositories for alerts, incidents, action_results, and reports. Persist workflow results, add idempotency by alert_id, and expose read APIs to query by alert_id or ticket_id.",
        "--requested-by", $LeaderAgent,
        "--assigned-to", $PersistenceAgent,
        "--priority", "high",
        "--label", "phase-2",
        "--label", "storage",
        "--label", "api"
    ) | Out-Host

    Invoke-A2A -Args @(
        "create-task",
        "--workspace", $Workspace,
        "--title", "Phase 3 and 6 scaffold: policy as data plus async execution prep",
        "--description", "Move response rules into config, add schema validation and fallback behavior, then scaffold worker queue boundaries and correlation hooks without breaking the synchronous path.",
        "--requested-by", $LeaderAgent,
        "--assigned-to", $PolicyAgent,
        "--priority", "high",
        "--label", "phase-3",
        "--label", "phase-6",
        "--label", "policy",
        "--label", "async"
    ) | Out-Host

    Invoke-A2A -Args @(
        "send-message",
        "--workspace", $Workspace,
        "--sender-agent", $LeaderAgent,
        "--recipient-agent", $PersistenceAgent,
        "--kind", "kickoff",
        "--content", "Work inside Phase 2 only first. Touch service and API surfaces carefully, keep backward compatibility, and publish artifacts for every migration or schema decision."
    ) | Out-Host

    Invoke-A2A -Args @(
        "send-message",
        "--workspace", $Workspace,
        "--sender-agent", $LeaderAgent,
        "--recipient-agent", $PolicyAgent,
        "--kind", "kickoff",
        "--content", "Start with policy-as-data before async work. Keep the current policy behavior identical under default config, and leave the sync execution path intact."
    ) | Out-Host
}

Write-Host ""
Write-Host "Workspace ready: $Workspace" -ForegroundColor Green
Write-Host ""
Write-Host "Open 3 Codex tabs and assign these identities:" -ForegroundColor Yellow
Write-Host "  1. $LeaderAgent"
Write-Host "  2. $PersistenceAgent"
Write-Host "  3. $PolicyAgent"
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Yellow
Write-Host "  python -m a2a.cli list-agents --workspace $Workspace"
Write-Host "  python -m a2a.cli list-tasks --workspace $Workspace"
Write-Host "  python -m a2a.cli poll-messages --workspace $Workspace --agent-id $PersistenceAgent"
Write-Host "  python -m a2a.cli poll-messages --workspace $Workspace --agent-id $PolicyAgent"
Write-Host "  python -m a2a.cli timeline --workspace $Workspace --limit 30"
