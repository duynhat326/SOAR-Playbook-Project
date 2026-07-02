# Three-Codex Team Setup

This is the recommended split if you want 3 Codex agents to push this repo forward in parallel with minimal file conflicts.

## Team split

### 1. `codex-lead`

Responsibility:

- Own the architecture direction
- Keep `main.py`, `dashboard/src/App.tsx`, and `api/app.py` stable
- Review the work from the other two agents
- Merge interface changes into the shared service layer
- Run regression tests before handoff

Primary scope:

- `services/`
- `api/`
- high-level docs
- integration and test repair

Definition of done:

- Other agents can work without stepping on each other
- Shared interfaces are coherent
- Final branch passes the full test suite

### 2. `codex-persistence`

Responsibility:

- Deliver Phase 2 from the roadmap

Primary scope:

- `storage/` or `repositories/`
- persistence schema
- workflow result persistence
- query APIs for incidents and reports

Concrete backlog:

1. Add SQLite-backed repositories for `alerts`, `incidents`, `action_results`, and `reports`.
2. Persist workflow outputs right after `SoarWorkflowService.process_alert`.
3. Add idempotency by `alert_id`.
4. Add read paths for lookup by `alert_id` and `ticket_id`.
5. Add tests for persistence and API reads.

Definition of done:

- Re-running the same alert does not create duplicate incidents
- Incidents can be queried after processing

### 3. `codex-policy`

Responsibility:

- Deliver Phase 3 first, then lay the Phase 6 scaffold

Primary scope:

- `engine/policy_engine.py`
- `policies/`
- queue or worker boundary interfaces
- config validation and fallback behavior

Concrete backlog:

1. Move hardcoded rules into `policies/response_rules.yaml`.
2. Add schema validation and a safe fallback.
3. Keep current behavior unchanged under the default config.
4. Introduce queue-ready boundaries so ingestion and execution can split later.
5. Add correlation hook points for `hostname`, `username`, `file_hash`, `destination_ip`.

Definition of done:

- Rules can be changed through config
- Current sync flow still works
- Async split can be added later without rewriting the pipeline

## Why this split works

- `codex-persistence` mostly touches storage and read-side APIs.
- `codex-policy` mostly touches the policy engine and new config files.
- `codex-lead` absorbs interface churn and keeps the entrypoints aligned.

That minimizes merge conflicts while still moving the roadmap forward.

## One-command bootstrap

Run this from the repo root:

```powershell
.\scripts\bootstrap-3-codex-team.ps1
```

If Windows blocks local PowerShell scripts on your machine, use:

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\scripts\bootstrap-3-codex-team.ps1 -Workspace soar-sprint-01
```

That will:

- create a new A2A workspace
- register 3 Codex agents
- seed the initial tasks
- post kickoff messages to the worker agents

If you want a custom workspace name:

```powershell
.\scripts\bootstrap-3-codex-team.ps1 -Workspace soar-sprint-01
```

## What to put in each Codex tab

### Tab 1

Identity:

```text
codex-lead
```

First prompt:

```text
You are codex-lead for workspace soar-sprint-01. Read docs/upgrade-roadmap.md and docs/three-codex-team.md. Use the A2A bus to coordinate the sprint, review worker outputs, and keep shared interfaces stable. Start by listing tasks, reading your assigned task, and posting a short kickoff plan to the timeline.
```

### Tab 2

Identity:

```text
codex-persistence
```

First prompt:

```text
You are codex-persistence for workspace soar-sprint-01. Your scope is Phase 2 only: persistence layer, workflow result storage, idempotency, and incident query APIs. Before editing, read your task from the A2A bus, claim it if needed, and post progress updates back through the bus.
```

### Tab 3

Identity:

```text
codex-policy
```

First prompt:

```text
You are codex-policy for workspace soar-sprint-01. Your scope is Phase 3 first, then Phase 6 scaffold: policy-as-data, validation, safe fallback, and queue-ready boundaries. Preserve current behavior under default config. Read your assigned task from the A2A bus and post artifacts for every major decision.
```

## Operating rules for the 3-agent sprint

1. The lead owns shared interfaces and final integration.
2. Worker agents stay inside their scope unless the lead reassigns work.
3. Every meaningful handoff must include:
   - a message
   - an artifact path
   - a task completion summary
4. Before changing shared files, workers should notify the lead through the bus.
5. The lead runs the full tests before accepting completed work.

## Useful commands

```powershell
python -m a2a.cli list-tasks --workspace soar-sprint-01
python -m a2a.cli poll-messages --workspace soar-sprint-01 --agent-id codex-lead
python -m a2a.cli poll-messages --workspace soar-sprint-01 --agent-id codex-persistence
python -m a2a.cli poll-messages --workspace soar-sprint-01 --agent-id codex-policy
python -m a2a.cli timeline --workspace soar-sprint-01 --limit 50
```
