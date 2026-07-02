# Multi-Agent Playbook

Use this repo-local bus when several agent tabs are working on the same task.

## Conventions

- One incident or feature branch maps to one `workspace`
- One tab maps to one `agent_id`
- The coordinator creates tasks
- Workers claim tasks before editing
- All handoffs happen through messages and artifacts

## Minimal flow

```powershell
python -m a2a.cli ensure-workspace --workspace incident-2026-07-02
python -m a2a.cli register-agent --workspace incident-2026-07-02 --agent-id codex-lead --platform codex --role coordinator
python -m a2a.cli register-agent --workspace incident-2026-07-02 --agent-id claude-review --platform claude --role reviewer
python -m a2a.cli register-agent --workspace incident-2026-07-02 --agent-id gemini-research --platform gemini --role researcher
```

Coordinator:

```powershell
python -m a2a.cli create-task --workspace incident-2026-07-02 --title "Research" --requested-by codex-lead
python -m a2a.cli send-message --workspace incident-2026-07-02 --sender-agent codex-lead --recipient-agent gemini-research --content "Collect references and propose options."
```

Worker:

```powershell
python -m a2a.cli list-tasks --workspace incident-2026-07-02 --status open
python -m a2a.cli poll-messages --workspace incident-2026-07-02 --agent-id gemini-research
```

Handoff:

```powershell
python -m a2a.cli publish-artifact --workspace incident-2026-07-02 --author-agent gemini-research --kind note --uri docs/a2a-collaboration.md --summary "Research notes."
python -m a2a.cli complete-task --task-id task-xxxxxxxxxx --agent-id gemini-research --summary "Research done."
```
