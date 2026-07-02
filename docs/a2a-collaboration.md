# A2A Collaboration Setup

This repo now includes a local agent-to-agent collaboration bus for Codex, Claude, Gemini, or any other tool that can run shell commands or call the FastAPI app.

## What was added

- Shared SQLite bus at `output/a2a/a2a_bus.db` by default
- Collaboration service in `a2a/`
- REST endpoints under `/api/v1/a2a/*`
- Local CLI at `python -m a2a.cli`
- Timeline storage for agents, tasks, messages, and artifacts

The design goal is portability. Different coding agents do not need native tab-to-tab integration if they can all read and write the same bus.

## Default model

- A `workspace` is one shared room, for example `incident-2026-07-02`
- An `agent` is one tab or one tool instance, for example `codex-lead`, `claude-review`, `gemini-research`
- A `task` is a unit of work that can be claimed and completed
- A `message` is direct or broadcast communication between agents
- An `artifact` is a file path, patch, note, report, or other output linked back to a task

## Option 1: Use the CLI only

This is the simplest setup for multiple tabs on the same machine.

```powershell
python -m a2a.cli ensure-workspace --workspace incident-2026-07-02

python -m a2a.cli register-agent `
  --workspace incident-2026-07-02 `
  --agent-id codex-lead `
  --platform codex `
  --role coordinator `
  --capability plan `
  --capability review

python -m a2a.cli register-agent `
  --workspace incident-2026-07-02 `
  --agent-id claude-review `
  --platform claude `
  --role reviewer `
  --capability analysis

python -m a2a.cli register-agent `
  --workspace incident-2026-07-02 `
  --agent-id gemini-research `
  --platform gemini `
  --role researcher `
  --capability docs `
  --capability ideation
```

Create and assign work:

```powershell
python -m a2a.cli create-task `
  --workspace incident-2026-07-02 `
  --title "Review A2A integration points" `
  --description "Check API and workflow boundaries before editing." `
  --requested-by codex-lead `
  --priority high `
  --label review
```

Workers can poll open tasks:

```powershell
python -m a2a.cli list-tasks --workspace incident-2026-07-02 --status open
python -m a2a.cli claim-task --task-id task-xxxxxxxxxx --agent-id claude-review
```

Send messages:

```powershell
python -m a2a.cli send-message `
  --workspace incident-2026-07-02 `
  --sender-agent codex-lead `
  --recipient-agent claude-review `
  --task-id task-xxxxxxxxxx `
  --kind brief `
  --content "Audit for regressions first. Keep the existing SOAR pipeline behavior unchanged."
```

Read inbox:

```powershell
python -m a2a.cli poll-messages `
  --workspace incident-2026-07-02 `
  --agent-id claude-review `
  --limit 20
```

Publish results and close the task:

```powershell
python -m a2a.cli publish-artifact `
  --workspace incident-2026-07-02 `
  --author-agent claude-review `
  --task-id task-xxxxxxxxxx `
  --kind review `
  --uri docs/review-notes.md `
  --summary "Main risks and required fixes."

python -m a2a.cli complete-task `
  --task-id task-xxxxxxxxxx `
  --agent-id claude-review `
  --summary "Review finished and handed back to codex-lead."
```

Watch the shared timeline:

```powershell
python -m a2a.cli timeline --workspace incident-2026-07-02 --limit 50
```

## Option 2: Use the FastAPI service

Start the API:

```powershell
uvicorn api.app:app --reload
```

Relevant endpoints:

- `GET /api/v1/a2a/health`
- `POST /api/v1/a2a/workspaces`
- `POST /api/v1/a2a/agents/register`
- `POST /api/v1/a2a/agents/{agent_id}/heartbeat`
- `GET /api/v1/a2a/agents?workspace=...`
- `POST /api/v1/a2a/tasks`
- `GET /api/v1/a2a/tasks?workspace=...`
- `POST /api/v1/a2a/tasks/{task_id}/claim`
- `POST /api/v1/a2a/tasks/{task_id}/complete`
- `POST /api/v1/a2a/messages`
- `GET /api/v1/a2a/messages?workspace=...&agent_id=...`
- `POST /api/v1/a2a/artifacts`
- `GET /api/v1/a2a/timeline?workspace=...`

This is useful if you want a dashboard or a future MCP wrapper to interact with the bus over HTTP.

## Shared DB path

By default the bus uses:

```text
output/a2a/a2a_bus.db
```

To point all tools at another shared file:

```powershell
$env:SOAR_A2A_DB_PATH="C:\path\to\shared\a2a_bus.db"
```

Every Codex, Claude, and Gemini tab must use the same DB path.

## Recommended collaboration pattern

1. Pick one coordinator, usually `codex-lead`.
2. Register every tab as a separate agent ID.
3. Create narrow tasks with a clear owner.
4. Use messages for brief handoffs and clarification.
5. Publish artifacts as file paths back into the repo.
6. Complete tasks when the result is ready for the next agent.
7. Use the timeline as the single audit log.

## Practical notes

- This is a repo-local collaboration layer, not a full implementation of the public Google A2A protocol.
- It is enough to coordinate multiple agent tabs and multiple model providers on one machine or over a shared filesystem.
- If you later want strict protocol interoperability, this bus is a good internal backbone and can sit behind an MCP server or HTTP adapter.
