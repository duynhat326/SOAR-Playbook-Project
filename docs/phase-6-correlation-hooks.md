# Phase 6 Correlation Hook Notes

Author: `codex-policy`

## Scope

Follow-up on the queue-ready remediation boundary to emit explicit correlation hook data for:

- `hostname`
- `username`
- `file_hash`
- `destination_ip`

Default synchronous behavior remains unchanged.

## Decisions

1. Correlation strategy is config-driven.
   - Added `execution.queue.correlation_fields` to the policy schema and default policy YAML.
   - Default value follows the roadmap order: `hostname`, `username`, `file_hash`, `destination_ip`.
   - Validation rejects empty or duplicate correlation field lists, which triggers the existing safe fallback to built-in defaults when loading policy config.

2. Queue envelopes now carry explicit correlation metadata.
   - Added `CorrelationHook` and attached `correlation_hooks` to each `QueuedActionRequest`.
   - `correlation_id` and `deduplication_key` stay unchanged as `correlation_prefix:alert_id:action` to avoid changing current queue boundary behavior.
   - Workers can now consume the explicit hook list without reverse-engineering alert context from free-form payloads.

3. Sync-default behavior is preserved.
   - Sync mode still executes remediation directly.
   - Queued mode still falls back to sync when no publisher is registered and `fallback_to_sync=true`.
   - The new correlation hooks are emitted only on queued request metadata and execution trace artifacts.

## Verification

- `pytest tests/test_policy_loader.py tests/test_policy_engine.py`
- `pytest tests/test_workflow_service.py tests/test_api_app.py tests/test_sqlite_repository.py`
