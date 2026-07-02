# Phase 3 / Phase 6 Policy Boundary Notes

Author: `codex-policy`

## Decisions

1. Policy config is now stricter policy-as-data.
   - Added an `execution` block to the policy schema and default YAML.
   - Validates supported `condition_type` values, required `matches.value` fields, and unique `rule_id` values.
   - Invalid or unreadable policy files still fall back to `DEFAULT_POLICY_CONFIG`.

2. Queue preparation is behind an explicit dispatch boundary.
   - Added `engine/action_dispatcher.py` to isolate remediation dispatch from rule evaluation.
   - Default mode remains `sync`, so current behavior is unchanged unless config opts into `queued`.
   - Queue mode produces correlation-aware queue envelopes using `correlation_prefix:alert_id:action`.

3. Safe fallback is on by default for queue mode.
   - If `execution.mode=queued` but no queue publisher is registered, remediation actions execute synchronously when `fallback_to_sync=true`.
   - The response records this as `execution_trace.effective_mode=sync_fallback`.

4. Queue scaffolding is intentionally limited to remediation actions for now.
   - `create_ticket` and `notify_soc` remain synchronous and unconditional to keep the current workflow stable.
   - The queue seam is ready for a later worker implementation without changing the policy evaluation contract again.

## Verification

- `pytest tests/test_policy_loader.py tests/test_policy_engine.py tests/test_workflow_service.py`
- `pytest tests/test_api_app.py tests/test_sqlite_repository.py`
