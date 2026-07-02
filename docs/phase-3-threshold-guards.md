# Phase 3 Threshold and Guard Notes

Author: `codex-policy`

## Scope

Advance policy-as-data with threshold-style rule controls and one focused guard that fits the current alert schema, while preserving shipped behavior under the default policy file.

## Decisions

1. Rules now support explicit threshold gates.
   - Added `thresholds.min_risk_score` and `thresholds.min_severity` to the policy schema.
   - Thresholds are evaluated before the rule condition. If the alert does not meet the configured threshold, the rule returns `passed` with explanatory reasoning and does not trigger its action.

2. Rules now support one focused suppression guard.
   - Added `guards.username_allowlist` to the policy schema.
   - If the alert `username` matches the allowlist for that rule, the rule returns `passed` with explanatory reasoning and does not trigger its action.
   - Validation rejects empty usernames and case-insensitive duplicates, which keeps the existing safe fallback behavior intact.

3. Default behavior remains backward-compatible.
   - Shipped defaults are no-op values: `min_risk_score: 0.0`, `min_severity: low`, and `username_allowlist: []`.
   - Existing rules therefore behave the same unless a deployment explicitly opts into tighter thresholds or per-rule username suppression.

4. Queue-ready boundaries stay stable.
   - No queue contract, correlation payload, or sync-default execution path changed in this task.
   - Thresholds and guards only affect whether a rule reaches its existing action path.

## Compatibility assumptions

- The current alert context already exposes `username`, `severity`, and `risk_score`, so the new controls fit the existing schema without widening API or service contracts.
- Guard matching is case-insensitive for duplicate validation but uses the configured usernames as-authored in the policy file for readability.
- Invalid threshold or guard config still falls back to `DEFAULT_POLICY_CONFIG`, matching the existing loader safety model.

## Verification

Command run:

```text
pytest tests/test_policy_loader.py tests/test_policy_engine.py
```

Exact result:

- `32 passed`
- `270 warnings`

Command run:

```text
pytest tests/test_workflow_service.py tests/test_sqlite_repository.py tests/test_api_app.py -k "not test_process_scenario_replays_existing_incident_without_new_side_effects"`
```

Exact result:

- `15 passed`
- `1 deselected`
- `192 warnings`

## Notes

- The adjacent compatibility sweep intentionally excludes `test_process_scenario_replays_existing_incident_without_new_side_effects`, which is a replay-timestamp issue outside this policy task.
