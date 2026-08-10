# Security Issues Tracker

Updated: 2026-08-10

This file tracks security findings identified during the current EDR/SOAR review so remediation can be followed in one place.

## Status Summary

| ID | Severity | Status | Title |
| --- | --- | --- | --- |
| SEC-001 | High | Fixed in current branch, pending deploy | Audit identity spoofing via request body |
| SEC-002 | Medium | Fixed in current branch, pending deploy | Workspace scoping is defined in auth tokens but not enforced by API routes |
| SEC-003 | Low/Medium | Fixed in current branch, pending deploy | Unbounded text and filter payload sizes can be abused for storage or request amplification |
| SEC-004 | Low | Fixed in current branch, pending deploy | Pentest script is not hermetic when live intel mode is enabled |

## SEC-001 - Audit identity spoofing via request body

- Severity: High
- Status: Fixed in current branch, pending deploy
- Affected area:
  [api/app.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/api/app.py),
  [api/schemas.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/api/schemas.py)
- Impact:
  Any authenticated operator with a valid token could submit a forged `author`, `actor`, or `created_by` value and make notes, approval actions, rollback actions, or saved filters appear to come from another identity.
- Root cause:
  The API trusted identity-like fields from the request body instead of treating the bearer-authenticated principal as the source of truth.
- Fixed behavior:
  Backend now resolves actor identity from the authenticated principal.
  If the request explicitly provides `author`, `actor`, or `created_by` and it does not match the authenticated principal, the API returns `403`.
- Verification:
  Regression coverage added in [tests/test_api_app.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/tests/test_api_app.py).
  `pytest tests/test_api_app.py tests/test_security_regressions.py -q` passed.
- Follow-up:
  Deploy the fix to all environments.
  Review any external clients or dashboards that still send identity fields redundantly.

## SEC-002 - Workspace scoping is defined in auth tokens but not enforced by API routes

- Severity: Medium
- Status: Fixed in current branch, pending deploy
- Affected area:
  [security/auth.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/security/auth.py),
  [api/app.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/api/app.py)
- Impact:
  The token model contains `workspaces`, but the reviewed API routes are authorized by role only.
  If the platform evolves into a real multi-tenant or multi-workspace deployment, a token may be able to access incidents outside its intended scope.
- Root cause:
  Workspace information is loaded into the authenticated principal, but route handlers and repository access paths do not currently use it as an authorization boundary.
- Fixed behavior:
  Alerts, incidents, and saved filters now persist a canonical `workspace`.
  Incident reads, mutations, correlation lookups, and saved-filter listing are scoped to the authenticated principal workspace set.
  Cross-workspace detail lookups are hidden with `404`.
- Verification:
  Regression coverage added in [tests/test_api_app.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/tests/test_api_app.py).
  `python scripts/run_pentest.py --output-root output/pentest --report-path docs/pentest-report-2026-08-10.md` passed with `PT-03`.

## SEC-003 - Unbounded text and filter payload sizes can be abused for storage or request amplification

- Severity: Low/Medium
- Status: Fixed in current branch, pending deploy
- Affected area:
  [api/schemas.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/api/schemas.py),
  [storage/sqlite_repository.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/storage/sqlite_repository.py)
- Impact:
  Fields such as note bodies, approval comments, reopen comments, case comments, and saved filter payloads do not currently have explicit size limits.
  A valid authenticated user can submit oversized payloads that bloat storage, logs, and response bodies.
- Root cause:
  Request models validate structure but not practical size boundaries.
- Fixed behavior:
  Analyst-entered note, comment, owner, actor, and saved-filter fields now enforce explicit length limits.
  Saved filters also enforce JSON shape, nesting, and serialized-size limits.
- Verification:
  Regression coverage added in [tests/test_api_app.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/tests/test_api_app.py).
  `python scripts/run_pentest.py --output-root output/pentest --report-path docs/pentest-report-2026-08-10.md` passed with `PT-04`.

## SEC-004 - Pentest script is not hermetic when live intel mode is enabled

- Severity: Low
- Status: Fixed in current branch, pending deploy
- Affected area:
  [scripts/run_pentest.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/scripts/run_pentest.py),
  [enrichment/virustotal_client.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/enrichment/virustotal_client.py)
- Impact:
  The pentest script can fail in restricted or offline environments because it follows the currently configured live threat-intel provider and attempts outbound VirusTotal requests.
  This makes security regression checks less deterministic.
- Root cause:
  The script relies on ambient runtime provider configuration instead of forcing mock-safe test dependencies.
- Observed behavior:
  The script failed under restricted outbound networking when `SOAR_INTEL_PROVIDER=virustotal`.
  The same script passed when rerun with `SOAR_INTEL_PROVIDER=mock`.
- Fixed behavior:
  `scripts/run_pentest.py` now forces mock-safe provider settings for threat intel, CMDB, action, ticketing, and database connectors during the run.
- Verification:
  Regression coverage added in [tests/test_security_regressions.py](C:/Users/duynh/Documents/Code/Project/SOAR Playbook/tests/test_security_regressions.py).
  The pentest runner passes even when ambient env vars point `SOAR_INTEL_PROVIDER` at live providers.

## Suggested Next Order

1. Deploy the SEC-001, SEC-002, SEC-003, and SEC-004 fixes.
2. Re-run the updated pentest suite in each deployment environment after rollout.
3. If multi-workspace support expands further, extend the same boundary checks to any new API or dashboard surfaces.
