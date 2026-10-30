---
id: contract-witnessed-outcome-credit
type: contract
domain: correctness
enforcement: advisory
hypothesis: "Evidence credit requires a linked, current witness rather than a positive caller assertion."
prediction: "Stale or unwitnessed reports can inflate rule fitness and turn a claim into apparent verification."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/credit.py"
  - "aegis_core/checkrun.py"
  - "aegis_mcp/handlers/telemetry.py"
  - "tests/unit/mcp/test_mcp_report_outcome.py"
---
## Do
Derive outcome credit from witnessed checks, current content and server-owned scan exposure; caller claims, persisted exposure rows and echoed rule IDs cannot manufacture verified success.

Preserve tree/commit, check, session and CI bindings, idempotency and claim caps. No applicable check, no collected passing test, timeout, unavailable execution and actual failure remain distinct. Optional compatibility arguments are not evidence.

Verify: Cover stale trees, fresh sessions, replayed keys, unknown rules, forged attribution, missing witnesses, zero-test runs and concurrent check/report selection through public reporting APIs.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/credit.py, checkrun.py and MCP telemetry implement witnessed evidence and server attribution.
- tests/unit/mcp/test_mcp_report_outcome.py: test_a_fresh_server_process_credits_nothing_from_persisted_exposure_rows; test_the_credited_rules_follow_the_check_chosen_under_the_lock.
- aegis_core/testexec.py: TestsRun.evidence requires timely exit zero and at least one passing test.
