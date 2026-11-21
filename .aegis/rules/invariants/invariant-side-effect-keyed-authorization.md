---
id: invariant-side-effect-keyed-authorization
domain: security
type: invariant
enforcement: gate
hypothesis: "An authorization gate keyed on caller-supplied flags rather than on the side effect lets a caller reach a guarded write through an argument the gate does not inspect, such as an alias or an always-true disjunct"
prediction: "Every permission or exemption predicate in an MCP handler or CLI writer is computed after argument normalization, denies by default and has a negative test per alias"
falsification: "0 findings in 15 sessions: prune"
expiry_sessions: 15
expiry_days: 60
created: "2026-10-15T16:11:58Z"
impact_weight: 1.0
tags: ["debrief", "citadel", "authorization"]
target_paths: ["aegis_mcp/server.py", "aegis_mcp/handlers/governance.py", "aegis_mcp/handlers/telemetry.py", "aegis_mcp/registry.py", "tests/unit/mcp/**"]
lineage:
  parent_id: null
  created_by: "manual"
  generation: 0
  siblings: []
---
# Invariant: authorize the side effect, not the flags

**Rule**: Any authorization, exemption or permission predicate is derived from
the post-normalization argument set and defaults to deny. A call may skip a
check only when no argument that can reach a filesystem or rule-tier write is
present. Every disjunct of an exemption must be falsifiable by a test, and each
exemption needs a negative test that sends every alias of a guarded argument.

## Incident (v4 Citadel review)

- The receipt gate for `aegis_capture_insight` (aegis_mcp/server.py) inspected
  only scaffold flags, but the insight writer also accepted an identifier alias
  that created gate-tier rules. Argument normalization mapped `rule_id` to that
  unchecked identifier. A receiptless
  call with `rule_id='pwn'` created an attacker-controlled gate rule.
- The `telemetry_keys` check of `aegis_report_outcome` was made vacuous by an
  always-true `or os.path.isdir(workspace)` disjunct, so receiptless fitness
  writes were accepted.
- It was missed because the gate and the writer disagreed about which arguments
  trigger a write and no test crossed that seam: mutating the scaffold guard to
  `if False:` or dropping the `isdir` disjunct left the suite green.

v4.0 deleted the receipts and the insight tool (D2, D4). The rule still binds
every remaining gate: the four MCP handlers, the CLI writers and the hook safety
gate.

## Check

1. Name the writer the predicate protects and list every argument, including
   every alias after normalization, that reaches it.
2. The predicate reads the normalized arguments and denies by default.
3. For each guarded argument and alias, a test sends it without authorization
   and asserts nothing was written (no rule file, no ledger row).
4. Mutate each disjunct (`if False:`, drop the clause): some test must fail.
