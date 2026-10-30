---
id: trap-schema-contract-drift
domain: correctness
type: trap
enforcement: advisory
promotion_threshold: 0.85
demotion_threshold: 0.3
hypothesis: "JSONL producer/consumer pairs in separate module files use mismatched field names, causing silent data loss in the fitness pipeline"
prediction: Will catch field name mismatches between module files that read/write the same JSONL ledger files
falsification: 0 findings in 10 sessions → prune
target_paths:
  - "aegis_core/*.py"
  - "aegis_core/*.py"
  - "aegis_mcp/*.py"
  - "aegis_cli/*.py"
triggers:
  - module_modification
  - pipeline_change
expiry_sessions: 10
expiry_days: 30
created: 2026-09-30
impact_weight: 1.0
tags:
  - pipeline
  - schema
  - silent-failure
---

When modifying a module that writes to a JSONL file (fitness.jsonl,
sessions_processed.jsonl, outcomes.jsonl), grep for ALL consumers of that
file and verify field names match.

Known incident: `fitness_updater.py` emitted `{triggered_at}` but
`oracle_checkpoint.py` consumed `{triggered}` — 100% of records silently
dropped, rendering the entire fitness loop inoperative.

Citadel C1 incident: `aegis_mcp/tools.py` wrote outcomes to `.aegis/outcomes.jsonl`
with `{rules_used: [...]}` while `lifecycle.py` read from `.aegis/evidence/outcomes.jsonl`
with `{rule_id: str}` — 100% of MCP-reported outcomes silently ignored.
