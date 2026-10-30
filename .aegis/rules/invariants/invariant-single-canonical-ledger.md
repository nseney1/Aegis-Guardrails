---
id: invariant-single-canonical-ledger
domain: correctness
type: invariant
enforcement: gate
hypothesis: "A ledger with two candidate files, unlocked read-modify-write, intolerant reads or random idempotency keys silently loses, duplicates or inflates outcome records"
prediction: "Every ledger reader and writer resolves one path from WorkspaceLayout, mutates it only under evidence_lock, reads bad bytes line by line and uses deterministic or required idempotency keys"
falsification: "0 findings in 15 sessions: prune"
expiry_sessions: 15
expiry_days: 60
created: "2026-10-15T16:11:59Z"
impact_weight: 1.0
tags: ["debrief", "citadel", "ledger", "locking"]
target_paths:
  - "aegis_core/telemetry_engine/ledger.py"
  - "aegis_core/storage.py"
  - "tests/unit/core/test_ledger*.py"
  - "tests/unit/core/test_shared_ledger.py"
  - "tests/helpers_ledgerrace.py"
lineage:
  parent_id: null
  created_by: "manual"
  generation: 0
  siblings: []
---
## Do
Resolve one shared ledger through ledger_site and mutate it under ledger_locked; preserve append-only rows, ordered lock ownership and stable idempotency identity for each logical report.

Worktrees share the repository ledger while retaining attribution. Replays of one report must not add credit, and conflicting payloads under one key must fail. Decode legacy/malformed rows according to the canonical reader without rewriting history; use one coherent view for a calculation.

Verify: Exercise interleaved worktree writers, replay/conflict keys, BOM/bad/torn rows, legacy versions and fresh versus retained snapshots through public ledger/storage calls.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/telemetry_engine/ledger.py documents ledger_site, ledger_locked, shared worktree attribution and the (key, rule) identity.
- tests/unit/core/test_shared_ledger.py and test_ledger_merge.py cover sharing/idempotency; test_scan_ledger_reads.py covers coherent snapshots.
- This replaces obsolete WorkspaceLayout/evidence_lock-only guidance without changing ledger implementation.
