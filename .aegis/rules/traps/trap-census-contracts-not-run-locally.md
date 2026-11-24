---
id: trap-census-contracts-not-run-locally
domain: efficiency
type: trap
enforcement: advisory
hypothesis: A change sent to remote qualification without the census contracts run locally loses a full round to a failure a short local run would have shown.
prediction: Running the census contracts locally first removes those failures from the remote run.
falsification: Retire if ten remote qualification runs in a row show no census-contract failure.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:54Z"
impact_weight: 1.0
tags:
  - test_creation
  - python_file_creation
target_paths:
  - "tests/contract/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Before requesting a remote qualification run, run the census contracts locally: module size, private imports, monkeypatch and the retired-vocabulary ratchet.

Running the census contracts locally first removes those failures from the remote run.

These contracts judge new code and tests wherever they sit, so a focused selection of the changed files does not cover them.

## Evidence

- 2026-11-14 — Three changes each lost a remote round to the monkeypatch census.
- 2026-11-23 — A retired-vocabulary offender was found only by the remote run.

Catalog comparison: nearest is trap-local-green-ci-red; this names the specific contracts to run.
