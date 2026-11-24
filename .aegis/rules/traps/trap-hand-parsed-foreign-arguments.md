---
id: trap-hand-parsed-foreign-arguments
domain: security
type: trap
enforcement: advisory
hypothesis: "A hand-written reader of another tool's arguments or configuration grammar disagrees with that tool on some form, and the disagreement becomes an allow decision."
prediction: "Classifying with the owning tool's parser and refusing what it cannot classify closes the escape forms together."
falsification: "Retire if ten allow-or-refuse decisions over foreign arguments each use the owning tool's parser and refuse unclassified input."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:50Z"
impact_weight: 1.0
tags:
  - security_review
  - python_file_modification
target_paths:
  - "aegis_core/**"
  - tests/contract/test_process_ratchets.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Classify another tool's arguments or configuration with that tool's own parser, never a hand-written reader, and refuse whatever the parser cannot classify.

Classifying with the owning tool's parser and refusing what it cannot classify closes the escape forms together.

An allowlist over parsed options is stable; a denylist over raw text meets a new spelling each round (abbreviations, joined values, option files, environment defaults).

## Evidence

- 2026-11-24 — A hand-written reader of a test runner's options met four escape forms over successive review rounds; an allowlist classified with the runner's own parser closed them.

Catalog comparison: no existing rule covers allow decisions over another tool's argument grammar.
