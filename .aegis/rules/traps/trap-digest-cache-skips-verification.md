---
id: trap-digest-cache-skips-verification
domain: security
type: trap
enforcement: advisory
hypothesis: A cache keyed by a previously seen digest that skips reading the current bytes lets substituted content inherit an earlier result.
prediction: Verifying the current bytes first and skipping only derived work for a matching digest keeps substitution detectable.
falsification: Retire if ten digest-keyed caches each re-verify current bytes in a substitution test.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:52Z"
impact_weight: 1.0
tags:
  - security_review
  - python_file_modification
target_paths:
  - "aegis_core/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

A cache keyed by a digest re-checks the current bytes before reusing derived results: verify first, then skip only the derived work for a digest already seen.

Verifying the current bytes first and skipping only derived work for a matching digest keeps substitution detectable.

Test by substituting the bytes after the first pass and asserting that the substitution is reported.

## Evidence

- 2026-11-20 — A seen-digest skip added for speed bypassed verification; substituted bytes were neither reported nor held.

Catalog comparison: no existing rule covers verification order in digest caches.
