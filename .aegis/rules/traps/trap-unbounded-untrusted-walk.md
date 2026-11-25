---
id: trap-unbounded-untrusted-walk
domain: security
type: trap
enforcement: advisory
hypothesis: "A recursive walk over an untrusted tree, or an unexpected per-request exception, can wedge a long-running service for every later request."
prediction: Bounded traversal and a terminal refusal per failed request keep the service answering the next request.
falsification: Retire if ten reviewed services each survive a deep tree and an injected per-request exception with a terminal refusal.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:49Z"
impact_weight: 1.0
tags:
  - security_review
  - python_file_modification
target_paths:
  - "aegis_core/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Bound every walk over an untrusted tree (iterative or depth-capped), turn any unexpected per-request exception into a terminal refusal for that request, and remove its partial artifacts.

Bounded traversal and a terminal refusal per failed request keep the service answering the next request.

One request must not be able to stop a service loop. Test with a tree deeper than the cap and with an exception injected into one request while a second request waits.

## Evidence

- 2026-11-24 — Review of a request-serving gate found unbounded recursion over caller-supplied directories and an exception path that left the service loop dead with a partial artifact on disk.

Catalog comparison: no existing rule bounds traversal of untrusted trees or isolates per-request failures.
