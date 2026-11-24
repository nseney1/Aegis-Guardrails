---
id: trap-golden-pin-unexplained-delta
domain: testing
type: trap
enforcement: advisory
hypothesis: A hash or byte pin updated without attributing the difference can absorb an unintended change.
prediction: Attributing every changed byte to the intended change before updating the pin exposes any unintended difference.
falsification: Retire if ten pin updates each record a complete byte-level attribution that review confirms.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:52Z"
impact_weight: 1.0
tags:
  - test_modification
  - verification_modification
target_paths:
  - "tests/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Before changing a hash or byte pin, attribute every byte of the difference to the intended change and record that delta next to the pin.

Attributing every changed byte to the intended change before updating the pin exposes any unintended difference.

Equal length is not equal content. Diff the old and new bytes and name each added and removed span.

## Evidence

- 2026-11-24 — A tools-list pin kept its length while the content changed; the update was accepted only after the delta was attributed span by span.

Catalog comparison: no existing rule covers updates to golden pins.
