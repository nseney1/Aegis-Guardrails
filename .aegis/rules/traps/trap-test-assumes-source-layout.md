---
id: trap-test-assumes-source-layout
domain: testing
type: trap
enforcement: advisory
hypothesis: "A test that locates shipped files by their position in the source tree fails, or tests the wrong copy, once the files are installed in a different layout."
prediction: Resolving shipped files through the same lookup the installed code uses keeps the test valid in both the source and the installed layout.
falsification: Retire if in fifty installs no test fails or tests a stale copy because of a layout difference.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-25T13:02:24Z"
impact_weight: 1.0
tags:
  - testing
  - install
target_paths:
  - "tests/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

A test that copies or executes a shipped file must find it through the same lookup the installed code uses, not through its position in the source tree.

When the source layout and the installed layout differ, run the test against both, or resolve the file the way the installed entry point does and fail with a clear message when it is missing.

## Evidence

On 2026-11-25 an installed test copied bin/kit_bootstrap.sh, but the install routes that file to coordinator/. All five tests errored with FileNotFoundError on the installed layout while passing on the packet layout, and the gap surfaced only after the install.
