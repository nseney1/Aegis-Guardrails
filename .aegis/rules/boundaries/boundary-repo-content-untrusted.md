---
id: boundary-repo-content-untrusted
domain: security
type: boundary
enforcement: advisory
hypothesis: "When repository files choose what the verifier executes or interpolates (commands, slots, scripts, interpreters, test files), a hostile clone runs its own code with the governance tool's trust"
prediction: "Each subprocess sink takes its executable from packaged templates or user-scope config only, and ships with a hostile-clone marker-file test"
falsification: "0 findings in 15 sessions: prune"
expiry_sessions: 15
expiry_days: 60
created: "2026-10-15T16:11:59Z"
impact_weight: 1.0
tags: ["debrief", "citadel", "subprocess", "trust"]
target_paths:
  - "aegis_core/ast/runner.py"
  - "aegis_core/ast/batch.py"
  - "aegis_core/testexec.py"
  - "aegis_core/pathlookup.py"
  - "aegis_core/gitsafe.py"
  - "aegis_core/skills/slots.py"
  - "aegis_cli/hooks/runtime.py"
lineage:
  parent_id: null
  created_by: "manual"
  generation: 0
  siblings: []
---
## Do
Treat governed repository content as data, not executable authority; choose commands, interpreters and slot roles from trusted packaged or user-scope sources and confine repository-derived paths.

Pass validated repository values as structured argv/data to trusted programs rather than evaluating repository-selected commands. Preserve isolated environment/cwd policies at each subprocess boundary, bounded process ownership and explicit execution opt-in.

Verify: Use hostile-clone marker fixtures for command selection, relative/inside-repository executables, slot overrides, interpreter choice, symlink escape and process-group timeout behavior.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/testexec.py rejects user configuration that resolves inside the workspace and normalizes trusted test execution.
- aegis_core/ast/runner.py and pathlookup.py resolve executable authority; batch.py isolates owned drivers.
- tests/unit/core/test_testexec.py and test_repo_slots_untrusted.py cover trust boundaries.
