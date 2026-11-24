---
id: trap-function-globals-without-builtins
domain: testing
type: trap
enforcement: advisory
hypothesis: A function built from a code object with a globals mapping that has no builtins entry resolves builtin names differently across supported interpreter versions.
prediction: Giving the mapping an explicit fixture-owned builtins entry makes the test pass identically on the oldest and newest supported interpreters.
falsification: Retire if ten constructed-function fixtures without a builtins entry each behave identically on every supported interpreter.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T19:07:53Z"
impact_weight: 1.0
tags:
  - testing
  - test_creation
target_paths:
  - "tests/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

When a test builds a function from a code object (for example with `types.FunctionType`) and supplies its own globals mapping, put an explicit builtins entry in that mapping. Give it only the names the code under test needs, as a mapping the fixture owns; do not import the builtins module or share its dictionary when a contract in the repository restricts that.

Run such a test on the oldest supported interpreter before calling it done. Newer interpreters give a function without a builtins entry the caller's builtins; older ones give it a nearly empty table, so the same test passes on one and raises `NameError` on the other.

## Evidence

- 2026-11-24 — Five parametrized cases of a contract test passed on Python 3.12 and failed on Python 3.9 with `NameError: name 'max' is not defined`: the fixture executed a copied function body through `FunctionType(code, {...})` with no builtins entry. The first fix (importing builtins and passing its dictionary) was rejected by a strict monkeypatch contract; a fixture-owned mapping with the one needed name passed both.

Catalog comparison: nearest are trap-future-annotations (version-dependent syntax) and trap-test-depends-on-host-tool (host differences); neither covers version-dependent builtins resolution for constructed functions.
