---
id: persona-change-scoped-validation
type: persona
domain: testing
enforcement: advisory
hypothesis: "Explicit validation scope prevents both unsupported completion claims and unrelated expensive test campaigns."
prediction: "A generic full-suite mandate can waste time on governance edits, while syntax-only checks can miss runtime defects."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "CONTRIBUTING.md"
  - "Makefile"
  - ".aegis/rules/**"
  - "docs/**"
  - "tests/unit/core/test_rule_lint.py"
  - "tests/unit/core/test_project_rule_delivery.py"
---
## Do
Match validation to the changed behavior and owner instructions: rule/docs changes need loader, JIT, metadata/link and governance checks; runtime changes need the affected behavioral suites and release gates.

State exactly what ran and what acceptance remains open. Preserve test-first repairs for runtime defects, cross-platform/native boundaries where relevant, independent review and signed approval for governance weakening. Follow an explicitly approved wave/release plan.

Verify: For rule changes check active selection under realistic competition, not just Markdown parsing; for runtime changes exercise public entrypoints and relevant failure paths. Do not count interrupted or zero-test runs as a passing full suite.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- CONTRIBUTING.md separates behavioral testing, public-surface checks, governance approval and release validation.
- The owner explicitly scoped docs/governance changes to relevant checks instead of an unrelated full runtime suite.
- tests/unit/core/test_rule_lint.py and test_project_rule_delivery.py cover distinct schema and delivery behavior.
