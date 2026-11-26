---
id: contract-guidance-markdown-structure
domain: correctness
type: contract
enforcement: advisory
hypothesis: "rule_lint and guidance projection scan Markdown by line or regex without block structure (fences, list containers, code spans, headings), so commands hide from lint, Evidence boundaries are invented and Do scope is lost."
prediction: "Rule bodies with nested containers, multi-backtick spans, fences inside lists or slot substitution yield ok=True with a hidden concrete command or a misplaced Evidence boundary."
falsification: Revisit if lint and projection share one CommonMark-conformant block parser and fewer than 5 findings appear in 14 days.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:59Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - correctness
target_paths:
  - aegis_core/rule_lint.py
  - aegis_core/rule_lint_reasons.py
  - aegis_core/guidance_projection.py
  - aegis_core/guidance_grammar.py
  - tests/unit/core/test_rule_lint.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Parse markdown in rule lint and guidance projection structurally (front matter, headings, fenced and indented code, lists) rather than by line patterns, so code blocks, comments and nesting cannot change a rule's meaning.

Verify: fixtures with fences, HTML comments, indented code and nested lists keep the parsed rule unchanged.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 109 blocking findings in this class across 19 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- codex-d, 2026-11-14, Medium: backtick pairing crosses block boundaries and hides commands.
- grok-d, 2026-11-14, P1: fence handling can serve a real Evidence section.
- rb2-fix, 2026-11-19, Medium: opacity loses the surrounding Do scope.
- codex-d, 2026-11-14, Medium: nested-container extraction remains incomplete.
- codex-a, 2026-11-16, P2: compatibility rendering loses checked refusals.
- Why existing rules did not cover it: no rule targets `rule_lint.py`, `guidance_projection.py` or `guidance_grammar.py`. `contract-jit-rule-delivery` mentions `test_rule_lint.py` only in its Evidence section and targets `scan`/`match`/`rules`/`rule_integrity`.
