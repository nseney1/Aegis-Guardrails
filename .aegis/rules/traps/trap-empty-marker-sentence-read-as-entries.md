---
id: trap-empty-marker-sentence-read-as-entries
domain: correctness
type: trap
enforcement: advisory
hypothesis: A parser that accepts only an exact empty marker reads an empty marker followed by an explanation as content.
prediction: Deciding the empty case from the leading marker and testing marker-plus-sentence inputs removes false pending states.
falsification: Retire if ten field parsers with an empty marker each classify a marker followed by a sentence as empty without a dedicated test.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T16:33:22Z"
impact_weight: 1.0
tags:
  - parsing
  - review
target_paths:
  - "aegis_core/**"
  - "aegis_cli/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

When a parser reads a declared field that may be empty, decide the empty case from the whole value, not from an exact spelling. A value that begins with the empty marker and continues with an explanation ("None required for the test-only change.") is still empty.

Write the grammar down next to the parser: which openings mean empty, what a real entry must contain (for example a table name or a tuple), and what happens to text that is neither. Test an empty marker alone, an empty marker followed by a sentence, a real entry, and prose that only mentions the field.

Prefer refusing ambiguous text with a message that names the field over guessing in either direction when the field gates later work.

## Evidence

- 2026-11-24 — A handoff carried the line "Registry rows:" followed by "None required for the test-only change." The reader accepted only a bare "none" and treated the sentence as pending entries, so finished work sat idle until a person noticed. No entry was pending.

Catalog comparison: nearest are trap-empty-gate-input-passes (an empty input that passes a gate) and trap-hand-parsed-foreign-arguments (hand-written argument parsing); neither covers an empty marker with trailing prose read as content.
