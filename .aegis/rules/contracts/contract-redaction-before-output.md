---
id: contract-redaction-before-output
type: contract
domain: security
enforcement: advisory
hypothesis: "Privacy depends on one consistent redaction boundary across persistence and display paths."
prediction: "A local redaction variant or truncation shortcut can preserve a secret that another surface correctly masks."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/redaction.py"
  - "aegis_core/insights/**"
  - "aegis_cli/hooks/redaction.py"
  - "aegis_core/verification/scanners.py"
  - "tests/unit/core/test_redaction.py"
---
## Do
Apply the shared bounded redactor before persisting or exposing sensitive text; malformed, oversized or incomplete secret material must not escape through excerpts, diagnostics or truncation.

Preserve idempotence, matching PEM delimiters and incomplete-key handling. Keep source text as untrusted data, sanitize display controls, and retain explicit limits without replacing failed masking with raw output. Never duplicate secrets in metadata or error details.

Verify: Use synthetic secrets and near misses through public redaction/persistence surfaces, including incomplete keys, mismatched labels, large inputs, repeated passes and excerpt boundaries.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/redaction.py is the shared L0 table for hook commands, insights and scanner excerpts.
- tests/unit/core/test_redaction.py covers near misses, repeated passes and bounded truncation.
- Release fixes 83a50c31 and b8ae14af hardened oversized/incomplete PEM handling and matching key labels.
