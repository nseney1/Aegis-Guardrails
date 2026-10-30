---
id: trap-format-code-injection
domain: security
type: trap
enforcement: advisory
hypothesis: Using str.format() or f-strings to inject variables into executable code templates enables code injection when inputs contain quotes or Python syntax
prediction: "Will catch .format() calls on strings that are later executed via subprocess, exec(), eval(), or written as .py files"
falsification: 0 findings in 20 sessions → prune
target_paths:
  - "**/*.py"
triggers:
  - python_file_creation
  - python_file_modification
  - security_review
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-09-30
impact_weight: 1.0
tags:
  - security
  - injection
  - critical
---
## Do
Keep untrusted values as structured arguments or serialized data; when generating executable text, escape for the exact destination language and validate the complete executable boundary.

Python repr, JSON encoding and shell quoting solve different problems. Never treat JSON serialization as shell escaping, interpolate untrusted text into an executable template, or allow a quoted prefix to conceal later shell syntax.

Verify: Use synthetic quotes, newlines, substitutions, separators and path edge cases at the public subprocess/template boundary; ensure hostile data stays inert.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- The original coverage-template incident interpolated a path into executable Python source.
- aegis_core/testexec.py, gitsafe.py and AST driver planning preserve structured execution and command authority.
