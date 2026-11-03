---
id: invariant-safety-gate
domain: security
type: invariant
enforcement: gate
hypothesis: The safety gate script is a critical security boundary.
prediction: Enforcing strict boundaries on this file prevents unauthorized circumvention of safety checks.
falsification: The script is entirely benign and requires no protection.
target_paths:
  - "aegis_core/command_safety/**"
  - "aegis_cli/hooks/safety.py"
  - "aegis_cli/hooks/pretool.py"
  - "tests/unit/core/test_command*.py"
expiry_sessions: 100
impact_weight: 1.0
minimum_mode: bulwark
tags:
  - safety
  - security
  - gate
created: 2026-09-28
---
## Do
Preserve the distinct safety-gate and pre-tool guard policies, normalize the entire compound command before classification, and keep irreversible side effects behind their documented authorization boundary.

The analyzer asks on commands it cannot safely parse; the pre-tool guard blocks only recognized irreversible operations and deliberately differs on unknown input. Shared lexer/wrapper handling must not hide a destructive suffix, alias, bundled option or nested command.

Verify: Update the documented policy parity table and exercise compound commands, wrappers, dry-run exceptions, malformed input, aliases and command substitutions through both public surfaces.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/command_safety/guard.py documents the deliberate analyzer/guard policy split and parity exceptions.
- tests/unit/core/test_command_safety.py and test_command_guard.py cover the shared lexer and different decisions.
- This replaces obsolete fixed-log-path guidance; human merge/release restrictions remain unchanged.
