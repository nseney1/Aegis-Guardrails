---
id: trap-stdout-protocol-corruption
domain: correctness
type: trap
enforcement: advisory
hypothesis: "Hook scripts that echo human-readable text to stdout after emitting their JSON protocol response corrupt the caller's JSON parser silently — no error is raised, the downstream consumer just gets garbage"
prediction: "Will fire when a CLI or hook script adds echo/printf to stdout for debugging, status messages, or logging instead of redirecting to stderr"
falsification: 0 findings in 10 sessions → prune
target_paths:
  - "aegis_cli/hooks/**"
  - aegis
triggers:
  - cli_modification
  - hook_modification
  - shell_script_change
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-10-01
impact_weight: 1.2
tags:
  - correctness
  - protocol
  - stdout
  - silent-corruption
  - critical
---

All hook scripts communicate with their caller via JSON on stdout. Any
non-JSON output to stdout silently corrupts the protocol.

Phase 2 incident (aegis_init.sh):
Lines 246-252 echoed "📊 Telemetry: ..." status messages to stdout AFTER
the `echo "$MERGED"` JSON payload. Line 270 echoed escalation sentinel
recommendations to stdout. The caller's JSON parser received:
  {"injectSteps": [...]}
  📊 Telemetry: Waste rate nominal (5-15%). Standard review protocol.
  Escalation sentinel recommends: sweep
Result: Silent parse failure downstream.

Fix pattern: ALL human-readable output in hooks MUST use `>&2`:
  echo "Status message" >&2    # CORRECT
  echo "Status message"        # WRONG — corrupts JSON protocol

Detection: `grep -n 'print(' aegis_cli/hooks/*.py | grep -v 'file=sys.stderr' | grep -v 'json.dumps'`
