---
id: trap-ghost-cli-flags
domain: correctness
type: trap
enforcement: advisory
hypothesis: CLI flags registered in the argument parser but not consumed by the handler function create a false contract — users believe the flag does something but it is silently ignored
prediction: "Will fire when argparse registers --flag but the run_* handler never reads args.flag, or reads it but takes no action"
falsification: 0 findings in 10 sessions → prune
target_paths:
  - aegis_cli/cli.py
  - "aegis_cli/*.py"
triggers:
  - cli_modification
  - new_subcommand
  - flag_registration
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-09-30
impact_weight: 0.9
tags:
  - correctness
  - cli
  - dead-code
  - contract
---

Every CLI flag registered in argparse MUST be consumed by the handler function.

Citadel Cycle 2 incident:
`aegis_cli/cli.py:93-96` registered `--force` and `--rule` flags for `aegis demote`.
However, `run_demote()` in `aegis_cli/demote.py` completely ignored `args.force`
and `args.rule`. The command accepted the flags and silently did nothing.

Detection: For each subcommand parser, grep for `add_argument('--flag')` and
verify the handler function reads `args.flag` or `getattr(args, 'flag')`.

Automated check: AST parse cli.py to extract registered flags per subcommand,
then grep each handler for the corresponding attribute access.
