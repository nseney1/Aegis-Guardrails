---
id: trap-shell-true-portability
domain: portability
type: trap
enforcement: advisory
hypothesis: subprocess calls with shell=True fail on Windows due to different shell quoting rules and may introduce shell injection vulnerabilities
prediction: Will flag subprocess.run/check_output/Popen calls using shell=True
falsification: 0 findings in 20 sessions → prune
target_paths:
  - "**/*.py"
triggers:
  - python_file_creation
  - python_file_modification
  - portability_review
minimum_mode: patrol
expiry_sessions: 30
expiry_days: 90
created: 2026-09-30
impact_weight: 1.0
tags:
  - portability
  - windows
  - subprocess
---

Citadel C6 incident: `jit_engine.py` used
`subprocess.check_output(cmd, shell=True)` for git diff commands. On Windows,
shell quoting differs and paths with spaces break. Fix: pass command as a list
without shell=True.
