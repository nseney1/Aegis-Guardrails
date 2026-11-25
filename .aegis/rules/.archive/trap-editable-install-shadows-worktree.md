---
id: trap-editable-install-shadows-worktree
domain: correctness
type: trap
enforcement: advisory
hypothesis: "An editable install of aegis-guardrails made from one checkout serves that checkout's modules to every interpreter with the user site on, so tests and python3 -m aegis_cli in another git worktree can run code the worktree changed or deleted"
prediction: "Will catch test or CLI results that came from a different checkout: a deleted module that still imports, a fix that passes without being exercised, a lane whose suite matches main instead of its branch"
falsification: 0 findings in 10 sessions → prune
expiry_sessions: 15
expiry_days: 60
created: "2026-10-24T11:59:11Z"
impact_weight: 1.0
tags:
  - testing
  - worktrees
  - environment
target_paths:
  - "tests/**"
  - pyproject.toml
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
Before you trust a test run or a CLI result in a worktree, check which code runs. From the worktree root, `python3 -c "import aegis_core; print(aegis_core.__file__)"` must print a path inside that worktree. If it prints another checkout, an editable finder (`__editable___aegis_guardrails_*_finder` on `sys.meta_path`) is serving that checkout's modules. Python puts the editable finder ahead of `PYTHONPATH=.`.

Drop the finder for the run. One way is a `sitecustomize.py`, first on `PYTHONPATH`, that removes every finder whose module name contains `__editable__` from `sys.meta_path`. Another is a virtualenv per worktree. Do not uninstall or reinstall the developer's editable install: that is their environment, and their git hooks may depend on it.

The git hooks are a second case. `.git/hooks` is shared by every worktree of a repository, so the pre-commit hook runs the interpreter it names (`AEGIS_PYTHON`) with whatever Aegis that interpreter imports. A commit in a worktree is checked by the hook's installed Aegis, not by the worktree's code. To test a hook change, run the worktree's code directly: `PYTHONPATH=. python3 -m aegis_cli check --hook`, with the editable finder dropped.

This was seen during the 4.4.0 build: modules a lane had deleted still imported from the main checkout until the finder was dropped.
