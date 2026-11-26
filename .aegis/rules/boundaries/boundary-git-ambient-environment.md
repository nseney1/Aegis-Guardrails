---
id: boundary-git-ambient-environment
domain: security
type: boundary
enforcement: advisory
hypothesis: "Git calls inherit ambient selectors (GIT_NAMESPACE, XDG/system gitconfig, includeIf, HOME, scrubbed variables restored by nested scopes) and trust gitfile/commondir bytes, so observed refs, attributes and custody differ from the governed worktree."
prediction: Setting one ambient Git variable or config include in a test changes observe/verify results instead of being neutralised.
falsification: Revisit if all Git calls go through one sanitised environment builder with an ambient-variable matrix and fewer than 5 findings appear in 14 days.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:59Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - security
target_paths:
  - aegis_core/gitsafe_run.py
  - aegis_core/gitsafe_policy.py
  - "aegis_core/team_git*.py"
  - aegis_core/team_jobs_source.py
  - aegis_core/workspace/target.py
  - aegis_core/treeid.py
  - aegis_core/team_publish.py
  - tests/unit/core/test_team_git.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Run git with a scrubbed environment (no inherited GIT_* variables, no user or system config, explicit safe.directory) and treat gitfile and config bytes from a repository as untrusted input.

Verify: tests with hostile GIT_DIR / GIT_CONFIG_* variables and crafted gitfiles cannot redirect or inject.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 84 blocking findings in this class across 20 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- grok-d, 2026-11-17, High: `GIT_NAMESPACE` changes the observed oid.
- codex-a, 2026-11-15, High: ambient `XDG_CONFIG_HOME` / system gitconfig `filter.lfs` leaks in.
- mc3-fix, 2026-11-20, P2: blob reads restore scrubbed ambient variables.
- codex-b, 2026-11-21, Medium: conditional includes bypass the setting check.
- grok-b, 2026-11-15, P2: seed initialisation bypasses HOME isolation.
- Why existing rules did not cover it: `boundary-repo-content-untrusted` does require isolated env/cwd at subprocess boundaries, but its scope includes `aegis_core/gitsafe.py` and not `gitsafe_run.py`, `team_git*.py`, `workspace/target.py` or `team_jobs_source.py`.
