---
id: trap-path-traversal
domain: security
type: trap
enforcement: advisory
hypothesis: "User-supplied file paths (CLI --files, API params) that are joined with a root directory without containment checks enable reading/writing arbitrary files outside the workspace"
prediction: "Will flag os.path.join(root, user_input) without is_relative_to() or startswith() guard"
falsification: 0 findings in 20 sessions → prune
target_paths:
  - "**/*.py"
triggers:
  - python_file_creation
  - python_file_modification
  - security_review
minimum_mode: patrol
expiry_sessions: 30
expiry_days: 90
created: 2026-09-30
impact_weight: 1.0
tags:
  - security
  - path-traversal
  - critical
---
## Do
Resolve and confine paths with the canonical workspace/storage helpers before access; reject traversal, foreign roots and unsafe symlinks without relying on string-prefix containment.

Preserve drive/case/UNC and native path semantics across platforms. Binding identifies the authorized workspace; confinement then validates the normalized target. Writes additionally preserve the destination API's symlink and regular-file policy.

Verify: Exercise sibling-prefix directories, relative traversal, absolute/foreign paths, symlinks, nonregular sources and Windows spellings through public path/storage APIs.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/workspace/confinement.py and storage.py provide canonical confinement and safe file access.
- tests/unit/core/test_workspace_binding.py and test_storage.py cover root conflicts, path spelling and symlink boundaries.
