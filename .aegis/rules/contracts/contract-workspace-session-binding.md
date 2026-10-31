---
id: contract-workspace-session-binding
type: contract
domain: security
enforcement: advisory
hypothesis: "Workspace identity is an authority boundary independent of the caller's file labels."
prediction: "Fallback rebinding can read, write or credit another checkout while presenting the result as local."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/workspace/binding.py"
  - "aegis_core/workspace/confinement.py"
  - "aegis_mcp/handlers/common.py"
  - "tests/unit/core/test_workspace_binding.py"
  - "tests/unit/mcp/test_binding_guards.py"
---
## Do
Bind scans and writes to the explicitly resolved workspace and server session; conflicting or ambiguous host, registry or file roots must hold without silently switching projects.

Keep operator pins, host attestations and registry ownership distinct. Confine normalized paths and preserve shared-repository versus per-worktree identity. Read-only discovery must not initialize an unrelated workspace or let caller arguments choose server attribution.

Verify: Exercise conflicting roots, several host roots, subdirectories, foreign absolute paths, symlink escapes and unavailable workspaces through public binding/MCP surfaces.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/workspace/binding.py and workspace/confinement.py separate binding authority and confined file resolution.
- tests/unit/core/test_workspace_binding.py: test_pin_and_a_disagreeing_host_root_hold; test_files_in_two_registered_workspaces_hold.
- tests/unit/mcp/test_mcp_report_outcome.py: test_tool_arguments_cannot_choose_host_session_source_or_workspace.
