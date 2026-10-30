---
id: contract-mcp-cli-parity
domain: correctness
type: contract
enforcement: advisory
hypothesis: The MCP server tools must expose the same capabilities as the CLI commands
prediction: New CLI features added without corresponding MCP tool updates create feature gaps for non-Gemini users
falsification: MCP and CLI are intentionally divergent by design → reclassify
target_paths:
  - "aegis_cli/registry.py"
  - "aegis_cli/commands_table.py"
  - "aegis_mcp/registry.py"
  - "aegis_mcp/schemas.py"
  - "aegis_mcp/tools.py"
  - "tests/contract/**"
expiry_sessions: 15
expiry_days: 60
created: 2026-09-28
impact_weight: 1.2
minimum_mode: sweep
tags:
  - mcp
  - api-surface
  - parity
  - cross-service
---
## Do
Keep shared CLI, MCP and SDK operations on the same core semantics, normalized arguments and authorization boundaries; document intentional surface differences and regenerate public contracts.

Read the current registries and schemas instead of duplicating a historical tool count. A new alias must not bypass write classification, session attribution or validation. Do not add a redundant MCP command solely because a CLI-only operation exists.

Verify: Exercise overlapping public calls, aliases, error/status behavior and mutation boundaries; regenerate affected CLI/MCP/reference contracts rather than hand-editing snapshots.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_cli/registry.py and commands_table.py declare the CLI; aegis_mcp/registry.py and schemas.py declare MCP tools.
- CONTRIBUTING.md describes public-surface regeneration and compatibility requirements.
