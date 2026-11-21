---
id: trap-installer-clobbers-user-state
domain: correctness
type: trap
enforcement: advisory
hypothesis: "Installers and config writers that overwrite, duplicate or misdetect user state break the host's existing setup, and tests that use hand-built Namespaces or empty configs do not notice"
prediction: "Fires when init, a platform adapter or MCP registration changes; the writer strict-parses then merges, writes atomically with a backup, emits only the canonical entry and touches only entries it owns"
falsification: "0 findings in 15 sessions: prune"
expiry_sessions: 15
expiry_days: 60
created: "2026-10-15T16:11:59Z"
impact_weight: 1.0
tags: ["debrief", "citadel", "installer", "config"]
target_paths: ["aegis_cli/init.py", "aegis_cli/install_hosts.py", "aegis_cli/uninstall.py", "aegis_core/skills/slots.py", "aegis_mcp/server.py", "tests/unit/cli/**"]
lineage:
  parent_id: null
  created_by: "manual"
  generation: 0
  siblings: []
---
# Trap: installers and config writers clobber user state

**Rule**: Installers and config writers preserve foreign and customized user
state: strict-parse, then merge; write atomically with a backup; emit only the
canonical entry; touch only the entries they own; match headings and clients by
exact identity. Test them end to end through the real argparse parser against a
pre-populated hostile config, with a golden differential against the previous
release.

## Incident (v4 Citadel review)

- `aegis init --mcp` and `McpAdapter` registered the same server under two names, spawning two processes that double-counted session-close fitness.
- `McpAdapter.install` overwrote a non-strict-JSON `.mcp.json` and a customized
  `aegis` env, and pinned `AEGIS_WORKSPACE` to the adapter workspace rather than
  `project_root`; uninstall deleted a foreign server entry.
- `--portable` and `--mcp-only` were read through `getattr` but never registered
  in the parser. `init` silently seeded `.aegis/rules` and `manifest.json`, and
  `--force` overwrote them. `detect_platform` ranked `CLAUDE.md` above `.cursor`.
- The global cleanse purged user sections by bidirectional or empty-slug
  substring and followed symlinks. The scan defaulted unknown clients to the
  gemini slot profile and swallowed slot parse errors.
- It was missed because tests built hand-made Namespaces instead of using the
  real parser, no differential test compared `init` output between releases,
  adapter tests never started from a hostile or foreign config, and the slot and
  platform tables were tested for key membership only.

## Check

1. Installer tests parse real argv (`_build_parser().parse_args([...])`), never a
   hand-built `argparse.Namespace`.
2. Each writer test starts from a config with foreign entries, a customized env
   and non-canonical formatting, and asserts those bytes survive.
3. Writes are atomic (`_replace` in aegis_cli/install_hosts.py) and
   back up the user config they replace (`~/.aegis/backups/`).
4. Heading and client matching uses equality, not substring or prefix tests.
