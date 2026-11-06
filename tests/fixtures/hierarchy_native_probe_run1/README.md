# Native probe run 1: Codex code-mode records

The owner's native probe run 1 (2026-11-06, codex-cli 0.166.0, ChatGPT login in a disposable CODEX_HOME) probed 7
roles. Its reader then knew no code-mode record, so its report said NOT_ATTEMPTED for every refusal; the refusals
were verified by hand from the rollouts. These files let `test_hierarchy_native_probe.py` re-judge that run.

- `<role>.jsonl`: one per role, from the rollout named in `plan.json` (`source_rollout`, with its original
  `source_sha256` from the evidence's SHA256SUMS). Kept: `session_meta` (id, session_id, timestamp, cwd, originator,
  cli_version, source, model_provider), every `task_started`, `task_complete` and `turn_aborted` (type, turn_id,
  root_turn_id), and in the probe turn each `custom_tool_call` named `exec` that calls `tools.exec_command` or
  `tools.apply_patch`, its `custom_tool_call_output` and every `item_completed` `CommandExecution` or `FileChange`.
  The implementer also keeps its first wake-turn `exec`, which re-ran the old hold's `sleep 600` beside a tool
  listing. Kept records are otherwise verbatim; record `metadata` and payload
  `internal_chat_message_metadata_passthrough` are dropped.
- `plan.json`: the plan's layout, shells and attempts, plus per role the session, the probe and wake turn ids and,
  per attempt, run 1's verdict (`run1_verdict`) and whether its nonce file existed after the turn (`nonce_file`).
- Paths are sanitized: the probe root is `@PROBE_ROOT@` and the source checkout `@SOURCE@`. A test replaces both
  with temporary folders. No account id, user name or other path is left.

These records prove the shapes one Codex version wrote on one host. They are not a claim about another version.
