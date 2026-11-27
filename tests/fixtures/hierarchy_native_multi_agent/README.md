# Codex multi-agent v2 in a live role session

`v2.jsonl` is cut from one Codex role session of the owner's M1 end-to-end run (2026-11-06, codex-cli 0.166.0,
`codex exec` started with `--disable multi_agent`): `rollout-2026-11-06T09-05-13-01a1b12d-890c-7532-8c37-6f22b5c0246c.jsonl`,
sha256 `a397d48d1ec85189acd0314128af6e739fdd5fc48fecf7075e04a06c8bc0618a`. All six role sessions of that run show the
same two signals.

Kept, in order: `session_meta` (id, session_id, timestamp, originator, cli_version, source, model_provider; `cwd`
replaced by `@WORKTREE@`), `task_started`, the `response_item` whose payload type is `additional_tools`, the
`turn_context` and `task_complete`. In `additional_tools` each namespace keeps its type, name, description and its
tools' type and name; tool descriptions, parameters and grammars are dropped. `turn_context` keeps turn_id,
root_turn_id, model, effort and `multi_agent_version`. Record `metadata` and every other record are dropped, among
them the developer message that begins "You are `/root`, the primary agent in a team of agents" and says "You can
spawn sub-agents". No account id, user name or home path is left.

These records prove what one Codex version wrote on one host under the owner's login. They are not a claim about
another version or about whether a disable flag is honoured.
