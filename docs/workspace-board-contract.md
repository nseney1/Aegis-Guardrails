# Workspace board contract

Status: implemented in `tools/hierarchy_board.py` and served as its own scoped server when the
adapter starts with `--board`. Its tests run the real adapter with no host behind it,
so no real Claude or Codex session has used the board yet, and the trial below has not run.
Nothing here grants a permission. These are the public acceptance tests for the
[agent hierarchies](agent-hierarchies.md) board, in `tests/integration/test_hierarchy_board.py`.

The board is an information surface. A post cannot bind a session, acknowledge a
checkpoint, dispatch work, accept readiness, claim or release a lease, grant a job slot,
approve a review, sign, merge or publish. Posts are untrusted input, including posts from
recognized peers. Identity establishes attribution, not truth or authority.

## Decisions

| Decision | Choice | Trade-off |
| --- | --- | --- |
| Per-session adapter or a daemon | A per-session adapter of its own, with sequence numbers issued under one lock file | Nothing has to keep running and it costs nothing when idle, and a damaged board leaves the mailbox working, but each call replays the history, and a crashed writer's lock needs root's attention |
| Who issues channel grants | Root, through the board's CLI. No tool a session can call changes one | Root stays a step in setup, but a post can never widen access |
| Which mailbox traffic moves to the board | Information several roles may want, such as status and blockers. Control stays in the mailbox | Only a trial can show whether `info` traffic really falls, so the board stays optional for each initiative |
| Who produces digests | The `digest` command, a fixed filter and order | The same log and time give the same text, but it only lists posts and cannot summarize them |

Other limits to plan around: a board stops accepting records at 10,000, so root starts a new
one when it fills. Each sender gets 30 posts and dispositions per minute.

## Size budgets

A valid post must always fit a page, or a reader's cursor can never pass it. A model of
one post nested the way the mailbox adapter nests responses gave these sizes against a
32,768-byte page. The tests measure the real response line instead, including the largest
post by worst-case escaping beside a full list of open blockers.

| Post | Emitted bytes |
| --- | --- |
| 4 KiB of control characters, no references | 29,398 |
| 4 KiB of control characters, 8 references with 64-byte control-character descriptions | 33,852 |
| 4 KiB of quotes, 8 references with 256-byte quote descriptions | 26,172 |
| 1,024 emoji, 8 references with 256-byte quote descriptions | 24,124 |

The contract therefore rejects control characters other than newline and tab, in every
field, and gives every field a budget. 20.9% of ordinary mailbox bodies exceed 4 KiB
today, so posts must link evidence rather than paste it.

## Acceptance tests

**Page size and errors**
- The largest legal post, by worst-case escaping, fits a page alone through CLI and MCP.
- One byte over any field budget is refused and stores nothing.
- Pages never split a post, and a cursor always advances past a returned post.
- Every error response stays within the page budget, including ones that echo input.

**Attribution**
- A wrong or stale session or generation is refused, including after a session moves to a
  new ID.
- An author named in a post body is only text, and an author given as a tool argument is
  refused.
- A same-user process replaying another role's connection arguments is a known gap, not
  something this blocks.

**Storage**
- Concurrent publishers get unique, gap-free sequence numbers.
- A hand-edited or truncated record is detected and fails loudly. Someone who recomputes the
  digests, or removes the newest records, is not detected.
- The same sender, key and payload returns the same post, and the same key with a changed
  payload fails.
- No test or document claims tamper resistance without a separate OS user.

**Grants and freshness**
- After revocation or rotation, channel pages, thread parents, evidence references, cursors
  and idempotent replays all refuse.
- A refusal reveals nothing about the post: a forbidden thread parent and a missing one give
  the same answer.
- Knowing a post ID or channel name grants no access.

**Read positions**
- A successor resumes from its predecessor's position with no missed or repeated posts.
- Open blockers stay listed whatever the read position.

**Blockers**
- Only the author's endpoint or the channel's orchestrator can append a disposition.
- Expired items are flagged and stay visible as history.
- A quiet channel or a completion post is never read as proof that a process stopped or a
  resource is free.

**Evidence references**
- A malformed hash or revision is refused.
- A reference to a missing file or an unreachable URL is accepted as inert data, and the
  server opens no file and makes no connection. A sentinel file stays unread and a local
  listener receives nothing.

**Forged authority**
- A post shaped like an approval, dispatch, lease or grant leaves bindings, dispatches and
  leases byte-identical, and is returned as quoted data.

**Secrets**
- Key-shaped text is refused at publish, with the limits of pattern matching documented.
- An owner-only tombstone hides a body and keeps its ID, hash and history. No agent tool can
  create one.

**Volume and attention**
- A flooding sender gets an explicit refusal, and other senders are unaffected.
- No post wakes a session by itself.

## Trial measures

Compare with the mailbox baseline of 61.1 messages per dispatch and 435 of 489 messages as
generic `info`. In a trial with actual Codex and Claude sessions, keep the board only if
mailbox `info` per dispatch falls and missed updates do not rise.
