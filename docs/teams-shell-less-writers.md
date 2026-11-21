# Shell-less writers and commit jobs

A shell-less Claude team can use the existing `commit-exact` recipe with a commit
packet carrying `"derive": "runner"`. The packet still names `checkout`, `commit`,
`tree`, `paths` and `message`, and may omit `dirty_content_sha256` and
`expected_tree`. Other derive values and derive on command or merge recipes are
refused. Packets without derive retain their existing requirements and checks.

At the first admission, the runner takes the dirty content digest from its live
source witness. It derives the expected tree by running `read-tree`,
`add -- <paths>` and `write-tree` through the recipe's sandbox, PATH, prefix and
environment, using the same staging steps as commit execution. The private index,
staging logs and process record live in the job's own durable folder. Admission
never stages into the real index or moves HEAD. A no-op is refused. Explicit
digest or tree fields must still match.

After staging, `git diff-tree --name-only -r` compares the packet's commit with
the derived tree. Every changed name must appear exactly in `paths`; directory
names and `.` cannot authorize unlisted files beneath them. Otherwise admission
refuses with `derive staged files outside paths: ...`. The runner also takes
another source witness and refuses any change during derivation.

The runner locates `<base>/host-plan.json` beside the registered `<base>/mailbox`.
The root must be exactly `<base>/mailbox`, and that base's `provision.json` must
name the same mailbox and initiative. PR3's `hierarchy_hosts.base_plan` reader
validates the complete `aegis.hierarchy-host-plan/v1` schema. The plan must serve
this initiative with `team` equal to `claude-code`; missing, unreadable, invalid
or non-Claude plans are refused with `derive is for shell-less teams`. A waiting
admission and execution recheck the plan, including its hash.

The durable records are:

- `claim.json` and the original `packet.md`: custody starts before staging.
- `derivation.json`: `derived_by: runner`, `dirty_content_sha256`, `expected_tree`,
  the sorted `changed_paths`, and `host_plan` with its path, SHA-256 and team host.
  A known staging failure records available observations; uncomputed tree and
  changed names are `null`.
- `admitted.json`: written only after successful admission, binding the packet,
  recipe and derivation bytes by SHA-256. Later polls reuse the first admission's
  digest and tree, including after a job-limit wait; they never derive again.
- `execution.json`: the one-use execution claim, separate from admission custody.
- `disposition.lock`: an exclusive kernel file lock shared by execution admission
  and root resolution. Both recheck terminal state and runner ownership while
  holding it; resolution holds it until the terminal result is durable. Execution
  checks for a result again after publishing its claim and never starts a resolved
  job. The kernel releases the lock when its holder exits; the file's presence
  alone does not mean it is held.
- `result.json`: the outcome and repeated derivation fields when available. Its
  `steps` describe execution; the separate staging logs remain alongside it.

Completed, failed and refused receipts with a `derivation.json` hash-bind that
file, the result and the retained step logs/outputs. Refusals before derivation
starts and non-derived refusal receipts keep their existing behavior. Recovery
uses the recorded digest, or a completed job's `after` witness, for comparison.

An uncertain staging stop, a live staging group or a lost runner without a
successful admission marker stays held/unknown under the job's process record.
It produces no terminal refusal and is never automatically retried. The existing
operator `resolve` flow must reconcile process effects before closing it.

The guarantee lost is the lane's report-to-admit binding: the runner commits the
named paths as they exist at admit, even if they differ from what the lane
reported. Recording the values makes this auditable afterward; it does not
prevent that difference.

The guarantees kept are the admit-to-run source binding, the exact path list,
lease conflict checks at admit and again before execution, and independent
review of the exact resulting commit. The admitted digest and tree go through
the existing source recheck, staged-tree check and post-commit check. Independent
review remains a separate gate; a completed commit job supplies no review verdict.

This derive path ends when T2(b) qualifies an OS-enforced Claude write scope,
together with the weaker writer boundary accepted for T2(a).
