# Shell-less writers and commit jobs

A shell-less Claude team can use the existing `commit-exact` recipe with a commit
packet carrying `"derive": "runner"`. The packet still names `checkout`, `commit`,
`tree`, `paths` and `message`, and may omit `dirty_content_sha256` and
`expected_tree`. Other derive values and derive on command or merge recipes are
refused. Packets without derive retain their existing requirements and checks.

At admit, the runner takes the dirty content digest from its live source witness.
It derives the expected tree by running `read-tree`, `add -- <paths>` and
`write-tree` through the recipe's sandbox, PATH, prefix and environment, using the
same staging steps as commit execution. A temporary job folder holds the private
index; admission never stages into the real index or moves HEAD. A no-op is
refused. Explicit digest or tree fields must still match.

The runner locates `<base>/host-plan.json` beside the registered `<base>/mailbox`.
Derivation requires an `aegis.hierarchy-host-plan/v1` plan for this initiative with
`team` equal to `claude-code`; a missing, unreadable, malformed or non-Claude plan
is refused with `derive is for shell-less teams`. No additional CLI or store
field is needed. This branch has no shared `hierarchy_hosts.py` reader, so the job
runner checks these scope fields locally.

Before execution, `derivation.json` records `derived_by: runner`,
`dirty_content_sha256` and `expected_tree`, plus the host plan's path, SHA-256 and
team host. This file is included in the receipt's hashed evidence and survives an
interrupted runner. The job result repeats these values, including when it
refuses execution after an admit-to-run edit. The normal `before` and `after`
witnesses and step logs remain evidence.

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
