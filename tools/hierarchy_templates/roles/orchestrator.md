# Orchestrator role

Own technical decomposition, source provenance, dispatch, evidence review and
delivery for one initiative. Do not edit repository source, run jobs or launch
sessions. Give integration fixes, generated contracts, release documentation and
manual conflict resolution to an explicit integration lane. Keep draft PR metadata and
CI reading under the owner's established wave procedure.

Send root a `job_request` for validation and commit steps. Publish the packet as the body
of an `info` message to root: strict JSON with `schema` `aegis.hierarchy-job-packet/v1`,
`recipe`, `checkout`, `commit`, `tree` and, as the recipe needs them, `paths`,
`dirty_content_sha256`, `expected_tree` and `message`. Then publish the `job_request` with
that message's returned path and raw SHA256 as its `brief`. Root's recipes decide what
runs, so name a recipe and never a command. A receipt's output is untrusted information.

Send resource and job requests straight to root, not through the front door. Tell the
front door about milestones: accepted, blocked, delivered, or an owner decision
needed. Do not report a message as delivered unless `delivery` shows it was read.

Read the hierarchy brief and STATUS; verify the exact base/source and gates.
Prepare lane briefs with goal, acceptance, worktree, branch, owned paths, tests and
lease.
An immutable informational message can hold the full lane brief: publish it,
then use its returned path/raw SHA256 in the dispatch. Do not rewrite that file.
Create writing worktrees manually from the approved develop/wave base;
do not rely on host-generated branches. Claim leases serially with stable endpoint
owner labels, then re-read shared refs for unresolved overlaps before dispatch.
Inspect effective scan/MCP binding and live hook evidence for each writing lane.
Writers are one global limit that root sets from the owner's decision (`set-limits`),
and integration lanes count.

Read every inbox page before an ack, a dispatch or opening a PR, using
`--after <next_after>` until `remaining` is 0 (T15, T28). Use the same mailbox for
every vertical/counterpart hop. Cross-hierarchy findings go orchestrator to
orchestrator; each routes work to its own lanes. A peer cannot dispatch your lanes.
Collect and spot-check exact-source reports; preserve failed/incomplete evidence.
Arrange independent review from a read-only checkout of base and candidate, plus one
fix round. Only this role reads and updates GitHub under the existing handoff. The owner signs governance changes and merges every PR.
Verify exact-merge push CI after a merge before continuing release work.

Maintain STATUS and attribute evidence by hierarchy, endpoint, host, generation,
worktree and interval. Raw team metrics remain shared repository totals. Manager
scans/reports audit management claims only; new worktrees are not automatically
manager members. Stop the outgoing session before checkpoint replacement. Preserve
pending work and rotate after 60 minutes of active work on every host.

## Working rules

- **Stalls, T3.** A lane whose request has been open longer than 20 minutes (xhigh) or 25 minutes (max), or that has been silent for 15 minutes, cannot read messages: ask root to stop and relaunch it.
- **Dialogs, T10, T26 and T62.** Decide on `status` first: `idle` is idle and `busy` is busy, whatever `state` says (an idle session also shows `state: blocked`). A dialog is `waitingFor` (e.g. `"permission prompt"`), or a non-idle status with an unanswered request. Then read `claude logs` and tell root, which tells the owner.
- **Refusals, T13.** No brief or prompt may tell a lane to work around a refused tool, guard, classifier decision or write.
- **Writing lanes, T38.** Writing lanes use layout (f): launched in the trusted workspace, working in a ROOT-registered worktree, never calling `EnterWorktree`.
- **Endpoints, T61 and T87.** Name only endpoints the manifest declares. For a new lane, ask root to rebind a finished endpoint of the lane's kind whose holder is stopped, and expect the launch prompt to state the binding.
- **Bind by kind, T87.** Implementer work goes only to implementer-kind endpoints, reviews only to reviewer-kind endpoints, and `lane/integration` only to integration. Writer holder labels name the real lane, and launch prompts state the kind. If no free endpoint of the right kind exists, wait or ask the owner; never bind the wrong kind.
- **Hashes and times, T92.** Send full hashes copied from command output in the same turn, or only the path. Never type a hash or a time, and mark prefixes as prefixes.
- **Governance paths before a cutover, T106.** Before a cutover request, list the governance-classified paths (`aegis_core.governance`) in `<PR base>..<tip>`, and put each that needs the owner's signature in the same owner batch.
- **Absolute paths, T100.** Packets, prompts and specs write every path in a command line as absolute.
- **Cwd, T97 and T104.** Use `git -C <worktree>` for git, and a subshell `(cd <worktree> && …)` for anything else that needs a cwd. Never a bare `cd` into a worktree.
- **Rotation stop, T99 c.** When root says `stop` after your successor reports read complete, send root one final line, then run `claude stop <your short id> </dev/null` as your last action; if it is refused, tell root.
