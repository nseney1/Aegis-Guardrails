# Standalone handoff maintenance design, 2026-11-03

Status: source design and evidence-ledger implementation; native cutover is HOLD.
This maintenance task inherits no ROOT custody or workflow execution authority.

## Source and authority

The owner requested a task outside the workflow at 2026-11-03T21:20:54Z in
ROOT25 rollout `01a1a2f3-1058-7b52-ba2e-889fc90e33da`, line 1564, raw-record
SHA256 `a094100581368e878ce72c3ae23aec298d738c9eecda2f5f9ef900e1c6742984`.
The supplied ROOT policy request hashes to
`86d04bd3c7c0329c4974a13e78d4beee27d90a60ef67cc95717b07f0d9a51c10`.
Authoring base is `bb864014cbb2418e9d5bcd8caee942f99562c3f0`, the exact source
of merged PR266. Deployed dogfood source remains
`4f752c11856caf8f2293f6acdeee0c5572d81ae7`; adoption is unverified.

The four packets in that request are reconciled here. This design supersedes
the ROOT physical-runner, launch, custody logistics, resource settlement and
90-minute default clauses in the ROOT21 unified architect charter (SHA256
`9e49624f817fb0270b59024943fccc14ffcbd14913684d50e790819df66f2018`)
for every owner-facing ROOT. It does not supersede the charter's remaining
program backlog, source, independent-review or owner signing/release gates.

## Failure, cause, invariant and repair

`Mailbox.open_job_requests` closes a request on a terminal job receipt.
`hierarchy_sweep.remaining` sees unread messages and open jobs, rather than the
work's acceptance and next obligations. Thus a read FINAL/HOLD can disappear
from the queue while incomplete work remains. PR266 fixes the narrower case
of unread ROOT intake/open jobs; it does not close this loop.

The invariant is: each registered request remains an obligation until exact
independent acceptance and delivery, or until an atomic FINAL/HOLD disposition
links an immutable next request with accountable owner and next decision, or
records an owned blocker with a release condition. A job result, a read, a
decision, and accepted delivery are different facts. Unknown effects prevent
completion, retries, and resource-release claims.

Add `tools/hierarchy_lifecycle.py`, an append-only **evidence-only** local ledger.
Its public CLI records fixture/maintenance evidence, reads status and exports
complete checkpoints. It never launches a process, publishes workflow mail,
claims capacity, changes custody, or executes a request. Configured CLI actor
identity is provenance, not authenticated native identity. Mutation explicitly
requires `--evidence-only`. This is a state/safety repair and integration seam,
not a production decision service or continuous native scheduler acceptance.

## Closed contracts

An immutable policy defines distinct ROOT, router, coordinator, operator and
reviewer identities, generations, source policy evidence, owner authority refs,
role profiles, cumulative caps, and explicitly allowed successor identities.
ROOT's required profile is read-only; a requested profile is never reported as
effective enforcement. Router retains medium/ultrafast. Actor/generation checks
apply to every new event; one current generation per role is fenced in state.

Requests retain exact UTF-8 raw bytes and SHA256, ID/version, team, owner,
next decision, phase, operation, explicit source witness and paths,
prerequisites, and bounded authority. A packet can enumerate exact future
request ID/hash/phase/operation tuples, a maximum intent count and expiry.
ROOT can record only approve/deny with a bounded reason against an existing
request's exact hash (and its own incoming checkpoint attestation). Approval
does not start work. A denial/revocation preserves previous decisions and
unknown intents; it cannot cancel work or release resources.

Publication, recipient read, routing, decisions, admission, capacity/lock wait,
intent, start, terminal/unknown effects, independent review, disposition and
delivery are separate fields/events. Admission requires separate evidence refs
for source, capability, lease, capacity, observer and registered job gates.
Every execution correlation includes request raw hash, phase, operation,
actor generation and a single durable intent ID. A crash after intent is
unknown, and no second intent can be issued for that request. Explicit terminal
evidence can settle it; success alone does not establish acceptance.

Independent review names exact request and result hashes, matches the source,
and comes from a reviewer distinct from the author/operator. Completion also
requires delivery. FINAL/HOLD without one valid disposition is refused before
publication. Next-request insertion/linking is one journal append. Blockers
remain visible until a separately evidenced explicit resolution creates a next
request or completes an independently accepted delivered request.

The journal is bounded, locked, schema-checked and hash-chained. Each complete
record is flushed and fsynced before atomic no-replace publication and directory
fsync. Same event ID/same bytes returns the stored receipt; changed bytes
conflict. Replay rejects gaps, partial/corrupt entries and invalid transitions.
No failed evidence is rewritten or silently repaired.

A checkpoint includes the policy/hash, sequence/head, all requests, historical
decisions/consumption, actor generation/cap meters, waits, blockers, results and
unresolved intents. Incoming actors attest the exact checkpoint themselves;
another actor cannot impersonate their attestation. Succession preserves the
queue and unknowns, fences the predecessor, retains policy/model/effort/tier,
and refuses a stale checkpoint or writable ROOT profile. Native own-attestation
and process/custody settlement remain separate unqualified gates.

`hierarchy_sweep --lifecycle <path>` reads this ledger and reports its obligations
separately from mail quiet. A missing ledger is explicitly untracked; malformed
or unavailable lifecycle state is HOLD. Neither is work completion. A pending
obligation keeps the combined report nonquiet even with zero jobs. Status covers
registered requests only; reconciling all-team inventory is a separate gate.
Late arrivals are loaded afresh on each read; the source tool does not invent a
native watcher or dispatch loop.

## Native capability and operations gaps

The inspected mailbox adapter explicitly rejects ROOT and says its configured
sender is provenance, not native authentication. Provisioning a ROOT returns a
binding without verifying native capabilities. Existing Codex CLI launch argv
can request a read-only sandbox for CLI roles; it does not prove the applied
policy of an app-server thread or provide a decision-only service. Existing
sweep yields `message_thread` for native Codex; no qualified persistent native
dispatch interface or trusted effective-capability readback is implemented here.

Keep ROOT shell/file/config/raw-RPC/actor/job/lease/source operations denied by
policy. Keep router routing-only. The historical ROOT operator instructions move
to an explicitly unactivated operator template: current legacy mailbox/job APIs
still expect root endpoints and cannot be adopted by merely renaming a role.
No helper may proxy a forbidden ROOT operation. A trusted authenticated transport,
native tool allowlist, applied filesystem policy/readback and distinct operator
admission/controller integration require independent qualification before cutover.

## Validation and recovery inventory

Public fixture checks cover Engine partial recovery, bare FINAL/HOLD refusals,
owned blockers/next requests, late arrivals, bounded continuation, exact hashes,
duplicate/lost replies and replay, unknown intent fencing, stale identity/custody,
ROOT/router refusals, independent acceptance/delivery, and cap succession.
Fixture passes establish local state behavior only. They do not establish host
enforcement, continuous progress, hosted CI, integration or owner acceptance.

The delegation preserves these unfinished cases as reported evidence, without
rerunning or accepting them: Engine seven-file partial, 13 unexecuted cases,
two P1s (incomplete attempt becomes Eligible; cleanup unwind missed), missing
controls; Content hero capture success/zero-fallback instrumentation and scope
review; Campaign 70 scoped passes with failure-inclusive retention, actual
worker/backend/assets and 332-pointer reconciliation pending; B1 154 targeted
passes at dirty digest `9199e8dbde2783ee6a6ff9b896b6e34a0ece81988dda7e3f1d016af9ed8dd025`
with no full-suite request. These are not new validations.

Runtime g20 is final/over cap; Delivery g8 is final at 3547.577 seconds. Neither
may be resumed. Delivery g9 has no verified rollout/binding/activation. Router4
remains routing-only. Preserve R3 implicit-cwd EROFS evidence and all failed
publications; no retry/normalization, permissions change or workflow restart.
