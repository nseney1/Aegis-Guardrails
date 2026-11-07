# Handoff maintenance: review, cutover and rollback

This parent's patch is a bounded evidence/safety repair. It is not approval to
restart the real workflow. Shutdown was intended by the owner but has not been
verified by this task. Native enforcement and continuous dispatch remain HOLD.
The later owner-authorized three-session restart amendment integrates this patch
into draft PR259; Session 1 owns that integration, normal push and final readiness.
No parent/child source preparation, fixture pass or review closes native gates.

## Implemented public surface

`tools/hierarchy_lifecycle.py --root <absolute directory>` supports `init`,
`record`, `status`, and `checkpoint`. `init --policy <absolute JSON>` and
`record --event <absolute JSON>` require `--evidence-only`. The policy and event
schemas are closed and tested in `tests/integration/test_hierarchy_lifecycle.py`.
Use those fixture constructors as examples, never as real identity/authority.
`inspect-request --file <absolute JSON>` needs no `--root` and reads declarations
without loading or changing a journal. Its [small-change contract](teams-t1-small-change-reader.md)
separates declared eligibility from approval, admitted checks and authenticated
Reviewer independence. Existing drafting, publication, admission and replay stay v1.
Evidence refs are inert path/hash claims; this tool does not read/verify their
contents, authenticate CIDs, or execute any packet. Mutations require POSIX
directory fsync; other hosts refuse before mutation. Non-POSIX durability is
not qualified. The exact policy hash must be independently pinned by an adopter.

An admitted [small-change plan](teams-t1-small-change-admission.md) can now record
route, writer intent/start, terminal, independent Reviewer acceptance, delivery
and complete closure without Orchestrator or Decider events. Routing is confined
to the approved lane; approval, admission, expiry and participant generations are
rechecked. UNKNOWN retains its obligation and accounting. Terminal/review sources
remain the request's base source; new commits are evidence only. Mailbox/job
dispatch and native qualification remain separate gates. The lifecycle replay
successor pin changes with this seam; historical corpus and checkpoint pins stay
unchanged.

`hierarchy_sweep.py --store <absolute store> --lifecycle <absolute journal>`
preflights the supplied journal before any wake and rereads after rounds. A bad
journal returns HOLD, `work_complete=false`, and starts no turn. An owned blocker
or unresolved request keeps `quiet=false` with zero jobs. `mail_quiet` remains a
separate fact. Without a journal, `work_complete=false`/`untracked` is explicit;
the legacy quiet exit still describes mail only. Completion with a journal
covers registered requests only, never an unreconciled all-team inventory.
The existing sweep can wake legacy hosts; this patch does not activate that
behavior or establish a supported native operator dispatch loop.

Each request retains its raw UTF-8 bytes/hash and immutable ID/version. The
authority request enumerates future request ID/hash/phase/operation tuples,
maximum intents and expiry. A root decision changes only recorded decisions.
Admit, intent, start, result, review, delivery and disposition remain separate.
After a lost reply, replay the same event ID with identical envelope bytes to
retrieve the original receipt. Different bytes conflict. A committed intent is
unknown until exact terminal evidence; a restart/successor cannot issue it twice.
Result replacement invalidates review/delivery; completion requires current
exact independent acceptance and delivery. Closed versions cannot be revised.

The `checkpoint` output hashes durable state, including absolute open-wait
timestamps, rather than a moving elapsed-time view. Incoming self-attestation
must name that exact checkpoint and an approved same-profile successor. It
fences the old actor generation but changes no native custody, process, job,
binding or lease. Neither checkpointing nor denying releases resources.

## Owner shutdown evidence

1. Use the owner's supported host/task controls to stop new workflow admission
   and turn dispatch. Owner-facing ROOT does not perform this operation. Do not
   assume an archived or silent task has stopped, or stop the shared daemon.
2. Have the qualified operator capture actual active tasks/process identity,
   outstanding native turns, jobs, reservations/leases and their owners. If
   process visibility is incomplete, retain HOLD and reservations as unknown.
3. Preserve all source witnesses, request/decision/event journals, mailbox
   publication/read receipts, failed outputs and complete checkpoints. Record
   the shutdown observation time and the operator's actual identity/capability.
4. Do not resume Runtime g20 or Delivery g8. Delivery g9 remains unverified.
   Keep the Engine, Content, Campaign and B1 obligations in the design inventory.
   Do not rerun Stormheir validations or normalize/retry R3's implicit-cwd EROFS.

## Cutover gate, currently blocked

Before any workflow cutover, Session 1 must integrate the exact reviewed parent
source with the three restart contributions, reconcile PR259 against its actual
base/head, and preserve the owner's governance-signing gates. Then require:

- Trusted native CID/role/generation and actual applied profile/capability readback.
- ROOT filesystem read-only with no workspace/tmp/config writes, a read-only
  tool allowlist plus narrow decision/own-attestation operations, and service
  rejection of operational calls and proxy attempts. Router remains routing-only.
- A distinct qualified operator, supported host bridge and persistent model-free
  supervisor with lifetime, correlation, idempotency and generation fencing.
- Source/authority validation before resource admission, fixed-capacity recovery,
  retained unknown effects and failure-inclusive evidence; no silent cleanup.
- All-team inventory reconciliation, exact-source affected/full checks, distinct
  independent review, hosted CI and owner-required signatures.
- A disposable native rehearsal proving approval -> distinct admission -> intent
  -> operation -> result -> independent acceptance/delivery -> later work, plus
  late arrivals, cap succession, lost replies and restart recovery.

These are acceptance conditions, not claimed existing APIs. The inspected native
mailbox adapter remains ROOT-refusing and configured sender provenance remains
unauthenticated. `codex exec --help` confirms the installed CLI advertises a
`read-only` sandbox option; it does not qualify app-server thread policy,
decision-only tools or a durable bridge. Use supported host configuration/admin
controls, not ad hoc raw RPC, global settings edits or broader permissions.

## Rollback and reconnect

If candidate evidence or qualification fails, stop candidate admission using its
qualified control, preserve its journal and unknown effects, and leave the real
workflow stopped. Do not delete journals, reset policy/counters, clear locks or
free resources because a client disappeared. A partial/pending journal entry,
unreadable source or unmatched receipt remains HOLD for evidence-based recovery.
The ledger deliberately performs no automatic repair of such evidence.

Restore only a separately verified previous source/configuration through the
owner-approved normal deployment mechanism. Old operational ROOT templates and
workspace-write profiles cannot be restored for the owner-facing role; a
previous source lacking the new boundary is not a valid restart fallback. Keep
old mailbox roots historical and never replay their dispatch as fresh authority.

Reconnect by revalidating actual actor identity/profile, current generation and
source/policy hashes; rehash the complete checkpoint and correlate all unresolved
intents before considering later work. Recorded receipt retrieval is idempotent;
it does not dispatch a new operation. Qualify actual incoming own-attestation
through the trusted host boundary. No readiness claim here authorizes restart.

Actual workflow restart is a separate owner action after Session 1 delivers the
final integrated evidence and explicit READY/BLOCKED verdict. This parent makes
no native READY claim, performs no merge/release and changes no live workflow
binding, custody, actor, job, lease, deployed clone or global permission.
