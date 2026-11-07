# Receipt-driven check sequences

The job runner accepts opt-in `aegis.hierarchy-job-packet/v2` packets for dependent
command checks on one fixed checkout, commit and tree. An Orchestrator submits
the requests once through the existing mailbox interface. `run-open` waits for
the predecessor's verified completion and runs the dependent check on a later
pass, without another model turn or a new message publisher.

This is the first Teams T1 progression slice. It does not implement dynamic
commit-to-check source substitution, small-change team provisioning, fresh
threads or full actor-succession continuity.

## Packet and compatibility

V2 keeps the v1 command-packet fields and adds two required fields:

```json
{
  "schema": "aegis.hierarchy-job-packet/v2",
  "recipe": "lint",
  "checkout": "/absolute/path/to/registered/checkout",
  "commit": "<fixed commit>",
  "tree": "<fixed tree>",
  "recipes_sha256": "<SHA-256 of the exact recipe file bytes>",
  "after": {
    "message_id": "first-check",
    "sha256": "<SHA-256 of the original predecessor job-request Markdown bytes>"
  }
}
```

Replace placeholders with actual hashes. `after.sha256` is the hash returned by
publishing the predecessor **job request**, not its packet brief or its receipt.
The reference is restricted to the same initiative, requester and recipient.
Both recipes must be command checks on the same clean source. Commit and merge
recipes are excluded. Optional `paths` retain their ordinary admission rules.

V1 packets and result/receipt schemas are unchanged; the existing team command
still writes v1. Deploy and qualify the v2 reader before opting any writer into
v2. Older runners refuse v2 rather than execute it without the dependency. The
original v2 packet is retained with the execution claim and remains readable by
`recovery-status`.

## Progression and recovery

Use the existing public command:

```sh
python tools/hierarchy_jobs.py --store /absolute/path/to/store \
  --recipes /absolute/path/to/recipes.json run-open
```

A dependency is satisfied only when the referenced request and packet hashes,
successful durable result, before/after source witnesses, claim and result recipe-file hashes,
terminal receipt and retained evidence all agree. Process-stop evidence must be
valid, the predecessor runner must be gone, and its reservations must be settled.
A terminal receipt alone is insufficient.

Pending dependencies return `state: waiting`, `reason: dependency_pending` and a
bounded explanation. Failed or conflicting evidence returns `dependency_held`.
Neither state claims, starts, settles or closes the dependent job. The overall
command returns 3 while work is held; unrelated eligible jobs still proceed.
Malformed packet shape and source drift use the existing explicit refusal path.
Self-dependencies refuse. Unsatisfied cycles cannot execute and remain held or
waiting; a pass does not recursively chase dependencies or busy-wait for them.

If a dependency changes after the dependent job already queued or received a
capacity reservation, the runner instead uses the existing terminal refusal
path. An exclusive claim and zero-step result record that no command started;
only then can the receipt and settlement release or withdraw that reservation.
A competing execution claim or failed settlement retains capacity for recovery.
This avoids stranding slots when evidence changes during a capacity wait.

Dependency evidence is revalidated immediately before claiming execution. The
binding fence and claim share the mailbox writer lock. Claimed jobs preserve
their original identities and use existing recovery/settlement, so a lost reply
does not authorize replay. This feature creates no additional request IDs or
resource ledger. Lost terminal delivery is repaired by the existing settlement
path before progression.

An unclaimed request without a capacity reservation whose sender binding has
changed is held conservatively.
Automatic successor adoption of that immutable request remains later T1 work;
do not work around a hold by replaying a possibly completed job. Claimed jobs
continue to reconcile through the existing job identity.

This is the existing configuration-bound operator tier, not native authenticated
authority. Dependency ordering grants no approval, new role capability or larger
budget. Recipe isolation is unchanged: a clean Git witness alone does not imply
commit-export isolation; checks needing that guarantee must use the existing
`require_clean` recipe policy. Native Linux provider qualification remains separate.
