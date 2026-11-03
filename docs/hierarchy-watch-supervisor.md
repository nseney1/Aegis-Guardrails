# Model-free lifecycle watch

`tools/hierarchy_watch_supervisor.py` is a bounded, independent POSIX process
that repeatedly reads the canonical lifecycle ledger. A quiet mailbox or a
finished model turn does not end its polling loop. Pending dependencies, actor
caps, revocation, unknown effects and next-request dispositions remain governed
by `hierarchy_lifecycle.Lifecycle.status()`. The watch does not implement another
request, decision or execution-intent ledger.

This maintenance slice is **evidence-only**. The default native bridge holds all
execution. The process/storage checks and fixture bridge results do not establish
authenticated native admission, a production decision service, persistent native
executor lifetime, recipient read, independent acceptance or restart readiness.
See [the bridge contract](hierarchy-watch-bridge.md) for those separate gates.

## Public entry points

All paths must be absolute and free of symlinks or traversal. Initialize against
an existing lifecycle store in a disposable test directory:

```sh
python3 -I -B tools/hierarchy_watch_supervisor.py --root /scratch/watch init \
  --lifecycle /scratch/lifecycle --watch-id team-watch --evidence-only
python3 -I -B tools/hierarchy_watch_supervisor.py --root /scratch/watch step \
  --generation 1 --evidence-only
python3 -I -B tools/hierarchy_watch_supervisor.py --root /scratch/watch run \
  --generation 1 --seconds 60 --interval 1 --evidence-only
python3 -I -B tools/hierarchy_watch_supervisor.py --root /scratch/watch status
```

`run` has a finite duration of at most 3600 seconds; polling intervals range from
0.01 to 60 seconds. These are service-call bounds, not authority to restart a
capped actor. The canonical ledger independently rechecks actor active caps.
SIGINT and SIGTERM request a bounded loop shutdown. Starting a real service or
changing its operating authority requires the separately qualified operator.
Stop/deadline checks run before every observation, before durable dispatch and
immediately before the provider call. If persistence consumes the remaining
budget, the unsent dispatch is retained as `refused` with `effect: none`.
The optional process bridge receives the run deadline and stop event and can
cancel its owned disposable child while a call is in flight, retaining unknown
effects and output. Its bounded cleanup follows the run deadline; see the
[process port limits](hierarchy-watch-bridge.md#bounded-disposable-process-port).
Legacy synchronous Python bridges cannot interrupt an already running host call.
Each real provider still needs independently qualified timeout/cancellation and
containment; this slice does not establish a native executor lifetime bound.

For public Python integration, use `initialize(root, lifecycle_root, watch_id,
evidence_only=True)`, then `Supervisor(root).step(generation, bridge)` or
`Supervisor(root).run(generation, seconds=..., interval=..., bridge=...)`.
The injected bridge is the external host boundary; fixture callers must retain
the evidence-only interpretation. No CLI flag enables arbitrary host execution.

## Durability and fencing

The immutable watch configuration pins its lifecycle root and watch ID with a
digest in a SQLite database. SQLite full synchronous commits persist dispatch
references before an external call. The store holds request IDs/hashes, stable
watch operation IDs, generations, result observations and failure history. The
canonical operator owns admission and the sole execution intent.

A POSIX advisory lock permits one worker for a store. `run` holds it for the
whole loop, including waits and host calls. `step` and generation changes use
the same lock. A process crash releases the OS lock but leaves the dispatch
record. `advance --generation N --next-generation N+1 --evidence-only` refuses
while a worker is active; afterward, the previous generation is fenced.
Generation changes never erase pending operations or grant actor succession.

A lost reply, process crash, malformed result or uncertain effect remains held.
The watch never redispatches an unresolved or completed watch operation. Only
an explicit `refused` result with `effect: none`, followed by a fresh eligible
observation and canonical revalidation, permits another call with the same watch
operation ID. The canonical operator must still enforce its durable intent and
deduplication rules. Publication and a host's successful exit do not establish
recipient read or work acceptance.

The store retains up to 10000 watch operations and 40000 history rows, then
refuses further mutation. It does not silently compact, delete failed evidence,
reset generations or repair corrupt databases. Preserve the store on failure.
These same-user stores and advisory locks are cooperative coordination, not an
authentication boundary against another process running as the same user.

A failed lifecycle observation is recorded as an explicit history HOLD. The
bounded loop continues observing, but never dispatches from that failed sample
or repairs the ledger. Status reports unavailable state as unknown, never quiet.
Host-observation transport failures are also retained as explicit HOLD samples;
a later read-only observation can establish reconnect. This never retries an
effect whose reply was lost.
If the canonical ledger later records a terminal result for the exact request
hash, status derives a `canonical_settlement` reference while preserving the
original failed watch reply. Work completion still requires the canonical
independent acceptance, delivery and disposition; terminal evidence alone does
not close a request.

## Team integration and remaining acceptance

Team orchestrators can leave pending dependencies and next requests in the
canonical ledger. Each iteration reloads it, so late arrivals, newly available
capacity and changed eligibility are reconsidered within the existing approved
envelope. The [operator](hierarchy-restart.md) must independently revalidate
authority, role, source, generation, admission and capacity at the effect boundary.
Neither the watch nor the router creates new teams or approves broader scope.

The current command set is the agreed standalone maintenance contract. The
larger roadmap's proposed authenticated control service, source/head-pinned
command envelope, provider-specific continuation records, native own-attestation,
automatic service-manager installation and live restart remain dependent work.
No existing live control directory is migrated or activated by this tool.

The public tests use real temporary lifecycle/watch stores and fake host effects.
They cover lost replies, restart, competing workers/generations, caps, capacity
waits, late arrivals, post-FINAL next work, refusal and malformed storage/results.
An independent launcher/process test exercises the local bounded loop after its
launcher exits. That test does not prove survival across a real model turn or a
native host/daemon shutdown. Exact integrated source, independent review, full
suite, hosted CI and native acceptance are separate delivery facts.
