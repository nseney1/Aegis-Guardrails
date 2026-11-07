# Bounded host transport and owned control source

This source leaf implements a real bounded Codex 0.166.0 stdio client and strict
dynamic-call codec. The inactive owned-control constructor also validates a
private Linux peer, protected source files and bound app-server pipes before
interning reservations. Source-only genesis and INITIAL fences now bind the
actual canonical producer to those owned objects. The decision-only LIVE source
path now verifies a protected role map, observes an owned start and correlates
actual app-server calls before creating process-local invocations and guards.
This source provides no deployed runtime or native qualification.
Its public pipe tests use
disposable external host processes. Passing source tests does not
qualify a deployed host, effective tool restrictions or native behavior.

## Public source interface

`tools/hierarchy_host_authority.py` exports:

- `OwnedHostBinding.from_owned_channels(control, reader, writer, deployment)`
  owns three distinct descriptors: a connected private Unix stream socket and
  the two app-server pipes. It checks Linux peer credentials, process start and
  namespace facts, executable/source hashes, protected ancestors and ACLs,
  endpoint and pipe directions, then performs the private `describe` exchange.
  A returned witness must match actual readback; JSON alone is not authority.
  `reserve_initial(plan_ref)` is one attempt per connection. It reads protected
  plan bytes, uses the real canonical policy validator, checks the full sorted
  reservation set and interns opaque `ReservedEnrollment` objects. Lost replies
  and duplicate attempts do not retry or allocate replacement identities.
  The deployment argument must be a text path or `pathlib.Path`. Nonce
  acquisition and path validation run inside the constructor's cleanup scope;
  their failures close the owned channels before the typed refusal returns.
- `binding.owned_runtime` is the same sealed binding; `binding.authority` is a
  `HostAuthority` composition facade, not an affirmative callback.
  `canonical_root`, `channel_witness`, `accepted_plan`, `approved_plan_ref`, and
  each reservation's `witness` expose fixed paths or inert copies. Plan bytes
  contain `source`, `actors`, `current`, and `successors`; the validated policy
  adds the existing schema and `authority: [plan_ref]` without a self-hash cycle.
  Direct reservation construction, copying and serialization do not create an
  owned object. `close()` retires the binding and closes all three resources.
  It is a revocation fence, not a drain: it first fences all three descriptors
  (see below) without waiting for any reply, so an in-flight control exchange
  or app-server wait fails promptly with a typed `HostAuthorityError`
  (`HOST_PROTOCOL_ERROR`, or `STALE_INVOCATION` when the operation sees the
  closed binding first). Provenance readback of the descriptors runs under the
  same fence, so a concurrent `close()` yields `STALE_INVOCATION`, never a raw
  `OSError` from a released descriptor. `close()` then waits only for a section
  that is already exiting, such as a guarded canonical publication, before
  invalidating sessions. After `close()` returns, no owned-descriptor I/O and
  no guarded publication can start. A request that was already written keeps
  its unknown outcome under the caller's existing possible-send handling.

- `ProtocolClient(reader, writer, timeout_seconds=5, max_frame_bytes=1048576)`
  takes ownership of two already-created binary pipe streams. It launches no
  process. `initialize()` performs the experimental-capability handshake;
  `receive_call()` yields a new untrusted `item/tool/call` envelope;
  `reply(rpc_id, result)` writes the matching bounded text result. `close()` is
  idempotent and closes both streams. Every read and write syscall runs under
  the same gate that `close()` takes before releasing a descriptor, so after
  `close()` the client never reads or writes a descriptor number that another
  file may have reused. A blocked wait notices `close()` within
  `REVOCATION_POLL_SECONDS` (0.05 s) instead of running to its deadline. The
  process owner separately reaps its actual owned child and proves any
  required quiescence.
- `decode_call_frame(raw)` validates one bounded UTF-8 JSONL call. Caller/model
  arguments remain inert data and cannot replace envelope thread/turn/call/RPC
  identifiers. It is not an identity or role-attestation interface.
- `refuse_unowned_call(call)` produces an explicit no-effect
  `STALE_INVOCATION` refusal, including for a claimed current ROOT identity.
  It cannot substitute for the owned LIVE constructor.
- `HostAuthorityError(PermissionError)` has read-only public `code` and `reason`
  properties. Codes are closed to the H contract, reasons are bounded and do
  not echo a malformed frame or environment. An error type grants nothing.

`authority.bootstrap_fence(runtime, plan_ref, reservations)` yields a real
`ReservedGenesisGuard`. It checks OS/runtime/source provenance before acquiring
the bounded H mutex, then locally rechecks the exact complete owned set,
reservation expiry, epoch, lexical lifetime and operation budget. N1 acquires
its own canonical exclusion in H-then-canonical order and calls
`require_reserved_genesis_current()` before publication and successful return.
Genesis guard exit also rechecks currentness; N1 retains UNKNOWN after a root
claim if that exit fails.

`authority.initial_creation_fence(runtime, plan_ref, reservation)` yields the
distinct `InitialCreationGuard`. `require_initial_identity_current()` takes no
loaded state and runs before canonical load/disclosure. The post-load
`require_initial_creation_current(..., None)` is identity/correlation only.
The actual original creation row is guarded before replay comparison; only an
absent original permits the separate `require_initial_creation_new()` checks
against its original genesis witness, current generation and unexpired/unissued
reservation. Old reservation expiry does not deny exact original receipt
recovery. Actual current operation budget and runtime ownership always apply.
Neither guard accepts caller/model state as an authority constructor or appends
a canonical record. N1 supplies actual public-read products under its writer
exclusion. No control IPC is permitted inside an active H fence.

The INITIAL lexical scope may contain several completed N1 transactions; its
exit retires the guard and unlocks rather than reclassifying a previously
returned result. N1 owns publication-UNKNOWN classification and the final
current check in each public transaction, including its writer-exit boundary.
Escaped, copied, serialized, cross-thread or reentered guards cannot authorize
another operation. Binding, facade and guard use reject a forked process before
preflight or lock acquisition. Full host process incarnation is read back during
external preflight; local PID ownership is checked again under the fences.
Same-thread nested entry refuses before any external readback, with a second
check after lock acquisition to cover a race.

`binding.bind_initial(reservation)` accepts an actual owned reservation, never
a caller-provided receipt or loaded canonical state. It claims one local attempt,
calls the real N1 public INITIAL writer under a real guard, and reads the actual
original prefix again under H plus canonical exclusion. Only a newly recorded
INITIAL can bind; recovered receipts do not create another startup context.
Fresh current-role, policy and original-row correlations are checked before the
exact thirteen-field private bind request is sent outside both lexical fences.

The returned `BoundInitialEnrollment` is an opaque host-local object with a
read-only actor CID. It cannot be copied or serialized. The runtime's own permit
stays inside the runtime; no permit ID or model-bearer grant crosses the channel.
One original five-second operation deadline includes queue waits, canonical
work, wire I/O and provenance readback. Binding caps it at the original reservation
expiry. Internal guard budgets intersect that original deadline; the existing
public guard interface is unchanged.

`binding.start_initial(context)` claims that exact local context once before a
possible startup command. It checks a fresh real canonical projection under the
guards, releases the fences, then sends the same original bound deadline. It
does not grant a new five seconds or refund an expired or issued context. Its
returned actor/state pair is inert startup observation, not LIVE enrollment,
decision authority or native qualification. Lost, late or malformed replies after
a possibly sent bind/start preserve `PROVIDER_OUTCOME_UNKNOWN`, close the owned
channels and cannot cause a retry, replacement CID or another context.

The entry point is this public Python API; no `serve`, model-callable control
CLI, provider/canonical callback or native-enable flag is implemented. LIVE
activation and the later decision/invocation effect fence remain subsequent
source increments; no successful placeholders stand in for them.

## Private owned-control protocol

This is a new protected internal protocol, not a stock Codex JSON flag or RPC.
Strict frames have `schema`, `id`, `epoch`, `nonce`, `method`, and `params`.
The fresh 32-byte H nonce, monotonically increasing request ID and actual
runtime epoch correlate replies. Frames are bounded to 1 MiB/depth 32, at most
32 requests, and an absolute five-second operation deadline including lock
waits. No semantic retransmission or reconnection is automatic. Constructor
post-reply provenance readback counts against that same original deadline;
expiry closes all owned channels before a binding can be returned. Constructor
and reservation requests implement `describe` and `reserve_initial`. The inactive
H source also implements `bind_initial` and `start_initial` using the actual
canonical chain above. Public source tests mock the external Rust control peer;
they do not prove a compiled receiver, native startup or deployment wiring.

The current constructor supports the actual same-process runtime/app-server/
control-peer alias only. A different app-server identity refuses until its
distinct protected ownership can be independently proven. Linux-only protected
construction does not change the portable codec or POSIX transport interface.
Source tests may mock actual OS/runtime boundaries; deployed credential
separation, complete runtime source/binary equality, current effect admission,
and owner cutover remain separate gates.

## Wire and resource limits

The client uses the supported app-server JSONL subset: one `initialize` request,
its exact reply, `initialized`, then `item/tool/call` requests and
`DynamicToolCallResponse` text results. It preserves RPC-ID type: integer `7`
and string `"7"` are different. Replies can finish out of order without crossing
pending calls. An identical repeated host-call tuple retrieves the cached reply
without another dispatch. Changed payload or rebound RPC ID fails closed.

Strict framing rejects duplicate JSON keys, nonfinite values, bool RPC IDs,
unknown envelope fields/methods, malformed UTF-8/JSON, torn frames and depth
above 32. Frame size is at most 1 MiB. Initialization validates the pinned
response's `codexHome`, `platformFamily`, `platformOs` and `userAgent` fields as
data; their presence does not establish protected runtime custody.

The connection retains at most 32 distinct host calls and RPC identities.
It closes on capacity exhaustion instead of evicting replay history and treating
an old call as new. The leaf is therefore a bounded component, not yet the
unlimited long-lived service required by the full H goal. Text results have at
most 64 items and the same frame/depth bound. Each public I/O operation uses one
absolute monotonic deadline, capped at five seconds. Partial OS reads/writes
continue within that same deadline; semantic requests are never retransmitted.

Terminal protocol errors close the owned streams. Timeout and EOF do not prove
that an unrelated future consumer effect was absent, that the external process
stopped, or that an intent/reservation may be released. No process is signalled
or canonical/resource record changed by this module.

Pipe transport is explicitly POSIX-only in this source phase, including Linux
and macOS. Other platforms return `UNSUPPORTED_HOST` before pipe access.
Portable codec, typed-error and unowned-refusal cases remain applicable; an
unsupported positive transport case is not native qualification.

## Source and test provenance

The constructor source baseline is commit
`3aaf202d11a6ab2f7d54e0e3fb74848ef6afea9f`, tree
`45dd3541c5ffe506e773193a38a004acf7e12612`. The original transport leaf was
tested on `c3471723d32706852a8c182de0eef8cce87e7465`. The separate
[native provider codec](../tools/hierarchy_native_protocol.py) remains unchanged;
its provider controls are not enabled by this client.

The first public test was written before the module. An isolated S1-owned run
failed with the expected missing `tools.hierarchy_host_authority` module, with
unchanged test/source pins and a reaped child. Exact RED/GREEN, failure and
review records live in the source-bound maintenance packet. A source fixture
never supplies native identity or a positive internal authority callback.

## Decision-only LIVE source

`binding.open_live_session(actor_cid)` requires that exact binding's observed
successful `start_initial` exchange. It retains the actual send/receive clock
window; a returned start dictionary cannot establish this fact. The fixed
deployment's `role_ceiling_ref` must contain a unique versioned role-map row for
the actor's canonical profile. An old INITIAL role-list file remains valid for
INITIAL only. LIVE also requires the canonical producer and publication helper
in the protected host source closure.

The canonical profile hash and full 17-field runtime projection hash are
distinct. H checks exact protected projection bytes, source/process/pipe/epoch
correlation and the immutable decision tool ceiling before `enroll_live`.
Nonempty shell environment overrides are rejected before their values are
copied, hashed or emitted. No Config, environment or credential dump is used.
The admitted source fixture uses raw namespace `null` and `aegis_decision`,
normalized to `functions` for ceiling checks; the old `aegis_decide` spelling
is not a LIVE alias.

`HostSession.receive_invocation()` receives a real bounded stdio frame and
compares it against the owned runtime's `pending_call` record before interning
a `HostInvocation`. Integer RPC zero differs from string zero. Read-only
`actor_cid`, `rpc_id`, `event_id` and `decision_recovery_event_id` expose inert
correlation; copying, serialization or direct construction does not create a
registered invocation. Original-only recovery must correlate to an actual
retained H-owned Unknown call, never an old object made pending again.

`authority.effect_fence(invocation, "decision")` performs external preflight
before taking H's lock. The real N1 writer then takes canonical exclusion and
calls `authority.require_current(invocation, policy, state, None)` before any
target disclosure. Target checks use the actual fresh/original canonical row,
before N1's replay payload comparison. Under both locks H uses local owned
facts and clocks, without IPC. H always checks the current original runtime
and call budget; N1 separately owns NEW-event cap and NEW-approve expiry checks.
The original actor end is start plus cap, and a call cannot extend its original
dispatch TTL, actor end or initial request deadline. INITIAL and LIVE share
one nonce, epoch and 32-control-request allowance.

After that fresh identity check, N1 calls
`authority.require_decision_command(invocation, command)` under both fences,
before any event key, target or receipt lookup. This local check requires the
actual active guard and invocation, then matches all five plain command fields
against the actual received frame. It returns no proof, frame or receipt and
performs no IPC. Direct public N1 entry uses the same check; mismatches refuse
with `STALE_INVOCATION` before canonical disclosure or append.

Each owned invocation retains whether a decision guard has ever entered
successfully, separately from its current scope depth. History is set only
after successful guard entry and is never cleared by scope exit, a body
exception or owner invalidation. It records possible prior entry, not proof of
a canonical append; it creates no authority or second ledger.

`session.dispatch_decision(invocation, command)` snapshots that history under
H's existing lock while consuming the original dispatch attempt. If a guard
entered before this dispatch, H retains the original as unknown, releases the
lock, closes the owner and raises `PROVIDER_OUTCOME_UNKNOWN` with reason
`canonical decision outcome is unresolved`. This happens before command
mismatch, producer availability or writer entry. No refusal proof, completion,
reply, retirement, append or replacement deadline is created.

The decision guard applies the same rule to every entry, including direct
public N1 calls that bypass dispatch: entering `effect_fence(invocation,
"decision")` for an invocation whose guard already entered once marks it
unknown, closes the owner and raises `PROVIDER_OUTCOME_UNKNOWN`. History is
checked before currentness, so the result is the same when the invocation is
already stale or its owner is already closed. N1 reports it as
`unknown`/`possible`/`PUBLICATION_UNKNOWN`, so a repeat entry can neither
publish a fresh decision nor claim that nothing happened. This includes a
retry after a no-effect refusal such as `CANONICAL_WRITER_BUSY`: once a guard
has entered, a retry needs a new invocation, as dispatch already requires.

Without prior guard entry, all five command fields must match the actual owned
frame before the fixed co-located `ProtectedCanonicalDecisionWriter` is called.
H never accepts a writer callback or canonical path from D/model arguments.
The real N1 implementation is a separate source dependency; its absence returns
typed `CANONICAL_API_UNAVAILABLE`. A fresh first dispatch may enter its own
writer guard, set history and still return the genuine private completion after
scope exit. A structured pre-dispatch refusal instead requires no historical
guard entry and has a distinct private proof without a canonical result.
Neither proof can be supplied through a D reply dictionary. Owner close preserves
historical unknown state; it does not establish quiescence or settle resources.

`session.reply(invocation, result)` sends bounded inert result data only after
one of these source-owned completions. It encodes `retire_call` from that proof,
not from result fields. Runtime callback retirement and Core future termination
remain separate requirements. `awaiting_terminal`, timeout, EOF and late JSON
do not settle custody, resources or capacity; possible publication retains the
same event key and Unknown objects. No automatic retry, unknown-clear method,
replacement deadline or second canonical ledger is provided.

## Continuing protected identity and capability work

The full H goal continues beyond this source slice. Coupled N1/D behavior,
recovery, all entry points, native runtime production/enforcement and owner
cutover require their own observed evidence. The INITIAL guards remain
distinct from model invocation authority. Source authoring, syntax checks and
an observed missing API do not establish semantic GREEN or deployed custody.

The actual N1 public decision/effect transaction and D projection must use real
reviewed H source with a real temporary canonical store for source TDD. Mock
only external OS/Codex boundaries, never an internal affirmative authority
callback, serialized grant or a second ledger. Source tests may precede admin
deployment; deployment and native qualification remain distinct requirements.

Complete tool enforcement requires a separately owned Rust runtime integration.
The researched 0.166.0 `ToolPolicy`/`ExtensionDataInit` seam is internal startup
source, not a Python JSON field or deployed-binary proof. Startup/resume/fork,
current-generation dispatch, direct control RPC and actual all-tool/OS coverage
require their own exact source contracts, review and qualification. Current
production refusals and the [restart gates](hierarchy-restart.md) remain held.
