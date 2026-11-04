# Watch continuation bridge

`tools/hierarchy_watch_bridge.py` defines the external host port used by the
[watch supervisor](hierarchy-watch-supervisor.md). It keeps a native HOLD explicit
where supported authenticated execution and persistent lifetime are unavailable.
It never bootstraps raw RPC, changes permissions, starts another actor, or treats
local JSON as authenticated owner approval.

## Frozen Python contract

`observe(request_id, request_sha256)` returns `state` (`eligible` or `hold`), a
`reason`, and `native_qualified`. `continue_request(request_id, request_sha256,
operation_id)` returns `state`, `effect`, `reason` and `native_qualified`, with an
optional canonical `intent_id`. The valid result pairs are:

| State | Effect | Watch behavior |
|---|---|---|
| `completed` | `confirmed` | Retain result; never redispatch. Acceptance remains separate. |
| `refused` | `none` | May reconsider after fresh eligibility; preserve the operation ID and failed history. |
| `unknown` | `possible` | Hold for explicit canonical settlement; never retry automatically. |

An exception or invalid result after dispatch becomes unknown. A watch operation
ID is only a delivery correlation; it is not a second execution intent.

`OperatorBridge(lifecycle_root, provider, actor, generation, evidence_only=False)`
uses the canonical `Operator(lifecycle_root, provider, evidence_only=...)` and
its `execute(request_id, actor, generation)` API. Evidence-only use is explicit
at both layers. Provider observations use the frozen `qualified`, `mode`,
`source`, `gates` and `reason` contract; `mode` must be `fixture` here. Operator
repeats admission checks under the canonical lock before recording or executing
its one intent. The bridge rechecks the request hash at each call.

The operator provider's `execute(request, intent_id)` returns `outcome`,
`exit_code` and retained `evidence`. Providers are an external boundary supplied
by trusted integration code, not a user-authenticated plugin or a JSON authority
grant. The installed native path remains refused regardless of fixture claims.

## Bounded disposable process port

`ProcessBridge(argv, cwd=..., evidence_dir=..., timeout_seconds=30,
stop_grace=0.2, evidence_only=True)` supplies an opt-in POSIX process boundary.
It requires `waitid` with `WNOWAIT`, an absolute executable, a trusted argument
vector, and explicit evidence-only operation. No shell, native session launch,
authentication grant, service installation, or new lifecycle ledger is supplied.
The host command must implement the port and repeat canonical Operator admission;
the public tests run the real `OperatorBridge` in a disposable Python host.

Construction refuses before creating evidence or launching a process unless the
host exposes `waitid`, `P_PID`, `WEXITED`, `WNOHANG`, and `WNOWAIT`. In particular,
macOS Python 3.9 and 3.11 are unsupported: Python added macOS `waitid` support in
[3.13](https://docs.python.org/3/library/os.html#os.waitid). Public refusal tests
exercise missing capabilities on every host. Only the subprocess execution tests
skip when those capabilities are absent; portable input and default-refusal tests
still run. A supported capability set is not native-host qualification.

Each call receives one JSON object on stdin with schema `aegis.watch-process/v1`,
`method` (`observe` or `continue_request`), `request_id`, `request_sha256`, and
`operation_id` (null for observation). It returns that exact object plus `result`.
The result follows the Python contract above and must report `native_qualified:
false`. A zero exit code alone cannot establish a valid result. Correlation,
JSON validity, effect/state pairs and output size are checked independently.

Unique evidence directories retain `request.json`, `stdout`, `stderr`, and
`result.json` for successes and failures. Each output has a 1 MiB acceptance limit,
checked while polling and again after exit; this is not a disk quota. A failed
observation is HOLD. Launch refusal or cancellation before launch is known
no-effect. Timeout, cancellation, malformed replies and nonzero exit after launch
leave a continuation unknown. Canonical terminal settlement can still be derived
without rewriting that failed transport history or repeating its effect.

The optional `with_control(deadline=..., stop_event=...)` returns a bounded copy.
`Supervisor.run` passes its deadline and stop event through this port; the earlier
of call timeout and run deadline applies. The bridge observes exit without reaping
its direct child, keeping that PID reserved while signalling its own process group
with TERM then KILL. Only afterward does it reap the child. This also handles a
leader that exits while a same-group descendant remains. Cleanup allows up to two
additional `stop_grace` periods; an unconfirmed reap is an explicit unknown HOLD.

Reaping the direct child and signalling its group do not prove that descendants
which escaped the group, a remote executor, or an uninterruptible host operation
stopped. Those require host-specific containment and observation. Cancellation
may leave the canonical writer's lock file behind; retain it and the unresolved
intent for qualified reconciliation. This bridge never removes abandoned locks
or releases capacity. Legacy synchronous Python bridges remain uninterruptible.

## Bounded asynchronous fixture provider

`validate_process_provider(spec)` validates and copies a plain data descriptor;
it creates neither evidence nor a process. The closed descriptor has `schema`
(`aegis.fixture-process-provider/v1`), `mode` (`fixture`), `provider`, opaque
`endpoint_id`, `argv`, `cwd`, `evidence_dir`, and `stop_grace`. The executable
and paths must be absolute, with no symlink or traversal. The argument vector
has at most 64 strings of at most 4096 characters. Stop grace is positive and
at most 0.2 seconds; the encoded descriptor is at most 256 KiB.

`process_provider_call(spec, method, request, request_sha256, actor=...,
generation=..., association=None, provider_handle=None, reason=None,
deadline=..., evidence_only=True)` provides the fixed process boundary used
by canonical asynchronous fixture transactions. Methods are `inspect`, `submit`,
`observe`, and `cancel`. No provider callback, native transport, authority store,
or dispatch queue is supplied. The canonical operator owns all admission and
the one attempted association; the helper checks only transport/input correlation.

The caller supplies one absolute monotonic deadline spanning its final inspection,
canonical publication, and submit, with a total budget of at most five seconds.
Every helper call reserves two stop-grace periods inside that same deadline for
owned-child cleanup. An expired or insufficient budget returns `not_sent` before
launch. The canonical operator converts remaining wall-clock authority, target,
and actor-cap durations to its monotonic budget and repeats its final checks;
this helper never renews an authority or resets a caller's budget.

The stdin frame has schema `aegis.fixture-process-call/v1`, a fresh local `call_id`,
method, request and exact raw request hash, caller actor/generation, canonical
association and its digest, known provider handle, and cancellation reason.
The child echoes every field plus `result`. Correlation includes exact JSON
types: a boolean cannot echo an integer generation. Frames are at most 1 MiB
and 32 levels deep. Inspect returns the existing five provider-inspection fields;
other methods return the six closed canonical observation fields
`association_sha256`, `provider_state`, `provider_handle`, `exit_code`, `evidence`,
and `quiescent`. The canonical operator independently validates evidence and
terminal semantics. The disposable fixture envelope is separate from the pinned
native-protocol codec and does not send shared-daemon RPC.

Provider and endpoint names remain bounded to 128 characters. Canonical
`thread_id` and `turn_id` values support up to 256 characters at both input and
response boundaries. An oversized caller-supplied thread or known handle refuses
before a child is started; an oversized returned handle leaves an uncertain reply.

Results use schema `aegis.fixture-process-call-result/v1` and include `transport`,
`reason`, `result`, direct-call `process` details, `evidence_dir`, and
`native_qualified: false`. A valid reply is `received`; refusal before launch is
`not_sent`; any uncertain reply or cleanup after launch is `uncertain`. Neither
`received` nor reaping the call process proves that its associated job stopped.
An interrupt acknowledgment remains nonterminal. Missing, malformed, oversized,
wrongly correlated or nonzero-exit replies retain evidence and never retry.

The implementation reuses the existing POSIX owned-child runner and regular
stdout/stderr files, retaining `request.json`, `stdout`, `stderr`, and `result.json`.
It never waits for inherited-pipe EOF. Legacy watch-process envelopes/results
remain unchanged. Escaped descendants, remote job containment, uninterruptible
OS/storage operations and authenticated native lifetime remain unqualified.


## Asynchronous bridge/watch consumer

An optional `async_target` keyword on `OperatorBridge` selects the canonical
asynchronous fixture path. It is copied as plain JSON data. Discovery checks the
canonical candidate and descriptor; final inspection remains inside the operator's
one bounded transaction. An unstarted continuation calls public `Operator.submit`.
An existing intent is observed through `poll_request(request_id, request_sha256,
operation_id)`, never submitted again. The original synchronous object-provider
and `execute` path remain the default.

Async results additionally admit `running/possible`. The bridge retains the
canonical result fields and checks request, intent and immutable association
correlation on follow-up. Watch operation IDs correlate delivery only. They do not
mint execution intents, provider handles, authority or resource reservations.

`cancel_request(request_id, request_sha256, operation_id, reason)` is an explicit
stop-only request to public `Operator.cancel`. The supervisor never cancels
automatically because a grant expired, was denied, an actor reached its cap, or a
host went quiet. A cancellation acknowledgment stays unknown. Only canonical
owned-job quiescence and a nonzero terminal exit settle cancellation as failure;
neither cancellation nor local child cleanup releases resources.

`with_control(deadline=..., stop_event=...)` supplies a bounded copy for async
calls. A stop request or less than the complete five-second transaction budget
remaining prevents a new operator call. This can hold an otherwise eligible
request near the end of a short watch run. The operator API cannot interrupt a
call already in progress; its existing five-second process budget, cleanup
reserve, original authority/target expiry and actor cap still apply.
Uninterruptible OS/storage behavior and native persistent lifetime remain
unqualified. This option does not make legacy synchronous callbacks interruptible.

Missing/legacy associations hold without dispatch. Unsupported process primitives
retain explicit no-effect refusals; only supported execution fixture tests use a
capability guard. These results remain disposable fixture evidence and do not
qualify any actual native host or decision service.

## Supported-host qualification matrix

```sh
python3 -I -B tools/hierarchy_watch_bridge.py capabilities --host codex
```

| Host | Available observation evidence | Execution and lifetime verdict |
|---|---|---|
| Codex native UI | Session 1's native observer reads rollout profile provenance. The current UI exposes `read_thread`; a real read returned the existing maintenance thread's active status and recent turn. `send_message_to_thread` metadata describes a 1000 UTF-8-byte prompt limit. | HOLD: no independently qualified persistent observer/continuation executor is installed by this slice. Tool exposure does not establish an authenticated workflow decision boundary. |
| Codex CLI | Installed CLI help exposes `queue` and `exec resume`. Queue help explicitly permits success when requested resume fails. | HOLD: queue acceptance is not execution, read, or persistent executor proof. |
| Claude Code | Installed help exposes background-session controls. Those command names alone do not establish the required same-session continuation contract. | HOLD: provider admission, continuation correlation and persistent lifetime require independent qualification. |
| Other providers | No qualified adapter in this slice. | HOLD: unsupported host. |

The local help and native tool inspection are capability discovery only. The bridge does not run
those commands as a fallback. The model-free watch can poll after its OS launcher
exits, but a fake-host process test cannot establish actual native host survival
after the originating model turn. Source authoring, fixture acceptance, native
execution, recipient delivery/read and independent review remain distinct.

The remaining native work needs a supported authenticated caller/role boundary,
narrow ROOT decision service, provider-specific observation/continuation schema,
per-call source/authority/generation fences, and a separately operated executor
with independently observed lifetime. Missing any of those retains HOLD. Global
permissions and the deployed tools/daemon remain untouched.
