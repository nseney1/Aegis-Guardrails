# Disposable persistent fixture broker

`tools/hierarchy_fixture_broker.py` is a finite, test-owned fixture, not an
installed service or authenticated native provider. It runs only fixed waiting
work and an optional fixed descendant. There is no arbitrary payload, shell,
command callback, original job claim, resource settlement or native control.

The existing evidence-only `Operator` owns the sole admission, intent, start,
association and observations. The broker reads that canonical store. Its only
process map is transient ownership of actual `Popen` objects. It cannot approve
a request or create a second intent. All six inspection gates explicitly use
synthetic disposable fixture evidence; they prove no original-job admission,
recipe, reservation, source qualification, host identity or native containment.

## Public composition

After separate admission of a disposable test window, a test owner starts:

```text
python -I -B tools/hierarchy_fixture_broker.py serve \
  --directory NEW_PRIVATE_DIRECTORY --lifecycle-root DISPOSABLE_CANONICAL_ROOT \
  --work-seconds 2 --lifetime-seconds 10 --with-descendant
```

The directory must be new, its ancestors must not be symlinks, and its Unix
socket path must fit the 100-byte limit. `ready.json` publishes exactly schema,
provider, endpoint_id, socket, lifecycle_root, pid and native_qualified. Its
`aegis.fixture-broker-ready/v1` identity is a new incarnation, not authentication.
The diagnostic PID must never be used as a caller-supplied signal target.

`descriptor(directory, cwd=..., evidence_dir=...)` returns the existing closed
`aegis.fixture-process-provider/v1` descriptor accepted by
`validate_process_provider`. It invokes this module's short-lived `call`
command with the fixed directory. The caller supplies the existing canonical
target using that provider/endpoint, its original thread and deadline.

`process_provider_call` and `Operator.submit/observe/cancel` use the unchanged
eleven-field `aegis.fixture-process-call/v1` frame. No deadline, identity, job
mapping or permission extension has been added to that wire. Each normal reply
echoes the exact JSON types and fields and appends only `result`. Provider
observations retain the existing six-field shape. Same-user IPC is unauthenticated.

## Lifetime and uncertainty

The submitting N2 child owns only its socket connection. The independently
running broker owns the fixed worker and its stdin EOF guard. Reaping or exiting
the submitting child does not terminate that work. A new client can observe the
same canonical association and broker-generated opaque turn handle. A repeated
association never creates a second worker while this instance remains alive.

An instance never rebinds its directory or socket, including after loss. A new
directory has a different endpoint and cannot serve the old association. Missing
process-map ownership remains UNKNOWN. Receipt files are observations, not a
durable work queue or instructions to reconstruct an attempt.

**N2's absolute caller deadline is absent from the frame.** The client has its
own one-second socket deadline, and the broker caps each socket transaction at
half a second. These are not a shared issuance fence. A caller can time out or
disconnect while a request is queued or after a possible write. There is also
a canonical-read-to-`Popen` race. These fixture-only late-first-write limits must
remain UNKNOWN/possible, retaining the original association; never resubmit or
promote this broker as a native executor.

New fixture work checks current canonical operator/generation, exact request
bytes/hash/source and association/endpoint, latest decision, cap and original
expiry. Its duration is bounded by the fixed broker lifetime, requested fixture
duration, association deadline and original authority expiry. These checks are
fixture provenance, not authenticated or atomic native authorization. Reading,
observing or cancelling never settles original workspace resources.

Before a group signal the broker retains and checks its actual unreaped direct
child with POSIX `waitid(WNOWAIT)`. It never signals a reaped PID, a JSON PID or
a foreign handle. The fixed worker terminates and waits its own nonescaping
descendant and publishes a bounded receipt. Terminal fixture success requires
actual direct-child exit, matching exit code and that descendant-reap evidence.
Missing evidence, unconfirmed ownership or fallback group killing remains
UNKNOWN, even if the call child or group leader was reaped. Broker loss triggers
the worker's EOF/deadline cleanup but is not itself a quiescence witness.

## Limits and failures

Request raw and normalized bytes are capped at 768 KiB, JSON depth at 32, and
the entire echoed response plus result and LF at N2's 1 MiB limit. Result
evidence uses bounded path/hash references, never inline output. A partial,
duplicate-key, nonfinite, non-UTF8, multiple or oversized frame fails before
processing. Clients close their write half; the server waits for complete EOF
within its socket deadline. Reply loss never removes a possible work attempt.

Work duration is 0.05–30 seconds, broker lifetime 1–120 seconds, and the transient
map has at most 32 entries. Booleans are not numeric bounds. Handle strings are
at most 256 characters. Per-process stop grace is 0.2 seconds; the N2 call-child
descriptor uses 0.02 seconds. Every wait and cleanup step is bounded.

`BrokerError.code` reports exact `FIXTURE_` categories for invalid configuration,
reused/unavailable endpoint, malformed/large frame, correlation, stale actor,
handle, deadline, capacity, unknown outcome and socket timeout. CLI errors print
the stable category to stderr and exit 2. Unsupported platforms use code
`FIXTURE_UNSUPPORTED_HOST` and the exact diagnostic
`fixture broker requires POSIX waitid WNOWAIT`. They do not silently weaken the
process-ownership boundary. N2 transport uncertainty after a spawned call stays
uncertain regardless of a server's no-work diagnostic.

## Test and release boundaries

Public tests use real temporary canonical objects, the real N2 transport and
owned Unix sockets/processes. Lost replies use an external relay/socket boundary;
broker loss targets only the test's retained broker `Popen`. No internal positive
authority callbacks or arbitrary workload launchers are used. Workers remain
bounded, and test owners must reconcile their own broker/work/descendant scope.

Source tests and independent review are fixture evidence only. Original
job/claim/recipe/resource mapping remains a separate producer-owned dependency.
Full tests, hosted CI, protected deployment, authenticated native qualification
and owner workflow cutover remain distinct gates. Never release capacity from
this broker's fixture observation or a synthetic inspection marker.
