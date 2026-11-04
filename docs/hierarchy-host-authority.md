# Bounded host transport and unowned-call refusal

This source leaf implements a real bounded Codex 0.166.0 stdio client and strict
dynamic-call codec. It provides **no authenticated enrollment, positive role
authority, canonical decision, provider execution or bootstrap**. Its public
pipe tests use disposable external host processes. Passing those tests does not
qualify a deployed host, effective tool restrictions or native behavior.

## Public source interface

`tools/hierarchy_host_authority.py` exports:

- `ProtocolClient(reader, writer, timeout_seconds=5, max_frame_bytes=1048576)`
  takes ownership of two already-created binary pipe streams. It launches no
  process. `initialize()` performs the experimental-capability handshake;
  `receive_call()` yields a new untrusted `item/tool/call` envelope;
  `reply(rpc_id, result)` writes the matching bounded text result. `close()` is
  idempotent and closes both streams. The process owner separately reaps its
  actual owned child and proves any required quiescence.
- `decode_call_frame(raw)` validates one bounded UTF-8 JSONL call. Caller/model
  arguments remain inert data and cannot replace envelope thread/turn/call/RPC
  identifiers. It is not an identity or role-attestation interface.
- `refuse_unowned_call(call)` produces an explicit no-effect
  `STALE_INVOCATION` refusal, including for a claimed current ROOT identity.
  There is no positive enrollment constructor in this leaf.
- `HostAuthorityError(PermissionError)` has read-only public `code` and `reason`
  properties. Codes are closed to the H contract, reasons are bounded and do
  not echo a malformed frame or environment. An error type grants nothing.

The entry point is this public Python API; no `serve`, raw-frame control CLI,
provider/canonical callback or native-enable flag is implemented. Keep imported
code in a protected composition when a later phase actually supplies authority.

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

The accepted source baseline is commit
`c3471723d32706852a8c182de0eef8cce87e7465`, tree
`69691322f217818108577f3bb54546e7ae7de5b1`. The separate
[native provider codec](../tools/hierarchy_native_protocol.py) remains unchanged;
its provider controls are not enabled by this client.

The first public test was written before the module. An isolated S1-owned run
failed with the expected missing `tools.hierarchy_host_authority` module, with
unchanged test/source pins and a reaped child. Exact RED/GREEN, failure and
review records live in the source-bound maintenance packet. A source fixture
never supplies native identity or a positive internal authority callback.

## Continuing protected identity and capability work

The full H goal continues beyond this leaf. A subsequent separately accepted
source phase must implement actual owned process/channel custody, dormant
thread creation or admitted resume, protected canonical genesis/enrollment,
current role/generation/custody/source validation and a real bounded H fence.
`require_current(..., None)` will be identity-only preflight under H plus
canonical fences; actual fresh or original replay target-row checks remain
mandatory. No such positive method is implemented here.

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
