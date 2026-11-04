# Pinned native protocol codec

This is a source-checkout, stateless codec for a deliberately narrow subset of
the retained Codex CLI **0.166.0 default-export** protocol. It prepares and
interprets inert bytes. It has no socket, subprocess, retry, callback transport,
session registry, canonical store, credential access or native execution path.
It does not implement the authenticated service or persistent executor described
in the retained predecessor native-executor design packet, which is separate
from this pinned source baseline.

The new public module is [hierarchy_native_protocol.py](../tools/hierarchy_native_protocol.py).
It is outside the wheel's explicit package list. No installed CLI/MCP surface,
legacy provider signature or existing production refusal is changed.

## Accepted source contract

The codec follows N3 wire-contract-v1 and S1's six clarifications: revalidate
prepared bytes; require root-cursor plus explicit terminal cursor for pagination;
validate required nested fields/status; keep start correlation request-only;
treat effectful acknowledgements as possible; and keep native integration
separately gated. N1/N2 consumer acknowledgements concern this inert seam only.
They do not approve coupled bridge/canonical imports or a live transport.

The exact thirteen SHA-256 constants in `SCHEMA_PINS` match the retained
default-export schemas and the accepted executor design's pin table. Command
execution schemas are retained for their connection-scope limitation; their
methods are not allowed by the codec. Different versions, experimental fields
and new methods need a separately reviewed contract/pin update.

## Public API

`verify_schema_bundle(directory, version="0.166.0")` checks the exact thirteen
regular files under the explicitly supplied schema root. It reads at most 4 MiB
per file, refuses symlink/nonregular inputs, checks opened-file identity and
compares the raw-byte hashes. It returns an inert version/pins report.
`verified: true` means bytes match; it is not authentication or qualification.
Unsupported versions fail before filesystem inspection.

`prepare_request(method, params, request_id, *, version="0.166.0")` returns one
bounded JSONL byte frame containing only `id`, `method` and `params`.
It sends nothing and creates no authority, intent or session.

| Method | Supported parameter subset |
|---|---|
| `thread/read` | `threadId`, optional `includeTurns: false` |
| `thread/turns/list` | `threadId`, string/null `cursor`, limit 1..100, `itemsView: "full"`, `sortDirection: "asc"/"desc"` |
| `thread/items/list` | `threadId`, optional nonempty `turnId`, string/null `cursor`, limit 1..100, sort direction |
| `thread/resume` | `threadId`, optional `excludeTurns: true` |
| `turn/start` | `threadId`, exactly one text input, optional `clientUserMessageId` |
| `turn/interrupt` | `threadId`, `turnId` |

Every unreviewed parameter is rejected, including null-valued model, approval,
permission, sandbox, instruction, cwd, plugin, output-schema and configuration
overrides. There is no `thread/start`, fork or `command/exec` preparation.
The local version selector is not an invented wire field.

`interpret_response(prepared_request, response_bytes=None, *,
transport_error=None, expected_turn_id=None)` revalidates the supplied prepared
frame with the same closed rules before interpreting a response. It never
trusts a caller's method classification. Invalid preparation returns
`unknown/possible/INVALID_PREPARATION`, even if it claimed to be a read.

The response must be one complete UTF-8 JSONL frame, at most 1 MiB, depth at most
32, without duplicate keys, nonfinite numbers or additional frames. The output
\`request_id\` is the JSON-RPC transport ID, never the canonical request or intent
ID. Response IDs must match the wire request in both JSON type and value; boolean IDs are not
integers. Server calls/notifications are not response or authenticated call
context. Result arrays are bounded to 100, identifiers to 256 characters,
request IDs to 128, cursors to 4096 and text to 8192. Optional result extensions
are retained as inert data and cannot change the diagnostic flags.

This is not a general JSON Schema validator. The reviewed result subset
validates required Thread/Turn/item fields and status enums. Thread \`createdAt\`
and \`updatedAt\` are both required strict int64 values; booleans are not integers.
Thread source
supports the pinned string variants; custom/subagent source objects are outside
this slice. History items support text-only `userMessage` and `agentMessage`;
other item variants return `UNSUPPORTED_RESULT_VARIANT`. Nonempty text-element
annotations are outside the subset. Resume readback supports the `readOnly`
sandbox variant and string approval policies only. This restriction is decoding
scope, not evidence that an actual host is read-only or authenticated.

## Correlation, history and effect semantics

| Observation | Diagnostic meaning |
|---|---|
| Valid metadata/history read | `observed/none`; raw observation only |
| Valid resume/start/interrupt reply | `acknowledged/possible`; no terminal/quiescence proof |
| Missing, torn, malformed, conflicting or lost effectful reply | `unknown/possible`, never safe to retry |
| Remote error/denial after an effectful request | `unknown/possible`; error text does not establish no effect |
| Invalid read response | `invalid/none` for this read call only |
| Invalid preparation | `unknown/possible`; cannot safely infer what was attempted |

The supplied `transport_error` may be `timeout`, `disconnected` or
`lost_reply`. It is evidence supplied by an external boundary, not a timer or
mechanically enforced timeout. Passing both error and response is ambiguous.
No call or automatic resend can occur during interpretation.

Thread-bearing replies must match the requested thread. Turn-filtered item
pages must match every returned entry's turn. Start replies contain a Turn but
no thread identity, so their correlation remains `request_id_only`.
An optional expected turn is compared exactly. If a start reply returns
client IDs while the prepared input supplied a client ID, conflicting IDs
remain unknown; missing client IDs never become ownership proof.
Interrupt's requested turn ID is provenance only; its empty ACK authenticates
neither turn ownership nor cancellation.

`pagination_complete` is true only when the prepared cursor was absent/null,
the bounded result is valid, and the reply explicitly contains
`nextCursor: null`. Missing/non-null cursors or a non-root requested cursor
keep it false. This describes this decoded root page, not a consistent traversal
snapshot, absence of a prior effect or complete canonical provider history.
The codec does not fetch pages, join chains or reconstruct a missing association.

Every answer keeps `native_qualified`, `ownership_authenticated` and
`completion_proven` false, and `can_retry` false. Provider status strings such
as completed/failed remain inert observations. No cancellation acknowledgement,
archive status, process silence or response field can release a reservation.
Call-local read/no-effect diagnostics cannot erase an older unknown effect.

## Diagnostic errors and validation

Local preparation/schema problems raise `ProtocolError`, a `ValueError` with
an exact stable `code` and message. Preparation codes include
`UNSUPPORTED_VERSION`, `UNSUPPORTED_METHOD`, `UNSUPPORTED_PARAMETER`,
`INVALID_REQUEST_ID`, `INVALID_PARAMETER`, `FRAME_TOO_LARGE` and `MAX_DEPTH`.
Schema codes distinguish missing, unavailable, nonregular, changed, oversized
and hash-mismatched inputs. A partial successful schema read never returns a
verified report.

Response problems return diagnostics: `TORN_FRAME`, `MULTIPLE_FRAMES`,
`INVALID_JSON`, `INVALID_UTF8`, `DUPLICATE_KEY`, `NONFINITE_NUMBER`,
`MAX_DEPTH`, `WRONG_RESPONSE_ID`, `NOT_A_RESPONSE`, `INVALID_RESULT`,
`UNSUPPORTED_RESULT_VARIANT`, `WRONG_THREAD`, `WRONG_TURN`,
`WRONG_CLIENT_ID`, `REMOTE_ERROR` or the explicit transport error code.
No broad retry or hidden exception recovery promotes an uncertain effect.

Public tests are in
[test_hierarchy_native_protocol.py](../tests/integration/test_hierarchy_native_protocol.py).
They use real decoding objects and temporary schema inputs; simulated external
wire replies/failures never connect to a host. The retained source packet
includes the initial missing-module RED, later correlation/path REDs, GREEN,
and a separate positive read of all thirteen retained raw schema files.
Tests run with isolated HOME/USERPROFILE/TMPDIR and finite process deadlines.
A passing codec test is not native host qualification.

The canonical owner still owns current authority/generation, the one intent,
durable provider association, source/deadline fencing and replay exclusion.
Watch IDs remain delivery-only. The codec neither supplies nor mechanically
bounds N1's external start callback. Actual transport, coupled adapters,
containment, independently persistent lifetime, integrated full/CI and owner
cutover require their separate reviewed contracts and admission.
