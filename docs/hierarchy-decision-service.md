# Protected decision service

`tools.hierarchy_decision_service` exposes `CanonicalDecisionBackend` and
`DecisionService` over the fixed H/N1 decision route, plus two pure data
functions. The pure functions perform no I/O, host authentication, canonical
transaction, retry or operational action. A result dictionary or a successful
validation never grants execution authority or proves that a producer ran.

## Command validation

`validate_command(command)` returns an independent plain dictionary containing
exactly `event_id`, `request_id`, `request_sha256`, `decision` and `reason`.
The input dictionary, field names and all five values must have their exact
built-in types; mapping and string subclasses are rejected.

Both IDs match `[a-z0-9][a-z0-9_-]{0,79}`. The request hash contains exactly 64
lowercase hexadecimal characters. The decision is `approve` or `deny`. The
reason contains 1–1024 characters and no NUL. Whitespace and Unicode text are
preserved without trimming or normalization. Missing fields, extra fields and
malformed values raise `ValueError("invalid decision command")`.

## Producer-result projection

`project_commit_result(result, *, command)` validates the exact ten-field
`aegis.protected-decision-commit/v1` producer data shape and its correlation to
the supplied command. It replaces the schema with
`aegis.decision-service-result/v1` and drops only the top-level `event_id`.
The remaining nine fields are `schema`, `state`, `effect`, `code`, `reason`,
`request_id`, `request_sha256`, `receipt` and `native_qualified`.

| State | Effect | Code | Receipt |
| --- | --- | --- | --- |
| `recorded` | `canonical_decision` | null | Original receipt |
| `recovered` | `none` | null | Original receipt |
| `refused` | `none` | Closed refusal code | null |
| `unknown` | `possible` | `PUBLICATION_UNKNOWN` | null |

Success and error reasons must equal their fixed producer-contract messages.
Malformed input permits only `refused`/`INVALID_DECISION_INPUT`; individually
invalid input correlation fields remain null without coercion. A valid command
cannot be paired with that invalid-input code. Other state/effect/code
contradictions, cross-command correlation, missing/extra fields or nonplain
types raise `ValueError("invalid canonical decision result")`.

Receipts contain exactly `event_id`, `sequence`, `event_sha256` and
`execution_enabled`. The receipt ID matches the submitted event ID, sequence is
a positive integer excluding booleans, and the original envelope hash is 64
lowercase hexadecimal characters. `execution_enabled` and `native_qualified`
must each be the exact boolean `False`. The returned receipt is an independent
copy; projection preserves its values and does not reconstruct an envelope.

This function checks data consistency. Its accepted data examples do not
establish host ownership, canonical publication, native qualification,
completion or permission to release retained UNKNOWN state.

## Fixed service composition

`CanonicalDecisionBackend(host_session)` accepts the exact H `HostSession`
type and checks its public `owned_runtime` property before retaining the
session. Invalid types raise
`TypeError("backend requires an owned HostSession")` before attribute traversal.
An actual stale session raises its existing H error during construction;
construction has no command correlations and produces no D result.

`DecisionService(backend)` accepts the exact `CanonicalDecisionBackend` type;
other types raise `TypeError("service requires a CanonicalDecisionBackend")`.
Neither constructor accepts a caller path, writer, authority, callback or
canonical state. Construction grants no effect.

`DecisionService.handle(invocation, arguments)` validates the five inert fields
first on every call, including when the supplied invocation is a reservation or
the saved session has become stale. Malformed input returns the closed D9
`refused`/`none`/`INVALID_DECISION_INPUT` result before backend or H access.
Individually valid request/hash correlations are retained, invalid correlations
are null, the receipt is null, and `native_qualified` is `False`.

Valid input calls `CanonicalDecisionBackend.commit(invocation, command)` once.
That method calls only the actual session's fixed two-argument
`dispatch_decision(invocation, command)`. H binds all five fields to the owned
inbound frame and selects the fixed N1
`ProtectedCanonicalDecisionWriter.commit_decision` producer. D validates its
ten-field result with `project_commit_result` and returns the strict nine-field
projection. There is no D retry, canonical lookup, lock or journal append.

H owns actual invocation and terminal proof; N1 owns canonical exclusion,
current-state checks, original-row recovery and the sole journal. D never reads
private H registries, invocation frames or completion objects. D result data
cannot create H completion, authorize a reply or clear retained UNKNOWN state.

## Closed dispatch errors

Only the following `HostAuthorityError` codes from fixed dispatch are adapted.
Each result keeps the validated request/hash correlations, null receipt and
`native_qualified: false`; the reason equals the fixed D contract message.

| H code | D code | State/effect | Reason |
| --- | --- | --- | --- |
| `STALE_INVOCATION`, `HOST_CALL_CONFLICT`, `HOST_PROTOCOL_ERROR`, `HOST_PROTOCOL_TIMEOUT` | `STALE_INVOCATION` | `refused`/`none` | decision invocation is stale |
| `ROLE_OPERATION_FORBIDDEN` | `UNAUTHORIZED_ROLE` | `refused`/`none` | decision requires a current ROOT HostInvocation |
| `CANONICAL_CORRELATION_MISMATCH` | `SOURCE_MISMATCH` | `refused`/`none` | protected canonical source binding mismatch |
| `CANONICAL_API_UNAVAILABLE`, `UNSUPPORTED_HOST`, `UNPROTECTED_DEPLOYMENT`, `HOST_PROFILE_UNQUALIFIED` | `HOST_AUTHORITY_UNAVAILABLE` | `refused`/`none` | protected host authority is unavailable |
| `PROVIDER_OUTCOME_UNKNOWN` | `PUBLICATION_UNKNOWN` | `unknown`/`possible` | canonical decision publication is unresolved |

H reports post-writer ambiguity and prior successful guard-entry history as
`PROVIDER_OUTCOME_UNKNOWN`. The existing D mapping returns
`unknown`/`possible`/`PUBLICATION_UNKNOWN` with reason
`canonical decision publication is unresolved`, null receipt and
`native_qualified: false`. Guard history persists after scope exit; changed
valid input cannot turn it into a no-effect refusal or permit another dispatch.
H closes the original owner without reply or retirement. This does not prove
publication, quiescence or settlement and cannot renew the original deadline.

Other H codes and raw exceptions propagate. Malformed producer data raises the
projection error instead of being relabeled as a host refusal. An adapted error
is inert data, not proof that an earlier invocation or publication had no effect.
Malformed command validation still runs before H access; its inert refusal
cannot clear any original UNKNOWN. D production code and its fixed mapping are
unchanged by this H-history candidate.

## Qualification boundary

The earlier preimplementation public approve/deny target reached real H/N1
setup and failed twice with `FEATURE_ABSENT` at missing `DecisionService`;
that historical evidence remains. On frozen pre-change H/N1/D source, a single
ordinary approve control passed. The changed-command H-history branch then
reached the intended public semantic RED: `STALE_INVOCATION` where
`PROVIDER_OUTCOME_UNKNOWN` was required after successful guard entry and exit.
Those observations do not establish post-change behavior.

This isolated candidate adds H guard-entry history while retaining N1v5, fixed D
production code and all tests. No post-change tests have run. Independent exact
candidate review, all four H/D history branches, fresh approve/deny, all-five
frame binding and direct N1 controls, affected and full checks remain required.
Positive stdio reply/recovery fixtures, valid succession, native execution,
hosted checks, performance, owner acceptance and protected workflow restart
retain their separate gates.
