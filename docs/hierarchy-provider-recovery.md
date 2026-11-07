# Provider and workspace job recovery views

`tools/hierarchy_provider_recovery.py` reads existing evidence. Its two public
views deliberately keep canonical provider identity and workspace job identity
separate until an accepted producer supplies their original admission binding.
It writes no journal, mailbox, job, claim, result or reservation, and exposes no
start, cancel, resolve, repair or settlement operation.

## Canonical provider evidence

```sh
python tools/hierarchy_provider_recovery.py --lifecycle /absolute/lifecycle provider \
  --request-id original-request --request-sha256 ORIGINAL_RAW_REQUEST_SHA256
```

The imported API is `provider_status(lifecycle_root, request_id, request_sha256)`.
It loads the real lifecycle journal and checks the exact original raw request
hash. The result preserves the original intent, immutable association, original
actor/generation/cap/authority expiry/deadline, known provider handle, latest
observation, cancellation attempt and retained terminal record. Historical
UNKNOWN terminal evidence stays distinct from a later provider observation.
Denial or expiry does not erase history or renew permission to start.

Legacy intents without an association remain visible with null association,
handle and original-association fields. The result always reports the original
provider-to-job admission mapping as unavailable. A thread, turn, client ID or
generic `GATES.job` reference cannot identify a workspace job or reservation.

## Original workspace job inventory

```sh
python tools/hierarchy_provider_recovery.py --store /absolute/workspace job \
  --job initiative/original-message
```

The imported API is `job_status(store_path, job_id)`. It calls the existing public
`hierarchy_jobs.recovery_status` for the registered initiative and selects only
the exact original job row. It never fabricates a message or packet to feed a
lower-level recovery helper. An absent job is an error. Existing registered
reservations or orphan folders can supply an inventory row, but an absent or
unreadable original mailbox `job_request` is explicitly `correlation: orphan`.
A visible original mailbox request still has `correlation: unbound` to any
canonical provider operation.

The existing recovery row remains intact, including source changes, missing or
partial claims, process visibility errors, exact original reservations, retained
results and receipt conflicts. Its scope is `existing_workspace_job_inventory`.
Even `reserved_not_started` or `finished` describes only that local inventory:
the external `payload_effect` is always `unknown`. Ledger capacity has
`capacity_scope: ledger_only`; it is neither independently observed free runtime
capacity nor settlement permission. Workspace reservations have no expiry field,
and this adapter invents none.

These reads are separate observations, not an atomic provider/workspace snapshot.
They cannot authorize a new claim, resubmit an unknown operation, renew an
authority deadline, release a grant or withdraw queued resources. Actual
settlement remains with the existing exact job/result/receipt/process checks
and the separately authorized resource owner. Provider assertions, a reaped
call child, a cancellation ACK, an empty scan or model-turn completion cannot
prove the original payload's owned quiescence.

## Output and evidence limits

Both views return JSON with `read_only: true` and `native_qualified: false`.
A successful observation exits zero even when its evidence is unknown, orphaned
or erroneous. Invalid identifiers, mismatched request hashes and unavailable
required stores exit two with an `error` JSON object. Existing row errors remain
visible; the adapter does not repair them. CLI argument errors also use JSON.

Source tests use disposable real canonical/workspace/mailbox objects and retained
evidence. They do not qualify authenticated native identity, actual original-job
mapping, provider lifetime, payload containment, hosted CI or workflow cutover.
An original-job producer must freeze and implement the immutable packet, recipe,
source, claim, resource and actual-attempt binding before a coupled projection
can make stronger claims. No such binding or dispatch queue is created here.
