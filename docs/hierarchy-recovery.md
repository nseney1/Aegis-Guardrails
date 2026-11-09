# Resource recovery and status

The workspace ledger retains fixed-capacity claims until correlated terminal
evidence permits release. A lease expiry, actor cap, changed coordinator,
unreadable process table, or missing runner record does not release a claim.
The maintenance changes do not raise limits or authorize a live restart.

Use the read-only public surface:

```sh
python3 -I -B tools/hierarchy_jobs.py --store /absolute/store recovery-status
python3 -I -B tools/hierarchy_jobs.py --store /absolute/store recovery-status --initiative engine
```

`recovery_status(store_path, chosen=())` returns `(exit_code, report)`. The report
uses `aegis.hierarchy-recovery-status/v1` and includes `read_only`, `capacity`,
`initiatives`, `jobs`, and `blockers`. Each blocker names an accountable owner
and next action. Code 0 means no observed outstanding recovery obligation;
code 3 means pending work or unavailable evidence; code 2 means the request or
store cannot be read. None of these codes establishes native qualification,
independent acceptance, or permission to execute. An empty mailbox is not proof
that the resource ledger or retained job directories are empty.

The capacity view describes ledger reservations. `recovery-status` takes no
recipes and always reports the raw process census with count semantics: outside
work reduces its observed available slots. Unavailable census evidence leaves
available capacity unknown. The census sees the current process namespace; it
does not qualify a host-wide observer or discover processes hidden by an
unsupported host boundary.
Admission with `"report"` or `"ignore"` may therefore proceed when this count-only
recovery view shows no available slots.

For job admission, the optional top-level `census_outside_policy` in
`aegis.hierarchy-job-recipes/v1` accepts `"count"`, `"report"` or `"ignore"`.
Absent means `"count"`: it creates no census record and preserves legacy recipe
parsing, hash input, waiting-row capacity and result bytes when no earlier grant
record exists. Explicit `"count"` counts outside roots as before. When the next
eligible grant belongs to this pass's waiting holders, `"report"`
observes the same roots but returns no outside roots to the grant callback:
its full view records `external_roots: []`, `outside_policy: "report"` and the
observed `outside` rows.
Under the same condition, `"ignore"` skips outside observation entirely,
including fixture reads and the outside `/proc` walk, records
`external_roots: []`, `outside_policy: "ignore"` and
`census: "none"`, and has no `outside` key. Observing policies label `census` as
`"fixture"` or `"proc"` according to the source actually read. Each kind is
separate: full outside observations for `heavy` have class `pytest`, and those for
`heavy-tests` have class `cargo`. Each observation contains only integer `pid`
and `class`, sorted by PID and capped at 64; `outside_truncated` records the
omitted count when nonzero. Counting uses the full root list. Outside rows contain no
argv, paths or environment. The fixture census obeys the same policy. Ledger-held
jobs, limits, process ownership, `low_disk` and `store_busy` retain their rules.
Unknown or non-string policy values refuse recipe loading with
`invalid census_outside_policy: expected count, report or ignore`; misspelled
keys are refused as unexpected fields.

On a shared store, the grant callback checks the locked ledger using
`grant_next`'s exact eligibility rules and `(priority, seq)` order. `"report"`
and `"ignore"` relax counting only for an unambiguous next request whose holder
belongs to this pass's waiting jobs. A foreign job (including another runner's
job in the same initiative), manual holder, absent candidate or tied selection
uses count semantics instead. That view records `outside_policy: "count"` and
`outside_policy_applied: "count"`, observes the real roots, and labels the
census source accordingly. When outside load fills the limit, no grant is
written. When capacity permits a foreign grant, its record and eventual result
retain this count view, regardless of the executor's recipes policy.

For every grant published under an explicit policy, including `granted_elsewhere`,
the runner attempts to publish `<store>/census/<request_id>.json`. Exact keys are
`request_id`, `holder`, `kind` and `capacity`; the last contains the full bounded
view. Request IDs must have the controller's ASCII `req-00000000` form. One
canonicalization helper protects records, markers and output references,
including the top-level `granted_elsewhere` reference. An invalid ID becomes
`"invalid_request_id"`; no census record is opened or published for it. Summaries
retain their size bound even for traversal, Unicode or oversized ledger IDs. The
census runs freshly under the grant lock. Record publication follows the grant
using the atomic, no-replace file helper; these two publications are not one
transaction. A crash or a competing executor can observe a grant before its
record appears. Existing files are never overwritten. On an existing path, an
exact byte match is a benign retry. Different readable bytes are a conflict,
even if the planted record is otherwise well formed: this pass records
`census: "invalid_record"` with reason code `"conflict"`, and flags the granted
row's summary. The conflicting file stays untouched. In a later pass, a valid
record planted before publication and never contradicted cannot be distinguished
from a genuine record; the same-user store has no authentication.

An audit publication I/O error cannot abort the pass or block execution. A
`granted_elsewhere` summary or this pass's result-writing executor records
`census: "publish_failed"`, `publish_failed: true`, and reason code
`"publish_failed"`, with no raw exception text or paths. This in-memory failure
marker is bound to that request ID. Another executor without this pass's marker
sees `"unrecorded"` if no file exists. Inspect the census directory's permissions,
available space and hard-link support before relying on later audit records.

The execution claimant reads only its own granted request's record. It checks
the exact fields, grant identity, kind, types, policy, observation source, row
bound and an 8192-byte file limit. Reads use a nonblocking, no-follow descriptor
where supported, check its type and size with `fstat`, and read at most the bound
plus one byte. FIFOs and other non-regular files produce `"invalid_record"`.
The shared `read_bytes` helper is unchanged. A valid full view goes into `result.json`
`capacity`, even when the executor has changed or removed the recipes policy
since the grant. A missing record under an explicit current policy produces
`{"outside_policy": P, "census": "unrecorded", "request_id": R}`. An invalid
or mismatched record produces `census: "invalid_record"`, the request ID and a
bounded inspection instruction or reason code, without echoing untrusted content. If known,
the current recipes policy is included in this marker, not invented as evidence
of the original observation. Malformed audit evidence does not block execution;
the ledger still enforces held capacity, and the marker does not claim a valid
census. Structural checks do not authenticate a same-user writer.

Explicit-policy waiting rows and `granted_elsewhere` rows carry a small
`z_census` summary; no full view or PID list is attached. The summary contains
`outside_policy`, `census`, `limit`, `held`, `external_roots_count`, `outside_count`,
`outside_truncated` when known, and the request ID for a grant record.
Count fallback also includes `outside_policy_applied: "count"` in the
full view and summary. Publication failures also include `publish_failed: true`;
short `"publish_failed"`,
`"conflict"`, `"ambiguous_grant"` and `"invalid_request_id"` reason codes remain visible. Counts
include truncated observations; unavailable counts in audit markers are `null`.
Summaries are at most 384 JSON characters and
sort after actionable fields such as `error`, `reason` and `process_group` in
the loop's 512-character hold prefix. Waiting rows describe the latest observed
capacity for that kind; they do not claim that their own request was granted.
The absent-policy waiting view retains its legacy shape for compatibility.

Execution and `settle_pending` rows receive a summary only if this pass took
custody and atomically wrote the result. A `running` row for another claimant,
an abandoned job without a result, or settlement of an older result receives no
new summary. `resolve` reads the abandoned job's grant record with the same
validator before writing its result. Lookup selects only heavy kinds, using the
recipe's kind during execution/refusal and `census_kind` in an explicit-policy
execution claim during resolution. Other-kind grants with a matching holder do
not select another request's audit record. Unknown kinds and zero applicable
grants attach no audit metadata: a queued dependency refusal, changed-checkout
refusal or another-kind-only grant does not imply an invalid record. Only two
or more applicable grants produce `"invalid_record"` with reason code
`"ambiguous_grant"`, when audit metadata is active. An unavailable lookup also
attaches no metadata rather than claiming a grant it could not verify. Historical
claims without kind metadata receive no new audit view. Legacy default-policy
claims without their own audit record keep their old rows and result bytes,
even if unrelated jobs have census records.
Without a record for the job, `resolve` cannot recover the historical policy and
leaves capacity provenance absent. It does not invent a census.
In the normal heavy-job loop, audit lookup uses the fresh grant answer or the
already-loaded ledger snapshot. It does not replay the ledger for each job's
audit lookup. Resolution and standalone refusals retain the replay fallback.
Records are retained after settlement for manual grants and later
inspection. This tool creates at most one record per ledger request, bounded by
the store's 10000-event limit and the per-file limit; retained records and any
interrupted atomic-publication files require normal store archival, not a new
pruning operation in `run-open`.

This policy protects against misconfiguration and accidents only. `check-recipes`
shows `census_outside_policy` whenever it is explicitly set and adds
`census_outside_policy_non_default: true` for `"report"` and `"ignore"`.
With no key, the check output keeps its legacy bytes. Each job result records
the loaded recipes' `recipes_sha256`.

Use `run-open --expect-recipes-sha256 HEX` with the reviewed init hash to refuse
changed recipes before admission, job claims or ledger changes. The optional
value must be a 64-character lowercase hexadecimal SHA-256. A mismatch returns
`recipes changed since team init; re-run the reviewed team init`; malformed
values return `invalid expected recipes sha256`. Without the flag, `run-open`
accepts any recipes file that passes validation. **Known gap:** the team loop
does not yet pass the init hash; wiring it to this flag remains a follow-up in
`hierarchy_loop.py`. Until then, reviewers must compare each result's hash with
the hash pinned at init to detect edits after the fact. The setting comes from
the recipes file, including templates selected by team configuration;
environment variables and job packets do not select it.
`"report"` and `"ignore"` knowingly accept outside load, such as another
team's work on a shared machine or a container whose census sees only its own
namespace (container spec amendment 7). The default stays `"count"`.

## Recovery invariants

- Replay retains original request ID, holder, repository and declared path scope.
  A successor changing an initiative's declarations does not erase a granted
  writer's original path claim. Ordinary unreserved declarations remain advisory.
- A job claim records process start identity, boot ID and PID namespace. PID reuse
  does not identify the old runner or exclude unrelated work from the census.
  Missing legacy scope stays unknown; do not stamp a historical claim with the
  current observer's scope or rewrite it to manufacture stopped-process evidence.
- Explicit process enumeration and a current self witness are required. An
  unreadable process entry or table refuses recovery/admission. A disappeared
  process entry within the same observed scope can be distinguished from a
  permission error.
- A terminal result must name the exact job and a consistent terminal state and
  exit code. Settlement refuses a still-live recorded process group or an
  unrecorded process effect. Explicit stopped-process confirmation is retained
  when the existing `resolve --process-stopped` boundary is used.
- Reusing a receipt ID requires matching sender/recipient roles, original request,
  terminal payload, evidence references and body. A matching receipt from the
  original generation survives succession; an unrelated or changed receipt holds.
- Source revision, tree and dirty-content witness are revalidated before a job
  executes. Commit jobs also repeat the path/lease check after claim publication.
  Source changes observed later are reported separately from historical results.
- Failed logs and results remain evidence. Recipe `keep` outputs are retained with
  their hashes, including failures; copy failures remain explicit result entries.
  Acceptance, receipt publication, process exit and capacity release are separate.
  A readable terminal result, its retained-output references and exact receipt
  correlation remain visible even when missing or changed process scope blocks
  settlement. The row stays `evidence_error`; these historical observations do
  not establish stopped processes, acceptance or permission to release capacity.

The loop validates each child tool's response before consuming it. A malformed
object or row raises an owner `child_failed` hold and leaves independent steps
running. Any retained `diagnostics` are validated reporting fields for inspection;
they do not establish that no effect occurred. The next pass consults the tools'
durable records, so a lost route report does not cause a completed route to replay.

If a later job command cannot launch, the result retains the completed `steps`,
their logs and a `failed_launch` record naming the attempted step and arguments.
An uncertain process stop still holds the job without a terminal result. Reading
the failure report alone never permits release of resources.

## Crash and reconnect procedure

1. Inspect the original store, mailbox, job claim, source witness and current
   process visibility. Preserve every failed output and original claim. Do not
   replace an actor or resource holder just because its timer expired.
2. Use `recovery-status` to identify pending requests, reserved-but-not-started
   jobs, unknown effects, blocked settlement and incoming-source changes. Review
   every team, including paused initiatives and jobs whose requests already have
   a receipt. A capacity reservation without a mailbox request is still retained.
3. A qualified operator may run an already authorized `run-open` after fresh
   source and path admission. A grant written before job claim publication is
   reused; the exclusive job directory prevents duplicate execution. A directory
   without a readable claim remains unknown rather than being retried after TTL.
4. After a terminal result, rerunning `run-open` can publish the exact missing
   receipt or finish the original release. It does not rerun the command.
   A receipt published before a failed release leaves the slot charged; the next
   pass correlates the original receipt and releases at most once.
5. Resolve unknown effects only through an independently qualified operator with
   original-scope stop evidence. Unsupported namespace recovery, absent native
   controls and legacy missing scope remain named blockers. This patch does not
   add a migration that fabricates that evidence.
6. Before cutover, freeze source, independently review the integrated patch and
   run its coordinated affected/full checks. Keep original tools and live stores
   untouched until separately authorized cutover. Rollback switches candidate
   code only after quiescence; it never rewinds ledger events or frees held claims.

## Representative pending work

The disposable tests model Engine's unfinished partial handoff: original resource
claim retained, missing native stop/acceptance evidence and changed incoming
source all prevent implied completion. Content, Campaign and B1 remain separate
initiative obligations in the inventory. These labels are recovery fixtures;
they do not run Stormheir validation or establish acceptance of historical work.
The maintenance handoff supplies hash-bound external evidence and next owners.

This surface supplies observations for a qualified provider to consume and
revalidate through the canonical lifecycle ledger and operator boundary. The
current supervisor bridge delegates capacity evidence to its supplied provider;
no built-in native consumer is qualified. No second lifecycle or admission
ledger is introduced. See [the job runner and workspace
coordination](hierarchy-dogfood.md) for the existing public
commands and their cooperative, single-user trust boundary.
