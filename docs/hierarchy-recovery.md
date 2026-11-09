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

For job admission, the optional top-level `census_outside_policy` in
`aegis.hierarchy-job-recipes/v1` accepts `"count"`, `"report"` or `"ignore"`.
Absent means `"count"` and preserves the existing recipe parsing, hash input and
waiting-row capacity. Explicit `"count"` counts outside roots as before and adds
`outside_policy` and `outside` to waiting-row capacity. `"report"` observes the
same roots but returns no outside roots to the grant callback: capacity records
`external_roots: []`, `outside_policy: "report"` and the observed `outside` rows.
`"ignore"` skips outside observation entirely, including fixture reads and the
outside `/proc` walk, records `external_roots: []` and `outside_policy: "ignore"`,
and has no `outside` key. Each kind is separate: `heavy` rows have class `pytest`,
and `heavy-tests` rows have class `cargo`. Rows contain only integer `pid` and
`class`, sorted by PID and capped at 64; `outside_truncated` records the omitted
count when nonzero. Counting uses the full root list. No argv, paths or
environment are recorded. The fixture census obeys the same policy. Ledger-held
jobs, limits, process ownership, `low_disk` and `store_busy` retain their rules.
Unknown or non-string policy values refuse recipe loading with
`invalid census_outside_policy: expected count, report or ignore`; misspelled
keys are refused as unexpected fields.

This policy protects against misconfiguration and accidents only. It is reviewed
because it sits in the recipes file, whose sha256 (`check-recipes`,
`recipes_sha256`) team init pins; changing it means re-running the reviewed init.
Unreviewed team state, environment variables and job packets can never switch off
counting. `"report"` and `"ignore"` knowingly accept outside load, such as another
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
