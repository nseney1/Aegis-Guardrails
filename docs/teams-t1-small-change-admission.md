# Teams T1 small-change approval and admission evidence

The existing lifecycle `record --event FILE --evidence-only` command records
small-change approval, admission and deterministic execution evidence.
Configured actor IDs and evidence references do not authenticate a Reviewer,
verify a recipe artifact or grant native authority. The protected host decision
ABI remains unchanged. Automated routing, mailbox dispatch and jobs still require
their separate integration; this lifecycle seam runs no model turn.

## Closed event contracts

All three events retain the existing envelope (`id`, `actor`, `generation`,
`custody`, `event`) and common event fields (`type`, `request_id`,
`request_sha256`). Unknown or missing fields refuse atomically. Mutation still
requires `--evidence-only`. The added event fields are:

| Type / configured role | Additional fields |
|---|---|
| `small_change_plan` / coordinator or router | `proposal`, `participants` |
| `small_change_decision` / ROOT | `plan_sha256`, `decision`, `reason` |
| `small_change_admit` / operator | `plan_sha256`, `decision_sha256`, `source`, `participants`, `checks`, `gates` |

`proposal` is `{raw, sha256}` over the complete unchanged
`aegis.small-change-plan/v1` declaration envelope, preserving the original v1
request's exact raw bytes. `plan_sha256` is this outer raw hash. Registration
requires declared eligibility, a self-authorizing request with exactly one start
and no continuation members, and no recorded route, legacy admission, intent or
disposition. Shared interfaces, migration, governance, extra writers, expanded
budgets and uncertain scope retain full-planning escalation.

`participants` is a closed object with `writer` and `reviewer`, each containing
`cid` and integer `generation`. These must match the plan and the current
configured operator/Reviewer roles. The Reviewer must differ from publisher and
writer. The immutable registration binds these generations; approval and
admission recheck them. Succession requires a new request/plan, never rebinding.

Plan decisions allow first approve/deny and approve-to-deny only. Approval is
separate from both canonical v1 approval and admission; it cannot populate v1
authority, consume starts or reserve resources. Admission names the canonical
JSON SHA-256 of the complete last stored plan-decision record (including actor,
generation and timestamp), plus the exact source and participants. Explicit
canonical denial vetoes plan approval and admission. Expiry and incomplete
prerequisites refuse admission. Revocation retains earlier evidence.

Each `checks` entry has exactly `check`, `recipe`, `recipes_sha256`, `evidence`;
IDs use lifecycle slug syntax and the recipe-file hash uses SHA-256 syntax.
The check IDs must cover the declared set exactly once. `gates` contains the six
existing evidence gates plus `reviewer`, each with bounded nonempty evidence
references. These are operator claims: artifact contents and authenticated
independence remain unverified. This evidence cannot authorize a job.

Registration, decision and admission use the existing idempotent journal receipt
mechanism. Lost replies recover by the same event ID and exact bytes; changed
bytes refuse. An admission cannot be replaced under a new event ID. None of these
three events settles an UNKNOWN effect or changes accounting.

Before admission, registered plans remain held from execution. After admission,
`route` accepts only `<request.team>/lane/<plan lane>`; `intent` and `start` accept
only the registered writer. Intent consumes the single start; a second intent or
start refuses. These three paths recheck plan approval, canonical denial, expiry,
prerequisites and participant generations. `review` requires terminal evidence,
plan approval/admission and the plan-bound Reviewer in its current generation,
independent of the writer who recorded the intent. Expiry or writer succession
after work started does not prevent review of that evidence.
Legacy `admit` remains refused; small-change admission stays separate from
canonical authority and admission. Canonical `associate` refuses every small-change
row, including rows also approved canonically, until a separately reviewed provider
integration exists. Admitted, unstarted rows stay out of `continuation_candidates`:
the pinned watch/Operator cannot execute them. Their explicit hold is
`small-change requires the T1 dispatcher`; eligibility appears separately in
`small_change_ready`. This view-only key appears only in journals containing
small-change rows and never changes checkpoints or canonical-only status.
No Orchestrator or Decider event is needed for the evidence sequence `route`
-> `intent` -> `start` -> `terminal` -> `review` -> `delivery` -> `disposition`
with resolution `complete`. Terminal and review sources remain the request's
base source; the writer's new commit appears only in evidence. UNKNOWN blocks
closure, preserves accounting and admission, and permits no repeated start or
resource release. Existing exact-receipt recovery applies to every event.

Plan-decision/admission events still require an untouched request; after routing
or intent, canonical denial remains the existing revocation path.
A legacy delivery lost before registration remains visible as
`delivered_unrecorded`; recovery refuses without resending or discarding it.
Only new events introduce projection keys, preserving historical checkpoints.
Old readers refuse these new event types; this opt-in evidence writer does not
claim mixed-version runtime activation or N/N-1 qualification.
Readers predating the execution seam also refuse admitted-row execution events.

## Base and acceptance ledger

The clean existing checkout branched directly from fetched integration commit
`76e720f2f2f207a2c58ac0841957f2804b994cf5` (PR #282 merge), tree
`cc714fc31f2002f0032f1b3097ad80173e8d8f70`. This equals tested/reviewed candidate
`2194b9337fb698d4af46974716a2eef86c0815d8`'s tree. PR #259 was rechecked open,
draft, targeting `develop`; this PR targets `feature/manager-workspace-prototype`.
No active runtime source pin is changed.

Prior reader full local result: 17,601 passed, 16 skipped, 6 warnings. Hosted
[Validate 42377572320](https://github.com/nseney1/Aegis-Guardrails/actions/runs/42377572320)
was still running at reconciliation: test-fast, dependency audit, wheel build and
Linux 3.11 passed; other platform legs pending. Prior hosted Ubuntu 3.9 elapsed
failure and local Go metadata timeout remain retained; causation is not inferred.

| Gate | This slice |
|---|---|
| Implementation | Registration/admission and the complete lifecycle evidence path; separate `small_change_ready` eligibility, stable canonical watch hold, provider association refused, terminal review survives expiry/writer rotation |
| Public RED/GREEN | Missing-event RED retained; initial GREEN 33 passed; review found canonical-denial bypass and two public RED regressions reproduced it |
| Independent frozen-commit review | Codex and Claude requested changes on `1d15dc4e`; this follow-up addresses those findings and awaits independent review |
| Affected / full local verification | First affected: 604 passed in 121.09s; post-revocation-fix affected: 607 passed in 128.12s; first full RED retained: 7 failed, 17,648 passed, 16 skipped, 6 warnings in 1410.71s |
| Hosted verification | Pending publication |
| Native / installed runtime / efficiency / Teams acceptance | Open; owner explicitly authorizes this slice's integration under the qualification gaps below |

The registered-workspace Aegis scan supplied repository guidance from the
reviewed merge-base with `origin/HEAD`, not host authentication or execution
approval. Historical fixtures, reservations, job identities, UNKNOWN holds,
cumulative accounting and the five-team capacity remain unchanged.

Local verification uses Linux/Python 3.12.3 and the existing CI environment with
pytest 8.3.4, xdist 3.6.1, Ruff 0.9.10, Hypothesis 6.126.0, coverage 7.6.12,
PyYAML 6.0.2 and AnyIO 4.12.1. Its interpreter directory is prepended to PATH;
HOME/config/cache/temp are isolated under `/var/tmp`, with four workers and
normal pytest retention. Ruff and Layer 1 checks passed; warnings are retained.
Python 3.9 runtime/platform coverage remains a separate hosted result.

The first full run exposed a missed role-registry vocabulary/projection update
and the fixture replay reader's exact lifecycle successor pin. All seven failures
are retained. The registry now names the three evidence events under their
existing roles without adding provisioned tools. The lifecycle execution seam in
`1d15dc4e` used replay pin
`e030d6aa17466837fb69a135b8eaad669b3f58c44d272725001ce8bad8ac7fb9`.
This review follow-up changes `LIFECYCLE_SHA256` to
`a7bae191536781004abe8b9cb9a8e5d6380e5a58498c7eb5ae147bf3e95e6dbd`.
This is a reviewable source change to the replay adapter, not a refresh of any
active runtime pin. Historical corpus bytes and their original pins remain
unchanged. Expanded affected checks include registry/provisioning and foundation
replay, retaining source-tamper and poisoned-bytecode refusal coverage. Final
full qualification and exact-source independent review remain pending.

Expanded affected RED retained: 2 failed, 863 passed in 225.43s. The remaining
registry failures required listing the new approval in non-ROOT prohibitions
and updating the exact ROOT approval vocabulary assertion to include the new
plan-decision evidence. The root-only assertion is retained and extended;
provisioned adapters, calls and tools stay unchanged. No assertions, deadlines
or runtime guards are weakened.

Owner steering: finish this in-progress slice and stop. Major plan changes and
the owner's report of removed core features require separate reconciliation;
this slice neither resolves that concern nor removes any actors or core features.

The owner subsequently explicitly approved push and merge into
`feature/manager-workspace-prototype`, with successor-session fixes and scope
reconciliation to follow. No second local full suite is claimed. The final
expanded affected check was running at source freeze; its result, exact commit,
review receipt and merge identity belong to the delivery PR and retained local
evidence. Earlier failed runs stay part of the record. Hosted qualification for
this slice is unrun; provider/native/Stormheir/M1 gates remain deferred.

At the owner's follow-up request, task-created scratch directories will be
removed after preserving logs, failure fixtures, metadata and exact source
snapshots in a compact local evidence bundle under `docs/internal/`. Existing
evidence directories from earlier work are outside this cleanup scope.

Remaining T1: authenticate approval and Reviewer/check admission through the
protected integration; build complete deterministic routing/mail/job delivery
and conservative reply recovery before omitting model turns; complete fresh
brief composition and continuity qualification. Remaining T4: workspace/proposal
integration and compatibility qualification. T0/T2/T3/T5 acceptance stays separate.
Native providers, Stormheir and M1 exit-gate runs remain deferred.
