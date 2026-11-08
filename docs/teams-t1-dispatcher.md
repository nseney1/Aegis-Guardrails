# Teams T1 PR3: small-change dispatcher design, accepted D4–D7

Design only at HEAD `30f9ae7e1f57bfceff237ecf1e418b2c7f550a51`; references use this branch's lines. Complete `t1-dispatcher/design-review-r1.md`
read; all REAL findings accepted. D4–D7 are accepted in v5.0-teams-dogfood-reconciliation-20261107.md, Owner decisions D4–D7. All host behavior is
**modelled**, not observed; names are proposals. Python 3.9/stdlib only.

## 1. Placement, scope and existing gaps

Add `tools/hierarchy_small_change_dispatch.py`, called by a proposed router `dispatch` subcommand in the loop: `router_status -> route ->
dispatch -> sweep -> run_open`; receipts advance dispatch on the next tick. Today's four-step sequence is `tools/hierarchy_loop.py:541-556`.
Pass dispatch the configured `--recipes` path; leave the existing global run-open invocation, arguments, budget and scheduling unchanged
(`:520-539`). The current router lifecycle actor records only `route` (`tools/hierarchy_router.py:260-273`).
D7's mixed-queue check gates every new route, dispatch and job_request in that initiative; it never gates the existing global run-open call.

D3 authorizes publishing under the borrowed current `<team>/orchestrator` mailbox binding, without its model turn. The routes already exist
(`tools/hierarchy_mailbox.py:492-509`); fencing/readiness remain mandatory (`:457-473`). The cross-role precedent is the job runner borrowing
ROOT (`tools/hierarchy_jobs.py:1271-1274`); the router borrows its own role's binding (`tools/hierarchy_router.py:321-325`). D4 resolves registry
attribution through a dedicated dispatcher service with exactly mailbox:dispatch and mailbox:job_request; no ADR-only waiver.

Read lifecycle rows/events/policy including `small_change_ready` and closed-row audits, validated mailbox/binding/acceptance history, delivery
receipts, initiative registry, recipes and retained job evidence. Ready disappears after intent (`tools/hierarchy_lifecycle.py:999-1042`), so
inspect all rows; retain the pinned watch exclusion (`:1031-1035`). Write initiative briefs/check packets, existing mailbox messages, route
events and derived status. No descriptors, saved route envelopes, recipe snapshots or second authority ledger.

PR3 does not supply participant recording: the writer must be an operator (`tools/hierarchy_lifecycle.py:509-511`), but lanes/Reviewer have no
provisioned journal connection (`tools/hierarchy_provision.py:471-491`, `tools/hierarchy_mailbox_mcp.py:287-294`,
`tools/hierarchy_roles.py:50`). D5 assigns that seam to a separate provision/MCP follow-up, including Claude writers; PR3 tests participant events through
the public lifecycle CLI in tests. Do not imply a real team can progress past writer dispatch today, or add an invented always-failing
capability gate. Coordinator means Orchestrator (`tools/hierarchy_templates/role-registry.json:75-79`); D6 makes closure an owner CLI action
under that current coordinator actor, never a dispatcher-authored event or automatic Orchestrator turn.

## 2. Endpoints and per-row progression

Writer endpoint is exactly `<team>/lane/<plan.writing_lanes[0].lane>` (`tools/hierarchy_lifecycle.py:790-794`). Before writer publication
require manifest kind `implementer` or `integrator`, and exactly one lane in that team with `kind=reviewer`; that unique lane is the Reviewer
endpoint. Missing/ambiguous/wrong kinds hold before work. Resolve both with `Mailbox.current_binding`, requiring acknowledged handoffs
(`tools/hierarchy_mailbox.py:470-473`, `:868-871`). Lifecycle participants must independently match registered
CID/generation/role/currency/independence (`tools/hierarchy_lifecycle.py:495-514`). No CID-to-session authentication exists; generations are
separate namespaces. Dispatch metadata and the composed brief name endpoint/target generation; original acceptance/result bindings must match
that target's historical binding. No free endpoint mapping or undefined dispatcher configuration is introduced.

```mermaid
sequenceDiagram
    participant D as Dispatcher service (router lifecycle actor)
    participant M as Mailbox (borrowed Orchestrator sender)
    participant W as Writer lane
    participant L as Lifecycle journal
    participant J as Existing ROOT job runner
    participant R as Unique Reviewer lane
    participant O as Owner via public CLI (current coordinator actor)
    D->>M: scw dispatch + composed brief
    D->>L: route, current router and ROOT custody
    W->>M: acceptance with readiness
    W->>L: intent, matching start (D5 follow-up)
    par Either arrival order; both required
        W->>L: terminal with raw SHA-256 T
    and
        W->>M: result with lane_check lifecycle-terminal:T
    end
    D->>M: preflight all N checks, then missing deterministic scj requests
    J->>M: receipts for original requests
    D->>M: scr Reviewer dispatch + composed brief
    R->>L: review (D5 follow-up)
    R->>M: review completion
    D-->>O: small_change_close_due + draft envelopes
    O->>L: delivery + disposition complete, or owned HOLD
```

| Transition | Trigger / durable proof | Actor and refusal |
|---|---|---|
| Admission -> writer sent | Ready row, no prior attempt; scw message and matching route receipt | Mailbox: borrowed current Orchestrator; journal: current router/custody. Require approved/admitted exact plan, prerequisites, unspent start, participants, endpoints and §3 expiry margin; otherwise publish nothing. |
| Writer sent -> writing | Accepted scw with readiness; intent/start receipts | Lane mailbox binding and registered operator CID/generation. Writer checks route receipt cooperatively. Intent consumes one start; repeat, revoked/expired/stale participant refuses (`tools/hierarchy_lifecycle.py:797-843`). Acceptance gates apply because the writer kind was checked (`tools/hierarchy_mailbox.py:881-894`). |
| Writing -> result validated | Accepted completion reply plus matching passed terminal | Starting writer records terminal (`tools/hierarchy_lifecycle.py:844-863`). Dispatcher verifies correlation and the terminal reference below. Missing second record waits; unknown/failed/malformed/mismatched evidence holds. |
| Result validated -> checking | §4 preflights all N; one job_request per admitted check, each published ID is proof only of request delivery | Borrowed current Orchestrator -> own ROOT. Check live canonical deny before every publish, recipe hash, fixed result commit/tree, accepted readiness's registered clean checkout and supported recipe; any failure stops missing publications. |
| Checking -> checks complete | Every original scj has matching completed/exit-0 receipt, retained packet/claim/result/witness/evidence and settled reservation | Existing runner borrows ROOT, not a ROOT model. Admitted hash must equal claim and result; mismatch holds this row. Failed/refused/unknown/malformed evidence never causes replay. |
| Checks complete -> reviewing | All checks verified and terminal passed; one scr plus composed brief naming exact commit/tree and receipts | Borrowed current Orchestrator -> unique Reviewer lane. Live canonical deny, plan approval/admission, registered current independent Reviewer and handoff readiness rechecked. Refuse any missing prerequisite. |
| Reviewing -> close due | Lifecycle review accept matches terminal hash/base source; mailbox review completion matches scr and result commit/tree | Registered Reviewer lifecycle actor and original Reviewer lane binding; both records required. Reject/mismatch holds, never synthesize acceptance (`tools/hierarchy_lifecycle.py:555-562`, `:866-875`). |
| Close due -> disposition | Owner records drafted delivery then FINAL/complete, or HOLD/blocked | Current coordinator/custody via owner CLI, D6; dispatcher borrows no coordinator recording authority. Revalidate all receipts and review; lifecycle enforces terminal/acceptance/delivery but not job coverage (`tools/hierarchy_lifecycle.py:681-705`, `:876-887`). UNKNOWN permits owned blocked disposition only. |

Binding direction A is fixed: result.lane_check must match `^lifecycle-terminal:[0-9a-f]{64}$` and name row.terminal.sha256. The writer can
precompute this raw terminal hash before either publication; terminal evidence references the dispatched brief/evidence, never the future result
message file. Either arrival order is valid; once both exist a missing/malformed/mismatched reference is `small_change_result_invalid` across
ticks, with no replacement start/result. No jobs publish until both agree. Terminal/review source remains the request's base source; new
commit/tree appears in evidence/result only (`tools/hierarchy_lifecycle.py:850-863`, `:869-873`). `completion()` checks shape/outcome enum, not
duplicates or success (`tools/hierarchy_mailbox.py:847-861`): nonduplicate check names and all-pass lane checks are new dispatcher validation.
Lane claims do not replace admitted job checks.

## 3. Identity, route recovery and expiry margin

IDs: writer `scw-<plan_sha256>`, Reviewer `scr-<plan_sha256>`, check `scj-<sha256(encoded({plan_sha256, check}))>`; full hashes fit existing
slug syntax. Route event ID equals scw ID. Immutable route identity is only event/message ID, request ID/hash and `to`; actor/generation/custody
are rebuilt. Message bodies bind request/plan/admission hashes and stage; dispatches name target generation, jobs name check, recipe/hash and
exact result reference. No timestamp, binding succession or result revision creates another work ID.

Under mailbox writer lock, load/release the journal's exclusive **writer lock** (`tools/hierarchy_router.py:71-76`). First inspect row.routed
and the scw receipt: load the receipt's journal entry, verify route identity and router role, and return the original receipt without
record/rebuilding its actor. Mismatched/other route identity holds. A receipt with an absent message is `small_change_message_lost`, never a
reason to republish. If no receipt, rebuild from the current router and ROOT custody as `tools/hierarchy_router.py:302-309` does; validate
current router, copied-state/cap dry-run (`:276-282`), publish only if absent, then public Lifecycle.record. Release the journal lock before
record reacquires it, retaining the mailbox lock. No private append or backdating. After append, rebuilding and resubmitting would conflict with
exact-envelope replay (`tools/hierarchy_lifecycle.py:978-988`), which is why the recorded-receipt check comes first.

Generalize canonical same/conflict (`tools/hierarchy_router.py:139-148`): compare from/to/type/reply and parsed request/plan/admission/stage
identity; for jobs compare exact deterministic packet bytes and result/check inputs. Verify the published brief's byte hash, request and target
generation; stored reads skip attachment hashing (`tools/hierarchy_mailbox.py:488-489`, `:531-560`). Reuse the published brief, never recompose
over it. Historical sender binding lookup is NEW dispatcher validation via Mailbox.bindings(from); canonical prior_delivery explicitly ignores
sender binding fields (`tools/hierarchy_router.py:142-143`). Never require today's generation. If absent, recompose PR2 with explicit current
target_generation and live as_of; unused content-addressed briefs are harmless (`tools/hierarchy_fresh_brief.py:590-631`). Missing/corrupt
references or ID conflicts hold.

Before a new writer publication, after composition and under mailbox lock, require `expires_at - now > M`, where proposed `M = 2 * wait + 30
seconds` (40 seconds at the router's default wait=5; `tools/hierarchy_router.py:375`). The two waits budget nested lock retry windows (`:59-68`,
`:325-329`); 30 seconds is a modelled scan/publish reserve, not an observed host latency bound. Margin failure is small_change_expired with no
message. It reduces, not eliminates, the race: record stamps a fresh time and rechecks expiry/participants
(`tools/hierarchy_lifecycle.py:790-794`, `:986-988`). Late record refusal retains delivered_unrecorded and skips the writer lane until
receipt/reconciliation. Intent/start without the matching route receipt is a protocol-violation hold; lifecycle alone does not forbid it.

Crash after publish/before append: find same, rebuild current actor/custody, append once. Router/ROOT succession in that gap is not a hold;
expiry, denial or participant changes can still refuse. Crash after append returns receipt. No journal append accompanies scj/scr publication;
published history is sufficient for recovery. Fsync dispatcher-published packet/brief and destination mailbox directories before subsequent
route append; publish_file fsyncs file contents only (`tools/hierarchy_mailbox.py:298-317`). A SIGKILL can leave O_EXCL locks (`:257-270`):
report busy/owner recovery; never remove/reclaim them automatically. Recovery assumes locks available after owner verifies the recorded process
is gone. These are local crash claims, not power-loss/native qualification.

## 4. All-check batch and per-row recipe provenance

Use v1 packets after the result: closed v1 cannot contain recipes_sha256, and v2 requires a preceding job_request
(`tools/hierarchy_jobs.py:919-945`, `:837-858`). Bind the admitted hash in job message body, not the packet. No existing plan field binds a
recipe's test-argument selection (`tools/hierarchy_lifecycle.py:220-249`, `:619-629`): support only command, require_clean=true recipes with no
`$paths` step; omit paths. Otherwise configuration hold, not guessed paths/globs or a new configuration store
(`tools/hierarchy_jobs.py:407-424`).

Before ANY scj publication, under one mailbox lock preflight ALL N admission entries: exact coverage/unique IDs; valid route/start/passed
terminal/result; live plan approval and no canonical deny; expiry; current participants; registered clean checkout at result commit/tree; all
supported recipes/hashes; packet sizes/attachments, binding readiness, existing same/conflict messages and record-limit headroom for the entire
missing set. Failure publishes none of that set. Prepare deterministic packets in memory/content-addressed briefs, without descriptors. Then
publish missing IDs in sorted check order in that lock. Immediately before EACH message, reload journal and require last_decision(request_id) !=
deny (`tools/hierarchy_router.py:79-82`), recheck expiry and hash the configured recipe file's raw bytes as load_recipes does
(`tools/hierarchy_jobs.py:247-279`); require that check's admitted hash. A concurrent denial after the live check remains a race like canonical
routing (`tools/hierarchy_router.py:285-290`).

This batch is not atomic. On a crash after k of N, derive the entire set again from admission and published history; validate every existing
message, then resume only missing deterministic IDs under the same preconditions. After expiry/deny/drift/failure, publish no missing requests:
hold with published IDs/runner states and missing IDs. Existing published jobs remain in the unchanged runner protocol; never cancel, release or
reissue them. Expiry mid-batch similarly holds the remainder. An incomplete batch cannot dispatch Reviewer; owner records HOLD.

Leave loop run-open untouched: no snapshots, per-initiative substitutions, dispatch-success gate or recipe gate. If recipes change after
publication, a check may run under the owner's current recipe, consume its ID and fail provenance afterwards. Require admission hash == claim
hash == result hash at settlement; any mismatch is a per-row small_change_recipe_mismatch, even if exit is zero (`tools/hierarchy_jobs.py:1187`,
`:1806`, `:867-870`). Other canonical jobs continue. Failed/refused/unknown jobs never receive replacement IDs; exclusive Job.claim and
retained-result settlement already prevent runner replay (`tools/hierarchy_jobs.py:1177-1190`, `:1955-1982`).

Retained-artifact successor to the denied whole-candidate review: receipt validation consumes one private, descriptor-anchored snapshot of
all step-* and derivation candidates plus result/claim/process/packet metadata. Preflight original paths before discovery; retain validated
ancestor and file descriptors, refuse symlinks/nonregular entries before reading, and detect identity, content metadata or membership change
before publication. Evidence hashes, original-path references, result validation, process-stop checks and exact receipt body use captured data;
never return the folder to unchecked Job readers. This fixed-v1 path refuses the exact reserved names execution.json, derivation.json and
admitted.json at anchored directory discovery, before any content open, regardless of file type or apparent execution liveness. Surface
small_change_receipt_invalid with the unsupported retained v1 metadata filename. The current qualification-base runner may prefer execution
claims or include derivation evidence; this refusal is a version boundary, not a copy of dependent-job support or proof of current-base runtime
parity. D5 dependent-job adoption remains a separate held successor.
Read each regular file at most its initially observed N bytes through bounded chunk requests and a remaining counter; do not follow appends
to EOF. Short reads, growth or rewrites hold, followed by the existing identity/content-metadata/membership validation. Large valid regular logs
have no mailbox-size cap; preserve the runner's 4 MiB result limit, 2000-byte numeric-log tail, empty-log fallback, UTF-8 replacement and control
filtering. This snapshot is ephemeral, not a persistent store.
A valid retained failed/refused result with matching admitted recipe provenance holds small_change_check_failed even if terminal receipt
publication failed. Publish no missing batch IDs or Reviewer work; only the unchanged runner settles the original job and reservation.
Receipt history is checked before PR2 job_state: any valid failed/refused receipt holds small_change_check_failed whatever follows it, and a
nonterminal receipt ordered by receipt_order after a terminal one is small_change_receipt_invalid (Mailbox.publish refuses that history).

## 5. Loop-only skips, reporting and holds

Canonical-compatibility successor to prior R4 b087f711ae76460591095c81760f10454d1806d56379772e07f0f065110ff17b:
the seven malformed-status failures retained in receiver-20261108/dispatcher-full require independent durable reconstruction.
The guarantee is: while a team's small-change rows require dispatch coordination, THIS LOOP starts no Orchestrator or Decider turn. Manual
wake/sweep, launcher resume and team turn are owner actions outside it; manual sweep/run-open must not accompany the loop
(`docs/agent-hierarchies.md:1013-1014`). No automatic cancellation of running turns. Immediately before sweep, even after a dispatch-child
failure, call public hierarchy_small_change_dispatch.project(..., mutate=False) directly, independently of canonical child output. Preflight
RAW lifecycle/store paths with router.preflight_paths before constructing Lifecycle/Store or discovering private inputs. Validate this public
projection with _decode_dispatch(..., status=True), never the canonical decoder. Malformed canonical/dispatch child holds remain visible;
they do not prove durable inputs unreadable or block healthy independent work. No cached report, failed payload or empty-default evidence.
Use the validated team-scoped exclusion set (Orchestrator AND Decider), plus writer-lane exclusions for scw present/conflicting without verified
route receipt. Release query locks before wakes. An empty canonical projection keeps small_changes=None and omits that output field.
Pass the sweep's generic --skip (`tools/hierarchy_sweep.py:296-301`); never put these
sets in Pass.skipped, keep_skips or status.json as skip authority. Change loop skipped-row handling (`tools/hierarchy_loop.py:469-485`):
planning skips retain unread counts and a small_change_planning_skipped report, never a fabricated start_failing. Existing start_failing
handling stays separate (`:512-518`, `:643-644`). Losing status.json cannot release a planning skip. Actual busy, corrupt, unreadable, private
or symlinked durable input, or invalid projection, means owner planning_exclusions_unavailable and skipped sweep, with the cross-team wake
delay explicit; run-open still runs. This projection records no event/publication and changes no capacity, claim or accounting authority.

Malformed durable policy roles that raise TypeError/KeyError at this reconstruction boundary also produce planning_exclusions_unavailable;
the finite exception boundary does not hide failures elsewhere. Under the mailbox lock, canonical delivery reloads the journal and classifies
original delivery first: conflict remains conflict, identical publication recovers its receipt even after a queue becomes mixed. With no prior
delivery, a fresh mixed queue refuses before publication. The outer filter admits delivered_unrecorded rows for that recovery. The existing
bounded race after the final journal check remains explicit; no lock is held across a wake.
A foreign writer/Reviewer assignment is closed only by unique correlated acceptance and completion over validated mailbox records, correct
historical bindings/endpoints and chronology. Valid closed history permits later work across binding succession without proving any new
lifecycle/check success. Missing, duplicate, malformed or ambiguous completion holds; live canonical conflicts remain independently enforced.
Each of the dispatch, acceptance and completion must come from the sender generation in force at its created_at (that binding's creation
at or before it, the next binding's creation strictly after it) and acknowledged: the historical form of Mailbox.fence. A superseded
generation's record holds small_change_mixed_queue. Completion may come from a later generation than acceptance, as Mailbox.publish permits
an acknowledged successor; never an earlier one. The dispatcher's own scw/scr target-generation checks are unchanged. Before a new scw, the
writer-lane open-dispatch guard applies this same validated closure to every dispatch to that lane, sibling small-change scw included: one
not validly closed is open and holds small_change_configuration ("writer lane already has an open dispatch"). After the writer
terminal, a foreign job_request whose packet cannot be read or decoded, or is not a JSON object, holds small_change_mixed_queue
("malformed foreign job packet") as a row hold; the loop pass and run-open continue.

For skip purposes an owned HOLD is a recorded coordinator disposition/resolve with blocked resolution and bounded
owner/next_decision/condition/evidence; lifecycle obligations and UNKNOWN are still retained. Planning skips lift when EVERY small-change row in
the team is complete or has such an owned HOLD. D7 independently permits early owner release without denial or a blocker; current records lack
that independent decision (§9). Do not substitute HOLD, denial, status edits or arbitrary message bodies. At release, list retained replies by scw/scj/scr parent IDs, message IDs,
paths and unread counts in status. They are dispatcher-owned information, not newly assigned work. The next sweep MAY wake Orchestrator on that
mail; the zero-turn guarantee ends at release. Acknowledging a successor mailbox binding is also an owner action.

Router status requests/route candidates must OMIT every small-change row, including routed ones: retire the stale per-pass
small_change_dispatch_unavailable (`tools/hierarchy_router.py:88-94`) and avoid canonical routed/revoked duplicates (`:166-170`;
`tools/hierarchy_loop.py:440-448`). A separate small_changes projection owns their progress and holds, including canonical denial as
small_change_revoked. Update the loop decoder (`:186-206`) for that projection. Keep team_view.standing and canonical pending rows unchanged;
team_status's legacy routed state remains a canonical projection, with separate small-change progress, not evidence of delivery to Orchestrator.

| Hold / report | Trigger and action |
|---|---|
| small_change_result_invalid / small_change_receipt_invalid | Malformed/duplicate/nonpassing/mismatched evidence, wrong terminal reference, result binding or absent route for intent/start. Hold without replay; mailbox readers revalidate stored records (`tools/hierarchy_mailbox.py:531-560`). |
| small_change_check_failed / small_change_review_rejected | Failed/refused check or reject; preserve evidence and surface owner HOLD drafts. Recipe provenance mismatch uses small_change_recipe_mismatch instead. |
| small_change_unknown_effect | Unknown terminal/receipt/process or interrupted original writer. Keep lifecycle obligations/continuation_holds (`tools/hierarchy_lifecycle.py:1009-1018`). The pinned 'dispatcher resume required' text does NOT mean PR3 can resume a writer replaced by succession; owner HOLD/blocked is the available reconciliation. |
| stalled_dispatch | Reuse sweep's existing accepted/unanswered/no-unread/no-running-turn hold (`tools/hierarchy_sweep.py:258-275`; `tools/hierarchy_loop.py:490-493`). No reminder dispatch. |
| small_change_expired / small_change_revoked | Block new writer/check publications; live deny also blocks scr. Keep terminal/receipts; read-only Reviewer dispatch after valid start may survive expiry, never denial (`tools/hierarchy_lifecycle.py:555-562`). No release by expiry/deny. |
| delivered_unrecorded / small_change_message_conflict / small_change_message_lost | Missing route append, conflicting deterministic message or missing published scw despite receipt. Owner reconciliation if live route preconditions cannot recover; never resend. |
| small_change_configuration / small_change_binding_changed | Endpoint/recipe unsupported, participant changed, borrowed Orchestrator binding unready, or concurrent planning turn. Owner action; after acknowledged Orchestrator succession use the same IDs. |
| small_change_planning_skipped / small_change_mixed_queue | D7 holds a mixed live canonical/small-change queue in one initiative: stop new route/dispatch there and list both queues; other initiatives and the existing global job runner continue. An open canonical row alongside an open small-change row is mixed; completed, denied or owned-HOLD rows are not pending work. Correlated foreign IDs also hold; deterministic IDs do not prevent outside publications. |
| small_change_close_due / small_change_closed_unverified | Owner closure drafts due; audit complete rows too and flag missing scr/check receipts. Lifecycle completion alone does not verify jobs; do not undo or conceal an already recorded completion. |

Receipt validation additionally checks retained packet, recipe, before/after source witnesses, evidence hashes, receipt_matches, stopped
processes and settled reservation (`tools/hierarchy_jobs.py:862-891`, `:1312-1353`). Use PR2 job_state ordering for later unknown/ties
(`tools/hierarchy_fresh_brief.py:358-381`); no synthetic reads. Full rows/drafts/evidence are in router status.small_changes; bounded loop holds
surface through team_status.holds_by_act (`tools/hierarchy_team_view.py:175-195`).

## 6. ROOT pending and explicit owner closure

Keep every canonical pending row/root_decide argument byte-compatible (`tools/hierarchy_team_view.py:42-69`, `:100-132`): team approve selects
that array (`tools/hierarchy_team.py:1249`), and root_decide records only decision (`tools/hierarchy_mailbox_mcp.py:392-417`). Add optional
sibling small_change_pending for actionable plan decisions: request ID/hash, plan hash, last decision/admission, expiry and why. No redundant
all-plans array or unusable ROOT decision templates. ROOT can relay plan decisions to the owner CLI; no new ROOT tool or shell is implied.

Under D6, surface small_change_close_due in router small_changes/loop owner holds. Draft exact coordinator delivery then disposition
FINAL/complete envelopes, or HOLD/blocked with named owner/next_decision/condition/evidence. Dry-run the ordered sequence on a copy, including
cap/event limits and the evidence required for the chosen outcome. Owner records via hierarchy_lifecycle.py record --evidence-only; dispatcher records
neither. Drafts use current coordinator and ROOT custody, deterministic event identities and existing receipts; redraft after succession. After
an owned blocker, draft resolve with the exact blocker_sha256 instead of a second disposition (`tools/hierarchy_lifecycle.py:881-887`).
Incomplete/failed/unknown/revoked work gets blocked, never complete.

## 7. Pins, authority and accounting

No protected-file change is needed: preserve mailbox, wake, lifecycle at PR1's c941520a successor, native_protocol, operator, watch_bridge,
watch_supervisor, tests/fixtures/** and test_hierarchy_lifecycle.py. Effective foundation pins combine the manifest with FOUR overrides:
mailbox, wake, lifecycle, and the watch-bridge TEST (`tools/hierarchy_foundation_acceptance.py:18-25`, `:195-204`). WATCH_TEST_SHA256 is
cf5df318...; the manifest's older watch-test/lifecycle/wake entries are not effective overrides. Stop if implementation needs a protected edit.
D4 serializes the dedicated dispatcher entry after T2(a), preserving PR283 lifecycle/registry vocabulary and Router prohibitions; no new action names or ADR-only deviation.

Dispatcher does not append Store events, acquire/renew/release leases, grant/reclaim slots, meter actors or reset accounting. Acceptance still
counts writers (`tools/hierarchy_mailbox.py:881-894`); writer intent alone consumes its start/opens its meter
(`tools/hierarchy_lifecycle.py:821-825`); jobs alone enqueue/grant/release on evidence (`tools/hierarchy_jobs.py:2145-2180`, `:1329-1353`).
Ordinary elapsed time still advances (`tools/hierarchy_lifecycle.py:317-320`).

## 8. Expected implementation and tests after approval

PR3 files: tools/hierarchy_router.py, tools/hierarchy_loop.py, tools/hierarchy_team_view.py and new tools/hierarchy_small_change_dispatch.py;
tests/integration/{test_hierarchy_router,test_hierarchy_loop,test_hierarchy_team_view,test_hierarchy_small_change_admission}.py (including the
retired-hold assertion at test_hierarchy_small_change_admission.py:249), new tests/integration/test_hierarchy_small_change_dispatch.py; docs/agent-hierarchies.md
and this note. D4 also serializes role-registry.json and its service-attribution tests after T2(a), using the existing vocabulary/trigger names;
D5's provision/MCP lane recorder, Claude included, is a separate FOLLOW-UP. No jobs, team CLI, composer/launcher/handoff, role templates or protected-file
edits in dispatcher behavior work.

Public CLI/subprocess RED then GREEN with temporary real journals/mailboxes; fake only host/process boundaries. Test: no loop planning turns
while open, retained unread visible, no false start_failing, status loss preserves skips; mixed same-initiative queues hold without changing canonical jobs; closure/owned HOLD releases skips and lists retained
replies; public CLI participant injection reaches close_due, then owner CLI reaches complete or owned HOLD. ROOT plan decisions stay separate,
canonical pending/approve unchanged. Crash after writer publish recovers one message across router AND ROOT succession; crash after append
returns original receipt; near-M boundaries, delayed record expiry, absent message with receipt, and unrecorded route never wake writer.
Malformed result/receipt, wrong/missing terminal reference in either arrival order, failed/unknown/rejected checks hold across ticks without
replay; reservations/leases/meters unchanged by dispatcher-only passes; stalled hold reused. Batch preflight failure publishes zero; crash after
k/N resumes only missing IDs before expiry, holds remainder after expiry/deny/drift; deny before jobs or scr publishes nothing. Two rows with
different recipe hashes and post-publish drift hold only affected rows while unrelated canonical jobs run. Test wrong writer kind, zero/multiple
Reviewers, unsupported $paths, binding handoff, closed-row audit and foreign publications. Run affected suites, then full suite before
orchestrator commit; no commits here. PR4 fake-host continuity and real-host/native qualification remain separate.

## 9. Accepted decisions and remaining qualification

- D4: dedicated model-free dispatcher registry entry, calls exactly mailbox:dispatch and mailbox:job_request under the borrowed Orchestrator binding; serialized after T2(a), PR283 vocabulary preserved. No ADR-only exception or coordinator authority.
- D5: PR3 tests dispatcher behavior using participant events through the public lifecycle CLI. A separate provision/MCP follow-up provides writer intent/start/terminal and Reviewer review, including Claude writers. Registry/tools must qualify before real end-to-end activation.
- D6: owner records exact drafted delivery/disposition envelopes via hierarchy_lifecycle.py record --evidence-only, surfaced as small_change_close_due. No model turn or dispatcher-borrowed coordinator recording authority.
- D7: per-team Orchestrator/Decider skip until all small-change rows are complete or owned HOLD, retained replies visible, mixed same-initiative queues held; owner may lift early by a recorded decision without revoking work or declaring a blocker.

Independent early-release gap: decision accepts only approve/deny (`tools/hierarchy_lifecycle.py:778-785`); small_change_decision also accepts only approve/deny and requires an untouched row (`:565-604`); disposition/resolve changes the obligation (`:881-890`). None represents a skip-only owner decision. Mailbox records carry information_only (`tools/hierarchy_mailbox.py:517-519`); status is derived, not authority.
Bounded follow-up: specify/qualify a closed, owner-attributed, team/plan-scoped early-release representation and public recorder/reader over existing durable record transport, with reason, binding/custody, idempotency and conflict checks. No new store, guessed API, pinned edit or free-form body promoted to authority. Transport/representation selection and qualification are unfinished work, not a further D7 policy choice. Until supported, retain the automatic skip and expose this dependency; never demand denial/HOLD instead. Early release changes wakes only, granting no execution or recording authority.

Standing execution contract: present plan/policy/config rejects unexpected input; only absent config keeps valid legacy behavior and no-host-plan Codex bytes. Validate/stage all writes before each publish; precommit refusal leaves state unchanged. Earlier committed messages in a crash/partial batch stay visible (§4), never falsely reported rolled back. Exemptions are reasoned schema allow-lists, never free-form. Never replay unknown writer effects or fabricate receipt reads.

Never read/write owner-private .claude/.codex directories; locate them using pwd rather than HOME for exclusion. Reject symlinks inside run homes. Children receive explicit environments, venv bin first, stripping CLAUDECODE/CLAUDE_PID/CLAUDE_CODE_* unless the host sets them. Tests use temporary homes and monkeypatched pwd.

Every guard needs RED/GREEN and a guard-removal check. Preserve valid behavior; fix/report unsafe invalid-input legacy behavior. One pytest at a time during a full suite; no lane team/m1_loop suites without instruction. Pins/fixtures remain untouched; no machine-local paths in repo files. Retain the verified document claim until orchestrator merge/release.
Implementation stop/report: `tests/integration/test_hierarchy_small_change_admission.py:249` asserts `loop.status()[change.value["id"]]["reason"] == "small_change_dispatch_unavailable"`; planned exclusion supersedes it. Preserve the exact existing calls assertion at `tests/integration/test_hierarchy_role_registry.py:168`: `supervisor["calls"] == ["session:wake", "router:route", "jobs:run-open"]` with PR283 vocabulary, or report a required change first. No silent test edits: orchestrator decides, with per-assertion justification and RED/GREEN evidence.
Freeze for two independent design reviews. Registry qualification, D5 recorder qualification, D7 early-release record seam, dispatcher/continuity/native qualification remain open. Implementation requires a separate brief after design review. No D4–D7 owner question remains.
