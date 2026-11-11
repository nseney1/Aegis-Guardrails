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
receipts, initiative registry, recipes and retained job evidence. Provision data must be an object, validated once and reused for delivery
selection; malformed provision data is a per-row small_change_configuration hold while independent canonical jobs continue.
Ready disappears after intent (`tools/hierarchy_lifecycle.py:999-1042`), so
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
that target's historical binding. For owned scw/scr assignments, fence the dispatch sender and each acceptance/completion by the binding's
creation and supersession interval and recorded handoff acknowledgment. Require dispatch <= acceptance <= completion while retaining strict
target-generation equality. Valid generation-1 replies published before a later rotation remain usable; retired senders cannot answer afterward.
No free endpoint mapping or undefined dispatcher configuration is introduced.

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
deny (`tools/hierarchy_router.py:79-82`) and recheck expiry. R8 captures/parses/hashes the configured recipe file once per operation, using the
same schema validation as load_recipes; require each check's admitted hash and revalidate the captured file witness at each effect boundary.
A concurrent denial after the live check remains a race like canonical
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
all step-* and derivation candidates plus result/claim/process/packet metadata. Preflight original paths before discovery; use temporary
validated ancestor handles and one artifact descriptor at a time, refusing symlinks/nonregular entries before reading. Close capture handles
before processing another job; retain captured bytes and identity witnesses, not batch-wide open descriptors. Before publication, reopen one
anchored path at a time and revalidate ancestor/artifact identity, content metadata and membership without rereading artifact contents.
Descriptor use depends on path depth, not the admitted check count. Evidence hashes, original-path references, result validation,
process-stop checks and exact receipt body use captured data;
never return the folder to unchecked Job readers. This fixed-v1 path refuses the exact reserved names execution.json, derivation.json and
admitted.json at anchored directory discovery, before any content open, regardless of file type or apparent execution liveness. Surface
small_change_receipt_invalid with the unsupported retained v1 metadata filename. The current qualification-base runner may prefer execution
claims or include derivation evidence; this refusal is a version boundary, not a copy of dependent-job support or proof of current-base runtime
parity. D5 dependent-job adoption remains a separate held successor.
Read each regular file at most its initially observed N bytes through bounded chunk requests and a remaining counter; do not follow appends
to EOF. Short reads, growth or rewrites hold, followed by the existing identity/content-metadata/membership validation. Large valid regular logs
have no mailbox-size cap; preserve the runner's 4 MiB result limit, 2000-byte numeric-log tail, empty-log fallback, UTF-8 replacement and control
filtering. This snapshot is ephemeral, not a persistent store.
R16b requires an exact positive integer group whenever a local process record exists; null/false/malformed groups contradict a claimed stop
and hold even when process_stopped_confirmed is true. Observe that group for surviving members. Derive exact step-N.log and any captured
step-N.out names from the producer's ordered Step objects; padded, signed, extra or aliased artifacts cannot satisfy a step.
Original process-record binding in terminal receipts is explicitly DEFERRED to JOBS-PROC after JOBS-1 and dispatcher. Current v1 receipts
contain step/result evidence without process.json; preserve exact original-receipt matching and pristine v1 progression. Local captured
process observations do not authenticate the original process record. No new required receipt field, producer edit or replacement receipt ID.
A valid retained failed/refused result with matching admitted recipe provenance holds small_change_check_failed even if terminal receipt
publication failed. Publish no missing batch IDs or Reviewer work; only the unchanged runner settles the original job and reservation.
Receipt history is checked before PR2 job_state: any valid failed/refused receipt holds small_change_check_failed whatever follows it, and a
nonterminal receipt ordered by receipt_order after a terminal one is small_change_receipt_invalid (Mailbox.publish refuses that history).

R5 recovery validates the original owned publication's sender interval and handoff acknowledgment before any route append. A retired or
unacknowledged sender cannot acquire a route receipt or release the writer exclusion. Valid publications predating succession still recover
their original receipt. Every check receipt must likewise come from its sender binding in force and be dated at or after its own request;
violations hold small_change_receipt_invalid without publishing missing work.
The shared fresh-brief reader covers dispatcher verification and composition's prepare/lifecycle/evidence traversal. R6 uses anchored,
nonblocking no-follow descriptors on capable hosts. Other hosts retain portable reference/standalone verification: lstat captures the leaf
and ancestor identities, open uses no-follow/nonblocking flags wherever available (binary mode on Windows), and fstat must match the regular
leaf before any content read. Recheck ancestry before reading and leaf/ancestor identity and content metadata afterwards; reject symlinks,
reparse points, nonregular inputs and changed identities. Publication retains its separate existing descriptor-capability requirement.
This portable fallback is not an anchored-descriptor or hostile-same-user guarantee; Windows/macOS CI and native qualification remain separate.
One stream routine hashes/captures at most the initial N bytes plus one EOF probe. Observed growth refuses before that probe; nonempty
zero-size virtual inputs or any readable content beyond N refuse instead of authenticating an empty/truncated hash. The same routine serves
retained job artifacts, preserving their limits, log tail and receipt body. Large regular logs have no mailbox-size cap.
R19 bounds the complete retained v1 artifact set before any artifact content open/hash: one anchored, non-following metadata gate refuses
unsupported candidate names, nonregular/reparse entries, files over 64 MiB and a job total over 256 MiB. The per-artifact ceiling matches the
operator/lifecycle reference ceiling; the aggregate bounds one stopped job's hash work to four such ceilings including metadata. Claim/process/
packet metadata retain 262144 bytes and result metadata 4 MiB. Only canonical step-1 through step-20 log/out names are supported; recipe-exact
step/capture validation still follows. All candidates must pass the metadata plan before capture; fstat must match the planned size/identity
before reading. Logs stream into hashes and a 2000-byte tail, never a full in-memory log. Refusals retain the job with fixed-text
small_change_receipt_invalid; no cancellation, deletion, replacement ID or canonical run-open gate is introduced.
Dispatcher and composer attachment consumers first validate the public envelope without content IO, then validate SHA-256 against bounded
captured bytes; packet comparisons, parsing and brief inspection consume those bytes without reopening through pinned Mailbox readers.
Attachments keep the 262144-byte limit; result metadata keeps 4 MiB. Completed command results require nonempty steps, every exit code zero,
and no timed-out step (timed_out, when present, must be boolean). Contradictions hold small_change_receipt_invalid; ordinary failed/refused
jobs retain small_change_check_failed. No descriptor is held across a wake, and no pinned mailbox/job schema or recording authority changes.
R7 extends captured-byte attachment handling to virtual Mailbox validation and publication hooks, including all three publication kinds
and the Mailbox used by the fresh composer's locate/prepare path. One operation-local capture supplies the hash and consumed attachment
bytes; subsequent validation/brief inspection reuses those bytes and rechecks ancestor/leaf identity and content metadata before publication.
Identical check packets share staging/capture across a batch and partial-batch recovery; existing publication capability checks still apply.
No persistent cache or module-global reader replacement is used. Portable witnesses compare file type, reparse status, available device/inode,
size and timestamps, excluding pathname-derived permission bits; unchanged Windows executable references remain valid. Retained snapshots use
the same witnesses. Type, identity, reparse and content changes still refuse; portable checks do not imply anchored or hostile-same-user custody.
Completed fixed-command results also require reason=None, commit=None and internally consistent test counts, including recipe-less status.
Configured status/dispatch loads the exact admitted recipe hash and, for expects_tests, requires non-null counts with total>0 and passed>0,
matching the runner: failed/errors need not be zero if some tests passed. Recheck configured recipe semantics before Reviewer publication and
successful owner closure drafts. Recipe-less status remains a read-only projection: it cannot verify expects_tests, guesses no recipe path,
and emits no successful closure drafts. Publishing/closing paths require and verify the configured recipe; a durable recipe-semantics witness
remains a separate protocol follow-up. No missing field is interpreted as expects_tests=False on an effectful path.
With no terminal receipt, inspect only the original claim and reserved-version metadata before observing existing process identity/scope.
A known-live runner reports check state running (row checking, complete=False), without log capture, missing-batch continuation or owner draft.
Unknown liveness or a dead runner without its original terminal receipt holds small_change_unknown_effect, even with a retained completed
result: no missing batch ID may publish before original run-open recovers that receipt/settlement. Retained failed/refused results keep
small_change_check_failed precedence. Claim capture explicitly refuses absent POSIX descriptor capabilities before opening. No replay or signalling.
Before accepting retained scr or surfacing successful closure drafts, require exactly the immutable assignment's verified writer-result,
terminal and completed-check receipt references, including their hashes. Those references bind the writer's commit/tree transitively through
the validated result; changing a source/proof reference cannot reuse a valid brief header. Assignment and lifecycle review timestamps must
follow the writer terminal/result and every completed check receipt; the existing acceptance/completion chronology still applies. Scope or
chronology mismatch holds small_change_message_conflict. This validation grants no Reviewer or coordinator recording authority.

R8 extends the operation-local capture to message entries, bindings/read acknowledgments, manifest, journal policy/events and optional unread
typed attachments on brief/ack/result/review/job_receipt messages. Bounded nonblocking no-follow reads supply both hashes and consumed bytes.
For standalone fresh_brief compose, unread oversized/nonregular/linked attachments are labelled unverified from metadata, without opening
them; missing/changed notes remain unverified too. Authoritative dispatcher composition holds small_change_brief_unverified;
reconcile the declared attachment with its original durable reference, then rerun dispatch. Open dispatch/job packets still refuse.
Ordinary non-attachment evidence keeps generic large-file hashing. Closed historical attachments retain the existing not_reverified contract.
Journal replay uses the pinned reducers over captured bytes, indexes provenance per revision, and captures newly validated append records once;
recipes parse once per row capture. Parsed JSON releases its raw bytes. A later typed consumer of a hash-only/parsed entry may perform a bounded
content promotion only if its original hash, identity and ancestry witnesses still agree. No new persistent store, public jobs API or global patch.
For borrowed dispatch/job_request publication, dispatch_history is the last virtual hook after binding/readiness checks: recheck all captured
file/directory witnesses there and immediately after commit. A changed witness before commit refuses; after commit retain original ID/path/hash
as partial_publication, hold, and record no route or further publication. Preserve specific known denial/recipe-drift reasons alongside that
partial evidence. Route append also rechecks the same witnesses under journal exclusion. Standalone compose retains this operation through
output publication and rechecks before replacement and after commit; post-commit uncertainty is explicitly reported without pretending rollback.
Configured completed results must contain exactly the admitted recipe's ordered, expanded command steps, contiguous numeric log steps 1..N,
and process.json at step N. Truncated/reordered/extra/gapped or contradictory process evidence holds small_change_receipt_invalid even when
all supplied hashes/body were recomputed. R8b retains the frozen small_change_unknown_effect hold for a known-live runner after a terminal
receipt; it clears when the runner exits. Started/live checks still report running, and an appearing claim is observed before classifying a
lost receipt. Unknown liveness/dead unsettled effects still hold. Both capture paths check descriptor
capabilities before accessing flags. These are modelled subprocess controls; platform/native runtime qualification remains separate.
R9 extends bounded capture to role contracts, assignment templates, the host plan and workspace events. Parse/render and hash use the same
captured bytes; contracts/plans retain the mailbox budget. Host-plan validation uses the existing pure schema validator, without its blocking
file loader. Workspace replay uses the existing Ledger reducers without exposing mutation. Recipe hide/ro_binds paths and raw standalone
verify paths refuse owner-private inputs before metadata discovery; recipe parser parity controls remain separate from this stricter privacy gate.
Missing delivery/provision/wake/ack inputs retain absence witnesses. Receipt names and values use the same captured listing. Final verification
groups file and directory witnesses by parent, opening one anchored parent per group, with the portable identity-check fallback retained.
Provision discovery captures each initiative base's identity and its declared provision, without treating the tool's own new brief directory
as an input-membership change. Actual mailbox, receipt, binding, workspace-event and lifecycle-event listings retain membership witnesses.
Role-contract size refusal retains the existing fresh-brief budget message, still before opening oversized content. The final live-authority
hook enforces writer/check expiry; verified read-only Reviewer dispatch may finish after execution expiry, without granting new execution.
Retained job/result/process/claim/log and recipe witnesses participate in final pre-commit and post-commit checks, and read-only row/draft checks.
Failure clears already computed success drafts. Post-commit mailbox failure retains the original record's path/hash without rereading a swapped
file. Pre-commit composer CaptureChanged refuses with exit 2; post-commit refusal names the committed brief and reconciliation action.
Recipe-less audit of a complete or owned-HOLD row reports small_change_close_unverified and rerun with --recipes <file>, with no success drafts;
the recorded lifecycle disposition still determines planning-skip release. The runner exposes no pure bytes recipe parser, so private schema
validation remains, checked against the public runner over shared valid/invalid files; no dependent-job or v2 metadata support is implied.
One-read claims are per capture, excluding bounded promotions and cross-consumer retained-job reads. Canonical router status uses the captured
lifecycle replay before project; the workspace Store preload remains unchanged. The pinned lifecycle implementation is never edited.
R9b distinguishes a publication that returned from a lost reply inside publication. After a route append returns, sync its event directory
before capture adoption/verification. Any subsequent failure holds small_change_committed_event with the original event ID, path and raw-byte
sha256, without rereading the evidence or retrying a known publication because its error says busy. The writer remains excluded until reconciled.
A lost reply inside publication still uses delivered_unrecorded and recovers the original receipt across succession without a second message.

R10 closes the sibling registry/source-reader paths: composition captures the canonical role registry through the same bounded nonblocking
operation reader, applies the existing pure registry validator, and resolves the endpoint role from those bytes. Its identity/content witness
remains live through publication; a module-global registry cache cannot bypass it. Writer, Reviewer and standalone compose share this path.
Fixed-v1 check preflight, including read-only status/planning, requires clean Git status before and after observing the exact revision/tree
and rejects submodules. Dirty entries are refused without opening or fingerprinting their content; Git subprocess observations retain explicit
environments and timeouts. This does not change canonical job admission or support dependent-job metadata.
After mailbox publication returns, retain the original ID/path/hash before directory sync. A sync failure is small_change_partial_publication,
with writer_message_present true and the writer excluded when its route remains unrecorded. Writer/check/Reviewer recovery inspects the retained
message rather than issuing another one. No failure after a known publication claims rollback or clears custody.

R12 checks the complete retained before/after source-witness schema, clean status/content digests and integer-zero dirty-entry counts, with
equal observations before Reviewer progression. Git observation drains both pipes incrementally under a 4 MiB combined byte ceiling and
10,000 index-record ceiling; the first dirty-status byte refuses immediately. Directory capture and revalidation share incremental discovery
with 10,000-entry and 10,240,000-byte name budgets, counting ignored/pending names before retaining them. No unbounded listing precedes these checks.
Private-root preflight derives configured home variables and default owner folders from the host registry. Case-variant containment uses
read-only public-sibling probes in each differing component's parent; it never discovers or opens a protected root, and ambiguity refuses.
Git children remove every registry host's declared billing variables and session variable equally, including newly declared hosts.
HOSTENV-1, after pr4b, will declare extra session markers and one shared environment policy, then migrate this reader, the frozen loop child
launcher and object_read_env callers; the loop's existing marker filter remains outside this admission until then.

R13 preserves the existing per-row private-evidence refusal and the public preflight's exact ValueError contract. A typed private router
privacy error for a row's exact declared evidence
is caught only during that row's read replay. Validate the original event chain, schema, actor, custody, hashes, consumption and accounting;
retain every original record/reference. An operation-local reducer namespace runs the pinned functions' original code/defaults/closures,
changing only the path validator for those already-refused declarations to absolute/no-traversal lexical validation. It performs no
private metadata discovery, changes no lifecycle module globals and is never used for recording. Malformed hashes, roles and other inputs
still refuse globally. This is inert claim replay, not successful evidence verification or authority to act on the refused row.
Before row composition/publication, project that row as held/small_change_configuration with owner-private detail (closed-row audit and
recorded owned-HOLD rules still apply). Preserve unknown effects, retained messages and accounting. Other rows validate their own references;
their briefs list the refused row as a hold linked to its original journal record, without promoting its private declaration into approved
scope or a usable artifact reference. Global policy/store/configuration failures remain global; row reference refusals remain scoped.

R15 extends this read-only quarantine to canonical rows and list-valued scope paths, before any private metadata discovery. R16 restores
inert canonical evidence in status/route: lexical privacy quarantine only, without evidence metadata/content reads. Changed/missing/huge
canonical artifacts do not hold ready work or override routed/closed/denied states. Small-change consumption lazily validates its complete
authority/prerequisite closure, with cycle protection. R17 supersedes the aggregate 1 MiB budget: each consumed reference uses the operator
producer's 64 MiB limit, checked from captured metadata before content open, allocation or hashing. Every claimed hash still checks. Policy
authority, review and delivery evidence use the same bounded reference reader. Hashes are memoized only within one pass by path and identity/
content mark; matching ancestry and fresh witnesses remain required. Valid producer logs do not become permanently unconsumable as a closure grows.
Dispatcher composition selects only its request's authority/prerequisite closure, including completed dependency proof records, without
promoting completed paths into new approved work. Unrelated rows' evidence is never opened. Standalone composition keeps journal-wide coverage.
Consumed dependency captures revalidate under the journal writer lock immediately before a small-change route append and after commit; a
pre-commit failure leaves the journal unchanged, while a post-commit failure retains the original receipt evidence for reconciliation.
The consumed dependency check follows the parent operation's witness check, immediately before append, so a change during that parent check
cannot commit a route receipt. Malformed publish envelopes and non-object raw requests refuse as typed lifecycle input before field access;
composition/planning reports the existing hold and lets canonical run-open continue, without an AttributeError/KeyError traceback.
R18 applies one closed event-shape validator before correlation for every v1 event, including INITIAL bootstrap records. Request events
require their complete key set and typed ID/hash before target lookup. Meter/succession records remain global even if an attacker supplies
request fields: malformed global/accounting input cannot become a row-only quarantine. Shape refusals are static; original pinned reducers
still validate all roles, payloads, custody, transitions and accounting. Validated replay supplies the other event readers; route recording
uses the same shape validator. No protected reducer or protocol changes.
Retained identical canonical deliveries still recover their original receipt. Stored-message protocol validation keeps references
inert; a private message is listed as held and cannot close an assignment or poison another endpoint's composition. In standalone composition,
missing/changed regular attachments on unread typed notes remain unverified; open dispatch/job packets retain their existing refusals.
R16b preflights nested string values and keys, including exact decoded raw capsules, through an iterative walk capped at 64 levels and
1,048,576 visited/pending nodes. Bound JSON structure before recursive protocol validators or hashing; decoder recursion becomes a static
invalid-input refusal. Reduced lifecycle marks containing a raw capsule are not themselves capsules. Reuse the operation-local private-root
policy during traversal; preserve per-row quarantine and verify the policy before effects. Standalone inspection uses this same preflight.
Canonical status/route/report use captured workspace events and mailbox readers for original-delivery classification, endpoint readiness,
binding histories and generation-two checkpoints. Recheck those mailbox witnesses before reporting facts; no plain-Mailbox fallback can
discover an unchecked private checkpoint. Malformed mailbox input holds its initiative while independent canonical routing continues.
Store checkouts, mailbox_root and delivery_dir retain the closed Ledger schemas' lexical validation and per-initiative private-path
quarantine. Captured canonical reads keep other initiatives available; each mailbox consumer preflights its declared root before metadata.
An uncorrelatable malformed event (including event=[]) refuses with a static global planning error; never advance accounting past it or guess
a request ID. Malformed meter/start-budget events remain global UNKNOWN. A semantic refusal on a non-accounting row event is quarantined only
after the original actor/custody and request-hash checks succeed. Reduction uses an isolated trial; retain the accepted prefix and raw hash chain,
without a successful event receipt or validated provenance entry. The row and requests depending on it through authority/prerequisites remain UNKNOWN, including
their planner/writer exclusions and closure refusal; subsequent events cannot manufacture a successful recovery. Canonical run-open continues.
Read-only projection shares the validated journal replay/index across rows while keeping each
row's mailbox/store/reference captures independent. Mutation still reacquires fresh state under the relevant mailbox lock.
Workspace register/update checkouts remain inert declarations under the original pure Ledger reducers: refuse a private current checkout at
that initiative's dispatch boundary, before any effect or metadata access. Other store fields and structural failures retain strict global
validation. Stored mailbox roots preflight before constructor metadata. Quarantined private message references cannot become usable briefs;
their contextual malformed-message diagnostic remains visible. A classified legacy canonical route retains only its actual recipients' custody,
plus any separately observed scw exclusion; an unreadable listing still cannot prove writer absence. Invalid plan registration is global UNKNOWN,
because treating an unestablished small-change row as absent could release planners. Never manufacture its registration or a lifecycle receipt.
Completed checks require a well-formed source_export bound exactly to the packet commit/tree as well as the clean/equal before/after witnesses.
Canonical denial is checked even when auditing an owned HOLD, and cannot draft successful delivery/resolve. Recovery parses exact, unique
Endpoint and Target generation headers and one exact request/plan assignment. An unavailable/oversized mailbox never proves writer absence:
an open unrouted small-change row conservatively excludes its admitted writer unless a complete, verified mailbox snapshot proves its scw absent.
The mailbox_history_verified projection marks that captured proof; failed listings and lifecycle UNKNOWN never establish absence.
Recorded intent/start also retains writer custody even when the mailbox is empty. Refused event IDs remain reserved without successful
receipts; the existing route dry-run rejects both accepted-ID conflicts and refused-ID reuse before any mailbox publication. Canonical
delivery revalidates captured journal witnesses before publication, independently of mailbox witnesses.
Canonical post-commit fsync/witness failure catches only the known committed-event exception: return a held delivery_error with the original
message ID and journal path/hash as partial_publication, continue remaining rows and emit JSON/exit 0. This pass reports reconciliation rather
than losing known effects in a traceback; later reads recover the recorded original receipt without a second message.
Each read operation captures registry-derived private-root policy once, reducing repeated password-database/registry queries for inert
history. Candidate paths still normalize lexically and refuse before metadata; UID or home-variable changes refuse on every read, and
password-database home plus registry declarations revalidate with captured witnesses before effects. Windows uses the OS current-user profile
location (CSIDL_PROFILE), with the same registry-declared owner folders even when home override variables are absent. Never infer the owner's
default profile from HOME/USERPROFILE; an unavailable profile location refuses before input discovery. No global cache or authority is created.
Whole-file recipe-parser parity (including census_outside_policy) is explicitly deferred by R15 until JOBS-1's public validate_recipes(data)
lands. recipe_file is unchanged this round; its dedicated strict xfail records this known gap, not activation or recipe qualification.

## 5. Loop-only skips, reporting and holds

R15 activation is explicit: --dispatcher-host-plan <absolute-host-plan> selects the dispatcher path using an existing
aegis.hierarchy-host-plan/v1 record, validated through hierarchy_hosts.validate_plan with a bounded captured reader. The argument and record
are independent of the journal and status.json; loss of status cannot lift the activated skip. This selects loop behavior, granting no
mailbox, lifecycle, capacity or native authority and satisfying none of D4/D5/D7's outstanding qualification requirements. Invalid configured
plan input holds dispatcher planning/sweep while canonical run-open continues. With no activation argument, dispatch and refresh_planning
are absent from the pass: valid unplanned runs follow the tip's legacy steps, including independent Codex wakes while the journal is busy.
The loop tests retain the frozen R15 named-tip (d69acf0b) bytes; activated hold assertions live in dispatcher tests.

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
R16b requires both the original route receipt and the validated original writer publication before releasing writer custody. A retained
receipt alone cannot release a lost/conflicting message, mismatched plan body, corrupt brief or unready historical binding. The informational
writer_publication_verified marker follows full identity/header/binding/proof validation, including a newly published writer before reporting
release; it is reconstructed, not a new record or authority. Recorded complete/owned-HOLD closure keeps its existing release rules.
R17 publishes route_receipt and writer_publication_verified only after the final operation/dependency verification succeeds. A failed
verification latches uncertainty for this operation; exception and mailbox-lock-exit paths clear both public release flags and retain writer
custody. DISP-LATCH-1 supersedes release from an ordinary row hold: release requires a complete positive verification pass. No failed capture can
become a release by a later successful metadata check in the same operation; a fresh pass must reconcile the original durable records.
R18 retains consumed dependency operations across journal replay and propagates failed reference captures/checks into their parent operation.
Once latched, verification refuses even if the original path is restored; neither append nor recovery can recapture a replacement as the
original witness. Finalization first clears the prior mailbox-absence marker as well as release flags, and establishes it only after successful
final verification. A fresh projection may reconcile the original records; it creates no new store and never replays a writer effect.
The latch retains its first typed validation cause, so later refusal preserves the original diagnostic without retrying or clearing uncertainty.
R19 retains operation capture-failure boundaries for reference reads/promotions, JSON/path/discovery checks, publication adoption and retained-job/
claim construction. DISP-LATCH-1 also covers subsequent checks that fail before registering a validator. A failed constructor latches immediately. Dependency operations propagate
their failure to the publishing parent; a cached same-inode proof with changed ancestry cannot become unverified prose that permits a writer
publish. Restoring a symlinked claim or a temporarily failed read before recovery cannot restore either release flag in that operation.
Standalone descriptive composition checks optional evidence and unread typed notes in a separate capture operation; a failed declaration stays
latched there and renders unverified, including missing/oversized receipt evidence, missing policy authority and stale notes in either ID order.
Already consumed/cached identity witnesses and shared privacy-policy failures still latch that standalone parent's operation. A declaration's
expected-hash mismatch alone cannot poison that parent. Dispatcher composition uses the publishing parent's latch for all references, including
retained-job paths absent from the cache. Unverified attachments, including open job packets, open dispatches and unread typed notes, hold
small_change_brief_unverified and identify their message in unverified_message_id (redacted for display). Reconcile that message's original
durable reference, then rerun dispatch. Failed shared authority witnesses retain their original diagnostics.
This internal distinction follows the existing request-closure argument, never configuration or a caller-selectable dispatch gate. Required
captures cannot become unverified prose: authoritative evidence and unread-attachment checks propagate their refusals immediately. Standalone
composition alone catches declaration refusals as unverified prose. A fresh projection reconciles retained original evidence.
DISP-LATCH-1 creates a positive proof only at the end of the parent operation's complete row pass and final witness verification. The sequence
includes attachment reads and expected hashes, both reference-check classes, both live retained-claim validations, and every capture. Any
exception or Hold leaves no proof. Only finalize_writer_release writes the release fields, and it requires that proof plus the verified current
writer publication and route receipt. Recovery may recheck stable metadata and draft owner reconciliation, but cannot create proof or release
custody. A fresh full pass is required; absence of a recorded failure never suffices. This proof is internal, operation-local and authoritative
dispatcher-only; it adds no public gate or durable record. Artifact budgets before open and dependency-failure propagation remain unchanged.
Writer custody releases only when target_generation still names the current acknowledged recipient binding, in addition to its historical
existence at publication. An unacknowledged target, or a superseded target without verified original completion, holds without replay. Valid
completion recorded before handoff may feed subsequent checks, preserving historical semantics, but cannot establish either writer release flag.
Configured-plan structural/depth refusals are contained at dispatch and reconstruction: owner planning_exclusions_unavailable, skipped sweep,
unchanged canonical run-open. No missing/invalid planning input supplies an empty exclusion set or consumes retained unread mail.
Pass the sweep's generic --skip (`tools/hierarchy_sweep.py:296-301`); never put these
sets in Pass.skipped, keep_skips or status.json as skip authority. Change loop skipped-row handling (`tools/hierarchy_loop.py:469-485`):
planning skips retain unread counts and a small_change_planning_skipped report, never a fabricated start_failing. Existing start_failing
handling stays separate (`:512-518`, `:643-644`). Losing status.json cannot release a planning skip. Actual busy, corrupt, unreadable, private
or symlinked durable input, or invalid projection, means owner planning_exclusions_unavailable and skipped sweep, with the cross-team wake
delay explicit; run-open still runs. This projection records no event/publication and changes no capacity, claim or accounting authority.

R9 selects rows using a read-only capture, then captures again inside each row's mailbox lock with a fresh operation, and independently reads
the final lifecycle revision for planning exclusions. Other teams' mailbox churn is not in the row's witness set. Replay advanced by composition
requires a fresh live-authority check before publication, including the final mailbox hook; a newly adopted denial prevents writer delivery.
Composition itself takes no journal writer lock. R9b's approved count oracle requires one recipe read/parse per command and at most one journal
read per distinct capture phase: selection, each locked row and final planning. One-check and three-check runs must have equal journal counts;
the work may grow with rows/revisions, without growing with checks multiplied by publications. Row isolation and freshness checks remain.

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
| small_change_close_unverified / small_change_partial_publication | Recipe-less close has no success drafts: rerun with --recipes <file>. A post-commit witness failure retains the committed message and holds further work; never replay or erase the effect. |
| small_change_committed_event | Route publication returned but directory sync or subsequent capture verification failed. Hold with original route-event path/sha256 and retain writer custody; this is distinct from a lost publication reply. |

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
