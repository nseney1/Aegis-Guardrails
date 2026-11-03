# Six-team recovery and cutover plan

State: BLOCKED. This is a reviewable plan; it performs no cutover or live-state
mutation. The task-owned maintenance evidence `six-team-readiness.json` pins the
observation, original claims, historical evidence and accountable destination
for all 11 existing initiatives; it is retained outside the repository. There are two planned Aegis teams and four planned Stormheir teams.
Engine-native remains an Engine backing route.

Observation snapshot: 2026-11-03T23:22:21.946064+00:00. Re-observe before any
future cutover. The observed store is at sequence 426: four of five writer slots held,
zero of three heavy slots held, and zero of one heavy-tests slot held. These
ledger numbers and the current namespace census do not establish admission.
All 116 historical jobs with results lack qualified original process-scope
evidence. Their 89 completed, 20 failed and seven refused results and matching
receipts remain historical observations; three other jobs remain pending.
Released historical reservations are not recreated. The four currently held
writer requests retain their original IDs, holders and path/repository scope.

## Preconditions and accountable owners

1. **Runtime and native host maintainer:** qualify authenticated caller identity,
   generation, effective role restrictions, narrow canonical ROOT decisions and
   a distinct operator. Qualify executor lifetime, reconnect, bounded in-flight
   cancellation and lost-reply recovery at supported native boundaries. A model
   turn, task-message delivery or disposable fixture does not satisfy these gates.
2. **Delivery integration owner (maintenance Session 1):** freeze the exact
   integrated source, retain source-bound independent reviews, run the serialized
   full suite and required hosted workflow. Record executed versus skipped jobs.
   The approved f85 baseline supersedes the earlier Makefile approval failure;
   later governance changes still require the supported owner signing process.
3. **Each original team evidence owner, with the qualified operator:** reconcile
   source, original resource claims, process effects, receipts and acceptance
   separately. Missing scope requires contemporaneous authoritative evidence;
   absent that, keep the unknown and prohibit automatic settlement. Never stamp
   a current boot/namespace onto a legacy claim or infer stop from expiry/archive.
4. **Owner:** authorize actual cutover only after the above gates and the exact
   six-team migration proposal are independently accepted. This maintenance
   delegation supplies no live activation, protected merge or release authority.

## Team mapping and source ownership

| Planned team | Retained routes and next obligation |
|---|---|
| Aegis Runtime | `aegis47-live`, `aegis47-multihost`, `prototype47`, and closed `prototype47-flowfix-20261102` history; native/runtime qualification and recovery. Runtime g20 stays stopped. |
| Aegis Delivery | `aegis`, `aegis47-build`, and unstaffed D2-probe history; B1 partial, CLI/MCP, product integration and CI. Delivery g8 stays stopped; g9 remains unverified. Preserve req-00000392. |
| Stormheir Engine | `stormheir-engine` and `stormheir-engine-native`; seven-file partial, 13 unexecuted cases, two P1 findings, controls and exact game adoption. Preserve req-00000360 and req-00000422. |
| Stormheir Content | `stormheir`; Settings/T140 metadata and source adoption, hero capture and zero-fallback instrumentation, content/art/audio. Preserve req-00000357 and owner visual/audio acceptance. |
| Stormheir Campaign | `stormheir-campaign`; capped G2 partial, scoped 6+64 test claims, 332-pointer reconciliation, actual worker/backend/assets and compatibility. |
| Stormheir Integration & Acceptance | New planning scope with no current actor, registry row or grant. One integrator with independent review inside existing capacity; exact combined source, shared-seam ownership, compatibility and end-to-end validation. |

Content must explicitly transfer the agreed shared integration responsibilities.
Before that transfer, Content and Integration & Acceptance exchange a correlated
proposal naming each path, producer/consumer, exact source witness, acceptance
criteria, merge order, compatibility obligations and rollback checkpoint. Engine
and Campaign acknowledge affected interfaces and their adoption bounds. A reply
must accept or reject that exact proposal; message delivery alone is insufficient.
Do not infer a blanket transfer from team names or treat current `touched_paths`
as replacement scope for an older granted writer. The retaining source owner
keeps each contested path until the supported transfer is accepted and executed.

## Sequence after separate cutover authorization

1. **Qualified operator:** establish a quiescent checkpoint through admitted host
   controls. Record every in-flight request/effect, actor generation, claim and
   independent stop observation. An unknown process or unacknowledged effect
   blocks its affected scope. Do not launch a successor over it.
2. **Evidence owners and integrator:** pin immutable ledger, mailbox, claims,
   source witnesses, failures, output hashes and acceptance references. Record
   the original and candidate code versions. This checkpoint is evidence; the
   append-only state is never replaced by a backup during rollback.
3. **Router and team orchestrators:** prepare routing entries for the six teams
   using the accepted mapping, correlated ownership transfers and current native
   generations. ROOT discusses feature intent and decides canonical requests;
   router selects a team or requests bounded formation; qualified operators
   perform provision/admission. No old maintenance binding is reused implicitly.
4. **Qualified operator:** perform the admitted migration/cutover using supported
   controls after exact source and authority revalidation. Preserve original
   request/receipt identities across succession. Retained claims are transferred
   or released only through the existing supported, evidenced protocol; a new
   team label does not allocate or free capacity.
5. **Orchestrators and integrator:** triage each pending request against current
   source, planning needs and cross-team integration bounds. Admit bounded TDD
   lanes inside existing capacity. Integration & Acceptance starts with one
   integrator and independent review, not an additional capacity allowance.
   Route failed source checks back to the producing team through correlated
   requests. Actual Stormheir validation needs its own admitted operator window.
6. **Independent reviewers:** verify exact integrated behavior, duplicate-effect
   protection, late arrival, reconnect and cap succession. Retain both passing
   and failed evidence. Owner visual/audio acceptance, signing, protected merge
   and release remain distinct decisions.

## Stop conditions and rollback

The qualified operator stops admission when source, authority, generation,
capability, process visibility, path ownership, receipt correlation or capacity
cannot be revalidated. It checkpoints the failure and outstanding effects.
The integrator identifies the last independently accepted code checkpoint and
the affected producer/consumer contracts; original team owners retain partial
source and evidence.

An authorized rollback switches candidate code only after quiescence and a
compatibility review against the current append-only state. If an older version
cannot safely interpret new records, keep the affected scope held and repair
forward; do not load it over the store. Never rewind ledger events, delete failed
outputs, recreate released claims or free an unknown effect. Reconcile any
partially completed routing/ownership operation by its original correlation and
receipt through the supported idempotent boundary before another attempt.
Restart admission only after the named blocker owner supplies new evidence and
the relevant decision/review gates accept it.

## Current bounded delivery

Session 3 supplies the read-only observations and recovery patch, Session 1
reviews and integrates it, and Session 3 independently reviews Session 2.
The status patch keeps `evidence_error` while displaying retained result hashes,
failed-output references and exact receipt matches. It introduces no automatic
legacy migration, admission, resource release or native execution.
