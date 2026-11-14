# Model selection

Host-neutral policy selection with bounded, atomically published JSONL history.

select_model returns (choice, record); subject identifies a lane/endpoint/generation.
host_kinds is required registry data supplied by the caller, never inferred here.
Semantic intents, in ascending order, are light, standard, deep, extended, max,
and ultra. The ultra slot is reserved but maps to null on every host until native
provisioning support is qualified. Native ultra is not accepted in binding rows.
The legacy team.json ultra alias still resolves to max and is not a native ultra
capability. Existing role bands stop at max.
Policy requires team_id, team_family, manager_family, family_hosts (ordered host
lists), family_order (two families), target_shares, flexible_tasks and review_families
(task -> stage -> family, including primary). Optional task_intents maps task ->
family -> intent. Hosts, models, shares, review families and effort overrides are
data. Encode T4 correctness, T5 security, T6 lenses and T8 stage declarations in
policy. T8 primary uses the marker "opposite" and optional second uses "author".
The core infers no vendor from a name.

T2 writers and T13 helpers stay on team_family; T3 requires lane_family matching
team_family. Writer roles refuse a supplied lane_family outside team_family. T1 uses
manager_family. Only explicitly flexible helper tasks split. The chooser ports
family_split.py for nonzero shares: empty history picks family_order[0]; thereafter
pick it while its share is strictly below target, otherwise family_order[1]. A
zero-share flexible family is never chosen: this is an intentional divergence from
the build tool's 0.0/1.0 quirks; the interior targets retain exact parity.
Share arithmetic is exact Fraction.
All reviews require a known author. T4/T5 primaries and T6 stages each cover both
families; a security lens may share the author's family.
T8 primary derives the opposite family and second derives the author's family,
so paired checks always cover both families. Review stage names are closed.
T7 records set author_family to the chosen family and refuse a contradictory
author, providing the binding for a subsequent T8 check. No Router seat, launch
or effort update is added.

Selection requires admitted bindings. Every choice and record carries admission
`admitted`. Distinguish a current binding refusal from a historical admission refusal:

| Symptom | Action |
| --- | --- |
| Binding refusal: an unprobed or rejected level returns `binding_not_admitted: <host>/<class> intent <intent> for <role>; probe the level or repair model-bindings.json`. Provision uses the same refusal at load and resolution. | Probe the level or repair the current bindings. Choose an alternative level only when the refusal offers that action under the role's band and fixed-effort policy, as described below. |
| Legacy-history refusal: replay or append returns `invalid_history` even with today's bindings admitted, and the original log contains records with admission `unprobed`. The code alone does not distinguish this from other invalid history. | Keep the original audit log unchanged; repairing today's bindings cannot repair historical admission provenance. Never edit old admission fields. If restarting is appropriate, the owner must explicitly choose a separately named new history. Empty history restarts split counts and does not preserve split continuity. |

A null selected capability refuses binding_unavailable:<host>:<intent>.
Non-endpoint selections with caller-selectable effort append
`or choose an admitted level within the band` to the next action.
Provision's unbanded front-door offers `or choose an admitted supported level`;
roles with registry-fixed effort, such as router, keep only the probe/repair action.
Endpoint refusals retain the owner probe/repair action.
All structural validation finishes before admission is checked, so a missing row,
invalid role class or null band endpoint cannot be masked by an unadmitted level.
Core malformed inputs refuse `invalid_bindings`; provision retains its structural
`invalid model bindings ...` envelope. Host diagnostics follow caller registry
order (or row order when inferred); unordered set registries are sorted.
The new admission and unavailable-binding refusals bound locator text before shared-table redaction.
Redaction markers are emitted whole, including when redaction expands the field.
Both validators build these diagnostics only on refusal; healthy provision never
loads the secret table. In an exported tools checkout without the shared table, provision
keeps the new refusal code and action. A canonical identifier matching
`[A-Za-z0-9][A-Za-z0-9_.-]{0,127}` is shown as is; anything else becomes
`<redacted locator>`. The full value must match before any truncation.
Core imports the shared table directly and applies its patterns to locators,
using one fixed `[REDACTED_TOKEN]` marker.
Codes and actions match; locator text can differ when provision lacks the table.
Refusals that predate MR-1c-SEL retain their exact original formatting and bytes in
every layout, independently of table availability (coordinator round-5 ruling).
Planned hosts describe
capabilities only and never select, even if policy names them. The Gemini and Grok
rows remain planned and unprobed; this registry change grants no routing admission.
Selectable hosts need admitted, concrete non-null band defaults and ceilings; a null endpoint
is refused at load just like a missing key. Planned-host refusal applies before
host-default and ROOT waivers as well as explicit model resolution.
Validation matches MR-1's band/coverage/model-token rules for selectable hosts in
the caller's required registry; planned rows may name hosts outside that registry.
The v1 schema accepts effort_encoding (flag by default, or model_suffix),
served_aliases, and host_status (selectable by default, or planned). model_suffix
renders the base model plus '-' and the native effort, such as
gemini-4-carbon-high. Served aliases describe usage identity only; they do not
change selection or provide alternative provision model names.
Base model names, rendered suffix ids and usage aliases share a unique per-host
identity namespace across rows, regardless of class or admission state. Collisions
refuse at load, and provision refuses ambiguous matches without choosing a row.
Standalone validate_bindings may infer hosts when inspecting a document only.
Deferred to MR-1c/MR-3b: T6 whole-change on a non-coding model, and "Opus gating"
for Claude-authored docs. These require further binding/admission policy data.

File inputs must be regular, not symlinks, and are read with no-follow opens and
a fixed byte cap before strict UTF-8 decoding and JSON parsing. UTF-8 BOM and
UTF-16/32 inputs refuse invalid_bindings or invalid_policy. Config opens walk from a held filesystem
root descriptor with no-follow opens for every directory component and compare
the final entry and descriptor with the expected inode. Parsed and file inputs
share structural budgets before validation. OS path rejections use invalid_bindings,
invalid_policy or unsafe_decision_path; semantic refusals, lock timeouts and
descriptor write/fsync errors retain their own codes. Decision reads stream bounded lines with
cumulative byte/record caps; read_decisions yields records without retaining them.
Consume or close that iterator promptly: it holds the .lock during iteration.
At the cap, archive/rotate the log and carry forward calibrated policy explicitly.
Decision directories must exist, belong to the current uid, and forbid group/other
writes. Logs must be owner-owned regular files without group/other write bits,
verified on the opened descriptor. Log names ending in .lock refuse invalid_log_path.
Missing-log reads in an existing valid directory create neither directories nor
locks. Missing directories and any .. path component refuse unsafe_decision_path.
Path text is capped at MAX_INPUT_BYTES characters and 256 separators before pathlib parsing, and
invalid decision path types refuse unsafe_decision_path without raw TypeError.
Platforms lacking
POSIX directory descriptors refuse anchored_io_unavailable, with no path fallback.
Directory acquisition resolves the parent once, then walks from the filesystem
root with no-follow directory opens relative to held descriptors. The acquired
leaf must match the expected and anchored-entry identities, owner and mode.
An append streams validated old bytes and the new line into an exclusive no-follow
sibling at a held directory descriptor, fchmods/fsyncs its descriptor, checks its
identity, then renames within that descriptor and fsyncs the directory. A partial
write/error before publication leaves the original untouched. Cleanup failures
are chained under an original failure without masking its type or code. No corrupt history
is repaired or reset. Use select_and_append for launches: its one anchored lock
covers read, select and atomic publication. Low-level append_decision refuses a
new stale_decision when counts_before disagrees with matching-split counts or
previous_decision_id disagrees with the same-team chain head.
Existing decision IDs may receive outcome observations; those keep decision_id.
Counts use split_id, the hash of target_shares and family_order; unrelated policy
edits preserve counts and policy_id remains audit provenance. Restoring an earlier
split resumes only that split's counts. Every split_id requires its exact snapshot.
An explicit outcome.launch_status="not_launched" excludes a HOLD or failed start;
only an explicit "launched" can reverse that state. An initial decision without
status counts as launched, while status-free observations preserve its state.
Other outcome data is opaque.
Each new launch hashes previous_decision_id (the previous new decision for its
team, across policies); observations do not advance the chain. Replay refuses a
broken chain with invalid_history:decision_chain: restore_complete_decision_log.
Replay checks each new row's chronological counts_before per team/split and the
split result (including zero-share exclusion); historical observations update
counts without rechecking their original snapshot against later counts.
Every reader enforces a fixed family set per team across all policies, including
when selection is for another team. Recorded T4/T5 primaries under one policy
identity must remain consistent and cover both families when both appear.
Selection re-derives same-team history reasons, split eligibility and stage/fixed
families from the supplied rules only for rows with the current policy_id.
Older policy rows retain their per-policy structural checks, formal-pair consistency,
validated split snapshots and chronological counts. Changing manager, team, review
or flexible-task rules produces a new policy_id and preserves matching split counts.
A row claiming the current policy_id must match its current targets/order too.
If a current-policy row disagrees with the supplied rules, selection refuses
`invalid_history:policy_rules_changed: start a new team history`.
Review or manager edits under the same policy_id require a new team history and
restart the split; those rows cannot be silently reinterpreted as new rules.
Records include policy_id (SHA256 of bounded canonical policy JSON).
Before hashing/encoding, records have 64-level, 1024-node, 256-item collection,
425-bit integer and aggregate byte budgets; encoding stops at the line limit.
Config input node and collection budgets scale with MAX_INPUT_BYTES; the byte cap
also bounds nodes because each JSON node consumes at least one byte. A registry of
65 hosts with four bindings each (260 rows, 76,862 canonical bytes with the tracked
binding templates) validates in both the core and MR-1. Record budgets stay fixed.
History rows have one canonical form: sorted-key compact ASCII JSON plus one LF.
Append, disk validation and replay measure those exact bytes including the LF;
noncanonical disk rows refuse invalid_history, with no silent normalization.
Internal reader rows are validated once per pass and reused by selection without
re-encoding or hashing. select_and_append retains only validated immutable raw
lines (at most MAX_HISTORY_BYTES, MAX_HISTORY_RECORDS) for publication under its
same anchored lock, avoiding a second validation pass. read_decisions,
append_decision and select_and_append share one locked-log context with a
60-second timeout for the 4096-row cap and a queued peer. Low-level append validates
its own streaming rewrite. Before rename, both publication paths reopen the log
relative to the held directory and compare device/inode and the size/mtime_ns/ctime_ns
generation from storage.file_generation against the read snapshot (or continued
absence). A changed log refuses stale_decision and leaves the external bytes intact.
This O(1) stale check supplements the shared lock; it does not fence a noncooperating
writer that changes the file after the check. Both remain O(n) under fixed caps.
Identity is not authentication. These APIs
grant neither admission authority nor native execution qualification.

