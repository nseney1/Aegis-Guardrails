# Rule exposure and report evidence

An exposure identifies one server-served selection. It ties a reference to the
subject, the scope checked, and the rule IDs and revisions actually served after
selection and response limits. Each report can supply a claim. Evidence that
qualifies that claim is checked separately.

## Repository scans

The repository server retains the exact Git path coverage of every final served
rule and the LF-normalized SHA-256 revision and type of each captured policy.
Identical full guidance in the same workspace, host and live server session
shares a receipt. To get its reference, set
`params._meta["aegis/returnScanRef"]` to `true` on the scan request. A qualifying
response carries `result._meta["aegis/scanRef"]`. Pass that value as the optional
`scan_ref` argument to repository `aegis_report_outcome`.

The server publishes the receipt and revision telemetry for a full return.
On stdio this follows strict JSON encoding of the tool payload and response,
and a successful flush. Invalid JSON-RPC IDs are refused before tool dispatch.
Compact summaries, ID views, notifications and failed responses leave neither
delivery record. A summary that returns full guidance can carry a receipt.
Full guidance still records the served telemetry revisions at receipt capacity.
Mixed guidance can receive a receipt when every served rule has a captured
policy or a known synthetic policy and at least one rule is captured.
Only the captured rules contribute revision telemetry or checked attribution.
Unknown provenance, unproved Git scope and guidance consisting solely of
synthetic rules withhold a receipt. A valid empty projection can receive one.
Omit the reference when the session has a
single unambiguous projection. Retention is bounded, and reconnecting or closing
retires the session's receipts. Expired, foreign or malformed references receive
`invalid_scan_ref`. Caller labels and ambient exposure telemetry are advisory.
An advancing unreviewed local HEAD can change response provenance while leaving
the paths, rules and instructions identical. Each such response has its own
receipt, and those receipts remain equivalent for implicit reporting.
When a standalone scope is evicted, a subsequent scan can supply a new
explicit receipt. Implicit reporting withholds credit if earlier evidence may
have been evicted. An alias that normalizes to a different Git path withholds
attribution even when guidance matches the displayed spelling.

The report must have a passing test receipt for the current tree. Each attributed
rule must match both a nondeleted changed path in the checked diff and the rule
file's blob in the checked tree. A bounded batch verifies the candidate outside
the append lock. The healthy raw ledger must still select the same check when
the lock is held. A concurrent change receives `report_check_changed`. An
unreadable ledger receives `report_ledger_unavailable`. The report row records
`scan_ref`, `rule_revision` and `rule_type`. The first qualifying report for the
check and rule supplies retry evidence, even across sessions. An append must
complete before its row can be acknowledged. The local witness remains
provisional until landing, required CI and approval gates are satisfied.
Confirmed evidence contributes to fitness totals and reinforcement when its
revision and type match the effective captured policy. Older revision-bound
reports recover their type from a unique matching source in the immutable
checked tree. A completed proof of a different or nonunique policy withholds
its confirmed evidence. A required proof read that fails also marks the
affected fitness evidence unavailable, so lifecycle actions refuse. Restoring
the same captured policy restores its confirmed evidence.
The first usable ordinary outcome for each key and rule is used in storage
order for totals, observation age and reinforcement. Confirmed reports use
their own check and rule identities.
Credit events retain their own evidence rules, even when an event carries an
outcome field.

Status consumers sharing a ledger view can inspect `LedgerView.raw_rows` for
`observation == "empty_join"`. The diagnostic names the witnessed `check` and
`tree`. The server records at most one observation per pair and caps the total
per ledger. The diagnostic requires the checked changes to be disjoint from
the complete served coverage, including synthetic rules. Failed Git
reads, missing revisions and unavailable receipts withhold the diagnostic. The
observation contributes zero to fitness. A report without a tested witness
follows the ordinary claim path.

## Manager decisions

An adjudicator uses the same identity ingredients with the manager's existing
audit data. Resolve the `decision_ref` in the recorded `workspace_id` and
`activation_ref`. Use the decision's action and canonical context digest to
bind the scope, and the context's enrolled member and worktree IDs to bind the
subject. Match any attributed rule against the ID and revision in the decision's
served rules, which the outcome receipt repeats as `rule_revisions`.

Validate evidence against that decision and its enrolled subject. A submitted
reference, outcome label or test flag is a claim. The manager scan and outcome
receipt both report zero raw fitness credit. Manager acknowledgements do not
confirm check execution or confer approval.
