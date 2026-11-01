# Manager workspace audit prototype

Manager mode serves management rules and records claims across explicitly approved
worktrees. Implementation governance remains with each repository. Every manager
outcome returns zero fitness credit; audit acknowledgement establishes no delegation
authority, implementation approval, native execution or verified completion.

On 2026-11-01 the owner authorized this isolated prototype and dogfood preparation
before the 4.5/4.6 releases. The 4.7 release prerequisite, evidence-trim, review and
fixed S7/S8/S9 gates remain unchanged. Native Teams enforcement and the hierarchy
comparison remain separate acceptance gates. This page documents a prototype API;
it does not claim that a manager registration or policy is active.

## Prepare and review

Use the CLI from the reviewed, source-pinned prototype artifact. The installed
repository-mode `aegis` can be an older release. Paths below are example absolute
locations that must be replaced with the reviewed local paths.

```sh
AEGIS_MANAGER_BIN=/absolute/source-pinned-venv/bin/aegis
"$AEGIS_MANAGER_BIN" workspace init \
  --config /absolute/private/manager.json \
  --workspace-id aegis-workspace \
  --control-repo /absolute/aegis-workspace-governance \
  --store /absolute/private/manager-audit \
  --trusted-signers /absolute/private/manager-allowed-signers \
  --json
"$AEGIS_MANAGER_BIN" workspace status \
  --config /absolute/private/manager.json --json
```

`init` creates a draft external configuration and initial audit record, then prints
a separately named `aegis-manager` registration proposal. It installs no host
registration and activates no policy. It refuses ordinary repository locations
for config/signers and implementation worktrees for audit storage. The control
repository is a distinct local Git repository; it must remain private if published.
The workspace parent needs neither `.git` nor an ordinary `.aegis/` directory.

The public signer file is separately reviewed, contains an `owner` principal and
is kept outside repositories. Its SHA256 is pinned in the private configuration,
whose SHA256 is bound to the audit genesis. Git SSH signatures use namespace `git`.
The service reads public signer material only. Signature custody and signing remain
with the owner; manager tools cannot create approval or activate policy.

The fixed payloads `manager-policy/policy.json` and `manager-policy/membership.json`
are read from an exact full Git commit. Dirty payload files cannot substitute for
that commit. Raw blob SHA256 values pin the exact reviewed payload bytes. Each
manager rule receives a revision from its canonical original rule. Policy matching
accepts a management action and optional `role`, `phase` and `risk` selectors.
Unknown fields, repository predicates, file scopes, executable settings and policy
inheritance are rejected. Rule prose still needs management-only relevance review.

## Owner activation

First commit and independently review the candidate control policy and membership.
The initial local candidate is in `aegis-workspace-governance`, branch
`draft/manager-workspace-bootstrap`. Its exact reviewed bootstrap commit and review
state are recorded in the local `aegis-guides/v4.7-manager-bootstrap-review.json`
review manifest kept alongside the implementation checkout.
Initially only the main Aegis checkout and existing team-session pilot
are enrolled as worktrees of repository `aegis`. Other repositories require explicit
review and a new owner-approved activation.

Request an activation proposal without an approval packet:

```sh
"$AEGIS_MANAGER_BIN" workspace activate \
  --config /absolute/private/manager.json \
  --revision FULL_CONTROL_COMMIT --expect none --json
```

`--expect none` is the initial expected state. Later transitions use the current
`status.active_revision` value, which is an activation digest rather than a Git
commit. The proposal contains the exact `approval_statement`, `approval_digest`
and `required_trailer`; it activates nothing. The statement schema is
`aegis.manager-activation/v1` and binds workspace/configuration identity, control
commit, policy/membership blob digests, runtime membership bindings, previous
activation, audit head and pending-decision digest. Any new audit event or relevant
binding change invalidates the proposed expected state. Resolve pending decisions
before changing revisions.

The owner reviews that statement and makes an SSH-signed empty Git commit in the
control repository. Its message contains exactly one trailer:

```text
Aegis-Manager-Approve: APPROVAL_DIGEST
```

Prepare an external approval JSON object with exactly two fields: `statement` is
the unchanged complete proposed statement, and `commit` is the full owner-signed
approval commit ID. The service verifies that signature against the pinned public
`owner` signer. It does not sign or accept a self-attested approval flag.

```sh
"$AEGIS_MANAGER_BIN" workspace activate \
  --config /absolute/private/manager.json \
  --revision FULL_CONTROL_COMMIT --expect none \
  --approval /absolute/private/owner-approval.json --json
```

Owner signatures bind the local runtime membership identities. Replaced worktree,
Git-directory or common-directory identities require review and renewed approval.
Missing worktrees remain explicit in status; stored policy inspection does not
admit an unavailable member for a new management scan.

## Management decisions and outcomes

Supported actions are `delegation`, `ownership`, `hierarchy`, `resource_budget`,
`checkpoint`, `handoff`, `evidence_review`, `escalation` and `policy_change`.
Context requires `member_id` and `worktree_id`; optional fields are `role`, `phase`,
`risk` and `summary`. It accepts no arbitrary paths, executable commands, identity
assertions, approval flags or scope changes.

```sh
"$AEGIS_MANAGER_BIN" workspace scan \
  --config /absolute/private/manager.json --action handoff \
  --context '{"member_id":"aegis","worktree_id":"pilot","summary":"Review the management handoff evidence"}' \
  --json
"$AEGIS_MANAGER_BIN" workspace report \
  --config /absolute/private/manager.json --decision DECISION_REF \
  --rules manager-handoff --outcome partial --evidence '[]' \
  --idempotency-key handoff-review-1 --json
```

Every successful scan appends a new immutable decision reference with its served
manager rules and revisions. Report only rules served for that decision. A report
stores a claim and audit acknowledgement. Reconnect/retry with the identical
idempotency key and request returns the original acknowledgement; changed content
under that key is refused. Reporting a pending decision reconciles the audit claim;
it does not establish approval, execution or verified completion. Preserve any
separate outstanding operational or human-approval gate.

Evidence entries require `member_id`, `worktree_id`, `source_tree`, `check`,
`rule_id`, `rule_revision` and `reference`. Source trees are full Git tree IDs;
rule revisions are SHA256 values. References are stored data and are never fetched
as arbitrary paths/URLs. Source identity/tree/dirty state is checked separately
from check execution, which remains unverified. `tests_passed` is accepted by the
manager MCP report as a claim and earns no credit. The CLI has no tests flag.

Status distinguishes `manager_audit_available`, `policy_approval` and
`native_enforcement_ready`. It always reports no native enforcement, Teams
mutations or delegation authority. It revalidates the latest 20 evidence references,
reports `evidence_total`/`evidence_omitted`, and marks omitted evidence unverified.
Missing, stale, dirty, mismatched and unavailable evidence are retained explicitly.
Repository witness and fitness requirements are unchanged; bootstrap work is never
backfilled as witnessed evidence.

## Separate manager registration

Back up the exact host MCP configuration before any registration change. Review
the source-pinned artifact, private config bytes/digest and printed registration.
The proposed server process uses the artifact's interpreter with `-I -m aegis_mcp` (isolated Python imports)
and startup environment `AEGIS_MANAGER_CONFIG` plus
`AEGIS_MANAGER_CONFIG_SHA256`. It has a distinct `aegis-manager` name. Do not set
`AEGIS_WORKSPACE` on that process: mixed manager/repository scope is refused.

The manager process advertises only manager variants of `aegis_scan`,
`aegis_list_rules` and `aegis_report_outcome`. Tool arguments cannot change the
startup binding, membership, policy or identity. MCP client labels are self-reported
transport provenance; the server session UUID is not an authenticated native identity.
Existing repository registrations retain their existing interfaces and refuse an
unconfigured parent folder.

After separately reviewed activation/registration, reconnect the same conversation,
inspect the advertised manager tools and source identity, scan a real management
decision, record its claim, inspect provenance and reconnect/replay. Those live
observations are independent of local unit tests. No live result is asserted here.
Rollback removes only the additional manager registration and preserves control
policy revisions, owner approvals and the external audit history.

## Storage and limits

The append-only audit is separate from repository fitness ledgers. It uses private
0700 directories/0600 regular files, confined path checks, a five-second lock wait,
sequence/hash-chain replay checks and durable appends. The current limits are
16 MiB per audit and 1 MiB per row. Corrupt/torn rows and capacity failures are
explicit refusals; there is no automatic repair, truncation or history pruning.

Configuration anchoring, signatures and replay checks detect unsupported policy or
receipt substitution through these APIs. The store and service run under the same
local user and are not a protected native host control boundary or tamper-resistant
execution evidence. A manager success claim, copied log, workspace membership or
operational success grants zero fitness and no repository witness. Native caller
binding, permission/endpoint isolation, lifecycle enforcement and comparative
hierarchy acceptance remain separate work.

POSIX directory-descriptor confinement is covered by the local store tests. Windows
ancestor-swap races remain unsupported and unverified by this prototype; passing
Linux tests provides no Windows security guarantee. Native Windows acceptance
requires separate platform evidence.
