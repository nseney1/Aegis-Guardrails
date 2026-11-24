# Manager policy fitness

An owner can review the effect of manager guidance against independent operational
evidence. The owner-side command uses the registered manager config and pinned
SSH signers. Obtain the config digest and accepted signed anchor from the owner
through a trusted channel. The command reads the local manager audit and the
control repository. Its JSON projection is separate from repository rule fitness
and from manager MCP. Manager acknowledgements continue to carry zero fitness
credit.

## Prepare and sign a review

Commit a reviewed JSON object at `adjudication/label.json` in the control
repository. Use a regular nonexecutable Git blob. The manager's policy and
membership payloads stay in their existing locations. Use these exact fields.

| Field | Value |
| --- | --- |
| `schema` | `aegis.manager-label/v2` |
| `workspace_id` | Workspace in the pinned registration |
| `audit_head` | Exact audit head returned by manager status for the reviewed history |
| `episode_id` | Owner-selected identifier for one operational episode |
| `decision_refs` | Array of one to 64 distinct served decision references for this episode and rule revision |
| `rule_id`, `rule_revision` | Rule ID and exact served SHA-256 revision |
| `assessment` | `helpful`, `misleading`, `missing_evidence` or `ignored_appropriate` |
| `evidence_digest` | SHA-256 of the evidence the owner reviewed. JSON null is allowed for `missing_evidence` |
| `previous_anchor` | Previous accepted adjudication commit, or JSON null for the first review |
| `predecessor` | Current statement digest for this episode and rule revision, or JSON null for its first review |

IDs start with a lowercase ASCII letter and contain up to 64 lowercase ASCII
letters, digits, periods, underscores or hyphens. Git commit IDs are full
lowercase hex object IDs. Decision references and SHA-256 values are 64
lowercase hex characters.

Obtain `audit_head` from manager status and review the audit through that row.
The owner checks independent evidence and episode membership before signing.
An acknowledgement, self-reported result or evidence reference from the manager
does not establish either. The evidence digest commits to the reviewed bytes.
The command does not fetch evidence or infer whether it is relevant.

```sh
python -m aegis_cli.manager_adjudication prepare \
  --config "$MANAGER_CONFIG" --config-digest "$MANAGER_CONFIG_SHA256" \
  --manifest "$REVIEWED_MANIFEST_COMMIT"
```

The result contains the signing statement, its digest and a required trailer.
The statement uses the `aegis.manager-adjudication/v2` domain and commits to
the pinned config, the exact manifest bytes, the audit head, each full hash-chained
decision snapshot, the evidence digest and both predecessor links. The standard manager
owner trailer carries the digest of this statement. An activation authorizes
its own statement digest in the activation domain.

Review the result, then sign a control-repository Git commit containing the
same manifest bytes. Include the emitted trailer exactly once, on one line.
Use the registered owner SSH key to sign. Keep the accepted anchor commit ID
under owner custody. For a correction, retain the old signed commit, set
`previous_anchor` to the current accepted tip and use the superseded statement's
digest as `predecessor`. Include additional served decision references when a
later review links repeated scans to the episode. A decision keeps its first
verified episode assignment. A correction affects the entire current vote for
that episode and rule revision. Each bound decision stays visible.
Each checkpoint must be at or after its previous anchor's checkpoint. The
checkpoint must include every decision named in that label. Anchors using the
previous schema require fresh owner review and signing with a checkpoint.

## Rebuild the projection

```sh
python -m aegis_cli.manager_adjudication verify \
  --config "$MANAGER_CONFIG" --config-digest "$MANAGER_CONFIG_SHA256" \
  --anchor "$ACCEPTED_ADJUDICATION_COMMIT"
```

The command rebuilds the `aegis.manager-fitness/v2` projection from one validated
audit snapshot and the signed manifest chain ending at the supplied commit. Keep
all referenced commits and the complete audit prefix available. A trusted operator
chooses the current anchor and can request a historical rebuild with an older
checkpointed anchor. `audit_head` is the observed audit tip and `signed_audit_head`
is the selected anchor's checkpoint.

Each entry in `decisions` identifies the workspace, activation, served decision,
episode, action, member, worktree, rule ID and revision. The signed prefix
includes decisions with a reported failure and decisions awaiting acknowledgement.
Unassigned decisions have a null episode and each contributes
one provisional unresolved opportunity per served revision until the owner
links it to a reviewed episode. Actions with no served rules have zero eligible
opportunities.

`by_revision` counts distinct reviewed episodes and provisional opportunities.
`by_action` counts these within each action and served revision. In both,
`eligible` is the sum of `tp`, `fp` and `unresolved`. The action's `covered`
count is the sum of the two resolved verdicts. An episode can span actions, so
the action totals can overlap. One current helpful label gives a true positive.
One current misleading label gives a false positive. Missing evidence, ignored
appropriate guidance and unreviewed opportunities stay unresolved.

The top-level decisions and totals use only the prefix through `signed_audit_head`.
`unsigned_tail` shows the later decisions, their per-rule opportunities and their
separate revision and action totals. It includes decisions with zero served rules
and shows zero opportunities for their actions. Appending or removing rows after
the signed checkpoint can change the tail. The signed metrics stay fixed.

Successful commands write JSON to stdout. An invalid invocation exits 2 with
`invalid_arguments`. A refused review exits 1 and writes a JSON refusal to stderr.

| Refusal | Meaning |
| --- | --- |
| `missing_anchor`, `missing_manifest_commit` | The relevant full commit ID is missing, invalid or unavailable |
| `missing_label_manifest`, `unsafe_label_manifest`, `invalid_label_manifest` | The fixed manifest path, Git object mode or JSON schema fails validation |
| `manifest_limit`, `anchor_limit` | Maximum manifest size is 64 KiB, commit size is 128 KiB and signed chain length is 128 |
| `uncheckpointed_history`, `invalid_audit_checkpoint` | The manifest uses the previous schema, omits its audit head or gives a malformed checkpoint |
| `audit_checkpoint_unavailable`, `audit_checkpoint_regressed`, `decision_after_checkpoint` | The checkpoint is absent from the validated audit, precedes the prior anchor's checkpoint or excludes a named decision |
| `workspace_mismatch`, `unknown_decision`, `unserved_revision` | The workspace, decision or exact rule revision is absent from the required history |
| `divergent_predecessor`, `episode_conflict` | A correction names the wrong predecessor or tries to reassign a decision |
| `membership_unavailable`, `unauthorized_membership` | The served worktree binding is unavailable or outside the signed membership |
| `invalid_owner_signature`, `signature_verifier_unavailable` | The owner signature or its one-line trailer fails verification, or SSH verification is unavailable |
| `activation_integrity`, `audit_corrupt` | A historical activation lacks its exact approval commit or fails integrity validation, or the manager audit contains a malformed row or reference |
| `invalid_config_digest`, `git_unavailable`, `adjudication_unavailable` | The config digest has the wrong form, Git could not complete a read, or system I/O failed |

Existing manager config, audit and activation integrity refusals also apply.
See [Manager workspaces](manager-workspaces.md) for registration and the audit
trust boundary.
