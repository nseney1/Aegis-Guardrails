# Manager starter catalog

The `aegis_core/manager_starter.json` resource contains twelve editable manager
rules. Installing the distribution makes the draft available for copying.
Serving rules requires the ordinary owner-approved activation of a reviewed
control commit.

## Prepare a control policy

1. Open `python -I` with the interpreter that has the reviewed Aegis wheel
   installed. Run this snippet from the root of the chosen control repository.
   The destination must be new. If a policy already exists, compare with the
   resource and merge the rules you choose into a reviewable draft.

   ```python
   from importlib.resources import files
   from pathlib import Path

   target = Path("manager-policy/policy.json")
   target.parent.mkdir(exist_ok=True)
   with target.open("xb") as output:
       output.write(files("aegis_core").joinpath("manager_starter.json").read_bytes())
   ```

2. Replace `null` in `workspace_id` with the identity chosen for your manager
   configuration and membership. The stock draft deliberately requires this
   edit to pass v1 validation. Review each rule against the decisions your
   managers make. Keep `id`, `actions`, `match` and `text` as the rule's only
   fields. Each ID must be unique and each action must be supported by manager
   policy v1. Text must be nonblank and no longer than 4,096 characters. An
   empty `match` serves the rule for every context with a listed action. Add
   exact `role`, `phase` or `risk` selectors only when they correspond to values
   your workspace actually uses. All listed selectors must match.
3. Prepare `manager-policy/membership.json` for the same workspace and commit
   both payloads in the control repository. Use the full control commit ID
   and your manager configuration to validate the committed draft and request
   the activation proposal. Substitute your own values for the placeholders.
   For a replacement policy, use the current activation reference in place
   of `none`.

   ```sh
   aegis workspace activate --config CONFIG_PATH --revision FULL_CONTROL_COMMIT --expect none --json
   ```

4. Review the proposal's policy, membership and approval statement. Ask the
   owner to sign the approval for that exact statement and use the signed
   approval packet through the ordinary activation flow. The activation
   proposal leaves the draft inert. After activation, use a manager scan to
   confirm that the intended action and context serve the reviewed rule
   revision. [Manager setup and signed activation](manager-workspaces.md#owner-activation)

## Why the rules are included

| Rule | Lesson |
| --- | --- |
| `ground-rulings` | A ruling made from an assumption can acquire authority it never had. Verify its factual and approval basis. |
| `reconcile-due-work` | A submitted or queued request can stay unstarted, and completed work can go unobserved. Reconcile both transitions against due work. |
| `reconcile-before-intervention` | An interruption can arrive after a side effect. Reconcile the existing operation before taking over or repeating it. |
| `validate-assignment` | An issued assignment can omit an input, permitted scope, response format or outcome check even when the planning record is complete. Review the issued text. |
| `carry-decisions-forward` | A successor can inherit a stale checkpoint that drops an open obligation or a standing decision. Reconcile what the successor actually receives. |
| `reconcile-required-evidence` | A successful partial retry can obscure a missing check. Keep each check tied to the candidate revision and its own observed result. |
| `bind-owner-answers` | A genuine owner answer can be applied to a different question, scope or revision. Retain the terms of the answer with the exact decision. |
| `reconcile-custody-transfers` | A transfer can update one record while the outgoing writer still holds a claim or the successor lacks admission. Check both parties and the resulting claims. |
| `check-retry-budgets` | Another attempt can exhaust the time or reservation available for the work. Check remaining capacity against the work still due. |
| `verify-reported-state` | Requests, neighboring events and first-hand results carry different evidence. Report each transition from the observation for that exact work. |
| `verify-served-assignment` | The assignment or execution identity observed at launch or resume can differ from the approved one. Compare the observed binding with the required binding. |
| `measure-round-benefit` | Repeated work can consume time and resources without closing the gap to the objective. Measure the result before authorizing another round. |

## Adapt a reviewed proposal

When a mined proposal passes review and the lesson applies to management,
adapt its reviewed guidance into `text`, choose a unique `id`, assign the
management `actions` and select any adopter-specific `match` fields. Keep
source evidence with the review record. Use the same control-policy review,
validation and signed activation for the new entry. Proposal acceptance and
manager activation are separate decisions.
