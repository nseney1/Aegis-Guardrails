---
id: trap-incomplete-lease-transfer
type: trap
enforcement: advisory
domain: correctness
hypothesis: "A lease can change while the lender and borrower still have incompatible assignments."
prediction: "A loan that updates only ownership will leave an admission refusal or out-of-scope write on at least one side."
falsification: "Retire if ten loans with active follow-on work reconcile both parties' assignments and the return condition without a later admission repair."
target_paths:
  - aegis_core/team_claims.py
  - aegis_core/team_lease_custody.py
triggers:
  - ownership_change
  - lease_transfer
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Check both parties’ writer state, current claim identity, branch, duration and
admitted scope before accepting a transfer, then verify the new claims and
record the return duty.

A loan that updates only ownership will leave an admission refusal or
out-of-scope write on at least one side.

Keep an interrupted transfer pending until the observed claims and
assignments agree.

## Evidence

The workspace binding contract identifies the right repository and session.
The transfer also has a donor, a recipient, a stopped-writer check and a
scheduled return.

- 2026-11-20 — Omitted the branch on a manual claim. The writer refused the foreign lease (coordinator decision log).
- 2026-11-23 — Lent files without reconciling both assignments. The borrower's admission and lender's next writer required repair (coordinator decision log).

Catalog comparison: extends contract-workspace-session-binding.
