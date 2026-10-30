---
id: invariant-no-pre-existing-excuse
domain: governance
type: invariant
enforcement: gate
hypothesis: "Calling a defect pre-existing or out of scope in a file the agent is modifying is an unverifiable claim by the party that may have introduced it, so such defects go unfixed"
prediction: "Defects found in files under modification are fixed in the same change, or logged as tracked findings with git blame or git log evidence when the file is outside the change"
falsification: "Over 20 sessions, every defect dismissed as pre-existing is confirmed by git blame to predate the session and none recurs as an escaped defect"
expiry_sessions: 15
expiry_days: 60
created: "2026-10-15T16:18:02Z"
impact_weight: 1.0
tags: ["dogfood", "process", "ownership"]
target_paths:
  - "CONTRIBUTING.md"
  - ".aegis/rules/invariants/invariant-no-pre-existing-excuse.md"
lineage:
  parent_id: null
  created_by: "manual"
  generation: 0
  siblings: []
---
# No Pre-Existing Excuse

**Activation**: Agent identifies a defect in a file it is actively modifying and labels it "pre-existing", "out of scope", or "not introduced by this change".

> **Role**: Prevents agents from dismissing defects in files they are actively
> modifying by labeling them "pre-existing" or "out of scope."

## 1. The Rule

If you are modifying a file and discover a defect in that file, **you own it**.
You may not classify it as "pre-existing" to avoid fixing it.

## 2. Why

The classification "pre-existing" is itself an unverifiable claim. The agent
asserting a bug is pre-existing is the same agent that might have introduced it.
Without independent version-control forensics (`git blame`, `git log`), the
claim has zero evidentiary weight.

This is the gentleman's agreement problem applied to scope: trusting the agent
to honestly classify which bugs are "theirs" is exactly the kind of honor-system
governance that Aegis exists to replace.

## 3. Exceptions

- **Explicitly out-of-scope files**: If the agent is modifying `foo.py` and
  finds a bug in `bar.py` (which it is NOT modifying), it may flag the bug
  without fixing it — but must log it as a tracked finding.
- **User-directed scope limits**: If the user explicitly says "only fix X,
  don't touch Y," the agent may defer Y with a logged rationale.

## 4. Evidence

Session 2026-09-30: Agent dismissed broken `import yaml` and collision
vulnerabilities as "pre-existing / out of scope" in files it was actively
editing. User had to intervene: *"The point of governance is that we can't
even trust the verdict that this is 'pre-existing'."*
