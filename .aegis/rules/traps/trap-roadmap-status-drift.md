---
id: trap-roadmap-status-drift
domain: documentation
type: trap
enforcement: advisory
hypothesis: "Shipping a release without moving its work out of the planned sections (docs/why-aegis.md section 6, SECURITY.md 'What Aegis does not claim') and into a CHANGELOG entry leaves the docs telling readers that shipped work is planned, or that planned work has shipped"
prediction: "Will fire when a version bump or CHANGELOG entry ships work that docs/why-aegis.md section 6 or SECURITY.md still calls planned, or when the version is bumped without a CHANGELOG entry for it"
falsification: 0 findings in 20 sessions → prune
target_paths:
  - docs/why-aegis.md
  - CHANGELOG.md
  - SECURITY.md
  - aegis_core/_version.py
  - pyproject.toml
triggers:
  - release
  - feature_addition
  - version_bump
  - commit_review
minimum_mode: patrol
expiry_sessions: 30
expiry_days: 90
created: 2026-10-01
impact_weight: 1.0
tags:
  - documentation
  - drift
  - roadmap
  - process
---

Origin (v0.81): two Phase 4 features shipped in v0.80, but the roadmap document still
listed them as planned and next, and the CI Outcome Reporter shipped in v0.81 with no
roadmap entry at all. The v4.0 docs deleted the roadmap; planned work is now stated in
docs/why-aegis.md section 6 ("planned, not shipped") and in SECURITY.md under
"What Aegis does not claim", and each release is recorded in CHANGELOG.md.

Detection: when a commit touches aegis_core/_version.py (the one version source;
pyproject.toml reads it dynamically), check that CHANGELOG.md has an entry for the new
version, and that nothing the entry lists as shipped is still called planned in
docs/why-aegis.md section 6 or in SECURITY.md. When a commit marks planned work as
shipped in one of these files, check the other two. If any of them disagrees, flag the
change for review.
