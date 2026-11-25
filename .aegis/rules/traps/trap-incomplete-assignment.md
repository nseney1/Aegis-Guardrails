---
id: trap-incomplete-assignment
type: trap
enforcement: advisory
domain: correctness
hypothesis: "A valid draft can render as an empty, stale or inadmissible assignment."
prediction: "Validating the final job request will detect a missing input or unauthorized write before a worker is started."
falsification: "Retire if ten malformed rendered requests are all rejected before worker start with the affected input identified."
target_paths:
  - tools/hierarchy_jobs.py
  - aegis_core/team_queue.py
triggers:
  - delegation
  - request_validation
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Validate the rendered request against the chosen recipe and current declared
scope before admission, and report the exact missing or conflicting input to
the sender.

Validating the final job request will detect a missing input or unauthorized
write before a worker is started.

Check the recipient-facing representation after defaults, substitutions and
scope restrictions have been applied.

## Evidence

The catalog trap verifies a delegate's output. The additional check is at
intake, where hierarchy_jobs.admit and checked_paths consume the job and
recipe.

- 2026-11-16 — Wrote readiness in a form the lander skipped. Four landings accumulated about 159 idle lane-minutes (coordinator decision log).
- 2026-11-21 — Copied the preceding round's write list. The writer stopped despite holding all seven files (coordinator decision log).

Catalog comparison: extends trap-unverified-delegation.
