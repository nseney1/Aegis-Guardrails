---
id: trap-platform-capability-guard
domain: portability
type: trap
enforcement: advisory
hypothesis: "Tests and modules that use descriptor-relative I/O, pidfds, POSIX tools or post-3.9 Python behaviour without a capability guard (or with a version-equality skip) fail or silently skip on the Windows and Python 3.9 CI legs."
prediction: "New tests that reach dir_fd, pidfd or POSIX-tool paths without the existing capability guard draw 'missing Windows capability guard' or 'unavailable on Python 3.9' findings."
falsification: "Revisit if a ratchet enforces capability guards, the Windows/3.9 legs pass, and fewer than 5 such findings appear in 14 days."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:58Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - portability
target_paths:
  - "tests/**"
  - aegis_core/pathlookup.py
  - "aegis_core/workspace/*.py"
  - aegis_core/storage_confined.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Code and tests that use POSIX-only behaviour or Python features newer than the supported floor carry the existing capability guards (Windows, Python 3.9) instead of assuming the developer's platform.

Verify: affected tests run on Python 3.9 and skip or adapt correctly where the capability is missing.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 146 blocking findings in this class across 22 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- codex-a, 2026-11-17, P1: missing Windows capability guard.
- grok-b, 2026-11-24, Medium: Codex registration unavailable on Python 3.9.
- strip-fix, 2026-11-23, Medium: test skips unless the Python version equals 3.12.
- dispatcher, 2026-11-22, Medium: a regression test still assumes POSIX capabilities.
- rf50-fix, 2026-11-14, P2: indirect-process tests lack guards.
- Why existing rules did not cover it: `persona-cross-platform-qa` targets only `install_hosts.py`, `hooks/management.py` and the Makefile. `trap-future-annotations` covers only PEP 604 syntax, and `trap-shell-true-portability` covers only `shell=True`.
