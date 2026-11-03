---
id: contract-atomic-storage-boundaries
type: contract
domain: security
enforcement: advisory
hypothesis: "Publication safety depends on preserving each storage API's documented path, mode and ownership behavior."
prediction: "A generic write replacement can follow an attacker-controlled link, widen permissions or lose a concurrent update."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/storage.py"
  - "aegis_core/atomicio.py"
  - "tests/unit/core/test_storage.py"
---
## Do
Use the established atomic/locked storage APIs with explicit symlink and permission semantics; reject unsafe destinations without overwriting valid data or exposing partial/private artifacts.

Keep exclusive creation distinct from replacement, set modes on owned temporary files, and retain bounded Windows sharing-violation behavior. JSONL append serializes before mutation and preserves valid rows around torn tails; ledger writes use the shared ledger lock.

Verify: Exercise existing/dangling/swapped symlinks, nonregular destinations, umasks, write/rename failure, torn tails and concurrent writers through public storage calls.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- tests/unit/core/test_storage.py covers exclusive creation, atomic replacement, permissions, symlink swaps and torn JSONL tails.
- aegis_core/storage.py and atomicio.py provide the canonical publication primitives.
- aegis_core/telemetry_engine/ledger.py documents shared ledger locking and append-only publication.
