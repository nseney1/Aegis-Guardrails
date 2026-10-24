---
id: invariant-test-canonical-colocality
type: invariant
domain: testing
enforcement: gate
hypothesis: 1:1 test colocality and pure fixture injection eliminates circular dependency bloat and test state pollution.
prediction: Zero hardcoded lookup tables in verification checks, zero base-class inheritance coupling, and zero sprint-named orphan tests.
falsification: Any test file using class inheritance, sprint milestone naming, or lacking a mirrored module path.
tags:
- testing
- colocality
- architecture
- invariant
impact_weight: 1.0
created: '2026-10-06'
---
# Invariant: Canonical Test Colocality & Behavioral Testing

> **Role**: Enforces 1:1 module-to-test colocation, behavioral assertion density, and bans test base-class inheritance across Aegis-Guardrails.

## 1. 1:1 Directory Mirroring
Every production source module MUST map 1:1 to a canonical test file:
- `aegis_core/<mod>.py` -> `tests/core/test_<mod>.py`
- `aegis_cli/<mod>.py` -> `tests/cli/test_<mod>.py`
- `aegis_mcp/<mod>.py` -> `tests/mcp/test_<mod>.py`
- `aegis_sdk/<mod>.py` -> `tests/sdk/test_<mod>.py`

## 2. Prohibited Test Naming Patterns
Ad-hoc sprint and milestone names are strictly forbidden:
- ❌ No `test_phase*.py`
- ❌ No `test_*_hardening.py`
- ❌ No `test_*_fix_*.py`
- ❌ No `test_doctor_fix_path.py`

## 3. Strict Ban on Test Class Inheritance
- ❌ Prohibit `class BaseTestCase` or any test base-class inheritance hierarchies.
- Test dependencies must be injected via Pytest fixtures.
- Classes are permitted *only* as uninherited organizational namespaces (e.g. `class TestPromoteValidation:`).

## 4. Behavioral Assertions & Anti-Tautology Mandate
- Tests must assert observable state transitions, output payloads, or explicit exceptions.
- ❌ Forbid tautological mock assertions (e.g., asserting mock return values without verifying state changes).
- ❌ Forbid mocking the system under test (SUT).
- ❌ Forbid trivial type-only checks (`isinstance()`) in place of behavioral verification.
