"""AC24 acquisition's npm gate: only the runner's existing npm 10 or 11, never an upgrade."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".github/scripts/ac24_acquire.py"
REFUSAL = "proposal requires existing npm 10 or 11; no upgrade is authorized"


@pytest.fixture(scope="module")
def acquire():
    # Import only: main() would need Windows, the pinned kit and real Node/npm, so the
    # gate is exercised directly and no test can reach node, npm or the network.
    spec = importlib.util.spec_from_file_location("ac24_acquire", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("version", ["10.9.2", "11.19.0"])
def test_existing_npm_10_or_11_passes_the_gate(acquire, version):
    assert acquire.require_existing_npm(version) is None


@pytest.mark.parametrize("version", ["9.9.4", "12.0.0"])
def test_other_npm_majors_are_refused_without_an_upgrade(acquire, version):
    with pytest.raises(RuntimeError) as refused:
        acquire.require_existing_npm(version)
    assert str(refused.value) == REFUSAL
