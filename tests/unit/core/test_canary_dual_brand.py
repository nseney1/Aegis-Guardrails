"""Canonical Aegis package prefixes resolve to their matching test homes."""
from pathlib import Path
from aegis_core.verification.checkpoint_checks import _resolve_canonical_test_candidates


def test_canonical_package_prefix_stripping():
    root = Path("/dummy/repo")
    for package, domain, module in (("aegis_core", "core", "scoring"), ("aegis_cli", "cli", "verify")):
        candidates = _resolve_canonical_test_candidates(root, root / package / (module + ".py"))
        assert root / "tests" / domain / ("test_" + module + ".py") in candidates
