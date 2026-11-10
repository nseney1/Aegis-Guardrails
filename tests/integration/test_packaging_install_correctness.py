"""Regression coverage for packaging."""
from __future__ import annotations

import os
import re

from conftest import REPO_ROOT, read


def test_packaging_excludes_private_state_and_ships_rules_inside_aegis_core():
    manifest = read(os.path.join(REPO_ROOT, "MANIFEST.in"))
    assert "recursive-include .aegis" not in manifest
    assert "prune .aegis" in manifest
    assert ".aegis/evidence" not in manifest
    assert ".aegis/dreams" not in manifest

    pyproject = read(os.path.join(REPO_ROOT, "pyproject.toml"))
    # No top-level `rules`/`skills` package (release review): the sources map into aegis_core.
    assert '"rules*"' not in pyproject and '"skills*"' not in pyproject
    assert not re.search(r"(?m)^(rules|skills)\s*=\s*\[", pyproject)
    assert re.search(r'(?m)^"aegis_core\._data\.rules"\s*=\s*"rules"$', pyproject)
    assert '"*.md"' in pyproject and '".oracles/*.md"' in pyproject


def test_manifest_ships_no_bytecode_and_no_stale_trees():
    lines = [ln.strip() for ln in read(os.path.join(REPO_ROOT, "MANIFEST.in")).splitlines()]
    assert "global-exclude __pycache__" in lines
    assert "global-exclude *.py[cod]" in lines
    for stale in ("obsolete_rules", "obsolete_cli", "obsolete_core", "install"):
        assert not any(re.search(rf"\b{stale}\b", ln) for ln in lines if not ln.startswith("#")), stale


def test_runtime_has_no_dependencies_and_only_a_dev_extra():
    pyproject = read(os.path.join(REPO_ROOT, "pyproject.toml"))
    assert re.search(r"(?m)^dependencies = \[\]$", pyproject)
    extras = re.search(r"(?ms)^\[project\.optional-dependencies\]\n(.*?)^\[", pyproject).group(1)
    names = re.findall(r"(?m)^([A-Za-z0-9_-]+)\s*=", extras)
    assert names == ["dev"]
