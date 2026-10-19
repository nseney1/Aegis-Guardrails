"""Golden ``tree_algo`` v1 vectors (ARCH-3): the tree a work tree would commit must not drift.

``tree=`` is persisted in ledger ``check`` rows and ``Aegis-Check`` trailers, so a changed value
strands every stored row. ``tree_vectors_v1.json`` describes six repositories byte for byte (files,
modes, configuration, commit identity) and the ``TreeBinding.as_dict()`` that ``treeid.tree_of``
gave on ``cdb527b``. Each fixture is rebuilt here, and each expected tree is also cross-checked
against plain git (``git add -A`` with the state exclusion, then ``git write-tree``) on an identical
repository, which ties the vectors to git rather than to a snapshot of treeid's own output.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, Mapping

import pytest

from aegis_core import treeid

VECTORS = json.loads((Path(__file__).with_name("tree_vectors_v1.json")).read_text(encoding="utf-8"))
FIXTURES = {f["name"]: f for f in VECTORS["fixtures"]}

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _git(root: Path, *args: str) -> str:
    env = {**os.environ, **VECTORS["identity"]}
    return subprocess.run(["git", "-c", "core.autocrlf=false", *args], cwd=str(root), env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def _init(root: Path) -> None:
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    for key, value in VECTORS["repository"]["config"].items():
        _git(root, "config", key, value)


def _write(root: Path, spec: Mapping[str, Any]) -> None:
    path = root / spec["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(spec["data"].encode("utf-8"))
    os.chmod(path, int(spec["mode"], 8))
    if spec["mode"] == "0755" and not os.access(path, os.X_OK):
        pytest.skip("the file system refuses the executable bit")


def _build(root: Path, fixture: Mapping[str, Any]) -> None:
    if fixture.get("posix_only") and os.name == "nt":
        pytest.skip("UNVERIFIED how git on Windows records the executable bit")
    _init(root)
    for spec in VECTORS["base"]["files"]:
        _write(root, spec)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", VECTORS["base"]["message"])
    for spec in fixture["files"]:
        _write(root, spec)
    sub = fixture.get("submodule")
    if sub:
        nested = root / sub["path"]
        _init(nested)
        for spec in sub["files"]:
            _write(nested, spec)
        _git(nested, "add", "-A")
        _git(nested, "commit", "-q", "-m", sub["message"])
        assert _git(nested, "rev-parse", "HEAD") == sub["commit"], fixture["name"]
        _git(root, "add", sub["path"])
        for spec in fixture["after_add"]:
            _write(root, spec)


def _check(name: str, expected: Mapping[str, Any], actual: Dict[str, Any]) -> None:
    assert actual == dict(expected), f"tree vector {name!r} drifted: expected {dict(expected)}, got {actual}"


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_tree_of_reproduces_the_recorded_binding(tmp_path, name):
    fixture = FIXTURES[name]
    _build(tmp_path / "repo", fixture)
    binding = treeid.tree_of(tmp_path / "repo")
    assert binding.algo == "v1"
    _check(name, fixture["expected"], binding.as_dict())


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_recorded_tree_is_what_plain_git_writes(tmp_path, name):
    fixture = FIXTURES[name]
    root = tmp_path / "repo"
    _build(root, fixture)
    _git(root, "add", "-A", "--", ".", ":(exclude,glob)**/.aegis/state/**")
    assert _git(root, "write-tree") == fixture["expected"]["tree"], name


def test_vector_file_pins_the_v1_recipe_and_binding_shape():
    assert VECTORS["tree_algo"] == treeid.TREE_ALGO == "v1"
    assert len(FIXTURES) == 6
    shape = set(treeid.TreeBinding("ok", "0" * 40).as_dict())
    assert all(set(f["expected"]) == shape for f in FIXTURES.values())


def test_a_vector_altered_by_one_hex_digit_fails_naming_the_fixture(tmp_path):
    fixture = FIXTURES["plain"]
    _build(tmp_path / "repo", fixture)
    actual = treeid.tree_of(tmp_path / "repo").as_dict()
    tree = fixture["expected"]["tree"]
    tampered = dict(fixture["expected"], tree=tree[:-1] + ("0" if tree[-1] != "0" else "1"))
    with pytest.raises(AssertionError, match="'plain' drifted"):
        _check("plain", tampered, actual)
