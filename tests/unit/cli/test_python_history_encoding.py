"""Historical Python and live Python must use the same source-decoding contract."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from aegis_cli.cli import main
from tests.helpers_humangate import git_ok

pytestmark = pytest.mark.skipif(not git_ok(), reason="needs git")

RULE = '''---
id: no-fr
type: invariant
domain: correctness
enforcement: gate
hypothesis: h
target_paths: ["app.py"]
forbid_ast:
  calls:
    - name: send
      where:
        locale: "français"
---
# Rule
'''
REPLAY_SOURCE = 'def send(*, locale):\n    pass\nsend(locale="français")\n'


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", "user.name=T", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", *args], cwd=root, text=True,
        stderr=subprocess.PIPE, timeout=20,
    ).strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("AEGIS_WORKSPACE", "GITHUB_BASE_REF", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(key, raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".aegis" / "rules").mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    return root


def _commit(root: Path) -> str:
    _git(root, "add", "app.py", ".aegis")
    _git(root, "commit", "-qm", "fixture")
    return _git(root, "rev-parse", "HEAD")


def _check(root: Path, capsys, staged: bool = False):
    args = ["--hook"] if staged else ["--base", "main", "app.py"]
    result = main(["check", "--workspace", str(root), "--json", *args])
    return result, json.loads(capsys.readouterr().out)


def _failed(payload):
    return sorted(row["tool"] for row in payload["layer1"] if not row["verdict"])


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "utf-8-sig"])
@pytest.mark.parametrize("staged", [False, True], ids=["working", "staged"])
def test_unrelated_edit_does_not_reintroduce_encoded_python_security_finding(repo, capsys, encoding, staged):
    text = f'# coding: {encoding}\nimport pickle\ndef load(data):\n    return pickle.loads(data)  # café\n'
    (repo / "app.py").write_bytes(text.encode(encoding))
    _commit(repo)
    _git(repo, "checkout", "-qb", "work")
    (repo / "app.py").write_bytes((text + "unrelated = 1\n").encode(encoding))
    if staged:
        _git(repo, "add", "app.py")
    result, payload = _check(repo, capsys, staged)
    assert (result, _failed(payload)) == (0, [])


@pytest.mark.parametrize("encoding", ["latin-1", "utf-8-sig"])
@pytest.mark.parametrize("staged", [False, True], ids=["working", "staged"])
def test_new_security_call_in_encoded_python_still_blocks(repo, capsys, encoding, staged):
    prefix = f'# coding: {encoding}\nimport pickle\n'
    (repo / "app.py").write_bytes((prefix + 'TEXT = "café"\n').encode(encoding))
    _commit(repo)
    _git(repo, "checkout", "-qb", "work")
    (repo / "app.py").write_bytes((prefix + 'TEXT = "café"\ndef load(data):\n    return pickle.loads(data)\n').encode(encoding))
    if staged:
        _git(repo, "add", "app.py")
    result, payload = _check(repo, capsys, staged)
    assert (result, _failed(payload)) == (1, ["security_pack:sec-py-pickle-loads"])


@pytest.mark.parametrize("prefix", [
    b"# coding: utf-7\n", b"# coding: unknown-codec\n", b"\xef\xbb\xbf# coding: latin-1\n",
    b"# coding: utf-8\n# \xff\n",
], ids=["stateful", "unknown", "bom-conflict", "invalid-utf8"])
def test_unreadable_historical_encoding_cannot_grandfather_a_security_call(repo, capsys, prefix):
    body = b"import pickle\ndef load(data):\n    return pickle.loads(data)\n"
    (repo / "app.py").write_bytes(prefix + body)
    _commit(repo)
    _git(repo, "checkout", "-qb", "work")
    (repo / "app.py").write_bytes(body)
    result, payload = _check(repo, capsys)
    assert (result, _failed(payload)) == (1, ["security_pack:sec-py-pickle-loads"])


def test_python_baseline_decoding_keeps_secret_delta_representation_symmetric(repo, capsys):
    text = '# coding: latin-1\nURL = "https://café:pàssword@vault.invalid"\n'
    (repo / "app.py").write_bytes(text.encode("latin-1"))
    _commit(repo)
    _git(repo, "checkout", "-qb", "work")
    (repo / "app.py").write_bytes((text + "unrelated = 1\n").encode("latin-1"))
    result, payload = _check(repo, capsys)
    assert (result, _failed(payload)) == (0, [])


def test_a_new_secret_in_latin1_python_still_blocks(repo, capsys):
    text = '# coding: latin-1\nTEXT = "café"\n'
    (repo / "app.py").write_bytes(text.encode("latin-1"))
    _commit(repo)
    _git(repo, "checkout", "-qb", "work")
    (repo / "app.py").write_bytes((text + 'URL = "https://café:pàssword@vault.invalid"\n').encode("latin-1"))
    result, payload = _check(repo, capsys)
    assert (result, _failed(payload)) == (1, ["secret_scan:url-basic-auth"])


def _history(root: Path, source: bytes) -> str:
    rule = root / ".aegis" / "rules" / "invariants" / "no-fr.md"
    rule.parent.mkdir()
    rule.write_text(RULE, encoding="utf-8")
    (root / "app.py").write_bytes(source)
    head = _commit(root)
    _git(root, "update-ref", "refs/remotes/origin/main", head)
    _git(root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return head


def _sync(root: Path, capsys):
    assert main(["sync", "--workspace", str(root), "--json"]) == 0
    return json.loads(capsys.readouterr().out)["replay"]


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "utf-8-sig"])
def test_replay_matches_non_ascii_argument_in_supported_python_encoding(repo, capsys, encoding):
    _history(repo, (f"# coding: {encoding}\n" + REPLAY_SOURCE).encode(encoding))
    replay = _sync(repo, capsys)
    assert (replay["detections"], replay["files_skipped"], replay["errors"]) == (1, [], [])


@pytest.mark.parametrize("source", [
    ("# coding: utf-8\n" + REPLAY_SOURCE).encode("latin-1"),
    ("# coding: unknown-codec\n" + REPLAY_SOURCE).encode("utf-8"),
    ("# coding: utf-7\n" + REPLAY_SOURCE).encode("utf-8"),
    b"\xef\xbb\xbf" + ("# coding: latin-1\n" + REPLAY_SOURCE).encode("utf-8"),
], ids=["invalid-utf8", "unknown", "stateful", "bom-conflict"])
def test_replay_reports_undecodable_historical_python_as_unverified(repo, capsys, source):
    _history(repo, source)
    replay = _sync(repo, capsys)
    assert (replay["detections"], replay["files_skipped"], replay["errors"]) == (0, ["app.py"], [])


def test_replay_revisits_a_complete_cache_written_by_the_utf8_replacement_decoder(repo, capsys):
    head = _history(repo, ("# coding: latin-1\n" + REPLAY_SOURCE).encode("latin-1"))
    state = repo / ".aegis" / "state" / "derived.json"
    state.parent.mkdir()
    # A v1 replay document recorded by the public sync command for this exact rule.
    state.write_text(json.dumps({"v": 1, "rules": {}, "replay": {
        "branch": "main", "tip": head,
        "rules": "5ef706c682f149e31603572efaf2506c4cb1b1de1f87746c850431fbe4c5cbc9",
    }}), encoding="utf-8")
    replay = _sync(repo, capsys)
    assert (replay["detections"], replay["files_skipped"]) == (1, [])
