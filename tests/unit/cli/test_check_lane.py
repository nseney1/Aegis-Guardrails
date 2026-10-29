"""`aegis check --lane <lane> [--base REF] [--paths G...] [--base-policy]` (v4.1 spec §1).

The post-lane gate through the real CLI: exit 0 when the lane's committed range passes
containment and Python test integrity, 1 when it does not or cannot be checked (a
shallow clone, an unresolvable base, no allowed paths), 2 for a usage error. ``--paths``
and ``--base-policy`` belong to ``--lane`` (``--base`` also names a plain check's baseline
source); FILES and the Layer 1/2 options do not combine with it. ``--json`` (or
``--format json``) prints one document with ``source``, ``aegis_version``, ``checked_at``
and ``scope``, errors included.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Optional

import pytest

from aegis_cli.check import CheckCommand
from aegis_cli.cli import main
from aegis_cli.verify import run_verify
from aegis_core import events, lane_gate, team
from aegis_core._version import __version__

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def _git(root: Path, *args: str, stdin: Optional[str] = None) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", "-c", "commit.gpgsign=false",
         "-c", "core.autocrlf=false", *args],
        cwd=str(root), check=True, capture_output=True, text=True, input=stdin,
    ).stdout.strip()


def _write(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode("utf-8"))


def _commit(root: Path, message: str = "change") -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "--allow-empty", "-m", message)
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture(autouse=True)
def _no_ci_base(monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / ".aegis").mkdir()
    _write(root, "docs/guide.md", "guide\n")
    _write(root, "src/app.py", "def app():\n    return 1\n")
    _write(root, "tests/test_app.py", "def test_a():\n    assert 1\n\n\ndef test_b():\n    assert 2\n")
    _commit(root, "base")
    _git(root, "checkout", "-q", "-b", "lane/docs")
    monkeypatch.chdir(root)
    return root.resolve()


def _run(capsys, *argv: str):
    try:
        rc = main(["check", *argv])
    except SystemExit as exc:  # argparse
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _json(capsys, *argv: str):
    rc, out, err = _run(capsys, *argv, "--json")
    return rc, json.loads(out), err


# ── Pass and fail ────────────────────────────────────────────────────────────

def test_a_contained_lane_passes_with_exit_0(repo: Path, capsys):
    _write(repo, "docs/guide.md", "lane\n")
    _commit(repo)
    rc, out, err = _run(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**")
    assert rc == 0, err
    assert out.splitlines()[0] == "aegis check --lane docs: PASSED (self-attested)"


def test_a_head_already_in_base_passes_and_says_nothing_was_checked(repo: Path, capsys):
    warning = "HEAD is already contained in main: nothing was checked"
    rc, out, err = _run(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**")
    assert rc == 0, err
    assert f"warning: {warning}" in out.splitlines()
    assert warning not in err  # printed once, in the report
    rc, payload, _ = _json(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**")
    assert (rc, payload["status"], payload["warnings"]) == (0, "pass", [warning])


def test_a_stray_path_or_a_removed_test_fails_with_exit_1(repo: Path, capsys):
    _write(repo, "src/app.py", "def app():\n    return 2\n")
    _write(repo, "tests/test_app.py", "def test_a():\n    assert 1\n")
    _commit(repo)
    rc, out, _ = _run(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**", "tests/**")
    assert rc == 1
    assert out.splitlines()[0] == "aegis check --lane docs: FAILED (self-attested)"
    finding = lane_gate.finding_id("removed", "tests/test_app.py", "test_b")
    assert f"{finding} removed tests/test_app.py: test_b" in out
    assert "src/app.py" in out


def test_the_lease_supplies_the_paths(repo: Path, capsys):
    team.claim(repo, "docs", ["docs/**"], owner="o@h")
    _write(repo, "docs/guide.md", "lane\n")
    _commit(repo)
    rc, payload, _ = _json(capsys, "--lane", "docs", "--base", "main")
    assert rc == 0
    assert payload["provenance"] == {"paths": "lease", "shared": "worktree"}


def test_base_policy_is_witnessed(repo: Path, capsys):
    _write(repo, "docs/guide.md", "lane\n")
    _commit(repo)
    _git(repo, "checkout", "-q", "main")
    _write(repo, ".aegis/team.json", json.dumps({"v": 1, "lanes": {"docs": ["docs/**"]}}))
    tip = _commit(repo, "policy")
    _git(repo, "checkout", "-q", "lane/docs")
    rc, payload, _ = _json(capsys, "--lane", "docs", "--base", "main", "--base-policy")
    assert rc == 0
    assert payload["label"] == "witnessed: base policy"
    assert payload["provenance"] == {"paths": f"base@{tip}", "shared": f"base@{tip}"}


def test_the_default_base_is_the_branch_base(repo: Path, capsys):
    _write(repo, "docs/guide.md", "lane\n")
    _commit(repo)
    rc, payload, _ = _json(capsys, "--lane", "docs", "--paths", "docs/**")
    assert rc == 0
    assert payload["scope"]["base"] == "main"


# ── JSON ─────────────────────────────────────────────────────────────────────

def test_json_carries_the_envelope_and_the_records(repo: Path, capsys):
    _write(repo, "src/app.py", "def app():\n    return 2\n")
    _commit(repo)
    rc, payload, _ = _json(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**")
    assert rc == 1
    assert payload["source"] == "aegis check --lane"
    assert payload["aegis_version"] == __version__
    assert TS.match(payload["checked_at"])
    assert payload["scope"]["lane"] == "docs" and payload["scope"]["base"] == "main"
    assert payload["status"] == "fail"
    assert payload["containment"]["violations"] == ["src/app.py"]
    assert payload["protected_changed"] is False


def test_format_json_is_the_same_document(repo: Path, capsys):
    _commit(repo)
    rc, out, _ = _run(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**", "--format", "json")
    assert rc == 0
    payload = json.loads(out)
    assert payload["status"] == "pass"
    assert out == json.dumps(payload, indent=2) + "\n"


def test_an_error_is_a_json_document_too(repo: Path, capsys):
    rc, out, _ = _run(capsys, "--lane", "docs", "--base", "origin/nope", "--paths", "docs/**", "--json")
    payload = json.loads(out)
    assert out == json.dumps(payload, indent=2) + "\n"
    assert rc == 1
    assert payload["source"] == "aegis check --lane"
    assert TS.match(payload["checked_at"]) and payload["aegis_version"] == __version__
    assert payload["scope"] == {"workspace": str(repo), "lane": "docs"}
    assert payload["status"] == "error"
    assert payload["error"].startswith("needs history: fetch with fetch-depth 0")


def test_a_usage_error_in_json_mode_exits_2_with_a_document(repo: Path, capsys):
    rc, payload, _ = _json(capsys, "--lane", "docs", "--base-policy", "--paths", "docs/**")
    assert rc == 2
    assert payload["status"] == "error" and "--paths" in payload["error"]


# ── Errors ───────────────────────────────────────────────────────────────────

def test_needs_history_exits_1(repo: Path, capsys):
    rc, out, err = _run(capsys, "--lane", "docs", "--base", "origin/nope", "--paths", "docs/**")
    assert rc == 1
    assert out == ""
    assert "Error: needs history: fetch with fetch-depth 0" in err


def test_no_allowed_paths_exits_1(repo: Path, capsys):
    rc, _, err = _run(capsys, "--lane", "docs", "--base", "main")
    assert rc == 1
    assert "no live lease" in err


@pytest.mark.parametrize("argv, flag", [
    # --base is not here: since v4.2 a plain check takes it too, to read the baseline from the base
    # (tests/unit/cli/test_check_baseline.py); --paths and --base-policy stay with --lane.
    (["--paths", "docs/**"], "--paths"),
    (["--base-policy"], "--base-policy"),
])
def test_lane_options_without_lane_are_usage_errors(repo: Path, capsys, argv, flag):
    rc, _, err = _run(capsys, *argv)
    assert rc == 2
    assert f"{flag} only applies with --lane" in err


@pytest.mark.parametrize("extra, flag", [
    (["src/app.py"], "FILES"),
    (["--full"], "--full"),
    (["--plan", "x"], "--plan"),
    (["--plan-file", "plan.md"], "--plan-file"),
    (["--hook"], "--hook"),
    (["--strict"], "--strict"),
    (["--dry-run"], "--dry-run"),
    (["--llm-cmd", "x"], "--llm-cmd"),
])
def test_lane_mode_refuses_the_other_check_options(repo: Path, capsys, extra, flag):
    # FILES first: after --paths, argparse would read them as more globs.
    rc, _, err = _run(capsys, *extra, "--lane", "docs", "--base", "main", "--paths", "docs/**")
    assert rc == 2
    assert f"--lane does not combine with {flag}" in err
    assert events.read(repo, "lane_check").rows == []  # refused before any check


def test_base_policy_with_paths_is_a_usage_error(repo: Path, capsys):
    rc, _, err = _run(capsys, "--lane", "docs", "--base-policy", "--paths", "docs/**")
    assert rc == 2
    assert "--paths" in err


def test_an_invalid_lane_name_is_a_usage_error(repo: Path, capsys):
    rc, _, err = _run(capsys, "--lane", "Bad/Lane", "--paths", "docs/**")
    assert rc == 2
    assert "invalid lane name" in err


def test_an_invalid_team_json_is_a_usage_error(repo: Path, capsys):
    _write(repo, ".aegis/team.json", '{"v": 1, "secret_key_name": 1}')
    rc, _, err = _run(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**")
    assert rc == 2
    assert "team.json: 1 unknown key(s)" in err
    assert "secret_key_name" not in err


@pytest.mark.skipif(os.name == "nt", reason="control characters in a path need a POSIX checkout")
def test_text_output_strips_terminal_controls_from_paths(repo: Path, capsys):
    oid = _git(repo, "hash-object", "-w", "--stdin", stdin="x\n")
    _git(repo, "update-index", "--add", "--cacheinfo", f"100644,{oid},src/\x1b]0;evil\x07.md")
    _git(repo, "commit", "-q", "-m", "control")
    rc, out, _ = _run(capsys, "--lane", "docs", "--base", "main", "--paths", "docs/**")
    assert rc == 1
    assert "\x1b" not in out and "\x07" not in out


def test_run_verify_dispatches_on_the_lane_attribute(repo: Path, capsys):
    _commit(repo)
    args = argparse.Namespace(lane="docs", base="main", paths=["docs/**"], base_policy=False, files=[], hook=False,
                              strict=False, full=False, plan=None, plan_file=None, llm_cmd=None, dry_run=False,
                              format="text", json=False, workspace=str(repo))
    assert run_verify(args) == 0
    assert capsys.readouterr().out.startswith("aegis check --lane docs: PASSED")


def test_run_verify_without_the_lane_options_checks_as_before(repo: Path, capsys):
    """Callers that build their own namespace (older SDK callers) never set the v4.1 options."""
    args = argparse.Namespace(files=["src/app.py"], hook=False, strict=False, full=False, plan=None, plan_file=None,
                              llm_cmd=None, dry_run=True, format="json", json=False, workspace=str(repo))
    assert run_verify(args) == 0
    assert json.loads(capsys.readouterr().out)["files"] == ["src/app.py"]


# ── Parser and help ──────────────────────────────────────────────────────────

def test_lane_is_in_the_check_mode_group():
    parser = argparse.ArgumentParser()
    CheckCommand().configure_parser(parser)
    modes = [g for g in parser._mutually_exclusive_groups if any("--lane" in a.option_strings for a in g._group_actions)]
    assert len(modes) == 1
    args = parser.parse_args(["--lane", "docs", "--base", "origin/main", "--paths", "a/**", "b", "--base-policy"])
    assert (args.lane, args.base, args.paths, args.base_policy) == ("docs", "origin/main", ["a/**", "b"], True)
    defaults = parser.parse_args([])
    assert (defaults.lane, defaults.base, defaults.paths, defaults.base_policy) == (None, None, None, False)


def test_help_documents_the_gate_and_its_limits(capsys):
    rc, out, _ = _run(capsys, "--help")
    assert rc == 0
    flat = " ".join(out.split())
    for flag in ("--lane LANE", "--base REF", "--paths GLOB", "--base-policy"):
        assert flag in flat
    assert "advisory" in flat and "v4.1" not in flat
    assert "only as strong as the protection on .github/** and on the base branch" in flat
    assert "CHANGELOG.md also admits docs/CHANGELOG.md" in flat
    assert "fetch-depth 0" in flat
