"""CLI-level tests for `aegis rule create` workspace resolution and body input.

Dogfood finding (ADR 0005 §1.5): `aegis rule create --workspace <dir without
.aegis>` walked up and wrote into `$HOME/.aegis/rules`. Every test runs `main`
with argv against an isolated HOME that holds a user-plane rule and a sentinel,
and proves HOME is byte-identical afterwards.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

from aegis_cli.cli import main
from aegis_cli.rule import run_rule
from aegis_core.workspace.base import Workspace
from aegis_core.yaml_engine.frontmatter import _get_body, parse_frontmatter

MAX_BODY = 64 * 1024


def _tree(root: Path) -> list[tuple[str, str]]:
    out = []
    for dirpath, dirs, files in os.walk(root):
        for d in dirs:
            out.append(((Path(dirpath) / d).relative_to(root).as_posix() + "/", ""))
        for name in files:
            full = Path(dirpath) / name
            out.append((full.relative_to(root).as_posix(), hashlib.sha256(full.read_bytes()).hexdigest()))
    return sorted(out)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (home / ".aegis" / "rules" / "traps" / "user-plane.md").write_text(
        "---\nid: user-plane\ntype: trap\n---\nUser rule.\n", encoding="utf-8"
    )
    (home / "SENTINEL").write_text("do not touch\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    return home


def _git_repo(path: Path, initialized: bool) -> Path:
    (path / ".git").mkdir(parents=True)
    if initialized:
        (path / ".aegis" / "rules").mkdir(parents=True)
    return path


def _not_a_workspace(directory: Path) -> str:
    return f"not an Aegis workspace (no .aegis/ in {directory}); run aegis init"


def _said(captured) -> str:
    """Everything a command printed, with the strings of a --json document decoded:
    JSON escapes each backslash of a Windows path, so a raw substring check misses it."""
    text = captured.out + captured.err
    try:
        doc = json.loads(captured.out)
    except ValueError:
        return text

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    return "\n".join([text, *strings(doc)])


# ── Workspace resolution ───────────────────────────────────────────────

def test_explicit_workspace_without_aegis_fails_and_writes_nothing(home, monkeypatch, capsys) -> None:
    repo = _git_repo(home / "code" / "repo", initialized=False)
    monkeypatch.chdir(repo)
    before = _tree(home)

    rc = main(["rule", "create", "--workspace", str(repo), "--hypothesis", "Never land here"])

    err = capsys.readouterr().err
    assert rc == 1
    assert _not_a_workspace(repo) in err
    assert _tree(home) == before
    assert not (repo / ".aegis").exists()


def test_implicit_workspace_never_walks_up_into_home(home, monkeypatch, capsys) -> None:
    repo = _git_repo(home / "code" / "repo", initialized=False)
    monkeypatch.chdir(repo)
    before = _tree(home)

    rc = main(["rule", "create", "--hypothesis", "Never land here"])

    assert rc == 1
    assert _not_a_workspace(repo) in capsys.readouterr().err
    assert _tree(home) == before


def test_explicit_home_workspace_is_rejected(home, monkeypatch, capsys) -> None:
    monkeypatch.chdir(home)
    before = _tree(home)

    rc = main(["rule", "create", "--workspace", str(home), "--hypothesis", "Never land here"])

    assert rc == 1
    assert (
        f"Error: not an Aegis workspace ({home} is the home directory; ~/.aegis is the user rule layer); "
        "run aegis init in a project"
    ) in capsys.readouterr().err
    assert _tree(home) == before


def test_resolution_never_crosses_the_git_toplevel(home, monkeypatch, capsys) -> None:
    outer = home / "code"
    (outer / ".aegis" / "rules").mkdir(parents=True)
    inner = _git_repo(outer / "inner", initialized=False)
    monkeypatch.chdir(inner)
    before_home, before_outer = _tree(home), _tree(outer / ".aegis")

    rc = main(["rule", "create", "--hypothesis", "Stay inside the repo"])

    assert rc == 1
    assert _not_a_workspace(inner) in capsys.readouterr().err
    assert _tree(outer / ".aegis") == before_outer
    assert _tree(home) == before_home


def test_rule_list_does_not_resolve_to_home(home, monkeypatch, capsys) -> None:
    """The walk-up stops at the repo's git toplevel (AD-4), so the uninitialized repo is
    listed as having no rules; the user layer in ~/.aegis/rules is never listed."""
    repo = _git_repo(home / "code" / "repo", initialized=False)
    monkeypatch.chdir(repo)
    before = _tree(home)

    rc = main(["rule", "list"])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.strip() == "No rules directory found."
    assert "user-plane" not in captured.out
    assert _tree(home) == before


def test_create_from_subdirectory_of_initialized_repo(home, monkeypatch, capsys) -> None:
    repo = _git_repo(home / "code" / "repo", initialized=True)
    (repo / "src").mkdir()
    monkeypatch.chdir(repo / "src")
    before = _tree(home / ".aegis")

    rc = main(["rule", "create", "--hypothesis", "Inside the repo", "--id", "inside"])

    assert rc == 0, capsys.readouterr().err
    assert (repo / ".aegis" / "rules" / "traps" / "inside.md").is_file()
    assert _tree(home / ".aegis") == before


def test_explicit_initialized_workspace_creates_rule(home, tmp_path, monkeypatch, capsys) -> None:
    repo = _git_repo(tmp_path / "elsewhere" / "repo", initialized=True)
    monkeypatch.chdir(tmp_path)
    before = _tree(home)

    rc = main(["rule", "create", "--workspace", str(repo), "--hypothesis", "Explicit", "--id", "explicit", "--json"])

    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["status"] == "created"
    assert Path(payload["path"]).resolve() == (repo / ".aegis" / "rules" / "traps" / "explicit.md").resolve()
    assert _tree(home) == before


def test_json_mode_reports_workspace_error_on_stdout(home, monkeypatch, capsys) -> None:
    repo = _git_repo(home / "code" / "repo", initialized=False)
    monkeypatch.chdir(repo)

    rc = main(["rule", "create", "--workspace", str(repo), "--hypothesis", "x", "--json"])

    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"status": "error", "error": _not_a_workspace(repo)}


def _trap(repo: Path, rule_id: str) -> Path:
    path = repo / ".aegis" / "rules" / "traps" / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\nid: {rule_id}\ntype: trap\nenforcement: advisory\n---\nBody.\n", encoding="utf-8")
    return path


@pytest.fixture
def elsewhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return cwd


@pytest.mark.parametrize("form", ["subcommand", "global"])
def test_explicit_workspace_subdirectory_lists_the_repo_rules(home, elsewhere, capsys, form: str) -> None:
    """The global and subcommand --workspace forms resolve a repo subdirectory the same way."""
    repo = _git_repo(home / "proj", initialized=True)
    _trap(repo, "repo-rule")
    (repo / "src").mkdir()
    src = str(repo / "src")
    argv = ["rule", "list", "--workspace", src, "--json"] if form == "subcommand" else ["--workspace", src, "rule", "list", "--json"]

    rc = main(argv)

    assert rc == 0
    assert [r["id"] for r in json.loads(capsys.readouterr().out)] == ["repo-rule"]


def test_explicit_workspace_subdirectory_promotes_in_the_repo(home, elsewhere, capsys) -> None:
    repo = _git_repo(home / "proj", initialized=True)
    source = _trap(repo, "repo-rule")
    (repo / "src").mkdir()

    rc = main(["rule", "promote", "repo-rule", "--workspace", str(repo / "src")])

    assert rc == 0, capsys.readouterr().out
    assert not source.exists()
    assert (repo / ".aegis" / "rules" / "invariants" / "repo-rule.md").is_file()


@pytest.mark.parametrize("action", [["list"], ["promote", "outer-rule"], ["demote", "outer-rule"], ["archive"]], ids=lambda a: a[0])
def test_explicit_workspace_never_resolves_above_its_git_toplevel(home, elsewhere, capsys, action: list[str]) -> None:
    outer = home / "code"
    _trap(outer, "outer-rule")
    inner = _git_repo(outer / "inner", initialized=False)
    before = _tree(home)

    rc = main(["rule", *action, "--workspace", str(inner)])

    assert rc == 1
    assert f"Error: {_not_a_workspace(inner)}" in capsys.readouterr().err
    assert _tree(home) == before


def test_preserved_global_workspace_flag_is_bounded_like_the_subcommand_flag(home, elsewhere, capsys) -> None:
    """A namespace whose resolved workspace was walked past INNER's git toplevel (as
    cli.main once did) still fails: rule.py checks the bound against the raw flag kept
    as ``_workspace_arg``. Discovery itself no longer walks out (test_workspace_binding).
    """
    outer = home / "code"
    (outer / ".aegis" / "rules").mkdir(parents=True)
    inner = _git_repo(outer / "inner", initialized=False)
    walked = Workspace(root=outer)
    before = _tree(home)
    args = argparse.Namespace(
        rule_action="create", hypothesis="crossing", id="crossing", json=False,
        ws=walked, workspace=str(walked.root), _project_root=walked.root, _workspace_arg=str(inner),
    )

    rc = run_rule(args)

    assert rc == 1
    assert f"Error: {_not_a_workspace(inner)}" in capsys.readouterr().err
    assert _tree(home) == before


@pytest.mark.parametrize("position", ["before-rule", "before-action"])
def test_global_workspace_flag_never_resolves_above_its_git_toplevel(home, elsewhere, capsys, position: str) -> None:
    """`aegis --workspace INNER rule create` and `aegis rule --workspace INNER create`.

    Both store into the shared top-level ``--workspace``; cli.main keeps the raw value
    as ``args._workspace_arg`` and resolves it no further than its git toplevel.
    """
    outer = home / "code"
    (outer / ".aegis" / "rules").mkdir(parents=True)
    inner = _git_repo(outer / "inner", initialized=False)
    before = _tree(home)
    create = ["create", "--hypothesis", "crossing", "--id", "crossing"]
    argv = (
        ["--workspace", str(inner), "rule", *create] if position == "before-rule"
        else ["rule", "--workspace", str(inner), *create]
    )

    rc = main(argv)

    assert rc == 1
    assert f"Error: {_not_a_workspace(inner)}" in capsys.readouterr().err
    assert _tree(home) == before


# ── never $HOME, never a workspace that encloses it (C-fix T6, AD-4) ───

_ACTIONS = [["list", "--json"], ["promote", "outer-rule"], ["demote", "outer-rule"], ["archive", "--dry-run"],
            ["create", "--hypothesis", "Never land here", "--id", "never"]]


@pytest.mark.parametrize("explicit", [True, False], ids=["explicit", "cwd"])
@pytest.mark.parametrize("action", _ACTIONS, ids=lambda a: a[0])
def test_the_user_rule_layer_never_makes_home_the_rule_workspace(home, monkeypatch, capsys, action, explicit):
    repo = _git_repo(home / "code" / "repo", initialized=False)
    (repo / "src").mkdir()
    monkeypatch.chdir(repo / "src")
    before = _tree(home)

    rc = main(["rule", *action, *(["--workspace", str(repo / "src")] if explicit else [])])

    captured = capsys.readouterr()
    said = _said(captured)
    assert "user-plane" not in said
    assert str(home / ".aegis") not in said
    assert _tree(home) == before
    if explicit or action[0] == "create":
        assert rc == 1 and _not_a_workspace((repo / "src").resolve()) in said
    elif action[0] == "list":
        assert rc == 0 and json.loads(captured.out) == []


@pytest.fixture
def enclosed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """$HOME inside a directory that is itself an Aegis workspace."""
    outer = tmp_path / "outer"
    _trap(outer, "outer-rule")
    home = outer / "home"
    (home / ".aegis").mkdir(parents=True)  # the user plane, with no rule layer
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    return home


@pytest.mark.parametrize("action", _ACTIONS[:4], ids=lambda a: a[0])
def test_an_explicit_workspace_never_walks_past_home(enclosed_home, elsewhere, capsys, action):
    notes = enclosed_home / "notes"  # no .git: only $HOME bounds the walk
    notes.mkdir()
    outer = enclosed_home.parent
    before = _tree(outer)

    rc = main(["rule", *action, "--workspace", str(notes)])

    captured = capsys.readouterr()
    assert rc == 1
    assert _not_a_workspace(notes.resolve()) in _said(captured)
    assert "outer-rule" not in _said(captured)
    assert _tree(outer) == before


# ── Lifecycle outcomes the CLI must not report as success ─────────────

def test_promote_into_a_protected_namespace_fails(repo, capsys) -> None:
    source = _trap(repo, "testing")

    rc = main(["rule", "promote", "testing"])

    assert rc == 1
    assert "Cannot promote a rule into the protected core rule namespace: 'testing'" in capsys.readouterr().out
    assert source.is_file()


def test_demote_with_an_invalid_rule_id_fails(repo, capsys) -> None:
    rc = main(["rule", "demote", "../escape", "--json"])

    assert rc == 1
    assert json.loads(capsys.readouterr().out) == {"error": "Invalid rule ID: '../escape'"}


# ── --body-file ────────────────────────────────────────────────────────

@pytest.fixture
def repo(home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = _git_repo(home / "code" / "repo", initialized=True)
    monkeypatch.chdir(repo)
    return repo


def _created(repo: Path, rule_id: str) -> Path:
    return repo / ".aegis" / "rules" / "traps" / f"{rule_id}.md"


def test_body_file_supplies_rule_body(repo, tmp_path, capsys) -> None:
    body_file = tmp_path / "body.md"
    body_file.write_text("## Detail\n\nUse argv lists, never shell strings.\n", encoding="utf-8")

    rc = main(["rule", "create", "--hypothesis", "No shell strings", "--id", "argv", "--body-file", str(body_file)])

    assert rc == 0, capsys.readouterr().err
    text = _created(repo, "argv").read_text(encoding="utf-8")
    assert (parse_frontmatter(text) or {})["hypothesis"] == "No shell strings"
    assert _get_body(text).strip() == "## Detail\n\nUse argv lists, never shell strings."


def test_body_file_dash_reads_stdin(repo, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO("Body from stdin ✓\n".encode("utf-8")), encoding="utf-8"))

    rc = main(["rule", "create", "--hypothesis", "Stdin body", "--id", "stdin-body", "--body-file", "-"])

    assert rc == 0, capsys.readouterr().err
    assert _get_body(_created(repo, "stdin-body").read_text(encoding="utf-8")).strip() == "Body from stdin ✓"


@pytest.mark.parametrize("content", [b"", b"  \n\n\t"], ids=["empty", "whitespace"])
def test_empty_body_file_is_rejected(repo, tmp_path, capsys, content: bytes) -> None:
    body_file = tmp_path / "empty.md"
    body_file.write_bytes(content)

    rc = main(["rule", "create", "--hypothesis", "Empty", "--id", "empty", "--body-file", str(body_file)])

    assert rc == 1
    assert f"Error: --body-file {body_file}: rule body is empty" in capsys.readouterr().err
    assert not _created(repo, "empty").exists()


def test_body_file_over_64_kib_is_rejected(repo, tmp_path, capsys) -> None:
    body_file = tmp_path / "huge.md"
    body_file.write_bytes(b"x" * (MAX_BODY + 1))

    rc = main(["rule", "create", "--hypothesis", "Huge", "--id", "huge", "--body-file", str(body_file)])

    assert rc == 1
    assert f"Error: --body-file {body_file}: rule body exceeds 64 KiB (65536 bytes)" in capsys.readouterr().err
    assert not _created(repo, "huge").exists()


def test_body_file_of_exactly_64_kib_is_accepted(repo, tmp_path, capsys) -> None:
    body_file = tmp_path / "max.md"
    body_file.write_bytes(b"y" * MAX_BODY)

    rc = main(["rule", "create", "--hypothesis", "Max", "--id", "max", "--body-file", str(body_file)])

    assert rc == 0, capsys.readouterr().err
    assert _created(repo, "max").is_file()


def test_stdin_body_over_64_kib_is_rejected(repo, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"z" * (MAX_BODY + 1)), encoding="utf-8"))

    rc = main(["rule", "create", "--hypothesis", "Huge stdin", "--id", "huge-stdin", "--body-file", "-"])

    assert rc == 1
    assert "Error: --body-file <stdin>: rule body exceeds 64 KiB (65536 bytes)" in capsys.readouterr().err
    assert not _created(repo, "huge-stdin").exists()


def test_missing_body_file_is_rejected(repo, tmp_path, capsys) -> None:
    missing = tmp_path / "nope.md"

    rc = main(["rule", "create", "--hypothesis", "Missing", "--id", "missing", "--body-file", str(missing)])

    assert rc == 1
    assert f"Error: --body-file {missing}: cannot read file (No such file or directory)" in capsys.readouterr().err
    assert not _created(repo, "missing").exists()


def test_non_utf8_body_file_is_rejected(repo, tmp_path, capsys) -> None:
    body_file = tmp_path / "latin1.md"
    body_file.write_bytes("caf\xe9\n".encode("latin-1"))

    rc = main(["rule", "create", "--hypothesis", "Latin1", "--id", "latin1", "--body-file", str(body_file)])

    assert rc == 1
    assert f"Error: --body-file {body_file}: rule body is not valid UTF-8" in capsys.readouterr().err
    assert not _created(repo, "latin1").exists()


# ── Ghost flag ─────────────────────────────────────────────────────────

def test_from_description_ghost_flag_is_removed(repo, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["rule", "create", "--from-description", "make me a rule"])

    assert exc.value.code == 2
    assert "unrecognized arguments: --from-description" in capsys.readouterr().err
    assert list((repo / ".aegis" / "rules").rglob("*.md")) == []


# ── v4 flag diet (D17): never-read flags are rejected, not silently ignored ──

@pytest.mark.parametrize(
    "flag",
    [
        ["--weight", "2.0"], ["-w", "2.0"],
        ["--expiry-sessions", "3"], ["--expiry-days", "9"],
        ["--minimum-mode", "sweep"], ["--effector"], ["--memory"],
    ],
    ids=lambda f: f[0],
)
def test_rule_create_rejects_cut_flags(repo, capsys, flag) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["rule", "create", "--hypothesis", "h", "--id", "cut-flag", *flag])

    assert exc.value.code == 2
    assert f"unrecognized arguments: {flag[0]}" in capsys.readouterr().err
    assert not _created(repo, "cut-flag").exists()


@pytest.mark.parametrize(
    "argv",
    [
        ["promote", "--rule", "x"], ["demote", "--rule", "x"],
        ["promote", "x", "--force"], ["demote", "x", "--force"],
        ["promote", "x", "--reason", "why"], ["demote", "x", "--reason", "why"],
        ["archive", "--apply"], ["archive", "some-rule"],
    ],
    ids=lambda a: "-".join(a),
)
def test_lifecycle_actions_reject_cut_arguments(repo, capsys, argv) -> None:
    """promote/demote take the rule only as a positional; archive has no --apply or rule id."""
    with pytest.raises(SystemExit) as exc:
        main(["rule", *argv])

    assert exc.value.code == 2
    assert "error:" in capsys.readouterr().err


def _extinct(repo: Path, rule_id: str) -> Path:
    """A rule the ledger says misfires: three false positives and no true positive."""
    from aegis_core.telemetry_engine import ledger

    path = repo / ".aegis" / "rules" / "traps" / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\nid: {rule_id}\ntype: trap\nhypothesis: h\n---\nBody\n", encoding="utf-8")
    # MIN_N (25) false positives: no archive below the one sample gate (R-evidence-8)
    ledger.append(repo, [{"rule": rule_id, "outcome": "fp", "source": "ci", "key": f"run-{n}"} for n in range(25)])
    return path


def test_rule_archive_dry_run_moves_nothing(repo) -> None:
    rule = _extinct(repo, "extinct-trap")

    assert main(["rule", "archive", "--dry-run"]) == 0

    assert rule.is_file()
    assert not (repo / ".aegis" / "rules" / ".archive" / "extinct-trap.md").exists()


def test_rule_archive_applies_by_default(repo) -> None:
    rule = _extinct(repo, "extinct-trap")

    assert main(["rule", "archive"]) == 0

    assert not rule.exists()
    assert (repo / ".aegis" / "rules" / ".archive" / "extinct-trap.md").is_file()


def test_rule_clean_points_at_manual_cleanup(repo, capsys) -> None:
    assert main(["rule", "clean", "--apply"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "aegis rule clean was removed in v4: no replacement; "
        "remove leaked global rule copies by hand\n"
    )


# ── Rules that would never apply ─────────────────────────────────────────

_UNSCOPED = (
    "Warning: rule 'unscoped' has no target_paths, so it matches no file: aegis scan never "
    "shows it and aegis check records nothing for it. Pass --target-paths (for example 'src/**/*.py')."
)


def test_create_without_target_paths_warns_that_the_rule_matches_no_file(repo, capsys) -> None:
    rc = main(["rule", "create", "--hypothesis", "Scope me", "--id", "unscoped"])

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.err.strip() == _UNSCOPED
    assert _created(repo, "unscoped").is_file()


def test_create_json_lists_the_warning(repo, capsys) -> None:
    rc = main(["rule", "create", "--hypothesis", "Scope me", "--id", "unscoped", "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "created" and payload["id"] == "unscoped"
    assert payload["warnings"] == [_UNSCOPED[len("Warning: "):]]


def test_create_with_target_paths_does_not_warn(repo, capsys) -> None:
    rc = main(["rule", "create", "--hypothesis", "Scoped", "--id", "scoped", "--target-paths", "src/*.py", "--json"])

    assert rc == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["warnings"] == [] and captured.err == ""


@pytest.mark.parametrize("rule_id", ["readme", "README", "ReadMe", ".hidden"])
def test_create_rejects_an_id_the_loader_would_never_serve(repo, capsys, rule_id: str) -> None:
    rc = main(["rule", "create", "--hypothesis", "h", "--id", rule_id, "--target-paths", "src/*.py"])

    assert rc == 1
    assert f"Error: Invalid rule id {rule_id!r}: " in capsys.readouterr().err
    assert list((repo / ".aegis" / "rules").rglob("*.md")) == []
