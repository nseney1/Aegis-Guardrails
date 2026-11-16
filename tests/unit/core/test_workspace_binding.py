"""The AD-4 workspace binding resolver (host-matrix §3.6): pin, host-attested roots,
the registry, a bounded walk-up; never $HOME, never the filesystem root, never above
the git toplevel, and a HOLD with a machine-readable reason when sources disagree.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from tests.conftest import symlink_or_skip

from aegis_core.errors import WorkspaceNotFoundError
from aegis_core.workspace.binding import (
    Attested,
    WorkspaceHold,
    bounded_walk_up,
    git_boundary,
    read_registry,
    resolve_binding,
    resolve_cli_root,
)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".aegis" / "rules").mkdir(parents=True)  # what v3.3 auto-created
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home.resolve()


def _governed(path: Path) -> Path:
    (path / ".aegis" / "rules").mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _git_marker(path: Path) -> Path:
    (path / ".git").mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _registry(home: Path, roots, v=1) -> Path:
    path = home / ".aegis" / "workspaces.json"
    entries = [{"root": str(r), "added_at": "2026-10-15T00:00:00Z", "added_by": "aegis init", "hosts": []}
               for r in roots]
    path.write_text(json.dumps({"v": v, "workspaces": entries}), encoding="utf-8")
    return path


# ── bounded walk-up ──────────────────────────────────────────────────────────

def test_walk_up_finds_the_workspace_from_a_subdirectory(home, tmp_path):
    root = _governed(tmp_path / "repo")
    (root / "src" / "pkg").mkdir(parents=True)
    assert bounded_walk_up(root / "src" / "pkg") == root


def test_walk_up_never_crosses_the_git_marker(home, tmp_path):
    _governed(tmp_path / "outer")
    inner = _git_marker(tmp_path / "outer" / "inner")
    (inner / "src").mkdir()
    assert bounded_walk_up(inner / "src") is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_walk_up_never_crosses_a_real_git_toplevel(home, tmp_path):
    _governed(tmp_path / "outer")
    inner = tmp_path / "outer" / "inner"
    inner.mkdir()
    subprocess.run(["git", "init", "-q", str(inner)], check=True, capture_output=True)
    (inner / "src").mkdir()
    assert bounded_walk_up(inner / "src") is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_a_work_tree_moved_off_the_path_by_core_worktree_never_bounds_it(home, tmp_path):
    # A repository's config is attacker-controlled: git's toplevel can name a directory
    # that is not on the start's path, where a walk up could never stop.
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    elsewhere = tmp_path / "a" / "b" / "c" / "d"
    elsewhere.mkdir(parents=True)
    subprocess.run(["git", "-C", str(repo), "config", "core.worktree", str(elsewhere)], check=True, capture_output=True)
    (repo / "src").mkdir()
    assert git_boundary((repo / "src").resolve()) == repo.resolve()


def test_walk_up_never_selects_home_even_with_v33_user_rules(home):
    project = home / "code" / "project"
    project.mkdir(parents=True)
    assert bounded_walk_up(project) is None
    assert bounded_walk_up(home) is None


def test_walk_up_never_goes_above_home(home, tmp_path):
    _governed(tmp_path)  # tmp_path contains home: a workspace above $HOME is never chosen
    project = home / "project"
    project.mkdir()
    assert bounded_walk_up(project) is None


# ── 1. operator pin ──────────────────────────────────────────────────────────

def test_a_valid_pin_binds_with_operator_confidence(home, tmp_path):
    root = _governed(tmp_path / "repo")
    binding = resolve_binding(pin=str(root))
    assert (binding.status, binding.root, binding.source, binding.confidence) == ("bound", root, "pin", "operator")


@pytest.mark.parametrize("case,reason", [
    ("missing", "pin_missing"),
    ("plain", "pin_not_a_workspace"),
    ("home", "pin_denied"),
])
def test_an_invalid_pin_is_an_error_never_a_fallback(home, tmp_path, case, reason):
    plain = tmp_path / "plain"
    plain.mkdir()
    _governed(tmp_path / "cwd")
    pin = {"missing": tmp_path / "nope", "plain": plain, "home": home}[case]
    binding = resolve_binding(pin=str(pin), cwd=tmp_path / "cwd")
    assert (binding.status, binding.reason, binding.root) == ("error", reason, None)
    assert str(pin) in binding.message


def test_pin_and_a_disagreeing_host_root_hold(home, tmp_path):
    pin = _governed(tmp_path / "a")
    other = _governed(tmp_path / "b")
    binding = resolve_binding(pin=str(pin), attested=[Attested("claude_project_dir", str(other))])
    assert (binding.status, binding.reason) == ("hold", "pin_conflicts_with_host_root")
    assert binding.as_dict()["details"] == {"pin": str(pin), "host_roots": [str(other)]}


def test_pin_agrees_with_a_host_root_inside_it(home, tmp_path):
    pin = _governed(tmp_path / "repo")
    (pin / "pkg").mkdir()
    binding = resolve_binding(pin=str(pin), attested=[Attested("claude_project_dir", str(pin / "pkg"))])
    assert (binding.status, binding.root, binding.source) == ("bound", pin, "pin")


def test_pin_holds_when_the_files_belong_to_another_registered_workspace(home, tmp_path):
    pin = _governed(tmp_path / "a")
    other = _governed(tmp_path / "b")
    binding = resolve_binding(pin=str(pin), files=[str(other / "x.py")], registry=read_registry(_registry(home, [pin, other])))
    assert (binding.status, binding.reason) == ("hold", "pin_conflicts_with_registry")
    assert binding.as_dict()["details"]["registered_root"] == str(other)


# ── 2. host-attested roots ───────────────────────────────────────────────────

def test_a_codex_workspace_binds_as_host_attested(home, tmp_path):
    root = _governed(tmp_path / "repo")
    binding = resolve_binding(attested=[Attested("codex_meta", str(root))], cwd=tmp_path)
    assert (binding.status, binding.root, binding.source, binding.confidence) == (
        "bound", root, "codex_meta", "host_attested")


def test_a_host_root_in_a_monorepo_subdirectory_binds_to_the_governed_toplevel(home, tmp_path):
    root = _governed(_git_marker(tmp_path / "mono"))
    (root / "services" / "api").mkdir(parents=True)
    binding = resolve_binding(attested=[Attested("mcp_roots", str(root / "services" / "api"))])
    assert (binding.status, binding.root) == ("bound", root)


def test_several_host_roots_are_chosen_by_the_calls_files(home, tmp_path):
    a = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    (b / "src").mkdir()
    (b / "src" / "x.py").write_text("x\n", encoding="utf-8")
    roots = [Attested("mcp_roots", str(a)), Attested("mcp_roots", str(b))]
    assert resolve_binding(attested=roots, files=[str(b / "src" / "y.py")]).root == b
    assert resolve_binding(attested=roots, files=["src/x.py"]).root == b


@pytest.mark.parametrize("files", [None, [], ["nowhere.py"]])
def test_several_host_roots_without_deciding_files_hold(home, tmp_path, files):
    a = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    binding = resolve_binding(attested=[Attested("mcp_roots", str(a)), Attested("mcp_roots", str(b))], files=files)
    assert (binding.status, binding.reason) == ("hold", "ambiguous_host_roots")
    assert binding.as_dict()["details"]["candidates"] == [str(a), str(b)]


def test_ungoverned_host_roots_are_not_governed_and_skip_the_cwd(home, tmp_path):
    plain = _git_marker(tmp_path / "plain")
    cwd = _governed(tmp_path / "elsewhere")
    binding = resolve_binding(attested=[Attested("codex_meta", str(plain))], cwd=cwd)
    assert (binding.status, binding.reason, binding.root) == ("unbound", "host_roots_not_governed", None)


def test_ungoverned_host_root_and_files_in_a_registered_workspace_hold(home, tmp_path):
    plain = _git_marker(tmp_path / "plain")
    other = _governed(tmp_path / "b")
    binding = resolve_binding(
        attested=[Attested("codex_meta", str(plain))], files=[str(other / "x.py")],
        registry=read_registry(_registry(home, [other])),
    )
    assert (binding.status, binding.reason) == ("hold", "host_root_conflicts_with_registry")


def test_a_host_root_at_home_is_never_a_candidate(home):
    binding = resolve_binding(attested=[Attested("mcp_roots", str(home))])
    assert (binding.status, binding.reason) == ("unbound", "host_roots_not_governed")


# ── 3. registry ──────────────────────────────────────────────────────────────

def test_absolute_files_select_a_registered_workspace(home, tmp_path):
    a = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    binding = resolve_binding(files=[str(b / "new.py")], registry=read_registry(_registry(home, [a, b])), cwd=home)
    assert (binding.status, binding.root, binding.source, binding.confidence) == ("bound", b, "registry", "registered")


def test_relative_files_select_the_one_registered_workspace_holding_them(home, tmp_path):
    a = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    (b / "only_in_b.py").write_text("x\n", encoding="utf-8")
    binding = resolve_binding(files=["only_in_b.py"], registry=read_registry(_registry(home, [a, b])), cwd=home)
    assert (binding.status, binding.root) == ("bound", b)


def test_files_cannot_introduce_an_unregistered_workspace(home, tmp_path):
    a = _governed(tmp_path / "a")
    stray = _governed(tmp_path / "stray")
    binding = resolve_binding(files=[str(stray / "x.py")], registry=read_registry(_registry(home, [a])), cwd=home)
    assert (binding.status, binding.root) == ("unbound", None)


def test_no_files_never_pick_a_registered_workspace(home, tmp_path):
    a = _governed(tmp_path / "a")
    binding = resolve_binding(files=None, registry=read_registry(_registry(home, [a])), cwd=home)
    assert (binding.status, binding.reason) == ("unbound", "no_workspace")


def test_files_in_two_registered_workspaces_hold(home, tmp_path):
    a = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    for root in (a, b):
        (root / "same.py").write_text("x\n", encoding="utf-8")
    binding = resolve_binding(files=["same.py"], registry=read_registry(_registry(home, [a, b])), cwd=home)
    assert (binding.status, binding.reason) == ("hold", "ambiguous_registry_selection")


def test_a_registered_root_without_aegis_or_at_home_is_ignored(home, tmp_path):
    gone = tmp_path / "gone"
    gone.mkdir()
    registry = read_registry(_registry(home, [gone, home]))
    binding = resolve_binding(files=[str(gone / "x.py"), str(home / "y.py")], registry=registry, cwd=home)
    assert binding.status == "unbound"


def test_relative_files_held_by_the_cwd_workspace_bind_it_over_another_registered_one(home, tmp_path):
    """A clone with a committed .aegis/ that was never registered: README.md in it is its own, not B's."""
    cwd_ws = _governed(tmp_path / "clone")
    b = _governed(tmp_path / "b")
    for root in (cwd_ws, b):
        (root / "README.md").write_text("x\n", encoding="utf-8")
    binding = resolve_binding(files=["README.md"], registry=read_registry(_registry(home, [b])), cwd=cwd_ws)
    assert (binding.status, binding.root, binding.source) == ("bound", cwd_ws, "walk_up")


def test_relative_files_in_two_registered_workspaces_follow_the_cwd(home, tmp_path):
    a = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    for root in (a, b):
        (root / "src").mkdir()
        (root / "src" / "x.py").write_text("x\n", encoding="utf-8")
    binding = resolve_binding(files=["src/x.py"], registry=read_registry(_registry(home, [a, b])), cwd=a / "src")
    assert (binding.status, binding.root, binding.source) == ("bound", a, "registry")


def test_relative_files_only_in_another_registered_workspace_hold_against_the_cwd(home, tmp_path):
    cwd_ws = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    (b / "only_in_b.py").write_text("x\n", encoding="utf-8")
    binding = resolve_binding(files=["only_in_b.py"], registry=read_registry(_registry(home, [cwd_ws, b])), cwd=cwd_ws)
    assert (binding.status, binding.root, binding.reason) == ("hold", None, "cwd_conflicts_with_registry")
    assert binding.as_dict()["details"] == {"cwd_root": str(cwd_ws), "candidates": [str(b)]}


def test_absolute_files_still_select_a_registered_workspace_from_a_governed_cwd(home, tmp_path):
    cwd_ws = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    binding = resolve_binding(files=[str(b / "new.py")], registry=read_registry(_registry(home, [b])), cwd=cwd_ws)
    assert (binding.status, binding.root, binding.source) == ("bound", b, "registry")


@pytest.mark.parametrize("files", [["proj/app.py"], ["{home}/proj/app.py"]], ids=["relative", "absolute"])
def test_a_registry_listing_home_and_the_filesystem_root_never_binds_them(home, files):
    """$HOME holds .aegis/ (the user layer) and every file under it; the denylist alone keeps it out."""
    (home / "proj").mkdir()
    (home / "proj" / "app.py").write_text("x\n", encoding="utf-8")
    registry = read_registry(_registry(home, [home, Path(home.anchor)]))
    assert registry.roots == (home, Path(home.anchor))

    binding = resolve_binding(files=[f.format(home=home) for f in files], registry=registry)

    assert (binding.status, binding.root, binding.reason) == ("unbound", None, "no_workspace")


@pytest.mark.parametrize("content,problem", [
    ("{not json", "not valid JSON"),
    ('{"v": 2, "workspaces": []}', "unsupported registry version 2"),
    ('{"v": 1, "workspaces": {}}', "'workspaces' must be a list"),
    ("[1, 2]", "must be a JSON object"),
])
def test_a_malformed_registry_reads_as_empty_with_a_problem(home, content, problem):
    path = home / ".aegis" / "workspaces.json"
    path.write_text(content, encoding="utf-8")
    registry = read_registry(path)
    assert registry.roots == ()
    assert any(problem in p for p in registry.problems), registry.problems


def test_registry_entries_must_be_absolute_roots(home, tmp_path):
    a = _governed(tmp_path / "a")
    path = home / ".aegis" / "workspaces.json"
    path.write_text(json.dumps({"v": 1, "workspaces": [{"root": "relative/dir"}, {"nope": 1}, {"root": str(a)}]}),
                    encoding="utf-8")
    registry = read_registry(path)
    assert registry.roots == (a,)
    assert len(registry.problems) == 2


def test_a_missing_registry_is_empty_and_nothing_is_created(home):
    before = sorted(p.name for p in (home / ".aegis").iterdir())
    registry = read_registry()
    assert (registry.roots, registry.problems) == ((), ())
    assert sorted(p.name for p in (home / ".aegis").iterdir()) == before


# ── 4. walk-up from the server cwd, 5. nothing ───────────────────────────────

def test_the_cwd_walk_up_binds_as_inferred(home, tmp_path):
    root = _governed(tmp_path / "repo")
    (root / "src").mkdir()
    binding = resolve_binding(cwd=root / "src")
    assert (binding.status, binding.root, binding.source, binding.confidence) == ("bound", root, "walk_up", "inferred")


@pytest.mark.parametrize("cwd", ["home", "root", None])
def test_nothing_resolves_to_unbound(home, cwd):
    where = {"home": home, "root": Path(home.anchor), None: None}[cwd]
    binding = resolve_binding(cwd=where)
    assert (binding.status, binding.root, binding.reason) == ("unbound", None, "no_workspace")


def test_binding_as_dict_is_json_ready(home, tmp_path):
    root = _governed(tmp_path / "repo")
    data = resolve_binding(pin=str(root)).as_dict()
    assert json.loads(json.dumps(data)) == {
        "status": "bound", "root": str(root), "source": "pin", "confidence": "operator",
        "reason": None, "message": "", "details": {},
    }


# ── the CLI's global --workspace (wave A deferral) ───────────────────────────

def test_cli_explicit_target_walks_up_within_its_git_toplevel(home, tmp_path):
    root = _governed(_git_marker(tmp_path / "repo"))
    (root / "src").mkdir()
    assert resolve_cli_root(explicit=str(root / "src"), cwd=tmp_path) == root


def test_cli_explicit_target_never_resolves_above_its_git_toplevel(home, tmp_path):
    _governed(tmp_path / "outer")
    inner = _git_marker(tmp_path / "outer" / "inner")
    assert resolve_cli_root(explicit=str(inner), cwd=tmp_path) == inner


def test_cli_relative_explicit_target_is_relative_to_the_cwd(home, tmp_path):
    root = _governed(tmp_path / "repo")
    assert resolve_cli_root(explicit="repo", cwd=tmp_path) == root


@pytest.mark.parametrize("explicit", [True, False])
def test_cli_home_is_never_a_workspace(home, explicit):
    with pytest.raises(WorkspaceNotFoundError) as exc:
        resolve_cli_root(explicit=str(home) if explicit else None, cwd=home)
    assert str(exc.value) == (
        f"not an Aegis workspace ({home} is the home directory; ~/.aegis is the user rule layer); "
        "run aegis init in a project"
    )


def test_cli_pin_wins_when_the_cwd_is_in_no_workspace_or_repository(home, tmp_path):
    pin = _governed(tmp_path / "pinned")
    cwd = tmp_path / "scratch"
    cwd.mkdir()
    assert resolve_cli_root(cwd=cwd, pin=str(pin)) == pin


def test_cli_pin_agrees_with_a_cwd_inside_the_pinned_workspace(home, tmp_path):
    pin = _governed(_git_marker(tmp_path / "pinned"))
    (pin / "src" / "deep").mkdir(parents=True)
    assert resolve_cli_root(cwd=pin / "src" / "deep", pin=str(pin)) == pin


def test_cli_pin_agrees_with_the_repository_that_holds_it(home, tmp_path):
    """A monorepo: the pinned workspace lies in the cwd's repository, which has no .aegis/."""
    repo = _git_marker(tmp_path / "mono")
    pin = _governed(repo / "packages" / "app")
    (repo / "tools").mkdir()
    assert resolve_cli_root(cwd=repo / "tools", pin=str(pin)) == pin


def test_cli_pin_and_a_cwd_in_another_workspace_hold(home, tmp_path):
    """The git hook runs in the repository being committed: a pin elsewhere must not
    make it check another repository."""
    pin = _governed(_git_marker(tmp_path / "pinned"))
    other = _governed(_git_marker(tmp_path / "other"))
    (other / "src").mkdir()
    with pytest.raises(WorkspaceHold) as exc:
        resolve_cli_root(cwd=other / "src", pin=str(pin))
    binding = exc.value.binding.as_dict()
    assert (binding["status"], binding["reason"]) == ("hold", "pin_conflicts_with_cwd")
    assert binding["details"] == {"pin": str(pin), "cwd": str(other / "src"), "cwd_root": str(other)}
    assert "AEGIS_WORKSPACE" in binding["message"]


def test_cli_pin_and_a_cwd_in_another_ungoverned_repository_hold(home, tmp_path):
    pin = _governed(_git_marker(tmp_path / "pinned"))
    other = _git_marker(tmp_path / "plain-repo")
    with pytest.raises(WorkspaceHold) as exc:
        resolve_cli_root(cwd=other, pin=str(pin))
    assert exc.value.binding.reason == "pin_conflicts_with_cwd"
    assert exc.value.binding.as_dict()["details"]["cwd_root"] == str(other)


def test_cli_pin_wins_from_home_even_when_home_is_a_repository(home, tmp_path):
    _git_marker(home)  # a dotfiles repository: home is never a workspace, so never a conflict
    pin = _governed(tmp_path / "pinned")
    assert resolve_cli_root(cwd=home, pin=str(pin)) == pin


def test_cli_a_pin_that_is_not_a_workspace_is_an_error(home, tmp_path):
    pin = tmp_path / "plain"
    pin.mkdir()
    with pytest.raises(WorkspaceNotFoundError) as exc:
        resolve_cli_root(cwd=pin, pin=str(pin))
    assert str(exc.value) == f"AEGIS_WORKSPACE is set to {pin}, which has no .aegis/ (run aegis init there)"


def test_cli_a_pin_the_command_accepts_need_not_hold_aegis(home, tmp_path):
    """aegis migrate accepts a legacy workspace (accept), at the pin too."""
    pin = tmp_path / "legacy"
    (pin / ".old").mkdir(parents=True)
    accept = lambda d: (d / ".old").is_dir() or (d / ".aegis").is_dir()  # noqa: E731
    assert resolve_cli_root(cwd=pin, pin=str(pin), accept=accept) == pin.resolve()


def test_cli_pin_and_explicit_target_that_agree_bind(home, tmp_path):
    pin = _governed(tmp_path / "pinned")
    (pin / "src").mkdir()
    assert resolve_cli_root(explicit=str(pin / "src"), cwd=tmp_path, pin=str(pin)) == pin


def test_cli_pin_and_a_different_explicit_target_hold(home, tmp_path):
    pin = _governed(tmp_path / "pinned")
    target = _governed(tmp_path / "target")
    with pytest.raises(WorkspaceHold) as exc:
        resolve_cli_root(explicit=str(target), cwd=tmp_path, pin=str(pin))
    assert exc.value.binding.as_dict()["status"] == "hold"
    assert exc.value.binding.reason == "pin_conflicts_with_target"
    assert exc.value.binding.as_dict()["details"] == {"pin": str(pin), "target": str(target)}


@pytest.mark.parametrize("case", ["missing", "home"])
def test_cli_an_unusable_pin_is_an_error(home, tmp_path, case):
    pin = {"missing": tmp_path / "nope", "home": home}[case]
    with pytest.raises(WorkspaceNotFoundError) as exc:
        resolve_cli_root(cwd=tmp_path, pin=str(pin))
    assert f"AEGIS_WORKSPACE is set to {pin}" in str(exc.value)


def test_cli_uninitialized_directory_resolves_to_itself(home, tmp_path):
    plain = _git_marker(tmp_path / "plain")
    assert resolve_cli_root(cwd=plain) == plain


@pytest.mark.skipif(os.name == "nt", reason="POSIX filesystem root")
def test_cli_filesystem_root_is_never_a_workspace(home):
    with pytest.raises(WorkspaceNotFoundError):
        resolve_cli_root(explicit="/", cwd=home)


def test_a_host_root_enclosing_the_pin_agrees(home, tmp_path):
    pin = _governed(tmp_path / "code" / "repo")
    binding = resolve_binding(pin=str(pin), attested=[Attested("mcp_roots", str(tmp_path / "code"))])
    assert (binding.status, binding.root) == ("bound", pin)


# ── Workspace.resolve (every CLI command's own re-resolution) uses the same walk ──

def test_workspace_resolve_never_walks_out_of_a_nested_repository(home, tmp_path, monkeypatch):
    from aegis_core.workspace.base import Workspace

    _governed(tmp_path / "outer")
    inner = _git_marker(tmp_path / "outer" / "inner")
    (inner / "src").mkdir()
    assert Workspace.resolve(inner).root == inner
    assert Workspace.resolve(inner / "src").root == inner / "src"
    monkeypatch.chdir(inner / "src")
    assert Workspace.resolve().root == inner / "src"


def test_workspace_resolve_never_selects_home(home, monkeypatch):
    from aegis_core.workspace.base import Workspace

    project = home / "code" / "project"
    project.mkdir(parents=True)
    assert Workspace.resolve(project).root == project
    monkeypatch.chdir(project)
    assert Workspace.resolve().root == project


def test_workspace_resolve_still_walks_up_inside_one_repository(home, tmp_path, monkeypatch):
    from aegis_core.workspace.base import Workspace

    root = _governed(_git_marker(tmp_path / "repo"))
    (root / "a" / "b").mkdir(parents=True)
    assert Workspace.resolve(root / "a" / "b").root == root
    monkeypatch.chdir(root / "a")
    assert Workspace.resolve().root == root


def test_without_deciding_files_the_highest_precedence_host_source_wins(home, tmp_path):
    project = _governed(tmp_path / "project")
    added = _governed(tmp_path / "added")
    attested = [Attested("claude_project_dir", str(project)), Attested("mcp_roots", str(project)),
                Attested("mcp_roots", str(added))]
    assert resolve_binding(attested=attested).root == project
    assert resolve_binding(attested=attested, files=[str(added / "x.py")]).root == added


def test_a_chosen_host_root_holds_when_the_files_belong_to_another_registered_workspace(home, tmp_path):
    host = _governed(tmp_path / "a")
    other = _governed(tmp_path / "b")
    binding = resolve_binding(
        attested=[Attested("codex_meta", str(host))], files=[str(other / "x.py")],
        registry=read_registry(_registry(home, [host, other])),
    )
    assert (binding.status, binding.reason) == ("hold", "host_root_conflicts_with_registry")
    assert binding.as_dict()["details"] == {"host_root": str(host), "registered_root": str(other)}


# ── unresolvable paths: a symlink loop (RuntimeError before Python 3.13) or a NUL
#    byte (ValueError) is "cannot be resolved", never an exception ─────────────────

def _loop(where: Path) -> Path:
    """``where/l1 -> where/l2 -> where/l1``; skipped where symlinks cannot be made."""
    where.mkdir(parents=True, exist_ok=True)
    first, second = where / "l1", where / "l2"
    try:
        os.symlink(second, first)
        os.symlink(first, second)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    return first


def _unresolvable(tmp_path: Path, kind: str) -> str:
    return str(_loop(tmp_path / "links")) if kind == "loop" else str(tmp_path / "nul\0byte")


@pytest.mark.parametrize("kind", ["loop", "nul"])
def test_an_unresolvable_pin_is_the_pin_missing_error(home, tmp_path, kind):
    _governed(tmp_path / "cwd")
    binding = resolve_binding(pin=_unresolvable(tmp_path, kind), cwd=tmp_path / "cwd")
    assert (binding.status, binding.reason, binding.source, binding.root) == ("error", "pin_missing", "pin", None)


@pytest.mark.parametrize("kind", ["loop", "nul"])
def test_an_unresolvable_cwd_is_unbound(home, tmp_path, kind):
    binding = resolve_binding(cwd=_unresolvable(tmp_path, kind))
    assert (binding.status, binding.reason) == ("unbound", "no_workspace")


@pytest.mark.parametrize("kind", ["loop", "nul"])
def test_an_unresolvable_host_root_is_not_governed(home, tmp_path, kind):
    binding = resolve_binding(attested=[Attested("codex_meta", _unresolvable(tmp_path, kind))], cwd=tmp_path)
    assert (binding.status, binding.reason) == ("unbound", "host_roots_not_governed")


@pytest.mark.parametrize("kind", ["loop", "nul"])
def test_an_unresolvable_host_root_disagrees_with_the_pin(home, tmp_path, kind):
    pin = _governed(tmp_path / "a")
    binding = resolve_binding(pin=str(pin), attested=[Attested("codex_meta", _unresolvable(tmp_path, kind))])
    assert (binding.status, binding.reason) == ("hold", "pin_conflicts_with_host_root")
    assert len(binding.as_dict()["details"]["host_roots"]) == 1


@pytest.mark.parametrize("kind", ["loop", "nul"])
def test_an_unresolvable_host_root_with_files_in_a_registered_workspace_holds(home, tmp_path, kind):
    other = _governed(tmp_path / "b")
    binding = resolve_binding(
        attested=[Attested("codex_meta", _unresolvable(tmp_path, kind))], files=[str(other / "x.py")],
        registry=read_registry(_registry(home, [other])),
    )
    assert (binding.status, binding.reason) == ("hold", "host_root_conflicts_with_registry")


def test_call_files_through_a_symlink_loop_never_raise(home, tmp_path):
    a = _governed(tmp_path / "a")
    b = _governed(tmp_path / "b")
    _loop(a)
    registry = read_registry(_registry(home, [a]))
    for files in (["l1/x.py"], [str(a / "l1" / "x.py")], ["nul\0.py"], [str(a / "nul\0.py")]):
        unbound = resolve_binding(files=files, registry=registry, cwd=home)
        assert unbound.status in ("unbound", "bound") and unbound.root in (None, a), files
        both = resolve_binding(attested=[Attested("mcp_roots", str(a)), Attested("mcp_roots", str(b))], files=files)
        assert both.status in ("hold", "bound") and both.root in (None, a), files


@pytest.mark.parametrize("kind", ["loop", "nul"])
def test_a_registry_root_that_cannot_be_resolved_is_skipped(home, tmp_path, kind):
    a = _governed(tmp_path / "a")
    registry = read_registry(_registry(home, [_unresolvable(tmp_path, kind), a]))
    assert registry.roots[-1] == a


def test_cli_a_target_through_a_symlink_loop_is_a_workspace_error_or_itself(home, tmp_path):
    loop = _loop(tmp_path / "links")
    try:
        root = resolve_cli_root(explicit=str(loop), cwd=tmp_path)
    except WorkspaceNotFoundError as exc:
        assert "cannot be resolved" in str(exc)
    else:  # Python 3.13+ resolves a loop leniently: the target names itself
        assert not (root / ".aegis").is_dir()


# Contract before WORKSPACE-DIAGNOSTIC-CORE: compare actual resolver sentences to
# adapter output, rather than copying a third set of sentence templates here.
_MCP_WORDING_REASONS = {
    "pin_conflicts_with_host_root": "pin_conflicts_with_host_root",
    "pin_conflicts_with_registry": "pin_conflicts_with_registry",
    "host_root_conflicts_with_registry": "host_root_conflicts_with_registry",
    "host_root_conflicts_with_registry_outside": "host_root_conflicts_with_registry",
    "ambiguous_host_roots": "ambiguous_host_roots",
    "cwd_conflicts_with_registry": "cwd_conflicts_with_registry",
    "ambiguous_registry_selection": "ambiguous_registry_selection",
    "host_roots_not_governed": "host_roots_not_governed",
    "no_workspace": "no_workspace",
    "pin_missing": "pin_missing",
    "pin_missing_directory": "pin_missing",
    "pin_not_a_workspace": "pin_not_a_workspace",
    "pin_denied": "pin_denied",
    "pin_denied_root": "pin_denied",
}
_CLI_HOLD_REASONS = {"pin_conflicts_with_target", "pin_conflicts_with_cwd"}


@pytest.fixture
def wording_paths(home, tmp_path):
    a = _governed(_git_marker(tmp_path / "a"))
    b = _governed(_git_marker(tmp_path / "b"))
    plain = _git_marker(tmp_path / "plain")
    for root in (a, b):
        (root / "shared.py").write_text("", encoding="ascii")
    # Ordinary temp files suffice except for the guarded resolution-error cases.
    _registry(home, [a, b])
    return a, b, plain


def _wording_resolution_path(where):
    loop = where / "unresolvable"
    symlink_or_skip(loop, loop)
    try:
        loop.resolve()
    except (OSError, RuntimeError):
        return loop
    pytest.skip("non-strict path resolution does not reject symlink loops")


def _mcp_wording_inputs(case, home, paths):
    a, b, plain = paths
    host = lambda *roots: [Attested("mcp_roots", str(root)) for root in roots]
    cases = {
        "pin_conflicts_with_host_root": {"pin": str(a), "attested": host(b, plain)},
        "pin_conflicts_with_registry": {"pin": str(a), "files": [str(b / "new.py")]},
        "host_root_conflicts_with_registry": {"attested": host(a), "files": [str(b / "new.py")]},
        "host_root_conflicts_with_registry_outside": {"attested": host(plain), "files": [str(b / "new.py")]},
        "ambiguous_host_roots": {"attested": host(a, b)},
        "cwd_conflicts_with_registry": {"cwd": plain, "files": ["shared.py"]},
        "ambiguous_registry_selection": {"files": ["shared.py"]},
        "host_roots_not_governed": {"attested": host(plain)},
        "no_workspace": {},
        "pin_missing": {"pin": str(plain / "unresolvable")},
        "pin_missing_directory": {"pin": str(a / "shared.py")},
        "pin_not_a_workspace": {"pin": str(plain)},
        "pin_denied": {"pin": str(home)},
        "pin_denied_root": {"pin": home.anchor},
    }
    # The cwd must be governed but lack shared.py, while both registered roots
    # contain it. This also checks the comma-separated candidates sentence.
    if case == "cwd_conflicts_with_registry":
        _governed(plain)
    inputs = {"cwd": home, "registry": read_registry(), **cases[case]}
    if case == "pin_missing":
        inputs["pin"] = str(_wording_resolution_path(plain))
    return inputs


def _wording_environment(pin):
    env = dict(os.environ)
    env.pop("AEGIS_WORKSPACE", None)
    env.pop("AEGIS_MANAGER_CONFIG", None)
    env.pop("AEGIS_MANAGER_CONFIG_SHA256", None)
    if pin:
        env["AEGIS_WORKSPACE"] = pin
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[3])
    return env


@pytest.mark.parametrize("case", _MCP_WORDING_REASONS)
def test_mcp_binding_wording_equals_resolver(home, wording_paths, case):
    inputs = _mcp_wording_inputs(case, home, wording_paths)
    canonical = resolve_binding(**inputs)
    assert canonical.reason == _MCP_WORDING_REASONS[case]
    frames = [{"jsonrpc": "2.0", "id": 0, "method": "initialize",
               "params": {"clientInfo": {"name": "codex-mcp-client", "version": "1"}}}]
    roots = {item.path: {} for item in inputs.get("attested", ())}
    for req_id in (1, 2):  # A retry must retain both the reason and full wording.
        frames.append({
            "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": "aegis_list_rules", "arguments": {"files": inputs.get("files", [])},
                       "_meta": {"x-codex-turn-metadata": {"workspaces": roots}}},
        })
    run = subprocess.run(
        [sys.executable, "-m", "aegis_mcp"], cwd=inputs["cwd"], env=_wording_environment(inputs.get("pin")),
        input="".join(json.dumps(frame) + "\n" for frame in frames),
        text=True, capture_output=True, timeout=15,
    )
    assert run.returncode == 0, run.stderr
    responses = {frame["id"]: frame for frame in map(json.loads, run.stdout.splitlines()) if "id" in frame}
    for req_id in (1, 2):
        response = responses[req_id]
        result = response["result"]
        assert result["isError"] is True
        payload = json.loads(result["content"][0]["text"])
        assert payload["binding"]["reason"] == canonical.reason
        assert payload["binding"]["message"] == canonical.message, case
        assert payload["binding"]["message"] != "workspace binding refused", case
        if canonical.status != "unbound":
            assert payload["error"] == canonical.message, case


@pytest.mark.parametrize("json_mode", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("case", [
    "pin_conflicts_with_target", "pin_conflicts_with_cwd", "pin_missing_directory",
    "pin_not_a_workspace", "pin_denied", "pin_denied_root", "home", "root",
    "pin_resolution", "target_resolution",
])
def test_cli_binding_wording_equals_resolver(home, wording_paths, case, json_mode):
    a, b, plain = wording_paths
    pin, explicit, cwd = None, None, plain
    if case in _CLI_HOLD_REASONS:
        pin = str(a)
        if case == "pin_conflicts_with_target":
            explicit = str(b)
        else:
            cwd = b
    elif case in ("home", "root"):
        explicit = str(home) if case == "home" else home.anchor
    elif case.endswith("resolution"):
        target = _wording_resolution_path(plain)
        if case == "pin_resolution":
            pin = str(target)
        else:
            explicit = str(target)
    else:
        pin = {"pin_missing_directory": str(a / "shared.py"), "pin_not_a_workspace": str(plain),
               "pin_denied": str(home), "pin_denied_root": home.anchor}[case]
    with pytest.raises((WorkspaceHold, WorkspaceNotFoundError)) as caught:
        resolve_cli_root(explicit=explicit, cwd=cwd, pin=pin)
    canonical = caught.value
    expected = str(canonical)
    if case.endswith("resolution"):
        # binding.py:_cli_path includes the OS-error suffix; scan deliberately
        # omits that untrusted suffix, preserving exactly this fixed sentence.
        prefix = "AEGIS_WORKSPACE " if pin else "--workspace "
        expected = prefix + (pin or explicit) + " cannot be resolved"
        cause = canonical.__cause__
        assert isinstance(cause, OSError)
        assert str(canonical) == expected + ": " + str(cause.__cause__ or cause)
    argv = ["scan", "app.py"]
    if explicit:
        argv += ["--workspace", explicit]
    if json_mode:
        argv.append("--json")
    for _ in range(2):
        run = subprocess.run([sys.executable, "-m", "aegis_cli", *argv], cwd=cwd,
                             env=_wording_environment(pin), text=True, capture_output=True, timeout=15)
        assert run.returncode == 2, run.stderr
        if isinstance(canonical, WorkspaceHold) and json_mode:
            payload = json.loads(run.stdout)
            assert run.stderr == ""
            assert payload["reason"] == canonical.binding.reason
            assert payload["message"] == canonical.binding.message
        else:
            assert run.stdout == ""
            prefix = f"Hold ({canonical.binding.reason}): " if isinstance(canonical, WorkspaceHold) else "Error: "
            assert run.stderr == prefix + expected + "\n", case
        assert "workspace binding refused" not in run.stdout + run.stderr, case


_REASON_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _reason_scope_nodes(scope):
    pending = [scope]
    while pending:
        node = pending.pop()
        yield node
        if node is scope or not isinstance(node, _REASON_SCOPES):
            pending.extend(ast.iter_child_nodes(node))


def _reason_bindings(nodes):
    # Only a unique simple assignment proves a returned tuple or pin-helper
    # result. Every other write (including loop targets) invalidates that proof.
    simple = {}
    for node in nodes:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            simple[id(node.targets[0])] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            simple[id(node.target)] = node.value
    bindings = {}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bindings.setdefault(node.id, []).append(simple.get(id(node)))
    return bindings


def _unsupported_binding_reason(filename, node):
    raise AssertionError(f"{filename}:{node.lineno}: unsupported binding reason form")


def _assigned_reason_value(value, bindings, filename, site):
    seen = set()
    while isinstance(value, ast.Name):
        choices = bindings.get(value.id, [])
        if value.id in seen or len(choices) != 1 or choices[0] is None:
            _unsupported_binding_reason(filename, site)
        assigned = choices[0]
        if (assigned.lineno, assigned.col_offset) >= (value.lineno, value.col_offset):
            _unsupported_binding_reason(filename, site)
        seen.add(value.id)
        value = assigned
    return value


def _literal_binding_reason(value, filename, site):
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or not value.value:
        _unsupported_binding_reason(filename, site)
    return value.value


def _binding_call_reason(node, bindings, filename):
    values = ([node.args[1]] if len(node.args) > 1 else [])
    values += [keyword.value for keyword in node.keywords if keyword.arg == "reason"]
    if (len(values) != 1 or any(isinstance(arg, ast.Starred) for arg in node.args)
            or any(keyword.arg is None for keyword in node.keywords)):
        _unsupported_binding_reason(filename, node)
    value = values[0]
    # The resolver's sole dynamic reason is problem[0], where problem was
    # assigned _pin_problem(...); its possible reasons come from that helper.
    if (isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name)
            and isinstance(value.slice, ast.Constant) and type(value.slice.value) is int and value.slice.value == 0):
        assigned = _assigned_reason_value(value.value, bindings, filename, node)
        if isinstance(assigned, ast.Call) and isinstance(assigned.func, ast.Name) and assigned.func.id == "_pin_problem":
            return None
    return _literal_binding_reason(value, filename, node)


def _check_binding_constructor(node, scope, bindings, filename):
    name = getattr(scope, "name", None)
    keywords = {keyword.arg: keyword.value for keyword in node.keywords}
    # These two constructors forward the status/reason supplied by the producers
    # we inspect. A new constructor or a changed reason forwarder needs review.
    if (name == "_bound" and len(node.args) == 4 and not node.keywords
            and isinstance(node.args[0], ast.Name) and node.args[0].id == "BOUND"):
        return
    reason = keywords.get("reason")
    if (name == "_not_bound" and len(node.args) == 1 and None not in keywords
            and isinstance(node.args[0], ast.Name) and node.args[0].id == "status"
            and isinstance(reason, ast.Name) and reason.id == "reason" and "reason" not in bindings
            and "reason" in {arg.arg for arg in scope.args.args}):
        return
    _unsupported_binding_reason(filename, node)


def _reason_identifier_fields(node):
    for field, value in ast.iter_fields(node):
        values = value if isinstance(value, list) else [value]
        for name in values:
            if isinstance(name, str):
                yield field, name.split(".")


def _check_reason_producer_loads(tree, filename):
    producers = {"_not_bound", "WorkspaceBinding", "_pin_problem"}
    nodes = list(ast.walk(tree))
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    direct_calls = {node.func for node in nodes if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    postponed = any(isinstance(node, ast.ImportFrom) and node.module == "__future__"
                    and any(alias.name == "annotations" for alias in node.names) for node in tree.body)
    type_nodes = set()
    if postponed:
        # binding.py uses postponed WorkspaceBinding annotations. These are type
        # metadata, not evaluated producer loads; defaults/decorators still are.
        for node in nodes:
            annotation = None
            if isinstance(node, (ast.arg, ast.AnnAssign)):
                annotation = node.annotation
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                annotation = node.returns
            if annotation is not None:
                type_nodes.update(ast.walk(annotation))
    # The resolver exports its class name as inert metadata. A read of __all__
    # makes those strings potential lookup keys, so that use is not exempt.
    export_reads = any("__all__" in parts for node in nodes
                       if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store))
                       for _, parts in _reason_identifier_fields(node))
    export_nodes = set()
    if not export_reads:
        for node in tree.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "__all__"
                    and isinstance(node.value, (ast.List, ast.Tuple))
                    and all(isinstance(part, ast.Constant) and isinstance(part.value, str) for part in node.value.elts)):
                export_nodes.update(node.value.elts)
    for node in nodes:
        if node in direct_calls or node in type_nodes or node in export_nodes:
            continue
        # Check identifier fields themselves, including alias/keyword names and
        # literal lookup keys, instead of maintaining a list of AST node types.
        for field, parts in _reason_identifier_fields(node):
            if field == "name" and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # The producer's own declaration.
            if producers.intersection(parts):
                # Python 3.9 import aliases have no independent source position.
                site = node if hasattr(node, "lineno") else parents[node]
                _unsupported_binding_reason(filename, site)


def _binding_reason_sites(source, filename):
    tree = ast.parse(source, filename=filename)
    _check_reason_producer_loads(tree, filename)
    scopes = [tree] + [node for node in ast.walk(tree) if isinstance(node, _REASON_SCOPES)]
    reasons = set()
    for scope in scopes:
        nodes = list(_reason_scope_nodes(scope))
        bindings = _reason_bindings(nodes)
        for node in nodes:
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "WorkspaceBinding":
                _check_binding_constructor(node, scope, bindings, filename)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_not_bound":
                reason = _binding_call_reason(node, bindings, filename)
                if reason is not None:
                    reasons.add(reason)
            if getattr(scope, "name", None) == "_pin_problem" and isinstance(node, ast.Return):
                if node.value is None or isinstance(node.value, ast.Constant) and node.value.value is None:
                    continue  # A successful pin has no refusal reason.
                value = _assigned_reason_value(node.value, bindings, filename, node)
                if (not isinstance(value, ast.Tuple) or len(value.elts) != 2
                        or any(isinstance(part, ast.Starred) for part in value.elts)):
                    _unsupported_binding_reason(filename, node)
                reasons.add(_literal_binding_reason(value.elts[0], filename, node))
    return reasons


def _assert_binding_wording_reasons(reasons):
    covered = set(_MCP_WORDING_REASONS.values()) | _CLI_HOLD_REASONS
    if reasons != covered:
        raise AssertionError(f"binding wording reasons without contract cases: {sorted(reasons - covered)}")


def test_binding_wording_matrix_covers_every_resolver_reason():
    from aegis_core.workspace import binding

    path = Path(binding.__file__)
    _assert_binding_wording_reasons(_binding_reason_sites(path.read_text(encoding="utf-8"), str(path)))


@pytest.mark.parametrize("source", [
    '_not_bound(HOLD, "new_reason", "refusal")',
    '_not_bound(HOLD, reason="new_reason", message="refusal")',
    'def _pin_problem(pin):\n    return "new_reason", "refusal"',
    'def _pin_problem(pin):\n    refusal = ("new_reason", "refusal")\n    return refusal',
    'def _pin_problem(pin):\n    refusal: tuple = ("new_reason", "refusal")\n    return refusal',
    'def _pin_problem(pin):\n    refusal = ("new_reason", "refusal")\n    alias = refusal\n    return alias',
    'def _pin_problem(pin):\n    return "new_reason", "refusal"\n'
    'def resolve():\n    problem = _pin_problem(None)\n    return _not_bound(HOLD, problem[0], problem[1])',
], ids=["positional", "keyword", "tuple", "assigned_tuple", "annotated_tuple", "tuple_alias", "pin_forwarding"])
def test_binding_reason_forms_require_a_wording_case(source):
    reasons = _binding_reason_sites(source, "binding_fixture.py")
    assert reasons == {"new_reason"}
    covered = set(_MCP_WORDING_REASONS.values()) | _CLI_HOLD_REASONS
    with pytest.raises(AssertionError) as caught:
        _assert_binding_wording_reasons(covered | reasons)
    assert str(caught.value) == "binding wording reasons without contract cases: ['new_reason']"


@pytest.mark.parametrize("source,line", [
    ('_not_bound(HOLD, choose_reason(), "refusal")', 1),
    ('_not_bound(HOLD, reason=choose_reason(), message="refusal")', 1),
    ('def _pin_problem(pin):\n    return choose_refusal()', 2),
    ('def _pin_problem(pin):\n    return reason, "refusal"', 2),
    ('def _pin_problem(pin):\n    refusal = choose_refusal()\n    return refusal', 3),
    ('def _pin_problem(pin):\n    refusal = ("first", "refusal")\n    refusal = ("second", "refusal")\n    return refusal', 4),
    ('def _pin_problem(pin):\n    first = second\n    second = first\n    return first', 4),
    ('def resolve():\n    problem = other_problem()\n    return _not_bound(HOLD, problem[0], problem[1])', 3),
    ('_not_bound(HOLD, message="refusal")', 1),
    ('_not_bound(*parts)', 1),
    ('WorkspaceBinding(HOLD, reason="new_reason", message="refusal")', 1),
    ('def _not_bound(status, reason, message):\n    return WorkspaceBinding(status, reason=choose_reason())', 2),
    ('def _pin_problem(pin):\n    return ()', 2),
    ('def _pin_problem(pin):\n    refusal = ("new_reason", "refusal")\n    for refusal in others:\n        pass\n    return refusal', 5),
    ('_not_bound(HOLD, "first", reason="second", message="refusal")', 1),
], ids=["dynamic_positional", "dynamic_keyword", "dynamic_tuple", "dynamic_tuple_reason",
        "dynamic_assignment", "reassigned_tuple", "cyclic_assignment", "unknown_forwarding",
        "missing_reason", "starred_arguments", "direct_constructor", "changed_forwarder",
        "empty_tuple", "loop_rebinding", "duplicate_reason"])
def test_binding_reason_discovery_refuses_unsupported_forms(source, line):
    with pytest.raises(AssertionError) as caught:
        _binding_reason_sites(source, "binding_fixture.py")
    assert str(caught.value) == f"binding_fixture.py:{line}: unsupported binding reason form"


@pytest.mark.parametrize("producer,alias", [
    ("_not_bound", "refuse"), ("WorkspaceBinding", "Binding"), ("_pin_problem", "pin_problem"),
])
@pytest.mark.parametrize("source,line", [
    ('def resolve():\n    {alias} = {producer}\n'
     '    return {alias}(HOLD, reason="new_reason", message="refusal")', 2),
    ('{alias}: object = {producer}', 1),
    ('first = second = {producer}', 1),
    ('({alias} := {producer})', 1),
    ('consume({producer})', 1),
    ('consume(factory={producer})', 1),
    ('factories = [{producer}]', 1),
    ('factories = dict(refuse={producer})', 1),
    ('def resolve():\n    return {producer}', 2),
    ('def resolve(factory={producer}):\n    pass', 1),
    ('@{producer}\ndef resolve():\n    pass', 1),
    ('def resolve() -> {producer}:\n    pass', 1),
    ('module.{producer}', 1),
    ('module.{producer}(HOLD, reason="new_reason", message="refusal")', 1),
    ('from __future__ import annotations\n{alias} = {producer}', 2),
    ('from __future__ import annotations\ndef resolve(factory={producer}):\n    pass', 2),
    ('from __future__ import annotations\nresult: WorkspaceBinding = {producer}', 2),
], ids=["alias_call", "annotated_alias", "chained_alias", "named_alias", "argument",
        "keyword_argument", "list", "mapping", "returned", "default", "decorator", "evaluated_annotation",
        "qualified_reference", "qualified_call", "postponed_alias", "postponed_default", "postponed_value"])
def test_binding_reason_discovery_refuses_producer_references(producer, alias, source, line):
    source = source.format(producer=producer, alias=alias)
    with pytest.raises(AssertionError) as caught:
        _binding_reason_sites(source, "binding_fixture.py")
    assert str(caught.value) == f"binding_fixture.py:{line}: unsupported binding reason form"


def test_binding_reason_discovery_preserves_postponed_type_annotations():
    source = ('from __future__ import annotations\n'
              'def resolve(binding: WorkspaceBinding) -> WorkspaceBinding:\n'
              '    result: WorkspaceBinding = _not_bound(HOLD, reason="new_reason", message="refusal")\n'
              '    return result')
    assert _binding_reason_sites(source, "binding_fixture.py") == {"new_reason"}


@pytest.mark.parametrize("producer,alias", [
    ("_not_bound", "refuse"), ("WorkspaceBinding", "Binding"), ("_pin_problem", "pin_problem"),
])
@pytest.mark.parametrize("source,line", [
    ('def resolve():\n    from aegis_core.workspace.binding import {producer} as {alias}\n'
     '    return {alias}(HOLD, reason="new_reason", message="refusal")', 2),
    ('from aegis_core.workspace.binding import {producer}', 1),
    ('from module import other as {producer}', 1),
    ('import {producer} as {alias}', 1),
    ('import module as {producer}', 1),
    ('import package.{producer} as {alias}', 1),
    ('from package.{producer} import other', 1),
    ('getattr(module, "{producer}")', 1),
    ('setattr(module, "{producer}", replacement)', 1),
    ('builtins.getattr(module, "{producer}")', 1),
    ('builtins.setattr(module, "{producer}", replacement)', 1),
    ('consume({producer}=replacement)', 1),
    ('{producer} = replacement', 1),
    ('del {producer}', 1),
    ('def resolve({producer}):\n    pass', 1),
    ('global {producer}', 1),
    ('try:\n    pass\nexcept Exception as {producer}:\n    pass', 3),
    ('key = "{producer}"\ngetattr(module, key)', 1),
    ('consume(**dict.fromkeys(["{producer}"], replacement))', 1),
    ('__all__ = ["{producer}"]\ngetattr(module, __all__[0])', 1),
    ('__all__ = ["{producer}"]\ngetattr(module, getattr(module, "__all__")[0])', 1),
], ids=["from_alias_call", "from_import", "from_asname", "import_name", "import_asname",
        "dotted_import", "from_module", "getattr", "setattr", "qualified_getattr", "qualified_setattr",
        "keyword", "assignment", "deletion", "parameter", "global", "exception_target",
        "assigned_getattr_key", "stored_keyword_key", "consumed_export", "reflected_export"])
def test_binding_reason_discovery_refuses_producer_identifiers(producer, alias, source, line):
    with pytest.raises(AssertionError) as caught:
        _binding_reason_sites(source.format(producer=producer, alias=alias), "binding_fixture.py")
    assert str(caught.value) == f"binding_fixture.py:{line}: unsupported binding reason form"


def test_binding_reason_discovery_preserves_definitions_and_export_metadata():
    source = ('from __future__ import annotations\n'
              '__all__ = ["WorkspaceBinding"]\n'
              'class WorkspaceBinding:\n    pass\n'
              'def _not_bound(status, reason, message) -> WorkspaceBinding:\n'
              '    return WorkspaceBinding(status, reason=reason, message=message)\n'
              'def _pin_problem(pin):\n    return "new_reason", "refusal"\n'
              'def resolve() -> WorkspaceBinding:\n'
              '    return _not_bound(HOLD, reason="new_reason", message="refusal")')
    assert _binding_reason_sites(source, "binding_fixture.py") == {"new_reason"}


@pytest.mark.parametrize("producer", ["_not_bound", "WorkspaceBinding", "_pin_problem"])
def test_binding_reason_import_diagnostic_without_alias_locations(producer):
    tree = ast.Module(body=[ast.ImportFrom(
        module="aegis_core.workspace.binding", names=[ast.alias(name=producer, asname="factory")],
        level=0, lineno=2,
    )], type_ignores=[])
    with pytest.raises(AssertionError) as caught:
        _binding_reason_sites(tree, "binding_fixture.py")
    assert str(caught.value) == "binding_fixture.py:2: unsupported binding reason form"


def test_cli_preserves_core_pin_missing_sentence(home, wording_paths, capsys):
    import aegis_cli.cli as cli

    inputs = _mcp_wording_inputs("pin_missing", home, wording_paths)
    canonical = resolve_binding(**inputs)
    assert canonical.reason == "pin_missing"
    # The CLI's own _cli_path normally raises a different sentence (covered
    # above). Exercise the formatter with the shared resolver's real refusal to
    # also pin its "which cannot be resolved" template without patching a caller.
    args = Namespace(command="scan", _workspace_pin=inputs["pin"])
    for _ in range(2):
        assert cli._DefaultErrorPolicy().workspace_error(args, WorkspaceNotFoundError(canonical.message)) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "Error: " + canonical.message + "\n"
