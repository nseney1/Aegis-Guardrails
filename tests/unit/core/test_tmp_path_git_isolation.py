"""Temporary workspaces must not inherit an enclosing checkout's Git state."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from aegis_core import gitsafe, storage
from tests.conftest import symlink_or_skip


# Match the subprocess hang ceiling in test_polyglot_recipes; no timing budget.
_HANG_CEILING = 600.0
_POSIX_SYMLINK_DOTDOT = pytest.mark.skipif(
    os.name == "nt", reason="Windows collapses '..' lexically before following symlinks")


def _init_repo(path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("needs git")
    path.mkdir()
    subprocess.run([git, "init", "--quiet"], cwd=str(path), check=True,
                   capture_output=True, timeout=_HANG_CEILING)
    return path


@pytest.fixture(params=["directory", "gitfile"])
def enclosing_checkout(tmp_path, request):
    outer = _init_repo(tmp_path / "outer")
    if request.param == "gitfile":
        metadata = tmp_path / "outer.git"
        (outer / ".git").rename(metadata)
        (outer / ".git").write_text("gitdir: " + str(metadata) + "\n", encoding="utf-8")
    ceiling = outer / "ceiling"
    workspace = ceiling / "workspace"
    workspace.mkdir(parents=True)
    return outer, ceiling, workspace


def test_workspace_is_git_respects_ceiling(enclosing_checkout, monkeypatch):
    from aegis_core.workspace.base import Workspace

    outer, ceiling, workspace = enclosing_checkout
    monkeypatch.delenv("GIT_CEILING_DIRECTORIES", raising=False)
    assert gitsafe.toplevel(workspace) == outer
    assert Workspace(root=workspace).is_git is True

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling))
    assert gitsafe.toplevel(workspace) is None
    assert Workspace(root=workspace).is_git is False

    inner = _init_repo(workspace / "inner")
    child = inner / "sub"
    child.mkdir()
    assert gitsafe.toplevel(child) == inner
    assert Workspace(root=inner).is_git is True
    assert Workspace(root=child).is_git is True
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(inner))
    assert gitsafe.toplevel(inner) == inner
    assert Workspace(root=inner).is_git is True


def test_insight_workspace_id_respects_ceiling(enclosing_checkout, monkeypatch):
    from aegis_core.insights import insight_workspace_id

    outer, ceiling, workspace = enclosing_checkout
    standalone = hashlib.sha256(workspace.as_posix().encode("utf-8", "surrogatepass")).hexdigest()[:16]
    monkeypatch.delenv("GIT_CEILING_DIRECTORIES", raising=False)
    assert gitsafe.toplevel(workspace) == outer
    assert insight_workspace_id(workspace) != standalone

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling))
    assert gitsafe.toplevel(workspace) is None
    assert insight_workspace_id(workspace) == standalone

    inner = _init_repo(workspace / "inner")
    (inner / ".aegis" / "rules").mkdir(parents=True)
    child = inner / "sub"
    child.mkdir()
    identity = insight_workspace_id(inner)
    assert identity != hashlib.sha256(inner.as_posix().encode("utf-8", "surrogatepass")).hexdigest()[:16]
    assert insight_workspace_id(child) == identity
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(inner))
    assert gitsafe.toplevel(inner) == inner
    assert insight_workspace_id(inner) == identity


def test_session_ceiling_preserves_checkout_discovery(tmp_path_factory, repo_root):
    basetemp = tmp_path_factory.getbasetemp().resolve()
    ceiling = basetemp if Path(repo_root).resolve() in basetemp.parents else basetemp.parent
    assert str(ceiling) in os.environ["GIT_CEILING_DIRECTORIES"].split(os.pathsep)


def test_collect_only_preserves_existing_basetemp(tmp_path, repo_root):
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_probe.py").write_text(
        "def test_body():\n"
        "    assert False, 'collect-only executed a test body'\n",
        encoding="utf-8",
    )
    basetemp = tmp_path / "run"
    basetemp.mkdir()
    sentinel = basetemp / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-p", "tests.conftest", "--collect-only",
         str(suite), "-q", "-n", "0",
         "-p", "no:cacheprovider", "--rootdir", str(suite), "--confcutdir", str(suite),
         "--basetemp", str(basetemp)],
        cwd=repo_root, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_HANG_CEILING,
    )

    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert "1 test collected" in result.stdout
    assert sentinel.is_file(), "collect-only removed the existing basetemp sentinel"
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"


@pytest.mark.parametrize("basetemp_name", [".tmp", ".pytest_cache/run", "tests/.tmp"])
def test_serial_basetemp_preserves_checkout_and_isolates_temp_workspaces(tmp_path, repo_root, basetemp_name):
    checkout = _init_repo(tmp_path / "checkout")
    suite = checkout / "tests"
    suite.mkdir()
    shutil.copyfile(Path(repo_root) / "tests" / "conftest.py", suite / "conftest.py")
    source = suite / "unit" / "core"
    source.mkdir(parents=True)
    (source / "test_probe.py").write_text(
        "from pathlib import Path\n"
        "from aegis_core import gitsafe\n"
        "def test_discovery(tmp_path):\n"
        "    checkout = Path(__file__).resolve().parents[3]\n"
        "    common_dir = gitsafe.common_dir(Path(__file__).parent)\n"
        "    assert common_dir is not None, 'checkout discovery was blocked'\n"
        "    assert common_dir.resolve() == (checkout / '.git').resolve()\n"
        "    assert gitsafe.common_dir(tmp_path) is None\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (repo_root, env.get("PYTHONPATH"))))
    basetemp = checkout / basetemp_name
    basetemp.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", str(source / "test_probe.py"), "-q", "-n", "0",
         "-p", "no:cacheprovider", "--rootdir", str(checkout), "--confcutdir", str(checkout),
         "--basetemp", str(basetemp)],
        cwd=str(checkout), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_HANG_CEILING,
    )

    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr


def test_ceiling_blocks_enclosing_repository(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path / "outer")
    ceiling = repo / "ceiling"
    workspace = ceiling / "workspace"
    workspace.mkdir(parents=True)

    monkeypatch.delenv("GIT_CEILING_DIRECTORIES", raising=False)
    assert gitsafe.common_dir(workspace).resolve() == (repo / ".git").resolve()
    assert storage.ledger_site(workspace, create=False).shared is True

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling.resolve()))
    assert gitsafe.common_dir(workspace) is None
    assert storage.ledger_site(workspace, create=False).shared is False


def test_repository_inside_tmp_path_is_still_found(tmp_path):
    repo = _init_repo(tmp_path / "inner")
    workspace = repo / "workspace"
    workspace.mkdir()

    assert gitsafe.common_dir(workspace).resolve() == (repo / ".git").resolve()
    assert storage.ledger_site(workspace, create=False).shared is True


@pytest.mark.parametrize("separator", [
    pytest.param(":", id="posix-colon",
                 marks=pytest.mark.skipif(os.name == "nt", reason="colon is not a Windows path character")),
    pytest.param(";", id="windows-semicolon",
                 marks=pytest.mark.skipif(os.name != "nt", reason="Windows uses semicolon as its path separator")),
])
@pytest.mark.parametrize("location", ["parent", "basetemp"])
@pytest.mark.parametrize("mode", ["serial", "parallel", "collect"])
def test_separator_in_basetemp_refuses_before_test_body(tmp_path, repo_root, separator, location, mode):
    suite = tmp_path / "tests"
    suite.mkdir()
    (suite / "test_probe.py").write_text(
        "from pathlib import Path\n"
        "def test_body():\n"
        "    Path(__file__).with_name('body-ran').write_text('ran', encoding='utf-8')\n",
        encoding="utf-8",
    )
    parent = tmp_path / ("ceiling" + separator + "entry" if location == "parent" else "ceiling")
    parent.mkdir()
    basetemp = parent / ("run" + separator + "entry" if location == "basetemp" else "run")
    basetemp.mkdir()
    sentinel = basetemp / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    shutil.copyfile(Path(repo_root) / "tests" / "conftest.py", suite / "conftest.py")
    options = ["-n", "2"] if mode == "parallel" else ["-n", "0"]
    if mode == "collect":
        options.append("--collect-only")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(tmp_path), repo_root, env.get("PYTHONPATH"))))
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", str(suite / "test_probe.py"),
         "-q", *options, "-p", "no:cacheprovider", "--confcutdir", str(suite),
         "--basetemp", str(basetemp)],
        cwd=repo_root, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_HANG_CEILING,
    )

    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert output.count("choose --basetemp outside paths containing the path separator") == 1, output
    assert str(basetemp) in output
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"
    assert not (suite / "body-ran").exists()


@pytest.mark.parametrize("marker", ["directory", "file"])
def test_workspace_discovery_respects_ceiling_but_store_placement_does_not(tmp_path, monkeypatch, marker):
    from aegis_core.manager_policy import ManagerError
    from aegis_core.manager_store import ManagerStore
    from aegis_core.workspace import as_workspace
    from aegis_core.workspace.binding import bounded_walk_up, git_boundary

    outer = tmp_path / "outer"
    (outer / ".aegis" / "rules").mkdir(parents=True)
    if marker == "directory":
        (outer / ".git").mkdir()
    else:
        (outer / ".git").write_text("gitdir: absent\n", encoding="utf-8")
    ceiling = outer / "ceiling"
    workspace = ceiling / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.delenv("GIT_CEILING_DIRECTORIES", raising=False)
    assert git_boundary(workspace) == outer
    assert bounded_walk_up(workspace) == outer
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        ManagerStore(workspace / "audit").read()

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling))
    assert git_boundary(workspace) is None
    assert bounded_walk_up(workspace) is None
    assert as_workspace(workspace).root == workspace
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        ManagerStore(workspace / "audit").read()
    # Explicit forbidden roots remain authoritative even beyond the ceiling.
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        ManagerStore(workspace / "audit", forbidden_roots=[outer]).read()

    (workspace / ".git").mkdir()
    (workspace / ".aegis" / "rules").mkdir(parents=True)
    assert git_boundary(workspace) == workspace
    assert bounded_walk_up(workspace) == workspace
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        ManagerStore(workspace / "audit").read()


@pytest.mark.parametrize("entry", ["same", "relative", "empty", "missing", "multiple"])
def test_ceiling_entry_semantics_match_git(tmp_path, monkeypatch, entry):
    from aegis_core.workspace.binding import bounded_walk_up, git_boundary

    repo = _init_repo(tmp_path / "repo")
    (repo / ".aegis" / "rules").mkdir(parents=True)
    workspace = repo / "ceiling" / "workspace"
    workspace.mkdir(parents=True)
    ceilings = {
        "same": str(repo),
        "relative": "repo",
        "empty": os.pathsep,
        "missing": str(tmp_path / "absent"),
        "multiple": os.pathsep.join((str(tmp_path), "", workspace.parent.as_posix())),
    }
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", ceilings[entry])
    start = repo if entry == "same" else workspace
    expected = None if entry == "multiple" else repo
    assert gitsafe.toplevel(start) == expected
    assert git_boundary(start) == expected
    assert bounded_walk_up(start) == expected


@pytest.mark.parametrize("case", [
    "plain", "symlink-start", "proc-alias", "empty-before", "empty-after", "empty-mixed",
    "empty-symlink", "empty-dotdot", "empty-double-slash", "trailing-slash", "dotdot",
    "nonexistent", "missing-intermediate", "git-env-symlink", "repo-ceiling", "nested",
])
def test_git_boundary_matches_git_oracle(tmp_path, monkeypatch, case):
    from aegis_core.workspace.binding import git_boundary, git_discovery_paths

    repo = _init_repo(tmp_path / "repo")
    ceiling = repo / "ceiling"
    start = ceiling / "workspace"
    start.mkdir(parents=True)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_CEILING_DIRECTORIES"):
        monkeypatch.delenv(name, raising=False)
    entries = None
    if case == "symlink-start":
        alias = tmp_path / "alias"
        symlink_or_skip(repo, alias, target_is_directory=True)
        start = alias / "ceiling" / "workspace"
        entries = str(ceiling)
    elif case == "proc-alias":
        proc = Path("/proc/self/cwd")
        if os.name != "posix" or not proc.is_dir():
            pytest.skip("needs the /proc/self/cwd directory alias")
        start = proc / os.path.relpath(start, Path.cwd())
        entries = str(ceiling)
    elif case == "empty-before":
        alias = tmp_path / "ceiling-alias"
        symlink_or_skip(ceiling, alias, target_is_directory=True)
        entries = str(alias) + os.pathsep
    elif case in {"empty-after", "empty-mixed", "empty-dotdot", "empty-double-slash"}:
        entry = ceiling.as_posix()  # Git compares post-empty entries with its slash-form cwd.
        if case == "empty-dotdot":
            (ceiling / "unused").mkdir()
            entry += "/unused/.."
        elif case == "empty-double-slash":
            entry += "//"
        prefix = str(tmp_path) if case == "empty-mixed" else ""
        entries = os.pathsep.join((prefix, "", entry))
    elif case == "empty-symlink":
        alias = tmp_path / "ceiling-alias"
        symlink_or_skip(ceiling, alias, target_is_directory=True)
        entries = os.pathsep + alias.as_posix()
    elif case in {"trailing-slash", "dotdot", "nonexistent", "missing-intermediate"}:
        entry = str(ceiling)
        if case == "trailing-slash":
            entry += "/"
        elif case == "dotdot":
            (ceiling / "unused").mkdir()
            entry += "/unused/.."
        elif case == "nonexistent":
            entry += "/missing"
        else:
            entry += "/missing/.."
        entries = entry
    elif case == "git-env-symlink":
        worktree = tmp_path / "worktree"
        (worktree / "sub").mkdir(parents=True)
        alias = tmp_path / "worktree-alias"
        symlink_or_skip(worktree, alias, target_is_directory=True)
        start = alias / "sub"
        monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
        monkeypatch.setenv("GIT_WORK_TREE", str(worktree))
        entries = str(worktree)
    elif case == "repo-ceiling":
        entries = str(repo)
    elif case == "nested":
        inner = _init_repo(ceiling / "inner")
        start = inner / "sub"
        start.mkdir()
        entries = str(ceiling)
    if entries is not None:
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", entries)
    result = subprocess.run([shutil.which("git"), "rev-parse", "--show-toplevel"], cwd=start,
                            env=dict(os.environ), capture_output=True, text=True, timeout=_HANG_CEILING)
    expected = Path(result.stdout.strip()).resolve() if result.returncode == 0 else None
    assert git_boundary(start) == expected
    if "GIT_DIR" not in os.environ:
        marker = next((d for d in git_discovery_paths(start) if os.path.lexists(d / ".git")), None)
        assert marker == expected


def test_empty_ceiling_marker_avoids_resolving_later_entries(tmp_path, monkeypatch):
    from aegis_core.workspace import binding

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    slow = tmp_path / "slow-filesystem"
    real_path_type = type(Path())

    class GuardedPath(real_path_type):
        def resolve(self, *args, **kwargs):
            assert self != slow, "a ceiling after the empty marker was resolved"
            return super().resolve(*args, **kwargs)

    monkeypatch.setattr(binding, "Path", GuardedPath)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.pathsep + slow.as_posix())
    assert next(iter(binding.git_discovery_paths(workspace))) == workspace


def _run_basetemp_probe(tmp_path, repo_root, mode, env, options=()):
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_probe.py").write_text(
        "from pathlib import Path\n"
        "def test_body(): Path(__file__).with_name('body-ran').write_text('ran')\n", encoding="utf-8")
    execution = ["-n", "2"] if mode == "parallel" else ["-n", "0"]
    if mode == "collect":
        execution.append("--collect-only")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-p", "tests.conftest", str(suite),
         "-q", *execution, "-p", "no:cacheprovider", "--confcutdir", str(suite), *options],
        cwd=repo_root, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_HANG_CEILING)
    return result, suite


@pytest.mark.parametrize("mode", ["serial", "parallel", "collect"])
@pytest.mark.parametrize("case", ["empty-debug", "user", "logname", "explicit-link", "default-link"])
def test_prospective_basetemp_refuses_separators(tmp_path, repo_root, case, mode):
    root = tmp_path / "temporary-root"
    root.mkdir()
    env = dict(os.environ, PYTEST_DEBUG_TEMPROOT=str(root),
               USER="rf81", LOGNAME="rf81", LNAME="rf81", USERNAME="rf81")
    options = []
    token = "ghp_" + "a" * 24
    if case == "empty-debug":
        root = tmp_path / ("temporary" + os.pathsep + "root")
        root.mkdir()
        env["PYTEST_DEBUG_TEMPROOT"] = ""
    elif case in {"user", "logname"}:
        if case == "user":
            env.pop("LOGNAME")
        env[case.upper()] = "rf81" + os.pathsep + "user"
    else:
        alias = tmp_path / ("ceiling" + os.pathsep + token)
        symlink_or_skip(root, alias, target_is_directory=True)
        if case == "explicit-link":
            options = ["--basetemp", str(alias)]
        else:
            env["PYTEST_DEBUG_TEMPROOT"] = str(alias)
    for name in ("TMPDIR", "TMP", "TEMP"):
        env[name] = str(root)
    sentinel = root / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    before = set(root.iterdir())
    result, suite = _run_basetemp_probe(tmp_path, repo_root, mode, env, options)
    output = result.stdout + result.stderr
    assert sentinel.is_file(), output
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"
    assert set(root.iterdir()) == before, output
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert output.count("choose --basetemp outside paths containing the path separator") == 1, output
    assert not (suite / "body-ran").exists()
    if case.endswith("link"):
        assert token not in output
        assert "ghp_REDACTED" in output


@_POSIX_SYMLINK_DOTDOT
@pytest.mark.parametrize("mode", ["serial", "parallel", "collect"])
def test_symlink_dotdot_temproot_refuses_before_initialization(tmp_path, repo_root, mode):
    private_root = tmp_path / ("run" + os.pathsep + "root")
    child = private_root / "child"
    child.mkdir(parents=True)
    safe = tmp_path / "safe"
    safe.mkdir()
    alias = safe / "link"
    symlink_or_skip(child, alias, target_is_directory=True)
    prospective = private_root / "pytest-of-rf81"
    lexical = safe / "pytest-of-rf81"
    assert not prospective.exists()
    assert not lexical.exists()
    env = dict(os.environ, PYTEST_DEBUG_TEMPROOT=str(alias / ".."),
               USER="rf81", LOGNAME="rf81", LNAME="rf81", USERNAME="rf81")
    sentinel = private_root / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    result, suite = _run_basetemp_probe(tmp_path, repo_root, mode, env)
    output = result.stdout + result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"
    # Check both possible roots even when the old fixture eventually refuses.
    assert not prospective.exists(), output
    assert not lexical.exists(), output
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert output.count("choose --basetemp outside paths containing the path separator") == 1, output
    assert not (suite / "body-ran").exists()


@pytest.mark.parametrize("mode", ["serial", "parallel", "collect"])
@pytest.mark.parametrize("case", [
    "explicit-alias-dotdot",
    "default-user-link",
    "explicit-dotdot-q",
    pytest.param("explicit-physical-dotdot", marks=_POSIX_SYMLINK_DOTDOT),
])
def test_basetemp_spellings_refuse_before_initialization(tmp_path, repo_root, case, mode):
    private_root = tmp_path / ("run" + os.pathsep + "root")
    private_root.mkdir()
    safe = tmp_path / "safe"
    (safe / "child").mkdir(parents=True)
    env = dict(os.environ, PYTEST_DEBUG_TEMPROOT=str(safe),
               USER="rf81", LOGNAME="rf81", LNAME="rf81", USERNAME="rf81")
    options = []
    if case == "explicit-alias-dotdot":
        alias = tmp_path / "alias"
        symlink_or_skip(private_root, alias, target_is_directory=True)
        symlink_or_skip(safe / "child", private_root / "link", target_is_directory=True)
        candidate = alias / "link" / ".." / "run"
        target = failed_spelling = private_root / "run"
    elif case == "default-user-link":
        symlink_or_skip(private_root, safe / "pytest-of-rf81", target_is_directory=True)
        target = failed_spelling = private_root
    elif case == "explicit-dotdot-q":
        p, e = tmp_path / "p", tmp_path / "e"
        p.mkdir()
        (e / "f").mkdir(parents=True)
        (e / "q").mkdir()
        symlink_or_skip(e / "f", p / "link", target_is_directory=True)
        symlink_or_skip(private_root, p / "q", target_is_directory=True)
        candidate = p / "link" / ".." / "q" / "bt"
        target = failed_spelling = private_root / "bt"
    else:
        (private_root / "child").mkdir()
        symlink_or_skip(private_root / "child", safe / "link", target_is_directory=True)
        candidate = safe / "link" / ".." / "bt"
        target, failed_spelling = safe / "bt", private_root / "bt"
    if case != "default-user-link":
        options = ["--basetemp", str(candidate)]
        target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    before = set(target.iterdir())
    result, suite = _run_basetemp_probe(tmp_path, repo_root, mode, env, options)
    output = result.stdout + result.stderr
    assert sentinel.is_file(), output
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"
    assert set(target.iterdir()) == before, output
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert output.count("choose --basetemp outside paths containing the path separator") == 1, output
    assert str(failed_spelling) in output
    assert not (suite / "body-ran").exists()


@pytest.mark.parametrize("mode", ["serial", "parallel", "collect"])
@pytest.mark.parametrize("trigger", [
    "file",
    pytest.param("dangling-link", marks=pytest.mark.skipif(
        os.name == "nt", reason="dangling symlink mkdir fallback uses POSIX semantics")),
    "slash-user",
])
def test_default_basetemp_fallback_refuses_before_initialization(tmp_path, repo_root, trigger, mode):
    root = tmp_path / "safe"
    root.mkdir()
    target = tmp_path / ("run" + os.pathsep + "root")
    target.mkdir()
    symlink_or_skip(target, root / "pytest-of-unknown", target_is_directory=True)
    env = dict(os.environ, PYTEST_DEBUG_TEMPROOT=str(root),
               USER="rf81", LOGNAME="rf81", LNAME="rf81", USERNAME="rf81")
    if trigger == "file":
        (root / "pytest-of-rf81").write_text("block the user directory", encoding="utf-8")
    elif trigger == "dangling-link":
        symlink_or_skip(root / "missing", root / "pytest-of-rf81", target_is_directory=True)
    else:
        env["LOGNAME"] = "a/b"
        assert not (root / "pytest-of-a").exists()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    before_target, before_root = set(target.iterdir()), set(root.iterdir())
    result, suite = _run_basetemp_probe(tmp_path, repo_root, mode, env)
    output = result.stdout + result.stderr
    assert sentinel.is_file(), output
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"
    assert set(target.iterdir()) == before_target, output
    assert set(root.iterdir()) == before_root, output
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert output.count("choose --basetemp outside paths containing the path separator") == 1, output
    assert str(target) in output
    assert not (suite / "body-ran").exists()


@pytest.mark.parametrize("mode", ["serial", "parallel", "collect"])
def test_benign_symlinked_temproot_runs(tmp_path, repo_root, mode):
    root, alias = tmp_path / "clean-root", tmp_path / "alias"
    root.mkdir()
    symlink_or_skip(root, alias, target_is_directory=True)
    sentinel = root / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    env = dict(os.environ, PYTEST_DEBUG_TEMPROOT=str(alias),
               USER="rf81", LOGNAME="rf81", LNAME="rf81", USERNAME="rf81")
    result, suite = _run_basetemp_probe(tmp_path, repo_root, mode, env)
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.OK, output
    assert "choose --basetemp" not in output
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"
    assert (suite / "body-ran").exists() == (mode != "collect")
    assert (root / "pytest-of-rf81").exists() == (mode != "collect")


@pytest.mark.parametrize("operation", ["read", "append", "transaction"])
def test_operator_ceiling_cannot_admit_manager_store_in_enclosing_checkout(enclosing_checkout, monkeypatch, operation):
    from aegis_core.manager_policy import ManagerError
    from aegis_core.manager_store import ManagerStore

    outer, ceiling, workspace = enclosing_checkout
    store = ManagerStore(workspace / "audit")
    monkeypatch.delenv("GIT_CEILING_DIRECTORIES", raising=False)
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        store.append({"kind": "scan"})
    assert not store.root.exists()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling))
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        if operation == "read":
            store.read()
        elif operation == "append":
            store.append({"kind": "scan"})
        else:
            store.transaction(lambda rows: pytest.fail("refused placement invoked callback"))
    assert not store.root.exists()


@pytest.mark.skipif(os.name == "nt", reason="control characters are not Windows path characters")
def test_separator_refusal_canonicalizes_and_redacts_the_path(tmp_path, repo_root):
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_probe.py").write_text("def test_body(): pass\n", encoding="utf-8")
    # The control splits a credential prefix until canonicalization removes it.
    credential = "gh\rp_" + "a" * 24
    basetemp = tmp_path / ("ceiling:" + credential)
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-p", "tests.conftest", str(suite),
         "-q", "-n", "0", "-p", "no:cacheprovider", "--confcutdir", str(suite),
         "--basetemp", str(basetemp)],
        cwd=repo_root, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_HANG_CEILING,
    )
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert "a" * 24 not in output
    assert "ghp_REDACTED" in output
    assert "ceiling:" in output
