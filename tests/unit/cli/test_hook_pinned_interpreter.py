"""The git pre-commit hook runs only the aegis that installed it (Citadel finding, H7).

`aegis hook install` bakes one absolute interpreter (sys.executable of the
installing aegis) and the directory aegis_cli was imported from. The hook runs
that interpreter with -I, so neither the repository's working tree, nor a
repo-resident .venv, nor whatever `aegis` or `python3` is first on PATH can
run in its place. When the interpreter or aegis is gone, the hook fails
closed with one line naming the fix; `git commit --no-verify` stays the
documented bypass.

Formerly tests/unit/core/test_precommit_hook_fallback.py (BUG-047), whose
PATH/venv fallback chain is what made repo-resident code runnable.
"""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

import aegis_cli
from aegis_cli.hooks.management import (
    CURRENT_HOOK_FORMAT_VERSION,
    _AEGIS_HOOK_END,
    _AEGIS_HOOK_START,
    generate_hook_block,
    hook_status,
    install_hook,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="runs the hook with /bin/sh")

AEGIS_ROOT = Path(aegis_cli.__file__).resolve().parent.parent

OLD_BLOCK = (f"{_AEGIS_HOOK_START}\n"
             "# Installed by aegis init — runs deterministic quality checks before commit.\n"
             "aegis checkpoint --pre-commit\n"
             f"{_AEGIS_HOOK_END}\n")


def _not_found(path) -> str:
    return (f"aegis pre-commit: aegis not found at {path}; "
            "run aegis hook install, or commit with --no-verify\n")


def git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=str(path), check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=str(path), check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=str(path), check=True)
    return path


def bare_repo(path: Path) -> Path:
    (path / ".git" / "hooks").mkdir(parents=True)
    return path


def marker_script(path: Path, marker: Path, exit_code: int = 0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho "$0 $*" >> "{marker}"\nexit {exit_code}\n', encoding="utf-8")
    path.chmod(0o755)
    return path


def run_hook(project: Path, path_dirs, extra_env=None):
    hook = project / ".git" / "hooks" / "pre-commit"
    env = {"PATH": os.pathsep.join(str(d) for d in path_dirs), "HOME": str(project.parent)}
    env.update(extra_env or {})
    return subprocess.run(["/bin/sh", str(hook)], cwd=str(project), env=env,
                          capture_output=True, text=True, timeout=120)


def test_repo_resident_code_never_runs(tmp_path):
    """A planted .venv python, a repo-local aegis_cli, a stdlib-shadowing module
    and PATH impostors are all ignored."""
    project = git_repo(tmp_path / "p")
    marker = tmp_path / "marker"
    marker_script(project / ".venv" / "bin" / "python", marker)
    marker_script(project / ".venv" / "bin" / "python3", marker)
    planted = project / "aegis_cli"
    planted.mkdir()
    for name in ("__init__.py", "__main__.py", "cli.py"):
        (planted / name).write_text(
            f"open({str(marker)!r}, 'a').write('repo aegis_cli imported\\n')\n"
            "def main(*a, **k):\n    return 0\n",
            encoding="utf-8",
        )
    # The pinned AEGIS_PATH comes first on sys.path, so it already hides the
    # planted aegis_cli. Only -I keeps the working tree from shadowing a stdlib
    # module that aegis imports, which is what this file catches.
    (project / "json.py").write_text(
        f"open({str(marker)!r}, 'a').write('repo json.py imported\\n')\n",
        encoding="utf-8",
    )
    fakebin = tmp_path / "fakebin"
    marker_script(fakebin / "aegis", marker)
    marker_script(fakebin / "python3", marker)
    (project / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(project), check=True)

    install_hook(project)
    proc = run_hook(project, [fakebin, "/usr/bin", "/bin"],
                    {"VIRTUAL_ENV": str(project / ".venv")})

    assert not marker.exists(), marker.read_text(encoding="utf-8")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASSED" in proc.stdout


def test_missing_interpreter_fails_closed_with_one_line(tmp_path):
    project = bare_repo(tmp_path / "p")
    gone = tmp_path / "gone dir" / "python3"
    marker = tmp_path / "marker"
    fakebin = tmp_path / "fakebin"
    marker_script(fakebin / "aegis", marker)
    marker_script(fakebin / "python3", marker)
    install_hook(project, python=str(gone))
    proc = run_hook(project, [fakebin, "/usr/bin", "/bin"])
    assert proc.returncode == 1
    assert proc.stderr == _not_found(gone)
    assert not marker.exists()


def test_missing_aegis_package_fails_closed_with_one_line(tmp_path):
    project = bare_repo(tmp_path / "p")
    empty_root = tmp_path / "uninstalled"
    empty_root.mkdir()
    install_hook(project, python=sys.executable, import_root=str(empty_root))
    proc = run_hook(project, ["/usr/bin", "/bin"])
    assert proc.returncode == 1
    assert proc.stderr == _not_found(sys.executable)


def test_check_failure_propagates_and_stops_the_hook(tmp_path):
    project = bare_repo(tmp_path / "p")
    log = tmp_path / "log"
    py = marker_script(tmp_path / "py dir'x" / "python", log, exit_code=3)
    install_hook(project, python=str(py), import_root=str(AEGIS_ROOT))
    hook = project / ".git" / "hooks" / "pre-commit"
    hook.write_text(hook.read_text(encoding="utf-8") + "echo user-tail\n", encoding="utf-8")
    proc = run_hook(project, ["/usr/bin", "/bin"])
    assert proc.returncode == 3
    assert "user-tail" not in proc.stdout
    # A space and a quote in the path prove the interpreter is shell-quoted;
    # -I keeps the working tree off sys.path.
    call = log.read_text(encoding="utf-8")
    assert call.startswith(f"{py} -I -c ")
    assert call.rstrip("\n").endswith(f"{AEGIS_ROOT} check --hook")


def test_block_names_no_path_or_repo_relative_interpreter():
    block = generate_hook_block("/opt/py/bin/python3", import_root="/opt/site")
    for unsafe in ("command -v", "$PWD", ".venv", "VIRTUAL_ENV"):
        assert unsafe not in block
    assert f"aegis-hook-format: {CURRENT_HOOK_FORMAT_VERSION}" in block
    run_lines = [ln.strip() for ln in block.splitlines() if "check --hook" in ln]
    assert len(run_lines) == 1
    tokens = shlex.split(run_lines[0])
    assert tokens[:2] == ["$AEGIS_PYTHON", "-I"]


def test_default_interpreter_and_import_root_are_the_installing_aegis(tmp_path):
    project = bare_repo(tmp_path / "p")
    install_hook(project)
    text = (project / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert f"AEGIS_PYTHON={shlex.quote(sys.executable)}\n" in text
    assert f"AEGIS_PATH={shlex.quote(str(AEGIS_ROOT))}\n" in text


def test_hook_is_posix_sh(tmp_path):
    project = bare_repo(tmp_path / "p")
    install_hook(project, python="/usr/bin/python3")
    text = (project / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    for bashism in ("[[", "function ", "$(<", "local "):
        assert bashism not in text


def test_reinstall_replaces_an_old_block_and_runs_it_first(tmp_path):
    project = bare_repo(tmp_path / "p")
    hook = project / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho user-before\n\n" + OLD_BLOCK + "echo user-after\n",
                    encoding="utf-8")
    install_hook(project, python="/usr/bin/python3")
    text = hook.read_text(encoding="utf-8")
    assert text.count(_AEGIS_HOOK_START) == 1 and text.count(_AEGIS_HOOK_END) == 1
    assert text.startswith("#!/bin/sh\n" + _AEGIS_HOOK_START + "\n")
    assert text.endswith(_AEGIS_HOOK_END + "\necho user-before\n\necho user-after\n")
    assert "check --hook" in text
    # Idempotent: a second run is byte-identical.
    install_hook(project, python="/usr/bin/python3")
    assert hook.read_text(encoding="utf-8") == text


def test_unterminated_block_is_left_alone(tmp_path):
    project = bare_repo(tmp_path / "p")
    hook = project / ".git" / "hooks" / "pre-commit"
    broken = "#!/bin/sh\n" + _AEGIS_HOOK_START + "\naegis checkpoint --pre-commit\necho mine\n"
    hook.write_text(broken, encoding="utf-8")
    install_hook(project, python="/usr/bin/python3")
    assert hook.read_text(encoding="utf-8") == broken


def test_status_reports_the_pinned_interpreter(tmp_path):
    project = bare_repo(tmp_path / "p")
    install_hook(project, python=sys.executable)
    st = hook_status(project)
    assert st["status"] == "installed"
    assert st["interpreter"] == {"path": sys.executable, "exists": True}

    gone = str(tmp_path / "gone" / "python3")
    install_hook(project, python=gone)
    assert hook_status(project)["interpreter"] == {"path": gone, "exists": False}


def test_status_reports_the_pinned_aegis_path(tmp_path):
    project = bare_repo(tmp_path / "p")
    install_hook(project, python=sys.executable)
    assert hook_status(project)["aegis_path"] == {"path": str(AEGIS_ROOT), "exists": True}

    gone = str(tmp_path / "gone-site")
    install_hook(project, python=sys.executable, import_root=gone)
    assert hook_status(project)["aegis_path"] == {"path": gone, "exists": False}


def test_status_text_names_each_missing_pinned_path(tmp_path, capsys):
    from aegis_cli.cli import main

    project = bare_repo(tmp_path / "p")
    py, site = str(tmp_path / "gone-py"), str(tmp_path / "gone-site")
    install_hook(project, python=py, import_root=site)
    assert main(["hook", "status", "--workspace", str(project)]) == 0
    out = capsys.readouterr().out
    assert f"Runs:            {py} ❌ (missing: run 'aegis hook install')" in out
    assert f"Aegis path:      {site} ❌ (missing: run 'aegis hook install')" in out


@pytest.mark.parametrize("missing", ["interpreter", "aegis_path"])
def test_doctor_flags_a_current_hook_that_would_fail_closed(tmp_path, capsys, missing):
    """The hook refuses every commit when either pinned path is gone, so doctor must not show green."""
    from aegis_cli.doctor import _check_precommit_hook

    project = bare_repo(tmp_path / "p")
    gone = str(tmp_path / "gone")
    if missing == "interpreter":
        install_hook(project, python=gone)
    else:
        install_hook(project, python=sys.executable, import_root=gone)
    assert _check_precommit_hook(project) is False
    out = capsys.readouterr().out
    assert "is current" not in out
    assert f"pins {gone}, which no longer exists" in out
    assert "aegis hook install" in out


@pytest.mark.parametrize("version", [1, 2, 3, 4])
def test_doctor_flags_every_earlier_format_as_outdated(tmp_path, capsys, version):
    """Formats 1-4 resolved aegis through PATH or the repo; re-install to pin it."""
    from aegis_cli.doctor import _check_precommit_hook

    project = bare_repo(tmp_path / "p")
    (project / ".git" / "hooks" / "pre-commit").write_text(
        f"#!/bin/sh\n{_AEGIS_HOOK_START}\n# aegis-hook-format: {version}\nexec aegis check --hook\n{_AEGIS_HOOK_END}\n",
        encoding="utf-8",
    )
    assert _check_precommit_hook(project) is False
    assert "aegis hook install" in capsys.readouterr().out


def test_doctor_flags_unversioned_aegis_block(tmp_path, capsys):
    from aegis_cli.doctor import _check_precommit_hook

    project = bare_repo(tmp_path / "p")
    (project / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n" + OLD_BLOCK, encoding="utf-8")
    assert _check_precommit_hook(project) is False
    assert "aegis hook install" in capsys.readouterr().out


def test_doctor_accepts_current_hook(tmp_path):
    from aegis_cli.doctor import _check_precommit_hook

    project = bare_repo(tmp_path / "p")
    install_hook(project, python=sys.executable)
    assert _check_precommit_hook(project) is True


def test_doctor_silent_without_hook(tmp_path):
    from aegis_cli.doctor import _check_precommit_hook

    assert _check_precommit_hook(bare_repo(tmp_path / "p")) is None


# ── A pinned path must be absolute; a tracked hooks dir is called out ─────

@pytest.mark.parametrize(
    "python, import_root, message",
    [
        ("python3", "/opt/site", "hook interpreter must be an absolute path, got 'python3'"),
        (".venv/bin/python", "/opt/site", "hook interpreter must be an absolute path, got '.venv/bin/python'"),
        ("", "/opt/site", "hook interpreter must be an absolute path, got ''"),
        ("/usr/bin/python3", "src", "aegis import root must be an absolute path, got 'src'"),
    ],
)
def test_relative_interpreter_or_import_root_is_refused(python, import_root, message):
    """A relative path would resolve against the repository the hook runs in."""
    with pytest.raises(ValueError) as exc:
        generate_hook_block(python, import_root=import_root)
    assert str(exc.value) == message


def test_install_with_a_relative_interpreter_writes_nothing(tmp_path):
    project = bare_repo(tmp_path / "p")
    with pytest.raises(ValueError):
        install_hook(project, python="python3")
    assert list((project / ".git" / "hooks").iterdir()) == []


def _work_tree_warning(hook_file: Path) -> str:
    return (f"Warning: {hook_file} is inside the work tree (core.hooksPath) and pins this "
            "machine's Python; do not commit it, or other clones fail closed until they run "
            "aegis hook install.\n")


def aegis_repo(path: Path, hooks_path=None) -> Path:
    project = git_repo(path)
    (project / ".aegis" / "rules").mkdir(parents=True)
    if hooks_path is not None:
        subprocess.run(["git", "config", "core.hooksPath", str(hooks_path)], cwd=str(project), check=True)
    return project


def test_install_warns_when_core_hooks_path_is_inside_the_work_tree(tmp_path, capsys):
    from aegis_cli.cli import main

    project = aegis_repo(tmp_path / "p", ".githooks")
    rc = main(["hook", "install", "--workspace", str(project)])
    hook = (project / ".githooks" / "pre-commit").resolve()
    captured = capsys.readouterr()
    assert rc == 0
    assert hook.is_file()
    assert captured.err == _work_tree_warning(hook)


def test_status_reports_a_hooks_dir_inside_the_work_tree(tmp_path, capsys):
    from aegis_cli.cli import main

    project = aegis_repo(tmp_path / "p", ".githooks")
    install_hook(project, python=sys.executable)
    hook = (project / ".githooks" / "pre-commit").resolve()

    assert main(["hook", "status", "--json", "--workspace", str(project)]) == 0
    assert json.loads(capsys.readouterr().out)["hooks_dir_in_work_tree"] is True
    assert main(["hook", "status", "--workspace", str(project)]) == 0
    assert capsys.readouterr().err == _work_tree_warning(hook)


@pytest.mark.parametrize("where", ["git-dir", "outside"])
def test_no_warning_when_the_hooks_dir_is_not_in_the_work_tree(tmp_path, capsys, where):
    from aegis_cli.cli import main

    shared = tmp_path / "shared-hooks"
    project = aegis_repo(tmp_path / "p", shared if where == "outside" else None)
    assert main(["hook", "install", "--workspace", str(project)]) == 0
    assert capsys.readouterr().err == ""
    assert main(["hook", "status", "--json", "--workspace", str(project)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["hooks_dir_in_work_tree"] is False
    assert captured.err == ""


def _init(project: Path, tmp_path: Path, monkeypatch) -> int:
    from aegis_cli.cli import main

    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(project)
    return main(["init", "--yes"])


def test_init_warns_when_core_hooks_path_is_inside_the_work_tree(tmp_path, monkeypatch, capsys):
    """init is the main entry point; it pins the same machine paths as hook install."""
    project = git_repo(tmp_path / "p")
    subprocess.run(["git", "config", "core.hooksPath", ".githooks"], cwd=str(project), check=True)
    rc = _init(project, tmp_path, monkeypatch)
    hook = (project / ".githooks" / "pre-commit").resolve()
    captured = capsys.readouterr()
    assert rc == 0
    assert hook.is_file()
    assert f"Pre-commit hook installed ({hook})" in captured.out
    assert ".git/hooks/pre-commit" not in captured.out
    assert _work_tree_warning(hook) in captured.err


def test_init_names_the_hook_it_wrote_without_a_warning_under_git_dir(tmp_path, monkeypatch, capsys):
    project = git_repo(tmp_path / "p")
    rc = _init(project, tmp_path, monkeypatch)
    hook = (project / ".git" / "hooks" / "pre-commit").resolve()
    captured = capsys.readouterr()
    assert rc == 0
    assert hook.is_file()
    assert f"Pre-commit hook installed ({hook})" in captured.out
    assert "inside the work tree" not in captured.err
