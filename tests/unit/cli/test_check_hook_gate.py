"""`aegis check --hook`: the command the installed git pre-commit hook runs (defense #21).

Ported from tests/unit/core/test_precommit_layer1.py, which exercised the
parallel `run_pre_commit` implementation that no installed hook ever called.
These run the real `check --hook` path against staged files in a temp repo.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from aegis_cli.cli import main

CLEAN = "def add(a: int, b: int) -> int:\n    return a + b\n"

GATE_RULE = (
    "---\n"
    "id: no-subprocess-run\n"
    "type: invariant\n"
    "enforcement: gate\n"
    "hypothesis: Production code never shells out.\n"
    "target_paths:\n"
    "  - src/*\n"
    "forbid_ast:\n"
    "  calls:\n"
    "    - subprocess.run\n"
    "---\n"
    "# No subprocess.run\n"
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Tester")
    monkeypatch.chdir(root)
    return root


def _stage(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _git(repo, "add", rel)


def test_clean_staged_python_file_passes(repo, capsys):
    _stage(repo, "calculator.py", CLEAN)
    assert main(["check", "--hook"]) == 0
    assert "PASSED" in capsys.readouterr().out


def test_staged_unguarded_third_party_import_blocks(repo, capsys):
    _stage(repo, "calculator.py", CLEAN)
    _stage(repo, "aegis_core/bad_mod.py", "import google.genai\n\ndef run():\n    return 1\n")
    assert main(["check", "--hook"]) == 1
    out = capsys.readouterr().out
    assert "import_guard" in out
    assert "google" in out


def test_json_mode_reports_the_blocking_check(repo, capsys):
    _stage(repo, "aegis_core/bad_mod.py", "import google.genai\n\ndef run():\n    return 1\n")
    assert main(["check", "--hook", "--json"]) == 1
    out = capsys.readouterr().out
    assert '"passed": false' in out
    assert '"import_guard"' in out


def _entries_naming(node, name):
    if isinstance(node, dict):
        if name in (node.get("tool"), node.get("check")):
            yield node
        for value in node.values():
            yield from _entries_naming(value, name)
    elif isinstance(node, list):
        for value in node:
            yield from _entries_naming(value, name)


def test_json_mode_stdout_is_one_document_naming_the_blocking_check(repo, capsys):
    """The removed `hook pre-commit --json` printed one parseable document; `check --hook --json` must too."""
    _stage(repo, "aegis_core/bad_mod.py", "import google.genai\n\ndef run():\n    return 1\n")
    assert main(["check", "--hook", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    blocking = [e for e in _entries_naming(payload, "import_guard") if e.get("verdict") is not True]
    assert blocking, payload


def test_gate_rule_under_aegis_rules_blocks_a_forbid_ast_hit(repo, capsys):
    """BUG-100: rules under .aegis/rules are the ones the commit gate enforces."""
    _stage(repo, ".aegis/rules/invariants/no-subprocess-run.md", GATE_RULE)
    _stage(repo, "src/runner.py", "import subprocess\n\ndef go():\n    subprocess.run(['ls'])\n")
    assert main(["check", "--hook"]) == 1
    out = capsys.readouterr().out
    assert "forbid_ast:no-subprocess-run" in out
    assert "subprocess.run" in out


def test_gate_rule_passes_a_compliant_file(repo):
    _stage(repo, ".aegis/rules/invariants/no-subprocess-run.md", GATE_RULE)
    _stage(repo, "src/runner.py", CLEAN)
    assert main(["check", "--hook"]) == 0


# ── The hook checks the index: what `git commit` records, not the working tree ──

NO_EVAL = (
    "---\n"
    "id: no-eval\n"
    "type: invariant\n"
    "enforcement: gate\n"
    "forbid_ast:\n"
    "  calls: [eval]\n"
    "---\n"
    "# No eval\n"
)
EVAL = "x = eval(input())\n"
SAFE = "x = 1\n"


def _commit(repo: Path, message: str = "c") -> None:
    _git(repo, "commit", "-q", "--no-verify", "-m", message)


@pytest.fixture
def governed(repo):
    """The repo with the no-eval gate rule and a clean app.py committed."""
    _stage(repo, ".aegis/rules/invariants/no-eval.md", NO_EVAL)
    _stage(repo, "app.py", SAFE)
    _commit(repo, "base")
    return repo


def test_a_staged_violation_blocks_even_when_the_working_copy_no_longer_has_it(governed, capsys):
    _stage(governed, "app.py", EVAL)
    (governed / "app.py").write_text(SAFE, encoding="utf-8")  # unstaged: the commit still records eval

    assert main(["check", "--hook"]) == 1
    out = capsys.readouterr().out
    assert "forbid_ast:no-eval: app.py" in out
    assert "PASSED" not in out


def test_an_unstaged_violation_never_blocks_a_clean_staged_commit(governed, capsys):
    _stage(governed, "other.py", "y = 2\n")
    (governed / "app.py").write_text(EVAL, encoding="utf-8")  # not staged: not part of the commit

    assert main(["check", "--hook"]) == 0
    out = capsys.readouterr().out
    assert "forbid_ast" not in out
    assert "PASSED" in out


def test_a_staged_file_deleted_from_the_working_tree_is_still_checked(governed, capsys):
    _stage(governed, "app.py", EVAL)
    (governed / "app.py").unlink()

    assert main(["check", "--hook"]) == 1
    assert "forbid_ast:no-eval: app.py" in capsys.readouterr().out


def test_hook_targets_are_the_staged_files_reported_repo_relative(repo, capsys):
    _stage(repo, ".aegis/rules/invariants/no-subprocess-run.md", GATE_RULE)
    _commit(repo, "rules")
    _stage(repo, "src/runner.py", "import subprocess\n\ndef go():\n    subprocess.run(['ls'])\n")
    (repo / "src" / "runner.py").write_text(CLEAN, encoding="utf-8")
    (repo / "notes.py").write_text("y = 1\n", encoding="utf-8")  # untracked: not committed, not checked

    assert main(["check", "--hook", "--json"]) == 1
    stdout = capsys.readouterr().out
    payload = json.loads(stdout)
    assert payload["files"] == ["src/runner.py"]
    failing = [e for e in payload["layer1"] if not e["verdict"]]
    assert [(e["tool"], e["target"]) for e in failing] == [("forbid_ast:no-subprocess-run", "src/runner.py")]
    assert "aegis-index-" not in stdout  # the snapshot directory never leaks into the report


def test_rule_target_paths_match_the_staged_path(repo):
    _stage(repo, ".aegis/rules/invariants/no-subprocess-run.md", GATE_RULE)
    _commit(repo, "rules")
    _stage(repo, "lib/runner.py", "import subprocess\n\ndef go():\n    subprocess.run(['ls'])\n")

    assert main(["check", "--hook"]) == 0  # the rule names src/* only


@pytest.mark.parametrize("folder", ["", "scripts/"])
def test_a_staged_module_importing_an_unchanged_sibling_passes(repo, capsys, folder):
    _stage(repo, f"{folder}helper.py", "def value():\n    return 1\n")
    _commit(repo, "helper")
    _stage(repo, f"{folder}main.py", "import helper\n\n\ndef run():\n    return helper.value()\n")

    assert main(["check", "--hook"]) == 0, capsys.readouterr().out


def test_nothing_staged_checks_no_files(governed, capsys):
    (governed / "app.py").write_text(EVAL, encoding="utf-8")

    assert main(["check", "--hook"]) == 0
    out = capsys.readouterr().out
    assert "Layer 1: 0 files staged" in out
    assert "forbid_ast" not in out


def test_hook_outside_a_git_work_tree_fails_closed(tmp_path, monkeypatch, capsys):
    plain = tmp_path / "plain"
    (plain / ".aegis" / "rules" / "invariants").mkdir(parents=True)
    (plain / "app.py").write_text(EVAL, encoding="utf-8")
    monkeypatch.chdir(plain)

    assert main(["check", "--hook"]) == 1
    captured = capsys.readouterr()
    assert "cannot read the staged changes" in captured.err
    assert "PASSED" not in captured.out


@pytest.mark.skipif(os.name == "nt", reason="runs git's pre-commit hook through /bin/sh")
@pytest.mark.parametrize("commit", [["commit", "-m", "x", "app.py"], ["commit", "-a", "-m", "x"]],
                         ids=["only-paths", "all"])
def test_the_installed_hook_checks_the_index_git_commit_builds(governed, commit):
    """`git commit <paths>` and `git commit -a` stage into a temporary index (GIT_INDEX_FILE)."""
    from aegis_cli.hooks.management import install_hook

    assert install_hook(governed)
    (governed / "app.py").write_text(EVAL, encoding="utf-8")  # unstaged: the commit itself stages it

    proc = subprocess.run(["git", *commit], cwd=str(governed), capture_output=True, text=True, timeout=120)

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "forbid_ast:no-eval: app.py" in proc.stdout + proc.stderr  # git sends hook output to stderr
    log = subprocess.run(["git", "log", "--oneline"], cwd=str(governed), capture_output=True, text=True).stdout
    assert len(log.splitlines()) == 1


@pytest.mark.parametrize("hook", [True, False], ids=["hook", "working-tree"])
def test_a_workspace_below_the_git_toplevel_checks_its_own_files(repo, monkeypatch, capsys, hook):
    """git names changed files from the top of the work tree; the workspace's checks need
    them relative to the workspace, and a file outside it is not its to check."""
    pkg = repo / "pkg"
    _stage(repo, "pkg/.aegis/rules/invariants/no-eval.md", NO_EVAL)
    _stage(repo, "pkg/app.py", SAFE)
    _stage(repo, "other/tool.py", SAFE)
    _commit(repo, "base")
    _stage(repo, "pkg/app.py", EVAL)
    _stage(repo, "other/tool.py", EVAL)
    monkeypatch.chdir(pkg)

    assert main(["check", "--hook", "--json"] if hook else ["check", "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["files"] == ["app.py"]
    assert [(e["tool"], e["target"]) for e in payload["layer1"] if not e["verdict"]] == [("forbid_ast:no-eval", "app.py")]


def test_a_workspace_the_enclosing_repository_does_not_track_enforces_its_own_rules(repo, monkeypatch, capsys):
    """Given a workspace in a directory the enclosing repository never committed (a project inside
    a $HOME repository), When plain ``aegis check`` runs on it, Then its own gate rules are enforced:
    that repository's base holds no reviewed rules for it, which must not mean no rules."""
    _stage(repo, "README.md", "# home\n")
    _commit(repo, "home")
    pkg = repo / "project"
    (pkg / ".aegis" / "rules" / "invariants").mkdir(parents=True)
    (pkg / ".aegis" / "rules" / "invariants" / "no-eval.md").write_text(NO_EVAL, encoding="utf-8")
    (pkg / "app.py").write_text(EVAL, encoding="utf-8")
    monkeypatch.chdir(pkg)

    assert main(["check", "--format", "json", "app.py"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert ("forbid_ast:no-eval", "app.py") in [(e["tool"], e["target"]) for e in payload["layer1"] if not e["verdict"]]


# ── The hook reads from git only what a check can read ──────────────────────

def _staged_oid(repo: Path, rel: str) -> str:
    out = subprocess.run(["git", "rev-parse", f":{rel}"], cwd=str(repo), check=True, capture_output=True, text=True)
    return out.stdout.strip()


@pytest.fixture
def blob_reads(monkeypatch):
    """The object ids each `git cat-file --batch` call asked for: the content git hands over."""
    from aegis_core import gitsafe

    real_run, asked = gitsafe.run, []

    def spy(args, cwd, *rest, **kwargs):
        if list(args[:2]) == ["cat-file", "--batch"]:
            asked.extend((kwargs.get("stdin") or b"").decode("ascii").split())
        return real_run(args, cwd, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", spy)
    return asked


def test_a_staged_file_no_check_can_read_is_never_read_from_git(repo, blob_reads, capsys):
    (repo / "asset.bin").write_bytes(os.urandom(1 << 20))
    _git(repo, "add", "asset.bin")
    _stage(repo, ".env", "API_TOKEN=not-a-real-token\n")
    _stage(repo, "app.py", SAFE)

    assert main(["check", "--hook"]) == 0, capsys.readouterr().out
    assert _staged_oid(repo, "app.py") in blob_reads
    assert _staged_oid(repo, "asset.bin") not in blob_reads
    assert _staged_oid(repo, ".env") not in blob_reads


def _oversized_source(runner_module) -> str:
    line = "x = 1\n"
    return line * (runner_module.INDEX_BLOB_LIMIT_BYTES // len(line) + 1)


def test_an_oversized_staged_source_file_a_gate_rule_covers_fails_closed(governed, blob_reads, capsys):
    from aegis_core.verification import runner

    _stage(governed, "big.py", _oversized_source(runner))

    assert main(["check", "--hook"]) == 1
    out = capsys.readouterr().out
    assert "forbid_ast:no-eval: big.py" in out
    assert "over the" in out and "PASSED" not in out
    assert _staged_oid(governed, "big.py") not in blob_reads


def test_an_oversized_staged_source_file_no_rule_covers_is_skipped_and_said(repo, blob_reads, capsys):
    from aegis_core.verification import runner

    _stage(repo, "big.py", _oversized_source(runner))
    _stage(repo, "app.py", SAFE)

    assert main(["check", "--hook"]) == 0
    out = capsys.readouterr().out
    assert "big.py not checked" in out
    assert _staged_oid(repo, "big.py") not in blob_reads


def test_a_block_on_an_import_of_an_untracked_sibling_says_why(repo, capsys):
    """The commit would not include the sibling, so the hook does not count it as local."""
    (repo / ".gitignore").write_text("local_settings.py\n", encoding="utf-8")
    (repo / "local_settings.py").write_text("SECRET = 1\n", encoding="utf-8")
    _stage(repo, "settings.py", "from local_settings import SECRET\n")

    assert main(["check", "--hook"]) == 1
    out = capsys.readouterr().out
    assert "import_guard: settings.py" in out
    assert "local_settings.py is not staged or tracked" in out


# ── Files an AST driver parses (Rust here) are read from the index snapshot too ──
# Regression (v4.0.0): the snapshot lives outside the repository, and the driver path
# confined it to the repository, so every staged .rs file failed with "escapes workspace".

RUST_CLEAN = "fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n\nfn main() {\n    println!(\"{}\", add(1, 2));\n}\n"
RUST_DANGER = "fn main() {\n    danger();\n}\n"
NO_DANGER = (
    "---\n"
    "id: no-danger\n"
    "type: invariant\n"
    "enforcement: gate\n"
    "hypothesis: Rust code never calls danger.\n"
    "target_paths:\n"
    "  - \"src/*.rs\"\n"
    "forbid_ast:\n"
    "  calls:\n"
    "    - danger\n"
    "---\n"
    "# No danger\n"
)


@pytest.fixture
def rust_repo(repo):
    """The repo with the packaged Rust driver turned on, as `aegis init` does for Rust projects."""
    (repo / ".aegis").mkdir()
    (repo / ".aegis" / "config.json").write_text('{"v": 1, "ast": {"packaged_drivers": ["rs"]}}', encoding="utf-8")
    return repo


def test_a_staged_rust_file_is_parsed_from_the_snapshot_not_refused_as_escaping(rust_repo, capsys):
    _stage(rust_repo, "src/main.rs", RUST_CLEAN)
    rc = main(["check", "--hook"])
    out = capsys.readouterr().out
    assert "escapes" not in out
    assert rc == 0, out


def test_a_gate_rule_catches_a_forbidden_call_in_a_staged_rust_file(rust_repo, capsys):
    _stage(rust_repo, ".aegis/rules/invariants/no-danger.md", NO_DANGER)
    _stage(rust_repo, "src/main.rs", RUST_DANGER)
    rc = main(["check", "--hook"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "forbid_ast:no-danger" in out and "danger" in out
    assert "escapes" not in out
