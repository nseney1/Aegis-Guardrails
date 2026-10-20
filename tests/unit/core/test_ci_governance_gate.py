"""`aegis check --ci` gates the governance set, not only rule weakenings (v4.3 spec 2.2, 2.3).

Given a base whose ``allowed_signers`` lists a key, a pull request that changes the files that
bind the agent (allowed_signers, CODEOWNERS, workflows, .aegis config/team/baseline, test
infrastructure, a deleted test) passes only with a signed approval from a key on the BASE.
Rule edits stay under the weakening check; ``pyproject.toml``, ``setup.cfg`` and ``tox.ini``
count only when their pytest section changes. With no key at the base nobody could sign, so the
change is noted and passes (tier C). Real git and ssh-keygen; no network, no host CLI.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest

from aegis_cli.cli import main
from aegis_core import gitsafe, human_gate
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")

RULE = ("---\nid: gate-no-eval\ntype: gate\nenforcement: gate\nhypothesis: Never eval\n"
        "target_paths:\n  - 'src/*.py'\nforbid_ast:\n  calls:\n    - eval\n---\n# No eval\n\nThe body explains why.\n")
GATE = ".aegis/rules/gates/gate-no-eval.md"
PYPROJECT = '[project]\nname = "x"\nversion = "1.0.0"\n\n[tool.pytest.ini_options]\naddopts = "-q"\n'
SETUP_CFG = "[metadata]\nname = x\n\n[tool:pytest]\naddopts = -q\n"
TOX_INI = "[tox]\nenvlist = py\n\n[pytest]\naddopts = -q\n"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("SSH_AUTH_SOCK", "GIT_CONFIG_GLOBAL", "GITHUB_BASE_REF", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY",
                 "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


@pytest.fixture
def keys(tmp_path):
    human, human_pub = hg.keygen(tmp_path / "keys", "human")
    agent, agent_pub = hg.keygen(tmp_path / "keys", "agent")
    return {"human": human, "human_pub": human_pub, "agent": agent, "agent_pub": agent_pub}


def make_repo(tmp_path: Path, signer_pub: Optional[str] = None) -> hg.Repo:
    """main: a gate rule, sources, a test, conftest.py, pytest sections in pyproject.toml,
    setup.cfg and tox.ini, a workflow and (with ``signer_pub``) allowed_signers; ``work`` is
    checked out."""
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "def app():\n    return 1\n")
    repo.write("tests/test_app.py", "def test_app():\n    assert True\n")
    repo.write("tests/test_other.py", "def test_other():\n    assert True\n")
    repo.write("conftest.py", "# shared fixtures\n")
    repo.write("pyproject.toml", PYPROJECT)
    repo.write("setup.cfg", SETUP_CFG)
    repo.write("tox.ini", TOX_INI)
    repo.write("sub/pyproject.toml", '[project]\nname = "sub"\n')
    repo.write(".github/workflows/ci.yml", "name: CI\non: [pull_request]\njobs:\n  aegis:\n    runs-on: ubuntu-latest\n")
    repo.write(GATE, RULE)
    if signer_pub is not None:
        repo.write("allowed_signers", hg.allowed_signers_text(signer_pub))
    repo.commit("base")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    return repo


def run_ci(repo: hg.Repo, capsys, *extra: str) -> Tuple[int, str, str]:
    os.chdir(repo.root)
    try:
        rc = main(["check", "--ci", "--base", "main", *extra])
    except SystemExit as exc:
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def ci_json(repo: hg.Repo, capsys) -> Tuple[int, Dict[str, Any]]:
    rc, out, err = run_ci(repo, capsys, "--format", "json")
    assert out.strip(), err
    return rc, json.loads(out)


def approve(repo: hg.Repo, key: Path) -> str:
    digest = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    return repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=key, allow_empty=True)


def edit(repo: hg.Repo, path: str, text: str) -> None:
    existing = (repo.root / path).read_text(encoding="utf-8") if (repo.root / path).exists() else ""
    repo.write(path, existing + text)


# Each is in the governance set and is not a rule, so only the governance gate catches it.
GOVERNANCE_EDITS = [
    ("allowed_signers", "signers", None),
    ("CODEOWNERS", "signers", "* @octo\n"),
    (".github/workflows/evil.yml", "workflows", "name: evil\n"),
    (".github/workflows/ci.yml", "workflows", "# changed\n"),
    (".aegis/config.json", "aegis-state", None),
    (".aegis/baseline.json", "aegis-state", None),
    ("conftest.py", "test-infra", "# changed\n"),
    ("pyproject.toml", "test-infra", None),
    ("Makefile", "test-infra", "test:\n\ttrue\n"),
]


@needs_git
@needs_signing
@pytest.mark.parametrize("path,category,text", GOVERNANCE_EDITS, ids=[
    "signers", "codeowners", "new-wf", "wf", "config", "baseline", "conftest", "pyproject", "make"])
def test_a_governance_change_fails_without_approval_and_passes_with_a_base_key(tmp_path, capsys, keys, path,
                                                                               category, text):
    repo = make_repo(tmp_path, keys["human_pub"])
    if path == "allowed_signers":
        edit(repo, path, hg.allowed_signers_text(keys["agent_pub"]))
    elif path == ".aegis/config.json":
        repo.write(path, '{"v": 1}\n')
    elif path == ".aegis/baseline.json":
        repo.write(path, '{"v": 1, "findings": []}\n')
    elif path == "pyproject.toml":
        repo.write(path, PYPROJECT.replace('addopts = "-q"', 'addopts = "-q -p no:randomly"'))
    else:
        edit(repo, path, text)
    repo.commit("agent change")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["status"] == "fail" and payload["weakenings"] == []
    assert payload["governance"] == {"categories": [category], "paths": [{"path": path, "category": category}],
                                     "enforced": True, "approved": False}
    assert payload["approval"] is None
    approve(repo, keys["human"])
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["approval"]["valid"] is True and payload["governance"]["approved"] is True


@needs_git
@needs_signing
def test_an_agent_cannot_approve_its_own_signer_addition(tmp_path, capsys, keys):
    """The two-pull-request takeover: pull request one adds the agent's key with a workflow; it must
    not pass, whether the key it adds signs it or nobody does."""
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write("allowed_signers", hg.allowed_signers_text(keys["human_pub"], keys["agent_pub"]))
    repo.write(".github/workflows/evil.yml", "name: evil\n")
    repo.commit("add a signer and a workflow")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["governance"]["categories"] == ["signers", "workflows"]
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 1 and "FAILED: governance change without approval" in out
    approve(repo, keys["agent"])
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["status"] == "fail"
    assert payload["approval"] is None or payload["approval"]["valid"] is False
    approve(repo, keys["human"])
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0 and "approved by" in out


@needs_git
@needs_signing
@pytest.mark.parametrize("how", ["delete", "move"])
def test_removing_or_moving_a_governance_file_needs_an_approval(tmp_path, capsys, keys, how):
    repo = make_repo(tmp_path, keys["human_pub"])
    if how == "delete":
        (repo.root / "allowed_signers").unlink()
    else:
        repo.git("mv", "conftest.py", "fixtures_old.py")
    repo.commit(how)
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["governance"]["categories"] == (["signers"] if how == "delete" else ["test-infra"])


@needs_git
@needs_signing
def test_an_approval_is_void_after_a_further_governance_change(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    edit(repo, "conftest.py", "# changed\n")
    repo.commit("change")
    approve(repo, keys["human"])
    edit(repo, ".github/workflows/ci.yml", "# then another\n")
    repo.commit("then another")
    rc, _payload = ci_json(repo, capsys)
    assert rc == 1


@needs_git
@needs_signing
def test_a_change_outside_the_governance_set_passes_without_approval(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.write("README.md", "# docs\n")
    repo.commit("code and docs")
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["status"] == "pass"
    assert payload["governance"] == {"categories": [], "paths": [], "enforced": False, "approved": False}


def _aegis_approve(repo: hg.Repo, monkeypatch, key: Path) -> int:
    from aegis_cli import approve as approve_cli

    repo.home.sign_with(str(key))
    monkeypatch.setattr(approve_cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    args = argparse.Namespace(workspace=str(repo.root), json=True, base="main")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return approve_cli.run_approve(args)


@needs_git
@needs_signing
def test_deleting_a_test_needs_the_approval_aegis_approve_makes(tmp_path, capsys, monkeypatch, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.git("rm", "-q", "tests/test_app.py")
    repo.commit("remove a test")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["governance"]["categories"] == ["tests-deleted"]
    assert _aegis_approve(repo, monkeypatch, keys["human"]) == 0
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["approval"]["valid"] is True


@needs_git
@needs_signing
@pytest.mark.parametrize("label,path,text", [
    ("stricter", GATE, RULE.replace("    - eval\n", "    - eval\n    - exec\n")),
    ("advisory", ".aegis/rules/traps/trap-new.md",
     "---\nid: trap-new\ntype: trap\nenforcement: advisory\nhypothesis: h\ntarget_paths:\n  - 'src/*.py'\n---\n# T\n\nBody.\n"),
], ids=["stricter", "advisory"])
def test_a_rule_edit_that_weakens_nothing_needs_no_approval(tmp_path, capsys, keys, label, path, text):
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write(path, text)
    repo.commit(label)
    rc, payload = ci_json(repo, capsys)
    assert rc == 0, payload
    assert payload["weakenings"] == [] and payload["governance"]["categories"] == []


@needs_git
def test_a_base_with_no_signing_key_notes_the_change_and_passes(tmp_path, capsys, keys):
    """Adopting tier B is itself a pull request that adds allowed_signers: nobody can sign it yet."""
    repo = make_repo(tmp_path)
    repo.write("allowed_signers", hg.allowed_signers_text(keys["human_pub"]))
    repo.write(".github/workflows/evil.yml", "name: evil\n")
    repo.write(".aegis/baseline.json", '{"v": 1, "findings": []}\n')
    repo.commit("set up tier B")
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["status"] == "pass"
    assert payload["governance"]["enforced"] is False
    assert payload["governance"]["categories"] == ["aegis-state", "signers", "workflows"]
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0 and "no key in allowed_signers" in out and "tier C: detection only" in out
    rc, out, _err = run_ci(repo, capsys, "--format", "github")
    assert rc == 0 and [line for line in out.splitlines() if line.startswith("::")] == [
        next(line for line in out.splitlines() if line.startswith("::warning"))]
    assert "title=governance change not enforced" in out


@needs_git
def test_a_weakening_on_a_base_with_no_signing_key_still_fails(tmp_path, capsys):
    repo = make_repo(tmp_path)
    (repo.root / GATE).unlink()
    edit(repo, ".github/workflows/ci.yml", "# changed\n")
    repo.commit("drop the gate")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and [w["code"] for w in payload["weakenings"]] == ["deleted"]
    assert payload["governance"]["enforced"] is False


@needs_git
@needs_signing
def test_the_text_annotations_and_sarif_agree_with_the_exit_code(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write(".github/workflows/evil.yml", "name: evil\n")
    repo.write("allowed_signers", hg.allowed_signers_text(keys["human_pub"], keys["agent_pub"]))
    repo.commit("agent change")
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 1 and "FAILED: governance change without approval (2 path(s) in signers, workflows" in out
    assert "PASSED" not in out
    assert "[governance:workflows] .github/workflows/evil.yml" in out and "[governance:signers] allowed_signers" in out
    rc, out, _err = run_ci(repo, capsys, "--format", "github")
    errors = [line for line in out.splitlines() if line.startswith("::error")]
    assert rc == 1 and len(errors) == 2 and all("title=governance change without approval" in e for e in errors)
    assert any("file=allowed_signers" in e for e in errors) and "PASSED" not in out
    rc, out, _err = run_ci(repo, capsys, "--format", "sarif")
    results = json.loads(out)["runs"][0]["results"]
    assert rc == 1 and sorted(r["ruleId"] for r in results) == ["governance:signers", "governance:workflows"]
    approve(repo, keys["human"])
    rc, out, _err = run_ci(repo, capsys, "--format", "github")
    notices = [line for line in out.splitlines() if line.startswith("::notice")]
    assert rc == 0 and len(notices) == 2 and not [line for line in out.splitlines() if line.startswith("::error")]
    rc, out, _err = run_ci(repo, capsys, "--format", "sarif")
    assert rc == 0 and json.loads(out)["runs"][0]["results"] == []
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0 and "PASSED, 2 governance path(s) approved by" in out and "FAILED" not in out


@needs_git
@needs_signing
def test_a_weakening_and_a_governance_change_share_one_approval(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    (repo.root / GATE).unlink()
    edit(repo, "conftest.py", "# changed\n")
    repo.commit("drop the gate and change conftest")
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 1 and "FAILED: weakening and governance change without approval (1 finding(s), 1 path(s)" in out
    assert "[deleted] gate-no-eval" in out and "[governance:test-infra] conftest.py" in out
    approve(repo, keys["human"])
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["approval"]["valid"] is True and payload["governance"]["approved"] is True


# ── pyproject.toml, setup.cfg and tox.ini count by their pytest section ─────

@needs_git
@needs_signing
@pytest.mark.parametrize("path,old,new", [
    ("pyproject.toml", 'addopts = "-q"', 'addopts = "-q"\npythonpath = ["src"]'),
    ("pyproject.toml", 'addopts = "-q"', 'addopts = "-q"\nrequired_plugins = ["evil"]'),
    ("setup.cfg", "addopts = -q", "addopts = -q -x"),
    ("tox.ini", "addopts = -q", "addopts = -q -x"),
], ids=["pythonpath", "plugins", "setup", "tox"])
def test_a_pytest_section_edit_is_gated(tmp_path, capsys, keys, path, old, new):
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write(path, (repo.root / path).read_text(encoding="utf-8").replace(old, new))
    repo.commit("edit the pytest section")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["governance"]["paths"] == [{"path": path, "category": "test-infra"}]
    approve(repo, keys["human"])
    assert ci_json(repo, capsys)[0] == 0


@needs_git
@needs_signing
def test_a_version_bump_outside_the_pytest_sections_is_not_gated(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write("pyproject.toml", PYPROJECT.replace('version = "1.0.0"', 'version = "1.0.1"')
               .replace('addopts = "-q"', 'addopts  =  "-q"   # quiet, reformatted'))
    repo.write("setup.cfg", SETUP_CFG.replace("name = x", "name = y"))
    repo.write("tox.ini", TOX_INI.replace("envlist = py", "envlist = py312"))
    repo.commit("bump")
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["governance"] == {"categories": [], "paths": [], "enforced": False, "approved": False}


@needs_git
@needs_signing
@pytest.mark.parametrize("change", ["unparsable", "deleted", "gains", "with-workflow"])
def test_a_pytest_view_that_cannot_be_shown_equal_stays_gated(tmp_path, capsys, keys, change):
    repo = make_repo(tmp_path, keys["human_pub"])
    if change == "unparsable":
        repo.write("pyproject.toml", PYPROJECT + "[tool.pytest.ini_options\n")
    elif change == "deleted":
        (repo.root / "pyproject.toml").unlink()
    elif change == "gains":
        repo.write("sub/pyproject.toml", '[project]\nname = "sub"\n\n[tool.pytest.ini_options]\naddopts = "-x"\n')
    else:
        repo.write("pyproject.toml", PYPROJECT.replace('version = "1.0.0"', 'version = "2.0.0"'))
        edit(repo, ".github/workflows/ci.yml", "# changed\n")
    repo.commit(change)
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["governance"]["enforced"] is True
    expected = ["workflows"] if change == "with-workflow" else ["test-infra"]
    assert payload["governance"]["categories"] == expected


def _set_base(repo: hg.Repo, files: Dict[str, str]) -> None:
    """Commit ``files`` on ``work`` and move ``main`` (the base) to that commit."""
    for path, text in files.items():
        repo.write(path, text)
    repo.commit("base files", allow_empty=True)
    repo.git("branch", "-f", "main", "HEAD")


def _stage_symlink(repo: hg.Repo, path: str, target: str) -> None:
    """Stage ``path`` as a symlink (mode 120000) whose link text is ``target``, without touching the
    work tree, so it works where the OS refuses symlinks."""
    oid = repo.git("hash-object", "-w", "--stdin", stdin=target)
    repo.git("update-index", "--add", "--cacheinfo", f"120000,{oid},{path}")


def _commit_index(repo: hg.Repo, message: str, sign_key: Optional[Path] = None) -> None:
    """Commit what is staged as is (``Repo.commit`` would re-add the work tree over a staged symlink)."""
    args = ["commit", "-q", "--allow-empty", "-m", message]
    if sign_key is not None:
        args = ["-c", "gpg.format=ssh", "-c", f"user.signingkey={sign_key}", *args, "-S"]
    repo.git(*args)


# Each base file holds no pytest section; the link text parses as a comment in its format (a TOML or
# ini comment), so a reader of the blob sees no pytest view on either side while pytest follows the
# link to a file that deselects the failing test.
SYMLINKED_CONFIGS = [
    ("sub/pyproject.toml", '[project]\nname = "sub"\n', "sub/evil.toml",
     '[tool.pytest.ini_options]\naddopts = "-k nothing_matches"\n', "#/../evil.toml"),
    ("sub/tox.ini", "[tox]\nenvlist = py\n", "sub/evil.ini", "[pytest]\naddopts = -k nothing_matches\n",
     "#/../evil.ini"),
    ("sub/setup.cfg", "[metadata]\nname = sub\n", "sub/evil.cfg", "[tool:pytest]\naddopts = -k nothing_matches\n",
     "#/../evil.cfg"),
]


@needs_git
@needs_signing
@pytest.mark.parametrize("path,base_text,target,target_text,link", SYMLINKED_CONFIGS,
                         ids=["pyproject", "tox", "setup"])
def test_a_pytest_config_file_replaced_by_a_symlink_is_gated_as_a_whole_file(tmp_path, capsys, keys, path,
                                                                            base_text, target, target_text, link):
    """Given a base whose config file has no pytest section, When the branch replaces it with a symlink
    (a type change, 100644 -> 120000) to a file that configures pytest, Then the gate does not compare
    the link text by section: the path needs the approval, and a signed one passes."""
    repo = make_repo(tmp_path, keys["human_pub"])
    _set_base(repo, {path: base_text})
    repo.write(target, target_text)
    repo.git("add", "--", target)
    repo.git("rm", "-q", "--cached", "--", path)
    _stage_symlink(repo, path, link)
    _commit_index(repo, "agent")
    assert repo.git("diff-tree", "-r", "--raw", "--no-renames", "main", "HEAD").count(" T\t" + path) == 1
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["governance"]["paths"] == [{"path": path, "category": "test-infra"}]
    assert payload["governance"]["enforced"] is True
    _commit_index(repo, f"approve\n\nAegis-Approve: {human_gate.governance_tree_hash(repo.root, 'HEAD', base='main')}\n",
                  sign_key=keys["human"])
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["approval"]["valid"] is True


@needs_git
@needs_signing
def test_a_symlinked_pytest_config_file_that_is_relinked_is_gated(tmp_path, capsys, keys):
    """Given a base where sub/pyproject.toml is already a symlink, When the branch points it elsewhere
    (mode 120000 on both sides), Then the change counts whole: both link texts parse as comments."""
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write("sub/a.toml", '[project]\nname = "sub"\n')
    repo.write("sub/b.toml", '[tool.pytest.ini_options]\naddopts = "-k nothing_matches"\n')
    repo.git("add", "--", "sub/a.toml", "sub/b.toml")
    repo.git("rm", "-q", "--cached", "--", "sub/pyproject.toml")
    _stage_symlink(repo, "sub/pyproject.toml", "#/../a.toml")
    _commit_index(repo, "base symlink")
    repo.git("branch", "-f", "main", "HEAD")
    _stage_symlink(repo, "sub/pyproject.toml", "#/../b.toml")
    _commit_index(repo, "relink")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["governance"]["paths"] == [{"path": "sub/pyproject.toml", "category": "test-infra"}]


@needs_git
@needs_signing
@pytest.mark.parametrize("direction,section_edit,gated", [
    ("+x", False, False),
    ("-x", False, False),
    ("+x", True, True),
], ids=["exec-on", "exec-off", "exec-and-section"])
def test_a_mode_change_between_regular_files_is_still_compared_by_section(tmp_path, capsys, keys, direction,
                                                                         section_edit, gated):
    """Given pyproject.toml as a regular file on both sides, When only its executable bit flips
    (100644 <-> 100755), Then the pytest view decides: unchanged stays ungated, a section edit is gated."""
    repo = make_repo(tmp_path, keys["human_pub"])
    if direction == "-x":
        repo.git("update-index", "--chmod=+x", "--", "pyproject.toml")
        _commit_index(repo, "executable at the base")
        repo.git("branch", "-f", "main", "HEAD")
    if section_edit:
        repo.write("pyproject.toml", PYPROJECT.replace('addopts = "-q"', 'addopts = "-k nothing_matches"'))
        repo.git("add", "--", "pyproject.toml")
    repo.git("update-index", f"--chmod={direction}", "--", "pyproject.toml")
    _commit_index(repo, "mode change")
    modes = repo.git("diff-tree", "-r", "--raw", "--no-renames", "main", "HEAD")
    assert ("100644 100755" if direction == "+x" else "100755 100644") in modes
    rc, payload = ci_json(repo, capsys)
    if gated:
        assert rc == 1 and payload["governance"]["paths"] == [{"path": "pyproject.toml", "category": "test-infra"}]
    else:
        assert rc == 0 and payload["governance"]["categories"] == []


@needs_git
@needs_signing
def test_an_unreadable_base_fails_the_check_with_an_error(tmp_path, capsys, monkeypatch, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    repo.write("pyproject.toml", PYPROJECT.replace('version = "1.0.0"', 'version = "1.0.1"'))
    repo.commit("bump")

    def unreadable(*_a, **_kw):
        raise gitsafe.GitError("git returned content that does not match the object id")

    monkeypatch.setattr(gitsafe, "read_blob", unreadable)
    rc, out, err = run_ci(repo, capsys, "--format", "json")
    assert rc == 1 and not out.strip() and err.startswith("Error:")


# ── an approval covers whole files, the gate their pytest section (R-trust-a2, option A) ──

@needs_git
@needs_signing
@pytest.mark.parametrize("base_change,needs_again", [
    ("version", True),
    ("pytest", True),
    ("readme", False),
], ids=["version", "pytest", "readme"])
def test_an_approval_signed_before_merging_the_base_holds_only_while_the_hashed_files_do(
        tmp_path, capsys, monkeypatch, keys, base_change, needs_again):
    """Given a signed base and a branch whose workflow edit carries a valid approval, When the base
    changes and the branch merges it, Then the approval still holds only if no governance blob
    changed: a version bump in pyproject.toml is outside the gate's pytest section but inside the
    hash, so it needs aegis approve again on the merged head."""
    repo = make_repo(tmp_path, keys["human_pub"])
    edit(repo, ".github/workflows/ci.yml", "# reviewed change\n")
    repo.commit("workflow change")
    approve(repo, keys["human"])
    assert ci_json(repo, capsys)[0] == 0
    repo.git("checkout", "-q", "main")
    if base_change == "version":
        repo.write("pyproject.toml", PYPROJECT.replace('version = "1.0.0"', 'version = "1.1.0"'))
    elif base_change == "pytest":
        repo.write("pyproject.toml", PYPROJECT.replace('addopts = "-q"', 'addopts = "-q -x"'))
    else:
        repo.write("README.md", "# project\n")
    repo.commit("base moves on")
    repo.git("checkout", "-q", "work")
    repo.git("merge", "-q", "--no-edit", "main")
    rc, payload = ci_json(repo, capsys)
    assert payload["governance"]["categories"] == ["workflows"]
    assert rc == (1 if needs_again else 0), payload
    if needs_again:
        assert _aegis_approve(repo, monkeypatch, keys["human"]) == 0
        assert ci_json(repo, capsys)[0] == 0
