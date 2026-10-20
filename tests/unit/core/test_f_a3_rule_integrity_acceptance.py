"""Acceptance contract for lane f-a3-rule-integrity (v4.3 spec T3, T2, section 9; v4.4 spec 12).

Given/When/Then, written before the code and never weakened to make it pass:

1. Weakening needs approval. An agent commit that deletes a gate rule (no signed approval) makes
   ``aegis check --ci`` fail with an itemized "weakening without approval" annotation; the same
   commit with a signed approval from a key in the BASE allowed_signers passes. Every other
   weakening the spec lists is flagged, and a strengthening is not.
2. Local edits don't bind. A branch-local edit to an invariant is not what ``aegis_scan`` serves:
   the BASE version is, and the edit appears in ``unreviewed_rules`` (id and title only). A new
   local invariant is never served as mandatory.
3. Release verification fails closed. With gh 2.45 on PATH, ``aegis doctor --release <sha>``
   prints "UNVERIFIED (gh >= 2.93.0 required)" and exits non-zero; with no gh at all, the same.
4. The one loader accepts ``applies_to`` as a known key and refuses ``expired_at`` on a rank 2+ rule.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Any, Dict, List, Optional, Tuple

import pytest

from aegis_cli.cli import main
from aegis_core import human_gate, rule_integrity, scan as scan_mod
from aegis_core.rules import load_rules
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")
posix_only = pytest.mark.skipif(os.name == "nt", reason="shell stubs")

TYPE_DIRS = {"gate": "gates", "invariant": "invariants", "trap": "traps", "boundary": "boundaries"}
SRC = ("src/*.py",)


def rule_text(rid: str, rtype: str = "gate", enforcement: str = "gate", paths: Tuple[str, ...] = SRC,
              forbid: Optional[Dict[str, List[str]]] = None, extra: str = "", hypothesis: str = "Never do the thing",
              body: str = "# Title of the rule\n\nThe body explains why the thing is forbidden here.\n") -> str:
    lines = ["---", f"id: {rid}", f"type: {rtype}", f"enforcement: {enforcement}", f"hypothesis: {hypothesis}"]
    if paths:
        lines.append("target_paths:")
        lines += [f"  - '{p}'" for p in paths]
    if forbid:
        lines.append("forbid_ast:")
        for key, values in forbid.items():
            lines.append(f"  {key}:")
            lines += [f"    - {v}" for v in values]
    if extra:
        lines.append(extra.rstrip("\n"))
    lines += ["---", body]
    return "\n".join(lines)


def rule_path(rid: str, rtype: str = "gate") -> str:
    return f".aegis/rules/{TYPE_DIRS[rtype]}/{rid}.md"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)


@pytest.fixture
def keys(tmp_path):
    human, human_pub = hg.keygen(tmp_path / "keys", "human")
    return {"human": human, "human_pub": human_pub}


def make_repo(tmp_path: Path, signer_pub: Optional[str] = None, origin: bool = True,
              rules: Optional[Dict[str, str]] = None) -> hg.Repo:
    """main: a gate, an invariant, a trap, sources (plus ``rules``, path to text); ``work`` is
    checked out. With ``origin`` the remote-tracking refs a clone has (origin/main, origin/HEAD)
    point at main's tip."""
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "project", home)
    repo.write("README.md", "# project\n")
    repo.write("src/app.py", "def app():\n    return 1\n")
    repo.write("src/util.py", "def util():\n    return 2\n")
    repo.write("lib/helper.py", "def helper():\n    return 3\n")
    repo.write(rule_path("gate-no-eval"), rule_text("gate-no-eval", "gate", forbid={"calls": ["eval"]}))
    repo.write(rule_path("inv-sample", "invariant"), rule_text("inv-sample", "invariant", "advisory"))
    repo.write(rule_path("trap-sample", "trap"), rule_text("trap-sample", "trap", "advisory", paths=("lib/*.py",)))
    for path, text in (rules or {}).items():
        repo.write(path, text)
    if signer_pub is not None:
        repo.write("allowed_signers", hg.allowed_signers_text(signer_pub))
    repo.commit("base")
    if origin:
        repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
        repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    return repo


def run_ci(repo: hg.Repo, capsys, *extra: str, base: str = "main") -> Tuple[int, str, str]:
    os.chdir(repo.root)
    try:
        rc = main(["check", "--ci", "--base", base, *extra])
    except SystemExit as exc:  # argparse
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def ci_json(repo: hg.Repo, capsys, *extra: str) -> Tuple[int, Dict[str, Any]]:
    rc, out, err = run_ci(repo, capsys, "--format", "json", *extra)
    assert out.strip(), err
    return rc, json.loads(out)


def codes(payload: Dict[str, Any]) -> List[Tuple[str, str]]:
    return sorted((w["code"], w["rule"]) for w in payload["weakenings"])


@pytest.fixture(autouse=True)
def _restore_cwd():
    before = os.getcwd()
    yield
    os.chdir(before)


# ── 1. weakening needs an approval the agent cannot produce ──────────────────

@needs_git
def test_deleting_a_gate_rule_without_approval_fails_with_an_itemized_annotation(tmp_path, capsys):
    repo = make_repo(tmp_path)
    (repo.root / rule_path("gate-no-eval")).unlink()
    repo.commit("drop the gate")
    rc, out, _err = run_ci(repo, capsys, "--format", "github")
    assert rc == 1
    annotations = [line for line in out.splitlines() if line.startswith("::error")]
    assert len(annotations) == 1
    assert "weakening without approval" in annotations[0]
    assert f"file={rule_path('gate-no-eval')}" in annotations[0]
    assert "gate-no-eval" in annotations[0]


@needs_git
def test_the_text_report_itemizes_each_weakening_and_says_no_approval(tmp_path, capsys):
    repo = make_repo(tmp_path)
    (repo.root / rule_path("gate-no-eval")).unlink()
    (repo.root / rule_path("inv-sample", "invariant")).unlink()
    repo.commit("drop both")
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 1
    assert "FAILED" in out and "weakening without approval" in out
    assert "gate-no-eval" in out and "inv-sample" in out


@needs_git
@needs_signing
def test_the_same_deletion_with_a_signed_approval_from_a_base_key_passes(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    (repo.root / rule_path("gate-no-eval")).unlink()
    repo.commit("drop the gate")
    digest = human_gate.governance_tree_hash(repo.root, "HEAD")
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    rc, payload = ci_json(repo, capsys)
    assert rc == 0, payload
    assert payload["status"] == "pass"
    assert [w["code"] for w in payload["weakenings"]] == ["deleted"]
    assert payload["approval"]["valid"] is True


@needs_git
@needs_signing
def test_an_unsigned_or_forged_approval_does_not_pass(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    (repo.root / rule_path("gate-no-eval")).unlink()
    repo.commit("drop the gate")
    digest = human_gate.governance_tree_hash(repo.root, "HEAD")
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", allow_empty=True)  # unsigned
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and payload["status"] == "fail"
    assert payload["approval"] is None or payload["approval"]["valid"] is False


@needs_git
@needs_signing
def test_an_approval_of_an_earlier_governance_state_is_void_after_a_further_change(tmp_path, capsys, keys):
    repo = make_repo(tmp_path, keys["human_pub"])
    (repo.root / rule_path("gate-no-eval")).unlink()
    repo.commit("drop the gate")
    digest = human_gate.governance_tree_hash(repo.root, "HEAD")
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    (repo.root / rule_path("inv-sample", "invariant")).unlink()
    repo.commit("then drop another")
    rc, _payload = ci_json(repo, capsys)
    assert rc == 1


@needs_git
def test_a_change_that_weakens_nothing_passes_without_any_approval(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def app():\n    return 5\n")
    repo.write(rule_path("trap-new", "trap"), rule_text("trap-new", "trap", "advisory", paths=("lib/*.py",)))
    repo.commit("code and a new advisory rule")
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["status"] == "pass" and payload["weakenings"] == []


@needs_git
@pytest.mark.parametrize("label,new_text,expected", [
    ("narrowed target_paths loses existing files",
     rule_text("gate-no-eval", "gate", forbid={"calls": ["eval"]}, paths=("src/app.py",)), "coverage"),
    ("a forbid_ast pattern removed",
     rule_text("gate-no-eval", "gate", forbid={"calls": ["exec"]}), "forbid_ast"),
    ("forbid_ast dropped entirely",
     rule_text("gate-no-eval", "gate"), "forbid_ast"),
    ("rank decrease: gate becomes a trap",
     rule_text("gate-no-eval", "trap", "advisory", forbid={"calls": ["eval"]}), "rank"),
    ("enforcement lowered from gate",
     rule_text("gate-no-eval", "gate", "advisory", forbid={"calls": ["eval"]}), "rank"),
    ("a new unknown key fails closed",
     rule_text("gate-no-eval", "gate", forbid={"calls": ["eval"]}, extra="waive_for: [src/app.py]"), "unknown_key"),
])
def test_each_weakening_the_spec_lists_is_flagged(tmp_path, capsys, label, new_text, expected):
    repo = make_repo(tmp_path)
    target = rule_path("gate-no-eval", "gate")
    if expected == "rank" and "type: trap" in new_text:
        (repo.root / target).unlink()
        target = rule_path("gate-no-eval", "trap")
    repo.write(target, new_text)
    repo.commit(label)
    rc, payload = ci_json(repo, capsys)
    assert rc == 1, label
    assert expected in {w["code"] for w in payload["weakenings"]}, (label, payload["weakenings"])


@needs_git
@pytest.mark.parametrize("label,new_text", [
    ("broader target_paths", rule_text("gate-no-eval", "gate", forbid={"calls": ["eval"]}, paths=("src/*.py", "lib/*.py"))),
    ("an added forbid_ast pattern", rule_text("gate-no-eval", "gate", forbid={"calls": ["eval", "exec"]})),
    ("a broader dotted-suffix call pattern", rule_text("gate-no-eval", "gate", forbid={"calls": ["eval", "builtins.eval"]})),
    ("excluded keys only", rule_text("gate-no-eval", "gate", forbid={"calls": ["eval"]},
                                      extra="impact_weight: 1.4\nminimum_mode: sweep\nexpiry_days: 90")),
    ("a rewritten body", rule_text("gate-no-eval", "gate", forbid={"calls": ["eval"]}, body="# New\n\nBetter prose.\n")),
])
def test_a_strengthening_or_a_neutral_edit_is_not_flagged(tmp_path, capsys, label, new_text):
    repo = make_repo(tmp_path)
    repo.write(rule_path("gate-no-eval"), new_text)
    repo.commit(label)
    rc, payload = ci_json(repo, capsys)
    assert rc == 0, (label, payload["weakenings"])
    assert payload["weakenings"] == []


@needs_git
def test_archiving_a_rule_is_a_deletion_but_moving_it_to_another_type_dir_at_the_same_rank_is_not(tmp_path, capsys):
    repo = make_repo(tmp_path)
    old = (repo.root / rule_path("inv-sample", "invariant"))
    old.unlink()
    repo.write(".aegis/rules/.archive/inv-sample.md", rule_text("inv-sample", "invariant", "advisory"))
    repo.commit("archive")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and codes(payload) == [("deleted", "inv-sample")]
    repo.git("reset", "-q", "--hard", "main")
    repo.write(rule_path("inv-sample", "invariant"), rule_text("inv-sample", "invariant", "gate"))
    repo.commit("raise to enforcement gate")
    rc, payload = ci_json(repo, capsys)
    assert rc == 0, payload["weakenings"]


@needs_git
def test_loss_of_coverage_follows_renames(tmp_path, capsys):
    repo = make_repo(tmp_path)
    # still covered after the move: not a loss
    repo.git("mv", "src/util.py", "src/util2.py")
    repo.commit("rename inside the covered area")
    rc, payload = ci_json(repo, capsys)
    assert rc == 0, payload["weakenings"]
    # moved out of the covered area: the gate no longer reaches a file it reached
    repo.git("mv", "src/util2.py", "lib/util2.py")
    repo.commit("move out of the gate's reach")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and ("coverage", "gate-no-eval") in codes(payload)


@needs_git
def test_forbid_ast_subsumption_uses_prefix_for_imports_and_suffix_for_calls(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(rule_path("gate-no-eval"), rule_text(
        "gate-no-eval", "gate", forbid={"imports": ["os.path"], "calls": ["os.system"]}))
    repo.commit("start from specific patterns")
    repo.git("branch", "specific")
    broader = rule_text("gate-no-eval", "gate", forbid={"imports": ["os"], "calls": ["system"]})
    repo.write(rule_path("gate-no-eval"), broader)
    repo.commit("broaden: os covers os.path, system covers os.system")
    rc, out, err = run_ci(repo, capsys, "--format", "json", base="specific")
    assert rc == 0, out + err
    narrower = rule_text("gate-no-eval", "gate", forbid={"imports": ["os.path.join"], "calls": ["os.system"]})
    repo.write(rule_path("gate-no-eval"), narrower)
    repo.commit("narrow the import")
    rc, out, _err = run_ci(repo, capsys, "--format", "json", base="specific")
    payload = json.loads(out)
    assert rc == 1 and "forbid_ast" in {w["code"] for w in payload["weakenings"]}


@needs_git
@needs_signing
def test_narrowing_a_call_entry_needs_an_approval_and_the_base_entry_is_served(tmp_path, capsys, keys):
    run_shell = "{name: subprocess.run, where: {shell: {equals: true}}}"
    repo = make_repo(tmp_path, keys["human_pub"], rules={
        rule_path("gate-run"): rule_text("gate-run", "gate", paths=("lib/*.py",), forbid={"calls": [run_shell]})})
    reviewed = rule_integrity.effective(repo.root).ruleset.get("gate-run").meta["forbid_ast"]
    repo.write(rule_path("gate-run"), rule_text("gate-run", "gate", paths=("lib/*.py",), forbid={
        "calls": ["{name: subprocess.run, where: {shell: {equals: never-matches}}}"]}))
    repo.commit("narrow the call entry")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and codes(payload) == [("forbid_ast", "gate-run")]
    view = rule_integrity.effective(repo.root)
    assert view.ruleset.get("gate-run").meta["forbid_ast"] == reviewed
    assert [(u.id, u.change) for u in view.unreviewed] == [("gate-run", "changed")]
    digest = human_gate.governance_tree_hash(repo.root, "HEAD")
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    rc, payload = ci_json(repo, capsys)
    assert rc == 0 and payload["approval"]["valid"] is True


@needs_git
def test_adding_a_mandatory_rule_past_the_scan_cap_on_an_overlapping_path_is_a_governance_change(tmp_path, capsys):
    repo = make_repo(tmp_path)  # src/*.py already has the gate and the invariant
    repo.write(rule_path("gate-third", "gate"), rule_text("gate-third", "gate", forbid={"calls": ["exec"]}))
    repo.commit("a third mandatory rule on src/*.py")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and ("mandatory_cap", "gate-third") in codes(payload)


@needs_git
def test_a_mandatory_rule_on_a_disjoint_path_is_not_over_the_cap(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(rule_path("gate-docs", "gate"), rule_text("gate-docs", "gate", paths=("docs/*.md",), forbid={"calls": ["exec"]}))
    repo.write("docs/a.md", "doc\n")
    repo.commit("a gate on other files")
    rc, payload = ci_json(repo, capsys)
    assert rc == 0, payload["weakenings"]


@needs_git
def test_any_change_to_applies_to_is_flagged_for_a_rule_of_any_rank(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(rule_path("trap-sample", "trap"), rule_text(
        "trap-sample", "trap", "advisory", paths=("lib/*.py",), extra="applies_to:\n  - api-surface"))
    repo.commit("scope the trap")
    rc, payload = ci_json(repo, capsys)
    assert rc == 1 and ("applies_to", "trap-sample") in codes(payload)


@needs_git
def test_the_json_report_carries_the_envelope_and_the_scope(tmp_path, capsys):
    repo = make_repo(tmp_path)
    rc, payload = ci_json(repo, capsys)
    assert rc == 0
    for key in ("source", "aegis_version", "checked_at", "scope"):
        assert payload[key]
    assert payload["scope"]["base"] and payload["scope"]["head"] and payload["scope"]["merge_base"]


@needs_git
def test_an_unresolvable_base_fails_closed(tmp_path, capsys):
    repo = make_repo(tmp_path)
    rc, out, err = run_ci(repo, capsys, base="no-such-branch")
    assert rc == 1
    assert "no-such-branch" in out + err


@needs_git
def test_ci_is_a_mode_of_its_own(tmp_path, capsys):
    repo = make_repo(tmp_path)
    rc, _out, _err = run_ci(repo, capsys, "--lane", "x")
    assert rc == 2
    rc, _out, err = run_ci(repo, capsys, "src/app.py")
    assert rc == 2 and "--ci" in err


# ── 2. local edits do not bind ───────────────────────────────────────────────

def scan_result(repo: hg.Repo, files: Optional[List[str]] = None) -> Dict[str, Any]:
    scan_mod.RULE_CACHE.invalidate()
    return scan_mod.scan(str(repo.root), changed_files=files or ["src/app.py"], budget=5, max_tokens=4000)


def served_names(result: Dict[str, Any]) -> List[str]:
    return [item["name"] for item in result["relevant_rules"]]


@needs_git
def test_a_branch_local_edit_to_an_invariant_serves_base_and_lists_the_edit(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(rule_path("inv-sample", "invariant"),
               rule_text("inv-sample", "invariant", "advisory", hypothesis="Anything goes now"))
    result = scan_result(repo)
    assert "inv-sample" in served_names(result)
    assert "Never do the thing" in result["guidance"] and "Anything goes now" not in result["guidance"]
    ids = [u["id"] for u in result["unreviewed_rules"]]
    assert ids == ["inv-sample"]
    assert set(result["unreviewed_rules"][0]) == {"id", "title", "change"}


@needs_git
def test_a_committed_branch_edit_does_not_bind_either(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(rule_path("inv-sample", "invariant"),
               rule_text("inv-sample", "invariant", "advisory", hypothesis="Committed softening"))
    repo.commit("soften")
    result = scan_result(repo)
    assert "Committed softening" not in result["guidance"] and "Never do the thing" in result["guidance"]
    assert [u["id"] for u in result["unreviewed_rules"]] == ["inv-sample"]
    assert result["rules_base"]["witnessed"] is True


@needs_git
def test_a_deleted_invariant_is_still_served_from_base(tmp_path):
    repo = make_repo(tmp_path)
    (repo.root / rule_path("inv-sample", "invariant")).unlink()
    result = scan_result(repo)
    assert "inv-sample" in served_names(result)
    assert [(u["id"], u["change"]) for u in result["unreviewed_rules"]] == [("inv-sample", "removed")]


@needs_git
def test_a_stricter_local_version_wins_but_is_still_listed(tmp_path):
    repo = make_repo(tmp_path)
    stricter = rule_text("gate-no-eval", "gate", forbid={"calls": ["eval", "exec"]}, paths=("src/*.py", "lib/*.py"))
    repo.write(rule_path("gate-no-eval"), stricter)
    result = scan_result(repo)
    item = next(i for i in result["relevant_rules"] if i["name"] == "gate-no-eval")
    assert item["matched_files"] == ["src/app.py"]
    assert [u["id"] for u in result["unreviewed_rules"]] == ["gate-no-eval"]
    ruleset = rule_integrity.effective_ruleset(repo.root)
    served = ruleset.get("gate-no-eval")
    assert served.meta["forbid_ast"]["calls"] == ["eval", "exec"]


@needs_git
def test_a_new_local_invariant_is_listed_and_never_served_as_mandatory(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(rule_path("inv-new", "invariant"), rule_text("inv-new", "invariant", "gate"))
    result = scan_result(repo)
    assert "inv-new" not in served_names(result)
    assert [(u["id"], u["change"]) for u in result["unreviewed_rules"]] == [("inv-new", "new")]


@needs_git
def test_a_new_advisory_rule_is_served_as_before_and_is_not_an_unreviewed_binding(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(rule_path("trap-new", "trap"), rule_text("trap-new", "trap", "advisory", paths=("src/*.py",)))
    result = scan_result(repo)
    assert "trap-new" in served_names(result)
    assert "unreviewed_rules" not in result


@needs_git
def test_with_no_remote_the_anchor_is_head_and_says_it_is_not_review_witnessed(tmp_path):
    repo = make_repo(tmp_path, origin=False)
    repo.write(rule_path("inv-sample", "invariant"),
               rule_text("inv-sample", "invariant", "advisory", hypothesis="Uncommitted softening"))
    result = scan_result(repo)
    assert "Uncommitted softening" not in result["guidance"]
    assert result["rules_base"]["witnessed"] is False
    assert "local-head, not review-witnessed" in result["rules_base"]["label"]


@needs_git
def test_the_user_scope_base_ref_wins(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(rule_path("inv-sample", "invariant"),
               rule_text("inv-sample", "invariant", "advisory", hypothesis="Reviewed on main2"))
    repo.commit("main2 content")
    repo.git("update-ref", "refs/heads/reviewed", "HEAD")
    repo.write(rule_path("inv-sample", "invariant"),
               rule_text("inv-sample", "invariant", "advisory", hypothesis="Unreviewed after"))
    repo.commit("later")
    cfg = tmp_path / "home" / ".aegis"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "config.json").write_text(json.dumps({"v": 1, "rules": {"base_ref": "reviewed"}}), encoding="utf-8")
    result = scan_result(repo)
    assert "Reviewed on main2" in result["guidance"]
    assert result["rules_base"]["source"] == "user-config"


@needs_git
def test_a_repo_config_cannot_name_the_base_ref(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"v": 1, "rules": {"base_ref": "work"}}))
    repo.write(rule_path("inv-sample", "invariant"),
               rule_text("inv-sample", "invariant", "advisory", hypothesis="Attacker text"))
    repo.commit("point the base at myself")
    result = scan_result(repo)
    assert "Attacker text" not in result["guidance"]


@needs_git
def test_a_directory_that_is_not_a_repository_is_served_as_before(tmp_path):
    root = tmp_path / "plain"
    (root / ".aegis/rules/invariants").mkdir(parents=True)
    (root / rule_path("inv-sample", "invariant")).write_text(rule_text("inv-sample", "invariant", "advisory"),
                                                             encoding="utf-8")
    (root / "src").mkdir()
    (root / "src/app.py").write_text("x = 1\n", encoding="utf-8")
    scan_mod.RULE_CACHE.invalidate()
    result = scan_mod.scan(str(root), changed_files=["src/app.py"], budget=5, max_tokens=4000)
    assert "inv-sample" in served_names(result)
    assert "unreviewed_rules" not in result and "rules_base" not in result


@needs_git
def test_the_enforcement_ruleset_is_the_base_version(tmp_path):
    repo = make_repo(tmp_path)
    (repo.root / rule_path("gate-no-eval")).unlink()
    ruleset = rule_integrity.effective_ruleset(repo.root)
    assert ruleset.get("gate-no-eval") is not None


# ── 3. release verification fails closed ────────────────────────────────────

SHA = "a" * 40


def fake_gh(directory: Path, version: str, body: str = "") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "gh"
    script.write_text(f"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'gh version {version} (2026-01-01)'; exit 0; fi\n"
                      f"{body}\nexit 0\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return directory


def run_release(repo: hg.Repo, monkeypatch, capsys, path: str, *extra: str, sha: str = SHA) -> Tuple[int, str, str]:
    monkeypatch.setenv("PATH", path)
    os.chdir(repo.root)
    try:
        rc = main(["doctor", "--release", sha, *extra])
    except SystemExit as exc:
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@needs_git
@posix_only
def test_an_old_gh_is_unverified_and_exits_non_zero(tmp_path, monkeypatch, capsys):
    repo = make_repo(tmp_path)
    gh_dir = fake_gh(tmp_path / "bin", "2.45.0")
    git_dir = os.path.dirname(shutil.which("git"))
    rc, out, err = run_release(repo, monkeypatch, capsys, f"{gh_dir}{os.pathsep}{git_dir}")
    assert rc not in (0, None)
    assert "UNVERIFIED (gh >= 2.93.0 required)" in out + err


@needs_git
def test_no_gh_at_all_is_unverified_and_exits_non_zero(tmp_path, monkeypatch, capsys):
    repo = make_repo(tmp_path)
    git_dir = os.path.dirname(shutil.which("git"))
    empty = tmp_path / "empty"
    empty.mkdir()
    rc, out, err = run_release(repo, monkeypatch, capsys, f"{empty}{os.pathsep}{git_dir}")
    assert rc not in (0, None)
    assert "UNVERIFIED (gh >= 2.93.0 required)" in out + err


# ── 4. the one loader ────────────────────────────────────────────────────────

def _loaded(tmp_path, relative: str, text: str):
    root = tmp_path / "ws"
    target = root / ".aegis/rules" / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return load_rules(root)


def test_applies_to_is_a_known_key_and_the_rule_still_loads(tmp_path):
    text = rule_text("trap-scoped", "trap", "advisory", extra="applies_to:\n  - api-surface")
    ruleset = _loaded(tmp_path, "traps/trap-scoped.md", text)
    (rule,) = ruleset.rules
    assert rule.ok, rule.error
    assert rule.applies_to("src/app.py")  # served as an unscoped rule: only target_paths decide


@pytest.mark.parametrize("rtype,enforcement", [("invariant", "advisory"), ("gate", "gate"), ("trap", "gate")])
def test_expired_at_on_a_rank_two_rule_is_an_error(tmp_path, rtype, enforcement):
    text = rule_text("r-old", rtype, enforcement, extra="expired_at: 2026-01-01")
    ruleset = _loaded(tmp_path, f"{TYPE_DIRS[rtype]}/r-old.md", text)
    (rule,) = ruleset.rules
    assert rule.error and "expired_at" in rule.error


def test_expired_at_on_an_advisory_trap_still_just_retires_it(tmp_path):
    text = rule_text("trap-old", "trap", "advisory", extra="expired_at: 2026-01-01")
    (rule,) = _loaded(tmp_path, "traps/trap-old.md", text).rules
    assert rule.ok and rule.expired
