"""aegis_core.rule_integrity beyond the acceptance contract: sad paths, edges and the shape of the output.

Real git repositories in tmp dirs; a corrupt object is a forged loose object on disk.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import zlib
from typing import Any, Dict, List, Optional, Tuple

import pytest

from aegis_cli.cli import main
from aegis_core import gitsafe, rule_integrity, scan as scan_mod
from aegis_core.rule_integrity import IntegrityError, Weakening, weakenings
from aegis_core.rules import load_rules
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")
DIRS = {"gate": "gates", "invariant": "invariants", "trap": "traps"}


def rule_text(rid: str, rtype: str = "invariant", enforcement: str = "gate", paths: Tuple[str, ...] = ("src/*.py",),
              extra: str = "", forbid: Optional[Dict[str, List[str]]] = None,
              body: str = "# The title\n\nWhy this rule exists.\n") -> str:
    lines = ["---", f"id: {rid}", f"type: {rtype}", f"enforcement: {enforcement}", "hypothesis: keep it so"]
    if paths:
        lines += ["target_paths:"] + [f"  - '{p}'" for p in paths]
    if forbid:
        lines.append("forbid_ast:")
        for kind, values in forbid.items():
            lines.append(f"  {kind}:")
            lines += [f"    - {v}" for v in values]
    if extra:
        lines.append(extra)
    lines += ["---", body]
    return "\n".join(lines)


def path_of(rid: str, rtype: str = "invariant") -> str:
    return f".aegis/rules/{DIRS[rtype]}/{rid}.md"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_EVENT_PATH", "GITHUB_BASE_REF", "SSH_AUTH_SOCK", "GIT_CONFIG_GLOBAL", "CLAUDE_CONFIG_DIR",
                 "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


def make_repo(tmp_path: Path, origin: bool = True, paths: Tuple[str, ...] = ("src/*.py",),
              signer_pub: Optional[str] = None) -> hg.Repo:
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "x = 1\n")
    repo.write("src/util.py", "y = 2\n")
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=paths))
    repo.write(path_of("trap-a", "trap"), rule_text("trap-a", "trap", "advisory", paths=("src/*.py",)))
    if signer_pub is not None:
        repo.write("allowed_signers", hg.allowed_signers_text(signer_pub))
    repo.commit("base")
    if origin:
        repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
        repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    return repo


def ci(repo: hg.Repo, capsys, *extra: str) -> Tuple[int, Any, str]:
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--base", "main", "--format", "json", *extra])
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return rc, payload, captured.err


def parsed(tmp_path: Path, rid: str, text: str, rtype: str = "invariant"):
    root = tmp_path / "ws"
    target = root / path_of(rid, rtype)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    (rule,) = load_rules(root).rules
    assert rule.ok, rule.error
    return rule


# ── the analysis on its own ──────────────────────────────────────────────────

def codes(found: List[Weakening]) -> List[str]:
    return sorted(w.code for w in found)


def test_an_unchanged_rule_weakens_nothing(tmp_path):
    rule = parsed(tmp_path, "inv-a", rule_text("inv-a"))
    assert weakenings(rule, rule) == []


def test_a_head_that_no_longer_loads_counts_as_a_deletion(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a"))
    broken_root = tmp_path / "broken"
    (broken_root / ".aegis/rules/invariants").mkdir(parents=True)
    (broken_root / path_of("inv-a")).write_text(rule_text("inv-a", extra="paths: [src]"), encoding="utf-8")
    (broken,) = load_rules(broken_root).rules
    assert not broken.ok
    (found,) = weakenings(base, broken)
    assert found.code == "deleted" and "no longer loads" in found.message


def test_dotted_prefix_for_imports_and_suffix_for_calls_and_decorators(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text(
        "inv-a", forbid={"imports": ["os.path"], "calls": ["os.system"], "decorators": ["app.route"]}))
    broader = parsed(tmp_path / "b", "inv-a", rule_text(
        "inv-a", forbid={"imports": ["os"], "calls": ["system"], "decorators": ["route"]}))
    assert weakenings(base, broader) == []
    narrower = parsed(tmp_path / "c", "inv-a", rule_text(
        "inv-a", forbid={"imports": ["os.path"], "calls": ["os.system"], "decorators": ["flask.app.route"]}))
    (found,) = weakenings(base, narrower)
    assert found.code == "forbid_ast" and "decorator 'app.route'" in found.message


def test_a_call_entry_where_is_compared_and_a_top_level_key_the_enforcer_rejects_is_not(tmp_path):
    entry = "{name: eval, where: {x: 1}}"
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", forbid={"calls": [entry], "where": ["x"]}))
    dropped = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", forbid={"calls": [entry]}))
    assert weakenings(base, dropped) == []  # verification.runner refuses a top-level where: it bound nothing
    narrowed = parsed(tmp_path / "c", "inv-a", rule_text("inv-a", forbid={"calls": ["{name: eval, where: {x: 2}}"]}))
    (found,) = weakenings(base, narrowed)
    assert found.code == "forbid_ast" and "call 'eval' is no longer forbidden everywhere it was" in found.message


RUN_SHELL = "{name: subprocess.run, where: {shell: true}}"


@pytest.mark.parametrize("entry", [
    "{name: subprocess.run, where: {shell: never-matches}}",
    "{name: subprocess.run, where: {shell: 1}}",
    "{name: subprocess.run, where: {shell: true, cwd: x}}",
    "{name: subprocess.run, where: {shell: true}, builtin: true}",
    "{name: subprocess.run, where: {shell: {not: false}}}",
    "{name: subprocess.runx, where: {shell: true}}",
], ids=["never", "one", "addkey", "builtin", "reworded", "rename"])
def test_each_narrowing_of_a_call_entry_is_one_finding(tmp_path, entry):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", forbid={"calls": [RUN_SHELL]}))
    head = parsed(tmp_path / "h", "inv-a", rule_text("inv-a", forbid={"calls": [entry, "os.system"]}))
    found = weakenings(base, head)
    assert [w.code for w in found] == ["forbid_ast"] and "call 'subprocess.run'" in found[0].message


def test_a_where_or_builtin_added_to_a_plain_call_narrows_it_and_removing_them_does_not(tmp_path):
    plain = parsed(tmp_path, "inv-a", rule_text("inv-a", forbid={"calls": ["eval"]}))
    where = parsed(tmp_path / "w", "inv-a", rule_text("inv-a", forbid={"calls": ["{name: eval, where: {x: never}}"]}))
    (found,) = weakenings(plain, where)
    assert "call 'eval' is no longer forbidden everywhere it was (its where or builtin was narrowed)" in found.message
    builtin = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", forbid={"calls": ["{name: eval, builtin: true}"]}))
    assert codes(weakenings(plain, builtin)) == ["forbid_ast"]
    assert weakenings(builtin, plain) == []


@pytest.mark.parametrize("base_entry,entries", [
    (RUN_SHELL, [RUN_SHELL]),
    (RUN_SHELL, ["{name: subprocess.run, where: {shell: true}, builtin: false}"]),
    (RUN_SHELL, ["{name: run, where: {shell: true}}"]),
    (RUN_SHELL, ["{name: subprocess.run}"]),
    (RUN_SHELL, ["subprocess.run"]),
    ("{name: subprocess.run, where: {shell: true, cwd: x}}", [RUN_SHELL]),
    (RUN_SHELL, [RUN_SHELL, "eval", "{name: exec, builtin: true}"]),
], ids=["same", "notbuiltin", "broader", "nowhere", "plain", "dropkey", "added"])
def test_an_equal_or_broader_call_entry_is_not_a_weakening(tmp_path, base_entry, entries):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", forbid={"calls": [base_entry]}))
    head = parsed(tmp_path / "h", "inv-a", rule_text("inv-a", forbid={"calls": [*entries, "os.system"]}))
    assert weakenings(base, head) == []


def test_the_compared_call_keys_are_the_keys_the_enforcer_accepts():
    from aegis_core.verification.runner import _CALL_SPEC_KEYS

    assert set(rule_integrity._CallEntry._fields) == set(_CALL_SPEC_KEYS)


@pytest.mark.parametrize("entry,lost", [
    ("{name: subprocess.run, where: {shell: true}, unknown: skip}", False),
    ("{call: subprocess.run, where: {shell: true}}", True),
], ids=["unknown", "call-alias"])
def test_a_removed_call_key_is_refused_by_the_enforcer_and_never_counts_as_coverage(tmp_path, entry, lost):
    """Given a head entry with a key the enforcer no longer accepts, Then the rule fails closed at
    load (a broken gate blocks every change), and the comparison never reads the key: a ``call:``
    alias names no call, so the base entry is reported lost."""
    from aegis_core.verification.runner import _forbid_ast_spec_error

    base = parsed(tmp_path, "inv-a", rule_text("inv-a", forbid={"calls": [RUN_SHELL]}))
    head = parsed(tmp_path / "h", "inv-a", rule_text("inv-a", forbid={"calls": [entry, "os.system"]}))
    assert "unknown key" in (_forbid_ast_spec_error(head.meta["forbid_ast"]) or "")
    assert codes(weakenings(base, head)) == (["forbid_ast"] if lost else [])


def test_a_detect_key_must_stay_an_exact_superset(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", extra="detect:\n  - 'a'\n  - 'b'"))
    same_plus = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", extra="detect:\n  - 'a'\n  - 'b'\n  - 'c'"))
    fewer = parsed(tmp_path / "c", "inv-a", rule_text("inv-a", extra="detect:\n  - 'a'"))
    gone = parsed(tmp_path / "d", "inv-a", rule_text("inv-a"))
    assert weakenings(base, same_plus) == []
    assert codes(weakenings(base, fewer)) == ["detect"]
    assert codes(weakenings(base, gone)) == ["detect"]


def test_descriptive_keys_may_change_but_an_invented_key_may_not(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", extra="tags:\n  - a"))
    edited = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", extra="tags:\n  - b\nimpact_weight: 3"))
    assert weakenings(base, edited) == []
    invented = parsed(tmp_path / "c", "inv-a", rule_text("inv-a", extra="exempt_files: [src]"))
    (found,) = weakenings(base, invented)
    assert found.code == "unknown_key" and "exempt_files" in found.message


def test_a_key_that_was_already_there_and_is_unchanged_is_not_new(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", extra="custom_note: kept"))
    same = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", extra="custom_note: kept"))
    assert weakenings(base, same) == []
    changed = parsed(tmp_path / "c", "inv-a", rule_text("inv-a", extra="custom_note: changed"))
    assert codes(weakenings(base, changed)) == ["unknown_key"]


def test_an_enforcement_drop_is_a_rank_loss_even_when_the_type_stays(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", "invariant", "gate"))
    dropped = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", "invariant", "advisory"))
    assert codes(weakenings(base, dropped)) == ["rank"]  # still rank 2 by type, but it declared less
    mechanical = parsed(tmp_path / "c", "inv-a", rule_text("inv-a", "invariant", "mechanical"))
    assert weakenings(mechanical, base) == []  # raising it is not a weakening
    assert codes(weakenings(mechanical, dropped)) == ["rank"]


# ── reading git ──────────────────────────────────────────────────────────────

@needs_git
def test_a_forged_base_object_is_refused_by_the_public_loaders(tmp_path):
    repo = make_repo(tmp_path)
    oid = repo.git("rev-parse", "HEAD:" + path_of("inv-a"))
    # The base blob is read from git only when the working-tree rule no longer hashes to it.
    repo.write(path_of("inv-a"), rule_text("inv-a", body="# The title\n\nA reworded reason.\n"))
    assert rule_integrity.effective(repo.root).ruleset  # control: the untouched object loads
    ok = scan_mod.scan(repo.root, ["src/app.py"])
    assert ok.get("status") != "FAIL" and ok["relevant_rules"]
    loose = repo.root / ".git" / "objects" / oid[:2] / oid[2:]
    os.chmod(str(loose), 0o644)
    loose.write_bytes(zlib.compress(b"blob 5\x00lies!"))
    with pytest.raises(IntegrityError, match="does not match the object id"):
        rule_integrity.effective(repo.root)
    # A process that read the commit's rules once keeps that verified copy; a new one reads the forgery.
    assert scan_mod.scan(repo.root, ["src/app.py"]) == ok
    scan_mod.RULE_CACHE.invalidate()
    result = scan_mod.scan(repo.root, ["src/app.py"])
    assert result["status"] == "FAIL"
    assert "the reviewed (base) version of the rules cannot be read" in result["error"]
    assert not result.get("relevant_rules")


@needs_git
def test_content_that_does_not_hash_to_its_object_id_is_refused(tmp_path, monkeypatch):
    """The lying cat-file is forged at the public git boundary (gitsafe.run), not at a module seam."""
    repo = make_repo(tmp_path)
    oid = repo.git("rev-parse", "HEAD:" + path_of("inv-a"))
    real = gitsafe.run

    def forged(args, cwd, **kw):
        if args and args[0] == "cat-file":
            return subprocess.CompletedProcess(["git", *args], 0, f"{oid} blob 5\nlies!\n".encode("ascii"), b"")
        return real(args, cwd, **kw)

    monkeypatch.setattr(gitsafe, "run", forged)
    with pytest.raises(IntegrityError, match="does not match the object id"):
        rule_integrity._read_blobs(str(repo.root), [oid])


@needs_git
def test_a_missing_object_is_an_error_not_an_empty_rule(tmp_path):
    repo = make_repo(tmp_path)
    with pytest.raises(IntegrityError, match="cannot read object"):
        rule_integrity._read_blobs(str(repo.root), ["0" * 40])


@needs_git
def test_an_anchor_in_a_repository_with_no_commit_is_none(tmp_path):
    root = tmp_path / "fresh"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    assert rule_integrity.resolve_base(root) is None


@needs_git
def test_a_user_base_ref_that_does_not_resolve_falls_back_to_the_next_anchor(tmp_path):
    repo = make_repo(tmp_path)
    cfg = tmp_path / "home" / ".aegis"
    cfg.mkdir()
    (cfg / "config.json").write_text(json.dumps({"v": 1, "rules": {"base_ref": "no-such-ref"}}), encoding="utf-8")
    anchor = rule_integrity.resolve_base(repo.root)
    assert anchor is not None and anchor.source == "origin-head"


def user_base_ref(tmp_path: Path, ref: str) -> None:
    cfg = tmp_path / "home" / ".aegis"
    cfg.mkdir(exist_ok=True)
    (cfg / "config.json").write_text(json.dumps({"v": 1, "rules": {"base_ref": ref}}), encoding="utf-8")


@needs_git
def test_a_user_base_ref_anchors_at_the_fork_point_not_at_its_moving_tip(tmp_path):
    repo = make_repo(tmp_path)
    fork = repo.head()
    repo.git("checkout", "-q", "main")
    repo.write(path_of("inv-a"), rule_text("inv-a", body="# The title\n\nReworded on main after the fork.\n"))
    repo.git("update-ref", "refs/remotes/origin/main", repo.commit("main moves on"))
    repo.git("checkout", "-q", "work")
    repo.write("src/app.py", "x = 5\n")
    repo.commit("branch work that touches no rule")
    user_base_ref(tmp_path, "origin/main")
    anchor = rule_integrity.resolve_base(repo.root)
    assert anchor is not None and (anchor.source, anchor.commit) == ("user-config", fork)
    assert list(rule_integrity.effective(repo.root).unreviewed) == []


@needs_git
def test_a_user_base_ref_with_no_common_history_falls_back_to_its_tip_and_says_so(tmp_path):
    repo = make_repo(tmp_path)
    repo.git("checkout", "-q", "--orphan", "island")
    repo.git("rm", "-rfq", ".")
    repo.write("a.txt", "x\n")
    island = repo.commit("island")
    repo.git("checkout", "-q", "work")
    user_base_ref(tmp_path, "island")
    anchor = rule_integrity.resolve_base(repo.root)
    assert anchor is not None and anchor.commit == island
    assert "no common history with HEAD, using its tip" in anchor.label


@needs_git
def test_a_user_config_that_lies_inside_the_workspace_is_repository_content(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    inside = repo.root / "fakehome"
    (inside / ".aegis").mkdir(parents=True)
    (inside / ".aegis/config.json").write_text(json.dumps({"v": 1, "rules": {"base_ref": "work"}}), encoding="utf-8")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(inside))
    anchor = rule_integrity.resolve_base(repo.root)
    assert anchor is not None and anchor.source == "origin-head"


# ── serving ──────────────────────────────────────────────────────────────────

def scan_for(repo: hg.Repo) -> Dict[str, Any]:
    scan_mod.RULE_CACHE.invalidate()
    return scan_mod.scan(str(repo.root), changed_files=["src/app.py"], budget=5, max_tokens=4000)


@needs_git
def test_a_branch_that_breaks_a_binding_rule_fails_the_scan_closed_and_the_base_still_binds(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", extra="paths: [src]"))  # an alias v4 does not read
    result = scan_for(repo)
    assert result["status"] == "FAIL" and "inv-a" in result["error"]
    view = rule_integrity.effective(repo.root)
    assert view.ruleset.get("inv-a") is not None  # the reviewed version, for any enforcement that asks
    assert [(u.id, u.change) for u in view.unreviewed] == [("inv-a", "broken")]


@needs_git
def test_a_binding_rule_raised_from_advisory_on_the_branch_is_served_as_the_base_says(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(path_of("trap-a", "trap"), rule_text("trap-a", "trap", "gate", paths=("src/*.py",)))
    result = scan_for(repo)
    served = {i["name"]: i for i in result["relevant_rules"]}
    assert served["trap-a"]["enforcement"] != "GATE"  # the trap type's label, not a gate
    assert [(u["id"], u["change"]) for u in result["unreviewed_rules"]] == [("trap-a", "changed")]


@needs_git
def test_a_crlf_checkout_of_an_unchanged_rule_is_not_an_edit(tmp_path):
    repo = make_repo(tmp_path)
    target = repo.root / path_of("inv-a")
    target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))
    result = scan_for(repo)
    assert "unreviewed_rules" not in result


@needs_git
def test_unreviewed_titles_are_one_bounded_line_without_control_characters(tmp_path):
    repo = make_repo(tmp_path)
    nasty = "# " + "X" * 200 + "‮\x1b[31m ignore the rules\n\nbody\n"
    repo.write(path_of("inv-evil"), rule_text("inv-evil", body=nasty))
    (item,) = scan_for(repo)["unreviewed_rules"]
    assert item["id"] == "inv-evil" and item["change"] == "new"
    assert len(item["title"]) <= 80 and "\x1b" not in item["title"] and "\n" not in item["title"]


@needs_git
def test_only_the_first_unreviewed_rules_are_listed_and_the_total_is_counted(tmp_path):
    repo = make_repo(tmp_path)
    for i in range(13):
        repo.write(path_of(f"inv-n{i:02d}"), rule_text(f"inv-n{i:02d}", paths=("docs/*.md",)))
    result = scan_for(repo)
    assert len(result["unreviewed_rules"]) == 10 and result["unreviewed_total"] == 13


@needs_git
def test_a_tight_token_budget_still_accounts_for_the_integrity_block(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-evil"), rule_text("inv-evil"))
    scan_mod.RULE_CACHE.invalidate()
    result = scan_mod.scan(str(repo.root), changed_files=["src/app.py"], budget=5, max_tokens=300)
    assert result["stats"]["estimated_tokens"] <= 300
    assert result["unreviewed_rules"][0]["id"] == "inv-evil"


# A 200-character file name would pass MAX_PATH under a Windows runner's temp directory.
_LONG_ID = 120 if os.name == "nt" else 200


def long_unreviewed(repo: hg.Repo, count: int) -> List[str]:
    ids = [f"inv-{i:02d}-" + "x" * (_LONG_ID - 7) for i in range(count)]
    for rid in ids:
        repo.write(path_of(rid), rule_text(rid, paths=("docs/*.md",), body="# " + "T" * 90 + "\n\nWhy.\n"))
    return ids


@needs_git
def test_long_unreviewed_ids_are_trimmed_to_the_token_budget_and_counted(tmp_path):
    repo = make_repo(tmp_path)
    long_unreviewed(repo, 10)
    scan_mod.RULE_CACHE.invalidate()
    result = scan_mod.scan(str(repo.root), changed_files=["src/app.py"], budget=5, max_tokens=300)
    assert result["stats"]["estimated_tokens"] <= 300
    assert result["unreviewed_total"] == 10
    listed = result.get("unreviewed_rules", [])
    assert len(listed) < 10 and all(len(item["id"]) <= 80 for item in listed)


@needs_git
def test_a_short_unreviewed_list_that_is_trimmed_still_says_how_many_there_are(tmp_path):
    repo = make_repo(tmp_path)
    long_unreviewed(repo, 3)
    scan_mod.RULE_CACHE.invalidate()
    tight = scan_mod.scan(str(repo.root), changed_files=["src/app.py"], budget=5, max_tokens=300)
    assert tight["stats"]["estimated_tokens"] <= 300
    assert len(tight.get("unreviewed_rules", [])) < 3 and tight["unreviewed_total"] == 3
    roomy = scan_mod.scan(str(repo.root), changed_files=["src/app.py"], budget=5, max_tokens=40000)
    assert len(roomy["unreviewed_rules"]) == 3 and "unreviewed_total" not in roomy
    assert all(len(item["id"]) == 80 and item["id"].endswith("...") for item in roomy["unreviewed_rules"])


@needs_git
def test_with_no_changed_files_the_unreviewed_list_still_fits_the_budget(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    long_unreviewed(repo, 10)
    scan_mod.RULE_CACHE.invalidate()
    monkeypatch.setattr(scan_mod, "_git_changed_files", lambda workspace: [])
    result = scan_mod.scan(str(repo.root), changed_files=None, budget=5, max_tokens=300)
    assert result["guidance"] == scan_mod.NO_CHANGES_TEXT
    assert result["stats"]["estimated_tokens"] <= 300 and result["unreviewed_total"] == 10


# ── the cost of reading the base (R-trust-45) ───────────────────────────────

def git_calls(monkeypatch) -> List[List[str]]:
    calls: List[List[str]] = []
    real = gitsafe.run

    def spy(args, *a, **kw):
        calls.append(list(args))
        return real(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", spy)
    return calls


def parse_count(monkeypatch) -> List[str]:
    from aegis_core import rules as rules_mod

    parsed_paths: List[str] = []
    real = rules_mod._parse
    monkeypatch.setattr(rules_mod, "_parse", lambda entry, *a: parsed_paths.append(entry.relative_path) or real(entry, *a))
    return parsed_paths


@needs_git
@pytest.mark.parametrize("origin", [True, False], ids=["origin", "local"])
def test_reading_the_base_of_a_clean_tree_costs_two_git_calls_with_an_origin(tmp_path, monkeypatch, origin):
    repo = make_repo(tmp_path, origin=origin)
    calls = git_calls(monkeypatch)
    view = rule_integrity.effective(repo.root, scan_mod.RuleCache())
    assert view.anchor is not None and view.anchor.source == ("origin-head" if origin else "local-head")
    assert view.unreviewed == () and len(calls) <= (2 if origin else 3), calls


@needs_git
def test_the_base_rules_are_parsed_once_per_anchor_and_working_tree(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    repo.write(path_of("trap-a", "trap"), rule_text("trap-a", "trap", "advisory", body="# Softer\n\nEdited.\n"))
    cache = scan_mod.RuleCache()
    first = rule_integrity.effective(repo.root, cache)
    parsed_paths = parse_count(monkeypatch)
    second = rule_integrity.effective(repo.root, cache)
    assert parsed_paths == [] and second == first
    assert "Edited." in second.ruleset.get("trap-a").body and second.unreviewed == ()
    repo.git("update-ref", "refs/remotes/origin/main", repo.commit("move the reviewed base"))
    repo.write(path_of("trap-a", "trap"), rule_text("trap-a", "trap", "advisory", body="# Again\n\nEdited twice.\n"))
    third = rule_integrity.effective(repo.root, cache)
    assert third.anchor.commit != first.anchor.commit and parsed_paths  # a moved anchor is a new key
    assert "Edited twice." in third.ruleset.get("trap-a").body


@needs_git
def test_a_binding_edit_is_still_held_to_the_base_when_the_base_is_cached(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", enforcement="advisory"))
    cache = scan_mod.RuleCache()
    for _ in range(2):
        view = rule_integrity.effective(repo.root, cache)
        assert view.ruleset.get("inv-a").enforcement == "gate"
        assert [(u.id, u.change) for u in view.unreviewed] == [("inv-a", "changed")]


@needs_git
def test_a_crlf_working_copy_of_lf_blobs_reads_no_blob_and_lists_nothing(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    repo.git("config", "core.autocrlf", "true")
    target = repo.root / path_of("inv-a")
    lf = rule_integrity.effective(repo.root).ruleset.get("inv-a")
    target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))
    calls = git_calls(monkeypatch)
    view = rule_integrity.effective(repo.root, scan_mod.RuleCache())
    assert view.unreviewed == () and not [c for c in calls if "cat-file" in c], calls
    assert rule_integrity.policy_view(view.ruleset.get("inv-a")) == rule_integrity.policy_view(lf)


# ── BASE is read once per commit and blob (R-structure-8) ───────────────────

def base_loads(monkeypatch) -> List[int]:
    loads: List[int] = []
    real = rule_integrity.load_rules
    monkeypatch.setattr(rule_integrity, "load_rules", lambda *a, **kw: loads.append(1) or real(*a, **kw))
    return loads


def object_reads(calls: List[List[str]]) -> List[List[str]]:
    return [c for c in calls if c and c[0] in ("ls-tree", "cat-file")]


def reword(repo: hg.Repo, n: int) -> None:
    repo.write(path_of("trap-a", "trap"), rule_text("trap-a", "trap", "advisory", body=f"# Softer\n\nEdit {n}.\n"))


@needs_git
def test_a_branch_that_keeps_editing_a_rule_reads_and_parses_the_base_once(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    cache = scan_mod.RuleCache()
    loads, calls = base_loads(monkeypatch), git_calls(monkeypatch)
    views = []
    for n in range(3):
        reword(repo, n)  # a new working fingerprint each time, the same BASE
        views.append(rule_integrity.effective(repo.root, cache))
        if n == 0:
            calls.clear()
    assert object_reads(calls) == [] and loads == [1], calls
    for n, view in enumerate(views):
        assert f"Edit {n}." in view.ruleset.get("trap-a").body and view.unreviewed == ()
        assert view.anchor == views[0].anchor
    assert rule_integrity.effective(repo.root).ruleset == views[-1].ruleset  # what an uncached read serves


@needs_git
def test_a_base_that_moves_is_listed_again_and_served_new(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    cache = scan_mod.RuleCache()
    reword(repo, 0)
    first = rule_integrity.effective(repo.root, cache)
    repo.write(path_of("inv-a"), rule_text("inv-a", body="# The title\n\nReviewed anew.\n"))
    repo.git("update-ref", "refs/remotes/origin/main", repo.commit("move the reviewed base"))
    reword(repo, 1)
    calls = git_calls(monkeypatch)
    second = rule_integrity.effective(repo.root, cache)
    assert second.anchor.commit != first.anchor.commit
    assert [c[0] for c in object_reads(calls)][:1] == ["ls-tree"]
    assert "Reviewed anew." in second.ruleset.get("inv-a").body


@needs_git
def test_a_forged_blob_is_refused_and_nothing_of_it_is_kept(tmp_path):
    repo = make_repo(tmp_path)
    oid = repo.git("rev-parse", "HEAD:" + path_of("inv-a"))
    loose = repo.root / ".git" / "objects" / oid[:2] / oid[2:]
    genuine = loose.read_bytes()
    os.chmod(str(loose), 0o644)
    loose.write_bytes(zlib.compress(b"blob 5\x00lies!"))
    repo.write(path_of("inv-a"), rule_text("inv-a", body="# The title\n\nA reworded reason.\n"))
    cache = scan_mod.RuleCache()
    with pytest.raises(IntegrityError, match="does not match the object id"):
        rule_integrity.effective(repo.root, cache)
    loose.write_bytes(genuine)
    view = rule_integrity.effective(repo.root, cache)
    assert "Why this rule exists." in view.ruleset.get("inv-a").body  # the reviewed text, not the forgery


@needs_git
def test_a_blob_cache_smaller_than_the_rules_evicts_and_still_serves_them_right(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    padding = "x" * 16000 + "\n"
    for n in range(300):
        repo.write(f".aegis/rules/traps/bulk-{n}.md", rule_text(f"bulk-{n}", "trap", "advisory", body=f"# B{n}\n\n{padding}"))
    repo.git("update-ref", "refs/remotes/origin/main", repo.commit("many large rules"))
    monkeypatch.setattr(scan_mod.RuleCache, "_MAX_BLOB_BYTES", 4 * 1024 * 1024)
    cache = scan_mod.RuleCache()
    for round_ in range(2):
        for n in range(300):
            repo.write(f".aegis/rules/traps/bulk-{n}.md",
                       rule_text(f"bulk-{n}", "trap", "advisory", body=f"# B{n} r{round_}\n\n{padding}"))
        view = rule_integrity.effective(repo.root, cache)
        assert view.ruleset == rule_integrity.effective(repo.root).ruleset
    assert cache._blob_bytes <= 4 * 1024 * 1024


@needs_git
def test_a_spy_at_the_git_boundary_does_not_bypass_the_base_caches(tmp_path, monkeypatch):
    """R-structure-22 (rewrites the seam test it removes): production code no longer branches on a
    replaced git runner, so a spy at gitsafe.run sees the cached base serve the second read."""
    repo = make_repo(tmp_path)
    calls = git_calls(monkeypatch)
    cache = scan_mod.RuleCache()
    for n in range(2):
        reword(repo, n)
        rule_integrity.effective(repo.root, cache)
    assert [c[0] for c in object_reads(calls)] == ["ls-tree", "cat-file"], calls


# ── the CI check ─────────────────────────────────────────────────────────────

@needs_git
def test_the_report_names_the_range_and_counts_the_binding_rules(tmp_path, capsys):
    repo = make_repo(tmp_path)
    rc, payload, _err = ci(repo, capsys)
    assert rc == 0 and payload["rules_checked"] == 1
    assert payload["schema"] == "aegis.rule_integrity/v1"
    assert payload["scope"]["mode"] == "ci"


@needs_git
def test_narrowing_target_paths_is_a_loss_of_coverage_even_when_the_dropped_file_is_deleted(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=("src/app.py",)))
    repo.commit("narrow to one file")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1 and [w["code"] for w in payload["weakenings"]] == ["coverage"]
    assert "'src/*.py'" in payload["weakenings"][0]["message"]
    repo.git("reset", "-q", "--hard", "main")
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=("src/app.py",)))
    repo.git("rm", "-q", "src/util.py")
    repo.commit("narrow and remove what it no longer covers")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1 and [w["code"] for w in payload["weakenings"]] == ["coverage"]


DEEP = ("src/**/*.py",)
LISTED = ("src/app.py", "src/util.py")


def approve(repo: hg.Repo, key: Path) -> None:
    from aegis_core import human_gate

    digest = human_gate.governance_tree_hash(repo.root, "HEAD")
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=key, allow_empty=True)


@needs_git
def test_narrowing_a_glob_to_the_present_files_is_flagged_although_no_file_loses_the_rule(tmp_path, capsys):
    repo = make_repo(tmp_path, paths=DEEP)
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=LISTED))
    repo.write("src/evil.py", "import os\n")
    repo.commit("narrow to what exists, then add a file")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1 and [(w["code"], w["rule"]) for w in payload["weakenings"]] == [("coverage", "inv-a")]
    assert "'src/**/*.py'" in payload["weakenings"][0]["message"]


@needs_git
@needs_signing
@pytest.mark.parametrize("move", [False, True], ids=["listed", "moved"])
def test_a_pattern_rewrite_needs_an_approval_even_when_it_reaches_every_file(tmp_path, capsys, move):
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, paths=DEEP if not move else ("src/*.py",), signer_pub=pub)
    if move:
        repo.git("mv", "src", "lib")
        repo.write(path_of("inv-a"), rule_text("inv-a", paths=("lib/*.py",)))
    else:
        repo.write("src/new.py", "z = 3\n")
        repo.write("docs/notes.md", "notes\n")
        repo.write(path_of("inv-a"), rule_text("inv-a", paths=(*LISTED, "src/new.py", "docs/notes.md")))
    repo.commit("rewrite the patterns")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1 and [w["code"] for w in payload["weakenings"]] == ["coverage"]
    approve(repo, key)
    rc, payload, _err = ci(repo, capsys)
    assert rc == 0 and payload["approval"]["valid"] is True


@needs_git
def test_a_local_narrowing_is_not_served_so_files_that_do_not_exist_yet_stay_covered(tmp_path):
    repo = make_repo(tmp_path, paths=DEEP)
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=LISTED))
    repo.write("src/evil.py", "import os\n")
    view = rule_integrity.effective(repo.root)
    served = view.ruleset.get("inv-a")
    assert served.applies_to("src/evil.py") and served.applies_to("src/pkg/deep.py")
    assert [(u.id, u.change) for u in view.unreviewed] == [("inv-a", "changed")]


def test_a_reach_lost_to_a_new_pattern_list_or_to_skipping_tests_is_coverage(tmp_path):
    everywhere = parsed(tmp_path, "inv-a", rule_text("inv-a", paths=(), forbid={"calls": ["eval"]}))
    scoped = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", paths=("src/**",), forbid={"calls": ["eval"]}))
    (found,) = weakenings(everywhere, scoped)
    assert found.code == "coverage" and "'**'" in found.message
    plain = parsed(tmp_path / "c", "inv-a", rule_text("inv-a", paths=("src/**",)))
    (found,) = weakenings(plain, scoped)
    assert found.code == "coverage" and "test files" in found.message
    assert weakenings(scoped, parsed(tmp_path / "d", "inv-a", rule_text(
        "inv-a", paths=("src/**", "lib/**"), forbid={"calls": ["eval"]}))) == []


@needs_git
def test_serving_a_broader_pattern_list_lists_no_tree(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=("src/*.py", "lib/*.py")))
    calls: List[List[str]] = []
    real = gitsafe.run

    def spy(args, *a, **kw):
        calls.append(list(args))
        return real(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", spy)
    served = rule_integrity.effective(repo.root).ruleset.get("inv-a")
    assert served.applies_to("lib/x.py")
    assert calls and not [c for c in calls if "ls-tree" in c and "--name-only" in c]


@needs_git
def test_the_head_defaults_to_head_and_can_be_named(tmp_path, capsys):
    repo = make_repo(tmp_path)
    (repo.root / path_of("inv-a")).unlink()
    repo.commit("drop it")
    repo.git("branch", "dropped")
    repo.git("reset", "-q", "--hard", "main")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 0
    rc, payload, _err = ci(repo, capsys, "--head", "dropped")
    assert rc == 1 and payload["weakenings"][0]["code"] == "deleted"


@needs_git
def test_the_pull_request_event_names_the_range_when_no_flags_do(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path)
    base = repo.head()
    (repo.root / path_of("inv-a")).unlink()
    head = repo.commit("drop it")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1 and payload["scope"]["base"] == base and payload["scope"]["head"] == head


@needs_git
def test_no_base_at_all_is_a_failure_that_says_what_to_pass(tmp_path, capsys):
    root = tmp_path / "lone"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "side", str(root)], check=True)
    os.chdir(root)
    rc = main(["check", "--ci"])
    err = capsys.readouterr().err
    assert rc == 1 and "--base" in err


@needs_git
def test_unrelated_histories_fail_instead_of_passing(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.git("checkout", "-q", "--orphan", "island")
    repo.git("rm", "-rfq", ".")
    repo.write("a.txt", "x\n")
    repo.commit("island")
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--base", "main"])
    assert rc == 1 and "share no history" in capsys.readouterr().err


@needs_git
@pytest.mark.parametrize("flag", [["--lane", "x", "--format", "github"], ["--head", "HEAD"]])
def test_ci_only_options_are_refused_elsewhere(tmp_path, capsys, flag):
    repo = make_repo(tmp_path)
    os.chdir(repo.root)
    rc = main(["check", *flag])
    assert rc == 2 and "--ci" in capsys.readouterr().err


@needs_git
def test_github_annotations_escape_what_would_break_the_command(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", extra="odd: 1"))
    repo.commit("add an odd key")
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--base", "main", "--format", "github"])
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if l.startswith("::error"))
    assert rc == 1 and "title=weakening without approval" in line and "\n" not in line.partition("::")[2]


@needs_git
def test_a_json_flag_is_honoured_for_ci(tmp_path, capsys):
    repo = make_repo(tmp_path)
    os.chdir(repo.root)
    rc = main(["--json", "check", "--ci", "--base", "main"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["status"] == "pass"


@needs_git
def test_the_mandatory_cap_counts_only_rules_that_share_a_real_file(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-b"), rule_text("inv-b"))
    repo.commit("a second mandatory rule: at the cap")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 0, payload["weakenings"]
    repo.write(path_of("inv-c"), rule_text("inv-c"))
    repo.commit("a third")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1 and [(w["code"], w["rule"]) for w in payload["weakenings"]] == [("mandatory_cap", "inv-c")]


def cap_repo(tmp_path: Path) -> hg.Repo:
    """main: gate-a and gate-b on src/*.py (the cap is full there), gate-c on lib/*.py."""
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    for path in ("src/app.py", "lib/x.py", "lib/deep/y.py", "docs/a.md"):
        repo.write(path, "x = 1\n")
    for rid, paths in (("gate-a", ("src/*.py",)), ("gate-b", ("src/*.py",)), ("gate-c", ("lib/*.py",))):
        repo.write(path_of(rid, "gate"), rule_text(rid, "gate", paths=paths, forbid={"calls": ["exec"]}))
    repo.commit("base")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    return repo


def widen_c(repo: hg.Repo, *paths: str) -> None:
    repo.write(path_of("gate-c", "gate"), rule_text("gate-c", "gate", paths=("lib/*.py", *paths), forbid={"calls": ["exec"]}))


@needs_git
@pytest.mark.parametrize("added,expected", [
    (("**/*.py",), [("mandatory_cap", "gate-c")]),
    (("docs/*.md",), []),
    (("lib/**/*.py",), []),
], ids=["crowded", "free", "inside"])
def test_widening_a_mandatory_rule_is_held_to_the_cap_where_its_reach_is_new(tmp_path, capsys, added, expected):
    repo = cap_repo(tmp_path)
    widen_c(repo, *added)
    repo.commit("widen gate-c")
    rc, payload, _err = ci(repo, capsys)
    assert [(w["code"], w["rule"]) for w in payload["weakenings"]] == expected
    assert rc == (1 if expected else 0)
    if expected:
        assert "src/app.py" in payload["weakenings"][0]["message"]


@needs_git
@pytest.mark.parametrize("added,served_paths", [
    (("**/*.py",), ("lib/*.py",)),
    (("docs/*.md",), ("lib/*.py", "docs/*.md")),
], ids=["crowded", "free"])
def test_a_local_widening_into_a_full_slot_is_not_served(tmp_path, added, served_paths):
    repo = cap_repo(tmp_path)
    widen_c(repo, *added)
    view = rule_integrity.effective(repo.root)
    assert view.ruleset.get("gate-c").target_paths == served_paths
    assert [(u.id, u.change) for u in view.unreviewed] == [("gate-c", "changed")]


# ── a workspace below the git top level ──────────────────────────────────────

def nested_repo(tmp_path: Path, prefix: str) -> Tuple[hg.Repo, Path]:
    """A monorepo whose workspace ``prefix`` holds a gate invariant on src/*.py; a sibling
    ``other/`` workspace holds a rule of its own."""
    repo = hg.Repo(tmp_path / "mono", hg.Home(tmp_path / "home"))
    repo.write("README.md", "# mono\n")
    repo.write(f"{prefix}/src/a.py", "x = 1\n")
    repo.write(f"{prefix}/{path_of('inv-a')}", rule_text("inv-a"))
    repo.write(f"other/{path_of('inv-o')}", rule_text("inv-o"))
    repo.commit("base")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    return repo, repo.root / prefix


def ci_from(where: Path, capsys) -> Tuple[int, Any, str]:
    os.chdir(where)
    rc = main(["check", "--ci", "--base", "main", "--format", "json"])
    captured = capsys.readouterr()
    return rc, json.loads(captured.out) if captured.out.strip() else None, captured.err


@needs_git
@pytest.mark.parametrize("prefix", ["pkg", "pkg dir/ü", ""], ids=["nested", "spaced", "flat"])
def test_a_workspace_below_the_top_level_checks_its_own_binding_rules(tmp_path, capsys, prefix):
    repo, ws = nested_repo(tmp_path, prefix) if prefix else (make_repo(tmp_path), None)
    ws = ws or repo.root
    repo.write(f"{prefix}/{path_of('inv-a')}".lstrip("/"), rule_text("inv-a", enforcement="advisory"))
    repo.commit("drop the gate to advisory")
    rc, payload, err = ci_from(ws, capsys)
    assert rc == 1, err
    assert payload["rules_checked"] == 1 and [(w["code"], w["rule"]) for w in payload["weakenings"]] == [("rank", "inv-a")]


@needs_git
def test_a_nested_workspace_serves_its_base_rules_and_lists_an_edit_as_changed(tmp_path):
    repo, ws = nested_repo(tmp_path, "pkg")
    repo.write(f"pkg/{path_of('inv-a')}", rule_text("inv-a", body="# The title\n\nA softer reason.\n"))
    view = rule_integrity.effective(ws)
    assert [(u.id, u.change) for u in view.unreviewed] == [("inv-a", "changed")]
    assert "Why this rule exists." in view.ruleset.get("inv-a").body
    assert view.ruleset.get("inv-o") is None


@needs_git
@pytest.mark.parametrize("move,expected", [
    (("pkg/src", "pkg/lib"), [("coverage", "inv-a")]),
    (("pkg/src/a.py", "pkg/src/b.py"), []),
], ids=["out", "inside"])
def test_coverage_follows_renames_inside_a_nested_workspace(tmp_path, capsys, move, expected):
    repo, ws = nested_repo(tmp_path, "pkg")
    repo.git("mv", *move)
    repo.commit("move")
    rc, payload, err = ci_from(ws, capsys)
    assert [(w["code"], w["rule"]) for w in payload["weakenings"]] == expected, err
    assert rc == (1 if expected else 0)


@needs_git
def test_a_layout_git_cannot_place_fails_the_ci_check(tmp_path, capsys, monkeypatch):
    repo, ws = nested_repo(tmp_path, "pkg")
    real = gitsafe.run

    def refuse(args, *a, **kw):
        if "--show-prefix" in args:
            return subprocess.CompletedProcess(list(args), 128, b"", b"fatal: not a git repository")
        return real(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", refuse)
    rc, payload, err = ci_from(ws, capsys)
    assert rc == 1 and payload is None and err.startswith("Error:")


def test_a_path_is_relative_to_the_workspace_prefix_only_inside_it():
    assert gitsafe.relative_to_prefix("", "src/a.py") == "src/a.py"
    assert gitsafe.relative_to_prefix("pkg dir/ü/", "pkg dir/ü/src/a.py") == "src/a.py"
    assert gitsafe.relative_to_prefix("pkg/", "pkgx/src/a.py") is None
    assert gitsafe.relative_to_prefix("pkg/", "other/pkg/a.py") is None


def test_the_cap_is_the_one_the_scan_uses():
    assert scan_mod.MANDATORY_SLOT_CAP == rule_integrity.MANDATORY_SLOT_CAP == 2


@needs_git
def test_reading_the_range_never_writes_to_the_repository(tmp_path, capsys):
    repo = make_repo(tmp_path)
    (repo.root / path_of("inv-a")).unlink()
    repo.commit("drop it")
    before = repo.git("count-objects", "-v"), repo.git("for-each-ref"), repo.git("status", "--porcelain")
    ci(repo, capsys)
    assert (repo.git("count-objects", "-v"), repo.git("for-each-ref"), repo.git("status", "--porcelain")) == before


def test_gitsafe_is_how_git_is_run():
    assert rule_integrity.gitsafe is gitsafe


# ── R-trust-43: at tier A a non-author's approving review of the head commit approves ──

class ReviewGh(hg.FakeGh):
    """FakeGh plus the pull request reviews endpoint; ``fail`` maps a path fragment to a failing GhResult."""

    def __init__(self, reviews: Optional[List[Dict[str, Any]]] = None, fail: Optional[Dict[str, Any]] = None,
                 branch_rules: Optional[Dict[str, List[Dict[str, Any]]]] = None, **kw: Any) -> None:
        kw.setdefault("rules", [hg.pull_request_rule(approvals=1, code_owners=True, dismiss_stale=True, last_push=True)])
        super().__init__(**kw)
        self.reviews = reviews if reviews is not None else []
        self.fail = fail or {}
        self.branch_rules = branch_rules or {}  # the quoted branch of a rules/branches/ path -> its rules

    def __call__(self, argv, stdin=None, cwd=None):
        from aegis_core import ghcli
        if self.missing:
            return None
        path = tuple(argv)[-1]
        for fragment, result in self.fail.items():
            if fragment in path:
                self.calls.append((tuple(argv), stdin))
                return result
        if "/pulls/" in path:
            self.calls.append((tuple(argv), stdin))
            return ghcli.GhResult(0, json.dumps(self.reviews), "")
        branch = path.partition("/rules/branches/")[2]
        if branch in self.branch_rules:
            self.calls.append((tuple(argv), stdin))
            return ghcli.GhResult(0, json.dumps(self.branch_rules[branch]), "")
        return super().__call__(argv, stdin, cwd)

    @property
    def review_calls(self) -> List[str]:
        return [c[0][-1] for c in self.calls if "/pulls/" in c[0][-1]]

    @property
    def rules_calls(self) -> List[str]:
        return [c[0][-1] for c in self.calls if "/rules/branches/" in c[0][-1]]


def review(login: str, sha: str, state: str = "APPROVED", association: str = "COLLABORATOR",
           kind: Optional[str] = "User") -> Dict[str, Any]:
    user = {"login": login, **({} if kind is None else {"type": kind})}
    return {"user": user, "state": state, "commit_id": sha, "author_association": association}


def tier_a_repo(tmp_path: Path, codeowners: Optional[str] = hg.CODEOWNERS_FULL, signer: bool = False) -> hg.Repo:
    """make_repo with the base's CODEOWNERS (and an allowed_signers key) committed on main."""
    repo = make_repo(tmp_path)
    repo.git("checkout", "-q", "main")
    if codeowners is not None:
        repo.write(".github/CODEOWNERS", codeowners)
    if signer:
        repo.write("allowed_signers", hg.allowed_signers_text(hg.hardware_public_key()))
    repo.commit("protect", allow_empty=True)
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("checkout", "-q", "-B", "work")
    return repo


_ABSENT = object()


def pull_event(tmp_path: Path, monkeypatch, base: str, head: str, number: Any = 7, login: Any = "agent",
               name: str = "pull_request", base_ref: Any = "main") -> None:
    event = tmp_path / "event.json"
    pull = {"number": number, "user": {"login": login}, "base": {"sha": base, **({} if base_ref is _ABSENT else
                                                                                 {"ref": base_ref})},
            "head": {"sha": head}}
    event.write_text(json.dumps({"number": number, "pull_request": pull}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", name)


def reviewed_weakening(tmp_path: Path, monkeypatch, gh: ReviewGh, **event: Any) -> Tuple[hg.Repo, str]:
    """A tier A repo whose pull request deletes the binding rule inv-a, run as a pull_request job."""
    from aegis_core import ghcli
    repo = tier_a_repo(tmp_path)
    base = repo.head()
    (repo.root / path_of("inv-a")).unlink()
    head = repo.commit("drop the rule")
    pull_event(tmp_path, monkeypatch, base, event.pop("head", head), **event)
    monkeypatch.setattr(ghcli, "default_gh_runner", gh)
    os.chdir(repo.root)
    return repo, head


def ci_event(capsys, *extra: str) -> Tuple[int, Any]:
    rc = main(["check", "--ci", "--format", "json", *extra])
    out = capsys.readouterr().out
    return rc, json.loads(out) if out.strip() else None


@needs_git
def test_tier_a_a_non_author_approving_review_of_the_head_approves_a_weakening(tmp_path, capsys, monkeypatch):
    gh = ReviewGh()
    repo, head = reviewed_weakening(tmp_path, monkeypatch, gh)
    gh.reviews = [review("human", head, association="OWNER")]
    rc, payload = ci_event(capsys)
    assert rc == 0 and payload["status"] == "pass", payload
    assert payload["approval"]["valid"] is True and payload["approval"]["method"] == "review"
    assert payload["approval"]["signer"] == "human" and payload["approval"]["scope"]["commit"] == head
    assert gh.review_calls == ["repos/{owner}/{repo}/pulls/7/reviews?per_page=100"]
    assert gh.posts == []
    assert main(["check", "--ci"]) == 0
    assert "approved by review of human" in capsys.readouterr().out


def _without_last_push() -> Dict[str, Any]:
    rule = hg.pull_request_rule(approvals=1, code_owners=True, dismiss_stale=True, last_push=True)
    del rule["parameters"]["require_last_push_approval"]
    return rule


@needs_git
@pytest.mark.parametrize("rule", [
    hg.pull_request_rule(approvals=1, code_owners=False, dismiss_stale=True, last_push=True),
    hg.pull_request_rule(approvals=1, code_owners=True, dismiss_stale=False, last_push=True),
    hg.pull_request_rule(approvals=0, code_owners=True, dismiss_stale=True, last_push=True),
    hg.pull_request_rule(approvals=1, code_owners=True, dismiss_stale=True, last_push=False),
    _without_last_push(),
], ids=["no-code-owner-review", "stale-kept", "no-approval", "last-pusher-may-approve", "last-push-absent"])
def test_a_review_under_a_tier_b_or_c_ruleset_approves_nothing_and_reviews_are_never_read(
        tmp_path, capsys, monkeypatch, rule):
    gh = ReviewGh(rules=[rule])
    _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh)
    gh.reviews = [review("human", head, association="OWNER")]
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None
    assert gh.review_calls == []


@needs_git
@pytest.mark.parametrize("codeowners", [None, "/src/ @octo\n"], ids=["none", "partial"])
def test_a_base_codeowners_that_does_not_own_the_change_reads_no_review(tmp_path, capsys, monkeypatch, codeowners):
    from aegis_core import ghcli
    gh = ReviewGh()
    repo = tier_a_repo(tmp_path, codeowners=codeowners)
    base = repo.head()
    (repo.root / path_of("inv-a")).unlink()
    head = repo.commit("drop the rule")
    gh.reviews = [review("human", head, association="OWNER")]
    pull_event(tmp_path, monkeypatch, base, head)
    monkeypatch.setattr(ghcli, "default_gh_runner", gh)
    os.chdir(repo.root)
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None and gh.review_calls == []


def _old_sha() -> str:
    return "0123456789abcdef0123456789abcdef01234567"


@needs_git
@pytest.mark.parametrize("make_reviews", [
    lambda head: [review("human", _old_sha())],
    lambda head: [review("agent", head)],
    lambda head: [review("Agent", head)],
    lambda head: [review("human", head, association="NONE")],
    lambda head: [review("human", head, association="CONTRIBUTOR")],
    lambda head: [review("human", head), review("human", head, state="CHANGES_REQUESTED")],
    lambda head: [review("human", head, state="DISMISSED")],
    lambda head: [review("human", head, state="COMMENTED")],
    lambda head: [review(f"user{i}", head, state="COMMENTED") for i in range(100)],
    lambda head: [{"state": "APPROVED", "commit_id": head, "author_association": "OWNER"}],
    lambda head: {"message": "not a list"},
    lambda head: [review("helper[bot]", head, kind="Bot")],
    lambda head: [review("helper", head, kind=None)],
], ids=["old-sha", "author", "author-case", "none-assoc", "contributor", "later-change-request", "dismissed",
        "commented", "full-page", "no-user", "not-a-list", "bot", "untyped"])
def test_a_review_that_does_not_approve_this_head_as_a_reviewer_fails(tmp_path, capsys, monkeypatch, make_reviews):
    gh = ReviewGh()
    _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh)
    gh.reviews = make_reviews(head)
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None


@needs_git
def test_a_full_first_page_fails_closed_even_when_it_holds_an_approval(tmp_path, capsys, monkeypatch):
    gh = ReviewGh()
    _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh)
    gh.reviews = [review("human", head)] + [review(f"user{i}", head, state="COMMENTED") for i in range(99)]
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None


@needs_git
@pytest.mark.parametrize("fail", [
    {"/rules/branches/": (1, "", "gh: Not Found (HTTP 404)")},
    {"repos/{owner}/{repo}": (4, "", "To get started with GitHub CLI, please run:  gh auth login")},
    {"/pulls/": (1, "", "gh: Resource not accessible by integration (HTTP 403)")},
    {"/pulls/": (0, "not json", "")},
    {"/rules/branches/": (0, "not json", "")},
], ids=["rules-404", "unauthenticated", "http-403", "reviews-bad-json", "rules-bad-json"])
def test_gh_that_cannot_answer_fails_closed(tmp_path, capsys, monkeypatch, fail):
    from aegis_core import ghcli
    gh = ReviewGh(fail={k: ghcli.GhResult(*v) for k, v in fail.items()})
    _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh)
    gh.reviews = [review("human", head, association="OWNER")]
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None


@needs_git
def test_without_gh_the_review_path_fails_closed(tmp_path, capsys, monkeypatch):
    gh = ReviewGh()
    gh.missing = True
    _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh)
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None


@needs_git
@pytest.mark.parametrize("event", [
    {"number": -1}, {"number": 0}, {"number": True}, {"number": "7"},
    {"login": "a/b"}, {"login": "x?y"}, {"login": ""}, {"login": None},
    {"head": "short"}, {"name": "push"}, {"name": ""},
    {"base_ref": _ABSENT}, {"base_ref": None}, {"base_ref": ""}, {"base_ref": "../main"}, {"base_ref": "main?x=1"},
    {"base_ref": "-x"}, {"base_ref": "a b"}, {"base_ref": "x/"}, {"base_ref": "x.lock"}, {"base_ref": ["main"]},
], ids=["negative", "zero", "bool", "string", "slash", "query", "empty-login", "no-login", "short-sha",
        "push", "no-event", "no-base-ref", "null-base-ref", "empty-base-ref", "dotdot-base-ref",
        "query-base-ref", "dash-base-ref", "space-base-ref", "slash-end-base-ref", "lock-base-ref", "list-base-ref"])
def test_a_doubtful_event_is_no_pull_request_and_calls_no_gh(tmp_path, capsys, monkeypatch, event):
    gh = ReviewGh()
    if event.get("head") == "short":
        repo = tier_a_repo(tmp_path)
        base = repo.head()
        (repo.root / path_of("inv-a")).unlink()
        head = repo.commit("drop the rule")
        event = {"head": head[:7]}
        from aegis_core import ghcli
        pull_event(tmp_path, monkeypatch, base, **event)
        monkeypatch.setattr(ghcli, "default_gh_runner", gh)
        os.chdir(repo.root)
    else:
        _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh, **event)
    gh.reviews = [review("human", head, association="OWNER")]
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None and gh.calls == []


TIER_A_RULES = [hg.pull_request_rule(approvals=1, code_owners=True, dismiss_stale=True, last_push=True)]


@needs_git
def test_a_pull_request_into_another_branch_is_judged_by_that_branchs_rules(tmp_path, capsys, monkeypatch):
    """Given main's rules make the review the merge gate and develop's do not require code-owner review,
    When the pull request targets develop, Then its review approves nothing and the reviews are never read."""
    develop = [hg.pull_request_rule(approvals=1, code_owners=False, dismiss_stale=True, last_push=True)]
    gh = ReviewGh(rules=TIER_A_RULES, branch_rules={"main": TIER_A_RULES, "develop": develop})
    _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh, base_ref="develop")
    gh.reviews = [review("human", head, association="OWNER")]
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["approval"] is None
    assert gh.rules_calls == ["repos/{owner}/{repo}/rules/branches/develop"] and gh.review_calls == []


@needs_git
@pytest.mark.parametrize("ref,quoted", [("develop", "develop"), ("release/4.4", "release%2F4.4")])
def test_a_pull_request_into_a_branch_whose_own_rules_gate_the_review_is_approved(
        tmp_path, capsys, monkeypatch, ref, quoted):
    weak = [hg.pull_request_rule(approvals=0, code_owners=False, dismiss_stale=False)]
    gh = ReviewGh(rules=weak, branch_rules={"main": weak, quoted: TIER_A_RULES})
    _repo, head = reviewed_weakening(tmp_path, monkeypatch, gh, base_ref=ref)
    gh.reviews = [review("human", head, association="OWNER")]
    rc, payload = ci_event(capsys)
    assert rc == 0 and payload["approval"]["method"] == "review", payload
    assert gh.rules_calls == [f"repos/{{owner}}/{{repo}}/rules/branches/{quoted}"]


@needs_git
def test_a_review_of_the_event_head_does_not_approve_another_head(tmp_path, capsys, monkeypatch):
    gh = ReviewGh()
    repo, head = reviewed_weakening(tmp_path, monkeypatch, gh)
    gh.reviews = [review("human", head, association="OWNER")]
    repo.write("src/app.py", "x = 2\n")
    later = repo.commit("a later commit the review never saw")
    rc, payload = ci_event(capsys, "--head", later)
    assert rc == 1 and payload["approval"] is None and gh.calls == []


@needs_git
@needs_signing
def test_a_signed_approval_still_passes_with_no_gh_call(tmp_path, capsys, monkeypatch):
    key, pub = hg.keygen(tmp_path / "keys", "human")
    gh = ReviewGh()
    from aegis_core import ghcli
    repo = make_repo(tmp_path, signer_pub=pub)
    base = repo.head()
    (repo.root / path_of("inv-a")).unlink()
    repo.commit("drop the rule")
    approve(repo, key)
    pull_event(tmp_path, monkeypatch, base, repo.head())
    monkeypatch.setattr(ghcli, "default_gh_runner", gh)
    os.chdir(repo.root)
    rc, payload = ci_event(capsys)
    assert rc == 0 and payload["approval"]["method"] == "signature" and gh.calls == []


@needs_git
def test_a_governance_change_at_a_signed_base_accepts_the_same_review(tmp_path, capsys, monkeypatch):
    from aegis_core import ghcli
    gh = ReviewGh()
    repo = tier_a_repo(tmp_path, signer=True)
    base = repo.head()
    repo.write(".github/workflows/ci.yml", "name: CI\n")
    head = repo.commit("a workflow")
    pull_event(tmp_path, monkeypatch, base, head)
    monkeypatch.setattr(ghcli, "default_gh_runner", gh)
    os.chdir(repo.root)
    rc, payload = ci_event(capsys)
    assert rc == 1 and payload["governance"]["enforced"] is True and payload["approval"] is None
    gh.reviews = [review("human", head, association="MEMBER")]
    rc, payload = ci_event(capsys)
    assert rc == 0 and payload["governance"]["approved"] is True and payload["approval"]["method"] == "review"


# ── R-trust-63: a skip marker is a lane finding, not a check --ci gate (the accepted 2.3 gap) ──

@needs_git
def test_a_skip_marker_is_reported_by_the_lane_gate_and_not_gated_by_check_ci(tmp_path, capsys):
    from aegis_core import lane_gate
    repo = make_repo(tmp_path)
    repo.git("checkout", "-q", "main")
    repo.write("tests/test_app.py", "def test_app():\n    assert True\n")
    repo.commit("a test")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("checkout", "-q", "-B", "work")
    repo.write("tests/test_app.py", "import pytest\n\n\n@pytest.mark.skip\ndef test_app():\n    assert True\n")
    repo.commit("skip it")
    lane = lane_gate.check_lane(repo.root, "docs", base="main", paths=["**"])
    assert [f.kind for f in lane.findings] == ["skip"]
    rc, payload, _err = ci(repo, capsys)
    # The gap stays visible: this flips when check --ci gates skip markers (R-trust-63 option B).
    assert rc == 0 and payload["weakenings"] == [] and payload["governance"]["paths"] == []


# ── R-trust-13 (a): check --ci --no-exec reads git objects only ──────────────────

def _ledger_spies(monkeypatch) -> List[str]:
    """Every way to the ledger, recorded: its site, its rows and a void row."""
    from aegis_core import credit, storage
    from aegis_core.telemetry_engine import ledger
    seen: List[str] = []
    for module, name in ((storage, "ledger_site"), (ledger, "ledger_site"), (credit, "read_rows"),
                         (credit, "record_void")):
        real = getattr(module, name)

        def spy(*a, _real=real, _name=name, **kw):
            seen.append(_name)
            return _real(*a, **kw)
        monkeypatch.setattr(module, name, spy)
    return seen


def trailer_repo(tmp_path: Path, sentinel: Path) -> hg.Repo:
    """A pull request whose head adds a conftest.py that writes ``sentinel`` and carries a matching
    Aegis-Check trailer, so a full check --ci reruns the head snapshot's tests. The user-scope test
    command runs that conftest.py itself (this machine's pytest may live outside the hermetic run)."""
    import sys
    aegis_home = tmp_path / "home" / ".aegis"
    aegis_home.mkdir(parents=True, exist_ok=True)
    (aegis_home / "config.json").write_text(json.dumps({"v": 1, "tests": {"command": [sys.executable, "conftest.py"]}}),
                                            encoding="utf-8")
    repo = make_repo(tmp_path)
    repo.write("tests/test_app.py", "def test_app():\n    assert True\n")
    repo.write("conftest.py", f"open({str(sentinel)!r}, 'w').close()\n")
    repo.git("add", "-A")
    tree = repo.git("write-tree")
    repo.commit(f"tests\n\nAegis-Check: tree={tree} exit=0\n")
    return repo


@needs_git
def test_no_exec_runs_no_repository_code_and_never_touches_the_ledger(tmp_path, capsys, monkeypatch):
    sentinel = tmp_path / "sentinel"
    repo = trailer_repo(tmp_path, sentinel)
    seen = _ledger_spies(monkeypatch)
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--no-exec", "--base", "main"])
    out = capsys.readouterr().out
    assert rc == 0 and not sentinel.exists()
    assert "note: --no-exec: the regression and Aegis-Check trailer checks were not run" in out
    assert seen == [] and not (repo.root / ".git" / "aegis").exists()
    rc, payload, _err = ci(repo, capsys, "--no-exec")
    assert rc == 0 and payload["skipped"] == ["regression", "trailer_checks"] and "trailer_checks" not in payload
    assert "regression" not in payload and seen == [] and not sentinel.exists()
    for fmt in ("sarif", "github"):
        assert main(["check", "--ci", "--no-exec", "--base", "main", "--format", fmt]) == 0
    assert "--no-exec" in capsys.readouterr().out and seen == [] and not sentinel.exists()


@needs_git
def test_without_no_exec_the_same_range_runs_the_head_snapshot(tmp_path, capsys):
    sentinel = tmp_path / "sentinel"
    repo = trailer_repo(tmp_path, sentinel)
    rc, payload, _err = ci(repo, capsys)
    assert sentinel.exists(), "the control must prove the harness executes the pull request's code"
    assert "skipped" not in payload and payload["trailer_checks"]


@needs_git
@needs_signing
def test_no_exec_still_fails_an_unapproved_gate_deletion_and_passes_a_signed_one(tmp_path, capsys):
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, signer_pub=pub)
    (repo.root / path_of("inv-a")).unlink()
    repo.commit("drop the rule")
    rc, payload, _err = ci(repo, capsys, "--no-exec")
    assert rc == 1 and [w["code"] for w in payload["weakenings"]] == ["deleted"]
    approve(repo, key)
    rc, payload, _err = ci(repo, capsys, "--no-exec")
    assert rc == 0 and payload["approval"]["valid"] is True


@needs_git
@pytest.mark.parametrize("path,text", [
    (".github/workflows/aegis.yml", "name: Aegis\non: [pull_request]\njobs: {}\n"),
    ("allowed_signers", None),
    ("CODEOWNERS", "* @someone-else\n"),
], ids=["workflow", "signers", "codeowners"])
def test_no_exec_fails_an_unapproved_change_to_what_defines_enforcement(tmp_path, capsys, path, text):
    repo = make_repo(tmp_path, signer_pub=hg.hardware_public_key())
    repo.write(path, text if text is not None else hg.allowed_signers_text(hg.hardware_public_key(), "ssh-ed25519 " + "A" * 68))
    repo.commit("rewrite enforcement")
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--no-exec", "--base", "main"])
    out = capsys.readouterr().out
    assert rc == 1 and "FAILED: governance change without approval" in out
    assert f"] {path}" in out


@needs_git
@pytest.mark.parametrize("flag", ["--coverage", "--perf"])
def test_no_exec_refuses_the_flags_that_run_code(tmp_path, capsys, flag):
    repo = make_repo(tmp_path)
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--no-exec", flag, "--base", "main"])
    err = capsys.readouterr().err
    assert rc == 2 and "--no-exec" in err and flag in err


@needs_git
def test_no_exec_never_says_strict_runs_code_and_strict_gets_the_ci_refusal(tmp_path, capsys):
    """Review F5: --strict runs no code under --ci, where it is a usage error of its own. Given --no-exec
    --strict, Then exit 2 with --ci's refusal of --strict; given --no-exec --coverage --strict, Then exit
    2 and the --no-exec refusal names --coverage alone."""
    repo = make_repo(tmp_path)
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--no-exec", "--strict", "--base", "main"])
    err = capsys.readouterr().err
    assert rc == 2 and "--ci does not combine with --strict" in err and "run the repository's code" not in err
    rc = main(["check", "--ci", "--no-exec", "--coverage", "--strict", "--base", "main"])
    err = capsys.readouterr().err
    assert rc == 2 and "Error: --no-exec does not combine with --coverage: they run the repository's code" in err


@needs_git
def test_no_exec_refuses_a_required_regression_gate(tmp_path, capsys):
    import argparse
    from aegis_cli.check import run_check
    repo = make_repo(tmp_path)
    args = argparse.Namespace(ci=True, no_exec=True, require_regression=True, base="main", workspace=str(repo.root))
    assert run_check(args) == 2 and "--require-regression" in capsys.readouterr().err


@needs_git
def test_no_exec_without_ci_is_a_usage_error(tmp_path, capsys):
    repo = make_repo(tmp_path)
    os.chdir(repo.root)
    rc = main(["check", "--no-exec"])
    assert rc == 2 and "--ci" in capsys.readouterr().err


@needs_git
def test_no_exec_with_an_unresolvable_base_still_fails(tmp_path, capsys):
    repo = make_repo(tmp_path)
    os.chdir(repo.root)
    rc = main(["check", "--ci", "--no-exec", "--base", "no-such-branch"])
    assert rc == 1 and "cannot resolve the base" in capsys.readouterr().err


# ── R-trust-49: one fingerprint, one key schema, one rank; the JSON shapes stay as they were ──

# The key order of each serialized record at ff3ac4d0 (AC-9): a reader that walks the keys sees the same document.
WEAKENING_KEYS = ["code", "rule", "path", "message"]
RULES_BASE_KEYS = ["ref", "commit", "source", "witnessed", "label"]
UNREVIEWED_KEYS = ["id", "title", "change"]


@needs_git
def test_a_deleted_gate_rule_serializes_its_weakening_in_the_pinned_key_order(tmp_path, capsys):
    repo = make_repo(tmp_path)
    (repo.root / path_of("inv-a")).unlink()
    repo.commit("drop the rule")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1 and [w["code"] for w in payload["weakenings"]] == ["deleted"]
    assert list(payload["weakenings"][0]) == WEAKENING_KEYS
    assert payload["weakenings"][0]["rule"] == "inv-a" and payload["weakenings"][0]["path"] == path_of("inv-a")


@needs_git
def test_a_scan_serializes_the_base_and_each_unreviewed_rule_in_the_pinned_key_order(tmp_path):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", body="# A branch-local title\n\nReworded.\n"))
    scan_mod.RULE_CACHE.invalidate()
    result = scan_mod.scan(str(repo.root), ["src/app.py"])
    assert list(result["rules_base"]) == RULES_BASE_KEYS
    assert result["rules_base"]["source"] == "origin-head" and result["rules_base"]["witnessed"] is True
    assert [list(u) for u in result["unreviewed_rules"]] == [UNREVIEWED_KEYS]
    assert result["unreviewed_rules"] == [{"id": "inv-a", "title": "A branch-local title", "change": "changed"}]


@needs_git
def test_one_fingerprint_function_decides_a_working_tree_equal_to_base_and_one_that_is_not(tmp_path):
    from aegis_core import rule_inventory

    repo = make_repo(tmp_path)
    working = rule_inventory.inventory_rules(repo.root)
    base = rule_integrity._inventory_at(str(repo.root), repo.head())
    assert base.fingerprint == rule_inventory.fingerprint(base.entries) == rule_inventory.fingerprint(working.entries)
    assert working.fingerprint == base.fingerprint
    view = rule_integrity.effective(repo.root)
    assert view.unreviewed == () and view.ruleset.fingerprint == load_rules(repo.root).fingerprint

    target = repo.root / path_of("trap-a", "trap")
    target.write_bytes(target.read_bytes().replace(b"Why this rule", b"why this rule"))
    edited = rule_inventory.inventory_rules(repo.root)
    assert edited.fingerprint == rule_inventory.fingerprint(edited.entries) != base.fingerprint
    assert rule_integrity.effective(repo.root).ruleset.fingerprint == f"{edited.fingerprint}@{repo.head()}"


@needs_git
def test_no_rule_files_give_the_fingerprint_of_no_entries_on_both_sides(tmp_path):
    from aegis_core import rule_inventory

    repo = hg.Repo(tmp_path / "bare-rules", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "x = 1\n")
    repo.commit("no rules")
    empty = rule_inventory.fingerprint(())
    assert rule_inventory.inventory_rules(repo.root).fingerprint == empty
    assert rule_integrity._inventory_at(str(repo.root), repo.head()).fingerprint == empty


def test_weakenings_no_longer_reports_applies_to_and_check_ci_still_does(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a"))
    scoped = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", extra="applies_to:\n  - api-surface"))
    assert weakenings(base, scoped) == [] and weakenings(scoped, base) == []


@needs_git
def test_applies_to_is_reported_once_per_rule_last_within_a_base_rule_then_for_head_rules(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=("src/app.py",), extra="applies_to:\n  - api-surface"))
    repo.write(path_of("trap-a", "trap"), rule_text("trap-a", "trap", "advisory", extra="applies_to:\n  - cli"))
    repo.commit("scope both rules")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1
    assert [(w["code"], w["rule"]) for w in payload["weakenings"]] == [
        ("coverage", "inv-a"), ("applies_to", "inv-a"), ("applies_to", "trap-a")]


@needs_git
def test_a_binding_edit_that_changes_applies_to_and_widens_target_paths_is_still_served_as_reviewed(tmp_path):
    """The _stricter guard: a widening alone would be merged, but not one that also changes applies_to."""
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=("src/*.py", "lib/*.py"), extra="applies_to:\n  - api-surface"))
    view = rule_integrity.effective(repo.root)
    served = view.ruleset.get("inv-a")
    assert not served.applies_to("lib/x.py") and "applies_to" not in served.meta
    assert [(u.id, u.change) for u in view.unreviewed] == [("inv-a", "changed")]


@pytest.mark.parametrize("rtype,enforcement,rank", [
    ("gate", None, 3), ("gate", "advisory", 3), ("invariant", None, 2), ("invariant", "advisory", 2),
    ("trap", "gate", 2), ("boundary", "gate", 2), ("trap", "mechanical", 1), ("trap", None, 1), (None, None, 1),
], ids=["gate", "gate-advisory", "invariant", "invariant-advisory", "trap-gate", "boundary-gate", "trap-mech",
        "trap", "untyped"])
def test_the_rank_is_three_for_a_gate_two_for_any_other_mandatory_rule_and_one_otherwise(rtype, enforcement, rank):
    from aegis_core import rules as rules_mod

    meta = {} if enforcement is None else {"enforcement": enforcement}
    rule = rules_mod.Rule("r", "x.md", rtype, meta, "", "0" * 64)
    assert rule.rank == rank and rule.mandatory is (rank >= 2)


def test_the_duplicated_definitions_are_gone():
    from aegis_core import rules as rules_mod

    assert not hasattr(rules_mod, "rank_of")
    assert [name for name in ("renamed_rules", "BENIGN_KEYS", "EXCLUDED_KEYS") if hasattr(rule_integrity, name)] == []


# Adding a key to a rule's known keys is a reviewed edit of this literal (aegis_core.rules owns the schema).
KNOWN_KEYS = frozenset({
    "type", "enforcement", "target_paths", "forbid_ast", "expired_at", "applies_to",
    "minimum_mode", "impact_weight", "expiry_days", "expiry_sessions", "detect",
    "id", "name", "description", "domain", "hypothesis", "prediction", "falsification", "created", "tags",
    "lineage", "triggers", "persona_name", "origin", "expertise", "expertise_domain", "promotion_threshold",
    "demotion_threshold",
})


def test_the_known_keys_are_the_pinned_schema_and_only_another_key_is_unknown(tmp_path):
    from dataclasses import replace

    from aegis_core import rules as rules_mod

    assert rules_mod.KNOWN_KEYS == KNOWN_KEYS and "KNOWN_KEYS" in rules_mod.__all__
    base = parsed(tmp_path, "inv-a", rule_text("inv-a"))
    for key in sorted(KNOWN_KEYS):
        head = replace(base, meta={**base.meta, key: "changed-value"})
        assert "unknown_key" not in codes(weakenings(base, head)), key
    invented = replace(base, meta={**base.meta, "exempt_files": ["src"]})
    assert codes(weakenings(base, invented)) == ["unknown_key"]
