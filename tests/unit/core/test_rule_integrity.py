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
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


def make_repo(tmp_path: Path, origin: bool = True) -> hg.Repo:
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "x = 1\n")
    repo.write("src/util.py", "y = 2\n")
    repo.write(path_of("inv-a"), rule_text("inv-a"))
    repo.write(path_of("trap-a", "trap"), rule_text("trap-a", "trap", "advisory", paths=("src/*.py",)))
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


def test_a_forbid_ast_option_this_version_cannot_compare_must_be_carried_over(tmp_path):
    base = parsed(tmp_path, "inv-a", rule_text("inv-a", forbid={"imports": ["os"], "where": ["x"]}))
    dropped = parsed(tmp_path / "b", "inv-a", rule_text("inv-a", forbid={"imports": ["os"]}))
    assert codes(weakenings(base, dropped)) == ["forbid_ast"]
    widened = parsed(tmp_path / "c", "inv-a", rule_text("inv-a", forbid={"imports": ["os"], "where": ["x", "y"]}))
    assert weakenings(base, widened) == []


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
    result = scan_mod.scan(repo.root, ["src/app.py"])
    assert result["status"] == "FAIL"
    assert "the reviewed (base) version of the rules cannot be read" in result["error"]
    assert not result.get("relevant_rules")


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


# ── the CI check ─────────────────────────────────────────────────────────────

@needs_git
def test_the_report_names_the_range_and_counts_the_binding_rules(tmp_path, capsys):
    repo = make_repo(tmp_path)
    rc, payload, _err = ci(repo, capsys)
    assert rc == 0 and payload["rules_checked"] == 1
    assert payload["schema"] == "aegis.rule_integrity/v1"
    assert payload["scope"]["mode"] == "ci"


@needs_git
def test_deleting_a_file_a_gate_covered_is_not_a_loss_of_coverage(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=("src/app.py",)))
    repo.commit("narrow to one file")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 1 and [w["code"] for w in payload["weakenings"]] == ["coverage"]
    assert "src/util.py" in payload["weakenings"][0]["message"]
    repo.git("reset", "-q", "--hard", "main")
    repo.write(path_of("inv-a"), rule_text("inv-a", paths=("src/app.py",)))
    repo.git("rm", "-q", "src/util.py")
    repo.commit("narrow and remove what it no longer covers")
    rc, payload, _err = ci(repo, capsys)
    assert rc == 0, payload["weakenings"]


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
@pytest.mark.parametrize("flag", [["--format", "github"], ["--head", "HEAD"]])
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
