"""`aegis check --ci` when there is nothing to compare (R-trust-17).

A push to the default branch, a dispatch run or a stale branch resolves the base to the head (or
to a descendant of it): the range is empty, so the run says it compared nothing instead of the
PASSED a real comparison prints. Exit code and JSON shape stay as they were; a pull request run
still compares its base with its head. Real git; no network, no host CLI.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_cli.cli import main
from aegis_cli import check as check_cli
from aegis_cli.formatters import report as report_formats
from aegis_core import approval_policy, checkrun, credit, gitsafe, regression
from aegis_core import rule_integrity as ci_integrity
from aegis_core.verification import coverage_check, perf_check
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

GATE = ".aegis/rules/gates/gate-no-eval.md"
RULE = ("---\nid: gate-no-eval\ntype: gate\nenforcement: gate\nhypothesis: Never eval\n"
        "target_paths:\n  - 'src/*.py'\nforbid_ast:\n  calls:\n    - eval\n---\n# No eval\n\nThe body explains why.\n")
NOTE = "nothing was compared"
PASSED = "PASSED, no rule weakened"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_STEP_SUMMARY", "SSH_AUTH_SOCK",
                 "GIT_CONFIG_GLOBAL", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


def make_repo(tmp_path: Path) -> hg.Repo:
    """``main`` holds a gate rule and its origin/main tracking ref; ``main`` stays checked out."""
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "x = 1\n")
    repo.write(GATE, RULE)
    repo.commit("base")
    repo.git("remote", "add", "origin", "/not-contacted")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return repo


def policy_repo(tmp_path: Path, mode="signature") -> hg.Repo:
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": mode, "*": "none"}}))
    repo.commit("policy")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    return repo


def push_event(tmp_path: Path, monkeypatch, before: str, after: str, target=None, *, ref=None, ref_present=True) -> None:
    event = tmp_path / "push.json"
    ref = "refs/heads/" + (target or "main") if ref is None else ref
    event.write_text(json.dumps({"ref": ref, "before": before, "after": after}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    environment = {"GITHUB_REF_NAME": target or "main"}
    if ref_present:
        environment["GITHUB_REF"] = ref
    for name, value in environment.items():
        monkeypatch.setenv(name, value)


def run_ci(repo: hg.Repo, capsys, *extra: str):
    os.chdir(repo.root)
    rc = main(["check", "--ci", *extra])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@needs_git
@pytest.mark.parametrize("has_map", [False, True])
def test_empty_explicit_base_keeps_push_discovery(tmp_path, capsys, monkeypatch, has_map):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    push_event(tmp_path, monkeypatch, base, head, "main")
    path = Path(os.environ["GITHUB_EVENT_PATH"])
    document = json.loads(path.read_text(encoding="utf-8"))
    document["pull_request"] = {"base": {"sha": ""}, "head": {"sha": ""}}
    path.write_text(json.dumps(document), encoding="utf-8")
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        omitted = json.loads(out)
        empty_rc, out, _err = run_ci(repo, capsys, "--base", "", "--no-exec", "--json")
        empty = json.loads(out)
        for result in (omitted, empty):
            result.pop("checked_at")
        assert rc == empty_rc == 1 and omitted == empty
        assert empty["scope"]["base"] == base and empty["weakenings"]
        assert empty.get("approval_mode") == ("signature" if has_map else None)


@needs_git
@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("event", ["push", "pull_request", "pull_request_target"])
def test_event_HEAD_cannot_bypass_the_target_guard(tmp_path, capsys, monkeypatch, has_map, event):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    if event == "push":
        push_event(tmp_path, monkeypatch, base, head, "HEAD")
    else:
        event_file(tmp_path, monkeypatch, event, {"pull_request": {
            "base": {"sha": base, "ref": "HEAD"}, "head": {"sha": head}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1 and document["weakenings"]
        assert document.get("approval_mode") == ("signature" if has_map else None)
        assert document.get("approval_target") is None


@needs_git
def test_a_push_to_main_that_deletes_a_gate_says_it_compared_nothing(tmp_path, capsys, monkeypatch):
    """Given a push to main whose commit deletes a gate rule (origin/main is that commit), When check --ci
    runs on the push event, Then it says nothing was compared, never a bare PASSED, and exits 0."""
    repo = make_repo(tmp_path)
    before = repo.head()
    (repo.root / GATE).unlink()
    after = repo.commit("drop the gate")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    push_event(tmp_path, monkeypatch, before, after)
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0
    assert f"aegis check --ci: note: base and head are the same commit; {NOTE} ({after[:10]}..{after[:10]})" in out
    assert PASSED not in out


@needs_git
def test_the_json_document_keeps_its_shape_when_nothing_was_compared(tmp_path, capsys):
    repo = make_repo(tmp_path)
    head = repo.head()
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--format", "json")
    payload = json.loads(out)
    assert rc == 0 and payload["status"] == "pass" and NOTE not in out
    assert payload["scope"]["merge_base"] == payload["scope"]["head"] == head
    assert set(payload) == {"source", "aegis_version", "checked_at", "scope", "schema", "status", "rules_checked",
                            "weakenings", "approval", "governance", "regression", "blocking"}


@needs_git
def test_a_stale_branch_behind_its_base_also_compares_nothing(tmp_path, capsys):
    """Sad: a head that is an ancestor of the base gives the note, not PASSED."""
    repo = make_repo(tmp_path)
    repo.branch("stale")
    repo.git("checkout", "-q", "main")
    repo.write("src/app.py", "x = 2\n")
    repo.commit("main moves on")
    repo.git("checkout", "-q", "stale")
    rc, out, _err = run_ci(repo, capsys, "--base", "main")
    assert rc == 0 and NOTE in out and PASSED not in out


@needs_git
def test_a_pull_request_run_still_compares_and_fails_an_unapproved_weakening(tmp_path, capsys, monkeypatch):
    """Sad: the pull_request event file names a real range; the deletion is found and fails."""
    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("drop the gate")
    event = tmp_path / "pr.json"
    event.write_text(json.dumps({"pull_request": {"number": 1, "user": {"login": "agent"},
                                                  "base": {"sha": base}, "head": {"sha": head}}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 1 and "FAILED: weakening without approval" in out and NOTE not in out
    assert f"{base[:10]}..{head[:10]}" in out


@needs_git
def test_a_real_comparison_still_says_passed(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.branch("work")
    repo.write("src/app.py", "x = 3\n")
    repo.commit("an ordinary change")
    rc, out, _err = run_ci(repo, capsys, "--base", "main")
    assert rc == 0 and PASSED in out and NOTE not in out


@needs_git
@pytest.mark.parametrize("event_name,target,mode", [
    ("push", "feature/integration", "none"),
    ("pull_request", "develop", "review"),
    ("pull_request_target", "main", "signature"),
])
def test_policy_events_use_the_target_base_and_report_findings(tmp_path, capsys, monkeypatch, event_name, target, mode):
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "develop": "review", "*": "none"}}))
    before = repo.commit("policy base")
    repo.git("update-ref", "refs/remotes/origin/main", before)
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    after = repo.commit("weakening and head attempts to lower policy")
    if event_name == "push":
        repo.git("update-ref", "refs/remotes/origin/main", after)
        push_event(tmp_path, monkeypatch, before, after, target)
    else:
        event_file(tmp_path, monkeypatch, event_name, {"pull_request": {
            "base": {"sha": before, "ref": target}, "head": {"sha": after}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        payload = json.loads(out)
        assert rc == (1 if mode == "signature" else 0)
        assert payload["scope"]["base"] == before
        assert payload["approval_mode"] == mode and payload["approval_target"] == target
        assert payload["weakenings"] and payload["policy_source"] == "base"
        assert payload["owner_review_required"] == (mode == "review")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--format", "github")
    if mode == "review":
        assert "owner review required" in out and "aegis approve" not in out
    elif mode == "signature":
        assert "aegis approve --base origin/main" in out
    else:
        assert "approved by" not in out and "aegis approve" not in out


@needs_git
def test_malformed_head_policy_returns_a_fixed_json_refusal(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.branch("work")
    repo.write(".aegis/config.json", '{"approvals":{"*":"secret\\nvalue"}}')
    repo.commit("invalid policy")
    rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    payload = json.loads(out)
    assert rc == 1 and payload["code"] == "invalid_approval_policy"
    assert payload["key"] == "approvals" and payload["path"] == ".aegis/config.json"
    assert payload["next_action"] and "secret" not in out + err


@needs_git
@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("base_value", ["secret", [], None, {"ref": [], "sha": "a" * 40},
    {"ref": "main", "sha": []}, {"ref": 7, "sha": "a" * 40}],
    ids=["string", "list", "null", "list-ref", "list-sha", "integer-ref"])
def test_malformed_event_base_reaches_fixed_ci_error(tmp_path, capsys, monkeypatch, base_value, fmt):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": base_value, "head": {"sha": repo.head()}}})
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--format", fmt)
        assert rc == 1 and "Error: invalid_ci_event" in err
        assert "Traceback" not in out + err and "secret" not in out + err
        if fmt == "json":
            document = json.loads(out)
            assert document["status"] == "fail" and document["code"] == "invalid_ci_event"
            assert document["approval"] is None


@needs_git
@pytest.mark.parametrize("head_value", ["secret", [], None, {"sha": []}, {"sha": "secret"}],
                         ids=["string", "list", "null", "list-sha", "invalid-sha"])
def test_malformed_event_head_reaches_fixed_json_error(tmp_path, capsys, monkeypatch, head_value):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": repo.head(), "ref": "main"}, "head": head_value}})
    rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["code"] == "invalid_ci_event" and document["approval"] is None
    assert "secret" not in out + err


@needs_git
@pytest.mark.parametrize("name", ["pull_request", "push"])
@pytest.mark.parametrize("text", ['[' * 1500 + ']' * 1500, '[]', '"secret"'], ids=["deep", "array", "scalar"])
def test_invalid_event_document_reaches_fixed_ci_error(tmp_path, capsys, monkeypatch, name, text):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, name, {})
    event = tmp_path / "event.json"
    event.write_text(text, encoding="utf-8")
    rc, out, err = run_ci(repo, capsys, "--no-exec")
    assert rc == 1 and "Error: invalid_ci_event" in err and "Traceback" not in out + err


@needs_git
@pytest.mark.parametrize("mode", ["none", "review", "signature"])
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
def test_policy_output_redacts_target_findings_and_paths(tmp_path, capsys, mode, fmt):
    token = "ghp_" + "a" * 36
    repo = make_repo(tmp_path)
    rule = f".aegis/rules/gates/gate-{token}.md"
    repo.write(rule, RULE.replace("gate-no-eval", "gate-" + token))
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": mode}}))
    base = repo.commit("policy and token rule")
    target = "feature/" + token
    repo.git("update-ref", "refs/remotes/origin/" + target, base)
    repo.branch("work")
    (repo.root / rule).unlink()
    repo.write(f".github/workflows/{token}.yml", "name: changed\n")
    repo.commit("governance and weakening")
    rc, out, err = run_ci(repo, capsys, "--base", "origin/" + target, "--no-exec", "--format", fmt)
    assert rc == (1 if mode == "signature" else 0)
    assert token not in out + err and "REDACTED" in out
    if fmt == "json":
        payload = json.loads(out)
        assert "REDACTED" in payload["approval_target"]
        assert "REDACTED" in payload["weakenings"][0]["path"]
        assert "REDACTED" in payload["governance"]["paths"][0]["path"]
    elif fmt == "github" and mode != "signature":
        assert "::error" not in out and "without approval" not in out
        assert "tier C" not in out
        assert "owner review required" in out if mode == "review" else "approval mode none" in out
    elif fmt == "sarif" and mode != "signature":
        notifications = json.loads(out)["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert len(notifications) >= 2 and all(item["level"] == "note" for item in notifications)


@needs_git
def test_event_is_one_snapshot_even_if_file_changes_after_read(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    base = repo.commit("policy")
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("weakening")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}})
    original, reads = check_cli._event_pull, []
    def swap(*args, **kwargs):
        result = original(*args, **kwargs)
        reads.append(True)
        (tmp_path / "event.json").write_text(json.dumps({"pull_request": {
            "base": {"sha": base, "ref": "feature/lower"}, "head": {"sha": head}}}), encoding="utf-8")
        return result
    monkeypatch.setattr(check_cli, "_event_pull", swap)
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["approval_mode"] == "signature" and document["approval_target"] == "main"
    assert len(reads) == 1


# ── R-trust-13 (c)-(f): the base-sourced governance job runs on pull_request_target ─────────────


@needs_git
@pytest.mark.parametrize("before_kind", ["missing", "malformed", "unavailable", "head"])
def test_push_never_uses_candidate_policy_as_its_own_base(tmp_path, capsys, monkeypatch, before_kind):
    repo = policy_repo(tmp_path)
    repo.branch("work")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    (repo.root / GATE).unlink()
    head = repo.commit("lower policy and remove gate")
    repo.git("update-ref", "refs/remotes/origin/main", head)
    before = {"missing": None, "malformed": "secret", "unavailable": "f" * 40, "head": head}[before_kind]
    push_event(tmp_path, monkeypatch, before, head, "main")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1 and document["code"] == ("comparison_unavailable" if before_kind == "head" else "base_unavailable")
        assert document["next_action"] == ("pass --base that is a proper ancestor of the head" if before_kind == "head"
                                          else "fetch the push's before commit (fetch-depth) and re-run")
        assert "secret" not in out + err


@needs_git
def test_policy_push_refuses_head_as_the_comparison_merge_base(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    head = repo.commit("policy head")
    repo.write("README.md", "descendant\n")
    descendant = repo.commit("tracking ref advanced")
    repo.git("update-ref", "refs/remotes/origin/main", descendant)
    repo.git("checkout", "-q", head)
    push_event(tmp_path, monkeypatch, descendant, head, "main")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    assert rc == 1 and json.loads(out)["code"] == "comparison_unavailable"


@needs_git
@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("position", ["head", "descendant"])
def test_push_zero_before_keeps_permitted_fallback(tmp_path, capsys, monkeypatch, has_map, explicit, position):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    head = repo.head()
    if position == "descendant":
        repo.write("README.md", "remote advanced\n")
        repo.commit("descendant")
        repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
        repo.git("checkout", "-q", head)
    base = repo.git("rev-parse", "refs/remotes/origin/main")
    push_event(tmp_path, monkeypatch, "0" * 40, head, "main")
    extra = ["--base", "origin/main"] if explicit else []
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, *extra, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 0 and document["status"] == "pass" and document["scope"]["base"] == base


@needs_git
@pytest.mark.parametrize("before", [None, "secret", "f" * 40])
def test_no_map_missing_push_predecessor_retains_legacy_bytes(tmp_path, capsys, monkeypatch, before):
    repo = make_repo(tmp_path)
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    expected = json.loads(out)
    push_event(tmp_path, monkeypatch, before, repo.head(), "main")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    actual = json.loads(out)
    for document in (expected, actual):
        document.pop("checked_at")
    assert rc == 0 and json.dumps(actual) == json.dumps(expected)


@needs_git
@pytest.mark.parametrize("config_text", ['{broken', '[]', 'x' * (64 * 1024 + 1)], ids=["invalid", "non-object", "oversized"])
def test_unusable_before_config_does_not_narrow_legacy_push_range(tmp_path, capsys, monkeypatch, config_text):
    repo = make_repo(tmp_path)
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.write(".aegis/config.json", config_text)
    before = repo.commit("earlier push removed gate")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("later push")
    push_event(tmp_path, monkeypatch, before, head, "main")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["weakenings"]
    assert "approval_mode" not in document


@needs_git
@pytest.mark.parametrize("ref", ["release+1", "développement"])
@pytest.mark.parametrize("has_map", [False, True])
def test_out_of_grammar_event_ref_is_legacy_or_strictest(tmp_path, capsys, monkeypatch, ref, has_map):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("change workflow")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": base, "ref": ref}, "head": {"sha": head}}})
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == (1 if has_map else 0)
    if has_map:
        assert document["approval_mode"] == "signature" and document["approval_target"] is None
    else:
        assert "approval_mode" not in document


@needs_git
@pytest.mark.parametrize("shape", ["no-path", "missing-sha", "short-sha"])
def test_legacy_event_fallback_matches_local_report(tmp_path, capsys, monkeypatch, shape):
    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("code only")
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    expected = json.loads(out)
    pull = {"base": {"ref": "main"}, "head": {}}
    if shape == "short-sha":
        pull["base"]["sha"], pull["head"]["sha"] = base[:8], head[:8]
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": pull}, path_present=shape != "no-path")
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    actual = json.loads(out)
    for document in (expected, actual):
        document.pop("checked_at")
    assert rc == 0 and json.dumps(actual) == json.dumps(expected)


@needs_git
def test_push_event_over_one_mib_is_supported(tmp_path, capsys, monkeypatch):
    repo = policy_repo(tmp_path, "none")
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("code only")
    event_file(tmp_path, monkeypatch, "push", {"before": base, "after": head,
        "commits": [{"message": "message " * 100} for _ in range(2048)]})
    size = (tmp_path / "event.json").stat().st_size
    assert 1024 * 1024 < size < 25 * 1024 * 1024
    rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
    assert rc == 0 and json.loads(out)["approval_mode"] == "none" and "invalid_ci_event" not in err


@needs_git
def test_oversized_event_refuses_before_json_parse(tmp_path, capsys, monkeypatch):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, "pull_request", {})
    (tmp_path / "event.json").write_bytes(b"x" * (25 * 1024 * 1024 + 1))
    def premature_parse(*args, **kwargs):
        pytest.fail("oversized event reached JSON parsing")
    monkeypatch.setattr(check_cli, "json", SimpleNamespace(loads=premature_parse, dumps=json.dumps))
    rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    assert rc == 1 and json.loads(out)["code"] == "invalid_ci_event" and "Traceback" not in err


@needs_git
@pytest.mark.parametrize("entrypoint", ["check", "approve"])
def test_shared_policy_blob_io_failure_returns_fixed_refusal(tmp_path, capsys, monkeypatch, entrypoint):
    repo = policy_repo(tmp_path)
    blob = gitsafe.tree_blobs(repo.root, repo.head(), paths=(".aegis/config.json",))[".aegis/config.json"][1]
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    before = repo.commit("workflow with same policy blob")
    original = gitsafe.read_object
    def unavailable(root, oid, limit):
        if oid == blob:
            raise gitsafe.GitError("secret object read failure")
        return original(root, oid, limit)
    monkeypatch.setattr(gitsafe, "read_object", unavailable)
    if entrypoint == "check":
        rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    else:
        rc = main(["approve", "--workspace", str(repo.root), "--base", "main", "--json"])
        captured = capsys.readouterr()
        out, err = captured.out, captured.err
    document = json.loads(out)
    assert rc == 1 and document["code"] == "invalid_approval_policy"
    assert "secret" not in out + err and "fetch or repair" in out + err
    assert repo.head() == before


@needs_git
@pytest.mark.parametrize("name", ["pull_request", "push"])
@pytest.mark.parametrize("text", ['[' * 1500 + ']' * 1500, '[]'], ids=["deep", "array"])
def test_legacy_unreadable_event_keeps_local_report(tmp_path, capsys, monkeypatch, name, text):
    repo = make_repo(tmp_path)
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    expected = json.loads(out)
    event_file(tmp_path, monkeypatch, name, {})
    (tmp_path / "event.json").write_text(text, encoding="utf-8")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    actual = json.loads(out)
    for document in (expected, actual):
        document.pop("checked_at")
    assert rc == 0 and json.dumps(actual) == json.dumps(expected)


@needs_git
def test_other_remote_git_branch_is_a_known_target(tmp_path, capsys):
    repo = policy_repo(tmp_path)
    repo.git("remote", "add", "upstream", "/not-contacted")
    base = repo.head()
    repo.git("update-ref", "refs/remotes/upstream/main", base)
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    repo.commit("governance")
    rc, out, _err = run_ci(repo, capsys, "--base", "upstream/main", "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["approval_mode"] == "signature" and document["approval_target"] == "main"


@needs_git
@pytest.mark.parametrize("selector", ["upstream/main", "refs/remotes/upstream/main", "v1.2", "sha", "origin/HEAD"])
def test_pr_event_cannot_upgrade_an_unknown_explicit_target(tmp_path, capsys, monkeypatch, selector):
    repo = policy_repo(tmp_path)
    base = repo.head()
    repo.git("update-ref", "refs/remotes/upstream/main", base)
    repo.git("tag", "v1.2", base)
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "number": 1, "user": {"login": "agent"},
        "base": {"sha": base, "ref": "feature/x"}, "head": {"sha": head}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--base", base if selector == "sha" else selector, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1 and document["status"] == "fail" and document["weakenings"]
        assert document["approval_mode"] == "signature" and document["approval_target"] is None


@needs_git
@pytest.mark.parametrize("tracking", ["matching", "missing", "different", "event-different", "shadow-tag"])
def test_explicit_pr_sha_stays_unknown_even_with_matching_origin(tmp_path, capsys, monkeypatch, tracking):
    repo = policy_repo(tmp_path)
    older = repo.git("rev-parse", "HEAD^")
    base = repo.head()
    if tracking == "shadow-tag":
        repo.git("tag", "refs/remotes/origin/feature/x", base)
    elif tracking != "missing":
        repo.git("update-ref", "refs/remotes/origin/feature/x", older if tracking == "different" else base)
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": older if tracking == "event-different" else base, "ref": "feature/x"}, "head": {"sha": head}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--base", base, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1
        assert document["approval_target"] is None and document["approval_mode"] == "signature"


@needs_git
@pytest.mark.parametrize("ref", ["refs/tags/v1.2", "refs/tags/release/1", "refs/pull/1/merge", "main", "", None])
def test_push_non_branch_ref_uses_strictest_mode(tmp_path, capsys, monkeypatch, ref):
    repo = policy_repo(tmp_path)
    repo.branch("outside-main")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow on tagged commit")
    push_event(tmp_path, monkeypatch, "0" * 40, head, "v1.2", ref=ref, ref_present=ref is not None)
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1 and document["governance"]["categories"] == ["workflows"]
        assert document["approval_mode"] == "signature" and document["approval_target"] is None


@needs_git
@pytest.mark.parametrize("fallback", ["head", "descendant"])
@pytest.mark.parametrize("delete_gate", [False, True])
def test_first_map_push_compares_the_resolved_legacy_predecessor(tmp_path, capsys, monkeypatch, fallback, delete_gate):
    repo = make_repo(tmp_path)
    before = repo.head()
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    if delete_gate:
        (repo.root / GATE).unlink()
    head = repo.commit("adopt approval policy")
    if fallback == "descendant":
        repo.write("README.md", "later\n")
        repo.commit("remote advanced")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("checkout", "-q", head)
    push_event(tmp_path, monkeypatch, before, head, "main")
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == int(delete_gate) and document["scope"]["base"] == before
        assert document["scope"]["merge_base"] == before and document["governance"]["categories"]
        assert bool(document["weakenings"]) == delete_gate
        assert "approval_mode" not in document


@needs_git
@pytest.mark.parametrize("before", [None, "secret", "f" * 40])
@pytest.mark.parametrize("mode", ["signature", "none"])
def test_explicit_push_base_does_not_require_before(tmp_path, capsys, monkeypatch, before, mode):
    repo = policy_repo(tmp_path, mode)
    base = repo.head()
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow")
    push_event(tmp_path, monkeypatch, before, head, "main")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", "origin/main", "--no-exec", "--json")
        document = json.loads(out)
        assert rc == int(mode == "signature") and document["scope"]["base"] == base and document["governance"]["categories"]
        assert document["approval_mode"] == mode and document["approval_target"] == "main"
        assert "base_unavailable" not in out + err and "secret" not in out + err


@needs_git
@pytest.mark.parametrize("mode", ["none", "review"])
def test_step_summary_keeps_permitted_review_surface(tmp_path, capsys, mode):
    repo = policy_repo(tmp_path, mode)
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    repo.commit("weakening and governance")
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    summary = report_formats.format_github_step_summary(json.loads(out), repo.root)
    assert rc == 0 and "PASSED" in summary and "No findings reported" not in summary
    assert "gate-no-eval" in summary and ".github/workflows/changed.yml" in summary
    assert "approval mode " + mode in summary
    assert ("owner review required" in summary) == (mode == "review")


@needs_git
@pytest.mark.parametrize("kind", ["head", "descendant", "unrelated", "missing"])
@pytest.mark.parametrize("fmt", ["text", "json"])
def test_explicit_push_refusal_names_its_base_without_echoing_secrets(tmp_path, capsys, monkeypatch, kind, fmt):
    repo = policy_repo(tmp_path)
    head = repo.head()
    token = "ghp_" + "a" * 36
    selector = "origin/feature/" + token
    base = head
    if kind == "descendant":
        repo.write("README.md", "later\n")
        base = repo.commit("descendant")
        repo.git("checkout", "-q", head)
    elif kind == "unrelated":
        base = repo.git("commit-tree", "HEAD^{tree}", stdin="unrelated\n")
    if kind != "missing":
        repo.git("update-ref", "refs/remotes/" + selector, base)
    push_event(tmp_path, monkeypatch, None, head, "main")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", selector, "--no-exec", "--format", fmt)
        code = "base_unavailable" if kind == "missing" else "comparison_unavailable"
        assert rc == 1 and code in out + err
        if kind == "missing":
            assert "fetch it or pass the full commit id" in out + err and "fetch origin" in out + err
            assert "origin/feature/" in out + err and "REDACTED" in out + err
        else:
            assert "proper ancestor" in out + err
        assert token not in out + err and "before commit" not in out + err and "Traceback" not in out + err
        if fmt == "json":
            document = json.loads(out)
            assert document["code"] == code and document["next_action"]


@needs_git
@pytest.mark.parametrize("selector", ["origin/feature/x", "refs/remotes/origin/feature/x", "feature/x", "refs/heads/feature/x"])
@pytest.mark.parametrize("event,landing", [
    ("pull_request", "main"), ("pull_request", "feature/x"),
    ("pull_request_target", "main"), ("pull_request_target", "feature/x"),
    ("push", "main"), ("push", "feature/x"), ("tag", "v1.2"),
])
def test_explicit_base_target_must_agree_with_the_landing_event(tmp_path, capsys, monkeypatch, selector, event, landing):
    repo = policy_repo(tmp_path)
    base = repo.head()
    repo.git("update-ref", "refs/remotes/origin/feature/x", base)
    repo.git("branch", "feature/x", base)
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow")
    if event in ("push", "tag"):
        push_event(tmp_path, monkeypatch, base, head, landing,
                   ref="refs/tags/v1.2" if event == "tag" else "refs/heads/" + landing)
    else:
        event_file(tmp_path, monkeypatch, event, {"pull_request": {
            "base": {"sha": base, "ref": landing}, "head": {"sha": head}}})
    agrees = landing == "feature/x"
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--base", selector, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == (0 if agrees else 1) and document["scope"]["base"] == base
        assert document["approval_target"] == ("feature/x" if agrees else None)
        assert document["approval_mode"] == ("none" if agrees else "signature")


@needs_git
@pytest.mark.parametrize("source", ["local", "push-explicit", "push-discovered"])
@pytest.mark.parametrize("selector", ["origin/main", "main"])
def test_explicit_and_discovered_bases_keep_their_git_semantics(tmp_path, capsys, monkeypatch, source, selector):
    repo = policy_repo(tmp_path)
    base = repo.head()
    legacy = repo.git("rev-parse", "HEAD^")
    repo.git("tag", selector, legacy)
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow")
    if source != "local":
        push_event(tmp_path, monkeypatch, "0" * 40, head, "main")
    extra = [] if source == "push-discovered" else ["--base", selector]
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, *extra, "--no-exec", "--json")
        document = json.loads(out)
        # Explicit ambiguous input uses Git's tag and its legacy policy. Only
        # automatic discovery selects the qualified branch despite that tag.
        discovered = source == "push-discovered"
        assert rc == int(discovered) and document["scope"]["base"] == (base if discovered else legacy)
        assert document.get("approval_mode") == ("signature" if discovered else None)
        assert document.get("approval_target") == ("main" if discovered else None)


@needs_git
@pytest.mark.parametrize("mode", ["none", "review"])
def test_permitted_mode_still_prints_first_blocker(tmp_path, capsys, monkeypatch, mode):
    repo = policy_repo(tmp_path, mode)
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    repo.commit("code only")
    result = {"status": "fail", "regressed": True, "noisy": False, "passed": False, "rounds": 15,
              "threshold": 0.05, "base_min": 0.01, "head_min": 0.02, "base_median": 0.01, "head_median": 0.02}
    monkeypatch.setattr(perf_check, "run_perf_check", lambda *args, **kwargs: result)
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--perf")
    assert rc == 1 and "FAILED, approval mode " + mode in out
    assert ": performance regression (" in out


@needs_git
@pytest.mark.parametrize("event", ["local", "push", "pull_request", "pull_request_target", "workflow_dispatch"])
@pytest.mark.parametrize("move_ref", [False, True])
def test_no_map_ci_consumers_share_one_pinned_branch_base(tmp_path, capsys, monkeypatch, event, move_ref):
    repo = make_repo(tmp_path)
    tag = repo.head()
    repo.write("README.md", "branch base\n")
    base = repo.commit("branch advances")
    repo.git("update-ref", "refs/remotes/origin/main", base)
    repo.git("tag", "origin/main", tag)
    repo.branch("work")
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    head = repo.commit("workflow")
    extra = ["--base", "origin/main"] if event == "local" else []
    if event == "push":
        push_event(tmp_path, monkeypatch, base, head, "main")
    elif event != "local":
        document = {"pull_request": {"base": {"sha": base, "ref": "main"}, "head": {"sha": head}}}
        event_file(tmp_path, monkeypatch, event, document if event.startswith("pull_request") else {})
    seen = {name: [] for name in ("weakening", "regression", "checkrun", "credit", "coverage", "perf")}
    weakening, regressions = ci_integrity.check_ci, regression.check_ci_regressions
    trailers, credit_trailers = checkrun.verify_commit_trailers, credit.verify_commit_trailers
    def weakening_check(root, candidate, tip, **kwargs):
        seen["weakening"].append(candidate)
        report = weakening(root, candidate, tip, **kwargs)
        if move_ref:
            repo.git("update-ref", "refs/remotes/origin/main", tag)
        return report
    def regression_check(root, candidate, tip, **kwargs):
        seen["regression"].append(candidate)
        return regressions(root, candidate, tip, **kwargs)
    def trailer_check(root, candidate, tip, **kwargs):
        seen["checkrun"].append(candidate)
        return trailers(root, candidate, tip, **kwargs)
    def credit_check(root, candidate, tip, **kwargs):
        seen["credit"].append(candidate)
        return credit_trailers(root, candidate, tip, **kwargs)
    def coverage(root, candidate, tip):
        seen["coverage"].append(candidate)
        return {"status": "reported", "reason": "", "covered_lines": 1, "executable_lines": 1,
                "ratio": 1.0, "uncovered_ranges": {}, "unmeasured": []}
    def perf(root, *, base_ref):
        seen["perf"].append(base_ref)
        return {"status": "pass", "regressed": False, "noisy": False, "passed": True, "rounds": 15,
                "threshold": 0.05, "base_min": 0.01, "head_min": 0.01, "base_median": 0.01, "head_median": 0.01}
    monkeypatch.setattr(ci_integrity, "check_ci", weakening_check)
    monkeypatch.setattr(regression, "check_ci_regressions", regression_check)
    monkeypatch.setattr(checkrun, "verify_commit_trailers", trailer_check)
    monkeypatch.setattr(credit, "verify_commit_trailers", credit_check)
    monkeypatch.setattr(coverage_check, "run_diff_coverage", coverage)
    monkeypatch.setattr(perf_check, "run_perf_check", perf)
    for _ in range(2):
        repo.git("update-ref", "refs/remotes/origin/main", base)
        rc, out, _err = run_ci(repo, capsys, *extra, "--coverage", "--perf", "--json")
        report = json.loads(out)
        expected_base = tag if event == "local" else base
        assert rc == 0 and report["scope"]["base"] == report["scope"]["merge_base"] == expected_base
        assert "approval_mode" not in report
        assert all(values and set(values) == {expected_base} for values in seen.values()), seen

PULL = {"number": 7, "user": {"login": "agent"}, "base": {"sha": "a" * 40, "ref": "main"}, "head": {"sha": "B" * 40}}


@needs_git
def test_discovered_tag_cannot_hide_the_local_branch_policy(tmp_path, capsys):
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("README.md", "legacy tag\n")
    tag = repo.commit("legacy")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    base = repo.commit("local branch policy")
    repo.branch("work")
    (repo.root / ".aegis/config.json").unlink()
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    repo.commit("head drops the policy")
    repo.git("tag", "origin/main", tag)
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        report = json.loads(out)
        assert rc == 1 and report["scope"]["base"] == base
        assert report["approval_mode"] == "signature" and report["approval_target"] is None


@needs_git
def test_ci_pins_before_a_branch_deletion_can_change_the_target_policy(tmp_path, capsys, monkeypatch):
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}}))
    base = repo.commit("branch policy")
    repo.branch("work")
    repo.write("README.md", "tag descendant\n")
    tag = repo.commit("tag descendant")
    repo.git("tag", "main", tag)
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    repo.commit("workflow")
    original = gitsafe.resolve_commit
    def delete_between_steps(root, selector):
        commit = original(root, selector)
        if selector == "refs/heads/main" and commit == base:
            repo.git("update-ref", "-d", "refs/heads/main")
        return commit
    monkeypatch.setattr(gitsafe, "resolve_commit", delete_between_steps)
    for _ in range(2):
        repo.git("update-ref", "refs/heads/main", base)
        rc, out, _err = run_ci(repo, capsys, "--base", "refs/heads/main", "--no-exec", "--json")
        report = json.loads(out)
        assert rc == 1 and report["scope"]["base"] == base
        assert report["approval_mode"] == "signature" and report["approval_target"] is None


@needs_git
@pytest.mark.parametrize("selector", ["tag-only", "origin/tag-only", "refs/tags/tag-only"])
def test_tag_only_base_runs_the_strictest_policy(tmp_path, capsys, selector):
    repo = policy_repo(tmp_path)
    repo.git("tag", "origin/tag-only" if selector == "origin/tag-only" else "tag-only", repo.head())
    repo.branch("work")
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    repo.commit("workflow")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", selector, "--no-exec", "--json")
        report = json.loads(out)
        assert rc == 1 and report["approval_mode"] == "signature" and report["approval_target"] is None
        assert report["scope"]["base"] == repo.git("rev-parse", "refs/tags/" + ("origin/tag-only" if selector == "origin/tag-only" else "tag-only"))
        assert "base_unavailable" not in out + err and "Traceback" not in out + err


@needs_git
def test_branch_ref_io_failure_has_a_fixed_policy_refusal(tmp_path, capsys, monkeypatch):
    repo = policy_repo(tmp_path)
    def unavailable(*args, **kwargs):
        raise gitsafe.GitError("secret ref read failure")
    monkeypatch.setattr(gitsafe, "read_ref", unavailable)
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
        assert rc == 1 and json.loads(out)["code"] == "invalid_approval_policy"
        assert "secret" not in out + err and "Traceback" not in out + err


def event_file(tmp_path: Path, monkeypatch, name: str, payload, path_present=True) -> None:
    if path_present:
        event = tmp_path / "event.json"
        event.write_bytes(json.dumps(payload).encode("utf-8"))
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", name)


@pytest.mark.parametrize("name", ["pull_request", "pull_request_target"])
def test_a_pull_request_target_run_names_its_pull_request_for_the_review_lookup(tmp_path, monkeypatch, name):
    from aegis_cli import check
    from aegis_core import human_gate

    event_file(tmp_path, monkeypatch, name, {"pull_request": PULL})
    assert check._event_pull_request() == human_gate.PullRequest(7, "agent", "b" * 40, "main")


@pytest.mark.parametrize("name", ["push", "workflow_dispatch", "pull_request_review", "PULL_REQUEST_TARGET", ""])
def test_any_other_event_names_no_pull_request(tmp_path, monkeypatch, name):
    from aegis_cli import check

    event_file(tmp_path, monkeypatch, name, {"pull_request": PULL})
    assert check._event_pull_request() is None


@pytest.mark.parametrize("pull", [
    {**PULL, "number": "7"}, {**PULL, "number": 0}, {**PULL, "user": {"login": "two words"}},
    {**PULL, "head": {"sha": "abc"}}, {**PULL, "base": {"sha": "a" * 40, "ref": "../main"}},
    {k: v for k, v in PULL.items() if k != "user"}, "not an object",
], ids=["number-str", "number-zero", "login", "sha", "ref", "no-user", "string"])
def test_a_malformed_pull_request_target_payload_names_no_pull_request(tmp_path, monkeypatch, pull):
    from aegis_cli import check

    event_file(tmp_path, monkeypatch, "pull_request_target", {"pull_request": pull})
    assert check._event_pull_request() is None


@needs_git
def test_no_exec_on_pull_request_target_hands_the_pull_request_to_the_weakening_check(tmp_path, capsys, monkeypatch):
    """--no-exec runs no repository code, but tier A's review lookup (a GitHub read) still gets the
    pull request; nothing is flagged here, so no gh call happens."""
    from aegis_core import human_gate, rule_integrity

    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("an ordinary change")
    event_file(tmp_path, monkeypatch, "pull_request_target", {"pull_request": {
        "number": 3, "user": {"login": "agent"}, "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}})
    seen = []
    real = rule_integrity.check_ci

    def spy(*args, pull_request=None, **kwargs):
        seen.append(pull_request)
        return real(*args, pull_request=pull_request, **kwargs)

    monkeypatch.setattr(rule_integrity, "check_ci", spy)
    rc, out, _err = run_ci(repo, capsys, "--no-exec")
    assert rc == 0 and PASSED in out
    assert seen == [human_gate.PullRequest(3, "agent", head, "main")]
