"""Branch approval policy through committed Git objects and the public CI gate."""
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Barrier
from types import SimpleNamespace

import pytest

from aegis_core import approval_policy, gitsafe, human_gate, rule_integrity
from aegis_cli import cli
from tests import helpers_humangate as hg

MAP = {"main": "signature", "develop": "review", "release/**": "review", "*": "none"}


@pytest.fixture
def _policy_environment(tmp_path, monkeypatch):
    home = hg.Home(tmp_path / "home")
    for name, value in home.env.items():
        monkeypatch.setenv(name, value)
    for name in ("GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_REF", "GITHUB_REF_NAME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("base_policy", [None, {"main": "none", "*": "signature"},
                                         {"main": "signature", "*": "none"}],
                         ids=["legacy", "known-none", "known-signature"])
@pytest.mark.parametrize("form", [
    "main", "origin/main", "refs/remotes/origin/main", "refs/heads/main",
    "v1.2", "refs/tags/v1.2", "ambiguous", "FETCH_HEAD", "ORIG_HEAD",
    "HEAD@{1}", "@{u}", "@{upstream}", "oid", "short", "absent-remote",
    "tree", "blob", "alias", "upstream/main", "origin/HEAD", "refs/aegis/example", "empty",
    "origin/HEAD-direct", "team/fork/main", "refs/remotes/team/fork/main", "slash-upstream",
    "unknown/main", "refs/heads/HEAD", "refs/remotes/team/fork/HEAD", "refs/remotes/origin/release+1",
])
def test_git_selector_table_agrees_across_public_commands(tmp_path, _policy_environment, monkeypatch, capsys, base_policy, form):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    project.write(".aegis/config.json", json.dumps({"approvals": base_policy} if base_policy is not None else {}))
    project.write("README.md", "tag base\n")
    older = project.commit("tag base")
    project.write("README.md", "branch base\n")
    base = project.commit("branch base")
    project.git("update-ref", "refs/remotes/origin/main", base)
    project.git("update-ref", "refs/remotes/upstream/main", base)
    project.git("update-ref", "refs/remotes/team/fork/main", base)
    project.git("update-ref", "refs/remotes/team/fork/HEAD", base)
    project.git("update-ref", "refs/remotes/unknown/main", base)
    project.git("update-ref", "refs/remotes/origin/release+1", base)
    project.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    project.git("symbolic-ref", "refs/heads/alias", "refs/heads/main")
    project.git("update-ref", "refs/aegis/example", base)
    project.git("tag", "v1.2", base)
    project.git("tag", "ambiguous", older)
    project.git("branch", "ambiguous", base)
    for remote in ("origin", "upstream", "team", "team/fork"):
        project.git("remote", "add", remote, "/not-contacted")
    project.branch("work")
    project.git("branch", "--set-upstream-to=origin/main", "work")
    project.write(".github/workflows/ci.yml", "name: changed\n")
    head = project.commit("workflow")
    (project.root / ".git" / "FETCH_HEAD").write_text(base + "\n", encoding="ascii")
    project.git("update-ref", "ORIG_HEAD", base)
    selector = form
    if form == "empty":
        selector = ""
    elif form == "origin/HEAD-direct":
        selector = "origin/HEAD"
        project.git("update-ref", "--no-deref", "refs/remotes/origin/HEAD", base)
    elif form == "slash-upstream":
        selector = "@{u}"
        project.git("config", "branch.work.remote", "team/fork")
        project.git("config", "branch.work.merge", "refs/heads/main")
    elif form == "refs/heads/HEAD":
        project.git("update-ref", "refs/heads/HEAD", base)
    elif form == "absent-remote":
        project.git("update-ref", "-d", "refs/remotes/origin/main")
        project.git("branch", "-f", "main", older)
        selector = "refs/remotes/origin/main"
    elif form == "oid":
        selector = base
    elif form == "short":
        selector = base[:12]
    elif form in ("tree", "blob"):
        selector = project.git("rev-parse", "HEAD^{tree}" if form == "tree" else "HEAD:README.md")
    unavailable = form in ("absent-remote", "tree", "blob")
    known = form in ("main", "origin/main", "refs/remotes/origin/main", "refs/heads/main",
                     "@{u}", "@{upstream}", "alias", "upstream/main", "origin/HEAD", "empty",
                     "team/fork/main", "refs/remotes/team/fork/main", "slash-upstream")
    expected_base = older if form == "ambiguous" else base
    expected_target = "main" if known else None
    expected_mode = (base_policy["main"] if known else "signature") if base_policy is not None else None
    original, observed = approval_policy.resolve_policy, []
    def observe(root, anchor, candidate, target):
        policy = original(root, anchor, candidate, target)
        observed.append((anchor, target, policy.mode))
        return policy
    # Observe the real public policy decision; no behaviour is replaced.
    monkeypatch.setattr(approval_policy, "resolve_policy", observe)
    for _ in range(2):
        for consumer in ("check", "approve", "core"):
            observed.clear()
            if consumer == "core":
                # Only CLI --base has omission semantics; the core base argument
                # is required, so an empty direct argument still refuses.
                if unavailable or form == "empty":
                    with pytest.raises(rule_integrity.IntegrityError, match="cannot resolve the base"):
                        rule_integrity.check_ci(project.root, selector)
                    assert not observed
                    continue
                report = rule_integrity.check_ci(project.root, selector)
                assert report.base == expected_base
                assert report.passed == (expected_mode != "signature")
            else:
                args = [consumer, "--workspace", str(project.root), "--base", selector, "--json"]
                if consumer == "check":
                    args += ["--ci", "--no-exec"]
                rc = cli.main(args)
                captured = capsys.readouterr()
                document = json.loads(captured.out)
                assert "Traceback" not in captured.out + captured.err
                if unavailable:
                    assert rc == 1 and document["code"] == ("base_unavailable" if consumer == "check" else "no_base")
                    action = document["next_action"] if consumer == "check" else document["reason"]
                    assert "fetch it or pass the full commit id" in action
                    if form == "absent-remote":
                        assert "fetch origin" in action
                    assert not observed
                    continue
                if consumer == "check":
                    assert rc == int(expected_mode == "signature")
                    assert document["scope"]["base"] == expected_base
                    assert document.get("approval_mode") == expected_mode
                else:
                    assert rc == 1 and document["code"] == ("not_required" if expected_mode == "none" else "no_key")
                assert "fetch-depth" not in captured.out + captured.err
            assert observed == [(expected_base, expected_target, expected_mode)]
        assert project.head() == head


@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("failure", ["oversized", "too-many", "invalid-name", "nul", "encoding",
                                    "nonzero", "timeout", "ambiguous", "empty"])
def test_remote_inventory_failure_is_fixed_or_unknown(tmp_path, _policy_environment, monkeypatch, capsys, has_map, failure):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}} if has_map else {}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.git("remote", "add", "origin", "/not-contacted")
    project.git("update-ref", "refs/remotes/origin/main", base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    head = project.commit("workflow")
    original_run, original_policy, observed = gitsafe.run, approval_policy.resolve_policy, []
    replies = {"oversized": b"secret" * 12000, "too-many": b"origin\n" * 257,
               "invalid-name": b"origin secret\n", "nul": b"ori\x00secret\n", "encoding": b"\xffsecret\n",
               "nonzero": b"", "ambiguous": b"origin\norigin\n", "empty": b""}
    def inventory(args, *rest, **kwargs):
        if list(args) == ["remote"]:
            if failure == "timeout":
                raise gitsafe.GitError("secret remote timeout")
            return SimpleNamespace(returncode=int(failure == "nonzero"), stdout=replies[failure], stderr=b"secret")
        return original_run(args, *rest, **kwargs)
    def observe(root, anchor, candidate, target):
        policy = original_policy(root, anchor, candidate, target)
        observed.append((anchor, target, policy.mode))
        return policy
    monkeypatch.setattr(gitsafe, "run", inventory)
    monkeypatch.setattr(approval_policy, "resolve_policy", observe)
    unknown = failure in ("ambiguous", "empty")
    for _ in range(2):
        for command in ("check", "approve", "core"):
            observed.clear()
            if command == "core":
                if not unknown:
                    with pytest.raises(approval_policy.PolicyUnavailable, match="invalid_approval_policy"):
                        rule_integrity.check_ci(project.root, "origin/main")
                    continue
                report = rule_integrity.check_ci(project.root, "origin/main")
                assert report.passed == (not has_map)
            else:
                args = [command, "--workspace", str(project.root), "--base", "origin/main", "--json"]
                if command == "check":
                    args += ["--ci", "--no-exec"]
                rc = cli.main(args)
                captured = capsys.readouterr()
                document = json.loads(captured.out)
                assert "secret" not in captured.out + captured.err and "Traceback" not in captured.out + captured.err
                if not unknown:
                    assert rc == 1 and document["code"] == "invalid_approval_policy"
                    assert observed == []
                    continue
                if command == "check":
                    assert rc == int(has_map) and document.get("approval_mode") == ("signature" if has_map else None)
                else:
                    assert rc == 1 and document["code"] == "no_key"
            assert observed == [(base, None, "signature" if has_map else None)]
        assert project.head() == head


@pytest.mark.parametrize("has_map", [False, True])
def test_remote_inventory_retry_requeries_git(tmp_path, _policy_environment, monkeypatch, capsys, has_map):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}} if has_map else {}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.git("remote", "add", "origin", "/not-contacted")
    project.git("update-ref", "refs/remotes/origin/main", base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow")
    original, failed = gitsafe.run, []
    def fail_once(args, *rest, **kwargs):
        if list(args) == ["remote"] and not failed:
            failed.append(True)
            raise gitsafe.GitError("secret remote timeout")
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", fail_once)
    for command in ("check", "approve", "core"):
        failed.clear()
        if command == "core":
            with pytest.raises(approval_policy.PolicyUnavailable, match="invalid_approval_policy"):
                rule_integrity.check_ci(project.root, "origin/main")
            report = rule_integrity.check_ci(project.root, "origin/main")
            assert report.base == base and report.passed
            assert report.approval_policy.target == ("main" if has_map else None)
            assert report.approval_policy.mode == ("none" if has_map else None)
            continue
        args = [command, "--workspace", str(project.root), "--base", "origin/main", "--json"]
        if command == "check":
            args += ["--ci", "--no-exec"]
        assert cli.main(args) == 1
        captured = capsys.readouterr()
        assert json.loads(captured.out)["code"] == "invalid_approval_policy" and "secret" not in captured.out + captured.err
        rc = cli.main(args)
        document = json.loads(capsys.readouterr().out)
        if command == "check":
            assert rc == 0 and document["scope"]["base"] == base
            assert document.get("approval_mode") == ("none" if has_map else None)
        else:
            assert rc == 1 and document["code"] == ("not_required" if has_map else "no_key")


def test_parallel_slash_remote_checks_share_the_target_table(repo, monkeypatch):
    base = repo.git("rev-parse", "main")
    for remote in ("team", "team/fork"):
        repo.git("remote", "add", remote, "/not-contacted")
    repo.git("update-ref", "refs/remotes/team/fork/main", base)
    original, ready = gitsafe.run, Barrier(2)
    def overlap(args, *rest, **kwargs):
        if list(args) == ["remote"]:
            ready.wait(timeout=10)
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", overlap)
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, "team/fork/main"), range(4), timeout=30))
    assert all(report.base == base and report.approval_policy.target == "main"
               and report.approval_policy.mode == "signature" and not report.passed for report in reports)


def test_HEAD_is_unknown_even_when_the_policy_lists_it():
    assert approval_policy.mode_for({"HEAD": "none", "main": "signature"}, "HEAD") == "signature"
    assert approval_policy.mode_for({"HEAD/**": "none", "*": "signature"}, "HEAD/topic") == "none"


@pytest.mark.parametrize("failure", ["oversized", "multiline", "nonref", "invalidref", "timeout", "nul", "encoding"])
def test_git_classification_failure_is_bounded_and_fixed(tmp_path, _policy_environment, monkeypatch, capsys, failure):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow")
    original = gitsafe.run
    outputs = {"oversized": b"secret" * 2000, "multiline": b"refs/heads/main\nrefs/heads/secret\n",
               "nonref": b"secret\n", "invalidref": b"refs/heads/../secret\n",
               "nul": b"refs/heads/secret\x00suffix\n", "encoding": b"refs/heads/\xff\n"}
    def malformed(args, *rest, **kwargs):
        if list(args[:2]) == ["rev-parse", "--symbolic-full-name"]:
            if failure == "timeout":
                raise gitsafe.GitError("secret timeout detail")
            return SimpleNamespace(returncode=0, stdout=outputs[failure], stderr=b"secret")
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", malformed)
    for _ in range(2):
        for command in ("check", "approve"):
            args = [command, "--workspace", str(project.root), "--base", "main", "--json"]
            if command == "check":
                args += ["--ci", "--no-exec"]
            assert cli.main(args) == 1
            captured = capsys.readouterr()
            assert json.loads(captured.out)["code"] == "invalid_approval_policy"
            assert "secret" not in captured.out + captured.err and "Traceback" not in captured.out + captured.err


@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("invalid", ["nul", "surrogate"])
def test_invalid_selector_text_refuses_before_git(tmp_path, _policy_environment, monkeypatch, capsys, has_map, invalid):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"*": "signature"}} if has_map else {}))
    project.commit("configuration")
    token = "ghp_" + "a" * 36
    selector = "origin/" + (token[:10] + "\x00" + token[10:] if invalid == "nul" else "bad\ud800")
    original, calls = gitsafe.resolve_commit, []
    def observe(root, ref):
        calls.append(ref)
        return original(root, ref)
    monkeypatch.setattr(gitsafe, "resolve_commit", observe)
    for _ in range(2):
        calls.clear()
        assert approval_policy.resolve_base(project.root, selector) is None
        assert calls == []
        assert cli.main(["check", "--ci", "--workspace", str(project.root), "--base", selector, "--no-exec", "--json"]) == 1
        captured = capsys.readouterr()
        assert json.loads(captured.out)["code"] == "base_unavailable"
        assert "Traceback" not in captured.out + captured.err and token not in captured.out + captured.err
        assert cli.main(["approve", "--workspace", str(project.root), "--base", selector, "--json"]) == 2
        captured = capsys.readouterr()
        assert not captured.out and "one line of printable text" in captured.err and token not in captured.err


def test_a_branch_named_after_a_commit_cannot_upgrade_its_unknown_target(tmp_path, _policy_environment, capsys):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.git("tag", "release", base)
    project.git("branch", base, base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow")
    for _ in range(2):
        for selector in ("release", base):
            rc = cli.main(["check", "--ci", "--workspace", str(project.root), "--base", selector, "--no-exec", "--json"])
            report = json.loads(capsys.readouterr().out)
            assert rc == 1 and report["scope"]["base"] == base
            assert report["approval_target"] is None and report["approval_mode"] == "signature"
            core = rule_integrity.check_ci(project.root, selector)
            assert not core.passed and core.approval_policy.target is None and core.approval_policy.mode == "signature"


@pytest.mark.parametrize("has_map", [False, True])
def test_resolved_unrelated_base_has_a_comparison_refusal(tmp_path, _policy_environment, capsys, has_map):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"*": "signature"}} if has_map else {}))
    project.commit("policy")
    unrelated = project.git("commit-tree", "HEAD^{tree}", stdin="unrelated\n")
    for _ in range(2):
        for command in ("check", "approve"):
            args = [command, "--workspace", str(project.root), "--base", unrelated, "--json"]
            if command == "check":
                args += ["--ci", "--no-exec"]
            assert cli.main(args) == 1
            captured = capsys.readouterr()
            assert captured.out, "a comparison refusal must return its JSON code"
            assert json.loads(captured.out)["code"] == ("comparison_unavailable" if command == "check" else "no_common_history")
            assert "fetch-depth" not in captured.out + captured.err and "base_unavailable" not in captured.out + captured.err


@pytest.fixture
def repo(tmp_path, _policy_environment):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    for remote in ("origin", "upstream"):
        project.git("remote", "add", remote, "/not-contacted")
    project.write(".aegis/config.json", json.dumps({"approvals": MAP}))
    project.commit("policy")
    project.git("branch", "-f", "main", "HEAD")
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow change")
    return project


@pytest.mark.parametrize("target,mode", [
    ("main", "signature"), ("develop", "review"), ("release/1", "review"),
    ("release/deep/1", "review"), ("feature/lane", "none"),
    (None, "signature"), ("bad\nbranch", "signature"), ("HEAD", "signature"),
])
def test_modes_preserve_findings_and_gate_only_signature(repo, target, mode):
    base = repo.git("rev-parse", "main") if target is None else "main"
    report = rule_integrity.check_ci(repo.root, base, target=target)
    document = report.as_dict()
    assert document["approval_mode"] == mode
    assert document["approval_target"] == (target if target and "\n" not in target and target != "HEAD" else None)
    assert document["policy_source"] == "base"
    assert document["owner_review_required"] == (mode == "review")
    assert report.passed == (mode != "signature")
    assert document["governance"]["categories"] == ["workflows"]


@pytest.mark.parametrize("head_policy", [{"*": "none"}, {"*": "signature"}, None])
def test_head_policy_can_only_tighten_the_mode_even_on_retry(repo, head_policy):
    repo.write(".aegis/config.json", json.dumps({} if head_policy is None else {"approvals": head_policy}))
    repo.commit("head policy edit")
    for target, expected in (("main", "signature"), ("develop", "review")):
        expected = "signature" if head_policy == {"*": "signature"} else expected
        for _ in range(2):
            report = rule_integrity.check_ci(repo.root, "main", target=target)
            assert report.as_dict()["approval_mode"] == expected
            assert report.passed == (expected == "review")
            assert report.as_dict()["policy_source"] == ("head" if target == "develop" and expected == "signature" else "base")


def test_specificity_is_independent_of_map_order():
    raw = {"*": "signature", "release/**": "review", "release/private/**": "none", "release/private/x": "signature"}
    for entries in (raw, dict(reversed(list(raw.items())))):
        parsed = approval_policy.parse_policy({"approvals": entries})
        assert approval_policy.mode_for(parsed, "release/private/x") == "signature"
        assert approval_policy.mode_for(parsed, "release/private/y") == "none"
        assert approval_policy.mode_for(parsed, "release/public") == "review"
        assert approval_policy.mode_for(parsed, "releases/public") == "signature"
        assert approval_policy.mode_for(parsed, "release") == "signature"


def test_oversized_base_is_refused_before_git_or_name_allocation(repo, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("oversized base reached Git")
    monkeypatch.setattr(gitsafe, "resolve_commit", unexpected)
    assert approval_policy.resolve_base(repo.root, "origin/" + "x" * (8 * 1024)) is None


@pytest.mark.parametrize("value", [None, [], "none", {}, {"*": "bogus"}, {"*": []},
    {"bad\nbranch": "none"}, {"release/*": "review"}, {"../main": "none"},
    {"a/**/b": "none"}, {"x" * 256: "none"}, {"main.lock": "none"}, {1: "none"},
])
def test_malformed_maps_refuse_without_echoing_values(value):
    with pytest.raises(approval_policy.InvalidApprovalPolicy) as exc:
        approval_policy.parse_policy({"approvals": value})
    assert str(exc.value) == approval_policy.INVALID_DETAIL


@pytest.mark.parametrize("text", [
    '{"approvals": {"*": "bad"}}', '{"approvals": null}',
    '{"approvals":{"*":"none","*":"signature"}}', '{broken',
    '[' * 1100 + ']' * 1100, 'x' * (64 * 1024 + 1),
], ids=["unknown-mode", "null", "duplicate-key", "invalid-json", "deep-json", "oversized"])
def test_malformed_head_policy_refuses_repeated_checks(repo, text):
    repo.write(".aegis/config.json", text)
    repo.commit("invalid head")
    for _ in range(2):
        with pytest.raises(approval_policy.InvalidApprovalPolicy, match="invalid_approval_policy"):
            rule_integrity.check_ci(repo.root, "main", target="feature/x")


def test_invalid_base_uses_legacy_gate_and_reports_error(repo):
    repo.write(".aegis/config.json", '{"approvals": {"*": "bad"}}')
    repo.commit("old invalid policy")
    base = repo.head()
    repo.write(".aegis/config.json", '{}')
    repo.commit("repair policy")
    report = rule_integrity.check_ci(repo.root, base, target="feature/x")
    assert report.passed  # no signers at the base: the legacy tier-C governance rule
    assert report.as_dict()["approval_policy_error"] == approval_policy.INVALID_DETAIL
    assert "approval_mode" not in report.as_dict()


def test_signature_still_accepts_the_existing_approval_boundary(repo, monkeypatch):
    seen = []
    def approved(root, head, base):
        seen.append((head, base))
        return human_gate.Approval(True, "ok", "approved", head, "Human")
    monkeypatch.setattr(human_gate, "find_approval", approved)
    report = rule_integrity.check_ci(repo.root, "main", target="main")
    assert report.passed and seen == [(report.head, report.base)]


def test_parallel_checks_remain_bound_to_resolved_commits_when_ref_moves(repo, monkeypatch):
    base, head = repo.git("rev-parse", "main"), repo.head()
    original = gitsafe.tree_blobs
    moved = []
    def move_after_resolution(root, revision, **kwargs):
        if not moved:
            moved.append(True)
            repo.git("update-ref", "refs/heads/main", head)
        return original(root, revision, **kwargs)
    monkeypatch.setattr(gitsafe, "tree_blobs", move_after_resolution)
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, base, head, target="main"), range(4)))
    assert all(report.base == base and report.head == head and not report.passed for report in reports)


def test_oversized_blob_is_refused_before_content_read(repo, monkeypatch):
    repo.write(".aegis/config.json", "x" * (64 * 1024 + 1))
    repo.commit("oversized")
    actual_read, actual_run = gitsafe.read_object, gitsafe.run
    reads, commands = [], []
    def watch(root, oid, limit):
        reads.append(limit)
        return actual_read(root, oid, limit)
    def run(args, *rest, **kwargs):
        commands.append(tuple(args))
        return actual_run(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "read_object", watch)
    monkeypatch.setattr(gitsafe, "run", run)
    with pytest.raises(approval_policy.InvalidApprovalPolicy):
        approval_policy.read_policy(repo.root, repo.head())
    assert reads == [64 * 1024]
    assert ("cat-file", "--batch-check") in commands
    assert ("cat-file", "--batch") not in commands


@pytest.mark.parametrize("text", ['{broken', '[]', 'x' * (64 * 1024 + 1)], ids=["unparseable", "non-object", "oversized"])
def test_no_policy_keeps_legacy_for_unusable_head_config(repo, text):
    repo.write(".aegis/config.json", '{}')
    base = repo.commit("legacy base")
    repo.write(".aegis/config.json", text)
    head = repo.commit("legacy config")
    for _ in range(2):
        report = rule_integrity.check_ci(repo.root, base, head, target="main")
        assert report.passed
        assert not any(key.startswith("approval_") or key == "policy_source" for key in report.as_dict())


def test_introduced_valid_policy_does_not_change_legacy_report(repo):
    repo.write(".aegis/config.json", '{}')
    base = repo.commit("legacy base")
    repo.write(".aegis/config.json", '{"v":1}')
    repo.commit("ordinary legacy configuration")
    baseline = rule_integrity.check_ci(repo.root, base).as_dict()
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "signature"}}))
    repo.commit("introduce map")
    result = rule_integrity.check_ci(repo.root, base, target="main").as_dict()
    for document in (baseline, result):
        document.pop("checked_at")
        document["scope"]["head"] = "comparison-head"
    assert json.dumps(result, sort_keys=True) == json.dumps(baseline, sort_keys=True)


@pytest.mark.parametrize("value", [None, [], {"*": "bad"}])
def test_introduced_malformed_map_refuses_on_a_legacy_base(repo, value):
    repo.write(".aegis/config.json", '{}')
    base = repo.commit("legacy base")
    repo.write(".aegis/config.json", json.dumps({"approvals": value}))
    repo.commit("invalid introduced map")
    with pytest.raises(approval_policy.InvalidApprovalPolicy, match="invalid_approval_policy"):
        rule_integrity.check_ci(repo.root, base)


@pytest.mark.parametrize("selector", ["short", "upstream/main", "origin/HEAD", "v1.2", "refs/tags/v1.2"])
def test_git_classifies_tag_commit_and_remote_selectors(repo, selector):
    base = repo.git("rev-parse", "main")
    repo.git("update-ref", "refs/remotes/upstream/main", base)
    repo.git("update-ref", "refs/remotes/origin/main", base)
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.git("tag", "v1.2", base)
    selector = base[:8] if selector == "short" else selector
    report = rule_integrity.check_ci(repo.root, selector)
    # Git names both remote selectors as refs/remotes/R/main; tags and oids
    # remain unknown. This is the round-8 table, not a spelling heuristic.
    target = "main" if selector in ("upstream/main", "origin/HEAD") else None
    assert not report.passed and report.as_dict()["approval_target"] == target
    assert report.as_dict()["approval_mode"] == "signature"


@pytest.mark.parametrize("selector", ["main", "origin/main", "refs/remotes/origin/main", "refs/heads/main"])
def test_known_branch_selectors_keep_the_branch_target(repo, selector):
    repo.git("update-ref", "refs/remotes/origin/main", repo.git("rev-parse", "main"))
    report = rule_integrity.check_ci(repo.root, selector)
    assert report.as_dict()["approval_target"] == "main" and not report.passed


@pytest.mark.parametrize("selector", ["origin/main", "main", "refs/remotes/origin/main", "refs/heads/main"])
def test_parallel_checks_pin_gits_selected_policy_despite_a_shadowing_tag(repo, selector):
    base, head = repo.git("rev-parse", "refs/heads/main"), repo.head()
    repo.git("update-ref", "refs/remotes/origin/main", base)
    older = repo.git("rev-parse", "refs/heads/main^")
    repo.git("tag", selector, older)
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, selector, head), range(4)))
    ambiguous = selector in ("main", "origin/main")
    # Git pins the tag for bare ambiguity and the branch for qualified input.
    # Both have empty symbolic-full-name output in this collision: UNKNOWN.
    assert all(report.base == (older if ambiguous else base) and report.passed == ambiguous for report in reports)
    assert all(report.approval_policy.mode == (None if ambiguous else "signature")
               and report.approval_policy.target is None for report in reports)


@pytest.mark.parametrize("shadow", ["tag", "local"])
@pytest.mark.parametrize("selector", ["origin/feature/x", "refs/remotes/origin/feature/x", "refs/heads/feature/x"])
def test_git_classifies_ref_shaped_local_branches_and_tags(repo, shadow, selector):
    base = repo.git("rev-parse", "main")
    repo.git("tag" if shadow == "tag" else "branch", selector, base)
    for _ in range(2):
        # Git identifies a local shadow as refs/heads/<selector>, hence a known
        # local branch under the new table. A tag remains unknown and strictest.
        target = selector if shadow == "local" else None
        assert approval_policy.branch_from_base(selector, repo.root, commit=base) == target
        report = rule_integrity.check_ci(repo.root, selector)
        assert report.base == base and report.approval_policy.target == target
        assert report.approval_policy.mode == ("none" if shadow == "local" else "signature")
        assert report.passed == (shadow == "local")


def test_branch_identity_read_failure_is_an_unknown_target(repo, monkeypatch):
    base = repo.git("rev-parse", "refs/heads/main")
    def unavailable(*args, **kwargs):
        raise gitsafe.GitError("secret ref read failure")
    monkeypatch.setattr(gitsafe, "read_ref", unavailable)
    for _ in range(2):
        assert approval_policy.branch_from_base("main", repo.root, commit=base) is None
        report = rule_integrity.check_ci(repo.root, base)
        assert report.approval_policy.target is None and report.approval_policy.mode == "signature"
        assert not report.passed and "secret" not in json.dumps(report.as_dict())


def test_branch_moving_after_base_resolution_cannot_reclassify_the_pinned_commit(repo, monkeypatch):
    base, head = repo.git("rev-parse", "main"), repo.head()
    repo.git("update-ref", "refs/remotes/origin/develop", base)
    original = gitsafe.resolve_commit
    def move(root, revision):
        commit = original(root, revision)
        if revision == "origin/develop":
            repo.git("update-ref", "refs/remotes/origin/develop", head)
        return commit
    monkeypatch.setattr(gitsafe, "resolve_commit", move)
    report = rule_integrity.check_ci(repo.root, "origin/develop")
    assert report.base == base and report.approval_policy.target is None
    assert report.approval_policy.mode == "signature" and not report.passed


@pytest.mark.parametrize("explicit", [False, True])
def test_push_policy_base_is_pinned_across_fallback_ref_move(repo, monkeypatch, explicit):
    repo.write(".aegis/config.json", '{}')
    before = repo.commit("legacy predecessor")
    repo.write(".aegis/config.json", json.dumps({"approvals": MAP}))
    protected = repo.commit("reviewed fallback policy")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    head = repo.commit("candidate loosens policy")
    repo.git("update-ref", "refs/remotes/origin/main", protected)
    original = gitsafe.read_ref
    def move(root, revision):
        result = original(root, revision)
        if revision == "refs/remotes/origin/main" and result != head:
            repo.git("update-ref", "refs/remotes/origin/main", head)
        return result
    monkeypatch.setattr(gitsafe, "read_ref", move)
    pinned = approval_policy.push_base(repo.root, before, "origin/main", head, explicit=explicit)
    assert pinned == (protected if explicit else before)
    report = rule_integrity.check_ci(repo.root, pinned, head, target="main")
    assert report.passed == (not explicit)
    def retry(_):
        try:
            return approval_policy.push_base(repo.root, before, "origin/main", head, explicit=explicit)
        except approval_policy.BaseUnavailable as exc:
            assert str(exc) == (approval_policy.COMPARISON_UNAVAILABLE_DETAIL if explicit
                                else approval_policy.BASE_UNAVAILABLE_DETAIL)
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(retry, range(4)))
    assert results == (["refused"] * 4 if explicit else [before] * 4)


@pytest.mark.parametrize("supplied_target", [False, True])
def test_parallel_pr_checks_never_infer_a_target_from_review_identity(repo, supplied_target):
    base, head = repo.git("rev-parse", "main"), repo.head()
    pull = human_gate.PullRequest(1, "agent", head, "feature/x")
    kwargs = {"target": None} if supplied_target else {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, base, head, pull_request=pull, **kwargs), range(4)))
    assert all(not report.passed and report.approval_policy.target is None
               and report.approval_policy.mode == "signature" for report in reports)


def test_explicit_zero_before_fallback_stays_pinned_when_the_branch_moves(repo, monkeypatch):
    base, head = repo.git("rev-parse", "refs/heads/main"), repo.head()
    repo.git("update-ref", "refs/remotes/origin/main", base)
    original = gitsafe.read_ref
    def move(root, revision):
        commit = original(root, revision)
        if revision == "refs/remotes/origin/main" and commit == base:
            repo.git("update-ref", "refs/remotes/origin/main", head)
        return commit
    monkeypatch.setattr(gitsafe, "read_ref", move)
    pinned = approval_policy.push_base(repo.root, "0" * 40, "origin/main", head, explicit=True)
    assert pinned == base
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, pinned, head, target="main"), range(4)))
    assert all(report.base == base and not report.passed for report in reports)
    for _ in range(2):
        assert approval_policy.push_base(repo.root, "0" * 40, "origin/main", head, explicit=True) == head


@pytest.mark.parametrize("failure", ["tree", "blob"])
def test_unreadable_committed_policy_never_becomes_legacy(repo, monkeypatch, failure):
    def unavailable(*args, **kwargs):
        raise gitsafe.GitError("secret object read failure")
    if failure == "tree":
        monkeypatch.setattr(gitsafe, "tree_blobs", unavailable)
    else:
        monkeypatch.setattr(gitsafe, "read_object", unavailable)
    for _ in range(2):
        with pytest.raises(approval_policy.InvalidApprovalPolicy, match="invalid_approval_policy") as exc:
            rule_integrity.check_ci(repo.root, "main", target="main")
        assert "secret" not in str(exc.value)
