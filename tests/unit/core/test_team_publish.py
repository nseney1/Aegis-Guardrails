"""Publisher effects require exact, single-use grants from the policy gate."""
from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
from threading import Barrier, Lock
from types import SimpleNamespace

import pytest

from aegis_core import approval_policy, ghcli, gitsafe, team_gitops
from aegis_core import team_publish as publish
from tests import helpers_humangate as hg


OLD, NEW, OTHER = "a" * 40, "b" * 40, "c" * 40
REMOTE = "https://github.com/owner/project.git"
REF = "refs/heads/integration"
HEAD = "refs/heads/aegis/publish/" + NEW
OPERATIONS = ("push", "pr", "release_pr", "cancel")


class FakeGit:
    def __init__(self):
        self.tips = {REF: OLD, HEAD: NEW, "refs/heads/develop": OLD}
        self.policies = {OLD: {"*": "none", "develop": "review", "main": "signature"}, NEW: {"*": "none"}}
        self.calls = []
        self.non_ff = False
        self.lost_reply = False
        self.unsafe_config = False
        self.reject_push = False
        self.scopes = []
        self.policy_calls = []
        self.before_push = None
        self.writes = []
        self.output_override = None
        self.config_keys = []
        self.config_entries = {}
        self.probe_failure = False
        self.mutation_guard = Lock()

    def run(self, args, cwd, **kwargs):
        self.scopes.append(gitsafe.custody_active())
        self.calls.append((list(args), kwargs))
        output, rc = b"", 0
        if args[0] == "config":
            keys = ["url.hostile.insteadof"] if self.unsafe_config else self.config_keys
            entries = {**dict.fromkeys(keys, ""), **self.config_entries}
            if "--list" in args:
                output = b"".join(("local\0" + key + "\n" + value + "\0").encode() for key, value in entries.items())
            else:
                keys = [key for key in entries if re.search(args[-1], key)]
                rc = 0 if keys else 1
                output = ("\n".join(keys) + "\n").encode() if keys else b""
        elif args[0] == "ls-remote":
            ref = args[-1]
            if self.probe_failure:
                rc = 128
            elif ref in self.tips:
                output = (self.tips[ref] + "\t" + ref + "\n").encode()
            else:
                rc = 2
        elif args[0] == "push":
            oid, ref = args[-1].split(":")
            if self.before_push is not None:
                self.before_push()
            with self.mutation_guard:
                old = self.tips.get(ref)
                lease = next((arg for arg in args if arg.startswith("--force-with-lease=")), None)
                stale = lease is not None and lease.split("=", 1)[1] != ref + ":" + (old or "")
                if stale or self.non_ff or self.reject_push:
                    rc = 1
                    summary = "[rejected] (stale info)" if stale else "[rejected] (non-fast-forward)"
                    output = ("!\t" + oid + ":" + ref + "\t" + summary + "\n").encode()
                else:
                    self.tips[ref] = oid
                    self.writes.append((ref, old, oid))
                    output = (("*" if old is None else " ") + "\t" + oid + ":" + ref + "\tupdated\n").encode()
            if self.output_override is not None:
                output = self.output_override
            if self.lost_reply:
                raise OSError("token=SECRET lost reply")
        elif args[0] == "merge-base":
            rc = int(self.non_ff)
        return subprocess.CompletedProcess(args, rc, output, b"token=SECRET")

    def resolve_commit(self, root, oid):
        return oid if oid in (OLD, NEW, OTHER) else None

    def resolve_policy(self, root, base, head, target):
        """Model the trusted immutable-policy reader, using its public map helpers."""
        self.policy_calls.append((root, base, head, target))
        policies = [approval_policy.parse_policy({"approvals": self.policies[oid]}) for oid in (base, head)]
        modes = [approval_policy.mode_for(policy, target) for policy in policies]
        effective = max(modes, key=approval_policy.MODES.index)
        return approval_policy.Policy(effective, target, source="head" if modes[1] != modes[0] and effective == modes[1] else "base")


class ControlledJournal(team_gitops.GitOpsJournal):
    """Real descriptor journal with test-owned boundary failure controls."""

    def __init__(self, root):
        super().__init__(root)
        self.intent_barrier = None
        self.after_intent = None
        self.fail_results = False

    def record_intent(self, **fields):
        if self.intent_barrier is not None:
            self.intent_barrier.wait()
        receipt = super().record_intent(**fields)
        if self.after_intent is not None and receipt.created:
            self.after_intent(fields)
        return receipt

    def record_result(self, *args, **kwargs):
        if self.fail_results:
            raise team_gitops.GitOpsError("journal_io")
        return super().record_result(*args, **kwargs)


class FakeGh:
    def __init__(self, git=None):
        self.calls = []
        self.failure = None
        self.pull = None
        self.run_state = {"id": 12, "head_sha": OTHER, "head_branch": "integration", "event": "push", "status": "in_progress", "conclusion": None}
        self.lost_reply = False
        self.git = git
        self.before_post = None

    def __call__(self, args, stdin=None, cwd=None, **kwargs):
        self.calls.append((list(args), stdin))
        if self.failure == "unavailable":
            return None
        if self.failure == "malformed":
            return ghcli.GhResult(0, "token=SECRET", "")
        method = args[args.index("--method") + 1]
        endpoint = args[-1]
        if method == "POST" and self.before_post is not None:
            self.before_post()
        if endpoint == "repos/owner/project":
            data = json.dumps({"full_name": "owner/project", "permissions": {"push": True}})
        elif endpoint.endswith("/cancel"):
            self.run_state.update(status="completed", conclusion="cancelled")
            data = ""
        elif "/actions/runs/" in endpoint:
            data = json.dumps(self.run_state)
        elif method == "POST":
            fields = json.loads(stdin)
            commit = self.git.tips["refs/heads/" + fields["head"]] if self.git is not None else NEW
            self.pull = {"number": 42, "state": "open", "draft": fields["draft"], "head": {"sha": commit, "ref": fields["head"], "repo": {"full_name": "owner/project"}}, "base": {"ref": fields["base"], "repo": {"full_name": "owner/project"}}}
            data = json.dumps(self.pull)
            if self.lost_reply:
                raise TimeoutError("token=SECRET")
        else:
            data = json.dumps([self.pull] if self.pull else [])
        return ghcli.GhResult(0, data, "")


@pytest.fixture
def rig(tmp_path):
    if not team_gitops.descriptor_supported():
        pytest.skip("descriptor-relative journal needs POSIX no-follow operations")
    root = tmp_path / "common"
    root.mkdir()
    git = FakeGit()
    gh = FakeGh(git)
    journal = ControlledJournal(root)
    evidence = {"allowed": True, "calls": []}
    def qualified(request):
        evidence["calls"].append(request)
        return evidence["allowed"]
    setup = SimpleNamespace(git=git, gh=gh, journal=journal, evidence=evidence, root=root, credentials={"token": "test-publisher-credential"})
    setup.service = publisher(setup, qualified=qualified)
    yield setup
    # Every test waits for its worker threads before releasing any owned receipt.
    for row in journal.open_intents():
        journal.reconcile(row["lane"], lambda intent: team_gitops.Observation(None))


def publisher(rig, *, gh=None, qualified=None, **readers):
    dependencies = {"git_runner": rig.git.run, "commit_resolver": rig.git.resolve_commit,
                    "policy_resolver": rig.git.resolve_policy, "credential_reader": lambda: rig.credentials["token"]}
    dependencies.update(readers)
    return publish.Publisher(rig.root, rig.journal, remote=REMOTE, qualified=qualified if qualified is not None else lambda item: True,
                             gh=gh if gh is not None else rig.gh, **dependencies)


def primitives(service):
    return {"push": service.push, "pr": service.pr, "release_pr": service.release_pr,
            "cancel": service.cancel, "_execute": service._execute, "_effect": service._effect}


def request(operation="push", **changes):
    fields = dict(request_id="request-1", lane="writer", actor="publisher", remote=REMOTE, ref=REF, commit=NEW, expected_old=OLD, operation=operation)
    if operation in ("pr", "release_pr"):
        fields["head_ref"] = HEAD
    if operation == "release_pr":
        fields["ref"] = "refs/heads/develop"
    if operation == "cancel":
        fields["run_id"] = 12
        fields["commit"] = OLD
    return publish.PublishRequest(**{**fields, **changes})


def execute(rig, item):
    permit = rig.service.gate(item)
    return primitives(rig.service)[item.operation](permit)


def refuses(code, call):
    with pytest.raises(publish.PublishError) as error:
        call()
    assert error.value.code == code
    assert str(error.value) == publish.REFUSALS[code]
    assert error.value.next_action["actor"] == "owner"
    assert "SECRET" not in str(error.value) + repr(error.value.next_action)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_allowed_effect_has_intent_result_and_retry_never_reexecutes(rig, operation):
    item = request(operation)
    result = execute(rig, item)
    assert result["status"] == "done"
    effects = effect_count(rig)
    assert execute(rig, item)["status"] == "done"
    assert effect_count(rig) == effects == 1
    assert [row["kind"] for row in rig.journal.read().rows] == ["intent", "result"]
    assert rig.evidence["calls"]


def effect_count(rig):
    return sum(args[0] == "push" for args, _ in rig.git.calls) + sum("POST" in args for args, _ in rig.gh.calls)


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("case,code", [("refused", "policy_refused"), ("unavailable", "gh_unavailable"), ("malformed", "gh_malformed"), ("moved", "ref_moved"), ("credential", "unsafe_remote"), ("encoding", "invalid_request")])
def test_operation_failure_matrix_refuses_with_fixed_code_and_no_effect(rig, operation, case, code):
    item = request(operation)
    if case == "refused":
        # A release PR may open on review/signature targets, but never on none.
        rig.git.policies[OLD] = {"*": "none" if operation == "release_pr" else "review"}
    elif case in ("unavailable", "malformed"):
        rig.gh.failure = case
    elif case == "moved":
        rig.git.tips[item.ref] = OTHER
    elif case == "credential":
        item = replace(item, remote="https://token:SECRET@github.com/owner/project.git")
    else:
        item = replace(item, ref="refs/heads/\udcff")
    refuses(code, lambda: execute(rig, item))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("operation", OPERATIONS)
def test_gate_to_effect_ref_race_refuses_and_records_no_attempt(rig, operation):
    item = request(operation)
    permit = rig.service.gate(item)
    rig.git.tips[item.ref] = OTHER
    refuses("ref_moved", lambda: primitives(rig.service)[operation](permit))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("operation", OPERATIONS)
def test_missing_forged_wrong_operation_and_foreign_permits_cannot_publish(rig, operation):
    primitive = primitives(rig.service)[operation]
    for forged in (None, object(), request(operation)):
        refuses("invalid_permit", lambda: primitive(forged))
    other = publisher(rig)
    refuses("invalid_permit", lambda: primitives(other)[operation](rig.service.gate(request(operation))))
    wrong = "pr" if operation == "push" else "push"
    refuses("invalid_permit", lambda: primitive(rig.service.gate(request(wrong))))
    assert effect_count(rig) == 0


def test_policy_head_can_tighten_but_never_loosen(rig):
    rig.git.policies[OLD] = {"*": "review"}
    rig.git.policies[NEW] = {"*": "none"}
    refuses("policy_refused", lambda: execute(rig, request()))
    rig.git.policies[OLD] = {"*": "none"}
    rig.git.policies[NEW] = {"*": "signature"}
    refuses("policy_refused", lambda: execute(rig, request()))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("policy", [None, {}, {"*": "bogus"}])
def test_missing_or_invalid_policy_fails_closed(rig, policy):
    rig.git.policies[OLD] = policy
    refuses("policy_unavailable", lambda: execute(rig, request()))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("operation", OPERATIONS)
def test_qualification_is_bound_to_entire_request_and_failure_is_closed(rig, operation):
    rig.evidence["allowed"] = False
    item = request(operation)
    refuses("not_qualified", lambda: execute(rig, item))
    assert rig.evidence["calls"] == [item]
    assert effect_count(rig) == 0
    rig.evidence["allowed"] = True
    assert execute(rig, item)["status"] == "done"


@pytest.mark.parametrize("operation", ("push", "cancel"))
@pytest.mark.parametrize("branch", ("main", "develop", "release/v1"))
def test_protected_branches_refuse_even_if_policy_says_none(rig, operation, branch):
    ref = "refs/heads/" + branch
    rig.git.tips[ref] = OLD
    rig.git.policies[OLD] = {"*": "none"}
    refuses("protected_target", lambda: execute(rig, request(operation, ref=ref)))


@pytest.mark.parametrize("operation", OPERATIONS)
def test_concurrent_use_of_one_permit_gets_one_effect(rig, operation):
    permit = rig.service.gate(request(operation))
    def attempt(_):
        try:
            return primitives(rig.service)[operation](permit)["status"]
        except publish.PublishError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(attempt, range(3)))
    assert sorted(outcomes) == ["done", "invalid_permit", "invalid_permit"]
    assert effect_count(rig) == 1


@pytest.mark.parametrize("operation", ("push", "pr", "release_pr"))
def test_lost_reply_is_resolved_by_observation_without_retry(rig, operation):
    rig.git.lost_reply = rig.gh.lost_reply = True
    item = request(operation)
    assert execute(rig, item)["status"] == "done"
    assert execute(rig, item)["status"] == "done"
    assert effect_count(rig) == 1


@pytest.mark.parametrize("field,value", [("ref", "refs/heads/line\nbreak"), ("commit", NEW + "\n"), ("ref", "x" * 100000), ("head_ref", "refs/heads/../../x"), ("operation", "merge"), ("run_id", True)], ids=("multiline-ref", "multiline-commit", "oversized", "traversal", "merge", "boolean-run"))
def test_malformed_and_oversized_inputs_refuse_before_transport(rig, field, value):
    refuses("invalid_request", lambda: execute(rig, request(**{field: value})))
    assert rig.git.calls == rig.gh.calls == []


def test_credentials_never_reach_argv_or_public_results(rig):
    result = execute(rig, request())
    argv = json.dumps([args for args, _ in rig.git.calls] + [args for args, _ in rig.gh.calls])
    assert "test-publisher-credential" not in argv + json.dumps(result)
    assert "SECRET" not in argv + json.dumps(result)
    push = next((args, kwargs) for args, kwargs in rig.git.calls if args[0] == "push")
    assert push[0][-1] == NEW + ":" + REF
    assert push[1]["_env"]["GIT_ALLOW_PROTOCOL"] == "https"


def test_unsupported_journal_platform_has_fixed_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(team_gitops, "descriptor_supported", lambda: False)
    service = publish.Publisher(tmp_path, team_gitops.GitOpsJournal(tmp_path), remote=REMOTE, qualified=lambda item: True, gh=FakeGh())
    refuses("unsupported_platform", lambda: service.gate(request()))


def test_every_publishing_callable_requires_a_permit(rig):
    # Repository-owned source reads are deliberately plain and cross-platform.
    tree = ast.parse(Path(publish.__file__).read_text(encoding="utf-8"))
    module_functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert module_functions == {"_valid_request", "_remote_identity", "_oid", "_branch", "_json", "_source_ref", "_safe_config", "_push_status"}
    for name, obj in vars(publish).items():
        if inspect.isfunction(obj) and obj.__module__ == publish.__name__:
            assert name in module_functions
    for name in (*OPERATIONS, "_execute", "_effect"):
        method = primitives(rig.service)[name]
        assert "permit" in inspect.signature(method).parameters
        refuses("invalid_permit", lambda: method(None))
    effect_sites, git_sites = [], {}
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                    if child.func.attr == "__git_run":
                        assert child.args and isinstance(child.args[0], ast.List)
                        assert child.args[0].elts and isinstance(child.args[0].elts[0], ast.Constant)
                        command = child.args[0].elts[0].value
                        git_sites[node.name] = command
                        if command in ("push", "ls-remote"):
                            scope = parents[id(child)]
                            while not isinstance(scope, ast.FunctionDef):
                                if isinstance(scope, ast.With) and any(isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func, ast.Attribute) and item.context_expr.func.attr == "_transport_safety" for item in scope.items):
                                    break
                                scope = parents[id(scope)]
                            assert isinstance(scope, ast.With)
                        if command == "push":
                            effect_sites.append(node.name)
                    if isinstance(child.func.value, ast.Name) and child.func.value.id == "self" and child.func.attr == "__gh":
                        scope = parents[id(child)]
                        while not isinstance(scope, ast.FunctionDef):
                            if isinstance(scope, ast.With) and any(isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func, ast.Attribute) and item.context_expr.func.attr == "_transport_safety" for item in scope.items):
                                break
                            scope = parents[id(scope)]
                        assert isinstance(scope, ast.With)
                        argv = child.args[0]
                        assert isinstance(argv, ast.List)
                        methods = [part.value for part in argv.elts if isinstance(part, ast.Constant) and part.value in ("GET", "POST")]
                        assert len(methods) == 1
                        if methods == ["POST"]:
                            effect_sites.append(node.name)
    assert effect_sites == ["_effect", "_effect"]
    assert git_sites == {"_tip": "ls-remote", "_ancestor": "merge-base", "_transport_safety": "config", "_effect": "push"}


@pytest.mark.parametrize("operation", OPERATIONS)
def test_distinct_permits_for_concurrent_same_request_reserve_one_attempt(rig, operation):
    item = request(operation)
    permits = [rig.service.gate(item) for _ in range(3)]
    rig.journal.intent_barrier = Barrier(3, timeout=5)
    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(primitives(rig.service)[operation], permits))
    assert all(result["status"] in ("done", "pending") for result in outcomes)
    assert any(result["status"] == "done" for result in outcomes)
    assert effect_count(rig) == 1
    assert execute(rig, item)["status"] == "done"


@pytest.mark.parametrize("operation", OPERATIONS)
def test_qualification_change_between_gate_and_execution_refuses(rig, operation):
    permit = rig.service.gate(request(operation))
    rig.evidence["allowed"] = False
    refuses("not_qualified", lambda: primitives(rig.service)[operation](permit))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("field,value", [("remote", "https://github.com/other/project.git"), ("ref", "refs/heads/another"), ("commit", OTHER), ("actor", "another-actor"), ("lane", "another-lane")])
def test_request_id_cannot_be_rebound_to_different_effect(rig, field, value):
    item = request()
    assert execute(rig, item)["status"] == "done"
    refuses("unsafe_remote" if field == "remote" else "request_conflict", lambda: rig.service.gate(replace(item, **{field: value})))
    assert effect_count(rig) == 1


def test_non_fast_forward_and_transport_configuration_refuse_before_effect(rig):
    permit = rig.service.gate(request())
    rig.git.non_ff = True
    refuses("not_fast_forward", lambda: rig.service.push(permit))
    rig.git.non_ff = False
    rig.git.unsafe_config = True
    refuses("unsafe_git_config", lambda: execute(rig, request()))
    assert effect_count(rig) == 0
    rig.git.unsafe_config = False
    assert execute(rig, request())["status"] == "done"


def test_missing_credential_has_fixed_code_and_no_transport_or_effect(rig):
    rig.credentials["token"] = None
    refuses("identity_unavailable", lambda: execute(rig, request()))
    assert effect_count(rig) == 0


def test_push_rejection_is_recorded_and_never_retried(rig):
    rig.git.reject_push = True
    refuses("push_refused", lambda: execute(rig, request()))
    assert rig.journal.read().rows[-1]["status"] == "not_applied"
    assert execute(rig, request()) == {"status": "not_applied", "code": "effect_unconfirmed"}
    assert effect_count(rig) == 1


@pytest.mark.parametrize("operation", ("pr", "release_pr", "cancel"))
def test_forge_effect_failure_has_result_and_never_retries(rig, operation):
    original = rig.gh.__call__
    def no_post(args, **kwargs):
        if "POST" in args:
            rig.gh.calls.append((args, kwargs.get("stdin")))
            return None
        return original(args, **kwargs)
    service = publisher(rig, gh=no_post)
    item = request(operation)
    refuses("gh_unavailable", lambda: primitives(service)[operation](service.gate(item)))
    assert rig.journal.read().rows[-1]["status"] == "not_applied"
    assert primitives(service)[operation](service.gate(item))["status"] == "not_applied"
    assert effect_count(rig) == 1


@pytest.mark.parametrize("operation", ("pr", "release_pr", "cancel"))
def test_failed_observation_after_effect_records_sticky_unknown(rig, operation):
    original = rig.gh.__call__
    def fail_observation(args, **kwargs):
        result = original(args, **kwargs)
        if "POST" in args:
            rig.gh.failure = "malformed"
        return result
    service = publisher(rig, gh=fail_observation)
    item = request(operation)
    refuses("gh_malformed", lambda: primitives(service)[operation](service.gate(item)))
    assert rig.journal.read().rows[-1]["status"] == "unknown"
    calls = len(rig.gh.calls)
    assert primitives(service)[operation](service.gate(item)) == {"status": "unknown", "code": "effect_unconfirmed"}
    assert len(rig.gh.calls) == calls
    assert effect_count(rig) == 1


def test_completed_uncancelled_run_is_not_cancellable(rig):
    rig.gh.run_state.update(status="completed", conclusion="success")
    refuses("run_refused", lambda: execute(rig, request("cancel")))
    assert effect_count(rig) == 0


def test_cancel_refuses_unrelated_or_current_commit_and_wrong_event(rig):
    for fields in ({"head_sha": OLD}, {"event": "pull_request"}, {"head_branch": "main"}):
        original = dict(rig.gh.run_state)
        rig.gh.run_state.update(fields)
        refuses("run_refused", lambda: execute(rig, request("cancel")))
        rig.gh.run_state = original
    assert effect_count(rig) == 0


@pytest.mark.parametrize("operation", ("pr", "release_pr"))
def test_existing_exact_pull_is_reused_but_moved_pull_and_pr259_refuse(rig, operation):
    assert execute(rig, request(operation))["status"] == "done"
    assert execute(rig, request(operation, request_id="request-2"))["status"] == "done"
    assert effect_count(rig) == 1
    rig.gh.pull["head"]["sha"] = OTHER
    refuses("ref_moved", lambda: rig.service.gate(request(operation, request_id="request-3")))
    rig.gh.pull["head"]["sha"] = NEW
    rig.gh.pull["number"] = 259
    refuses("gh_malformed", lambda: rig.service.gate(request(operation, request_id="request-3")))
    assert effect_count(rig) == 1


@pytest.mark.parametrize("payload", ["x" * (publish.MAX_OUTPUT + 1), "\udcff", '{"x": 1, "x": 2}', "[" * 5000], ids=("oversized", "non-utf8", "duplicate", "depth"))
def test_forge_json_refuses_oversize_encoding_duplicate_and_depth(payload):
    refuses("gh_malformed", lambda: publish._json(ghcli.GhResult(0, payload, "token=SECRET")))


def test_size_check_precedes_json_parser():
    # Valid JSON distinguishes a size refusal from a parse-error fallback.
    payload = json.dumps("x" * publish.MAX_OUTPUT)
    refuses("gh_malformed", lambda: publish._json(ghcli.GhResult(0, payload, "")))


def test_no_implicit_unbounded_forge_transport_is_activated(tmp_path):
    refuses("gh_unavailable", lambda: publish.Publisher(tmp_path, team_gitops.GitOpsJournal(tmp_path), remote=REMOTE, qualified=lambda item: True))


def test_permit_detaches_request_and_cannot_be_directly_constructed(rig):
    item = request()
    permit = rig.service.gate(item)
    with pytest.raises(FrozenInstanceError, match="cannot assign to field 'ref'"):
        item.ref = "refs/heads/main"
    assert rig.service.push(permit)["status"] == "done"
    refuses("invalid_permit", lambda: type(permit)())
    refuses("invalid_permit", lambda: rig.service.push(object.__new__(type(permit))))


def test_post_uses_json_stdin_and_only_safe_generated_text(rig):
    execute(rig, request("pr"))
    args, data = next((args, data) for args, data in rig.gh.calls if "POST" in args)
    assert args[args.index("--input") + 1] == "-"
    assert json.loads(data) == {"head": HEAD[11:], "base": "integration", "title": "Qualified lane " + NEW, "body": "Exact qualified commit: " + NEW, "draft": True}


def test_network_disables_askpass_maintenance_and_config_includes(rig):
    execute(rig, request())
    assert all(rig.git.scopes)
    for args, kwargs in rig.git.calls:
        if args[0] == "config":
            assert "--no-includes" in args
        if args[0] in ("push", "ls-remote"):
            env = kwargs["_env"]
            assert env["GIT_ASKPASS"] == env["SSH_ASKPASS"] == os.devnull
            settings = {env["GIT_CONFIG_KEY_" + str(index)]: env["GIT_CONFIG_VALUE_" + str(index)] for index in range(int(env["GIT_CONFIG_COUNT"]))}
            assert settings["gc.auto"] == "0"
            assert settings["maintenance.auto"] == "false"
            assert settings["http.followRedirects"] == "false"
            assert settings["http.sslVerify"] == "true"
            assert env["GIT_CONFIG_KEY_0"] == "http." + REMOTE + ".extraHeader"


@pytest.mark.parametrize("operation", OPERATIONS)
def test_lost_result_write_is_reconciled_without_another_effect(rig, operation):
    rig.journal.fail_results = True
    item = request(operation)
    refuses("journal_io", lambda: execute(rig, item))
    assert effect_count(rig) == 1
    assert [row["kind"] for row in rig.journal.read().rows] == ["intent"]
    rig.journal.fail_results = False
    assert execute(rig, item)["status"] == "done"
    assert effect_count(rig) == 1
    assert [row["kind"] for row in rig.journal.read().rows] == ["intent", "result"]


@pytest.mark.parametrize("operation", ("pr", "release_pr"))
def test_source_ref_movement_after_gate_refuses(rig, operation):
    item = request(operation)
    permit = rig.service.gate(item)
    rig.git.tips[HEAD] = OTHER
    refuses("ref_moved", lambda: primitives(rig.service)[operation](permit))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("operation", OPERATIONS)
def test_ref_movement_after_intent_refuses_without_effect_and_never_retries(rig, operation):
    item = request(operation)
    def moved(fields):
        rig.git.tips[item.ref] = OTHER
    rig.journal.after_intent = moved
    refuses("ref_moved", lambda: execute(rig, item))
    assert effect_count(rig) == 0
    assert execute(rig, item)["status"] == "unknown"
    assert effect_count(rig) == 0


def test_accepted_cancel_with_pending_state_is_unknown_and_never_retried(rig):
    original = rig.gh.__call__
    def pending_cancel(args, **kwargs):
        if "POST" in args:
            rig.gh.calls.append((args, None))
            return ghcli.GhResult(0, "", "")
        return original(args, **kwargs)
    service = publisher(rig, gh=pending_cancel)
    item = request("cancel")
    assert service.cancel(service.gate(item)) == {"status": "unknown", "code": "effect_unconfirmed"}
    assert rig.journal.read().rows[-1]["status"] == "unknown"
    assert service.cancel(service.gate(item))["status"] == "unknown"
    assert effect_count(rig) == 1


@pytest.mark.parametrize("operation", ("pr", "release_pr"))
@pytest.mark.parametrize("case", ("row", "head", "base", "head_repo", "base_repo", "missing_sha"))
def test_malformed_pull_shapes_refuse_without_effect_and_allow_corrected_retry(rig, operation, case):
    item = request(operation)
    assert execute(rig, item)["status"] == "done"
    valid = json.loads(json.dumps(rig.gh.pull))
    if case == "row":
        rig.gh.pull = 42
    elif case in ("head", "base"):
        rig.gh.pull[case] = "token=SECRET"
    elif case == "missing_sha":
        del rig.gh.pull["head"]["sha"]
    else:
        rig.gh.pull[case.split("_")[0]]["repo"] = []
    retry = replace(item, request_id="request-2")
    refuses("gh_malformed", lambda: execute(rig, retry))
    assert effect_count(rig) == 1
    rig.gh.pull = valid
    assert execute(rig, retry)["status"] == "done"
    assert effect_count(rig) == 1


@pytest.mark.parametrize("field", ("id", "head_sha", "head_branch", "event", "status", "conclusion"))
def test_missing_run_fields_have_fixed_refusal_and_allow_corrected_retry(rig, field):
    valid = dict(rig.gh.run_state)
    del rig.gh.run_state[field]
    refuses("gh_malformed", lambda: execute(rig, request("cancel")))
    assert effect_count(rig) == 0
    rig.gh.run_state = valid
    assert execute(rig, request("cancel"))["status"] == "done"
    assert effect_count(rig) == 1


@pytest.mark.parametrize("operation", OPERATIONS)
def test_policy_reader_receives_pinned_base_head_and_target(rig, operation):
    item = request(operation)
    assert execute(rig, item)["status"] == "done"
    assert rig.git.policy_calls
    assert all(call == (rig.root, item.expected_old, item.commit, item.ref[11:]) for call in rig.git.policy_calls)


@pytest.mark.parametrize("reader,code", [("git_runner", "git_unavailable"), ("commit_resolver", "git_unavailable"), ("policy_resolver", "policy_unavailable"), ("credential_reader", "identity_unavailable")])
@pytest.mark.parametrize("failure", ("exception", "shape"))
def test_injected_reader_failures_have_fixed_codes_before_any_effect(rig, reader, code, failure):
    def unavailable(*args, **kwargs):
        if failure == "exception":
            raise RuntimeError("token=SECRET")
        return None
    service = publisher(rig, **{reader: unavailable})
    refuses(code, lambda: service.push(service.gate(request())))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("reader", ("git_runner", "commit_resolver", "policy_resolver", "credential_reader"))
def test_noncallable_injected_dependency_has_fixed_refusal(tmp_path, reader):
    refuses("invalid_request", lambda: publish.Publisher(tmp_path, team_gitops.GitOpsJournal(tmp_path), remote=REMOTE,
            qualified=lambda item: True, gh=FakeGh(), **{reader: object()}))


def test_push_race_after_final_check_is_cas_refusal_without_update(rig):
    # OTHER is still an ancestor of NEW in this model, so ordinary push accepts it.
    rig.git.before_push = lambda: rig.git.tips.update({REF: OTHER})
    refuses("ref_moved", lambda: execute(rig, request()))
    assert rig.git.tips[REF] == OTHER
    assert rig.git.writes == []
    assert rig.journal.read().rows[-1]["status"] == "unknown"
    assert execute(rig, request())["status"] == "unknown"
    assert rig.git.writes == []


@pytest.mark.parametrize("operation", ("pr", "release_pr"))
def test_immutable_source_rejects_competing_publisher_inside_post(rig, operation):
    item = request(operation)
    contender = publisher(rig)
    attempted = []
    def compete():
        change = request("push", request_id="source-race", ref=HEAD, expected_old=NEW, commit=OTHER)
        refuses("immutable_source", lambda: contender.push(contender.gate(change)))
        attempted.append(True)
    rig.gh.before_post = compete
    assert execute(rig, item)["status"] == "done"
    assert attempted == [True]
    assert rig.git.writes == []
    assert rig.gh.pull["head"]["sha"] == NEW
    assert not any(row["request_id"] == "source-race" for row in rig.journal.read().rows)


@pytest.mark.parametrize("operation", ("pr", "release_pr"))
def test_mutable_pr_source_is_refused_before_effect(rig, operation):
    refuses("immutable_source", lambda: execute(rig, request(operation, head_ref="refs/heads/lane/writer")))
    assert effect_count(rig) == 0


@pytest.mark.parametrize("operation", ("pr", "release_pr"))
def test_diverged_draft_and_successive_release_prs_do_not_require_fast_forward(rig, operation):
    rig.git.non_ff = True
    first = request(operation)
    assert execute(rig, first)["status"] == "done"
    # The owner merges the first head, leaving the integration history diverged.
    rig.git.tips[first.ref] = OTHER
    rig.git.policies[OTHER] = rig.git.policies[OLD]
    rig.gh.pull = None
    second = replace(first, request_id="successive", expected_old=OTHER)
    assert execute(rig, second)["status"] == "done"
    assert not any(args[0] == "merge-base" for args, _ in rig.git.calls)


def test_create_only_first_push_has_independent_policy_base_and_retry(rig):
    ref = "refs/heads/lane/writer"
    item = request("push", ref=ref, expected_old=None, policy_base=OLD)
    assert execute(rig, item)["status"] == "done"
    assert rig.git.writes == [(ref, None, NEW)]
    assert execute(rig, item)["status"] == "done"
    assert len(rig.git.writes) == 1
    assert all(call[1] == OLD for call in rig.git.policy_calls)
    args, _ = next((args, kwargs) for args, kwargs in rig.git.calls if args[0] == "push")
    assert "--force-with-lease=" + ref + ":" in args


@pytest.mark.parametrize("other", (NEW, OTHER))
def test_create_only_race_at_push_never_overwrites_competing_creation(rig, other):
    ref = "refs/heads/lane/writer"
    item = request("push", ref=ref, expected_old=None, policy_base=OLD)
    rig.git.before_push = lambda: rig.git.tips.update({ref: other})
    refuses("ref_moved", lambda: execute(rig, item))
    assert rig.git.tips[ref] == other
    assert rig.git.writes == []
    assert rig.journal.read().rows[-1]["status"] != "done"


def test_absence_probe_failure_is_not_authoritative_absence(rig):
    item = request("push", ref="refs/heads/lane/writer", expected_old=None, policy_base=OLD)
    rig.git.probe_failure = True
    refuses("git_unavailable", lambda: execute(rig, item))
    assert rig.git.writes == []
    rig.git.probe_failure = False
    assert execute(rig, item)["status"] == "done"


@pytest.mark.parametrize("output", [b"", b"garbage\n", (" \t" + NEW + ":" + REF + "\tupdated\n*\t" + NEW + ":refs/tags/extra\tcreated\n").encode()], ids=("empty", "malformed", "extra-ref"))
def test_push_porcelain_must_prove_only_the_permitted_ref(rig, output):
    rig.git.output_override = output
    refuses("push_output_invalid", lambda: execute(rig, request()))
    assert rig.journal.read().rows[-1]["status"] == "unknown"
    count = len(rig.git.writes)
    assert execute(rig, request())["status"] == "unknown"
    assert len(rig.git.writes) == count


@pytest.mark.parametrize("key", ("remote.origin.push", "remote.origin.mirror", "remote.origin.pushurl", "push.pushoption", "push.futureexpansion"))
def test_configuration_cannot_add_refspecs_redirect_or_server_options(rig, key):
    rig.git.config_keys = [key]
    refuses("unsafe_git_config", lambda: execute(rig, request()))
    assert rig.git.writes == []


class LocalGitTransport:
    """A test-only local bare repository in place of the HTTPS network boundary."""

    def __init__(self, remote):
        self.remote = remote
        self.calls = []
        self.before_push = None
        self.failure = None

    def __call__(self, args, cwd, **kwargs):
        self.calls.append(list(args))
        if args[0] in ("push", "ls-remote"):
            if args[0] == "push" and self.before_push is not None:
                try:
                    self.before_push()
                except Exception as error:
                    self.failure = error
                    raise
            args = [str(self.remote) if value == REMOTE else value for value in args]
            env = dict(kwargs.get("_env", {}))
            index = int(env.get("GIT_CONFIG_COUNT", "0"))
            env.update({"GIT_ALLOW_PROTOCOL": "file", "GIT_CONFIG_COUNT": str(index + 1),
                        "GIT_CONFIG_KEY_" + str(index): "protocol.file.allow",
                        "GIT_CONFIG_VALUE_" + str(index): "always"})
            kwargs["_env"] = env
        return gitsafe.run(args, cwd, **kwargs)


@pytest.fixture
def local_git(tmp_path):
    if not team_gitops.descriptor_supported():
        pytest.skip("descriptor-relative journal needs POSIX no-follow operations")
    if not hg.git_ok():
        pytest.skip("needs git")
    repo = hg.make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    old = repo.commit("policy")
    repo.write("src/app.py", "changed = 1\n")
    middle = repo.commit("intermediate")
    repo.write("src/app.py", "changed = True\n")
    new = repo.commit("candidate")
    remote = tmp_path / "remote.git"
    repo.git("init", "--bare", "-q", str(remote))
    repo.git("push", "-q", str(remote), old + ":" + REF)
    # The concurrent remote writer needs candidate objects, but no extra live ref.
    repo.git("push", "-q", str(remote), new + ":refs/heads/object-seed")
    repo.git("--git-dir=" + str(remote), "update-ref", "-d", "refs/heads/object-seed", new)
    journal_root = tmp_path / "journal"
    journal_root.mkdir()
    journal = team_gitops.GitOpsJournal(journal_root)
    transport = LocalGitTransport(remote)
    service = publish.Publisher(repo.root, journal, remote=REMOTE, qualified=lambda item: True,
                                gh=FakeGh(), git_runner=transport, credential_reader=lambda: "fake-local-token")
    return SimpleNamespace(repo=repo, remote=remote, journal=journal, transport=transport, service=service, old=old, middle=middle, new=new)


def test_real_git_follow_tags_cannot_widen_branch_permit(local_git):
    control = local_git
    control.repo.git("config", "push.followTags", "true")
    control.repo.git("tag", "-a", "unpublished", "-m", "must stay local", control.new)
    item = request(commit=control.new, expected_old=control.old)
    assert control.service.push(control.service.gate(item))["status"] == "done"
    refs = control.repo.git("--git-dir=" + str(control.remote), "for-each-ref", "--format=%(refname)").splitlines()
    assert refs == [REF]
    args = next(args for args in control.transport.calls if args[0] == "push")
    assert "--no-follow-tags" in args
    assert "--recurse-submodules=no" in args


@pytest.mark.parametrize("advance", ("ancestor", "same-commit"))
def test_real_git_lease_rejects_ancestor_advance_after_final_check(local_git, advance):
    control = local_git
    def move():
        target = control.middle if advance == "ancestor" else control.new
        control.repo.git("--git-dir=" + str(control.remote), "update-ref", REF, target, control.old)
    control.transport.before_push = move
    item = request(commit=control.new, expected_old=control.old)
    try:
        refuses("ref_moved", lambda: control.service.push(control.service.gate(item)))
    finally:
        assert control.transport.failure is None, (str(control.transport.failure), getattr(control.transport.failure, "stderr", None))
    assert control.journal.read().rows[-1]["status"] != "done"


@pytest.mark.parametrize("kind", ("lane", "immutable"))
def test_concurrent_create_permits_have_one_winner_after_both_final_checks(rig, kind):
    ref = "refs/heads/lane/writer" if kind == "lane" else HEAD
    rig.git.tips.pop(ref, None)
    rig.git.policies[OTHER] = {"*": "none"}
    first = request(ref=ref, expected_old=None, policy_base=OLD)
    second = replace(first, request_id="second-creator", commit=OTHER if kind == "lane" else NEW)
    barrier = Barrier(2, timeout=5)
    rig.git.before_push = lambda: barrier.wait()
    def create(item):
        try:
            return execute(rig, item)["status"]
        except publish.PublishError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, (first, second)))
    assert sorted(results) == ["done", "ref_moved"]
    assert len(rig.git.writes) == 1
    assert sorted(row["status"] for row in rig.journal.read().rows if row["kind"] == "result") == ["done", "unknown"]


@pytest.mark.parametrize("code,raw", [(0, b""), (2, b"garbage"), (128, b""), (2, bytearray())], ids=("empty-success", "malformed-absence", "transport-error", "wrong-type"))
def test_absence_requires_exact_authoritative_git_response(rig, code, raw):
    def probe(args, root, **kwargs):
        if args[0] == "ls-remote":
            return subprocess.CompletedProcess(args, code, raw, b"token=SECRET")
        return rig.git.run(args, root, **kwargs)
    service = publisher(rig, git_runner=probe)
    item = request(ref="refs/heads/lane/writer", expected_old=None, policy_base=OLD)
    refuses("git_unavailable", lambda: service.gate(item))
    assert rig.git.writes == []


def test_missing_configuration_output_has_fixed_refusal(rig):
    def missing(args, root, **kwargs):
        if args[0] == "config":
            return SimpleNamespace(returncode=0)
        return rig.git.run(args, root, **kwargs)
    service = publisher(rig, git_runner=missing)
    refuses("git_unavailable", lambda: service.gate(request()))


@pytest.mark.parametrize("namespace", ("lane", "immutable"))
def test_real_git_create_only_first_push_and_matching_creation_race(local_git, namespace):
    control = local_git
    ref = "refs/heads/lane/writer" if namespace == "lane" else "refs/heads/aegis/publish/" + control.new
    item = request(ref=ref, commit=control.new, expected_old=None, policy_base=control.old)
    assert control.service.push(control.service.gate(item))["status"] == "done"
    assert control.repo.git("--git-dir=" + str(control.remote), "rev-parse", ref) == control.new
    # A distinct intent expecting absence cannot claim the already existing ref.
    refuses("ref_moved", lambda: control.service.push(control.service.gate(replace(item, request_id="another-creator"))))


def test_real_git_expected_absent_lease_does_not_accept_up_to_date_receipt(local_git):
    control = local_git
    ref = "refs/heads/lane/writer"
    def create():
        control.repo.git("--git-dir=" + str(control.remote), "update-ref", ref, control.new, "0" * 40)
    control.transport.before_push = create
    item = request(ref=ref, commit=control.new, expected_old=None, policy_base=control.old)
    refuses("ref_moved", lambda: control.service.push(control.service.gate(item)))
    assert control.journal.read().rows[-1]["status"] != "done"


def test_server_transaction_rejection_with_moved_ref_has_fixed_cas_code(rig):
    rig.git.before_push = lambda: rig.git.tips.update({REF: OTHER})
    rig.git.output_override = ("!\t" + NEW + ":" + REF + "\t[remote rejected] (failed to update ref)\n").encode()
    refuses("ref_moved", lambda: execute(rig, request()))
    assert rig.git.writes == []
    assert rig.journal.read().rows[-1]["status"] == "unknown"


def test_real_immutable_source_can_be_provisioned_then_used_for_exact_pr(local_git):
    control = local_git
    ref = "refs/heads/aegis/publish/" + control.new
    gh = FakeGh(SimpleNamespace(tips={ref: control.new}))
    service = publish.Publisher(control.repo.root, control.journal, remote=REMOTE, qualified=lambda item: True,
                                gh=gh, git_runner=control.transport, credential_reader=lambda: "fake-local-token")
    pin = request(request_id="pin", ref=ref, commit=control.new, expected_old=None, policy_base=control.old)
    assert service.push(service.gate(pin))["status"] == "done"
    def compete():
        move = request(request_id="pin-move", ref=ref, commit=control.middle, expected_old=control.new)
        refuses("immutable_source", lambda: service.push(service.gate(move)))
    gh.before_post = compete
    item = request("pr", request_id="pr", head_ref=ref, commit=control.new, expected_old=control.old)
    assert service.pr(service.gate(item))["status"] == "done"
    assert gh.pull["head"]["sha"] == control.new
    assert control.repo.git("--git-dir=" + str(control.remote), "rev-parse", ref) == control.new


def credentialed_count(rig):
    return sum(args[0] in ("ls-remote", "push") for args, _ in rig.git.calls) + len(rig.gh.calls)


@pytest.mark.parametrize("key", ("url", "pushurl", "proxy"))
def test_url_named_remote_subsection_is_refused_before_credentials(rig, key):
    rig.git.config_entries["remote." + REMOTE + "." + key] = "https://github.com/attacker/repo.git"
    refuses("unsafe_git_config", lambda: execute(rig, request()))
    assert credentialed_count(rig) == 0
    assert rig.git.writes == []


def test_replay_checks_redirect_before_any_credentialed_observation(rig):
    rig.journal.fail_results = True
    item = request()
    refuses("journal_io", lambda: execute(rig, item))
    rig.journal.fail_results = False
    rig.git.config_entries["url.https://github.com/attacker/repo.git.insteadof"] = REMOTE
    rig.git.calls.clear()
    rig.gh.calls.clear()
    refuses("unsafe_git_config", lambda: execute(rig, item))
    assert credentialed_count(rig) == 0
    assert [row["kind"] for row in rig.journal.read().rows] == ["intent"]
    rig.git.config_entries.clear()
    assert execute(rig, item)["status"] == "done"
    assert len(rig.git.writes) == 1


@pytest.mark.parametrize("operation", ("pr", "release_pr"))
def test_exact_pr_observation_after_intent_cannot_skip_redirect_guard(rig, operation):
    assert execute(rig, request(operation, request_id="existing"))["status"] == "done"
    def redirect(fields):
        rig.git.config_entries["url.https://github.com/attacker/repo.git.insteadof"] = REMOTE
        rig.git.calls.clear()
        rig.gh.calls.clear()
    rig.journal.after_intent = redirect
    refuses("unsafe_git_config", lambda: execute(rig, request(operation)))
    assert credentialed_count(rig) == 0
    rows = [row for row in rig.journal.read().rows if row["request_id"] == "request-1"]
    assert rows[-1]["status"] == "unknown"


class SafetyRacePublisher(publish.Publisher):
    """Install a redirect exactly between the final check and effect entry."""

    def __init__(self, *args, install_redirect, **kwargs):
        self.install_redirect = install_redirect
        super().__init__(*args, **kwargs)

    def _effect(self, permit):
        self.install_redirect()
        return super()._effect(permit)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_effect_entry_cannot_skip_transport_guard(rig, operation):
    def redirect():
        rig.git.config_entries["remote." + REMOTE + ".url"] = "https://github.com/attacker/repo.git"
        rig.git.calls.clear()
        rig.gh.calls.clear()
    gated = SafetyRacePublisher(rig.root, rig.journal, remote=REMOTE, qualified=lambda item: True, gh=rig.gh,
                    git_runner=rig.git.run, commit_resolver=rig.git.resolve_commit, policy_resolver=rig.git.resolve_policy,
                    credential_reader=lambda: rig.credentials["token"], install_redirect=redirect)
    item = request(operation)
    refuses("unsafe_git_config", lambda: primitives(gated)[operation](gated.gate(item)))
    assert credentialed_count(rig) == 0
    assert rig.git.writes == []
    assert rig.journal.read().rows[-1]["status"] == "unknown"


@pytest.mark.parametrize("method", ("tip", "get"))
def test_direct_read_entry_always_checks_transport_safety(rig, method):
    rig.git.config_entries["remote." + REMOTE + ".proxy"] = "https://attacker.invalid"
    call = {"tip": lambda: rig.service._tip(REF), "get": lambda: rig.service._get("repos/owner/project")}[method]
    refuses("unsafe_git_config", call)
    assert credentialed_count(rig) == 0


@pytest.mark.parametrize("key", ("include.path", "includeif.gitdir:/.path", "protocol.https.allow", "http.proxy", "credential.helper", "core.sshcommand", "new.transport.option"))
def test_transport_allowlist_refuses_includes_and_unknown_configuration(rig, key):
    rig.git.config_entries[key] = "token=SECRET"
    refuses("unsafe_git_config", lambda: execute(rig, request()))
    assert credentialed_count(rig) == 0


def test_exact_expected_remote_configuration_is_allowed(rig):
    rig.git.config_entries.update({"remote.origin.url": REMOTE, "remote.origin.fetch": "+refs/heads/*:refs/remotes/origin/*"})
    assert execute(rig, request())["status"] == "done"
    assert len(rig.git.writes) == 1


@pytest.mark.parametrize("key", ("url", "pushurl", "proxy"))
def test_real_git_remote_url_subsection_is_blocked_before_network_adapter(local_git, key):
    control = local_git
    control.repo.git("config", "remote." + REMOTE + "." + key, "https://github.com/attacker/repo.git")
    item = request(commit=control.new, expected_old=control.old)
    refuses("unsafe_git_config", lambda: control.service.gate(item))
    assert not any(args[0] in ("ls-remote", "push") for args in control.transport.calls)


def test_effect_requires_journal_arming_not_merely_a_checked_permit(rig):
    permit = rig.service.gate(request())
    refuses("invalid_permit", lambda: rig.service._effect(permit))
    with rig.service._active_permit(permit, "push"):
        refuses("invalid_permit", lambda: rig.service._effect(permit))
    assert rig.git.writes == []
    assert rig.journal.read().rows == []
    assert execute(rig, request())["status"] == "done"


def test_noop_push_still_records_done_without_pushing(rig):
    item = request(commit=OLD)
    assert execute(rig, item)["status"] == "done"
    assert effect_count(rig) == 0
    assert rig.journal.read().rows[-1]["status"] == "done"


def test_real_git_malformed_include_is_refused_before_network(local_git):
    control = local_git
    include = control.repo.root / "model-editable.cfg"
    include.write_text("[malformed config", encoding="utf-8")
    control.repo.git("config", "include.path", str(include))
    item = request(commit=control.new, expected_old=control.old)
    refuses("unsafe_git_config", lambda: control.service.gate(item))
    assert not any(args[0] in ("ls-remote", "push") for args in control.transport.calls)


def test_real_git_worktree_redirect_is_refused_before_network(local_git):
    control = local_git
    control.repo.git("config", "extensions.worktreeConfig", "true")
    path = control.repo.root / ".git" / "config.worktree"
    path.write_text('[remote "' + REMOTE + '"]\nurl = https://github.com/attacker/repo.git\n', encoding="utf-8")
    item = request(commit=control.new, expected_old=control.old)
    refuses("unsafe_git_config", lambda: control.service.gate(item))
    assert not any(args[0] in ("ls-remote", "push") for args in control.transport.calls)


def test_git_header_url_scope_does_not_match_another_repository(rig, tmp_path):
    if not hg.git_ok():
        pytest.skip("needs git")
    execute(rig, request())
    env = next(kwargs["_env"] for args, kwargs in rig.git.calls if args[0] == "push")
    def header(url):
        return subprocess.run(["git", "config", "--get-urlmatch", "http.extraHeader", url], cwd=tmp_path,
                              env={**os.environ, **env}, capture_output=True, timeout=10)
    assert header(REMOTE).returncode == 0
    other = header("https://github.com/attacker/repo.git")
    assert other.returncode == 1 and other.stdout == b""


def test_root_size_is_refused_before_entering_custody(tmp_path):
    root = "/" + "x" * 16384
    refuses("unsafe_journal", lambda: publish.Publisher(root, team_gitops.GitOpsJournal(tmp_path), remote=REMOTE,
            qualified=lambda item: True, gh=FakeGh()))


def test_ref_reaching_candidate_during_intent_is_refused_without_effect(rig):
    rig.journal.after_intent = lambda fields: rig.git.tips.update({REF: NEW})
    item = request()
    refuses("ref_moved", lambda: execute(rig, item))
    assert effect_count(rig) == 0
    assert rig.git.writes == []
    assert rig.journal.read().rows[-1]["status"] == "unknown"
    assert execute(rig, item)["status"] == "unknown"
    assert effect_count(rig) == 0


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("change,code", [("qualification", "not_qualified"), ("policy", "policy_refused"), ("ref", "ref_moved")])
def test_satisfied_operation_rechecks_authority_after_intent(rig, operation, change, code):
    item = request(operation, **({"commit": OLD} if operation == "push" else {}))
    if operation != "push":
        assert execute(rig, replace(item, request_id="existing"))["status"] == "done"
    effects = effect_count(rig)
    def revoke(fields):
        if change == "qualification":
            rig.evidence["allowed"] = False
        elif change == "policy":
            rig.git.policies[OLD] = {"*": "none" if operation == "release_pr" else "review"}
        else:
            rig.git.tips[item.ref] = OTHER
    rig.journal.after_intent = revoke
    refuses(code, lambda: execute(rig, item))
    assert effect_count(rig) == effects
    rows = [row for row in rig.journal.read().rows if row["request_id"] == item.request_id]
    assert [row["kind"] for row in rows] == ["intent", "result"]
    assert rows[-1]["status"] == "unknown"
    assert execute(rig, item)["status"] == "unknown"
    assert effect_count(rig) == effects


def test_cas_runs_when_ref_reaches_candidate_after_post_intent_check(rig):
    checks = []
    def forge(args, **kwargs):
        result = rig.gh(args, **kwargs)
        if args[-1] == "repos/owner/project":
            checks.append(True)
            if len(checks) == 3:
                rig.git.tips[REF] = NEW
        return result
    rig.service = publisher(rig, gh=forge)
    item = request()
    refuses("ref_moved", lambda: execute(rig, item))
    assert effect_count(rig) == 1
    assert rig.git.writes == []
    assert rig.journal.read().rows[-1]["status"] == "unknown"
    assert execute(rig, item)["status"] == "unknown"
    assert effect_count(rig) == 1


@pytest.mark.parametrize("updated", (True, False), ids=("lost-reply", "before-update"))
@pytest.mark.parametrize("output", (b"", b"To remote\nDone\n"), ids=("empty", "no-status"))
def test_empty_nonzero_push_reply_is_resolved_by_observation(rig, updated, output):
    rig.git.reject_push = not updated
    def transport(args, cwd, **kwargs):
        result = rig.git.run(args, cwd, **kwargs)
        if args[0] == "push":
            return subprocess.CompletedProcess(args, 128, output, b"token=SECRET")
        return result
    rig.service = publisher(rig, git_runner=transport)
    item = request()
    if updated:
        assert execute(rig, item) == {"status": "done", "code": None}
    else:
        refuses("git_unavailable", lambda: execute(rig, item))
    status = "done" if updated else "not_applied"
    assert rig.journal.read().rows[-1]["status"] == status
    assert len(rig.git.writes) == int(updated)
    assert effect_count(rig) == 1
    assert execute(rig, item)["status"] == status
    assert effect_count(rig) == 1


@pytest.mark.parametrize("operation,code", [("push", "identity_unavailable"), ("push", "git_unavailable"),
                         ("pr", "gh_unavailable"), ("pr", "gh_malformed"), ("cancel", "run_refused")])
def test_pending_replay_preserves_observation_refusal_and_can_reconcile(rig, operation, code):
    item = request(operation)
    rig.journal.fail_results = True
    refuses("journal_io", lambda: execute(rig, item))
    rig.journal.fail_results = False
    assert effect_count(rig) == 1
    if code == "identity_unavailable":
        rig.credentials["token"] = None
    elif code == "git_unavailable":
        rig.git.probe_failure = True
    elif code in ("gh_unavailable", "gh_malformed"):
        rig.gh.failure = "unavailable" if code == "gh_unavailable" else "malformed"
    else:
        rig.gh.run_state["event"] = "pull_request"
    refuses(code, lambda: execute(rig, item))
    assert [row["kind"] for row in rig.journal.read().rows] == ["intent"]
    assert effect_count(rig) == 1
    rig.credentials["token"] = "test-publisher-credential"
    rig.git.probe_failure = False
    rig.gh.failure = None
    rig.gh.run_state["event"] = "push"
    assert execute(rig, item)["status"] == "done"
    assert effect_count(rig) == 1


def test_real_git_maximum_policy_config_can_gate_and_publish(local_git):
    control = local_git
    config = json.dumps({"approvals": {"*": "none"}})
    config += " " * (approval_policy.MAX_CONFIG_BYTES - len(config.encode("utf-8")))
    assert len(config.encode("utf-8")) == approval_policy.MAX_CONFIG_BYTES
    control.repo.write(".aegis/config.json", config)
    commit = control.repo.commit("maximum policy config")
    item = request(commit=commit, expected_old=control.old)
    assert control.service.push(control.service.gate(item))["status"] == "done"
    assert control.repo.git("--git-dir=" + str(control.remote), "rev-parse", REF) == commit
    assert control.journal.read().rows[-1]["status"] == "done"
    assert control.service.push(control.service.gate(item))["status"] == "done"
    assert sum(args[0] == "push" for args in control.transport.calls) == 1
