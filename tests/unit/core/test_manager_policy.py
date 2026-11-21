"""Manager policy intake through strict public parsers and pinned Git blobs."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess

import pytest

from aegis_core import manager_policy as policy
from tests.conftest import symlink_or_skip


def git(root, *args, stdin=None):
    return subprocess.run(
        ["git", "-c", "user.email=manager@example.invalid", "-c", "user.name=Manager", *args],
        cwd=root, check=True, capture_output=True, input=stdin, timeout=10,
    ).stdout.decode().strip()


def repository(root):
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "README").write_text("fixture\n", encoding="utf-8")
    git(root, "add", "README")
    git(root, "commit", "-qm", "initial")
    return root


def document():
    return {"schema": "aegis.manager-policy/v1", "workspace_id": "aegis-workspace", "rules": [
        {"id": "handoff-evidence", "actions": ["handoff", "evidence_review"],
         "match": {"role": "manager", "risk": "high"},
         "text": "Review source-bound evidence before acknowledging a management handoff."},
    ]}


def members(root, pilot=None):
    worktrees = [{"id": "main", "path": str(root)}]
    if pilot is not None:
        worktrees.append({"id": "pilot", "path": str(pilot)})
    return {"schema": "aegis.manager-membership/v1", "workspace_id": "aegis-workspace",
            "repositories": [{"id": "aegis", "common_dir": str(root / ".git"), "worktrees": worktrees}]}


def commit_payload(control, member, *, raw_policy=None, raw_membership=None):
    target = control / "manager-policy"
    target.mkdir(exist_ok=True)
    (target / "policy.json").write_bytes(raw_policy if raw_policy is not None else policy.canonical(document()))
    (target / "membership.json").write_bytes(raw_membership if raw_membership is not None else policy.canonical(members(member)))
    git(control, "add", "manager-policy")
    git(control, "commit", "-qm", "manager payload")
    return git(control, "rev-parse", "HEAD")


@pytest.fixture
def repos(tmp_path):
    return repository(tmp_path / "control"), repository(tmp_path / "aegis")


def test_canonical_is_sorted_ascii_and_digest_matches_bytes():
    value = {"z": "é", "a": [True, None, 3]}
    encoded = policy.canonical(value)
    assert encoded == b'{"a":[true,null,3],"z":"\\u00e9"}'
    assert policy.digest(value) == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "not a string key"}, {"x": (1, 2)}])
def test_canonical_refuses_non_json_values(value):
    with pytest.raises(policy.ManagerError, match="^invalid_json$"):
        policy.canonical(value)


def test_policy_computes_revision_without_mutating_caller():
    original = document()
    before = copy.deepcopy(original)
    loaded = policy.parse_policy(original)
    assert loaded["rules"][0]["revision"] == policy.digest(original["rules"][0])
    assert original == before
    loaded["rules"][0]["match"]["role"] = "reviewer"
    assert original == before


@pytest.mark.parametrize("field,value", [
    ("target_paths", ["aegis_core/**"]), ("predicate", {"kind": "forbid_ast"}),
    ("command", ["pytest"]), ("inherits", "child-policy"), ("approval", True),
])
def test_repository_fields_are_rejected(field, value):
    candidate = document()
    candidate["rules"][0][field] = value
    with pytest.raises(policy.ManagerError, match="^invalid_policy$"):
        policy.parse_policy(candidate)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(scope="repository"),
    lambda d: d.update(schema="aegis.manager-policy/v2"),
    lambda d: d.update(workspace_id="../escape"),
    lambda d: d.update(rules=[]),
    lambda d: d["rules"].append(copy.deepcopy(d["rules"][0])),
    lambda d: d["rules"][0].update(actions=["edit_code"]),
    lambda d: d["rules"][0].update(actions=["handoff", "handoff"]),
    lambda d: d["rules"][0].update(match={"file": "src/app.py"}),
    lambda d: d["rules"][0].update(match={"role": {"exec": "evil"}}),
    lambda d: d["rules"][0].update(text=""),
    lambda d: d["rules"][0].update(text="x" * 4097),
])
def test_malformed_policy_is_refused(mutation):
    candidate = document()
    mutation(candidate)
    with pytest.raises(policy.ManagerError, match="^invalid_policy$"):
        policy.parse_policy(candidate)


def test_real_main_and_linked_pilot_share_one_approved_repository(repos, tmp_path):
    _, member = repos
    pilot = tmp_path / "pilot"
    git(member, "worktree", "add", "-qb", "pilot", str(pilot))
    assert policy.parse_membership(members(member, pilot)) == members(member, pilot)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(approved=True),
    lambda d: d["repositories"][0].update(id="stormheir"),
    lambda d: d["repositories"].append(copy.deepcopy(d["repositories"][0])),
    lambda d: d["repositories"][0]["worktrees"].append(copy.deepcopy(d["repositories"][0]["worktrees"][0])),
    lambda d: d["repositories"][0].update(command="git status"),
    lambda d: d["repositories"][0]["worktrees"][0].update(id="../escape"),
])
def test_unauthorized_or_ambiguous_membership_is_rejected(repos, mutation):
    candidate = members(repos[1])
    mutation(candidate)
    with pytest.raises(policy.ManagerError, match="^invalid_membership$"):
        policy.parse_membership(candidate)


def test_foreign_repository_cannot_impersonate_an_approved_worktree(repos):
    control, member = repos
    candidate = members(member)
    candidate["repositories"][0]["worktrees"][0]["path"] = str(control)
    with pytest.raises(policy.ManagerError, match="^membership_identity_mismatch$"):
        policy.parse_membership(candidate)


def test_subdirectory_is_not_a_worktree_root(repos):
    _, member = repos
    child = member / "subdir"
    child.mkdir()
    candidate = members(member)
    candidate["repositories"][0]["worktrees"][0]["path"] = str(child)
    with pytest.raises(policy.ManagerError, match="^membership_identity_mismatch$"):
        policy.parse_membership(candidate)


def test_symlinked_member_ancestor_is_refused(repos, tmp_path):
    _, member = repos
    alias = tmp_path / "alias"
    symlink_or_skip(member.parent, alias, target_is_directory=True)
    candidate = members(member)
    candidate["repositories"][0]["worktrees"][0]["path"] = str(alias / member.name)
    with pytest.raises(policy.ManagerError, match="^unsafe_path$"):
        policy.parse_membership(candidate)


def test_candidate_uses_pinned_git_bytes_and_ignores_dirty_payload(repos):
    control, member = repos
    raw = json.dumps(document(), indent=2).encode() + b"\n"
    revision = commit_payload(control, member, raw_policy=raw)
    (control / "manager-policy" / "policy.json").write_text("forged dirty policy", encoding="utf-8")
    candidate = policy.read_candidate(control, revision)
    assert candidate["workspace_id"] == "aegis-workspace"
    assert candidate["control_commit"] == revision
    assert candidate["control_root"] == str(control)
    assert candidate["policy_digest"] == hashlib.sha256(raw).hexdigest()
    assert candidate["membership_digest"] == hashlib.sha256(policy.canonical(members(member))).hexdigest()
    assert candidate["policy"]["rules"][0]["revision"] == policy.digest(document()["rules"][0])


@pytest.mark.parametrize("revision", ["HEAD", "main", "a" * 8, "A" * 40, "a" * 40])
def test_candidate_requires_existing_full_commit(repos, revision):
    with pytest.raises(policy.ManagerError, match="^invalid_revision$"):
        policy.read_candidate(repos[0], revision)


def test_duplicate_json_keys_are_rejected(repos):
    control, member = repos
    revision = commit_payload(control, member, raw_policy=b'{"schema":"x","schema":"y"}')
    with pytest.raises(policy.ManagerError, match="^invalid_payload$"):
        policy.read_candidate(control, revision)


def test_oversize_payload_is_refused_before_loading(repos):
    control, member = repos
    revision = commit_payload(control, member, raw_policy=b" " * (256 * 1024 + 1))
    with pytest.raises(policy.ManagerError, match="^payload_limit$"):
        policy.read_candidate(control, revision)


@pytest.mark.parametrize("mode", ["100755", "120000", "160000"])
def test_nonregular_or_executable_git_payload_is_rejected(repos, mode):
    control, member = repos
    commit_payload(control, member)
    oid = git(control, "rev-parse", "HEAD") if mode == "160000" else git(control, "hash-object", "-w", "--stdin", stdin=b"README")
    git(control, "update-index", "--add", "--cacheinfo", mode + "," + oid + ",manager-policy/policy.json")
    git(control, "commit", "-qm", "unsafe payload mode")
    with pytest.raises(policy.ManagerError, match="^(unsafe_payload|missing_payload)$"):
        policy.read_candidate(control, git(control, "rev-parse", "HEAD"))


def test_mismatched_workspace_payloads_are_refused(repos):
    control, member = repos
    membership = members(member)
    membership["workspace_id"] = "other-workspace"
    revision = commit_payload(control, member, raw_membership=policy.canonical(membership))
    with pytest.raises(policy.ManagerError, match="^workspace_mismatch$"):
        policy.read_candidate(control, revision)


def test_control_repository_cannot_be_implementation_member(repos):
    control, _ = repos
    revision = commit_payload(control, control)
    with pytest.raises(policy.ManagerError, match="^control_member_overlap$"):
        policy.read_candidate(control, revision)


def test_control_root_symlink_ancestor_is_refused(repos, tmp_path):
    control, member = repos
    revision = commit_payload(control, member)
    alias = tmp_path / "alias"
    symlink_or_skip(control.parent, alias, target_is_directory=True)
    with pytest.raises(policy.ManagerError, match="^unsafe_path$"):
        policy.read_candidate(alias / control.name, revision)


def test_missing_payload_is_explicit(repos):
    control, _ = repos
    with pytest.raises(policy.ManagerError, match="^missing_payload$"):
        policy.read_candidate(control, git(control, "rev-parse", "HEAD"))


@pytest.mark.parametrize("value", [None, [], "policy", True])
def test_nonobject_policy_is_refused(value):
    with pytest.raises(policy.ManagerError, match="^invalid_policy$"):
        policy.parse_policy(value)


@pytest.mark.parametrize("raw", [b"{", bytes([255]), b'{"value":NaN}', b'{"value":1e999}'])
def test_malformed_json_payload_is_refused(repos, raw):
    control, member = repos
    revision = commit_payload(control, member, raw_policy=raw)
    with pytest.raises(policy.ManagerError, match="^invalid_payload$"):
        policy.read_candidate(control, revision)


def test_git_timeout_is_explicit_and_does_not_load_checkout(repos, monkeypatch):
    from aegis_core import gitsafe

    control, _ = repos

    def unavailable(*args, **kwargs):
        raise gitsafe.GitError("git timed out")

    monkeypatch.setattr(gitsafe, "toplevel", unavailable)
    with pytest.raises(policy.ManagerError, match="^git_unavailable$"):
        policy.read_candidate(control, "a" * 40)


@pytest.mark.parametrize("value", [None, {}, 12, object()])
def test_control_root_wrong_type_is_refused(value):
    with pytest.raises(policy.ManagerError, match="^unsafe_path$"):
        policy.read_candidate(value, "a" * 40)


def test_replay_parse_preserves_missing_membership_without_granting_authority(repos):
    _, member = repos
    membership = members(member)
    member.rename(member.with_name("member-moved"))
    with pytest.raises(policy.ManagerError, match="^unsafe_path$"):
        policy.parse_membership(membership)
    assert policy.parse_membership(membership, verify_identity=False) == membership


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(approved=True),
    lambda d: d["repositories"][0].update(id="stormheir"),
    lambda d: d["repositories"][0].update(common_dir="relative/.git"),
    lambda d: d["repositories"][0].update(common_dir="/directory/../escape"),
    lambda d: d["repositories"][0]["worktrees"][0].update(path="relative/worktree"),
    lambda d: d["repositories"][0]["worktrees"][0].update(path="/directory//child"),
    lambda d: d["repositories"][0]["worktrees"].append(copy.deepcopy(d["repositories"][0]["worktrees"][0])),
])
def test_replay_parse_still_refuses_malformed_membership(repos, mutation):
    candidate = members(repos[1])
    mutation(candidate)
    with pytest.raises(policy.ManagerError, match="^(invalid_membership|unsafe_path)$"):
        policy.parse_membership(candidate, verify_identity=False)


def test_replay_candidate_verifies_pinned_payload_when_member_is_missing(repos):
    control, member = repos
    revision = commit_payload(control, member)
    before = policy.read_candidate(control, revision)
    member.rename(member.with_name("member-moved"))
    with pytest.raises(policy.ManagerError, match="^unsafe_path$"):
        policy.read_candidate(control, revision)
    assert policy.read_candidate(control, revision, verify_membership=False) == before


def test_replay_candidate_still_refuses_symlinked_control_root(repos, tmp_path):
    control, member = repos
    revision = commit_payload(control, member)
    alias = tmp_path / "alias"
    symlink_or_skip(control.parent, alias, target_is_directory=True)
    with pytest.raises(policy.ManagerError, match="^unsafe_path$"):
        policy.read_candidate(alias / control.name, revision, verify_membership=False)
