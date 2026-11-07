"""Real Git repositories and ephemeral SSH owner keys for manager surface tests."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


def git(root, *args):
    return subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                           "-c", "commit.gpgsign=false", *args], cwd=root, check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()


def prepare(tmp_path):
    from aegis_core.manager import initialize
    if not shutil.which("ssh-keygen"):
        pytest.skip("SSH approval verification requires ssh-keygen")
    member = tmp_path / "member"
    member.mkdir()
    git(member, "init", "-q")
    (member / "source.txt").write_text("baseline\n")
    git(member, "add", "source.txt")
    git(member, "commit", "-qm", "baseline")
    control = tmp_path / "control"
    control.mkdir()
    git(control, "init", "-q")
    payload = control / "manager-policy"
    payload.mkdir()
    policy = {"schema": "aegis.manager-policy/v1", "workspace_id": "test-manager",
              "rules": [{"id": "manager-handoff", "actions": ["handoff"], "match": {},
                         "text": "Review evidence before acknowledging a management handoff."}]}
    membership = {"schema": "aegis.manager-membership/v1", "workspace_id": "test-manager",
                  "repositories": [{"id": "aegis", "common_dir": str(member / ".git"),
                                    "worktrees": [{"id": "main", "path": str(member)}]}]}
    (payload / "policy.json").write_text(json.dumps(policy))
    (payload / "membership.json").write_text(json.dumps(membership))
    git(control, "add", "manager-policy")
    git(control, "commit", "-qm", "draft policy")
    key = tmp_path / "owner-key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                   check=True, capture_output=True, timeout=10)
    signers = tmp_path / "trusted-signers"
    signers.write_text("owner " + key.with_suffix(".pub").read_text())
    signers.chmod(0o600)
    config = tmp_path / "manager-config.json"
    state = tmp_path / "audit"
    initialize(config, workspace_id="test-manager", control_root=control, store_root=state,
               trusted_signers=signers)
    return {"member": member, "control": control, "revision": git(control, "rev-parse", "HEAD"),
            "config": config, "store": state, "key": key, "signers": signers,
            "context": {"member_id": "aegis", "worktree_id": "main", "summary": "handoff review"}}


def approve(env, candidate):
    from aegis_core.manager_policy import digest
    statement = candidate["approval_statement"]
    message = "Owner approval\n\nAegis-Manager-Approve: " + digest(statement)
    git(env["control"], "-c", "gpg.format=ssh", "-c", "user.signingkey=" + str(env["key"]),
        "commit", "--allow-empty", "--no-verify", "-S", "-qm", message)
    return {"statement": statement, "commit": git(env["control"], "rev-parse", "HEAD")}


def active(env):
    from aegis_core.manager import ManagerService
    service = ManagerService(env["config"], provenance={"transport": "test", "native_identity": None})
    candidate = service.candidate(env["revision"])
    service.activate(env["revision"], expected=None, approval=approve(env, candidate))
    return service
