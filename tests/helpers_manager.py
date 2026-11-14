"""Real Git repositories and ephemeral SSH owner keys for manager surface tests."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

GIT_PLACEMENT_NAMES = (".git", ".git.", ".git ", ".git::$INDEX_ALLOCATION", ".GIT",
                       ".git.::$INDEX_ALLOCATION", ".git ::$DATA", ".git .:x")


@pytest.fixture(params=["repo", "alias"])
def missing_traversal_path(tmp_path_factory, request):
    from tests.conftest import symlink_or_skip

    root = tmp_path_factory.mktemp("missing-traversal")
    repo = root / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    if request.param == "alias":
        symlink_or_skip(repo, root / "alias", target_is_directory=True)
    yield root / "missing" / ".." / request.param / "audit"
    assert not (root / "missing").exists()
    assert not (repo / "audit").exists()
    assert (repo / ".git").is_dir()


@pytest.fixture
def unsearchable_manager_alias(tmp_path_factory):
    if os.name != "posix" or os.geteuid() == 0:
        pytest.skip("requires non-root POSIX search permissions")
    from tests.conftest import symlink_or_skip

    root = tmp_path_factory.mktemp("unsearchable-placement")
    target = root / "repo" / "sub"
    target.mkdir(parents=True)
    (target.parent / ".git").mkdir()
    blocked = root / "blocked"
    blocked.mkdir()
    alias = blocked / "alias"
    symlink_or_skip(target, alias, target_is_directory=True)
    blocked.chmod(0)
    try:
        try:
            alias.stat()
        except PermissionError:
            pass
        else:
            pytest.skip("chmod does not remove directory search permission")
        yield alias
    finally:
        blocked.chmod(0o700)


@pytest.fixture
def manager_root():
    """External manager files must not rely on pytest's Git discovery ceiling."""
    from aegis_core.manager_store import in_git_worktree
    from aegis_core.manager_policy import ManagerError

    candidates = [tempfile.gettempdir()]
    candidates.extend(os.environ[name] for name in ("TMPDIR", "TEMP", "TMP") if os.environ.get(name))
    if os.name == "nt":
        if os.environ.get("SystemRoot"):
            candidates.append(str(Path(os.environ["SystemRoot"]) / "Temp"))
    else:
        candidates.extend(("/tmp", "/var/tmp", "/usr/tmp"))
    for candidate in dict.fromkeys(candidates):
        try:
            parent = Path(candidate).resolve()
            if in_git_worktree(parent):
                continue
            temporary = tempfile.TemporaryDirectory(prefix="aegis-manager-", dir=parent)
        except (OSError, RuntimeError, ManagerError):
            continue
        try:
            try:
                root = Path(temporary.name).resolve()
                refused = in_git_worktree(root)
            except (OSError, RuntimeError, ManagerError):
                continue
            if refused:
                continue
            yield root
            return
        finally:
            temporary.cleanup()
    pytest.skip("no writable directory outside a Git worktree: audit-store placement correctly refuses")


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
