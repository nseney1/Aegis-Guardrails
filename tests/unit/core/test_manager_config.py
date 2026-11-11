"""Owner approvals share the single-authority message contract."""
import hashlib
import json
import errno
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core import manager_config
from aegis_core.manager_policy import ManagerError, digest
from tests import helpers_humangate as hg
from tests.helpers_manager import GIT_PLACEMENT_NAMES, git, manager_root, missing_traversal_path, unsearchable_manager_alias
from tests.conftest import symlink_or_skip


@pytest.mark.parametrize("operation", ["public_file", "load_config", "initialize"])
def test_config_refuses_missing_parent_traversal(missing_traversal_path, operation):
    with pytest.raises(ManagerError, match="^unsafe_config$"):
        if operation == "initialize":
            manager_config.initialize(missing_traversal_path, workspace_id="placement-test",
                                      control_root=missing_traversal_path, store_root=missing_traversal_path,
                                      trusted_signers=missing_traversal_path)
        else:
            getattr(manager_config, operation)(missing_traversal_path)


@pytest.mark.parametrize("location", ["config", "signer"])
@pytest.mark.parametrize("name", GIT_PLACEMENT_NAMES)
@pytest.mark.parametrize("position", ["final", "intermediate"])
def test_initialize_refuses_git_components_before_creating_anything(manager_root, location, name, position):
    control = manager_root / "control"
    control.mkdir()
    git(control, "init", "-q")
    signers = manager_root / "signers"
    signers.write_bytes(b"public signer fixture\n")
    config = manager_root / "config.json"
    missing = manager_root / "missing"
    reserved = missing / name if position == "final" else missing / name / "file"
    if location == "config":
        config = reserved
    else:
        signers = reserved
    audit = manager_root / "audit"

    refusal = "config_in_repository" if location == "config" else "trust_root_in_repository"
    with pytest.raises(ManagerError, match="^" + refusal + "$"):
        manager_config.initialize(config, workspace_id="placement-test", control_root=control,
                                  store_root=audit, trusted_signers=signers)
    assert not missing.exists()
    assert not config.exists()
    assert not audit.exists()
    assert not (missing / ".git").exists()


@pytest.mark.parametrize("error", [errno.EACCES, errno.ELOOP, errno.ENAMETOOLONG, errno.EIO])
@pytest.mark.parametrize("stage", ["prefix", "marker"])
def test_initialize_metadata_errors_are_unsafe_config(tmp_path, monkeypatch, error, stage):
    from aegis_core import manager_store

    control = tmp_path / "control"
    control.mkdir()
    git(control, "init", "-q")
    signers = tmp_path / "signers"
    signers.write_bytes(b"public signer fixture\n")
    config = tmp_path / "config.json"
    audit = tmp_path / "audit"
    real_os = manager_store.os

    def failing_lstat(path, *args, **kwargs):
        if (stage == "prefix" and Path(path) == config) or (stage == "marker" and Path(path).name == ".git"):
            raise OSError(error, "simulated placement metadata failure")
        return real_os.lstat(path, *args, **kwargs)

    monkeypatch.setattr(manager_store, "os", SimpleNamespace(**{**vars(real_os), "lstat": failing_lstat}))
    with pytest.raises(ManagerError, match="^unsafe_config$"):
        manager_config.initialize(config, workspace_id="placement-test", control_root=control,
                                  store_root=audit, trusted_signers=signers)
    assert not config.exists()
    assert not audit.exists()
    assert not (tmp_path / ".git").exists()


def test_unsearchable_prefix_is_unsafe_config(unsearchable_manager_alias):
    with pytest.raises(ManagerError, match="^unsafe_config$"):
        manager_config.public_file(unsearchable_manager_alias / "signers")
    target = unsearchable_manager_alias.parent.parent / "repo" / "sub"
    assert list(target.iterdir()) == []


def test_config_symlink_loop_is_unsafe(tmp_path):
    loop = tmp_path / "loop"
    symlink_or_skip("loop", loop, target_is_directory=True)
    with pytest.raises(ManagerError, match="^unsafe_config$"):
        manager_config.public_file(loop / "config.json")
    assert list(tmp_path.iterdir()) == [loop]


def test_benign_external_symlink_prefix_prepares(manager_root):
    control = manager_root / "control"
    control.mkdir()
    git(control, "init", "-q")
    target = manager_root / "files"
    target.mkdir()
    (target / "signers").write_bytes(b"public signer fixture\n")
    alias = manager_root / "alias"
    symlink_or_skip(target, alias, target_is_directory=True)

    result = manager_config.initialize(alias / "new" / "config.json", workspace_id="placement-test",
                                       control_root=control, store_root=alias / "audit",
                                       trusted_signers=alias / "signers")
    assert result["status"] == "prepared"
    config, _ = manager_config.load_config(alias / "new" / "config.json")
    assert config["store_root"] == str(target / "audit")
    assert (target / "audit" / "audit.jsonl").is_file()


def _ceiling_workspace(tmp_path, monkeypatch, marker):
    outer = tmp_path / "outer"
    outer.mkdir()
    git(outer, "init", "-q")
    if marker == "gitfile":
        metadata = tmp_path / "outer.git"
        (outer / ".git").rename(metadata)
        (outer / ".git").write_text("gitdir: " + str(metadata) + "\n", encoding="utf-8")
    ceiling = outer / "ceiling"
    workspace = ceiling / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling))
    return workspace


def _config_file(path, signers, control):
    path.write_text(json.dumps({
        "schema": "aegis.manager-config/v1", "workspace_id": "placement-test",
        "control_root": str(control), "store_root": str(path.parent / "audit"),
        "trusted_signers": str(signers),
        "trusted_signers_digest": hashlib.sha256(signers.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    path.chmod(0o600)


@pytest.mark.parametrize("marker", ["directory", "gitfile"])
def test_load_config_refuses_repository_hidden_by_ceiling(tmp_path, monkeypatch, marker):
    workspace = _ceiling_workspace(tmp_path, monkeypatch, marker)
    signers = workspace / "signers"
    signers.write_bytes(b"public signer fixture\n")
    path = workspace / "config.json"
    _config_file(path, signers, workspace / "control")

    with pytest.raises(ManagerError, match="^config_in_repository$"):
        manager_config.load_config(path)
    assert not (workspace / "audit").exists()


@pytest.mark.parametrize("marker", ["directory", "gitfile"])
def test_initialize_refuses_repository_hidden_by_ceiling(tmp_path, monkeypatch, marker):
    workspace = _ceiling_workspace(tmp_path, monkeypatch, marker)
    control = workspace / "control"
    control.mkdir()
    git(control, "init", "-q")
    signers = workspace / "signers"
    signers.write_bytes(b"public signer fixture\n")
    path = workspace / "new" / "config.json"

    with pytest.raises(ManagerError, match="^config_in_repository$"):
        manager_config.initialize(path, workspace_id="placement-test", control_root=control,
                                  store_root=workspace / "audit", trusted_signers=signers)
    assert not path.parent.exists()
    assert not (workspace / "audit").exists()


@pytest.mark.parametrize("marker", ["directory", "gitfile"])
def test_load_config_refuses_signer_hidden_by_ceiling(manager_root, tmp_path, monkeypatch, marker):
    workspace = _ceiling_workspace(tmp_path, monkeypatch, marker)
    signers = workspace / "signers"
    signers.write_bytes(b"public signer fixture\n")
    path = manager_root / "config.json"
    _config_file(path, signers, workspace / "control")

    with pytest.raises(ManagerError, match="^trust_root_in_repository$"):
        manager_config.load_config(path)
    assert not (manager_root / "audit").exists()


@pytest.mark.parametrize("marker", ["directory", "gitfile"])
def test_initialize_refuses_signer_hidden_by_ceiling(manager_root, tmp_path, monkeypatch, marker):
    workspace = _ceiling_workspace(tmp_path, monkeypatch, marker)
    control = workspace / "control"
    control.mkdir()
    git(control, "init", "-q")
    signers = workspace / "signers"
    signers.write_bytes(b"public signer fixture\n")
    path = manager_root / "config.json"

    with pytest.raises(ManagerError, match="^trust_root_in_repository$"):
        manager_config.initialize(path, workspace_id="placement-test", control_root=control,
                                  store_root=manager_root / "audit", trusted_signers=signers)
    assert not path.exists()
    assert not (manager_root / "audit").exists()


@pytest.fixture
def owner(tmp_path, monkeypatch):
    if not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")
    key, public = hg.keygen(tmp_path / "keys", "owner")
    repo = hg.make_repo(tmp_path)
    for name, value in repo.home.env.items():
        monkeypatch.setenv(name, value)
    signers = tmp_path / "trusted-signers"
    raw = ("owner " + public + "\n").encode("utf-8")
    signers.write_bytes(raw)
    config = {"control_root": str(repo.root), "trusted_signers": str(signers),
              "trusted_signers_digest": hashlib.sha256(raw).hexdigest()}
    return config, repo, key


@pytest.mark.parametrize("extra", [
    "Aegis-Approve: ", "Aegis-Approve-Insight: ", "Aegis-Exempt-Test: ",
    "Aegis-Future: ", "continued ",
])
def test_owner_approval_refuses_other_authority_unknown_lines_and_continuation(owner, extra):
    config, repo, key = owner
    statement = {"purpose": "one owner decision"}
    message = "Owner approval\n\nAegis-Manager-Approve: " + digest(statement) + "\n" + extra + "b" * 64
    commit = repo.commit(message, sign_key=key, allow_empty=True)
    with pytest.raises(ManagerError, match="^invalid_owner_signature$"):
        manager_config.verify_owner(config, statement, {"statement": statement, "commit": commit})


def test_owner_approval_keeps_check_and_signoff_metadata(owner):
    config, repo, key = owner
    statement = {"purpose": "one owner decision"}
    message = ("Owner approval\n\nAegis-Manager-Approve: " + digest(statement) + "\n"
               "Aegis-Check: tree=" + "b" * 40 + " exit=0\nSigned-off-by: Owner <owner@example.invalid>\n")
    commit = repo.commit(message, sign_key=key, allow_empty=True)
    result = manager_config.verify_owner(config, statement, {"statement": statement, "commit": commit})
    assert result["state"] == "owner_signature_verified"


@pytest.mark.parametrize("separator", ["\r", "\u2028"])
def test_owner_approval_does_not_split_or_join_a_multiline_signed_value(owner, separator):
    config, repo, key = owner
    statement = {"purpose": "one owner decision"}
    message = "Owner approval\n\nAegis-Manager-Approve: " + digest(statement) + separator + "continued\n"
    commit = repo.commit(message, sign_key=key, allow_empty=True)
    with pytest.raises(ManagerError, match="^invalid_owner_signature$"):
        manager_config.verify_owner(config, statement, {"statement": statement, "commit": commit})


def test_owner_message_limits_precede_the_owner_regex(owner, monkeypatch):
    config, repo, key = owner
    statement = {"purpose": "one owner decision"}
    message = ("Owner approval\n\nAegis-Manager-Approve: " + digest(statement) + "\n"
               "Signed-off-by:" + " " * 8192 + "\r\n")
    repo.git("-c", "gpg.format=ssh", "-c", "user.signingkey=" + str(key), "commit", "-q", "-S",
             "--allow-empty", "--cleanup=verbatim", "-F", "-", stdin=message)

    class UnreachablePattern:
        def findall(self, *_args):
            pytest.fail("owner regex ran before the message limits")

    monkeypatch.setattr(manager_config, "_OWNER_LINE", UnreachablePattern())
    with pytest.raises(ManagerError, match="^invalid_owner_signature$"):
        manager_config.verify_owner(config, statement, {"statement": statement, "commit": repo.head()})
