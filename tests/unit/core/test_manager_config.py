"""Owner approvals share the single-authority message contract."""
import hashlib

import pytest

from aegis_core import manager_config
from aegis_core.manager_policy import ManagerError, digest
from tests import helpers_humangate as hg


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
