"""The installed owner-side module has a fixed refusal and JSON output surface."""
import hashlib
import json
import sys

import pytest

from aegis_cli import manager_adjudication as cli
from aegis_core.manager import ManagerService
from tests.conftest import run
from tests.helpers_humangate import Home, signing_ok
from tests.helpers_manager import git, manager_root, prepare


def command(*args, env=None):
    return run([sys.executable, "-m", "aegis_cli.manager_adjudication", *args], env=env, timeout=25)


def test_missing_anchor_and_argument_errors_do_not_reflect_input():
    refused = command("verify", "--config", "owner-config", "--config-digest", "a" * 64)
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert json.loads(refused.stderr) == {"status": "refused", "reason": "missing_anchor"}
    malformed = command("invalid-private-input")
    assert malformed.returncode == 2
    assert malformed.stdout == ""
    assert json.loads(malformed.stderr) == {"status": "refused", "reason": "invalid_arguments"}


def sign(env, owner_home, trailer):
    signed = run(["git", "-c", "user.name=Owner", "-c", "user.email=owner@example.invalid",
                  "-c", "gpg.format=ssh", "-c", "user.signingkey=" + str(env["key"]),
                  "commit", "--allow-empty", "--no-verify", "-S", "-qm", "Owner review\n\n" + trailer],
                 cwd=env["control"], env=owner_home, timeout=10)
    assert signed.returncode == 0, signed.stderr
    return git(env["control"], "rev-parse", "HEAD")


def test_owner_prepares_and_verifies_through_module_command(manager_root):
    if not signing_ok():
        pytest.skip("needs Git SSH commit signing")
    owner_home = Home(manager_root / "owner-home").env
    env = prepare(manager_root)
    service = ManagerService(env["config"])
    candidate = service.candidate(env["revision"])
    approval = {"statement": candidate["approval_statement"],
                "commit": sign(env, owner_home, candidate["required_trailer"])}
    service.activate(env["revision"], None, approval)
    decision = service.scan("handoff", env["context"])
    rule = decision["rules"][0]
    episode = "ghp_" + "a" * 36
    signed_head = service.status()["audit_head"]
    label = {"schema": "aegis.manager-label/v2", "workspace_id": decision["workspace_id"],
             "audit_head": signed_head,
             "decision_refs": [decision["decision_ref"]], "episode_id": episode, "rule_id": rule["id"],
             "rule_revision": rule["revision"], "assessment": "helpful", "evidence_digest": "e" * 64,
             "previous_anchor": None, "predecessor": None}
    path = env["control"] / "adjudication" / "label.json"
    path.parent.mkdir()
    path.write_text(json.dumps(label), encoding="utf-8")
    git(env["control"], "add", "adjudication/label.json")
    git(env["control"], "commit", "-qm", "Reviewed label")
    revision = git(env["control"], "rev-parse", "HEAD")
    tail = service.scan("checkpoint", env["context"])
    pin = hashlib.sha256(env["config"].read_bytes()).hexdigest()
    config = ["--config", str(env["config"]), "--config-digest", pin]
    prepared = command("prepare", *config, "--manifest", revision, env=owner_home)
    assert prepared.returncode == 0, prepared.stderr
    assert prepared.stderr == ""
    payload = json.loads(prepared.stdout)
    assert payload["statement"]["audit_head"] == signed_head
    assert payload["statement"]["schema"] == "aegis.manager-adjudication/v2"
    trailer = payload["required_trailer"]
    anchor = sign(env, owner_home, trailer)
    verified = command("verify", *config, "--anchor", anchor, env=owner_home)
    assert verified.returncode == 0, verified.stderr
    assert verified.stderr == ""
    assert episode not in verified.stdout
    projection = json.loads(verified.stdout)
    assert projection["schema"] == "aegis.manager-fitness/v2"
    assert projection["signed_audit_head"] == signed_head != projection["audit_head"]
    assert projection["by_revision"] == [
        {"rule_id": rule["id"], "rule_revision": rule["revision"], "tp": 1, "fp": 0,
         "unresolved": 0, "eligible": 1},
    ]
    assert [item["decision_ref"] for item in projection["unsigned_tail"]["decisions"]] == [tail["decision_ref"]]
    assert projection["unsigned_tail"]["opportunities"] == []
    assert command("verify", *config, "--anchor", anchor, env=owner_home).stdout == verified.stdout

    audit = env["store"] / "audit.jsonl"
    intact = audit.read_bytes()
    audit.write_bytes(b"".join(intact.splitlines(keepends=True)[:2]))
    try:
        refused = command("verify", *config, "--anchor", anchor, env=owner_home)
        assert refused.returncode == 1 and refused.stdout == ""
        assert json.loads(refused.stderr) == {"status": "refused", "reason": "audit_checkpoint_unavailable"}
    finally:
        audit.write_bytes(intact)
    assert command("verify", *config, "--anchor", anchor, env=owner_home).stdout == verified.stdout


def test_cli_clips_redacted_fields_at_complete_marker_boundaries(monkeypatch, capsys):
    text = "://a:b@ " * 9
    monkeypatch.setattr(cli, "verify", lambda *_: {"decisions": [{"decision_ref": text}]})
    assert cli.main(["verify", "--config", "owner", "--config-digest", "x", "--anchor", "y"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)["decisions"][0]["decision_ref"]
    assert value == "://a:[REDACTED]@ " * 7
