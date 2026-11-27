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


def test_cli_assigns_report_local_ordinals_to_redacted_episodes(monkeypatch, capsys):
    first = "ghp_" + "a" * 36
    second = "ghp_" + "b" * 36
    containing = "retry" + first
    partial = first + ".review"
    ordinary = "redacted-episode-1"
    episodes = (containing, first, ordinary, second, first, containing, partial, None)
    report = {
        "workspace_id": "team" + containing,
        "decisions": [{"episode_id": episode} for episode in episodes],
        "unsigned_tail": {"opportunities": [{"episode_id": None, "member_id": first,
                                             "worktree_id": "tail" + second}]},
    }
    monkeypatch.setattr(cli, "verify", lambda *_: report)
    args = ["verify", "--config", "owner", "--config-digest", "x", "--anchor", "y"]

    assert cli.main(args) == 0
    initial = capsys.readouterr()
    assert initial.err == ""
    assert not any(episode in initial.out for episode in (first, second, containing, partial))
    rendered = json.loads(initial.out)
    assert rendered["workspace_id"] == "[REDACTED]"
    assert [row["episode_id"] for row in rendered["decisions"]] == [
        "[redacted-episode-1]", "[redacted-episode-2]", ordinary, "[redacted-episode-3]",
        "[redacted-episode-2]", "[redacted-episode-1]", "[redacted-episode-4]", None,
    ]
    assert rendered["unsigned_tail"] == {"opportunities": [
        {"episode_id": None, "member_id": "ghp_REDACTED", "worktree_id": "[REDACTED]"},
    ]}

    assert cli.main(args) == 0
    assert capsys.readouterr() == initial

    report["decisions"] = [{"episode_id": second}, {"episode_id": containing}, {"episode_id": first}]
    assert cli.main(args) == 0
    fresh = capsys.readouterr()
    assert fresh.err == ""
    assert [row["episode_id"] for row in json.loads(fresh.out)["decisions"]] == [
        "[redacted-episode-1]", "[redacted-episode-2]", "[redacted-episode-3]",
    ]


@pytest.mark.parametrize("case", ["partial", "crossing", "self_overlap", "adjacent", "interacting", "composite"])
def test_cli_masks_fields_containing_private_episodes(monkeypatch, capsys, case):
    private = "ghp_" + "a" * 20
    remainder = "b" * 16
    partial = private + ".xoxb-" + "c" * 10
    crossing = "retry-context-lead" + private
    repeated = "q." + private + ".q"
    shared = "xoxb-abcd-sk-_" + "c" * 20
    value, episodes = {
        "partial": ("x" + partial + "extra.xoxb-" + "d" * 10 + ".z", [partial]),
        "crossing": ("x" + crossing + remainder + ".end", [crossing, private + remainder, private]),
        "self_overlap": ("x" + repeated + "." + private + ".q.end", [repeated]),
        "adjacent": ("x" + private + private + ".end", [private]),
        "interacting": (shared + "." + private, [private]),
        "composite": (partial, [partial]),
    }[case]
    assert len(value) <= 64
    context = dict.fromkeys(("workspace_id", "member_id", "worktree_id"), value)
    rule = {"rule_id": value}
    report = {
        "workspace_id": value,
        "decisions": [{**context, **rule, "episode_id": episode} for episode in episodes],
        "by_revision": [{**rule, "eligible": 1}],
        "unsigned_tail": {
            "decisions": [context, {**context, "member_id": "aegis", "worktree_id": shared}],
            "opportunities": [{**context, **rule, "episode_id": None}],
            "by_revision": [{**rule, "eligible": 1}],
        },
    }
    monkeypatch.setattr(cli, "verify", lambda *_: report)
    args = ["verify", "--config", "owner", "--config-digest", "x", "--anchor", "y"]

    assert cli.main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    shown = dict.fromkeys(context, "[REDACTED]")
    shown_rule = {"rule_id": "[REDACTED]"}
    assert json.loads(captured.out) == {
        "workspace_id": "[REDACTED]",
        "decisions": [{**shown, **shown_rule, "episode_id": f"[redacted-episode-{index}]"}
                      for index in range(1, len(episodes) + 1)],
        "by_revision": [{**shown_rule, "eligible": 1}],
        "unsigned_tail": {
            "decisions": [shown, {**shown, "member_id": "aegis", "worktree_id": "[REDACTED_TOKEN]"}],
            "opportunities": [{**shown, **shown_rule, "episode_id": None}],
            "by_revision": [{**shown_rule, "eligible": 1}],
        },
    }
    assert not any(secret in captured.out for secret in (*episodes, private, remainder, "abcd"))
