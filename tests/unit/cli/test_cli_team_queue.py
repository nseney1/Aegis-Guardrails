"""Public queue command behaviour, envelopes, refusals and core parity."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aegis_cli.cli import main
from aegis_cli import team as cli_team
from aegis_core import team, team_queue


@pytest.fixture
def workspace(tmp_path):
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    (root / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"writer": ["src/**"]}}), encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    home = tmp_path / "home"
    home.mkdir()
    # The autouse hermetic_environment_and_mcp_isolation fixture restores this
    # environment. Explicit --workspace keeps cwd unchanged throughout.
    os.environ.update({"HOME": str(home), "USERPROFILE": str(home)})
    return root


def run(capsys, root, *arguments):
    try:
        code = main(["--workspace", str(root), "team", "queue", *arguments, "--json"])
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out)


def test_cli_unclaim_releases_lane_lease_and_preserves_refusal_envelope(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")
    assert code == 0
    lease = team.claim(workspace, "writer", ["src/**"])
    revision = claimed["item"]["revision"]
    code, refused = run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer")
    assert code == 1 and refused["reason"] == "writer_not_stopped"
    code, refused = run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer", "--writer-stopped", "--reason", "token=private-value")
    assert code == 2 and refused["reason"] == "credential_like_text"
    assert "private-value" not in json.dumps(refused)
    code, released = run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer", "--writer-stopped", "--reason", "Waiting for review")
    assert code == 0 and released["schema"] == "aegis.team.queue.unclaim/v1"
    assert released["item"]["state"] == "queued" and released["released_lease_ids"] == [lease.oid]
    assert team.read_leases(workspace).get("writer") is None
    assert run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer", "--writer-stopped")[0] == 1


def test_queue_cli_lifecycle_and_core_parity(workspace, capsys):
    item = {"id": "ONE", "title": "Core work", "paths": ["src/**"], "capabilities": ["core"]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(item))
    assert code == 0 and added["schema"] == "aegis.team.queue.add/v1"
    revision = added["item"]["revision"]
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", revision,
                        "--lane", "writer", "--capability", "core")
    assert code == 0 and claimed["item"]["label"] == "writer [ONE: Core work]"
    code, listed = run(capsys, workspace, "list")
    assert code == 0
    expected = team_queue.list(workspace)
    listed.pop("checked_at")
    expected.pop("checked_at")
    assert listed == expected
    assert run(capsys, workspace, "claim", "ONE", "--expect", revision,
               "--lane", "writer", "--capability", "core")[0] == 1
    code, released = run(capsys, workspace, "release", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", released["item"]["revision"],
                        "--lane", "writer", "--capability", "core", "--ttl", "60")
    assert code == 0
    code, completed = run(capsys, workspace, "done", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")
    assert code == 0 and completed["item"]["state"] == "done"
    code, audited = run(capsys, workspace, "audit")
    assert code == 0 and audited["findings"] == []


def test_live_queue_claim_remains_ready_after_cli_repository_claim(workspace, capsys):
    value = {"id": "ONE", "title": "Core work", "paths": ["src/**"], "capabilities": [],
             "hold_until": [{"kind": "lease_free", "paths": ["src/**"]}]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"],
                        "--lane", "writer")
    assert code == 0
    assert main(["--workspace", str(workspace), "team", "claim", "writer", "--paths", "src/**", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out)["status"] == "claimed"
    code, listed = run(capsys, workspace, "list")
    assert code == 0 and listed["items"][0]["conditions_met"] is True
    assert listed["items"][0]["blockers"] == []
    assert "Wait for" not in json.dumps(listed)


@pytest.mark.parametrize("arguments", [
    (), ("unknown", "token=private-value"), ("add", "--item", "token=private-value"),
    ("add", "--item", "{}", "--unknown", "token=private-value"),
    ("claim", "ONE", "--expect", "token=private-value", "--lane", "writer"),
    ("claim", "ONE", "--expect", "0" * 64, "--lane", "writer", "--ttl", "secret"),
    ("list", "--capability", "token=private-value"),
])
def test_queue_usage_refuses_without_echo(workspace, capsys, arguments):
    code, result = run(capsys, workspace, *arguments)
    assert code == 2 and result["refused"] and result["reason"] in ("invalid_arguments", "invalid_item")
    assert result["next_action"]
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("verb", ["list", "audit", "compact"])
def test_cli_unsupported_platform_uses_refusal_envelope(tmp_path, monkeypatch, capsys, verb):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.setattr(team_queue, "descriptor_supported", lambda: False)
    code, result = run(capsys, tmp_path, verb)
    assert code == 1 and result["reason"] == "unsupported_platform"


def test_queue_workspace_failure_does_not_echo_path(tmp_path, capsys):
    code, result = run(capsys, tmp_path, "list", "--workspace", "token=private-value/missing")
    assert code == 1 and result["refused"] and result["next_action"]
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("mode", ("json", "text"))
def test_refused_lane_claim_exposes_anchor_next_action_in_subprocess(workspace, mode):
    (workspace / "pyproject.toml").write_text("# root file\n", encoding="utf-8")
    team.claim(workspace, "docs", ["/docs/"], owner="owner")
    source = Path(__file__).resolve().parents[3]
    environment = dict(os.environ, PYTHONPATH=str(source))
    arguments = [sys.executable, "-m", "aegis_cli", "team", "claim", "writer",
                 "--workspace", str(workspace), "--paths", "pyproject.toml"]
    if mode == "json":
        arguments.append("--json")
    result = subprocess.run(arguments, cwd=workspace, env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, (result.stdout, result.stderr)
    expected = "Retry with root-anchored lease paths: /pyproject.toml; slashless paths cover every depth."
    if mode == "json":
        payload = json.loads(result.stdout)
        assert payload["reason"] == "overlap"
        assert payload["next_action"] == expected
        assert result.stderr == ""
    else:
        assert result.stdout == ""
        assert expected in result.stderr

@pytest.mark.parametrize("prefix", [("--bad=token=private-value", "team"),
                                   ("team", "--bad=token=private-value"),
                                   ("--bad", "token=private-value", "team"),
                                   ("team", "--bad", "token=private-value")])
def test_queue_ancestor_parser_refuses_without_echo(workspace, capsys, prefix):
    try:
        code = main(["--workspace", str(workspace), *prefix, "queue", "list", "--json"])
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert code == 2 and captured.err == ""
    payload = json.loads(captured.out)
    assert payload["refused"] and payload["reason"] == "invalid_arguments"
    assert "private-value" not in captured.out


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("options", [
    ["--unknown=token=private-value"],
    ["--unknown", "token=private-value"],
    ["--bad", "--workspace", "/ws", "--unknown=token=private-value"],
    ["--bad", "--other", "token=private-value"],
    ["--bad", "--work", "token=private-value"],
    ["--bad", "--work=token=private-value"],
    ["--=token=private-value"],
], ids=["equals", "separate", "unknown-workspace", "unknown-option", "abbreviation",
        "abbreviation-equals", "ambiguous-abbreviation"])
@pytest.mark.parametrize("model_value", [False, True], ids=["ordinary", "model-data"])
def test_queue_privacy_scope_refuses_malformed_options(capsys, position, options, model_value):
    argv = ["team", "queue", "list"]
    argv[position:position] = options
    if model_value:
        argv.extend(["--capability", "model"])
    try:
        code = main(argv)
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert "token=private-value" not in captured.out + captured.err
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    payload = json.loads(captured.out)
    assert payload["schema"] == "aegis.team.queue.usage/v1"
    assert payload["refused"] is True and payload["reason"] == "invalid_arguments"
    assert payload["exit_code"] == 2
    assert payload["next_action"] == "Use the documented queue arguments and the revision returned by list."


@pytest.mark.parametrize("argv", [
    ["--bad", "--workspace", "/ws", "--unknown=token=private-value", "team", "queue", "list"],
    ["--bad", "--other", "token=private-value", "team", "queue", "list"],
    ["team", "--bad", "--workspace", "claim", "--leak=token=private-value", "queue", "list"],
    ["--bad", "queue", "--leak=token=private-value", "team", "queue", "list"],
    ["--bad", "queue", "--leak=token=private-value", "team", "queue", "list", "--capability", "model"],
    ["--bad", "queue", "--leak=token=private-value", "team", "queue", "list", "--capability", "msg"],
    ["--pl", "team", "queue", "unknown"],
    ["--js", "--workspace", "/tmp/ws", "team", "queue", "unknown"],
])
def test_queue_privacy_scope_reviewer_reproducers(capsys, argv):
    try:
        code = main(argv)
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    payload = json.loads(captured.out)
    assert payload["reason"] == "invalid_arguments" and payload["next_action"]


@pytest.mark.parametrize("argv", [
    ["team", "list", "queue", "--unknown=token=private-value"],
    ["--workspace", "team", "--unknown=token=private-value", "queue"],
    ["team", "--workspace", "queue", "--unknown=token=private-value"],
])
def test_queue_privacy_scope_includes_option_values_and_nonqueue_commands(capsys, argv):
    try:
        code = main(argv)
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    assert json.loads(captured.out)["reason"] == "invalid_arguments"


@pytest.mark.parametrize("argv", [
    ["--", "team", "queue", "--x=token=private-value"],
    ["team", "--", "queue", "--x=token=private-value"],
    ["--", "team", "--x=token=private-value", "queue", "list"],
    ["--", "team", "queue", "list", "--x=token=private-value"],
    ["team", "queue", "--", "list", "--x=token=private-value"],
    ["team", "queue", "list", "--", "--x=token=private-value"],
])
def test_queue_privacy_scope_includes_double_dash(capsys, argv):
    try:
        code = main(argv)
    except SystemExit as refused:
        code = refused.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.usage/v1"
    assert result["reason"] == "invalid_arguments" and result["next_action"]


@pytest.mark.parametrize("removed", ["audit", "report", "agent"])
@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("form", ["separate", "equals"])
@pytest.mark.parametrize("separator", [False, True], ids=["ordinary", "double-dash"])
def test_queue_privacy_scope_bypasses_removed_command_pointer(capsys, removed, position, form, separator):
    options = (["--bad", removed, "--leak=token=private-value"] if form == "separate" else
               ["--bad=token=private-value", removed])
    argv = ["team", "queue", "list"]
    argv[position:position] = options
    if separator:
        argv.insert(0, "--")
    try:
        code = main(argv)
    except SystemExit as refused:
        code = refused.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.usage/v1"
    assert result["refused"] is True and result["reason"] == "invalid_arguments"
    assert result["exit_code"] == 2 and result["next_action"]


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("padding", ["/." * 300, "x" * 32769], ids=["components", "length"])
def test_queue_privacy_scope_bounds_merged_workspace(capsys, tmp_path, position, padding):
    argv = ["team", "queue", "list"]
    argv[position:position] = ["--workspace", str(tmp_path) + padding]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and str(tmp_path) not in captured.out
    payload = json.loads(captured.out)
    assert payload["reason"] == "invalid_arguments" and payload["next_action"]


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("verb", ["list", "add", "claim"])
@pytest.mark.parametrize("invalid", ["parent", "windows-parent", "empty", "nul",
    "drive-parent", "drive-parent-only", "rooted-parent", "relative-parent"])
def test_queue_refuses_invalid_raw_workspace_before_resolution(tmp_path, monkeypatch, capsys, position, verb, invalid):
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.chdir(root)
    values = {"parent": str(root) + "/../" + root.name,
              "windows-parent": str(root) + "\\..\\" + root.name,
              "empty": "", "nul": str(root) + "/\x00",
              "drive-parent": "C:..\\ws", "drive-parent-only": "C:..",
              "rooted-parent": "\\..\\ws", "relative-parent": "ws/../x"}
    argv = ["team", "queue", verb]
    if verb == "add":
        argv.extend(["--item", json.dumps({"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})])
    elif verb == "claim":
        argv.extend(["ONE", "--expect", "0" * 64, "--lane", "writer"])
    argv[position:position] = ["--workspace", values[invalid]]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and str(root) not in captured.out
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.usage/v1"
    assert result["refused"] is True and result["reason"] == "invalid_arguments"
    assert result["exit_code"] == 2 and result["next_action"]
    assert not (root / ".aegis" / "state" / "team-queue.json").exists()


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("suffix", ["/./", "/..cache"])
def test_queue_workspace_accepts_nonparent_components(workspace, capsys, position, suffix):
    (workspace / "..cache").mkdir()
    argv = ["team", "queue", "list"]
    argv[position:position] = ["--workspace", str(workspace) + suffix]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.list/v1" and result["refused"] is False


@pytest.mark.parametrize("field", ["title", "hold", "scope_rulings", "invariants"])
def test_secret_item_text_reaches_fixed_service_refusal(workspace, capsys, field):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    value[field] = ["token=private-value"] if field in ("scope_rulings", "invariants") else "token=private-value"
    code, result = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 2 and result["schema"] == "aegis.team.queue.add/v1"
    assert result["reason"] == "credential_like_text" and result["next_action"]
    assert "private-value" not in json.dumps(result)
    assert not (workspace / ".aegis" / "state" / "team-queue.json").exists()


@pytest.mark.parametrize("argv", [
    ["team", "claim", "model", "--paths", "src/**"],
    ["team", "claim", "model", "--paths", "queue"],
    ["team", "claim", "alpha", "--paths", "queue", "--owner", "model"],
])
def test_successful_nonqueue_parse_keeps_model_token_policy(capsys, argv):
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


def test_cli_completed_filter_compact_and_retry(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")
    assert code == 0
    assert run(capsys, workspace, "done", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")[0] == 0
    assert run(capsys, workspace, "list")[1]["items"] == []
    assert run(capsys, workspace, "list", "--include-done")[1]["items"][0]["id"] == "ONE"
    code, compacted = run(capsys, workspace, "compact")
    assert code == 0 and compacted["removed_count"] == 1
    assert compacted["schema"] == "aegis.team.queue.compact/v1"
    assert run(capsys, workspace, "compact")[1]["removed_count"] == 0


def test_cli_brief_and_foreign_lease_preflight(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"],
             "capabilities": [], "brief_paths": ["src/a.py"]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    lease = team.claim(workspace, "foreign", ["src/**"], owner="owner")
    code, refused = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")
    assert code == 1 and refused["reason"] == "blocked"
    assert refused["blockers"][0]["reason"] == "foreign_lease"
    team.release(workspace, "foreign", lease.oid, caller="owner")
    assert run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")[0] == 0


@pytest.mark.parametrize("branch", [None, "lane/writer", "refs/heads/lane/writer"])
def test_cli_queue_branch_evidence_is_explicit(workspace, capsys, branch):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    assert run(capsys, workspace, "add", "--item", json.dumps(value))[0] == 0
    revision = team_queue.list(workspace)["items"][0]["revision"]
    args = ["claim", "ONE", "--expect", revision, "--lane", "writer"]
    if branch is not None:
        args.extend(["--branch", branch])
    code, claimed = run(capsys, workspace, *args)
    assert code == 0
    assert claimed["item"]["branch"] == (None if branch is None else "lane/writer")
    team.claim(workspace, "writer", ["src/**"], owner="owner", branch="lane/writer")
    subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/other"], cwd=workspace, check=True)
    code, audited = run(capsys, workspace, "audit")
    assert code == 0
    assert [row["code"] for row in audited["findings"]] == (["CLAIM-BRANCH-UNKNOWN"] if branch is None else [])


@pytest.mark.parametrize("branch,accepted", [
    ("feature/c++", True), ("fix/issue#12", True), ("user@topic", True), ("feat/naïve", True),
    ("refs/heads/x", True), ("x" * 200, True), ("x" * 201, False),
    ("refs/tags/x", False), ("HEAD", False), ("private-value topic", False),
    ("private-value\ntrailer", False),
], ids=["plus", "hash", "at", "unicode", "full", "limit", "over-limit", "tag", "head", "space", "multiline"])
def test_cli_queue_uses_lease_branch_grammar(workspace, capsys, branch, accepted):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    if accepted:
        team.claim(workspace, "writer", ["src/**"], owner="owner", branch=branch)
    code, result = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"],
                       "--lane", "writer", "--branch", branch)
    if accepted:
        assert code == 0, result
        assert result["item"]["branch"] == branch.removeprefix("refs/heads/")
        code, audited = run(capsys, workspace, "audit")
        assert code == 0 and audited["findings"] == []
    else:
        assert code == 2 and result["reason"] == "invalid_arguments"
        assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("branch,unsupported", [
    ("refs/heads/refs/tags/x", True), ("refs/heads/refs/heads/x", True),
    ("refs/heads/refs/remotes/origin/x", True), ("lane/writer", False),
], ids=["nested-tag", "nested-head", "nested-remote", "valid"])
@pytest.mark.parametrize("state", ["active", "expired", "completed"])
@pytest.mark.parametrize("verb", ["list", "audit", "compact", "add", "claim", "release", "done"])
def test_cli_stored_branch_isolated_from_queue_operations(workspace, capsys, monkeypatch, branch, unsupported, state, verb):
    root = workspace
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    (root / ".aegis" / "team.json").write_text(json.dumps({"v": 1,
        "lanes": {"writer": ["src/**"], "beta": ["docs/**"]}}), encoding="utf-8")
    profile = root / ".aegis" / "team" / "profile.json"
    profile.parent.mkdir()
    profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": 2}}}), encoding="utf-8")
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, root, "add", "--item", json.dumps(value))
    assert code == 0
    code, second = run(capsys, root, "add", "--item", json.dumps({**value, "id": "TWO", "paths": ["docs/**"]}))
    assert code == 0
    code, claimed = run(capsys, root, "claim", "ONE", "--expect", added["item"]["revision"],
                         "--lane", "writer", "--branch", "lane/writer", "--ttl", "10")
    assert code == 0
    if state == "completed":
        assert run(capsys, root, "done", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")[0] == 0
    path = root / ".aegis" / "state" / "team-queue.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["items"]["ONE"]["branch"] = branch
    path.write_text(json.dumps(document), encoding="utf-8")
    revision = document["items"]["ONE"]["revision"]
    team.claim(root, "writer", ["src/**"], owner="owner", branch="lane/writer", now=100)
    team.claim(root, "beta", ["docs/**"], owner="owner", branch="lane/beta", now=100)
    moment = 112 if state == "expired" else 103
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: moment))
    arguments = [verb]
    if verb == "list":
        arguments.append("--include-done")
    elif verb == "add":
        arguments.extend(["--item", json.dumps({**value, "id": "THREE", "paths": ["other/**"]})])
    elif verb == "claim":
        arguments.extend(["TWO", "--expect", second["item"]["revision"], "--lane", "beta", "--branch", "lane/beta"])
    elif verb in ("release", "done"):
        arguments.extend(["ONE", "--expect", revision, "--lane", "writer"])
    code, result = run(capsys, root, *arguments)
    expected_error = ("not_claimed" if state == "completed" else "lease_expired"
                      if state == "expired" and verb == "done" else None) if verb in ("release", "done") else None
    if expected_error:
        assert code == 1 and result["reason"] == expected_error
    else:
        assert code == 0, result
    cleared = ((verb == "release" and state != "completed") or
               (verb == "done" and state == "active") or (verb == "compact" and state == "completed"))
    code, audited = run(capsys, root, "audit")
    assert code == 0, audited
    findings = audited["findings"]
    assert [row["code"] for row in findings] == (["CLAIM-BRANCH-UNSUPPORTED"] if unsupported and not cleared else [])
    if findings:
        assert findings[0]["item_id"] == "ONE" and findings[0]["reason"] == "claim_branch_unsupported"
        assert findings[0]["next_action"] and branch not in json.dumps(findings)
    if not cleared:
        assert json.loads(path.read_text(encoding="utf-8"))["items"]["ONE"]["branch"] == branch
    if unsupported and not cleared:
        recovery_args = ["compact"] if state == "completed" else ["release", "ONE", "--expect", revision, "--lane", "writer"]
        assert run(capsys, root, *recovery_args)[0] == 0
        assert run(capsys, root, "audit")[1]["findings"] == []


@pytest.mark.parametrize("lease_state,lease_code", [
    ("missing", "LANE-NO-LEASE"), ("branchless", "LEASE-BRANCH-UNKNOWN"),
    ("unreadable", "LEASE-UNREADABLE"), ("healthy", None),
])
def test_cli_unsupported_branch_preserves_independent_lease_findings(workspace, capsys, monkeypatch, lease_state, lease_code):
    from aegis_core import gitsafe

    root = workspace
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, root, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, root, "claim", "ONE", "--expect", added["item"]["revision"],
                        "--lane", "writer", "--branch", "lane/writer")
    assert code == 0
    branch = "refs/heads/refs/tags/private-value"
    path = root / ".aegis" / "state" / "team-queue.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["items"]["ONE"]["branch"] = branch
    path.write_text(json.dumps(document), encoding="utf-8")
    if lease_state == "unreadable":
        bad = gitsafe.write_blob(root, b"{}")
        gitsafe.update_ref(root, team.lane_ref("writer"), bad, None)
    elif lease_state != "missing":
        team.claim(root, "writer", ["src/**"], owner="owner", now=100,
                   branch=None if lease_state == "branchless" else "other/branch")
    code, result = run(capsys, root, "audit")
    assert code == 0, result
    findings = result["findings"]
    expected = ["CLAIM-BRANCH-UNSUPPORTED"] + ([lease_code] if lease_code else [])
    assert [row["code"] for row in findings] == expected
    assert all(row["item_id"] == "ONE" and row["lane"] == "writer" and
               row["refused"] and row["reason"] and row["next_action"] for row in findings)
    assert "private-value" not in json.dumps(findings)
    assert json.loads(path.read_text(encoding="utf-8"))["items"]["ONE"]["branch"] == branch


def test_cli_outside_brief_is_refused_at_add_and_corrected_retry_succeeds(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": [], "brief_paths": ["docs/a.md"]}
    code, result = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 2 and result["reason"] == "brief_outside_scope"
    assert not (workspace / ".aegis" / "state" / "team-queue.json").exists()
    value["brief_paths"] = ["src/a.py"]
    assert run(capsys, workspace, "add", "--item", json.dumps(value))[0] == 0


def test_queue_with_model_data_keeps_workspace_refusal(tmp_path, capsys):
    code, result = run(capsys, tmp_path, "list", "--capability", "model",
                       "--workspace", "token=private-value/missing")
    assert code == 1 and result["reason"] == "queue_io_unavailable"
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("position", [0, 1], ids=["root", "team"])
def test_queue_model_data_works_with_ancestor_option_abbreviation(workspace, capsys, position):
    argv = ["team", "queue", "list", "--capability", "model"]
    argv[position:position] = ["--js", "--workspace", str(workspace)]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["schema"] == "aegis.team.queue.list/v1"


def test_model_values_are_queue_identifiers(workspace, capsys):
    (workspace / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"model": ["src/**"]}}), encoding="utf-8")
    value = {"id": "model", "title": "Work", "paths": ["src/**"], "capabilities": ["model"]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "model", "--expect", added["item"]["revision"],
                        "--lane", "model", "--capability", "model")
    assert code == 0, claimed
    assert run(capsys, workspace, "list", "--capability", "model")[1]["items"][0]["id"] == "model"
    code, released = run(capsys, workspace, "release", "model", "--expect", claimed["item"]["revision"], "--lane", "model")
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "model", "--expect", released["item"]["revision"],
                        "--lane", "model", "--capability", "model")
    assert code == 0
    assert run(capsys, workspace, "done", "model", "--expect", claimed["item"]["revision"], "--lane", "model")[0] == 0

@pytest.mark.parametrize("mode", ["json", "text"])
def test_legacy_refusal_changes_only_by_optional_hint(workspace, capsys, monkeypatch, mode):
    monkeypatch.setattr(cli_team, "time", SimpleNamespace(time=lambda: 1760000000))
    hint = "Retry with root-anchored lease paths: /pyproject.toml; slashless paths cover every depth."
    current = [""]
    def refused(*args, **kwargs):
        raise team.LeaseRefused("overlap: fixed refusal", "overlap", "writer",
                                lanes=("docs",), next_action=current[0])
    monkeypatch.setattr(cli_team, "team", SimpleNamespace(**{**vars(team), "claim": refused}))
    args = ["--workspace", str(workspace), "team", "claim", "writer", "--paths", "pyproject.toml"]
    if mode == "json":
        args.append("--json")
    assert main(args) == 1
    baseline = capsys.readouterr()
    current[0] = hint
    assert main(args) == 1
    changed = capsys.readouterr()
    if mode == "json":
        assert "next_action" not in json.loads(baseline.out)
        assert changed.out.replace(',\n  "next_action": ' + json.dumps(hint), "") == baseline.out
        assert baseline.err == changed.err == ""
    else:
        assert baseline.out == changed.out == ""
        assert changed.err.replace(hint + "\n", "") == baseline.err
