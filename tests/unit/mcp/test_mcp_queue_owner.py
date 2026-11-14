"""Owner launch entry has no caller role/root override and fixed errors."""
import ast
import json
import io
import os
from pathlib import Path

import pytest

import aegis_mcp.queue_role as queue_role
import aegis_mcp.queue_owner as queue_owner
import aegis_mcp.server as server
from tests.unit.mcp.test_mcp_queue_role import owner_factory

_USAGE = "Launch with exactly one registration id."
_SECRET = "token=private-value"
# Launch recoveries. The code set is not this table: tests derive it from issue().
_LAUNCH_SENTENCES = {
    "invalid_arguments": _USAGE,
    "role_missing": "Ask the owner to install the registration and restart the queue connection.",
    "role_invalid": "Ask the owner to repair the authority records and restart the queue connection.",
    "role_stale": "Retry the launch.",
    "role_lock_timeout": "Wait for the authority writer, then restart the queue connection.",
    "role_io_unavailable": "Ask the owner to inspect authority storage and restart the queue connection.",
    "unsupported_platform": "Use Linux with descriptor-relative no-follow operations.",
}
_CLAIM_ONLY = (
    "Ask the owner to restart the queue connection with a fresh session record.",
    "Wait for the authority writer, list the queue and retry the current revision.",
)


def _launch_err(code, sentence):
    return "aegis-mcp-queue: " + code + ": " + sentence + "\n"


def _registration(workspace):
    return dict(schema="aegis.mcp.queue-registration/v1", registration_id="alpha",
                endpoint="a/orchestrator", role="orchestrator", workspace=workspace,
                lanes={"alpha": {"capabilities": ["core"], "branch": "refs/heads/lane/alpha"}},
                ttl_s=600, session_ttl_s=7200)


def _role_tree():
    source = Path(__file__).resolve().parents[3] / "aegis_mcp" / "queue_role.py"
    return ast.parse(source.read_text(encoding="utf-8"))


def _expr_strings(node):
    if isinstance(node, ast.Dict):
        return {value.value for value in node.values
                if isinstance(value, ast.Constant) and isinstance(value.value, str)}
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        found = _expr_strings(node.func.value)
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
            found.add(node.args[1].value)
        return found
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _expr_strings(node.body) | _expr_strings(node.orelse)
    return set()


def _assigned_strings(func, name):
    found = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
                                                for target in node.targets):
            found |= _expr_strings(node.value)
    return found


def _issue_refusal_codes():
    """Refusal literals issue() can raise, including helpers it reaches. Not a hand list."""
    functions = {node.name: node for node in _role_tree().body if isinstance(node, ast.FunctionDef)}
    reachable = set()
    pending = ["issue"]
    while pending:
        name = pending.pop()
        if name in reachable or name not in functions:
            continue
        reachable.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                pending.append(node.func.id)
    require_default = None
    arguments = functions["require"].args
    for arg, default in zip(arguments.args[-len(arguments.defaults):], arguments.defaults):
        if arg.arg == "reason" and isinstance(default, ast.Constant) and isinstance(default.value, str):
            require_default = default.value
    reasons = set()
    for name in reachable:
        func = functions[name]
        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "require":
                explicit = None
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    explicit = node.args[1].value
                for keyword in node.keywords:
                    if keyword.arg == "reason" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                        explicit = keyword.value.value
                if explicit is None and len(node.args) < 2 and not any(keyword.arg == "reason" for keyword in node.keywords):
                    explicit = require_default
                if explicit:
                    reasons.add(explicit)
            elif node.func.id == "RoleRefusal" and node.args:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    reasons.add(argument.value)
                elif isinstance(argument, ast.Name):
                    reasons.update(_assigned_strings(func, argument.id))
    return reasons


def _launch_sentences_from_source():
    for node in _role_tree().body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_LAUNCH"
                                                for target in node.targets):
            mapping = {}
            for key, value in zip(node.value.keys, node.value.values):
                mapping[key.value] = value.value
            return mapping
    return None


def _encoded_boundary():
    """One filesystem-encoding byte under the cap, then one byte over, within the char cap."""
    unit = "é"
    prefix = "/"
    room = queue_role.MAX_WORKSPACE - len(os.fsencode(prefix))
    exact = prefix + unit * (room // len(os.fsencode(unit)))
    while len(os.fsencode(exact)) < queue_role.MAX_WORKSPACE:
        exact += "a"
    over = exact + "b"
    assert len(exact) <= queue_role.MAX_WORKSPACE and len(os.fsencode(exact)) == queue_role.MAX_WORKSPACE
    assert len(over) <= queue_role.MAX_WORKSPACE and len(os.fsencode(over)) > queue_role.MAX_WORKSPACE
    return exact, over


@pytest.mark.parametrize("arguments", [[], ["alpha", "extra"], ["../alpha"],
    ["token=private-value"], ["alpha\n"], ["x" * 65], ["--role=orchestrator"],
    "token=private-value", [None], [{"id": "token=private-value"}]],
    ids=["none", "two", "dotdot", "secret", "newline", "long", "option", "string", "null-item", "mapping"])
def test_owner_launch_closed_arguments(arguments, capsys):
    assert queue_owner.main(arguments) == 2
    err = capsys.readouterr().err
    assert err == _launch_err("invalid_arguments", _USAGE)
    assert queue_role.RoleRefusal("invalid_arguments").next_action not in err
    assert _SECRET not in err
    supplied = arguments if type(arguments) is list else [arguments]
    for item in supplied:
        if type(item) is str and len(item) > 3:
            assert item not in err


def test_owner_launch_stdio_public_surface(owner_factory, tmp_path, monkeypatch, capsys):
    role, root, path, workspace, policy = owner_factory()

    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    frames_in = b"".join((json.dumps(v) + "\n").encode() for v in requests)
    monkeypatch.setattr(server, "input_stream", lambda stream: io.BytesIO(frames_in))
    assert queue_owner.main(["alpha"]) == 0
    frames = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [t["name"] for t in frames[1]["result"]["tools"]] == ["aegis_team_queue", "aegis_team_queue_claim"]
    assert server._session_id is None


def test_owner_launch_failure_is_fixed(owner_factory, tmp_path, monkeypatch, capsys):
    role, root, path, workspace, policy = owner_factory()

    path.unlink()
    assert queue_owner.main(["alpha"]) == 1
    assert capsys.readouterr().err == _launch_err(
        "role_missing", queue_role.RoleRefusal("role_missing").next_action)
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setattr(server, "input_stream", lambda stream: io.BytesIO(b""))
    assert queue_owner.main(["alpha"]) == 0


@pytest.mark.parametrize("code", sorted(_issue_refusal_codes()))
def test_owner_launch_refusal_prints_code_and_fixed_sentence(monkeypatch, capsys, code):
    def refuse(registration):
        raise queue_role.RoleRefusal(code)

    monkeypatch.setattr(queue_role, "issue", refuse)
    registration = "sk" + "a" * 20
    assert queue_owner.main([registration]) == 1
    err = capsys.readouterr().err
    sentence = queue_role.launch_advice(code)
    assert sentence == _LAUNCH_SENTENCES[code]
    assert err == _launch_err(code, sentence)
    assert "\n" not in err[:-1] and "\r" not in err
    claim = queue_role.RoleRefusal(code).next_action
    if claim != sentence:
        assert claim not in err
    assert registration not in err
    assert _SECRET not in err


def test_launch_advice_covers_exactly_the_refusals_issue_can_raise():
    codes = _issue_refusal_codes()
    assert codes == set(_LAUNCH_SENTENCES)
    assert _launch_sentences_from_source() == _LAUNCH_SENTENCES
    for code, sentence in _LAUNCH_SENTENCES.items():
        assert queue_role.launch_advice(code) == sentence
        assert "\n" not in sentence and "\r" not in sentence and sentence == sentence.strip()
    for code in ("role_foreign", "role_forbidden", "queue_io_unavailable", "not-a-launch-code"):
        assert queue_role.launch_advice(code) == _LAUNCH_SENTENCES["role_io_unavailable"]
    assert queue_role.launch_advice("role_stale") == "Retry the launch."
    assert queue_role.launch_advice("role_lock_timeout") == (
        "Wait for the authority writer, then restart the queue connection.")
    assert queue_role.RoleRefusal("role_stale").next_action == _CLAIM_ONLY[0]
    assert queue_role.RoleRefusal("role_lock_timeout").next_action == _CLAIM_ONLY[1]
    assert queue_role.refusal("role_stale")["next_action"] == _CLAIM_ONLY[0]
    assert queue_role.refusal("role_lock_timeout")["next_action"] == _CLAIM_ONLY[1]
    for code in ("role_missing", "role_invalid", "role_io_unavailable", "unsupported_platform"):
        assert queue_role.launch_advice(code) == queue_role.RoleRefusal(code).next_action


def test_owner_launch_unexpected_error_is_fixed(monkeypatch, capsys):
    def boom(registration):
        raise OSError(_SECRET)

    monkeypatch.setattr(queue_role, "issue", boom)
    assert queue_owner.main(["alpha"]) == 1
    err = capsys.readouterr().err
    assert err == _launch_err(
        "role_io_unavailable", queue_role.RoleRefusal("role_io_unavailable").next_action)
    assert _SECRET not in err and "OSError" not in err and "Traceback" not in err


def test_owner_launch_unsupported_platform_uses_the_probe(monkeypatch, capsys):
    monkeypatch.setattr(queue_role, "supported", lambda: False)
    registration = "sk" + "b" * 20
    assert queue_owner.main([registration]) == 1
    err = capsys.readouterr().err
    assert err == _launch_err(
        "unsupported_platform", queue_role.RoleRefusal("unsupported_platform").next_action)
    assert registration not in err


def test_owner_launch_io_failure_uses_fixed_recovery(monkeypatch, capsys):
    monkeypatch.setattr(queue_role, "supported", lambda: True)

    def boom():
        raise OSError(_SECRET)

    monkeypatch.setattr(queue_role, "account_home", boom)
    assert queue_owner.main(["alpha"]) == 1
    err = capsys.readouterr().err
    assert err == _launch_err(
        "role_io_unavailable", queue_role.RoleRefusal("role_io_unavailable").next_action)
    assert _SECRET not in err and "OSError" not in err


def test_owner_launch_invalid_workspace_omits_the_path_and_retries(owner_factory, monkeypatch, capsys):
    role, root, path, workspace, policy = owner_factory()
    policy["workspace"] = "relative/" + _SECRET + "\n/etc"
    path.write_text(json.dumps(policy), encoding="utf-8")
    assert queue_owner.main(["alpha"]) == 1
    err = capsys.readouterr().err
    assert err == _launch_err("role_invalid", queue_role.RoleRefusal("role_invalid").next_action)
    assert _SECRET not in err and "relative" not in err and "Traceback" not in err
    policy["workspace"] = str(workspace)
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setattr(server, "input_stream", lambda stream: io.BytesIO(b""))
    assert queue_owner.main(["alpha"]) == 0


@pytest.mark.parametrize("workspace", ["/srv/café", "/srv/工作"], ids=["cafe", "cjk"])
def test_policy_accepts_unicode_workspace_spellings(workspace):
    policy = _registration(workspace)
    assert queue_role._policy(policy, "alpha") is policy
    assert policy["workspace"] == workspace


def test_endpoint_and_role_stay_ascii_beside_a_unicode_workspace():
    assert queue_role._policy(_registration("/srv/café"), "alpha")["workspace"] == "/srv/café"
    for field, value in (("endpoint", "a/café"), ("role", "orchestratér")):
        policy = _registration("/srv/工作")
        policy[field] = value
        with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
            queue_role._policy(policy, "alpha")
        assert caught.value.args == ("role_invalid",)
        assert "caf" not in str(caught.value) and value not in str(caught.value)
    policy = _registration("/srv/café")
    policy["lanes"] = {"café": policy["lanes"]["alpha"]}
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
        queue_role._policy(policy, "alpha")
    assert "caf" not in str(caught.value)


@pytest.mark.parametrize("kind,workspace", [
    ("c0-nul", "/srv/" + _SECRET + "\x00"),
    ("c0-lf", "/srv/café\n/srv/工作"),
    ("c0-cr", "/srv/café\r"),
    ("c0-tab", "/srv/café\t"),
    ("c0-esc", "/srv/café\x1b"),
    ("del", "/srv/café\x7f"),
    ("c1", "/srv/café\x85"),
    ("c1-end", "/srv/café\x9f"),
    ("surrogate", "/srv/café\ud800"),
    ("surrogate-dcff", "/srv/\udcff"),
    ("relative", "srv/café"),
    ("dotdot", "/srv/../café"),
    ("dotdot-tail", "/srv/café/.."),
    ("empty", ""),
    ("bytes", b"/srv/cafe"),
    ("none", None),
    ("over-chars", "/" + "Q" * queue_role.MAX_WORKSPACE),
], ids=["c0-nul", "c0-lf", "c0-cr", "c0-tab", "c0-esc", "del", "c1", "c1-end",
        "surrogate", "surrogate-dcff", "relative", "dotdot", "dotdot-tail", "empty",
        "bytes", "none", "over-chars"])
def test_workspace_grammar_refusals_omit_the_path(kind, workspace):
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
        queue_role._policy(_registration(workspace), "alpha")
    assert caught.value.args == ("role_invalid",)
    text = str(caught.value)
    assert _SECRET not in text and "caf" not in text and "QQQQ" not in text
    if type(workspace) is str and workspace:
        assert workspace not in text


def test_workspace_grammar_rejects_encoded_overflow_and_then_accepts():
    exact, over = _encoded_boundary()
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
        queue_role._policy(_registration(over), "alpha")
    assert caught.value.args == ("role_invalid",) and over not in str(caught.value)
    policy = _registration(exact)
    assert queue_role._policy(policy, "alpha")["workspace"] == exact
    policy["workspace"] = "/srv/../" + _SECRET
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$"):
        queue_role._policy(policy, "alpha")
    policy["workspace"] = "/srv/café"
    assert queue_role._policy(policy, "alpha")["workspace"] == "/srv/café"


def test_unencodable_workspace_is_role_invalid_without_echo(monkeypatch):
    def fail(value):
        raise UnicodeEncodeError("utf-8", "x", 0, 1, "unencodable")

    monkeypatch.setattr(queue_role, "_fsencode", fail)
    workspace = "/srv/café-" + _SECRET
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
        queue_role._policy(_registration(workspace), "alpha")
    assert caught.value.args == ("role_invalid",)
    assert workspace not in str(caught.value) and "unencodable" not in str(caught.value)
    monkeypatch.setattr(queue_role, "_fsencode", os.fsencode)
    assert queue_role._policy(_registration("/srv/工作"), "alpha")["workspace"] == "/srv/工作"


def test_unicode_workspace_is_identity_pinned(owner_factory):
    role, root, path, workspace, policy = owner_factory()
    for name in ("café", "工作"):
        directory = workspace.parent / name
        directory.mkdir()
        policy["workspace"] = str(directory)
        raw = json.dumps(policy).encode("utf-8")
        path.write_bytes(raw)
        role.issue("alpha")
        grant = role.bind("alpha")
        info = directory.stat()
        assert grant.workspace_pin[1] == (info.st_dev, info.st_ino)
        assert path.read_bytes() == raw
        sessions = root / "sessions"
        for child in sessions.iterdir():
            child.unlink()


def test_unicode_workspace_symlink_replacement_does_not_rebind(owner_factory, tmp_path):
    from conftest import symlink_or_skip

    role, root, path, workspace, policy = owner_factory()
    directory = tmp_path / "café"
    decoy = tmp_path / "decoy"
    directory.mkdir()
    decoy.mkdir()
    policy["workspace"] = str(directory)
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)
    role.issue("alpha")
    pinned = role.bind("alpha").workspace_pin[1]
    info = directory.stat()
    assert pinned == (info.st_dev, info.st_ino)
    assert pinned != (decoy.stat().st_dev, decoy.stat().st_ino)
    held = directory.with_name("café-held")
    directory.rename(held)
    symlink_or_skip(decoy, directory, target_is_directory=True)
    with pytest.raises(role.RoleRefusal, match="^role_invalid$") as caught:
        role.bind("alpha")
    assert caught.value.args == ("role_invalid",)
    assert "decoy" not in str(caught.value) and "café" not in str(caught.value)
    directory.unlink()
    held.rename(directory)
    assert role.bind("alpha").workspace_pin[1] == pinned


def _collapsed_spelling(workspace):
    """The POSIX form _workspace_path hands to the core spelling predicate."""
    from pathlib import PurePosixPath

    return PurePosixPath("/", *PurePosixPath(workspace).parts[1:]).as_posix()


@pytest.mark.parametrize("workspace", ["/tmp/café\\..", "/srv/café:..", "/a" * 257],
                         ids=["backslash-dot-dot", "colon-dot-dot", "separator-cap"])
def test_workspace_spelling_matches_the_core_predicate(workspace):
    from aegis_core.team_queue import valid_workspace_spelling

    collapsed = _collapsed_spelling(workspace)
    assert valid_workspace_spelling(collapsed) is False
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
        queue_role._policy(_registration(workspace), "alpha")
    assert caught.value.args == ("role_invalid",)
    assert workspace not in str(caught.value) and collapsed not in str(caught.value)
    assert "caf" not in str(caught.value)


@pytest.mark.parametrize("workspace", ["/srv/café", "/a" * 256], ids=["cafe", "separator-bound"])
def test_core_accepted_spellings_stay_valid(workspace):
    from aegis_core.team_queue import valid_workspace_spelling

    assert valid_workspace_spelling(_collapsed_spelling(workspace)) is True
    assert queue_role._policy(_registration(workspace), "alpha")["workspace"] == workspace


def _rejected_directory(parent, kind):
    if kind == "separator-cap":
        directory = parent
        for _ in range(257):
            directory = directory / "a"
            directory.mkdir()
        return directory
    directory = parent / ("café\\.." if kind == "backslash-dot-dot" else "café:..")
    directory.mkdir()
    return directory


@pytest.mark.parametrize("kind", ["backslash-dot-dot", "colon-dot-dot", "separator-cap"])
def test_core_spelling_refusal_prints_role_invalid_and_creates_nothing(owner_factory, monkeypatch, capsys, kind):
    role, root, path, workspace, policy = owner_factory()
    bad = _rejected_directory(workspace.parent, kind)
    policy["workspace"] = str(bad)
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setattr(server, "input_stream", lambda stream: io.BytesIO(b""))
    assert queue_owner.main(["alpha"]) == 1
    err = capsys.readouterr().err
    assert err == _launch_err("role_invalid", queue_role.launch_advice("role_invalid"))
    assert str(bad) not in err and "café" not in err and "/a/a/a" not in err
    assert not (root / "sessions").exists()
    assert not (bad / ".aegis" / "state").exists()


def test_unicode_workspace_launch_list_and_claim(owner_factory, monkeypatch, capsys):
    import shutil
    import subprocess

    from aegis_core import team_queue

    role, root, path, workspace, policy = owner_factory()
    cafe = workspace.parent / "café"
    workspace.rename(cafe)
    policy["workspace"] = str(cafe)
    path.write_bytes(json.dumps(policy).encode("utf-8"))
    path.chmod(0o600)
    assert not (cafe / ".aegis" / "state").exists()
    assert queue_role._policy(_registration("/srv/café"), "alpha")["workspace"] == "/srv/café"
    # List and claim need a git workspace. A missing git skips only that half,
    # the same way require_store does, and launch must still create no queue state.
    if not team_queue.descriptor_supported() or shutil.which("git") is None:
        monkeypatch.setattr(server, "input_stream", lambda stream: io.BytesIO(b""))
        assert queue_owner.main(["alpha"]) == 0
        captured = capsys.readouterr()
        assert list((root / "sessions").glob("*.json"))
        assert not (cafe / ".aegis" / "state").exists()
        assert "café" not in captured.err and "Traceback" not in captured.err
        return
    subprocess.run(["git", "init", "-q", str(cafe)], check=True)
    added = team_queue.add(cafe, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": ["core"]})
    assert not added["refused"], added
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    frames_in = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "aegis_team_queue", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "aegis_team_queue_claim", "arguments": arguments}},
    ]
    blob = b"".join((json.dumps(item) + "\n").encode() for item in frames_in)
    monkeypatch.setattr(server, "input_stream", lambda stream: io.BytesIO(blob))
    assert queue_owner.main(["alpha"]) == 0
    captured = capsys.readouterr()
    frames = [json.loads(line) for line in captured.out.splitlines()]
    assert [frame["id"] for frame in frames] == [1, 2, 3]
    listed = json.loads(frames[1]["result"]["content"][0]["text"])
    claimed = json.loads(frames[2]["result"]["content"][0]["text"])
    assert frames[1]["result"]["isError"] is False and frames[2]["result"]["isError"] is False
    assert [item["id"] for item in listed["items"]] == ["ONE"]
    assert not claimed["refused"], claimed
    assert claimed["item"]["lane"] == "alpha"
    assert list((root / "sessions").glob("*.json"))
    assert (cafe / ".aegis" / "state").is_dir()
    assert "café" not in captured.err and "Traceback" not in captured.err
