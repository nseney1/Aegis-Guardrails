"""aegis-mcp binds every tools/call through the AD-4 resolver (host-matrix §3.6).

Driven over stdio with an isolated HOME. The model never names the workspace: the
pin, the host's attestations (Codex per-call ``_meta``, CLAUDE_PROJECT_DIR, MCP roots),
the registry the call's files select from, and a bounded walk-up from the server cwd
do. Disagreement is a machine-readable hold; nothing resolved serves the read-only
user layer (H8) to aegis_scan and "not governed here" to the other tools.
"""
from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

import aegis_mcp.server as server
from aegis_core.yaml_engine.serializer import dump_frontmatter
from tests.conftest import symlink_or_skip

NOT_GOVERNED = 'not an Aegis workspace: run "aegis init" in your repository'


@pytest.mark.parametrize("name", ["aegis_scan", "aegis_list_rules", "unknown_tool"])
@pytest.mark.parametrize("transport", ["direct", "concurrent", "stdio", "stdio_dispatch"])
def test_failure_envelope_golden_bytes(home, monkeypatch, capsys, record_property, name, transport):
    """Golden transport bytes, with a deterministic external traceback sink."""
    from aegis_core.workspace.binding import WorkspaceBinding

    text = "bad\x1btext\nretry"
    projected = "bad text retry"

    def refuse(*args, **kwargs):
        raise OSError(text)

    def print_traceback(*, file):
        assert sys.exc_info()[0] is OSError
        print("Traceback (most recent call last):\nOSError: " + text, file=file)

    monkeypatch.setattr(server, "traceback", SimpleNamespace(print_exc=print_traceback))
    monkeypatch.setattr(server, "_bind", lambda *args: WorkspaceBinding("unbound", reason="no_workspace")
                        if name == "aegis_scan" else WorkspaceBinding("bound", root=str(home), source="test"))
    monkeypatch.setattr(server, "_workspace_for", lambda binding: home)
    monkeypatch.setattr(server, "execute_tool", refuse)
    if transport == "stdio_dispatch":
        monkeypatch.setattr(server, "_bind", refuse)
    calls = [_call(1, name, {}), _call(2, name, {}), _frame(3, "ping")]
    if transport in ("direct", "concurrent"):
        server.handle_request(json.loads(_init()))
        if transport == "concurrent":
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=2) as pool:
                responses = list(pool.map(server.handle_request, map(json.loads, calls)))
        else:
            responses = [server.handle_request(json.loads(line)) for line in calls]
        captured = capsys.readouterr()
        output = "".join(json.dumps(response) + "\n" for response in responses)
        assert captured.out == ""
    else:
        monkeypatch.setattr(server, "sys", SimpleNamespace(stdin=io.StringIO(
            "\n".join([_init()] + calls) + "\n"), stdout=sys.stdout, stderr=sys.stderr))
        assert server.run_stdio_server() == 0
        captured = capsys.readouterr()
        output = "\n".join(captured.out.splitlines()[1:]) + "\n"
    if name == "unknown_tool":
        expected = [{"jsonrpc": "2.0", "id": req_id, "error": {
            "code": -32602, "message": "Unknown tool: unknown_tool"}} for req_id in (1, 2)]
        diagnostic = ""
    elif transport == "stdio_dispatch":
        expected = [{"jsonrpc": "2.0", "id": req_id, "error": {
            "code": -32603, "message": "Internal error"}} for req_id in (1, 2)]
        diagnostic = ("aegis-mcp: " + projected + "\n" if name == "aegis_scan" else
                      "Traceback (most recent call last):\nOSError: " + text + "\n") * 2
    else:
        message = projected if name == "aegis_scan" else text
        expected = [{"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": "Tool execution failed: " + message}], "isError": True}}
                    for req_id in (1, 2)]
        diagnostic = ("aegis-mcp: " + projected + "\n" if name == "aegis_scan" else
                      "Traceback (most recent call last):\nOSError: " + text + "\n") * 2
    expected.append({"jsonrpc": "2.0", "id": 3, "result": {}})
    assert output.encode("utf-8") == ("".join(json.dumps(row) + "\n" for row in expected)).encode("utf-8")
    assert captured.err.encode("utf-8") == diagnostic.encode("utf-8")
    record_property("stdout_hex", output.encode("utf-8").hex())
    record_property("stderr_hex", captured.err.encode("utf-8").hex())


@pytest.mark.parametrize("transport", ["direct", "stdio", "stdio_dispatch"])
@pytest.mark.parametrize("name", list(getattr(server, "_TOOL_FAILURE_ENVELOPES", {None: str, "aegis_scan": str})))
def test_failure_envelope_table_controls_each_transport(home, monkeypatch, capsys, name, transport):
    # Every declared row must drive both catches, including the default for other tools.
    table = server._TOOL_FAILURE_ENVELOPES
    monkeypatch.setattr(server, "_TOOL_FAILURE_ENVELOPES", {**table, name: lambda text: "table diagnostic"})
    from aegis_core.workspace.binding import WorkspaceBinding

    def refuse(*args, **kwargs):
        raise OSError("original failure")

    monkeypatch.setattr(server, "_bind", lambda *args: WorkspaceBinding("bound", root=home, source="test"))
    monkeypatch.setattr(server, "_workspace_for", lambda binding: home)
    monkeypatch.setattr(server, "execute_tool", refuse)
    if transport == "stdio_dispatch":
        monkeypatch.setattr(server, "_bind", refuse)
    request = _call(1, name or "aegis_list_rules", {})
    if transport == "direct":
        server.handle_request(json.loads(_init()))
        response = server.handle_request(json.loads(request))
        assert response["result"]["content"][0]["text"] == "Tool execution failed: table diagnostic"
    else:
        monkeypatch.setattr(server, "sys", SimpleNamespace(stdin=io.StringIO(
            _init() + "\n" + request + "\n"), stdout=sys.stdout, stderr=sys.stderr))
        assert server.run_stdio_server() == 0
    captured = capsys.readouterr()
    assert captured.err == "aegis-mcp: table diagnostic\n"


def test_non_scan_failure_keeps_real_traceback(home, monkeypatch, capsys):
    from aegis_core.workspace.binding import WorkspaceBinding

    def refuse(*args):
        raise OSError("raw\x1bfailure\nretry")

    monkeypatch.setattr(server, "_bind", lambda *args: WorkspaceBinding("bound", root=home, source="test"))
    monkeypatch.setattr(server, "_workspace_for", lambda binding: home)
    monkeypatch.setattr(server, "execute_tool", refuse)
    server.handle_request(json.loads(_init()))
    response = server.handle_request(json.loads(_call(1, "aegis_list_rules", {})))
    assert response["result"]["content"][0]["text"] == "Tool execution failed: raw\x1bfailure\nretry"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("Traceback (most recent call last):\n")
    assert captured.err.endswith("OSError: raw\x1bfailure\nretry\n")
    assert ", line 629, in _finish_repository_call\n" in captured.err


@pytest.mark.parametrize("transport", ["direct", "stdio_dispatch"])
def test_non_scan_failure_preserves_exception_formatting(home, monkeypatch, capsys, transport):
    from aegis_core.workspace.binding import WorkspaceBinding

    class DisplayError(OSError):
        def __str__(self):
            raise AssertionError("exception string unavailable")

        def __format__(self, spec):
            assert spec == ""
            return "formatted failure"

    def refuse(*args):
        raise DisplayError()

    monkeypatch.setattr(server, "_bind", lambda *args: WorkspaceBinding("bound", root=home, source="test"))
    monkeypatch.setattr(server, "_workspace_for", lambda binding: home)
    monkeypatch.setattr(server, "execute_tool", refuse)
    request = _call(1, "aegis_list_rules", {})
    if transport == "direct":
        server.handle_request(json.loads(_init()))
        response = server.handle_request(json.loads(request))
        assert response["result"]["content"][0]["text"] == "Tool execution failed: formatted failure"
    else:
        monkeypatch.setattr(server, "_bind", refuse)
        monkeypatch.setattr(server, "sys", SimpleNamespace(stdin=io.StringIO(
            _init() + "\n" + request + "\n"), stdout=sys.stdout, stderr=sys.stderr))
        assert server.run_stdio_server() == 0
    captured = capsys.readouterr()
    assert captured.err.startswith("Traceback (most recent call last):\n")
    expected_exception = "".join(traceback.format_exception_only(DisplayError, DisplayError()))
    assert captured.err.endswith(expected_exception)
    if transport == "stdio_dispatch":
        assert json.loads(captured.out.splitlines()[-1])["error"] == {"code": -32603, "message": "Internal error"}


def _tree(root: Path) -> list:
    out = []
    for dirpath, dirs, files in os.walk(root):
        for name in dirs:
            out.append((Path(dirpath, name).relative_to(root).as_posix() + "/", ""))
        for name in files:
            full = Path(dirpath, name)
            out.append((full.relative_to(root).as_posix(), hashlib.sha256(full.read_bytes()).hexdigest()))
    return sorted(out)


def _rule(root: Path, rule_id: str, target: str = "src/*.py", folder: str = "traps", kind: str = "trap") -> None:
    rules = root / ".aegis" / "rules" / folder
    rules.mkdir(parents=True, exist_ok=True)
    fm = {"id": rule_id, "type": kind, "target_paths": [target], "hypothesis": f"h-{rule_id}", "prediction": "p"}
    (rules / f"{rule_id}.md").write_text(dump_frontmatter(fm, body="Body\n"), encoding="utf-8")


def _governed(root: Path, rule_id: str) -> Path:
    _rule(root, rule_id)
    (root / ".git").mkdir(exist_ok=True)
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return root.resolve()


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    monkeypatch.chdir(home)
    return home.resolve()


def _frame(req_id, method, params=None):
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _init(client="codex-mcp-client", capabilities=None):
    return _frame(0, "initialize", {"clientInfo": {"name": client, "version": "1"}, "capabilities": capabilities or {}})


def _call(req_id, name, arguments, meta=None):
    params = {"name": name, "arguments": arguments}
    if meta is not None:
        params["_meta"] = meta
    return _frame(req_id, "tools/call", params)


def _codex_meta(*roots: Path) -> dict:
    return {"x-codex-turn-metadata": {"session_id": "s", "workspaces": {str(r): {"has_changes": True} for r in roots}}}


def _serve(monkeypatch, capsys, lines, *, capture=False):
    monkeypatch.setattr("sys.stdin", io.StringIO("".join(f"{line}\n" for line in lines)))
    assert server.run_stdio_server() == 0
    captured = capsys.readouterr()
    frames = [json.loads(line) for line in captured.out.splitlines() if line.strip()]
    results = {f.get("id"): f for f in frames if "method" not in f}
    return (results, captured) if capture else results


def _payload(frame):
    return frame["result"]["isError"], json.loads(frame["result"]["content"][0]["text"])


def _registry(home: Path, *roots: Path) -> None:
    (home / ".aegis").mkdir(exist_ok=True)
    (home / ".aegis" / "workspaces.json").write_text(json.dumps({
        "v": 1, "workspaces": [{"root": str(r), "added_at": "2026-10-15T00:00:00Z", "added_by": "aegis init", "hosts": []}
                               for r in roots],
    }), encoding="utf-8")


# ── host-attested binding ────────────────────────────────────────────────────

def test_codex_meta_binds_each_call_to_its_workspace(home, tmp_path, monkeypatch, capsys):
    a = _governed(tmp_path / "a", "rule-a")
    b = _governed(tmp_path / "b", "rule-b")

    frames = _serve(monkeypatch, capsys, [
        _init(),
        _call(1, "aegis_list_rules", {}, _codex_meta(a)),
        _call(2, "aegis_list_rules", {}, _codex_meta(b)),
    ])

    assert {r["_name"] for r in _payload(frames[1])[1]["rules"]} == {"rule-a"}
    assert {r["_name"] for r in _payload(frames[2])[1]["rules"]} == {"rule-b"}


def test_claude_project_dir_binds_and_a_model_workspace_argument_is_ignored(home, tmp_path, monkeypatch, capsys):
    project = _governed(tmp_path / "project", "rule-project")
    other = _governed(tmp_path / "other", "rule-other")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))

    frames = _serve(monkeypatch, capsys, [_init("claude-code"), _call(1, "aegis_list_rules", {"workspace": str(other)})])

    assert {r["_name"] for r in _payload(frames[1])[1]["rules"]} == {"rule-project"}


def test_mcp_roots_bind_once_the_client_answers(home, tmp_path, monkeypatch, capsys):
    root = _governed(tmp_path / "rooted", "rule-rooted")
    initialized = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    roots_reply = json.dumps({"jsonrpc": "2.0", "id": "aegis-roots-1", "result": {"roots": [{"uri": root.as_uri()}]}})

    frames = _serve(monkeypatch, capsys, [
        _init("claude-code", {"roots": {"listChanged": True}}), initialized, roots_reply,
        _call(1, "aegis_list_rules", {}),
    ])

    assert {r["_name"] for r in _payload(frames[1])[1]["rules"]} == {"rule-rooted"}


@pytest.mark.parametrize("uri", ["file://evil.example/etc", "file://evil.example{root}"], ids=["etc", "governed"])
def test_a_roots_answer_naming_a_remote_host_is_ignored(home, tmp_path, monkeypatch, capsys, uri):
    """A ``file://host/...`` root lives on another machine; read locally it could name any directory."""
    root = _governed(tmp_path / "rooted", "rule-rooted")
    initialized = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    remote = uri.format(root="/" + root.as_posix().lstrip("/"))
    roots_reply = json.dumps({"jsonrpc": "2.0", "id": "aegis-roots-1", "result": {"roots": [{"uri": remote}]}})

    frames = _serve(monkeypatch, capsys, [
        _init("claude-code", {"roots": {"listChanged": True}}), initialized, roots_reply,
        _call(1, "aegis_list_rules", {}),
    ])

    is_error, payload = _payload(frames[1])
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


def test_a_relative_codex_meta_workspace_is_ignored(home, tmp_path, monkeypatch, capsys):
    """Only absolute host roots attest a session; a relative one would resolve against the server cwd."""
    cwd = tmp_path / "cwd"
    (cwd / ".git").mkdir(parents=True)
    _governed(cwd / "a", "rule-a")
    monkeypatch.chdir(cwd)

    frames = _serve(monkeypatch, capsys, [
        _init(), _call(1, "aegis_list_rules", {}, {"x-codex-turn-metadata": {"workspaces": {"a": {}}}}),
    ])

    is_error, payload = _payload(frames[1])
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


def test_several_host_roots_choose_by_the_files_and_otherwise_hold(home, tmp_path, monkeypatch, capsys):
    a = _governed(tmp_path / "a", "rule-a")
    b = _governed(tmp_path / "b", "rule-b")

    frames = _serve(monkeypatch, capsys, [
        _init(),
        _call(1, "aegis_scan", {"files": [str(b / "src" / "app.py")]}, _codex_meta(a, b)),
        _call(2, "aegis_scan", {}, _codex_meta(a, b)),
    ])

    is_error, first = _payload(frames[1])
    assert not is_error and [r["name"] for r in first["relevant_rules"]] == ["rule-b"]
    is_error, second = _payload(frames[2])
    assert is_error
    assert (second["status"], second["reason"]) == ("hold", "ambiguous_host_roots")
    assert second["binding"]["details"]["candidates"] == [str(a), str(b)]


# ── operator pin ─────────────────────────────────────────────────────────────

def test_a_pin_that_disagrees_with_the_host_holds_and_writes_nothing(home, tmp_path, monkeypatch, capsys):
    pinned = _governed(tmp_path / "pinned", "rule-pinned")
    other = _governed(tmp_path / "other", "rule-other")
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pinned))
    before = (_tree(pinned), _tree(other))

    frames = _serve(monkeypatch, capsys, [
        _init(),
        _call(1, "aegis_scan", {"files": ["src/app.py"]}, _codex_meta(other)),
        _call(2, "aegis_report_outcome", {"outcome": "tp", "rules_used": ["rule-pinned"], "idempotency_key": "k"},
              _codex_meta(other)),
    ])

    for req_id in (1, 2):
        is_error, payload = _payload(frames[req_id])
        assert is_error
        assert payload["status"] == "hold"
        assert payload["reason"] == "pin_conflicts_with_host_root"
        assert payload["binding"]["details"] == {"pin": str(pinned), "host_roots": [str(other)]}
    assert (_tree(pinned), _tree(other)) == before


@pytest.mark.parametrize("case,reason", [("plain", "pin_not_a_workspace"), ("missing", "pin_missing"), ("home", "pin_denied")])
def test_an_unusable_pin_puts_the_server_in_an_error_state(home, tmp_path, monkeypatch, capsys, case, reason):
    plain = tmp_path / "plain"
    plain.mkdir()
    pin = {"plain": plain, "missing": tmp_path / "missing", "home": home}[case]
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pin))
    _governed(tmp_path / "cwd", "rule-cwd")
    monkeypatch.chdir(tmp_path / "cwd")  # the pin is final: no fallback to the cwd
    before = (_tree(home), _tree(plain))

    frames = _serve(monkeypatch, capsys, [
        _init(), _frame(1, "tools/list"),
        _call(2, "aegis_list_rules", {}), _call(3, "aegis_scan", {"files": ["src/app.py"]}),
    ])

    assert frames[1]["result"]["tools"]
    for req_id in (2, 3):
        is_error, payload = _payload(frames[req_id])
        assert is_error
        assert payload["status"] == "FAIL"
        binding = payload["binding"]
        assert (binding["status"], binding["reason"], binding["source"], binding["root"]) == ("error", reason, "pin", None)
        assert f"AEGIS_WORKSPACE is set to {pin}" in payload["error"]
    assert (_tree(home), _tree(plain)) == before


# ── registry and walk-up ─────────────────────────────────────────────────────

def test_absolute_files_select_a_registered_workspace_for_antigravity(home, tmp_path, monkeypatch, capsys):
    a = _governed(tmp_path / "a", "rule-a")
    b = _governed(tmp_path / "b", "rule-b")
    _registry(home, a, b)

    frames = _serve(monkeypatch, capsys, [_init("antigravity-client"), _call(1, "aegis_scan", {"files": [str(b / "src" / "app.py")]})])

    is_error, payload = _payload(frames[1])
    assert not is_error
    assert [r["name"] for r in payload["relevant_rules"]] == ["rule-b"]


def test_relative_files_in_two_registered_workspaces_follow_the_server_cwd(home, tmp_path, monkeypatch, capsys):
    a = _governed(tmp_path / "a", "rule-a")
    b = _governed(tmp_path / "b", "rule-b")
    _registry(home, a, b)
    monkeypatch.chdir(a)

    frames = _serve(monkeypatch, capsys, [_init("antigravity-client"), _call(1, "aegis_scan", {"files": ["src/app.py"]})])

    is_error, payload = _payload(frames[1])
    assert not is_error, payload
    assert [r["name"] for r in payload["relevant_rules"]] == ["rule-a"]


def test_the_server_cwd_walks_up_to_its_workspace(home, tmp_path, monkeypatch, capsys):
    root = _governed(tmp_path / "repo", "rule-repo")
    monkeypatch.chdir(root / "src")

    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_list_rules", {})])

    assert {r["_name"] for r in _payload(frames[1])[1]["rules"]} == {"rule-repo"}


# ── not governed here (H8) ───────────────────────────────────────────────────

def test_unbound_scan_serves_the_read_only_user_layer(home, monkeypatch, capsys):
    _rule(home, "user-rule", target="**/*.py")
    _rule(home, "user-other", target="docs/*.md")
    before = _tree(home)

    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {"files": ["src/app.py"]})])

    is_error, payload = _payload(frames[1])
    assert not is_error
    assert payload["status"] == "not_governed"
    assert payload["message"] == NOT_GOVERNED
    assert payload["user_layer"] == {"path": str(home / ".aegis" / "rules"), "rules": 2}
    assert [r["name"] for r in payload["relevant_rules"]] == ["user-rule"]
    assert "user-rule" in payload["guidance"]
    assert _tree(home) == before


def test_unbound_scan_without_a_user_layer_creates_nothing(home, monkeypatch, capsys):
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {"files": ["a.py"]}), _call(2, "aegis_scan", {})])

    for req_id in (1, 2):
        is_error, payload = _payload(frames[req_id])
        assert not is_error
        assert payload["status"] == "not_governed"
        assert payload["relevant_rules"] == []
        assert payload["user_layer"] == {"path": str(home / ".aegis" / "rules"), "rules": 0}
    assert _tree(home) == []


@pytest.mark.parametrize("name,arguments", [
    ("aegis_list_rules", {}),
    ("aegis_create_rule", {"description": "x"}),
    ("aegis_report_outcome", {"outcome": "tp", "rules_used": ["user-rule"], "idempotency_key": "k"}),
])
def test_unbound_tools_other_than_scan_answer_not_governed(home, monkeypatch, capsys, name, arguments):
    _rule(home, "user-rule", target="**/*.py")
    before = _tree(home)

    frames = _serve(monkeypatch, capsys, [_init(), _call(1, name, arguments)])

    is_error, payload = _payload(frames[1])
    assert is_error
    assert payload["status"] == "not_governed"
    assert payload["error"] == NOT_GOVERNED
    assert payload["binding"]["reason"] == "no_workspace"
    assert _tree(home) == before


def test_one_workspace_object_serves_every_call_bound_to_the_same_root_and_source(home, tmp_path, monkeypatch, capsys):
    import aegis_mcp.handlers.governance as governance

    root = _governed(tmp_path / "repo", "rule-repo")
    seen = []
    real = governance.list_rules

    def spy(workspace, rule_type=None):
        seen.append(workspace)
        return real(workspace, rule_type=rule_type)

    monkeypatch.setattr(governance, "list_rules", spy)
    _serve(monkeypatch, capsys, [_init(), *(_call(i, "aegis_list_rules", {}, _codex_meta(root)) for i in range(1, 4))])

    assert len(seen) == 3 and seen[0].root == root
    assert all(ws is seen[0] for ws in seen)


# ── attestation is per host and never the model's ────────────────────────────

@pytest.mark.parametrize("client", ["claude-code", "some-other-client"])
def test_codex_turn_metadata_from_another_client_is_ignored(home, tmp_path, monkeypatch, capsys, client):
    other = _governed(tmp_path / "other", "rule-other")

    frames = _serve(monkeypatch, capsys, [_init(client), _call(1, "aegis_list_rules", {}, _codex_meta(other))])

    is_error, payload = _payload(frames[1])
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


@pytest.mark.parametrize("client", ["codex-mcp-client", "some-other-client"])
def test_an_inherited_claude_project_dir_under_another_client_is_ignored(home, tmp_path, monkeypatch, capsys, client):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(_governed(tmp_path / "other", "rule-other")))

    frames = _serve(monkeypatch, capsys, [_init(client), _call(1, "aegis_list_rules", {})])

    is_error, payload = _payload(frames[1])
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


def test_a_model_supplied_meta_argument_is_never_host_attestation(home, tmp_path, monkeypatch, capsys):
    other = _governed(tmp_path / "other", "rule-other")

    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_list_rules", {"_meta": _codex_meta(other)})])

    is_error, payload = _payload(frames[1])
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


# ── the registry is re-read when it changes ──────────────────────────────────

def test_a_registry_rewritten_mid_session_is_read_on_the_next_call(home, tmp_path, monkeypatch, capsys):
    a = _governed(tmp_path / "a", "rule-a")
    b = _governed(tmp_path / "b", "rule-b")
    _registry(home, a)
    scan_b = {"files": [str(b / "src" / "app.py")]}

    before_refresh = _init("antigravity-client") + "\n" + _call(1, "aegis_scan", scan_b) + "\n"

    class RefreshingInput(io.StringIO):
        def readline(self, size=-1):
            assert size > 0
            if self.tell() == len(before_refresh):
                _registry(home, a, b)  # `aegis init` in b, from another process
            return super().readline(size)

    stream = RefreshingInput(before_refresh + _call(2, "aegis_scan", scan_b) + "\n")
    monkeypatch.setattr("sys.stdin", stream)
    assert server.run_stdio_server() == 0
    frames = {f["id"]: f for f in map(json.loads, capsys.readouterr().out.splitlines()) if "method" not in f}

    assert _payload(frames[1])[1]["status"] == "not_governed"
    assert [r["name"] for r in _payload(frames[2])[1]["relevant_rules"]] == ["rule-b"]


# ── unresolvable paths keep the server up ────────────────────────────────────

def _loop(where: Path) -> Path:
    """``where/l1 -> where/l2 -> where/l1``; skipped where symlinks cannot be made."""
    where.mkdir(parents=True, exist_ok=True)
    first, second = where / "l1", where / "l2"
    try:
        os.symlink(second, first)
        os.symlink(first, second)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    return first


def test_a_pin_through_a_symlink_loop_keeps_the_server_up_in_an_error_state(home, tmp_path, monkeypatch, capsys):
    pin = _loop(tmp_path / "links")
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pin))

    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_list_rules", {})])

    assert frames[0]["result"]["serverInfo"]["name"] == "aegis-mcp"
    is_error, payload = _payload(frames[1])
    assert is_error
    assert (payload["binding"]["status"], payload["binding"]["reason"]) == ("error", "pin_missing")


@pytest.mark.parametrize("params", [
    {"name": "no_such_tool", "arguments": {}},
    "not an object",
    {"name": "aegis_list_rules", "arguments": ["not", "an", "object"]},
], ids=["unknown_tool", "params_not_an_object", "arguments_not_an_object"])
def test_a_pin_error_answers_every_tool_call_before_its_params_are_read(home, tmp_path, monkeypatch, capsys, params):
    """While the pin is unusable the server says so first: nothing about the call can route around it."""
    monkeypatch.setenv("AEGIS_WORKSPACE", str(_loop(tmp_path / "links")))

    frames = _serve(monkeypatch, capsys, [_init(), _frame(1, "tools/call", params)])

    assert "error" not in frames[1], frames[1]
    is_error, payload = _payload(frames[1])
    assert is_error
    assert payload["status"] == "FAIL"
    assert (payload["binding"]["status"], payload["binding"]["reason"]) == ("error", "pin_missing")


def test_call_files_through_a_symlink_loop_answer_a_tool_result(home, tmp_path, monkeypatch, capsys):
    a = _governed(tmp_path / "a", "rule-a")
    _loop(a)
    _registry(home, a)
    files = [[str(a / "l1" / "x.py")], ["l1/x.py"]]

    frames = _serve(monkeypatch, capsys, [
        _init("antigravity-client"),
        *(_call(i, "aegis_scan", {"files": f}) for i, f in enumerate(files, 1)),
    ])

    for req_id in (1, 2):
        assert "error" not in frames[req_id], frames[req_id]
        assert frames[req_id]["result"]["content"][0]["type"] == "text"


def test_call_files_through_a_symlink_loop_in_a_bound_workspace_fail_cleanly(home, tmp_path, monkeypatch, capsys):
    a = _governed(tmp_path / "a", "rule-a")
    try:
        os.symlink(a / "src" / "loop", a / "src" / "loop")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    before = _tree(a / ".aegis")

    frames = _serve(monkeypatch, capsys, [
        _init(),
        _call(1, "aegis_scan", {"files": ["src/loop"]}, _codex_meta(a)),
        _call(2, "aegis_report_outcome", {"outcome": "tp", "rules_used": ["rule-a"], "idempotency_key": "k",
                                          "files": ["src/loop"]}, _codex_meta(a)),
    ])

    for req_id in (1, 2):
        text = frames[req_id]["result"]["content"][0]["text"]
        assert not text.startswith("Tool execution failed"), text
        payload = json.loads(text)
        if sys.version_info < (3, 13):  # 3.13 resolves a loop leniently and serves the call
            assert payload["status"] == "FAIL"
            assert "src/loop cannot be resolved" in payload["error"].replace("\\", "/")
    if sys.version_info < (3, 13):
        assert _tree(a / ".aegis") == before  # no ledger or activity row for a refused call


# ── the user layer (H8) ──────────────────────────────────────────────────────

def test_a_symlinked_user_rules_directory_is_never_served(home, tmp_path, monkeypatch, capsys):
    elsewhere = tmp_path / "elsewhere"
    _rule(elsewhere, "planted", target="**/*.py")
    (home / ".aegis").mkdir()
    try:
        os.symlink(elsewhere / ".aegis" / "rules", home / ".aegis" / "rules", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {"files": ["src/app.py"]})])

    is_error, payload = _payload(frames[1])
    assert not is_error
    assert payload["relevant_rules"] == []
    assert payload["user_layer"] == {"path": str(home / ".aegis" / "rules"), "rules": 0}


@pytest.mark.parametrize("case", ["missing", "unreadable", "symlink", "controls", pytest.param(
    "long", marks=pytest.mark.skipif(os.name == "nt", reason="the long paths exceed MAX_PATH"))])
def test_scan_dispatcher_and_startup_project_workspace_refusals(home, tmp_path, monkeypatch, capsys, case):
    from aegis_core.workspace import binding

    secret = "ghp_" + "S" * 30
    pin = tmp_path / (secret + ("\x1b[31m" if case == "controls" else ""))
    if case == "long":
        pin = tmp_path.joinpath(*(["x" * 100] * 16), secret)
    elif case == "symlink":
        link = tmp_path / ("link-" + secret)
        symlink_or_skip(pin, link, target_is_directory=True)
        pin = link
    elif case == "unreadable":
        pin.mkdir()
        resolve = binding._resolve

        def denied(path):
            if str(path) == str(pin):
                raise PermissionError("access denied: " + str(pin))
            return resolve(path)

        monkeypatch.setattr("aegis_core.workspace.binding._resolve", denied)
    monkeypatch.setattr(server, "env_workspace", lambda environ=None: str(pin))
    server._start()
    canonical = server._workspace_error
    before = canonical.as_dict()
    capsys.readouterr()
    frames, captured = _serve(monkeypatch, capsys, [
        _init(), _call(1, "aegis_scan", {"files": ["app.py"]}),
        _call(2, "aegis_scan", {"files": ["app.py"]}, _codex_meta(home)),
    ], capture=True)
    assert secret not in captured.out + captured.err and "\x1b" not in captured.err
    assert captured.err.startswith("aegis-mcp: AEGIS_WORKSPACE is set to ")
    assert len(captured.err.rstrip("\n")) <= len("aegis-mcp: ") + 1024
    for req_id in (1, 2):
        is_error, payload = _payload(frames[req_id])
        assert is_error and payload["status"] == "FAIL"
        assert payload["binding"]["reason"] == "pin_missing"
        assert payload["error"] == payload["binding"]["message"]
        assert payload["error"].startswith("AEGIS_WORKSPACE is set to ")
        assert len(payload["error"]) <= 1024
    # Only the display copy changes; the captured refusal remains canonical.
    assert str(pin) in canonical.message
    assert canonical.as_dict() == before


@pytest.mark.parametrize("case", ["missing", "unreadable", "symlink", pytest.param(
    "controls", marks=pytest.mark.skipif(os.name == "nt", reason="Windows file names refuse controls")), pytest.param(
    "long", marks=pytest.mark.skipif(os.name == "nt", reason="the long paths exceed MAX_PATH"))])
def test_scan_projects_a_workspace_that_becomes_unusable_after_startup(home, tmp_path, monkeypatch, capsys, case):
    from aegis_core.workspace import binding

    secret = "ghp_" + "B" * 30
    location = tmp_path / (secret + ("\x1b[31m" if case == "controls" else ""))
    if case == "long":
        location = tmp_path.joinpath(*(["x" * 100] * 16), secret)
    root = _governed(location, "rule-project")
    pin = root
    if case == "symlink":
        pin = tmp_path / ("alias-" + secret)
        symlink_or_skip(root, pin, target_is_directory=True)
    monkeypatch.setattr(server, "env_workspace", lambda environ=None: str(pin))
    server._start()
    server.handle_request(json.loads(_init()))
    assert server._workspace_error is None
    capsys.readouterr()
    if case == "unreadable":
        resolve = binding._resolve

        def denied(path):
            if str(path) == str(pin):
                raise PermissionError("access denied: " + str(pin))
            return resolve(path)

        monkeypatch.setattr("aegis_core.workspace.binding._resolve", denied)
    else:
        root.rename(tmp_path / "retained")
    # Both retries refuse rather than serving the user layer or a stale cached workspace.
    for req_id, meta in enumerate((None, _codex_meta(home)), 1):
        response = server.handle_request(json.loads(_call(req_id, "aegis_scan", {"files": ["src/app.py"]}, meta)))
        is_error, payload = _payload(response)
        assert is_error and payload["status"] == "FAIL"
        assert payload["binding"]["reason"] == "pin_missing"
        assert payload["error"] == payload["binding"]["message"]
        assert payload["error"].startswith("AEGIS_WORKSPACE is set to ")
        assert len(payload["error"]) <= 1024
        assert secret not in json.dumps(payload) and "\x1b" not in payload["error"]
    assert server._canonical_workspace == str(pin)


@pytest.mark.parametrize("status", ["hold", "error", "unbound"])
@pytest.mark.parametrize("name", ["ghp_" + "H" * 30, "bad\nname", "bad\x1bname", "x" * 5000],
                         ids=["token", "newline", "controls", "long"])
def test_scan_dispatcher_projects_complete_binding_envelopes(home, tmp_path, monkeypatch, capsys, status, name):
    from aegis_core.workspace.binding import WorkspaceBinding

    path = str(tmp_path / name)
    details = {key: path for key in ("pin", "target", "cwd", "cwd_root", "host_root", "registered_root")}
    details.update(host_roots=[path], candidates=[path])
    binding = WorkspaceBinding(status, root=Path(path), source=path, confidence=path,
                               reason="pin_conflicts_with_host_root", message=f"workspace {path} disagrees",
                               details=tuple(details.items()))
    before = binding.as_dict()
    # The dispatcher owns this resolver reference; no global OS function is patched.
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    # Unbound scans deliberately serve the user layer; another tool exercises its envelope.
    tool = "aegis_list_rules" if status == "unbound" else "aegis_scan"
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, tool, {}), _call(2, tool, {})])
    for req_id in (1, 2):
        is_error, payload = _payload(frames[req_id])
        assert is_error
        assert payload["status"] == {"hold": "hold", "error": "FAIL", "unbound": "not_governed"}[status]
        assert name not in json.dumps(payload)
        shown = payload["binding"]
        assert shown["reason"] == binding.reason
        assert shown["message"].startswith("AEGIS_WORKSPACE pins ")
        assert "disagrees" not in shown["message"]  # raw diagnostic prose is never interpolated
        for key in ("root", "source", "confidence", "message"):
            assert len(shown[key]) <= 1024 and "\x1b" not in shown[key] and "\n" not in shown[key]
        for value in shown["details"].values():
            assert all(len(item) <= 1024 for item in (value if isinstance(value, list) else [value]))
    assert binding.as_dict() == before


def test_concurrent_scan_holds_keep_canonical_binding_private(home, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.workspace.binding import WorkspaceBinding

    path = "/workspace/ghp_" + "C" * 30
    binding = WorkspaceBinding("hold", reason="pin_conflicts_with_host_root", message=f"workspace {path} disagrees",
                               details=(("pin", path), ("host_roots", [path])))
    before = binding.as_dict()
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    server.handle_request(json.loads(_init()))
    with ThreadPoolExecutor(max_workers=3) as pool:
        frames = list(pool.map(server.handle_request, [
            json.loads(_call(i, "aegis_scan", {"files": ["app.py"]})) for i in range(1, 7)
        ]))
    for frame in frames:
        is_error, payload = _payload(frame)
        assert is_error and payload["reason"] == "pin_conflicts_with_host_root"
        assert "ghp_" + "C" * 30 not in json.dumps(payload)
        assert payload["binding"]["details"]["host_roots"] == ["/workspace/ghp_REDACTED"]
    assert binding.as_dict() == before


def test_scan_dispatcher_refuses_oversized_binding_fields(home, monkeypatch, capsys):
    from aegis_core.workspace.binding import WorkspaceBinding

    huge = "x" * (1024 * 1024 + 1)
    binding = WorkspaceBinding("hold", reason="pin_conflicts_with_host_root", message=huge,
                               details=(("pin", huge), ("host_roots", [huge])))
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})])
    is_error, payload = _payload(frames[1])
    assert is_error
    assert payload["error"] == payload["binding"]["message"] == "guidance_projection_limit"
    assert payload["binding"]["details"] == {}


@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
@pytest.mark.parametrize("failure", ["handler", "resolver"])
@pytest.mark.parametrize("text", ["ghp_" + "F" * 30, "bad\x1btext", "x" * 5000, "bad\nINFO: approved"],
                         ids=["token", "controls", "long", "newline"])
def test_scan_dispatcher_exception_diagnostics_are_projected(home, tmp_path, monkeypatch, capsys,
                                                            bound, failure, text):
    if bound:
        pin = str(_governed(tmp_path / "project", "rule-project"))
        monkeypatch.setattr(server, "env_workspace", lambda environ=None: pin)

    def refuse(*args):
        raise OSError(text)

    if failure == "handler":
        monkeypatch.setattr(server, "execute_tool", refuse)
    else:
        monkeypatch.setattr(server, "_bind", refuse)
    frames, captured = _serve(monkeypatch, capsys, [
        _init(), _call(1, "aegis_scan", {"files": ["app.py"]}),
        _call(2, "aegis_scan", {"files": ["app.py"]}), _frame(3, "ping"),
    ], capture=True)
    for req_id in (1, 2):
        frame = frames[req_id]
        if failure == "resolver":
            assert frame["error"] == {"code": -32603, "message": "Internal error"}
        else:
            assert frame["result"]["isError"]
            assert frame["result"]["content"][0]["text"].startswith("Tool execution failed: ")
    assert frames[3]["result"] == {}
    assert text not in captured.out + captured.err
    assert "\x1b" not in captured.err and "Traceback" not in captured.err
    assert all(len(line) <= len("aegis-mcp: ") + 1024 for line in captured.err.splitlines())


@pytest.mark.parametrize("error_type", [PermissionError, FileNotFoundError, NotADirectoryError],
                         ids=["permission", "missing", "not_directory"])
def test_startup_marker_permission_failure_is_projected_and_retryable(home, tmp_path, monkeypatch, capsys, error_type):
    from aegis_core.workspace import binding

    secret = "ghp_" + "M" * 30
    pin = _governed(tmp_path / secret, "rule-project")
    marker = binding.is_aegis_workspace

    def denied(root):
        if root == pin:
            raise error_type("workspace marker denied: " + str(pin / ".aegis"))
        return marker(root)

    monkeypatch.setattr(server, "env_workspace", lambda environ=None: str(pin))
    monkeypatch.setattr("aegis_core.workspace.binding.is_aegis_workspace", denied)
    for _ in range(2):
        frames, captured = _serve(monkeypatch, capsys, [
            _init(), _call(1, "aegis_scan", {"files": ["src/app.py"]}),
            _call(2, "aegis_scan", {"files": ["src/app.py"]}), _frame(3, "ping"),
        ], capture=True)
        assert secret not in captured.out + captured.err and "Traceback" not in captured.err
        assert captured.err.startswith("aegis-mcp: AEGIS_WORKSPACE is set to ")
        for req_id in (1, 2):
            is_error, payload = _payload(frames[req_id])
            assert is_error and payload["status"] == "FAIL"
            assert payload["binding"]["reason"] == "pin_missing"
            assert payload["error"] == payload["binding"]["message"]
        assert frames[3]["result"] == {}
    monkeypatch.setattr("aegis_core.workspace.binding.is_aegis_workspace", marker)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {"files": ["src/app.py"]})])
    is_error, payload = _payload(frames[1])
    assert not is_error and [rule["name"] for rule in payload["relevant_rules"]] == ["rule-project"]


def test_startup_os_path_limit_is_a_projected_binding_refusal(home, tmp_path, monkeypatch, capsys):
    secret = "ghp_" + "L" * 30
    pin = str(tmp_path / secret / ("x" * 5000))
    monkeypatch.setattr(server, "env_workspace", lambda environ=None: pin)
    frames, captured = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})], capture=True)
    is_error, payload = _payload(frames[1])
    assert is_error and payload["binding"]["reason"] == "pin_missing"
    assert secret not in captured.out + captured.err and "Traceback" not in captured.err
    assert payload["error"].startswith("AEGIS_WORKSPACE is set to ")
    assert len(payload["error"]) <= 1024


def test_oversized_startup_pin_is_refused_before_resolution(home, monkeypatch, capsys):
    huge = "x" * (1024 * 1024 + 1)

    def unexpected(**kwargs):
        raise AssertionError("oversized pin reached path resolution")

    monkeypatch.setattr(server, "env_workspace", lambda environ=None: huge)
    monkeypatch.setattr(server, "resolve_binding", unexpected)
    frames, captured = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})], capture=True)
    is_error, payload = _payload(frames[1])
    assert is_error and payload["binding"]["reason"] == "pin_missing"
    assert payload["error"] == "guidance_projection_limit"
    assert captured.err == "aegis-mcp: guidance_projection_limit\n"


@pytest.mark.parametrize("root_count", [8, 32, 128, 2048])
def test_real_conflicting_roots_have_bounded_projection_work(home, tmp_path, monkeypatch, capsys, root_count):
    from aegis_core.workspace import diagnostics

    pin = _governed(tmp_path / "pin", "rule-pin")
    roots = [tmp_path / ("foreign-" + str(i)) for i in range(root_count)]
    resolve = server.resolve_binding
    project_name, project_text = diagnostics.project_error_name, diagnostics.project_diagnostic
    visits = []
    searches = []

    class CountedMessage(str):
        def count(self, *args):
            searches.append("count")
            return super().count(*args)

        def replace(self, *args):
            searches.append("replace")
            return super().replace(*args)

    def observed_resolve(**kwargs):
        from dataclasses import replace

        result = resolve(**kwargs)
        return replace(result, message=CountedMessage(result.message))

    def observed_name(value):
        visits.append(len(value))
        return project_name(value)

    def observed_text(value, **kwargs):
        visits.append(len(value))
        return project_text(value, **kwargs)

    monkeypatch.setattr(server, "resolve_binding", observed_resolve)
    monkeypatch.setattr("aegis_core.workspace.diagnostics.project_error_name", observed_name)
    monkeypatch.setattr("aegis_core.workspace.diagnostics.project_diagnostic", observed_text)
    monkeypatch.setattr(server, "env_workspace", lambda environ=None: str(pin))
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {}, _codex_meta(*roots))])
    is_error, payload = _payload(frames[1])
    assert is_error and payload["reason"] == "pin_conflicts_with_host_root"
    assert visits
    assert searches == []  # composition never rescans a finished diagnostic
    if root_count > 256:
        assert payload["error"] == "guidance_projection_limit"
        assert payload["binding"]["details"] == {}
        assert len(visits) <= 16
    else:
        assert len(payload["binding"]["details"]["host_roots"]) == root_count
        assert len(payload["error"]) <= 1024
        assert len(visits) <= 8 * root_count + 32
        assert sum(visits) <= 16 * (sum(len(str(root)) for root in roots) + len(str(pin)) + 1024)


def test_binding_component_limit_precedes_detail_projection(home, monkeypatch, capsys):
    from aegis_core.workspace.binding import WorkspaceBinding
    from aegis_core.workspace import diagnostics

    paths = ["x" * (1024 * 1024 + 1)]
    binding = WorkspaceBinding("hold", reason="ambiguous_host_roots", message="host roots conflict",
                               details=(("candidates", paths),))
    projected = []
    project_name = diagnostics.project_error_name

    def observed(value):
        projected.append(value)
        return project_name(value)

    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    monkeypatch.setattr("aegis_core.workspace.diagnostics.project_error_name", observed)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})])
    is_error, payload = _payload(frames[1])
    assert is_error and payload["reason"] == "ambiguous_host_roots"
    assert payload["error"] == "guidance_projection_limit"
    assert payload["binding"]["details"] == {}
    assert all(len(value) < 5000 for value in projected)


@pytest.mark.parametrize("value", ["ghp_" + "C" * 30, "host\x1b\nvalue", "host\n## Evidence\nvalue",
                                   "x" * 5000, "x" * (1024 * 1024 + 1), "unknown-host"],
                         ids=["token", "controls", "evidence", "long", "oversized", "ordinary"])
def test_unknown_client_environment_is_projected_before_startup_warning(home, monkeypatch, capsys, value):
    # Exercise the real env adapter through a consumer-local environment view.
    monkeypatch.setattr("aegis_core.config.os", SimpleNamespace(**{**vars(os), "environ": {"AEGIS_CLIENT": value}}))
    frames, captured = _serve(monkeypatch, capsys, [_init()], capture=True)
    assert frames[0]["result"]["serverInfo"]["name"] == "aegis-mcp"
    assert len(captured.err.rstrip("\n")) <= 1024
    assert captured.err.count("\n") == 1 and "\x1b" not in captured.err
    if value == "unknown-host":
        assert captured.err == ("aegis-mcp: AEGIS_CLIENT='unknown-host' names no known host; "
                                "identifying the client by clientInfo\n")
    else:
        assert value not in captured.err
    if "Evidence" in value:
        assert "host ## Evidence value" in captured.err
    if "\x1b" in value:
        assert "host value" in captured.err
    if len(value) > 1024 * 1024:
        assert "guidance_projection_limit" in captured.err


@pytest.mark.parametrize("field", ["name", "value", "nested_value"])
@pytest.mark.parametrize("value", ["ghp_" + "A" * 30, "bad\x1b\ninput", "## Evidence", "x" * 5000,
                                   "## Evidence\n" + "x" * (1024 * 1024 + 1)],
                         ids=["token", "controls", "evidence", "long", "oversized"])
def test_dispatch_argument_diagnostics_project_names_and_values(home, monkeypatch, capsys, field, value):
    args = {value: 1} if field == "name" else {"view": value if field == "value" else {"nested": value}}
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", args)])
    is_error, payload = _payload(frames[1])
    assert is_error and payload["status"] == "FAIL"
    error = payload["error"]
    assert len(error) <= 1024 and "\n" not in error and "\x1b" not in error
    if value == "## Evidence":
        assert value in error
    else:
        assert value not in error
    if len(value) > 1024 * 1024:
        assert "guidance_projection_limit" in error
    if "\x1b" in value:
        assert "bad input" in error


@pytest.mark.parametrize("phase", ["validate", "execute"])
@pytest.mark.parametrize("value", ["ghp_" + "G" * 30, "bad\x1b\ninput", "## Evidence\nremaining",
                                   "x" * (1024 * 1024 + 1)], ids=["token", "controls", "evidence", "oversized"])
def test_manager_dispatch_diagnostics_use_the_same_projection(home, tmp_path, monkeypatch, capsys, phase, value):
    monkeypatch.setattr(server, "env_manager_registration", lambda environ=None: (str(tmp_path / "manager.json"), "0" * 64))
    args = {"action": "handoff", "context": {"member_id": "m", "worktree_id": "w"}}
    if phase == "validate":
        args[value] = 1
    else:
        def fail(*args):
            raise OSError(value)

        monkeypatch.setattr("aegis_mcp.manager.execute", fail)
    if phase == "validate" and len(value) > server.MANAGER_MAX_BYTES:
        # Stdio refuses this frame before inspecting its fields; test the public
        # in-process dispatcher too, without relaxing the framing limit.
        server._start()
        server.handle_request(json.loads(_init()))
        frames = {1: server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                           "params": {"name": "aegis_scan", "arguments": args}})}
    else:
        frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", args)])
    if phase == "validate":
        assert frames[1]["error"]["code"] == -32602
        error = frames[1]["error"]["message"]
    else:
        is_error, payload = _payload(frames[1])
        assert is_error and payload["status"] == "FAIL"
        error = payload["error"]
    assert value not in error and "\n" not in error and "\x1b" not in error and len(error) <= 1024
    if "Evidence" in value:
        assert "## Evidence remaining" in error
    if len(value) > 1024 * 1024:
        assert "guidance_projection_limit" in error


@pytest.mark.parametrize("case", ["items", "characters"])
def test_unknown_argument_limits_precede_projection(case, monkeypatch):
    from aegis_mcp.tools import execute_tool

    args = ({"extra" + str(i): 1 for i in range(300)} if case == "items" else
            {"a" * 600000: 1, "b" * 600000: 1})

    def unexpected(value):
        raise AssertionError("over-limit argument collection reached projection")

    monkeypatch.setattr("aegis_mcp.tools._project_diagnostic", unexpected)
    assert execute_tool("aegis_scan", args) == {"status": "FAIL", "error": "guidance_projection_limit"}


def test_scalar_diagnostics_refuse_cycles_and_unprintable_values():
    from aegis_mcp.tools import execute_tool

    class Unprintable:
        def __repr__(self):
            raise AssertionError("untrusted repr ran")

    result = execute_tool("aegis_scan", {"view": Unprintable()})
    assert result == {"status": "FAIL", "error": "Invalid 'view': guidance_projection_invalid_field. Expected a string."}
    cycle = []
    cycle.append(cycle)
    assert execute_tool("aegis_scan", {"view": cycle}) == {
        "status": "FAIL", "error": "Invalid 'view': guidance_projection_limit. Expected a string."}


def test_scalar_value_token_projection_precedes_the_legacy_display_cut():
    from aegis_mcp.tools import execute_tool

    value = "prefix-" * 7 + " ghp_" + "T" * 30
    result = execute_tool("aegis_scan", {"view": value})
    assert result["status"] == "FAIL" and "ghp_T" not in result["error"]
    assert "..." in result["error"]


@pytest.mark.parametrize("route", ["handler", "resolver", "manager_execute", "manager_validate"])
@pytest.mark.parametrize("separator", ["\t", "\n", "\x1b", "\x85", "\u200b", "\u2028", "\ud800", "\udc80", "\udfff",
                                      "\ue000", "\uffff", "\U0010ffff", "\u0378"])
@pytest.mark.parametrize("scheme", ["bearer", "github"])
def test_formatted_dispatch_errors_project_escaped_filename_or_name(home, tmp_path, monkeypatch, capsys,
                                                                 route, separator, scheme):
    token = "F" * 30
    name = ("Bearer" + separator if scheme == "bearer" else separator + "ghp_") + token
    shown_name = "Bearer REDACTED" if scheme == "bearer" else " ghp_REDACTED"

    def fail(*args):
        raise OSError(13, "workspace denied", name)

    if route.startswith("manager_"):
        monkeypatch.setattr(server, "env_manager_registration",
                            lambda environ=None: (str(tmp_path / "manager.json"), "0" * 64))
        if route == "manager_execute":
            monkeypatch.setattr("aegis_mcp.manager.execute", fail)
    elif route == "handler":
        monkeypatch.setattr(server, "execute_tool", fail)
    else:
        monkeypatch.setattr(server, "_bind", fail)
    args = {"action": "handoff", "context": {"member_id": "m", "worktree_id": "w"}}
    tool = [name] if route == "manager_validate" else "aegis_scan"
    frames, captured = _serve(monkeypatch, capsys, [
        _init(), _call(1, tool, args), _call(2, tool, args), _frame(3, "ping"),
    ], capture=True)
    assert token not in captured.out + captured.err and "Traceback" not in captured.err
    for req_id in (1, 2):
        if route == "resolver":
            assert frames[req_id]["error"] == {"code": -32603, "message": "Internal error"}
        elif route == "manager_validate":
            assert frames[req_id]["error"] == {"code": -32602, "message": "Unknown tool: ['" + shown_name + "']"}
        else:
            assert frames[req_id]["result"]["isError"]
            assert shown_name in frames[req_id]["result"]["content"][0]["text"]
    if route != "manager_validate":
        shown = captured.err if route == "resolver" else frames[1]["result"]["content"][0]["text"]
        assert "[Errno 13] workspace denied: '" + shown_name + "'" in shown
    assert frames[3]["result"] == {}


def test_concurrent_escaped_diagnostic_projection_is_stateless():
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.guidance_projection import project_diagnostic

    inputs = ["Bearer\\t" + "S" * 30, "Bearer\\u200b" + "T" * 30, "ordinary diagnostic"] * 8
    with ThreadPoolExecutor(max_workers=3) as pool:
        outputs = list(pool.map(project_diagnostic, inputs))
    assert outputs == ["Bearer REDACTED", "Bearer REDACTED", "ordinary diagnostic"] * 8


@pytest.mark.parametrize("number", [errno.EACCES, errno.ENAMETOOLONG, errno.ELOOP, errno.ENOTDIR])
@pytest.mark.parametrize("source", ["pinned", "attested"])
def test_per_call_workspace_marker_errors_are_fail_closed(home, tmp_path, monkeypatch, capsys, number, source):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.workspace import binding

    root = _governed(tmp_path / "project", "rule-project")
    if source == "pinned":
        monkeypatch.setattr(server, "env_workspace", lambda environ=None: str(root))
    server._start()
    server.handle_request(json.loads(_init()))
    marker = binding.is_aegis_workspace

    def denied(path):
        if path == root:
            raise OSError(number, "marker denied", "Bearer\t" + "S" * 30)
        return marker(path)

    monkeypatch.setattr("aegis_core.workspace.binding.is_aegis_workspace", denied)
    for req_id in (1, 2):
        response = server.handle_request(json.loads(_call(req_id, "aegis_scan", {}, _codex_meta(root))))
        is_error, payload = _payload(response)
        assert is_error and payload["status"] == "FAIL" and payload["binding"]["status"] == "error"
        assert payload["binding"]["reason"] == ("pin_missing" if source == "pinned" else "no_workspace")
        assert "marker denied" not in json.dumps(payload) and "S" * 30 not in json.dumps(payload)
    assert server.handle_request(json.loads(_frame(3, "ping")))["result"] == {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        replies = list(pool.map(server.handle_request, [
            json.loads(_call(req_id, "aegis_scan", {}, _codex_meta(root))) for req_id in (4, 5, 6)]))
    assert all(_payload(reply)[1]["status"] == "FAIL" for reply in replies)
    monkeypatch.setattr("aegis_core.workspace.binding.is_aegis_workspace", marker)
    is_error, payload = _payload(server.handle_request(json.loads(
        _call(7, "aegis_scan", {"files": ["src/app.py"]}, _codex_meta(root)))))
    assert not is_error and [rule["name"] for rule in payload["relevant_rules"]] == ["rule-project"]
    assert "Traceback" not in capsys.readouterr().err


def test_large_normalized_startup_pin_is_clipped_without_double_counting(home, tmp_path, monkeypatch, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    pin = str(plain) + "/" * (600000 - len(str(plain)))
    monkeypatch.setattr(server, "env_workspace", lambda environ=None: pin)
    frames, captured = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})], capture=True)
    is_error, payload = _payload(frames[1])
    assert is_error and payload["binding"]["reason"] == "pin_not_a_workspace"
    assert "guidance_projection_limit" not in captured.err + json.dumps(payload)
    assert len(payload["error"]) == 1024
    assert payload["error"].endswith(", which has no .aegis/ (run aegis init there)")
    assert "... [display-only]" in payload["error"]


@pytest.mark.parametrize("identity", ["h" * 5000, "Bearer\t" + "S" * 30 + "\n" + "h" * 5000,
                                      "ghp_" + "S" * 30 + "/" + "h" * 5000],
                         ids=["long", "controls", "secret"])
def test_scan_binding_keeps_recovery_after_long_host_roots(home, monkeypatch, capsys, identity):
    from aegis_core.workspace.binding import WorkspaceBinding

    binding = WorkspaceBinding("hold", reason="pin_conflicts_with_host_root",
                               details=(("pin", "pinned"), ("host_roots", [identity, "h" * 5000])))
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {}), _call(2, "aegis_scan", {})])
    for req_id in (1, 2):
        is_error, payload = _payload(frames[req_id])
        assert is_error and payload["status"] == "hold"
        assert payload["reason"] == "pin_conflicts_with_host_root"
        assert payload["error"] == payload["binding"]["message"]
        assert "fix the pin or open the pinned project" in payload["error"]
        assert len(payload["error"]) <= 1024 and "... [display-only]" in payload["error"]
        assert "S" * 30 not in json.dumps(payload)
        assert "\n" not in payload["error"] and "\t" not in payload["error"]


def test_valid_component_collection_is_clipped_independently(home, monkeypatch, capsys):
    from aegis_core.workspace.binding import WorkspaceBinding

    paths = ["x" * 5000 + str(i) for i in range(240)]
    binding = WorkspaceBinding("hold", reason="ambiguous_host_roots", message="host roots conflict",
                               details=(("candidates", paths),))
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})])
    is_error, payload = _payload(frames[1])
    assert is_error and payload["status"] == "hold"
    assert "guidance_projection_limit" not in json.dumps(payload)
    assert len(payload["binding"]["details"]["candidates"]) == 240
    assert all(len(value) == 1024 and value.endswith("...") for value in payload["binding"]["details"]["candidates"])


@pytest.mark.parametrize("case", ["inner_separator", "name_control", "derived_escape", "two_escapes",
                                  "unknown", "empty", "unclosed", "nested"])
def test_named_escape_text_cannot_shield_a_credential(case):
    from aegis_core.guidance_projection import project_diagnostic

    token = "S" * 30
    values = {"inner_separator": "\\N{unknown Bearer\\t" + token + "}",
              "name_control": "Bearer\\N{ZERO\u200bWIDTH SPACE}" + token,
              "derived_escape": "Bearer\\N{ZERO\\tWIDTH SPACE}" + token,
              "two_escapes": "Bearer\\N{ZERO\\t\\tWIDTH SPACE}" + token,
              "unknown": "Bearer\\N{unknown}" + token, "empty": "Bearer\\N{}" + token,
              "unclosed": "Bearer\\N{SPACE" + token,
              "nested": "Bearer\\N{ZERO\\N{SPACE}WIDTH SPACE}" + token}
    expected = "Bearer REDACTED" if case == "name_control" else "guidance_projection_invalid_field"
    assert project_diagnostic(values[case]) == expected


@pytest.mark.parametrize("value", [r"C:\tmp\repo", r"C:\N{unknown}\repo"])
def test_literal_diagnostic_paths_do_not_read_escapes(value):
    from aegis_core.guidance_projection import project_diagnostic

    assert project_diagnostic(value, escaped=False) == value


@pytest.mark.parametrize("kind", ["nonprintable", "backslash_quote"])
def test_unknown_argument_list_repr_stays_bounded_at_the_maximum_key_count(kind):
    from aegis_mcp.tools import execute_tool

    body = "\U0010ffff" * 1020 if kind == "nonprintable" else "\\'\"" * 340
    args = {body + f"{index:04d}": 1 for index in range(256)}
    assert len(args) == 256 and all(len(key) == 1024 for key in args)
    result = execute_tool("aegis_scan", args)
    assert result["status"] == "FAIL"
    assert result["error"].startswith("Unknown argument(s) for aegis_scan: [")
    assert "guidance_projection_limit" not in result["error"]
    assert len(result["error"]) <= 1024 and result["error"].endswith("...")


@pytest.mark.parametrize("value", ["café", "中文", "café 中文"])
def test_printable_non_ascii_dispatch_diagnostics_are_unchanged(home, monkeypatch, capsys, value):
    def fail(*args):
        raise OSError(value)

    monkeypatch.setattr(server, "execute_tool", fail)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})])
    assert frames[1]["result"]["content"][0]["text"] == "Tool execution failed: " + value


@pytest.mark.parametrize("filename", [r"C:\tmp\new\folder\repo", r"C:\folder\file"])
@pytest.mark.parametrize("route", ["handler", "resolver", "manager_execute", "manager_validate"])
def test_formatted_dispatch_errors_preserve_literal_windows_paths(home, tmp_path, monkeypatch, capsys,
                                                                filename, route):
    error = OSError(13, "workspace denied", filename)

    def fail(*args):
        raise error

    if route.startswith("manager_"):
        monkeypatch.setattr(server, "env_manager_registration",
                            lambda environ=None: (str(tmp_path / "manager.json"), "0" * 64))
        if route == "manager_execute":
            monkeypatch.setattr("aegis_mcp.manager.execute", fail)
    elif route == "handler":
        monkeypatch.setattr(server, "execute_tool", fail)
    else:
        monkeypatch.setattr(server, "_bind", fail)
    args = {"action": "handoff", "context": {"member_id": "m", "worktree_id": "w"}}
    name = [filename] if route == "manager_validate" else "aegis_scan"
    frames, captured = _serve(monkeypatch, capsys, [_init(), _call(1, name, args), _frame(2, "ping")],
                                capture=True)
    assert frames[2]["result"] == {}
    if route == "resolver":
        assert frames[1]["error"] == {"code": -32603, "message": "Internal error"}
        assert captured.err == "aegis-mcp: " + str(error) + "\n"
    elif route == "manager_validate":
        assert frames[1]["error"] == {"code": -32602, "message": "Unknown tool: " + str([filename])}
        assert captured.err == ""
    else:
        assert frames[1]["result"]["isError"]
        if route == "handler":
            assert frames[1]["result"]["content"][0]["text"] == "Tool execution failed: " + str(error)
        else:
            _, payload = _payload(frames[1])
            assert payload["error"] == str(error)
        assert captured.err == ("aegis-mcp: " + str(error) + "\n" if route == "handler" else "")


def test_binding_preserves_literal_windows_path_components(home, monkeypatch, capsys):
    from aegis_core.workspace.binding import WorkspaceBinding

    pin, other = r"C:\tmp\repo", r"C:\new\repo"
    binding = WorkspaceBinding("hold", reason="pin_conflicts_with_host_root",
                               details=(("pin", pin), ("host_roots", [other])))
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {})])
    is_error, payload = _payload(frames[1])
    assert is_error and payload["reason"] == "pin_conflicts_with_host_root"
    assert payload["binding"]["details"] == {"pin": pin, "host_roots": [other]}
    assert pin in payload["error"] and other in payload["error"]


@pytest.mark.parametrize("kind,reason,suffix", [
    ("not_a_directory", "pin_missing", "which is not a directory"),
    ("filesystem_root", "pin_denied", "which is the filesystem root"),
])
def test_scan_binding_variant_ignores_message(home, monkeypatch, capsys, kind, reason, suffix):
    from aegis_core.workspace.binding import WorkspaceBinding

    binding = WorkspaceBinding("error", reason=reason, kind=kind, message="unrelated OS-error suffix",
                               details=(("pin", r"C:\new\repo"),))
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {}), _call(2, "aegis_scan", {})])
    for req_id in (1, 2):
        is_error, payload = _payload(frames[req_id])
        assert is_error and payload["status"] == "FAIL"
        assert payload["error"] == "AEGIS_WORKSPACE is set to C:\\new\\repo, " + suffix
        assert payload["binding"]["reason"] == reason
        assert list(payload["binding"]) == ["status", "root", "source", "confidence", "reason", "details", "message"]


@pytest.mark.parametrize("details", [None, (("candidates", "not a list"),), (("pin", 3),)])
def test_scan_malformed_binding_details_return_fixed_refusal(home, monkeypatch, capsys, details):
    from aegis_core.workspace.binding import WorkspaceBinding

    binding = WorkspaceBinding("hold", reason="pin_conflicts_with_host_root", details=details)
    monkeypatch.setattr(server, "_bind", lambda params, args: binding)
    frames = _serve(monkeypatch, capsys, [_init(), _call(1, "aegis_scan", {}), _call(2, "aegis_scan", {})])
    for req_id in (1, 2):
        is_error, payload = _payload(frames[req_id])
        assert is_error and payload["status"] == "hold"
        assert payload["error"] == "guidance_projection_invalid_field"
        assert payload["binding"]["details"] == {}


@pytest.mark.parametrize("closed", [False, True], ids=["open", "closed"])
@pytest.mark.parametrize("route", ["handler", "manager_validate"])
def test_literal_named_text_cannot_shield_a_repr_credential(home, tmp_path, monkeypatch, capsys, closed, route):
    tail = "}" if closed else ""
    filename = r"\N{literal Bearer" + "\t" + "S" * 30 + tail
    shown = r"\N{literal Bearer REDACTED" + tail

    def fail(*args):
        raise OSError(13, "workspace denied", filename)

    if route == "handler":
        monkeypatch.setattr(server, "execute_tool", fail)
    else:
        monkeypatch.setattr(server, "env_manager_registration",
                            lambda environ=None: (str(tmp_path / "manager.json"), "0" * 64))
    name = "aegis_scan" if route == "handler" else [filename]
    args = {"action": "handoff", "context": {"member_id": "m", "worktree_id": "w"}}
    frames, captured = _serve(monkeypatch, capsys, [_init(), _call(1, name, args), _frame(2, "ping")],
                                capture=True)
    assert frames[2]["result"] == {}
    assert "S" * 30 not in captured.out + captured.err
    if route == "handler":
        message = str(OSError(13, "workspace denied", shown))
        assert frames[1]["result"]["isError"]
        assert frames[1]["result"]["content"][0]["text"] == "Tool execution failed: " + message
        assert captured.err == "aegis-mcp: " + message + "\n"
    else:
        assert frames[1]["error"] == {"code": -32602, "message": "Unknown tool: " + str([shown])}
        assert captured.err == ""
