"""aegis-mcp binds every tools/call through the AD-4 resolver (host-matrix §3.6).

Driven over stdio with an isolated HOME. The model never names the workspace: the
pin, the host's attestations (Codex per-call ``_meta``, CLAUDE_PROJECT_DIR, MCP roots),
the registry the call's files select from, and a bounded walk-up from the server cwd
do. Disagreement is a machine-readable hold; nothing resolved serves the read-only
user layer (H8) to aegis_scan and "not governed here" to the other tools.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

import aegis_mcp.server as server
from aegis_core.yaml_engine.serializer import dump_frontmatter

NOT_GOVERNED = 'not an Aegis workspace: run "aegis init" in your repository'


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


def _serve(monkeypatch, capsys, lines):
    monkeypatch.setattr("sys.stdin", io.StringIO("".join(f"{line}\n" for line in lines)))
    assert server.run_stdio_server() == 0
    frames = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    return {f.get("id"): f for f in frames if "method" not in f}


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
