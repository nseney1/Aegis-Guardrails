"""Guards on what may name a workspace (AD-4), each pinned by a test that fails without it.

The runtime re-review found binding guards that survived mutation. At this base the
direct forms are covered (test_workspace_binding, test_mcp_runtime_binding); these
tests pin the forms that still survived:

- a registry entry equal to ``$HOME`` is not a usable workspace, so it can neither be
  selected nor "own" a call's files and turn a good binding into a hold;
- a host root must be an absolute local path: a relative ``file:`` URI, or a relative
  ``CLAUDE_PROJECT_DIR`` (the sibling of the Codex ``_meta`` check), would resolve
  against whatever the server's process cwd is; ``file://localhost/...`` is local, and a
  URI of any other scheme names no local directory at all.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys

import pytest

import aegis_mcp.server as server
from aegis_core.workspace.binding import Attested, read_registry, resolve_binding


REAL_HARDEN_PROCESS = server.harden_process


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".aegis" / "rules").mkdir(parents=True)  # the user layer: $HOME holds .aegis/
    (home / "proj").mkdir()
    (home / "proj" / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(home)
    return home.resolve()


def _governed(path: Path, rule_id: str = "rule-x") -> Path:
    rules = path / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / f"{rule_id}.md").write_text(
        f"---\nid: {rule_id}\ntype: trap\ntarget_paths: ['src/*.py']\nhypothesis: h\n---\nBody\n", encoding="utf-8")
    (path / ".git").mkdir(exist_ok=True)
    return path.resolve()


def _registry_with(home: Path, *roots: Path):
    path = home / ".aegis" / "workspaces.json"
    path.write_text(json.dumps({"v": 1, "workspaces": [{"root": str(r)} for r in roots]}), encoding="utf-8")
    registry = read_registry(path)
    assert home in registry.roots  # the reader keeps it; only the denylist keeps it out
    return registry


# ── a registry entry for $HOME never owns a call's files (binding._usable) ──

def test_a_registered_home_never_contests_the_operator_pin(home, tmp_path):
    pinned = _governed(tmp_path / "pinned")
    registry = _registry_with(home, home, pinned)

    binding = resolve_binding(pin=pinned, files=[str(home / "proj" / "app.py")], registry=registry)

    assert (binding.status, binding.root, binding.source) == ("bound", pinned, "pin")


def test_a_registered_home_never_contests_a_host_attested_root(home, tmp_path):
    attested = _governed(tmp_path / "attested")
    registry = _registry_with(home, home)

    binding = resolve_binding(attested=[Attested("codex_meta", str(attested))],
                              files=[str(home / "proj" / "app.py")], registry=registry)

    assert (binding.status, binding.root, binding.source) == ("bound", attested, "codex_meta")


def test_a_registered_home_never_claims_files_when_the_host_root_is_ungoverned(home, tmp_path):
    plain = tmp_path / "plain"
    (plain / ".git").mkdir(parents=True)
    registry = _registry_with(home, home)

    binding = resolve_binding(attested=[Attested("mcp_roots", str(plain))],
                              files=[str(home / "proj" / "app.py")], registry=registry)

    assert (binding.status, binding.reason) == ("unbound", "host_roots_not_governed")


# ── host roots are absolute local paths (aegis_mcp.server) ──────────────────

def _frame(req_id, method, params=None) -> str:
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _serve(monkeypatch, capsys, lines):
    monkeypatch.setattr("sys.stdin", io.StringIO("".join(f"{line}\n" for line in lines)))
    assert server.run_stdio_server() == 0
    frames = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    return {f.get("id"): f for f in frames if "method" not in f}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_GET_DUMPABLE is Linux-only")
def test_in_process_stdio_preserves_worker_dumpability(home, monkeypatch, capsys):
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    before = libc.prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
    assert before >= 0

    frames = _serve(monkeypatch, capsys, [_frame(1, "ping")])

    assert frames[1]["result"] == {}
    assert libc.prctl(3, 0, 0, 0, 0) == before


def test_hardening_policy_applies_in_another_module():
    assert server.harden_process is not REAL_HARDEN_PROCESS
    assert server.harden_process() is False


def _list_rules(monkeypatch, capsys, client: str, roots_uri=None):
    lines = [_frame(0, "initialize", {"clientInfo": {"name": client, "version": "1"},
                                      "capabilities": {"roots": {"listChanged": True}}})]
    if roots_uri is not None:
        lines.append(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        lines.append(json.dumps({"jsonrpc": "2.0", "id": "aegis-roots-1",
                                 "result": {"roots": [{"uri": roots_uri}]}}))
    lines.append(_frame(1, "tools/call", {"name": "aegis_list_rules", "arguments": {}}))
    frame = _serve(monkeypatch, capsys, lines)[1]
    return frame["result"]["isError"], json.loads(frame["result"]["content"][0]["text"])


@pytest.fixture
def cwd_with_a_governed_child(home, tmp_path, monkeypatch) -> Path:
    """The server runs in an ungoverned repository holding a governed directory "child":
    a relative path resolved against the process cwd would name that workspace."""
    cwd = tmp_path / "cwd"
    (cwd / ".git").mkdir(parents=True)
    _governed(cwd / "child", "rule-child")
    monkeypatch.chdir(cwd)
    return cwd


def test_a_relative_file_uri_root_is_ignored(cwd_with_a_governed_child, monkeypatch, capsys):
    is_error, payload = _list_rules(monkeypatch, capsys, "claude-code", roots_uri="file:child")
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


def test_a_relative_claude_project_dir_is_ignored(cwd_with_a_governed_child, monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "child")
    is_error, payload = _list_rules(monkeypatch, capsys, "claude-code")
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


@pytest.mark.parametrize("scheme", ["http", "https", "vscode-remote"])
def test_a_root_uri_of_another_scheme_is_ignored(cwd_with_a_governed_child, tmp_path, monkeypatch, capsys,
                                                 scheme):
    # Only a file: URI names a local directory; the same path under another scheme does not.
    root = _governed(tmp_path / "rooted", "rule-rooted")
    is_error, payload = _list_rules(monkeypatch, capsys, "claude-code",
                                    roots_uri=f"{scheme}:///" + root.as_posix().lstrip("/"))
    assert is_error
    assert (payload["status"], payload["binding"]["reason"]) == ("not_governed", "no_workspace")


def test_a_localhost_file_uri_root_is_local_and_binds(home, tmp_path, monkeypatch, capsys):
    root = _governed(tmp_path / "rooted", "rule-rooted")
    uri = "file://localhost/" + root.as_posix().lstrip("/")
    is_error, payload = _list_rules(monkeypatch, capsys, "claude-code", roots_uri=uri)
    assert not is_error
    assert {r["_name"] for r in payload["rules"]} == {"rule-rooted"}
