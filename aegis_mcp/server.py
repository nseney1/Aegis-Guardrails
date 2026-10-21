"""aegis-mcp stdio server: JSON-RPC framing, client identity, workspace binding and
server-owned arguments (host-matrix §3.5, §3.6, §3.8).

- **Identity** (§3.5): the registration's ``AEGIS_CLIENT`` names the host when it is a
  known host id; otherwise the exact ``clientInfo.name`` table in ``aegis_core.hosts``;
  otherwise ``generic``. Host, client name and version and the session id are server
  state: no tool argument can set them.
- **Binding** (§3.6, AD-4): every ``tools/call`` is bound by
  ``aegis_core.workspace.binding.resolve_binding`` from the operator pin, what the host
  attests (Codex per-call ``_meta``, ``CLAUDE_PROJECT_DIR``, MCP roots), the registry
  and a bounded walk-up from the server's cwd. A hold or an error answers the call with
  a machine-readable reason; unbound, ``aegis_scan`` serves the read-only user layer.
- **Protocol**: ``ping``; ``protocolVersion`` echoed when supported; ``server/discover``
  is Method not found so hosts fall back to ``initialize`` (the stateful era);
  responses to the server's own ``roots/list`` requests are routed, never answered.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import threading
import time
import traceback
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import url2pathname

from aegis_core import hosts
from aegis_core._version import __version__
from aegis_core.bootstrap import instructions_text
from aegis_core.config import env_client, env_workspace
from aegis_core.taxonomy import MCP_DEFAULT_RATE_LIMITS
from aegis_core.workspace.base import Workspace
from aegis_core.workspace.binding import Attested, Registry, WorkspaceBinding, read_registry, resolve_binding
from aegis_core.workspace.layout import UserLayout

from .projection import is_error_result
from .registry import DEFAULT_CLIENT_PLATFORM, NOT_GOVERNED_MESSAGE, TOOL_DEFINITIONS
from .tools import execute_tool, is_known_tool

# Arguments only the server may set. A client value is dropped before dispatch, so the
# workspace, the host attribution and the session of a ledger row are never the caller's.
SERVER_OWNED_KEYS = frozenset({
    "workspace", "host", "session", "source", "platform",
    "client_host", "client_name", "client_version",
    "_host", "_session", "_client_platform", "_client_host", "_client_name", "_client_version",
    "_binding", "_unbound",
})

# Versions this server speaks, oldest first. 2025-03-26 is left out: it requires
# receiving JSON-RPC batches, which this server rejects.
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-06-18", "2025-11-25")
_BASELINE_PROTOCOL = SUPPORTED_PROTOCOL_VERSIONS[0]
_VERSION_SHAPE = re.compile(r"\d{4}-\d{2}-\d{2}")

# ── Connection state (one MCP client per process; reset by run_stdio_server) ──
# The operator pin: run_stdio_server sets it from AEGIS_WORKSPACE; an in-process
# caller may set it directly.
_canonical_workspace: Workspace | str | None = None
_client_platform: str = DEFAULT_CLIENT_PLATFORM  # the host id
_client_name: str = ""
_client_version: str = ""
_session_id: Optional[str] = None
# Set by run_stdio_server when the pin is unusable: every tools/call answers with it.
_workspace_error: Optional[WorkspaceBinding] = None
_server_cwd: Optional[str] = None
_claude_project_dir: Optional[str] = None
_roots_capable: bool = False
_host_roots: Tuple[str, ...] = ()
_outbox: List[Dict[str, Any]] = []
_pending: Dict[str, str] = {}
_request_seq: int = 0
_workspaces: Dict[Tuple[str, str], Workspace] = {}
_registry_cache: Optional[Tuple[Tuple[Any, ...], Registry]] = None


def fresh_state() -> Dict[str, Any]:
    """The connection state of a new process, by module attribute name."""
    return {
        "_canonical_workspace": None,
        "_client_platform": DEFAULT_CLIENT_PLATFORM,
        "_client_name": "",
        "_client_version": "",
        "_session_id": None,
        "_workspace_error": None,
        "_server_cwd": None,
        "_claude_project_dir": None,
        "_roots_capable": False,
        "_host_roots": (),
        "_outbox": [],
        "_pending": {},
        "_request_seq": 0,
        "_workspaces": {},
        "_registry_cache": None,
    }

_RATE_LIMITS = {
    "aegis_report_outcome": MCP_DEFAULT_RATE_LIMITS["MUTATION"],
    "aegis_capture_insight": MCP_DEFAULT_RATE_LIMITS["MUTATION"],
}
_tool_call_times: Dict[str, list] = defaultdict(list)
_rate_limit_lock = threading.Lock()


def strip_server_owned(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of client arguments without server-owned keys."""
    # Only an object reaches here: tools/call answers other arguments with -32602 first.
    return {k: v for k, v in args.items() if k not in SERVER_OWNED_KEYS}


def _check_rate_limit(tool_name: str) -> bool:
    """Return True if the call is within rate limits, False if exceeded."""
    if tool_name not in _RATE_LIMITS:
        return True
    max_calls, window_seconds = _RATE_LIMITS[tool_name]
    now = time.monotonic()
    with _rate_limit_lock:
        recent = [ts for ts in _tool_call_times[tool_name] if now - ts < window_seconds]
        if len(recent) >= max_calls:
            _tool_call_times[tool_name] = recent
            return False
        recent.append(now)
        _tool_call_times[tool_name] = recent
        return True


def send_response(response: Dict[str, Any]):
    # stdout is the JSON-RPC transport: only framed messages may be written here.
    print(json.dumps(response), flush=True)


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def send_error(id: Any, code: int, message: str):
    send_response(_error(id, code, message))


def _valid_id(value: Any) -> bool:
    """JSON-RPC ids are strings, numbers or null; anything else is never echoed."""
    return value is None or isinstance(value, str) or (isinstance(value, (int, float)) and not isinstance(value, bool))


def _safe_id(value: Any) -> Any:
    return value if _valid_id(value) else None


# ── identity ─────────────────────────────────────────────────────────────────

def _identify(params: Dict[str, Any]) -> Tuple[str, str, str]:
    """(host id, client name, client version) for an ``initialize``."""
    info = params.get("clientInfo")
    name = info.get("name") if isinstance(info, dict) else None
    version = info.get("version") if isinstance(info, dict) else None
    name = name[:200] if isinstance(name, str) else ""
    version = version[:100] if isinstance(version, str) else ""
    host = hosts.identify(name)
    registered = env_client()
    if registered:
        try:
            host = hosts.get(registered).id
        except KeyError:
            print(f"aegis-mcp: AEGIS_CLIENT={registered!r} names no known host; "
                  "identifying the client by clientInfo", file=sys.stderr)
    return host, name, version


def negotiate_protocol(requested: Any) -> str:
    """The requested version when supported, else the newest supported version older
    than it, else the baseline (MCP lifecycle: the client disconnects if it cannot
    speak the answer)."""
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    if isinstance(requested, str) and _VERSION_SHAPE.fullmatch(requested):
        older = [v for v in SUPPORTED_PROTOCOL_VERSIONS if v < requested]
        if older:
            return older[-1]
    return _BASELINE_PROTOCOL


# ── roots (server-initiated requests) ────────────────────────────────────────

def take_outbox() -> List[Dict[str, Any]]:
    """Requests the server wants to send to the client, oldest first (and forget them)."""
    global _outbox
    queued, _outbox = _outbox, []
    return queued


def _request_roots() -> None:
    global _request_seq
    if not _roots_capable or _session_id is None:
        return
    _request_seq += 1
    request_id = f"aegis-roots-{_request_seq}"
    _pending[request_id] = "roots/list"
    _outbox.append({"jsonrpc": "2.0", "id": request_id, "method": "roots/list"})


def _file_uri_path(uri: Any) -> Optional[str]:
    if not isinstance(uri, str):
        return None
    parsed = urlparse(uri)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        return None
    path = url2pathname(parsed.path)
    return path if os.path.isabs(path) else None


def _route_response(message: Dict[str, Any]) -> None:
    """A client's response to one of our requests; unknown ids are ignored."""
    global _host_roots
    request_id = message.get("id")
    kind = _pending.pop(request_id, None) if isinstance(request_id, str) else None
    result = message.get("result")
    if kind == "roots/list" and isinstance(result, dict) and isinstance(result.get("roots"), list):
        paths = (_file_uri_path(r.get("uri")) for r in result["roots"] if isinstance(r, dict))
        _host_roots = tuple(dict.fromkeys(p for p in paths if p))


# ── binding ──────────────────────────────────────────────────────────────────

def _attested(params: Dict[str, Any]) -> List[Attested]:
    """What the host (never the model) reports about the session, in precedence order."""
    out: List[Attested] = []
    if _client_platform == "codex-cli":
        meta = params.get("_meta")
        turn = meta.get("x-codex-turn-metadata") if isinstance(meta, dict) else None
        spaces = turn.get("workspaces") if isinstance(turn, dict) else None
        names = list(spaces) if isinstance(spaces, (dict, list)) else []
        out.extend(Attested("codex_meta", p) for p in names if isinstance(p, str) and os.path.isabs(p))
    if _client_platform == "claude-code" and _claude_project_dir and os.path.isabs(_claude_project_dir):
        out.append(Attested("claude_project_dir", _claude_project_dir))
    out.extend(Attested("mcp_roots", p) for p in _host_roots)
    return out


def _registry() -> Registry:
    """~/.aegis/workspaces.json, re-read only when it changes."""
    global _registry_cache
    layout = UserLayout.current()
    if layout is None:
        return Registry()
    path = layout.workspaces_file
    try:
        st = os.stat(path)
        key: Tuple[Any, ...] = (str(path), st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        key = (str(path), None)
    if _registry_cache is None or _registry_cache[0] != key:
        _registry_cache = (key, read_registry(path))
    return _registry_cache[1]


def _bind(params: Dict[str, Any], args: Dict[str, Any]) -> WorkspaceBinding:
    if _workspace_error is not None:
        return _workspace_error
    raw_files = args.get("files")
    files = [f for f in raw_files if isinstance(f, str)] if isinstance(raw_files, list) else None
    pin = getattr(_canonical_workspace, "root", _canonical_workspace)
    return resolve_binding(pin=pin, attested=_attested(params), files=files, cwd=_server_cwd, registry=_registry())


def _workspace_for(binding: WorkspaceBinding) -> Workspace:
    """One Workspace per (root, source), reused across calls."""
    key = (str(binding.root), str(binding.source))
    if key not in _workspaces:
        _workspaces[key] = Workspace(root=binding.root)
    return _workspaces[key]


def _unbound_result(binding: WorkspaceBinding) -> Dict[str, Any]:
    if binding.status == "hold":
        return {"status": "hold", "reason": binding.reason, "error": binding.message, "binding": binding.as_dict()}
    if binding.status == "error":
        return {"status": "FAIL", "error": binding.message, "binding": binding.as_dict()}
    return {"status": "not_governed", "error": NOT_GOVERNED_MESSAGE, "binding": binding.as_dict()}


def _tool_result(
    req_id: Any,
    text: str,
    is_error: bool,
    structured: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if not is_error and isinstance(structured, dict):
        payload["structuredContent"] = structured
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": payload,
    }


def handle_request(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    global _session_id, _client_platform, _client_name, _client_version, _roots_capable, _host_roots

    if not isinstance(request, dict):
        return _error(None, -32600, "Invalid Request")
    req_id = request.get("id")
    if not _valid_id(req_id):
        return _error(None, -32600, "Invalid Request")
    if "method" not in request:
        if "result" in request or "error" in request:
            _route_response(request)
            return None
        return _error(req_id, -32600, "Invalid Request")
    method = request.get("method")
    if not isinstance(method, str):
        return _error(req_id, -32600, "Invalid Request")
    params = request.get("params")
    if params is None:
        params = {}

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "initialize":
        params = params if isinstance(params, dict) else {}
        _session_id = uuid.uuid4().hex
        _client_platform, _client_name, _client_version = _identify(params)
        capabilities = params.get("capabilities")
        _roots_capable = isinstance(capabilities, dict) and isinstance(capabilities.get("roots"), dict)
        _host_roots = ()
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiate_protocol(params.get("protocolVersion")),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "aegis-mcp", "version": __version__},
                "instructions": instructions_text(),
            },
        }
    if method in ("notifications/initialized", "notifications/roots/list_changed"):
        _request_roots()
        return None
    if method.startswith("notifications/"):
        return None
    if method not in ("tools/list", "tools/call"):
        return _error(req_id, -32601, f"Method not found: {method}")
    if _session_id is None:
        return _error(req_id, -32002, "Server not initialized")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOL_DEFINITIONS}}

    if _workspace_error is not None:
        return _tool_result(req_id, json.dumps(_unbound_result(_workspace_error)), True)
    if not isinstance(params, dict):
        return _error(req_id, -32602, "Tool call params must be an object.")

    name = params.get("name")
    args = params.get("arguments", {})
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return _error(req_id, -32602, "Tool arguments must be an object.")
    if not is_known_tool(name):
        return _error(req_id, -32602, f"Unknown tool: {name}")
    if not _check_rate_limit(name):
        max_calls, window = _RATE_LIMITS[name]
        return _error(req_id, -32000, f"Rate limit exceeded for '{name}': max {max_calls} calls per {window}s")

    # The client never chooses the workspace or the attribution of what it reports.
    args = strip_server_owned(args)
    binding = _bind(params, args)
    if binding.bound:
        args["workspace"] = _workspace_for(binding)
        args["_binding"] = binding.source
    elif binding.status == "unbound" and name == "aegis_scan":
        args["_unbound"] = binding.reason
    else:
        return _tool_result(req_id, json.dumps(_unbound_result(binding)), True)
    args["_host"] = _client_platform
    args["_session"] = _session_id
    args["_client_name"] = _client_name
    args["_client_version"] = _client_version

    try:
        # Handlers may print progress notes; stdout belongs to the JSON-RPC framing.
        with contextlib.redirect_stdout(sys.stderr):
            result = execute_tool(name, args)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return _tool_result(req_id, f"Tool execution failed: {exc}", True)
    return _tool_result(
        req_id,
        json.dumps(result),
        is_error_result(result),
        structured=result if isinstance(result, dict) else None,
    )


def _start(environ: Optional[Dict[str, str]] = None) -> None:
    """Reset the connection state and read what the process was started with."""
    global _canonical_workspace, _workspace_error, _server_cwd, _claude_project_dir
    for attr, value in fresh_state().items():
        globals()[attr] = value
    env = os.environ if environ is None else environ
    try:
        _server_cwd = os.getcwd()
    except OSError:
        _server_cwd = None
    _claude_project_dir = env.get("CLAUDE_PROJECT_DIR") or None
    pin = env_workspace(env)
    if pin:
        checked = resolve_binding(pin=pin)
        if checked.status == "error":
            # Stay up so the host does not mark the server failed; tools/call explains why.
            _workspace_error = checked
            print(f"aegis-mcp: {checked.message}", file=sys.stderr)
        else:
            _canonical_workspace = pin


def harden_process() -> bool:
    """Mark this process non-dumpable (``prctl(PR_SET_DUMPABLE, 0)``) on Linux.

    A non-dumpable process cannot be ptraced or have its memory read by a sibling of the same
    uid, and ``/proc/<pid>/fd`` stops being openable by them, independent of Yama. Best effort:
    False off Linux or when libc will not do it, and the server serves either way.
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes

        return ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE == 4
    except Exception:
        return False


def run_stdio_server():
    harden_process()
    _start()
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except (ValueError, RecursionError):
                # A deeply nested line exhausts the decoder's recursion budget: answer it
                # as unparseable and keep serving.
                send_error(None, -32700, "Parse error")
                continue

            if not isinstance(request, dict):
                # Batches are not supported; a scalar or array frame is an Invalid Request.
                send_error(None, -32600, "Invalid Request")
                continue

            try:
                if request.get("jsonrpc") != "2.0":
                    if "id" in request:
                        send_error(_safe_id(request["id"]), -32600, "Invalid Request")
                    continue

                response = handle_request(request)
                if response is not None and "id" in request:
                    send_response(response)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                if "id" in request:
                    send_error(_safe_id(request["id"]), -32603, "Internal error")
            for message in take_outbox():
                send_response(message)
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    finally:
        # Nothing of this connection may outlive it in an embedding process.
        for attr, value in fresh_state().items():
            globals()[attr] = value

    # Shutdown deliberately runs nothing (ADR 0005 AD-1): close-time reflection ran the
    # project's test target and, with N servers per repo, recorded one change N times.
    return 0


def main():
    sys.exit(run_stdio_server())
