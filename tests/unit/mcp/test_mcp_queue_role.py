"""Owner-bound queue connections: hostile inputs never enroll a caller."""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import symlink_or_skip

import aegis_mcp.server as server
import aegis_mcp.queue_role as queue_role
from aegis_core import team_queue
from aegis_core._version import __version__


QUEUE_INSTRUCTIONS = "Use aegis_team_queue to list and aegis_team_queue_claim to claim under owner policy."


def queue_initialize_response(instructions=QUEUE_INSTRUCTIONS):
    return {"jsonrpc": "2.0", "id": 1, "result": {
        "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
        "serverInfo": {"name": "aegis-mcp-queue", "version": __version__},
        "instructions": instructions,
    }}


@pytest.fixture
def owner_factory(tmp_path, monkeypatch):
    def create(*, role="orchestrator", environment_home=None, **changes):
        if not queue_role.supported():
            pytest.skip("requires Linux process identity and descriptor-relative operations")
        home = tmp_path / "owner"
        home.mkdir(mode=0o700)
        root = home / ".aegis" / "mcp-queue"
        registrations = root / "registrations"
        registrations.mkdir(parents=True, mode=0o700)
        (home / ".aegis").chmod(0o700)
        root.chmod(0o700)
        workspace = tmp_path / "repo"
        (workspace / ".aegis" / "rules").mkdir(parents=True)
        (workspace / ".aegis" / "team.json").write_text(
            json.dumps({"v": 1, "lanes": {"alpha": ["src/**"]}}), encoding="utf-8")
        policy = dict(schema="aegis.mcp.queue-registration/v1", registration_id="alpha",
                      endpoint="a/orchestrator", role=role, workspace=str(workspace),
                      lanes={"alpha": {"capabilities": ["core"], "branch": "refs/heads/lane/alpha"}},
                      ttl_s=600, session_ttl_s=7200)
        policy.update(changes)
        path = registrations / "alpha.json"
        path.write_text(json.dumps(policy), encoding="utf-8")
        path.chmod(0o600)
        monkeypatch.setattr(queue_role, "account_home", lambda: home)
        monkeypatch.setenv("HOME", str(home if environment_home is None else environment_home))
        monkeypatch.setenv("USERPROFILE", str(home if environment_home is None else environment_home))
        return queue_role, root, path, workspace, policy
    return create


def rpc(method, arguments=None, name="aegis_team_queue_claim"):
    params = {"name": name, "arguments": arguments} if method == "tools/call" else {}
    return server.handle_request({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def claim(arguments):
    response = rpc("tools/call", arguments)
    assert "error" not in response, response
    return json.loads(response["result"]["content"][0]["text"])


def start_owner(registration="alpha"):
    queue_role.issue(registration)
    server._start(queue_registration=registration)
    rpc("initialize")


def _os_view(**overrides):
    """Product os reference with the directory-opener callbacks authority() passes through."""
    values = dict(geteuid=os.geteuid, getpid=os.getpid, open=os.open, close=os.close,
                  fstat=os.fstat, stat=os.stat, fsencode=os.fsencode)
    values.update(overrides)
    return SimpleNamespace(**values)


def _confined_os_view(**overrides):
    values = dict(name=os.name, supports_dir_fd=os.supports_dir_fd, supports_follow_symlinks=os.supports_follow_symlinks,
                  O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_NOFOLLOW=os.O_NOFOLLOW,
                  O_NONBLOCK=os.O_NONBLOCK, O_CLOEXEC=os.O_CLOEXEC, fsencode=os.fsencode,
                  open=os.open, close=os.close, read=os.read, fstat=os.fstat, stat=os.stat)
    values.update(overrides)
    return SimpleNamespace(**values)


def _require_authority():
    if not queue_role.supported():
        pytest.skip("requires Linux descriptor-relative no-follow operations")


def _same_length(raw):
    mutated = bytearray(raw)
    mutated[-1] ^= 1
    mutated = bytes(mutated)
    assert len(mutated) == len(raw) and mutated != raw
    return mutated


def test_ordinary_initialize_and_tools_list_bytes_unchanged():
    # Captured from 0b0310f4 before the product edit. No git history is needed.
    server._start(environ={})
    initialized = rpc("initialize")
    initialized["result"]["serverInfo"]["version"] = "<version>"
    raw = json.dumps(initialized).encode("utf-8")
    assert len(raw) == 558
    assert hashlib.sha256(raw).hexdigest() == "a80c0f890703c21d02db8d54cbdf628a6d18b6453e37dea45355db5d91004e5e"
    listed = rpc("tools/list")
    raw = json.dumps(listed).encode("utf-8")
    assert len(listed["result"]["tools"]) == 10
    assert len(raw) == 11267
    # The scan_ref field is part of RULES-EVIDENCE-ATTRIBUTION-b.
    assert hashlib.sha256(raw).hexdigest() == "988fac033ecf63635185f9451f4311d020212bbf35a032debb198a3db6db4455"


@pytest.mark.parametrize("count", [1, queue_role.MAX_LANES], ids=["one", "max"])
def test_initialize_names_exact_startup_lanes_only(owner_factory, monkeypatch, count):
    lanes = {"lane-" + str(i).zfill(2) + "." + "x" * 54: {
        "capabilities": ["private-capability"], "branch": "refs/heads/private-branch"}
        for i in reversed(range(count))}
    role, root, path, workspace, policy = owner_factory(lanes=lanes)
    role.issue("alpha")
    server._start(queue_registration="alpha")
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    def unexpected():
        raise AssertionError("initialize must use the validated startup snapshot without authority IO")
    original = queue_role.authority
    monkeypatch.setattr(queue_role, "authority", unexpected)
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "lanes": ["forged"], "workspace": "forged", "capabilities": {"private": {}},
        "_meta": {"lane": "forged"}}})
    monkeypatch.setattr(queue_role, "authority", original)
    expected = (QUEUE_INSTRUCTIONS + " Startup lane ids (information only; grants no authority): "
                + json.dumps(list(lanes), separators=(",", ":"))
                + ". Claims revalidate owner policy, expiry and queue state.")
    assert response == queue_initialize_response(expected)
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    assert not (workspace / ".aegis" / "state").exists()


@pytest.mark.parametrize("mode,reason", [("missing", "role_missing"), ("invalid", "role_invalid"),
                                         ("too-many-lanes", "role_invalid")])
def test_refused_queue_initialize_bytes_unchanged(owner_factory, mode, reason):
    role, root, path, workspace, policy = owner_factory()
    if mode == "invalid":
        path.write_text("{}", encoding="utf-8")
    elif mode == "too-many-lanes":
        policy["lanes"] = {"lane" + str(i): policy["lanes"]["alpha"]
                           for i in range(role.MAX_LANES + 1)}
        path.write_text(json.dumps(policy), encoding="utf-8")
    server._start(queue_registration="alpha")
    assert json.dumps(rpc("initialize")).encode() == json.dumps(queue_initialize_response()).encode()
    for _ in range(2):
        result = claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})
        assert result["reason"] == reason and result["exit_code"] == 1


@pytest.mark.parametrize("mode", ["revoke", "remove-lane"])
@pytest.mark.parametrize("when", ["before-initialize", "after-initialize"])
def test_initialize_is_startup_information_after_policy_changes(owner_factory, mode, when):
    role, root, path, workspace, policy = owner_factory()
    role.issue("alpha")
    server._start(queue_registration="alpha")
    original = path.read_bytes()
    if mode == "revoke":
        policy["role"] = "reviewer"
    else:
        policy["lanes"] = {"beta": policy["lanes"]["alpha"]}
    if when == "before-initialize":
        path.write_text(json.dumps(policy), encoding="utf-8")
    response = rpc("initialize")
    assert 'Startup lane ids (information only; grants no authority): ["alpha"]' in response["result"]["instructions"]
    if when == "after-initialize":
        path.write_text(json.dumps(policy), encoding="utf-8")
    result = claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})
    assert result["reason"] == "role_stale" and result["exit_code"] == 1
    path.write_bytes(original)
    assert claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})["reason"] == "role_stale"
    assert not (workspace / ".aegis" / "state").exists()


def test_startup_lane_is_revalidated_after_waiting_for_queue_lock(owner_factory, monkeypatch):
    role, root, path, workspace, policy = owner_factory()
    role.issue("alpha")
    server._start(queue_registration="alpha")
    assert '["alpha"]' in rpc("initialize")["result"]["instructions"]
    real = role.storage
    @contextmanager
    def changed_while_waiting(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            policy["lanes"] = {"beta": policy["lanes"]["alpha"]}
            path.write_text(json.dumps(policy), encoding="utf-8")
            yield held
    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=changed_while_waiting, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    for _ in range(2):
        result = claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})
        assert result["reason"] == "role_stale" and result["exit_code"] == 1
    assert not (workspace / ".aegis" / "state" / "team-queue.json").exists()


def test_ordinary_connection_has_no_grant(owner_factory, tmp_path, monkeypatch):
    from aegis_mcp.registry import TOOL_DEFINITIONS

    monkeypatch.setenv("AEGIS_ROLE", "orchestrator")
    monkeypatch.setenv("AEGIS_QUEUE_REGISTRATION", "alpha")
    server._start(environ={})
    rpc("initialize")
    assert rpc("tools/list")["result"]["tools"] == TOOL_DEFINITIONS
    result = claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})
    assert result["reason"] == "role_missing" and result["exit_code"] == 1


def test_model_writable_records_and_metadata_cannot_enroll(tmp_path, monkeypatch):
    root = tmp_path / "model-workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    forged = root / ".aegis" / "mcp-queue" / "registrations"
    forged.mkdir(parents=True)
    (forged / "alpha.json").write_text(json.dumps({"role": "orchestrator", "registration_id": "alpha"}))
    (root / "connection.json").write_text(json.dumps({"role": "orchestrator", "session": "forged"}))
    def unexpected():
        raise AssertionError("ordinary connections must not discover role records")
    monkeypatch.setattr(queue_role, "account_home", unexpected)
    server._start(environ={"AEGIS_WORKSPACE": str(root)})
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "clientInfo": {"name": "orchestrator"}, "role": "orchestrator",
        "_meta": {"role": "orchestrator", "registration_id": "alpha", "session": "forged"}}})
    assert "error" not in response
    assert claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})["reason"] == "role_missing"
    assert not (root / ".aegis" / "state").exists()


@pytest.mark.parametrize("arguments", [None, [], "token=private-value", {},
    {"id": "ONE\n", "expect": "a" * 64, "lane": "alpha"},
    {"id": "sk-" + "a" * 24, "expect": "a" * 64, "lane": "alpha"},
    {"id": "A" * 65, "expect": "a" * 64, "lane": "alpha"},
    {"id": "ONE", "expect": "a" * 65, "lane": "alpha"},
    {"id": "ONE", "expect": "A" * 64, "lane": "alpha"},
    {"id": "ONE", "expect": 1, "lane": "alpha"},
    *[{"id": "ONE", "expect": "a" * 64, "lane": "alpha", key: "token=private-value"}
      for key in ("role", "_role", "_grant", "workspace", "_session", "_binding", "files",
                  "capabilities", "branch", "ttl_s", "host", "record")]])
def test_claim_closed_input_precedes_binding(arguments, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid input must not bind")

    rpc("initialize")
    monkeypatch.setattr(server, "_bind", unexpected)
    result = claim(arguments)
    assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("bound", [False, True], ids=["ordinary", "owner"])
@pytest.mark.parametrize("lane", ["a..b", "-alpha", "a" * 64, "alpha.", "alpha.lock"],
                         ids=["parent", "leading-dash", "length", "trailing-dot", "lock-suffix"])
def test_client_lane_uses_core_predicate_before_any_io(owner_factory, monkeypatch, bound, lane):
    if bound:
        role, root, path, workspace, policy = owner_factory()
        start_owner()
        before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    else:
        rpc("initialize")
    def unexpected(*args, **kwargs):
        raise AssertionError("malformed lane reached binding or authority IO")
    monkeypatch.setattr(server, "_bind", unexpected)
    monkeypatch.setattr(queue_role, "authority", unexpected)
    result = claim({"id": "ONE", "expect": "a" * 64, "lane": lane})
    assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
    if bound:
        assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("kind,value", [
    ("lane", "a..b"), ("lane", "alpha."), ("lane", "alpha.lock"),
    ("capabilities", ["core", "core"]), ("branch", "refs/heads/HEAD"),
    ("branch", "refs/heads/" + "x" * (201 - len("refs/heads/")))],
    ids=["parent-lane", "dot-lane", "lock-lane", "duplicate-capability", "head-branch", "branch-length"])
def test_owner_policy_uses_core_predicates_before_issuance(owner_factory, kind, value):
    role, root, path, workspace, policy = owner_factory()
    original = path.read_bytes()
    if kind == "lane":
        policy["lanes"] = {value: policy["lanes"]["alpha"]}
    else:
        policy["lanes"]["alpha"][kind] = value
    path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.issue("alpha")
    assert not (root / "sessions").exists()
    path.write_bytes(original)
    role.issue("alpha")
    assert len(list((root / "sessions").glob("*.json"))) == 1


def _registration_boundary_bytes(policy, workspace, boundary, extra=0):
    # These are independent documented schema bounds, not implementation caps.
    if boundary in ("workspace", "escaped-workspace"):
        policy["workspace"] = str(workspace) + "/" * (4096 + extra - len(str(workspace)))
    elif boundary == "lanes":
        policy["lanes"] = {"lane" + str(i): {"capabilities": [], "branch": "refs/heads/lane/work"} for i in range(64 + extra)}
    elif boundary == "capabilities":
        policy["lanes"]["alpha"]["capabilities"] = ["c" + str(i) for i in range(128 + extra)]
    elif boundary in ("bytes", "bytes-exact"):
        policy["lanes"] = {"lane" + str(i): {"capabilities": ["c" + str(j) for j in range(128)],
                                           "branch": "refs/heads/lane/work"} for i in range(64)}
    elif boundary == "branch":
        prefix = "refs/heads/"
        policy["lanes"]["alpha"]["branch"] = prefix + "x" * (200 + extra - len(prefix))
    raw = json.dumps(policy, separators=(",", ":"))
    if boundary == "escaped-workspace":
        quoted = json.dumps(policy["workspace"])
        escaped = '"' + "".join("\\u%04x" % ord(char) for char in policy["workspace"]) + '"'
        raw = raw.replace(quoted, escaped)
    data = raw.encode("utf-8")
    if boundary in ("bytes", "bytes-exact"):
        limit = 65536 if boundary == "bytes-exact" else 65535 if extra == 0 else 65537
        assert len(data) < limit
        data += b" " * (limit - len(data))
    return data


@pytest.mark.parametrize("boundary", ["workspace", "escaped-workspace", "lanes", "capabilities", "bytes", "bytes-exact", "branch"])
def test_schema_boundary_registration_issues(owner_factory, boundary):
    role, root, path, workspace, policy = owner_factory()
    raw = _registration_boundary_bytes(policy, workspace, boundary)
    assert len(raw) <= 65536
    path.write_bytes(raw)
    role.issue("alpha")
    assert len(list((root / "sessions").glob("*.json"))) == 1


@pytest.mark.parametrize("boundary", ["workspace", "lanes", "capabilities", "bytes", "branch"])
def test_schema_boundary_plus_one_has_fixed_refusal(owner_factory, boundary):
    role, root, path, workspace, policy = owner_factory()
    path.write_bytes(_registration_boundary_bytes(policy, workspace, boundary, extra=1))
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.issue("alpha")
    assert not (root / "sessions").exists()


def test_owner_session_lifetime_and_two_tool_surface(owner_factory, tmp_path, monkeypatch):
    role, root, path, workspace, policy = owner_factory()
    start_owner()
    tools = rpc("tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["aegis_team_queue", "aegis_team_queue_claim"]
    assert len(json.dumps(tools).encode()) <= 11500
    record = next((root / "sessions").glob("*.json"))
    value = json.loads(record.read_text())
    assert value["expires_at"] - value["created_at"] == 7200
    assert value["mcp_session"] == server._session_id
    assert set(value) == {"schema", "registration_id", "registration_sha256", "process",
                          "mcp_session", "created_at", "expires_at"}


def test_queue_root_uses_account_home_when_environment_differs(owner_factory, tmp_path):
    environment_home = tmp_path / "environment-home"
    environment_home.mkdir()
    role, root, path, workspace, policy = owner_factory(environment_home=environment_home)
    assert Path(os.environ["HOME"]) == environment_home
    assert Path(os.environ["USERPROFILE"]) == environment_home
    assert role.account_home() != environment_home
    start_owner()
    records = list((root / "sessions").glob("*.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["mcp_session"] == server._session_id
    assert not list(environment_home.iterdir())


@pytest.mark.parametrize("mode", ["replace", "same-bytes", "remove", "chmod", "expire"])
def test_revalidation_latches_stale(owner_factory, tmp_path, monkeypatch, mode):
    role, root, path, workspace, policy = owner_factory()
    start_owner()
    original = path.read_bytes()
    if mode in ("replace", "same-bytes"):
        replacement = path.with_suffix(".new")
        replacement.write_bytes(original if mode == "same-bytes" else b"{}")
        replacement.chmod(0o600)
        replacement.replace(path)
    elif mode == "remove":
        path.unlink()
    elif mode == "chmod":
        path.chmod(0o666)
    else:
        monkeypatch.setattr(queue_role, "time", SimpleNamespace(time=lambda: 4102444800))
    arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    assert claim(arguments)["reason"] == "role_stale"
    path.write_bytes(original)
    path.chmod(0o600)
    assert claim(arguments)["reason"] == "role_stale"
    assert not (workspace / ".aegis" / "state").exists()


@pytest.mark.parametrize("seat", ["root", "router", "decider", "reviewer", "builder", "implementer"])
def test_non_claiming_role_refused(owner_factory, tmp_path, monkeypatch, seat):
    owner_factory(role=seat)
    start_owner()
    assert claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})["reason"] == "role_forbidden"


def test_second_initialize_invalidates(owner_factory, tmp_path, monkeypatch):
    owner_factory()
    start_owner()
    assert rpc("initialize")["error"] == {"code": -32600, "message": "Queue connection already initialized."}
    assert claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})["reason"] == "role_stale"


def test_unsupported_probe_is_fixed(monkeypatch):
    monkeypatch.setattr(queue_role, "supported", lambda: False)
    server._start(queue_registration="alpha")
    assert json.dumps(rpc("initialize")).encode() == json.dumps(queue_initialize_response()).encode()
    assert claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})["reason"] == "unsupported_platform"


@pytest.mark.parametrize("raw", [b"{" * 13, b'{"schema":1,"schema":2}', b'{"x":NaN}',
    b'{"x":1e999}', b'"' + b"x" * 4097 + b'"', b" " * 65537, b"\xff", b"{}"],
    ids=["depth", "duplicate", "nonfinite", "overflow", "token", "size", "utf8", "shape"])
def test_malformed_owner_record_fixed(owner_factory, tmp_path, monkeypatch, raw):
    role, root, path, workspace, policy = owner_factory()
    path.write_bytes(raw)
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.issue("alpha")
    assert not (root / "sessions").exists()


def test_missing_and_foreign_session_records(owner_factory, tmp_path, monkeypatch):
    role, root, path, workspace, policy = owner_factory()
    server._start(queue_registration="alpha")
    rpc("initialize")
    args = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    assert claim(args)["reason"] == "role_missing"
    role.issue("alpha")
    record = next((root / "sessions").glob("*.json"))
    value = json.loads(record.read_text())
    value["process"]["pid"] += 1
    record.write_text(json.dumps(value))
    server._start(queue_registration="alpha")
    rpc("initialize")
    assert claim(args)["reason"] == "role_foreign"


@pytest.mark.parametrize("component", ["registration", "registrations", "authority"])
def test_symlink_authority_refuses(owner_factory, tmp_path, monkeypatch, component):
    role, root, path, workspace, policy = owner_factory()
    target = {"registration": path, "registrations": path.parent, "authority": root}[component]
    moved = target.with_name(target.name + "-old")
    target.rename(moved)
    symlink_or_skip(moved, target, target_is_directory=component != "registration")
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.issue("alpha")


def test_authority_read_fault_has_no_echo_and_closes_handles(owner_factory, tmp_path, monkeypatch):
    role, root, path, workspace, policy = owner_factory()
    before = len(list(Path("/proc/self/fd").iterdir()))
    def failed(*args, **kwargs):
        raise OSError("token=private-value")
    monkeypatch.setattr(queue_role, "os", _os_view(stat=failed))
    with pytest.raises(role.RoleRefusal, match="^role_io_unavailable$"):
        role.issue("alpha")
    assert len(list(Path("/proc/self/fd").iterdir())) == before


def test_queue_identity_environment_is_never_printed(owner_factory, monkeypatch, capsys):
    owner_factory()
    monkeypatch.setenv("AEGIS_CLIENT", "token=private-value")
    start_owner()
    assert "private-value" not in capsys.readouterr().err


@pytest.mark.parametrize("mode", ["hardlink", "directory", "fifo", "group-writable", "foreign-owner"])
def test_unsafe_owner_files_refuse(owner_factory, monkeypatch, mode):
    role, root, path, workspace, policy = owner_factory()
    if mode == "hardlink":
        os.link(path, path.with_suffix(".copy"))
    elif mode == "directory":
        path.unlink()
        path.mkdir()
    elif mode == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif mode == "group-writable":
        path.chmod(0o620)
    else:
        monkeypatch.setattr(queue_role, "os", _os_view(geteuid=lambda: os.geteuid() + 1))
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.issue("alpha")


def test_oversize_refuses_before_parser(owner_factory, monkeypatch):
    role, root, path, workspace, policy = owner_factory()
    path.write_bytes(b" " * 65537)
    def unexpected(raw):
        raise AssertionError("oversize record reached the parser")
    monkeypatch.setattr(queue_role, "primitives", SimpleNamespace(strict_loads=unexpected))
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.issue("alpha")


def test_owner_lock_timeout_is_retryable(owner_factory, monkeypatch):
    from contextlib import contextmanager
    from aegis_core import storage

    role, root, path, workspace, policy = owner_factory()
    real = role.storage
    @contextmanager
    def timed_out(*args, **kwargs):
        raise storage.LockTimeoutError("token=private-value")
        yield
    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(file_lock=timed_out, LockTimeoutError=storage.LockTimeoutError))
    with pytest.raises(role.RoleRefusal, match="^role_lock_timeout$"):
        role.issue("alpha")
    monkeypatch.setattr(queue_role, "storage", real)
    role.issue("alpha")


def test_ancestor_rename_between_validation_and_read_is_confined(owner_factory, monkeypatch):
    role, root, path, workspace, policy = owner_factory()
    moved = path.parent.with_name("registrations-old")
    parent = path.parent.stat()

    def inspect(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino) and not moved.exists():
            path.parent.rename(moved)
            symlink_or_skip(workspace, path.parent, target_is_directory=True)
        return info

    monkeypatch.setattr("aegis_core.storage_confined.os", SimpleNamespace(**{**vars(os), "fstat": inspect}))
    # The anchored original parent may complete issuance; its replacement cannot
    # redirect the read. Binding then refuses the new symlinked pathname.
    role.issue("alpha")
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.bind("alpha")
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    path.parent.unlink()
    moved.rename(path.parent)
    assert role.bind("alpha").workspace == str(workspace)


def test_record_generation_change_during_read_refuses_then_allows_retry(owner_factory, monkeypatch):
    role, root, path, workspace, _ = owner_factory()
    replacement = path.with_name("replacement.json")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    parent = path.parent.stat()
    stats = []
    opened_leaves = []

    def opened(name, flags, *, dir_fd):
        descriptor = os.open(name, flags, dir_fd=dir_fd)
        if name == path.name:
            opened_leaves.append(descriptor)
        return descriptor

    def inspect(name, *, dir_fd=None, follow_symlinks=True):
        if name == path.name:
            assert dir_fd is not None and follow_symlinks is False
            held = os.fstat(dir_fd)
            assert (held.st_dev, held.st_ino) == (parent.st_dev, parent.st_ino)
            if opened_leaves:
                stats.append(dir_fd)
                if len(stats) == 2:
                    replacement.replace(path)
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr("aegis_core.storage_confined.os", _confined_os_view(open=opened, stat=inspect))
    with pytest.raises(role.RoleRefusal, match="^role_stale$"):
        role.issue("alpha")
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    assert len(stats) == 2 and stats[0] == stats[1]
    assert not (root / "sessions").exists()
    role.issue("alpha")
    assert role.bind("alpha").workspace == str(workspace)


def test_issue_checks_opened_record_policy_before_reading(owner_factory, monkeypatch):
    role, root, path, workspace, _ = owner_factory()
    original = path.with_suffix(".original")
    replacement = path.with_suffix(".replacement")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o640)
    consumed = []
    leaves = []

    def opened(name, flags, *args, **kwargs):
        if name == path.name:
            path.rename(original)
            replacement.replace(path)
            leaf = os.open(name, flags, *args, **kwargs)
            leaves.append(leaf)
            return leaf
        return os.open(name, flags, *args, **kwargs)

    def read(fd, count):
        if fd in leaves:
            consumed.append(count)
        return os.read(fd, count)

    monkeypatch.setattr("aegis_core.storage_confined.os", _confined_os_view(open=opened, read=read))
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.issue("alpha")
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    assert consumed == []
    assert not (root / "sessions").exists()
    original.replace(path)
    role.issue("alpha")
    assert role.bind("alpha").workspace == str(workspace)


def _authority_socket(directory):
    path = directory / "authority.sock"
    os.mknod(path, stat.S_IFSOCK | 0o600)
    return path


_LAUNCH_READ_ADVICE = {
    "role_missing": "Ask the owner to install the registration and restart the queue connection.",
    "role_invalid": "Ask the owner to repair the authority records and restart the queue connection.",
    "role_stale": "Retry the launch.",
    "role_io_unavailable": "Ask the owner to inspect authority storage and restart the queue connection.",
}


@pytest.mark.parametrize("operation,record", [("issue", "registration"), ("bind", "registration"), ("bind", "session")])
@pytest.mark.parametrize("fault,reason", [
    ("socket", "role_invalid"), ("unlink", "role_missing"), ("replace", "role_stale"),
    ("short", "role_stale"), ("growth", "role_stale"), ("io", "role_io_unavailable"),
    ("unreadable", "role_invalid"), ("nonprivate", "role_invalid"),
    ("hardlink", "role_invalid"), ("oversize", "role_invalid"),
    ("definite-missing", "role_missing"), ("definite-unsafe", "role_invalid"),
    ("open-unreadable", "role_invalid"), ("fstat-oversize", "role_invalid"),
])
def test_launch_checked_authority_read_refusals(owner_factory, monkeypatch, operation, record, fault, reason):
    role, root, path, workspace, _ = owner_factory()
    if operation == "bind":
        role.issue("alpha")
    target = path if record == "registration" else _session_file(root)
    original = target.read_bytes()
    replacement = target.with_suffix(".new")
    replacement.write_bytes(original)
    replacement.chmod(0o600)
    sock = _authority_socket(workspace.parent) if fault == "socket" else None
    reading = set()
    initial_defects = ("unreadable", "nonprivate", "hardlink", "oversize")
    hardlink = target.with_suffix(".link")
    if fault == "unreadable":
        target.chmod(0o000)
    elif fault == "nonprivate":
        target.chmod(0o640)
    elif fault == "hardlink":
        os.link(target, hardlink)
    elif fault == "oversize":
        target.write_bytes(b"x" * (role.MAX_BYTES + 1))
    failed_opens = []

    def opened(name, flags, *args, **kwargs):
        if name != target.name:
            return os.open(name, flags, *args, **kwargs)
        if fault in ("definite-missing", "definite-unsafe"):
            replacement.replace(target)
            number = errno.ENOENT if fault == "definite-missing" else errno.ELOOP
            raise OSError(number, "private-value")
        if fault == "open-unreadable":
            target.chmod(0o000)
            raise OSError(errno.EACCES, "private-value")
        if fault == "socket":
            sock.replace(target)
        if fault == "io" or fault in initial_defects:
            failed_opens.append(name)
            raise OSError(errno.EIO, "private-value")
        fd = os.open(name, flags, *args, **kwargs)
        reading.add(fd)
        return fd

    def inspect_opened(fd):
        if fd in reading:
            if fault == "unlink":
                target.unlink()
            if fault == "replace":
                replacement.replace(target)
            if fault == "fstat-oversize":
                target.write_bytes(original + b" " * role.MAX_BYTES)
                raise OSError(errno.EIO, "private-value")
        return os.fstat(fd)

    def read(fd, count):
        if fd in reading:
            reading.discard(fd)
            if fault == "short":
                return b""
            if fault == "growth":
                target.write_bytes(original + b" " * role.MAX_BYTES)
        return os.read(fd, count)

    launch = role.issue if operation == "issue" else role.bind
    monkeypatch.setattr("aegis_core.storage_confined.os", _confined_os_view(open=opened, fstat=inspect_opened, read=read))
    with pytest.raises(role.RoleRefusal) as caught:
        launch("alpha")
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    assert caught.value.reason == str(caught.value) == reason
    assert role.launch_advice(caught.value.reason) == _LAUNCH_READ_ADVICE[reason]
    if fault in initial_defects:
        assert failed_opens == []
    if operation == "issue":
        assert not (root / "sessions").exists()
    if fault == "socket":
        target.unlink()
    if fault == "hardlink":
        hardlink.unlink()
    if fault in ("unreadable", "open-unreadable"):
        target.chmod(0o600)
    target.write_bytes(original)
    target.chmod(0o600)
    if operation == "issue":
        role.issue("alpha")
    assert role.bind("alpha").workspace == str(workspace)


@pytest.mark.parametrize("operation,record", [("issue", "registration"), ("bind", "registration"), ("bind", "session")])
@pytest.mark.parametrize("defect,later_name", [
    ("mode", "restored"), ("size", "restored"), ("mode", "different"), ("size", "missing"),
])
def test_launch_descriptor_defect_preserves_repair_advice(
        owner_factory, monkeypatch, operation, record, defect, later_name):
    role, root, path, workspace, _ = owner_factory()
    if operation == "bind":
        role.issue("alpha")
    target = path if record == "registration" else _session_file(root)
    original = target.read_bytes()
    replacement = target.with_suffix(".new")
    replacement.write_bytes(original)
    replacement.chmod(0o600)
    leaves = set()
    name_checks, observed = [], []

    def opened(name, flags, *args, **kwargs):
        fd = os.open(name, flags, *args, **kwargs)
        if name == target.name:
            leaves.add(fd)
        return fd

    def inspect(fd):
        if fd not in leaves:
            return os.fstat(fd)
        assert not observed
        if defect == "mode":
            os.fchmod(fd, 0o640)
        else:
            target.write_bytes(original + b" " * role.MAX_BYTES)
        info = os.fstat(fd)
        observed.append(info)
        if later_name == "restored":
            if defect == "mode":
                os.fchmod(fd, 0o600)
            else:
                target.write_bytes(original)
        else:
            target.rename(target.with_suffix(".displaced"))
            if later_name == "different":
                replacement.replace(target)
        return info

    def stat_at(name, *args, **kwargs):
        if name == target.name:
            assert kwargs.get("dir_fd") is not None and kwargs.get("follow_symlinks") is False
            name_checks.append(name)
        return os.stat(name, *args, **kwargs)

    def read(fd, count):
        assert fd not in leaves, "refused record reached byte consumption"
        return os.read(fd, count)

    def close(fd):
        leaves.discard(fd)
        os.close(fd)

    launch = role.issue if operation == "issue" else role.bind
    monkeypatch.setattr("aegis_core.storage_confined.os", _confined_os_view(
        open=opened, fstat=inspect, stat=stat_at, read=read, close=close))
    with pytest.raises(role.RoleRefusal) as caught:
        launch("alpha")
    assert caught.value.reason == str(caught.value) == "role_invalid"
    assert role.launch_advice(caught.value.reason) == _LAUNCH_READ_ADVICE["role_invalid"]
    assert not leaves and name_checks == [target.name]
    assert len(observed) == 1 and observed[0].st_nlink == 1
    if operation == "issue":
        assert not (root / "sessions").exists()


_CHECKED_READ_FAULTS = [
    ("name-io-after-rewrite", "role_stale"),
    ("name-and-read-io-after-rewrite", "role_stale"),
    ("leaf-close-after-unlink", "role_missing"),
    ("parent-close-after-unlink", "role_missing"),
    ("leaf-close", "role_io_unavailable"),
    ("parent-close", "role_io_unavailable"),
    ("parent-stat", "role_io_unavailable"),
    ("admission-stat-after-unlink", "role_io_unavailable"),
]


class _RecordReadFault:
    def __init__(self, target, fault, *, active):
        self.target = target
        self.fault = fault
        self.active = active
        self.started = False
        self.owned = {}
        self.closed = []

    def open(self, name, flags, *args, **kwargs):
        fd = os.open(name, flags, *args, **kwargs)
        if self.active and name == self.target.name:
            self.owned[fd] = "leaf"
        elif self.active and name == self.target.parent.name:
            self.owned[fd] = "parent"
        return fd

    def read(self, fd, count):
        if not self.started and self.owned.get(fd) == "leaf":
            self.started = True
            if self.fault.endswith("rewrite"):
                os.utime(self.target, ns=(0, 0))
            if self.fault.endswith("unlink"):
                self.target.unlink()
            if self.fault.startswith("name-and-read-io"):
                raise OSError(errno.EIO, "private-value")
        return os.read(fd, count)

    def stat(self, name, *args, **kwargs):
        if (self.fault == "admission-stat-after-unlink" and name == self.target.name
                and "leaf" in self.owned.values()):
            self.target.unlink()
            raise OSError(errno.EIO, "private-value")
        if self.started and name == self.target.name and self.fault.startswith("name"):
            assert kwargs.get("dir_fd") is not None and kwargs.get("follow_symlinks") is False
            raise OSError(errno.EIO, "private-value")
        return os.stat(name, *args, **kwargs)

    def fstat(self, fd):
        if self.fault == "parent-stat" and self.owned.get(fd) == "parent":
            raise OSError(errno.EIO, "private-value")
        return os.fstat(fd)

    def close(self, fd):
        os.close(fd)
        kind = self.owned.pop(fd, None)
        if kind is not None:
            self.closed.append(kind)
            if self.fault.startswith(kind + "-close"):
                raise OSError(errno.EIO, "private-value")

    def os_view(self):
        return _confined_os_view(open=self.open, read=self.read, stat=self.stat, fstat=self.fstat, close=self.close)


@pytest.mark.parametrize("operation,record", [("issue", "registration"), ("bind", "registration"), ("bind", "session")])
@pytest.mark.parametrize("fault,reason", _CHECKED_READ_FAULTS)
def test_launch_checked_read_decision_through_cleanup(owner_factory, monkeypatch, operation, record, fault, reason):
    role, root, path, workspace, _ = owner_factory()
    if operation == "bind":
        role.issue("alpha")
    target = path if record == "registration" else _session_file(root)
    original = target.read_bytes()
    failure = _RecordReadFault(target, fault, active=True)
    launch = role.issue if operation == "issue" else role.bind
    monkeypatch.setattr("aegis_core.storage_confined.os", failure.os_view())
    with pytest.raises(role.RoleRefusal) as caught:
        launch("alpha")
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    assert caught.value.reason == str(caught.value) == reason
    assert role.launch_advice(caught.value.reason) == _LAUNCH_READ_ADVICE[reason]
    assert failure.closed == (["parent"] if fault == "parent-stat" else ["leaf", "parent"])
    assert not failure.owned
    if operation == "issue":
        assert not (root / "sessions").exists()
    if fault.endswith("unlink"):
        target.write_bytes(original)
        target.chmod(0o600)
    if operation == "issue":
        role.issue("alpha")
    assert role.bind("alpha").workspace == str(workspace)


_ROLE_ARGUMENT_NEXT = "Use only id, expect and lane from the queue list and owner policy."
_QUEUE_ARGUMENT_NEXT = "Use the documented queue arguments and the revision returned by list."


def _registration(**lane):
    options = {"capabilities": ["core"], "branch": "refs/heads/lane/alpha"}
    options.update(lane)
    return {"schema": "aegis.mcp.queue-registration/v1", "registration_id": "alpha",
            "endpoint": "a/orchestrator", "role": "orchestrator", "workspace": "/workspace",
            "lanes": {"alpha": options}, "ttl_s": 600, "session_ttl_s": 7200}


def _calls(seen, real):
    def spy(*args, **kwargs):
        seen.append(args[0] if args else None)
        return real(*args, **kwargs)

    return spy


def _seen_valid_key(monkeypatch):
    seen = []
    monkeypatch.setattr(queue_role.team_queue, "valid_key", _calls(seen, team_queue.valid_key))
    return seen


def _seen_valid_revision(monkeypatch):
    seen = []
    monkeypatch.setattr(queue_role.team_queue, "valid_revision", _calls(seen, team_queue.valid_revision))
    return seen


def _seen_valid_lane(monkeypatch):
    seen = []
    monkeypatch.setattr(queue_role.team_queue, "valid_lane", _calls(seen, team_queue.valid_lane))
    return seen


def _seen_check_capabilities(monkeypatch):
    seen = []
    monkeypatch.setattr(queue_role.team_queue, "check_capabilities", _calls(seen, team_queue.check_capabilities))
    return seen


def _seen_normalize_branch(monkeypatch):
    seen = []
    monkeypatch.setattr(queue_role.team_queue, "normalize_branch", _calls(seen, team_queue.normalize_branch))
    return seen


def _no_role_io(monkeypatch):
    def unavailable(*args, **kwargs):
        pytest.fail("role field validation must not touch authority storage")

    # Authority and confinement are this module's own bindings. descriptor_supported
    # is the public probe team_queue calls before descriptor I/O.
    monkeypatch.setattr(queue_role, "authority", unavailable)
    monkeypatch.setattr(queue_role, "storage_confined", SimpleNamespace(
        confined_file=unavailable, read_checked_file=unavailable, descriptor_supported=unavailable))
    monkeypatch.setattr(team_queue, "descriptor_supported", unavailable)


def _assert_role_refusal(result):
    rendered = json.dumps(result)
    assert result["reason"] == "invalid_arguments" and result["error"] == "invalid_arguments"
    assert result["exit_code"] == 2 and result["refused"] is True and result["status"] == "refused"
    assert result["next_action"] == _ROLE_ARGUMENT_NEXT
    assert "\n" not in rendered and "injected" not in rendered and "private-value" not in rendered
    assert "bad id" not in rendered


def _assert_stale_claim(result):
    fields = dict(result)
    assert fields.pop("checked_at")
    assert fields == {
        "schema": "aegis.team.queue.claim/v1", "source": "aegis team queue claim",
        "aegis_version": __version__, "scope": {}, "refused": True, "status": "refused",
        "reason": "role_stale", "error": "role_stale", "exit_code": 1,
        "next_action": "Ask the owner to restart the queue connection with a fresh session record.",
    }


@pytest.mark.parametrize("identifier,revision,lane,stopped", [
    ("bad id", "a" * 64, "alpha", "valid_key"),
    ("ONE\ninjected", "a" * 64, "alpha", "valid_key"),
    ("", "a" * 64, "alpha", "valid_key"),
    ("A" * 65, "a" * 64, "alpha", "valid_key"),
    ("ONE", "A" * 64, "alpha", "valid_revision"),
    ("ONE", "a" * 63, "alpha", "valid_revision"),
    ("ONE", "a" * 63 + "\ninjected", "alpha", "valid_revision"),
    ("ONE", "g" * 64, "alpha", "valid_revision"),
    ("ONE", None, "alpha", "valid_revision"),
    ("ONE", "a" * 64, "a..b", "valid_lane"),
    ("ONE", "a" * 64, "alpha.lock", "valid_lane"),
    ("ONE", "a" * 64, "Alpha", "valid_lane"),
    ("ONE", "a" * 64, "alpha\ninjected", "valid_lane"),
    ("ONE", "a" * 64, "", "valid_lane"),
], ids=["spaced-id", "multiline-id", "empty-id", "long-id", "upper-revision", "short-revision",
        "multiline-revision", "nonhex-revision", "revision-type", "parent-lane", "lock-lane",
        "upper-lane", "multiline-lane", "empty-lane"])
def test_claim_argument_refusal_uses_public_predicates(monkeypatch, identifier, revision, lane, stopped):
    seen = {"valid_key": _seen_valid_key(monkeypatch), "valid_revision": _seen_valid_revision(monkeypatch),
            "valid_lane": _seen_valid_lane(monkeypatch)}
    _no_role_io(monkeypatch)
    arguments = {"id": identifier, "expect": revision, "lane": lane}
    result = queue_role.claim_argument_refusal(arguments)
    role_seen = {name: list(values) for name, values in seen.items()}
    operation = team_queue.claim("/workspace", identifier, expect=revision, lane=lane,
                                 capabilities=["core"], now=100)
    _assert_role_refusal(result)
    assert operation["reason"] == "invalid_arguments" and operation["exit_code"] == 2
    assert operation["next_action"] == _QUEUE_ARGUMENT_NEXT
    assert role_seen["valid_key"][0] == identifier
    if stopped == "valid_key":
        assert role_seen["valid_key"] == [identifier]
        assert role_seen["valid_revision"] == [] and role_seen["valid_lane"] == []
    elif stopped == "valid_revision":
        assert role_seen["valid_key"] == [identifier]
        assert role_seen["valid_revision"] == [revision] and role_seen["valid_lane"] == []
    else:
        assert role_seen["valid_key"] == [identifier, lane]
        assert role_seen["valid_revision"] == [revision] and role_seen["valid_lane"] == [lane]
    repaired = queue_role.claim_argument_refusal({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})
    assert repaired is None


def test_claim_arguments_reject_extra_fields_before_predicates(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("field predicates ran before the closed claim schema")

    _no_role_io(monkeypatch)
    monkeypatch.setattr(queue_role.team_queue, "valid_key", explode)
    monkeypatch.setattr(queue_role.team_queue, "valid_lane", explode)
    monkeypatch.setattr(queue_role.team_queue, "valid_revision", explode)
    monkeypatch.setattr(queue_role.team_queue, "check_capabilities", explode)
    monkeypatch.setattr(queue_role.team_queue, "normalize_branch", explode)
    result = queue_role.claim_argument_refusal({
        "id": "ONE", "expect": "a" * 64, "lane": "alpha",
        "capabilities": ["core", "core"], "branch": "refs/tags/private-value"})
    _assert_role_refusal(result)


@pytest.mark.parametrize("kind,value", [
    ("lane", "a..b"),
    ("lane", "alpha.lock"),
    ("lane", "alpha\ninjected"),
    ("capabilities", ["core", "core"]),
    ("capabilities", ["bad id"]),
    ("capabilities", ["core\ninjected"]),
    ("capabilities", "core"),
    ("branch", "refs/tags/private-value"),
    ("branch", "refs/heads/HEAD"),
    ("branch", "HEAD"),
    ("branch", "refs/heads/"),
    ("branch", "private-value topic"),
    ("branch", "private-value\ninjected"),
    ("branch", ""),
    ("branch", 1),
], ids=["parent-lane", "lock-lane", "multiline-lane", "duplicate-capabilities", "spaced-capability",
        "multiline-capability", "capability-type", "tags-branch", "heads-head", "head", "empty-name",
        "spaced-branch", "multiline-branch", "empty-branch", "branch-type"])
def test_policy_failures_use_public_predicates_and_retry(monkeypatch, kind, value):
    lanes = _seen_valid_lane(monkeypatch)
    capabilities = _seen_check_capabilities(monkeypatch)
    branches = _seen_normalize_branch(monkeypatch)
    _no_role_io(monkeypatch)
    policy = _registration()
    if kind == "lane":
        policy["lanes"] = {value: policy["lanes"]["alpha"]}
    else:
        policy["lanes"]["alpha"][kind] = value
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
        queue_role._policy(policy, "alpha")
    assert str(caught.value) == "role_invalid"
    assert "private-value" not in str(caught.value) and "injected" not in str(caught.value)
    assert "\n" not in str(caught.value)
    if kind == "lane":
        assert lanes == [value] and capabilities == [] and branches == []
    elif kind == "capabilities":
        assert lanes == ["alpha"] and capabilities == [value] and branches == []
    elif type(value) is not str:
        assert lanes == ["alpha"] and capabilities == [] and branches == []
    else:
        assert lanes == ["alpha"] and capabilities == [["core"]] and branches == [value]
    restored = _registration()
    accepted = queue_role._policy(restored, "alpha")
    assert accepted["lanes"]["alpha"]["branch"] == "refs/heads/lane/alpha"
    assert accepted["lanes"]["alpha"]["capabilities"] == ["core"]


def test_policy_checks_every_lane_and_stops_on_the_first_failure(monkeypatch):
    lanes = _seen_valid_lane(monkeypatch)
    capabilities = _seen_check_capabilities(monkeypatch)
    branches = _seen_normalize_branch(monkeypatch)
    _no_role_io(monkeypatch)
    policy = _registration()
    policy["lanes"]["beta"] = {"capabilities": ["core", "core"], "branch": "private-value\ninjected"}
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$"):
        queue_role._policy(policy, "alpha")
    assert lanes == ["alpha", "beta"]
    assert capabilities == [["core"], ["core", "core"]]
    assert branches == ["refs/heads/lane/alpha"]
    policy["lanes"]["beta"] = {"capabilities": ["review"], "branch": "refs/heads/lane/beta"}
    accepted = queue_role._policy(policy, "alpha")
    assert list(accepted["lanes"]) == ["alpha", "beta"]
    assert accepted["lanes"]["beta"]["branch"] == "refs/heads/lane/beta"


def test_policy_branch_type_precedes_capabilities(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("capabilities must wait until the branch is a string")

    _no_role_io(monkeypatch)
    monkeypatch.setattr(queue_role.team_queue, "check_capabilities", explode)
    monkeypatch.setattr(queue_role.team_queue, "normalize_branch", explode)
    policy = _registration()
    policy["lanes"]["alpha"]["branch"] = {"name": "private-value\ninjected"}
    with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$") as caught:
        queue_role._policy(policy, "alpha")
    assert "private-value" not in str(caught.value) and "injected" not in str(caught.value)


def test_role_predicates_agree_across_threads():
    from concurrent.futures import ThreadPoolExecutor

    def check(_index):
        accepted = queue_role._policy(_registration(), "alpha")
        assert accepted["lanes"]["alpha"]["branch"] == "refs/heads/lane/alpha"
        for policy in (_registration(capabilities=["core", "core"]),
                       _registration(branch="private-value\ninjected")):
            with pytest.raises(queue_role.RoleRefusal, match="^role_invalid$"):
                queue_role._policy(policy, "alpha")
        refused = queue_role.claim_argument_refusal({"id": "bad id", "expect": "A" * 64, "lane": "a..b"})
        assert refused["reason"] == "invalid_arguments" and refused["exit_code"] == 2
        assert refused["next_action"] == _ROLE_ARGUMENT_NEXT
        assert "bad id" not in json.dumps(refused)
        return True

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(check, range(8))) == [True] * 8


def _watch_decodes_and_hashes(monkeypatch):
    seen = {"loads": 0, "hashes": 0}
    real_loads = queue_role.primitives.strict_loads
    real_sha = queue_role.hashlib.sha256

    def loads(text):
        seen["loads"] += 1
        return real_loads(text)

    def sha256(data):
        seen["hashes"] += 1
        return real_sha(data)

    monkeypatch.setattr(queue_role, "primitives", SimpleNamespace(
        strict_loads=loads, envelope=queue_role.primitives.envelope))
    monkeypatch.setattr(queue_role, "hashlib", SimpleNamespace(sha256=sha256))
    return seen


def test_issue_and_bind_decode_json_claim_only_rehashes(owner_factory, monkeypatch):
    """JSON is decoded at issue and bind. A claim re-reads, size-checks and re-hashes both records twice."""
    _require_authority()
    role, root, path, workspace, policy = owner_factory()
    seen = _watch_decodes_and_hashes(monkeypatch)
    role.issue("alpha")
    assert seen == {"loads": 1, "hashes": 1}
    role.bind("alpha")
    assert seen == {"loads": 3, "hashes": 3}
    server._start(queue_registration="alpha")
    rpc("initialize")
    before = dict(seen)
    result = claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})
    # No git work tree: the queue service refuses after both pin checkpoints.
    assert result["reason"] == "queue_io_unavailable" and result["refused"] is True
    assert seen["loads"] == before["loads"]
    assert seen["hashes"] == before["hashes"] + 4
    assert server._queue_grant.stale is False


def _session_file(root):
    return next((root / "sessions").glob("*.json"))


def _restore_registration(path, original):
    path.write_bytes(original)
    path.chmod(0o600)


@pytest.mark.parametrize("fault", ["same-length", "malformed", "session-replaced", "mode-widened"])
def test_claim_replacement_is_role_stale_without_decoding(owner_factory, monkeypatch, fault):
    _require_authority()
    role, root, path, workspace, policy = owner_factory()
    start_owner()
    grant = server._queue_grant
    original = path.read_bytes()
    session = _session_file(root)
    session_original = session.read_bytes()
    seen = _watch_decodes_and_hashes(monkeypatch)
    if fault == "same-length":
        path.write_bytes(_same_length(original))
    elif fault == "malformed":
        path.write_bytes(b"x" * len(original))
    elif fault == "session-replaced":
        replacement = session.with_suffix(".new")
        replacement.write_bytes(b"{" * len(session_original))
        replacement.chmod(0o600)
        replacement.replace(session)
    else:
        path.chmod(0o666)
    arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    result = claim(arguments)
    rendered = json.dumps(result)
    assert result["reason"] == "role_stale" and result["error"] == "role_stale"
    assert result["exit_code"] == 1 and grant.stale is True
    assert seen["loads"] == 0
    assert "\n" not in rendered and "private-value" not in rendered and b"x" * 8 not in rendered.encode()
    assert seen["hashes"] == (1 if fault == "session-replaced" else 0)
    _restore_registration(path, original)
    if fault == "session-replaced":
        session.write_bytes(session_original)
        session.chmod(0o600)
    assert claim(arguments)["reason"] == "role_stale"
    assert not (workspace / ".aegis" / "state" / "team-queue.json").exists()


def test_mutate_replacement_spends_grant_before_lock_exit(owner_factory, monkeypatch):
    _require_authority()
    role, root, path, workspace, policy = owner_factory()
    start_owner()
    grant = server._queue_grant
    original = path.read_bytes()
    seen = _watch_decodes_and_hashes(monkeypatch)
    arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    with role.authority() as (anchor, chain):
        path.write_bytes(b"x" * len(original))
        with pytest.raises(role.RoleRefusal, match="^role_stale$") as caught:
            grant._mutate(anchor, chain, arguments, grant.session)
    assert str(caught.value) == "role_stale" and grant.stale is True
    assert seen["loads"] == 0 and seen["hashes"] == 0
    _restore_registration(path, original)
    # Rewriting the record moves its generation, so restored bytes stay stale.
    assert claim(arguments)["reason"] == "role_stale"
    assert grant.stale is True
    assert not (workspace / ".aegis" / "state" / "team-queue.json").exists()


def test_expiry_while_waiting_for_the_queue_lock_is_rehashed(owner_factory, monkeypatch):
    _require_authority()
    role, root, path, workspace, policy = owner_factory()
    start_owner()
    grant = server._queue_grant
    expires = grant.record["expires_at"]
    clock = {"now": expires - 1}
    real = role.storage
    seen = _watch_decodes_and_hashes(monkeypatch)
    workspace_calls = []
    real_workspace = role._workspace_identity

    def workspace_identity(value):
        workspace_calls.append(value)
        return real_workspace(value)

    monkeypatch.setattr(queue_role, "_workspace_identity", workspace_identity)
    monkeypatch.setattr(queue_role, "time", SimpleNamespace(time=lambda: clock["now"]))

    @contextmanager
    def expired_while_waiting(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            clock["now"] = expires
            yield held

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=expired_while_waiting, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    assert claim(arguments)["reason"] == "role_stale"
    assert grant.stale is True
    # Both checkpoints hash both records. Expiry is checked after the pins, so the
    # second checkpoint still re-hashes before the workspace pin.
    assert seen["loads"] == 0 and seen["hashes"] == 4
    assert len(workspace_calls) == 1
    path.chmod(0o600)
    assert claim(arguments)["reason"] == "role_stale"


def test_queue_lock_waits_see_a_concurrent_registration_change(owner_factory, monkeypatch):
    _require_authority()
    role, root, path, workspace, policy = owner_factory()
    start_owner()
    grant = server._queue_grant
    original = path.read_bytes()
    mutated = _same_length(original)
    real = role.storage
    started, changed = threading.Event(), threading.Event()

    def replace():
        assert started.wait(timeout=10)
        path.write_bytes(mutated)
        changed.set()

    worker = threading.Thread(target=replace)
    worker.start()

    @contextmanager
    def wait_for_replacement(*args, **kwargs):
        started.set()
        assert changed.wait(timeout=10)
        with real.locked(*args, **kwargs) as held:
            yield held

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=wait_for_replacement, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    seen = _watch_decodes_and_hashes(monkeypatch)
    try:
        arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
        assert claim(arguments)["reason"] == "role_stale"
        assert grant.stale is True and seen["loads"] == 0 and seen["hashes"] == 2
        _restore_registration(path, original)
        assert claim(arguments)["reason"] == "role_stale"
    finally:
        worker.join(timeout=10)
        assert not worker.is_alive()


def test_claim_acquires_the_queue_lock_inside_authority(owner_factory, monkeypatch):
    _require_authority()
    role, root, path, workspace, policy = owner_factory()
    start_owner()
    real = role.storage
    events = []

    @contextmanager
    def file_lock(*args, **kwargs):
        events.append("authority-enter")
        with real.file_lock(*args, **kwargs):
            yield
        events.append("authority-exit")

    @contextmanager
    def locked(*args, **kwargs):
        events.append("queue-enter")
        assert "authority-enter" in events and "authority-exit" not in events
        with real.locked(*args, **kwargs) as held:
            yield held
        events.append("queue-exit")

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        file_lock=file_lock, locked=locked, LockTimeoutError=real.LockTimeoutError))
    assert claim({"id": "ONE", "expect": "a" * 64, "lane": "alpha"})["reason"] == "queue_io_unavailable"
    assert events.index("queue-enter") < events.index("authority-exit")
    assert events.index("queue-exit") < events.index("authority-exit")


@pytest.mark.parametrize("phase", ["before-lock", "under-lock"])
@pytest.mark.parametrize("record", ["registration", "session"])
@pytest.mark.parametrize("fault", ["missing", "unsafe", "socket", "changed", "io", "io-fstat", "io-read", "io-stat"])
def test_claim_authority_read_failure_policy(owner_factory, monkeypatch, phase, record, fault):
    role, root, path, workspace, _ = owner_factory()
    start_owner()
    grant = server._queue_grant
    target = path if record == "registration" else _session_file(root)
    original = target.read_bytes()
    sock = _authority_socket(workspace.parent) if fault == "socket" else None
    added = team_queue.add(workspace, {
        "id": "ONE", "title": "Queue work", "paths": ["src/**"], "capabilities": ["core"],
    }, caller="owner")
    assert not added["refused"], added
    queue_file = workspace / ".aegis/state/team-queue.json"
    before = queue_file.read_bytes()
    real = queue_role.storage
    observations = []
    lock_state = {"phase": "before-lock", "read_started": False}
    faulted_leaves = set()
    stable_io = fault.startswith("io")

    @contextmanager
    def locked(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            lock_state["phase"] = "under-lock"
            try:
                yield held
            finally:
                lock_state["phase"] = "before-lock"

    def opened(name, flags, *args, **kwargs):
        if name == target.name:
            current_phase = lock_state["phase"]
            observations.append(current_phase)
            if current_phase == phase:
                if fault == "io":
                    raise OSError(errno.EIO, "private-value")
                if fault == "socket":
                    sock.replace(target)
                elif fault == "changed":
                    replacement = target.with_suffix(".new")
                    replacement.write_bytes(original)
                    replacement.chmod(0o600)
                    replacement.replace(target)
                elif not stable_io:
                    target.unlink()
                    if fault == "unsafe":
                        symlink_or_skip(path.parent / "absent", target)
                if stable_io:
                    fd = os.open(name, flags, *args, **kwargs)
                    faulted_leaves.add(fd)
                    return fd
        return os.open(name, flags, *args, **kwargs)

    def inspect(fd):
        if fault == "io-fstat" and fd in faulted_leaves:
            raise OSError(errno.EIO, "private-value")
        return os.fstat(fd)

    def read(fd, count):
        if fd in faulted_leaves:
            lock_state["read_started"] = True
            if fault == "io-read":
                raise OSError(errno.EIO, "private-value")
        return os.read(fd, count)

    def stat_at(name, *args, **kwargs):
        if fault == "io-stat" and lock_state["read_started"] and name == target.name:
            raise OSError(errno.EIO, "private-value")
        return os.stat(name, *args, **kwargs)

    def close(fd):
        faulted_leaves.discard(fd)
        os.close(fd)

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=locked, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    monkeypatch.setattr("aegis_core.storage_confined.os", _confined_os_view(
        open=opened, close=close, fstat=inspect, read=read, stat=stat_at))
    result = claim(arguments)
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    assert observations == (["before-lock"] if phase == "before-lock" else ["before-lock", "under-lock"])
    assert faulted_leaves == set()
    _assert_stale_claim(result)
    assert grant.stale is True
    assert queue_file.read_bytes() == before

    if not stable_io:
        if fault == "socket" or target.is_symlink():
            target.unlink()
        target.write_bytes(original)
        target.chmod(0o600)
    _assert_stale_claim(claim(arguments))
    assert server._queue_grant is grant
    assert queue_file.read_bytes() == before


@pytest.mark.parametrize("phase", ["before-lock", "under-lock"])
@pytest.mark.parametrize("record", ["registration", "session"])
@pytest.mark.parametrize("fault", [fault for fault, _ in _CHECKED_READ_FAULTS])
def test_claim_checked_read_decision_through_cleanup(owner_factory, monkeypatch, phase, record, fault):
    role, root, path, workspace, _ = owner_factory()
    start_owner()
    grant = server._queue_grant
    target = path if record == "registration" else _session_file(root)
    original = target.read_bytes()
    added = team_queue.add(workspace, {
        "id": "ONE", "title": "Queue work", "paths": ["src/**"], "capabilities": ["core"],
    }, caller="owner")
    assert not added["refused"], added
    queue_file = workspace / ".aegis/state/team-queue.json"
    before = queue_file.read_bytes()
    real = role.storage
    failure = _RecordReadFault(target, fault, active=phase == "before-lock")

    @contextmanager
    def locked(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            failure.active = phase == "under-lock"
            yield held

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=locked, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    monkeypatch.setattr("aegis_core.storage_confined.os", failure.os_view())
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    result = claim(arguments)
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    _assert_stale_claim(result)
    assert grant.stale is True
    assert failure.closed == (["parent"] if fault == "parent-stat" else ["leaf", "parent"])
    assert not failure.owned
    assert queue_file.read_bytes() == before
    if fault.endswith("unlink"):
        target.write_bytes(original)
        target.chmod(0o600)
    _assert_stale_claim(claim(arguments))
    assert server._queue_grant is grant
    assert queue_file.read_bytes() == before


@pytest.mark.parametrize("phase,queue_close,authority_close", [
    ("before-lock", False, True), ("under-lock", True, False), ("under-lock", True, True),
])
@pytest.mark.parametrize("record", ["registration", "session"])
def test_claim_preserves_spent_grant_through_lock_cleanup(
        owner_factory, monkeypatch, phase, queue_close, authority_close, record):
    role, root, path, workspace, _ = owner_factory()
    start_owner()
    grant = server._queue_grant
    target = path if record == "registration" else _session_file(root)
    added = team_queue.add(workspace, {
        "id": "ONE", "title": "Queue work", "paths": ["src/**"], "capabilities": ["core"],
    }, caller="owner")
    assert not added["refused"], added
    queue_file = workspace / ".aegis/state/team-queue.json"
    before = queue_file.read_bytes()
    real = role.storage
    failure = _RecordReadFault(target, "leaf-close", active=phase == "before-lock")
    teardown = []

    @contextmanager
    def locked(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            failure.active = phase == "under-lock"
            try:
                yield held
            finally:
                if queue_close:
                    teardown.append("queue")
                    raise OSError(errno.EIO, "private-value")

    @contextmanager
    def file_lock(*args, **kwargs):
        with real.file_lock(*args, **kwargs):
            try:
                yield
            finally:
                if authority_close:
                    teardown.append("authority")
                    raise OSError(errno.EIO, "private-value")

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=locked, file_lock=file_lock, LockTimeoutError=real.LockTimeoutError))
    monkeypatch.setattr("aegis_core.storage_confined.os", failure.os_view())
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    result = claim(arguments)
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    monkeypatch.setattr(queue_role, "storage", real)
    _assert_stale_claim(result)
    assert grant.stale is True
    assert teardown == [kind for kind, failed in (("queue", queue_close), ("authority", authority_close)) if failed]
    assert failure.closed == ["leaf", "parent"] and not failure.owned
    assert queue_file.read_bytes() == before
    _assert_stale_claim(claim(arguments))
    assert server._queue_grant is grant and queue_file.read_bytes() == before


def test_queue_lock_io_allows_retry_on_the_same_grant(owner_factory, monkeypatch):
    role, root, path, workspace, _ = owner_factory()
    start_owner()
    grant = server._queue_grant
    added = team_queue.add(workspace, {
        "id": "ONE", "title": "Queue work", "paths": ["src/**"], "capabilities": ["core"],
    }, caller="owner")
    assert not added["refused"], added
    queue_file = workspace / ".aegis/state/team-queue.json"
    before = queue_file.read_bytes()
    real = role.storage

    def fail_lock(*args, **kwargs):
        raise OSError(errno.EIO, "private-value")

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=fail_lock, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    result = claim(arguments)
    assert result["reason"] == result["error"] == "queue_io_unavailable"
    assert result["next_action"] == "Check the trusted workspace and queue, then list before retrying."
    assert grant.stale is False and queue_file.read_bytes() == before
    monkeypatch.setattr(queue_role, "storage", real)
    retry = claim(arguments)
    assert retry["reason"] == "queue_io_unavailable"
    assert retry["next_action"] == "Check the trusted workspace and queue paths, then list before retrying a mutation."
    assert grant.stale is False and server._queue_grant is grant and queue_file.read_bytes() == before


def test_claim_preserves_process_refusal_cleanup_behavior(owner_factory, monkeypatch):
    role, root, path, workspace, _ = owner_factory()
    start_owner()
    grant = server._queue_grant
    real = role.storage

    @contextmanager
    def file_lock(*args, **kwargs):
        with real.file_lock(*args, **kwargs):
            try:
                yield
            finally:
                raise OSError(errno.EIO, "private-value")

    monkeypatch.setattr(queue_role, "process_identity", lambda: {**grant.process, "pid": 0})
    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=real.locked, file_lock=file_lock, LockTimeoutError=real.LockTimeoutError))
    arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    denied = claim(arguments)
    assert denied["reason"] == denied["error"] == "role_io_unavailable"
    assert grant.stale is True and not (workspace / ".aegis/state/team-queue.json").exists()
    monkeypatch.setattr(queue_role, "storage", real)
    _assert_stale_claim(claim(arguments))


@pytest.mark.parametrize("phase", ["before-lock", "under-lock"])
@pytest.mark.parametrize("record", ["registration", "session"])
def test_claim_preserves_unsupported_record_reason(owner_factory, monkeypatch, phase, record):
    role, root, path, workspace, _ = owner_factory()
    start_owner()
    grant = server._queue_grant
    target = path if record == "registration" else _session_file(root)
    confined = role.storage_confined
    real = role.storage
    state = {"phase": "before-lock"}

    def read_checked_file(root, parts, *args, **kwargs):
        if parts[-1] == target.name and state["phase"] == phase:
            raise confined.ConfinedFileError("unsupported")
        return confined.read_checked_file(root, parts, *args, **kwargs)

    @contextmanager
    def locked(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            state["phase"] = "under-lock"
            yield held

    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=locked, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    monkeypatch.setattr(queue_role, "storage_confined", SimpleNamespace(**{
        **vars(confined), "read_checked_file": read_checked_file,
    }))
    arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    denied = claim(arguments)
    assert denied["reason"] == denied["error"] == "unsupported_platform"
    assert denied["next_action"] == "Use Linux with descriptor-relative no-follow operations."
    assert grant.stale is False and server._queue_grant is grant
    assert not (workspace / ".aegis/state/team-queue.json").exists()


@pytest.mark.parametrize("phase", ["before-lock", "under-lock"])
@pytest.mark.parametrize("record", ["registration", "session"])
@pytest.mark.parametrize("defect", ["unreadable", "generation", "digest"])
def test_known_claim_defect_precedes_later_io(owner_factory, monkeypatch, phase, record, defect):
    role, root, path, workspace, _ = owner_factory()
    start_owner()
    grant = server._queue_grant
    session = _session_file(root)
    target = path if record == "registration" else session
    original = target.read_bytes()
    added = team_queue.add(workspace, {
        "id": "ONE", "title": "Queue work", "paths": ["src/**"], "capabilities": ["core"],
    }, caller="owner")
    assert not added["refused"], added
    queue_file = workspace / ".aegis/state/team-queue.json"
    before = queue_file.read_bytes()
    real = role.storage
    process_identity = role.process_identity
    state = {"active": False}
    target_descriptors = set()
    later_io = []

    def introduce_defect():
        state["active"] = True
        if defect == "unreadable":
            target.chmod(0o000)
        elif defect == "generation":
            replacement = target.with_suffix(".new")
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            replacement.replace(target)

    @contextmanager
    def locked(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            if phase == "under-lock":
                introduce_defect()
            yield held

    def fail_io():
        later_io.append(True)
        raise OSError(errno.EIO, "private-value")

    def opened(name, flags, *args, **kwargs):
        current = state["active"] and name == target.name
        if current and defect != "digest":
            fail_io()
        if state["active"] and defect == "digest" and record == "registration" and name == session.name:
            fail_io()
        fd = os.open(name, flags, *args, **kwargs)
        if current:
            target_descriptors.add(fd)
        return fd

    def read(fd, count):
        data = os.read(fd, count)
        if data and fd in target_descriptors:
            return _same_length(data)
        return data

    def close(fd):
        target_descriptors.discard(fd)
        os.close(fd)

    def inspect_process():
        if state["active"] and defect == "digest" and record == "session":
            fail_io()
        return process_identity()

    seen = _watch_decodes_and_hashes(monkeypatch)
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=locked, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    monkeypatch.setattr(queue_role, "process_identity", inspect_process)
    monkeypatch.setattr("aegis_core.storage_confined.os", _confined_os_view(open=opened, read=read, close=close))
    if phase == "before-lock":
        introduce_defect()
    result = claim(arguments)
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    monkeypatch.setattr(queue_role, "process_identity", process_identity)
    monkeypatch.setattr(queue_role, "storage", real)
    assert result["reason"] == result["error"] == "role_stale"
    assert result["next_action"] == "Ask the owner to restart the queue connection with a fresh session record."
    assert result["exit_code"] == 1 and result["refused"] is True
    assert later_io == [] and target_descriptors == set()
    assert seen == {"loads": 0, "hashes": 2 * (phase == "under-lock") + (record == "session") + (defect == "digest")}
    assert grant.stale is True
    assert queue_file.read_bytes() == before
    target.chmod(0o600)
    target.write_bytes(original)
    assert claim(arguments)["reason"] == "role_stale"
    assert queue_file.read_bytes() == before


def _authority_tree(components):
    """An account home whose mcp-queue path has exactly ``components`` parts."""
    base = Path(tempfile.mkdtemp(prefix="qr", dir="/tmp"))
    home = base
    # /tmp/<name> is three parts; .aegis/mcp-queue adds two. The rest are home parents.
    for index in range(components - 5):
        home = home / ("d" + str(index))
        home.mkdir(mode=0o700)
        home.chmod(0o700)
    from aegis_core.workspace.layout import UserLayout

    root = UserLayout(home).aegis_dir / "mcp-queue"
    root.mkdir(parents=True, mode=0o700)
    for directory in (root, root.parent):
        directory.chmod(0o700)
    assert len(root.parts) == components
    return base, home, root


def _count_directory_opens(monkeypatch):
    calls = []

    def opened(name, flags, dir_fd=None):
        calls.append(name)
        return os.open(name, flags, dir_fd=dir_fd)

    monkeypatch.setattr(queue_role, "os", _os_view(open=opened))
    return calls


@pytest.mark.parametrize("components", [5, 16, 32])
def test_authority_opens_each_component_once_and_retains_one_parent(monkeypatch, components):
    _require_authority()
    base, home, root = _authority_tree(components)
    calls = _count_directory_opens(monkeypatch)
    monkeypatch.setattr(queue_role, "account_home", lambda: home)
    before = len(list(Path("/proc/self/fd").iterdir()))
    try:
        with queue_role.authority() as (anchored, chain):
            during = len(list(Path("/proc/self/fd").iterdir()))
        prefixes = [Path(*root.parts[:index]) for index in range(1, len(root.parts) + 1)]
        expected = tuple((path.lstat().st_dev, path.lstat().st_ino) for path in prefixes)
        assert anchored == root
        assert chain == expected
        assert calls == list(root.parts)
        assert during - before == 2
    finally:
        shutil.rmtree(base)
    assert len(list(Path("/proc/self/fd").iterdir())) == before


@pytest.mark.parametrize("fault,reason", [
    ("unowned", "role_invalid"),
    ("mode-group", "role_invalid"),
    ("mode-other", "role_invalid"),
    ("symlink", "role_invalid"),
    ("missing", "role_missing"),
])
def test_authority_ancestor_failures_keep_refusal_codes(monkeypatch, fault, reason):
    _require_authority()
    base, home, root = _authority_tree(5)
    monkeypatch.setattr(queue_role, "account_home", lambda: home)
    try:
        if fault == "unowned":
            monkeypatch.setattr(queue_role, "os", _os_view(geteuid=lambda: os.geteuid() + 1))
        elif fault == "mode-group":
            root.parent.chmod(0o720)
        elif fault == "mode-other":
            root.parent.chmod(0o702)
        elif fault == "symlink":
            parent = root.parent
            moved = parent.with_name(parent.name + "-real")
            parent.rename(moved)
            symlink_or_skip(moved, parent, target_is_directory=True)
        else:
            root.rmdir()
        with pytest.raises(queue_role.RoleRefusal, match="^" + reason + "$") as caught:
            with queue_role.authority():
                raise AssertionError("refused authority must not yield")
        assert str(caught.value) == reason
        if fault == "symlink":
            parent.unlink()
            moved.rename(parent)
        elif fault == "missing":
            root.mkdir(mode=0o700)
            root.chmod(0o700)
        elif fault.startswith("mode-"):
            root.parent.chmod(0o700)
        else:
            monkeypatch.setattr(queue_role, "os", _os_view())
        with queue_role.authority() as (anchored, chain):
            assert anchored == root and len(chain) == 5
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_authority_walk_is_stable_across_threads(monkeypatch):
    _require_authority()
    base, home, root = _authority_tree(6)
    monkeypatch.setattr(queue_role, "account_home", lambda: home)
    try:
        with queue_role.authority() as (anchored, expected):
            assert anchored == root

        def once(_index):
            with queue_role.authority() as (found, chain):
                assert found == root and chain == expected
            return True

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert list(pool.map(once, range(8))) == [True] * 8
    finally:
        shutil.rmtree(base)
