"""Owner-bound queue connections: hostile inputs never enroll a caller."""
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import symlink_or_skip

import aegis_mcp.server as server
import aegis_mcp.queue_role as queue_role


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
    rpc("initialize")
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
    monkeypatch.setattr(queue_role, "os", SimpleNamespace(geteuid=os.geteuid, getpid=os.getpid, stat=failed))
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
        monkeypatch.setattr(queue_role, "os", SimpleNamespace(geteuid=lambda: os.geteuid() + 1))
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
    from contextlib import contextmanager
    from aegis_core import storage_confined

    role, root, path, workspace, policy = owner_factory()
    moved = path.parent.with_name("registrations-old")
    original = storage_confined.confined_file
    @contextmanager
    def swapping_file(anchor, parts, **options):
        with original(anchor, parts, **options) as handle:
            if parts == ("registrations", "alpha.json") and not moved.exists():
                path.parent.rename(moved)
                symlink_or_skip(workspace, path.parent, target_is_directory=True)
            yield handle
    monkeypatch.setattr(queue_role, "storage_confined", SimpleNamespace(
        confined_file=swapping_file, descriptor_supported=storage_confined.descriptor_supported,
        ConfinedFileError=storage_confined.ConfinedFileError))
    # The anchored original parent may complete issuance; its replacement cannot
    # redirect the read. Binding then refuses the new symlinked pathname.
    role.issue("alpha")
    with pytest.raises(role.RoleRefusal, match="^role_invalid$"):
        role.bind("alpha")
