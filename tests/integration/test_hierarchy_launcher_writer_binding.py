"""Writer-binding integration at the launcher resume-turn recording site."""
from __future__ import annotations

import ast
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import FunctionType, SimpleNamespace
import uuid

import pytest

from aegis_core import team
from aegis_core import team_writer_binding as binding
from tests.conftest import symlink_or_skip
from tests.helpers_writer_binding import call_bind, make_home, make_store
from tools import hierarchy_launcher as launcher


def _function(tree, name):
    found = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(found) == 1
    return found[0]


def _closure(code, values, globals_dict):
    slots = []
    for name in code.co_freevars:
        def capture(value=values[name]):
            def inner():
                return value
            return inner
        slots.append(capture().__closure__[0])
    return FunctionType(code, globals_dict, code.co_name, closure=tuple(slots))


def test_claim_renew_run_start_and_start_loop_do_not_reference_binding():
    root = Path(__file__).resolve().parents[2]
    for rel in ("aegis_core/team.py", "aegis_cli/team.py", "tools/hierarchy_team.py",
                "aegis_core/team_supervisor_start.py"):
        assert "team_writer_binding" not in (root / rel).read_text(encoding="utf-8")
    source = (root / "tools/hierarchy_launcher.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    run_start = ast.get_source_segment(source, _function(tree, "run_start"))
    start_loop = (root / "tools/hierarchy_team.py").read_text(encoding="utf-8")
    assert "team_writer_binding" not in run_start
    assert "bind_writer_process" not in run_start
    assert "def start_loop" in start_loop
    created = ast.get_source_segment(source, _function(tree, "created_child"))
    assert created.index("children.append") < created.index("bind_writer_process") < created.index("write_running_wake")


def _host_plan(base, hierarchy="hier", host="codex-cli"):
    base.mkdir(parents=True, exist_ok=True)
    plan = launcher.hierarchy_hosts.plan_record(hierarchy, host, host, {}, "a" * 64)
    (base / "host-plan.json").write_text(json.dumps(plan), encoding="utf-8")


def _binding_source(root, body):
    if not launcher.bootstrap_descriptor_capable():
        pytest.skip("verified source loading requires no-follow directory descriptors")
    package = root / "aegis_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "team_writer_binding.py").write_text(body, encoding="utf-8")


_VERIFIED_CALLS = []


def _verified_bind(tail):
    """Record bind arguments on this module. The record is not a file write."""
    return (
        "def bind(user_root, workspace_root, lane, pid):\n"
        "    import sys\n"
        "    sys.modules[%r]._VERIFIED_CALLS.append((user_root, workspace_root, lane, pid))\n"
        "%s" % (__name__, tail)
    )


def _resume_launches(tmp_path, source, kind="implementer"):
    base = tmp_path / "base"
    _host_plan(base)
    profile = tmp_path / "wake.json"
    cwd = tmp_path / "work"
    cwd.mkdir()
    profile.write_text(json.dumps({"cwd": str(cwd)}), encoding="utf-8")

    class Mailbox:
        def __init__(self, kind):
            self.kind = kind

        def endpoint(self, endpoint):
            return {"kind": self.kind}

    launches = SimpleNamespace(
        base=base, setup={"source": str(source), "mailbox_root": str(base / "mailbox")}, mailbox=Mailbox(kind),
    )
    return launches, str(profile), cwd


def _run_created_child(values):
    code = next(const for const in launcher.admitted_wake_locked.__code__.co_consts
                if getattr(const, "co_name", None) == "created_child")
    missing = [name for name in code.co_freevars if name not in values]
    assert missing == []
    namespace = {name: getattr(launcher, name) for name in code.co_names if hasattr(launcher, name)}
    # FunctionType needs explicit builtins on Python 3.9.
    namespace["__builtins__"] = launcher.__builtins__
    return _closure(code, values, namespace)


def test_created_child_namespace_has_explicit_builtins():
    callback = _run_created_child({
        "children": [], "fence": None, "launches": None, "endpoint": None,
        "profile": None, "known": {}, "running": [],
    })
    assert "__builtins__" in callback.__globals__
    assert callback.__globals__["__builtins__"] is launcher.__builtins__


@pytest.mark.parametrize("mode", ["locked", "raises"])
def test_refused_replacement_is_reaped_and_not_left_running(tmp_path, monkeypatch, mode):
    """A refused bind stops this launch's child before a later observation can call it dead."""
    pytest.importorskip("pwd")
    if not hasattr(os, "killpg"):
        pytest.skip("process-group stop is unavailable")
    program = shutil.which("sleep")
    if program is None:
        pytest.skip("sleep unavailable")
    source = tmp_path / "verified"
    _VERIFIED_CALLS.clear()
    if mode == "locked":
        body = _verified_bind(
            "    return {'status': 'refused', 'code': 'state_locked',"
            " 'reason': 'writer binding is locked'}\n"
        )
        expected = "writer binding refused: state_locked"
    else:
        body = _verified_bind("    raise RuntimeError('TOKEN=secret')\n")
        expected = "writer binding refused: state_unavailable"
    _binding_source(source, body)
    launches, profile, _cwd = _resume_launches(tmp_path, source)
    published = []
    monkeypatch.setattr(launcher, "write_running_wake", lambda *args, **kwargs: published.append(args))
    monkeypatch.setattr(binding, "bind", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("ambient")))
    if hasattr(launcher, "_BINDING_LOCK_WAIT_S"):
        monkeypatch.setattr(launcher, "_BINDING_LOCK_WAIT_S", 0)
    children = []

    class Fence:
        def check(self):
            return None

    values = {
        "children": children,
        "fence": Fence(),
        "launches": launches,
        "endpoint": "hier/lane/writer",
        "profile": profile,
        "known": {"host": "codex"},
        "running": [{"wake_id": "wake-1"}],
    }
    process = subprocess.Popen([program, "30"], start_new_session=True)
    try:
        with pytest.raises(ValueError, match="^writer binding refused$"):
            _run_created_child(values)(process)
        assert children == [process]
        assert published == []
        assert process.poll() is not None
        with pytest.raises(ProcessLookupError):
            os.kill(process.pid, 0)
        assert launches.writer_binding_refusal == expected
        assert "TOKEN" not in launches.writer_binding_refusal
        assert "secret" not in launches.writer_binding_refusal
        if mode == "locked":
            assert len(_VERIFIED_CALLS) == launcher._BINDING_LOCK_TRIES
            assert {row[2] for row in _VERIFIED_CALLS} == {"hier-writer"}
            assert {row[3] for row in _VERIFIED_CALLS} == {process.pid}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_helper_skips_non_implementers_and_uses_passwd_home(tmp_path, monkeypatch):
    pwd = pytest.importorskip("pwd")
    source = tmp_path / "verified"
    _VERIFIED_CALLS.clear()
    _binding_source(source, _verified_bind(
        "    return {'status': 'refused', 'code': 'lease_unavailable',"
        " 'reason': 'writer lease is unavailable'}\n"
    ))
    launches, profile, cwd = _resume_launches(tmp_path, source)
    ambient = []
    monkeypatch.setattr(binding, "bind", lambda *args: ambient.append(args) or {"status": "ok"})
    previous_home = os.environ.get("HOME")
    os.environ["HOME"] = "/ZZMARKER-not-home"
    try:
        launches.mailbox.kind = "reviewer"
        skipped = launcher.bind_writer_process(launches, "hier/lane/writer", profile, 99)
        assert skipped is None and ambient == [] and _VERIFIED_CALLS == []
        launches.mailbox.kind = "implementer"
        bound = launcher.bind_writer_process(launches, "hier/lane/writer", profile, 99)
        assert bound == "writer binding refused: lease_unavailable"
        assert ambient == []
        assert _VERIFIED_CALLS == [(pwd.getpwuid(os.getuid()).pw_dir, str(cwd), "hier-writer", 99)]
        assert "ZZMARKER" not in repr(_VERIFIED_CALLS)
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


def test_helper_swallows_passwd_and_bind_failures(tmp_path, monkeypatch):
    source = tmp_path / "verified"
    _binding_source(source, "def bind(user_root, workspace_root, lane, pid):\n    return {'status': 'ok'}\n")
    launches, profile, _cwd = _resume_launches(tmp_path, source)

    def missing_home():
        raise KeyError("missing")

    monkeypatch.setattr(launcher, "_passwd_home", missing_home)
    result = launcher.bind_writer_process(launches, "hier/lane/writer", profile, 5)
    assert result == "writer binding refused: state_unavailable"
    assert "missing" not in result


def test_helper_swallows_a_bind_exception(tmp_path, monkeypatch):
    pytest.importorskip("pwd")
    source = tmp_path / "verified"
    _binding_source(source, "def bind(user_root, workspace_root, lane, pid):\n    raise RuntimeError('TOKEN=secret')\n")
    ambient = []
    monkeypatch.setattr(binding, "bind", lambda *args: ambient.append("ambient"))
    launches, profile, _cwd = _resume_launches(tmp_path, source)
    result = launcher.bind_writer_process(launches, "hier/lane/writer", profile, 5)
    assert result == "writer binding refused: state_unavailable"
    assert "TOKEN" not in result and "secret" not in result
    assert ambient == []


def test_no_plan_resume_does_not_read_or_write_bindings(tmp_path, monkeypatch):
    calls = []
    refs = []
    monkeypatch.setattr(binding, "bind", lambda *args: calls.append(args) or {"status": "ok"})
    monkeypatch.setattr(team.gitsafe, "read_ref", lambda *args: refs.append(args) or None)
    base = tmp_path / "base"
    base.mkdir()
    profile = tmp_path / "wake.json"
    profile.write_text(json.dumps({"cwd": str(tmp_path)}), encoding="utf-8")

    class Mailbox:
        def endpoint(self, endpoint):
            return {"kind": "implementer"}

    launches = SimpleNamespace(
        base=base, setup={"source": str(tmp_path), "mailbox_root": str(base)}, mailbox=Mailbox(),
    )
    result = launcher.bind_writer_process(launches, "hier/lane/writer", str(profile), os.getpid())
    assert result is None
    assert calls == []
    assert refs == []
    assert not (base / ".config" / "aegis" / binding.NAME).exists()


def test_missing_verified_binding_does_not_run_foreign_code(tmp_path, monkeypatch):
    pytest.importorskip("pwd")
    foreign = tmp_path / "foreign"
    _VERIFIED_CALLS.clear()
    _binding_source(foreign, _verified_bind("    return {'status': 'ok'}\n"))
    verified = tmp_path / "verified"
    verified.mkdir()
    ambient = []
    monkeypatch.setattr(binding, "bind", lambda *args: ambient.append(args) or {"status": "ok"})
    launches, profile, _cwd = _resume_launches(tmp_path, verified)
    sys.path.insert(0, str(foreign))
    try:
        result = launcher.bind_writer_process(launches, "hier/lane/writer", profile, os.getpid())
    finally:
        sys.path.remove(str(foreign))
    assert result == "writer binding refused: source_unavailable"
    assert ambient == []
    assert _VERIFIED_CALLS == []


def test_plan_present_bind_ok_uses_the_verified_source(tmp_path, monkeypatch):
    pwd = pytest.importorskip("pwd")
    source = tmp_path / "verified"
    _VERIFIED_CALLS.clear()
    _binding_source(source, _verified_bind("    return {'status': 'ok'}\n"))
    ambient = []
    monkeypatch.setattr(binding, "bind", lambda *args: ambient.append(args) or {"status": "ok"})
    launches, profile, cwd = _resume_launches(tmp_path, source)
    result = launcher.bind_writer_process(launches, "hier/lane/writer", profile, 99)
    assert result is None
    assert ambient == []
    assert _VERIFIED_CALLS == [(pwd.getpwuid(os.getuid()).pw_dir, str(cwd), "hier-writer", 99)]


def test_exact_lane_read_ignores_foreign_lane_refs(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    ref_reads, object_reads, list_reads = [], [], []
    blob = json.dumps({
        "v": 1, "lane": "writer", "role": "implementer", "owner": "owner", "claim_id": "a" * 16,
        "gen": 1, "branch": "lane/writer", "paths": ["docs/**"], "ts": 50, "ttl_s": 100,
    }).encode()
    oid = "b" * 40

    def read_ref(repo, ref):
        ref_reads.append(ref)
        return oid if ref == team.lane_ref("writer") else None

    def read_object(repo, seen, limit):
        object_reads.append((seen, limit))
        return blob

    def list_refs(repo, prefix):
        list_reads.append(prefix)
        return [("refs/aegis/lanes/f%04d" % index, "c" * 40) for index in range(10000)]

    monkeypatch.setattr(team.gitsafe, "read_ref", read_ref)
    monkeypatch.setattr(team.gitsafe, "read_object", read_object)
    monkeypatch.setattr(team.gitsafe, "list_refs", list_refs)
    result = call_bind(home, workspace)
    assert result == {"status": "ok"}
    assert ref_reads == [team.lane_ref("writer")]
    assert object_reads == [(oid, team.MAX_LEASE_BYTES)]
    assert list_reads == []


def test_binding_refusal_is_exposed_on_the_resume_answer():
    launches = SimpleNamespace(writer_binding_refusal="writer binding refused: state_locked")
    code, answer = launcher.expose_binding_refusal(launches, 0, {"state": "started"})
    assert code == 2
    assert answer["error"] == "writer binding refused: state_locked"
    assert answer["state"] == "started"
    leaked = SimpleNamespace(writer_binding_refusal="TOKEN=secret")
    code, answer = launcher.expose_binding_refusal(leaked, 0, {"error": "kept"})
    assert code == 0
    assert answer == {"error": "kept"}


@pytest.mark.parametrize("mode", [
    "malformed", "foreign", "conflicting", "indeterminate", "missing-base", "missing-mailbox",
])
def test_invalid_governing_plan_refuses_before_binding(tmp_path, monkeypatch, mode):
    source = tmp_path / "verified"
    _VERIFIED_CALLS.clear()
    _binding_source(source, _verified_bind("    return {'status': 'ok'}\n"))
    launches, profile, _cwd = _resume_launches(tmp_path, source)
    if mode == "malformed":
        (launches.base / "host-plan.json").write_text("{}", encoding="utf-8")
    elif mode == "foreign":
        _host_plan(launches.base, hierarchy="other")
    elif mode == "conflicting":
        other = tmp_path / "governing"
        _host_plan(other, host="claude-code")
        launches.setup["mailbox_root"] = str(other / "mailbox")
    elif mode == "missing-base":
        launches.base = None
    elif mode == "missing-mailbox":
        (launches.base / "host-plan.json").unlink()
        launches.setup.pop("mailbox_root")
    else:
        monkeypatch.setattr(launcher, "bootstrap_plan_present", lambda folder: None)

    def no_home():
        pytest.fail("plan refusal must precede owner-home access")

    monkeypatch.setattr(launcher, "_passwd_home", no_home)
    assert launcher.bind_writer_process(launches, "hier/lane/writer", profile, 99) == (
        "writer binding refused: state_unavailable")
    assert _VERIFIED_CALLS == []


_ISOLATED_BIND = '''import importlib.util
import json
import os
from pathlib import Path
import sys

entry, home, request, foreign, marker = sys.argv[1:]
spec = importlib.util.spec_from_file_location("isolated_launcher", entry)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
from types import SimpleNamespace
value = json.loads(Path(request).read_text())
if foreign:
    sys.path.insert(0, foreign)
assert "aegis_core" not in sys.modules
module._passwd_home = lambda: home
launches = SimpleNamespace(base=Path(value["base"]), setup=value["setup"],
                          mailbox=SimpleNamespace(endpoint=lambda endpoint: {"kind": "implementer"}))
before = list(sys.meta_path)
result = module.bind_writer_process(launches, "hier/lane/writer", value["profile"], os.getpid())
assert result is None, result
assert sys.meta_path == before
assert "aegis_core" not in sys.modules
assert not Path(marker).exists(), "competing installation executed"
row = json.loads((Path(home) / ".config/aegis/writer-bindings.json").read_text())["bindings"]["hier-writer"]
assert row["pid"] == os.getpid()
assert row["claim_id"] == "a" * 16
print("bound from verified source")
'''


@pytest.mark.parametrize("competing", [False, True], ids=["no-installation", "competing-installation"])
def test_real_binding_in_isolated_child_uses_only_verified_source(tmp_path, competing):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    source = Path(__file__).resolve().parents[2]
    subprocess.run(["git", "init", "-q", str(workspace)], check=True, capture_output=True, timeout=10)
    raw = json.dumps({
        "v": 1, "lane": "hier-writer", "role": "implementer", "owner": "owner",
        "claim_id": "a" * 16, "gen": 1, "branch": "lane/writer", "paths": ["docs/**"],
        "ts": 50, "ttl_s": 100,
    }).encode()
    hashed = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=workspace, input=raw,
                            check=True, capture_output=True, timeout=10).stdout.decode().strip()
    subprocess.run(["git", "update-ref", "refs/aegis/lanes/hier-writer", hashed], cwd=workspace,
                   check=True, capture_output=True, timeout=10)
    launches, profile, _cwd = _resume_launches(tmp_path, source)
    Path(profile).write_text(json.dumps({"cwd": str(workspace)}), encoding="utf-8")
    request = tmp_path / "bind-request.json"
    request.write_text(json.dumps({"base": str(launches.base), "setup": launches.setup,
                                   "profile": profile}), encoding="utf-8")
    marker = tmp_path / "ambient-executed"
    foreign = tmp_path / "foreign"
    if competing:
        package = foreign / "aegis_core"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(
            "from pathlib import Path\nimport sys\nPath(sys.argv[5]).touch()\n", encoding="utf-8")
    ran = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", _ISOLATED_BIND,
                          str(source / "tools/hierarchy_launcher.py"), str(home), str(request),
                          str(foreign) if competing else "", str(marker)],
                         capture_output=True, text=True, timeout=30)
    assert not marker.exists()
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert ran.stdout == "bound from verified source\n"


_RESUME_BINDING_WORKER = '''import importlib.util
import json
from pathlib import Path
import sys

entry, arguments, mode = sys.argv[1:]
spec = importlib.util.spec_from_file_location("binding_resume_worker", entry)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if mode == "stop-unconfirmed":
    module.running_wake_group_exited = lambda record: False
sys.exit(module.main(json.loads(arguments)))
'''


def _binding_resume_case(tmp_path, mode):
    from tests.integration.test_hierarchy_launcher import Launch
    from tests.integration.test_hierarchy_mailbox import git

    built = Launch(tmp_path)
    bodies = {
        "locked": "return {'status': 'refused', 'code': 'state_locked'}",
        "other-refusal": "return {'status': 'refused', 'code': 'lease_unavailable'}",
        "exception": "raise RuntimeError('TOKEN=secret')",
        "stop-unconfirmed": "return {'status': 'refused', 'code': 'state_unavailable'}",
    }
    if mode in bodies:
        _binding_source(built.source, "def bind(*args):\n    " + bodies[mode] + "\n")
        git(built.source, "add", "aegis_core")
        git(built.source, "commit", "-qm", "binding boundary fixture")
    built.init()
    endpoint = "pilot/lane/f2"
    built.add_role(endpoint, host="codex-cli", session="019a" + uuid.uuid4().hex[:28], cwd=str(built.source))
    built.publish_to(endpoint, "binding-refusal")
    _host_plan(built.base, hierarchy="pilot")
    return built, endpoint


@pytest.mark.skipif(os.name == "nt", reason="resume uses POSIX process groups and inherited descriptors")
@pytest.mark.parametrize("mode,reason", [
    ("locked", "state_locked"), ("missing-source", "source_unavailable"),
    ("other-refusal", "lease_unavailable"), ("exception", "state_unavailable"),
    ("stop-unconfirmed", "state_unavailable"),
])
def test_binding_refusal_survives_complete_resume_and_launch_record(tmp_path, monkeypatch, mode, reason):
    built, endpoint = _binding_resume_case(tmp_path, mode)

    def run_worker(argv, **kwargs):
        if "_resume-wake" not in argv:
            return subprocess.run(argv, **kwargs)
        return subprocess.run([sys.executable, "-I", "-B", "-c", _RESUME_BINDING_WORKER,
                               str(built.source / "tools/hierarchy_launcher.py"),
                               json.dumps(argv[argv.index("--base"):]), mode], env=built.env(), timeout=30, **kwargs)

    monkeypatch.setattr(launcher, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run_worker}))
    code, record = launcher.resume(launcher.Launches(str(built.base)), endpoint, False)
    assert code == 2
    assert record["state"] == "refused"
    assert record["wake_exit_code"] == 2
    assert record["error"] == "writer binding refused: " + reason
    if mode == "stop-unconfirmed":
        assert record["wake"]["state"] == "stop_unconfirmed"
        assert launcher.read_running_wake(built.base, endpoint) is not None
    else:
        assert launcher.read_running_wake(built.base, endpoint) is None
    assert built.records(endpoint)[-1] == record
    assert "TOKEN" not in json.dumps(record)
    assert "secret" not in json.dumps(record)


def test_unsupported_verified_loader_refuses_without_owner_home_access(tmp_path, monkeypatch):
    launches, profile, _cwd = _resume_launches(tmp_path, tmp_path / "source")
    monkeypatch.setattr(launcher, "bootstrap_descriptor_capable", lambda: False)

    def no_home():
        pytest.fail("unsupported verified loading must precede owner-home access")

    monkeypatch.setattr(launcher, "_passwd_home", no_home)
    assert launcher.bind_writer_process(launches, "hier/lane/writer", profile, 99) == (
        "writer binding refused: source_unavailable")


@pytest.mark.parametrize("mode", ["oversize", "read-error", "ancestor-rename", "ancestor-link"])
def test_unsafe_verified_source_is_refused_without_execution_and_closes_fds(tmp_path, monkeypatch, mode):
    source = tmp_path / "verified"
    _VERIFIED_CALLS.clear()
    _binding_source(source, _verified_bind("    return {'status': 'ok'}\n"))
    launches, profile, _cwd = _resume_launches(tmp_path, source)
    target = source / "aegis_core" / "team_writer_binding.py"
    if mode == "oversize":
        with target.open("a", encoding="utf-8") as stream:
            stream.write("#" + "x" * 1048576)
    foreign = tmp_path / "foreign"
    _binding_source(foreign, _verified_bind("    return {'status': 'ok'}\n"))
    opened, source_fds = [], set()

    def open_at(path, flags, *args, **kwargs):
        if path == "team_writer_binding.py" and mode.startswith("ancestor-"):
            package = source / "aegis_core"
            package.rename(source / "parked")
            if mode == "ancestor-link":
                symlink_or_skip(foreign / "aegis_core", package, target_is_directory=True)
            else:
                shutil.copytree(foreign / "aegis_core", package)
        fd = os.open(path, flags, *args, **kwargs)
        opened.append(fd)
        if path == "team_writer_binding.py":
            source_fds.add(fd)
        return fd

    def read_at(fd, count):
        if mode == "read-error" and fd in source_fds:
            raise OSError("TOKEN=secret")
        return os.read(fd, count)

    monkeypatch.setattr(launcher, "os", SimpleNamespace(**{**vars(os), "open": open_at, "read": read_at}))
    finders_before = list(sys.meta_path)
    assert launcher.bind_writer_process(launches, "hier/lane/writer", profile, 99) == (
        "writer binding refused: source_unavailable")
    assert _VERIFIED_CALLS == []
    assert sys.meta_path == finders_before
    from aegis_core import team_writer_binding as restored_binding
    assert restored_binding is binding
    assert opened
    for fd in set(opened):
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


def test_verified_import_context_covers_lazy_import_after_lock_retry(tmp_path, monkeypatch):
    source = tmp_path / "verified"
    _VERIFIED_CALLS.clear()
    _binding_source(source, _verified_bind(
        "    if len(sys.modules[%r]._VERIFIED_CALLS) == 1:\n"
        "        return {'status': 'refused', 'code': 'state_locked'}\n"
        "    from aegis_core.retry_marker import VALUE\n"
        "    return {'status': 'ok'} if VALUE == 'verified' else None\n" % __name__
    ))
    (source / "aegis_core/retry_marker.py").write_text("VALUE = 'verified'\n", encoding="utf-8")
    launches, profile, _cwd = _resume_launches(tmp_path, source)
    monkeypatch.setattr(launcher, "_passwd_home", lambda: str(tmp_path))
    monkeypatch.setattr(launcher, "_BINDING_LOCK_WAIT_S", 0)
    assert launcher.bind_writer_process(launches, "hier/lane/writer", profile, 99) is None
    assert len(_VERIFIED_CALLS) == 2


@pytest.mark.skipif(os.name == "nt", reason="resume uses POSIX inherited descriptors")
@pytest.mark.parametrize("reason", ["writer binding refused: state_locked", "writer binding refused: bad\nTOKEN=secret"])
def test_code_three_launch_record_keeps_only_valid_binding_reason(tmp_path, monkeypatch, reason):
    built, endpoint = _binding_resume_case(tmp_path, "missing-source")

    def legacy_worker(argv, **kwargs):
        if "_resume-wake" not in argv:
            return subprocess.run(argv, **kwargs)
        return subprocess.CompletedProcess(argv, 3, json.dumps({"state": "stop_unconfirmed", "error": reason}), "")

    monkeypatch.setattr(launcher, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": legacy_worker}))
    code, record = launcher.resume(launcher.Launches(str(built.base)), endpoint, False)
    assert code == 3
    assert record["state"] == "resumed_unread"
    if reason == "writer binding refused: state_locked":
        assert record["error"] == reason
    else:
        assert "error" not in record
    assert built.records(endpoint)[-1] == record


@pytest.mark.skipif(os.name == "nt", reason="resume uses POSIX process groups and inherited descriptors")
@pytest.mark.parametrize("mode,reason", [("locked", "state_locked"), ("other-refusal", "lease_unavailable")])
@pytest.mark.parametrize("failure", ["admission", "running-read", "running-clear"])
def test_parent_recovery_keeps_binding_reason_in_resume_and_status(tmp_path, monkeypatch, capsys,
                                                                 mode, reason, failure):
    built, endpoint = _binding_resume_case(tmp_path, mode)
    write_admission = launcher.write_resume_admission
    read_running = launcher.read_running_wake
    admissions, completed = [], []

    def run_worker(argv, **kwargs):
        if "_resume-wake" not in argv:
            return subprocess.run(argv, **kwargs)
        ran = subprocess.run([sys.executable, "-I", "-B", "-c", _RESUME_BINDING_WORKER,
                              str(built.source / "tools/hierarchy_launcher.py"),
                              json.dumps(argv[argv.index("--base"):]), mode], env=built.env(), timeout=30, **kwargs)
        assert ran.returncode == 2, ran.stdout + ran.stderr
        answer = json.loads(ran.stdout)
        assert answer["error"] == "writer binding refused: " + reason
        assert set(answer["_admission_exit"]) == {"wake_id", "driver_pid", "host_pid"}
        completed.append(answer)
        return ran

    def fail_second_admission(*args, **kwargs):
        admissions.append(args)
        if len(admissions) == 2:
            assert completed
            raise OSError("TOKEN=secret\nparent publication failed")
        return write_admission(*args, **kwargs)

    def fail_running_read(*args, **kwargs):
        if completed:
            raise OSError("TOKEN=secret\nparent read failed")
        return read_running(*args, **kwargs)

    def fail_running_clear(*args, **kwargs):
        assert completed
        raise OSError("TOKEN=secret\nparent clear failed")

    monkeypatch.setattr(launcher, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run_worker}))
    if failure == "admission":
        monkeypatch.setattr(launcher, "write_resume_admission", fail_second_admission)
        recovery = "resume admission publication failed; preserve admission evidence and run stop"
    elif failure == "running-read":
        monkeypatch.setattr(launcher, "read_running_wake", fail_running_read)
        recovery = "running wake retirement unavailable; preserve its evidence and run stop"
    else:
        monkeypatch.setattr(launcher, "clear_running_wake", fail_running_clear)
        recovery = "running wake retirement unavailable; preserve its evidence and run stop"
    code = launcher.main(["--base", str(built.base), "resume", "--endpoint", endpoint])
    record = json.loads(capsys.readouterr().out)
    assert completed
    assert code == (2 if failure == "admission" else 3)
    assert record["state"] == ("refused" if failure == "admission" else "resumed_unread")
    assert record["error"] == "writer binding refused: " + reason
    assert record["recovery_error"] == recovery
    assert built.records(endpoint)[-1] == record
    status_code, status = launcher.status(launcher.Launches(str(built.base)), endpoint)
    assert status_code == 0
    assert status["endpoints"][endpoint]["last"] == record
    assert read_running(built.base, endpoint) is not None
    assert "TOKEN" not in json.dumps(record)
    assert "secret" not in json.dumps(record)


def test_launcher_binding_codes_match_declared_refusals():
    assert set(binding._REASONS) | {"source_unavailable"} == launcher._BINDING_CODES
