"""Public process-port parity, refusal, resource and concurrency contracts."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import errno
import json
import os
from pathlib import Path
import stat
import sys
from threading import Barrier, Event, current_thread
import time
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_native_bridge as bridge
from tests.unit.core.test_team_mailbox import owner_plane


HASH = "a" * 64


@pytest.fixture
def build(tmp_path):
    if not bridge.process_supported():
        pytest.skip("descriptor process port requires POSIX waitid WNOWAIT")

    def create(program=None, *, evidence_dir=None, stop_grace=0.01, **options):
        if program is None:
            program = ("import json,sys; r=json.load(sys.stdin); "
                       "print(json.dumps(dict(r,result={'state':'eligible','native_qualified':False})))")
        return bridge.ProcessBridge([sys.executable, "-I", "-B", "-c", program],
                                    cwd=tmp_path, evidence_dir=evidence_dir or tmp_path / "evidence",
                                    timeout_seconds=2, stop_grace=stop_grace,
                                    evidence_only=True, **options)
    return create


def descriptor(tmp_path, program="pass"):
    return {"schema": "aegis.fixture-process-provider/v1", "mode": "fixture", "provider": "fixture",
            "endpoint_id": "endpoint", "argv": [sys.executable, "-I", "-c", program],
            "cwd": tmp_path.as_posix(), "evidence_dir": (tmp_path / "evidence").as_posix(), "stop_grace": 0.01}


def test_native_refusal_parity_and_gate_never_enables_execution():
    from tools.hierarchy_watch_bridge import NativeBridge as Legacy
    for host in ("codex", "claude-code", "unknown-host"):
        current, legacy = bridge.NativeBridge(host), Legacy(host)
        assert current.capabilities() == legacy.capabilities()
        for result, expected in (
                (current.observe("work-one", HASH), legacy.observe("work-one", HASH)),
                (current.continue_request("work-one", HASH, "op"), legacy.continue_request("work-one", HASH, "op"))):
            assert {key: result[key] for key in expected} == expected
            assert result["next_action"]
    gated = bridge.NativeBridge(qualification_gate=lambda: True)
    assert gated.continue_request("work-one", HASH, "op")["state"] == "refused"
    assert gated.capabilities()["execution_enabled"] is False


@pytest.mark.parametrize("args", [("BAD", HASH), ("work-one", "bad"), ([], HASH)])
def test_bad_correlation_is_typed_and_input_free(args):
    with pytest.raises(bridge.BridgeRefusal) as caught:
        bridge.correlation(*args)
    assert caught.value.reason == "invalid_correlation"
    assert caught.value.next_action
    assert str(caught.value) == "native bridge refused: invalid_correlation"


def test_explicit_evidence_required_before_any_io(tmp_path):
    with pytest.raises(bridge.BridgeRefusal, match="^native bridge refused: evidence_only_required$"):
        bridge.ProcessBridge([sys.executable], cwd=tmp_path, evidence_dir=tmp_path / "evidence")
    assert list(tmp_path.iterdir()) == []


def test_unsupported_probe_refuses_without_io(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "process_supported", lambda: False)
    with pytest.raises(bridge.BridgeRefusal, match="^native bridge refused: unsupported_platform$"):
        bridge.ProcessBridge([sys.executable], cwd=tmp_path, evidence_dir=tmp_path / "evidence", evidence_only=True)
    result = bridge.process_provider_call(descriptor(tmp_path), "inspect", {"id": "work-one", "source": {}},
                                          HASH, actor="operator", generation=1,
                                          deadline=time.monotonic() + 1, evidence_only=True)
    assert result["transport"] == "not_sent"
    assert result["reason"] == "process provider requires POSIX waitid WNOWAIT"
    assert result["next_action"]
    assert list(tmp_path.iterdir()) == []


def test_success_retains_correlated_evidence_and_reaps(build):
    result = build().observe("work-one", HASH)
    assert result["state"] == "eligible"
    assert result["process"]["reaped"] is True
    folder = Path(result["evidence_dir"])
    assert json.loads((folder / "request.json").read_bytes())["request_sha256"] == HASH
    assert json.loads((folder / "result.json").read_bytes()) == result


@pytest.mark.parametrize("program,reason", [
    ("print('{broken')", "invalid process bridge response"),
    ("raise SystemExit(7)", "process bridge exited unsuccessfully"),
    ("import sys;sys.stdout.write('x'*1100000)", "process bridge output limit exceeded"),
    ("import sys;sys.stderr.write('x'*1100000)", "process bridge output limit exceeded"),
    ("import json,sys;r=json.load(sys.stdin);r['request_sha256']='b'*64;"
     "print(json.dumps(dict(r,result={})))", "process bridge response correlation mismatch"),
    ("import json,sys;r=json.load(sys.stdin);print(json.dumps(dict(r,result=[])))",
     "invalid process bridge qualification"),
])
def test_process_failures_are_uncertain_bounded_and_retryable(build, program, reason):
    result = build(program).continue_request("work-one", HASH, "op")
    assert (result["state"], result["effect"], result["reason"]) == ("unknown", "possible", reason)
    assert result["process"]["reaped"] and result["next_action"]
    assert max((Path(result["evidence_dir"]) / name).stat().st_size for name in ("stdout", "stderr")) <= 1048576
    assert build().observe("work-one", HASH)["state"] == "eligible"


def test_cancel_before_launch_and_timeout_after_launch(build):
    event = Event()
    event.set()
    controlled = build().with_control(deadline=None, stop_event=event)
    result = controlled.continue_request("work-one", HASH, "op")
    assert (result["state"], result["effect"], result["evidence_dir"]) == ("refused", "none", None)
    hanging = build("import time;time.sleep(30)").with_control(deadline=time.monotonic() + 0.1, stop_event=None)
    result = hanging.continue_request("work-one", HASH, "op")
    assert result["reason"] == "process bridge deadline reached"
    assert result["state"] == "unknown" and result["process"]["reaped"]


def test_concurrent_calls_have_distinct_evidence(build):
    adapter = build()
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: adapter.observe("work-one", HASH), range(3)))
    assert all(result["state"] == "eligible" for result in results)
    assert len({result["evidence_dir"] for result in results}) == 3
    assert adapter.observe("work-one", HASH)["state"] == "eligible"


def test_symlink_evidence_is_refused_and_retry_succeeds(build, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    symlink_or_skip(outside, tmp_path / "evidence", target_is_directory=True)
    with pytest.raises(bridge.BridgeRefusal, match="^native bridge refused: unsafe_path$"):
        build()
    assert list(outside.iterdir()) == []
    (tmp_path / "evidence").unlink()
    assert build().observe("work-one", HASH)["state"] == "eligible"


def test_descriptor_validation_matches_legacy_without_mutation(tmp_path):
    from tools.hierarchy_watch_bridge import validate_process_provider as legacy
    spec = descriptor(tmp_path)
    assert bridge.validate_process_provider(spec) == legacy(spec)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("field,value", [("argv", ["relative"]), ("argv", ["x"] * 65),
                                          ("stop_grace", True), ("mode", "native"),
                                          ("endpoint_id", "https://host"), ("provider", "x" * 262145)],
                         ids=["relative", "argv-count", "bool-grace", "native", "url", "oversize"])
def test_descriptor_refusal_is_bounded_and_input_free(tmp_path, field, value):
    spec = descriptor(tmp_path)
    spec[field] = value
    with pytest.raises(bridge.BridgeRefusal) as caught:
        bridge.validate_process_provider(spec)
    assert caught.value.next_action
    assert len(str(caught.value)) < 128
    assert list(tmp_path.iterdir()) == []


def test_cyclic_provider_input_is_typed_before_spawn(tmp_path):
    spec = descriptor(tmp_path)
    spec["cycle"] = spec
    with pytest.raises(bridge.BridgeRefusal):
        bridge.validate_process_provider(spec)
    assert list(tmp_path.iterdir()) == []


def test_provider_inspection_closed_schema(build, tmp_path):
    program = ("import json,sys;r=json.load(sys.stdin);v={'qualified':True,'mode':'fixture',"
               "'source':r['request']['source'],'gates':{k:[] for k in "
               "['source','capability','lease','capacity','observer','job']},'reason':'fixture'};"
               "print(json.dumps(dict(r,result=v)))")
    result = bridge.process_provider_call(descriptor(tmp_path, program), "inspect",
                                          {"id": "work-one", "source": {}}, HASH,
                                          actor="operator", generation=1, deadline=time.monotonic() + 2,
                                          evidence_only=True)
    assert result["transport"] == "received"
    assert result["native_qualified"] is False


def test_launch_failure_never_echoes_exception(build, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("private-untrusted-input")
    monkeypatch.setattr(bridge, "subprocess", SimpleNamespace(**{**vars(bridge.subprocess), "Popen": fail}))
    result = build().continue_request("work-one", HASH, "op")
    assert result["state"] == "refused" and result["effect"] == "none"
    assert result["reason"] == "process bridge launch failed"
    assert "private-untrusted-input" not in json.dumps(result)


@pytest.mark.parametrize("option", ["timeout_seconds", "stop_grace"])
def test_huge_numeric_control_refuses_before_float_conversion(tmp_path, option):
    with pytest.raises(bridge.BridgeRefusal, match="^native bridge refused: invalid_input$"):
        bridge.ProcessBridge([sys.executable], cwd=tmp_path, evidence_dir=tmp_path / "evidence",
                             evidence_only=True, **{option: 10 ** 10000})


def test_control_deadline_and_provider_deadline_refuse_huge_integer(build, tmp_path):
    with pytest.raises(bridge.BridgeRefusal):
        build().with_control(deadline=10 ** 10000, stop_event=None)
    with pytest.raises(bridge.BridgeRefusal):
        bridge.process_provider_call(descriptor(tmp_path), "inspect", {"id": "work-one", "source": {}},
                                     HASH, actor="operator", generation=1, deadline=10 ** 10000,
                                     evidence_only=True)


def test_host_display_canonicalizes_redacts_before_truncation():
    secret = "gh" + "p_" + "a" * 36
    result = bridge.NativeBridge("\x1b[31m" + secret[:8] + "\r" + secret[8:]).capabilities()
    assert secret not in json.dumps(result)
    assert "\x1b" not in result["host"] and "\r" not in result["host"]


def test_request_size_refuses_before_evidence_allocation(tmp_path):
    with pytest.raises(bridge.BridgeRefusal):
        bridge.process_provider_call(descriptor(tmp_path), "inspect",
                                     {"id": "work-one", "source": {"large": "x" * 1048577}},
                                     HASH, actor="operator", generation=1,
                                     deadline=time.monotonic() + 1, evidence_only=True)
    assert list(tmp_path.iterdir()) == []


def test_provider_reply_extra_fields_are_uncertain(build, tmp_path):
    program = "import json,sys;r=json.load(sys.stdin);print(json.dumps(dict(r,result={'extra':1})))"
    result = bridge.process_provider_call(descriptor(tmp_path, program), "inspect", {"id": "work-one", "source": {}},
                                          HASH, actor="operator", generation=1,
                                          deadline=time.monotonic() + 2, evidence_only=True)
    assert result["transport"] == "uncertain" and result["reason"] == "invalid process provider inspection"
    assert result["next_action"]


def test_failed_descriptor_open_closes_previously_opened_fds(build, monkeypatch):
    opened = []
    real_open = os.open

    def fail(path, *args, **kwargs):
        if path == "stdout":
            raise OSError("untrusted-detail")
        fd = real_open(path, *args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(bridge, "os", SimpleNamespace(**{**vars(os), "open": fail}))
    result = build().observe("work-one", HASH)
    assert result["reason"] == "process bridge evidence unavailable"
    for fd in opened:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == 9


def test_provider_deadline_reserve_does_not_launch(tmp_path):
    result = bridge.process_provider_call(descriptor(tmp_path), "inspect", {"id": "work-one", "source": {}},
                                          HASH, actor="operator", generation=1,
                                          deadline=time.monotonic() - 1, evidence_only=True)
    assert result["transport"] == "not_sent"
    assert result["next_action"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("method", ["submit", "observe", "cancel"])
def test_provider_association_and_handle_roundtrip(build, tmp_path, method):
    program = ("import json,sys;r=json.load(sys.stdin);v={'association_sha256':r['association_sha256'],"
               "'provider_state':'running','provider_handle':{'thread_id':'thread','turn_id':'turn'},"
               "'exit_code':None,'evidence':[{'fixture':True}],'quiescent':False};"
               "print(json.dumps(dict(r,result=v)))")
    association = {"request_id": "work-one", "request_sha256": HASH, "source": {},
                   "provider": "fixture", "endpoint_id": "endpoint", "thread_id": "thread"}
    result = bridge.process_provider_call(descriptor(tmp_path, program), method, {"id": "work-one", "source": {}},
                                          HASH, actor="operator", generation=1, association=association,
                                          provider_handle={"thread_id": "thread", "turn_id": "turn"},
                                          reason="stop" if method == "cancel" else None,
                                          deadline=time.monotonic() + 2, evidence_only=True)
    assert result["transport"] == "received" and result["result"]["provider_state"] == "running"
    assert result["native_qualified"] is False and result["process"]["reaped"]


@pytest.mark.parametrize("mutation,reason", [
    ("v['provider_state']=[]", "invalid process provider observation"),
    ("v['extra']=True", "invalid process provider observation"),
    ("v['association_sha256']='bad'", "invalid process provider observation"),
    ("v['provider_handle']={'thread_id':'wrong','turn_id':'turn'}", "process provider handle correlation mismatch"),
    ("v['provider_handle']=[]", "invalid process provider handle"),
], ids=["bad-state", "extra", "hash", "wrong-thread", "bad-handle"])
def test_provider_closed_observation_refuses_without_raw_exceptions(build, tmp_path, mutation, reason):
    program = ("import json,sys;r=json.load(sys.stdin);v={'association_sha256':r['association_sha256'],"
               "'provider_state':'running','provider_handle':None,'exit_code':None,"
               "'evidence':[{}],'quiescent':False};" + mutation + ";print(json.dumps(dict(r,result=v)))")
    association = {"request_id": "work-one", "request_sha256": HASH, "source": {},
                   "provider": "fixture", "endpoint_id": "endpoint", "thread_id": "thread"}
    result = bridge.process_provider_call(descriptor(tmp_path, program), "submit", {"id": "work-one", "source": {}},
                                          HASH, actor="operator", generation=1, association=association,
                                          deadline=time.monotonic() + 2, evidence_only=True)
    assert result["transport"] == "uncertain" and result["reason"] == reason
    assert result["next_action"] and result["process"]["reaped"]


def test_pipe_close_failure_preserves_possible_execution_and_closes_both(build, monkeypatch):
    real_popen = bridge.subprocess.Popen
    streams = []

    class FaultyStream:
        def __init__(self, stream):
            self.stream = stream

        def fileno(self):
            return self.stream.fileno()

        def close(self):
            self.stream.close()
            raise OSError("untrusted-close-detail")

    def start(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        streams.extend((process.stdout, process.stderr))
        process.stdout = FaultyStream(process.stdout)
        return process

    monkeypatch.setattr(bridge, "subprocess", SimpleNamespace(**{**vars(bridge.subprocess), "Popen": start}))
    result = build().continue_request("work-one", HASH, "op")
    assert (result["state"], result["effect"]) == ("unknown", "possible")
    assert result["reason"] == "process bridge observation failed"
    assert result["process"]["reaped"] and all(stream.closed for stream in streams)
    assert "untrusted-close-detail" not in json.dumps(result)


def test_ancestor_swap_during_launch_uses_held_cwd_and_evidence(build, tmp_path, monkeypatch):
    root, saved, outside = (tmp_path / name for name in ("work", "saved", "outside"))
    root.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    (root / "marker").write_text("original")
    program = ("import json,sys;r=json.load(sys.stdin);print(json.dumps(dict(r,result="
               "{'state':'eligible','native_qualified':False,'marker':open('marker').read()})))")
    adapter = bridge.ProcessBridge([sys.executable, "-I", "-c", program], cwd=root,
                                   evidence_dir=root / "evidence", timeout_seconds=2,
                                   stop_grace=0.01, evidence_only=True)
    real_popen = bridge.subprocess.Popen

    def swap(*args, **kwargs):
        root.rename(saved)
        symlink_or_skip(outside, root, target_is_directory=True)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(bridge, "subprocess", SimpleNamespace(**{**vars(bridge.subprocess), "Popen": swap}))
    try:
        result = adapter.observe("work-one", HASH)
        assert result["state"] == "eligible" and result["marker"] == "original"
        assert list(outside.iterdir()) == []
        assert len(list((saved / "evidence").glob("*/result.json"))) == 1
    finally:
        if root.is_symlink():
            root.unlink()
        if saved.exists():
            saved.rename(root)


def test_result_wire_limit_is_checked_before_result_file_creation(build):
    program = ("import json,sys;r=json.load(sys.stdin);print(json.dumps(dict(r,result="
               "{'state':'eligible','native_qualified':False,'payload':[chr(233)*4096]*100}),ensure_ascii=False))")
    result = build(program).observe("work-one", HASH)
    assert result["state"] == "hold" and result["process"]["reaped"]
    assert result["reason"] == "process bridge evidence unavailable"
    assert not (Path(result["evidence_dir"]) / "result.json").exists()
    assert build().observe("work-one", HASH)["state"] == "eligible"


def wait_for_started(directory, count, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if len(list(directory.glob("started-*"))) == count:
            return
        time.sleep(0.01)
    pytest.fail("not all fixture children started before the bounded deadline")


def overlapping_program(count):
    return ("import json,os,sys,time;from pathlib import Path\n"
            "r=json.load(sys.stdin);Path('started-'+str(os.getpid())).touch();limit=time.monotonic()+3\n"
            "while len(list(Path('.').glob('started-*'))) < " + str(count) + ":\n"
            " if time.monotonic()>=limit: raise SystemExit(9)\n"
            " time.sleep(.01)\n"
            "print(json.dumps(dict(r,result={'state':'eligible','native_qualified':False})))")


@pytest.mark.parametrize("count", [2, 8])
def test_overlapping_children_all_start_before_any_finishes(build, tmp_path, count):
    adapter = build(overlapping_program(count))
    start = Barrier(count)

    def call(index):
        start.wait(timeout=3)
        return adapter.observe("work-" + str(index), HASH)

    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(pool.map(call, range(count)))
    assert len(list(tmp_path.glob("started-*"))) == count
    assert all(result["state"] == "eligible" and result["process"]["reaped"] for result in results)
    folders = [Path(result["evidence_dir"]) for result in results]
    assert len(set(folders)) == count
    assert len(list((tmp_path / "evidence").glob("*/result.json"))) == count
    assert all(json.loads((folder / "result.json").read_bytes()) == result for folder, result in zip(folders, results))


@pytest.mark.parametrize("failure", ["EINVAL", "ENOTSUP"])
def test_calls_succeed_when_directory_flock_is_unavailable(build, monkeypatch, failure):
    class UnflockableStore(bridge.Store):
        def owner_lock(self, transaction):
            assert stat.S_ISDIR(os.fstat(self.fd).st_mode)
            raise OSError(getattr(errno, failure), "directory flock unsupported")

    monkeypatch.setattr(bridge, "Store", UnflockableStore)
    result = build().observe("work-one", HASH)
    assert result["state"] == "eligible" and result["process"]["reaped"]
    assert json.loads((Path(result["evidence_dir"]) / "result.json").read_bytes()) == result


def test_creation_collision_deadline_refuses_without_partial_directory(build, monkeypatch):
    deadline = time.monotonic() + 10
    adapter = build().with_control(deadline=deadline, stop_event=None)
    adapter.evidence_dir.mkdir(mode=0o700)
    occupied = adapter.evidence_dir / ("a" * 32)
    occupied.mkdir(mode=0o700)
    elapsed = Event()

    def mkdir(name, mode, *, dir_fd):
        try:
            os.mkdir(name, mode, dir_fd=dir_fd)
        except FileExistsError:
            if name == occupied.name:
                elapsed.set()
            raise

    monkeypatch.setattr(bridge, "os", SimpleNamespace(**{**vars(os), "mkdir": mkdir}))
    monkeypatch.setattr(bridge, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex=occupied.name)))
    monkeypatch.setattr(bridge, "time", SimpleNamespace(
        monotonic=lambda: deadline if elapsed.is_set() else time.monotonic(), sleep=time.sleep))
    result = adapter.continue_request("work-one", HASH, "op")
    assert (result["state"], result["effect"], result["process"], result["evidence_dir"]) == (
        "refused", "none", None, None)
    assert result["reason"] == "process bridge deadline reached" and result["next_action"]
    assert elapsed.is_set()
    assert list(adapter.evidence_dir.iterdir()) == [occupied]
    assert list(occupied.iterdir()) == []


@pytest.mark.parametrize("entry", ["directory", "symlink"])
def test_creation_collision_retries_with_fresh_directory(build, tmp_path, monkeypatch, entry):
    adapter = build()
    adapter.evidence_dir.mkdir(mode=0o700)
    occupied = adapter.evidence_dir / ("a" * 32)
    if entry == "directory":
        occupied.mkdir(mode=0o700)
        destination = occupied
    else:
        destination = tmp_path / "outside"
        destination.mkdir(mode=0o700)
        symlink_or_skip(destination, occupied, target_is_directory=True)
    names = iter([occupied.name, "b" * 32])
    monkeypatch.setattr(bridge, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex=next(names))))

    result = adapter.observe("work-one", HASH)
    assert result["state"] == "eligible" and result["process"]["reaped"]
    assert Path(result["evidence_dir"]) == adapter.evidence_dir / ("b" * 32)
    assert list(destination.iterdir()) == []


def test_evidence_mkdir_failure_is_typed_and_retryable(build, tmp_path, monkeypatch):
    adapter = build(evidence_dir=tmp_path / "runs" / "evidence")
    fail_once = [True]

    def mkdir(name, mode, *, dir_fd):
        if name == "evidence" and fail_once[0]:
            fail_once[0] = False
            raise OSError(errno.ENOTSUP, "untrusted-filesystem-detail")
        os.mkdir(name, mode, dir_fd=dir_fd)

    monkeypatch.setattr(bridge, "os", SimpleNamespace(**{**vars(os), "mkdir": mkdir}))
    result = adapter.continue_request("work-one", HASH, "op")
    assert (result["state"], result["effect"], result["process"], result["evidence_dir"]) == (
        "refused", "none", None, None)
    assert result["reason"] == "process bridge evidence unavailable" and result["next_action"]
    assert "untrusted-filesystem-detail" not in json.dumps(result)
    assert list(tmp_path.iterdir()) == []
    assert adapter.observe("work-one", HASH)["state"] == "eligible"


def test_existing_evidence_ancestors_do_not_require_mkdir(build, tmp_path, monkeypatch):
    adapter = build(evidence_dir=tmp_path / "runs" / "evidence")
    adapter.evidence_dir.parent.mkdir(mode=0o700)
    adapter.evidence_dir.mkdir(mode=0o700)

    def mkdir(name, mode, *, dir_fd):
        if name in {"runs", "evidence"}:
            raise OSError(errno.EROFS, "ancestor allows traversal only")
        os.mkdir(name, mode, dir_fd=dir_fd)

    monkeypatch.setattr(bridge, "os", SimpleNamespace(**{**vars(os), "mkdir": mkdir}))
    result = adapter.observe("work-one", HASH)
    assert result["state"] == "eligible" and result["process"]["reaped"]
    assert Path(result["evidence_dir"]).parent == adapter.evidence_dir


def test_call_retries_when_an_interrupted_call_removes_shared_parent(build, monkeypatch):
    adapter = build()
    caller = current_thread()
    created, borrowed, rolled_back, stop = Event(), Event(), Event(), Event()

    class InterleavingStore(bridge.Store):
        @contextmanager
        def directory(self, path, *args, **kwargs):
            with super().directory(path, *args, **kwargs) as fd:
                if path == adapter.evidence_dir and kwargs.get("parent") is not None:
                    if current_thread() is caller:
                        created.set()
                        assert borrowed.wait(timeout=1), "concurrent call could not borrow the shared parent"
                        stop.set()
                    elif not borrowed.is_set():
                        borrowed.set()
                        assert rolled_back.wait(timeout=2)
                yield fd

    monkeypatch.setattr(bridge, "Store", InterleavingStore)

    def call():
        assert created.wait(timeout=2)
        return adapter.observe("work-two", HASH)

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(call)
        try:
            interrupted = adapter.with_control(deadline=None, stop_event=stop).observe("work-one", HASH)
        finally:
            rolled_back.set()
        result = pending.result(timeout=3)
    assert interrupted["reason"] == "process bridge stop requested"
    assert interrupted["process"] is None and interrupted["evidence_dir"] is None
    assert result["state"] == "eligible" and result["process"]["reaped"]
    assert list(adapter.evidence_dir.iterdir()) == [Path(result["evidence_dir"])]


def test_evidence_rewalks_after_bound_ancestor_is_removed(build, tmp_path, monkeypatch):
    adapter = build()
    ancestor = adapter.evidence_dir.name
    steps = []
    held_folders = []
    assert not adapter.evidence_dir.exists()

    def identity(info):
        return info.st_dev, info.st_ino

    with bridge.Store.from_parent(tmp_path) as anchor:
        anchor_identity = identity(os.fstat(anchor.fd))

        def mkdir(name, mode, *, dir_fd):
            if name == ancestor:
                assert identity(os.fstat(dir_fd)) == anchor_identity
                os.mkdir(name, mode, dir_fd=dir_fd)
                steps.append("ancestor created")
                return
            if steps == ["ancestor created"]:
                assert identity(os.fstat(dir_fd)) == identity(os.lstat(ancestor, dir_fd=anchor.fd))
                os.rmdir(ancestor, dir_fd=anchor.fd)
                try:
                    os.mkdir(name, mode, dir_fd=dir_fd)
                except FileNotFoundError as error:
                    assert error.errno == errno.ENOENT
                    assert os.fstat(dir_fd).st_nlink == 0
                    steps.append("detached parent refused leaf")
                    raise
                pytest.fail("mkdir succeeded through the descriptor of the removed ancestor")
            os.mkdir(name, mode, dir_fd=dir_fd)
            steps.append("leaf created")

        def open_evidence(name, flags, mode, *, dir_fd):
            if name == "request.json":
                held_folders.append(identity(os.fstat(dir_fd)))
            return os.open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(bridge, "os", SimpleNamespace(**{**vars(os), "mkdir": mkdir, "open": open_evidence}))
        result = adapter.observe("work-one", HASH)
        assert result["state"] == "eligible" and result["process"]["reaped"]
        assert steps == ["ancestor created", "detached parent refused leaf", "ancestor created", "leaf created"]
        folder = Path(result["evidence_dir"])
        assert folder.parent == adapter.evidence_dir
        assert held_folders == [identity(os.lstat(folder.relative_to(tmp_path), dir_fd=anchor.fd))]
        assert json.loads((folder / "request.json").read_bytes())["request_sha256"] == HASH
        assert json.loads((folder / "result.json").read_bytes()) == result


def test_creation_borrow_failure_rolls_back_and_retries(build, tmp_path, monkeypatch):
    fail_once = [True]

    class FailingStore(bridge.Store):
        @contextmanager
        def directory(self, *args, **kwargs):
            if kwargs.get("held") and fail_once[0]:
                fail_once[0] = False
                raise OSError("untrusted-borrow-detail")
            with super().directory(*args, **kwargs) as fd:
                yield fd

    monkeypatch.setattr(bridge, "Store", FailingStore)
    result = build().continue_request("work-one", HASH, "op")
    assert (result["state"], result["effect"], result["process"]) == ("refused", "none", None)
    assert result["reason"] == "process bridge evidence unavailable" and result["next_action"]
    assert "untrusted-borrow-detail" not in json.dumps(result)
    assert list(tmp_path.iterdir()) == []
    assert build().observe("work-one", HASH)["state"] == "eligible"


@pytest.mark.parametrize("interruption", ["cancel", "timeout"])
def test_one_interrupted_child_does_not_disturb_other_calls(build, tmp_path, interruption):
    program = ("import json,os,time,sys;from pathlib import Path\n"
               "r=json.load(sys.stdin);Path('started-'+str(os.getpid())).touch();limit=time.monotonic()+4\n"
               "while not Path('release').exists():\n"
               " if time.monotonic()>=limit: raise SystemExit(9)\n"
               " time.sleep(.01)\n"
               "print(json.dumps(dict(r,result={'state':'eligible','native_qualified':False})))")
    adapter = build(program)
    event = Event()
    controlled = adapter.with_control(deadline=time.monotonic() + 1 if interruption == "timeout" else None,
                                      stop_event=event)
    with ThreadPoolExecutor(max_workers=3) as pool:
        affected = pool.submit(controlled.continue_request, "affected", HASH, "op")
        survivors = [pool.submit(adapter.observe, "survivor-" + str(index), HASH) for index in range(2)]
        try:
            wait_for_started(tmp_path, 3)
            if interruption == "cancel":
                event.set()
            result = affected.result(timeout=3)
            assert (result["state"], result["effect"]) == ("unknown", "possible")
            expected = "process bridge stop requested" if interruption == "cancel" else "process bridge deadline reached"
            assert result["reason"] == expected and result["process"]["reaped"]
            assert all(not future.done() for future in survivors)
        finally:
            (tmp_path / "release").touch()
        other_results = [future.result(timeout=3) for future in survivors]
    assert all(result["state"] == "eligible" and result["process"]["reaped"] for result in other_results)
    assert len({result["evidence_dir"] for result in [result, *other_results]}) == 3


@pytest.mark.parametrize("root_kind", ["cwd", "evidence"])
def test_non_private_root_is_refused_without_effects(build, tmp_path, root_kind):
    selected = tmp_path / "writable"
    selected.mkdir(mode=0o700)
    selected.chmod(0o777)
    try:
        with pytest.raises(bridge.BridgeRefusal, match="^native bridge refused: unsafe_path$"):
            bridge.ProcessBridge([sys.executable], cwd=selected if root_kind == "cwd" else tmp_path,
                                 evidence_dir=selected if root_kind == "evidence" else tmp_path / "evidence",
                                 evidence_only=True)
        assert list(selected.iterdir()) == [] and not (tmp_path / "evidence").exists()
    finally:
        selected.chmod(0o700)


def test_non_owner_root_is_refused_without_effects(build, tmp_path):
    if Path("/").stat().st_uid == os.geteuid():
        pytest.skip("a foreign-owned root is unavailable for this effective owner")
    with pytest.raises(bridge.BridgeRefusal, match="^native bridge refused: unsafe_path$"):
        bridge.ProcessBridge([sys.executable], cwd=Path("/"), evidence_dir=tmp_path / "evidence", evidence_only=True)
    assert list(tmp_path.iterdir()) == []


def test_custom_json_objects_are_refused_without_running_hooks(tmp_path):
    class HostileDict(dict):
        def __iter__(self):
            raise AssertionError("custom object hook must not run")

    spec = descriptor(tmp_path)
    spec["extra"] = HostileDict()
    with pytest.raises(bridge.BridgeRefusal, match="^native bridge refused: invalid_input$"):
        bridge.validate_process_provider(spec)
    assert list(tmp_path.iterdir()) == []


def test_display_key_collision_cannot_overwrite_validated_qualification(build):
    program = ("import json,sys;r=json.load(sys.stdin);v={'state':'completed','effect':'confirmed','native_qualified':False};"
               "v['native_'+chr(27)+'[31mqualified']=True;print(json.dumps(dict(r,result=v)))")
    result = build(program).continue_request("work-one", HASH, "op")
    assert result["native_qualified"] is False
    assert (result["state"], result["effect"]) == ("unknown", "possible")
    assert result["reason"] == "process bridge evidence unavailable" and result["next_action"]
    assert build().observe("work-one", HASH)["state"] == "eligible"


def test_nested_provider_display_collision_is_uncertain(build, tmp_path):
    program = ("import json,sys;r=json.load(sys.stdin);p={'proof':False};p['pro'+chr(27)+'[31mof']=True;"
               "v={'qualified':True,'mode':'fixture','source':r['request']['source'],"
               "'gates':{k:[p] for k in ['source','capability','lease','capacity','observer','job']},'reason':'fixture'};"
               "print(json.dumps(dict(r,result=v)))")
    result = bridge.process_provider_call(descriptor(tmp_path, program), "inspect", {"id": "work-one", "source": {}},
                                          HASH, actor="operator", generation=1,
                                          deadline=time.monotonic() + 2, evidence_only=True)
    assert result["transport"] == "uncertain" and result["native_qualified"] is False
    assert result["reason"] == "process bridge evidence unavailable" and result["next_action"]
    assert result["process"]["reaped"]


@pytest.mark.parametrize("stream", [1, 2])
def test_cleanup_descendant_output_counts_toward_limit(build, stream):
    if not hasattr(os, "fork"):
        pytest.skip("descendant fixture needs fork")
    program = """import json,os,signal,sys,time
from pathlib import Path
r=json.load(sys.stdin)
if os.fork()==0:
    def stopped(*args):
        os.write(STREAM,b'x'*1100000)
        os._exit(0)
    signal.signal(signal.SIGTERM,stopped)
    Path('cleanup-ready').touch()
    while True: time.sleep(.01)
end=time.monotonic()+2
while not Path('cleanup-ready').exists():
    if time.monotonic()>=end: raise SystemExit(9)
    time.sleep(.01)
print(json.dumps(dict(r,result={'state':'eligible','native_qualified':False})),flush=True)
"""
    adapter = build(program.replace("STREAM", str(stream)), stop_grace=0.2)
    result = adapter.observe("work-one", HASH)
    assert result["state"] == "hold" and result["reason"] == "process bridge output limit exceeded"
    assert result["process"]["reaped"]
    leaf = "stdout" if stream == 1 else "stderr"
    assert (Path(result["evidence_dir"]) / leaf).stat().st_size == adapter.MAX_OUTPUT


def test_child_io_accepts_high_descriptors(build, tmp_path):
    # Allocate consecutive descriptors without overwriting a live descriptor.
    import resource
    if resource.getrlimit(resource.RLIMIT_NOFILE)[0] in range(1100):
        pytest.skip("fd limit cannot exercise a pipe above FD_SETSIZE")
    adapter = build()
    source = tmp_path / "held"
    source.touch()
    with ExitStack() as files:
        while files.enter_context(source.open("rb")).fileno() < 1050:
            pass
        result = adapter.observe("work-one", HASH)
    assert result["state"] == "eligible" and result["process"]["reaped"]


@pytest.mark.parametrize("state,effect", [("hold", None), ("refused", "none"), ("unknown", "possible")])
@pytest.mark.parametrize("reason", [None, [], "", "x" * 4097], ids=["missing", "list", "empty", "oversize"])
def test_child_refusal_requires_bounded_string_reason(build, state, effect, reason):
    reply = {"state": state, "effect": effect, "native_qualified": False}
    if reason is not None and reason != "x" * 4097:
        reply["reason"] = reason
    large_reason = "v['reason']='x'*4097;" if reason == "x" * 4097 else ""
    program = ("import json,sys;r=json.load(sys.stdin);v=" + repr(reply) + ";"
               + large_reason + "print(json.dumps(dict(r,result=v)))")
    adapter = build(program)
    result = (adapter.observe("work-one", HASH) if effect is None
              else adapter.continue_request("work-one", HASH, "op"))
    assert result["reason"] == "invalid process bridge refusal reason" and result["next_action"]
    assert result["state"] == ("hold" if effect is None else "unknown")


def test_nested_evidence_creation_uses_no_owner_storage(build, tmp_path, owner_plane):
    owner_plane.rmdir()
    adapter = build(evidence_dir=tmp_path / "runs" / "job" / "evidence")
    result = adapter.observe("work-one", HASH)
    assert result["state"] == "eligible"
    assert Path(result["evidence_dir"]).parent == adapter.evidence_dir
    assert all(path.stat().st_mode & 0o777 == 0o700 for path in
               (tmp_path / "runs", tmp_path / "runs" / "job", adapter.evidence_dir))


def test_child_refusal_keeps_diagnostic_separate_from_fixed_reason(build):
    program = ("import json,sys;r=json.load(sys.stdin);print(json.dumps(dict(r,result="
               "{'state':'refused','effect':'none','native_qualified':False,"
               "'reason':chr(27)+'[31mchild detail','next_action':'child advice'})))")
    result = build(program).continue_request("work-one", HASH, "op")
    assert (result["state"], result["effect"]) == ("refused", "none")
    assert result["reason"] == "process bridge child reported refused"
    assert result["child_reason"] == "child detail"
    assert result["next_action"] != "child advice"


@pytest.mark.parametrize("inside", ["anchor", "directory"])
def test_deadline_inside_creation_preserves_reason_and_rolls_back(build, tmp_path, monkeypatch, inside):
    adapter = build().with_control(deadline=1.0, stop_event=None)
    elapsed = Event()

    class ClockStore(bridge.Store):
        @contextmanager
        def directory(self, *args, **kwargs):
            with super().directory(*args, **kwargs) as fd:
                opened = "anchor" if kwargs.get("parent") is None else "directory"
                if inside == opened:
                    elapsed.set()
                yield fd

    monkeypatch.setattr(bridge, "Store", ClockStore)
    monkeypatch.setattr(bridge, "time", SimpleNamespace(monotonic=lambda: 2.0 if elapsed.is_set() else 0.0,
                                                       sleep=time.sleep))
    result = adapter.continue_request("work-one", HASH, "op")
    assert result["reason"] == "process bridge deadline reached"
    assert (result["state"], result["effect"], result["process"]) == ("refused", "none", None)
    assert list(tmp_path.iterdir()) == []
