"""Public disposable broker lifetime; never native identity or job settlement."""
from datetime import datetime, timedelta, timezone
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_fixture_broker.py"


def module():
    assert TOOL.is_file(), "persistent fixture broker public entry point is missing"
    return importlib.import_module("tools.hierarchy_fixture_broker")


def until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("fixture observation deadline reached")


@pytest.fixture
def broker(tmp_path, request):
    candidate = module()
    try:
        candidate.supported()
    except candidate.BrokerError as exc:
        if exc.code != "FIXTURE_UNSUPPORTED_HOST":
            raise
        pytest.skip(str(exc))
    from tests.integration.test_hierarchy_lifecycle import Ledger, request as canonical_request
    ledger = Ledger(tmp_path)
    value = canonical_request("broker-work")
    ledger.publish(value)
    ledger.approve(value)
    # Unix socket path limits are independent of pytest's potentially long
    # isolated evidence directory. This namespace is still test-owned.
    socket_home = tempfile.TemporaryDirectory(prefix="n4-broker-", dir="/tmp")
    directory = Path(socket_home.name).resolve() / "b"
    output = (tmp_path / "broker-output").open("w+b")
    argv = [sys.executable, "-I", "-B", str(TOOL), "serve", "--directory", str(directory),
            "--lifecycle-root", str(ledger.path), "--work-seconds", "1.5",
            "--lifetime-seconds", "12", "--with-descendant"]
    mode = getattr(request, "param", None)
    if mode == "leader-exit-race":
        # Model the real OS/Popen race: the child exits while a signal API is
        # entered, and that API reaps it before returning. Work remains real;
        # neither canonical state nor a positive authorization is substituted.
        wrapper = tmp_path / "signal_boundary.py"
        wrapper.write_text(
            "import sys,subprocess,runpy\n"
            "original=subprocess.Popen.send_signal\n"
            "def signal_boundary(process,number):\n"
            "    process.wait(timeout=4)\n"
            "    return original(process,number)\n"
            "subprocess.Popen.send_signal=signal_boundary\n"
            "sys.argv=sys.argv[1:]\nrunpy.run_path(sys.argv[0],run_name='__main__')\n"
        )
        argv.insert(3, str(wrapper))
    elif mode == "startup-delay":
        # A slow external interpreter start must consume the ORIGINAL deadline,
        # not create a fresh relative work/descendant duration after startup.
        delayed = tmp_path / "delayed_interpreter.py"
        delayed.write_text(
            "import sys,time,runpy\ntime.sleep(3)\n"
            "sys.argv=sys.argv[1:]\nrunpy.run_path(sys.argv[0],run_name='__main__')\n"
        )
        wrapper = tmp_path / "spawn_boundary.py"
        wrapper.write_text(
            "import sys,subprocess,runpy\noriginal=subprocess.Popen\n"
            "def launch(argv,*args,**kwargs):\n"
            "    if len(argv)>4 and argv[4]=='worker':\n"
            "        argv=argv[:3]+[" + repr(str(delayed)) + "]+argv[3:]\n"
            "    return original(argv,*args,**kwargs)\n"
            "subprocess.Popen=launch\nsys.argv=sys.argv[1:]\n"
            "runpy.run_path(sys.argv[0],run_name='__main__')\n"
        )
        argv.insert(3, str(wrapper))
    process = subprocess.Popen(
        argv,
        stdout=output, stderr=output, start_new_session=True,
    )
    try:
        until(lambda: (directory / "ready.json").exists() or process.poll() is not None)
        output.flush()
        assert process.poll() is None, (tmp_path / "broker-output").read_text()
        spec = candidate.descriptor(directory, cwd=tmp_path, evidence_dir=tmp_path / "calls")
        target = {"provider": spec["provider"], "endpoint_id": spec["endpoint_id"],
                  "thread_id": "fixture-thread",
                  "deadline": (datetime.now(timezone.utc) + timedelta(seconds=20)).isoformat().replace("+00:00", "Z")}
        yield candidate, ledger, value, directory, process, spec, target
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            raise AssertionError("owned fixture broker cleanup exceeded deadline")
        output.close()
        # Fixed workers publish this only after their own descendant was waited.
        for started in directory.glob("work-*/started.json"):
            until(lambda: (started.parent / "finished.json").exists(), timeout=4)
        socket_home.cleanup()


def submit(job, spec=None):
    from tools.hierarchy_operator import Operator
    _, ledger, value, _, _, original, target = job
    operator = Operator(ledger.path, spec or original, evidence_only=True)
    result = operator.submit(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, target)
    return operator, result


def observe(operator, ledger, value):
    return operator.observe(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1)


def test_public_fixture_broker_exists():
    assert module() is not None


def test_short_lived_n2_client_exit_preserves_actual_work_and_reconnect(broker):
    _, ledger, value, directory, _, _, _ = broker
    operator, result = submit(broker)
    assert result["provider_state"] == "running", result
    row = ledger.status()["requests"][value["id"]]
    identity = (row["intent"], row["association"])
    starts = until(lambda: list(directory.glob("work-*/started.json")))
    assert len(starts) == 1
    started = json.loads(starts[0].read_text())
    receipts = [json.loads(path.read_text()) for path in Path(broker[5]["evidence_dir"]).glob("*/result.json")]
    assert receipts and all(row["process"]["reaped"] is True for row in receipts)
    assert all(started["pid"] != row["process"]["pid"] for row in receipts)
    assert started["descendant_pid"] != started["pid"]
    from tools.hierarchy_operator import Operator
    reconnected = Operator(ledger.path, broker[5], evidence_only=True)
    again = observe(reconnected, ledger, value)
    assert again["association_sha256"] == result["association_sha256"]
    assert again["provider_handle"] == result["provider_handle"]
    done = until(lambda: (item if (item := observe(reconnected, ledger, value))["state"] == "completed" else None))
    assert done["outcome"] == "passed" and done["exit_code"] == 0
    finished = json.loads((starts[0].parent / "finished.json").read_text())
    assert finished["descendant_reaped"] is True
    final = ledger.status()["requests"][value["id"]]
    assert (final["intent"], final["association"]) == identity
    assert len(list(directory.glob("work-*/started.json"))) == 1
    assert done["native_qualified"] is False


def test_lost_submitting_client_response_keeps_one_actual_attempt(broker, tmp_path):
    _, ledger, value, directory, _, spec, _ = broker
    relay = tmp_path / "lost_reply.py"
    relay.write_text(
        "import sys,json\nsys.path.insert(0, " + repr(str(ROOT / "tools")) + ")\n"
        "from hierarchy_fixture_broker import call\n"
        "raw=sys.stdin.buffer.read()\nresult=call(sys.argv[1],raw)\n"
        "print('lost external transport reply' if json.loads(raw)['method']=='submit' else json.dumps(result))\n"
    )
    changed = {**spec, "argv": [sys.executable, "-I", "-B", str(relay), str(directory)]}
    _, lost = submit(broker, changed)
    assert lost["state"] == "unknown" and lost["effect"] == "possible", lost
    assert len(until(lambda: list(directory.glob("work-*/started.json")))) == 1
    from tools.hierarchy_operator import Operator
    current = Operator(ledger.path, spec, evidence_only=True)
    recovered = observe(current, ledger, value)
    assert recovered["provider_state"] in {"running", "passed"}, recovered
    same = current.submit(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, broker[6])
    assert same["intent_id"] == lost["intent_id"]
    assert len(list(directory.glob("work-*/started.json"))) == 1


def test_current_owner_cancel_reaps_fixed_descendant(broker):
    _, ledger, value, directory, _, _, _ = broker
    operator, result = submit(broker)
    assert result["provider_handle"] is not None, result
    response = operator.cancel(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, "fixture stop")
    assert response["provider_state"] in {"cancel_requested", "cancelled"}, response
    done = until(lambda: (item if (item := observe(operator, ledger, value))["state"] == "completed" else None))
    assert done["provider_state"] == "cancelled" and done["exit_code"] != 0
    finished = json.loads(next(directory.glob("work-*/finished.json")).read_text())
    assert finished["descendant_reaped"] is True
    assert finished["cancelled"] is True


@pytest.mark.parametrize("broker", ["leader-exit-race"], indirect=True)
def test_cancel_preserves_leader_reservation_across_exit_race(broker):
    _, ledger, value, directory, _, _, _ = broker
    operator, result = submit(broker)
    assert result["provider_handle"] is not None, result
    until(lambda: list(directory.glob("work-*/started.json")))
    operator.cancel(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, "owned exit race")
    final = until(lambda: (item if (item := observe(operator, ledger, value))["state"] == "completed" else None), timeout=6)
    assert final["provider_state"] in {"passed", "cancelled"}
    assert json.loads(next(directory.glob("work-*/finished.json")).read_text())["descendant_reaped"] is True


@pytest.mark.parametrize("broker", ["startup-delay"], indirect=True)
def test_original_deadline_is_not_renewed_by_worker_startup(broker):
    _, ledger, _, directory, _, _, _ = broker
    _, result = submit(broker)
    assert result["provider_handle"] is not None, result
    finished_path = until(lambda: next(directory.glob("work-*/finished.json"), None), timeout=8)
    finished = json.loads(finished_path.read_text())
    assert finished["cancelled"] is True, "expired original work deadline was renewed after interpreter startup"
    assert finished["descendant_pid"] is None, "an already-expired worker must not start its descendant"
    assert finished["descendant_reaped"] is True


def test_broker_loss_never_rebinds_or_resubmits_original_association(broker):
    candidate, ledger, value, directory, process, _, _ = broker
    operator, result = submit(broker)
    original = ledger.status()["requests"][value["id"]]
    process.kill()
    process.wait(timeout=3)
    unknown = observe(operator, ledger, value)
    assert unknown["state"] == "unknown" and unknown["effect"] == "possible"
    assert unknown["association_sha256"] == result["association_sha256"]
    replay = operator.submit(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, broker[6])
    assert replay["intent_id"] == result["intent_id"]
    assert len(list(directory.glob("work-*/started.json"))) == 1
    row = ledger.status()["requests"][value["id"]]
    assert row["intent"] == original["intent"] and row["association"] == original["association"]
    with pytest.raises(candidate.BrokerError, match="^FIXTURE_ENDPOINT_REUSED$"):
        candidate.serve(directory, ledger.path, work_seconds=1, lifetime_seconds=2)


@pytest.mark.parametrize("raw,code", [
    (b'{}', "FIXTURE_FRAME_INVALID"),
    (b'{"schema":1,"schema":2}\n', "FIXTURE_FRAME_INVALID"),
    (b'NaN\n', "FIXTURE_FRAME_INVALID"),
    (b'\xff\n', "FIXTURE_FRAME_INVALID"),
    (b'{}\n{}\n', "FIXTURE_FRAME_INVALID"),
    (b'x' * (768 * 1024 + 1), "FIXTURE_FRAME_TOO_LARGE"),
], ids=["empty-object", "duplicate-key", "nan", "invalid-utf8", "multiple-frames", "oversized"])
def test_invalid_public_client_frame_refuses_before_endpoint_access(tmp_path, raw, code):
    candidate = module()
    with pytest.raises(candidate.BrokerError, match="^" + code + "$"):
        candidate.call(tmp_path / "missing", raw)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("seconds", [True, 0, -1, float("inf"), 31])
def test_invalid_duration_refuses_before_creating_endpoint(tmp_path, seconds):
    candidate = module()
    with pytest.raises(candidate.BrokerError, match="^FIXTURE_INVALID_CONFIG$"):
        candidate.serve(tmp_path / "new", tmp_path / "missing", work_seconds=seconds, lifetime_seconds=2)
    assert list(tmp_path.iterdir()) == []


def test_missing_endpoint_has_exact_public_error_and_no_files(tmp_path):
    candidate = module()
    with pytest.raises(candidate.BrokerError, match="^FIXTURE_ENDPOINT_UNAVAILABLE$"):
        candidate.descriptor(tmp_path / "missing", cwd=tmp_path, evidence_dir=tmp_path / "calls")
    assert list(tmp_path.iterdir()) == []


def test_symlink_ready_file_has_closed_public_error_without_reading_target(tmp_path):
    candidate = module()
    directory = tmp_path / "endpoint"
    directory.mkdir()
    target = tmp_path / "foreign.json"
    target.write_bytes(b'{"untrusted":"fixture target"}\n')
    (directory / "ready.json").symlink_to(target)
    before = target.read_bytes()
    with pytest.raises(candidate.BrokerError, match="^FIXTURE_INVALID_CONFIG$"):
        candidate.descriptor(directory, cwd=tmp_path, evidence_dir=tmp_path / "calls")
    assert target.read_bytes() == before
    assert not (tmp_path / "calls").exists()


def test_unsupported_host_refuses_explicitly_without_endpoint(tmp_path, monkeypatch):
    candidate = module()
    monkeypatch.delattr(os, "waitid", raising=False)
    with pytest.raises(candidate.BrokerError, match="^fixture broker requires POSIX waitid WNOWAIT$") as error:
        candidate.serve(tmp_path / "new", tmp_path / "missing", work_seconds=1, lifetime_seconds=2)
    assert error.value.code == "FIXTURE_UNSUPPORTED_HOST"
    assert list(tmp_path.iterdir()) == []


HOST_CAPABILITIES = ("name", "AF_UNIX", "waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")


def missing_host_capability(candidate, missing, monkeypatch):
    """Substitute only the external OS capability surface, never authorization."""
    name = "socket" if missing == "AF_UNIX" else "os"
    values = vars(getattr(candidate, name)).copy()
    if missing == "name":
        values["name"] = "unsupported"
    else:
        values.pop(missing, None)
    monkeypatch.setattr(candidate, name, SimpleNamespace(**values))


@pytest.mark.parametrize("missing", HOST_CAPABILITIES)
def test_positive_fixture_skips_missing_host_capability_before_ledger(tmp_path, missing):
    # The child collector must stay inside its owned probe directory, even
    # when an ancestor has pytest configuration or a Windows junction alias.
    (tmp_path / "conftest.py").write_text("raise RuntimeError('child pytest loaded an ancestor conftest')\n")
    directory = tmp_path / "probe"
    directory.mkdir()
    probe = directory / "test_capability_probe.py"
    probe.write_text(
        "import pytest\n"
        "from tests.integration.test_hierarchy_fixture_broker import module, missing_host_capability\n"
        "pytest_plugins = ['tests.integration.test_hierarchy_fixture_broker']\n"
        "@pytest.fixture(autouse=True)\n"
        "def unsupported(monkeypatch):\n"
        "    missing_host_capability(module(), " + repr(missing) + ", monkeypatch)\n"
        "def test_positive(broker):\n"
        "    pass\n"
    )
    fixtures = tmp_path / "fixtures"
    report = tmp_path / "capability-report.xml"
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-ra", "-p", "no:cacheprovider",
         "--confcutdir", str(directory), "--basetemp", str(fixtures), "--junitxml", str(report),
         str(probe) + "::test_positive"], cwd=ROOT,
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Prove that exactly one target was collected and skipped for the required
    # host capability, without accepting duplicate alias or teardown reports.
    cases = ET.parse(report).getroot().findall(".//testcase")
    evidence = report.read_text(encoding="utf-8") + result.stdout + result.stderr
    assert len(cases) == 1 and cases[0].get("name") == "test_positive", evidence
    skipped = cases[0].findall("skipped")
    assert len(skipped) == 1, evidence
    assert skipped[0].get("type") == "pytest.skip", evidence
    assert skipped[0].get("message") == "fixture broker requires POSIX waitid WNOWAIT", evidence
    assert cases[0].find("failure") is None and cases[0].find("error") is None, evidence
    assert not list(fixtures.rglob("policy.json")), "unsupported fixture created a canonical ledger"
    assert not list(fixtures.rglob("broker-output")), "unsupported fixture launched its broker"


@pytest.mark.parametrize("missing", [None, *HOST_CAPABILITIES])
def test_public_unsupported_serve_and_cli_preserve_inputs(tmp_path, monkeypatch, missing):
    candidate = module()
    if missing is None:
        try:
            candidate.supported()
        except candidate.BrokerError as exc:
            assert exc.code == "FIXTURE_UNSUPPORTED_HOST"
        else:
            pytest.skip("actual host supports the disposable broker; negative OS cases run separately")
    else:
        missing_host_capability(candidate, missing, monkeypatch)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    sentinel = inputs / "untouched.json"
    sentinel.write_bytes(b'{"foreign":"unchanged"}\n')
    before = sentinel.read_bytes()
    with pytest.raises(candidate.BrokerError, match="^fixture broker requires POSIX waitid WNOWAIT$") as error:
        candidate.serve(tmp_path / "endpoint", inputs, work_seconds=1, lifetime_seconds=2)
    assert error.value.code == "FIXTURE_UNSUPPORTED_HOST"
    argv = ["serve", "--directory", str(tmp_path / "endpoint"), "--lifecycle-root", str(inputs),
            "--work-seconds", "1", "--lifetime-seconds", "2"]
    if missing is None:
        command = [sys.executable, "-I", "-B", str(TOOL), *argv]
    else:
        command = [sys.executable, "-I", "-B", "-c",
                   "import sys; sys.path.insert(0, sys.argv[1]); from types import SimpleNamespace; "
                   "from tools import hierarchy_fixture_broker as candidate; "
                   "missing=sys.argv[2]; name='socket' if missing=='AF_UNIX' else 'os'; "
                   "values=vars(getattr(candidate,name)).copy(); "
                   "values.update(name='unsupported') if missing=='name' else values.pop(missing,None); "
                   "setattr(candidate,name,SimpleNamespace(**values)); "
                   "sys.exit(candidate.main(sys.argv[3:]))", str(ROOT), missing, *argv]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "fixture broker requires POSIX waitid WNOWAIT\n"
    assert sentinel.read_bytes() == before
    assert list(inputs.iterdir()) == [sentinel]
    assert list(tmp_path.iterdir()) == [inputs]
