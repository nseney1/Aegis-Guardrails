"""Root runs an orchestrator's job request through a fixed recipe and answers it with a receipt.

Jobs here are real processes and the sandbox tests run real bubblewrap when it works on this machine.
No host session is involved, so these tests say nothing about how a model behaves.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke
from tests.integration.test_hierarchy_provision import INITIATIVE, LANES, Setup, provision
from tests.integration.test_hierarchy_workspace import write_lease


JOBS = ROOT / "tools" / "hierarchy_jobs.py"
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the job runner reads /proc")
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
EMPTY = hashlib.sha256(b"").hexdigest()


def bubblewrap_works():
    if shutil.which("bwrap") is None:
        return False
    probe = subprocess.run(["bwrap", "--unshare-net", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"],
                           capture_output=True, timeout=10)
    return probe.returncode == 0


needs_bubblewrap = pytest.mark.skipif(not sys.platform.startswith("linux") or not bubblewrap_works(),
                                      reason="bubblewrap does not run here")


class Shop(Setup):
    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.init()
        self.orchestrator = self.add_role("pilot/orchestrator", cwd=str(tmp_path))
        self.add_role("pilot/root", "codex-cli", session="root-session")
        self.checkout = self.make_checkout("checkout")
        self.workspace.run("update", {"initiative": "pilot", "source": "owner", "checkouts": [str(self.checkout)]})
        self.sentinel = tmp_path / "recipe-ran"
        self.recipes_path = tmp_path / "recipes.json"
        python = "$python"
        touch = "open(%r, 'a').write('ran\\n')" % str(self.sentinel)
        self.recipes = {
            "schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable, "path": ["/usr/bin", "/bin"],
            "identity": {"name": "Hierarchy Root", "email": "root@example.invalid"}, "recipes": {
                "ok": self.command([python, "-c", "print('job output')"]),
                "touch": self.command([python, "-c", touch]),
                "with-paths": self.command([python, "-c", "import sys; print(sys.argv[1:]); " + touch, "$paths"]),
                "fail": self.command([python, "-c", "import sys; print('bad output'); sys.exit(7)"]),
                "heavy": self.command([python, "-c", "print('heavy output')"], heavy=True),
                "two-steps": {"kind": "command", "heavy": False, "sandbox": "none", "timeout_seconds": 30, "steps": [
                    [python, "-c", "print('first')"], [python, "-c", "import sys; sys.exit(9)"],
                    [python, "-c", touch]]},
                "commit": {"kind": "commit", "sandbox": "none", "timeout_seconds": 30}}}
        self.save_recipes()

    @staticmethod
    def command(argv, *, heavy=False, sandbox="none", timeout_seconds=30, **extra):
        return {"kind": "command", "heavy": heavy, "sandbox": sandbox, "timeout_seconds": timeout_seconds,
                "steps": [argv], **extra}

    def save_recipes(self):
        self.recipes_path.write_text(json.dumps(self.recipes), encoding="utf-8")

    def make_checkout(self, name):
        checkout = self.tmp / name
        (checkout / "src").mkdir(parents=True)
        (checkout / "tests").mkdir()
        git(checkout, "init", "-q", "-b", "feature/x")
        (checkout / "src" / "app.py").write_text("value = 1\n")
        (checkout / "tests" / "test_app.py").write_text("def test_app():\n    pass\n")
        git(checkout, "add", ".")
        git(checkout, "commit", "-qm", "base")
        return checkout

    def head(self, checkout=None):
        checkout = checkout or self.checkout
        return {"checkout": str(checkout), "commit": git(checkout, "rev-parse", "HEAD"),
                "tree": git(checkout, "rev-parse", "HEAD^{tree}")}

    def publish(self, identifier, kind, body, *, root=None, sender="pilot/orchestrator", to="pilot/root", **extra):
        root = root or self.root
        binding = invoke(root, "status")["bindings"][sender]
        return invoke(root, "publish", {"message_id": identifier, "from": sender, "to": to, "host": binding["host"],
                                        "session": binding["session"], "binding_generation": binding["generation"],
                                        "type": kind, "body": body, **extra})

    def request_job(self, identifier, recipe, *, raw=None, root=None, prefix="pilot", checkout=None, body="Please run it.",
                    **changes):
        packet = {"schema": PACKET_SCHEMA, "recipe": recipe, **self.head(checkout), **changes}
        packet = {key: value for key, value in packet.items() if value is not None}
        text = raw if raw is not None else json.dumps(packet)
        held = self.publish(identifier + "-packet", "info", text, root=root, sender=prefix + "/orchestrator", to=prefix + "/root")
        return self.publish(identifier, "job_request", body, root=root, sender=prefix + "/orchestrator", to=prefix + "/root",
                            brief={"path": held["path"], "sha256": held["sha256"]})

    def argv(self, command, *flags, census=None, lock_wait=None):
        argv = [sys.executable, "-I", str(JOBS), "--store", str(self.workspace.store), "--recipes", str(self.recipes_path)]
        if census is not None:
            fixture = self.tmp / ("census-%d.json" % time.monotonic_ns())
            fixture.write_text(json.dumps(census))
            argv += ["--census-fixture", str(fixture)]
        if lock_wait is not None:
            argv += ["--lock-wait", str(lock_wait)]
        return argv + [command, *flags]

    def env(self):
        return {"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1", "SECRET_TOKEN": "must-not-reach-a-job"}

    def jobs(self, command, *flags, expect=0, census=(), lock_wait=None, env=None, timeout=90):
        result = subprocess.run(self.argv(command, *flags, census=None if census is None else list(census), lock_wait=lock_wait),
                                capture_output=True, text=True, timeout=timeout, env=env or self.env())
        assert not result.stderr, result.stderr
        assert result.returncode == expect, result.stdout
        return json.loads(result.stdout)

    def run_open(self, *flags, **options):
        return self.jobs("run-open", *flags, **options)

    def headers(self, folder=("pilot", "orchestrator"), root=None):
        rows = []
        for path in sorted((root or self.root).joinpath(*folder).glob("*.md")):
            header, body = path.read_text(encoding="utf-8")[4:].split("\n---\n\n", 1)
            rows.append({**json.loads(header), "body": body})
        return rows

    def receipts(self, identifier, root=None, prefix="pilot"):
        return [row for row in self.headers((prefix, "orchestrator"), root)
                if row["type"] == "job_receipt" and row["in_reply_to"] == identifier]

    def states(self, identifier, **options):
        return [row["receipt"]["state"] for row in self.receipts(identifier, **options)]

    def open_jobs(self, root=None):
        return [row["message_id"] for row in invoke(root or self.root, "status")["open_job_requests"]]

    def events(self):
        return [json.loads(path.read_text()) for path in sorted((self.workspace.store / "events").iterdir())]

    def heavy(self):
        return self.workspace.run("status")["capacity"]["heavy"]


@pytest.fixture
def shop(tmp_path):
    return Shop(tmp_path)


def verified_evidence(receipt):
    """Every reference must point at the bytes it names, or the receipt proves nothing."""
    for item in receipt["receipt"]["evidence"]:
        assert hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() == item["sha256"]
    return {Path(item["path"]).name: Path(item["path"]) for item in receipt["receipt"]["evidence"]}


def test_a_requested_job_runs_and_is_answered_with_evidence(shop):
    shop.request_job("job-1", "ok")
    result = shop.run_open()
    assert [(row["job"], row["state"]) for row in result["rows"]] == [("pilot/job-1", "completed")]
    assert shop.states("job-1") == ["started", "completed"]
    final = shop.receipts("job-1")[-1]
    assert final["from"] == "pilot/root" and final["authority"] == "information_only"
    assert final["receipt"]["exit_code"] == 0 and "job output" in final["body"]
    evidence = verified_evidence(final)
    recorded = json.loads(evidence["result.json"].read_text())
    assert recorded["recipe"] == "ok" and recorded["state"] == "completed"
    assert recorded["before"] == recorded["after"]
    assert recorded["before"]["source_revision"] == shop.head()["commit"]
    assert "job output" in evidence["step-1.log"].read_text()
    assert shop.open_jobs() == []


def test_a_job_is_not_run_twice(shop):
    shop.request_job("job-1", "touch")
    shop.run_open()
    assert shop.run_open()["rows"] == []
    assert shop.sentinel.read_text() == "ran\n"
    assert shop.states("job-1") == ["started", "completed"]


def test_a_failing_job_reports_its_exit_code_and_keeps_its_output(shop):
    shop.request_job("job-1", "fail")
    result = shop.run_open()
    assert result["rows"][0]["state"] == "failed"
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == "failed" and final["receipt"]["exit_code"] == 7
    assert "bad output" in verified_evidence(final)["step-1.log"].read_text() and "bad output" in final["body"]
    assert shop.open_jobs() == []


def test_steps_stop_at_the_first_failure(shop):
    shop.request_job("job-1", "two-steps")
    shop.run_open()
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["exit_code"] == 9
    assert not shop.sentinel.exists()
    assert [step["exit_code"] for step in json.loads(verified_evidence(final)["result.json"].read_text())["steps"]] == [0, 9]


def test_a_plain_markdown_packet_works_as_well_as_a_message_file(shop):
    packet = shop.base / "packet.md"
    raw = json.dumps({"schema": PACKET_SCHEMA, "recipe": "ok", **shop.head()}).encode()
    packet.write_bytes(raw)
    shop.publish("job-1", "job_request", "Run.", brief={"path": str(packet), "sha256": hashlib.sha256(raw).hexdigest()})
    assert shop.run_open()["rows"][0]["state"] == "completed"


def test_the_message_body_is_never_acted_on(shop):
    shop.request_job("job-1", "ok", body=json.dumps({"recipe": "touch"}) + "\n$(touch %s); touch %s" % (shop.sentinel, shop.sentinel))
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert not shop.sentinel.exists()


@pytest.mark.parametrize("recipe, changes, reason", [
    ("does-not-exist", {}, "unknown recipe"),
    ("with-paths", {"paths": ["src/app.py"], "commit": "0" * 40}, "source does not match"),
    ("with-paths", {"paths": ["src/app.py"], "tree": "0" * 40}, "source does not match"),
    ("with-paths", {"paths": ["src/app.py"], "dirty_state_sha256": "0" * 64}, "source does not match"),
    ("with-paths", {"paths": ["--rootdir=/etc"]}, "invalid path"),
    ("with-paths", {"paths": ["-x"]}, "invalid path"),
    ("with-paths", {"paths": ["../outside.py"]}, "invalid path"),
    ("with-paths", {"paths": ["src/../../outside.py"]}, "invalid path"),
    ("with-paths", {"paths": ["/etc/passwd"]}, "invalid path"),
    ("with-paths", {"paths": ["src/*.py"]}, "invalid path"),
    ("with-paths", {"paths": ["src/missing.py"]}, "path does not exist"),
    ("with-paths", {"paths": []}, "needs paths"),
    ("with-paths", {}, "needs paths"),
    ("touch", {"paths": ["src/app.py"]}, "takes no paths"),
    ("touch", {"expected_tree": "0" * 40}, "only a commit recipe"),
    ("touch", {"message": "Not a commit."}, "only a commit recipe"),
    ("touch", {"argv": ["sh", "-c", "touch x"]}, "unexpected"),
    ("touch", {"schema": "something/else"}, "packet schema"),
    ("touch", {"commit": "not-an-id"}, "commit"),
])
def test_a_bad_packet_is_refused_with_a_reason_and_nothing_runs(shop, recipe, changes, reason):
    shop.request_job("job-1", recipe, **changes)
    result = shop.run_open()
    assert result["rows"][0]["state"] == "refused", result
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == "refused" and reason in final["receipt"]["reason"], final
    assert shop.states("job-1") == ["refused"]
    assert not shop.sentinel.exists()
    assert shop.open_jobs() == []


def test_a_packet_that_is_not_json_is_refused(shop):
    shop.request_job("job-1", "touch", raw="Please just run whatever you think is best.")
    shop.run_open()
    assert shop.states("job-1") == ["refused"]
    assert not shop.sentinel.exists()


def test_a_checkout_the_initiative_never_registered_is_refused(shop):
    elsewhere = shop.make_checkout("elsewhere")
    shop.request_job("job-1", "touch", checkout=elsewhere)
    shop.run_open()
    assert "checkout is not registered" in shop.receipts("job-1")[-1]["receipt"]["reason"]
    assert not shop.sentinel.exists()


def test_uncommitted_changes_refuse_a_request_that_named_a_clean_checkout(shop):
    shop.request_job("job-1", "touch")
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    shop.run_open()
    assert "source does not match" in shop.receipts("job-1")[-1]["receipt"]["reason"]
    assert not shop.sentinel.exists()


def test_a_request_can_name_an_exact_dirty_state(shop):
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    status = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=shop.checkout,
                            capture_output=True, check=True, timeout=10).stdout
    shop.request_job("job-1", "touch", dirty_state_sha256=hashlib.sha256(status).hexdigest())
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert shop.sentinel.exists()


def test_a_changed_packet_file_is_refused(shop):
    packet = shop.base / "packet.md"
    raw = json.dumps({"schema": PACKET_SCHEMA, "recipe": "touch", **shop.head()}).encode()
    packet.write_bytes(raw)
    shop.publish("job-1", "job_request", "Run.", brief={"path": str(packet), "sha256": hashlib.sha256(raw).hexdigest()})
    packet.write_bytes(raw + b" ")
    shop.run_open()
    assert shop.states("job-1") == ["refused"]
    assert "sha256" in shop.receipts("job-1")[-1]["receipt"]["reason"]
    assert not shop.sentinel.exists()


def test_paths_arrive_as_separate_arguments_and_cannot_add_options(shop):
    shop.request_job("job-1", "with-paths", paths=["src/app.py", "tests/test_app.py::test_app"])
    shop.run_open()
    output = verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()
    assert "['src/app.py', 'tests/test_app.py::test_app']" in output


def test_a_job_sees_only_the_fixed_environment(shop):
    shop.recipes["recipes"]["probe"] = shop.command(["$python", "-c", "import json, os; print(json.dumps(dict(os.environ)))"])
    shop.recipes["env"] = {"PYTHONPATH": "$checkout", "CUSTOM": "fixed"}
    shop.save_recipes()
    shop.request_job("job-1", "probe")
    shop.run_open()
    log = verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()
    seen = json.loads(log.strip().splitlines()[-1])
    assert "SECRET_TOKEN" not in seen
    assert seen["PATH"] == "/usr/bin:/bin"
    assert seen["PYTHONPATH"] == str(shop.checkout) and seen["CUSTOM"] == "fixed"
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
    for name in ("HOME", "USERPROFILE", "TMPDIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME", "CARGO_HOME", "CARGO_TARGET_DIR"):
        assert seen[name].startswith(str(folder)), name


def spawn_fake_heavy(tmp_path, name):
    """A process called pytest whose parent is gone, so the census sees it as an outside job."""
    fake = tmp_path / name
    fake.write_text("#!%s\nimport time\ntime.sleep(60)\n" % sys.executable)
    fake.chmod(0o700)
    launcher = subprocess.run(["sh", "-c", "%s >/dev/null 2>&1 </dev/null & echo $!" % fake],
                              capture_output=True, text=True, timeout=5)
    return int(launcher.stdout.strip())


def finished(pid, seconds=5):
    """Gone, or a zombie waiting for init: either way it cannot do anything more."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if Path("/proc/%d/stat" % pid).read_text().rpartition(")")[2].split()[0] == "Z":
                return True
        except (FileNotFoundError, ProcessLookupError):
            return True
        time.sleep(0.02)
    return False


def test_a_heavy_job_holds_a_ledger_slot_and_frees_it_with_evidence(shop):
    shop.request_job("job-1", "heavy")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    capacity = [event for event in shop.events() if event["kind"] in ("request", "grant", "release")]
    assert [event["kind"] for event in capacity] == ["request", "grant", "release"]
    assert capacity[0]["data"]["holder"] == "job:pilot/job-1"
    evidence = capacity[2]["data"]["evidence"]
    assert hashlib.sha256(Path(evidence["path"]).read_bytes()).hexdigest() == evidence["sha256"]
    assert shop.heavy()["used"] == 0


def test_outside_heavy_work_counts_against_the_limit_and_the_job_waits(shop):
    shop.request_job("job-1", "heavy")
    result = shop.run_open(census=[101, 102, 103], expect=3)
    row = result["rows"][0]
    assert row["state"] == "waiting" and row["reason"] == "capacity_full"
    assert row["capacity"] == {"limit": 3, "held": 0, "external_roots": [101, 102, 103], "census": "fixture"}
    assert shop.receipts("job-1") == [] and shop.open_jobs() == ["job-1"]
    shop.run_open(census=[101, 102, 103], expect=3)
    assert sum(event["kind"] == "request" for event in shop.events()) == 1, "a waiting job must not queue twice"
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert shop.states("job-1") == ["started", "completed"]


def test_a_full_ledger_makes_the_job_wait(shop):
    for number in range(3):
        shop.workspace.run("request", {"initiative": "pilot", "kind": "heavy", "holder": "other-%d" % number})
        shop.workspace.run("grant-next", kind="heavy")
    shop.request_job("job-1", "heavy")
    result = shop.run_open(expect=3)
    assert result["rows"][0]["state"] == "waiting"
    assert result["rows"][0]["capacity"]["held"] == 3
    assert shop.receipts("job-1") == []


def test_the_real_census_finds_outside_heavy_processes(shop, tmp_path):
    pids = [spawn_fake_heavy(tmp_path, "pytest") for _ in range(3)]
    try:
        shop.request_job("job-1", "heavy")
        row = shop.run_open(census=None, expect=3)["rows"][0]
        assert row["state"] == "waiting"
        assert set(pids) <= set(row["capacity"]["external_roots"])
        assert row["capacity"]["census"] == "proc"
    finally:
        for pid in pids:
            os.kill(pid, signal.SIGKILL)


def add_initiative(shop, identifier, priority):
    base = shop.tmp / "initiatives" / identifier
    checkout = shop.make_checkout(identifier + "-checkout")
    provision("init", shop.request(store=str(shop.workspace.store), base=str(base), source=str(shop.source), lanes=LANES,
                                   initiative={**INITIATIVE, "id": identifier, "priority": priority, "project": identifier,
                                               "repository": identifier, "checkouts": [str(checkout)]}))
    provision("add-role", shop.request(base=str(base), endpoint=identifier + "/orchestrator", host="claude-code", cwd=str(shop.tmp)))
    provision("add-role", shop.request(base=str(base), endpoint=identifier + "/root", host="codex-cli", session="root-session"))
    return base / "mailbox", checkout


def test_heavy_jobs_run_in_the_owners_priority_order(shop):
    other, checkout = add_initiative(shop, "urgent", 1)
    shop.request_job("job-low", "heavy")
    shop.request_job("job-high", "heavy", root=other, prefix="urgent", checkout=checkout)
    result = shop.run_open("--max-jobs", "1", expect=3)
    states = {row["job"]: row["state"] for row in result["rows"]}
    assert states == {"urgent/job-high": "completed", "pilot/job-low": "waiting"}
    assert shop.run_open()["rows"][0]["job"] == "pilot/job-low"


def test_a_paused_initiative_runs_nothing(shop):
    shop.request_job("job-1", "touch")
    shop.workspace.run("update", {"initiative": "pilot", "source": "owner", "state": "paused"})
    assert shop.run_open()["rows"] == []
    assert not shop.sentinel.exists() and shop.open_jobs() == ["job-1"]


def test_only_a_chosen_initiative_runs(shop):
    other, checkout = add_initiative(shop, "urgent", 1)
    shop.request_job("job-1", "touch")
    shop.request_job("job-2", "ok", root=other, prefix="urgent", checkout=checkout)
    assert [row["job"] for row in shop.run_open("--initiative", "urgent")["rows"]] == ["urgent/job-2"]
    assert not shop.sentinel.exists()


def test_a_job_past_its_timeout_is_stopped_with_its_children(shop, tmp_path):
    pid_file = tmp_path / "child-pid"
    script = ("import subprocess, sys, time; child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
              "open(%r, 'w').write(str(child.pid)); print('started', flush=True); time.sleep(60)" % str(pid_file))
    shop.recipes["recipes"]["slow"] = shop.command(["$python", "-c", script], timeout_seconds=2)
    shop.save_recipes()
    shop.request_job("job-1", "slow")
    began = time.monotonic()
    assert shop.run_open()["rows"][0]["state"] == "failed"
    assert time.monotonic() - began < 30
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["exit_code"] != 0 and "timed out" in final["receipt"]["reason"]
    assert json.loads(verified_evidence(final)["result.json"].read_text())["steps"][0]["timed_out"] is True
    assert finished(int(pid_file.read_text()))


def test_a_process_left_behind_is_stopped_and_recorded(shop, tmp_path):
    pid_file = tmp_path / "left-behind"
    script = ("import subprocess, sys; child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
              "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); open(%r, 'w').write(str(child.pid))" % str(pid_file))
    shop.recipes["recipes"]["leaves"] = shop.command(["$python", "-c", script])
    shop.save_recipes()
    shop.request_job("job-1", "leaves")
    shop.run_open()
    final = shop.receipts("job-1")[-1]
    recorded = json.loads(verified_evidence(final)["result.json"].read_text())
    assert recorded["steps"][0]["stopped_leftovers"] is True
    assert "left processes running" in final["body"]
    assert finished(int(pid_file.read_text()))


def test_source_that_changes_during_a_job_fails_it_even_with_a_clean_exit(shop):
    target = shop.checkout / "src" / "app.py"
    shop.recipes["recipes"]["edits"] = shop.command(["$python", "-c", "open(%r, 'a').write('# changed\\n')" % str(target)])
    shop.save_recipes()
    shop.request_job("job-1", "edits")
    assert shop.run_open()["rows"][0]["state"] == "failed"
    final = shop.receipts("job-1")[-1]
    assert "source changed during the job" in final["receipt"]["reason"]
    recorded = json.loads(verified_evidence(final)["result.json"].read_text())
    assert recorded["steps"][0]["exit_code"] == 0
    assert recorded["before"]["dirty_state_sha256"] != recorded["after"]["dirty_state_sha256"]


def wait_for(path, seconds=10):
    deadline = time.monotonic() + seconds
    while not path.exists():
        assert time.monotonic() < deadline, "timed out waiting for " + str(path)
        time.sleep(0.02)


def start_stuck_job(shop, tmp_path):
    ready = tmp_path / "job-is-running"
    script = "import time; open(%r, 'w').close(); time.sleep(60)" % str(ready)
    shop.recipes["recipes"]["stuck"] = shop.command(["$python", "-c", script], heavy=True)
    shop.save_recipes()
    shop.request_job("job-1", "stuck")
    runner = subprocess.Popen(shop.argv("run-open", census=[]), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=shop.env(), start_new_session=True)
    wait_for(ready)
    deadline = time.monotonic() + 10
    while shop.states("job-1") != ["started"]:
        assert time.monotonic() < deadline, "the started receipt never appeared"
        time.sleep(0.02)
    return runner


def test_a_running_job_is_reported_and_not_started_again(shop, tmp_path):
    runner = start_stuck_job(shop, tmp_path)
    group = None
    try:
        row = shop.run_open(expect=3)["rows"][0]
        group = row["process_group"]
        assert row["state"] == "running"
        assert shop.states("job-1") == ["started"]
    finally:
        os.killpg(runner.pid, signal.SIGKILL)
        runner.communicate()
        if group:
            os.killpg(group, signal.SIGKILL)


def test_a_runner_that_dies_leaves_a_clear_unknown_and_keeps_the_slot_until_root_resolves_it(shop, tmp_path):
    runner = start_stuck_job(shop, tmp_path)
    os.killpg(runner.pid, signal.SIGKILL)
    runner.communicate()
    row = shop.run_open(expect=3)["rows"][0]
    assert row["state"] == "abandoned" and row["process_alive"] is True
    assert shop.states("job-1") == ["started", "unknown"]
    assert shop.heavy()["used"] == 1, "a lost process must not free its slot"
    assert shop.open_jobs() == ["job-1"]
    shop.run_open(expect=3)
    assert shop.states("job-1") == ["started", "unknown"], "reporting again must not repeat the receipt"

    refused = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "Stopped by hand.", expect=2)
    assert "still running" in refused["error"]
    os.killpg(row["process_group"], signal.SIGKILL)
    deadline = time.monotonic() + 5
    while shop.run_open(expect=3)["rows"][0]["process_alive"]:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    resolved = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.")
    assert resolved["state"] == "failed"
    assert shop.states("job-1") == ["started", "unknown", "failed"]
    final = shop.receipts("job-1")[-1]
    assert "The runner crashed." in final["receipt"]["reason"] and verified_evidence(final)
    assert shop.heavy()["used"] == 0 and shop.open_jobs() == []
    assert shop.run_open()["rows"] == []


def test_resolve_refuses_a_job_with_no_claim_or_one_already_finished(shop):
    assert "no running job" in shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "x", expect=2)["error"]
    shop.request_job("job-1", "ok")
    assert "no running job" in shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "x", expect=2)["error"]
    shop.run_open()
    assert "already finished" in shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "x", expect=2)["error"]
    assert "invalid job" in shop.jobs("resolve", "--job", "../../etc", "--reason", "x", expect=2)["error"]


def test_a_receipt_blocked_by_a_busy_mailbox_is_published_later_exactly_once(shop):
    lock = shop.root / ".write.lock"
    # Waits for the started receipt first, so only the final receipt meets the busy mailbox.
    published = str(shop.root / "pilot" / "orchestrator" / "*-root-to-orchestrator-*.md")
    script = ("import glob, time\nfor _ in range(1000):\n    if glob.glob(%r):\n        break\n    time.sleep(0.01)\n"
              "open(%r, 'x').close()" % (published, str(lock)))
    shop.recipes["recipes"]["locks"] = shop.command(["$python", "-c", script], heavy=True)
    shop.save_recipes()
    shop.request_job("job-1", "locks")
    row = shop.run_open(lock_wait=0.2, expect=3)["rows"][0]
    assert row["state"] == "settle_pending" and "busy" in row["error"]
    assert shop.states("job-1") == ["started"]
    assert shop.heavy()["used"] == 1, "the slot stays held until the receipt is out"
    lock.unlink()
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert shop.states("job-1") == ["started", "completed"]
    assert shop.heavy()["used"] == 0
    assert shop.run_open()["rows"] == []


def test_a_slot_blocked_by_a_busy_store_is_released_later(shop):
    """The receipt is already out by then, so the request is closed and only the ledger still remembers the job."""
    lock = shop.workspace.store / ".write.lock"
    published = str(shop.root / "pilot" / "orchestrator" / "*-root-to-orchestrator-*.md")
    script = ("import glob, time\nfor _ in range(1000):\n    if glob.glob(%r):\n        break\n    time.sleep(0.01)\n"
              "open(%r, 'x').close()" % (published, str(lock)))
    shop.recipes["recipes"]["locks"] = shop.command(["$python", "-c", script], heavy=True)
    shop.save_recipes()
    shop.request_job("job-1", "locks")
    row = shop.run_open(lock_wait=0.2, expect=3)["rows"][0]
    assert row["state"] == "settle_pending" and "busy" in row["error"]
    assert shop.states("job-1") == ["started", "completed"] and shop.open_jobs() == []
    assert shop.heavy()["used"] == 1
    lock.unlink()
    assert [row["state"] for row in shop.run_open()["rows"]] == ["completed"]
    assert shop.heavy()["used"] == 0
    assert shop.states("job-1") == ["started", "completed"]
    assert shop.run_open()["rows"] == []


def commit_request(shop, **changes):
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    (shop.checkout / "src" / "other.py").write_text("not part of this commit\n")
    (shop.checkout / "tests" / "test_app.py").write_text("def test_app():\n    assert True\n")
    status = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=shop.checkout,
                            capture_output=True, check=True, timeout=10).stdout
    # The expected tree comes from a throwaway index, which is how a lane computes it.
    index = shop.tmp / ("lane-index-%d" % time.monotonic_ns())
    env = {**os.environ, "GIT_INDEX_FILE": str(index)}
    run = lambda *args: subprocess.run(["git", *args], cwd=shop.checkout, env=env, capture_output=True, text=True,  # noqa: E731
                                       check=True, timeout=10).stdout.strip()
    run("read-tree", "HEAD")
    run("add", "--", "src/app.py", "tests/test_app.py")
    tree = run("write-tree")
    packet = {"paths": ["src/app.py", "tests/test_app.py"], "expected_tree": tree, "message": "fix: raise value\n\nExact text; $(not run).\n",
              "dirty_state_sha256": hashlib.sha256(status).hexdigest(), **changes}
    shop.request_job("job-1", "commit", **packet)
    return tree


def test_a_commit_job_commits_exactly_the_named_paths(shop):
    before = shop.head()["commit"]
    tree = commit_request(shop)
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
    assert git(shop.checkout, "rev-parse", "HEAD^") == before
    assert git(shop.checkout, "log", "-1", "--format=%B") == "fix: raise value\n\nExact text; $(not run)."
    assert git(shop.checkout, "log", "-1", "--format=%an <%ae>") == "Hierarchy Root <root@example.invalid>"
    assert git(shop.checkout, "log", "-1", "--format=%G?") == "N"
    assert sorted(git(shop.checkout, "show", "--name-only", "--format=", "HEAD").splitlines()) == ["src/app.py", "tests/test_app.py"]
    assert git(shop.checkout, "status", "--porcelain=v1", "--untracked-files=all") == "?? src/other.py", "the real index must match the new commit"
    final = shop.receipts("job-1")[-1]
    recorded = json.loads(verified_evidence(final)["result.json"].read_text())
    assert recorded["commit"] == git(shop.checkout, "rev-parse", "HEAD")
    assert recorded["commit"] in final["body"]


def test_a_commit_job_does_not_run_repository_hooks(shop):
    hook = shop.checkout / ".git" / "hooks" / "pre-commit"
    witness = shop.tmp / "hook-ran"
    hook.write_text("#!/bin/sh\ntouch %s\nexit 1\n" % witness)
    hook.chmod(0o700)
    (shop.checkout / ".git" / "hooks" / "commit-msg").write_bytes(hook.read_bytes())
    (shop.checkout / ".git" / "hooks" / "commit-msg").chmod(0o700)
    commit_request(shop)
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert not witness.exists()


def test_a_tree_that_does_not_match_changes_nothing(shop):
    before = shop.head()["commit"]
    commit_request(shop, expected_tree="0" * 40)
    assert shop.run_open()["rows"][0]["state"] == "failed"
    final = shop.receipts("job-1")[-1]
    assert "tree" in final["receipt"]["reason"]
    assert git(shop.checkout, "rev-parse", "HEAD") == before
    assert git(shop.checkout, "diff", "--cached", "--name-only") == "", "the real index must stay untouched"
    assert (shop.checkout / "src" / "app.py").read_text() == "value = 2\n"


@pytest.mark.parametrize("changes, reason", [
    ({"expected_tree": None}, "commit recipe needs"),
    ({"message": None}, "commit recipe needs"),
    ({"paths": None}, "needs paths"),
    ({"paths": ["src/app.py::test"]}, "invalid path"),
    ({"message": ""}, "message"),
])
def test_a_commit_request_missing_its_details_is_refused(shop, changes, reason):
    before = shop.head()["commit"]
    commit_request(shop, **changes)
    shop.run_open()
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == "refused" and reason in final["receipt"]["reason"], final
    assert git(shop.checkout, "rev-parse", "HEAD") == before


def test_a_commit_with_nothing_new_is_refused(shop):
    shop.request_job("job-1", "commit", paths=["src/app.py"], expected_tree=shop.head()["tree"], message="chore: nothing")
    shop.run_open()
    assert "no change" in shop.receipts("job-1")[-1]["receipt"]["reason"]


def test_a_commit_overlapping_another_lease_is_refused(shop):
    write_lease(shop.checkout, "someone-else", ["src/app.py"])
    before = shop.head()["commit"]
    commit_request(shop)
    shop.run_open()
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == "refused" and "someone-else" in final["receipt"]["reason"]
    assert git(shop.checkout, "rev-parse", "HEAD") == before


def test_a_commit_recipe_needs_an_identity(shop):
    del shop.recipes["identity"]
    shop.save_recipes()
    assert "identity" in shop.jobs("check-recipes", expect=2)["error"]


@pytest.mark.parametrize("change, reason", [
    (lambda r: r.update(schema="other"), "recipes schema"),
    (lambda r: r.update(python="python3"), "python"),
    (lambda r: r.update(path=["relative"]), "path"),
    (lambda r: r["recipes"]["ok"].update(steps=[]), "steps"),
    (lambda r: r["recipes"]["ok"].update(steps=[["$python", "$unknown"]]), "token"),
    (lambda r: r["recipes"]["ok"].update(steps=[["$python", "--flag=$paths"]]), "token"),
    (lambda r: r["recipes"]["ok"].update(steps=["$python -c print(1)"]), "steps"),
    (lambda r: r["recipes"]["ok"].update(steps=[["$python"]] * 21), "steps"),
    (lambda r: r["recipes"]["ok"].update(heavy="yes"), "heavy"),
    (lambda r: r["recipes"]["ok"].update(sandbox="docker"), "sandbox"),
    (lambda r: r["recipes"]["ok"].update(timeout_seconds=0), "timeout"),
    (lambda r: r["recipes"]["ok"].update(kind="shell"), "kind"),
    (lambda r: r["recipes"]["ok"].update(shell=True), "unexpected"),
    (lambda r: r.update(hide=["/no/such/folder"]), "hide"),
    (lambda r: r.update(ro_binds=["relative"]), "ro_binds"),
    (lambda r: r.update(env={"X": "$unknown"}), "token"),
])
def test_bad_recipes_are_refused_before_anything_runs(shop, change, reason):
    change(shop.recipes)
    shop.save_recipes()
    shop.request_job("job-1", "ok")
    refused = shop.jobs("run-open", expect=2)
    assert reason in refused["error"], refused
    assert shop.states("job-1") == []


def test_good_recipes_pass_the_check_with_a_summary(shop):
    summary = shop.jobs("check-recipes")
    assert summary["recipes"]["heavy"]["heavy"] is True and summary["recipes"]["commit"]["kind"] == "commit"


def test_a_recipe_that_needs_a_sandbox_is_refused_when_none_is_available(shop, tmp_path):
    shop.recipes["recipes"]["boxed"] = shop.command(["$python", "-c", "open(%r, 'w').close()" % str(shop.sentinel)], sandbox="bwrap")
    shop.save_recipes()
    shop.request_job("job-1", "boxed")
    tools = tmp_path / "no-bwrap"
    tools.mkdir()
    (tools / "git").symlink_to(shutil.which("git"))
    shop.run_open(env={**shop.env(), "PATH": str(tools)})
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == "refused" and "bubblewrap" in final["receipt"]["reason"]
    assert not shop.sentinel.exists()


PROBE = """
import json, os, socket, sys
checks = {}
def attempt(name, action):
    try:
        action()
        checks[name] = "allowed"
    except OSError as error:
        checks[name] = type(error).__name__
attempt("write_checkout", lambda: open(os.path.join(sys.argv[1], "planted"), "w").close())
attempt("write_outside", lambda: open(sys.argv[2], "w").close())
attempt("read_hidden", lambda: open(sys.argv[3]).read())
attempt("write_job_home", lambda: open(os.path.join(os.environ["HOME"], "ok"), "w").close())
attempt("write_tmp", lambda: open(os.path.join(os.environ["TMPDIR"], "ok"), "w").close())
attempt("read_checkout", lambda: open(os.path.join(sys.argv[1], "src", "app.py")).read())
def connect():
    with socket.create_connection(("1.1.1.1", 53), timeout=1):
        pass
attempt("network", connect)
checks["interfaces"] = sorted(line.split(":")[0].strip() for line in open("/proc/net/dev").read().splitlines()[2:])
print(json.dumps(checks))
"""


@needs_bubblewrap
def test_a_sandboxed_job_is_contained(shop):
    try:
        # Outside /tmp when possible, so only `hide` can be what conceals it. A full-suite job runs
        # with the host read-only, and its own temporary folder is already outside /tmp.
        hidden = Path(tempfile.mkdtemp(prefix="hierarchy-jobs-hidden-", dir="/var/tmp"))
    except OSError:
        hidden = shop.tmp / "hidden"
        hidden.mkdir()
    try:
        secret = hidden / "credentials"
        secret.write_text("secret\n")
        outside = hidden.parent / (hidden.name + "-outside")
        shop.recipes["hide"] = [str(hidden)]
        shop.recipes["recipes"]["boxed"] = shop.command(
            ["$python", "-I", "-c", PROBE, str(shop.checkout), str(outside), str(secret)], sandbox="bwrap")
        shop.save_recipes()
        shop.request_job("job-1", "boxed")
        assert shop.run_open()["rows"][0]["state"] == "completed"
        log = verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()
        checks = json.loads(log.strip().splitlines()[-1])
        assert checks["write_checkout"] in ("OSError", "PermissionError")
        assert checks["write_outside"] in ("OSError", "PermissionError")
        assert checks["read_hidden"] == "FileNotFoundError"
        assert checks["write_job_home"] == "allowed" and checks["write_tmp"] == "allowed"
        assert checks["read_checkout"] == "allowed"
        assert checks["network"] != "allowed" and checks["interfaces"] == ["lo"]
        assert not (shop.checkout / "planted").exists() and not outside.exists()
    finally:
        shutil.rmtree(hidden, ignore_errors=True)


@needs_bubblewrap
def test_a_recipe_can_allow_writing_to_its_checkout_and_the_source_check_still_applies(shop):
    target = shop.checkout / "planted"
    shop.recipes["recipes"]["boxed"] = shop.command(
        ["$python", "-c", "open(%r, 'w').close()" % str(target)], sandbox="bwrap", writable_checkout=True)
    shop.save_recipes()
    shop.request_job("job-1", "boxed")
    assert shop.run_open()["rows"][0]["state"] == "failed"
    assert target.exists()
    assert "source changed during the job" in shop.receipts("job-1")[-1]["receipt"]["reason"]


@needs_bubblewrap
def test_a_sandboxed_commit_can_write_git_data_but_not_the_working_tree(shop):
    shop.recipes["recipes"]["commit"]["sandbox"] = "bwrap"
    shop.save_recipes()
    tree = commit_request(shop)
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree


@needs_bubblewrap
def test_a_sandboxed_commit_works_from_a_linked_worktree(shop):
    linked = shop.tmp / "linked"
    git(shop.checkout, "worktree", "add", "-q", "-b", "feature/linked", str(linked))
    shop.workspace.run("update", {"initiative": "pilot", "source": "owner", "checkouts": [str(linked)]})
    shop.recipes["recipes"]["commit"]["sandbox"] = "bwrap"
    shop.save_recipes()
    (linked / "src" / "app.py").write_text("value = 5\n")
    status = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=linked,
                            capture_output=True, check=True, timeout=10).stdout
    env = {**os.environ, "GIT_INDEX_FILE": str(shop.tmp / "linked-index")}
    run = lambda *args: subprocess.run(["git", *args], cwd=linked, env=env, capture_output=True, text=True,  # noqa: E731
                                       check=True, timeout=10).stdout.strip()
    run("read-tree", "HEAD")
    run("add", "--", "src/app.py")
    tree = run("write-tree")
    shop.request_job("job-1", "commit", checkout=linked, paths=["src/app.py"], expected_tree=tree, message="fix: from a worktree",
                     dirty_state_sha256=hashlib.sha256(status).hexdigest())
    result = shop.run_open()
    assert result["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]
    assert git(linked, "rev-parse", "HEAD^{tree}") == tree
    assert git(linked, "status", "--porcelain=v1") == ""


@needs_bubblewrap
def test_a_sandboxed_pytest_job_can_run_in_a_read_only_checkout(shop):
    shop.recipes["recipes"]["pytest"] = shop.command(
        ["$python", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp", "$scratch", "$paths"],
        heavy=True, sandbox="bwrap")
    shop.recipes["env"] = {"PYTHONPATH": "$checkout"}
    if "PYTHONUSERBASE" in os.environ:  # Local runs may keep pytest in the user site.
        shop.recipes["env"].update(PYTHONUSERBASE=os.environ["PYTHONUSERBASE"], PYTHONNOUSERSITE="")
    shop.save_recipes()
    shop.request_job("job-1", "pytest", paths=["tests/test_app.py::test_app"])
    assert shop.run_open()["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]["body"]
    assert "1 passed" in shop.receipts("job-1")[-1]["body"]
