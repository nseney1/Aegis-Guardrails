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
import uuid

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
    ("with-paths", {"paths": ["src/app.py"], "dirty_content_sha256": "0" * 64}, "source does not match"),
    ("with-paths", {"paths": ["src/app.py"], "dirty_state_sha256": "0" * 64}, "unexpected"),
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
    assert "exit None" not in final["body"]


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


def source_digest(shop, checkout=None, *, expect=0):
    done = subprocess.run([sys.executable, "-I", str(JOBS), "source-digest", "--checkout", str(checkout or shop.checkout)],
                          capture_output=True, text=True, timeout=30, env=shop.env())
    assert not done.stderr, done.stderr
    assert done.returncode == expect, done.stdout
    return json.loads(done.stdout)


def test_a_request_can_name_exact_uncommitted_bytes(shop):
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    shop.request_job("job-1", "touch", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert shop.sentinel.exists()


def test_the_source_digest_gives_what_a_packet_needs(shop):
    clean = source_digest(shop)
    assert clean == {"commit": shop.head()["commit"], "tree": shop.head()["tree"], "dirty_entries": 0, "dirty_content_sha256": EMPTY}
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    assert source_digest(shop)["dirty_entries"] == 1
    plain = shop.tmp / "not-a-checkout"
    plain.mkdir()
    assert "status" in source_digest(shop, plain, expect=2)["error"]


def test_changing_an_already_changed_file_refuses_a_request_bound_to_its_old_bytes(shop):
    """The status looks identical in both states, so only the content can tell them apart."""
    target = shop.checkout / "src" / "app.py"
    target.write_text("value = 2\n")
    status_before = subprocess.run(["git", "status", "--porcelain=v1", "-z"], cwd=shop.checkout, capture_output=True, check=True, timeout=10).stdout
    shop.request_job("job-1", "touch", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    target.write_text("value = 3\n")
    assert subprocess.run(["git", "status", "--porcelain=v1", "-z"], cwd=shop.checkout, capture_output=True, check=True, timeout=10).stdout == status_before
    assert shop.run_open()["rows"][0]["state"] == "refused"
    assert "source does not match" in shop.receipts("job-1")[-1]["receipt"]["reason"]
    assert not shop.sentinel.exists()


def test_changing_an_already_changed_file_during_a_job_fails_it(shop):
    target = shop.checkout / "src" / "app.py"
    target.write_text("value = 2\n")
    shop.recipes["recipes"]["edits"] = shop.command(["$python", "-c", "open(%r, 'w').write('value = 3\\n')" % str(target)])
    shop.save_recipes()
    shop.request_job("job-1", "edits", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    assert shop.run_open()["rows"][0]["state"] == "failed"
    final = shop.receipts("job-1")[-1]
    assert "source changed during the job" in final["receipt"]["reason"]
    recorded = json.loads(verified_evidence(final)["result.json"].read_text())
    assert recorded["before"]["dirty_content_sha256"] != recorded["after"]["dirty_content_sha256"]
    assert recorded["before"]["dirty_state_sha256"] == recorded["after"]["dirty_state_sha256"]


@pytest.mark.parametrize("change", [
    lambda checkout: (checkout / "src" / "new.py").write_text("x\n"),
    lambda checkout: (checkout / "src" / "app.py").unlink(),
    lambda checkout: (checkout / "src" / "app.py").chmod(0o755),
    lambda checkout: (checkout / "untracked.txt").write_text("other\n"),
    lambda checkout: (checkout / "linked").unlink() or (checkout / "linked").symlink_to("elsewhere"),
])
def test_every_kind_of_uncommitted_change_moves_the_digest(shop, change):
    (shop.checkout / "untracked.txt").write_text("first\n")
    (shop.checkout / "linked").symlink_to("somewhere")
    before = source_digest(shop)["dirty_content_sha256"]
    change(shop.checkout)
    assert source_digest(shop)["dirty_content_sha256"] != before


def add_submodule(shop, name="sub"):
    origin = shop.tmp / ("origin-" + name)
    origin.mkdir()
    git(origin, "init", "-q", "-b", "main")
    (origin / "data.txt").write_text("one\n")
    git(origin, "add", ".")
    git(origin, "commit", "-qm", "origin")
    git(shop.checkout, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(origin), name)
    git(shop.checkout, "commit", "-qm", "add a submodule")
    return shop.checkout / name


def digest_or_error(shop):
    done = subprocess.run([sys.executable, "-I", str(JOBS), "source-digest", "--checkout", str(shop.checkout)],
                          capture_output=True, text=True, timeout=30, env=shop.env())
    assert not done.stderr, done.stderr
    return done.returncode, json.loads(done.stdout)


def test_a_submodule_is_refused_by_path_instead_of_hiding_its_bytes(shop):
    """The parent's status shows only ` M sub` for any content or revision inside it, so no digest can bind it."""
    sub = add_submodule(shop)
    seen = {"clean": digest_or_error(shop)}
    (sub / "data.txt").write_text("two\n")
    seen["dirty-a"] = digest_or_error(shop)
    (sub / "data.txt").write_text("three\n")
    seen["dirty-b"] = digest_or_error(shop)
    git(sub, "commit", "-qam", "moved")
    seen["new-revision"] = digest_or_error(shop)
    git(shop.checkout, "submodule", "deinit", "-q", "-f", "sub")
    seen["uninitialized"] = digest_or_error(shop)
    assert all(code == 2 and "submodule" in out["error"] and "sub" in out["error"] for code, out in seen.values()), seen


def test_a_nested_repository_is_refused_by_path_and_ordinary_bytes_still_count(shop):
    nested = shop.checkout / "nested"
    nested.mkdir()
    git(nested, "init", "-q", "-b", "main")
    (nested / "inner.txt").write_text("a\n")
    code, out = digest_or_error(shop)
    assert code == 2 and "nested" in out["error"] and "byte for byte" in out["error"], out
    shutil.rmtree(nested)
    target = shop.checkout / "src" / "app.py"
    digests = []
    for content in ("value = 2\n", "value = 3\n"):
        target.write_text(content)
        digests.append(source_digest(shop)["dirty_content_sha256"])
    (shop.checkout / "linked").symlink_to("app.py")
    digests.append(source_digest(shop)["dirty_content_sha256"])
    assert len(set(digests)) == 3


def test_a_job_on_a_checkout_with_a_submodule_is_refused_by_path_and_holds_nothing(shop, tmp_path):
    add_submodule(shop)
    proof = tmp_path / "recipe-ran"
    shop.recipes["recipes"]["probe"] = shop.command(["$python", "-c", "open(%r, 'w').close()" % str(proof)], heavy=True)
    shop.save_recipes()
    shop.request_job("job-1", "probe")
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "submodule" in row["reason"] and "sub" in row["reason"], row
    assert not proof.exists() and shop.states("job-1") == ["refused"]
    assert shop.heavy()["used"] == 0 and not [event for event in shop.events() if event["kind"] == "grant"]


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


def test_a_large_valid_result_settles_and_frees_its_slot(shop):
    names = ["src/%03d-%s.py" % (number, "x" * 150) for number in range(256)]
    for name in names:
        (shop.checkout / name).write_text("")
    git(shop.checkout, "add", ".")
    git(shop.checkout, "commit", "-qm", "many long names")
    shop.recipes["recipes"]["wide"] = {"kind": "command", "heavy": True, "sandbox": "none", "timeout_seconds": 60,
                                       "steps": [["$python", "-c", "pass", "$paths"]] * 20}
    shop.save_recipes()
    shop.request_job("job-1", "wide", paths=names)
    assert shop.run_open()["rows"][0]["state"] == "completed"
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == "completed"
    assert verified_evidence(final)["result.json"].stat().st_size > 262144
    assert shop.heavy()["used"] == 0


def test_paths_over_their_total_budget_are_refused(shop):
    """A message body cannot carry this many, so the packet comes as a file, which allows more bytes."""
    names = ["src/%03d-%s.py" % (number, "y" * 300) for number in range(256)]
    packet = shop.base / "packet.md"
    raw = json.dumps({"schema": PACKET_SCHEMA, "recipe": "with-paths", **shop.head(), "paths": names}).encode()
    packet.write_bytes(raw)
    shop.publish("job-1", "job_request", "Run.", brief={"path": str(packet), "sha256": hashlib.sha256(raw).hexdigest()})
    shop.run_open()
    assert "too long together" in shop.receipts("job-1")[-1]["receipt"]["reason"]
    assert not shop.sentinel.exists()


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
    for name in ("HOME", "USERPROFILE", "TMPDIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME", "CARGO_HOME", "CARGO_TARGET_DIR",
                 "RUFF_CACHE_DIR", "HYPOTHESIS_STORAGE_DIRECTORY"):
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


SPAN = ("import os, time\nname = str(os.getpid())\nopen(%r, 'a').write('start ' + name + '\\n')\ntime.sleep(0.6)\n"
        "open(%r, 'a').write('end ' + name + '\\n')\n")


def peak(log):
    running = most = 0
    for line in log.read_text().splitlines():
        running += 1 if line.startswith("start") else -1
        most = max(most, running)
    return most


def test_concurrent_runners_never_exceed_the_combined_cap(shop, tmp_path):
    """The census takes time. If it ran outside the grant lock, runners that counted at once would all see room."""
    log = tmp_path / "spans.log"
    shop.recipes["recipes"]["span"] = shop.command(["$python", "-c", SPAN % (str(log), str(log))], heavy=True)
    shop.save_recipes()
    for number in range(4):
        shop.request_job("job-%d" % number, "span")
    fixture = tmp_path / "slow-census.json"
    fixture.write_text(json.dumps({"external_roots": [101, 102], "delay_seconds": 0.4}))
    argv = [sys.executable, "-I", str(JOBS), "--store", str(shop.workspace.store), "--recipes", str(shop.recipes_path),
            "--census-fixture", str(fixture), "run-open", "--max-jobs", "1"]
    runners = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=shop.env()) for _ in range(4)]
    for runner in runners:
        runner.communicate(timeout=120)
    assert peak(log) == 1, "two outside roots and a limit of three leave room for one job at a time"
    while shop.open_jobs():
        shop.jobs("run-open", census=[101, 102], expect=0)
    assert shop.heavy()["used"] == 0 and peak(log) == 1


def test_a_census_fixture_is_checked(shop, tmp_path):
    fixture = tmp_path / "bad-census.json"
    fixture.write_text(json.dumps({"external_roots": [101], "delay_seconds": 60}))
    shop.request_job("job-1", "heavy")
    argv_error = subprocess.run([sys.executable, "-I", str(JOBS), "--store", str(shop.workspace.store), "--recipes", str(shop.recipes_path),
                                 "--census-fixture", str(fixture), "run-open"], capture_output=True, text=True, timeout=60, env=shop.env())
    assert argv_error.returncode == 2 and "delay_seconds" in argv_error.stdout


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


def test_a_checkout_that_cannot_be_witnessed_afterward_fails_the_job_and_frees_its_slot(shop):
    script = "import shutil; shutil.rmtree(%r)" % str(shop.checkout / ".git")
    shop.recipes["recipes"]["breaks"] = shop.command(["$python", "-c", script], heavy=True)
    shop.save_recipes()
    shop.request_job("job-1", "breaks")
    assert shop.run_open()["rows"][0]["state"] == "failed"
    final = shop.receipts("job-1")[-1]
    assert "could not witness" in final["receipt"]["reason"]
    assert verified_evidence(final) and shop.heavy()["used"] == 0 and shop.open_jobs() == []


def test_a_busy_store_leaves_a_heavy_job_waiting_and_loses_nothing(shop):
    shop.request_job("job-1", "heavy")
    shop.request_job("job-2", "touch")
    lock = shop.workspace.store / ".write.lock"
    lock.write_text("fixture active writer")
    rows = {row["job"]: row for row in shop.run_open(lock_wait=0.1, expect=3)["rows"]}
    assert rows["pilot/job-1"]["state"] == "waiting" and rows["pilot/job-1"]["reason"] == "store_busy"
    assert rows["pilot/job-2"]["state"] == "completed", "other work still gets done and reported"
    assert shop.receipts("job-1") == []
    lock.unlink()
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert shop.heavy()["used"] == 0


MAKES_WORK = ("import os, sys, stat\n"
              "folder = os.path.join(os.environ['TMPDIR'], 'nested')\n"
              "os.makedirs(folder)\n"
              "open(os.path.join(folder, 'big'), 'w').write('x' * 1000)\n"
              "os.chmod(folder, 0o500)\n"
              "open(os.path.join(os.environ['HOME'], 'dropped'), 'w').close()\n"
              "print('made work')\n")


def work_names(shop, identifier="job-1"):
    return sorted(path.name for path in (shop.workspace.store / "jobs" / "pilot" / identifier).iterdir())


def test_a_completed_job_keeps_its_evidence_and_removes_its_work_folders(shop):
    shop.recipes["recipes"]["works"] = shop.command(["$python", "-c", MAKES_WORK])
    shop.save_recipes()
    shop.request_job("job-1", "works")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert work_names(shop) == ["claim.json", "packet.md", "process.json", "result.json", "step-1.log"]
    assert "made work" in verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()


def test_a_failed_job_keeps_its_work_folders_until_root_cleans_them(shop):
    shop.recipes["recipes"]["works"] = shop.command(["$python", "-c", MAKES_WORK + "sys.exit(4)\n"])
    shop.save_recipes()
    shop.request_job("job-1", "works")
    row = shop.run_open()["rows"][0]
    assert row["state"] == "failed" and row["work_kept"] is True
    assert {"home", "tmp", "scratch"} <= set(work_names(shop))
    cleaned = shop.jobs("clean", "--job", "pilot/job-1")
    assert {"home", "tmp", "scratch"} <= set(cleaned["removed"])
    assert work_names(shop) == ["claim.json", "packet.md", "process.json", "result.json", "step-1.log"]
    assert verified_evidence(shop.receipts("job-1")[-1])
    assert shop.jobs("clean", "--job", "pilot/job-1")["removed"] == []


def test_clean_refuses_a_job_that_has_not_finished(shop, tmp_path):
    assert "no job here" in shop.jobs("clean", "--job", "pilot/job-1", expect=2)["error"]
    assert "invalid job" in shop.jobs("clean", "--job", "../../etc", expect=2)["error"]
    runner = start_stuck_job(shop, tmp_path)
    group = shop.run_open(expect=3)["rows"][0]["process_group"]
    try:
        assert "not finished" in shop.jobs("clean", "--job", "pilot/job-1", expect=2)["error"]
    finally:
        os.killpg(runner.pid, signal.SIGKILL)
        runner.communicate()
        os.killpg(group, signal.SIGKILL)


def test_clean_does_not_follow_a_symlink_out_of_a_work_folder(shop, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o500)
    script = ("import os, sys\nos.symlink(%r, os.path.join(os.environ['HOME'], 'link'))\nsys.exit(4)\n" % str(outside))
    shop.recipes["recipes"]["links"] = shop.command(["$python", "-c", script])
    shop.save_recipes()
    shop.request_job("job-1", "links")
    shop.run_open()
    shop.jobs("clean", "--job", "pilot/job-1")
    assert outside.exists() and not outside.stat().st_mode & 0o200, "its mode must stay as it was"
    outside.chmod(0o700)


def test_a_heavy_job_waits_when_the_disk_is_low(shop):
    shop.recipes["min_free_gigabytes"] = 1000000
    shop.save_recipes()
    shop.request_job("job-1", "heavy")
    shop.request_job("job-2", "ok")
    rows = {row["job"]: row for row in shop.run_open(expect=3)["rows"]}
    assert rows["pilot/job-1"]["state"] == "waiting" and rows["pilot/job-1"]["reason"] == "low_disk"
    assert rows["pilot/job-2"]["state"] == "completed", "a light job still runs"
    assert shop.receipts("job-1") == []
    shop.recipes["min_free_gigabytes"] = 1
    shop.save_recipes()
    assert shop.run_open()["rows"][0]["state"] == "completed"


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


def processes_with(marker):
    found = []
    for item in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if marker.encode() in item.read_bytes():
                found.append(int(item.parent.name))
        except OSError:
            pass
    return found


def test_a_step_whose_process_record_cannot_be_written_is_stopped_before_its_slot_is_freed(shop):
    marker = "marker-" + uuid.uuid4().hex
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
    # The first step blocks the second step's record by putting a folder where the record is written.
    first = ("import os, time\nfor _ in range(500):\n    if os.path.exists(%r):\n        break\n    time.sleep(0.01)\nos.mkdir(%r)\n"
             % (str(folder / "process.json"), str(folder / "process.pending")))
    shop.recipes["recipes"]["two"] = {"kind": "command", "heavy": True, "sandbox": "none", "timeout_seconds": 30,
                                      "steps": [["$python", "-c", first], ["$python", "-c", "import time; time.sleep(40)", marker]]}
    shop.save_recipes()
    shop.request_job("job-1", "two")
    try:
        assert shop.run_open()["rows"][0]["state"] == "failed"
        assert "could not run" in shop.receipts("job-1")[-1]["receipt"]["reason"]
        deadline = time.monotonic() + 5
        while processes_with(marker):
            assert time.monotonic() < deadline, "the second step kept running after its job was reported"
            time.sleep(0.05)
        assert shop.heavy()["used"] == 0
    finally:
        for pid in processes_with(marker):
            os.kill(pid, signal.SIGKILL)


def test_resolve_needs_a_confirmation_when_no_process_was_ever_recorded(shop, tmp_path):
    runner = start_stuck_job(shop, tmp_path)
    group = shop.run_open(expect=3)["rows"][0]["process_group"]
    os.killpg(runner.pid, signal.SIGKILL)
    runner.communicate()
    os.killpg(group, signal.SIGKILL)
    deadline = time.monotonic() + 5
    while shop.run_open(expect=3)["rows"][0]["process_alive"]:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    (shop.workspace.store / "jobs" / "pilot" / "job-1" / "process.json").unlink()
    refused = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.", expect=2)
    assert "--process-stopped" in refused["error"]
    assert shop.heavy()["used"] == 1
    assert shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.", "--process-stopped")["state"] == "failed"
    assert shop.heavy()["used"] == 0


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


def wait_until(check, seconds, message):
    deadline = time.monotonic() + seconds
    while not check():
        assert time.monotonic() < deadline, message
        time.sleep(0.02)


def two_step_job(shop, first, second, marker):
    shop.recipes["recipes"]["two"] = {"kind": "command", "heavy": True, "sandbox": "none", "timeout_seconds": 50,
                                      "steps": [["$python", "-c", first], ["$python", "-c", second, marker]]}
    shop.save_recipes()
    shop.request_job("job-1", "two")


def after_own_record(folder, action):
    # The first step plants its obstacle only once the runner recorded the first step's own group, so the obstacle
    # meets the second step's launch and not the first step's record.
    return ("import json, os, time\nfor _ in range(1000):\n    try:\n"
            "        if json.load(open(%r)).get('group') == os.getpgrp():\n            break\n"
            "    except (OSError, ValueError):\n        pass\n    time.sleep(0.01)\n%s\n" % (str(folder / "process.json"), action))


def start_runner(shop, **options):
    return subprocess.Popen(shop.argv("run-open", census=[]), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=shop.env(), start_new_session=True, **options)


def stop_runner(runner):
    if runner.returncode is None:
        try:
            os.killpg(runner.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        runner.communicate(timeout=10)


def release_count(shop):
    return sum(1 for event in shop.events() if event["kind"] == "release")


def assert_held_until_root_confirms(shop, marker):
    """The later step's own group was never recorded, so neither its runner's loss nor the earlier step's dead
    group may free the slot or send a final receipt. Only root's explicit confirmation does, exactly once."""
    assert processes_with(marker), "the later step outlives its runner"
    assert shop.run_open(expect=3)["rows"][0]["state"] == "abandoned"
    assert shop.heavy()["used"] == 1 and shop.states("job-1") == ["started", "unknown"]
    refused = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.", expect=2)
    assert "--process-stopped" in refused["error"]
    for pid in processes_with(marker):
        os.kill(pid, signal.SIGKILL)
    wait_until(lambda: not processes_with(marker), 5, "the later step did not stop")
    refused = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.", expect=2)
    assert "--process-stopped" in refused["error"], "a dead earlier group proves nothing about the later step"
    assert shop.heavy()["used"] == 1 and shop.states("job-1") == ["started", "unknown"] and release_count(shop) == 0
    resolved = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.", "--process-stopped")
    assert resolved["state"] == "failed"
    assert shop.heavy()["used"] == 0 and shop.states("job-1") == ["started", "unknown", "failed"]
    assert release_count(shop) == 1
    assert shop.run_open()["rows"] == [] and release_count(shop) == 1
    again = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "Again.", "--process-stopped", expect=2)
    assert "already finished" in again["error"] and release_count(shop) == 1


def test_a_runner_lost_between_a_later_launch_and_its_record_keeps_the_slot_until_root_confirms(shop):
    marker = "marker-" + uuid.uuid4().hex
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
    # A pipe nobody reads, where the second step's record is written, holds the runner just after that launch.
    two_step_job(shop, after_own_record(folder, "os.mkfifo(%r)" % str(folder / "process.pending")),
                 "import time; time.sleep(60)", marker)
    runner = start_runner(shop)
    try:
        wait_until(lambda: processes_with(marker), 10, "the second step never started")
        stop_runner(runner)
        assert_held_until_root_confirms(shop, marker)
    finally:
        stop_runner(runner)
        for pid in processes_with(marker):
            os.kill(pid, signal.SIGKILL)


def test_a_later_step_whose_record_fails_and_whose_stop_is_lost_keeps_the_slot_until_root_confirms(shop):
    marker = "marker-" + uuid.uuid4().hex
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
    two_step_job(shop, after_own_record(folder, "os.mkdir(%r)" % str(folder / "process.pending")),
                 "import time; time.sleep(60)", marker)
    # An ignored SIGTERM is inherited, so the second step outlasts the polite part of its stop, and the runner is
    # lost inside that 5 s grace, before the stop was confirmed.
    runner = start_runner(shop, preexec_fn=lambda: signal.signal(signal.SIGTERM, signal.SIG_IGN))
    try:
        wait_until(lambda: processes_with(marker), 10, "the second step never started")
        time.sleep(1)
        stop_runner(runner)
        assert_held_until_root_confirms(shop, marker)
    finally:
        stop_runner(runner)
        for pid in processes_with(marker):
            os.kill(pid, signal.SIGKILL)


def test_a_step_whose_launch_cannot_be_recorded_first_never_starts(shop, tmp_path):
    marker = "marker-" + uuid.uuid4().hex
    proof = tmp_path / "second-step-ran"
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
    two_step_job(shop, after_own_record(folder, "os.mkdir(%r)" % str(folder / "process.intent")),
                 "open(%r, 'w').close()" % str(proof), marker)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "failed" and "could not run" in row["reason"]
    assert not proof.exists(), "a step must not start before its launch is on record"
    assert shop.heavy()["used"] == 0 and release_count(shop) == 1


def test_a_later_step_that_cannot_launch_is_an_ordinary_failure(shop, tmp_path):
    missing = str(tmp_path / ("no-such-program-" + uuid.uuid4().hex))
    shop.recipes["recipes"]["two"] = {"kind": "command", "heavy": True, "sandbox": "none", "timeout_seconds": 30,
                                      "steps": [["$python", "-c", "print('first')"], [missing]]}
    shop.save_recipes()
    shop.request_job("job-1", "two")
    row = shop.run_open()["rows"][0]
    assert row["state"] == "failed" and "could not run" in row["reason"]
    assert shop.states("job-1") == ["started", "failed"]
    assert shop.heavy()["used"] == 0 and release_count(shop) == 1


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
    # The expected tree comes from a throwaway index, which is how a lane computes it.
    index = shop.tmp / ("lane-index-%d" % time.monotonic_ns())
    env = {**os.environ, "GIT_INDEX_FILE": str(index)}
    run = lambda *args: subprocess.run(["git", *args], cwd=shop.checkout, env=env, capture_output=True, text=True,  # noqa: E731
                                       check=True, timeout=10).stdout.strip()
    run("read-tree", "HEAD")
    run("add", "--", "src/app.py", "tests/test_app.py")
    tree = run("write-tree")
    packet = {"paths": ["src/app.py", "tests/test_app.py"], "expected_tree": tree, "message": "fix: raise value\n\nExact text; $(not run).\n",
              "dirty_content_sha256": source_digest(shop)["dirty_content_sha256"], **changes}
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
    (lambda r: r.update(min_free_gigabytes="lots"), "min_free_gigabytes"),
    (lambda r: r["recipes"]["ok"].update(heavy_tests="yes"), "heavy_tests"),
    (lambda r: r["recipes"]["ok"].update(heavy_tests=True), "heavy_tests needs heavy"),
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


def test_a_cargo_test_step_runs_only_in_a_heavy_tests_recipe(shop):
    shop.recipes["recipes"]["storm"] = shop.command(["/opt/rust/bin/cargo", "test", "--quiet"], heavy=True)
    shop.save_recipes()
    shop.request_job("job-1", "ok")
    refused = shop.jobs("run-open", expect=2)
    assert refused["error"] == ("recipe storm step 1 runs a cargo build or test (cargo test), which only a heavy_tests "
                                "recipe may run")
    assert shop.states("job-1") == [] and shop.jobs("check-recipes", expect=2) == refused
    shop.recipes["recipes"]["storm"]["heavy_tests"] = True
    shop.save_recipes()
    summary = shop.jobs("check-recipes")["recipes"]
    assert summary["storm"]["heavy_tests"] is True and summary["heavy"]["heavy_tests"] is False


@pytest.mark.parametrize("step, compiles", [
    (["cargo", "test"], True),
    (["/opt/rust/bin/cargo", "+nightly", "--locked", "build", "--release"], True),
    (["cargo", "t"], True),
    (["cargo", "nextest", "run"], True),
    (["cargo", "clippy", "--", "-D", "warnings"], True),
    (["/usr/bin/rustc", "main.rs"], True),
    (["rustc", "--version"], True),
    (["cargo", "fmt", "--all", "--", "--check"], False),
    (["cargo", "metadata", "--format-version", "1"], False),
    (["cargo", "tree"], False),
    (["cargo", "--version"], False),
    (["$python", "-c", "print('cargo test')"], False),
])
def test_only_a_heavy_tests_recipe_may_compile_with_cargo_or_rustc(shop, step, compiles):
    """A script that runs cargo itself is not seen: only the step's own program and subcommand are read."""
    shop.recipes["recipes"]["probe"] = shop.command(step)
    shop.save_recipes()
    answer = shop.jobs("check-recipes", expect=2 if compiles else 0)
    assert ("only a heavy_tests recipe may run" in answer.get("error", "")) is compiles, answer
    shop.recipes["recipes"]["probe"].update(heavy=True, heavy_tests=True)
    shop.save_recipes()
    assert shop.jobs("check-recipes")["recipes"]["probe"]["heavy_tests"] is True


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


FORGER = """
import json, os, sys
folder, attempts = sys.argv[1], {}
for name in ("result.json", "claim.json", "process.json", "packet.md", "step-1.log", "step-9.log", "planted"):
    try:
        with open(os.path.join(folder, name), "a") as stream:
            stream.write("forged")
        attempts[name] = "written"
    except OSError as error:
        attempts[name] = type(error).__name__
attempts["work"] = "written"
open(os.path.join(os.environ["HOME"], "ok"), "w").close()
print(json.dumps(attempts))
"""


@needs_bubblewrap
def test_a_sandboxed_job_cannot_write_its_own_verdict_or_records(shop):
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
    shop.recipes["recipes"]["forges"] = shop.command(["$python", "-I", "-c", FORGER, str(folder)], sandbox="bwrap")
    shop.save_recipes()
    shop.request_job("job-1", "forges")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    attempts = json.loads(evidence["step-1.log"].read_text().strip().splitlines()[-1])
    for name in ("result.json", "claim.json", "process.json", "packet.md", "step-1.log", "step-9.log", "planted"):
        assert attempts[name] != "written", name
    assert json.loads(evidence["result.json"].read_text())["state"] == "completed"
    assert not (folder / "planted").exists() and not (folder / "step-9.log").exists()
    assert json.loads((folder / "claim.json").read_text())["job"] == "pilot/job-1"


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
    env = {**os.environ, "GIT_INDEX_FILE": str(shop.tmp / "linked-index")}
    run = lambda *args: subprocess.run(["git", *args], cwd=linked, env=env, capture_output=True, text=True,  # noqa: E731
                                       check=True, timeout=10).stdout.strip()
    run("read-tree", "HEAD")
    run("add", "--", "src/app.py")
    tree = run("write-tree")
    shop.request_job("job-1", "commit", checkout=linked, paths=["src/app.py"], expected_tree=tree, message="fix: from a worktree",
                     dirty_content_sha256=source_digest(shop, linked)["dirty_content_sha256"])
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
