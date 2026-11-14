"""Root runs an orchestrator's job request through a fixed recipe and answers it with a receipt.

Jobs here are real processes and the sandbox tests run real bubblewrap when it works on this machine.
No host session is involved, so these tests say nothing about how a model behaves.
"""
import copy
import errno
import hashlib
import io
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

from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch as jobs2_patch

import pytest

import tools as jobs2_tools
from tools import hierarchy_jobs as jobs2_module
import hierarchy_mailbox as jobs2_mailbox
import hierarchy_fresh_brief as jobs2_fresh_brief

from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke
from tests.integration import test_hierarchy_provision as provision_fixtures
from tests.integration.test_hierarchy_provision import INITIATIVE, LANES, Setup, provision
from tests.integration.test_hierarchy_workspace import write_lease
from tests.conftest import symlink_or_skip


JOBS = ROOT / "tools" / "hierarchy_jobs.py"
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the job runner reads /proc")
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
EMPTY = hashlib.sha256(b"").hexdigest()
_WORKER_SHOP = pytest.StashKey[object]()


# The CI Linux legs run this same probe as a hard step (test_ci_workflows), so a sandbox that
# cannot start fails the run there instead of silently skipping the tests below.
BUBBLEWRAP_PROBE = ("bwrap", "--unshare-net", "--unshare-pid", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                    "true")


def bubblewrap_works():
    if shutil.which("bwrap") is None:
        return False
    probe = subprocess.run(list(BUBBLEWRAP_PROBE), capture_output=True, timeout=10)
    return probe.returncode == 0


needs_bubblewrap = pytest.mark.skipif(not sys.platform.startswith("linux") or not bubblewrap_works(),
                                      reason="bubblewrap does not run here")


class Shop(Setup):
    def __init__(self, tmp_path, *, source_seed=None):
        super().__init__(tmp_path, source_seed=source_seed)
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
        census = census if census is None or isinstance(census, dict) else list(census)
        result = subprocess.run(self.argv(command, *flags, census=census, lock_wait=lock_wait),
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


class PristineShop:
    """A private snapshot restored at its recorded absolute path, once per worker."""
    def __init__(self, folder, source_seed):
        active = folder / "active"
        active.mkdir()
        self.original = Shop(active, source_seed=source_seed)
        self.snapshot = folder / "pristine"
        # No hard links: tests can change even Git object bytes or modes.
        shutil.copytree(active, self.snapshot, symlinks=True)
        self.failures_before = None
        self.retained_count = 0
        self.nodeid = None

    def preserve_if_failed(self, testsfailed):
        active = self.original.tmp
        failed = self.failures_before is not None and testsfailed > self.failures_before
        if not active.exists():
            return
        metadata = {"nodeid": self.nodeid, "time": time.time()}
        if failed:
            metadata["reason"] = "failure count rose"
        else:
            marker = None
            try:
                # RF-36 dot-markers deliberately exclude ordinary product names like evidence.
                pending = [active]
                while pending:
                    folder = pending.pop()
                    # A 0400 directory can be listed but cannot be searched, even when empty.
                    os.stat(os.path.join(folder, "."))
                    with os.scandir(folder) as entries:
                        for entry in entries:
                            if entry.name.lower() in (".keep", ".retain"):
                                marker = entry.name
                            # Keep classification errors outside os.walk's silent fallback.
                            if entry.is_dir(follow_symlinks=False):
                                pending.append(entry.path)
            except OSError as error:
                metadata.update(reason="discovery error", error={"type": type(error).__name__, "errno": error.errno})
            else:
                if marker is None:
                    return  # Only a completed, marker-free traversal permits deletion.
                metadata.update(reason="marker present", marker=marker)
        destination = self.snapshot.parent / ("retained-%d" % (self.retained_count + 1))
        sidecar = destination.with_suffix(".json")
        if any(path.exists() or path.is_symlink() for path in (destination, sidecar)):
            raise FileExistsError(errno.EEXIST, "retained Shop destination already exists")
        # Rename preserves even read-only modes, links and Git metadata byte for byte.
        active.rename(destination)
        self.retained_count += 1
        self.failures_before = None
        with sidecar.open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream)
            stream.write("\n")

    def restore(self, *, nodeid, copy_tree=shutil.copytree, testsfailed=0):
        # This also catches a teardown error reported after the fixture's own teardown.
        self.preserve_if_failed(testsfailed)
        active = self.original.tmp
        if active.exists():
            remove_tree(active)
        self.failures_before = testsfailed
        self.nodeid = nodeid
        # A failed copy raises; the next request discards its partial destination.
        copy_tree(self.snapshot, active, symlinks=True)
        return copy.deepcopy(self.original)


def worker_shop(tmp_path_factory, request, *, copy_tree=shutil.copytree):
    session = request.session
    if _WORKER_SHOP not in session.stash:
        worker = getattr(request.config, "workerinput", {}).get("workerid", "main")
        folder = tmp_path_factory.mktemp("jobs-shop-" + worker)
        seed = provision_fixtures.worker_source_seed(tmp_path_factory, request)
        session.stash[_WORKER_SHOP] = PristineShop(folder, seed)
    return session.stash[_WORKER_SHOP].restore(nodeid=request.node.nodeid, copy_tree=copy_tree,
                                             testsfailed=getattr(session, "testsfailed", 0))


def build_fresh_shop(tmp_path, tmp_path_factory, request):
    return Shop(tmp_path, source_seed=provision_fixtures.worker_source_seed(tmp_path_factory, request))


@pytest.fixture
def fresh_shop(tmp_path, tmp_path_factory, request):
    return build_fresh_shop(tmp_path, tmp_path_factory, request)


@pytest.fixture
def shop(tmp_path_factory, request):
    if getattr(request, "param", None) == "fresh":
        yield build_fresh_shop(request.getfixturevalue("tmp_path"), tmp_path_factory, request)
        return
    # Preserve on the next checkout, after every fixture teardown has finished.
    yield worker_shop(tmp_path_factory, request)


def shop_image(folder):
    """Compare all private fixture bytes and modes, including untracked Git metadata."""
    image = {".": folder.stat().st_mode}
    for path in sorted(folder.rglob("*")):
        name = path.relative_to(folder).as_posix()
        if path.is_symlink():
            image[name] = (path.lstat().st_mode, os.readlink(path))
        elif path.is_dir():
            image[name] = path.stat().st_mode
        else:
            image[name] = (path.stat().st_mode, hashlib.sha256(path.read_bytes()).hexdigest())
    return image


def test_rf36_next_case_restores_every_shop_byte_mode_and_python_value(tmp_path_factory, request):
    first = worker_shop(tmp_path_factory, request)
    before = shop_image(first.tmp)
    original_head = first.head()
    original_recipes = json.loads(first.recipes_path.read_text())
    first.request_job("rf36-dirty", "touch")
    first.run_open()
    first.add_role("pilot/lane/f2")
    first.workspace.register("another")
    first.workspace.run("update", {"initiative": "pilot", "lanes": ["rf36-mutated"], "source": "owner"})
    (first.base / "team.json").write_text("case-local team record\n")
    for repository in (first.checkout, first.source):
        (repository / "dirty").write_text("new commit\n")
        git(repository, "add", "dirty")
        git(repository, "commit", "-qm", "fixture mutation")
        git(repository, "update-ref", "refs/heads/extra", "HEAD")
        git(repository, "worktree", "add", "-qb", "linked", str(first.tmp / (repository.name + "-linked")))
        git(repository, "checkout", "-q", "--detach")
        (repository / "staged").write_text("index mutation\n")
        git(repository, "add", "staged")
    symlink_or_skip(first.recipes_path, first.tmp / "linked-recipes")
    first.recipes["recipes"].clear()
    first.save_recipes()
    first.orchestrator.clear()
    first.recipes_path.chmod(0o400)
    first.checkout.chmod(0o500)
    first.tmp.chmod(0o500)

    second = worker_shop(tmp_path_factory, request)
    assert second is not first and second.tmp == first.tmp
    assert shop_image(second.tmp) == before
    assert second.head() == original_head
    assert second.recipes == original_recipes and second.orchestrator
    assert second.open_jobs() == [] and not second.sentinel.exists()
    # A repeated restore must remain pristine after readers refresh Git's index.
    third = worker_shop(tmp_path_factory, request)
    assert shop_image(third.tmp) == before


def test_rf36_partial_restore_fails_loudly_and_the_next_case_recovers(tmp_path_factory, request):
    first = worker_shop(tmp_path_factory, request)
    before = shop_image(first.tmp)
    def partial_copy(source, destination, **options):
        Path(destination).mkdir()
        (Path(destination) / "partial").write_text("incomplete restore")
        raise OSError(errno.ENOSPC, "rf36 restore full")

    with pytest.raises(OSError, match="rf36 restore full") as failure:
        worker_shop(tmp_path_factory, request, copy_tree=partial_copy)
    assert failure.value.errno == errno.ENOSPC
    restored = worker_shop(tmp_path_factory, request)
    assert restored.tmp == first.tmp and shop_image(restored.tmp) == before


def test_rf36_worker_stashes_restore_concurrently_without_sharing_paths(tmp_path_factory, request):
    # Model two independent pytest worker sessions, including reused worker ids.
    sessions = [SimpleNamespace(stash=pytest.Stash(), addfinalizer=request.session.addfinalizer) for _ in range(2)]
    requests = [SimpleNamespace(session=session, config=request.config, node=request.node) for session in sessions]
    try:
        shops = [worker_shop(tmp_path_factory, item) for item in requests]
        images = [shop_image(item.tmp) for item in shops]
        assert shops[0].tmp != shops[1].tmp
        assert all(tmp_path_factory.getbasetemp() in item.tmp.parents for item in shops)
        for item in shops:
            item.sentinel.write_text("private mutation")
            (item.tmp / ".keep").touch()
        retained_images = [shop_image(item.tmp) for item in shops]
        with ThreadPoolExecutor(max_workers=2) as pool:
            restored = list(pool.map(lambda item: worker_shop(tmp_path_factory, item), requests))
        assert [shop_image(item.tmp) for item in restored] == images
        assert [shop_image(item.tmp.parent / "retained-1") for item in restored] == retained_images
        for item in restored:
            metadata = json.loads((item.tmp.parent / "retained-1.json").read_text())
            assert metadata["nodeid"] == request.node.nodeid
            assert metadata["reason"] == "marker present"
    finally:
        for session in sessions:
            if _WORKER_SHOP in session.stash:
                remove_tree(session.stash[_WORKER_SHOP].snapshot.parent)


def test_rf36_fixture_restores_between_two_actual_pytest_cases(tmp_path):
    try:
        suite = tmp_path / "test_shop_isolation.py"
        suite.write_text(
            "from tests.integration.test_hierarchy_jobs import shop, shop_image\n"
            "seen = []\n"
            "def test_first(shop):\n"
            "    seen.append((shop.tmp, shop_image(shop.tmp)))\n"
            "    shop.sentinel.write_text('previous case')\n"
            "    shop.recipes.clear()\n"
            "def test_second(shop):\n"
            "    path, image = seen[0]\n"
            "    assert shop.tmp == path and shop_image(shop.tmp) == image\n"
            "    assert shop.recipes and not shop.sentinel.exists()\n", encoding="utf-8")
        result = subprocess.run([sys.executable, "-m", "pytest", str(suite), "-n", "0", "-q",
                                 "-c", str(ROOT / "pyproject.toml"),
                                 "--confcutdir", str(tmp_path), "--basetemp", str(tmp_path / "nested"),
                                 "-o", "tmp_path_retention_policy=failed"],
                                cwd=ROOT, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "2 passed" in result.stdout
    finally:
        if (tmp_path / "nested").exists():
            remove_tree(tmp_path / "nested")


@pytest.mark.parametrize("fixture", ["shop", "kind_shop", "fresh_shop"])
def test_rf42_job_fixtures_reuse_the_worker_source_seed(tmp_path_factory, request, monkeypatch, fixture):
    seed = provision_fixtures.worker_source_seed(tmp_path_factory, request)

    def refuse_rebuild(source):
        pytest.fail("job fixtures must reuse the worker source seed")

    monkeypatch.setattr(provision_fixtures, "build_source", refuse_rebuild)
    built = request.getfixturevalue(fixture)
    assert git(built.source, "rev-parse", "HEAD") == git(seed, "rev-parse", "HEAD")


def run_shop_cases(tmp_path, source):
    suite = tmp_path / "test_shop_cases.py"
    suite.write_text(source, encoding="utf-8")
    return subprocess.run([sys.executable, "-m", "pytest", str(suite), "-n", "0", "-q",
                           "-c", str(ROOT / "pyproject.toml"),
                           "--confcutdir", str(tmp_path), "--basetemp", str(tmp_path / "nested"),
                           "-o", "tmp_path_retention_policy=failed"],
                          cwd=ROOT, capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("module,fixture", [
    ("jobs", "shop"), ("jobs", "kind_shop"), ("jobs_census_policy", "policy_shop")])
@pytest.mark.parametrize("marker", [".keep", None])
@pytest.mark.parametrize("mode", [0o111, 0o400], ids=["unlistable", "unsearchable"])
def test_rf36_passing_case_with_unreadable_ancestor_is_retained(tmp_path, module, fixture, marker, mode):
    # Probe actual enumeration permissions: root and some filesystems ignore these mode bits.
    probe = tmp_path / "unreadable-probe"
    probe.mkdir()
    try:
        probe.chmod(mode)
        try:
            with os.scandir(probe) as entries:
                list(entries)
            os.stat(os.path.join(probe, "."))
        except PermissionError:
            pass
        else:
            pytest.skip("chmod is ineffective: restricted ancestor remains listable and searchable")
    finally:
        probe.chmod(0o700)
    try:
        result = run_shop_cases(tmp_path,
            "from tests.integration.test_hierarchy_%s import %s\n" % (module, fixture) +
            "seen = []\n"
            "def test_first(%s):\n" % fixture +
            "    shop = %s\n" % fixture +
            "    ancestor = shop.checkout / 'src'\n"
            "    (ancestor / 'evidence.txt').write_text('passing case evidence')\n"
            "    marker = %r\n" % marker +
            "    if marker: (ancestor / marker).touch()\n"
            "    ancestor.chmod(%r)\n" % mode +
            "    seen.append(shop.tmp)\n"
            "def test_second(%s):\n" % fixture +
            "    shop = %s\n" % fixture +
            "    retained = seen[0].parent / 'retained-1'\n"
            "    assert retained.is_dir(), 'incomplete discovery must retain evidence'\n"
            "    ancestor = retained / 'checkout/src'\n"
            "    assert ancestor.stat().st_mode & 0o777 == %r\n" % mode +
            "    ancestor.chmod(0o700)\n"
            "    assert (ancestor / 'evidence.txt').read_text() == 'passing case evidence'\n"
            "    assert not (shop.checkout / 'src/evidence.txt').exists()\n")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "2 passed" in result.stdout
        sidecars = list((tmp_path / "nested").glob("jobs-shop-main[0-9]*/retained-1.json"))
        assert len(sidecars) == 1
        metadata = json.loads(sidecars[0].read_text())
        assert metadata["nodeid"].endswith("::test_first")
        assert metadata["reason"] == "discovery error"
        assert metadata["error"] == {"type": "PermissionError", "errno": errno.EACCES}
        assert isinstance(metadata["time"], (int, float))
    finally:
        if (tmp_path / "nested").exists():
            remove_tree(tmp_path / "nested")


@pytest.mark.parametrize("module,fixture", [
    ("jobs", "shop"), ("jobs", "kind_shop"), ("jobs_census_policy", "policy_shop")])
@pytest.mark.parametrize("marker", [".keep", ".retain", ".KEEP", ".ReTaIn"])
def test_rf36_dot_markers_retain_passing_case(tmp_path, module, fixture, marker):
    try:
        result = run_shop_cases(tmp_path,
            "from tests.integration.test_hierarchy_%s import %s\n" % (module, fixture) +
            "seen = []\n"
            "def test_first(%s):\n" % fixture +
            "    shop = %s\n" % fixture +
            "    (shop.checkout / 'src' / %r).touch()\n" % marker +
            "    seen.append(shop.tmp)\n"
            "def test_second(%s):\n" % fixture +
            "    shop = %s\n" % fixture +
            "    assert (seen[0].parent / 'retained-1/checkout/src' / %r).exists()\n" % marker +
            "    assert not (shop.checkout / 'src' / %r).exists()\n" % marker)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "2 passed" in result.stdout
        sidecars = list((tmp_path / "nested").glob("jobs-shop-main[0-9]*/retained-1.json"))
        assert len(sidecars) == 1
        metadata = json.loads(sidecars[0].read_text())
        assert metadata["nodeid"].endswith("::test_first")
        assert metadata["reason"] == "marker present"
        assert metadata["marker"].lower() == marker.lower()
        assert isinstance(metadata["time"], (int, float))
    finally:
        if (tmp_path / "nested").exists():
            remove_tree(tmp_path / "nested")


@pytest.mark.parametrize("module,fixture", [
    ("jobs", "shop"), ("jobs", "kind_shop"), ("jobs_census_policy", "policy_shop")])
def test_rf36_product_evidence_and_bare_keep_names_do_not_retain_passing_cases(tmp_path, module, fixture):
    try:
        result = run_shop_cases(tmp_path,
            "from tests.integration.test_hierarchy_%s import %s\n" % (module, fixture) +
            "seen = []\n"
            "def test_first(%s):\n" % fixture +
            "    shop = %s\n" % fixture +
            "    script = \"from pathlib import Path; import sys; p = Path(sys.argv[1]); p.mkdir(); (p / 'report.txt').write_text('kept')\"\n"
            "    shop.recipes['recipes']['keeps'] = shop.command(['$python', '-c', script, '$scratch'], keep=['run/report.txt'])\n"
            "    shop.save_recipes()\n"
            "    shop.request_job('ordinary-evidence', 'keeps')\n"
            "    shop.run_open()\n"
            "    evidence = shop.workspace.store / 'jobs/pilot/ordinary-evidence/evidence/run/report.txt'\n"
            "    assert evidence.read_text() == 'kept'\n"
            "    for name in ('keep', 'KEEP', 'evidence', 'EvIdEnCe'): (shop.checkout / 'src' / name).touch()\n"
            "    seen.append(shop.tmp)\n"
            "def test_second(%s):\n" % fixture +
            "    shop = %s\n" % fixture +
            "    assert not list(seen[0].parent.glob('retained-*')), 'ordinary product names must not retain a passing Shop'\n"
            "    assert not (shop.workspace.store / 'jobs/pilot/ordinary-evidence').exists()\n"
            "    for name in ('keep', 'KEEP', 'evidence', 'EvIdEnCe'): assert not (shop.checkout / 'src' / name).exists()\n")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "2 passed" in result.stdout
    finally:
        if (tmp_path / "nested").exists():
            remove_tree(tmp_path / "nested")


@pytest.mark.parametrize("failure", ["call", "teardown", "teardown_write", "keep", "nested_keep"])
def test_rf36_retains_failed_case_evidence_before_the_next_case(tmp_path, failure):
    try:
        result = run_shop_cases(tmp_path,
            "import pytest\n"
            "from tests.integration.test_hierarchy_jobs import shop, shop_image, git\n"
            "seen = []\n"
            "failure = %r\n" % failure +
            "@pytest.fixture\n"
            "def earlier():\n"
            "    yield\n"
            "    if failure == 'teardown_write':\n"
            "        active, pristine, dirty = seen[0]\n"
            "        active.chmod(0o700)\n"
            "        (active / 'teardown.log').write_text('last teardown evidence')\n"
            "        active.chmod(0o500)\n"
            "        seen[0] = active, pristine, shop_image(active)\n"
            "@pytest.fixture\n"
            "def finish():\n"
            "    yield\n"
            "    if failure == 'teardown': pytest.fail('intentional teardown failure')\n"
            "def test_first(earlier, shop, finish):\n"
            "    pristine = shop_image(shop.tmp)\n"
            "    shop.request_job('retain-evidence', 'touch')\n"
            "    shop.run_open()\n"
            "    (shop.checkout / 'src/app.py').write_text('failed case edit\\n')\n"
            "    git(shop.checkout, 'add', 'src/app.py')\n"
            "    (shop.base / 'team.json').write_text('failed case record')\n"
            "    if failure == 'keep': (shop.tmp / '.keep').touch()\n"
            "    if failure == 'nested_keep': (shop.checkout / 'src/.keep').touch()\n"
            "    shop.recipes_path.chmod(0o400)\n"
            "    shop.tmp.chmod(0o500)\n"
            "    seen.append((shop.tmp, pristine, shop_image(shop.tmp)))\n"
            "    if failure in ('call', 'teardown_write'): pytest.fail('intentional call failure')\n"
            "def test_second(shop):\n"
            "    active, pristine, dirty = seen[0]\n"
            "    retained = [p for p in active.parent.glob('retained-*') if p.is_dir()]\n"
            "    assert len(retained) == 1\n"
            "    assert shop_image(retained[0]) == dirty\n"
            "    assert (retained[0] / 'recipe-ran').read_text() == 'ran\\n'\n"
            "    assert shop.tmp == active and shop_image(shop.tmp) == pristine\n")
        expected = "1 failed, 1 passed" if failure in ("call", "teardown_write") else "2 passed"
        assert result.returncode == (0 if failure in ("keep", "nested_keep") else 1), result.stdout + result.stderr
        assert expected in result.stdout, result.stdout + result.stderr
        assert ("error" in result.stdout.strip().splitlines()[-1]) == (failure == "teardown"), result.stdout
        retained = [path for path in (tmp_path / "nested").glob("jobs-shop-main*/retained-*")
                    if not path.parent.is_symlink() and path.is_dir()]
        assert len(retained) == 1
        assert (retained[0] / "recipe-ran").read_text() == "ran\n"
        metadata = json.loads(retained[0].with_suffix(".json").read_text())
        assert metadata["nodeid"].endswith("::test_first")
        assert metadata["reason"] == ("marker present" if failure in ("keep", "nested_keep") else "failure count rose")
        assert isinstance(metadata["time"], (int, float))
    finally:
        if (tmp_path / "nested").exists():
            remove_tree(tmp_path / "nested")


def test_rf36_retention_names_the_shop_owner_after_an_unrelated_failure(tmp_path):
    try:
        result = run_shop_cases(tmp_path,
            "import json, pytest\n"
            "from tests.integration.test_hierarchy_jobs import shop\n"
            "seen = []\n"
            "def test_first(shop, request):\n"
            "    seen.append((shop.tmp, request.node.nodeid))\n"
            "    shop.sentinel.write_text('passing owner')\n"
            "def test_unrelated():\n"
            "    pytest.fail('unrelated case failure')\n"
            "def test_second(shop):\n"
            "    active, owner = seen[0]\n"
            "    metadata = json.loads((active.parent / 'retained-1.json').read_text())\n"
            "    assert metadata['nodeid'] == owner\n"
            "    assert metadata['reason'] == 'failure count rose'\n"
            "    assert (active.parent / 'retained-1/recipe-ran').read_text() == 'passing owner'\n"
            "    assert not shop.sentinel.exists()\n"
            "def test_third(shop):\n"
            "    assert not (shop.tmp.parent / 'retained-2').exists()\n")
        assert result.returncode == 1, result.stdout + result.stderr
        assert "1 failed, 3 passed" in result.stdout
    finally:
        if (tmp_path / "nested").exists():
            remove_tree(tmp_path / "nested")


@pytest.mark.parametrize("collision", ["tree", "sidecar"])
def test_rf36_retention_collision_refuses_before_deleting_evidence_and_can_retry(tmp_path_factory, request, collision):
    session = SimpleNamespace(stash=pytest.Stash(), addfinalizer=request.session.addfinalizer, testsfailed=0)
    isolated = SimpleNamespace(session=session, config=request.config, node=request.node)
    try:
        built = worker_shop(tmp_path_factory, isolated)
        built.sentinel.write_text("failure evidence")
        (built.tmp / ".keep").touch()
        before = shop_image(built.tmp)
        destination = built.tmp.parent / "retained-1"
        if collision == "tree":
            destination.mkdir()
        obstacle = destination / "existing" if collision == "tree" else destination.with_suffix(".json")
        obstacle.write_text("earlier evidence")
        with pytest.raises(FileExistsError, match="retained Shop destination already exists") as failure:
            worker_shop(tmp_path_factory, isolated)
        assert failure.value.errno == errno.EEXIST
        assert shop_image(built.tmp) == before
        assert obstacle.read_text() == "earlier evidence"
        obstacle.unlink()
        if collision == "tree":
            destination.rmdir()
        restored = worker_shop(tmp_path_factory, isolated)
        assert restored.tmp == built.tmp and not restored.sentinel.exists()
        assert shop_image(destination) == before
    finally:
        if _WORKER_SHOP in session.stash:
            remove_tree(session.stash[_WORKER_SHOP].snapshot.parent)


@pytest.mark.parametrize("module,fixture", [
    ("jobs", "shop"), ("jobs", "kind_shop"),
    ("jobs_census_policy", "shop"), ("jobs_census_policy", "policy_shop"),
    ("recovery", "shop"), ("job_dependencies", "shop"), ("job_results", "shop"),
    ("jobs_derive", "shop"), ("git_reads", "shop")])
def test_rf36_fresh_optout_resolves_in_every_using_module(tmp_path, module, fixture):
    try:
        source = (
            "import pytest\n"
            "from tests.integration import test_hierarchy_%s as fixtures\n"
            "%s = fixtures.%s\n"
            "if hasattr(fixtures, 'fresh_shop'): fresh_shop = fixtures.fresh_shop\n"
            "@pytest.mark.parametrize(%r, ['fresh'], indirect=True)\n"
            "def test_fresh(%s, tmp_path):\n"
            "    assert %s.tmp == tmp_path\n"
            "    assert not %s.sentinel.exists()\n" % (module, fixture, fixture, fixture, fixture, fixture, fixture))
        result = run_shop_cases(tmp_path, source)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "1 passed" in result.stdout
    finally:
        if (tmp_path / "nested").exists():
            remove_tree(tmp_path / "nested")


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
    folder = Path(tempfile.mkdtemp(prefix="census-child-", dir=tmp_path))
    fake, ready, errors = folder / name, folder / "ready", folder / "stderr.log"
    # A later launch must never truncate a script an earlier child is still opening.
    fake.write_text("import os, time\nwith open(%r, 'x') as stream:\n    stream.write(str(os.getpid()))\ntime.sleep(60)\n"
                    % str(ready))
    fake.chmod(0o500)
    with errors.open("wb") as stream:
        launcher = subprocess.run(["sh", "-c", '"$@" >/dev/null & echo $!', "sh", sys.executable, str(fake)],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stream, text=True, timeout=5)
    details = {"folder": str(folder), "launcher_returncode": launcher.returncode, "launcher_stdout": launcher.stdout}

    def diagnostic():
        return json.dumps({**details, "stderr": errors.read_text(errors="replace")[-4096:]}, sort_keys=True)

    assert launcher.returncode == 0 and launcher.stdout.strip().isdigit(), "census fixture launch failed: " + diagnostic()
    pid = int(launcher.stdout.strip())
    details["pid"] = pid
    (folder / "launch.json").write_text(json.dumps(details, sort_keys=True) + "\n")
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                state = Path("/proc/%d/stat" % pid).read_text().rpartition(")")[2].split()[0]
            except (FileNotFoundError, ProcessLookupError):
                state = "absent"
            assert state not in ("absent", "Z", "X"), "census fixture exited before readiness: " + diagnostic()
            if ready.exists() and ready.read_text() == str(pid):
                return pid, folder
            time.sleep(0.01)
        raise AssertionError("census fixture did not become ready within 5 seconds: " + diagnostic())
    except BaseException:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # Preserve the readiness failure when its child has already exited.
        assert finished(pid), "census fixture could not be stopped: " + diagnostic()
        raise


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


JOB_HOLDER = "job:pilot/job-1"
# (kind the job asks for, another kind its holder already has). Each kind is a slot class of its own.
OTHER_KIND_CASES = [("heavy", "writer"), ("heavy", "heavy-tests"), ("heavy-tests", "writer"), ("heavy-tests", "heavy")]


kind_shop = shop


def request_kind_job(shop, kind):
    """Job "job-1" asks for `kind`; its only side effect is shop.sentinel, written only if its command runs."""
    touch = "open(%r, 'a').write('ran\\n')" % str(shop.sentinel)
    shop.recipes["recipes"]["heavy-touch"] = shop.command(["$python", "-c", touch], heavy=True,
                                                          heavy_tests=kind == "heavy-tests")
    shop.save_recipes()
    shop.request_job("job-1", "heavy-touch")


def fill_with_other_holders(shop, kind):
    """Grant every `kind` slot to a holder that is not the job. Returns their request ids."""
    taken = []
    for _ in range(shop.workspace.run("status")["capacity"][kind]["limit"]):
        taken.append(shop.workspace.ask("pilot", kind, "other-" + uuid.uuid4().hex[:12]))
        assert shop.workspace.grant(kind)["request_id"] == taken[-1]
    return taken


def hold_only_other_kind(shop, kind, state):
    """Unlike manual_grant, the job's holder gets nothing of the kind it asks for: only `kind`, queued or granted."""
    request_id = shop.workspace.ask("pilot", kind, JOB_HOLDER)
    if state == "granted":
        assert shop.workspace.grant(kind)["request_id"] == request_id
    return request_id


def ledger_rows(shop, holder=JOB_HOLDER, initiative="pilot"):
    """The holder's requests filed by `initiative` (None: any), replayed from the event log: request_id -> {kind, state}."""
    rows = {}
    states = {"grant": "granted", "release": "released", "withdraw": "withdrawn"}
    for event in shop.events():
        data = event["data"]
        if event["kind"] == "request" and data["holder"] == holder and initiative in (None, data["initiative"]):
            rows[data["request_id"]] = {"kind": data["kind"], "state": "queued"}
        elif event["kind"] in states and data.get("request_id") in rows:
            rows[data["request_id"]]["state"] = states[event["kind"]]
    return rows


def requests_of(shop, kind, holder=JOB_HOLDER):
    return {identifier: row["state"] for identifier, row in ledger_rows(shop, holder).items() if row["kind"] == kind}


def assert_did_not_run(shop, identifier="job-1"):
    folder = shop.workspace.store / "jobs" / "pilot" / identifier
    assert not (folder / "result.json").exists() and not (folder / "claim.json").exists()
    assert not shop.sentinel.exists(), "the job's command ran while its own kind had no free slot"
    assert shop.receipts(identifier) == [] and identifier in shop.open_jobs()


@pytest.mark.parametrize("state", ["granted", "queued"])
@pytest.mark.parametrize("kind, other", OTHER_KIND_CASES)
def test_a_reservation_of_another_kind_never_lets_a_job_past_its_own_full_ledger(kind_shop, kind, other, state):
    shop = kind_shop
    fill_with_other_holders(shop, kind)
    other_request = hold_only_other_kind(shop, other, state)
    request_kind_job(shop, kind)
    row = next(row for row in shop.run_open(expect=3)["rows"] if row.get("job") == "pilot/job-1")
    if other in ("heavy", "heavy-tests") and state == "granted":
        assert (row["state"], row["reason"], row["request_id"]) == ("waiting", "stale_grant", other_request)
        assert requests_of(shop, kind) == {}, "no second slot while the stale grant is held"
        assert_did_not_run(shop)
        return
    assert (row["state"], row["reason"], row["kind"]) == ("waiting", "capacity_full", kind)
    assert row["capacity"]["held"] == row["capacity"]["limit"]
    assert_did_not_run(shop)
    # The job asked for its own kind even though its holder already had a request of another kind.
    assert list(requests_of(shop, kind).values()) == ["queued"]
    other_state = "withdrawn" if other in ("heavy", "heavy-tests") else state
    assert ledger_rows(shop)[other_request] == {"kind": other, "state": other_state}
    if other_state == "withdrawn":
        assert withdrawals(shop)[other_request] == "job runner"
    shop.run_open(expect=3)
    assert len(requests_of(shop, kind)) == 1, "a waiting job must not queue its own kind twice"
    assert_did_not_run(shop)


@pytest.mark.parametrize("kind, other", OTHER_KIND_CASES)
def test_a_job_holding_another_kind_gets_its_own_grant_once_a_slot_frees(kind_shop, kind, other):
    shop = kind_shop
    taken = fill_with_other_holders(shop, kind)
    other_request = hold_only_other_kind(shop, other, "granted")
    request_kind_job(shop, kind)
    assert shop.run_open(expect=3)["rows"][0]["state"] == "waiting"
    if other in ("heavy", "heavy-tests"):
        assert requests_of(shop, kind) == {}
        shop.workspace.release(other_request)  # Root's evidence-backed settlement of the stale grant.
    shop.workspace.release(taken[0])
    row = shop.run_open()["rows"][0]
    assert row["state"] == "completed" and shop.sentinel.exists()
    assert shop.states("job-1") == ["started", "completed"]
    (own_request, own_state), = requests_of(shop, kind).items()
    grants = [event["data"]["request_id"] for event in shop.events() if event["kind"] == "grant"]
    assert own_request in grants, "the job ran on a grant of its own kind, written by the normal grant path"
    # Settlement is holder-wide: a finished job's one-use holder keeps nothing, so no slot is stranded.
    assert own_state == "released" and ledger_rows(shop)[other_request]["state"] == "released"
    released = [event["data"] for event in shop.events() if event["kind"] == "release"
                and event["data"]["request_id"] in (own_request, other_request)]
    own_evidence = str(shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json")
    assert next(data for data in released if data["request_id"] == own_request)["evidence"]["path"] == own_evidence
    if other == "writer":
        assert [data["evidence"]["path"] for data in released] == [own_evidence] * 2
    assert shop.workspace.run("status")["capacity"][kind]["used"] == len(taken) - 1


FOREIGN = "intruder"


def file_foreign_row(shop, kind, state, holder=JOB_HOLDER):
    """Another initiative files a request carrying this job's holder. The workspace accepts any holder string and
    de-duplicates on (kind, holder) across the whole ledger, so the job's own initiative cannot file that kind meanwhile."""
    shop.workspace.register(FOREIGN)
    request_id = shop.workspace.ask(FOREIGN, kind, holder)
    if state == "granted":
        assert shop.workspace.grant(kind)["request_id"] == request_id
    return request_id


def clear_foreign_row(shop, request_id, state):
    if state == "granted":
        shop.workspace.release(request_id)
    else:
        shop.workspace.run("withdraw", {"request_id": request_id, "source": "root checked who filed it"})


def job_row(answer, identifier="job-1"):
    return next(row for row in answer["rows"] if row.get("job") == "pilot/" + identifier)


def request_dependent(shop, parent, identifier, recipe="touch"):
    packet = {"schema": "aegis.hierarchy-job-packet/v2", "recipe": recipe, **shop.head(),
              "recipes_sha256": hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest(),
              "after": {"message_id": "first-check", "sha256": parent["sha256"]}}
    return shop.request_job(identifier, recipe, raw=json.dumps(packet))


def foreign_touches(shop, request_id):
    return [event["kind"] for event in shop.events() if event["kind"] in ("grant", "release", "withdraw")
            and event["data"]["request_id"] == request_id]


@pytest.mark.parametrize("state", ["granted", "queued"])
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_another_initiatives_row_carrying_the_jobs_holder_never_admits_the_job(kind_shop, kind, state):
    shop = kind_shop
    foreign = file_foreign_row(shop, kind, state)
    request_kind_job(shop, kind)
    for _ in range(2):
        row = job_row(shop.run_open(expect=3))
        assert (row["state"], row["reason"], row["kind"]) == ("waiting", "holder_conflict", kind)
        assert (row["request_id"], row["initiative"]) == (foreign, FOREIGN)
        assert foreign in row["next_action"] and "withdraw or release" in row["next_action"]
        assert_did_not_run(shop)
        assert ledger_rows(shop) == {}, "the job filed nothing and borrowed nothing"
        assert ledger_rows(shop, initiative=FOREIGN)[foreign] == {"kind": kind, "state": state}
        assert foreign_touches(shop, foreign) == (["grant"] if state == "granted" else [])
    # Once root clears the foreign row, the job takes the normal path under its own initiative.
    clear_foreign_row(shop, foreign, state)
    assert job_row(shop.run_open())["state"] == "completed" and shop.sentinel.exists()
    assert list(ledger_rows(shop).values()) == [{"kind": kind, "state": "released"}]


@pytest.mark.parametrize("state", ["granted", "queued"])
def test_settlement_frees_only_its_own_initiatives_rows_and_reports_a_foreign_one(kind_shop, state):
    shop = kind_shop
    foreign = file_foreign_row(shop, "writer", state)
    request_kind_job(shop, "heavy")
    assert job_row(shop.run_open())["state"] == "completed"
    assert list(ledger_rows(shop).values()) == [{"kind": "heavy", "state": "released"}]
    # The job's result is no evidence about another initiative's row: it is neither released nor withdrawn.
    assert ledger_rows(shop, initiative=FOREIGN)[foreign] == {"kind": "writer", "state": state}
    assert foreign_touches(shop, foreign) == (["grant"] if state == "granted" else [])
    assert shop.run_open()["rows"] == [], "the finished job is not settled again on every pass"
    report = shop.jobs("recovery-status", expect=3)
    # The filing initiative retains it; the affected initiative's own foreign_reservation blocker is pinned separately.
    blocker = next(row for row in report["blockers"]
                   if row.get("request_id") == foreign and row["reason"] == "retained_reservation")
    assert (blocker["initiative"], blocker["holder"]) == (FOREIGN, JOB_HOLDER)
    job = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
    assert job["state"] == "finished"
    assert [row["initiative"] for row in job["reservations"]] == ["pilot"]
    assert job["foreign_reservations"] == [{"request_id": foreign, "initiative": FOREIGN, "kind": "writer", "state": state}]


def test_a_foreign_row_under_a_predecessors_holder_holds_its_dependent_with_a_named_reason(kind_shop):
    shop = kind_shop
    parent = shop.request_job("first-check", "ok")
    assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    foreign = file_foreign_row(shop, "writer", "queued", holder="job:pilot/first-check")
    request_dependent(shop, parent, "job-2")
    row = job_row(shop.run_open(expect=3), "job-2")
    assert (row["state"], row["reason"]) == ("waiting", "foreign_reservation")
    assert foreign in row["detail"] and FOREIGN in row["detail"] and "withdraw or release" in row["detail"]
    assert_did_not_run(shop, "job-2")
    clear_foreign_row(shop, foreign, "queued")
    assert job_row(shop.run_open(), "job-2")["state"] == "completed"


def test_a_foreign_row_under_a_pending_dependents_holder_never_refuses_it(kind_shop):
    shop = kind_shop
    parent = shop.request_job("first-check", "ok")
    foreign = file_foreign_row(shop, "writer", "granted", holder="job:pilot/job-2")
    request_dependent(shop, parent, "job-2")
    row = job_row(shop.run_open(expect=3), "job-2")
    # Another initiative's row is not this job's reservation: no terminal refusal, nothing released.
    assert (row["state"], row["reason"]) == ("waiting", "dependency_pending")
    assert_did_not_run(shop, "job-2")
    assert job_row(shop.run_open(), "job-2")["state"] == "completed" and shop.sentinel.exists()
    assert foreign_touches(shop, foreign) == ["grant"]


def ledger_row(**changes):
    return {"request_id": "req-00000001", "initiative": "pilot", "kind": "heavy", "holder": JOB_HOLDER,
            "state": "granted", **changes}


MALFORMED_ROWS = [None, "row", ["list"], 7, ledger_row(holder=None), ledger_row(holder=7), ledger_row(kind=None),
                  ledger_row(state=["granted"]), ledger_row(initiative=None),
                  {key: value for key, value in ledger_row().items() if key != "holder"},
                  {key: value for key, value in ledger_row().items() if key != "initiative"}]


@pytest.mark.parametrize("wide", ["kind", "holder"])
@pytest.mark.parametrize("malformed", MALFORMED_ROWS, ids=lambda value: repr(value)[:40])
def test_wide_ledger_lookups_refuse_a_malformed_row_and_exact_lookups_match_nothing_in_it(malformed, wide):
    jobs = load_jobs_module()
    good = ledger_row(request_id="req-00000002")
    filters = {"kind": jobs.ANY_KIND if wide == "kind" else "heavy", "initiative": "pilot", "states": jobs.OPEN_STATES}
    holder = jobs.ANY_HOLDER if wide == "holder" else JOB_HOLDER
    with pytest.raises(ValueError, match="malformed ledger request row") as raised:
        jobs.holder_requests([good, malformed], holder, **filters)
    assert "event log" in str(raised.value) and "req-" not in str(raised.value)
    exact = {"kind": "heavy", "initiative": "pilot", "states": jobs.OPEN_STATES}
    assert jobs.holder_requests([malformed, good], JOB_HOLDER, **exact) == [good]


@pytest.mark.parametrize("changes, message", [
    ({"kind": "Heavy"}, "use one of writer, heavy, heavy-tests, or ANY_KIND"),
    ({"kind": None}, "use one of writer, heavy, heavy-tests, or ANY_KIND"),
    ({"kind": ""}, "use one of writer, heavy, heavy-tests, or ANY_KIND"),
    ({"initiative": ""}, "pass the job's initiative id, or ANY_INITIATIVE"),
    ({"initiative": None}, "pass the job's initiative id, or ANY_INITIATIVE"),
    ({"holder": ""}, "pass a holder string, or ANY_HOLDER"),
    ({"holder": None}, "pass a holder string, or ANY_HOLDER"),
    ({"states": ()}, "non-empty tuple of queued, granted, released, withdrawn"),
    ({"states": ["granted"]}, "non-empty tuple of queued, granted, released, withdrawn"),
    ({"states": ("granted", "held")}, "non-empty tuple of queued, granted, released, withdrawn"),
])
def test_holder_requests_refuses_an_unclear_filter_and_says_what_to_pass(changes, message):
    jobs = load_jobs_module()
    arguments = {"holder": JOB_HOLDER, "kind": "heavy", "initiative": "pilot", "states": ("granted",), **changes}
    holder = arguments.pop("holder")
    with pytest.raises(ValueError, match=message):
        jobs.holder_requests([ledger_row()], holder, **arguments)


def test_holder_requests_has_no_default_kind_or_initiative_and_binds_both():
    jobs = load_jobs_module()
    with pytest.raises(TypeError):
        jobs.holder_requests([ledger_row()], JOB_HOLDER, kind="heavy", states=("granted",))
    with pytest.raises(TypeError):
        jobs.holder_requests([ledger_row()], JOB_HOLDER, initiative="pilot", states=("granted",))
    own, foreign, other = ledger_row(), ledger_row(request_id="req-2", initiative=FOREIGN), ledger_row(kind="writer")
    rows = [own, foreign, other]
    assert jobs.holder_requests(rows, JOB_HOLDER, kind="heavy", initiative="pilot", states=("granted",)) == [own]
    assert jobs.holder_requests(rows, JOB_HOLDER, kind="heavy", initiative=jobs.ANY_INITIATIVE,
                                states=("granted",)) == [own, foreign]
    assert jobs.holder_requests(rows, JOB_HOLDER, kind=jobs.ANY_KIND, initiative="pilot",
                                states=("granted",)) == [own, other]


# case: (filing initiative, holder, claim folder under <store>/jobs, the claim's "job", exempt from the census).
# REFUSED: the census refuses. A claim in a job's own folder that names another job is corruption, not outside load.
REFUSED = "refused"
CENSUS_EXEMPTION_CASES = {
    "own-initiative": ("pilot", JOB_HOLDER, "pilot/job-1", "pilot/job-1", True),
    "foreign-initiative": (FOREIGN, JOB_HOLDER, "pilot/job-1", "pilot/job-1", False),
    "holder-names-another-initiative": ("pilot", "job:" + FOREIGN + "/job-1", FOREIGN + "/job-1", FOREIGN + "/job-1", False),
    "holder-without-initiative": ("pilot", "job:job-1", "job-1", "job-1", False),
    "holder-with-extra-segment": ("pilot", "job:pilot/job-1/extra", "pilot/job-1/extra", "pilot/job-1/extra", False),
    "other-holders-claim": ("pilot", JOB_HOLDER, "pilot/job-1", "pilot/job-2", REFUSED),
    # A foreign row never reads the claim, so it can neither exempt a process nor make the census refuse.
    "foreign-initiative-other-holders-claim": (FOREIGN, JOB_HOLDER, "pilot/job-1", "pilot/job-2", False),
}


def live_claim(jobs, pid, job_id):
    return {"pid": pid, "start": jobs.process_start(pid), "job": job_id, "at": "2026-11-09T00:00:00Z",
            "process_scope": jobs.process_scope(), "recipes_sha256": None}


@pytest.mark.parametrize("kind_shop", ["fresh"], indirect=True)
@pytest.mark.parametrize("row_kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("case", sorted(CENSUS_EXEMPTION_CASES))
def test_only_a_canonical_own_initiative_grant_exempts_a_live_process_from_the_real_census(kind_shop, case, row_kind):
    """The /proc branch, not the fixture: a granted row's holder names whose live processes are ledger work."""
    shop = kind_shop
    filer, holder, folder, claimed, exempt = CENSUS_EXEMPTION_CASES[case]
    if row_kind != "heavy":
        exempt = False  # Another kind neither exempts pytest nor reads its runner claim during the heavy census.
    shop.workspace.register(FOREIGN)
    request_id = shop.workspace.ask(filer, row_kind, holder)
    assert shop.workspace.grant(row_kind)["request_id"] == request_id
    jobs = load_jobs_module()
    child = None
    try:
        child, _ = spawn_fake_heavy(shop.tmp, "pytest")
        claim = shop.workspace.store / "jobs" / folder / "claim.json"
        claim.parent.mkdir(parents=True)
        claim.write_text(json.dumps(live_claim(jobs, child, claimed)))
        (claim.parent / "process.json").write_text(json.dumps({"step": 1, "group": child,
                                                              "start": jobs.process_start(child)}))
        ledger = jobs.Store(str(shop.workspace.store)).load()
        if exempt == REFUSED:
            with pytest.raises(ValueError, match="invalid runner claim: pilot/job-1"):
                jobs.census(shop.workspace.store, ledger, None, "heavy")
            report = shop.jobs("recovery-status", expect=3)
            assert report["process_census"]["heavy"]["state"] == "unavailable"
            assert any(row["reason"] == "census_unavailable" and row["kind"] == "heavy" for row in report["blockers"])
            shop.request_job("job-k", "heavy")
            assert shop.run_open(census=None, expect=2) == {"error": "invalid runner claim: pilot/job-1"}
            assert list(requests_of(shop, "heavy", holder="job:pilot/job-k").values()) == ["queued"]
            assert shop.receipts("job-k") == []
            return
        # Other pytest processes on the host may be outside roots too; only this child's membership is asserted.
        view = jobs.census(shop.workspace.store, ledger, None, "heavy")
        assert view["census"] == "proc"
        assert (child not in view["external_roots"]) is exempt
        if case == "holder-with-extra-segment":
            # Existing fail-closed rule: an initiative's own row under its job prefix must name a job id.
            assert shop.jobs("recovery-status", expect=2) == {"error": "invalid job message id"}
        else:
            observed = shop.jobs("recovery-status", expect=3)["process_census"]["heavy"]
            assert observed["state"] == "observed", observed
            assert (child not in observed["external_roots"]) is exempt
    finally:
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            assert finished(child), "census child %d did not stop" % child


@pytest.mark.parametrize("state", ["granted", "queued"])
@pytest.mark.parametrize("with_job", [True, False], ids=["finished-job", "no-job"])
def test_scoped_and_unscoped_recovery_agree_that_a_foreign_reservation_blocks(kind_shop, state, with_job):
    shop = kind_shop
    if with_job:
        request_kind_job(shop, "heavy")
        assert job_row(shop.run_open())["state"] == "completed"
    foreign = file_foreign_row(shop, "writer", state)
    for flags in ((), ("--initiative", "pilot")):
        report = shop.jobs("recovery-status", *flags, expect=3)
        blockers = [row for row in report["blockers"] if row["reason"] == "foreign_reservation"]
        assert len(blockers) == 1, report["blockers"]
        blocker = blockers[0]
        assert {key: blocker[key] for key in ("initiative", "job", "request_id", "filing_initiative", "kind", "state",
                                              "holder")} == {
            "initiative": "pilot", "job": "pilot/job-1", "request_id": foreign, "filing_initiative": FOREIGN,
            "kind": "writer", "state": state, "holder": JOB_HOLDER}
        assert blocker["owner"] and foreign in blocker["next_action"] and "withdraw or release" in blocker["next_action"]
        if with_job:
            job = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
            assert job["state"] == "finished" and foreign in job["next_action"], "no clean verdict while it is open"
    clear_foreign_row(shop, foreign, state)
    for flags in ((), ("--initiative", "pilot")):
        assert shop.jobs("recovery-status", *flags)["blockers"] == []


KIND_CHANGES = [("heavy", "heavy-tests"), ("heavy-tests", "heavy")]


def add_recipe_of_kind(shop, name, kind):
    shop.recipes["recipes"][name] = shop.command(["$python", "-c", "print(%r)" % name], heavy=True,
                                                 heavy_tests=kind == "heavy-tests")
    shop.save_recipes()


def withdrawals(shop):
    return {event["data"]["request_id"]: event["data"]["source"] for event in shop.events() if event["kind"] == "withdraw"}


@pytest.mark.parametrize("old, new", KIND_CHANGES)
def test_a_recipe_kind_change_withdraws_the_jobs_stale_queued_request(kind_shop, old, new):
    """The job keeps at most one open request, for the kind it needs now; a stale one never takes a slot."""
    shop = kind_shop
    taken = fill_with_other_holders(shop, old)
    request_kind_job(shop, old)
    assert job_row(shop.run_open(expect=3))["reason"] == "capacity_full"
    (stale,) = requests_of(shop, old)
    # Nothing binds a waiting job to the recipe file it was queued under. Its new kind is full, so it keeps waiting.
    shop.recipes["recipes"]["heavy-touch"]["heavy_tests"] = new == "heavy-tests"
    add_recipe_of_kind(shop, "stay", old)
    shop.request_job("job-k", "stay")
    shop.workspace.release(taken[0])
    blocking = fill_with_other_holders(shop, new)
    rows = shop.run_open(expect=3)["rows"]
    assert not any(row["state"] == "granted_elsewhere" for row in rows), rows
    assert (job_row({"rows": rows})["state"], job_row({"rows": rows})["kind"]) == ("waiting", new)
    assert job_row({"rows": rows}, "job-k")["state"] == "completed", "the freed slot went to the job that needs it"
    assert requests_of(shop, old) == {stale: "withdrawn"} and withdrawals(shop)[stale] == "job runner"
    assert list(requests_of(shop, new).values()) == ["queued"], "exactly one open request, for the kind it needs"
    shop.workspace.release(blocking[0])
    assert job_row(shop.run_open())["state"] == "completed" and shop.sentinel.exists()
    assert list(requests_of(shop, new).values()) == ["released"]


@pytest.mark.parametrize("old, new", KIND_CHANGES)
def test_a_granted_request_for_a_kind_the_recipe_no_longer_needs_holds_the_job_until_settlement(kind_shop, old, new):
    shop = kind_shop
    request_kind_job(shop, new)
    # Granted under the old recipe and never claimed, as after a crash between grant and claim.
    stale = shop.workspace.ask("pilot", old, JOB_HOLDER)
    assert shop.workspace.grant(old)["request_id"] == stale
    for _ in range(2):
        row = job_row(shop.run_open(expect=3))
        assert (row["state"], row["reason"], row["kind"], row["request_id"]) == ("waiting", "stale_grant", new, stale)
        assert all(word in row["next_action"] for word in (stale, old, new, "settle"))
        assert_did_not_run(shop)
        assert requests_of(shop, new) == {}, "never a second slot while the stale one is held"
        assert requests_of(shop, old) == {stale: "granted"}, "a wait is not settlement evidence"
    shop.workspace.release(stale)
    assert job_row(shop.run_open())["state"] == "completed" and shop.sentinel.exists()
    assert list(requests_of(shop, new).values()) == ["released"]


def test_a_grant_to_a_waiting_jobs_stale_kind_is_reported_with_its_reason(kind_shop, monkeypatch, capsys):
    shop = kind_shop
    request_kind_job(shop, "heavy-tests")
    add_recipe_of_kind(shop, "stay", "heavy")
    shop.request_job("job-k", "stay")
    jobs = load_jobs_module()
    original = jobs.enqueue

    def racing(store, job, kind, wait):
        answer = original(store, job, kind, wait)
        if job.holder == JOB_HOLDER:
            # A runner still on the old recipes files the job's heavy request after this runner's own check.
            shop.workspace.ask("pilot", "heavy", JOB_HOLDER)
        return answer

    monkeypatch.setattr(jobs, "enqueue", racing)
    assert jobs.main(shop.argv("run-open", census=[])[3:]) == 3
    rows = json.loads(capsys.readouterr().out)["rows"]
    (stale,) = requests_of(shop, "heavy")
    elsewhere = [row for row in rows if row["state"] == "granted_elsewhere"]
    assert len(elsewhere) == 1 and elsewhere[0]["request_id"] == stale
    assert (elsewhere[0]["stale_job"], elsewhere[0]["reason"]) == ("pilot/job-1", "stale_kind")
    assert "job" not in elsewhere[0], "a job keeps exactly one row of its own per pass"
    assert "heavy-tests" in elsewhere[0]["next_action"]
    assert job_row({"rows": rows}, "job-k")["state"] == "completed"
    row = job_row({"rows": rows})
    assert (row["state"], row["reason"], row["request_id"]) == ("waiting", "stale_grant", stale)
    assert_did_not_run(shop)
    assert requests_of(shop, "heavy") == {stale: "granted"}, "no release without settlement evidence"
    assert list(requests_of(shop, "heavy-tests").values()) == ["withdrawn"], "a stale-only job leaves no grantable queue"


DEPENDENT_PATHS = ["admit-queued", "admit-granted", "pre-claim-recheck"]


def test_a_stale_grant_appearing_during_current_kind_admission_runs_on_the_current_grant(kind_shop, monkeypatch, capsys):
    shop = kind_shop
    request_kind_job(shop, "heavy-tests")
    jobs = load_jobs_module()
    original, filed = jobs.grant_next, []

    def appearing(store, kind, **kwargs):
        answer = original(store, kind, **kwargs)
        # Both kinds are already granted when admission resumes: round 6 requires execution on the matching grant.
        if kind == "heavy-tests" and not filed:
            filed.append(shop.workspace.ask("pilot", "heavy", JOB_HOLDER))
            assert shop.workspace.grant("heavy")["request_id"] == filed[0]
        return answer

    monkeypatch.setattr(jobs, "grant_next", appearing)
    assert jobs.main(shop.argv("run-open", census=[])[3:]) == 0
    row = job_row(json.loads(capsys.readouterr().out))
    assert row["state"] == "completed" and shop.sentinel.exists()
    assert filed[0] in row["detail"]
    assert requests_of(shop, "heavy") == {filed[0]: "released"}
    assert list(requests_of(shop, "heavy-tests").values()) == ["released"]
    evidence = str(shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json")
    releases = [event["data"] for event in shop.events() if event["kind"] == "release"]
    assert len(releases) == 2 and all(data["evidence"]["path"] == evidence for data in releases)
    assert shop.states("job-1") == ["started", "completed"]


@pytest.mark.parametrize("kind, other", KIND_CHANGES)
@pytest.mark.parametrize("current_first", [True, False], ids=["current-first", "other-first"])
def test_a_current_kind_grant_runs_despite_another_heavy_grant(kind_shop, kind, other, current_first):
    shop = kind_shop
    request_kind_job(shop, kind)
    grants = {}
    for requested in ((kind, other) if current_first else (other, kind)):
        grants[requested] = shop.workspace.ask("pilot", requested, JOB_HOLDER)
        assert shop.workspace.grant(requested)["request_id"] == grants[requested]
    row = job_row(shop.run_open())
    assert row["state"] == "completed" and shop.sentinel.exists()
    assert grants[other] in row["detail"]
    assert ledger_rows(shop) == {request_id: {"kind": requested, "state": "released"}
                                 for requested, request_id in grants.items()}
    evidence = str(shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json")
    releases = [event["data"] for event in shop.events() if event["kind"] == "release"]
    assert {data["request_id"] for data in releases} == set(grants.values())
    assert all(data["evidence"]["path"] == evidence for data in releases)
    assert shop.states("job-1") == ["started", "completed"]
    assert shop.run_open()["rows"] == [], "the job runs and settles once"


@pytest.mark.parametrize("path", DEPENDENT_PATHS)
@pytest.mark.parametrize("foreign_state", ["queued", "granted"])
def test_another_initiatives_row_under_a_predecessors_holder_never_ends_a_capacity_admitted_dependent(
        kind_shop, monkeypatch, capsys, path, foreign_state):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    touch = "open(%r, 'a').write('ran\\n')" % str(shop.sentinel)
    shop.recipes["recipes"]["heavy-touch"] = shop.command(["$python", "-c", touch], heavy=True)
    shop.save_recipes()
    parent = shop.request_job("first-check", "ok")
    assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    request_dependent(shop, parent, "job-1", recipe="heavy-touch")
    predecessor = "job:pilot/first-check"
    taken = []
    if path == "admit-queued":
        taken = fill_with_other_holders(shop, "heavy")
        assert job_row(shop.run_open(expect=3))["reason"] == "capacity_full"
        foreign = file_foreign_row(shop, "writer", foreign_state, holder=predecessor)
    elif path == "admit-granted":
        own_request = shop.workspace.ask("pilot", "heavy", JOB_HOLDER)
        assert shop.workspace.grant("heavy")["request_id"] == own_request
        foreign = file_foreign_row(shop, "writer", foreign_state, holder=predecessor)
    else:
        # The row appears after admission, between the grant and the dependent's re-check before its claim.
        jobs = load_jobs_module()
        original, calls, filed = jobs.check_dependency, [], []

        def appearing(store, initiative, message, packet, recipes):
            if message["message_id"] == "job-1":
                calls.append(message["message_id"])
                if len(calls) == 2:  # The first call is admission; the second is the re-check before the claim.
                    assert list(requests_of(shop, "heavy").values()) == ["granted"]
                    filed.append(file_foreign_row(shop, "writer", foreign_state, holder=predecessor))
            return original(store, initiative, message, packet, recipes)

        monkeypatch.setattr(jobs, "check_dependency", appearing)
        assert jobs.main(shop.argv("run-open", census=[])[3:]) == 3
        row = job_row(json.loads(capsys.readouterr().out))
        (foreign,) = filed
        assert (row["state"], row["reason"], row["request_id"]) == ("waiting", "foreign_reservation", foreign)
    own = {request: "withdrawn" if state == "queued" else state
           for request, state in requests_of(shop, "heavy").items()}
    for _ in range(2):
        row = job_row(shop.run_open(expect=3))
        assert (row["state"], row["reason"]) == ("waiting", "foreign_reservation")
        assert (row["request_id"], row["initiative"]) == (foreign, FOREIGN) and foreign in row["detail"]
        assert_did_not_run(shop)
        assert requests_of(shop, "heavy") == own, "withdraw queued rows; retained grants still need evidence"
        assert "Root" in row["next_action"] and foreign in row["next_action"]
        for request, state in own.items():
            if state == "granted":
                assert request in row["next_action"] and "still charge capacity" in row["next_action"]
    clear_foreign_row(shop, foreign, foreign_state)
    if taken:
        shop.workspace.release(taken[0])
    assert job_row(shop.run_open())["state"] == "completed" and shop.sentinel.exists()


def test_a_closed_job_with_two_open_rows_is_settled_once_per_pass(kind_shop):
    shop = kind_shop
    lock = shop.workspace.store / ".write.lock"
    shop.recipes["recipes"]["locks"] = shop.command(["$python", "-c", lock_after_started_receipt(shop, lock)], heavy=True)
    shop.save_recipes()
    writer = shop.workspace.ask("pilot", "writer", JOB_HOLDER)
    assert shop.workspace.grant("writer")["request_id"] == writer
    shop.request_job("job-1", "locks")
    row = shop.run_open(lock_wait=0.2, expect=3)["rows"][0]
    assert row["state"] == "settle_pending" and "busy" in row["error"]
    lock.unlink()
    rows = shop.run_open()["rows"]
    assert [(row["job"], row["state"]) for row in rows] == [("pilot/job-1", "completed")]
    assert sorted(row["state"] for row in ledger_rows(shop).values()) == ["released", "released"]
    assert shop.states("job-1") == ["started", "completed"]
    assert shop.run_open()["rows"] == []


@pytest.mark.parametrize("order", ["stale-first", "matching-after-wait", "matching-first"])
def test_sibling_admission_rederives_grants_without_stranding_a_slot(kind_shop, monkeypatch, capsys, order):
    shop = kind_shop
    request_kind_job(shop, "heavy-tests")
    add_recipe_of_kind(shop, "sibling", "heavy-tests")
    add_recipe_of_kind(shop, "heavy-neighbor", "heavy")
    shop.request_job("job-b", "sibling")
    shop.request_job("job-h", "heavy-neighbor")
    jobs = load_jobs_module()
    original_enqueue, original_grant = jobs.enqueue, jobs.grant_next
    extra, appeared = [], []

    def old_runner(store, job, kind, wait):
        result = original_enqueue(store, job, kind, wait)
        if job.holder == JOB_HOLDER:
            if order == "matching-first":
                shop.workspace.grant("heavy-tests")
            extra.append(shop.workspace.ask("pilot", "heavy", JOB_HOLDER))
        return result

    def matching_arrives(store, kind, **kwargs):
        if order == "matching-after-wait" and kind == "heavy-tests" and not appeared:
            assert list(requests_of(shop, kind).values()) == ["withdrawn"]
            # Root changes the queue while this runner is outside the grant lock: A receives a matching grant,
            # then B requeues. The pass must reconsider A even though its earlier state was stale-only.
            (sibling,) = requests_of(shop, kind, holder="job:pilot/job-b")
            shop.workspace.run("withdraw", {"request_id": sibling, "source": "root race fixture"})
            appeared.append(shop.workspace.ask("pilot", kind, JOB_HOLDER))
            assert shop.workspace.grant(kind)["request_id"] == appeared[0]
            shop.workspace.ask("pilot", kind, "job:pilot/job-b")
        answer = original_grant(store, kind, **kwargs)
        if kind == "heavy" and answer[0] == 0 and answer[1]["granted"]["holder"] == JOB_HOLDER:
            expected = "granted" if order == "matching-first" else "withdrawn"
            assert list(requests_of(shop, "heavy-tests").values()) == [expected], "reconcile before grant unlocks"
        return answer

    monkeypatch.setattr(jobs, "enqueue", old_runner)
    monkeypatch.setattr(jobs, "grant_next", matching_arrives)
    assert jobs.main(shop.argv("run-open", census=[])[3:]) in (0, 3)
    report = json.loads(capsys.readouterr().out)
    assert job_row(report, "job-b")["state"] == "completed", "A's stale queue must not consume B's free slot"
    assert job_row(report, "job-h")["state"] == "completed"
    for row in report["rows"]:
        if row.get("reason") == "stale_kind":
            assert row["request_id"] == extra[0], "a matching heavy-tests grant is never called stale_kind"
        if row["state"] == "granted_elsewhere":
            assert row["request_id"] not in requests_of(shop, "heavy-tests"), "A's matching grant must execute"
    first = job_row(report)
    if order == "stale-first":
        assert (first["state"], first["reason"]) == ("waiting", "stale_grant")
        assert list(requests_of(shop, "heavy-tests").values()) == ["withdrawn"]
        assert requests_of(shop, "heavy") == {extra[0]: "granted"}
        assert_did_not_run(shop)
        second = shop.run_open(expect=3)
        assert (job_row(second)["state"], job_row(second)["reason"]) == ("waiting", "stale_grant")
        assert list(requests_of(shop, "heavy-tests").values()) == ["withdrawn"]
        shop.workspace.release(extra[0])
        assert job_row(shop.run_open())["state"] == "completed"
    else:
        assert first["state"] == "completed" and shop.sentinel.exists()
        assert all(row["state"] in ("released", "withdrawn") for row in ledger_rows(shop).values())
        assert shop.run_open()["rows"] == []
        evidence = str(shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json")
        release = next(event["data"] for event in shop.events()
                       if event["kind"] == "release" and event["data"]["request_id"] == extra[0])
        assert release["evidence"]["path"] == evidence
    assert shop.sentinel.read_text() == "ran\n"
    assert shop.states("job-1") == ["started", "completed"]
    assert shop.states("job-b") == ["started", "completed"]


@pytest.mark.parametrize("kind, other", KIND_CHANGES)
def test_stale_only_grant_withdraws_existing_current_queue_at_admission(kind_shop, kind, other):
    shop = kind_shop
    request_kind_job(shop, kind)
    current = shop.workspace.ask("pilot", kind, JOB_HOLDER)
    stale = shop.workspace.ask("pilot", other, JOB_HOLDER)
    assert shop.workspace.grant(other)["request_id"] == stale
    for _ in range(2):
        row = job_row(shop.run_open(expect=3))
        assert (row["state"], row["reason"]) == ("waiting", "stale_grant")
        assert requests_of(shop, kind) == {current: "withdrawn"}
        assert withdrawals(shop)[current] == "job runner"
        assert requests_of(shop, other) == {stale: "granted"}
        assert_did_not_run(shop)
    shop.workspace.release(stale)
    assert job_row(shop.run_open())["state"] == "completed"


@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_a_matching_grant_released_without_an_execution_claim_never_starts_the_job(kind_shop, monkeypatch, capsys, kind):
    shop = kind_shop
    request_kind_job(shop, kind)
    jobs = load_jobs_module()
    original, released = jobs.grant_next, []

    def release_before_claim(store, granted_kind, **kwargs):
        answer = original(store, granted_kind, **kwargs)
        if answer[0] == 0 and not released:
            released.append(answer[1]["granted"]["request_id"])
            shop.workspace.release(released[0])
        return answer

    monkeypatch.setattr(jobs, "grant_next", release_before_claim)
    assert jobs.main(shop.argv("run-open", census=[])[3:]) == 3
    row = job_row(json.loads(capsys.readouterr().out))
    assert row["state"] == "waiting" and row["reason"] == "queue_empty"
    assert requests_of(shop, kind) == {released[0]: "released"}
    assert_did_not_run(shop)
    assert job_row(shop.run_open())["state"] == "completed" and shop.sentinel.exists()


@pytest.mark.parametrize("fault, reason", [
    ("withdraw-limit", "post_grant_reconcile_failed"),
    ("withdraw-unexpected", "post_grant_reconcile_failed"),
    ("publication-busy", "post_grant_store_busy"),
    ("extra-replay", "post_grant_ledger_unreadable"),
])
def test_a_durable_grant_fault_retains_rows_audit_and_recovers(kind_shop, monkeypatch, capsys, fault, reason):
    shop = kind_shop
    shop.request_job("job-prior", "ok")
    withdrawal = fault in ("withdraw-limit", "withdraw-unexpected")
    kind = "heavy-tests" if withdrawal else "heavy"
    request_kind_job(shop, kind)
    shop.recipes["census_outside_policy"] = "count"
    shop.save_recipes()
    foreign = None
    if withdrawal:
        other_root, checkout = add_initiative(shop, "later", 20)
        shop.request_job("job-later", "heavy", root=other_root, prefix="later", checkout=checkout)
    elif fault == "publication-busy":
        other_root, checkout = add_initiative(shop, "urgent", 1)
        shop.request_job("job-high", "heavy", root=other_root, prefix="urgent", checkout=checkout)
        foreign = shop.workspace.ask("urgent", "heavy", "job:urgent/job-high")
    jobs = load_jobs_module()
    original_append, original_link, original_unlink, original_load = jobs.Store.append, os.link, Path.unlink, jobs.Store.load
    events, census_folder = shop.workspace.store / "events", shop.workspace.store / "census"
    lock = shop.workspace.store / ".write.lock"
    first_event = sorted(events.iterdir())[0]
    first_bytes = first_event.read_bytes()
    durable, publications, injected, old_request, post_reads = [], [], [], [], []

    def append(store, ledger, event_kind, data):
        # The workspace Store is the external persistence boundary. Its real grant is always written; only the
        # subsequent withdrawal models the history-limit refusal from Store.append, without 10,000 subprocesses.
        if withdrawal and event_kind == "withdraw" and durable:
            injected.append("history-limit")
            if fault == "withdraw-unexpected":
                raise RuntimeError("private-store-failure-must-not-leak")
            raise ValueError("workspace event history limit reached")
        event = original_append(store, ledger, event_kind, data)
        if event_kind == "grant":
            durable.append(data["request_id"])
        return event

    def unlink(path, *args, **kwargs):
        result = original_unlink(path, *args, **kwargs)
        if withdrawal and path == lock and not old_request and requests_of(shop, kind):
            old_request.append(shop.workspace.ask("pilot", "heavy", JOB_HOLDER))
        return result

    def link(source, target, *args, **kwargs):
        if Path(target).parent == census_folder:
            publications.append(Path(target).name)
            if fault == "publication-busy":
                lock.write_text("fixture active store writer")
                injected.append("publication-and-store-busy")
                raise PermissionError("private-publication-error-must-not-leak")
        return original_link(source, target, *args, **kwargs)

    def load(store):
        if fault == "extra-replay" and durable:
            post_reads.append("replay")
            if len(post_reads) == 1:  # The first locked post-grant snapshot; no redundant detail-only replay exists.
                first_event.write_bytes(b"{}")
                injected.append("malformed-event")
        return original_load(store)

    flags = ("--initiative", "pilot") if fault == "publication-busy" else ()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(jobs.Store, "append", append)
            patch.setattr(Path, "unlink", unlink)
            patch.setattr(os, "link", link)
            patch.setattr(jobs.Store, "load", load)
            code = jobs.main(shop.argv("run-open", *flags, census=[], lock_wait=0)[3:])
            report = json.loads(capsys.readouterr().out)
    finally:
        first_event.write_bytes(first_bytes)
        if lock.exists():
            lock.unlink()
    assert injected, "the fault must fire after a real durable grant"
    assert len(durable) == 1
    assert code == 3, report
    assert job_row(report, "job-prior")["state"] == "completed", "retain rows written before the grant"
    request_id = durable[0]
    grant = next(row for row in report["rows"] if row.get("request_id") == request_id
                 and "z_census" in row)
    assert grant.get("failure_reason", grant.get("reason")) == reason
    summary = grant["z_census"]
    assert summary["request_id"] == request_id and summary["outside_policy"] == "count"
    assert publications == [request_id + ".json"], "every durable explicit-policy grant attempts publication once"
    assert not shop.sentinel.exists() and shop.receipts("job-1") == []
    assert "private-publication-error" not in json.dumps(report)
    assert "private-store-failure" not in json.dumps(report) and "private-claim-error" not in json.dumps(report)
    if fault == "publication-busy":
        assert grant["state"] == "granted_elsewhere" and request_id == foreign
        assert (summary["census"], summary["publish_failed"], summary["reason"]) == (
            "publish_failed", True, "publish_failed")
        assert shop.run_open("--initiative", "urgent")["rows"][0]["state"] == "completed"
        result = shop.workspace.store / "jobs/urgent/job-high/result.json"
    else:
        assert summary["census"] == "fixture"
        assert (census_folder / (request_id + ".json")).is_file()
        if withdrawal:
            assert request_id == old_request[0] and grant["state"] == "granted_elsewhere"
            assert job_row(shop.run_open(expect=3))["reason"] == "stale_grant"
            matching = shop.workspace.ask("pilot", "heavy-tests", JOB_HOLDER)
            assert shop.workspace.grant("heavy-tests")["request_id"] == matching
        assert job_row(shop.run_open())["state"] == "completed"
        result = shop.workspace.store / "jobs/pilot/job-1/result.json"
    releases = [event["data"] for event in shop.events()
                if event["kind"] == "release" and event["data"]["request_id"] == request_id]
    assert len(releases) == 1 and releases[0]["evidence"]["path"] == str(result)
    assert releases[0]["evidence"]["sha256"] == hashlib.sha256(result.read_bytes()).hexdigest()
    if fault == "publication-busy":
        assert job_row(shop.run_open())["state"] == "completed"
    assert shop.sentinel.read_text() == "ran\n"
    assert shop.run_open()["rows"] == []


@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
def test_a_handled_grant_keeps_later_contention_legacy_bytes(kind_shop, monkeypatch, capsys, kind, policy):
    shop = kind_shop
    request_kind_job(shop, "heavy")
    add_recipe_of_kind(shop, "second", kind)
    shop.request_job("job-2", "second")
    if policy is not None:
        shop.recipes["census_outside_policy"] = policy
        shop.save_recipes()
    limit = shop.workspace.run("status")["capacity"]["heavy"]["limit"]
    jobs = load_jobs_module()
    lock = shop.workspace.store / ".write.lock"
    result = shop.workspace.store / "jobs/pilot/job-1/result.json"
    original_unlink = Path.unlink
    injected = []

    def unlink(path, *args, **kwargs):
        answer = original_unlink(path, *args, **kwargs)
        if path == lock and result.exists() and not injected and list(requests_of(shop, "heavy").values()) == ["released"]:
            lock.write_text("fixture concurrent store writer after completed settlement")
            injected.append(True)
        return answer

    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", unlink)
            assert jobs.main(shop.argv("run-open", "--max-jobs", "10", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
            report = json.loads(output)
    finally:
        if lock.exists():
            lock.unlink()
    assert injected and report["rows"][0]["state"] == "completed"
    expected = {"job": "pilot/job-2", "state": "waiting", "kind": kind, "reason": "store_busy"}
    if kind == "heavy":
        if policy is None:
            expected["capacity"] = {"limit": limit, "held": 0, "external_roots": [], "census": "fixture"}
        else:
            expected["z_census"] = {"outside_policy": policy, "census": "none" if policy == "ignore" else "fixture",
                                     "limit": limit, "held": 0, "external_roots_count": 0, "outside_count": 0,
                                     "outside_truncated": 0}
    # The earlier completed row is retained; the waiting row has exactly the legacy fields and capacity observation.
    assert output == json.dumps({"rows": [report["rows"][0], expected]}, sort_keys=True) + "\n"
    assert not any(str(row.get("reason", row.get("failure_reason", ""))).startswith("post_grant_") for row in report["rows"])
    folder = shop.workspace.store / "jobs/pilot/job-2"
    assert not folder.exists() and shop.receipts("job-2") == []
    assert list(requests_of(shop, kind, holder="job:pilot/job-2").values()) == ["queued"]
    assert shop.sentinel.read_text() == "ran\n"
    assert job_row(shop.run_open(), "job-2")["state"] == "completed"
    assert shop.sentinel.read_text() == "ran\n" and shop.run_open()["rows"] == []


@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_an_unhandled_grant_still_makes_contention_a_postgrant_fault(kind_shop, monkeypatch, capsys, kind):
    shop = kind_shop
    request_kind_job(shop, "heavy")
    add_recipe_of_kind(shop, "second", kind)
    shop.request_job("job-2", "second")
    shop.recipes["census_outside_policy"] = "count"
    shop.save_recipes()
    jobs = load_jobs_module()
    census_folder, lock = shop.workspace.store / "census", shop.workspace.store / ".write.lock"
    original_link = os.link
    publications = []

    def link(source, target, *args, **kwargs):
        answer = original_link(source, target, *args, **kwargs)
        if Path(target).parent == census_folder:
            publications.append(Path(target).stem)
            if len(publications) == 2:
                lock.write_text("fixture concurrent writer while second grant is unhandled")
        return answer

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "link", link)
            assert jobs.main(shop.argv("run-open", "--max-jobs", "10", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if lock.exists():
            lock.unlink()
    assert len(publications) == 2 and job_row(report)["state"] == "completed"
    row = job_row(report, "job-2")
    assert (row["state"], row["reason"], row["request_id"]) == ("waiting", "post_grant_store_busy", publications[1])
    assert row["z_census"]["request_id"] == publications[1] and "Root" in row["next_action"]
    assert requests_of(shop, kind, holder="job:pilot/job-2") == {publications[1]: "granted"}
    assert not (shop.workspace.store / "jobs/pilot/job-2").exists() and shop.receipts("job-2") == []
    assert job_row(shop.run_open(), "job-2")["state"] == "completed"
    assert requests_of(shop, kind, holder="job:pilot/job-2") == {publications[1]: "released"}


def test_a_refusal_before_any_grant_still_exits_two(kind_shop):
    shop = kind_shop
    request_kind_job(shop, "heavy")
    shop.recipes["census_outside_policy"] = "invalid"
    shop.save_recipes()
    before = shop.events()
    assert shop.run_open(expect=2) == {"error": "invalid census_outside_policy: expected count, report or ignore"}
    assert shop.events() == before
    assert_did_not_run(shop)


@pytest.mark.parametrize("foreign_state", ["queued", "granted"])
@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
def test_foreign_dependency_withdraws_its_queue_before_a_free_slot_can_be_granted(kind_shop, foreign_state, planned):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    request_kind_job(shop, "heavy-tests")
    # Replace the initial independent request with a dependent request in a fresh message; its recipe is unchanged.
    assert job_row(shop.run_open())["state"] == "completed"
    shop.sentinel.unlink()
    add_recipe_of_kind(shop, "ready-peer", "heavy-tests")
    parent = shop.request_job("first-check", "ok")
    assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    occupied = fill_with_other_holders(shop, "heavy-tests")
    request_dependent(shop, parent, "job-dependent", recipe="heavy-touch")
    assert job_row(shop.run_open(expect=3), "job-dependent")["reason"] == "capacity_full"
    (queued,) = requests_of(shop, "heavy-tests", holder="job:pilot/job-dependent")
    foreign = file_foreign_row(shop, "writer", foreign_state, holder="job:pilot/first-check")
    extras = [shop.workspace.ask("pilot", kind, "job:pilot/job-dependent") for kind in ("writer", "heavy")]
    shop.request_job("job-peer", "ready-peer")
    shop.workspace.release(occupied[0])
    report = shop.run_open(expect=3)
    dependent = job_row(report, "job-dependent")
    assert (dependent["state"], dependent["reason"]) == ("waiting", "foreign_reservation")
    if planned:
        assert "Root" in dependent["next_action"] and foreign in dependent["next_action"]
    else:
        assert set(dependent) == {"job", "state", "reason", "detail", "request_id", "initiative"}
    assert job_row(report, "job-peer")["state"] == "completed"
    assert requests_of(shop, "heavy-tests", holder="job:pilot/job-dependent") == {queued: "withdrawn"}
    assert withdrawals(shop)[queued] == "job runner"
    for request in extras:
        assert ledger_rows(shop, holder="job:pilot/job-dependent")[request]["state"] == "withdrawn"
        assert withdrawals(shop)[request] == "job runner"
    assert not any(event["kind"] == "grant" and event["data"]["request_id"] == queued for event in shop.events())
    assert_did_not_run(shop, "job-dependent")
    shop.request_job("job-peer-2", "ready-peer")
    assert job_row(shop.run_open(expect=3), "job-peer-2")["state"] == "completed"
    clear_foreign_row(shop, foreign, foreign_state)
    assert job_row(shop.run_open(), "job-dependent")["state"] == "completed"
    assert shop.sentinel.read_text() == "ran\n"


@pytest.mark.parametrize("fault", ["mailbox-busy", "before-directory", "after-directory"])
def test_job_claim_boundary_keeps_other_jobs_running_and_preserves_unknown_custody(kind_shop, monkeypatch, capsys, fault):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    plan = json.loads(host_plan(shop).read_text())
    effects = {name: shop.tmp / (name + "-ran") for name in ("a", "b", "c", "d")}
    for name in effects:
        code = "open(%r, 'x').write('ran')" % str(effects[name])
        shop.recipes["recipes"][name] = shop.command(["$python", "-c", code], heavy=True, heavy_tests=name == "d")
    shop.save_recipes()
    other_root, checkout = add_initiative(shop, "blocked", 5)
    (other_root.parent / "host-plan.json").write_text(json.dumps({**plan, "hierarchy": "blocked"}))
    parent = shop.request_job("first-check", "ok", root=other_root, prefix="blocked", checkout=checkout)
    assert shop.run_open("--initiative", "blocked")["rows"][0]["state"] == "completed"
    packet = {"schema": "aegis.hierarchy-job-packet/v2", "recipe": "b", **shop.head(checkout),
              "recipes_sha256": hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest(),
              "after": {"message_id": "first-check", "sha256": parent["sha256"]}}
    shop.request_job("job-a", "a")
    shop.request_job("job-b", "b", raw=json.dumps(packet), root=other_root, prefix="blocked", checkout=checkout)
    shop.request_job("job-c", "c")
    shop.request_job("job-d", "d")
    # A runs before B's existing grant is installed, reproducing the pass-wide coupling from the review.
    shop.workspace.ask("pilot", "heavy", "job:pilot/job-a")
    jobs = load_jobs_module()
    original_link, original_mkdir, original_open = os.link, Path.mkdir, os.open
    a_result = shop.workspace.store / "jobs/pilot/job-a/result.json"
    b_folder = shop.workspace.store / "jobs/blocked/job-b"
    mailbox_lock = other_root / ".write.lock"
    grants, injected = [], []

    def link(source, target, *args, **kwargs):
        result = original_link(source, target, *args, **kwargs)
        if Path(target) == a_result and not grants:
            grant = shop.workspace.grant("heavy")
            assert grant["holder"] == "job:blocked/job-b"
            grants.append(grant["request_id"])
            if fault == "mailbox-busy":
                mailbox_lock.write_text("fixture active mailbox writer")
                injected.append(fault)
        return result

    def mkdir(path, *args, **kwargs):
        if fault == "before-directory" and path == b_folder:
            injected.append(fault)
            raise PermissionError("fixture claim directory denied")
        return original_mkdir(path, *args, **kwargs)

    def open_claim(path, flags, *args, **kwargs):
        if fault == "after-directory" and Path(path).parent == b_folder and flags & os.O_CREAT:
            assert b_folder.is_dir()
            injected.append(fault)
            raise OSError(errno.ENOSPC, "fixture claim publication full")
        return original_open(path, flags, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "link", link)
            patch.setattr(Path, "mkdir", mkdir)
            patch.setattr(os, "open", open_claim)
            assert jobs.main(shop.argv("run-open", "--max-jobs", "10", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if mailbox_lock.exists():
            mailbox_lock.unlink()
    assert injected and len(grants) == 1, report
    blocked = next(row for row in report["rows"] if row.get("job") == "blocked/job-b")
    if fault == "after-directory":
        assert blocked["state"] == "abandoned" and blocked["reason"] == "execution_custody_unknown"
        assert blocked["process_alive"] is None and "Root" in blocked["next_action"]
        assert b_folder.exists() and not (b_folder / "claim.json").exists()
    else:
        assert blocked["state"] == "settle_pending"
        assert "Run run-open again" in blocked["next_action"]
        assert not b_folder.exists(), "a failure before the fence exists is retryable"
    for name in ("a", "c", "d"):
        assert job_row(report, "job-" + name)["state"] == "completed"
        assert effects[name].read_text() == "ran"
    assert not effects["b"].exists()
    assert ledger_rows(shop, holder="job:blocked/job-b", initiative="blocked")[grants[0]]["state"] == "granted"
    if fault == "after-directory":
        again = shop.run_open(expect=3)
        unknown = next(row for row in again["rows"] if row.get("job") == "blocked/job-b")
        assert unknown["state"] == "abandoned" and unknown["process_alive"] is None
        assert "Root" in unknown["next_action"] and not effects["b"].exists()
        assert not (b_folder / "execution.json").exists() and not (b_folder / "result.json").exists()
    else:
        assert shop.run_open()["rows"][0]["state"] == "completed"
        assert effects["b"].read_text() == "ran"
        assert ledger_rows(shop, holder="job:blocked/job-b", initiative="blocked")[grants[0]]["state"] == "released"


@pytest.mark.parametrize("busy", [True, False], ids=["busy-store", "readable-store"])
@pytest.mark.parametrize("light_first", [False, True], ids=["already-queued", "not-yet-queued"])
def test_exhausted_budget_preserves_enqueue_but_skips_kind_grant_admission(kind_shop, monkeypatch, capsys, busy, light_first):
    shop = kind_shop
    add_recipe_of_kind(shop, "heavy-tests", "heavy-tests")
    lock = shop.workspace.store / ".write.lock"
    shop.recipes["recipes"]["light"] = shop.command(["$python", "-c", "open(%r, 'x').close()" % str(lock) if busy else "pass"])
    shop.save_recipes()
    light = "aaa-light" if light_first else "zzz-light"
    if light_first:
        shop.request_job(light, "light")
    shop.request_job("job-a", "heavy")
    shop.request_job("job-d", "heavy-tests")
    if not light_first:
        shop.request_job(light, "light")
    jobs = load_jobs_module()
    original_load, original_open = jobs.Store.load, os.open
    light_result = shop.workspace.store / "jobs/pilot" / light / "result.json"
    reads, lock_attempts = [], []

    def load(store):
        if light_result.exists():
            reads.append("post-light replay")
        return original_load(store)

    def open_store(path, flags, *args, **kwargs):
        if Path(path) == lock and flags & os.O_EXCL and light_result.exists():
            lock_attempts.append("post-light lock")
        return original_open(path, flags, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(jobs.Store, "load", load)
            patch.setattr(os, "open", open_store)
            assert jobs.main(shop.argv("run-open", "--max-jobs", "1", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if lock.exists():
            lock.unlink()
    assert job_row(report, light)["state"] == "completed"
    assert [(job_row(report, name)["state"], job_row(report, name)["reason"]) for name in ("job-a", "job-d")] == [
        ("waiting", "job_limit"), ("waiting", "job_limit")]
    assert reads == ["post-light replay"] * (3 if light_first and not busy else 1), "settlement plus legacy enqueue only"
    assert lock_attempts == ["post-light lock"] * (2 if light_first else 0), "enqueue still attempts each kind; no grant snapshot"
    assert not any(event["kind"] == "grant" for event in shop.events())


def test_a_budget_exhausted_legacy_job_keeps_its_queue_position(kind_shop):
    shop = kind_shop
    add_recipe_of_kind(shop, "cargo-later", "heavy-tests")
    shop.request_job("first-light", "ok")
    shop.request_job("job-heavy", "cargo-later")
    row = job_row(shop.run_open("--max-jobs", "1", expect=3), "job-heavy")
    assert (row["state"], row["reason"]) == ("waiting", "job_limit")
    own = requests_of(shop, "heavy-tests", holder="job:pilot/job-heavy")
    assert len(own) == 1 and list(own.values()) == ["queued"]
    manual = shop.workspace.ask("pilot", "heavy-tests", "later-manual")
    assert not any(event["kind"] == "grant" for event in shop.events())
    assert job_row(shop.run_open("--max-jobs", "1"), "job-heavy")["state"] == "completed"
    assert requests_of(shop, "heavy-tests", holder="job:pilot/job-heavy") == {next(iter(own)): "released"}
    assert shop.workspace.grant("heavy-tests")["request_id"] == manual


@pytest.mark.parametrize("wide", ["kind", "holder"])
@pytest.mark.parametrize("changes", [{"state": "held"}, {"state": ""}, {"kind": "unknown"}])
def test_wide_scans_refuse_invalid_ledger_domains(changes, wide):
    jobs = load_jobs_module()
    row = ledger_row(**changes)
    with pytest.raises(ValueError, match="malformed ledger request row"):
        jobs.holder_requests([row], jobs.ANY_HOLDER if wide == "holder" else JOB_HOLDER,
                             kind=jobs.ANY_KIND if wide == "kind" else "heavy", initiative="pilot",
                             states=jobs.OPEN_STATES)
    assert jobs.holder_requests([row], JOB_HOLDER, kind="heavy", initiative="pilot", states=jobs.OPEN_STATES) == []


@pytest.mark.parametrize("stage", ["admit", "pre-claim"])
@pytest.mark.parametrize("after_fence", [False, True], ids=["before-fence", "after-fence"])
def test_reserved_dependency_refusal_respects_the_claim_boundary(kind_shop, monkeypatch, capsys, stage, after_fence):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    request_kind_job(shop, "heavy")
    assert job_row(shop.run_open())["state"] == "completed"
    shop.sentinel.unlink()
    log = shop.workspace.store / "jobs/pilot/first-check/step-1.log"
    shop.recipes["recipes"]["tamper"] = shop.command(["$python", "-c", "open(%r, 'a').write('changed')" % str(log)])
    shop.save_recipes()
    parent = shop.request_job("first-check", "ok")
    assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    original_log = log.read_bytes()
    if stage == "pre-claim":
        shop.request_job("before-dependent", "tamper")
    else:
        log.write_bytes(original_log + b"changed")
    request_dependent(shop, parent, "job-dependent", recipe="heavy-touch")
    request = shop.workspace.ask("pilot", "heavy", "job:pilot/job-dependent")
    assert shop.workspace.grant("heavy")["request_id"] == request
    folder = shop.workspace.store / "jobs/pilot/job-dependent"
    original_open, original_mkdir = os.open, Path.mkdir
    injected = []

    def open_claim(path, flags, *args, **kwargs):
        if after_fence and Path(path).parent == folder and flags & os.O_CREAT:
            assert folder.is_dir()
            injected.append("claim publication")
            raise OSError(errno.ENOSPC, "fixture claim publication full")
        return original_open(path, flags, *args, **kwargs)

    def mkdir(path, *args, **kwargs):
        if not after_fence and path == folder:
            injected.append("claim directory")
            raise PermissionError("fixture claim directory denied")
        return original_mkdir(path, *args, **kwargs)

    jobs = load_jobs_module()
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", open_claim)
        patch.setattr(Path, "mkdir", mkdir)
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        row = job_row(json.loads(capsys.readouterr().out), "job-dependent")
    assert injected
    assert row["state"] == ("abandoned" if after_fence else "settle_pending")
    if after_fence:
        assert row["reason"] == "execution_custody_unknown" and row["process_alive"] is None
        assert "Root" in row["next_action"] and folder.exists()
        again = job_row(shop.run_open(expect=3), "job-dependent")
        assert again["state"] == "abandoned" and again["process_alive"] is None
    else:
        assert "Run run-open again" in row["next_action"] and not folder.exists()
    assert requests_of(shop, "heavy", holder="job:pilot/job-dependent") == {request: "granted"}
    assert_did_not_run(shop, "job-dependent")


def test_a_derived_publication_loser_reports_pending_settlement(kind_shop, monkeypatch, capsys):
    import fcntl

    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    request = shop.workspace.ask("pilot", "writer", JOB_HOLDER)
    assert shop.workspace.grant("writer")["request_id"] == request
    jobs = load_jobs_module()
    original_link, original_flock = os.link, fcntl.flock
    folder = shop.workspace.store / "jobs/pilot/job-1"
    lock = shop.workspace.store / ".write.lock"
    contenders, entering, lost = [], [], []

    def flock(fd, operation):
        # Runner 1 completes after runner 2's admission, before runner 2 obtains execution exclusion.
        if operation == fcntl.LOCK_EX | fcntl.LOCK_NB and not entering:
            entering.append(True)
            code = jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:])
            contenders.append((code, json.loads(capsys.readouterr().out)))
            assert (folder / "execution.json").exists() and (folder / "result.json").exists()
            assert json.loads((folder / "result.json").read_bytes())["state"] == "completed"
        return original_flock(fd, operation)

    def link(source, target, *args, **kwargs):
        execution_target = (Path(target) == folder / "execution.json"
                            or (str(target) == "execution.json" and "dst_dir_fd" in kwargs))
        if execution_target and (folder / "execution.json").exists():
            lost.append("existing execution claim")
        answer = original_link(source, target, *args, **kwargs)
        if Path(target) == folder / "result.json":
            lock.write_text("fixture store writer after terminal publication")
        return answer

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "link", link)
            patch.setattr(fcntl, "flock", flock)
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if lock.exists():
            lock.unlink()
    assert len(contenders) == 1 and contenders[0][0] == 3
    assert lost == ["existing execution claim"], "the outer runner really loses publication to a completed claimant"
    assert job_row(contenders[0][1])["state"] == "settle_pending"
    assert job_row(report)["state"] == "settle_pending"
    assert "busy" in job_row(report)["error"] and "Run run-open again" in job_row(report)["next_action"]
    result = (folder / "result.json").read_bytes()
    assert json.loads(result)["state"] == "completed"
    assert ledger_rows(shop)[request]["state"] == "granted"
    assert job_row(shop.run_open())["state"] == "completed"
    assert (folder / "result.json").read_bytes() == result
    assert ledger_rows(shop)[request]["state"] == "released"


@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
def test_blocked_receipt_preserves_legacy_bytes_and_planned_action(kind_shop, planned, capsys):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    lock = shop.root / ".write.lock"
    code = lock_after_started_receipt(shop, lock) + "open(%r, 'a').write('ran\\n')" % str(shop.sentinel)
    shop.recipes["recipes"]["lock"] = shop.command(["$python", "-c", code])
    shop.save_recipes()
    shop.request_job("job-1", "lock")
    jobs = load_jobs_module()
    expected = {"job": "pilot/job-1", "state": "settle_pending",
                "error": "mailbox writer is busy; inspect an abandoned lock before retrying"}
    if planned:
        expected["next_action"] = ("Run run-open again after repairing the reported mailbox, storage or "
                                   "settlement error; an existing claim is never executed twice.")
    try:
        for _ in range(2):  # Both first settlement and visit_existing must keep the original legacy bytes.
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            assert capsys.readouterr().out == json.dumps({"rows": [expected]}, sort_keys=True) + "\n"
            assert shop.sentinel.read_text() == "ran\n"
    finally:
        if lock.exists():
            lock.unlink()
    assert job_row(shop.run_open())["state"] == "completed"
    assert shop.sentinel.read_text() == "ran\n"


@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
def test_unknown_existing_claim_preserves_legacy_reporting(kind_shop, planned, capsys):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    shop.request_job("job-1", "touch")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    folder.mkdir(parents=True)
    jobs = load_jobs_module()
    assert jobs.main(shop.argv("run-open", census=[])[3:]) == 3
    output = capsys.readouterr().out
    expected = {"job": "pilot/job-1", "state": "abandoned", "process_group": None, "process_alive": None,
                "reason": "runner visibility is unknown; retain the original claim and reservation"}
    if planned:
        action = json.loads(output)["rows"][0]["next_action"]
        assert action == JOBS2_UNVERIFIED_ACTION
        expected["next_action"] = action
    assert output == json.dumps({"rows": [expected]}, sort_keys=True) + "\n"
    assert_did_not_run(shop)


@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
@pytest.mark.parametrize("holder", ["manual-work", "job:pilot/other-job"])
def test_granted_elsewhere_preserves_legacy_reporting(kind_shop, planned, holder, capsys):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    request = shop.workspace.ask("pilot", "heavy", holder)
    shop.request_job("job-1", "heavy")
    jobs = load_jobs_module()
    assert jobs.main(shop.argv("run-open", census=[])[3:]) == 3
    output = capsys.readouterr().out
    rows = json.loads(output)["rows"]
    expected = {"state": "granted_elsewhere", "holder": holder, "request_id": request}
    if planned:
        action = rows[0]["next_action"]
        assert ("re-admit" if holder.startswith("job:") else "already authorized") in action
        expected["next_action"] = action
    assert rows[0] == expected
    assert output == json.dumps({"rows": [expected, rows[1]]}, sort_keys=True) + "\n"
    assert rows[1]["state"] == "completed"


@pytest.mark.parametrize("count", [1, 2])
def test_job_execution_reuses_its_locked_ledger_snapshot(kind_shop, monkeypatch, capsys, count):
    shop = kind_shop
    for index in range(count):
        shop.request_job("job-%d" % index, "heavy")
    jobs = load_jobs_module()
    original = jobs.Store.load
    reads = []

    def load(store):
        if not (store.path / ".write.lock").exists():
            reads.append("unlocked replay")
        return original(store)

    monkeypatch.setattr(jobs.Store, "load", load)  # Observe real storage reads, preserving every actual replay.
    assert jobs.main(shop.argv("run-open", census=[])[3:]) == 0
    report = json.loads(capsys.readouterr().out)
    assert all(row["state"] == "completed" for row in report["rows"]) and len(report["rows"]) == count
    assert reads == ["unlocked replay"] * (1 + count), "initial admission and each terminal settlement only"


@pytest.mark.parametrize("kind_shop", ["fresh"], indirect=True)
@pytest.mark.parametrize("record_state", ["missing", "stale", "live"])
def test_a_census_exemption_needs_the_jobs_recorded_process_birth(kind_shop, record_state):
    shop = kind_shop
    request = shop.workspace.ask("pilot", "heavy", JOB_HOLDER)
    assert shop.workspace.grant("heavy")["request_id"] == request
    jobs = load_jobs_module()
    child = None
    try:
        child, _ = spawn_fake_heavy(shop.tmp, "pytest")
        folder = shop.workspace.store / "jobs/pilot/job-1"
        folder.mkdir(parents=True)
        (folder / "claim.json").write_text(json.dumps(live_claim(jobs, os.getpid(), "pilot/job-1")))
        if record_state != "missing":
            start = jobs.process_start(child)
            if record_state == "stale":
                start = str(int(start) + 1)
            (folder / "process.json").write_text(json.dumps({"step": 1, "group": child, "start": start}))
        report = shop.jobs("recovery-status", census=None, expect=3)
        observed = report["process_census"]["heavy"]
        assert observed["state"] == "observed", observed
        assert (child not in observed["external_roots"]) is (record_state == "live")
    finally:
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            assert finished(child)


@pytest.mark.parametrize("kind_shop", ["fresh"], indirect=True)
def test_a_retained_heavy_claim_cannot_exempt_the_runners_next_heavy_tests_job(kind_shop, monkeypatch, capsys):
    from contextlib import contextmanager

    shop = kind_shop
    shop.workspace.run("set-limits", {"source": "owner test", "heavy_limit": 2})
    other_root, checkout = add_initiative(shop, "other", 5)
    lock = shop.root / ".write.lock"
    shop.recipes["recipes"]["retained"] = shop.command(
        ["$python", "-c", lock_after_started_receipt(shop, lock)], heavy=True)
    ready, release = shop.tmp / "next-pytest-ready", shop.tmp / "next-pytest-release"
    script = shop.tmp / "pytest.py"
    script.write_text("import os, time\nopen(%r, 'x').write(str(os.getpid()))\n"
                      "deadline = time.monotonic() + 40\nwhile not os.path.exists(%r):\n"
                      "    if time.monotonic() > deadline: raise RuntimeError('fixture release timed out')\n"
                      "    time.sleep(0.02)\n" % (str(ready), str(release)))
    shop.recipes["recipes"]["next-pytest"] = shop.command(["$python", str(script)], heavy=True, heavy_tests=True,
                                                          timeout_seconds=45)
    shop.save_recipes()
    shop.request_job("job-a", "retained")
    shop.request_job("job-b", "next-pytest", root=other_root, prefix="other", checkout=checkout)
    out, err = shop.tmp / "reused-runner-out", shop.tmp / "reused-runner-err"
    launch = subprocess.run(["sh", "-c", 'job_output=$1; job_error=$2; shift 2; "$@" >"$job_output" 2>"$job_error" & echo $!',
                             "sh", str(out), str(err), "setsid", *shop.argv("run-open", census=[], lock_wait=0)],
                            capture_output=True, text=True, timeout=5, env=shop.env())
    assert launch.returncode == 0 and launch.stdout.strip().isdigit(), launch.stderr
    runner, child = int(launch.stdout.strip()), None
    try:
        wait_for(ready)
        child = int(ready.read_text())
        wait_until(lambda: shop.states("job-b", root=other_root, prefix="other") == ["started"]
                   and not (other_root / ".write.lock").exists(), 10, "second job did not finish announcing started")
        folders = [shop.workspace.store / "jobs" / name for name in ("pilot/job-a", "other/job-b")]
        claims = [json.loads((folder / "claim.json").read_text()) for folder in folders]
        assert [claim["pid"] for claim in claims] == [runner, runner]
        assert json.loads((folders[0] / "result.json").read_text())["state"] == "completed"
        assert shop.states("job-a") == ["started"] and lock.exists()
        assert list(requests_of(shop, "heavy", holder="job:pilot/job-a").values()) == ["granted"]
        assert [row["state"] for row in ledger_rows(shop, holder="job:other/job-b", initiative="other").values()
                if row["kind"] == "heavy-tests"] == ["granted"]
        shop.request_job("job-c", "heavy", root=other_root, prefix="other", checkout=checkout)
        jobs = load_jobs_module()
        original_scan = os.scandir
        original_read = Path.read_bytes

        def read(path):
            if path == Path("/proc/%d/cmdline" % os.getpid()):
                return b"fixture-census-observer\0"
            return original_read(path)

        @contextmanager
        def limited_scan(path):
            with original_scan(path) as entries:
                # Real processes and ancestry, with unrelated host load isolated at the enumeration boundary.
                yield (entry for entry in entries if entry.name in {str(os.getpid()), str(runner), str(child)})

        def scan(path):
            return limited_scan(path) if str(path) == "/proc" else original_scan(path)

        with monkeypatch.context() as patch:
            patch.setattr(os, "scandir", scan)
            patch.setattr(Path, "read_bytes", read)
            assert jobs.main(shop.argv("run-open", "--initiative", "other", census=None, lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        row = next(row for row in report["rows"] if row.get("job") == "other/job-c")
        assert (row["state"], row.get("reason")) == ("waiting", "capacity_full"), report
        assert row["capacity"] == {"limit": 2, "held": 1, "external_roots": [child], "census": "proc"}
        assert not (shop.workspace.store / "jobs/other/job-c").exists()
        assert [row["state"] for row in ledger_rows(shop, holder="job:other/job-c", initiative="other").values()
                if row["kind"] == "heavy"] == ["queued"]
        lock.unlink()
        release.touch()
        wait_until(lambda: finished(runner), 10, "reused runner did not finish")
        assert err.read_text() == ""
        first_report = json.loads(out.read_text())
        assert job_row(first_report, "job-a")["state"] == "settle_pending"
        assert next(row for row in first_report["rows"] if row.get("job") == "other/job-b")["state"] == "completed"
        assert all(row["state"] == "completed" for row in shop.run_open()["rows"])
    finally:
        if lock.exists():
            lock.unlink()
        release.touch()
        for pid in (child, runner):
            if pid is not None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("publication", ["claim.json", "packet.md"])
def test_a_failed_derived_admission_preserves_its_partial_claim_custody(kind_shop, monkeypatch, capsys, publication):
    from types import SimpleNamespace

    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    request = shop.workspace.ask("pilot", "writer", JOB_HOLDER)
    assert shop.workspace.grant("writer")["request_id"] == request
    shop.request_job("job-2", "touch", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    before = shop.head()
    folder = shop.workspace.store / "jobs/pilot/job-1"
    original_link = os.link
    injected = []

    def link(source, target, *args, **kwargs):
        if Path(target) == folder / publication:
            assert folder.is_dir()
            injected.append(publication)
            raise OSError(errno.ENOSPC, "fixture derived admission publication full")
        return original_link(source, target, *args, **kwargs)

    jobs = jobs2_module
    with jobs2_patch.object(jobs2_mailbox, "os", SimpleNamespace(**{**vars(os)})):
        with monkeypatch.context() as patch:
            patch.setattr(jobs2_mailbox.os, "link", link)
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    row = job_row(report)
    assert injected == [publication]
    assert row == {"job": "pilot/job-1", "state": "abandoned", "process_group": None, "process_alive": None,
                   "reason": "execution_custody_unknown", "next_action":
                   "Root: preserve the original execution fence and reservation; inspect recovery-status, "
                   "the original claim and process scope. Establish custody and stopped-process evidence "
                   "before recovery or settlement. Do not remove the fence or retry execution."
                   if publication == "packet.md" else JOBS2_UNVERIFIED_ACTION}
    assert folder.is_dir() and not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert (folder / "claim.json").exists() is (publication == "packet.md")
    assert shop.receipts("job-1") == [] and ledger_rows(shop)[request]["state"] == "granted"
    assert job_row(report, "job-2")["state"] == "completed" and shop.sentinel.read_text() == "ran\n"
    assert shop.head() == before
    again = shop.run_open(expect=3)
    assert job_row(again)["state"] in {"running", "abandoned"}
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()


@pytest.mark.parametrize("kind_shop", ["fresh"], indirect=True)
def test_a_running_heavy_tests_pytest_step_blocks_a_heavy_grant(kind_shop, capsys):
    shop = kind_shop
    shop.workspace.run("set-limits", {"source": "owner test", "heavy_limit": 1})
    ready, release = shop.tmp / "pytest-ready", shop.tmp / "pytest-release"
    script = shop.tmp / "pytest.py"
    script.write_text("import os, time\nopen(%r, 'x').write(str(os.getpid()))\n"
                      "deadline = time.monotonic() + 25\nwhile not os.path.exists(%r):\n"
                      "    if time.monotonic() > deadline: raise RuntimeError('fixture release timed out')\n"
                      "    time.sleep(0.02)\n" % (str(ready), str(release)))
    shop.recipes["recipes"]["pytest-phase"] = shop.command(["$python", str(script)], heavy=True, heavy_tests=True)
    shop.save_recipes()
    shop.request_job("job-a", "pytest-phase")
    out, err = shop.tmp / "runner-out", shop.tmp / "runner-err"
    # Reparent the real runner so this test's own pytest ancestor cannot absorb its pytest step as a topmost root.
    launch = subprocess.run(["sh", "-c", 'job_output=$1; job_error=$2; shift 2; "$@" >"$job_output" 2>"$job_error" & echo $!',
                             "sh", str(out), str(err), "setsid", *shop.argv("run-open", census=[])],
                            capture_output=True, text=True, timeout=5, env=shop.env())
    assert launch.returncode == 0 and launch.stdout.strip().isdigit(), launch.stderr
    runner = int(launch.stdout.strip())
    child = None
    try:
        wait_for(ready)
        child = int(ready.read_text())
        claim = json.loads((shop.workspace.store / "jobs/pilot/job-a/claim.json").read_text())
        assert claim["pid"] == runner
        assert list(requests_of(shop, "heavy-tests", holder="job:pilot/job-a").values()) == ["granted"]
        # The child can signal ready before its runner finishes publishing the started receipt.
        wait_until(lambda: shop.states("job-a") == ["started"] and not (shop.root / ".write.lock").exists(),
                   10, "the real runner did not finish publishing its started receipt")
        shop.request_job("job-b", "heavy")
        jobs = load_jobs_module()
        assert jobs.main(shop.argv("run-open", lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
        row = job_row(report, "job-b")
        assert (row["state"], row["reason"]) == ("waiting", "capacity_full")
        assert row["capacity"]["held"] == 0 and child in row["capacity"]["external_roots"]
        assert list(requests_of(shop, "heavy", holder="job:pilot/job-b").values()) == ["queued"]
        assert_did_not_run(shop, "job-b")
        release.write_text("go")
        wait_until(lambda: finished(runner), 10, "real Heavy-Tests runner did not finish")
        assert err.read_text() == ""
        assert job_row(json.loads(out.read_text()), "job-a")["state"] == "completed"
        assert job_row(shop.run_open(), "job-b")["state"] == "completed"
    finally:
        release.touch()
        for pid in (child, runner):
            if pid is not None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.mark.parametrize("kind_shop", ["fresh"], indirect=True)
@pytest.mark.parametrize("heavy", [False, True], ids=["light", "heavy"])
@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
def test_a_preclaim_mailbox_error_does_not_adopt_another_runners_fence(kind_shop, monkeypatch, capsys, heavy, planned):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    shop.recipes["recipes"]["touch"]["heavy"] = heavy
    shop.save_recipes()
    parent = shop.request_job("first-check", "ok")
    assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    request_dependent(shop, parent, "job-dependent")
    jobs = load_jobs_module()
    folder = shop.workspace.store / "jobs/pilot/job-dependent"
    lock = shop.root / ".write.lock"
    original_open = os.open
    child, _ = spawn_fake_heavy(shop.tmp, "other-runner")
    claim = json.dumps(live_claim(jobs, child, "pilot/job-dependent")).encode()
    injected = []

    def open_lock(path, flags, *args, **kwargs):
        if Path(path) == lock and flags & os.O_EXCL and not injected:
            # Another claimant arrives after admission but before this attempt can enter take_execution.
            folder.mkdir(parents=True)
            (folder / "claim.json").write_bytes(claim)
            lock.write_text("fixture live mailbox writer")
            injected.append(True)
        return original_open(path, flags, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", open_lock)
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            row = job_row(json.loads(capsys.readouterr().out), "job-dependent")
        assert injected and row["state"] == "settle_pending"
        assert row["error"] == "mailbox writer is busy; inspect an abandoned lock before retrying"
        if planned:
            assert "Run run-open again" in row["next_action"]
        else:
            assert set(row) == {"job", "state", "error"}
        lock.unlink()
        assert job_row(shop.run_open(expect=3), "job-dependent")["state"] == "running"
        assert (folder / "claim.json").read_bytes() == claim
        assert not (folder / "result.json").exists() and not shop.sentinel.exists()
        assert shop.receipts("job-dependent") == []
    finally:
        if lock.exists():
            lock.unlink()
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        assert finished(child)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("next_kind_job", [False, True], ids=["empty-next-kind", "waiting-next-kind"])
def test_a_postcompletion_fault_appends_its_own_hold_without_changing_an_unknown_job(
        kind_shop, monkeypatch, capsys, next_kind_job):
    from contextlib import contextmanager
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    unknown = shop.workspace.store / "jobs/pilot/job-u"
    shop.request_job("job-u", "touch")
    unknown.mkdir(parents=True)
    original_row = job_row(shop.run_open(expect=3), "job-u")
    assert original_row["state"] == "abandoned" and original_row["next_action"] == JOBS2_UNVERIFIED_ACTION
    request_kind_job(shop, "heavy")
    if next_kind_job:
        add_recipe_of_kind(shop, "later", "heavy-tests")
        shop.request_job("job-tail", "later")
    store, backup = shop.workspace.store, shop.tmp / "critical-retained-store"
    result = store / "jobs/pilot/job-1/result.json"
    jobs = jobs2_module
    original_lock = jobs.Store.lock
    injected = []

    @contextmanager
    def locked(current):
        with original_lock(current):
            yield
        if current.path == store and result.exists() and not injected and list(requests_of(shop, "heavy").values()) == ["released"]:
            store.rename(backup)
            symlink_or_skip(backup, store, target_is_directory=True)
            injected.append(True)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(jobs2_module.Store, "lock", locked)
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
            backup.rename(store)
    assert injected and job_row(report, "job-u") == original_row
    own = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert [row["state"] for row in own] == ["completed", "settle_pending"]
    assert own[1]["reason"] == "post_grant_step_failed"
    assert "retain terminal evidence" in own[1]["next_action"] and "do not rerun completed work" in own[1]["next_action"]
    assert "request_id" not in own[1] and list(requests_of(shop, "heavy").values()) == ["released"]
    again = shop.run_open(expect=3)
    assert job_row(again, "job-u") == original_row and shop.sentinel.read_text() == "ran\n"
    assert not (unknown / "claim.json").exists() and not (unknown / "result.json").exists()
    assert not any(row.get("job") == "pilot/job-1" for row in again["rows"])
    if next_kind_job:
        assert job_row(again, "job-tail")["state"] == "completed"


def test_a_postcompletion_store_failure_becomes_a_root_hold(kind_shop, monkeypatch, capsys):
    import importlib.util
    from types import SimpleNamespace

    shop = kind_shop
    request_kind_job(shop, "heavy")
    jobs = load_jobs_module()
    store, backup = shop.workspace.store, shop.tmp / "retained-store"
    lock = store / ".write.lock"
    result = store / "jobs/pilot/job-1/result.json"
    original_unlink = Path.unlink
    injected = []

    def unlink(path, *args, **kwargs):
        answer = original_unlink(path, *args, **kwargs)
        if path == lock and result.exists() and not injected and list(requests_of(shop, "heavy").values()) == ["released"]:
            store.rename(backup)
            store.symlink_to(backup, target_is_directory=True)
            injected.append(True)
        return answer

    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", unlink)
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
            backup.rename(store)
    assert injected and report["rows"][0]["state"] == "completed"
    assert shop.sentinel.read_text() == "ran\n" and list(requests_of(shop, "heavy").values()) == ["released"]

    spec = importlib.util.spec_from_file_location("hierarchy_loop_jobs_probe", ROOT / "tools/hierarchy_loop.py")
    loop = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loop)
    original_run = subprocess.run

    def run(argv, *args, **kwargs):
        if str(JOBS) in [str(word) for word in argv]:
            # Deliver the actual captured jobs response at the loop's external child-process boundary.
            return subprocess.CompletedProcess(argv, 3, json.dumps(report) + "\n", "")
        return original_run(argv, *args, **kwargs)

    current = loop.Pass(SimpleNamespace(store=store, recipes=shop.recipes_path, max_jobs=None))
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", run)
        current.run_open()
    assert current.steps[0]["state"] == "hold" and any(row["act"] == "root" for row in current.holds)
    assert any(row["state"] in jobs.NEEDS_ROOT for row in report["rows"])
    assert shop.run_open()["rows"] == []


def test_a_released_grant_is_not_resurrected_by_later_recovery(kind_shop, monkeypatch, capsys):
    shop = kind_shop
    request_kind_job(shop, "heavy")
    add_recipe_of_kind(shop, "other-kind", "heavy-tests")
    shop.request_job("job-b", "other-kind")
    shop.recipes["census_outside_policy"] = "count"
    shop.save_recipes()
    jobs = load_jobs_module()
    original_link = os.link
    census_folder, lock = shop.workspace.store / "census", shop.workspace.store / ".write.lock"
    publications = []

    def link(source, target, *args, **kwargs):
        answer = original_link(source, target, *args, **kwargs)
        if Path(target).parent == census_folder:
            publications.append(Path(target).stem)
            if len(publications) == 1:
                shop.workspace.release(publications[0])
            else:
                lock.write_text("fixture store writer after the other-kind grant")
        return answer

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "link", link)
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if lock.exists():
            lock.unlink()
    assert len(publications) == 2
    released, held = publications
    assert requests_of(shop, "heavy") == {released: "released"}
    assert job_row(report)["reason"] == "queue_empty"
    assert not any(row.get("request_id") == released for row in report["rows"]), "release evidence retires the grant record"
    pending = job_row(report, "job-b")
    assert pending["request_id"] == held and pending["reason"] == "post_grant_store_busy"
    assert requests_of(shop, "heavy-tests", holder="job:pilot/job-b") == {held: "granted"}
    assert_did_not_run(shop)
    assert_did_not_run(shop, "job-b")
    recovered = shop.run_open()
    assert all(row["state"] == "completed" for row in recovered["rows"])
    assert requests_of(shop, "heavy-tests", holder="job:pilot/job-b") == {held: "released"}
    assert shop.sentinel.read_text() == "ran\n"


def cargo_and_pytest_jobs(shop):
    """Job "cargo" stands in for a cargo test: it takes Heavy-Tests without running cargo. Job "pytest" takes heavy."""
    shop.recipes["recipes"]["fake-cargo"] = shop.command(["$python", "-c", "print('cargo output')"], heavy=True,
                                                         heavy_tests=True)
    shop.save_recipes()
    shop.request_job("cargo", "fake-cargo")
    shop.request_job("pytest", "heavy")


def kinds_requested(shop):
    return {event["data"]["holder"]: event["data"]["kind"] for event in shop.events() if event["kind"] == "request"}


def test_a_heavy_tests_job_waits_for_its_own_slot_while_a_test_job_runs(shop):
    shop.workspace.run("request", {"initiative": "pilot", "kind": "heavy-tests", "holder": "other-cargo"})
    shop.workspace.run("grant-next", kind="heavy-tests")
    cargo_and_pytest_jobs(shop)
    rows = {row["job"]: row for row in shop.run_open(expect=3)["rows"]}
    assert rows["pilot/cargo"]["state"] == "waiting" and rows["pilot/cargo"]["reason"] == "capacity_full"
    assert rows["pilot/cargo"]["kind"] == "heavy-tests"
    assert rows["pilot/cargo"]["capacity"] == {"limit": 1, "held": 1, "external_roots": [], "census": "fixture"}
    assert rows["pilot/pytest"]["state"] == "completed", "a full Heavy-Tests slot never blocks the test slots"
    assert kinds_requested(shop)["job:pilot/cargo"] == "heavy-tests"
    assert kinds_requested(shop)["job:pilot/pytest"] == "heavy"
    assert shop.receipts("cargo") == [] and shop.heavy()["used"] == 0


@pytest.mark.parametrize("census, blocked", [
    ({"external_roots": {"heavy-tests": [201]}}, "cargo"),
    ({"external_roots": {"heavy": [101, 102, 103]}}, "pytest"),
    ([101, 102, 103], "pytest"),
    ({"external_roots": [101, 102, 103]}, "pytest"),
])
def test_outside_work_counts_only_against_its_own_kind(shop, census, blocked):
    cargo_and_pytest_jobs(shop)
    rows = {row["job"].split("/")[1]: row for row in shop.run_open(census=census, expect=3)["rows"]}
    assert rows[blocked]["state"] == "waiting" and rows[blocked]["reason"] == "capacity_full"
    other = "pytest" if blocked == "cargo" else "cargo"
    assert rows[other]["state"] == "completed"
    assert shop.run_open()["rows"][0]["state"] == "completed"


def test_low_disk_holds_both_heavy_kinds(shop):
    shop.recipes["min_free_gigabytes"] = 1000000
    cargo_and_pytest_jobs(shop)
    rows = shop.run_open(expect=3)["rows"]
    assert sorted((row["job"], row["state"], row["reason"]) for row in rows) == [
        ("pilot/cargo", "waiting", "low_disk"), ("pilot/pytest", "waiting", "low_disk")]


def test_a_census_fixture_names_only_known_kinds(shop):
    cargo_and_pytest_jobs(shop)
    refused = shop.run_open(census={"external_roots": {"writer": [1]}}, expect=2)
    assert "census fixture kind" in refused["error"]


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
def test_the_real_census_finds_outside_heavy_processes(shop, tmp_path):
    children = []
    try:
        for _ in range(3):
            children.append(spawn_fake_heavy(tmp_path, "pytest"))
        pids = [pid for pid, _ in children]
        shop.request_job("job-1", "heavy")
        row = shop.run_open(census=None, expect=3)["rows"][0]
        assert row["state"] == "waiting"
        assert set(pids) <= set(row["capacity"]["external_roots"])
        assert row["capacity"]["census"] == "proc"
    finally:
        failures = []
        for pid, folder in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                failures.append("census fixture %d exited before cleanup: %s; stderr=%r" % (
                    pid, folder, (folder / "stderr.log").read_text(errors="replace")[-4096:]))
            if not finished(pid):
                failures.append("census fixture %d did not stop: %s" % (pid, folder))
        assert not failures, "\n".join(failures)


SPAN = ("import os, time\nname = str(os.getpid())\nopen(%r, 'a').write('start ' + name + '\\n')\ntime.sleep(0.6)\n"
        "open(%r, 'a').write('end ' + name + '\\n')\n")


def peak(log):
    running = most = 0
    for line in log.read_text().splitlines():
        running += 1 if line.startswith("start") else -1
        most = max(most, running)
    return most


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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
    assert row["state"] == "failed" and row["removed"] == ["cargo-target"], "a build cache is never evidence"
    assert row["work_kept"] == ["scratch", "tmp", "home", "ruff-cache", "hypothesis"]
    assert {"home", "tmp", "scratch"} <= set(work_names(shop)) and "cargo-target" not in work_names(shop)
    cleaned = shop.jobs("clean", "--job", "pilot/job-1")
    assert {"home", "tmp", "scratch"} <= set(cleaned["removed"])
    assert work_names(shop) == ["claim.json", "packet.md", "process.json", "result.json", "step-1.log"]
    assert verified_evidence(shop.receipts("job-1")[-1])
    assert shop.jobs("clean", "--job", "pilot/job-1")["removed"] == []


def test_a_failed_heavy_tests_job_leaves_no_work_folders_and_keeps_its_evidence(shop):
    shop.recipes["recipes"]["works"] = shop.command(["$python", "-c", MAKES_WORK + "sys.exit(4)\n"], heavy=True,
                                                    heavy_tests=True)
    shop.save_recipes()
    shop.request_job("job-1", "works")
    row = shop.run_open()["rows"][0]
    assert row["state"] == "failed" and "work_kept" not in row and "cleanup_error" not in row
    assert row["removed"] == ["scratch", "tmp", "home", "cargo-target", "ruff-cache", "hypothesis"]
    assert work_names(shop) == ["claim.json", "packet.md", "process.json", "result.json", "step-1.log"]
    assert "made work" in verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()


TAGS = ("import os\nfor name in ('CARGO_TARGET_DIR', 'RUFF_CACHE_DIR', 'HYPOTHESIS_STORAGE_DIRECTORY'):\n"
        "    print(name, open(os.path.join(os.environ[name], 'CACHEDIR.TAG')).readline().strip())\n")


def test_a_new_job_folder_marks_its_cache_folders_for_backup_tools(shop):
    shop.recipes["recipes"]["tags"] = shop.command(["$python", "-c", TAGS])
    shop.save_recipes()
    shop.request_job("job-1", "tags")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    log = verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()
    for name in ("CARGO_TARGET_DIR", "RUFF_CACHE_DIR", "HYPOTHESIS_STORAGE_DIRECTORY"):
        assert name + " Signature: 8a477f597d28d172789f06886806bc55" in log


KEEPS = ("import os, sys\nfolder = sys.argv[1]\nos.makedirs(folder)\n"
         "open(os.path.join(folder, 'report.xml'), 'w').write('<testsuite/>')\n"
         "with open(os.path.join(folder, 'huge.bin'), 'wb') as stream:\n    stream.truncate(64 * 1048576 + 1)\n"
         "os.symlink('/etc/hostname', os.path.join(folder, 'link'))\n"
         "sys.exit(int(sys.argv[2]))\n")


@pytest.mark.parametrize("exit_code, heavy_tests", [(0, False), (3, True)])
def test_a_kept_file_survives_cleanup_with_its_hash(shop, exit_code, heavy_tests):
    keep = ["run/report.xml", "run/missing.txt", "run/huge.bin", "run/link"]
    shop.recipes["recipes"]["keeps"] = shop.command(["$python", "-c", KEEPS, "$scratch", str(exit_code)], heavy=heavy_tests,
                                                    heavy_tests=heavy_tests, keep=keep)
    shop.save_recipes()
    shop.request_job("job-1", "keeps")
    row = shop.run_open()["rows"][0]
    assert row["state"] == ("failed" if exit_code else "completed") and "scratch" in row["removed"]
    result = json.loads(verified_evidence(shop.receipts("job-1")[-1])["result.json"].read_text())
    kept = {item["path"]: item for item in result["kept"]}
    copy = shop.workspace.store / "jobs" / "pilot" / "job-1" / "evidence" / "run" / "report.xml"
    assert copy.read_text() == "<testsuite/>"
    assert kept["run/report.xml"] == {"path": "run/report.xml", "bytes": 12, "copy": str(copy),
                                      "sha256": hashlib.sha256(b"<testsuite/>").hexdigest()}
    assert kept["run/missing.txt"]["error"] == "missing"
    assert "keep limit" in kept["run/huge.bin"]["error"], "an oversized file is reported, never truncated"
    assert kept["run/link"]["error"] == "not a regular file inside scratch"
    assert sorted(path.name for path in copy.parent.iterdir()) == ["report.xml"]
    assert "run/missing.txt (missing)" in shop.receipts("job-1")[-1]["body"]


def test_a_step_can_name_the_job_cargo_target_folder(shop):
    script = "import os, sys; print('target', sys.argv[1:], os.environ['CARGO_TARGET_DIR'])"
    shop.recipes["recipes"]["target"] = shop.command(["$python", "-c", script, "--target-dir", "$cargo_target"])
    shop.save_recipes()
    shop.request_job("job-1", "target")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    folder = str(shop.workspace.store / "jobs" / "pilot" / "job-1" / "cargo-target")
    log = verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()
    assert "target %r %s" % (["--target-dir", folder], folder) in log


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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
    # A visible receipt precedes the writer lock's release. Killing before release strands that fixture lock.
    while shop.states("job-1") != ["started"] or (shop.root / ".write.lock").exists():
        assert time.monotonic() < deadline, "the started receipt never appeared"
        time.sleep(0.02)
    return runner


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
def test_clean_finished_frees_every_finished_job_of_an_initiative_and_skips_running_ones(shop, tmp_path):
    shop.recipes["recipes"]["works"] = shop.command(["$python", "-c", MAKES_WORK + "sys.exit(4)\n"])
    shop.save_recipes()
    shop.request_job("job-a", "works")
    shop.request_job("job-b", "works")
    assert [row["state"] for row in shop.run_open()["rows"]] == ["failed", "failed"]
    runner = start_stuck_job(shop, tmp_path)
    group = shop.run_open(expect=3)["rows"][0]["process_group"]
    try:
        cleaned = shop.jobs("clean", "--initiative", "pilot", "--finished")
        assert [row["job"] for row in cleaned["jobs"]] == ["pilot/job-a", "pilot/job-b"]
        assert all(row["removed"] == ["scratch", "tmp", "home", "ruff-cache", "hypothesis"] and row["freed_bytes"] >= 1000
                   for row in cleaned["jobs"])
        assert cleaned["freed_bytes"] == sum(row["freed_bytes"] for row in cleaned["jobs"])
        assert cleaned["not_finished"] == ["pilot/job-1"], "a running job is never cleaned"
        for identifier in ("job-a", "job-b"):
            assert work_names(shop, identifier) == ["claim.json", "packet.md", "process.json", "result.json", "step-1.log"]
        assert {"scratch", "home"} <= set(work_names(shop, "job-1"))
        assert shop.jobs("clean", "--initiative", "pilot", "--finished")["jobs"] == []
    finally:
        os.killpg(runner.pid, signal.SIGKILL)
        runner.communicate()
        os.killpg(group, signal.SIGKILL)
    assert "--finished" in shop.jobs("clean", "--initiative", "pilot", expect=2)["error"]
    assert "--job" in shop.jobs("clean", expect=2)["error"]
    assert "initiative" in shop.jobs("clean", "--initiative", "../x", "--finished", expect=2)["error"]


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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
    # A claim written before the hash was stored: the resolution records null rather than hash the file given now.
    claim_path = shop.workspace.store / "jobs" / "pilot" / "job-1" / "claim.json"
    claim = json.loads(claim_path.read_text())
    assert claim.pop("recipes_sha256") == recipes_sha256(shop)
    claim_path.write_text(json.dumps(claim))
    assert shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.", "--process-stopped")["state"] == "failed"
    assert shop.heavy()["used"] == 0
    assert recorded(shop)["recipes_sha256"] is None


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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
    claimed = recipes_sha256(shop)
    shop.recipes_path.write_bytes(shop.recipes_path.read_bytes() + b"\n")
    resolved = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "The runner crashed.")
    assert resolved["state"] == "failed"
    assert recorded(shop)["recipes_sha256"] == claimed != recipes_sha256(shop), \
        "a root resolution names the recipe file the job was claimed under, not the one given at resolve time"
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


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
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


def lock_after_started_receipt(shop, lock):
    # Publication can become visible before its writer releases the lock. Keep the
    # existing ten-second budget for both observing the receipt and acquiring our obstacle.
    published = str(shop.root / "pilot" / "orchestrator" / "*-root-to-orchestrator-*-started.md")
    return ("import glob, time\ndeadline = time.monotonic() + 10\nwhile time.monotonic() < deadline:\n"
            "    if glob.glob(%r):\n        try:\n            open(%r, 'x').close()\n"
            "        except FileExistsError:\n            pass\n        else:\n            break\n"
            "    time.sleep(0.01)\nelse:\n"
            "    raise TimeoutError('fixture could not acquire lock after started receipt within 10 seconds')\n"
            % (published, str(lock)))


def test_a_receipt_blocked_by_a_busy_mailbox_is_published_later_exactly_once(shop):
    lock = shop.root / ".write.lock"
    script = lock_after_started_receipt(shop, lock)
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
    script = lock_after_started_receipt(shop, lock)
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


BAD_RECIPE_CASES = [
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
    (lambda r: r["recipes"]["ok"].update(keep=["run/../../secret"]), "invalid keep"),
    (lambda r: r["recipes"]["ok"].update(keep=["/etc/passwd"]), "invalid keep"),
    (lambda r: r["recipes"]["ok"].update(keep=["file-%d" % n for n in range(17)]), "invalid keep"),
    (lambda r: r["recipes"]["commit"].update(keep=["report.xml"]), "unexpected"),
    (lambda r: r["recipes"]["ok"].update(require_clean=True, writable_checkout=True),
     "require_clean recipe ok cannot take writable_checkout: it runs on a read-only export of the commit"),
    (lambda r: r["recipes"].update(merge={"kind": "merge", "sandbox": "none", "timeout_seconds": 30, "steps": [["x"]]}),
     "unexpected"),
]


@pytest.mark.parametrize("change, reason", BAD_RECIPE_CASES)
def test_bad_recipes_are_refused_before_anything_runs(shop, change, reason):
    change(shop.recipes)
    shop.save_recipes()
    shop.request_job("job-1", "ok")
    refused = shop.jobs("run-open", expect=2)
    assert reason in refused["error"], refused
    assert shop.states("job-1") == []


def validator_recipes():
    return {"schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable, "path": ["/usr/bin"],
            "identity": {"name": "Root", "email": "root@example.invalid"}, "recipes": {
                "ok": Shop.command(["$python", "-c", "pass"]),
                "heavy": Shop.command(["$python", "-c", "pass"], heavy=True),
                "commit": {"kind": "commit", "sandbox": "none", "timeout_seconds": 30}}}


@pytest.mark.parametrize("change, reason", BAD_RECIPE_CASES)
def test_public_recipe_validation_matches_existing_refusals(tmp_path, change, reason):
    data = validator_recipes()
    change(data)
    raw = json.dumps(data).encode()
    path = tmp_path / "recipes.json"
    path.write_bytes(raw)
    jobs = load_jobs_module()
    with pytest.raises(ValueError, match=reason) as expected:
        jobs.load_recipes(path)
    for captured in (raw, data):
        with pytest.raises(type(expected.value)) as actual:
            jobs.validate_recipes(captured)
        assert str(actual.value) == str(expected.value)
    assert json.dumps(data).encode() == raw


@pytest.mark.parametrize("policy", ["absent", "count", "report", "ignore", "off", False, 1, [], {}, None])
def test_public_recipe_validation_preserves_policy_and_captured_bytes(tmp_path, monkeypatch, policy):
    data = validator_recipes()
    if policy != "absent":
        data["census_outside_policy"] = policy
    raw = (json.dumps(data, indent=2) + "\n\n").encode()
    path = tmp_path / "recipes.json"
    path.write_bytes(raw)
    jobs = load_jobs_module()
    if policy != "absent" and policy not in ("count", "report", "ignore"):
        with pytest.raises(ValueError) as expected:
            jobs.load_recipes(path)
        for captured in (raw, data):
            with pytest.raises(ValueError) as actual:
                jobs.validate_recipes(captured)
            assert str(actual.value) == str(expected.value)
        return
    loaded = jobs.load_recipes(path)
    assert loaded.pop("recipes_sha256") == hashlib.sha256(raw).hexdigest()
    original_open = io.open

    def open_file(name, *args, **kwargs):
        assert name != path, "validation must not reopen the retained input path"
        return original_open(name, *args, **kwargs)

    monkeypatch.setattr(io, "open", open_file)
    assert jobs.validate_recipes(raw) == jobs.validate_recipes(data) == loaded == data
    assert "recipes_sha256" not in data


@pytest.mark.parametrize("raw", [b"{", b"[]", b"null", b"\xff", b'{"schema":"a","schema":"b"}'])
def test_public_recipe_validation_matches_parse_refusals(tmp_path, raw):
    path = tmp_path / "recipes.json"
    path.write_bytes(raw)
    jobs = load_jobs_module()
    with pytest.raises(ValueError) as expected:
        jobs.load_recipes(path)
    with pytest.raises(type(expected.value)) as actual:
        jobs.validate_recipes(raw)
    assert str(actual.value) == str(expected.value)


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
    # The job sandbox gives /tmp and /dev private mounts, and bwrap makes the parents of its bind points in
    # them, so a write below either succeeds unseen and shows nothing about `hide` or the read-only host.
    # pytest's basetemp can itself be in /tmp: a full-suite job puts it there, with the host read-only and
    # its own TMPDIR outside /tmp. So take the first writable folder outside both, in this order.
    def private(folder):
        return any(folder.resolve().is_relative_to(root) for root in (Path("/tmp"), Path("/dev")))

    for folder in sorted([Path("/var/tmp"), Path(tempfile.gettempdir()), shop.tmp], key=private):
        try:
            hidden = Path(tempfile.mkdtemp(prefix="hierarchy-jobs-hidden-", dir=folder))
            break
        except OSError:
            continue
    else:
        pytest.fail("no writable folder for the hidden secret")
    outside = hidden.parent / (hidden.name + "-outside")
    try:
        secret = hidden / "credentials"
        secret.write_text("secret\n")
        shop.recipes["hide"] = [str(hidden)]
        shop.recipes["recipes"]["boxed"] = shop.command(
            ["$python", "-I", "-c", PROBE, str(shop.checkout), str(outside), str(secret)], sandbox="bwrap")
        shop.save_recipes()
        shop.request_job("job-1", "boxed")
        assert shop.run_open()["rows"][0]["state"] == "completed"
        log = verified_evidence(shop.receipts("job-1")[-1])["step-1.log"].read_text()
        checks = json.loads(log.strip().splitlines()[-1])
        assert checks["write_checkout"] in ("OSError", "PermissionError")
        if private(hidden):
            # Last resort: the write lands in the job's own private /tmp, so only the host side can show it is contained.
            assert checks["write_outside"] in ("OSError", "PermissionError", "allowed")
        else:
            assert checks["write_outside"] in ("OSError", "PermissionError")
        assert checks["read_hidden"] == "FileNotFoundError"
        assert checks["write_job_home"] == "allowed" and checks["write_tmp"] == "allowed"
        assert checks["read_checkout"] == "allowed"
        assert checks["network"] != "allowed" and checks["interfaces"] == ["lo"]
        assert not (shop.checkout / "planted").exists() and not outside.exists()
    finally:
        shutil.rmtree(hidden, ignore_errors=True)
        outside.unlink(missing_ok=True)


ORPHAN = ("import subprocess, sys, time\n"
          "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)', sys.argv[1]], start_new_session=True)\n"
          "print('started', flush=True)\ntime.sleep(60)\n")


@pytest.mark.parametrize("shop", ["fresh"], indirect=True)
@needs_bubblewrap
def test_a_sandboxed_step_past_its_timeout_takes_its_own_sessions_with_it(shop):
    """The stop at the end of a step reaches the step's group. A child that called setsid left that group, so only
    the sandbox's own PID namespace can take it down with the job."""
    marker = "marker-" + uuid.uuid4().hex
    shop.recipes["recipes"]["escapes"] = shop.command(["$python", "-c", ORPHAN, marker], sandbox="bwrap", timeout_seconds=2)
    shop.save_recipes()
    shop.request_job("job-1", "escapes")
    try:
        assert shop.run_open()["rows"][0]["state"] == "failed"
        assert "timed out" in shop.receipts("job-1")[-1]["receipt"]["reason"]
        deadline = time.monotonic() + 5
        while processes_with(marker) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert processes_with(marker) == []
    finally:
        for pid in processes_with(marker):
            os.kill(pid, signal.SIGKILL)


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


# The merge kind (ADR D3 with J1 and J2). Written out here rather than imported, because this is the orchestrator's side
# of the contract: its prediction must use exactly the runner's -c set, with no global or system config.
MERGE_CONFIG = ("merge.renames=true", "merge.directoryRenames=false", "merge.renameLimit=7000", "merge.renormalize=false")


def with_merge_recipe(shop, **extra):
    shop.recipes["recipes"]["merge-exact"] = {"kind": "merge", "sandbox": "none", "timeout_seconds": 30, **extra}
    shop.save_recipes()


def side_commit(shop, branch, files, *, orphan=False, gitlink=None):
    """A commit on another branch, made from the current HEAD; the checkout ends back on feature/x, clean."""
    git(shop.checkout, "switch", "-q", "--orphan" if orphan else "-c", branch)
    for name, content in files.items():
        (shop.checkout / name).parent.mkdir(parents=True, exist_ok=True)
        (shop.checkout / name).write_text(content)
    git(shop.checkout, "add", "-A")
    if gitlink:
        git(shop.checkout, "update-index", "--add", "--cacheinfo", "160000,%s,vendored" % gitlink)
    git(shop.checkout, "commit", "-qm", "side " + branch)
    commit = git(shop.checkout, "rev-parse", "HEAD")
    git(shop.checkout, "switch", "-q", "feature/x")
    return commit


def main_commit(shop, files):
    for name, content in files.items():
        (shop.checkout / name).parent.mkdir(parents=True, exist_ok=True)
        (shop.checkout / name).write_text(content)
    git(shop.checkout, "add", "-A")
    git(shop.checkout, "commit", "-qm", "main")
    return git(shop.checkout, "rev-parse", "HEAD")


def predict(shop, commit, merge, *, pinned=True):
    """The orchestrator's prediction, run the way it must run it."""
    config = [part for item in MERGE_CONFIG for part in ("-c", item)] if pinned else []
    found = subprocess.run(["git", *config, "merge-tree", "--write-tree", commit, merge], cwd=shop.checkout,
                           env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
                           capture_output=True, text=True, timeout=10)
    lines = found.stdout.splitlines()
    return found.returncode, lines[0] if lines else None


def merge_request(shop, merge, identifier="job-1", **changes):
    if "merge-exact" not in shop.recipes["recipes"]:
        with_merge_recipe(shop)
    _, tree = predict(shop, shop.head()["commit"], merge)
    packet = {"merge": merge, "expected_tree": tree, "message": "Merge side\n\nExact text; $(not run).\n", **changes}
    shop.request_job(identifier, "merge-exact", **packet)
    return tree


def snapshot(shop):
    """HEAD, the real index and every file outside .git: what a refused or halted merge must leave as it found."""
    files = {str(path.relative_to(shop.checkout)): path.read_bytes() for path in sorted(shop.checkout.rglob("*"))
             if path.is_file() and ".git" not in path.relative_to(shop.checkout).parts}
    return git(shop.checkout, "rev-parse", "HEAD"), git(shop.checkout, "ls-files", "--stage"), files


def assert_stopped(shop, before, state, *reasons):
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == state and all(reason in final["receipt"]["reason"] for reason in reasons), final
    assert snapshot(shop) == before


def two_sides(shop):
    side = side_commit(shop, "side", {"src/app.py": "value = 3\n", "docs/side.md": "side\n"})
    return side, main_commit(shop, {"docs/main.md": "main\n"})


def test_a_merge_job_commits_exactly_the_predicted_tree_with_both_parents(shop):
    side, before = two_sides(shop)
    tree = merge_request(shop, side)
    assert shop.run_open()["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]
    head = git(shop.checkout, "rev-parse", "HEAD")
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
    assert git(shop.checkout, "rev-list", "--parents", "-n", "1", "HEAD").split() == [head, before, side]
    assert git(shop.checkout, "log", "-1", "--format=%B") == "Merge side\n\nExact text; $(not run)."
    assert git(shop.checkout, "log", "-1", "--format=%an <%ae> %G?") == "Hierarchy Root <root@example.invalid> N"
    assert git(shop.checkout, "status", "--porcelain=v1", "--untracked-files=all") == "", "index and files must match the merge"
    assert (shop.checkout / "src" / "app.py").read_text() == "value = 3\n" and (shop.checkout / "docs" / "side.md").exists()
    assert shop.states("job-1") == ["started", "completed"]
    final = shop.receipts("job-1")[-1]
    recorded = json.loads(verified_evidence(final)["result.json"].read_text())
    assert recorded["commit"] == head and head in final["body"]
    record = recorded["merge"]
    assert record.pop("git_version").startswith("git version "), "the receipt shows which git merged"
    assert record == {"commit": before, "merge": side, "merge_bases": [git(shop.checkout, "merge-base", before, side)],
                      "expected_tree": tree, "tree": tree, "new_commit": head, "config": list(MERGE_CONFIG),
                      "head_ref": "refs/heads/feature/x"}


def test_a_conflicting_merge_halts_with_its_paths_even_when_the_packet_names_the_conflicted_tree(shop):
    side = side_commit(shop, "side", {"src/app.py": "value = 3\n"})
    main_commit(shop, {"src/app.py": "value = 2\n"})
    assert predict(shop, shop.head()["commit"], side)[0] == 1
    merge_request(shop, side)
    before = snapshot(shop)
    assert shop.run_open()["rows"][0]["state"] == "failed"
    assert_stopped(shop, before, "failed", "conflict", "src/app.py")


def test_a_merged_tree_other_than_the_expected_one_halts_before_anything_moves(shop):
    side, _ = two_sides(shop)
    merge_request(shop, side, expected_tree="1" * 40)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "failed", "is not the expected tree " + "1" * 40)


@pytest.mark.parametrize("which, reason", [("base", "already contained"), ("head", "merge equals commit")])
def test_a_merge_that_would_change_nothing_is_refused(shop, which, reason):
    base = shop.head()["commit"]
    head = main_commit(shop, {"docs/main.md": "main\n"})
    merge_request(shop, base if which == "base" else head)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", reason)


def test_a_merge_of_unrelated_histories_is_refused(shop):
    lonely = side_commit(shop, "lonely", {"README": "another history\n"}, orphan=True)
    merge_request(shop, lonely, expected_tree="1" * 40)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", "unrelated histories")


def test_a_merge_bringing_a_gitlink_is_refused(shop):
    side = side_commit(shop, "side", {"docs/side.md": "side\n"}, gitlink=shop.head()["commit"])
    main_commit(shop, {"docs/main.md": "main\n"})
    merge_request(shop, side)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", "submodules", "vendored")


@pytest.mark.parametrize("attributes, reason", [("*.bin filter=lfs -text\n", "filter=lfs"), ("*.bin merge=union\n", "merge=union")])
def test_a_merge_touching_a_filtered_or_union_merged_path_is_refused(shop, attributes, reason):
    side = side_commit(shop, "side", {".gitattributes": attributes, "data.bin": "payload\n"})
    main_commit(shop, {"docs/main.md": "main\n"})
    merge_request(shop, side)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", reason, "data.bin")


@pytest.mark.parametrize("side, path, attributes", [
    ("merge", ".gitattributes", "untouched.txt filter=aegis-test-absent\n"),
    ("commit", ".gitattributes", "untouched.txt filter=aegis-test-absent\n"),
    ("merge", "src/.gitattributes", "app.py filter=aegis-test-absent\n"),
])
def test_a_merge_changing_gitattributes_on_either_side_is_refused(shop, side, path, attributes):
    # The new filter lands on a path neither side changes, which the per-path attribute check never reads.
    # An unconfigured filter preserves that premise even when Git LFS is installed.
    base = main_commit(shop, {"untouched.txt": "the same on both sides\n"})
    change = {path: attributes}
    merge = side_commit(shop, "side", change if side == "merge" else {"docs/side.md": "side\n"})
    main_commit(shop, change if side == "commit" else {"docs/main.md": "main\n"})
    untouched = "src/app.py" if path.startswith("src/") else "untouched.txt"
    for revision in (merge, shop.head()["commit"]):
        assert untouched not in git(shop.checkout, "diff", "--name-only", base, revision).splitlines()
    merge_request(shop, merge)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", ".gitattributes", path, "integrator lane")


@pytest.mark.parametrize("key, value", [("merge.default", "union"), ("merge.text.driver", "cat %A > /dev/null")])
def test_a_merge_with_a_merge_driver_in_local_config_is_refused(shop, key, value):
    # merge.default serves every path whose merge attribute is unspecified, and a configured driver named text wins over the
    # built-in, so either would bring back a union or custom merge that the attribute check refuses.
    git(shop.checkout, "config", key, value)
    side, _ = two_sides(shop)
    merge_request(shop, side)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", key, "integrator lane")


def test_a_merge_whose_head_moved_after_the_packet_is_refused(shop):
    side, _ = two_sides(shop)
    merge_request(shop, side)
    main_commit(shop, {"docs/later.md": "later\n"})
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", "source does not match")


MOVES_HEAD = ("import os, subprocess, sys\n"
              "if 'update-ref' in sys.argv:\n"
              "    subprocess.run(['git', 'update-ref', 'HEAD', %r], check=True)\n"
              "os.execvp(sys.argv[1], sys.argv[1:])\n")


def test_a_head_moved_during_the_merge_is_never_overwritten(shop):
    elsewhere = side_commit(shop, "elsewhere", {"docs/elsewhere.md": "another lane\n"})
    side, _ = two_sides(shop)
    # Every step goes through this prefix, which moves HEAD just before the compare-and-swap, as a racing lane would.
    wrapper = shop.tmp / "moves-head.py"
    wrapper.write_text(MOVES_HEAD % elsewhere)
    shop.recipes["prefix"] = [sys.executable, str(wrapper)]
    merge_request(shop, side)
    before = snapshot(shop)
    shop.run_open()
    final = shop.receipts("job-1")[-1]
    assert final["receipt"]["state"] == "failed" and "compare-and-swap" in final["receipt"]["reason"], final
    assert git(shop.checkout, "rev-parse", "HEAD") == elsewhere, "the other lane's HEAD must stand"
    assert snapshot(shop)[1:] == before[1:], "the index and files must not move"


# Fails the step past the swap that brings the real index forward (and for a merge the files), as a lock taken by an IDE
# at that moment would.
FAILS_AFTER_SWAP = ("import os, sys\n"
                    "argv = sys.argv[1:]\n"
                    "if %r in argv and '-n' not in argv and 'GIT_INDEX_FILE' not in os.environ:\n"
                    "    sys.stderr.write('error: simulated failure past the swap\\n')\n"
                    "    sys.exit(128)\n"
                    "os.execvp(argv[0], argv)\n")


@pytest.mark.parametrize("kind", ["merge", "commit"])
def test_a_step_failing_after_the_swap_puts_head_back_and_says_so(shop, kind):
    wrapper = shop.tmp / "fails-after-swap.py"
    wrapper.write_text(FAILS_AFTER_SWAP % ("read-tree" if kind == "merge" else "add"))
    shop.recipes["prefix"] = [sys.executable, str(wrapper)]
    shop.save_recipes()
    if kind == "merge":
        merge_request(shop, two_sides(shop)[0])
    else:
        commit_request(shop)
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "failed", "HEAD was restored to " + before[0], "simulated failure past the swap")
    assert json.loads(verified_evidence(shop.receipts("job-1")[-1])["result.json"].read_text())["commit"] is None


# Puts an obstacle in the checkout after admit, while the merge is being computed and before anything moves.
OBSTACLE_AFTER_ADMIT = ("import os, sys\n"
                        "if 'ls-tree' in sys.argv:\n"
                        "    open(%r, 'w').close()\n"
                        "os.execvp(sys.argv[1], sys.argv[1:])\n")


@pytest.mark.parametrize("obstacle, error", [
    ("docs/side.md", "Untracked working tree file 'docs/side.md' would be overwritten"),
    (".git/index.lock", "index.lock': File exists"),
])
def test_an_obstacle_appearing_after_admit_is_refused_before_head_moves(shop, obstacle, error):
    side, _ = two_sides(shop)
    wrapper = shop.tmp / "obstacle.py"
    wrapper.write_text(OBSTACLE_AFTER_ADMIT % str(shop.checkout / obstacle))
    shop.recipes["prefix"] = [sys.executable, str(wrapper)]
    merge_request(shop, side)
    before = snapshot(shop)
    shop.run_open()
    (shop.checkout / obstacle).unlink()
    assert_stopped(shop, before, "failed", "dry run", "HEAD, the index and the files were not changed", error)


def test_a_file_only_the_owners_global_excludes_ignore_keeps_a_merge_out(shop):
    # The steps read no global excludes, so a merge's clean check reads none either: one ignore view for both.
    side, _ = two_sides(shop)
    excludes = shop.tmp / "owner-config" / "git" / "ignore"
    excludes.parent.mkdir(parents=True)
    excludes.write_text("docs/side.md\n")
    (shop.checkout / "docs" / "side.md").write_text("the owner's notes\n")
    merge_request(shop, side)
    before = snapshot(shop)
    shop.run_open(env={**shop.env(), "XDG_CONFIG_HOME": str(excludes.parent.parent)})
    assert_stopped(shop, before, "refused", "clean worktree")


SLOW_AFTER_SWAP = ("import os, sys, time\n"
                   "if 'read-tree' in sys.argv and '-n' not in sys.argv:\n"
                   "    time.sleep(60)\n"
                   "os.execvp(sys.argv[1], sys.argv[1:])\n")


def test_a_timeout_after_the_swap_names_where_head_and_the_index_are(shop):
    with_merge_recipe(shop, timeout_seconds=5)
    side, commit = two_sides(shop)
    wrapper = shop.tmp / "slow-after-swap.py"
    wrapper.write_text(SLOW_AFTER_SWAP)
    shop.recipes["prefix"] = [sys.executable, str(wrapper)]
    shop.save_recipes()
    merge_request(shop, side)
    shop.run_open()
    head = git(shop.checkout, "rev-parse", "HEAD")
    final = shop.receipts("job-1")[-1]
    assert head != commit
    assert all(part in final["receipt"]["reason"] for part in (
        "timed out", "HEAD names %s (the new commit)" % head, "the index holds the tree of the packet's commit")), final
    assert json.loads(verified_evidence(final)["result.json"].read_text())["commit"] == head


def test_a_merge_into_a_dirty_worktree_is_refused(shop):
    side, _ = two_sides(shop)
    (shop.checkout / "notes.txt").write_text("uncommitted\n")
    merge_request(shop, side, dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", "clean worktree")


def test_a_second_merge_is_a_second_job_on_the_first_merge_commit(shop):
    first = side_commit(shop, "first", {"src/app.py": "value = 3\n"})
    second = side_commit(shop, "second", {"docs/second.md": "second\n"})
    main_commit(shop, {"docs/main.md": "main\n"})
    merge_request(shop, first, "job-1")
    assert shop.run_open()["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]
    merged = git(shop.checkout, "rev-parse", "HEAD")
    tree = merge_request(shop, second, "job-2")
    assert [row["state"] for row in shop.run_open()["rows"]] == ["completed"], shop.receipts("job-2")[-1]
    assert git(shop.checkout, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [merged, second]
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
    assert (shop.checkout / "src" / "app.py").read_text() == "value = 3\n" and (shop.checkout / "docs" / "second.md").exists()


def test_the_pinned_prediction_matches_the_runner_whatever_the_local_merge_config(shop):
    git(shop.checkout, "config", "merge.directoryRenames", "true")
    side = side_commit(shop, "side", {"src/extra.py": "extra = 1\n"})
    git(shop.checkout, "mv", "src", "lib")
    git(shop.checkout, "commit", "-qm", "move src to lib")
    commit = shop.head()["commit"]
    code, tree = predict(shop, commit, side)
    assert code == 0
    assert predict(shop, commit, side, pinned=False)[1] != tree, "unpinned, the local config moves the new file into lib/"
    merge_request(shop, side)
    assert shop.run_open()["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
    assert (shop.checkout / "src" / "extra.py").exists() and not (shop.checkout / "lib" / "extra.py").exists()


@pytest.mark.parametrize("recipe, changes, reason", [
    ("merge-exact", {"merge": None}, "needs merge"),
    ("merge-exact", {"expected_tree": None}, "merge recipe needs expected_tree"),
    ("merge-exact", {"message": None}, "merge recipe needs expected_tree"),
    ("merge-exact", {"paths": ["src/app.py"]}, "takes no paths"),
    ("merge-exact", {"paths": []}, "takes no paths"),
    ("merge-exact", {"paths": ""}, "takes no paths"),
    ("merge-exact", {"merge": "not-an-id"}, "invalid merge"),
    ("touch", {"merge": "0" * 40}, "only a merge recipe"),
    ("commit", {"merge": "0" * 40}, "only a merge recipe"),
])
def test_a_merge_packet_missing_or_misplacing_its_details_is_refused(shop, recipe, changes, reason):
    side = side_commit(shop, "side", {"docs/side.md": "side\n"})
    with_merge_recipe(shop)
    packet = {"merge-exact": {"merge": side, "expected_tree": "1" * 40, "message": "Merge side"},
              "commit": {"paths": ["src/app.py"], "expected_tree": "1" * 40, "message": "fix: x"}}.get(recipe, {})
    shop.request_job("job-1", recipe, **{**packet, **changes})
    before = snapshot(shop)
    shop.run_open()
    assert_stopped(shop, before, "refused", reason)
    assert not shop.sentinel.exists()


def test_a_merge_recipe_needs_an_identity(shop):
    del shop.recipes["recipes"]["commit"], shop.recipes["identity"]
    with_merge_recipe(shop)
    assert "identity" in shop.jobs("check-recipes", expect=2)["error"]


@needs_bubblewrap
def test_a_sandboxed_merge_can_bring_the_working_tree_forward(shop):
    with_merge_recipe(shop, sandbox="bwrap")
    side, _ = two_sides(shop)
    tree = merge_request(shop, side)
    assert shop.run_open()["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
    assert git(shop.checkout, "status", "--porcelain=v1", "--untracked-files=all") == ""


# Item 6 (ADR-JOB-EVIDENCE): the evidence a Reviewer reads. A test recipe can demand a clean checkout, keeps its junit
# report, and settles as failed when that report shows no tests or cannot be read; every result names the recipe file's
# hash and the interpreter's version.
TEMPLATE = ROOT / "tools" / "hierarchy_templates" / "job-recipes.json"
CLEAN_REFUSAL = "recipe tests requires a clean checkout; commit or discard local changes"
WRITE_JUNIT = ("import os, sys\npath, content = sys.argv[1], sys.argv[2]\n"
               "if content == 'big':\n    content = '<testsuites>' + ' ' * (8 * 1048576) + '</testsuites>'\n"
               "if content != '-':\n    os.makedirs(os.path.dirname(path), exist_ok=True)\n"
               "    open(path, 'w', encoding='utf-8').write(content)\n"
               "print('junit written to', path)\nsys.exit(int(sys.argv[3]))\n")


def suite(tests, failures=0, errors=0, skipped=0):
    return '<testsuite name="pytest" tests="%d" failures="%d" errors="%d" skipped="%d"/>' % (tests, failures, errors, skipped)


def with_tests_recipe(shop, junit, exit_code=0, *, heavy=False, **flags):
    flags = {"keep": ["run/junit.xml"], "expects_tests": True, "require_clean": True, **flags}
    shop.recipes["recipes"]["tests"] = shop.command(["$python", "-c", WRITE_JUNIT, "$scratch/junit.xml", junit, str(exit_code)],
                                                    heavy=heavy, **flags)
    shop.save_recipes()


def final_result(shop, identifier="job-1"):
    receipt = shop.receipts(identifier)[-1]
    return receipt, json.loads(verified_evidence(receipt)["result.json"].read_text())


def test_a_test_job_records_its_counts_in_the_result_and_the_receipt(shop):
    with_tests_recipe(shop, "<testsuites>%s%s</testsuites>" % (suite(3, skipped=1), suite(2)))
    shop.request_job("job-1", "tests")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    receipt, result = final_result(shop)
    assert result["state"] == "completed" and result["exit_code"] == 0 and result["reason"] is None
    assert result["tests"] == {"total": 5, "passed": 4, "failed": 0, "errors": 0, "skipped": 1}
    assert "Tests: 5 total, 4 passed, 0 failed, 0 errors, 1 skipped." in receipt["body"]
    kept = {item["path"]: item for item in result["kept"]}
    assert Path(kept["run/junit.xml"]["copy"]).read_text().startswith("<testsuites>")


def test_a_failing_test_job_keeps_its_exit_and_still_records_its_counts(shop):
    with_tests_recipe(shop, suite(4, failures=1, errors=1), 1)
    shop.request_job("job-1", "tests")
    assert shop.run_open()["rows"][0]["state"] == "failed"
    receipt, result = final_result(shop)
    assert (result["exit_code"], result["reason"]) == (1, "step 1 exited 1")
    assert result["tests"] == {"total": 4, "passed": 2, "failed": 1, "errors": 1, "skipped": 0}
    assert "Tests: 4 total, 2 passed, 1 failed, 1 errors, 0 skipped." in receipt["body"]


def test_a_single_testsuite_root_is_counted_too(shop):
    with_tests_recipe(shop, suite(2, skipped=1))
    shop.request_job("job-1", "tests")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert final_result(shop)[1]["tests"] == {"total": 2, "passed": 1, "failed": 0, "errors": 0, "skipped": 1}


def test_a_test_job_that_passes_no_tests_fails_and_a_failed_step_keeps_its_own_reason(shop):
    with_tests_recipe(shop, suite(2, failures=2), 1)
    shop.request_job("job-1", "tests")
    shop.run_open()
    result = final_result(shop)[1]
    assert (result["state"], result["exit_code"], result["reason"]) == ("failed", 1, "step 1 exited 1")
    assert result["tests"]["passed"] == 0


@pytest.mark.parametrize("junit, reason", [
    (suite(0), "the run reported no tests"),
    ("<testsuites></testsuites>", "the run reported no tests"),
    ("-", "junit.xml is missing"),
])
def test_a_test_job_that_shows_no_tests_fails_even_with_a_clean_exit(shop, junit, reason):
    with_tests_recipe(shop, junit)
    shop.request_job("job-1", "tests")
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("failed", reason)
    receipt, result = final_result(shop)
    assert (result["state"], result["exit_code"], result["reason"]) == ("failed", -1, reason)
    assert result["steps"][0]["exit_code"] == 0
    assert result["tests"] == ({"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0} if junit != "-" else None)
    assert receipt["receipt"]["state"] == "failed" and receipt["receipt"]["reason"] == reason


BILLION_LAUGHS = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
                  '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0" name="&lol2;"/></testsuites>')


@pytest.mark.parametrize("junit, reason", [
    ("<testsuites><testsuite", "junit.xml is unreadable: it is not well-formed XML"),
    (BILLION_LAUGHS, "junit.xml is unreadable: it has a DOCTYPE or ENTITY declaration"),
    ('<!ENTITY x "y"><testsuites/>', "junit.xml is unreadable: it has a DOCTYPE or ENTITY declaration"),
    ("<html><testsuite tests='1'/></html>", "junit.xml is unreadable: its root is html, not testsuites or testsuite"),
    ('<!DOCTYPE testsuites><testsuites><testsuite tests="1"/></testsuites>',
     "junit.xml is unreadable: it has a DOCTYPE or ENTITY declaration"),
    ("<testsuites><testsuite tests='many'/></testsuites>",
     "junit.xml is unreadable: testsuite attribute tests is not a non-negative integer"),
    ("<testsuites><testsuite tests='1' skipped='-2'/></testsuites>",
     "junit.xml is unreadable: testsuite attribute skipped is not a non-negative integer"),
    ("<testsuites><testsuite tests='1' failures='2'/></testsuites>",
     "junit.xml is unreadable: failures, errors and skipped exceed tests"),
    ("big", "junit.xml is unreadable: it is larger than 8388608 bytes"),
])
def test_an_unreadable_junit_report_fails_the_job(shop, junit, reason):
    with_tests_recipe(shop, junit)
    shop.request_job("job-1", "tests")
    assert shop.run_open()["rows"][0]["state"] == "failed"
    receipt, result = final_result(shop)
    assert (result["exit_code"], result["reason"], result["tests"]) == (-1, reason, None)
    assert reason in receipt["body"]


def test_a_junit_report_that_is_not_utf8_is_unreadable(shop):
    with_tests_recipe(shop, "x")
    script = ("import os, sys\nos.makedirs(os.path.dirname(sys.argv[1]))\n"
              "open(sys.argv[1], 'wb').write('<testsuites/>'.encode('utf-16'))\n")
    shop.recipes["recipes"]["tests"]["steps"] = [["$python", "-c", script, "$scratch/junit.xml"]]
    shop.save_recipes()
    shop.request_job("job-1", "tests")
    shop.run_open()
    assert final_result(shop)[1]["reason"] == "junit.xml is unreadable: it is not UTF-8"


def test_a_failed_step_keeps_its_own_reason_when_the_junit_report_is_missing(shop):
    with_tests_recipe(shop, "-", 2)
    shop.request_job("job-1", "tests")
    shop.run_open()
    result = final_result(shop)[1]
    assert (result["exit_code"], result["reason"], result["tests"]) == (2, "step 1 exited 2", None)


def test_a_recipe_without_expects_tests_records_no_counts(shop):
    shop.request_job("job-1", "ok")
    shop.run_open()
    receipt, result = final_result(shop)
    assert result["tests"] is None and "Tests:" not in receipt["body"]


def test_a_recipe_that_requires_a_clean_checkout_refuses_uncommitted_changes_at_admit(shop):
    with_tests_recipe(shop, suite(1))
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    shop.request_job("job-1", "tests", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", CLEAN_REFUSAL)
    assert shop.states("job-1") == ["refused"]
    assert shop.receipts("job-1")[-1]["receipt"]["reason"] == CLEAN_REFUSAL
    assert recorded(shop)["recipes_sha256"] == recipes_sha256(shop), "an admit refusal names the recipe file too"


def test_a_recipe_that_requires_a_clean_checkout_runs_on_a_clean_one(shop):
    with_tests_recipe(shop, suite(1))
    (shop.checkout / "notes.txt").write_text("ignored? no, untracked\n")
    shop.request_job("job-2", "tests", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    assert shop.run_open()["rows"][0]["reason"] == CLEAN_REFUSAL, "an untracked file is uncommitted content too"
    (shop.checkout / "notes.txt").unlink()
    shop.request_job("job-1", "tests")
    assert shop.run_open()["rows"][0]["state"] == "completed"


def test_a_recipe_that_requires_a_clean_checkout_is_checked_again_when_its_slot_comes(shop):
    with_tests_recipe(shop, suite(1), heavy=True)
    shop.request_job("job-1", "tests")
    assert shop.run_open(census=[101, 102, 103], expect=3)["rows"][0]["state"] == "waiting"
    (shop.checkout / "src" / "app.py").write_text("value = 3\n")
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", CLEAN_REFUSAL), "a packet that claimed a clean checkout learns why"
    assert shop.heavy()["used"] == 0 and shop.states("job-1") == ["refused"]


DIRTY = "import sys; open(sys.argv[1] + '/src/app.py', 'w').write('value = 9\\n')"


def test_a_recipe_that_requires_a_clean_checkout_is_witnessed_again_just_before_it_runs(shop):
    with_tests_recipe(shop, suite(1))
    shop.recipes["recipes"]["dirty"] = shop.command(["$python", "-c", DIRTY, "$checkout"])
    shop.save_recipes()
    shop.request_job("job-a", "dirty")
    shop.request_job("job-b", "tests")
    rows = {row["job"]: row for row in shop.run_open()["rows"]}
    assert rows["pilot/job-a"]["state"] == "failed", "the first job changed the source it ran on"
    assert (rows["pilot/job-b"]["state"], rows["pilot/job-b"]["reason"]) == ("refused", CLEAN_REFUSAL)
    result = json.loads((shop.workspace.store / "jobs" / "pilot" / "job-b" / "result.json").read_text())
    assert result["recipes_sha256"] == hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()
    assert result["steps"] == [] and "python" not in result


def test_a_result_names_the_recipe_file_hash_and_the_python_version(shop):
    shop.request_job("job-1", "ok")
    shop.recipes_path.write_bytes(shop.recipes_path.read_bytes() + b"\n\n")
    shop.run_open()
    result = final_result(shop)[1]
    assert result["recipes_sha256"] == hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()
    version = subprocess.run([sys.executable, "-c", "import platform; print(platform.python_version())"],
                             capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    assert result["python"] == {"version": version, "executable": sys.executable}
    assert shop.jobs("check-recipes")["recipes_sha256"] == result["recipes_sha256"]


def test_a_commit_result_names_the_recipe_file_hash_but_no_python(shop):
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    git(shop.checkout, "add", "src/app.py")
    tree = git(shop.checkout, "write-tree")
    git(shop.checkout, "reset", "-q")
    shop.request_job("job-1", "commit", paths=["src/app.py"], expected_tree=tree, message="fix: value",
                     dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    assert shop.run_open()["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]
    result = final_result(shop)[1]
    assert result["recipes_sha256"] == hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()
    assert result["python"] is None and result["tests"] is None


def fake_python(shop, body):
    """A stand-in interpreter that logs each call and then runs the real one; it never reaches any other program."""
    calls = shop.tmp / "python-calls"
    fake = shop.tmp / "bin" / "python"
    fake.parent.mkdir(exist_ok=True)
    fake.write_text("#!/bin/sh\necho \"$*\" >> %s\n%s\n" % (calls, body))
    fake.chmod(0o755)
    shop.recipes["python"] = str(fake)
    shop.save_recipes()
    return calls


def test_the_python_version_is_read_once_per_run(shop):
    calls = fake_python(shop, 'exec %s "$@"' % sys.executable)
    shop.request_job("job-1", "ok")
    shop.request_job("job-2", "ok")
    assert [row["state"] for row in shop.run_open()["rows"]] == ["completed", "completed"]
    lines = calls.read_text().splitlines()
    assert len(lines) == 3 and sum(line.startswith("-I -S -c") for line in lines) == 1, lines
    assert final_result(shop, "job-2")[1]["python"]["executable"] == str(shop.tmp / "bin" / "python")


def test_a_python_whose_version_cannot_be_read_is_recorded_without_failing_the_job(shop):
    fake_python(shop, 'case "$1" in -I) exit 4;; esac\nexec %s "$@"' % sys.executable)
    shop.request_job("job-1", "ok")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    python = final_result(shop)[1]["python"]
    assert python["version"] is None and python["executable"] == str(shop.tmp / "bin" / "python")
    assert python["error"] == "the version probe exited 4"


@pytest.mark.parametrize("change, error", [
    (lambda r: r["recipes"]["ok"].update(require_clean="yes"), "invalid require_clean flag for recipe ok"),
    (lambda r: r["recipes"]["ok"].update(expects_tests=1), "invalid expects_tests flag for recipe ok"),
    (lambda r: r["recipes"]["ok"].update(expects_tests=True), "expects_tests needs keep to include run/junit.xml for recipe ok"),
    (lambda r: r["recipes"]["ok"].update(expects_tests=True, keep=["junit.xml"]),
     "expects_tests needs keep to include run/junit.xml for recipe ok"),
    (lambda r: r["recipes"]["ok"].update(requires_clean=True), "unexpected fields: requires_clean"),
    (lambda r: r["recipes"]["commit"].update(require_clean=True), "unexpected fields: require_clean"),
    (lambda r: r["recipes"]["commit"].update(expects_tests=True), "unexpected fields: expects_tests"),
    (lambda r: r["recipes"]["ok"].update(steps=[["$python", "$scratch/../escape"]]),
     "unsupported token in recipe ok: $scratch/../escape"),
    (lambda r: r["recipes"]["ok"].update(steps=[["$python", "$scratch/"]]), "unsupported token in recipe ok: $scratch/"),
    (lambda r: r["recipes"]["ok"].update(steps=[["$python", "$scratch/$paths"]]),
     "unsupported token in recipe ok: $scratch/$paths"),
    (lambda r: r["recipes"]["ok"].update(steps=[["$python", "$checkout/x"]]), "unsupported token in recipe ok: $checkout/x"),
    (lambda r: r.update(env={"X": "$scratch/junit.xml"}), "unsupported token in env: $scratch/junit.xml"),
    (lambda r: r["recipes"]["ok"].update(require_clean=True, export_git="yes"), "invalid export_git flag for recipe ok"),
    (lambda r: r["recipes"]["ok"].update(export_git=True), "export_git needs require_clean for recipe ok"),
    (lambda r: r["recipes"]["ok"].update(require_clean=False, export_git=True), "export_git needs require_clean for recipe ok"),
    (lambda r: r["recipes"]["commit"].update(export_git=True), "unexpected fields: export_git"),
])
def test_bad_evidence_flags_are_refused_with_an_exact_error(shop, change, error):
    change(shop.recipes)
    shop.save_recipes()
    shop.request_job("job-1", "ok")
    assert shop.jobs("run-open", expect=2) == {"error": error}
    assert shop.jobs("check-recipes", expect=2) == {"error": error}
    assert shop.states("job-1") == []


def test_check_recipes_summarizes_the_evidence_flags(shop):
    with_tests_recipe(shop, suite(1))
    summary = shop.jobs("check-recipes")
    assert summary["recipes"]["tests"]["require_clean"] is True and summary["recipes"]["tests"]["expects_tests"] is True
    assert summary["recipes"]["ok"]["require_clean"] is False and summary["recipes"]["ok"]["expects_tests"] is False
    assert summary["recipes"]["tests"]["export_git"] is False


def template_for_this_machine(shop):
    """The template with its placeholders filled the way an owner fills them: a real python, and nothing to hide."""
    recipes = json.loads(TEMPLATE.read_text())
    recipes.update(python=sys.executable, hide=[], ro_binds=[])
    shop.recipes_path.write_text(json.dumps(recipes))
    return recipes


def test_the_template_test_recipes_demand_a_clean_checkout_and_a_junit_report(shop):
    recipes = json.loads(TEMPLATE.read_text())["recipes"]
    for name in ("targeted-tests", "full-suite"):
        recipe = recipes[name]
        assert recipe["require_clean"] is True and recipe["expects_tests"] is True and recipe["keep"] == ["run/junit.xml"]
        step = recipe["steps"][0]
        assert step[step.index("--junitxml") + 1] == "$scratch/junit.xml"
        assert step[step.index("--basetemp") + 1] == "$scratch"


def test_the_template_lint_recipe_checks_the_fixed_tree_and_takes_no_paths(shop):
    lint = json.loads(TEMPLATE.read_text())["recipes"]["lint"]
    assert lint["steps"] == [["$python", "-m", "ruff", "check", "--isolated", "--no-cache", "--select", "E9,F63,F7,F82",
                              "aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk", "tests", ".github/scripts", "tools"]]
    assert not any("$paths" in word for step in lint["steps"] for word in step)


def test_the_template_loads_once_its_placeholders_are_filled(shop):
    template_for_this_machine(shop)
    summary = shop.jobs("check-recipes")
    assert summary["recipes_sha256"] == hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()
    assert summary["recipes"]["full-suite"] == {"kind": "command", "heavy": True, "heavy_tests": False, "sandbox": "bwrap",
                                                "require_clean": True, "expects_tests": True, "export_git": False}
    assert summary["recipes"]["lint"]["require_clean"] is False
    rust = {"kind": "command", "heavy": True, "heavy_tests": True, "sandbox": "bwrap", "require_clean": True,
            "export_git": True}
    assert summary["recipes"]["rust-targeted-tests"] == {**rust, "expects_tests": True}
    assert summary["recipes"]["rust-lint"] == {**rust, "expects_tests": False}


def test_the_template_rust_recipes_run_offline_on_a_commit_export_with_a_git_stub(shop):
    template = json.loads(TEMPLATE.read_text())
    assert template["env"]["CARGO_NET_OFFLINE"] == "true"
    assert template["env"]["CARGO_HOME"] in template["ro_binds"], "cargo's registry and git cache are read-only in the job"
    tests, lint = template["recipes"]["rust-targeted-tests"], template["recipes"]["rust-lint"]
    for recipe in (tests, lint):
        assert recipe["require_clean"] and recipe["export_git"] and recipe["heavy_tests"] and recipe["sandbox"] == "bwrap"
        assert all("--frozen" in step for step in recipe["steps"] if step[:2] in (["cargo", "nextest"], ["cargo", "clippy"]))
    assert tests["expects_tests"] is True and tests["keep"] == ["run/junit.xml"]
    config, run = tests["steps"]
    assert config[0] == "$python" and config[-2:] == ["$scratch", "$scratch/junit.xml"]
    assert run[:4] == ["cargo", "nextest", "--config-file", "$scratch/nextest-aegis.toml"]


def pytest_env(shop):
    shop.recipes["env"] = {"PYTHONPATH": "$checkout"}
    if "PYTHONUSERBASE" in os.environ:  # Local runs may keep pytest in the user site.
        shop.recipes["env"].update(PYTHONUSERBASE=os.environ["PYTHONUSERBASE"], PYTHONNOUSERSITE="")


@pytest.mark.parametrize("sandbox", ["none", pytest.param("bwrap", marks=needs_bubblewrap)])
def test_the_template_targeted_tests_recipe_counts_a_real_pytest_run(shop, sandbox):
    template = template_for_this_machine(shop)
    recipe = {**template["recipes"]["targeted-tests"], "sandbox": sandbox}
    shop.recipes["recipes"]["targeted-tests"] = recipe
    pytest_env(shop)
    shop.save_recipes()
    shop.request_job("job-1", "targeted-tests", paths=["tests/test_app.py"])
    assert shop.run_open()["rows"][0]["state"] == "completed", shop.receipts("job-1")[-1]["body"]
    receipt, result = final_result(shop)
    assert result["tests"] == {"total": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}
    assert "Tests: 1 total, 1 passed, 0 failed, 0 errors, 0 skipped." in receipt["body"]


def test_the_template_targeted_tests_recipe_fails_a_selection_that_collects_nothing(shop):
    template = template_for_this_machine(shop)
    shop.recipes["recipes"]["targeted-tests"] = {**template["recipes"]["targeted-tests"], "sandbox": "none"}
    pytest_env(shop)
    shop.save_recipes()
    (shop.checkout / "tests" / "test_app.py").write_text("def check_app():\n    pass\n")
    git(shop.checkout, "commit", "-qam", "no tests")
    shop.request_job("job-1", "targeted-tests", paths=["tests/test_app.py"])
    assert shop.run_open()["rows"][0]["state"] == "failed"
    result = final_result(shop)[1]
    assert result["steps"][0]["exit_code"] == 5 and result["tests"]["total"] == 0


def recorded(shop, identifier="job-1"):
    return json.loads((shop.workspace.store / "jobs" / "pilot" / identifier / "result.json").read_text())


def recipes_sha256(shop):
    return hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()


def test_a_clean_checkout_refuses_a_packet_that_claims_uncommitted_bytes_with_the_clean_reason(shop):
    with_tests_recipe(shop, suite(1))
    shop.request_job("job-1", "tests", dirty_content_sha256="ab" * 32)
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", CLEAN_REFUSAL)
    assert recorded(shop)["recipes_sha256"] == recipes_sha256(shop)


def first_job(shop, script, identifier="job-0", **changes):
    """A job that runs before the next one and changes what that one was admitted against."""
    shop.recipes["recipes"]["first"] = shop.command(["$python", "-c", script, "$checkout"])
    shop.save_recipes()
    shop.request_job(identifier, "first", **changes)


def assert_refused_before_running(shop, identifier, reason):
    row = next(row for row in shop.run_open()["rows"] if row["job"] == "pilot/" + identifier)
    assert row["state"] == "refused" and reason in row["reason"], row
    result = recorded(shop, identifier)
    assert result["state"] == "refused" and result["steps"] == [] and reason in result["reason"]
    assert result["recipes_sha256"] == recipes_sha256(shop)


def test_a_source_that_cannot_be_witnessed_when_the_slot_comes_is_refused_with_the_recipe_hash(shop):
    first_job(shop, "import shutil, sys; shutil.rmtree(sys.argv[1] + '/.git')")
    shop.request_job("job-1", "touch")
    assert_refused_before_running(shop, "job-1", "could not witness the source: ")
    assert not shop.sentinel.exists()


def test_a_source_that_changed_while_the_job_waited_is_refused_with_the_recipe_hash(shop):
    first_job(shop, DIRTY)
    shop.request_job("job-1", "touch")
    assert_refused_before_running(shop, "job-1", "source does not match the packet: it changed while the job waited")
    assert not shop.sentinel.exists()


SWITCH_BRANCH = "import subprocess, sys; subprocess.run(['git', 'switch', '-q', '-c', 'other'], cwd=sys.argv[1], check=True)"


def test_a_merge_whose_branch_changed_while_it_waited_is_refused_with_the_recipe_hash(shop):
    side, _ = two_sides(shop)
    first_job(shop, SWITCH_BRANCH)
    merge_request(shop, side)
    before = git(shop.checkout, "rev-parse", "HEAD")
    assert_refused_before_running(shop, "job-1", "HEAD points at refs/heads/other now, not refs/heads/feature/x")
    assert git(shop.checkout, "rev-parse", "HEAD") == before


LEASE = ("import json, subprocess, sys, time\n"
         "blob = json.dumps({'v': 1, 'lane': 'someone-else', 'role': 'implementer', 'owner': 'test@host',\n"
         "                   'claim_id': '9f2c0d1e2b3a4f56', 'gen': 1, 'branch': 'lane/someone-else',\n"
         "                   'paths': ['src/app.py'], 'ts': int(time.time()), 'ttl_s': 3600})\n"
         "oid = subprocess.run(['git', 'hash-object', '-w', '--stdin'], cwd=sys.argv[1], input=blob, text=True,\n"
         "                     capture_output=True, check=True).stdout.strip()\n"
         "subprocess.run(['git', 'update-ref', 'refs/aegis/lanes/someone-else', oid], cwd=sys.argv[1], check=True)\n")


def test_a_commit_whose_paths_were_leased_while_it_waited_is_refused_with_the_recipe_hash(shop):
    # The same bytes commit_request writes, so the first job is admitted against the source the commit needs.
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    (shop.checkout / "src" / "other.py").write_text("not part of this commit\n")
    (shop.checkout / "tests" / "test_app.py").write_text("def test_app():\n    assert True\n")
    first_job(shop, LEASE, dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    before = shop.head()["commit"]
    commit_request(shop)
    assert_refused_before_running(shop, "job-1", "path ownership changed before execution: ")
    assert "someone-else" in recorded(shop)["reason"] and git(shop.checkout, "rev-parse", "HEAD") == before


def test_a_template_test_recipe_whose_tests_are_all_skipped_fails(shop):
    template = template_for_this_machine(shop)
    shop.recipes["recipes"]["targeted-tests"] = {**template["recipes"]["targeted-tests"], "sandbox": "none"}
    pytest_env(shop)
    shop.save_recipes()
    (shop.checkout / "tests" / "test_app.py").write_text(
        "import pytest\n\n\n@pytest.mark.skip(reason='not today')\ndef test_app():\n    pass\n\n\n"
        "def test_other():\n    pytest.skip('nor this')\n")
    git(shop.checkout, "commit", "-qam", "all skipped")
    shop.request_job("job-1", "targeted-tests", paths=["tests/test_app.py"])
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("failed", "the run passed no tests")
    receipt, result = final_result(shop)
    assert (result["state"], result["exit_code"], result["reason"]) == ("failed", -1, "the run passed no tests")
    assert result["steps"][0]["exit_code"] == 0, "pytest itself exits 0 when everything is skipped"
    assert result["tests"] == {"total": 2, "passed": 0, "failed": 0, "errors": 0, "skipped": 2}
    assert receipt["receipt"]["reason"] == "the run passed no tests"


def test_expects_tests_needs_a_step_that_writes_the_junit_report(shop):
    with_tests_recipe(shop, suite(1))
    shop.recipes["recipes"]["tests"]["steps"] = [["$python", "-c", "print('no report')", "$scratch/other.xml"],
                                                 ["$python", "-c", "pass", "--junitxml", "$scratch/junit.xml.tmp"]]
    shop.save_recipes()
    error = "expects_tests needs a step that writes $scratch/junit.xml for recipe tests"
    assert shop.jobs("check-recipes", expect=2) == {"error": error}
    shop.request_job("job-1", "tests")
    assert shop.jobs("run-open", expect=2) == {"error": error}
    assert shop.states("job-1") == []



@pytest.fixture
def jobs2_fresh_cache(monkeypatch):
    """Preserve a fresh runner's per-test interpreter probe cache."""
    monkeypatch.setattr(jobs2_module, "PYTHON_INFO", {})


def load_jobs_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("hierarchy_jobs_probe_test", JOBS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gone(pid):
    try:
        with open("/proc/%d/stat" % pid) as stream:
            return stream.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        # Reaped between open() and read() reads as ESRCH (ProcessLookupError), not as a missing file.
        return True


def test_a_version_probe_past_its_timeout_takes_what_it_started_with_it(tmp_path, monkeypatch):
    jobs = load_jobs_module()
    monkeypatch.setattr(jobs, "PYTHON_PROBE_SECONDS", 0.5)
    monkeypatch.setattr(jobs, "PYTHON_INFO", {})
    pidfile = tmp_path / "sleeper.pid"
    # Not a python at all: it starts a sleeper that lets go of the pipe, then hangs itself, so only its group stops both.
    fake = tmp_path / "python"
    fake.write_text("#!/bin/sh\nsleep 30 >/dev/null 2>&1 </dev/null &\necho $! > %s\nexec sleep 30\n" % pidfile)
    fake.chmod(0o755)
    started = time.monotonic()
    info = jobs.python_info({"python": str(fake), "path": ["/usr/bin", "/bin"]})
    sleeper = int(pidfile.read_text())
    try:
        assert time.monotonic() - started < 10
        assert info["version"] is None and info["error"].startswith("the version probe took longer than"), info
        deadline = time.monotonic() + 2
        while not gone(sleeper):
            assert time.monotonic() < deadline, "the probe's child outlived its timeout"
            time.sleep(0.05)
    finally:
        try:
            os.kill(sleeper, signal.SIGKILL)
        except ProcessLookupError:
            pass



# Review fixes for item 6 (evidence/27-item6-review.json).
@pytest.mark.parametrize("junit, counts", [
    ("<testsuites><testsuite tests='2'><testsuite tests='2'/></testsuite></testsuites>",
     {"total": 2, "passed": 2, "failed": 0, "errors": 0, "skipped": 0}),
    ("<testsuite tests='5' failures='1'><testsuite tests='3' failures='1'/><testsuite tests='2' skipped='1'/></testsuite>",
     {"total": 5, "passed": 3, "failed": 1, "errors": 0, "skipped": 1}),
    ("<testsuites><testsuite tests='many'><testsuite tests='1'/></testsuite></testsuites>",
     {"total": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}),
])
def test_nested_testsuites_are_summed_only_at_the_leaves(shop, junit, counts):
    with_tests_recipe(shop, junit, 1 if counts["failed"] else 0)
    shop.request_job("job-1", "tests")
    shop.run_open()
    assert final_result(shop)[1]["tests"] == counts


@pytest.mark.parametrize("make", [
    "os.makedirs(path)",
    "os.makedirs(os.path.dirname(path), exist_ok=True); open(path + '.real', 'w').write('<testsuite tests=\"1\"/>'); "
    "os.symlink(path + '.real', path)",
])
def test_a_junit_report_that_is_kept_with_an_error_fails_the_job(shop, make):
    with_tests_recipe(shop, "x")
    shop.recipes["recipes"]["tests"]["steps"] = [["$python", "-c", "import os, sys\npath = sys.argv[1]\n" + make,
                                                  "$scratch/junit.xml"]]
    shop.save_recipes()
    shop.request_job("job-1", "tests")
    row = shop.run_open()["rows"][0]
    reason = "junit.xml is unreadable: not a regular file inside scratch"
    assert (row["state"], row["reason"]) == ("failed", reason), row
    result = final_result(shop)[1]
    assert (result["state"], result["exit_code"], result["reason"], result["tests"]) == ("failed", -1, reason, None)


def test_a_version_probe_that_prints_no_version_is_recorded_without_one(shop):
    fake_python(shop, 'case "$1" in -I) echo "not a version"; exit 0;; esac\nexec %s "$@"' % sys.executable)
    shop.request_job("job-1", "ok")
    assert shop.run_open()["rows"][0]["state"] == "completed"
    python = final_result(shop)[1]["python"]
    assert python["version"] is None and python["error"] == "the version probe printed no version"


def test_a_version_probe_whose_escaped_child_holds_the_pipe_still_returns(tmp_path, monkeypatch):
    jobs = load_jobs_module()
    monkeypatch.setattr(jobs, "PYTHON_PROBE_SECONDS", 0.5)
    monkeypatch.setattr(jobs, "PYTHON_PROBE_DRAIN_SECONDS", 1)
    monkeypatch.setattr(jobs, "PYTHON_INFO", {})
    pidfile = tmp_path / "escaped.pid"
    # Not a python: a child in its own session keeps stdout open, so the group kill misses it and EOF never comes.
    fake = tmp_path / "python"
    fake.write_text("#!/bin/sh\nsetsid sleep 60 &\necho $! > %s\nexec sleep 60\n" % pidfile)
    fake.chmod(0o755)
    started = time.monotonic()
    try:
        info = jobs.python_info({"python": str(fake), "path": ["/usr/bin", "/bin"]})
        assert time.monotonic() - started < 10, "the probe waited on a pipe its escaped child held"
        assert info["version"] is None and info["error"] == "the version probe took longer than 0.5 seconds", info
    finally:
        if pidfile.exists() and pidfile.read_text().strip():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


def paths_tests_recipe(shop):
    shop.recipes["recipes"]["paths-tests"] = shop.command(["$python", "-c", "print('ran')", "$paths"], require_clean=True)
    shop.save_recipes()


def commit_ignore(shop, pattern):
    (shop.checkout / ".gitignore").write_text(pattern + "\n")
    git(shop.checkout, "add", ".gitignore")
    git(shop.checkout, "commit", "-qm", "ignore")


@pytest.mark.parametrize("path", ["build/test_feature.py", "build/test_feature.py::test_it", "build"])
def test_a_clean_test_recipe_refuses_a_path_that_is_not_in_the_commit(shop, path):
    paths_tests_recipe(shop)
    commit_ignore(shop, "build/")
    (shop.checkout / "build").mkdir()
    (shop.checkout / "build" / "test_feature.py").write_text("def test_it():\n    pass\n")
    short = git(shop.checkout, "rev-parse", "HEAD")[:12]
    shop.request_job("job-1", "paths-tests", paths=[path])
    row = shop.run_open()["rows"][0]
    reason = "path %s is not in commit %s" % (path.partition("::")[0], short)
    assert (row["state"], row["reason"]) == ("refused", reason), row
    assert recorded(shop)["steps"] == []


# A require_clean job runs on an export of its commit, so code Git ignores in the checkout never runs in the commit's name.
# The ignored code writes run/evil below the job's scratch folder, which the recipe keeps, so its absence is evidence in
# either sandbox: under bubblewrap /tmp is private, and a marker there would prove nothing.
EVIL = ("import os\npath = os.path.join(os.path.dirname(os.environ['TMPDIR']), 'scratch', 'run')\n"
        "os.makedirs(path, exist_ok=True)\nopen(os.path.join(path, 'evil'), 'a').write('ran\\n')\n")
SANDBOXES = ["none", pytest.param("bwrap", marks=needs_bubblewrap)]


def clean_pytest_recipe(shop, sandbox):
    shop.recipes["recipes"]["pt"] = shop.command(
        ["$python", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", "$scratch/junit.xml", "$paths"],
        sandbox=sandbox, require_clean=True, expects_tests=True, keep=["run/junit.xml", "run/evil"])
    shop.recipes["env"] = {"PYTHONPATH": "$checkout"}
    if "PYTHONUSERBASE" in os.environ:  # Local runs may keep pytest in the user site.
        shop.recipes["env"].update(PYTHONUSERBASE=os.environ["PYTHONUSERBASE"], PYTHONNOUSERSITE="")
    shop.save_recipes()


def commit_all(shop, message="c"):
    git(shop.checkout, "add", "-A")
    git(shop.checkout, "commit", "-qm", message)


def evil_ran(result):
    return next(row for row in result["kept"] if row["path"] == "run/evil").get("error") != "missing"


def plant(shop, case):
    """Code outside the commit, as each case hides it; returns the paths to name and whether the run can pass."""
    c = shop.checkout
    (c / ".gitignore").write_text("build/\nconftest.py\npytest.ini\ntests/vendor/\ntests/evil\nsitecustomize.py\npytest.py\n")
    commit_all(shop, "ignore")
    (c / "build").mkdir()
    (c / "build" / "test_real.py").write_text(EVIL + "def test_real():\n    pass\n")
    if case == "committed_symlink_to_ignored_file":
        os.symlink("../build/test_real.py", c / "tests" / "test_link.py")
        commit_all(shop)
        return ["tests/test_link.py"], False
    if case == "committed_symlink_to_ignored_dir":
        os.symlink("../build", c / "tests" / "linkdir")
        commit_all(shop)
        return ["tests/linkdir"], False
    if case == "ignored_conftest_beside":
        (c / "tests" / "conftest.py").write_text(EVIL)
    elif case in ("ignored_root_conftest", "ignored_root_conftest_dot"):
        (c / "conftest.py").write_text(EVIL)
        return ["tests" if case == "ignored_root_conftest" else "."], True
    elif case == "ignored_pytest_ini_plugin":
        (c / "pytest.ini").write_text("[pytest]\naddopts = -p build.plug\n")
        (c / "build" / "__init__.py").write_text("")
        (c / "build" / "plug.py").write_text(EVIL)
    elif case == "ignored_nested_repo":
        vendor = c / "tests" / "vendor"
        vendor.mkdir()
        git(vendor, "init", "-q")
        (vendor / "test_evil.py").write_text(EVIL + "def test_e():\n    pass\n")
        return ["tests"], True
    elif case == "ignored_symlink_dir":
        os.symlink("../build", c / "tests" / "evil")
        return ["tests"], True
    elif case == "ignored_pytest_shadow":
        (c / "pytest.py").write_text(EVIL + "import sys\nsys.exit(0)\n")
    elif case == "ignored_sitecustomize":
        (c / "sitecustomize.py").write_text(EVIL)
    return ["tests/test_app.py"], True


@pytest.mark.parametrize("sandbox", SANDBOXES)
@pytest.mark.parametrize("case", ["ignored_conftest_beside", "ignored_root_conftest", "ignored_root_conftest_dot",
                                  "ignored_pytest_ini_plugin", "ignored_nested_repo", "ignored_symlink_dir",
                                  "ignored_pytest_shadow", "ignored_sitecustomize", "committed_symlink_to_ignored_file",
                                  "committed_symlink_to_ignored_dir"])
def test_a_clean_test_job_never_runs_code_outside_its_commit(shop, case, sandbox):
    clean_pytest_recipe(shop, sandbox)
    paths, passes = plant(shop, case)
    assert git(shop.checkout, "status", "--porcelain=v1", "--untracked-files=all") == ""
    shop.request_job("job-1", "pt", paths=paths)
    row = shop.run_open()["rows"][0]
    result = recorded(shop)
    assert not evil_ran(result), "%s ran code outside the commit: %s" % (case, row)
    if passes:
        assert row["state"] == "completed", row
        assert (result["tests"]["total"], result["tests"]["passed"]) == (1, 1), "the committed test still runs and counts"
    else:
        # The link is in the commit, its target is not, so it dangles in the export and the run fails instead of passing.
        assert row["state"] == "failed" and not (result["tests"] or {}).get("passed"), row
    entries = len(git(shop.checkout, "ls-tree", "-r", "--name-only", "HEAD").splitlines())
    assert result["source_export"] == {"commit": git(shop.checkout, "rev-parse", "HEAD"), "removed": True,
                                       "tree": git(shop.checkout, "rev-parse", "HEAD^{tree}"), "entries": entries,
                                       "bytes": result["source_export"]["bytes"]}
    assert not (shop.workspace.store / "jobs" / "pilot" / "job-1" / "source").exists(), "the export is removed after the run"


def remove_tree(folder):
    """The export's folders are read-only, so they are made writable before the removal."""
    os.chmod(folder, 0o700)
    for current, folders, _ in os.walk(folder):
        for child in folders:
            if not os.path.islink(os.path.join(current, child)):
                os.chmod(os.path.join(current, child), 0o700)
    shutil.rmtree(folder)


@pytest.mark.parametrize("sandbox", SANDBOXES)
def test_a_clean_test_job_runs_in_the_export_and_bubblewrap_hides_the_live_checkout(sandbox, tmp_path_factory, request):
    # Outside /tmp, because bubblewrap mounts an empty /tmp anyway: a checkout there would look hidden even if the
    # export's own mounts left it visible.
    base = Path(tempfile.mkdtemp(prefix="aegis-jobs-", dir="/var/tmp"))
    try:
        shop = Shop(base, source_seed=provision_fixtures.worker_source_seed(tmp_path_factory, request))
        clean_pytest_recipe(shop, sandbox)
        commit_ignore(shop, "build/")
        (shop.checkout / "build").mkdir()
        (shop.checkout / "build" / "local.txt").write_text("ignored\n")
        export = shop.workspace.store / "jobs" / "pilot" / "job-1" / "source"
        live = str(shop.checkout / "build" / "local.txt")
        assert not live.startswith("/tmp/")
        (shop.checkout / "tests" / "test_where.py").write_text(
            "import os, subprocess\n\ndef test_where():\n"
            "    assert os.getcwd() == %r and os.environ['PYTHONPATH'] == %r\n"
            "    assert os.path.exists(%r) == %r\n"
            "    assert not os.access('tests/test_where.py', os.W_OK), 'the export is read-only'\n"
            "    assert subprocess.run(['git', 'rev-parse', '--git-dir'], capture_output=True).returncode != 0, 'no repository'\n"
            % (str(export), str(export), live, sandbox == "none"))
        commit_all(shop)
        shop.request_job("job-1", "pt", paths=["tests/test_where.py"])
        row = shop.run_open()["rows"][0]
        assert row["state"] == "completed", (row, (shop.workspace.store / "jobs" / "pilot" / "job-1" / "step-1.log").read_text())
    finally:
        remove_tree(base)


def test_a_clean_test_job_runs_a_directory_without_a_test_file_only_info_exclude_hides(shop):
    clean_pytest_recipe(shop, "none")
    (shop.checkout / ".git" / "info" / "exclude").write_text("tests/test_extra.py\n")
    (shop.checkout / "tests" / "test_extra.py").write_text(EVIL + "def test_extra():\n    pass\n")
    assert git(shop.checkout, "status", "--porcelain=v1", "--untracked-files=all") == ""
    shop.request_job("job-1", "pt", paths=["tests/test_extra.py"])
    shop.request_job("job-2", "pt", paths=["tests"])
    rows = {row["job"]: row for row in shop.run_open()["rows"]}
    short = git(shop.checkout, "rev-parse", "HEAD")[:12]
    assert rows["pilot/job-1"]["reason"] == "path tests/test_extra.py is not in commit " + short
    assert rows["pilot/job-2"]["state"] == "completed", rows["pilot/job-2"]
    result = recorded(shop, "job-2")
    assert result["tests"]["total"] == 1 and not evil_ran(result), "only the committed test ran"


def test_a_clean_test_job_ignores_a_test_file_added_while_it_waited(shop):
    clean_pytest_recipe(shop, "none")
    commit_ignore(shop, "tests/test_local_*.py")
    first_job(shop, "import sys; open(sys.argv[1] + '/tests/test_local_x.py', 'w').write(%r)"
              % (EVIL + "def test_x():\n    pass\n"))
    shop.request_job("job-1", "pt", paths=["tests"])
    rows = {row["job"]: row for row in shop.run_open()["rows"]}
    assert rows["pilot/job-0"]["state"] == "completed", "an ignored file changes no status, so job-0 itself passed"
    assert rows["pilot/job-1"]["state"] == "completed", rows["pilot/job-1"]
    result = recorded(shop)
    assert result["tests"]["total"] == 1 and not evil_ran(result)
    assert (shop.checkout / "tests" / "test_local_x.py").exists(), "the live checkout still holds it"


@pytest.mark.parametrize("make, reason", [
    (lambda c: os.symlink("/etc/hostname", c / "tests" / "outside"), "the commit has a symlink that leaves it: tests/outside"),
    (lambda c: os.symlink("../../x", c / "tests" / "outside"), "the commit has a symlink that leaves it: tests/outside"),
    # Each link stays inside lexically, but d resolves to the export's root, so esc resolves two folders above it.
    (lambda c: (os.symlink(".", c / "d"), os.symlink("d/d/../..", c / "esc"), os.symlink("../esc/x", c / "tests" / "via")),
     "the commit has a symlink that leaves it: esc -> d/d/../.."),
])
def test_a_commit_that_cannot_be_exported_exactly_is_refused_before_anything_runs(shop, make, reason):
    clean_pytest_recipe(shop, "none")
    make(shop.checkout)
    commit_all(shop)
    shop.request_job("job-1", "pt", paths=["tests/test_app.py"])
    row = shop.run_open()["rows"][0]
    short = git(shop.checkout, "rev-parse", "HEAD")[:12]
    assert row["state"] == "refused" and row["reason"].startswith("could not export commit %s: " % short), row
    assert reason in row["reason"], row
    assert recorded(shop)["steps"] == []
    assert not (shop.workspace.store / "jobs" / "pilot" / "job-1" / "source").exists()


POINTER = "version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 3\n" % ("0" * 64)


@pytest.mark.parametrize("case", ["export-ignore", "export-subst", "eol", "lfs-filter", "replace-ref"])
def test_a_clean_test_job_exports_the_committed_bytes_whatever_attributes_or_replace_refs_say(shop, case):
    """The export reads blobs, never a checkout or an archive, so no attribute, filter or replace ref changes a byte."""
    clean_pytest_recipe(shop, "none")
    c = shop.checkout
    marker = shop.tmp / "smudge-ran"
    expected = {"src/app.py": "value = 1\n", "tests/test_app.py": "def test_app():\n    pass\n"}
    if case == "export-ignore":
        (c / ".gitattributes").write_text("tests/test_app.py export-ignore\n")
    elif case == "export-subst":
        (c / ".gitattributes").write_text("src/app.py export-subst\n")
        expected["src/app.py"] = "$Format:%H$\n"
    elif case == "eol":
        (c / ".gitattributes").write_text("* text eol=crlf\n")
    elif case == "lfs-filter":
        # As Git LFS sets it up: the commit holds a pointer, and the repository's own config names a smudge filter.
        git(c, "config", "filter.lfs.smudge", "echo ran >> '%s'; cat" % marker)
        git(c, "config", "filter.lfs.clean", "cat")
        (c / ".gitattributes").write_text("*.bin filter=lfs\n")
        expected["data.bin"] = POINTER
    for path, data in expected.items():
        (c / path).write_text(data)
    (c / "tests" / "test_exact.py").write_text(
        "import pathlib\n\ndef test_exact():\n    for path, data in %r.items():\n"
        "        assert pathlib.Path(path).read_bytes() == data.encode(), path\n" % expected)
    commit_all(shop)
    if case == "replace-ref":
        (shop.tmp / "other.py").write_text("value = 2\n")
        git(c, "replace", git(c, "rev-parse", "HEAD:src/app.py"), git(c, "hash-object", "-w", str(shop.tmp / "other.py")))
    assert git(c, "status", "--porcelain=v1", "--untracked-files=all") == "" and not marker.exists()
    shop.request_job("job-1", "pt", paths=["tests/test_exact.py"])
    row = shop.run_open()["rows"][0]
    log = shop.workspace.store / "jobs" / "pilot" / "job-1" / "step-1.log"
    assert row["state"] == "completed", (row, log.read_text() if log.exists() else "no step ran")
    result = recorded(shop)
    assert (result["tests"]["total"], result["tests"]["passed"]) == (1, 1)
    assert result["source_export"]["entries"] == len(git(c, "ls-tree", "-r", "--name-only", "HEAD").splitlines())
    assert not marker.exists(), "the smudge filter ran"


# Hand-made trees: Git's own porcelain refuses most of these names, so they are written as raw objects.
def stored(repo, data, kind="blob"):
    return subprocess.run(["git", "hash-object", "-t", kind, "--literally", "-w", "--stdin"], cwd=repo, input=data,
                          capture_output=True, check=True).stdout.decode().strip()


def hand_made_tree(repo, rows):
    """rows are (mode, name, id); they are sorted here as Git sorts a tree, folders as if their name ended in '/'."""
    rows = sorted(rows, key=lambda row: row[1] + (b"/" if row[0] == "40000" else b""))
    return stored(repo, b"".join(mode.encode() + b" " + name + b"\0" + bytes.fromhex(oid) for mode, name, oid in rows), "tree")


def hand_made_commit(tmp_path, rows):
    repo = tmp_path / "repo"
    if not repo.exists():
        repo.mkdir()
        git(repo, "init", "-q")
    tree = hand_made_tree(repo, rows(repo))
    commit = git(repo, "commit-tree", tree, "-m", "hand-made")
    return repo, commit, tree


def export_or_refusal(jobs, repo, commit, tree, target, **options):
    try:
        return jobs.export_commit(str(repo), commit, tree, str(target), **options)
    except jobs.ERRORS as exc:
        return str(exc)


def test_an_export_whose_link_checks_outlast_its_deadline_is_refused_within_it(tmp_path, monkeypatch):
    """The link walk shares the export's one deadline, so a tree of costly links is refused instead of stalling."""
    jobs = load_jobs_module()
    monkeypatch.setattr(jobs, "EXPORT_SECONDS", 1.5)
    # Each link of the chain is within the hop limit but makes the resolver stat x 800 times, and many links share it.
    detour = b"x/../" * 800

    def rows(repo):
        chain = [("120000", b"a%02d" % i, stored(repo, detour + b"a%02d" % (i + 1))) for i in range(35)]
        many = [("120000", b"p%04d" % i, stored(repo, b"a00")) for i in range(400)]
        folder = hand_made_tree(repo, [("100644", b"keep", stored(repo, b"x\n"))])
        return chain + many + [("100644", b"a35", stored(repo, b"end\n")), ("40000", b"x", folder)]

    repo, commit, tree = hand_made_commit(tmp_path, rows)
    started = time.monotonic()
    outcome = export_or_refusal(jobs, repo, commit, tree, tmp_path / "out")
    assert outcome == "the export took longer than 1.5 seconds", outcome
    assert time.monotonic() - started < 6, "the link walk ran past the export's deadline"


@pytest.mark.parametrize("links, shown", [
    # 45 links in a row to a file inside the export: the kernel stops at 40 hops, and so does the check.
    (lambda repo: [("120000", b"l%02d" % i, stored(repo, b"l%02d" % (i + 1))) for i in range(45)]
     + [("100644", b"l45", stored(repo, b"end\n"))], "l00 -> l01"),
    (lambda repo: [("120000", b"a", stored(repo, b"b")), ("120000", b"b", stored(repo, b"a"))], "a -> b"),
])
def test_an_export_refuses_a_link_that_loops_or_needs_more_than_40_hops(tmp_path, links, shown):
    jobs = load_jobs_module()
    repo, commit, tree = hand_made_commit(tmp_path, links)
    outcome = export_or_refusal(jobs, repo, commit, tree, tmp_path / "out")
    assert outcome == "the commit has a symlink that loops or passes more than 40 links: " + shown, outcome


@pytest.mark.parametrize("rows, name", [
    (lambda repo: [("100644", b".git", stored(repo, b"gitdir: /elsewhere\n"))], ".git"),
    (lambda repo: [("40000", b".GIT", hand_made_tree(repo, [("100644", b"config", stored(repo, b"[core]\n"))]))],
     ".GIT/config"),
    (lambda repo: [("40000", b"sub", hand_made_tree(repo, [("100644", b".Git", stored(repo, b"x\n"))]))], "sub/.Git"),
])
def test_an_export_refuses_a_commit_that_holds_a_git_entry(tmp_path, rows, name):
    """A .git in the export would make it, or a folder of it, a repository whose config Git runs."""
    jobs = load_jobs_module()
    repo, commit, tree = hand_made_commit(tmp_path, lambda repo: rows(repo) + [("100644", b"f", stored(repo, b"x\n"))])
    for git_stub in (False, True):
        outcome = export_or_refusal(jobs, repo, commit, tree, tmp_path / "out", git_stub=git_stub)
        assert outcome == "the commit holds a .git entry: " + name, outcome
        assert not (tmp_path / "out").exists(), "refused before a byte was written"


def test_a_partial_clone_is_refused_before_a_missing_object_is_fetched(shop):
    """A partial clone fetches a missing object on read, through whatever command its remote config names."""
    clean_pytest_recipe(shop, "none")
    c = shop.checkout
    (c / "tests" / "data.txt").write_text("lazy\n")
    commit_all(shop)
    missing = git(c, "rev-parse", "HEAD:tests/data.txt")
    os.remove(c / ".git" / "objects" / missing[:2] / missing[2:])
    marker = shop.tmp / "fetch-ran"
    for key, value in {"core.repositoryformatversion": "1", "extensions.partialClone": "origin",
                       "remote.origin.url": "ext::sh -c touch%% %s" % marker, "remote.origin.promisor": "true",
                       "protocol.ext.allow": "always"}.items():
        git(c, "config", key, value)
    shop.request_job("job-1", "pt", paths=["tests/test_app.py"])
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "a partial clone cannot be exported: its missing objects would be "
                                                        "fetched"), row
    jobs = load_jobs_module()
    outcome = export_or_refusal(jobs, c, git(c, "rev-parse", "HEAD"), git(c, "rev-parse", "HEAD^{tree}"), shop.tmp / "out")
    assert outcome == "a partial clone cannot be exported: its missing objects would be fetched", outcome
    assert not marker.exists(), "the fetch command ran"


def test_a_commit_whose_blob_is_missing_is_refused_with_its_name(shop):
    c = shop.checkout
    (c / "tests" / "data.txt").write_text("gone\n")
    commit_all(shop)
    missing = git(c, "rev-parse", "HEAD:tests/data.txt")
    os.remove(c / ".git" / "objects" / missing[:2] / missing[2:])
    jobs = load_jobs_module()
    outcome = export_or_refusal(jobs, c, git(c, "rev-parse", "HEAD"), git(c, "rev-parse", "HEAD^{tree}"), shop.tmp / "out")
    assert outcome == "the commit lacks the object of tests/data.txt: " + missing, outcome


def test_a_replaced_tree_cannot_make_a_path_look_present_in_the_commit(tmp_path):
    jobs = load_jobs_module()
    repo, commit, tree = hand_made_commit(tmp_path, lambda repo: [("100644", b"f", stored(repo, b"1\n"))])
    fake = hand_made_tree(repo, [("100644", b"f", stored(repo, b"1\n")), ("100644", b"only_in_fake", stored(repo, b"2\n"))])
    git(repo, "replace", tree, fake)
    with pytest.raises(ValueError) as refused:
        jobs.refuse_paths_outside_commit(str(repo), commit, ["only_in_fake"])
    assert str(refused.value) == "path only_in_fake is not in commit " + commit[:12]


def stub_listing(stub):
    rows = {}
    for current, folders, files in os.walk(stub):
        for name in folders + files:
            path = Path(current) / name
            rows[str(path.relative_to(stub))] = (oct(path.lstat().st_mode & 0o7777), path.is_dir())
    return rows


def test_an_export_with_a_git_stub_holds_only_head_config_and_empty_objects_and_refs(tmp_path):
    jobs = load_jobs_module()
    repo, commit, tree = hand_made_commit(tmp_path, lambda repo: [("100644", b"f", stored(repo, b"x\n")),
                                                                  ("120000", b"l", stored(repo, b"f"))])
    plain = jobs.export_commit(str(repo), commit, tree, str(tmp_path / "plain"))
    stubbed = jobs.export_commit(str(repo), commit, tree, str(tmp_path / "out"), git_stub=True)
    assert stubbed == {**plain, "git_stub": True}, "the stub changes neither the entries nor the bytes recorded"
    assert "git_stub" not in plain and not (tmp_path / "plain" / ".git").exists()
    stub = tmp_path / "out" / ".git"
    assert stub_listing(stub) == {"HEAD": ("0o444", False), "config": ("0o444", False), "objects": ("0o555", True),
                                  "refs": ("0o555", True)}
    assert oct(stub.stat().st_mode & 0o7777) == "0o555" and oct((tmp_path / "out").stat().st_mode & 0o7777) == "0o555"
    assert (stub / "HEAD").read_text() == commit + "\n" and len(commit) == 40
    assert (stub / "config").read_text() == "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
    for target in ("plain", "out"):
        os.chmod(tmp_path / target, 0o700)
        remove_tree(tmp_path / target)


# A build step, like a build.rs that stamps its provenance, that asks git about HEAD from the export's root and from a
# folder below it, and keeps the answers as evidence.
GIT_PROBE = ("import json, os, subprocess, sys\nrows = {}\n"
             "for where in ('.', 'src'):\n"
             "    for args in (['HEAD'], ['--git-path', 'HEAD'], ['--symbolic-full-name', 'HEAD'], ['--show-toplevel']):\n"
             "        done = subprocess.run(['git', 'rev-parse'] + args, cwd=where, capture_output=True, text=True)\n"
             "        rows[' '.join([where] + args)] = [done.returncode, done.stdout.strip(), os.path.abspath(where)]\n"
             "os.makedirs(sys.argv[1], exist_ok=True)\n"
             "open(os.path.join(sys.argv[1], 'git.json'), 'w').write(json.dumps(rows))\n")


def git_probe_job(shop, sandbox, **flags):
    shop.recipes["recipes"]["build"] = shop.command(["$python", "-I", "-c", GIT_PROBE, "$scratch"], sandbox=sandbox,
                                                    require_clean=True, keep=["run/git.json"], **flags)
    shop.save_recipes()
    shop.request_job("job-1", "build")
    row = shop.run_open()["rows"][0]
    assert row["state"] == "completed", row
    result = final_result(shop)[1]
    kept = next(row for row in result["kept"] if row["path"] == "run/git.json")
    data = Path(kept["copy"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == kept["sha256"], "the kept answers are the evidence the result names"
    return result, json.loads(data)


def outer_repository(shop):
    """A repository around the whole store with a HEAD of its own, which the job must never resolve."""
    git(shop.tmp, "init", "-q")
    git(shop.tmp, "commit", "-q", "--allow-empty", "-m", "outer")
    outer = git(shop.tmp, "rev-parse", "HEAD")
    assert outer != shop.head()["commit"]
    return outer


@pytest.mark.parametrize("sandbox", SANDBOXES)
def test_git_in_an_export_git_job_resolves_the_stub_and_the_packet_commit(shop, sandbox):
    outer = outer_repository(shop)
    commit = shop.head()["commit"]
    result, rows = git_probe_job(shop, sandbox, export_git=True)
    assert result["source_export"]["git_stub"] is True and result["source_export"]["removed"] is True
    export = str(shop.workspace.store / "jobs" / "pilot" / "job-1" / "source")
    assert outer not in json.dumps(rows)
    for where in (".", "src"):
        assert rows[where + " HEAD"][:2] == [0, commit], rows
        assert rows[where + " --symbolic-full-name HEAD"][:2] == [0, "HEAD"], "a detached HEAD at the commit"
        code, path, cwd = rows[where + " --git-path HEAD"]
        assert code == 0 and os.path.normpath(os.path.join(cwd, path)) == os.path.join(export, ".git", "HEAD"), rows
        assert rows[where + " --show-toplevel"][:2] == [0, export], "the stub, never the live checkout or the outer repo"


@pytest.mark.parametrize("sandbox", SANDBOXES)
def test_git_in_a_clean_job_without_export_git_finds_no_repository(shop, sandbox):
    outer_repository(shop)
    result, rows = git_probe_job(shop, sandbox)
    assert "git_stub" not in result["source_export"]
    assert len(rows) == 8 and all(code != 0 and not out for code, out, _ in rows.values()), rows


# Git in a folder of the export, as a build script that runs git from its own crate folder does.
BARE_PROBE = ("import json, os, subprocess, sys\nrows = {}\n"
              "for where in ('fake', 'fake/sub'):\n"
              "    for args in (['rev-parse', 'HEAD'], ['cat-file', '-t', sys.argv[2]], ['config', '--get', 'core.pager']):\n"
              "        done = subprocess.run(['git'] + args, cwd=where, capture_output=True, text=True)\n"
              "        rows[' '.join([where] + args)] = [done.returncode, done.stdout.strip()]\n"
              "os.makedirs(sys.argv[1], exist_ok=True)\n"
              "open(os.path.join(sys.argv[1], 'git.json'), 'w').write(json.dumps(rows))\n")


@pytest.mark.parametrize("export_git", [True, False])
@pytest.mark.parametrize("sandbox", SANDBOXES)
def test_a_committed_folder_shaped_like_a_bare_repository_is_never_git_in_the_export(shop, sandbox, export_git):
    """A folder holding HEAD, objects/ and refs/ is a bare repository to Git's discovery, which would take its HEAD, its
    config and its alternates, here the live checkout's objects, in place of the stub or nothing."""
    c = shop.checkout
    fake = c / "fake"
    for folder in ("objects/info", "refs", "sub"):
        (fake / folder).mkdir(parents=True)
    (fake / "refs" / "keep").write_text("")
    (fake / "sub" / "keep").write_text("")
    (fake / "HEAD").write_text("1" * 40 + "\n")
    (fake / "objects" / "info" / "alternates").write_text(str(c / ".git" / "objects") + "\n")
    (fake / "config").write_text("[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tpager = planted\n")
    commit_all(shop)
    commit = shop.head()["commit"]
    shop.recipes["recipes"]["build"] = shop.command(["$python", "-I", "-c", BARE_PROBE, "$scratch", commit], sandbox=sandbox,
                                                    require_clean=True, keep=["run/git.json"], export_git=export_git)
    shop.save_recipes()
    shop.request_job("job-1", "build")
    row = shop.run_open()["rows"][0]
    assert row["state"] == "completed", row
    kept = next(row for row in final_result(shop)[1]["kept"] if row["path"] == "run/git.json")
    rows = json.loads(Path(kept["copy"]).read_text())
    assert len(rows) == 6 and all(code != 0 and not out for code, out in rows.values()), rows


def test_an_export_that_fails_its_checks_never_gets_a_git_stub(tmp_path):
    """The stub is the last thing written, so a partial export left by a refusal is never a repository."""
    jobs = load_jobs_module()
    repo, commit, tree = hand_made_commit(tmp_path, lambda repo: [("100644", b"f", stored(repo, b"x\n")),
                                                                  ("120000", b"out", stored(repo, b"../../x"))])
    outcome = export_or_refusal(jobs, repo, commit, tree, tmp_path / "out", git_stub=True)
    assert outcome == "the commit has a symlink that leaves it: out -> ../../x", outcome
    assert (tmp_path / "out" / "f").exists() and not os.path.lexists(tmp_path / "out" / ".git")
    remove_tree(tmp_path / "out")


def test_an_admitted_derivation_with_a_busy_execution_lock_stays_retryable(kind_shop, monkeypatch, capsys):
    import fcntl
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    before = shop.head()
    request_derive(shop)
    jobs = load_jobs_module()
    original_flock = fcntl.flock
    blocked = []

    def flock(fd, operation):
        if operation == (fcntl.LOCK_EX | fcntl.LOCK_NB):
            blocked.append(True)
            raise BlockingIOError("fixture execution disposition is busy")
        return original_flock(fd, operation)

    with monkeypatch.context() as patch:
        patch.setattr(fcntl, "flock", flock)
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        row = job_row(json.loads(capsys.readouterr().out))
    folder = shop.workspace.store / "jobs/pilot/job-1"
    assert blocked and (folder / "admitted.json").exists()
    assert row["state"] == "settle_pending" and row["error"] == "job disposition is busy: pilot/job-1"
    assert "Run run-open again" in row["next_action"]
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert shop.head() == before
    assert job_row(shop.run_open())["state"] == "completed"
    assert shop.head()["commit"] != before["commit"]
    assert shop.run_open()["rows"] == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("completed_prior", [False, True])
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-byte-compatible", "host-plan"])
def test_jobs2_released_unexecuted_grant_is_not_recovered_after_a_replay_fault(
        kind_shop, monkeypatch, capsys, kind, completed_prior, planned):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    if completed_prior:
        add_recipe_of_kind(shop, "prior", kind)
        shop.request_job("job-0", "prior")
    request_kind_job(shop, kind)
    jobs = jobs2_module
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    first_event = sorted((shop.workspace.store / "events").iterdir())[0]
    original_bytes = first_event.read_bytes()
    released, post_reads = [], []

    def grant(store, granted_kind, **kwargs):
        answer = original_grant(store, granted_kind, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["holder"] == JOB_HOLDER:
            released.append(answer[1]["granted"]["request_id"])
            shop.workspace.release(released[-1])
        return answer

    def load(store):
        if released:
            post_reads.append(True)
            if len(post_reads) == 2:
                first_event.write_bytes(b"{}")
        return original_load(store)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
            report = json.loads(output)
    finally:
        first_event.write_bytes(original_bytes)
    assert len(released) == 1 and len(post_reads) == 2
    own = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    waiting = {"job": "pilot/job-1", "state": "waiting", "kind": kind,
               "reason": "post_grant_ledger_unreadable"}
    if planned:
        waiting_rows = [row for row in own if row["state"] == "waiting"]
        assert waiting_rows == [{key: value for key, value in waiting.items() if key != "reason"}], report
        faults = [row for row in report["rows"] if row.get("reason") == "post_grant_ledger_unreadable"]
        assert len(faults) == 1 and faults[0]["state"] == "settle_pending"
        assert "request_id" not in faults[0]
        if not completed_prior:
            assert len(own) == 2 and "has not started" in faults[0]["next_action"]
    else:
        # Literal base recovery rows: no repository history is needed in a full-suite snapshot.
        legacy = [waiting, {"job": "pilot/job-1", "state": "settle_pending",
                           "reason": "post_grant_ledger_unreadable", "next_action":
                           "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."}]
        terminal = report["rows"][:1] if completed_prior else []
        expected = json.dumps({"rows": terminal + legacy}, sort_keys=True) + "\n"
        assert output.encode("utf-8") == expected.encode("utf-8")
    if completed_prior and planned:
        assert [row["state"] for row in report["rows"] if row.get("job") == "pilot/job-0"] == [
            "completed", "settle_pending"]
    elif completed_prior:
        assert [row["state"] for row in report["rows"] if row.get("job") == "pilot/job-0"] == ["completed"]
    assert requests_of(shop, kind) == {released[0]: "released"}
    assert_did_not_run(shop)
    assert job_row(shop.run_open())["state"] == "completed"
    assert shop.sentinel.read_text() == "ran\n"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["own-publication-cleanup", "peer-before-enospc", "before-publication",
                                 "claim-read-error", "oversized-claim", "malformed-claim", "non-object-claim",
                                 "peer-search-only-ancestor", "descriptor-support-unavailable",
                                 "cleanup-missing-claim", "cleanup-renamed-ancestor", "cleanup-denied-missing-claim",
                                 "cleanup-collision-missing-claim", "cleanup-runtime-error", "publication-directory-denied"])
def test_jobs2_derived_publication_failure_tracks_only_this_attempts_fence(
        kind_shop, monkeypatch, capsys, fault):
    from types import SimpleNamespace
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    search_only = fault == "peer-search-only-ancestor"
    ancestor_mode = shop.tmp.stat().st_mode & 0o7777
    if search_only:
        if os.name != "posix" or not hasattr(os, "O_PATH"):
            pytest.skip("search-only ancestor requires POSIX modes and Linux O_PATH")
        if os.geteuid() == 0:
            pytest.skip("root bypasses search-only ancestor read permissions")
        try:
            shop.tmp.chmod(0o111)
            try:
                with os.scandir(shop.tmp):
                    pass
            except PermissionError:
                pass
            else:
                pytest.skip("chmod is ineffective: search-only ancestor remains listable")
        finally:
            shop.tmp.chmod(ancestor_mode)
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    jobs = jobs2_module
    mailbox = jobs2_mailbox
    original_open = jobs.os.open
    original_execution_publish = jobs.Job.publish_execution_claim
    original_run_job = jobs.run_job
    folder = shop.workspace.store / "jobs/pilot/job-1"
    execution = folder / "execution.json"
    retained = shop.tmp / "retained-execution-folder"
    injected, peer_bytes, descriptors = [], {}, []
    peer_completed = fault in ("peer-before-enospc", "peer-search-only-ancestor")
    unsupported = []

    def refuse_descriptors():
        unsupported.append(True)
        injected.append("unsupported-descriptors")
        raise ValueError("secure brief publication requires directory descriptor support")

    def fdopen(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        if fault == "oversized-claim":
            pytest.fail("oversized execution claim must be refused before reading")
        raise OSError(errno.EIO, "fixture execution claim read failed")

    def open_pending(path, flags, *args, **kwargs):
        if Path(path).name.startswith(".pending-") and flags & os.O_CREAT:
            injected.append("pending-enospc")
            raise OSError(errno.ENOSPC, "fixture execution publication full")
        return original_open(path, flags, *args, **kwargs)

    def publish(job, raw):
        if fault == "publication-directory-denied":
            import hierarchy_fresh_brief

            def denied(path):
                injected.append("directory-denied")
                raise hierarchy_fresh_brief.PublicationRefused("permission denied: private-input-must-not-echo")

            patch.enter_context(jobs2_patch.object(jobs2_fresh_brief, "open_directory", denied))
            return original_execution_publish(job, raw)
        if fault == "descriptor-support-unavailable":
            import hierarchy_fresh_brief
            patch.enter_context(jobs2_patch.object(jobs2_fresh_brief, "require_secure_publication", refuse_descriptors))
            return original_execution_publish(job, raw)
        if peer_completed or fault == "before-publication":
            if search_only:
                shop.tmp.chmod(0o111)
                assert execution.read_bytes() == peer_bytes["execution.json"], "claim is readable by pathname"
            with ExitStack() as pending_patch:
                pending_patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_pending})))
                return original_execution_publish(job, raw)
        if fault.startswith("cleanup-"):
            def unlink_pending(name, *args, **kwargs):
                assert str(name).startswith(".pending-") and "dir_fd" in kwargs
                assert job.execution_published, "publication must be recorded before cleanup starts"
                injected.append(fault)
                if fault == "cleanup-renamed-ancestor":
                    folder.rename(retained)
                elif fault != "cleanup-runtime-error":
                    execution.unlink()
                error = {"cleanup-missing-claim": FileNotFoundError, "cleanup-renamed-ancestor": FileNotFoundError,
                         "cleanup-denied-missing-claim": PermissionError,
                         "cleanup-collision-missing-claim": FileExistsError,
                         "cleanup-runtime-error": RuntimeError}[fault]
                raise error("fixture cleanup failed after execution publication")

            with ExitStack() as cleanup_patch:
                cleanup_patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "unlink": unlink_pending})))
                return original_execution_publish(job, raw)
        original_execution_publish(job, raw)
        if fault in ("malformed-claim", "non-object-claim"):
            execution.write_bytes(b"{" if fault == "malformed-claim" else b"null")
        if fault in ("claim-read-error", "oversized-claim"):
            if fault == "oversized-claim":
                execution.write_bytes(b"x" * (mailbox.MAX_BYTES + 1))
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "fdopen": fdopen})))
        injected.append("published-cleanup-error")
        raise OSError(errno.ENOSPC, "fixture execution publication cleanup full")

    def run_job(*args, **kwargs):
        if peer_completed:
            # Both attempts are admitted; let the peer finish before this attempt takes disposition exclusion.
            assert job_row(shop.run_open())["state"] == "completed"
            peer_bytes.update({name: (folder / name).read_bytes() for name in ("execution.json", "result.json")})
        return original_run_job(*args, **kwargs)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module.Job, "publish_execution_claim", publish))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if search_only:
            shop.tmp.chmod(ancestor_mode)
        if retained.exists():
            retained.rename(folder)
    row = job_row(report)
    missing = fault in ("before-publication", "cleanup-missing-claim", "cleanup-denied-missing-claim",
                        "cleanup-collision-missing-claim", "descriptor-support-unavailable", "publication-directory-denied")
    assert len(injected) == 1 and execution.exists() is not missing
    if peer_completed:
        assert row["state"] == "settle_pending", row
        assert row["error"] == "[Errno 28] fixture execution publication full"
        assert "Run run-open again" in row["next_action"]
        assert {name: (folder / name).read_bytes() for name in peer_bytes} == peer_bytes
        assert shop.states("job-1") == ["started", "completed"]
        assert shop.run_open()["rows"] == []
    elif fault in ("before-publication", "descriptor-support-unavailable", "publication-directory-denied"):
        assert row["state"] == "settle_pending", row
        expected = {"before-publication": "[Errno 28] fixture execution publication full",
                    "descriptor-support-unavailable": "secure brief publication requires directory descriptor support",
                    "publication-directory-denied": "execution claim directory unavailable"}[fault]
        assert row["error"] == expected
        assert "private-input-must-not-echo" not in json.dumps(report)
        assert "Run run-open again" in row["next_action"]
        assert not (folder / "result.json").exists() and shop.receipts("job-1") == []
        assert job_row(shop.run_open())["state"] == "completed"
    else:
        assert row["state"] == "abandoned", row
        assert (row["state"], row["reason"], row["process_alive"]) == (
            "abandoned", "execution_custody_unknown", None)
        assert not (folder / "result.json").exists() and shop.receipts("job-1") == []
    if fault == "claim-read-error":
        assert descriptors == [], "known publication does not depend on reading the pathname again"
    if fault == "descriptor-support-unavailable":
        assert unsupported == [True]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("replacement", [False, True], ids=["waiting-queue-empty", "replacement-completed"])
def test_jobs2_retired_grant_does_not_swallow_a_later_store_fault(kind_shop, monkeypatch, capsys, replacement):
    from tools import hierarchy_loop as loop
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    request_kind_job(shop, "heavy")
    jobs = jobs2_module
    original_grant, original_safe_path = jobs.grant_next, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "retained-fault-store"
    released, replacements, swapped = [], [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and not released:
            released.append(answer[1]["granted"]["request_id"])
            shop.workspace.release(released[0])
            if replacement:
                replacements.append(shop.workspace.ask("pilot", "heavy", JOB_HOLDER))
                assert shop.workspace.grant("heavy")["request_id"] == replacements[0]
        return answer

    def safe_path(path):
        if Path(path) == store and released and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe_path(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert swapped == [True] and len(released) == 1
    own = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    if replacement:
        assert [row["state"] for row in own] == ["completed", "settle_pending"], report
        assert own[1]["reason"] == "post_grant_step_failed" and "request_id" not in own[1]
        assert "do not rerun completed work" in own[1]["next_action"]
        assert requests_of(shop, "heavy") == {released[0]: "released", replacements[0]: "released"}
        assert shop.sentinel.read_text() == "ran\n" and shop.states("job-1") == ["started", "completed"]
    else:
        assert [row["state"] for row in own] == ["waiting", "settle_pending"]
        assert own[0]["reason"] == "queue_empty", report
        assert own[1]["reason"] == "post_grant_step_failed"
        assert "has not started" in own[1]["next_action"]
        assert requests_of(shop, "heavy") == {released[0]: "released"}
        assert_did_not_run(shop)
    original_run = subprocess.run

    def run(argv, *args, **kwargs):
        if str(JOBS) in [str(word) for word in argv]:
            return subprocess.CompletedProcess(argv, 3, json.dumps(report) + "\n", "")
        return original_run(argv, *args, **kwargs)

    current = loop.Pass(SimpleNamespace(store=store, recipes=shop.recipes_path, max_jobs=None))
    with ExitStack() as patch:
        patch.enter_context(jobs2_patch.object(jobs2_tools.hierarchy_loop, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run})))
        current.run_open()
    assert current.steps[0]["state"] == "hold" and any(row["act"] == "root" for row in current.holds)


@pytest.mark.parametrize("occupied", [False, True], ids=["normal", "no-replace"])
def test_jobs2_execution_publisher_is_equivalent_to_pinned_publish_file(tmp_path, occupied):
    jobs = load_jobs_module()
    job = jobs.Job(tmp_path / "store", {"id": "pilot"}, {"message_id": "publication"})
    job.folder.mkdir(parents=True)
    baseline = tmp_path / "pinned" / "execution.json"
    claim = {"job": job.id, "pid": os.getpid(), "start": jobs.process_start(os.getpid()), "at": jobs.timestamp(),
             "process_scope": jobs.process_scope(), "recipes_sha256": "a" * 64}
    raw = jobs.encoded(claim) + b"\n"
    if occupied:
        jobs.publish_file(baseline, b"earlier claim\n")
        jobs.publish_file(job.execution_path, b"earlier claim\n")
        with pytest.raises(FileExistsError):
            jobs.publish_file(baseline, raw)
        with pytest.raises(FileExistsError):
            job.publish_execution_claim(raw)
        assert not job.execution_published
    else:
        jobs.publish_file(baseline, raw)
        job.publish_execution_claim(raw)
        assert job.execution_published and job.execution_fence == job.execution_path
        assert job.execution_path.read_bytes() == raw
    assert job.execution_path.read_bytes() == baseline.read_bytes()
    assert (job.execution_path.stat().st_mode & 0o777) == (baseline.stat().st_mode & 0o777)
    assert sorted(p.name for p in baseline.parent.iterdir()) == ["execution.json"]
    assert sorted(p.name for p in job.folder.iterdir()) == ["execution.json"]


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_jobs2_execution_publisher_closes_handles_when_fdopen_raises(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import hierarchy_fresh_brief

    jobs = jobs2_module
    job = jobs.Job(tmp_path / "store", {"id": "pilot"}, {"message_id": "publication"})
    job.folder.mkdir(parents=True)
    original_directory = hierarchy_fresh_brief.open_directory
    descriptors = []

    def directory(path):
        descriptor = original_directory(path)
        descriptors.append(descriptor)
        return descriptor

    def fdopen(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        raise OSError(errno.EIO, "fixture execution fdopen failed")

    with ExitStack() as patch:
        patch.enter_context(jobs2_patch.object(jobs2_fresh_brief, "open_directory", directory))
        patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "fdopen": fdopen})))
        with pytest.raises(OSError, match="fixture execution fdopen failed"):
            job.publish_execution_claim(b"claim\n")
    assert len(descriptors) == 2 and not job.execution_published and not job.execution_path.exists()
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            assert exc.errno == errno.EBADF
        else:
            os.close(descriptor)
            pytest.fail("execution publisher leaked a descriptor when fdopen failed")
    assert list(job.folder.iterdir()) == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_jobs2_execution_publisher_refuses_size_before_opening(tmp_path, monkeypatch):
    from types import SimpleNamespace

    jobs = jobs2_module
    job = jobs.Job(tmp_path / "store", {"id": "pilot"}, {"message_id": "publication"})

    def refuse_open(*args, **kwargs):
        pytest.fail("oversized execution claim must be refused before opening")

    with ExitStack() as patch:
        patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": refuse_open})))
        with pytest.raises(ValueError, match="^record exceeds 262144 bytes$"):
            job.publish_execution_claim(b"x" * (jobs.MAX_BYTES + 1))
    assert not job.folder.exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["fdopen", "oversized"])
def test_jobs2_bounded_claim_reader_closes_or_refuses_before_reading(tmp_path, monkeypatch, fault):
    from types import SimpleNamespace

    jobs = jobs2_module
    job = jobs.Job(tmp_path / "store", {"id": "pilot"}, {"message_id": "publication"})
    job.folder.mkdir(parents=True)
    job.execution_path.write_bytes(b"x" * (jobs.MAX_BYTES + 1) if fault == "oversized" else b"claim\n")
    descriptors = []

    def fdopen(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        if fault == "oversized":
            pytest.fail("oversized claim must be refused before reading")
        raise OSError(errno.EIO, "fixture claim read fdopen failed")

    with ExitStack() as patch:
        patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "fdopen": fdopen})))
        assert job.execution_publication_matches({}) is None
    assert len(descriptors) == (1 if fault == "fdopen" else 0)
    for descriptor in descriptors:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-bytes", "planned"])
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("prior_completed", [False, True], ids=["single-outcome", "prior-completed"])
@pytest.mark.parametrize("outcome", ["completed", "running", "dependency-waiting", "stale-grant",
                                     "abandoned", "settle-pending"])
def test_jobs2_replacement_replay_reports_one_pass_fault(
        kind_shop, monkeypatch, capsys, planned, kind, prior_completed, outcome):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    add_recipe_of_kind(shop, "replacement", kind)
    dependent = outcome in ("dependency-waiting", "settle-pending")
    if dependent:
        parent = shop.request_job("first-check", "ok")
        assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    if prior_completed:
        shop.request_job("job-0", "replacement")
    if dependent:
        request_dependent(shop, parent, "job-1", recipe="replacement")
    else:
        shop.request_job("job-1", "replacement")
    if outcome == "dependency-waiting":
        shop.workspace.register(FOREIGN)
    jobs = jobs2_module
    original_grant, original_safe_path, original_open = jobs.grant_next, jobs.safe_path, os.open
    store, retained = shop.workspace.store, shop.tmp / "replay-retained-store"
    folder, lock = store / "jobs/pilot/job-1", shop.root / ".write.lock"
    released, replacements, injected, swapped = [], [], [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["holder"] == JOB_HOLDER and not released:
            released.append(answer[1]["granted"]["request_id"])
            shop.workspace.release(released[0])
            replacement_kind = ("heavy-tests" if kind == "heavy" else "heavy") if outcome == "stale-grant" else kind
            replacements.append(shop.workspace.ask("pilot", replacement_kind, JOB_HOLDER))
            assert shop.workspace.grant(replacement_kind)["request_id"] == replacements[0]
            if outcome == "running":
                folder.mkdir(parents=True)
                (folder / "claim.json").write_text(json.dumps(live_claim(jobs, os.getpid(), "pilot/job-1")))
            elif outcome == "dependency-waiting":
                shop.workspace.ask(FOREIGN, "writer", "job:pilot/first-check")
            elif outcome == "settle-pending":
                lock.write_text("fixture concurrent mailbox writer")
        return answer

    def open_claim(path, flags, *args, **kwargs):
        if outcome == "abandoned" and Path(path).parent == folder and flags & os.O_CREAT:
            injected.append("claim-publication-full")
            raise OSError(errno.ENOSPC, "fixture claim publication full")
        return original_open(path, flags, *args, **kwargs)

    def safe_path(path):
        # This is run_open's final boundary check, after run_kind has recorded the real outcome.
        if Path(path) == store and released and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe_path(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            patch.enter_context(jobs2_patch.object(jobs2_mailbox, "os", SimpleNamespace(**{**vars(os), "open": open_claim})))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
            report = json.loads(output)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
        if lock.exists():
            lock.unlink()
    assert swapped == [True] and len(released) == len(replacements) == 1
    state = {"dependency-waiting": "waiting", "stale-grant": "waiting",
             "settle-pending": "settle_pending"}.get(outcome, outcome)
    prior = report["rows"][:1] if prior_completed else []
    if prior_completed:
        assert (prior[0]["job"], prior[0]["state"]) == ("pilot/job-0", "completed")
    original = report["rows"][len(prior)]
    assert (original["job"], original["state"]) == ("pilot/job-1", state)
    if outcome == "stale-grant":
        assert original["reason"] == "stale_grant" and original["request_id"] == replacements[0]
    elif outcome == "dependency-waiting":
        assert original["reason"] == "foreign_reservation"
        if planned:
            assert replacements[0] in original["next_action"]
    elif outcome == "abandoned":
        assert injected == ["claim-publication-full"]
        assert (original["reason"], original["process_alive"]) == ("execution_custody_unknown", None)
    elif outcome == "settle-pending":
        assert original["error"] == "mailbox writer is busy; inspect an abandoned lock before retrying"
    elif outcome == "running":
        assert original == {"job": "pilot/job-1", "state": "running", "process_group": None}
    if planned:
        faults = [row for row in report["rows"] if row.get("reason") == "post_grant_step_failed"
                  or row.get("failure_reason") == "post_grant_step_failed"]
        assert len(faults) == 1, report
        diagnostics = report["rows"][len(prior) + 1:]
        expected_jobs = {"pilot/job-0", "pilot/job-1"} if prior_completed else {"pilot/job-1"}
        assert {row["job"] for row in diagnostics} == expected_jobs and len(diagnostics) == len(expected_jobs), report
        assert all(row["state"] == "settle_pending" and "request_id" not in row
                   and "Root:" in row["next_action"] for row in diagnostics)
        fault = next(row for row in diagnostics if row["job"] == "pilot/job-1")
        if prior_completed:
            assert "do not rerun completed work" in next(row for row in diagnostics if row["job"] == "pilot/job-0")["next_action"]
        guidance = {"completed": "do not rerun completed work", "running": "running",
                    "dependency-waiting": "has not started", "stale-grant": "reservation",
                    "abandoned": "custody", "settle-pending": "has not started"}[outcome]
        assert guidance in fault["next_action"]
        if outcome == "settle-pending":
            assert "Run run-open again" in fault["next_action"]
            assert "original fence" not in fault["next_action"] and "stopped-process" not in fault["next_action"]
        assert "post_grant_" not in json.dumps(original)
    else:
        # The unchanged legacy recovery appends this literal diagnostic for every outcome.
        diagnostic = {"job": "pilot/job-1", "state": "settle_pending", "reason": "post_grant_step_failed",
                      "next_action": "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."}
        assert output.encode() == (json.dumps({"rows": prior + [original, diagnostic]}, sort_keys=True) + "\n").encode()
    assert requests_of(shop, kind)[released[0]] == "released"
    assert not shop.sentinel.exists()
    if outcome != "completed":
        assert not (folder / "result.json").exists() and shop.receipts("job-1") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-bytes", "planned"])
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("holder", ["manual-holder", "job:pilot/outside-candidates"])
@pytest.mark.parametrize("retire", [False, True], ids=["active", "retired"])
def test_jobs2_ownerless_grant_preserves_every_jobs_obligation(
        kind_shop, monkeypatch, capsys, planned, kind, holder, retire):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        plan = host_plan(shop)
    add_recipe_of_kind(shop, "ownerless", kind)
    shop.request_job("job-1", "ownerless")
    shop.workspace.ask("pilot", kind, JOB_HOLDER)
    ownerless = shop.workspace.ask("pilot", kind, holder)
    shop.request_job("job-tail", "ownerless")
    jobs = jobs2_module
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "ownerless-retained-store"
    acknowledged, post_reads, swapped = [], [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["request_id"] == ownerless:
            assert (store / "jobs/pilot/job-1/result.json").is_file()
            if retire:
                shop.workspace.release(ownerless)
            acknowledged.append(ownerless)
        return answer

    def load(current):
        if acknowledged:
            post_reads.append(True)
            if len(post_reads) == 2:
                # The first post-grant snapshot observed the holder's disposition; a later replay loses its path.
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
                if planned:
                    plan.unlink()  # Reporting must use the grant's remembered plan status, not re-probe it.
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
            report = json.loads(output)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert acknowledged == [ownerless] and len(post_reads) == 2 and swapped == [True]
    completed = report["rows"][0]
    assert (completed["job"], completed["state"]) == ("pilot/job-1", "completed")
    if planned:
        faults = [r for r in report["rows"] if r.get("reason") == "post_grant_ledger_unreadable"]
        assert len(faults) == 1, report
        assert (faults[0].get("job"), faults[0]["state"]) == ("pilot/job-1", "settle_pending")
        assert "do not rerun completed work" in faults[0]["next_action"]
        reservations = [r for r in report["rows"] if r.get("request_id") == ownerless]
        if retire:
            assert reservations == [] and not any(r.get("holder") == holder for r in report["rows"])
        else:
            # Additional diagnostics use the validated request reference, never another copy of holder text.
            assert len(reservations) == 2, report
            original, diagnostic = reservations
            assert original["holder"] == holder and original["state"] == "granted_elsewhere"
            assert "holder" not in diagnostic and diagnostic["state"] == "granted_elsewhere"
            assert "reservation" in diagnostic["next_action"]
    else:
        held = [] if retire else [{"state": "granted_elsewhere", "holder": holder, "request_id": ownerless}]
        legacy = [completed] + held + [{"job": "pilot/job-tail", "state": "waiting", "kind": kind,
                              "reason": "post_grant_ledger_unreadable"},
                  {"state": "granted_elsewhere", "holder": holder, "reason": "post_grant_ledger_unreadable",
                   "next_action": "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."}]
        assert output.encode() == (json.dumps({"rows": legacy}, sort_keys=True) + "\n").encode()
    assert requests_of(shop, kind, holder=holder) == {ownerless: "released" if retire else "granted"}
    assert shop.states("job-1") == ["started", "completed"] and shop.receipts("job-tail") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-bytes", "planned"])
def test_jobs2_stale_kind_outcome_cannot_hide_a_completed_replacement(
        kind_shop, monkeypatch, capsys, planned):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    add_recipe_of_kind(shop, "other-kind", "heavy-tests")
    add_recipe_of_kind(shop, "replacement", "heavy")
    shop.request_job("job-0", "other-kind")
    shop.request_job("job-1", "replacement")
    jobs = jobs2_module
    original_enqueue, original_grant, original_safe_path = jobs.enqueue, jobs.grant_next, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "multi-outcome-retained-store"
    stale, released, replacements, swapped = [], [], [], []

    def enqueue(current, job, kind, wait):
        answer = original_enqueue(current, job, kind, wait)
        if job.id == "pilot/job-0" and not stale:
            # The older runner files R0 after this attempt has reconciled job-0's current kind.
            stale.append(shop.workspace.ask("pilot", "heavy", job.holder))
        return answer

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["holder"] == JOB_HOLDER and not released:
            released.append(answer[1]["granted"]["request_id"])
            shop.workspace.release(released[0])
            replacements.append(shop.workspace.ask("pilot", "heavy", JOB_HOLDER))
            assert shop.workspace.grant("heavy")["request_id"] == replacements[0]
        return answer

    def safe_path(path):
        if Path(path) == store and replacements and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe_path(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "enqueue", enqueue))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
            report = json.loads(output)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert swapped == [True] and len(stale) == len(released) == len(replacements) == 1
    original = report["rows"][:3]
    assert (original[0]["state"], original[0]["reason"], original[0]["stale_job"], original[0]["request_id"]) == (
        "granted_elsewhere", "stale_kind", "pilot/job-0", stale[0])
    assert (original[1]["job"], original[1]["state"]) == ("pilot/job-1", "completed")
    assert (original[2]["job"], original[2]["state"], original[2]["reason"], original[2]["request_id"]) == (
        "pilot/job-0", "waiting", "stale_grant", stale[0])
    if planned:
        diagnostics = report["rows"][3:]
        assert {row.get("job") for row in diagnostics} == {"pilot/job-0", "pilot/job-1"}, report
        assert len(diagnostics) == 2 and all(row["state"] == "settle_pending" for row in diagnostics)
        assert sum(row.get("reason") == "post_grant_step_failed" for row in report["rows"]) == 1
        completed = next(row for row in diagnostics if row["job"] == "pilot/job-1")
        assert "do not rerun completed work" in completed["next_action"] and "request_id" not in completed
        waiting = next(row for row in diagnostics if row["job"] == "pilot/job-0")
        assert "has not started" in waiting["next_action"] and "reservation" in waiting["next_action"]
    else:
        legacy = {"job": "pilot/job-1", "state": "settle_pending", "reason": "post_grant_step_failed",
                  "next_action": "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."}
        assert output.encode() == (json.dumps({"rows": original + [legacy]}, sort_keys=True) + "\n").encode()
    assert requests_of(shop, "heavy", holder="job:pilot/job-0") == {stale[0]: "granted"}
    assert requests_of(shop, "heavy") == {released[0]: "released", replacements[0]: "released"}
    assert shop.states("job-1") == ["started", "completed"] and shop.receipts("job-0") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("planned_p", [False, True], ids=["legacy-p-planned-u", "planned-p-legacy-u"])
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("holder", ["manual-holder", "job:unrelated/outside-candidates"])
@pytest.mark.parametrize("retire", [False, True], ids=["held", "retired"])
@pytest.mark.parametrize("preexisting", [False, True], ids=["acknowledged-p", "preexisting-p"])
def test_jobs2_shared_store_recovery_keeps_each_initiatives_mode(
        kind_shop, monkeypatch, capsys, planned_p, kind, holder, retire, preexisting):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    other_root, _ = add_initiative(shop, "unrelated", 1)
    idle_root, _ = add_initiative(shop, "idle", 20)
    (idle_root.parent / "host-plan.json").write_text(json.dumps({
        "schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "idle", "root": "codex-cli",
        "team": "claude-code", "stand_ins": {}, "config_sha256": "a" * 64}))
    plans = []
    if planned_p:
        plans.append(host_plan(shop))
    else:
        plan = other_root.parent / "host-plan.json"
        plan.write_text(json.dumps({"schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "unrelated",
                                    "root": "codex-cli", "team": "claude-code", "stand_ins": {},
                                    "config_sha256": "a" * 64}))
        plans.append(plan)
    add_recipe_of_kind(shop, "shared-recovery", kind)
    shop.request_job("job-a", "shared-recovery")
    shop.request_job("job-b", "shared-recovery")
    if preexisting:
        first = shop.workspace.ask("pilot", kind, "job:pilot/job-a")
        assert shop.workspace.grant(kind)["request_id"] == first
    jobs = jobs2_module
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "mixed-mode-retained-store"
    requested, acknowledged, post_reads, swapped = [], [], [], []

    def ask_unrelated():
        requested.append(shop.workspace.ask("unrelated", kind, holder))

    if preexisting:
        ask_unrelated()

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            request = answer[1]["granted"]
            if request["holder"] == "job:pilot/job-a" and not requested:
                ask_unrelated()
            elif request["holder"] == holder:
                assert (store / "jobs/pilot/job-a/result.json").exists()
                if retire:
                    shop.workspace.release(request["request_id"])
                acknowledged.append(request["request_id"])
        return answer

    def load(current):
        if acknowledged:
            post_reads.append(True)
            if len(post_reads) == 2:
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
                for plan in plans:
                    plan.unlink()  # Both participating jobs and ownerless grants must retain their observed mode.
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert requested == acknowledged and len(acknowledged) == 1 and swapped == [True] and len(post_reads) == 2
    assert not any(row.get("initiative") == "idle" for row in report["rows"]), report
    reason = "post_grant_ledger_unreadable"
    p_rows = [row for row in report["rows"] if row.get("job", "").startswith("pilot/")]
    completed = p_rows[0]
    assert (completed["job"], completed["state"]) == ("pilot/job-a", "completed")
    assert "next_action" not in completed and "failure_reason" not in completed
    if planned_p:
        assert [row["state"] for row in p_rows if row["job"] == "pilot/job-a"] == ["completed", "settle_pending"], report
        assert sum(row.get("reason") == reason for row in p_rows) == 1
        reconcile_a = next(row for row in p_rows if row["job"] == "pilot/job-a" and row["state"] == "settle_pending")
        assert "do not rerun completed work" in reconcile_a["next_action"]
        waiting_b = next(row for row in p_rows if row["job"] == "pilot/job-b" and row["state"] == "waiting")
        assert waiting_b == {"job": "pilot/job-b", "state": "waiting", "kind": kind}
        reconcile_b = next(row for row in p_rows if row["job"] == "pilot/job-b" and row["state"] == "settle_pending")
        assert "has not started" in reconcile_b["next_action"]
    else:
        legacy_p = [completed, {"job": "pilot/job-b", "state": "waiting", "kind": kind, "reason": reason}]
        assert json.dumps(p_rows, sort_keys=True).encode() == json.dumps(legacy_p, sort_keys=True).encode(), report
    u_rows = [row for row in report["rows"] if row not in p_rows]
    legacy_action = "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."
    if planned_p:
        original = [] if retire else [{"state": "granted_elsewhere", "holder": holder, "request_id": acknowledged[0]}]
        legacy_u = original + [{"state": "granted_elsewhere", "holder": holder, "reason": reason,
                                "next_action": legacy_action}]
        assert json.dumps(u_rows, sort_keys=True).encode() == json.dumps(legacy_u, sort_keys=True).encode(), report
    elif retire:
        assert len(u_rows) == 1 and u_rows[0]["state"] == "mailbox_error", report
        assert u_rows[0]["initiative"] == "unrelated" and u_rows[0]["reason"] == reason
        assert "holder" not in u_rows[0] and "request_id" not in u_rows[0]
    else:
        assert len(u_rows) == 2, report
        original, fault = u_rows
        assert original["holder"] == holder and original["request_id"] == acknowledged[0]
        assert fault["state"] == "granted_elsewhere" and fault["request_id"] == acknowledged[0]
        assert "holder" not in fault and fault["reason"] == reason and "reservation" in fault["next_action"]
    unrelated_requests = {identifier: row["state"] for identifier, row in
                          ledger_rows(shop, holder=holder, initiative="unrelated").items() if row["kind"] == kind}
    assert unrelated_requests == {acknowledged[0]: "released" if retire else "granted"}
    assert shop.states("job-a") == ["started", "completed"] and shop.receipts("job-b") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_jobs2_terminal_settlement_failure_keeps_its_terminal_guidance(kind_shop, monkeypatch, capsys, kind):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    request_kind_job(shop, kind)
    jobs = jobs2_module
    original_link, original_safe_path = os.link, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "terminal-settlement-retained-store"
    result, lock = store / "jobs/pilot/job-1/result.json", store / ".write.lock"
    blocked, swapped = [], []

    def link(source, target, *args, **kwargs):
        answer = original_link(source, target, *args, **kwargs)
        if Path(target) == result:
            lock.write_text("fixture concurrent store writer after terminal publication")
            blocked.append(True)
        return answer

    def safe_path(path):
        if Path(path) == store and blocked and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe_path(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_mailbox, "os", SimpleNamespace(**{**vars(os), "link": link})))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
        if lock.exists():
            lock.unlink()
    assert blocked == [True] and swapped == [True]
    original, fault = report["rows"]
    assert original["state"] == "settle_pending" and "workspace store is busy" in original["error"]
    assert fault["reason"] == "post_grant_step_failed"
    assert "retain terminal evidence" in fault["next_action"] and "retry settlement" in fault["next_action"]
    assert "do not rerun completed work" in fault["next_action"] and "has not started" not in fault["next_action"]
    assert json.loads(result.read_text())["state"] == "completed" and shop.sentinel.read_text() == "ran\n"
    assert job_row(shop.run_open())["state"] == "completed" and shop.sentinel.read_text() == "ran\n"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("holder", ["manual-holder", "job:foreign/outside-candidates"])
def test_jobs2_argon_light_completion_survives_a_foreign_retired_grant(
        kind_shop, monkeypatch, capsys, kind, holder):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    plan = host_plan(shop)
    shop.workspace.run("update", {"initiative": "pilot", "source": "owner", "priority": 10})
    shop.workspace.register("foreign", project="foreign", priority=1)
    foreign = shop.workspace.ask("foreign", kind, holder)
    shop.request_job("job-0", "ok")
    request_kind_job(shop, kind)
    jobs = jobs2_module
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "light-completion-retained-store"
    released, post_reads, swapped = [], [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["request_id"] == foreign:
            assert (store / "jobs/pilot/job-0/result.json").is_file()
            shop.workspace.release(foreign)
            released.append(foreign)
        return answer

    def load(current):
        if released:
            post_reads.append(True)
            if len(post_reads) == 2:
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
                plan.unlink()
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert released == [foreign] and swapped == [True] and len(post_reads) == 2
    completed = [row for row in report["rows"] if row.get("job") == "pilot/job-0"]
    assert [row["state"] for row in completed] == ["completed", "settle_pending"], report
    assert "do not rerun completed work" in completed[1]["next_action"]
    waiting = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert [row["state"] for row in waiting] == ["waiting", "settle_pending"]
    assert "has not started" in waiting[1]["next_action"]
    foreign_rows = [row for row in report["rows"] if row.get("holder") == holder]
    assert len(foreign_rows) == 1 and foreign_rows[0]["reason"] == "post_grant_ledger_unreadable"
    assert "request_id" not in foreign_rows[0]
    assert shop.states("job-0") == ["started", "completed"]
    assert_did_not_run(shop)


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_jobs2_argon_later_stale_kind_cannot_replace_a_jobs_waiting_context(kind_shop, monkeypatch, capsys):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    add_recipe_of_kind(shop, "first-kind", "heavy")
    add_recipe_of_kind(shop, "second-kind", "heavy-tests")
    shop.request_job("job-0", "first-kind")
    shop.request_job("job-1", "second-kind")
    jobs = jobs2_module
    original_enqueue, original_grant, original_safe_path = jobs.enqueue, jobs.grant_next, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "late-stale-kind-retained-store"
    stale, released, stale_granted, swapped = [], [], [], []

    def enqueue(current, job, kind, wait):
        answer = original_enqueue(current, job, kind, wait)
        if job.id == "pilot/job-0" and not stale:
            stale.append(shop.workspace.ask("pilot", "heavy-tests", job.holder))
        return answer

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            request = answer[1]["granted"]
            if request["holder"] == "job:pilot/job-0" and request["kind"] == "heavy":
                shop.workspace.release(request["request_id"])
                released.append(request["request_id"])
            elif request["request_id"] == stale[0]:
                stale_granted.append(request["request_id"])
        return answer

    def safe_path(path):
        if Path(path) == store and stale_granted and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe_path(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "enqueue", enqueue))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert swapped == [True] and len(released) == 1 and stale_granted == stale
    rows = report["rows"]
    waiting_index = next(index for index, row in enumerate(rows) if row.get("job") == "pilot/job-0")
    stale_index = next(index for index, row in enumerate(rows) if row.get("stale_job") == "pilot/job-0")
    assert waiting_index < stale_index and rows[waiting_index]["reason"] == "queue_empty"
    assert rows[stale_index]["reason"] == "stale_kind" and rows[stale_index]["request_id"] == stale[0]
    fault = next(row for row in rows if row.get("job") == "pilot/job-0" and row["state"] == "settle_pending")
    assert "has not started" in fault["next_action"]
    assert "original fence" not in fault["next_action"] and "stopped-process" not in fault["next_action"]
    assert requests_of(shop, "heavy", holder="job:pilot/job-0") == {released[0]: "released"}
    assert requests_of(shop, "heavy-tests", holder="job:pilot/job-0") == {stale[0]: "granted"}
    assert shop.receipts("job-0") == shop.receipts("job-1") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("outcome", ["settle_pending", "running", "abandoned"])
def test_jobs2_argon_attempted_owner_survives_later_kind_arbitration(
        kind_shop, monkeypatch, capsys, kind, outcome):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    other = "heavy-tests" if kind == "heavy" else "heavy"
    add_recipe_of_kind(shop, "owner-kind", kind)
    add_recipe_of_kind(shop, "other-kind", other)
    parent = shop.request_job("first-check", "ok")
    assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    request_dependent(shop, parent, "job-0", recipe="owner-kind")
    shop.request_job("job-1", "other-kind")
    if kind == "heavy-tests":
        # The reverse ordering also covers an alias before the actual attempt, using an existing matching grant.
        matching = shop.workspace.ask("pilot", kind, "job:pilot/job-0")
        assert shop.workspace.grant(kind)["request_id"] == matching
    jobs = jobs2_module
    original_enqueue, original_grant = jobs.enqueue, jobs.grant_next
    original_run, original_safe, original_open = jobs.run_job, jobs.safe_path, os.open
    store, retained = shop.workspace.store, shop.tmp / "attempted-owner-retained-store"
    folder, lock = store / "jobs/pilot/job-0", shop.root / ".write.lock"
    stale, granted, attempted, injected, swapped = [], [], [], [], []

    def enqueue(current, job, row_kind, wait):
        answer = original_enqueue(current, job, row_kind, wait)
        if job.id == "pilot/job-0" and not stale:
            stale.append(shop.workspace.ask("pilot", other, job.holder))
        return answer

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            request = answer[1]["granted"]
            if request["request_id"] == stale[0]:
                granted.append(stale[0])
            if request["holder"] == "job:pilot/job-0" and not injected:
                injected.append(outcome)
                if outcome == "settle_pending":
                    lock.write_text("fixture concurrent dependency mailbox writer")
                elif outcome == "running":
                    folder.mkdir(parents=True)
                    (folder / "claim.json").write_text(json.dumps(live_claim(jobs, os.getpid(), "pilot/job-0")))
        return answer

    def open_claim(path, flags, *args, **kwargs):
        if outcome == "abandoned" and Path(path).parent == folder and flags & os.O_CREAT:
            raise OSError(errno.ENOSPC, "fixture claim publication full")
        return original_open(path, flags, *args, **kwargs)

    def run_job(current, job, *args, **kwargs):
        try:
            return original_run(current, job, *args, **kwargs)
        finally:
            if job.id == "pilot/job-0":
                attempted.append(job.id)

    def safe_path(path):
        if Path(path) == store and granted and attempted and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "enqueue", enqueue))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            patch.enter_context(jobs2_patch.object(jobs2_mailbox, "os", SimpleNamespace(**{**vars(os), "open": open_claim})))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
        if lock.exists():
            lock.unlink()
    assert swapped == [True] and attempted == ["pilot/job-0"] and granted == stale
    rows = report["rows"]
    original = next(row for row in rows if row.get("job") == "pilot/job-0")
    assert original["state"] == outcome
    reservation = next(row for row in rows if row.get("request_id") == stale[0])
    assert reservation.get("stale_job") == "pilot/job-0" and reservation.get("reason") == "stale_kind", report
    assert kind in reservation["next_action"]
    fault_index = next(index for index, row in enumerate(rows) if row.get("reason") == "post_grant_step_failed")
    diagnostics = rows[fault_index:]
    assert len(diagnostics) == 2 and {row.get("job") for row in diagnostics} == {"pilot/job-0", "pilot/job-1"}, report
    fault = next(row for row in diagnostics if row.get("job") == "pilot/job-0")
    guidance = {"settle_pending": "has not started execution", "running": "preserve the running job",
                "abandoned": "preserve any candidate claim"}[outcome]
    assert guidance in fault["next_action"]
    assert sum(row.get("reason") == "post_grant_step_failed" for row in rows) == 1
    assert ledger_rows(shop, holder="job:pilot/job-0")[stale[0]]["state"] == "granted"
    assert not (folder / "result.json").exists() and shop.receipts("job-0") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-worker", "planned-worker"])
def test_jobs2_argon_mailbox_only_error_does_not_participate_in_another_owners_fault(
        kind_shop, monkeypatch, capsys, kind, planned):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    plan = host_plan(shop)
    empty, _ = add_initiative(shop, "empty", 1)
    (empty.parent / "host-plan.json").write_text(json.dumps({**json.loads(plan.read_text()), "hierarchy": "empty"}))
    if not planned:
        plan.unlink()
    request_kind_job(shop, kind)
    jobs = jobs2_module
    original_safe, original_mailbox = jobs.safe_path, jobs.Mailbox
    store, retained = shop.workspace.store, shop.tmp / "mailbox-only-retained-store"
    enumerated, swapped = [], []

    class Mailbox(original_mailbox):
        def messages(self):
            if self.root == empty:
                enumerated.append(True)
                raise PermissionError("fixture mailbox enumeration denied")
            return super().messages()

    def safe_path(path):
        if Path(path) == store and (store / "jobs/pilot/job-1/result.json").is_file() and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "Mailbox", Mailbox))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert enumerated == swapped == [True]
    assert [row for row in report["rows"] if row.get("initiative") == "empty"] == [
        {"initiative": "empty", "state": "mailbox_error", "error": "fixture mailbox enumeration denied"}]
    assert sum(row.get("reason") == "post_grant_step_failed" for row in report["rows"]) == 1
    assert shop.sentinel.read_text() == "ran\n"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_jobs2_argon_unverified_absent_publication_keeps_prefence_retry_guidance(
        kind_shop, monkeypatch, capsys, kind):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    add_recipe_of_kind(shop, "acknowledged-heavy", kind)
    shop.request_job("job-2", "acknowledged-heavy", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    jobs = jobs2_module
    original_open, original_safe = os.open, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "emfile-retained-store"
    folder = store / "jobs/pilot/job-1"
    injected, swapped = [], []

    def open_claim(path, flags, *args, **kwargs):
        if Path(path).name.startswith(".pending-") and flags & os.O_CREAT:
            assert (folder / "admitted.json").is_file() and not (folder / "execution.json").exists()
            injected.append("pending-open")
            raise OSError(errno.EMFILE, "fixture execution descriptors exhausted")
        if Path(path).name == "execution.json":
            injected.append("verification-open")
            raise OSError(errno.EMFILE, "fixture verification descriptors exhausted")
        return original_open(path, flags, *args, **kwargs)

    def safe_path(path):
        if Path(path) == store and injected and (store / "jobs/pilot/job-2/result.json").is_file() and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_claim})))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert injected == ["pending-open"] and swapped == [True], report  # Metadata proves absence before a leaf open.
    original, diagnostic = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert original["state"] == diagnostic["state"] == "settle_pending"
    assert original["error"] == "[Errno 24] fixture execution descriptors exhausted"
    assert "has not started execution" in diagnostic["next_action"]
    assert "Run run-open again" in diagnostic["next_action"]
    assert "original fence" not in diagnostic["next_action"] and "stopped-process" not in diagnostic["next_action"]
    assert sum(row.get("reason") == "post_grant_step_failed" for row in report["rows"]) == 1
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert shop.receipts("job-1") == []
    assert list(requests_of(shop, kind, holder="job:pilot/job-2").values()) == ["released"]
    assert job_row(shop.run_open())["state"] == "completed"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("state", ["running", "abandoned"])
def test_jobs2_considered_owner_survives_an_existing_claim(kind_shop, monkeypatch, capsys, kind, state):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    add_recipe_of_kind(shop, "old-owner", "heavy-tests" if kind == "heavy" else "heavy")
    add_recipe_of_kind(shop, "new-owner", kind)
    shop.request_job("job-0", "old-owner")
    shop.request_job("job-1", "new-owner")
    old = shop.workspace.ask("pilot", kind, "job:pilot/job-0")
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "considered-owner-retained-store"
    folder = store / "jobs/pilot/job-0"
    folder.mkdir(parents=True)
    claim = live_claim(jobs, os.getpid(), "pilot/job-0")
    if state == "abandoned":
        boot = claim["process_scope"]["boot_id"]
        claim["process_scope"]["boot_id"] = ("0" if boot[0] != "0" else "1") + boot[1:]
    (folder / "claim.json").write_text(json.dumps(claim))
    original_grant, original_safe = jobs.grant_next, jobs.safe_path
    granted, swapped = [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["request_id"] == old:
            granted.append(old)
        return answer

    def safe_path(path):
        if Path(path) == store and granted and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert granted == [old] and swapped == [True]
    rows = report["rows"]
    assert rows[0]["job"] == "pilot/job-0" and rows[0]["state"] == state
    fault_index = next(index for index, row in enumerate(rows) if row.get("reason") == "post_grant_step_failed")
    diagnostics = rows[fault_index:]
    assert len(diagnostics) == 2 and {row.get("job") for row in diagnostics} == {"pilot/job-0", "pilot/job-1"}, report
    assert "request_id" not in json.dumps(diagnostics)
    owner = next(row for row in diagnostics if row["job"] == "pilot/job-0")
    assert ("preserve the running job" if state == "running" else "original fence") in owner["next_action"]
    assert requests_of(shop, kind, holder="job:pilot/job-0") == {old: "granted"}


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind, owner_type", [
    ("heavy", "attempted-heavy"), ("heavy-tests", "attempted-heavy"),
    ("heavy", "completed-light"), ("heavy-tests", "completed-light"),
    ("heavy-tests", "different-kind-heavy"),
])
@pytest.mark.parametrize("fault_at", [1, 2], ids=["before-reservation-row", "after-reservation-row"])
def test_jobs2_legacy_owner_views_preserve_literal_rows(kind_shop, monkeypatch, capsys, kind, owner_type, fault_at):
    from tests.conftest import symlink_or_skip

    shop = kind_shop
    owner_kind = "heavy" if owner_type == "different-kind-heavy" else kind
    add_recipe_of_kind(shop, "pending-kind", kind)
    if owner_type != "completed-light":
        add_recipe_of_kind(shop, "owner-kind", owner_kind)
    if owner_type == "completed-light":
        shop.request_job("job-0", "ok")
    else:
        parent = shop.request_job("first-check", "ok")
        assert job_row(shop.run_open(), "first-check")["state"] == "completed"
        request_dependent(shop, parent, "job-0", recipe="owner-kind")
    if owner_type == "attempted-heavy":
        # A later same-kind request wins by initiative priority even though it was filed after the attempt.
        root, checkout = add_initiative(shop, "later", 20)
        shop.request_job("job-1", "pending-kind", root=root, prefix="later", checkout=checkout)
        pending = "later/job-1"
    else:
        shop.request_job("job-1", "pending-kind")
        pending = "pilot/job-1"
    jobs = jobs2_module
    original_enqueue, original_grant = jobs.enqueue, jobs.grant_next
    original_run, original_load = jobs.run_job, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "legacy-owner-retained-store"
    folder, lock = store / "jobs/pilot/job-0", shop.root / ".write.lock"
    old, matching, acknowledged, post_reads, swapped = [], [], [], [], []

    def enqueue(current, job, row_kind, wait):
        if owner_type == "completed-light" and job.id == pending and not old:
            assert (folder / "result.json").is_file()
            old.append(shop.workspace.ask("pilot", kind, "job:pilot/job-0"))
        answer = original_enqueue(current, job, row_kind, wait)
        if owner_type == "different-kind-heavy" and job.id == "pilot/job-0" and not old:
            old.append(shop.workspace.ask("pilot", kind, job.holder))
        return answer

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            request = answer[1]["granted"]
            if old and request["request_id"] == old[0]:
                acknowledged.append(old[0])
            elif request["holder"] == "job:pilot/job-0":
                matching.append(request["request_id"])
                lock.write_text("fixture concurrent dependency mailbox writer")
        return answer

    def run_job(current, job, *args, **kwargs):
        try:
            return original_run(current, job, *args, **kwargs)
        finally:
            if owner_type == "attempted-heavy" and job.id == "pilot/job-0":
                shop.workspace.release(matching[0])
                old.append(shop.workspace.ask("pilot", kind, job.holder))

    def load(current):
        if acknowledged:
            post_reads.append(True)
            if len(post_reads) == fault_at:
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "enqueue", enqueue))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
        if lock.exists():
            lock.unlink()
    assert acknowledged == old and len(old) == 1 and swapped == [True] and len(post_reads) == fault_at, output
    reason = "post_grant_ledger_unreadable"
    if owner_type == "completed-light":
        initial = {"job": "pilot/job-0", "state": "completed", "exit_code": 0,
                   "result": str(folder / "result.json"),
                   "removed": ["scratch", "tmp", "home", "cargo-target", "ruff-cache", "hypothesis"]}
    else:
        initial = {"job": "pilot/job-0", "state": "settle_pending",
                   "error": "mailbox writer is busy; inspect an abandoned lock before retrying"}
    waiting = {"job": pending, "state": "waiting", "kind": kind, "reason": reason}
    if fault_at == 1:
        reservation = {"state": "granted_elsewhere", "kind": kind, "holder": "job:pilot/job-0",
                       "request_id": old[0], "reason": reason,
                       "next_action": "Root: preserve the reservation; repair store or audit access, then reconcile and "
                                      "settle with correlated terminal evidence."}
        expected = [initial, reservation, waiting]
    else:
        reservation = {"state": "granted_elsewhere", "holder": "job:pilot/job-0", "request_id": old[0]}
        fallback = {"state": "granted_elsewhere", "holder": "job:pilot/job-0", "reason": reason,
                    "next_action": "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."}
        expected = [initial, reservation, waiting, fallback]
    # Literal public rows: the test needs no reference module, checkout revision, or git history.
    assert output.encode() == (json.dumps({"rows": expected}, sort_keys=True) + "\n").encode()
    assert requests_of(shop, kind, holder="job:pilot/job-0")[old[0]] == "granted"
    assert not (store / "jobs" / pending / "result.json").exists()


JOBS2_PREFENCE_ACTION = ("Root: repair store or audit access; this attempt has not started execution. Run run-open again "
                         "after repairing the reported error; existing claims are rechecked and never executed twice.")
JOBS2_WAITING_ACTION = ("Root: repair store or audit access; this job has not started. Preserve any reservation and "
                        "reconcile its blockers before run-open.")
JOBS2_RESERVATION_ACTION = ("Root: preserve the reservation; repair store or audit access, then reconcile and "
                            "settle with correlated terminal evidence.")
JOBS2_LEGACY_FALLBACK_ACTION = "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."
JOBS2_READMIT_ACTION = ("Root: re-admit the owning job through run-open for its initiative and clear its dependency or "
                        "reservation blockers; a grant alone does not authorize job execution.")
JOBS2_BLOCKED_ACTION = ("Run run-open again after repairing the reported mailbox, storage or settlement error; "
                        "an existing claim is never executed twice.")


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-bytes", "planned"])
@pytest.mark.parametrize("owner_kind", ["none", "heavy", "heavy-tests"])
@pytest.mark.parametrize("grant_kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("fault_at", [1, 2], ids=["before-reservation-row", "after-reservation-row"])
def test_jobs2_argon2128_owner_kind_table_preserves_literal_rows(
        kind_shop, monkeypatch, capsys, planned, owner_kind, grant_kind, fault_at):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    add_recipe_of_kind(shop, "driving-kind", grant_kind)
    if owner_kind == "none":
        owner_recipe = "ok"
    else:
        owner_recipe = "owner-kind"
        add_recipe_of_kind(shop, owner_recipe, owner_kind)
    parent = shop.request_job("first-check", "ok")
    assert job_row(shop.run_open(), "first-check")["state"] == "completed"
    request_dependent(shop, parent, "job-0", recipe=owner_recipe)
    shop.request_job("job-1", "driving-kind")
    old = []
    if owner_kind == "none":
        # Argon's exact light input: R0 already exists, and the execution budget is two.
        old.append(shop.workspace.ask("pilot", grant_kind, "job:pilot/job-0"))
    reverse = owner_kind == "heavy-tests" and grant_kind == "heavy"
    if reverse:
        matching = shop.workspace.ask("pilot", owner_kind, "job:pilot/job-0")
        assert shop.workspace.grant(owner_kind)["request_id"] == matching
    jobs = jobs2_module
    original_enqueue, original_grant = jobs.enqueue, jobs.grant_next
    original_run, original_load = jobs.run_job, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "argon2128-owner-retained-store"
    folder, lock = store / "jobs/pilot/job-0", shop.root / ".write.lock"
    acknowledged, attempted, post_reads, swapped = [], [], [], []

    def enqueue(current, job, kind, wait):
        answer = original_enqueue(current, job, kind, wait)
        if job.id == "pilot/job-0" and not old:
            if owner_kind == grant_kind:
                (identifier,) = requests_of(shop, grant_kind, holder=job.holder)
                old.append(identifier)  # The existing matching request; no duplicate open request is filed.
            else:
                old.append(shop.workspace.ask("pilot", grant_kind, job.holder))
        return answer

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["request_id"] == old[0]:
            acknowledged.append(old[0])
        return answer

    def run_job(current, job, *args, **kwargs):
        if job.id == "pilot/job-0":
            # Admission has finished; a real concurrent mailbox writer now prevents the dependency lock.
            attempted.append(True)
            lock.write_text("fixture concurrent dependency mailbox writer")
        return original_run(current, job, *args, **kwargs)

    def load(current):
        if acknowledged:
            post_reads.append(True)
            if len(post_reads) == fault_at:
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "enqueue", enqueue))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", "--max-jobs", "2", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
        if lock.exists():
            lock.unlink()
    matching_kind = owner_kind == grant_kind
    had_attempt = owner_kind == "none" or (owner_kind == "heavy" and grant_kind == "heavy-tests") or (matching_kind and fault_at == 2)
    assert attempted == ([True] if had_attempt else [])
    assert acknowledged == old and len(old) == 1 and swapped == [True] and len(post_reads) == fault_at
    reason = "post_grant_ledger_unreadable"
    originals = []
    if had_attempt:
        initial = {"job": "pilot/job-0", "state": "settle_pending",
                   "error": "mailbox writer is busy; inspect an abandoned lock before retrying"}
        if planned:
            initial["next_action"] = JOBS2_BLOCKED_ACTION
        originals.append(initial)
    # Both heavy kinds can be stale; a light owner and a matching kind cannot.
    stale = owner_kind in ("heavy", "heavy-tests") and not matching_kind and (planned or reverse)
    reserve = {"state": "waiting" if matching_kind and fault_at == 1 else "granted_elsewhere",
               "request_id": old[0]}
    if fault_at == 1:
        reserve.update(kind=grant_kind, next_action=JOBS2_RESERVATION_ACTION)
        reserve.update({"job": "pilot/job-0"} if matching_kind else {"holder": "job:pilot/job-0"})
        if not planned:
            reserve["reason"] = reason
    else:
        reserve["holder"] = "job:pilot/job-0"
        if planned:
            reserve["next_action"] = JOBS2_READMIT_ACTION
    if stale:
        reserve.update(stale_job="pilot/job-0", reason="stale_kind")
        if fault_at == 1 and not planned:
            reserve["failure_reason"] = reason
        if fault_at == 2:
            reserve["next_action"] = (
                "Job pilot/job-0 now needs %s; this %s grant is additional capacity, not its execution grant. It runs "
                "only on a matching grant; otherwise it waits for root to reconcile and settle this reservation. "
                "Settlement releases additional grants with the job's result as evidence." % (owner_kind, grant_kind))
    if fault_at == 2 and not matching_kind:
        originals.append(reserve)
    additions = [reserve] if fault_at == 1 else []
    if reverse:
        additions.append({"job": "pilot/job-0", "state": "waiting", "kind": owner_kind})
    additions.append({"job": "pilot/job-1", "state": "waiting", "kind": grant_kind})
    if not planned:
        for row in additions:
            if row["state"] == "waiting" and "request_id" not in row:
                row["reason"] = reason
        if fault_at == 2:
            fallback = {"state": "settle_pending" if matching_kind or reverse else "granted_elsewhere",
                        "reason": reason, "next_action": JOBS2_LEGACY_FALLBACK_ACTION}
            fallback.update({"job": "pilot/job-0"} if matching_kind or reverse else {"holder": "job:pilot/job-0"})
            additions.append(fallback)
        expected = originals + additions
    else:
        diagnostic = {"job": "pilot/job-0", "state": "settle_pending", "reason": reason,
                      "next_action": JOBS2_PREFENCE_ACTION if had_attempt else JOBS2_WAITING_ACTION}
        expected = originals + [diagnostic] + additions + [
            {"job": "pilot/job-1", "state": "settle_pending", "next_action": JOBS2_WAITING_ACTION}]
    assert output.encode() == (json.dumps({"rows": expected}, sort_keys=True) + "\n").encode()
    assert not (folder / "claim.json").exists() and not (folder / "result.json").exists()
    assert requests_of(shop, grant_kind, holder="job:pilot/job-0")[old[0]] == "granted"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-bytes", "planned"])
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("fault_at", [1, 2], ids=["before-reservation-row", "after-reservation-row"])
def test_jobs2_argon2128_refused_receipt_without_execution_preserves_literal_rows(
        kind_shop, monkeypatch, capsys, planned, kind, fault_at):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    add_recipe_of_kind(shop, "driving-kind", kind)
    shop.request_job("job-0", "ok")
    shop.publish("job-0-root-refusal", "job_receipt", "Root refused without execution.",
                 sender="pilot/root", to="pilot/orchestrator", in_reply_to="job-0",
                 receipt={"state": "refused", "reason": "root refused without execution"})
    old = shop.workspace.ask("pilot", kind, "job:pilot/job-0")
    other, checkout = add_initiative(shop, "later", 20)
    shop.request_job("job-1", "driving-kind", root=other, prefix="later", checkout=checkout)
    jobs = jobs2_module
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "argon2128-refusal-retained-store"
    acknowledged, post_reads, swapped = [], [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["request_id"] == old:
            acknowledged.append(old)
        return answer

    def load(current):
        if acknowledged:
            post_reads.append(True)
            if len(post_reads) == fault_at:
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", "--max-jobs", "2", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert acknowledged == [old] and swapped == [True] and len(post_reads) == fault_at
    reason = "post_grant_ledger_unreadable"
    pending = {"job": "later/job-1", "state": "waiting", "kind": kind, "reason": reason}
    reserve = {"state": "granted_elsewhere", "holder": "job:pilot/job-0", "request_id": old}
    if fault_at == 1:
        reserve.update(kind=kind, next_action=JOBS2_RESERVATION_ACTION)
        if not planned:
            reserve["reason"] = reason
    elif planned:
        reserve["next_action"] = JOBS2_READMIT_ACTION
    if planned:
        diagnostic = {"job": "pilot/job-0", "state": "settle_pending", "reason": reason,
                      "next_action": JOBS2_PREFENCE_ACTION}
        expected = [diagnostic, reserve, pending] if fault_at == 1 else [reserve, diagnostic, pending]
    else:
        fallback = {"state": "granted_elsewhere", "holder": "job:pilot/job-0", "reason": reason,
                    "next_action": JOBS2_LEGACY_FALLBACK_ACTION}
        expected = [reserve, pending] if fault_at == 1 else [reserve, pending, fallback]
    assert output.encode() == (json.dumps({"rows": expected}, sort_keys=True) + "\n").encode()
    assert not (store / "jobs/pilot/job-0").exists()
    assert shop.states("job-0") == ["refused"] and requests_of(shop, kind, holder="job:pilot/job-0") == {old: "granted"}


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_jobs2_argon2128_unobservable_publication_does_not_claim_a_verified_fence(
        kind_shop, monkeypatch, capsys, kind):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    if os.name != "posix" or not hasattr(os, "O_PATH"):
        pytest.skip("unobservable publication requires POSIX modes and O_PATH")
    if os.geteuid() == 0:
        pytest.skip("root bypasses the candidate-directory permission check")
    shop = kind_shop
    probe = shop.tmp / "unobservable-candidate-probe"
    probe.mkdir()
    try:
        probe.chmod(0)
        try:
            (probe / "candidate").lstat()
        except PermissionError:
            pass
        except FileNotFoundError:
            pytest.skip("chmod is ineffective for the candidate-path capability check")
        else:
            pytest.skip("chmod is ineffective for the candidate-path capability check")
    finally:
        probe.chmod(0o700)
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    add_recipe_of_kind(shop, "driving-kind", kind)
    edit_source(shop)
    request_derive(shop)
    shop.request_job("job-2", "driving-kind", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    jobs = jobs2_module
    original_open, original_stat, original_safe = os.open, os.stat, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "unobservable-publication-retained-store"
    folder = store / "jobs/pilot/job-1"
    injected, swapped, denied = [], [], []

    def open_claim(path, flags, *args, **kwargs):
        if Path(path).name.startswith(".pending-") and flags & os.O_CREAT:
            injected.append("pending-open")
            folder.chmod(0)
            raise OSError(errno.EMFILE, "fixture publication descriptors exhausted")
        if Path(path).name == "execution.json":
            injected.append("verification-open")
            raise OSError(errno.EMFILE, "fixture verification descriptors exhausted")
        return original_open(path, flags, *args, **kwargs)

    def stat_claim(path, *args, **kwargs):
        try:
            return original_stat(path, *args, **kwargs)
        except PermissionError:
            if Path(path).name == "execution.json" and "dir_fd" in kwargs:
                denied.append(True)
            raise

    def safe_path(path):
        if Path(path) == store and injected and (store / "jobs/pilot/job-2/result.json").is_file() and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_claim, "stat": stat_claim})))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
        if folder.exists():
            folder.chmod(0o700)
    assert injected == ["pending-open"] and denied and swapped == [True], report
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert [row["state"] for row in owned] == ["abandoned", "settle_pending"]
    action = ("Root: preserve any candidate claim and reservation; inspect recovery-status and establish execution "
              "custody before settlement or retry. Do not retry execution while custody is unknown.")
    assert all(row["next_action"] == action for row in owned)
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert job_row(shop.run_open())["state"] == "completed"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_jobs2_argon2128_peer_execution_link_records_its_observed_fence(kind_shop, monkeypatch, capsys, kind):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    add_recipe_of_kind(shop, "driving-kind", kind)
    edit_source(shop)
    request_derive(shop)
    shop.request_job("job-2", "driving-kind", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    jobs = jobs2_module
    original_run, original_safe = jobs.run_job, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "peer-link-retained-store"
    folder = store / "jobs/pilot/job-1"
    peer, swapped = [], []

    def run_job(current, job, *args, **kwargs):
        if job.id == "pilot/job-1":
            assert (folder / "admitted.json").is_file()
            raw = json.dumps(live_claim(jobs, os.getpid(), job.id)).encode()
            (folder / "execution.json").write_bytes(raw)
            peer.append(raw)
        return original_run(current, job, *args, **kwargs)

    def safe_path(path):
        if Path(path) == store and (store / "jobs/pilot/job-2/result.json").is_file() and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert len(peer) == 1 and swapped == [True]
    original, diagnostic = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    group = json.loads((folder / "process.json").read_text())["group"]
    assert type(group) is int and group > 0
    assert original == {"job": "pilot/job-1", "state": "running", "process_group": group}
    assert diagnostic == {"job": "pilot/job-1", "state": "settle_pending",
                          "next_action": "Root: repair store or audit access; preserve the running job's custody and "
                                         "reservation; inspect recovery-status before settlement. Do not rerun it."}
    assert (folder / "execution.json").read_bytes() == peer[0] and not (folder / "result.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_jobs2_argon2128_released_peer_grant_records_its_observed_fence(kind_shop, monkeypatch, capsys, kind):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    request_kind_job(shop, kind)
    other = "heavy-tests" if kind == "heavy" else "heavy"
    add_recipe_of_kind(shop, "driving-kind", other)
    shop.request_job("job-2", "driving-kind")
    jobs = jobs2_module
    original_grant, original_safe = jobs.grant_next, jobs.safe_path
    store, retained = shop.workspace.store, shop.tmp / "released-peer-retained-store"
    folder = store / "jobs/pilot/job-1"
    released, swapped = [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["kind"] == kind and not released:
            folder.mkdir(parents=True)
            (folder / "claim.json").write_text(json.dumps(live_claim(jobs, os.getpid(), "pilot/job-1")))
            released.append(answer[1]["granted"]["request_id"])
            shop.workspace.release(released[0])
        return answer

    def safe_path(path):
        if Path(path) == store and (store / "jobs/pilot/job-2/result.json").is_file() and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_safe(path)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "safe_path", safe_path))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert len(released) == 1 and swapped == [True]
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    diagnostic = {"job": "pilot/job-1", "state": "settle_pending",
                  "next_action": "Root: repair store or audit access; preserve the running job's custody and "
                                 "reservation; inspect recovery-status before settlement. Do not rerun it."}
    if kind == "heavy":
        diagnostic["reason"] = "post_grant_step_failed"
    assert owned == [
        {"job": "pilot/job-1", "state": "running", "process_group": None},
        diagnostic]
    assert requests_of(shop, kind, holder=JOB_HOLDER) == {released[0]: "released"}
    assert not (folder / "result.json").exists() and not shop.sentinel.exists()


JOBS2_UNVERIFIED_ACTION = ("Root: preserve any candidate claim and reservation; inspect recovery-status and establish "
                            "execution custody before settlement or retry. Do not retry execution while custody is unknown.")
JOBS2_FENCED_ACTION = ("Root: repair store or audit access; preserve execution custody, the original fence and any "
                       "reservation; inspect recovery-status and establish stopped-process evidence before settlement or retry.")
JOBS2_OBSERVED_RESULT_ACTION = ("Root: repair store or audit access; retain the observed result and any reservation. Inspect "
                                "recovery-status and validate terminal evidence before settlement; do not rerun execution.")


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("failure", ["open", "fdopen", "oversized", "symlink"])
def test_jobs2_argon0057_retained_publication_path_does_not_verify_its_contents(
        kind_shop, monkeypatch, capsys, kind, failure):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    add_recipe_of_kind(shop, "driving-kind", kind)
    edit_source(shop)
    request_derive(shop)
    shop.request_job("job-2", "driving-kind", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    jobs = jobs2_module
    original_run, original_open, original_fdopen, original_close = jobs.run_job, os.open, os.fdopen, os.close
    original_grant, original_load, original_stat = jobs.grant_next, jobs.Store.load, os.stat
    store, retained = shop.workspace.store, shop.tmp / "argon0057-unverified-store"
    folder = store / "jobs/pilot/job-1"
    execution = folder / "execution.json"
    injected, acknowledged, swapped, descriptors, closed, directories, closed_directories = [], [], [], set(), [], set(), []

    def run_job(current, job, *args, **kwargs):
        if job.id == "pilot/job-1":
            assert (folder / "admitted.json").is_file()
            raw = json.dumps(live_claim(jobs, os.getpid(), job.id)).encode()
            if failure == "symlink":
                target = shop.tmp / "unverified-peer-claim"
                target.write_bytes(raw)
                symlink_or_skip(target, execution)
            else:
                execution.write_bytes(b"x" * (jobs.MAX_BYTES + 1) if failure == "oversized" else raw)
        return original_run(current, job, *args, **kwargs)

    def open_claim(path, flags, *args, **kwargs):
        if Path(path).name == "execution.json":
            directories.add(kwargs["dir_fd"])
        if Path(path).name.startswith(".pending-") and flags & os.O_CREAT:
            injected.append("pending-open")
            raise OSError(errno.EMFILE, "fixture pending descriptors exhausted")
        if Path(path).name == "execution.json" and failure == "open":
            injected.append("verification-open")
            raise OSError(errno.EMFILE, "fixture verification descriptors exhausted")
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path).name == "execution.json":
            descriptors.add(descriptor)
        return descriptor

    def stat_claim(path, *args, **kwargs):
        if Path(path).name == "execution.json" and "dir_fd" in kwargs:
            directories.add(kwargs["dir_fd"])
        return original_stat(path, *args, **kwargs)

    def fdopen(descriptor, *args, **kwargs):
        if descriptor in descriptors:
            if failure == "oversized":
                pytest.fail("oversized publication must be refused before reading")
            if failure == "fdopen":
                injected.append("verification-fdopen")
                raise OSError(errno.EMFILE, "fixture stream descriptors exhausted")
        return original_fdopen(descriptor, *args, **kwargs)

    def close(descriptor):
        original_close(descriptor)
        if descriptor in descriptors:
            with pytest.raises(OSError) as error:
                os.fstat(descriptor)
            assert error.value.errno == errno.EBADF
            closed.append(descriptor)
            descriptors.remove(descriptor)
        if descriptor in directories:
            with pytest.raises(OSError) as error:
                os.fstat(descriptor)
            assert error.value.errno == errno.EBADF
            closed_directories.append(descriptor)
            directories.remove(descriptor)

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["holder"] == "job:pilot/job-2":
            acknowledged.append(True)
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_claim, "stat": stat_claim, "fdopen": fdopen, "close": close})))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert swapped == [True] and injected[0] == "pending-open" and not descriptors and not directories
    assert closed_directories
    if failure == "fdopen":
        assert closed, "the bounded publication descriptor must close even when fdopen fails"
    if failure == "oversized":
        assert not closed, "reject an oversized claim from metadata before opening it"
    assert execution.lstat(), "the retained candidate is observable by lstat, even when verification failed"
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert owned == [
        {"job": "pilot/job-1", "state": "abandoned", "process_group": None, "process_alive": None,
         "reason": "execution_custody_unknown", "next_action": JOBS2_UNVERIFIED_ACTION},
        {"job": "pilot/job-1", "state": "settle_pending", "next_action": JOBS2_UNVERIFIED_ACTION}]
    assert not (folder / "result.json").exists()




@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-bytes", "planned"])
@pytest.mark.parametrize("evidence", ["malformed-result", "execution-directory", "derived-publication",
                                      "unsupported-observation", "result-vanishes", "admission-marker"])
def test_jobs2_argon0057_closed_job_retains_observed_execution_evidence(
        kind_shop, monkeypatch, capsys, kind, planned, evidence):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    if planned:
        host_plan(shop)
    add_recipe_of_kind(shop, "driving-kind", kind)
    shop.request_job("job-0", "ok")
    shop.publish("job-0-root-refusal", "job_receipt", "Root closed this job.", sender="pilot/root",
                 to="pilot/orchestrator", in_reply_to="job-0", receipt={"state": "refused", "reason": "root refused"})
    old = shop.workspace.ask("pilot", kind, "job:pilot/job-0")
    shop.request_job("job-1", "driving-kind")
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "argon0057-closed-store"
    folder = store / "jobs/pilot/job-0"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps(live_claim(jobs, os.getpid(), "pilot/job-0")))
    if evidence in ("malformed-result", "result-vanishes"):
        (folder / "result.json").write_text("{}")
    elif evidence in ("derived-publication", "admission-marker"):
        (folder / "admitted.json").write_text("{}")
        if evidence == "derived-publication":
            (folder / "execution.json").write_text("{")
    original_grant, original_load, original_settle = jobs.grant_next, jobs.Store.load, jobs.settle
    original_observe = jobs.Job.observe_existing_fence
    acknowledged, swapped, unsupported = [], [], []

    def unavailable():
        unsupported.append(True)
        raise ValueError("secure brief publication requires directory descriptor support")

    def observe(job):
        if evidence == "unsupported-observation" and job.id == "pilot/job-0":
            with ExitStack() as local:
                local.enter_context(jobs2_patch.object(jobs2_fresh_brief, "require_secure_publication", unavailable))
                return original_observe(job)
        return original_observe(job)

    def settle(current, job, wait):
        if evidence == "result-vanishes" and job.id == "pilot/job-0":
            (folder / "result.json").unlink()
        return original_settle(current, job, wait)

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and answer[1]["granted"]["request_id"] == old:
            acknowledged.append(old)
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module.Job, "observe_existing_fence", observe))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            patch.enter_context(jobs2_patch.object(jobs2_module, "settle", settle))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert acknowledged == [old] and swapped == [True]
    reason = "post_grant_ledger_unreadable"
    originals = []
    if evidence in ("malformed-result", "result-vanishes"):
        blocked = {"job": "pilot/job-0", "state": "settle_pending",
                   "error": ("job has no validated terminal result" if planned else "'NoneType' object is not subscriptable")
                   if evidence == "result-vanishes" else "invalid job result schema"}
        if planned:
            blocked["next_action"] = JOBS2_BLOCKED_ACTION
        originals.append(blocked)
    if planned and evidence == "unsupported-observation":
        originals.append({"job": "pilot/job-0", "state": "abandoned", "process_group": None,
                          "process_alive": None, "reason": "execution_custody_unknown",
                          "next_action": JOBS2_UNVERIFIED_ACTION})
    reserve = {"state": "granted_elsewhere", "kind": kind, "request_id": old,
               "holder": "job:pilot/job-0", "next_action": JOBS2_RESERVATION_ACTION}
    pending = {"job": "pilot/job-1", "state": "waiting", "kind": kind}
    if planned:
        diagnostic = {"job": "pilot/job-0", "state": "settle_pending", "reason": reason,
                      "next_action": JOBS2_FENCED_ACTION if evidence in ("malformed-result", "execution-directory", "result-vanishes")
                                     else JOBS2_UNVERIFIED_ACTION}
        expected = originals + [diagnostic, reserve, pending,
            {"job": "pilot/job-1", "state": "settle_pending", "next_action": JOBS2_WAITING_ACTION}]
    else:
        reserve["reason"] = pending["reason"] = reason
        expected = originals + [reserve, pending]
    assert output.encode() == (json.dumps({"rows": expected}, sort_keys=True) + "\n").encode()
    if planned and evidence == "unsupported-observation":
        assert unsupported, "exercise the unsupported-platform probe, rather than relying on the host platform"
    assert requests_of(shop, kind, holder="job:pilot/job-0") == {old: "granted"}
    assert (folder / "result.json").exists() is (evidence == "malformed-result")


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("site", ["visit-existing", "link-loss"])
@pytest.mark.parametrize("evidence", ["malformed", "oversized", "symlink", "fdopen"])
def test_jobs2_argon0057_peer_publication_observations_preserve_uncertainty(
        kind_shop, monkeypatch, capsys, kind, site, evidence):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    add_recipe_of_kind(shop, "driving-kind", kind)
    edit_source(shop)
    if site == "visit-existing":
        shop.request_job("first-check", "ok", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    request_derive(shop)
    if site == "visit-existing":
        assert job_row(shop.run_open("--max-jobs", "1", expect=3), "first-check")["state"] == "completed"
    shop.request_job("job-2", "driving-kind", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "argon0057-peer-store"
    folder = store / "jobs/pilot/job-1"
    execution = folder / "execution.json"
    original_run, original_grant, original_load = jobs.run_job, jobs.grant_next, jobs.Store.load
    original_open, original_fdopen, original_close = os.open, os.fdopen, os.close
    created, acknowledged, swapped, reads, descriptors, closed, directories, closed_directories = [], [], [], [], set(), [], set(), []

    def create_peer():
        assert (folder / "admitted.json").is_file()
        raw = json.dumps(live_claim(jobs, os.getpid(), "pilot/job-1")).encode()
        if evidence == "symlink":
            target = shop.tmp / "peer-candidate-target"
            target.write_bytes(raw)
            symlink_or_skip(target, execution)
        else:
            execution.write_bytes(b"{" if evidence == "malformed" else b"x" * (jobs.MAX_BYTES + 1) if evidence == "oversized" else raw)
        created.append(True)

    if site == "visit-existing":
        create_peer()

    def run_job(current, job, *args, **kwargs):
        if site == "link-loss" and job.id == "pilot/job-1":
            create_peer()
        return original_run(current, job, *args, **kwargs)

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            request = answer[1]["granted"]
            if request["holder"] == "job:pilot/job-2":
                acknowledged.append(request["request_id"])
        return answer

    def load(current):
        if acknowledged:
            reads.append(True)
            if len(reads) == 1:
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    def open_claim(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path).name == "execution.json":
            descriptors.add(descriptor)
            directories.add(kwargs["dir_fd"])
        return descriptor

    def fdopen(descriptor, *args, **kwargs):
        if descriptor in descriptors:
            raise OSError(errno.EMFILE, "fixture candidate stream unavailable")
        return original_fdopen(descriptor, *args, **kwargs)

    def close(descriptor):
        original_close(descriptor)
        if descriptor in descriptors:
            with pytest.raises(OSError) as error:
                os.fstat(descriptor)
            assert error.value.errno == errno.EBADF
            closed.append(descriptor)
            descriptors.remove(descriptor)
        if descriptor in directories:
            with pytest.raises(OSError) as error:
                os.fstat(descriptor)
            assert error.value.errno == errno.EBADF
            closed_directories.append(descriptor)
            directories.remove(descriptor)

    try:
        with ExitStack() as patch:
            if evidence == "fdopen":
                patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_claim, "fdopen": fdopen, "close": close})))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert created == [True] and swapped == [True] and len(acknowledged) == 1
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert len(owned) == 2, report
    assert owned[-1]["state"] == "settle_pending" and owned[-1]["next_action"] == JOBS2_UNVERIFIED_ACTION
    assert owned[0]["state"] == "abandoned" and owned[0]["next_action"] == JOBS2_UNVERIFIED_ACTION
    if evidence == "fdopen":
        assert closed and closed_directories and not descriptors and not directories
    assert not (folder / "result.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_jobs2_argon0057_unvalidated_admission_marker_is_not_unstarted_work(kind_shop, monkeypatch, capsys, kind):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    add_recipe_of_kind(shop, "driving-kind", kind)
    shop.request_job("job-0", "ok")
    shop.request_job("job-1", "driving-kind")
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "argon0057-open-marker-store"
    folder = store / "jobs/pilot/job-0"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps(live_claim(jobs, os.getpid(), "pilot/job-0")))
    (folder / "admitted.json").write_text("{}")
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    acknowledged, swapped = [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            acknowledged.append(True)
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert acknowledged == [True] and swapped == [True]
    original, diagnostic = [row for row in report["rows"] if row.get("job") == "pilot/job-0"]
    assert original == jobs2_2m_unknown_report("job-0", JOBS2_UNVERIFIED_ACTION)["rows"][0]
    assert diagnostic["state"] == "settle_pending"
    assert diagnostic["next_action"] == JOBS2_UNVERIFIED_ACTION
    assert not (folder / "result.json").exists() and not (folder / "execution.json").exists()


JOBS2_2I_FIELDS = ("job", "pid", "start", "at", "process_scope", "recipes_sha256")
JOBS2_2I_BAD_VALUES = {"null": None, "object": {}, "array": [], "bool": True, "number": 3.5}
JOBS2_2I_VARIANTS = (
    ["valid", "valid-null-recipes"]
    + ["missing-" + field for field in JOBS2_2I_FIELDS]
    + ["bad-" + field + "-" + kind for field in JOBS2_2I_FIELDS for kind in JOBS2_2I_BAD_VALUES
       if not (field == "recipes_sha256" and kind == "null")]
    + ["bad-job-value", "bad-pid-zero", "bad-pid-negative", "bad-start-text", "bad-at-date", "bad-at-multiline",
       "scope-missing-boot", "scope-missing-namespace", "scope-extra", "scope-boot-type", "scope-boot-format",
       "scope-namespace-type", "scope-namespace-format", "recipe-not-hex", "extra-field", "doc-object", "doc-null",
       "doc-array", "json-invalid", "json-nested", "dangling", "symlink", "directory", "unreadable", "oversized"])


def jobs2_2i_nested_json():
    from hierarchy_mailbox import MAX_BYTES

    # The native JSON decoder can accept nesting beyond Python's recursion limit.
    depth = max(10000, sys.getrecursionlimit() + 200)
    assert depth * 2 + 1 <= MAX_BYTES, "the depth fixture must fit the claim byte limit"
    return b"[" * depth + b"0" + b"]" * depth


def jobs2_2i_claim_payload(claim, variant):
    claim = {**claim, "process_scope": dict(claim["process_scope"])}
    if variant == "valid-null-recipes":
        claim["recipes_sha256"] = None  # This is an explicitly supported legacy writer value.
    elif variant.startswith("missing-"):
        claim.pop(variant[len("missing-"):])
    elif variant.startswith("bad-"):
        field, kind = variant[len("bad-"):].rsplit("-", 1)
        if kind in JOBS2_2I_BAD_VALUES:
            claim[field] = JOBS2_2I_BAD_VALUES[kind]
        else:
            field, value = {"bad-job-value": ("job", "pilot/different"), "bad-pid-zero": ("pid", 0),
                            "bad-pid-negative": ("pid", -1), "bad-start-text": ("start", "not-a-tick"),
                            "bad-at-date": ("at", "2026-99-99T00:00:00Z"),
                            "bad-at-multiline": ("at", "2026-11-12T00:00:00Z\nsecond line")}[variant]
            claim[field] = value
    elif variant == "scope-missing-boot":
        claim["process_scope"].pop("boot_id")
    elif variant == "scope-missing-namespace":
        claim["process_scope"].pop("pid_namespace")
    elif variant == "scope-extra":
        claim["process_scope"]["extra"] = "not writer metadata"
    elif variant.startswith("scope-"):
        field = "boot_id" if "boot" in variant else "pid_namespace"
        claim["process_scope"][field] = [] if variant.endswith("type") else "invalid-scope"
    elif variant == "recipe-not-hex":
        claim["recipes_sha256"] = "z" * 64
    elif variant == "extra-field":
        claim["extra"] = "not writer metadata"
    if variant == "doc-object":
        return b"{}"
    if variant == "doc-null":
        return b"null"
    if variant == "doc-array":
        return b"[]"
    if variant == "json-invalid":
        return b"{"
    if variant == "json-nested":
        return jobs2_2i_nested_json()
    return json.dumps(claim).encode()


@pytest.mark.parametrize("variant", JOBS2_2I_VARIANTS)
def test_jobs2_2i_claim_verifier_matrix_without_shop(tmp_path, monkeypatch, variant):
    jobs = jobs2_module
    # Plan discovery selects custody guidance; this verifier needs no ledger or admission.
    (tmp_path / jobs.hierarchy_hosts.PLAN_FILE).write_text("{}")
    initiative = {"id": "pilot", "mailbox_root": str(tmp_path / "mailbox")}
    job = jobs.Job(tmp_path / "store", initiative, {"message_id": "job-1"})
    job.execution_claim_name = "execution.json"
    job.folder.mkdir(parents=True)
    candidate = job.execution_path
    claim = live_claim(jobs, os.getpid(), job.id)
    claim["recipes_sha256"] = "a" * 64
    if variant == "directory":
        candidate.mkdir()
    elif variant in ("dangling", "symlink"):
        other = tmp_path / "claim-target"
        if variant == "symlink":
            other.write_bytes(jobs2_2i_claim_payload(claim, "valid"))
        symlink_or_skip(other, candidate)
    else:
        candidate.write_bytes(b"x" * (jobs.MAX_BYTES + 1) if variant == "oversized"
                              else jobs2_2i_claim_payload(claim, variant))
    original_open = os.open
    denied = []

    def open_claim(path, flags, *args, **kwargs):
        if variant == "unreadable" and Path(path).name == candidate.name:
            denied.append(True)
            raise PermissionError(errno.EACCES, "fixture claim unreadable")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_claim}))
    observation = job.observe_fence()
    assert observation.present is True
    if variant.startswith("valid"):
        assert observation.state == jobs.FENCE_VERIFIED
        assert observation.value == json.loads(jobs2_2i_claim_payload(claim, variant))
        assert job.recorded_execution_fence() is True
    else:
        assert observation.state == jobs.FENCE_UNCERTAIN
        assert job.recorded_execution_fence() is None
        assert jobs.unknown_custody_row(job)["next_action"] == JOBS2_UNVERIFIED_ACTION
    assert bool(denied) is (variant == "unreadable")


def test_jobs2_2i_claim_verifier_refuses_unsupported_descriptors(tmp_path, monkeypatch):
    jobs = jobs2_module
    job = jobs.Job(tmp_path / "store", {"id": "pilot"}, {"message_id": "job-1"})
    job.folder.mkdir(parents=True)
    job.claim_path.write_bytes(jobs2_2i_claim_payload(live_claim(jobs, os.getpid(), job.id), "valid"))

    def unsupported():
        raise ValueError("secure brief publication requires directory descriptor support")

    monkeypatch.setattr(jobs2_fresh_brief, "require_secure_publication", unsupported)
    observation = job.observe_fence()
    assert observation.state == jobs.FENCE_UNCERTAIN and observation.present is None
    assert isinstance(observation.read_error, ValueError)
    assert str(observation.read_error) == "secure brief publication requires directory descriptor support"


# Payload and filesystem shapes are covered above without rebuilding a Shop per shape.
# Each route still meets both a valid claim and a semantically invalid job binding.
@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("entry", ["existing", "closed-execution", "closed-claim", "taken", "lost-link", "own-publication", "released", "refusal"])
@pytest.mark.parametrize("variant", ["valid", "bad-job-value"])
def test_jobs2_2i_claim_matrix_uses_only_verified_regular_claims(kind_shop, capsys, kind, entry, variant):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    derived = entry in ("existing", "lost-link", "own-publication")
    target = "pilot/job-1" if derived else "pilot/job-0"
    driving = "job-2" if derived else "job-1"
    add_recipe_of_kind(shop, "driving-kind", kind)
    if derived:
        shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
        shop.save_recipes()
        edit_source(shop)
        if entry == "existing":
            shop.request_job("first-check", "ok", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
        request_derive(shop)
        if entry == "existing":
            assert job_row(shop.run_open("--max-jobs", "1", expect=3), "first-check")["state"] == "completed"
    else:
        shop.request_job("job-0", "refusal-only-unknown-recipe" if entry == "refusal" else
                         "driving-kind" if entry == "released" else "ok")
        if entry.startswith("closed-"):
            shop.publish("root-closed-job-0", "job_receipt", "Root refused this job.", sender="pilot/root",
                         to="pilot/orchestrator", in_reply_to="job-0", receipt={"state": "refused", "reason": "root refused"})
            shop.workspace.ask("pilot", kind, "job:pilot/job-0")
    shop.request_job(driving, "driving-kind", **(
        {"dirty_content_sha256": source_digest(shop)["dirty_content_sha256"]} if derived else {}))
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "jobs2-2i-matrix-store"
    folder = store / "jobs" / target
    filename = "execution.json" if derived or entry == "closed-execution" else "claim.json"
    candidate = folder / filename
    original_run, original_grant, original_load = jobs.run_job, jobs.grant_next, jobs.Store.load
    original_refuse = jobs.refuse
    original_link, original_unlink = os.link, os.unlink
    original_observe = jobs.Job.observe_fence
    created, acknowledged, reads, swapped, observed = [], [], [], [], []

    def put_candidate(claim=None):
        folder.mkdir(parents=True, exist_ok=True)
        if entry == "closed-execution":
            (folder / "admitted.json").write_text("{}")
        if claim is None:
            claim = live_claim(jobs, os.getpid(), target)
            claim["recipes_sha256"] = hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()
        if candidate.exists() or candidate.is_symlink():
            candidate.unlink()
        candidate.write_bytes(jobs2_2i_claim_payload(claim, variant))
        created.append(True)

    if entry == "existing" or entry.startswith("closed-"):
        put_candidate()

    def run_job(current, job, *args, **kwargs):
        if job.id == target and entry in ("taken", "lost-link"):
            put_candidate()
        return original_run(current, job, *args, **kwargs)

    def refuse(current, job, *args, **kwargs):
        if job.id == target and entry == "refusal":
            put_candidate()
        return original_refuse(current, job, *args, **kwargs)

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            request = answer[1]["granted"]
            if entry == "released" and request["holder"] == "job:" + target:
                put_candidate()
                shop.workspace.release(request["request_id"])
                acknowledged.append(request["request_id"])
            elif entry != "released":
                acknowledged.append(request["request_id"])
        return answer

    def load(current):
        if acknowledged:
            reads.append(True)
            if len(reads) == (2 if entry == "released" else 1):
                store.rename(retained)
                swapped.append(True)
                symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    def observe(job, name=None, directory=None):
        observation = original_observe(job, name, directory)
        if created and job.id == target and (job.execution_claim_name if name is None else name) == filename:
            observed.append(observation.state)
        return observation

    def link(source, destination, *args, **kwargs):
        answer = original_link(source, destination, *args, **kwargs)
        if entry == "own-publication" and Path(destination).name == "execution.json":
            if variant == "valid":
                created.append(True)
            else:
                put_candidate(json.loads(candidate.read_bytes()))
        return answer

    def unlink(path, *args, **kwargs):
        if entry == "own-publication" and created and str(path).startswith(".pending-"):
            raise OSError(errno.EIO, "fixture cleanup after publication")
        return original_unlink(path, *args, **kwargs)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "link": link, "unlink": unlink})))
            patch.enter_context(jobs2_patch.object(jobs2_module.Job, "observe_fence", observe))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module, "refuse", refuse))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert created == [True] and swapped == [True] and len(acknowledged) == 1, report
    owned = [row for row in report["rows"] if row.get("job") == target]
    assert owned and owned[-1]["state"] == "settle_pending", report
    if variant.startswith("valid"):
        assert jobs.FENCE_VERIFIED in observed, "the route must verify the candidate through observe_fence"
        assert "original fence" in owned[-1]["next_action"] or "preserve the running job" in owned[-1]["next_action"]
    else:
        assert observed and set(observed) == {jobs.FENCE_UNCERTAIN}, "the route must refuse the invalid candidate"
        assert owned[-1]["next_action"] == JOBS2_UNVERIFIED_ACTION
        if not entry.startswith("closed-"):
            assert owned[0]["state"] == "abandoned" and owned[0]["next_action"] == JOBS2_UNVERIFIED_ACTION
    assert not (folder / "result.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("entry", ["closed", "taken"])
@pytest.mark.parametrize("result_change", ["malformed", "vanishing"])
def test_jobs2_2i_regular_result_survives_an_independent_observer_failure(
        kind_shop, monkeypatch, capsys, kind, entry, result_change):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    add_recipe_of_kind(shop, "driving-kind", kind)
    if entry == "taken":
        shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
        shop.save_recipes()
        edit_source(shop)
        request_derive(shop)
        target, driving = "pilot/job-1", "job-2"
        shop.request_job(driving, "driving-kind", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    else:
        target, driving = "pilot/job-0", "job-1"
        shop.request_job("job-0", "ok")
        shop.publish("closed-job-0", "job_receipt", "Root closed it.", sender="pilot/root", to="pilot/orchestrator",
                     in_reply_to="job-0", receipt={"state": "refused", "reason": "root refused"})
        shop.workspace.ask("pilot", kind, "job:" + target)
        shop.request_job(driving, "driving-kind")
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "result-observation-retained-store"
    folder = store / "jobs" / target
    original_run, original_settle, original_grant, original_load = jobs.run_job, jobs.settle, jobs.grant_next, jobs.Store.load
    original_stat = os.stat
    failed, acknowledged, swapped, settled = [], [], [], []

    def evidence():
        folder.mkdir(parents=True, exist_ok=True)
        (folder / ("execution.json" if entry == "taken" else "claim.json")).write_text("{}")
        (folder / "result.json").write_text("{}")

    if entry == "closed":
        evidence()

    def run_job(current, job, *args, **kwargs):
        if entry == "taken" and job.id == target:
            evidence()
        return original_run(current, job, *args, **kwargs)

    def stat_result(path, *args, **kwargs):
        if Path(path).name == "result.json" and kwargs.get("dir_fd") is not None and not failed:
            failed.append(True)
            raise PermissionError(errno.EACCES, "fixture first observation unavailable")
        return original_stat(path, *args, **kwargs)

    def settle(current, job, wait):
        if job.id == target:
            settled.append(True)
            if result_change == "vanishing":
                (folder / "result.json").unlink()
        return original_settle(current, job, wait)

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            acknowledged.append(True)
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "stat": stat_result})))
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module, "settle", settle))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert failed == [True] and swapped == [True] and settled == [True], report
    owned = [row for row in report["rows"] if row.get("job") == target]
    assert owned[-1]["state"] == "settle_pending"
    assert owned[-1]["next_action"] == JOBS2_OBSERVED_RESULT_ACTION
    assert "original fence" not in owned[-1]["next_action"]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("failure", ["disposition", "pending-file"])
def test_jobs2_2i_successful_admission_validation_clears_only_admission_uncertainty(
        kind_shop, monkeypatch, capsys, kind, failure):
    import fcntl
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    add_recipe_of_kind(shop, "driving-kind", kind)
    edit_source(shop)
    shop.request_job("first-check", "ok", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    request_derive(shop)
    assert job_row(shop.run_open("--max-jobs", "1", expect=3), "first-check")["state"] == "completed"
    folder = shop.workspace.store / "jobs/pilot/job-1"
    assert (folder / "admitted.json").is_file() and not (folder / "execution.json").exists()
    (shop.checkout / "src/app.py").write_text("value = 300\n")  # A later check refuses after persisted admission validates.
    shop.request_job("job-2", "driving-kind", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    jobs = jobs2_module
    original_open, original_grant, original_load = os.open, jobs.grant_next, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "admission-clear-retained-store"
    acknowledged, swapped, blocked = [], [], []
    lock = (folder / "disposition.lock").open("a+b")
    if failure == "disposition":
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def open_pending(path, flags, *args, **kwargs):
        if failure == "pending-file" and str(path).startswith(".pending-") and flags & os.O_CREAT:
            blocked.append(True)
            raise OSError(errno.EMFILE, "fixture pending-file descriptors unavailable")
        return original_open(path, flags, *args, **kwargs)

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            acknowledged.append(True)
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_pending})))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        lock.close()
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    assert swapped == [True] and (failure == "disposition" or blocked)
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert owned[-1]["state"] == "settle_pending" and owned[-1]["next_action"] == JOBS2_PREFENCE_ACTION
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
@pytest.mark.parametrize("node, shape", [(node, shape) for node in ("execution", "result", "admitted")
                                        for shape in ("dangling", "symlink", "directory")]
                         + [("folder", "dangling"), ("folder", "symlink")])
def test_jobs2_2i_metadata_nodes_use_no_follow_classification(kind_shop, monkeypatch, capsys, kind, node, shape):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    shop = kind_shop
    host_plan(shop)
    add_recipe_of_kind(shop, "driving-kind", kind)
    shop.request_job("job-0", "ok")
    shop.request_job("job-1", "driving-kind")
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "metadata-node-retained-store"
    folder = store / "jobs/pilot/job-0"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps(live_claim(jobs, os.getpid(), "pilot/job-0")))
    moved_folder = shop.tmp / "metadata-node-original-folder"
    target = shop.tmp / "metadata-link-target"
    if node in ("execution", "result"):
        (folder / "admitted.json").write_text("{}")
    if node != "folder":
        path = folder / (node + ".json")
        if shape == "directory":
            path.mkdir()
        else:
            if shape == "symlink":
                target.write_text("{}")
            symlink_or_skip(target, path)
    original_visit, original_grant, original_load = jobs.visit_existing, jobs.grant_next, jobs.Store.load
    injected, acknowledged, swapped = [], [], []

    def visit(current, job, wait):
        if node == "folder" and job.id == "pilot/job-0" and not injected:
            folder.rename(moved_folder)
            if shape == "symlink":
                target.mkdir()
            symlink_or_skip(target, folder, target_is_directory=True)
            injected.append(True)
        return original_visit(current, job, wait)

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            acknowledged.append(True)
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "visit_existing", visit))
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
        if moved_folder.exists():
            if folder.is_symlink():
                folder.unlink()
            moved_folder.rename(folder)
    assert swapped == [True]
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-0"]
    if node == "admitted":
        assert owned[0]["state"] == "running" and "preserve the running job" in owned[-1]["next_action"]
    elif node == "result":
        assert owned[0]["state"] == "settle_pending"
        assert owned[0]["error"] == "result is not a readable file within its limit"
        assert owned[-1]["next_action"] == JOBS2_UNVERIFIED_ACTION
    else:
        assert owned[0]["state"] == "abandoned" and owned[-1]["next_action"] == JOBS2_UNVERIFIED_ACTION
    assert not (folder / "execution.json").is_file() or node == "execution"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("variant", ["valid", "missing-at", "bad-at-array", "bad-process_scope-object",
                                     "bad-recipes_sha256-array", "doc-object", "doc-null", "json-nested", "dangling", "symlink", "directory"])
@pytest.mark.parametrize("entry", ["existing", "refusal"])
def test_jobs2_2i_no_plan_claim_rows_remain_literal_bytes(kind_shop, monkeypatch, capsys, entry, variant):
    from tests.conftest import symlink_or_skip

    shop = kind_shop
    shop.request_job("job-0", "refusal-only-unknown-recipe" if entry == "refusal" else "ok")
    shop.request_job("job-1", "heavy")
    jobs = jobs2_module
    store, retained = shop.workspace.store, shop.tmp / "legacy-claim-retained-store"
    folder = store / "jobs/pilot/job-0"
    def put_candidate():
        folder.mkdir(parents=True)
        claim = live_claim(jobs, os.getpid(), "pilot/job-0")
        path = folder / "claim.json"
        if variant == "directory":
            path.mkdir()
        elif variant in ("dangling", "symlink"):
            target = shop.tmp / "legacy-claim-target"
            if variant == "symlink":
                target.write_bytes(jobs2_2i_claim_payload(claim, "valid"))
            symlink_or_skip(target, path)
        else:
            path.write_bytes(jobs2_2i_claim_payload(claim, variant))

    if entry == "existing":
        put_candidate()
    original_refuse = jobs.refuse

    def refuse(current, job, *args, **kwargs):
        if entry == "refusal" and job.id == "pilot/job-0":
            put_candidate()
        return original_refuse(current, job, *args, **kwargs)

    original_grant, original_load = jobs.grant_next, jobs.Store.load
    acknowledged, swapped = [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            acknowledged.append(answer[1]["granted"]["request_id"])
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    fatal = entry == "existing" and variant in ("doc-object", "doc-null", "json-nested")
    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
            patch.enter_context(jobs2_patch.object(jobs2_module, "refuse", refuse))
            patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == (2 if fatal else 3)
            output = capsys.readouterr().out
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    if fatal:
        expected = {"error": "claim does not belong to job: pilot/job-0"}
        if variant == "json-nested":
            try:
                json.loads(jobs2_2i_nested_json())
            except RecursionError as exc:
                expected = {"error": str(exc)}
            else:
                pytest.fail("the nested fixture must exceed the JSON parser's depth")
        assert not acknowledged
    else:
        assert len(acknowledged) == 1 and swapped == [True]
        unknown = entry == "existing" and variant in ("bad-process_scope-object", "dangling", "symlink", "directory")
        first = ({"job": "pilot/job-0", "state": "abandoned", "process_group": None, "process_alive": None,
                  "reason": "runner visibility is unknown; retain the original claim and reservation"}
                 if unknown else {"job": "pilot/job-0", "state": "running", "process_group": None})
        expected = {"rows": [first, {"job": "pilot/job-1", "state": "waiting", "kind": "heavy",
                                    "request_id": acknowledged[0], "reason": "post_grant_ledger_unreadable",
                                    "next_action": JOBS2_RESERVATION_ACTION}]}
    assert output.encode() == (json.dumps(expected, sort_keys=True) + "\n").encode()


@pytest.mark.parametrize("surface", ["resolve", "recovery-status"])
@pytest.mark.parametrize("variant", ["valid", "missing-at", "doc-null", "dangling"])
def test_jobs2_2i_fresh_liveness_selects_execution_after_admission(kind_shop, capsys, surface, variant):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    shop.request_job("first-check", "ok", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    request_derive(shop)
    assert job_row(shop.run_open("--max-jobs", "1", expect=3), "first-check")["state"] == "completed"
    jobs = load_jobs_module()
    folder = shop.workspace.store / "jobs/pilot/job-1"
    execution = folder / "execution.json"
    claim = live_claim(jobs, os.getpid(), "pilot/job-1")
    if variant == "dangling":
        symlink_or_skip(shop.tmp / "missing-execution-claim", execution)
    else:
        execution.write_bytes(jobs2_2i_claim_payload(claim, variant))
    before = shop.head()
    flags = ("--job", "pilot/job-1", "--reason", "must not resolve a live or unverified execution") if surface == "resolve" else ()
    code = jobs.main(shop.argv(surface, *flags, census=[], lock_wait=0)[3:])
    report = json.loads(capsys.readouterr().out)
    if surface == "resolve":
        assert code == 2, report
        assert report == {"error": ("its runner is still running: pilot/job-1" if variant == "valid"
                                     else "runner visibility is unknown: pilot/job-1")}
    else:
        assert code == 3, report
        row = next(row for row in report["jobs"] if row.get("job") == "pilot/job-1")
        assert row["runner_alive"] is (True if variant == "valid" else None), row
        if variant == "valid":
            assert row["state"] == "running"
    assert not (folder / "result.json").exists() and shop.receipts("job-1") == []
    assert shop.head() == before


def jobs2_2j_stopped_derived_admission(shop):
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    shop.request_job("first-check", "ok", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    request_derive(shop)
    assert job_row(shop.run_open("--max-jobs", "1", expect=3), "first-check")["state"] == "completed"
    folder = shop.workspace.store / "jobs/pilot/job-1"
    status = shop.jobs("recovery-status", census=[], expect=3)
    row = next(row for row in status["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "admitted" and row["runner_alive"] is False
    assert (folder / "admitted.json").is_file()
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    return folder


@pytest.mark.parametrize("claim", ["empty-object", "live-without-at"])
def test_jobs2_2j_argon0305_claim1_invalid_execution_remains_unknown(kind_shop, capsys, claim):
    shop = kind_shop
    folder = jobs2_2j_stopped_derived_admission(shop)
    jobs = load_jobs_module()
    execution = folder / "execution.json"
    payload = {}
    if claim == "live-without-at":
        payload = live_claim(jobs, os.getpid(), "pilot/job-1")
        del payload["at"]
    execution.write_text(json.dumps(payload))
    before = {name: (folder / name).read_bytes()
              for name in ("admitted.json", "claim.json", "packet.md", "derivation.json", "execution.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    for _ in range(2):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
        row = job_row(report)
        assert row["state"] == "abandoned" and row["process_alive"] is None, report
        assert row["next_action"] == JOBS2_UNVERIFIED_ACTION
        assert {name: (folder / name).read_bytes() for name in before} == before
        assert not (folder / "result.json").exists() and shop.receipts("job-1") == []
        assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index


def test_jobs2_2j_argon0305_claim2_dangling_execution_is_not_readmitted(kind_shop, capsys):
    from tests.conftest import symlink_or_skip

    shop = kind_shop
    folder = jobs2_2j_stopped_derived_admission(shop)
    execution, target = folder / "execution.json", shop.tmp / "argon0305-missing-execution"
    symlink_or_skip(target, execution)
    assert execution.is_symlink() and not execution.exists()
    before = {name: (folder / name).read_bytes()
              for name in ("admitted.json", "claim.json", "packet.md", "derivation.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    jobs = load_jobs_module()
    for _ in range(2):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
        row = job_row(report)
        assert row["state"] == "abandoned" and row["process_alive"] is None, report
        assert row["next_action"] == JOBS2_UNVERIFIED_ACTION
        assert execution.is_symlink() and execution.readlink() == target and not target.exists()
        assert {name: (folder / name).read_bytes() for name in before} == before
        assert not (folder / "result.json").exists() and shop.receipts("job-1") == []
        assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_jobs2_2j_argon0305_claim3_busy_refusal_keeps_prefence_guidance(kind_shop, monkeypatch, capsys, kind):
    import fcntl
    from tests.conftest import symlink_or_skip

    shop = kind_shop
    add_recipe_of_kind(shop, "post-admission-driver", kind)
    folder = jobs2_2j_stopped_derived_admission(shop)
    source = shop.checkout / "src/app.py"
    original = source.read_bytes()
    changed = original.replace(b"2", b"3", 1)
    assert len(changed) == len(original) and sum(a != b for a, b in zip(original, changed)) == 1
    source.write_bytes(changed)
    shop.request_job("job-2", "post-admission-driver", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    jobs = jobs2_module
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "argon0305-claim3-retained-store"
    acknowledged, swapped = [], []
    before = {name: (folder / name).read_bytes()
              for name in ("admitted.json", "claim.json", "packet.md", "derivation.json")}
    index = (shop.checkout / ".git/index").read_bytes()

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            assert answer[1]["granted"]["holder"] == "job:pilot/job-2"
            acknowledged.append(answer[1]["granted"]["request_id"])
        return answer

    def load(current):
        if acknowledged and not swapped:
            store.rename(retained)
            swapped.append(True)
            symlink_or_skip(retained, store, target_is_directory=True)
        return original_load(current)

    with (folder / "disposition.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with ExitStack() as patch:
                patch.enter_context(jobs2_patch.object(jobs2_module, "grant_next", grant))
                patch.enter_context(jobs2_patch.object(jobs2_module.Store, "load", load))
                assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
                report = json.loads(capsys.readouterr().out)
        finally:
            if store.is_symlink():
                store.unlink()
            if retained.exists():
                retained.rename(store)
    assert len(acknowledged) == 1 and swapped == [True], report
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert len(owned) == 2, report
    assert owned[0]["state"] == "settle_pending" and owned[0]["error"] == "job disposition is busy: pilot/job-1"
    assert owned[1]["state"] == "settle_pending" and owned[1]["next_action"] == JOBS2_PREFENCE_ACTION
    assert sum(row.get("reason") == "post_grant_ledger_unreadable" for row in report["rows"]) == 1
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert source.read_bytes() == changed and (shop.checkout / ".git/index").read_bytes() == index
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert shop.receipts("job-1") == [] and ledger_rows(shop, holder="job:pilot/job-2")[acknowledged[0]]["state"] == "granted"


# These literal row oracles were replayed against df8232ec during authoring.
# They use only fresh fixture repositories and do not load historical source at test time.
JOBS2_2L_RESULT_NODES = ["directory", "fifo", "symlink", "dangling", "unreadable"]
JOBS2_2L_RESULT_ERROR = "result is not a readable file within its limit"
JOBS2_2L_RETRY = ("Run run-open again after repairing the reported mailbox, storage or "
                  "settlement error; an existing claim is never executed twice.")


def jobs2_2l_result_node(shop, result, node):
    from tests.conftest import symlink_or_skip

    if node == "directory":
        result.mkdir()
    elif node == "fifo":
        if os.name != "posix" or not hasattr(os, "mkfifo"):
            pytest.skip("FIFO result needs POSIX mkfifo")
        os.mkfifo(result)
    elif node in ("symlink", "dangling"):
        target = shop.tmp / "result-target.json"
        if node == "symlink":
            target.write_bytes(b"{}")
        symlink_or_skip(target, result)
    else:
        if os.name != "posix" or os.geteuid() == 0:
            pytest.skip("unreadable result needs effective POSIX file permissions")
        result.write_bytes(b"{}")
        result.chmod(0)
        try:
            result.read_bytes()
        except PermissionError:
            pass
        else:
            result.chmod(0o600)
            pytest.skip("file mode does not refuse result reads")


def jobs2_2l_result_setup(shop, entry, node, planned):
    from tests.integration.test_hierarchy_jobs_derive import host_plan

    if planned:
        host_plan(shop)
    identifier = "first-check" if entry == "dependency" else "job-0"
    parent = shop.request_job(identifier, "ok")
    if entry in ("closed", "dependency"):
        shop.publish(identifier + "-closed", "job_receipt", "Root closed this request.", sender="pilot/root",
                     to="pilot/orchestrator", in_reply_to=identifier, receipt={"state": "refused", "reason": "root closed"})
    reservation = None
    if entry == "closed":
        reservation = shop.workspace.ask("pilot", "heavy", "job:pilot/" + identifier)
        assert shop.workspace.grant("heavy")["request_id"] == reservation
    if entry == "dependency":
        request_dependent(shop, parent, "job-1")
    folder = shop.workspace.store / "jobs/pilot" / identifier
    folder.mkdir(parents=True)
    claim = live_claim(jobs2_module, os.getpid(), "pilot/" + identifier)
    (folder / "claim.json").write_text(json.dumps(claim))
    jobs2_2l_result_node(shop, folder / "result.json", node)
    return identifier, folder, claim, reservation


def jobs2_2l_expected_result_row(shop, entry, node, planned, identifier, claim):
    error = JOBS2_2L_RESULT_ERROR
    if not planned and node == "unreadable":
        error = str(PermissionError(errno.EACCES, os.strerror(errno.EACCES),
                                    str(shop.workspace.store / "jobs/pilot" / identifier / "result.json")))
    if entry == "closed" and node == "dangling" and not planned:
        return None
    if entry == "existing" and node == "dangling" and not planned:
        return {"job": "pilot/job-0", "state": "running", "process_group": None}
    if entry == "dependency":
        pending = not planned and node == "dangling"
        return {"job": "pilot/job-1", "state": "waiting",
                "reason": "dependency_pending" if pending else "dependency_held",
                "detail": "predecessor has no validated terminal result" if pending else error}
    if entry == "recovery":
        row = {"job": "pilot/job-0", "owner": "pilot/orchestrator", "reservations": [], "claim": claim,
               "runner_alive": None, "process_alive": None, "receipt": "not_published",
               "source": {"state": "unavailable"},
               "next_action": "Preserve all evidence and capacity; reconcile the unavailable or inconsistent record.",
               "state": "evidence_error", "error": error}
        if node == "dangling" and not planned:
            head = shop.head()
            empty = hashlib.sha256(b"").hexdigest()
            expected = {"source_revision": head["commit"], "source_tree": head["tree"], "dirty_content_sha256": empty}
            observed = {**expected, "worktree": str(shop.checkout), "dirty_state_sha256": empty, "dirty_entries": 0}
            row.update(runner_alive=True, process_group=None, state="running",
                       source={"state": "match", "expected": expected, "observed": observed},
                       next_action="Retain the original reservation; a qualified operator must reconcile process effects.")
            del row["error"]
        return row
    row = {"job": "pilot/" + identifier, "state": "settle_pending", "error": error}
    if planned:
        row["next_action"] = (JOBS2_OBSERVED_RESULT_ACTION if node == "unreadable"
                              else JOBS2_2L_RETRY)
    return row


def jobs2_2l_check_result_row(shop, capsys, entry, node, planned):
    identifier, folder, claim, reservation = jobs2_2l_result_setup(shop, entry, node, planned)
    claim_bytes = (folder / "claim.json").read_bytes()
    result = folder / "result.json"
    mode = result.lstat().st_mode
    try:
        command = "recovery-status" if entry == "recovery" else "run-open"
        code = jobs2_module.main(shop.argv(command, census=[], lock_wait=0)[3:])
        output = capsys.readouterr().out
        expected = jobs2_2l_expected_result_row(shop, entry, node, planned, identifier, claim)
        if entry == "recovery":
            report = json.loads(output)
            row = next(row for row in report["jobs"] if row["job"] == "pilot/" + identifier)
            assert json.dumps(row, sort_keys=True).encode() == json.dumps(expected, sort_keys=True).encode()
            assert code == 3
        else:
            expected_report = {"rows": [] if expected is None else [expected]}
            assert output.encode() == (json.dumps(expected_report, sort_keys=True) + "\n").encode()
            assert code == (0 if expected is None else 3)
        assert (folder / "claim.json").read_bytes() == claim_bytes
        assert result.lstat().st_mode == mode
        if reservation is not None:
            assert ledger_rows(shop, holder="job:pilot/" + identifier)[reservation]["state"] == "granted"
        assert not shop.sentinel.exists()
    finally:
        if node == "unreadable":
            result.chmod(0o600)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("entry", ["closed", "existing", "dependency", "recovery"])
@pytest.mark.parametrize("node", JOBS2_2L_RESULT_NODES)
def test_jobs2_2l_no_plan_result_rows_match_df8232ec(kind_shop, capsys, entry, node):
    """Includes Argon #1's closed job, granted reservation and directory result exactly."""
    jobs2_2l_check_result_row(kind_shop, capsys, entry, node, False)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("entry", ["closed", "existing", "dependency", "recovery"])
@pytest.mark.parametrize("node", JOBS2_2L_RESULT_NODES)
def test_jobs2_2l_planned_nonabsent_results_report_their_error(kind_shop, capsys, entry, node):
    jobs2_2l_check_result_row(kind_shop, capsys, entry, node, True)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("node", JOBS2_2L_RESULT_NODES)
def test_jobs2_2l_argon2_publication_loser_settles_retained_result(kind_shop, capsys, node):
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    folder = shop.workspace.store / "jobs/pilot/job-1"
    original_run = jobs2_module.run_job
    peers, losers = [], []

    def run_job(store, job, *args, **kwargs):
        assert job.id == "pilot/job-1" and not peers
        assert job_row(shop.run_open())["state"] == "completed"
        execution = (folder / "execution.json").read_bytes()
        result = folder / "result.json"
        terminal = result.read_bytes()
        result.unlink()
        jobs2_2l_result_node(shop, result, node)
        peers.append((execution, terminal, shop.head(), (shop.checkout / ".git/index").read_bytes()))
        losers.append(job)
        return original_run(store, job, *args, **kwargs)

    try:
        with jobs2_patch.object(jobs2_module, "run_job", run_job):
            assert jobs2_module.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        action = JOBS2_OBSERVED_RESULT_ACTION if node == "unreadable" else JOBS2_2L_RETRY
        assert report == {"rows": [{"job": "pilot/job-1", "state": "settle_pending",
                                    "error": JOBS2_2L_RESULT_ERROR, "next_action": action}]}
        assert len(peers) == len(losers) == 1
        assert losers[0].recorded_execution_fence() is None
        assert losers[0].fence_observations["execution.json"].state == jobs2_module.FENCE_VERIFIED
        assert losers[0].settlement_attempted and not losers[0].execution_owned
        assert (folder / "execution.json").read_bytes() == peers[0][0]
        assert shop.head() == peers[0][2] and (shop.checkout / ".git/index").read_bytes() == peers[0][3]
        assert shop.states("job-1") == ["started", "completed"]
    finally:
        if node == "unreadable" and peers:
            (folder / "result.json").chmod(0o600)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("number", [errno.EIO, errno.ENOENT, errno.EACCES])
def test_jobs2_2l_no_plan_result_read_error_after_probe_keeps_os_bytes(kind_shop, capsys, number):
    from types import SimpleNamespace

    shop = kind_shop
    identifier, folder, claim, _ = jobs2_2l_result_setup(shop, "existing", "directory", False)
    result = folder / "result.json"
    result.rmdir()
    result.write_bytes(b"{}")
    original_open = os.open
    injected = []

    def open_result(path, *args, **kwargs):
        if str(path) == "result.json" and "dir_fd" in kwargs:
            injected.append(number)
            raise OSError(number, os.strerror(number), "result.json")
        return original_open(path, *args, **kwargs)

    with jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "open": open_result})):
        assert jobs2_module.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
    error = str(OSError(number, os.strerror(number), str(result)))
    assert output.encode() == (json.dumps({"rows": [{"job": "pilot/" + identifier,
                                                   "state": "settle_pending", "error": error}]},
                                          sort_keys=True) + "\n").encode()
    assert injected == [number] and result.read_bytes() == b"{}"



JOBS2_2M_FENCED_UNKNOWN_ACTION = (
    "Root: preserve the original execution fence and reservation; inspect recovery-status, "
    "the original claim and process scope. Establish custody and stopped-process evidence "
    "before recovery or settlement. Do not remove the fence or retry execution.")


def jobs2_2m_unknown_report(identifier, action):
    return {"rows": [{"job": "pilot/" + identifier, "state": "abandoned", "process_group": None,
                      "process_alive": None, "reason": "execution_custody_unknown", "next_action": action}]}


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("entry", ["closed", "existing"])
@pytest.mark.parametrize("fault", ["symlink", "descriptor-refusal"])
def test_jobs2_2m_uncertain_result_probe_never_attempts_settlement(kind_shop, capsys, entry, fault):
    from tests.conftest import symlink_or_skip

    shop = kind_shop
    identifier, folder, _, reservation = jobs2_2l_result_setup(shop, entry, "directory", True)
    (folder / "result.json").rmdir()
    saved, missing = shop.tmp / "uncertain-original-job", shop.tmp / "missing-job"
    original_existing, original_result = jobs2_module.Job.observe_existing_fence, jobs2_module.Job.observe_result
    captured, changed, first, refused = [], [], [], []

    def unavailable():
        refused.append(True)
        raise ValueError("secure brief publication requires directory descriptor support")

    def change(job):
        captured.append(job)
        assert job.id == "pilot/job-0" and not changed
        changed.append(True)
        if fault == "symlink":
            folder.rename(saved)
            symlink_or_skip(missing, folder, target_is_directory=True)
        else:
            patch.enter_context(jobs2_patch.object(jobs2_fresh_brief, "require_secure_publication", unavailable))

    def existing(job):
        # finish_closed_jobs constructs Job before it reaches this filesystem boundary.
        if entry == "closed" and job.id == "pilot/job-0":
            change(job)
        return original_existing(job)

    def result(job, directory=None):
        if entry == "existing" and job.id == "pilot/job-0" and directory is None:
            assert first == ["absent"]
            change(job)
        observed = original_result(job, directory)
        if entry == "existing" and job.id == "pilot/job-0" and directory is not None:
            first.append(observed)
        return observed

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module.Job, "observe_existing_fence", existing))
            patch.enter_context(jobs2_patch.object(jobs2_module.Job, "observe_result", result))
            assert jobs2_module.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        action = JOBS2_UNVERIFIED_ACTION if entry == "closed" else JOBS2_2M_FENCED_UNKNOWN_ACTION
        assert report == jobs2_2m_unknown_report(identifier, action)
        assert changed == [True] and len(captured) == 1
        assert captured[0].settlement_attempted is False
        assert captured[0].result_observed is False and captured[0].execution_owned is False
        assert "Run run-open again" not in report["rows"][0]["next_action"]
        if reservation is not None:
            assert ledger_rows(shop, holder="job:pilot/" + identifier)[reservation]["state"] == "granted"
        if fault == "descriptor-refusal":
            assert refused, "exercise the unsupported descriptor probe explicitly"
    finally:
        if folder.is_symlink():
            folder.unlink()
        if saved.exists():
            saved.rename(folder)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["symlink", "observed-nonregular"])
def test_jobs2_2m_publication_loser_distinguishes_uncertainty_from_an_observed_node(kind_shop, capsys, fault):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_jobs_derive import edit_source, host_plan, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    folder = shop.workspace.store / "jobs/pilot/job-1"
    saved, missing = shop.tmp / "publication-original-job", shop.tmp / "missing-peer-job"
    original_run, original_link = jobs2_module.run_job, os.link
    peers, captured, changed = [], [], []

    def run_job(store, job, *args, **kwargs):
        assert job.id == "pilot/job-1" and not captured
        captured.append(job)
        assert job_row(shop.run_open())["state"] == "completed"
        peers.append((folder / "execution.json").read_bytes())
        if fault == "observed-nonregular":
            (folder / "result.json").unlink()
            (folder / "result.json").mkdir()
        return original_run(store, job, *args, **kwargs)

    def link(source, target, *args, **kwargs):
        try:
            return original_link(source, target, *args, **kwargs)
        except FileExistsError:
            if str(target) == "execution.json" and "dst_dir_fd" in kwargs and fault == "symlink":
                assert peers and not changed
                folder.rename(saved)
                symlink_or_skip(missing, folder, target_is_directory=True)
                changed.append(True)
            raise

    try:
        with ExitStack() as patch:
            patch.enter_context(jobs2_patch.object(jobs2_module, "run_job", run_job))
            patch.enter_context(jobs2_patch.object(jobs2_module, "os", SimpleNamespace(**{**vars(os), "link": link})))
            assert jobs2_module.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        assert len(captured) == len(peers) == 1
        assert captured[0].recorded_execution_fence() is None
        assert captured[0].fence_observations["execution.json"].state == jobs2_module.FENCE_VERIFIED
        assert captured[0].execution_owned is False
        if fault == "symlink":
            assert changed == [True]
            assert report == jobs2_2m_unknown_report("job-1", JOBS2_2M_FENCED_UNKNOWN_ACTION)
            assert captured[0].settlement_attempted is False and captured[0].result_observed is False
            assert "Run run-open again" not in report["rows"][0]["next_action"]
        else:
            assert report == {"rows": [{"job": "pilot/job-1", "state": "settle_pending",
                                        "error": JOBS2_2L_RESULT_ERROR, "next_action": JOBS2_2L_RETRY}]}
            assert captured[0].settlement_attempted is True
    finally:
        if folder.is_symlink():
            folder.unlink()
        if saved.exists():
            saved.rename(folder)
    assert (folder / "execution.json").read_bytes() == peers[0]
    assert shop.states("job-1") == ["started", "completed"]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("entry", ["closed", "existing"])
def test_jobs2_2m_observed_nonregular_result_still_attempts_settlement(kind_shop, capsys, entry):
    jobs2_2l_check_result_row(kind_shop, capsys, entry, "directory", True)
