"""Provisioning builds a working initiative: real adapter connections and wake profiles per role.

Generated connections are started through the real adapter here. Host CLIs are not run, so these
tests show the profiles are well formed and match the flags that worked on real hosts, not that a
host accepts them today.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

from tests.integration.test_hierarchy_mailbox import HELPER, ROOT, git, invoke
from tests.integration.test_hierarchy_workspace import Workspace
from tests.conftest import symlink_or_skip


# Generated profiles use POSIX paths and the wake tool needs POSIX process groups.
pytestmark = pytest.mark.skipif(os.name == "nt", reason="generated profiles and wakes are POSIX only")
PROVISION = ROOT / "tools" / "hierarchy_provision.py"
WAKE = ROOT / "tools" / "hierarchy_wake.py"
INITIATIVE = {"id": "pilot", "project": "aegis", "repository": "aegis", "priority": 5, "target_branch": "develop"}
LANES = {"f2": "implementer", "integration": "integrator", "review": "reviewer"}
MAILBOX_TOOLS = {"mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"}
RB2_PYTHON_UNAVAILABLE = ('python interpreter is unavailable; '
                          'pass an absolute, executable "python" in the init request')
RB2_RECORDED_PYTHON_UNAVAILABLE = ('the interpreter recorded in provision.json is unavailable; '
                                  'restore it, or remove the unregistered base and run init again')
_SOURCE_SEED = pytest.StashKey[Path]()
LINK_FALLBACK = frozenset(getattr(errno, name) for name in
                          ("EXDEV", "EPERM", "EACCES", "ENOSYS", "EOPNOTSUPP", "ENOTSUP", "EMLINK")
                          if hasattr(errno, name))


def provision(command, request, *, expect=0):
    path = Path(request.pop("_request_path"))
    path.write_text(json.dumps(request), encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(PROVISION), command, "--request", str(path)], capture_output=True,
                            text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not result.stderr, result.stderr
    assert result.returncode == expect, result.stdout
    return json.loads(result.stdout)


def build_source(source):
    (source / "tools").mkdir(parents=True)
    for path in (ROOT / "tools").glob("hierarchy_*.py"):
        shutil.copy(path, source / "tools" / path.name)
    shutil.copytree(ROOT / "tools" / "hierarchy_templates", source / "tools" / "hierarchy_templates")
    git(source, "init", "-q", "-b", "develop")
    git(source, "add", ".")
    git(source, "commit", "-qm", "pinned source")


def copy_git_object(source, destination):
    link = getattr(os, "link", None)
    if link is not None:
        try:
            link(source, destination)
        except NotImplementedError:
            pass
        except OSError as exc:
            if exc.errno not in LINK_FALLBACK:
                raise
        else:
            return destination
    return shutil.copy2(source, destination)


def copy_source(source, destination):
    source = Path(source)

    def copy_file(path, target):
        parts = Path(path).relative_to(source).parts
        loose = len(parts) == 4 and len(parts[2]) == 2 and all(c in "0123456789abcdef" for c in parts[2])
        packed = len(parts) == 4 and parts[2] == "pack"
        if parts[:2] == (".git", "objects") and (loose or packed):
            return copy_git_object(path, target)
        # Mutable Git metadata, including objects/info, and working files stay private.
        return shutil.copy2(path, target)

    return shutil.copytree(source, destination, symlinks=True, copy_function=copy_file)


def source_object_snapshot(seed):
    objects = {}
    for path in sorted((seed / ".git" / "objects").rglob("*")):
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(65536), b""):
                    digest.update(block)
            objects[path.relative_to(seed).as_posix()] = (path.stat().st_size, digest.hexdigest())
    return objects


def check_source_seed(seed, commit, objects):
    observed = source_object_snapshot(seed)
    for name in sorted(objects.keys() | observed.keys()):
        assert observed.get(name) == objects.get(name), "source seed object changed: " + name
    assert git(seed, "status", "--porcelain") == ""
    assert git(seed, "rev-parse", "HEAD") == commit


def worker_source_seed(tmp_path_factory, request):
    # setup is also imported as a fixture by other modules. A session stash
    # keeps one seed per worker without requiring those modules to import it.
    session = request.session
    if _SOURCE_SEED not in session.stash:
        seed = tmp_path_factory.mktemp("provision-source-seed") / "source"
        build_source(seed)
        # One pack per worker avoids copying loose-object directory metadata per case.
        git(seed, "repack", "-ad")
        commit = git(seed, "rev-parse", "HEAD")
        objects = source_object_snapshot(seed)

        def check_seed():
            check_source_seed(seed, commit, objects)

        session.addfinalizer(check_seed)
        session.stash[_SOURCE_SEED] = seed
    return session.stash[_SOURCE_SEED]


@pytest.fixture(scope="session")
def source_seed(tmp_path_factory, request):
    return worker_source_seed(tmp_path_factory, request)


class Setup:
    def __init__(self, tmp_path, *, source_seed=None):
        self.tmp = tmp_path
        self.base = tmp_path / "initiatives" / "pilot"
        self.workspace = Workspace(tmp_path)
        self.workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
        self.source = tmp_path / "source"
        if source_seed is None:
            # Preserve direct callers in other test modules.
            build_source(self.source)
        else:
            # Mutable files, index and refs stay private; immutable objects share
            # the seed's storage without clone's remote or object alternates.
            copy_source(source_seed, self.source)

    def request(self, **body):
        return {"_request_path": str(self.tmp / ("request-%s.json" % uuid.uuid4().hex)), **body}

    def init_request(self, **changes):
        return self.request(store=str(self.workspace.store), base=str(self.base), source=str(self.source),
                            initiative=dict(INITIATIVE), lanes=LANES, **changes)

    def init(self):
        return provision("init", self.init_request())

    def add_role(self, endpoint, host="claude-code", *, expect=0, **changes):
        return provision("add-role", self.request(base=str(self.base), endpoint=endpoint, host=host, **changes), expect=expect)

    @property
    def root(self):
        return self.base / "mailbox"


@pytest.fixture
def setup(tmp_path, tmp_path_factory, request):
    built = Setup(tmp_path, source_seed=worker_source_seed(tmp_path_factory, request))
    built.init()
    return built


def test_rf42_seed_copy_is_a_standalone_checkout_with_a_verified_runtime(tmp_path, source_seed):
    from tools.hierarchy_runtime_source import verify

    built = Setup(tmp_path, source_seed=source_seed)
    assert git(built.source, "remote") == ""
    assert not (built.source / ".git" / "objects" / "info" / "alternates").exists()
    assert git(built.source, "rev-parse", "HEAD") == git(source_seed, "rev-parse", "HEAD")
    # Verify before status has a chance to refresh the copied index's stat cache.
    pin = {"source": str(built.source), "source_commit": git(source_seed, "rev-parse", "HEAD"),
           "source_tree": git(source_seed, "rev-parse", "HEAD^{tree}")}
    bootstrap = (source_seed / "tools" / "hierarchy_runtime_source.py").read_bytes()
    assert verify(pin) == bootstrap
    record = built.init()
    assert verify(record, built.base) == bootstrap
    assert git(built.source, "status", "--porcelain") == ""


def test_rf42_seed_copy_preserves_symlinks(tmp_path, source_seed):
    seed = tmp_path / "seed"
    copy_source(source_seed, seed)
    (seed / "notes.txt").write_text("fixture note", encoding="utf-8")
    symlink_or_skip("notes.txt", seed / "notes-link")
    git(seed, "add", ".")
    git(seed, "commit", "-qm", "fixture symlink")
    folder = tmp_path / "case"
    folder.mkdir()
    built = Setup(folder, source_seed=seed)
    assert (built.source / "notes-link").is_symlink()
    assert os.readlink(built.source / "notes-link") == "notes.txt"
    assert (built.source / "notes-link").read_bytes() == b"fixture note"


@pytest.mark.parametrize("packed", [False, True], ids=["loose", "packed"])
def test_rf42_seed_copies_share_immutable_git_objects(tmp_path, packed):
    for name in ("base", "copy"):
        (tmp_path / name).mkdir()
    seed = tmp_path / "base" / "source"
    build_source(seed)
    if packed:
        git(seed, "repack", "-ad")
        objects = sorted((seed / ".git" / "objects" / "pack").iterdir())
    else:
        objects = sorted((seed / ".git" / "objects").glob("[0-9a-f][0-9a-f]/*"))
    assert objects
    link = getattr(os, "link", None)
    if link is None:
        pytest.skip("hard links are unavailable")
    probe = tmp_path / "hardlink-probe"
    try:
        link(objects[0], probe)
    except NotImplementedError:
        pytest.skip("hard links are not implemented")
    except OSError as exc:
        if exc.errno not in LINK_FALLBACK:
            raise
        pytest.skip("hard links are unavailable on this filesystem (errno %s)" % exc.errno)
    else:
        probe.unlink()
    built = Setup(tmp_path / "copy", source_seed=seed)
    for original in objects:
        copied = built.source / original.relative_to(seed)
        assert copied.stat().st_dev == original.stat().st_dev
        assert copied.stat().st_ino == original.stat().st_ino


def test_rf42_seed_copy_keeps_mutable_git_state_private(tmp_path, source_seed):
    names = ("index", "HEAD", "config", "refs/heads/develop")
    original = {name: (source_seed / ".git" / name).read_bytes() for name in names}
    built = Setup(tmp_path, source_seed=source_seed)
    for name in names:
        assert not os.path.samefile(source_seed / ".git" / name, built.source / ".git" / name)
    path = "tools/hierarchy_templates/model-bindings.json"
    (built.source / path).write_text("{}", encoding="utf-8")
    git(built.source, "add", "--", path)
    git(built.source, "commit", "-qm", "private mutable state")
    git(built.source, "checkout", "-qb", "private-copy")
    assert (built.source / ".git" / "index").read_bytes() != original["index"]
    assert (built.source / ".git" / "refs/heads/develop").read_bytes() != original["refs/heads/develop"]
    for name, raw in original.items():
        assert (source_seed / ".git" / name).read_bytes() == raw
    assert git(source_seed, "branch", "--list", "private-copy") == ""


@pytest.mark.parametrize("failure", [
    pytest.param(getattr(errno, name), id=name.lower())
    for name in ("EXDEV", "EPERM", "EACCES", "ENOSYS", "EOPNOTSUPP", "ENOTSUP", "EMLINK")
    if hasattr(errno, name)
] + [pytest.param("unavailable", id="unavailable"), pytest.param("not-implemented", id="not-implemented")])
def test_rf42_seed_copy_falls_back_when_hard_links_are_unavailable(tmp_path, source_seed, monkeypatch, failure):
    module = sys.modules[Setup.__module__]
    attempts = []

    def refused(source, destination):
        attempts.append(source)
        if failure == "not-implemented":
            raise NotImplementedError("hard links unavailable")
        raise OSError(failure, "hard links unavailable")

    monkeypatch.setattr(module, "os", SimpleNamespace(link=None if failure == "unavailable" else refused))
    built = Setup(tmp_path, source_seed=source_seed)
    if failure != "unavailable":
        assert attempts
    objects = source_seed / ".git" / "objects"
    original = next(iter(sorted(objects.glob("[0-9a-f][0-9a-f]/*")) + sorted((objects / "pack").glob("*"))))
    copied = built.source / original.relative_to(source_seed)
    assert copied.read_bytes() == original.read_bytes()
    assert not copied.samefile(original)
    assert git(built.source, "status", "--porcelain") == ""


def test_rf42_seed_copy_does_not_hide_unexpected_link_errors(tmp_path, source_seed, monkeypatch):
    module = sys.modules[Setup.__module__]

    def broken(source, destination):
        raise OSError(errno.EIO, "unexpected object link failure")

    monkeypatch.setattr(module, "os", SimpleNamespace(link=broken))
    with pytest.raises(shutil.Error, match="unexpected object link failure"):
        Setup(tmp_path, source_seed=source_seed)


def test_rf42_seed_finalizer_names_a_shared_object_corrupted_in_place(tmp_path, tmp_path_factory):
    checks = []
    session = SimpleNamespace(stash=pytest.Stash(), addfinalizer=checks.append)
    seed = worker_source_seed(tmp_path_factory, SimpleNamespace(session=session))
    original = next((seed / ".git" / "objects" / "pack").glob("*.pack"))
    probe = tmp_path / "link-probe"
    link = getattr(os, "link", None)
    if link is None:
        pytest.skip("hard links are unavailable")
    try:
        link(original, probe)
    except NotImplementedError:
        pytest.skip("hard links are not implemented")
    except OSError as exc:
        if exc.errno not in LINK_FALLBACK:
            raise
        pytest.skip("hard links are unavailable on this filesystem (errno %s)" % exc.errno)
    else:
        probe.unlink()
    copied = tmp_path / "copy"
    copy_source(seed, copied)
    relative = original.relative_to(seed)
    changed = copied / relative
    assert changed.samefile(original)
    mode = changed.stat().st_mode & 0o777
    try:
        changed.chmod(mode | 0o200)
        with changed.open("r+b") as stream:
            first = stream.read(1)
            stream.seek(0)
            stream.write(bytes([first[0] ^ 0xff]))
    finally:
        changed.chmod(mode)
    assert len(checks) == 1
    with pytest.raises(AssertionError) as caught:
        checks[0]()
    assert str(caught.value).splitlines()[0] == "source seed object changed: " + relative.as_posix()


def test_rf33_source_clones_keep_mutations_private(tmp_path, source_seed):
    for name in ("first", "second", "third"):
        (tmp_path / name).mkdir()
    seed = source_seed
    path = "tools/hierarchy_templates/model-bindings.json"
    original = (seed / path).read_bytes()
    commit = git(seed, "rev-parse", "HEAD")
    first = Setup(tmp_path / "first", source_seed=seed)
    second = Setup(tmp_path / "second", source_seed=seed)
    first.init()
    second.init()
    first_record = (first.base / "provision.json").read_bytes()
    second_record = (second.base / "provision.json").read_bytes()

    # Overwrite a tracked file, stage it, commit it and change the local refs.
    (first.source / path).write_text("{}", encoding="utf-8")
    git(first.source, "add", "--", path)
    for source in (seed, second.source):
        assert (source / path).read_bytes() == original
        assert git(source, "status", "--porcelain") == ""
        assert git(source, "rev-parse", "HEAD") == commit
    git(first.source, "commit", "-qm", "private fixture policy")
    git(first.source, "branch", "private-fixture")
    (first.source / "untracked.txt").write_text("private", encoding="utf-8")
    (first.base / "provision.json").write_text("{}", encoding="utf-8")

    third = Setup(tmp_path / "third", source_seed=seed)
    third.init()
    for source in (seed, second.source, third.source):
        assert (source / path).read_bytes() == original
        assert git(source, "status", "--porcelain") == ""
        assert git(source, "rev-parse", "HEAD") == commit
        assert git(source, "branch", "--list", "private-fixture") == ""
    assert (second.base / "provision.json").read_bytes() == second_record
    assert json.loads((third.base / "provision.json").read_text())["source_commit"] == commit
    # Restore only this case's record so the public pin verifier sees its drift.
    (first.base / "provision.json").write_bytes(first_record)
    assert "checkout identity changed" in first.add_role("pilot/orchestrator", expect=2)["error"]
    assert second.add_role("pilot/orchestrator")["generation"] == 1
    assert third.add_role("pilot/orchestrator")["generation"] == 1


def test_init_builds_the_mailbox_registers_the_initiative_and_pins_the_source(setup):
    manifest = json.loads((setup.root / "manifest.json").read_text())
    assert set(manifest["endpoints"]) == {"pilot/front-door", "pilot/orchestrator", "pilot/root", "pilot/lane/f2",
                                          "pilot/lane/integration", "pilot/lane/review"}
    assert manifest["endpoints"]["pilot/lane/review"] == {"kind": "reviewer"}
    assert manifest["writer_limit"] == 3
    record = setup.workspace.run("status")["initiatives"]["pilot"]
    assert record["mailbox_root"] == str(setup.root) and record["delivery_dir"] == str(setup.base / "delivery")
    pinned = json.loads((setup.base / "provision.json").read_text())
    assert pinned["source_commit"] == git(setup.source, "rev-parse", "HEAD")
    assert pinned["source_tree"] == git(setup.source, "rev-parse", "HEAD^{tree}")


def test_init_uses_the_bound_interpreter_for_a_working_mcp_connection(tmp_path):
    built = Setup(tmp_path)
    record = built.init()
    assert record["python"] == sys.executable
    assert json.loads((built.base / "provision.json").read_text())["python"] == sys.executable
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    server = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]
    assert server["command"] == sys.executable
    assert "mailbox_inbox" in start_connection(role["connection"])


def test_init_needs_no_system_python_path(tmp_path, mr1_cli, monkeypatch):
    module, call = mr1_cli
    built = Setup(tmp_path)
    interpreter = str(tmp_path / "bound-python")
    shutil.copy2(sys.executable, interpreter)
    monkeypatch.setattr(module, "sys", SimpleNamespace(executable=interpreter))
    # Replace only the provisioner's OS reference, leaving pytest's filesystem operations intact.
    monkeypatch.setattr(module, "os", SimpleNamespace(
        X_OK=os.X_OK, access=lambda path, mode: path != "/usr/bin/python3" and os.access(path, mode)))
    record = call("init", built.init_request())
    assert record["python"] == interpreter


@pytest.mark.parametrize("interpreter", [None, "", "missing"])
def test_init_refuses_an_unavailable_bound_interpreter_without_publication(tmp_path, mr1_cli, monkeypatch,
                                                                         interpreter):
    module, call = mr1_cli
    built = Setup(tmp_path)
    if interpreter == "missing":
        interpreter = str(tmp_path / "missing-python")
    monkeypatch.setattr(module, "sys", SimpleNamespace(executable=interpreter))
    assert call("init", built.init_request(), expect=2) == {"error": RB2_PYTHON_UNAVAILABLE}
    assert not built.base.exists()
    assert "pilot" not in built.workspace.run("status")["initiatives"]


@pytest.mark.parametrize("kind", ["missing", "directory", "not-executable"])
def test_init_refuses_an_unavailable_explicit_interpreter(tmp_path, kind):
    built = Setup(tmp_path)
    interpreter = tmp_path / "unavailable-python"
    if kind == "directory":
        interpreter.mkdir()
    elif kind == "not-executable":
        interpreter.write_text("not executable", encoding="utf-8")
        interpreter.chmod(0o600)
    assert provision("init", built.init_request(python=str(interpreter)), expect=2) == {
        "error": RB2_PYTHON_UNAVAILABLE}
    assert not built.base.exists()
    assert "pilot" not in built.workspace.run("status")["initiatives"]


def test_init_preserves_an_explicit_interpreter_override(tmp_path):
    built = Setup(tmp_path)
    interpreter = str(Path(sys.executable).resolve())
    assert provision("init", built.init_request(python=interpreter))["python"] == interpreter
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    server = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]
    assert server["command"] == interpreter
    assert "mailbox_inbox" in start_connection(role["connection"])


@pytest.mark.parametrize("python", [5, "", None, "\x00", "x" * 4097])
def test_rb2_explicit_malformed_python_keeps_its_validation_error(tmp_path, python):
    built = Setup(tmp_path)
    assert provision("init", built.init_request(python=python), expect=2) == {"error": "invalid python"}
    assert not built.base.exists()
    assert "pilot" not in built.workspace.run("status")["initiatives"]


@pytest.fixture
def rb2_pending(tmp_path, mr1_cli, monkeypatch):
    import hierarchy_workspace

    _, call = mr1_cli
    built = Setup(tmp_path)
    built.python = tmp_path / "pending-python"
    shutil.copy2(sys.executable, built.python)
    publish = hierarchy_workspace.publish_file

    def interrupted(path, raw, **kwargs):
        if path.parent == built.workspace.store / "events":
            raise OSError("registration interrupted")
        return publish(path, raw, **kwargs)

    # Fail only the workspace's file-publication boundary, after the real base was renamed into place.
    with monkeypatch.context() as patch:
        patch.setattr(hierarchy_workspace, "publish_file", interrupted)
        assert call("init", built.init_request(python=str(built.python)), expect=2) == {
            "error": "registration interrupted"}
    assert json.loads((built.base / "provision.json").read_text())["python"] == str(built.python)
    assert "pilot" not in built.workspace.run("status")["initiatives"]
    return built


@pytest.mark.parametrize("kind", ["removed", "relative", "directory", "not-executable", "missing-field", "invalid",
                                 "oversized"])
def test_rb2_pending_init_refuses_an_unavailable_recorded_interpreter(rb2_pending, kind):
    built = rb2_pending
    path = built.base / "provision.json"
    record = json.loads(path.read_text())
    if kind == "removed":
        built.python.unlink()
    elif kind == "not-executable":
        built.python.chmod(0o600)
    elif kind == "missing-field":
        del record["python"]
    else:
        record["python"] = {"relative": "relative-python", "directory": str(built.tmp), "invalid": 5,
                            "oversized": "x" * 4097}[kind]
    path.write_text(json.dumps(record), encoding="utf-8")
    before = path.read_bytes()
    assert provision("init", built.init_request(), expect=2) == {"error": RB2_RECORDED_PYTHON_UNAVAILABLE}
    assert path.read_bytes() == before
    assert "pilot" not in built.workspace.run("status")["initiatives"]


def test_rb2_pending_init_keeps_the_runtime_source_refusal_for_a_non_object_record(rb2_pending):
    built = rb2_pending
    path = built.base / "provision.json"
    path.write_text("[]", encoding="utf-8")
    assert provision("init", built.init_request(), expect=2) == {
        "error": ("runtime source verification failed: expected commit=None tree=None; "
                  "observed commit=unavailable tree=unavailable; list indices must be integers or slices, not str; "
                  "reprovision into a new base through the existing handoff flow")}
    assert path.read_text() == "[]"
    assert "pilot" not in built.workspace.run("status")["initiatives"]


@pytest.mark.parametrize("recorded_available", [False, True])
def test_rb2_init_reports_a_base_collision_before_interpreter_checks(rb2_pending, recorded_available):
    built = rb2_pending
    if not recorded_available:
        built.python.unlink()
    before = (built.base / "provision.json").read_bytes()
    request = built.init_request(python=sys.executable)
    request["initiative"]["id"] = "second"
    assert provision("init", request, expect=2) == {
        "error": "initiative base already exists: " + str(built.base)}
    assert (built.base / "provision.json").read_bytes() == before
    initiatives = built.workspace.run("status")["initiatives"]
    assert "pilot" not in initiatives and "second" not in initiatives


def test_rb2_pending_init_refuses_a_conflicting_explicit_python(rb2_pending):
    built = rb2_pending
    before = (built.base / "provision.json").read_bytes()
    assert provision("init", built.init_request(python=sys.executable), expect=2) == {
        "error": "python does not match provision.json"}
    assert (built.base / "provision.json").read_bytes() == before
    assert "pilot" not in built.workspace.run("status")["initiatives"]


@pytest.mark.parametrize("explicit", [False, True])
def test_rb2_pending_init_reuses_the_available_recorded_interpreter(rb2_pending, explicit):
    built = rb2_pending
    options = {"python": str(built.python)} if explicit else {}
    assert provision("init", built.init_request(**options))["python"] == str(built.python)
    assert "pilot" in built.workspace.run("status")["initiatives"]


@pytest.mark.parametrize("fault", [OSError, ValueError])
def test_rb2_interpreter_probe_failure_has_a_fixed_refusal_and_hint(tmp_path, mr1_cli, monkeypatch, fault):
    module, call = mr1_cli
    built = Setup(tmp_path)

    def unavailable(*args):
        raise fault("probe detail must not be echoed")

    monkeypatch.setattr(module, "os", SimpleNamespace(X_OK=os.X_OK, access=unavailable))
    assert call("init", built.init_request(), expect=2) == {"error": RB2_PYTHON_UNAVAILABLE}
    assert not built.base.exists()
    assert "pilot" not in built.workspace.run("status")["initiatives"]


@pytest.mark.parametrize("host", ["claude-code", "codex-cli", "codex"])
@pytest.mark.parametrize("kind", ["removed", "relative", "directory", "not-executable", "missing-field", "invalid",
                                 "empty", "nul", "oversized"])
def test_rb2c_add_role_refuses_an_unavailable_recorded_interpreter(setup, host, kind):
    path = setup.base / "provision.json"
    record = json.loads(path.read_text())
    interpreter = setup.tmp / "recorded-python"
    if kind in ("removed", "not-executable"):
        shutil.copy2(sys.executable, interpreter)
        if kind == "removed":
            interpreter.unlink()
        else:
            interpreter.chmod(0o600)
        record["python"] = str(interpreter)
    elif kind == "missing-field":
        del record["python"]
    else:
        record["python"] = {"relative": "relative-python", "directory": str(setup.tmp), "invalid": 5,
                            "empty": "", "nul": "\x00", "oversized": "x" * 4097}[kind]
    path.write_text(json.dumps(record), encoding="utf-8")
    before = {p.relative_to(setup.base): p.read_bytes() for p in setup.base.rglob("*") if p.is_file()}
    assert setup.add_role("pilot/orchestrator", host, session="01a19a8e-3073-7af2-b5c0-d0c41fe82ada", cwd=str(setup.source),
                          expect=2) == {"error": RB2_RECORDED_PYTHON_UNAVAILABLE}
    assert {p.relative_to(setup.base): p.read_bytes() for p in setup.base.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("fault", [OSError, ValueError])
def test_rb2c_add_role_interpreter_probe_failure_is_a_fixed_refusal(setup, mr1_cli, monkeypatch, fault):
    module, call = mr1_cli
    before = invoke(setup.root, "status")["bindings"]

    def unavailable(*args):
        raise fault("probe detail must not be echoed")

    monkeypatch.setattr(module, "os", SimpleNamespace(X_OK=os.X_OK, access=unavailable))
    assert call("add-role", setup.request(base=str(setup.base), endpoint="pilot/orchestrator", host="claude-code"),
                expect=2) == {"error": RB2_RECORDED_PYTHON_UNAVAILABLE}
    assert invoke(setup.root, "status")["bindings"] == before


@pytest.fixture
def rb2c_registered_move(setup):
    old = setup.tmp / "old" / "mailbox"
    old.parent.mkdir()
    invoke(old, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {
        "pilot/front-door": {}, "pilot/orchestrator": {}, "pilot/root": {}}, "writer_limit": 3, "counterparts": []})
    invoke(old, "bind", {"endpoint": "pilot/orchestrator", "host": "codex", "session": "native-orchestrator",
                         "expected_generation": 0})
    body = {"store": str(setup.workspace.store), "base": str(setup.base), "source": str(setup.source),
            "old_root": str(old), "hierarchy": "pilot", "note": "The owner approved this move.",
            "root": {"host": "codex", "session": "01a19a8e-3073-7af2-b5c0-d0c41fe82ada"},
            "initiative": {key: value for key, value in INITIATIVE.items() if key != "id"}}
    return setup, body


def test_rb2c_registered_move_refuses_a_conflicting_explicit_python(rb2c_registered_move):
    built, body = rb2c_registered_move
    interpreter = built.tmp / "other-python"
    shutil.copy2(sys.executable, interpreter)
    before = {p.relative_to(built.base): p.read_bytes() for p in built.base.rglob("*") if p.is_file()}
    assert provision("move", built.request(**body, python=str(interpreter)), expect=2) == {
        "error": "python does not match provision.json"}
    assert {p.relative_to(built.base): p.read_bytes() for p in built.base.rglob("*") if p.is_file()} == before


def test_rb2c_registered_move_refuses_an_unavailable_recorded_python(rb2c_registered_move):
    built, body = rb2c_registered_move
    path = built.base / "provision.json"
    record = json.loads(path.read_text())
    record["python"] = str(built.tmp / "deleted-python")
    path.write_text(json.dumps(record), encoding="utf-8")
    before = {p.relative_to(built.base): p.read_bytes() for p in built.base.rglob("*") if p.is_file()}
    assert provision("move", built.request(**body), expect=2) == {"error": RB2_RECORDED_PYTHON_UNAVAILABLE}
    assert {p.relative_to(built.base): p.read_bytes() for p in built.base.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("explicit", [False, True])
def test_rb2c_registered_move_reuses_the_available_recorded_python(rb2c_registered_move, explicit):
    built, body = rb2c_registered_move
    options = {"python": sys.executable} if explicit else {}
    assert provision("move", built.request(**body, **options))["hierarchy"] == "pilot"
    path = built.base / "connections" / "pilot%2Forchestrator-g1.json"
    assert json.loads(path.read_text())["command"] == sys.executable


def test_rb2_no_plan_codex_output_changes_only_the_legacy_interpreter(tmp_path):
    built = Setup(tmp_path)
    request = built.init_request()
    assert "python" not in request
    provision("init", request)
    assert not (built.base / "host-plan.json").exists()
    session = "01a19a29-d635-7411-8529-9efedafc0881"
    role = built.add_role("pilot/lane/review", "codex-cli", session=session, cwd=str(built.source))
    arguments = ["-I", "-B", str(built.base / "runtime-source.py"), "--provision", str(built.base / "provision.json"),
                 "--entry", str(built.source / "tools/hierarchy_mailbox.py"), "--", "--root", str(built.root), "serve",
                 "--endpoint", "pilot/lane/review", "--host", "codex-cli", "--session", session, "--generation", "1",
                 "--delivery-dir", str(built.base / "delivery"), "--workspace-store", str(built.workspace.store),
                 "--initiative", "pilot"]
    features = ["apps", "plugins", "remote_plugin", "multi_agent", "multi_agent_v2", "memories", "computer_use",
                "browser_use", "browser_use_external", "browser_use_full_cdp_access", "goals", "shell_tool", "unified_exec"]
    tools = ["mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"]
    # Literal pre-RB-2 expectations; no checkout history or product renderer supplies expected bytes.
    legacy_profile = {
        "schema": "aegis.hierarchy-codex-profile/v1", "endpoint": "pilot/lane/review", "role": "reviewer",
        "host": "codex-cli", "session": session, "generation": 1, "sandbox": "read-only", "writable_roots": [],
        "network_access": False, "approval_policy": "never", "ignore_user_config": True, "disabled_features": features,
        "mcp_servers": {"aegis_mailbox": {"command": "/usr/bin/python3", "args": arguments, "required": True,
            "enabled_tools": tools, "tools": {"mailbox_inbox": {"output_token_limit": 30000},
                "mailbox_publish": {"approval_mode": "approve"}, "mailbox_ack_handoff": {"approval_mode": "approve"}}}},
        "model": None, "effort": None, "service_tier": None, "tmpdir": None, "add_dirs": [],
        "cwd": str(built.source), "skip_git_repo_check": False}
    legacy_config = ('mcp_servers={aegis_mailbox={command="/usr/bin/python3",args=' + json.dumps(arguments) +
                     ',required=true,enabled_tools=' + json.dumps(tools) +
                     ',tools={mailbox_inbox={output_token_limit=30000},mailbox_publish={approval_mode="approve"},'
                     'mailbox_ack_handoff={approval_mode="approve"}}}}')
    legacy_argv = ["codex", *[word for feature in features for word in ("--disable", feature)], "exec",
                   "--ignore-user-config", "--sandbox", "read-only", "-c", 'approval_policy="never"',
                   "-c", legacy_config, "--json", "-C", str(built.source), "resume", session]

    def substitute(value):
        return value.replace(json.dumps("/usr/bin/python3"), json.dumps(sys.executable))

    expected_profile = substitute(json.dumps(legacy_profile, indent=2)) + "\n"
    expected_argv = [substitute(word) for word in legacy_argv]
    assert Path(role["codex_profile"]).read_text() == expected_profile
    wake = {"schema": "aegis.hierarchy-wake-profile/v1", "endpoint": "pilot/lane/review", "host": "codex-cli",
            "session": session, "generation": 1, "argv": expected_argv, "cwd": str(built.source),
            "timeout_seconds": 900, "prompt_via": "argv"}
    assert Path(role["wake_profile"]).read_text() == json.dumps(wake, indent=2) + "\n"
    assert json.loads(Path(role["connection"]).read_text()) == {
        "mcpServers": {"aegis_mailbox": {"command": sys.executable, "args": arguments}}}
    assert substitute(legacy_config) in json.loads(Path(role["wake_profile"]).read_text())["argv"]


def test_init_refuses_an_existing_base(setup):
    request = setup.init_request()
    request["initiative"] = {**INITIATIVE, "id": "second"}
    refused = provision("init", request, expect=2)
    assert refused["error"] == "initiative base already exists: " + str(setup.base)
    assert "second" not in setup.workspace.run("status")["initiatives"]


def test_a_dirty_source_is_refused_because_every_adapter_runs_from_it(tmp_path, source_seed):
    built = Setup(tmp_path, source_seed=source_seed)
    (built.source / "uncommitted.txt").write_text("not pinned")
    refused = provision("init", built.init_request(), expect=2)
    assert refused["error"] == "source checkout must be clean so adapters run exact committed code"
    assert not built.base.exists()


def test_a_source_that_is_not_a_checkout_is_refused(tmp_path, source_seed):
    built = Setup(tmp_path, source_seed=source_seed)
    source = tmp_path / "never-a-checkout"
    source.mkdir()
    request = built.init_request()
    request["source"] = str(source)
    assert provision("init", request, expect=2)["error"] == "source checkout is not a git checkout: " + str(source)
    assert not built.base.exists()


def test_a_duplicate_initiative_or_missing_store_creates_nothing(tmp_path, source_seed):
    built = Setup(tmp_path, source_seed=source_seed)
    built.workspace.register("pilot")
    assert provision("init", built.init_request(), expect=2)["error"] == "initiative already registered: pilot"
    assert not built.base.exists()
    request = built.init_request()
    request["store"] = str(tmp_path / "absent-store")
    assert provision("init", request, expect=2)["error"] == "workspace store is not initialized"
    assert not built.base.exists()


@pytest.mark.parametrize("change,error", [
    ({"base": "relative/base"}, "path must be absolute"),
    ({"lanes": {"f2": "wizard"}}, "invalid lane kind"),
    ({"lanes": {"../escape": "implementer"}}, "invalid lane id"),
    ({"initiative": {**INITIATIVE, "priority": 0}}, "invalid priority"),
    ({"initiative": {**INITIATIVE, "mailbox_root": "/set/by/the/tool"}}, "unexpected fields"),
    ({"run": "rm -rf /"}, "unexpected fields"),
])
def test_malformed_init_requests_are_refused(tmp_path, change, error, source_seed):
    built = Setup(tmp_path, source_seed=source_seed)
    assert error in provision("init", {**built.init_request(), **change}, expect=2)["error"]
    assert not built.base.exists()


def start_connection(connection, server="aegis_mailbox"):
    definition = json.loads(Path(connection).read_text())["mcpServers"][server]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    result = subprocess.run([definition["command"], *definition["args"]], input="".join(json.dumps(f) + "\n" for f in frames),
                            capture_output=True, text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    return {tool["name"] for tool in json.loads(result.stdout.splitlines()[1])["result"]["tools"]}


@pytest.mark.parametrize("endpoint,extra", [
    ("pilot/front-door", {"workspace_initiative"}),
    ("pilot/orchestrator", {"workspace_capacity", "workspace_initiative"}),
    ("pilot/lane/f2", {"workspace_path_overlap"}),
    ("pilot/lane/integration", {"workspace_path_overlap"}),
    ("pilot/lane/review", set()),
])
def test_each_role_gets_a_working_connection_with_only_its_tools(setup, endpoint, extra):
    role = setup.add_role(endpoint, cwd=str(setup.tmp))
    assert uuid.UUID(role["session"])
    assert role["generation"] == 1
    assert start_connection(role["connection"]) == MAILBOX_TOOLS | extra
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]
    assert str(setup.source / "tools" / "hierarchy_mailbox.py") in definition["args"]
    assert str(setup.base / "delivery") in definition["args"]


def test_a_claude_profile_uses_the_flags_that_worked_on_a_real_host(setup):
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), model="claude-opus-5-5", effort="max",
                          add_dirs=[str(setup.source)], timeout_seconds=600)
    wake = json.loads(Path(role["wake_profile"]).read_text())
    argv = wake["argv"]
    assert wake["prompt_via"] == "stdin", "a trailing variadic flag consumed the prompt on the real host"
    assert wake["timeout_seconds"] == 600 and wake["cwd"] == str(setup.tmp)
    assert argv[0] == "claude" and "--restricted" in argv and "--strict-mcp-config" in argv and "--print" in argv
    assert "--tools=Read,Glob,Grep" in argv, "the separate empty --tools argument failed on the real host"
    assert argv[argv.index("--resume") + 1] == role["session"]
    assert argv[argv.index("--permission-mode") + 1] == "manual"
    assert argv[argv.index("--permission-prompts") + 1] == "none"
    assert argv[argv.index("--mcp-config") + 1] == role["connection"]
    assert argv[argv.index("--model") + 1] == "claude-opus-5-5"
    assert argv[argv.index("--add-dir") + 1] == str(setup.source)
    allowed = argv[argv.index("--allowedTools") + 1].split(",")
    assert set(allowed) == {"mcp__aegis_mailbox__" + name for name in MAILBOX_TOOLS | {"workspace_capacity", "workspace_initiative"}}
    start = role["start_argv"]
    assert start[start.index("--session-id") + 1] == role["session"] and "--resume" not in start


@pytest.mark.parametrize("endpoint,tools", [
    ("pilot/front-door", "--tools="),
    ("pilot/orchestrator", "--tools=Read,Glob,Grep"),
    ("pilot/lane/review", "--tools=Read,Glob,Grep"),
    ("pilot/lane/f2", "--tools=Read,Glob,Grep,Edit,Write"),
    ("pilot/lane/integration", "--tools=Read,Glob,Grep,Edit,Write"),
])
def test_claude_roles_get_only_their_default_tools(setup, endpoint, tools):
    role = setup.add_role(endpoint, cwd=str(setup.tmp))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert tools in argv
    allowed = argv[argv.index("--allowedTools") + 1].split(",")
    assert ("Edit" in allowed) == endpoint.endswith(("f2", "integration"))


def test_the_generated_wake_profile_is_accepted_by_the_wake_tool(setup):
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    invoke(setup.root, "bind", {"endpoint": "pilot/front-door", "host": "h", "session": "fd", "expected_generation": 0})
    invoke(setup.root, "publish", {"message_id": "hello", "from": "pilot/front-door", "to": "pilot/orchestrator", "host": "h",
                                   "session": "fd", "binding_generation": 1, "type": "info", "body": "Hello."})
    result = subprocess.run([sys.executable, "-I", str(WAKE), "--root", str(setup.root), "--delivery-dir",
                             str(setup.base / "delivery"), "--endpoint", "pilot/orchestrator", "--profile",
                             role["wake_profile"], "--dry-run"], capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["would_wake"] == ["hello"]


def test_a_native_thread_gets_a_flat_connection_and_no_wake_profile(setup):
    role = setup.add_role("pilot/orchestrator", "codex", session="01a19a9d-b1ad-7b22-bec1-5e465d490ae6")
    assert role["wake"] == "native" and "wake_profile" not in role and "start_argv" not in role
    definition = json.loads(Path(role["connection"]).read_text())
    assert definition["command"] == sys.executable
    arguments = definition["args"]
    assert arguments[arguments.index("--host") + 1] == "codex"
    assert arguments[arguments.index("--session") + 1] == "01a19a9d-b1ad-7b22-bec1-5e465d490ae6"
    assert not list((setup.base / "profiles").glob("*")) if (setup.base / "profiles").exists() else True
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    done = subprocess.run([definition["command"], *arguments], input=json.dumps(frame) + "\n", capture_output=True, text=True, timeout=20,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert {"mailbox_inbox", "mailbox_publish", "workspace_capacity"} <= {tool["name"] for tool in json.loads(done.stdout)["result"]["tools"]}


def test_a_native_thread_needs_its_actual_session(setup):
    assert "actual session" in setup.add_role("pilot/orchestrator", "codex", expect=2)["error"]


def test_root_may_be_a_native_thread(setup):
    role = setup.add_role("pilot/root", "codex", session="01a19a8e-3073-7af2-b5c0-d0c41fe82ada")
    assert role["host"] == "codex" and "connection" not in role


def test_a_moved_writer_keeps_its_real_sandbox_options(setup, tmp_path):
    writable, tmp = tmp_path / "integration", tmp_path / "private-tmp"
    writable.mkdir()
    tmp.mkdir()
    role = setup.add_role("pilot/lane/f2", "codex-cli", session="01a19969-41df-7631-8ecd-57add111e96b", cwd=str(setup.source), writable_roots=[str(writable)],
                          add_dirs=[str(writable)], tmpdir=str(tmp), effort="medium", skip_git_repo_check=True)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    settings = [argv[index + 1] for index, word in enumerate(argv) if word == "-c"]
    assert 'sandbox_workspace_write.writable_roots=["%s"]' % writable in settings
    assert 'shell_environment_policy.set.TMPDIR="%s"' % tmp in settings
    assert 'shell_environment_policy.set.TMPPREFIX="%s/zsh"' % tmp in settings
    assert 'model_reasoning_effort="medium"' in settings
    assert argv[argv.index("--add-dir") + 1] == str(writable)
    assert "--skip-git-repo-check" in argv
    assert argv[-2:] == ["resume", "01a19969-41df-7631-8ecd-57add111e96b"]


def test_writer_options_are_checked(setup, tmp_path):
    missing = str(tmp_path / "no-such-folder")
    options = {"session": "writer-session", "cwd": str(setup.source)}
    assert "writable_roots" in setup.add_role("pilot/lane/f2", "codex-cli", writable_roots=[missing], expect=2, **options)["error"]
    assert "tmpdir" in setup.add_role("pilot/lane/f2", "codex-cli", tmpdir=missing, expect=2, **options)["error"]
    assert "writable_roots" in setup.add_role("pilot/orchestrator", "codex-cli", writable_roots=[str(tmp_path)], expect=2, **options)["error"]
    assert "skip_git_repo_check" in setup.add_role("pilot/lane/f2", "claude-code", skip_git_repo_check=True, cwd=str(tmp_path), expect=2)["error"]


def test_codex_needs_a_git_cwd_unless_a_real_lane_says_otherwise(setup, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert "git checkout" in setup.add_role("pilot/lane/f2", "codex-cli", session="writer-session", cwd=str(plain), expect=2)["error"]
    assert setup.add_role("pilot/lane/f2", "codex-cli", session="writer-session", cwd=str(plain), skip_git_repo_check=True)["cwd"] == str(plain)


def codex_config(argv):
    tomllib = pytest.importorskip("tomllib", reason="Codex settings are read with tomllib, Python 3.11+")

    def merge(into, new):
        for key, value in new.items():
            if isinstance(value, dict) and isinstance(into.get(key), dict):
                merge(into[key], value)
            else:
                into[key] = value

    parsed = {}
    for value in [argv[index + 1] for index, word in enumerate(argv) if word == "-c"]:
        merge(parsed, tomllib.loads(value))
    return parsed


def test_a_read_only_codex_role_matches_the_profile_that_worked_on_a_real_host(setup):
    role = setup.add_role("pilot/orchestrator", "codex-cli", session="01a19a29-d635-7411-8529-9efedafc0881",
                          cwd=str(setup.source))
    wake = json.loads(Path(role["wake_profile"]).read_text())
    argv = wake["argv"]
    assert wake["prompt_via"] == "argv"
    assert argv[0] == "codex" and argv[-2:] == ["resume", "01a19a29-d635-7411-8529-9efedafc0881"]
    assert argv[argv.index("-C") + 1] == str(setup.source)
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert "--ignore-user-config" in argv and "--json" in argv
    # multi_agent_v2 too: run 1's sessions were offered the v2 agent tools with only multi_agent disabled.
    for feature in ("shell_tool", "unified_exec", "multi_agent", "multi_agent_v2", "apps", "plugins", "memories", "goals"):
        assert feature in [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]
    config = codex_config(argv)
    assert config["approval_policy"] == "never"
    server = config["mcp_servers"]["aegis_mailbox"]
    assert server["required"] is True and server["command"] == sys.executable
    assert set(server["enabled_tools"]) == MAILBOX_TOOLS | {"workspace_capacity", "workspace_initiative"}
    assert "--endpoint" in server["args"] and "pilot/orchestrator" in server["args"]
    assert server["tools"]["mailbox_publish"]["approval_mode"] == "approve"
    assert "start_argv" not in role, "Codex assigns its own session ID, so a session must exist before this step"


def test_a_codex_writer_gets_its_own_worktree_and_no_network(setup):
    role = setup.add_role("pilot/lane/f2", "codex-cli", session="01a19a29-d635-7411-8529-9efedafc0882", cwd=str(setup.source))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[argv.index("--sandbox") + 1] == "workspace-write"
    assert "shell_tool" not in [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]
    settings = codex_config(argv)["sandbox_workspace_write"]
    assert settings == {"writable_roots": [], "exclude_slash_tmp": True, "exclude_tmpdir_env_var": True, "network_access": False}


def test_codex_needs_a_session_and_a_git_checkout(setup):
    missing = setup.add_role("pilot/orchestrator", "codex-cli", cwd=str(setup.source), expect=2)
    assert missing["error"] == "codex assigns its own session ID; start it first and give the session here"
    outside = setup.add_role("pilot/orchestrator", "codex-cli", session="abc", cwd=str(setup.tmp), expect=2)
    assert outside["error"] == "codex needs a cwd inside a git checkout"
    assert invoke(setup.root, "status")["bindings"]["pilot/orchestrator"] is None


def test_root_gets_a_binding_but_no_connection_or_profile(setup):
    role = setup.add_role("pilot/root", "codex-cli", session="root-session-1")
    assert role["generation"] == 1 and "connection" not in role and "wake_profile" not in role
    assert invoke(setup.root, "status")["bindings"]["pilot/root"]["session"] == "root-session-1"
    assert not list((setup.base / "connections").glob("*root*"))


def test_add_role_with_the_manifest_kind_is_accepted(setup):
    assert setup.add_role("pilot/lane/f2", cwd=str(setup.tmp), kind="implementer")["generation"] == 1


@pytest.mark.parametrize("endpoint,kind,error", [
    ("pilot/lane/f2", "reviewer", "kind 'reviewer' does not match the manifest kind 'implementer' of pilot/lane/f2"),
    ("pilot/orchestrator", "implementer", "kind 'implementer' does not match the manifest kind (none) of pilot/orchestrator"),
    ("pilot/lane/review", 7, "invalid kind"),
])
def test_add_role_with_another_kind_is_refused_and_binds_nothing(setup, endpoint, kind, error):
    assert setup.add_role(endpoint, cwd=str(setup.tmp), kind=kind, expect=2)["error"] == error
    assert not (setup.root / "bindings" / endpoint).exists()


def test_adding_a_role_again_keeps_its_session_and_a_different_session_is_refused(setup):
    first = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    again = setup.add_role("pilot/orchestrator", session=first["session"], cwd=str(setup.tmp))
    assert again["generation"] == 1 and again["connection"] == first["connection"]
    refused = setup.add_role("pilot/orchestrator", session=str(uuid.uuid4()), cwd=str(setup.tmp), expect=2)
    assert refused["error"] == "endpoint is bound to another session; hand it off first"


def test_after_a_handoff_new_files_are_written_and_the_old_ones_are_kept(setup):
    first = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    brief = setup.base / "brief.md"
    brief.write_bytes(b"Handoff.\n")
    successor = str(uuid.uuid4())
    invoke(setup.root, "bind", invoke(setup.root, "draft-handoff", {
        "endpoint": "pilot/orchestrator", "host": "claude-code", "session": successor, "outgoing_stopped": True,
        "briefs": [{"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}]}))
    second = setup.add_role("pilot/orchestrator", session=successor, cwd=str(setup.tmp))
    assert second["generation"] == 2 and second["connection"] != first["connection"]
    assert Path(first["connection"]).exists() and Path(second["connection"]).exists()
    assert "--generation" in json.loads(Path(second["connection"]).read_text())["mcpServers"]["aegis_mailbox"]["args"]
    assert start_connection(second["connection"]) == MAILBOX_TOOLS | {"workspace_capacity", "workspace_initiative"}


@pytest.mark.parametrize("endpoint,host,changes,error", [
    ("pilot/lane/none", "claude-code", {}, "unknown endpoint"),
    ("pilot/orchestrator", "gemini", {}, "unsupported host"),
    ("pilot/orchestrator", "claude-code", {"session": "not-a-uuid"}, "claude sessions need a UUID"),
    ("pilot/orchestrator", "claude-code", {"cwd": "relative"}, "path must be absolute"),
    ("pilot/orchestrator", "claude-code", {"cwd": "/no/such/directory"}, "cwd is not a directory"),
    ("pilot/orchestrator", "claude-code", {"tools": "Read,Bash"}, "unsupported tool: Bash"),
    ("pilot/orchestrator", "claude-code", {"add_dirs": ["relative"]}, "path must be absolute"),
    ("pilot/orchestrator", "claude-code", {"timeout_seconds": 0}, "invalid timeout_seconds"),
    ("pilot/orchestrator", "claude-code", {"assistants": "yes"}, "invalid assistants"),
    ("pilot/orchestrator", "claude-code", {"run": "x"}, "unexpected fields"),
])
def test_malformed_roles_are_refused_and_bind_nothing(setup, endpoint, host, changes, error):
    request = {"cwd": str(setup.tmp), **changes}
    refused = setup.add_role(endpoint, host, expect=2, **request)
    assert error in refused["error"]
    assert invoke(setup.root, "status")["bindings"]["pilot/orchestrator"] is None


def test_assistants_are_off_by_default_and_never_offered_on_codex(setup):
    plain = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    argv = json.loads(Path(plain["wake_profile"]).read_text())["argv"]
    assert "--agents" not in argv and not any("Agent" in word for word in argv)
    refused = setup.add_role("pilot/lane/f2", "codex-cli", session="abc", cwd=str(setup.source), assistants=True, expect=2)
    assert refused["error"] == "codex assistants stay off until a live probe"


@pytest.mark.parametrize("endpoint,catalog", [
    ("pilot/front-door", "assistants-front-door.json"), ("pilot/orchestrator", "assistants-orchestrator.json"),
    ("pilot/lane/f2", "assistants-builder.json"), ("pilot/lane/integration", "assistants-builder.json"),
    ("pilot/lane/review", "assistants-reviewer.json"),
])
def test_claude_assistants_are_limited_to_the_roles_own_list(setup, endpoint, catalog):
    role = setup.add_role(endpoint, cwd=str(setup.tmp), assistants=True)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[:3] == ["env", "CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH=1", "CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS=2"]
    assert argv[argv.index("--agents") + 1].endswith(catalog)
    tools = next(word for word in argv if word.startswith("--tools="))
    assert tools.split("=")[1].split(",")[-1] == "Agent"
    denied = argv[argv.index("--disallowedTools") + 1]
    assert "Agent(general-purpose)" in denied and "Agent(Explore)" in denied
    assert role["assistants"] == "enabled; using them needs the owner's go-ahead and a live probe"


def test_the_codex_start_command_matches_the_real_startup(setup):
    path = setup.tmp / "start.json"
    path.write_text(json.dumps({"base": str(setup.base), "endpoint": "pilot/orchestrator", "cwd": str(setup.source)}))
    result = subprocess.run([sys.executable, "-I", str(PROVISION), "codex-start", "--request", str(path)], capture_output=True,
                            text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    argv = json.loads(result.stdout)["start_argv"]
    assert "resume" not in argv and codex_config(argv)["mcp_servers"] == {}
    assert argv[argv.index("-C") + 1] == str(setup.source) and argv[argv.index("--sandbox") + 1] == "read-only"
    assert json.loads(result.stdout)["prompt_via"] == "argv"
    assert HELPER.exists()


CODEX_SESSION = "01a19969-41df-7631-8ecd-57add111e96b"


def write_team(setup, **team):
    (setup.base / "team.json").write_text(json.dumps(team), encoding="utf-8")


def flag(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


def codex_start(setup, expect=0, **changes):
    return provision("codex-start", setup.request(base=str(setup.base), endpoint="pilot/orchestrator",
                                                  cwd=str(setup.source), **changes), expect=expect)


def test_a_claude_role_takes_model_and_reasoning_from_team_config(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="max")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    for argv in (json.loads(Path(role["wake_profile"]).read_text())["argv"], role["start_argv"]):
        assert flag(argv, "--model") == "claude-opus-5-5" and flag(argv, "--effort") == "max"
        assert "--settings" not in argv
    assert role["team"] == {"model": "claude-opus-5-5", "effort": "max", "reasoning": "max",
                            "model_from": "team.json", "effort_from": "team.json", "reasoning_from": "default"}


def test_request_values_win_over_team_config(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="max")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), model="claude-sonnet-5-5")
    assert flag(role["start_argv"], "--model") == "claude-sonnet-5-5" and flag(role["start_argv"], "--effort") == "max"
    assert role["team"]["model_from"] == "request" and role["team"]["effort_from"] == "team.json"
    explicit = setup.add_role("pilot/lane/review", cwd=str(setup.tmp), model="claude-haiku-5-5", effort="low")
    assert flag(explicit["start_argv"], "--effort") == "low" and "team" not in explicit


def test_ultra_reasoning_runs_claude_at_max_effort_with_ultracode(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="ultra")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), background=True)
    for argv in (json.loads(Path(role["wake_profile"]).read_text())["argv"], role["start_argv"]):
        assert flag(argv, "--effort") == "max" and json.loads(flag(argv, "--settings")) == {"ultracode": True}
        assert argv[-1] == "--", "the settings stay before the end of options"
    assert role["team"]["reasoning"] == "ultra" and role["team"]["effort"] == "max"


def test_a_codex_role_maps_team_reasoning_and_records_the_ultra_downgrade(setup):
    write_team(setup, model="gpt-5.5-codex", reasoning="ultra")
    role = setup.add_role("pilot/lane/f2", "codex-cli", session=CODEX_SESSION, cwd=str(setup.source))
    settings = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])
    assert settings["model"] == "gpt-5.5-codex" and settings["model_reasoning_effort"] == "max"
    assert role["team"]["reasoning"] == "ultra" and role["team"]["effort"] == "max"
    assert "no ultracode" in role["team"]["downgrade"]


def test_codex_start_takes_team_config_too(setup):
    write_team(setup, model="gpt-5.5-codex", reasoning="high")
    started = codex_start(setup)
    settings = codex_config(started["start_argv"])
    assert settings["model"] == "gpt-5.5-codex" and settings["model_reasoning_effort"] == "high"
    assert started["team"] == {"model": "gpt-5.5-codex", "effort": "high", "reasoning": "high",
                               "model_from": "team.json", "effort_from": "team.json", "reasoning_from": "default"}


@pytest.mark.parametrize("team,host,error", [
    ({"model": "claude-opus-5-5", "reasoning": "turbo"}, "claude-code", "unknown reasoning level in team.json: turbo"),
    ({"model": "claude-opus-5-5", "reasoning": "max"}, "codex-cli", "team.json model claude-opus-5-5 needs host claude-code"),
    ({"model": "gpt-5.5-codex", "reasoning": "max"}, "claude-code", "team.json model gpt-5.5-codex needs host codex-cli"),
    ({"model": "claude-opus-5-5"}, "claude-code", "missing"),
    ({"model": "claude-opus-5-5", "reasoning": "max", "effort": "low"}, "claude-code", "unexpected"),
])
def test_a_bad_team_config_is_refused_before_anything_binds(setup, team, host, error):
    write_team(setup, **team)
    changes = {"session": CODEX_SESSION, "cwd": str(setup.source)} if host == "codex-cli" else {"cwd": str(setup.tmp)}
    endpoint = "pilot/lane/f2" if host == "codex-cli" else "pilot/orchestrator"
    result = setup.add_role(endpoint, host, expect=2, **changes)
    assert error in result["error"], result
    assert not list((setup.base / "profiles").glob("*.wake.json")) if (setup.base / "profiles").exists() else True


def test_codex_start_refuses_a_claude_team_model(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="max")
    assert "needs host claude-code" in codex_start(setup, expect=2)["error"]


def test_a_request_model_for_another_host_still_takes_the_team_reasoning(setup):
    # The team's model is not used, so its host does not bind this role; its reasoning still does (review r2 R1).
    write_team(setup, model="claude-opus-5-5", reasoning="high")
    role = setup.add_role("pilot/lane/f2", "codex-cli", session=CODEX_SESSION, cwd=str(setup.source),
                          model="gpt-5.5-codex")
    settings = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])
    assert settings["model"] == "gpt-5.5-codex" and settings["model_reasoning_effort"] == "high"
    assert role["team"]["model_from"] == "request" and role["team"]["effort_from"] == "team.json"


def test_a_full_request_does_not_read_team_config(setup):
    (setup.base / "team.json").write_text("not json", encoding="utf-8")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), model="claude-opus-5-5", effort="high")
    assert flag(role["start_argv"], "--effort") == "high" and "team" not in role


def test_no_team_config_keeps_the_host_defaults(setup):
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    assert "--model" not in role["start_argv"] and "--effort" not in role["start_argv"] and "team" not in role


BY_KIND = {"model": "claude-opus-5-5", "reasoning": "max", "reasoning_by_kind": {"implementer": "xhigh"}}


@pytest.mark.parametrize("endpoint,effort,source", [
    ("pilot/lane/f2", "xhigh", "kind"),
    ("pilot/lane/review", "max", "default"),
    ("pilot/orchestrator", "max", "default"),
])
def test_team_reasoning_can_differ_by_role_kind(setup, endpoint, effort, source):
    write_team(setup, **BY_KIND)
    role = setup.add_role(endpoint, cwd=str(setup.tmp))
    assert flag(role["start_argv"], "--effort") == effort
    assert role["team"]["reasoning"] == effort and role["team"]["reasoning_from"] == source


def test_an_explicit_effort_wins_over_the_role_kind_map(setup):
    write_team(setup, **BY_KIND)
    role = setup.add_role("pilot/lane/f2", cwd=str(setup.tmp), effort="low")
    assert flag(role["start_argv"], "--effort") == "low"
    assert role["team"]["reasoning_from"] == "request" and role["team"]["model_from"] == "team.json"


def test_codex_start_uses_the_orchestrator_entry_of_the_role_kind_map(setup):
    write_team(setup, model="gpt-5.5-codex", reasoning="max", reasoning_by_kind={"orchestrator": "high"})
    started = codex_start(setup)
    assert codex_config(started["start_argv"])["model_reasoning_effort"] == "high"
    assert started["team"]["reasoning_from"] == "kind"


@pytest.mark.parametrize("by_kind,error", [
    ({"implementer": "turbo"}, "unknown reasoning level in team.json: turbo"),
    ({"implementor": "xhigh"}, "unknown role kind in team.json reasoning_by_kind: implementor"),
    (["xhigh"], "invalid team.json reasoning_by_kind"),
])
def test_a_bad_role_kind_map_is_refused(setup, by_kind, error):
    write_team(setup, model="claude-opus-5-5", reasoning="max", reasoning_by_kind=by_kind)
    result = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), expect=2)
    assert error in result["error"], result


# Lifecycle connections, the Router's tier and the Codex profile record (M1 item 4)


ROOT_SESSION = "root-session-1"
REVIEW_SESSION = "01a19a29-d635-7411-8529-9efedafc0885"
NO_LIFECYCLE = "the %s role has no lifecycle connection"
PAIR = "lifecycle and actor must be given together"
ROUTER_ACTOR = "the router session takes no lifecycle actor; routing is the router tool's"


@pytest.fixture
def team(tmp_path, source_seed):
    """A provisioned initiative with a Router and a Decider, and a lifecycle journal whose policy has both."""
    from tests.integration.test_hierarchy_decider import Decider
    built = Setup(tmp_path, source_seed=source_seed)
    provision("init", built.init_request(roles=["router", "decider"]))
    (tmp_path / "journal").mkdir()
    built.ledger = Decider(tmp_path / "journal")
    built.lifecycle = str(built.ledger.path)
    return built


def unbound(setup, endpoint):
    return invoke(setup.root, "status")["bindings"][endpoint] is None


# MR-1: claude_start is a public launcher function, not a provision CLI subcommand.
def mr1_provision(command, request, expect=0):
    if command != "claude-start":
        return provision(command, request, expect=expect)
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_provision
    request.pop("_request_path")
    if expect == 2:
        with pytest.raises(ValueError) as caught:
            hierarchy_provision.claude_start(request)
        return {"error": str(caught.value)}
    return hierarchy_provision.claude_start(request)


# Exercise the JSON entry point in-process where the data-file OS boundary is patched.
@pytest.fixture
def mr1_cli(capsys):
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_provision

    def call(command, request, expect=0):
        if command == "claude-start":
            return mr1_provision(command, request, expect=expect)
        path = Path(request.pop("_request_path"))
        path.write_text(json.dumps(request), encoding="utf-8")
        code = hierarchy_provision.main([command, "--request", str(path)])
        captured = capsys.readouterr()
        assert not captured.err, captured.err
        answer = json.loads(captured.out)
        assert code == expect, answer
        return answer

    return hierarchy_provision, call


def mr1_plan(setup, host="claude-code"):
    (setup.base / "host-plan.json").write_text(json.dumps({
        "schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "pilot", "root": "codex-cli",
        "team": host, "stand_ins": {}, "config_sha256": "ab" * 32}), encoding="utf-8")


def mr1_request(setup, command, endpoint="pilot/orchestrator", host="claude-code", **changes):
    body = {"base": str(setup.base), "endpoint": endpoint, "cwd": str(setup.source)}
    if command == "add-role":
        body.update(host=host, session=CODEX_SESSION if host == "codex-cli" else str(uuid.uuid4()))
    elif command == "claude-start":
        body["session"] = str(uuid.uuid4())
    return setup.request(**dict(body, **changes))


MR1_BAD_EFFORTS = ["bogus", "ultra", "ULTRA", "High", " high", "high\n", "", None, 7, ["high"],
                   "x" * 129, "ｈｉｇｈ", "\x01"]


@pytest.mark.parametrize("command", ["add-role", "codex-start", "claude-start"])
@pytest.mark.parametrize("value", MR1_BAD_EFFORTS)
def test_mr1_request_effort_refusals_leave_endpoint_unbound(setup, command, value):
    shown = ascii(value)
    shown = shown if len(shown) <= 80 else shown[:77] + "..."
    error = ("request effort 'ultra' is a deprecated alias accepted only in team.json; "
             "ask for max, or set team.json reasoning to ultra; allowed request efforts: low, medium, high, xhigh, max"
             if value == "ultra" else
             "invalid request effort %s; choose one of: low, medium, high, xhigh, max" % shown)
    refused = mr1_provision(command, mr1_request(setup, command, model="claude-opus-5-5", effort=value), expect=2)
    assert refused == {"error": error}
    assert refused["error"].isascii() and "\n" not in refused["error"] and "\x01" not in refused["error"]
    assert unbound(setup, "pilot/orchestrator")


def mr1_bindings():
    levels = dict(zip(("light", "standard", "deep", "extended", "max"), ("low", "medium", "high", "xhigh", "max")))
    return {"schema": "aegis.model-bindings/v1", "roles": [
        {"kind": kind, "model_class": "coding", "band": dict(zip(("floor", "default", "ceiling"), band))}
        for kind, band in [("orchestrator", ("light", "standard", "standard")),
                           ("decider", ("light", "standard", "standard")),
                           ("implementer", ("standard", "deep", "max")),
                           ("integrator", ("standard", "deep", "max")),
                           ("reviewer", ("deep", "deep", "max"))]], "hosts": [
        {"host": host, "class": cls, "model": model, "levels": dict(levels),
         "admission": {intent: "unprobed" for intent in levels}}
        for host, models in [("claude-code", ["claude-opus-5-5", "claude-fable-5-1", "claude-sonnet-5-5", "claude-haiku-5-5"]),
                             ("codex-cli", ["gpt-6.1-sol", "gpt-6-astra", "gpt-6.1-terra", "gpt-6-luna"])]
        for cls, model in zip(("coding", "frontier", "scout", "mechanical"), models)]}


@pytest.mark.parametrize("case,problem", [
    ("missing", "cannot read file"), ("json", "invalid JSON"), ("duplicate-key", "duplicate JSON key 'schema'"),
    ("schema", "unsupported schema"), ("top-key", "unexpected top-level keys"),
    ("kind", "unknown role kind 'wizard'"), ("class", "unknown model class 'wizard'"),
    ("intent", "unknown intent 'ultra'"), ("order", "band must satisfy floor <= default <= ceiling"),
    ("native", "unknown native level 'ultra'"), ("duplicate-host", "duplicate host/class row"),
    ("missing-intent", "binding claude-code/coding lacks band ceiling max for implementer"),
    ("role-key", "unexpected role keys"), ("host-key", "unexpected host keys"),
    ("duplicate-role", "duplicate role row"), ("band-key", "unexpected band keys"),
    ("ceiling", "band must satisfy floor <= default <= ceiling"),
    ("duplicate-level", "levels must map to distinct native levels"),
    ("host", "unknown host 'other'"), ("shape", "top-level must be an object"),
    ("roles-shape", "roles must be a list"), ("hosts-shape", "hosts must be a list"),
    ("model-type", "model must be a nonempty ASCII identifier"),
    ("admission-type", "admission must map exactly supported intents"),
    ("missing-coding", "missing host/class rows: claude-code/coding"),
    ("missing-codex-coding", "missing host/class rows: codex-cli/coding"),
    ("duplicate-model", "duplicate host/model row: claude-code/claude-opus-5-5"),
    ("missing-orchestrator", "missing role kinds: orchestrator"),
    ("missing-decider", "missing role kinds: decider"),
    ("missing-implementer", "missing role kinds: implementer"),
    ("missing-integrator", "missing role kinds: integrator"),
    ("missing-reviewer", "missing role kinds: reviewer"),
    ("empty-roles", "missing role kinds: decider, implementer, integrator, orchestrator, reviewer"),
    ("missing-scout", "missing host/class rows: codex-cli/scout"),
])
def test_mr1_broken_bindings_refuse_before_binding(setup, mr1_cli, monkeypatch, case, problem):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    if case == "schema":
        data["schema"] = "v2"
    elif case == "top-key":
        data["extra"] = True
    elif case == "kind":
        data["roles"][0]["kind"] = "wizard"
    elif case == "class":
        data["hosts"][0]["class"] = "wizard"
    elif case == "intent":
        data["roles"][0]["band"]["floor"] = "ultra"
    elif case == "order":
        data["roles"][0]["band"]["floor"] = "deep"
    elif case == "native":
        data["hosts"][0]["levels"]["max"] = "ultra"
    elif case == "duplicate-host":
        data["hosts"].append(data["hosts"][0])
    elif case == "missing-intent":
        del data["hosts"][0]["levels"]["max"]
        del data["hosts"][0]["admission"]["max"]
    elif case == "role-key":
        data["roles"][0]["extra"] = True
    elif case == "host-key":
        data["hosts"][0]["extra"] = True
    elif case == "duplicate-role":
        data["roles"].append(data["roles"][0])
    elif case == "band-key":
        data["roles"][0]["band"]["extra"] = True
    elif case == "ceiling":
        data["roles"][0]["band"]["ceiling"] = "light"
    elif case == "duplicate-level":
        data["hosts"][0]["levels"]["max"] = "high"
    elif case == "host":
        data["hosts"][0]["host"] = "other"
    elif case == "shape":
        data = []
    elif case == "roles-shape":
        data["roles"] = {}
    elif case == "hosts-shape":
        data["hosts"] = {}
    elif case == "model-type":
        data["hosts"][0]["model"] = ["bad"]
    elif case == "admission-type":
        data["hosts"][0]["admission"] = None
    elif case == "missing-coding":
        data["hosts"].pop(0)
    elif case == "missing-codex-coding":
        data["hosts"] = [row for row in data["hosts"] if (row["host"], row["class"]) != ("codex-cli", "coding")]
    elif case == "duplicate-model":
        data["hosts"][1]["model"] = data["hosts"][0]["model"]
    elif case.startswith("missing-") and case[8:] in {row["kind"] for row in data["roles"]}:
        data["roles"] = [row for row in data["roles"] if row["kind"] != case[8:]]
    elif case == "empty-roles":
        data["roles"] = []
    elif case == "missing-scout":
        data["roles"][0]["model_class"] = "scout"
        data["hosts"] = [row for row in data["hosts"] if (row["host"], row["class"]) != ("codex-cli", "scout")]
    path = setup.tmp / "model-bindings.json"
    if case != "missing":
        raw = "{" if case == "json" else '{"schema":1,"schema":2}' if case == "duplicate-key" else json.dumps(data)
        path.write_text(raw, encoding="utf-8")
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    refused = call("add-role", mr1_request(setup, "add-role", model="claude-opus-5-5", effort="medium"), expect=2)
    assert refused == {"error": "invalid model bindings %s: %s; repair model-bindings.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command", ["add-role", "codex-start", "claude-start"])
@pytest.mark.parametrize("endpoint,effort,intent,band", [
    ("pilot/orchestrator", "high", "deep", "light..standard"),
    ("pilot/lane/review", "medium", "standard", "deep..max"),
    ("pilot/lane/f2", "low", "light", "standard..max"),
    ("pilot/lane/integration", "low", "light", "standard..max"),
])
def test_mr1_plan_bands_check_explicit_requests_before_binding(setup, command, endpoint, effort, intent, band):
    host = "codex-cli" if command == "codex-start" else "claude-code"
    model = "gpt-6.1-sol" if host == "codex-cli" else "claude-opus-5-5"
    mr1_plan(setup, host)
    kind = {"f2": "implementer", "review": "reviewer", "integration": "integrator"}.get(endpoint.split("/")[-1], "orchestrator")
    refused = mr1_provision(command, mr1_request(setup, command, endpoint, host, model=model, effort=effort), expect=2)
    assert refused == {"error": "%s effort %s maps to intent %s outside band %s; choose an effort within the band" %
                       (kind, effort, intent, band)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("by_kind", [False, True])
def test_mr1_plan_refuses_team_ultra_above_orchestrator_band(setup, by_kind):
    mr1_plan(setup)
    write_team(setup, model="claude-opus-5-5", reasoning="medium" if by_kind else "ultra",
               **({"reasoning_by_kind": {"orchestrator": "ultra"}} if by_kind else {}))
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2)
    assert refused == {"error": "orchestrator effort max maps to intent max outside band light..standard; "
                       "choose an effort within the band" +
                       ("; set team.json reasoning_by_kind.orchestrator to an in-band effort" if not by_kind else "")}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("host,model", [("claude-code", "claude-opus-5-5"), ("codex-cli", "gpt-6.1-sol")])
@pytest.mark.parametrize("endpoint,effort,intent,band", [
    ("pilot/orchestrator", "low", "light", ("light", "standard", "standard")),
    ("pilot/lane/f2", "medium", "standard", ("standard", "deep", "max")),
    ("pilot/lane/integration", "xhigh", "extended", ("standard", "deep", "max")),
    ("pilot/lane/review", "high", "deep", ("deep", "deep", "max")),
    ("pilot/lane/review", "max", "max", ("deep", "deep", "max")),
])
def test_mr1_in_band_requests_record_provenance(setup, host, model, endpoint, effort, intent, band):
    mr1_plan(setup, host)
    answer = provision("add-role", mr1_request(setup, "add-role", endpoint, host, model=model, effort=effort))
    assert answer["team"] == {"model": model, "effort": effort, "reasoning": effort, "model_from": "request",
                              "effort_from": "request", "reasoning_from": "request", "model_class": "coding",
                              "intent": intent, "band": dict(zip(("floor", "default", "ceiling"), band)),
                              "bindings_sha256": hashlib.sha256((ROOT / "tools/hierarchy_templates/model-bindings.json").read_bytes()).hexdigest(),
                              "admission": "unprobed"}


@pytest.mark.parametrize("host,model", [("claude-code", "claude-opus-5-5"), ("codex-cli", "gpt-6.1-sol")])
def test_mr1_team_ultra_keeps_argv_and_records_deprecation_under_plan(setup, host, model):
    write_team(setup, model=model, reasoning="ultra")
    command = "claude-start" if host == "claude-code" else "codex-start"
    request = mr1_request(setup, command, "pilot/lane/f2", host)
    before = mr1_provision(command, dict(request))
    mr1_plan(setup, host)
    after = mr1_provision(command, dict(request))
    assert after["start_argv"] == before["start_argv"]
    assert after["team"]["deprecated"] == "ultra" and after["team"]["intent"] == "max"
    assert {key: after["team"][key] for key in before["team"]} == before["team"]


@pytest.mark.parametrize("model,error", [
    ("unknown", "model unknown is not bound for host claude-code; choose a model bound in model-bindings.json"),
    ("gpt-6.1-sol", "team.json model gpt-6.1-sol needs host codex-cli, not claude-code"),
    ("bad\nｘ", "model 'bad\\n\\uff58' is not bound for host claude-code; choose a model bound in model-bindings.json"),
])
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_plan_refuses_models_outside_host_bindings(setup, source, model, error):
    mr1_plan(setup)
    write_team(setup, model=model, reasoning="medium")
    changes = {"model": model, "effort": "medium"} if source == "request" else {}
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2, **changes)
    if error.startswith("model "):
        error = source + " " + error
    if source == "request":
        error = error.replace("team.json model ", "request model ")
    assert refused == {"error": error}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command", ["add-role", "codex-start", "claude-start"])
def test_mr1_planless_does_not_open_bindings_and_preserves_answers(setup, mr1_cli, monkeypatch, command):
    module, call = mr1_cli
    request = mr1_request(setup, command, model="gpt-5.5-codex" if command == "codex-start" else "claude-opus-5-5",
                          effort="high")
    before = call(command, dict(request))
    garbage = setup.tmp / "garbage.json"
    garbage.write_text("not JSON", encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", garbage, raising=False)
    original = Path.open

    def open_file(path, *args, **kwargs):
        assert path != garbage, "plan-less provision must never open the bindings file"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)
    assert call(command, dict(request)) == before
    assert "team" not in before


@pytest.mark.parametrize("endpoint", ["pilot/orchestrator", "pilot/lane/f2", "pilot/lane/integration", "pilot/lane/review"])
def test_mr1_shipped_defaults_have_identical_argv_with_and_without_plan(setup, endpoint):
    defaults = json.loads((ROOT / "tools/hierarchy_templates/team-run.json").read_text())["team"]
    write_team(setup, **defaults)
    request = mr1_request(setup, "codex-start", endpoint, "codex-cli")
    before = provision("codex-start", dict(request))
    mr1_plan(setup, "codex-cli")
    after = provision("codex-start", dict(request))
    assert after["start_argv"] == before["start_argv"]
    assert after["codex_profile"] == before["codex_profile"]
    assert after["team"]["model_class"] == "coding"
    assert {key: after["team"][key] for key in before["team"]} == before["team"]


def test_mr1_binding_bytes_and_generic_rows_drive_resolution(setup, mr1_cli, monkeypatch):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    data["hosts"][0]["model"] = "custom-code"
    data["hosts"][0]["levels"].update(standard="high", deep="medium")
    path = setup.tmp / "recalibrated.json"
    raw = (json.dumps(data, indent=3) + "\n\n").encode("utf-8")
    path.write_bytes(raw)
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    answer = call("add-role", mr1_request(setup, "add-role", model="custom-code", effort="high"))
    assert flag(answer["start_argv"], "--model") == "custom-code"
    assert flag(answer["start_argv"], "--effort") == "high"
    assert answer["team"]["intent"] == "standard"
    assert answer["team"]["bindings_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("value,shown", [(None, "None"), (["high"], "['high']"),
                                         ("ｈｉｇｈ", "'\\uff48\\uff49\\uff47\\uff48'"), ("high\n", "'high\\n'")])
def test_mr1_bad_team_reasoning_has_safe_refusal_before_binding(setup, value, shown):
    mr1_plan(setup)
    write_team(setup, model="claude-opus-5-5", reasoning=value)
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2)
    assert refused == {"error": "unknown reasoning level in team.json: " + shown}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("endpoint,effort", [("pilot/front-door", "max"), ("pilot/router", "medium")])
@pytest.mark.parametrize("model", ["claude-opus-5-5", "unbound-model"])
def test_mr1_unbanded_roles_require_a_bound_model_and_keep_effort(team, endpoint, effort, model):
    mr1_plan(team)
    request = mr1_request(team, "add-role", endpoint, model=model, effort=effort)
    if model == "unbound-model":
        refused = provision("add-role", request, expect=2)
        assert refused == {"error": "request model unbound-model is not bound for host claude-code; "
                           "choose a model bound in model-bindings.json"}
        assert unbound(team, endpoint)
    else:
        answer = provision("add-role", request)
        assert flag(answer["start_argv"], "--effort") == effort
        assert answer["team"]["model_class"] == "coding" and answer["team"]["band"] is None


@pytest.mark.parametrize("effort", ["low", "medium", "high"])
def test_mr1_decider_uses_coordination_band(team, effort):
    mr1_plan(team)
    request = mr1_request(team, "add-role", "pilot/decider", model="claude-opus-5-5", effort=effort)
    if effort == "high":
        refused = provision("add-role", request, expect=2)
        assert refused == {"error": "decider effort high maps to intent deep outside band light..standard; "
                           "choose an effort within the band"}
        assert unbound(team, "pilot/decider")
    else:
        answer = provision("add-role", request)
        assert answer["team"]["band"] == {"floor": "light", "default": "standard", "ceiling": "standard"}


@pytest.mark.parametrize("raw", ['{"model":"claude-opus-5-5","reasoning":"medium","bad\\nｘ":0}',
                                '{"model":"claude-opus-5-5","reasoning":"medium","bad\\nｘ":0,"bad\\nｘ":1}'])
def test_mr1_malformed_team_keys_never_reach_errors_raw(setup, raw):
    mr1_plan(setup)
    (setup.base / "team.json").write_text(raw, encoding="utf-8")
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2)
    assert refused["error"].isascii() and "\n" not in refused["error"]
    assert "\\n" in refused["error"] and "\\uff58" in refused["error"]
    assert unbound(setup, "pilot/orchestrator")


@pytest.fixture
def mr1_r2_setup(tmp_path, source_seed):
    built = Setup(tmp_path, source_seed=source_seed)
    provision("init", built.init_request(roles=["decider", "router"]))
    return built


MR1_R2_ENTRY_POINTS = [("add-role", "claude-code"), ("add-role", "codex-cli"),
                    ("claude-start", "claude-code"), ("codex-start", "codex-cli")]
MR1_R2_BANDED_ROLES = [("orchestrator", "pilot/orchestrator", "medium"), ("decider", "pilot/decider", "medium"),
                    ("implementer", "pilot/lane/f2", "high"), ("integrator", "pilot/lane/integration", "high"),
                    ("reviewer", "pilot/lane/review", "high")]


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,effort", MR1_R2_BANDED_ROLES)
@pytest.mark.parametrize("model_class", ["frontier", "scout", "mechanical"])
@pytest.mark.parametrize("source", ["team.json", "request"])
def test_mr1_r2_every_banded_role_refuses_models_of_other_classes(mr1_r2_setup, mr1_cli, command, host, kind, endpoint,
                                                             effort, model_class, source):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    rows = [row for row in mr1_bindings()["hosts"] if row["host"] == host]
    model = next(row["model"] for row in rows if row["class"] == model_class)
    coding_model = next(row["model"] for row in rows if row["class"] == "coding")
    write_team(setup, model=model if source == "team.json" else coding_model, reasoning=effort)
    changes = {"model": model, "effort": effort} if source == "request" else {}
    refused = call(command, mr1_request(setup, command, endpoint, host, **changes), expect=2)
    assert refused == {"error": "%s model %s has class %s, requires class coding; choose model %s" %
                       (kind, model, model_class, coding_model)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint,effort", [("pilot/root", "max")])
def test_mr1_r2_exempt_roles_keep_exact_answers_even_with_broken_bindings(mr1_r2_setup, mr1_cli, monkeypatch,
                                                                     command, host, endpoint, effort):
    setup = mr1_r2_setup
    module, call = mr1_cli
    request = mr1_request(setup, command, endpoint, host, model="outside-bindings", effort=effort)
    before = call(command, dict(request))
    mr1_plan(setup, host)
    # ROOT follows its own plan host; only the model policy is being tested here.
    plan_path = setup.base / "host-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["root"] = host
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    garbage = setup.tmp / "broken-bindings.json"
    garbage.write_text("not JSON", encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", garbage)
    assert call(command, dict(request)) == before
    assert "team" not in before




def test_mr1_r2_provenance_and_levels_come_from_validated_class_binding(setup, mr1_cli, monkeypatch):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    coding = next(row for row in data["hosts"] if row["host"] == "claude-code" and row["class"] == "coding")
    coding["levels"].update(light="high", deep="low")
    coding["admission"]["deep"] = "admitted"
    path = setup.tmp / "class-bindings.json"
    raw = json.dumps(data, indent=1).encode("utf-8")
    path.write_bytes(raw)
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    answer = call("add-role", mr1_request(setup, "add-role", "pilot/lane/f2", model=coding["model"], effort="low"))
    assert flag(answer["start_argv"], "--effort") == "low"
    assert answer["team"]["model_class"] == "coding" and answer["team"]["intent"] == "deep"
    assert answer["team"]["admission"] == "admitted"
    assert answer["team"]["bindings_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("kind", [None, "unexpected-kind"])
def test_mr1_r2_unknown_policy_kind_never_gets_an_implicit_exemption(setup, mr1_cli, host, kind):
    module, _ = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    plan = module.hierarchy_hosts.governing_plan(setup.base, setup.root, "pilot")
    with pytest.raises(ValueError) as caught:
        module.team_settings(setup.base, host, {"model": model, "effort": "medium"}, kind=kind, plan=plan)
    assert str(caught.value) == "invalid model bindings %s: no role policy for %s; repair model-bindings.json" % (
        setup.source / "tools/hierarchy_templates/model-bindings.json", ascii(kind))
    assert unbound(setup, "pilot/orchestrator")






@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r3_cross_host_model_refusal_names_its_source(setup, mr1_cli, command, host, source):
    _, call = mr1_cli
    mr1_plan(setup, host)
    own = next(row for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    other = next(row for row in mr1_bindings()["hosts"] if row["host"] != host and row["class"] == "coding")
    write_team(setup, model=other["model"] if source == "team.json" else own["model"], reasoning="medium")
    changes = {"model": other["model"], "effort": "medium"} if source == "request" else {}
    refused = call(command, mr1_request(setup, command, host=host, **changes), expect=2)
    assert refused == {"error": "%s model %s needs host %s, not %s" % (source, other["model"], other["host"], host)}
    assert unbound(setup, "pilot/orchestrator")


def test_mr1_r3_exemptions_equal_registry_endpoints_without_team_policy(mr1_cli):
    module, _ = mr1_cli
    roles = json.loads((ROOT / "tools/hierarchy_templates/role-registry.json").read_text(encoding="utf-8"))["roles"]
    assert roles["root"]["provision"]["team_kind"] is False
    assert set(module.MODEL_POLICY_EXEMPT_ROLES) == {"root"}


@pytest.mark.parametrize("copied_base", [False, True])
def test_mr1_r7_direct_resolver_discovers_the_governing_plan(setup, mr1_cli, tmp_path_factory, copied_base):
    module, _ = mr1_cli
    mr1_plan(setup, "codex-cli")
    write_team(setup, model="gpt-6.1-sol", reasoning="high")
    base = mr1_r4_copy_base(setup, tmp_path_factory) if copied_base else setup.base
    with pytest.raises(ValueError) as caught:
        module.team_settings(base, "codex-cli", {}, "orchestrator")
    assert str(caught.value) == ("orchestrator effort high maps to intent deep outside band light..standard; "
                                 "choose an effort within the band; set team.json reasoning_by_kind.orchestrator "
                                 "to an in-band effort")
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("planned", [False, True])
def test_mr1_r7_direct_resolver_refuses_request_ultra_before_full_request_return(setup, mr1_cli, planned):
    module, _ = mr1_cli
    if planned:
        mr1_plan(setup, "codex-cli")
    with pytest.raises(ValueError) as caught:
        module.team_settings(setup.base, "codex-cli", {"model": "gpt-6.1-sol", "effort": "ultra"}, "orchestrator")
    assert str(caught.value) == ("request effort 'ultra' is a deprecated alias accepted only in team.json; "
                                 "ask for max, or set team.json reasoning to ultra; allowed request efforts: "
                                 "low, medium, high, xhigh, max")
    assert unbound(setup, "pilot/orchestrator")


def test_mr1_r7_explicit_no_plan_preserves_planless_resolution(setup, mr1_cli, monkeypatch):
    module, _ = mr1_cli
    mr1_plan(setup, "codex-cli")
    monkeypatch.setattr(module, "MODEL_BINDINGS", setup.tmp / (uuid.uuid4().hex + ".garbage"))
    request = {"model": "gpt-6.1-sol", "effort": "high"}
    assert module.team_settings(setup.base, "codex-cli", request, "orchestrator", plan=None) == (request, None)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint", ["pilot/router", "pilot/front-door"])
def test_mr1_r7_unbanded_host_defaults_still_validate_bindings(mr1_r2_setup, mr1_cli, monkeypatch,
                                                            command, host, endpoint):
    setup = mr1_r2_setup
    module, call = mr1_cli
    mr1_plan(setup, host)
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    path.write_text("not JSON", encoding="utf-8")
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    refused = call(command, mr1_request(setup, command, endpoint, host), expect=2)
    assert refused == {"error": "invalid model bindings %s: invalid JSON; repair model-bindings.json" % path}
    assert unbound(setup, endpoint)


def test_mr1_r7_team_up_preflights_all_profiles_before_starting_router(tmp_path, monkeypatch):
    from tests.integration.test_hierarchy_team import Run
    run = Run(tmp_path, monkeypatch)
    run.config["team"] = {"model": "gpt-6.1-sol", "reasoning": "high"}
    run.save()
    run.team("init")
    assert (run.base_dir / "host-plan.json").is_file()
    before = run.host_log.read_bytes() if run.host_log.exists() else b""
    bindings_before = run.mailbox().status()["bindings"]
    assert bindings_before["pilot/router"] is None
    refused = run.team("up", "--no-loop", expect=2)
    assert refused == {"error": "orchestrator effort high maps to intent deep outside band light..standard; "
                       "choose an effort within the band; set team.json reasoning_by_kind.orchestrator to an in-band effort"}
    assert run.mailbox().status()["bindings"] == bindings_before
    assert run.mailbox().status()["bindings"]["pilot/router"] is None
    assert (run.host_log.read_bytes() if run.host_log.exists() else b"") == before
    assert not list((run.base_dir / "launches").glob("**/*.json"))
    assert not (run.run / "loop.pid").exists()


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint", ["pilot/router", "pilot/front-door"])
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r7_unbanded_roles_refuse_cross_host_models(mr1_r2_setup, mr1_cli, command, host, endpoint, source):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    other = next(row for row in mr1_bindings()["hosts"] if row["host"] != host and row["class"] == "coding")
    options = {"effort": "max"} if endpoint.endswith("front-door") else {}
    if source == "request":
        options["model"] = other["model"]
    else:
        write_team(setup, model=other["model"], reasoning="max")
    refused = call(command, mr1_request(setup, command, endpoint, host, **options), expect=2)
    assert refused == {"error": "%s model %s needs host %s, not %s" % (source, other["model"], other["host"], host)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint", ["pilot/router", "pilot/front-door"])
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r7_unbanded_roles_refuse_frontier_seats(mr1_r2_setup, mr1_cli, command, host, endpoint, source):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "frontier")
    options = {"effort": "max"} if endpoint.endswith("front-door") else {}
    if source == "request":
        options["model"] = model
    else:
        write_team(setup, model=model, reasoning="medium")
    refused = call(command, mr1_request(setup, command, endpoint, host, **options), expect=2)
    assert refused == {"error": "%s model %s has class frontier; frontier models are only for isolated turns, "
                       "not long-lived seats" % (endpoint.split("/")[-1], model)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint", ["pilot/router", "pilot/front-door"])
def test_mr1_r7_unbanded_resolution_uses_rows_instead_of_model_prefixes(mr1_r2_setup, mr1_cli, monkeypatch,
                                                                   command, host, endpoint):
    setup = mr1_r2_setup
    module, call = mr1_cli
    mr1_plan(setup, host)
    data = mr1_bindings()
    coding = next(row for row in data["hosts"] if row["host"] == host and row["class"] == "coding")
    coding["model"] = "custom-code"
    coding["levels"].update(standard="high", deep="medium")
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    raw = json.dumps(data).encode("utf-8")
    path.write_bytes(raw)
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    write_team(setup, model="custom-code", reasoning="max")
    answer = call(command, mr1_request(setup, command, endpoint, host))
    argv = json.loads(Path(answer["wake_profile"]).read_text())["argv"] if command == "add-role" else answer["start_argv"]
    assert "custom-code" in " ".join(argv)
    assert answer["team"]["model_class"] == "coding" and answer["team"]["band"] is None
    assert answer["team"]["intent"] == ("deep" if endpoint.endswith("router") else "max")
    assert answer["team"]["bindings_sha256"] == hashlib.sha256(raw).hexdigest()
    if endpoint.endswith("router"):
        assert answer["model_profile"]["effort"] == "medium"
        assert answer["model_profile"]["tier"] == "ultrafast"


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("shape,error", [("empty", "missing fields: model, reasoning"),
                                         ("model-only", "missing fields: reasoning"),
                                         ("reasoning-only", "missing fields: model")])
def test_mr1_r3_present_incomplete_team_file_is_never_host_defaults(setup, mr1_cli, command, host, shape, error):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    team = {"model": model} if shape == "model-only" else {"reasoning": "medium"} if shape == "reasoning-only" else {}
    write_team(setup, **team)
    refused = call(command, mr1_request(setup, command, host=host), expect=2)
    assert refused == {"error": error}
    assert unbound(setup, "pilot/orchestrator")


def mr1_r4_copy_base(setup, tmp_path_factory):
    copied = tmp_path_factory.mktemp("mr1-copy-" + uuid.uuid4().hex)
    for name in ("provision.json", "runtime-source.py"):
        shutil.copyfile(setup.base / name, copied / name)
    return copied


def mr1_r4_request(setup, copied, command, host, **changes):
    request = mr1_request(setup, command, host=host, **changes)
    request["base"] = str(copied)
    if command in ("add-role", "claude-start"):
        request["session"] = str(uuid.uuid4())
    return request


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("case", ["out-of-band", "malformed", "differing", "format-only", "copy-only"])
def test_mr1_r4_copied_base_cannot_replace_canonical_policy(setup, mr1_cli, tmp_path_factory, command, host, case):
    _, call = mr1_cli
    mr1_plan(setup, host)
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    team = {"model": model, "reasoning": "high" if case == "out-of-band" else "medium"}
    if case == "malformed":
        (setup.base / "team.json").write_text("not JSON", encoding="utf-8")
        error = "invalid JSON file %s: invalid JSON; repair team.json" % (setup.base / "team.json")
    elif case == "out-of-band":
        write_team(setup, **team)
        error = ("orchestrator effort high maps to intent deep outside band light..standard; "
                 "choose an effort within the band; set team.json reasoning_by_kind.orchestrator to an in-band effort")
    else:
        if case != "copy-only":
            write_team(setup, **team)
        local = dict(team, reasoning="low") if case == "differing" else team
        (copied / "team.json").write_text(json.dumps(local, indent=3), encoding="utf-8")
        error = "copied base team.json differs from canonical team.json; use the governing mailbox's team.json"
    refused = call(command, mr1_r4_request(setup, copied, command, host), expect=2)
    assert refused == {"error": error}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("copy_team", [False, True])
def test_mr1_r4_copied_base_uses_canonical_resolution_and_provenance(setup, mr1_cli, tmp_path_factory,
                                                                  command, host, copy_team):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model=model, reasoning="max", reasoning_by_kind={"orchestrator": "medium"})
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    if copy_team:
        (copied / "team.json").write_bytes((setup.base / "team.json").read_bytes())
    answer = call(command, mr1_r4_request(setup, copied, command, host))
    assert answer["team"]["model"] == model and answer["team"]["effort"] == "medium"
    assert answer["team"]["reasoning_from"] == "kind" and answer["team"]["intent"] == "standard"
    assert answer["team"]["admission"] == "unprobed"
    argv = json.loads(Path(answer["wake_profile"]).read_text())["argv"] if command == "add-role" else answer["start_argv"]
    if host == "codex-cli":
        assert codex_config(argv)["model"] == model and codex_config(argv)["model_reasoning_effort"] == "medium"
    else:
        assert flag(argv, "--model") == model and flag(argv, "--effort") == "medium"




@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("copied_base", [False, True])
@pytest.mark.parametrize("full_request", [False, True])
@pytest.mark.parametrize("shape", ["invalid-json", "empty-file", "directory", "dangling-symlink"])
def test_mr1_r4_present_canonical_team_is_always_validated(setup, mr1_cli, tmp_path_factory, command, host,
                                                        copied_base, full_request, shape):
    _, call = mr1_cli
    mr1_plan(setup, host)
    path = setup.base / "team.json"
    if shape in ("invalid-json", "empty-file"):
        path.write_text("not JSON" if shape == "invalid-json" else "", encoding="utf-8")
        error = "invalid JSON"
    elif shape == "directory":
        path.mkdir()
        error = "input must be a regular file"
    else:
        target = tmp_path_factory.mktemp("mr1-missing-" + uuid.uuid4().hex) / (uuid.uuid4().hex + ".json")
        path.symlink_to(target)
        error = "symlink paths are not supported: " + str(path)
    base = mr1_r4_copy_base(setup, tmp_path_factory) if copied_base else setup.base
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    options = {"model": model, "effort": "medium"} if full_request else {}
    refused = call(command, mr1_r4_request(setup, base, command, host, **options), expect=2)
    assert refused == {"error": "invalid JSON file %s: %s; repair team.json" % (path, error)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
def test_mr1_r4_full_request_cannot_ignore_conflicting_local_team(setup, mr1_cli, tmp_path_factory, command, host):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model=model, reasoning="medium")
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    (copied / "team.json").write_text("not JSON", encoding="utf-8")
    refused = call(command, mr1_r4_request(setup, copied, command, host, model=model, effort="medium"), expect=2)
    assert refused == {"error": "copied base team.json differs from canonical team.json; use the governing mailbox's team.json"}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r4_unbound_model_message_names_its_source(setup, mr1_cli, command, host, source):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model="unbound-model" if source == "team.json" else model, reasoning="medium")
    options = {"model": "unbound-model", "effort": "medium"} if source == "request" else {}
    refused = call(command, mr1_r4_request(setup, setup.base, command, host, **options), expect=2)
    assert refused == {"error": "%s model unbound-model is not bound for host %s; choose a model bound in model-bindings.json" %
                       (source, host)}
    assert unbound(setup, "pilot/orchestrator")


MR1_R5_BAD_JSON = [
    pytest.param(b'{"unused_probe": 1e9999}', "non-finite JSON is not supported", id="overflow-positive"),
    pytest.param(b'{"unused_probe": -1e9999}', "non-finite JSON is not supported", id="overflow-negative"),
    pytest.param(b'{"unused_probe": 1e400}', "non-finite JSON is not supported", id="overflow-small-exponent"),
    pytest.param(b"[" * 10000, "JSON nesting exceeds supported limit", id="deep-array"),
    pytest.param(b"{" * 10000, "invalid JSON", id="deep-object"),
    pytest.param(b"\xff", "invalid UTF-8 JSON", id="invalid-utf8"),
    pytest.param(b"\xef\xbb\xbf{}", "invalid JSON", id="bom"),
    pytest.param(b"NaN", "non-finite JSON is not supported", id="nan"),
    pytest.param(b"Infinity", "non-finite JSON is not supported", id="infinity"),
    pytest.param(b"-Infinity", "non-finite JSON is not supported", id="negative-infinity"),
    pytest.param(b"9" * 10000, "integer literal exceeds 128 digits", id="huge-integer"),
    pytest.param(b" " * 262145, "input exceeds 262144 bytes", id="oversize"),
]


@pytest.mark.parametrize("token", ["1e9999", "-1e9999", "1e400"])
@pytest.mark.parametrize("location", ["bootstrap-request", "bootstrap-provision", "ordinary-record", "carry-record"])
def test_mr1_r6_overflow_numbers_refuse_at_every_record_boundary(setup, mr1_cli, token, location):
    module, _ = mr1_cli
    request = mr1_r4_request(setup, setup.base, "codex-start", "codex-cli")
    request_path = Path(request.pop("_request_path"))
    request_path.write_text(json.dumps(request), encoding="utf-8")
    path = setup.base / "provision.json"
    if location == "bootstrap-request":
        path = request_path
    elif location == "carry-record":
        path = setup.base / "carried" / "carry.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"old_root": str(setup.root), "endpoints": [], "message_ids": [],
                                    "generations": {}}), encoding="utf-8")
    value = json.loads(path.read_text())
    value["unused_probe"] = "OVERFLOW_TOKEN"
    path.write_text(json.dumps(value).replace('"OVERFLOW_TOKEN"', token), encoding="utf-8")
    expected = "invalid JSON file %s: non-finite JSON is not supported; repair %s" % (path, path.name)
    if location == "ordinary-record":
        with pytest.raises(ValueError) as caught:
            module.codex_start(request)
        assert str(caught.value) == expected
    else:
        command = "carry-check" if location == "carry-record" else "codex-start"
        if location == "carry-record":
            request_path.write_text(json.dumps({"base": str(setup.base)}), encoding="utf-8")
        done = subprocess.run([sys.executable, "-I", str(PROVISION), command, "--request", str(request_path)],
                              capture_output=True, text=True, timeout=10)
        assert not done.stderr
        assert done.returncode == 2, done.stdout
        assert json.loads(done.stdout) == {"error": expected}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO boundary")
def test_mr1_r6_bootstrap_refuses_fifo_without_waiting_for_a_writer(setup):
    path = setup.tmp / ("fifo-" + uuid.uuid4().hex)
    os.mkfifo(path)
    done = subprocess.run([sys.executable, "-I", str(PROVISION), "codex-start", "--request", str(path)],
                          capture_output=True, text=True, timeout=3)
    assert not done.stderr
    assert done.returncode == 2
    assert json.loads(done.stdout) == {"error": "invalid JSON file %s: not a regular file; repair %s" % (path, path.name)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("reader", ["host-plan.json", "mailbox manifest"])
def test_mr1_r6_delegated_deep_json_refuses_before_binding(setup, mr1_cli, command, host, reader):
    _, call = mr1_cli
    mr1_plan(setup, host)
    path = setup.base / "host-plan.json" if reader == "host-plan.json" else setup.root / "manifest.json"
    original = path.read_bytes()
    path.write_bytes(b"[" * 10000)
    try:
        refused = call(command, mr1_r4_request(setup, setup.base, command, host), expect=2)
        assert refused == {"error": "invalid delegated JSON read (%s): JSON nesting exceeds supported limit; repair the input" % reader}
    finally:
        path.write_bytes(original)
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("reader", ["session record", "lifecycle policy"])
def test_mr1_r6_other_delegated_readers_refuse_deep_json(setup, mr1_cli, reader):
    module, call = mr1_cli
    mr1_plan(setup, "codex-cli")
    endpoint = "pilot/orchestrator" if reader == "session record" else "pilot/root"
    options = {"model": "gpt-6.1-sol", "effort": "medium"}
    if reader == "session record":
        path = module.hierarchy_hosts.session_record_path(setup.base, endpoint, 1)
    else:
        journal = setup.tmp / ("journal-" + uuid.uuid4().hex)
        options.update(lifecycle=str(journal), actor="root")
        path = journal / "policy.json"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"[" * 10000)
    refused = call("add-role", mr1_r4_request(setup, setup.base, "add-role", "codex-cli",
                                            endpoint=endpoint, **options), expect=2)
    assert refused == {"error": "invalid delegated JSON read (%s): JSON nesting exceeds supported limit; repair the input" % reader}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_mr1_r6_copied_base_launcher_records_delegated_plan_refusal(tmp_path_factory, host):
    from tests.integration.test_hierarchy_launcher_hosts import Hosts
    launch = Hosts(tmp_path_factory.mktemp("mr1-r6-launch-" + uuid.uuid4().hex))
    launch.init()
    mr1_plan(launch, host)
    (launch.base / "host-plan.json").write_bytes(b"[" * 10000)
    original_root = launch.root
    launch.base = mr1_r4_copy_base(launch, tmp_path_factory)
    refused = launch.start(endpoint="pilot/lane/f2", expect=2)
    assert refused["state"] == "refused"
    assert refused["error"] == "invalid delegated JSON read (host-plan.json): JSON nesting exceeds supported limit; repair the input"
    assert launch.records("pilot/lane/f2") == [refused]
    assert invoke(original_root, "status")["bindings"]["pilot/lane/f2"] is None
    assert not launch.codex_log.exists() and not launch.claude_log.exists()


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("planned", [False, True])
@pytest.mark.parametrize("raw,problem", MR1_R5_BAD_JSON)
def test_mr1_r5_team_parse_failures_are_normal_refusals(setup, mr1_cli, command, host, planned, raw, problem):
    _, call = mr1_cli
    if planned:
        mr1_plan(setup, host)
    path = setup.base / "team.json"
    path.write_bytes(raw)
    refused = call(command, mr1_r4_request(setup, setup.base, command, host), expect=2)
    assert refused == {"error": "invalid JSON file %s: %s; repair team.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("raw,problem", MR1_R5_BAD_JSON)
def test_mr1_r5_bindings_parse_failures_are_normal_refusals(setup, mr1_cli, monkeypatch, command, host, raw, problem):
    module, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model=model, reasoning="medium")
    path = setup.tmp / (uuid.uuid4().hex + "-bindings.json")
    path.write_bytes(raw)
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    refused = call(command, mr1_r4_request(setup, setup.base, command, host), expect=2)
    assert refused == {"error": "invalid model bindings %s: %s; repair model-bindings.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_mr1_r5_launcher_records_deep_team_parse_refusal(tmp_path_factory, host):
    from tests.integration.test_hierarchy_launcher_hosts import Hosts
    launch = Hosts(tmp_path_factory.mktemp("mr1-launch-" + uuid.uuid4().hex))
    launch.init()
    mr1_plan(launch, host)
    path = launch.base / "team.json"
    path.write_bytes(b"[" * 10000)
    refused = launch.start(endpoint="pilot/lane/f2", expect=2)
    assert refused["state"] == "refused"
    assert refused["error"] == "invalid JSON file %s: JSON nesting exceeds supported limit; repair team.json" % path
    assert launch.records("pilot/lane/f2") == [refused]
    assert launch.binding("pilot/lane/f2") is None
    assert not launch.codex_log.exists() and not launch.claude_log.exists()


@pytest.mark.parametrize("case,problem", [
    ("missing-admission", "admission must map exactly supported intents"),
    ("extra-admission", "admission must map exactly supported intents"),
    ("unknown-admission", "unknown admission value 'allowed'"),
    ("typed-admission", "unknown admission value 7"),
    ("empty-levels", "levels must map a nonempty subset of light, standard, deep, extended, max"),
    ("unknown-intent", "levels must map a nonempty subset of light, standard, deep, extended, max"),
    ("missing-default", "binding claude-code/coding lacks band default standard for orchestrator"),
    ("missing-ceiling", "binding claude-code/coding lacks band ceiling max for implementer"),
    ("rejected-default", "binding claude-code/coding has rejected band default standard for orchestrator"),
    ("rejected-ceiling", "binding claude-code/coding has rejected band ceiling max for implementer"),
])
def test_mr1_r5_admission_and_partial_levels_fail_closed(setup, mr1_cli, monkeypatch, case, problem):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    row = data["hosts"][0]
    if case == "missing-admission":
        del row["admission"]["deep"]
    elif case == "extra-admission":
        row["admission"]["other"] = "unprobed"
    elif case == "unknown-admission":
        row["admission"]["standard"] = "allowed"
    elif case == "typed-admission":
        row["admission"]["standard"] = 7
    elif case.startswith("rejected-"):
        row["admission"]["standard" if case == "rejected-default" else "max"] = "rejected"
    elif case == "empty-levels":
        row["levels"] = {}
        row["admission"] = {}
    elif case == "unknown-intent":
        row["levels"]["other"] = "high"
        row["admission"]["other"] = "unprobed"
    else:
        intent = "standard" if case == "missing-default" else "max"
        del row["levels"][intent]
        del row["admission"][intent]
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    refused = call("add-role", mr1_r4_request(setup, setup.base, "add-role", "claude-code",
                                            model="claude-opus-5-5", effort="medium"), expect=2)
    assert refused == {"error": "invalid model bindings %s: %s; repair model-bindings.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("state", ["unprobed", "admitted", "rejected"])
def test_mr1_r5_selected_admission_is_recorded_or_refused(setup, mr1_cli, monkeypatch, command, host, state):
    module, call = mr1_cli
    mr1_plan(setup, host)
    data = mr1_bindings()
    row = next(row for row in data["hosts"] if row["host"] == host and row["class"] == "coding")
    row["admission"]["extended"] = state
    row["admission"]["light"] = "rejected"  # Neither a required default nor ceiling.
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    request = mr1_r4_request(setup, setup.base, command, host, endpoint="pilot/lane/f2",
                             model=row["model"], effort="xhigh")
    answer = call(command, request, expect=2 if state == "rejected" else 0)
    if state == "rejected":
        assert answer == {"error": "%s intent extended (effort xhigh) is rejected for %s; choose a different supported level" %
                          (row["model"], host)}
        assert unbound(setup, "pilot/lane/f2")
    else:
        assert answer["team"]["admission"] == state and answer["team"]["intent"] == "extended"


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("effort", ["low", "medium"])
def test_mr1_r5_partial_binding_accepts_supported_levels_and_names_unsupported_ones(setup, mr1_cli, monkeypatch,
                                                                                command, host, effort):
    module, call = mr1_cli
    mr1_plan(setup, host)
    data = mr1_bindings()
    for row in data["hosts"]:
        intents = ("standard", "deep", "max") if row["class"] == "coding" else ("deep",)
        row["levels"] = {key: row["levels"][key] for key in intents}
        row["admission"] = {key: "unprobed" for key in intents}
    row = next(row for row in data["hosts"] if row["host"] == host and row["class"] == "coding")
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
    answer = call(command, mr1_r4_request(setup, setup.base, command, host, model=row["model"], effort=effort),
                  expect=2 if effort == "low" else 0)
    if effort == "low":
        assert answer == {"error": "orchestrator effort low has no supported intent; supported intents: standard, deep, max; "
                          "choose a supported effort"}
        assert unbound(setup, "pilot/orchestrator")
    else:
        assert answer["team"]["intent"] == "standard" and answer["team"]["effort"] == "medium"


@pytest.mark.parametrize("which", ["team", "bindings"])
def test_mr1_r5_unicode_paths_and_repair_text_survive_refusals(tmp_path_factory, mr1_cli, monkeypatch, which, source_seed):
    module, call = mr1_cli
    folder = tmp_path_factory.mktemp("mr1-unicode-" + uuid.uuid4().hex) / "José"
    folder.mkdir()
    setup = Setup(folder, source_seed=source_seed)
    setup.init()
    mr1_plan(setup)
    if which == "team":
        path = setup.base / "team.json"
        path.write_text('{"bad-ｘ":1,"bad-ｘ":2}', encoding="utf-8")
        error = "invalid JSON file %s: duplicate JSON key 'bad-\\uff58'; repair team.json" % path
    else:
        path = folder / "model-bindings.json"
        data = mr1_bindings()
        data["hosts"][0]["class"] = "ｘ" * 100
        path.write_text(json.dumps(data), encoding="utf-8")
        path = mr1_r9_publish_bindings(setup, path.read_bytes() if path.exists() else None)
        shown = ascii("ｘ" * 100)[:77] + "..."
        error = "invalid model bindings %s: unknown model class %s; repair model-bindings.json" % (path, shown)
    refused = call("add-role", mr1_r4_request(setup, setup.base, "add-role", "claude-code",
                                            model="claude-opus-5-5", effort="medium"), expect=2)
    assert refused == {"error": error}
    assert str(path) in refused["error"] and "José" in refused["error"] and "ｘ" not in refused["error"]
    assert unbound(setup, "pilot/orchestrator")





@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,default", MR1_R2_BANDED_ROLES)
def test_mr1_r2_missing_effort_names_band_default_without_applying_it(mr1_r2_setup, mr1_cli, command, host, kind, endpoint,
                                                                  default):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    refused = call(command, mr1_request(setup, command, endpoint, host, model=model), expect=2)
    intent = "standard" if default == "medium" else "deep"
    assert refused == {"error": "%s has no effort; set %s (intent %s, band default) in request effort or team.json reasoning" %
                       (kind, default, intent)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,effort", MR1_R2_BANDED_ROLES)
def test_mr1_r3_host_defaults_keep_exact_answers_without_policy_provenance(mr1_r2_setup, mr1_cli, monkeypatch,
                                                                        command, host, kind, endpoint, effort):
    setup = mr1_r2_setup
    module, call = mr1_cli
    request = mr1_request(setup, command, endpoint, host)
    before = call(command, dict(request))
    mr1_plan(setup, host)
    garbage = setup.tmp / "unused-bindings.json"
    garbage.write_text("not JSON", encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", garbage)
    after = call(command, dict(request))
    assert after == before
    assert "team" not in after
    argv = json.loads(Path(after["wake_profile"]).read_text())["argv"] if command == "add-role" else after["start_argv"]
    if host == "codex-cli":
        config = codex_config(argv)
        assert "model" not in config and "model_reasoning_effort" not in config
    else:
        assert "--model" not in argv and "--effort" not in argv


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,effort", MR1_R2_BANDED_ROLES)
def test_mr1_r3_effort_without_model_resolves_the_binding(mr1_r2_setup, mr1_cli, command, host,
                                                                   kind, endpoint, effort):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    answer = call(command, mr1_request(setup, command, endpoint, host, effort=effort))
    assert answer["team"]["model"] == model and answer["team"]["model_from"] == "model-bindings.json"
    assert answer["team"]["effort"] == effort and answer["team"]["model_class"] == "coding"


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("planned", [False, True])
def test_mr1_r4_copy_without_any_team_file_keeps_host_defaults(setup, mr1_cli, tmp_path_factory, command, host, planned):
    _, call = mr1_cli
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    request = mr1_r4_request(setup, copied, command, host)
    before = call(command, dict(request))
    if planned:
        mr1_plan(setup, host)
    else:
        # Without a plan only the caller's own team.json applies, as before.
        (setup.base / "team.json").write_text("not JSON", encoding="utf-8")
    assert call(command, dict(request)) == before
    assert "team" not in before


ROOT_TOOLS = ["root_decide", "team_status", "team_pending", "team_request"]
ROOT_READS = "loop_state and evidence are only for ROOT's decision adapter, with its lifecycle and actor"


def root_args(setup, host, session=ROOT_SESSION, actor="root-1", reads=()):
    # ROOT's own entry, which also carries the read-only --loop-state and --evidence the pinned mailbox CLI cannot.
    return ["-I", "-B", str(setup.base / "runtime-source.py"), "--provision", str(setup.base / "provision.json"),
            "--entry", str(setup.source / "tools" / "hierarchy_mailbox_mcp.py"), "--", "--root", str(setup.root), "serve",
            "--endpoint", "pilot/root", "--host", host, "--session", session, "--generation", "1",
            "--lifecycle", setup.lifecycle, "--actor", actor, *reads]


def call_server(definition, calls):
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
    frames += [{"jsonrpc": "2.0", "id": index + 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
               for index, (name, arguments) in enumerate(calls)]
    result = subprocess.run([definition["command"], *definition["args"]], input="".join(json.dumps(f) + "\n" for f in frames),
                            capture_output=True, text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()][1:]


def test_root_with_a_journal_gets_a_decision_connection_that_records_root_decide(team):
    from tests.integration.test_hierarchy_lifecycle import raw_request, request as lifecycle_request
    role = team.add_role("pilot/root", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    assert "wake_profile" not in role and "start_argv" not in role and "mcp_config" not in role
    assert not (team.base / "profiles").exists() or not list((team.base / "profiles").glob("*root*"))
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]
    assert definition == {"command": sys.executable, "args": root_args(team, "claude-code")}
    assert Path(role["connection"]).name == "pilot%2Froot-g1.json"
    assert start_connection(role["connection"], "aegis_decision") == set(ROOT_TOOLS)
    value = lifecycle_request("feature-1")
    team.ledger.publish(value)
    [answer] = call_server(definition, [("root_decide", {
        "event_id": "root-decision-1", "request_id": "feature-1", "request_sha256": raw_request(value)["sha256"],
        "decision": "approve", "reason": "the owner agreed this feature"})])
    assert answer["result"].get("isError") is not True, answer
    assert [(d["request_id"], d["decision"], d["actor"]) for d in team.ledger.status()["decisions"]] == [
        ("feature-1", "approve", "root-1")]


def test_a_codex_root_gets_the_decision_server_inline_and_a_native_root_a_flat_file(team, tmp_path, source_seed):
    tomllib = pytest.importorskip("tomllib", reason="Codex settings are read with tomllib, Python 3.11+")
    role = team.add_role("pilot/root", "codex-cli", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    # ROOT runs with approval_policy "never", so each enabled tool, the read tools too, carries its approve entry.
    assert tomllib.loads(role["mcp_config"]) == {"mcp_servers": {"aegis_decision": {
        "command": sys.executable, "args": root_args(team, "codex-cli"), "required": True,
        "enabled_tools": ROOT_TOOLS, "tools": {name: {"approval_mode": "approve"} for name in ROOT_TOOLS}}}}
    assert json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]["args"] == root_args(team, "codex-cli")
    (tmp_path / "native").mkdir()
    native = Setup(tmp_path / "native", source_seed=source_seed)
    native.init()
    native.lifecycle = team.lifecycle
    flat = native.add_role("pilot/root", "codex", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    assert json.loads(Path(flat["connection"]).read_text()) == {"command": sys.executable, "args": root_args(native, "codex")}
    assert "mcp_config" not in flat


def test_root_without_a_journal_keeps_its_binding_only_answer(team):
    role = team.add_role("pilot/root", session=ROOT_SESSION)
    assert role == {"endpoint": "pilot/root", "host": "claude-code", "session": ROOT_SESSION, "generation": 1}


def test_roots_enabled_tools_are_its_adapters_own_list(team):
    """The Codex allow-list and the adapter's tools/list come from the same registry entry, so neither drifts."""
    tomllib = pytest.importorskip("tomllib", reason="Codex settings are read with tomllib, Python 3.11+")
    role = team.add_role("pilot/root", "codex-cli", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    enabled = tomllib.loads(role["mcp_config"])["mcp_servers"]["aegis_decision"]["enabled_tools"]
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    listed = subprocess.run([definition["command"], *definition["args"]], capture_output=True, text=True, timeout=20,
                            input="".join(json.dumps(f) + "\n" for f in frames),
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert enabled == [tool["name"] for tool in json.loads(listed.stdout.splitlines()[1])["result"]["tools"]]


def test_root_given_the_loop_state_and_evidence_reads_them_through_its_connection(team, tmp_path):
    state_dir, evidence = tmp_path / "loop", tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "init.json").write_text("{}")
    role = team.add_role("pilot/root", "codex-cli", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1",
                         loop_state=str(state_dir), evidence=str(evidence))
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]
    assert definition["args"] == root_args(team, "codex-cli", reads=["--loop-state", str(state_dir),
                                                                     "--evidence", str(evidence)])
    [answer] = call_server(definition, [("team_status", {})])
    status = json.loads(answer["result"]["content"][0]["text"])
    # The loop has not run yet, so its folder has no status file; the evidence folder holds one file.
    assert status["loop"]["state"] == "absent"
    assert (status["evidence"]["present"], status["evidence"]["files"]) == (True, 1)
    assert not state_dir.exists()


@pytest.mark.parametrize("endpoint,changes,error", [
    ("pilot/root", {"loop_state": "<loop>"}, ROOT_READS),
    ("pilot/root", {"evidence": "<loop>"}, ROOT_READS),
    ("pilot/root", {"lifecycle": "<journal>", "actor": "root-1", "loop_state": "relative/loop"},
     "path must be absolute without traversal"),
    ("pilot/root", {"lifecycle": "<journal>", "actor": "root-1", "evidence": 7}, "invalid evidence"),
    ("pilot/root", {"lifecycle": "<journal>", "actor": "root-1", "loop_state": ""}, "invalid loop_state"),
    ("pilot/orchestrator", {"loop_state": "<loop>"}, ROOT_READS),
    ("pilot/decider", {"lifecycle": "<journal>", "actor": "decider-1", "evidence": "<loop>"}, ROOT_READS),
    ("pilot/router", {"lifecycle": "<journal>", "loop_state": "<loop>"}, ROOT_READS),
])
def test_loop_state_and_evidence_go_only_to_roots_decision_adapter(team, endpoint, changes, error):
    swap = {"<journal>": team.lifecycle, "<loop>": str(team.tmp / "loop")}
    changes = {key: swap.get(value, value) if isinstance(value, str) else value for key, value in changes.items()}
    session = ROOT_SESSION if endpoint == "pilot/root" else str(uuid.uuid4())
    refused = team.add_role(endpoint, session=session, cwd=str(team.tmp), expect=2, **changes)
    assert refused["error"] == error
    assert unbound(team, endpoint) and not (team.base / "connections").exists()


@pytest.mark.parametrize("changes,error", [
    ({"lifecycle": "<journal>"}, PAIR),
    ({"actor": "root-1"}, PAIR),
    ({"lifecycle": "<journal>", "actor": "router-1"}, "actor router-1 is not a root actor in the lifecycle policy"),
    ({"lifecycle": "<journal>", "actor": "absent-1"}, "actor absent-1 is not a root actor in the lifecycle policy"),
    ({"lifecycle": "<journal>", "actor": "../root"}, "invalid actor"),
    ({"lifecycle": "relative/journal", "actor": "root-1"}, "path must be absolute without traversal"),
])
def test_root_lifecycle_keys_are_checked_before_binding(team, changes, error):
    changes = {key: team.lifecycle if value == "<journal>" else value for key, value in changes.items()}
    refused = team.add_role("pilot/root", session=ROOT_SESSION, expect=2, **changes)
    assert refused["error"] == error
    assert unbound(team, "pilot/root") and not (team.base / "connections").exists()


def test_a_router_with_the_journal_gets_router_status(team):
    role = team.add_role("pilot/router", cwd=str(team.tmp), lifecycle=team.lifecycle)
    arguments = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]["args"]
    assert arguments[-2:] == ["--lifecycle", team.lifecycle] and "--actor" not in arguments
    assert "router_status" in start_connection(role["connection"])
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert "mcp__aegis_mailbox__router_status" in flag(argv, "--allowedTools").split(",")


def test_a_codex_router_enables_router_status_and_without_the_journal_does_not(team, tmp_path, source_seed):
    role = team.add_role("pilot/router", "codex-cli", session=REVIEW_SESSION, cwd=str(team.source), lifecycle=team.lifecycle)
    server = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])["mcp_servers"]["aegis_mailbox"]
    assert server["enabled_tools"][-1] == "router_status" and "router_status" not in server["tools"]
    (tmp_path / "plain").mkdir()
    plain = Setup(tmp_path / "plain", source_seed=source_seed)
    provision("init", plain.init_request(roles=["router"]))
    without = plain.add_role("pilot/router", cwd=str(plain.tmp))
    assert "router_status" not in start_connection(without["connection"])


def test_the_router_session_is_refused_an_actor(team):
    refused = team.add_role("pilot/router", cwd=str(team.tmp), lifecycle=team.lifecycle, actor="router-1", expect=2)
    assert refused["error"] == ROUTER_ACTOR
    refused = team.add_role("pilot/router", cwd=str(team.tmp), actor="router-1", expect=2)
    assert refused["error"] == ROUTER_ACTOR
    assert unbound(team, "pilot/router")


def test_a_decider_with_the_journal_and_its_actor_gets_decider_record(team, source_seed):
    role = team.add_role("pilot/decider", "codex-cli", session=REVIEW_SESSION, cwd=str(team.source), reader_shell=True,
                         lifecycle=team.lifecycle, actor="decider-1")
    server = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])["mcp_servers"]["aegis_mailbox"]
    assert server["args"][-4:] == ["--lifecycle", team.lifecycle, "--actor", "decider-1"]
    assert server["enabled_tools"][-1] == "decider_record"
    assert server["tools"]["decider_record"] == {"approval_mode": "approve"}
    (team.tmp / "claude").mkdir()
    claude = Setup(team.tmp / "claude", source_seed=source_seed)
    provision("init", claude.init_request(roles=["decider"]))
    plain = claude.add_role("pilot/decider", cwd=str(claude.tmp), lifecycle=team.lifecycle, actor="decider-1")
    assert "decider_record" in start_connection(plain["connection"])
    argv = json.loads(Path(plain["wake_profile"]).read_text())["argv"]
    assert "mcp__aegis_mailbox__decider_record" in flag(argv, "--allowedTools").split(",")


@pytest.mark.parametrize("changes,error", [
    ({"lifecycle": "<journal>"}, PAIR),
    ({"actor": "decider-1"}, PAIR),
    ({"lifecycle": "<journal>", "actor": "root-1"}, "actor root-1 is not a decider actor in the lifecycle policy"),
])
def test_decider_lifecycle_keys_are_checked_before_binding(team, changes, error):
    changes = {key: team.lifecycle if value == "<journal>" else value for key, value in changes.items()}
    refused = team.add_role("pilot/decider", cwd=str(team.tmp), expect=2, **changes)
    assert refused["error"] == error
    assert unbound(team, "pilot/decider")


@pytest.mark.parametrize("endpoint,role,key", [
    ("pilot/orchestrator", "orchestrator", "lifecycle"), ("pilot/lane/f2", "implementer", "actor"),
    ("pilot/lane/review", "reviewer", "lifecycle"), ("pilot/front-door", "front-door", "actor"),
])
def test_other_roles_have_no_lifecycle_connection(team, endpoint, role, key):
    refused = team.add_role(endpoint, cwd=str(team.tmp), expect=2, **{key: team.lifecycle if key == "lifecycle" else "root-1"})
    assert refused["error"] == NO_LIFECYCLE % role
    assert unbound(team, endpoint)


@pytest.mark.parametrize("journal,error", [
    ("<missing>", "lifecycle is not a journal directory: <missing>"),
    ("<file>", "lifecycle is not a journal directory: <file>"),
    (None, "invalid lifecycle"),
    (7, "invalid lifecycle"),
])
def test_a_router_journal_that_is_not_a_journal_is_refused_before_binding(team, journal, error):
    paths = {"<missing>": str(team.tmp / "no-journal"), "<file>": str(team.tmp / "journal-file")}
    (team.tmp / "journal-file").write_text("{}")
    journal = paths.get(journal, journal)
    for name, path in paths.items():
        error = error.replace(name, path)
    refused = team.add_role("pilot/router", cwd=str(team.tmp), lifecycle=journal, expect=2)
    assert refused["error"] == error
    assert unbound(team, "pilot/router") and not (team.base / "connections").exists()


@pytest.mark.parametrize("endpoint,changes,error", [
    ("pilot/orchestrator", {"lifecycle": None}, NO_LIFECYCLE % "orchestrator"),
    ("pilot/orchestrator", {"actor": None}, NO_LIFECYCLE % "orchestrator"),
    ("pilot/router", {"actor": None}, ROUTER_ACTOR),
    ("pilot/router", {"lifecycle": "<journal>", "actor": None}, ROUTER_ACTOR),
    ("pilot/root", {"lifecycle": None, "actor": None}, "invalid actor"),
    ("pilot/root", {"lifecycle": None, "actor": "root-1"}, "invalid lifecycle"),
    ("pilot/root", {"lifecycle": "<journal>", "actor": None}, "invalid actor"),
    ("pilot/root", {"lifecycle": "<journal>"}, PAIR),
    ("pilot/decider", {"lifecycle": "<journal>", "actor": None}, "invalid actor"),
    ("pilot/decider", {"lifecycle": ["<journal>"], "actor": "decider-1"}, "invalid lifecycle"),
    ("pilot/decider", {"actor": None}, PAIR),
])
def test_a_null_or_non_string_lifecycle_key_is_refused_before_binding(team, endpoint, changes, error):
    changes = {key: team.lifecycle if value == "<journal>" else value for key, value in changes.items()}
    extra = {"session": ROOT_SESSION} if endpoint == "pilot/root" else {"cwd": str(team.tmp)}
    refused = team.add_role(endpoint, expect=2, **extra, **changes)
    assert refused["error"] == error
    assert unbound(team, endpoint) and not (team.base / "connections").exists()


def test_a_codex_router_applies_its_registry_tier(team):
    role = team.add_role("pilot/router", "codex-cli", session=REVIEW_SESSION, cwd=str(team.source))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    settings = [argv[index + 1] for index, word in enumerate(argv) if word == "-c"]
    effort = settings.index('model_reasoning_effort="medium"')
    assert settings[effort + 1] == 'service_tier="ultrafast"'
    assert role["model_profile"] == {"source": "registry", "effort": "medium", "tier": "ultrafast", "tier_applied": True}
    profile = json.loads(Path(role["codex_profile"]).read_text())
    assert profile["service_tier"] == "ultrafast" and profile["effort"] == "medium"


def test_a_claude_router_records_its_tier_without_a_flag(team):
    role = team.add_role("pilot/router", cwd=str(team.tmp))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert not any("ultrafast" in word for word in argv) and "codex_profile" not in role
    assert role["model_profile"]["tier_applied"] is False


def disabled(argv):
    return [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]


def assert_argv_follows_profile(argv, profile):
    config = codex_config(argv)
    assert disabled(argv) == profile["disabled_features"]
    assert flag(argv, "--sandbox") == profile["sandbox"] and flag(argv, "-C") == profile["cwd"]
    assert ("--ignore-user-config" in argv) is profile["ignore_user_config"]
    assert config["approval_policy"] == profile["approval_policy"]
    assert config["mcp_servers"] == profile["mcp_servers"]
    for setting, key in (("model", "model"), ("model_reasoning_effort", "effort"), ("service_tier", "service_tier")):
        assert config.get(setting) == profile[key], setting
    if profile["sandbox"] == "workspace-write":
        assert config["sandbox_workspace_write"]["writable_roots"] == profile["writable_roots"]
        assert config["sandbox_workspace_write"]["network_access"] is profile["network_access"]
    else:
        assert "sandbox_workspace_write" not in config
    assert [argv[index + 1] for index, word in enumerate(argv) if word == "--add-dir"] == profile["add_dirs"]
    assert ("--skip-git-repo-check" in argv) is profile["skip_git_repo_check"]
    tmpdir = (config.get("shell_environment_policy") or {}).get("set", {}).get("TMPDIR")
    assert tmpdir == profile["tmpdir"]


def test_a_codex_reviewer_profile_is_recorded_and_its_argv_is_built_from_it(setup):
    role = setup.add_role("pilot/lane/review", "codex-cli", session=REVIEW_SESSION, cwd=str(setup.source))
    assert Path(role["codex_profile"]) == setup.base / "profiles" / "pilot%2Flane%2Freview-g1.codex.json"
    profile = json.loads(Path(role["codex_profile"]).read_text())
    assert {key: profile[key] for key in ("schema", "endpoint", "role", "host", "session", "generation", "sandbox",
                                          "writable_roots", "network_access", "approval_policy", "ignore_user_config",
                                          "cwd", "skip_git_repo_check", "model", "effort", "service_tier", "tmpdir",
                                          "add_dirs")} == {
        "schema": "aegis.hierarchy-codex-profile/v1", "endpoint": "pilot/lane/review", "role": "reviewer",
        "host": "codex-cli", "session": REVIEW_SESSION, "generation": 1, "sandbox": "read-only", "writable_roots": [],
        "network_access": False, "approval_policy": "never", "ignore_user_config": True, "cwd": str(setup.source),
        "skip_git_repo_check": False, "model": None, "effort": None, "service_tier": None, "tmpdir": None, "add_dirs": []}
    assert "shell_tool" in profile["disabled_features"]
    server = profile["mcp_servers"]["aegis_mailbox"]
    # The reviewer's registry entry reads no workspace view, so it has the mailbox tools alone.
    assert server["enabled_tools"] == ["mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"]
    assert server["required"] is True and server["command"] == sys.executable
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[-2:] == ["resume", REVIEW_SESSION]
    assert_argv_follows_profile(argv, profile)


def test_a_codex_implementer_profile_writes_only_its_roots(setup, tmp_path):
    writable, private = tmp_path / "worktree", tmp_path / "private-tmp"
    writable.mkdir()
    private.mkdir()
    role = setup.add_role("pilot/lane/f2", "codex-cli", session=CODEX_SESSION, cwd=str(setup.source),
                          writable_roots=[str(writable)], tmpdir=str(private), add_dirs=[str(writable)],
                          model="gpt-5.5-codex", effort="high", skip_git_repo_check=True)
    profile = json.loads(Path(role["codex_profile"]).read_text())
    assert profile["role"] == "implementer" and profile["sandbox"] == "workspace-write"
    assert profile["writable_roots"] == [str(writable)] and profile["network_access"] is False
    assert profile["approval_policy"] == "never" and "shell_tool" not in profile["disabled_features"]
    assert (profile["model"], profile["effort"], profile["tmpdir"]) == ("gpt-5.5-codex", "high", str(private))
    assert_argv_follows_profile(json.loads(Path(role["wake_profile"]).read_text())["argv"], profile)


def test_codex_start_returns_the_profile_without_writing_it(team):
    started = provision("codex-start", team.request(base=str(team.base), endpoint="pilot/router", cwd=str(team.source)))
    profile = started["codex_profile"]
    assert (profile["session"], profile["generation"], profile["mcp_servers"]) == (None, None, {})
    assert profile["role"] == "router" and profile["service_tier"] == "ultrafast"
    assert_argv_follows_profile(started["start_argv"], profile)
    assert not (team.base / "profiles").exists()


def test_a_launched_codex_role_records_its_codex_profile(tmp_path):
    from tests.integration.test_hierarchy_launcher import Launch
    launch = Launch(tmp_path)
    launch.init()
    thread = "019a6c3e-1111-7222-8333-444455556677"
    answer = launch.start(thread=thread, cwd=str(launch.source))
    assert answer["state"] == "bound"
    profile = json.loads(Path(answer["codex_profile"]).read_text())
    assert profile["session"] == thread and profile["role"] == "reviewer"
    assert_argv_follows_profile(json.loads(Path(answer["wake_profile"]).read_text())["argv"], profile)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("model", ["gpt-6-luna", "claude-haiku-5-5", "claude-sonnet-5-5", "gpt-6.1-terra"])
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r8_router_refuses_cheap_product_seats(mr1_r2_setup, mr1_cli, command, host, model, source):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    row = next(item for item in mr1_bindings()["hosts"] if item["model"] == model)
    coding = next(item for item in mr1_bindings()["hosts"] if item["host"] == host and item["class"] == "coding")
    options = {"model": model} if source == "request" else {}
    if source == "team.json":
        write_team(setup, model=model, reasoning="high")
    refused = call(command, mr1_request(setup, command, "pilot/router", host, **options), expect=2)
    error = ("%s model %s needs host %s, not %s" % (source, model, row["host"], host)
             if row["host"] != host else
             "router model %s has class %s, requires class coding; choose model %s" %
             (model, row["class"], coding["model"]))
    assert refused == {"error": error}
    assert unbound(setup, "pilot/router")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r8_router_accepts_coding_with_fixed_effort_and_tier(mr1_r2_setup, mr1_cli, command, host, source):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(item["model"] for item in mr1_bindings()["hosts"] if item["host"] == host and item["class"] == "coding")
    options = {"model": model} if source == "request" else {}
    if source == "team.json":
        write_team(setup, model=model, reasoning="max")
    answer = call(command, mr1_request(setup, command, "pilot/router", host, **options))
    argv = json.loads(Path(answer["wake_profile"]).read_text())["argv"] if command == "add-role" else answer["start_argv"]
    assert ("model=" + json.dumps(model)) in argv if host == "codex-cli" else flag(argv, "--model") == model
    assert ("model_reasoning_effort=" + json.dumps("medium")) in argv if host == "codex-cli" else flag(argv, "--effort") == "medium"
    assert answer["team"]["model_class"] == "coding" and answer["team"]["effort"] == "medium"
    assert answer["model_profile"] == {"source": "registry", "effort": "medium", "tier": "ultrafast",
                                       "tier_applied": host == "codex-cli"}


@pytest.mark.parametrize("command,host,team_host,team_model", [
    ("codex-start", "codex-cli", "claude-code", "claude-opus-5-5"),
    ("claude-start", "claude-code", "codex-cli", "gpt-6.1-sol"),
])
@pytest.mark.parametrize("model", [None, "owner-selected-model"])
@pytest.mark.parametrize("effort", [None, "xhigh"])
def test_mr1_r8_planned_root_never_resolves_team_settings(setup, mr1_cli, command, host, team_host, team_model,
                                                       model, effort):
    _, call = mr1_cli
    mr1_plan(setup, team_host)
    plan_path = setup.base / "host-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["root"] = host
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    write_team(setup, model=team_model, reasoning="high")
    options = {}
    if model is not None:
        options["model"] = model
    if effort is not None:
        options["effort"] = effort
    answer = call(command, mr1_request(setup, command, "pilot/root", host, **options))
    argv = answer["start_argv"]
    if host == "codex-cli":
        assert [word for word in argv if word.startswith("model=")] == ([] if model is None else ["model=" + json.dumps(model)])
        assert answer["codex_profile"]["model"] == model
        assert answer["codex_profile"]["effort"] == effort
    else:
        assert flag(argv, "--model") == model and flag(argv, "--effort") == effort
    if model is None or effort is None:
        assert answer["team"] == {"model": model, "model_from": "host-default" if model is None else "request",
                                  "effort": effort, "effort_from": "host-default" if effort is None else "request",
                                  "reasoning": effort, "reasoning_from": "host-default" if effort is None else "request"}
    assert unbound(setup, "pilot/root")


@pytest.mark.parametrize("command,host,team_host,team_model", [
    ("codex-start", "codex-cli", "claude-code", "claude-opus-5-5"),
    ("claude-start", "claude-code", "codex-cli", "gpt-6.1-sol"),
])
def test_mr1_r8_planless_root_keeps_legacy_cross_host_refusal(setup, mr1_cli, command, host, team_host, team_model):
    _, call = mr1_cli
    write_team(setup, model=team_model, reasoning="high")
    refused = call(command, mr1_request(setup, command, "pilot/root", host), expect=2)
    assert refused == {"error": "team.json model %s needs host %s, not %s" % (team_model, team_host, host)}
    assert unbound(setup, "pilot/root")


def mr1_r9_publish_bindings(setup, raw):
    """Publish fixture policy through the same source pin a real base requires."""
    path = setup.source / "tools/hierarchy_templates/model-bindings.json"
    if raw is None:
        path.unlink()
    else:
        path.write_bytes(raw)
    git(setup.source, "add", "--", "tools/hierarchy_templates/model-bindings.json")
    git(setup.source, "commit", "--allow-empty", "-qm", "fixture model bindings")
    record_path = setup.base / "provision.json"
    setup_record = json.loads(record_path.read_text())
    setup_record.update(source_commit=git(setup.source, "rev-parse", "HEAD"),
                        source_tree=git(setup.source, "rev-parse", "HEAD^{tree}"))
    record_path.write_text(json.dumps(setup_record), encoding="utf-8")
    return path


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("matching", [False, True])
def test_mr1_r9_start_host_matches_the_governing_plan(setup, mr1_cli, tmp_path_factory, command, host, copied, matching):
    _, call = mr1_cli
    expected = host if matching else "codex-cli" if host == "claude-code" else "claude-code"
    mr1_plan(setup, expected)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    base = mr1_r4_copy_base(setup, tmp_path_factory) if copied else setup.base
    answer = call(command, mr1_r4_request(setup, base, command, host, endpoint="pilot/lane/f2", model=model, effort="high"),
                  expect=0 if matching else 2)
    if matching:
        assert answer["team"]["model"] == model and answer["team"]["intent"] == "deep"
    else:
        assert answer == {"error": "pilot/lane/f2 runs on %s in this run's host plan, not %s" % (expected, host)}
        assert not (base / "profiles").exists()
        assert not (base / "connections" / "pilot%2Flane%2Ff2.start.json").exists()
        assert unbound(setup, "pilot/lane/f2")


def test_mr1_r9_copied_base_launcher_refuses_before_executing_a_host(tmp_path_factory):
    from tests.integration.test_hierarchy_launcher_hosts import Hosts
    launch = Hosts(tmp_path_factory.mktemp("mr1-r9-launch-" + uuid.uuid4().hex))
    launch.init()
    mr1_plan(launch, "claude-code")
    write_team(launch, model="claude-opus-5-5", reasoning="high")
    original_root = launch.root
    launch.base = mr1_r4_copy_base(launch, tmp_path_factory)
    refused = launch.start(endpoint="pilot/lane/f2", model="gpt-6.1-sol", effort="high", cwd=str(launch.source), expect=2)
    assert refused["state"] == "refused"
    assert refused["error"] == "pilot/lane/f2 runs on claude-code in this run's host plan, not codex-cli"
    assert launch.records("pilot/lane/f2") == [refused]
    assert invoke(original_root, "status")["bindings"]["pilot/lane/f2"] is None
    assert not launch.codex_log.exists() and not launch.claude_log.exists()


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint,effort", [("pilot/front-door", "xhigh"), ("pilot/router", None),
                                            ("pilot/lane/f2", "high")])
def test_mr1_r9_effort_without_model_resolves_the_pinned_binding(mr1_r2_setup, mr1_cli, command, host, endpoint, effort):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    options = {} if effort is None else {"effort": effort}
    answer = call(command, mr1_request(setup, command, endpoint, host, **options))
    actual_effort = effort or "medium"
    assert answer["team"]["model"] == model and answer["team"]["model_from"] == "model-bindings.json"
    assert answer["team"]["effort"] == actual_effort and answer["team"]["model_class"] == "coding"
    path = setup.source / "tools/hierarchy_templates/model-bindings.json"
    assert answer["team"]["bindings_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    argv = json.loads(Path(answer["wake_profile"]).read_text())["argv"] if command == "add-role" else answer["start_argv"]
    assert ("model=" + json.dumps(model)) in argv if host == "codex-cli" else flag(argv, "--model") == model
    assert ("model_reasoning_effort=" + json.dumps(actual_effort)) in argv if host == "codex-cli" else flag(argv, "--effort") == actual_effort


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint,effort,supported", [("pilot/front-door", "xhigh", "light, standard, deep, max"),
                                                      ("pilot/router", "medium", "standard, deep, max")])
def test_mr1_r9_unbound_effort_never_bypasses_supported_levels(mr1_r2_setup, mr1_cli, command, host,
                                                            endpoint, effort, supported):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    data = mr1_bindings()
    row = next(row for row in data["hosts"] if row["host"] == host and row["class"] == "coding")
    if endpoint.endswith("router"):
        row["levels"] = {"standard": "low", "deep": "high", "max": "max"}
    else:
        del row["levels"]["extended"]
    row["admission"] = {intent: "unprobed" for intent in row["levels"]}
    mr1_r9_publish_bindings(setup, json.dumps(data).encode("utf-8"))
    options = {} if endpoint.endswith("router") else {"effort": effort}
    refused = call(command, mr1_request(setup, command, endpoint, host, **options), expect=2)
    assert refused == {"error": "%s effort %s has no supported intent; supported intents: %s; choose a supported effort" %
                       (endpoint.split("/")[-1], effort, supported)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("explicit_model", [False, True])
@pytest.mark.parametrize("copied", [False, True])
def test_mr1_r9_importer_bindings_cannot_replace_the_governing_pin(setup, tmp_path_factory, explicit_model, copied):
    import importlib.util
    mr1_plan(setup, "codex-cli")
    importer = tmp_path_factory.mktemp("mr1-r9-importer-" + uuid.uuid4().hex)
    module_path = importer / "hierarchy_provision.py"
    shutil.copyfile(PROVISION, module_path)
    local = importer / "hierarchy_templates" / "model-bindings.json"
    local.parent.mkdir()
    data = mr1_bindings()
    next(row for row in data["hosts"] if row["host"] == "codex-cli" and row["class"] == "coding")["model"] = "gpt-6.1-sol-local"
    local.write_text(json.dumps(data), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("mr1_importer_" + uuid.uuid4().hex, module_path)
    module = importlib.util.module_from_spec(spec)
    previous_path = list(sys.path)
    try:
        spec.loader.exec_module(module)
        base = mr1_r4_copy_base(setup, tmp_path_factory) if copied else setup.base
        request = {"endpoint": "pilot/lane/f2", "effort": "high"}
        if explicit_model:
            request["model"] = "gpt-6.1-sol"
        options, record = module.team_settings(base, "codex-cli", request, "implementer")
    finally:
        sys.path[:] = previous_path
    assert options["model"] == "gpt-6.1-sol" and record["model"] == "gpt-6.1-sol"
    pinned = setup.source / "tools/hierarchy_templates/model-bindings.json"
    assert record["bindings_sha256"] == hashlib.sha256(pinned.read_bytes()).hexdigest()
    assert record["bindings_sha256"] != hashlib.sha256(local.read_bytes()).hexdigest()


@pytest.mark.parametrize("damage", ["bytes", "head", "missing", "symlink"])
def test_mr1_r9_direct_resolution_refuses_an_unverified_pin(setup, mr1_cli, damage):
    module, _ = mr1_cli
    mr1_plan(setup, "codex-cli")
    pinned = setup.source / "tools/hierarchy_templates/model-bindings.json"
    if damage == "missing":
        pinned.unlink()
    elif damage == "symlink":
        outside = setup.tmp / (uuid.uuid4().hex + ".json")
        outside.write_bytes(pinned.read_bytes())
        pinned.unlink()
        pinned.symlink_to(outside)
    else:
        pinned.write_bytes(pinned.read_bytes() + b"\n")
        if damage == "head":
            git(setup.source, "add", "--", "tools/hierarchy_templates/model-bindings.json")
            git(setup.source, "commit", "-qm", "unrecorded policy change")
    with pytest.raises(ValueError) as caught:
        module.team_settings(setup.base, "codex-cli", {"endpoint": "pilot/lane/f2", "model": "gpt-6.1-sol", "effort": "high"},
                             "implementer")
    assert str(caught.value) == ("invalid model bindings %s: source pin verification failed; "
                                 "restore the pinned source or reprovision; repair model-bindings.json" % pinned)
    assert unbound(setup, "pilot/lane/f2")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("model_only", [False, True])
def test_mr1_r10_unbanded_missing_effort_holds_before_profile(setup, mr1_cli, command, host, model_only):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    options = {"model": model} if model_only else {}
    refused = call(command, mr1_request(setup, command, "pilot/front-door", host, **options), expect=2)
    assert refused == {"error": "front-door has no effort; provide request effort or team.json reasoning; "
                       "host defaults are not allowed for an unbanded role"}
    assert unbound(setup, "pilot/front-door")
    assert not (setup.base / "profiles").exists()


@pytest.mark.parametrize("bad_source", [[], {}])
def test_mr1_r14a_malformed_generation_provenance_is_a_fixed_refusal(setup, mr1_cli, bad_source):
    _, call = mr1_cli
    mr1_plan(setup, "codex-cli")
    endpoint, session = "pilot/lane/f2", str(uuid.uuid4())
    request = dict(model="gpt-6.1-sol", effort="high", session=session)
    call("add-role", mr1_request(setup, "add-role", endpoint, "codex-cli", **request))
    path = setup.base / "sessions/pilot%2Flane%2Ff2-g1.json"
    record = json.loads(path.read_text())
    record["model_profile"]["effort_from"] = bad_source
    path.write_text(json.dumps(record), encoding="utf-8")
    before = mr1_r12_registered_files(setup)
    refused = call("add-role", mr1_request(setup, "add-role", endpoint, "codex-cli", **request), expect=2)
    assert refused == {"error": "session record for pilot/lane/f2 generation 1 differs from this binding"}
    assert mr1_r12_registered_files(setup) == before


@pytest.mark.parametrize("command,host", [("codex-start", "codex-cli"), ("claude-start", "claude-code")])
@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("complete", [False, True])
def test_mr1_r10_standin_start_refuses_before_argv(setup, mr1_cli, tmp_path_factory, command, host, copied, complete):
    _, call = mr1_cli
    mr1_plan(setup, "claude-code" if host == "codex-cli" else "codex-cli")
    plan_path = setup.base / "host-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["stand_ins"] = {"pilot/front-door": host}
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    base = mr1_r4_copy_base(setup, tmp_path_factory) if copied else setup.base
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    options = {"model": model, "effort": "medium"} if complete else {}
    refused = call(command, mr1_r4_request(setup, base, command, host, endpoint="pilot/front-door", **options), expect=2)
    assert refused == {"error": "pilot/front-door is a stand-in binding that never runs a host; use add-role to register it"}
    assert unbound(setup, "pilot/front-door")
    assert not (base / "connections" / "pilot%2Ffront-door.start.json").exists()


@pytest.mark.parametrize("host", ["codex-cli", "claude-code"])
def test_mr1_r10_endpointless_frontdoor_resolver_keeps_standin_fact(setup, mr1_cli, host):
    module, _ = mr1_cli
    mr1_plan(setup, "claude-code" if host == "codex-cli" else "codex-cli")
    path = setup.base / "host-plan.json"
    plan = json.loads(path.read_text())
    plan["stand_ins"] = {"pilot/front-door": host}
    path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ValueError) as caught:
        module.team_settings(setup.base, host, {}, "front-door")
    assert str(caught.value) == "pilot/front-door is a stand-in binding that never runs a host; use add-role to register it"


def test_mr1_r10_copied_standin_launcher_never_executes(tmp_path_factory):
    from tests.integration.test_hierarchy_launcher_hosts import Hosts
    launch = Hosts(tmp_path_factory.mktemp("mr1-r10-standin-" + uuid.uuid4().hex))
    launch.init()
    mr1_plan(launch, "codex-cli")
    path = launch.base / "host-plan.json"
    plan = json.loads(path.read_text())
    plan["stand_ins"] = {"pilot/front-door": "codex-cli"}
    path.write_text(json.dumps(plan), encoding="utf-8")
    original_root = launch.root
    launch.base = mr1_r4_copy_base(launch, tmp_path_factory)
    refused = launch.start(endpoint="pilot/front-door", model="gpt-6.1-sol", effort="medium", expect=2)
    assert refused["state"] == "refused"
    assert refused["error"] == "pilot/front-door is a stand-in binding that never runs a host; use add-role to register it"
    assert launch.records("pilot/front-door") == [refused]
    assert invoke(original_root, "status")["bindings"]["pilot/front-door"] is None
    assert not launch.codex_log.exists() and not launch.claude_log.exists()


@pytest.mark.parametrize("host", ["codex-cli", "claude-code", "codex"])
def test_mr1_r10_standin_registration_has_no_executable_profile(setup, mr1_cli, host):
    _, call = mr1_cli
    mr1_plan(setup, "codex-cli")
    path = setup.base / "host-plan.json"
    plan = json.loads(path.read_text())
    plan["stand_ins"] = {"pilot/front-door": host}
    path.write_text(json.dumps(plan), encoding="utf-8")
    request = mr1_request(setup, "add-role", "pilot/front-door", host, session=str(uuid.uuid4()))
    answer = call("add-role", request)
    assert answer["stand_in"] is True
    assert Path(answer["connection"]).is_file()
    assert not {"start_argv", "wake_profile", "codex_profile"} & answer.keys()
    assert not (setup.base / "profiles").exists()
    record = json.loads((setup.base / "sessions" / "pilot%2Ffront-door-g1.json").read_text())
    assert record["stand_in"] is True and record["start_mode"] is None
    assert not unbound(setup, "pilot/front-door")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,_effort", MR1_R2_BANDED_ROLES + [("root", "pilot/root", None)])
def test_mr1_r10_default_path_verifies_canonical_pin(mr1_r2_setup, mr1_cli, tmp_path_factory, command, host, kind, endpoint, _effort):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    plan_path = setup.base / "host-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["root"] = host
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    replacement = tmp_path_factory.mktemp("mr1-r10-source-" + uuid.uuid4().hex) / "source"
    copy_source(setup.source, replacement)
    canonical_path = setup.base / "provision.json"
    canonical = json.loads(canonical_path.read_text())
    canonical["source"] = str(replacement)
    canonical_path.write_text(json.dumps(canonical), encoding="utf-8")
    bindings = replacement / "tools/hierarchy_templates/model-bindings.json"
    bindings.write_bytes(bindings.read_bytes() + b"\n")
    refused = call(command, mr1_r4_request(setup, copied, command, host, endpoint=endpoint), expect=2)
    assert refused == {"error": "invalid model bindings %s: source pin verification failed; "
                       "restore the pinned source or reprovision; repair model-bindings.json" % bindings}
    assert unbound(setup, endpoint)
    assert not (copied / "profiles").exists()


MR1_R12_PIN_ERROR = "runtime source pin differs from governing provision; use the governing base or reprovision"


def mr1_r13_old_source(setup, tmp_path_factory):
    source = tmp_path_factory.mktemp("mr1-r13-old-" + uuid.uuid4().hex) / "source"
    shutil.copytree(setup.source, source, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    marker = source.parent / "old-provisioner-ran"
    # A runnable, permissive older entry without any dependency on this repository's history.
    (source / "tools/hierarchy_provision.py").write_text(
        "import argparse\nimport json\nfrom pathlib import Path\n"
        "Path(%r).write_text('executed\\n', encoding='utf-8')\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('command')\n"
        "parser.add_argument('--request', required=True)\n"
        "request = json.loads(Path(parser.parse_args().request).read_text(encoding='utf-8'))\n"
        "print(json.dumps({'accepted_effort': request.get('effort')}))\n" % str(marker), encoding="utf-8")
    git(source, "init", "-q", "-b", "develop")
    git(source, "add", ".")
    git(source, "commit", "-qm", "synthetic older provisioner")
    return source, marker


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
def test_mr1_r12_old_copied_pin_never_selects_the_old_provisioner(setup, tmp_path_factory, command, host):
    mr1_plan(setup, host)
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    source, marker = mr1_r13_old_source(setup, tmp_path_factory)
    setup_path = copied / "provision.json"
    record = json.loads(setup_path.read_text())
    record.update(source=str(source), source_commit=git(source, "rev-parse", "HEAD"),
                  source_tree=git(source, "rev-parse", "HEAD^{tree}"))
    setup_path.write_text(json.dumps(record), encoding="utf-8")
    shutil.copyfile(source / "tools/hierarchy_runtime_source.py", copied / "runtime-source.py")
    model = "claude-fable-5-1" if host == "claude-code" else "gpt-6.1-sol"
    request = mr1_r4_request(setup, copied, command, host, model=model, effort="ultra")
    assert not marker.exists()
    refused = mr1_provision(command, request, expect=2)
    assert refused == {"error": MR1_R12_PIN_ERROR}
    assert not marker.exists()
    assert unbound(setup, "pilot/orchestrator")
    assert not (copied / "profiles").exists()
    assert not (copied / "connections").exists()
    assert not (setup.base / "sessions").exists()


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
def test_mr1_r13_equal_copied_pin_still_resolves_governing_policy(setup, tmp_path_factory, command, host):
    mr1_plan(setup, host)
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    request = mr1_r4_request(setup, copied, command, host, model=model, effort="medium")
    answer = mr1_provision(command, request)
    assert answer["team"]["model"] == model and answer["team"]["effort"] == "medium"
    assert answer["team"]["intent"] == "standard" and answer["team"]["model_class"] == "coding"
    assert unbound(setup, "pilot/orchestrator") == (command != "add-role")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("component", ["source_commit", "source_tree"])
def test_mr1_r12_imported_entry_points_compare_both_governing_pin_components(setup, mr1_cli, tmp_path_factory,
                                                                         command, host, component):
    _, call = mr1_cli
    mr1_plan(setup, host)
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    path = copied / "provision.json"
    record = json.loads(path.read_text())
    record[component] = "0" * 40
    path.write_text(json.dumps(record), encoding="utf-8")
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    refused = call(command, mr1_r4_request(setup, copied, command, host, model=model, effort="medium"), expect=2)
    assert refused == {"error": MR1_R12_PIN_ERROR}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("kind,endpoint,effort", MR1_R2_BANDED_ROLES)
@pytest.mark.parametrize("model_class", ["scout", "mechanical", "frontier"])
def test_mr1_r12_product_role_class_cannot_be_changed_by_pinned_data(mr1_r2_setup, mr1_cli, host, kind, endpoint,
                                                                effort, model_class):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    data = mr1_bindings()
    next(row for row in data["roles"] if row["kind"] == kind)["model_class"] = model_class
    model = next(row["model"] for row in data["hosts"] if row["host"] == host and row["class"] == model_class)
    path = mr1_r9_publish_bindings(setup, json.dumps(data).encode("utf-8"))
    refused = call("add-role", mr1_request(setup, "add-role", endpoint, host, model=model, effort=effort), expect=2)
    assert refused == {"error": "invalid model bindings %s: %s requires model class coding; got %s; "
                       "repair model-bindings.json" % (path, kind, ascii(model_class))}
    assert unbound(setup, endpoint)


def mr1_r12_registered_files(setup):
    return {str(path.relative_to(setup.base)): path.read_bytes()
            for folder in ("profiles", "connections", "sessions")
            for path in (setup.base / folder).rglob("*") if path.is_file()}


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("source", ["request", "team.json"])
@pytest.mark.parametrize("dimension", ["model", "effort", "host-default"])
def test_mr1_r12_live_generation_never_rewrites_model_or_effort(setup, mr1_cli, host, source, dimension):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    session = str(uuid.uuid4())
    if source == "team.json":
        write_team(setup, model=model, reasoning="high")
    options = {"model": model, "effort": "high"} if source == "request" else {}
    first = call("add-role", mr1_request(setup, "add-role", "pilot/lane/f2", host, session=session, **options))
    if dimension == "model":
        data = mr1_bindings()
        model += "-recalibrated"
        next(row for row in data["hosts"] if row["host"] == host and row["class"] == "coding")["model"] = model
        mr1_r9_publish_bindings(setup, json.dumps(data).encode("utf-8"))
    effort = "max" if dimension == "effort" else "high"
    if dimension == "host-default":
        options = {}
        if source == "team.json":
            (setup.base / "team.json").unlink()
    elif source == "team.json":
        write_team(setup, model=model, reasoning=effort)
    else:
        options = {"model": model, "effort": effort}
    before = mr1_r12_registered_files(setup)
    refused = call("add-role", mr1_request(setup, "add-role", "pilot/lane/f2", host, session=session, **options), expect=2)
    assert refused == {"error": "session record for pilot/lane/f2 generation 1 differs from this binding"}
    assert first["generation"] == 1
    assert mr1_r12_registered_files(setup) == before
    record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g1.json").read_text())
    assert record["model_profile"]["model"] == first["team"]["model"]
    assert record["model_profile"]["native_effort"] == "high"
    assert invoke(setup.root, "status")["bindings"]["pilot/lane/f2"]["generation"] == 1


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_mr1_r12_same_generation_is_idempotent_and_successor_can_change_effort(setup, mr1_cli, host):
    from tests.integration.test_hierarchy_handoff import handoff
    from tests.integration.test_hierarchy_host_plan import spec
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    session = str(uuid.uuid4())
    options = {"model": model, "effort": "high", "session": session}
    first = call("add-role", mr1_request(setup, "add-role", "pilot/lane/f2", host, **options))
    before = mr1_r12_registered_files(setup)
    assert call("add-role", mr1_request(setup, "add-role", "pilot/lane/f2", host, **options)) == first
    assert mr1_r12_registered_files(setup) == before
    record_path = setup.base / "sessions/pilot%2Flane%2Ff2-g1.json"
    record = json.loads(record_path.read_text())
    assert record["model_profile"]["model"] == model and record["model_profile"]["native_effort"] == "high"
    successor = str(uuid.uuid4())
    assert handoff(setup.tmp, spec(setup, host, successor, "pilot/lane/f2"), 0)["entries"][0]["generation"] == 2
    second = call("add-role", mr1_request(setup, "add-role", "pilot/lane/f2", host,
                                         session=successor, model=model, effort="max"))
    assert second["generation"] == 2
    assert json.loads(record_path.read_text()) == record
    next_record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g2.json").read_text())
    assert next_record["model_profile"]["model"] == model and next_record["model_profile"]["native_effort"] == "max"


def mr1_r14_reasoning(setup, model, level, by_kind):
    write_team(setup, model=model, reasoning="high" if by_kind else level,
               **({"reasoning_by_kind": {"implementer": level}} if by_kind else {}))


@pytest.mark.parametrize("initial,changed", [("max", "ultra"), ("ultra", "max")])
@pytest.mark.parametrize("by_kind", [False, True])
def test_mr1_r14_claude_alias_change_cannot_rewrite_a_live_generation(setup, mr1_cli, initial, changed, by_kind):
    _, call = mr1_cli
    mr1_plan(setup, "claude-code")
    model, endpoint, session = "claude-opus-5-5", "pilot/lane/f2", str(uuid.uuid4())
    mr1_r14_reasoning(setup, model, initial, by_kind)
    first = call("add-role", mr1_request(setup, "add-role", endpoint, session=session))
    first_wake = json.loads(Path(first["wake_profile"]).read_text())
    assert first["team"]["effort"] == "max"
    assert ("--settings" in first_wake["argv"]) == (initial == "ultra")
    before = mr1_r12_registered_files(setup)
    mr1_r14_reasoning(setup, model, changed, by_kind)
    refused = call("add-role", mr1_request(setup, "add-role", endpoint, session=session), expect=2)
    assert refused == {"error": "session record for pilot/lane/f2 generation 1 differs from this binding"}
    assert mr1_r12_registered_files(setup) == before
    record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g1.json").read_text())
    assert record["model_profile"]["model"] == model and record["model_profile"]["native_effort"] == "max"
    assert record["model_profile"]["ultracode"] is (initial == "ultra")
    assert invoke(setup.root, "status")["bindings"][endpoint]["generation"] == 1


@pytest.mark.parametrize("initial,changed", [("max", "ultra"), ("ultra", "max")])
@pytest.mark.parametrize("by_kind", [False, True])
def test_mr1_r14_same_effective_config_is_idempotent_and_alias_change_needs_rotation(setup, mr1_cli,
                                                                                initial, changed, by_kind):
    from tests.integration.test_hierarchy_handoff import handoff
    from tests.integration.test_hierarchy_host_plan import spec
    _, call = mr1_cli
    mr1_plan(setup, "claude-code")
    model, endpoint, session = "claude-opus-5-5", "pilot/lane/f2", str(uuid.uuid4())
    mr1_r14_reasoning(setup, model, initial, by_kind)
    first = call("add-role", mr1_request(setup, "add-role", endpoint, session=session))
    before = mr1_r12_registered_files(setup)
    assert call("add-role", mr1_request(setup, "add-role", endpoint, session=session)) == first
    assert mr1_r12_registered_files(setup) == before
    record_path = setup.base / "sessions/pilot%2Flane%2Ff2-g1.json"
    record = json.loads(record_path.read_text())
    assert record["model_profile"]["ultracode"] is (initial == "ultra")
    successor = str(uuid.uuid4())
    assert handoff(setup.tmp, spec(setup, "claude-code", successor, endpoint), 0)["entries"][0]["generation"] == 2
    mr1_r14_reasoning(setup, model, changed, by_kind)
    second = call("add-role", mr1_request(setup, "add-role", endpoint, session=successor))
    assert second["generation"] == 2
    assert json.loads(record_path.read_text()) == record
    assert Path(first["wake_profile"]).read_bytes() == before["profiles/pilot%2Flane%2Ff2-g1.wake.json"]
    next_record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g2.json").read_text())
    assert next_record["model_profile"]["ultracode"] is (changed == "ultra")
    wake = json.loads(Path(second["wake_profile"]).read_text())
    assert ("--settings" in wake["argv"]) == (changed == "ultra")


@pytest.mark.parametrize("initial,changed", [("max", "ultra"), ("ultra", "max")])
def test_mr1_r14_codex_alias_provenance_does_not_change_effective_config(setup, mr1_cli, initial, changed):
    _, call = mr1_cli
    mr1_plan(setup, "codex-cli")
    model, endpoint, session = "gpt-6.1-sol", "pilot/lane/f2", str(uuid.uuid4())
    write_team(setup, model=model, reasoning=initial)
    first = call("add-role", mr1_request(setup, "add-role", endpoint, "codex-cli", session=session))
    before = mr1_r12_registered_files(setup)
    write_team(setup, model=model, reasoning=changed)
    second = call("add-role", mr1_request(setup, "add-role", endpoint, "codex-cli", session=session))
    assert second["generation"] == 1 and second["team"]["reasoning"] == changed
    assert mr1_r12_registered_files(setup) == before
    record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g1.json").read_text())
    assert record["model_profile"]["ultracode"] is False
    assert first["team"]["effort"] == second["team"]["effort"] == "max"


@pytest.mark.parametrize("host,model", [("claude-code", "claude-opus-5-5"), ("codex-cli", "gpt-6.1-sol")])
@pytest.mark.parametrize("initial,changed", [("max", "ultra"), ("ultra", "max")])
def test_mr1_r14_explicit_effort_and_explicit_defaults_keep_the_same_config(setup, mr1_cli, host, model,
                                                                        initial, changed):
    _, call = mr1_cli
    mr1_plan(setup, host)
    endpoint, session = "pilot/lane/f2", str(uuid.uuid4())
    write_team(setup, model=model, reasoning=initial)
    first = call("add-role", mr1_request(setup, "add-role", endpoint, host, session=session, effort="max"))
    before = mr1_r12_registered_files(setup)
    write_team(setup, model=model, reasoning=changed)
    defaults = ({"background": False, "assistants": False, "add_dirs": []} if host == "claude-code" else
                {"skip_git_repo_check": False, "writable_roots": [], "add_dirs": []})
    assert call("add-role", mr1_request(setup, "add-role", endpoint, host,
                                       session=session, effort="max", **defaults)) == first
    assert mr1_r12_registered_files(setup) == before
    record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g1.json").read_text())
    assert record["model_profile"]["ultracode"] is False


@pytest.mark.parametrize("setting", ["reader_shell", "skip_git_repo_check", "add_dirs", "tmpdir",
                                     "writable_roots", "tools", "cwd", "timeout_seconds", "source_repo"])
def test_mr1_r14_other_effective_launch_settings_cannot_change_in_generation(setup, mr1_cli, setting):
    _, call = mr1_cli
    host = "claude-code" if setting in ("tools", "cwd") else "codex-cli"
    endpoint = ("pilot/lane/review" if setting in ("reader_shell", "source_repo") else
                "pilot/orchestrator" if setting == "cwd" else "pilot/lane/f2")
    model = "claude-opus-5-5" if host == "claude-code" else "gpt-6.1-sol"
    effort = "medium" if setting == "cwd" else "high"
    mr1_plan(setup, host)
    session = str(uuid.uuid4())
    extra, added = setup.tmp / "extra", setup.tmp / "added"
    extra.mkdir()
    added.mkdir()
    initial, changed = {}, {}
    if setting == "reader_shell":
        changed = {"reader_shell": True}
    elif setting == "skip_git_repo_check":
        changed = {"skip_git_repo_check": True}
    elif setting == "add_dirs":
        initial = {"writable_roots": [str(extra)], "add_dirs": [str(extra), str(added)]}
        changed = dict(initial, add_dirs=[str(added)])
    elif setting == "tmpdir":
        initial = {"writable_roots": [str(extra), str(added)], "tmpdir": str(extra)}
        changed = dict(initial, tmpdir=str(added))
    elif setting == "writable_roots":
        initial = {"writable_roots": [str(extra)]}
        changed = {"writable_roots": [str(extra), str(extra)]}
    elif setting == "tools":
        changed = {"tools": "Read"}
    elif setting == "cwd":
        changed = {"cwd": str(extra)}
    elif setting == "timeout_seconds":
        changed = {"timeout_seconds": 1200}
    elif setting == "source_repo":
        changed = {"source_repo": str(setup.source)}
    first = call("add-role", mr1_request(setup, "add-role", endpoint, host,
                                        session=session, model=model, effort=effort, **initial))
    before = mr1_r12_registered_files(setup)
    refused = call("add-role", mr1_request(setup, "add-role", endpoint, host,
                                          session=session, model=model, effort=effort, **changed), expect=2)
    assert refused == {"error": "session record for %s generation 1 differs from this binding" % endpoint}
    assert first["generation"] == 1 and mr1_r12_registered_files(setup) == before


MR1_R14_GOVERNING_ERROR = "governing source pin check failed; use the governing base or reprovision"
MR1_R14_FIXED_ROLES = [
    (entry["endpoint"].get("lane_kind", entry["endpoint"]["role"]), entry["endpoint"]["role"],
     entry["model_profile"]["effort"])
    for entry in json.loads((ROOT / "tools/hierarchy_templates/role-registry.json").read_text())["roles"].values()
    if entry.get("endpoint") is not None and entry.get("model_profile", {}).get("source") == "fixed"]


@pytest.mark.parametrize("initial_explicit", [False, True])
@pytest.mark.parametrize("by_kind", [False, True])
def test_mr1_r14a_effort_presence_cannot_switch_ultracode_and_profile_has_one_optional_key(setup, mr1_cli,
                                                                                       initial_explicit, by_kind):
    _, call = mr1_cli
    mr1_plan(setup, "claude-code")
    model, endpoint, session = "claude-opus-5-5", "pilot/lane/f2", str(uuid.uuid4())
    mr1_r14_reasoning(setup, model, "ultra", by_kind)
    options = {"effort": "max"} if initial_explicit else {}
    first = call("add-role", mr1_request(setup, "add-role", endpoint, session=session, **options))
    before = mr1_r12_registered_files(setup)
    options = {} if initial_explicit else {"effort": "max"}
    refused = call("add-role", mr1_request(setup, "add-role", endpoint, session=session, **options), expect=2)
    assert refused == {"error": "session record for pilot/lane/f2 generation 1 differs from this binding"}
    assert mr1_r12_registered_files(setup) == before
    record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g1.json").read_text())
    base_keys = {"schema", "endpoint", "role_kind", "host_kind", "start_mode", "session", "generation",
                 "stand_in", "write_scope"}
    assert set(record) == base_keys | {"model_profile"}
    profile = record["model_profile"]
    assert {"model_class", "model", "intent", "native_effort", "band", "model_from", "effort_from",
            "reasoning_from", "bindings_sha256", "signals"} <= profile.keys()
    assert profile["native_effort"] == first["team"]["effort"] == "max"
    assert profile["ultracode"] is (not initial_explicit)
    assert profile["signals"] == []


@pytest.mark.parametrize("host,model", [("claude-code", "claude-opus-5-5"), ("codex-cli", "gpt-6.1-sol")])
@pytest.mark.parametrize("initial_explicit", [False, True])
def test_mr1_r14a_effective_equality_keeps_first_selection_provenance(setup, mr1_cli, host, model, initial_explicit):
    _, call = mr1_cli
    mr1_plan(setup, host)
    endpoint, session = "pilot/lane/f2", str(uuid.uuid4())
    write_team(setup, model=model, reasoning="max")
    options = {"effort": "max"} if initial_explicit else {}
    first = call("add-role", mr1_request(setup, "add-role", endpoint, host, session=session, **options))
    before = mr1_r12_registered_files(setup)
    options = {} if initial_explicit else {"effort": "max"}
    second = call("add-role", mr1_request(setup, "add-role", endpoint, host, session=session, **options))
    assert second["generation"] == 1 and second["team"]["effort"] == first["team"]["effort"] == "max"
    assert mr1_r12_registered_files(setup) == before
    record = json.loads((setup.base / "sessions/pilot%2Flane%2Ff2-g1.json").read_text())
    assert record["model_profile"]["effort_from"] == ("request" if initial_explicit else "team.json")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("planned", [False, True])
def test_mr1_r14a_looping_mailbox_preserves_no_plan_json_and_planned_fixed_error(setup, command, host, planned):
    if planned:
        mr1_plan(setup, host)
    loop = setup.base / "loop"
    loop.symlink_to("loop", target_is_directory=True)
    mailbox_root = loop / "mailbox"
    path = setup.base / "provision.json"
    record = json.loads(path.read_text())
    record["mailbox_root"] = str(mailbox_root)
    path.write_text(json.dumps(record), encoding="utf-8")
    legacy_error = "symlink paths are not supported: " + str(loop)
    expected = MR1_R14_GOVERNING_ERROR if planned else legacy_error
    model = "claude-opus-5-5" if host == "claude-code" else "gpt-6.1-sol"
    request = mr1_request(setup, command, host=host, model=model, effort="medium")
    if command == "claude-start":
        assert mr1_provision(command, request, expect=2) == {"error": expected}
    else:
        request_path = Path(request.pop("_request_path"))
        request_path.write_text(json.dumps(request), encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", str(PROVISION), command, "--request", str(request_path)],
                                capture_output=True, text=True, timeout=60)
        assert (result.returncode, result.stdout, result.stderr) == (
            2, json.dumps({"error": expected}, sort_keys=True) + "\n", "")
        if not planned:
            control = subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(mailbox_root), "status"],
                                     capture_output=True, text=True, timeout=60)
            assert (result.returncode, result.stdout, result.stderr) == (
                control.returncode, control.stdout, control.stderr)
    assert not (setup.base / "profiles").exists() and not (setup.base / "sessions").exists()


@pytest.mark.parametrize("fault", [RuntimeError, OSError, ValueError])
def test_mr1_r14a_governing_check_errors_never_escape_or_echo_details(setup, mr1_cli, tmp_path_factory,
                                                                  monkeypatch, fault):
    _, call = mr1_cli
    mr1_plan(setup, "codex-cli")
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    original = Path.resolve

    def broken(path, *args, **kwargs):
        if path == setup.base:
            raise fault("detail must not be printed")
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "resolve", broken)
        refused = call("add-role", mr1_r4_request(setup, copied, "add-role", "codex-cli",
                                                model="gpt-6.1-sol", effort="medium"), expect=2)
    assert refused == {"error": MR1_R14_GOVERNING_ERROR}
    assert unbound(setup, "pilot/orchestrator") and not (copied / "profiles").exists()


@pytest.mark.parametrize("kind,label,effort", MR1_R14_FIXED_ROLES)
@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_mr1_r14a_direct_fixed_roles_refuse_non_registry_effort(mr1_r2_setup, mr1_cli, host, kind, label, effort):
    setup = mr1_r2_setup
    module, _ = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    wrong = "max" if effort != "max" else "low"
    with pytest.raises(ValueError) as caught:
        module.team_settings(setup.base, host, {"model": model, "effort": wrong}, kind=kind)
    assert str(caught.value) == "the %s role runs at effort %s from the role registry" % (label, effort)
    assert not (setup.base / "profiles").exists()


@pytest.mark.parametrize("kind,label,effort", MR1_R14_FIXED_ROLES)
@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("model_present,effort_present", [(False, False), (True, False), (False, True), (True, True)])
def test_mr1_r14a_direct_fixed_roles_record_registry_provenance(mr1_r2_setup, mr1_cli, host, kind, label, effort,
                                                            model_present, effort_present):
    setup = mr1_r2_setup
    module, _ = mr1_cli
    mr1_plan(setup, host)
    request = {}
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    if model_present:
        request["model"] = model
    if effort_present:
        request["effort"] = effort
    options, record = module.team_settings(setup.base, host, request, kind=kind)
    assert options["model"] == model and options["effort"] == effort
    assert record["effort_from"] == record["reasoning_from"] == "registry"
    assert record["model_from"] == ("request" if model_present else "model-bindings.json")
    assert not (setup.base / "profiles").exists()
