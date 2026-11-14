"""C1 public adapter contract. No real owner homes or engines are used by default."""
import ast
import copy
from contextlib import redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "hierarchy_container.py"
FAKE = Path(__file__).with_name("hierarchy_fake_engine.py")
IMAGE = "localhost/aegis-teams@sha256:" + "a" * 64
ENGINE_HOME = str(Path.home())  # Podman alone needs its original local image store in the opt-in test.
REAL_PODMAN = shutil.which("podman")  # Resolve before layout places the test fake on PATH.
ISOLATION = {"mode": "container", "engine": "podman", "image": IMAGE,
             "cpus": 1, "memory": "1g", "pids": 64}
SECRET_PATHS = (".claude", ".codex", ".ssh", ".gnupg", ".config", ".aws", ".kube", ".docker",
                ".netrc", ".git-credentials")
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="container isolation requires Linux")


@pytest.fixture
def layout(tmp_path, monkeypatch):
    import pwd

    host_getpwuid = pwd.getpwuid
    previous_umask = os.umask(0o077)
    (tmp_path / ".keep").write_text("Retain C1 desktop-pytest evidence.\n", encoding="utf-8")
    # The managed sandbox maps / to nobody and exposes group-writable workspace parents. Model trusted
    # outer ancestors at the OS boundary; permissions of paths within tmp_path remain real and testable.
    outer = {str(path) for path in tmp_path.parents}
    original_lstat = os.lstat

    def trusted_outer(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if str(path) in outer:
            parts = list(info)
            parts[0], parts[4] = info.st_mode & ~0o022, 0
            return os.stat_result(parts)
        return info

    monkeypatch.setattr(os, "lstat", trusted_outer)
    home = tmp_path / "owner"
    passwd_home = tmp_path / "password-home"
    paths = {key: tmp_path / key for key in ("run", "project", "source", "prefix", "live")}
    for folder in (home, passwd_home, *paths.values()):
        folder.mkdir()
    for owner in (home, passwd_home):
        for name in SECRET_PATHS:
            if name in (".netrc", ".git-credentials"):
                (owner / name).touch()
            else:
                (owner / name).mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    def isolated_passwd(uid):
        entry = host_getpwuid(uid)
        return SimpleNamespace(pw_uid=entry.pw_uid, pw_gid=entry.pw_gid, pw_name=entry.pw_name,
                               pw_dir=str(passwd_home))

    monkeypatch.setattr(pwd, "getpwuid", isolated_passwd)
    (paths["prefix"] / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for engine in ("podman", "docker"):
        shutil.copyfile(FAKE, binaries / engine)
        (binaries / engine).chmod(0o755)
    monkeypatch.setenv("PATH", str(binaries) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("AEGIS_FAKE_ENGINE_STATE", str(tmp_path / "engine-state.json"))
    monkeypatch.setenv("AEGIS_FAKE_ENGINE_LOG", str(tmp_path / "engine-argv.jsonl"))
    try:
        yield SimpleNamespace(home=home, passwd_home=passwd_home, outer=sorted(outer), host_lstat=original_lstat, **paths)
    finally:
        os.umask(previous_umask)


@pytest.fixture
def adapter():
    # Lazy import leaves CLI RED observable even before the module exists.
    return importlib.import_module("tools.hierarchy_container")


def config_for(layout):
    return {"schema": "aegis.team-run/v2", "run": str(layout.run), "project": str(layout.project),
            "source": str(layout.source), "recipes": {"python": str(layout.prefix / "bin" / "python")},
            "live_checkouts": [str(layout.live)], "isolation": dict(ISOLATION)}


def fake_engine_call(argv, *, uid=None, gid=None):
    """Run the unchanged fake's public CLI in a fresh module with private OS/account references."""
    spec = importlib.util.spec_from_file_location("container_test_fake", FAKE)
    fake = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fake)
    stdout, stderr = io.StringIO(), io.StringIO()
    fake.sys = SimpleNamespace(argv=argv, stderr=stderr)
    fake.os = SimpleNamespace(**{**vars(os),
                                "getuid": os.getuid if uid is None else lambda: uid,
                                "getgid": os.getgid if gid is None else lambda: gid})
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = fake.main(argv[1:])
    return subprocess.CompletedProcess(argv, code, stdout.getvalue(), stderr.getvalue())


def cli(layout, config, *args, bootstrap="", isolated=False):
    path = layout.run.parent / "team-run.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    argv = [*args, "--config", str(path)]
    if not bootstrap and not isolated:
        adapter = importlib.import_module("tools.hierarchy_container")
        stdout, stderr = io.StringIO(), io.StringIO()
        # The engine is the process boundary. Replace only the adapter's reference, never global run().
        with pytest.MonkeyPatch.context() as patch, redirect_stdout(stdout), redirect_stderr(stderr):
            patch.setattr(adapter, "subprocess", SimpleNamespace(**{
                **vars(adapter.subprocess), "run": lambda command, **kwargs: fake_engine_call(command)}))
            code = adapter.main(argv)
        return subprocess.CompletedProcess(argv, code, stdout.getvalue(), stderr.getvalue())
    # Password database is an OS boundary. Patch it in the child too: changing HOME alone must never hide
    # the real password-database home from production checks, or aim a test at ~/.claude or ~/.codex.
    # Python 3.9's pathlib accessor must capture native OS functions before our lstat double; a captured
    # Python function becomes a bound method and forwards an extra accessor argument to native lstat.
    code = ("import os, pathlib, pwd, runpy, sys; from types import SimpleNamespace; "
            "pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=%r); " % str(layout.passwd_home)
            + "_lstat = os.lstat; _outer = %r; " % layout.outer
            + "os.lstat = lambda p,*a,**kw: (lambda st: os.stat_result([st.st_mode & ~0o022] + list(st)[1:4] "
              "+ [0] + list(st)[5:]) if str(p) in _outer else st)(_lstat(p,*a,**kw)); "
            + bootstrap + "sys.argv = [%r] + sys.argv[1:]; runpy.run_path(%r, run_name='__main__')"
            % (str(SCRIPT), str(SCRIPT)))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-I", "-B", "-c", code, *argv],
                          env=env, capture_output=True, text=True, timeout=15)


def mounts(adapter, layout, **changes):
    args = {"run": layout.run, "project": layout.project, "source": layout.source,
            "python_prefix": layout.prefix, "live_checkouts": [layout.live], "home": layout.home}
    args.update(changes)
    return adapter.mount_plan(**args)


def image_info(image=IMAGE):
    # Modelled default image fixture; its config hash agrees with the fake's image-inspect response.
    config_id = hashlib.sha256(("config:" + image).encode("utf-8")).hexdigest()
    return [{"Id": "sha256:" + config_id, "Digest": image.rsplit("@", 1)[-1], "RepoDigests": [image],
             "Config": {"Env": ["PATH=/venv/bin:/usr/bin", "PYTHONDONTWRITEBYTECODE=1"]}}]


def expected_for(adapter, isolation, **kwargs):
    kwargs.setdefault("image_inspect", image_info(isolation["image"]))
    return adapter.expected_plan(isolation, **kwargs)


@pytest.mark.parametrize("module", ["hierarchy_container", "hierarchy_container_verify"])
def test_container_identity_needs_no_orchestrator(module):
    code = ("import sys; sys.path.insert(0, %r); " % str(SCRIPT.parent)
            + "import %s as adapter; " % module
            + "assert adapter.container_name('/fixture/run').startswith('aegis-team-'); "
              "assert 'hierarchy_team' not in sys.modules; "
              "assert 'hierarchy_provision' not in sys.modules")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_team_import_loads_no_container_modules():
    code = ("import sys; sys.path.insert(0, %r); " % str(SCRIPT.parent)
            + "import hierarchy_team; "
              "assert sorted(name for name in sys.modules if name.startswith('hierarchy_container')) "
              "== []")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_team_absolute_delegates_to_absolute_leaf(adapter, monkeypatch):
    team = importlib.import_module("hierarchy_team")
    verifier = importlib.import_module("hierarchy_absolute")
    calls = []
    expected = Path("/fixture/run")

    def absolute(value, label):
        calls.append((value, label))
        return expected

    monkeypatch.setattr(verifier, "_absolute", absolute)
    assert team.absolute("/fixture/run", "fixture path") is expected
    assert calls == [("/fixture/run", "fixture path")]


@pytest.mark.parametrize("value", [Path("/fixture/run"), b"/fixture/run"])
def test_team_absolute_keeps_string_input_contract(adapter, value):
    team = importlib.import_module("hierarchy_team")
    with pytest.raises(ValueError, match="^invalid fixture path$"):
        team.absolute(value, "fixture path")


def test_verification_leaf_public_contract(adapter, layout):
    verifier = importlib.import_module("hierarchy_container_verify")
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    assert verifier.verify(value, expected) == []
    value[0]["Config"]["User"] = "wrong"
    assert verifier.verify(value, expected) == ["user"]
    assert verifier.verify("[", expected) == ["inspect"]
    assert verifier.verify(value, None) == ["expected"]


def test_container_facade_imports_only_consumed_verifier_names():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported = {alias.asname or alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
                and node.module == "hierarchy_container_verify" for alias in node.names}
    used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    assert imported - used - {"container_name", "verify"} == set()


def test_facade_exposes_every_name_used_by_suite(adapter):
    # Read our tracked source directly: this guard also covers opt-in tests that CI normally skips.
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
             and isinstance(node.value, ast.Name) and node.value.id == "adapter"}
    for function in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
        getters = [node.args[1] for node in ast.walk(function) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "getattr"
                   and len(node.args) >= 2 and isinstance(node.args[0], ast.Name)
                   and node.args[0].id == "adapter"]
        names.update(node.value for node in getters if isinstance(node, ast.Constant))
        for decorator in function.decorator_list:
            if (not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute)
                    or decorator.func.attr != "parametrize" or len(decorator.args) < 2):
                continue
            parameters = [name.strip() for name in ast.literal_eval(decorator.args[0]).split(",")]
            if "builder" in parameters and any(isinstance(node, ast.Name) and node.id == "builder"
                                               for node in getters):
                index = parameters.index("builder")
                for row in decorator.args[1].elts:
                    target = row if len(parameters) == 1 else row.elts[index]
                    names.add(ast.literal_eval(target))
        for loop in (node for node in ast.walk(function) if isinstance(node, ast.For)):
            targets = loop.target.elts if isinstance(loop.target, ast.Tuple) else [loop.target]
            for index, target in enumerate(targets):
                if isinstance(target, ast.Name) and target.id == "builder":
                    for row in loop.iter.elts:
                        names.add(ast.literal_eval(row.elts[index] if isinstance(loop.target, ast.Tuple) else row))
    assert sorted(name for name in names if not hasattr(adapter, name)) == []


@pytest.mark.parametrize("value,expected", [
    ("/fixture/run", Path("/fixture/run")),
    ("relative", (ValueError, "fixture path must be an absolute path without ..: relative")),
    ("/fixture/../run", (ValueError, "fixture path must be an absolute path without ..: /fixture/../run")),
    ("/fixture/\x00run", (ValueError, "invalid fixture path")),
    ("", (ValueError, "invalid fixture path")),
    ("/" + "x" * 4096, (ValueError, "invalid fixture path")),
    (Path("/fixture/run"), Path("/fixture/run")),
    (b"/fixture/run", (ValueError, "invalid fixture path")),
    ("/" + "x" * 4095, Path("/" + "x" * 4095)),
    ("/fixture/./run/", Path("/fixture/run")),
], ids=["absolute", "relative", "parent", "nul", "empty", "too-long", "pathlike", "bytes",
        "length-limit", "lexical-normalization"])
def test_path_contract_matches_independent_oracle(adapter, value, expected):
    team = importlib.import_module("hierarchy_team")
    verifier = importlib.import_module("hierarchy_container_verify")

    def result(check, argument):
        try:
            return check(argument, "fixture path")
        except (ValueError, TypeError) as exc:
            return type(exc), str(exc)

    # This conversion was the adapter boundary before extraction; team.absolute itself takes strings.
    original_argument = os.fspath(value) if isinstance(value, os.PathLike) else value
    assert result(verifier._absolute, value) == expected
    assert result(team.absolute, original_argument) == expected


def test_owner_capture_missing_file_has_documented_diagnostic(adapter, layout, monkeypatch):
    variable = "AEGIS_TEST_C1_HISTORICAL_CAPTURE_DIR"
    root = layout.run.parent / "missing-capture"
    root.mkdir()
    monkeypatch.setenv(variable, str(root))
    with pytest.raises(pytest.fail.Exception) as error:
        test_owner_capture_replay(adapter, layout)
    missing = FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(root / "container-inspect.json"))
    assert str(error.value) == ("%s=%s: invalid container-inspect.json: %s; supply the historical "
                                "real-podman-4.9.3 capture directory" % (variable, root, missing))


@pytest.mark.parametrize("surface", ["plan", "verify", "created"])
def test_matrix_surfaces_do_not_spawn(adapter, layout, monkeypatch, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)

    def unexpected_child(*args, **kwargs):
        pytest.fail("matrix helper spawned a child Python")

    # Replace this test module's reference, leaving pytest and the product's subprocess module intact.
    monkeypatch.setattr(sys.modules[__name__], "subprocess",
                        SimpleNamespace(**{**vars(subprocess), "run": unexpected_child}))
    monkeypatch.setattr(adapter, "subprocess",
                        SimpleNamespace(**{**vars(adapter.subprocess), "run": unexpected_child}))
    verifier = importlib.import_module("hierarchy_container_verify")
    if hasattr(verifier, "subprocess"):
        monkeypatch.setattr(verifier, "subprocess",
                            SimpleNamespace(**{**vars(verifier.subprocess), "run": unexpected_child}))
    if surface == "created":
        expected, value = fake_created_inspect(adapter, layout, ISOLATION)
        assert adapter.verify(value, expected) == []
    elif surface == "verify":
        assert verify_surface(adapter, layout, expected, value, "fake-cli") == []
    else:
        result = cli(layout, config_for(layout), "plan")
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout)["mode"] == "container"


@pytest.mark.parametrize("case", ["host", "plan", "refused", "verify", "mismatch"])
def test_standalone_cli_parity(adapter, layout, case):
    config, args = config_for(layout), ["plan"]
    if case == "host":
        config = {}
    elif case == "refused":
        config["isolation"]["cpus"] = 0
    elif case in ("verify", "mismatch"):
        expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
        value = inspect_for(expected)
        if case == "mismatch":
            value[0]["Config"]["User"] = "wrong"
        path = layout.run.parent / "standalone-inspect.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        args = ["verify", "--inspect", str(path)]
    local = cli(layout, config, *args)
    child = cli(layout, config, *args, isolated=True)
    assert (child.returncode, child.stdout, child.stderr) == (local.returncode, local.stdout, local.stderr)
    assert local.returncode == (2 if case in ("refused", "mismatch") else 0)


@pytest.mark.parametrize("raw", [None, {"mode": "host"}])
def test_host_library(adapter, layout, raw):
    assert adapter.read_isolation(raw, run=layout.run, home=layout.home) is None


@pytest.mark.parametrize("raw", [None, {"mode": "host"}])
def test_host_cli(layout, raw):
    config = {} if raw is None else {"schema": "aegis.team-run/v2", "isolation": raw}
    proc = cli(layout, config, "plan")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"mode": "host", "isolation": None, "mounts": [], "create_argv": None}


def test_cli_pathlib_lstat_preserves_symlink_metadata(layout):
    link = layout.home / "dangling-link"
    link.symlink_to(layout.home / "missing-target")
    # Probe before main's error boundary so a broken child accessor retains its full traceback.
    proc = cli(layout, {}, "plan", bootstrap=(
        "from pathlib import Path; import stat; "
        "assert stat.S_ISLNK(Path(%r).lstat().st_mode); " % str(link)))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout) == {"mode": "host", "isolation": None, "mounts": [], "create_argv": None}


@pytest.mark.parametrize("raw", [None, False, [], "container", 1])
def test_cli_present_isolation_is_not_absence(layout, raw):
    absent = cli(layout, {}, "plan")
    assert absent.returncode == 0
    assert json.loads(absent.stdout) == {"mode": "host", "isolation": None, "mounts": [], "create_argv": None}
    present = cli(layout, {"schema": "aegis.team-run/v2", "isolation": raw}, "plan")
    assert present.returncode == 2
    assert json.loads(present.stdout) == {"error": "isolation must be a JSON object"}


INVALID = [
    ({**ISOLATION, "cpus": 0.001}, "isolation.cpus must be >= 0.01 and <= os.cpu_count()"),
    ([], "isolation must be a JSON object"),
    ({}, "isolation.mode must be host or container"),
    ({"mode": "other"}, "isolation.mode must be host or container"),
    ({"mode": "host", "engine": "podman"}, "isolation host mode accepts only mode"),
    ({**ISOLATION, "extra": True}, "isolation has unknown fields: extra"),
    ({**ISOLATION, "engine": "other"}, "isolation.engine must be podman or docker"),
    ({k: v for k, v in ISOLATION.items() if k != "engine"}, "isolation.engine must be podman or docker"),
    ({**ISOLATION, "image": "ubuntu:24.04"}, "isolation.image must carry @sha256:<64 hex>"),
    ({**ISOLATION, "image": "x@sha256:" + "a" * 63}, "isolation.image must carry @sha256:<64 hex>"),
    ({**ISOLATION, "image": "x@sha256:" + "z" * 64}, "isolation.image must carry @sha256:<64 hex>"),
    ({**ISOLATION, "image": "-x@sha256:" + "a" * 64}, "isolation.image must carry @sha256:<64 hex>"),
    ({**ISOLATION, "image": "x\n@sha256:" + "a" * 64}, "isolation.image must carry @sha256:<64 hex>"),
    ({**ISOLATION, "cpus": 0}, "isolation.cpus must be >= 0.01 and <= os.cpu_count()"),
    ({**ISOLATION, "cpus": -1}, "isolation.cpus must be >= 0.01 and <= os.cpu_count()"),
    ({**ISOLATION, "cpus": True}, "isolation.cpus must be >= 0.01 and <= os.cpu_count()"),
    ({**ISOLATION, "cpus": "1"}, "isolation.cpus must be >= 0.01 and <= os.cpu_count()"),
    ({**ISOLATION, "cpus": 10 ** 9}, "isolation.cpus must be >= 0.01 and <= os.cpu_count()"),
    ({**ISOLATION, "cpus": 10 ** 400}, "isolation.cpus must be >= 0.01 and <= os.cpu_count()"),
    ({**ISOLATION, "memory": "1G"}, "isolation.memory must be <positive int>[kmg]"),
    ({**ISOLATION, "memory": "0g"}, "isolation.memory must be <positive int>[kmg]"),
    ({**ISOLATION, "memory": "1.5g"}, "isolation.memory must be <positive int>[kmg]"),
    ({**ISOLATION, "memory": 1024}, "isolation.memory must be <positive int>[kmg]"),
    ({**ISOLATION, "pids": 63}, "isolation.pids must be an integer >= 64"),
    ({**ISOLATION, "pids": True}, "isolation.pids must be an integer >= 64"),
    ({**ISOLATION, "pids": 64.0}, "isolation.pids must be an integer >= 64"),
    ({**ISOLATION, "allow_unqualified": 1}, "isolation.allow_unqualified must be a bool"),
    ({**ISOLATION, "engine": "docker"}, "docker is unqualified; set isolation.allow_unqualified to true"),
]


@pytest.mark.parametrize("raw,message", INVALID)
def test_validation_cli(layout, raw, message):
    config = config_for(layout)
    config["isolation"] = raw
    proc = cli(layout, config, "plan")
    assert proc.returncode == 2, proc.stderr
    assert json.loads(proc.stdout) == {"error": message}
    assert list(layout.run.iterdir()) == []


@pytest.mark.parametrize("field", ["image", "cpus", "memory", "pids"])
def test_missing_required(adapter, layout, field):
    raw = dict(ISOLATION)
    del raw[field]
    message = {"image": "isolation.image must carry @sha256:<64 hex>",
               "cpus": "isolation.cpus must be >= 0.01 and <= os.cpu_count()",
               "memory": "isolation.memory must be <positive int>[kmg]",
               "pids": "isolation.pids must be an integer >= 64"}[field]
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        adapter.read_isolation(raw, run=layout.run, home=layout.home)


def test_platform_and_unknown_cpu(adapter, layout, monkeypatch):
    monkeypatch.setattr(adapter.sys, "platform", "darwin")
    with pytest.raises(ValueError, match="^container isolation requires Linux$"):
        adapter.read_isolation(ISOLATION, run=layout.run, home=layout.home)
    monkeypatch.setattr(adapter.sys, "platform", "linux")
    monkeypatch.setattr(adapter.os, "cpu_count", lambda: None)
    with pytest.raises(ValueError, match=r"^isolation.cpus must be >= 0.01 and <= os.cpu_count\(\)$"):
        adapter.read_isolation(ISOLATION, run=layout.run, home=layout.home)


def test_valid_limits(adapter, layout, monkeypatch):
    monkeypatch.setattr(adapter.os, "cpu_count", lambda: 2)
    for cpus in (0.01, 0.5, 2):
        for memory in ("1k", "128m", "16g"):
            value = {**ISOLATION, "cpus": cpus, "memory": memory}
            assert adapter.read_isolation(value, run=layout.run, home=layout.home) == {
                **value, "allow_unqualified": False}
    for cpus in (float("nan"), float("inf")):
        with pytest.raises(ValueError, match=r"^isolation.cpus must be >= 0.01 and <= os.cpu_count\(\)$"):
            adapter.read_isolation({**ISOLATION, "cpus": cpus}, run=layout.run, home=layout.home)


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
@pytest.mark.parametrize("child", ["", *SECRET_PATHS, ".codex/sessions", ".claude/projects", ".config/gh"])
def test_protected_home(adapter, layout, owner, child):
    path = getattr(layout, owner) / child
    with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(path)) + "$"):
        mounts(adapter, layout, project=path)


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
def test_documents_project_and_venv_allowed_cli(layout, owner):
    documents = getattr(layout, owner) / "Documents"
    project, prefix = documents / "project", documents / "venv"
    project.mkdir(parents=True)
    prefix.mkdir()
    (prefix / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    config = config_for(layout)
    config["project"] = str(project)
    config["recipes"]["python"] = str(prefix / "bin" / "python")
    proc = cli(layout, config, "plan")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    planned = json.loads(proc.stdout)["mounts"]
    assert {"source": str(project), "destination": str(project), "rw": True} in planned
    assert {"source": str(prefix), "destination": str(prefix), "rw": False} in planned


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
def test_documents_containing_relocated_secret_refused_cli(layout, owner):
    home = getattr(layout, owner)
    documents = home / "Documents"
    credentials = documents / "credentials"
    credentials.mkdir(parents=True)
    config = config_for(layout)
    config["project"] = str(documents)
    proc = cli(layout, config, "plan")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    (home / ".codex").rmdir()
    (home / ".codex").symlink_to(credentials, target_is_directory=True)
    proc = cli(layout, config, "plan")
    assert proc.returncode == 2, proc.stderr
    assert json.loads(proc.stdout) == {"error": "mount overlaps protected home: " + str(documents)}


def test_mount_inode_alias_contains_relocated_secret(adapter, layout, monkeypatch):
    parent = layout.run.parent / "relocated-parent"
    credentials = parent / "credentials"
    credentials.mkdir(parents=True)
    (layout.home / ".codex").rmdir()
    (layout.home / ".codex").symlink_to(credentials, target_is_directory=True)
    original_stat, identity = os.stat, parent.stat()

    def bind_stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if Path(path) == layout.project:
            return SimpleNamespace(st_dev=identity.st_dev, st_ino=identity.st_ino, st_mode=info.st_mode)
        return info

    monkeypatch.setattr(adapter.os, "stat", bind_stat)
    with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(layout.project)) + "$"):
        mounts(adapter, layout)


def test_all_three_owner_homes_remain_protected(adapter, layout):
    explicit_home = layout.run.parent / "explicit-owner"
    project, prefix = explicit_home / "Documents" / "project", explicit_home / "Documents" / "venv"
    project.mkdir(parents=True)
    prefix.mkdir()
    plan = mounts(adapter, layout, home=explicit_home, project=project, python_prefix=prefix)
    assert {"source": str(project), "destination": str(project), "rw": True} in plan
    for owner in (explicit_home, layout.home, layout.passwd_home):
        with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(owner)) + "$"):
            mounts(adapter, layout, home=explicit_home, project=owner)
        secret = owner / ".ssh"
        secret.mkdir(exist_ok=True)
        with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(secret)) + "$"):
            mounts(adapter, layout, home=explicit_home, project=secret)


def test_missing_secrets_are_not_created_or_enumerated(adapter, layout, monkeypatch):
    missing = layout.home / ".ssh"
    missing.rmdir()

    def no_enumeration(*args, **kwargs):
        raise AssertionError("mount planning must not enumerate directories")

    with monkeypatch.context() as m:
        m.setattr(os, "scandir", no_enumeration)
        mounts(adapter, layout)
    assert not missing.exists()


def test_mount_contains_home(adapter, layout):
    with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(layout.home.parent)) + "$"):
        mounts(adapter, layout, project=layout.home.parent)


@pytest.mark.parametrize("name", [".claude", ".codex"])
def test_protected_config_relocated_outside_home(adapter, layout, name):
    relocated = layout.run.parent / "relocated"
    relocated.mkdir()
    (layout.home / name).rmdir()
    (layout.home / name).symlink_to(relocated, target_is_directory=True)
    with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(relocated)) + "$"):
        mounts(adapter, layout, project=relocated)


def test_password_home_unavailable(adapter, layout, monkeypatch):
    import pwd

    def unavailable(uid):
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", unavailable)
    with pytest.raises(ValueError, match="^cannot find the owner's password-database home$"):
        mounts(adapter, layout)


@pytest.mark.parametrize("suffix", ["", ".claude", ".codex"])
def test_symlink_alias(adapter, layout, suffix):
    alias = layout.run.parent / "alias"
    alias.symlink_to(layout.home / suffix, target_is_directory=True)
    with pytest.raises(ValueError, match="^mount source contains a symlink: " + re.escape(str(alias)) + "$"):
        mounts(adapter, layout, project=alias)


def test_symlink_ancestor_and_relative(adapter, layout):
    alias = layout.run.parent / "alias"
    alias.symlink_to(layout.project, target_is_directory=True)
    with pytest.raises(ValueError, match="^mount source contains a symlink: " + re.escape(str(alias)) + "$"):
        mounts(adapter, layout, project=alias / "child")
    for path in ("relative", str(layout.project / ".." / "project")):
        with pytest.raises(ValueError, match="^project must be an absolute path without "):
            mounts(adapter, layout, project=path)


@pytest.mark.parametrize("suffix", [",readonly", ":bad"])
def test_mount_argument_injection_refused(adapter, layout, suffix):
    path = layout.project / ("source" + suffix)
    with pytest.raises(ValueError, match="^mount source contains an unsupported character: " + re.escape(str(path)) + "$"):
        mounts(adapter, layout, project=path)


@pytest.mark.parametrize("target", ["home", ".claude", ".codex", "ancestor", "secret-ancestor"])
def test_inode_alias_checks_every_ancestor(adapter, layout, monkeypatch, target):
    # Model bind mounts at the stat boundary; no mount privileges or secret reads required.
    alias = layout.run.parent / "bind-alias"
    alias.mkdir()
    protected = (layout.home if target in ("home", "ancestor") else
                 layout.home / (".codex" if target == "secret-ancestor" else target))
    identity = protected.stat()
    original_stat = os.stat

    def bind_stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if Path(path) == alias:
            return SimpleNamespace(st_dev=identity.st_dev, st_ino=identity.st_ino, st_mode=info.st_mode)
        return info

    monkeypatch.setattr(adapter.os, "stat", bind_stat)
    candidate = alias / "missing" / "child" if target in ("ancestor", "secret-ancestor") else alias
    if target == "ancestor":
        plan = mounts(adapter, layout, project=candidate)
        assert {"source": str(candidate), "destination": str(candidate), "rw": True} in plan
        return
    with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(candidate)) + "$"):
        mounts(adapter, layout, project=candidate)


@pytest.mark.parametrize("kind", ["equal", "rw-parent", "ro-parent", "inode"])
def test_rw_ro_overlap(adapter, layout, monkeypatch, kind):
    source, project = layout.source, layout.project
    if kind == "equal":
        source = project
    elif kind == "rw-parent":
        source = project / "runtime"
    elif kind == "ro-parent":
        project = source / "project"
    else:
        original_stat, identity = os.stat, project.stat()

        def bind_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if Path(path) == source:
                return SimpleNamespace(st_dev=identity.st_dev, st_ino=identity.st_ino, st_mode=info.st_mode)
            return info

        monkeypatch.setattr(adapter.os, "stat", bind_stat)
    with pytest.raises(ValueError, match="^read-write and read-only mounts overlap: "):
        mounts(adapter, layout, project=project, source=source)


def test_inode_alias_with_missing_tails_on_both_sides(adapter, layout, monkeypatch):
    alias = layout.run.parent / "parent-alias"
    alias.mkdir()
    original_stat, identity = os.stat, layout.project.stat()

    def bind_stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if Path(path) == alias:
            return SimpleNamespace(st_dev=identity.st_dev, st_ino=identity.st_ino, st_mode=info.st_mode)
        return info

    monkeypatch.setattr(adapter.os, "stat", bind_stat)
    with pytest.raises(ValueError, match="^read-write and read-only mounts overlap: "):
        mounts(adapter, layout, project=layout.project / "missing", source=alias / "missing" / "runtime")


def test_mount_plan_is_sorted_same_path_and_deduplicated(adapter, layout):
    plan = mounts(adapter, layout, live_checkouts=[layout.live, layout.source, layout.live])
    assert plan == sorted([
        {"source": str(folder), "destination": str(folder), "rw": rw}
        for folder, rw in ((layout.run, True), (layout.project, True), (layout.source, False),
                           (layout.prefix, False), (layout.live, False))], key=lambda row: row["source"])


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_create_golden(adapter, layout, engine):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    plan = mounts(adapter, layout)
    name = "aegis-team-" + hashlib.sha256(str(layout.run).encode()).hexdigest()[:12]
    expected = [engine, "run", "-d", "--name", name, "--label", "aegis.team.run=" + str(layout.run),
                "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--tmpfs", "/dev/shm:rw,nosuid,nodev", "--init", "--cpus", "1", "--memory", "1g",
                "--pids-limit", "64", "--ipc=private", "--network=bridge"]
    expected += (["--pid=private", "--userns=keep-id", "--security-opt=unmask=/proc/*", "--env-host=false",
                  "--http-proxy=false", "--read-only-tmpfs=false"] if engine == "podman" else
                 ["--user", "1234:5678", "--security-opt", "systempaths=unconfined"])
    environment = {"HOME": str(layout.run / "home"), "CODEX_HOME": str(layout.run / "codex-home"),
                   "CLAUDE_CONFIG_DIR": str(layout.run / "claude-home"), "LANG": "C.UTF-8",
                   "PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    for key, value in sorted(environment.items()):
        expected += ["--env", key + "=" + value]
    for row in plan:
        expected += ["--mount", "type=bind,src={source},dst={destination}".format(**row)
                     + ("" if row["rw"] else ",readonly")]
    expected += [IMAGE, "/bin/sleep", "infinity"]
    argv = adapter.create_argv(isolation, run=layout.run, mounts=plan, uid=1234, gid=5678,
                               env={"LANG": "C.UTF-8"})
    assert argv == expected
    assert "--env-host" not in argv
    assert not any(word.startswith("--cap-add") for word in argv)


def test_environment_refuses_secrets_and_home_override(adapter, layout):
    for env, message in (({"SSH_AUTH_SOCK": "/secret"}, "environment variables not allowlisted: SSH_AUTH_SOCK"),
                         ({"HOME": "/owner"}, "container HOME is fixed inside the run"),
                         ({"LANG": "C\x00bad"}, "invalid environment value: LANG")):
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            adapter.create_argv(ISOLATION, run=layout.run, mounts=mounts(adapter, layout), env=env)


def container_registry(monkeypatch, entries, kinds=None):
    verifier = importlib.import_module("hierarchy_container_verify")
    registry = importlib.import_module("hierarchy_hosts")

    def entry(kind):
        value = entries[kind] if kind in entries else registry.entry(kind)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    # Replace only the consumer's module reference, never the shared registry.
    monkeypatch.setattr(verifier, "hierarchy_hosts", SimpleNamespace(
        TEAM_HOSTS=registry.TEAM_HOSTS if kinds is None else kinds, entry=entry))


def test_registry_host_environment_golden(adapter, layout):
    assert json.dumps(adapter.container_env(layout.run), sort_keys=True) == json.dumps({
        "PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
        "HOME": str(layout.run / "home"), "CODEX_HOME": str(layout.run / "codex-home"),
        "CLAUDE_CONFIG_DIR": str(layout.run / "claude-home")}, sort_keys=True)


def test_registry_new_host_needs_no_container_edit(adapter, layout, monkeypatch):
    registry = importlib.import_module("hierarchy_hosts")
    extra = {"kind": "fixture-host", "home": {"variable": "FIXTURE_HOST_HOME", "run_folder": "fixture-home"}}
    container_registry(monkeypatch, {"fixture-host": extra}, (*registry.TEAM_HOSTS, "fixture-host"))
    fixed = str(layout.run / "fixture-home")
    assert adapter.container_env(layout.run)["FIXTURE_HOST_HOME"] == fixed
    for argv in (adapter.create_argv(ISOLATION, run=layout.run, mounts=[], uid=1234, gid=5678),
                 adapter.exec_argv("podman", layout.run, ["true"], workdir=layout.project)):
        assert "FIXTURE_HOST_HOME=" + fixed in argv
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=[], uid=1234, gid=5678)
    value = inspect_for(expected, {"FIXTURE_HOST_HOME": fixed})
    assert adapter.verify(value, expected) == []
    with pytest.raises(ValueError, match="^container FIXTURE_HOST_HOME is fixed inside the run$"):
        adapter.container_env(layout.run, {"FIXTURE_HOST_HOME": "/outside"})
    # Matching tampered expected/actual values cannot authorize a different host home.
    fingerprint = json.dumps(["FIXTURE_HOST_HOME", "/outside"], separators=(",", ":")).encode("utf-8")
    expected["environment"]["FIXTURE_HOST_HOME"] = hashlib.sha256(fingerprint).hexdigest()
    value[0]["Config"]["Env"] = ["FIXTURE_HOST_HOME=/outside" if item.startswith("FIXTURE_HOST_HOME=")
                                  else item for item in value[0]["Config"]["Env"]]
    value[0]["Config"]["CreateCommand"] = ["FIXTURE_HOST_HOME=/outside" if item.startswith("FIXTURE_HOST_HOME=")
                                            else item for item in value[0]["Config"]["CreateCommand"]]
    assert adapter.verify(value, expected) == ["environment"]


@pytest.mark.parametrize("case", ["unknown", "entry", "entry-type-error", "entry-recursion", "kind", "home",
    "variable-missing", "variable-type",
    "variable-invalid", "variable-long", "variable-reserved", "variable-duplicate", "folder-missing",
    "folder-type", "folder-empty", "folder-parent", "folder-absolute", "folder-slash", "folder-backslash",
    "folder-long", "folder-reserved", "folder-duplicate", "kinds-empty", "kinds-type", "kinds-long"])
def test_registry_malformed_host_refuses(adapter, layout, monkeypatch, case):
    registry = importlib.import_module("hierarchy_hosts")
    kinds = registry.TEAM_HOSTS
    kind = kinds[0]
    entry = registry.entry(kind)
    if case == "unknown":
        kinds = (*kinds, "untrusted-registry-sentinel")
    elif case == "entry":
        entry = []
    elif case == "entry-type-error":
        entry = TypeError("untrusted-registry-sentinel")
    elif case == "entry-recursion":
        entry = RecursionError("untrusted-registry-sentinel")
    elif case == "kind":
        entry["kind"] = "untrusted-registry-sentinel"
    elif case == "home":
        entry["home"] = None
    elif case.endswith("-missing"):
        del entry["home"]["variable" if case.startswith("variable") else "run_folder"]
    elif case.startswith("variable-"):
        entry["home"]["variable"] = {"type": [], "invalid": "untrusted-registry-sentinel=bad",
            "long": "X" * 129, "reserved": "PATH", "duplicate": registry.entry(kinds[1])["home"]["variable"]}[
                case[len("variable-"):]]
    elif case.startswith("folder-"):
        entry["home"]["run_folder"] = {"type": None, "empty": "", "parent": "..", "absolute": "/outside",
            "slash": "x/y", "backslash": "x\\y", "long": "x" * 129, "reserved": "home",
            "duplicate": registry.entry(kinds[1])["home"]["run_folder"]}[case[len("folder-"):]]
    elif case == "kinds-empty":
        kinds = ()
    elif case == "kinds-type":
        kinds = "untrusted-registry-sentinel"
    elif case == "kinds-long":
        kinds = (kind,) * 65
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=[], uid=1234, gid=5678)
    value = inspect_for(expected)
    container_registry(monkeypatch, {kind: entry}, kinds)
    with pytest.raises(ValueError, match="^invalid container host registry$"):
        adapter.container_env(layout.run)
    assert adapter.verify(value, expected) == ["environment"]
    result = cli(layout, config_for(layout), "plan")
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": "invalid container host registry"}


def test_other_argv_builders(adapter, layout):
    run = layout.run
    name = "aegis-team-" + hashlib.sha256(str(run).encode()).hexdigest()[:12]
    assert adapter.inspect_argv("podman", run) == ["podman", "container", "inspect", name]
    assert adapter.stop_argv("docker", run, timeout=7) == ["docker", "stop", "--time", "7", name]
    assert adapter.rm_argv("podman", run) == ["podman", "rm", name]
    assert adapter.image_inspect_argv("docker", IMAGE) == ["docker", "image", "inspect", IMAGE]
    assert adapter.build_image_argv("podman", context=layout.source, containerfile=layout.source / "Containerfile",
                                    tag="localhost/aegis-teams:c2") == [
        "podman", "build", "--file", str(layout.source / "Containerfile"), "--tag", "localhost/aegis-teams:c2",
        str(layout.source)]
    argv = adapter.exec_argv("docker", run, ["id", "-u"], workdir=layout.project, env={"LANG": "C"})
    assert argv[:4] == ["docker", "exec", "--workdir", str(layout.project)]
    assert argv[-3:] == [name, "id", "-u"]
    assert "LANG=C" in argv and "HOME=" + str(run / "home") in argv
    assert "--env-host" not in argv
    with pytest.raises(ValueError, match="^stop timeout must be a positive integer$"):
        adapter.stop_argv("podman", run, timeout=0)


def test_exec_preserves_empty_arguments(adapter, layout):
    argv = adapter.exec_argv("podman", layout.run, ["printf", "%s", ""], workdir=layout.project)
    assert argv[-3:] == ["printf", "%s", ""]


def inspect_id_map(identity):
    before = min(identity, 65536)
    rows = (["0:1:%d" % before] if before else []) + ["%d:0:1" % identity]
    if before < 65536:
        rows.append("%d:%d:%d" % (identity + 1, before + 1, 65536 - before))
    return rows


def inspect_for(expected, env=None):
    uid, gid = map(int, expected["user"].split(":"))
    podman = expected["engine"] == "podman"
    # Positive model records carry the environment actually requested by the golden create argv.
    environment = {"HOME": expected["run"] + "/home", "CODEX_HOME": expected["run"] + "/codex-home",
                   "CLAUDE_CONFIG_DIR": expected["run"] + "/claude-home",
                   "PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    environment.update(env or {})
    env_argv = [word for key, value in sorted(environment.items()) for word in ("--env", key + "=" + value)]
    # Observed Podman plain name; Docker's single slash is modelled from Moby v27.5.1 daemon/names.go.
    name = "aegis-team-" + hashlib.sha256(expected["run"].encode()).hexdigest()[:12]
    value = [{"Name": name if podman else "/" + name,
             "Config": {"Labels": {"aegis.team.run": expected["run"]}, "User": expected["user"],
                        "Image": expected["image"], "Env": [key + "=" + value for key, value in sorted(environment.items())],
                        "CreateCommand": ["podman", "run", "--security-opt=unmask=/proc/*", "--env-host=false",
                                          "--http-proxy=false", "--read-only-tmpfs=false", *env_argv, expected["image"]]},
             "Image": expected["image_info"]["id"],
             "ImageDigest": expected["image"].split("@")[1],
             "Mounts": [{"Type": "bind", "Source": m["source"], "Destination": m["destination"], "RW": m["rw"]}
                        for m in expected["mounts"]], "HostConfig": {
                            "ReadonlyRootfs": True, "Privileged": False, "CapAdd": [], "Devices": [],
                            "PidMode": "private", "IpcMode": "private", "NetworkMode": "bridge",
                            "UsernsMode": "private" if podman else "",
                            "SecurityOpt": [] if podman else ["systempaths=unconfined"],
                            "IDMappings": {"UidMap": inspect_id_map(uid), "GidMap": inspect_id_map(gid)},
                            "NanoCpus": 1000000000, "Memory": 1073741824, "PidsLimit": 64,
                            "Tmpfs": {"/tmp": "rw,nosuid,nodev,rprivate,tmpcopyup",
                                      "/dev/shm": "rw,nosuid,nodev,rprivate,tmpcopyup"}}}]
    if not podman:
        del value[0]["Config"]["CreateCommand"]  # Not part of Moby's inspect schema.
    return value


@pytest.mark.parametrize("field", [None, "label", "image", "mounts", "read_only", "user"])
def test_verify_tampering(adapter, layout, field):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    obj = value[0]
    if field == "label":
        obj["Config"]["Labels"]["aegis.team.run"] = "/other"
    elif field == "image":
        obj["ImageDigest"] = "sha256:" + "b" * 64
    elif field == "mounts":
        obj["Mounts"][0]["RW"] = not obj["Mounts"][0]["RW"]
    elif field == "read_only":
        obj["HostConfig"]["ReadonlyRootfs"] = False
    elif field == "user":
        obj["Config"]["User"] = "0:0"
    obj["FutureEngineField"] = {"anything": [1, 2, 3]}
    assert adapter.verify(value, expected) == ([] if field is None else [field])
    assert adapter.verify(json.dumps(value), expected) == ([] if field is None else [field])


@pytest.mark.parametrize("tamper", ["source", "destination", "missing", "extra", "duplicate", "tmpfs", "wrong-type"])
def test_verify_exact_mounts(adapter, layout, tamper):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    rows = value[0]["Mounts"]
    if tamper in ("source", "destination"):
        rows[0][tamper.title()] = "/changed"
    elif tamper == "missing":
        rows.pop()
    elif tamper == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif tamper == "wrong-type":
        rows[0]["Type"] = "volume"
    else:
        rows.append({"Type": "tmpfs" if tamper == "tmpfs" else "bind", "Source": "x",
                     "Destination": "/extra", "RW": True})
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("value", [None, [], [1], [{}, {}], "bad json", {"Config": None, "Mounts": None}])
def test_verify_malformed_never_raises(adapter, layout, value):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    assert adapter.verify(value, expected)


def test_docker_inspect_and_declared_tmpfs(adapter, layout):
    expected = expected_for(adapter, {**ISOLATION, "engine": "docker", "allow_unqualified": True},
                                     run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    del value[0]["ImageDigest"]  # Docker records the manifest reference in Config.Image, Image is a config ID.
    value[0]["Image"] = expected["image_info"]["id"]
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True})
    assert adapter.verify(value, expected) == []
    value[0]["Image"] = "sha256:" + "c" * 64
    assert adapter.verify(value, expected) == ["image"]


def test_plan_and_verify_cli(adapter, layout):
    config = config_for(layout)
    proc = cli(layout, config, "plan")
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    assert plan["mode"] == "container" and plan["isolation"] == {**ISOLATION, "allow_unqualified": False}
    assert plan["create_argv"][:3] == ["podman", "run", "-d"]
    assert len(plan["mounts"]) == 5
    path = layout.run.parent / "inspect.json"
    value = inspect_for(expected_for(adapter, plan["isolation"], run=config["run"], mounts=plan["mounts"]))
    path.write_text(json.dumps(value), encoding="utf-8")
    proc = cli(layout, config, "verify", "--inspect", str(path))
    assert proc.returncode == 0 and json.loads(proc.stdout) == {"mismatches": []}
    value[0]["Config"]["User"] = "wrong"
    path.write_text(json.dumps(value), encoding="utf-8")
    proc = cli(layout, config, "verify", "--inspect", str(path))
    assert proc.returncode == 2 and json.loads(proc.stdout) == {"mismatches": ["user"]}
    assert list(layout.run.iterdir()) == []  # A plan never starts an engine or creates homes.


def test_cli_missing_inspect_and_internal_error(layout):
    proc = cli(layout, config_for(layout), "verify", "--inspect", str(layout.run / "missing.json"))
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["error"] == "file unavailable: " + str(layout.run / "missing.json")
    proc = cli(layout, config_for(layout), "plan", bootstrap=(
        "import os; os.cpu_count = lambda: (_ for _ in ()).throw(RuntimeError('fixture internal')); "))
    assert proc.returncode == 3
    assert json.loads(proc.stdout) == {"error": "internal error: fixture internal"}


def test_isolation_requires_v2_and_host_cannot_verify(layout):
    config = config_for(layout)
    config["schema"] = "aegis.team-run/v1"
    proc = cli(layout, config, "plan")
    assert proc.returncode == 2 and json.loads(proc.stdout) == {
        "error": "isolation requires schema aegis.team-run/v2"}
    proc = cli(layout, {}, "verify", "--inspect", str(layout.run / "not-read.json"))
    assert proc.returncode == 2 and json.loads(proc.stdout) == {"error": "verify requires container isolation"}


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_fake_engine_round_trip(adapter, layout, monkeypatch, engine):
    executable = layout.run.parent / engine
    shutil.copyfile(FAKE, executable)
    executable.chmod(0o755)
    state, log = layout.run.parent / "fake-state.json", layout.run.parent / "fake-argv.jsonl"
    monkeypatch.setenv("AEGIS_FAKE_ENGINE_STATE", str(state))
    monkeypatch.setenv("AEGIS_FAKE_ENGINE_LOG", str(log))
    monkeypatch.setenv("SSH_AUTH_SOCK", "/fixture/host-socket-must-not-leak")
    monkeypatch.setenv("HTTPS_PROXY", "fixture-ambient-proxy")
    monkeypatch.setenv("PATH", str(executable.parent) + os.pathsep + os.environ["PATH"])

    def call(argv):
        return subprocess.run(argv, capture_output=True, text=True, timeout=15)

    plan = mounts(adapter, layout)
    isolation = {**ISOLATION, "engine": engine, "cpus": 0.29, "allow_unqualified": engine == "docker"}
    inspected_image = call(adapter.image_inspect_argv(engine, IMAGE))
    assert inspected_image.returncode == 0
    expected = expected_for(adapter, isolation, run=layout.run, mounts=plan, image_inspect=inspected_image.stdout)
    create = adapter.create_argv(isolation, run=layout.run, mounts=plan)
    proc = call(create)
    assert proc.returncode == 0 and re.fullmatch(r"[0-9a-f]{64}\n", proc.stdout), proc.stderr
    inspected = json.loads(call(adapter.inspect_argv(engine, layout.run)).stdout)
    host = inspected[0]["HostConfig"]
    if engine == "podman":
        assert host["UsernsMode"] == "private" and host["SecurityOpt"] == []
        assert host["CpuPeriod"] == 100000 and host["CpuQuota"] == 28999 and host["NanoCpus"] == 289990000
        assert "IDMappings" in host
        assert all(bind.endswith(",rprivate,rbind") for bind in host["Binds"])
    else:
        assert host["PidMode"] == "" and host["UsernsMode"] == "" and "IDMappings" not in host
        assert "ImageDigest" not in inspected[0] and "--pid=private" not in create
    assert not any(item.startswith("HTTPS_PROXY=") for item in inspected[0]["Config"]["Env"])
    assert adapter.verify(inspected, expected) == []
    command = [sys.executable, "-c", "import json, os; print(json.dumps([os.getcwd(), os.environ['LANG'], "
               "os.environ['HOME'], 'SSH_AUTH_SOCK' in os.environ]))"]
    proc = call(adapter.exec_argv(engine, layout.run, command, workdir=layout.project, env={"LANG": "C"}))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == [str(layout.project), "C", str(layout.run / "home"), False]
    failing = call(adapter.exec_argv(engine, layout.run, [sys.executable, "-c", "raise SystemExit(7)"],
                                     workdir=layout.project))
    assert failing.returncode == 7
    assert json.loads(log.read_text(encoding="utf-8").splitlines()[1]) == create[1:]
    refused = call([engine, "system", "prune"])
    assert refused.returncode == 2 and refused.stderr == "fake engine: unsupported command: system\n"
    refused = call([engine, "run", "--privileged"])
    assert refused.returncode == 2 and refused.stderr == "fake engine: unsupported option: --privileged\n"
    assert call(create).stderr == "fake engine: container already exists: " + adapter.container_name(layout.run) + "\n"
    assert call(adapter.rm_argv(engine, layout.run)).returncode == 2
    assert call(adapter.stop_argv(engine, layout.run)).returncode == 0
    assert call(adapter.exec_argv(engine, layout.run, ["id"], workdir=layout.project)).returncode == 2
    assert call(adapter.rm_argv(engine, layout.run)).returncode == 0
    assert call(adapter.inspect_argv(engine, layout.run)).stderr == (
        "fake engine: no such container: " + adapter.container_name(layout.run) + "\n")


@pytest.mark.parametrize("case", ["foreign", "sticky", "group-writable"])
def test_mount_ancestor_trust(adapter, layout, monkeypatch, case):
    original = os.lstat
    original_getxattr = os.getxattr
    uid = os.geteuid()
    shared_uid = uid + 1 if case == "foreign" else uid
    shared_mode = 0o770 if case == "group-writable" else 0o700
    virtual = {Path("/tmp"): (0, 0o1777), Path("/tmp/shared"): (shared_uid, shared_mode),
               Path("/tmp/shared/project"): (uid, 0o700)}

    def lstat(path, *args, **kwargs):
        if Path(path) in virtual:
            owner, mode = virtual[Path(path)]
            return SimpleNamespace(st_uid=owner, st_gid=os.getegid() + 1, st_mode=stat.S_IFDIR | mode)
        return original(path, *args, **kwargs)

    def getxattr(path, name, **kwargs):
        # The virtual directories also model authoritative ACL absence, not a real nonexistent path.
        if Path(path) in virtual:
            assert name == "system.posix_acl_access" and kwargs == {"follow_symlinks": False}
            raise OSError(errno.ENODATA, "modelled ACL absence")
        return original_getxattr(path, name, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "getxattr", getxattr)
    if case == "sticky":
        plan = mounts(adapter, layout, project="/tmp/shared/project")
        assert {"source": "/tmp/shared/project", "destination": "/tmp/shared/project", "rw": True} in plan
    else:
        reason = "owned by another user" if case == "foreign" else "writable by other users"
        message = "mount component %s: /tmp/shared (uid %d)" % (reason, shared_uid)
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            mounts(adapter, layout, project="/tmp/shared/project")


@pytest.mark.parametrize("path", ["/", "/usr", "/usr/local", "/opt", "/run", "/etc", "/tmp"])
def test_image_system_mount_refused(adapter, layout, path):
    with pytest.raises(ValueError, match="^mount replaces image system directory: " + re.escape(path) + "$"):
        mounts(adapter, layout, project=path)


def test_local_prefix_and_inferred_non_venv_refuse(adapter, layout):
    local = layout.home / ".local"
    with pytest.raises(ValueError, match="^mount replaces image system directory: " + re.escape(str(local)) + "$"):
        mounts(adapter, layout, python_prefix=local)
    (layout.prefix / "pyvenv.cfg").unlink()
    config = config_for(layout)
    proc = cli(layout, config, "plan")
    assert proc.returncode == 2 and json.loads(proc.stdout) == {
        "error": "python_prefix requires pyvenv.cfg or an explicit config key"}
    config["python_prefix"] = str(layout.prefix)
    proc = cli(layout, config, "plan")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_dangling_secret_protects_target(adapter, layout):
    (layout.home / ".codex").rmdir()
    target = layout.run.parent / "unmounted-vault" / "codex"
    (layout.home / ".codex").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(str(target.parent)) + "$"):
        mounts(adapter, layout, project=target.parent)


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
@pytest.mark.parametrize("tamper", ["relative", "destination", "comma", "newline", "colon", "rw", "extra", "image"])
def test_builders_revalidate_stored_plan(adapter, layout, builder, tamper):
    plan = mounts(adapter, layout)
    isolation = dict(ISOLATION)
    message = ""
    if tamper == "relative":
        plan[0]["source"] = "relative"
        message = "mount source must be an absolute path without ..: relative"
    elif tamper == "destination":
        plan[0]["destination"] = "/other"
        message = "mount source and destination must be equal"
    elif tamper in ("comma", "newline", "colon"):
        value = str(layout.project) + {"comma": ",readonly", "newline": "\nbad", "colon": ":bad"}[tamper]
        plan[0]["source"] = plan[0]["destination"] = value
        message = "mount source contains an unsupported character: " + value
    elif tamper == "rw":
        plan[0]["rw"] = "false"
        message = "mount row rw must be a bool"
    elif tamper == "extra":
        plan[0]["extra"] = True
        message = "mount row must contain only source, destination and rw"
    else:
        isolation["image"] = "ubuntu:24.04"
        message = "isolation.image must carry @sha256:<64 hex>"
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        getattr(adapter, builder)(isolation, run=layout.run, mounts=plan, **(
            {"image_inspect": image_info(isolation["image"])} if builder == "expected_plan" else {}))


@pytest.mark.parametrize("tamper", ["tmpfs", "binds", "conflict", "duplicate-tmpfs"])
def test_docker_writable_mount_declarations(adapter, layout, tamper):
    isolation = {**ISOLATION, "engine": "docker", "allow_unqualified": True}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    host = value[0]["HostConfig"]
    if tamper == "tmpfs":
        host["Tmpfs"] = {"/tmp": "rw", "/var/lib/extra": "rw"}
    elif tamper == "binds":
        host["Binds"] = ["/other:/other:rw"]
    elif tamper == "duplicate-tmpfs":
        value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True})
        host["Tmpfs"] = {"/tmp": "ro"}
    else:
        row = expected["mounts"][0]
        host["Binds"] = ["%s:%s:%s" % (row["source"], row["destination"], "ro" if row["rw"] else "rw")]
    assert adapter.verify(value, expected) == ["mounts"]


def test_docker_mount_representations_agree(adapter, layout):
    expected = expected_for(adapter, {**ISOLATION, "engine": "docker", "allow_unqualified": True},
                                     run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    # Modelled Moby v27.5.1: MountPoint has Mode/RW, not Options; --tmpfs lives in HostConfig.Tmpfs.
    # https://github.com/moby/moby/blob/v27.5.1/api/types/container/hostconfig.go
    value[0]["HostConfig"]["Tmpfs"] = {"/tmp": "rw,nosuid,nodev", "/dev/shm": "rw,nosuid,nodev"}
    value[0]["HostConfig"]["Binds"] = ["%s:%s:%s" % (m["source"], m["destination"], "rw" if m["rw"] else "ro")
                                        for m in expected["mounts"]]
    assert adapter.verify(value, expected) == []


@pytest.mark.parametrize("field,bad,name", [
    ("Privileged", True, "privileged"), ("CapAdd", ["SYS_ADMIN"], "cap_add"),
    ("PidMode", "host", "pid_mode"), ("IpcMode", "host", "ipc_mode"),
    ("UsernsMode", "host", "userns_mode"), ("NetworkMode", "host", "network_mode"),
    ("Devices", [{"PathOnHost": "/dev/sda"}], "devices"),
    ("SecurityOpt", ["seccomp=unconfined"], "security_opt"),
    ("NanoCpus", 0, "cpus"), ("Memory", 0, "memory"), ("PidsLimit", -1, "pids")])
def test_verify_confinement_and_limits(adapter, layout, field, bad, name):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"][field] = bad
    assert adapter.verify(value, expected) == [name]


@pytest.mark.parametrize("membership", ["private", "root-owned", "explicit-other", "primary-other"])
def test_private_group_writable_ancestors(adapter, layout, monkeypatch, membership):
    import grp
    import pwd

    owner = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid(), pw_name="owner", pw_dir=str(layout.home))
    root_owner = SimpleNamespace(pw_uid=0, pw_gid=0, pw_name="root", pw_dir=str(layout.home))
    other = SimpleNamespace(pw_uid=owner.pw_uid + 1, pw_gid=owner.pw_gid, pw_name="other")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: owner if uid == owner.pw_uid else root_owner)
    monkeypatch.setattr(pwd, "getpwall", lambda: [owner, other] if membership == "primary-other" else [owner])
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(
        gr_gid=gid, gr_name="owner", gr_mem=["other"] if membership == "explicit-other" else []))
    layout.home.chmod(0o755)
    documents = layout.home / "Documents"
    documents.mkdir(mode=0o775)
    documents.chmod(0o775)
    project = documents / "project"
    project.mkdir(mode=0o775)
    project.chmod(0o775)
    if membership == "root-owned":
        original = os.lstat

        def root_owned_parent(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if Path(path) == documents:
                parts = list(info)
                parts[4] = 0
                return os.stat_result(parts)
            return info

        monkeypatch.setattr(os, "lstat", root_owned_parent)
    if membership in ("private", "root-owned"):
        assert {"source": str(project), "destination": str(project), "rw": True} in mounts(
            adapter, layout, project=project)
    else:
        message = "mount component writable by other users: %s (uid %d)" % (documents, owner.pw_uid)
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            mounts(adapter, layout, project=project)


def test_leaf_write_permission_cannot_replace_leaf(adapter, layout):
    layout.project.chmod(0o777)
    assert {"source": str(layout.project), "destination": str(layout.project), "rw": True} in mounts(adapter, layout)


@pytest.mark.parametrize("representation", ["quota", "nano", "both"])
def test_captured_podman_cpu_conversion(adapter, layout, representation):
    expected = expected_for(adapter, {**ISOLATION, "cpus": 0.29}, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    host = value[0]["HostConfig"]
    host.update(NanoCpus=289990000, CpuPeriod=100000, CpuQuota=28999)
    if representation == "quota":
        del host["NanoCpus"]
    elif representation == "nano":
        del host["CpuPeriod"], host["CpuQuota"]
    assert adapter.verify(value, expected) == []
    if representation == "nano":
        host["NanoCpus"] = 290000000
    else:
        host["CpuQuota"] = 29000
    assert adapter.verify(value, expected) == ["cpus"]


@pytest.mark.parametrize("tamper", ["missing", "root-mapping", "gid-mapping", "overlap", "malformed"])
def test_keep_id_requires_observed_mappings(adapter, layout, tamper):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    maps = value[0]["HostConfig"]["IDMappings"]
    if tamper == "missing":
        del value[0]["HostConfig"]["IDMappings"]
    elif tamper == "root-mapping":
        maps["UidMap"] = ["0:0:65536"]
    elif tamper == "gid-mapping":
        maps["GidMap"] = ["0:0:65536"]
    elif tamper == "overlap":
        maps["UidMap"].append("0:0:65536")
    else:
        maps["UidMap"] = ["not:a:mapping"]
    assert adapter.verify(value, expected) == ["userns_mode"]


@pytest.mark.parametrize("case,mode", [
    ("private", "private"), ("false", False), ("null", None), ("integer", 1), ("list", ["private"]),
    ("missing", None), ("shared", "container:unrelated"), ("shared-path", "container:/unrelated"),
    ("host", "host"), ("intent-alias", "keep-id"), ("empty", ""), ("object", {"mode": "private"}),
])
@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
def test_keep_id_requires_observed_private_mode(adapter, layout, case, mode, surface):
    # Observed Podman 4.9.3 (including real-podman-fix7-native): private, not the create-argv spelling keep-id.
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    host = value[0]["HostConfig"]
    mappings = copy.deepcopy(host["IDMappings"])
    assert adapter.verify(value, expected) == []
    if case == "missing":
        del host["UsernsMode"]
    else:
        host["UsernsMode"] = mode
    assert verify_surface(adapter, layout, expected, value, surface) == ([] if case == "private" else ["userns_mode"])
    assert host["IDMappings"] == mappings


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("builder", ["expected_plan", "create_argv"])
@pytest.mark.parametrize("axis", ["uid", "gid"])
@pytest.mark.parametrize("identity", [4294967295, 4294967296, 18446744073709551616])
def test_user_upper_bounds_refuse_before_effect(adapter, layout, monkeypatch, engine, builder, axis, identity):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    plan = mounts(adapter, layout)

    def no_engine(*args, **kwargs):
        raise AssertionError("pure builders must not invoke an engine")

    monkeypatch.setattr(subprocess, "run", no_engine)
    ids = {"uid": 1000, "gid": 1000, axis: identity}
    kwargs = {"image_inspect": image_info()} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^user uid and gid must be < 4294967295$"):
        getattr(adapter, builder)(isolation, run=layout.run, mounts=plan, **ids, **kwargs)
    assert list(layout.run.iterdir()) == []
    assert not Path(os.environ["AEGIS_FAKE_ENGINE_LOG"]).exists()


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("builder", ["expected_plan", "create_argv"])
@pytest.mark.parametrize("axis", ["uid", "gid"])
@pytest.mark.parametrize("identity", [True, False, -1, 1.5, "1000"])
def test_user_numeric_type_diagnostic_stays_stable(adapter, layout, engine, builder, axis, identity):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    ids = {"uid": 1000, "gid": 1000, axis: identity}
    kwargs = {"image_inspect": image_info()} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^user must be a numeric uid:gid$"):
        getattr(adapter, builder)(isolation, run=layout.run, mounts=mounts(adapter, layout), **ids, **kwargs)


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("axis", ["uid", "gid"])
@pytest.mark.parametrize("identity", [0, 1000, 4294967294])
def test_user_valid_linux_boundaries(adapter, layout, engine, axis, identity):
    # Modelled numeric records only; this neither executes an engine nor qualifies a high-ID host account.
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    ids = {"uid": 1000, "gid": 1000, axis: identity}
    plan = mounts(adapter, layout)
    expected = expected_for(adapter, isolation, run=layout.run, mounts=plan, **ids)
    argv = adapter.create_argv(isolation, run=layout.run, mounts=plan, **ids)
    assert expected["user"] == "%d:%d" % (ids["uid"], ids["gid"])
    if engine == "docker":
        assert argv[argv.index("--user") + 1] == expected["user"]
    else:
        assert "--user" not in argv
    assert adapter.verify(inspect_for(expected), expected) == []


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("axis", ["uid", "gid"])
@pytest.mark.parametrize("identity", [4294967295, 4294967296, 18446744073709551616])
def test_matching_invalid_user_records_still_refuse(adapter, layout, engine, axis, identity):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout), uid=1000, gid=1000)
    value = inspect_for(expected)
    ids = {"uid": 1000, "gid": 1000, axis: identity}
    expected["user"] = value[0]["Config"]["User"] = "%d:%d" % (ids["uid"], ids["gid"])
    assert adapter.verify(value, expected) == (["user", "userns_mode"] if engine == "podman" else ["user"])


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("record", [False, "name:1000", "-1:1000", "1000"])
def test_matching_malformed_numeric_user_records_refuse(adapter, layout, engine, record):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["user"] = value[0]["Config"]["User"] = record
    assert adapter.verify(value, expected) == (["user", "userns_mode"] if engine == "podman" else ["user"])


def test_recorded_unmask_request_is_distinct_from_effective_mask(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    assert value[0]["HostConfig"]["SecurityOpt"] == []
    assert adapter.verify(value, expected) == []
    value[0]["Config"]["CreateCommand"] = ["podman", "run", expected["image"]]
    assert adapter.verify(value, expected) == ["security_opt"]


def test_explicit_shared_memory_is_required(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"]["Tmpfs"]["/dev/shm"] = "ro,nosuid,nodev"
    assert adapter.verify(value, expected) == ["mounts"]


def test_expected_plan_requires_image_inspection(adapter, layout):
    with pytest.raises(TypeError, match="image_inspect"):
        adapter.expected_plan(ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    with pytest.raises(ValueError, match="^image inspect must describe exactly one image$"):
        adapter.expected_plan(ISOLATION, run=layout.run, mounts=mounts(adapter, layout), image_inspect=None)


def test_observed_pwd_is_an_engine_environment_key(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["Config"]["Env"] += ["PWD=/", "container=podman"]
    assert adapter.verify(value, expected) == []


@pytest.fixture
def acl_ancestor(layout, monkeypatch):
    """Modelled NSS membership, real directory metadata; ACL reads are real unless a test replaces them."""
    import grp
    import pwd

    owner = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid(), pw_name="owner", pw_dir=str(layout.home))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: owner)
    monkeypatch.setattr(pwd, "getpwall", lambda: [owner])
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_gid=gid, gr_name="owner", gr_mem=[]))
    parent = layout.home / "Documents"
    parent.mkdir()
    parent.chmod(0o775)
    project = parent / "project"
    project.mkdir()
    return parent, project


ACL_UNDEFINED = 0xffffffff
# Observed Linux bytes/modes: real-acl-host-fix5/capture.json, 2026-11-08, named UID 65534.
# That capture used adapter SHA256 f4368160b7ebed0a4b9018b84cd4eb787820cf5178de147ac5d778709a83c45c.
ACL_CAPTURE = {
    "foreign-write": (0o775, "0200000001000700ffffffff02000700feff000004000700ffffffff10000700ffffffff20000500ffffffff"),
    "foreign-read": (0o775, "0200000001000700ffffffff02000500feff000004000700ffffffff10000700ffffffff20000500ffffffff"),
    "masked-write": (0o755, "0200000001000700ffffffff02000700feff000004000700ffffffff10000500ffffffff20000500ffffffff"),
}


def foreign_id(identity):
    return 65534 if identity != 65534 else 65533


def acl_bytes(entries, version=2):
    return struct.pack("<I", version) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def model_access_acl(monkeypatch, parent, raw):
    """Only the ACL query is modelled; lstat and the public mount plan remain real."""
    getter = os.getxattr

    def getxattr(path, name, **kwargs):
        if Path(path) == parent:
            assert name == "system.posix_acl_access" and kwargs == {"follow_symlinks": False}
            if isinstance(raw, OSError):
                raise raw
            return raw
        return getter(path, name, **kwargs)

    monkeypatch.setattr(os, "getxattr", getxattr)


@pytest.mark.parametrize("case", list(ACL_CAPTURE))
@pytest.mark.parametrize("surface", ["mount-plan", "cli"])
def test_observed_linux_access_acl_permissions(adapter, layout, acl_ancestor, monkeypatch, case, surface):
    parent, project = acl_ancestor
    mode, raw = ACL_CAPTURE[case]
    parent.chmod(mode)
    # UID 65534 denotes a trusted grant if the tests themselves run as that user; other tests always model
    # a distinct foreign ID. Keep these observed bytes unchanged on every host.
    unsafe = case == "foreign-write" and os.geteuid() != 65534
    message = "mount component writable by other users: %s (uid %d)" % (parent, os.geteuid())
    if surface == "mount-plan":
        model_access_acl(monkeypatch, parent, bytes.fromhex(raw))
        if unsafe:
            with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
                mounts(adapter, layout, project=project)
        else:
            assert {"source": str(project), "destination": str(project), "rw": True} in mounts(
                adapter, layout, project=project)
    else:
        bootstrap = ("import grp; _acl_get = os.getxattr; "
                     "os.getxattr = lambda p,n,**kw: bytes.fromhex(%r) if str(p)==%r else _acl_get(p,n,**kw); "
                     "_owner = SimpleNamespace(pw_uid=%r,pw_gid=%r,pw_name='owner',pw_dir=%r); "
                     "pwd.getpwuid = lambda uid: _owner; pwd.getpwall = lambda: [_owner]; "
                     "grp.getgrgid = lambda gid: SimpleNamespace(gr_name='owner',gr_mem=[]); "
                     % (raw, str(parent), os.geteuid(), os.getegid(), str(layout.passwd_home)))
        config = {**config_for(layout), "project": str(project)}
        result = cli(layout, config, "plan", bootstrap=bootstrap)
        assert result.returncode == (2 if unsafe else 0), result.stdout + result.stderr
        if unsafe:
            assert json.loads(result.stdout) == {"error": message}
        else:
            assert {"source": str(project), "destination": str(project), "rw": True} in json.loads(result.stdout)["mounts"]


@pytest.mark.parametrize("case", ["foreign-user-write", "trusted-root", "trusted-user", "named-private-write",
                                 "named-foreign-read", "named-foreign-write", "named-foreign-masked",
                                 "owning-shared-write", "mask-is-not-grant", "minimal", "optional-mask",
                                 "other-is-not-masked"])
def test_modelled_acl_effective_grants(adapter, layout, acl_ancestor, monkeypatch, case):
    import grp

    parent, project = acl_ancestor
    uid, gid = foreign_id(os.geteuid()), foreign_id(os.getegid())
    users = [(2, 5, uid)]
    groups = []
    group_perm, mask, other = 7, 7, 5
    if case == "foreign-user-write":
        users = [(2, 7, uid)]
    elif case in ("trusted-root", "trusted-user"):
        users = [(2, 7, 0 if case == "trusted-root" else os.geteuid())]
    elif case.startswith("named-"):
        groups = [(8, 5 if case == "named-foreign-read" else 7,
                   os.getegid() if case == "named-private-write" else gid)]
        if case == "named-foreign-masked":
            mask = 5
    elif case in ("owning-shared-write", "mask-is-not-grant"):
        monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="users", gr_mem=[]))
        if case == "mask-is-not-grant":
            group_perm = 5  # A writable mask alone grants nobody write permission.
    elif case in ("minimal", "optional-mask"):
        users = []
        if case == "minimal":
            mask = None
    else:
        mask, other = 5, 7  # OTHER is deliberately outside the mask.
    parent.chmod(0o700 | ((group_perm if mask is None else mask) << 3) | other)
    entries = ([(1, 7, ACL_UNDEFINED)] + users + [(4, group_perm, ACL_UNDEFINED)] + groups
               + ([] if mask is None else [(16, mask, ACL_UNDEFINED)]) + [(32, other, ACL_UNDEFINED)])
    model_access_acl(monkeypatch, parent, acl_bytes(entries))
    unsafe = case in ("foreign-user-write", "named-foreign-write", "owning-shared-write", "other-is-not-masked")
    if unsafe:
        message = "mount component writable by other users: %s (uid %d)" % (parent, os.geteuid())
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            mounts(adapter, layout, project=project)
    else:
        assert {"source": str(project), "destination": str(project), "rw": True} in mounts(adapter, layout, project=project)


@pytest.mark.parametrize("case,reason", [
    ("string", "expected bytes"), ("boolean", "expected bytes"), ("bytearray", "expected bytes"),
    ("short-header", "invalid length"), ("header-only", "invalid length"), ("trailing-byte", "invalid length"),
    ("version", "unsupported version"), ("big-endian", "unsupported version"), ("tag", "invalid tag"),
    ("permission", "invalid permissions"), ("user-id", "invalid entry ID"), ("group-id", "invalid entry ID"),
    ("owner-qualifier", "invalid entry ID"), ("group-qualifier", "invalid entry ID"),
    ("mask-qualifier", "invalid entry ID"), ("other-qualifier", "invalid entry ID"),
    ("duplicate-user", "duplicate named ID"), ("duplicate-group", "duplicate named ID"),
    ("duplicate-owner", "duplicate singleton"), ("duplicate-owning-group", "duplicate singleton"),
    ("duplicate-mask", "duplicate singleton"), ("duplicate-other", "duplicate singleton"),
    ("missing-owner", "missing required entries"), ("missing-owning-group", "missing required entries"),
    ("missing-other", "missing required entries"), ("missing-user-mask", "missing mask"),
    ("missing-group-mask", "missing mask"), ("tag-order", "entries out of order"),
])
def test_modelled_acl_malformed_abi_refuses(adapter, layout, acl_ancestor, monkeypatch, case, reason):
    parent, project = acl_ancestor
    uid, gid = foreign_id(os.geteuid()), foreign_id(os.getegid())
    entries = [(1, 7, ACL_UNDEFINED), (2, 5, uid), (4, 7, ACL_UNDEFINED),
               (16, 7, ACL_UNDEFINED), (32, 5, ACL_UNDEFINED)]
    if case in ("tag", "permission", "user-id"):
        entries[1] = {"tag": (3, 5, uid), "permission": (2, 8, uid), "user-id": (2, 5, ACL_UNDEFINED)}[case]
    elif case == "group-id":
        entries.insert(3, (8, 5, ACL_UNDEFINED))
    elif case.endswith("qualifier"):
        index = {"owner-qualifier": 0, "group-qualifier": 2, "mask-qualifier": 3, "other-qualifier": 4}[case]
        tag, perm, _ = entries[index]
        entries[index] = (tag, perm, 0)
    elif case.startswith("duplicate-"):
        if case == "duplicate-group":
            entries[3:3] = [(8, 5, gid), (8, 5, gid)]
        else:
            index = {"duplicate-user": 1, "duplicate-owner": 0, "duplicate-owning-group": 2,
                     "duplicate-mask": 3, "duplicate-other": 4}[case]
            entries.insert(index, entries[index])
    elif case.startswith("missing-"):
        tag = {"missing-owner": 1, "missing-owning-group": 4, "missing-other": 32,
               "missing-user-mask": 16, "missing-group-mask": 16}[case]
        entries = [entry for entry in entries if entry[0] != tag]
        if case == "missing-group-mask":
            entries[1] = (8, 5, gid)
            entries.sort()
    elif case == "tag-order":
        entries[1], entries[2] = entries[2], entries[1]
    raw = acl_bytes(entries, version=1 if case == "version" else 2)
    raw = {"string": "not bytes", "boolean": True, "bytearray": bytearray(raw), "short-header": raw[:3],
           "header-only": raw[:4], "trailing-byte": raw + b"x", "big-endian": b"\0\0\0\2" + raw[4:]}.get(case, raw)
    model_access_acl(monkeypatch, parent, raw)
    message = "mount access ACL malformed: %s: %s; require Linux POSIX access ACL v2 metadata" % (parent, reason)
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        mounts(adapter, layout, project=project)


@pytest.mark.parametrize("case", ["owner", "mask", "other", "minimal-group", "masked-mode"])
def test_modelled_acl_mode_correspondence_refuses(adapter, layout, acl_ancestor, monkeypatch, case):
    parent, project = acl_ancestor
    entries = [(1, 5 if case == "owner" else 7, ACL_UNDEFINED), (2, 5, foreign_id(os.geteuid())),
               (4, 7, ACL_UNDEFINED), (16, 5 if case == "mask" else 7, ACL_UNDEFINED),
               (32, 7 if case == "other" else 5, ACL_UNDEFINED)]
    if case == "minimal-group":
        entries = [(1, 7, ACL_UNDEFINED), (4, 5, ACL_UNDEFINED), (32, 5, ACL_UNDEFINED)]
    if case == "masked-mode":
        parent.chmod(0o755)
    model_access_acl(monkeypatch, parent, acl_bytes(entries))
    message = "mount access ACL mode mismatch: %s; revalidate unchanged ACL and lstat metadata" % parent
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        mounts(adapter, layout, project=project)


@pytest.mark.parametrize("case", ["malformed", "unreadable"])
def test_modelled_sticky_does_not_hide_invalid_acl_metadata(adapter, layout, acl_ancestor, monkeypatch, case):
    parent, project = acl_ancestor
    parent.chmod(0o1777)
    raw = b"invalid" if case == "malformed" else OSError(errno.EACCES, "modelled denied ACL")
    model_access_acl(monkeypatch, parent, raw)
    if case == "malformed":
        message = "mount access ACL malformed: %s: invalid length; require Linux POSIX access ACL v2 metadata" % parent
    else:
        message = ("mount access ACL cannot be qualified: %s: access ACL query failed (EACCES); require readable "
                   "Linux POSIX access ACL metadata" % parent)
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        mounts(adapter, layout, project=project)


def test_native_acl_absence_preserves_private_775(adapter, layout, acl_ancestor):
    parent, project = acl_ancestor
    # Observed Linux OS boundary: this tests an actual ACL query, not a model of an absent ACL.
    with pytest.raises(OSError) as caught:
        os.getxattr(parent, "system.posix_acl_access", follow_symlinks=False)
    assert caught.value.errno == errno.ENODATA
    assert {"source": str(project), "destination": str(project), "rw": True} in mounts(adapter, layout, project=project)


@pytest.mark.parametrize("case", ["unsupported", "denied", "no-api"])
def test_modelled_acl_query_failures_refuse(adapter, layout, acl_ancestor, monkeypatch, case):
    parent, project = acl_ancestor
    getter = os.getxattr

    def getxattr(path, name, **kwargs):
        if Path(path) == parent:
            assert name == "system.posix_acl_access" and kwargs == {"follow_symlinks": False}
            raise OSError(errno.EOPNOTSUPP if case == "unsupported" else errno.EACCES, case)
        return getter(path, name, **kwargs)

    if case == "no-api":
        monkeypatch.delattr(os, "getxattr")
    else:
        monkeypatch.setattr(os, "getxattr", getxattr)
    reason = {"unsupported": "access ACL query failed (EOPNOTSUPP)", "denied": "access ACL query failed (EACCES)",
              "no-api": "Linux access ACL API is unavailable"}[case]
    component = Path("/") if case == "no-api" else parent
    message = ("mount access ACL cannot be qualified: %s: %s; require readable Linux POSIX access ACL metadata" %
               (component, reason))
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        mounts(adapter, layout, project=project)


def test_modelled_acl_does_not_defeat_sticky_child_protection(adapter, layout, acl_ancestor, monkeypatch):
    parent, project = acl_ancestor
    parent.chmod(0o1777)
    entries = [(1, 7, ACL_UNDEFINED), (2, 7, foreign_id(os.geteuid())), (4, 7, ACL_UNDEFINED),
               (16, 7, ACL_UNDEFINED), (32, 7, ACL_UNDEFINED)]
    model_access_acl(monkeypatch, parent, acl_bytes(entries))
    assert {"source": str(project), "destination": str(project), "rw": True} in mounts(adapter, layout, project=project)


def test_modelled_shared_group_name_cannot_claim_private_nss(adapter, layout, acl_ancestor, monkeypatch):
    import grp

    parent, project = acl_ancestor
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_gid=gid, gr_name="users", gr_mem=[]))
    message = "mount component writable by other users: %s (uid %d)" % (parent, os.geteuid())
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        mounts(adapter, layout, project=project)


@pytest.mark.parametrize("field", ["config", "digest", "empty-digest", "config-ref", "repo", "empty-config",
                                   "expected-id", "expected-digest"])
def test_captured_image_witnesses_are_conjunctive(adapter, layout, field):
    # Config/digest association copied from the owner Podman 4.9.3 capture; paths remain fixture-owned.
    digest = "sha256:6b10bb037f470542125fe00896d5235cf253fc603d2266c052fba6e94e86ec9c"
    config_id = "1df87640e83ef43b4fc4b891f58f28e16cf800327fe85ea90f9601c2d9d34a78"
    image = "localhost/aegis-test@" + digest
    inspected_image = [{"Id": config_id, "Digest": digest, "RepoDigests": [image], "Config": {"Env": []}}]
    expected = expected_for(adapter, {**ISOLATION, "image": image}, run=layout.run, mounts=mounts(adapter, layout),
                            image_inspect=inspected_image)
    value = inspect_for(expected)
    if field == "config":
        value[0]["Image"] = "f" * 64
    elif field in ("digest", "empty-digest"):
        value[0]["ImageDigest"] = "sha256:" + "f" * 64 if field == "digest" else ""
    elif field == "config-ref":
        value[0]["Config"]["Image"] = "localhost/other@sha256:" + "f" * 64
    elif field == "repo":
        value[0]["RepoDigests"] = ["localhost/other@sha256:" + "f" * 64]
    elif field == "empty-config":
        value[0]["Image"] = ""
    elif field == "expected-id":
        expected["image_info"]["id"] = ""
    else:
        expected["image_info"]["digest"] = ""
    assert adapter.verify(value, expected) == ["image"]


def test_canonical_image_config_ids_agree(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["Image"] = expected["image_info"]["id"].removeprefix("sha256:").upper()
    assert adapter.verify(value, expected) == []


@pytest.mark.parametrize("case", ["empty-id", "id-conflict", "digest-conflict", "empty-digest", "boolean-id"])
def test_pinned_image_inspect_has_no_contradictory_identity(adapter, layout, case):
    info = image_info()
    if case == "empty-id":
        info[0]["Id"] = ""
    elif case == "id-conflict":
        info[0]["ID"] = "f" * 64
    elif case == "digest-conflict":
        info[0]["ImageDigest"] = "sha256:" + "f" * 64
    elif case == "empty-digest":
        info[0]["Digest"] = ""
    else:
        info[0]["Id"] = True
    with pytest.raises(ValueError, match="^image inspect has conflicting or invalid identity$"):
        adapter.expected_plan(ISOLATION, run=layout.run, mounts=mounts(adapter, layout), image_inspect=info)


def test_modelled_docker_does_not_match_empty_digest(adapter, layout):
    info = image_info()
    del info[0]["Digest"]  # Docker supplies its association via RepoDigests and config Id.
    expected = expected_for(adapter, {**ISOLATION, "engine": "docker", "allow_unqualified": True},
                            run=layout.run, mounts=mounts(adapter, layout), image_inspect=info)
    value = inspect_for(expected)
    del value[0]["ImageDigest"]
    assert adapter.verify(value, expected) == []
    value[0]["ImageDigest"] = ""
    assert adapter.verify(value, expected) == ["image"]


@pytest.mark.parametrize("axis", ["UidMap", "GidMap"])
@pytest.mark.parametrize("entry", ["4294967295:4294967295:1", "4294967294:4294967294:2",
                                  "4294967294:70000:2", "70000:4294967294:2",
                                  "4294967296:70000:1", "70000:4294967296:1", "70000:70000:0",
                                  "70000:70000:-1", True, {"inside": 70000, "outside": 70000, "count": True}])
def test_mapping_numeric_domain_refuses_malformed_inspect(adapter, layout, axis, entry):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"]["IDMappings"][axis].append(entry)
    assert adapter.verify(value, expected) == ["userns_mode"]


def test_mapping_last_usable_linux_id_is_valid(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    for axis in ("UidMap", "GidMap"):
        value[0]["HostConfig"]["IDMappings"][axis].append("4294967294:4294967294:1")
    assert adapter.verify(value, expected) == []


@pytest.mark.parametrize("flag", ["--read-only-tmpfs=false", "--env-host=false", "--http-proxy=false"])
@pytest.mark.parametrize("case", ["missing", "contradictory"])
def test_unverifiable_effects_require_recorded_requests(adapter, layout, flag, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    argv = value[0]["Config"]["CreateCommand"]
    if case == "missing":
        argv.remove(flag)
    else:
        argv.insert(-1, flag.replace("=false", "=true"))
    assert adapter.verify(value, expected) == ["security_opt"]


def test_recorded_option_value_cannot_hide_later_relaxation(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    argv = value[0]["Config"]["CreateCommand"]
    argv[-1:-1] = ["--label", expected["image"], "--security-opt=unmask=ALL"]
    assert adapter.verify(value, expected) == ["security_opt"]


@pytest.mark.parametrize("dest", ["/tmp", "/dev/shm"])
@pytest.mark.parametrize("options", ["rw", "rw,nosuid", "rw,nodev", "rw,nosuid,nodev,suid", "rw,nosuid,nodev,dev",
                                    "rw,ro,nosuid,nodev", "rw,nosuid,nodev,exec,noexec"])
def test_writable_tmpfs_requires_safe_option_witnesses(adapter, layout, dest, options):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"]["Tmpfs"][dest] = options
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("options", [["rw", "suid", "dev"], "rw,nosuid,nodev", True, [True]])
def test_tmpfs_metadata_cannot_override_conflicting_options(adapter, layout, options):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": "/dev/shm", "RW": True,
                               "Options": options})
    assert adapter.verify(value, expected) == ["mounts"]


def test_unattested_engine_shm_options_refuse(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    del value[0]["HostConfig"]["Tmpfs"]["/dev/shm"]
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "shm", "Destination": "/dev/shm", "RW": True})
    assert adapter.verify(value, expected) == ["mounts"]


def test_owner_capture_replay(adapter, layout):
    # External owner evidence stays outside the repository and tests/fixtures. The fake embeds its shape for CI.
    variable = "AEGIS_TEST_C1_HISTORICAL_CAPTURE_DIR"
    location = os.environ.get(variable)
    if location is None:
        pytest.skip("set " + variable + " to replay optional historical Podman 4.9.3 evidence")
    if not location.strip():
        pytest.fail(variable + " must name the historical capture directory; the supplied value is empty", pytrace=False)
    root = Path(location)

    def capture_json(name):
        try:
            if not root.is_dir():
                raise ValueError("capture directory does not exist or is not a directory")
            data = adapter.strict_json((root / name).read_text(encoding="utf-8"))
            if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
                raise ValueError("expected a one-element JSON array containing an inspect object")
        except (OSError, UnicodeError, ValueError) as exc:
            pytest.fail("%s=%s: invalid %s: %s; supply the historical real-podman-4.9.3 capture directory" %
                        (variable, root, name, exc), pytrace=False)
        return data

    value = capture_json("container-inspect.json")
    image = capture_json("image-inspect.json")
    try:
        if not isinstance(value[0]["HostConfig"]["Tmpfs"], dict):
            raise ValueError("container-inspect.json HostConfig.Tmpfs must be an object")
        if not isinstance(image[0]["Config"]["Env"], list):
            raise ValueError("image-inspect.json Config.Env must be an array")
        run = value[0]["Config"]["Labels"]["aegis.team.run"]
        rows = [{"source": row["Source"], "destination": row["Destination"], "rw": row["RW"]}
                for row in value[0]["Mounts"]]
        expected = adapter.expected_plan({**ISOLATION, "cpus": 0.29, "pids": 4096,
                                          "image": image[0]["RepoDigests"][0]},
                                         run=run, mounts=rows, uid=1000, gid=1000, image_inspect=image)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        pytest.fail("%s=%s: malformed historical inspect fields: %s; both inspect files must come from the "
                    "historical real-podman-4.9.3 capture" % (variable, root, exc), pytrace=False)
    # The supplied capture predates the explicit shm mount: it should now fail only that changed plan field.
    assert adapter.verify(value, expected) == ["mounts"], (
        variable + " must reference the historical capture before the writable shm fix")
    value[0]["HostConfig"]["Tmpfs"]["/dev/shm"] = "rw,nosuid,nodev,rprivate,tmpcopyup"
    assert adapter.verify(value, expected) == [], variable + ": historical capture must verify after the in-memory shm update"


def test_verify_quota_cpu_form(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    host = value[0]["HostConfig"]
    host.update(NanoCpus=0, CpuPeriod=100000, CpuQuota=100000)
    assert adapter.verify(value, expected) == []
    host["CpuQuota"] = 200000
    assert adapter.verify(value, expected) == ["cpus"]


def test_verify_unexpected_environment(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["Config"]["Env"] += ["HTTPS_PROXY=fixture-proxy"]
    assert adapter.verify(value, expected) == ["environment"]


def fake_created_inspect(adapter, layout, isolation, *, env=None, uid=None, gid=None):
    """Public fake CLI in-process; high account IDs are modelled only in the fake's OS reference."""
    plan = mounts(adapter, layout)

    def call(argv):
        p = fake_engine_call(argv, uid=uid, gid=gid)
        assert p.returncode == 0, p.stderr
        return p.stdout

    image = call(adapter.image_inspect_argv(isolation["engine"], isolation["image"]))
    argv = adapter.create_argv(isolation, run=layout.run, mounts=plan, env=env, uid=uid, gid=gid)
    call(argv)
    value = json.loads(call(adapter.inspect_argv(isolation["engine"], layout.run)))
    kwargs = {"env": env} if env is not None else {}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=plan, image_inspect=image,
                            uid=uid, gid=gid, **kwargs)
    return expected, value


def verify_surface(adapter, layout, expected, value, surface):
    if surface == "pure":
        return adapter.verify(value, expected)
    path = layout.run.parent / "tampered-inspect.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    result = cli(layout, {**config_for(layout), "isolation": {
        **ISOLATION, "engine": expected["engine"], "allow_unqualified": expected["engine"] == "docker"}},
                 "verify", "--inspect", str(path))
    assert result.returncode in (0, 2), result.stdout + result.stderr
    answer = json.loads(result.stdout)
    assert set(answer) == {"mismatches"}, answer
    return answer["mismatches"]


@pytest.mark.parametrize("flag,label,admitted", [("--userns", "userns_mode", "keep-id"),
                                               ("--pid", "pid_mode", "private"),
                                               ("--ipc", "ipc_mode", "private"),
                                               ("--network", "network_mode", "bridge")])
@pytest.mark.parametrize("arity", ["equals", "separate"])
@pytest.mark.parametrize("change", ["absent", "agree", "contradict", "bad-then-good", "good-then-bad"])
@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
def test_recorded_namespace_witnesses_conjoin(adapter, layout, flag, label, admitted, arity, change, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    requests = {"absent": [], "agree": [admitted], "contradict": ["host"],
                "bad-then-good": ["host", admitted], "good-then-bad": [admitted, "host"]}[change]
    argv = value[0]["Config"]["CreateCommand"]
    words = [word for request in requests for word in (
        [flag + "=" + request] if arity == "equals" else [flag, request])]
    argv[-1:-1] = words
    assert verify_surface(adapter, layout, expected, value, surface) == (
        [] if change in ("absent", "agree") else [label])


@pytest.mark.parametrize("change", ["missing", "null", "false", "list", "string", "integer"])
@pytest.mark.parametrize("surface", ["constructor", "cli"])
def test_image_config_requires_known_object(adapter, layout, monkeypatch, change, surface):
    info = image_info()
    if change == "missing":
        del info[0]["Config"]
    else:
        info[0]["Config"] = {"null": None, "false": False, "list": [], "string": "", "integer": 0}[change]
    if surface == "constructor":
        with pytest.raises(ValueError, match="^image inspect has invalid Config$"):
            expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout), image_inspect=info)
    else:
        image_path = layout.run.parent / "unknown-image-config.json"
        image_path.write_text(json.dumps(info), encoding="utf-8")
        monkeypatch.setenv("AEGIS_FAKE_ENGINE_IMAGE", str(image_path))
        expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
        path = layout.run.parent / "inspect.json"
        path.write_text(json.dumps(inspect_for(expected)), encoding="utf-8")
        p = cli(layout, config_for(layout), "verify", "--inspect", str(path))
        assert p.returncode == 2
        assert json.loads(p.stdout) == {"error": "image inspect has invalid Config"}


@pytest.mark.parametrize("config", [{}, {"Env": None}, {"Env": []}])
def test_known_empty_image_env_remains_valid(adapter, layout, config):
    info = image_info()
    info[0]["Config"] = config
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout), image_inspect=info)
    assert expected["image_info"]["env_fingerprints"] == {}
    assert adapter.verify(inspect_for(expected), expected) == []


@pytest.mark.parametrize("bad", [None, False, [], {"TERM": None}, {"TERM": "not-a-fingerprint"}, {"BAD-NAME": "a" * 64}])
def test_expected_fingerprint_unknown_is_not_empty(adapter, layout, bad):
    info = image_info()
    info[0]["Config"] = {"Env": []}
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout), image_inspect=info)
    value = inspect_for(expected)
    expected["image_info"]["env_fingerprints"] = bad
    assert adapter.verify(value, expected) == ["environment"]


@pytest.mark.parametrize("destination", ["/tmp", "/dev/shm"])
@pytest.mark.parametrize("mode", ["ro", "rw,suid", "rw,dev", "ro,suid,dev", None, False, [], ["rw"],
                                  "rw,nosuid,nodev,ro", "rw,nosuid,nodev,suid", "rw,nosuid,nodev,dev",
                                  "rw,nosuid,nodev,exec,noexec"])
@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
def test_tmpfs_mode_cannot_waive_other_witnesses(adapter, layout, destination, mode, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": destination,
                               "RW": True, "Mode": mode})
    assert verify_surface(adapter, layout, expected, value, surface) == ["mounts"]


@pytest.mark.parametrize("mode", ["", "rw", "rw,nosuid,nodev", "rw,nosuid,nodev,exec", "rw,nosuid,nodev,noexec"])
def test_tmpfs_partial_mode_does_not_require_noexec(adapter, layout, mode):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True, "Mode": mode})
    assert adapter.verify(value, expected) == []


@pytest.mark.parametrize("mode", ["", "rw", "rw,nosuid,nodev"])
def test_tmpfs_mode_only_full_safe_witness_can_supply_safety(adapter, layout, mode):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    del value[0]["HostConfig"]["Tmpfs"]["/dev/shm"]
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "shm", "Destination": "/dev/shm", "RW": True, "Mode": mode})
    assert adapter.verify(value, expected) == ([] if mode == "rw,nosuid,nodev" else ["mounts"])


@pytest.mark.parametrize("mode,other", [("exec", "noexec"), ("noexec", "exec")])
def test_tmpfs_explicit_optional_flags_cannot_contradict(adapter, layout, mode, other):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"]["Tmpfs"]["/tmp"] += "," + other
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True,
                               "Mode": "rw,nosuid,nodev," + mode})
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("change", ["same", "slash", "double-slash", "wrong", "null", "false", "list", "missing"])
@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
def test_name_witness_is_derived_from_run(adapter, layout, engine, change, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    name = adapter.container_name(layout.run)
    if change == "missing":
        del value[0]["Name"]
    else:
        value[0]["Name"] = {"same": name, "slash": "/" + name, "double-slash": "//" + name,
                             "wrong": "unrelated", "null": None, "false": False, "list": [name]}[change]
    valid = change == "same" or (engine == "docker" and change == "slash")
    assert verify_surface(adapter, layout, expected, value, surface) == ([] if valid else ["name"])


@pytest.mark.parametrize("change", ["absent", "agree", "contradict", "bad-then-good", "good-then-bad"])
def test_recorded_name_cannot_waive_derived_name(adapter, layout, change):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    name = adapter.container_name(layout.run)
    names = {"absent": [], "agree": [name], "contradict": ["unrelated"],
             "bad-then-good": ["unrelated", name], "good-then-bad": [name, "unrelated"]}[change]
    value[0]["Config"]["CreateCommand"][-1:-1] = [word for item in names for word in ("--name", item)]
    assert adapter.verify(value, expected) == ([] if change in ("absent", "agree") else ["name"])


@pytest.mark.parametrize("field,bad,actual", [
    ("memory", 0, 0), ("memory", -1, -1), ("memory", True, 1), ("memory", 1024.0, 1024),
    ("memory", "1024", 1024), ("memory", None, 0), ("memory", [], 0), ("memory", 1, 1), ("memory", 1025, 1025),
    ("pids", -1, -1), ("pids", 0, 0), ("pids", 63, 63), ("pids", True, 1), ("pids", 64.0, 64),
    ("pids", "64", 64), ("pids", None, 0), ("pids", [], 0),
    ("cpus", True, 1000000000), ("cpus", False, 0), ("cpus", 0, 0), ("cpus", 0.001, 1000000),
    ("cpus", float("nan"), 1000000000), ("cpus", float("inf"), 1000000000), ("cpus", "1", 1000000000),
    ("cpus", None, 1000000000), ("cpus", [], 1000000000),
])
def test_expected_resource_domains_precede_equality(adapter, layout, field, bad, actual):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected[field] = bad
    value[0]["HostConfig"][{"memory": "Memory", "pids": "PidsLimit", "cpus": "NanoCpus"}[field]] = actual
    assert adapter.verify(value, expected) == [field]


def test_matching_unlimited_expected_limits_never_authorize(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected.update(memory=0, pids=-1)
    value[0]["HostConfig"].update(Memory=0, PidsLimit=-1)
    assert adapter.verify(value, expected) == ["memory", "pids"]


@pytest.mark.parametrize("field,labels", [
    ("run", ["label", "name", "environment"]), ("engine", ["engine"]), ("image", ["image"]),
    ("user", ["user", "userns_mode"]), ("read_only", ["read_only"]), ("mounts", ["mounts"]),
    ("cpus", ["cpus"]), ("memory", ["memory"]), ("pids", ["pids"]),
    ("image_info", ["image", "environment"]), ("environment", ["environment"]),
])
def test_expected_record_requires_every_field(adapter, layout, field, labels):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    del expected[field]
    assert adapter.verify(value, expected) == labels


@pytest.mark.parametrize("field,bad,labels", [
    ("read_only", False, ["read_only"]), ("read_only", 1, ["read_only"]),
    ("read_only", None, ["read_only"]), ("mounts", None, ["mounts"]), ("mounts", {}, ["mounts"]),
    ("engine", None, ["engine"]), ("engine", False, ["engine"]), ("engine", "unknown", ["engine"]),
    ("run", False, ["label", "name", "environment"]), ("run", "relative", ["label", "name", "environment"]),
    ("run", "/bad-\ud800", ["label", "name", "environment"]),
    ("image", None, ["image"]), ("image", False, ["image"]),
    ("image_info", None, ["image", "environment"]), ("image_info", False, ["image", "environment"]),
    ("image_info", [], ["image", "environment"]), ("environment", None, ["environment"]),
    ("environment", [], ["environment"]),
])
def test_expected_record_wrong_types_never_become_absence(adapter, layout, field, bad, labels):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected[field] = bad
    assert adapter.verify(value, expected) == labels


@pytest.mark.parametrize("change", ["null", "false", "list", "unknown-field"])
def test_expected_record_root_is_explicit(adapter, layout, change):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    if change == "unknown-field":
        expected["unreviewed"] = True
    else:
        expected = {"null": None, "false": False, "list": []}[change]
    assert adapter.verify(value, expected) == ["expected"]


@pytest.mark.parametrize("field", ["id", "digest", "repo_digests", "env_fingerprints"])
@pytest.mark.parametrize("change", ["missing", "null", "false", "wrong-type"])
def test_expected_image_record_witnesses_are_typed(adapter, layout, field, change):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    info = expected["image_info"]
    if change == "missing":
        del info[field]
    else:
        info[field] = {"null": None, "false": False,
                       "wrong-type": {} if field == "repo_digests" else []}[change]
    # An explicit absent platform Digest is supported when the RepoDigest still ties the image to the pin.
    labels = [] if field == "digest" and change == "null" else [
        "environment" if field == "env_fingerprints" else "image"]
    assert adapter.verify(value, expected) == labels


@pytest.mark.parametrize("change", ["unknown-key", "unassociated-pin", "non-digest-repo"])
def test_expected_image_association_is_an_explicit_contract(adapter, layout, change):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    if change == "unknown-key":
        expected["image_info"]["unreviewed"] = True
    elif change == "unassociated-pin":
        expected["image"] = "localhost/other@sha256:" + "f" * 64
    else:
        expected["image_info"]["repo_digests"] = [False]
    assert adapter.verify(value, expected) == ["image"]


def test_expected_mount_access_is_boolean_before_equality(adapter, layout):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    next(row for row in expected["mounts"] if row["rw"])["rw"] = 1
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("cpus,memory,pids,nano", [(0.01, "1k", 64, 10000000),
                                                 (0.29, "128m", 4096, 290000000),
                                                 (1, "16g", 64000, 1000000000)])
def test_expected_contract_preserves_valid_resource_boundaries(adapter, layout, engine, cpus, memory, pids, nano):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker",
                 "cpus": cpus, "memory": memory, "pids": pids}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    host = value[0]["HostConfig"]
    host.update(Memory=expected["memory"], PidsLimit=pids, NanoCpus=nano)
    if engine == "podman":
        quota = int(float(cpus) * 100000)  # Observed Podman conversion, not a native high-ID/resource probe.
        host.update(CpuPeriod=100000, CpuQuota=quota, NanoCpus=quota * 10000)
    assert adapter.verify(value, expected) == []


@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
@pytest.mark.parametrize("key", ["HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "PATH", "PYTHONDONTWRITEBYTECODE"])
@pytest.mark.parametrize("change", ["missing", "changed", "outside"])
def test_required_create_environment_values(adapter, layout, surface, key, change):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    items = dict(item.split("=", 1) for item in value[0]["Config"]["Env"])
    if change == "missing":
        del items[key]
    else:
        items[key] = ("/outside" if change == "outside" else str(layout.project)) if key in (
            "HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR") else "unrequested-value"
    value[0]["Config"]["Env"] = [k + "=" + v for k, v in items.items()]
    assert verify_surface(adapter, layout, expected, value, surface) == ["environment"]


@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
@pytest.mark.parametrize("change", ["runtime", "recorded", "both"])
@pytest.mark.parametrize("key", ["ANTHROPIC_API_KEY", "TERM"])
def test_pinned_image_credential_cannot_be_overridden(adapter, layout, monkeypatch, surface, change, key):
    info = image_info()
    info[0]["Config"]["Env"].append(key + "=placeholder")  # Synthetic, never an owner credential.
    image_path = layout.run.parent / "pinned-image.json"
    image_path.write_text(json.dumps(info), encoding="utf-8")
    monkeypatch.setenv("AEGIS_FAKE_ENGINE_IMAGE", str(image_path))
    credential = "synthetic-ambient-credential-not-an-owner-secret"
    monkeypatch.setenv(key, credential)
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    assert adapter.verify(value, expected) == []
    assert "placeholder" not in json.dumps(expected)
    assert credential not in json.dumps(expected)
    if change in ("runtime", "both"):
        value[0]["Config"]["Env"] = [key + "=" + credential if item.startswith(key + "=")
                                      else item for item in value[0]["Config"]["Env"]]
    if change in ("recorded", "both"):
        argv = value[0]["Config"]["CreateCommand"]
        index = argv.index(IMAGE)
        argv[index:index] = ["--env", key + "=" + credential]
    assert verify_surface(adapter, layout, expected, value, surface) == ["environment"]
    assert credential not in Path(os.environ["AEGIS_FAKE_ENGINE_LOG"]).read_text(encoding="utf-8")


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_explicit_environment_overrides_have_value_witnesses(adapter, layout, engine):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    env = {"LANG": "C.UTF-8", "PATH": "/controlled/bin:/usr/bin"}
    expected, value = fake_created_inspect(adapter, layout, isolation, env=env)
    assert adapter.verify(value, expected) == []
    value[0]["Config"]["Env"] += ["PWD=/", "TERM=xterm"]
    assert adapter.verify(value, expected) == []
    default = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    assert adapter.verify(value, default) == ["environment"]
    value[0]["Config"]["Env"] = ["LANG=unapproved" if item.startswith("LANG=") else item
                                  for item in value[0]["Config"]["Env"]]
    assert adapter.verify(value, expected) == ["environment"]


@pytest.mark.parametrize("key", ["LANG", "LC_ALL", "TZ"])
def test_allowlist_name_without_override_witness_refuses(adapter, layout, key):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["Config"]["Env"].append(key + "=ambient-value")
    assert adapter.verify(value, expected) == ["environment"]


@pytest.mark.parametrize("change", ["missing", "wrong-value", "duplicate", "inherit-host"])
def test_recorded_create_environment_must_agree(adapter, layout, change):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    argv = value[0]["Config"]["CreateCommand"]
    index = next(i for i, word in enumerate(argv) if word.startswith("HOME="))
    if change == "missing":
        del argv[index - 1:index + 1]
    elif change == "wrong-value":
        argv[index] = "HOME=" + str(layout.project)
    elif change == "inherit-host":
        argv[index] = "HOME"
    else:
        argv[index:index] = [argv[index], "--env"]
    assert adapter.verify(value, expected) == ["environment"]


@pytest.mark.parametrize("change", ["missing-map", "missing-home", "fixed-home", "unapproved-key"])
def test_expected_environment_cannot_waive_value_contract(adapter, layout, change):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    assert adapter.verify(value, expected) == []

    def fingerprint(key, content):
        # The normalized witness format hashes canonical JSON [name,value], not raw credential values.
        return hashlib.sha256(json.dumps([key, content], ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()

    values = dict(item.split("=", 1) for item in value[0]["Config"]["Env"])
    expected.setdefault("environment", {key: fingerprint(key, content) for key, content in values.items()})
    if change == "missing-map":
        del expected["environment"]
    elif change == "missing-home":
        del expected["environment"]["HOME"]
    else:
        key = "HOME" if change == "fixed-home" else "UNAPPROVED_KEY"
        content = str(layout.project) if change == "fixed-home" else "synthetic-value"
        expected["environment"][key] = fingerprint(key, content)
        values[key] = content
        value[0]["Config"]["Env"] = [k + "=" + v for k, v in values.items()]
        argv = value[0]["Config"]["CreateCommand"]
        if change == "fixed-home":
            argv[next(i for i, word in enumerate(argv) if word.startswith("HOME="))] = "HOME=" + content
        else:
            argv[-1:-1] = ["--env", key + "=" + content]
    assert adapter.verify(value, expected) == ["environment"]


@pytest.mark.parametrize("bad", [False, {}, ["A=one", "A=two"], ["not-an-assignment"], ["BAD-NAME=value"]])
def test_image_environment_malformed_refuses(adapter, layout, bad):
    info = image_info()
    info[0]["Config"]["Env"] = bad
    with pytest.raises(ValueError, match="^image inspect has invalid Config.Env$"):
        expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout), image_inspect=info)


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
@pytest.mark.parametrize("change", ["opposite", "both", "duplicate", "wrong-type", "bad-member", "binds",
                                    "binds-duplicate", "binds-both", "binds-last-match"])
def test_every_bind_access_witness_must_agree(adapter, layout, engine, rw, surface, change):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    if surface == "fake-cli":
        expected, value = fake_created_inspect(adapter, layout, isolation)
    else:
        expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
        value = inspect_for(expected)
    row = next(row for row in value[0]["Mounts"] if row["RW"] is rw)
    opposite = "ro" if rw else "rw"
    access = "rw" if rw else "ro"
    if change.startswith("binds"):
        flags = {"binds": opposite, "binds-duplicate": access + "," + access,
                 "binds-both": "ro,rw", "binds-last-match": access}[change]
        value[0]["HostConfig"]["Binds"] = ["%s:%s:%s" % (row["Source"], row["Destination"], flags)]
        if change == "binds-last-match":
            row["RW"] = not rw
            row["Options" if engine == "podman" else "Mode"] = [opposite] if engine == "podman" else opposite
    elif engine == "podman":
        row["Options"] = {"opposite": [opposite], "both": ["ro", "rw"], "duplicate": [access, access],
                          "wrong-type": opposite, "bad-member": [False]}[change]
    else:
        row["Mode"] = {"opposite": opposite, "both": "ro,rw", "duplicate": access + "," + access,
                       "wrong-type": [opposite], "bad-member": False}[change]
    assert verify_surface(adapter, layout, expected, value, surface) == ["mounts"]


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("rw", [False, True])
def test_optional_bind_access_fields_may_be_absent_or_agree(adapter, layout, engine, rw):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected, value = fake_created_inspect(adapter, layout, isolation)
    row = next(row for row in value[0]["Mounts"] if row["RW"] is rw)
    field = "Options" if engine == "podman" else "Mode"
    row.pop(field, None)
    assert adapter.verify(value, expected) == []
    row[field] = ["rw" if rw else "ro", "rbind"] if engine == "podman" else ("rw" if rw else "ro")
    assert adapter.verify(value, expected) == []


@pytest.mark.parametrize("axis", ["uid", "gid"])
@pytest.mark.parametrize("identity", [0, 1000, 65536, 70000, 4294967294])
@pytest.mark.parametrize("surface", ["pure", "fake-cli"])
def test_modelled_mapping_supports_independent_linux_ids(adapter, layout, axis, identity, surface):
    uid, gid = (identity, 1000) if axis == "uid" else (1000, identity)
    if surface == "fake-cli":
        expected, value = fake_created_inspect(adapter, layout, ISOLATION, uid=uid, gid=gid)
    else:
        expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout), uid=uid, gid=gid)
        value = inspect_for(expected)
    wanted = (["0:0:1", "1:1:65536"] if identity == 0 else
              ["0:1:1000", "1000:0:1", "1001:1001:64536"] if identity == 1000 else
              ["0:1:65536", "%d:0:1" % identity])
    assert adapter.verify(value, expected) == []
    assert value[0]["HostConfig"]["IDMappings"]["UidMap" if axis == "uid" else "GidMap"] == wanted


def test_fake_image_environment_and_manifest_list(adapter, layout, monkeypatch):
    image_path = layout.run.parent / "image.json"
    image_path.write_text(json.dumps([{"Id": "sha256:" + "b" * 64, "Digest": "sha256:" + "c" * 64,
                                      "RepoDigests": [IMAGE], "Config": {"Env": ["IMAGE_SETTING=fixture"]}}]),
                          encoding="utf-8")
    monkeypatch.setenv("AEGIS_FAKE_ENGINE_IMAGE", str(image_path))
    monkeypatch.setenv("HTTPS_PROXY", "fixture-host-proxy")
    plan = mounts(adapter, layout)

    def call(argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        return result.stdout

    image_info = call(adapter.image_inspect_argv("podman", IMAGE))
    call(adapter.create_argv(ISOLATION, run=layout.run, mounts=plan))
    value = json.loads(call(adapter.inspect_argv("podman", layout.run)))
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=plan, image_inspect=image_info)
    assert "IMAGE_SETTING=fixture" in value[0]["Config"]["Env"]
    assert not any(item.startswith("HTTPS_PROXY=") for item in value[0]["Config"]["Env"])
    assert adapter.verify(value, expected) == []
    value[0]["ImageDigest"] = "sha256:" + "d" * 64
    assert adapter.verify(value, expected) == ["image"]


def test_verify_cli_inspects_pinned_image_once(adapter, layout):
    config = config_for(layout)
    planned = cli(layout, config, "plan")
    assert planned.returncode == 0, planned.stdout
    plan = json.loads(planned.stdout)
    path = layout.run.parent / "inspect.json"
    path.write_text(json.dumps(inspect_for(expected_for(adapter, plan["isolation"], run=config["run"], mounts=plan["mounts"]))), encoding="utf-8")
    verified = cli(layout, config, "verify", "--inspect", str(path))
    assert verified.returncode == 0, verified.stdout
    log = Path(os.environ["AEGIS_FAKE_ENGINE_LOG"])
    assert log.exists(), "verify must inspect the pinned image"
    assert [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] == [["image", "inspect", IMAGE]]


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
def test_builders_refuse_unequal_path_spellings(adapter, layout, builder):
    plan = mounts(adapter, layout)
    plan[0]["source"] += "/."
    with pytest.raises(ValueError, match="^mount source and destination must be equal$"):
        getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=plan, **(
            {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}))


@pytest.mark.parametrize("field,bad", [("Tmpfs", []), ("Binds", {})])
def test_verify_malformed_mount_declarations(adapter, layout, field, bad):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    # Retain the valid declaration in Mounts so a malformed, empty second representation cannot be ignored.
    value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True})
    value[0]["HostConfig"][field] = bad
    assert adapter.verify(value, expected) == ["mounts"]


def test_verify_cpu_quota_rounding(adapter, layout):
    isolation = {**ISOLATION, "cpus": 0.33333333}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"].update(NanoCpus=0, CpuPeriod=100000, CpuQuota=33333)
    assert adapter.verify(value, expected) == []
    value[0]["HostConfig"]["CpuQuota"] = 33334
    assert adapter.verify(value, expected) == ["cpus"]


def test_verify_cli_image_timeout(adapter, layout):
    config = config_for(layout)
    plan = json.loads(cli(layout, config, "plan").stdout)
    path = layout.run.parent / "inspect.json"
    path.write_text(json.dumps(inspect_for(expected_for(adapter, plan["isolation"], run=config["run"], mounts=plan["mounts"]))), encoding="utf-8")
    result = cli(layout, config, "verify", "--inspect", str(path), bootstrap=(
        "import subprocess; subprocess.run = lambda *a,**kw: "
        "(_ for _ in ()).throw(subprocess.TimeoutExpired(a[0], kw['timeout'])); "))
    assert result.returncode == 2 and json.loads(result.stdout) == {"error": "image inspect timed out after 30 seconds"}


@pytest.mark.skipif(os.environ.get("AEGIS_TEST_CONTAINER") != "podman",
                    reason="set AEGIS_TEST_CONTAINER=podman to opt into a real local container")
def test_real_podman_opt_in(adapter, layout, monkeypatch):
    if REAL_PODMAN is None:
        pytest.skip("podman is not on PATH")

    def call(argv):
        # Keep the engine's existing local image store; container HOME is independently passed with --env.
        return subprocess.run([REAL_PODMAN, *argv[1:]], env=dict(os.environ, HOME=ENGINE_HOME),
                              capture_output=True, text=True, timeout=60)

    image = call(adapter.image_inspect_argv("podman", "ubuntu:24.04"))
    if image.returncode:
        pytest.skip("local ubuntu:24.04 is unavailable: " + image.stderr.strip())
    info = json.loads(image.stdout)[0]
    refs = info.get("RepoDigests", [])
    if not refs:
        pytest.skip("local ubuntu:24.04 has no repository digest")
    isolation = adapter.read_isolation({**ISOLATION, "image": refs[0]}, run=layout.run, home=layout.home)
    monkeypatch.setattr(os, "lstat", layout.host_lstat)  # Native admission must use real ownership and modes.
    plan = mounts(adapter, layout)
    for name in ("home", "codex-home", "claude-home"):
        (layout.run / name).mkdir()
    proc = call(adapter.create_argv(isolation, run=layout.run, mounts=plan))
    assert proc.returncode == 0, proc.stderr
    try:
        pinned_image = call(adapter.image_inspect_argv("podman", isolation["image"]))
        assert pinned_image.returncode == 0, pinned_image.stderr
        expected = expected_for(adapter, isolation, run=layout.run, mounts=plan, image_inspect=pinned_image.stdout)
        inspected = call(adapter.inspect_argv("podman", layout.run))
        assert inspected.returncode == 0, inspected.stderr
        assert adapter.verify(inspected.stdout, expected) == []
        identity = call(adapter.exec_argv("podman", layout.run, ["id", "-u"], workdir=layout.project))
        assert identity.returncode == 0 and identity.stdout.strip() == str(os.getuid()), identity.stderr
    finally:
        stopped = call(adapter.stop_argv("podman", layout.run, timeout=5))
        removed = call(adapter.rm_argv("podman", layout.run))
        assert stopped.returncode == removed.returncode == 0, stopped.stderr + removed.stderr


def assert_request_witness(adapter, layout, expected, value, surface, labels):
    if surface == "pure":
        assert adapter.verify(value, expected) == labels
        return
    path = layout.run.parent / "request-inspect.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    isolation = {**ISOLATION, "cpus": expected["cpus"], "pids": expected["pids"],
                 "memory": str(expected["memory"] // 1024) + "k"}
    result = cli(layout, {**config_for(layout), "isolation": isolation}, "verify", "--inspect", str(path))
    assert result.returncode == (2 if labels else 0), result.stdout + result.stderr
    assert json.loads(result.stdout) == {"mismatches": labels}


def add_recorded(value, flag, requests):
    value[0]["Config"]["CreateCommand"][-1:-1] = [word for request in requests for word in (flag, request)]


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("flag,label,bad", [
    ("--cpus", "cpus", bad) for bad in
    ("0", "-1", "0.001", "NaN", "inf", "1e9999", "malformed", "", "0.5", "1_0", " 1 ")
] + [("--memory", "memory", bad) for bad in
     ("0", "-1", "0g", "NaN", "1", "1G", "2g", "", "1.5g", "true")
] + [("--pids-limit", "pids", bad) for bad in
     ("-1", "0", "63", "nan", "65", "64.0", "true", "", "1e3")])
def test_recorded_resource_request_refuses(adapter, layout, surface, flag, label, bad):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    add_recorded(value, flag, [bad])
    assert_request_witness(adapter, layout, expected, value, surface, [label])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("flag,label,good,bad", [("--cpus", "cpus", "1", "0"),
                                                ("--memory", "memory", "1g", "0"),
                                                ("--pids-limit", "pids", "64", "-1")])
@pytest.mark.parametrize("bad_first", [False, True])
def test_recorded_resource_duplicates_conjoin(adapter, layout, surface, flag, label, good, bad, bad_first):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    add_recorded(value, flag, [bad, good] if bad_first else [good, bad])
    assert_request_witness(adapter, layout, expected, value, surface, [label])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("case", ["absent", "matching", "equivalent", "agreeing-duplicates"])
def test_recorded_resource_request_admitted(adapter, layout, surface, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    if case != "absent":
        for flag, good, equivalent in (("--cpus", "1", "+1.0"), ("--memory", "1g", "1024m"),
                                        ("--pids-limit", "64", "+064")):
            requests = [good] if case == "matching" else [equivalent]
            add_recorded(value, flag, [good, equivalent] if case == "agreeing-duplicates" else requests)
    assert_request_witness(adapter, layout, expected, value, surface, [])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("representation", ["both", "quota", "nano"])
@pytest.mark.parametrize("cpus,cpu_request,equal", [(0.29, "0.290", True), (0.5, "0.500000001", True),
                                              (0.29, "0.29000000000000004", False), (0.5, "0.50002", False)])
def test_recorded_cpu_request_uses_observed_rounding(adapter, layout, surface, representation, cpus, cpu_request, equal):
    expected = expected_for(adapter, {**ISOLATION, "cpus": cpus}, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    quota = int(float(cpus) * 100000)  # Model the captured conversion; this does not execute Podman.
    value[0]["HostConfig"].update(CpuPeriod=100000, CpuQuota=quota, NanoCpus=quota * 10000)
    if representation == "quota":
        value[0]["HostConfig"]["NanoCpus"] = 0
    elif representation == "nano":
        value[0]["HostConfig"].update(CpuQuota=0, CpuPeriod=0)
    add_recorded(value, "--cpus", [cpu_request])
    assert_request_witness(adapter, layout, expected, value, surface, [] if equal else ["cpus"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
def test_recorded_cpu_domain_cannot_be_waived_by_rounding(adapter, layout, surface):
    available = os.cpu_count()
    expected = expected_for(adapter, {**ISOLATION, "cpus": available}, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    quota = available * 100000
    value[0]["HostConfig"].update(CpuPeriod=100000, CpuQuota=quota, NanoCpus=quota * 10000)
    cpu_request = str(available) + ".000000001"
    assert float(cpu_request) > available and int(float(cpu_request) * 100000) == quota
    add_recorded(value, "--cpus", [cpu_request])
    assert_request_witness(adapter, layout, expected, value, surface, ["cpus"])


def recorded_bind(row):
    return "type=bind,src={source},dst={destination}".format(**row) + ("" if row["rw"] else ",readonly")


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("case", ["source", "destination", "access", "extra", "malformed", "missing-kind",
                                  "wrong-kind", "conflicting-src-before", "conflicting-src-after",
                                  "bad-good", "good-bad"])
def test_recorded_bind_request_refuses(adapter, layout, surface, rw, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    row = next(row for row in expected["mounts"] if row["rw"] == rw)
    good = recorded_bind(row)
    bad = {"source": recorded_bind({**row, "source": "/wrong"}),
           "destination": recorded_bind({**row, "destination": "/wrong"}),
           "access": recorded_bind({**row, "rw": not rw}),
           "extra": "type=bind,src=/extra,dst=/extra", "malformed": "type=bind,src=",
           "missing-kind": good.removeprefix("type=bind,"), "wrong-kind": good.replace("type=bind", "type=volume"),
           "conflicting-src-before": "src=/wrong," + good, "conflicting-src-after": good + ",src=/wrong",
           "bad-good": recorded_bind({**row, "rw": not rw}),
           "good-bad": recorded_bind({**row, "rw": not rw})}[case]
    requests = [bad, good] if case == "bad-good" else [good, bad] if case == "good-bad" else [bad]
    add_recorded(value, "--mount", requests)
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("case", ["absent", "matching-subset", "emitted-all", "matching-duplicate", "matching-fields"])
def test_recorded_bind_request_admitted(adapter, layout, surface, rw, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    row = next(row for row in expected["mounts"] if row["rw"] == rw)
    good = recorded_bind(row)
    requests = {"absent": [], "matching-subset": [good],
                "emitted-all": [recorded_bind(row) for row in expected["mounts"]], "matching-duplicate": [good, good],
                "matching-fields": [good + ",type=bind,src=" + row["source"] + ",dst=" + row["destination"]]}[case]
    add_recorded(value, "--mount", requests)
    assert_request_witness(adapter, layout, expected, value, surface, [])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("dest", ["/tmp", "/dev/shm"])
@pytest.mark.parametrize("case", ["wrong-destination", "ro", "suid", "dev", "access-conflict", "duplicate-rw",
                                  "exec-conflict", "exec-noexec", "noexec-exec", "actual-conflict",
                                  "missing-safety", "missing-options", "malformed", "bad-good", "good-bad"])
def test_recorded_tmpfs_request_refuses(adapter, layout, surface, dest, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    safe = dest + ":rw,nosuid,nodev"
    bad = {"wrong-destination": "/run:rw,nosuid,nodev", "ro": dest + ":ro,nosuid,nodev",
           "suid": safe + ",suid", "dev": safe + ",dev", "access-conflict": safe + ",ro",
           "duplicate-rw": safe + ",rw", "exec-conflict": safe + ",exec,noexec",
           "actual-conflict": safe + ",exec", "missing-safety": dest + ":rw,nodev",
           "missing-options": dest, "malformed": dest + ":rw:nosuid,nodev",
           "bad-good": dest + ":rw,suid,dev", "good-bad": dest + ":rw,suid,dev"}.get(case)
    if case in ("exec-noexec", "noexec-exec"):
        requests = [safe + ",exec", safe + ",noexec"]
        if case == "noexec-exec":
            requests.reverse()
    else:
        requests = [bad, safe] if case == "bad-good" else [safe, bad] if case == "good-bad" else [bad]
    if case == "actual-conflict":
        value[0]["HostConfig"]["Tmpfs"][dest] += ",noexec"
    add_recorded(value, "--tmpfs", requests)
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("case", ["absent", "safe", "both", "agreeing-duplicates", "exec", "noexec"])
def test_recorded_tmpfs_request_admitted(adapter, layout, surface, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    good = "/tmp:rw,nosuid,nodev"
    requests = {"absent": [], "safe": [good], "both": [good, "/dev/shm:rw,nosuid,nodev"],
                "agreeing-duplicates": [good, good], "exec": [good + ",exec"], "noexec": [good + ",noexec"]}[case]
    add_recorded(value, "--tmpfs", requests)
    assert_request_witness(adapter, layout, expected, value, surface, [])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("case", ["malformed", "empty", "negative", "reserved-uid", "reserved-gid", "huge",
                                  "wrong", "bad-good", "good-bad"])
def test_recorded_user_request_refuses(adapter, layout, surface, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    uid, gid = map(int, expected["user"].split(":"))
    wrong = "%d:%d" % ((uid + 1) % 4294967295, gid)
    bad = {"malformed": "1:2:3", "empty": "", "negative": "-1:0", "reserved-uid": "4294967295:0",
           "reserved-gid": "0:4294967295", "huge": "4294967296:0", "wrong": wrong,
           "bad-good": wrong, "good-bad": wrong}[case]
    add_recorded(value, "--user", [bad, expected["user"]] if case == "bad-good" else [
        expected["user"], bad] if case == "good-bad" else [bad])
    assert_request_witness(adapter, layout, expected, value, surface, ["user"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("case", ["absent", "matching", "leading-zeros", "agreeing-duplicates"])
def test_recorded_user_request_admitted(adapter, layout, surface, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    user = expected["user"]
    requests = {"absent": [], "matching": [user], "leading-zeros": ["0" + user.replace(":", ":0")],
                "agreeing-duplicates": [user, user]}[case]
    add_recorded(value, "--user", requests)
    assert_request_witness(adapter, layout, expected, value, surface, [])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("case", ["wrong", "missing-equals", "empty", "bad-good", "good-bad",
                                  "absent", "matching", "unrelated", "unrelated-no-equals", "agreeing-duplicates"])
def test_recorded_run_label_request(adapter, layout, surface, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    good = "aegis.team.run=" + expected["run"]
    bad = "aegis.team.run=/wrong"
    requests = {"wrong": [bad], "missing-equals": ["aegis.team.run"], "empty": ["aegis.team.run="],
                "bad-good": [bad, good], "good-bad": [good, bad], "absent": [], "matching": [good],
                "unrelated": ["unrelated=/wrong", "aegis.team.runner=/wrong"],
                "unrelated-no-equals": ["unrelated"], "agreeing-duplicates": [good, good]}[case]
    add_recorded(value, "--label", requests)
    assert_request_witness(adapter, layout, expected, value, surface,
                           ["label"] if case in ("wrong", "missing-equals", "empty", "bad-good", "good-bad") else [])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("kind", ["bind", "tmpfs"])
@pytest.mark.parametrize("bad", ["missing", None, False, 1, [], {}, "", "volume"])
def test_mount_kind_requires_explicit_supported_witness(adapter, layout, surface, kind, bad):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"]["Binds"] = [row["source"] + ":" + row["destination"] + ":" + (
        "rw" if row["rw"] else "ro") + ",rprivate,rbind" for row in expected["mounts"]]
    row = value[0]["Mounts"][0]
    if kind == "tmpfs":
        row = {"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True}
        value[0]["Mounts"].append(row)
    if bad == "missing":
        del row["Type"]
    else:
        row["Type"] = bad
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("kind", ["bind", "tmpfs"])
@pytest.mark.parametrize("optional", ["absent", "empty-mode", "neutral-mode", "options"])
def test_explicit_mount_kind_preserves_optional_metadata(adapter, layout, surface, kind, optional):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    row = value[0]["Mounts"][0]
    if kind == "tmpfs":
        row = {"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True}
        value[0]["Mounts"].append(row)
    if optional in ("empty-mode", "neutral-mode"):
        row["Mode"] = "" if optional == "empty-mode" else "rprivate"
    elif optional == "options":
        row["Options"] = ["rbind"] if kind == "bind" else ["rw", "nosuid", "nodev"]
    assert_request_witness(adapter, layout, expected, value, surface, [])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("arity", ["separate", "equals"])
def test_recorded_request_mismatch_order_is_stable(adapter, layout, surface, arity):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    for flag, request in (("--pids-limit", "-1"), ("--memory", "0"), ("--cpus", "0"),
                          ("--user", "invalid"), ("--tmpfs", "/tmp:rw,suid,dev"),
                          ("--label", "aegis.team.run=/wrong")):
        if arity == "separate":
            add_recorded(value, flag, [request])
        else:
            value[0]["Config"]["CreateCommand"].insert(-1, flag + "=" + request)
    assert_request_witness(adapter, layout, expected, value, surface,
                           ["label", "mounts", "user", "cpus", "memory", "pids"])


def select_recorded_mount_requests(value, selection):
    # The adapter emits these two flags as separate flag/value pairs; retain every other emitted word.
    original = value[0]["Config"]["CreateCommand"]
    argv, pairs = [], []
    index = 0
    while index < len(original):
        if original[index] in ("--mount", "--tmpfs"):
            pairs.append(original[index:index + 2])
            index += 2
        else:
            argv.append(original[index])
            index += 1
    if selection == "partial":
        pairs = [next(pair for pair in pairs if pair[0] == flag) for flag in ("--mount", "--tmpfs")]
    elif selection == "absent":
        pairs = []
    if selection == "conflicting":
        pairs.append(["--tmpfs", "/tmp:rw,suid,dev"])
    # Insert before the image, using its emitted position rather than treating command arguments as options.
    image_index = argv.index(value[0]["Config"]["Image"])
    argv[image_index:image_index] = [word for pair in pairs for word in pair]
    value[0]["Config"]["CreateCommand"] = argv


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("requests", ["absent", "partial", "matching", "conflicting"])
def test_requests_never_reconstruct_all_actual_mount_evidence(adapter, layout, surface, requests):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    select_recorded_mount_requests(value, requests)
    value[0]["Mounts"] = []
    value[0]["HostConfig"].update(Binds=None, Tmpfs=None)
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("requests", ["absent", "partial", "matching", "conflicting"])
@pytest.mark.parametrize("missing", ["run", "project", "source", "prefix", "live"])
def test_request_never_replaces_one_actual_bind(adapter, layout, surface, requests, missing):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    select_recorded_mount_requests(value, requests)
    dest = str(getattr(layout, missing))
    value[0]["Mounts"] = [row for row in value[0]["Mounts"] if row["Destination"] != dest]
    value[0]["HostConfig"]["Binds"] = [row for row in value[0]["HostConfig"]["Binds"] if row.split(":")[1] != dest]
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("requests", ["absent", "partial", "matching", "conflicting"])
@pytest.mark.parametrize("dest", ["/tmp", "/dev/shm"])
@pytest.mark.parametrize("actual", ["no-declaration", "no-safety", "missing-nosuid", "missing-nodev", "malformed"])
def test_recorded_flags_never_supply_actual_scratch_safety(adapter, layout, surface, requests, dest, actual):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    select_recorded_mount_requests(value, requests)
    del value[0]["HostConfig"]["Tmpfs"][dest]
    if actual != "no-declaration":
        # Model supported explicit tmpfs rows, already covered by the public actual-mount contract.
        # The fake's native-derived baseline supplies all other fields; this is not fresh native evidence.
        mode = {"no-safety": "", "missing-nosuid": "rw,nodev", "missing-nodev": "rw,nosuid",
                "malformed": None}[actual]
        value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": dest,
                                   "RW": True, "Mode": mode})
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("requests", ["absent", "partial", "matching", "conflicting"])
@pytest.mark.parametrize("field,bad", [("Mounts", None), ("Binds", {}), ("Tmpfs", [])])
def test_matching_requests_never_replace_unknown_actual_mount_metadata(adapter, layout, surface, requests, field, bad):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    select_recorded_mount_requests(value, requests)
    if field == "Mounts":
        value[0][field] = bad
    else:
        value[0]["HostConfig"][field] = bad
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("requests", ["absent", "partial", "matching"])
@pytest.mark.parametrize("representations", ["captured", "mounts-plus-tmpfs", "binds-plus-tmpfs", "mounts-only", "mixed"])
def test_actual_mount_evidence_combinations_remain_sufficient(adapter, layout, surface, requests, representations):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    select_recorded_mount_requests(value, requests)
    host = value[0]["HostConfig"]
    if representations == "mounts-plus-tmpfs":
        host["Binds"] = None
    elif representations == "binds-plus-tmpfs":
        value[0]["Mounts"] = []
    elif representations in ("mounts-only", "mixed"):
        # Alternate supported representations are modelled from the existing inspect schema, not native claims.
        destinations = ("/tmp", "/dev/shm")
        if representations == "mixed":
            host["Binds"] = host["Binds"][3:]
            value[0]["Mounts"] = value[0]["Mounts"][:3]
            del host["Tmpfs"]["/dev/shm"]
            destinations = ("/dev/shm",)
        else:
            host.update(Binds=None, Tmpfs=None)
        for dest in destinations:
            value[0]["Mounts"].append({"Type": "tmpfs", "Source": "tmpfs", "Destination": dest, "RW": True,
                                       "Mode": "", "Options": ["rw", "nosuid", "nodev", "rprivate", "tmpcopyup"]})
    assert_request_witness(adapter, layout, expected, value, surface, [])


def test_actual_evidence_supports_a_declared_empty_bind_plan(adapter, layout):
    # The pure record API permits an empty bind plan; this prevents replacing exact coverage with count > 0.
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=[])
    assert adapter.verify(inspect_for(expected), expected) == []


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("field,label", [("cpu", "cpus"), ("memory", "memory"), ("pids", "pids"),
                                        ("user", "user"), ("label", "label"), ("name", "name"),
                                        ("env", "environment"), ("image", "image"), ("namespace", "userns_mode"),
                                        ("readonly", "read_only"), ("security", "security_opt")])
def test_other_requests_cannot_supply_missing_actual_facts(adapter, layout, surface, field, label):
    expected, value = fake_created_inspect(adapter, layout, ISOLATION)
    actual, config, host = value[0], value[0]["Config"], value[0]["HostConfig"]
    if field == "cpu":
        host.update(NanoCpus=0, CpuQuota=0, CpuPeriod=0)
    elif field in ("memory", "pids"):
        host["Memory" if field == "memory" else "PidsLimit"] = None
    elif field == "user":
        config["User"] = None
    elif field == "label":
        config["Labels"] = {}
    elif field == "name":
        actual["Name"] = None
    elif field == "env":
        config["Env"] = []
    elif field == "image":
        actual["Image"] = None
    elif field == "namespace":
        host["IDMappings"] = None
    elif field == "readonly":
        host["ReadonlyRootfs"] = None
    else:
        host["SecurityOpt"] = None
    assert_request_witness(adapter, layout, expected, value, surface, [label])


def model_system_mount_metadata(monkeypatch):
    # Model only OS metadata for these system paths. Never create/write them or inspect owner homes.
    paths = {"/", "//", "/dev", "/dev/shm", "/usr", "//usr", "/opt", "/var", "/var/tmp"}
    original_lstat, original_xattr = os.lstat, os.getxattr

    def lstat(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if str(path) in paths:
            parts = list(info)
            parts[0], parts[4], parts[5] = stat.S_IFDIR | 0o755, 0, 0
            return os.stat_result(parts)
        return info

    def getxattr(path, *args, **kwargs):
        if str(path) in paths:
            raise OSError(errno.ENODATA, "modelled absent access ACL")
        return original_xattr(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "getxattr", getxattr)
    return ("import errno,stat; _system_paths=%r; _system_lstat=os.lstat; _system_xattr=os.getxattr; "
            "os.lstat=lambda p,*a,**kw: (lambda st: os.stat_result([stat.S_IFDIR|0o755]+list(st)[1:4]+[0,0]"
            "+list(st)[6:]) if str(p) in _system_paths else st)(_system_lstat(p,*a,**kw)); "
            "os.getxattr=lambda p,*a,**kw: (_ for _ in ()).throw(OSError(errno.ENODATA,"
            "'modelled absent access ACL')) if str(p) in _system_paths else _system_xattr(p,*a,**kw); " % sorted(paths))


def bind_policy_case(layout, case):
    path = {"scratch": "/dev/shm", "system-alias": "//usr",
            "ordinary-alias": "/" + str(layout.project)}[case]
    message = ("mount conflicts with mandatory scratch tmpfs: " if case == "scratch" else
               "mount path has double leading slash: ") + path
    return path, message


@pytest.mark.parametrize("surface", ["library", "cli"])
@pytest.mark.parametrize("case", ["scratch", "system-alias", "ordinary-alias"])
def test_bind_policy_planner_refuses_reserved_and_double_slash(adapter, layout, monkeypatch, surface, case):
    path, message = bind_policy_case(layout, case)
    bootstrap = model_system_mount_metadata(monkeypatch)
    if surface == "library":
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            mounts(adapter, layout, project=path)
    else:
        result = cli(layout, {**config_for(layout), "project": path}, "plan", bootstrap=bootstrap)
        assert result.returncode == 2
        assert json.loads(result.stdout) == {"error": message}


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("case", ["scratch", "system-alias", "ordinary-alias"])
def test_bind_policy_public_builders_refuse(adapter, layout, builder, engine, rw, case):
    path, message = bind_policy_case(layout, case)
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        getattr(adapter, builder)(isolation, run=layout.run,
                                  mounts=[{"source": path, "destination": path, "rw": rw}], **kwargs)


@pytest.mark.parametrize("case", ["scratch", "system-alias", "ordinary-alias"])
def test_bind_policy_malicious_expected_and_actual_refuse(adapter, layout, case):
    path, _ = bind_policy_case(layout, case)
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["mounts"][0].update(source=path, destination=path)
    value[0]["Mounts"][0].update(Source=path, Destination=path)
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("carrier", ["actual", "request"])
@pytest.mark.parametrize("case", ["scratch", "system-alias", "ordinary-alias"])
def test_bind_policy_actual_and_request_refuse(adapter, layout, surface, carrier, case):
    path, _ = bind_policy_case(layout, case)
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    if carrier == "actual":
        value[0]["Mounts"][0].update(Source=path, Destination=path)
    else:
        add_recorded(value, "--mount", ["type=bind,src=" + path + ",dst=" + path])
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("surface", ["library", "cli"])
def test_bind_policy_planner_keeps_scratch_descendant(adapter, layout, monkeypatch, surface):
    bootstrap = model_system_mount_metadata(monkeypatch)
    path = "/dev/shm/aegis-project"
    if surface == "library":
        plan = mounts(adapter, layout, project=path)
    else:
        result = cli(layout, {**config_for(layout), "project": path}, "plan", bootstrap=bootstrap)
        assert result.returncode == 0, result.stdout
        plan = json.loads(result.stdout)["mounts"]
    assert {"source": path, "destination": path, "rw": True} in plan


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("path", ["/dev/shm/aegis-project", "/opt/aegis-project"])
def test_bind_policy_builders_keep_ordinary_descendants(adapter, layout, engine, path):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows = [{"source": path, "destination": path, "rw": True}]
    argv = adapter.create_argv(isolation, run=layout.run, mounts=rows)
    expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
    assert "type=bind,src=" + path + ",dst=" + path in argv
    assert adapter.verify(inspect_for(expected), expected) == []


# Same-path binds inside these trees would replace pinned image userland or expose host runtime/devices.
IMAGE_USERLAND_PATHS = ["/usr/bin", "/usr/local/bin", "/usr/lib", "/etc/aegis", "/var/lib/aegis", "/run/user/1000",
                        "/bin/aegis", "/lib64/aegis", "/dev/aegis", "/var/tmp"]


@pytest.mark.parametrize("surface", ["library", "cli"])
@pytest.mark.parametrize("field", ["project", "python_prefix", "live_checkouts"])
@pytest.mark.parametrize("path", IMAGE_USERLAND_PATHS)
def test_image_userland_descendant_planner_refuses(adapter, layout, surface, field, path):
    message = "mount replaces image system directory: " + path
    value = [path] if field == "live_checkouts" else path
    if surface == "library":
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            mounts(adapter, layout, **{field: value})
        return
    config = {**config_for(layout), field: value}
    for command in (["plan"], ["verify", "--inspect", str(layout.run.parent / "not-read-inspect.json")]):
        result = cli(layout, config, *command)
        assert result.returncode == 2, result.stdout + result.stderr
        assert json.loads(result.stdout) == {"error": message}


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("path", IMAGE_USERLAND_PATHS)
def test_image_userland_descendant_builders_refuse(adapter, layout, builder, engine, rw, path):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
        getattr(adapter, builder)(isolation, run=layout.run,
                                  mounts=[{"source": path, "destination": path, "rw": rw}], **kwargs)


@pytest.mark.parametrize("path", IMAGE_USERLAND_PATHS)
def test_image_userland_expected_record_and_matching_actual_refuse(adapter, layout, path):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["mounts"][0].update(source=path, destination=path)
    value[0]["Mounts"][0].update(Source=path, Destination=path)
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("surface", ["library", "cli"])
@pytest.mark.parametrize("path", ["/opt/aegis-project", "/var/tmp/aegis-project", "/dev/shm/aegis-project"])
def test_image_userland_planner_keeps_carve_outs(adapter, layout, monkeypatch, surface, path):
    bootstrap = model_system_mount_metadata(monkeypatch)
    if surface == "library":
        plan = mounts(adapter, layout, project=path)
    else:
        result = cli(layout, {**config_for(layout), "project": path}, "plan", bootstrap=bootstrap)
        assert result.returncode == 0, result.stdout
        plan = json.loads(result.stdout)["mounts"]
    assert {"source": path, "destination": path, "rw": True} in plan


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("path", ["/opt/aegis-project", "/var/tmp/aegis-project", "/dev/shm/aegis-project",
                                  "/srv/aegis-project"])
def test_image_userland_builders_keep_carve_outs(adapter, layout, engine, path):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows = [{"source": path, "destination": path, "rw": True}] + mounts(adapter, layout)
    argv = adapter.create_argv(isolation, run=layout.run, mounts=rows)
    expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
    assert "type=bind,src=" + path + ",dst=" + path in argv
    assert adapter.verify(inspect_for(expected), expected) == []


def owner_secret_case(layout, case):
    if case == "alias":
        alias = layout.run.parent / "codex-alias"
        alias.symlink_to(layout.home / ".codex", target_is_directory=True)
        return alias
    return {"home-secret": layout.home / ".codex", "passwd-secret": layout.passwd_home / ".codex",
            "missing-tail": layout.home / ".codex" / "sessions", "file-secret": layout.passwd_home / ".netrc",
            "home": layout.home, "contains-home": layout.home.parent}[case]


OWNER_SECRET_CASES = ["home-secret", "passwd-secret", "missing-tail", "file-secret", "alias", "home", "contains-home"]


@pytest.mark.parametrize("case", OWNER_SECRET_CASES)
def test_expected_record_cannot_authorize_owner_secret(adapter, layout, case):
    path = str(owner_secret_case(layout, case))
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["mounts"][0].update(source=path, destination=path)
    value[0]["Mounts"][0].update(Source=path, Destination=path)
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("case", OWNER_SECRET_CASES)
def test_builders_refuse_owner_homes_and_secrets(adapter, layout, builder, rw, case):
    path = str(owner_secret_case(layout, case))
    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^mount overlaps protected home: " + re.escape(path) + "$"):
        getattr(adapter, builder)(ISOLATION, run=layout.run,
                                  mounts=[{"source": path, "destination": path, "rw": rw}], **kwargs)


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
@pytest.mark.parametrize("owner", ["home", "passwd_home"])
def test_builders_refuse_every_owner_home_local(adapter, layout, builder, owner):
    # HOME and the password-database home differ in this layout; planning refuses both .local folders.
    path = str(getattr(layout, owner) / ".local")
    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^mount replaces image system directory: " + re.escape(path) + "$"):
        getattr(adapter, builder)(ISOLATION, run=layout.run,
                                  mounts=[{"source": path, "destination": path, "rw": True}], **kwargs)


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
def test_expected_record_cannot_bind_owner_home_local(adapter, layout, owner):
    path = str(getattr(layout, owner) / ".local")
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["mounts"][0].update(source=path, destination=path)
    value[0]["Mounts"][0].update(Source=path, Destination=path)
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
def test_cli_verify_refuses_owner_secret_mount(layout, owner):
    path = getattr(layout, owner) / ".codex"
    result = cli(layout, {**config_for(layout), "project": str(path)}, "verify",
                 "--inspect", str(layout.run.parent / "not-read-inspect.json"))
    assert result.returncode == 2, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"error": "mount overlaps protected home: " + str(path)}


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
def test_expected_record_keeps_missing_non_secret_home_path(adapter, layout, monkeypatch, owner):
    path = str(getattr(layout, owner) / "Documents" / "missing-project")

    def no_enumeration(*args, **kwargs):
        raise AssertionError("expected-record validation must not enumerate directories")

    with monkeypatch.context() as m:
        m.setattr(os, "scandir", no_enumeration)
        m.setattr(os, "listdir", no_enumeration)
        rows = [{"source": path, "destination": path, "rw": True}] + mounts(adapter, layout)
        assert "type=bind,src=" + path + ",dst=" + path in adapter.create_argv(ISOLATION, run=layout.run, mounts=rows)
        expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=rows)
        assert adapter.verify(inspect_for(expected), expected) == []
    assert not Path(path).exists()


def test_cli_verify_keeps_non_secret_home_project(adapter, layout):
    project = layout.home / "Documents" / "project"
    project.mkdir(parents=True)
    config = {**config_for(layout), "project": str(project)}
    plan = json.loads(cli(layout, config, "plan").stdout)
    assert {"source": str(project), "destination": str(project), "rw": True} in plan["mounts"]
    path = layout.run.parent / "home-project-inspect.json"
    path.write_text(json.dumps(inspect_for(expected_for(adapter, plan["isolation"], run=config["run"],
                                                       mounts=plan["mounts"]))), encoding="utf-8")
    result = cli(layout, config, "verify", "--inspect", str(path))
    assert result.returncode == 0 and json.loads(result.stdout) == {"mismatches": []}, result.stdout


def mount_alias(layout, target, child=""):
    # Dangling targets are deliberate: the engine binds whatever the link names when it resolves the source.
    alias = layout.run.parent / "alias"
    alias.symlink_to(layout.project if target == "project" else target, target_is_directory=True)
    return str(alias / child) if child else str(alias)


PROTECTED_ALIASES = [("/usr/bin", ""), ("/usr/local/bin", ""), ("/usr", "bin"), ("/run/user/1000", ""),
                     ("/dev", ""), ("/var/lib", ""), ("/tmp", ""), ("/", "")]


@pytest.mark.parametrize("target,child", PROTECTED_ALIASES)
def test_alias_into_protected_tree_expected_record_refuses(adapter, layout, target, child):
    path = mount_alias(layout, target, child)
    symlink = "mount source contains a symlink: " + str(layout.run.parent / "alias")
    with pytest.raises(ValueError, match="^" + re.escape(symlink) + "$"):
        mounts(adapter, layout, project=path)
    result = cli(layout, {**config_for(layout), "project": path}, "plan")
    assert result.returncode == 2 and json.loads(result.stdout) == {"error": symlink}, result.stdout
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["mounts"][0].update(source=path, destination=path)
    value[0]["Mounts"][0].update(Source=path, Destination=path)
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("target,child", PROTECTED_ALIASES)
def test_alias_into_protected_tree_builders_refuse(adapter, layout, builder, engine, target, child):
    path = mount_alias(layout, target, child)
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
        getattr(adapter, builder)(isolation, run=layout.run,
                                  mounts=[{"source": path, "destination": path, "rw": True}], **kwargs)


@pytest.mark.parametrize("target", ["project", "/var/tmp/aegis-project", "/dev/shm/aegis-project"])
def test_alias_outside_protected_trees_keeps_builders(adapter, layout, target):
    path = mount_alias(layout, target)
    rows = [{"source": path, "destination": path, "rw": True}] + mounts(adapter, layout)
    assert "type=bind,src=" + path + ",dst=" + path in adapter.create_argv(ISOLATION, run=layout.run, mounts=rows)
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=rows)
    assert adapter.verify(inspect_for(expected), expected) == []


def unreadable_mount(layout, case):
    # Real ENOTDIR, ENAMETOOLONG and ELOOP metadata; none of these is a missing path that may stay legal.
    if case == "file":
        return str(layout.run.parent / ".keep" / "child")
    if case == "long":
        return str(layout.run.parent / ("L" * 300))
    loop = layout.run.parent / "loop"
    loop.symlink_to(loop)
    return str(loop / "child")


UNREADABLE_MOUNTS = ["file", "long", "loop"]


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("case", UNREADABLE_MOUNTS)
def test_recorded_unreadable_mount_is_named_mismatch(adapter, layout, surface, case):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    path = unreadable_mount(layout, case)
    add_recorded(value, "--mount", ["type=bind,src=%s,dst=%s" % (path, path)])
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("case", UNREADABLE_MOUNTS)
def test_expected_record_unreadable_mount_is_named_mismatch(adapter, layout, case):
    path = unreadable_mount(layout, case)
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["mounts"][0].update(source=path, destination=path)
    value[0]["Mounts"][0].update(Source=path, Destination=path)
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
@pytest.mark.parametrize("case", UNREADABLE_MOUNTS)
def test_builders_refuse_unreadable_mount(adapter, layout, builder, case):
    path = unreadable_mount(layout, case)
    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + path) + "$"):
        getattr(adapter, builder)(ISOLATION, run=layout.run,
                                  mounts=[{"source": path, "destination": path, "rw": False}], **kwargs)


def test_unreadable_owner_identity_fails_closed(adapter, layout, monkeypatch):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    denied, original_stat = str(layout.home / ".codex"), os.stat

    def stat_(path, *args, **kwargs):
        # Model EACCES at the OS boundary; a root CI runner could otherwise read a chmod-000 folder.
        if os.fspath(path) == denied:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), denied)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat_)
    assert adapter.verify(value, expected) == ["mounts"]
    first = expected["mounts"][0]["source"]
    for builder, kwargs in (("create_argv", {}), ("expected_plan", {"image_inspect": image_info(IMAGE)})):
        with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + first) + "$"):
            getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=expected["mounts"], **kwargs)
    # The planner keeps reporting the OS error: unreadable identities are never treated as absent there.
    with pytest.raises(PermissionError):
        mounts(adapter, layout)


@pytest.mark.parametrize("surface", ["pure", "cli"])
@pytest.mark.parametrize("field,label", [("CapAdd", "cap_add"), ("Devices", "devices")])
@pytest.mark.parametrize("change", ["missing", "null", "empty"])
def test_confinement_witness_must_be_present(adapter, layout, surface, field, label, change):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    host = value[0]["HostConfig"]
    if change == "missing":
        del host[field]
    else:
        host[field] = None if change == "null" else []
    assert_request_witness(adapter, layout, expected, value, surface, [label] if change == "missing" else [])


@pytest.mark.parametrize("field,label", [("CapAdd", "cap_add"), ("Devices", "devices")])
def test_docker_confinement_witness_must_be_present(adapter, layout, field, label):
    isolation = {**ISOLATION, "engine": "docker", "allow_unqualified": True}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"][field] = None
    assert adapter.verify(value, expected) == []
    del value[0]["HostConfig"][field]
    assert adapter.verify(value, expected) == [label]


def deny_secret_discovery(layout, monkeypatch, owner, code, scope):
    home = layout.home if owner == "home" else layout.passwd_home
    secret = home / ".codex"
    secret.rmdir()
    secret.symlink_to(layout.project, target_is_directory=True)
    names = [".codex"] if scope == "name" else list(SECRET_PATHS)
    denied = {str(home / name) for name in names}
    original = os.lstat
    probes = []

    def lstat_(path, *args, **kwargs):
        if os.fspath(path) in denied:
            probes.append(os.fspath(path))
            raise OSError(code, os.strerror(code), os.fspath(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat_)
    bootstrap = ("_discovery_lstat=os.lstat; _denied_secrets=%r; "
                 "os.lstat=lambda p,*a,**kw: (_ for _ in ()).throw(OSError(%d,%r,os.fspath(p))) "
                 "if os.fspath(p) in _denied_secrets else _discovery_lstat(p,*a,**kw); "
                 % (sorted(denied), code, os.strerror(code)))
    return home / names[0], probes, bootstrap


@pytest.mark.parametrize("owner", ["home", "password"])
@pytest.mark.parametrize("code", [errno.EACCES, errno.EIO, errno.EPERM, errno.ENOTDIR])
@pytest.mark.parametrize("scope", ["name", "directory"])
@pytest.mark.parametrize("surface", ["planner", "create_argv", "expected_plan", "verify"])
def test_secret_discovery_errors_cannot_be_absence(adapter, layout, monkeypatch, owner, code, scope, surface):
    # Build safe comparison inputs before relocating the fake secret, then model discovery (lstat) failure.
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    denied, probes, _ = deny_secret_discovery(layout, monkeypatch, owner, code, scope)
    if surface == "planner":
        with pytest.raises(OSError) as error:
            mounts(adapter, layout)
        assert error.value.errno == code and error.value.filename == str(denied)
    elif surface == "verify":
        assert adapter.verify(value, expected) == ["mounts"]
    else:
        rows = [{"source": str(layout.project), "destination": str(layout.project), "rw": True}]
        kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
        with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + str(layout.project)) + "$"):
            getattr(adapter, surface)(ISOLATION, run=layout.run, mounts=rows, **kwargs)
    assert probes, "the refusal must exercise secret-name discovery itself"


@pytest.mark.parametrize("command", ["plan", "verify"])
@pytest.mark.parametrize("code", [errno.EACCES, errno.EIO, errno.ENOTDIR])
def test_cli_secret_discovery_error_refuses(adapter, layout, monkeypatch, command, code):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    path = layout.run.parent / "discovery-inspect.json"
    path.write_text(json.dumps(inspect_for(expected)), encoding="utf-8")
    denied, _, bootstrap = deny_secret_discovery(layout, monkeypatch, "password", code, "directory")
    args = ("--inspect", str(path)) if command == "verify" else ()
    result = cli(layout, config_for(layout), command, *args, bootstrap=bootstrap)
    assert result.returncode == 2, result.stdout
    assert json.loads(result.stdout) == {"error": str(OSError(code, os.strerror(code), str(denied)))}


@pytest.mark.parametrize("code", [errno.ELOOP, errno.ENOTDIR, errno.EBADF])
def test_source_symlink_probe_errors_are_not_absence(adapter, layout, monkeypatch, code):
    original, probes = os.lstat, []

    def lstat_(path, *args, **kwargs):
        # Fail only the first symlink probe. Later stat/lstat reads cannot retroactively justify ignoring it.
        if os.fspath(path) == str(layout.project) and not probes:
            probes.append(os.fspath(path))
            raise OSError(code, os.strerror(code), os.fspath(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat_)
    with pytest.raises(OSError) as error:
        mounts(adapter, layout)
    assert error.value.errno == code and probes == [str(layout.project)]


@pytest.mark.parametrize("code", [errno.ELOOP, errno.ENOTDIR])
def test_inferred_venv_marker_errors_are_not_missing(layout, code):
    marker = str(layout.prefix / "pyvenv.cfg")
    bootstrap = ("_marker_stat=os.stat; os.stat=lambda p,*a,**kw: (_ for _ in ()).throw("
                 "OSError(%d,%r,os.fspath(p))) if os.fspath(p)==%r else _marker_stat(p,*a,**kw); "
                 % (code, os.strerror(code), marker))
    result = cli(layout, config_for(layout), "plan", bootstrap=bootstrap)
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": str(OSError(code, os.strerror(code), marker))}


def test_confirmed_non_directory_owner_has_no_secret_children(adapter, layout):
    owner_file = layout.run.parent / "non-directory-home"
    owner_file.write_text("not a directory\n", encoding="utf-8")
    plan = mounts(adapter, layout, home=owner_file)
    assert {"source": str(layout.project), "destination": str(layout.project), "rw": True} in plan


@pytest.fixture
def recursive_mount_chain(layout):
    # Real temporary symlinks: an acyclic chain exercises Python realpath recursion, not kernel ELOOP alone.
    folder = layout.run.parent / "recursive-links"
    folder.mkdir()
    links = [folder / ("link-%d" % index) for index in range(sys.getrecursionlimit() + 32)]
    for index, link in enumerate(links):
        link.symlink_to(links[index + 1].name if index + 1 < len(links) else layout.project)
    return str(links[0])


@pytest.mark.parametrize("surface", ["pure", "cli"])
def test_recorded_recursive_mount_refuses(adapter, layout, recursive_mount_chain, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    add_recorded(value, "--mount", ["type=bind,src=%s,dst=%s" % (recursive_mount_chain, recursive_mount_chain)])
    assert_request_witness(adapter, layout, expected, value, surface, ["mounts"])


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_expected_recursive_mount_refuses(adapter, layout, recursive_mount_chain, engine):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    expected["mounts"][0].update(source=recursive_mount_chain, destination=recursive_mount_chain)
    assert adapter.verify(value, expected) == ["mounts"]


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
def test_builder_recursive_mount_refuses(adapter, layout, recursive_mount_chain, engine, builder):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows = [{"source": recursive_mount_chain, "destination": recursive_mount_chain, "rw": True}]
    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + recursive_mount_chain) + "$"):
        getattr(adapter, builder)(isolation, run=layout.run, mounts=rows, **kwargs)


def test_planner_recursive_source_refuses_symlink(adapter, layout, recursive_mount_chain):
    with pytest.raises(ValueError, match="^" + re.escape("mount source contains a symlink: " + recursive_mount_chain) + "$"):
        mounts(adapter, layout, project=recursive_mount_chain)


def test_planner_recursive_secret_refuses(adapter, layout, recursive_mount_chain):
    secret = layout.home / ".codex"
    secret.rmdir()
    secret.symlink_to(recursive_mount_chain)
    with pytest.raises(OSError) as error:
        mounts(adapter, layout)
    assert error.value.errno == errno.ELOOP


MOUNT_RECURSION_PROBES = [("realpath", "source"), ("stat", "source"), ("lstat", "source"),
                          ("realpath", "owner"), ("stat", "owner"), ("lstat", "secret")]


@pytest.mark.parametrize("operation,target", MOUNT_RECURSION_PROBES)
@pytest.mark.parametrize("surface", ["planner", "create_argv", "expected_plan", "expected", "recorded"])
def test_mount_metadata_recursion_is_refused(adapter, layout, monkeypatch, operation, target, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    # Only project rows keep the builder's existing path-specific refusal diagnostic deterministic.
    rows = [{"source": str(layout.project), "destination": str(layout.project), "rw": True}]
    denied = {"source": layout.project, "owner": layout.home, "secret": layout.home / ".codex"}[target]
    # Keep the legacy canonicalization case IDs; inject at the strict resolver's actual OS probe now.
    module, operation = os, "lstat" if operation == "realpath" else operation
    original, probes = getattr(module, operation), []

    def fail(path, *args, **kwargs):
        if os.fspath(path) == str(denied):
            probes.append(str(denied))
            raise RecursionError("modelled mount metadata recursion")
        return original(path, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(module, operation, fail)
        if surface == "planner":
            with pytest.raises(ValueError, match="^mount metadata exceeds recursion limit$"):
                mounts(adapter, layout)
        elif surface in ("create_argv", "expected_plan"):
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + str(layout.project)) + "$"):
                getattr(adapter, surface)(ISOLATION, run=layout.run, mounts=rows, **kwargs)
        else:
            if surface == "recorded":
                add_recorded(value, "--mount", ["type=bind,src=%s,dst=%s" % (denied, denied)])
            assert adapter.verify(value, expected) == ["mounts"]
    assert probes


@pytest.mark.parametrize("surface", ["planner", "create_argv", "expected_plan", "expected", "recorded"])
def test_mount_canonicalization_oserror_refuses(adapter, layout, monkeypatch, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    original, denied = os.lstat, str(layout.project)

    def fail(path, *args, **kwargs):
        if os.fspath(path) == denied:
            raise OSError(errno.EIO, os.strerror(errno.EIO), denied)
        return original(path, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "lstat", fail)
        if surface == "planner":
            with pytest.raises(OSError) as error:
                mounts(adapter, layout)
            assert error.value.errno == errno.EIO and error.value.filename == denied
        elif surface in ("create_argv", "expected_plan"):
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + denied) + "$"):
                getattr(adapter, surface)(ISOLATION, run=layout.run,
                                          mounts=[{"source": denied, "destination": denied, "rw": True}], **kwargs)
        else:
            if surface == "recorded":
                add_recorded(value, "--mount", ["type=bind,src=%s,dst=%s" % (denied, denied)])
            assert adapter.verify(value, expected) == ["mounts"]


def test_planner_acl_metadata_recursion_refuses(adapter, layout, monkeypatch):
    original = os.getxattr

    def fail(path, *args, **kwargs):
        if os.fspath(path) == str(layout.project.parent):
            raise RecursionError("modelled mount ACL query recursion")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "getxattr", fail)
    with pytest.raises(ValueError, match="^mount metadata exceeds recursion limit$"):
        mounts(adapter, layout)


@pytest.mark.parametrize("owner", ["home", "passwd_home", "symlinked_passwd_home"])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_resolved_local_alias_refuses(adapter, layout, monkeypatch, owner, engine, surface):
    import pwd

    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    home = layout.home if owner == "home" else layout.passwd_home
    (home / ".local").mkdir()
    password_home = layout.passwd_home
    if owner == "symlinked_passwd_home":
        password_home = layout.run.parent / "password-home-link"
        password_home.symlink_to(layout.passwd_home, target_is_directory=True)
    alias = layout.run.parent / "local-alias"
    alias.symlink_to((password_home if owner != "home" else home) / ".local", target_is_directory=True)
    path = str(alias)
    with monkeypatch.context() as m:
        if owner == "symlinked_passwd_home":
            # Model only the password-database path; all identity fields retain their fixture values.
            entry = pwd.getpwuid(os.getuid())
            m.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(
                pw_uid=entry.pw_uid, pw_gid=entry.pw_gid, pw_name=entry.pw_name, pw_dir=str(password_home)))
        if surface == "verify":
            expected["mounts"][0].update(source=path, destination=path)
            assert adapter.verify(inspect_for(expected), expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
                getattr(adapter, surface)(isolation, run=layout.run,
                                          mounts=[{"source": path, "destination": path, "rw": True}], **kwargs)


def unavailable_home_lookup(m, shape):
    import pwd

    def unavailable(uid):
        raise KeyError(uid)

    m.delenv("HOME", raising=False)
    m.setattr(pwd, "getpwuid", unavailable)
    if shape == "python39":
        # Model the reported older Path.home KeyError boundary; native Python 3.12 translates it to RuntimeError.
        m.setattr(Path, "home", classmethod(lambda cls: cls(pwd.getpwuid(os.getuid()).pw_dir)))


@pytest.mark.parametrize("shape", ["native", "python39"])
@pytest.mark.parametrize("surface", ["planner", "create_argv", "expected_plan", "verify"])
def test_unavailable_home_lookup_refuses(adapter, layout, monkeypatch, shape, surface):
    rows = mounts(adapter, layout)
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=rows)
    value = inspect_for(expected)
    with monkeypatch.context() as m:
        unavailable_home_lookup(m, shape)
        if surface == "verify":
            assert adapter.verify(value, expected) == ["mounts"]
        else:
            with pytest.raises(ValueError, match="^cannot find the owner's password-database home$"):
                if surface == "planner":
                    mounts(adapter, layout)
                else:
                    kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
                    getattr(adapter, surface)(ISOLATION, run=layout.run, mounts=rows, **kwargs)


@pytest.mark.parametrize("shape", ["native", "python39"])
@pytest.mark.parametrize("command", ["plan", "verify"])
def test_cli_unavailable_home_lookup_refuses(layout, shape, command):
    bootstrap = ("os.environ.pop('HOME',None); "
                 "pwd.getpwuid=lambda uid: (_ for _ in ()).throw(KeyError(uid)); ")
    if shape == "python39":
        bootstrap += ("import pathlib; pathlib.Path.home=classmethod("
                      "lambda cls: cls(pwd.getpwuid(os.getuid()).pw_dir)); ")
    args = ("--inspect", str(layout.run.parent / "not-read.json")) if command == "verify" else ()
    result = cli(layout, config_for(layout), command, *args, bootstrap=bootstrap)
    assert result.returncode == 2, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"error": "cannot find the owner's password-database home"}


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
def test_home_lookup_keeps_environment_and_password_fallback(adapter, layout, monkeypatch, builder):
    import pwd

    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    # Empty stored rows isolate the lookup: owner exclusions still require pwd on any real mount row.
    before = getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=[], **kwargs)
    with monkeypatch.context() as m:
        m.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(KeyError(uid)))
        assert Path.home() == layout.home
        assert getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=[], **kwargs) == before
    rows = mounts(adapter, layout)
    before = getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=rows, **kwargs)
    with monkeypatch.context() as m:
        m.delenv("HOME", raising=False)
        assert Path.home() == layout.passwd_home
        assert getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=rows, **kwargs) == before


STORED_OVERLAPS = ["ro-parent", "rw-parent", "symlink-child", "symlink-equal", "inode", "missing-inode"]


def stored_overlap_rows(layout, kind):
    left, right = layout.source, layout.source / "tools"
    alias = layout.run.parent / "overlap-alias"
    identity = None
    if kind.startswith("symlink"):
        alias.symlink_to(left, target_is_directory=True)
        right = alias if kind == "symlink-equal" else alias / "tools"
    elif kind in ("inode", "missing-inode"):
        alias.mkdir()
        identity = (alias, left.stat())
        right = alias / "tools"
        if kind == "missing-inode":
            left = left / "missing" / "runtime"
            right = alias / "missing" / "runtime" / "tools"
    rows = [{"source": str(left), "destination": str(left), "rw": kind == "rw-parent"},
            {"source": str(right), "destination": str(right), "rw": kind != "rw-parent"}]
    return rows, identity


def model_stored_inode_alias(m, identity):
    if identity is None:
        return
    alias, target = identity
    original = os.stat

    def stat_(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if Path(path) == alias:
            return SimpleNamespace(st_dev=target.st_dev, st_ino=target.st_ino, st_mode=info.st_mode)
        return info

    m.setattr(os, "stat", stat_)


@pytest.mark.parametrize("kind", STORED_OVERLAPS)
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_stored_mixed_access_overlap_refuses(adapter, layout, monkeypatch, kind, reverse, engine, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    rows, identity = stored_overlap_rows(layout, kind)
    if reverse:
        rows.reverse()
    canonical = [os.path.realpath(row["source"]) for row in rows]
    message = "read-write and read-only mounts overlap: %s and %s" % tuple(canonical)
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, identity)
        if surface == "verify":
            expected["mounts"] = rows
            assert adapter.verify(inspect_for(expected), expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
                getattr(adapter, surface)(isolation, run=layout.run, mounts=rows, **kwargs)


@pytest.mark.parametrize("kind", STORED_OVERLAPS)
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_stored_same_access_overlap_stays_valid(adapter, layout, monkeypatch, kind, rw, engine):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows, identity = stored_overlap_rows(layout, kind)
    for row in rows:
        row["rw"] = rw
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, identity)
        assert adapter.create_argv(isolation, run=layout.run, mounts=rows)
        expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
        assert adapter.verify(inspect_for(expected), expected) == []


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_stored_disjoint_access_and_surrogate_paths_stay_valid(adapter, layout, engine):
    # Linux surrogate-escaped bytes are allowed; do not turn the unrelated allegation into a restriction.
    path = str(layout.run.parent / ("bytes-" + chr(0xdcff)))
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows = mounts(adapter, layout, project=path)
    assert {"source": path, "destination": path, "rw": True} in rows
    argv = adapter.create_argv(isolation, run=layout.run, mounts=rows)
    assert "type=bind,src=" + path + ",dst=" + path in argv
    expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
    assert adapter.verify(inspect_for(expected), expected) == []


EMPTY_NAMESPACE_CASES = [("podman", "PidMode", "pid_mode", False),
                         ("podman", "PidMode", "pid_mode", True),
                         ("podman", "IpcMode", "ipc_mode", False),
                         ("podman", "IpcMode", "ipc_mode", True),
                         ("docker", "IpcMode", "ipc_mode", False)]


@pytest.mark.parametrize("engine,field,label,recorded", EMPTY_NAMESPACE_CASES)
@pytest.mark.parametrize("surface", ["pure", "cli"])
def test_empty_private_namespace_witness_refuses(adapter, layout, engine, field, label, recorded, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"][field] = ""
    if recorded:
        add_recorded(value, "--pid" if field == "PidMode" else "--ipc", ["private"])
    if surface == "pure":
        assert adapter.verify(value, expected) == [label]
    else:
        path = layout.run.parent / "empty-namespace-inspect.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        result = cli(layout, {**config_for(layout), "isolation": isolation}, "verify", "--inspect", str(path))
        assert result.returncode == 2, result.stdout + result.stderr
        assert json.loads(result.stdout) == {"mismatches": [label]}


@pytest.mark.parametrize("engine,pid", [("podman", "private"), ("docker", ""), ("docker", "private")])
@pytest.mark.parametrize("surface", ["pure", "cli"])
def test_private_namespace_domains_stay_valid(adapter, layout, engine, pid, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    value[0]["HostConfig"]["PidMode"] = pid
    if surface == "pure":
        assert adapter.verify(value, expected) == []
    else:
        path = layout.run.parent / "private-namespace-inspect.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        result = cli(layout, {**config_for(layout), "isolation": isolation}, "verify", "--inspect", str(path))
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout) == {"mismatches": []}


LOCAL_ROOT_CASES = ["relocated-direct", "relocated-alias", "identity", "relocated-identity", "dangling-direct",
                    "ordinary-symlink"]


def recorded_local_root(layout, owner, kind):
    home = getattr(layout, owner) if owner != "configured" else layout.run.parent / "configured-home"
    home.mkdir(exist_ok=True)
    local = home / ".local"
    target = local
    if kind.startswith("relocated") or kind == "dangling-direct":
        target = layout.run.parent / ("unmounted/local" if kind == "dangling-direct" else "relocated-local")
        if kind != "dangling-direct":
            target.mkdir()
        local.symlink_to(target, target_is_directory=True)
    else:
        local.mkdir()
    identity = None
    path = target
    if kind in ("identity", "relocated-identity"):
        path = layout.run.parent / "local-identity-alias"
        path.mkdir()
        identity = (path, target.stat())
    elif kind in ("relocated-alias", "ordinary-symlink"):
        path = layout.run.parent / "local-root-link"
        path.symlink_to(local, target_is_directory=True)
    return home, path, identity


@pytest.mark.parametrize("kind", LOCAL_ROOT_CASES)
@pytest.mark.parametrize("owner", ["home", "passwd_home"])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_recorded_local_root_refuses(adapter, layout, monkeypatch, kind, owner, engine, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    _, source, identity = recorded_local_root(layout, owner, kind)
    path = str(source)
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, identity)
        if surface == "verify":
            expected["mounts"] = [{"source": path, "destination": path, "rw": True}]
            assert adapter.verify(inspect_for(expected), expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
                getattr(adapter, surface)(isolation, run=layout.run,
                                          mounts=[{"source": path, "destination": path, "rw": True}], **kwargs)


@pytest.mark.parametrize("kind", ["relocated-direct", "identity", "relocated-identity", "dangling-direct"])
@pytest.mark.parametrize("owner", ["home", "passwd_home", "configured"])
def test_planner_recorded_local_root_refuses(adapter, layout, monkeypatch, kind, owner):
    home, source, identity = recorded_local_root(layout, owner, kind)
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, identity)
        with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + str(source)) + "$"):
            mounts(adapter, layout, home=home if owner == "configured" else layout.home, project=source)


@pytest.mark.parametrize("kind", ["relocated-direct", "identity", "relocated-identity", "dangling-direct"])
@pytest.mark.parametrize("owner", ["home", "passwd_home"])
@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_recorded_local_root_descendants_stay_valid(adapter, layout, monkeypatch, kind, owner, engine):
    _, root, identity = recorded_local_root(layout, owner, kind)
    path = str(root / "share" / "x")  # Missing descendants too: a missing leaf must not equal a missing root ID.
    rows = [{"source": path, "destination": path, "rw": True}]
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, identity)
        assert adapter.create_argv(isolation, run=layout.run, mounts=rows)
        expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
        assert adapter.verify(inspect_for(expected), expected) == []


@pytest.mark.parametrize("owner", ["home", "passwd_home", "configured"])
def test_planner_recorded_local_descendant_stays_valid(adapter, layout, owner):
    home, root, _ = recorded_local_root(layout, owner, "relocated-direct")
    path = root / "share" / "x"
    plan = mounts(adapter, layout, home=home if owner == "configured" else layout.home, project=path)
    assert {"source": str(path), "destination": str(path), "rw": True} in plan


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
@pytest.mark.parametrize("fault", [errno.EACCES, errno.EIO, errno.ENOTDIR, "recursion", "identity-io"])
@pytest.mark.parametrize("surface", ["planner", "create_argv", "expected_plan", "verify"])
def test_local_root_metadata_cannot_be_absence(adapter, layout, monkeypatch, owner, fault, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    value = inspect_for(expected)
    local = getattr(layout, owner) / ".local"
    target = layout.run.parent / "local-metadata-target"
    target.mkdir()
    local.symlink_to(target, target_is_directory=True)
    denied = target if fault == "identity-io" else local
    # Resolution now reads links explicitly instead of delegating to non-strict realpath.
    module, operation = os, "readlink" if fault == "recursion" else ("stat" if fault == "identity-io" else "lstat")
    original, probes = getattr(module, operation), []

    def fail(path, *args, **kwargs):
        if os.fspath(path) == str(denied):
            probes.append(str(denied))
            if fault == "recursion":
                raise RecursionError("modelled local-root resolution recursion")
            code = errno.EIO if fault == "identity-io" else fault
            raise OSError(code, os.strerror(code), str(denied))
        return original(path, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(module, operation, fail)
        if surface == "verify":
            assert adapter.verify(value, expected) == ["mounts"]
        elif surface == "planner":
            if fault == "recursion":
                with pytest.raises(ValueError, match="^mount metadata exceeds recursion limit$"):
                    mounts(adapter, layout)
            else:
                with pytest.raises(OSError) as error:
                    mounts(adapter, layout)
                assert error.value.errno == (errno.EIO if fault == "identity-io" else fault)
                assert error.value.filename == str(denied)
        else:
            rows = [{"source": str(layout.project), "destination": str(layout.project), "rw": True}]
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + str(layout.project)) + "$"):
                getattr(adapter, surface)(ISOLATION, run=layout.run, mounts=rows, **kwargs)
        assert probes


@pytest.mark.parametrize("shape", ["native", "python39"])
@pytest.mark.parametrize("explicit_host", [False, True])
def test_host_plan_needs_no_owner_home(layout, shape, explicit_host):
    bootstrap = ("os.environ.pop('HOME',None); "
                 "pwd.getpwuid=lambda uid: (_ for _ in ()).throw(KeyError(uid)); ")
    if shape == "python39":
        bootstrap += ("import pathlib; pathlib.Path.home=classmethod("
                      "lambda cls: cls(pwd.getpwuid(os.getuid()).pw_dir)); ")
    config = {"schema": "aegis.team-run/v2", "isolation": {"mode": "host"}} if explicit_host else {}
    result = cli(layout, config, "plan", bootstrap=bootstrap)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"mode": "host", "isolation": None, "mounts": [], "create_argv": None}


NESTED_DESTINATIONS = ["child-link", "ancestor-link", "missing-target"]


def nested_destination_rows(layout, kind, parent_rw):
    parent = layout.source
    if kind == "ancestor-link":
        parent = layout.run.parent / "destination-parent-link"
        parent.symlink_to(layout.source, target_is_directory=True)
    child = parent / "sub"
    child.symlink_to(layout.project / "missing" if kind == "missing-target" else layout.project,
                     target_is_directory=True)
    # Host source resolution is deliberately disjoint, while the container's supplied destinations nest.
    resolved_parent, resolved_child = Path(os.path.realpath(parent)), Path(os.path.realpath(child))
    assert resolved_parent != resolved_child
    assert resolved_parent not in resolved_child.parents and resolved_child not in resolved_parent.parents
    return [{"source": str(parent), "destination": str(parent), "rw": parent_rw},
            {"source": str(child), "destination": str(child), "rw": not parent_rw}]


@pytest.mark.parametrize("kind", NESTED_DESTINATIONS)
@pytest.mark.parametrize("parent_rw", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_mixed_access_nested_destinations_refuse(adapter, layout, kind, parent_rw, reverse, engine, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    rows = nested_destination_rows(layout, kind, parent_rw)
    if reverse:
        rows.reverse()
    message = "read-write and read-only mounts overlap: %s and %s" % tuple(row["destination"] for row in rows)
    if surface == "verify":
        expected["mounts"] = rows
        assert adapter.verify(inspect_for(expected), expected) == ["mounts"]
    else:
        kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
        with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
            getattr(adapter, surface)(isolation, run=layout.run, mounts=rows, **kwargs)


@pytest.mark.parametrize("kind", NESTED_DESTINATIONS)
@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_equal_access_nested_destinations_stay_valid(adapter, layout, kind, rw, engine):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows = nested_destination_rows(layout, kind, rw)
    rows[1]["rw"] = rw
    assert adapter.create_argv(isolation, run=layout.run, mounts=rows)
    expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
    assert adapter.verify(inspect_for(expected), expected) == []


def relocated_local_parent(layout, owner, placement, alias, missing):
    home = getattr(layout, owner) if owner != "configured" else layout.run.parent / "configured-local-home"
    home.mkdir(exist_ok=True)
    parent = home / "dotfiles" if placement == "inside" else layout.run.parent / "external-local-store"
    parent.mkdir()
    target = parent / ".local"
    if not missing:
        target.mkdir()
    (home / ".local").symlink_to(target, target_is_directory=True)
    source, identity = parent, None
    if alias:
        source = layout.run.parent / "local-parent-alias"
        source.mkdir()
        identity = (source, parent.stat())
    return home, source, identity


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
@pytest.mark.parametrize("placement", ["inside", "outside"])
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("missing", [False, True])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_relocated_local_parent_refuses(adapter, layout, monkeypatch, owner, placement, alias, missing, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    _, source, identity = relocated_local_parent(layout, owner, placement, alias, missing)
    path = str(source)
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, identity)
        if surface == "verify":
            expected["mounts"] = [{"source": path, "destination": path, "rw": True}]
            assert adapter.verify(inspect_for(expected), expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
                getattr(adapter, surface)(ISOLATION, run=layout.run,
                                          mounts=[{"source": path, "destination": path, "rw": True}], **kwargs)


@pytest.mark.parametrize("owner", ["home", "passwd_home", "configured"])
@pytest.mark.parametrize("placement", ["inside", "outside"])
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("missing", [False, True])
def test_planner_relocated_local_parent_refuses(adapter, layout, monkeypatch, owner, placement, alias, missing):
    home, source, identity = relocated_local_parent(layout, owner, placement, alias, missing)
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, identity)
        with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + str(source)) + "$"):
            mounts(adapter, layout, home=home if owner == "configured" else layout.home, project=source)


def local_via_intermediate_link(layout, owner, relative=False, repeated=False):
    data = layout.run.parent / "canonical-local-data"
    data.mkdir()
    hop = layout.run.parent / "canonical-local-hop"
    hop.symlink_to(data, target_is_directory=True)
    local = getattr(layout, owner) / ".local"
    target = str(hop / "missing")
    if repeated:
        target = str(hop) + "/../" + hop.name + "/missing"
    if relative:
        target = os.path.relpath(target, local.parent)
    local.symlink_to(target, target_is_directory=True)
    return hop, data / "missing"


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("code", [errno.EIO, errno.EACCES, errno.ELOOP, errno.ENOTDIR])
@pytest.mark.parametrize("candidate", ["root", "unrelated"])
@pytest.mark.parametrize("surface", ["planner", "create_argv", "expected_plan", "verify"])
def test_intermediate_local_metadata_refuses(adapter, layout, monkeypatch, owner, relative, code, candidate, surface):
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    hop, root = local_via_intermediate_link(layout, owner, relative)
    path = str(root if candidate == "root" else layout.project)
    rows = [{"source": path, "destination": path, "rw": True}]
    expected["mounts"] = rows
    value = inspect_for(expected)
    original, probes = os.lstat, []

    def fail(target, *args, **kwargs):
        if os.fspath(target) == str(hop):
            probes.append(str(hop))
            raise OSError(code, os.strerror(code), str(hop))
        return original(target, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "lstat", fail)
        if surface == "planner":
            with pytest.raises(OSError) as error:
                mounts(adapter, layout, project=path)
            assert error.value.errno == code and error.value.filename == str(hop)
        elif surface == "verify":
            assert adapter.verify(value, expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + path) + "$"):
                getattr(adapter, surface)(ISOLATION, run=layout.run, mounts=rows, **kwargs)
        assert probes


@pytest.mark.parametrize("owner", ["home", "passwd_home"])
@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("repeated", [False, True])
def test_intermediate_local_enoent_target_protected_descendants_allowed(adapter, layout, owner, relative, repeated):
    _, root = local_via_intermediate_link(layout, owner, relative, repeated)
    path = str(root)
    for surface in ("create_argv", "expected_plan"):
        kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
        with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
            getattr(adapter, surface)(ISOLATION, run=layout.run,
                                      mounts=[{"source": path, "destination": path, "rw": True}], **kwargs)
    with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
        mounts(adapter, layout, project=root)
    child = str(root / "share" / "x")
    rows = mounts(adapter, layout, project=child)
    assert {"source": child, "destination": child, "rw": True} in rows
    assert adapter.create_argv(ISOLATION, run=layout.run, mounts=rows)
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=rows)
    assert adapter.verify(inspect_for(expected), expected) == []


@pytest.mark.parametrize("ending", ["/..", "/.", "/"])
def test_exclusion_resolution_nondirectory_traversal_refuses(adapter, layout, ending):
    file = layout.run.parent / "local-intermediate-file"
    file.write_text("not a directory\n", encoding="utf-8")
    (layout.home / ".local").symlink_to(str(file) + ending + "/missing", target_is_directory=True)
    with pytest.raises(OSError) as error:
        mounts(adapter, layout)
    assert error.value.errno == errno.ENOTDIR


def test_exclusion_resolution_cycle_refuses(adapter, layout):
    loop = layout.run.parent / "local-cycle"
    loop.symlink_to(loop)
    (layout.home / ".local").symlink_to(loop)
    with pytest.raises(OSError) as error:
        mounts(adapter, layout)
    assert error.value.errno == errno.ELOOP


def test_existing_local_leaf_identity_alias_boundary(adapter, layout, monkeypatch):
    # Existing-leaf identity protection is retained. This models no host bind of a missing root or ancestor;
    # owner-created host bind aliases remain outside the documented threat model.
    expected = expected_for(adapter, ISOLATION, run=layout.run, mounts=mounts(adapter, layout))
    leaf = layout.home / ".local"
    leaf.mkdir()
    alias = layout.run.parent / "existing-local-leaf-alias"
    alias.mkdir()
    path = str(alias)
    rows = [{"source": path, "destination": path, "rw": True}]
    with monkeypatch.context() as m:
        model_stored_inode_alias(m, (alias, leaf.stat()))
        for builder in ("create_argv", "expected_plan"):
            kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
                getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=rows, **kwargs)
        expected["mounts"] = rows
        assert adapter.verify(inspect_for(expected), expected) == ["mounts"]


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("code", [errno.EIO, errno.EACCES, errno.EAGAIN])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_home_nss_oserror_is_validation_refusal(adapter, layout, monkeypatch, engine, code, surface):
    import pwd

    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows = mounts(adapter, layout)
    expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
    value = inspect_for(expected)
    calls = []

    def unavailable(uid):
        calls.append(uid)
        raise OSError(code, "modelled NSS failure")

    with monkeypatch.context() as m:
        m.delenv("HOME", raising=False)
        m.setattr(pwd, "getpwuid", unavailable)
        if surface == "verify":
            assert adapter.verify(value, expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^cannot find the owner's password-database home$"):
                getattr(adapter, surface)(isolation, run=layout.run, mounts=rows, **kwargs)
        assert calls


@pytest.mark.parametrize("code", [errno.EIO, errno.EACCES, errno.EAGAIN])
@pytest.mark.parametrize("command", ["plan", "verify"])
def test_cli_home_nss_oserror_has_normalized_message(layout, code, command):
    bootstrap = ("os.environ.pop('HOME',None); "
                 "pwd.getpwuid=lambda uid: (_ for _ in ()).throw(OSError(%d,'modelled NSS failure')); " % code)
    args = ("--inspect", str(layout.run.parent / "not-read-nss.json")) if command == "verify" else ()
    result = cli(layout, config_for(layout), command, *args, bootstrap=bootstrap)
    assert result.returncode == 2, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"error": "cannot find the owner's password-database home"}


@pytest.mark.parametrize("builder", ["create_argv", "expected_plan"])
def test_home_set_does_not_require_nss_for_empty_builder(adapter, layout, monkeypatch, builder):
    import pwd

    kwargs = {"image_inspect": image_info(IMAGE)} if builder == "expected_plan" else {}
    before = getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=[], **kwargs)
    with monkeypatch.context() as m:
        m.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(OSError(errno.EIO, "modelled NSS failure")))
        assert getattr(adapter, builder)(ISOLATION, run=layout.run, mounts=[], **kwargs) == before


def expansion_links(layout, kind, size):
    folder = layout.run.parent / "expansion-links"
    folder.mkdir()
    final = layout.run.parent / "expansion-final"
    final.mkdir()
    if kind == "graph":
        links = [folder / ("s%d" % index) for index in range(size + 1)]
        for index, link in enumerate(links):
            link.symlink_to("." if index == 0 else "s%d/s%d" % (index - 1, index - 1))
        return links[-1], links, folder
    links = [folder / ("c%d" % index) for index in range(size)]
    for index, link in enumerate(links):
        link.symlink_to(links[index + 1].name if index + 1 < len(links) else final)
    return links[0], links, final


def bound_readlink_probe(m):
    original, calls = os.readlink, []

    def readlink(path, *args, **kwargs):
        calls.append(os.fspath(path))
        # Deterministic sentinel prevents the pre-fix implementation from executing the exponential graph.
        assert len(calls) <= 40, "public resolution exceeded the 40-expansion test ceiling"
        return original(path, *args, **kwargs)

    m.setattr(os, "readlink", readlink)
    return calls


@pytest.mark.parametrize("kind,size", [("graph", 5), ("graph", 30), ("chain", 41)])
@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_symlink_expansion_budget_refuses(adapter, layout, monkeypatch, kind, size, engine, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    entry, _, _ = expansion_links(layout, kind, size)
    path = str(entry)
    rows = [{"source": path, "destination": path, "rw": True}]
    expected["mounts"] = rows
    value = inspect_for(expected)
    with monkeypatch.context() as m:
        calls = bound_readlink_probe(m)
        if surface == "verify":
            assert adapter.verify(value, expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + path) + "$"):
                getattr(adapter, surface)(isolation, run=layout.run, mounts=rows, **kwargs)
        assert 0 < len(calls) <= 40


@pytest.mark.parametrize("kind,size", [("graph", 5), ("graph", 30), ("chain", 40)])
@pytest.mark.parametrize("owner", ["home", "passwd_home", "configured"])
def test_local_symlink_expansion_budget_refuses(adapter, layout, monkeypatch, kind, size, owner):
    entry, _, _ = expansion_links(layout, kind, size)
    home = getattr(layout, owner) if owner != "configured" else layout.run.parent / "expansion-owner"
    home.mkdir(exist_ok=True)
    (home / ".local").symlink_to(entry, target_is_directory=True)
    with monkeypatch.context() as m:
        calls = bound_readlink_probe(m)
        with pytest.raises(OSError) as error:
            mounts(adapter, layout, home=home if owner == "configured" else layout.home)
        assert error.value.errno == errno.ELOOP
        assert 0 < len(calls) <= 40


@pytest.mark.parametrize("size", [1, 4, 40])
@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_symlink_expansion_short_and_limit_chains_stay_valid(adapter, layout, size, engine):
    entry, _, _ = expansion_links(layout, "chain", size)
    path = str(entry)
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    rows = [{"source": path, "destination": path, "rw": True}]
    assert adapter.create_argv(isolation, run=layout.run, mounts=rows)
    expected = expected_for(adapter, isolation, run=layout.run, mounts=rows)
    assert adapter.verify(inspect_for(expected), expected) == []


@pytest.mark.parametrize("size", [1, 4, 39])
def test_local_symlink_expansion_short_chains_stay_valid(adapter, layout, size):
    entry, _, _ = expansion_links(layout, "chain", size)
    (layout.home / ".local").symlink_to(entry, target_is_directory=True)
    plan = mounts(adapter, layout)
    assert {"source": str(layout.project), "destination": str(layout.project), "rw": True} in plan


def test_symlink_completed_resolution_memoizes_each_link(adapter, layout, monkeypatch):
    entry, links, _ = expansion_links(layout, "graph", 4)  # 31 logical follows, five unique links.
    original, calls = os.readlink, []

    def readlink(path, *args, **kwargs):
        calls.append(os.fspath(path))
        return original(path, *args, **kwargs)

    path = str(entry)
    with monkeypatch.context() as m:
        m.setattr(os, "readlink", readlink)
        assert adapter.create_argv(ISOLATION, run=layout.run,
                                   mounts=[{"source": path, "destination": path, "rw": True}])
    top_level_resolutions = calls.count(path)
    assert top_level_resolutions > 0
    assert all(calls.count(str(link)) == top_level_resolutions for link in links)


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_symlink_memo_does_not_survive_top_level_call(adapter, layout, engine):
    alias = layout.run.parent / "memo-scope-alias"
    alias.symlink_to(layout.project, target_is_directory=True)
    path = str(alias)
    rows = [{"source": path, "destination": path, "rw": True}]
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    assert adapter.create_argv(isolation, run=layout.run, mounts=rows)
    local = layout.home / ".local"
    local.mkdir()
    alias.unlink()
    alias.symlink_to(local, target_is_directory=True)
    with pytest.raises(ValueError, match="^" + re.escape("mount replaces image system directory: " + path) + "$"):
        adapter.create_argv(isolation, run=layout.run, mounts=rows)


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("surface", ["create_argv", "expected_plan", "verify"])
def test_symlink_memo_hit_still_checks_link_metadata(adapter, layout, monkeypatch, engine, surface):
    isolation = {**ISOLATION, "engine": engine, "allow_unqualified": engine == "docker"}
    expected = expected_for(adapter, isolation, run=layout.run, mounts=mounts(adapter, layout))
    entry, links, _ = expansion_links(layout, "graph", 1)
    path, repeated = str(entry), str(links[0])
    rows = [{"source": path, "destination": path, "rw": True}]
    expected["mounts"] = rows
    value = inspect_for(expected)
    original, visits = os.lstat, []

    def lstat(target, *args, **kwargs):
        if os.fspath(target) == repeated:
            visits.append(repeated)
            if len(visits) == 2:
                raise OSError(errno.EIO, "modelled repeated-link metadata failure", repeated)
        return original(target, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "lstat", lstat)
        if surface == "verify":
            assert adapter.verify(value, expected) == ["mounts"]
        else:
            kwargs = {"image_inspect": image_info(IMAGE)} if surface == "expected_plan" else {}
            with pytest.raises(ValueError, match="^" + re.escape("mount overlaps protected home: " + path) + "$"):
                getattr(adapter, surface)(isolation, run=layout.run, mounts=rows, **kwargs)
        assert len(visits) == 2


def test_absolute_leaf_imports_only_mailbox():
    code = ("import sys; sys.path.insert(0, %r); " % str(SCRIPT.parent)
            + "import hierarchy_absolute; "
              "assert sorted(name for name in sys.modules if name.startswith('hierarchy_')) "
              "== ['hierarchy_absolute', 'hierarchy_mailbox']")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_verifier_and_facade_reexport_absolute_leaf(adapter):
    leaf = importlib.import_module("hierarchy_absolute")
    verifier = importlib.import_module("hierarchy_container_verify")
    assert verifier._absolute is leaf._absolute
    assert adapter._absolute is leaf._absolute
