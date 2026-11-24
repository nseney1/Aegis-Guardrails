"""Build and check a manager pin through the public command and Python API."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import zlib

import pytest

from aegis_core import manager_runtime
from conftest import symlink_or_skip
from tests.helpers_manager import active, git, prepare
from tests.helpers_manager import manager_root as manager_root

REPO = Path(__file__).resolve().parents[2]


def make_store(root):
    if os.name != "posix" or not manager_runtime.descriptor_supported():
        pytest.skip("manager pin requires descriptor-relative no-follow storage")
    root = root.resolve()
    root.mkdir(mode=0o700)
    return root


def cli(operation, args, *, env=None):
    return subprocess.run([sys.executable, "-m", "aegis_core.manager_runtime", operation, *map(str, args)],
                          cwd=REPO, env=env, capture_output=True, text=True, timeout=300)


def result(process, reason=None):
    assert process.returncode == (1 if reason else 0), (process.stdout, process.stderr)
    assert process.stderr == ""
    payload = json.loads(process.stdout)
    assert payload["status"] == ("refused" if reason else "verified")
    if reason:
        assert payload["reason"] == reason
        assert payload["next_action"]
        assert "interpreter" not in payload
    return payload


def reviewed_source(source, *, oversized_smoke=False, without_verifier=False, startup=None):
    source.mkdir()
    for name in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk", "rules", "skills"):
        shutil.copytree(REPO / name, source / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("pyproject.toml", "README.md", "MANIFEST.in", "LICENSE", "NOTICE"):
        shutil.copyfile(REPO / name, source / name)
    if oversized_smoke:
        (source / "aegis_mcp" / "__main__.py").write_text(
            'print("oversized-smoke-output" * 10_000)\n', encoding="utf-8")
    if startup is not None:
        entry = source / "aegis_mcp" / "__main__.py"
        entry.write_text(startup + entry.read_text(encoding="utf-8"), encoding="utf-8")
    if without_verifier:
        (source / "aegis_core" / "manager_runtime.py").unlink()
    git(source, "init", "-q")
    git(source, "add", "--", ".")
    git(source, "commit", "-qm", "Reviewed package")
    return git(source, "rev-parse", "HEAD")


@pytest.fixture(scope="module")
def pin(tmp_path_factory):
    root = make_store(tmp_path_factory.mktemp("manager-runtime").resolve() / "private")
    for builder in dict.fromkeys((sys.executable, getattr(sys, "_base_executable", sys.executable))):
        probe = subprocess.run([builder, "-I", "-c", "import pip, setuptools.build_meta, wheel, packaging"],
                               capture_output=True, timeout=30)
        if probe.returncode == 0:
            break
    else:
        pytest.skip("isolated offline builder needs pip, setuptools, wheel and packaging")
    source = root / "source"
    commit = reviewed_source(source)
    artifacts = make_store(root / "artifacts")
    output = make_store(root / "output")
    args = ("--source", source, "--commit", commit, "--artifact-root", artifacts, "--output-root", output)
    built = result(cli("build", (*args, "--build-python", builder)))
    return root, source, artifacts, output, args, built, builder


def test_build_verifies_artifacts_and_serves_real_manager_wire(pin):
    _root, source, artifacts, output, args, built, _builder = pin
    assert result(cli("verify", (*args, "--python", built["interpreter"]))) == built
    assert built["source"]["commit"] == git(source, "rev-parse", "HEAD")
    assert built["source"]["tree"] == git(source, "rev-parse", "HEAD^{tree}")
    assert set(built["artifacts"]) == {"wheel", "sdist"}
    for artifact in built["artifacts"].values():
        path = artifacts / artifact["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]
    for origin in built["import_origins"].values():
        assert Path(origin).is_file()
        assert Path(origin).is_relative_to(output)
        assert not Path(origin).is_relative_to(source)
    assert built["manager_smoke"] == {
        "server": "aegis-manager-mcp",
        "tools": ["aegis_list_rules", "aegis_report_outcome", "aegis_scan"],
        "transport": "stdio",
    }


def test_verify_resolves_git_inside_custody(pin):
    if shutil.which("git", path=os.defpath) is None:
        pytest.skip("Git is required on the custody search path")
    _root, _source, _artifacts, _output, args, built, _builder = pin
    env = {**os.environ, "PATH": ""}
    assert result(cli("verify", args, env=env)) == built


def test_build_and_verify_do_not_run_checkout_filters(pin):
    root, _source, artifacts, output, previous_args, built, builder = pin
    source = root / "filter-source"
    reviewed_source(source)
    attr = source / ".gitattributes"
    attr.write_text("README.md filter=fixture\n", encoding="ascii")
    git(source, "add", ".gitattributes")
    git(source, "commit", "-qm", "Select fixture filter")
    marker = root / "filter-ran"
    wrapper = root / "fixture-filter"
    wrapper.write_text(f'#!/bin/sh\necho ran >> "{marker}"\ncat\n', encoding="utf-8")
    wrapper.chmod(0o700)
    git(source, "config", "filter.fixture.clean", str(wrapper))
    git(source, "config", "filter.fixture.required", "true")
    index = source / ".git" / "index"
    when = (source / "README.md").stat().st_mtime_ns - 1_000_000_000
    os.utime(index, ns=(when, when))
    before = (output / "pin.json").read_bytes()
    args = ("--source", source, "--commit", git(source, "rev-parse", "HEAD"),
            "--artifact-root", artifacts, "--output-root", output)
    try:
        candidate = result(cli("build", (*args, "--build-python", builder)))
        assert not marker.exists()
        assert result(cli("verify", args)) == candidate
        assert not marker.exists()
    finally:
        (output / "pin.json").write_bytes(before)
    assert result(cli("verify", previous_args)) == built


@pytest.mark.parametrize("directory", [".", "aegis_mcp"])
def test_source_tree_objects_are_authenticated(pin, directory):
    _root, source, _artifacts, _output, args, built, builder = pin
    tree = git(source, "rev-parse", "HEAD^{tree}" if directory == "." else "HEAD:" + directory)
    obj = source / ".git" / "objects" / tree[:2] / tree[2:]
    saved = obj.read_bytes()
    raw = zlib.decompress(saved)
    old_name = b"README.md" if directory == "." else b"manager.py"
    new_name = b"README.mx" if directory == "." else b"manager.px"
    assert old_name + b"\0" in raw
    git(source, "mv", str(Path(directory) / os.fsdecode(old_name)), str(Path(directory) / os.fsdecode(new_name)))
    mode = obj.stat().st_mode & 0o777
    obj.chmod(0o600)
    obj.write_bytes(zlib.compress(raw.replace(old_name + b"\0", new_name + b"\0", 1)))
    try:
        result(cli("build", (*args, "--build-python", builder)), "source_changed")
        result(cli("verify", args), "source_changed")
    finally:
        obj.write_bytes(saved)
        obj.chmod(mode)
        git(source, "read-tree", "--reset", "-u", "HEAD")
    assert result(cli("verify", args)) == built


@pytest.mark.parametrize("where", ["source", "artifacts", "output"])
@pytest.mark.parametrize("alias_kind", ["leaf", "parent"])
def test_builder_alias_is_refused_before_execution(pin, where, alias_kind):
    root, source, artifacts, output, args, built, builder = pin
    target = {"source": source, "artifacts": artifacts, "output": output}[where]
    # The source fixture ignores this executable, so the builder fence must refuse it.
    (source / ".git" / "info" / "exclude").write_text("/builder-fixture/\n", encoding="ascii")
    inside = target / "builder-fixture"
    inside.mkdir()
    marker = root / "builder-ran"
    script = inside / "python"
    script.write_text(f'#!/bin/sh\necho ran >> "{marker}"\nexec "{builder}" "$@"\n', encoding="utf-8")
    script.chmod(0o700)
    alias = root / "builder-alias"
    before = (output / "pin.json").read_bytes()
    try:
        symlink_or_skip(script if alias_kind == "leaf" else inside, alias,
                        target_is_directory=alias_kind == "parent")
        entry = alias if alias_kind == "leaf" else alias / "python"
        result(cli("build", (*args, "--build-python", entry)), "invalid_input")
        assert not marker.exists()
        assert (output / "pin.json").read_bytes() == before
    finally:
        if alias.is_symlink():
            alias.unlink()
        shutil.rmtree(inside)
        (output / "pin.json").write_bytes(before)
        if marker.exists():
            marker.unlink()
    assert result(cli("verify", args)) == built


@pytest.mark.parametrize("where", ["bin-config", "root-config", "dist-packages", "stdlib", "stdlib-zip", "lib64"])
def test_alternate_startup_layout_refused_before_execution(pin, where):
    root, _source, _artifacts, output, args, built, _builder = pin
    runtime = Path(built["interpreter"]).parent.parent
    marker = root / "startup-ran"
    line = f"open({str(marker)!r}, 'w').close()\n"
    site = Path(built["import_origins"]["aegis_mcp"]).parent.parent
    version = site.parent.name
    lib64_existed = (runtime / "lib64").exists()
    cfg = runtime / "pyvenv.cfg"
    prior = cfg.read_bytes()
    next_cfg = prior + b"include-system-site-packages = true\n"
    manifest = output / "pin.json"
    prior_manifest = manifest.read_bytes()
    if where == "bin-config":
        path = runtime / "bin" / "pyvenv.cfg"
    elif where == "root-config":
        path = cfg
    elif where == "dist-packages":
        path = runtime / "lib" / "python3" / "dist-packages" / "sitecustomize.py"
    elif where == "stdlib":
        path = runtime / "lib" / version / "os.py"
    elif where == "stdlib-zip":
        path = runtime / "lib" / (version.replace(".", "") + ".zip")
    else:
        path = runtime / "lib64" / version / "sitecustomize.py"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(next_cfg if where.endswith("config") else line.encode("utf-8"))
        if where == "root-config":
            payload = json.loads(prior_manifest)
            payload["venv_sha256"] = hashlib.sha256(next_cfg).hexdigest()
            manifest.write_text(json.dumps(payload), encoding="ascii")
        result(cli("verify", args), "install_mismatch")
        assert not marker.exists()
    finally:
        if path == cfg:
            cfg.write_bytes(prior)
        else:
            path.unlink()
        if where == "dist-packages":
            shutil.rmtree(runtime / "lib" / "python3")
        if where == "lib64" and not lib64_existed:
            shutil.rmtree(runtime / "lib64")
        manifest.write_bytes(prior_manifest)
        if marker.exists():
            marker.unlink()
    assert result(cli("verify", args)) == built


def test_candidate_layout_checked_before_install(pin):
    root, _source, _artifacts, output, args, built, builder = pin
    marker = root / "candidate-launches"
    exercise = """
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
from aegis_core import manager_runtime

marker = Path(sys.argv.pop(1))

@contextmanager
def launch(argv, **kwargs):
    with subprocess.Popen(argv, **kwargs) as process:
        yield process
    if "venv" in argv:
        runtime = Path(argv[-1])
        (runtime / "bin" / "pyvenv.cfg").write_bytes((runtime / "pyvenv.cfg").read_bytes())
        marker.write_text("venv", encoding="ascii")
    if "pip" in argv:
        marker.write_text("pip", encoding="ascii")

manager_runtime.subprocess = SimpleNamespace(**{**vars(subprocess), "Popen": launch})
raise SystemExit(manager_runtime.main(sys.argv[1:]))
"""
    before = (output / "pin.json").read_bytes()
    failed = subprocess.run([sys.executable, "-c", exercise, str(marker), "build", *map(str, args),
                             "--build-python", builder], cwd=REPO, capture_output=True, text=True, timeout=300)
    result(failed, "install_mismatch")
    assert marker.read_text(encoding="ascii") == "venv"
    assert (output / "pin.json").read_bytes() == before
    assert result(cli("verify", args)) == built


def test_source_is_authenticated_again_after_build_and_verify(pin):
    root, _source, artifacts, output, previous_args, built, builder = pin
    armed = root / "change-source-after-smoke"
    source = root / "late-source"
    readme = source / "README.md"
    startup = (f"from pathlib import Path\nif Path({str(armed)!r}).exists():\n"
               f"    Path({str(readme)!r}).write_bytes(b'changed after probe')\n")
    commit = reviewed_source(source, startup=startup)
    args = ("--source", source, "--commit", commit, "--artifact-root", artifacts, "--output-root", output)
    previous = (output / "pin.json").read_bytes()
    original = readme.read_bytes()
    try:
        armed.touch()
        result(cli("build", (*args, "--build-python", builder)), "source_changed")
        assert readme.read_bytes() != original
        assert (output / "pin.json").read_bytes() == previous
        readme.write_bytes(original)
        armed.unlink()
        candidate = result(cli("build", (*args, "--build-python", builder)))
        armed.touch()
        result(cli("verify", args), "source_changed")
        assert readme.read_bytes() != original
        readme.write_bytes(original)
        armed.unlink()
        assert result(cli("verify", args)) == candidate
    finally:
        readme.write_bytes(original)
        armed.unlink(missing_ok=True)
        (output / "pin.json").write_bytes(previous)
    assert result(cli("verify", previous_args)) == built


def install_with_previous_profile(builder, wheel, runtime):
    subprocess.run([builder, "-I", "-B", "-m", "venv", "--copies", "--without-pip", str(runtime)],
                   check=True, capture_output=True, timeout=30)
    python = runtime / "bin" / "python"
    subprocess.run([builder, "-I", "-B", "-m", "pip", "--python", str(python), "install", "--isolated",
                    "--no-index", "--no-deps", "--no-compile", "--no-cache-dir", str(wheel)],
                   check=True, capture_output=True, timeout=60)
    return python


def test_previously_published_v1_pins_still_verify(pin):
    root, source, artifacts, output, _args, built, builder = pin
    previous = make_store(root / "previous-output")
    manifest = json.loads((output / "pin.json").read_bytes())
    runtime = previous / manifest["generation"]
    python = install_with_previous_profile(builder, artifacts / manifest["artifacts"]["wheel"]["path"], runtime)
    manifest["venv_sha256"] = hashlib.sha256((runtime / "pyvenv.cfg").read_bytes()).hexdigest()
    manifest["python_sha256"] = hashlib.sha256(python.read_bytes()).hexdigest()
    (previous / "pin.json").write_text(json.dumps(manifest), encoding="ascii")
    args = ("--source", source, "--commit", built["source"]["commit"],
            "--artifact-root", artifacts, "--output-root", previous)
    first = result(cli("verify", args))
    assert first["interpreter"] == str(python)
    assert first["manager_smoke"] == built["manager_smoke"]
    assert result(cli("verify", args)) == first


def api_inputs(pin):
    _, source, artifacts, output, _, built, _ = pin
    return dict(source=source, commit=built["source"]["commit"], artifact_root=artifacts,
                output_root=output)


@contextmanager
def set_pin_home(pin, home):
    _, _, _, output, _, built, _ = pin
    cfg = Path(built["interpreter"]).parent.parent / "pyvenv.cfg"
    manifest = output / "pin.json"
    original_cfg, original_manifest = cfg.read_bytes(), manifest.read_bytes()
    try:
        changed = b"\n".join(os.fsencode(f"home = {home}") if row.startswith(b"home = ") else row
                             for row in original_cfg.split(b"\n"))
        cfg.write_bytes(changed)
        record = json.loads(original_manifest)
        record["venv_sha256"] = hashlib.sha256(changed).hexdigest()
        manifest.write_text(json.dumps(record), encoding="ascii")
        yield
    finally:
        cfg.write_bytes(original_cfg)
        manifest.write_bytes(original_manifest)


def test_python_api_launches_share_the_checked_profile(pin, tmp_path, monkeypatch):
    builder = pin[-1]
    options = dict(api_inputs(pin), artifact_root=make_store(tmp_path / "artifacts"),
                   output_root=make_store(tmp_path / "output"))
    base = Path(sys._base_executable).resolve(strict=True)
    prefix = base.parent.parent
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    stdlib = prefix / sys.platlibdir / version
    search = stdlib.with_name(version.replace(".", "") + ".zip"), stdlib, stdlib / "lib-dynload"
    launches = []

    def launch(argv, **kwargs):
        fd, = kwargs["pass_fds"]
        locator = f"/proc/self/fd/{fd}"
        assert kwargs["executable"] == locator
        interpreter = Path(os.readlink(locator))
        assert os.path.samestat(os.fstat(fd), interpreter.stat())
        assert argv[0:5] == [str(base), "-I", "-S", "-B", "-c"]
        assert argv[6:11] == list(map(str, (base, prefix, *search)))
        launches.append((interpreter, argv[11]))
        return subprocess.Popen(argv, **kwargs)

    monkeypatch.setattr(manager_runtime, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    built = manager_runtime.build_pin(**options, build_python=builder)
    assert manager_runtime.verify_pin(**options) == built
    interpreter = Path(built["interpreter"])
    site = str(Path(built["import_origins"]["aegis_mcp"]).parent.parent)
    assert [path for path, _ in launches] == [base] * 4 + [interpreter] * 4
    assert [packages for _, packages in launches[4:]] == [site] * 4
    builder_roots = prefix, Path(builder).parent.parent.resolve()
    selected = json.loads(launches[0][1])
    assert selected and all(any(Path(path).is_relative_to(root) for root in builder_roots) for path in selected)
    assert [json.loads(packages) for _, packages in launches[:4]] == [selected] * 4


@pytest.mark.parametrize("operation", ["build", "verify"])
@pytest.mark.parametrize("boundary", ["stdio", "final_source"])
def test_python_api_binds_named_interpreter_through_receipt(pin, monkeypatch, operation, boundary):
    root, _, artifacts, output, args, built, builder = pin
    interpreter = Path(built["interpreter"])
    previous = (output / "pin.json").read_bytes()
    generations = set(output.iterdir())
    artifact_generations = set(artifacts.iterdir())
    moved = []

    def replace(path):
        original = root / "held-interpreter"
        path.rename(original)
        shutil.copy2(original, path)
        moved.append((original, path))

    @contextmanager
    def launch(argv, **kwargs):
        with subprocess.Popen(argv, **kwargs) as process:
            yield process
        if "AEGIS_MANAGER_CONFIG" in kwargs["env"]:
            replace(Path(argv[-1]).parents[2] / "bin" / "python")

    source_probe = manager_runtime._source
    witnesses = []

    def read_source(*args):
        outcome = source_probe(*args)
        witnesses.append(outcome[1])
        if len(witnesses) == 2:
            path = interpreter
            if operation == "build":
                new, = set(output.iterdir()) - generations - {args[-1]}
                path = new / "bin" / "python"
            replace(path)
        return outcome

    options = api_inputs(pin)
    run = manager_runtime.verify_pin
    if operation == "build":
        options["build_python"] = builder
        run = manager_runtime.build_pin
    saved = manager_runtime.subprocess if boundary == "stdio" else manager_runtime._source
    try:
        if boundary == "stdio":
            monkeypatch.setattr(manager_runtime, "subprocess", SimpleNamespace(
                **{**vars(subprocess), "Popen": launch}))
        else:
            monkeypatch.setattr(manager_runtime, "_source", read_source)
        with pytest.raises(manager_runtime.RuntimeRefusal) as rejected:
            run(**options)
        assert rejected.value.reason == "wrong_interpreter"
        assert rejected.value.next_action
        assert len(moved) == 1
        assert (output / "pin.json").read_bytes() == previous
        assert set(output.iterdir()) == generations
        assert set(artifacts.iterdir()) == artifact_generations
    finally:
        for original, path in moved:
            if operation == "verify":
                original.replace(path)
            else:
                original.unlink()
        (output / "pin.json").write_bytes(previous)
        if boundary == "stdio":
            manager_runtime.subprocess = saved
        else:
            manager_runtime._source = saved
    assert manager_runtime.verify_pin(**api_inputs(pin)) == built
    try:
        retried = run(**options)
        assert result(cli("verify", args)) == retried
    finally:
        (output / "pin.json").write_bytes(previous)


def provision_build_packages(builder, target):
    program = (
        "from importlib.util import find_spec; import json; from pathlib import Path; "
        "names = ('pip', 'setuptools', 'wheel', 'packaging', '_distutils_hack', 'pkg_resources'); "
        "print(json.dumps([str(Path(spec.origin).resolve().parent) for spec in map(find_spec, names) if spec]))"
    )
    package_dirs = json.loads(subprocess.check_output([builder, "-I", "-B", "-c", program], timeout=30))
    for package in map(Path, package_dirs):
        shutil.copytree(package, target / package.name)
        for pattern in ("*.dist-info", "*.egg-info"):
            for metadata in package.parent.glob(f"{package.name}-{pattern}"):
                if metadata.is_dir():
                    shutil.copytree(metadata, target / metadata.name)
                else:
                    shutil.copy2(metadata, target / metadata.name)


@pytest.mark.parametrize("copies", [False, True])
def test_external_builder_alias_retains_isolated_packages(pin, copies):
    root, _, artifacts, _, args, built, builder = pin
    tools = root / f"offline-tools-{copies}"
    mode = "--copies" if copies else "--symlinks"
    subprocess.run([builder, "-I", "-B", "-m", "venv", mode, "--without-pip", str(tools)],
                   check=True, capture_output=True, timeout=30)
    target = next((tools / "lib").glob("python*/site-packages"))
    provision_build_packages(builder, target)
    alias = root / f"offline-alias-{copies}"
    symlink_or_skip(tools / "bin" / "python", alias)
    output = make_store(root / f"offline-output-{copies}")
    options = (*args[:-1], output)
    isolated = result(cli("build", (*options, "--build-python", alias)))
    assert isolated["source"] == built["source"]
    (target / "wheel").rename(root / f"unused-wheel-{copies}")
    result(cli("build", (*options, "--build-python", alias)), "build_backend_unavailable")
    assert result(cli("verify", options)) == isolated
    assert (artifacts / built["artifacts"]["wheel"]["path"]).is_file()


@pytest.mark.parametrize("operation", ["build", "verify"])
@pytest.mark.parametrize("redirect", ["bin-config", "root-config", "stdlib", "archive", "dynload",
                                     "encodings", "ancestor-archive", "cross-prefix-executable"])
def test_indeterminate_base_refuses_before_launch(pin, tmp_path, monkeypatch, redirect, operation):
    source = pin[1]
    prefix = make_store(tmp_path / "alternate-base")
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    bin_dir = prefix / "bin"
    bin_dir.mkdir()
    executable = bin_dir / version
    if redirect == "cross-prefix-executable":
        other_bin = tmp_path / "other-prefix" / "bin"
        other_bin.mkdir(parents=True)
        physical = other_bin / version
        shutil.copy2(sys.executable, physical)
        symlink_or_skip(physical, executable)
    else:
        shutil.copy2(sys.executable, executable)
        physical = executable
    stdlib = prefix / sys.platlibdir / version
    encodings = stdlib / "encodings"
    dynload = stdlib / "lib-dynload"
    if redirect == "stdlib":
        stdlib.parent.mkdir()
        symlink_or_skip(source, stdlib, target_is_directory=True)
    else:
        encodings.parent.mkdir(parents=True)
        if redirect == "encodings":
            symlink_or_skip(source, encodings, target_is_directory=True)
        else:
            encodings.mkdir()
            for name in ("__init__.py", "aliases.py", "utf_8.py"):
                (encodings / name).touch()
        (stdlib / "os.py").touch()
        if redirect == "dynload":
            symlink_or_skip(source, dynload, target_is_directory=True)
        else:
            dynload.mkdir()
    if redirect == "archive":
        symlink_or_skip(source / "README.md", stdlib.with_name(version.replace(".", "") + ".zip"))
    if redirect == "ancestor-archive":
        archive = tmp_path / sys.platlibdir / (version.replace(".", "") + ".zip")
        archive.parent.mkdir()
        archive.touch()
    if redirect.endswith("config"):
        cfg = (bin_dir if redirect == "bin-config" else prefix) / "pyvenv.cfg"
        cfg.touch()
    monkeypatch.setattr(manager_runtime, "sys", SimpleNamespace(
        **{**vars(sys), "base_prefix": str(prefix), "base_exec_prefix": str(prefix),
           "_base_executable": str(physical)}))

    def unexpected(*args, **kwargs):
        pytest.fail("Python launched without a verified base startup profile")

    monkeypatch.setattr(manager_runtime, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    options = api_inputs(pin)
    run, reason = manager_runtime.verify_pin, "install_mismatch"
    if operation == "build":
        options["build_python"] = executable
        run, reason = manager_runtime.build_pin, "invalid_input"
    use_home = operation == "verify" and redirect == "cross-prefix-executable"
    with set_pin_home(pin, bin_dir) if use_home else nullcontext():
        with pytest.raises(manager_runtime.RuntimeRefusal) as rejected:
            run(**options)
    assert rejected.value.as_dict() == manager_runtime.RuntimeRefusal(reason).as_dict()


def test_v1_replay_with_physical_lib64(pin):
    root, _, _, output, args, built, _ = pin
    runtime = Path(built["interpreter"]).parent.parent
    manifest = output / "pin.json"
    previous = manifest.read_bytes()
    parsed = json.loads(previous)
    old, new = (runtime / name for name in ("lib", "lib64"))
    if parsed["site"].startswith("lib64/"):
        old, new = new, old
    backup = root / "previous-lib-alias"
    if new.is_symlink():
        new.rename(backup)
    old.rename(new)
    try:
        parsed["site"] = new.name + "/" + parsed["site"].partition("/")[2]
        manifest.write_text(json.dumps(parsed), encoding="ascii")
        symlink_or_skip(Path(new.name), old, target_is_directory=True)
        replay = result(cli("verify", args))
        assert replay["interpreter"] == built["interpreter"]
        assert Path(replay["import_origins"]["aegis_mcp"]).is_relative_to(new)
    finally:
        old.unlink(missing_ok=True)
        new.rename(old)
        if backup.is_symlink():
            backup.rename(new)
        manifest.write_bytes(previous)


@pytest.mark.parametrize("same_directory", [False, True])
def test_venv_home_alias_must_name_the_bound_directory(pin, tmp_path, same_directory):
    _, _, _, _, args, built, _ = pin
    physical = Path(sys._base_executable).resolve(strict=True)
    home = tmp_path / "home"
    if same_directory:
        symlink_or_skip(physical.parent, home, target_is_directory=True)
    else:
        home.mkdir()
        symlink_or_skip(physical, home / physical.name)
    with set_pin_home(pin, home):
        if same_directory:
            assert result(cli("verify", args)) == built
        else:
            result(cli("verify", args), "install_mismatch")


def relocated_builder(root, builder):
    base = Path(sys._base_executable).resolve(strict=True)
    prefix = root / "relocated-base"
    python = prefix / "bin" / base.name
    python.parent.mkdir(parents=True)
    shutil.copy2(base, python)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    if python.name != version:
        symlink_or_skip(python, python.with_name(version))
    base_lib = base.parent.parent / sys.platlibdir
    copied_lib = prefix / sys.platlibdir
    shutil.copytree(base_lib / version, copied_lib / version, symlinks=True,
                    ignore=shutil.ignore_patterns("site-packages", "dist-packages"))
    for native in base_lib.glob(f"lib{version}*.so*"):
        shutil.copy2(native, copied_lib / native.name)
    tools = root / "relocated-builder"
    subprocess.run([python, "-I", "-B", "-m", "venv", "--copies", "--without-pip", str(tools)],
                   check=True, capture_output=True, timeout=30)
    provision_build_packages(builder, next((tools / "lib").glob("python*/site-packages")))
    return tools / "bin" / "python"


@pytest.mark.parametrize("relocated", [False, True])
def test_documented_commands_use_the_installed_verifier_and_isolated_host(pin, tmp_path, relocated):
    _, _, artifacts, _, _, built, builder = pin
    root = tmp_path.resolve()
    if relocated:
        builder = relocated_builder(root, builder)
    verifier = root / "trusted-verifier"
    python = install_with_previous_profile(builder, artifacts / built["artifacts"]["wheel"]["path"], verifier)
    assert b"include-system-site-packages = false" in (verifier / "pyvenv.cfg").read_bytes()
    source = root / "documented-source"
    commit = reviewed_source(source, without_verifier=True)
    (source / ".git" / "info" / "exclude").write_text("/aegis_core/manager_runtime.py\n", encoding="ascii")
    marker = root / "checkout-verifier-ran"
    (source / "aegis_core" / "manager_runtime.py").write_text(
        f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    documented = (REPO / "docs" / "manager-runtime.md").read_text(encoding="utf-8").split("```sh\n")
    examples = [section.split("```", 1)[0] for section in documented[1:]]
    artifact_root, runtime_root = (make_store(root / name) for name in ("doc-artifacts", "doc-output"))
    env = {**os.environ, "VERIFIER_PYTHON": str(python), "OFFLINE_BUILD_PYTHON": str(builder),
           "SOURCE_CHECKOUT": str(source), "REVIEWED_COMMIT": commit,
           "ARTIFACT_ROOT": str(artifact_root), "RUNTIME_ROOT": str(runtime_root), "TRUSTED_PATH": os.defpath}
    proc = subprocess.run(["/bin/sh", "-eu", "-c", examples[0]], cwd=source, env=env,
                          capture_output=True, text=True, check=True, timeout=300)
    first, second = map(json.loads, proc.stdout.splitlines())
    assert first == second and second["source"]["commit"] == commit
    assert not marker.exists()
    site = Path(second["import_origins"]["aegis_mcp"]).parent.parent
    env.update(PINNED_PYTHON=second["interpreter"], PINNED_SITE=str(site),
               MANAGER_CONFIG=str(root / "unused-host-config"), MANAGER_CONFIG_SHA256="0" * 64)
    frames = ({"jsonrpc": "2.0", "id": 1, "method": "initialize"},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    wire = "".join(json.dumps(frame) + "\n" for frame in frames)
    server = subprocess.run(["/bin/sh", "-eu", "-c", examples[1]], cwd=source, env=env, input=wire,
                            capture_output=True, text=True, check=True, timeout=60)
    setup, listing = map(json.loads, server.stdout.splitlines())
    assert setup["result"]["serverInfo"]["name"] == second["manager_smoke"]["server"]
    assert sorted(row["name"] for row in listing["result"]["tools"]) == second["manager_smoke"]["tools"]


@pytest.mark.parametrize(("kind", "refusal"), [
    ("wheel", "artifact_mismatch"),
    ("sdist", "artifact_mismatch"),
    ("installed", "install_mismatch"),
    ("changed_bytes", "install_mismatch"),
    ("interpreter", "wrong_interpreter"),
    ("source", "source_changed"),
])
def test_changed_inputs_refuse_and_retry(pin, kind, refusal):
    _root, source, artifacts, _output, args, built, _builder = pin
    paths = {"wheel": artifacts / built["artifacts"]["wheel"]["path"],
             "sdist": artifacts / built["artifacts"]["sdist"]["path"],
             "installed": Path(built["import_origins"]["aegis_mcp.manager"]),
             "changed_bytes": Path(built["import_origins"]["aegis_mcp.manager"]),
             "source": source / "README.md"}
    if kind == "interpreter":
        result(cli("verify", (*args, "--python", sys.executable)), refusal)
    else:
        path = paths[kind]
        original = path.read_bytes()
        try:
            if kind == "installed":
                path.unlink()
            else:
                path.write_bytes(original + b"\nchanged\n")
            result(cli("verify", args), refusal)
        finally:
            path.write_bytes(original)
    assert result(cli("verify", args)) == built


def test_failed_replacement_and_concurrent_verification_preserve_pin(pin):
    root, _source, artifacts, output, args, built, builder = pin
    before = (output / "pin.json").read_bytes()
    no_tools = root / "unprovisioned"
    subprocess.run([builder, "-I", "-m", "venv", "--without-pip", "--copies", str(no_tools)],
                   check=True, capture_output=True, timeout=30)
    previous = (sorted(artifacts.iterdir()), sorted(output.iterdir()))
    with ThreadPoolExecutor(max_workers=2) as workers:
        replay = workers.submit(cli, "verify", args)
        failed = cli("build", (*args, "--build-python", no_tools / "bin" / "python"))
        result(failed, "build_backend_unavailable")
        assert result(replay.result(timeout=300)) == built
    assert (output / "pin.json").read_bytes() == before
    assert (sorted(artifacts.iterdir()), sorted(output.iterdir())) == previous
    assert result(cli("verify", args)) == built


def test_late_smoke_refusal_keeps_published_generation(pin):
    root, _source, artifacts, output, args, built, builder = pin
    alternate = root / "oversized-source"
    commit = reviewed_source(alternate, oversized_smoke=True)
    before = (output / "pin.json").read_bytes()
    previous = (sorted(artifacts.iterdir()), sorted(output.iterdir()))
    failed = cli("build", ("--source", alternate, "--commit", commit, "--artifact-root", artifacts,
                           "--output-root", output, "--build-python", builder))
    result(failed, "smoke_failed")
    assert "oversized-smoke-output" not in failed.stdout
    assert (output / "pin.json").read_bytes() == before
    assert (sorted(artifacts.iterdir()), sorted(output.iterdir())) == previous
    assert result(cli("verify", args)) == built


def test_verify_refuses_added_site_startup_file(pin):
    _root, _source, _artifacts, _output, args, built, _builder = pin
    site = Path(built["import_origins"]["aegis_mcp"]).parent.parent
    extra = site / "unexpected.pth"
    try:
        extra.write_text("# unexpected startup file\n", encoding="utf-8")
        result(cli("verify", args), "install_mismatch")
    finally:
        extra.unlink()
    assert result(cli("verify", args)) == built


def test_verify_leaves_disposable_activation_and_host_settings_untouched(pin, request):
    from aegis_core.config import manager_registration_env

    _root, _source, _artifacts, _output, args, built, _builder = pin
    root = request.getfixturevalue("manager_root")
    manager = prepare(root)
    service = active(manager)
    before = service.status()
    home = root / "host-home"
    home.mkdir()
    settings = home / "settings.toml"
    settings.write_bytes(b"test_setting = true\n")
    config = manager["config"].read_bytes()
    env = {**os.environ, "HOME": str(home),
           **manager_registration_env(manager["config"], hashlib.sha256(config).hexdigest())}
    audit = {path.name: path.read_bytes() for path in manager["store"].iterdir() if path.is_file()}
    assert result(cli("verify", args, env=env)) == built
    assert result(cli("verify", args, env=env)) == built
    assert service.status() == before
    assert manager["config"].read_bytes() == config
    assert {path.name: path.read_bytes() for path in manager["store"].iterdir() if path.is_file()} == audit
    assert settings.read_bytes() == b"test_setting = true\n"


def test_symlinked_artifact_generation_refuses(pin):
    _root, _source, artifacts, _output, args, built, _builder = pin
    generation = (artifacts / built["artifacts"]["wheel"]["path"]).parent
    moved = generation.with_name("moved-generation")
    generation.rename(moved)
    try:
        symlink_or_skip(moved, generation, target_is_directory=True)
        result(cli("verify", args), "artifact_mismatch")
    finally:
        if generation.is_symlink():
            generation.unlink()
        moved.rename(generation)
    assert result(cli("verify", args)) == built


def test_malformed_manifest_refuses_without_echo(pin):
    _root, _source, _artifacts, output, args, built, _builder = pin
    manifest = output / "pin.json"
    original = manifest.read_bytes()
    try:
        manifest.write_bytes(b'{"schema":"unknown-operator-input"}')
        failed = cli("verify", args)
        result(failed, "invalid_manifest")
        assert "unknown-operator-input" not in failed.stdout
    finally:
        manifest.write_bytes(original)
    assert result(cli("verify", args)) == built


def test_unsupported_platform_is_a_public_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(manager_runtime, "descriptor_supported", lambda: False)
    args = ["verify", "--source", str(tmp_path), "--commit", "a" * 40,
            "--artifact-root", str(tmp_path), "--output-root", str(tmp_path)]
    assert manager_runtime.main(args) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["reason"] == "unsupported_platform"
    assert payload["next_action"]


def test_unavailable_execution_descriptor_refuses_before_spawn(pin, monkeypatch):
    monkeypatch.setattr(manager_runtime, "os", SimpleNamespace(**{**vars(os), "access": lambda *_: False}))

    def unexpected(*args, **kwargs):
        pytest.fail("Python launched without an executable descriptor")

    monkeypatch.setattr(manager_runtime, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    options = api_inputs(pin)
    for run, arguments in ((manager_runtime.build_pin, dict(options, build_python=pin[-1])),
                           (manager_runtime.verify_pin, options)):
        with pytest.raises(manager_runtime.RuntimeRefusal) as rejected:
            run(**arguments)
        assert rejected.value.reason == "unsupported_platform"
        assert rejected.value.next_action == "Use a host with descriptor-relative no-follow file and directory operations."
