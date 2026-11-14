"""Provisioned entry points check their pinned checkout before executing peer source."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import signal
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke
from tests.integration.test_hierarchy_provision import Setup, provision, start_connection
from tests.integration.test_hierarchy_launcher import Launch, REVIEW, LINUX_HOST_PROGRAMS, owned_pids, wait_until

pytestmark = pytest.mark.skipif(os.name == "nt", reason="provisioned runtime profiles are POSIX only")


def py39_api_violations(source):
    """Finite stdlib API guard, not a replacement for running the real Python 3.9 gate."""
    try:
        tree = ast.parse(source, feature_version=(3, 9))
    except SyntaxError as exc:
        return ["Python 3.9 grammar: " + str(exc)]
    # Version references: docs.python.org/3.10/whatsnew/3.10.html and /3.11/whatsnew/3.11.html.
    # removeprefix/removesuffix, functools.cache and Path.is_relative_to ARE Python 3.9 APIs.
    symbols = {"itertools.pairwise", "itertools.batched", "pathlib.Path.hardlink_to", "pathlib.Path.walk",
               "pathlib.Path.is_junction", "enum.StrEnum", "enum.ReprEnum", "typing.Self", "typing.TypeAlias",
               "typing.ParamSpec", "typing.Concatenate", "typing.TypeGuard", "typing.Never", "typing.LiteralString",
               "typing.Required", "typing.NotRequired", "typing.Unpack", "typing.TypeVarTuple",
               "typing.assert_type", "typing.reveal_type", "datetime.UTC", "types.UnionType",
               "inspect.get_annotations", "asyncio.TaskGroup", "asyncio.Runner", "asyncio.timeout",
               "asyncio.timeout_at", "ExceptionGroup", "BaseExceptionGroup", "aiter", "anext"}
    keywords = {"zip": {"strict"}, "dataclasses.dataclass": {"slots", "kw_only"},
                "subprocess.Popen": {"pipesize", "process_group"}, "pathlib.Path.write_text": {"newline"},
                "tempfile.TemporaryDirectory": {"ignore_cleanup_errors", "delete"}}
    aliases, problems = {}, []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
                if alias.name == "tomllib":
                    problems.append("%d: tomllib requires Python 3.11" % node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                full = node.module + "." + alias.name
                aliases[alias.asname or alias.name] = full
                if node.module == "tomllib" or full in symbols:
                    problems.append("%d: post-3.9 import %s" % (node.lineno, full))

    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return qualified(node.value) + "." + node.attr
        if isinstance(node, ast.Call):
            return qualified(node.func)
        return "?"

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        if name in symbols:
            problems.append("%d: post-3.9 call %s" % (node.lineno, name))
        if name.endswith(".subprocess.Popen"):
            name = "subprocess.Popen"
        if any(key.arg in keywords.get(name, ()) for key in node.keywords):
            problems.append("%d: post-3.9 keyword in %s" % (node.lineno, name))
        # Paths are often local variables, so also guard their distinctive post-3.9 member APIs.
        if isinstance(node.func, ast.Attribute) and (node.func.attr in ("hardlink_to", "is_junction") or
                node.func.attr == "write_text" and any(key.arg == "newline" for key in node.keywords)):
            problems.append("%d: post-3.9 pathlib API %s" % (node.lineno, node.func.attr))
    return problems


def py39_runtime_sources():
    """Read local peer imports and named CLI entries without executing any of that source."""
    pending = [ROOT / "tools" / (name + ".py") for name in
               ("hierarchy_launcher", "hierarchy_hosts", "hierarchy_handoff")]
    sources = {}
    while pending:
        path = pending.pop()
        if path in sources:
            continue
        source = path.read_text()
        sources[path] = source
        for node in ast.walk(ast.parse(source)):
            names = ([alias.name for alias in node.names] if isinstance(node, ast.Import) else
                     [node.module] if isinstance(node, ast.ImportFrom) else
                     [node.value[:-3]] if isinstance(node, ast.Constant) and isinstance(node.value, str) and
                     node.value.startswith("hierarchy_") and node.value.endswith(".py") else [])
            for name in names:
                if name and name.startswith("hierarchy_"):
                    peer = ROOT / "tools" / (name.split(".")[0] + ".py")
                    if peer.is_file() and peer not in sources:
                        pending.append(peer)
    return sources


@pytest.mark.parametrize("source", [
    "import itertools as it\nit.pairwise([])",
    "from pathlib import Path\nPath('x').hardlink_to('y')",
    "list(zip([], [], strict=True))",
    "from dataclasses import dataclass\n@dataclass(slots=True)\nclass Example: pass",
    "from typing import Self",
    "from subprocess import Popen\nPopen([], process_group=0)",
    "import tomllib",
    "from pathlib import Path\nPath('x').write_text('data', newline='\\n')",
])
def test_py39_api_guard_rejects_known_newer_stdlib_features(source):
    assert py39_api_violations(source), source


def test_py39_api_guard_preserves_features_added_in_python39():
    assert py39_api_violations("from functools import cache\n'a'.removeprefix('a')\n'a'.removesuffix('a')\n"
                               "from pathlib import Path\nPath('x').is_relative_to(Path('.'))") == []


def test_admitted_tool_runtime_imports_use_python39_apis():
    problems = {str(path.relative_to(ROOT)): violations for path, source in py39_runtime_sources().items()
                if (violations := py39_api_violations(source))}
    assert problems == {}


def drift(built, kind, marker):
    module = built.source / "tools" / "hierarchy_roles.py"
    payload = "from pathlib import Path\nPath(%r).write_text('EXECUTED')\n" % str(marker)
    if kind == "module":
        module.write_text(module.read_text() + "\n" + payload)
    elif kind == "template":
        path = built.source / "tools" / "hierarchy_templates" / "role-registry.json"
        path.write_text(path.read_text() + "\n")
    elif kind == "commit":
        git(built.source, "commit", "--allow-empty", "-qm", "different identity")
    elif kind in ("assume-unchanged", "skip-worktree"):
        git(built.source, "update-index", "--" + kind, "tools/hierarchy_roles.py")
    elif kind == "ignored":
        (built.source / ".git" / "info" / "exclude").write_text("tools/extra/\n")
        folder = built.source / "tools" / "extra"
        folder.mkdir()
        (folder / "__init__.py").write_text(payload)
    elif kind == "bytecode":
        malicious = built.tmp / "malicious.py"
        malicious.write_text(payload + module.read_text().replace("from __future__ import annotations", ""))
        cache = Path(importlib.util.cache_from_source(str(module)))
        cache.parent.mkdir(exist_ok=True)
        py_compile.compile(str(malicious), cfile=str(cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    elif kind == "missing-bootstrap":
        (built.base / "runtime-source.py").unlink(missing_ok=True)
    else:
        raise AssertionError(kind)


def connection_process(connection):
    definition = json.loads(Path(connection).read_text())["mcpServers"]["aegis_mailbox"]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
    return subprocess.run([definition["command"], *definition["args"]],
                          input="".join(json.dumps(row) + "\n" for row in frames),
                          capture_output=True, text=True, timeout=20)


@pytest.mark.parametrize("kind", ["module", "template", "commit", "assume-unchanged", "skip-worktree", "ignored", "bytecode"])
def test_provisioned_mcp_refuses_source_drift_before_peer_imports(tmp_path, kind):
    built = Setup(tmp_path)
    built.init()
    role = built.add_role("pilot/orchestrator", cwd=str(built.tmp))
    marker = tmp_path / "executed"
    drift(built, kind, marker)
    ran = connection_process(role["connection"])
    assert ran.returncode == 2, ran.stdout + ran.stderr
    error = json.loads(ran.stdout)["error"]
    assert "runtime source verification failed" in error
    assert "expected commit=" in error and "observed commit=" in error
    assert "new base" in error
    assert not marker.exists()


@pytest.mark.parametrize("command", ["add-role", "codex-start"])
def test_profile_generation_refuses_changed_source_without_binding_or_publication(tmp_path, command):
    built = Setup(tmp_path)
    built.init()
    drift(built, "commit", tmp_path / "executed")
    request = built.request(base=str(built.base), endpoint="pilot/orchestrator")
    if command == "add-role":
        request.update(host="claude-code", cwd=str(tmp_path))
    answer = provision(command, request, expect=2)
    assert "runtime source verification failed" in answer["error"]
    assert not any(invoke(built.root, "status")["bindings"].values())
    assert not (built.base / "connections").exists()
    assert not (built.base / "profiles").exists()


@pytest.mark.parametrize("action", ["start", "resume"])
def test_launcher_refuses_changed_peer_before_import_or_host_launch(tmp_path, action):
    built = Launch(tmp_path)
    built.init()
    marker = tmp_path / "executed"
    drift(built, "module", marker)
    words = (["start", "--request", str(built.start_request())] if action == "start" else
             ["resume", "--endpoint", "pilot/lane/review", "--dry-run"])
    ran = subprocess.run([sys.executable, "-I", "-B", str(built.source / "tools" / "hierarchy_launcher.py"),
                          "--base", str(built.base), *words], capture_output=True, text=True, timeout=20, env=built.env())
    assert ran.returncode == 2, ran.stdout + ran.stderr
    assert "runtime source verification failed" in json.loads(ran.stdout)["error"]
    assert not marker.exists()
    assert not built.codex_log.exists()


def test_unchanged_checkout_runs_and_source_drift_still_allows_status(tmp_path):
    built = Launch(tmp_path)
    built.init()
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    assert "mailbox_inbox" in start_connection(role["connection"])
    drift(built, "commit", tmp_path / "executed")
    assert built.run("status")["schema"] == "aegis.hierarchy-launch-status/v1"


def test_existing_base_without_bootstrap_refuses_profile_regeneration(tmp_path):
    built = Setup(tmp_path)
    built.init()
    drift(built, "missing-bootstrap", tmp_path / "executed")
    refused = built.add_role("pilot/orchestrator", cwd=str(tmp_path), expect=2)
    assert "runtime source verifier is missing" in refused["error"]
    assert "new base" in refused["error"]
    assert not any(invoke(built.root, "status")["bindings"].values())


@pytest.mark.parametrize("missing", [False, True])
def test_legacy_provisioned_connection_requires_retained_verifier(tmp_path, missing):
    built = Setup(tmp_path)
    built.init()
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    path = Path(role["connection"])
    connection = json.loads(path.read_text())
    args = connection["mcpServers"]["aegis_mailbox"]["args"]
    if "--entry" in args:
        args = ["-I", "-B", args[args.index("--entry") + 1], *args[args.index("--") + 1:]]
    connection["mcpServers"]["aegis_mailbox"]["args"] = args
    path.write_text(json.dumps(connection))
    if missing:
        drift(built, "missing-bootstrap", tmp_path / "executed")
    ran = connection_process(path)
    assert ran.returncode == (2 if missing else 0), ran.stdout + ran.stderr
    if missing:
        assert "runtime source verifier is missing" in json.loads(ran.stdout)["error"]
    else:
        assert json.loads(ran.stdout)["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"


def test_ignored_importable_directory_symlink_refuses_startup(tmp_path):
    built = Setup(tmp_path)
    built.init()
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    package = tmp_path / "outside-package"
    package.mkdir()
    (package / "__init__.py").write_text("# importable code outside the pin\n")
    link = built.source / "tools" / "extra"
    link.symlink_to(package, target_is_directory=True)
    (built.source / ".git" / "info" / "exclude").write_text("tools/extra\n")
    ran = connection_process(role["connection"])
    assert ran.returncode == 2, ran.stdout + ran.stderr
    assert "untracked or ignored importable code" in json.loads(ran.stdout)["error"]


@pytest.mark.parametrize("kind", ["commit", "module"])
@LINUX_HOST_PROGRAMS
def test_trusted_control_checkout_can_stop_owned_session_after_pinned_source_drift(tmp_path, kind):
    """Recovery uses the trusted operator tools, never executes the drifted runtime as a stop implementation."""
    built = Launch(tmp_path)
    built.init()
    session = built.start()["session"]
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case

    context = R2Case(built)
    # MODELLED complete host atoms, independently captured real Python instance. Recovery imports trusted ROOT.
    process = context.spawn(["codex", "exec", "--json", "resume", session])
    try:
        wait_until(lambda: owned_pids(session, projection=context.projection) == [process.pid])
        drift(built, kind, tmp_path / "executed")
        stopped = built.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1")
        assert stopped["state"] == "stopped" and stopped["pids"] == [process.pid]
        assert process.wait(timeout=5) < 0
        assert not (tmp_path / "executed").exists()
    finally:
        context.close()


def test_source_drift_refusal_leaves_existing_profile_bytes_and_binding_unchanged(tmp_path):
    built = Setup(tmp_path)
    built.init()
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    before = {path: path.read_bytes() for folder in ("connections", "profiles") for path in (built.base / folder).iterdir()}
    bindings = invoke(built.root, "status")["bindings"]
    drift(built, "template", tmp_path / "executed")
    refused = built.add_role("pilot/orchestrator", cwd=str(tmp_path), session=role["session"], expect=2)
    assert "runtime bytes differ" in refused["error"]
    assert all(path.read_bytes() == contents for path, contents in before.items())
    assert invoke(built.root, "status")["bindings"] == bindings


@pytest.mark.parametrize("root_flag,peer", [("--root=", "hierarchy_roles.py"), ("--roo=", "hierarchy_roles.py"),
                                            ("--root", "hierarchy_mailbox_mcp.py"), ("--root", "hierarchy_mailbox_mcp.pyc")])
def test_legacy_entry_verifies_before_its_first_peer_import(tmp_path, root_flag, peer):
    built = Setup(tmp_path)
    built.init()
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    connection = json.loads(Path(role["connection"]).read_text())
    args = connection["mcpServers"]["aegis_mailbox"]["args"]
    args = ["-I", "-B", args[args.index("--entry") + 1], *args[args.index("--") + 1:]]
    if root_flag != "--root":
        pos = args.index("--root")
        args[pos:pos + 2] = [root_flag + args[pos + 1]]
    marker = tmp_path / "executed"
    module = built.source / "tools" / (peer[:-1] if peer.endswith(".pyc") else peer)
    payload = "from pathlib import Path\nPath(%r).write_text('EXECUTED')\n" % str(marker)
    changed = payload + module.read_text().replace("from __future__ import annotations", "")
    if peer.endswith(".pyc"):
        malicious = tmp_path / "malicious.py"
        malicious.write_text(changed)
        cache = Path(importlib.util.cache_from_source(str(module)))
        cache.parent.mkdir(exist_ok=True)
        py_compile.compile(str(malicious), cfile=str(cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    else:
        module.write_text(changed)
    ran = subprocess.run([connection["mcpServers"]["aegis_mailbox"]["command"], *args],
                         input='', capture_output=True, text=True, timeout=20)
    assert ran.returncode == 2, ran.stdout + ran.stderr
    assert "runtime source verification failed" in json.loads(ran.stdout)["error"]
    assert not marker.exists()


@pytest.mark.parametrize("root_flag", ["--root=", "--roo="])
def test_direct_mcp_entry_checks_source_with_all_accepted_root_spellings(tmp_path, root_flag):
    built = Setup(tmp_path)
    built.init()
    marker = tmp_path / "executed"
    drift(built, "module", marker)
    ran = subprocess.run([sys.executable, "-I", "-B", str(built.source / "tools" / "hierarchy_mailbox_mcp.py"),
                          root_flag + str(built.root), "serve", "--endpoint", "pilot/root", "--host", "codex",
                          "--session", "root-1", "--generation", "1"], input='', capture_output=True, text=True, timeout=20)
    assert ran.returncode == 2, ran.stdout + ran.stderr
    assert "runtime source verification failed" in json.loads(ran.stdout)["error"]
    assert not marker.exists()


@pytest.mark.parametrize("record", [[], None, {}, {"source": []}, {"source": None}, {"source": ""}],
                         ids=["array", "null", "missing-source", "array-source", "null-source", "empty-source"])
def test_legacy_entry_refuses_malformed_provision_before_importing_peers(tmp_path, record):
    built = Setup(tmp_path)
    built.init()
    role = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]
    args = definition["args"]
    legacy = ["-I", "-B", args[args.index("--entry") + 1], *args[args.index("--") + 1:]]
    marker = tmp_path / "executed"
    peer = built.source / "tools" / "hierarchy_mailbox_mcp.py"
    peer.write_text("from pathlib import Path\nPath(%r).touch()\n" % str(marker))
    provision_path = built.base / "provision.json"
    provision_path.write_text(json.dumps(record))
    before = {path: path.read_bytes() for path in built.base.rglob("*") if path.is_file()}

    ran = subprocess.run([definition["command"], *legacy], input="", capture_output=True, text=True, timeout=20)

    assert ran.returncode == 2, ran.stdout + ran.stderr
    assert not ran.stderr
    assert json.loads(ran.stdout) == {"error": "invalid runtime source provision"}
    assert not marker.exists()
    assert {path: path.read_bytes() for path in built.base.rglob("*") if path.is_file()} == before
