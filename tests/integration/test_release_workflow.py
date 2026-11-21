from pathlib import Path
"""Release-integrity regression tests (v0.89 audit fixes).

v0.89.0 reused one build artifact but (a) ran every test from the checkout,
where ``pythonpath = ["."]`` lets source modules shadow the installed wheel,
(b) installed only ``ls dist/*.whl | head -n 1``, and (c) published
``dist/*`` — including an sdist that was never tested — with no digest check.
"""
import os
import ast
import binascii
import contextlib
import hashlib
import importlib.util
import io
import json
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import zipfile
import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

yaml = pytest.importorskip("yaml")

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
VERIFY_DIST = os.path.join(REPO_ROOT, ".github", "scripts", "verify_dist.py")
SMOKE = os.path.join(REPO_ROOT, ".github", "scripts", "wheel_smoke.py")


def _load(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _runs(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


def _verify(*args):
    return subprocess.run([sys.executable, VERIFY_DIST, *args],
                          capture_output=True, text=True, timeout=60)


def _dist(tmp_path, extra=(), metadata="", *, typed=(), sdist=None):
    d = tmp_path / "dist"
    d.mkdir()
    with zipfile.ZipFile(d / "aegis_governance-0.0.0-py3-none-any.whl", "w") as wheel:
        for name in ("__init__.py", "go_ast.go", "go.mod"):
            wheel.writestr("aegis_core/ast/drivers/templates/" + name, "")
        wheel.writestr("aegis_guardrails-0.0.0.dist-info/METADATA",
                       "Metadata-Version: 2.1\nName: aegis-guardrails\nVersion: 0.0.0\n"
                       "Provides-Extra: dev\nRequires-Dist: pytest; extra == 'dev'\n" + metadata)
        for name in extra:
            member = zipfile.ZipInfo(name)
            # Preserve malformed archive bytes: ZipInfo otherwise normalizes
            # backslashes on Windows and truncates names at NUL on every OS.
            member.filename = name
            wheel.writestr(member, "injected")
        for name, mode, payload in typed:
            member = zipfile.ZipInfo(name)
            member.filename = name
            # Unix type bits live in the archive metadata, not the member name.
            member.create_system = 3
            member.external_attr = (int(mode) & 0xFFFF) << 16
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            wheel.writestr(member, payload)
    (d / "aegis_governance-0.0.0.tar.gz").write_bytes(_archive_bytes("sdist", []) if sdist is None else sdist)
    return d


def _write_sums(dist):
    rows = []
    for path in sorted(dist.iterdir()):
        if path.name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(digest + "  " + path.name + "\n")
    (dist / "SHA256SUMS").write_bytes("".join(rows).encode("ascii"))


def _hardlink_sdist():
    """In-memory sdist whose team-templates member is a tar hard link."""
    payload = b"{}\n"
    regular = tarfile.TarInfo("release/aegis_core/team_templates/role-registry.json")
    regular.size = len(payload)
    link = tarfile.TarInfo("release/aegis_core/team_templates/link.json")
    link.type = tarfile.LNKTYPE
    link.linkname = "aegis_core/team_templates/role-registry.json"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        archive.addfile(regular, io.BytesIO(payload))
        archive.addfile(link)
    return buf.getvalue()


def test_publish_never_rebuilds_and_verifies_digests():
    publish = _load("publish.yml")["jobs"]["publish"]
    runs = _runs(publish)
    assert "python -m build" not in runs, "publish must not rebuild the artifact"
    assert "verify_dist.py verify dist" in runs
    assert "twine upload dist/*" not in runs, "publish must upload only verified files"
    assert "needs" in publish and "validate" in str(publish["needs"])


def test_digest_verification_failure_cannot_be_masked_by_a_pipe():
    """`verify ... | tee` exits 0 when verify fails (no pipefail by default)."""
    for workflow, job in (("publish.yml", "publish"), ("validate.yml", "validate"),
                          ("validate.yml", "build-wheel")):
        for step in _load(workflow)["jobs"][job]["steps"]:
            run = step.get("run", "")
            if "verify_dist.py" not in run:
                continue
            for line in run.splitlines():
                if "verify_dist.py" in line:
                    assert "|" not in line, f"{workflow}:{job} pipes verify_dist output: {line}"


def test_build_records_digests_and_smoke_tests_sdist():
    build = _load("validate.yml")["jobs"]["build-wheel"]
    runs = _runs(build)
    assert "verify_dist.py record dist" in runs
    assert "wheel_smoke.py" in runs and "-I" in runs, "sdist must be smoke-tested"


def test_validate_matrix_smoke_tests_wheel_source_hidden():
    validate = _load("validate.yml")["jobs"]["validate"]
    runs = _runs(validate)
    assert "verify_dist.py verify dist" in runs
    assert "head -n 1" not in runs, "must install the single verified wheel, not the first match"
    smoke = [s.get("run", "") for s in validate["steps"] if "wheel_smoke.py" in s.get("run", "")]
    assert smoke, "matrix must smoke-test the installed wheel"
    assert "env -u PYTHONPATH" in smoke[0] and "python -I" in smoke[0]
    assert 'cd "$RUNNER_TEMP"' in smoke[0], "smoke must run outside the checkout"


def test_wheel_smoke_expected_tools_match_the_shipped_registry():
    from aegis_mcp.registry import TOOL_DEFINITIONS

    tree = ast.parse(Path(SMOKE).read_text(encoding="utf-8"))
    expectations = [ast.literal_eval(node.value) for node in tree.body
                    if isinstance(node, ast.Assign) and any(
                        isinstance(target, ast.Name) and target.id == "EXPECTED_MCP_TOOLS"
                        for target in node.targets)]
    assert expectations == [tuple(sorted(tool["name"] for tool in TOOL_DEFINITIONS))]


def test_wheel_smoke_queue_registry_and_modules(wheel_smoke):
    from aegis_mcp.registry import QUEUE_TOOL_DEFINITIONS

    assert wheel_smoke.EXPECTED_QUEUE_MCP_TOOLS == tuple(sorted(t["name"] for t in QUEUE_TOOL_DEFINITIONS))
    wheel_smoke.check_queue_tools(QUEUE_TOOL_DEFINITIONS)
    assert {"aegis_mcp.queue_role", "aegis_mcp.queue_owner"} <= set(wheel_smoke.EXPECTED_MODULES)


@pytest.mark.parametrize("tools", [None, [], [{"name": "token=private-value"}]])
def test_wheel_smoke_queue_registry_refuses_fixed(wheel_smoke, tools, capsys):
    with pytest.raises(SystemExit) as exc:
        wheel_smoke.check_queue_tools(tools)
    assert exc.value.code == 1
    output = capsys.readouterr()
    assert "queue MCP tools mismatch" in output.err
    assert "private-value" not in output.err + output.out


@pytest.fixture
def wheel_smoke():
    spec = importlib.util.spec_from_file_location("wheel_smoke", SMOKE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _expected_facts(channel, value):
    raw = value if isinstance(value, bytes) else (value if isinstance(value, str) else json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))).encode("utf-8", "surrogatepass")
    lines = raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))
    result = f"{channel} bytes={len(raw)} lines={lines} sha256={hashlib.sha256(raw).hexdigest()[:12]}"
    if len(raw) > 1024 * 1024:
        return result + " json=unparsed"
    try:
        decoded = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return result + " json=invalid"
    types = {str: "string", dict: "object", list: "array", bool: "boolean", int: "number", float: "number", type(None): "null"}
    result += " json=" + types[type(decoded)]
    if isinstance(decoded, dict):
        expected = {"aegis_capture_insight", "aegis_create_rule", "aegis_list_rules", "aegis_msg_read", "aegis_msg_write",
            "aegis_report_outcome", "aegis_scan", "aegis_team_config", "aegis_team_model", "aegis_team_queue",
            "result", "error", "tools", "name", "content", "text", "rules", "_name", "schema", "lanes", "check",
            "status", "tip", "hosts", "source", "dry_run", "aegis_version", "checked_at", "scope", "actions",
            "rule", "type", "triggers", "tp", "fp", "score"}
        known = sorted(set(decoded) & expected)
        result += f" keys={len(decoded)} known-keys=[{','.join(known)}] other-keys={len(decoded) - len(known)}"
    return result


def _expected_identifier(value, expected, label=None, schema=False):
    raw = value.encode("utf-8", "surrogatepass")
    difference = next((i for i, pair in enumerate(zip(value, expected)) if pair[0] != pair[1]), min(len(value), len(expected)))
    result = (f"expected={expected if label is None else label!r} actual-type=str length={len(value)} "
              f"sha256={hashlib.sha256(raw).hexdigest()[:12]} first-difference={difference}")
    if schema and re.fullmatch(r"aegis(\.[a-z]{1,24}){1,4}/v[0-9]{1,3}", value):
        result += " actual-schema=" + value
    return result


@pytest.mark.parametrize("change", ["same", "missing", "unexpected", "substituted", "duplicate",
    "non-dict", "nameless", "non-string", "whitespace-name", "zero-width-name", "fullwidth-name", "empty-name", "long-name",
    "queue-duplicate", "queue-fact-key"])
def test_wheel_smoke_checks_mcp_names(wheel_smoke, monkeypatch, tmp_path, capsys, change):
    from aegis_mcp.registry import TOOL_DEFINITIONS

    names = sorted(tool["name"] for tool in TOOL_DEFINITIONS)
    missing = [names.pop()] if change in ("missing", "substituted") else []
    unexpected = ["aegis_unexpected"] if change in ("unexpected", "substituted") else []
    duplicates = (["aegis_scan"] if change == "duplicate" else
                  ["aegis_team_queue"] if change == "queue-duplicate" else [])
    tools = [{"name": name} for name in reversed(names + unexpected)] + [{"name": name} for name in duplicates]
    invalid = {"non-dict": None, "nameless": {}, "non-string": {"name": 7}}
    invalid_names = {"whitespace-name": "aegis_scan ", "zero-width-name": "aegis_scan\u200b",
                     "fullwidth-name": "\uff41egis_scan", "empty-name": "", "long-name": "a" * 129}
    if change in invalid:
        tools.append(invalid[change])
    if change in invalid_names:
        tools.append({"name": invalid_names[change]})
    queue_error = {"aegis_team_queue": "private-value", "private-field": "private-value"}
    frame = {"error": queue_error} if change == "queue-fact-key" else {"result": {"tools": tools}}
    frames = [{}, frame,
              {"result": {"content": [{"text": json.dumps({"rules": [{"_name": "trap-smoke"}]})}]}}]
    proc = subprocess.CompletedProcess([], 0, "\n".join(map(json.dumps, frames)), "")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=lambda *a, **kw: proc))
    if change == "same":
        wheel_smoke.check_mcp(str(tmp_path))
        assert "ok  aegis_mcp" in capsys.readouterr().out
        return
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    if change == "queue-fact-key":
        reason = ("returned no result: " + _expected_facts("error", queue_error) +
                  "; " + _expected_facts("stderr", proc.stderr))
    elif change in invalid:
        reason = f"invalid tool entry at index {len(names)}: expected a dict with a string name"
    elif change in invalid_names:
        actual = invalid_names[change]
        expected = max(sorted(tool["name"] for tool in TOOL_DEFINITIONS), key=lambda item: next(
            (i for i, pair in enumerate(zip(actual, item)) if pair[0] != pair[1]), min(len(actual), len(item))))
        reason = (f"invalid tool name at index {len(names)}: expected [A-Za-z0-9_.-]{{1,128}}; " +
                  _expected_identifier(actual, expected))
    else:
        def identifiers(values):
            rows = []
            for actual in values:
                expected = max(sorted(tool["name"] for tool in TOOL_DEFINITIONS), key=lambda item: next(
                    (i for i, pair in enumerate(zip(actual, item)) if pair[0] != pair[1]), min(len(actual), len(item))))
                rows.append(_expected_identifier(actual, expected))
            return f"count={len(values)} [" + "; ".join(rows) + "]"
        reason = f"tools mismatch: missing={missing!r}, unexpected={identifiers(unexpected)}, duplicates={identifiers(duplicates)}"
    captured = capsys.readouterr()
    assert captured.err == f"wheel smoke FAILED: MCP tools/list {reason}\n"
    if change in ("queue-duplicate", "queue-fact-key"):
        assert captured.out == ""
        assert "private-value" not in captured.err and "private-field" not in captured.err
        assert all(FACT_LINE.fullmatch(line) for line in captured.err.splitlines())
        if change == "queue-fact-key":
            assert "known-keys=[aegis_team_queue]" in captured.err


@pytest.mark.parametrize("response", ["error", "no-result", "null-result", "bad-json", "wrong-tools"])
def test_wheel_smoke_mcp_response_refusals(wheel_smoke, monkeypatch, tmp_path, capsys, response):
    error_value = {"code": -32603, "message": "server failed"}
    frame = {"error": error_value} if response == "error" else {}
    if response == "null-result":
        frame["result"] = None
    if response == "wrong-tools":
        frame["result"] = {"tools": None}
    stdout = "not-json" if response == "bad-json" else "\n".join(map(json.dumps, [{}, frame, {}]))
    proc = subprocess.CompletedProcess([], 1, stdout, "server stderr")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=lambda *a, **kw: proc))
    if response == "bad-json":
        reason = f"returned invalid JSON: exception=omitted; {_expected_facts('stdout', stdout)}; {_expected_facts('stderr', proc.stderr)}"
    elif response == "wrong-tools":
        reason = "tools/list tools must be a list"
    else:
        reason = f"tools/list returned no result: {_expected_facts('error', error_value if response == 'error' else None)}; {_expected_facts('stderr', proc.stderr)}"
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == f"wheel smoke FAILED: MCP {reason}\n"


@pytest.fixture
def launcher_commands(wheel_smoke, monkeypatch, tmp_path):
    from aegis_cli import install_hosts

    commands = {"registered": ["registered-mcp"], "fallback": [sys.executable, "-I", "-c", "pass"]}
    monkeypatch.setattr(install_hosts, "mcp_command", lambda **kw: commands["fallback" if kw else "registered"])
    monkeypatch.setattr(install_hosts, "launch_risk", lambda command: None)
    monkeypatch.setattr(wheel_smoke, "tempfile", SimpleNamespace(mkdtemp=lambda **kw: tempfile.mkdtemp(dir=tmp_path, **kw)))
    return commands


@pytest.mark.parametrize("kind", ["registered", "fallback"])
@pytest.mark.parametrize("response", ["one-line", "error", "bad-json"])
def test_wheel_smoke_launcher_refusals(wheel_smoke, launcher_commands, monkeypatch, capsys, kind, response):
    from aegis_mcp.registry import TOOL_DEFINITIONS

    value = {"code": -32603, "message": "server failed"}
    stdout = json.dumps({"result": {}})
    if response == "error":
        stdout += "\n" + json.dumps({"error": value})
    if response == "bad-json":
        stdout = "not-json"
    good = "\n".join(map(json.dumps, [{}, {"result": {"tools": TOOL_DEFINITIONS}}]))
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout, "launcher stderr") if command == launcher_commands[kind] else subprocess.CompletedProcess(command, 0, good, "")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=run))
    context = f"the {kind} MCP launcher {_expected_facts('command', launcher_commands[kind])}"
    if response == "error":
        reason = f"tools/list returned no result: {_expected_facts('error', value)}; {_expected_facts('stderr', 'launcher stderr')}"
    elif response == "bad-json":
        reason = f"returned invalid JSON: exception=omitted; {_expected_facts('stdout', stdout)}; {_expected_facts('stderr', 'launcher stderr')}"
    else:
        reason = f"did not return 2 responses: {_expected_facts('stdout', stdout)}; {_expected_facts('stderr', 'launcher stderr')}"
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp_launcher()
    assert error.value.code == 1
    assert calls == ([launcher_commands["registered"]] if kind == "registered" else list(launcher_commands.values()))
    assert capsys.readouterr().err == f"wheel smoke FAILED: {context} {reason}\n"


@pytest.mark.parametrize("response", ["error", "missing-content", "bad-json", "no-rules", "missing-rule"])
def test_wheel_smoke_rules_response_refusals(wheel_smoke, monkeypatch, tmp_path, capsys, response):
    from aegis_mcp.registry import TOOL_DEFINITIONS

    error_value = {"code": -32603, "message": "server failed"}
    payload = {"rules": None if response == "no-rules" else []}
    frame = {"result": {"content": [{"text": "not-json" if response == "bad-json" else json.dumps(payload)}]}}
    if response == "error":
        frame = {"error": error_value}
    if response == "missing-content":
        frame = {"result": {}}
    stdout = "\n".join(map(json.dumps, [{}, {"result": {"tools": TOOL_DEFINITIONS}}, frame]))
    proc = subprocess.CompletedProcess([], 0, stdout, "server stderr")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=lambda *a, **kw: proc))
    reasons = {
        "error": f"returned no result: {_expected_facts('error', error_value)}; {_expected_facts('stderr', proc.stderr)}",
        "missing-content": f"returned invalid content; {_expected_facts('stderr', proc.stderr)}",
        "bad-json": f"returned invalid JSON; exception=omitted; {_expected_facts('stderr', proc.stderr)}",
        "no-rules": f"returned no rules list: {_expected_facts('rules', payload)}",
        "missing-rule": "did not see the workspace rule: count=0 []"}
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == f"wheel smoke FAILED: MCP aegis_list_rules {reasons[response]}\n"


@pytest.mark.parametrize("rule", [{"_name": []}, {"_name": {}}, {"_name": 7}, {}, None],
                         ids=["list-name", "dict-name", "number-name", "missing-name", "non-object"])
def test_wheel_smoke_invalid_rule_names(wheel_smoke, monkeypatch, tmp_path, capsys, rule):
    from aegis_mcp.registry import TOOL_DEFINITIONS
    frames = [{}, {"result": {"tools": TOOL_DEFINITIONS}},
              {"result": {"content": [{"text": json.dumps({"rules": [rule]})}]}}]
    proc = subprocess.CompletedProcess([], 0, "\n".join(map(json.dumps, frames)), "")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=lambda *a, **kw: proc))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == "wheel smoke FAILED: MCP aegis_list_rules invalid rule entry at index 0: expected a dict with a string _name\n"


@pytest.mark.parametrize("name", ["trap-smoke ", "trap-smoke\r", "trap-smoke\u200b", "\uff54rap-smoke"])
def test_wheel_smoke_refuses_ambiguous_rule_names(wheel_smoke, monkeypatch, tmp_path, capsys, name):
    from aegis_mcp.registry import TOOL_DEFINITIONS
    frames = [{}, {"result": {"tools": TOOL_DEFINITIONS}},
              {"result": {"content": [{"text": json.dumps({"rules": [{"_name": name}]})}]}}]
    proc = subprocess.CompletedProcess([], 0, "\n".join(map(json.dumps, frames)), "")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=lambda *a, **kw: proc))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == ("wheel smoke FAILED: MCP aegis_list_rules invalid rule name at index 0: expected [A-Za-z0-9_.-]{1,128}; " +
                                     _expected_identifier(name, "trap-smoke") + "\n")


@pytest.mark.parametrize("field", ["claim-schema", "status-schema", "check-status", "tip", "doctor-schema", "init-source", "init-status"])
@pytest.mark.parametrize("value", ["wrong", "wrong ", "wrong\r", "wrong\u200b", "\uff57rong"])
def test_wheel_smoke_names_mismatched_identifier_fields(wheel_smoke, monkeypatch, tmp_path, capsys, field, value):
    from aegis_core import gitsafe
    tips = []
    def run(command, **kwargs):
        if "claim" in command:
            payload = {"schema": value if field == "claim-schema" else "aegis.team.claim/v1"}
        elif "status" in command:
            tips.append(gitsafe.head_commit(kwargs["cwd"]))
            payload = {"schema": value if field == "status-schema" else "aegis.team.status/v1", "lanes": [
                {"check": {"status": value if field == "check-status" else "pass"}, "tip": value if field == "tip" else tips[-1]}]}
        elif "doctor" in command:
            payload = {"schema": value, "hosts": []}
        elif "--dry-run" in command:
            payload = {"source": value if field == "init-source" else "aegis init", "status": value if field == "init-status" else "ok", "dry_run": True}
        else:
            return subprocess.run(command, **kwargs)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
    monkeypatch.setattr(wheel_smoke, "tempfile", SimpleNamespace(
        TemporaryDirectory=lambda **kw: tempfile.TemporaryDirectory(dir=tmp_path, **kw),
        mkdtemp=lambda **kw: tempfile.mkdtemp(dir=tmp_path, **kw)))
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=run))
    contexts = {"claim-schema": ("installed team claim schema", "aegis.team.claim/v1"),
                "status-schema": ("installed team status schema", "aegis.team.status/v1"),
                "check-status": ("installed team status check.status", "pass"), "tip": ("installed team status tip", "workspace-tip"),
                "doctor-schema": ("aegis doctor --json schema", "aegis.doctor/v1"),
                "init-source": ("aegis init --dry-run source", "aegis init"), "init-status": ("aegis init --dry-run status", "ok")}
    with pytest.raises(SystemExit) as error:
        if field.startswith("init-"):
            wheel_smoke.check_init_dry_run(str(tmp_path))
        elif field == "doctor-schema":
            wheel_smoke.check_doctor(str(tmp_path))
        else:
            wheel_smoke.check_team_status()
    assert error.value.code == 1
    context, expected = contexts[field]
    identity = _expected_identifier(value, tips[-1], "workspace-tip") if field == "tip" else _expected_identifier(value, expected)
    assert capsys.readouterr().err == f"wheel smoke FAILED: {context} mismatch: {identity}\n"


@pytest.mark.parametrize("result", [None, [], [None], [{"rule": "other"}],
    [{"rule": "trap-smoke", "type": "trap", "triggers": 0, "tp": 0, "fp": 0, "score": 1.0}]],
    ids=["not-list", "empty", "invalid-row", "missing-rule", "bad-score"])
def test_wheel_smoke_governance_validates_landscape(wheel_smoke, monkeypatch, tmp_path, capsys, result):
    from aegis_sdk import governance
    monkeypatch.setattr(governance, "Governance", lambda **kw: SimpleNamespace(fitness_landscape=lambda: result))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_governance_fitness(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == f"wheel smoke FAILED: governance fitness_landscape invalid workspace fitness: {_expected_facts('result', result)}\n"


def test_wheel_smoke_governance_real_landscape(wheel_smoke, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(wheel_smoke, "tempfile", SimpleNamespace(mkdtemp=lambda **kw: tempfile.mkdtemp(dir=tmp_path, **kw)))
    wheel_smoke.check_governance_fitness(wheel_smoke.make_workspace())
    assert capsys.readouterr().out == "ok  governance (Governance.fitness_landscape)\n"


def test_wheel_smoke_governance_inventory_refusal(wheel_smoke, monkeypatch, tmp_path, capsys):
    from aegis_sdk import governance
    def landscape():
        raise RuntimeError("rules inventory unavailable")
    monkeypatch.setattr(governance, "Governance", lambda **kw: SimpleNamespace(fitness_landscape=landscape))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_governance_fitness(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == "wheel smoke FAILED: governance fitness_landscape failed: exception=RuntimeError\n"


FACT_CHANNELS = ("stdout-json", "stderr-json", "non-json", "mapping", "scalar", "json-key",
                 "timeout-stdout", "timeout-stderr", "identifier", "rule-name", "dry-run", "seeded", "active", "exception")
LEAK_CASES = [
    (f"{key}-{index}", f'{key}={escape}"opaque-auth-value99"{escape}', "opaque-auth-value99")
    for key in ("token", "pwd", "auth")
    for index, escape in enumerate((r'\"', r'\t', r'\b', r'\f', r'\n', r'\r', r"\'", r'\u0009'))
] + [
    ("quoted-token", 'token="opaque-credential-value"', "opaque-credential-value"),
    ("quoted-api-key", 'api_key="abcdEFGH12345678secret"', "abcdEFGH12345678secret"),
    ("old-pwd", r'pwd=\"opaque-value-1234\"', "opaque-value-1234"),
    ("prose-pwd", r'my pwd is \"opaque-auth-value99\"', "opaque-auth-value99"),
    ("encoded-key", r'\u0074oken=\"opaque-auth-value99\"', "opaque-auth-value99"),
    ("long-unicode", r'\U00000074oken=\"opaque-auth-value99\"', "opaque-auth-value99"),
    ("hex-key", r'\x74oken=\"opaque-auth-value99\"', "opaque-auth-value99"),
    ("encoded-prefix", r'\u0067hp_1234567890abcdefghijklmnopqrstuv', "1234567890abcdefghij"),
    ("encoded-middle-prefix", r'gh\u0070_1234567890abcdefghijklmnopqrstuv', "1234567890abcdefghij"),
    ("zero-width", 'to\u200bken=opaque-auth-value99', "opaque-auth-value99"),
    ("repr-zero-width", r'to\u200bken=opaque-auth-value99', "opaque-auth-value99"),
    ("combining", 'to\u0301ken=opaque-auth-value99', "opaque-auth-value99"),
    ("encoded-combining", r'to\u0301ken=opaque-auth-value99', "opaque-auth-value99"),
    ("fullwidth", '\uff54\uff4f\uff4b\uff45\uff4e\uff1dopaque-auth-value99', "opaque-auth-value99"),
    ("fullwidth-backslash", "token=\uff3c'opaque-auth-value99\uff3c'", "opaque-auth-value99"),
    ("nested-quotes", r'{"token":"\"opaque-auth-value99\""}', "opaque-auth-value99"),
    ("python-repr", r'''token=\'opaque-auth-value99\' "x"''', "opaque-auth-value99"),
    ("separator", "tok-en=opaque-auth-value99", "opaque-auth-value99"),
    ("yaml-block", "token: >-\n  opaque-auth-value99", "opaque-auth-value99"),
    ("windows", r"FileNotFoundError: 'C:\opaque-auth-value99\rules'", "opaque-auth-value99"),
    ("boundary-tail", "x" * 290 + " token=" + "s" * 40, "s" * 40),
    ("argon-comma", 'token=aaaa, "opaque-auth-value99"', "opaque-auth-value99"),
    ("argon-json-corruption", r'{"result":{"a":"token=abcd\"","b":"\u0067hp_1234567890abcdefghijklmnopqrstuv"}}', "1234567890abcdefghij"),
    ("argon-fullwidth-quote", '{"result":{"a":"token=abcd\uff02","b":"\\u0067hp_1234567890abcdefghijklmnopqrstuv"}}', "1234567890abcdefghij"),
] + [(f"pem-{index}", f"-----BEGIN {label}-----\nYWJjZGVmZ2hpamts\nbW5vcHFyc3R1dnd4\n-----END {label}-----", "YWJjZGVmZ2hpamts")
     for index, label in enumerate(("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "CERTIFICATE"))
] + [(f"prefix-{index}", "err\\n" + prefix + "1234567890abcdefghijklmnopqrstuv", "1234567890abcdefghij")
     for index, prefix in enumerate(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "sk-",
        "sk-proj-", "sk-ant-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_",
        "AIza", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-", "npm_", "pypi-"))]

# Independent output alphabet: words are fixed messages, channels, type labels,
# or expected keys/constants. No child-derived word is accepted by this grammar.
_FACT_WORDS = """wheel smoke FAILED MCP returned invalid JSON did not return responses tools/list aegis_list_rules
tools mismatch missing unexpected duplicates invalid tool name rule entry at index expected a dict with string
no result error stdout stderr timeout-stdout timeout-stderr command bytes lines sha256 json object array number
boolean null str list tuple int float unsupported unparsed keys known-keys other-keys count length first-difference
actual-type actual-schema none true false source status schema rules content text name _name result tools hosts
lanes check tip dry_run aegis_version checked_at scope actions type triggers tp fp score rule path command
timed out after seconds could not run exception FileNotFoundError Exception omitted wrote entries seeded active
aegis init --dry-run --json --help read the repository's own rules/ planted code ran
seeded the active starters no-eval expected valid-tool-name trap-smoke registered fallback launcher
is unsafe this interpreter in isolated mode ignores packages imported from its start directory
installed team claim schema check.status workspace-tip TOOL_DEFINITIONS
returned invalid content rules list see workspace must be exceeds characters invalid identifier
stdout-json non-json mapping scalar json-key identifier rule-name dry-run seeded active
""".split()
_EXPECTED_FACT_WORDS = ("aegis.team.claim/v1", "aegis.team.status/v1", "aegis.doctor/v1", "aegis init", "ok", "pass",
    "aegis_capture_insight", "aegis_create_rule", "aegis_list_rules", "aegis_msg_read", "aegis_msg_write",
    "aegis_report_outcome", "aegis_scan", "aegis_team_config", "aegis_team_model", "aegis_team_queue",
    "[A-Za-z0-9_.-]{1,128}", "True", "False")
_FACT_TOKEN = "(?:" + "|".join(re.escape(word) for word in sorted(set(_FACT_WORDS + list(_EXPECTED_FACT_WORDS)), key=len, reverse=True)) + r"|[0-9a-f]{12}|[0-9]+|aegis(?:\.[a-z]{1,24}){1,4}/v[0-9]{1,3})"
FACT_LINE = re.compile(_FACT_TOKEN + r"(?:[ ,;:=\[\]'().-]+" + _FACT_TOKEN + r")*[ ,;:=\[\]'().-]*", re.ASCII)


@pytest.fixture
def smoke_failure(wheel_smoke, monkeypatch, tmp_path):
    from aegis_mcp.registry import TOOL_DEFINITIONS

    original_os = os

    def invoke(channel, payload):
        def names(path):
            if channel == "seeded":
                return [payload]
            if channel == "active":
                return [f"rule-{index}.md" for index in range(wheel_smoke.FULL_PRESET_RULES)] if str(path).endswith("personas") else [payload]
            return [payload] if channel == "dry-run" else []

        @contextlib.contextmanager
        def scan(path):
            yield iter(SimpleNamespace(name=name) for name in names(path))

        local_os = SimpleNamespace(**vars(original_os))
        local_os.scandir = scan
        local_os.listdir = names
        monkeypatch.setattr(wheel_smoke, "os", local_os)
        monkeypatch.setattr(wheel_smoke, "tempfile", SimpleNamespace(
            mkdtemp=lambda **kw: tempfile.mkdtemp(dir=tmp_path, **kw),
            TemporaryDirectory=lambda **kw: tempfile.TemporaryDirectory(dir=tmp_path, **kw)))

        def run(command, **kwargs):
            if channel.startswith("timeout-"):
                raise subprocess.TimeoutExpired(command, kwargs["timeout"],
                    output=payload.encode("utf-8", "surrogatepass") if channel == "timeout-stdout" else b"",
                    stderr=payload.encode("utf-8", "surrogatepass") if channel == "timeout-stderr" else b"")
            if channel == "exception":
                raise FileNotFoundError(payload)
            if channel in ("dry-run", "seeded", "active"):
                value = dict(source="aegis init", status="ok", dry_run=True, aegis_version="fixture", checked_at="fixture", scope={}, actions=[])
                return subprocess.CompletedProcess(command, 0, json.dumps(value).encode(), b"")
            stdout, stderr = "not-json", ""
            if channel == "stdout-json":
                stdout = json.dumps({"result": {"message": payload}})
            elif channel == "stderr-json":
                stderr = json.dumps({"message": payload})
            elif channel == "non-json":
                stdout = "broken JSON " + payload
            elif channel == "json-key":
                stdout = json.dumps({payload: None})
            elif channel in ("mapping", "scalar"):
                stdout = "\n".join(map(json.dumps, [{}, {"error": {"message": payload} if channel == "mapping" else payload}, {}]))
            else:
                tools = [{"name": payload}] if channel == "identifier" else TOOL_DEFINITIONS
                rule_name = payload if channel == "rule-name" else "trap-smoke"
                stdout = "\n".join(map(json.dumps, [{}, {"result": {"tools": tools}},
                    {"result": {"content": [{"text": json.dumps({"rules": [{"_name": rule_name}]})}]}}]))
            return subprocess.CompletedProcess(command, 0, stdout.encode("utf-8", "surrogatepass"), stderr.encode("utf-8", "surrogatepass"))

        monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=run))
        if channel == "dry-run":
            wheel_smoke.check_init_dry_run(str(tmp_path))
        elif channel in ("seeded", "active"):
            wheel_smoke.check_init_ignores_a_repository_rules_package()
        else:
            wheel_smoke.check_mcp(str(tmp_path))
    return invoke


@pytest.mark.parametrize("channel", FACT_CHANNELS)
@pytest.mark.parametrize(("case", "payload", "secret"), LEAK_CASES, ids=[row[0] for row in LEAK_CASES])
def test_wheel_smoke_facts_negative_control(smoke_failure, capsys, channel, case, payload, secret):
    with pytest.raises(SystemExit) as error:
        smoke_failure(channel, payload)
    assert error.value.code == 1
    output = capsys.readouterr()
    combined = output.out + output.err
    for form in (secret, json.dumps(secret)[1:-1], repr(secret)[1:-1]):
        assert form not in combined
    assert output.err
    assert all(line.isascii() and FACT_LINE.fullmatch(line) for line in combined.splitlines()), combined


@pytest.mark.parametrize("channel", FACT_CHANNELS)
@settings(max_examples=10, deadline=None, derandomize=True, database=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(payload=st.text(max_size=160))
def test_wheel_smoke_facts_output_property(smoke_failure, capsys, channel, payload):
    # invoke resets every patched boundary; tmp_path is only a sandbox for the
    # script's own generated fixtures, never the generated child text.
    with pytest.raises(SystemExit) as error:
        smoke_failure(channel, payload)
    assert error.value.code == 1
    output = capsys.readouterr()
    assert all(line.isascii() and FACT_LINE.fullmatch(line) for line in (output.out + output.err).splitlines())


def test_wheel_smoke_facts_exact_line(wheel_smoke):
    data = b'{"result":{},"opaque-auth-value99":"opaque-auth-value99"}\n'
    assert wheel_smoke._facts("stdout", data) == (
        f"stdout bytes={len(data)} lines=1 sha256={hashlib.sha256(data).hexdigest()[:12]} "
        "json=object keys=2 known-keys=[result] other-keys=1")


@pytest.mark.parametrize("actual", ["ghp_1234567890abcdefghijklmnopqrstuv", "aegis.doctor/v2", "aegis.doctor/v2\nsecret"])
def test_wheel_smoke_facts_exact_identifier(wheel_smoke, monkeypatch, tmp_path, capsys, actual):
    proc = subprocess.CompletedProcess([], 0, json.dumps({"schema": actual, "hosts": []}), "")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=lambda *a, **kw: proc))
    monkeypatch.setattr(wheel_smoke, "tempfile", SimpleNamespace(mkdtemp=lambda **kw: tempfile.mkdtemp(dir=tmp_path, **kw)))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_doctor(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == ("wheel smoke FAILED: aegis doctor --json schema mismatch: " +
        _expected_identifier(actual, "aegis.doctor/v1", schema=True) + "\n")


@pytest.mark.parametrize("custom", [False, True])
def test_wheel_smoke_facts_exact_exception(wheel_smoke, monkeypatch, tmp_path, capsys, custom):
    commands = []
    exception = type("pwd=opaque-auth-value99", (FileNotFoundError,), {}) if custom else FileNotFoundError
    def run(command, **kwargs):
        commands.append(command)
        raise exception("pwd=opaque-auth-value99")
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=run))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == (
        f"wheel smoke FAILED: command {_expected_facts('command', commands[-1])} could not run: exception={'omitted' if custom else 'FileNotFoundError'}\n")


def test_wheel_smoke_facts_exact_filename(smoke_failure, capsys):
    payload = "pwd=opaque-auth-value99"
    with pytest.raises(SystemExit) as error:
        smoke_failure("dry-run", payload)
    assert error.value.code == 1
    assert capsys.readouterr().err == f"wheel smoke FAILED: aegis init --dry-run wrote count=1 [{_expected_facts('name', payload)}]\n"


def test_wheel_smoke_facts_preserve_child_raw_bytes(wheel_smoke, monkeypatch, tmp_path, capsys):
    calls = []
    def run(command, **kwargs):
        calls.append(kwargs)
        # Model a non-UTF-8 host decoding byte e9 in text mode.
        stdout, stderr = ("not-json", "\u00e9") if kwargs.get("text") else (b"not-json", b"\xe9")
        return subprocess.CompletedProcess(command, 0, stdout, stderr)
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=run))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    assert calls[0]["text"] is False
    assert isinstance(calls[0]["input"], bytes)
    assert capsys.readouterr().err == (
        "wheel smoke FAILED: MCP returned invalid JSON: exception=omitted; " +
        _expected_facts("stdout", b"not-json") + "; " + _expected_facts("stderr", b"\xe9") + "\n")


def test_wheel_smoke_facts_empty_timeout(wheel_smoke, monkeypatch, tmp_path, capsys):
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        raise subprocess.TimeoutExpired(command, 60)
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=run))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == (
        f"wheel smoke FAILED: command {_expected_facts('command', commands[-1])} timed out after 60 seconds; " +
        _expected_facts("timeout-stdout", b"") + "; " + _expected_facts("timeout-stderr", b"") + "\n")


@pytest.mark.parametrize("mode", ["byte-limit", "character-limit"])
def test_wheel_smoke_limits_output_before_json_parsing(wheel_smoke, monkeypatch, tmp_path, capsys, mode):
    stdout = "\u00e9" * 600000 if mode == "byte-limit" else " " * (1024 * 1024 + 1)
    proc = subprocess.CompletedProcess([], 0, stdout, "")
    def parse(data):
        assert data != stdout, "oversized field reached JSON parsing"
        return json.loads(data)
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=lambda *a, **kw: proc))
    monkeypatch.setattr(wheel_smoke, "json", SimpleNamespace(loads=parse, dumps=json.dumps))
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_mcp(str(tmp_path))
    assert error.value.code == 1
    unit = "bytes" if mode == "byte-limit" else "characters"
    assert capsys.readouterr().err == (
        f"wheel smoke FAILED: MCP stdout exceeds 1048576 {unit}; {_expected_facts('stdout', stdout)}; {_expected_facts('stderr', '')}\n")


@pytest.mark.parametrize("value", [["x" * 1000000], object()], ids=["oversized", "unsupported"])
def test_wheel_smoke_limits_structured_facts_before_serializing(wheel_smoke, monkeypatch, capsys, value):
    def serialize(*args, **kwargs):
        pytest.fail("refused structure reached serialization")
    monkeypatch.setattr(wheel_smoke, "json", SimpleNamespace(dumps=serialize))
    with pytest.raises(SystemExit) as error:
        wheel_smoke._facts("error", value)
    assert error.value.code == 1
    expected = "exceeds limits" if isinstance(value, list) else "unsupported"
    assert capsys.readouterr().err == f"wheel smoke FAILED: diagnostic data {expected}\n"


def test_wheel_smoke_facts_missing_installation_refuses_without_traceback(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    env.pop("PYTHONPATH", None)
    proc = subprocess.run([sys.executable, "-I", "-S", SMOKE], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert proc.stderr == "wheel smoke FAILED: smoke check raised exception=ModuleNotFoundError\n"


def test_wheel_smoke_packaged_registry_refusal(wheel_smoke, monkeypatch, tmp_path, capsys):
    from aegis_mcp import registry

    tools = [dict(tool) for tool in registry.TOOL_DEFINITIONS]
    missing = tools[-1]["name"]
    tools[-1]["name"] = "aegis_unexpected"
    monkeypatch.setattr(registry, "TOOL_DEFINITIONS", tools)
    with pytest.raises(SystemExit) as error:
        wheel_smoke.check_packaged_rules_and_skills(str(tmp_path))
    assert error.value.code == 1
    assert capsys.readouterr().err == (
        f"wheel smoke FAILED: TOOL_DEFINITIONS tools mismatch: missing={[missing]!r}, unexpected=count=1 [" +
        _expected_identifier("aegis_unexpected", "aegis_capture_insight") + "], duplicates=count=0 []\n")


@pytest.mark.parametrize("entry", ["claim", "status", "doctor", "dry-run"])
@pytest.mark.parametrize("output", ["not-json", "[]", "oversized"])
def test_wheel_smoke_cli_json_refusals(wheel_smoke, monkeypatch, tmp_path, capsys, entry, output):
    stdout = "\u00e9" * 600000 if output == "oversized" else output
    commands = []
    def run(command, **kwargs):
        if (entry in command or (entry == "dry-run" and "--dry-run" in command)):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout, "server stderr")
        if "claim" in command:
            return subprocess.CompletedProcess(command, 0, '{"schema":"aegis.team.claim/v1"}', "")
        return subprocess.run(command, **kwargs)
    monkeypatch.setattr(wheel_smoke, "tempfile", SimpleNamespace(
        TemporaryDirectory=lambda **kw: tempfile.TemporaryDirectory(dir=tmp_path, **kw),
        mkdtemp=lambda **kw: tempfile.mkdtemp(dir=tmp_path, **kw)))
    monkeypatch.setattr(wheel_smoke, "subprocess", SimpleNamespace(run=run))
    with pytest.raises(SystemExit) as error:
        if entry == "dry-run":
            wheel_smoke.check_init_dry_run(str(tmp_path))
        elif entry == "doctor":
            wheel_smoke.check_doctor(str(tmp_path))
        else:
            wheel_smoke.check_team_status()
    assert error.value.code == 1
    if output == "oversized":
        reason = "stdout exceeds 1048576 bytes; "
    elif output == "[]":
        reason = "returned a non-object JSON response; "
    else:
        reason = "returned invalid JSON; exception=omitted; "
    assert capsys.readouterr().err == (
        f"wheel smoke FAILED: command {_expected_facts('command', commands[-1])} {reason}" +
        _expected_facts("stdout", stdout) + "; " + _expected_facts("stderr", "server stderr") + "\n")


def test_verify_dist_accepts_recorded_artifacts(tmp_path):
    d = _dist(tmp_path)
    assert _verify("record", str(d)).returncode == 0
    proc = _verify("verify", str(d))
    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout.split()) == 2


def test_record_accepts_the_exact_first_party_ast_corpus(tmp_path):
    d = _dist(tmp_path, extra=("aegis_core/benchmark_corpus/ast.json",))
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    proc = _verify("verify", str(d))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


@pytest.mark.parametrize("prefix", ["", "licenses/"])
def test_verify_dist_accepts_packaged_first_party_license_and_notice(tmp_path, prefix):
    d = _dist(tmp_path, extra=["aegis_guardrails-0.0.0.dist-info/" + prefix + name
                               for name in ("LICENSE", "NOTICE")],
              metadata="License-File: LICENSE\nLicense-File: NOTICE\n")
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    proc = _verify("verify", str(d))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


def test_verify_dist_rejects_tampered_artifact(tmp_path):
    d = _dist(tmp_path)
    assert _verify("record", str(d)).returncode == 0
    with open(d / "aegis_governance-0.0.0-py3-none-any.whl", "ab") as f:
        f.write(b"tampered")
    proc = _verify("verify", str(d))
    assert proc.returncode == 1 and "sha256" in proc.stderr


def test_verify_dist_rejects_unlisted_artifact(tmp_path):
    d = _dist(tmp_path)
    assert _verify("record", str(d)).returncode == 0
    (d / "aegis_governance-0.0.1-py3-none-any.whl").write_bytes(b"other")
    assert _verify("verify", str(d)).returncode == 1


@pytest.mark.parametrize("name", [
    "aegis_core/node_modules/x.py", "aegis_core/vendor/x.py", "aegis_core/third_party/x.py",
    "aegis_core/x.so", "aegis_core/x.pyd", "aegis_core/x.dll", "aegis_core/x.dylib",
    "aegis_core/x.wasm", "aegis_core/x.node", "aegis_core/x.jar", "aegis_core/x.js",
    "aegis_core/ast/drivers/templates/extra.py", "aegis_core/ast/drivers/templates/nested/x.go",
    "aegis_core/ast/drivers/templates/ts_ast.js",
    "aegis_core/ast/drivers/templates/rust_ast.py",
    "aegis_core/unexpected.json", "aegis_core/benchmark_corpus/adjacent.json",
    "foreign/__init__.py", "../aegis_core/x.py",
    "aegis_core/../x.py", "aegis_core\\x.py", "aegis_core/_data/rules/injected.md",
    "aegis_guardrails-0.0.0.dist-info/vendor.py",
    "aegis_core//x.py", "aegis_guardrails-9.9.9.dist-info/WHEEL",
    "aegis_core/x.py\x00hidden.py",
])
def test_record_rejects_injected_wheel_members_before_signing(tmp_path, name):
    d = _dist(tmp_path, extra=[name])
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "wheel member" in proc.stderr, proc.stderr
    assert not (d / "SHA256SUMS").exists()


@pytest.mark.parametrize("metadata", [
    "Requires-Dist: requests\n", "Provides-Extra: parser\n",
    "Requires-Dist: requests; extra == 'dev' or python_version > '3'\n",
    "Requires-Dist: requests; extra == 'parser'\n",
])
def test_record_rejects_runtime_dependencies_and_foreign_extras(tmp_path, metadata):
    proc = _verify("record", str(_dist(tmp_path, metadata=metadata)))
    assert proc.returncode == 1 and "wheel metadata" in proc.stderr, proc.stderr


def test_verify_rechecks_contents_even_with_matching_digests(tmp_path):
    import hashlib

    d = _dist(tmp_path, extra=["aegis_core/vendor/x.py"])
    (d / "SHA256SUMS").write_text("".join(
        hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in sorted(d.iterdir())),
        encoding="utf-8")
    proc = _verify("verify", str(d))
    assert proc.returncode == 1 and "wheel member" in proc.stderr, proc.stderr


def test_record_rejects_a_missing_phase_template(tmp_path):
    d = _dist(tmp_path)
    path = next(d.glob("*.whl"))
    with zipfile.ZipFile(path) as wheel:
        members = {name: wheel.read(name) for name in wheel.namelist() if not name.endswith("/go_ast.go")}
    with zipfile.ZipFile(path, "w") as wheel:
        for name, content in members.items():
            wheel.writestr(name, content)
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "template allowlist" in proc.stderr, proc.stderr


def test_record_rejects_a_corrupt_wheel(tmp_path):
    d = _dist(tmp_path)
    next(d.glob("*.whl")).write_bytes(b"not a zip")
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "invalid wheel" in proc.stderr, proc.stderr


# Display cap in .github/scripts/verify_dist.py. The boundary case below straddles it
# so truncation cannot run before the value is masked and still hide it.
_MEMBER_TEXT_LIMIT = 240
_TEAM_TEMPLATE_ASSETS = (
    "aegis_core/team_templates/role-registry.json",
    "aegis_core/team_templates/__init__.py",
    "aegis_core/team_templates/model-bindings.json",
    "aegis_core/team_templates/roles/builder.md",
    "aegis_core/team_templates/hosts/assistants-builder.json",
    "aegis_core/team_templates/native-probe-attempt.py",
    "aegis_core/team_templates/caf\u00e9.json",
)
_REJECTED_TEAM_TEMPLATE_MEMBERS = (
    "aegis_core/team_templates/payload.exe",
    "aegis_core/team_templates/payload.so",
    "aegis_core/team_templates/__pycache__/x.py",
    "aegis_core/team_templates/__PYCACHE__/x.py",
    "aegis_core/team_templates/roles/__pycache__/x.pyc",
    "aegis_core/team_templates/../x.json",
    "aegis_core/team_templates/roles/../../team_templatez/x.json",
    "aegis_core/team_templatez/x.json",
)


@pytest.mark.parametrize("name", _TEAM_TEMPLATE_ASSETS)
def test_record_accepts_declared_team_template_assets(tmp_path, name):
    """Suffix allowlist under one prefix, not one hard-coded filename."""
    d = _dist(tmp_path, extra=(name,))
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    proc = _verify("verify", str(d))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


def test_record_accepts_nested_team_templates_together(tmp_path):
    d = _dist(tmp_path, extra=_TEAM_TEMPLATE_ASSETS)
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    proc = _verify("verify", str(d))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


@pytest.mark.parametrize("name", _REJECTED_TEAM_TEMPLATE_MEMBERS)
def test_record_rejects_undeclared_team_template_members(tmp_path, name):
    d = _dist(tmp_path, extra=(name,))
    proc = _verify("record", str(d))
    assert proc.returncode == 1, proc.stderr
    assert "wheel member" in proc.stderr
    assert name in proc.stderr
    assert not (d / "SHA256SUMS").exists()


def test_verify_rejects_a_sibling_template_member_with_matching_digests(tmp_path):
    name = "aegis_core/team_templatez/x.json"
    d = _dist(tmp_path, extra=(name,))
    (d / "SHA256SUMS").write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
        for path in sorted(d.iterdir())), encoding="utf-8")
    proc = _verify("verify", str(d))
    assert proc.returncode == 1 and name in proc.stderr, proc.stderr


def test_rejected_team_template_member_is_canonicalized_redacted_then_truncated(tmp_path):
    """The secret straddles the display cap: redact the whole value, then cut."""
    secret = "supersecretvalue12345678"
    prefix = "aegis_core/team_templates/"
    # The hyphen keeps the key matchable; token= starts on the display-cap boundary.
    name = prefix + ("a" * (219 - len(prefix))) + "-token=" + secret + ".exe"
    assert name.index("token=") == 220
    assert 220 < _MEMBER_TEXT_LIMIT < len(name)
    d = _dist(tmp_path, extra=(name,))
    proc = _verify("record", str(d))
    assert proc.returncode == 1, proc.stderr
    assert secret not in proc.stderr and "token=super" not in proc.stderr
    assert "[REDACTED]" in proc.stderr
    assert prefix in proc.stderr
    assert proc.stderr.count("\n") == 1
    assert not (d / "SHA256SUMS").exists()


def test_record_refuses_a_multiline_wheel_member_without_joining(tmp_path):
    name = "aegis_core/team_templates/role-registry.json\ninjected-line"
    d = _dist(tmp_path, extra=(name,))
    proc = _verify("record", str(d))
    assert proc.returncode == 1, proc.stderr
    assert "injected-line" not in proc.stderr
    assert "\n" not in proc.stderr.rstrip("\n")
    assert "wheel member" in proc.stderr
    assert not (d / "SHA256SUMS").exists()


def test_record_rejects_a_non_normalized_team_template_name(tmp_path):
    name = "aegis_core/team_templates/cafe\u0301.json"
    d = _dist(tmp_path, extra=(name,))
    proc = _verify("record", str(d))
    assert proc.returncode == 1, proc.stderr
    assert "\u0301" not in proc.stderr
    assert "caf\u00e9.json" in proc.stderr
    assert not (d / "SHA256SUMS").exists()


def test_rejected_team_template_leaves_digests_unwritten_for_retry(tmp_path):
    rejected_root = tmp_path / "rejected"
    accepted_root = tmp_path / "accepted"
    rejected_root.mkdir()
    accepted_root.mkdir()
    rejected = _dist(rejected_root, extra=("aegis_core/team_templates/payload.exe",))
    proc = _verify("record", str(rejected))
    assert proc.returncode == 1 and "payload.exe" in proc.stderr, proc.stderr
    assert not (rejected / "SHA256SUMS").exists()
    accepted = _dist(accepted_root, extra=("aegis_core/team_templates/roles/builder.md",))
    proc = _verify("record", str(accepted))
    assert proc.returncode == 0, proc.stderr
    assert (accepted / "SHA256SUMS").is_file()
    proc = _verify("verify", str(accepted))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


def test_record_refuses_an_overlong_team_template_member_before_echoing_its_tail(tmp_path):
    """The limit is applied before the untrusted tail is encoded into the message."""
    secret = "supersecretvalue12345678"
    name = "aegis_core/team_templates/" + ("a" * 5000) + secret + ".json"
    assert len(name) > 4096
    d = _dist(tmp_path, extra=(name,))
    proc = _verify("record", str(d))
    assert proc.returncode == 1, proc.stderr
    assert secret not in proc.stderr and "supersecret" not in proc.stderr
    assert "member-sha256=" in proc.stderr and "wheel member" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert proc.stderr.count("\n") == 1
    assert not (d / "SHA256SUMS").exists()


def test_verify_refuses_an_escaping_digest_name_then_record_retries(tmp_path):
    d = _dist(tmp_path, extra=("aegis_core/team_templates/role-registry.json",))
    wheel = next(d.glob("*.whl")).name
    outside = tmp_path / "outside-secret"
    (d / "SHA256SUMS").write_text(
        ("a" * 64) + "  " + wheel + "\n" + ("b" * 64) + "  ../outside-secret\n",
        encoding="utf-8")
    proc = _verify("verify", str(d))
    assert proc.returncode == 1, proc.stderr
    assert "Traceback" not in proc.stderr and "refused dist name" in proc.stderr
    assert not outside.exists()
    assert not outside.is_file()
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    lines = (d / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all("/" not in line and "\\" not in line for line in lines)
    proc = _verify("verify", str(d))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


def test_verify_refuses_an_overlong_digest_line_without_its_tail(tmp_path):
    d = _dist(tmp_path)
    secret = "supersecretvalue12345678"
    blob = (b"a" * 64) + b"  " + (b"n" * 5000) + secret.encode("ascii") + b"\n"
    (d / "SHA256SUMS").write_bytes(blob)
    proc = _verify("verify", str(d))
    assert proc.returncode == 1, proc.stderr
    assert secret not in proc.stderr and "member-sha256=overlong" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert proc.stderr.count("\n") == 1


def test_concurrent_team_template_records_do_not_cross_wires(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    good_root = tmp_path / "good"
    bad_root = tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _dist(good_root, extra=("aegis_core/team_templates/role-registry.json",))
    bad = _dist(bad_root, extra=("aegis_core/team_templatez/x.json",))
    with ThreadPoolExecutor(max_workers=2) as pool:
        good_proc, bad_proc = pool.map(lambda dist: _verify("record", str(dist)), (good, bad))
    assert good_proc.returncode == 0, good_proc.stderr
    assert bad_proc.returncode == 1 and "aegis_core/team_templatez/x.json" in bad_proc.stderr, bad_proc.stderr
    assert (good / "SHA256SUMS").is_file()
    assert not (bad / "SHA256SUMS").exists()


_SPECIAL_TEAM_TEMPLATE_MEMBERS = (
    ("aegis_core/team_templates/escape.json", stat.S_IFLNK | 0o777, "../../../outside"),
    ("aegis_core/team_templates/inside.json", stat.S_IFLNK | 0o777, "role-registry.json"),
    ("aegis_core/team_templates/device.json", stat.S_IFCHR | 0o666, ""),
    ("aegis_core/team_templates/fifo.json", stat.S_IFIFO | 0o666, ""),
    ("aegis_core/team_templates/socket.json", stat.S_IFSOCK | 0o666, ""),
)
_DATA_TEAM_TEMPLATE_MEMBERS = (
    "aegis_core/team_templates/_data/payload.py",
    "aegis_core/team_templates/_data/payload.json",
    "aegis_core/team_templates/roles/_data/payload.py",
    "aegis_core/team_templates/roles/_data/payload.json",
)


@pytest.mark.parametrize("command", ["record", "verify"])
@pytest.mark.parametrize(
    ("name", "mode", "payload"),
    _SPECIAL_TEAM_TEMPLATE_MEMBERS,
    ids=["escape-symlink", "inside-symlink", "device", "fifo", "socket"],
)
def test_special_team_template_members_are_refused(tmp_path, command, name, mode, payload):
    """Archive type comes from metadata. The stored target is not a path we open."""
    d = _dist(tmp_path, typed=((name, mode, payload),))
    if command == "verify":
        _write_sums(d)
    proc = _verify(command, str(d))
    assert proc.returncode == 1, proc.stderr
    assert "unexpected wheel member" in proc.stderr
    assert name in proc.stderr
    assert "Traceback" not in proc.stderr
    if command == "record":
        assert not (d / "SHA256SUMS").exists()


@pytest.mark.parametrize("command", ["record", "verify"])
def test_sdist_hardlink_team_template_member_is_refused(tmp_path, command):
    name = "aegis_core/team_templates/link.json"
    d = _dist(tmp_path, sdist=_hardlink_sdist())
    if command == "verify":
        _write_sums(d)
    proc = _verify(command, str(d))
    assert proc.returncode == 1, proc.stderr
    assert "unexpected" in proc.stderr and "member" in proc.stderr
    assert name in proc.stderr
    assert "Traceback" not in proc.stderr
    if command == "record":
        assert not (d / "SHA256SUMS").exists()


@pytest.mark.parametrize("command", ["record", "verify"])
@pytest.mark.parametrize("name", _DATA_TEAM_TEMPLATE_MEMBERS, ids=[
    "data-py", "data-json", "nested-data-py", "nested-data-json"])
def test_team_template_data_components_are_refused(tmp_path, command, name):
    d = _dist(tmp_path, extra=(name,))
    if command == "verify":
        _write_sums(d)
    proc = _verify(command, str(d))
    assert proc.returncode == 1, proc.stderr
    assert "unexpected wheel member" in proc.stderr
    assert name in proc.stderr
    if command == "record":
        assert not (d / "SHA256SUMS").exists()


@pytest.mark.parametrize("command", ["record", "verify"])
def test_exact_data_asset_is_still_accepted(tmp_path, command):
    d = _dist(tmp_path, extra=("aegis_core/_data/rules/META.md",))
    if command == "verify":
        _write_sums(d)
    proc = _verify(command, str(d))
    assert proc.returncode == 0, proc.stderr
    if command == "verify":
        assert len(proc.stdout.split()) == 2


def test_record_writes_sha256sums_with_lf_only(tmp_path):
    d = _dist(tmp_path, extra=("aegis_core/team_templates/role-registry.json",))
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    data = (d / "SHA256SUMS").read_bytes()
    assert b"\r" not in data
    assert data.endswith(b"\n")
    assert all(not line.endswith(b"\r") for line in data.splitlines(keepends=True))


def test_verify_refuses_crlf_digest_lines(tmp_path):
    d = _dist(tmp_path, extra=("aegis_core/team_templates/role-registry.json",))
    rows = []
    for path in sorted(d.iterdir()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(digest + "  " + path.name)
    (d / "SHA256SUMS").write_bytes(("\r\n".join(rows) + "\r\n").encode("ascii"))
    proc = _verify("verify", str(d))
    assert proc.returncode == 1, proc.stderr
    assert b"\r" in (d / "SHA256SUMS").read_bytes()
    assert "Traceback" not in proc.stderr


def test_special_member_refusal_leaves_digests_unwritten_for_retry(tmp_path):
    rejected_root = tmp_path / "rejected"
    accepted_root = tmp_path / "accepted"
    rejected_root.mkdir()
    accepted_root.mkdir()
    rejected = _dist(rejected_root, typed=((
        "aegis_core/team_templates/escape.json", stat.S_IFLNK | 0o777, "../../../outside"),))
    proc = _verify("record", str(rejected))
    assert proc.returncode == 1 and "escape.json" in proc.stderr, proc.stderr
    assert not (rejected / "SHA256SUMS").exists()
    accepted = _dist(accepted_root, extra=("aegis_core/team_templates/role-registry.json",))
    proc = _verify("record", str(accepted))
    assert proc.returncode == 0, proc.stderr
    assert b"\r" not in (accepted / "SHA256SUMS").read_bytes()
    proc = _verify("verify", str(accepted))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


def test_concurrent_special_member_records_do_not_cross_wires(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    good_root = tmp_path / "good"
    bad_root = tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _dist(good_root, extra=("aegis_core/team_templates/role-registry.json",))
    bad = _dist(bad_root, typed=((
        "aegis_core/team_templates/inside.json", stat.S_IFLNK | 0o777, "role-registry.json"),))
    with ThreadPoolExecutor(max_workers=2) as pool:
        good_proc, bad_proc = pool.map(lambda dist: _verify("record", str(dist)), (good, bad))
    assert good_proc.returncode == 0, good_proc.stderr
    assert bad_proc.returncode == 1 and "inside.json" in bad_proc.stderr, bad_proc.stderr
    assert (good / "SHA256SUMS").is_file()
    assert not (bad / "SHA256SUMS").exists()
    assert b"\r" not in (good / "SHA256SUMS").read_bytes()


# Independent admission table from the round-1c contract. The sdist has no
# whole-tree allowlist, so ordinary source outside a package is permitted.
_ADMISSION_LOCATIONS = {
    "module": ("aegis_core/probe.py", "aegis_core/probe", "child.py"),
    "template": ("aegis_core/team_templates/roles/probe.json", "aegis_core/team_templates/roles", "child.json"),
    "template_suffix": ("aegis_core/team_templates/payload.exe", "aegis_core/team_templates/payload.exe", "child.json"),
    "template_data": ("aegis_core/team_templates/_data/probe.py", "aegis_core/team_templates/_data", "child.py"),
    "nested_data": ("aegis_core/team_templates/roles/_data/probe.json", "aegis_core/team_templates/roles/_data", "child.json"),
    "dist_info": ("aegis_guardrails-0.0.0.dist-info/NOTICE", "aegis_guardrails-0.0.0.dist-info/licenses", "LICENSE"),
    "unknown_info": ("aegis_guardrails-0.0.0.dist-info/extra.txt", "aegis_guardrails-0.0.0.dist-info/extra", "child.py"),
    "outside": ("foreign/probe.py", "foreign/probe", "child.py"),
}
_ADMISSION_TABLE = {
    "wheel": {"module": True, "template": True, "template_suffix": False,
              "template_data": False, "nested_data": False, "dist_info": True,
              "unknown_info": False, "outside": False},
    "sdist": {"module": True, "template": True, "template_suffix": False,
              "template_data": False, "nested_data": False, "dist_info": True,
              "outside": True},
}
_ADMISSION_SHAPES = ("file", "directory", "directory_bytes_no_slash",
                     "regular_with_slash", "directory_bytes", "symlink", "device", "fifo")
_ADMISSION_FORMS = ("plain", "parent", "absolute", "backslash")
_ADMISSION_MATRIX = tuple(
    (kind, location, shape, form)
    for kind, locations in _ADMISSION_TABLE.items()
    for location in locations
    for shape in _ADMISSION_SHAPES + (("hardlink",) if kind == "sdist" else ())
    for form in _ADMISSION_FORMS + (("unicode_path",) if kind == "wheel" else ())
)


def _archive_bytes(kind, entries):
    """Construct metadata in memory; no host symlink or POSIX capability needed."""
    buf = io.BytesIO()
    if kind == "wheel":
        with zipfile.ZipFile(buf, "w") as archive:
            for name in ("__init__.py", "go_ast.go", "go.mod"):
                archive.writestr("aegis_core/ast/drivers/templates/" + name, "")
            archive.writestr("aegis_guardrails-0.0.0.dist-info/METADATA",
                             "Metadata-Version: 2.1\nName: aegis-guardrails\nVersion: 0.0.0\n"
                             "Provides-Extra: dev\n")
            for entry in entries:
                name, mode, payload = entry[:3]
                member = zipfile.ZipInfo(name)
                member.filename = name
                member.create_system = 3
                member.external_attr = mode << 16
                if len(entry) == 4:
                    member.extra = entry[3]
                archive.writestr(member, payload)
    else:
        with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name, mode, payload in [("release/README.md", tarfile.REGTYPE, b"source"), *entries]:
                member = tarfile.TarInfo(name)
                member.type = mode
                member.size = len(payload)
                if mode in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    member.linkname = "../../../outside"
                archive.addfile(member, io.BytesIO(payload))
    return buf.getvalue()


def _admission_dist(tmp_path, kind, entries):
    d = tmp_path / "dist"
    d.mkdir()
    (d / "aegis_governance-0.0.0-py3-none-any.whl").write_bytes(
        _archive_bytes("wheel", entries if kind == "wheel" else []))
    (d / "aegis_governance-0.0.0.tar.gz").write_bytes(
        _archive_bytes("sdist", entries if kind == "sdist" else []))
    return d


def _assert_both_admission_commands(dist, admitted, member=None):
    recorded = _verify("record", str(dist))
    if not admitted:
        assert not (dist / "SHA256SUMS").exists(), recorded.stderr
    _write_sums(dist)
    verified = _verify("verify", str(dist))
    assert recorded.returncode == verified.returncode, (recorded.stderr, verified.stderr)
    for proc in (recorded, verified):
        assert proc.returncode == (0 if admitted else 1), proc.stderr
        if not admitted:
            assert "member" in proc.stderr and "Traceback" not in proc.stderr, proc.stderr
            assert proc.stderr.count("\n") == 1
            if member is not None:
                assert member in proc.stderr


def _admission_entries(kind, location, shape, form):
    file_name, directory, child = _ADMISSION_LOCATIONS[location]
    prefix = "release/" if kind == "sdist" else ""
    directory_shape = shape in ("directory", "directory_bytes_no_slash", "regular_with_slash", "directory_bytes")
    name = prefix + (directory if directory_shape else file_name)
    if shape in ("directory", "regular_with_slash", "directory_bytes"):
        name += "/"
    if form == "parent":
        name = prefix + "../" + name[len(prefix):]
    elif form == "absolute":
        name = "/" + name
    elif form == "backslash":
        name = name.replace("/", "\\", 1)
    zip_types = {"file": stat.S_IFREG, "directory": stat.S_IFDIR,
                 "directory_bytes_no_slash": stat.S_IFDIR, "regular_with_slash": stat.S_IFREG,
                 "directory_bytes": stat.S_IFDIR, "symlink": stat.S_IFLNK,
                 "device": stat.S_IFCHR, "fifo": stat.S_IFIFO}
    tar_types = {"file": tarfile.REGTYPE, "directory": tarfile.DIRTYPE,
                 "directory_bytes_no_slash": tarfile.DIRTYPE, "regular_with_slash": tarfile.REGTYPE,
                 "directory_bytes": tarfile.DIRTYPE, "symlink": tarfile.SYMTYPE,
                 "device": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE, "hardlink": tarfile.LNKTYPE}
    mode = zip_types[shape] if kind == "wheel" else tar_types[shape]
    payload = b"" if shape in ("directory", "regular_with_slash") else b"payload"
    entries = [(name, mode, payload)]
    if form == "unicode_path":
        entries = [(name, mode, payload, _unicode_path_extra(name, name + ".alternate"))]
    if shape == "directory" and form == "plain" and _ADMISSION_TABLE[kind][location]:
        child_type = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
        entries.append((name + child, child_type, b"child"))
    return entries


@pytest.mark.parametrize("kind,location,shape,form", _ADMISSION_MATRIX,
                         ids=["-".join(row) for row in _ADMISSION_MATRIX])
def test_archive_admission_matrix(tmp_path, kind, location, shape, form):
    admitted = (_ADMISSION_TABLE[kind][location] and form == "plain" and
                shape in ("file", "directory"))
    d = _admission_dist(tmp_path, kind, _admission_entries(kind, location, shape, form))
    _assert_both_admission_commands(d, admitted)


_ADMISSION_REVIEW_CASES = (
    ("wheel", "aegis_core/team_templates/payload.exe", stat.S_IFDIR, b"payload"),
    ("sdist", "release/aegis_core/team_templates/../../../../outside.py", tarfile.REGTYPE, b"x"),
    ("sdist", "release/aegis_core/team_templates/payload.exe", tarfile.REGTYPE, b"x"),
    ("wheel", "aegis_core/team_templates/_data/payload.py", stat.S_IFDIR, b"x"),
    ("sdist", "release/aegis_core/team_templates/_data/payload.py", tarfile.REGTYPE, b"x"),
    ("sdist", "release/aegis_core/team_templates/roles/_data/payload.json", tarfile.REGTYPE, b"x"),
    ("sdist", "../../outside", tarfile.DIRTYPE, b""),
    ("sdist", "../../payload.so", tarfile.REGTYPE, b"x"),
    ("sdist", "/tmp/payload.so", tarfile.REGTYPE, b"x"),
    ("sdist", "C:/Windows/payload.exe", tarfile.REGTYPE, b"x"),
    ("sdist", "aegis_core/team_templates/payload.exe", tarfile.REGTYPE, b"x"),
    ("sdist", "aegis_core/team_templates/roles/__pycache__/x.pyc", tarfile.REGTYPE, b"x"),
)


@pytest.mark.parametrize("kind,name,mode,payload", _ADMISSION_REVIEW_CASES,
                         ids=["finding-" + str(i + 1) for i in range(len(_ADMISSION_REVIEW_CASES))])
def test_archive_admission_review_negative_controls(tmp_path, kind, name, mode, payload):
    d = _admission_dist(tmp_path, kind, [(name, mode, payload)])
    _assert_both_admission_commands(d, False, name)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_archive_admission_refuses_stray_directory(tmp_path, kind):
    name = ("release/" if kind == "sdist" else "") + "aegis_core/team_templates/empty/"
    mode = stat.S_IFDIR if kind == "wheel" else tarfile.DIRTYPE
    d = _admission_dist(tmp_path, kind, [(name, mode, b"")])
    _assert_both_admission_commands(d, False, name.rstrip("/"))


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("fragment", ["./probe.json", "roles//probe.json", "cafe\u0301.json",
                                     "bad\nname.json", "bad\rname.json", "bad\u2028name.json",
                                     "bad\u0085name.json", "x" * 4097 + ".json"],
                         ids=["dot", "empty", "nfc", "lf", "cr", "unicode-line", "unicode-next-line", "overlong"])
def test_archive_admission_name_boundaries(tmp_path, kind, fragment):
    name = ("release/" if kind == "sdist" else "") + "aegis_core/team_templates/" + fragment
    mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    d = _admission_dist(tmp_path, kind, [(name, mode, b"{}")])
    _assert_both_admission_commands(d, False)


@pytest.mark.parametrize("name", ["second_root/source.py", "source.py", "release",
                                  "aegis_core/team_templates/role-registry.json",
                                  "team_templates/role-registry.json"])
def test_archive_admission_sdist_requires_one_root(tmp_path, name):
    d = _admission_dist(tmp_path, "sdist", [(name, tarfile.REGTYPE, b"source")])
    _assert_both_admission_commands(d, False, name)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("directory_first", [False, True])
def test_archive_admission_directory_order_and_root(tmp_path, kind, directory_first):
    prefix = "release/" if kind == "sdist" else ""
    parent = prefix + "aegis_core/team_templates/roles"
    file_mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    dir_mode = stat.S_IFDIR if kind == "wheel" else tarfile.DIRTYPE
    entries = [(parent + "/", dir_mode, b""), (parent + "/builder.md", file_mode, b"role")]
    # Include the root itself: tar writers ordinarily omit a directory slash.
    entries.append(("aegis_core/" if kind == "wheel" else "release", dir_mode, b""))
    if not directory_first:
        entries.reverse()
    d = _admission_dist(tmp_path, kind, entries)
    _assert_both_admission_commands(d, True)


@pytest.mark.parametrize("mode", [0, stat.S_IFREG])
def test_archive_admission_zip_file_type_can_be_absent(tmp_path, mode):
    d = _admission_dist(tmp_path, "wheel", [("aegis_core/team_templates/probe.json", mode, b"{}")])
    _assert_both_admission_commands(d, True)


def test_archive_admission_zip_directory_type_can_be_absent(tmp_path):
    d = _admission_dist(tmp_path, "wheel", [
        ("aegis_core/team_templates/roles/", 0, b""),
        ("aegis_core/team_templates/roles/builder.md", stat.S_IFREG, b"role")])
    _assert_both_admission_commands(d, True)


def test_archive_admission_zip_compressed_directory_is_refused(tmp_path):
    d = _admission_dist(tmp_path, "wheel", [
        ("aegis_core/team_templates/roles/builder.md", stat.S_IFREG, b"role")])
    path = next(d.glob("*.whl"))
    with zipfile.ZipFile(path, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo("aegis_core/team_templates/roles/")
        member.external_attr = stat.S_IFDIR << 16
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, b"")
        assert archive.getinfo(member.filename).file_size == 0
        assert archive.getinfo(member.filename).compress_size > 0
    _assert_both_admission_commands(d, False, "aegis_core/team_templates/roles/")


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("directory", [False, True])
def test_archive_admission_exact_asset_exception_requires_a_file(tmp_path, kind, directory):
    name = ("release/" if kind == "sdist" else "") + "aegis_core/_data/rules/META.md"
    mode = (stat.S_IFDIR if directory else stat.S_IFREG) if kind == "wheel" else (
        tarfile.DIRTYPE if directory else tarfile.REGTYPE)
    entries = [(name + ("/" if directory else ""), mode, b"" if directory else b"rules")]
    if directory:
        child_mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
        entries.append((name + "/child.py", child_mode, b"child"))
    d = _admission_dist(tmp_path, kind, entries)
    _assert_both_admission_commands(d, not directory)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_archive_admission_refusal_preserves_existing_sums_then_retries(tmp_path, kind):
    prefix = "release/" if kind == "sdist" else ""
    mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    d = _admission_dist(tmp_path, kind, [(prefix + "aegis_core/team_templates/roles/_data/x.py", mode, b"x")])
    sums = d / "SHA256SUMS"
    sums.write_bytes(b"previous digests\n")
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "member" in proc.stderr, proc.stderr
    assert sums.read_bytes() == b"previous digests\n"
    path = next(d.glob("*.whl" if kind == "wheel" else "*.tar.gz"))
    path.write_bytes(_archive_bytes(kind, [(prefix + "aegis_core/team_templates/roles/builder.md", mode, b"role")]))
    recorded = _verify("record", str(d))
    assert recorded.returncode == 0, recorded.stderr
    verified = _verify("verify", str(d))
    assert verified.returncode == 0, verified.stderr
    assert b"\r" not in sums.read_bytes()


def test_archive_admission_concurrent_sdist_records_do_not_share_ancestry(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    parent = "release/aegis_core/team_templates/roles/"
    good = _admission_dist(good_root, "sdist", [(parent, tarfile.DIRTYPE, b""),
                                              (parent + "builder.md", tarfile.REGTYPE, b"role")])
    bad = _admission_dist(bad_root, "sdist", [(parent, tarfile.DIRTYPE, b"")])
    with ThreadPoolExecutor(max_workers=2) as pool:
        recorded = list(pool.map(lambda dist: _verify("record", str(dist)), (good, bad)))
    assert recorded[0].returncode == 0, recorded[0].stderr
    assert recorded[1].returncode == 1 and "member" in recorded[1].stderr, recorded[1].stderr
    assert not (bad / "SHA256SUMS").exists()
    _write_sums(bad)
    with ThreadPoolExecutor(max_workers=2) as pool:
        verified = list(pool.map(lambda dist: _verify("verify", str(dist)), (good, bad)))
    assert verified[0].returncode == 0, verified[0].stderr
    assert verified[1].returncode == 1 and "member" in verified[1].stderr, verified[1].stderr


def test_archive_admission_bounds_metadata_before_parsing(tmp_path):
    name = "aegis_guardrails-0.0.0.dist-info/METADATA"
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(_archive_bytes("wheel", []))) as source:
        with zipfile.ZipFile(buf, "w") as target:
            for member in source.infolist():
                target.writestr(member, b"x" * ((1 << 20) + 1) if member.filename == name else source.read(member))
    d = _admission_dist(tmp_path, "wheel", [])
    next(d.glob("*.whl")).write_bytes(buf.getvalue())
    _assert_both_admission_commands(d, False, name)


def test_archive_admission_rejects_corrupt_sdist(tmp_path):
    d = _admission_dist(tmp_path, "sdist", [])
    next(d.glob("*.tar.gz")).write_bytes(b"not a tar archive")
    for command in ("record", "verify"):
        if command == "verify":
            _write_sums(d)
        proc = _verify(command, str(d))
        assert proc.returncode == 1, proc.stderr
        assert "invalid sdist" in proc.stderr and "Traceback" not in proc.stderr
        if command == "record":
            assert not (d / "SHA256SUMS").exists()


def test_archive_admission_rejects_duplicate_sdist_members(tmp_path):
    name = "release/aegis_core/team_templates/roles/builder.md"
    d = _admission_dist(tmp_path, "sdist", [(name, tarfile.REGTYPE, b"one"),
                                          (name, tarfile.REGTYPE, b"two")])
    _assert_both_admission_commands(d, False, name)


@pytest.mark.parametrize("name", ["release/README.rst", "release/pyproject.toml",
                                  "release/aegis_guardrails-0.0.0.dist-info/source.txt"])
def test_archive_admission_sdist_other_source_has_no_tree_allowlist(tmp_path, name):
    d = _admission_dist(tmp_path, "sdist", [(name, tarfile.REGTYPE, b"source")])
    _assert_both_admission_commands(d, True)


def test_archive_admission_zip_directory_type_needs_a_slash_even_when_empty(tmp_path):
    name = "aegis_core/team_templates/probe.json"
    d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFDIR, b"")])
    _assert_both_admission_commands(d, False, name)


def _unicode_path_extra(name, alternate, *, version=1, checksum=None):
    encoded = alternate.encode("utf-8")
    checksum = binascii.crc32(name.encode("utf-8")) if checksum is None else checksum
    return struct.pack("<HHBI", 0x7075, 5 + len(encoded), version, checksum) + encoded


def _assert_name_refusal_commands(dist, message):
    """Run both commands even when record unexpectedly accepts the archive."""
    recorded = _verify("record", str(dist))
    written = (dist / "SHA256SUMS").exists()
    _write_sums(dist)
    verified = _verify("verify", str(dist))
    for proc in (recorded, verified):
        assert proc.returncode == 1, proc.stderr
        assert message in proc.stderr, proc.stderr
        assert "Traceback" not in proc.stderr
        assert proc.stderr.count("\n") == 1
    assert not written, recorded.stderr


_ZIP_NAME_ALTERNATES = (
    ("aegis_core/team_templates/probe.json", "aegis_core/team_templates/payload.exe"),
    ("aegis_core/team_templates/probe.json", "aegis_core/team_templates/_data/payload.json"),
    ("aegis_core/team_templates/probe.json", "aegis_core/team_templates/roles/_data/payload.py"),
    ("aegis_core/native.py", "aegis_core/native.so"),
    ("aegis_core/team_templates/probe.json", "../outside.json"),
    ("aegis_core/team_templates/probe.json", "aegis_core/ast/drivers/templates/__init__.py"),
    ("aegis_core/team_templates/probe.json", "aegis_core/team_templates/roles/"),
    ("aegis_core/team_templates/probe.json", "aegis_core/team_templates/probe.json"),
)


@pytest.mark.parametrize("name,alternate", _ZIP_NAME_ALTERNATES,
                         ids=["executable", "data", "nested-data", "native-module", "escape",
                              "duplicate", "directory-shape", "same-name"])
def test_zip_name_unicode_path_records_are_refused(tmp_path, name, alternate):
    d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"{}", _unicode_path_extra(name, alternate))])
    _assert_name_refusal_commands(d, "forbidden wheel member")


@pytest.mark.parametrize("version,checksum", [(0, None), (1, 0)], ids=["ignored-version", "ignored-crc"])
def test_zip_name_ignored_unicode_path_records_are_still_refused(tmp_path, version, checksum):
    name = "aegis_core/team_templates/probe.json"
    extra = _unicode_path_extra(name, name, version=version, checksum=checksum)
    d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"{}", extra)])
    _assert_name_refusal_commands(d, "forbidden wheel member")


@pytest.mark.parametrize("extra", [b"\x75", b"\x75\x70", b"\x75\x70\x00"])
def test_zip_name_truncated_extra_framing_is_refused(tmp_path, extra):
    d = _admission_dist(tmp_path, "wheel", [("aegis_core/probe.py", stat.S_IFREG, b"", extra)])
    _assert_name_refusal_commands(d, "forbidden wheel member")


def test_zip_name_oversized_extra_record_is_invalid(tmp_path):
    extra = struct.pack("<HH", 0xCAFE, 2) + b"x"
    d = _admission_dist(tmp_path, "wheel", [("aegis_core/probe.py", stat.S_IFREG, b"", extra)])
    _assert_name_refusal_commands(d, "invalid wheel")


def test_zip_name_well_formed_unknown_extra_is_allowed(tmp_path):
    extra = struct.pack("<HH", 0xCAFE, 3) + b"xyz"
    d = _admission_dist(tmp_path, "wheel", [("aegis_core/probe.py", stat.S_IFREG, b"", extra)])
    _assert_both_admission_commands(d, True)


def _zip_header_name_bytes(blob, name, replacement, *, local_only=False, flags=None, header_offset=None):
    """Change controlled ZIP header fields without rewriting their spelling."""
    encoded = name.encode("ascii")
    assert len(encoded) == len(replacement)
    data = bytearray(blob)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        offset = archive.getinfo(name).header_offset
    assert data[offset:offset + 4] == b"PK\x03\x04"
    data[offset + 30:offset + 30 + len(encoded)] = replacement
    if flags is not None:
        struct.pack_into("<H", data, offset + 6, flags)
    if not local_only:
        end = data.rfind(b"PK\x05\x06")
        central = struct.unpack_from("<I", data, end + 16)[0]
        while data[central:central + 4] == b"PK\x01\x02":
            length, extra, comment = struct.unpack_from("<HHH", data, central + 28)
            if data[central + 46:central + 46 + length] == encoded:
                data[central + 46:central + 46 + length] = replacement
                if flags is not None:
                    struct.pack_into("<H", data, central + 8, flags)
                if header_offset is not None:
                    struct.pack_into("<I", data, central + 42, header_offset)
            central += 46 + length + extra + comment
    return bytes(data)


@pytest.mark.parametrize("name", ["aegis_core/native.py", "aegis_core/team_templates/probe.json",
                                  "aegis_guardrails-0.0.0.dist-info/NOTICE"],
                         ids=["module", "template", "dist-info-not-metadata"])
def test_zip_local_header_name_must_match_every_member(tmp_path, name):
    d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"payload")])
    path = next(d.glob("*.whl"))
    raw = name.encode("ascii")
    replacement = raw[:-1] + (b"X" if raw[-1:] != b"X" else b"Y")
    path.write_bytes(_zip_header_name_bytes(path.read_bytes(), name, replacement, local_only=True))
    _assert_name_refusal_commands(d, "invalid wheel")


def test_zip_name_zip64_header_offset_overflow_is_a_refusal(tmp_path):
    name = "aegis_core/probe.py"
    extra = struct.pack("<HHQ", 1, 8, 1 << 63)
    d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"module", extra)])
    path = next(d.glob("*.whl"))
    path.write_bytes(_zip_header_name_bytes(path.read_bytes(), name, name.encode("ascii"), header_offset=0xFFFFFFFF))
    _assert_name_refusal_commands(d, "invalid wheel")


def test_zip_name_memory_backed_zip64_offset_is_a_refusal(distribution_verifier, capsys):
    name = "aegis_core/probe.py"
    extra = struct.pack("<HHQ", 1, 8, 1 << 63)
    blob = _archive_bytes("wheel", [(name, stat.S_IFREG, b"module", extra)])
    malformed = _zip_header_name_bytes(blob, name, name.encode("ascii"), header_offset=0xFFFFFFFF)
    with pytest.raises(SystemExit) as error:
        distribution_verifier.check_wheel(io.BytesIO(malformed))
    assert error.value.code == 1
    assert capsys.readouterr().err.startswith("verify_dist: invalid wheel: ")


@pytest.mark.parametrize("name", ["aegis_core\\probe.py", "aegis_core/probe.py\x00hidden.py"],
                         ids=["backslash", "nul"])
def test_tip_archive_spelling_refusal_survives(tmp_path, name):
    d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"module")])
    _assert_name_refusal_commands(d, "forbidden wheel member")


@pytest.mark.parametrize("encoding", ["utf8", "cp437"])
def test_zip_name_decoding_checks_the_installed_spelling(tmp_path, encoding):
    name = "aegis_core/team_templates/caf\u00e9.json"
    if encoding == "utf8":
        d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"{}")])
    else:
        stored = name.replace("\u00e9", "X")
        d = _admission_dist(tmp_path, "wheel", [(stored, stat.S_IFREG, b"{}")])
        path = next(d.glob("*.whl"))
        path.write_bytes(_zip_header_name_bytes(path.read_bytes(), stored, name.encode("cp437"), flags=0))
    with zipfile.ZipFile(next(d.glob("*.whl"))) as archive:
        member = archive.getinfo(name)
        assert member.orig_filename == member.filename == name
    _assert_both_admission_commands(d, True)


@pytest.fixture
def distribution_verifier():
    spec = importlib.util.spec_from_file_location("release_distribution_verifier", VERIFY_DIST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_member_admission_requires_one_name(distribution_verifier, capsys, kind):
    prefix = "release/" if kind == "sdist" else ""
    name = prefix + "aegis_core/team_templates/probe.json"
    other = prefix + "aegis_core/team_templates/other.json"
    state = {"root": None, "names": set(), "ancestors": set(), "templates": set(), "info_roots": set()}
    mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    with pytest.raises(SystemExit) as error:
        distribution_verifier.admit_member(kind, name, other, mode, 0, state)
    assert error.value.code == 1
    assert capsys.readouterr().err == "verify_dist: forbidden " + kind + " member: " + name + "\n"
    assert state == {"root": None, "names": set(), "ancestors": set(), "templates": set(), "info_roots": set()}


def test_tip_duplicate_wheel_refusal_survives(tmp_path):
    name = "aegis_core/probe.py"
    with pytest.warns(UserWarning, match="Duplicate name"):
        d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"one"), (name, stat.S_IFREG, b"two")])
    _assert_name_refusal_commands(d, "duplicate wheel member")


def _wheel_metadata_payload(dist, payload):
    path = next(dist.glob("*.whl"))
    buf = io.BytesIO()
    with zipfile.ZipFile(path) as source:
        with zipfile.ZipFile(buf, "w") as target:
            for member in source.infolist():
                if member.filename.endswith(".dist-info/METADATA"):
                    if payload is not None:
                        target.writestr(member, payload)
                else:
                    target.writestr(member, source.read(member))
    path.write_bytes(buf.getvalue())


@pytest.mark.parametrize("payload", [None, "Name: other\nProvides-Extra: dev\n",
                                     "Name: aegis-guardrails\nProvides-Extra: other\n",
                                     "Name: aegis-guardrails\nProvides-Extra: dev\nRequires-Dist: requests\n"],
                         ids=["missing", "name", "extra", "runtime"])
def test_tip_metadata_refusals_survive(tmp_path, payload):
    d = _admission_dist(tmp_path, "wheel", [("aegis_guardrails-0.0.0.dist-info/NOTICE", stat.S_IFREG, b"license")])
    _wheel_metadata_payload(d, payload)
    _assert_name_refusal_commands(d, "wheel metadata")


def test_tip_invalid_wheel_runtime_error_refusal_survives(tmp_path):
    d = _admission_dist(tmp_path, "wheel", [])
    path = next(d.glob("*.whl"))
    name = "aegis_guardrails-0.0.0.dist-info/METADATA"
    path.write_bytes(_zip_header_name_bytes(path.read_bytes(), name, name.encode("ascii"), flags=1))
    _assert_name_refusal_commands(d, "invalid wheel")


def test_tip_invalid_wheel_oserror_refusal_survives(distribution_verifier, tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        distribution_verifier.check_wheel(tmp_path / "absent.whl")
    assert error.value.code == 1
    assert capsys.readouterr().err.startswith("verify_dist: invalid wheel: ")


def test_tip_missing_digest_refusal_survives(tmp_path):
    d = _admission_dist(tmp_path, "wheel", [])
    proc = _verify("verify", str(d))
    assert proc.returncode == 1
    assert "SHA256SUMS is missing" in proc.stderr and "Traceback" not in proc.stderr


def test_tip_digest_membership_refusal_survives(tmp_path):
    d = _admission_dist(tmp_path, "wheel", [])
    _write_sums(d)
    sums = d / "SHA256SUMS"
    sums.write_bytes(sums.read_bytes().splitlines(keepends=True)[0])
    proc = _verify("verify", str(d))
    assert proc.returncode == 1
    assert "do not match SHA256SUMS" in proc.stderr and "Traceback" not in proc.stderr


def test_tip_multiple_dist_info_roots_refusal_survives(tmp_path):
    d = _admission_dist(tmp_path, "wheel", [("aegis_guardrails-9.9.9.dist-info/WHEEL", stat.S_IFREG, b"wheel")])
    _assert_name_refusal_commands(d, "unexpected wheel member: multiple dist-info directories")


@pytest.mark.parametrize("selection", ["missing-wheel", "missing-sdist", "extra-wheel", "extra-sdist"])
def test_tip_distribution_count_refusal_survives(tmp_path, selection):
    d = _admission_dist(tmp_path, "wheel", [])
    path = next(d.glob("*.whl" if selection.endswith("wheel") else "*.tar.gz"))
    if selection.startswith("missing"):
        path.unlink()
    else:
        (d / ("extra.whl" if selection.endswith("wheel") else "extra.tar.gz")).write_bytes(path.read_bytes())
    _assert_name_refusal_commands(d, "expected exactly one wheel and one sdist")


def test_tip_usage_refusal_survives(tmp_path):
    proc = _verify("unsupported", str(tmp_path))
    assert proc.returncode == 1
    assert proc.stderr == "verify_dist: usage: verify_dist.py record|verify DIST_DIR\n"


_TAR_NAME_STYLES = (
    "pax-path", "pax-global-path", "pax-path-slash", "pax-sparse-name", "gnu-longname",
    "ustar-prefix", "nul-terminated", "utf8", "binary-pax", "surrogateescape",
    "pax-symlink", "pax-hardlink", "gnu-longlink", "old-directory", "directory-slashes",
)


def _tar_name_archive(style, forbidden):
    """Use public tar writers to exercise every reader name-override family."""
    leaf = "payload.exe" if forbidden else "probe.json"
    name = "release/aegis_core/team_templates/" + leaf
    raw = "release/aegis_core/team_templates/raw.json"
    if style in ("gnu-longname", "ustar-prefix"):
        name = "release/aegis_core/team_templates/" + "r" * 110 + "/" + leaf
    if style == "utf8":
        name = "release/aegis_core/team_templates/caf\u00e9/" + leaf
    if style in ("binary-pax", "surrogateescape"):
        name = "release/aegis_core/team_templates/raw\udcff/" + leaf
    member = tarfile.TarInfo(name)
    if style.startswith("pax-") or style == "binary-pax":
        member.name = raw
        if style == "pax-sparse-name":
            member.pax_headers = {"GNU.sparse.name": name}
        elif style != "pax-global-path":
            member.pax_headers = {"path": name + ("/" if style == "pax-path-slash" else "")}
    if style == "nul-terminated":
        member.name = name + "\x00ignored.exe"
    linked = style in ("pax-symlink", "pax-hardlink", "gnu-longlink")
    if linked:
        member.name = raw
        member.type = tarfile.LNKTYPE if style == "pax-hardlink" else tarfile.SYMTYPE
        member.linkname = "../" * 40 + "outside" if forbidden else "roles/" + "r" * 110 + ".json"
        if style != "gnu-longlink":
            member.pax_headers = {"linkpath": member.linkname}
    directory = style in ("old-directory", "directory-slashes")
    if directory:
        member.name = "release/aegis_core/team_templates/roles/" + ("/" if style == "directory-slashes" else "")
        member.type = tarfile.AREGTYPE if style == "old-directory" else tarfile.DIRTYPE
    payload = b"" if directory or linked else b"{}"
    member.size = len(payload)
    archive_format = tarfile.GNU_FORMAT if style.startswith("gnu-") else (
        tarfile.USTAR_FORMAT if style in ("ustar-prefix", "nul-terminated", "surrogateescape", "old-directory", "directory-slashes")
        else tarfile.PAX_FORMAT)
    kwargs = {"pax_headers": {"path": name}} if style == "pax-global-path" else {}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=archive_format,
                      encoding="utf-8", errors="surrogateescape", **kwargs) as archive:
        archive.addfile(member, io.BytesIO(payload))
        if directory:
            child = tarfile.TarInfo("release/aegis_core/team_templates/roles/" + leaf)
            child.size = 2
            archive.addfile(child, io.BytesIO(b"{}"))
    return buf.getvalue()


@pytest.mark.parametrize("style", _TAR_NAME_STYLES)
@pytest.mark.parametrize("forbidden", [False, True], ids=["allowed-name", "forbidden-name"])
def test_tar_name_normalizations_use_the_installed_name(tmp_path, style, forbidden):
    d = _admission_dist(tmp_path, "sdist", [])
    next(d.glob("*.tar.gz")).write_bytes(_tar_name_archive(style, forbidden))
    # binary-pax and surrogateescape install a lone surrogate in one component.
    # The portable grammar refuses that component. The other styles keep the
    # previous outcome: the installed name is admitted only for a regular member.
    surrogate = style in ("binary-pax", "surrogateescape")
    admitted = (not forbidden and not surrogate and
                style not in ("pax-symlink", "pax-hardlink", "gnu-longlink"))
    # stderr encodes a lone surrogate with backslashreplace, so the installed
    # component is the ASCII escape. That escape is absent from the ustar name.
    if surrogate:
        _assert_both_admission_commands(d, False, "\\udcff")
    else:
        _assert_both_admission_commands(d, admitted)


def test_zip_name_refusal_preserves_digests_then_retry_succeeds(tmp_path):
    name = "aegis_core/team_templates/probe.json"
    d = _admission_dist(tmp_path, "wheel", [(name, stat.S_IFREG, b"{}", _unicode_path_extra(name, name))])
    sums = d / "SHA256SUMS"
    sums.write_bytes(b"previous digests\n")
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "forbidden wheel member" in proc.stderr, proc.stderr
    assert sums.read_bytes() == b"previous digests\n"
    next(d.glob("*.whl")).write_bytes(_archive_bytes("wheel", [(name, stat.S_IFREG, b"{}")]))
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    proc = _verify("verify", str(d))
    assert proc.returncode == 0, proc.stderr


def test_zip_name_concurrent_records_do_not_share_validation(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    name = "aegis_core/team_templates/probe.json"
    good = _admission_dist(good_root, "wheel", [(name, stat.S_IFREG, b"{}")])
    bad = _admission_dist(bad_root, "wheel", [(name, stat.S_IFREG, b"{}", _unicode_path_extra(name, name))])
    with ThreadPoolExecutor(max_workers=2) as pool:
        recorded = list(pool.map(lambda dist: _verify("record", str(dist)), (good, bad)))
    assert recorded[0].returncode == 0, recorded[0].stderr
    assert recorded[1].returncode == 1 and "forbidden wheel member" in recorded[1].stderr, recorded[1].stderr
    assert not (bad / "SHA256SUMS").exists()
    _write_sums(bad)
    with ThreadPoolExecutor(max_workers=2) as pool:
        verified = list(pool.map(lambda dist: _verify("verify", str(dist)), (good, bad)))
    assert verified[0].returncode == 0, verified[0].stderr
    assert verified[1].returncode == 1 and "forbidden wheel member" in verified[1].stderr, verified[1].stderr


@pytest.mark.parametrize("kind,name", [
    ("wheel", "aegis_core/team_templates/.. /.. /probe.py"),
    ("sdist", "release/payload.exe."),
    ("sdist", "release/payload.exe "),
], ids=["wheel-parent-spaces", "sdist-executable-dot", "sdist-executable-space"])
def test_member_admission_refuses_windows_component_aliases(distribution_verifier, capsys, tmp_path, kind, name):
    state = {"root": None, "names": set(), "ancestors": set(), "templates": set(), "info_roots": set()}
    mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    with pytest.raises(SystemExit) as error:
        distribution_verifier.admit_member(kind, name, name, mode, 0, state)
    assert error.value.code == 1
    assert capsys.readouterr().err == "verify_dist: forbidden " + kind + " member: " + name + "\n"
    assert state["root"] is None and not state["names"] and not state["ancestors"]
    _assert_both_admission_commands(
        _admission_dist(tmp_path, kind, [(name, mode, b"x")]), False, name)


@pytest.mark.parametrize("kind,good_name,bad_name,mode,pattern", [
    ("wheel", "aegis_core/team_templates/roles/probe.json", "aegis_core/team_templates/roles./probe.json",
     stat.S_IFREG, "*.whl"),
    ("sdist", "release/notes.txt", "release/notes.txt ", tarfile.REGTYPE, "*.tar.gz"),
], ids=["wheel-directory-dot", "sdist-leaf-space"])
def test_dist_component_refusal_isolated_and_retryable(tmp_path, kind, good_name, bad_name, mode, pattern):
    from concurrent.futures import ThreadPoolExecutor

    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _admission_dist(good_root, kind, [(good_name, mode, b"notes")])
    bad = _admission_dist(bad_root, kind, [(bad_name, mode, b"notes")])
    assert _verify("record", str(good)).returncode == 0
    _write_sums(bad)
    previous_sums = (bad / "SHA256SUMS").read_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for command in ("record", "verify"):
            accepted, refused = pool.map(lambda dist: _verify(command, str(dist)), (good, bad))
            assert accepted.returncode == 0, accepted.stderr
            assert refused.returncode == 1, refused.stderr
            assert refused.stderr.startswith("verify_dist: forbidden " + kind + " member: ")
            assert (bad / "SHA256SUMS").read_bytes() == previous_sums
    next(bad.glob(pattern)).write_bytes(next(good.glob(pattern)).read_bytes())
    for command in ("record", "verify"):
        retried = _verify(command, str(bad))
        assert retried.returncode == 0, retried.stderr


@pytest.mark.parametrize("kind,filename", [("wheel", "pkg.WHL"), ("sdist", "pkg.TAR.GZ")])
def test_verify_checks_discovered_uppercase_artifacts(tmp_path, kind, filename):
    from concurrent.futures import ThreadPoolExecutor

    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _admission_dist(good_root, "wheel", [])
    bad = _admission_dist(bad_root, "wheel", [])
    for dist in (good, bad):
        next(dist.glob("*.whl")).rename(dist / "pkg.WHL")
        next(dist.glob("*.tar.gz")).rename(dist / "pkg.TAR.GZ")
    (bad / filename).write_bytes(b"not an archive")
    for dist in (good, bad):
        _write_sums(dist)
    preserved = (bad / "SHA256SUMS").read_bytes()

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted, refused = pool.map(lambda dist: _verify("verify", str(dist)), (good, bad))
    assert accepted.returncode == 0, accepted.stderr
    assert refused.returncode == 1, refused.stderr
    assert refused.stderr.startswith("verify_dist: invalid " + kind + ": ")
    assert "Traceback" not in refused.stderr
    assert {str(good / "pkg.WHL"), str(good / "pkg.TAR.GZ")} <= set(accepted.stdout.splitlines())
    assert (bad / "SHA256SUMS").read_bytes() == preserved

    (bad / filename).write_bytes((good / filename).read_bytes())
    recorded = _verify("record", str(bad))
    assert recorded.returncode == 0, recorded.stderr
    verified = _verify("verify", str(bad))
    assert verified.returncode == 0, verified.stderr
    assert set(verified.stdout.splitlines()) == {str(bad / "pkg.WHL"), str(bad / "pkg.TAR.GZ")}


def _tar_bytes(entries):
    """Sdist bytes with an explicit permission mode on each added member."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, typ, payload, perm in [("release/README.md", tarfile.REGTYPE, b"source", 0o644), *entries]:
            member = tarfile.TarInfo(name)
            member.type = typ
            member.size = len(payload)
            member.mode = perm
            archive.addfile(member, io.BytesIO(payload))
    return buf.getvalue()


_PORTABLE_REVIEW_MEMBERS = (
    ("sdist", "release/probe.exe::$DATA", tarfile.REGTYPE, b"x"),
    ("wheel", "aegis_core/probe.exe::$DATA", stat.S_IFREG, b"x"),
    ("sdist", "release/aegis_core/TEAM_TEMPLATES/probe.cmd", tarfile.REGTYPE, b"x"),
    ("wheel", "aegis_core/TEAM_TEMPLATES/probe.cmd", stat.S_IFREG, b"x"),
    ("sdist", "release/aegis_core/_DATA/payload.py", tarfile.REGTYPE, b"x"),
    ("wheel", "aegis_core/_DATA/payload.py", stat.S_IFREG, b"x"),
    ("wheel", "aegis_core/_DATA/rules/META.md", stat.S_IFREG, b"x"),
    ("sdist", "release/CON", tarfile.REGTYPE, b"x"),
    ("wheel", "aegis_core/team_templates/NUL.json", stat.S_IFREG, b"x"),
    ("sdist", "release/AUX.txt", tarfile.REGTYPE, b"x"),
    ("wheel", "aegis_core/PRN.py", stat.S_IFREG, b"x"),
    ("sdist", "release/COM1.json", tarfile.REGTYPE, b"x"),
    ("wheel", "aegis_core/LPT9.py", stat.S_IFREG, b"x"),
    ("sdist", "release/con.txt", tarfile.REGTYPE, b"x"),
)


def _portable_case_id(name):
    """Node ids stay free of slash and colon so a host rerun can select them."""
    return "".join(char if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
                   else "-" for char in name)


@pytest.mark.parametrize("kind,name,mode,payload", _PORTABLE_REVIEW_MEMBERS,
                         ids=[_portable_case_id(row[1]) for row in _PORTABLE_REVIEW_MEMBERS])
def test_portable_member_grammar_refuses_review_spellings(tmp_path, kind, name, mode, payload):
    d = _admission_dist(tmp_path, kind, [(name, mode, payload)])
    _assert_both_admission_commands(d, False, name)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_casefolded_destination_collision_is_refused(tmp_path, kind):
    from concurrent.futures import ThreadPoolExecutor

    prefix = "release/" if kind == "sdist" else ""
    mode = tarfile.REGTYPE if kind == "sdist" else stat.S_IFREG
    first = prefix + "aegis_core/team_templates/roles/probe.json"
    second = prefix + "aegis_core/team_templates/ROLES/probe.json"
    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _admission_dist(good_root, kind, [(first, mode, b"{}")])
    bad = _admission_dist(bad_root, kind, [(first, mode, b"{}"), (second, mode, b"{}")])
    assert _verify("record", str(good)).returncode == 0
    _write_sums(bad)
    preserved = (bad / "SHA256SUMS").read_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for command in ("record", "verify"):
            accepted, refused = pool.map(lambda dist: _verify(command, str(dist)), (good, bad))
            assert accepted.returncode == 0, accepted.stderr
            assert refused.returncode == 1, refused.stderr
            assert "duplicate " + kind + " member" in refused.stderr
            assert second in refused.stderr and "Traceback" not in refused.stderr
            assert (bad / "SHA256SUMS").read_bytes() == preserved
    next(bad.glob("*.whl" if kind == "wheel" else "*.tar.gz")).write_bytes(
        next(good.glob("*.whl" if kind == "wheel" else "*.tar.gz")).read_bytes())
    for command in ("record", "verify"):
        retried = _verify(command, str(bad))
        assert retried.returncode == 0, retried.stderr


def test_team_template_execute_bit_is_refused_then_retries(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    wheel_name = "aegis_core/team_templates/probe.json"
    tar_name = "release/aegis_core/team_templates/probe.json"
    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _admission_dist(good_root, "wheel", [(wheel_name, stat.S_IFREG | 0o644, b"{}")])
    good_tar = _tar_bytes([(tar_name, tarfile.REGTYPE, b"{}", 0o644)])
    next(good.glob("*.tar.gz")).write_bytes(good_tar)
    bad = _admission_dist(bad_root, "wheel", [(wheel_name, stat.S_IFREG | 0o755, b"{}")])
    bad_tar = _tar_bytes([(tar_name, tarfile.REGTYPE, b"{}", 0o755)])
    next(bad.glob("*.tar.gz")).write_bytes(bad_tar)
    accepted_record = _verify("record", str(good))
    assert accepted_record.returncode == 0, accepted_record.stderr
    # A second record of the same bytes must stay clean.
    assert _verify("record", str(good)).returncode == 0
    refused = _verify("record", str(bad))
    assert refused.returncode == 1 and "unexpected" in refused.stderr and wheel_name in refused.stderr
    assert "Traceback" not in refused.stderr
    assert not (bad / "SHA256SUMS").exists()
    _write_sums(bad)
    preserved = (bad / "SHA256SUMS").read_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted, denied = pool.map(lambda dist: _verify("verify", str(dist)), (good, bad))
    assert accepted.returncode == 0, accepted.stderr
    assert denied.returncode == 1 and (tar_name in denied.stderr or wheel_name in denied.stderr)
    assert "Traceback" not in denied.stderr
    assert (bad / "SHA256SUMS").read_bytes() == preserved
    next(bad.glob("*.whl")).write_bytes(next(good.glob("*.whl")).read_bytes())
    next(bad.glob("*.tar.gz")).write_bytes(next(good.glob("*.tar.gz")).read_bytes())
    assert _verify("record", str(bad)).returncode == 0
    assert _verify("verify", str(bad)).returncode == 0


def _plant_dist_decoy(dist, kind):
    if kind == "wheel-dir":
        nested = dist / "extra.whl"
        nested.mkdir()
        (nested / "unchecked.whl").write_bytes(b"unchecked")
    elif kind == "sdist-dir":
        (dist / "extra.tar.gz").mkdir()
    elif kind == "wheel-dot":
        (dist / ".hidden.whl").write_bytes(b"hidden wheel")
    elif kind == "sdist-dot":
        (dist / ".hidden.tar.gz").write_bytes(b"hidden sdist")
    else:
        raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["wheel-dir", "sdist-dir", "wheel-dot", "sdist-dot"])
def test_dist_discovery_refuses_extra_archive_entries(tmp_path, kind):
    from concurrent.futures import ThreadPoolExecutor

    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _admission_dist(good_root, "wheel", [])
    bad = _admission_dist(bad_root, "wheel", [])
    marker = ".hidden" if "dot" in kind else "extra"
    assert _verify("record", str(good)).returncode == 0
    # Sums describe the valid pair. The decoy arrives afterwards, as a
    # directory or dotfile planted beside an already recorded dist/.
    _write_sums(bad)
    _plant_dist_decoy(bad, kind)
    preserved = (bad / "SHA256SUMS").read_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for command in ("record", "verify"):
            accepted, refused = pool.map(lambda dist: _verify(command, str(dist)), (good, bad))
            assert accepted.returncode == 0, accepted.stderr
            assert refused.returncode == 1, refused.stderr
            assert "expected exactly one wheel and one sdist" in refused.stderr
            assert marker in refused.stderr and "Traceback" not in refused.stderr
            assert (bad / "SHA256SUMS").read_bytes() == preserved
    if kind == "wheel-dir":
        (bad / "extra.whl").joinpath("unchecked.whl").unlink()
        (bad / "extra.whl").rmdir()
    elif kind == "sdist-dir":
        (bad / "extra.tar.gz").rmdir()
    elif kind == "wheel-dot":
        (bad / ".hidden.whl").unlink()
    else:
        (bad / ".hidden.tar.gz").unlink()
    for command in ("record", "verify"):
        retried = _verify(command, str(bad))
        assert retried.returncode == 0, retried.stderr


def test_dist_discovery_refuses_archive_symlinks(tmp_path):
    from conftest import symlink_or_skip

    dist = _admission_dist(tmp_path, "wheel", [])
    _write_sums(dist)
    payload = tmp_path / "payload"
    payload.mkdir()
    symlink_or_skip(payload, dist / "extra.whl", target_is_directory=True)
    symlink_or_skip(payload, dist / "extra.tar.gz", target_is_directory=True)
    preserved = (dist / "SHA256SUMS").read_bytes()
    for command in ("record", "verify"):
        refused = _verify(command, str(dist))
        assert refused.returncode == 1, refused.stderr
        assert "extra.whl" in refused.stderr and "extra.tar.gz" in refused.stderr
        assert "Traceback" not in refused.stderr
        assert (dist / "SHA256SUMS").read_bytes() == preserved


def test_archive_entry_probe_counts_a_symlink_without_following(distribution_verifier):
    class _Symlink:
        def is_symlink(self):
            return True

        def is_file(self, follow_symlinks=True):
            return True

    class _Other:
        def is_symlink(self):
            raise OSError("unsupported")

        def is_file(self, follow_symlinks=True):
            raise OSError("unsupported")

    assert distribution_verifier._entry_kind(_Symlink()) == "symlink"
    assert distribution_verifier._entry_kind(_Other()) == "other"


def test_record_step_precedes_attestation_without_continue_on_error():
    steps = _load("validate.yml")["jobs"]["build-wheel"]["steps"]
    record = next(i for i, step in enumerate(steps) if "verify_dist.py record" in step.get("run", ""))
    attest = next(i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("actions/attest"))
    assert record < attest
    assert "continue-on-error" not in steps[record]


# Each component of aegis_core/ast/drivers/templates, and every combination.
_AST_TEMPLATE_CASE_VARIANTS = (
    ("AST", "drivers", "templates"),
    ("ast", "DRIVERS", "templates"),
    ("ast", "drivers", "TEMPLATES"),
    ("AST", "DRIVERS", "templates"),
    ("AST", "drivers", "TEMPLATES"),
    ("ast", "DRIVERS", "TEMPLATES"),
    ("AST", "DRIVERS", "TEMPLATES"),
)


def _ast_case_member(kind, ast_name, drivers_name, templates_name):
    logical = "aegis_core/" + "/".join((ast_name, drivers_name, templates_name)) + "/extra.py"
    if kind == "sdist":
        return "release/" + logical
    return logical


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("ast_name,drivers_name,templates_name", _AST_TEMPLATE_CASE_VARIANTS,
                         ids=["-".join(row) for row in _AST_TEMPLATE_CASE_VARIANTS])
def test_protected_prefix_refuses_noncanonical_ast_template_spellings(
        tmp_path, kind, ast_name, drivers_name, templates_name):
    name = _ast_case_member(kind, ast_name, drivers_name, templates_name)
    mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    d = _admission_dist(tmp_path, kind, [(name, mode, b"code")])
    _assert_both_admission_commands(d, False, name)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_protected_prefix_refusal_retries_and_stays_isolated(tmp_path, kind):
    from concurrent.futures import ThreadPoolExecutor

    name = _ast_case_member(kind, "AST", "DRIVERS", "TEMPLATES")
    mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _admission_dist(good_root, kind, [])
    bad = _admission_dist(bad_root, kind, [(name, mode, b"code")])
    accepted_record = _verify("record", str(good))
    assert accepted_record.returncode == 0, accepted_record.stderr
    _write_sums(bad)
    preserved = (bad / "SHA256SUMS").read_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for command in ("record", "verify"):
            accepted, refused = pool.map(
                lambda dist, command=command: _verify(command, str(dist)), (good, bad))
            assert accepted.returncode == 0, accepted.stderr
            assert refused.returncode == 1, refused.stderr
            assert "forbidden" in refused.stderr and name in refused.stderr
            assert "Traceback" not in refused.stderr
            assert (bad / "SHA256SUMS").read_bytes() == preserved
    pattern = "*.whl" if kind == "wheel" else "*.tar.gz"
    next(bad.glob(pattern)).write_bytes(next(good.glob(pattern)).read_bytes())
    for command in ("record", "verify"):
        retried = _verify(command, str(bad))
        assert retried.returncode == 0, retried.stderr


def test_build_runs_the_source_and_offline_go_gate_before_building():
    steps = _load("validate.yml")["jobs"]["build-wheel"]["steps"]
    gate = [i for i, step in enumerate(steps) if "check_zero_dependencies.py" in step.get("run", "")]
    assert len(gate) == 1
    assert gate[0] < next(i for i, step in enumerate(steps) if "python -m build" in step.get("run", ""))
    run = steps[gate[0]]["run"]
    assert "check_zero_dependencies.py source ." in run and "check_zero_dependencies.py go ." in run
    assert "continue-on-error" not in steps[gate[0]] and "||" not in run


def test_wheel_smoke_refuses_when_source_can_shadow_site_packages():
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    proc = subprocess.run([sys.executable, "-I", SMOKE], capture_output=True,
                          text=True, timeout=60, env=env)
    assert proc.returncode == 1 and "PYTHONPATH" in proc.stderr
    env.pop("PYTHONPATH")
    proc = subprocess.run([sys.executable, SMOKE], capture_output=True,
                          text=True, timeout=60, env=env, cwd=REPO_ROOT)
    assert proc.returncode == 1 and "-I" in proc.stderr


def _namespace_entries(kind, rows):
    """Archive members for one per-parent namespace case. No host symlinks."""
    prefix = "release/" if kind == "sdist" else ""
    file_mode = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    dir_mode = stat.S_IFDIR if kind == "wheel" else tarfile.DIRTYPE
    entries = []
    for path, shape in rows:
        directory = shape == "directory"
        name = prefix + path
        if directory and not name.endswith("/"):
            name += "/"
        payload = b"" if directory else b"payload"
        entries.append((name, dir_mode if directory else file_mode, payload))
    return entries


def _namespace_shown(kind, path, shape):
    """The name verify_dist echoes. Zip keeps one directory slash; tar does not."""
    name = ("release/" if kind == "sdist" else "") + path
    if shape == "directory" and kind == "wheel" and not name.endswith("/"):
        name += "/"
    return name


def _assert_namespace_message(dist, message):
    """Both release commands refuse with one canonical line and do not write sums."""
    recorded = _verify("record", str(dist))
    assert not (dist / "SHA256SUMS").exists(), recorded.stderr
    _write_sums(dist)
    verified = _verify("verify", str(dist))
    expected = "verify_dist: " + message + "\n"
    assert recorded.returncode == 1 and recorded.stderr == expected, recorded.stderr
    assert verified.returncode == 1 and verified.stderr == expected, verified.stderr
    assert "Traceback" not in recorded.stderr


def _component_file_conflict_cases():
    """Pairs whose full folded paths differ. The collision is one component."""
    rows = (
        ("spelling", "aegis_core/Foo/a.py", "aegis_core/foo/b.py", ("wheel", "sdist")),
        ("kind", "aegis_core/foo.py", "aegis_core/foo.py/bar.py", ("wheel", "sdist")),
        ("kind-case", "aegis_core/Foo.py", "aegis_core/foo.py/bar.py", ("wheel", "sdist")),
        ("deep", "aegis_core/foo/Bar/a.py", "aegis_core/foo/bar/b.py", ("wheel", "sdist")),
        ("template", "aegis_core/team_templates/Roles/a.json",
         "aegis_core/team_templates/roles/b.json", ("wheel", "sdist")),
        ("sdist-tree", "guide/Foo/a.txt", "guide/foo/b.txt", ("sdist",)),
    )
    cases = []
    ids = []
    for label, left, right, kinds in rows:
        for kind in kinds:
            cases.append((kind, left, right))
            ids.append(kind + "-" + label)
    return tuple(cases), tuple(ids)


_COMPONENT_FILE_CONFLICTS, _COMPONENT_FILE_CONFLICT_IDS = _component_file_conflict_cases()


@pytest.mark.parametrize("kind,left,right", _COMPONENT_FILE_CONFLICTS, ids=_COMPONENT_FILE_CONFLICT_IDS)
def test_per_parent_namespace_refuses_conflicting_files(tmp_path, kind, left, right):
    """Each parent has one spelling and one kind, in either member order."""
    for index, (first, second) in enumerate(((left, right), (right, left))):
        root = tmp_path / str(index)
        root.mkdir()
        rows = ((first, "file"), (second, "file"))
        shown = _namespace_shown(kind, second, "file")
        dist = _admission_dist(root, kind, _namespace_entries(kind, rows))
        _assert_namespace_message(dist, "duplicate " + kind + " member: " + shown)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("order", ["file-first", "directory-first"])
def test_per_parent_namespace_refuses_explicit_directory_spelling(tmp_path, kind, order):
    file_row = ("aegis_core/team_templates/roles/probe.json", "file")
    dir_row = ("aegis_core/team_templates/Roles", "directory")
    rows = (file_row, dir_row) if order == "file-first" else (dir_row, file_row)
    shown = _namespace_shown(kind, dir_row[0], "directory")
    dist = _admission_dist(tmp_path, kind, _namespace_entries(kind, rows))
    _assert_namespace_message(dist, "duplicate " + kind + " member: " + shown)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("order", ["parent-first", "child-first"])
def test_per_parent_namespace_requires_directory_descendant(tmp_path, kind, order):
    parent = ("aegis_core/team_templates/roles", "directory")
    child = ("aegis_core/team_templates/roles/sub", "directory")
    rows = (parent, child) if order == "parent-first" else (child, parent)
    shown = _namespace_shown(kind, rows[0][0], "directory")
    dist = _admission_dist(tmp_path, kind, _namespace_entries(kind, rows))
    _assert_namespace_message(dist, "unexpected " + kind + " member: " + shown)


def _component_accept_cases():
    rows = (
        ("siblings", (
            ("aegis_core/foo/a.py", "file"),
            ("aegis_core/foo/b.py", "file"),
        ), ("wheel", "sdist")),
        ("explicit-dir", (
            ("aegis_core/foo/a.py", "file"),
            ("aegis_core/foo", "directory"),
        ), ("wheel", "sdist")),
        ("template-dir", (
            ("aegis_core/team_templates/roles/probe.json", "file"),
            ("aegis_core/team_templates/roles", "directory"),
        ), ("wheel", "sdist")),
        ("nested", (
            ("aegis_core/team_templates/roles/sub/probe.json", "file"),
            ("aegis_core/team_templates/roles", "directory"),
            ("aegis_core/team_templates/roles/sub", "directory"),
        ), ("wheel", "sdist")),
        ("sdist-siblings", (
            ("guide/foo/a.txt", "file"),
            ("guide/foo/b.txt", "file"),
        ), ("sdist",)),
    )
    cases = []
    ids = []
    for label, tree, kinds in rows:
        for kind in kinds:
            cases.append((kind, tree))
            ids.append(kind + "-" + label)
    return tuple(cases), tuple(ids)


_COMPONENT_ACCEPT_CASES, _COMPONENT_ACCEPT_IDS = _component_accept_cases()


@pytest.mark.parametrize("kind,tree", _COMPONENT_ACCEPT_CASES, ids=_COMPONENT_ACCEPT_IDS)
def test_per_parent_namespace_accepts_consistent_members(tmp_path, kind, tree):
    """Implicit parents, explicit directories and every member order both install."""
    import itertools

    for index, ordered in enumerate(itertools.permutations(tree)):
        root = tmp_path / str(index)
        root.mkdir()
        dist = _admission_dist(root, kind, _namespace_entries(kind, ordered))
        _assert_both_admission_commands(dist, True)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_per_parent_namespace_retries_and_stays_isolated(tmp_path, kind):
    from concurrent.futures import ThreadPoolExecutor

    good_root, bad_root = tmp_path / "good", tmp_path / "bad"
    good_root.mkdir()
    bad_root.mkdir()
    good = _admission_dist(good_root, kind, _namespace_entries(kind, (
        ("aegis_core/foo/a.py", "file"),)))
    bad = _admission_dist(bad_root, kind, _namespace_entries(kind, (
        ("aegis_core/foo/a.py", "file"),
        ("aegis_core/Foo/b.py", "file"),
    )))
    shown = _namespace_shown(kind, "aegis_core/Foo/b.py", "file")
    expected = "verify_dist: duplicate " + kind + " member: " + shown + "\n"
    assert _verify("record", str(good)).returncode == 0
    assert _verify("record", str(good)).returncode == 0
    _write_sums(bad)
    preserved = (bad / "SHA256SUMS").read_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for command in ("record", "verify"):
            accepted, refused = pool.map(
                lambda dist, command=command: _verify(command, str(dist)), (good, bad))
            assert accepted.returncode == 0, accepted.stderr
            assert refused.returncode == 1 and refused.stderr == expected, refused.stderr
            assert "Traceback" not in refused.stderr
            assert (bad / "SHA256SUMS").read_bytes() == preserved
    pattern = "*.whl" if kind == "wheel" else "*.tar.gz"
    next(bad.glob(pattern)).write_bytes(next(good.glob(pattern)).read_bytes())
    for command in ("record", "verify"):
        retried = _verify(command, str(bad))
        assert retried.returncode == 0, retried.stderr


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_component_index_records_spelling_kind_and_explicit_state(distribution_verifier, kind):
    prefix = "release/" if kind == "sdist" else ""
    file_type = stat.S_IFREG if kind == "wheel" else tarfile.REGTYPE
    dir_type = stat.S_IFDIR if kind == "wheel" else tarfile.DIRTYPE
    file_name = prefix + "aegis_core/team_templates/roles/probe.json"
    other_name = prefix + "aegis_core/team_templates/roles/other.json"
    dir_name = prefix + "aegis_core/team_templates/roles" + ("/" if kind == "wheel" else "")
    state = distribution_verifier._admission_state()
    assert distribution_verifier.admit_member(
        kind, file_name, file_name, file_type, 2, state, mode=0o644) == "admitted"
    parent = distribution_verifier._fold_key(prefix + "aegis_core/team_templates")
    assert state["components"][parent]["roles"] == ("roles", "directory", False)
    assert distribution_verifier.admit_member(
        kind, other_name, other_name, file_type, 2, state, mode=0o644) == "admitted"
    assert state["components"][parent]["roles"] == ("roles", "directory", False)
    assert distribution_verifier.admit_member(
        kind, dir_name, dir_name, dir_type, 0, state, mode=0) == "admitted"
    assert state["components"][parent]["roles"] == ("roles", "directory", True)
    leaf_parent = distribution_verifier._fold_key(prefix + "aegis_core/team_templates/roles")
    assert state["components"][leaf_parent]["probe.json"] == ("probe.json", "file", False)
    root_part = "release" if kind == "sdist" else "aegis_core"
    assert state["components"][""][distribution_verifier._fold_part(root_part)] == (
        root_part, "directory", False)


@pytest.mark.parametrize("first,second", [
    ("aegis_core/foo.py", "aegis_core/foo.py/bar.py"),
    ("aegis_core/Foo/a.py", "aegis_core/foo/b.py"),
], ids=["kind-conflict", "spelling-conflict"])
def test_component_conflict_does_not_mutate_admission_state(
        distribution_verifier, capsys, first, second):
    import copy

    state = distribution_verifier._admission_state()
    assert distribution_verifier.admit_member(
        "wheel", first, first, stat.S_IFREG, 1, state, mode=0o644) == "admitted"
    snapshot = copy.deepcopy(state)
    with pytest.raises(SystemExit) as error:
        distribution_verifier.admit_member(
            "wheel", second, second, stat.S_IFREG, 1, state, mode=0o644)
    assert error.value.code == 1
    assert state == snapshot
    assert capsys.readouterr().err == "verify_dist: duplicate wheel member: " + second + "\n"


def test_component_index_threads_do_not_share_state(distribution_verifier):
    from concurrent.futures import ThreadPoolExecutor

    def walk(pair):
        first, second = pair
        state = distribution_verifier._admission_state()
        admitted = distribution_verifier.admit_member(
            "wheel", first, first, stat.S_IFREG, 1, state, mode=0o644)
        try:
            distribution_verifier.admit_member(
                "wheel", second, second, stat.S_IFREG, 1, state, mode=0o644)
        except SystemExit as error:
            return admitted, error.code, set(state["names"])
        return admitted, 0, set(state["names"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        good, bad = pool.map(walk, (
            ("aegis_core/foo/a.py", "aegis_core/foo/b.py"),
            ("aegis_core/Foo/a.py", "aegis_core/foo/b.py"),
        ))
    assert good == ("admitted", 0, {"aegis_core/foo/a.py", "aegis_core/foo/b.py"})
    assert bad[0] == "admitted" and bad[1] == 1
    assert bad[2] == {"aegis_core/Foo/a.py"}


def test_explicit_directory_missing_descendant_is_refused(distribution_verifier, capsys):
    state = {"components": {"": {"roles": ("roles", "directory", True)}}}
    with pytest.raises(SystemExit) as error:
        distribution_verifier._refuse_orphan_directories("wheel", state)
    assert error.value.code == 1
    assert capsys.readouterr().err == "verify_dist: unexpected wheel member: directory\n"
    state["components"]["roles"] = {"probe.json": ("probe.json", "file", False)}
    distribution_verifier._refuse_orphan_directories("sdist", state)
    assert capsys.readouterr().err == ""
    distribution_verifier._refuse_orphan_directories("wheel", {"components": {}})
