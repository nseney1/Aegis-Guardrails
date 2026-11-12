from pathlib import Path
"""Release-integrity regression tests (v0.89 audit fixes).

v0.89.0 reused one build artifact but (a) ran every test from the checkout,
where ``pythonpath = ["."]`` lets source modules shadow the installed wheel,
(b) installed only ``ls dist/*.whl | head -n 1``, and (c) published
``dist/*`` — including an sdist that was never tested — with no digest check.
"""
import os
import ast
import contextlib
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
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


def _dist(tmp_path, extra=(), metadata=""):
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
    (d / "aegis_governance-0.0.0.tar.gz").write_bytes(b"sdist bytes")
    return d


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
            "aegis_report_outcome", "aegis_scan", "aegis_team_config", "aegis_team_model",
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
    "non-dict", "nameless", "non-string", "whitespace-name", "zero-width-name", "fullwidth-name", "empty-name", "long-name"])
def test_wheel_smoke_checks_mcp_names(wheel_smoke, monkeypatch, tmp_path, capsys, change):
    from aegis_mcp.registry import TOOL_DEFINITIONS

    names = sorted(tool["name"] for tool in TOOL_DEFINITIONS)
    missing = [names.pop()] if change in ("missing", "substituted") else []
    unexpected = ["aegis_unexpected"] if change in ("unexpected", "substituted") else []
    duplicates = ["aegis_scan"] if change == "duplicate" else []
    tools = [{"name": name} for name in reversed(names + unexpected)] + [{"name": name} for name in duplicates]
    invalid = {"non-dict": None, "nameless": {}, "non-string": {"name": 7}}
    invalid_names = {"whitespace-name": "aegis_scan ", "zero-width-name": "aegis_scan\u200b",
                     "fullwidth-name": "\uff41egis_scan", "empty-name": "", "long-name": "a" * 129}
    if change in invalid:
        tools.append(invalid[change])
    if change in invalid_names:
        tools.append({"name": invalid_names[change]})
    frames = [{}, {"result": {"tools": tools}},
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
    if change in invalid:
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
    assert capsys.readouterr().err == f"wheel smoke FAILED: MCP tools/list {reason}\n"


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
    "aegis_report_outcome", "aegis_scan", "aegis_team_config", "aegis_team_model", "[A-Za-z0-9_.-]{1,128}", "True", "False")
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
