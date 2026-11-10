"""Every legacy role keeps the exact profile it had before the role registry existed.

The golden file was generated from the hard-coded role rules at 2fc3bee, before provisioning and the
mailbox adapter read tools/hierarchy_templates/role-registry.json. A difference here means an existing
role gained or lost a tool, a sandbox setting or an option, which the registry move must never do.

M1 item 2 regenerated it once, after checking that the only difference was the new read-only mailbox_self
tool in every mailbox role's allowlist and Codex enabled_tools. M1 item 9 inserted multi_agent_v2 after multi_agent
in every Codex disabled_features list and --disable pair, and changed nothing else.

PR259's registry enforcement now refuses the front door's former Read override: that role does not read source.
The archived golden remains unchanged; the expected successor explicitly names this capability correction.
Runtime provenance adds an exact retained-bootstrap envelope around every old MCP command, including the inline
Codex config. Only the expected snapshot gets that reviewed envelope; actual settings and argv remain exact.
The MCP interpreter follows the provision record; the archived golden keeps its historical path.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT
from tests.integration.test_hierarchy_provision import PROVISION, Setup


pytestmark = pytest.mark.skipif(os.name == "nt", reason="generated profiles and wakes are POSIX only")
GOLDEN = ROOT / "tests" / "fixtures" / "hierarchy_role_profiles.json"
ENDPOINTS = ["pilot/front-door", "pilot/orchestrator", "pilot/root", "pilot/lane/f2", "pilot/lane/integration",
             "pilot/lane/review"]
# Fixed sessions, so the snapshot does not depend on generated identifiers.
SESSIONS = {endpoint: str(uuid.UUID(int=index + 1)) for index, endpoint in enumerate(ENDPOINTS)}


def normalized(value, tmp):
    if isinstance(value, dict):
        return {key: normalized(item, tmp) for key, item in value.items()}
    if isinstance(value, list):
        return [normalized(item, tmp) for item in value]
    if isinstance(value, str):
        return value.replace(str(tmp), "<tmp>")
    return value


def with_runtime_bootstrap(value, python):
    """The reviewed successor of the historical expected commands; never transform actual output."""
    legacy = ["-I", "-B", "<tmp>/source/tools/hierarchy_mailbox.py"]
    successor = ["-I", "-B", "<tmp>/initiatives/pilot/runtime-source.py", "--provision",
                 "<tmp>/initiatives/pilot/provision.json", "--entry", legacy[2], "--"]
    if isinstance(value, dict):
        return {key: (python if key == "command" and item == "/usr/bin/python3" and
                      value.get("args", [])[:3] == legacy else with_runtime_bootstrap(item, python))
                for key, item in value.items()}
    if isinstance(value, list):
        if value[:3] == legacy:
            return successor + value[3:]
        return [with_runtime_bootstrap(item, python) for item in value]
    if isinstance(value, str) and value.startswith("mcp_servers="):
        # The Codex wake argv embeds TOML. Replace only this exact legacy args prefix, keeping every suffix byte.
        before = "args=" + json.dumps(legacy)[:-1] + ", "
        after = "args=" + json.dumps(successor)[:-1] + ", "
        value = value.replace(before, after, 1)
        command = 'mcp_servers={aegis_mailbox={command="/usr/bin/python3",'
        successor_command = "mcp_servers={aegis_mailbox={command=" + json.dumps(python) + ","
        return value.replace(command, successor_command, 1)
    return value


def answer(setup, command, request):
    """Either a successful answer with the files it wrote, or the refusal text."""
    path = setup.tmp / ("request-%s.json" % uuid.uuid4().hex)
    path.write_text(json.dumps(request), encoding="utf-8")
    run = subprocess.run([sys.executable, "-I", str(PROVISION), command, "--request", str(path)], capture_output=True,
                         text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not run.stderr, run.stderr
    assert run.returncode in (0, 2), run.stdout
    result = json.loads(run.stdout)
    assert ("error" in result) == (run.returncode == 2), result
    if "error" in result:
        return {"error": result["error"]}
    files = {}
    for key in ("connection", "board_connection", "wake_profile"):
        if key in result:
            files[key] = json.loads(Path(result[key]).read_text())
    return {"answer": result, "files": files}


def variants(host):
    """Each request a role could make on this host, including ones that must be refused."""
    return {"claude-code": [{}, {"assistants": True}, {"background": True}, {"tools": "Read"},
                            {"model": "claude-opus-5-5", "effort": "max"}],
            "codex-cli": [{}, {"reader_shell": True}, {"writable_roots": ["<writable>"]}, {"tmpdir": "<writable>"},
                          {"skip_git_repo_check": True}, {"model": "gpt-5.5-codex", "effort": "high"}],
            "codex": [{}]}[host]


def build(tmp_path):
    snapshot = {}
    interpreters = {}
    for host in ("claude-code", "codex-cli", "codex"):
        for index, options in enumerate(variants(host)):
            # A fresh initiative per variant, so one role's binding never decides another variant's answer.
            folder = tmp_path / ("%s-%d" % (host, index))
            folder.mkdir()
            setup = Setup(folder)
            setup.init()
            python = normalized(json.loads((setup.base / "provision.json").read_text(encoding="utf-8"))["python"], folder)
            writable = folder / "writable"
            writable.mkdir()
            for endpoint in ENDPOINTS:
                request = {"base": str(setup.base), "endpoint": endpoint, "host": host, "session": SESSIONS[endpoint],
                           "cwd": str(setup.source)}
                for key, value in options.items():
                    if value == "<writable>":
                        value = str(writable)
                    elif value == ["<writable>"]:
                        value = [str(writable)]
                    request[key] = value
                key = "%s %s %s" % (host, endpoint, json.dumps(options, sort_keys=True))
                snapshot[key] = normalized(answer(setup, "add-role", request), folder)
                interpreters[key] = python
            if host == "codex-cli":
                for endpoint in ENDPOINTS:
                    if endpoint.endswith("/root"):
                        continue
                    request = {"base": str(setup.base), "endpoint": endpoint, "cwd": str(setup.source)}
                    request.update({key: ([str(writable)] if value == ["<writable>"] else
                                          str(writable) if value == "<writable>" else value)
                                    for key, value in options.items()})
                    key = "codex-start %s %s" % (endpoint, json.dumps(options, sort_keys=True))
                    snapshot[key] = normalized(answer(setup, "codex-start", request), folder)
                    interpreters[key] = python
    return snapshot, interpreters


def team_kinds(tmp_path):
    """Which reasoning_by_kind keys team.json accepts, for every legacy role kind and a typo."""
    folder = tmp_path / "team"
    folder.mkdir()
    setup = Setup(folder)
    setup.init()
    accepted = {}
    for kind in ("orchestrator", "implementer", "integrator", "reviewer", "front-door", "root", "lane", "builder"):
        (setup.base / "team.json").write_text(json.dumps({"model": "claude-opus-5-5", "reasoning": "high",
                                                          "reasoning_by_kind": {kind: "low"}}))
        result = answer(setup, "add-role", {"base": str(setup.base), "endpoint": "pilot/orchestrator",
                                            "host": "claude-code", "session": SESSIONS["pilot/orchestrator"],
                                            "cwd": str(setup.source)})
        accepted[kind] = "error" not in result
        shutil.rmtree(setup.base / "connections", ignore_errors=True)
    return accepted


def test_every_legacy_role_keeps_its_exact_profile(tmp_path):
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    expected["profiles"]['claude-code pilot/front-door {"tools": "Read"}'] = {
        "error": "the front-door role does not permit file tool: Read"}
    profiles, interpreters = build(tmp_path)
    actual = {"profiles": profiles, "team_kinds": team_kinds(tmp_path)}
    assert set(actual["profiles"]) == set(expected["profiles"])
    for key in sorted(expected["profiles"]):
        assert actual["profiles"][key] == with_runtime_bootstrap(expected["profiles"][key], interpreters[key]), key
    assert actual["team_kinds"] == expected["team_kinds"]
