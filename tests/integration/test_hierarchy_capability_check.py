"""Offline capability contracts; inline adapter data, no host, history or OS privileges."""
import ast
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
from types import MappingProxyType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_capability_check as check  # noqa: E402
import hierarchy_roles as roles  # noqa: E402


REGISTRY = json.loads((ROOT / "tools/hierarchy_templates/role-registry.json").read_text(encoding="utf-8"))["roles"]
SESSION_ROLES = [name for name, entry in REGISTRY.items() if entry["endpoint"] is not None]
CALL_TOOLS = {name: ["mcp:forbidden/" + name.replace(":", "_")]
              for name in roles.VOCABULARY["calls"]}
FILE_MAP = {name: "read" for name in roles.READ_TOOLS}
FILE_MAP.update({name: "write-scope" for name in roles.WRITE_TOOLS})
HOSTS = {
    "claude-code": {"file_tools": FILE_MAP, "reader_shell": False, "writer_shell": False,
                    "session_helpers": False},
    "codex-cli": {"file_tools": FILE_MAP, "reader_shell": True, "writer_shell": True,
                  "session_helpers": False},
}


def mcp_surface(entry):
    # Inline context for negative tests only; acceptance parity uses rendered_profiles below.
    import hierarchy_provision as provision
    if entry["provision"]["adapter"] == "decision":
        return ["mcp:aegis_decision/" + name for name in ("root_decide", *roles.decision_tools(entry))]
    return ["mcp:aegis_mailbox/" + name for name in
            (*provision.MAILBOX_TOOLS, *roles.workspace_tools(entry), *roles.lifecycle_tools(entry))]


def resolved(name="reviewer", host="claude-code", **changes):
    args = dict(entry=REGISTRY[name], host_capabilities=HOSTS[host], mcp_tools=mcp_surface(REGISTRY[name]),
                prohibited_call_tools=CALL_TOOLS)
    args.update(changes)
    return check.resolved_capabilities(**args)


def rendered_profile(name, host, extras, monkeypatch, requested=None):
    import hierarchy_provision as provision
    entry = REGISTRY[name]
    endpoint = "pilot/lane/a" if entry["endpoint"]["role"] == "lane" else "pilot/" + entry["endpoint"]["role"]
    mailbox = SimpleNamespace(endpoint=lambda _: {"kind": entry["endpoint"].get("lane_kind")})
    # The ROOT renderer reopens the mailbox at the filesystem boundary. Replace
    # only that module-local constructor; profiles/argv are rendered by real code.
    if name == "root":
        monkeypatch.setattr(provision, "Mailbox", lambda path: mailbox)
    file_tools, writer = provision.role_tools(endpoint, mailbox, requested)
    setup = {"python": sys.executable, "source": str(ROOT), "mailbox_root": str(ROOT / "mailbox"),
             "delivery_dir": str(ROOT / "delivery"), "store": str(ROOT / "store"), "initiative": "pilot"}
    request = {"reader_shell": entry["provision"]["reader_shell"]}
    if extras:
        setup["board"] = str(ROOT / "board")
        request.update(lifecycle=str(ROOT / "journal"), actor="coordinator")
        if roles.source_views(entry):
            request["source_repo"] = str(ROOT)
    emitted = {}
    answer = provision.render_role_profile(
        setup, ROOT / "base", mailbox, endpoint, host, "session", 1, request, ROOT,
        30, False, file_tools, writer, None, False, lambda path, value: emitted.__setitem__(str(path), value))
    mcp, served = set(), set()
    if name == "root":
        if "mcp_config" not in answer:
            # ROOT has no locally rendered CLI allowlist on this path. Absence
            # stays unknown; do not manufacture a catalog from the registry.
            return file_tools, [], None
        tools = json.loads(re.search(r"enabled_tools=(\[[^\]]*\])", answer["mcp_config"]).group(1))
        server = next(iter(emitted[answer["connection"]]["mcpServers"]))
        mcp.update("mcp:" + server + "/" + tool for tool in tools)
        return file_tools, sorted(mcp), None  # ROOT's external session has no rendered native tool catalog.
    elif host == "claude-code":
        argv = emitted[answer["wake_profile"]]["argv"]
        allowed = argv[argv.index("--allowedTools") + 1].split(",")
        native = next(arg[len("--tools="):] for arg in argv if arg.startswith("--tools=")).split(",")
        served.update(FILE_MAP[tool] for tool in native if tool in roles.READ_TOOLS or tool in allowed)
        mcp.update("mcp:" + tool[5:].replace("__", "/") for tool in allowed if tool.startswith("mcp__"))
    else:
        profile = emitted[answer["codex_profile"]]
        mcp.update("mcp:" + server + "/" + tool for server, config in profile["mcp_servers"].items()
                   for tool in config["enabled_tools"])
        if any(feature not in profile["disabled_features"] for feature in provision.CODEX_SHELL):
            served.update(("read", "shell"))
            if profile["sandbox"] == "workspace-write":
                served.add("write-scope")
    served.update(mcp)
    return file_tools, sorted(mcp), sorted(served)


@pytest.mark.parametrize("name", SESSION_ROLES)
@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("extras", [False, True])
def test_resolves_every_session_role_against_rendered_provision(name, host, extras, monkeypatch):
    file_tools, mcp, served = rendered_profile(name, host, extras, monkeypatch)
    result = resolved(name, host, file_tools=file_tools, mcp_tools=mcp)
    assert result["status"] == "resolved"
    assert result["file_tools"] == file_tools
    assert [cap for cap in result["capabilities"] if cap.startswith("mcp:")] == mcp
    assert check.compare(result, served, CALL_TOOLS)["status"] == ("match" if served is not None else "unknown")
    if served is not None:
        assert result["capabilities"] == served


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("requested", ["Read", "Read,Glob,Grep", "Edit"])
def test_narrowed_rendered_profile_matches(host, requested, monkeypatch):
    file_tools, mcp, served = rendered_profile("implementer", host, True, monkeypatch, requested)
    result = resolved("implementer", host, file_tools=file_tools, mcp_tools=mcp)
    assert result["status"] == "resolved"
    assert result["file_tools"] == file_tools
    assert check.compare(result, served, CALL_TOOLS)["status"] == "match"


@pytest.mark.parametrize("extra", ["write-scope", "shell", "subagent", "mcp:other/mailbox_inbox",
                                   "mcp:aegis_mailbox/mailbox_inbox_extra", "Read", "READ", "read ", " read",
                                   "\tread", "read\n"])
def test_exact_comparison_reports_each_extra(extra):
    result = resolved()
    verdict = check.compare(result, result["capabilities"] + [extra], CALL_TOOLS)
    assert verdict["status"] == "exceeds"
    assert verdict["extras"] == [extra]


@pytest.mark.parametrize("catalog", [None, [], "read", {"read": True}, ["read", "read"], [1],
                                    ["ｒｅａｄ"], ["read\N{NO-BREAK SPACE}"], ["read\x00"], ["x" * 257],
                                    ["read"] * 257], ids=lambda x: str(type(x).__name__))
def test_invalid_catalogs_are_unknown_without_echoing_input(catalog):
    assert check.compare(resolved(), catalog, CALL_TOOLS) == {
        "status": "unknown", "code": "invalid_catalog", "extras": [], "missing": [], "uncovered_calls": []}


def test_incomplete_catalog_is_never_a_match():
    result = resolved()
    verdict = check.compare(result, result["capabilities"][1:], CALL_TOOLS)
    assert verdict["status"] == "unknown"
    assert verdict["code"] == "incomplete_catalog"
    assert verdict["missing"] == result["capabilities"][:1]


@pytest.mark.parametrize("mapping", [None, [], {"merge": "shell"}, {"merge": ["shell", "shell"]},
                                    {"merge": ["ｓｈｅｌｌ"]}, {"merge ": ["shell"]}, {"merge": []},
                                    {"merge": ["read"] * 257}], ids=lambda x: type(x).__name__)
def test_missing_or_malformed_call_mapping_is_unknown_at_both_surfaces(mapping):
    resolution = resolved(prohibited_call_tools=mapping)
    assert resolution["status"] == "unknown"
    assert resolution["capabilities"] == []
    assert resolution["uncovered_calls"]
    verdict = check.compare(resolved(), resolved()["capabilities"], mapping)
    assert verdict["status"] == "unknown"
    assert verdict["uncovered_calls"]


def test_uncovered_calls_are_named_and_compare_rechecks_coverage():
    mapping = dict(CALL_TOOLS)
    del mapping["merge"]
    assert resolved(prohibited_call_tools=mapping)["uncovered_calls"] == ["merge"]
    assert check.compare(resolved(), resolved()["capabilities"], mapping)["uncovered_calls"] == ["merge"]
    full = MappingProxyType({key: tuple(value) for key, value in CALL_TOOLS.items()})
    assert resolved(prohibited_call_tools=full)["status"] == "resolved"


def test_prohibited_tools_cannot_appear_even_if_mapping_conflicts_with_expected_surface():
    mapping = dict(CALL_TOOLS, merge=["read"])
    assert resolved(prohibited_call_tools=mapping)["code"] == "prohibited_capability"
    assert check.compare(resolved(), resolved()["capabilities"], mapping)["code"] == "prohibited_capability"


def test_helpers_are_subagent_and_reviewers_never_receive_them():
    host = dict(HOSTS["claude-code"], session_helpers=True)
    assert "subagent" in resolved("orchestrator", host_capabilities=host)["capabilities"]
    assert "subagent" not in resolved(host_capabilities=host)["capabilities"]
    result = resolved(host_capabilities=host)
    assert check.compare(result, result["capabilities"] + ["subagent"], CALL_TOOLS)["status"] == "exceeds"


@pytest.mark.parametrize("entry", [None, [], {}, {"reads": [1]}, {"reads": ["source"] * 257}])
def test_invalid_registry_entry_is_refused(entry):
    assert resolved(entry=entry)["code"] == "invalid_role"


@pytest.mark.parametrize("mapping", [None, {}, {"reader_shell": "yes"},
                                    dict(HOSTS["claude-code"], file_tools={"Read": "write-scope"})])
def test_invalid_host_mapping_is_refused(mapping):
    assert resolved(host_capabilities=mapping)["code"] == "invalid_host_mapping"


def plan(name="reviewer", windows=False, host="claude-code", **changes):
    prefix = "C:/probe" if windows else "/probe"
    args = dict(entry=REGISTRY[name], resolved=resolved(name, host), host_capabilities=HOSTS[host],
                mcp_tools=mcp_surface(REGISTRY[name]), prohibited_call_tools=CALL_TOOLS,
                prohibited_tool="subagent", prohibited_mcp="mcp:forbidden/merge",
                write_roots=[prefix + "/lanes/a"], outside_path=prefix + "/outside/write",
                edit_path=prefix + "/outside/existing-edit-canary", canary_path=prefix + "/outside/canary",
                sibling_path=prefix + "/lanes/ab/file")
    args.update(changes)
    return check.probe_plan(**args)


def observed(planned):
    return [dict(attempt, outcome="refused") for attempt in planned["attempts"]]


def verdict(planned, observations, name="reviewer", roots=None, host="claude-code", **changes):
    args = dict(entry=REGISTRY[name], resolved=resolved(name, host), host_capabilities=HOSTS[host],
                mcp_tools=mcp_surface(REGISTRY[name]), prohibited_call_tools=CALL_TOOLS,
                roots=["/probe/lanes/a"] if roots is None else roots, plan=planned, observations=observations)
    args.update(changes)
    return check.probe_verdict(**args)


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("name", ["reviewer", "implementer"])
def test_probe_plan_separates_write_and_edit_and_checks_prefix_sibling(name, windows):
    result = plan(name, windows)
    assert result["status"] == "planned"
    attempts = result["attempts"]
    assert [a["id"] for a in attempts] == ["prohibited-tool", "outside-write", "outside-edit", "outside-read",
                                          "prohibited-mcp"] + (["sibling-write"] if name == "implementer" else [])
    assert [a["operation"] for a in attempts[:5]] == ["call", "write", "edit", "read", "call"]
    assert attempts[1]["path"] != attempts[2]["path"]
    assert attempts[2]["path"].endswith("/outside/existing-edit-canary")
    assert attempts[3]["path"].endswith("/outside/canary")
    if name == "implementer":
        assert attempts[-1]["path"].endswith("/lanes/ab/file")


@pytest.mark.parametrize("changes", [dict(outside_path="/probe/lanes/a/file"),
                                    dict(canary_path="/probe/lanes/a/canary"), dict(outside_path="../escape"),
                                    dict(outside_path="/probe/../escape"), dict(sibling_path=None),
                                    dict(sibling_path="/probe/lanes/b/file"), dict(write_roots=[]),
                                    dict(prohibited_tool="read"), dict(prohibited_mcp="merge"),
                                    dict(outside_path="x" * 4097)])
def test_invalid_probe_targets_return_documented_unknown(changes):
    result = plan("implementer", **changes)
    assert result == {"status": "unknown", "code": "invalid_probe_plan", "attempts": []}


def test_windows_case_does_not_escape_write_roots():
    assert plan("implementer", True, outside_path="c:/PROBE/LANES/A/file")["status"] == "unknown"


def test_probe_verdict_requires_every_independent_refusal_and_allowed_dominates_missing():
    planned = plan("implementer")
    observations = observed(planned)
    assert verdict(planned, observations, "implementer") == {"status": "pass", "code": "all_refused"}
    for i in range(len(observations)):
        short = observations[:i] + observations[i + 1:]
        assert verdict(planned, short, "implementer")["status"] == "unknown"
        allowed = copy.deepcopy(observations)
        allowed[i]["outcome"] = "allowed"
        assert verdict(planned, allowed, "implementer")["status"] == "fail"
        assert verdict(planned, [allowed[i]], "implementer")["status"] == "fail"


@pytest.mark.parametrize("observations", [None, {}, [], [{"id": "outside-write", "outcome": "error"}],
                                         [{"id": "outside-write", "outcome": "refused"}] * 2,
                                         [{"id": "unknown", "outcome": "refused"}], ["refused"]])
def test_malformed_or_missing_observations_are_unknown(observations):
    assert verdict(plan(), observations)["status"] == "unknown"


@pytest.mark.parametrize("planned", [None, {}, {"status": "planned", "attempts": []}])
def test_invalid_plan_cannot_pass(planned):
    assert verdict(planned, [])["status"] == "unknown"


def test_inputs_are_not_mutated():
    entry, host, mapping = copy.deepcopy((REGISTRY["implementer"], HOSTS["codex-cli"], CALL_TOOLS))
    before = copy.deepcopy((entry, host, mapping))
    result = resolved("implementer", entry=entry, host_capabilities=host, prohibited_call_tools=mapping)
    check.compare(result, result["capabilities"], mapping)
    assert (entry, host, mapping) == before


def test_analyzer_has_no_host_kind_or_io_imports():
    source = (ROOT / "tools/hierarchy_capability_check.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    literals = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    assert not any(host in value for value in literals for host in ("claude-code", "codex-cli", "codex"))
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert all((isinstance(node, ast.ImportFrom) and node.module in {"collections.abc", "pathlib"})
               or (isinstance(node, ast.Import) and all(alias.name in {"sys", "hierarchy_roles"} for alias in node.names))
               for node in imports)
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in
                   {"open", "exec", "eval", "__import__"} for node in ast.walk(tree))


@pytest.mark.parametrize("value", [[], {}, 1, True, "unknown-helper", "x" * 257], ids=lambda x: type(x).__name__)
def test_malformed_assistants_never_raise(value):
    entry = copy.deepcopy(REGISTRY["reviewer"])
    entry["provision"]["assistants"] = value
    assert resolved(entry=entry)["code"] == "invalid_role"


def test_reader_shell_requires_source_read_and_no_source_write():
    entry = copy.deepcopy(REGISTRY["implementer"])
    entry["provision"]["reader_shell"] = True
    assert resolved(entry=entry)["code"] == "invalid_role"


@pytest.mark.parametrize("value", [[], {}, "attacker-controlled"], ids=lambda x: type(x).__name__)
def test_malformed_resolution_code_never_raises_or_echoes(value):
    result = resolved()
    result.update(status="unknown", code=value)
    assert check.compare(result, ["read"], CALL_TOOLS)["code"] == "invalid_resolution"


class BoundedList(list):
    """Fail if a public input is traversed before its declared size is rejected."""
    def __init__(self, size):
        self.size = size

    def __len__(self):
        return self.size

    def __iter__(self):
        raise AssertionError("oversized input was traversed")


def test_catalog_and_mapping_limits_precede_traversal():
    assert check.compare(resolved(), BoundedList(257), CALL_TOOLS)["code"] == "invalid_catalog"
    assert resolved(prohibited_call_tools={"merge": BoundedList(257)})["code"] == "invalid_prohibited_call_tools"
    mapping = {key: BoundedList(256) for key in sorted(CALL_TOOLS)[:5]}
    assert resolved(prohibited_call_tools=mapping)["code"] == "invalid_prohibited_call_tools"
    assert plan("implementer", write_roots=BoundedList(17))["code"] == "invalid_probe_plan"
    assert verdict(plan(), BoundedList(7))["code"] == "invalid_observations"


def test_combined_resolution_cannot_exceed_catalog_limit():
    mcp = ["mcp:server/tool-%d" % i for i in range(256)]
    assert resolved(mcp_tools=mcp)["code"] == "invalid_mcp_tools"


def test_exact_catalog_size_boundary_is_usable():
    result = resolved(mcp_tools=["mcp:server/tool-%d" % i for i in range(255)])
    assert result["status"] == "resolved"
    assert len(result["capabilities"]) == 256
    assert check.compare(result, result["capabilities"], CALL_TOOLS)["status"] == "match"


@pytest.mark.parametrize("changes", [dict(operation="write"), dict(path="relative"), dict(capability="shell")])
def test_tampered_plan_cannot_pass(changes):
    planned = plan()
    planned["attempts"][2].update(changes)
    assert verdict(planned, observed(planned))["code"] == "invalid_probe_plan"


def test_isolated_tools_import_uses_the_same_role_module():
    script = ("import sys; sys.path.insert(0, sys.argv[1]); "
              "import hierarchy_capability_check as check; import hierarchy_roles; "
              "assert check.roles is hierarchy_roles")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools")],
                            capture_output=True, text=True, timeout=15, cwd=ROOT / "tools")
    assert result.returncode == 0, result.stderr


def test_writer_cannot_drop_sibling_probe():
    planned = plan("implementer")
    planned["attempts"].pop()
    assert verdict(planned, observed(planned), "implementer")["status"] == "unknown"


@pytest.mark.parametrize("target", ["write-edit", "read", "sibling"])
def test_verdict_cannot_certify_in_root_or_unrelated_targets(target):
    planned = plan("implementer")
    if target == "write-edit":
        planned["attempts"][1]["path"] = planned["attempts"][2]["path"] = "/probe/lanes/a/file"
    elif target == "read":
        planned["attempts"][3]["path"] = "/probe/lanes/a/canary"
    else:
        planned["attempts"][-1]["path"] = "/probe/lanes/unrelated/file"
    assert verdict(planned, observed(planned), "implementer")["status"] == "unknown"


@pytest.mark.parametrize("changes", [dict(outside_path="//probe/lanes/a/file"),
                                    dict(canary_path="//probe/lanes/a/canary"),
                                    dict(write_roots=["//probe/lanes/a"]),
                                    dict(sibling_path="//probe/lanes/ab/file")])
def test_ambiguous_slash_form_is_never_a_probe_target(changes):
    assert plan("implementer", **changes)["status"] == "unknown"


def test_edit_target_is_independent_of_refused_write():
    attempts = plan()["attempts"]
    assert attempts[1]["path"] != attempts[2]["path"]


def test_resolver_honors_provisioned_file_tool_narrowing():
    result = resolved("implementer", file_tools=["Read", "Glob", "Grep"])
    assert result["status"] == "resolved"
    assert "write-scope" not in result["capabilities"]
    assert result["file_tools"] == ["Read", "Glob", "Grep"]


@pytest.mark.parametrize("tools", ["Read", ["Read", "Read"], ["Bash"], ["ｒｅａｄ"], [1], BoundedList(257)],
                         ids=["not-list", "duplicate", "extra", "unicode", "not-string", "oversized"])
def test_provisioned_file_tools_must_be_a_bounded_role_subset(tools):
    assert resolved(file_tools=tools)["code"] == "invalid_file_tools"


def test_empty_provisioned_file_list_stays_empty_without_a_shell():
    result = resolved("implementer", file_tools=[])
    assert result["file_tools"] == []
    assert "read" not in result["capabilities"] and "write-scope" not in result["capabilities"]


@pytest.mark.parametrize("capability", ["shell", "mcp:aegis_mailbox/mailbox_inbox"])
def test_probe_plan_refuses_a_call_in_the_resolved_grants(capability):
    changes = {"prohibited_tool" if capability == "shell" else "prohibited_mcp": capability}
    assert plan("implementer", host="codex-cli", **changes)["code"] == "invalid_probe_plan"


@pytest.mark.parametrize("index,capability,host", [(0, "shell", "codex-cli"),
                                                 (0, "subagent", "claude-code"),
                                                 (4, "mcp:aegis_mailbox/mailbox_inbox", "codex-cli")])
def test_verdict_refuses_substituted_granted_calls(index, capability, host):
    settings = dict(HOSTS[host], session_helpers=capability == "subagent")
    resolution = resolved("implementer", host, host_capabilities=settings)
    assert resolution["status"] == "resolved"
    assert capability in resolution["capabilities"]
    native = "shell" if capability == "subagent" else "subagent"
    context = dict(host=host, resolved=resolution, host_capabilities=settings)
    planned = plan("implementer", prohibited_tool=native, **context)
    assert planned["status"] == "planned"
    assert verdict(planned, observed(planned), "implementer", **context) == {
        "status": "pass", "code": "all_refused"}
    planned["attempts"][index]["capability"] = capability
    assert verdict(planned, observed(planned), "implementer", **context) == {
        "status": "unknown", "code": "invalid_probe_plan"}


@pytest.mark.parametrize("surface", ["plan", "verdict"])
@pytest.mark.parametrize("defect", ["wrong-role", "incomplete"])
def test_probes_refuse_wrong_role_or_incomplete_resolution(surface, defect):
    actual = resolved("implementer", "codex-cli")
    assert "shell" in actual["capabilities"]
    if defect == "wrong-role":
        supplied = resolved("front-door", "codex-cli")
        assert "shell" not in supplied["capabilities"]
        native = "shell"
    else:
        supplied = dict(actual, uncovered_calls=["merge"])
        native = "subagent"
    if surface == "plan":
        result = plan("implementer", host="codex-cli", resolved=supplied, prohibited_tool=native)
    else:
        planned = plan("implementer", host="codex-cli", resolved=actual)
        assert planned["status"] == "planned"
        planned["attempts"][0]["capability"] = native
        result = verdict(planned, observed(planned), "implementer", host="codex-cli", resolved=supplied)
    assert result["status"] == "unknown"
    assert result["code"] == "invalid_probe_plan"


@pytest.mark.parametrize("surface", ["plan", "verdict"])
@pytest.mark.parametrize("setting", ["host_capabilities", "mcp_tools", "file_tools", "prohibited_call_tools"])
def test_probes_recheck_independent_provisioning_settings(surface, setting):
    resolution = resolved("implementer")
    changes = {
        "host_capabilities": HOSTS["codex-cli"],
        "mcp_tools": mcp_surface(REGISTRY["implementer"]) + ["mcp:extra/tool"],
        "file_tools": [],
        "prohibited_call_tools": None,
    }
    context = {setting: changes[setting], "resolved": resolution}
    if surface == "plan":
        result = plan("implementer", **context)
    else:
        planned = plan("implementer")
        result = verdict(planned, observed(planned), "implementer", **context)
    assert result["code"] == "invalid_probe_plan"
    assert result["status"] == "unknown"


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("tools", [[], ["Read"]])
def test_matching_provisioned_narrowing_plans_and_passes(host, tools):
    resolution = resolved("implementer", host, file_tools=tools)
    context = dict(host=host, resolved=resolution, file_tools=tools)
    planned = plan("implementer", **context)
    assert planned["status"] == "planned"
    assert verdict(planned, observed(planned), "implementer", **context) == {
        "status": "pass", "code": "all_refused"}


@pytest.mark.parametrize("resolution", [None, {}, {"status": "unknown"},
                                      dict(status="resolved", capabilities=["subagent"], prohibited_calls=[])])
def test_probe_plan_requires_a_matching_resolution(resolution):
    assert plan(resolved=resolution)["code"] == "invalid_probe_plan"
    planned = plan()
    assert verdict(planned, observed(planned), resolved=resolution) == {
        "status": "unknown", "code": "invalid_probe_plan"}


@pytest.mark.parametrize("surface", ["plan", "verdict"])
@pytest.mark.parametrize("site", ["capabilities", "prohibited_calls", "file_tools", "uncovered_calls"])
def test_probe_resolution_limits_precede_traversal(site, surface):
    resolution = resolved()
    resolution[site] = BoundedList(257)
    if surface == "plan":
        result = plan(resolved=resolution)
    else:
        planned = plan()
        result = verdict(planned, observed(planned), resolved=resolution)
    assert result["code"] == "invalid_probe_plan"
    assert result["status"] == "unknown"


def test_verdict_attempt_limit_precedes_traversal():
    planned = plan("implementer")
    planned["attempts"] = BoundedList(257)
    assert verdict(planned, [], "implementer") == {"status": "unknown", "code": "invalid_probe_plan"}


@pytest.mark.parametrize("name", ["reviewer", "implementer"])
@pytest.mark.parametrize("windows", [False, True])
def test_valid_probe_targets_are_bound_through_the_verdict(name, windows):
    planned = plan(name, windows)
    roots = ["C:/probe/lanes/a" if windows else "/probe/lanes/a"]
    assert verdict(planned, observed(planned), name, roots)["status"] == "pass"


@pytest.mark.parametrize("index", range(6))
@pytest.mark.parametrize("field,value", [("path", "/probe/lanes/a/file"), ("operation", "other"),
                                        ("capability", "shell"), ("path", "x" * 4097)],
                         ids=["in-root", "wrong-operation", "wrong-capability", "oversized-path"])
def test_observation_must_repeat_the_planned_target(index, field, value):
    planned = plan("implementer")
    observations = observed(planned)
    observations[index][field] = value
    assert verdict(planned, observations, "implementer")["code"] == "invalid_observations"


def test_observation_cannot_replace_a_required_null_target_field():
    planned = plan()
    observations = observed(planned)
    observations[0]["extra"] = observations[0].pop("path")
    assert verdict(planned, observations)["code"] == "invalid_observations"


def test_trusted_role_and_roots_override_plan_shape_and_targets():
    planned = plan("implementer")
    assert verdict(planned, observed(planned), "reviewer")["code"] == "invalid_probe_plan"
    assert verdict(planned, observed(planned), "implementer", ["/probe/outside"])["code"] == "invalid_probe_plan"
    assert verdict(plan(), observed(plan()), roots=BoundedList(17))["code"] == "invalid_probe_plan"


@pytest.mark.parametrize("site", ["write_roots", "outside_path", "edit_path", "canary_path", "sibling_path"])
@pytest.mark.parametrize("path", ["//probe/lanes/a/file", "/probe/./outside/file", "/probe/../outside/file",
                                  "/probe//outside/file", "/probe/outside/file/"])
def test_all_probe_path_sites_share_normalization(site, path):
    value = [path] if site == "write_roots" else path
    assert plan("implementer", **{site: value})["code"] == "invalid_probe_plan"


@pytest.mark.parametrize("site,index", [("outside_path", 1), ("edit_path", 2), ("canary_path", 3), ("sibling_path", 5)])
def test_verdict_revalidates_every_path_after_planning(site, index):
    planned = plan("implementer")
    planned["attempts"][index]["path"] = "//probe/lanes/ab/file"
    assert verdict(planned, observed(planned), "implementer")["code"] == "invalid_probe_plan"


@pytest.mark.parametrize("path", ["C:/probe/lanes/a./file", "C:/probe/lanes/a /file", "C:/probe/lanes/a:stream/file"])
def test_windows_ambiguous_component_forms_are_refused(path):
    assert plan("implementer", True, outside_path=path)["code"] == "invalid_probe_plan"


def test_edit_canary_must_be_separate_and_outside_the_roots():
    assert plan(edit_path="/probe/outside/write")["code"] == "invalid_probe_plan"
    assert plan(edit_path="/probe/lanes/a/canary")["code"] == "invalid_probe_plan"
    assert plan(edit_path=None)["code"] == "invalid_probe_plan"
