"""Model selection parity through the CLI and public MCP transport."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_cli.cli import main
from aegis_cli import team as cli_team
from aegis_core import model_select as core
from aegis_core.storage import LockTimeoutError
import aegis_mcp.server as server
from aegis_mcp.tools import execute_tool
from aegis_mcp import tools as mcp_tools


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    # Outside-workspace targets must still belong to this test's tmp_path.
    root = (tmp_path / "workspace").resolve()
    root.mkdir(mode=0o700 if os.name == "posix" else 0o777)
    (root / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    monkeypatch.setattr(server, "_canonical_workspace", str(root))
    monkeypatch.setattr(server, "_workspace_error", None)
    monkeypatch.setattr(server, "_session_id", None)
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    bindings = json.loads((Path(__file__).resolve().parents[3] /
                           "tools/hierarchy_templates/model-bindings.json").read_text(encoding="utf-8"))
    policy = {"team_id": "team-one", "manager_family": "second", "team_family": "first",
              "target_shares": {"first": 0.7, "second": 0.3}, "family_order": ["first", "second"],
              "flexible_tasks": ["T9"],
              "family_hosts": {"first": ["codex-cli"], "second": ["claude-code"]},
              "review_families": {"T4": {"primary": "second"}, "T5": {"primary": "first"},
                                  "T6": {"primary": "first", "whole": "second"},
                                  "T8": {"primary": "opposite", "second": "author"}}}
    for name, value in (("bindings.json", bindings), ("policy.json", policy)):
        (root / name).write_text(json.dumps(value), encoding="utf-8")
    return root


def require_descriptors():
    if not core._DIR_FD_SUPPORTED:
        pytest.skip("requires anchored model-selection I/O")


def arguments(**updates):
    return dict(bindings="bindings.json", policy="policy.json", history="decisions.jsonl",
                task_kind="T9", role_kind="implementer", subject="lane-one",
                host_kinds=["codex-cli", "claude-code"], **updates)


def cli(capsys, args, record_option="--record"):
    argv = ["team", "model", "--json"]
    for key, value in args.items():
        if key == "host_kinds":
            for host in value:
                argv.extend(["--host-kind", host])
        elif key == "record":
            if value:
                argv.append(record_option)
        else:
            argv.extend(["--" + key.replace("_", "-"), value])
    code = main(argv)
    captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out)


def call(args):
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "aegis_team_model", "arguments": args}})
    result = response["result"]
    return result["isError"], json.loads(result["content"][0]["text"])


def test_preview_parity_and_core_result_without_history_writes(workspace, capsys):
    require_descriptors()
    args = arguments()
    code, expected = cli(capsys, args)
    failed, actual = call(args)
    choice, record = core.select_model(workspace / args["bindings"], workspace / args["policy"],
                                       "T9", "implementer", [], host_kinds=args["host_kinds"], subject="lane-one")
    assert code == 0 and failed is False
    assert actual == expected == {"choice": choice, "record": record}
    assert json.dumps(actual) == json.dumps({"choice": choice, "record": record})
    assert not (workspace / args["history"]).exists()
    assert not (workspace / (args["history"] + ".lock")).exists()


@pytest.mark.parametrize("location", ["absolute", "relative", "cwd"])
def test_cli_subdirectory_resolves_to_the_mcp_workspace(workspace, monkeypatch, capsys, location):
    require_descriptors()
    subdirectory = workspace / "sub"
    subdirectory.mkdir()
    assert not (subdirectory / ".aegis").exists()
    args = arguments()
    if location == "cwd":
        monkeypatch.chdir(subdirectory)
        cli_args = args
    else:
        cli_args = dict(args, workspace=str(subdirectory) if location == "absolute" else "sub")
    code, expected = cli(capsys, cli_args)
    failed, actual = call(args)
    assert code == 0 and failed is False
    assert actual == expected
    assert not (workspace / args["history"]).exists()
    assert not (subdirectory / args["history"]).exists()


@pytest.mark.parametrize("surface", ["cli-adapter", "mcp-adapter", "dispatch"])
@pytest.mark.parametrize("location", ["absolute", "relative", "cwd", "workspace-object"])
def test_direct_subdirectory_adapter_matches_both_frontends(workspace, monkeypatch, capsys, surface, location):
    from aegis_core.workspace.base import Workspace

    require_descriptors()
    subdirectory = workspace / "docs"
    subdirectory.mkdir()
    code, expected = cli(capsys, arguments())
    failed, actual = call(arguments())
    assert code == 0 and failed is False and actual == expected
    root = str(subdirectory) if location == "absolute" else "docs"
    if location == "workspace-object":
        root = Workspace(root=subdirectory)
    elif location == "cwd":
        monkeypatch.chdir(subdirectory)
        root = None
    if surface == "dispatch":
        result = execute_tool("aegis_team_model", dict(arguments(), workspace=root))
    else:
        adapter = cli_team.model_result if surface == "cli-adapter" else mcp_tools.model_result
        result = adapter(arguments(), root)
    assert result == expected
    assert not (workspace / "decisions.jsonl").exists()
    assert not (subdirectory / "decisions.jsonl").exists()


@pytest.mark.parametrize("surface", ["cli-adapter", "mcp-adapter", "dispatch"])
@pytest.mark.parametrize("location", ["home", "filesystem-root"])
def test_direct_adapter_denied_roots_refuse_before_paths(workspace, monkeypatch, surface, location):
    home = workspace.parent / "home"
    (home / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = str(home if location == "home" else Path(workspace.anchor))
    args = arguments()
    args["bindings"] = "../outside"
    if surface == "dispatch":
        result = execute_tool("aegis_team_model", dict(args, workspace=root))
    else:
        adapter = cli_team.model_result if surface == "cli-adapter" else mcp_tools.model_result
        result = adapter(args, root)
    assert result == {"error": "model_workspace_unavailable"}


@pytest.mark.parametrize("surface", ["cli-adapter", "mcp-adapter", "dispatch"])
@pytest.mark.parametrize("root", [False, 42, [], {}, "x" * (core.MAX_INPUT_BYTES + 1), "x/" * 257],
                         ids=["bool", "number", "array", "object", "oversize", "too-many-components"])
def test_direct_adapter_workspace_shape_and_bounds_refuse(workspace, surface, root):
    if surface == "dispatch":
        result = execute_tool("aegis_team_model", dict(arguments(), workspace=root))
    else:
        adapter = cli_team.model_result if surface == "cli-adapter" else mcp_tools.model_result
        result = adapter(arguments(), root)
    assert result == {"error": "model_workspace_unavailable"}


@pytest.mark.parametrize("surface", ["cli", "mcp"])
def test_record_is_atomic_and_next_preview_uses_recorded_split(workspace, capsys, surface):
    require_descriptors()
    args = arguments(record=True)
    if surface == "cli":
        code, result = cli(capsys, args)
        assert code == 0
    else:
        failed, result = call(args)
        assert failed is False
    assert list(core.read_decisions(workspace / args["history"])) == [result["record"]]
    assert result["choice"]["family"] == "first"
    code, preview = cli(capsys, arguments())
    failed, actual = call(arguments())
    assert code == 0 and failed is False and preview == actual
    assert preview["choice"]["family"] == "second"


@pytest.mark.parametrize("field,data,error", [
    ("bindings", b"{bad json", "invalid_bindings"),
    ("policy", b"{bad json", "invalid_policy"),
    ("bindings", b" " * (core.MAX_INPUT_BYTES + 1), "invalid_bindings"),
    ("history", b"{}\n", "invalid_history"),
    ("policy", None, "invalid_policy"),
], ids=["bad-bindings", "bad-policy", "oversize-bindings", "bad-history", "missing-policy"])
def test_file_refusals_match_without_input_echo(workspace, capsys, field, data, error):
    require_descriptors()
    args = arguments()
    if data is None:
        args[field] = "token=private-value"
    else:
        (workspace / args[field]).write_bytes(data)
        if field == "history":
            (workspace / args[field]).chmod(0o600)
    code, expected = cli(capsys, args)
    failed, actual = call(args)
    assert code == 2 and failed is True
    assert actual == expected == {"error": error}


@pytest.mark.parametrize("location", ["root", "subdirectory"])
def test_unsupported_platform_has_explicit_parity(workspace, monkeypatch, capsys, location):
    monkeypatch.setattr(core, "_DIR_FD_SUPPORTED", False)
    cli_args = arguments()
    if location == "subdirectory":
        subdirectory = workspace / "sub"
        subdirectory.mkdir()
        cli_args["workspace"] = str(subdirectory)
    code, expected = cli(capsys, cli_args)
    failed, actual = call(arguments())
    assert code == 2 and failed is True
    assert actual == expected == {"error": "anchored_io_unavailable"}
    root = cli_args.get("workspace", str(workspace))
    assert cli_team.model_result(arguments(), root) == expected
    assert mcp_tools.model_result(arguments(), root) == expected
    assert execute_tool("aegis_team_model", dict(arguments(), workspace=root)) == expected


@pytest.mark.parametrize("exception,error", [(OSError, "model_io_unavailable"),
                                           (LockTimeoutError, "model_lock_timeout")])
def test_io_errors_are_fixed_refusals(workspace, monkeypatch, capsys, exception, error):
    require_descriptors()
    def fail(*args, **kwargs):
        raise exception("token=private-value\n\x1b[31m")

    if exception is LockTimeoutError:
        monkeypatch.setattr(core, "file_lock", fail)
    else:
        # Own the module reference; pytest's cleanup keeps the real os module.
        module_os = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
        module_os.write = fail
        monkeypatch.setattr(core, "os", module_os)
    code, expected = cli(capsys, arguments(record=True))
    failed, actual = call(arguments(record=True))
    assert code == 2 and failed is True
    assert actual == expected == {"error": error}


@pytest.mark.parametrize("args", [[], False, "token=private-value", {"extra": "token=private-value"},
                                  {"record": "false"}, {"workspace": "token=private-value"}])
def test_malformed_arguments_refuse_without_echo_or_io(workspace, args, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid arguments reached core I/O")

    monkeypatch.setattr(core, "read_decisions", unexpected)
    failed, actual = call(args)
    assert failed is True and actual == {"error": "invalid_model_arguments"}


@pytest.mark.parametrize("field,value,error", [("subject", "token=private-value\n", "model_output_needs_redaction"),
    ("intent", "ultra", "unknown_intent"), ("task_kind", "hostile", "unknown_task_kind"),
    ("role_kind", "router", "unknown_role_kind"), ("lane_family", "other", "invalid_request:lane_family")])
def test_semantic_refusals_are_core_codes(workspace, capsys, field, value, error):
    require_descriptors()
    args = arguments()
    args[field] = value
    code, expected = cli(capsys, args)
    failed, actual = call(args)
    assert code == 2 and failed is True
    assert actual == expected == {"error": error}


def test_symlink_policy_refuses(workspace, capsys):
    require_descriptors()
    symlink_or_skip(workspace / "policy.json", workspace / "alias.json")
    args = arguments()
    args["policy"] = "alias.json"
    code, expected = cli(capsys, args)
    failed, actual = call(args)
    assert code == 2 and failed is True
    assert actual == expected == {"error": "invalid_policy"}


def test_direct_dispatch_matches_transport(workspace):
    require_descriptors()
    failed, expected = call(arguments())
    assert failed is False
    assert execute_tool("aegis_team_model", dict(arguments(), workspace=str(workspace))) == expected


@pytest.mark.parametrize("key", sorted(server.SERVER_OWNED_KEYS))
def test_reserved_arguments_refuse_before_binding(workspace, monkeypatch, key):
    def unexpected(*args, **kwargs):
        pytest.fail("reserved input reached workspace binding")

    monkeypatch.setattr(server, "_bind", unexpected)
    args = arguments()
    args[key] = "token=private-value"
    failed, actual = call(args)
    assert failed is True and actual == {"error": "invalid_model_arguments"}


def test_unbound_model_has_fixed_refusal(workspace, monkeypatch):
    monkeypatch.setattr(server, "_canonical_workspace", str(workspace / "missing-pin"))
    failed, actual = call(arguments())
    assert failed is True and actual == {"error": "model_workspace_unavailable"}


def test_startup_workspace_error_has_fixed_refusal(workspace, monkeypatch):
    from aegis_core.workspace.binding import WorkspaceBinding

    monkeypatch.setattr(server, "_workspace_error", WorkspaceBinding(status="hold", reason="pin_conflict"))
    failed, actual = call(arguments())
    assert failed is True and actual == {"error": "model_workspace_unavailable"}


@pytest.mark.parametrize("field", ["bindings", "policy", "history", "subject", "intent"])
def test_oversize_arguments_refuse_without_echo(workspace, field):
    args = arguments()
    args[field] = "x" * (core.MAX_INPUT_BYTES + 1)
    failed, actual = call(args)
    assert failed is True and actual == {"error": "invalid_model_arguments"}


def test_token_fields_in_core_result_refuse_without_altering_record(workspace, capsys):
    require_descriptors()
    path = workspace / "bindings.json"
    bindings = json.loads(path.read_text(encoding="utf-8"))
    token = "sk-" + "a" * 48
    for host in bindings["hosts"]:
        if host["class"] == "coding":
            host["model"] = token
    path.write_text(json.dumps(bindings), encoding="utf-8")
    code, expected = cli(capsys, arguments())
    failed, actual = call(arguments())
    assert code == 2 and failed is True
    assert actual == expected == {"error": "model_output_needs_redaction"}
    assert token not in json.dumps(actual)


@pytest.mark.parametrize("root", [False, 42, [], {}], ids=["bool", "number", "array", "object"])
def test_direct_invalid_workspace_is_fixed_refusal(workspace, root):
    assert execute_tool("aegis_team_model", dict(arguments(), workspace=root)) == {
        "error": "model_workspace_unavailable"}


@pytest.mark.parametrize("task,role,options", [
    ("T1", "orchestrator", {"intent": "standard"}),
    ("T2", "implementer", {}),
    ("T3", "integrator", {"lane_family": "first"}),
    ("T4", "reviewer", {"author_family": "first"}),
    ("T5", "reviewer", {"author_family": "second", "intent": "extended"}),
    ("T6", "reviewer", {"author_family": "first", "review_stage": "whole"}),
    ("T7", "implementer", {}),
    ("T8", "reviewer", {"author_family": "first", "review_stage": "second"}),
], ids=["manager", "writer", "lane", "correctness", "security", "whole", "author", "second"])
def test_optional_arguments_and_task_roles_match_core(workspace, capsys, task, role, options):
    require_descriptors()
    args = arguments()
    args.update(task_kind=task, role_kind=role, **options)
    code, expected = cli(capsys, args)
    failed, actual = call(args)
    choice, record = core.select_model(workspace / "bindings.json", workspace / "policy.json", task, role, [],
                                       host_kinds=args["host_kinds"], subject="lane-one", **options)
    assert code == 0 and failed is False
    assert actual == expected == {"choice": choice, "record": record}


@pytest.mark.parametrize("surface", ["cli", "mcp"])
@pytest.mark.parametrize("field", ["bindings", "policy", "history"])
@pytest.mark.parametrize("spelling", ["absolute", "parent"])
def test_paths_cannot_escape_workspace(workspace, capsys, surface, field, spelling):
    args = arguments(record=True)
    outside = workspace.parent / (workspace.name + "-outside-" + field + ".json")
    if field != "history":
        outside.write_bytes((workspace / args[field]).read_bytes())
    args[field] = str(outside) if spelling == "absolute" else "../" + outside.name
    if surface == "cli":
        code, actual = cli(capsys, args)
        assert code == 2
    else:
        failed, actual = call(args)
        assert failed is True
    assert actual == {"error": "invalid_model_arguments"}
    if field == "history":
        assert not outside.exists()
        assert not outside.with_name(outside.name + ".lock").exists()


@pytest.mark.parametrize("surface", ["cli", "mcp"])
@pytest.mark.parametrize("subject", ["root/token:lane-42", "ghp_" + "a" * 20], ids=["keyed", "token"])
def test_token_subject_refuses_before_history_publication(workspace, capsys, surface, subject):
    require_descriptors()
    code, _ = cli(capsys, arguments(record=True))
    assert code == 0
    history = workspace / "decisions.jsonl"
    before = history.read_bytes()
    args = arguments(record=True)
    args["subject"] = subject
    if surface == "cli":
        code, actual = cli(capsys, args)
        assert code == 2
    else:
        failed, actual = call(args)
        assert failed is True
    assert actual == {"error": "model_output_needs_redaction"}
    assert history.read_bytes() == before


@pytest.mark.parametrize("field", ["subject", "intent", "author_family", "lane_family", "review_stage", "host_kinds"])
def test_input_redaction_preflight_precedes_core_file_reads(workspace, capsys, field):
    args = arguments(record=True)
    args["bindings"] = "missing-bindings.json"
    token = "ghp_" + "a" * 20
    args[field] = [token] if field == "host_kinds" else token
    code, expected = cli(capsys, args)
    failed, actual = call(args)
    assert code == 2 and failed is True
    assert actual == expected == {"error": "model_output_needs_redaction"}
    assert not (workspace / args["history"]).exists()


@pytest.mark.parametrize("surface", ["cli", "mcp"])
def test_colliding_redacted_family_keys_refuse_instead_of_collapsing(workspace, capsys, surface):
    require_descriptors()
    path = workspace / "policy.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    names = {"first": "ghp_" + "a" * 20, "second": "ghp_" + "b" * 20}

    for key in ("manager_family", "team_family"):
        policy[key] = names[policy[key]]
    policy["family_order"] = [names[family] for family in policy["family_order"]]
    for key in ("target_shares", "family_hosts"):
        policy[key] = {names[family]: value for family, value in policy[key].items()}
    for stages in policy["review_families"].values():
        stages.update({stage: names.get(family, family) for stage, family in stages.items()})
    path.write_text(json.dumps(policy), encoding="utf-8")
    _, record = core.select_model(workspace / "bindings.json", path, "T9", "implementer", [],
                                  host_kinds=arguments()["host_kinds"], subject="lane-one")
    assert set(record["target_shares"]) == set(names.values())
    if surface == "cli":
        code, actual = cli(capsys, arguments())
        assert code == 2
    else:
        failed, actual = call(arguments())
        assert failed is True
    assert actual == {"error": "model_output_needs_redaction"}


@pytest.mark.parametrize("surface", ["cli", "mcp"])
@pytest.mark.parametrize("field", ["bindings", "policy", "history"])
def test_symlink_escape_refuses_before_outside_publication(workspace, capsys, surface, field):
    outside = workspace.parent / (workspace.name + "-outside-directory")
    outside.mkdir()
    args = arguments(record=True)
    if field != "history":
        (outside / args[field]).write_bytes((workspace / args[field]).read_bytes())
    symlink_or_skip(outside, workspace / "alias", target_is_directory=True)
    args[field] = "alias/" + args[field]
    if surface == "cli":
        code, actual = cli(capsys, args)
        assert code == 2
    else:
        failed, actual = call(args)
        assert failed is True
    assert actual == {"error": "invalid_model_arguments"}
    assert not (outside / "decisions.jsonl").exists()


@pytest.mark.parametrize("surface", ["cli", "mcp"])
def test_component_swap_after_confinement_keeps_no_follow_refusal(workspace, monkeypatch, capsys, surface):
    require_descriptors()
    directory = workspace / "configs"
    directory.mkdir()
    (directory / "bindings.json").write_bytes((workspace / "bindings.json").read_bytes())
    outside = workspace.parent / (workspace.name + "-outside-directory")
    outside.mkdir()
    (outside / "bindings.json").write_bytes((workspace / "bindings.json").read_bytes())
    switched = []

    def swap_open(name, flags, *args, **kwargs):
        if name == "configs" and "dir_fd" in kwargs and not switched:
            directory.rename(workspace / "original-configs")
            symlink_or_skip(outside, directory, target_is_directory=True)
            switched.append(True)
        return os.open(name, flags, *args, **kwargs)

    module_os = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    module_os.open = swap_open
    monkeypatch.setattr(core, "os", module_os)
    args = arguments(record=True)
    args["bindings"] = "configs/bindings.json"
    if surface == "cli":
        code, actual = cli(capsys, args)
        assert code == 2
    else:
        failed, actual = call(args)
        assert failed is True
    assert switched == [True]
    assert actual == {"error": "invalid_bindings"}
    assert not (workspace / "decisions.jsonl").exists()


@pytest.mark.parametrize("state", ["missing", "plain-directory", "empty-aegis"])
def test_uninitialized_workspace_matches_all_model_surfaces(workspace, monkeypatch, capsys, state):
    # A plain child of a valid workspace resolves to its initialized ancestor.
    # Keep truly uninitialized targets outside it, within the owning tmp_path.
    target = workspace.parent / "uninitialized"
    if state != "missing":
        target.mkdir()
        (target / "bindings.json").write_bytes(b"not JSON; must not be read")
        if state == "empty-aegis":
            (target / ".aegis").mkdir()
    monkeypatch.setattr(server, "_canonical_workspace", str(target))
    args = arguments()
    code, expected = cli(capsys, dict(args, workspace=str(target)))
    failed, actual = call(args)
    direct = execute_tool("aegis_team_model", dict(args, workspace=str(target)))
    assert code == 2 and failed is True
    assert actual == direct == expected == {"error": "model_workspace_unavailable"}
    assert not (target / args["history"]).exists()


@pytest.mark.parametrize("args", [{}, {"record": "false"}, dict(arguments(), subject=False),
                                  dict(arguments(), host_kinds="codex-cli"), dict(arguments(), record="false")],
                         ids=["empty", "record-only-string", "subject-type", "hosts-type", "record-type"])
def test_argument_refusal_precedes_held_workspace(workspace, monkeypatch, capsys, args):
    from aegis_core.workspace.binding import WorkspaceBinding

    monkeypatch.setattr(server, "_workspace_error", WorkspaceBinding(status="hold", reason="pin_conflict"))
    monkeypatch.setenv("AEGIS_WORKSPACE", str(workspace / "missing-pin"))
    assert main(["team", "model"]) == 2
    expected = json.loads(capsys.readouterr().out)
    failed, actual = call(args)
    assert failed is True
    assert actual == expected == {"error": "invalid_model_arguments"}


def test_workspace_refusal_precedes_path_refusal(workspace, monkeypatch, capsys):
    target = workspace / "missing-workspace"
    monkeypatch.setattr(server, "_canonical_workspace", str(target))
    args = arguments()
    args["history"] = "../outside.jsonl"
    code, expected = cli(capsys, dict(args, workspace=str(target)))
    failed, actual = call(args)
    assert code == 2 and failed is True
    assert actual == expected == {"error": "model_workspace_unavailable"}


def test_record_abbreviation_uses_the_same_parser_and_publication(workspace, capsys):
    require_descriptors()
    code, actual = cli(capsys, arguments(record=True), record_option="--rec")
    assert code == 0
    assert list(core.read_decisions(workspace / "decisions.jsonl")) == [actual["record"]]
