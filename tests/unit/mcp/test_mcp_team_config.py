"""Read-only team config uses the CLI payload, provenance and refusals."""
import argparse
import json
import os
from pathlib import Path

import pytest

from conftest import symlink_or_skip
from aegis_cli import team
from aegis_core import primitives, team_profile as profile
from aegis_core.workspace.base import Workspace
import aegis_mcp.server as server
from aegis_mcp.tools import execute_tool


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = (tmp_path / "workspace").resolve()
    (root / ".aegis" / "rules").mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(primitives, "utc_stamp", lambda moment=None: "2026-11-11T12:00:00Z")
    monkeypatch.setattr(server, "_canonical_workspace", str(root))
    monkeypatch.setattr(server, "_workspace_error", None)
    monkeypatch.setattr(server, "_session_id", None)
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    return root, home


def cli(root, capsys):
    args = argparse.Namespace(team_action="config", config_action="show", workspace=str(root), json=True)
    code = team.run_team(args)
    return code, json.loads(capsys.readouterr().out)


def call(arguments=None):
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "aegis_team_config", "arguments": {} if arguments is None else arguments}})
    assert "error" not in response, response
    result = response["result"]
    return result, json.loads(result["content"][0]["text"])


def write_profile(root, parts, document):
    target = root.joinpath(*parts)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


def require_descriptors():
    if not profile.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")


def test_registered_read_only_without_client_arguments(workspace):
    listed = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool = next(t for t in listed["result"]["tools"] if t["name"] == "aegis_team_config")
    assert tool["annotations"] == {"readOnlyHint": True, "destructiveHint": False,
                                   "idempotentHint": True, "openWorldHint": False, "title": "Team Config"}
    assert tool["inputSchema"] == {"type": "object", "properties": {}, "additionalProperties": False}


def test_exact_cli_payload_with_every_resolver_layer(workspace, monkeypatch, capsys):
    root, _ = workspace
    resolved = profile.resolve(
        repo={"run_config": {"limits": {"writers_max": 2}}},
        user={"run_config": {"runners": {"local": {"image": "test-image"}}}},
        flags={"run_config": {"runners": {"local": {"cpus": 3}}}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    code, expected = cli(root, capsys)
    result, actual = call()
    assert code == 0 and result["isError"] is False
    assert actual == expected
    assert {record["layer"] for record in actual["values"].values()} == {
        "defaults", "preset:solo", "repo", "user", "flags"}


def test_real_profiles_match_cli_and_write_nothing(workspace, capsys):
    require_descriptors()
    root, home = workspace
    write_profile(root, profile.REPO_PATH, {"version": 1, "preset": "pair",
                                          "run_config": {"limits": {"writers_max": 2}}})
    write_profile(home, profile.USER_PATH, {"version": 1, "run_config": {
        "runners": {"local": {"image": "test-image", "credentials": "private-value"}}}})
    before = {path: path.read_bytes() for base in (root, home) for path in base.rglob("*") if path.is_file()}
    code, expected = cli(root, capsys)
    result, actual = call()
    assert code == 0 and result["isError"] is False
    assert actual == expected
    assert actual["values"]["run_config.runners.local.image"]["layer"] == "user"
    assert actual["values"]["run_config.limits.writers_max"]["layer"] == "repo"
    assert "private-value" not in json.dumps(actual)
    assert {path: path.read_bytes() for base in (root, home) for path in base.rglob("*") if path.is_file()} == before


def test_missing_profiles_do_not_create_files(workspace, capsys):
    require_descriptors()
    root, home = workspace
    code, expected = cli(root, capsys)
    result, actual = call()
    assert code == 0 and result["isError"] is False and actual == expected
    assert list(home.iterdir()) == []
    assert list((root / ".aegis").iterdir()) == [root / ".aegis" / "rules"]


@pytest.mark.parametrize("layer", ["repo", "user"])
@pytest.mark.parametrize("data,reason", [(b'{"version":1,"unexpected":true}', "unknown key: unexpected"),
                                        (b"{bad JSON", "invalid profile JSON"),
                                        (b" " * (profile.MAX_BYTES + 1), "profile size limit exceeded")],
                         ids=["unknown-key", "malformed", "oversize"])
def test_file_refusals_match_cli(workspace, capsys, layer, data, reason):
    require_descriptors()
    root, home = workspace
    base, parts = (root, profile.REPO_PATH) if layer == "repo" else (home, profile.USER_PATH)
    target = write_profile(base, parts, {})
    target.write_bytes(data)
    code, expected = cli(root, capsys)
    result, actual = call()
    assert actual == expected
    assert (actual["status"], actual["layer"], actual["file"], actual["reason"]) == (
        "refused", layer, str(target), reason)
    assert code == 1 and result["isError"] is True


def test_unsupported_platform_refuses_like_cli(workspace, monkeypatch, capsys):
    root, _ = workspace
    monkeypatch.setattr(profile, "descriptor_supported", lambda: False)
    code, expected = cli(root, capsys)
    result, actual = call()
    assert actual == expected
    assert actual["reason"] == "unsupported platform: anchored profile operations unavailable"
    assert actual["layer"] == "repo"
    assert code == 1 and result["isError"] is True


@pytest.mark.parametrize("exception", [OSError, ValueError, RuntimeError])
def test_loader_failure_is_fixed_cli_refusal(workspace, monkeypatch, capsys, exception):
    root, _ = workspace

    def fail(root):
        raise exception("token=private-value\n\x1b[31m")

    monkeypatch.setattr(profile, "load", fail)
    code, expected = cli(root, capsys)
    result, actual = call()
    assert actual == expected
    assert actual["reason"] == "profile operation unavailable"
    assert actual["layer"] == "filesystem"
    assert "private-value" not in json.dumps(actual)
    assert code == 1 and result["isError"] is True


@pytest.mark.parametrize("argument", ["init", "force", "preset", "flags", "view", "token=private-value\n\x1b[31m"])
def test_client_arguments_refused_without_loading_or_echo(workspace, monkeypatch, argument):
    def unexpected(root):
        pytest.fail("invalid arguments reached the loader")

    monkeypatch.setattr(profile, "load", unexpected)
    result, actual = call({argument: "private-value"})
    assert actual["status"] == "refused"
    assert (actual["layer"], actual["file"], actual["reason"]) == (
        "flags", "<command-line>", "aegis_team_config accepts no arguments")
    assert "private-value" not in json.dumps(actual)
    assert result["isError"] is True


def test_direct_dispatch_uses_same_cli_payload(workspace, monkeypatch, capsys):
    root, _ = workspace
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve())
    code, expected = cli(root, capsys)
    assert code == 0
    assert execute_tool("aegis_team_config", {"workspace": str(root)}) == expected


@pytest.mark.parametrize("argument", sorted(server.SERVER_OWNED_KEYS))
def test_raw_reserved_client_key_refuses_before_stripping_binding_or_loading(workspace, monkeypatch, argument):
    def unexpected(*args, **kwargs):
        pytest.fail("raw client argument reached stripping, binding or loading")

    monkeypatch.setattr(server, "strip_server_owned", unexpected)
    monkeypatch.setattr(server, "_bind", unexpected)
    monkeypatch.setattr(profile, "load", unexpected)
    result, actual = call({argument: "token=private-value"})
    assert result["isError"] is True
    assert (actual["status"], actual["layer"], actual["file"], actual["reason"]) == (
        "refused", "flags", "<command-line>", "aegis_team_config accepts no arguments")
    assert actual["scope"] == {}
    assert "private-value" not in json.dumps(actual)


@pytest.mark.parametrize("arguments", [[], [1], "token=private-value", "", 0, False],
                         ids=["empty-array", "array", "string", "empty-string", "integer", "boolean"])
def test_nonobject_client_arguments_get_fixed_refusal(workspace, arguments):
    result, actual = call(arguments)
    assert result["isError"] is True
    assert (actual["status"], actual["layer"], actual["file"], actual["reason"]) == (
        "refused", "flags", "<command-line>", "aegis_team_config accepts no arguments")
    assert "private-value" not in json.dumps(actual)


def test_direct_profile_only_root_matches_cli(workspace, capsys):
    require_descriptors()
    root, home = workspace
    project = home / "profile-only"
    write_profile(project, profile.REPO_PATH, {"version": 1, "preset": "pair"})
    assert not (project / ".aegis" / "rules").exists()
    code, expected = cli(project, capsys)
    assert code == 0
    assert execute_tool("aegis_team_config", {"workspace": str(project)}) == expected


def test_injected_workspace_retains_cli_payload(workspace, monkeypatch, capsys):
    root, _ = workspace
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve())
    code, expected = cli(root, capsys)
    assert code == 0
    assert execute_tool("aegis_team_config", {"workspace": Workspace(root), "_host": "pytest",
                                             "_session": "server-session", "_binding": "pin"}) == expected


def test_missing_workspace_matches_cli_without_raw_token(workspace, monkeypatch, capsys):
    require_descriptors()
    from aegis_cli.cli import main

    root, _ = workspace
    missing = root / "absent" / "token=private-value"
    monkeypatch.chdir(root)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    assert main(["team", "config", "show", "--workspace", str(missing), "--json"]) == 0
    captured = capsys.readouterr()
    expected = json.loads(captured.out)
    actual = execute_tool("aegis_team_config", {"workspace": str(missing)})
    assert captured.err == ""
    assert actual == expected
    assert actual["status"] == "done"
    assert actual["profile"]["preset"] == "solo"
    assert str(missing) not in json.dumps(actual)
    assert "private-value" not in json.dumps(actual)


def test_direct_invalid_arguments_precede_workspace_resolution(workspace):
    root, _ = workspace
    missing = root / "absent" / "token=private-value"
    actual = execute_tool("aegis_team_config", {"workspace": str(missing), "force": True})
    assert (actual["status"], actual["layer"], actual["file"], actual["reason"]) == (
        "refused", "flags", "<command-line>", "aegis_team_config accepts no arguments")
    assert actual["scope"] == {}
    assert "private-value" not in json.dumps(actual)


@pytest.mark.parametrize("source", ["cwd", "pin"])
def test_default_root_uses_cli_resolution_without_rules(workspace, monkeypatch, capsys, source):
    root, _ = workspace
    project = root / "profile-only"
    write_profile(project, profile.REPO_PATH, {"version": 1})
    monkeypatch.chdir(project)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    if source == "pin":
        monkeypatch.setenv("AEGIS_WORKSPACE", str(project))
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve())
    code, expected = cli(project, capsys)
    assert code == 0
    assert execute_tool("aegis_team_config", {}) == expected


@pytest.mark.parametrize("raw", [0, False, {}, []], ids=["integer", "boolean", "object", "array"])
def test_nonpath_workspace_gets_fixed_refusal(workspace, monkeypatch, raw):
    def unexpected(root):
        pytest.fail("invalid workspace reached profile loading")

    monkeypatch.setattr(profile, "load", unexpected)
    actual = execute_tool("aegis_team_config", {"workspace": raw})
    assert (actual["status"], actual["layer"], actual["file"], actual["reason"]) == (
        "refused", "filesystem", "<workspace>", "profile operation unavailable")
    assert actual["scope"] == {}


@pytest.mark.parametrize("spelling", ["relative-string", "relative-path", "parent", "symlink", "subdirectory"])
def test_supplied_workspace_spellings_match_public_cli(workspace, monkeypatch, capsys, spelling):
    require_descriptors()
    from aegis_cli.cli import main

    root, _ = workspace
    write_profile(root, profile.REPO_PATH, {"version": 1, "preset": "pair"})
    nested = root / "src"
    nested.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    if spelling == "relative-string":
        raw = "."
    elif spelling == "relative-path":
        raw = Path(".")
    elif spelling == "parent":
        raw = root / "src" / ".."
    elif spelling == "symlink":
        raw = root.parent / "profile-alias"
        symlink_or_skip(root, raw, target_is_directory=True)
    else:
        raw = nested

    assert main(["team", "config", "show", "--workspace", str(raw), "--json"]) == 0
    expected = json.loads(capsys.readouterr().out)
    assert expected["profile"]["preset"] == "pair"
    actual = execute_tool("aegis_team_config", {"workspace": raw})
    assert actual == expected


@pytest.mark.parametrize("raw,preset", [
    pytest.param(".", "pair", id="dot-string"),
    pytest.param(Path("."), "pair", id="dot-path"),
    pytest.param("~/project", "pair", id="home-string"),
    pytest.param(Path("~/project"), "pair", id="home-path"),
    pytest.param("~/repo", "pair", id="argon0852-home-repo"),
    pytest.param("~<user>/project", "pair", id="user-home-string"),
    pytest.param(Path("~<user>/project"), "pair", id="user-home-path"),
    pytest.param("src", "pair", id="relative"),
    pytest.param(Path("src/.."), "pair", id="parent"),
    pytest.param(Path("absent/.."), "pair", id="missing-component-parent"),
    pytest.param(Path("../project-alias"), "pair", id="symlink"),
    pytest.param(Path("src/nested"), "pair", id="repository-subdirectory"),
    pytest.param("src/tracked.txt", "pair", id="file-string"),
    pytest.param(Path("src/tracked.txt"), "pair", id="file-path"),
    pytest.param("missing", "solo", id="missing"),
    pytest.param(Path("missing/token=private-value"), "solo", id="missing-token"),
    pytest.param("../token=private-value", "pair", id="token-path"),
])
def test_workspace_input_table_matches_public_cli(workspace, monkeypatch, capsys, raw, preset):
    require_descriptors()
    from aegis_cli.cli import main

    _, home = workspace
    project = home / "project"
    write_profile(project, profile.REPO_PATH, {"version": 1, "preset": "pair"})
    (project / "src" / "nested").mkdir(parents=True)
    (project / "src" / "tracked.txt").write_text("fixture", encoding="utf-8")
    monkeypatch.chdir(project)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    if str(raw).startswith("~<user>/"):
        if os.name != "posix":
            pytest.skip("requires a named home-directory user")
        import pwd

        try:
            account = pwd.getpwuid(os.getuid())
        except KeyError:
            pytest.skip("no home-directory user for the current uid")
        if not account.pw_dir or not account.pw_name:
            pytest.skip("no named user with a home directory")
        expanded = "~" + account.pw_name + "/" + os.path.relpath(project, account.pw_dir)
        raw = Path(expanded) if isinstance(raw, Path) else expanded
    elif raw == "~/repo":
        write_profile(home / "repo", profile.REPO_PATH, {"version": 1, "preset": "pair"})
        work = home.parent / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        assert not (work / "~").exists()
    elif raw == Path("../project-alias"):
        symlink_or_skip(project, home / "project-alias", target_is_directory=True)
    elif raw == "../token=private-value":
        write_profile(home / "token=private-value", profile.REPO_PATH, {"version": 1, "preset": "pair"})

    code = main(["team", "config", "show", "--workspace", str(raw), "--json"])
    captured = capsys.readouterr()
    expected = json.loads(captured.out)
    actual = execute_tool("aegis_team_config", {"workspace": raw})
    assert captured.err == ""
    assert actual == expected
    assert expected["status"] == "done"
    assert code == 0
    assert "private-value" not in json.dumps(actual)
    assert actual["profile"]["preset"] == preset
