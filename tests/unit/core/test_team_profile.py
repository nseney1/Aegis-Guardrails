"""Public profile validation, provenance and anchored storage."""
import argparse
import json
from types import SimpleNamespace

import pytest

from aegis_core import storage, storage_confined, team_profile as profile
from aegis_core import team_supervisor as supervisor_io
from aegis_core import team_status as profile_status
from aegis_core import team_hosts as profile_hosts
from aegis_core import config as profile_config
from aegis_cli import team as profile_cli


@pytest.mark.parametrize("surface", ["validate_resolved", "display_profile"])
@pytest.mark.parametrize("defect,reason,path", [
    ("envelope", "invalid value: profile", "profile"),
    ("native_type", "wrong type: run_config.limits.writers_max", "run_config.limits.writers_max"),
    ("required_first", "invalid value: supervisor", "supervisor"),
    ("string_limit", "profile string size limit exceeded", "preset"),
    ("unknown_host", "unregistered host kind: model_settings.hosts.primary.kind", "model_settings.hosts.primary.kind"),
])
@pytest.mark.parametrize("reverse", [False, True])
def test_schema_extraction_first_refusal_golden(surface, defect, reason, path, reverse):
    value = profile.resolve()
    if defect == "envelope":
        del value["profile"]
        value["values"] = None
    elif defect == "native_type":
        value["profile"]["run_config"]["limits"]["writers_max"] = True
    elif defect == "required_first":
        del value["profile"]["supervisor"]["components"]
        value["profile"]["supervisor"]["pauses"] = ["bad"]
    elif defect == "string_limit":
        value["profile"]["preset"] = "x" * 4097
    else:
        value["profile"]["model_settings"]["hosts"]["primary"]["kind"] = "private-input"
    value = _reordered_objects(value, reverse)
    before = json.dumps(value)
    for _ in range(2):
        with pytest.raises(profile.ProfileError) as refused:
            getattr(profile, surface)(value)
        error = refused.value
        assert (str(error), error.layer, error.path, error.exit_code) == (reason, "repo", path, 1)
        assert json.dumps(value) == before
    profile.validate_resolved(profile.resolve())


@pytest.mark.parametrize("document,reason,path", [
    ({}, "profile version required", None),
    ({"version": 1, "run_config": {"limits": {"writers_max": True}}},
     "wrong type: run_config.limits.writers_max", "run_config.limits.writers_max"),
    ({"version": 1, "preset": "x" * 4097}, "profile string size limit exceeded", None),
    ({"version": 1, "model_settings": {"hosts": {"primary": {"kind": "private-input"}}}},
     "unregistered host kind: model_settings.hosts.primary.kind", "model_settings.hosts.primary.kind"),
])
def test_schema_extraction_load_refusal_golden(tmp_path, document, reason, path):
    root = make_store(tmp_path)
    target = root.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    raw = json.dumps(document).encode("utf-8")
    target.write_bytes(raw)
    for _ in range(2):
        with pytest.raises(profile.ProfileError) as refused:
            profile.load(root, user_root=root)
        error = refused.value
        assert (str(error), error.layer, error.path, error.exit_code) == (reason, "repo", path, 1)
        assert error.file == str(target) and target.read_bytes() == raw


def test_profile_schema_validation_is_shared_below_both_facades():
    import ast
    from pathlib import Path
    from aegis_core import team_profile_schema

    assert supervisor_io.validate_input is team_profile_schema.validate_input
    assert supervisor_io.SupervisorError is team_profile_schema.SupervisorError
    assert profile.team_profile_schema is team_profile_schema
    for module in (team_profile_schema, profile, supervisor_io):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        definitions = [node for node in ast.walk(tree)
                       if isinstance(node, ast.FunctionDef) and node.name == "validate_input"]
        assert len(definitions) == int(module is team_profile_schema)
        if module is team_profile_schema:
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(node.module or "")
                    imports.extend((node.module or "") + "." + alias.name for alias in node.names)
            assert not {"aegis_core.team_profile", "aegis_core.team_supervisor"}.intersection(imports)


def test_schema_validation_budgets_are_isolated_across_concurrent_calls():
    from concurrent.futures import ThreadPoolExecutor

    valid = profile.resolve()
    bad = profile.resolve()
    bad["values"] = {"preset": {"path": ["preset"], "value": "x" * 4097}}
    before = json.dumps([valid, bad])

    def check(index):
        for _ in range(2):
            profile.validate_resolved(valid)
            shown = profile.display_profile(valid)
            with pytest.raises(profile.ProfileError) as refused:
                profile.validate_resolved(bad)
            assert (str(refused.value), refused.value.layer, refused.value.path) == (
                "profile string size limit exceeded", "repo", "preset")
        return shown

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check, range(6)))
    assert all(result == results[0] for result in results)
    assert json.dumps([valid, bad]) == before


@pytest.mark.parametrize("operation", ["load", "initialize"])
@pytest.mark.parametrize("limit,bound,message", [
    ("bytes", 13, "profile size limit exceeded"),
    ("depth", 1, "profile nesting limit exceeded"),
    ("nodes", 151, "profile node limit exceeded"),
    ("items", 1, "profile container size limit exceeded"),
    ("string", 7, "profile string size limit exceeded"),
])
@pytest.mark.parametrize("over", [False, True])
def test_json_preflight_boundary_golden(tmp_path, monkeypatch, operation, limit, bound, message, over):
    root = make_store(tmp_path)
    target = root.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    raw = b'{"version":1}'
    if limit == "nodes":
        raw = json.dumps({"version": 1, "policy": {"gates": [
            {"name": "g" + str(i), "runner": "local", "selector": "whole", "must_pass": True}
            for i in range(16)]}}).encode("utf-8")
    target.write_bytes(raw)
    limits = dict(bytes=10000, depth=16, nodes=4096, items=64, string=100)
    limits[limit] = bound - int(over)
    monkeypatch.setattr(profile, "MAX_BYTES", limits["bytes"])
    monkeypatch.setattr(profile, "MAX_DEPTH", limits["depth"])
    monkeypatch.setattr(profile, "MAX_NODES", limits["nodes"])
    monkeypatch.setattr(profile, "MAX_ITEMS", limits["items"])
    monkeypatch.setattr(profile, "MAX_STRING", limits["string"])
    if over:
        def forbidden(*args, **kwargs):
            pytest.fail("JSON tree allocated before the resource refusal")
        monkeypatch.setattr(profile, "json", SimpleNamespace(loads=forbidden, dumps=json.dumps))
    def run():
        if operation == "load":
            return profile.load(root, user_root=root)
        return profile.initialize(root, "solo", force=True)
    if over:
        for _ in range(2):
            with pytest.raises(profile.ProfileError) as refused:
                run()
            assert (str(refused.value), refused.value.exit_code, refused.value.layer) == (message, 1, "repo")
            assert target.read_bytes() == raw
    elif operation == "load":
        assert run() == {**profile.resolve(repo=json.loads(raw)), "repository_profile_exists": True}
    else:
        assert run() == {"version": 1, "preset": "solo"}


@pytest.mark.parametrize("operation", ["load", "initialize"])
@pytest.mark.parametrize("raw,message", [
    (b"[", "invalid profile JSON"),
    (b"\xff", "invalid profile JSON"),
    (b'{"version":NaN}', "invalid profile JSON"),
    (b'{"version":1,"version":1}', "duplicate key in profile JSON"),
    (b"{}", "profile version required"),
])
def test_json_parse_refusal_golden(tmp_path, operation, raw, message):
    root = make_store(tmp_path)
    target = root.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_bytes(raw)
    for _ in range(2):
        with pytest.raises(profile.ProfileError) as refused:
            if operation == "load":
                profile.load(root, user_root=root)
            else:
                profile.initialize(root, "solo", force=True)
        error = refused.value
        assert (str(error), error.exit_code, error.layer, error.file) == (message, 1, "repo", str(target))
        assert target.read_bytes() == raw


def make_store(root):
    if not profile.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    return root.resolve()


@pytest.mark.parametrize("name", ["solo", "pair", "mixed", "ci-only"])
def test_presets_resolve(name):
    result = profile.resolve(preset=name)
    assert result["profile"]["version"] == 1
    assert result["profile"]["policy"]["landing"]["signature_required_for"] == ["main"]
    assert result["profile"]["run_config"]["autopilot"]["rulings"] == "owner"
    if name == "solo":
        assert result["profile"]["policy"]["review"]["require_cross_family"] is False
    if name == "mixed":
        assert result["profile"]["model_settings"]["roles"]["lens.extra"]["hosts"] == []


@pytest.mark.parametrize("layer,document,message", [
    ("repo", {"run_config": {"oops": True}}, "unknown key: run_config.oops"),
    ("repo", {"model_settings": {"hosts": {"primary": {"auth_mode": "token"}}}}, "user-only"),
    ("repo", {"run_config": {"runners": {"remote": {"pool": "p"}}}}, "user-only"),
    ("repo", {"run_config": {"limits": {"writers_max": True}}}, "wrong type"),
    ("repo", {"version": 2}, "unsupported profile version"),
    ("repo", {"model_settings": {"hosts": {"primary": {"kind": "unknown"}}}}, "unregistered host kind"),
    ("repo", {"policy": {"landing": {"signature_required_for": []}}}, "governance"),
    ("user", {"run_config": {"autopilot": {"rulings": "coordinator"}}}, "governance"),
    ("flags", {"policy": {"landing": {"strategy": "direct"}}}, "governance"),
])
def test_refusals(layer, document, message):
    with pytest.raises(profile.ProfileError, match=message):
        profile.resolve(**{layer: document})


@pytest.mark.parametrize("terminal", ("hold", "skip"))
@pytest.mark.parametrize("section", ("hosts", "capacity"))
@pytest.mark.parametrize("layer,file", (("repo", ".aegis/team/profile.json"),
                                      ("user", "~/.config/aegis/team.json"), ("flags", "<command-line>")))
def test_terminal_host_alias_declarations_refuse_in_every_layer(terminal, section, layer, file):
    value = {} if section == "capacity" else {"auth_mode": "sso"} if layer == "user" else {"kind": "claude-code"}
    with pytest.raises(profile.ProfileError, match="host alias is reserved for a fallback terminal") as refused:
        profile.resolve(**{layer: {"model_settings": {section: {terminal: value}}}})
    assert refused.value.exit_code == 1 and refused.value.layer == layer and refused.value.file == file
    assert refused.value.path == "model_settings." + section + "." + terminal


@pytest.mark.parametrize("terminal", ("hold", "skip"))
@pytest.mark.parametrize("layer", ("repo", "user"))
@pytest.mark.parametrize("escaped", (False, True))
def test_terminal_host_aliases_refuse_at_load_after_json_decoding(tmp_path, terminal, layer, escaped):
    root = make_store(tmp_path)
    value = {"kind": "claude-code"} if layer == "repo" else {"auth_mode": "sso"}
    text = json.dumps({"version": 1, "model_settings": {"hosts": {terminal: value}}})
    if escaped:
        spelling = r"\u0068old" if terminal == "hold" else r"\u0073kip"
        text = text.replace('"' + terminal + '":', '"' + spelling + '":')
    target = root.joinpath(*(profile.REPO_PATH if layer == "repo" else profile.USER_PATH))
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text(text, encoding="utf-8")
    with pytest.raises(profile.ProfileError, match="host alias is reserved for a fallback terminal") as refused:
        profile.load(root, user_root=root)
    assert refused.value.exit_code == 1 and refused.value.layer == layer and refused.value.file == str(target)
    assert refused.value.path == "model_settings.hosts." + terminal


@pytest.mark.parametrize("alias", ("Hold", "SKIP", "hold.worker", "skip.worker"))
def test_distinct_host_aliases_keep_exact_identity(alias):
    result = profile.resolve(repo={"model_settings": {"hosts": {alias: {"kind": "claude-code"}},
        "capacity": {"primary": {"fallback": {"doc": [alias]}}}}})
    route = profile.plan(result["profile"], "doc", start_host="primary")
    assert route["entries"][1]["host"] == alias


def test_provenance_and_frozen_flags():
    result = profile.resolve(repo={"run_config": {"limits": {"writers_max": 2}}},
                             user={"run_config": {"runners": {"local": {"image": "test-image"}}}},
                             flags={"run_config": {"runners": {"local": {"cpus": 3}}}})
    values = result["values"]
    assert values["run_config.limits.writers_max"]["layer"] == "repo"
    assert values["run_config.runners.local.image"]["layer"] == "user"
    assert values["run_config.runners.local.cpus"]["layer"] == "flags"
    assert values["policy.review.require_cross_family"]["layer"] == "preset:solo"
    assert values["run_config.limits.writers_max"]["frozen_at_run_start"] is True
    with pytest.raises(profile.ProfileError, match="frozen_at_run_start"):
        profile.resolve(flags={"run_config": {"runners": {"local": {"cpus": 3}}}}, live_run=True)


def test_config_io_bounded_and_no_overwrite(tmp_path):
    root = make_store(tmp_path)
    profile.initialize(root, "pair")
    target = root / ".aegis/team/profile.json"
    assert json.loads(target.read_text())["preset"] == "pair"
    assert profile.load(root, user_root=root)["profile"]["preset"] == "pair"
    with pytest.raises(profile.ProfileError, match="already exists"):
        profile.initialize(root, "solo")
    profile.initialize(root, "solo", force=True)
    target.write_bytes(b" " * (profile.MAX_BYTES + 1))
    with pytest.raises(profile.ProfileError, match="size limit"):
        profile.load(root, user_root=root)


def test_symlink_component_refused(tmp_path):
    from conftest import symlink_or_skip
    root = make_store(tmp_path / "repo")
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_or_skip(outside, root / ".aegis", target_is_directory=True)
    with pytest.raises(profile.ProfileError, match="unsafe|unreadable"):
        profile.initialize(root, "solo")
    assert not list(outside.iterdir())


def test_unsupported_platform_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "descriptor_supported", lambda: False)
    with pytest.raises(profile.ProfileError, match="unsupported platform"):
        profile.initialize(tmp_path, "solo")
    with pytest.raises(profile.ProfileError, match="unsupported platform"):
        profile.load(tmp_path, user_root=tmp_path)


@pytest.mark.parametrize("data,message", [
    (b'{"version":1,"version":2}', "duplicate key"),
    (b'[' * 1000, "nesting limit"),
    (b'not json', "invalid profile JSON"),
    (b'\xff', "invalid profile JSON"),
])
def test_malformed_files(tmp_path, data, message):
    root = make_store(tmp_path)
    target = root / ".aegis/team/profile.json"
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_bytes(data)
    with pytest.raises(profile.ProfileError, match=message):
        profile.load(root, user_root=root)


def test_user_auth_never_exposed():
    from aegis_cli.team import display_profile
    resolved = profile.resolve(user={"model_settings": {"hosts": {"codex-cli": {"auth_mode": "token"}}},
                                     "run_config": {"runners": {"local": {"credentials": "secret-value"}}}})
    shown = display_profile(resolved)
    assert "secret-value" not in json.dumps(shown)
    assert shown["values"]["run_config.runners.local.credentials"]["value"] == "[REDACTED]"


def test_user_cannot_change_policy_by_selecting_preset():
    with pytest.raises(profile.ProfileError, match="governance"):
        profile.resolve(repo={"preset": "pair"}, user={"preset": "solo"})


def test_native_host_not_qualified():
    with pytest.raises(profile.ProfileError, match="not qualified"):
        profile.resolve(repo={"model_settings": {"hosts": {"primary": {"kind": "codex"}}}})


@pytest.mark.parametrize("role", ["writer", "reviewer.correctness", "reviewer.security", "research", "lens.extra"])
def test_candidate_host_cannot_enable_any_role(role):
    with pytest.raises(profile.ProfileError, match="^host kind not qualified for team-run roles$"):
        profile.resolve(repo={"model_settings": {
            "hosts": {"candidate": {"kind": "antigravity"}},
            "roles": {role: {"hosts": ["candidate"]}}}})


def test_fallback_must_be_declared_and_respect_pinned_family():
    with pytest.raises(profile.ProfileError, match="undeclared"):
        profile.resolve(repo={"model_settings": {"capacity": {"primary": {"fallback": {"review": ["absent"]}}}}})
    with pytest.raises(profile.ProfileError, match="pinned"):
        profile.resolve(preset="mixed", repo={"model_settings": {
            "capacity": {"primary": {"fallback": {"review": ["review"]}}}}})


@pytest.mark.parametrize("name", (
    "CAPACITY_DEFAULTS", "CAPACITY_KINDS", "JSON_SCHEMA", "MAX_BYTES", "MAX_DEPTH", "MAX_ITEMS",
    "MAX_NODES", "MAX_STRING", "MAX_HOSTS", "MAX_FALLBACK_CHAIN", "MAX_LENSES", "MAX_FALLBACK_EDGES",
    "PRESET_DATA", "PROFILE_SCHEMA", "REPO_PATH", "USER_PATH", "USER_JSON_SCHEMA", "ProfileError",
    "capacity_thresholds", "descriptor_supported", "doctor", "plan", "governance_status", "initialize",
    "load", "resolve", "validate_resolved", "display_profile", "NEXT_ACTION_TEMPLATES",
))
def test_shared_display_extraction_preserves_profile_exports(name):
    assert name in profile.__all__
    assert getattr(profile, name) is not None


def test_shared_display_defaults_preserve_mcp_redaction(tmp_path, monkeypatch):
    from aegis_cli import team
    from aegis_mcp.tools import execute_tool

    declared, ignored = "ghp_" + "A" * 20, "ghp_" + "B" * 20
    resolved = profile.resolve(repo={"model_settings": {
        "hosts": {declared: {"kind": "claude-code"}},
        "capacity": {"primary": {"fallback": {"writer": [declared]}}}}},
        user={"model_settings": {"capacity": {"codex-cli": {"fallback": {"writer": [ignored]}}}},
              "run_config": {"runners": {"local": {"credentials": "private-credential"}}}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    assert team.display_profile is profile.display_profile
    assert "display_profile" in profile.__all__
    payload = execute_tool("aegis_team_config", {"workspace": str(tmp_path)})
    assert payload["status"] == "done"
    assert declared not in payload["profile"]["model_settings"]["capacity"]["primary"]["fallback"]["writer"]
    record = "user.model_settings.capacity.codex-cli.fallback.writer"
    assert ignored not in payload["values"][record]["value"]
    assert "private-credential" not in json.dumps(payload)


def test_shared_display_capacity_formatting_is_explicit():
    host = "ghp_" + "A" * 20
    value = {"host": host, "next_action": "unused", "next_action_parts": [
        "Start the job on ", {"identifier": host}, "; capacity advice grants no execution authority."]}
    rendered = profile.display_profile(value, capacity=True)
    assert rendered["host"] == host and host in rendered["next_action"]
    assert host not in profile.display_profile(value)["host"]


def test_window_thresholds_inherit_host_values_and_keep_independent_overrides():
    capacity = {"usage_source": "subscription-window",
                "thresholds": {"hold_pct": 90, "route_pct": 85, "flex_route_pct": 75},
                "window_thresholds": {"5h": {"hold_pct": 65}, "7d": {"flex_route_pct": 70}}}
    resolved = profile.resolve(repo={"model_settings": {"capacity": {"primary": capacity}}})
    entry = profile.display_profile(resolved)["profile"]["model_settings"]["capacity"]["primary"]
    assert entry == capacity
    assert profile.capacity_thresholds(entry) == capacity["thresholds"]
    assert profile.capacity_thresholds(entry, window="5h") == {
        "hold_pct": 65, "route_pct": 65, "flex_route_pct": 65}
    assert profile.capacity_thresholds(entry, window="7d") == {
        "hold_pct": 90, "route_pct": 85, "flex_route_pct": 70}
    assert profile.capacity_thresholds(entry, window="30d") == capacity["thresholds"]


def test_window_threshold_order_refuses_at_the_window_and_user_conflicts_are_ignored():
    path = "model_settings.capacity.primary.window_thresholds.7d"
    with pytest.raises(profile.ProfileError, match="capacity thresholds must satisfy") as refused:
        profile.resolve(repo={"model_settings": {"capacity": {"primary": {
            "window_thresholds": {"7d": {"hold_pct": 70, "route_pct": 80}}}}}})
    assert refused.value.exit_code == 1
    assert refused.value.path == path
    resolved = profile.resolve(
        repo={"model_settings": {"capacity": {"primary": {
            "window_thresholds": {"7d": {"route_pct": 90}}}}}},
        user={"model_settings": {"capacity": {"codex-cli": {"thresholds": {"hold_pct": 80}}}}},
    )
    preference = resolved["values"]["user.model_settings.capacity.codex-cli.thresholds.hold_pct"]
    assert preference["status"] == "ignored"
    assert preference["reason"] == "threshold preferences conflict with repository"


def test_window_thresholds_refuse_an_oversized_map_first():
    path = "model_settings.capacity.primary.window_thresholds"
    with pytest.raises(profile.ProfileError, match="^profile object size limit exceeded$") as refused:
        profile.resolve(repo={"model_settings": {"capacity": {"primary": {
            "window_thresholds": {str(i): None for i in range(9)}}}}})
    assert refused.value.exit_code == 1
    assert refused.value.path == path


def test_redaction_after_canonicalization_before_truncation():
    from aegis_cli.team import display_profile
    value = "x" * 490 + " token=\x1b[31msuper-secret-credential" + "y" * 20
    shown = display_profile({"reason": value})["reason"]
    assert "super-secret" not in shown
    assert len(shown) <= 512


@pytest.mark.parametrize("operation", ["read", "write", "fstat"])
def test_descriptor_cleanup_on_failures(tmp_path, monkeypatch, operation):
    from types import SimpleNamespace
    import os
    root = make_store(tmp_path)
    profile.initialize(root, "solo")
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def failed(*args, **kwargs):
        raise OSError("untrusted failure")

    class ModuleOS(SimpleNamespace):
        def __getattr__(self, name):
            return getattr(os, name)

    module_os = ModuleOS(open=opened, close=closed, **{operation: failed})
    monkeypatch.setattr(storage_confined, "os", module_os)
    with pytest.raises(profile.ProfileError, match="unsafe|unreadable"):
        if operation == "write":
            profile.initialize(root, "pair", force=True)
        else:
            profile.load(root, user_root=root)
    assert live == set()
    from aegis_core import team_supervisor
    if operation == "read":
        assert team_supervisor.load_state(user_root=root)["components"]["autopilot"]["failures"] == []
    elif operation == "fstat":
        config = root / ".config" / "aegis"
        config.mkdir(mode=0o700, parents=True)
        with pytest.raises(team_supervisor.SupervisorError, match="unsafe|unreadable"):
            team_supervisor.load_state(user_root=root)
    else:
        config = root / ".config" / "aegis"
        config.mkdir(mode=0o700, parents=True)
        with pytest.raises(team_supervisor.SupervisorError, match="unsafe|unreadable"):
            team_supervisor.store_state(team_supervisor.empty_state(), user_root=root)
    assert live == set()


def test_rename_symlink_race_stays_anchored(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from conftest import symlink_or_skip
    import os
    root = make_store(tmp_path / "repo")
    root.mkdir()
    profile.initialize(root, "solo")
    outside = tmp_path / "outside"
    outside.mkdir()
    moved = root / "moved"
    changed = []

    def opened(path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        if path == "team" and not changed:
            (root / ".aegis" / "team").rename(moved)
            symlink_or_skip(outside, root / ".aegis" / "team", target_is_directory=True)
            changed.append(True)
        return fd

    class ModuleOS(SimpleNamespace):
        def __getattr__(self, name):
            return getattr(os, name)

    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=opened))
    result = profile.load(root, user_root=root)
    assert result["profile"]["preset"] == "solo"
    assert not list(outside.iterdir())


@pytest.mark.parametrize("field,value,message", [
    ("run_config", {"limits": {"writers_max": "1"}}, "wrong type"),
    ("model_settings", {"hosts": {"other": {}}}, "incomplete host"),
    ("model_settings", {"roles": {"writer": {"hosts": ["missing"]}}}, "undeclared"),
])
def test_incomplete_and_wrong_type(field, value, message):
    with pytest.raises(profile.ProfileError, match=message):
        profile.resolve(repo={field: value})


@pytest.mark.parametrize("document,message", [
    ({"version": 2}, "unsupported profile version"),
    ({"version": 1, "unknown": True}, "unknown key"),
])
def test_force_does_not_misread_future_or_unknown_schema(tmp_path, document, message):
    root = make_store(tmp_path)
    profile.initialize(root, "solo")
    target = root / ".aegis/team/profile.json"
    original = json.dumps(document)
    target.write_text(original)
    with pytest.raises(profile.ProfileError, match=message):
        profile.initialize(root, "solo", force=True)
    assert target.read_text() == original


@pytest.mark.parametrize("content,message", [
    ('{"version":1,"preset":"' + "a" * (profile.MAX_STRING + 1) + '"}', "string size limit"),
    (json.dumps({"version": 1, "unused": [[0] * 64 for _ in range(64)]}), "node limit"),
    (json.dumps({"version": 1, "unused": [0] * 65}), "container size limit"),
    (json.dumps({"version": 1, "unused": {str(i): 0 for i in range(65)}}), "container size limit"),
], ids=["string", "nodes", "array-items", "object-members"])
def test_limits_before_json_parse(tmp_path, monkeypatch, content, message):
    from types import SimpleNamespace
    root = make_store(tmp_path)
    target = root / ".aegis/team/profile.json"
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text(content)

    def forbidden(*args, **kwargs):
        pytest.fail("json.loads ran before the resource limit")

    monkeypatch.setattr(profile, "json", SimpleNamespace(loads=forbidden))
    with pytest.raises(profile.ProfileError, match=message):
        profile.load(root, user_root=root)


@pytest.mark.parametrize("limit,path", [
    ("hosts", "model_settings.hosts"), ("chain", "model_settings.capacity.h00.fallback.review"),
    ("lenses", "policy.review.lenses"), ("extra-lens", "policy.review.lenses"),
    ("edges", "model_settings.capacity"), ("reviewer-profile", "model_settings.hosts"),
])
def test_routing_limits_refuse_at_load_before_traversal(tmp_path, monkeypatch, limit, path):
    root = make_store(tmp_path)
    settings = {"hosts": {f"h{i:02d}": {"kind": "codex-cli"} for i in range(16)}}
    document = {"version": 1, "preset": "ci-only", "model_settings": settings}
    if limit == "reviewer-profile":
        names = [f"h{i:02d}" for i in range(64)]
        settings["hosts"] = {name: {"kind": "codex-cli"} for name in names}
        settings["roles"] = {kind: {"hosts": names[:1]} for kind in ("writer", "reviewer.correctness")}
        settings["capacity"] = {name: {"fallback": {"review": [names[(i + offset) % 64]
                                for offset in range(1, 41)]}} for i, name in enumerate(names)}
        document["policy"] = {"review": {"require_cross_family": False, "lenses": [
            {"name": f"audit{i:02d}", "host_pref": names[:1], "voting": True} for i in range(64)]}}
    elif limit == "hosts":
        settings["hosts"]["overflow"] = {"kind": "codex-cli"}
    elif limit == "chain":
        settings["capacity"] = {"h00": {"fallback": {"review": ["h00"] * 9}}}
    elif limit == "edges":
        settings["capacity"] = {"h00": {"fallback": {kind: ["h00"] * 8 for kind in profile.CAPACITY_KINDS}},
                                "h01": {"fallback": {"writer": ["h00"]}}}
    else:
        document["policy"] = {"review": {"lenses": [
            {"name": f"audit{i:02d}", "host_pref": ["h00"]} for i in range(17 if limit == "lenses" else 16)]}}
        if limit == "extra-lens":
            settings["roles"] = {"lens.extra": {"hosts": ["h00"], "optional": True}}
    target = root.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(document), encoding="utf-8")

    def forbidden(*args, **kwargs):
        pytest.fail("traversal started before refusing an oversized routing graph")

    monkeypatch.setattr(profile, "plan", forbidden)
    with pytest.raises(profile.ProfileError, match="limit exceeded") as refused:
        profile.load(root, user_root=root)
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert refused.value.file == str(target) and refused.value.path == path


def test_routing_host_limit_includes_preset_aliases(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("traversal started before counting the preset host")

    monkeypatch.setattr(profile, "plan", forbidden)
    with pytest.raises(profile.ProfileError, match="profile host limit exceeded") as refused:
        profile.resolve(repo={"model_settings": {"hosts": {
            f"h{i:02d}": {"kind": "codex-cli"} for i in range(16)}}})
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert refused.value.file == "/".join(profile.REPO_PATH) and refused.value.path == "model_settings.hosts"


@pytest.mark.parametrize("parts,component", [
    (profile.REPO_PATH, 0), (profile.REPO_PATH, 1), (profile.REPO_PATH, 2),
    (profile.USER_PATH, 2),
])
def test_each_untrusted_path_component_refuses_symlink(tmp_path, parts, component):
    from conftest import symlink_or_skip
    root = make_store(tmp_path)
    outside = root / "outside"
    outside.mkdir()
    if component == 2:
        destination = outside / "data.json"
        destination.write_text('{"version":1,"preset":"pair"}')
    else:
        destination = outside
    target = root.joinpath(*parts[:component + 1])
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    symlink_or_skip(destination, target, target_is_directory=component != 2)
    with pytest.raises(profile.ProfileError, match="unsafe|unreadable"):
        profile.load(root, user_root=root)


@pytest.mark.parametrize("alias", ["home", "config"])
@pytest.mark.parametrize("present", [False, True])
def test_user_root_aliases_resolve_before_anchored_read(tmp_path, monkeypatch, alias, present):
    from conftest import symlink_or_skip
    root = make_store(tmp_path / "repo")
    root.mkdir()
    home = tmp_path / "home"
    actual = tmp_path / "actual"
    actual.mkdir()
    if alias == "home":
        symlink_or_skip(actual, home, target_is_directory=True)
        config = actual / ".config"
    else:
        home.mkdir()
        symlink_or_skip(actual, home / ".config", target_is_directory=True)
        config = actual
    if present:
        target = config / "aegis/team.json"
        target.parent.mkdir(mode=0o700, parents=True)
        target.write_text('{"version":1,"run_config":{"runners":{"local":{"cpus":3}}}}')
    monkeypatch.setenv("HOME", str(home))
    result = profile.load(root)
    record = result["values"]["run_config.runners.local.cpus"]
    assert record["value"] == (3 if present else 1)
    assert record["layer"] == ("user" if present else "defaults")


@pytest.mark.parametrize("component", ["actual-config", "aegis"])
def test_user_alias_read_remains_anchored_during_rename(tmp_path, monkeypatch, component):
    from types import SimpleNamespace
    from conftest import symlink_or_skip
    import os
    root = make_store(tmp_path / "repo")
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    config = tmp_path / "actual-config"
    target = config / "aegis/team.json"
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text('{"version":1,"run_config":{"runners":{"local":{"cpus":3}}}}')
    symlink_or_skip(config, home / ".config", target_is_directory=True)
    outside = tmp_path / "outside"
    outside_target = outside / ("aegis/team.json" if component == "actual-config" else "team.json")
    outside_target.parent.mkdir(mode=0o700, parents=True)
    outside_target.write_text('{"version":1,"run_config":{"runners":{"local":{"cpus":9}}}}')
    changed = []

    def opened(path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        if path == component and not changed:
            original = config if component == "actual-config" else config / "aegis"
            original.rename(tmp_path / "moved")
            symlink_or_skip(outside, original, target_is_directory=True)
            changed.append(True)
        return fd

    class ModuleOS(SimpleNamespace):
        def __getattr__(self, name):
            return getattr(os, name)

    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=opened))
    result = profile.load(root, user_root=home)
    assert changed == [True]
    assert result["values"]["run_config.runners.local.cpus"]["value"] == 3


def test_repository_and_user_files_layer_with_origins(tmp_path):
    root = make_store(tmp_path)
    profile.initialize(root, "solo")
    (root / ".aegis/team/profile.json").write_text(json.dumps({
        "version": 1, "run_config": {"runners": {"local": {"cpus": 2}}}}))
    user = root / "home"
    target = user / ".config/aegis/team.json"
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text(json.dumps({"version": 1, "run_config": {"runners": {"local": {"cpus": 3}}}}))
    result = profile.load(root, user_root=user)
    assert result["values"]["run_config.runners.local.cpus"]["value"] == 3
    assert result["values"]["run_config.runners.local.cpus"]["layer"] == "user"


def test_repository_policy_is_settable_through_governance_path():
    result = profile.resolve(repo={
        "policy": {"review": {"cap": 3, "mode": "delta"},
                   "landing": {"strategy": "direct"},
                   "gates": [{"name": "checks", "runner": "local", "selector": "whole", "must_pass": True}]},
        "run_config": {"autopilot": {"claim_next": True}, "limits": {"votes_max": 3}},
    })
    assert result["values"]["policy.review.cap"] == {
        "value": 3, "layer": "repo", "frozen_at_run_start": False, "path": ["policy", "review", "cap"]}
    assert result["profile"]["policy"]["landing"]["strategy"] == "direct"
    assert result["profile"]["run_config"]["autopilot"]["claim_next"] is True
    assert result["profile"]["run_config"]["limits"]["votes_max"] == 3


@pytest.mark.parametrize("layer", ["user", "flags"])
@pytest.mark.parametrize("document", [
    {"policy": {"review": {"cap": None}}},
    {"policy": {"gates": []}},
    {"policy": {"landing": {"batch_max": 1}}},
    {"run_config": {"autopilot": {"queue_full_on_ready": True}}},
    {"run_config": {"limits": {"writers_max": 1}}},
], ids=["review", "gates", "landing", "autopilot", "limits"])
def test_policy_blocks_are_repository_only(layer, document):
    with pytest.raises(profile.ProfileError, match="governance policy is repository-only"):
        profile.resolve(**{layer: document})


def test_registry_data_matches_tracked_registry():
    # Source fixtures stay ordinary reads and require no git history.
    import ast
    from pathlib import Path
    tree = ast.parse((Path(__file__).resolve().parents[3] / "tools/hierarchy_hosts.py").read_text())
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Constant):
                constants[node.targets[0].id] = node.value.value
            if node.targets[0].id == "HOST_KINDS":
                kinds = {constants[item.id] for item in node.value.elts}
    from aegis_core import hosts
    candidates = {spec.id for spec in hosts.all_hosts() if spec.team_adapter}
    assert set(profile.PRESET_DATA["hosts"]) == kinds | candidates
    for kind in candidates - kinds:
        assert profile.PRESET_DATA["hosts"][kind]["writer"] is False
        assert profile.PRESET_DATA["hosts"][kind]["boundary"] is None
    registry = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "_HOSTS" for target in node.targets))
    for key, value in zip(registry.keys, registry.values):
        kind = constants[key.id]
        fields = {key.value: value for key, value in zip(value.keys, value.values)}
        scope = ast.literal_eval(fields["write_scope"])
        expected = {"family": ast.literal_eval(fields["family"]),
                    "boundary": scope["boundary"] if scope is not None else None,
                    "writer": ast.literal_eval(fields["qualification"])["writer"] != "refused"}
        assert {name: profile.PRESET_DATA["hosts"][kind][name] for name in expected} == expected


@pytest.mark.parametrize("preset", ["solo", "pair"])
@pytest.mark.parametrize("layer", ["user", "flags"])
@pytest.mark.parametrize("settings", [
    {"roles": {"reviewer.correctness": {"hosts": [], "optional": True}}},
    {"roles": {"reviewer.security": {"hosts": [], "optional": True}}},
    {"roles": {"reviewer.security": {"pinned_family": False}},
     "capacity": {"primary": {"fallback": {"review": ["review"]}}}},
    {"capacity": {"review": {"fallback": {"review": ["primary"]}}}},
], ids=["remove-correctness", "remove-security", "unpin-security", "fallback-to-writer"])
def test_review_routing_is_repository_only(layer, settings, preset):
    with pytest.raises(profile.ProfileError):
        profile.resolve(preset=preset, **{layer: {"model_settings": settings}})


@pytest.mark.parametrize("document,message", [
    ({"model_settings": {"capacity": {"review": {"fallback": {"review": ["primary"]}}}}}, "cross-family"),
    ({"policy": {"review": {"lenses": [{"name": "check", "host_pref": ["absent"], "voting": True}]}}}, "undeclared"),
    ({"policy": {"review": {"lenses": [{"name": "check", "host_pref": ["primary", "review"],
                                           "voting": False, "pinned_family": True}]}}}, "pinned"),
    ({"policy": {"review": {"lenses": [{"name": "check", "host_pref": ["primary"], "voting": True}]}}}, "cross-family"),
    ({"model_settings": {"roles": {"reviewer.correctness": {"optional": True, "hosts": []}}}}, "optional"),
], ids=["fallback", "unknown-lens-host", "pinned-lens", "same-family-lens", "optional-correctness"])
def test_every_review_route_is_validated(document, message):
    with pytest.raises(profile.ProfileError, match=message):
        profile.resolve(preset="pair", repo=document)


def test_transitive_review_fallback_and_pinned_host_kind_are_governed():
    with pytest.raises(profile.ProfileError, match="cross-family"):
        profile.resolve(preset="pair", repo={"model_settings": {
            "hosts": {"third": {"kind": "claude-code"}},
            "capacity": {"review": {"fallback": {"review": ["third"]}},
                         "third": {"fallback": {"review": ["primary"]}}}}})
    with pytest.raises(profile.ProfileError, match="repository-only"):
        profile.resolve(preset="pair", flags={"model_settings": {"hosts": {
            "primary": {"kind": "claude-code"}, "review": {"kind": "codex-cli"}}}})


def test_user_token_budgets_have_a_valid_path():
    result = profile.resolve(user={"run_config": {"token_budgets": {"writer": 1000}}})
    assert result["values"]["run_config.token_budgets.writer"]["value"] == 1000
    assert result["values"]["run_config.token_budgets.writer"]["layer"] == "user"
    for layer in ("repo", "flags"):
        with pytest.raises(profile.ProfileError, match="user-only"):
            profile.resolve(**{layer: {"run_config": {"token_budgets": {"writer": 1000}}}})


@pytest.mark.parametrize("preset", ["solo", "ci-only"])
def test_global_user_auth_is_keyed_by_kind_and_does_not_create_hosts(preset):
    result = profile.resolve(preset=preset, user={"model_settings": {"hosts": {
        "claude-code": {"auth_mode": "sso"}, "codex-cli": {"auth_mode": "token"}}}})
    assert set(result["profile"]["model_settings"]["hosts"]) == ({"primary"} if preset == "solo" else set())
    entry = result["values"]["user.model_settings.hosts.claude-code.auth_mode"]
    assert entry["status"] == "ignored" and entry["layer"] == "user"
    if preset == "solo":
        assert result["profile"]["model_settings"]["hosts"]["primary"]["auth_mode"] == "token"


def test_refusals_identify_layer_and_file():
    for layer, expected_file in (("repo", ".aegis/team/profile.json"),
                                 ("user", "~/.config/aegis/team.json"), ("flags", "<command-line>")):
        with pytest.raises(profile.ProfileError) as refused:
            profile.resolve(**{layer: {"run_config": {"unknown": True}}})
        assert refused.value.layer == layer
        assert refused.value.file == expected_file


def test_doctor_refuses_unvalidated_review_routes():
    resolved = profile.resolve(preset="pair")
    resolved["profile"]["model_settings"]["capacity"]["review"] = {"fallback": {"review": ["primary"]}}
    with pytest.raises(profile.ProfileError, match="cross-family"):
        profile.doctor(resolved)


@pytest.mark.parametrize("preset", ["solo", "ci-only"])
def test_populated_user_file_works_across_repository_presets(tmp_path, preset):
    root = make_store(tmp_path)
    profile.initialize(root, preset)
    user_root = root / "home"
    target = user_root / ".config/aegis/team.json"
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text(json.dumps({"version": 1, "model_settings": {"hosts": {
        "codex-cli": {"auth_mode": "sso"}, "claude-code": {"auth_mode": "token"}}}}))
    result = profile.load(root, user_root=user_root)
    assert result["values"]["user.model_settings.hosts.claude-code.auth_mode"]["status"] == "ignored"
    assert profile.doctor(result, root=root)["complete"] is True


def test_valid_cross_family_fallback_and_nonvoting_pinned_lens():
    result = profile.resolve(preset="pair", repo={"model_settings": {
        "hosts": {"alternate": {"kind": "claude-code"}},
        "capacity": {"review": {"fallback": {"review": ["alternate"]}}}},
        "policy": {"review": {"lenses": [{"name": "security", "host_pref": ["primary"],
                                           "voting": False, "pinned_family": True}]}}})
    assert result["profile"]["policy"]["review"]["require_cross_family"] is True


@pytest.mark.parametrize("layer,settings", [
    ("repo", {"hosts": {"primary": {"kind": "claude-code"}}}),
    ("flags", {"roles": {"writer": {"hosts": ["review"]}}}),
])
def test_semantic_refusals_name_the_overriding_layer(layer, settings):
    with pytest.raises(profile.ProfileError, match="cross-family") as refused:
        profile.resolve(preset="pair", **{layer: {"model_settings": settings}})
    assert refused.value.layer == layer
    assert refused.value.file == (".aegis/team/profile.json" if layer == "repo" else "<command-line>")


@pytest.mark.parametrize("preset", ["ci-only", "solo", "pair", "mixed"])
@pytest.mark.parametrize("entry", ["writer-model", "extra-model", "capacity", "auth", "writer-hosts"])
def test_user_overlay_only_applies_to_repository_targets(preset, entry):
    base = profile.resolve(preset=preset)["profile"]["model_settings"]
    if entry == "writer-model":
        settings = {"roles": {"writer": {"model": "preferred"}}}
        path, applies = "roles.writer.model", "writer" in base["roles"]
        targets = ["model_settings." + path] if applies else []
    elif entry == "extra-model":
        settings = {"roles": {"lens.extra": {"model": "preferred"}}}
        path, applies = "roles.lens.extra.model", "lens.extra" in base["roles"]
        targets = ["model_settings." + path] if applies else []
    elif entry == "capacity":
        settings = {"capacity": {"codex-cli": {"thresholds": {"hold_pct": 80}}}}
        path = "capacity.codex-cli.thresholds.hold_pct"
        targets = ["model_settings.capacity." + name + ".thresholds.hold_pct"
                   for name, host in base["hosts"].items() if host["kind"] == "codex-cli"]
        applies = bool(targets)
    elif entry == "auth":
        settings = {"hosts": {"codex-cli": {"auth_mode": "sso"}, "codex": {"auth_mode": "token"}}}
        path = "hosts.codex-cli.auth_mode"
        targets = ["model_settings.hosts." + name + ".auth_mode"
                   for name, host in base["hosts"].items() if host["kind"] == "codex-cli"]
        applies = bool(targets)
    else:
        settings = {"roles": {"writer": {"hosts": base["roles"].get("writer", {}).get("hosts", [])}}}
        path, applies = "roles.writer.hosts", "writer" in base["roles"]
        targets = ["model_settings." + path] if applies else []
    resolved = profile.resolve(preset=preset, user={"version": 1, "model_settings": settings})
    assert profile.doctor(resolved)["complete"] is True
    record = resolved["values"]["user.model_settings." + path]
    assert record["status"] == ("applied" if applies else "ignored")
    assert record["applied_to"] == targets and record["reason"]
    for target in targets:
        assert resolved["values"][target]["value"] == record["value"]
    if entry == "auth":
        assert resolved["values"]["user.model_settings.hosts.codex.auth_mode"]["status"] == "ignored"
    if not applies:
        assert resolved["profile"]["model_settings"] == base


@pytest.mark.parametrize("role,field,value", [
    ("writer", "hosts", ["absent"]), ("research", "hosts", []),
    ("writer", "optional", True), ("research", "pinned_family", True),
])
def test_user_structural_role_preferences_cannot_break_repository(role, field, value):
    resolved = profile.resolve(preset="pair", user={"model_settings": {"roles": {role: {field: value}}}})
    assert profile.doctor(resolved)["complete"] is True
    assert resolved["values"]["user.model_settings.roles." + role + "." + field]["status"] == "ignored"


@pytest.mark.parametrize("preset,settings,user_settings", [
    ("solo", {"roles": {"research": {"hosts": ["absent"]}}},
     {"hosts": {"claude-code": {"auth_mode": "sso"}}}),
    ("pair", {"capacity": {"review": {"fallback": {"review": ["primary"]}}}},
     {"roles": {"writer": {"hosts": ["primary"]}}}),
])
def test_repository_refusal_is_not_attributed_to_unrelated_user_entry(tmp_path, preset, settings, user_settings):
    root = make_store(tmp_path)
    repo_file = root.joinpath(*profile.REPO_PATH)
    repo_file.parent.mkdir(mode=0o700, parents=True)
    repo_file.write_text(json.dumps({"version": 1, "preset": preset, "model_settings": settings}))
    user_file = root.joinpath(*profile.USER_PATH)
    user_file.parent.mkdir(mode=0o700, parents=True)
    user_file.write_text(json.dumps({"version": 1, "model_settings": user_settings}))
    with pytest.raises(profile.ProfileError) as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == "repo" and refused.value.file == str(repo_file)


@pytest.mark.parametrize("role,preset,settings", [
    ("research", "pair", {}),
    ("writer", "solo", {"hosts": {"alternate": {"kind": "claude-code"}}}),
    ("reviewer.security", "solo", {"hosts": {"alternate": {"kind": "claude-code"}}}),
    ("reviewer.correctness", "solo", {"hosts": {"alternate": {"kind": "claude-code"}}}),
    ("lens.extra", "mixed", {}),
])
def test_every_role_family_pin_refuses_a_mixed_chain(role, preset, settings):
    chain = ["primary", "review" if preset in ("pair", "mixed") else "alternate"]
    settings = {**settings, "roles": {role: {"hosts": chain, "pinned_family": True}}}
    with pytest.raises(profile.ProfileError, match="pinned"):
        profile.resolve(preset=preset, repo={"model_settings": settings})


def test_stow_folded_aegis_directory_is_accepted_but_leaf_link_refuses(tmp_path):
    from conftest import symlink_or_skip
    root = make_store(tmp_path)
    actual = root / "dotfiles/aegis"
    actual.mkdir(mode=0o700, parents=True)
    target = actual / "team.json"
    target.write_text('{"version":1,"run_config":{"runners":{"local":{"cpus":3}}}}')
    config = root / ".config"
    config.mkdir()
    symlink_or_skip(actual, config / "aegis", target_is_directory=True)
    assert profile.load(root, user_root=root)["values"]["run_config.runners.local.cpus"]["value"] == 3
    target.rename(actual / "linked.json")
    symlink_or_skip(actual / "linked.json", target)
    with pytest.raises(profile.ProfileError, match="unsafe or unreadable") as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == "user" and refused.value.file == str(target)


@pytest.mark.parametrize("unsafe", ["owner", "group", "other"])
def test_stow_directory_requires_owner_and_private_write_access(tmp_path, monkeypatch, unsafe):
    from types import SimpleNamespace
    from conftest import symlink_or_skip
    import os
    root = make_store(tmp_path)
    actual = root / "dotfiles/aegis"
    actual.mkdir(mode=0o700, parents=True)
    (actual / "team.json").write_text('{"version":1}')
    config = root / ".config"
    config.mkdir()
    symlink_or_skip(actual, config / "aegis", target_is_directory=True)
    identity = actual.stat()

    def inspected(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            return SimpleNamespace(st_uid=info.st_uid + (1 if unsafe == "owner" else 0),
                                   st_mode=info.st_mode | {"owner": 0, "group": 0o020, "other": 0o002}[unsafe])
        return info

    class ModuleOS(SimpleNamespace):
        def __getattr__(self, name):
            return getattr(os, name)

    monkeypatch.setattr(storage_confined, "os", ModuleOS(fstat=inspected))
    with pytest.raises(profile.ProfileError, match="user profile directory must be owned by the current user and not group/other-writable") as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == "user" and refused.value.file == str(actual / "team.json")


def test_user_kind_preferences_bind_all_aliases_without_splitting_identifiers():
    result = profile.resolve(repo={"model_settings": {"hosts": {"alias.with.dots": {"kind": "codex-cli"}}}},
                             user={"model_settings": {"hosts": {"codex-cli": {"auth_mode": "sso"}},
                                                      "capacity": {"codex-cli": {"thresholds": {"hold_pct": 70}}}}})
    for alias in ("primary", "alias.with.dots"):
        assert result["profile"]["model_settings"]["hosts"][alias]["auth_mode"] == "sso"
        assert result["profile"]["model_settings"]["capacity"][alias]["thresholds"]["hold_pct"] == 70
    assert set(result["profile"]["model_settings"]["hosts"]) == {"primary", "alias.with.dots"}


def test_empty_user_objects_and_unbound_capacity_routes_do_not_create_origins():
    result = profile.resolve(user={"model_settings": {"capacity": {"codex-cli": {
        "thresholds": {}, "fallback": {"doc": ["absent"]}}}}, "run_config": {"runners": {"empty": {}}}})
    assert result["profile"]["model_settings"]["capacity"] == {}
    assert result["values"]["model_settings.capacity"]["layer"] == "defaults"
    assert "empty" not in result["profile"]["run_config"]["runners"]
    for path in ("thresholds", "fallback.doc"):
        record = result["values"]["user.model_settings.capacity.codex-cli." + path]
        assert record["status"] == "ignored" and record["reason"] and not record["applied_to"]


@pytest.mark.parametrize("role", ["writer", "research", "reviewer.correctness", "reviewer.security", "lens.extra"])
def test_role_pin_accepts_same_family_aliases(role):
    result = profile.resolve(repo={"model_settings": {
        "hosts": {"alternate": {"kind": "codex-cli"}},
        "roles": {role: {"hosts": ["primary", "alternate"], "pinned_family": True}}}})
    assert result["profile"]["model_settings"]["roles"][role]["pinned_family"] is True


@pytest.mark.parametrize("installed", [[], ["codex"], ["claude"], ["codex", "claude"]])
def test_doctor_lists_all_available_preset_bindings(monkeypatch, installed):
    from types import SimpleNamespace
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda name, **kw: "/qualified/" + name if name in installed else None))
    result = profile.doctor(profile.resolve())
    actual = {(item["preset"], item["host"]) for item in result["runnable_bindings"]}
    expected = {("ci-only", None)}
    for binary, kind in (("codex", "codex-cli"), ("claude", "claude-code")):
        if binary in installed:
            expected.add(("solo", kind))
            if set(installed) == {"codex", "claude"}:
                expected.update((preset, kind) for preset in ("pair", "mixed"))
    assert actual == expected
    assert set(result["runnable_presets"]) == {preset for preset, kind in expected}


@pytest.mark.parametrize("preference", [{"usage_source": "credits"}, {"thresholds": {"flex_route_pct": 70}}])
@pytest.mark.parametrize("route", ["review", "doc"])
def test_invalid_repository_capacity_leaf_outranks_user_siblings(preference, route):
    with pytest.raises(profile.ProfileError, match="capacity references undeclared host") as refused:
        profile.resolve(repo={"model_settings": {"capacity": {"primary": {"fallback": {route: ["absent"]}}}}},
                        user={"model_settings": {"capacity": {"codex-cli": preference}}})
    assert refused.value.path == "model_settings.capacity.primary.fallback." + route
    assert refused.value.layer == "repo" and refused.value.file == "/".join(profile.REPO_PATH)


@pytest.mark.parametrize("document", [
    {"policy": {"review": {"lenses": [{"name": "lens token=secret", "host_pref": ["primary"], "voting": False}]}}},
    {"model_settings": {"roles": {"writer": {"hosts": ["host token=secret"]}}}},
])
def test_identifier_fields_are_schema_constrained_without_echo(document):
    with pytest.raises(profile.ProfileError, match="invalid identifier") as refused:
        profile.resolve(repo=document)
    assert "token=secret" not in str(refused.value)


def test_research_pin_refusal_identifies_the_flag_that_added_it():
    with pytest.raises(profile.ProfileError, match="pinned") as refused:
        profile.resolve(preset="pair", flags={"model_settings": {"roles": {"research": {"pinned_family": True}}}})
    assert refused.value.layer == "flags" and refused.value.file == "<command-line>"


ATTRIBUTION_CASES = [
    ({"hosts": {"primary.fallback.review": {"kind": "codex-cli"}},
      "capacity": {"primary": {"fallback": {"review": ["absent"]}}}},
     {"capacity": {"codex-cli": {"usage_source": "credits"}}}, "solo"),
    ({"hosts": {"primary.fallback.doc": {"kind": "codex-cli"}},
      "capacity": {"primary": {"fallback": {"doc": ["absent"]}}}},
     {"capacity": {"codex-cli": {"usage_source": "credits"}}}, "solo"),
    ({"hosts": {"broken.child": {"kind": "codex-cli"}}, "capacity": {"broken": {}}},
     {"capacity": {"codex-cli": {"usage_source": "credits"}}}, "solo"),
    ({"hosts": {"broken": {}, "broken.child": {"kind": "codex-cli"}}},
     {"hosts": {"codex-cli": {"auth_mode": "sso"}}}, "solo"),
    ({"hosts": {"broken": {"kind": "codex"}, "broken.kind.child": {"kind": "codex-cli"}}},
     {"hosts": {"codex-cli": {"auth_mode": "sso"}}}, "solo"),
    ({"roles": {"research": {"pinned_family": True}}},
     {"roles": {"research": {"hosts": ["primary", "review"]}}}, "pair"),
    ({"hosts": {"review": {"kind": "codex-cli"}}}, {"roles": {"writer": {"hosts": ["primary"]}}}, "pair"),
    ({"roles": {"research": {"pinned_family": True}}}, {"roles": {"research": {"pinned_family": True}}}, "pair"),
    ({"hosts": {"alternate": {"kind": "claude-code"}},
      "roles": {"writer": {"hosts": ["primary", "alternate"], "pinned_family": True}}},
     {"roles": {"writer": {"hosts": ["primary", "alternate"]}}}, "solo"),
    ({"capacity": {"primary": {"fallback": {"doc": ["absent"]}}}},
     {"capacity": {"codex-cli": {"fallback": {"doc": ["absent"]}}}}, "solo"),
    ({"roles": {"writer": {"optional": True}}}, {"roles": {"writer": {"optional": True}}}, "solo"),
    ({"roles": {"research": {"optional": True}}}, {"roles": {"research": {"optional": True}}}, "solo"),
]


@pytest.mark.parametrize("settings,user_settings,preset", ATTRIBUTION_CASES)
@pytest.mark.parametrize("malformed_user", [False, True])
def test_counterfactual_repo_refusal_wins_regardless_of_user(settings, user_settings, preset, malformed_user):
    user = {"model_settings": user_settings}
    if malformed_user:
        user["unknown"] = "private-input"
    with pytest.raises(profile.ProfileError) as baseline:
        profile.resolve(repo={"preset": preset, "model_settings": settings})
    with pytest.raises(profile.ProfileError) as refused:
        profile.resolve(repo={"preset": preset, "model_settings": settings}, user=user)
    assert refused.value.layer == "repo" and refused.value.file == "/".join(profile.REPO_PATH)
    assert str(refused.value) == str(baseline.value)


@pytest.mark.parametrize("settings,user_settings,preset", ATTRIBUTION_CASES)
def test_counterfactual_user_refusal_when_repository_is_valid(settings, user_settings, preset):
    with pytest.raises(profile.ProfileError, match="unknown key: unknown") as refused:
        profile.resolve(repo={"preset": preset}, user={"model_settings": user_settings, "unknown": "private-input"})
    assert refused.value.layer == "user" and refused.value.file == "~/" + "/".join(profile.USER_PATH)
    assert "private-input" not in str(refused.value)


def test_repetitions_preserve_origins_and_have_explicit_records():
    result = profile.resolve(repo={"preset": "pair", "model_settings": {"roles": {"writer": {"model": "m"}},
                             "capacity": {"primary": {"usage_source": "credits"}}}},
                             user={"version": 1, "model_settings": {"roles": {"writer": {"hosts": ["primary"], "model": "m"}},
                                  "capacity": {"codex-cli": {"usage_source": "credits"}}},
                                  "run_config": {"runners": {"local": {"cpus": 1}}}})
    for path, layer in (("model_settings.roles.writer.hosts", "preset:pair"),
                        ("model_settings.roles.writer.model", "repo"),
                        ("model_settings.capacity.primary.usage_source", "repo"),
                        ("run_config.runners.local.cpus", "defaults")):
        assert result["values"][path]["layer"] == layer
    for path in ("model_settings.roles.writer.hosts", "model_settings.roles.writer.model",
                 "model_settings.capacity.codex-cli.usage_source", "run_config.runners.local.cpus"):
        record = result["values"]["user." + path]
        assert record["status"] == "applied" and record["reason"] == "repeats repository"


def test_provenance_keeps_colliding_dotted_alias_components_distinct():
    result = profile.resolve(repo={"model_settings": {
        "hosts": {"primary.fallback.doc": {"kind": "codex-cli"}},
        "capacity": {"primary": {"fallback": {"doc": ["primary"]}}, "primary.fallback.doc": {}}}})
    paths = {tuple(record["path"]) for record in result["values"].values()}
    assert ("model_settings", "capacity", "primary", "fallback", "doc") in paths
    assert ("model_settings", "capacity", "primary.fallback.doc") in paths


@pytest.mark.parametrize("settings,user_settings,preset", ATTRIBUTION_CASES)
@pytest.mark.parametrize("repo_defect", [False, True])
def test_counterfactual_file_table(tmp_path, settings, user_settings, preset, repo_defect):
    root = make_store(tmp_path)
    repo_file = root.joinpath(*profile.REPO_PATH)
    repo_file.parent.mkdir(mode=0o700, parents=True)
    repo_file.write_text(json.dumps({"version": 1, "preset": preset, "model_settings": settings if repo_defect else {}}))
    user_file = root.joinpath(*profile.USER_PATH)
    user_file.parent.mkdir(mode=0o700, parents=True)
    user_file.write_text(json.dumps({"version": 1, "model_settings": user_settings, **({} if repo_defect else {"unknown": True})}))
    with pytest.raises(profile.ProfileError) as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == ("repo" if repo_defect else "user")
    assert refused.value.file == str(repo_file if repo_defect else user_file)


@pytest.mark.parametrize("repo_defect", [False, True])
def test_counterfactual_attribution_includes_user_parse_failures(tmp_path, repo_defect):
    root = make_store(tmp_path)
    repo_file = root.joinpath(*profile.REPO_PATH)
    repo_file.parent.mkdir(mode=0o700, parents=True)
    repo_file.write_text(json.dumps({"version": 1, "model_settings": {
        "hosts": {"broken": {}}} if repo_defect else {}}))
    user_file = root.joinpath(*profile.USER_PATH)
    user_file.parent.mkdir(mode=0o700, parents=True)
    user_file.write_bytes(b"{malformed private-input")
    with pytest.raises(profile.ProfileError) as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == ("repo" if repo_defect else "user")
    assert refused.value.file == str(repo_file if repo_defect else user_file)
    assert str(refused.value) == ("incomplete host: kind required" if repo_defect else "invalid profile JSON")


@pytest.mark.parametrize("repo,flags,message", [
    ({"model_settings": {"hosts": {"alternate": {"kind": "claude-code"}},
                         "roles": {"writer": {"hosts": ["primary", "alternate"]}}}},
     {"model_settings": {"roles": {"writer": {"pinned_family": True}}}}, "optional/pinned-family settings are repository-only; use the approval-before-merge path"),
    ({"preset": "ci-only"}, {"model_settings": {"roles": {"writer": {"model": "m"}}}}, "incomplete role: declared hosts required"),
    ({}, {"model_settings": {"roles": {"lens.extra": {"model": "m"}}}}, "incomplete role: declared hosts required"),
    ({}, {"model_settings": {"roles": {"lens.extra": {}}}}, "incomplete role: declared hosts required"),
])
def test_argon_flag_defects_name_flags_after_valid_repo_counterfactual(repo, flags, message):
    assert profile.resolve(repo=repo)["profile"]["version"] == 1
    with pytest.raises(profile.ProfileError) as refused:
        profile.resolve(repo=repo, flags=flags)
    assert str(refused.value) == message
    assert refused.value.layer == "flags" and refused.value.file == "<command-line>"


def test_kind_preference_only_merges_nonrepeating_targets():
    result = profile.resolve(repo={"model_settings": {"hosts": {"alternate.with.dots": {"kind": "codex-cli"}},
        "capacity": {"primary": {"usage_source": "credits"}}}},
        user={"model_settings": {"capacity": {"codex-cli": {"usage_source": "credits"}}}})
    values = {tuple(record["path"]): record for record in result["values"].values()}
    assert values[("model_settings", "capacity", "primary", "usage_source")]["layer"] == "repo"
    assert values[("model_settings", "capacity", "alternate.with.dots", "usage_source")]["layer"] == "user"


@pytest.mark.parametrize("flags", [{"unknown": True}, {"policy": {}}])
def test_first_refusing_layer_wins_even_when_later_flags_fail_validation(flags):
    with pytest.raises(profile.ProfileError, match="governance: select the preset in the repository profile") as refused:
        profile.resolve(repo={"preset": "pair"}, user={"preset": "solo"}, flags=flags)
    assert refused.value.layer == "user" and refused.value.file == "~/" + "/".join(profile.USER_PATH)


@pytest.mark.parametrize("present", [False, True])
def test_load_records_repository_profile_presence_from_anchored_read(tmp_path, present):
    root = make_store(tmp_path)
    if present:
        profile.initialize(root, "solo")
    resolved = profile.load(root, user_root=root)
    assert resolved["repository_profile_exists"] is present


def test_profile_reads_and_publishes_through_shared_storage(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    original = storage.confined_file
    calls = []

    def confined(root, parts, **kwargs):
        calls.append(tuple(parts))
        return original(root, parts, **kwargs)

    monkeypatch.setattr(storage, "confined_file", confined)
    profile.initialize(root, "solo")
    loaded = profile.load(root, user_root=root)
    assert loaded["profile"]["preset"] == "solo"
    assert loaded["profile"]["supervisor"]["components"]["autopilot"]["enabled"] is False
    assert calls == [profile.REPO_PATH, profile.REPO_PATH, profile.USER_PATH[-1:]]


def test_relative_or_malformed_user_root_refuses_before_resolve(tmp_path):
    from pathlib import Path
    message = "^user profile root unavailable; configure a home directory$"
    for user_root in ("", ".", Path("."), Path("relative"), "relative", 15, "/tmp/bad\x00path"):
        with pytest.raises(profile.ProfileError, match=message) as refused:
            profile.load(tmp_path, user_root=user_root)
        assert refused.value.layer == "user" and refused.value.exit_code == 1
        assert "\x00" not in str(refused.value) and "bad" not in str(refused.value)


def test_validate_resolved_refuses_supervisor_bounds():
    resolved = profile.resolve()
    resolved["profile"]["supervisor"]["components"]["autopilot"]["restart"]["window_s"] = 0
    with pytest.raises(profile.ProfileError, match="^value out of range: supervisor.components.autopilot.restart.window_s$") as refused:
        profile.validate_resolved(resolved)
    assert refused.value.layer == "repo" and "0" not in str(refused.value)


@pytest.mark.parametrize("bad", [15, [], None, {"extra": "private-input"}, {"profile": None}, {"profile": {}}])
def test_validate_resolved_envelope_refuses_malformed_inputs(bad):
    with pytest.raises(profile.ProfileError) as refused:
        profile.validate_resolved(bad)
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert "private-input" not in str(refused.value)


@pytest.mark.parametrize("bad", [15, [], {}, None])
def test_load_refuses_malformed_repository_root_before_conversion(tmp_path, bad):
    with pytest.raises(profile.ProfileError, match="^unsafe profile root; use an absolute trusted directory$") as refused:
        profile.load(bad, user_root=tmp_path)
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"


@pytest.mark.parametrize("bad", [15, [], {}])
def test_validate_resolved_refuses_malformed_repository_root(tmp_path, bad):
    with pytest.raises(profile.ProfileError, match="^unsafe profile root; use an absolute trusted directory$") as refused:
        profile.validate_resolved(profile.resolve(), root=bad)
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"


def test_world_writable_owner_profile_refuses_before_parsing(tmp_path):
    root = make_store(tmp_path)
    target = root.joinpath(*profile.USER_PATH)
    target.parent.mkdir(mode=0o755, parents=True)
    target.parent.chmod(0o755)
    target.write_bytes(b'{invalid private-input')
    target.chmod(0o666)
    with pytest.raises(profile.ProfileError, match="^user profile file must be owned by the current user and not group/other-writable$") as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == "user" and refused.value.file == str(target)
    assert target.read_bytes() == b'{invalid private-input'


def test_owner_profile_uid_is_checked_on_the_open_descriptor(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    root = make_store(tmp_path)
    target = root.joinpath(*profile.USER_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text(json.dumps({"version": 1}), encoding="utf-8")

    def foreign(fd):
        info = os.fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_size=info.st_size, st_uid=os.getuid() + 1)

    monkeypatch.setattr(supervisor_io, "os", SimpleNamespace(**{**vars(os), "fstat": foreign}))
    with pytest.raises(profile.ProfileError, match="^user profile file must be owned by the current user and not group/other-writable$") as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == "user"


def test_owner_profile_leaf_replacement_cannot_change_the_checked_bytes(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    from conftest import symlink_or_skip
    root = make_store(tmp_path)
    target = root.joinpath(*profile.USER_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text(json.dumps({"version": 1, "supervisor": {"pauses": ["owner"]}}), encoding="utf-8")
    outside = root / "outside.json"
    outside.write_text(json.dumps({"version": 1, "supervisor": {"components": {"writer": {"enabled": True}}}}), encoding="utf-8")
    opened_once = []

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        try:
            target.rename(target.with_name("held.json"))
            symlink_or_skip(outside, target)
            opened_once.append(fd)
        except BaseException:
            os.close(fd)
            raise
        return fd

    monkeypatch.setattr(supervisor_io, "os", SimpleNamespace(**{**vars(os), "open": opened}))
    loaded = profile.load(root, user_root=root)
    assert len(opened_once) == 1
    assert loaded["profile"]["supervisor"]["pauses"] == ["owner"]
    assert loaded["profile"]["supervisor"]["components"]["writer"]["enabled"] is False


def _widened_repo():
    return {"version": 1, "supervisor": {"components": {"autopilot": {"restart": {"limit": 4}}}}}


def test_owner_ceiling_is_used_before_flag_attribution():
    repo = _widened_repo()
    user = {"supervisor": {"components": {"autopilot": {"restart": {"limit": 5}}}}}
    assert profile.resolve(repo=repo, user=user)["profile"]["supervisor"]["components"]["autopilot"]["restart"]["limit"] == 4
    with pytest.raises(profile.ProfileError, match="^supervisor settings are owner-file only$") as refused:
        profile.resolve(repo=repo, user=user, flags={"supervisor": {}})
    assert refused.value.layer == "flags"
    user["supervisor"]["components"]["autopilot"]["restart"]["limit"] = 3
    with pytest.raises(profile.ProfileError, match="cannot be widened") as refused:
        profile.resolve(repo=repo, user=user)
    assert refused.value.layer == "repo"


@pytest.mark.parametrize("defect,message", [
    ("key", "unknown key: unknown"),
    ("json", "invalid profile JSON"),
    ("directory", "user profile directory must be owned by the current user and not group/other-writable"),
])
def test_owner_failure_not_blamed_on_repo_above_default_ceiling(tmp_path, defect, message):
    from aegis_core import team_status
    root = make_store(tmp_path)
    repo_file = root.joinpath(*profile.REPO_PATH)
    repo_file.parent.mkdir(parents=True)
    repo_file.write_text(json.dumps(_widened_repo()), encoding="utf-8")
    user_file = root.joinpath(*profile.USER_PATH)
    user_file.parent.mkdir(mode=0o700, parents=True)
    user = {"version": 1, "unknown": True} if defect == "key" else {"version": 1}
    user_file.write_text(json.dumps(user) if defect != "json" else "{private-input", encoding="utf-8")
    if defect == "directory":
        user_file.parent.chmod(0o770)
    with pytest.raises(profile.ProfileError) as refused:
        profile.load(root, user_root=root)
    assert str(refused.value) == message and refused.value.layer == "user"
    assert refused.value.file == str(user_file)
    health = team_status.supervisor_health(root, 0, user_root=root)
    assert health["profile"] == "refused" and health["reason"] == message and health["layer"] == "user"


def test_validated_root_does_not_use_the_home_lookup_facade(tmp_path, monkeypatch):
    from types import SimpleNamespace

    class HomeLookup:
        @staticmethod
        def home():
            raise KeyError("private-input")

    monkeypatch.setattr(profile, "Path", HomeLookup)
    monkeypatch.setattr(profile, "UserLayout", SimpleNamespace(current=lambda: None))
    with pytest.raises(profile.ProfileError, match="^user profile root unavailable; configure a home directory$") as refused:
        profile.load(tmp_path)
    assert refused.value.layer == "user" and refused.value.exit_code == 1
    assert refused.value.file == "~/" + "/".join(profile.USER_PATH)


@pytest.mark.parametrize("root_kind", ["string", "path"])
def test_repository_roots_are_converted_from_validated_spelling(tmp_path, root_kind):
    root = str(tmp_path) if root_kind == "string" else tmp_path
    with pytest.raises(profile.ProfileError, match="^user profile root unavailable; configure a home directory$") as refused:
        profile.load(root, user_root="")
    assert refused.value.layer == "user" and "private-input" not in str(refused.value)


@pytest.mark.parametrize("root_kind", ["pathlike", "path_subclass"])
def test_non_path_root_is_refused_without_calling_fspath(tmp_path, root_kind):
    class ForeignPath:
        def __fspath__(self):
            pytest.fail("unvalidated path-like object was converted")

    class PathSubclass(type(tmp_path)):
        def __fspath__(self):
            pytest.fail("unvalidated path subclass was converted")

    root = ForeignPath() if root_kind == "pathlike" else PathSubclass(str(tmp_path))
    with pytest.raises(profile.ProfileError, match="^unsafe profile root; use an absolute trusted directory$") as refused:
        profile.load(root, user_root=tmp_path)
    assert refused.value.layer == "repo" and refused.value.exit_code == 1


@pytest.mark.parametrize("error_type", [TypeError, ValueError])
@pytest.mark.parametrize("consumer", ["load", "resolved_home"])
def test_root_subclass_spelling_errors_are_layered_refusals(tmp_path, error_type, consumer):
    called = []

    class BrokenPath(type(tmp_path)):
        def __str__(self):
            called.append(True)
            raise error_type("private-input")

    root = BrokenPath(str(tmp_path))
    if consumer == "load":
        with pytest.raises(profile.ProfileError, match="^unsafe profile root; use an absolute trusted directory$") as refused:
            profile.load(root, user_root=tmp_path)
        assert refused.value.layer == "repo" and refused.value.exit_code == 1
    else:
        with pytest.raises(supervisor_io.SupervisorError, match="^user profile root unavailable; configure a home directory$") as refused:
            supervisor_io.resolved_home(root)
        assert refused.value.layer == "user"
    assert "private-input" not in str(refused.value)
    assert called == []


def _reordered_objects(value, reverse):
    if type(value) is dict:
        keys = sorted(value, reverse=reverse)
        return {key: _reordered_objects(value[key], reverse) for key in keys}
    if type(value) is list:
        return [_reordered_objects(item, reverse) for item in value]
    return value


@pytest.mark.parametrize("surface", ["resolve", "validate_resolved"])
@pytest.mark.parametrize("reverse", [False, True])
def test_host_limit_precedes_lens_limit_for_every_object_order(surface, reverse):
    resolved = profile.resolve(preset="ci-only")
    body = resolved["profile"]
    body["model_settings"]["hosts"] = {
        "h%02d" % index: {"kind": "codex-cli"} for index in range(profile.MAX_HOSTS + 1)}
    body["policy"]["review"]["lenses"] = [
        {"name": "audit%02d" % index, "host_pref": ["h00"]}
        for index in range(profile.MAX_LENSES + 1)]
    resolved = _reordered_objects(resolved, reverse)
    with pytest.raises(profile.ProfileError, match="limit exceeded") as refused:
        if surface == "resolve":
            profile.resolve(repo=resolved["profile"])
        else:
            profile.validate_resolved(resolved)
    assert refused.value.path == "model_settings.hosts"
    assert refused.value.layer == "repo" and refused.value.exit_code == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_dynamic_profile_maps_use_identifier_order_for_refusals(reverse):
    runners = {"z-runner": {"cpus": False}, "a-runner": {"cpus": False}}
    document = _reordered_objects({"run_config": {"runners": runners}}, reverse)
    with pytest.raises(profile.ProfileError, match="^wrong type: run_config.runners.a-runner.cpus$") as refused:
        profile.resolve(repo=document)
    assert refused.value.path == "run_config.runners.a-runner.cpus"


@pytest.mark.parametrize("bad", [15, [], {}, None])
def test_initialize_rejects_root_types_before_io(bad):
    with pytest.raises(profile.ProfileError, match="^unsafe profile root; use an absolute trusted directory$") as refused:
        profile.initialize(bad, "solo")
    assert refused.value.layer == "repo" and refused.value.exit_code == 1


@pytest.mark.parametrize("defect,path", [
    ("hosts", "model_settings.hosts.a-host"),
    ("roles", "model_settings.roles.research.hosts"),
    ("capacity", "model_settings.capacity.a-host"),
    ("pinned", "model_settings.roles.research.hosts"),
    ("routes", "model_settings.capacity.primary.fallback.review"),
])
@pytest.mark.parametrize("reverse", [False, True])
def test_semantic_refusals_use_identifier_order(defect, path, reverse):
    document = {"preset": "ci-only", "model_settings": {}}
    settings = document["model_settings"]
    if defect == "hosts":
        settings["hosts"] = {"z-host": {}, "a-host": {}}
    elif defect == "roles":
        settings["roles"] = {"writer": {}, "research": {}}
    elif defect == "capacity":
        settings["capacity"] = {"z-host": {}, "a-host": {}}
    elif defect == "pinned":
        settings["hosts"] = {"codex": {"kind": "codex-cli"}, "claude": {"kind": "claude-code"}}
        settings["roles"] = {name: {"hosts": ["codex", "claude"], "pinned_family": True}
                             for name in ("writer", "research")}
    else:
        settings["hosts"] = {"primary": {"kind": "codex-cli"}}
        settings["roles"] = {name: {"hosts": ["primary"]} for name in ("writer", "reviewer.correctness")}
        settings["capacity"] = {"primary": {"fallback": {"writer": ["skip"], "review": ["skip"]}}}
    with pytest.raises(profile.ProfileError) as refused:
        profile.resolve(repo=_reordered_objects(document, reverse))
    assert refused.value.path == path and refused.value.layer == "repo"


@pytest.mark.parametrize("reverse", [False, True])
def test_supervisor_conflicts_use_component_order(reverse):
    body = profile.resolve()["profile"]["supervisor"]
    for name in ("monitor", "autopilot"):
        body["components"][name]["restart"].update(initial_s=50, max_s=40)
    with pytest.raises(supervisor_io.SupervisorError) as refused:
        supervisor_io.require_resolved(_reordered_objects(body, reverse))
    assert refused.value.path == "supervisor.components.autopilot.restart.initial_s"
    assert refused.value.layer == "repo"


_ROUTE_REASON = {
    "cross_family": "cross-family review route reaches the writer family",
    "admission": "fallback destination is not admitted for this job",
    "pinned_family": "pinned lens fallback changes family",
    "terminal": "skip is allowed only for non-voting jobs",
}
_ROUTE_PAIRS = [
    ("writer", ("admission", "terminal"), "admission"),
    ("review", ("cross_family", "admission"), "cross_family"),
    ("review", ("cross_family", "terminal"), "cross_family"),
    ("review", ("cross_family", "pinned_family"), "cross_family"),
    ("review", ("admission", "terminal"), "admission"),
    ("review", ("pinned_family", "terminal"), "pinned_family"),
    ("review", ("admission", "pinned_family"), "admission"),
]


def _route_pair_document(route_kind, failures):
    hosts = {"w": {"kind": "codex-cli"}, "clean": {"kind": "claude-code"},
             "r": {"kind": "claude-code"}, "a": {"kind": "claude-code"},
             "leak": {"kind": "codex-cli" if "cross_family" in failures or "pinned_family" in failures else "claude-code"}}
    roles = {"writer": {"hosts": ["w"]}, "reviewer.correctness": {"hosts": ["clean"]}}
    lenses = []
    first, fallback = ("w", "writer") if route_kind == "writer" else ("r", "research" if route_kind == "other" else "review")
    if route_kind == "writer":
        hosts["a"] = {"kind": "codex-cli"}
        if "admission" not in failures:
            hosts["leak"] = {"kind": "codex-cli"}
    elif route_kind == "other":
        hosts["leak"] = {"kind": "codex-cli"}
    binding = [first, "a"]
    if "admission" not in failures and "pinned_family" not in failures:
        binding.append("leak")
    if route_kind == "review" and "pinned_family" in failures:
        lenses = [{"name": "audit", "host_pref": binding, "voting": True, "pinned_family": True}]
    else:
        role = "writer" if route_kind == "writer" else "research" if route_kind == "other" else "reviewer.correctness"
        roles[role] = {"hosts": binding}
    terminal = "skip" if "terminal" in failures else "hold"
    capacity = {first: {"fallback": {fallback: ["a", "leak"]}},
                "a": {"fallback": {fallback: [first, terminal]}}}
    if failures == ("admission", "pinned_family"):
        # Admission is inactive on a pinned route; two review lenses make both
        # rules fail together without fabricating an impossible route shape.
        hosts.update({"b": {"kind": "codex-cli"}, "foreign": {"kind": "claude-code"}})
        lenses = [{"name": "a-pin", "host_pref": ["w", "b"], "voting": False, "pinned_family": True},
                  {"name": "z-admission", "host_pref": ["r", "a"], "voting": True}]
        roles["reviewer.correctness"] = {"hosts": ["clean"]}
        capacity.update({"w": {"fallback": {"review": ["b", "foreign"]}},
                         "b": {"fallback": {"review": ["w", "hold"]}}})
    return {"preset": "ci-only", "policy": {"review": {
        "require_cross_family": "cross_family" in failures or route_kind in ("writer", "other"), "lenses": lenses}},
        "model_settings": {"hosts": hosts, "roles": roles, "capacity": capacity}}


def _route_snapshot(document):
    snapshot = profile.resolve(preset=document["preset"])
    snapshot["profile"]["policy"]["review"].update(document["policy"]["review"])
    snapshot["profile"]["model_settings"].update(document["model_settings"])
    return snapshot


@pytest.mark.parametrize("route_kind,failures,winner", _ROUTE_PAIRS)
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("surface", ["resolve", "consumer", "check", "status", "doctor", "supervisor"])
def test_route_kind_refusal_precedence(tmp_path, monkeypatch, capsys, route_kind, failures, winner, reverse, surface):
    document = _reordered_objects(_route_pair_document(route_kind, failures), reverse)
    before = json.dumps(document)
    if surface == "resolve" and not reverse:
        for failure in failures:
            with pytest.raises(profile.ProfileError) as isolated:
                profile.resolve(repo=_route_pair_document(route_kind, (failure,)))
            assert str(isolated.value) == _ROUTE_REASON[failure]
    if surface in ("resolve", "consumer"):
        with pytest.raises(profile.ProfileError) as refused:
            if surface == "resolve":
                profile.resolve(repo=document)
            else:
                profile.validate_resolved(_route_snapshot(document))
        reason, layer = str(refused.value), refused.value.layer
        assert refused.value.exit_code == 1
    else:
        monkeypatch.setattr(profile, "load", lambda root, **kwargs: profile.resolve(repo=document))
        if surface == "supervisor":
            result = profile_status.supervisor_health(tmp_path, 0, user_root=tmp_path)
            assert result["profile"] == "refused" and result["start"] == []
            assert "components" not in result and "observations" not in result
        else:
            parser = argparse.ArgumentParser()
            profile_cli.TeamCommand().configure_parser(parser)
            argv = ["doctor"] if surface == "doctor" else ["hosts", "status"] if surface == "status" else ["hosts", "check", "w", "writer"]
            args = parser.parse_args(argv + ["--json"])
            args.workspace = str(tmp_path)
            assert profile_cli.run_team(args) == 1
            result = json.loads(capsys.readouterr().out)
            assert result["status"] == "refused"
        reason, layer = result["reason"], result["layer"]
    assert reason == _ROUTE_REASON[winner] and layer == "repo"
    assert json.dumps(document) == before


@pytest.mark.parametrize("failures", [("terminal",), ("admission",), ("admission", "terminal")])
@pytest.mark.parametrize("reverse", [False, True])
def test_nonreview_routes_allow_skip_and_do_not_apply_reviewer_independence(failures, reverse):
    document = _reordered_objects(_route_pair_document("other", failures), reverse)
    if "admission" in failures:
        with pytest.raises(profile.ProfileError, match="^fallback destination is not admitted for this job$"):
            profile.resolve(repo=document)
    else:
        resolved = profile.resolve(repo=document)
        profile.validate_resolved(resolved)
        assert "leak" in resolved["profile"]["model_settings"]["roles"]["research"]["hosts"]


def _numeric_field_bounds(schema, path=(), user_only=False):
    user_only = user_only or schema.get("user_layer_only", False) or path[:1] == ("supervisor",)
    types = schema["type"] if type(schema["type"]) is list else [schema["type"]]
    if "integer" in types or "number" in types:
        bounds = (schema["minimum"], schema["maximum"]) if "minimum" in schema else (1,)
        for bound in dict.fromkeys(bounds):
            yield path, bound, user_only
    for name, child in schema.get("properties", {}).items():
        yield from _numeric_field_bounds(child, (*path, name), user_only)
    for child in schema.get("patternProperties", {}).values():
        name = "local" if path == ("run_config", "runners") else "writer" if path == ("run_config", "token_budgets") else "primary"
        if path[-1:] == ("window_thresholds",):
            name = "5h"
        yield from _numeric_field_bounds(child, (*path, name), user_only)


@pytest.mark.parametrize("path,bound,user_only", list(_numeric_field_bounds(profile.JSON_SCHEMA)))
def test_numeric_schema_bounds_round_trip_through_provenance(path, bound, user_only):
    patch = {}
    dest = patch
    for part in path[:-1]:
        dest = dest.setdefault(part, {})
    if path[-2:-1] == ("restart",):
        dest.update(initial_s=1, max_s=86400)
    if path[:2] == ("model_settings", "capacity"):
        dest.update(hold_pct=bound, route_pct=bound, flex_route_pct=bound)
    dest[path[-1]] = bound
    result = profile.resolve(**{"user" if user_only else "repo": patch})
    profile.validate_resolved(result)
    profile.validate_resolved(json.loads(json.dumps(result)))


@pytest.mark.parametrize("gate_count,test_count", [(32, 64), (58, 64), (64, 32)])
def test_large_valid_profile_and_copied_provenance_have_separate_budgets(gate_count, test_count):
    gates = [{"name": "g%02d" % i, "runner": "local", "selector": "list", "must_pass": True,
              "tests": ["t.py"] * test_count} for i in range(gate_count)]
    resolved = profile.resolve(repo={"policy": {"gates": gates}})
    profile.validate_resolved(resolved)
    profile.validate_resolved(json.loads(json.dumps(resolved)))
    if gate_count == 58:
        with pytest.raises(profile.ProfileError, match="profile nesting or node limit exceeded"):
            profile.resolve(repo={"policy": {"gates": gates + [gates[0]]}})


@pytest.mark.parametrize("gate_count,test_count", [(32, 64), (64, 32)])
def test_large_profile_and_numeric_upper_bound_reach_consumers(tmp_path, gate_count, test_count):
    root = make_store(tmp_path)
    repo_file = root.joinpath(*profile.REPO_PATH)
    repo_file.parent.mkdir(mode=0o700, parents=True)
    gates = [{"name": "g%02d" % i, "runner": "local", "selector": "list", "must_pass": True,
              "tests": ["t.py"] * test_count} for i in range(gate_count)]
    repo_file.write_text(json.dumps({"version": 1, "policy": {"gates": gates}}), encoding="utf-8")
    user_file = root.joinpath(*profile.USER_PATH)
    user_file.parent.mkdir(mode=0o700, parents=True)
    user_file.write_text(json.dumps({"version": 1, "supervisor": {"health": {"disk_floor_mib": 1048576}}}),
                         encoding="utf-8")
    result = profile.load(root, user_root=root)
    assert profile.doctor(result, root)["complete"] is True
    assert profile_hosts.HostCapacity(result).check("primary", "writer")["decision"] == "go"
    assert profile_status.supervisor_health(root, 0, user_root=root)["profile"] == "valid"


def test_provenance_value_uses_its_field_schema_and_keeps_user_records():
    result = profile.resolve(user={"supervisor": {"health": {"disk_floor_mib": 1048576}},
        "model_settings": {"hosts": {"codex-cli": {"auth_mode": "token"}},
                           "roles": {"writer": {"model": "preferred"}}}})
    profile.validate_resolved(json.loads(json.dumps(result)))
    result["values"]["supervisor.health.disk_floor_mib"]["value"] = 1048577
    with pytest.raises(profile.ProfileError, match="^value out of range: supervisor.health.disk_floor_mib$"):
        profile.validate_resolved(result)


@pytest.mark.parametrize("records", [
    None, [], {1: {}}, {"x" * 4097: {}}, {str(i): {} for i in range(4097)},
    {"x": None}, {"x": {"path": ["preset"]}}, {"x": {"value": "solo"}},
    {"x": {"path": [], "value": "solo"}},
    {"x": {"path": ["unknown"], "value": "solo"}},
    {"x": {"path": ["user"], "value": "solo"}},
    {"x": {"path": ["preset"], "value": "solo", "unknown": True}},
    {"x": {"path": ["preset"], "value": "solo"},
     "y": {"path": ["preset"], "value": "solo"}},
])
def test_malformed_provenance_has_a_fixed_refusal(records):
    result = profile.resolve()
    result["values"] = records
    with pytest.raises(profile.ProfileError, match="^invalid value: profile provenance$") as refused:
        profile.validate_resolved(result)
    assert refused.value.path == "values" and refused.value.layer == "repo"
    assert refused.value.exit_code == 1


@pytest.mark.parametrize("field,value,reason,path", [
    ("path", None, "wrong type: values.path", "values.path"),
    ("path", [None], "wrong type: values.path.0", "values.path.0"),
    ("path", ["preset"] * 18, "profile array size limit exceeded: values.path", "values.path"),
    ("path", ["x" * 65], "profile string size limit exceeded", "values.path.0"),
    ("layer", "x" * 4097, "profile string size limit exceeded", "values.layer"),
    ("applied_paths", [["preset"]] * 65, "profile array size limit exceeded: values.applied_paths", "values.applied_paths"),
    ("value", None, "wrong type: preset", "preset"),
    ("value", "bad", "invalid value: preset", "preset"),
])
def test_provenance_metadata_and_field_values_keep_their_bounds(field, value, reason, path):
    result = profile.resolve()
    result["values"] = {"preset": {"path": ["preset"], "value": "solo", field: value}}
    with pytest.raises(profile.ProfileError) as refused:
        profile.validate_resolved(result)
    assert str(refused.value) == reason and refused.value.path == path
    assert refused.value.layer == "repo" and refused.value.exit_code == 1


_EARLY_PROFILE_FAILURES = [
    ({"preset": "bad"}, "invalid value: preset", "preset"),
    ({"version": 2}, "unsupported profile version; upgrade aegis", "version"),
    ({"model_settings": {"hosts": []}}, "wrong type: model_settings.hosts", "model_settings.hosts"),
    ({"policy": {"review": {"mode": "bad"}}}, "invalid value: policy.review.mode", "policy.review.mode"),
    ({"run_config": {"runners": []}}, "wrong type: run_config.runners", "run_config.runners"),
]


def _overlay_test_fields(target, patch):
    for key, value in patch.items():
        if type(value) is dict and type(target.get(key)) is dict:
            _overlay_test_fields(target[key], value)
        else:
            target[key] = value


@pytest.mark.parametrize("earlier,reason,path", _EARLY_PROFILE_FAILURES)
@pytest.mark.parametrize("layer", ["repo", "user"])
@pytest.mark.parametrize("surface", ["resolve", "load", "supervisor", "consumer"])
def test_earlier_profile_refusals_precede_supervisor_validation(tmp_path, earlier, reason, path, layer, surface):
    document = {**earlier, "supervisor": {"health": []}}
    if surface == "consumer":
        resolved = profile.resolve()
        _overlay_test_fields(resolved["profile"], document)
        with pytest.raises(profile.ProfileError) as refused:
            profile.validate_resolved(resolved)
        assert str(refused.value) == reason and refused.value.path == path
    elif surface == "resolve":
        with pytest.raises(profile.ProfileError) as refused:
            profile.resolve(**{layer: document})
        assert str(refused.value) == reason and refused.value.path == path
        assert refused.value.layer == layer
    else:
        root = make_store(tmp_path)
        target = root.joinpath(*(profile.REPO_PATH if layer == "repo" else profile.USER_PATH))
        target.parent.mkdir(mode=0o700, parents=True)
        target.write_text(json.dumps({"version": 1, **document}), encoding="utf-8")
        if surface == "load":
            with pytest.raises(profile.ProfileError) as refused:
                profile.load(root, user_root=root)
            assert str(refused.value) == reason and refused.value.path == path
            assert refused.value.layer == layer
        else:
            health = profile_status.supervisor_health(root, 0, user_root=root)
            assert health["profile"] == "refused" and health["reason"] == reason
            assert health["path"] == path and health["layer"] == layer


def test_flags_keep_owner_only_refusal_after_earlier_schema_fields():
    with pytest.raises(profile.ProfileError, match="^invalid value: preset$"):
        profile.resolve(flags={"preset": "bad", "supervisor": None})
    with pytest.raises(profile.ProfileError, match="^supervisor settings are owner-file only$"):
        profile.resolve(flags={"supervisor": None})


_ENVELOPE_REFUSALS = {
    "missing_profile": ("invalid value: profile", "profile"),
    "missing_values": ("invalid value: values", "values"),
    "missing_write_scope": ("invalid value: write_scope", "write_scope"),
    "profile_only": ("invalid value: values", "values"),
    "missing_model_settings": ("invalid value: model_settings", "model_settings"),
    "empty_supervisor": ("invalid value: supervisor", "supervisor"),
    "missing_supervisor_health": ("invalid value: supervisor", "supervisor"),
    "conflicting_restart": ("value out of range: supervisor.components.autopilot.restart.initial_s",
                            "supervisor.components.autopilot.restart.initial_s"),
    "incomplete_host": ("incomplete host: kind required", "model_settings.hosts.primary"),
    "invalid_values": ("invalid value: profile provenance", "values"),
    "invalid_write_scope": ("wrong type: write_scope", "write_scope"),
}


def _malformed_resolved_envelope(defects):
    value = profile.resolve()
    for defect in defects:
        if defect in ("missing_profile", "missing_values", "missing_write_scope"):
            del value[defect.removeprefix("missing_")]
        elif defect == "profile_only":
            value = {"profile": value["profile"]}
        elif defect == "missing_model_settings":
            del value["profile"]["model_settings"]
        elif defect == "empty_supervisor":
            value["profile"]["supervisor"] = {}
        elif defect == "missing_supervisor_health":
            del value["profile"]["supervisor"]["health"]
        elif defect == "conflicting_restart":
            value["profile"]["supervisor"]["components"]["autopilot"]["restart"]["initial_s"] = 400
        elif defect == "incomplete_host":
            del value["profile"]["model_settings"]["hosts"]["primary"]["kind"]
        elif defect == "invalid_values":
            value["values"] = None
        elif defect == "invalid_write_scope":
            value["write_scope"] = None
        else:
            raise AssertionError("unknown test defect")
    return value


_ENVELOPE_SURFACES = ["validate", "doctor", "display", "host_status", "host_check", "host_usage",
                      "cli_status", "cli_check", "cli_usage", "cli_doctor", "supervisor"]
_ENVELOPE_PAIRS = [
    (first, second) for first in ("empty_supervisor", "conflicting_restart", "incomplete_host",
                                  "missing_model_settings")
    for second in ("invalid_values", "invalid_write_scope", "missing_values", "missing_write_scope")
] + [("invalid_values", "invalid_write_scope"), ("invalid_values", "missing_write_scope"),
     ("missing_values", "invalid_write_scope"), ("missing_profile", "invalid_values"),
     ("empty_supervisor", "invalid_values", "invalid_write_scope")]


@pytest.mark.parametrize("defects", [(name,) for name in _ENVELOPE_REFUSALS] + _ENVELOPE_PAIRS)
@pytest.mark.parametrize("surface", _ENVELOPE_SURFACES)
@pytest.mark.parametrize("reverse", [False, True])
def test_resolved_envelope_refusals_and_precedence_across_consumers(tmp_path, monkeypatch, capsys,
                                                                  defects, surface, reverse):
    value = _reordered_objects(_malformed_resolved_envelope(defects), reverse)
    before = json.dumps(value)
    reason, path = _ENVELOPE_REFUSALS[defects[0]]
    if surface.startswith("cli_") or surface == "supervisor":
        monkeypatch.setattr(profile, "load", lambda root, **kwargs: value)
        if surface == "supervisor":
            def unread_state(**kwargs):
                raise AssertionError("invalid profiles must refuse before state access")

            monkeypatch.setattr(supervisor_io, "load_state", unread_state)
            result = profile_status.supervisor_health(tmp_path, 0, user_root=tmp_path)
            assert result["profile"] == "refused" and result["start"] == []
            assert result["path"] == path and "components" not in result
        else:
            parser = argparse.ArgumentParser()
            profile_cli.TeamCommand().configure_parser(parser)
            verb = surface.removeprefix("cli_")
            argv = ["doctor"] if verb == "doctor" else ["hosts", verb]
            if verb == "check":
                argv += ["primary", "writer"]
            args = parser.parse_args(argv + ["--json"])
            args.workspace = str(tmp_path)
            assert profile_cli.run_team(args) == 1
            result = json.loads(capsys.readouterr().out)
            assert result["status"] == "refused"
        assert result["reason"] == reason and result["layer"] == "repo"
    else:
        with pytest.raises(profile.ProfileError) as refused:
            if surface == "validate":
                profile.validate_resolved(value)
            elif surface == "doctor":
                profile.doctor(value)
            elif surface == "display":
                profile.display_profile(value)
            else:
                service = profile_hosts.HostCapacity(value)
                if surface == "host_check":
                    service.check("primary", "writer")
                elif surface == "host_status":
                    service.status()
                else:
                    service.usage()
        assert str(refused.value) == reason and refused.value.path == path
        assert refused.value.layer == "repo" and refused.value.exit_code == 1
    assert json.dumps(value) == before


@pytest.mark.parametrize("position", ["key", "schema"])
def test_display_rejects_malformed_discriminators_before_conversion_hooks(position):
    class Untrusted:
        def __hash__(self):
            return hash("profile")

        def __eq__(self, other):
            raise AssertionError("input conversion hook must not run")

    value = {Untrusted(): True} if position == "key" else {**profile.resolve(), "schema": Untrusted()}
    with pytest.raises(profile.ProfileError) as refused:
        profile.display_profile(value)
    assert str(refused.value) == "invalid value: profile display"
    assert refused.value.layer == "repo" and refused.value.exit_code == 1


@pytest.mark.parametrize("value", [None, [], 15, {}])
def test_display_accepts_native_diagnostic_roots(value):
    shown = profile.display_profile(value)
    assert shown == value
    if type(value) in (dict, list):
        assert shown is not value


@pytest.mark.parametrize("kind", ["show", "init", "body"])
def test_display_preserves_valid_command_views_and_profile_body(kind):
    resolved = profile.resolve()
    value = resolved["profile"] if kind == "body" else {
        "schema": "aegis.team.config." + kind + "/v1", "status": "done",
        **(resolved if kind == "show" else {"profile": resolved["profile"]})}
    before = json.dumps(value)
    assert profile.display_profile(value) == value
    assert json.dumps(value) == before


def test_display_does_not_treat_an_unknown_schema_as_a_command_view():
    value = {**profile.resolve(), "schema": "unknown"}
    with pytest.raises(profile.ProfileError, match="^unknown key: schema$"):
        profile.display_profile(value)


_AGGREGATE_CASES = {
    "runners_default": ("profile object size limit exceeded", "repo"),
    "runners_layers": ("profile object size limit exceeded", "user"),
    "hosts_default": ("profile host limit exceeded", "repo"),
    "lenses_extra": ("profile lens limit exceeded", "repo"),
    "fallback_edges": ("profile fallback edge limit exceeded", "repo"),
    "token_budgets": ("profile container size limit exceeded", "user"),
}


def _aggregate_bound_documents(case, overflow):
    repo, user = {"version": 1}, {"version": 1}
    if case == "runners_default":
        repo["run_config"] = {"runners": {"r%d" % i: {"cpus": 1} for i in range(63 + overflow)}}
    elif case == "runners_layers":
        repo["run_config"] = {"runners": {"r%d" % i: {"cpus": 1} for i in range(31 + overflow)}}
        user["run_config"] = {"runners": {"u%d" % i: {"cpus": 1} for i in range(32)}}
    elif case == "hosts_default":
        repo["model_settings"] = {"hosts": {"h%d" % i: {"kind": "codex-cli"} for i in range(15 + overflow)}}
    elif case == "lenses_extra":
        repo["model_settings"] = {"roles": {"lens.extra": {"hosts": ["primary"], "optional": True}}}
        repo["policy"] = {"review": {"lenses": [{"name": "audit%d" % i, "host_pref": ["primary"], "voting": False}
                                                for i in range(15 + overflow)]}}
    elif case == "fallback_edges":
        names = ["h%d" % i for i in range(9)]
        capacity = {name: {"fallback": {"doc": names[:8]}} for name in names[:8]}
        if overflow:
            capacity[names[-1]] = {"fallback": {"doc": [names[-1]]}}
        repo["model_settings"] = {"hosts": {name: {"kind": "codex-cli"} for name in names}, "capacity": capacity}
    elif case == "token_budgets":
        user["run_config"] = {"token_budgets": {"b%d" % i: 1 for i in range(64 + overflow)}}
    else:
        raise AssertionError("unknown aggregate bound")
    return repo, user


@pytest.mark.parametrize("case", _AGGREGATE_CASES)
@pytest.mark.parametrize("overflow", [False, True])
@pytest.mark.parametrize("surface", ["load", "cli_show", "mcp_show", "doctor", "cli_status", "supervisor"])
def test_real_loading_enforces_aggregate_bounds_before_display(tmp_path, monkeypatch, capsys, case, overflow, surface):
    base = make_store(tmp_path)
    root, home = base / "project", base / "owner"
    root.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    monkeypatch.setattr(profile, "UserLayout", SimpleNamespace(current=lambda: SimpleNamespace(home=home)))
    monkeypatch.setattr(profile_config, "env_workspace", lambda: None)
    repo, user = _aggregate_bound_documents(case, overflow)
    for parent, parts, document in ((root, profile.REPO_PATH, repo), (home, profile.USER_PATH, user)):
        target = parent.joinpath(*parts)
        target.parent.mkdir(mode=0o700, parents=True)
        target.write_text(json.dumps(document), encoding="utf-8")
    reason, layer = _AGGREGATE_CASES[case]
    if surface in ("load", "doctor"):
        if overflow:
            with pytest.raises(profile.ProfileError) as refused:
                loaded = profile.load(root, user_root=home)
                if surface == "doctor":
                    profile.doctor(loaded, root)
            assert str(refused.value) == reason and refused.value.layer == layer
            assert refused.value.exit_code == 1
        else:
            loaded = profile.load(root, user_root=home)
            assert profile.display_profile(loaded)["profile"]["preset"] == "solo"
            assert profile.doctor(loaded, root)["complete"] is True
        return
    if surface.startswith("cli_"):
        parser = argparse.ArgumentParser()
        profile_cli.TeamCommand().configure_parser(parser)
        argv = ["config", "show"] if surface == "cli_show" else ["hosts", "status"]
        args = parser.parse_args(argv + ["--json"])
        args.workspace = str(root)
        assert profile_cli.run_team(args) == (1 if overflow else 0)
        output = capsys.readouterr()
        assert output.err == ""
        result = json.loads(output.out)
    elif surface == "mcp_show":
        from aegis_mcp.tools import execute_tool
        result = execute_tool("aegis_team_config", {"workspace": str(root)})
    else:
        result = profile_status.supervisor_health(root, 0, user_root=home)
        assert result["profile"] == ("refused" if overflow else "valid")
    if overflow:
        assert result["reason"] == reason and result["layer"] == layer
        if surface != "supervisor":
            assert result["status"] == "refused"
    elif surface != "supervisor":
        assert result["status"] == "done"


@pytest.mark.parametrize("overflow", [False, True])
def test_owner_and_flag_runners_keep_the_aggregate_map_limit(overflow):
    user = {"run_config": {"runners": {"u%d" % i: {"cpus": 1} for i in range(32)}}}
    flags = {"run_config": {"runners": {"f%d" % i: {"cpus": 1} for i in range(31 + overflow)}}}
    if overflow:
        with pytest.raises(profile.ProfileError, match="^profile object size limit exceeded$") as refused:
            profile.resolve(user=user, flags=flags)
        assert refused.value.layer == "flags" and refused.value.path == "run_config.runners"
    else:
        result = profile.resolve(user=user, flags=flags)
        assert len(result["profile"]["run_config"]["runners"]) == 64
        profile.display_profile(result)


@pytest.mark.parametrize("value", [
    {"write_scope": None}, {"version": 2, "preset": "solo"},
    {"schema": "aegis.team.config.init/v1", "status": "done"},
    {"schema": "aegis.team.config.show/v1", "status": "done"},
])
def test_argon_display_refuses_incomplete_view_shapes(value):
    if value == {"write_scope": None}:
        shown = profile.display_profile(value)
        assert shown == value and shown is not value
        return
    with pytest.raises(profile.ProfileError) as refused:
        profile.display_profile(value)
    assert refused.value.exit_code == 1


@pytest.mark.parametrize("position", ["write_scope", "show_extra"])
def test_argon_display_refuses_unvalidated_keys_without_string_conversion(position):
    converted = []

    class Untrusted:
        def __str__(self):
            converted.append(True)
            raise AssertionError("unvalidated conversion must never run")

    value = {"write_scope": {Untrusted(): 1}} if position == "write_scope" else {
        **profile.resolve(), "schema": "aegis.team.config.show/v1", "extra": {Untrusted(): 1}}
    with pytest.raises(profile.ProfileError) as refused:
        profile.display_profile(value)
    assert refused.value.exit_code == 1 and converted == []


def test_argon_init_view_refuses_resolved_envelope_fields():
    value = {**profile.resolve(), "schema": "aegis.team.config.init/v1", "status": "done"}
    with pytest.raises(profile.ProfileError) as refused:
        profile.display_profile(value)
    assert refused.value.exit_code == 1


@pytest.mark.parametrize("kind", ["argument", "workspace", "presets", "doctor", "hosts"])
def test_native_diagnostic_views_preserve_their_bytes_and_copy_containers(kind):
    payloads = {
        "argument": {"schema": "aegis.team.config.show/v1", "status": "refused", "layer": "flags",
                     "reason": "aegis_team_config accepts no arguments", "file": "<command-line>"},
        "workspace": {"schema": "aegis.team.config.show/v1", "status": "refused", "layer": "filesystem",
                      "reason": "profile operation unavailable", "file": "<workspace>"},
        "presets": {"schema": "aegis.team.config.presets/v1", "status": "done",
                    "presets": list(profile.PRESET_DATA["presets"]), "host_kinds": profile.PRESET_DATA["hosts"]},
        "doctor": {"schema": "aegis.team.doctor/v1", "status": "done", "hosts": [],
                   "checks": {"profile": "complete", "login": "not checked"}, "write_scope": []},
        "hosts": {"schema": "aegis.team.hosts.status/v1", "status": "done", "hosts": [{
            "host": "primary", "usage_status": "known", "usage": {"tokens": 10**15, "used_pct": 25.5},
            "decisions": [{"kind": "writer", "decision": "go", "write_scope": ["write scope: OS sandbox"]}]}]},
    }
    value = payloads[kind]
    before = json.dumps(value, separators=(",", ":"))
    shown = profile.display_profile(value, capacity=True)
    assert json.dumps(shown, separators=(",", ":")) == before
    assert json.dumps(value, separators=(",", ":")) == before
    assert shown is not value
    for key, child in value.items():
        if type(child) in (dict, list):
            assert shown[key] is not child


@pytest.mark.parametrize("position", ["value", "key", "list", "show_extra"])
def test_display_never_calls_user_string_repr_or_format_hooks(position):
    calls = []

    class Untrusted:
        def __str__(self):
            calls.append("str")
            return "private"

        def __repr__(self):
            calls.append("repr")
            return "private"

        def __format__(self, spec):
            calls.append("format")
            return "private"

    obj = Untrusted()
    value = {"extra": obj} if position == "value" else {"extra": {obj: 1}} if position == "key" else {
        "extra": [obj]} if position == "list" else {**profile.resolve(),
            "schema": "aegis.team.config.show/v1", "extra": {obj: 1}}
    with pytest.raises(profile.ProfileError, match="^invalid value: profile display$") as refused:
        profile.display_profile(value)
    assert refused.value.exit_code == 1 and calls == []


@pytest.mark.parametrize("value", [b"bytes", (1,), {1}, float("nan"), float("inf"), -float("inf")])
def test_display_refuses_non_json_types_and_nonfinite_numbers(value):
    with pytest.raises(profile.ProfileError, match="^invalid value: profile display$"):
        profile.display_profile({"extra": value})


@pytest.mark.parametrize("bound", ["container", "string", "depth", "nodes", "characters", "integer"])
def test_display_enforces_diagnostic_resource_bounds(bound):
    if bound == "container":
        value = {"extra": [0] * 4097}
    elif bound == "string":
        value = {"extra": "x" * 131073}
    elif bound == "depth":
        value = 0
        for _ in range(17):
            value = {"extra": value}
    elif bound == "nodes":
        value = {"extra": [[0] * 4096] * 257}
    elif bound == "characters":
        value = {"extra": ["x" * 131072] * 513}
    else:
        value = {"extra": 1 << 4096}
    with pytest.raises(profile.ProfileError, match="^invalid value: profile display$"):
        profile.display_profile(value)


def test_display_accepts_large_valid_pure_resolver_output():
    gates = [{"name": "full", "runner": "local", "selector": "list", "must_pass": True,
              "tests": ["x" * profile.MAX_STRING] * 64} for _ in range(58)]
    resolved = profile.resolve(repo={"policy": {"gates": gates}})
    shown = profile.display_profile(resolved)
    assert len(shown["profile"]["policy"]["gates"]) == 58
    assert len(shown["profile"]["policy"]["gates"][0]["tests"][0]) == 512


# Invariant: policy.landing is the only landing policy. Omitted keys use the
# documented empty defaults (speculation off, no slot move, no leg override).
# Malformed or unknown fields refuse before any landing write or profile replace.
_LANDING_DEFAULTS = {
    "target_branch": "main", "strategy": "combined-full", "batch_max": 1,
    "signature_required_for": ["main"], "publish": {"remote": "origin", "app": ""},
    "registries": [], "jobs": {}, "flake_rerun_count": 0, "requalify_repeats": 1,
    "speculative_wait_s": 0, "speculative_enabled": False,
}
_LANDING_ROW = {"path": "tables/rows", "encoding": "line_table", "key": "name", "separator": "|"}
_LANDING_JOB = {"marker_dir": "marks/build", "slot": "fast", "encoding": "json_line"}


def _landing_document(landing):
    return {"policy": {"landing": landing}}


def _assert_landing_refusal(landing, message, path):
    document = _landing_document(landing)
    before = json.dumps(document)
    with pytest.raises(profile.ProfileError) as refused:
        profile.resolve(repo=document)
    error = refused.value
    assert (str(error), error.exit_code, error.layer, error.path) == (message, 1, "repo", path)
    assert "\n" not in str(error) and "\r" not in str(error)
    assert json.dumps(document) == before


def test_empty_landing_defaults_keep_speculation_off():
    resolved = profile.resolve()
    landing = resolved["profile"]["policy"]["landing"]
    assert landing == _LANDING_DEFAULTS
    assert "reliable_slot" not in landing and "required_legs" not in landing
    assert "max_title_chars" not in landing and "host" not in landing
    values = resolved["values"]
    assert values["policy.landing.speculative_enabled"]["value"] is False
    assert values["policy.landing.speculative_enabled"]["layer"] == "defaults"
    assert values["policy.landing.speculative_wait_s"]["value"] == 0
    assert "policy.landing.reliable_slot" not in values
    assert "policy.landing.required_legs" not in values
    again = profile.resolve()["profile"]["policy"]["landing"]
    again["registries"].append({"path": "mutated"})
    again["jobs"]["mutated"] = dict(_LANDING_JOB)
    assert profile.resolve()["profile"]["policy"]["landing"] == _LANDING_DEFAULTS
    for name in ("solo", "pair", "ci-only"):
        assert profile.resolve(preset=name)["profile"]["policy"]["landing"] == _LANDING_DEFAULTS
    mixed = profile.resolve(preset="mixed")["profile"]["policy"]["landing"]
    assert mixed["batch_max"] == 4 and {**mixed, "batch_max": 1} == _LANDING_DEFAULTS


def test_two_unrelated_profiles_resolve_landing_policy():
    alpha = {
        "target_branch": "alpha-trunk",
        "registries": [{"path": "alpha/rows.list", "encoding": "line_table", "key": "alpha_key", "separator": "|"}],
        "jobs": {"alpha-job": {"marker_dir": "alpha/markers", "slot": "alpha-slot", "encoding": "json_line"}},
        "reliable_slot": "alpha-hold", "required_legs": ["alpha-leg"],
        "flake_rerun_count": 1, "requalify_repeats": 4, "speculative_wait_s": 15,
        "speculative_enabled": True,
    }
    beta = {
        "target_branch": "beta-trunk",
        "registries": [{"path": "beta/table.txt", "encoding": "whole_file", "key": "beta_key", "separator": "\t"}],
        "jobs": {"beta-job": {"marker_dir": "beta/markers", "slot": "beta-slot", "encoding": "json_line"}},
        "flake_rerun_count": 0, "requalify_repeats": 8, "speculative_wait_s": 0,
        "speculative_enabled": False,
    }
    left = profile.resolve(repo=_landing_document(alpha))["profile"]["policy"]["landing"]
    right = profile.resolve(repo=_landing_document(beta))["profile"]["policy"]["landing"]
    assert left["target_branch"] == "alpha-trunk" and right["target_branch"] == "beta-trunk"
    assert left["registries"] == alpha["registries"] and right["registries"] == beta["registries"]
    assert left["registries"][0]["encoding"] != right["registries"][0]["encoding"]
    assert left["jobs"] == alpha["jobs"] and right["jobs"] == beta["jobs"]
    assert "beta-job" not in left["jobs"] and "alpha-job" not in right["jobs"]
    assert left["reliable_slot"] == "alpha-hold" and "reliable_slot" not in right
    assert left["required_legs"] == ["alpha-leg"] and "required_legs" not in right
    assert left["speculative_enabled"] is True and right["speculative_enabled"] is False
    assert left["strategy"] == "combined-full" and left["signature_required_for"] == ["main"]
    explicit = profile.resolve(repo=_landing_document({"required_legs": []}))
    assert explicit["profile"]["policy"]["landing"]["required_legs"] == []
    assert "required_legs" not in profile.resolve()["profile"]["policy"]["landing"]


def _landing_git_root(path):
    import os
    from pathlib import Path
    import shutil

    from tests.helpers_team_git import git

    root = make_store(path)
    if shutil.which("git") is None:
        pytest.skip("needs git")
    root.mkdir()
    env = {**{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    git(root, "init", "-q", env=env)
    assert Path(git(root, "rev-parse", "--show-toplevel", env=env).decode().strip()).resolve() == root
    return root


def _landing_repo_entries(root):
    return {str(entry.relative_to(root)) for entry in root.rglob("*")
            if entry.relative_to(root).parts[0] != ".git"}


def test_git_repository_landing_defaults(tmp_path):
    root = _landing_git_root(tmp_path / "empty")
    resolved = profile.load(root, user_root=root)
    assert resolved["profile"]["policy"]["landing"] == _LANDING_DEFAULTS
    assert resolved["repository_profile_exists"] is False
    assert _landing_repo_entries(root) == set()
    assert profile.initialize(root, "solo", force=True) == {"version": 1, "preset": "solo"}
    target = root.joinpath(*profile.REPO_PATH)
    before = target.read_bytes()
    entries = _landing_repo_entries(root)
    resolved = profile.load(root, user_root=root)
    assert resolved["profile"]["policy"]["landing"] == _LANDING_DEFAULTS
    assert resolved["repository_profile_exists"] is True
    assert target.read_bytes() == before
    assert entries == _landing_repo_entries(root) == {str(part.relative_to(root)) for part in (
        target, target.parent, target.parent.parent)}


def test_two_repositories_load_landing_without_a_sidecar(tmp_path):
    def write(name, landing):
        root = _landing_git_root(tmp_path / name)
        target = root.joinpath(*profile.REPO_PATH)
        target.parent.mkdir(mode=0o700, parents=True)
        raw = json.dumps({"version": 1, **_landing_document(landing)}).encode("utf-8")
        target.write_bytes(raw)
        return root, target, raw, _landing_repo_entries(root)

    alpha, alpha_file, alpha_bytes, alpha_entries = write("alpha-repo", {"target_branch": "alpha-trunk", "registries": [
        {"path": "alpha/rows.list", "encoding": "line_table", "key": "alpha_key", "separator": "|"}],
        "jobs": {"alpha-job": {"marker_dir": "alpha/markers", "slot": "alpha-slot", "encoding": "json_line"}}})
    beta, beta_file, beta_bytes, beta_entries = write("beta-repo", {"target_branch": "beta-trunk", "registries": [
        {"path": "beta/table.txt", "encoding": "whole_file", "key": "beta_key", "separator": "\t"}],
        "jobs": {"beta-job": {"marker_dir": "beta/markers", "slot": "beta-slot", "encoding": "json_line"}}})
    loaded_alpha = profile.load(alpha, user_root=alpha)["profile"]["policy"]["landing"]
    loaded_beta = profile.load(beta, user_root=beta)["profile"]["policy"]["landing"]
    assert loaded_alpha["target_branch"] == "alpha-trunk" and loaded_beta["target_branch"] == "beta-trunk"
    assert loaded_alpha["registries"][0]["encoding"] == "line_table"
    assert loaded_beta["registries"][0]["encoding"] == "whole_file"
    assert loaded_alpha["jobs"]["alpha-job"]["slot"] == "alpha-slot"
    assert loaded_beta["jobs"]["beta-job"]["slot"] == "beta-slot"
    assert "alpha-job" not in loaded_beta["jobs"] and "beta-job" not in loaded_alpha["jobs"]
    assert loaded_alpha["speculative_enabled"] is False and loaded_beta["speculative_enabled"] is False
    loaded_alpha["jobs"].clear()
    loaded_beta["registries"].clear()
    assert profile.load(alpha, user_root=alpha)["profile"]["policy"]["landing"]["jobs"] == {
        "alpha-job": {"marker_dir": "alpha/markers", "slot": "alpha-slot", "encoding": "json_line"}}
    assert profile.load(beta, user_root=beta)["profile"]["policy"]["landing"]["registries"] == [
        {"path": "beta/table.txt", "encoding": "whole_file", "key": "beta_key", "separator": "\t"}]
    assert alpha_file.read_bytes() == alpha_bytes and beta_file.read_bytes() == beta_bytes
    assert _landing_repo_entries(alpha) == alpha_entries and _landing_repo_entries(beta) == beta_entries


def _landing_path_case(field, value):
    if field == "registry":
        return {"registries": [{**_LANDING_ROW, "path": value}]}, "policy.landing.registries.0.path"
    return {"jobs": {"build": {**_LANDING_JOB, "marker_dir": value}}}, "policy.landing.jobs.build.marker_dir"


def _assert_landing_path_case(field, value, accepted):
    landing, path = _landing_path_case(field, value)
    if accepted:
        result = profile.resolve(repo=_landing_document(landing))
        assert result["profile"]["policy"]["landing"] == {**_LANDING_DEFAULTS, **landing}
        profile.validate_resolved(result)
        return
    _assert_landing_refusal(landing, "invalid value: " + path, path)
    resolved = profile.resolve()
    resolved["profile"]["policy"]["landing"].update(landing)
    with pytest.raises(profile.ProfileError) as refused:
        profile.validate_resolved(resolved)
    assert (str(refused.value), refused.value.path, refused.value.layer, refused.value.exit_code) == (
        "invalid value: " + path, path, "repo", 1)


@pytest.mark.parametrize("field", ["registry", "marker"])
@pytest.mark.parametrize("value", ["rows//leaf", "rows/./leaf", "rows/", "rows/\ud800",
                                   "rows/a\rb", "rows/a\x00b", "C:rows"])
def test_round_1c_landing_paths_refuse_noncanonical_spellings(field, value):
    _assert_landing_path_case(field, value, False)


@pytest.mark.parametrize("field,value,accepted", [
    ("registry", ".git/rows", False),
    ("registry", "rows/.git/value", False),
    ("registry", "r/" + "é" * 2047, True),
    ("registry", "r/" + "é" * 2047 + "x", False),
    ("marker", "marks/" + "é" * 127 + "x", True),
    ("marker", "marks/" + "é" * 128, False),
    ("marker", "/".join(["a"] * 127), True),
    ("marker", "/".join(["a"] * 128), False),
    ("marker", "marks/.git/leaf", True),
    ("marker", "marks/with\\backslash", False),
], ids=["git-root", "git-nested", "git-4096-bytes", "git-4097-bytes", "state-255-bytes",
        "state-256-bytes", "state-127-components", "state-128-components", "state-dotgit",
        "state-backslash"])
def test_round_1c_landing_path_consumer_limits(field, value, accepted):
    import os

    if accepted:
        # A path at the UTF-8 boundary still has to fit the native byte limit.
        try:
            native = os.fsencode(value)
        except UnicodeError:
            accepted = False
        else:
            accepted = (len(native) <= 4096 if field == "registry"
                        else all(len(part) <= 255 for part in native.split(b"/")))
    _assert_landing_path_case(field, value, accepted)


@pytest.mark.parametrize("value", ["rows/with\\backslash", "rows/with:colon"])
def test_round_1c_registry_path_platform_grammar(value):
    import os

    _assert_landing_path_case("registry", value, os.name != "nt")


def test_round_1c_required_legs_follow_the_profile_bound():
    from aegis_core.team_qualify import qualification_ref

    names = ["3.12-linux", "a" * 65, "9" + "x" * 127]
    assert all(qualification_ref("a" * 40, name).endswith("/" + name) for name in names)
    resolved = profile.resolve(repo=_landing_document({"required_legs": names}))
    profile.validate_resolved(resolved)
    assert resolved["profile"]["policy"]["landing"]["required_legs"] == names
    assert resolved["values"]["policy.landing.required_legs"]["value"] == names
    path = "policy.landing.required_legs.0"
    _assert_landing_refusal({"required_legs": ["a" * 129]}, "profile string size limit exceeded", path)
    for value in ("", "leg\nnext", "leg\rnext", "leg\0next"):
        _assert_landing_refusal({"required_legs": [value]}, "invalid identifier: " + path, path)


@pytest.mark.parametrize("document,reason,path", [
    ({"policy": {"landing_backup": {}}}, "unknown key", "policy.landing_backup"),
    ({"policy": {"landing.extra": 1}}, "unknown key", "policy.landing.extra"),
    ({"policy.landing.extra": 1}, "unknown key", "policy.landing.extra"),
    ({"policy": {"landing.extra": 1, "landing": {"extra": 1}}}, "profile_unavailable", "policy.landing.extra"),
    (_landing_document({"extra": 1}), "profile_unavailable", "policy.landing.extra"),
    (_landing_document({"publish": {"extra": 1}}), "profile_unavailable", "policy.landing.publish.extra"),
    (_landing_document({"registries": [{**_LANDING_ROW, "extra": 1}]}), "profile_unavailable",
     "policy.landing.registries.0.extra"),
    (_landing_document({"jobs": {"\nunsafe": _LANDING_JOB}}), "profile_unavailable", "policy.landing.jobs"),
    (_landing_document({"jobs": {"build.alt": {**_LANDING_JOB, "extra": 1}}}), "profile_unavailable",
     "policy.landing.jobs.build.alt.extra"),
    (_landing_document({"publish": {"unsafe\nkey": 1}}), "profile_unavailable", "policy.landing.publish"),
])
def test_round_1c_unknown_reason_uses_the_rejecting_object(document, reason, path):
    expected = "unknown key: " + path if reason == "unknown key" else reason
    before = json.dumps(document)
    resolved = profile.resolve()
    _overlay_test_fields(resolved["profile"], document)
    for operation in (lambda: profile.resolve(repo=document), lambda: profile.validate_resolved(resolved)):
        with pytest.raises(profile.ProfileError) as refused:
            operation()
        error = refused.value
        assert (str(error), error.path, error.layer, error.file, error.exit_code) == (
            expected, path, "repo", "/".join(profile.REPO_PATH), 1)
    assert json.dumps(document) == before


@pytest.mark.parametrize("layer,file", [("user", "~/" + "/".join(profile.USER_PATH)),
                                        ("flags", "<command-line>")])
def test_round_1c_unknown_sibling_keeps_its_layer(layer, file):
    with pytest.raises(profile.ProfileError) as refused:
        profile.resolve(**{layer: {"policy": {"landing.extra": 1}}})
    error = refused.value
    assert (str(error), error.path, error.layer, error.file, error.exit_code) == (
        "unknown key: policy.landing.extra", "policy.landing.extra", layer, file, 1)


def test_round_1c_unknown_registry_key_in_copied_provenance():
    resolved = profile.resolve()
    resolved["values"]["policy.landing.registries"]["value"] = [{**_LANDING_ROW, "extra": True}]
    with pytest.raises(profile.ProfileError) as refused:
        profile.display_profile(resolved)
    error = refused.value
    assert (str(error), error.path, error.layer, error.exit_code) == (
        "profile_unavailable", "policy.landing.registries.0.extra", "repo", 1)


@pytest.mark.parametrize("field,label", [("registry", "policy.landing.registries"),
                                         ("marker", "policy.landing.jobs.build.marker_dir")])
def test_round_1c_landing_path_in_copied_provenance(field, label):
    good, path = _landing_path_case(field, "dir/leaf")
    resolved = profile.resolve(repo=_landing_document(good))
    record = resolved["values"][label]
    if field == "registry":
        record["value"] = [{**record["value"][0], "path": "dir/./leaf"}]
    else:
        record["value"] = "dir/./leaf"
    with pytest.raises(profile.ProfileError) as refused:
        profile.validate_resolved(resolved)
    error = refused.value
    assert (str(error), error.path, error.layer, error.exit_code) == (
        "invalid value: " + path, path, "repo", 1)


def _assert_repository_landing_refusal(root, document, message, path):
    target = root.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = json.dumps({"version": 1, **document}, indent=2).encode("utf-8") + b"\n"
    target.write_bytes(raw)
    landing_state = root / ".aegis" / "state" / "landing.json"
    assert not landing_state.exists()
    entries = _landing_repo_entries(root)
    for operation in (lambda: profile.load(root, user_root=root),
                      lambda: profile.initialize(root, "pair", force=True)):
        with pytest.raises(profile.ProfileError) as refused:
            operation()
        error = refused.value
        assert (str(error), error.path, error.layer, error.file, error.exit_code) == (
            message, path, "repo", str(target), 1)
        assert not landing_state.exists()
        assert target.read_bytes() == raw
        assert _landing_repo_entries(root) == entries
    return target, entries


@pytest.mark.parametrize("field", ["registry", "marker", "unknown", "sibling"])
def test_round_1c_git_repository_refusal_preserves_bytes_and_retries(tmp_path, field):
    root = _landing_git_root(tmp_path / "invalid")
    if field == "unknown":
        document, path = _landing_document({"publish": {"extra": 1}}), "policy.landing.publish.extra"
        reason = "profile_unavailable"
    elif field == "sibling":
        document, path = {"policy": {"landing.extra": 1}}, "policy.landing.extra"
        reason = "unknown key: " + path
    else:
        landing, path = _landing_path_case(field, "dir/./leaf")
        document, reason = _landing_document(landing), "invalid value: " + path
    target, entries = _assert_repository_landing_refusal(root, document, reason, path)
    corrected = b'{"version":1,"policy":{"landing":{"target_branch":"retry-trunk"}}}\n'
    target.write_bytes(corrected)
    assert profile.load(root, user_root=root)["profile"]["policy"]["landing"] == {
        **_LANDING_DEFAULTS, "target_branch": "retry-trunk"}
    assert target.read_bytes() == corrected
    assert profile.initialize(root, "pair", force=True) == {"version": 1, "preset": "pair"}
    assert profile.load(root, user_root=root)["profile"]["policy"]["landing"] == _LANDING_DEFAULTS
    assert _landing_repo_entries(root) == entries


@pytest.mark.parametrize("landing,message,path", [
    ({"max_title_chars": 80}, "profile_unavailable", "policy.landing.max_title_chars"),
    ({"host": {"adapter": "local"}}, "profile_unavailable", "policy.landing.host"),
    ({"registries": [{**_LANDING_ROW, "owner": "kit"}]}, "profile_unavailable", "policy.landing.registries.0.owner"),
    ({"jobs": {"build": {**_LANDING_JOB, "timeout": 1}}}, "profile_unavailable", "policy.landing.jobs.build.timeout"),
    ({"bad\nkey": True}, "profile_unavailable", "policy.landing"),
    ({"registries": [{**_LANDING_ROW, "path": "/etc/passwd"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "path": "\\\\server\\share"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "path": "C:/rows"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "path": "../rows"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "path": "rows/../secret"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "path": "rows/foo..bar"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "path": "rows/a\nb"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "path": ""}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"registries": [{**_LANDING_ROW, "encoding": "csv"}]}, "invalid value: policy.landing.registries.0.encoding", "policy.landing.registries.0.encoding"),
    ({"registries": [{**_LANDING_ROW, "separator": "\n"}]}, "invalid value: policy.landing.registries.0.separator", "policy.landing.registries.0.separator"),
    ({"registries": [{**_LANDING_ROW, "key": "a\nb"}]}, "invalid value: policy.landing.registries.0.key", "policy.landing.registries.0.key"),
    ({"registries": [{"encoding": "line_table", "key": "name", "separator": "|"}]}, "invalid value: policy.landing.registries.0.path", "policy.landing.registries.0.path"),
    ({"jobs": {"build": {"marker_dir": "a/../b", "slot": "fast", "encoding": "json_line"}}}, "invalid value: policy.landing.jobs.build.marker_dir", "policy.landing.jobs.build.marker_dir"),
    ({"jobs": {"build": {"marker_dir": "marks", "slot": "fast", "encoding": "line_table"}}}, "invalid value: policy.landing.jobs.build.encoding", "policy.landing.jobs.build.encoding"),
    ({"jobs": {"build": {"slot": "fast", "encoding": "json_line"}}}, "invalid value: policy.landing.jobs.build.marker_dir", "policy.landing.jobs.build.marker_dir"),
    ({"flake_rerun_count": 2}, "value out of range: policy.landing.flake_rerun_count", "policy.landing.flake_rerun_count"),
    ({"flake_rerun_count": True}, "wrong type: policy.landing.flake_rerun_count", "policy.landing.flake_rerun_count"),
    ({"requalify_repeats": 0}, "value out of range: policy.landing.requalify_repeats", "policy.landing.requalify_repeats"),
    ({"requalify_repeats": 9}, "value out of range: policy.landing.requalify_repeats", "policy.landing.requalify_repeats"),
    ({"speculative_wait_s": 3601}, "value out of range: policy.landing.speculative_wait_s", "policy.landing.speculative_wait_s"),
    ({"speculative_wait_s": -1}, "value out of range: policy.landing.speculative_wait_s", "policy.landing.speculative_wait_s"),
    ({"speculative_enabled": "false"}, "wrong type: policy.landing.speculative_enabled", "policy.landing.speculative_enabled"),
    ({"registries": [{**_LANDING_ROW, "path": "tables/r%d" % i} for i in range(33)]}, "profile array size limit exceeded: policy.landing.registries", "policy.landing.registries"),
    ({"reliable_slot": "bad slot"}, "invalid identifier: policy.landing.reliable_slot", "policy.landing.reliable_slot"),
    ({"required_legs": ["leg\nnext"]}, "invalid identifier: policy.landing.required_legs.0", "policy.landing.required_legs.0"),
    ({"max_title_chars": 40, "registries": [{**_LANDING_ROW, "path": "/abs"}]}, "profile_unavailable", "policy.landing.max_title_chars"),
])
def test_landing_fields_refuse_before_any_landing_write(tmp_path, landing, message, path):
    _assert_landing_refusal(landing, message, path)
    root = _landing_git_root(tmp_path / "invalid")
    _assert_repository_landing_refusal(root, _landing_document(landing), message, path)


@pytest.mark.parametrize("layer", ["user", "flags"])
def test_landing_policy_stays_repository_only(layer):
    with pytest.raises(profile.ProfileError, match="governance policy is repository-only") as refused:
        profile.resolve(**{layer: _landing_document({"speculative_enabled": False, "flake_rerun_count": 0})})
    assert refused.value.exit_code == 1 and refused.value.layer == layer


def test_landing_refusal_retries_without_joining_lines(tmp_path):
    raw = "marks/a\nb"
    bad = {"jobs": {"build": {"marker_dir": raw, "slot": "fast", "encoding": "json_line"}}}
    before = json.dumps(bad)
    path = "policy.landing.jobs.build.marker_dir"
    _assert_landing_refusal(bad, "invalid value: " + path, path)
    assert json.dumps(bad) == before and "marks/a b" not in json.dumps(bad) and "marks/ab" not in json.dumps(bad)
    root = _landing_git_root(tmp_path / "invalid")
    target, entries = _assert_repository_landing_refusal(
        root, _landing_document(bad), "invalid value: " + path, path)
    corrected = _landing_document({"jobs": {"build": dict(_LANDING_JOB)}})
    landing = profile.resolve(repo=corrected)
    assert landing["profile"]["policy"]["landing"]["jobs"]["build"]["marker_dir"] == "marks/build"
    assert landing["profile"]["policy"]["landing"]["speculative_enabled"] is False
    profile.validate_resolved(landing)
    shown = profile.display_profile(landing)
    assert shown["profile"]["policy"]["landing"]["jobs"]["build"]["marker_dir"] == "marks/build"
    target.write_text(json.dumps({"version": 1, **corrected}), encoding="utf-8")
    loaded = profile.load(root, user_root=root)
    assert loaded["profile"]["policy"]["landing"] == landing["profile"]["policy"]["landing"]
    assert _landing_repo_entries(root) == entries


@pytest.mark.parametrize("surface", ["validate_resolved", "display"])
def test_resolved_landing_defect_refuses_on_every_consumer(surface):
    resolved = profile.resolve()
    resolved["profile"]["policy"]["landing"]["registries"] = [
        {**_LANDING_ROW, "path": "rows/a\nb"}]
    before = json.dumps(resolved["profile"]["policy"]["landing"]["registries"])
    with pytest.raises(profile.ProfileError) as refused:
        if surface == "validate_resolved":
            profile.validate_resolved(resolved)
        else:
            profile.display_profile(resolved)
    assert str(refused.value) == "invalid value: policy.landing.registries.0.path"
    assert refused.value.exit_code == 1 and "\n" not in str(refused.value)
    assert json.dumps(resolved["profile"]["policy"]["landing"]["registries"]) == before


def test_landing_bounds_round_trip_and_display_redacts_untrusted_text():
    secret = "token=\x1b[31msuper-secret-credential"
    plain = "token=super-secret-credential"
    landing = {
        "flake_rerun_count": 1, "requalify_repeats": 8, "speculative_wait_s": 3600,
        "speculative_enabled": False,
        "registries": [{"path": "tables/" + secret, "encoding": "whole_file", "key": secret, "separator": "|"}],
        "jobs": {"build": {"marker_dir": "marks/" + plain, "slot": "fast", "encoding": "json_line"}},
    }
    resolved = profile.resolve(repo=_landing_document(landing))
    stored = resolved["profile"]["policy"]["landing"]
    assert stored["flake_rerun_count"] == 1 and stored["requalify_repeats"] == 8
    assert stored["speculative_wait_s"] == 3600 and stored["speculative_enabled"] is False
    assert stored["registries"][0]["path"] == "tables/" + secret
    assert stored["registries"][0]["key"] == secret
    assert stored["jobs"]["build"]["marker_dir"] == "marks/" + plain
    profile.validate_resolved(resolved)
    shown = profile.display_profile(resolved)
    rendered = json.dumps(shown)
    assert "super-secret" not in rendered and "\x1b" not in rendered
    visible = shown["profile"]["policy"]["landing"]
    copied = shown["values"]["policy.landing.registries"]["value"][0]
    assert visible["registries"][0]["path"] == "tables/token=REDACTED"
    assert copied["path"] == "tables/token=REDACTED"
    assert visible["registries"][0]["key"] == "token=REDACTED"
    assert copied["key"] == "token=REDACTED"
    assert visible["jobs"]["build"]["marker_dir"] == "marks/token=REDACTED"
    assert stored["registries"][0]["path"] == "tables/" + secret
    assert stored["registries"] is resolved["values"]["policy.landing.registries"]["value"]
    wide = profile.resolve(repo=_landing_document({"registries": [
        {**_LANDING_ROW, "path": "tables/r%d" % index} for index in range(32)]}))
    assert len(wide["profile"]["policy"]["landing"]["registries"]) == 32


def test_registry_path_display_keeps_source_and_clip_order():
    """Both views redact registry paths after canonicalization and before the 512 clip.

    A control split inside the key is not a secret until canonicalization joins it.
    Padding leaves the replacement across the clip boundary. The metadata path
    array and other path fields stay schema references. The caller's document
    keeps the raw characters.
    """
    ordered = "rows/" + ("n" * 494) + "/tok\x1b[31men=super-secret-credential" + ("y" * 40)
    plain = "tables/token=super-secret-credential"
    benign = "tables/plain"
    resolved = profile.resolve(repo=_landing_document({"registries": [
        {"path": ordered, "encoding": "line_table", "key": ordered, "separator": "|"},
        {"path": plain, "encoding": "whole_file", "key": "plain", "separator": "\t"},
        {"path": benign, "encoding": "line_table", "key": "name", "separator": "|"},
    ]}))
    stored = resolved["profile"]["policy"]["landing"]["registries"]
    assert resolved["values"]["policy.landing.registries"]["value"] is stored
    assert [row["path"] for row in stored] == [ordered, plain, benign]
    before = json.dumps(resolved)
    reference = {"path": "model_settings.roles.token=super-secret-credential"}
    for capacity in (False, True):
        shown = profile.display_profile(resolved, capacity=capacity)
        bare = profile.display_profile(resolved["profile"], capacity=capacity)
        views = (
            shown["profile"]["policy"]["landing"]["registries"],
            shown["values"]["policy.landing.registries"]["value"],
            bare["policy"]["landing"]["registries"],
        )
        for view in views:
            rendered = json.dumps(view)
            assert [row["separator"] for row in view] == ["|", "\t", "|"]
            assert "super-secret" not in rendered and "\x1b" not in rendered
            assert view[0]["path"].endswith("/token=RED...") and len(view[0]["path"]) == 512
            assert view[0]["key"] == view[0]["path"]
            assert "[REDACTED]" not in view[0]["path"] and "super-secret" not in view[0]["path"]
            assert view[1]["path"] == "tables/token=REDACTED"
            assert view[2]["path"] == benign
        assert shown["values"]["policy.landing.registries"]["path"] == [
            "policy", "landing", "registries"]
        assert profile.display_profile(reference, capacity=capacity)["path"] == reference["path"]
        assert profile.display_profile({"separator": "\t"}, capacity=capacity)["separator"] == " "
        assert json.dumps(resolved) == before
    assert stored[0]["path"] == ordered and stored[1]["path"] == plain
    assert resolved["values"]["policy.landing.registries"]["value"] is stored


@pytest.mark.parametrize("depth", [1, 2, 3], ids=["policy", "landing", "registries"])
@pytest.mark.parametrize("prefix", [[], ["user"]], ids=["repo", "user"])
@pytest.mark.parametrize("capacity", [False, True], ids=["config", "capacity"])
def test_round_1d_registry_copy_uses_validated_field_policy(depth, prefix, capacity):
    body_row = {**_LANDING_ROW, "path": "body/token=private-value", "separator": "|"}
    resolved = profile.resolve(repo=_landing_document({"registries": [body_row]}))
    components = ["policy", "landing", "registries"]
    ordered = "rows/" + "n" * 494 + "/tok\x1b[31men=private-value" + "y" * 40
    copy_row = {**_LANDING_ROW, "path": ordered, "key": ordered, "separator": "\t"}
    copied = [copy_row]
    for name in reversed(components[depth:]):
        copied = {name: copied}
    label = "policy.landing.jobs.build.alt.marker_dir"
    metadata = {"path": prefix + components[:depth], "layer": "user" if prefix else "repo",
                "applied_paths": [["policy", "landing", "jobs", "build.alt", "marker_dir"]]}
    resolved["values"] = {label: {**metadata, "value": copied}}
    before = json.dumps(resolved)

    profile.validate_resolved(resolved)
    shown = profile.display_profile(resolved, capacity=capacity)
    bare = profile.display_profile(resolved["profile"], capacity=capacity)
    for view in (shown["profile"], bare):
        assert view["policy"]["landing"]["registries"] == [{**body_row, "path": "body/token=REDACTED"}]
    displayed_record = shown["values"][label]
    assert {key: displayed_record[key] for key in metadata} == metadata
    displayed_copy = displayed_record["value"]
    for name in components[depth:]:
        displayed_copy = displayed_copy[name]
    clipped = "rows/" + "n" * 494 + "/token=RED..."
    assert displayed_copy[0]["separator"] == "\t"
    assert displayed_copy[0]["path"] == displayed_copy[0]["key"] == clipped
    assert json.dumps(resolved) == before


def _assert_round_1d_refusal(operation, reason, path, *, file=None):
    with pytest.raises(profile.ProfileError) as refused:
        operation()
    error = refused.value
    assert (str(error), error.path, error.layer, error.exit_code) == (reason, path, "repo", 1)
    if file is not None:
        assert error.file == str(file)


@pytest.mark.parametrize("field", ["registry", "marker"])
@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reverse"])
def test_round_1d_copy_and_body_structure_precede_landing_paths(field, reverse):
    bad_landing, path = _landing_path_case(field, "dir/./leaf")
    section = "registries" if field == "registry" else "jobs"
    row = bad_landing[section][0 if field == "registry" else "build"]
    row["z_extra"] = True

    def snapshots():
        body, copy = profile.resolve(), profile.resolve()
        body["profile"]["policy"]["landing"].update(_reordered_objects(bad_landing, reverse))
        # Copy from the array root for registry rows and the job record root for jobs.
        components = ["policy", "landing", section] + ([] if field == "registry" else ["build"])
        value = bad_landing[section] if field == "registry" else row
        copy["values"]["independent"] = {"path": components, "value": _reordered_objects(value, reverse)}
        return body, copy

    unknown = path.rsplit(".", 1)[0] + ".z_extra"
    for resolved in snapshots():
        _assert_round_1d_refusal(lambda: profile.validate_resolved(resolved), "profile_unavailable", unknown)
    del row["z_extra"]
    for resolved in snapshots():
        _assert_round_1d_refusal(lambda: profile.display_profile(resolved), "invalid value: " + path, path)


def test_round_1d_landing_semantic_order_matches_for_ancestor_copies():
    landing = {"registries": [{**_LANDING_ROW, "path": "dir/./leaf", "key": ""}],
               "jobs": {"build.alt": {**_LANDING_JOB, "marker_dir": "marks/./leaf"}}}
    for field in ("path", "key", "marker_dir"):
        path = ("policy.landing.jobs.build.alt." if field == "marker_dir" else "policy.landing.registries.0.") + field
        body, copy = profile.resolve(), profile.resolve()
        body["profile"]["policy"]["landing"].update(_reordered_objects(landing, False))
        copy["values"]["ancestor"] = {"path": ["user", "policy"], "value": _landing_document(
            _reordered_objects(landing, True))["policy"]}
        for resolved in (body, copy):
            _assert_round_1d_refusal(lambda: profile.validate_resolved(resolved), "invalid value: " + path, path)
        if field != "marker_dir":
            landing["registries"][0][field] = _LANDING_ROW[field]


def _round_1d_marker_operation(root, placement):
    marker = "marks/" + "\u00e9" * 127 + "x"
    jobs = {"build.alt": {**_LANDING_JOB, "marker_dir": marker}}
    document = _landing_document({"jobs": jobs})
    if placement == "resolve":
        return lambda: profile.resolve(repo=document)
    if placement == "load":
        return lambda: profile.load(root, user_root=root)
    if placement == "force":
        return lambda: profile.initialize(root, "pair", force=True)
    resolved = profile.resolve()
    if placement == "body":
        resolved["profile"]["policy"]["landing"]["jobs"] = jobs
    elif placement == "ancestor":
        resolved["values"]["independent"] = {"path": ["user", "policy", "landing"], "value": document["policy"]["landing"]}
    else:
        resolved["values"]["independent"] = {
            "path": ["policy", "landing", "jobs", "build.alt", "marker_dir"], "value": marker}
    return lambda: profile.display_profile(resolved)


def _assert_round_1d_ascii_marker(root, placement):
    import sys

    assert sys.getfilesystemencoding() == "ascii"
    assert profile.descriptor_supported()
    target = root.joinpath(*profile.REPO_PATH)
    raw = target.read_bytes()
    entries = _landing_repo_entries(root)
    path = "policy.landing.jobs.build.alt.marker_dir"
    file = target if placement in ("load", "force") else None
    _assert_round_1d_refusal(_round_1d_marker_operation(root, placement), "invalid value: " + path, path, file=file)
    assert not (root / "marks").exists()
    assert target.read_bytes() == raw and _landing_repo_entries(root) == entries

    # Only a successfully loaded profile can supply components to marker storage.
    corrected = raw.replace(b"\\u00e9" * 127 + b"x", b"retry")
    assert corrected != raw
    target.write_bytes(corrected)
    loaded = profile.load(root, user_root=root)
    marker = loaded["profile"]["policy"]["landing"]["jobs"]["build.alt"]["marker_dir"]
    assert marker == "marks/retry"
    with storage.confined_file(root, (*marker.split("/"), "attempt.json"), create_parents=True) as handle:
        handle.publish_bytes(b"{}\n")
    assert (root / "marks" / "retry" / "attempt.json").read_bytes() == b"{}\n"
    assert target.read_bytes() == corrected
    assert profile.initialize(root, "pair", force=True) == {"version": 1, "preset": "pair"}


@pytest.mark.parametrize("placement", ["resolve", "body", "ancestor", "leaf", "load", "force"])
def test_round_1d_marker_refuses_native_ascii_encoding(tmp_path, placement):
    import os
    from pathlib import Path
    import subprocess
    import sys

    if sys.platform != "linux":
        pytest.skip("requires a filesystem encoding selected by the POSIX locale")
    root = _landing_git_root(tmp_path / "ascii-repo")
    target = root.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    jobs = {"build.alt": {**_LANDING_JOB, "marker_dir": "marks/" + "\u00e9" * 127 + "x"}}
    raw = json.dumps({"version": 1, **_landing_document({"jobs": jobs})}, indent=2).encode("ascii") + b"\n"
    target.write_bytes(raw)
    program = ("from pathlib import Path\nimport sys\n"
               "from tests.unit.core.test_team_profile import _assert_round_1d_ascii_marker\n"
               "_assert_round_1d_ascii_marker(Path(sys.argv[1]), sys.argv[2])\n")
    result = subprocess.run([sys.executable, "-c", program, str(root), placement],
                            cwd=Path(__file__).resolve().parents[3], capture_output=True, timeout=30,
                            env={**os.environ, "LC_ALL": "C", "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0"})
    assert result.returncode == 0, result.stderr.decode("ascii", errors="backslashreplace")


def test_round_1d_marker_utf8_limit_reaches_confined_storage(tmp_path):
    import sys

    root = make_store(tmp_path)
    if sys.getfilesystemencoding() != "utf-8":
        pytest.skip("requires a UTF-8 filesystem encoding")
    marker = "marks/" + "\u00e9" * 127 + "x"
    resolved = _round_1d_marker_operation(root, "resolve")()
    profile.validate_resolved(resolved)
    assert resolved["profile"]["policy"]["landing"]["jobs"]["build.alt"]["marker_dir"] == marker
    with storage.confined_file(root, (*marker.split("/"), "attempt.json"), create_parents=True) as handle:
        handle.publish_bytes(b"{}\n")
    assert root.joinpath(*marker.split("/"), "attempt.json").read_bytes() == b"{}\n"


def test_concurrent_landing_profiles_do_not_share_state():
    import threading
    documents = {
        "alpha": _landing_document({"target_branch": "alpha-trunk", "jobs": {
            "alpha-job": {"marker_dir": "alpha/markers", "slot": "alpha-slot", "encoding": "json_line"}}}),
        "beta": _landing_document({"target_branch": "beta-trunk", "registries": [
            {"path": "beta/table.txt", "encoding": "whole_file", "key": "beta_key", "separator": "|"}]}),
    }
    barrier = threading.Barrier(2)
    found, errors = {}, []

    def worker(name):
        try:
            barrier.wait(timeout=5)
            for _ in range(6):
                landing = profile.resolve(repo=documents[name])["profile"]["policy"]["landing"]
                assert landing["target_branch"] == name + "-trunk"
                landing["registries"].append({"path": "mutated"})
                landing["jobs"]["mutated"] = {"marker_dir": "mutated", "slot": "fast", "encoding": "json_line"}
                found[name] = landing["target_branch"]
        except Exception as exc:
            errors.append((name, type(exc), str(exc)))

    threads = [threading.Thread(target=worker, args=(name,)) for name in documents]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == [] and found == {"alpha": "alpha-trunk", "beta": "beta-trunk"}
    assert all(not thread.is_alive() for thread in threads)
    assert profile.resolve()["profile"]["policy"]["landing"] == _LANDING_DEFAULTS


def test_malformed_landing_file_is_not_replaced(tmp_path):
    root = make_store(tmp_path)
    profile.initialize(root, "solo")
    bad, path = _landing_path_case("registry", "rows/a\nb")
    target, entries = _assert_repository_landing_refusal(root, _landing_document(bad), "invalid value: " + path, path)
    target.write_text(json.dumps({"version": 1, "policy": {"landing": {"target_branch": "retry-trunk"}}}),
                      encoding="utf-8")
    loaded = profile.load(root, user_root=root)
    assert loaded["profile"]["policy"]["landing"]["target_branch"] == "retry-trunk"
    assert loaded["profile"]["policy"]["landing"]["speculative_enabled"] is False
    assert _landing_repo_entries(root) == entries


def test_unsupported_platform_writes_no_landing_document(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "descriptor_supported", lambda: False)
    with pytest.raises(profile.ProfileError, match="unsupported platform") as refused:
        profile.initialize(tmp_path, "solo")
    assert refused.value.exit_code == 1
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(profile.ProfileError, match="unsupported platform"):
        profile.load(tmp_path, user_root=tmp_path)
    assert list(tmp_path.iterdir()) == []
