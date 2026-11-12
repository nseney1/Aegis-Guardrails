"""Public profile validation, provenance and anchored storage."""
import json

import pytest

from aegis_core import storage, storage_confined, team_profile as profile


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
    assert profile.load(root, user_root=root)["profile"]["preset"] == "solo"
    assert calls == [profile.REPO_PATH, profile.REPO_PATH, profile.USER_PATH[-1:]]
