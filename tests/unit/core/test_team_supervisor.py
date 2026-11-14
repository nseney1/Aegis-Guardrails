"""Supervisor profile matrix: narrow limits, pauses, backoff, state and health.

Filesystem cases skip without descriptor confinement. The unsupported-platform
case patches the module probe and still runs. No test needs git history.
"""
import copy
import inspect
import json
import os
import stat
from pathlib import Path

import pytest

from aegis_core import team_profile as profile
from aegis_core import team_status
from aegis_core import team_supervisor


def supervisor():
    return team_supervisor


def make_store(root):
    if not supervisor().descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    return root.resolve()


def _config(root):
    config = root / ".config" / "aegis"
    config.mkdir(mode=0o700, parents=True)
    config.chmod(0o700)
    return config


def _write(root, document):
    target = root.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


def _enabled_profile(*names):
    components = {name: {"enabled": True} for name in names}
    resolved = profile.resolve(user={"supervisor": {"components": components}})
    return resolved["profile"]


def _row(planned, name):
    return next(row for row in planned["components"] if row["id"] == name)


def test_module_exports_closed_sets_and_schema():
    module = supervisor()
    assert module.COMPONENTS == ("autopilot", "landing", "writer", "renew", "monitor")
    assert module.PAUSES == ("owner", "capacity", "disk", "audit", "autopilot", "landing", "writer", "renew", "monitor")
    assert module.SCHEMA == "aegis.team.supervisor/v1"
    assert module.STATE_NAME == "supervisor-state.json"
    assert module.SUPERVISOR_SCHEMA["additionalProperties"] is False


def test_defaults_are_disabled_and_frozen():
    result = profile.resolve()
    body = result["profile"]["supervisor"]
    assert body["pauses"] == []
    assert body["components"]["autopilot"]["interval_s"] == 30
    assert body["components"]["landing"]["interval_s"] == 60
    assert body["components"]["writer"]["interval_s"] == 60
    assert body["components"]["renew"]["interval_s"] == 9000
    assert body["components"]["monitor"]["interval_s"] == 20
    assert body["components"]["writer"]["restart"] == {"initial_s": 30, "max_s": 300, "limit": 3, "window_s": 300}
    assert body["health"]["writer_dead_s"] == 60
    assert body["health"]["disk_floor_mib"] == 4096
    assert all(spec["enabled"] is False for spec in body["components"].values())
    leaf = result["values"]["supervisor.components.autopilot.enabled"]
    assert leaf["layer"] == "defaults" and leaf["frozen_at_run_start"] is True


def test_initialize_keeps_supervisor_off_disk(tmp_path):
    root = make_store(tmp_path)
    profile.initialize(root, "solo")
    target = root / ".aegis" / "team" / "profile.json"
    assert "supervisor" not in json.loads(target.read_text(encoding="utf-8"))
    loaded = profile.load(root, user_root=root)
    assert loaded["profile"]["supervisor"]["components"]["writer"]["enabled"] is False


def test_repository_policy_does_not_enable_or_raise_ceilings():
    result = profile.resolve(repo={"run_config": {"autopilot": {"resume_writer": True}, "limits": {"writers_max": 8}}})
    writer = result["profile"]["supervisor"]["components"]["writer"]
    assert writer["enabled"] is False and writer["restart"]["limit"] == 3
    assert result["profile"]["supervisor"]["pauses"] == []


def test_resolve_does_not_mutate_caller_documents():
    repo = {"supervisor": {"components": {"autopilot": {"restart": {"limit": 1}}}}}
    user = {"supervisor": {"pauses": ["owner"]}}
    before = (json.dumps(repo), json.dumps(user))
    profile.resolve(repo=repo, user=user)
    assert (json.dumps(repo), json.dumps(user)) == before


@pytest.mark.parametrize("layer,document", [
    ("flags", {}),
    ("flags", {"components": {"autopilot": {"restart": {"limit": 1}}}}),
    ("flags", {"pauses": ["owner"]}),
])
def test_flags_cannot_set_supervisor(layer, document):
    with pytest.raises(profile.ProfileError, match="supervisor settings are owner-file only") as refused:
        profile.resolve(**{layer: {"supervisor": document}})
    assert refused.value.exit_code == 1 and refused.value.layer == "flags"
    assert refused.value.path == "supervisor"
    assert "\n" not in str(refused.value)


@pytest.mark.parametrize("document", [
    {"pauses": {"owner": False}},
    {"pauses": None},
    {"clear": True},
    {"unpause": ["owner"]},
    {"paused": False},
    {"pauses": [False]},
    {"pauses": ["owner", True]},
    {"components": {"writer": {"paused": False}}},
])
@pytest.mark.parametrize("layer", ["repo", "user"])
def test_pause_clear_shapes_refuse_before_union(layer, document):
    with pytest.raises(profile.ProfileError, match="supervisor pause cannot be cleared by the repository layer") as refused:
        profile.resolve(**{layer: {"supervisor": document}})
    assert refused.value.layer == layer and refused.value.exit_code == 1
    assert "false" not in str(refused.value).lower() or "cannot be cleared" in str(refused.value)


def test_pause_union_keeps_owner_names_and_canonical_order():
    kept = profile.resolve(user={"supervisor": {"pauses": ["owner"]}}, repo={"supervisor": {"pauses": []}})
    assert kept["profile"]["supervisor"]["pauses"] == ["owner"]
    assert kept["values"]["supervisor.pauses"]["layer"] == "user"
    merged = profile.resolve(user={"supervisor": {"pauses": ["owner"]}}, repo={"supervisor": {"pauses": ["landing"]}})
    assert merged["profile"]["supervisor"]["pauses"] == ["owner", "landing"]
    ordered = profile.resolve(repo={"supervisor": {"pauses": ["monitor", "owner"]}})
    assert ordered["profile"]["supervisor"]["pauses"] == ["owner", "monitor"]
    assert ordered["values"]["supervisor.pauses"]["layer"] == "repo"
    omitted = profile.resolve(user={"supervisor": {"pauses": ["capacity"]}})
    assert omitted["profile"]["supervisor"]["pauses"] == ["capacity"]


def test_duplicate_or_multiline_pause_is_refused_without_joining():
    with pytest.raises(profile.ProfileError, match="invalid value: supervisor.pauses") as duplicate:
        profile.resolve(repo={"supervisor": {"pauses": ["owner", "owner"]}})
    assert "\n" not in str(duplicate.value)
    with pytest.raises(profile.ProfileError, match="invalid value") as broken:
        profile.resolve(repo={"supervisor": {"pauses": ["owner\nlanding"]}})
    assert "\n" not in str(broken.value) and "owner\nlanding" not in str(broken.value)


def test_unknown_component_and_bool_limit_use_schema_refusals():
    with pytest.raises(profile.ProfileError, match="unknown key: supervisor.components.miner") as unknown:
        profile.resolve(repo={"supervisor": {"components": {"miner": {"enabled": True}}}})
    assert unknown.value.layer == "repo" and "\n" not in str(unknown.value)
    with pytest.raises(profile.ProfileError, match="wrong type: supervisor.components.autopilot.restart.limit"):
        profile.resolve(user={"supervisor": {"components": {"autopilot": {"restart": {"limit": True}}}}})


def test_unsafe_component_key_is_not_echoed():
    key = "token=super-secret-credential"
    with pytest.raises(profile.ProfileError, match="unknown key: supervisor.components") as refused:
        profile.resolve(repo={"supervisor": {"components": {key: {"enabled": True}}}})
    assert "super-secret" not in str(refused.value) and key not in str(refused.value)


@pytest.mark.parametrize("user,repo", [
    ({"components": {"autopilot": {"restart": {"limit": 2}}}}, {"components": {"autopilot": {"restart": {"limit": 3}}}}),
    ({}, {"components": {"autopilot": {"restart": {"limit": 4}}}}),
    ({}, {"components": {"autopilot": {"interval_s": 10}}}),
    ({}, {"components": {"autopilot": {"restart": {"max_s": 200}}}}),
    ({}, {"components": {"autopilot": {"enabled": True}}}),
    ({"health": {"writer_dead_s": 120}}, {"health": {"writer_dead_s": 60}}),
    ({"health": {"disk_floor_mib": 8192}}, {"health": {"disk_floor_mib": 4096}}),
])
def test_repository_cannot_widen_owner_ceiling(user, repo):
    with pytest.raises(profile.ProfileError, match="supervisor limit cannot be widened by the repository layer") as refused:
        profile.resolve(user={"supervisor": user} if user else None, repo={"supervisor": repo})
    assert refused.value.layer == "repo" and refused.value.exit_code == 1
    text = str(refused.value)
    assert not any(token in text for token in ("10", "200", "8192", "120"))


@pytest.mark.parametrize("user,repo,limit,interval,enabled", [
    ({"components": {"autopilot": {"restart": {"limit": 5}}}}, {"components": {"autopilot": {"restart": {"limit": 4}}}}, 4, 30, False),
    ({}, {"components": {"landing": {"interval_s": 60}}}, 3, 60, False),
    ({"components": {"writer": {"enabled": True}}}, {"components": {"writer": {"enabled": False}}}, 3, 60, False),
    ({"health": {"disk_floor_mib": 8192}}, {"health": {"disk_floor_mib": 16384}}, 3, 30, False),
])
def test_repository_may_narrow(user, repo, limit, interval, enabled):
    result = profile.resolve(user={"supervisor": user} if user else None, repo={"supervisor": repo})
    body = result["profile"]["supervisor"]
    if "limit" in json.dumps(repo):
        assert body["components"]["autopilot"]["restart"]["limit"] == limit
        assert result["values"]["supervisor.components.autopilot.restart.limit"]["layer"] == "repo"
        assert result["values"]["supervisor.components.autopilot.restart.initial_s"]["layer"] == "defaults"
    if "interval_s" in json.dumps(repo):
        assert body["components"]["landing"]["interval_s"] == interval
    if "enabled" in json.dumps(repo):
        assert body["components"]["writer"]["enabled"] is enabled
        assert result["values"]["supervisor.components.writer.enabled"]["layer"] == "repo"
    if "disk_floor_mib" in json.dumps(repo):
        assert body["health"]["disk_floor_mib"] == 16384
        assert result["values"]["supervisor.health.disk_floor_mib"]["layer"] == "repo"


def test_initial_above_max_names_the_layer_that_made_it_inconsistent():
    with pytest.raises(profile.ProfileError, match="value out of range: supervisor.components.autopilot.restart.initial_s") as user_error:
        profile.resolve(user={"supervisor": {"components": {"autopilot": {"restart": {"initial_s": 400}}}}})
    assert user_error.value.layer == "user" and "400" not in str(user_error.value)
    with pytest.raises(profile.ProfileError, match="value out of range: supervisor.components.writer.restart.initial_s") as repo_error:
        profile.resolve(repo={"supervisor": {"components": {"writer": {"restart": {"initial_s": 400}}}}})
    assert repo_error.value.layer == "repo" and "400" not in str(repo_error.value)


def test_backoff_window_success_and_pure_stepper():
    module = supervisor()
    policy = {"initial_s": 30, "max_s": 300, "limit": 3, "window_s": 300}
    original = module.empty_state()
    once = module.note_failure(original, "autopilot", 0, policy)
    assert original["components"]["autopilot"]["failures"] == []
    resolved = _enabled_profile("autopilot")
    waiting = module.plan(resolved, once, [], 0)
    assert _row(waiting, "autopilot")["action"] == "waiting_backoff"
    assert _row(waiting, "autopilot")["restart"]["delay_s"] == 30
    assert waiting["start"] == [] and waiting["starts_nothing"] is True
    ready = module.plan(resolved, once, [], 30)
    assert _row(ready, "autopilot")["action"] == "would_start" and ready["start"] == ["autopilot"]
    twice = module.note_failure(once, "autopilot", 10, policy)
    thrice = module.note_failure(twice, "autopilot", 20, policy)
    blocked = module.plan(resolved, thrice, [], 20)
    assert _row(blocked, "autopilot")["action"] == "restart_exhausted"
    assert "autopilot" not in blocked["start"]
    expired = module.plan(resolved, thrice, [], 300)
    row = _row(expired, "autopilot")
    assert row["restart"]["exhausted"] is False
    assert row["restart"]["failures"] == 2 and row["restart"]["delay_s"] == 60
    assert row["action"] == "would_start"
    reset = module.note_success(thrice, "autopilot", policy)
    assert reset["components"]["autopilot"]["failures"] == [] and reset["components"]["autopilot"]["delay_s"] == 30
    assert thrice["components"]["autopilot"]["failures"] == [0, 10, 20]
    ignored = module.empty_state()
    ignored["components"]["autopilot"]["delay_s"] = 86400
    ignored["components"]["autopilot"]["failures"] = [0]
    assert _row(module.plan(resolved, ignored, [], 0), "autopilot")["restart"]["delay_s"] == 30


def test_action_priority_and_pause_holds():
    module = supervisor()
    state = module.empty_state()
    disabled = module.plan(profile.resolve()["profile"], state, [], 0)
    assert disabled["start"] == [] and all(row["action"] == "disabled" for row in disabled["components"])
    held = module.plan(profile.resolve(user={"supervisor": {"pauses": ["audit"], "components": {name: {"enabled": True} for name in module.COMPONENTS}}})["profile"], state, [], 0)
    assert _row(held, "monitor")["action"] == "would_start"
    assert _row(held, "autopilot")["action"] == "paused"
    assert "audit" in _row(held, "writer")["pauses"] and "monitor" not in [row["id"] for row in held["components"] if "audit" in row["pauses"]]
    assert held["start"] == ["monitor"]
    named = module.plan(_enabled_profile("writer", "landing"), state, [], 0)
    # landing and writer are enabled; a writer pause holds only writer.
    paused = module.plan(profile.resolve(user={"supervisor": {"pauses": ["writer"], "components": {"writer": {"enabled": True}, "landing": {"enabled": True}}}})["profile"], state, [], 0)
    assert _row(paused, "writer")["action"] == "paused" and _row(paused, "landing")["action"] == "would_start"
    running = module.plan(_enabled_profile("autopilot"), state, ["autopilot"], 0)
    assert _row(running, "autopilot")["action"] == "already_running" and running["start"] == []
    assert named["start"] == ["landing", "writer"]


@pytest.mark.parametrize("running,now,reason", [
    (["miner"], 0, "invalid value: running"),
    (["autopilot", "autopilot"], 0, "invalid value: running"),
    ("autopilot", 0, "invalid value: running"),
    ([], -1, "invalid value: now"),
    ([], True, "invalid value: now"),
    ([], 10 ** 12 + 1, "invalid value: now"),
])
def test_plan_refusals_omit_components_and_input(running, now, reason):
    result = supervisor().plan(profile.resolve()["profile"], supervisor().empty_state(), running, now)
    assert result["status"] == "refused" and result["reason"] == reason and result["layer"] == "state"
    assert result["starts_nothing"] is True and result["start"] == [] and "components" not in result
    assert "miner" not in json.dumps(result)


def test_plan_rejects_bad_state_without_echo_or_mutation():
    state = {"version": 1, "secret": "token=super-secret-credential", "components": {}}
    before = json.dumps(state)
    result = supervisor().plan(profile.resolve()["profile"], state, [], 0)
    assert result["status"] == "refused" and result["reason"] == "unsafe or unreadable supervisor state"
    assert "secret" not in json.dumps(result) and "super-secret" not in json.dumps(result)
    assert json.dumps(state) == before and "components" not in result


def test_plan_and_health_are_idempotent_and_do_not_write(tmp_path):
    module = supervisor()
    root = make_store(tmp_path)
    config = _config(root)
    _write(root, {"version": 1, "preset": "solo"})
    (config / "team.json").write_text(json.dumps({"version": 1, "supervisor": {"components": {"autopilot": {"enabled": True}}}}), encoding="utf-8")
    module.store_state(module.note_failure(module.empty_state(), "autopilot", 0, {"initial_s": 30, "max_s": 300, "limit": 3, "window_s": 300}), user_root=root)
    before = {path.name: path.read_bytes() for path in config.iterdir()}
    loaded = profile.load(root, user_root=root)
    first = module.plan(loaded["profile"], module.load_state(user_root=root), [], 0)
    second = module.plan(loaded["profile"], module.load_state(user_root=root), [], 0)
    health = team_status.supervisor_health(root, 0, user_root=root)
    assert first == second and first["start"] == [] and health["starts_nothing"] is True
    assert {path.name: path.read_bytes() for path in config.iterdir()} == before


def test_widening_between_loads_does_not_reuse_the_first_start_list(tmp_path):
    root = make_store(tmp_path)
    config = _config(root)
    _write(root, {"version": 1, "supervisor": {"components": {"autopilot": {"restart": {"limit": 2}}}}})
    (config / "team.json").write_text(json.dumps({"version": 1, "supervisor": {"components": {"autopilot": {"enabled": True}}}}), encoding="utf-8")
    loaded = profile.load(root, user_root=root)
    planned = supervisor().plan(loaded["profile"], supervisor().empty_state(), [], 0)
    assert planned["start"] == ["autopilot"]
    _write(root, {"version": 1, "supervisor": {"components": {"autopilot": {"restart": {"limit": 4}}}}})
    with pytest.raises(profile.ProfileError, match="cannot be widened") as refused:
        profile.load(root, user_root=root)
    assert refused.value.layer == "repo" and planned["start"] == ["autopilot"]


def test_missing_state_is_empty_and_round_trips(tmp_path):
    module = supervisor()
    root = make_store(tmp_path)
    assert module.load_state(user_root=root)["components"]["renew"]["failures"] == []
    assert not (root / ".config").exists()
    config = _config(root)
    assert not (config / module.STATE_NAME).exists()
    state = module.note_failure(module.empty_state(), "landing", 5, {"initial_s": 30, "max_s": 300, "limit": 3, "window_s": 300})
    module.store_state(state, user_root=root)
    loaded = module.load_state(user_root=root)
    assert loaded["components"]["landing"]["failures"] == [5]
    assert set(loaded["components"]) == set(module.COMPONENTS)


@pytest.mark.parametrize("payload", [
    b"not json",
    b'{"version":1,"version":1}',
    b'{"version":2,"components":{}}',
    b'{"version":1,"components":{"autopilot":{"delay_s":1,"failures":[1e999]}}}',
    b'{"version":1,"note":"token=super-secret-credential"}',
    b"[" + b"[" * 20,
])
def test_malformed_state_refuses_without_echo_or_rewrite(tmp_path, payload):
    module = supervisor()
    root = make_store(tmp_path)
    config = _config(root)
    target = config / module.STATE_NAME
    target.write_bytes(payload)
    with pytest.raises(module.SupervisorError, match="^unsafe or unreadable supervisor state$") as refused:
        module.load_state(user_root=root)
    assert refused.value.layer == "state"
    assert "super-secret" not in str(refused.value) and "not json" not in str(refused.value)
    assert target.read_bytes() == payload


def test_oversized_state_refuses_before_a_rewrite(tmp_path):
    module = supervisor()
    root = make_store(tmp_path)
    target = _config(root) / module.STATE_NAME
    payload = b"{" + b" " * (profile.MAX_BYTES + 1)
    target.write_bytes(payload)
    with pytest.raises(module.SupervisorError, match="^unsafe or unreadable supervisor state$"):
        module.load_state(user_root=root)
    assert target.read_bytes() == payload


def test_group_writable_config_and_symlink_leaf_refuse(tmp_path):
    from conftest import symlink_or_skip
    module = supervisor()
    root = make_store(tmp_path / "repo")
    root.mkdir()
    config = _config(root)
    config.chmod(0o770)
    with pytest.raises(module.SupervisorError, match="owned by the current user"):
        module.load_state(user_root=root)
    config.chmod(0o700)
    outside = tmp_path / "outside.json"
    outside.write_text("token=super-secret-credential", encoding="utf-8")
    symlink_or_skip(outside, config / module.STATE_NAME)
    with pytest.raises(module.SupervisorError, match="^unsafe or unreadable supervisor state$") as refused:
        module.load_state(user_root=root)
    assert "super-secret" not in str(refused.value)
    assert outside.read_text(encoding="utf-8") == "token=super-secret-credential"


def test_store_does_not_create_a_missing_config_directory(tmp_path):
    root = make_store(tmp_path)
    with pytest.raises(supervisor().SupervisorError, match="unsafe or unreadable supervisor state"):
        supervisor().store_state(supervisor().empty_state(), user_root=root)
    assert not (root / ".config").exists()


def test_concurrent_replace_reads_whole_snapshots(tmp_path):
    import threading
    module = supervisor()
    root = make_store(tmp_path)
    _config(root)
    errors = []

    def write_one(index):
        state = module.empty_state()
        if index % 2:
            state["components"]["autopilot"]["failures"] = [index, index]
            state["components"]["autopilot"]["delay_s"] = 60
        else:
            state["components"]["autopilot"]["failures"] = [index]
            state["components"]["autopilot"]["delay_s"] = 30
        try:
            module.store_state(state, user_root=root)
        except module.SupervisorError as error:
            errors.append(str(error))

    def read_some():
        for _ in range(40):
            try:
                state = module.load_state(user_root=root)
            except module.SupervisorError as error:
                errors.append(str(error))
                return
            slot = state["components"]["autopilot"]
            failures, delay = slot["failures"], slot["delay_s"]
            whole = (failures == [] and delay == 30) or (len(failures) == 1 and delay == 30)
            whole = whole or (len(failures) == 2 and delay == 60 and failures[0] == failures[1])
            if not whole:
                errors.append((failures, delay))
                return

    threads = [threading.Thread(target=write_one, args=(index,)) for index in range(40)]
    threads.extend(threading.Thread(target=read_some) for _ in range(2))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == [] and all(not thread.is_alive() for thread in threads)


def test_unsupported_platform_refuses_state_io(tmp_path, monkeypatch):
    monkeypatch.setattr(team_supervisor, "descriptor_supported", lambda: False)
    with pytest.raises(team_supervisor.SupervisorError, match="unsupported platform"):
        team_supervisor.load_state(user_root=tmp_path)
    with pytest.raises(team_supervisor.SupervisorError, match="unsupported platform"):
        team_supervisor.store_state(team_supervisor.empty_state(), user_root=tmp_path)
    assert not (tmp_path / ".config").exists()


def test_health_reports_not_run_observations_and_never_starts(tmp_path):
    root = make_store(tmp_path)
    config = _config(root)
    _write(root, {"version": 1, "preset": "solo"})
    (config / "team.json").write_text(json.dumps({"version": 1, "supervisor": {"pauses": ["owner"], "components": {"monitor": {"enabled": True}}}}), encoding="utf-8")
    before = sorted(path.name for path in config.iterdir())
    health = team_status.supervisor_health(root, 0, user_root=root)
    assert health["schema"] == "aegis.team.supervisor/v1"
    assert health["profile"] == "valid" and health["reason"] is None and health["layer"] is None
    assert health["repository_profile_exists"] is True
    assert health["pauses"] == ["owner"] and health["starts_nothing"] is True and health["start"] == []
    assert health["observations"] == {name: "not_run" for name in ("writer_dead", "disk", "capacity", "usage", "audit")}
    assert all(row["next_eligible_at"] is None for row in health["components"])
    assert "action" not in health["components"][0]
    assert sorted(path.name for path in config.iterdir()) == before
    assert "supervisor" not in inspect.getsource(team_status.status)


def test_health_refusals_omit_observations_and_echo(tmp_path):
    root = make_store(tmp_path)
    target = _write(root, {"version": 1})
    target.write_bytes(b"not json")
    health = team_status.supervisor_health(root, 0, user_root=root)
    assert health["profile"] == "refused" and health["reason"] == "invalid profile JSON"
    assert health["starts_nothing"] is True and health["start"] == [] and health["pauses"] == []
    assert "components" not in health and "observations" not in health
    assert "not json" not in json.dumps(health)
    _config(root)
    target.write_text(json.dumps({"version": 1, "preset": "solo"}), encoding="utf-8")
    (root / ".config" / "aegis" / supervisor().STATE_NAME).write_bytes(b'{"secret":"token=super-secret-credential"}')
    refused = team_status.supervisor_health(root, 0, user_root=root)
    assert refused["profile"] == "refused" and refused["reason"] == "unsafe or unreadable supervisor state"
    assert "super-secret" not in json.dumps(refused) and "observations" not in refused and "components" not in refused


def test_health_redacts_untrusted_profile_text(tmp_path):
    root = make_store(tmp_path)
    _config(root)
    key = "token=\x1b[31msuper-secret-credential"
    _write(root, {"version": 1, "supervisor": {"components": {key: {"enabled": True}}}})
    health = team_status.supervisor_health(root, 0, user_root=root)
    rendered = json.dumps(health)
    assert health["profile"] == "refused" and "super-secret" not in rendered and "\x1b" not in rendered
    assert len(health["reason"]) <= 512


def test_health_unsupported_platform_uses_the_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(team_supervisor, "descriptor_supported", lambda: False)
    monkeypatch.setattr(profile, "descriptor_supported", lambda: False)
    health = team_status.supervisor_health(tmp_path, 0, user_root=tmp_path)
    assert health["profile"] == "refused" and "unsupported platform" in health["reason"]
    assert "components" not in health and "observations" not in health and health["starts_nothing"] is True


def test_symlink_profile_health_refuses(tmp_path):
    from conftest import symlink_or_skip
    root = make_store(tmp_path / "repo")
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_or_skip(outside, root / ".aegis", target_is_directory=True)
    health = team_status.supervisor_health(root, 0, user_root=root)
    assert health["profile"] == "refused" and "unsafe" in health["reason"]
    assert not list(outside.iterdir()) and "components" not in health


def test_host_plan_sources_do_not_import_supervisor():
    root = Path(__file__).resolve().parents[3]
    for name in ("aegis_core/model_select.py", "aegis_core/hosts.py", "aegis_core/team_hosts.py"):
        assert "team_supervisor" not in (root / name).read_text(encoding="utf-8")


def test_bad_clock_health_refuses_without_raising(tmp_path):
    root = make_store(tmp_path)
    _config(root)
    health = team_status.supervisor_health(root, -1, user_root=root)
    assert health["profile"] == "refused" and health["reason"] == "invalid value: now"
    assert "observations" not in health and "components" not in health


def _policy(**overrides):
    policy = {"initial_s": 30, "max_s": 300, "limit": 3, "window_s": 300}
    policy.update(overrides)
    return policy


def test_limit_reload_keeps_recorded_failures():
    module = supervisor()
    wide = _policy()
    narrow = _policy(limit=1)
    once = module.note_failure(module.empty_state(), "autopilot", 0, wide)
    twice = module.note_failure(once, "autopilot", 10, wide)
    reloaded = module.note_failure(twice, "autopilot", 20, narrow)
    assert reloaded["components"]["autopilot"]["failures"] == [0, 10, 20]
    assert twice["components"]["autopilot"]["failures"] == [0, 10]
    planned = module.plan(_enabled_profile("autopilot"), reloaded, [], 20)
    row = _row(planned, "autopilot")
    assert row["action"] == "restart_exhausted" and row["restart"]["failures"] == 3
    assert "autopilot" not in planned["start"]


def test_future_and_out_of_order_failures_stay_until_they_expire():
    module = supervisor()
    policy = _policy()
    state = module.empty_state()
    state["components"]["autopilot"]["failures"] = [1000, 1010, 1020]
    state["components"]["autopilot"]["delay_s"] = 30
    kept = module.note_failure(state, "autopilot", 500, policy)
    assert kept["components"]["autopilot"]["failures"] == [1000, 1010, 1020, 500]
    later = module.plan(_enabled_profile("autopilot"), kept, [], 1020)
    assert _row(later, "autopilot")["action"] == "restart_exhausted"
    assert _row(later, "autopilot")["restart"]["failures"] == 3
    ordered = module.empty_state()
    ordered["components"]["writer"]["failures"] = [80, 30, 10]
    ordered["components"]["writer"]["delay_s"] = 60
    revised = module.note_failure(ordered, "writer", 80, _policy(limit=2, window_s=100))
    assert 30 in revised["components"]["writer"]["failures"]
    blocked = module.plan(_enabled_profile("writer"), revised, [], 115)
    assert _row(blocked, "writer")["restart"]["exhausted"] is True
    assert 30 in revised["components"]["writer"]["failures"]


def test_pending_deadline_survives_window_expiry():
    module = supervisor()
    state = module.note_failure(module.empty_state(), "renew", 0, _policy())
    resolved = _enabled_profile("renew")
    early = module.plan(resolved, state, [], 0)
    assert _row(early, "renew")["action"] == "waiting_backoff"
    assert _row(early, "renew")["next_eligible_at"] == 9000
    assert early["start"] == []
    later = module.plan(resolved, state, [], 300)
    row = _row(later, "renew")
    assert row["action"] == "waiting_backoff" and row["next_eligible_at"] == 9000
    assert "renew" not in later["start"] and later["status"] == "dry_run"


def test_history_cap_drops_the_oldest_timestamp_not_the_policy_limit():
    module = supervisor()
    state = module.empty_state()
    state["components"]["landing"]["failures"] = list(range(100))
    state["components"]["landing"]["delay_s"] = 30
    updated = module.note_failure(state, "landing", 200, _policy(limit=3, window_s=86400))
    failures = updated["components"]["landing"]["failures"]
    assert len(failures) == 100 and 0 not in failures and 200 in failures and 1 in failures
    assert 1 <= updated["components"]["landing"]["delay_s"] <= 86400


def test_pause_union_labels_repository_additions():
    module = supervisor()
    body, origins = module.assemble({"pauses": []}, {"pauses": ["owner"]})
    assert body["pauses"] == ["owner"]
    assert origins[("supervisor", "pauses")] == "repo"
    _body, repeated = module.assemble({"pauses": ["owner"]}, {"pauses": ["owner"]})
    assert repeated[("supervisor", "pauses")] == "user"


def test_public_entries_refuse_out_of_range_bounds():
    module = supervisor()
    body = copy.deepcopy(_enabled_profile("autopilot"))
    body["supervisor"]["components"]["autopilot"]["restart"]["window_s"] = 0
    state = module.empty_state()
    state["components"]["autopilot"]["failures"] = [100]
    refused = module.plan(body, state, [], 100)
    assert refused["status"] == "refused" and refused["reason"] == "invalid value: supervisor"
    assert refused["start"] == [] and refused["starts_nothing"] is True and "components" not in refused
    assert "0" not in refused["reason"]
    with pytest.raises(module.SupervisorError, match="^invalid value: restart$") as limit_error:
        module.note_failure(module.empty_state(), "autopilot", 0, _policy(limit=0))
    assert "0" not in str(limit_error.value)
    with pytest.raises(module.SupervisorError, match="^invalid value: restart$"):
        module.note_success(module.empty_state(), "autopilot", _policy(initial_s=0))
    with pytest.raises(module.SupervisorError, match="^invalid value: restart$"):
        module.note_failure(module.empty_state(), "autopilot", 0, _policy(window_s=0))
    with pytest.raises(module.SupervisorError, match="pause cannot be cleared") as pause_error:
        module.assemble({"pauses": None}, {})
    assert type(pause_error.value) is module.SupervisorError
    with pytest.raises(module.SupervisorError, match="^value out of range:") as low_interval:
        module.assemble({}, {"components": {"autopilot": {"interval_s": 0}}})
    assert "widened" not in str(low_interval.value) and "0" not in str(low_interval.value)
    with pytest.raises(module.SupervisorError, match="cannot be widened"):
        module.assemble({}, {"components": {"autopilot": {"interval_s": 10}}})
    narrowed, _origins = module.assemble({"components": {"autopilot": {"restart": {"limit": 2}}}}, {})
    assert narrowed["components"]["autopilot"]["restart"]["limit"] == 2


def _filled_state(module, count):
    state = module.empty_state()
    for name in module.COMPONENTS:
        state["components"][name]["failures"] = list(range(count))
        state["components"][name]["delay_s"] = 30
    return state


def test_max_state_round_trips_and_one_past_is_refused(tmp_path):
    module = supervisor()
    root = make_store(tmp_path)
    config = _config(root)
    target = config / module.STATE_NAME
    module.store_state(_filled_state(module, 100), user_root=root)
    loaded = module.load_state(user_root=root)
    assert loaded["components"]["monitor"]["failures"] == list(range(100))
    assert loaded["components"]["renew"]["failures"] == list(range(100))
    before = target.read_bytes()
    with pytest.raises(module.SupervisorError, match="^unsafe or unreadable supervisor state$"):
        module.store_state(_filled_state(module, 101), user_root=root)
    assert target.read_bytes() == before
    over = json.loads(before.decode("utf-8"))
    over["components"]["autopilot"]["failures"].append(100)
    payload = (json.dumps(over, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    target.write_bytes(payload)
    with pytest.raises(module.SupervisorError, match="^unsafe or unreadable supervisor state$"):
        module.load_state(user_root=root)
    assert target.read_bytes() == payload


def test_two_writers_replace_full_history_as_whole_snapshots(tmp_path):
    import threading
    module = supervisor()
    root = make_store(tmp_path)
    _config(root)
    full = _filled_state(module, 100)
    blank = module.empty_state()
    errors = []

    def write_one(index):
        try:
            module.store_state(full if index % 2 else blank, user_root=root)
        except module.SupervisorError as error:
            errors.append(str(error))

    def read_some():
        for _ in range(20):
            try:
                state = module.load_state(user_root=root)
            except module.SupervisorError as error:
                errors.append(str(error))
                return
            lengths = [len(state["components"][name]["failures"]) for name in module.COMPONENTS]
            if lengths not in ([0, 0, 0, 0, 0], [100, 100, 100, 100, 100]):
                errors.append(lengths)
                return

    threads = [threading.Thread(target=write_one, args=(index,)) for index in range(8)]
    threads.extend(threading.Thread(target=read_some) for _ in range(2))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == [] and all(not thread.is_alive() for thread in threads)


def test_state_file_must_be_owner_only(tmp_path):
    module = supervisor()
    root = make_store(tmp_path)
    config = _config(root)
    config.chmod(0o755)
    target = config / module.STATE_NAME
    payload = (json.dumps(module.empty_state(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    target.write_bytes(payload)
    target.chmod(0o666)
    with pytest.raises(module.SupervisorError, match="supervisor state must be owned by the current user") as refused:
        module.load_state(user_root=root)
    assert refused.value.layer == "user" and "666" not in str(refused.value)
    with pytest.raises(module.SupervisorError, match="supervisor state must be owned by the current user"):
        module.store_state(module.note_failure(module.empty_state(), "monitor", 1, _policy()), user_root=root)
    assert target.read_bytes() == payload
    assert stat.S_IMODE(target.stat().st_mode) == 0o666
    target.chmod(0o644)
    assert module.load_state(user_root=root)["components"]["monitor"]["failures"] == []


def test_relative_user_root_refuses_before_anchor(tmp_path):
    module = supervisor()
    message = "^user profile root unavailable; configure a home directory$"
    for user_root in ("", ".", Path("."), Path("relative"), "relative", 15, "/tmp/bad\x00path"):
        with pytest.raises(module.SupervisorError, match=message) as refused:
            module.load_state(user_root=user_root)
        assert refused.value.layer == "user"
        with pytest.raises(module.SupervisorError, match=message):
            module.store_state(module.empty_state(), user_root=user_root)
    health = team_status.supervisor_health(tmp_path, 0, user_root="")
    assert health["profile"] == "refused"
    assert health["reason"] == "user profile root unavailable; configure a home directory"
    assert health["starts_nothing"] is True and health["start"] == [] and "components" not in health
    nulled = team_status.supervisor_health(tmp_path, 0, user_root="/tmp/bad\x00path")
    rendered = json.dumps(nulled)
    assert nulled["profile"] == "refused" and nulled["starts_nothing"] is True
    assert "\x00" not in rendered and "bad" not in rendered and "components" not in nulled


@pytest.mark.parametrize("entry", ["assemble", "plan", "health", "resolve", "load", "validate_resolved"])
@pytest.mark.parametrize("bad,reason", [
    (15, "wrong type: supervisor"),
    ([], "wrong type: supervisor"),
    ({"extra": "private-input"}, "unknown key: supervisor.extra"),
    (None, "wrong type: supervisor"),
], ids=["wrong_type", "wrong_container", "unknown_key", "none"])
def test_public_schema_refusal_census(tmp_path, entry, bad, reason):
    module = supervisor()
    if entry == "assemble":
        with pytest.raises(module.SupervisorError) as refused:
            module.assemble(bad, {})
        assert str(refused.value) == reason and refused.value.layer == "user"
        assert refused.value.path == ("supervisor.extra" if type(bad) is dict else "supervisor")
    elif entry == "plan":
        body = _enabled_profile("autopilot")
        body["supervisor"] = bad
        result = module.plan(body, module.empty_state(), [], 0)
        assert result == {"status": "refused", "reason": "invalid value: supervisor", "layer": "repo",
                          "starts_nothing": True, "start": []}
    elif entry in ("health", "load"):
        root = make_store(tmp_path)
        _write(root, {"version": 1, "supervisor": bad})
        if entry == "health":
            result = team_status.supervisor_health(root, 0, user_root=root)
            assert result["profile"] == "refused" and result["reason"] == reason
            assert result["layer"] == "repo" and result["start"] == []
            assert "components" not in result and "observations" not in result
        else:
            with pytest.raises(profile.ProfileError) as refused:
                profile.load(root, user_root=root)
            assert str(refused.value) == reason and refused.value.layer == "repo"
            assert refused.value.exit_code == 1
    else:
        with pytest.raises(profile.ProfileError) as refused:
            if entry == "resolve":
                profile.resolve(user={"supervisor": bad})
            else:
                resolved = profile.resolve()
                if type(bad) is dict:
                    resolved["profile"]["supervisor"].update(bad)
                else:
                    resolved["profile"]["supervisor"] = bad
                profile.validate_resolved(resolved)
        assert str(refused.value) == reason
        assert refused.value.layer == ("user" if entry == "resolve" else "repo")
        assert refused.value.exit_code == 1


@pytest.mark.parametrize("fragment,reason,path", [
    ({"health": 123}, "wrong type", "supervisor.health"),
    ({"components": []}, "wrong type", "supervisor.components"),
    ({"components": {"writer": False}}, "wrong type", "supervisor.components.writer"),
    ({"components": {"writer": {"restart": None}}}, "wrong type", "supervisor.components.writer.restart"),
    ({"components": {"writer": {"restart": {"limit": True}}}}, "wrong type", "supervisor.components.writer.restart.limit"),
    ({"components": {"miner": {}}}, "unknown key", "supervisor.components.miner"),
    ({"health": {"extra": "bad"}}, "unknown key", "supervisor.health.extra"),
    ({"components": {"writer": {"restart": {"extra": 1}}}}, "unknown key", "supervisor.components.writer.restart.extra"),
    ({"pauses": ["owner", "owner"]}, "invalid value", "supervisor.pauses"),
    ({"pauses": ["bad"]}, "invalid value", "supervisor.pauses.0"),
    ({"components": {"token=private-input": {}}}, "unknown key", "supervisor.components"),
])
@pytest.mark.parametrize("layer", ["user", "repo"])
def test_assemble_validates_closed_fragments_before_overlay(fragment, reason, path, layer):
    args = (fragment, {}) if layer == "user" else ({}, fragment)
    before = copy.deepcopy(args)
    with pytest.raises(team_supervisor.SupervisorError) as refused:
        team_supervisor.assemble(*args)
    assert str(refused.value) == reason + ": " + path
    assert refused.value.layer == layer and refused.value.path == path
    assert args == before


def test_invalid_owner_pause_wins_before_repository_widening():
    with pytest.raises(team_supervisor.SupervisorError) as refused:
        team_supervisor.assemble({"pauses": ["bad"]}, {"components": {"writer": {"enabled": True}}})
    assert str(refused.value) == "invalid value: supervisor.pauses.0"
    assert refused.value.layer == "user"


@pytest.mark.parametrize("name", team_supervisor.COMPONENTS)
@pytest.mark.parametrize("policy,failures,times,deadline", [
    (_policy(initial_s=200, max_s=600, limit=4, window_s=300), [0, 200], [200, 450, 510, 600], 600),
    (_policy(), [0], [30, 299, 300, 86400], 30),
    (_policy(window_s=50), [0, 30], [30, 60, 80, 90], 90),
    (_policy(), [0, 290], [290, 300, 350, 590], 350),
])
def test_pending_backoff_uses_failure_history_and_never_stored_delay(name, policy, failures, times, deadline):
    body = profile.resolve(user={"supervisor": {"components": {name: {
        "enabled": True, "interval_s": 30, "restart": policy}}}})["profile"]
    state = team_supervisor.empty_state()
    state["components"][name] = {"delay_s": 86400, "failures": failures}
    for now in times:
        row = _row(team_supervisor.plan(body, state, [], now), name)
        assert row["next_eligible_at"] == deadline
        assert row["action"] == ("waiting_backoff" if now < deadline else "would_start")


@pytest.mark.parametrize("failures", [[0, 30], [200, 0], [1000, 0, 290], [0, 1, 2, 50]])
def test_eligibility_never_moves_earlier_as_clock_advances(failures):
    body = _enabled_profile("autopilot")
    state = team_supervisor.empty_state()
    state["components"]["autopilot"] = {"delay_s": 86400, "failures": failures}
    deadlines = [_row(team_supervisor.plan(body, state, [], now), "autopilot")["next_eligible_at"]
                 for now in range(1101)]
    assert deadlines == sorted(deadlines)


@pytest.mark.parametrize("entry,operation", [("load", "fstat"), ("load", "read"), ("load", "close"),
                                          ("store", "fstat"), ("store", "close")])
def test_state_descriptor_errors_normalize_and_close(tmp_path, monkeypatch, operation, entry):
    from types import SimpleNamespace
    root = make_store(tmp_path)
    config = _config(root)
    target = config / team_supervisor.STATE_NAME
    target.write_text(json.dumps(team_supervisor.empty_state()), encoding="utf-8")
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)
        if operation == "close":
            raise OSError("private-input")

    def failed(*args, **kwargs):
        raise OSError("private-input")

    monkeypatch.setattr(team_supervisor, "os", SimpleNamespace(**{
        **vars(os), "open": opened, "close": closed,
        "fstat": failed if operation == "fstat" else os.fstat,
        "read": failed if operation == "read" else os.read,
    }))
    with pytest.raises(team_supervisor.SupervisorError, match="^unsafe or unreadable supervisor state$") as refused:
        if entry == "load":
            team_supervisor.load_state(user_root=root)
        else:
            team_supervisor.store_state(team_supervisor.empty_state(), user_root=root)
    assert refused.value.layer == "state" and live == set()
    assert json.loads(target.read_text(encoding="utf-8")) == team_supervisor.empty_state()


@pytest.mark.parametrize("root", [15, [], {}, None])
def test_health_refuses_malformed_repository_root(tmp_path, root):
    result = team_status.supervisor_health(root, 0, user_root=tmp_path)
    assert result["profile"] == "refused" and result["reason"] == "unsafe profile root; use an absolute trusted directory"
    assert result["layer"] == "repo" and "components" not in result


@pytest.mark.parametrize("root_kind", ["long", "nul_path"])
def test_malformed_owner_root_has_one_refusal_before_io(tmp_path, root_kind):
    root = "/" + "/".join(["a" * 200] * 200) if root_kind == "long" else Path(str(tmp_path) + "\x00bad")
    message = "^user profile root unavailable; configure a home directory$"
    with pytest.raises(team_supervisor.SupervisorError, match=message):
        team_supervisor.resolved_home(root)
    with pytest.raises(team_supervisor.SupervisorError, match=message):
        team_supervisor.load_state(user_root=root)
    with pytest.raises(team_supervisor.SupervisorError, match=message):
        team_supervisor.store_state(team_supervisor.empty_state(), user_root=root)
    with pytest.raises(profile.ProfileError, match=message):
        profile.load(tmp_path, user_root=root)
    health = team_status.supervisor_health(tmp_path, 0, user_root=root)
    assert health["profile"] == "refused" and health["reason"] == message[1:-1]


def test_health_refusal_fields_canonicalize_redact_then_truncate(tmp_path):
    secret = "x" * 490 + " token=\x1b[31msuper-secret-credential" + "y" * 40

    def refused(*args, **kwargs):
        raise profile.ProfileError(secret, path=secret, layer=secret)

    health = team_supervisor.report(refused, tmp_path, 0, user_root=tmp_path, profile_error=profile.ProfileError)
    assert health["profile"] == "refused" and health["layer"] is None
    for field in ("reason", "path"):
        assert len(health[field]) <= 512
        assert "super-secret" not in health[field] and "\x1b" not in health[field]


@pytest.mark.parametrize("separator", ["\n", "\r", "\v", "\f", "\x85", "\u2028", "\u2029"])
def test_health_refuses_multiline_values_without_joining(tmp_path, separator):
    def refused(*args, **kwargs):
        text = "first" + separator + "second"
        raise profile.ProfileError(text, path=text, layer="repo")

    health = team_supervisor.report(refused, tmp_path, 0, user_root=tmp_path, profile_error=profile.ProfileError)
    assert health["reason"] == "invalid value: supervisor" and health["path"] is None
    assert "first" not in json.dumps(health) and "second" not in json.dumps(health)


@pytest.mark.parametrize("name", team_supervisor.COMPONENTS)
def test_future_failure_cannot_shorten_an_outstanding_deadline(name):
    body = profile.resolve(user={"supervisor": {"components": {name: {
        "enabled": True, "interval_s": 30, "restart": _policy(limit=10, window_s=50)}}}})["profile"]
    state = team_supervisor.empty_state()
    state["components"][name] = {"delay_s": 86400, "failures": [60, 0, 1, 2, 3, 4]}
    for now in (59, 60, 90, 303, 304):
        row = _row(team_supervisor.plan(body, state, [], now), name)
        assert row["next_eligible_at"] == 304
        assert row["action"] == ("waiting_backoff" if now < 304 else "would_start")


@pytest.mark.parametrize("name", team_supervisor.COMPONENTS)
def test_later_failure_after_window_expiry_keeps_longer_pending_deadline(name):
    body = profile.resolve(user={"supervisor": {"components": {name: {
        "enabled": True, "interval_s": 30,
        "restart": _policy(initial_s=200, max_s=600, limit=4, window_s=300)}}}})["profile"]
    state = team_supervisor.empty_state()
    state["components"][name] = {"delay_s": 1, "failures": [0, 1, 2, 303]}
    for now in (2, 302, 303, 503, 601, 602):
        row = _row(team_supervisor.plan(body, state, [], now), name)
        assert row["next_eligible_at"] == 602
        assert row["action"] == ("waiting_backoff" if now < 602 else "would_start")


@pytest.mark.parametrize("history", [[], [60, 0, 1, 2, 3, 4], [0, 1, 2, 303], [100, 0, 0, 0, 0, 0],
                                    [5, 0, 1, 2, 3, 4], [200, 10, 100, 0]])
@pytest.mark.parametrize("window", [1, 5, 50, 300])
@pytest.mark.parametrize("initial,maximum", [(1, 300), (30, 300), (200, 600)])
def test_deadline_is_monotone_for_visible_history_prefixes(history, window, initial, maximum):
    body = profile.resolve(user={"supervisor": {"components": {"autopilot": {
        "enabled": True, "interval_s": 30,
        "restart": _policy(initial_s=initial, max_s=maximum, limit=100, window_s=window)}}}})["profile"]
    state = team_supervisor.empty_state()
    state["components"]["autopilot"] = {"delay_s": 86400, "failures": history}
    clocks = {0, 1, 4, 5, 30, 49, 50, 59, 60, 61, 90, 100, 200, 300, 600, 1000}
    for failure in history:
        clocks.update((max(0, failure - 1), failure, failure + window - 1, failure + window))
    deadlines = [_row(team_supervisor.plan(body, state, [], now), "autopilot")["next_eligible_at"]
                 for now in sorted(clocks)]
    visible = [deadline for deadline in deadlines if deadline is not None]
    assert visible == sorted(visible)
    assert state["components"]["autopilot"]["failures"] == history


@pytest.mark.parametrize("name", team_supervisor.COMPONENTS)
def test_recording_after_window_expiry_keeps_outstanding_deadline(name):
    policy = _policy(initial_s=200, max_s=600, limit=4, window_s=300)
    body = profile.resolve(user={"supervisor": {"components": {name: {
        "enabled": True, "interval_s": 30, "restart": policy}}}})["profile"]
    state = team_supervisor.empty_state()
    for now in (0, 1, 2):
        before = copy.deepcopy(state)
        updated = team_supervisor.note_failure(state, name, now, policy)
        assert state == before
        state = updated
    assert _row(team_supervisor.plan(body, state, [], 302), name)["next_eligible_at"] == 602
    state = team_supervisor.note_failure(state, name, 303, policy)
    for now in (303, 503, 601, 602):
        row = _row(team_supervisor.plan(body, state, [], now), name)
        assert row["next_eligible_at"] == 602
        assert row["action"] == ("waiting_backoff" if now < 602 else "would_start")
    expired = team_supervisor.note_failure(state, name, 604, policy)
    assert expired["components"][name]["failures"] == [604]


_TRANSITION_TIMELINES = [
    (_policy(initial_s=200, max_s=600, limit=4, window_s=300), [0, 1, 2, 303]),
    (_policy(limit=10, window_s=50), [0, 1, 2, 3, 4, 60]),
    (_policy(initial_s=1, max_s=86400, limit=100, window_s=50),
     list(range(18)) + list(range(200, 20200, 200))),
    (_policy(initial_s=1, max_s=86400, limit=100, window_s=50),
     list(range(17)) + list(range(200, 20200, 200))),
    (_policy(initial_s=1, max_s=86400, limit=100, window_s=86400), list(range(110))),
    (_policy(initial_s=200, max_s=600, limit=4, window_s=1), [0, 0, 0, 1, 2, 200, 201, 800]),
]


@pytest.mark.parametrize("policy,timeline", _TRANSITION_TIMELINES)
@pytest.mark.parametrize("interval", [30, 9000, 86400])
def test_public_record_and_plan_transitions_preserve_pending_deadlines(policy, timeline, interval):
    name = "autopilot"
    body = profile.resolve(user={"supervisor": {"components": {name: {
        "enabled": True, "interval_s": interval, "restart": policy}}}})["profile"]
    state, history, pending = team_supervisor.empty_state(), [], None
    for index, now in enumerate(timeline):
        before = _row(team_supervisor.plan(body, state, [], now), name)
        if pending is not None and now < pending:
            assert before["next_eligible_at"] >= pending
        updated = team_supervisor.note_failure(state, name, now, policy)
        assert len(updated["components"][name]["failures"]) <= 100
        state = updated
        history.append(now)
        after = _row(team_supervisor.plan(body, state, [], now), name)
        if before["next_eligible_at"] is not None and now < before["next_eligible_at"]:
            assert after["next_eligible_at"] >= before["next_eligible_at"]
        pending = after["next_eligible_at"]
        count = min(100, sum(now - failure < policy["window_s"] for failure in history))
        assert after["restart"]["failures"] == count
        assert after["restart"]["exhausted"] == (count >= policy["limit"])
        for clock in sorted({now, now + 1, now + policy["window_s"], pending - 1, pending}):
            if clock < now or index + 1 < len(timeline) and clock > timeline[index + 1]:
                continue
            row = _row(team_supervisor.plan(body, state, [], clock), name)
            assert row["next_eligible_at"] >= pending
            if clock < pending:
                assert row["action"] != "would_start"


def test_recording_refuses_capacity_pressure_without_losing_future_evidence():
    policy = _policy(window_s=86400)
    state = team_supervisor.empty_state()
    for now in range(1000, 1100):
        state = team_supervisor.note_failure(state, "autopilot", now, policy)
    before = copy.deepcopy(state)
    with pytest.raises(team_supervisor.SupervisorError, match="^supervisor failure history limit exceeded$") as refused:
        team_supervisor.note_failure(state, "autopilot", 500, policy)
    assert refused.value.layer == "state" and state == before


@pytest.mark.parametrize("name", team_supervisor.COMPONENTS)
@pytest.mark.parametrize("interval", [30, 9000])
@pytest.mark.parametrize("window,times", [(300, [1000, 1001, 1002]), (1, [1000, 1000, 1000])])
def test_public_record_and_plan_keep_deadlines_across_clock_rollback(name, interval, window, times):
    policy = _policy(initial_s=200, max_s=600, limit=4, window_s=window)
    body = profile.resolve(user={"supervisor": {"components": {name: {
        "enabled": True, "interval_s": interval, "restart": policy}}}})["profile"]
    state, history = team_supervisor.empty_state(), []
    for now in times:
        state = team_supervisor.note_failure(state, name, now, policy)
        history.append(now)
    pending = _row(team_supervisor.plan(body, state, [], times[-1]), name)["next_eligible_at"]
    assert pending == max(times[-1] + 600, times[-1] + interval)
    for now in (1001, 500, 500, 1003, 1603, 20000):
        before = _row(team_supervisor.plan(body, state, [], now), name)
        if now < pending:
            assert before["next_eligible_at"] >= pending
        state = team_supervisor.note_failure(state, name, now, policy)
        history.append(now)
        after = _row(team_supervisor.plan(body, state, [], now), name)
        if now < pending:
            assert after["next_eligible_at"] >= pending
            assert after["action"] != "would_start"
        pending = after["next_eligible_at"]
        count = sum(0 <= now - failure < window for failure in history)
        assert after["restart"]["failures"] == count


@pytest.mark.parametrize("parent,missing,sibling,bad", [
    ((), "components", "pauses", ["bad"]),
    (("components",), "autopilot", "writer", {"interval_s": 0}),
    (("components", "autopilot"), "enabled", "interval_s", 0),
    (("components", "autopilot", "restart"), "initial_s", "max_s", 0),
    (("health",), "audit_interval_s", "writer_dead_s", 0),
])
@pytest.mark.parametrize("surface", ["resolved", "supervisor"])
@pytest.mark.parametrize("reverse", [False, True])
def test_required_supervisor_keys_precede_invalid_siblings(parent, missing, sibling, bad, surface, reverse):
    resolved = profile.resolve()
    body = resolved["profile"]["supervisor"]
    target = body
    for part in parent:
        target = target[part]
    del target[missing]
    if type(bad) is dict:
        target[sibling].update(bad)
    else:
        target[sibling] = bad
    if reverse:
        resolved = json.loads(json.dumps(resolved), object_pairs_hook=lambda pairs: dict(reversed(pairs)))
        body = resolved["profile"]["supervisor"]
    path = ".".join(("supervisor", *parent))
    error = profile.ProfileError if surface == "resolved" else team_supervisor.SupervisorError
    with pytest.raises(error) as refused:
        if surface == "resolved":
            profile.validate_resolved(resolved)
        else:
            team_supervisor.require_resolved(body)
    assert str(refused.value) == "invalid value: " + path
    assert refused.value.path == path and refused.value.layer == "repo"
