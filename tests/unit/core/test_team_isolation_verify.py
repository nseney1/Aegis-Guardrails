"""Pure isolation contracts: caller-owned observations, no filesystem probes."""
import copy
import dataclasses
import errno
import importlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from aegis_core import hosts, team_host_registry, team_isolation
from tests.helpers_isolation_catalogue import catalogue_config_parts


IMAGE = "localhost/aegis-teams@sha256:" + "a" * 64
ISOLATION = dict(mode="container", engine="podman", image=IMAGE, cpus=1, memory="1g", pids=64)
TABLE = {"claude": {"home": {"variable": "CLAUDE_CONFIG_DIR", "run_folder": "claude-home"}},
         "codex": {"home": {"variable": "CODEX_HOME", "run_folder": "codex-home"}}}


@pytest.fixture
def core():
    return importlib.import_module("aegis_core.team_isolation_mounts")


@pytest.fixture
def verifier():
    return importlib.import_module("aegis_core.team_isolation_verify")


def _catalogue_names(rows):
    """Keep normalized top-level roots in their original case."""
    return {parts[0] for parts in catalogue_config_parts(rows, "/owner")}


def _non_teams_host(config_paths):
    """Copy of a catalogue host outside the Teams registry, with injected paths."""
    source = next(row for row in hosts.HOSTS if row.id not in team_host_registry.TEAM_HOSTS)
    return dataclasses.replace(source, config_paths=tuple(config_paths))


def _observation_names(catalogue):
    minimum = {".ssh", ".gnupg", ".config", ".aws", ".kube", ".docker", ".netrc", ".git-credentials", ".local"}
    exact = _catalogue_names(hosts.HOSTS if catalogue is None else catalogue)
    return minimum | exact | {name.casefold() for name in exact}


def _facts(paths, names):
    result = {}
    for path in paths:
        value = PurePosixPath(path)
        for part in (value, *value.parents):
            if str(part) in result:
                continue
            record = dict(device=1, inode=len(result) + 1, uid=1000, gid=1000,
                          mode=stat.S_IFDIR | 0o700, acl=None)
            result[str(part)] = dict(record, after=copy.deepcopy(record))
    owner = next((path for path in paths if path.endswith("/home") or path == "/owner"), "/owner")
    for name in names:
        result.setdefault(owner + "/" + name, None)
    return result


def facts(*paths, catalogue=None):
    """Model descriptor observations, including a second unchanged metadata sample."""
    return _facts(paths, _observation_names(catalogue))


def plan(core, **changes):
    args = dict(run="/work/run", project="/work/project", source="/source", python_prefix="/venv",
                home="/owner", owner_uid=1000,
                observed=facts("/work/run", "/work/project", "/source", "/venv", "/owner"))
    args.update(changes)
    args.setdefault("owner_homes", dict.fromkeys(("explicit", "ambient", "password"), args["home"]))
    return core.mount_plan(**args)


def test_plan_sorted_deduplicated_and_repeatable(core):
    expected = [{"source": p, "destination": p, "rw": rw} for p, rw in
                [("/source", False), ("/venv", False), ("/work/project", True), ("/work/run", True)]]
    assert plan(core) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: plan(core), range(6))) == [expected] * 6


@pytest.mark.parametrize("path", ["/owner", "/OWNER", "/work/../owner", "/owner/.ssh"],
                         ids=["home", "case", "climbs", "secret"])
def test_home_and_secret_aliases_refused(core, path):
    observed = facts("/work/run", "/source", "/venv", "/owner", path)
    if path == "/OWNER":
        observed[path]["inode"] = observed[path]["after"]["inode"] = observed["/owner"]["inode"]
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        plan(core, project=path, observed=observed)


@pytest.mark.parametrize("change,reason", [
    ({"mode": stat.S_IFLNK | 0o777}, "unsafe_mount"),
    ({"acl": "unreadable"}, "mount_metadata"),
    ({"uid": 1234}, "unsafe_mount"),
    ({"mode": stat.S_IFDIR | 0o777}, "unsafe_mount"),
])
def test_untrusted_component_refused_and_retry(core, change, reason):
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner")
    observed["/work"].update(change)
    observed["/work"]["after"].update(change)
    for _ in range(2):
        with pytest.raises(core.IsolationRefusal, match="^" + reason + "$"):
            plan(core, observed=observed)
    assert plan(core)


def test_changed_component_and_missing_observation_refused(core):
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner")
    observed["/work"]["after"]["inode"] += 1
    with pytest.raises(core.IsolationRefusal, match="^mount_changed$"):
        plan(core, observed=observed)
    del observed["/work"]
    with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
        plan(core, observed=observed)


@pytest.mark.parametrize("raw,reason", [
    (b"x" * (1024 * 1024 + 1), "document_size"), (b"\xff", "document_invalid"),
    (b'{"mode":"host","mode":"container"}', "document_invalid"),
    (b'{"mode":"host","token=secret":1}', "isolation_fields"),
    (b'{"mode":"container","engine":"docker","image":"' + IMAGE.encode() +
     b'","cpus":1,"memory":"1g","pids":64}', "docker_unqualified"),
], ids=["oversize", "utf8", "duplicate", "unknown", "docker"])
def test_document_refusals_are_typed_and_do_not_echo(core, raw, reason):
    with pytest.raises(core.IsolationRefusal) as error:
        core.load_isolation(raw, cpu_count=4, platform="linux")
    assert str(error.value) == reason
    assert error.value.reason == reason
    assert error.value.status == "refused"
    assert error.value.exit_code == 1


def test_size_checked_before_parser(core, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parser was called before size refusal")
    monkeypatch.setattr("aegis_core.team_isolation_mounts.strict_loads", forbidden)
    with pytest.raises(core.IsolationRefusal, match="^document_size$"):
        core.load_isolation(b" " * (core.MAX_DOCUMENT_BYTES + 1), cpu_count=4, platform="linux")


def test_host_mode_and_unsupported_platform(core, monkeypatch):
    monkeypatch.setattr("aegis_core.team_isolation_mounts.container_supported", lambda platform: False)
    assert core.read_isolation(None, cpu_count=None, platform="win32") is None
    assert core.load_isolation(b'{"mode":"host"}', cpu_count=None, platform="win32") is None
    with pytest.raises(core.IsolationRefusal, match="^unsupported_platform$"):
        core.read_isolation(ISOLATION, cpu_count=4, platform="linux")


def expected(core, verifier, **changes):
    return verifier.expected_plan(dict(ISOLATION, **changes), run="/work/run", mounts=plan(core),
        image_inspect=[{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}],
        host_table=TABLE, home="/owner", owner_uid=1000,
        owner_homes=dict.fromkeys(("explicit", "ambient", "password"), "/owner"),
        observed=facts("/work/run", "/work/project", "/source", "/venv", "/owner"),
        cpu_count=4, platform="linux", uid=1000, gid=1000)


def verification_context():
    return dict(host_table=TABLE, home="/owner", owner_uid=1000,
                owner_homes=dict.fromkeys(("explicit", "ambient", "password"), "/owner"),
                observed=facts("/work/run", "/work/project", "/source", "/venv", "/owner"))


def test_verification_reports_all_mismatches(core, verifier):
    wanted = expected(core, verifier)
    before = copy.deepcopy(wanted)
    errors = verifier.verify({}, wanted, **verification_context())
    assert errors == ["label", "name", "image", "mounts", "read_only", "user", "privileged", "cap_add",
                      "pid_mode", "ipc_mode", "userns_mode", "network_mode", "devices", "security_opt",
                      "cpus", "memory", "pids", "environment"]
    assert wanted == before
    assert verifier.verify({}, wanted, **verification_context()) == errors


def test_tools_plan_parity(core, legacy_observer):
    """Legacy test oracle only; core never imports unpackaged tools."""
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    assert_plan_parity(core, legacy_observer, homes, round2_facts(homes), allowed=True)


def test_host_names_are_injected(core):
    assert core.container_env("/work/run", host_table=TABLE)["CODEX_HOME"] == "/work/run/codex-home"
    assert any("~/.codex" in host.config_paths for host in hosts.HOSTS)


def inspected(core, verifier, wanted):
    env = core.container_env(wanted["run"], host_table=TABLE)
    actual = {"Name": "/" + verifier.container_name(wanted["run"]), "Image": "sha256:" + "b" * 64,
              "Config": {"Labels": {"aegis.team.run": wanted["run"]}, "User": wanted["user"],
                         "Env": [k + "=" + v for k, v in env.items()]},
              "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "CapAdd": [], "Devices": [],
                             "PidMode": "", "IpcMode": "private", "UsernsMode": "", "NetworkMode": "bridge",
                             "SecurityOpt": ["systempaths=unconfined"], "NanoCpus": 1000000000,
                             "Memory": wanted["memory"], "PidsLimit": wanted["pids"],
                             "Tmpfs": {"/tmp": "rw,nosuid,nodev", "/dev/shm": "rw,nosuid,nodev"}},
              "Mounts": [dict(Type="bind", Source=r["source"], Destination=r["destination"], RW=r["rw"])
                         for r in wanted["mounts"]]}
    if wanted["engine"] == "podman":
        actual["Name"] = actual["Name"][1:]
        actual["HostConfig"].update(PidMode="private", UsernsMode="private", SecurityOpt=[],
                                  IDMappings={"UidMap": ["1000:0:1"], "GidMap": ["1000:0:1"]})
        actual["Config"]["CreateCommand"] = ["podman", "run", "--security-opt=unmask=/proc/*",
            "--env-host=false", "--http-proxy=false", "--read-only-tmpfs=false"] + [
            word for key, value in sorted(env.items()) for word in ("--env", key + "=" + value)] + [IMAGE]
    return actual


@pytest.mark.parametrize("selected", ["docker", "podman"])
def test_matching_inspection_and_independent_mismatches(core, verifier, selected):
    wanted = expected(core, verifier, engine=selected, allow_unqualified=True)
    actual = inspected(core, verifier, wanted)
    assert verifier.verify(json.dumps([actual]), wanted, **verification_context()) == []
    assert verifier.verify(json.dumps([actual]).encode(), wanted, **verification_context()) == []
    before = copy.deepcopy(actual)
    actual["HostConfig"]["Privileged"] = True
    actual["HostConfig"]["Memory"] = 0
    actual["Mounts"][0]["RW"] = not actual["Mounts"][0]["RW"]
    assert verifier.verify(actual, wanted, **verification_context()) == ["mounts", "privileged", "memory"]
    assert verifier.verify(before, wanted, **verification_context()) == []


@pytest.mark.parametrize("selected", ["docker", "podman"])
def test_verification_parity_with_legacy(core, verifier, monkeypatch, selected, legacy_observer):
    context = verification_context()
    legacy = legacy_observer(context["owner_homes"], context["observed"])
    # Filesystem qualification and host discovery live in the adapter. Compare
    # the legacy pure verification algorithm with exactly the injected facts.
    monkeypatch.setattr("hierarchy_container_verify._home_folders", lambda: core.home_folders(TABLE))
    wanted = expected(core, verifier, engine=selected, allow_unqualified=True)
    actual = inspected(core, verifier, wanted)
    for mutate in (lambda a: None, lambda a: a["HostConfig"].update(Memory=0, Devices=["bad"]),
                   lambda a: a["Mounts"].clear(), lambda a: a["Config"].update(Env=[])):
        value = copy.deepcopy(actual)
        mutate(value)
        assert verifier.verify(value, wanted, **verification_context()) == legacy.verify(value, wanted)


def test_identity_alias_to_home_is_refused(core):
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner")
    observed["/work/project"]["inode"] = observed["/owner"]["inode"]
    observed["/work/project"]["after"]["inode"] = observed["/owner"]["inode"]
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        plan(core, observed=observed)


def test_identity_alias_across_access_boundary_is_refused(core):
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner")
    observed["/work/run"]["inode"] = observed["/source"]["inode"]
    observed["/work/run"]["after"]["inode"] = observed["/source"]["inode"]
    with pytest.raises(core.IsolationRefusal, match="^mount_overlap$"):
        plan(core, observed=observed)


@pytest.mark.parametrize("acl", [[], [[1, 7, 4294967295], [4, 0, 4294967295], [32, 0, 1]],
    [[1, 7, 4294967295], [2, 2, 1234], [4, 0, 4294967295], [16, 0, 4294967295], [32, 0, 4294967295]]],
    ids=["missing", "identity", "masked-valid"])
def test_acl_structure_and_mask(core, acl):
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner")
    observed["/work"]["acl"] = acl
    observed["/work"]["after"]["acl"] = copy.deepcopy(acl)
    if len(acl) == 5:
        assert plan(core, observed=observed)
    else:
        with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
            plan(core, observed=observed)


@pytest.mark.parametrize("value", [None, [], {"unexpected": 1}, {"Config": []}, {"Mounts": [{}]}])
def test_malformed_inspect_never_raises_raw_exception(core, verifier, value):
    wanted = expected(core, verifier)
    assert verifier.verify(value, wanted, **verification_context())


def test_deep_and_oversized_parsed_inputs_refused(core):
    for value in ({"mode": "container", "cpus": 1 << 200}, [None] * 4097):
        with pytest.raises(core.IsolationRefusal, match="^document_size$"):
            core.read_isolation(value, cpu_count=4, platform="linux")


def test_secret_symlink_target_is_protected(core):
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner", "/vault")
    record = dict(device=1, inode=100, uid=1000, gid=1000, mode=stat.S_IFLNK | 0o777,
                  acl=None, target="/vault")
    observed["/owner/.ssh"] = dict(record, after=copy.deepcopy(record))
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        plan(core, source="/vault", observed=observed)


def test_verification_revalidates_untrusted_expected_mounts(core, verifier):
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    wanted["mounts"][0] = dict(source="/owner", destination="/owner", rw=False)
    actual = inspected(core, verifier, wanted)
    assert verifier.verify(actual, wanted, **verification_context()) == ["mounts"]


def test_unknown_protected_metadata_is_not_absence(core):
    observed = verification_context()["observed"]
    del observed["/owner/.ssh"]
    with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
        plan(core, observed=observed)
    observed["/owner/.ssh"] = None
    assert plan(core, observed=observed)


def test_acl_foreign_writer_and_stale_protected_target_refused(core):
    observed = verification_context()["observed"]
    acl = [[1, 7, 4294967295], [2, 2, 1234], [4, 0, 4294967295], [16, 2, 4294967295], [32, 0, 4294967295]]
    observed["/work"]["mode"] = stat.S_IFDIR | 0o720
    observed["/work"]["acl"] = acl
    observed["/work"]["after"] = {k: copy.deepcopy(v) for k, v in observed["/work"].items() if k != "after"}
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        plan(core, observed=observed)
    observed = verification_context()["observed"]
    observed["/owner"]["after"]["inode"] += 1
    with pytest.raises(core.IsolationRefusal, match="^mount_changed$"):
        plan(core, observed=observed)


def test_concurrent_refusal_does_not_poison_valid_snapshots(core):
    bad = verification_context()["observed"]
    bad["/source"]["after"]["inode"] += 1
    def attempt(observed):
        try:
            return plan(core, observed=observed)
        except core.IsolationRefusal as error:
            return error.reason
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(attempt, [bad, verification_context()["observed"], bad]))
    assert results == ["mount_changed", plan(core), "mount_changed"]


def test_scalar_helpers_refuse_before_numeric_or_path_work(core):
    with pytest.raises(core.IsolationRefusal, match="^isolation_cpus$"):
        core.cpus_limit(1 << 10000)
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        core.absolute_path("/" + "/".join(["part"] * 129))


def test_unreadable_protected_acl_is_not_ignored(core):
    observed = verification_context()["observed"]
    observed["/owner"]["acl"] = "unreadable"
    observed["/owner"]["after"]["acl"] = "unreadable"
    with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
        plan(core, observed=observed)


def test_malformed_field_shapes_use_the_public_refusal_contract(core, verifier):
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    actual = inspected(core, verifier, wanted)
    shapes = [None, True, 0, 1.0, "invalid", [], {}, [None], {"invalid": None}]
    def refused_or_mismatched(value, expected_record):
        try:
            result = verifier.verify(value, expected_record, **verification_context())
        except core.IsolationRefusal as error:
            assert error.exit_code == 1
        else:
            # Some shapes are valid alternatives (e.g. CapAdd null or []).
            assert type(result) is list and all(type(field) is str for field in result)
    for field in wanted:
        for shape in shapes:
            invalid = copy.deepcopy(wanted)
            invalid[field] = shape
            refused_or_mismatched(actual, invalid)
    for group in (None, "Config", "HostConfig"):
        for field in (actual if group is None else actual[group]):
            for shape in shapes:
                invalid = copy.deepcopy(actual)
                (invalid if group is None else invalid[group])[field] = shape
                refused_or_mismatched(invalid, wanted)


def round2_facts(homes, *extra, catalogue=None):
    names = _observation_names(catalogue)
    observed = _facts(("/work/run", "/work/project", "/source", "/venv", *homes.values(), *extra), names)
    for home in homes.values():
        for name in names:
            observed.setdefault(home + "/" + name, None)
    return observed


def round2_plan(core, homes, observed, **changes):
    args = dict(run="/work/run", project="/work/project", source="/source", python_prefix="/venv",
                home=homes["explicit"], owner_uid=1000, observed=observed, owner_homes=homes)
    args.update(changes)
    return core.mount_plan(**args)


def observed_link(observed, path, target):
    row = dict(device=1, inode=10000 + len(observed), uid=1000, gid=1000,
               mode=stat.S_IFLNK | 0o777, acl=None, target=target)
    observed[path] = dict(row, after=copy.deepcopy(row))


@pytest.fixture
def legacy_observer(monkeypatch):
    """Inject OS facts while keeping every legacy exclusion algorithm intact."""
    if os.name != "posix" or not sys.platform.startswith("linux"):
        pytest.skip("legacy exclusion oracle requires POSIX paths and pwd")
    legacy = importlib.import_module("tools.hierarchy_container")
    checks = importlib.import_module("hierarchy_container_verify")
    native_absolute = checks._absolute

    def install(homes, observed):
        def lstat(path):
            key = "/" + str(Path(path)).lstrip("/")
            if key not in observed:
                if any(str(parent) in observed and observed[str(parent)] is None for parent in Path(key).parents):
                    raise FileNotFoundError(errno.ENOENT, "confirmed absent parent")
                raise OSError(errno.EACCES, "observation unavailable")
            row = observed[key]
            if row is None:
                raise FileNotFoundError(errno.ENOENT, "confirmed absence")
            return SimpleNamespace(st_mode=row["mode"], st_uid=row["uid"], st_gid=row["gid"],
                                   st_dev=row["device"], st_ino=row["inode"])

        def stat_path(path):
            return lstat(checks._canonical_path(Path(path)))

        def readlink(path):
            return observed[str(Path(path))]["target"]

        def absolute(value, label):
            # Inject only the password lookup's value at its existing lexical
            # validation boundary. _owner_roots and _owner_exclusions stay real.
            return native_absolute(homes["password"] if label == "password home" else value, label)

        facade = SimpleNamespace(**{**vars(os), "lstat": lstat, "stat": stat_path,
                                    "readlink": readlink, "geteuid": lambda: 1000})
        monkeypatch.setattr("tools.hierarchy_container.os", facade)
        monkeypatch.setattr("hierarchy_container_verify.os", facade)
        monkeypatch.setattr("hierarchy_container_verify._home", lambda: Path(homes["ambient"]))
        monkeypatch.setattr("hierarchy_container_verify._absolute", absolute)
        monkeypatch.setattr("tools.hierarchy_container._access_acl", lambda path, mode: observed[str(path)]["acl"])
        monkeypatch.setattr("hierarchy_container_verify._home_folders", lambda: {"HOME": "home",
                            **{row["home"]["variable"]: row["home"]["run_folder"] for row in TABLE.values()}})
        return legacy
    return install


def assert_plan_parity(core, legacy_observer, homes, observed, *, allowed, **changes):
    legacy = legacy_observer(homes, observed)
    args = dict(run="/work/run", project="/work/project", source="/source", python_prefix="/venv",
                home=homes["explicit"])
    args.update(changes)
    try:
        old = legacy.mount_plan(**args)
    except ValueError:
        old = None
    try:
        new = round2_plan(core, homes, observed, **changes)
    except core.IsolationRefusal:
        new = None
    assert (old is not None) is allowed
    assert (new is not None) is allowed
    assert new == old


@pytest.mark.parametrize("role", ["explicit", "ambient", "password"])
def test_complete_owner_roots_plan_parity(core, legacy_observer, role):
    homes = dict(explicit="/alt-home", ambient="/ambient-home", password="/home/alice")
    observed = round2_facts(homes)
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=False, project=homes[role])


@pytest.mark.parametrize("kind,allowed", [("home", True), ("secret", False), ("local", True)])
def test_owner_descendant_kinds_plan_parity(core, legacy_observer, kind, allowed):
    homes = dict(explicit="/owner", ambient="/owner", password="/owner")
    project = {"home": "/owner/project", "secret": "/owner/.ssh/project", "local": "/owner/.local/project"}[kind]
    observed = round2_facts(homes, project)
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=allowed, project=project)


@pytest.mark.parametrize("kind", ["secret", "local"])
@pytest.mark.parametrize("relation", ["root", "parent", "child"])
def test_relocated_exclusion_kinds_plan_parity(core, legacy_observer, kind, relation):
    homes = dict(explicit="/owner", ambient="/owner", password="/owner")
    project = {"root": "/storage/local", "parent": "/storage", "child": "/storage/local/share/project"}[relation]
    observed = round2_facts(homes, project, "/storage/local/venv")
    observed_link(observed, "/owner/" + (".local" if kind == "local" else ".ssh"), "/storage/local")
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=kind == "local" and relation == "child",
                       project=project, python_prefix="/storage/local/venv")


def test_absent_secret_target_plan_parity(core, legacy_observer):
    homes = dict(explicit="/owner", ambient="/owner", password="/owner")
    observed = round2_facts(homes, "/vault/credentials")
    observed["/vault/credentials"] = None
    observed_link(observed, "/owner/.ssh", "/vault/credentials")
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=True)
    for project in ("/vault", "/vault/credentials"):
        assert_plan_parity(core, legacy_observer, homes, observed, allowed=False, project=project)


def test_absent_mount_tail_plan_parity(core, legacy_observer):
    homes = dict(explicit="/owner", ambient="/owner", password="/owner")
    observed = round2_facts(homes, "/build/new/project")
    observed["/build/new"] = observed["/build/new/project"] = None
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=True, project="/build/new/project")


@pytest.mark.parametrize("role", ["ambient", "password"])
def test_required_owner_root_observation_refuses_then_retries(core, role):
    homes = dict(explicit="/alt-home", ambient="/ambient-home", password="/home/alice")
    observed = round2_facts(homes)
    denied = observed.pop(homes[role])
    for _ in range(2):
        with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
            round2_plan(core, homes, observed)
    observed[homes[role]] = denied
    assert round2_plan(core, homes, observed)


@pytest.mark.parametrize("invalid", [None, {}, {"explicit": "/owner", "ambient": "/owner"},
    {"explicit": "/owner", "ambient": "/owner", "password": None},
    {"explicit": "/other", "ambient": "/owner", "password": "/owner"},
    {"explicit": "/owner", "ambient": "/owner", "password": "/owner", "unknown": "/extra"}],
    ids=["omitted", "empty", "missing-password", "unknown-password", "explicit-mismatch", "unknown-role"])
def test_complete_home_provenance_required(core, invalid):
    with pytest.raises(core.IsolationRefusal, match="^owner_homes$"):
        plan(core, owner_homes=invalid)


def round2_expected(verifier, homes, observed, mounts):
    return verifier.expected_plan(dict(ISOLATION, engine="docker", allow_unqualified=True), run="/work/run",
        mounts=mounts, image_inspect=[{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}],
        host_table=TABLE, home=homes["explicit"], owner_homes=homes, owner_uid=1000, observed=observed,
        cpu_count=4, platform="linux", uid=1000, gid=1000)


@pytest.mark.parametrize("role", ["explicit", "ambient", "password"])
@pytest.mark.parametrize("surface", ["expected", "verify"])
def test_complete_roots_guard_both_comparison_surfaces(core, verifier, role, surface):
    homes = dict(explicit="/alt-home", ambient="/ambient-home", password="/home/alice")
    observed = round2_facts(homes)
    wanted = round2_expected(verifier, homes, observed, round2_plan(core, homes, observed))
    wanted["mounts"][0] = dict(source=homes[role], destination=homes[role], rw=False)
    if surface == "expected":
        with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
            round2_expected(verifier, homes, observed, wanted["mounts"])
    else:
        assert verifier.verify({}, wanted, host_table=TABLE, home=homes["explicit"], owner_homes=homes,
                               observed=observed, owner_uid=1000) == ["mounts"]


@pytest.mark.parametrize("scenario", ["local", "dangling-secret", "missing-tail"])
def test_comparison_surfaces_keep_plan_parity(core, verifier, legacy_observer, scenario):
    homes = dict(explicit="/alt-home", ambient="/ambient-home", password="/home/alice")
    changes = {}
    observed = round2_facts(homes, "/storage/local/share/project", "/storage/local/venv", "/vault/credentials",
                            "/build/new/project")
    if scenario == "local":
        observed_link(observed, homes["password"] + "/.local", "/storage/local")
        changes = dict(project="/storage/local/share/project", python_prefix="/storage/local/venv")
    elif scenario == "dangling-secret":
        observed_link(observed, homes["ambient"] + "/.ssh", "/vault/credentials")
        observed["/vault/credentials"] = None
    else:
        observed["/build/new"] = observed["/build/new/project"] = None
        changes = dict(project="/build/new/project")
    legacy = legacy_observer(homes, observed)
    mounts = round2_plan(core, homes, observed, **changes)
    wanted = round2_expected(verifier, homes, observed, mounts)
    legacy_wanted = legacy.expected_plan(dict(ISOLATION, engine="docker", allow_unqualified=True),
        run="/work/run", mounts=mounts,
        image_inspect=[{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}], uid=1000, gid=1000)
    assert wanted == legacy_wanted
    actual = inspected(core, verifier, wanted)
    assert verifier.verify(actual, wanted, host_table=TABLE, home=homes["explicit"], owner_homes=homes,
                           observed=observed, owner_uid=1000) == legacy.verify(actual, legacy_wanted) == []


@pytest.mark.parametrize("failure,reason", [("unknown", "mount_metadata"), ("unreadable", "mount_metadata"),
    ("changed", "mount_changed"), ("contradiction", "mount_metadata")])
def test_absence_never_hides_unknown_or_changed_facts(core, failure, reason):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/vault/credentials")
    present = copy.deepcopy(observed["/vault/credentials"])
    observed_link(observed, "/owner/.ssh", "/vault/credentials")
    observed["/vault/credentials"] = None
    if failure == "unknown":
        del observed["/vault/credentials"]
    elif failure == "unreadable":
        observed["/vault/credentials"] = {"unreadable": True}
    elif failure == "changed":
        present["after"] = None
        observed["/vault/credentials"] = present
    else:
        observed["/vault"] = None
        observed["/vault/credentials"] = present
    for _ in range(2):
        with pytest.raises(core.IsolationRefusal, match="^" + reason + "$"):
            round2_plan(core, homes, observed)
    assert round2_plan(core, homes, round2_facts(homes))


def test_missing_tail_alias_still_overlaps_secret(core, legacy_observer):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/vault/credentials", "/mirror/credentials")
    observed["/vault/credentials"] = observed["/mirror/credentials"] = None
    observed["/mirror"]["inode"] = observed["/vault"]["inode"]
    observed["/mirror"]["after"]["inode"] = observed["/vault"]["inode"]
    observed_link(observed, "/owner/.ssh", "/vault/credentials")
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=False, project="/mirror/credentials")


def test_absent_child_in_sticky_foreign_writable_parent_refused(core, legacy_observer):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/build/new/project")
    observed["/build/new"] = observed["/build/new/project"] = None
    observed["/build"]["mode"] = observed["/build"]["after"]["mode"] = stat.S_IFDIR | stat.S_ISVTX | 0o777
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=False, project="/build/new/project")


def test_concurrent_owner_local_and_absence_snapshots_are_independent(core):
    homes = dict(explicit="/alt-home", ambient="/ambient-home", password="/home/alice")
    valid = round2_facts(homes, "/storage/local/project", "/build/new/project")
    observed_link(valid, homes["password"] + "/.local", "/storage/local")
    valid["/build/new"] = valid["/build/new/project"] = None
    changed = copy.deepcopy(valid)
    changed[homes["ambient"]]["after"]["inode"] += 1
    unknown = copy.deepcopy(valid)
    del unknown[homes["password"] + "/.local"]
    def attempt(observed):
        try:
            return round2_plan(core, homes, observed, project="/storage/local/project", live_checkouts=["/build/new/project"])
        except core.IsolationRefusal as error:
            return error.reason
    expected_rows = attempt(valid)
    assert type(expected_rows) is list
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(attempt, [changed, valid, unknown, valid], timeout=10))
    assert results == ["mount_changed", expected_rows, "mount_metadata", expected_rows]


@pytest.mark.parametrize("alias", [False, True], ids=["distinct", "same-inode"])
def test_case_variant_owner_paths_follow_observed_identity(core, legacy_observer, alias):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/OWNER")
    if alias:
        observed["/OWNER"]["inode"] = observed["/OWNER"]["after"]["inode"] = observed["/owner"]["inode"]
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=not alias, project="/OWNER")


def test_confirmed_absent_parent_establishes_missing_child(core, legacy_observer):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/build/new/project")
    observed["/build/new"] = core.ABSENCE
    del observed["/build/new/project"]
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=True, project="/build/new/project")


@pytest.mark.parametrize("surface", ["verify", "image"])
@pytest.mark.parametrize("extra", [1, 1 << 300, "\ud800"], ids=["ordinary", "large-int", "surrogate"])
def test_inspect_transport_is_decoded_once(core, verifier, monkeypatch, surface, extra):
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    value = inspected(core, verifier, wanted) if surface == "verify" else {
        "Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}
    value["extra"] = extra
    transport = json.dumps(json.dumps([value]))
    decode, calls = verifier.load_document, []
    def decode_once(raw):
        calls.append(None)
        return decode(raw)
    monkeypatch.setattr("aegis_core.team_isolation_verify.load_document", decode_once)
    for _ in range(2):
        if surface == "verify":
            assert verifier.verify(transport, wanted, **verification_context()) == ["inspect"]
        else:
            with pytest.raises(core.IsolationRefusal, match="^image_inspect$"):
                verifier.expected_plan(ISOLATION, run="/work/run", mounts=wanted["mounts"], image_inspect=transport,
                    cpu_count=4, platform="linux", uid=1000, gid=1000, **verification_context())
    assert calls == [None, None]


@pytest.mark.parametrize("extra,reason", [(1 << 300, "document_size"), ("\ud800", "document_invalid")],
                         ids=["large-int", "surrogate"])
@pytest.mark.parametrize("surface", ["verify", "image"])
def test_single_decode_still_bounds_unknown_inspect_metadata(core, verifier, surface, extra, reason):
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    value = inspected(core, verifier, wanted) if surface == "verify" else {
        "Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}
    value["extra"] = extra
    with pytest.raises(core.IsolationRefusal, match="^" + reason + "$"):
        if surface == "verify":
            verifier.verify(json.dumps([value]), wanted, **verification_context())
        else:
            verifier.expected_plan(ISOLATION, run="/work/run", mounts=wanted["mounts"], image_inspect=json.dumps([value]),
                cpu_count=4, platform="linux", uid=1000, gid=1000, **verification_context())


@pytest.mark.parametrize("mounts", [None, [], [{"source": "/owner", "destination": "/owner", "rw": False}],
                                  [{"source": "/source", "destination": "/source", "rw": "invalid"}]],
                         ids=["null", "empty-valid", "protected-home", "invalid-access"])
def test_expected_mount_errors_aggregate_with_other_field_errors(core, verifier, mounts):
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    wanted.update(mounts=mounts, read_only=False, memory=0)
    errors = ["read_only", "memory"] if mounts == [] else ["mounts", "read_only", "memory"]
    for _ in range(2):
        assert verifier.verify({}, wanted, **verification_context()) == errors


def test_absent_mount_field_does_not_skip_required_home_provenance(core, verifier):
    wanted = expected(core, verifier)
    del wanted["mounts"]
    context = verification_context()
    del context["owner_homes"]["password"]
    with pytest.raises(core.IsolationRefusal, match="^owner_homes$"):
        verifier.verify({}, wanted, **context)


def test_concurrent_transport_and_aggregation_failures_are_independent(core, verifier):
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    actual = inspected(core, verifier, wanted)
    invalid = copy.deepcopy(wanted)
    invalid.update(mounts=None, read_only=False)
    nested = json.dumps(json.dumps([actual]))
    def attempt(which):
        try:
            return verifier.verify(nested if which == "transport" else actual,
                                   invalid if which == "mounts" else wanted, **verification_context())
        except core.IsolationRefusal as error:
            return error.reason
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(attempt, ["transport", "mounts", "valid"] * 2, timeout=10))
    assert results == [["inspect"], ["mounts", "read_only"], []] * 2


@pytest.mark.parametrize("role", ["explicit", "ambient", "password"])
def test_absent_local_root_remains_reserved(core, legacy_observer, role):
    homes = dict(explicit="/alt-home", ambient="/ambient-home", password="/home/alice")
    observed = round2_facts(homes)
    assert observed[homes[role] + "/.local"] is None
    assert_plan_parity(core, legacy_observer, homes, observed, allowed=False, project=homes[role] + "/.local")


def test_nested_inspect_transport_keeps_legacy_refusal_label(core, verifier, legacy_observer):
    context = verification_context()
    legacy = legacy_observer(context["owner_homes"], context["observed"])
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    actual = inspected(core, verifier, wanted)
    actual["extra"] = [1 << 300, "\ud800"]
    transport = json.dumps(json.dumps([actual]))
    assert legacy.verify(transport, wanted) == ["inspect"]
    assert verifier.verify(transport, wanted, **context) == ["inspect"]


def round3_surface(core, verifier, surface, homes, observed, *, mounts=None, **changes):
    if surface == "plan":
        return round2_plan(core, homes, observed, **changes)
    if mounts is None:
        paths = dict(run="/work/run", project="/work/project", source="/source", python_prefix="/venv")
        paths.update(changes)
        mounts = [dict(source=path, destination=path, rw=key in ("run", "project"))
                  for key, path in paths.items()]
    context = dict(home=homes["explicit"], owner_homes=homes, observed=observed, owner_uid=1000)
    if surface == "validate":
        return core.validate_mounts(mounts, **context)
    if surface == "expected":
        return round2_expected(verifier, homes, observed, mounts)
    wanted = expected(core, verifier, engine="docker", allow_unqualified=True)
    wanted["mounts"] = mounts
    return verifier.verify(inspected(core, verifier, wanted), wanted, host_table=TABLE, **context)


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
@pytest.mark.parametrize("target,resolved", [
    ("dotfiles/ssh", "/owner/dotfiles/ssh"), ("../vault/ssh", "/vault/ssh"),
    ("./dotfiles//ssh", "/owner/dotfiles/ssh"), ("/vault//ssh", "/vault/ssh"),
    ("dotfiles/config,old:ssh", "/owner/dotfiles/config,old:ssh"),
    ("dotfiles/mid/../ssh", "/relocated/ssh"),
    ("missing/../dotfiles/ssh", "/owner/dotfiles/ssh"),
], ids=["relative", "parent", "dots-and-slashes", "absolute-slashes", "punctuation", "intermediate-link", "missing-parent"])
def test_link_targets_resolve_left_to_right(core, verifier, surface, target, resolved):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, resolved, "/owner/dotfiles", "/relocated/branch")
    observed_link(observed, "/owner/.ssh", target)
    if "mid" in target:
        observed_link(observed, "/owner/dotfiles/mid", "/relocated/branch")
    if target.startswith("missing/"):
        observed["/owner/missing"] = None
    result = round3_surface(core, verifier, surface, homes, observed)
    assert result == [] if surface == "verify" else bool(result)
    assert str(core.resolved_path(PurePosixPath("/owner/.ssh"), observed)) == resolved
    # Punctuation is legal in a link target, but not in a supplied mount path.
    if "," not in resolved:
        if surface == "verify":
            assert round3_surface(core, verifier, surface, homes, observed, project=resolved) == ["mounts"]
        else:
            with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
                round3_surface(core, verifier, surface, homes, observed, project=resolved)


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
def test_relative_home_ancestor_link_keeps_unrelated_mounts(core, verifier, surface):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/home/alice")
    observed = round2_facts(homes, "/var/home/alice")
    canonical = round2_facts(dict.fromkeys(homes, "/var/home/alice"))
    observed.update(canonical)
    observed_link(observed, "/home", "var/home")
    assert str(core.resolved_path(PurePosixPath("/home/alice"), observed)) == "/var/home/alice"
    result = round3_surface(core, verifier, surface, homes, observed)
    assert result == [] if surface == "verify" else bool(result)


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
@pytest.mark.parametrize("length", [40, 41])
def test_link_follow_budget_is_per_resolution(core, verifier, surface, length):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/vault/ssh", "/links")
    links = ["/owner/.ssh"] + ["/links/link%d" % index for index in range(length - 1)]
    for link, target in zip(links, links[1:] + ["/vault/ssh"]):
        observed_link(observed, link, target)
    if length == 41:
        with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
            round3_surface(core, verifier, surface, homes, observed)
    else:
        result = round3_surface(core, verifier, surface, homes, observed)
        assert result == [] if surface == "verify" else bool(result)


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
@pytest.mark.parametrize("target", ["", None, "a" * 4097, "/" * 129, "dot\\ssh", "dot\nssh", "dot\x7fssh"],
                         ids=["empty", "non-string", "long", "slashes", "backslash", "control", "delete"])
def test_malformed_link_target_refuses_without_echo(core, verifier, surface, target):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes)
    observed_link(observed, "/owner/.ssh", target)
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$") as error:
        round3_surface(core, verifier, surface, homes, observed)
    assert error.value.reason == "unsafe_mount"
    assert error.value.exit_code == 1


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
def test_unrelated_bad_link_does_not_poison_resolution(core, verifier, surface):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes)
    observed_link(observed, "/unused", "bad\ntarget")
    result = round3_surface(core, verifier, surface, homes, observed)
    assert result == [] if surface == "verify" else bool(result)
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        core.resolved_path(PurePosixPath("/unused"), observed)


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
@pytest.mark.parametrize("suffix", ["/.", "/..", "//ssh", "/ssh"],
                         ids=["dot", "parent", "empty", "child"])
def test_link_target_requires_directory_before_traversal(core, verifier, surface, suffix):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/owner/file")
    observed["/owner/file"]["mode"] = observed["/owner/file"]["after"]["mode"] = stat.S_IFREG | 0o600
    observed_link(observed, "/owner/.ssh", "file" + suffix)
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        round3_surface(core, verifier, surface, homes, observed)


@pytest.mark.parametrize("value,reason", [("\ud800", "document_invalid"), (1 << 300, "document_size")],
                         ids=["surrogate", "large-int"])
def test_load_document_enforces_decoded_bounds(core, value, reason):
    with pytest.raises(core.IsolationRefusal, match="^" + reason + "$") as error:
        core.load_document(json.dumps({"x": value}).encode("ascii"))
    assert error.value.reason == reason
    assert error.value.exit_code == 1


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
def test_surrogate_link_target_is_a_document_refusal(core, verifier, surface):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes)
    observed_link(observed, "/owner/.ssh", "\ud800")
    with pytest.raises(core.IsolationRefusal, match="^document_invalid$"):
        round3_surface(core, verifier, surface, homes, observed)
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        core.resolved_path(PurePosixPath("/owner/.ssh"), observed)


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
def test_repeated_acyclic_link_follows_still_spend_budget(core, verifier, surface):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/vault/ssh", "/links")
    observed_link(observed, "/links/back", "/")
    observed_link(observed, "/owner/.ssh", "/" + "links/back/" * 40 + "vault/ssh")
    with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
        round3_surface(core, verifier, surface, homes, observed)


@pytest.mark.parametrize("surface", ["plan", "validate", "expected", "verify"])
def test_deep_mount_alias_lookups_are_linear_per_pair(core, verifier, monkeypatch, surface):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    base = "/" + "/".join(["d"] * 127)
    paths = [base + "/m%d" % index for index in range(128)]
    observed = round2_facts(homes, *paths)
    mounts = [dict(source=path, destination=path, rw=index < 2) for index, path in enumerate(paths)]
    native, counts = core.inside_alias, []

    def counted(child, parent, identities):
        count = [0]
        budget = 2 * (len(child.parts) + len(parent.parts))

        def lookup(key):
            count[0] += 1
            assert count[0] <= budget, "ancestor identity lookups exceeded the linear budget"
            return identities.get(key)

        result = native(child, parent, SimpleNamespace(get=lookup))
        counts.append(count[0])
        return result

    monkeypatch.setattr("aegis_core.team_isolation_mounts.inside_alias", counted)
    result = round3_surface(core, verifier, surface, homes, observed, mounts=mounts,
        run=paths[0], project=paths[1], source=paths[2], python_prefix=paths[3], live_checkouts=paths[4:])
    assert result == [] if surface == "verify" else bool(result)
    assert counts and sum(counts) <= len(counts) * 4 * 129


@pytest.mark.parametrize("changes", [{"project": "/source"}, {"source": "/work/project"},
                                    {"live_checkouts": ["/work/project"]}],
                         ids=["project-is-source", "source-is-project", "live-is-project"])
def test_exact_cross_access_mounts_refuse_as_overlap(core, changes):
    with pytest.raises(core.IsolationRefusal, match="^mount_overlap$"):
        plan(core, **changes)


def test_direct_duplicate_same_access_rows_keep_their_refusal(core):
    row = dict(source="/source", destination="/source", rw=False)
    with pytest.raises(core.IsolationRefusal, match="^mount_rows$"):
        core.mount_rows([row, dict(row)])


def test_verify_uses_new_registry_owner_folder_for_expected_mounts(core, verifier):
    context = verification_context()
    registry = {**TABLE, "fixture": {"home": {"variable": "FIXTURE_STATE", "run_folder": "fixture-state",
                                             "owner_folder": ".fixturestate"}}}
    credential = "/owner/.fixturestate"
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner", credential)
    context.update(host_table=registry, observed=observed)
    image = [{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}]
    options = dict(run="/work/run", image_inspect=image, cpu_count=4, platform="linux", uid=1000, gid=1000)
    wanted = verifier.expected_plan(ISOLATION, mounts=plan(core), **options, **context)
    forbidden = [dict(source=credential, destination=credential, rw=False)]
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        verifier.expected_plan(ISOLATION, mounts=forbidden, **options, **context)
    assert verifier.verify({}, dict(wanted, mounts=forbidden), **context) == ["mounts"]


@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
@pytest.mark.parametrize("root", [
    ".aws", ".claude", ".claude.json", ".codeium", ".codex", ".config", ".copilot", ".cursor",
    ".docker", ".gemini", ".git-credentials", ".gnupg", ".kiro", ".kube", ".local", ".netrc", ".ssh",
])
def test_baseline_credential_roots_apply_without_registry_owner_folders(core, verifier, root, rw):
    # TABLE intentionally omits owner_folder. The host catalogue supplies only the test oracle.
    path = "/owner/" + root
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner", path)
    if root in (".claude.json", ".git-credentials", ".netrc"):
        observed[path]["mode"] = observed[path]["after"]["mode"] = stat.S_IFREG | 0o600
    context = dict(home="/owner", owner_homes=verification_context()["owner_homes"],
                   observed=observed, owner_uid=1000)
    protected_names = core.host_policy(TABLE).protected_names
    rows = [dict(source=path, destination=path, rw=rw)]
    changes = {"project" if rw else "source": path}
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        plan(core, protected_names=protected_names, **context, **changes)
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        team_isolation.create_argv(ISOLATION, run="/work/run", mounts=rows, host_table=TABLE,
                                   cpu_count=4, platform="linux", uid=1000, gid=1000, **context)
    image = [{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}]
    options = dict(run="/work/run", image_inspect=image, cpu_count=4, platform="linux", uid=1000, gid=1000)
    with pytest.raises(core.IsolationRefusal, match="^unsafe_mount$"):
        verifier.expected_plan(ISOLATION, mounts=rows, host_table=TABLE, **options, **context)
    wanted = verifier.expected_plan(ISOLATION, mounts=plan(core), host_table=TABLE, **options, **context)
    actual = inspected(core, verifier, wanted)
    assert verifier.verify(actual, dict(wanted, mounts=rows), host_table=TABLE, **context) == ["mounts"]
    assert verifier.verify(actual, wanted, host_table=TABLE, **context) == []


@pytest.mark.parametrize("mode", ["missing-root", "missing-observation", "invalid-name"])
def test_incomplete_credential_metadata_refuses_mount_planning(core, mode):
    names = core.secret_names()
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner")
    if mode == "missing-root":
        names = names - {".ssh"}
    elif mode == "missing-observation":
        del observed["/owner/.kiro"]
    else:
        names = names | {"../invalid"}
    with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
        plan(core, protected_names=names, observed=observed)
    assert plan(core)


def _count_qualification(core, monkeypatch):
    """Count uncached metadata reads, protected-root builds and resolutions."""
    calls = {"metadata": 0, "roots": 0}
    resolved = []
    read = core._read_metadata

    def count_read(*args, **kwargs):
        calls["metadata"] += 1
        return read(*args, **kwargs)

    monkeypatch.setattr("aegis_core.team_isolation_mounts._read_metadata", count_read)
    roots = core._protected_roots

    def count_roots(*args, **kwargs):
        calls["roots"] += 1
        return roots(*args, **kwargs)

    monkeypatch.setattr("aegis_core.team_isolation_mounts._protected_roots", count_roots)
    resolve = core._resolved_path

    def count_resolve(path, *args, **kwargs):
        resolved.append(str(path))
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr("aegis_core.team_isolation_mounts._resolved_path", count_resolve)
    return calls, resolved


def test_verify_reuses_qualified_metadata_and_protected_roots(core, verifier, monkeypatch):
    # Build the fixture before installing counters so only one verify is measured.
    wanted = expected(core, verifier)
    actual = inspected(core, verifier, wanted)
    calls, resolved = _count_qualification(core, monkeypatch)
    assert verifier.verify(actual, wanted, **verification_context()) == []
    # One operation qualifies each distinct metadata key once and walks roots once.
    assert calls["metadata"] == 25
    assert calls["roots"] == 1
    assert resolved.count("/owner") == 1


def test_equal_owner_homes_deduped_after_role_validation(core, verifier, monkeypatch):
    wanted = expected(core, verifier)
    calls, resolved = _count_qualification(core, monkeypatch)
    incomplete = verification_context()
    incomplete["owner_homes"] = {"explicit": "/owner", "ambient": "/owner", "password": ""}
    with pytest.raises(core.IsolationRefusal, match="^owner_homes$") as error:
        verifier.verify({}, wanted, **incomplete)
    assert error.value.reason == "owner_homes"
    assert resolved == []
    assert calls["roots"] == 0
    homes = {"explicit": "/owner", "ambient": "/alt", "password": "/owner"}
    context = dict(host_table=TABLE, home="/owner", owner_uid=1000, owner_homes=homes,
                   observed=round2_facts(homes))
    result = verifier.verify({}, wanted, **context)
    assert result[0] == "label"
    assert "mounts" in result
    assert resolved == ["/owner", "/alt"]
    assert calls["roots"] == 1
    # Public role validation still reports every role; dedupe happens after that.
    assert core.validated_owner_homes("/owner", dict.fromkeys(
        ("explicit", "ambient", "password"), "/owner")) == (PurePosixPath("/owner"),) * 3


def test_absent_mounts_still_qualify_changed_observations(core, verifier):
    wanted = expected(core, verifier)
    del wanted["mounts"]
    context = verification_context()
    context["observed"]["/owner"]["after"]["inode"] += 1
    with pytest.raises(core.IsolationRefusal, match="^mount_changed$") as error:
        verifier.verify({}, wanted, **context)
    assert error.value.reason == "mount_changed"
    context["observed"]["/owner"]["after"]["inode"] -= 1
    # A missing mounts field is an expected-record error once the context qualifies.
    assert verifier.verify({}, wanted, **context) == ["mounts"]


def test_mount_row_refusal_precedes_root_qualification(core):
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner")
    del observed["/owner/.ssh"]
    duplicate = dict(source="/work/run", destination="/work/run", rw=True)
    with pytest.raises(core.IsolationRefusal, match="^mount_rows$") as error:
        core.validate_mounts([duplicate, dict(duplicate)], home="/owner", observed=observed,
                             owner_uid=1000,
                             owner_homes=dict.fromkeys(("explicit", "ambient", "password"), "/owner"))
    assert error.value.reason == "mount_rows"
    with pytest.raises(core.IsolationRefusal, match="^mount_metadata$"):
        core.validate_mounts([duplicate], home="/owner", observed=observed, owner_uid=1000,
                             owner_homes=dict.fromkeys(("explicit", "ambient", "password"), "/owner"))


def _secret_chain(observed, start, prefix, length, final):
    links = [start] + ["/links/%s%d" % (prefix, index) for index in range(length - 1)]
    for link, target in zip(links, links[1:] + [final]):
        observed_link(observed, link, target)


def test_reused_context_keeps_per_resolution_link_budgets(core, verifier):
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = round2_facts(homes, "/vault/ssh", "/vault/gpg", "/links")
    _secret_chain(observed, "/owner/.ssh", "s", 40, "/vault/ssh")
    _secret_chain(observed, "/owner/.gnupg", "g", 40, "/vault/gpg")
    # Two 40-follow resolutions in one operation must not share a budget.
    assert round3_surface(core, verifier, "verify", homes, observed) == []
    longer = round2_facts(homes, "/vault/ssh", "/links")
    _secret_chain(longer, "/owner/.ssh", "t", 41, "/vault/ssh")
    with pytest.raises(core.IsolationRefusal, match="^mount_metadata$") as error:
        round3_surface(core, verifier, "verify", homes, longer)
    assert error.value.reason == "mount_metadata"
    assert round3_surface(core, verifier, "verify", homes, observed) == []


def test_qualified_context_does_not_persist_across_operations(core, verifier):
    wanted = expected(core, verifier)
    actual = inspected(core, verifier, wanted)
    context = verification_context()
    assert verifier.verify(actual, wanted, **context) == []
    context["observed"]["/source"]["after"]["inode"] += 1
    with pytest.raises(core.IsolationRefusal, match="^mount_changed$") as error:
        verifier.verify(actual, wanted, **context)
    assert error.value.reason == "mount_changed"
    context["observed"]["/source"]["after"]["inode"] -= 1
    assert verifier.verify(actual, wanted, **context) == []

    def attempt(token):
        snapshot = verification_context()
        if token == "bad":
            snapshot["observed"]["/owner"]["after"]["inode"] += 1
            try:
                verifier.verify(actual, wanted, **snapshot)
            except core.IsolationRefusal as refusal:
                return refusal.reason
        return verifier.verify(actual, wanted, **snapshot)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(attempt, ["ok", "bad", "ok", "bad"], timeout=10))
    assert results == [[], "mount_changed", [], "mount_changed"]


def _boundary_fixture(core):
    """Group-writable /work plus a credential symlink whose target is mountable."""
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    observed = facts("/work/run", "/work/project", "/source", "/venv", "/owner", "/vault")
    observed["/work"]["gid"] = observed["/work"]["after"]["gid"] = 2000
    observed["/work"]["mode"] = observed["/work"]["after"]["mode"] = stat.S_IFDIR | 0o770
    observed_link(observed, "/owner/.fixturestate", "/vault")
    rows = [dict(source="/vault", destination="/vault", rw=False),
            dict(source="/work/project", destination="/work/project", rw=True)]
    return homes, observed, rows, core.secret_names()


def _validate(core, observed, homes, rows, **extra):
    kwargs = dict(home="/owner", observed=observed, owner_uid=1000, owner_homes=homes,
                  private_gids=(2000,))
    kwargs.update(extra)
    return core.validate_mounts(rows, **kwargs)


def _refusal(core, observed, homes, rows, **extra):
    try:
        _validate(core, observed, homes, rows, **extra)
    except core.IsolationRefusal as refusal:
        return refusal.reason
    return "accepted"


def test_exported_mount_entry_points_validate_fresh(core):
    """Exported mount functions neither accept nor return an operation cache."""
    entry_points = (
        core.require, core.bounded_value, core.load_document, core.container_supported, core.engine,
        core.image, core.cpus_limit, core.memory_bytes, core.pids_limit, core.read_isolation,
        core.load_isolation, core.absolute_path, core.inside, core.system_mount, core.mount_rows,
        core.host_policy, core.home_folders, core.container_env, core.metadata, core.foreign_write,
        core.aliases_overlap, core.secret_names, core.credential_names, core.inside_alias,
        core.link_target, core.resolved_path, core.path_identities, core.validated_owner_homes,
        core.protected_roots, core.validate_mounts, core.assess_expected_mounts, core.mount_plan)
    exported_functions = {name for name in core.__all__ if name[:1].islower()}
    assert exported_functions == {fn.__name__ for fn in entry_points}
    for fn in entry_points:
        params = inspect.signature(fn).parameters
        assert "qualified" not in params, fn.__name__
        assert "context" not in params, fn.__name__
    try:
        core.mount_operation_context
    except AttributeError:
        pass
    else:
        raise AssertionError("mount_operation_context is still callable")
    homes, observed, rows, _names = _boundary_fixture(core)
    with pytest.raises(TypeError):
        core.validate_mounts(rows, context=object(), home="/owner", observed=observed,
                             owner_uid=1000, owner_homes=homes)
    with pytest.raises(TypeError):
        core.metadata(PurePosixPath("/owner"), observed, qualified=object())
    with pytest.raises(TypeError):
        core.resolved_path(PurePosixPath("/owner"), observed, qualified=object())
    with pytest.raises(TypeError):
        core.path_identities(PurePosixPath("/owner"), observed, {}, qualified=object())
    with pytest.raises(TypeError):
        core.protected_roots((PurePosixPath("/owner"),), observed, {}, qualified=object())
    accepted = _validate(core, observed, homes, rows)
    assert type(accepted) is list and all(type(row) is dict for row in accepted)
    checked, structural = core.assess_expected_mounts(
        rows, home="/owner", observed=observed, owner_uid=1000, owner_homes=homes, private_gids=(2000,))
    assert structural is None and [row["source"] for row in checked] == ["/vault", "/work/project"]
    duplicate = dict(source="/vault", destination="/vault", rw=False)
    missing, code = core.assess_expected_mounts(
        [duplicate, dict(duplicate)], home="/owner", observed=observed, owner_uid=1000, owner_homes=homes,
        private_gids=(2000,))
    assert missing is None and code == "mount_rows"
    observed["/vault"]["after"]["inode"] += 1
    with pytest.raises(core.IsolationRefusal, match="^mount_changed$") as error:
        core.assess_expected_mounts(rows, home="/owner", observed=observed, owner_uid=1000,
                                    owner_homes=homes, private_gids=(2000,))
    assert error.value.reason == "mount_changed"
    observed["/vault"]["after"]["inode"] -= 1


def test_public_mount_boundary_rechecks_refreshed_facts_and_policy(core):
    """A later public call enforces the facts and policy arguments of that call."""
    homes, observed, rows, names = _boundary_fixture(core)
    assert [row["source"] for row in _validate(core, observed, homes, rows)] == ["/vault", "/work/project"]
    observed["/vault"]["after"]["inode"] += 1
    fresh = copy.deepcopy(observed)
    assert _refusal(core, observed, homes, rows) == _refusal(
        core, fresh, homes, rows) == "mount_changed"
    observed["/vault"]["after"]["inode"] -= 1
    assert _validate(core, observed, homes, rows)
    with pytest.raises(core.IsolationRefusal, match="^mount_changed$"):
        core.metadata(PurePosixPath("/vault"), fresh)
    fresh["/vault"]["after"]["inode"] -= 1
    assert core.metadata(PurePosixPath("/vault"), fresh)["inode"] == fresh["/vault"]["inode"]
    assert core.resolved_path(PurePosixPath("/vault"), fresh) == PurePosixPath("/vault")
    assert _refusal(core, observed, homes, rows, owner_uid=1000.0) == "mount_metadata"
    assert _refusal(core, observed, homes, rows, private_gids=(2000.0,)) == "mount_metadata"
    assert _refusal(core, observed, homes, rows, private_gids=()) == "unsafe_mount"
    assert _refusal(core, observed, homes, rows, home="/alt") == "owner_homes"
    assert _refusal(core, observed, homes, rows,
                    owner_homes=dict(homes, ambient="/alt")) == "mount_metadata"
    assert _refusal(core, observed, homes, rows,
                    protected_names=names | {".fixturestate"}) == "unsafe_mount"
    owners = core.validated_owner_homes("/owner", homes)
    roots = core.protected_roots(owners, observed, {}, protected_names=names | {".fixturestate"})
    assert ("/vault", "secret") in [(str(path), kind) for path, kind in roots]
    assert _validate(core, observed, homes, rows, protected_names=names)

    def attempt(token):
        snap = copy.deepcopy(observed)
        extra = {}
        if token == "changed":
            snap["/vault"]["after"]["inode"] += 1
        elif token == "float":
            extra["owner_uid"] = 1000.0
        elif token == "gids":
            extra["private_gids"] = ()
        elif token == "names":
            extra["protected_names"] = names | {".fixturestate"}
        elif token == "home":
            extra["home"] = "/alt"
        return _refusal(core, snap, homes, rows, **extra) if token != "ok" else (
            "ok" if _validate(core, snap, homes, rows) else "rejected")

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(attempt, ["ok", "changed", "float", "gids", "names", "home", "ok"],
                                 timeout=10))
    assert results == ["ok", "mount_changed", "mount_metadata", "unsafe_mount", "unsafe_mount",
                       "owner_homes", "ok"]


@pytest.mark.parametrize("config_path", ["~/.", "~/./.", "~/foo/..", "~/"])
def test_catalogue_entry_that_is_the_home_directory_is_a_catalogue_defect(config_path):
    """Observation setup fails a home-relative entry that normalizes to HOME."""
    host = _non_teams_host((config_path,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    message = "catalogue-defect: config path normalizes to the home directory"
    with pytest.raises(AssertionError) as caught:
        _catalogue_names((host,))
    assert str(caught.value) == message
    with pytest.raises(AssertionError) as observed:
        facts("/owner", catalogue=(host,))
    assert str(observed.value) == message
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    with pytest.raises(AssertionError) as recorded:
        round2_facts(homes, catalogue=(host,))
    assert str(recorded.value) == message


@pytest.mark.parametrize("config_path", ["~/..", "~/../.next-host", "~/foo/../.."])
def test_catalogue_entry_outside_home_is_a_catalogue_defect(config_path):
    """Observation setup fails a home-relative entry that normalizes outside HOME."""
    host = _non_teams_host((config_path,))
    message = "catalogue-defect: config path normalizes outside the home directory"
    with pytest.raises(AssertionError) as caught:
        _catalogue_names((host,))
    assert str(caught.value) == message
    with pytest.raises(AssertionError) as observed:
        facts("/owner", catalogue=(host,))
    assert str(observed.value) == message
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    with pytest.raises(AssertionError) as recorded:
        round2_facts(homes, catalogue=(host,))
    assert str(recorded.value) == message


_DOTTED_NEXT = ("~/./.next-host", "~/a/../.next-host", "~//.next-host", "~///.next-host")


@pytest.mark.parametrize("spelling", _DOTTED_NEXT,
                         ids=["dot-slash", "parent-dotdot", "double-slash", "triple-slash"])
def test_dotted_catalogue_spelling_is_observed_as_the_normalized_root(spelling):
    """~/./.next-host is observed as .next-host, then again on a fresh call."""
    host = _non_teams_host((spelling,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    assert _catalogue_names((host,)) == {".next-host"}
    observed = facts("/owner", catalogue=(host,))
    assert "/owner/.next-host" in observed
    assert observed["/owner/.next-host"] is None
    assert "/owner/.NEXT-HOST" not in observed
    assert "/owner/." not in observed
    again = facts("/owner", catalogue=(host,))
    assert again["/owner/.next-host"] is None
    assert "/owner/." not in again
    homes = dict.fromkeys(("explicit", "ambient", "password"), "/owner")
    recorded = round2_facts(homes, catalogue=(host,))
    assert recorded["/owner/.next-host"] is None
    assert "/owner/.NEXT-HOST" not in recorded
    assert "/owner/." not in recorded


def test_dotted_catalogue_observations_are_isolated_under_concurrency():
    """Concurrent dotted spellings observe .next-host, and a bad entry still fails."""
    def once(spelling):
        host = _non_teams_host((spelling,))
        try:
            observed = facts("/owner", catalogue=(host,))
            names = _catalogue_names((host,))
        except AssertionError as exc:
            return "defect" if str(exc).startswith("catalogue-defect:") else spelling
        if names == {".next-host"} and observed.get("/owner/.next-host") is None and "/owner/." not in observed:
            return "ok"
        return spelling

    spellings = [*_DOTTED_NEXT, "~/.", "~/.."] * 3
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, spellings, timeout=10)) == (["ok"] * 4 + ["defect", "defect"]) * 3


@pytest.mark.parametrize(("present", "absent"), [
    ("/owner/.NEXT-HOST", "/owner/.next-host"),
    ("/owner/.next-host", "/owner/.NEXT-HOST"),
], ids=["exact-present", "folded-present"])
def test_mixed_case_catalogue_observations_preserve_explicit_metadata(present, absent):
    catalogue = (_non_teams_host(("~/a/../.NEXT-HOST",)),)
    homes = {"explicit": "/owner", "ambient": "/ambient/home", "password": "/password-home"}
    plain = facts("/owner", catalogue=catalogue)
    assert plain["/owner/.NEXT-HOST"] is None
    assert plain["/owner/.next-host"] is None

    observed = facts("/owner", present, catalogue=catalogue)
    assert observed[present] == facts("/owner", present, catalogue=())[present]
    assert stat.S_ISDIR(observed[present]["mode"])
    assert observed[absent] is None

    recorded = round2_facts(homes, present, catalogue=catalogue)
    assert recorded[present] == round2_facts(homes, present, catalogue=())[present]
    assert stat.S_ISDIR(recorded[present]["mode"])
    assert all(recorded[path] is None for path in (
        absent, "/ambient/home/.NEXT-HOST", "/ambient/home/.next-host",
        "/password-home/.NEXT-HOST", "/password-home/.next-host",
    ))


def test_exact_catalogue_evidence_qualifies_public_mount_plan(core):
    catalogue = (*hosts.HOSTS, _non_teams_host(("~/a/../.NEXT-HOST",)))
    homes = {"explicit": "/owner", "ambient": "/ambient/home", "password": "/password-home"}
    names = core.secret_names() | {".NEXT-HOST"}
    eligible = "/owner/eligible"
    expected = [
        {"source": "/owner/eligible", "destination": "/owner/eligible", "rw": True},
        {"source": "/source", "destination": "/source", "rw": False},
        {"source": "/venv", "destination": "/venv", "rw": False},
        {"source": "/work/run", "destination": "/work/run", "rw": True},
    ]

    def attempt(_):
        observed = round2_facts(homes, eligible, catalogue=catalogue)
        assert round2_plan(core, homes, observed, project=eligible, protected_names=names) == expected
        incomplete = dict(observed)
        del incomplete["/ambient/home/.NEXT-HOST"]
        assert incomplete["/ambient/home/.next-host"] is None
        with pytest.raises(core.IsolationRefusal, match="^mount_metadata$") as refused:
            round2_plan(core, homes, incomplete, project=eligible, protected_names=names)
        assert refused.value.message == core.REFUSALS["mount_metadata"]
        fresh = round2_facts(homes, eligible, catalogue=catalogue)
        assert round2_plan(core, homes, fresh, project=eligible, protected_names=names) == expected

    attempt(None)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(attempt, range(6), timeout=10))
