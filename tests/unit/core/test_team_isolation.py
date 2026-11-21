"""TA-6c public plan, verification and engine argv parity."""
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import importlib
import json
from pathlib import PurePosixPath
import posixpath
import stat
import sys

import pytest

from aegis_core import hosts, team_host_registry, team_isolation as core
from aegis_core import team_isolation_mounts as mounts


HOME = "/owner"
RUN = "/work/run"
PROJECT = "/work/project"
SOURCE = "/source"
PREFIX = "/venv"
IMAGE = "localhost/aegis-teams@sha256:" + "a" * 64
TABLE = {host: team_host_registry.entry(host) for host in team_host_registry.TEAM_HOSTS}
ISOLATION = dict(mode="container", engine="podman", image=IMAGE, cpus=1, memory="1g", pids=64)


def config():
    return dict(schema="aegis.team-run/v2", isolation=ISOLATION, run=RUN, project=PROJECT,
                source=SOURCE, recipes={"python": PREFIX + "/bin/python"})


def observe(paths, homes, *, marker=None, protected_names=None):
    result = {}
    for path in (*paths, *homes):
        for component in (PurePosixPath(path), *PurePosixPath(path).parents):
            key = str(component)
            if key not in result:
                row = dict(device=1, inode=len(result) + 1, uid=0, gid=0,
                           mode=stat.S_IFDIR | 0o700, acl=None)
                result[key] = dict(row, after=dict(row))
    names = mounts.secret_names() if protected_names is None else protected_names
    for home in homes:
        for name in names | {".local"}:
            result[home + "/" + name] = None
    if marker is not None:
        row = dict(device=1, inode=100, uid=0, gid=0, mode=stat.S_IFREG | 0o600, acl=None)
        result[marker] = dict(row, after=dict(row))
    return result


def _inputs(**options):
    values = dict(observer=observe, owner_homes=lambda: dict.fromkeys(
        ("explicit", "ambient", "password"), HOME), owner_uid=0, owner_gid=0, cpu_count=4,
        platform="linux", host_table=TABLE, source=SOURCE)
    values.update(options)
    return values


def check(value, **options):
    raw = value if type(value) is bytes else json.dumps(value).encode()
    return core.check(raw, **_inputs(**options))


def direct(value, **options):
    return core.check(value, **_inputs(**options))


def refused_as(code):
    return {"status": "refused", "code": code, "reason": mounts.REFUSALS[code],
            "next_action": {"actor": "operator", "command": mounts.REFUSALS[code]}}


def _same_object(value, snapshot):
    assert value == snapshot
    if type(value) is dict:
        assert all(value[key] is snapshot[key] for key in value)


HOST = {"status": "ok", "mode": "host", "isolation": None, "mounts": [], "create_argv": None}


@pytest.fixture
def legacy():
    if not sys.platform.startswith("linux"):
        pytest.skip("legacy container argv requires Linux and native POSIX paths")
    return importlib.import_module("tools.hierarchy_container")


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_create_argv_matches_legacy_golden(engine, legacy):
    isolation = dict(ISOLATION, engine=engine, allow_unqualified=engine == "docker")
    rows = [dict(source=PROJECT, destination=PROJECT, rw=True)]
    expected = legacy.create_argv(isolation, run=RUN, mounts=rows, uid=0, gid=0, env={"LANG": "C"})
    assert core.create_argv(isolation, run=RUN, mounts=rows, uid=0, gid=0, env={"LANG": "C"},
                            host_table=TABLE, cpu_count=4, platform="linux", home=HOME,
                            observed=observe((PROJECT,), (HOME,)), owner_uid=0,
                            owner_homes=dict.fromkeys(("explicit", "ambient", "password"), HOME)) == expected


def test_other_argv_matches_legacy_and_keeps_empty_arguments(legacy):
    command = ["printf", "%s", ""]
    rows = [
        (core.exec_argv("docker", RUN, command, workdir=PROJECT, host_table=TABLE),
         legacy.exec_argv("docker", RUN, command, workdir=PROJECT)),
        (core.inspect_argv("podman", RUN), legacy.inspect_argv("podman", RUN)),
        (core.stop_argv("docker", RUN, timeout=7), legacy.stop_argv("docker", RUN, timeout=7)),
        (core.rm_argv("podman", RUN), legacy.rm_argv("podman", RUN)),
        (core.image_inspect_argv("docker", IMAGE), legacy.image_inspect_argv("docker", IMAGE)),
        (core.build_image_argv("podman", context=SOURCE, containerfile=SOURCE + "/Containerfile", tag="x"),
         legacy.build_image_argv("podman", context=SOURCE, containerfile=SOURCE + "/Containerfile", tag="x")),
    ]
    assert all(actual == expected for actual, expected in rows)
    assert rows[0][0][-1] == ""


@pytest.mark.parametrize(("builder", "args", "kwargs", "code"), [
    (core.inspect_argv, ("-engine", RUN), {}, "isolation_engine"),
    (core.image_inspect_argv, ("docker", "-image"), {}, "isolation_image"),
    (core.build_image_argv, ("podman",), {"context": SOURCE, "containerfile": "/file", "tag": "-tag"}, "image_tag"),
    (core.stop_argv, ("docker", RUN), {"timeout": True}, "stop_timeout"),
    (core.stop_argv, ("docker", RUN), {"timeout": 1 << 256}, "stop_timeout"),
    (core.exec_argv, ("docker", RUN, []), {"workdir": PROJECT, "host_table": TABLE}, "isolation_command"),
    (core.exec_argv, ("docker", RUN, ["-bad"]), {"workdir": PROJECT, "host_table": TABLE}, "isolation_command"),
    (core.exec_argv, ("docker", RUN, ["id", None]), {"workdir": PROJECT, "host_table": TABLE}, "isolation_command"),
])
def test_argv_refusals(builder, args, kwargs, code):
    with pytest.raises(mounts.IsolationRefusal, match="^" + code + "$"):
        builder(*args, **kwargs)


@pytest.mark.parametrize("value", [{}, {"isolation": {"mode": "host"}, "schema": "aegis.team-run/v2"}])
def test_host_plan_does_not_observe_or_lookup_owner(value):
    def unexpected(*args, **kwargs):
        pytest.fail("host plan touched a container dependency")

    assert check(value, observer=unexpected, owner_homes=unexpected,
                 platform="win32") == {"status": "ok", "mode": "host", "isolation": None,
                                       "mounts": [], "create_argv": None}
    assert check(value, inspect=lambda: b"[]", observer=unexpected, owner_homes=unexpected,
                 inspector=unexpected)["code"] == "container_required"


@pytest.mark.parametrize(("value", "code"), [
    ([], "document_invalid"), ({"schema": "bad"}, "team_run_schema"),
    ({"isolation": {}}, "team_run_schema"), ({"unknown": "opaque"}, "team_run_fields"),
    (b'{"schema":1,"schema":2}', "document_invalid"),
    (b"x" * (1024 * 1024 + 1), "document_size"),
    (dict(config(), recipes=None), "team_run_recipes"),
    (dict(config(), recipes={"python": "/venv/python"}), "python_bin"),
    (dict(config(), recipes={"python": "/venv/bin/python", "unknown": "opaque"}), "team_run_fields"),
    (dict(config(), live_checkouts=["/a"] * 125), "mount_rows"),
], ids=["shape", "schema", "required-schema", "unknown", "duplicate", "oversized",
        "recipes", "bin", "recipe-fields", "live-limit"])
def test_plan_refusal_and_retry(value, code):
    refused = check(value)
    assert refused == {"status": "refused", "code": code, "reason": mounts.REFUSALS[code],
                       "next_action": {"actor": "operator", "command": mounts.REFUSALS[code]}}
    assert check(config())["status"] == "ok"


def test_inferred_prefix_and_concurrent_plans():
    value = config()
    expected = check(value)
    assert [row["source"] for row in expected["mounts"]] == [SOURCE, PREFIX, PROJECT, RUN]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: check(value), range(6))) == [expected] * 6

    def absent(paths, homes, *, marker, protected_names):
        facts = observe(paths, homes, marker=None, protected_names=protected_names)
        if marker is not None:
            facts[marker] = None
        return facts

    assert check(value, observer=absent)["code"] == "python_prefix"
    assert check(dict(value, python_prefix=PREFIX), observer=absent)["status"] == "ok"


def test_inspection_refusal_order_and_retry():
    calls = []
    digest = IMAGE.rsplit("@", 1)[1]

    def inspector(argv):
        calls.append(argv)
        return json.dumps([{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE],
                            "Digest": digest, "Config": {"Env": []}}]).encode()

    refused = check(config(), inspect=lambda: b"bad", inspector=inspector)
    assert refused["code"] == "document_invalid" and not calls
    result = check(config(), inspect=lambda: b"[{}]", inspector=inspector)
    assert result["status"] == "mismatch" and result["mismatches"]
    assert calls == [["podman", "image", "inspect", IMAGE]]
    assert check(config(), inspect=lambda: b"[{}]", inspector=lambda _: b"{}")["code"] == "image_inspect"


@pytest.mark.parametrize("rw", [False, True])
@pytest.mark.parametrize("path", [HOME, HOME + "/.ssh", HOME + "/.local", HOME + "/.next-host"])
def test_create_rejects_protected_sources(path, rw):
    table = {**TABLE, "fixture": {"home": {"variable": "FIXTURE_STATE", "run_folder": "fixture-state",
                                          "owner_folder": ".next-host"}}}
    facts = observe((path,), (HOME,), protected_names=mounts.host_policy(table).protected_names)
    if path != HOME:
        credentials = dict(device=1, inode=101, uid=0, gid=0, mode=stat.S_IFDIR | 0o700, acl=None)
        facts[path] = dict(credentials, after=dict(credentials))
    with pytest.raises(mounts.IsolationRefusal, match="^unsafe_mount$"):
        core.create_argv(ISOLATION, run=RUN, mounts=[dict(source=path, destination=path, rw=rw)], host_table=table,
                         cpu_count=4, platform="linux", uid=0, gid=0, home=HOME, observed=facts,
                         owner_uid=0, owner_homes=dict.fromkeys(("explicit", "ambient", "password"), HOME))


@pytest.mark.parametrize("raw", [b"0", b"[]", b"[{},{}]", b'"[{}]"'])
def test_invalid_inspection_envelope_has_no_container_dependencies(raw):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid inspection reached a container dependency")

    assert check(config(), inspect=lambda: raw, observer=unexpected, owner_homes=unexpected,
                 inspector=unexpected) == {"status": "mismatch", "mismatches": ["inspect"]}


def _without_containers(**options):
    def unexpected(*args, **kwargs):
        pytest.fail("inert aliases reached a container dependency")

    options.setdefault("observer", unexpected)
    options.setdefault("owner_homes", unexpected)
    return options


def test_legacy_aliases_are_inert_for_host_and_container_inputs():
    """Bytes and direct dicts share one field policy and never take the caller's object."""
    families = (
        {"codex_home": "/unused"},
        {"claude_home": "/unused"},
        {"codex_home": "/unused", "claude_home": ""},
        {"codex_home": None, "claude_home": False},
        {"codex_home": {"nested": [1, "ok"]}, "claude_home": 0},
        {"codex_home": "h" * 16384, "claude_home": "/unused"},
        {"isolation": {"mode": "host"}, "schema": "aegis.team-run/v2",
         "codex_home": "/unused", "claude_home": "/unused"},
        {"schema": "aegis.team-run/v1", "claude_home": "/unused"},
    )
    for value in families:
        owned = dict(value)
        assert direct(owned, platform="win32", **_without_containers()) == HOST
        _same_object(owned, value)
        assert check(value, platform="win32", **_without_containers()) == HOST
    raw = b'{"codex_home":"/unused","claude_home":"/unused"}'
    assert check(raw, platform="win32", **_without_containers()) == HOST
    assert direct(raw, platform="win32", **_without_containers()) == HOST

    bare = dict(config(), isolation=dict(ISOLATION), recipes={"python": PREFIX + "/bin/python"})
    expected = check(bare)
    for extra in ({}, {"codex_home": "/unused"}, {"claude_home": "/unused"},
                  {"codex_home": "/unused", "claude_home": "/unused"}):
        aliased = dict(bare, **extra)
        isolation, recipes = aliased["isolation"], aliased["recipes"]
        assert direct(aliased) == expected == check(aliased)
        assert aliased["isolation"] is isolation and aliased["recipes"] is recipes
        assert "/unused" not in json.dumps(expected)


def test_ignored_alias_failures_keep_the_caller_and_then_retry():
    junk = {"codex_home": "/unused", "not-a-field": "marker"}
    schema = {"claude_home": "/unused", "schema": "nope"}
    oversized = {"codex_home": "m" * 16385}
    wide = {"claude_home": 1 << 129}
    chunk = "y" * 16384
    bulky = {"codex_home": [chunk] * (mounts.MAX_DOCUMENT_BYTES // 16384 + 1)}
    duplicate = b'{"codex_home":"/a","codex_home":"/marker"}'
    cases = (
        (junk, "team_run_fields"), (schema, "team_run_schema"), (oversized, "document_size"),
        (wide, "document_size"), (bulky, "document_size"), (duplicate, "document_invalid"),
        ([], "document_invalid"),
    )
    for value, code in cases:
        snapshot = dict(value) if type(value) is dict else list(value) if type(value) is list else value
        assert direct(value) == refused_as(code)
        assert check(value) == refused_as(code)
        rendered = json.dumps(direct(value))
        assert "marker" not in rendered and "m" * 40 not in rendered and "y" * 40 not in rendered
        _same_object(value, snapshot)
    odd = {1: "marker"}
    assert direct(odd) == refused_as("document_invalid")
    _same_object(odd, {1: "marker"})
    assert "marker" not in json.dumps(direct(odd))
    assert direct({"codex_home": "m" * 16384}) == HOST
    assert check(config())["status"] == "ok"
    assert direct(dict(config()))["status"] == "ok"


def test_aliased_documents_remain_caller_owned_under_concurrency():
    shared = dict(config(), isolation=dict(ISOLATION), codex_home="/unused", claude_home="/unused")
    recipes = shared["recipes"]
    expected = check({key: value for key, value in shared.items()
                      if key not in ("codex_home", "claude_home")})
    assert expected["status"] == "ok"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: direct(shared), range(6))) == [expected] * 6
    assert shared["codex_home"] == "/unused" and shared["claude_home"] == "/unused"
    assert shared["recipes"] is recipes
    bad = {"codex_home": "m" * 16385, "claude_home": "/unused"}
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: direct(bad)["code"], range(6))) == ["document_size"] * 6
    assert bad["codex_home"] == "m" * 16385
    assert direct(dict(config()))["status"] == "ok"


@pytest.mark.parametrize("value", ["{}", "1" * 200], ids=["encoded-object", "digits"])
def test_core_run_does_not_decode_strings(value):
    def unexpected(*args, **kwargs):
        pytest.fail("non-object config reached a container dependency")

    refused = core.check(value, observer=unexpected, owner_homes=unexpected, owner_identity=unexpected,
                         cpu_count=unexpected, host_table=unexpected, platform="linux", source="/source")
    assert refused["status"] == "refused" and refused["code"] == "document_invalid"


def test_core_rejects_double_encoded_matching_inspection():
    from aegis_core.team_isolation_verify import container_name

    value = config()
    value["isolation"] = dict(ISOLATION, engine="docker", allow_unqualified=True)
    plan = check(value)
    argv = plan["create_argv"]
    inspected = {"Name": "/" + container_name(RUN), "Image": "sha256:" + "b" * 64,
                 "Config": {"Labels": {"aegis.team.run": RUN}, "User": "0:0",
                            "Env": [argv[i + 1] for i, item in enumerate(argv) if item == "--env"]},
                 "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "CapAdd": [], "Devices": [],
                                "PidMode": "", "IpcMode": "private", "UsernsMode": "", "NetworkMode": "bridge",
                                "SecurityOpt": ["systempaths=unconfined"], "NanoCpus": 1000000000,
                                "Memory": 1073741824, "PidsLimit": 64,
                                "Tmpfs": {"/tmp": "rw,nosuid,nodev", "/dev/shm": "rw,nosuid,nodev"}},
                 "Mounts": [dict(Type="bind", Source=row["source"], Destination=row["destination"], RW=row["rw"])
                            for row in plan["mounts"]]}

    def inspector(argv):
        return [{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}]

    def unexpected(*args, **kwargs):
        pytest.fail("twice-encoded matching data reached container dependencies")

    raw = json.dumps([inspected])
    assert check(value, inspect=lambda: raw, inspector=inspector) == {"status": "ok", "mismatches": []}
    assert check(value, inspect=lambda: json.dumps(raw), inspector=unexpected, observer=unexpected) == (
        {"status": "mismatch", "mismatches": ["inspect"]})


# Credential roots that remain covered after a host row leaves the catalogue.
# File versus directory is part of this minimum. `.local` is the reserved home root.
_FIXED_MINIMUM = (
    (".aws", "dir"),
    (".config", "dir"),
    (".docker", "dir"),
    (".git-credentials", "file"),
    (".gnupg", "dir"),
    (".kube", "dir"),
    (".local", "dir"),
    (".netrc", "file"),
    (".ssh", "dir"),
)
# Run homes only. A catalogue root is refused when the fixed exclusion set contains it.
_BASELINE_HOSTS = {
    "claude": {"home": {"variable": "CLAUDE_CONFIG_DIR", "run_folder": "claude-home"}},
    "codex": {"home": {"variable": "CODEX_HOME", "run_folder": "codex-home"}},
}
_ELIGIBLE_NAME = ".eligible-notes"
_ELIGIBLE = HOME + "/" + _ELIGIBLE_NAME
_LOCAL_CHILD = HOME + "/.local/share/eligible"


def _normalized_catalogue_root(config_path):
    """Top-level component of one home-relative catalogue path.

    Both the matrix generator and the coverage assertion call this helper.
    The path is PurePosixPath(HOME).joinpath of the components after '~/',
    then posixpath.normpath of that absolute path. The result must be strictly
    below HOME. HOME itself or a path outside it is a catalogue-defect.
    Callers do not skip that entry. The top-level root is the first component
    below HOME.
    """
    if type(config_path) is not str or not config_path.startswith("~/"):
        return None
    absolute = PurePosixPath(HOME).joinpath(*config_path[2:].split("/"))
    normalized = PurePosixPath(posixpath.normpath(str(absolute)))
    try:
        below = normalized.relative_to(PurePosixPath(HOME))
    except ValueError:
        raise AssertionError("catalogue-defect: config path normalizes outside the home directory")
    if not below.parts:
        raise AssertionError("catalogue-defect: config path normalizes to the home directory")
    name = below.parts[0]
    kind = "dir" if (len(below.parts) > 1 or name.count(".") <= 1) else "file"
    return name, kind


def _catalogue_roots(rows=None):
    """Top-level components of home-relative host config paths."""
    found = {}
    for host in hosts.HOSTS if rows is None else rows:
        paths = host.config_paths
        if type(paths) not in (tuple, list):
            continue
        for config_path in paths:
            root = _normalized_catalogue_root(config_path)
            if root is None:
                continue
            name, kind = root
            if found.get(name) != "dir":
                found[name] = kind
    return tuple(sorted(found.items()))


def _non_teams_catalogue_host(config_paths):
    """Copy of a catalogue host outside the Teams registry, with injected paths."""
    source = next(row for row in hosts.HOSTS if row.id not in team_host_registry.TEAM_HOSTS)
    return dataclasses.replace(source, config_paths=tuple(config_paths))


def _refusal_roots():
    found = {name: kind for name, kind in _catalogue_roots()}
    for name, kind in _FIXED_MINIMUM:
        found[name] = kind
    return tuple(sorted(found.items()))


_ROOTS = _refusal_roots()


def _owners():
    return dict.fromkeys(("explicit", "ambient", "password"), HOME)


def _bind(path, rw):
    text = "type=bind,src=" + path + ",dst=" + path
    return text if rw else text + ",readonly"


def _mode(kind):
    return (stat.S_IFREG | 0o600) if kind == "file" else (stat.S_IFDIR | 0o700)


def _install(facts, path, kind, ident):
    row = dict(device=1, inode=ident, uid=0, gid=0, mode=_mode(kind), acl=None)
    facts[path] = dict(row, after=dict(row))


def _fill(facts, homes, extra=()):
    ident = 1000
    for home in dict.fromkeys(homes):
        for name, kind in _ROOTS:
            _install(facts, home + "/" + name, kind, ident)
            ident += 1
    for path, kind in extra:
        _install(facts, path, kind, ident)
        ident += 1


def _complete(extra=()):
    facts = observe(tuple(path for path, _kind in extra), (HOME,),
                    protected_names=mounts.secret_names())
    _fill(facts, (HOME,), extra)
    return facts


def _observing(extra=()):
    def observer(paths, homes, *, marker, protected_names):
        facts = observe(paths, homes, marker=marker, protected_names=protected_names)
        _fill(facts, homes, extra)
        return facts

    return observer


def _create(path, rw, observed):
    return core.create_argv(
        ISOLATION, run=RUN, mounts=[dict(source=path, destination=path, rw=rw)],
        host_table=_BASELINE_HOSTS, cpu_count=4, platform="linux", uid=0, gid=0, home=HOME,
        observed=observed, owner_uid=0, owner_homes=_owners())


def _plan(path, rw, extra=()):
    field = "project" if rw else "source"
    return check(dict(config(), **{field: path}), observer=_observing(extra), host_table=_BASELINE_HOSTS)


def test_catalogue_oracle_covers_home_relative_config_roots():
    """The refusal matrix follows the host catalogue and keeps the fixed minimum."""
    walked = []
    for host in hosts.HOSTS:
        paths = host.config_paths
        if type(paths) not in (tuple, list):
            continue
        for config_path in paths:
            root = _normalized_catalogue_root(config_path)
            if root is not None:
                walked.append(root[0])
    assert walked
    catalogue = {name for name, _kind in _catalogue_roots()}
    assert catalogue == set(walked)
    refused = dict(_ROOTS)
    assert catalogue <= set(refused)
    for name, kind in _FIXED_MINIMUM:
        assert refused[name] == kind
    assert _ELIGIBLE_NAME not in refused
    assert any(kind == "file" for _name, kind in _ROOTS)
    assert any(kind == "dir" for _name, kind in _ROOTS)


def _matrix_cases(roots):
    """Read-only and writable cases for each catalogue or minimum root."""
    return tuple((name, kind, rw) for name, kind in roots for rw in (False, True))


def _matrix_failure(root):
    return "matrix-failure: missing exclusion for " + HOME + "/" + root


def _public_matrix_case(root, kind, rw):
    """One case of test_public_mount_refuses_catalogued_and_minimum_roots.

    A catalogue root the public policy allows raises AssertionError with the
    matrix-failure message for that path. Callers do not treat that as success.
    """
    path = HOME + "/" + root
    facts = _complete(((path, kind), (_ELIGIBLE, "dir")))
    assert (stat.S_ISREG if kind == "file" else stat.S_ISDIR)(facts[path]["mode"])
    before = json.dumps(facts, sort_keys=True)
    try:
        _create(path, rw, facts)
    except mounts.IsolationRefusal as refusal:
        caught = refusal
    else:
        raise AssertionError(_matrix_failure(root))
    assert str(caught) == "unsafe_mount"
    assert caught.message == mounts.REFUSALS["unsafe_mount"]
    assert path not in caught.message
    assert json.dumps(facts, sort_keys=True) == before
    assert _bind(_ELIGIBLE, rw) in _create(_ELIGIBLE, rw, facts)
    assert _plan(path, rw, extra=((path, kind), (_ELIGIBLE, "dir"))) == refused_as("unsafe_mount")
    assert check(config(), host_table=_BASELINE_HOSTS)["status"] == "ok"


@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
@pytest.mark.parametrize(("root", "kind"), _ROOTS, ids=[name for name, _kind in _ROOTS])
def test_public_mount_refuses_catalogued_and_minimum_roots(root, kind, rw):
    """Each catalogue root and fixed minimum refuses both access modes.

    Observations name every such root. A sibling path stays eligible on the same
    facts. The public refusal is the documented code and does not echo the path.
    A later ordinary plan still succeeds.
    """
    _public_matrix_case(root, kind, rw)


@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
def test_comparable_eligible_mount_with_complete_observations(rw):
    facts = _complete(((_ELIGIBLE, "dir"),))
    for name, kind in _ROOTS:
        assert facts[HOME + "/" + name]["mode"] == _mode(kind)
    assert stat.S_ISDIR(facts[_ELIGIBLE]["mode"])
    assert _bind(_ELIGIBLE, rw) in _create(_ELIGIBLE, rw, facts)
    planned = _plan(_ELIGIBLE, rw, extra=((_ELIGIBLE, "dir"),))
    assert planned["status"] == "ok"
    assert any(row["source"] == _ELIGIBLE and row["rw"] is rw for row in planned["mounts"])
    before = json.dumps(facts, sort_keys=True)
    with pytest.raises(mounts.IsolationRefusal, match="^unsafe_mount$"):
        _create(HOME + "/.ssh", True, facts)
    assert json.dumps(facts, sort_keys=True) == before
    assert _bind(_ELIGIBLE, rw) in _create(_ELIGIBLE, rw, facts)


@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
def test_absent_local_root_stays_reserved(rw):
    path = HOME + "/.local"
    facts = _complete(((_ELIGIBLE, "dir"),))
    facts[path] = None
    before = json.dumps(facts, sort_keys=True)
    with pytest.raises(mounts.IsolationRefusal, match="^unsafe_mount$") as caught:
        _create(path, rw, facts)
    assert str(caught.value) == "unsafe_mount"
    assert path not in caught.value.message
    assert json.dumps(facts, sort_keys=True) == before
    assert _bind(_ELIGIBLE, rw) in _create(_ELIGIBLE, rw, facts)


@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
def test_local_descendant_stays_eligible(rw):
    facts = _complete(((HOME + "/.local/share", "dir"), (_LOCAL_CHILD, "dir")))
    assert stat.S_ISDIR(facts[HOME + "/.local"]["mode"])
    with pytest.raises(mounts.IsolationRefusal, match="^unsafe_mount$"):
        _create(HOME + "/.local", rw, facts)
    assert _bind(_LOCAL_CHILD, rw) in _create(_LOCAL_CHILD, rw, facts)
    assert _bind(_LOCAL_CHILD, rw) in _create(_LOCAL_CHILD, rw, facts)


@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
@pytest.mark.parametrize("root", [name for name, _kind in _ROOTS], ids=[name for name, _kind in _ROOTS])
def test_missing_root_observation_refuses_on_that_root_then_retries(root, rw):
    """Dropping one exclusion's observation refuses that case, then a complete retry works."""
    facts = _complete(((_ELIGIBLE, "dir"),))
    del facts[HOME + "/" + root]
    before = json.dumps(facts, sort_keys=True)
    with pytest.raises(mounts.IsolationRefusal, match="^mount_metadata$") as caught:
        _create(_ELIGIBLE, rw, facts)
    assert str(caught.value) == "mount_metadata"
    assert root not in caught.value.message
    assert json.dumps(facts, sort_keys=True) == before
    with pytest.raises(mounts.IsolationRefusal, match="^mount_metadata$"):
        _create(_ELIGIBLE, rw, facts)
    restored = _complete(((_ELIGIBLE, "dir"),))
    assert _bind(_ELIGIBLE, rw) in _create(_ELIGIBLE, rw, restored)


def test_catalogue_refusals_and_eligible_mounts_are_isolated_under_concurrency():
    def refuse(item):
        root, kind, rw = item
        path = HOME + "/" + root
        facts = _complete(((_ELIGIBLE, "dir"),))
        present = stat.S_ISREG(facts[path]["mode"]) if kind == "file" else stat.S_ISDIR(facts[path]["mode"])
        if not present:
            return root
        try:
            _create(path, rw, facts)
        except mounts.IsolationRefusal as exc:
            code = "echoed" if path in exc.message else exc.code
        else:
            code = "allowed"
        try:
            argv = _create(_ELIGIBLE, rw, facts)
        except mounts.IsolationRefusal as exc:
            return root + ":" + exc.code
        if code != "unsafe_mount" or _bind(_ELIGIBLE, rw) not in argv:
            return root
        return "ok"

    items = [(root, kind, rw) for root, kind in _ROOTS for rw in (False, True)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refuse, items)) == ["ok"] * len(items)

    shared = _complete(((_ELIGIBLE, "dir"),))
    shared[HOME + "/.local"] = None
    before = json.dumps(shared, sort_keys=True)

    def share(rw):
        try:
            _create(HOME + "/.local", rw, shared)
        except mounts.IsolationRefusal as exc:
            refused = exc.code
        else:
            refused = "allowed"
        argv = _create(_ELIGIBLE, rw, shared)
        return refused, _bind(_ELIGIBLE, rw) in argv

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(share, [False, True] * 3)) == [("unsafe_mount", True)] * 6
    assert json.dumps(shared, sort_keys=True) == before


_DOTTED_NEXT = ("~/./.next-host", "~/a/../.next-host", "~//.next-host", "~///.next-host")
_NEXT_ROOT = ".next-host"


@pytest.mark.parametrize("config_path", ["~/.", "~/./.", "~/foo/..", "~/"])
def test_catalogue_entry_that_is_the_home_directory_is_a_catalogue_defect(config_path):
    """A home-relative entry that normalizes to HOME itself is never skipped."""
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes to the home directory$"):
        _normalized_catalogue_root(config_path)
    host = _non_teams_catalogue_host((config_path,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes to the home directory$"):
        _catalogue_roots((host,))


@pytest.mark.parametrize("config_path", ["~/..", "~/../.next-host", "~/foo/../..", "~/a/../../.next-host"])
def test_catalogue_entry_outside_home_is_a_catalogue_defect(config_path):
    """A home-relative entry that normalizes outside HOME is never skipped."""
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes outside the home directory$"):
        _normalized_catalogue_root(config_path)
    host = _non_teams_catalogue_host((config_path,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes outside the home directory$"):
        _catalogue_roots((host,))


def test_dotted_spellings_name_the_same_top_level_root():
    """Every injected spelling survives normalization as one non-Teams catalogue root."""
    host = _non_teams_catalogue_host(_DOTTED_NEXT)
    assert host.id not in team_host_registry.TEAM_HOSTS
    walked = []
    for config_path in host.config_paths:
        walked.append(_normalized_catalogue_root(config_path)[0])
    assert walked == [_NEXT_ROOT] * len(_DOTTED_NEXT)
    assert dict(_catalogue_roots((host,))) == {_NEXT_ROOT: "dir"}
    assert {name for name, _kind in _catalogue_roots((host,))} == set(walked)


def test_normalized_catalogue_roots_stay_stable_under_concurrency():
    """Concurrent readers of the same spellings agree, and a bad entry still fails."""
    def once(spelling):
        host = _non_teams_catalogue_host((spelling,))
        try:
            root = _normalized_catalogue_root(spelling)
            found = _catalogue_roots((host,))
        except AssertionError as exc:
            return "defect" if str(exc).startswith("catalogue-defect:") else spelling
        if root == (_NEXT_ROOT, "dir") and found == ((_NEXT_ROOT, "dir"),):
            return "ok"
        return spelling

    spellings = list(_DOTTED_NEXT) * 3
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, spellings)) == ["ok"] * len(spellings)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, ["~/.", "~/.."] * 3)) == ["defect"] * 6


@pytest.mark.parametrize("spelling", ["~/./.ssh", "~/a/../.ssh"])
@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
def test_dotted_spelling_of_a_fixed_root_is_refused_then_retried(spelling, rw):
    """A dotted spelling of an excluded root is refused in both modes, then again."""
    host = _non_teams_catalogue_host((spelling,))
    assert _normalized_catalogue_root(spelling) == (".ssh", "dir")
    assert dict(_catalogue_roots((host,)))[".ssh"] == "dir"
    _public_matrix_case(".ssh", "dir", rw)
    _public_matrix_case(".ssh", "dir", rw)


def test_dotted_fixed_root_refusal_is_isolated_under_concurrency():
    """Concurrent dotted spellings of a fixed root each refuse on their own facts."""
    def once(item):
        spelling, rw = item
        host = _non_teams_catalogue_host((spelling,))
        if dict(_catalogue_roots((host,))).get(".ssh") != "dir":
            return spelling
        try:
            _public_matrix_case(".ssh", "dir", rw)
        except AssertionError as exc:
            return str(exc)
        return "ok"

    items = [(spelling, rw) for spelling in ("~/./.ssh", "~/a/../.ssh") for rw in (False, True)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, items)) == ["ok"] * len(items)


@pytest.mark.parametrize("spelling", _DOTTED_NEXT,
                         ids=["dot-slash", "parent-dotdot", "double-slash", "triple-slash"])
def test_missing_normalized_root_fails_its_matrix_case(spelling):
    """A dotted non-Teams spelling enters the matrix and the case body reports the gap.

    The public policy allows $HOME/.next-host. The shared matrix case fails with
    the matrix-failure message for that path, and a second call fails the same way.
    """
    host = _non_teams_catalogue_host((spelling,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    roots = _catalogue_roots((host,))
    assert dict(roots) == {_NEXT_ROOT: "dir"}
    cases = _matrix_cases(roots)
    assert (_NEXT_ROOT, "dir", False) in cases
    assert (_NEXT_ROOT, "dir", True) in cases
    message = _matrix_failure(_NEXT_ROOT)
    for rw in (False, True):
        with pytest.raises(AssertionError) as caught:
            _public_matrix_case(_NEXT_ROOT, "dir", rw)
        assert str(caught.value) == message
        with pytest.raises(AssertionError) as again:
            _public_matrix_case(_NEXT_ROOT, "dir", rw)
        assert str(again.value) == message


def test_missing_normalized_root_matrix_failures_are_isolated_under_concurrency():
    """Each dotted spelling fails its own matrix case without disturbing the other."""
    message = _matrix_failure(_NEXT_ROOT)

    def once(item):
        spelling, rw = item
        host = _non_teams_catalogue_host((spelling,))
        roots = _catalogue_roots((host,))
        if dict(roots).get(_NEXT_ROOT) != "dir":
            return spelling
        if (_NEXT_ROOT, "dir", rw) not in _matrix_cases(roots):
            return spelling
        try:
            _public_matrix_case(_NEXT_ROOT, "dir", rw)
        except AssertionError as exc:
            return "ok" if str(exc) == message else str(exc)
        return "allowed"

    items = [(spelling, rw) for spelling in _DOTTED_NEXT for rw in (False, True)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, items)) == ["ok"] * len(items)
