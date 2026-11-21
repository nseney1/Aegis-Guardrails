"""TA-6c public plan, verification and engine argv parity."""
from concurrent.futures import ThreadPoolExecutor
import importlib
import json
from pathlib import PurePosixPath
import stat
import sys

import pytest

from aegis_core import team_host_registry, team_isolation as core
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


def check(value, **options):
    inputs = dict(observer=observe, owner_homes=lambda: dict.fromkeys(
        ("explicit", "ambient", "password"), HOME), owner_uid=0, owner_gid=0, cpu_count=4,
        platform="linux", host_table=TABLE, source=SOURCE)
    inputs.update(options)
    raw = value if type(value) is bytes else json.dumps(value).encode()
    return core.check(raw, **inputs)


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


def test_run_core_refuses_host_specific_aliases():
    assert check(b'{"codex_home":"/unused","claude_home":"/unused"}').get("code") == "team_run_fields"


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
