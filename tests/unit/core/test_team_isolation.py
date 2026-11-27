"""TA-6c public plan, verification and engine argv parity."""
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import importlib
import json
from pathlib import PurePosixPath
import stat
import sys
from threading import Barrier

import pytest

from aegis_core import hosts, team_host_registry, team_isolation as core
from aegis_core import team_isolation_mounts as mounts
from aegis_core import team_isolation_verify as verifier
from aegis_core.team_isolation_refusal import plan_response, plan_text
from tests.helpers_isolation_catalogue import catalogue_config_parts, home_config_parts


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


def refused_as(code, stage=None):
    reason = mounts.REFUSALS[code]
    if stage == "image-inspection" and code in ("document_invalid", "document_size"):
        reason = "Check local engine inspection for the configured image and retry."
    body = {"status": "refused", "code": code, "reason": reason,
            "next_action": {"actor": "operator", "command": reason}}
    if stage is not None:
        body["stage"] = stage
    return body


def _document_stage(code):
    if code in ("document_invalid", "document_read", "document_size"):
        return "config"
    return None


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
    assert refused == refused_as(code, _document_stage(code))
    assert set(refused) == ({"status", "code", "reason", "next_action", "stage"}
                            if _document_stage(code) else {"status", "code", "reason", "next_action"})
    retry = check(config())
    assert retry["status"] == "ok" and "stage" not in retry


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


def unexpected_observer(*args, **kwargs):
    pytest.fail("malformed container input reached observation")


def test_inspection_refusal_order_and_retry():
    value, inspected, good_image = _matching_inspections()
    calls = []

    def inspector(argv):
        calls.append(argv)
        return good_image

    refused = check(value, inspect=lambda: b"bad", inspector=inspector, observer=unexpected_observer)
    assert refused == refused_as("document_invalid", "container-inspection") and not calls
    assert check(value, inspect=lambda: inspected, inspector=inspector) == {"status": "ok", "mismatches": []}
    assert calls == [["docker", "image", "inspect", IMAGE]]
    assert check(value, inspect=lambda: inspected, inspector=lambda _: b"{}") == refused_as("image_inspect")
    assert check(value, inspect=lambda: inspected, inspector=lambda _: b"{") == (
        refused_as("document_invalid", "image-inspection"))
    assert check(value, inspect=lambda: inspected, inspector=inspector) == {"status": "ok", "mismatches": []}


@pytest.mark.parametrize("stage", ["container-inspection", "image-inspection"])
def test_typed_reader_refusal_has_its_document_stage_and_retries(stage):
    value, inspected, good_image = _matching_inspections()

    class ReaderRefusal(mounts.IsolationRefusal):
        pass

    def unreadable(*args):
        error = ReaderRefusal("document_read")
        error.message = "untrusted\nreader message"
        raise error

    if stage == "container-inspection":
        refused = check(value, inspect=unreadable, inspector=unexpected_observer, observer=unexpected_observer)
    else:
        refused = check(value, inspect=lambda: inspected, inspector=unreadable)
    assert refused == refused_as("document_read", stage)
    assert check(value, inspect=lambda: inspected, inspector=lambda _: good_image) == (
        {"status": "ok", "mismatches": []})


def test_document_stages_stay_isolated_across_concurrent_checks():
    value, inspected, good_image = _matching_inspections()

    def project(index):
        kind = index % 3
        if kind == 0:
            body = check(b"{")
        elif kind == 1:
            body = check(value, inspect=lambda: b"{", observer=unexpected_observer,
                         inspector=unexpected_observer)
        else:
            body = check(value, inspect=lambda: inspected, inspector=lambda _argv: [{"extra": 1 << 128}])
        retry = check(value, inspect=lambda: inspected, inspector=lambda _argv: good_image)
        return body, retry

    with ThreadPoolExecutor(max_workers=3) as pool:
        found = list(pool.map(project, range(9)))
    success = {"status": "ok", "mismatches": []}
    assert found[0::3] == [(refused_as("document_invalid", "config"), success)] * 3
    assert found[1::3] == [(refused_as("document_invalid", "container-inspection"), success)] * 3
    assert found[2::3] == [(refused_as("document_size", "image-inspection"), success)] * 3


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
        assert direct(value) == refused_as(code, _document_stage(code))
        assert check(value) == refused_as(code, _document_stage(code))
        rendered = json.dumps(direct(value))
        assert "marker" not in rendered and "m" * 40 not in rendered and "y" * 40 not in rendered
        _same_object(value, snapshot)
    odd = {1: "marker"}
    assert direct(odd) == refused_as("document_invalid", "config")
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
    assert refused == refused_as("document_invalid", "config")


def _matching_inspections():
    value = config()
    value["isolation"] = dict(ISOLATION, engine="docker", allow_unqualified=True)
    plan = check(value)
    argv = plan["create_argv"]
    inspected = {"Name": "/" + verifier.container_name(RUN), "Image": "sha256:" + "b" * 64,
                 "Config": {"Labels": {"aegis.team.run": RUN}, "User": "0:0",
                            "Env": [argv[i + 1] for i, item in enumerate(argv) if item == "--env"]},
                 "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "CapAdd": [], "Devices": [],
                                "PidMode": "", "IpcMode": "private", "UsernsMode": "", "NetworkMode": "bridge",
                                "SecurityOpt": ["systempaths=unconfined"], "NanoCpus": 1000000000,
                                "Memory": 1073741824, "PidsLimit": 64,
                                "Tmpfs": {"/tmp": "rw,nosuid,nodev", "/dev/shm": "rw,nosuid,nodev"}},
                 "Mounts": [dict(Type="bind", Source=row["source"], Destination=row["destination"], RW=row["rw"])
                            for row in plan["mounts"]]}

    image = [{"Id": "sha256:" + "b" * 64, "RepoDigests": [IMAGE], "Config": {"Env": []}}]
    return value, json.dumps([inspected]), image


def _verification_context():
    return dict(host_table=TABLE, home=HOME, observed=observe((RUN, PROJECT, SOURCE, PREFIX), (HOME,)),
                owner_uid=0, owner_homes=_inputs()["owner_homes"]())


@pytest.mark.parametrize(("cpus", "code", "reason"), [
    (1 << 128, "document_size", "Reduce the isolation input to its documented size limits."),
    ("\ud800untrusted-cpu", "document_invalid", "Supply a valid bounded JSON document."),
], ids=["size", "invalid"])
def test_expected_plan_stages_config_document_refusal_then_verifies(cpus, code, reason):
    value, container, image = _matching_inspections()
    rows = check(value)["mounts"]
    context = _verification_context()

    def expected(isolation):
        return verifier.expected_plan(isolation, run=RUN, mounts=rows, image_inspect=image,
                                      uid=0, gid=0, cpu_count=4, platform="linux", **context)

    isolation = dict(value["isolation"], cpus=cpus)
    with pytest.raises(mounts.IsolationRefusal, match="^" + code + "$") as caught:
        expected(isolation)
    error = caught.value
    assert error.stage == "config"
    assert error.exit_code == 1
    body = plan_response(error)
    assert body == {"status": "refused", "code": code, "reason": reason, "stage": "config",
                    "next_action": {"actor": "operator", "command": reason}}
    assert plan_text(body) == code + " — " + reason + " (config)"

    isolation["cpus"] = value["isolation"]["cpus"]
    assert verifier.verify(container, expected(isolation), **context) == []


@pytest.mark.parametrize("entry", ["decoded", "text", "bytes", "argv"])
@pytest.mark.parametrize(("cpus", "code", "stage"), [
    (1 << 128, "document_size", "config"),
    ("\ud800untrusted-cpu", "document_invalid", "config"),
    (5, "isolation_cpus", None),
], ids=["size", "invalid", "semantic"])
def test_config_readers_and_argv_distinguish_document_and_field_errors(entry, cpus, code, stage):
    isolation = dict(ISOLATION, cpus=cpus)
    limits = dict(cpu_count=4, platform="linux")
    with pytest.raises(mounts.IsolationRefusal, match="^" + code + "$") as caught:
        if entry == "decoded":
            mounts.read_isolation(isolation, **limits)
        elif entry == "argv":
            core.create_argv(isolation, run=RUN, mounts=check(config())["mounts"], uid=0, gid=0,
                             **_verification_context(), **limits)
        else:
            text = json.dumps(isolation)
            mounts.load_isolation(text.encode() if entry == "bytes" else text, **limits)
    assert caught.value.stage == stage
    assert plan_response(caught.value) == refused_as(code, stage)


def test_isolation_readers_keep_their_input_domains():
    limits = dict(cpu_count=4, platform="linux")
    text = json.dumps(ISOLATION)
    for reader, raw, code, stage in (
        (mounts.read_isolation, text, "isolation_object", None),
        (mounts.read_isolation, text.encode(), "document_invalid", "config"),
        (mounts.load_isolation, ISOLATION, "document_invalid", "config"),
        (mounts.load_isolation, b'{"untrusted":', "document_invalid", "config"),
        (mounts.load_isolation, json.dumps(text), "isolation_object", None),
    ):
        with pytest.raises(mounts.IsolationRefusal, match="^" + code + "$") as caught:
            reader(raw, **limits)
        assert plan_response(caught.value) == refused_as(code, stage)


@pytest.mark.parametrize("entry", ["decoded", "text", "bytes"])
def test_isolation_readers_bound_each_config_document_once(entry, monkeypatch):
    decodes, bounds = [], []
    strict_loads, bounded_value = mounts.strict_loads, mounts.bounded_value

    def decode(text):
        decodes.append(text)
        return strict_loads(text)

    def bound(value):
        bounds.append(value)
        bounded_value(value)

    monkeypatch.setattr(mounts, "strict_loads", decode)
    monkeypatch.setattr(mounts, "bounded_value", bound)
    text = json.dumps(ISOLATION)
    limits = dict(cpu_count=4, platform="linux")
    if entry == "decoded":
        result = mounts.read_isolation(ISOLATION, **limits)
        assert decodes == []
    else:
        result = mounts.load_isolation(text.encode() if entry == "bytes" else text, **limits)
        assert decodes == [text]
    assert bounds == [ISOLATION]
    assert result == dict(ISOLATION, allow_unqualified=False)


def test_config_and_inspection_refusal_stages_are_call_local():
    value, container, image = _matching_inspections()
    rows = check(value)["mounts"]
    context = _verification_context()
    large = 1 << 128

    def expected(isolation, evidence):
        return verifier.expected_plan(isolation, run=RUN, mounts=rows, image_inspect=evidence,
                                      uid=0, gid=0, cpu_count=4, platform="linux", **context)

    isolation = value["isolation"]
    record = expected(isolation, image)
    cases = (
        (lambda: expected(dict(isolation, cpus=large), image), "config"),
        (lambda: expected(isolation, [{"extra": large}]), "image-inspection"),
        (lambda: verifier.verify([{"extra": large}], record, **context), "container-inspection"),
        (lambda: verifier.verify(container, dict(record, extra=large), **context), None),
        (lambda: verifier.verify(container, record, **dict(context, observed={"extra": large})), None),
        (lambda: mounts.load_document(json.dumps({"extra": large})), None),
    )
    start = Barrier(len(cases), timeout=10)

    def project(case):
        operation, stage = case
        start.wait()
        with pytest.raises(mounts.IsolationRefusal, match="^document_size$") as caught:
            operation()
        assert caught.value.stage == stage
        assert plan_response(caught.value) == refused_as("document_size", stage)

    with ThreadPoolExecutor(max_workers=len(cases)) as pool:
        list(pool.map(project, cases))
    assert verifier.verify(container, record, **context) == []


def test_core_rejects_double_encoded_matching_inspection():
    value, raw, image = _matching_inspections()

    def unexpected(*args, **kwargs):
        pytest.fail("twice-encoded matching data reached container dependencies")

    assert check(value, inspect=lambda: raw, inspector=lambda _: image) == {"status": "ok", "mismatches": []}
    assert check(value, inspect=lambda: json.dumps(raw), inspector=unexpected, observer=unexpected) == (
        {"status": "mismatch", "mismatches": ["inspect"]})


@pytest.mark.parametrize("encode", [lambda value: value, json.dumps, lambda value: json.dumps(value).encode()],
                         ids=["decoded", "text", "bytes"])
def test_verifier_stages_input_limits_and_bounds_each_inspection_once(encode, monkeypatch):
    value, container, image = _matching_inspections()
    container = json.loads(container)
    rows = check(value)["mounts"]
    context = _verification_context()
    invalid = [{"extra": 1 << 128}]

    def expected(evidence):
        return verifier.expected_plan(value["isolation"], run=RUN, mounts=rows, image_inspect=evidence,
                                      uid=0, gid=0, cpu_count=4, platform="linux", **context)

    def verify(evidence, record):
        return verifier.verify(evidence, record, **context)

    with pytest.raises(mounts.IsolationRefusal, match="^document_size$") as error:
        expected(encode(invalid))
    assert error.value.stage == "image-inspection"
    record = expected(encode(image))
    with pytest.raises(mounts.IsolationRefusal, match="^document_size$") as error:
        verify(encode(invalid), record)
    assert error.value.stage == "container-inspection"
    with pytest.raises(mounts.IsolationRefusal, match="^document_size$") as error:
        verify(encode(container), dict(record, extra=1 << 128))
    assert error.value.stage is None

    bounds = []
    bounded_value = mounts.bounded_value

    def track(candidate):
        bounds.append(candidate)
        bounded_value(candidate)

    monkeypatch.setattr(mounts, "bounded_value", track)
    monkeypatch.setattr(verifier, "bounded_value", track)
    assert expected(encode(image)) == record
    assert bounds.count(image) == 1
    bounds.clear()
    assert verify(encode(container), record) == []
    assert bounds.count(container) == 1


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


def _catalogue_roots(rows):
    """Each top-level root can be a directory. Only leaves can also be files."""
    roots = set()
    directories = set()
    for parts in catalogue_config_parts(rows, HOME):
        roots.add(parts[0])
        if len(parts) > 1:
            directories.add(parts[0])
    return tuple(sorted({(name, "dir") for name in roots}
                        | {(name, "file") for name in roots - directories}))


def _non_teams_catalogue_host(config_paths):
    """Copy of a catalogue host outside the Teams registry, with injected paths."""
    source = next(row for row in hosts.HOSTS if row.id not in team_host_registry.TEAM_HOSTS)
    return dataclasses.replace(source, config_paths=tuple(config_paths))


def _refusal_roots(rows):
    return tuple(sorted(set(_catalogue_roots(rows)) | set(_FIXED_MINIMUM)))


_ROOTS = _refusal_roots(hosts.HOSTS)
_OBSERVED_ROOTS = dict.fromkeys((name for name, _kind in _ROOTS), "dir") | dict(_FIXED_MINIMUM)


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
    observations = {home + "/" + name: kind for home in dict.fromkeys(homes)
                    for name, kind in _OBSERVED_ROOTS.items()}
    observations.update(extra)
    for ident, (path, kind) in enumerate(observations.items(), 1000):
        _install(facts, path, kind, ident)


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
    catalogue = {parts[0] for parts in catalogue_config_parts(hosts.HOSTS, HOME)}
    assert catalogue
    minimum = {
        (".aws", "dir"), (".config", "dir"), (".docker", "dir"), (".git-credentials", "file"),
        (".gnupg", "dir"), (".kube", "dir"), (".local", "dir"), (".netrc", "file"), (".ssh", "dir"),
    }
    assert set(_refusal_roots(())) == minimum
    assert minimum <= set(_ROOTS)
    assert catalogue <= _OBSERVED_ROOTS.keys()
    assert _ELIGIBLE_NAME not in _OBSERVED_ROOTS


def _matrix_cases(roots):
    """Read-only and writable cases for each catalogue or minimum root."""
    return tuple((name, kind, rw) for name, kind in roots for rw in (False, True))


_MATRIX_CASES = _matrix_cases(_ROOTS)


@pytest.mark.parametrize("reverse", [False, True])
def test_catalogue_matrix_covers_both_leaf_kinds_and_directory_ancestors(reverse):
    rows = (
        _non_teams_catalogue_host(("~/.claude.json", "~/.ssh", "~/.gemini")),
        _non_teams_catalogue_host(("~/other/../.gemini/config", "~/.ssh", "/outside")),
    )
    if reverse:
        rows = rows[::-1]
    assert set(_matrix_cases(_catalogue_roots(rows))) == {
        (".claude.json", "dir", False), (".claude.json", "dir", True),
        (".claude.json", "file", False), (".claude.json", "file", True),
        (".ssh", "dir", False), (".ssh", "dir", True),
        (".ssh", "file", False), (".ssh", "file", True),
        (".gemini", "dir", False), (".gemini", "dir", True),
    }
    assert {kind for name, kind in _refusal_roots(rows) if name == ".ssh"} == {"dir", "file"}


def _matrix_failure(root):
    return "matrix-failure: missing exclusion for " + HOME + "/" + root


def _public_matrix_case(root, kind, rw):
    """One case of test_public_mount_refuses_catalogued_and_minimum_roots.

    A catalogue root the public policy allows raises AssertionError with the
    matrix-failure message for that path. Callers do not treat that as success.
    """
    path = HOME + "/" + root
    extra = ((path, kind), (_ELIGIBLE, kind))
    facts = _complete(extra)
    for observed_path, observed_kind in extra:
        row = facts[observed_path]
        assert row["mode"] == row["after"]["mode"] == _mode(observed_kind)
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
    assert _plan(path, rw, extra=extra) == refused_as("unsafe_mount")
    assert check(config(), host_table=_BASELINE_HOSTS)["status"] == "ok"


@pytest.mark.parametrize(
    ("root", "kind", "rw"), _MATRIX_CASES,
    ids=[name + "-" + kind + ("-writable" if rw else "-read-only") for name, kind, rw in _MATRIX_CASES],
)
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
    for name, kind in _OBSERVED_ROOTS.items():
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
@pytest.mark.parametrize("root", tuple(_OBSERVED_ROOTS))
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
        _public_matrix_case(*item)

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(refuse, _MATRIX_CASES, timeout=10))

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
        assert list(pool.map(share, [False, True] * 3, timeout=10)) == [("unsafe_mount", True)] * 6
    assert json.dumps(shared, sort_keys=True) == before


_DOTTED_NEXT = ("~/./.next-host", "~/a/../.next-host", "~//.next-host", "~///.next-host")


@pytest.mark.parametrize("config_path", ["~/.", "~/./.", "~/foo/..", "~/"])
def test_catalogue_entry_that_is_the_home_directory_is_a_catalogue_defect(config_path):
    """A home-relative entry that normalizes to HOME itself is never skipped."""
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes to the home directory$"):
        home_config_parts(config_path, HOME)
    host = _non_teams_catalogue_host((config_path,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes to the home directory$"):
        _catalogue_roots((host,))


@pytest.mark.parametrize("config_path", ["~/..", "~/../.next-host", "~/foo/../..", "~/a/../../.next-host"])
def test_catalogue_entry_outside_home_is_a_catalogue_defect(config_path):
    """A home-relative entry that normalizes outside HOME is never skipped."""
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes outside the home directory$"):
        home_config_parts(config_path, HOME)
    host = _non_teams_catalogue_host((config_path,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    with pytest.raises(AssertionError, match="^catalogue-defect: config path normalizes outside the home directory$"):
        _catalogue_roots((host,))


def test_dotted_spellings_name_the_same_top_level_root():
    """Every injected spelling survives normalization as one non-Teams catalogue root."""
    host = _non_teams_catalogue_host(_DOTTED_NEXT)
    assert host.id not in team_host_registry.TEAM_HOSTS
    assert tuple(catalogue_config_parts((host,), HOME)) == ((".next-host",),) * len(_DOTTED_NEXT)
    assert _catalogue_roots((host,)) == ((".next-host", "dir"), (".next-host", "file"))


def test_normalized_catalogue_roots_stay_stable_under_concurrency():
    """Concurrent readers of the same spellings agree, and a bad entry still fails."""
    def once(spelling):
        host = _non_teams_catalogue_host((spelling,))
        try:
            parts = home_config_parts(spelling, HOME)
            found = _catalogue_roots((host,))
        except AssertionError as exc:
            return "defect" if str(exc).startswith("catalogue-defect:") else spelling
        if parts == (".next-host",) and found == ((".next-host", "dir"), (".next-host", "file")):
            return "ok"
        return spelling

    spellings = [*_DOTTED_NEXT, "~/.", "~/.."] * 3
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, spellings, timeout=10)) == (["ok"] * 4 + ["defect", "defect"]) * 3


@pytest.mark.parametrize("spelling", ["~/./.ssh", "~/a/../.ssh"])
@pytest.mark.parametrize("rw", [False, True], ids=["read-only", "writable"])
def test_dotted_spelling_of_a_fixed_root_is_refused_then_retried(spelling, rw):
    """A dotted spelling of an excluded root is refused in both modes, then again."""
    host = _non_teams_catalogue_host((spelling,))
    assert home_config_parts(spelling, HOME) == (".ssh",)
    roots = _catalogue_roots((host,))
    assert roots == ((".ssh", "dir"), (".ssh", "file"))
    for root, kind in roots:
        _public_matrix_case(root, kind, rw)
        _public_matrix_case(root, kind, rw)


def test_dotted_fixed_root_refusal_is_isolated_under_concurrency():
    """Concurrent dotted spellings of a fixed root each refuse on their own facts."""
    def once(item):
        spelling, rw = item
        host = _non_teams_catalogue_host((spelling,))
        roots = _catalogue_roots((host,))
        assert roots == ((".ssh", "dir"), (".ssh", "file"))
        for root, kind in roots:
            _public_matrix_case(root, kind, rw)

    items = [(spelling, rw) for spelling in ("~/./.ssh", "~/a/../.ssh") for rw in (False, True)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(once, items, timeout=10))


def _assert_missing_exclusion(root, kind, rw):
    with pytest.raises(AssertionError) as caught:
        _public_matrix_case(root, kind, rw)
    assert str(caught.value) == _matrix_failure(root)


@pytest.mark.parametrize("spelling", _DOTTED_NEXT,
                         ids=["dot-slash", "parent-dotdot", "double-slash", "triple-slash"])
def test_missing_normalized_root_fails_its_matrix_case(spelling):
    """A dotted non-Teams spelling enters the matrix and the case body reports the gap.

    The public policy allows $HOME/.next-host. The shared matrix case fails with
    the matrix-failure message for that path, and a second call fails the same way.
    """
    host = _non_teams_catalogue_host((spelling,))
    assert host.id not in team_host_registry.TEAM_HOSTS
    cases = _matrix_cases(_catalogue_roots((host,)))
    assert set(cases) == {
        (".next-host", "dir", False), (".next-host", "dir", True),
        (".next-host", "file", False), (".next-host", "file", True),
    }
    for root, kind, rw in cases:
        _assert_missing_exclusion(root, kind, rw)
        _assert_missing_exclusion(root, kind, rw)


def test_missing_normalized_root_matrix_failures_are_isolated_under_concurrency():
    """Each dotted spelling fails its own matrix case without disturbing the other."""
    def once(spelling):
        host = _non_teams_catalogue_host((spelling,))
        roots = _catalogue_roots((host,))
        assert roots == ((".next-host", "dir"), (".next-host", "file"))
        for root, kind, rw in _matrix_cases(roots):
            _assert_missing_exclusion(root, kind, rw)

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(once, _DOTTED_NEXT, timeout=10))


# RELEASE RULING 2026-11-21T15:14:28Z. Paired just-inside and just-outside records for the
# three pure-builder exceptions. Legacy calls are a read-only oracle. Product code is unchanged.
_BYTE_BUDGET = 1024 * 1024
_OPERAND_CODES = {"executable": "isolation_command", "image": "isolation_image", "tag": "image_tag"}
_LEGACY_OPERAND_REFUSALS = {
    "executable": {"invalid command executable", "command must not start with -", "invalid command argument"},
    "image": {"invalid image", "image must not start with -"},
    "tag": {"invalid image tag", "image tag must not start with -"},
}
# name, kind, argument, core accepts, legacy accepts, executable refusal override.
# The override is the command-document surrogate refusal. Image and tag use their operand code.
_OPERAND_SPECIMENS = (
    ("space", "scalar", 0x20, True, True, None),
    ("unit-separator", "scalar", 0x1F, False, True, None),
    ("tilde", "scalar", 0x7E, True, True, None),
    ("delete", "scalar", 0x7F, False, True, None),
    ("nbsp", "scalar", 0xA0, True, True, None),
    ("c1", "scalar", 0x9F, False, True, None),
    ("before-surrogate", "scalar", 0xD7FF, True, True, None),
    ("high-surrogate", "scalar", 0xD800, False, True, "document_invalid"),
    ("low-surrogate", "scalar", 0xDFFF, False, True, "document_invalid"),
    ("after-surrogate", "scalar", 0xE000, True, True, None),
    ("max-scalar", "scalar", 0x10FFFF, True, True, None),
    ("newline", "scalar", 0x0A, False, True, None),
    ("tab", "scalar", 0x09, False, True, None),
    ("nul", "scalar", 0x00, False, False, None),
    ("multiline", "text", "ok\nmore", False, True, None),
    ("embedded-dash", "text", "a-b", True, True, None),
    ("leading-dash", "text", "-a", False, False, None),
    ("length-4096", "repeat", 4096, True, True, None),
    ("length-4097", "repeat", 4097, False, False, None),
    ("empty", "repeat", 0, False, False, None),
)
# Trailing words are outside the operand domain. legacy_executable is the read-only oracle
# for the same text in the executable position.
_TRAILING_SPECS = (
    ("unit-separator", "scalar", 0x1F, "isolation_command", True),
    ("delete", "scalar", 0x7F, "isolation_command", True),
    ("c1", "scalar", 0x9F, "isolation_command", True),
    ("newline", "scalar", 0x0A, "isolation_command", True),
    ("multiline", "text", "ok\nmore", "isolation_command", True),
    ("tab", "scalar", 0x09, "isolation_command", True),
    ("leading-dash", "text", "-a", "isolation_command", False),
    ("past-executable-length", "repeat", 4097, "isolation_command", False),
    ("other-word-cap", "repeat", 16384, "isolation_command", False),
)


def _operand_cases():
    cases = []
    for surface in ("executable", "image", "tag"):
        for name, kind, argument, core_ok, legacy_ok, executable_code in _OPERAND_SPECIMENS:
            cases.append(pytest.param(
                surface, kind, argument, core_ok, legacy_ok, executable_code, id=surface + "-" + name))
    return cases


def _operand_text(kind, argument):
    if kind == "scalar":
        return chr(argument)
    if kind == "text":
        return argument
    if kind == "repeat":
        return "a" * argument
    raise AssertionError(kind)


def _operand_refusal_code(surface, executable_code):
    if surface == "executable" and executable_code is not None:
        return executable_code
    return _OPERAND_CODES[surface]


def _exec(command):
    return core.exec_argv("docker", RUN, command, workdir=PROJECT, host_table=TABLE)


def _legacy_exec(legacy, command):
    return legacy.exec_argv("docker", RUN, command, workdir=PROJECT)


def _create_command(command):
    rows = [dict(source=PROJECT, destination=PROJECT, rw=True)]
    return core.create_argv(
        ISOLATION, run=RUN, mounts=rows, host_table=TABLE, cpu_count=4, platform="linux", uid=0, gid=0,
        home=HOME, observed=observe((PROJECT,), (HOME,)), owner_uid=0,
        owner_homes=dict.fromkeys(("explicit", "ambient", "password"), HOME), command=command)


def _legacy_create(legacy, command):
    rows = [dict(source=PROJECT, destination=PROJECT, rw=True)]
    return legacy.create_argv(ISOLATION, run=RUN, mounts=rows, uid=0, gid=0, command=command)


def _core_surface(surface, value):
    if surface == "executable":
        return _exec([value])
    if surface == "image":
        return core.image_inspect_argv("docker", value)
    if surface == "tag":
        return core.build_image_argv(
            "podman", context=SOURCE, containerfile=SOURCE + "/Containerfile", tag=value)
    raise AssertionError(surface)


def _legacy_surface(legacy, surface, value):
    if surface == "executable":
        return _legacy_exec(legacy, [value])
    if surface == "image":
        return legacy.image_inspect_argv("docker", value)
    if surface == "tag":
        return legacy.build_image_argv(
            "podman", context=SOURCE, containerfile=SOURCE + "/Containerfile", tag=value)
    raise AssertionError(surface)


def _utf8_size(command):
    return sum(len(word.encode("utf-8")) for word in command)


def _utf8_command(extra_bytes):
    """ASCII command of exactly _BYTE_BUDGET + extra_bytes, inside the other caps."""
    tail = 16383 + extra_bytes
    command = ["x"] + ["a" * 16384] * 63 + ["b" * tail]
    return command


def _assert_kept(surface, argv, value):
    if surface == "image":
        assert argv == ["docker", "image", "inspect", value]
    elif surface == "tag":
        assert argv == ["podman", "build", "--file", SOURCE + "/Containerfile", "--tag", value, SOURCE]
    else:
        assert argv[0] == "docker" and argv[1] == "exec" and argv[-1] == value
    if "\n" in value and value.strip("\n"):
        for part in value.split("\n"):
            assert part not in argv


def _assert_core_refusal(call, code, payload):
    with pytest.raises(mounts.IsolationRefusal, match="^" + code + "$") as caught:
        call()
    refusal = caught.value
    assert refusal.args == (code,)
    assert refusal.code == code
    assert str(refusal) == code
    assert refusal.message == mounts.REFUSALS[code]
    if len(payload) >= 16:
        assert payload not in refusal.message
        assert payload not in str(refusal)
    return refusal


def _refuse_command(command, code):
    snapshot = list(command)
    _assert_core_refusal(lambda: _exec(command), code, snapshot[-1] if snapshot else "")
    assert list(command) == snapshot


def _command_outcome(command):
    snapshot = list(command)
    try:
        argv = _exec(command)
    except mounts.IsolationRefusal as exc:
        if list(command) != snapshot or exc.message != mounts.REFUSALS[exc.code] or str(exc) != exc.code:
            return "bad"
        if len(snapshot[-1]) >= 16 and snapshot[-1] in exc.message:
            return "echo"
        return exc.code
    if list(command) != snapshot or argv[-len(snapshot):] != snapshot:
        return "bad"
    return "ok"


def test_command_word_count_bound():
    """Invariant: core accepts 4096 command words and refuses 4097 with isolation_command.

    The count is applied before the per-word document cap. Both public command
    entry points share it. A refusal leaves the caller unchanged, repeats the
    same code, and a later valid command still succeeds. Concurrent calls stay isolated.
    """
    inside = ["cmd"] + ["w"] * 4095
    outside = inside + ["w"]
    mixed = inside + ["b" * 16385]
    assert len(inside) == 4096 and len(outside) == 4097 and len(mixed) == 4097
    assert _utf8_size(outside) < _BYTE_BUDGET
    assert mounts.MAX_DOCUMENT_BYTES == _BYTE_BUDGET

    assert _exec(inside)[-4096:] == inside
    assert _exec(tuple(inside))[-4096:] == inside
    assert _create_command(inside)[-4096:] == inside
    for command in (outside, tuple(outside), mixed):
        _refuse_command(command, "isolation_command")
        _refuse_command(command, "isolation_command")
    _assert_core_refusal(lambda: _create_command(outside), "isolation_command", "w")
    assert _create_command(None)[-2:] == ["/bin/sleep", "infinity"]
    assert _exec(["cmd"])[-1] == "cmd"
    assert inside == ["cmd"] + ["w"] * 4095

    samples = [inside, outside, mixed, tuple(inside)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(_command_outcome, samples * 2)) == [
            "ok", "isolation_command", "isolation_command", "ok"] * 2


def test_command_word_count_legacy_oracle(legacy):
    """Legacy has no word cap. Inside 4096, both builders return the same argv."""
    inside = ["cmd"] + ["w"] * 4095
    outside = inside + ["w"]
    assert _exec(inside) == _legacy_exec(legacy, inside)
    assert _exec(tuple(inside)) == _legacy_exec(legacy, tuple(inside))
    assert _create_command(inside) == _legacy_create(legacy, inside)
    assert _legacy_exec(legacy, outside)[-len(outside):] == outside
    assert _legacy_create(legacy, outside)[-len(outside):] == outside
    _refuse_command(outside, "isolation_command")


def test_command_executable_length_bound():
    """Invariant: the executable is at most 4096 characters, then the shared 16384 string cap.

    Lengths 4097 through 16384 refuse as isolation_command. Length 16385 hits the
    document string cap first and refuses as document_size. The caller is unchanged,
    the refusal repeats, and a later valid command succeeds.
    """
    inside = ["a" * 4096]
    outside = ["a" * 4097]
    at_string_cap = ["a" * 16384]
    past_string_cap = ["a" * 16385]
    assert _exec(inside)[-1] == inside[0]
    assert _create_command(inside)[-1] == inside[0]
    for command, code in ((outside, "isolation_command"), (at_string_cap, "isolation_command"),
                          (past_string_cap, "document_size")):
        _refuse_command(command, code)
        _refuse_command(command, code)
    _assert_core_refusal(lambda: _create_command(outside), "isolation_command", outside[0])
    assert _exec(["cmd"])[-1] == "cmd"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(_command_outcome, [inside, outside, past_string_cap] * 2)) == [
            "ok", "isolation_command", "document_size"] * 2


def test_command_executable_length_legacy_oracle(legacy):
    """Legacy text() also caps the executable at 4096. The argv matches on the inside edge."""
    inside = ["a" * 4096]
    assert _exec(inside) == _legacy_exec(legacy, inside)
    assert _create_command(inside) == _legacy_create(legacy, inside)
    for word in ("a" * 4097, "a" * 16384, "a" * 16385):
        with pytest.raises(ValueError, match="^invalid command executable$") as caught:
            _legacy_exec(legacy, [word])
        assert word not in str(caught.value)


def test_command_other_word_length_bound():
    """Invariant: a non-executable word may pass 4096 characters and stops at 16384.

    16384 is accepted. 16385 is document_size, including when that word is not the
    executable. The refusal does not echo the word, repeats, and a later command succeeds.
    """
    inside = ["cmd", "b" * 16384]
    outside = ["cmd", "b" * 16385]
    past_executable = ["cmd", "c" * 4097]
    assert len(inside[1]) == 16384 and len(outside[1]) == 16385
    assert _exec(inside)[-2:] == inside
    assert _exec(past_executable)[-2:] == past_executable
    assert _create_command(inside)[-2:] == inside
    _refuse_command(outside, "document_size")
    _refuse_command(outside, "document_size")
    _assert_core_refusal(lambda: _create_command(outside), "document_size", outside[1])
    assert outside[1] == "b" * 16385
    assert _exec(["cmd", "ok"])[-2:] == ["cmd", "ok"]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(_command_outcome, [inside, outside, past_executable] * 2)) == [
            "ok", "document_size", "ok"] * 2


def test_command_other_word_length_legacy_oracle(legacy):
    """Legacy accepts a 16385-character trailing word and matches core inside that cap."""
    inside = ["cmd", "b" * 16384]
    outside = ["cmd", "b" * 16385]
    past_executable = ["cmd", "c" * 4097]
    assert _exec(inside) == _legacy_exec(legacy, inside)
    assert _exec(past_executable) == _legacy_exec(legacy, past_executable)
    assert _create_command(inside) == _legacy_create(legacy, inside)
    assert _legacy_exec(legacy, outside)[-2:] == outside
    assert _legacy_create(legacy, outside)[-2:] == outside
    _refuse_command(outside, "document_size")
    with pytest.raises(ValueError, match="^invalid command executable$") as caught:
        _legacy_exec(legacy, ["b" * 16385])
    assert "b" * 16 not in str(caught.value)


def test_command_utf8_budget():
    """Invariant: command strings share a 1 MiB UTF-8 budget, counted in bytes.

    An ASCII command of exactly 1048576 bytes is accepted. One more ASCII byte is
    document_size. Widening one character to U+00A0 keeps the character count and
    still refuses, so the budget is bytes. The caller is unchanged and a later
    command succeeds. Concurrent inside and outside calls stay isolated.
    """
    assert mounts.MAX_DOCUMENT_BYTES == _BYTE_BUDGET
    inside = _utf8_command(0)
    outside = _utf8_command(1)
    widened = list(inside)
    widened[-1] = "\u00a0" + inside[-1][1:]
    assert _utf8_size(inside) == _BYTE_BUDGET
    assert _utf8_size(outside) == _BYTE_BUDGET + 1
    assert sum(len(word) for word in widened) == _BYTE_BUDGET
    assert _utf8_size(widened) == _BYTE_BUDGET + 1
    assert len(inside) <= 4096 and max(len(word) for word in outside) <= 16384
    assert _exec(inside)[-len(inside):] == inside
    owned = list(outside)
    _refuse_command(owned, "document_size")
    _refuse_command(owned, "document_size")
    _refuse_command(widened, "document_size")
    assert owned == outside
    assert _exec(["cmd"])[-1] == "cmd"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(_command_outcome, [inside, outside, widened])) == [
            "ok", "document_size", "document_size"]


def test_command_utf8_budget_legacy_oracle(legacy):
    """Legacy has no aggregate byte budget. Inside the budget the argv matches."""
    inside = _utf8_command(0)
    outside = _utf8_command(1)
    widened = list(inside)
    widened[-1] = "\u00a0" + inside[-1][1:]
    assert _exec(inside) == _legacy_exec(legacy, inside)
    assert _legacy_exec(legacy, outside)[-len(outside):] == outside
    assert _legacy_exec(legacy, widened)[-len(widened):] == widened
    _refuse_command(outside, "document_size")


def test_stop_timeout_bit_length_bound():
    """Invariant: a positive stop timeout may use at most 128 bits.

    (2**128) - 1 is accepted and rendered as one argv word. 2**128 is stop_timeout.
    The refusal does not echo the integer, repeats, and a later timeout succeeds.
    The existing broader refusal cases stay in test_argv_refusals.
    """
    inside = (1 << 128) - 1
    outside = 1 << 128
    assert inside.bit_length() == 128 and outside.bit_length() == 129
    argv = core.stop_argv("docker", RUN, timeout=inside)
    assert argv[argv.index("--time") + 1] == str(inside)
    assert "\n" not in argv[argv.index("--time") + 1]
    _assert_core_refusal(lambda: core.stop_argv("docker", RUN, timeout=outside), "stop_timeout", str(outside))
    _assert_core_refusal(lambda: core.stop_argv("docker", RUN, timeout=outside), "stop_timeout", str(outside))
    retried = core.stop_argv("docker", RUN, timeout=10)
    assert retried[retried.index("--time") + 1] == "10"
    again = core.stop_argv("docker", RUN, timeout=inside)
    assert again == argv

    def once(timeout):
        try:
            built = core.stop_argv("docker", RUN, timeout=timeout)
        except mounts.IsolationRefusal as exc:
            if str(timeout) in exc.message or exc.message != mounts.REFUSALS[exc.code]:
                return "echo"
            return exc.code
        text = built[built.index("--time") + 1]
        return "ok" if text == str(timeout) and "\n" not in text else "bad"

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, [inside, outside, 10] * 2)) == ["ok", "stop_timeout", "ok"] * 2


def test_stop_timeout_bit_length_legacy_oracle(legacy):
    """Legacy accepts any positive int. Inside 128 bits the argv matches."""
    inside = (1 << 128) - 1
    outside = 1 << 128
    assert core.stop_argv("docker", RUN, timeout=inside) == legacy.stop_argv("docker", RUN, timeout=inside)
    legacy_argv = legacy.stop_argv("docker", RUN, timeout=outside)
    assert legacy_argv[legacy_argv.index("--time") + 1] == str(outside)
    assert "\n" not in legacy_argv[legacy_argv.index("--time") + 1]
    _assert_core_refusal(lambda: core.stop_argv("docker", RUN, timeout=outside), "stop_timeout", str(outside))


@pytest.mark.parametrize(
    ("surface", "kind", "argument", "core_ok", "_legacy_ok", "executable_code"), _operand_cases())
def test_operand_domain_boundary(surface, kind, argument, core_ok, _legacy_ok, executable_code):
    """Invariant: executable, image and tag use the ordinary-scalar operand domain.

    Just inside the scalar, length and dash edges the value is one argv word.
    Just outside, core refuses with that surface's code and does not join a
    newline into one line. A surrogate executable is document_invalid because the
    command document scan runs first. The caller list is unchanged and a refusal
    retries with an ordinary value.
    """
    value = _operand_text(kind, argument)
    command = [value]
    snapshot = list(command)

    def call():
        if surface == "executable":
            return _exec(command)
        return _core_surface(surface, value)

    if core_ok:
        _assert_kept(surface, call(), value)
    else:
        _assert_core_refusal(call, _operand_refusal_code(surface, executable_code), value)
        _assert_kept(surface, _core_surface(surface, "cmd"), "cmd")
    if surface == "executable":
        assert command == snapshot


@pytest.mark.parametrize(
    ("surface", "kind", "argument", "core_ok", "legacy_ok", "executable_code"), _operand_cases())
def test_operand_domain_legacy_oracle(legacy, surface, kind, argument, core_ok, legacy_ok, executable_code):
    """Legacy keeps length, NUL and leading-dash rules and accepts the stricter scalar outsides."""
    value = _operand_text(kind, argument)
    if core_ok:
        assert legacy_ok
        assert _core_surface(surface, value) == _legacy_surface(legacy, surface, value)
        return
    _assert_core_refusal(
        lambda: _core_surface(surface, value), _operand_refusal_code(surface, executable_code), value)
    if legacy_ok:
        _assert_kept(surface, _legacy_surface(legacy, surface, value), value)
        return
    with pytest.raises(ValueError) as caught:
        _legacy_surface(legacy, surface, value)
    assert str(caught.value) in _LEGACY_OPERAND_REFUSALS[surface]
    if len(value) >= 16:
        assert value not in str(caught.value)


def test_operand_domain_is_stable_under_concurrency():
    """Concurrent operand refusals and successes stay on their own codes."""
    cases = (
        ("executable", "\x20", "ok"),
        ("executable", "\x1f", "isolation_command"),
        ("executable", chr(0xD800), "document_invalid"),
        ("image", "\x7f", "isolation_image"),
        ("image", "ok\nmore", "isolation_image"),
        ("tag", "a" * 4096, "ok"),
        ("tag", "-a", "image_tag"),
        ("tag", "a" * 4097, "image_tag"),
    )

    def once(item):
        surface, value, expected = item
        try:
            argv = _core_surface(surface, value)
        except mounts.IsolationRefusal as exc:
            if exc.message != mounts.REFUSALS[exc.code] or (len(value) >= 16 and value in exc.message):
                return "echo"
            return exc.code
        if surface == "tag":
            kept = argv[argv.index("--tag") + 1] == value
        elif surface == "image":
            kept = argv == ["docker", "image", "inspect", value]
        else:
            kept = argv[-1] == value
        return "ok" if kept else "bad"

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, cases * 2)) == [item[2] for item in cases] * 2


def _trailing_words():
    return [(name, _operand_text(kind, argument), code, legacy_executable)
            for name, kind, argument, code, legacy_executable in _TRAILING_SPECS]


def test_trailing_argv_words_skip_operand_limits():
    """Invariant: trailing words are not executable operands.

    A control, a newline, a leading dash, or a word longer than 4096 stays one
    trailing argv element. The same text in the executable position is refused
    and is not joined into a single line. A surrogate in any word remains
    document_invalid, and NUL in any word remains isolation_command.
    """
    for _name, word, code, _legacy_executable in _trailing_words():
        command = ["cmd", word]
        snapshot = list(command)
        argv = _exec(command)
        assert argv[-2:] == command and command == snapshot
        if "\n" in word and word.strip("\n"):
            for part in word.split("\n"):
                assert part not in argv
        _refuse_command([word], code)
        assert _exec(["cmd", "ok"])[-2:] == ["cmd", "ok"]
    for command in (["\ud800"], ["cmd", "\ud800"], ["cmd", "\udfff"]):
        _refuse_command(command, "document_invalid")
        _refuse_command(command, "document_invalid")
    _refuse_command(["cmd", "\x00"], "isolation_command")

    def once(word):
        command = ["cmd", word]
        argv = _exec(command)
        return "ok" if argv[-1] == word and list(command) == ["cmd", word] else "bad"

    words = ["\x1f", "-a", "ok\nmore", "a" * 4097]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, words * 2)) == ["ok"] * 8


def test_trailing_argv_words_legacy_oracle(legacy):
    """Legacy matches core for accepted trailing words and still accepts scalar outsides as the executable."""
    for _name, word, code, legacy_executable in _trailing_words():
        command = ["cmd", word]
        assert _exec(command) == _legacy_exec(legacy, command)
        _refuse_command([word], code)
        if legacy_executable:
            assert _legacy_exec(legacy, [word])[-1] == word
            continue
        with pytest.raises(ValueError) as caught:
            _legacy_exec(legacy, [word])
        assert str(caught.value) in _LEGACY_OPERAND_REFUSALS["executable"]
        if len(word) >= 16:
            assert word not in str(caught.value)
    for command in (["\ud800"], ["cmd", "\ud800"], ["cmd", "\udfff"]):
        assert _legacy_exec(legacy, command)[-len(command):] == list(command)
        _refuse_command(command, "document_invalid")
    with pytest.raises(ValueError, match="^invalid command argument$"):
        _legacy_exec(legacy, ["cmd", "\x00"])
    _refuse_command(["cmd", "\x00"], "isolation_command")
