"""Packaged role policy, typed refusals and legacy success/refusal parity."""
import ast
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from io import BytesIO
import inspect
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from aegis_core import team_roles as roles
from aegis_core.team_mailbox_primitives import RoleTables
from tools import hierarchy_roles as legacy


ROOT = Path(__file__).resolve().parents[3]
RAW = (ROOT / "tools/hierarchy_templates/role-registry.json").read_bytes()
BASE = json.loads(RAW)


def refused(reason, call, *args):
    with pytest.raises(roles.RoleRefusal) as caught:
        call(*args)
    error = caught.value
    assert error.reason == reason
    assert error.code == 1
    assert error.status == "refused"
    assert error.next_action
    assert error.as_dict() == {"reason": reason, "code": 1, "status": "refused",
                               "next_action": error.next_action}
    assert "private-marker" not in str(error) + repr(error.as_dict())


def legacy_cases():
    """Reuse every documented refusal without importing the integration harness."""
    tree = ast.parse((ROOT / "tests/integration/test_hierarchy_role_registry.py").read_text())
    cases = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "parametrize" and len(node.args) > 1
                and isinstance(node.args[0], ast.Constant) and node.args[0].value == "change,error"):
            cases.extend(eval(compile(ast.Expression(node.args[1]), "<tracked legacy cases>", "eval")))
    return cases


@pytest.mark.parametrize("change,message", legacy_cases(), ids=lambda value: None if callable(value) else "refusal")
def test_legacy_refusal_set_and_valid_retry(change, message):
    value = deepcopy(BASE)
    change(value)
    before = deepcopy(value)
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        legacy.validate(deepcopy(value))
    with pytest.raises(roles.RoleRefusal) as caught:
        roles.validate(value)
    assert caught.value.code == 1 and caught.value.reason and caught.value.next_action
    assert value == before
    assert roles.validate(deepcopy(BASE)) == BASE


def test_package_bytes_and_success_helpers_match_legacy():
    assert roles.resources.files("aegis_core.team_templates").joinpath("role-registry.json").read_bytes() == RAW
    assert roles.registry() == legacy.registry() == BASE
    for constant in ("SCHEMA", "VOCABULARY", "ENDPOINT_ROLES", "LANE_KINDS", "VERTICAL_ROUTES",
                     "SOURCE_VIEW_TOOLS", "WORKSPACE_TOOLS", "READ_TOOLS", "WRITE_TOOLS"):
        assert getattr(roles, constant) == getattr(legacy, constant)
    for name, entry in BASE["roles"].items():
        for helper in ("fixed_model_profile", "writer", "file_tools", "workspace_tools", "takes_board", "source_views"):
            assert getattr(roles, helper)(entry) == getattr(legacy, helper)(entry)
        if entry["endpoint"] is not None:
            for helper in ("lifecycle_tools", "decision_tools"):
                assert getattr(roles, helper)(entry) == getattr(legacy, helper)(entry)
            endpoint = "alpha/" + entry["endpoint"]["role"]
            kind = entry["endpoint"].get("lane_kind")
            if kind:
                endpoint += "/worker"
            assert roles.role_name(endpoint, kind) == legacy.role_name(endpoint, kind) == name
            assert roles.role(endpoint, kind) == legacy.role(endpoint, kind)
            for helper, extra in (("require_board", ()), ("require_source_views", ()),
                                  ("require_file_tools", (roles.file_tools(entry),))):
                try:
                    expected = getattr(legacy, helper)(endpoint, kind, *extra)
                except ValueError:
                    with pytest.raises(roles.RoleRefusal):
                        getattr(roles, helper)(endpoint, kind, *extra)
                else:
                    assert getattr(roles, helper)(endpoint, kind, *extra) == expected
    for helper in ("session_roles", "reader_shell_roles", "team_kinds"):
        assert getattr(roles, helper)() == getattr(legacy, helper)()


def test_tables_match_legacy_policy_and_are_immutable():
    value = deepcopy(BASE)
    tables = roles.role_tables(value)
    expected = RoleTables(writes={name: entry["writes"] for name, entry in legacy.registry()["roles"].items()},
                          independent={entry["endpoint"].get("lane_kind", entry["endpoint"]["role"])
                                       for entry in BASE["roles"].values()
                                       if entry["endpoint"] and entry["independence"]["separate_session"]})
    assert tables == expected
    value["roles"]["root"]["writes"].append("source")
    assert tables == expected


@pytest.mark.parametrize("change,reason", [
    (lambda r: r.update(schema="private-marker"), "unsupported_schema"),
    (lambda r: r.update(**{"private-marker": 1}), "unknown_key"),
    (lambda r: r["roles"]["router"]["calls"].append("private-marker"), "unknown_action"),
    (lambda r: r["roles"].update(duplicate=deepcopy(r["roles"]["router"])), "duplicate_role"),
    (lambda r: r["roles"]["root"]["reads"].append({}), "invalid_registry"),
    (lambda r: r["roles"]["root"].update(kind=[]), "invalid_registry"),
    (lambda r: r.update(routes=[[{}, []]]), "invalid_registry"),
    (lambda r: r["roles"]["root"].pop("title"), "invalid_registry"),
])
def test_invalid_registry_cannot_build_tables(change, reason, monkeypatch):
    value = deepcopy(BASE)
    change(value)
    def never_build(**kwargs):
        raise AssertionError("table built before validation")
    original = roles.RoleTables
    monkeypatch.setattr(roles, "RoleTables", never_build)
    refused(reason, roles.role_tables, value)
    monkeypatch.setattr(roles, "RoleTables", original)
    assert roles.role_tables(BASE).endpoint_roles == RoleTables().endpoint_roles


@pytest.mark.parametrize("raw,reason", [
    (b'{"schema":1,"schema":2}', "duplicate_key"),
    (b'{"roles":{"root":{},"root":{}}}', "duplicate_key"),
    (b"{", "invalid_registry"), (b"\xff", "invalid_registry"),
    (b"[" * 33, "invalid_registry"),
    (b" " * 262145, "too_large"),
    ("\u00e9" * 262144, "too_large"),
], ids=["duplicate-schema", "duplicate-role", "incomplete", "utf8", "depth", "bytes-limit", "text-limit"])
def test_raw_loading_refusals_and_retry(raw, reason):
    refused(reason, roles.load_registry, raw)
    assert roles.load_registry(RAW) == BASE


def test_size_is_checked_before_parsing(monkeypatch):
    def no_parse(*args, **kwargs):
        raise AssertionError("oversize input parsed")
    monkeypatch.setattr(roles, "json", SimpleNamespace(loads=no_parse))
    refused("too_large", roles.load_registry, b" " * 262145)


def test_large_file_tool_selection_preserves_legacy_success():
    names = ["Read"] * 10001
    assert legacy.require_file_tools("alpha/root", None, names) is None
    assert roles.require_file_tools("alpha/root", None, names) is None


@pytest.mark.parametrize("endpoint,kind", [("private-marker", None), ("alpha/unknown", None),
                                         ("alpha/lane/worker", "private-marker"), (None, None),
                                         ("a" * 262145, None), ("alpha/lane/worker", [])],
                         ids=["malformed", "unknown-role", "unknown-kind", "null", "size", "kind-type"])
def test_unknown_endpoint_and_kind_are_typed(endpoint, kind):
    refused("unknown_endpoint", roles.role_name, endpoint, kind)
    assert roles.role_name("alpha/root") == "root"


@pytest.mark.parametrize("kind", [[], {}, "x" * 300], ids=["list", "dict", "long-string"])
def test_non_lane_kind_is_ignored_as_in_legacy(kind):
    assert roles.role_name("alpha/root", kind) == legacy.role_name("alpha/root", kind) == "root"


def mailbox(bindings):
    endpoints = {"alpha/lane/worker": {"kind": "implementer"}, "alpha/lane/review": {"kind": "reviewer"},
                 "alpha/root": {}, "beta/root": {}}
    return SimpleNamespace(manifest={"endpoints": endpoints}, endpoint=endpoints.__getitem__,
                           bindings=lambda name: bindings.get(name, []))


def test_independence_refusal_no_writes_retry_and_latest_binding():
    bindings = {"alpha/lane/worker": [{"host": "host", "session": "private-marker"}]}
    box = mailbox(bindings)
    before = deepcopy(bindings)
    with pytest.raises(ValueError):
        legacy.require_independent_session(box, "alpha/lane/review", "host", "private-marker")
    refused("independent_session", roles.require_independent_session,
            box, "alpha/lane/review", "host", "private-marker")
    assert bindings == before
    assert roles.require_independent_session(box, "alpha/lane/review", "host", "fresh") is None
    bindings["alpha/lane/worker"].append({"host": "host", "session": "fresh"})
    assert roles.require_independent_session(box, "alpha/lane/review", "host", "private-marker") is None
    assert roles.require_independent_session(box, "alpha/lane/review", "other-host", "fresh") is None
    bindings.clear()
    bindings["alpha/root"] = [{"host": "host", "session": "same"}]
    assert roles.require_independent_session(box, "beta/root", "host", "same") is None


def test_concurrent_callers_get_isolated_policy_and_tables():
    def read_policy(index):
        value = roles.registry()
        value["roles"]["root"]["reads"].append({})
        refused("invalid_registry", roles.validate, value)
        return roles.role_tables(), roles.role_name("alpha/root")
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(read_policy, range(12)))
    assert all(table == roles.role_tables() and name == "root" for table, name in results)
    assert roles.registry() == BASE


@pytest.mark.parametrize("failure,reason", [(FileNotFoundError, "missing_registry"), (OSError, "registry_io")])
def test_package_read_failure_is_typed_and_retry_succeeds(monkeypatch, failure, reason):
    class Resource:
        def joinpath(self, name):
            assert name == "role-registry.json"
            return self
        def open(self, mode):
            raise failure("private-marker")
    original = roles.resources
    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=lambda name: Resource()))
    refused(reason, roles.registry)
    monkeypatch.setattr(roles, "resources", original)
    assert roles.registry() == BASE


def test_resource_stream_is_bounded_and_closed_on_refusal(monkeypatch):
    stream = BytesIO(b" " * 262145)
    class Resource:
        def joinpath(self, name):
            return self
        def open(self, mode):
            assert mode == "rb"
            return stream
    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=lambda name: Resource()))
    refused("too_large", roles.registry)
    assert stream.closed


def test_resource_read_error_closes_stream_and_allows_retry(monkeypatch):
    class FailingStream(BytesIO):
        def read(self, limit):
            raise OSError("private-marker")
    stream = FailingStream()
    resource = SimpleNamespace(open=lambda mode: stream)
    package = SimpleNamespace(joinpath=lambda name: resource)
    original = roles.resources
    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=lambda name: package))
    refused("registry_io", roles.registry)
    monkeypatch.setattr(roles, "resources", original)
    assert stream.closed
    assert roles.registry() == BASE


def test_mailbox_observation_error_is_typed_and_valid_retry_succeeds():
    box = mailbox({})
    def unavailable(name):
        raise OSError("private-marker")
    box.bindings = unavailable
    refused("policy_io", roles.require_independent_session, box, "alpha/root", "host", "session")
    assert roles.require_independent_session(mailbox({}), "alpha/root", "host", "session") is None


@pytest.mark.parametrize("helper,args", [("file_tools", ({},)), ("fixed_model_profile", ({},)),
    ("require_file_tools", ("alpha/root", None, ["private-marker"])),
    ("require_board", ("alpha/lane/review", None)),
    ("require_source_views", ("alpha/lane/work", "implementer"))])
def test_helper_failures_are_typed(helper, args):
    with pytest.raises(roles.RoleRefusal) as caught:
        getattr(roles, helper)(*args)
    assert caught.value.code == 1 and caught.value.next_action
    assert "private-marker" not in str(caught.value)


def public_operations():
    return {name: function for name, function in vars(roles).items()
            if not name.startswith("_") and inspect.isfunction(function)
            and function.__module__ == roles.__name__}


def operation_inputs(function):
    """Valid schema fixtures keyed by parameter, never a list of operations."""
    entry = deepcopy(BASE["roles"]["root"])
    samples = {"condition": True, "reason": "invalid_registry", "required": set(BASE),
               "optional": (), "value": BASE, "label": "field", "limit": 4096,
               "raw": RAW, "registry": BASE, "entry": entry, "role": entry, "name": "root",
               "group": "reads", "allowed": {key: set(entry[key]) for key in roles.VOCABULARY},
               "endpoint": "alpha/lane/worker", "kind": "implementer", "names": ["Read"],
               "mailbox": mailbox({}), "host": "host", "session": "session"}
    if function.__name__ == "text":
        samples["value"] = "text"
    if function.__name__ == "require_source_views":
        samples["kind"] = "reviewer"
    parameters = inspect.signature(function).parameters
    assert parameters.keys() <= samples.keys(), "a new public input needs a valid fixture"
    return {name: samples[name] for name in parameters}


def wrong_type_cases():
    constructors = (type(None), bool, int, float, str, bytes, list, dict, tuple, set, frozenset, object)
    collections = {list, tuple, set, frozenset}
    for name, function in public_operations().items():
        inputs = operation_inputs(function)
        if not inputs:
            yield pytest.param(name, "unexpected_input", object(), inputs, id=name + "-no-input")
        for parameter, valid in inputs.items():
            accepted = {type(valid)}
            if parameter in {"required", "optional", "names"}:
                accepted = collections
            elif parameter == "raw":
                accepted = {str, bytes}
            elif parameter == "kind" or name == "role_tables" and parameter == "value":
                accepted.add(type(None))
            for constructor in constructors:
                if constructor not in accepted:
                    yield pytest.param(name, parameter, constructor(), inputs,
                                       id=name + "-" + parameter + "-" + constructor.__name__)


@pytest.mark.parametrize("name,parameter,wrong,inputs", wrong_type_cases())
def test_every_public_operation_refuses_wrong_input_types(name, parameter, wrong, inputs):
    operation = public_operations()[name]
    before = roles.registry()
    with pytest.raises(roles.RoleRefusal) as caught:
        operation(**{**inputs, parameter: wrong})
    assert caught.value.code == 1 and caught.value.status == "refused"
    assert caught.value.next_action and caught.value.reason
    assert "private-marker" not in str(caught.value) + repr(caught.value.as_dict())
    assert roles.registry() == before
    operation(**inputs)


def registry_type_cases():
    """Generate each nested JSON field/element replacement from the real registry."""
    def paths(value, path=()):
        if type(value) is dict:
            for key, child in value.items():
                yield path + (key,), child
                yield from paths(child, path + (key,))
        elif type(value) is list:
            for index, child in enumerate(value):
                yield path + (index,), child
                yield from paths(child, path + (index,))
    for index, (path, original) in enumerate(paths(BASE)):
        for constructor in (type(None), bool, int, float, str, list, dict):
            if constructor is not type(original):
                yield pytest.param(path, constructor(), id=str(index) + "-" + constructor.__name__)


@pytest.mark.parametrize("path,wrong", registry_type_cases())
def test_generated_registry_type_mutations_preserve_refusal_decisions(path, wrong):
    value = deepcopy(BASE)
    parent = value
    for component in path[:-1]:
        parent = parent[component]
    parent[path[-1]] = wrong
    try:
        expected = legacy.validate(deepcopy(value))
    except (ValueError, TypeError, KeyError, AttributeError):
        with pytest.raises(roles.RoleRefusal) as caught:
            roles.validate(value)
        assert caught.value.code == 1 and caught.value.next_action
    else:
        assert roles.validate(value) == expected


def invalid_lane_kinds():
    non_lanes = {name for name, entry in BASE["roles"].items()
                 if entry["endpoint"] is None or entry["endpoint"]["role"] != "lane"}
    return sorted(non_lanes | {name + "-unregistered" for name in BASE["roles"]})


@pytest.mark.parametrize("kind", invalid_lane_kinds())
def test_lane_kind_refuses_every_non_lane_role_and_unknown_name(kind):
    refused("unknown_endpoint", roles.role_name, "alpha/lane/worker", kind)
    assert roles.role_name("alpha/lane/worker", "implementer") == "implementer"


@pytest.mark.parametrize("kind", invalid_lane_kinds())
def test_invalid_lane_kind_refuses_before_registry_read(kind, monkeypatch):
    def never_read(package):
        raise AssertionError("invalid lane kind reached the registry reader")
    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=never_read))
    refused("unknown_endpoint", roles.role_name, "alpha/lane/worker", kind)


def registry_operations():
    """Discover every public registry consumer through the module's call graph."""
    tree = ast.parse((ROOT / "aegis_core/team_roles.py").read_text())
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    calls = {name: {node.func.id for node in ast.walk(function)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
             for name, function in functions.items()}
    readers = {"registry"}
    while True:
        expanded = readers | {name for name in functions if calls[name] & readers}
        if expanded == readers:
            break
        readers = expanded
    return sorted(readers & public_operations().keys())


def snapshot_counters(monkeypatch, raw=RAW):
    counts = {"reads": 0, "validations": 0}
    class Resource:
        def joinpath(self, name):
            assert name == "role-registry.json"
            return self
        def open(self, mode):
            assert mode == "rb"
            counts["reads"] += 1
            return BytesIO(raw)
    validate = roles.validate
    def counted(value):
        counts["validations"] += 1
        return validate(value)
    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=lambda package: Resource()))
    monkeypatch.setattr(roles, "validate", counted)
    return counts


def same_role_mailbox():
    endpoints = {"alpha/lane/worker": {"kind": "implementer"},
                 "alpha/lane/peer": {"kind": "implementer"},
                 "beta/lane/peer": {"kind": "implementer"}}
    return SimpleNamespace(manifest={"endpoints": endpoints}, endpoint=endpoints.__getitem__,
                           bindings=lambda name: [{"host": "host", "session": "session"}])


@pytest.mark.parametrize("name", registry_operations())
def test_registry_operations_read_and_validate_exactly_once(name, monkeypatch):
    operation = public_operations()[name]
    inputs = operation_inputs(operation)
    if name == "role_tables":
        inputs["value"] = None
    if "mailbox" in inputs:
        inputs["mailbox"] = same_role_mailbox()
    counts = snapshot_counters(monkeypatch)
    operation(**inputs)
    assert counts == {"reads": 1, "validations": 1}


def test_explicit_table_registry_validates_once_without_package_io(monkeypatch):
    counts = snapshot_counters(monkeypatch)
    assert roles.role_tables(BASE) == RoleTables(writes={name: entry["writes"]
                                                       for name, entry in BASE["roles"].items()})
    assert counts == {"reads": 0, "validations": 1}


def test_composite_failure_keeps_one_snapshot_and_valid_retry_succeeds(monkeypatch):
    counts = snapshot_counters(monkeypatch)
    refused("not_permitted", roles.require_file_tools, "alpha/root", None, ["private-marker"])
    assert counts == {"reads": 1, "validations": 1}
    assert roles.require_file_tools("alpha/root", None, ["Read"]) is None
    assert counts == {"reads": 2, "validations": 2}


def test_independence_snapshot_is_deeply_read_only(monkeypatch):
    observed = []
    validate = roles.validate
    def observe(value):
        result = validate(value)
        observed.append(result)
        return result
    monkeypatch.setattr(roles, "validate", observe)
    endpoints = {"alpha/lane/worker": {"kind": "implementer"},
                 "alpha/lane/peer": {"kind": "integrator"}}
    def bindings(name):
        for value in observed:
            value["roles"]["implementer"]["independence"]["separate_session"] = True
        return [{"host": "host", "session": "session"}]
    box = SimpleNamespace(manifest={"endpoints": endpoints}, endpoint=endpoints.__getitem__, bindings=bindings)
    assert roles.require_independent_session(box, "alpha/lane/worker", "host", "session") is None
    assert len(observed) == 1


def test_successive_operations_see_fresh_registry_without_shared_cache(monkeypatch):
    first = deepcopy(BASE)
    first["roles"]["root"]["title"] = "first"
    second = deepcopy(BASE)
    second["roles"]["root"]["title"] = "second"
    second["roles"]["renamed-root"] = second["roles"].pop("root")
    for entry in second["roles"].values():
        for key in ("hat_of", "reports_to"):
            if entry[key] == "root":
                entry[key] = "renamed-root"
    data = iter((json.dumps(first).encode(), json.dumps(second).encode()))
    class Resource:
        def joinpath(self, name):
            return self
        def open(self, mode):
            return BytesIO(next(data))
    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=lambda package: Resource()))
    first_role = roles.role("alpha/root")
    assert first_role["title"] == "first"
    first_role["reads"].clear()
    second_role = roles.role("alpha/root")
    assert second_role["title"] == "second"
    assert second_role["reads"] == BASE["roles"]["root"]["reads"]
