"""Packaged role policy, typed refusals and legacy success/refusal parity."""
import ast
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from io import BytesIO
import inspect
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

from aegis_core import team_roles as roles
from aegis_core.team_mailbox_primitives import MailboxRefusal, RoleTables, render_mailbox_refusal
from tools import hierarchy_roles as legacy


ROOT = Path(__file__).resolve().parents[3]
RAW = (ROOT / "tools/hierarchy_templates/role-registry.json").read_bytes()
BASE = json.loads(RAW)
# Preserve the input shape of the established mailbox traversal counts.
MAILBOX_BASE = {key: BASE[key] for key in ("schema", "routes", "roles")}


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


def test_git_capabilities_match_the_adr_for_each_principal():
    status = {"team:status"}
    read = status | {"git:read"}
    own_lane = status | {"git:read-own-lane", "lane:commit-own", "lane:sync-own"}
    review = status | {"git:read-exact-head", "review:record-exact-head"}
    expected = {
        "root": read,
        "router": status | {"queue:add"},
        "orchestrator": read | {"queue:list", "queue:claim-team", "queue:release-team", "queue:done-team",
                                "lane:start-team", "lane:commit-team", "lane:sync-team", "lane:land-team",
                                "lane:resume-team", "lane:done-preview", "lane:gc-preview"},
        "reviewer": review,
        "decider": read,
        "implementer": own_lane,
        "test-author": own_lane,
        "owner": read | {"lane:start-owner", "lane:commit-owner", "lane:sync-owner", "lane:resume-owner",
                         "lane:done-preview", "lane:gc-preview", "lane:done-apply", "lane:gc-apply",
                         "git:recover", "git:prune", "git:configure", "forge:merge-review-target",
                         "forge:merge-signed-target", "git:sign-signature-target", "forge:owner-admin"},
        "watch-supervisor": status,
        "provider-bridge": status,
        "job-executor": status | {"git:read-exact-head", "job:run-exact-export", "job:write-evidence",
                                  "broker:route-git-requests"},
        "architect": read,
        "validation-operator": review | {"qualification:request-exact-tree"},
        "integrator": own_lane,
        "specialist-reviewer": review,
        "release-operator": read | {"release:open-review-or-signature-pr", "lane:land-repair-red-target",
                                    "lane:start-revert-red-target"},
        "front-door": status,
        "session-helper": status | {"git:read-parent-scope"},
        "git-custodian": read | {"git:manage-leased-worktree", "git:snapshot-private-index",
                                 "git:create-tested-commit", "git:create-queue-merge",
                                 "git:fast-forward-leased-lane-ref", "git:write-qualification-and-queue-refs",
                                 "git:write-lane-records", "git:write-operation-journal"},
        "publisher": read | {"forge:use-publisher-identity",
                             "forge:push-qualified-none-target-without-rule-changes",
                             "forge:open-qualified-draft-pr", "forge:open-release-pr",
                             "forge:cancel-superseded-run", "forge:delete-merged-lane-branch",
                             "forge:record-intent-result"},
    }
    assert set(BASE["git_capabilities"]) == expected.keys()
    legacy_policy = legacy.registry()["git_capabilities"]
    for name, grants in expected.items():
        assert set(roles.git_capabilities(name)) == grants
        assert roles.git_capabilities(name) == tuple(legacy_policy[name])


@pytest.mark.parametrize("change", [
    lambda grants: grants.update({"private-marker": []}),
    lambda grants: grants.pop("publisher"),
    lambda grants: grants.update(root={"private-marker": True}),
    lambda grants: grants.update(root=["private-marker\nsecret"]),
    lambda grants: grants.update(root=[{}]),
    lambda grants: grants.update(root=["team:status"] * 3),
    lambda grants: grants.update(root=["team:status", "team:status"]),
    lambda grants: grants.update(root=["git:fast-forward-leased-lane-ref"]),
    lambda grants: grants.update(router=["queue:claim-team"]),
    lambda grants: grants.update(implementer=["lane:commit-team"]),
    lambda grants: grants.update(orchestrator=["lane:done-apply"]),
    lambda grants: grants.update(reviewer=["git:write-qualification-and-queue-refs"]),
    lambda grants: grants.update({"session-helper": ["review:record-exact-head"]}),
    lambda grants: grants.update({"session-helper": ["lane:commit-own"]}),
    lambda grants: grants.update({"release-operator": ["forge:merge-review-target"]}),
    lambda grants: grants.update({"job-executor": ["forge:use-publisher-identity"]}),
    lambda grants: grants.update({"job-executor": ["git:write-qualification-and-queue-refs"]}),
    lambda grants: grants.update({"git-custodian": ["job:run-exact-export"]}),
    lambda grants: grants.update({"git-custodian": ["forge:use-publisher-identity"]}),
    lambda grants: grants.update(publisher=["git:fast-forward-leased-lane-ref"]),
    lambda grants: grants.update(publisher=["forge:push-qualified-none-target-with-rule-changes"]),
    lambda grants: grants.update(publisher=["forge:merge-signed-target"]),
    lambda grants: grants.update(publisher=["forge:force-push"]),
])
def test_git_capabilities_refuse_malformed_or_widened_policy_then_retry(change):
    invalid = deepcopy(BASE)
    change(invalid["git_capabilities"])
    before = deepcopy(invalid)
    refused("invalid_registry", roles.validate, invalid)
    with pytest.raises(ValueError, match="^role registry refused: invalid_registry$"):
        legacy.validate(invalid)
    assert invalid == before
    assert roles.validate(deepcopy(BASE)) == BASE
    assert legacy.validate(deepcopy(BASE)) == BASE


@pytest.mark.parametrize("registry_module", [roles, legacy], ids=["core", "legacy"])
def test_git_capabilities_isolate_concurrent_reads(registry_module):
    def attempt(index):
        exposed = registry_module.registry()["git_capabilities"]
        exposed["root"].clear()
        exposed["private-marker"] = ["git:read"]
        fresh = registry_module.registry()["git_capabilities"]
        assert fresh == BASE["git_capabilities"]
        assert roles.git_capabilities("root") == tuple(fresh["root"])
        return index

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(attempt, range(6))) == list(range(6))


@pytest.mark.parametrize("principal", ["private-marker", "root\n", "x" * 65], ids=["unknown", "newline", "oversized"])
def test_git_capabilities_refuse_bad_principal_before_resource_read(monkeypatch, principal):
    original = roles.resources

    def never_read(name):
        pytest.fail("invalid principal reached the policy reader")

    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=never_read))
    refused("not_permitted", roles.git_capabilities, principal)
    monkeypatch.setattr(roles, "resources", original)
    assert roles.git_capabilities("root") == ("team:status", "git:read")


def test_git_capabilities_legacy_data_grants_nothing_and_a_tightened_policy_stays_tight(monkeypatch):
    package = deepcopy(BASE)
    original = roles.resources

    def files(name):
        return SimpleNamespace(joinpath=lambda filename: SimpleNamespace(
            open=lambda mode: BytesIO(json.dumps(package).encode("utf-8"))))

    monkeypatch.setattr(roles, "resources", SimpleNamespace(files=files))
    package.pop("git_capabilities")
    assert roles.validate(package) == package
    refused("not_permitted", roles.git_capabilities, "root")
    package["git_capabilities"] = {**BASE["git_capabilities"], "root": []}
    assert roles.git_capabilities("root") == ()
    monkeypatch.setattr(roles, "resources", original)
    assert roles.git_capabilities("root") == ("team:status", "git:read")


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
    samples = {"condition": True, "reason": "invalid_registry", "repair": None, "required": set(BASE),
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


MISSING_FIELDS = "Restore the required registry fields and retry."
FIELD_TYPES = "Use the field types required by the role schema and retry."
ROUTE_PAIRS = "Restore the required endpoint route pairs and retry."
REGISTRY_FALLBACK = "Restore a complete registry matching the role schema and retry."
TOO_LARGE_ACTION = "Reduce the registry or input to the documented size limits and retry."
DUPLICATE_ROLE_ACTION = "Give each endpoint exactly one registry role and retry."
CLOSED_ACTIONS = {
    "invalid_registry": REGISTRY_FALLBACK,
    "unsupported_schema": "Install a registry using aegis.role-registry/v1 and retry.",
    "unknown_key": "Remove fields outside the role registry schema and retry.",
    "duplicate_key": "Remove duplicate JSON keys from the registry and retry.",
    "duplicate_role": DUPLICATE_ROLE_ACTION,
    "unknown_action": "Select actions from the closed role vocabulary and retry.",
    "unknown_endpoint": "Use a registered endpoint and its manifest lane kind and retry.",
    "independent_session": "Bind the independent role to a separate host session and retry.",
    "not_permitted": "Use a role permitted for the requested capability and retry.",
    "too_large": TOO_LARGE_ACTION,
    "missing_registry": "Restore the installed package role registry and retry.",
    "registry_io": "Check the installed package resource is readable and retry.",
    "policy_io": "Check role policy observations and retry from current trusted mailbox state.",
}


def refusal(call, *args):
    """Refuse without mutating caller input or echoing it into the envelope."""
    snapshot = deepcopy(args)
    with pytest.raises(roles.RoleRefusal) as caught:
        call(*args)
    assert args == snapshot
    error = caught.value
    assert error.code == 1 and error.status == "refused"
    assert str(error) == "role registry refused: " + error.reason
    assert set(error.as_dict()) == {"status", "reason", "code", "next_action"}
    assert error.as_dict() == {"status": "refused", "reason": error.reason, "code": 1,
                               "next_action": error.next_action}
    assert "\n" not in error.next_action
    return error


ROLE_REPAIRS = (
    ("missing-title", lambda role: role.pop("title"), "invalid_registry", MISSING_FIELDS),
    ("wrong-type", lambda role: role.update(kind=[]), "invalid_registry", FIELD_TYPES),
    ("title-type", lambda role: role.update(title=None), "invalid_registry", FIELD_TYPES),
    ("malformed-field", lambda role: role.update(kind="private-marker"), "invalid_registry", REGISTRY_FALLBACK),
    ("empty-title", lambda role: role.update(title=""), "invalid_registry", REGISTRY_FALLBACK),
    ("oversized", lambda role: role.update(title="x" * 262145), "too_large", TOO_LARGE_ACTION),
)


@pytest.mark.parametrize("reason,action", sorted(CLOSED_ACTIONS.items()))
def test_closed_reason_repairs_stay_on_the_reason_table(reason, action):
    error = roles.RoleRefusal(reason)
    assert error.reason == reason and error.code == 1 and error.status == "refused"
    assert error.next_action == action
    assert str(error) == "role registry refused: " + reason
    assert error.as_dict() == {"status": "refused", "reason": reason, "code": 1, "next_action": action}


def test_category_repair_is_selected_only_for_invalid_registry():
    error = refusal(lambda: roles.require(False, repair="missing_field"))
    assert error.reason == "invalid_registry" and error.next_action == MISSING_FIELDS
    error = refusal(lambda: roles.require(False, repair="field_type"))
    assert error.next_action == FIELD_TYPES
    error = refusal(lambda: roles.require(False, repair="routes"))
    assert error.next_action == ROUTE_PAIRS
    error = refusal(lambda: roles.require(False, repair="private-marker"))
    assert error.reason == "invalid_registry" and error.next_action == REGISTRY_FALLBACK
    assert "private-marker" not in str(error) + error.next_action + repr(error.as_dict())
    assert roles.require(True, repair=None) is None


@pytest.mark.parametrize("caller", ["validate_role", "validate", "role_tables"])
@pytest.mark.parametrize("label,mutate,reason,action", ROLE_REPAIRS, ids=[item[0] for item in ROLE_REPAIRS])
def test_role_repairs_match_across_top_level_and_nested_validation(caller, label, mutate, reason, action):
    if caller == "validate_role":
        role = deepcopy(BASE["roles"]["root"])
        mutate(role)
        error = refusal(roles.validate_role, "root", role)
        assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None
    else:
        registry = deepcopy(BASE)
        mutate(registry["roles"]["root"])
        call = roles.validate if caller == "validate" else roles.role_tables
        error = refusal(call, registry)
        assert roles.validate(deepcopy(BASE)) == BASE
    assert error.reason == reason and error.next_action == action
    assert "private-marker" not in str(error) + error.next_action + repr(error.as_dict())
    assert "x" * 64 not in error.next_action


@pytest.mark.parametrize("caller", ["validate", "role_tables"])
@pytest.mark.parametrize("label,routes,action", (
    ("not-a-list", None, ROUTE_PAIRS),
    ("short-pair", [[1]], ROUTE_PAIRS),
    ("marked-short-pair", [["private-marker"]], ROUTE_PAIRS),
    ("element-type", [[1, 2]], FIELD_TYPES),
    ("mixed-elements", [[{}, []]], FIELD_TYPES),
    ("self-pair", [["private-marker", "private-marker"]], ROUTE_PAIRS),
    ("wrong-pairs", [["front-door", "lane"]], ROUTE_PAIRS),
), ids=["not-a-list", "short-pair", "marked-short-pair", "element-type", "mixed-elements", "self-pair", "wrong-pairs"])
def test_route_repair_precedes_element_type(caller, label, routes, action):
    registry = deepcopy(BASE)
    registry["routes"] = routes
    call = roles.validate if caller == "validate" else roles.role_tables
    error = refusal(call, registry)
    assert error.reason == "invalid_registry" and error.next_action == action
    assert "private-marker" not in str(error) + error.next_action + repr(error.as_dict())
    assert "front-door" not in error.next_action
    assert roles.validate(deepcopy(BASE)) == BASE


@pytest.mark.parametrize("caller", ["validate", "role_tables"])
def test_duplicate_endpoint_keeps_its_repair(caller):
    registry = deepcopy(BASE)
    registry["roles"].update(duplicate=deepcopy(registry["roles"]["router"]))
    call = roles.validate if caller == "validate" else roles.role_tables
    error = refusal(call, registry)
    assert error.reason == "duplicate_role" and error.next_action == DUPLICATE_ROLE_ACTION
    assert "duplicate" not in error.next_action and "router" not in error.next_action
    assert roles.role_tables(deepcopy(BASE)).endpoint_roles == RoleTables().endpoint_roles


def test_other_invalid_registry_checks_keep_the_fallback_repair():
    registry = deepcopy(BASE)
    registry["schema"] = "private-marker"
    error = refusal(roles.validate, registry)
    assert error.reason == "unsupported_schema" and error.next_action == CLOSED_ACTIONS["unsupported_schema"]
    registry = deepcopy(BASE)
    registry["private-marker"] = 1
    error = refusal(roles.validate, registry)
    assert error.reason == "unknown_key" and error.next_action == CLOSED_ACTIONS["unknown_key"]
    role = deepcopy(BASE["roles"]["root"])
    role["reads"].append("private-marker")
    error = refusal(roles.validate_role, "root", role)
    assert error.reason == "unknown_action" and error.next_action == CLOSED_ACTIONS["unknown_action"]
    error = refusal(roles.load_registry, b'{"schema":1,"schema":2}')
    assert error.reason == "duplicate_key" and error.next_action == CLOSED_ACTIONS["duplicate_key"]
    assert "private-marker" not in error.next_action
    assert roles.load_registry(RAW) == BASE


def test_validation_bounds_each_caller_tree_once():
    registry = deepcopy(MAILBOX_BASE)
    result, expanded, ordered = _trace_visits(lambda: roles.validate(registry))
    assert result == registry and not ordered and len(expanded) == 1759
    for role in registry["roles"].values():
        assert expanded.count(id(role)) == 1
    result, expanded, ordered = _trace_visits(lambda: roles.validate(registry=registry))
    assert result["schema"] == BASE["schema"] and len(expanded) + len(ordered) == 1760
    for role in registry["roles"].values():
        assert expanded.count(id(role)) == 1
    role = deepcopy(BASE["roles"]["root"])
    result, expanded, ordered = _trace_visits(lambda: roles.validate_role("root", role))
    assert result is None and len(expanded) + len(ordered) == 120
    assert expanded.count(id(role)) == 1
    table_input = deepcopy(MAILBOX_BASE)
    result, expanded, ordered = _trace_visits(lambda: roles.role_tables(table_input))
    # role_tables and its nested validate each bound the registry in their own call.
    assert result.endpoint_roles == RoleTables().endpoint_roles and len(expanded) + len(ordered) == 3110
    for role in table_input["roles"].values():
        assert expanded.count(id(role)) == 2
    huge = deepcopy(MAILBOX_BASE)
    huge["roles"]["root"]["title"] = "x" * 262145
    error, expanded, ordered = _trace_visits(lambda: refusal(roles.validate, huge))
    assert error.reason == "too_large" and error.next_action == TOO_LARGE_ACTION
    assert not ordered
    assert len(expanded) == 33 and expanded.count(id(huge["roles"]["root"])) == 1
    result, expanded, ordered = _trace_visits(lambda: roles.validate(registry))
    assert result == registry and len(expanded) + len(ordered) == 1759


def test_repair_retry_and_concurrent_callers_stay_isolated():
    def attempt(index):
        if index % 4 == 0:
            registry = deepcopy(BASE)
            registry["roles"]["root"].pop("title")
            error = refusal(roles.validate, registry)
            assert error.next_action == MISSING_FIELDS
        elif index % 4 == 1:
            role = deepcopy(BASE["roles"]["root"])
            role["kind"] = []
            error = refusal(roles.validate_role, "root", role)
            assert error.next_action == FIELD_TYPES
        elif index % 4 == 2:
            registry = deepcopy(BASE)
            registry["routes"] = [[1]]
            error = refusal(roles.role_tables, registry)
            assert error.next_action == ROUTE_PAIRS
        else:
            role = deepcopy(BASE["roles"]["root"])
            role["title"] = "y" * 262145
            error = refusal(roles.validate_role, "root", role)
            assert error.reason == "too_large" and error.next_action == TOO_LARGE_ACTION
        assert roles.validate(deepcopy(BASE)) == BASE
        assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None
        return index
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert sorted(pool.map(attempt, range(12))) == list(range(12))


def expect_refusal(call, refusal_type=roles.RoleRefusal):
    """Refusal envelope for a call that may close over a cyclic value."""
    with pytest.raises(refusal_type) as caught:
        call()
    error = caught.value
    assert error.code == 1 and error.status == "refused"
    assert str(error) == "role registry refused: " + error.reason
    assert set(error.as_dict()) == {"status", "reason", "code", "next_action"}
    assert "\n" not in error.next_action
    assert "x" * 64 not in error.next_action and "A" * 64 not in error.next_action
    return error


def fresh_bound_reason(value):
    """Baseline budget: one fresh bounded_tree, with no shared-child shortcut."""
    try:
        roles.bounded_tree(value)
    except MailboxRefusal as error:
        reason = render_mailbox_refusal(error)["reason"]
        return "too_large" if reason == "too_large" else "invalid_registry"
    return None


def first_bound_reason(values):
    for value in values:
        reason = fresh_bound_reason(value)
        if reason is not None:
            return reason
    return None


def actions_envelope_reason(role, name):
    """Former actions(...) budgets, in vocabulary order, after the outer call fits."""
    for group in roles.VOCABULARY:
        reason = fresh_bound_reason((role, name, group))
        if reason is not None:
            return reason
    prohibitions = role["prohibitions"]
    for group in roles.VOCABULARY:
        reason = fresh_bound_reason((prohibitions, name, group))
        if reason is not None:
            return reason
    return None


def keyword_role_reason(name, role):
    reason = first_bound_reason(((name,), {"role": role}))
    if reason is not None:
        return reason
    return actions_envelope_reason(role, name)


def positional_role_reason(name, role):
    reason = first_bound_reason(((name, role), {}))
    if reason is not None:
        return reason
    return actions_envelope_reason(role, name)


def assert_role_matches_baseline(name, role):
    expected = keyword_role_reason(name, role)
    error = expect_refusal(lambda: roles.validate_role(name, role=role))
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]
    assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None
    expected = positional_role_reason(name, role)
    error = expect_refusal(lambda: roles.validate_role(name, role))
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]


def test_shared_positional_and_keyword_values_keep_one_budget():
    role = deepcopy(BASE["roles"]["root"])
    keywords = {"role": role}
    name = next(iter(keywords))
    role["title"] = name
    role["model_profile"] = {"source": "fixed", "tier": None, "effort": [None] * 10001}
    assert_role_matches_baseline(name, role)
    role = deepcopy(BASE["roles"]["root"])
    role["title"] = "role"
    role["model_profile"] = {"source": "fixed", "effort": "role", "tier": ["role"] + ["x"] * 10000}
    assert_role_matches_baseline("role", role)
    group = ["name"] + [1] * 10000
    expected = first_bound_reason((("name",), {"name": "ok", "group": group}))
    error = expect_refusal(lambda: roles.actions("name", name="ok", group=group))
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]


def _bounded_role(kind):
    role = deepcopy(BASE["roles"]["root"])
    role["title"] = "role"
    if kind == "links":
        role["hat_of"] = "A" * 200000
        role["reports_to"] = "B" * 200000
    elif kind == "cycle":
        cycle = ["role"]
        cycle.append(cycle)
        role["model_profile"] = {"source": "fixed", "effort": cycle}
    elif kind == "depth":
        nested = "role"
        for _ in range(200):
            nested = [nested]
        role["model_profile"] = {"source": "fixed", "effort": nested}
    elif kind == "items":
        role["model_profile"] = {"source": "fixed", "effort": ["role"] * 50000}
    elif kind == "int-key":
        role["model_profile"] = {"source": "fixed", "effort": {1: "role"}}
    return role


@pytest.mark.parametrize("kind", ["links", "cycle", "depth", "items", "int-key"])
def test_keyword_containers_keep_baseline_bounds(kind):
    role = _bounded_role(kind)
    assert_role_matches_baseline("role", role)
    assert roles.role_tables(deepcopy(BASE)).endpoint_roles == RoleTables().endpoint_roles


def test_bounds_precede_field_repair_when_singletons_are_shared():
    role = deepcopy(BASE["roles"]["root"])
    role["title"] = "x" * 262145
    expected = keyword_role_reason(["role", None], role)
    error = expect_refusal(lambda: roles.validate_role(["role", None], role=role))
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]
    assert error.reason == "too_large"
    role = deepcopy(BASE["roles"]["root"])
    role["model_profile"] = {"source": "fixed", "effort": "x" * 262145, "tier": ()}
    expected = keyword_role_reason((), role)
    error = expect_refusal(lambda: roles.validate_role(name=(), role=role))
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]
    role = deepcopy(BASE["roles"]["root"])
    role["title"] = "x" * 262145
    expected = first_bound_reason(((), {"name": (), "group": None, "role": role}))
    error = expect_refusal(lambda: roles.actions(name=(), group=None, role=role))
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]


def test_nested_actions_envelope_refuses_the_baseline_boundary():
    role = deepcopy(BASE["roles"]["root"])
    role["model_profile"] = {"source": "fixed", "effort": "x" * 261088}
    expected = positional_role_reason("root", role)
    error = expect_refusal(lambda: roles.validate_role("root", role))
    assert expected == "too_large"
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]
    assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None
    # Ids from a prior public call are not evidence for the next one.
    assert roles.role_tables(deepcopy(BASE)).endpoint_roles == RoleTables().endpoint_roles
    role = deepcopy(BASE["roles"]["root"])
    role["model_profile"] = {"source": "fixed", "effort": "x" * 261088}
    error = expect_refusal(lambda: roles.validate_role("root", role=role))
    assert error.reason == keyword_role_reason("root", role)


@pytest.mark.parametrize("value", ([], 123, True, {}))
@pytest.mark.parametrize("caller", ["validate_role", "validate", "role_tables"])
def test_service_type_precedes_the_kind_invariant(value, caller):
    if caller == "validate_role":
        role = deepcopy(BASE["roles"]["root"])
        role["service"] = value
        error = expect_refusal(lambda: roles.validate_role("root", role))
    else:
        registry = deepcopy(BASE)
        registry["roles"]["root"]["service"] = value
        call = roles.validate if caller == "validate" else roles.role_tables
        error = expect_refusal(lambda: call(registry))
    assert error.reason == "invalid_registry" and error.next_action == FIELD_TYPES
    assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None


@pytest.mark.parametrize("value", ([], 123, True, "bad"))
@pytest.mark.parametrize("caller", ["validate_role", "validate", "role_tables"])
def test_provision_type_precedes_the_endpoint_invariant(value, caller):
    if caller == "validate_role":
        role = deepcopy(BASE["roles"]["test-author"])
        role["provision"] = value
        error = expect_refusal(lambda: roles.validate_role("test-author", role))
    else:
        registry = deepcopy(BASE)
        registry["roles"]["test-author"]["provision"] = value
        call = roles.validate if caller == "validate" else roles.role_tables
        error = expect_refusal(lambda: call(registry))
    assert error.reason == "invalid_registry" and error.next_action == FIELD_TYPES
    assert roles.validate(deepcopy(BASE)) == BASE


def test_bound_refusals_retry_and_stay_isolated_across_callers():
    def attempt(index):
        if index % 2 == 0:
            role = deepcopy(BASE["roles"]["root"])
            role["model_profile"] = {"source": "fixed", "effort": "x" * 261088}
            error = expect_refusal(lambda: roles.validate_role("root", role))
            assert error.reason == "too_large" and error.next_action == TOO_LARGE_ACTION
        else:
            role = deepcopy(BASE["roles"]["root"])
            role["service"] = []
            error = expect_refusal(lambda: roles.validate_role("root", role))
            assert error.reason == "invalid_registry" and error.next_action == FIELD_TYPES
        assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None
        return index
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert sorted(pool.map(attempt, range(8))) == list(range(8))


def _effort_role(count):
    role = deepcopy(BASE["roles"]["root"])
    role["model_profile"] = {"source": "fixed", "effort": "x" * count}
    return role


def _refuse_role(role, style):
    if style == "keyword":
        expected = keyword_role_reason("root", role)
        error = expect_refusal(lambda: roles.validate_role("root", role=role))
    else:
        expected = positional_role_reason("root", role)
        error = expect_refusal(lambda: roles.validate_role("root", role))
    assert expected == "too_large"
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]
    return error


@pytest.mark.parametrize("count", [261077, 261080])
@pytest.mark.parametrize("style", ["positional", "keyword"])
def test_later_actions_envelope_is_charged_when_the_first_group_fits(count, style):
    role = _effort_role(count)
    groups = list(roles.VOCABULARY)
    assert fresh_bound_reason((role, "root", groups[0])) is None
    assert actions_envelope_reason(role, "root") == "too_large"
    _refuse_role(role, style)
    assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None
    assert roles.role_tables(deepcopy(BASE)).endpoint_roles == RoleTables().endpoint_roles


def test_effort_inside_every_actions_envelope_is_accepted():
    role = _effort_role(261076)
    assert positional_role_reason("root", role) is None
    assert keyword_role_reason("root", role) is None
    assert roles.validate_role("root", role) is None
    assert roles.validate_role("root", role=deepcopy(role)) is None


@pytest.mark.parametrize("count", [261077, 261080])
@pytest.mark.parametrize("style", ["positional", "keyword"])
def test_registry_effort_boundary_refuses_with_the_outer_budget(count, style):
    registry = deepcopy(BASE)
    registry["roles"]["root"]["model_profile"] = {"source": "fixed", "effort": "x" * count}
    if style == "keyword":
        expected = first_bound_reason(((), {"registry": registry}))
        error = expect_refusal(lambda: roles.validate(registry=registry))
    else:
        expected = first_bound_reason(((registry,), {}))
        error = expect_refusal(lambda: roles.validate(registry))
    assert expected == "too_large"
    assert error.reason == expected and error.next_action == CLOSED_ACTIONS[expected]
    assert roles.validate(deepcopy(BASE)) == BASE


def test_writer_walks_its_tree_once():
    entry = {"writes": ["source"]}
    result, cached, ordered = _trace_visits(lambda: roles.writer(entry))
    assert result is True
    assert len(cached) + len(ordered) == 6 and cached.count(id(entry)) == 1
    assert roles.writer({"writes": []}) is False
    assert roles.writer({"writes": ["source"]}) is True


def test_later_envelope_refusals_retry_and_stay_isolated():
    def attempt(index):
        role = _effort_role(261080 if index % 2 == 0 else 261077)
        _refuse_role(role, "positional" if index % 4 < 2 else "keyword")
        assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None
        return index
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert sorted(pool.map(attempt, range(8))) == list(range(8))


def _boxed(node, count, kind):
    for _ in range(count):
        node = [node] if kind == "list" else (node,)
    return node


def _shared_bytes(kind):
    if kind == "tuple":
        return ("x" * 140000, ())
    if kind == "dict":
        return {"pad": "x" * 140000, "tail": []}
    return ["x" * 140000, []]


def _cache_entries():
    """Reviewer trees where a cached summary and the baseline walk can disagree."""
    shared = _shared_bytes("list")
    shared_tuple = _shared_bytes("tuple")
    shared_dict = _shared_bytes("dict")
    return {
        "bytes-dict": ({"writes": ["source"], "a": shared, "b": _boxed(shared, 29, "list")}, shared),
        "tuple-dict": ({"writes": ["source"], "a": shared_tuple, "b": _boxed(shared_tuple, 29, "tuple")},
                       shared_tuple),
        "dict-dict": ({"writes": ["source"], "a": shared_dict, "b": _boxed(shared_dict, 29, "list")},
                      shared_dict),
        "bytes-list": ({"writes": ["source"], "nest": [shared, _boxed(shared, 28, "list")]}, shared),
        "bytes-tuple": ({"writes": ["source"], "nest": (shared, _boxed(shared, 28, "tuple"))}, shared),
    }


_CACHE_ENTRIES = _cache_entries()
_PRECEDENCE_CASES = (*_CACHE_ENTRIES, "depth-pad", "node-pad")


def _precedence_entry(caller, label, style):
    if label in _CACHE_ENTRIES:
        return _CACHE_ENTRIES[label]
    # Extra bytes and nodes before the second alias relative to writer(entry).
    byte_overhead, node_overhead = {
        "writer": {"positional": (0, 0), "keyword": (8, 1)},
        "actions": {"positional": (2, 0), "keyword": (11, 1)},
        "validate_role": {"positional": (7, 1), "keyword": (21, 3)},
        "validate": {"positional": (0, 0), "keyword": (11, 1)},
    }[caller][style]
    nested = _boxed(None, 30, "list")
    # The second alias gets 59 bytes or 30 nodes. The ordered walk reaches the
    # depth error before consuming either budget, but its full summary needs
    # 64 bytes and 31 nodes, so neither padded case can use the summary.
    if label == "depth-pad":
        pad = "x" * (261977 - byte_overhead)
    else:
        pad = [[0] * count for count in (10000, 10000, 10000, 2694 - node_overhead)]
    return {"writes": [], "first": nested, "pad": pad, "again": [nested]}, nested


def _precedence_args(caller, entry, style):
    kwargs = {
        "writer": {"entry": entry},
        "actions": {"role": entry, "name": "root", "group": "reads"},
        "validate_role": {"name": "root", "role": entry},
        "validate": {"registry": entry},
    }[caller]
    return ((), kwargs) if style == "keyword" else (tuple(kwargs.values()), {})


def _assert_cached_matches_baseline(uncached_roles, caller, label, style):
    entry, shared = _precedence_entry(caller, label, style)
    args, kwargs = _precedence_args(caller, entry, style)
    baseline = uncached_roles[caller]
    expected, uncached, baseline_visits = _trace_visits(
        lambda: expect_refusal(lambda: baseline(*args, **kwargs), uncached_roles["RoleRefusal"])
    )
    actual = getattr(roles, caller)
    error, cached, ordered = _trace_visits(lambda: expect_refusal(lambda: actual(*args, **kwargs)))
    reason = "invalid_registry" if label in ("depth-pad", "node-pad") else "too_large"
    assert expected.reason == reason and expected.next_action == CLOSED_ACTIONS[reason]
    assert error.as_dict() == expected.as_dict()
    assert not uncached
    assert cached.count(id(shared)) == 1
    assert ordered.count(id(shared)) == baseline_visits.count(id(shared)) == 2
    assert len(ordered) == len(baseline_visits)
    # Skip the fresh root tuple or dict and, for keywords, the empty args tuple.
    prefix = 2 if style == "keyword" else 1
    assert ordered[prefix:] == baseline_visits[prefix:]
    assert roles.writer({"writes": ["source"]}) is True
    assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None


@pytest.mark.parametrize("caller", ["writer", "actions", "validate_role", "validate"])
@pytest.mark.parametrize("label", _PRECEDENCE_CASES)
@pytest.mark.parametrize("style", ["positional", "keyword"])
def test_cached_summary_refusal_matches_baseline(uncached_roles, caller, label, style):
    _assert_cached_matches_baseline(uncached_roles, caller, label, style)


def test_cached_summary_and_lane_kind_refusals_retry_and_stay_isolated(uncached_roles):
    def attempt(index):
        if index % 5 == 4:
            role = deepcopy(BASE["roles"]["reviewer"])
            role["endpoint"].pop("lane_kind")
            error = refusal(roles.validate_role, "reviewer", role)
            assert error.reason == "invalid_registry" and error.next_action == MISSING_FIELDS
        else:
            label = _PRECEDENCE_CASES[index % len(_PRECEDENCE_CASES)]
            caller = "writer" if index % 2 == 0 else "validate_role"
            style = "positional" if index % 4 < 2 else "keyword"
            _assert_cached_matches_baseline(uncached_roles, caller, label, style)
        assert roles.validate_role("reviewer", deepcopy(BASE["roles"]["reviewer"])) is None
        return index
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert sorted(pool.map(attempt, range(8))) == list(range(8))


def test_lane_endpoint_missing_lane_kind_selects_missing_field():
    role = deepcopy(BASE["roles"]["reviewer"])
    role["endpoint"].pop("lane_kind")
    error = refusal(roles.validate_role, "reviewer", role)
    assert error.reason == "invalid_registry" and error.next_action == MISSING_FIELDS
    keyword_role = deepcopy(role)
    keyword_snapshot = deepcopy(keyword_role)
    error = expect_refusal(lambda: roles.validate_role("reviewer", role=keyword_role))
    assert keyword_role == keyword_snapshot
    assert error.reason == "invalid_registry" and error.next_action == MISSING_FIELDS
    registry = deepcopy(BASE)
    registry["roles"]["reviewer"]["endpoint"].pop("lane_kind")
    error = refusal(roles.validate, registry)
    assert error.reason == "invalid_registry" and error.next_action == MISSING_FIELDS
    error = refusal(roles.role_tables, deepcopy(registry))
    assert error.next_action == MISSING_FIELDS
    assert roles.validate(deepcopy(BASE)) == BASE
    assert roles.validate_role("reviewer", deepcopy(BASE["roles"]["reviewer"])) is None


def test_non_lane_endpoint_keeps_lane_kind_on_the_fallback_repair():
    role = deepcopy(BASE["roles"]["root"])
    role["endpoint"]["lane_kind"] = "reviewer"
    error = refusal(roles.validate_role, "root", role)
    assert error.reason == "invalid_registry" and error.next_action == REGISTRY_FALLBACK
    assert roles.validate_role("root", deepcopy(BASE["roles"]["root"])) is None


def _trace_visits(call):
    """Return the result and actual node visits from each bounds implementation."""
    expanded = []
    ordered = []
    ordered_source = roles.bounded_tree.__code__.co_filename
    cached_source = roles.__file__

    def tracer(frame, event, _arg):
        code = frame.f_code
        if event == "call":
            if code.co_filename == ordered_source and code.co_name == "visit":
                ordered.append(id(frame.f_locals["item"]))
            elif code.co_filename == cached_source and code.co_name == "_account_new":
                expanded.append(id(frame.f_locals["item"]))
        return None

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        result = call()
    finally:
        sys.settrace(previous)
    return result, expanded, ordered


@pytest.fixture(scope="module")
def uncached_roles():
    """Load the public role operations with the original uncached budget routing."""
    path = ROOT / "aegis_core/team_roles.py"
    source = path.read_text(encoding="utf-8")
    # Work on a fresh module namespace. Preserve the operation wrappers, and
    # call them at the nested sites where the cache normally elides them.
    replacements = (
        ("    completed = _BOUNDED.get()\n", "    completed = None\n"),
        ("        _former_args((role, name, group))\n        allowed[group] = _actions(",
         "        allowed[group] = actions("),
        ("        _former_args((prohibitions, name, group))\n        refused = _actions(",
         "        refused = actions("),
        ("        _validate_role(name, role)\n", "        validate_role(name, role)\n"),
    )
    for before, after in replacements:
        assert source.count(before) == 1, before
        source = source.replace(before, after)
    namespace = {"__name__": "uncached_team_roles"}
    exec(compile(source, str(path), "exec"), namespace)
    return namespace


def test_direct_call_expands_each_fresh_node_once(uncached_roles):
    entry = {"writes": ["source"]}
    result, expanded, ordered = _trace_visits(lambda: roles.writer(entry))
    expected, uncached, baseline = _trace_visits(lambda: uncached_roles["writer"](entry))
    assert result is expected is True
    assert not uncached and not ordered
    assert expanded.count(id(entry)) == 1
    assert len(expanded) == len(baseline) == 6
    # The wrappers allocate their own positional and keyword roots.
    assert expanded[1:-1] == baseline[1:-1]


def test_alias_is_expanded_once_when_it_fits(uncached_roles):
    shared = {"name": "alpha"}
    entry = {"writes": [], "a": shared, "b": shared}
    result, expanded, ordered = _trace_visits(lambda: roles.writer(entry))
    expected, uncached, baseline = _trace_visits(lambda: uncached_roles["writer"](entry))
    assert result is expected is False
    assert not uncached and not ordered
    assert expanded.count(id(shared)) == 1
    assert baseline.count(id(shared)) == 2
    assert len(expanded) == 10 and len(baseline) == 13


def test_mixed_arguments_reuse_a_shared_container_when_it_fits(uncached_roles):
    shared = {"name": "alpha"}
    role = {"reads": [shared]}
    error, expanded, ordered = _trace_visits(
        lambda: expect_refusal(lambda: roles.actions(role, "root", group=shared))
    )
    expected, uncached, baseline = _trace_visits(
        lambda: expect_refusal(lambda: uncached_roles["actions"](role, "root", group=shared),
                               uncached_roles["RoleRefusal"])
    )
    # Bounding both envelopes succeeds, then actions refuses the group type.
    assert error.next_action == FIELD_TYPES and error.as_dict() == expected.as_dict()
    assert not uncached and not ordered
    assert expanded.count(id(shared)) == 1 and baseline.count(id(shared)) == 2
    assert len(expanded) == 10 and len(baseline) == 13


def test_mixed_arguments_fall_back_for_a_shared_container(uncached_roles):
    shared = _shared_bytes("list")
    role = {"reads": [], "first": shared}
    group = {"pad": "x" * 140000, "again": _boxed(shared, 29, "list")}
    error, expanded, ordered = _trace_visits(
        lambda: expect_refusal(lambda: roles.actions(role, "root", group=group))
    )
    expected, uncached, baseline = _trace_visits(
        lambda: expect_refusal(lambda: uncached_roles["actions"](role, "root", group=group),
                               uncached_roles["RoleRefusal"])
    )
    assert expected.reason == "too_large" and expected.next_action == TOO_LARGE_ACTION
    assert error.as_dict() == expected.as_dict()
    assert not uncached
    assert expanded.count(id(shared)) == ordered.count(id(shared)) == 1
    assert baseline.count(id(shared)) == 2
    # The ordered phase repeats the keyword envelope. Its descendants are
    # the final bounded_tree walk in the fully uncached public call as well.
    assert ordered[1:] == baseline[-len(ordered):][1:]


def test_nested_envelopes_expand_shared_role_once(uncached_roles):
    role = deepcopy(BASE["roles"]["root"])
    result, expanded, ordered = _trace_visits(lambda: roles.validate_role("root", role))
    expected, uncached, baseline = _trace_visits(lambda: uncached_roles["validate_role"]("root", role))
    assert result is expected is None
    assert not uncached and not ordered
    assert expanded.count(id(role)) == expanded.count(id(role["prohibitions"])) == 1
    # Outer role, one actions call per group, then the two connection budgets.
    assert baseline.count(id(role)) == 1 + len(roles.VOCABULARY) + 2
    assert len(expanded) == 120 and len(baseline) == 790


@pytest.mark.parametrize("fallback", [False, True], ids=["fresh", "fallback"])
def test_early_refusal_skips_nodes_the_walk_never_reaches(uncached_roles, fallback):
    tail = {"later": 1}
    overflow = "x" * 262145
    entry = {"writes": ["source"], "big": overflow, "tail": tail}
    if fallback:
        cached_entry, shared = _CACHE_ENTRIES["bytes-dict"]
        entry = {**cached_entry, "tail": tail}
        overflow = shared[0]
    error, expanded, ordered = _trace_visits(lambda: expect_refusal(lambda: roles.writer(entry)))
    expected, uncached, baseline = _trace_visits(
        lambda: expect_refusal(lambda: uncached_roles["writer"](entry), uncached_roles["RoleRefusal"])
    )
    assert error.reason == "too_large" and error.next_action == TOO_LARGE_ACTION
    assert error.as_dict() == expected.as_dict() and not uncached
    # Compare the reached nodes after the call's freshly allocated argument tuple.
    if fallback:
        assert len(expanded) == 39 and len(ordered) == len(baseline) == 41
        assert expanded.count(id(shared)) == 1 and ordered.count(id(shared)) == 2
        assert expanded.count(id(overflow)) == 1 and ordered.count(id(overflow)) == 2
        assert ordered[1:] == baseline[1:]
    else:
        assert not ordered
        assert len(expanded) == len(baseline) == 7
        assert expanded[1:] == baseline[1:]
    assert id(tail) not in expanded + ordered + baseline
    assert roles.writer({"writes": ["source"]}) is True


def test_stock_registry_node_visits_show_the_cache_pays(uncached_roles):
    """Measure both modes through the same twelve public entry points."""
    registry = deepcopy(MAILBOX_BASE)
    role = deepcopy(BASE["roles"]["root"])
    # Each pair is positional, keyword.
    cases = (
        ("role_tables", {"value": registry}, (3110, 3111), (12741, 12742)),
        ("actions", {"role": role, "name": "root", "group": "reads"}, (97, 100), (97, 100)),
        ("validate_role", {"name": "root", "role": role}, (120, 122), (790, 792)),
        ("validate", {"registry": registry}, (1759, 1760), (11390, 11391)),
        ("fixed_model_profile", {"entry": role}, (95, 96), (95, 96)),
        ("writer", {"entry": role}, (95, 96), (95, 96)),
        ("file_tools", {"entry": role}, (95, 96), (95, 96)),
        ("workspace_tools", {"entry": role}, (95, 96), (95, 96)),
        ("lifecycle_tools", {"entry": role}, (95, 96), (95, 96)),
        ("decision_tools", {"entry": role}, (95, 96), (95, 96)),
        ("takes_board", {"entry": role}, (95, 96), (95, 96)),
        ("source_views", {"entry": role}, (95, 96), (95, 96)),
    )
    for entry, arguments, expected_current, expected_baseline in cases:
        actual = getattr(roles, entry)
        uncached = uncached_roles[entry]
        for index, (args, kwargs) in enumerate(((tuple(arguments.values()), {}), ((), arguments))):
            result, cached, ordered = _trace_visits(lambda: actual(*args, **kwargs))
            expected, expanded, baseline = _trace_visits(lambda: uncached(*args, **kwargs))
            assert result == expected, entry
            assert not expanded, entry
            assert len(cached) + len(ordered) == expected_current[index], entry
            assert len(baseline) == expected_baseline[index], entry
    assert roles.validate(deepcopy(BASE)) == BASE
    assert roles.role_tables(deepcopy(BASE)).endpoint_roles == RoleTables().endpoint_roles
