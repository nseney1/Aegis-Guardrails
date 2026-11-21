"""Job recipe wire parity, bounded refusals, retry and descriptor confinement."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import ast
from copy import deepcopy
import hashlib
import errno
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_jobs_recipes as core
from aegis_core import storage_confined
from aegis_core import team_mailbox_primitives
from aegis_core import team_mailbox_store
from tools import hierarchy_jobs as legacy


ROOT = Path(__file__).resolve().parents[3]
api = core.Recipes(mailbox_helpers=team_mailbox_primitives)


def recipes():
    return {
        "schema": legacy.RECIPES_SCHEMA,
        "python": str(Path(os.__file__).resolve()),
        "path": [str(ROOT)],
        "recipes": {
            "check": {
                "kind": "command",
                "timeout_seconds": 1,
                "sandbox": "none",
                "heavy": False,
                "steps": [["$python", "--version"]],
            }
        },
    }


def make_store(tmp_path):
    if not team_mailbox_store.descriptor_supported() or not storage_confined.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    return tmp_path


def refusal(code):
    return pytest.raises(core.JobRecipesRefusal, match="^job recipes refused: " + code + "$")


def test_template_bytes_equal():
    assert (ROOT / "aegis_core/team_templates/job-recipes.json").read_bytes() == (
        ROOT / "tools/hierarchy_templates/job-recipes.json"
    ).read_bytes()


@pytest.mark.parametrize("kind", ["command", "commit", "merge"])
def test_successful_recipe_values_and_nonmutation(kind):
    data = recipes()
    if kind != "command":
        data["recipes"]["check"] = {"kind": kind, "timeout_seconds": 10, "sandbox": "none"}
        data["identity"] = {"name": "Root", "email": "root@example.invalid"}
    before = deepcopy(data)
    assert api.validate_recipes(data) == legacy.validate_recipes(data) == before
    assert data == before
    raw = json.dumps(data).encode()
    assert api.validate_recipes(raw) == legacy.validate_recipes(raw)


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("schema", "untrusted-secret", "unsupported_schema"),
        ("extra", "untrusted-secret", "unknown_key"),
        ("python", 4, "invalid_recipe"),
        ("path", {}, "invalid_recipe"),
        ("env", {"BAD-KEY": "untrusted-secret"}, "invalid_recipe"),
        ("recipes", {}, "invalid_recipe"),
        ("min_free_gigabytes", -1, "invalid_recipe"),
        ("census_outside_policy", [], "invalid_recipe"),
    ],
)
def test_legacy_refusal_mapping_retry_and_no_side_effect(field, value, code):
    data = {**recipes(), field: value}
    before = deepcopy(data)
    with pytest.raises(ValueError):
        legacy.validate_recipes(data)
    with refusal(code) as caught:
        api.validate_recipes(data)
    envelope = caught.value.as_dict()
    assert envelope["reason"] == envelope["code"] == code
    assert envelope["next_action"] and "untrusted-secret" not in json.dumps(envelope)
    assert data == before
    assert api.validate_recipes(recipes()) == recipes()


@pytest.mark.parametrize("raw", [b"{", b"\xff", b'{"x":1,"x":2}', b"NaN"])
def test_legacy_json_refusal_mapping(raw):
    with pytest.raises((ValueError, UnicodeError)):
        legacy.validate_recipes(raw)
    with refusal("invalid_json"):
        api.validate_recipes(raw)
    assert api.validate_recipes(recipes()) == recipes()


@pytest.mark.parametrize(
    "field,value",
    [
        ("heavy", 1),
        ("timeout_seconds", True),
        ("sandbox", []),
        ("kind", "unknown"),
        ("steps", [[None]]),
        ("steps", [["$unknown"]]),
        ("steps", [["cargo", "build"]]),
        ("steps", []),
        ("keep", ["../x"]),
        ("heavy_tests", True),
        ("expects_tests", True),
        ("export_git", True),
        ("writable_checkout", "yes"),
        ("require_clean", "yes"),
    ],
)
def test_recipe_field_refusals(field, value):
    data = {**recipes()["recipes"]["check"], field: value}
    with pytest.raises(ValueError):
        legacy.validate_recipe("check", data)
    with refusal("invalid_recipe"):
        api.validate_recipe("check", data)


def test_load_hash_retry_and_size_before_parse(tmp_path):
    root = make_store(tmp_path)
    path = root / "recipes.json"
    path.write_bytes(b"{" * (core.MAX_BYTES + 1))
    with refusal("too_large"):
        api.load_recipes(path)
    raw = json.dumps(recipes()).encode()
    path.write_bytes(raw)
    expected = {**recipes(), "recipes_sha256": hashlib.sha256(raw).hexdigest()}
    assert api.load_recipes(path) == legacy.load_recipes(path) == expected
    path.unlink()
    with refusal("missing"):
        api.load_recipes(path)


@pytest.mark.parametrize("spelling", [None, "C:\\work\\recipes.json"], ids=["native_spelling", "windows_spelling"])
def test_unsupported_platform_has_fixed_refusal(tmp_path, monkeypatch, spelling):
    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    with refusal("unsupported_platform"):
        api.load_recipes(tmp_path / "recipes.json" if spelling is None else spelling)


@pytest.mark.parametrize("operation", ["folders", "paths", "report"])
def test_unsupported_platform_before_path_handling(monkeypatch, operation):
    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    monkeypatch.setattr(team_mailbox_store, "descriptor_supported", lambda: False)
    with refusal("unsupported_platform"):
        if operation == "folders":
            api.existing_folders(["C:\\work"], "hide")
        elif operation == "paths":
            api.checked_paths({"paths": ["test.py"]}, {"kind": "command", "steps": [["$paths"]]}, "C:\\work")
        else:
            api.kept_junit([{"path": core.JUNIT_KEEP, "copy": "C:\\work\\junit.xml"}], root="C:\\work")


def test_recipe_symlink_refused_retry(tmp_path):
    root = make_store(tmp_path)
    target = root / "target.json"
    target.write_bytes(json.dumps(recipes()).encode())
    link = root / "recipes.json"
    symlink_or_skip(target, link)
    with refusal("unsafe_path"):
        api.load_recipes(link)
    link.unlink()
    link.write_bytes(target.read_bytes())
    assert api.load_recipes(link)["schema"] == core.RECIPES_SCHEMA


@pytest.mark.parametrize("raw", [b"{}", b"---\nheader\n---\n\n{}"])
def test_packet_text_parity(raw):
    assert api.packet_text(raw) == legacy.packet_text(raw)


@pytest.mark.parametrize("raw", [b"\xff", b"---\nmissing body"])
def test_packet_text_refusal_retry(raw):
    with pytest.raises((ValueError, UnicodeError)):
        legacy.packet_text(raw)
    with refusal("invalid_packet"):
        api.packet_text(raw)
    assert api.packet_text(b"{}") == "{}"


def packet():
    return {
        "schema": core.PACKET_SCHEMA,
        "recipe": "check",
        "checkout": ROOT.as_posix(),
        "commit": "a" * 40,
        "tree": "b" * 40,
    }


def test_unknown_recipe_and_malformed_packet_refuse_without_queuing():
    for changed in ({"recipe": "unknown-secret"}, {"commit": []}, {"extra": "secret"}):
        value = {**packet(), **changed}
        before = deepcopy(value)
        with pytest.raises(core.JobRecipesRefusal) as caught:
            api.validate_packet(value, recipes(), registered_checkout=ROOT.as_posix())
        assert caught.value.next_action and "secret" not in str(caught.value)
        assert value == before
    assert api.validate_packet(packet(), recipes(), registered_checkout=ROOT.as_posix()) == packet()


def test_missing_registered_checkout_refuses_without_filesystem_access():
    accesses = []

    class NoAccessRecipes(core.Recipes):
        def _checkout_root(self, checkout):
            accesses.append(checkout)
            raise AssertionError("packet chose a filesystem root")

    local = NoAccessRecipes(mailbox_helpers=team_mailbox_primitives)
    data = recipes()
    data["recipes"]["check"]["steps"] = [["$paths"]]
    with refusal("invalid_packet"):
        local.validate_packet({**packet(), "paths": ["test.py"]}, data)
    assert accesses == []
    assert local.validate_packet(packet(), recipes(), registered_checkout=ROOT.as_posix()) == packet()


@pytest.mark.parametrize("variant", ["registered", "normalised", "other", "private", "alias", "relative", "malformed"])
def test_generated_packet_checkout_registration(tmp_path, variant):
    registered = tmp_path / "registered"
    registered.mkdir()
    (registered / "test.py").touch()
    selected = registered.as_posix()
    if variant == "normalised":
        selected += "/."
    elif variant == "other":
        selected = (tmp_path / "other").as_posix()
    elif variant == "private":
        selected = (tmp_path / "owner_private").as_posix()
    elif variant == "alias":
        symlink_or_skip(registered, tmp_path / "alias", target_is_directory=True)
        selected = (tmp_path / "alias").as_posix()
    elif variant == "relative":
        selected = "registered"
    elif variant == "malformed":
        selected = []
    accesses = []

    @contextmanager
    def factory(checkout):
        accesses.append(checkout)
        with api._checkout_root(checkout) as binding:
            yield binding

    local = core.Recipes(mailbox_helpers=team_mailbox_primitives, checkout_factory=factory)
    data = recipes()
    data["recipes"]["check"]["steps"] = [["$paths"]]
    value = {**packet(), "checkout": selected, "paths": ["test.py"]}
    if variant in ("registered", "normalised"):
        make_store(tmp_path)
        assert local.validate_packet(value, data, registered_checkout=registered) == value
        assert accesses == [registered]
    else:
        with refusal("invalid_packet") as caught:
            local.validate_packet(value, data, registered_checkout=registered)
        assert caught.value.next_action == core.JobRecipesRefusal("invalid_packet").next_action
        assert accesses == []
    if variant == "registered":
        assert legacy.checked_paths(value, data["recipes"]["check"], registered) == value["paths"]
    else:
        raw = json.dumps(value).encode()
        with pytest.raises(ValueError):
            legacy.admit(
                {},
                {"id": "one", "checkouts": [registered.as_posix()]},
                {"brief": "request", "message_id": "request"},
                SimpleNamespace(brief=lambda reference: raw),
                data,
            )
    assert local.validate_packet(packet(), recipes(), registered_checkout=ROOT.as_posix()) == packet()


@pytest.mark.parametrize("variant", ["missing", "extra", "not_object", "after_missing", "after_extra", "after_type"])
def test_packet_field_refusals_have_packet_guidance(variant):
    value = packet()
    if variant == "missing":
        value.pop("tree")
    elif variant == "extra":
        value["unknown-secret"] = True
    elif variant == "not_object":
        value = []
    else:
        value.update(
            schema="aegis.hierarchy-job-packet/v2",
            recipes_sha256="a" * 64,
            after={}
            if variant == "after_missing"
            else {"message_id": "prior", "sha256": "b" * 64, "extra": True}
            if variant == "after_extra"
            else [],
        )
    with refusal("invalid_packet") as caught:
        api.validate_packet(value, recipes(), registered_checkout=ROOT.as_posix())
    assert caught.value.next_action == core.JobRecipesRefusal("invalid_packet").next_action
    assert api.validate_packet(packet(), recipes(), registered_checkout=ROOT.as_posix()) == packet()


@pytest.mark.parametrize(
    "variant",
    [
        "relative_reentry",
        "absolute_alias",
        "external_reentry",
        "directory_alias",
        "root_reentry",
        "chain",
        "loop",
        "hop_limit",
        "escape",
    ],
)
def test_generated_symlink_final_destination(tmp_path, variant):
    root = make_store(tmp_path)
    checkout = root / "checkout"
    checkout.mkdir()
    (checkout / "actual.py").touch()
    outside = root / "outside.py"
    outside.touch()
    selected = checkout / "test.py"
    if variant == "relative_reentry":
        symlink_or_skip("../checkout/actual.py", selected)
    elif variant == "absolute_alias":
        symlink_or_skip(checkout, root / "another_alias", target_is_directory=True)
        symlink_or_skip(root / "another_alias/actual.py", selected)
    elif variant == "external_reentry":
        symlink_or_skip(checkout / "actual.py", root / "return.py")
        symlink_or_skip("../return.py", selected)
    elif variant in ("directory_alias", "root_reentry"):
        symlink_or_skip(checkout, root / "another_alias", target_is_directory=True)
        symlink_or_skip(
            root / "another_alias" if variant == "directory_alias" else "../checkout",
            selected,
            target_is_directory=True,
        )
    elif variant in ("chain", "hop_limit"):
        count = 4 if variant == "chain" else 41
        for index in range(count):
            symlink_or_skip(
                "actual.py" if index == count - 1 else "link%d.py" % (index + 1), checkout / ("link%d.py" % index)
            )
        selected = checkout / "link0.py"
    elif variant == "loop":
        symlink_or_skip("test.py", selected)
    else:
        symlink_or_skip(outside, selected)
    value = {"paths": [selected.name]}
    recipe = {"kind": "command", "steps": [["$paths"]]}
    if variant in ("loop", "hop_limit"):
        with pytest.raises(ValueError):
            legacy.checked_paths(value, recipe, checkout)
    else:
        assert legacy.checked_paths(value, recipe, checkout) == value["paths"]
    if variant in ("loop", "hop_limit", "escape"):
        with refusal("unsafe_path"):
            api.checked_paths(value, recipe, checkout)
    else:
        assert api.checked_paths(value, recipe, checkout) == value["paths"]
    selected.unlink()
    selected.touch()
    assert api.checked_paths(value, recipe, checkout) == value["paths"]


def test_packet_registration_and_symlink_validation_are_concurrent(tmp_path):
    root = make_store(tmp_path)
    (root / "actual.py").touch()
    symlink_or_skip(root, root / "alias", target_is_directory=True)
    symlink_or_skip(root / "alias/actual.py", root / "test.py")
    data = recipes()
    data["recipes"]["check"]["steps"] = [["$paths"]]
    good = {**packet(), "checkout": root.as_posix(), "paths": ["test.py"]}
    bad = {**good, "checkout": (root.parent / "private").as_posix()}
    before = deepcopy((good, bad, data))

    def run(index):
        if index % 2:
            with refusal("invalid_packet"):
                api.validate_packet(bad, data, registered_checkout=root)
        return api.validate_packet(good, data, registered_checkout=root)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(run, range(9))) == [good] * 9
    assert (good, bad, data) == before


@pytest.mark.parametrize("paths", [["one.py"], ["one.py::test_run"], ["folder"], ["gone.py"]])
def test_checked_paths_parity(tmp_path, paths):
    root = make_store(tmp_path)
    (root / "one.py").touch()
    (root / "folder").mkdir()
    for kind in ("commit", "command"):
        recipe = {"kind": kind, "steps": [["$paths"]]}
        value = {"paths": paths}
        try:
            expected = legacy.checked_paths(value, recipe, root)
        except ValueError:
            with pytest.raises(core.JobRecipesRefusal):
                api.checked_paths(value, recipe, root)
        else:
            assert api.checked_paths(value, recipe, root) == expected


@pytest.mark.parametrize("paths", [["../x"], [1], ["-x"], ["x"] * 257, []])
def test_checked_paths_refusal(paths):
    recipe = {"kind": "commit"}
    with pytest.raises(ValueError):
        legacy.checked_paths({"paths": paths}, recipe, ROOT)
    with pytest.raises(core.JobRecipesRefusal):
        api.checked_paths({"paths": paths}, recipe, ROOT)


@pytest.mark.parametrize(
    "raw",
    [
        b'<testsuite tests="3" failures="1" skipped="1"/>',
        b'<testsuites><testsuite tests="2"><testsuite tests="1"/></testsuite></testsuites>',
        b"not xml",
        b"\xff",
        b"<!DOCTYPE x><testsuite/>",
        b'<testsuite tests="-1"/>',
        b'<testsuite tests="0" failures="1"/>',
    ],
)
def test_junit_counts_parity(raw):
    assert api.junit_counts(raw) == legacy.junit_counts(raw)


def test_junit_root_refusal_never_echoes_input():
    assert api.junit_counts(b"<untrusted-secret/>") == (None, "its root is not testsuites or testsuite")


def test_kept_junit_confined_read_retry(tmp_path):
    root = make_store(tmp_path)
    report = root / "report.xml"
    kept = [{"path": core.JUNIT_KEEP, "copy": str(report)}]
    assert api.kept_junit(kept, root=root)[0] is None
    report.write_bytes(b'<testsuite tests="1"/>')
    assert api.kept_junit(kept, root=root) == legacy.kept_junit(kept)
    outside = root.parent / "outside.xml"
    with refusal("unsafe_path"):
        api.kept_junit([{"path": core.JUNIT_KEEP, "copy": str(outside)}], root=root)


def test_reservation_filters_and_injected_tables():
    rows = [
        {"request_id": "req-12345678", "initiative": "one", "kind": "heavy", "holder": "job", "state": "queued"},
        {"malformed": True},
    ]
    args = dict(kind="heavy", initiative="one", states=("queued",))
    assert api.holder_requests(rows, "job", ledger_kinds=("heavy",), **args) == legacy.holder_requests(
        rows, "job", **args
    )
    with refusal("invalid_request"):
        api.holder_requests(rows, core.ANY_HOLDER, ledger_kinds=("heavy",), **args)
    assert api.request_summary(rows[0], ledger_kinds=("heavy",)) == legacy.request_summary(rows[0])
    job = SimpleNamespace(holder="job", initiative={"id": "other"})
    assert api.foreign_rows(rows, job, kind="heavy", ledger_kinds=("heavy",)) == legacy.foreign_rows(
        rows, job, kind="heavy"
    )
    assert api.foreign_reason(rows[0], ledger_kinds=("heavy",)) == legacy.foreign_reason(rows[0])


def test_environment_policy_is_injected():
    calls = []

    def environment(overrides, *, inherit_config):
        return {"base": "yes", **(overrides or {})}

    def child(env, host):
        calls.append(host)
        return {**env, "host": host}

    ports = dict(object_read_env=environment, child_environment=child)
    assert api.read_environment(planned=False, **ports) == {"base": "yes"}
    assert calls == []
    assert api.read_environment(**ports) == {"base": "yes", "host": "no-host"}
    assert calls == ["no-host"]


def test_python_probe_injected_cached_and_concurrent():
    calls = []

    def probe(executable, path, timeout):
        calls.append(executable)
        return SimpleNamespace(stdout=b"3.12.3\n", returncode=0)

    cache = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(api.python_info, recipes(), probe=probe, cache=cache) for _ in range(6)]
        rows = [future.result(timeout=5) for future in futures]
    assert rows == [{"executable": recipes()["python"], "version": "3.12.3"}] * 6
    assert len(calls) == 1


@pytest.mark.parametrize("delta", ["large_int", "surrogate", "many_items", "bytes"])
def test_accepted_bounded_primitive_deltas(delta):
    data = recipes()
    if delta == "large_int":
        rows = [{"holder": "job", "kind": "heavy", "initiative": "one", "state": "queued", "extra": 1 << 65}]
        options = dict(kind="heavy", initiative="one", states=("queued",))
        assert legacy.holder_requests(rows, "job", **options) == rows
        with refusal("invalid_request"):
            api.holder_requests(rows, "job", ledger_kinds=("heavy",), **options)
        return
    if delta == "surrogate":
        data["env"] = {"TOKEN": "\ud800"}
    elif delta == "many_items":
        data["recipes"]["check"]["steps"] = [["x"] * 10001]
    else:
        data["recipes"]["check"]["steps"] = [["x" * (core.MAX_BYTES + 1)]]
    assert legacy.validate_recipes(data) == data
    with pytest.raises(core.JobRecipesRefusal):
        api.validate_recipes(data)


def test_concurrent_invalid_and_valid_retry_preserve_inputs():
    good = recipes()
    bad = {**good, "schema": "invalid"}
    before = deepcopy((good, bad))

    def run(index):
        if index % 2:
            with refusal("unsupported_schema"):
                api.validate_recipes(bad)
        return api.validate_recipes(good)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(run, range(12))) == [good] * 12
    assert (good, bad) == before


@pytest.mark.parametrize("value", [None, 3, [], {}])
def test_folder_label_malformed_is_typed(value):
    with pytest.raises(core.JobRecipesRefusal):
        api.existing_folders([], value)


def test_file_read_holds_parent_across_ancestor_rename(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    folder = root / "input"
    folder.mkdir()
    moved = root / "moved"
    outside = root / "outside"
    outside.mkdir()
    path = folder / "recipes.json"
    raw = json.dumps(recipes()).encode()
    path.write_bytes(raw)
    (outside / path.name).write_bytes(b'{"outside":true}')
    original = core.confined_file

    @contextmanager
    def swapped(base, parts):
        with original(base, parts) as handle:
            folder.rename(moved)
            symlink_or_skip(outside, folder, target_is_directory=True)
            yield handle

    monkeypatch.setattr(core, "confined_file", swapped)
    assert api.load_recipes(path)["recipes_sha256"] == hashlib.sha256(raw).hexdigest()
    assert (outside / path.name).read_bytes() == b'{"outside":true}'


def test_checked_paths_hold_one_root_across_rename(tmp_path):
    root = make_store(tmp_path)
    checkout = root / "checkout"
    checkout.mkdir()
    (checkout / "one.py").touch()
    (checkout / "two.py").touch()
    moved = root / "moved"
    outside = root / "outside"
    outside.mkdir()
    calls = []

    class SwappingRecipes(core.Recipes):
        @contextmanager
        def _checkout_root(self, path):
            with super()._checkout_root(path) as binding:
                checkout.rename(moved)
                symlink_or_skip(outside, checkout, target_is_directory=True)
                calls.append(path)
                yield binding

    local = SwappingRecipes(mailbox_helpers=team_mailbox_primitives)
    paths = ["one.py", "two.py"]
    assert local.checked_paths({"paths": paths}, {"kind": "command", "steps": [["$paths"]]}, checkout) == paths
    assert len(calls) == 1


def test_checked_paths_refuses_directory_swap_and_valid_retry(tmp_path):
    root = make_store(tmp_path)
    inside = root / "inside"
    inside.mkdir()
    (inside / "test.py").touch()
    outside = root.parent / (root.name + "-outside")
    outside.mkdir()
    (outside / "test.py").touch()
    moved = root / "moved"

    class SwappingRecipes(core.Recipes):
        swapped = False

        def _checkout_entry(self, descriptor, name):
            info = super()._checkout_entry(descriptor, name)
            if name == "inside" and not self.swapped:
                self.swapped = True
                inside.rename(moved)
                symlink_or_skip(outside, inside, target_is_directory=True)
            return info

    local = SwappingRecipes(mailbox_helpers=team_mailbox_primitives)
    value = {"paths": ["inside/test.py"]}
    recipe = {"kind": "command", "steps": [["$paths"]]}
    with refusal("unsafe_path"):
        local.checked_paths(value, recipe, root)
    inside.unlink()
    moved.rename(inside)
    assert local.checked_paths(value, recipe, root) == value["paths"]


def test_checked_paths_symlink_swap_retains_observed_target(tmp_path):
    root = make_store(tmp_path)
    (root / "actual.py").touch()
    outside = root.parent / (root.name + "-outside.py")
    outside.touch()
    link = root / "test.py"
    symlink_or_skip("actual.py", link)

    class SwappingRecipes(core.Recipes):
        swapped = False

        def _checkout_link(self, binding, target):
            plan = super()._checkout_link(binding, target)
            if not self.swapped:
                self.swapped = True
                link.unlink()
                symlink_or_skip(outside, link)
            return plan

    local = SwappingRecipes(mailbox_helpers=team_mailbox_primitives)
    value = {"paths": ["test.py"]}
    recipe = {"kind": "command", "steps": [["$paths"]]}
    assert local.checked_paths(value, recipe, root) == value["paths"]
    with refusal("unsafe_path"):
        local.checked_paths(value, recipe, root)
    link.unlink()
    symlink_or_skip("actual.py", link)
    assert local.checked_paths(value, recipe, root) == value["paths"]


def test_checked_paths_closes_held_directories_after_io_failure(tmp_path):
    root = make_store(tmp_path)
    (root / "inside").mkdir()
    (root / "inside/test.py").touch()
    held = []
    roots = []

    class FailingRecipes(core.Recipes):
        @contextmanager
        def _checkout_root(self, checkout):
            with super()._checkout_root(checkout) as binding:
                roots.extend(binding[2])
                yield binding

        def _checkout_entry(self, descriptor, name):
            held.append(descriptor)
            if name == "test.py":
                raise OSError("untrusted-secret")
            return super()._checkout_entry(descriptor, name)

    local = FailingRecipes(mailbox_helpers=team_mailbox_primitives)
    value = {"paths": ["inside/test.py"]}
    recipe = {"kind": "command", "steps": [["$paths"]]}
    with refusal("io"):
        local.checked_paths(value, recipe, root)
    assert len(held) == 2
    for descriptor in held + roots:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF
    assert api.checked_paths(value, recipe, root) == value["paths"]


@pytest.mark.parametrize("variant", ["loop", "missing", "file_as_directory"])
def test_checked_paths_link_failures_are_typed(tmp_path, variant):
    root = make_store(tmp_path)
    path = "test.py"
    if variant == "loop":
        symlink_or_skip("test.py", root / path)
        expected = "unsafe_path"
    elif variant == "missing":
        symlink_or_skip("absent.py", root / path)
        expected = "invalid_packet"
    else:
        (root / "plain").touch()
        path = "plain/test.py"
        expected = "invalid_packet"
    with refusal(expected):
        api.checked_paths({"paths": [path]}, {"kind": "command", "steps": [["$paths"]]}, root)


def test_read_failure_closes_context_and_valid_retry(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    path = root / "recipes.json"
    path.write_bytes(json.dumps(recipes()).encode())
    original = core.confined_file
    held = []

    @contextmanager
    def failed(base, parts):
        with original(base, parts) as handle:
            held.append(handle)
            yield SimpleNamespace(read_bytes=lambda limit: (_ for _ in ()).throw(OSError("untrusted-secret")))

    monkeypatch.setattr(core, "confined_file", failed)
    with refusal("io"):
        api.load_recipes(path)
    with pytest.raises(storage_confined.ConfinedFileError, match="context is closed"):
        held[0].read_bytes(1)
    monkeypatch.setattr(core, "confined_file", original)
    assert api.load_recipes(path)["schema"] == core.RECIPES_SCHEMA


@pytest.mark.parametrize("failure,error", [
    ("timeout", "the version probe took longer than 30 seconds"),
    ("os", "the version probe could not run"),
    ("unavailable", "the version probe could not run"),
    ("bad_output", "the version probe printed no version"),
    ("exit", "the version probe exited 1"),
])
def test_python_probe_failures_are_fixed_and_retry_succeeds(failure, error):
    def probe(executable, path, timeout):
        if failure == "timeout":
            raise core.ProbeTimeout("untrusted-secret")
        if failure == "os":
            raise OSError("untrusted-secret")
        if failure == "unavailable":
            raise core.ProbeUnavailable("untrusted-secret")
        return SimpleNamespace(stdout=b"untrusted-secret", returncode=1 if failure == "exit" else 0)

    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(lambda _: api.python_info(recipes(), probe=probe), range(3)))
    assert all(row == {"version": None, "executable": recipes()["python"], "error": error} for row in rows)
    retry = lambda executable, path, timeout: SimpleNamespace(stdout=b"3.9.0", returncode=0)
    assert api.python_info(recipes(), probe=retry)["version"] == "3.9.0"


def test_clean_refusal_and_probe_executable_screen_display(monkeypatch):
    secret = "https://user:password@example.invalid/python"
    assert secret in legacy.clean_refusal(secret)
    shown = api.clean_refusal(secret)
    assert "password" not in shown
    value = {**recipes(), "python": "/tmp/" + secret}
    probe = lambda executable, path, timeout: SimpleNamespace(stdout=b"3.12.3", returncode=0)
    monkeypatch.setattr(legacy, "PYTHON_INFO", {value["python"]: {"executable": value["python"], "version": "3.12.3"}})
    assert secret in legacy.python_info(value)["executable"]
    assert "password" not in api.python_info(value, probe=probe)["executable"]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("path/to/file", True),
        ("../file", False),
        ("file//name", False),
        (".", False),
    ],
)
def test_plain_relative_parity(value, expected):
    assert api.plain_relative(value) == legacy.plain_relative(value) == expected


@pytest.mark.parametrize("value", ["$scratch/file", "$scratch/../x", "$scratch/", "word", "$scratch/$x"])
def test_scratch_word_parity(value):
    assert api.scratch_word(value) == legacy.scratch_word(value)


@pytest.mark.parametrize(
    "value", [[], ["rustc"], ["cargo", "+stable", "--offline", "test"], ["cargo", "fmt"], ["echo"]]
)
def test_cargo_step_parity(value):
    assert api.cargo_step(value) == legacy.cargo_step(value)


def test_mailbox_shadow_reader_injected():
    calls = []

    def factory(mailbox, *, mode):
        calls.append((mailbox, mode))
        return "index"

    assert api.mailbox_reader("mailbox", index_factory=factory) == "index"
    assert calls == [("mailbox", "shadow")]
    with refusal("port_required"):
        api.mailbox_reader("mailbox", index_factory=None)


def test_cross_family_helpers_are_injected():
    tree = ast.parse((ROOT / "aegis_core/team_jobs_recipes.py").read_text(encoding="utf-8"))
    imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(name and name.startswith("aegis_core.team_mailbox") for name in imports)


def test_checkout_validation_needs_no_private_store_factory():
    local = core.Recipes(mailbox_helpers=team_mailbox_primitives)
    assert local.checked_paths({"paths": ["deleted.py"]}, {"kind": "commit"}, ROOT) == ["deleted.py"]


def test_request_summary_screens_every_untrusted_field():
    credential = "ghp_" + "a" * 36
    row = {"request_id": credential, "initiative": credential, "kind": credential, "state": credential}
    assert credential in json.dumps(legacy.request_summary(row))
    assert credential not in json.dumps(api.request_summary(row, ledger_kinds=(credential,)))


@pytest.mark.parametrize("delta", ["depth", "nodes", "finite"])
def test_accepted_request_primitive_deltas(delta):
    value = float("inf")
    if delta == "depth":
        value = None
        for _ in range(35):
            value = [value]
    if delta == "nodes":
        value = [[None] * 7 for _ in range(5000)]
    rows = [{"holder": "job", "kind": "heavy", "initiative": "one", "state": "queued", "extra": value}]
    options = dict(kind="heavy", initiative="one", states=("queued",))
    assert legacy.holder_requests(rows, "job", **options) == rows
    with pytest.raises(core.JobRecipesRefusal):
        api.holder_requests(rows, "job", ledger_kinds=("heavy",), **options)


@pytest.mark.parametrize(
    "variant",
    [
        "leaf_symlink",
        "ancestor_symlink",
        "hardlink",
        "writable_directory",
        "in_root_symlink",
        "relative_parent_symlink",
        "absolute_alias_symlink",
        "group_writable_directory",
        "backslash_target",
    ],
)
def test_measured_path_policy_deltas(tmp_path, variant):
    root = make_store(tmp_path)
    checkout = root / "checkout"
    checkout.mkdir()
    target = root / "target.py"
    target.touch()
    if variant == "leaf_symlink":
        symlink_or_skip(target, checkout / "test.py")
    elif variant == "ancestor_symlink":
        actual = root / "actual"
        actual.mkdir()
        (actual / "test.py").touch()
        checkout.rmdir()
        symlink_or_skip(actual, checkout, target_is_directory=True)
    elif variant == "hardlink":
        os.link(target, checkout / "test.py")
    elif variant in ("writable_directory", "group_writable_directory"):
        (checkout / "test.py").touch()
        checkout.chmod(0o777 if variant == "writable_directory" else 0o775)
    elif variant == "in_root_symlink":
        (checkout / "actual.py").touch()
        symlink_or_skip("actual.py", checkout / "test.py")
    elif variant == "relative_parent_symlink":
        (checkout / "nested").mkdir()
        (checkout / "nested/actual.py").touch()
        symlink_or_skip("nested/../nested/actual.py", checkout / "test.py")
    elif variant == "backslash_target":
        (checkout / r"actual\name.py").touch()
        symlink_or_skip(r"actual\name.py", checkout / "test.py")
    else:
        actual = root / "actual"
        actual.mkdir()
        (actual / "actual.py").touch()
        checkout.rmdir()
        symlink_or_skip(actual, checkout, target_is_directory=True)
        symlink_or_skip(checkout / "actual.py", actual / "test.py")
    value = {"paths": ["test.py"]}
    recipe = {"kind": "command", "steps": [["$paths"]]}
    assert legacy.checked_paths(value, recipe, checkout) == ["test.py"]
    if variant == "leaf_symlink":
        with refusal("unsafe_path"):
            api.checked_paths(value, recipe, checkout)
        (checkout / "test.py").unlink()
        (checkout / "test.py").touch()
    assert api.checked_paths(value, recipe, checkout) == ["test.py"]


def test_accepted_folder_root_binding_delta(tmp_path):
    root = make_store(tmp_path)
    actual = root / "actual"
    actual.mkdir()
    link = root / "link"
    symlink_or_skip(actual, link, target_is_directory=True)
    assert legacy.existing_folders([str(link)], "hide") is None
    with refusal("unsafe_path"):
        api.existing_folders([str(link)], "hide")
    assert api.existing_folders([str(actual)], "hide") is None


@pytest.mark.parametrize("variant", ["leaf_symlink", "outside_root"])
def test_measured_kept_report_policy_deltas(tmp_path, variant):
    root = make_store(tmp_path)
    trusted = root / "reports"
    trusted.mkdir()
    outside = root / "outside.xml"
    outside.write_bytes(b'<testsuite tests="1"/>')
    selected = outside
    if variant == "leaf_symlink":
        selected = trusted / "report.xml"
        symlink_or_skip(outside, selected)
    kept = [{"path": core.JUNIT_KEEP, "copy": str(selected)}]
    assert legacy.kept_junit(kept)[0]["passed"] == 1
    with refusal("unsafe_path"):
        api.kept_junit(kept, root=trusted)
    retry = trusted / "retry.xml"
    retry.write_bytes(outside.read_bytes())
    kept = [{"path": core.JUNIT_KEEP, "copy": str(retry)}]
    assert api.kept_junit(kept, root=trusted) == legacy.kept_junit(kept)


@pytest.mark.parametrize(
    "helper,value",
    [("plain_relative", "a" * 32769), ("scratch_word", "$scratch/" + "a" * 4096)],
    ids=["relative_limit", "scratch_limit"],
)
def test_accepted_lexical_path_ceiling_delta(helper, value):
    if helper == "plain_relative":
        assert legacy.plain_relative(value) is True
        with refusal("too_large"):
            api.plain_relative(value)
    else:
        assert legacy.scratch_word(value) is True
        with refusal("too_large"):
            api.scratch_word(value)


def test_accepted_unsupported_descriptor_delta(tmp_path, monkeypatch):
    path = tmp_path / "recipes.json"
    path.write_bytes(json.dumps(recipes()).encode())
    assert legacy.load_recipes(path)["schema"] == core.RECIPES_SCHEMA
    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    with refusal("unsupported_platform"):
        api.load_recipes(path)


@pytest.mark.parametrize("kind", ["command", "commit"])
def test_packet_wire_checks_match_legacy_admit(tmp_path, monkeypatch, kind):
    root = make_store(tmp_path)
    data = recipes()
    value = {**packet(), "checkout": str(root)}
    if kind == "commit":
        data["recipes"]["check"] = {"kind": "commit", "timeout_seconds": 1, "sandbox": "none"}
        value.update(paths=["deleted.py"], expected_tree="c" * 40, message="A commit\n\nBody")
    witness = {
        "source_revision": value["commit"],
        "source_tree": value["tree"],
        "dirty_content_sha256": core.EMPTY_STATUS,
    }
    monkeypatch.setattr(legacy, "source_state", lambda *args, **kwargs: witness)
    monkeypatch.setattr(legacy, "check_paths", lambda *args: (0, {"conflicts": [], "unreadable_checkouts": []}))
    raw = json.dumps(value).encode()
    mailbox = SimpleNamespace(brief=lambda reference: raw)
    admitted, captured = legacy.admit(
        {}, {"id": "one", "checkouts": [str(root)]}, {"brief": "one", "message_id": "message"}, mailbox, data
    )
    assert api.validate_packet(raw, data, registered_checkout=root) == value
    assert {**value, "dirty_content_sha256": core.EMPTY_STATUS, "paths": value.get("paths", [])} == admitted
    assert captured == raw
    for update in ({"recipe": "unknown-secret"}, {"commit": []}, {"tree": "wrong"}, {"extra": "secret"}):
        broken = {**value, **update}
        raw = json.dumps(broken).encode()
        with pytest.raises(ValueError):
            legacy.admit(
                {}, {"id": "one", "checkouts": [str(root)]}, {"brief": "one", "message_id": "message"}, mailbox, data
            )
        with pytest.raises(core.JobRecipesRefusal):
            api.validate_packet(raw, data, registered_checkout=root)
