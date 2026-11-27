"""aegis_core.pathlookup: the one lookup of a program on PATH (host-matrix §3.7).

Aegis starts what this finds (a host CLI, python3) and writes the aegis-mcp it finds
into a host's config, from inside a repository the user may just have cloned. So only
absolute PATH entries count: an empty or relative entry names the current directory,
where the repository can plant a program. An absolute entry inside a fence (the
workspace, for doctor) does not count either. ``only_skipped`` reports where a program
is reachable when every one of those places was refused, so a caller never reports a
host it passed over as plainly absent.
"""
from __future__ import annotations

from tests.helpers_pathlookup import (
    clean_host_os, governed_module_session, governed_module_state, monkeypatch, pathlookup_patch_writes,
)

import contextlib
from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from aegis_cli import cli
from aegis_core import pathlookup, pathlookup_gitcache
from aegis_core import gitsafe as bound_git
from aegis_mcp import server
from aegis_core.pathlookup import Hit, only_skipped, which
from tests import helpers_pathlookup as pathlookup_helpers

EXE = ".exe" if os.name == "nt" else ""


def test_pathlookup_module_patches_are_auto_restored():
    assert pathlookup_patch_writes(Path(__file__).resolve().parents[3]) == []


def test_pathlookup_import_parses_each_tracked_source_once():
    from tests.helpers_reviewed_sources import run_isolated_test

    program = (
        "import ast, sys\n"
        "from pathlib import Path\n"
        "root = Path(sys.argv[2])\n"
        "counts = dict.fromkeys((str(root / 'tests/unit/core/test_pathlookup.py'),\n"
        "                        str(root / 'tests/helpers_pathlookup.py')), 0)\n"
        "def count_parse(event, args):\n"
        "    if event == 'compile' and args[1] in counts:\n"
        "        if sys._getframe(1).f_code is ast.parse.__code__:\n"
        "            counts[args[1]] += 1\n"
        "sys.addaudithook(count_parse)\n"
        "from tests import helpers_pathlookup\n"
        "assert list(counts.values()) == [1, 1], counts\n"
    )
    result = run_isolated_test(program, Path(__file__).resolve().parents[3])
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


@pytest.mark.parametrize("mark", [
    "skip(reason='workload cut')",
    "skipif(True, reason='workload cut')",
    "xfail(reason='unverified')",
    "parametrize('missing', [])",
])
def test_static_contract_refuses_disabling_mark_on_the_proof_suite(tmp_path, mark):
    source = (f"pytestmark = pytest.mark.{mark}\n"
              "def test_additional_pathlookup_rules_in_child():\n"
              "    pass\n")
    status, output = _run_static_source_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "pathlookup proof suite cannot use a disabling module mark" in output


def test_static_contract_keeps_original_refusal_before_proof_suite_mark_check(tmp_path):
    relative = "tests/unit/core/test_pathlookup.py"
    source = ("import os, pytest\npytestmark = pytest.mark.skipif(os.name != 'nt', reason='modeled')\n"
              "def test_additional_pathlookup_rules_in_child():\n"
              "    pass\n")
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, 2, "pytest marks require a direct reviewed decorator")]


def test_pathlookup_batch_fails_if_a_diagnostic_does_not_match(tmp_path):
    cases = {
        "consumer-import-order": ("pathlookup_import_order", "tests/unit/core/test_pathlookup.py",
                                  "import os\n", 1, "helper import must be the first executable statement"),
        "helper-bootstrap": ("pathlookup_import_order", "tests/helpers_pathlookup.py",
                             "import sys\n", 1, "wrong diagnostic"),
    }
    result = _run_pathlookup_proof_batch(_pathlookup_batch_rows(tmp_path, cases))
    assert result.returncode == 1, result.stderr.decode("utf-8", "replace")
    assert result.stdout == b""
    assert "AssertionError" in result.stderr.decode("utf-8", "replace")


@pytest.fixture
def module():
    """Use one child target per case unless a representative proof overrides it."""
    return "pathlookup"


def _run_pathlookup_guard_child(case, configuration, root, *, deselect=False, import_path=None):
    from tests.helpers_reviewed_sources import run_isolated_test

    options = ["-k", "no_matching_case"] if deselect else []
    program = (
        "import pytest, sys\n"
        "raise SystemExit(pytest.main(['-q', '-c', sys.argv[3], '--confcutdir', sys.argv[4], "
        "'-o', 'addopts=', sys.argv[2]] + " + repr(options) + "))\n"
    )
    result = run_isolated_test(program, case, configuration, root, import_path=import_path,
        env={**os.environ, "PYTEST_ADDOPTS": "", "PYTHONDONTWRITEBYTECODE": "1",
             "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
    stdout = result.stdout.decode("utf-8", "replace")
    return result.returncode, stdout + result.stderr.decode("utf-8", "replace")


def _run_runtime_guard_case(tmp_path, module, source, *, before_helper=""):
    configuration = tmp_path / "pytest.ini"
    configuration.write_text("[pytest]\n", encoding="utf-8")
    case = tmp_path / "test_runtime_guard_case.py"
    case.write_text(
        before_helper + "from tests.helpers_pathlookup import "
        "governed_module_session, governed_module_state, monkeypatch\n"
        "import pytest\nfrom types import SimpleNamespace\n"
        f"import aegis_core\nfrom aegis_core import {module} as target\n" + source,
        encoding="utf-8",
    )
    return _run_pathlookup_guard_child(case, configuration, tmp_path)


def _runtime_warning_source():
    return (
        "import warnings\n"
        "def emit_warning(action='default'):\n"
        "    namespace = vars(target)\n"
        "    with warnings.catch_warnings(record=True) as caught:\n"
        "        warnings.simplefilter(action)\n"
        "        warnings.warn_explicit('governed module warning', UserWarning, target.__file__, 1,\n"
        "            module=target.__name__, module_globals=namespace,\n"
        "            registry=namespace.setdefault('__warningregistry__', {}))\n"
        "    assert len(caught) == 1\n"
        "    assert '__warningregistry__' in namespace\n"
    )


@pytest.mark.parametrize("timing", ["body", "module_finalizer"])
def test_runtime_guard_accepts_warning_registry_and_warning_failure_retry(tmp_path, module, timing):
    source = _runtime_warning_source()
    if timing == "module_finalizer":
        source += ("@pytest.fixture(scope='module', autouse=True)\n"
                   "def warning_after_tests(governed_module_session):\n    yield\n    emit_warning()\n")
        source += "def test_case():\n    pass\ndef test_retry():\n    pass\n"
    else:
        source += ("def test_case():\n    emit_warning()\n"
                   "def test_retry():\n"
                   "    with pytest.raises(UserWarning, match='governed module warning'):\n"
                   "        emit_warning('error')\n    emit_warning()\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.OK, output
    assert "2 passed" in output


@pytest.mark.parametrize("module", ["pathlookup", "gitsafe", "primitives"])
def test_runtime_guard_accepts_warning_registry_removal_and_recreation(tmp_path, module):
    before = f"from aegis_core import {module} as target\n" + _runtime_warning_source() + "emit_warning()\n"
    source = ("def test_removed():\n    del target.__warningregistry__\n"
              "def test_recreated():\n    emit_warning()\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source, before_helper=before)
    assert status == pytest.ExitCode.OK, output
    assert "2 passed" in output


@pytest.mark.parametrize("attribute,kind", [
    ("__doc__", "replaced"), ("__warningregistry___", "added"), ("_warningregistry", "added"),
])
def test_runtime_guard_warning_registry_exemption_preserves_real_write_failures(tmp_path, module, attribute, kind):
    source = _runtime_warning_source() + f"def test_case():\n    emit_warning()\n    target.{attribute} = object()\n"
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert f"aegis_core.{module}.{attribute} {kind}" in output
    assert f"aegis_core.{module}.__warningregistry__ added" not in output


def test_runtime_guard_warning_registries_are_independent_in_concurrent_children_and_retries(tmp_path):
    source = _runtime_warning_source() + "def test_case():\n    emit_warning()\n"
    roots = [tmp_path / name for name in ("left", "right")]
    for root in roots:
        root.mkdir()
    for _ in range(2):
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(_run_runtime_guard_case, root, module, source)
                       for root, module in zip(roots, ("pathlookup", "gitsafe"))]
            results = [future.result(timeout=30) for future in futures]
        for status, output in results:
            assert status == pytest.ExitCode.OK, output
            assert "1 passed" in output


def _runtime_guard_example(module, form):
    from textwrap import indent

    if form.endswith("comprehension") or form == "generator_expression":
        expression = {
            "list_comprehension": "[lookup.name for lookup in inputs]",
            "set_comprehension": "{lookup.name for lookup in inputs}",
            "dict_comprehension": "{lookup.name: None for lookup in inputs}",
            "generator_expression": "(lookup.name for lookup in inputs)",
        }[form]
        return (f"from aegis_core import {module} as lookup\n"
                "def test_case():\n    modeled = object()\n    inputs = [SimpleNamespace(name='owned')]\n"
                f"    names = {expression}\n    lookup.os = modeled\n")
    if form == "global_import":
        return ("def load():\n    global lookup\n"
                f"    from aegis_core import {module} as lookup\n"
                "def test_case():\n    load()\n    lookup.os = object()\n")
    if form == "nonlocal_import":
        return ("def test_case():\n    lookup = None\n    def load():\n        nonlocal lookup\n"
                f"        from aegis_core import {module} as lookup\n"
                "    load()\n    lookup.os = object()\n")
    body = {
        "annotated": "lookup: object = target\nlookup.os = modeled\n",
        "walrus": "if (lookup := target):\n    lookup.os = modeled\n",
        "tuple": "lookup, saved = target, target.os\nlookup.os = modeled\n",
        "list": "[lookup, saved] = [target, target.os]\nlookup.os = modeled\n",
        "attribute_lookup": f"lookup = getattr(aegis_core, '{module}')\nlookup.os = modeled\n",
    }[form]
    return "def test_case():\n    modeled = object()\n" + indent(body, "    ")


@pytest.mark.parametrize("form", [
    "annotated", "walrus", "tuple", "list", "list_comprehension", "set_comprehension",
    "dict_comprehension", "generator_expression", "global_import", "nonlocal_import", "attribute_lookup",
])
def test_runtime_guard_rejects_unrestored_reviewer_forms(tmp_path, module, form):
    status, output = _run_runtime_guard_case(tmp_path, module, _runtime_guard_example(module, form))
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert f"aegis_core.{module}.os replaced" in output
    assert "1 passed, 1 error" in output


@pytest.mark.parametrize("module", ["pathlookup", "gitsafe", "primitives"])
def test_runtime_guard_names_all_added_removed_and_replaced_attributes(tmp_path, module):
    source = ("def test_case():\n    target._runtime_probe = object()\n"
              "    del target.os\n    target.__doc__ = object()\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    for attribute, kind in (("_runtime_probe", "added"), ("os", "removed"), ("__doc__", "replaced")):
        assert f"aegis_core.{module}.{attribute} {kind}" in output


def test_runtime_guard_compares_identity_instead_of_equality(tmp_path, module):
    source = ("class Equal:\n    def __eq__(self, other):\n        return True\n"
              "def test_case():\n    target.os = Equal()\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert f"aegis_core.{module}.os replaced" in output


def test_runtime_guard_rejects_module_class_replacement(tmp_path, module):
    source = ("from types import ModuleType\nclass Replacement(ModuleType):\n    pass\n"
              "def test_case():\n    target.__class__ = Replacement\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert f"aegis_core.{module}.__class__ replaced" in output


@pytest.mark.parametrize("module", ["pathlookup", "gitsafe", "primitives"])
def test_runtime_guard_runs_after_consumer_and_monkeypatch_teardown(tmp_path, module):
    source = (
        "original = target.os\nmodeled = object()\n"
        "@pytest.fixture\ndef consumer(monkeypatch):\n"
        f"    monkeypatch.setattr('aegis_core.{module}.os', modeled)\n"
        "    yield\n    assert target.os is modeled\n"
        "def test_case(consumer):\n    assert target.os is modeled\n"
        "def test_next_case():\n    assert target.os is original\n"
    )
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.OK, output
    assert "2 passed" in output


def test_runtime_guard_restores_after_a_failed_test_body(tmp_path, module):
    source = ("def test_case(monkeypatch):\n"
              f"    monkeypatch.setattr('aegis_core.{module}.os', object())\n"
              "    raise RuntimeError('intentional body failure')\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert "intentional body failure" in output
    assert "1 failed" in output
    assert "unrestored governed module attributes" not in output
    assert "1 error" not in output


def test_runtime_guard_restores_after_consumer_teardown_failure(tmp_path, module):
    source = ("@pytest.fixture\ndef consumer(monkeypatch):\n"
              f"    monkeypatch.setattr('aegis_core.{module}.os', object())\n"
              "    yield\n    raise RuntimeError('intentional teardown failure')\n"
              "def test_case(consumer):\n    pass\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert "intentional teardown failure" in output
    assert "1 passed, 1 error" in output
    assert "unrestored governed module attributes" not in output


def test_runtime_guard_accepts_hand_restoration(tmp_path, module):
    source = ("def test_case():\n    original = target.os\n"
              "    target.os = object()\n    target.os = original\n")
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.OK, output
    assert "1 passed" in output


@pytest.mark.parametrize("timing", ["collection", "module_setup", "module_finalizer"])
def test_runtime_guard_rejects_writes_outside_function_scope(tmp_path, module, timing):
    write = "lookup: object = target\nlookup.os = object()\nlookup.__doc__ = object()\n"
    if timing == "collection":
        source = write + "def test_case():\n    pass\n"
    else:
        from textwrap import indent

        source = (
            '@pytest.fixture(scope="module", autouse=True)\n'
            "def modeled_host():\n"
            + ("    yield\n" if timing == "module_finalizer" else "")
            + indent(write, "    ")
            + "def test_case():\n    pass\n"
        )
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert f"aegis_core.{module}.os replaced" in output
    assert f"aegis_core.{module}.__doc__ replaced" in output


def test_runtime_guard_documents_pre_helper_trust_boundary(tmp_path, module):
    before = (f"from aegis_core import {module} as early\n"
              "preloaded = object()\nearly.__doc__ = preloaded\n")
    source = "def test_case():\n    assert target.__doc__ is preloaded\n"
    status, output = _run_runtime_guard_case(tmp_path, module, source, before_helper=before)
    assert status == pytest.ExitCode.OK, output
    assert "1 passed" in output
    assert "first import" in pathlookup_helpers.__doc__
    assert "opt-in global guard" in pathlookup_helpers.__doc__


@pytest.mark.parametrize("scope", ["module", "class", "package", "session"])
def test_runtime_guard_accepts_live_owned_broader_contexts_and_undo(tmp_path, scope):
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        "original = target.os\nmodeled = object()\n"
        f"@pytest.fixture(scope={scope!r})\ndef broader(request):\n"
        "    with owned_module_patch(request) as patch:\n"
        "        patch.setattr(target, 'os', modeled)\n        yield patch\n"
        "class TestOwned:\n"
        "    def test_first(self, broader, monkeypatch):\n"
        "        assert target.os is modeled\n"
        "        monkeypatch.setattr('aegis_core.pathlookup.os', object())\n"
        "    def test_retry(self, broader):\n        assert target.os is modeled\n"
        "def test_after_context():\n"
        + ("    assert target.os is original\n" if scope == "class" else "    pass\n")
    )
    status, output = _run_runtime_guard_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.OK, output
    assert "3 passed" in output


@pytest.mark.parametrize("owned", [True, False])
def test_runtime_guard_rejects_writes_unowned_by_a_live_context(tmp_path, owned):
    context = "owned_module_patch(request)" if owned else "pytest.MonkeyPatch.context()"
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        '@pytest.fixture(scope="module", autouse=True)\ndef broader(request):\n'
        f"    with {context} as patch:\n"
        "        patch.setattr(target, 'os', object())\n"
        + ("        target.__doc__ = object()\n" if owned else "")
        + "        yield\ndef test_case():\n    pass\n"
    )
    status, output = _run_runtime_guard_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    attribute = "__doc__" if owned else "os"
    assert f"aegis_core.pathlookup.{attribute} replaced" in output


@pytest.mark.parametrize("timing", ["setup", "teardown"])
def test_runtime_guard_owned_context_restores_after_failure_and_retry(tmp_path, timing):
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        "original = target.os\n"
        '@pytest.fixture(scope="class")\ndef broader(request):\n'
        "    with owned_module_patch(request) as patch:\n"
        "        patch.setattr(target, 'os', object())\n"
        + ("        raise RuntimeError('owned setup failure')\n" if timing == "setup" else "")
        + "        yield\n"
        + ("        raise RuntimeError('owned teardown failure')\n" if timing == "teardown" else "")
        + "class TestFailure:\n    def test_case(self, broader):\n        pass\n"
        "def test_retry():\n    assert target.os is original\n"
    )
    status, output = _run_runtime_guard_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert f"owned {timing} failure" in output
    assert "unrestored governed module attributes" not in output
    assert "1 error" in output
    assert ("1 passed" if timing == "setup" else "2 passed") in output


def test_runtime_guard_owned_contexts_are_independent_in_concurrent_workers(tmp_path):
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        '@pytest.fixture(scope="module", autouse=True)\ndef broader(request):\n'
        "    with owned_module_patch(request) as patch:\n"
        "        patch.setattr(target, 'os', object())\n        yield\n"
        "def test_case():\n    pass\n"
    )
    roots = [tmp_path / name for name in ("left", "right")]
    for root in roots:
        root.mkdir()
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(_run_runtime_guard_case, root, module, source)
                   for root, module in zip(roots, ("pathlookup", "gitsafe"))]
        results = [future.result(timeout=120) for future in futures]
    for status, output in results:
        assert status == pytest.ExitCode.OK, output
        assert "1 passed" in output


def test_runtime_guard_owned_context_rejects_invalid_targets_and_closed_reuse(tmp_path):
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        "original = target.os\n"
        '@pytest.fixture(scope="module", autouse=True)\ndef broader(request):\n'
        "    with owned_module_patch(request) as patch:\n"
        "        with pytest.raises(ValueError, match='^owned module patches require a governed module$'):\n"
        "            patch.setattr(SimpleNamespace(os=original), 'os', object())\n"
        "        for name in ('__class__', '__dict__', None):\n"
        "            with pytest.raises(ValueError, match='^owned module patches require a module namespace attribute$'):\n"
        "                patch.setattr(target, name, object())\n"
        "        with pytest.raises(AttributeError, match=\"has no attribute '_missing_owned_probe'\"):\n"
        "            patch.setattr(target, '_missing_owned_probe', object())\n"
        "        patch.setattr(target, 'os', original)\n"
        "    with pytest.raises(RuntimeError, match='^owned module patch context is closed$'):\n"
        "        patch.setattr(target, 'os', object())\n"
        "    yield\n"
        "def test_case(request):\n"
        "    with pytest.raises(ValueError, match='^owned module patches require a broader-scope fixture$'):\n"
        "        with owned_module_patch(request):\n            pass\n"
        "    assert target.os is original\n"
    )
    status, output = _run_runtime_guard_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.OK, output
    assert "1 passed" in output


def test_runtime_guard_nested_owned_contexts_restore_deleted_bindings_and_retry(tmp_path):
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        "original = target.os\ndoc = target.__doc__\nmodeled = object()\n"
        '@pytest.fixture(scope="module", autouse=True)\ndef broader(request):\n'
        "    with owned_module_patch(request) as outer:\n"
        "        outer.setattr(target, 'os', modeled)\n"
        "        with owned_module_patch(request) as inner:\n"
        "            inner.delattr(target, '__doc__')\n            yield\n"
        "        assert target.os is modeled\n        assert target.__doc__ is doc\n"
        "        with owned_module_patch(request) as retry:\n"
        "            retry.setattr(target, 'os', object())\n"
        "        assert target.os is modeled\n"
        "    assert target.os is original\n"
        "def test_case():\n    assert target.os is modeled\n"
        "def test_retry():\n    assert target.os is modeled\n"
    )
    status, output = _run_runtime_guard_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.OK, output
    assert "2 passed" in output


@pytest.mark.parametrize("module,operation,inner_operation", [
    ("pathlookup", "setattr", "setattr"),
    ("gitsafe", "setattr", "setattr"),
    ("primitives", "setattr", "setattr"),
    ("pathlookup", "setattr", "delattr"),
    ("pathlookup", "delattr", "setattr"),
    ("pathlookup", "delattr", "delattr"),
])
def test_owned_context_refuses_outer_write_to_inner_binding_before_mutation(tmp_path, module, operation, inner_operation):
    attempted = ("outer.setattr(target, '__doc__', third)" if operation == "setattr"
                 else "outer.delattr(target, '__doc__')")
    initial = ("inner.setattr(target, '__doc__', second)" if inner_operation == "setattr"
               else "inner.delattr(target, '__doc__')")
    unchanged = ("target.__doc__ is second" if inner_operation == "setattr"
                 else "'__doc__' not in vars(target)")
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        "original = target.__doc__\nfirst, second, third = object(), object(), object()\n"
        '@pytest.fixture(scope="module", autouse=True)\n'
        "def broader(request, governed_module_session):\n"
        "    with owned_module_patch(request) as outer:\n"
        "        outer.setattr(target, '__doc__', first)\n"
        "        with owned_module_patch(request) as inner:\n"
        f"            {initial}\n"
        "            with pytest.raises(ValueError, match='^owned module patch cannot shadow a newer live context$'):\n"
        f"                {attempted}\n"
        f"            assert {unchanged}\n            yield\n"
        "        assert target.__doc__ is first\n"
        "        outer.setattr(target, '__doc__', third)\n"
        "        assert target.__doc__ is third\n"
        "    assert target.__doc__ is original\n"
        f"def test_case():\n    assert {unchanged}\n"
        f"def test_retry():\n    assert {unchanged}\n"
    )
    status, output = _run_runtime_guard_case(tmp_path, module, source)
    assert status == pytest.ExitCode.OK, output
    assert "2 passed" in output


@pytest.mark.parametrize("phase", ["class_finalizer", "closed_context", "same_binding"])
def test_runtime_guard_session_and_owned_checks_do_not_allow_late_or_unrecorded_writes(tmp_path, phase):
    source = "from tests.helpers_pathlookup import owned_module_patch\n"
    if phase == "class_finalizer":
        source += ('@pytest.fixture(scope="class")\ndef broader():\n'
                   "    yield\n    target.__doc__ = object()\n")
    elif phase == "closed_context":
        source += ('@pytest.fixture(scope="module")\ndef broader(request):\n'
                   "    with owned_module_patch(request) as patch:\n"
                   "        patch.setattr(target, '__doc__', object())\n"
                   "    target.__doc__ = object()\n    yield\n")
    else:
        source += ('@pytest.fixture(scope="module")\ndef broader(request):\n'
                   "    with owned_module_patch(request) as patch:\n"
                   "        patch.setattr(target, '__doc__', object())\n"
                   "        target.__doc__ = object()\n        yield\n")
    source += "class TestCase:\n    def test_case(self, broader):\n        pass\n"
    status, output = _run_runtime_guard_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert "aegis_core.pathlookup.__doc__ replaced" in output


def test_runtime_guard_refuses_leaked_owned_context(tmp_path):
    source = (
        "from tests.helpers_pathlookup import owned_module_patch\n"
        "contexts = []\n"
        "@pytest.fixture(scope='module')\n"
        "def leaked_context(request):\n"
        "    context = owned_module_patch(request)\n"
        "    context.__enter__()\n"
        "    contexts.append(context)\n"
        "def test_case(leaked_context):\n"
        "    pass\n"
    )
    status, output = _run_runtime_guard_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.TESTS_FAILED, output
    assert "owned governed module patch contexts left open" in output


def _pathlookup_batch_rows(tmp_path, cases):
    rows = []
    for rule, (checker, relative, source, line, message) in cases.items():
        root = tmp_path / rule
        if checker == "pathlookup_patch_writes":
            _patch_guard_sources(root, relative, source)
        else:
            _import_order_sources(root, relative, source)
        rows.append((str(root), checker, relative, line, message))
    return rows


def _run_pathlookup_proof_batch(rows):
    import json

    from tests.helpers_reviewed_sources import run_isolated_test

    program = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "from tests import helpers_pathlookup as guards\n"
        "for root, checker, relative, line, message in json.loads(sys.argv[2]):\n"
        "    errors = getattr(guards, checker)(Path(root))\n"
        "    assert errors == [(relative, line, message)], (Path(root).name, errors)\n"
    )
    return run_isolated_test(program, json.dumps(rows))


def test_additional_pathlookup_rules_in_child(tmp_path):
    consumer = "tests/unit/core/test_pathlookup.py"
    helper = "tests/helpers_pathlookup.py"
    imports = "pathlookup_import_order"
    collection = "pathlookup_source_contract_errors"
    cases = {
        "consumer-import-order": (imports, consumer, "import os\n", 1,
                                  "helper import must be the first executable statement"),
        "helper-bootstrap": (imports, helper, "import sys\n", 1,
                             "helper bootstrap must precede executable code"),
        "helper-adjacent-baseline": (imports, helper, "from aegis_core import gitsafe, pathlookup, primitives\n", 1,
                                     "governed import must immediately capture the baseline"),
        "helper-missing-baseline": (imports, helper, "import ast\n", 1,
                                    "helper import-time baseline is missing"),
        "fixture-scope": (collection, consumer, "import pytest\n@pytest.fixture(scope=scope)\n"
                          "def value():\n    pass\n", 3, "fixture scope must be a literal supported pytest scope"),
        "decorator-factory": (collection, consumer, "@outside\ndef test_case():\n    pass\n", 1,
                               "collection-time decorator requires a reviewed factory"),
        "contextmanager-declaration": (collection, consumer, "from contextlib import contextmanager\n"
                                       "@contextmanager()\ndef callback():\n    yield\n", 2,
                                       "contextmanager must directly decorate a definition"),
        "parametrize-expansion": (collection, consumer, "import pytest\n@pytest.mark.parametrize(*arguments)\n"
                                   "def test_case():\n    pass\n", 2, "parametrize arguments must make ids explicit"),
        "decorator-arguments": (collection, consumer, "import os, pytest\n"
                                "@pytest.mark.skipif(os.getcwd(), reason='modeled')\ndef test_case():\n    pass\n",
                                2, "decorator arguments must use the reviewed grammar"),
        "direct-mark": (collection, consumer, "import pytest\npytestmark = pytest.mark.skip.with_args()\n",
                         2, "pytest marks require a direct reviewed decorator"),
        "factory-import": (collection, consumer, "from custom import other as property\n", 1,
                            "collection factory import must keep its standard binding"),
        "factory-binding": (collection, consumer, "property = None\n", 1, "collection factory binding cannot be replaced"),
        "collection-call": (collection, consumer, "callback()\n", 1,
                            "collection-time call requires a reviewed helper shape"),
        "class-base": (collection, consumer, "class Example(outside):\n    pass\n", 1,
                       "collection class requires a standard base without a metaclass"),
        "collection-body": (collection, consumer, "pass\n", 1,
                            "collection body statement is outside the reviewed grammar"),
        "governed-module-write": ("pathlookup_patch_writes", consumer,
                                  "from aegis_core import gitsafe\n"
                                  "def test_case():\n    gitsafe.os = None\n", 3, "gitsafe.os"),
    }
    result = _run_pathlookup_proof_batch(_pathlookup_batch_rows(tmp_path, cases))
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def _import_order_sources(root, relative, source):
    repository = Path(__file__).resolve().parents[3]
    for name in ("tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source if name == relative else (repository / name).read_text(encoding="utf-8"),
                        encoding="utf-8")


def test_pathlookup_import_order_guards_both_real_sources():
    assert pathlookup_helpers.pathlookup_import_order(Path(__file__).resolve().parents[3]) == []


def _run_static_source_case(tmp_path, module, source, *, deselect=False):
    repository = Path(__file__).resolve().parents[3]
    helper = tmp_path / "tests" / "helpers_pathlookup.py"
    helper.parent.mkdir(parents=True)
    helper.write_text((repository / "tests/helpers_pathlookup.py").read_text(encoding="utf-8"),
                      encoding="utf-8")
    # Keep the copied helper first while retaining the ordinary tests bootstrap.
    (helper.parent / "__init__.py").write_text(
        f"__path__.append({str(repository / 'tests')!r})\n", encoding="utf-8")
    case = tmp_path / "tests/unit/core/test_pathlookup.py"
    case.parent.mkdir(parents=True)
    case.write_text(
        "from tests.helpers_pathlookup import "
        "governed_module_session, governed_module_state, monkeypatch\n"
        "import pytest\n"
        f"from aegis_core import {module} as lookup\n" + source, encoding="utf-8")
    configuration = tmp_path / "pytest.ini"
    configuration.write_text("[pytest]\n", encoding="utf-8")
    return _run_pathlookup_guard_child(case, configuration, tmp_path, deselect=deselect,
                                      import_path=[str(tmp_path), *sys.path])


def test_static_contract_refuses_undeclared_session_finalizer(tmp_path, module):
    source = ('@pytest.fixture(scope="session", autouse=True)\n'
              "def aaa_modeled_host():\n    yield\n    alias: object = lookup\n"
              "    alias.__doc__ = 'modeled'\n"
              "def test_case():\n    pass\n")
    status, output = _run_static_source_case(tmp_path, module, source)
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "broader fixture must request governed_module_session" in output


@pytest.mark.parametrize("module,selection", [
    ("pathlookup", "skipped"),
    ("gitsafe", "deselected"),
    ("primitives", "deselected"),
])
def test_static_contract_refuses_collection_write_without_running_tests(tmp_path, module, selection):
    source = ("alias: object = lookup\nalias.__doc__ = 'modeled'\n"
              + ('pytestmark = pytest.mark.skip(reason="capability unavailable")\n' if selection == "skipped" else "")
              + "def test_case():\n    pass\n")
    status, output = _run_static_source_case(tmp_path, module, source, deselect=selection == "deselected")
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "collection-time attribute write" in output


@pytest.mark.parametrize("selection", ["skipped", "deselected"])
@pytest.mark.parametrize("location", ["module", "class"])
def test_static_contract_refuses_collection_hook_before_skip_or_deselection(tmp_path, module, selection, location):
    source = ('pytestmark = pytest.mark.skip(reason="capability unavailable")\n' if selection == "skipped" else "")
    if location == "module":
        source += ("def pytest_generate_tests(metafunc):\n"
                   "    alias: object = lookup\n    alias.__doc__ = 'modeled'\n"
                   "def test_case():\n    pass\n")
    else:
        source += ("class TestHook:\n"
                   "    def pytest_generate_tests(self, metafunc):\n"
                   "        alias: object = lookup\n        alias.__doc__ = 'modeled'\n"
                   "    def test_case(self):\n        pass\n")
    status, output = _run_static_source_case(tmp_path, module, source, deselect=selection == "deselected")
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "pytest_* collection hooks are forbidden" in output


@pytest.mark.parametrize("selection", ["skipped", "deselected"])
@pytest.mark.parametrize("factory", ["parametrize", "fixture"])
def test_static_contract_refuses_callable_ids_before_skip_or_deselection(tmp_path, module, selection, factory):
    source = ('pytestmark = pytest.mark.skip(reason="capability unavailable")\n' if selection == "skipped" else "")
    source += ("def generated_id(value):\n    alias: object = lookup\n"
               "    alias.__doc__ = 'modeled'\n    return 'case'\n")
    if factory == "parametrize":
        source += ("@pytest.mark.parametrize('value', [1], ids=generated_id)\n"
                   "def test_case(value):\n    pass\n")
    else:
        source += ("@pytest.fixture(params=[1], ids=generated_id)\n"
                   "def value(request):\n    return request.param\n"
                   "def test_case(value):\n    pass\n")
    status, output = _run_static_source_case(tmp_path, module, source, deselect=selection == "deselected")
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "ids must use the reviewed decorator grammar" in output


@pytest.mark.parametrize("selection", ["skipped", "deselected"])
@pytest.mark.parametrize("imports,factory", [
    ("import pytest", "pytest.fixture"),
    ("import pytest as p", "p.fixture"),
    ("from pytest import fixture as register", "register"),
])
def test_static_contract_refuses_functional_fixture_registration(tmp_path, module, selection, imports, factory):
    source = (imports + "\n"
              + ('pytestmark = pytest.mark.skip(reason="capability unavailable")\n' if selection == "skipped" else "")
              + "def aaa_modeled_host():\n    yield\n    alias: object = lookup\n"
              "    alias.__doc__ = 'modeled'\n"
              f"aaa_modeled_host = {factory}(aaa_modeled_host, scope='session', autouse=True)\n"
              "def test_case():\n    pass\n")
    status, output = _run_static_source_case(tmp_path, module, source, deselect=selection == "deselected")
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "fixture registration must decorate a function definition" in output


@pytest.mark.parametrize("selection", ["skipped", "deselected"])
def test_static_contract_refuses_stored_fixture_before_skip_or_deselection(tmp_path, module, selection):
    source = ("register = pytest.fixture\n"
              "def aaa_modeled_host():\n    yield\n    alias: object = lookup\n"
              "    alias.__doc__ = 'modeled'\n"
              "aaa_modeled_host = register(aaa_modeled_host, scope='session', autouse=True)\n"
              + ('pytestmark = pytest.mark.skip(reason="capability unavailable")\n' if selection == "skipped" else "")
              + "def test_case():\n    pass\n")
    status, output = _run_static_source_case(tmp_path, module, source, deselect=selection == "deselected")
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "fixture registration must decorate a function definition" in output


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
@pytest.mark.parametrize("imports,factory", [
    ("import pytest", "pytest.fixture"),
    ("import pytest as p", "p.fixture"),
    ("from pytest import fixture as register", "register"),
    ("from pytest import fixture", "fixture"),
])
@pytest.mark.parametrize("statement,line", [
    ("factory = FACTORY\n", 2),
    ("factories = [FACTORY]\n", 2),
    ("def configure(register=FACTORY):\n    pass\n", 2),
    ("def deferred():\n    factory = FACTORY\n", 3),
    ("factory: object = FACTORY\n", 2),
    ("factory = (FACTORY,)\n", 2),
])
def test_static_contract_refuses_fixture_references_outside_decorators(tmp_path, relative, imports, factory, statement, line):
    _import_order_sources(tmp_path, relative, imports + "\n" + statement.replace("FACTORY", factory))
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, line, "fixture registration must decorate a function definition")]


@pytest.mark.parametrize("imports,factory", [
    ("import pytest", "pytest.fixture"),
    ("import pytest as p", "p.fixture"),
    ("from pytest import fixture as register", "register"),
    ("from pytest import fixture", "fixture"),
])
@pytest.mark.parametrize("arguments", ["", "()"])
def test_static_contract_accepts_direct_fixture_decorators(tmp_path, imports, factory, arguments):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative,
        f"{imports}\n@{factory}{arguments}\ndef declared():\n    pass\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == []


def test_static_contract_fixture_refusal_retries_and_keeps_concurrent_roots_independent(tmp_path):
    relative = "tests/unit/core/test_pathlookup.py"
    roots = [tmp_path / name for name in ("left", "right")]
    invalid = "import pytest\nfactory = pytest.fixture\n"
    valid = "import pytest\n@pytest.fixture\ndef declared():\n    pass\n"
    for _ in range(2):
        _import_order_sources(roots[0], relative, invalid)
        _import_order_sources(roots[1], relative, valid)
        with ThreadPoolExecutor(max_workers=2) as workers:
            bad, good = workers.map(pathlookup_helpers.pathlookup_source_contract_errors, roots, timeout=5)
        assert bad == [(relative, 2, "fixture registration must decorate a function definition")]
        assert good == []
        _import_order_sources(roots[0], relative, valid)
        assert pathlookup_helpers.pathlookup_source_contract_errors(roots[0]) == []


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
@pytest.mark.parametrize("source,line", [
    ("def pytest_generate_tests(metafunc):\n    pass\n", 1),
    ("class TestHook:\n    def pytest_generate_tests(self, metafunc):\n        pass\n", 2),
    ("async def pytest_collection_modifyitems(items):\n    pass\n", 1),
    ("pytest_generate_tests = callback\n", 1),
    ("from callbacks import generate as pytest_generate_tests\n", 1),
])
def test_static_contract_refuses_all_collection_hook_bindings(tmp_path, relative, source, line):
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, line, "pytest_* collection hooks are forbidden")]


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
@pytest.mark.parametrize("factory", ["parametrize", "fixture"])
@pytest.mark.parametrize("value", ["callback", "lambda value: 'case'", "[f'{value}']", "[*names]"])
def test_static_contract_refuses_nonliteral_id_arguments(tmp_path, relative, factory, value):
    decorator = (f"pytest.mark.parametrize('value', [1], ids={value})" if factory == "parametrize"
                 else f"pytest.fixture(params=[1], ids={value})")
    _import_order_sources(tmp_path, relative,
        "import pytest\n@" + decorator + "\ndef declared(value):\n    pass\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, 2, "ids must use the reviewed decorator grammar")]


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
@pytest.mark.parametrize("factory", ["parametrize", "fixture"])
@pytest.mark.parametrize("value", ["None", "'case'", "[1]", "['case', None]"])
def test_closed_collection_accepts_literal_ids_under_the_amended_grammar(tmp_path, relative, factory, value):
    decorator = (f"pytest.mark.parametrize('value', [1], ids={value})" if factory == "parametrize"
                 else f"pytest.fixture(params=[1], ids={value})")
    _import_order_sources(tmp_path, relative,
        "import pytest\n@" + decorator + "\ndef declared(value):\n    pass\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == []


@pytest.mark.parametrize("factory", ["parametrize", "fixture"])
@pytest.mark.parametrize("value", ["[]", "()", "['one', 'two']", "('one', 'two')"])
def test_static_contract_accepts_literal_string_ids(tmp_path, factory, value):
    relative = "tests/unit/core/test_pathlookup.py"
    decorator = (f"pytest.mark.parametrize('value', [1, 2], ids={value})" if factory == "parametrize"
                 else f"pytest.fixture(params=[1, 2], ids={value})")
    _import_order_sources(tmp_path, relative,
        "import pytest\n@" + decorator + "\ndef declared(value):\n    pass\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == []


@pytest.mark.parametrize("arguments,message", [
    ("'value', [1], False, callback", "ids must use the reviewed decorator grammar"),
    ("*arguments", "parametrize arguments must make ids explicit"),
    ("'value', [1], **options", "parametrize arguments must make ids explicit"),
])
def test_static_contract_checks_positional_and_expanded_ids(tmp_path, arguments, message):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative,
        f"import pytest\n@pytest.mark.parametrize({arguments})\ndef declared(value):\n    pass\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [(relative, 2, message)]


def test_static_contract_callback_refusal_retries_and_keeps_concurrent_roots_independent(tmp_path):
    relative = "tests/unit/core/test_pathlookup.py"
    roots = [tmp_path / name for name in ("left", "right")]
    invalid = "def pytest_generate_tests(metafunc):\n    pass\n"
    valid = "import pytest\n@pytest.mark.parametrize('value', [1], ids=['case'])\ndef declared(value):\n    pass\n"
    for _ in range(2):
        _import_order_sources(roots[0], relative, invalid)
        _import_order_sources(roots[1], relative, valid)
        with ThreadPoolExecutor(max_workers=2) as workers:
            bad, good = workers.map(pathlookup_helpers.pathlookup_source_contract_errors, roots, timeout=5)
        assert bad == [(relative, 1, "pytest_* collection hooks are forbidden")]
        assert good == []
        _import_order_sources(roots[0], relative, valid)
        assert pathlookup_helpers.pathlookup_source_contract_errors(roots[0]) == []


@pytest.mark.parametrize("selection", ["skipped", "deselected"])
@pytest.mark.parametrize("route", ["with_args", "module_call", "class_call", "decorator_call"])
def test_closed_collection_refuses_execution_before_skip_or_deselection(tmp_path, module, selection, route):
    source = ("def write(value=None):\n    alias: object = lookup\n"
              "    alias.__doc__ = 'modeled'\n    return 'case'\n")
    skip = '@pytest.mark.skip(reason="capability unavailable")\n' if selection == "skipped" else ""
    if route == "with_args":
        diagnostic = "collection-time decorator requires a reviewed factory"
        source += skip + ("@pytest.mark.parametrize.with_args('value', [1], ids=write)\n"
                          "def test_case(value):\n    pass\n")
    elif route == "module_call":
        diagnostic = "collection-time call requires a reviewed helper shape"
        source += "write()\n" + skip + "def test_case():\n    pass\n"
    elif route == "class_call":
        diagnostic = "collection-time call requires a reviewed helper shape"
        source += "class TestCase:\n    write()\n"
        source += "    " + skip.replace("\n", "\n    ") + "def test_case(self):\n        pass\n"
    else:
        diagnostic = "decorator arguments must use the reviewed grammar"
        source += skip + "@pytest.mark.skipif(os.getcwd(), reason='modeled')\ndef test_case():\n    pass\n"
        source = "import os\n" + source
    status, output = _run_static_source_case(tmp_path, module, source, deselect=selection == "deselected")
    assert status == pytest.ExitCode.INTERRUPTED, output
    assert "pathlookup source contract:" in output
    assert diagnostic in output


@pytest.mark.parametrize("expression", [
    "None", "True", "-1", "('one', ['two'], {'three': 3})", "[OSError, ValueError, RuntimeError]",
    "os.name == 'nt'", "sys.platform != 'win32'", "sys.platform in ('linux', 'darwin')",
    "os.path.join('..', 'tools')", "hasattr(os, 'mkfifo')", "hasattr(sys, 'getwindowsversion')",
    "os.path.isdir('/proc/self/fd')", "os.path.exists('/dev/fd')",
    "not hasattr(os, 'mkfifo') or (os.name != 'posix' and sys.platform == 'linux')",
])
@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
def test_closed_collection_accepts_only_reviewed_decorator_expression_grammar(tmp_path, relative, expression):
    _import_order_sources(tmp_path, relative,
        "import os, sys, pytest\n@pytest.mark.skipif(" + expression + ", reason='modeled')\ndef declared():\n    pass\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == []


@pytest.mark.parametrize("expression", [
    "os.getcwd()", "os.path.join(root, 'bin')", "os.path.join('bin', **options)",
    "hasattr(lookup, 'os')", "hasattr(os, name)", "os.path.exists(root)", "os.environ",
    "os.name", "sys.platform.startswith('win')", "os.name == name", "os.name < 'posix'",
    "os.name in names", "callback", "lambda value: 'case'", "[value for value in names]",
    "{'modeled': callback}", "1 + 2", "(name := 'modeled')",
])
@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
def test_closed_collection_refuses_unreviewed_decorator_expressions(tmp_path, relative, expression):
    _import_order_sources(tmp_path, relative,
        "import os, sys, pytest\n@pytest.mark.skipif(" + expression + ", reason='modeled')\ndef declared():\n    pass\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path)


@pytest.mark.parametrize("imports,factory", [
    ("import pytest", "pytest.mark.parametrize"), ("import pytest as p", "p.mark.parametrize"),
])
@pytest.mark.parametrize("arguments", ["'value', [1], ids=callback", "'value', [1], False, callback", "*arguments", "**options"])
@pytest.mark.parametrize("location", ["function", "class", "module"])
def test_closed_collection_refuses_every_mark_method_route(tmp_path, imports, factory, arguments, location):
    relative = "tests/unit/core/test_pathlookup.py"
    call = f"{factory}.with_args({arguments})"
    declaration = (f"@{call}\ndef declared(value):\n    pass\n" if location == "function"
                   else f"@{call}\nclass Declared:\n    def test_case(self):\n        pass\n" if location == "class"
                   else f"pytestmark = {call}\n")
    _import_order_sources(tmp_path, relative, imports + "\n" + declaration)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path)


@pytest.mark.parametrize("statement", [
    "own = modeled", "own[0] = 1", "with manager:\n    pass", "for own in []:\n    pass",
    "if False:\n    pass", "try:\n    pass\nfinally:\n    pass", "initialize()", "pass",
])
@pytest.mark.parametrize("location", ["module", "class"])
def test_closed_collection_refuses_every_unlisted_body_statement(tmp_path, statement, location):
    relative = "tests/unit/core/test_pathlookup.py"
    source = statement + "\n"
    if location == "class":
        source = "class Carrier:\n" + "\n".join("    " + line for line in source.splitlines()) + "\n"
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path)


@pytest.mark.parametrize("alias", ["visit_AsyncFunctionDef = visit_FunctionDef", "visit_ClassDef = visit_FunctionDef"])
def test_closed_collection_accepts_local_visitor_method_aliases(tmp_path, alias):
    relative = "tests/helpers_pathlookup.py"
    _import_order_sources(tmp_path, relative,
        "class Visitor:\n    def visit_FunctionDef(self, node):\n        pass\n    " + alias + "\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == []


@pytest.mark.parametrize("alias", ["visit_Other = outside", "outside = visit_FunctionDef", "visit_Other = owner.visit_FunctionDef"])
def test_closed_collection_refuses_nonlocal_method_aliases(tmp_path, alias):
    relative = "tests/helpers_pathlookup.py"
    _import_order_sources(tmp_path, relative,
        "class Visitor:\n    def visit_FunctionDef(self, node):\n        pass\n    " + alias + "\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path)


@pytest.mark.parametrize("source", [
    "import os\nEXE = '.exe' if os.name == 'nt' else ''\n",
    "import pytest\npytestmark = pytest.mark.skip(reason='capability unavailable')\n",
])
def test_closed_collection_accepts_exact_module_exceptions(tmp_path, source):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == []


@pytest.mark.parametrize("source", [
    "import os\nEXE = os.getcwd() if os.name == 'nt' else ''\n",
    "import os\nEXE = '.cmd' if os.name == 'nt' else ''\n",
    "import pytest\nmarks = pytest.mark.skip(reason='modeled')\n",
    "import pytest\ndef deferred():\n    pytestmark = pytest.mark.skip(reason='modeled')\n",
    "import pytest\n@pytest.mark.skip.with_args(reason='modeled')\ndef declared():\n    pass\n",
    "def decorator(function):\n    return function\n@decorator\ndef declared():\n    pass\n",
])
def test_closed_collection_refuses_unreviewed_module_and_decorator_exceptions(tmp_path, source):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path)


def test_closed_collection_recovers_from_read_parse_and_policy_failures_with_concurrent_roots(tmp_path):
    relative = "tests/unit/core/test_pathlookup.py"
    roots = [tmp_path / name for name in ("left", "right")]
    valid = "import os, pytest\n@pytest.mark.skipif(os.name == 'nt', reason='modeled')\ndef declared():\n    pass\n"
    invalid = "import os, pytest\n@pytest.mark.skipif(os.getcwd(), reason='modeled')\ndef declared():\n    pass\n"
    with pytest.raises(FileNotFoundError):
        pathlookup_helpers.pathlookup_source_contract_errors(roots[0])
    _import_order_sources(roots[0], relative, "def broken(\n")
    with pytest.raises(SyntaxError):
        pathlookup_helpers.pathlookup_source_contract_errors(roots[0])
    for _ in range(2):
        _import_order_sources(roots[0], relative, invalid)
        _import_order_sources(roots[1], relative, valid)
        with ThreadPoolExecutor(max_workers=2) as workers:
            bad, good = workers.map(pathlookup_helpers.pathlookup_source_contract_errors, roots, timeout=5)
        assert bad
        assert good == []
        _import_order_sources(roots[0], relative, valid)
        assert pathlookup_helpers.pathlookup_source_contract_errors(roots[0]) == []


def test_static_contract_accepts_skipped_source_without_mutation(tmp_path):
    source = ('pytestmark = pytest.mark.skip(reason="capability unavailable")\n'
              "def test_case():\n    pass\n")
    status, output = _run_static_source_case(tmp_path, "pathlookup", source)
    assert status == pytest.ExitCode.OK, output
    assert "1 skipped" in output


def test_static_contract_guards_real_sources():
    assert pathlookup_helpers.pathlookup_source_contract_errors(Path(__file__).resolve().parents[3]) == []


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
@pytest.mark.parametrize("scope", ["session", "package", "module", "class"])
def test_static_contract_requires_broader_fixture_dependency(tmp_path, relative, scope):
    source = (f"import pytest\n@pytest.fixture(scope={scope!r})\n"
              "def modeled_host():\n    yield\n")
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, 3, "broader fixture must request governed_module_session")]


@pytest.mark.parametrize("signature", ["governed_module_session", "*, governed_module_session"])
def test_static_contract_accepts_required_dependency(tmp_path, signature):
    relative = "tests/unit/core/test_pathlookup.py"
    source = ('import pytest\n@pytest.fixture(scope="session")\n'
              f"def modeled_host({signature}):\n    yield\n")
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == []


@pytest.mark.parametrize("signature", ["governed_module_session=None", "**governed_module_session"])
def test_static_contract_refuses_optional_or_variadic_dependency(tmp_path, signature):
    relative = "tests/unit/core/test_pathlookup.py"
    source = ('import pytest\n@pytest.fixture(scope="session")\n'
              f"def modeled_host({signature}):\n    yield\n")
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, 3, "broader fixture must request governed_module_session")]


@pytest.mark.parametrize("arguments", ["scope=scope", "scope='unsupported'", "**options", "*options"])
def test_static_contract_refuses_opaque_fixture_scope(tmp_path, arguments):
    relative = "tests/unit/core/test_pathlookup.py"
    source = f"import pytest\n@pytest.fixture({arguments})\ndef modeled_host():\n    yield\n"
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, 3, "fixture scope must be a literal supported pytest scope")]


@pytest.mark.parametrize("statement", [
    "alias.os = modeled", "alias.os: object = modeled", "alias.os += modeled",
    "alias.os, own = modeled, None", "del alias.os", "setattr(alias, 'os', modeled)",
    "builtins.setattr(alias, 'os', modeled)",
])
@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
def test_static_contract_refuses_all_collection_attribute_targets(tmp_path, relative, statement):
    _import_order_sources(tmp_path, relative, statement + "\n")
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, 1, "collection-time attribute write")]


@pytest.mark.parametrize("source,line", [
    ("if flag:\n    unrelated.value = modeled\n", 2),
    ("class Example:\n    unrelated.value = modeled\n", 2),
    ("def own(value=setattr(unrelated, 'value', modeled)):\n    pass\n", 1),
    ("def initialize():\n    unrelated.value = modeled\ninitialize()\n", 3),
])
def test_static_contract_checks_collection_expressions_and_initializers(tmp_path, source, line):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative, source)
    errors = pathlookup_helpers.pathlookup_source_contract_errors(tmp_path)
    assert len(errors) == 1
    assert errors[0][:2] == (relative, line)


@pytest.mark.parametrize("source,line", [
    ("def initialize(*args, **kwargs):\n    unrelated.value = modeled\n"
     "class Carrier(metaclass=initialize):\n    pass\n", 3),
    ("class Parent:\n    def __init_subclass__(cls):\n        unrelated.value = modeled\n"
     "class Carrier(Parent):\n    pass\n", 4),
    ("def property():\n    unrelated.value = modeled\nproperty()\n", 1),
    ("def initialize():\n    unrelated.value = modeled\nproperty = initialize\nproperty()\n", 3),
])
def test_static_contract_refuses_indirect_collection_callbacks(tmp_path, source, line):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative, source)
    errors = pathlookup_helpers.pathlookup_source_contract_errors(tmp_path)
    assert len(errors) == 1
    assert errors[0][:2] == (relative, line)


@pytest.mark.parametrize("source", [
    "from custom import change as property\nproperty()\n",
    "import custom as os\nos.path.join('.', 'bin')\n",
])
def test_static_contract_refuses_replaced_factory_imports(tmp_path, source):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative, source)
    assert pathlookup_helpers.pathlookup_source_contract_errors(tmp_path) == [
        (relative, 1, "collection factory import must keep its standard binding")]


def test_static_contract_retries_and_keeps_concurrent_roots_independent(tmp_path):
    relative = "tests/unit/core/test_pathlookup.py"
    roots = [tmp_path / name for name in ("left", "right")]
    for _ in range(2):
        _import_order_sources(roots[0], relative, "unrelated.value = modeled\n")
        _import_order_sources(roots[1], relative, "own = None\n")
        with ThreadPoolExecutor(max_workers=2) as workers:
            bad, good = workers.map(pathlookup_helpers.pathlookup_source_contract_errors, roots, timeout=5)
        assert bad == [(relative, 1, "collection-time attribute write")]
        assert good == []
        _import_order_sources(roots[0], relative, "own = None\n")
        assert pathlookup_helpers.pathlookup_source_contract_errors(roots[0]) == []


@pytest.mark.parametrize("statement", [
    "from aegis_core import pathlookup as lookup", "import aegis_core.gitsafe",
    "from aegis_core.primitives import real_key", "import aegis_cli.cli",
    "lookup: object = pathlookup", "aegis_core.primitives.os = modeled",
    "def initialize():\n    from aegis_core import gitsafe\ninitialize()",
])
def test_pathlookup_import_order_rejects_any_code_before_helper(tmp_path, statement):
    relative = "tests/unit/core/test_pathlookup.py"
    _import_order_sources(tmp_path, relative,
        statement + "\nfrom tests.helpers_pathlookup import monkeypatch\n")
    errors = pathlookup_helpers.pathlookup_import_order(tmp_path)
    assert errors == [(relative, 1, "helper import must be the first executable statement")]


@pytest.mark.parametrize("statement", [
    "from aegis_core import pathlookup as lookup", "import aegis_core.gitsafe",
    "from aegis_core.primitives import real_key", "from aegis_cli import cli",
    "lookup: object = pathlookup", "aegis_core.primitives.os = modeled",
    "def initialize():\n    from aegis_core import gitsafe\ninitialize()",
])
def test_pathlookup_import_order_rejects_helper_pre_baseline_code(tmp_path, statement):
    relative = "tests/helpers_pathlookup.py"
    source = (Path(__file__).resolve().parents[3] / relative).read_text(encoding="utf-8")
    source = source.replace("from __future__ import annotations\n",
                            "from __future__ import annotations\n" + statement + "\n", 1)
    _import_order_sources(tmp_path, relative, source)
    errors = pathlookup_helpers.pathlookup_import_order(tmp_path)
    assert errors, errors
    assert all(error[0] == relative for error in errors)


@pytest.mark.parametrize("placement", ["snapshot", "between", "missing"])
def test_pathlookup_import_order_pins_read_only_bootstrap(tmp_path, placement):
    relative = "tests/helpers_pathlookup.py"
    source = (Path(__file__).resolve().parents[3] / relative).read_text(encoding="utf-8")
    if placement == "snapshot":
        source = source.replace("        self.module = module\n",
                                "        module.os = object()\n        self.module = module\n", 1)
    elif placement == "between":
        source = source.replace("_GOVERNED_BASELINE = tuple(",
                                "pathlookup.os = object()\n_GOVERNED_BASELINE = tuple(", 1)
    else:
        source = source.replace("_GOVERNED_BASELINE = tuple(", "discarded = tuple(", 1)
    _import_order_sources(tmp_path, relative, source)
    errors = pathlookup_helpers.pathlookup_import_order(tmp_path)
    assert errors, errors
    assert all(error[0] == relative for error in errors)


def test_pathlookup_import_order_retries_and_keeps_concurrent_roots_independent(tmp_path):
    relative = "tests/unit/core/test_pathlookup.py"
    roots = [tmp_path / name for name in ("left", "right")]
    valid = ("from tests.helpers_pathlookup import "
             "governed_module_session, governed_module_state, monkeypatch\n"
             "from aegis_core import pathlookup\n")
    invalid = "from aegis_core import pathlookup\n" + valid
    for _ in range(2):
        _import_order_sources(roots[0], relative, invalid)
        _import_order_sources(roots[1], relative, valid)
        with ThreadPoolExecutor(max_workers=2) as workers:
            bad, good = workers.map(pathlookup_helpers.pathlookup_import_order, roots, timeout=5)
        assert bad == [(relative, 1, "helper import must be the first executable statement")]
        assert good == []
        _import_order_sources(roots[0], relative, valid)
        assert pathlookup_helpers.pathlookup_import_order(roots[0]) == []


def _patch_guard_sources(root, relative, source):
    for name in ("tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source if name == relative else "", encoding="utf-8")


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
@pytest.mark.parametrize("module", ["pathlookup", "gitsafe", "primitives"])
@pytest.mark.parametrize("imports,receiver", [
    ("from aegis_core import {module}", "{module}"),
    ("from aegis_core import {module} as lookup", "lookup"),
    ("import aegis_core.{module} as lookup", "lookup"),
    ("import aegis_core.{module}", "aegis_core.{module}"),
    ("import aegis_core as core", "core.{module}"),
])
def test_pathlookup_patch_guard_rejects_ordinary_imports(tmp_path, relative, module, imports, receiver):
    binding = imports.format(module=module)
    owner = receiver.format(module=module)
    _patch_guard_sources(tmp_path, relative, binding + "\n" + owner + ".os = modeled\n")
    assert pathlookup_patch_writes(tmp_path) == [(relative, 2, owner + ".os")]


def test_pathlookup_patch_guard_rejects_helper_assignment(tmp_path):
    relative = "tests/helpers_pathlookup.py"
    _patch_guard_sources(tmp_path, relative, "from aegis_core import pathlookup\npathlookup.os = modeled\n")
    assert pathlookup_patch_writes(tmp_path) == [(relative, 2, "pathlookup.os")]


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
def test_pathlookup_patch_guard_refuses_missing_source(tmp_path, relative):
    _patch_guard_sources(tmp_path, relative, "")
    (tmp_path / relative).unlink()
    with pytest.raises(FileNotFoundError) as caught:
        pathlookup_patch_writes(tmp_path)
    assert caught.value.errno == 2
    assert caught.value.filename == str(tmp_path / relative)


@pytest.mark.parametrize("relative", ["tests/unit/core/test_pathlookup.py", "tests/helpers_pathlookup.py"])
def test_pathlookup_patch_guard_refuses_malformed_source(tmp_path, relative):
    _patch_guard_sources(tmp_path, relative, "value =\n")
    with pytest.raises(SyntaxError, match="invalid syntax") as caught:
        pathlookup_patch_writes(tmp_path)
    assert caught.value.filename == str(tmp_path / relative)
    assert caught.value.lineno == 1


@pytest.mark.parametrize("source", [
    "from types import SimpleNamespace as lookup\nlookup.os = modeled\n",
    "from aegis_core import pathlookup\ndef own(pathlookup):\n    pathlookup.os = modeled\n",
    "def other():\n    from aegis_core import pathlookup as lookup\n"
    "def own(lookup):\n    lookup.os = modeled\n",
    "from aegis_core import pathlookup as lookup\nseen = lookup.os\n",
])
def test_pathlookup_patch_guard_keeps_unrelated_scopes_and_reads(tmp_path, source):
    _patch_guard_sources(tmp_path, "tests/unit/core/test_pathlookup.py", source)
    assert pathlookup_patch_writes(tmp_path) == []


def test_pathlookup_patch_guard_checks_local_and_later_imports(tmp_path):
    relative = "tests/helpers_pathlookup.py"
    source = ("def first():\n    lookup.os = modeled\n"
              "from aegis_core import pathlookup as lookup\n"
              "def second():\n    from aegis_core import primitives as local\n    local.os = modeled\n")
    _patch_guard_sources(tmp_path, relative, source)
    assert pathlookup_patch_writes(tmp_path) == [(relative, 2, "lookup.os"), (relative, 6, "local.os")]


@pytest.mark.parametrize("source,line", [
    ("from aegis_core import pathlookup as lookup\nalias = lookup\ndef own(lookup):\n    alias.os = modeled\n", 4),
    ("import aegis_core as core\nalias = core.primitives\nalias.os = modeled\n", 3),
    ("def own():\n    from aegis_core import gitsafe as lookup\n    alias = lookup\n    alias.os = modeled\n", 4),
    ("import aegis_core.pathlookup as lookup\nalias = lookup\nlookup = alias\nalias.os = modeled\n", 4),
])
def test_pathlookup_patch_guard_follows_simple_aliases(tmp_path, source, line):
    relative = "tests/helpers_pathlookup.py"
    _patch_guard_sources(tmp_path, relative, source)
    assert pathlookup_patch_writes(tmp_path) == [(relative, line, "alias.os")]


@pytest.mark.parametrize("statement", [
    "lookup.os = modeled", "lookup.os = lookup.sys = modeled",
    "lookup.os, other = modeled, None", "lookup.os: object = modeled",
    "lookup.os += modeled", "del lookup.os",
])
def test_pathlookup_patch_guard_covers_direct_write_syntax(tmp_path, statement):
    relative = "tests/helpers_pathlookup.py"
    _patch_guard_sources(tmp_path, relative, "from aegis_core import gitsafe as lookup\n" + statement + "\n")
    expected = [(relative, 2, "lookup.os")]
    if "lookup.sys" in statement:
        expected.append((relative, 2, "lookup.sys"))
    assert pathlookup_patch_writes(tmp_path) == expected


def test_pathlookup_patch_guard_retries_after_source_repair(tmp_path):
    relative = "tests/helpers_pathlookup.py"
    for _ in range(2):
        _patch_guard_sources(tmp_path, relative, "import aegis_core.pathlookup as lookup\nlookup.os = modeled\n")
        assert pathlookup_patch_writes(tmp_path) == [(relative, 2, "lookup.os")]
        _patch_guard_sources(tmp_path, relative, "import aegis_core.pathlookup as lookup\nseen = lookup.os\n")
        assert pathlookup_patch_writes(tmp_path) == []


def test_pathlookup_patch_guard_keeps_concurrent_roots_independent(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    relative = "tests/helpers_pathlookup.py"
    roots = [tmp_path / name for name in ("left", "right")]
    _patch_guard_sources(roots[0], relative, "import aegis_core.primitives as lookup\nlookup.os = modeled\n")
    _patch_guard_sources(roots[1], relative, "from types import SimpleNamespace as lookup\nlookup.os = modeled\n")
    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(pathlookup_patch_writes, roots, timeout=5)) == [[(relative, 2, "lookup.os")], []]


def test_clean_host_os_preserves_fixture_markers_and_hides_ancestors(tmp_path):
    outer = tmp_path / ".git"
    outer.mkdir()
    root = tmp_path / "fixture"
    root.mkdir()
    marker = root / ".git"
    marker.write_text("gitdir: elsewhere\n", encoding="utf-8")
    modeled = clean_host_os(root)
    assert modeled.path.lexists(marker)
    assert modeled.stat(marker).st_mode == os.stat(marker).st_mode
    assert not modeled.path.lexists(outer)
    with pytest.raises(FileNotFoundError, match="^\\[Errno 2\\] marker outside fixture model$"):
        modeled.stat(outer)
    assert outer.is_dir()
    assert modeled.stat(root).st_mode == os.stat(root).st_mode


def test_clean_host_os_keeps_missing_marker_failure(tmp_path):
    modeled = clean_host_os(tmp_path)
    with pytest.raises(FileNotFoundError) as caught:
        modeled.stat(tmp_path / ".git")
    assert caught.value.errno == 2
    assert caught.value.filename == str(tmp_path / ".git")
    assert not modeled.path.lexists(tmp_path / ".git")


def test_clean_host_os_preserves_capability_names(tmp_path):
    modeled = clean_host_os(tmp_path)
    assert modeled.stat.__name__ == os.stat.__name__
    for capabilities in ("supports_dir_fd", "supports_follow_symlinks"):
        assert {fn.__name__ for fn in getattr(modeled, capabilities)} == {
            fn.__name__ for fn in getattr(os, capabilities)}


def test_clean_host_os_descriptor_markers(tmp_path):
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor-relative discovery is unavailable")
    root = tmp_path / "fixture"
    root.mkdir()
    (tmp_path / ".git").mkdir()
    (root / ".git").mkdir()
    modeled = clean_host_os(root)
    for directory, visible in ((tmp_path, False), (root, True)):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            if visible:
                assert modeled.stat(".git", dir_fd=fd, follow_symlinks=False).st_mode == os.stat(root / ".git").st_mode
            else:
                with pytest.raises(FileNotFoundError, match="^\\[Errno 2\\] marker outside fixture model$"):
                    modeled.stat(".git", dir_fd=fd, follow_symlinks=False)
        finally:
            os.close(fd)


def test_clean_host_os_models_are_independent_across_threads_and_retries(tmp_path):
    roots = [tmp_path / name for name in ("left", "right")]
    for root in roots:
        (root / ".git").mkdir(parents=True)
    models = [clean_host_os(root) for root in roots]

    def inspect(index):
        own, other = roots[index] / ".git", roots[1 - index] / ".git"
        return models[index].path.lexists(own), models[index].path.lexists(other)

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(inspect, [0, 1] * 3, timeout=5)) == [(True, False)] * 6


def test_clean_host_os_patch_restores_after_failure_and_retry(tmp_path, monkeypatch):
    original = pathlookup.os
    for _ in range(2):
        with pytest.raises(RuntimeError, match="^modeled failure$"):
            with monkeypatch.context() as patch:
                patch.setattr("aegis_core.pathlookup.os", clean_host_os(tmp_path))
                assert pathlookup.os is not original
                raise RuntimeError("modeled failure")
        assert pathlookup.os is original


def test_clean_host_os_works_without_descriptor_support(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    root = tmp_path / "fixture"
    (root / "workspace" / ".git").mkdir(parents=True)
    monkeypatch.setattr("aegis_core.pathlookup.os", clean_host_os(root))
    monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
    assert pathlookup.git_fence(root) == os.path.normcase(os.path.realpath(root))
    assert pathlookup.git_fence(root / "workspace") == os.path.normcase(os.path.realpath(root / "workspace"))


def test_git_cache_policy_and_bound_root_have_one_exported_home():
    from aegis_core import pathlookup_gitcache

    assert pathlookup_gitcache.__all__ == ["GitCache", "bound_ordinary_root", "ordinary_root"]
    assert issubclass(pathlookup.GitCache, pathlookup_gitcache.GitCache)
    assert pathlookup.ordinary_root is pathlookup_gitcache.ordinary_root
    assert pathlookup.__all__ == [
        "Hit", "INSIDE_FENCE", "RELATIVE_ENTRY", "descriptor_fence_supported", "GitCache",
        "fenced_program", "git_fence", "is_bare", "only_skipped", "ordinary_root", "which",
    ]
    assert type(pathlookup.GitCache().for_cwd()).__module__ == pathlookup_gitcache.__name__


def test_git_cache_keeps_dictionary_initialization_and_snapshot_updates():
    cache = pathlookup.GitCache({("root", "git"): "program"}, inside_program="value")
    assert cache.copy() == {("root", "git"): "program", "inside_program": "value"}
    other = pathlookup.GitCache(fence_for_cwd="value")
    other.update(cache)
    assert dict(other.items()) == {**cache.copy(), "fence_for_cwd": "value"}


def _program(directory: Path, name: str, data: bytes = b"#!/bin/sh\nexit 0\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + EXE)
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def _path(*entries) -> str:
    return os.pathsep.join(str(e) for e in entries)


# ── which ────────────────────────────────────────────────────────────────────

def test_the_first_absolute_entry_holding_the_program_wins(tmp_path):
    first = _program(tmp_path / "a", "codex")
    _program(tmp_path / "b", "codex")
    assert which("codex", _path(tmp_path / "empty", tmp_path / "a", tmp_path / "b")) == str(first)


def test_a_name_on_no_entry_is_none(tmp_path):
    (tmp_path / "empty").mkdir()
    assert which("codex", _path(tmp_path / "empty")) is None
    assert which("codex", "") is None


@pytest.mark.parametrize("entry", ["", ".", "bin", os.path.join(".", "bin")])
def test_empty_and_relative_entries_are_never_searched(tmp_path, monkeypatch, entry):
    # Each names a directory relative to the cwd, where a repository plants programs.
    _program(tmp_path, "codex")
    _program(tmp_path / "bin", "codex")
    monkeypatch.chdir(tmp_path)
    assert which("codex", _path(entry)) is None
    real = _program(tmp_path / "real", "codex")
    assert which("codex", _path(entry, real.parent)) == str(real)


def test_the_default_path_is_the_environment_path(tmp_path, monkeypatch):
    exe = _program(tmp_path / "bin", "aegis-mcp")
    monkeypatch.setenv("PATH", str(exe.parent))
    assert which("aegis-mcp") == str(exe)


def test_an_entry_inside_the_fence_is_skipped_and_the_next_one_wins(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "tools", "codex")
    real = _program(tmp_path / "bin", "codex")
    path = _path(ws / "tools", real.parent)
    assert which("codex", path, outside=ws) == str(real)
    assert which("codex", _path(ws / "tools"), outside=ws) is None
    assert which("codex", _path(ws / "tools")) == str(ws / "tools" / ("codex" + EXE))


def test_the_fence_itself_is_inside_the_fence(tmp_path):
    ws = tmp_path / "ws"
    _program(ws, "codex")
    assert which("codex", _path(ws), outside=ws) is None


def test_a_sibling_sharing_the_fence_prefix_is_outside_it(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sibling = _program(tmp_path / "ws-tools", "codex")
    assert which("codex", _path(sibling.parent), outside=ws) == str(sibling)


def test_a_linked_entry_into_the_fence_is_inside_it(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "bin", "codex")
    link = tmp_path / "linkbin"
    try:
        link.symlink_to(ws / "bin", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    assert which("codex", _path(link), outside=ws) is None


def test_a_linked_program_is_returned_under_its_own_name(tmp_path):
    # Version managers dispatch on argv[0]: the name found on PATH is what runs.
    real = _program(tmp_path / "toolchain", "dispatcher")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    try:
        (bindir / ("codex" + EXE)).symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    assert which("codex", _path(bindir)) == str(bindir / ("codex" + EXE))


@pytest.mark.skipif(os.name == "nt", reason="Windows has no execute bit")
def test_a_file_without_the_execute_bit_is_not_a_program(tmp_path):
    exe = _program(tmp_path / "bin", "codex")
    exe.chmod(0o644)
    assert which("codex", _path(exe.parent)) is None


def test_a_directory_named_like_the_program_is_not_a_program(tmp_path):
    (tmp_path / "bin" / ("codex" + EXE)).mkdir(parents=True)
    assert which("codex", _path(tmp_path / "bin")) is None


class TestWindowsLookup:
    """PATHEXT candidates matched case-insensitively against the directory, returned
    in the file's own spelling. Emulated off Windows by the platform name."""

    @pytest.fixture
    def windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("PATHEXT", os.pathsep.join([".COM", ".EXE", ".BAT", ".CMD"]))

    @pytest.mark.parametrize("on_disk", ["codex.exe", "codex.Exe", "CODEX.EXE"])
    def test_the_on_disk_spelling_is_returned(self, tmp_path, windows, on_disk):
        exe = tmp_path / "bin" / on_disk
        exe.parent.mkdir()
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert which("codex", str(exe.parent)) == str(exe)

    def test_a_cmd_shim_is_found_after_the_exe_extensions(self, tmp_path, windows):
        shim = tmp_path / "npm" / "codex.cmd"
        shim.parent.mkdir()
        shim.write_bytes(b"@echo off\r\n")
        shim.chmod(0o755)
        assert which("codex", str(shim.parent)) == str(shim)

    def test_explicit_pathext_selects_candidates_and_keeps_the_fence(self, tmp_path, monkeypatch):
        from types import SimpleNamespace

        exe, shim = tmp_path / "Git.Exe", tmp_path / "git.cmd"
        for program in (exe, shim):
            program.touch()
            if os.name == "posix":
                program.chmod(0o755)
        monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(
            **{**vars(os), "pathsep": ";", "environ": {"PATHEXT": ".CMD;.EXE"}}))
        monkeypatch.setattr("aegis_core.pathlookup.sys", SimpleNamespace(**{**vars(sys), "platform": "win32"}))

        assert which("git", str(tmp_path)) == str(shim)
        assert which("git", str(tmp_path), pathext=".EXE") == str(exe)
        assert which("git", str(tmp_path), pathext="") == str(exe)
        assert which("git", str(tmp_path), outside=tmp_path, pathext=".EXE") is None
        assert which("git", str(tmp_path), pathext=".BAT") is None
        assert only_skipped("git", str(tmp_path), outside=tmp_path) == [
            Hit(str(program), str(tmp_path), pathlookup.INSIDE_FENCE) for program in (shim, exe)
        ]
        with ThreadPoolExecutor(max_workers=2) as workers:
            selected = workers.submit(which, "git", str(tmp_path), pathext=".EXE")
            ambient = workers.submit(which, "git", str(tmp_path))
            assert selected.result(timeout=5) == str(exe)
            assert ambient.result(timeout=5) == str(shim)

    def test_a_name_that_carries_an_extension_is_looked_up_as_given(self, tmp_path, windows):
        exe = tmp_path / "bin" / "python3.exe"
        exe.parent.mkdir()
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert which("python3.EXE", str(exe.parent)) == str(exe)

    def test_a_name_without_a_pathext_extension_is_not_a_program(self, tmp_path, windows):
        script = tmp_path / "bin" / "codex"
        script.parent.mkdir()
        script.write_bytes(b"#!/bin/sh\n")
        script.chmod(0o755)
        assert which("codex", str(script.parent)) is None

    def test_relative_entries_are_skipped_on_windows_too(self, tmp_path, windows, monkeypatch):
        shim = tmp_path / "codex.cmd"
        shim.write_bytes(b"@echo off\r\n")
        shim.chmod(0o755)
        monkeypatch.chdir(tmp_path)
        assert which("codex", os.pathsep.join(["", "."])) is None

    # What only_skipped reports is what doctor lists in binary.ignored: the three Windows CI
    # failures at 41cd3f0 were codex.EXE reported for a codex.exe on disk.
    @pytest.mark.parametrize("on_disk", ["codex.exe", "Codex.Exe"])
    def test_a_program_passed_over_inside_the_fence_keeps_its_on_disk_spelling(self, tmp_path, windows,
                                                                               on_disk):
        ws = tmp_path / "ws"
        exe = ws / "tools" / on_disk
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert only_skipped("codex", str(exe.parent), outside=ws) == [
            Hit(path=str(exe), entry=str(exe.parent), reason="inside_fence")]

    @pytest.mark.parametrize("on_disk", ["codex.exe", "Codex.Exe"])
    def test_a_program_passed_over_on_a_relative_entry_keeps_its_on_disk_spelling(self, tmp_path, windows,
                                                                                  on_disk):
        ws = tmp_path / "ws"
        exe = ws / "bin" / on_disk
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert only_skipped("codex", "bin", outside=ws, base=ws) == [
            Hit(path=os.path.normpath(str(exe)), entry="bin", reason="relative_entry")]


@pytest.mark.skipif(os.name != "posix", reason="uses a POSIX executable")
def test_explicit_pathext_does_not_change_posix_lookup(tmp_path):
    program = _program(tmp_path, "git")
    assert which("git", str(tmp_path), pathext=".CMD") == str(program)


# ── only_skipped ─────────────────────────────────────────────────────────────

def test_only_skipped_is_empty_when_which_finds_the_program(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "bin", "codex")
    real = _program(tmp_path / "bin", "codex")
    assert only_skipped("codex", _path("bin", ws / "bin", real.parent), outside=ws, base=ws) == []


def test_only_skipped_is_empty_when_the_program_is_nowhere(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    assert only_skipped("codex", _path("", ".", "bin", ws), outside=ws, base=ws) == []


@pytest.mark.parametrize("entry, where", [("", "."), (".", "."), ("bin", "bin"),
                                          (os.path.join("..", "tools"), os.path.join("..", "tools"))])
def test_a_program_reachable_only_through_a_relative_entry_is_reported(tmp_path, entry, where):
    ws = tmp_path / "ws"
    exe = _program(ws / where, "codex")
    hits = only_skipped("codex", _path(entry), outside=ws, base=ws)
    assert hits == [Hit(path=os.path.normpath(str(exe)), entry=entry, reason="relative_entry")]


def test_a_relative_entry_resolves_against_the_cwd_by_default(tmp_path, monkeypatch):
    exe = _program(tmp_path / "bin", "codex")
    monkeypatch.chdir(tmp_path)
    assert only_skipped("codex", _path("bin")) == [
        Hit(path=os.path.normpath(os.path.join(os.getcwd(), "bin", "codex" + EXE)), entry="bin",
            reason="relative_entry")]
    assert exe.is_file()


def test_a_program_reachable_only_inside_the_fence_is_reported(tmp_path):
    ws = tmp_path / "ws"
    exe = _program(ws / "tools", "codex")
    assert only_skipped("codex", _path(ws / "tools"), outside=ws) == [
        Hit(path=str(exe), entry=str(ws / "tools"), reason="inside_fence")]


def test_every_refused_place_is_reported_once_in_path_order(tmp_path):
    ws = tmp_path / "ws"
    inside = _program(ws / "tools", "codex")
    relative = _program(ws / "bin", "codex")
    hits = only_skipped("codex", _path(ws / "tools", "bin", ws / "tools", "bin"), outside=ws, base=ws)
    assert [(h.path, h.reason) for h in hits] == [(str(inside), "inside_fence"),
                                                   (os.path.normpath(str(relative)), "relative_entry")]


def test_without_a_fence_only_relative_entries_are_refused(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "tools", "codex")
    assert only_skipped("codex", _path(ws / "tools"), base=ws) == []


def test_an_outside_program_whose_realpath_is_inside_the_fence_is_skipped(tmp_path):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    planted = _program(ws / "bin", "codex")
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = outside / ("codex" + EXE)
    symlink_or_skip(planted, alias)
    real = _program(tmp_path / "host", "codex")
    assert which("codex", _path(outside), outside=ws) == str(alias)
    assert which("codex", _path(outside, real.parent), outside=ws, fence_program=True) == str(real)
    assert only_skipped("codex", _path(outside), outside=ws, fence_program=True) == [
        Hit(path=str(alias), entry=str(outside), reason="inside_fence")]


@pytest.mark.parametrize("fence,entry", [
    (r"C:\ws", r"C:\ws\tools"),
    (r"C:\ws", r"\\?\C:\ws\tools"),
    (r"C:\ws", r"\\.\C:\ws\tools"),
    (r"\\server\share\ws", r"\\server\share\ws\tools"),
    (r"\\server\share\ws", r"\\?\UNC\server\share\ws\tools"),
    (r"\\server\share\ws", r"\\.\UNC\server\share\ws\tools"),
], ids=["drive", "extended-drive", "device-drive", "unc", "extended-unc", "device-unc"])
def test_windows_in_fence_alias_spellings_are_refused(fence, entry, monkeypatch):
    """Model Windows OS results so both path namespaces run on every CI host."""
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys

    def resolved(path):
        return fence if ntpath.normcase(os.fspath(path)) == ntpath.normcase(fence) else r"D:\host\git"

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": resolved,
        "islink": lambda path: False, "isfile": lambda path: True})
    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\",
        "altsep": "/", "pathsep": ";", "path": paths, "access": lambda *args: True,
        "listdir": lambda directory: ["git.exe"], "environ": {"PATHEXT": ".EXE"}})
    monkeypatch.setattr("aegis_core.pathlookup.os", modeled)
    monkeypatch.setattr("aegis_core.primitives.os", modeled)
    monkeypatch.setattr("aegis_core.pathlookup.sys", SimpleNamespace(**{**vars(original_sys), "platform": "win32"}))
    try:
        assert pathlookup.which("git.exe", path=entry, outside=fence, fence_program=True) is None
        assert pathlookup.only_skipped("git.exe", path=entry, outside=fence, fence_program=True) == [
            Hit(path=ntpath.join(entry, "git.exe"), entry=entry, reason=pathlookup.INSIDE_FENCE)]
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.primitives.os", primitive_os)
        monkeypatch.setattr("aegis_core.pathlookup.sys", original_sys)


def _outer_marker_fence(path):
    start = Path(os.path.realpath(path))
    for parent in reversed((start, *start.parents)):
        if os.path.lexists(parent / ".git"):
            return os.path.normcase(str(parent))
    return os.path.normcase(str(start))


def test_git_fence_uses_outermost_marker_across_discovery_ceilings(tmp_path, monkeypatch):
    from aegis_core import pathlookup
    high = tmp_path / "high"
    (high / ".git").mkdir(parents=True)
    ceiling = high / "stop"
    plain = ceiling / "plain"
    plain.mkdir(parents=True)
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / ".git").write_text("gitdir: /nowhere\n", encoding="utf-8")
    (nested / "sub").mkdir()
    previous = os.environ.get("GIT_CEILING_DIRECTORIES")
    os.environ["GIT_CEILING_DIRECTORIES"] = str(ceiling)
    try:
        assert pathlookup.git_fence(plain) == _outer_marker_fence(high)
        assert pathlookup.git_fence(nested / "sub") == _outer_marker_fence(nested)
        assert pathlookup.git_fence("bad\0start") == os.path.normcase(os.path.abspath(os.sep))
        probe = pathlookup.descriptor_fence_supported
        monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
        try:
            assert pathlookup.git_fence(nested / "sub") == _outer_marker_fence(nested)
            assert pathlookup.git_fence(plain) == _outer_marker_fence(high)
        finally:
            monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", probe)
    finally:
        if previous is None:
            os.environ.pop("GIT_CEILING_DIRECTORIES", None)
        else:
            os.environ["GIT_CEILING_DIRECTORIES"] = previous


def test_git_fence_counts_a_symlinked_marker_without_following_it(tmp_path, monkeypatch):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    linked = tmp_path / "linked"
    (linked / "sub").mkdir(parents=True)
    symlink_or_skip("not-a-target", linked / ".git")
    assert pathlookup.git_fence(linked / "sub") == _outer_marker_fence(linked)
    probe = pathlookup.descriptor_fence_supported
    monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
    try:
        assert pathlookup.git_fence(linked / "sub") == _outer_marker_fence(linked)
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", probe)


@pytest.mark.skipif(os.name != "posix", reason="FIFO markers need POSIX")
def test_git_fence_never_opens_a_fifo_marker(tmp_path):
    import subprocess
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor-relative discovery is unavailable")
    ws = tmp_path / "ws"
    ws.mkdir()
    os.mkfifo(ws / ".git")
    code = "from aegis_core.pathlookup import git_fence; import sys; print(git_fence(sys.argv[1]))"
    result = subprocess.run([sys.executable, "-c", code, str(ws)],
                            capture_output=True, text=True, timeout=5, check=True)
    assert result.stdout.strip() == _outer_marker_fence(ws)


@pytest.mark.skipif(os.name != "posix", reason="backslash is a POSIX filename character")
def test_git_fence_preserves_backslashes_in_directory_names(tmp_path):
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor-relative discovery is unavailable")
    ws = tmp_path / "ws\\name"
    (ws / ".git").mkdir(parents=True)
    sub = ws / "sub"
    sub.mkdir()
    assert pathlookup.git_fence(sub) == _outer_marker_fence(ws)


@pytest.mark.parametrize("failure", [OSError, ValueError, RuntimeError])
def test_git_fence_closes_parent_descriptor_when_location_fails(tmp_path, failure, monkeypatch):
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("descriptor count check needs Linux procfs")
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    sub = ws / "sub"
    sub.mkdir()
    original = pathlookup._fd_location
    calls = []

    def location(fd):
        calls.append(fd)
        if len(calls) == 3:
            raise failure("untrusted-location-diagnostic")
        return original(fd)

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr("aegis_core.pathlookup._fd_location", location)
    try:
        assert pathlookup.git_fence(sub) == os.path.abspath(os.sep)
    finally:
        monkeypatch.setattr("aegis_core.pathlookup._fd_location", original)
    assert len(os.listdir("/proc/self/fd")) == before
    assert pathlookup.git_fence(sub) == _outer_marker_fence(ws)


def test_git_fence_refuses_a_component_replaced_by_a_symlink_during_open(tmp_path, monkeypatch):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("no-follow descriptor discovery is unavailable")
    outside = tmp_path / "outside"
    outside.mkdir()
    pivot = tmp_path / "pivot"
    (pivot / ".git").mkdir(parents=True)
    parked = tmp_path / "parked"
    # Qualify symlink capability before entering the deterministic replacement.
    probe = tmp_path / "probe"
    symlink_or_skip(outside, probe, target_is_directory=True)
    probe.unlink()
    original = pathlookup._open_directory
    changes = []

    def opening(parent, name):
        if name == "pivot" and not changes:
            changes.append(name)
            pivot.rename(parked)
            symlink_or_skip(outside, pivot, target_is_directory=True)
        return original(parent, name)

    monkeypatch.setattr("aegis_core.pathlookup._open_directory", opening)
    try:
        assert pathlookup.git_fence(pivot) == os.path.abspath(os.sep)
    finally:
        monkeypatch.setattr("aegis_core.pathlookup._open_directory", original)
    assert changes == ["pivot"]
    pivot.unlink()
    parked.rename(pivot)
    assert pathlookup.git_fence(pivot) == _outer_marker_fence(pivot)


def test_git_fence_falls_back_when_fd_directory_cannot_locate_descriptors(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("models a POSIX descriptor locator")
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    original = pathlookup.os

    def realpath(path):
        text = os.fspath(path)
        if text.startswith("/proc/self/fd/") or text.startswith("/dev/fd/"):
            return text
        return os.path.realpath(path)

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(os), "path": SimpleNamespace(
        **{**vars(os.path), "realpath": realpath})}))
    try:
        assert pathlookup.git_fence(ws) == _outer_marker_fence(ws)
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)


def test_descriptor_probe_requires_nofollow_stat_support(monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original = pathlookup.os
    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(os), "supports_follow_symlinks": set()}))
    try:
        assert not pathlookup.descriptor_fence_supported()
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)


def test_git_fence_checks_component_budget_before_path_resolution(monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    start = os.sep + os.sep.join(["component"] * 513)
    original = pathlookup.os

    def resolve(path):
        if path == start:
            raise AssertionError("over-budget input reached path resolution")
        return os.path.realpath(path)

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(os), "path": SimpleNamespace(
        **{**vars(os.path), "realpath": resolve})}))
    try:
        assert pathlookup.git_fence(start) == os.path.normcase(os.path.abspath(os.sep))
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)


@pytest.mark.parametrize("root_marker", [False, True], ids=["no-markers", "filesystem-root"])
def test_git_fence_cwd_fallback_and_filesystem_root_are_explicit(tmp_path, root_marker, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original, probe = pathlookup.os, pathlookup.descriptor_fence_supported
    root = os.path.abspath(os.sep)

    def marker_stat(path, *args, **kwargs):
        if os.path.basename(path) == ".git":
            if root_marker and path == os.path.join(root, ".git"):
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            raise FileNotFoundError(2, "no modeled marker")
        return os.stat(path, *args, **kwargs)

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(os), "stat": marker_stat, "path": SimpleNamespace(
        **{**vars(os.path), "lexists": lambda path: root_marker and path == os.path.join(root, ".git")})}))
    monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
    try:
        expected = root if root_marker else os.path.realpath(tmp_path)
        assert pathlookup.git_fence(tmp_path) == os.path.normcase(expected)
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", probe)


@pytest.mark.parametrize("components", [512, 513])
def test_git_fence_component_limit_includes_the_root_walk(components, monkeypatch):
    import posixpath
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original, probe = pathlookup.os, pathlookup.descriptor_fence_supported
    start = "/anchor" + "/d" * (components - 1)
    paths = SimpleNamespace(**{**vars(posixpath), "realpath": lambda path: path,
        "islink": lambda path: False, "isfile": lambda path: False,
        "lexists": lambda path: path == "/anchor/.git"})

    def directory(path, *args, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    def marker_stat(path, *args, **kwargs):
        if path == "/anchor/.git":
            return SimpleNamespace(st_mode=stat.S_IFDIR)
        raise FileNotFoundError(2, "no modeled marker")

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(original), "sep": "/", "altsep": None, "path": paths,
        "lstat": directory, "stat": marker_stat}))
    monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
    try:
        assert pathlookup.git_fence(start) == ("/anchor" if components == 512 else "/")
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", probe)


@contextlib.contextmanager
def _metadata_walk(enabled, monkeypatch):
    """Force the no-descriptor walk when enabled is false; leave the host probe alone otherwise."""
    from aegis_core import pathlookup
    if enabled:
        yield
        return
    probe = pathlookup.descriptor_fence_supported
    monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
    try:
        yield
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", probe)


@contextlib.contextmanager
def _observe_reparse(observer, monkeypatch):
    """Install a no-follow reparse observer for one lookup, then restore the platform classifier."""
    from aegis_core import pathlookup
    previous = pathlookup._reparse_observer
    monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", observer)
    try:
        yield
    finally:
        monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", previous)


def _outside_resolved(path, fence):
    resolved, root = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(fence))
    return resolved != root and not resolved.startswith(root.rstrip(os.sep) + os.sep)


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_a_legitimate_outside_parent_entry_is_kept(tmp_path, descriptors, monkeypatch):
    """'..' on a walk that never enters the fence stays eligible, spelled as written."""
    ws = tmp_path / "ws"
    ws.mkdir()
    deep = tmp_path / "host" / "deep"
    deep.mkdir(parents=True)
    program = _program(tmp_path / "host" / "bin", "codex")
    entry = str(deep) + os.sep + ".." + os.sep + "bin"
    spelled = os.path.join(entry, program.name)
    with _metadata_walk(descriptors, monkeypatch):
        assert which("codex", entry, outside=ws) == spelled
        assert which("codex", entry, outside=ws, fence_program=True) == spelled


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_outside_symlink_into_the_fence_and_back_out_is_skipped(tmp_path, descriptors, monkeypatch):
    """A directory symlink whose target enters the fence and leaves is an inside entry."""
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    (ws / "decoy").mkdir(parents=True)
    program = _program(tmp_path / "host" / "bin", "codex")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = outside / "detour"
    target = os.path.join(str(ws / "decoy"), "..", "..", "host", "bin")
    symlink_or_skip(target, link, target_is_directory=True)
    real = _program(tmp_path / "real", "codex")
    assert _outside_resolved(link, ws)
    spelled = os.path.join(str(link), program.name)
    with _metadata_walk(descriptors, monkeypatch):
        assert which("codex", _path(link), outside=ws) is None
        assert which("codex", _path(link), outside=ws, fence_program=True) is None
        assert which("codex", _path(link, real.parent), outside=ws, fence_program=True) == str(real)
        assert only_skipped("codex", _path(link), outside=ws) == [
            Hit(path=spelled, entry=str(link), reason="inside_fence")]
        assert only_skipped("codex", _path(link), outside=ws, fence_program=True) == [
            Hit(path=spelled, entry=str(link), reason="inside_fence")]


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent traversal follows directory symlinks")
@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_parent_traversal_spelling_that_enters_the_fence_is_skipped(tmp_path, descriptors, monkeypatch):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    _program(ws / "host-bin", "codex")
    outside = tmp_path / "host-bin"
    real = _program(outside, "codex")
    first = tmp_path / "outside" / "deep"
    first.mkdir(parents=True)
    alias = ws / "pivot"
    symlink_or_skip(first, alias, target_is_directory=True)
    entry = str(alias) + os.sep + ".." + os.sep + ".." + os.sep + "host-bin"
    assert _outside_resolved(entry, ws)
    with _metadata_walk(descriptors, monkeypatch):
        assert which("codex", _path(entry), outside=ws) is None
        assert which("codex", _path(entry, real.parent), outside=ws) == str(real)
        assert only_skipped("codex", _path(entry), outside=ws) == [
            Hit(path=os.path.join(entry, real.name), entry=entry, reason="inside_fence")]


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_outside_directory_and_program_symlinks_stay_eligible(tmp_path, descriptors, monkeypatch):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    ws.mkdir()
    program = _program(tmp_path / "toolchain", "codex")
    linkdir = tmp_path / "linkbin"
    symlink_or_skip(program.parent, linkdir, target_is_directory=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    alias = bindir / ("codex" + EXE)
    symlink_or_skip(program, alias)
    with _metadata_walk(descriptors, monkeypatch):
        assert which("codex", _path(linkdir), outside=ws, fence_program=True) == str(linkdir / program.name)
        assert which("codex", _path(bindir), outside=ws, fence_program=True) == str(alias)


def test_a_symlink_cycle_is_skipped_without_searching_it(tmp_path):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    ws.mkdir()
    left = tmp_path / "left"
    left.mkdir()
    right = tmp_path / "right"
    symlink_or_skip(right, left / "cycle", target_is_directory=True)
    symlink_or_skip(left / "cycle", right, target_is_directory=True)
    real = _program(tmp_path / "bin", "codex")
    assert which("codex", _path(right, real.parent), outside=ws) == str(real)
    assert which("codex", _path(right), outside=ws) is None


def test_an_over_budget_entry_is_skipped_before_resolution(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    real = _program(tmp_path / "bin", "codex")
    huge = os.sep + os.sep.join(["component"] * 513)
    original = pathlookup.os

    def realpath(path):
        text = os.fspath(path)
        if text == huge or text.count(os.sep) > 500:
            raise AssertionError("over-budget entry reached resolution")
        return os.path.realpath(path)

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(os), "path": SimpleNamespace(
        **{**vars(os.path), "realpath": realpath})}))
    try:
        assert which("codex", _path(huge, real.parent), outside=ws) == str(real)
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)


@pytest.mark.parametrize("case", ["type", "os", "value", "runtime"])
def test_git_fence_propagates_a_caller_fspath_exception(case):
    from aegis_core import pathlookup
    failures = {"type": TypeError, "os": OSError, "value": ValueError, "runtime": RuntimeError}

    class MalformedPath(os.PathLike):
        def __fspath__(self):
            raise failures[case]("private-path-protocol-diagnostic")

    with pytest.raises(failures[case], match="^private-path-protocol-diagnostic$"):
        pathlookup.git_fence(MalformedPath())


@pytest.mark.parametrize("cwd", [123, 12.5], ids=["int", "float"])
def test_git_fence_refuses_an_unsupported_cwd_type(cwd):
    from aegis_core import pathlookup
    assert pathlookup.git_fence(cwd) == os.path.normcase(os.path.abspath(os.sep))


def test_git_fence_refuses_a_non_string_fspath_result(tmp_path):
    from aegis_core import pathlookup

    class MalformedPath(os.PathLike):
        def __fspath__(self):
            return 42

    class BytesPath(os.PathLike):
        def __fspath__(self):
            return os.fsencode(str(tmp_path))

    assert pathlookup.git_fence(MalformedPath()) == os.path.normcase(os.path.abspath(os.sep))
    assert pathlookup.git_fence(BytesPath()) == pathlookup.git_fence(str(tmp_path))


def test_ordinary_refusal_canonicalizes_redacts_then_truncates_its_fence(monkeypatch):
    from types import SimpleNamespace
    from aegis_core import gitsafe, pathlookup
    secret = "ghp_" + "A" * 40
    root = os.sep + "root-" + secret + "\n" + os.sep + "tail-" + "x" * 400
    original, probe = pathlookup.os, pathlookup.descriptor_fence_supported
    fake_path = SimpleNamespace(**{**vars(os.path), "realpath": lambda path: os.fspath(path),
        "islink": lambda path: False, "isfile": lambda path: False, "lexists": lambda path: False})
    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(os), "path": fake_path,
        "environ": {"PATH": ""}, "getcwd": lambda: root}))
    monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
    gitsafe._reset_for_tests()
    try:
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.git_executable()
        message = str(caught.value)
        assert caught.value.code == "ERR_AEGIS"
        assert secret not in message and "\n" not in message
        shown = message.split("enclosing checkout ", 1)[1]
        assert shown == os.path.normcase(os.path.abspath(os.sep))
        view = pathlookup_gitcache._RootCache(pathlookup.GitCache(), root)
        redacted = str(view.error(gitsafe.GitError)("git is not installed or not on PATH"))
        assert secret not in redacted and "\n" not in redacted and "[REDACTED" in redacted
        assert len(redacted.split("enclosing checkout ", 1)[1]) <= 256
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", probe)
        gitsafe._reset_for_tests()


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_cwd_alias_into_an_unmarked_subdirectory_keeps_the_outer_workspace(tmp_path):
    """A symlink into an unmarked subdirectory cannot shrink the physical checkout."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    workspace = tmp_path / "workspace"
    (workspace / "sub").mkdir(parents=True)
    (workspace / ".git").mkdir()
    owner = tmp_path / "owner"
    owner.mkdir()
    jump = owner / "jump"
    symlink_or_skip(workspace / "sub", jump, target_is_directory=True)
    expected = os.path.normcase(os.path.realpath(workspace))
    assert os.path.normcase(pathlookup.git_fence(jump, descriptors=False)) == expected
    if pathlookup.descriptor_fence_supported():
        assert os.path.normcase(pathlookup.git_fence(jump)) == expected


def _nested_alias(tmp_path, form):
    """/a/one -> /a/two -> /b, workspace /b/ws, shadow program at /a/ws/bin."""
    from conftest import symlink_or_skip
    base = tmp_path / "nest"
    a, b = base / "a", base / "b"
    (b / "ws").mkdir(parents=True)
    a.mkdir()
    if form == "absolute":
        symlink_or_skip(a / "two", a / "one", target_is_directory=True)
    else:
        symlink_or_skip("two", a / "one", target_is_directory=True)
    symlink_or_skip(b, a / "two", target_is_directory=True)
    shadow = _program(a / "ws" / "bin", "codex")
    _program(b / "ws" / "bin", "codex")
    return a, b, shadow


@pytest.mark.parametrize("form", ["absolute", "relative"])
@pytest.mark.parametrize("descriptors", [False, True], ids=["metadata", "descriptors"])
def test_nested_symlinks_keep_the_walked_physical_location(tmp_path, form, descriptors, monkeypatch):
    from aegis_core import pathlookup
    if descriptors and not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor walk is unavailable")
    a, b, shadow = _nested_alias(tmp_path, form)
    real = _program(tmp_path / "host", "codex")
    entry = a / "one" / "ws" / "bin"
    fence = b / "ws"
    with _metadata_walk(descriptors, monkeypatch):
        assert which("codex", _path(entry), outside=fence, fence_program=True) is None
        assert which("codex", _path(entry, real.parent), outside=fence, fence_program=True) == str(real)
        assert str(shadow) != str(real)


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_cached_nested_symlink_path_is_dropped_and_an_outside_path_hits(tmp_path):
    from aegis_core import pathlookup
    a, b, shadow = _nested_alias(tmp_path, "absolute")
    real = _program(tmp_path / "host", "codex")
    cache = pathlookup.GitCache()
    view = cache.for_cwd(b / "ws")
    view[("git",)] = str(a / "one" / "ws" / "bin" / shadow.name)
    assert view.get(("git",)) is None
    view[("git",)] = str(real)
    assert view.get(("git",)) == str(real)


def test_an_injected_junction_into_the_fence_is_skipped(tmp_path, monkeypatch):
    """Platforms without junctions still observe a mount-point reparse into the fence."""
    ws = tmp_path / "ws"
    host = tmp_path / "host"
    alias = host / "alias"
    planted = _program(alias, "codex")
    real = _program(tmp_path / "real", "codex")

    def observer(text):
        if os.path.normcase(text) == os.path.normcase(str(alias)):
            return ("link", str(ws / "bin"))
        return None

    with _observe_reparse(observer, monkeypatch):
        assert which("codex", _path(alias), outside=ws, descriptors=False) is None
        assert which("codex", _path(alias, real.parent), outside=ws, descriptors=False) == str(real)
    assert planted.is_file()


def test_an_unsupported_reparse_point_is_refused(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    alias = tmp_path / "host" / "alias"
    _program(alias, "codex")
    real = _program(tmp_path / "real", "codex")

    def observer(text):
        if os.path.normcase(text) == os.path.normcase(str(alias)):
            return ("unsupported", None)
        return None

    with _observe_reparse(observer, monkeypatch):
        assert which("codex", _path(alias), outside=ws, descriptors=False) is None
        assert which("codex", _path(alias, real.parent), outside=ws, descriptors=False) == str(real)


@pytest.mark.skipif(os.name != "nt", reason="directory junctions are a Windows reparse form")
def test_a_windows_junction_into_the_fence_is_skipped(tmp_path):
    import subprocess
    ws = tmp_path / "ws"
    _program(ws / "bin", "codex")
    link = tmp_path / "host" / "alias"
    link.parent.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(ws / "bin")], check=True, capture_output=True)
    real = _program(tmp_path / "real", "codex")
    assert which("codex", _path(link), outside=ws, descriptors=False) is None
    assert which("codex", _path(link, real.parent), outside=ws, descriptors=False) == str(real)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX fifo")
def test_a_fifo_path_entry_does_not_block_resolution(tmp_path):
    import signal
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    fifo = tmp_path / "fifo-entry"
    os.mkfifo(fifo)
    real = _program(tmp_path / "bin", "codex")
    assert pathlookup._provenance_inside(str(fifo), str(ws), descriptors=False) is True

    def lookup(descriptors):
        return which("codex", _path(fifo, real.parent), outside=ws, descriptors=descriptors)

    def bounded(descriptors):
        if hasattr(signal, "setitimer"):
            signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(TimeoutError("fifo lookup blocked")))
            signal.setitimer(signal.ITIMER_REAL, 2)
        try:
            return lookup(descriptors)
        finally:
            if hasattr(signal, "setitimer"):
                signal.setitimer(signal.ITIMER_REAL, 0)

    assert bounded(False) == str(real)
    if pathlookup.descriptor_fence_supported():
        assert bounded(None) == str(real)


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_cache_miss_clears_only_the_current_fence(tmp_path):
    from aegis_core import pathlookup
    left_root = tmp_path / "left"
    right_root = tmp_path / "right"
    (left_root / ".git").mkdir(parents=True)
    (right_root / ".git").mkdir(parents=True)
    real = _program(tmp_path / "host", "codex")
    cache = pathlookup.GitCache()
    left, right = cache.for_cwd(left_root), cache.for_cwd(right_root)
    assert left.fence != right.fence
    left[("git",)] = str(real)
    right[("git",)] = str(real)
    left.clear()
    assert ("git",) not in [key[1] for key in cache if isinstance(key, tuple) and key[0] == left.fence]
    assert right.get(("git",)) == str(real)


def _symlink_chain(root, hops: int):
    """``hops`` directory links, the last of which names a real directory."""
    from conftest import symlink_or_skip
    final = root / "final"
    final.mkdir(parents=True)
    current = final
    entry = final
    for index in range(hops):
        entry = root / f"hop{index}"
        symlink_or_skip(current, entry, target_is_directory=True)
        current = entry
    return entry


def test_link_hops_stop_at_the_cap_for_the_whole_walk(tmp_path):
    """One counter covers every link the walk follows, including ones after a nested target."""
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    short = _symlink_chain(tmp_path / "short", 5)
    planted = _program(tmp_path / "short" / "final", "codex")
    real = _program(tmp_path / "host", "codex")
    allowed = _symlink_chain(tmp_path / "allowed", 40)
    refused = _symlink_chain(tmp_path / "refused", 41)
    assert pathlookup._provenance_inside(str(allowed), str(ws), descriptors=False) is False
    assert pathlookup._provenance_inside(str(refused), str(ws), descriptors=False) is True
    assert which("codex", _path(short, real.parent), outside=ws, descriptors=False) == str(short / planted.name)
    if pathlookup.descriptor_fence_supported():
        assert pathlookup._provenance_inside(str(allowed), str(ws)) is False
        assert pathlookup._provenance_inside(str(refused), str(ws)) is True


def test_a_windows_rooted_path_uses_the_current_drive(monkeypatch):
    """``\\ws\\bin`` is on the cwd drive. Lexical collapse must not hide a visit to the fence."""
    import ntpath
    import stat as statmod
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    fence = r"C:\ws"
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    def rooted_isabs(path):
        # Python 3.13 ntpath.isabs('\\\\ws\\\\bin') is false. Model that here so 3.12 cannot hide it.
        text = os.fspath(path)
        if text[:1] in "\\/" and text[1:2] not in "\\/":
            return False
        return ntpath.isabs(text)

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": lambda path: path, "isabs": rooted_isabs,
        "islink": lambda path: False, "isfile": lambda path: True, "lexists": lambda path: False})

    def lstat(path, *args, **kwargs):
        return SimpleNamespace(st_mode=statmod.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\host", "lstat": lstat,
        "access": lambda *args, **kwargs: True, "listdir": lambda directory: ["git.exe"],
        "environ": {"PATHEXT": ".EXE"}})
    monkeypatch.setattr("aegis_core.pathlookup.os", modeled)
    monkeypatch.setattr("aegis_core.primitives.os", modeled)
    monkeypatch.setattr("aegis_core.pathlookup.sys", SimpleNamespace(**{**vars(original_sys), "platform": "win32"}))
    try:
        assert pathlookup._provenance_inside(r"\ws\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"\outside\..\ws\..\outside\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"\host\..\other\bin", fence, descriptors=False) is False
        assert pathlookup.which("git.exe", path=r"\ws\bin", outside=fence, fence_program=True, descriptors=False) is None
        assert pathlookup.which("git.exe", path=r"\host\bin", outside=fence, fence_program=True, descriptors=False) == ntpath.join(r"\host\bin", "git.exe")
        skipped = pathlookup.only_skipped("git.exe", path=r"\ws\bin", outside=fence, fence_program=True)
        assert skipped and skipped[0].reason == pathlookup.INSIDE_FENCE
        modeled.getcwd = lambda: r"D:\host"
        assert pathlookup._provenance_inside(r"\ws\bin", fence, descriptors=False) is False
        # Python 3.9–3.12 report a drive-less rooted path as absolute.
        paths.isabs = lambda path: rooted_isabs(path) or str(path).startswith("\\")
        paths.abspath = lambda path: "D:" + path if path.startswith("\\") else path
        assert pathlookup._provenance_inside(r"\bin\git.exe", r"C:\bin", descriptors=False) is False
        assert pathlookup.fenced_program(r"\bin\git.exe", r"C:\bin", descriptors=False) is None
        assert pathlookup.fenced_program(r"D:\bin\git.exe", r"C:\bin", descriptors=False) == r"D:\bin\git.exe"
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.primitives.os", primitive_os)
        monkeypatch.setattr("aegis_core.pathlookup.sys", original_sys)


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute-only mode")
def test_an_execute_only_outside_program_stays_selectable(tmp_path):
    """A leaf the caller can run but not read is outside. Opening it for the type check must not refuse it."""
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor walk is unavailable")
    ws = tmp_path / "ws"
    ws.mkdir()
    locked = _program(tmp_path / "locked", "codex")
    os.chmod(locked, 0o111)
    real = _program(tmp_path / "host", "codex")
    assert which("codex", _path(locked.parent, real.parent), outside=ws, fence_program=True) == str(locked)
    assert only_skipped("codex", _path(locked.parent), outside=ws, fence_program=True) == []


def test_nested_link_targets_share_one_hop_counter(tmp_path):
    """A target that links, continues, and links again spends the hops already used.

    Six stages of ``../d{n}/s/../../d{n}/s`` follow 63 links. A counter that resets
    when a nested target returns would accept them. The cap is 40.
    """
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    root = tmp_path / "shape"
    fence = root / "fence"
    fence.mkdir(parents=True)
    stages = 6
    for index in range(stages + 1):
        (root / f"d{index}").mkdir()
    (root / f"d{stages}" / "s").mkdir()
    for index in range(stages):
        symlink_or_skip(f"../d{index + 1}/s/../../d{index + 1}/s", root / f"d{index}" / "s", target_is_directory=True)
    entry = root / "d0" / "s"
    _program(root / f"d{stages}" / "s", "codex")
    real = _program(tmp_path / "host", "codex")
    assert pathlookup._provenance_inside(str(entry), str(fence), descriptors=False) is True
    assert which("codex", _path(entry, real.parent), outside=fence, descriptors=False) == str(real)
    if pathlookup.descriptor_fence_supported():
        assert pathlookup._provenance_inside(str(entry), str(fence)) is True


def _volume() -> str:
    return os.path.normcase(os.path.abspath(os.sep))


def _marker(path):
    (path / ".git").mkdir(parents=True, exist_ok=True)
    return path


def _both_modes(cwd):
    """Metadata and, when the host can, descriptor discovery of one cwd."""
    from aegis_core import pathlookup
    found = [pathlookup.git_fence(cwd, descriptors=False)]
    if pathlookup.descriptor_fence_supported():
        found.append(pathlookup.git_fence(cwd))
    return found


@pytest.fixture
def clean_checkout_ancestors(tmp_path, monkeypatch):
    """Model a clean host around synthetic checkouts; keep every fixture marker."""
    monkeypatch.setattr("aegis_core.pathlookup.os", clean_host_os(tmp_path))

@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_raw_cwd_dotdot_keeps_the_checkout_abspath_would_skip(tmp_path):
    """``/owner/jump/../sub`` must see the checkout ``jump`` enters, not the collapsed spelling."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    owner = tmp_path / "owner"
    owner.mkdir()
    ws = _marker(tmp_path / "ws")
    (ws / "deep").mkdir()
    (ws / "sub").mkdir()
    jump = owner / "jump"
    symlink_or_skip(ws / "deep", jump, target_is_directory=True)
    cwd = str(jump) + os.sep + ".." + os.sep + "sub"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == ([expected, expected] if pathlookup.descriptor_fence_supported() else [expected])
    planted = _program(ws / "bin", "git")
    real = _program(tmp_path / "host", "git")
    fence = pathlookup.git_fence(cwd, descriptors=False)
    assert which("git", _path(ws / "bin"), outside=fence, descriptors=False) is None
    assert which("git", _path(ws / "bin", real.parent), outside=fence, descriptors=False) == str(real)
    assert planted.is_file()


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_disjoint_checkouts_fence_the_whole_volume(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "ws")
    other = _marker(tmp_path / "other")
    jump = ws / "jump"
    symlink_or_skip(other, jump, target_is_directory=True)
    assert _both_modes(jump) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    fence = pathlookup.git_fence(jump, descriptors=False)
    assert which("git", _path(planted.parent), outside=fence, descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_descriptor_alias_keeps_the_workspace_marker(tmp_path):
    """``/alias -> /base`` then ``ws/jump -> /outside`` must not discover ``/outside``."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    base = tmp_path / "base"
    ws = _marker(base / "ws")
    alias = tmp_path / "alias"
    symlink_or_skip(base, alias, target_is_directory=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    jump = ws / "jump"
    symlink_or_skip(outside, jump, target_is_directory=True)
    cwd = alias / "ws" / "jump"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    assert which("git", _path(planted.parent), outside=pathlookup.git_fence(cwd, descriptors=False), descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_dotdot_through_a_pivot_still_records_the_workspace(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    home = tmp_path / "home" / "u"
    ws = _marker(home / "ws")
    man = tmp_path / "usr" / "share" / "man" / "man1"
    man.mkdir(parents=True)
    pivot = ws / "pivot"
    symlink_or_skip(man, pivot, target_is_directory=True)
    (tmp_path / "elsewhere").mkdir()
    cwd = str(pivot) + (os.sep + "..") * 4 + os.sep + "elsewhere"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    assert which("git", _path(planted.parent), outside=pathlookup.git_fence(cwd, descriptors=False), descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_symlinked_prefix_does_not_drop_the_workspace_marker(tmp_path):
    """macOS ``/var -> private/var`` plus ``ws/jump -> /usr`` stays on the workspace."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    private = tmp_path / "private" / "var"
    ws = _marker(private / "ws")
    var = tmp_path / "var"
    symlink_or_skip("private/var", var, target_is_directory=True)
    usr = tmp_path / "usr"
    usr.mkdir()
    jump = private / "ws" / "jump"
    symlink_or_skip(usr, jump, target_is_directory=True)
    cwd = var / "ws" / "jump"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_link_remainder_past_the_component_cap_fences_the_volume(tmp_path):
    """Splicing a link while keeping the previous remainder past 512 components refuses."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "workspace")
    sub = ws / "sub"
    sub.mkdir()
    owner = tmp_path / "owner"
    owner.mkdir()
    jump = owner / "jump"
    symlink_or_skip(sub, jump, target_is_directory=True)
    rest = (os.sep + ".." + os.sep + "sub") * 150
    symlink_or_skip("." + rest, sub / "l2", target_is_directory=True)
    symlink_or_skip("l2" + rest, sub / "l1", target_is_directory=True)
    cwd = jump / "l1"
    assert _both_modes(cwd) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    fence = pathlookup.git_fence(str(cwd), descriptors=False)
    assert fence == _volume()
    assert which("git", _path(planted.parent), outside=fence, descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_an_escape_after_a_marked_ancestor_keeps_that_checkout(tmp_path):
    """``jump -> workspace/sub`` then ``escape -> outside`` stays on the ancestor checkout."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "workspace")
    sub = ws / "sub"
    sub.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_or_skip(outside, sub / "escape", target_is_directory=True)
    owner = tmp_path / "owner"
    owner.mkdir()
    jump = owner / "jump"
    symlink_or_skip(sub, jump, target_is_directory=True)
    cwd = jump / "escape"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    _marker(sub)
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    assert which("git", _path(planted.parent), outside=pathlookup.git_fence(str(cwd), descriptors=False), descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_an_unproven_cwd_link_fences_the_volume(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "ws")
    (ws / "sub").mkdir()
    (ws / "deep").mkdir()
    owner = tmp_path / "owner"
    owner.mkdir()
    chain = tmp_path / "hops"
    chain.mkdir()
    current = ws / "sub"
    for index in range(41):
        link = chain / f"hop{index}"
        symlink_or_skip(current, link, target_is_directory=True)
        current = link
    hops = current
    dotted = owner / "jump"
    target = str(ws) + (os.sep + ".") * 600 + os.sep + "deep"
    symlink_or_skip(target, dotted, target_is_directory=True)
    assert _both_modes(hops) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    assert _both_modes(dotted) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    fence = pathlookup.git_fence(dotted, descriptors=False)
    assert fence == _volume()
    assert which("git", _path(planted.parent), outside=fence, descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_an_unsupported_cwd_reparse_fences_the_volume(tmp_path, monkeypatch):
    from aegis_core import pathlookup
    alias = tmp_path / "alias"
    alias.mkdir()
    ws = _marker(tmp_path / "ws")
    (ws / "sub").mkdir()

    def observer(text):
        if os.path.normcase(text) == os.path.normcase(str(alias)):
            return ("unsupported", None)
        return None

    with _observe_reparse(observer, monkeypatch):
        assert pathlookup.git_fence(alias, descriptors=False) == _volume()
    assert pathlookup.git_fence(ws, descriptors=False) == os.path.normcase(os.path.realpath(ws))


def test_a_walk_cannot_descend_through_a_regular_file(tmp_path):
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    regular = outside / "regular"
    regular.parent.mkdir()
    regular.write_bytes(b"not-a-directory")
    _program(outside / "bin", "codex")
    entry = str(regular) + os.sep + ".." + os.sep + "bin"
    assert pathlookup._provenance_inside(entry, str(ws), descriptors=False) is True
    assert which("codex", _path(entry), outside=ws, descriptors=False) is None
    if pathlookup.descriptor_fence_supported():
        assert pathlookup._provenance_inside(entry, str(ws)) is True


def test_a_trailing_separator_does_not_split_one_directory(tmp_path):
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    (ws / "bin").mkdir(parents=True)
    spelled = str(ws) + os.sep
    assert pathlookup._component_inside(str(ws), spelled) is True
    assert pathlookup._component_inside(spelled, str(ws)) is True
    assert pathlookup._provenance_inside(str(ws / "bin"), spelled, descriptors=False) is True


def test_real_key_none_refuses_a_walk_that_stayed_outside(tmp_path, monkeypatch):
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    program = _program(tmp_path / "host" / "bin", "codex")
    previous = pathlookup._real_key_observer

    def observer(path):
        return None

    monkeypatch.setattr("aegis_core.pathlookup._real_key_observer", observer)
    try:
        assert pathlookup._provenance_inside(str(program.parent), str(ws), descriptors=False) is True
        assert which("codex", _path(program.parent), outside=ws, descriptors=False) is None
    finally:
        monkeypatch.setattr("aegis_core.pathlookup._real_key_observer", previous)


def test_windows_short_names_trailing_dots_and_rooted_links_stay_closed(monkeypatch):
    """8.3 and trailing-dot aliases are real_key; ``..`` collapse is abspath; rooted links use the walked drive."""
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    fence = r"C:\workspace"
    hostile = r"C:\bin"
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    previous_key, previous_reparse = pathlookup._real_key_observer, pathlookup._reparse_observer

    def lstat(path, *args, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": lambda path: os.fspath(path),
        "islink": lambda path: False, "isfile": lambda path: True, "lexists": lambda path: False})
    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\host", "lstat": lstat,
        "access": lambda *args, **kwargs: True, "listdir": lambda directory: ["git.exe"],
        "environ": {"PATHEXT": ".EXE"}})

    def observer(path):
        text = ntpath.normcase(os.fspath(path))
        for alias in (r"c:\worksp~1", r"c:\workspace."):
            if text.startswith(alias):
                return ntpath.normcase(ntpath.normpath(r"C:\workspace" + text[len(alias):]))
        return pathlookup._REAL_KEY_FALLBACK

    monkeypatch.setattr("aegis_core.pathlookup.os", modeled)
    monkeypatch.setattr("aegis_core.primitives.os", modeled)
    monkeypatch.setattr("aegis_core.pathlookup.sys", SimpleNamespace(**{**vars(original_sys), "platform": "win32"}))
    monkeypatch.setattr("aegis_core.pathlookup._real_key_observer", observer)
    try:
        assert pathlookup._provenance_inside(r"C:\workspace.\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"C:\WORKSP~1\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"C:\WORKSP~1\..\host", fence, descriptors=False) is True
        assert pathlookup.which("git.exe", path=r"C:\WORKSP~1\bin", outside=fence, fence_program=True, descriptors=False) is None
        cache = pathlookup.GitCache()
        view = pathlookup_gitcache._RootCache(cache, ntpath.normcase(fence))
        view[("git",)] = r"C:\WORKSP~1\bin\git.exe"
        assert view.get(("git",)) is None

        def junction(text):
            if ntpath.normcase(os.fspath(text)) == ntpath.normcase(r"C:\g"):
                return ("link", r"C:\tools\git\sub")
            return None

        monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", junction)
        assert pathlookup._provenance_inside(r"C:\g\..\bin", hostile, descriptors=False) is True

        for drive, other in (("C:", "D:"), ("D:", "C:")):
            link = drive + r"\outside\link"

            def rooted(text):
                return ("link", r"\ws\bin") if ntpath.normcase(os.fspath(text)) == ntpath.normcase(link) else None

            monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", rooted)
            assert pathlookup._provenance_inside(link, other + r"\ws", descriptors=False) is False
            assert pathlookup._provenance_inside(link, drive + r"\ws", descriptors=False) is True
            assert pathlookup.which(
                "git.exe", path=link, outside=drive + r"\ws", fence_program=True, descriptors=False,
            ) is None
            cross = pathlookup_gitcache._RootCache(pathlookup.GitCache(), ntpath.normcase(drive + r"\ws"))
            cross[("git",)] = link + r"\git.exe"
            assert cross.get(("git",)) is None
        assert pathlookup._relative_parts("C:sub") is None
        assert pathlookup._fence_raw("C:sub") is None
        assert pathlookup._splice_target(r"\ws\bin", [], "D:")[0] == "D:"

        # The execution cwd also follows Win32 normalization. Prove the raw walk
        # first, then inspect the canonical cwd without discarding either checkout.
        monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", junction)
        paths.realpath = lambda path: ntpath.normpath(os.fspath(path))
        paths.isfile = lambda path: path.endswith("git.exe")

        def marker_stat(path, *args, **kwargs):
            if ntpath.normcase(path) == ntpath.normcase(r"C:\bin\.git"):
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            raise FileNotFoundError(2, "no modeled marker")

        modeled.stat = marker_stat
        assert pathlookup.git_fence(r"C:\g\..\bin", descriptors=False) == ntpath.normcase(r"C:\bin")
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.primitives.os", primitive_os)
        monkeypatch.setattr("aegis_core.pathlookup.sys", original_sys)
        monkeypatch.setattr("aegis_core.pathlookup._real_key_observer", previous_key)
        monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", previous_reparse)


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_concurrent_partition_misses_do_not_raise(tmp_path):
    """Two clears of one fence must not KeyError, and must leave the other fence."""
    import time
    from threading import Thread
    from aegis_core import pathlookup
    left_root, right_root = _marker(tmp_path / "left"), _marker(tmp_path / "right")
    real = _program(tmp_path / "host", "codex")

    class Slow(pathlookup.GitCache):
        def __iter__(self):
            keys = list(dict.keys(self))
            for key in keys:
                time.sleep(0.002)
                yield key

    cache = Slow()
    left, right = cache.for_cwd(left_root), cache.for_cwd(right_root)
    for index in range(30):
        left[("git", index)] = str(real)
        right[("git", index)] = str(real)
    errors = []

    def hammer(view):
        try:
            view.clear()
        except Exception as exc:
            errors.append(exc)

    workers = [Thread(target=hammer, args=(left,)) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(20)
    assert not errors and not any(worker.is_alive() for worker in workers)
    assert right.get(("git", 0)) == str(real)
    cache.clear()
    assert list(cache) == []


def test_descriptor_fence_closes_the_entered_directory_when_marker_recording_fails(tmp_path, monkeypatch):
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("descriptor counting requires procfs")
    ws = _marker(tmp_path / "ws")
    original = pathlookup._record_markers

    def record(path, markers):
        if os.path.normcase(path) == os.path.normcase(str(ws)):
            raise OSError(13, "marker inspection failed")
        return original(path, markers)

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr("aegis_core.pathlookup._record_markers", record)
    try:
        assert pathlookup.git_fence(ws) == _volume()
    finally:
        monkeypatch.setattr("aegis_core.pathlookup._record_markers", original)
    assert len(os.listdir("/proc/self/fd")) == before
    assert pathlookup.git_fence(ws) == _outer_marker_fence(ws)


def test_cwd_byte_budget_is_checked_before_decoding(monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original = pathlookup.os
    large = b"x" * 16385

    def decode(value):
        assert value is not large, "oversized cwd reached decoding"
        return os.fsdecode(value)

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(original), "fsdecode": decode}))
    try:
        assert pathlookup.git_fence(large) == _volume()
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)


def test_link_byte_budget_is_checked_before_decoding(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original, previous = pathlookup.os, pathlookup._reparse_observer
    large = b"x" * 16385
    ws = tmp_path / "ws"
    ws.mkdir()
    alias = tmp_path / "alias"
    alias.mkdir()
    real = _program(tmp_path / "host", "codex")

    def decode(value):
        assert value is not large, "oversized link reached decoding"
        return os.fsdecode(value)

    def observer(path):
        return ("link", large) if path == str(alias) else None

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(original), "fsdecode": decode}))
    monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", observer)
    try:
        assert which("codex", _path(alias, real.parent), outside=ws, descriptors=False) == str(real)
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", previous)


def test_cache_iteration_survives_another_partition_write(tmp_path, clean_checkout_ancestors):
    from threading import Thread
    from aegis_core import pathlookup
    left_root, right_root = _marker(tmp_path / "left"), _marker(tmp_path / "right")
    cache = pathlookup.GitCache()
    left, right = cache.for_cwd(left_root), cache.for_cwd(right_root)
    left[("git",)] = "left"
    right[("git",)] = "right"
    initial = set(cache)
    reader = iter(cache)
    first = next(reader)
    worker = Thread(target=lambda: right.__setitem__(("new",), "new"))
    worker.start()
    worker.join(5)
    assert not worker.is_alive()
    assert {first, *reader} == initial


@pytest.mark.parametrize("descriptors", [False, True], ids=["metadata", "descriptors"])
def test_unreadable_marker_metadata_closes_discovery(tmp_path, clean_checkout_ancestors, descriptors, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    if descriptors and not pathlookup.descriptor_fence_supported():
        pytest.skip("no descriptor discovery")
    ws = _marker(tmp_path / "ws")
    original = pathlookup.os

    def stat(path, *args, **kwargs):
        parent = kwargs.get("dir_fd")
        marker = os.path.join(pathlookup._fd_location(parent), path) if parent is not None else os.fspath(path)
        if os.path.normcase(marker) == os.path.normcase(str(ws / ".git")):
            raise PermissionError(13, "marker is unreadable")
        return original.stat(path, *args, **kwargs)

    monkeypatch.setattr("aegis_core.pathlookup.os", SimpleNamespace(**{**vars(original), "stat": stat}))
    try:
        assert pathlookup.git_fence(ws, descriptors=descriptors) == _volume()
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
    assert pathlookup.git_fence(ws, descriptors=False) == os.path.normcase(str(ws))


def test_an_unproven_cross_drive_cwd_refuses_programs_on_every_drive(monkeypatch):
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    previous = pathlookup._reparse_observer
    paths = SimpleNamespace(**{**vars(ntpath), "realpath": lambda path: os.fspath(path),
        "islink": lambda path: False, "isfile": lambda path: True})

    def lstat(path, *args, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    def marker_stat(path, *args, **kwargs):
        if ntpath.normcase(path) == ntpath.normcase(r"D:\ws\.git"):
            return SimpleNamespace(st_mode=stat.S_IFDIR)
        raise FileNotFoundError(2, "no modeled marker")

    def observer(path):
        text = ntpath.normcase(path)
        if text == ntpath.normcase(r"C:\owner\jump"):
            return ("link", r"D:\ws\sub")
        if text == ntpath.normcase(r"D:\ws\sub\blocked"):
            return ("unsupported", None)
        return None

    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\owner", "lstat": lstat,
        "stat": marker_stat, "access": lambda *args: True, "listdir": lambda path: ["git.exe"],
        "environ": {"PATHEXT": ".EXE"}})
    monkeypatch.setattr("aegis_core.pathlookup.os", modeled)
    monkeypatch.setattr("aegis_core.primitives.os", modeled)
    monkeypatch.setattr("aegis_core.pathlookup.sys", SimpleNamespace(**{**vars(original_sys), "platform": "win32"}))
    monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", observer)
    try:
        fence = pathlookup.git_fence(r"C:\owner\jump\blocked", descriptors=False)
        assert fence == ntpath.normcase("C:\\")
        assert pathlookup.which("git.exe", path=r"D:\ws\bin", outside=fence, descriptors=False) is None
        assert pathlookup.only_skipped("git.exe", path=r"D:\ws\bin", outside=fence)[0].reason == "inside_fence"
        # An explicitly proven volume fence still permits owner programs on another drive.
        assert pathlookup.which("git.exe", path=r"D:\host", outside="C:\\", descriptors=False) is not None
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.primitives.os", primitive_os)
        monkeypatch.setattr("aegis_core.pathlookup.sys", original_sys)
        monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", previous)


@pytest.fixture
def checkout_process(monkeypatch):
    """Own and restore this test's cwd, PATH and ordinary executable cache."""
    from aegis_core import gitsafe, pathlookup
    cwd, search, previous = os.getcwd(), os.environ.get("PATH"), gitsafe._GIT_FOUND
    cache = pathlookup.GitCache()
    monkeypatch.setattr("aegis_core.gitsafe._GIT_FOUND", cache)
    try:
        yield cache
    finally:
        os.chdir(cwd)
        monkeypatch.setattr("aegis_core.gitsafe._GIT_FOUND", previous)
        if search is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = search


@pytest.mark.skipif(os.name != "posix", reason="backslash is a POSIX filename character")
@pytest.mark.parametrize("name", ["repo\\", "repo\\inner"], ids=["trailing", "interior"])
@pytest.mark.parametrize("relative", [".", "sub/.."], ids=["dot", "parent"])
@pytest.mark.parametrize("descriptors", [False, True], ids=["metadata", "descriptors"])
def test_relative_cwd_keeps_literal_backslashes(tmp_path, checkout_process, clean_checkout_ancestors,
                                               name, relative, descriptors):
    from aegis_core import pathlookup
    if descriptors and not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor-relative discovery is unavailable")
    ws = _marker(tmp_path / name)
    sibling = _marker(tmp_path / name.replace("\\", ""))
    (ws / "sub").mkdir()
    (sibling / "sub").mkdir()
    os.chdir(ws)
    expected = os.path.normcase(str(ws))
    assert pathlookup.git_fence(relative, descriptors=descriptors) == expected
    assert pathlookup.git_fence(sibling, descriptors=descriptors) == str(sibling)


@pytest.mark.skipif(os.name != "posix", reason="backslash is a POSIX filename character")
@pytest.mark.parametrize("name", ["repo\\", "repo\\inner"], ids=["trailing", "interior"])
@pytest.mark.parametrize("relative", [".", "sub/.."], ids=["dot", "parent"])
def test_ordinary_relative_cwd_backslashes_keep_execution_and_cache_separate(
        tmp_path, checkout_process, clean_checkout_ancestors, name, relative):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import gitsafe, pathlookup
    ws = _marker(tmp_path / name)
    sibling = _marker(tmp_path / name.replace("\\", ""))
    (ws / "sub").mkdir()
    (sibling / "sub").mkdir()
    planted = _program(ws / "bin", "git", b"#!/bin/sh\nprintf 'workspace-program\\n'\n")
    host = _program(tmp_path / "host", "git", b"#!/bin/sh\nprintf 'host-program\\n'\n")
    cache = checkout_process
    os.chdir(ws)
    os.environ["PATH"] = _path(planted.parent, host.parent)
    other = str(sibling)
    # Prime the sibling partition with the program that our checkout must refuse.
    assert gitsafe.run(["--version"], other).stdout == b"workspace-program\n"
    assert gitsafe.run(["--version"], relative).stdout == b"host-program\n"
    assert cache.for_cwd(relative).fence == str(ws)
    assert cache.for_cwd(other).fence == str(sibling)
    with ThreadPoolExecutor(max_workers=2) as workers:
        own = workers.submit(gitsafe.run, ["--version"], relative)
        foreign = workers.submit(gitsafe.run, ["--version"], other)
        assert own.result(timeout=10).stdout == b"host-program\n"
        assert foreign.result(timeout=10).stdout == b"workspace-program\n"
    os.environ["PATH"] = str(planted.parent)
    for _attempt in range(2):
        with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH") as caught:
            gitsafe.run(["--version"], relative)
        assert caught.value.code == "ERR_AEGIS"
    os.environ["PATH"] = _path(planted.parent, host.parent)
    assert gitsafe.run(["--version"], relative).stdout == b"host-program\n"

@contextlib.contextmanager
def _windows_volume_root_model(volume, root_state, monkeypatch):
    """Model canonical drive/UNC aliases without creating host reparse points."""
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    drive = "X:" if volume == "drive" else r"\\server\share"
    root, state = drive + "\\", [root_state]
    alias = ntpath.normcase(drive)

    def canonical(path):
        assert len(path) <= pathlookup._MAX_FENCE_CHARS
        text = ntpath.normcase(ntpath.normpath(path))
        if text == r"c:\alias" or text.startswith("c:\\alias\\"):
            text = root + text[len(r"c:\alias"):].lstrip("\\")
        if text == r"c:\launch\git.exe":
            text = ntpath.join(root, "git.exe")
        current, rest = ntpath.splitdrive(ntpath.normcase(text))
        if current == alias and state[0] != "literal":
            if state[0] == "unproven" and rest in ("", "\\"):
                return None
            backing = {"inside": r"c:\ws", "outside": r"c:\owner",
                       "through_fence": r"c:\ws\hop", "unproven": r"c:\owner"}[state[0]]
            text = backing + rest
        prefix = r"c:\ws\hop"
        if text == prefix or text.startswith(prefix + "\\"):
            text = r"c:\host\bin" + text[len(prefix):]
        return ntpath.normcase(ntpath.normpath(text))

    def reparse(path):
        text = ntpath.normcase(path)
        if text == r"c:\alias":
            return ("link", root)
        if text == r"c:\launch\git.exe":
            return ("link", ntpath.join(root, "git.exe"))
        if text == r"c:\ws\hop":
            return ("link", r"C:\host\bin")
        return None

    def lstat(path):
        return SimpleNamespace(st_mode=stat.S_IFREG if path.endswith(".exe") else stat.S_IFDIR,
                               st_file_attributes=0, st_reparse_tag=0)

    def marker(path, *args, **kwargs):
        if ntpath.normcase(path) == r"c:\ws\.git":
            return SimpleNamespace(st_mode=stat.S_IFDIR)
        raise FileNotFoundError(2, "no modeled marker")

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": canonical,
        "isfile": lambda path: path.endswith(".exe"), "islink": lambda path: False})
    modeled = SimpleNamespace(**{**vars(os), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\owner", "lstat": lstat,
        "stat": marker, "listdir": lambda path: ["git.exe"], "access": lambda *args: True,
        "environ": {"PATHEXT": ".EXE", "PATH": r"C:\host\bin"}})
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    previous_key, previous_reparse = pathlookup._real_key_observer, pathlookup._reparse_observer
    monkeypatch.setattr("aegis_core.pathlookup.os", modeled)
    monkeypatch.setattr("aegis_core.primitives.os", modeled)
    monkeypatch.setattr("aegis_core.pathlookup.sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr("aegis_core.pathlookup._real_key_observer", canonical)
    monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", reparse)
    try:
        yield root, state
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.os", original)
        monkeypatch.setattr("aegis_core.primitives.os", primitive_os)
        monkeypatch.setattr("aegis_core.pathlookup.sys", original_sys)
        monkeypatch.setattr("aegis_core.pathlookup._real_key_observer", previous_key)
        monkeypatch.setattr("aegis_core.pathlookup._reparse_observer", previous_reparse)


@pytest.mark.parametrize("case", ["entry", "absolute_target", "program", "cache", "discovery"])
@pytest.mark.parametrize("root_state", ["through_fence", "inside", "outside", "unproven"])
@pytest.mark.parametrize("volume", ["drive", "unc"])
def test_windows_root_aliases_are_checked_before_components(case, root_state, volume, checkout_process, monkeypatch):
    import ntpath
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import gitsafe, pathlookup
    fence, host = r"C:\ws", r"C:\host\bin"
    with _windows_volume_root_model(volume, root_state, monkeypatch) as (root, state):
        entry = {"entry": root, "absolute_target": r"C:\alias",
                 "program": r"C:\launch", "cache": root, "discovery": root}[case]
        if case == "discovery":
            closed = pathlookup.git_fence(root, descriptors=False)
            assert closed == ntpath.normcase(root)
            assert pathlookup.which("git.exe", path=host, outside=closed, descriptors=False) is None
            with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH") as caught:
                gitsafe.git_executable(cwd=root)
            assert caught.value.code == "ERR_AEGIS"
            state[0] = "literal"
            assert gitsafe.git_executable(cwd=root) == ntpath.join(host, "git.exe")
        elif case == "cache":
            view = pathlookup.GitCache().for_cwd(fence)
            program = ntpath.join(entry, "git.exe")
            view["git"], view["host"] = program, ntpath.join(host, "git.exe")
            with ThreadPoolExecutor(max_workers=2) as workers:
                bad = workers.submit(view.get, "git")
                good = workers.submit(view.get, "host")
                assert bad.result(timeout=10) is None
                assert good.result(timeout=10) == ntpath.join(host, "git.exe")
            state[0] = "literal"
            assert view.get("git") == program
        else:
            for _attempt in range(2):
                assert pathlookup.which("git.exe", path=entry, outside=fence,
                                        fence_program=True, descriptors=False) is None
            hits = pathlookup.only_skipped("git.exe", path=entry, outside=fence, fence_program=True)
            assert len(hits) == 1 and hits[0].reason == pathlookup.INSIDE_FENCE
            assert pathlookup.which("git.exe", path=entry + ";" + host, outside=fence,
                                    fence_program=True, descriptors=False) == ntpath.join(host, "git.exe")
            state[0] = "literal"
            assert pathlookup.which("git.exe", path=entry, outside=fence,
                                    fence_program=True, descriptors=False) is not None
        assert pathlookup.which("git.exe", path=r"Z:\host", outside=fence,
                                fence_program=True, descriptors=False) == r"Z:\host\git.exe"
        literal_unc = r"\\literal\share\host"
        assert pathlookup.which("git.exe", path=literal_unc, outside=fence,
                                fence_program=True, descriptors=False) == ntpath.join(literal_unc, "git.exe")
        prefix = "\\\\server\\"
        unc_root = prefix + "s" * (pathlookup._MAX_FENCE_CHARS - len(prefix))
        assert pathlookup.which("git.exe", path=unc_root, outside=fence,
                                fence_program=True, descriptors=False) is None


@pytest.mark.skipif(os.name != "posix", reason="descriptor root checks require POSIX")
@pytest.mark.parametrize("phase", ["start", "reset"])
def test_descriptor_alias_roots_refuse_and_close_then_retry(tmp_path, clean_checkout_ancestors, phase, monkeypatch):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("descriptor counting requires procfs")
    ws = _marker(tmp_path / "ws")
    sub = ws / "sub"
    sub.mkdir()
    link = ws / "link"
    symlink_or_skip(os.sep, link, target_is_directory=True)
    original, roots = pathlookup._fd_location, []

    def location(fd):
        physical = original(fd)
        if physical == os.sep:
            roots.append(fd)
            if phase == "start" or len(roots) > 1:
                return str(sub)
        return physical

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr("aegis_core.pathlookup._fd_location", location)
    try:
        cwd = os.sep if phase == "start" else link
        assert pathlookup.git_fence(cwd) == _volume()
    finally:
        monkeypatch.setattr("aegis_core.pathlookup._fd_location", original)
    assert roots
    assert len(os.listdir("/proc/self/fd")) == before
    assert pathlookup.git_fence(ws) == str(ws)


@pytest.fixture
def ordinary_home(tmp_path):
    """Own the test's cwd and environment; restore both before tmp_path cleanup."""
    home = tmp_path / "home"
    home.mkdir()
    previous_cwd, previous_env = os.getcwd(), dict(os.environ)
    os.environ.update(HOME=str(home), USERPROFILE=str(home))
    os.environ.pop("AEGIS_WORKSPACE", None)
    os.environ.pop("AEGIS_CLIENT", None)
    os.chdir(home)
    try:
        yield home
    finally:
        os.chdir(previous_cwd)
        os.environ.clear()
        os.environ.update(previous_env)


def test_bound_ordinary_root_normalizes_clears_and_resets_on_failure_and_retry(tmp_path):
    """The public helper is the only arming spelling: normcase(fspath), or clear, then reset."""
    from aegis_core import pathlookup
    from aegis_core.pathlookup_gitcache import bound_ordinary_root

    root = tmp_path / "Outer"
    root.mkdir()
    expected = os.path.normcase(os.fspath(root))
    child = root / "missing-child"
    child_key = os.path.normcase(os.fspath(child))
    assert pathlookup.ordinary_root.get() is None
    with bound_ordinary_root(root) as installed:
        assert installed == expected
        assert pathlookup.ordinary_root.get() == expected
        with pytest.raises(RuntimeError, match="^fixture failure$"):
            with bound_ordinary_root(None):
                assert pathlookup.ordinary_root.get() is None
                raise RuntimeError("fixture failure")
        assert pathlookup.ordinary_root.get() == expected
        with bound_ordinary_root(child):
            assert pathlookup.ordinary_root.get() == child_key
        assert pathlookup.ordinary_root.get() == expected
    assert pathlookup.ordinary_root.get() is None
    with bound_ordinary_root(os.fspath(root)):
        assert pathlookup.ordinary_root.get() == expected
    assert pathlookup.ordinary_root.get() is None


def test_bound_ordinary_root_leaves_the_outer_root_when_normalization_fails(tmp_path):
    from aegis_core.pathlookup_gitcache import bound_ordinary_root

    with bound_ordinary_root(tmp_path) as outer:
        class InvalidPath:
            def __fspath__(self):
                assert pathlookup.ordinary_root.get() == outer
                assert pathlookup_gitcache.ordinary_root.get() == outer
                raise TypeError("fixture path conversion failed")

        with pytest.raises(TypeError, match="^fixture path conversion failed$"):
            with bound_ordinary_root(InvalidPath()):
                raise AssertionError("a non-path must fail before the body runs")
        assert pathlookup.ordinary_root.get() == outer
        assert pathlookup_gitcache.ordinary_root.get() == outer
    assert pathlookup.ordinary_root.get() is None
    assert pathlookup_gitcache.ordinary_root.get() is None


def _assert_read_only_root(carrier, expected):
    assert carrier.get() == expected
    with pytest.raises(AttributeError, match=r"\bset\b"):
        _ = carrier.set
    assert carrier.get() == expected
    with pytest.raises(AttributeError, match=r"\breset\b"):
        _ = carrier.reset
    assert carrier.get() == expected


@pytest.mark.parametrize("export_name", ["pathlookup", "pathlookup_gitcache"])
def test_public_ordinary_root_refuses_mutation_lookup(export_name, tmp_path):
    export = pathlookup if export_name == "pathlookup" else pathlookup_gitcache
    with pathlookup_gitcache.bound_ordinary_root(tmp_path) as installed:
        _assert_read_only_root(export.ordinary_root, installed)
        assert pathlookup.ordinary_root.get() == installed
        assert pathlookup_gitcache.ordinary_root.get() == installed
    assert export.ordinary_root.get() is None


def test_ordinary_root_aliases_are_read_only_after_import(tmp_path):
    from contextvars import ContextVar

    import aegis_core.pathlookup as lookup
    import aegis_core.pathlookup_gitcache as cache
    from aegis_core.pathlookup_gitcache import ordinary_root as reassigned

    with cache.bound_ordinary_root(tmp_path) as installed:
        class Aliases:
            from aegis_core.pathlookup import ordinary_root as direct

        # Run the conditional class body during the test, outside the collection grammar.
        namespace = {"installed": installed, "check": _assert_read_only_root}
        exec(
            "class ConditionalAliases:\n"
            "    if installed is not None:\n"
            "        from aegis_core.pathlookup import ordinary_root as facade\n"
            "        from aegis_core.pathlookup_gitcache import ordinary_root as cache\n"
            "        check(facade, installed)\n"
            "        check(cache, installed)\n",
            namespace,
        )
        conditional = namespace["ConditionalAliases"]
        for alias in (lookup.ordinary_root, Aliases.direct, conditional.facade, conditional.cache, reassigned):
            assert alias is cache.ordinary_root
            _assert_read_only_root(alias, installed)

        reassigned = ContextVar("independent_fixture", default=None)
        token = reassigned.set("independent")
        try:
            assert reassigned.get() == "independent"
            assert lookup.ordinary_root.get() == installed
            assert cache.ordinary_root.get() == installed
        finally:
            reassigned.reset(token)
        assert reassigned.get() is None
    assert lookup.ordinary_root.get() is None
    assert cache.ordinary_root.get() is None


def test_ordinary_root_reads_defaults_and_copied_contexts_through_both_exports(tmp_path):
    from contextvars import Context, copy_context

    carriers = (pathlookup.ordinary_root, pathlookup_gitcache.ordinary_root)
    fallback = object()

    def assert_reads(expected, with_default):
        for carrier in carriers:
            assert carrier.name == "aegis_gitsafe_ordinary_root"
            assert carrier.get() == expected
            assert carrier.get(fallback) == with_default

    assert_reads(None, fallback)

    def clear_copied_root():
        assert_reads(installed, installed)
        with pathlookup_gitcache.bound_ordinary_root(None):
            assert_reads(None, None)
        assert_reads(installed, installed)

    with pathlookup_gitcache.bound_ordinary_root(tmp_path / "Outer") as installed:
        assert_reads(installed, installed)
        copied = copy_context()
        Context().run(assert_reads, None, fallback)
        assert_reads(installed, installed)
    assert_reads(None, fallback)
    with pathlookup_gitcache.bound_ordinary_root(tmp_path / "Retry") as retry:
        copied.run(clear_copied_root)
        assert_reads(retry, retry)
    assert_reads(None, fallback)
    copied.run(assert_reads, installed, installed)


def test_bound_ordinary_root_threads_keep_separate_roots(tmp_path):
    from threading import Barrier

    from aegis_core.pathlookup_gitcache import bound_ordinary_root

    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    barrier = Barrier(2)
    carriers = (pathlookup.ordinary_root, pathlookup_gitcache.ordinary_root)

    def worker(root):
        previous = pathlookup.ordinary_root.get()
        with bound_ordinary_root(root):
            barrier.wait(5)
            expected = os.path.normcase(os.fspath(root))
            for carrier in carriers:
                _assert_read_only_root(carrier, expected)
        assert all(carrier.get() == previous for carrier in carriers)
        return previous

    with bound_ordinary_root(tmp_path) as inherited:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker, root) for root in (left, right)]
            before_left, before_right = [future.result(timeout=10) for future in futures]
        assert all(carrier.get() == inherited for carrier in carriers)
    assert all(carrier.get() is None for carrier in carriers)
    assert before_left == before_right
    assert before_left in (None, inherited)


def _carrier_fence(path):
    from aegis_core import pathlookup
    return pathlookup.real_key(os.fspath(path))


@contextlib.contextmanager
def _ordinary_root(path):
    from aegis_core.pathlookup_gitcache import bound_ordinary_root
    with bound_ordinary_root(_carrier_fence(path)):
        yield


def test_ordinary_root_fences_the_exact_directory_and_resets(tmp_path, monkeypatch):
    from aegis_core import pathlookup
    enclosing = tmp_path / "enclosing"
    (enclosing / ".git").mkdir(parents=True)
    app = enclosing / "app"
    (app / ".git").mkdir(parents=True)
    nested = app / "nested"
    nested.mkdir()
    (app / "bin").mkdir()
    (enclosing / "bin").mkdir()
    sibling = tmp_path / "app-twin"
    sibling.mkdir()
    unbound = pathlookup.GitCache().for_cwd(nested).fence
    assert unbound == pathlookup._fence(pathlookup.git_fence(nested, descriptors=False))
    assert _carrier_fence(app) != unbound
    walks = []
    original = pathlookup.git_fence

    def counted(*args, **kwargs):
        walks.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr("aegis_core.pathlookup.git_fence", counted)
    try:
        with _ordinary_root(app):
            assert walks == [], "installing the carrier must not rediscover or re-enter binding"
            assert pathlookup.GitCache().for_cwd(nested).fence == _carrier_fence(app)
            assert pathlookup.GitCache().for_cwd(enclosing).fence == _carrier_fence(app)
            assert walks == [], "a set carrier must not walk the outermost marker"
            assert pathlookup._provenance_inside(str(app / "bin"), _carrier_fence(app))
            assert not pathlookup._provenance_inside(str(enclosing / "bin"), _carrier_fence(app))
            assert not pathlookup._provenance_inside(str(sibling), _carrier_fence(app))
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.git_fence", original)
    assert pathlookup.ordinary_root.get() is None
    assert pathlookup.GitCache().for_cwd(nested).fence == unbound


def test_ordinary_root_exception_and_nested_scopes_restore_the_outer_fence(tmp_path):
    from aegis_core import pathlookup
    outer = tmp_path / "outer"
    inner = tmp_path / "inner"
    outer.mkdir()
    inner.mkdir()
    unbound = pathlookup.GitCache().for_cwd(outer).fence
    try:
        with _ordinary_root(outer):
            try:
                with _ordinary_root(inner):
                    assert pathlookup.GitCache().for_cwd(outer).fence == _carrier_fence(inner)
                    raise RuntimeError("fixture failure")
            except RuntimeError:
                assert pathlookup.GitCache().for_cwd(outer).fence == _carrier_fence(outer)
            raise RuntimeError("outer failure")
    except RuntimeError:
        pass
    assert pathlookup.ordinary_root.get() is None
    assert pathlookup.GitCache().for_cwd(outer).fence == unbound


def test_ordinary_root_keeps_the_captured_directory_if_a_link_is_retargeted(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    real = tmp_path / "real"
    decoy = tmp_path / "decoy"
    (real / "bin").mkdir(parents=True)
    (decoy / "bin").mkdir(parents=True)
    link = tmp_path / "link"
    symlink_or_skip(real, link, target_is_directory=True)
    with _ordinary_root(link):
        link.unlink()
        symlink_or_skip(decoy, link, target_is_directory=True)
        fence = pathlookup.GitCache().for_cwd(decoy).fence
        assert fence == _carrier_fence(real)
        assert pathlookup._provenance_inside(str(real / "bin"), fence)
        assert not pathlookup._provenance_inside(str(decoy / "bin"), fence)


def test_ordinary_root_holds_when_the_descriptor_probe_is_false(tmp_path, monkeypatch):
    from aegis_core import pathlookup
    enclosing = tmp_path / "enclosing"
    (enclosing / ".git").mkdir(parents=True)
    app = enclosing / "app"
    app.mkdir()
    probe = pathlookup.descriptor_fence_supported
    monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", lambda: False)
    try:
        outermost = pathlookup._fence(pathlookup.git_fence(app, descriptors=False))
        assert outermost != _carrier_fence(app)
        with _ordinary_root(app):
            assert pathlookup.descriptor_fence_supported() is False
            assert pathlookup.GitCache().for_cwd(app).fence == _carrier_fence(app)
            assert pathlookup.GitCache().for_cwd(app).fence != outermost
    finally:
        monkeypatch.setattr("aegis_core.pathlookup.descriptor_fence_supported", probe)
    assert pathlookup.ordinary_root.get() is None


def test_ordinary_roots_stay_inside_their_threads(tmp_path):
    from threading import Barrier, Thread
    from aegis_core import pathlookup
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    barrier = Barrier(2)
    found = []

    def worker(root):
        with _ordinary_root(root):
            barrier.wait(5)
            found.append(pathlookup.GitCache().for_cwd(root).fence)
        found.append(("after", pathlookup.ordinary_root.get()))

    from aegis_core.pathlookup_gitcache import bound_ordinary_root
    inherited = _carrier_fence(tmp_path)
    with bound_ordinary_root(inherited) as parent:
        assert parent is not None
        threads = [Thread(target=worker, args=(root,)) for root in (left, right)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
            assert not thread.is_alive()
        assert pathlookup.GitCache().for_cwd(tmp_path).fence == inherited
    assert sorted(item for item in found if not isinstance(item, tuple)) == sorted(
        [_carrier_fence(left), _carrier_fence(right)])
    # Reset drops that thread's fence. Context-copying threads restore the inherited
    # value; a thread that started empty restores None. Neither keeps a worker fence.
    after = [item for item in found if isinstance(item, tuple)]
    assert len(after) == 2 and after[0] == after[1]
    assert after[0] == ("after", after[0][1]) and after[0][1] in (None, inherited)
    assert after[0][1] not in (_carrier_fence(left), _carrier_fence(right))
    assert pathlookup.ordinary_root.get() is None


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="descriptor listing needs /proc/self/fd")
def test_ordinary_root_opens_no_file_descriptor(tmp_path):
    from aegis_core import pathlookup
    before = os.listdir("/proc/self/fd")
    with _ordinary_root(tmp_path):
        assert pathlookup.GitCache().for_cwd(tmp_path).fence == _carrier_fence(tmp_path)
    assert os.listdir("/proc/self/fd") == before


def test_cli_arms_the_ordinary_root_only_after_a_finished_bind(tmp_path, monkeypatch, ordinary_home):
    from types import SimpleNamespace
    from aegis_cli.cli import main
    from aegis_cli.registry import get_default_registry
    home = ordinary_home
    enclosing = tmp_path / "enclosing"
    (enclosing / ".git").mkdir(parents=True)
    app = enclosing / "app"
    (app / ".aegis").mkdir(parents=True)
    (app / ".git").mkdir()
    during = []
    state = {"command": False}
    original_cache = bound_git._GIT_FOUND

    def for_cwd(cwd=None):
        if not state["command"]:
            during.append(pathlookup.ordinary_root.get())
        return original_cache.for_cwd(cwd)

    monkeypatch.setattr(bound_git, "_GIT_FOUND", SimpleNamespace(for_cwd=for_cwd, clear=original_cache.clear))
    commands = {}

    def install(name, fn):
        command = get_default_registry().get(name)
        commands.setdefault(name, command.execute)

        def execute(args):
            state["command"] = True
            try:
                return fn(args)
            finally:
                state["command"] = False

        command.execute = execute

    try:
        def bound_execute(args):
            during.append(("execute", pathlookup.ordinary_root.get()))
            during.append(("fence", pathlookup.GitCache().for_cwd(app).fence))
            return 0

        def boom(args):
            during.append(("boom", pathlookup.ordinary_root.get()))
            raise RuntimeError("status fixture")

        install("status", bound_execute)
        assert main(["status", "--workspace", str(app), "--plain"]) == 0
        install("status", boom)
        assert main(["status", "--workspace", str(app), "--plain"]) == 1
        assert pathlookup.ordinary_root.get() is None

        def unbound_execute(args):
            during.append(("doctor", pathlookup.ordinary_root.get()))
            return 0

        install("doctor", unbound_execute)
        assert main(["doctor", "--workspace", str(home)]) == 0

        def migrate_execute(args):
            during.append(("migrate", pathlookup.ordinary_root.get()))
            return 0

        install("migrate", migrate_execute)
        assert main(["migrate", "--workspace", str(app)]) == 0

        def workspace_execute(args):
            during.append(("workspace", pathlookup.ordinary_root.get()))
            return 0

        install("workspace", workspace_execute)
        assert main(["workspace", "status"]) == 0
    finally:
        for name, execute in commands.items():
            get_default_registry().get(name).execute = execute
    executes = [item for item in during if isinstance(item, tuple)]
    assert executes[0][0] == "execute"
    assert executes[0][1] == _carrier_fence(app)
    assert executes[1] == ("fence", _carrier_fence(app))
    assert _carrier_fence(app) != pathlookup._fence(pathlookup.git_fence(app, descriptors=False))
    assert all(value is None for value in during if not isinstance(value, tuple))
    assert ("boom", _carrier_fence(app)) in executes
    assert ("doctor", None) in executes
    assert ("migrate", _carrier_fence(app)) in executes
    assert ("workspace", None) in executes
    assert pathlookup.ordinary_root.get() is None


def test_mcp_arms_the_ordinary_root_after_resolve_binding(tmp_path, monkeypatch, ordinary_home):
    home = ordinary_home
    enclosing = tmp_path / "enclosing"
    (enclosing / ".git").mkdir(parents=True)
    apps = []
    for name in ("one", "two"):
        app = enclosing / name
        (app / ".aegis").mkdir(parents=True)
        (app / ".git").mkdir()
        (app / "src").mkdir()
        apps.append(app.resolve())
    saved = {key: getattr(server, key) for key in server.fresh_state()}
    seen = []
    real_resolve = server.resolve_binding

    def resolve_binding(**kwargs):
        seen.append(("resolve", pathlookup.ordinary_root.get()))
        return real_resolve(**kwargs)

    def execute_tool(name, args, **kwargs):
        root = args["workspace"].root if "workspace" in args else None
        fence = None if root is None else pathlookup.GitCache().for_cwd(root).fence
        seen.append(("tool", name, pathlookup.ordinary_root.get(), fence))
        if name == "aegis_report_outcome":
            raise RuntimeError("tool fixture")
        return {"status": "ok"}

    monkeypatch.setattr(server, "resolve_binding", resolve_binding)
    monkeypatch.setattr(server, "execute_tool", execute_tool)
    try:
        server._start()
        initialized = server.handle_request({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"clientInfo": {"name": "codex-mcp-client", "version": "1"}, "capabilities": {}},
        })
        assert initialized["result"]["protocolVersion"]
        for number, app in enumerate(apps, start=1):
            response = server.handle_request({
                "jsonrpc": "2.0", "id": number, "method": "tools/call",
                "params": {"name": "aegis_list_rules", "arguments": {},
                           "_meta": {"x-codex-turn-metadata": {"workspaces": {str(app): {"has_changes": False}}}}},
            })
            assert response["result"]["isError"] is False
            assert pathlookup.ordinary_root.get() is None
        failed = server.handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "aegis_report_outcome", "arguments": {},
                       "_meta": {"x-codex-turn-metadata": {"workspaces": {str(apps[0]): {"has_changes": False}}}}},
        })
        assert failed["result"]["isError"] is True
        assert pathlookup.ordinary_root.get() is None
        server._server_cwd = str(home)
        unbound = server.handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "aegis_scan", "arguments": {}},
        })
        assert "result" in unbound
    finally:
        for key, value in saved.items():
            setattr(server, key, value)
    resolves = [item for item in seen if item[0] == "resolve"]
    tools = [item for item in seen if item[0] == "tool"]
    assert resolves and all(item[1] is None for item in resolves)
    bound_tools = [item for item in tools if item[1] == "aegis_list_rules"]
    assert [item[3] for item in bound_tools] == [_carrier_fence(app) for app in apps]
    assert all(item[2] == item[3] for item in bound_tools)
    assert ("tool", "aegis_report_outcome", _carrier_fence(apps[0]), _carrier_fence(apps[0])) in tools
    scan = [item for item in tools if item[1] == "aegis_scan"]
    assert scan and all(item[2] is None for item in scan)
    assert pathlookup.ordinary_root.get() is None


def test_queue_claim_arms_the_ordinary_root_after_bind_and_resets_on_failure(tmp_path, monkeypatch, ordinary_home):
    from aegis_core.workspace.binding import WorkspaceBinding
    app = (tmp_path / "app").resolve()
    app.mkdir()
    saved = {key: getattr(server, key) for key in server.fresh_state()}
    seen = []

    def bind(params, args):
        seen.append(("bind", pathlookup.ordinary_root.get()))
        return WorkspaceBinding("bound", root=app, source="walk_up", confidence="inferred")

    def execute(name, args, **kwargs):
        seen.append(("tool", pathlookup.GitCache().for_cwd(app).fence))
        if len([item for item in seen if item[0] == "tool"]) > 1:
            raise RuntimeError("claim fixture")
        return {"ok": True}

    monkeypatch.setattr("aegis_mcp.queue_role.claim_argument_refusal", lambda arguments: None)
    server._queue_grant = type("Grant", (), {"workspace": str(app), "session": "s"})()
    server._queue_error = None
    server._session_id = "s"
    monkeypatch.setattr(server, "_bind", bind)
    monkeypatch.setattr(server, "execute_tool", execute)
    try:
        first = server._queue_claim_call(1, {"arguments": {}})
        assert first["result"]["isError"] is False
        assert pathlookup.ordinary_root.get() is None
        second = server._queue_claim_call(2, {"arguments": {}})
        assert second["result"]["isError"] is True
        assert pathlookup.ordinary_root.get() is None
    finally:
        for key, value in saved.items():
            setattr(server, key, value)
    assert seen[0] == ("bind", None)
    assert seen[1] == ("tool", _carrier_fence(app))
    assert seen[2] == ("bind", None)
    assert seen[3] == ("tool", _carrier_fence(app))
    assert pathlookup.ordinary_root.get() is None


def test_nested_cli_invocation_discovers_unbound_and_restores_caller(tmp_path, monkeypatch, ordinary_home):
    from aegis_cli.registry import get_default_registry

    home = ordinary_home
    app = tmp_path / "app"
    (app / ".aegis").mkdir(parents=True)
    seen = []
    attach = cli._attach_workspace

    def attach_workspace(args):
        seen.append(("bind", args.command, pathlookup.ordinary_root.get()))
        return attach(args)

    def doctor(args):
        seen.append(("execute", args.command, pathlookup.ordinary_root.get()))
        return 0

    def status(args):
        seen.append(("execute", args.command, pathlookup.ordinary_root.get()))
        assert cli.main(["doctor", "--workspace", str(home)]) == 0
        seen.append(("restored", pathlookup.ordinary_root.get()))
        return 0

    monkeypatch.setattr(cli, "_attach_workspace", attach_workspace)
    status_command = get_default_registry().get("status")
    doctor_command = get_default_registry().get("doctor")
    status_execute, doctor_execute = status_command.execute, doctor_command.execute
    status_command.execute, doctor_command.execute = status, doctor
    try:
        assert cli.main(["status", "--workspace", str(app), "--plain"]) == 0
    finally:
        status_command.execute, doctor_command.execute = status_execute, doctor_execute
    assert seen == [("bind", "status", None), ("execute", "status", _carrier_fence(app)),
                    ("bind", "doctor", None), ("execute", "doctor", None),
                    ("restored", _carrier_fence(app))]
    assert pathlookup.ordinary_root.get() is None


def test_nested_mcp_invocation_discovers_unbound_and_restores_caller(tmp_path, monkeypatch, ordinary_home):

    home = ordinary_home
    app = tmp_path / "app"
    (app / ".aegis").mkdir(parents=True)
    saved = {key: getattr(server, key) for key in server.fresh_state()}
    seen = []
    resolve = server.resolve_binding

    def resolve_binding(**kwargs):
        seen.append(("bind", pathlookup.ordinary_root.get()))
        return resolve(**kwargs)

    def execute(name, args):
        seen.append((name, pathlookup.ordinary_root.get()))
        if name == "aegis_list_rules":
            nested = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "aegis_scan", "arguments": {}}})
            assert nested["result"]["isError"] is False
            seen.append(("restored", pathlookup.ordinary_root.get()))
        return {"status": "ok"}

    monkeypatch.setattr(server, "resolve_binding", resolve_binding)
    monkeypatch.setattr(server, "execute_tool", execute)
    try:
        server._start()
        server._server_cwd = str(home)
        initialized = server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"clientInfo": {"name": "codex-mcp-client", "version": "1"}, "capabilities": {}}})
        assert "result" in initialized
        result = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "aegis_list_rules", "arguments": {},
                "_meta": {"x-codex-turn-metadata": {"workspaces": {str(app): {}}}}}})
        assert result["result"]["isError"] is False
    finally:
        for key, value in saved.items():
            setattr(server, key, value)
    assert seen == [("bind", None), ("aegis_list_rules", _carrier_fence(app)),
                    ("bind", None), ("aegis_scan", None), ("restored", _carrier_fence(app))]
    assert pathlookup.ordinary_root.get() is None


@pytest.fixture
def ordinary_unbound_repo(tmp_path, ordinary_home):
    """An uninitialized child under a marked checkout with an executable Git trap."""
    real_git = shutil.which("git")
    if real_git is None:
        pytest.skip("needs git")
    repo = tmp_path / "unbound-repo"
    (repo / ".git").mkdir(parents=True)
    sub = repo / "sub"
    sub.mkdir()
    binary = repo / "bin"
    binary.mkdir()
    marker = tmp_path / "unbound-git-executed"
    if os.name == "nt":
        (binary / "git.cmd").write_text(
            f'@echo ran>> "{marker}"\n@"{real_git}" %*\n', encoding="utf-8")
    else:
        import shlex

        trap = binary / "git"
        trap.write_text('#!/bin/sh\nprintf ran >> ' + shlex.quote(str(marker)) +
                        '\nexec ' + shlex.quote(real_git) + ' "$@"\n', encoding="utf-8")
        trap.chmod(0o755)
    os.environ["PATH"] = os.pathsep.join((str(binary), os.path.dirname(real_git), os.defpath))
    bound_git._reset_for_tests()
    try:
        yield repo, sub, marker
    finally:
        bound_git._reset_for_tests()


@contextlib.contextmanager
def _ordinary_cwd(directory):
    previous = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous)


@pytest.mark.parametrize("explicit", [False, True], ids=["cwd", "workspace"])
@pytest.mark.parametrize("command", ["status", "doctor", "migrate"])
def test_unresolved_cli_commands_keep_outermost_git_fence(ordinary_unbound_repo, monkeypatch, command, explicit):
    repo, sub, marker = ordinary_unbound_repo
    selected = []
    original = cli._ordinary_bound_root

    def ordinary_bound_root(args):
        root = original(args)
        selected.append(root)
        return root

    monkeypatch.setattr(cli, "_ordinary_bound_root", ordinary_bound_root)
    argv = [command, "--plain"]
    if command == "doctor":
        argv += ["--github"]
    if explicit:
        argv += ["--workspace", str(sub)]
    with _ordinary_cwd(sub):
        result = cli.main(argv)
    assert not marker.exists(), "an unresolved public CLI command executed checkout Git"
    assert selected == [None], "a fallback directory is not a completed binding"
    assert result == 0
    assert pathlookup.ordinary_root.get() is None
    assert pathlookup.GitCache().for_cwd(sub).fence != _carrier_fence(sub)


def test_unresolved_init_has_no_ordinary_root(ordinary_unbound_repo):
    from aegis_cli.registry import get_default_registry

    repo, sub, marker = ordinary_unbound_repo
    command = get_default_registry().get("init")
    original = command.execute
    seen = []

    def execute(args):
        seen.append(pathlookup.ordinary_root.get())
        assert bound_git.run(["--version"], sub).returncode == 0
        return 0

    command.execute = execute
    try:
        assert cli.main(["init", "--workspace", str(sub), "--plain"]) == 0
    finally:
        command.execute = original
    assert not marker.exists(), "initialization trusted a directory before binding"
    assert seen == [None]
    assert pathlookup.ordinary_root.get() is None


@pytest.mark.parametrize("attested", [False, True], ids=["cwd", "host-root"])
@pytest.mark.parametrize("tool", ["aegis_list_rules", "aegis_scan", "aegis_report_outcome"])
def test_unresolved_mcp_requests_keep_outermost_git_fence(ordinary_unbound_repo, monkeypatch, tool, attested):
    import json

    repo, sub, marker = ordinary_unbound_repo
    saved = {key: getattr(server, key) for key in server.fresh_state()}
    original = server._arm_ordinary_root
    selected = []

    @contextlib.contextmanager
    def arm(binding):
        with original(binding):
            selected.append((binding.status, pathlookup.ordinary_root.get()))
            yield

    monkeypatch.setattr(server, "_arm_ordinary_root", arm)
    try:
        server._start()
        server._server_cwd = str(sub)
        server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"clientInfo": {"name": "codex-mcp-client", "version": "1"}, "capabilities": {}}})
        params = {"name": tool, "arguments": {"workspace": str(sub)}}
        if attested:
            params["_meta"] = {"x-codex-turn-metadata": {"workspaces": {str(sub): {}}}}
        response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
        payload = json.loads(response["result"]["content"][0]["text"])
        assert response["result"]["isError"] is (tool != "aegis_scan")
        assert payload["status"] == "not_governed"
    finally:
        for key, value in saved.items():
            setattr(server, key, value)
    assert selected == [("unbound", None)]
    assert not marker.exists()
    assert pathlookup.ordinary_root.get() is None
    assert pathlookup.GitCache().for_cwd(sub).fence != _carrier_fence(sub)


@pytest.mark.parametrize("pinned", [False, True], ids=["discovered", "pin"])
@pytest.mark.parametrize("legacy", [False, True], ids=["workspace", "migration"])
def test_cli_binding_provenance_resets_on_failure_and_retries(ordinary_unbound_repo, pinned, legacy):
    from aegis_cli.registry import get_default_registry
    from tests.contract.test_legacy_ratchet import REQUIRED_WORDS

    repo, sub, marker = ordinary_unbound_repo
    workspace_marker = sub / ("." + REQUIRED_WORDS[0] if legacy else ".aegis")
    workspace_marker.mkdir()
    deep = sub / "deep"
    deep.mkdir()
    name = "migrate" if legacy else "status"
    command = get_default_registry().get(name)
    original = command.execute
    seen = []

    def execute(args):
        seen.append(pathlookup.ordinary_root.get())
        assert bound_git.run(["--version"], deep).returncode == 0
        return 0

    if pinned:
        os.environ["AEGIS_WORKSPACE"] = str(sub)
    command.execute = execute
    try:
        argv = [name, "--workspace", str(deep), "--plain"]
        with _ordinary_cwd(deep):
            assert cli.main(argv) == 0
            assert seen == [_carrier_fence(sub)]
            assert marker.exists(), "a completed binding should permit Git in its enclosing checkout"
            marker.unlink()
            workspace_marker.rmdir()
            assert cli.main(argv) == (1 if pinned else 0)
            assert not marker.exists(), "failed discovery reused a previous invocation's bound root"
            assert seen == ([_carrier_fence(sub)] if pinned else [_carrier_fence(sub), None])
            assert pathlookup.ordinary_root.get() is None
            workspace_marker.mkdir()
            assert cli.main(argv) == 0
            assert seen[-1] == _carrier_fence(sub) and marker.exists()
    finally:
        command.execute = original
    assert pathlookup.ordinary_root.get() is None


def test_cli_discovery_result_survives_marker_removal_before_execution(ordinary_unbound_repo, monkeypatch):
    from aegis_cli.registry import get_default_registry

    repo, sub, marker = ordinary_unbound_repo
    workspace_marker = sub / ".aegis"
    workspace_marker.mkdir()
    accept = cli._refuse_legacy

    def remove_after_accept(candidate):
        accepted = accept(candidate)
        if accepted:
            workspace_marker.rmdir()
        return accepted

    monkeypatch.setattr(cli, "_refuse_legacy", remove_after_accept)
    command = get_default_registry().get("status")
    original = command.execute
    seen = []

    def execute(args):
        seen.append(pathlookup.ordinary_root.get())
        assert bound_git.run(["--version"], sub).returncode == 0
        return 0

    command.execute = execute
    try:
        assert cli.main(["status", "--workspace", str(sub), "--plain"]) == 0
    finally:
        command.execute = original
    assert seen == [_carrier_fence(sub)] and marker.exists()
    assert not workspace_marker.exists()
    assert pathlookup.ordinary_root.get() is None


def test_concurrent_cli_resolutions_do_not_share_discovery_provenance(ordinary_unbound_repo):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_cli.registry import get_default_registry

    repo, sub, marker = ordinary_unbound_repo
    bound = repo / "bound"
    (bound / ".aegis").mkdir(parents=True)
    command = get_default_registry().get("status")
    original = command.execute
    barrier = Barrier(2)
    seen = {}

    def execute(args):
        barrier.wait(5)
        seen[args.workspace] = (pathlookup.ordinary_root.get(), bound_git.git_executable(cwd=args.workspace))
        return 0

    command.execute = execute
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            calls = [workers.submit(cli.main, ["status", "--workspace", str(root), "--plain"])
                     for root in (bound, sub)]
            assert [call.result(timeout=10) for call in calls] == [0, 0]
    finally:
        command.execute = original
    assert seen[str(bound.resolve())][0] == _carrier_fence(bound)
    assert seen[str(sub.resolve())][0] is None
    assert Path(seen[str(bound.resolve())][1]).parent == repo / "bin"
    assert Path(seen[str(sub.resolve())][1]).parent != repo / "bin"
    assert not marker.exists(), "executable lookup must not itself launch a program"
    assert pathlookup.ordinary_root.get() is None
