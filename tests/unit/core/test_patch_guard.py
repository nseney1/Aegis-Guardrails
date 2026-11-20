"""Exercise runtime patch governance through isolated, real pytest sessions."""
import ast
from contextlib import nullcontext
import hashlib
import inspect
from itertools import islice
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import time

import pytest

from aegis_core import storage as _result_storage


ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("kind", ["namespace", "legacy", "registry-copy"])
@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("restored", [False, True])
def test_r38_final_registry_bindings_decide_import_violations(tmp_path, kind, copied, restored):
    setup = '''
from importlib.machinery import ModuleSpec
r38_control = ModuleType("r38_control")
r38_control.cached = [True]
sys.modules["r38_control"] = r38_control
class R38LegacyLoader:
    def load_module(self, name):
        module = r38_control.original if r38_control.cached[0] else ModuleType(name)
        sys.modules[name] = module
        return module
class R38LegacyFinder:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "r38_subject":
            return ModuleSpec(fullname, R38LegacyLoader())
r38_control.original = ModuleType("r38_subject")
if LEGACY:
    sys.meta_path.insert(0, R38LegacyFinder())
r38_control.original = import_module("r38_subject")
'''.replace("LEGACY", repr(kind == "legacy"))
    files = ({"r38_subject/data.txt": "namespace package"} if kind == "namespace" else
             {"r38_subject.py": ""} if kind == "registry-copy" else {})
    body = '''
import importlib, sys
from r38_control import original, cached
def test_a():
    previous = sys.modules
    if COPIED:
        sys.modules = dict(previous)
    transport = sys.modules
    if REGISTRY_COPY:
        sys.modules = dict(transport)
    cached[0] = RESTORED
    saved = sys.modules.pop("r38_subject")
    value = importlib.import_module("r38_subject")
    assert saved is original
    if RESTORED:
        if REGISTRY_COPY:
            sys.modules = transport
        else:
            sys.modules["r38_subject"] = saved
        sys.modules = previous
    else:
        assert value is not original
def test_b():
    assert sys.modules["r38_subject"] is original
'''.replace("COPIED", repr(copied)).replace("REGISTRY_COPY", repr(kind == "registry-copy"))
    body = body.replace("RESTORED", repr(restored))
    first_line = textwrap.dedent(body).splitlines().index(
        '    value = importlib.import_module("r38_subject")') + 1
    code, output = _session(tmp_path, body, extra=setup, files=files)
    assert code == (0 if restored else 1), output
    assert "2 passed" in output, output
    assert ("unrestored namespace" in output) is not restored, output
    if not restored:
        assert "expected original binding sys.modules[r38_subject]" in output, output
        assert "first observed displaced at tests/test_probe.py:" + str(first_line) in output, output
    assert "INTERNALERROR" not in output, output


def _r37_legacy_case(tmp_path, kind, copied, nested, *, enabled=True, fresh=False,
                     failed=False, cleanup=False, bridge=False):
    subject = "r37_host.subject" if nested else "r37_subject"
    requested = subject + ".child" if kind == "package-child" else subject
    setup = '''
from importlib.machinery import ModuleSpec
r37_control = ModuleType("r37_control")
r37_control.flags = [False, False]
r37_control.results = []
sys.modules["r37_control"] = r37_control
class R37LegacyLoader:
    def load_module(self, name):
        module = ModuleType(name)
        module.VALUE = "trusted"
        module.HELPER = ModuleType("r37_helper")
        if name == SUBJECT and PACKAGE:
            module.__path__ = []
        sys.modules[name] = module
        if r37_control.flags[1] and name == REQUESTED:
            sys.modules["r37_alias"] = module
            sys.modules["r37_helper_alias"] = module.HELPER
        if r37_control.flags[0] and name == REQUESTED:
            if CLEANUP:
                sys.modules.pop(name, None)
            raise RuntimeError("r37 legacy load failed")
        return module
class R37LegacyFinder:
    def find_spec(self, fullname, path=None, target=None):
        if fullname not in {SUBJECT, SUBJECT + ".child"}:
            return None
        return ModuleSpec(fullname, R37LegacyLoader(),
            is_package=fullname == SUBJECT and PACKAGE)
sys.meta_path.insert(0, R37LegacyFinder())
PRELOAD
r37_control.flags[:] = [FAILED, True]
'''
    preload = 'r37_control.original = import_module(' + repr(subject) + ')' if not fresh else 'pass'
    setup = setup.replace("SUBJECT", repr(subject)).replace("REQUESTED", repr(requested))
    setup = setup.replace("PACKAGE", repr(kind != "module"))
    setup = setup.replace("CLEANUP", repr(cleanup)).replace("FAILED", repr(failed)).replace("PRELOAD", preload)
    request = 'importlib.import_module(' + repr("r37_bridge" if bridge else requested) + ')'
    if failed:
        request = 'with pytest.raises(RuntimeError, match="^r37 legacy load failed$"):\n    ' + request
    else:
        request = 'results.append(' + request + ')'
    body = '''
import importlib, sys
import pytest
from r37_control import results
def test_a():
    previous = sys.modules
    if COPIED:
        sys.modules = dict(previous)
    transport = sys.modules
    try:
        DELETE
        REQUEST
    finally:
        sys.modules = previous
    if COPIED:
        # These are leak canaries. Preserve the refused aliases after restoring
        # the transport; R38 separately covers fully restored registry copies.
        for alias in ("r37_alias", "r37_helper_alias"):
            if alias in transport:
                sys.modules[alias] = transport[alias]
def test_b():
    from r37_control import original
    assert sys.modules[SUBJECT] is original
    assert "r37_alias" not in sys.modules
    assert "r37_helper_alias" not in sys.modules
    assert not hasattr(original, "child")
    if NESTED:
        import r37_host
        assert r37_host.subject is original
'''
    refused = enabled and not fresh
    if fresh:
        body = body[:body.index('def test_b():')] + '''
def test_b():
    assert sys.modules[REQUESTED] is results[0]
    assert sys.modules["r37_alias"] is results[0]
    assert sys.modules["r37_helper_alias"] is results[0].HELPER
    if NESTED:
        import r37_host
        assert r37_host.subject is sys.modules[SUBJECT]
'''
    elif not enabled:
        body = body[:body.index('def test_b():')] + 'def test_b(): pass\n'
    body = body.replace("COPIED", repr(copied)).replace("NESTED", repr(nested))
    body = body.replace("SUBJECT", repr(subject)).replace("REQUESTED", "REQUEST_BODY")
    body = body.replace("REQUEST_BODY", repr(requested))
    body = body.replace("DELETE", 'pass' if fresh else 'del sys.modules[' + repr(subject) + ']')
    body = body.replace("        REQUEST", textwrap.indent(request, "        "))
    files = {"r37_host/__init__.py": ""}
    if bridge:
        files["r37_bridge.py"] = 'import importlib\nvalue = importlib.import_module(' + repr(requested) + ')\n'
    code, output = _session(tmp_path, body, extra=setup, files=files,
        env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (1 if refused else 0), output
    assert "2 passed" in output, output
    assert ("unrestored namespace" in output) is refused, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("kind", ["module", "package", "package-child"])
@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_r37_legacy_publication_keeps_the_displaced_binding(tmp_path, kind, copied, nested, enabled):
    _r37_legacy_case(tmp_path, kind, copied, nested, enabled=enabled)


@pytest.mark.parametrize("kind", ["module", "package", "package-child"])
@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("cleanup", [False, True])
@pytest.mark.parametrize("bridge", [False, True])
def test_r37_failed_legacy_publication_keeps_its_refusal(tmp_path, kind, copied, cleanup, bridge):
    _r37_legacy_case(tmp_path, kind, copied, False, failed=True, cleanup=cleanup, bridge=bridge)


@pytest.mark.parametrize("kind", ["module", "package", "package-child"])
@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("nested", [False, True])
def test_r37_fresh_legacy_publication_stays_authenticated(tmp_path, kind, copied, nested):
    _r37_legacy_case(tmp_path, kind, copied, nested, fresh=True)


def _r36_mock_layout_prefix(layout, missing=False):
    # A separate module owns every altered class and function; the process's
    # unittest.mock module and pytest's cleanup machinery remain intact.
    prefix = '''
from importlib import util as r36_util
from unittest import mock as r36_installed_mock
r36_spec = r36_util.spec_from_file_location("r36_owned_mock", r36_installed_mock.__file__)
r36_mock = r36_util.module_from_spec(r36_spec)
sys.modules["r36_owned_mock"] = r36_mock
r36_spec.loader.exec_module(r36_mock)
'''
    if layout == "legacy":
        # CPython 3.9 defines this wrapper inside _patch_dict.__call__, with
        # no decorate_callable or decorate_async_callable methods.
        legacy = '''
def r36_legacy_dict_call(self, f):
    if isinstance(f, type):
        return self.decorate_class(f)
    @wraps(f)
    def _inner(*args, **kw):
        self._patch_dict()
        try:
            return f(*args, **kw)
        finally:
            self._unpatch_dict()
    return _inner
'''
        prefix += ('\nexec(compile(' + repr(textwrap.dedent(legacy))
                   + ', r36_mock.__file__, "exec"), vars(r36_mock))\n'
                   'r36_mock._patch_dict.__call__ = r36_mock.r36_legacy_dict_call\n'
                   'for r36_name in ("decorate_callable", "decorate_async_callable"):\n'
                   '    if hasattr(r36_mock._patch_dict, r36_name):\n'
                   '        delattr(r36_mock._patch_dict, r36_name)\n')
    if missing:
        prefix += '\ndel r36_mock._patch_dict.__call__\n'
    return prefix + '''
r36_import_module = import_module
def import_module(name, package=None):
    if name == "unittest.mock":
        return r36_mock
    return r36_import_module(name, package)
'''


@pytest.mark.parametrize("layout", ["installed", "legacy"])
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("refused", [False, True])
def test_r36_runtime_support_uses_the_running_mock_layout(tmp_path, layout, enabled, refused):
    code, output = _session(tmp_path, '''
import os
from conftest import r36_mock
owner = vars(os) if REFUSED else {"value": "original"}
updates = {"getpid": os.getpid} if REFUSED else {"value": "patched"}
@r36_mock.patch.dict(owner, updates)
def test_a():
    assert owner["getpid"] is os.getpid if REFUSED else owner["value"] == "patched"
def test_b():
    assert owner["getpid"] is os.getpid if REFUSED else owner == {"value": "original"}
'''.replace("REFUSED", repr(refused)), plugin_prefix=_r36_mock_layout_prefix(layout),
        env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (1 if enabled and refused else 0), output
    assert "2 passed" in output, output
    assert ("shared module patch count 1 exceeds 0" in output) is (enabled and refused), output
    assert "runtime guard API is unsupported" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("enabled", [False, True])
def test_r36_missing_mock_dispatch_still_refuses(tmp_path, enabled):
    code, output = _session(tmp_path, 'def test_probe(): pass\n',
        plugin_prefix=_r36_mock_layout_prefix("installed", missing=True),
        env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (4 if enabled else 0), output
    assert ("pytest runtime guard API is unsupported" in output) is enabled, output
    assert "INTERNALERROR" not in output, output


def test_r36_runtime_support_is_independent_of_contract_collection(tmp_path):
    selection = "test_r36_runtime_support_uses_the_running_mock_layout or test_r36_missing_mock_dispatch"
    results = []
    for combined in (False, True):
        run = tmp_path / ("combined" if combined else "alone")
        run.mkdir()
        paths = ["tests/unit/core/test_patch_guard.py"]
        if combined:
            paths += ["tests/contract/test_monkeypatch_raising.py", "tests/contract/test_module_size.py",
                      "tests/contract/test_no_credential_literals.py"]
        env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", AEGIS_PATCH_GUARD="on")
        result = subprocess.run([sys.executable, "-B", "-m", "pytest", *paths, "-k", selection,
            "-q", "-p", "no:cacheprovider", "--basetemp", str(run / "tmp"),
            "--junitxml", str(run / "result.xml")], cwd=ROOT, env=env,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        from xml.etree import ElementTree
        cases = [(case.attrib["classname"], case.attrib["name"], tuple(child.tag for child in case))
                 for case in ElementTree.parse(run / "result.xml").iter("testcase")]
        assert len(cases) == 10, output
        assert all(not children for _owner, _name, children in cases), output
        results.append(sorted(cases))
    assert results[0] == results[1]


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize("request_kind", ["package-child", "package-direct", "module-direct"])
def test_r35_bootstrap_displacement_restores_the_trusted_binding(
        tmp_path, enabled, copied, failed, request_kind):
    requested = "r35_subject.child" if request_kind == "package-child" else "r35_subject"
    source = ('from r35_control import failures\nVALUE = "trusted"\n'
              'if failures[0] and __name__ == ' + repr(requested) + ':\n'
              '    raise RuntimeError("r35 import failed")\n')
    request = ('with pytest.raises(RuntimeError, match="^r35 import failed$"):\n'
               '    importlib.import_module(' + repr(requested) + ')' if failed else
               'importlib.import_module(' + repr(requested) + ')')
    body = '''
import importlib, sys
import pytest
from r35_control import original
def test_a():
    previous = sys.modules
    if COPIED:
        sys.modules = dict(previous)
    try:
        del sys.modules["r35_subject"]
        REQUEST
    finally:
        sys.modules = previous
def test_b():
    if ENABLED:
        assert sys.modules["r35_subject"] is original
        assert original.VALUE == "trusted"
        assert not hasattr(original, "child")
    elif COPIED:
        assert sys.modules["r35_subject"] is original
    elif not FAILED or CHILD:
        assert sys.modules["r35_subject"] is not original
'''.replace("COPIED", repr(copied)).replace("ENABLED", repr(enabled))
    body = body.replace("FAILED", repr(failed)).replace("CHILD", repr(request_kind == "package-child"))
    body = body.replace("        REQUEST", textwrap.indent(request, "        "))
    files = ({"r35_subject.py": source} if request_kind == "module-direct" else
             {"r35_subject/__init__.py": source, "r35_subject/child.py": source})
    code, output = _session(tmp_path, body, files=files, extra='''
r35_control = ModuleType("r35_control")
r35_control.failures = [False]
sys.modules["r35_control"] = r35_control
r35_control.original = import_module("r35_subject")
r35_control.failures[0] = FAILED
'''.replace("FAILED", repr(failed)), env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (1 if enabled else 0), output
    assert "2 passed" in output, output
    if enabled:
        assert "unrestored namespace" in output, output
        if not copied:
            assert "sys.modules[r35_subject]" in output, output
    else:
        assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("caller", ["test", "fixture", "test-helper", "fixture-helper"])
@pytest.mark.parametrize("operation", ["none", "missing", "mock-create", "shared", "mock-shared", "mock-dict"])
def test_r35_nested_plain_pytest_keeps_patch_attribution(tmp_path, enabled, caller, operation):
    operations = {
        "none": "pass",
        "missing": 'monkeypatch.setattr(SimpleNamespace(), "missing", 1, raising=False)',
        "mock-create": 'with patch.object(SimpleNamespace(), "missing", 1, create=True): pass',
        "shared": 'monkeypatch.setattr(os, "getpid", os.getpid)',
        "mock-shared": 'with patch.object(os, "getpid", os.getpid): pass',
        "mock-dict": 'with patch.dict(vars(os), {"getpid": os.getpid}): pass',
    }
    execute = ('import os\nfrom types import SimpleNamespace\nfrom unittest.mock import patch\n'
               'from r35_control import events\n'
               'def exercise(monkeypatch):\n    ' + operations[operation] + '\n'
               '    events.append("ran")\n')
    uses_fixture = caller.startswith("fixture")
    helper = caller.endswith("-helper")
    imports = 'from r35_patch_helper import exercise\n' if helper else execute
    if uses_fixture:
        conftest = imports + '\nimport pytest\n@pytest.fixture\ndef subject(monkeypatch):\n    exercise(monkeypatch)\n'
        test = 'def test_inner(subject): pass\n'
        expected_file = "plain/conftest.py"
    else:
        conftest = ""
        test = imports + '\ndef test_inner(monkeypatch):\n    exercise(monkeypatch)\n'
        expected_file = "plain/test_inner.py"
    code, output = _session(tmp_path, '''
from pathlib import Path
import os, pytest
from r35_control import events
original = os.getpid
def test_a():
    root = Path(__file__).resolve().parents[1] / "plain"
    result = pytest.main(["-c", str(root / "pytest.ini"), "--confcutdir", str(root),
        str(root / "test_inner.py"), "--import-mode=importlib", "-q", "-p", "no:cacheprovider",
        "--basetemp", str(root / "run")])
    assert result == 0
    assert events == ["ran"]
def test_b():
    assert os.getpid is original
''', files={
        "plain/pytest.ini": "[pytest]\n", "plain/conftest.py": conftest,
        "plain/test_inner.py": test, "r35_patch_helper.py": execute,
    }, extra='''
r35_control = ModuleType("r35_control")
r35_control.events = []
sys.modules["r35_control"] = r35_control
''', env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    refused = enabled and operation != "none"
    assert code == (1 if refused else 0), output
    assert "2 passed" in output, output
    if refused:
        assert expected_file + ":" in output, output
        if operation in {"missing", "mock-create"}:
            assert "permits a missing target:None.missing" in output, output
        else:
            assert "shared module patch count 1 exceeds 0" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("caller", ["test", "fixture", "collection"])
def test_r35_cross_drive_callback_sources_keep_the_refusal(tmp_path, enabled, caller):
    execute = ('from types import SimpleNamespace\nfrom unittest.mock import patch\n'
               'from r35_control import events\ndef exercise():\n'
               '    with patch.object(SimpleNamespace(), "missing", 1, create=True): pass\n'
               '    events.append("ran")\n')
    if caller == "fixture":
        conftest = execute + '\nimport pytest\n@pytest.fixture\ndef subject(): exercise()\n'
        inner = 'def test_inner(subject): pass\n'
        expected_file = "plain/conftest.py"
    else:
        conftest = ""
        inner = execute + ('\nexercise()\ndef test_inner(): pass\n' if caller == "collection" else
                           '\ndef test_inner(): exercise()\n')
        expected_file = "plain/test_inner.py"
    code, output = _session(tmp_path, '''
from pathlib import Path
import pytest
from r35_control import events
def test_a():
    root = Path(__file__).resolve().parents[1] / "plain"
    result = pytest.main(["-c", str(root / "pytest.ini"), "--confcutdir", str(root),
        str(root / "test_inner.py"), "--import-mode=importlib", "-q", "-p", "no:cacheprovider",
        "--basetemp", str(root / "run")])
    assert result == 0
    assert events == ["ran"]
def test_b(): pass
''', files={"plain/pytest.ini": "[pytest]\n", "plain/conftest.py": conftest,
            "plain/test_inner.py": inner}, extra='''
r35_control = ModuleType("r35_control")
r35_control.events = []
sys.modules["r35_control"] = r35_control
# Replace this copied module's reference, leaving the process OS module intact.
_r35_real_os = os
class _R35Path:
    def __getattr__(self, name): return getattr(_r35_real_os.path, name)
    def relpath(self, path, start=None):
        if str(path).replace("\\\\", "/").endswith(("/plain/test_inner.py", "/plain/conftest.py")):
            raise ValueError("path is on another mount")
        return _r35_real_os.path.relpath(path, start)
class _R35OS:
    path = _R35Path()
    def __getattr__(self, name): return getattr(_r35_real_os, name)
os = _R35OS()
''', env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (1 if enabled else 0), output
    assert "2 passed" in output, output
    if enabled:
        assert expected_file + ":" in output, output
        assert "permits a missing target:None.missing" in output, output
    assert "ValueError:" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("caller", ["test", "fixture"])
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("shape", ["missing", "cycle", "uncaptured"])
def test_r35_unsupported_callback_receipts_use_the_fixed_refusal(tmp_path, caller, enabled, shape):
    # This hook changes our own callback only after pytest has collected its
    # signature, exercising the guard's runtime attribution boundary.
    extra = '''
@pytest.hookimpl(tryfirst=True)
def pytest_runtest_call(item):
    callback = item.obj
    if SHAPE == "missing":
        del callback.__wrapped__
    elif SHAPE == "cycle":
        callback.__wrapped__ = callback
    else:
        callback.__wrapped__ = lambda: None
'''.replace("SHAPE", repr(shape))
    if caller == "fixture":
        # Fixture execution precedes the call hook, so alter its selected
        # definition at setup instead of changing an unrelated global.
        extra = extra.replace("pytest_runtest_call", "pytest_runtest_setup")
        extra = extra.replace("callback = item.obj", 'callback = item._fixtureinfo.name2fixturedefs["subject"][-1].func')
        body = 'from conftest import subject\ndef test_probe(subject): pass\n'
        extra = ('\n@pytest.fixture\n@EARLY\ndef subject(): pass\n' + extra)
    else:
        body = 'from conftest import EARLY\n@EARLY\ndef test_probe(): pass\n'
    code, output = _session(tmp_path, body, plugin_prefix='''
from unittest.mock import patch as early_patch
from types import SimpleNamespace
EARLY = early_patch.object(SimpleNamespace(), "missing", 1, create=True)
''', extra=extra, env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (4 if enabled else 0), output
    if enabled:
        assert "pytest runtime guard API is unsupported" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("caller", ["test", "fixture"])
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("form", ["attribute", "dictionary", "stack"])
def test_r35_preinstalled_nested_decorators_keep_the_callback_source(tmp_path, caller, enabled, form):
    decorators = "@early\n@early_dict\n" if form == "stack" else (
        "@early\n" if form == "attribute" else "@early_dict\n")
    execute = 'from r35_control import early, early_dict, events\n'
    if caller == "fixture":
        conftest = (execute + 'import pytest\n@pytest.fixture\n' + decorators
                    + 'def subject(): events.append("ran")\n')
        inner = 'def test_inner(subject): pass\n'
        expected_file = "plain/conftest.py"
    else:
        conftest = ""
        inner = execute + decorators + 'def test_inner(): events.append("ran")\n'
        expected_file = "plain/test_inner.py"
    code, output = _session(tmp_path, '''
from pathlib import Path
import os, pytest
from r35_control import events
original = os.getpid
def test_a():
    root = Path(__file__).resolve().parents[1] / "plain"
    result = pytest.main(["-c", str(root / "pytest.ini"), "--confcutdir", str(root),
        str(root / "test_inner.py"), "--import-mode=importlib", "-q", "-p", "no:cacheprovider",
        "--basetemp", str(root / "run")])
    assert result == 0
    assert events == ["ran"]
def test_b():
    assert os.getpid is original
''', files={"plain/pytest.ini": "[pytest]\n", "plain/conftest.py": conftest,
            "plain/test_inner.py": inner}, plugin_prefix='''
from unittest.mock import patch as early_patch
from types import SimpleNamespace
EARLY = early_patch.object(SimpleNamespace(), "missing", 1, create=True)
EARLY_DICT = early_patch.dict(vars(os), {"getpid": os.getpid})
''', extra='''
r35_control = ModuleType("r35_control")
r35_control.early = EARLY
r35_control.early_dict = EARLY_DICT
r35_control.events = []
sys.modules["r35_control"] = r35_control
''', env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (1 if enabled else 0), output
    assert "2 passed" in output, output
    if enabled:
        assert expected_file + ":" in output, output
        if form != "dictionary":
            assert "permits a missing target:None.missing" in output, output
        if form != "attribute":
            assert "shared module patch count 1 exceeds 0" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("caller", ["test", "fixture"])
@pytest.mark.parametrize("operation", ["none", "missing", "mock-create", "shared", "mock-shared", "mock-dict"])
def test_r35_copied_inner_guard_records_each_patch_once(tmp_path, caller, operation):
    plugin = (ROOT / "tests/conftest.py").read_text(encoding="utf-8")
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh(): pass\n'
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh_on_path(): pass\n'
    policy = (ROOT / "tests/contract/test_monkeypatch_raising.py").read_text(encoding="utf-8")
    operations = {
        "none": "pass",
        "missing": 'monkeypatch.setattr(SimpleNamespace(), "missing", 1, raising=False)',
        "mock-create": 'with patch.object(SimpleNamespace(), "missing", 1, create=True): pass',
        "shared": 'monkeypatch.setattr(os, "getpid", os.getpid)',
        "mock-shared": 'with patch.object(os, "getpid", os.getpid): pass',
        "mock-dict": 'with patch.dict(vars(os), {"getpid": os.getpid}): pass',
    }
    execute = ('import os\nfrom types import SimpleNamespace\nfrom unittest.mock import patch\n'
               'from r35_control import events\n'
               'def exercise(monkeypatch):\n    ' + operations[operation] + '\n'
               '    events.append("ran")\n')
    if caller == "fixture":
        plugin += execute + '\n@pytest.fixture\ndef subject(monkeypatch):\n    exercise(monkeypatch)\n'
        inner = 'def test_inner(subject): pass\n'
    else:
        inner = execute + '\ndef test_inner(monkeypatch):\n    exercise(monkeypatch)\n'
    code, output = _session(tmp_path, '''
from pathlib import Path
import os, pytest
from r35_control import events
original = os.getpid
def test_a():
    root = Path(__file__).resolve().parents[1] / "inner"
    result = pytest.main(["-c", str(root / "pytest.ini"), "--confcutdir", str(root / "tests"),
        str(root / "tests/test_inner.py"), "--import-mode=importlib", "-q", "-p", "no:cacheprovider",
        "--basetemp", str(root / "run")])
    assert result == EXPECTED
    assert events == ["ran"]
def test_b():
    assert os.getpid is original
'''.replace("EXPECTED", "0" if operation == "none" else "1"), files={
        "inner/pytest.ini": "[pytest]\n", "inner/tests/conftest.py": plugin,
        "inner/tests/contract/test_monkeypatch_raising.py": policy,
        "inner/tests/test_inner.py": inner,
    }, extra='''
r35_control = ModuleType("r35_control")
r35_control.events = []
sys.modules["r35_control"] = r35_control
''', options=("-s",))
    assert code == 0, output
    assert "2 passed" in output, output
    if operation in {"missing", "mock-create"}:
        assert "permits a missing target:None.missing" in output, output
    elif operation != "none":
        assert "shared module patch count 1 exceeds 0" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("timing", ["collection", "call"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("transport", ["retained", "active-copy"])
@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize("value_kind", ["conftest", "helper", "held-helper"])
def test_r34_enclosing_import_keeps_conftest_publication_exclusions(
        tmp_path, timing, import_mode, transport, failed, value_kind):
    value = 'sys.modules[__name__]' if value_kind == "conftest" else 'ModuleType("fresh")'
    source = ('import sys\nfrom types import ModuleType\nfrom r34_control import held\n'
              + ('sys.modules = dict(sys.modules)\n' if transport == "active-copy" else '')
              + 'value = ' + value + '\nheld.append(value)\n'
              + ('sys.modules["r34_stray"] = value\n' if value_kind != "held-helper" else '')
              + 'import r34_legit\n'
              + ('raise RuntimeError("r34 conftest failed")\n' if failed else ''))
    request = ('with pytest.raises(RuntimeError, match="^r34 bridge failed$"):\n'
               '    importlib.import_module("r34_bridge")' if failed else
               'importlib.import_module("r34_bridge")')
    body = '''
import importlib, sys
import pytest
def request():
    REQUEST
COLLECT
def test_a():
    CALL
def test_b():
    assert "r34_stray" not in sys.modules
    assert sys.modules["r34_legit_alias"].VALUE == "trusted"
    assert sys.modules["r34_legit_native"].VALUE == "trusted"
'''.replace("    REQUEST", textwrap.indent(request, "    "))
    body = body.replace("COLLECT", "request()" if timing == "collection" else "")
    body = body.replace("CALL", "request()" if timing == "call" else "pass")
    bridge = '''
import importlib, sys
from r34_control import held
try:
    importlib.import_module("tests.sub.conftest")
except RuntimeError:
    if not FAILED:
        raise
sys.modules["r34_stray"] = held.pop()
if FAILED:
    raise RuntimeError("r34 bridge failed")
'''.replace("FAILED", repr(failed))
    code, output = _session(tmp_path, body, files={
        "tests/__init__.py": "", "tests/sub/__init__.py": "",
        "tests/sub/conftest.py": source, "r34_bridge.py": textwrap.dedent(bridge),
        "r34_legit.py": ('import sys\nfrom types import ModuleType\nVALUE = "trusted"\n'
                         'sys.modules["r34_legit_alias"] = sys.modules[__name__]\n'
                         'helper = ModuleType("native")\nhelper.VALUE = "trusted"\n'
                         'sys.modules["r34_legit_native"] = helper\n'),
    }, extra='''
r34_control = ModuleType("r34_control")
r34_control.held = []
sys.modules["r34_control"] = r34_control
''', options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "2 passed" in output, output
    assert "unrestored namespace" in output, output
    if transport == "retained":
        assert "sys.modules[r34_stray]" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("child_name", ["child", "test_child"])
@pytest.mark.parametrize("transport", ["retained", "active-copy"])
@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize("restored", ["test", "child", "bridge", "initializer"])
def test_r34_enclosing_import_keeps_refused_child_provenance(
        tmp_path, child_name, transport, failed, restored):
    source = ('import sys\nfrom r34_control import parent, substitute, failures\n'
              + ('sys.modules["r34_pkg"] = parent\n' if restored == "child" else '')
              + ('if failures[1]: sys.modules["r34_pkg"] = substitute\n' if restored == "initializer" else '')
              + 'VALUE = "trusted"\n'
              'sys.modules["r34_refused_alias"] = sys.modules[__name__]\n'
              'if failures[0]:\n    raise RuntimeError("r34 child failed")\n')
    request = ('with pytest.raises(RuntimeError, match="^r34 child failed$"):\n'
               '    importlib.import_module("r34_bridge")' if failed else
               'importlib.import_module("r34_bridge")')
    body = '''
import importlib, sys
import pytest
from r34_control import parent, substitute, failures
def test_a():
    REPLACE
    COPY
    try:
        REQUEST
    finally:
        sys.modules["r34_pkg"] = parent
        failures[0] = False
def test_b():
    assert "r34_pkg.CHILD" not in sys.modules
    assert "r34_refused_alias" not in sys.modules
    assert not hasattr(substitute, "CHILD")
    assert importlib.import_module("r34_pkg.CHILD").VALUE == "trusted"
'''.replace("CHILD", child_name)
    body = body.replace("COPY", "sys.modules = dict(sys.modules)" if transport == "active-copy" else "pass")
    body = body.replace("REPLACE", 'pass' if restored == "initializer" else 'sys.modules["r34_pkg"] = substitute')
    body = body.replace('failures[0] = False', 'failures[:] = [False, False]')
    body = body.replace("        REQUEST", textwrap.indent(request, "        "))
    bridge = ('import importlib, sys\nfrom r34_control import parent\ntry:\n'
              '    importlib.import_module("r34_pkg.' + child_name + '")\nfinally:\n'
              + ('    sys.modules["r34_pkg"] = parent\n' if restored in {"bridge", "initializer"} else '    pass\n'))
    extra = '''
r34_control = ModuleType("r34_control")
r34_control.parent = import_module("r34_pkg")
r34_control.substitute = ModuleType("r34_substitute")
r34_control.substitute.__path__ = r34_control.parent.__path__
r34_control.failures = [FAILED, True]
sys.modules["r34_control"] = r34_control
sys.modules["r34_substitute"] = r34_control.substitute
'''.replace("FAILED", repr(failed))
    code, output = _session(tmp_path, body, extra=extra, files={
        "r34_pkg/__init__.py": "", "r34_pkg/" + child_name + ".py": source,
        "r34_bridge.py": bridge,
    })
    assert code == 1, output
    assert "2 passed" in output, output
    assert "unrestored namespace" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("restored", [False, True, "initializer"])
@pytest.mark.parametrize("substitute_kind", ["fresh", "baselined"])
def test_r34_rejected_collected_child_cannot_publish_package_binding(tmp_path, restored, substitute_kind):
    victim = ('import sys\nfrom r34_control import parent, substitute\n'
              + ('sys.modules["tests"] = parent\n' if restored is True else '')
              + ('sys.modules["tests"] = substitute\n' if restored == "initializer" else '')
              + 'VALUE = "untrusted"\n'
              'def test_victim(saved=substitute):\n'
              '    if hasattr(saved, "test_01_victim"):\n'
              '        raise RuntimeError("r34 rejected child became package binding")\n'
              '    if "tests.test_01_victim" in __import__("sys").modules:\n'
              '        raise RuntimeError("r34 rejected child remained cached")\n')
    code, output = _session(tmp_path, "# Selection controls collection.\n", files={
        "tests/__init__.py": "",
        "tests/test_00_parent.py": ('import sys\nfrom r34_control import substitute\n'
                                   + ('sys.modules["tests"] = substitute\n' if restored != "initializer" else '')
                                   +
                                   'def test_parent(): pass\n'),
        "tests/test_01_victim.py": victim,
        "tests/test_02_restore.py": ('import sys\nfrom r34_control import parent\n'
                                    'sys.modules["tests"] = parent\ndef test_restore(): pass\n'),
    }, extra='''
r34_control = ModuleType("r34_control")
r34_control.parent = import_module("tests")
r34_control.substitute = SUBSTITUTE
r34_control.substitute.__path__ = r34_control.parent.__path__
sys.modules["r34_control"] = r34_control
sys.modules["r34_substitute"] = r34_control.substitute
'''.replace("SUBSTITUTE", 'import_module("os")' if substitute_kind == "baselined" else 'ModuleType("r34_substitute")'),
        selection=("tests/test_00_parent.py", "tests/test_01_victim.py", "tests/test_02_restore.py"),
        options=("--import-mode=importlib",))
    assert code == 1, output
    assert "3 passed" in output, output
    assert "unrestored namespace" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("leak", ["none", "inner", "outer", "outer-framework"])
def test_r34_independent_nested_sessions_share_creation_window(tmp_path, import_mode, leak):
    plugin = (ROOT / "tests/conftest.py").read_text(encoding="utf-8")
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh(): pass\n'
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh_on_path(): pass\n'
    policy = (ROOT / "tests/contract/test_monkeypatch_raising.py").read_text(encoding="utf-8")
    body = '''
from pathlib import Path
import os
import pytest
from _pytest.assertion import util
def test_outer(pytestconfig):
    OUTER_LEAK
    outer = pytestconfig.pluginmanager.getplugin("runtime-patch-guard")
    seen = []
    class Observe:
        def pytest_sessionstart(self, session):
            inner = session.config.pluginmanager.getplugin("runtime-patch-guard")
            assert inner is not None
            assert type(inner) is not type(outer)
            seen.append(inner)
    root = Path(__file__).resolve().parents[1] / "inner"
    for index in range(2):
        result = pytest.main(["-c", str(root / "pytest.ini"), "--confcutdir", str(root / "tests"),
            str(root / "tests/test_inner.py"), "--import-mode=MODE", "-q", "-p", "no:cacheprovider",
            "--basetemp", str(root / ("run-" + str(index)))], plugins=[Observe()])
        assert result == EXPECTED
    assert len(seen) == 2
    import r34_after
    assert r34_after.VALUE == "trusted"
def test_outer_repaired():
    assert not hasattr(os, "_r34_outer_leak")
'''.replace("MODE", import_mode).replace("EXPECTED", "1" if leak == "inner" else "0")
    body = body.replace("OUTER_LEAK", 'os._r34_outer_leak = object()' if leak == "outer" else
                        'util._reprcompare = lambda *args: None' if leak == "outer-framework" else "pass")
    inner = ('import os\ndef test_inner_a():\n    '
             + ('os._r34_inner_leak = object()' if leak == "inner" else 'pass')
             + '\ndef test_inner_b():\n    assert not hasattr(os, "_r34_inner_leak")\n')
    code, output = _session(tmp_path, body, files={
        "inner/pytest.ini": "[pytest]\n",
        "inner/tests/conftest.py": plugin,
        "inner/tests/contract/test_monkeypatch_raising.py": policy,
        "inner/tests/test_inner.py": inner,
        "r34_after.py": 'VALUE = "trusted"\n',
    }, options=("-s",))
    assert code == (1 if leak.startswith("outer") else 0), output
    assert "2 passed" in output, output
    assert "import API is unsupported" not in output, output
    if leak == "outer":
        assert "os._r34_outer_leak" in output, output
    elif leak == "outer-framework":
        assert "unrestored namespace: _pytest.assertion.util._reprcompare" in output, output
    elif leak == "inner":
        assert "os._r34_inner_leak" in output, output
    else:
        assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("operation", ["replace", "delete"])
def test_r34_recursive_parent_reload_requires_the_immediate_parent(tmp_path, operation):
    code, output = _session(tmp_path, "# Selection controls collection.\n", files={
        "tests/__init__.py": "",
        "tests/sub/__init__.py": 'VALUE = "initialized"\n',
        "tests/test_00_parent.py": ('import sys\nfrom types import ModuleType\n'
            + ('sys.modules["tests.sub"] = ModuleType("spoof")\n' if operation == "replace"
               else 'del sys.modules["tests.sub"]\n') + 'def test_parent(): pass\n'),
        "tests/sub/test_victim.py": '''
import sys
from r34_control import parent
def test_victim(saved=parent):
    if __import__("sys").modules.get("tests.sub") is not saved:
        raise RuntimeError("r34 replaced parent was adopted")
    if "tests.sub.test_victim" in __import__("sys").modules:
        raise RuntimeError("r34 refused descendant remained cached")
''',
    }, extra='''
r34_control = ModuleType("r34_control")
r34_control.parent = import_module("tests.sub")
sys.modules["r34_control"] = r34_control
''', selection=("tests/test_00_parent.py", "tests/sub/test_victim.py"),
        options=("--import-mode=importlib",))
    assert code == 1, output
    assert "2 passed" in output, output
    assert "unrestored namespace" in output, output
    assert "INTERNALERROR" not in output, output


def test_r34_unrelated_creation_owner_metadata_is_refused(tmp_path):
    code, output = _session(tmp_path, "def test_probe(): pass\n", extra='''
from types import SimpleNamespace
_r34_import = import_module
def import_module(name, *args, **kwargs):
    module = _r34_import(name, *args, **kwargs)
    if name == "importlib._bootstrap":
        original = module._load_unlocked
        def unrelated(spec):
            return original(spec)
        unrelated._patch_creation_owner = SimpleNamespace(creation_depth=0)
        return SimpleNamespace(_load_unlocked=unrelated,
            _find_and_load_unlocked=module._find_and_load_unlocked,
            module_from_spec=module.module_from_spec)
    return module
''')
    assert code == 4, output
    assert "runtime patch guard import API is unsupported" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r34_pytest_entry_preserves_external_patch_attribution(tmp_path, import_mode):
    code, output = _external_session(tmp_path, '''
from types import SimpleNamespace
def test_external(monkeypatch):
    owner = SimpleNamespace()
    monkeypatch.setattr(owner, "missing", 1, raising=False)
''', import_mode=import_mode)
    assert code == 1, output
    assert "1 passed" in output, output
    assert "permits a missing target:None.missing" in output, output
    assert "INTERNALERROR" not in output, output



@pytest.mark.parametrize("restored", [False, True])
def test_r33_source_initializer_keeps_interpreter_builtins(tmp_path, restored):
    source = ('import sys\nfrom r33_control import parent\n'
              'sys.modules["r33_pkg"] = parent\n' if restored else "")
    source += 'VALUE = "untrusted"\ndef probe(): return globals()["__builtins__"]\n'
    code, output = _session(tmp_path, '''
import builtins, importlib, sys
from types import ModuleType
from r33_control import held, parent
def test_a():
    replacement = ModuleType("spoof")
    replacement.__path__ = parent.__path__
    sys.modules["r33_pkg"] = replacement
    subject = importlib.import_module("r33_pkg.child")
    held.append((subject, subject.probe))
def test_b():
    subject, probe = held.pop()
    assert probe() is vars(builtins)
    assert "VALUE" not in vars(subject)
    assert "r33_pkg.child" not in sys.modules
''', files={"r33_pkg/__init__.py": "", "r33_pkg/child.py": source}, extra='''
r33_control = ModuleType("r33_control")
r33_control.parent = import_module("r33_pkg")
r33_control.held = []
sys.modules["r33_control"] = r33_control
''')
    assert code == 1, output
    assert "2 passed" in output, output
    assert "unrestored namespace" in output, output
    assert "r33_pkg.child.VALUE" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("operation", ["replace-dict", "replace-module", "delete"])
def test_r33_module_builtins_binding_is_repaired(tmp_path, operation):
    action = ('namespace.pop("__builtins__")' if operation == "delete" else
              'namespace["__builtins__"] = ' + ("{}" if operation == "replace-dict" else "builtins"))
    code, output = _session(tmp_path, '''
import builtins, r33_subject, r33_raw
def test_a():
    namespace = vars(r33_subject)
    ACTION
def test_b():
    assert vars(r33_subject)["__builtins__"] is vars(builtins)
    assert "__builtins__" not in vars(r33_raw)
'''.replace("ACTION", action), files={"r33_subject.py": "VALUE = 1\n"}, extra='''
r33_raw = ModuleType("r33_raw")
sys.modules["r33_raw"] = r33_raw
''')
    assert code == 1, output
    assert "2 passed" in output, output
    assert "unrestored namespace: r33_subject.__builtins__" in output, output
    assert "INTERNALERROR" not in output, output


def test_r31_available_window_publishes_fresh_module(tmp_path):
    code, output = _session(tmp_path, '''
import sys
def test_a():
    import r31_fresh
def test_b():
    assert sys.modules["r31_fresh_helper"].VALUE == "trusted"
''', files={"r31_fresh.py": '''
import sys
from types import ModuleType
fresh = ModuleType("fresh")
fresh.VALUE = "trusted"
sys.modules["r31_fresh_helper"] = fresh
'''})
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "creation window unavailable" not in output, output


@pytest.mark.parametrize("origin", ["earlier-import", "test-code"])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r31_earlier_allocations_do_not_receive_later_window_receipts(tmp_path, origin, failure, import_mode):
    setup = ('import r31_prior\nheld = r31_prior.value' if origin == "earlier-import"
             else 'held = ModuleType("old_local")')
    request = ('with pytest.raises(RuntimeError, match="^r31 import failed$"):\n'
               '    importlib.import_module("r31_publisher")' if failure
               else 'importlib.import_module("r31_publisher")')
    body = '''
import importlib, sys
from types import ModuleType
import pytest
from r31_control import requests
def test_a():
    SETUP
    requests.append(held)
    try:
        REQUEST
    finally:
        requests.pop()
def test_b():
    assert "r31_old_alias" not in sys.modules
'''.replace("    SETUP", textwrap.indent(setup, "    "))
    body = body.replace("        REQUEST", textwrap.indent(request, "        "))
    code, output = _session(tmp_path, body, extra='''
r31_control = ModuleType("r31_control")
r31_control.requests = []
sys.modules["r31_control"] = r31_control
''', files={
        "r31_prior.py": 'from types import ModuleType\nvalue = ModuleType("earlier")\n',
        "r31_publisher.py": ('import sys\nfrom r31_control import requests\n'
                             'sys.modules["r31_old_alias"] = requests[0]\n' +
                             ('raise RuntimeError("r31 import failed")\n' if failure else '')),
    }, options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "2 passed" in output, output
    assert "unrestored namespace: sys.modules[r31_old_alias]" in output, output
    assert "INTERNALERROR" not in output, output


def test_r31_native_helpers_have_creation_receipts(tmp_path):
    code, output = _session(tmp_path, '''
import pytest
def test_probe():
    pytest.importorskip("yaml")
''')
    assert code == 0, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("operation", ["prior-freeze", "unfreeze", "freeze-inside", "unfreeze-refreeze"])
def test_r32_foreign_gc_operations_follow_canary_integrity(tmp_path, operation):
    broken = operation in {"unfreeze", "unfreeze-refreeze"}
    refused = operation != "prior-freeze"
    if operation == "unfreeze-refreeze":
        action = "import r32_breaker\ngc.freeze()\n"
    else:
        action = "gc.unfreeze()\n" if broken else ""
    loader = ('import gc, sys\nfrom types import ModuleType\n' + action +
              'fresh = ModuleType("fresh")\nfresh.VALUE = "trusted"\n'
              'sys.modules["r32_window_helper"] = fresh\n' +
              ('gc.freeze()\n' if operation == "freeze-inside" else ""))
    check = ('assert "r32_window_helper" not in sys.modules' if refused else
             'assert sys.modules["r32_window_helper"].VALUE == "trusted"')
    if operation == "unfreeze-refreeze":
        check += '\nassert "r32_inner_helper" not in sys.modules'
    body = '''
import gc, importlib, sys
def test_a():
    importlib.import_module("r32_helper")
    assert sys.modules["r32_window_helper"].VALUE == "trusted"
def test_b():
    CHECK
'''.replace("    CHECK", textwrap.indent(check, "    "))
    code, output = _session(tmp_path, body, files={
        "r32_helper.py": loader,
        "r32_breaker.py": 'import gc, sys\nfrom types import ModuleType\n'
                          'gc.unfreeze()\nsys.modules["r32_inner_helper"] = ModuleType("inner")\n',
    }, plugin_prefix="import gc\ngc.freeze()\n" if operation == "prior-freeze" else "")
    assert code == (1 if refused else 0), output
    assert "2 passed" in output, output
    assert ("creation window unavailable:canary became young" in output) is broken, output
    assert ("unrestored namespace" in output) is refused, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("probe, reason", [("missing", "GC API unsupported"),
                                           ("self-check", "GC self-check failed")])
def test_r31_unsupported_creation_window_refuses(tmp_path, probe, reason):
    extra = '''
from types import SimpleNamespace
_r31_import = import_module
def import_module(name, *args, **kwargs):
    module = _r31_import(name, *args, **kwargs)
    if name == "gc":
        return SimpleNamespace(freeze=FREEZE, unfreeze=module.unfreeze,
            get_referrers=module.get_referrers, get_objects=OBJECTS)
    return module
'''.replace("FREEZE", "None" if probe == "missing" else "module.freeze")
    extra = extra.replace("OBJECTS", "module.get_objects" if probe == "missing" else "lambda: []")
    code, output = _session(tmp_path, '''
import sys
def test_a():
    import r31_unsupported_helper
def test_b():
    assert "r31_unsupported_alias" not in sys.modules
''', extra=extra, files={"r31_unsupported_helper.py":
        'import sys\nfrom types import ModuleType\n'
        'sys.modules["r31_unsupported_alias"] = ModuleType("fresh")\n'})
    assert code == 1, output
    assert "2 passed" in output, output
    assert "creation window unavailable:" + reason in output, output
    assert "INTERNALERROR" not in output, output


def test_r31_disabled_guard_does_not_initialize_creation_window(tmp_path):
    extra = '''
_r31_import = import_module
def import_module(name, *args, **kwargs):
    if name == "gc":
        raise RuntimeError("r31 guard-only GC initialization")
    return _r31_import(name, *args, **kwargs)
'''
    code, output = _session(tmp_path, "def test_probe(): pass\n", extra=extra,
                            env_overrides={"AEGIS_PATCH_GUARD": "off"})
    assert code == 0, output
    assert "1 passed" in output, output
    assert "r31 guard-only GC initialization" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r30_late_conftest_has_no_auxiliary_publication_authority(tmp_path, import_mode):
    code, output = _session(tmp_path, "def test_root(): pass\n", files={
        "tests/__init__.py": "",
        "tests/sub/__init__.py": "",
        "tests/sub/conftest.py": '''
import sys
sys.modules["r30_conftest_alias"] = sys.modules[__name__]
import r30_innocent
''',
        "r30_innocent.py": '''
import sys
VALUE = "trusted"
sys.modules["r30_nested_import_alias"] = sys.modules[__name__]
''',
        "tests/sub/test_nested.py": '''
import sys
def test_nested():
    assert "r30_conftest_alias" not in sys.modules
    assert sys.modules["r30_nested_import_alias"].VALUE == "trusted"
''',
    }, selection=("tests",), options=("--ignore=tests/contract", "--import-mode=" + import_mode))
    assert code == 1, output
    assert "2 passed" in output, output
    assert "collection:0:unrestored namespace:sys.modules[r30_conftest_alias]" in output, output
    assert "unrestored namespace:sys.modules[r30_nested_import_alias]" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("spoofed", [False, True, "restored"])
def test_r30_rewritten_initializer_requires_a_trusted_parent(tmp_path, spoofed):
    action = '''
import sys
from types import ModuleType
parent = sys.modules["tests"]
replacement = ModuleType("spoof")
replacement.__path__ = parent.__path__
sys.modules["tests"] = replacement
''' if spoofed else ""
    victim = '''
VALUE = "initialized"
def test_victim():
    if "__builtins__" not in globals():
        raise RuntimeError("r33 automatic builtins binding missing")
    if globals()["__builtins__"] is not vars(__import__("builtins")):
        raise RuntimeError("r33 automatic builtins binding replaced")
    assert ("VALUE" in globals()) is EXPECTED
    assert ("tests.test_01_victim" in __import__("sys").modules) is EXPECTED
'''.replace("EXPECTED", repr(not spoofed))
    if spoofed == "restored":
        victim = ('import sys\nfrom r30_original import parent\n'
                  'sys.modules["tests"] = parent\n' + victim)
    code, output = _session(tmp_path, "# Selection supplies both collected modules.\n", files={
        "tests/__init__.py": "",
        "tests/test_00_parent.py": action + "\ndef test_parent(): pass\n",
        "tests/test_01_victim.py": victim,
    }, extra='''
r30_original = ModuleType("r30_original")
r30_original.parent = import_module("tests")
sys.modules["r30_original"] = r30_original
''', selection=("tests/test_00_parent.py", "tests/test_01_victim.py"),
        options=("--import-mode=importlib",))
    assert code == (1 if spoofed else 0), output
    assert "2 passed" in output, output
    assert ("collection:0:unrestored namespace:tests.test_01_victim.VALUE" in output) is bool(spoofed), output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("storage", ["list", "tuple", "dict", "field", "closure", "local"])
@pytest.mark.parametrize("transport", ["active-copy", "retained"])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r30_preexisting_modules_need_positive_import_provenance(
        tmp_path, storage, transport, failure, import_mode):
    preparation = {
        "list": 'held = [ModuleType("old")]\nretrieve = lambda: held[0]',
        "tuple": 'held = (ModuleType("old"),)\nretrieve = lambda: held[0]',
        "dict": 'held = {"value": ModuleType("old")}\nretrieve = lambda: held["value"]',
        "field": 'held = SimpleNamespace(value=ModuleType("old"))\nretrieve = lambda: held.value',
        "closure": ('def capture(value):\n    return lambda: value\n'
                    'retrieve = capture(ModuleType("old"))'),
        "local": 'local = ModuleType("old")\nretrieve = lambda: local',
    }[storage]
    request = ('with pytest.raises(RuntimeError, match="^r30 import failed$"):\n'
               '    importlib.import_module("r30_publisher")' if failure
               else 'importlib.import_module("r30_publisher")')
    body = '''
import importlib, sys
from types import ModuleType, SimpleNamespace
import pytest
from r30_control import requests, registry
def test_a():
    PREPARATION
    requests.append(retrieve)
    saved = sys.modules
    sys.modules = saved.copy()
    try:
        REQUEST
    finally:
        RESTORE
        requests.pop()
def test_b():
    assert "r30_hidden_alias" not in sys.modules
    assert "r30_hidden_alias" not in registry
'''.replace("    PREPARATION", textwrap.indent(preparation, "    "))
    body = body.replace("        REQUEST", textwrap.indent(request, "        "))
    body = body.replace("RESTORE", "sys.modules = saved" if transport == "retained" else "pass")
    publisher = ('import sys\nfrom r30_control import requests, registry\n' +
                 ('registry' if transport == "retained" else 'sys.modules') +
                 '["r30_hidden_alias"] = requests[0]()\n' +
                 ('raise RuntimeError("r30 import failed")\n' if failure else ''))
    code, output = _session(tmp_path, body, extra='''
r30_control = ModuleType("r30_control")
r30_control.requests = []
r30_control.registry = sys.modules
sys.modules["r30_control"] = r30_control
''', files={"r30_publisher.py": publisher}, options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "2 passed" in output, output
    label = ("sys.modules[r30_hidden_alias]" if transport == "retained" else "sys.modules")
    assert "unrestored namespace: " + label in output, output
    assert "INTERNALERROR" not in output, output









@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r29_copied_context_cannot_reuse_completed_import_receipt(tmp_path, failure, import_mode):
    root = '''
import contextvars, sys
CAPTURED = contextvars.copy_context()
sys.modules["r29_context_owner"] = sys.modules[__name__]
'''
    if failure:
        root += 'raise RuntimeError("r29 capture import failed")\n'
    request = ('with pytest.raises(RuntimeError, match="^r29 capture import failed$"):\n'
               '    importlib.import_module("r29_capture_root")\n' if failure
               else 'importlib.import_module("r29_capture_root")\n')
    body = ('import importlib, pytest, sys\n' + request + '''
def test_probe():
    owner = sys.modules["r29_context_owner"]
    owner.CAPTURED.run(importlib.import_module, "r29_later")
def test_after():
    assert "r29_expired_alias" not in sys.modules
''')
    code, output = _session(tmp_path, body, files={
        "r29_capture_root.py": root,
        "r29_later.py": 'import sys\nsys.modules["r29_expired_alias"] = sys.modules["r29_context_owner"]\n',
    }, options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "2 passed" in output, output
    assert "unrestored namespace: sys.modules[r29_expired_alias]" in output, output
    assert "INTERNALERROR" not in output, output


def test_r29_disabled_guard_does_not_initialize_import_provenance(tmp_path):
    code, output = _session(tmp_path, '''
import sys
def test_probe():
    assert "multiprocessing" not in sys.modules
    assert "__mp_main__" not in sys.modules
''', env_overrides={"AEGIS_PATCH_GUARD": "off"})
    assert code == 0, output
    assert "1 passed" in output, output
    assert "runtime patch guard metrics" not in output, output


def test_r29_unavailable_stdlib_bootstrap_refuses(tmp_path):
    extra = '''
_real_import_module = import_module
def import_module(name, *args, **kwargs):
    if name == "multiprocessing":
        raise ImportError("r29 private bootstrap marker")
    return _real_import_module(name, *args, **kwargs)
'''
    code, output = _session(tmp_path, "def test_probe(): pass\n", extra=extra)
    assert code == 4, output
    assert "runtime patch guard import API is unsupported" in output, output
    assert "r29 private bootstrap marker" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("operation", ["read", "replace", "delete"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r29_initial_stdlib_alias_keeps_exact_binding(tmp_path, operation, import_mode):
    action = {"read": "pass", "replace": 'sys.modules["__mp_main__"] = os',
              "delete": 'del sys.modules["__mp_main__"]'}[operation]
    body = '''
import os, sys
def test_a(main_module):
    assert sys.modules.get("__mp_main__") is main_module
    ACTION
def test_after(main_module):
    assert sys.modules["__mp_main__"] is main_module
'''.replace("ACTION", action)
    code, output = _session(tmp_path, body, extra='''
@pytest.fixture
def main_module(): return sys.modules["__main__"]
''', options=("--import-mode=" + import_mode,))
    refused = operation != "read"
    assert code == (1 if refused else 0), output
    assert "2 passed" in output, output
    assert ("unrestored namespace: sys.modules[__mp_main__]" in output) is refused, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("value_origin", ["existing", "import-created"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r29_concurrent_alias_uses_value_provenance(tmp_path, value_origin, import_mode):
    extra = '''
import sys
from types import ModuleType
from threading import Event
r29_control = ModuleType("r29_control")
r29_control.entered = Event()
r29_control.release = Event()
sys.modules["r29_control"] = r29_control
'''
    loader = '''
from r29_control import entered, release
VALUE = "trusted"
entered.set()
if not release.wait(30):
    raise RuntimeError("r29 import release timed out")
'''
    body = '''
from concurrent.futures import ThreadPoolExecutor
import importlib, os, sys
from r29_control import entered, release
def test_a():
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(importlib.import_module, "r29_thread_loader")
        try:
            assert entered.wait(30)
            sys.modules["r29_concurrent_alias"] = ALIAS_VALUE
        finally:
            release.set()
        assert pending.result(timeout=30).VALUE == "trusted"
def test_after():
    ALIAS_CHECK
    assert sys.modules["r29_thread_loader"].VALUE == "trusted"
'''
    refused = value_origin == "existing"
    body = body.replace("ALIAS_VALUE", "os" if refused else 'sys.modules["r29_thread_loader"]')
    body = body.replace("ALIAS_CHECK", 'assert "r29_concurrent_alias" not in sys.modules' if refused
                        else 'assert sys.modules["r29_concurrent_alias"] is sys.modules["r29_thread_loader"]')
    code, output = _session(tmp_path, body, extra=extra, files={"r29_thread_loader.py": loader},
                            options=("--import-mode=" + import_mode,))
    assert code == (1 if refused else 0), output
    assert "2 passed" in output, output
    assert ("unrestored namespace: sys.modules[r29_concurrent_alias]" in output) is refused, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("scenario", ["own", "nested", "helper", "helper-spoof", "executed-existing",
                                      "existing", "unregistered-existing",
                                      "package-none", "outside-none", "prefix-none"])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("timing", ["collection", "call"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r29_import_receipt_checks_value_and_package(tmp_path, scenario, failure, timing, import_mode):
    name = {"package-none": "r29_pkg.blocked", "outside-none": "r29_outside",
            "prefix-none": "r29_pkg_other.blocked"}.get(scenario, "r29_module_alias")
    action = {
        "own": "written = sys.modules[__name__]",
        "nested": "from . import child as written",
        "helper": 'written = ModuleType("arbitrary_helper")\nwritten.VALUE = "trusted"',
        "helper-spoof": 'written = ModuleType("os")\nwritten.VALUE = "trusted"',
        "executed-existing": "import r29_reexecuted as written\nwritten.__loader__.exec_module(written)",
        "existing": "written = os",
        "unregistered-existing": "from r29_prior import value as written",
        "package-none": "written = None",
        "outside-none": "written = None",
        "prefix-none": "written = None",
    }[scenario]
    loader = ('import os, sys\nfrom types import ModuleType\nVALUE = "trusted"\n' + action +
              '\nsys.modules[' + repr(name) + '] = written\n' +
              ('raise RuntimeError("r29 loader refused")\n' if failure else ''))
    request = ('with pytest.raises(RuntimeError, match="^r29 loader refused$"):\n'
               '    importlib.import_module("r29_pkg.loader")\n' if failure
               else 'importlib.import_module("r29_pkg.loader")\n')
    refused = scenario in {"existing", "unregistered-existing", "outside-none", "prefix-none"}
    during = ('assert sys.modules[' + repr(name) + '] is None\n' if scenario.endswith("none")
              else 'assert sys.modules[' + repr(name) + '] is os\n' if scenario == "existing"
              else 'assert sys.modules[' + repr(name) + '].VALUE == "trusted"\n')
    after = ('assert ' + repr(name) + ' not in sys.modules\n') if refused else during
    body = "import importlib, os, sys\nimport pytest\n"
    if timing == "collection":
        body += request + "\ndef test_probe():\n" + textwrap.indent(after, "    ")
    else:
        body += ("\ndef test_probe():\n" + textwrap.indent(request + during, "    ") +
                 "\ndef test_after():\n" + textwrap.indent(after, "    "))
    code, output = _session(tmp_path, body, extra='''
import r29_reexecuted
r29_prior = ModuleType("r29_prior")
r29_prior.value = ModuleType("unregistered_prior")
r29_prior.value.VALUE = "trusted"
sys.modules["r29_prior"] = r29_prior
''', files={
        "r29_pkg/__init__.py": "",
        "r29_pkg/loader.py": loader,
        "r29_pkg/child.py": 'VALUE = "trusted"\n',
        "r29_reexecuted.py": 'VALUE = "trusted"\n',
    }, options=("--import-mode=" + import_mode,))
    assert code == (1 if refused else 0), output
    assert ("1 passed" if timing == "collection" else "2 passed") in output, output
    label = "unrestored namespace:" + (" " if timing == "call" else "") + "sys.modules[" + name + "]"
    assert (label in output) is refused, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("probe", ["missing", "nonclass"])
def test_r28_unsupported_collection_attribution_refuses(tmp_path, probe):
    extra = '''
_original_guard_getattr_static = getattr_static
def getattr_static(owner, name, *args, **kwargs):
    if name == "File":
        return VALUE
    return _original_guard_getattr_static(owner, name, *args, **kwargs)
'''.replace("VALUE", "None" if probe == "missing" else "object()")
    code, output = _session(tmp_path, "def test_probe(): pass\n", extra=extra)
    assert code == 4, output
    assert ("pytest runtime guard API is unsupported; install a compatible pytest/Python "
            "or update tests/conftest.py for the installed runtime") in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("transport", ["active-copy", "retained", "conflict"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r28_import_helpers_publish_from_both_registry_transports(tmp_path, transport, import_mode):
    target = "registry" if transport == "retained" else "sys.modules"
    loader = ('import sys\nfrom types import ModuleType\n'
              'from r28_transport_holder import registry\n'
              'VALUE = "trusted"\nwritten = ModuleType("transported")\nwritten.VALUE = "trusted"\n' +
              target + '["r28_transport_helper"] = written\n')
    if transport == "conflict":
        loader += ('registry["r28_transport_helper"] = ModuleType("conflicting")\n')
    body = '''
import importlib, sys
saved = sys.modules
sys.modules = saved.copy()
try:
    importlib.import_module("transport_loader")
finally:
    sys.modules = saved
def test_probe():
    assert sys.modules["r28_transport_helper"].VALUE == "trusted"
    assert sys.modules["transport_loader"].VALUE == "trusted"
'''
    if transport == "conflict":
        body = body.replace('assert sys.modules["r28_transport_helper"].VALUE == "trusted"',
                            'assert "r28_transport_helper" not in sys.modules')
    code, output = _session(tmp_path, body, extra='''
import sys
from types import ModuleType
transport_holder = ModuleType("r28_transport_holder")
transport_holder.registry = sys.modules
sys.modules["r28_transport_holder"] = transport_holder
''', files={"transport_loader.py": loader}, options=("--import-mode=" + import_mode,))
    assert code == (1 if transport == "conflict" else 0), output
    assert "1 passed" in output, output
    assert ("unrestored namespace:sys.modules[r28_transport_helper]" in output) is (transport == "conflict"), output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("export", ["ProcessPoolExecutor", "ThreadPoolExecutor"])
@pytest.mark.parametrize("operation", ["first-access", "replace", "delete"])
@pytest.mark.parametrize("foreign", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r28_lazy_exports_are_exact_framework_bindings(tmp_path, export, operation, foreign, import_mode):
    setup = '''
import concurrent.futures as owner
import pytest
@pytest.hookimpl(specname="pytest_sessionstart", hookwrapper=True, tryfirst=True)
def pytest_r28_make_export_lazy(session):
    yield
    vars(owner).pop(EXPORT, None)
'''.replace("EXPORT", repr(export))
    action = {
        "first-access": "expected = getattr(owner, EXPORT)",
        "replace": "expected = object()\nsetattr(owner, EXPORT, expected)",
        "delete": "getattr(owner, EXPORT)\ndelattr(owner, EXPORT)",
    }[operation].replace("EXPORT", repr(export))
    check = ('assert EXPORT not in vars(owner)' if operation == "delete"
             else 'assert vars(owner)[EXPORT] is expected').replace("EXPORT", repr(export))
    source = ('import concurrent.futures as owner\n' + action + '\n' +
              ('owner._r28_unregistered = object()\n' if foreign else '') +
              'def test_probe():\n    ' + check + '\n'
              '    assert "_r28_unregistered" not in vars(owner)\n')
    code, output = _session(tmp_path, source, extra=setup,
                            options=("--import-mode=" + import_mode,))
    assert code == (1 if foreign else 0), output
    assert "1 passed" in output, output
    assert ("concurrent.futures._r28_unregistered" in output) is foreign, output
    assert "unrestored namespace:concurrent.futures." + export not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("timing", ["collection", "call"])
@pytest.mark.parametrize("value_kind", ["module", "none", "alias"])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r28_import_helpers_are_authenticated_by_the_import(tmp_path, timing, value_kind, failure, import_mode):
    value = {
        "module": 'ModuleType("arbitrary_runtime_helper")',
        "none": "None",
        "alias": "sys.modules[__name__]",
    }[value_kind]
    loader = ('import sys\nfrom types import ModuleType\nVALUE = "trusted"\n'
              'written = ' + value + '\n'
              'if written is not None: written.VALUE = "trusted"\n'
              'sys.modules["r28_arbitrary_helper"] = written\n' +
              ('raise RuntimeError("intentional helper import failure")\n' if failure else ''))
    request = ('with pytest.raises(RuntimeError, match="^intentional helper import failure$"):\n'
               '    importlib.import_module("runtime_loader")\n' if failure
               else 'importlib.import_module("runtime_loader")\n')
    check = ('assert "r28_arbitrary_helper" in sys.modules\n' +
             ('assert sys.modules["r28_arbitrary_helper"] is None\n' if value_kind == "none"
              else 'assert sys.modules["r28_arbitrary_helper"].VALUE == "trusted"\n'))
    source = "import importlib, sys\nimport pytest\n"
    if timing == "collection":
        after = 'assert "r28_arbitrary_helper" not in sys.modules\n' if value_kind == "none" else check
        source += request + "\ndef test_probe():\n" + textwrap.indent(after, "    ")
    else:
        source += "\ndef test_probe():\n" + textwrap.indent(request + check, "    ")
        if value_kind == "none":
            source += '\ndef test_after():\n    assert "r28_arbitrary_helper" not in sys.modules\n'
    code, output = _session(tmp_path, source, files={"runtime_loader.py": loader},
                            options=("--import-mode=" + import_mode,))
    refused = value_kind == "none"
    assert code == (1 if refused else 0), output
    assert ("2 passed" if refused and timing == "call" else "1 passed") in output, output
    label = ("unrestored namespace:" + (" " if timing == "call" else "") +
             "sys.modules[r28_arbitrary_helper]")
    assert (label in output) is refused, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("placement", ["alone", "before-import", "after-import"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r28_collection_entries_outside_an_import_still_refuse(tmp_path, placement, import_mode):
    add = 'sys.modules["r28_outside_import"] = ModuleType("outside")\n'
    request = "import innocent_loader\n"
    actions = {"alone": add, "before-import": add + request, "after-import": request + add}[placement]
    source = ('import sys\nfrom types import ModuleType\n' + actions +
              'def test_probe():\n    assert "r28_outside_import" not in sys.modules\n' +
              ('    assert sys.modules["r28_nested_helper"].VALUE == "trusted"\n'
               if placement != "alone" else ''))
    code, output = _session(tmp_path, source, files={"innocent_loader.py": '''
import sys
from types import ModuleType
helper = ModuleType("nested")
helper.VALUE = "trusted"
sys.modules["r28_nested_helper"] = helper
'''}, options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "1 passed" in output, output
    assert "collection:0:unrestored namespace:sys.modules[r28_outside_import]" in output, output
    assert "unrestored namespace:sys.modules[r28_nested_helper]" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("scenario", ["existing", "nested-replacement", "later-replacement", "helper-namespace"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r28_import_receipts_keep_existing_bindings_exact(tmp_path, scenario, import_mode):
    leaf = '''
import sys
from types import ModuleType
written = ModuleType("runtime")
written.VALUE = "trusted"
sys.modules["r28_exact_helper"] = written
'''
    files = {"leaf_loader.py": leaf}
    setup = '''
import json
@pytest.fixture
def registry_original(): return json
'''
    if scenario == "existing":
        files["runtime_replacer.py"] = '''
import sys
from types import ModuleType
sys.modules["json"] = ModuleType("replacement")
'''
        source = '''
import sys
import runtime_replacer
def test_probe(registry_original):
    assert sys.modules["json"] is registry_original
'''
        expected = "sys.modules[json]"
    else:
        replacement = 'sys.modules["r28_exact_helper"] = ModuleType("replacement")\n'
        if scenario == "nested-replacement":
            files["runtime_replacer.py"] = ("import sys\nfrom types import ModuleType\n"
                                             "import leaf_loader\n" + replacement)
            actions = "import runtime_replacer\nimport leaf_loader\n"
        elif scenario == "later-replacement":
            actions = "import leaf_loader\n" + replacement
        else:
            actions = 'import leaf_loader\nleaf_loader.written.VALUE = "leaked"\n'
        source = ('import sys\nfrom types import ModuleType\n' + actions +
                  'def test_probe():\n'
                  '    assert sys.modules["r28_exact_helper"] is leaf_loader.written\n'
                  '    assert leaf_loader.written.VALUE == "trusted"\n')
        expected = "r28_exact_helper.VALUE" if scenario == "helper-namespace" else "sys.modules[r28_exact_helper]"
    code, output = _session(tmp_path, source, extra=setup, files=files,
                            options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "1 passed" in output, output
    assert "collection:0:unrestored namespace:" + expected in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("target", ["test", "conftest"])
@pytest.mark.parametrize("operation", ["none", "assign", "delete", "dictionary"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r27_nested_initializer_keeps_own_writes_and_repairs_foreign_writes(
        tmp_path, target, operation, import_mode):
    mutation = {
        "none": "",
        "assign": 'victim.VALUE = "leaked"',
        "delete": "del victim.VALUE",
        "dictionary": 'vars(victim)["VALUE"] = "leaked"',
    }[operation]
    imported = "tests.test_00_victim" if target == "test" else "tests.conftest"
    nested = ('from tests.conftest import COLLECTION_READY\nassert COLLECTION_READY\nimport ' + imported + ' as victim\nVALUE = "initial"\nVALUE = "trusted"\n' +
              mutation + '\nimport pytest\n@pytest.fixture\ndef initialized(): return VALUE, victim.VALUE\n')
    code, output = _session(tmp_path, "# Directory discovery controls collection timing.\n", extra='''
VALUE = "trusted"
COLLECTION_READY = []
@pytest.hookimpl(specname="pytest_sessionstart")
def pytest_r27_session_ready(session):
    COLLECTION_READY.append(True)
''',
        files={"tests/__init__.py": "",
               "tests/test_00_victim.py": 'VALUE = "trusted"\ndef test_victim(): assert VALUE == "trusted"\n',
               "tests/sub/conftest.py": nested,
               "tests/sub/test_nested.py":
                   'def test_nested(initialized):\n'
                   '    assert initialized == ("trusted", "trusted")\n'},
        selection=("tests",),
        options=("--ignore=tests/contract", "--import-mode=" + import_mode))
    assert code == (0 if operation == "none" else 1), output
    assert "2 passed" in output, output
    violations = [line for line in output.splitlines()
                  if line.startswith("collection:0:unrestored namespace:")]
    expected = [] if operation == "none" else ["collection:0:unrestored namespace:" + imported + ".VALUE"]
    assert violations == expected, output
    assert "ERROR at teardown" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("target", ["test", "conftest"])
@pytest.mark.parametrize("operation", ["assign", "delete", "dictionary"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r27_collection_import_mutations_fail_and_restore(tmp_path, target, operation, import_mode):
    mutation = {
        "assign": 'victim.VALUE = "leaked"',
        "delete": "del victim.VALUE",
        "dictionary": 'vars(victim)["VALUE"] = "leaked"',
    }[operation]
    imported = "tests.test_00_victim" if target == "test" else "tests.conftest"
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra='\nVALUE = "trusted"\n',
        files={"tests/__init__.py": "",
               "tests/test_00_victim.py": 'VALUE = "trusted"\ndef test_victim(): assert VALUE == "trusted"\n',
               "tests/test_01_other.py": "import " + imported + " as victim\n" + mutation +
                   '\ndef test_restored(): assert victim.VALUE == "trusted"\n'},
        options=("tests/test_00_victim.py", "tests/test_01_other.py", "--import-mode=" + import_mode))
    assert code == 1, output
    assert "3 passed" in output, output
    assert "collection:0:unrestored namespace:" in output, output
    assert ".VALUE" in output, output
    assert "ERROR at teardown" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("target", ["test", "conftest"])
@pytest.mark.parametrize("field", ["__warningregistry__", "__annotations__"])
@pytest.mark.parametrize("operation", ["replace", "delete"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r27_imported_registry_rebindings_fail_and_restore(tmp_path, target, field, operation, import_mode):
    imported = "tests.test_00_victim" if target == "test" else "tests.conftest"
    mutation = "victim.FIELD = {}" if operation == "replace" else "del victim.FIELD"
    module_source = ('import ' + imported + ' as victim\noriginal = vars(victim)["FIELD"]\n' +
                     mutation + '\ndef test_restored(): assert vars(victim)["FIELD"] is original\n').replace(
                         "FIELD", field)
    preset = '\n__warningregistry__ = {"owned": object()}\n__annotations__ = {"owned": object()}\n'
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=preset,
        files={"tests/__init__.py": "",
               "tests/test_00_victim.py": preset + "\ndef test_victim(): pass\n",
               "tests/test_01_other.py": module_source},
        options=("tests/test_00_victim.py", "tests/test_01_other.py", "--import-mode=" + import_mode))
    assert code == 1, output
    assert "3 passed" in output, output
    assert "collection:0:unrestored namespace:" in output, output
    assert "." + field in output, output
    assert "ERROR at teardown" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r27_own_import_globals_stay_trusted(tmp_path, import_mode):
    code, output = _session(tmp_path, '''
VALUE = "initial"
VALUE = "trusted"
REMOVED = 17
del REMOVED
vars()["DICTIONARY_VALUE"] = "trusted"
def test_probe():
    assert VALUE == DICTIONARY_VALUE == "trusted"
    assert "REMOVED" not in globals()
''', options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "1 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r27_first_observation_at_collection_keeps_module_bindings(tmp_path, import_mode):
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra='''
from types import ModuleType
def pytest_collection_modifyitems(items):
    module = ModuleType("first_seen")
    exec('VALUE = "first"\\ndef test_generated():\\n    assert VALUE == "first"\\n'
         '    assert type(__warningregistry__) is dict\\n', vars(module))
    item = items[0]
    item.getparent(pytest.Module)._obj = module
    item._obj = module.test_generated
''', options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "1 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("timing", ["collection", "during-test"])
@pytest.mark.parametrize("form", ["context", "callable"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_helper_warnings_keep_registry(tmp_path, timing, form, import_mode):
    body = """
import importlib
import pytest
PRELOAD
seen = []
def test_a():
    module = importlib.import_module("retained_helper")
    WARN
    original = module.__warningregistry__
    assert module.initial_registry is original
    seen.append((module, original))
def test_b():
    module, original = seen[-1]
    assert module.__warningregistry__ is original
""".replace("PRELOAD", "import retained_helper" if timing == "collection" else "").replace(
        "    WARN", '    with pytest.warns(UserWarning, match="expected"):\n'
        '        module.emit()' if form == "context" else
        "    pytest.warns(UserWarning, module.emit)")
    code, output = _external_session(tmp_path, body, import_mode=import_mode, files={
        "retained_helper.py": """
import warnings
initial_registry = globals().get("__warningregistry__")
def emit(): warnings.warn("expected", UserWarning)
"""})
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("timing", ["collection", "during-test"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_helper_lazy_annotations_keep_registry(tmp_path, timing, import_mode):
    from types import ModuleType
    if "__annotations__" not in vars(ModuleType):
        pytest.skip("This interpreter has no lazy module annotations")
    code, output = _external_session(tmp_path, """
import importlib
PRELOAD
seen = []
def test_a():
    module = importlib.import_module("retained_helper")
    original = module.__annotations__
    assert type(original) is dict
    seen.append((module, original))
def test_b():
    module, original = seen[-1]
    assert module.__annotations__ is original
""".replace("PRELOAD", "import retained_helper" if timing == "collection" else ""),
        import_mode=import_mode, files={"retained_helper.py": "VALUE = 17\n"})
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("field,seeded", [
    ("__warningregistry__", False), ("__warningregistry__", True), ("__annotations__", True)])
@pytest.mark.parametrize("operation", ["replace", "delete"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_helper_registry_rebindings_fail_and_restore(
        tmp_path, field, seeded, operation, import_mode):
    body = """
import retained_helper
seen = []
def test_a():
    original = vars(retained_helper)["FIELD"]
    assert type(original) is dict
    PRESERVED
    seen.append(original)
    OPERATION
def test_b():
    assert vars(retained_helper)["FIELD"] is seen[-1]
""".replace("PRESERVED", "assert original is retained_helper._original_registry" if seeded else "pass").replace(
        "OPERATION", "retained_helper.FIELD = {}" if operation == "replace" else
        "del retained_helper.FIELD").replace("FIELD", field)
    source = "FIELD = {}\n_original_registry = FIELD\n".replace("FIELD", field) if seeded else "VALUE = 17\n"
    code, output = _external_session(tmp_path, body, import_mode=import_mode,
                                    files={"retained_helper.py": source})
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "2 passed, 1 error" in output, output
    assert "." + field in output, output
    assert "INTERNALERROR" not in output, output


def _external_session(tmp_path, body, *, import_mode, enabled="on", plugin_suffix="", files=None):
    suite = tmp_path / "plugin-suite"
    plugin_dir = suite / "tests"
    contract = plugin_dir / "contract"
    contract.mkdir(parents=True)
    (plugin_dir / "__init__.py").write_text("", encoding="utf-8")
    (suite / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    plugin = (ROOT / "tests/conftest.py").read_text(encoding="utf-8")
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh(): pass\n'
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh_on_path(): pass\n'
    plugin += textwrap.dedent(plugin_suffix)
    (plugin_dir / "conftest.py").write_text(plugin, encoding="utf-8")
    (contract / "test_monkeypatch_raising.py").write_text(
        (ROOT / "tests/contract/test_monkeypatch_raising.py").read_text(encoding="utf-8"), encoding="utf-8")
    external = tmp_path / "external"
    external.mkdir()
    for name, source in (files or {}).items():
        (external / name).write_text(textwrap.dedent(source), encoding="utf-8")
    test_file = external / "test_external.py"
    test_file.write_text(textwrap.dedent(body), encoding="utf-8")
    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONPATH"] = os.pathsep.join((str(suite), str(external), str(ROOT), env.get("PYTHONPATH", "")))
    env["AEGIS_PATCH_GUARD"] = enabled
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-p", "tests.conftest",
         "-c", str(suite / "pytest.ini"), str(test_file), "-q", "-p", "no:cacheprovider",
         "--basetemp", str(tmp_path / "run"), "--import-mode=" + import_mode],
        cwd=str(suite), env=env, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.parametrize("origin", ["test", "fixture", "stacklevel"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_collected_warnings_keep_registry(tmp_path, origin, import_mode):
    body = '''
import sys
import warnings
import pytest
from warn_helper import emit
seen = []
@pytest.fixture
def emits_warning():
    with pytest.warns(UserWarning, match="expected") as caught:
        EMIT
    assert caught[0].filename == __file__
    return sys.modules[__name__]
def test_a(FIXTURE):
    NAMESPACE
    WARN
    original = vars(namespace)["__warningregistry__"]
    assert type(original) is dict
    seen.append((namespace, original))
def test_b():
    namespace, original = seen[-1]
    assert vars(namespace)["__warningregistry__"] is original
'''.replace("EMIT", "emit()" if origin == "stacklevel" else
            'warnings.warn("expected", UserWarning)').replace(
        "FIXTURE", "" if origin == "test" else "emits_warning").replace(
        "NAMESPACE", 'namespace = sys.modules[__name__]' if origin == "test" else
        "namespace = emits_warning").replace(
        "    WARN", '    with pytest.warns(UserWarning, match="expected"):\n'
        '        warnings.warn("expected", UserWarning)' if origin == "test" else "    pass")
    code, output = _external_session(tmp_path, body, import_mode=import_mode, files={
        "warn_helper.py": '''
import warnings
def emit(): warnings.warn("expected", UserWarning, stacklevel=2)
'''})
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("field,seeded", [
    ("__warningregistry__", False), ("__warningregistry__", True), ("__annotations__", True)])
@pytest.mark.parametrize("operation", ["replace", "delete"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_registry_rebindings_fail_and_restore(tmp_path, field, seeded, operation, import_mode):
    body = '''
import sys
PRESET
seen = []
def test_a():
    namespace = sys.modules[__name__]
    original = vars(namespace)["FIELD"]
    assert type(original) is dict
    PRESERVED
    seen.append((namespace, original))
    OPERATION
def test_b():
    namespace, original = seen[-1]
    assert vars(namespace)["FIELD"] is original
'''.replace("PRESET", 'FIELD = {"owned": object()}\n_original_registry = FIELD' if seeded else "").replace(
        "PRESERVED", 'assert original is _original_registry' if seeded else "pass").replace(
        "OPERATION", 'namespace.FIELD = {}' if operation == "replace" else
        'del namespace.FIELD').replace("FIELD", field)
    code, output = _external_session(tmp_path, body, import_mode=import_mode)
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "2 passed, 1 error" in output, output
    assert "." + field in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_lazy_annotations_keep_registry(tmp_path, import_mode):
    from types import ModuleType
    if "__annotations__" not in vars(ModuleType):
        pytest.skip("This interpreter has no lazy module annotations")
    code, output = _external_session(tmp_path, '''
import sys
seen = []
def test_a():
    namespace = sys.modules[__name__]
    original = namespace.__annotations__
    assert type(original) is dict
    seen.append((namespace, original))
def test_b():
    namespace, original = seen[-1]
    assert namespace.__annotations__ is original
''', import_mode=import_mode)
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_warning_registry_without_annotation_descriptor(tmp_path, import_mode):
    code, output = _external_session(tmp_path, '''
import sys
import warnings
import pytest
def test_probe():
    namespace = vars(sys.modules[__name__])
    assert type(namespace["__warningregistry__"]) is dict
    assert "__annotations__" not in namespace
    with pytest.warns(UserWarning, match="expected"):
        warnings.warn("expected", UserWarning)
''', import_mode=import_mode, plugin_suffix='''
_r26_static = getattr_static
def getattr_static(*args, **kwargs):
    if len(args) >= 2 and args[0] is ModuleType and args[1] == "__annotations__":
        return None
    return _r26_static(*args, **kwargs)
''')
    assert code == 0, output
    assert "1 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r26_external_guard_off_does_not_initialize_registry(tmp_path, import_mode):
    code, output = _external_session(tmp_path, '''
import sys
def test_probe():
    namespace = vars(sys.modules[__name__])
    assert "__warningregistry__" not in namespace
    assert "__annotations__" not in namespace
''', import_mode=import_mode, enabled="off")
    assert code == 0, output
    assert "1 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("target", ["test", "conftest"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r25_lazy_module_annotations_keep_the_registry_binding(tmp_path, target, import_mode):
    from types import ModuleType
    if "__annotations__" not in vars(ModuleType):
        pytest.skip("This interpreter has no lazy module annotations")
    code, output = _session(tmp_path, """
import sys
seen = []
def test_a(infrastructure):
    namespace = OWNER
    registry = namespace.__annotations__
    assert type(registry) is dict
    seen.append((namespace, registry))
def test_b():
    namespace, registry = seen[-1]
    assert namespace.__annotations__ is registry
""".replace("OWNER", "sys.modules[__name__]" if target == "test" else "infrastructure"),
        extra="""
import sys
@pytest.fixture
def infrastructure(): return sys.modules[__name__]
""", options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r25_absent_annotation_descriptor_keeps_warning_initialization(tmp_path, import_mode):
    code, output = _session(tmp_path, """
import sys
def test_probe(infrastructure):
    for namespace in (vars(sys.modules[__name__]), vars(infrastructure)):
        assert type(namespace["__warningregistry__"]) is dict
        assert "__annotations__" not in namespace
""", extra="""
import sys
_r25_static = getattr_static
def getattr_static(*args, **kwargs):
    if len(args) >= 2 and args[0] is ModuleType and args[1] == "__annotations__":
        return None
    return _r25_static(*args, **kwargs)
@pytest.fixture
def infrastructure(): return sys.modules[__name__]
""", options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "1 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("origin", ["test", "fixture", "stacklevel"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r25_expected_warnings_keep_the_registry_binding(tmp_path, origin, import_mode):
    extra = '''
import sys
import warnings
from r25_warning_helper import emit as _r25_warn
@pytest.fixture
def emits_warning():
    with pytest.warns(UserWarning, match="expected") as caught:
        EMIT
    assert caught[0].filename == __file__
    return sys.modules[__name__]
'''.replace("EMIT", '_r25_warn()' if origin == "stacklevel" else
            'warnings.warn("expected", UserWarning)')
    body = '''
import sys
import warnings
import pytest
seen = []
def test_a(FIXTURE):
    NAMESPACE
    EMIT
    registry = vars(namespace)["__warningregistry__"]
    assert type(registry) is dict
    seen.append((namespace, registry))
def test_b():
    namespace, registry = seen[-1]
    assert vars(namespace)["__warningregistry__"] is registry
'''.replace("FIXTURE", "" if origin == "test" else "emits_warning").replace(
        "NAMESPACE", 'namespace = sys.modules[__name__]' if origin == "test" else
        "namespace = emits_warning").replace(
        "    EMIT", '    with pytest.warns(UserWarning, match="expected"):\n'
        '        warnings.warn("expected", UserWarning)' if origin == "test" else "    pass")
    code, output = _session(tmp_path, body, extra=extra, files={
        "r25_warning_helper.py": 'import warnings\ndef emit(): warnings.warn("expected", UserWarning, stacklevel=2)\n'},
        options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("field", ["__warningregistry__", "__annotations__"])
@pytest.mark.parametrize("target", ["test", "conftest"])
@pytest.mark.parametrize("operation", ["replace", "delete"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r25_warning_registry_rebindings_fail_and_restore(tmp_path, field, target, operation, import_mode):
    body = '''
import sys
FIELD = {"owned": object()}
_original_registry = FIELD
seen = []
def test_a(infrastructure):
    namespace = OWNER
    original = vars(namespace)["_original_registry"]
    assert vars(namespace)["FIELD"] is original
    seen.append((namespace, original))
    OPERATION
def test_b():
    namespace, original = seen[-1]
    assert vars(namespace)["FIELD"] is original
'''.replace("OWNER", 'sys.modules[__name__]' if target == "test" else "infrastructure").replace(
        "OPERATION", 'namespace.FIELD = {}' if operation == "replace" else
        'del namespace.FIELD')
    body = body.replace("FIELD", field)
    code, output = _session(tmp_path, body, extra='''
import sys
FIELD = {"owned": object()}
_original_registry = FIELD
@pytest.fixture
def infrastructure(): return sys.modules[__name__]
'''.replace("FIELD", field), options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "2 passed, 1 error" in output, output
    assert "." + field in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("filename", ["test_late", "conftest"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r25_late_test_sources_have_a_warning_registry_before_execution(tmp_path, filename, import_mode):
    code, output = _session(tmp_path, '''
import importlib
import pytest
seen = []
def test_a():
    module = importlib.import_module("tests.late.FILENAME")
    with pytest.warns(UserWarning, match="expected"):
        module.emit()
    assert module.initial_registry is module.__warningregistry__
    seen.append((module, module.__warningregistry__))
def test_b():
    module, original = seen[-1]
    assert module.__warningregistry__ is original
'''.replace("FILENAME", filename), files={
        "tests/__init__.py": "",
        "tests/late/__init__.py": "",
        "tests/late/" + filename + ".py": '''
import warnings
initial_registry = globals().get("__warningregistry__")
def emit(): warnings.warn("expected", UserWarning)
'''}, options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r25_guard_off_does_not_initialize_warning_registries(tmp_path, import_mode):
    code, output = _session(tmp_path, '''
import sys
def test_probe(infrastructure):
    assert "__warningregistry__" not in vars(sys.modules[__name__])
    assert "__warningregistry__" not in vars(infrastructure)
''', extra='''
import sys
@pytest.fixture
def infrastructure(): return sys.modules[__name__]
''', env_overrides={"AEGIS_PATCH_GUARD": "off"}, options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "1 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("target", ["test", "conftest"])
@pytest.mark.parametrize("method", ["monkeypatch", "mock", "mock-dictionary"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r24_retained_namespace_repair_wins_over_saved_patch_values(tmp_path, target, method, import_mode):
    field = "COUNTER" if target == "test" else "_PATCH_GUARD_DEFAULT"
    owner = "current" if target == "test" else "infrastructure"
    operation = {
        "monkeypatch": 'with monkeypatch.context() as owned:\n    owned.setattr(OWNER, FIELD, object())',
        "mock": 'with patch.object(OWNER, FIELD, object()): pass',
        "mock-dictionary": 'with patch.dict(vars(OWNER), {FIELD: object()}): pass',
    }[method].replace("OWNER", owner).replace("FIELD", repr(field))
    body = '''
import sys
from unittest.mock import patch
COUNTER = 17
def test_a(infrastructure, monkeypatch):
    current = sys.modules[__name__]
    OWNER.FIELD = "leaked"
OPERATION
def test_b(infrastructure):
    assert COUNTER == 17
    assert infrastructure._PATCH_GUARD_DEFAULT is infrastructure._r24_original_default
'''.replace("OWNER", owner).replace("FIELD", field).replace(
        "OPERATION", textwrap.indent(operation, "    "))
    code, output = _session(tmp_path, body, extra='''
import sys
_r24_original_default = _PATCH_GUARD_DEFAULT
@pytest.fixture
def infrastructure(): return sys.modules[__name__]
''', options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "2 passed, 1 error" in output, output
    assert "unrestored namespace" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("shape", ["outer", "stacked", "bound"])
@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
@pytest.mark.parametrize("broken", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r24_every_validated_fixture_wrapper_keeps_its_source(
        tmp_path, shape, method, broken, import_mode):
    wrapper = '''
from functools import wraps
from unittest.mock import patch
def decorate(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        tool = function(*args, **kwargs)
        OPERATION
        return tool
    return wrapper
'''
    operation = ('kwargs["monkeypatch"].setattr(tool, FIELD, lambda: 17, raising=False)'
                 if method == "monkeypatch" else
                 'with patch.object(tool, FIELD, lambda: 17, create=True): pass')
    wrapper = wrapper.replace("        OPERATION", textwrap.indent(operation, "        "))
    loader = '''
from tests.sub.wrappers import decorate
from tests.sub.outer import decorate as outer
'''
    implementation = '''
tool = ModuleType("consumer")
if BROKEN:
    callback = request._fixturedef.func
    if hasattr(callback, "__func__"):
        callback = callback.__func__
    callback.__wrapped__ = callback
return tool
'''.replace("BROKEN", repr(broken))
    prefix = '''
import pytest
from types import ModuleType
from wrapper_loader import decorate, outer
'''
    if shape == "bound":
        fixture = prefix + '''
class Provider:
    @decorate
    def implementation(self, monkeypatch, request):
BODY
tool = pytest.fixture(name="tool")(Provider().implementation)
'''.replace("BODY", textwrap.indent(implementation.strip(), "        "))
    else:
        fixture = prefix + '''
@pytest.fixture
DECORATORS
def tool(monkeypatch, request):
BODY
'''.replace("DECORATORS", "@outer\n@decorate" if shape == "stacked" else "@decorate").replace(
            "BODY", textwrap.indent(implementation.strip(), "    "))
    policy = {("tests/sub/wrappers.py", "tool.open"): "Validated wrapper source."}
    if shape == "stacked":
        policy["tests/sub/outer.py", "tool.len"] = "Validated outer source."
    assertion = ('assert tool.open() == 17' if method == "monkeypatch"
                 else 'assert not hasattr(tool, "open")')
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", files={
        "wrapper_loader.py": loader,
        "tests/__init__.py": "",
        "tests/sub/__init__.py": "",
        "tests/sub/wrappers.py": wrapper.replace("FIELD", repr("open")),
        "tests/sub/outer.py": wrapper.replace("FIELD", repr("len")),
        "tests/sub/conftest.py": fixture,
        "tests/sub/test_wrappers.py": "def test_a(tool):\n    " + assertion + "\n"},
        policy_suffix="\nBUILTIN_GLOBALS = " + repr(policy) + "\n",
        options=("tests/sub/test_wrappers.py", "--import-mode=" + import_mode), child_timeout=60)
    assert code == (1 if broken else 0), output
    assert ("permits a missing target" in output) is broken, output
    assert "2 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("target", ["test", "conftest", "both"])
@pytest.mark.parametrize("operation", ["assign", "dictionary", "delete"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r24_test_and_conftest_rebindings_fail_and_restore(tmp_path, target, operation, import_mode):
    owners = []
    if target in ("test", "both"):
        owners.append(("current", "COUNTER"))
    if target in ("conftest", "both"):
        owners.append(("infrastructure", "_PATCH_GUARD_DEFAULT"))
    statements = []
    for owner, field in owners:
        if operation == "assign":
            statements.append(owner + "." + field + " = 'leaked'")
        elif operation == "dictionary":
            statements.append("vars(" + owner + ")[" + repr(field) + "] = 'leaked'")
        else:
            statements.append("del " + owner + "." + field)
    body = '''
import sys
COUNTER = 17
def test_a_change(infrastructure):
    current = sys.modules[__name__]
OPERATIONS
def test_b_retry(infrastructure):
    assert COUNTER == 17
    assert infrastructure._PATCH_GUARD_DEFAULT is infrastructure._r24_original_default
'''.replace("OPERATIONS", textwrap.indent("\n".join(statements), "    "))
    code, output = _session(tmp_path, body, extra='''
import sys
_r24_original_default = _PATCH_GUARD_DEFAULT
@pytest.fixture
def infrastructure(): return sys.modules[__name__]
''', options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "ERROR at teardown of test_a_change" in output, output
    assert "unrestored namespace" in output, output
    if target in ("test", "both"):
        assert ".COUNTER" in output, output
    if target in ("conftest", "both"):
        assert "._PATCH_GUARD_DEFAULT" in output, output
    assert "2 passed, 1 error" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("method", ["direct", "monkeypatch", "mock"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r24_restored_test_and_conftest_bindings_stay_clean(tmp_path, method, import_mode):
    operations = {
        "direct": '''
saved = COUNTER, infrastructure._PATCH_GUARD_DEFAULT
try:
    current.COUNTER = 99
    infrastructure._PATCH_GUARD_DEFAULT = "temporary"
finally:
    current.COUNTER, infrastructure._PATCH_GUARD_DEFAULT = saved
''',
        "monkeypatch": '''
with monkeypatch.context() as owned:
    owned.setattr(current, "COUNTER", 99)
    owned.setattr(infrastructure, "_PATCH_GUARD_DEFAULT", "temporary")
''',
        "mock": '''
with patch.object(current, "COUNTER", 99), patch.object(infrastructure, "_PATCH_GUARD_DEFAULT", "temporary"):
    assert COUNTER == 99
''',
    }
    body = '''
import sys
from unittest.mock import patch
COUNTER = 17
def test_a(infrastructure, monkeypatch):
    current = sys.modules[__name__]
OPERATION
def test_b(infrastructure):
    assert COUNTER == 17
    assert infrastructure._PATCH_GUARD_DEFAULT is infrastructure._r24_original_default
'''.replace("OPERATION", textwrap.indent(operations[method].strip(), "    "))
    code, output = _session(tmp_path, body, extra='''
import sys
_r24_original_default = _PATCH_GUARD_DEFAULT
@pytest.fixture
def infrastructure(): return sys.modules[__name__]
''', options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("trusted_parent", [False, True])
@pytest.mark.parametrize("package_stub", [False, True])
@pytest.mark.parametrize("form", ["importlib", "statement"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r24_imports_preserve_untrusted_live_parents_for_reconciliation(
        tmp_path, trusted_parent, package_stub, form, import_mode):
    operation = ('loaded = importlib.import_module("r24_package.child")' if form == "importlib" else
                 'import r24_package.child as loaded')
    body = '''
import importlib
from pathlib import Path
import sys
from types import ModuleType
import pytest
PRELOAD
seen = []
def test_a_stub():
    stub = ModuleType("r24_package")
    PATH
    sys.modules["r24_package"] = stub
    IMPORT
    assert sys.modules["r24_package"] is stub
    seen.append(stub)
def test_b_retry():
    assert sys.modules.get("r24_package") is not seen[-1]
    loaded = importlib.import_module("r24_package.child")
    assert loaded.VALUE == 17
    assert loaded is not seen[0]
    assert sys.modules["r24_package"].child is loaded
'''.replace("PRELOAD", "import r24_package" if trusted_parent else "").replace(
        "PATH", 'stub.__path__ = [str(Path("r24_package").resolve())]' if package_stub else "pass")
    if package_stub:
        operation += '\nassert loaded.VALUE == 17\nseen.append(loaded)'
    else:
        operation = ('with pytest.raises(ModuleNotFoundError, match="not a package"):\n' +
                     textwrap.indent(operation, "    "))
    body = body.replace("    IMPORT", textwrap.indent(operation, "    "))
    code, output = _session(tmp_path, body, files={
        "r24_package/__init__.py": 'VALUE = "parent"\n',
        "r24_package/child.py": "VALUE = 17\n"},
        options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "ERROR at teardown of test_a_stub" in output, output
    assert "unrestored namespace" in output and "sys.modules[r24_package]" in output, output
    assert "2 passed, 1 error" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("origin", ["item-receipt", "frame-receipt", "item-limit", "frame-limit"])
@pytest.mark.parametrize("policy_case", ["lower", "upper"])
@pytest.mark.parametrize("case_insensitive", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r23_policy_paths_use_the_platform_key(
        tmp_path, origin, policy_case, case_insensitive, import_mode):
    extra = '''
from types import ModuleType
_PATCH_PATH_CASE_INSENSITIVE = FLAG
@pytest.fixture
def tool(): return ModuleType("consumer")
'''.replace("FLAG", repr(case_insensitive))
    plugin = '''
from pathlib import Path
import os
import pytest
from unittest.mock import patch
@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items):
    for item in items:
        if ORIGIN == "item-receipt":
            item.path = item.path.parent.with_name("TESTS") / item.path.name
        elif ORIGIN.startswith("frame-"):
            filename = Path(item.obj.__code__.co_filename)
            item.obj.__code__ = item.obj.__code__.replace(co_filename=str(filename.with_name(filename.name.upper())))
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    yield
    if ORIGIN == "item-limit":
        prior = item.path
        item.path = prior.parent.with_name("TESTS") / prior.name
        try:
            with patch.object(os, "getpid", lambda: 7):
                assert os.getpid() == 7
        finally:
            item.path = prior
'''.replace("ORIGIN", repr(origin))
    if origin.endswith("receipt"):
        body = '''
def test_probe(tool, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(tool, "open", lambda: None, raising=False)
    assert not hasattr(tool, "open")
'''
    else:
        body = '''
import os
from unittest.mock import patch
def test_probe():
    if ORIGIN == "frame-limit":
        with patch.object(os, "getpid", lambda: 7):
            assert os.getpid() == 7
'''.replace("ORIGIN", repr(origin))
    path = "tests/test_probe.py" if policy_case == "lower" else "TESTS/TEST_PROBE.PY"
    code, output = _session(tmp_path, body, extra=extra, files={"conftest.py": plugin},
        limits={path: 1}, policy_suffix="\nBUILTIN_GLOBALS = " +
            repr({(path, "tool.open"): "Platform path key."}) + "\n",
        options=("--import-mode=" + import_mode,))
    assert code == (0 if case_insensitive else 1), output
    diagnostic = "permits a missing target" if origin.endswith("receipt") else "shared module patch count"
    assert (diagnostic in output) is not case_insensitive, output
    assert "1 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("origin", ["item", "frame"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r23_path_key_preserves_diagnostic_spelling(tmp_path, origin, import_mode):
    plugin = '''
from pathlib import Path
import os
import pytest
from unittest.mock import patch
@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items):
    for item in items:
        if ORIGIN == "frame":
            filename = Path(item.obj.__code__.co_filename)
            item.obj.__code__ = item.obj.__code__.replace(co_filename=str(filename.with_name(filename.name.upper())))
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    yield
    if ORIGIN == "item":
        prior = item.path
        item.path = prior.parent.with_name("TESTS") / prior.name
        try:
            with patch.object(os, "getpid", lambda: 7): pass
        finally:
            item.path = prior
'''.replace("ORIGIN", repr(origin))
    body = '''
import os
from unittest.mock import patch
def test_probe():
    if ORIGIN == "frame":
        with patch.object(os, "getpid", lambda: 7): pass
'''.replace("ORIGIN", repr(origin))
    code, output = _session(tmp_path, body, files={"conftest.py": plugin},
        extra="_PATCH_PATH_CASE_INSENSITIVE = True\n",
        limits={"tests/test_probe.py": 0}, options=("--import-mode=" + import_mode,))
    display = "TESTS/test_probe.py" if origin == "item" else "tests/TEST_PROBE.PY"
    assert code == 1, output
    assert display + ":0:shared module patch count 1 exceeds 0" in output, output
    assert "1 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r23_case_aliases_share_one_patch_limit(tmp_path, import_mode):
    body = '''
import os
from pathlib import Path
from unittest.mock import patch
def first():
    with patch.object(os, "getpid", lambda: 7): pass
def second():
    with patch.object(os, "getpid", lambda: 7): pass
filename = Path(second.__code__.co_filename)
second.__code__ = second.__code__.replace(co_filename=str(filename.with_name(filename.name.upper())))
def test_probe():
    first()
    second()
'''
    code, output = _session(tmp_path, body, extra="_PATCH_PATH_CASE_INSENSITIVE = True\n",
        limits={"tests/test_probe.py": 1, "tests/TEST_PROBE.PY": 1},
        options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "shared module patch count 2 exceeds 1" in output, output
    assert "1 passed" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("layers", [5, 20])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r23_shared_fixture_graph_has_linear_state_counts(tmp_path, layers, import_mode):
    definitions = 2 * layers + 2
    fixture = '''
from types import ModuleType
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
'''
    for level in range(1, layers + 1):
        arguments = "tool" if level == 1 else "a_%s, b_%s" % (level - 1, level - 1)
        value = "tool" if level == 1 else "a_%s" % (level - 1)
        for prefix in ("a", "b"):
            fixture += '\n@pytest.fixture(scope="session")\ndef %s_%s(%s): return %s\n' % (
                prefix, level, arguments, value)
    fixture += '\n@pytest.fixture(scope="session")\ndef root(a_%s, b_%s): return a_%s\n' % (
        layers, layers, layers)
    plugin = '''
import sys
from pathlib import Path
import pytest
BUDGET = DEFINITION_COUNT * 4
@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    counts = {"stack": [], "maximum_visits": 0, "maximum_views": 0}
    item.config._r23_counts = counts
    filename = str(Path(__file__).parent / "tests" / "conftest.py")
    def profile(frame, event, argument):
        if frame.f_code.co_filename != filename:
            return
        name = frame.f_code.co_name
        if name == "_activate_fixture_graph":
            if event == "call":
                counts["stack"].append(0)
            elif event == "return":
                visits = counts["stack"].pop()
                counts["maximum_visits"] = max(counts["maximum_visits"], visits)
        elif name == "_resolve_fixture_definition" and event == "call" and counts["stack"]:
            counts["stack"][-1] += 1
            assert counts["stack"][-1] <= BUDGET, "fixture graph repeats equivalent selection states"
        elif name == "_fixture_view" and event == "return":
            views = len(frame.f_locals["self"].fixture_selections)
            counts["maximum_views"] = max(counts["maximum_views"], views)
            assert views <= BUDGET, "fixture views retain per-path duplicates"
    prior = sys.getprofile()
    sys.setprofile(profile)
    try:
        yield
    finally:
        sys.setprofile(prior)
'''.replace("DEFINITION_COUNT", str(definitions))
    body = '''
def test_probe(root, request, monkeypatch):
    counts = request.config._r23_counts
    assert counts["maximum_visits"] > 0
    assert counts["maximum_views"] > 0
    with monkeypatch.context() as owned:
        owned.setattr(root, "open", lambda: None, raising=False)
    assert not hasattr(root, "open")
'''
    code, output = _session(tmp_path, body, extra=fixture, files={"conftest.py": plugin},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Selected graph leaf.'}\n",
        options=("--import-mode=" + import_mode,), child_timeout=60)
    assert code == 0, output
    assert "1 passed" in output, output
    assert "permits a missing target" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("decorator", ["patch-dict", "patch-object", "patch-string", "wraps",
                                       "two-level", "bound-inner", "bound-root", "plain"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r23_decorated_fixture_receipt_uses_implementation_source(tmp_path, decorator, import_mode):
    support = '''
from functools import wraps
from types import SimpleNamespace
target = SimpleNamespace(value=1)
def decorate(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)
    return wrapper
'''
    fixture = '''
import pytest
from types import ModuleType
from unittest.mock import patch
from decorator_support import decorate, target
DECORATORS
def tool(monkeypatch):
    tool = ModuleType("consumer")
    monkeypatch.setattr(tool, "open", lambda: "owned", raising=False)
    return tool
'''
    decorators = {
        "patch-dict": '@pytest.fixture\n@patch.dict({}, {})',
        "patch-object": '@pytest.fixture\n@patch.object(target, "value", 2)',
        "patch-string": '@pytest.fixture\n@patch("decorator_support.target.value", 2)',
        "wraps": '@pytest.fixture\n@decorate',
        "two-level": '@pytest.fixture\n@decorate\n@patch.dict({}, {})',
        "plain": '@pytest.fixture',
    }
    if decorator.startswith("bound-"):
        fixture = '''
import pytest
from types import ModuleType
from decorator_support import decorate
class Provider:
    def implementation(self, monkeypatch):
        tool = ModuleType("consumer")
        monkeypatch.setattr(tool, "open", lambda: "owned", raising=False)
        return tool
tool = pytest.fixture(name="tool")(FACTORY)
'''.replace("FACTORY", "decorate(Provider().implementation)" if decorator == "bound-inner"
            else "Provider().implementation")
    else:
        fixture = fixture.replace("DECORATORS", decorators[decorator])
    code, output = _session(tmp_path, "def test_placeholder(): pass\n",
        files={"decorator_support.py": support, "tests/sub/conftest.py": fixture,
               "tests/sub/test_decorated.py":
                   'def test_a(tool):\n    assert tool.open() == "owned"\n'},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/sub/conftest.py', 'tool.open'): 'Fixture implementation.'}\n",
        options=("tests/sub/test_decorated.py", "--import-mode=" + import_mode))
    assert code == 0, output
    assert "2 passed" in output, output
    assert "permits a missing target" not in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("shape", ["self-cycle", "two-cycle", "none", "unsupported",
                                   "depth-32", "depth-33", "depth-256"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r23_incomplete_fixture_wrapper_chains_refuse_without_looping(tmp_path, shape, import_mode):
    fixture = '''
import pytest
from types import ModuleType
@pytest.fixture
def tool(monkeypatch, request):
    tool = ModuleType("consumer")
    monkeypatch.setattr(tool, "open", lambda: "owned", raising=False)
    # Mutate this owned callable only after pytest has collected its signature.
    callback = request._fixturedef.func
    def leaf(): pass
    if SHAPE == "self-cycle":
        callback.__wrapped__ = callback
    elif SHAPE == "two-cycle":
        callback.__wrapped__ = leaf
        leaf.__wrapped__ = callback
    elif SHAPE == "none":
        callback.__wrapped__ = None
    elif SHAPE == "unsupported":
        callback.__wrapped__ = object()
    else:
        count = int(SHAPE.split("-")[1])
        current = callback
        for _ in range(count - 1):
            def successor(): pass
            current.__wrapped__ = successor
            current = successor
    return tool
'''.replace("SHAPE", repr(shape))
    code, output = _session(tmp_path, "def test_placeholder(): pass\n",
        files={"tests/sub/conftest.py": fixture,
               "tests/sub/test_decorated.py":
                   'def test_a(tool):\n    assert tool.open() == "owned"\n'},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/sub/conftest.py', 'tool.open'): 'Complete fixture implementation.'}\n",
        options=("tests/sub/test_decorated.py", "--import-mode=" + import_mode), child_timeout=60)
    refused = shape != "depth-32"
    assert code == (1 if refused else 0), output
    assert ("permits a missing target" in output) is refused, output
    assert "2 passed" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("scenario", ["sibling-tool", "dynamic-bridge"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_addendum_hidden_definitions_do_not_grant_receipts(tmp_path, scenario, import_mode):
    if scenario == "sibling-tool":
        extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def exposed(): return []
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
@pytest.fixture(scope="session")
def bundle(tool): return tool
@pytest.fixture(scope="session")
def outer(request): return request.getfixturevalue("bundle")
@pytest.fixture
def foreign(exposed): return exposed[0]
'''
        files = {
            "tests/a_consumer.py": "def test_a(outer): pass\n",
            "tests/sub_b/conftest.py": '''
import pytest
from types import ModuleType
@pytest.fixture(scope="session")
def tool(exposed):
    value = ModuleType("consumer")
    exposed.append(value)
    return value
''',
            "tests/sub_b/b_consumer.py": "def test_b(bundle): pass\n",
            "tests/c_consumer.py": '''
def fake(): pass
def test_c(outer, foreign, monkeypatch):
    assert outer is not foreign
    with monkeypatch.context() as owned:
        owned.setattr(foreign, "open", fake, raising=False)
    assert not hasattr(foreign, "open")
''',
        }
        paths = ("tests/a_consumer.py", "tests/sub_b/b_consumer.py", "tests/c_consumer.py")
        policy_path, passed = "tests/c_consumer.py", "4 passed"
    else:
        extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
@pytest.fixture(scope="session")
def bridge(request): return request.getfixturevalue("tool")
@pytest.fixture(scope="session")
def bundle(request): return request.getfixturevalue("bridge")
'''
        files = {
            "tests/a_consumer.py": "def test_a(bundle): pass\n",
            "tests/consumer_b/conftest.py": '''
import pytest
from types import ModuleType
@pytest.fixture(scope="session")
def bridge(): return ModuleType("local_consumer")
''',
            "tests/consumer_b/b_consumer.py": '''
def fake(): pass
def test_b(bundle, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
    assert not hasattr(bundle, "open")
''',
        }
        paths = ("tests/a_consumer.py", "tests/consumer_b/b_consumer.py")
        policy_path, passed = paths[-1], "3 passed"
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra, files=files,
        policy_suffix="\nBUILTIN_GLOBALS = " + repr({
            (policy_path, "tool.open"): "Current selected tool only."}) + "\n",
        options=paths + ("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "permits a missing target" in output, output
    assert passed in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_addendum_invocation_from_tests_keeps_fixture_receipts(tmp_path, import_mode):
    body = '''
def fake(): pass
def test_probe(tool, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(tool, "open", fake, raising=False)
    assert not hasattr(tool, "open")
'''
    code, output = _session(tmp_path, body, extra='''
from types import ModuleType
@pytest.fixture
def tool(): return ModuleType("consumer")
''', policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Selected tool.'}\n",
        options=("--collect-only", "--import-mode=" + import_mode))
    assert code == 0, output
    # Reuse the owned suite, then invoke its public entry point from tests/.
    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["AEGIS_PATCH_GUARD"] = "on"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "test_probe.py", "-q", "-p", "no:cacheprovider",
         "--basetemp", str(tmp_path / "cwd-run"), "--import-mode=" + import_mode],
        cwd=str(tmp_path / "suite/tests"), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "1 passed" in output, output
    assert "permits a missing target" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("shape", ["backslash", "none-line", "both"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_addendum_fallback_item_locations_are_canonical(tmp_path, shape, import_mode):
    plugin = '''
import os
import pytest
from unittest.mock import patch
def fake(): return 7
@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items):
    for item in items:
        path, line, name = item.location
        if SHAPE in ("backslash", "both"):
            path = path.replace("/", chr(92))
        item.location = (path, None if SHAPE in ("none-line", "both") else line, name)
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    yield
    with patch.object(os, "getpid", fake):
        assert os.getpid() == 7
'''.replace("SHAPE", repr(shape))
    code, output = _session(tmp_path, "def test_probe(): pass\n",
        files={"conftest.py": plugin}, limits={"tests/test_probe.py": 1},
        options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "1 passed" in output, output
    assert "shared module patch count" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "TypeError" not in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_addendum_missing_line_survives_repeated_report_leaks(tmp_path, import_mode):
    plugin = '''
import colorsys
import pytest
@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items):
    for item in items:
        path, _, name = item.location
        item.location = (path, None, name)
def pytest_runtest_logreport(report):
    if report.when == "teardown":
        colorsys._r22_report_leak = object()
'''
    code, output = _session(tmp_path, "def test_probe(): pass\n",
        files={"conftest.py": plugin}, options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert "unrestored namespace: colorsys._r22_report_leak" in output, output
    assert "tests/test_probe.py:0:unrestored namespace:colorsys._r22_report_leak" in output, output
    assert "INTERNALERROR" not in output, output
    assert "TypeError" not in output, output


@pytest.mark.parametrize("spelling", ["relative", "absolute"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_addendum_code_filenames_keep_the_original_test_site(tmp_path, spelling, import_mode):
    helper = '''
import os
from pathlib import Path
from unittest.mock import patch
def fake(): return 7
def patch_shared():
    with patch.object(os, "getpid", fake):
        assert os.getpid() == 7
filename = str(Path("tests") / "patch_helper.py") if SPELLING == "relative" else str(Path(__file__))
if os.name == "nt" and SPELLING == "absolute":
    filename = filename[0].swapcase() + filename[1:]
patch_shared.__code__ = patch_shared.__code__.replace(co_filename=filename)
'''.replace("SPELLING", repr(spelling))
    body = '''
import importlib.util
from pathlib import Path
def test_probe():
    spec = importlib.util.spec_from_file_location("r22_owned_helper", Path(__file__).with_name("patch_helper.py"))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.patch_shared()
'''
    code, output = _session(tmp_path, body, files={"tests/patch_helper.py": helper},
        limits={"tests/patch_helper.py": 1}, options=("--import-mode=" + import_mode,))
    assert code == 0, output
    assert "1 passed" in output, output
    assert "shared module patch count" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("site", ["sub-conftest", "test-module"])
@pytest.mark.parametrize("kind", ["monkeypatch", "mock-context", "mock-decorator"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_addendum_selected_fixture_owns_its_patch_site(tmp_path, site, kind, import_mode):
    fixture = '''
import pytest
from types import ModuleType
from unittest.mock import patch
def fake(): return "owned"
@pytest.fixture
def tool(PARAMS):
    tool = ModuleType("consumer")
    OPERATION
    return tool
'''.replace("PARAMS", "monkeypatch" if kind == "monkeypatch" else "")
    if kind == "monkeypatch":
        operation = 'monkeypatch.setattr(tool, "open", fake, raising=False)'
    elif kind == "mock-context":
        operation = 'with patch.object(tool, "open", fake, create=True):\n    assert tool.open() == "owned"'
    else:
        operation = '@patch.object(tool, "open", fake, create=True)\ndef initialize(): assert tool.open() == "owned"\ninitialize()'
    fixture = fixture.replace("    OPERATION", textwrap.indent(operation, "    "))
    body = '''
def test_probe(tool):
    EXPECTATION
'''.replace("    EXPECTATION", '    assert tool.open() == "owned"' if kind == "monkeypatch" else
              '    assert not hasattr(tool, "open")')
    source = "tests/sub/conftest.py" if site == "sub-conftest" else "tests/sub/test_owned_fixture.py"
    files = {"tests/sub/test_owned_fixture.py": body}
    if site == "sub-conftest":
        files[source] = fixture
    else:
        files[source] = fixture + body
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", files=files,
        policy_suffix="\nBUILTIN_GLOBALS = " + repr({(source, "tool.open"): "Fixture-owned patch."}) + "\n",
        options=("tests/sub/test_owned_fixture.py", "--import-mode=" + import_mode))
    assert code == 0, output
    assert "2 passed" in output, output
    assert "permits a missing target" not in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output


def _r22_local_bundle_fixture(depends_tool, *, method=False):
    args = (["self"] if method else []) + (["tool"] if depends_tool else [])
    return '''
@pytest.fixture(scope="session")
def bundle_1(ARGS):
    _r22_local_calls.append("bundle_1")
    return ModuleType("local_consumer")
@pytest.fixture
def local_audit(SELF): return lambda: len(_r22_local_calls)
'''.replace("ARGS", ", ".join(args)).replace("SELF", "self" if method else "")


@pytest.mark.parametrize("site", ["directory", "module", "class"])
@pytest.mark.parametrize("lookup", ["none", "first", "last"])
@pytest.mark.parametrize("depends_tool", [False, True])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_cached_dynamic_edges_follow_current_override(
        tmp_path, site, lookup, depends_tool, import_mode):
    extra = '''
from types import ModuleType
_r22_originals = []
@pytest.fixture(scope="session")
def tool():
    subject = ModuleType("consumer")
    _r22_originals.append(subject)
    return subject
@pytest.fixture(scope="session")
def bundle_1(tool): return tool
@pytest.fixture(scope="session")
def bundle_2(request): return request.getfixturevalue("bundle_1")
@pytest.fixture
def original_subject(): return _r22_originals[0]
'''
    arguments = ["bundle_2", "original_subject", "local_audit", "monkeypatch"]
    if lookup != "none":
        arguments.insert(0 if lookup == "first" else 1, "bundle_1")
    second = '''
def fake(): pass
def test_b(ARGS):
    assert bundle_2 is original_subject
    assert local_audit() == CALLS
    with monkeypatch.context() as owned:
        owned.setattr(bundle_2, "open", fake, raising=False)
        assert bundle_2.open is fake
    assert not hasattr(bundle_2, "open")
'''.replace("ARGS", ", ".join((["self"] if site == "class" else []) + arguments)).replace(
        "CALLS", "0" if lookup == "none" else "1")
    prefix = 'import pytest\nfrom types import ModuleType\n_r22_local_calls = []\n'
    local = _r22_local_bundle_fixture(depends_tool, method=site == "class")
    files = {"tests/a_consumer.py": "def test_a(bundle_2): pass\n"}
    if site == "directory":
        files["tests/consumer_b/conftest.py"] = prefix + local
    elif site == "module":
        second = prefix + local + second
    else:
        # Keep fake in the module so the method uses its ordinary global.
        second = second.replace("def fake(): pass\n", "", 1)
        second = prefix + 'def fake(): pass\nclass TestConsumer:\n' + textwrap.indent(local + second, "    ")
    files["tests/consumer_b/b_consumer.py"] = second
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra, files=files,
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/consumer_b/b_consumer.py', 'tool.open'): 'Selected current tool.'}\n",
        options=("tests/a_consumer.py", "tests/consumer_b/b_consumer.py", "--import-mode=" + import_mode))
    allowed = depends_tool and lookup != "none"
    assert code == (0 if allowed else 1), output
    assert ("permits a missing target" in output) is not allowed, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("kind", ["absent", "no-tool", "with-tool"])
@pytest.mark.parametrize("lookup", ["none", "first", "last"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_cached_execution_does_not_accumulate_sibling_overrides(
        tmp_path, kind, lookup, import_mode):
    extra = '''
from types import ModuleType
_r22_originals = []
@pytest.fixture(scope="session")
def subject():
    value = ModuleType("consumer")
    _r22_originals.append(value)
    return value
@pytest.fixture(scope="session")
def tool(subject): return subject
@pytest.fixture(scope="session")
def bundle_1(subject): return subject
@pytest.fixture(scope="session")
def bundle_2(bundle_1): return bundle_1
@pytest.fixture(scope="session")
def bundle_3(request): return request.getfixturevalue("bundle_2")
@pytest.fixture
def original_subject(): return _r22_originals[0]
'''
    prefix = 'import pytest\nfrom types import ModuleType\n_r22_local_calls = []\n'
    local_b = (_r22_local_bundle_fixture(kind == "with-tool") if kind != "absent" else
               '@pytest.fixture\ndef local_audit(): return lambda: len(_r22_local_calls)\n')
    arguments = ["bundle_3", "original_subject", "local_audit", "monkeypatch"]
    if lookup != "none":
        arguments.insert(0 if lookup == "first" else 1, "bundle_1")
    second = '''
def fake(): pass
def test_b(ARGS):
    assert bundle_3 is original_subject
    assert local_audit() == CALLS
    with monkeypatch.context() as owned:
        owned.setattr(bundle_3, "open", fake, raising=False)
        assert bundle_3.open is fake
    assert not hasattr(bundle_3, "open")
'''.replace("ARGS", ", ".join(arguments)).replace(
        "CALLS", "1" if lookup != "none" and kind != "absent" else "0")
    files = {
        "tests/warm_consumer.py": "def test_warm(bundle_3): pass\n",
        "tests/dir_a/conftest.py": prefix + _r22_local_bundle_fixture(True),
        "tests/dir_a/a_consumer.py": "def test_a(bundle_2, original_subject, local_audit):\n    assert bundle_2 is original_subject\n    assert local_audit() == 1\n",
        "tests/dir_b/conftest.py": prefix + local_b,
        "tests/dir_b/b_consumer.py": second,
    }
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra, files=files,
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/dir_b/b_consumer.py', 'tool.open'): 'Selected current tool.'}\n",
        options=("tests/warm_consumer.py", "tests/dir_a/a_consumer.py",
                 "tests/dir_b/b_consumer.py", "--import-mode=" + import_mode))
    allowed = kind == "with-tool" and lookup != "none"
    assert code == (0 if allowed else 1), output
    assert ("permits a missing target" in output) is not allowed, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "4 passed" in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_unavailable_dynamic_definition_is_not_authority(tmp_path, import_mode):
    extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
@pytest.fixture(scope="session")
def bundle_2(request): return request.getfixturevalue("bundle_1")
'''
    second = '''
def fake(): pass
def test_b(bundle_2, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle_2, "open", fake, raising=False)
    assert not hasattr(bundle_2, "open")
'''
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"tests/dir_a/conftest.py": 'import pytest\n@pytest.fixture(scope="session")\ndef bundle_1(tool): return tool\n',
               "tests/dir_a/a_consumer.py": "def test_a(bundle_2): pass\n",
               "tests/dir_b/b_consumer.py": second},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/dir_b/b_consumer.py', 'tool.open'): 'Selected current tool.'}\n",
        options=("tests/dir_a/a_consumer.py", "tests/dir_b/b_consumer.py", "--import-mode=" + import_mode))
    assert code == 1, output
    assert "permits a missing target" in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("lookup", ["none", "first", "last"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r22_current_request_chain_keeps_an_explicit_super_dependency(tmp_path, lookup, import_mode):
    extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def leaf(): return ModuleType("consumer")
@pytest.fixture(scope="session")
def bundle(request): return request.getfixturevalue("leaf")["subject"]
'''
    local = '''
import pytest
@pytest.fixture(scope="session")
def leaf(leaf): return {"subject": leaf}
'''
    arguments = ["bundle", "monkeypatch"]
    if lookup != "none":
        arguments.insert(0 if lookup == "first" else 1, "leaf")
    second = '''
def fake(): pass
def test_b(ARGS):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
        assert bundle.open is fake
    assert not hasattr(bundle, "open")
'''.replace("ARGS", ", ".join(arguments))
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"tests/consumers/conftest.py": local,
               "tests/consumers/a_consumer.py": "def test_a(bundle): pass\n",
               "tests/consumers/b_consumer.py": second},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/consumers/b_consumer.py', 'leaf.open'): 'Selected super dependency.'}\n",
        options=("tests/consumers/a_consumer.py", "tests/consumers/b_consumer.py", "--import-mode=" + import_mode))
    assert code == 0, output
    assert "permits a missing target" not in output, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "3 passed" in output, output


def _r21_split_fixture_plugin(extra):
    # A root plugin receives session fixture hooks as well as module hooks.
    fixtures, hook = extra.split("@pytest.hookimpl", 1)
    return fixtures, "import pytest\n@pytest.hookimpl" + hook


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r21_post_yield_retrieval_keeps_the_reviewed_dependency(tmp_path, import_mode):
    extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
@pytest.fixture(scope="session")
def bundle(request): return request.getfixturevalue("tool")
@pytest.fixture(scope="session")
def audit(): return None
@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(fixturedef, request):
    yield
    if fixturedef.argname == "bundle":
        request.getfixturevalue("audit")
'''
    second = '''
def fake(): pass
def test_b(bundle, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
        assert bundle.open is fake
    assert not hasattr(bundle, "open")
'''
    extra, plugin = _r21_split_fixture_plugin(extra)
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"conftest.py": plugin, "tests/a_consumer.py": "def test_a(bundle): pass\n", "tests/b_consumer.py": second},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/b_consumer.py', 'tool.open'): 'Selected dynamic dependency.'}\n",
        options=("tests/a_consumer.py", "tests/b_consumer.py", "--import-mode=" + import_mode))
    assert code == 0, output
    assert "permits a missing target" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("retrieval", ["body", "post", "both"])
@pytest.mark.parametrize("intermediate", ["module", "plain"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("registered", [False, True])
def test_r21_execution_edges_survive_all_setup_retrievals(
        tmp_path, cached, retrieval, intermediate, import_mode, registered):
    extra = '''
from types import ModuleType
_subject = ModuleType("consumer")
_calls = []
_seen_before_bridge = []
@pytest.fixture(scope="session")
def tool():
    _calls.append("tool")
    return _subject
@pytest.fixture(scope="session")
def audit(): return None
@pytest.fixture(scope="session")
def bridge(request):
    _seen_before_bridge.append("tool" in _calls)
    if RETRIEVAL in ("body", "both"):
        request.getfixturevalue("tool")
    return _subject if INTERMEDIATE == "module" else object()
@pytest.fixture(scope="session")
def bundle(request):
    request.getfixturevalue("bridge")
    return _subject
@pytest.fixture
def selection_audit():
    return lambda: (tuple(_seen_before_bridge), _calls.count("tool"))
@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(fixturedef, request):
    yield
    if RETRIEVAL in ("post", "both"):
        if fixturedef.argname == "bridge":
            request.getfixturevalue("tool")
        if fixturedef.argname in ("bridge", "bundle"):
            request.getfixturevalue("audit")
'''.replace("RETRIEVAL", repr(retrieval)).replace("INTERMEDIATE", repr(intermediate))
    second = '''
def fake(): pass
def test_b(bundle, selection_audit, monkeypatch):
    assert selection_audit() == ((CACHED,), 1)
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
        assert bundle.open is fake
    assert not hasattr(bundle, "open")
'''.replace("CACHED", repr(cached))
    target = "tool.open" if registered else "unregistered.open"
    extra, plugin = _r21_split_fixture_plugin(extra)
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"conftest.py": plugin, "tests/a_consumer.py": "def test_a(" + ("tool, " if cached else "") + "bundle): pass\n",
               "tests/b_consumer.py": second},
        policy_suffix="\nBUILTIN_GLOBALS = " + repr({
            ("tests/b_consumer.py", target): "Selected setup dependency."}) + "\n",
        options=("tests/a_consumer.py", "tests/b_consumer.py", "--import-mode=" + import_mode))
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("scope", ["session", "module"])
@pytest.mark.parametrize("ending", ["finalized", "failed"])
@pytest.mark.parametrize("intermediate", ["module", "plain"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r21_ended_executions_do_not_authorize_their_replacements(
        tmp_path, scope, ending, intermediate, import_mode):
    extra = '''
from types import ModuleType
_subject = ModuleType("consumer")
@pytest.fixture(scope=SCOPE)
def tool(): return _subject
@pytest.fixture(scope=SCOPE)
def audit(): return None
@pytest.fixture(scope=SCOPE)
def bridge(request):
    request.getfixturevalue("tool")
    return _subject if INTERMEDIATE == "module" else object()
@pytest.fixture(scope=SCOPE)
def bundle(request):
    if request.param == "selected":
        request.getfixturevalue("bridge")
        if ENDING == "failed":
            raise RuntimeError("owned setup failed")
    return _subject
@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(fixturedef, request):
    outcome = yield
    if outcome.excinfo is None and fixturedef.argname == "bundle" and request.param == "selected":
        request.getfixturevalue("audit")
'''.replace("SCOPE", repr(scope)).replace("INTERMEDIATE", repr(intermediate)).replace("ENDING", repr(ending))
    body = '''
import pytest
def fake(): pass
@pytest.mark.parametrize("bundle", ["selected"], indirect=True, scope=SCOPE)
def test_a_selected(bundle, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
    assert not hasattr(bundle, "open")
@pytest.mark.parametrize("bundle", ["hidden"], indirect=True, scope=SCOPE)
def test_b_hidden(bundle, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
    assert not hasattr(bundle, "open")
'''.replace("SCOPE", repr(scope))
    extra, plugin = _r21_split_fixture_plugin(extra)
    code, output = _session(tmp_path, body, extra=extra, files={"conftest.py": plugin},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Selected setup dependency.'}\n",
        options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert output.count(":permits a missing target:consumer.open") == 1, output
    assert "unrestored namespace" not in output, output
    assert "INTERNALERROR" not in output, output
    if ending == "failed":
        assert "RuntimeError: owned setup failed" in output, output
        assert "1 passed" in output and "1 error" in output, output
    else:
        assert "owned setup failed" not in output, output
        assert "2 passed" in output, output


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r21_failed_setup_does_not_authorize_a_cached_consumer(tmp_path, import_mode):
    extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
@pytest.fixture(scope="session")
def bundle(request): return request.getfixturevalue("tool")
@pytest.fixture(scope="session")
def audit(): return None
@pytest.hookimpl(wrapper=True)
def pytest_fixture_setup(fixturedef, request):
    result = yield
    if fixturedef.argname == "bundle":
        request.getfixturevalue("audit")
        raise RuntimeError("owned setup failed")
    return result
'''
    second = '''
def fake(): pass
def test_b(bundle, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
    assert not hasattr(bundle, "open")
'''
    extra, plugin = _r21_split_fixture_plugin(extra)
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"conftest.py": plugin, "tests/a_consumer.py": "def test_a(bundle): pass\n", "tests/b_consumer.py": second},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/b_consumer.py', 'tool.open'): 'Selected setup dependency.'}\n",
        options=("tests/a_consumer.py", "tests/b_consumer.py", "--import-mode=" + import_mode))
    assert code == 1, output
    assert output.count(":permits a missing target:consumer.open") == 1, output
    assert "RuntimeError: owned setup failed" in output, output
    assert "2 passed" in output and "1 error" in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("stage", ["before", "after"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r21_reentered_execution_has_the_fixed_runtime_refusal(tmp_path, stage, import_mode):
    extra = '''
from types import ModuleType
@pytest.fixture
def tool(): return ModuleType("consumer")
@pytest.hookimpl(wrapper=True)
def pytest_fixture_setup(fixturedef, request):
    if STAGE == "before" and fixturedef.argname == "tool":
        request.node.ihook.pytest_fixture_setup(fixturedef=fixturedef, request=request)
    result = yield
    if STAGE == "after" and fixturedef.argname == "tool":
        request.node.ihook.pytest_fixture_setup(fixturedef=fixturedef, request=request)
    return result
'''.replace("STAGE", repr(stage))
    extra, plugin = _r21_split_fixture_plugin(extra)
    code, output = _session(tmp_path, "def test_probe(tool): pass\n", extra=extra,
        files={"conftest.py": plugin},
        options=("--import-mode=" + import_mode,))
    assert code == 4, output
    assert "pytest runtime guard API is unsupported" in output, output
    assert "INTERNALERROR" not in output, output
    assert "RecursionError" not in output, output


@pytest.mark.parametrize("representation", ["legacy", "request-subclass", "unknown"])
def test_r20_installer_accepts_fixture_definition_representations(tmp_path, representation):
    prefix = '''
from types import SimpleNamespace as _OwnedNamespace
_real_pytest = pytest
_real_import_module = import_module
class _OwnedFixtureDef: pass
class _OwnedPseudoFixtureDef: pass
class _OwnedRequestFixtureDef(_OwnedFixtureDef): pass
class _OwnedUnknownDef: pass
_selected_type = {"legacy": _OwnedPseudoFixtureDef,
                  "request-subclass": _OwnedRequestFixtureDef,
                  "unknown": _OwnedUnknownDef}[REPRESENTATION]
_selected_definition = _selected_type()
_selected_definition.cached_result = ("owned fixture value", None, None)
_fixture_api_view = _OwnedNamespace(FixtureDef=_OwnedFixtureDef)
if REPRESENTATION != "request-subclass":
    _fixture_api_view.PseudoFixtureDef = _OwnedPseudoFixtureDef
class _OwnedFixtureRequest:
    getfixturevalue = _real_pytest.FixtureRequest.getfixturevalue
    def _get_active_fixturedef(self, argname):
        return _selected_definition
# Only this copied conftest's lookup references change. Neither pytest nor
# _pytest.fixtures has any attribute replaced.
pytest = _OwnedNamespace(**{**vars(_real_pytest), "FixtureRequest": _OwnedFixtureRequest})
def import_module(name, package=None):
    return _fixture_api_view if name == "_pytest.fixtures" else _real_import_module(name, package)
@pytest.fixture
def owned_request(): return _OwnedFixtureRequest()
'''.replace("REPRESENTATION", repr(representation))
    code, output = _session(tmp_path, '''
def test_probe(owned_request):
    assert owned_request.getfixturevalue("owned") == "owned fixture value"
''', plugin_prefix=prefix)
    accepted = representation != "unknown"
    assert code == (0 if accepted else 4), output
    assert ("pytest runtime guard API is unsupported" in output) is not accepted, output
    assert "INTERNALERROR" not in output, output
    if accepted:
        assert "1 passed" in output, output




@pytest.mark.parametrize("scope", ["session", "module"])
@pytest.mark.parametrize("order", ["AB", "BA"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("registered", [False, True])
def test_r20_cached_dynamic_edges_follow_the_fixture_cache(tmp_path, scope, order, import_mode, registered):
    extra = '''
from types import ModuleType
@pytest.fixture(scope=SCOPE)
def tool(): return ModuleType("consumer")
@pytest.fixture(scope=SCOPE)
def bundle(request): return request.getfixturevalue("tool")
'''.replace("SCOPE", repr(scope))
    second = '''
def fake(): pass
def test_b(bundle, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
        assert bundle.open is fake
    assert not hasattr(bundle, "open")
'''
    # Different modules have distinct module caches; warm B's cache locally too.
    if scope == "module":
        second = "def test_a_warm(bundle): pass\n" + second
    paths = {"A": "tests/a_consumer.py", "B": "tests/b_consumer.py"}
    target = "tool.open" if registered else "unregistered.open"
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={paths["A"]: "def test_a(bundle): pass\n", paths["B"]: second},
        policy_suffix="\nBUILTIN_GLOBALS = " + repr({
            (paths["B"], target): "Selected dynamic dependency."}) + "\n",
        options=tuple(paths[name] for name in order) + ("--import-mode=" + import_mode,))
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert ("3 passed" if scope == "session" else "4 passed") in output, output


@pytest.mark.parametrize("scope", ["session", "module"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r20_dynamic_edges_expire_with_the_cached_result(tmp_path, scope, import_mode):
    extra = '''
from types import ModuleType
_retained_tool = []
@pytest.fixture(scope=SCOPE)
def tool():
    subject = ModuleType("consumer")
    _retained_tool.append(subject)
    return subject
@pytest.fixture(scope=SCOPE)
def bundle(request):
    if request.param == "selected":
        return request.getfixturevalue("tool")
    return _retained_tool[0]
'''.replace("SCOPE", repr(scope))
    body = '''
import pytest
def fake(): pass
@pytest.mark.parametrize("bundle", ["selected", "hidden"], indirect=True, scope=SCOPE)
def test_probe(bundle, monkeypatch):
    with monkeypatch.context() as owned:
        owned.setattr(bundle, "open", fake, raising=False)
        assert bundle.open is fake
    assert not hasattr(bundle, "open")
'''.replace("SCOPE", repr(scope))
    code, output = _session(tmp_path, body, extra=extra,
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Selected dynamic dependency.'}\n",
        options=("--import-mode=" + import_mode,))
    assert code == 1, output
    assert output.count(":permits a missing target:consumer.open") == 1, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


def _r19_operation(shape, form):
    if shape != "expanded" and form != "start":
        return _r18_operation(shape, form)
    setter = {
        "positional": 'subject, "open", fake, False',
        "keyword": 'target=subject, name="open", value=fake, raising=False',
        "mixed": 'subject, name="open", value=fake, raising=False',
        "expanded": '*[subject, "open", fake], **{"raising": False}',
    }
    arguments = {
        "positional": 'subject, "open", fake, None, True',
        "keyword": 'target=subject, attribute="open", new=fake, create=True',
        "mixed": 'subject, attribute="open", new=fake, create=True',
        "expanded": '*[subject, "open"], **{"new": fake, "create": True}',
    }
    constructor = "patch.object(" + arguments[shape] + ")"
    if form == "setattr":
        return ('with monkeypatch.context() as owned:\n    owned.setattr(' + setter[shape] +
                ')\n    assert subject.open is fake')
    if form == "start":
        return ('patcher = ' + constructor + '\npatcher.start()\ntry:\n' +
                '    assert subject.open is fake\nfinally:\n    patcher.stop()')
    if form in {"context", "copy"}:
        return ('patcher = ' + constructor + '\nwith ' +
                ('patcher.copy()' if form == "copy" else 'patcher') +
                ':\n    assert subject.open is fake')
    if form == "function":
        return '@' + constructor + '\ndef invoke(): assert subject.open is fake\ninvoke()'
    return ('@' + constructor + '\nclass Probe:\n' +
            '    def test_invoke(self): assert subject.open is fake\nProbe().test_invoke()')


def _r19_chain_session(tmp_path, *, scope, depth, import_mode, overridden, registered,
                       retrieval="dynamic", shape="keyword", form="setattr",
                       container=False, cut=False, expect_original=False, alias=False):
    extra = '''
from types import ModuleType
_r19_created = []
_r19_originals = []
_r19_foreign = ModuleType("consumer")
@pytest.fixture(scope=SCOPE)
def tool():
    _r19_created.append("tool")
    subject = ModuleType("consumer")
    _r19_originals.append(subject)
    return subject
@pytest.fixture
def foreign(): return _r19_foreign
@pytest.fixture
def original_tool(): return _r19_originals[-1]
@pytest.fixture
def construction_audit(): return lambda: tuple(_r19_created)
@pytest.fixture
def override_audit(): return lambda: ()
'''.replace("SCOPE", repr(scope))
    for index in range(1, depth + 1):
        dependency = "tool" if index == 1 else "bundle_" + str(index - 1)
        result = '{"tool": tool}' if container and index == 1 else dependency
        extra += ('\n@pytest.fixture(scope=' + repr(scope) + ')\ndef bundle_' + str(index) +
                  '(' + dependency + '):\n    _r19_created.append("bundle_' + str(index) +
                  '")\n    return ' + result + '\n')
    top = "bundle_" + str(depth)
    if alias:
        assert depth == 1 and not overridden
        extra = extra.replace("bundle_1", "alias")
        top = "alias"
    first = 'def test_first(' + top + '): pass\n'
    if scope == "class":
        first = "class TestFirst:\n    " + first.replace("(", "(self, ", 1)
    second = '''
from unittest.mock import patch
warmed = []
def fake(): pass
def test_a_warm(TOP, construction_audit, override_audit):
    warmed.append((TOP, construction_audit(), override_audit()))
def test_b(ARGS):
    result = RETRIEVAL
    assert result is warmed[0][0]
    assert (construction_audit(), override_audit()) == warmed[0][1:]
    if EXPECT_ORIGINAL:
        assert result is original_tool
    subject = result["tool"] if CONTAINER else result
    if not REGISTERED:
        subject = foreign
    OPERATION
    assert not hasattr(subject, "open")
'''.replace("TOP", top).replace("ARGS", "request, monkeypatch, foreign, original_tool, construction_audit, override_audit" +
        (", " + top if retrieval == "static" else "")).replace(
        "RETRIEVAL", top if retrieval == "static" else 'request.getfixturevalue("' + top + '")').replace(
        "EXPECT_ORIGINAL", repr(expect_original)).replace("CONTAINER", repr(container)).replace(
        "REGISTERED", repr(registered)).replace(
        "    OPERATION", textwrap.indent(_r19_operation(shape, form), "    "))
    if scope == "class":
        header, methods = second.split("def test_a_warm", 1)
        methods = "def test_a_warm" + methods
        methods = methods.replace("def test_a_warm(", "def test_a_warm(self, ", 1).replace(
            "def test_b(", "def test_b(self, ", 1)
        second = header + "\nclass TestConsumer:\n" + textwrap.indent(methods, "    ")
    files = {"tests/a_consumer.py": first, "tests/consumer_b/b_consumer.py": textwrap.dedent(second)}
    if overridden:
        middle = "bundle_" + str((depth + 1) // 2)
        arguments = "" if cut else "tool"
        result = 'ModuleType("consumer")' if cut else ('{"tool": tool}' if container else "tool")
        files["tests/consumer_b/conftest.py"] = '''
from types import ModuleType
import pytest
_created = []
@pytest.fixture(scope=SCOPE)
def MIDDLE(ARGUMENTS):
    _created.append("override")
    return RESULT
@pytest.fixture
def override_audit(): return lambda: tuple(_created)
'''.replace("SCOPE", repr(scope)).replace("MIDDLE", middle).replace("ARGUMENTS", arguments).replace("RESULT", result)
    return _session(tmp_path, "def test_placeholder(): pass\n", extra=extra, files=files,
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/consumer_b/b_consumer.py', 'tool.open'): 'Selected transitive fixture owner.'}\n",
        options=("tests/a_consumer.py", "tests/consumer_b/b_consumer.py", "--import-mode=" + import_mode))


def _r19_assert_result(code, output, allowed):
    assert code == (0 if allowed else 1), output
    assert ("permits a missing target" in output) is not allowed, output
    assert "unrestored namespace" not in output, output
    assert "4 passed" in output, output


@pytest.mark.parametrize("depth", [1, 2, 3])
@pytest.mark.parametrize("scope", ["session", "module", "class"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("overridden", [False, True])
@pytest.mark.parametrize("registered", [False, True])
def test_r19_cached_selected_graph_activates_transitive_owners(tmp_path, depth, scope, import_mode, overridden, registered):
    code, output = _r19_chain_session(tmp_path, scope=scope, depth=depth, import_mode=import_mode,
        overridden=overridden, registered=registered)
    _r19_assert_result(code, output, registered)


@pytest.mark.parametrize("depth", [1, 2, 3])
@pytest.mark.parametrize("scope", ["session", "module", "class"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("registered", [False, True])
def test_r19_static_setup_uses_the_selected_cached_graph(tmp_path, depth, scope, import_mode, registered):
    code, output = _r19_chain_session(tmp_path, scope=scope, depth=depth, import_mode=import_mode,
        overridden=True, registered=registered, retrieval="static", form="context")
    _r19_assert_result(code, output, registered)


@pytest.mark.parametrize("shape", ["positional", "keyword", "mixed", "expanded"])
@pytest.mark.parametrize("form", ["setattr", "context", "start", "copy", "function", "class"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("registered", [False, True])
def test_r19_cached_graph_keeps_all_patch_forms(tmp_path, shape, form, import_mode, registered):
    code, output = _r19_chain_session(tmp_path, scope="session", depth=3, import_mode=import_mode,
        overridden=False, registered=registered, shape=shape, form=form)
    _r19_assert_result(code, output, registered)


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("registered", [False, True])
def test_r19_nonmodule_intermediates_keep_the_selected_dependency_graph(tmp_path, import_mode, registered):
    code, output = _r19_chain_session(tmp_path, scope="session", depth=3, import_mode=import_mode,
        overridden=True, registered=registered, container=True)
    _r19_assert_result(code, output, registered)


@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("cut", [False, True])
def test_r19_intermediate_override_does_not_activate_hidden_parent_dependencies(tmp_path, import_mode, cut):
    code, output = _r19_chain_session(tmp_path, scope="session", depth=2, import_mode=import_mode,
        overridden=True, registered=True, cut=cut, expect_original=True)
    _r19_assert_result(code, output, not cut)



@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("registered", [False, True])
def test_r19_cached_alias_activates_the_selected_tool_receipt(tmp_path, import_mode, registered):
    code, output = _r19_chain_session(tmp_path, scope="session", depth=1, import_mode=import_mode,
        overridden=False, registered=registered, alias=True)
    _r19_assert_result(code, output, registered)


def test_r19_unsupported_selected_definition_api_has_the_fixed_refusal(tmp_path):
    code, output = _session(tmp_path, "def test_probe(): pass\n",
        plugin_prefix="\npytest.FixtureRequest._get_active_fixturedef = None\n")
    assert code == 4, output
    assert "pytest runtime guard API is unsupported" in output, output
    assert "INTERNALERROR" not in output, output




@pytest.mark.parametrize("kind", ["none", "opaque"])
def test_r19_invalid_selected_definition_uses_the_fixed_refusal(tmp_path, kind):
    result = "None" if kind == "none" else "object()"
    prefix = ("\ndef unsupported_selection(self, argname): return " + result +
              "\npytest.FixtureRequest._get_active_fixturedef = unsupported_selection\n")
    code, output = _session(tmp_path, "def test_probe(): pass\n", plugin_prefix=prefix)
    assert code == 4, output
    assert "pytest runtime guard API is unsupported" in output, output
    assert "INTERNALERROR" not in output, output
    assert "AttributeError" not in output, output



@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r19_selected_graph_accepts_string_subclass_fixture_names(tmp_path, import_mode):
    extra = '''
from types import ModuleType
class FixtureName(str): pass
@pytest.fixture(scope="session", name=FixtureName("tool"))
def make_tool(): return ModuleType("consumer")
@pytest.fixture(scope="session")
def alias(tool): return tool
'''
    second = '''
def fake(): pass
def test_second(request, monkeypatch):
    subject = request.getfixturevalue("alias")
    with monkeypatch.context() as owned:
        owned.setattr(subject, "open", fake, raising=False)
        assert subject.open is fake
    assert not hasattr(subject, "open")
'''
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"tests/a_named.py": "def test_first(alias): pass\n",
               "tests/b_named.py": textwrap.dedent(second)},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/b_named.py', 'tool.open'): 'Selected named fixture.'}\n",
        options=("tests/a_named.py", "tests/b_named.py", "--import-mode=" + import_mode))
    assert code == 0, output
    assert "permits a missing target" not in output, output
    assert "3 passed" in output, output


def _r18_operation(shape, form):
    arguments = {
        "positional": 'subject, "open", fake, False',
        "keyword": 'target=subject, name="open", value=fake, raising=False',
        "mixed": 'subject, name="open", value=fake, raising=False',
    }
    mock_arguments = {
        "positional": 'subject, "open", fake, None, True',
        "keyword": 'target=subject, attribute="open", new=fake, create=True',
        "mixed": 'subject, attribute="open", new=fake, create=True',
    }
    constructor = "patch.object(" + mock_arguments[shape] + ")"
    if form == "setattr":
        return ('with monkeypatch.context() as owned:\n    owned.setattr(' + arguments[shape] +
                ')\n    assert subject.open is fake')
    if form in {"context", "copy"}:
        return ('patcher = ' + constructor + '\nwith ' +
                ('patcher.copy()' if form == "copy" else 'patcher') +
                ':\n    assert subject.open is fake')
    if form == "function":
        return '@' + constructor + '\ndef invoke(): assert subject.open is fake\ninvoke()'
    return ('@' + constructor + '\nclass Probe:\n' +
            '    def test_invoke(self): assert subject.open is fake\nProbe().test_invoke()')


@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("retrieval", ["test", "dependency"])
@pytest.mark.parametrize("shape", ["positional", "keyword", "mixed"])
@pytest.mark.parametrize("form", ["setattr", "context", "copy", "function", "class"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r18_cached_dynamic_fixture_uses_the_retrieved_owner(tmp_path, import_mode, registered, retrieval, shape, form):
    extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
'''
    second = '''
from unittest.mock import patch
import pytest
def fake(): pass
@pytest.fixture
def alias(request): return request.getfixturevalue("tool")
def test_second(REQUEST, monkeypatch):
    subject = RETRIEVAL
    OPERATION
    assert not hasattr(subject, "open")
'''.replace("REQUEST", "request" if retrieval == "test" else "alias").replace(
        "RETRIEVAL", 'request.getfixturevalue("tool")' if retrieval == "test" else "alias").replace(
        "    OPERATION", textwrap.indent(_r18_operation(shape, form), "    "))
    target = "tool.open" if registered else "unregistered.open"
    suffix = "\nBUILTIN_GLOBALS = " + repr({("tests/b_consumer.py", target): "Retrieved fixture result."}) + "\n"
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"tests/a_consumer.py": 'def test_first(tool): assert not hasattr(tool, "open")\n',
               "tests/b_consumer.py": textwrap.dedent(second)},
        policy_suffix=suffix, options=("tests/a_consumer.py", "tests/b_consumer.py", "--import-mode=" + import_mode))
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("order", ["tool, foreign", "foreign, tool"])
@pytest.mark.parametrize("form", ["setattr", "context", "copy", "function", "class"])
@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
def test_r18_hidden_parent_fixture_is_not_the_selected_consumer(tmp_path, import_mode, selected, order, form):
    extra = '''
from types import ModuleType
held = []
@pytest.fixture(scope="session")
def tool():
    subject = ModuleType("consumer")
    held.append(subject)
    return subject
@pytest.fixture
def foreign(): return held[0]
'''
    second = '''
from types import ModuleType
from unittest.mock import patch
import pytest
def fake(): pass
@pytest.fixture
def tool(): return ModuleType("consumer")
def test_second(ORDER, monkeypatch):
    assert tool is not foreign
    subject = tool if SELECTED else foreign
    OPERATION
    assert not hasattr(tool, "open")
    assert not hasattr(foreign, "open")
'''.replace("ORDER", order).replace("SELECTED", repr(selected)).replace(
        "    OPERATION", textwrap.indent(_r18_operation("mixed", form), "    "))
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"tests/a_consumer.py": 'def test_first(tool): assert not hasattr(tool, "open")\n',
               "tests/b_consumer.py": textwrap.dedent(second)},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/b_consumer.py', 'tool.open'): 'Selected override only.'}\n",
        options=("tests/a_consumer.py", "tests/b_consumer.py", "--import-mode=" + import_mode))
    assert code == (0 if selected else 1), output
    assert ("permits a missing target" in output) is not selected, output
    assert "unrestored namespace" not in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("retrieved", [False, True])
@pytest.mark.parametrize("form", ["setattr", "context"])
def test_r18_fixture_receipts_require_retrieval_for_each_item(tmp_path, retrieved, form):
    code, output = _session(tmp_path, '''
from types import ModuleType
from unittest.mock import patch
import pytest
held = []
def fake(): pass
@pytest.fixture(scope="session")
def tool():
    subject = ModuleType("consumer")
    held.append(subject)
    return subject
@pytest.fixture
def foreign(): return held[0]
def test_a(tool): assert not hasattr(tool, "open")
def test_b(request, foreign, monkeypatch):
    if RETRIEVED:
        assert request.getfixturevalue("tool") is foreign
    subject = foreign
    OPERATION
    assert not hasattr(subject, "open")
'''.replace("RETRIEVED", repr(retrieved)).replace(
        "    OPERATION", textwrap.indent(_r18_operation("keyword", form), "    ")),
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Current item retrieval only.'}\n")
    assert code == (0 if retrieved else 1), output
    assert ("permits a missing target" in output) is not retrieved, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("form", ["setattr", "context"])
def test_r18_explicit_override_parent_request_keeps_the_selected_chain(tmp_path, form):
    extra = '''
from types import ModuleType
held = []
@pytest.fixture(scope="session")
def tool():
    subject = ModuleType("consumer")
    held.append(subject)
    return subject
@pytest.fixture
def foreign(): return held[0]
'''
    second = '''
from types import ModuleType
from unittest.mock import patch
import pytest
def fake(): pass
@pytest.fixture
def tool(request, monkeypatch):
    subject = request.getfixturevalue("tool")
    OPERATION
    assert not hasattr(subject, "open")
    return ModuleType("override")
def test_second(tool, foreign):
    assert tool is not foreign
    assert not hasattr(foreign, "open")
'''.replace("    OPERATION", textwrap.indent(_r18_operation("keyword", form), "    "))
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"tests/a_consumer.py": "def test_first(tool): pass\n",
               "tests/b_consumer.py": textwrap.dedent(second)},
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/b_consumer.py', 'tool.open'): 'Actually retrieved parent in override request.'}\n",
        options=("tests/a_consumer.py", "tests/b_consumer.py"))
    assert code == 0, output
    assert "3 passed" in output, output


def test_r18_unsupported_fixture_retrieval_api_has_the_fixed_refusal(tmp_path):
    code, output = _session(tmp_path, "def test_probe(): pass\n",
        plugin_prefix="\npytest.FixtureRequest.getfixturevalue = None\n")
    assert code == 4, output
    assert "pytest runtime guard API is unsupported" in output, output
    assert "INTERNALERROR" not in output, output




@pytest.mark.parametrize("import_mode", ["prepend", "importlib"])
@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("shape", ["positional", "keyword", "mixed"])
@pytest.mark.parametrize("form", ["setattr", "context", "copy", "function", "class"])
def test_r18_authenticated_initializer_publishes_consumer_receipts(tmp_path, import_mode, registered, shape, form):
    body = '''
from types import ModuleType
from unittest.mock import patch
tool = ModuleType("consumer")
def fake(): pass
def test_a(monkeypatch):
    subject = tool if REGISTERED else ModuleType("consumer")
    OPERATION
    assert not hasattr(subject, "open")
def test_b_retry(): assert not hasattr(tool, "open")
'''.replace("REGISTERED", repr(registered)).replace(
        "    OPERATION", textwrap.indent(_r18_operation(shape, form), "    "))
    code, output = _session(tmp_path, body,
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Authenticated initializer result.'}\n",
        options=("--import-mode=" + import_mode,))
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("source", ["module", "loader"])
@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("shape", ["positional", "keyword", "mixed", "computed", "helper"])
@pytest.mark.parametrize("form", ["setattr", "context", "copy", "function", "class"])
def test_r17_consumer_call_shapes_keep_the_construction_receipt(tmp_path, source, registered, shape, form):
    setter_arguments = {
        "positional": 'tool, "open", track_open, False',
        "keyword": 'target=tool, name="open", value=track_open, raising=False',
        "mixed": 'tool, name="open", value=track_open, raising=False',
        "computed": 'target=tool, name=attribute, value=track_open, raising=False',
        "helper": 'target=subject, name="open", value=track_open, raising=False',
    }
    mock_arguments = {
        "positional": 'tool, "open", track_open, None, True',
        "keyword": 'target=tool, attribute="open", new=track_open, create=True',
        "mixed": 'tool, attribute="open", new=track_open, create=True',
        "computed": 'target=tool, attribute=attribute, new=track_open, create=True',
        "helper": 'target=subject, attribute="open", new=track_open, create=True',
    }
    constructor = "patch.object(" + mock_arguments[shape] + ")"
    prefix = ""
    if shape == "helper" and form != "setattr":
        prefix = "def make(subject): return " + constructor + "\n"
        constructor = "make(tool)"
    if form == "setattr":
        if shape == "helper":
            prefix = 'def install(subject, patcher): patcher.setattr(' + setter_arguments[shape] + ')\n'
            call = 'install(tool, owned)'
        else:
            call = 'owned.setattr(' + setter_arguments[shape] + ')'
        operation = ('with monkeypatch.context() as owned:\n    ' + call + '\n'
                     '    assert tool.open() == "tracked"')
    elif form in {"context", "copy"}:
        operation = ('patcher = ' + constructor + '\n'
                     'with ' + ('patcher.copy()' if form == "copy" else 'patcher') + ':\n'
                     '    assert tool.open() == "tracked"')
    elif form == "function":
        operation = ('@' + constructor + '\n'
                     'def invoke(): assert tool.open() == "tracked"\n'
                     'invoke()')
    else:
        operation = ('@' + constructor + '\n'
                     'class Probe:\n'
                     '    def test_invoke(self): assert tool.open() == "tracked"\n'
                     'Probe().test_invoke()')
    body = '''
import importlib.util
from types import ModuleType
from unittest.mock import patch
import pytest
held = []
def track_open(): return "tracked"
@pytest.fixture
def tool():
    if SOURCE == "module":
        owner = ModuleType("consumer")
    else:
        spec = importlib.util.spec_from_file_location("owned_r17_consumer", "owned_r17_consumer.py")
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
    held.append(owner)
    return owner
def test_a(tool, monkeypatch):
    if not REGISTERED:
        tool = ModuleType("consumer")
    attribute = "o" + "pen"
    OPERATION
    assert not hasattr(tool, "open")
def test_b_retry(): assert not hasattr(held[0], "open")
'''.replace("SOURCE", repr(source)).replace("REGISTERED", repr(registered)).replace(
        "    OPERATION", textwrap.indent(prefix + operation, "    "))
    suffix = "\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Owned uncached consumer lookup.'}\n"
    code, output = _session(tmp_path, body, policy_suffix=suffix,
                            files={"owned_r17_consumer.py": "VALUE = 1\n"})
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("shape", ["positional", "keyword", "mixed"])
def test_r17_noncreating_deletion_keeps_all_public_call_shapes(tmp_path, shape):
    arguments = {
        "positional": 'tool, "open", False',
        "keyword": 'target=tool, name="open", raising=False',
        "mixed": 'tool, name="open", raising=False',
    }
    code, output = _session(tmp_path, '''
from types import ModuleType
tool = ModuleType("consumer")
original = tool.open = object()
def test_a(monkeypatch):
    with monkeypatch.context() as owned:
        owned.delattr(ARGUMENTS)
        assert not hasattr(tool, "open")
    assert tool.open is original
def test_b_retry(): assert tool.open is original
'''.replace("ARGUMENTS", arguments[shape]))
    assert code == 0, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("api", ["setattr", "mock"])
@pytest.mark.parametrize("shape", ["starred", "mapping"])
@pytest.mark.parametrize("registered", [False, True])
def test_r17_expanded_arguments_keep_observed_consumer_ownership(tmp_path, api, shape, registered):
    setter = ('owned.setattr(subject, "open", *(track_open, False))' if shape == "starred" else
              'owned.setattr(subject, "open", track_open, **{"raising": False})')
    constructor = ('patch.object(subject, "open", *(track_open, None, True))' if shape == "starred" else
                   'patch.object(subject, "open", track_open, **{"create": True})')
    operation = ('with monkeypatch.context() as owned:\n    ' + setter if api == "setattr" else
                 'with ' + constructor + ': pass')
    code, output = _session(tmp_path, '''
from types import ModuleType
from unittest.mock import patch
tool = ModuleType("consumer")
def track_open(): return "tracked"
def test_a(monkeypatch):
    subject = tool if REGISTERED else ModuleType("consumer")
    OPERATION
    assert not hasattr(subject, "open")
def test_b_retry(): assert not hasattr(tool, "open")
'''.replace("REGISTERED", repr(registered)).replace("    OPERATION", textwrap.indent(operation, "    ")),
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Owned consumer lookup.'}\n")
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("leaked", [False, True])
def test_r17_fixture_output_authenticates_its_earlier_patch_without_hiding_leaks(tmp_path, leaked):
    code, output = _session(tmp_path, '''
from types import ModuleType
from unittest.mock import patch
import pytest
held = []
def fake(): return "tracked"
@pytest.fixture
def tool():
    subject = ModuleType("consumer")
    held.append(subject)
    patcher = patch.object(target=subject, attribute="open", new=fake, create=True)
    patcher.start()
    yield subject
    if not LEAKED:
        patcher.stop()
def test_a(tool): assert tool.open() == "tracked"
def test_b_retry():
    assert not hasattr(held[0], "open")
    if LEAKED:
        with pytest.raises(AttributeError):
            patch.stopall()
    else:
        patch.stopall()
'''.replace("LEAKED", repr(leaked)),
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Owned fixture result.'}\n")
    assert code == (1 if leaked else 0), output
    assert "permits a missing target" not in output, output
    assert ("unrestored namespace" in output) is leaked, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("api", ["setattr", "mock"])
def test_r17_fixture_spelling_cannot_authorize_a_canonical_foreign_module(tmp_path, api):
    operation = ('with monkeypatch.context() as owned:\n    owned.setattr(target=tool, name=attribute, value=fake, raising=False)'
                 if api == "setattr" else
                 'with patch.object(target=tool, attribute=attribute, new=fake, create=True): pass')
    code, output = _session(tmp_path, '''
from unittest.mock import patch
import pytest
def fake(): pass
@pytest.fixture
def tool():
    import json
    return json
def test_a(tool, monkeypatch):
    attribute = "o" + "pen"
    OPERATION
    assert not hasattr(tool, "open")
def test_b_retry():
    import json
    assert not hasattr(json, "open")
'''.replace("    OPERATION", textwrap.indent(operation, "    ")),
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Owned uncached fixture result only.'}\n")
    assert code == 1, output
    assert "permits a missing target" in output, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("registered", [False, True])
def test_r17_cached_fixture_receipt_is_scoped_to_each_consumer_file(tmp_path, registered):
    extra = '''
from types import ModuleType
@pytest.fixture(scope="session")
def tool(): return ModuleType("consumer")
'''
    first = 'def test_first(tool): assert not hasattr(tool, "open")\n'
    second = '''
def fake(): return "tracked"
def install(subject, patcher):
    name = "o" + "pen"
    patcher.setattr(target=subject, name=name, value=fake, raising=False)
def test_second(tool, monkeypatch):
    with monkeypatch.context() as owned:
        install(tool, owned)
        assert tool.open() == "tracked"
    assert not hasattr(tool, "open")
'''
    target = "tool.open" if registered else "unregistered.open"
    suffix = "\nBUILTIN_GLOBALS = " + repr({("tests/b_consumer.py", target): "Scoped cached fixture result."}) + "\n"
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", extra=extra,
        files={"tests/a_consumer.py": first, "tests/b_consumer.py": textwrap.dedent(second)},
        policy_suffix=suffix, options=("tests/a_consumer.py", "tests/b_consumer.py"))
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("registered", [False, True])
def test_r17_unhashable_target_metadata_keeps_observed_ownership(tmp_path, registered):
    code, output = _session(tmp_path, '''
from types import ModuleType
import sys
class Target(str):
    __hash__ = None
tool = ModuleType("consumer")
foreign = ModuleType("foreign")
def fake(): pass
def test_a(monkeypatch):
    assert "r17_alias" not in sys.modules
    subject = tool if REGISTERED else foreign
    sys.modules["r17_alias"] = subject
    try:
        with monkeypatch.context() as owned:
            owned.setattr(Target("r17_alias.open"), fake, raising=False)
            assert subject.open is fake
    finally:
        del sys.modules["r17_alias"]
def test_b_retry():
    assert not hasattr(tool, "open")
    assert not hasattr(foreign, "open")
'''.replace("REGISTERED", repr(registered)),
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'tool.open'): 'Observed owned consumer.'}\n")
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


def test_r17_receipts_do_not_extend_an_unregistered_fixture_lifetime(tmp_path):
    code, output = _session(tmp_path, '''
import gc
from types import ModuleType
from weakref import ref
import pytest
references = []
@pytest.fixture
def subject():
    value = ModuleType("unregistered")
    references.append(ref(value))
    return value
def test_a(subject): assert references[0]() is subject
def test_b_retry():
    gc.collect()
    assert references[0]() is None
''')
    assert code == 0, output
    assert "2 passed" in output, output


def _framework_registry(*bindings):
    """Declare synthetic framework state only in the copied child conftest."""
    entries = {binding: "Test-only declared framework state." for binding in bindings}
    return "\n_PATCH_FRAMEWORK_BINDINGS = MappingProxyType({**_PATCH_FRAMEWORK_BINDINGS, **" + repr(entries) + "})\n"


def test_r16_module_decisions_use_one_trusted_map():
    import ast
    tree = ast.parse((ROOT / "tests/conftest.py").read_text(encoding="utf-8"))
    guard = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_PatchGuard")
    allowed = {"_module_map": "Captures the trusted baseline and transports/repairs observed import registries."}
    violations = []
    for method in guard.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(method):
            direct = (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                      and node.value.id == "sys" and node.attr == "modules")
            indirect = (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "getattr" and len(node.args) > 1
                        and isinstance(node.args[0], ast.Name) and node.args[0].id == "sys"
                        and isinstance(node.args[1], ast.Constant) and node.args[1].value == "modules")
            if (direct or indirect) and method.name not in allowed:
                violations.append((method.name, node.lineno))
    assert not violations, violations
    assert any(isinstance(node, ast.FunctionDef) and node.name == "_module_map" for node in guard.body)


@pytest.mark.parametrize("module_owner", [False, True])
def test_r16_uncached_dictionary_owner_retains_only_its_patch_undo(tmp_path, module_owner):
    code, output = _session(tmp_path, '''
from types import ModuleType
from unittest.mock import patch
owner = ModuleType('uncached') if MODULE else None
namespace = vars(owner) if MODULE else {}
namespace['target'] = 1
def test_a():
    patch.dict(namespace, {'target': 2}).start()
    namespace['configuration'] = 2
def test_b_retry():
    assert namespace['target'] == (1 if MODULE else 2)
    assert namespace['configuration'] == 2
'''.replace('MODULE', repr(module_owner)))
    assert code == (1 if module_owner else 0), output
    assert ("unrestored namespace" in output) is module_owner, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("probe", ["get_objects", "get_referrers"])
def test_r16_unavailable_namespace_probe_refuses_only_when_enabled(tmp_path, enabled, probe):
    code, output = _session(tmp_path, "def test_probe(): pass\n",
        plugin_prefix="\nimport gc as owned_gc\ndel owned_gc." + probe + "\n",
        env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (4 if enabled else 0), output
    assert ("pytest runtime guard API is unsupported" in output) is enabled, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("result", ["None", "(object(), 'path')", "(lambda: object(), 'path')"],
                         ids=["missing-pair", "unsupported-getter", "missing-target-capture"])
def test_r16_unsupported_factory_receipts_use_the_fixed_refusal(tmp_path, enabled, result):
    code, output = _session(tmp_path, "def test_probe(): pass\n",
        plugin_prefix="\nimport unittest.mock as owned_mock\nowned_mock._get_target = lambda target: " + result + "\n",
        env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == (4 if enabled else 0), output
    assert ("pytest runtime guard API is unsupported; install a compatible pytest/Python" in output) is enabled, output
    assert "INTERNALERROR" not in output, output


def test_r16_written_owner_requires_a_module_even_with_a_none_registry_entry(tmp_path):
    code, output = _session(tmp_path, '''
import pytest
owner = None
def test_probe(monkeypatch):
    with pytest.raises((AttributeError, TypeError)):
        with monkeypatch.context() as owned:
            owned.setattr(owner, "open", None, raising=False)
''', extra="\nsys.modules['owned_r16_unavailable'] = None\n",
        policy_suffix="\nBUILTIN_GLOBALS = {('tests/test_probe.py', 'owner.open'): 'Owned consumer module only.'}\n")
    assert code == 1, output
    assert "permits a missing target" in output, output
    assert "1 passed" in output, output


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("form", ["string", "object", "preconstructed", "copy", "decorator", "dict"])
@pytest.mark.parametrize("case", ["replaced", "copied", "late", "helper_restore", "leaked"])
def test_r16_target_and_reconciliation_matrix(tmp_path, enabled, form, case):
    prefix = '''
from unittest.mock import patch as matrix_patch
def matrix_fake(*args): return "yes"
MATRIX_PRE = matrix_patch("aegis_cli.approve.input", matrix_fake, create=True)
'''
    if case not in {"late", "copied"}:
        prefix += "\nimport aegis_cli.approve\n"
    body = '''
import importlib, json, sys
from unittest.mock import patch
from conftest import MATRIX_PRE, matrix_fake
import owned_r16_matrix as helper
def test_a():
    previous_registry = sys.modules
    if CASE == "copied": sys.modules = dict(sys.modules)
    original = importlib.import_module("aegis_cli.approve")
    package = importlib.import_module("aegis_cli")
    if CASE == "replaced":
        sys.modules["aegis_cli.approve"] = json
        package.approve = json
    try:
        owner = json if CASE == "replaced" else original
        if FORM == "object": patcher = patch.object(owner, "input", matrix_fake, create=True)
        elif FORM == "preconstructed": patcher = MATRIX_PRE
        elif FORM == "copy": patcher = MATRIX_PRE.copy()
        elif FORM == "dict": patcher = patch.dict("aegis_cli.approve.__dict__", {"input": matrix_fake})
        else: patcher = patch("aegis_cli.approve.input", matrix_fake, create=True)
        def operation():
            assert owner.input is matrix_fake
            if CASE == "helper_restore": helper.temporary(owner)
        if FORM == "decorator":
            patcher(operation)()
            if CASE == "leaked": helper.persist(owner, matrix_fake)
        elif CASE == "leaked":
            patcher.start()
            operation()
        else:
            with patcher: operation()
    finally:
        if CASE == "replaced":
            package.approve = original
            sys.modules["aegis_cli.approve"] = original
        if CASE == "copied": sys.modules = previous_registry
def test_b_retry():
    owner = importlib.import_module("aegis_cli.approve")
    assert hasattr(owner, "input") is RETAINED
'''.replace("CASE", repr(case)).replace("FORM", repr(form))
    body = body.replace("RETAINED", repr(case == "leaked" and not enabled))
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", plugin_prefix=prefix,
        files={"tests/unit/cli/test_approve_cli.py": body, "owned_r16_matrix.py": '''
def pytest_configure(config): pass
def temporary(owner):
    saved = owner.input
    owner.input = object()
    owner.input = saved
def persist(owner, value): owner.input = value
'''}, options=("tests/unit/cli/test_approve_cli.py", "-p", "owned_r16_matrix"),
        env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    refused = enabled and (case == "leaked" or (case == "replaced" and form != "dict"))
    assert code == (1 if refused else 0), output
    assert ("permits a missing target" in output) is (enabled and case == "replaced" and form != "dict"), output
    assert "3 passed" in output, output


@pytest.mark.parametrize("form", ["context", "copy", "function", "class", "dict-function", "dict-class", "legacy-lambda"])
def test_r16_preinstalled_patchers_keep_construction_provenance(tmp_path, form):
    prefix = '''
from unittest.mock import patch as early_patch
def early_fake(*args): return "yes"
EARLY = early_patch("aegis_cli.approve.input", early_fake, create=True)
EARLY_DICT = early_patch.dict("aegis_cli.approve.__dict__", {"input": early_fake})
'''
    if form == "legacy-lambda":
        prefix = '''
import unittest.mock as early_mock
from importlib import import_module as early_import_module
def legacy_target(address):
    target, attribute = address.rsplit('.', 1)
    return lambda: early_import_module(target), attribute
early_mock._get_target = legacy_target
''' + prefix
    prelude = "from conftest import EARLY, EARLY_DICT, early_fake\nimport importlib\n"
    check = "    assert importlib.import_module('aegis_cli.approve').input is early_fake\n"
    if form in {"context", "legacy-lambda"}:
        body = "def test_prompt():\n    with EARLY:\n" + textwrap.indent(check, "    ")
    elif form == "copy":
        body = "def test_prompt():\n    with EARLY.copy():\n" + textwrap.indent(check, "    ")
    elif form.endswith("class"):
        decorator = "EARLY_DICT" if form.startswith("dict") else "EARLY"
        body = "@" + decorator + "\nclass TestPrompt:\n    def test_prompt(self):\n" + textwrap.indent(check, "    ")
    else:
        decorator = "EARLY_DICT" if form.startswith("dict") else "EARLY"
        body = "@" + decorator + "\ndef test_prompt():\n" + check
    code, output = _session(tmp_path, "def test_placeholder(): pass\n", plugin_prefix=prefix,
        files={"tests/unit/cli/test_approve_cli.py": prelude + body},
        options=("tests/unit/cli/test_approve_cli.py",))
    assert code == 0, output
    assert "permits a missing target" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("form", ["global", "setattr", "delete", "item", "itemdelete", "update", "clear"])
def test_r16_complete_helper_restoration_is_clean(tmp_path, form):
    operations = {
        "global": "global STATE\n    saved = STATE\n    STATE = 1\n    STATE = saved",
        "setattr": "saved = owner.STATE\n    setattr(owner, 'STATE', 1)\n    setattr(owner, 'STATE', saved)",
        "delete": "saved = owner.STATE\n    del owner.STATE\n    owner.STATE = saved",
        "item": "saved = namespace['STATE']\n    namespace['STATE'] = 1\n    namespace['STATE'] = saved",
        "itemdelete": "saved = namespace['STATE']\n    del namespace['STATE']\n    namespace['STATE'] = saved",
        "update": "saved = namespace['STATE']\n    namespace.update(STATE=1)\n    namespace.update(STATE=saved)",
        "clear": "saved = namespace.copy()\n    namespace.clear()\n    namespace.update(saved)",
    }
    plugin = "import sys\nSTATE = 0\nowner = sys.modules[__name__]\nnamespace = vars(owner)\ndef pytest_configure(config): pass\ndef exercise(namespace=namespace):\n    " + operations[form] + "\n"
    code, output = _session(tmp_path, '''
import owned_r16_restore as owner
def test_a(): owner.exercise()
def test_b_retry(): assert owner.STATE == 0
''', files={"owned_r16_restore.py": plugin}, options=("-p", "owned_r16_restore"))
    assert code == 0, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


def test_r16_authenticated_initializer_can_complete_a_restoration(tmp_path):
    code, output = _session(tmp_path, '''
import owned_r16_reload as owner
def test_a():
    owner.STATE = 1
    owner.__loader__.exec_module(owner)
def test_b_retry(): assert owner.STATE == 0
''', files={"owned_r16_reload.py": "STATE = 0\n"}, plugin_prefix="\nimport owned_r16_reload\n")
    assert code == 0, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


def test_r16_foreign_loader_cannot_publish_a_trusted_namespace_delta(tmp_path):
    code, output = _session(tmp_path, '''
import json
from importlib.machinery import SourceFileLoader
def test_a():
    SourceFileLoader('json', 'foreign_json.py').exec_module(json)
def test_b_retry(): assert not hasattr(json, '_r16_foreign_initializer')
''', files={"foreign_json.py": "_r16_foreign_initializer = 1\n"})
    assert code == 1, output
    assert "unrestored namespace: json._r16_foreign_initializer" in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("method", ["string", "object", "mock-string", "mock-object"])
def test_r16_platform_allowance_never_uses_replaced_live_identity(tmp_path, method):
    operations = {
        "string": "with monkeypatch.context() as owned:\n            owned.setattr('ctypes.WinDLL', None, raising=False)",
        "object": "with monkeypatch.context() as owned:\n            owned.setattr(json, 'WinDLL', None, raising=False)",
        "mock-string": "with patch('ctypes.WinDLL', None, create=True): pass",
        "mock-object": "with patch.object(json, 'WinDLL', None, create=True): pass",
    }
    code, output = _session(tmp_path, '''
import ctypes, json, sys
from unittest.mock import patch
def test_probe(monkeypatch):
    original = sys.modules['ctypes']
    sys.modules['ctypes'] = json
    try:
        OPERATION
    finally: sys.modules['ctypes'] = original
'''.replace("OPERATION", operations[method]))
    assert code == 1, output
    assert "permits a missing target" in output, output
    assert "1 passed" in output, output


@pytest.mark.parametrize("copied", [False, True])
@pytest.mark.parametrize("neighbor", [False, True])
def test_r16_late_framework_bindings_use_the_trusted_load_receipt(tmp_path, copied, neighbor):
    code, output = _session(tmp_path, '''
import importlib, sys
def test_a():
    previous = sys.modules
    if COPIED: sys.modules = dict(previous)
    try:
        owner = importlib.import_module('owned_r16_late')
        owner.CLOCK = 1
        if DIRTY_NEIGHBOR: owner.NEIGHBOR = 1
    finally: sys.modules = previous
def test_b_retry():
    owner = importlib.import_module('owned_r16_late')
    assert owner.CLOCK == 1
    assert owner.NEIGHBOR == 0
'''.replace("COPIED", repr(copied)).replace("DIRTY_NEIGHBOR", repr(neighbor)),
        files={"owned_r16_late.py": "CLOCK = 0\nNEIGHBOR = 0\n"},
        extra=_framework_registry(("owned_r16_late", "CLOCK")))
    assert code == (1 if neighbor else 0), output
    assert ("unrestored namespace: owned_r16_late.NEIGHBOR" in output) is neighbor, output
    assert "2 passed" in output, output


def test_r16_new_import_then_generated_examples_refresh_constant_pool(tmp_path):
    from hypothesis.internal.conjecture import providers
    if not hasattr(providers, "_get_local_constants"):
        pytest.skip("This Hypothesis version has no module constant pool")
    code, output = _session(tmp_path, '''
import importlib
from hypothesis import given, settings, strategies as st
from hypothesis.internal.conjecture import providers
def test_a(): importlib.import_module('owned_r16_constants')
@settings(max_examples=10, deadline=None, derandomize=True)
@given(st.integers())
def test_b(value):
    providers._get_local_constants()
    assert isinstance(value, int)
''', plugin_prefix="\nfrom hypothesis.internal.conjecture import providers\n",
        files={"owned_r16_constants.py": "CONSTANT = 16016016\n"}, options=("-p", "_hypothesis_pytestplugin"))
    assert code == 0, output
    assert "unrestored namespace" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("copied", [False, True])
def test_r16_reimported_hypothesis_module_keeps_its_exact_registration(tmp_path, copied):
    code, output = _session(tmp_path, '''
import importlib, sys
original = importlib.import_module('hypothesis.strategies._internal.lazy')
depth = original.unwrap_depth
def test_a():
    previous = sys.modules
    if COPIED: sys.modules = dict(previous)
    try:
        del sys.modules['hypothesis.strategies._internal.lazy']
        owner = importlib.import_module('hypothesis.strategies._internal.lazy')
        owner.unwrap_depth = 1
    finally: sys.modules = previous
def test_b_retry():
    owner = importlib.import_module('hypothesis.strategies._internal.lazy')
    assert owner is original
    assert owner.unwrap_depth == depth
    owner.unwrap_depth = depth + 1
def test_c_registered_field():
    assert original.unwrap_depth == depth + 1
'''.replace("COPIED", repr(copied)), options=("-p", "_hypothesis_pytestplugin"))
    assert code == 1, output
    assert "unrestored namespace" in output, output
    assert "3 passed" in output, output


@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("module, field, value", [
    ("hypothesis.core", "_hypothesis_global_random", "owner.Random(0)"),
    ("hypothesis.internal.conjecture.data", "global_test_counter", "owner.global_test_counter + 1"),
    ("hypothesis.strategies._internal.lazy", "unwrap_depth", "owner.unwrap_depth + 1"),
])
def test_r15_property_runtime_registry_has_exact_field_controls(tmp_path, registered, module, field, value):
    extra = "" if registered else '''
_PATCH_FRAMEWORK_BINDINGS = MappingProxyType({
    key: reason for key, reason in _PATCH_FRAMEWORK_BINDINGS.items() if key != KEY
})
'''.replace("KEY", repr((module, field)))
    code, output = _session(tmp_path, '''
import MODULE as owner
def test_a(): owner.FIELD = VALUE
def test_b_retry(): pass
'''.replace("MODULE", module).replace("FIELD", field).replace("VALUE", value),
        extra=extra, options=("-p", "_hypothesis_pytestplugin"))
    assert code == (0 if registered else 1), output
    assert (module + "." + field in output) is not registered, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("module, field", [
    ("hypothesis.internal.charmap", "_charmap"),
    ("hypothesis.internal.charmap", "_categories"),
    ("hypothesis.configuration", "_first_postinit_what"),
])
def test_r15_hypothesis_lazy_state_is_initialized_and_stays_guarded(tmp_path, module, field):
    code, output = _session(tmp_path, '''
import MODULE as owner
original = owner.FIELD
def test_a():
    assert original is not None
    owner.FIELD = object()
def test_b_retry(): assert owner.FIELD is original
'''.replace("MODULE", module).replace("FIELD", field),
        options=("-p", "_hypothesis_pytestplugin"))
    assert code == 1, output
    assert "unrestored namespace: " + module + "." + field in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("operation", ["property", "weakref"])
def test_r15_callback_effects_follow_binding_registry_in_every_delivery(tmp_path, registered, operation):
    code, output = _session(tmp_path, '''
import owned_delivery_policy as owner
def test_a():
    OPERATION
    assert owner.STATE == 1
def test_b_retry(): assert owner.STATE == EXPECTED
'''.replace("OPERATION", "owner.set_field(owner.Receiver(), 'x', 1)" if operation == "property" else "owner.release()")
        .replace("EXPECTED", "1" if registered else "0"), files={"owned_delivery_policy.py": '''
import weakref
STATE = 0
def pytest_configure(config): pass
def publish(*args):
    global STATE
    STATE = 1
class Target: pass
HELD = [Target()]
REFERENCE = weakref.ref(HELD[0], publish)
class Receiver:
    x = property(None, publish)
def set_field(owner, key, value): setattr(owner, key, value)
def release(): HELD[0] = None
'''}, extra=("\n_PATCH_FRAMEWORK_BINDINGS = MappingProxyType({**_PATCH_FRAMEWORK_BINDINGS, "
             "('owned_delivery_policy', 'STATE'): 'Synthetic framework-owned delivery control.'})\n") if registered else "",
        options=("-p", "owned_delivery_policy"))
    assert code == (0 if registered else 1), output
    assert ("unrestored namespace: owned_delivery_policy.STATE" in output) is not registered, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("registered", [False, True])
def test_r15_fixture_cleanup_and_plugin_store_follow_binding_registry(tmp_path, registered):
    code, output = _session(tmp_path, '''
import pytest
import owned_binding_policy as owner
@pytest.fixture
def replace():
    owner.LEFT = owner.A
    yield
    owner.LEFT = owner.O
def test_a(replace): assert owner.LEFT is owner.A
def test_b_retry(): assert owner.LEFT is owner.O
''', files={"owned_binding_policy.py": '''
O, A = object(), object()
LEFT = O
def pytest_runtest_call(item):
    if item.name == "test_a":
        global LEFT
        LEFT = A
'''}, extra=("\n_PATCH_FRAMEWORK_BINDINGS = MappingProxyType({**_PATCH_FRAMEWORK_BINDINGS, "
             "('owned_binding_policy', 'LEFT'): 'Synthetic framework-owned cleanup control.'})\n") if registered else "",
        options=("-p", "owned_binding_policy"))
    # Round 16 applies the same final-state rule to registered and ordinary
    # bindings: fixture cleanup has completely restored the trusted O.
    assert code == 0, output
    assert "unrestored namespace: owned_binding_policy.LEFT" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
def test_r15_string_target_cannot_trust_a_replaced_live_module_binding(tmp_path, method):
    operation = ("with monkeypatch.context() as owned:\n            owned.setattr('aegis_cli.approve.input', fake, raising=False)"
                 if method == "monkeypatch" else "with patch('aegis_cli.approve.input', fake, create=True): pass")
    source = '''
import importlib, json, sys
from unittest.mock import patch
def fake(*args): return "yes"
def test_prompt(monkeypatch):
    original = importlib.import_module("aegis_cli.approve")
    package = importlib.import_module("aegis_cli")
    sys.modules["aegis_cli.approve"] = json
    package.approve = json
    try:
        OPERATION
    finally:
        package.approve = original
        sys.modules["aegis_cli.approve"] = original
'''.replace("OPERATION", operation)
    code, output = _session(tmp_path, "def test_placeholder(): pass\n",
        files={"tests/unit/cli/test_approve_cli.py": source}, options=("tests/unit/cli/test_approve_cli.py",))
    assert code == 1, output
    assert "permits a missing target" in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("field", ["_gc_start", "_gc_cumulative_time"])
@pytest.mark.parametrize("writer", ["test", "gc"])
@pytest.mark.parametrize("registered", [False, True])
def test_r15_framework_registry_accepts_only_exact_hypothesis_bindings(tmp_path, field, writer, registered):
    extra = "" if registered else '''
_PATCH_FRAMEWORK_BINDINGS = MappingProxyType({
    key: reason for key, reason in _PATCH_FRAMEWORK_BINDINGS.items() if key[1] != FIELD
})
'''.replace("FIELD", repr(field))
    code, output = _session(tmp_path, '''
import gc
import hypothesis.internal.conjecture.junkdrawer as clock
def test_a():
    OPERATION
def test_b_retry(): pass
'''.replace("OPERATION", "clock." + field + " += 1" if writer == "test" else "gc.collect()"),
        extra=extra, options=("-p", "_hypothesis_pytestplugin"))
    assert code == (0 if registered else 1), output
    assert ("hypothesis.internal.conjecture.junkdrawer." + field in output) is not registered, output
    assert "2 passed" in output, output


def test_r15_framework_registry_does_not_exempt_neighbor_bindings(tmp_path):
    code, output = _session(tmp_path, '''
import hypothesis.internal.conjecture.junkdrawer as clock
original = clock.gc_cumulative_time
def test_a(): clock.gc_cumulative_time = lambda: 0
def test_b_retry(): assert clock.gc_cumulative_time is original
''', options=("-p", "_hypothesis_pytestplugin"))
    assert code == 1, output
    assert "unrestored namespace: hypothesis.internal.conjecture.junkdrawer.gc_cumulative_time" in output, output
    assert "2 passed" in output, output


def test_r15_framework_registry_does_not_trust_copied_module_metadata(tmp_path):
    code, output = _session(tmp_path, '''
import owned_registry_impostor as owner
def test_a(): owner._gc_start = 1
def test_b_retry(): assert owner._gc_start == 0
''', files={"owned_registry_impostor.py": '''
__name__ = "hypothesis.internal.conjecture.junkdrawer"
_gc_start = 0
def pytest_configure(config): pass
'''}, options=("-p", "owned_registry_impostor", "-p", "_hypothesis_pytestplugin"))
    assert code == 1, output
    assert "unrestored namespace: owned_registry_impostor._gc_start" in output, output
    assert "2 passed" in output, output


def test_r15_mock_target_limit_precedes_target_parsing(tmp_path):
    code, output = _session(tmp_path, '''
import pytest
from unittest.mock import patch
from conftest import _CENSUS_ADDRESS_LIMIT
class Oversize(str):
    def rsplit(self, *args): raise AssertionError("oversize target was parsed")
def test_probe():
    with pytest.raises(pytest.UsageError) as error:
        patch(Oversize("x" * (_CENSUS_ADDRESS_LIMIT + 1)))
    assert str(error.value) == "runtime patch guard mock target metadata is unsupported"
''')
    assert code == 0, output
    assert "1 passed" in output, output


@pytest.mark.parametrize("kind, delivery", [
    ("excepthook", "direct"), ("destructor", "direct"),
    ("weakref", "direct"), ("finalizer", "direct"),
    ("destructor", "gc"), ("weakref", "gc"), ("finalizer", "gc"),
])
def test_r15_callbacks_never_authorize_unregistered_plugin_bindings(tmp_path, kind, delivery):
    plugin = '''
import gc, sys, weakref
STATE = 0
def pytest_configure(config): pass
def callback(*args):
    global STATE
    STATE = 1
class Target:
    def __del__(self):
        if KIND == "destructor": callback()
HELD = [Target()]
REFERENCE = weakref.ref(HELD[0], callback) if KIND == "weakref" else None
FINALIZER = weakref.finalize(HELD[0], callback) if KIND == "finalizer" else None
if KIND == "excepthook": sys.excepthook = callback
def release():
    HELD[0] = None
    gc.collect()
'''.replace("KIND", repr(kind))
    operation = ("owner.release()" if delivery == "gc" else
                 "sys.excepthook(RuntimeError, RuntimeError('owned failure'), None)" if kind == "excepthook" else
                 "owner.HELD[0].__del__()" if kind == "destructor" else
                 "owner.REFERENCE.__callback__(owner.REFERENCE)" if kind == "weakref" else "owner.FINALIZER()")
    code, output = _session(tmp_path, '''
import sys
import owned_callback_policy as owner
def test_a():
    OPERATION
    assert owner.STATE == 1
def test_b_retry(): assert owner.STATE == 0
'''.replace("OPERATION", operation), files={"owned_callback_policy.py": plugin},
        options=("-p", "owned_callback_policy", "-p", "no:unraisableexception"))
    assert code == 1, output
    assert "unrestored namespace: owned_callback_policy.STATE" in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("module, field", [
    ("sys", "unraisablehook"), ("sys", "excepthook"), ("threading", "excepthook"),
])
@pytest.mark.parametrize("external_wrapper", [False, True])
def test_r15_equivalent_callback_bindings_repair_once_and_terminate(tmp_path, module, field, external_wrapper):
    plugin = '''
import functools, pytest, MODULE
OLD = MODULE.FIELD
POST = []
def callback(*args): pass
@functools.wraps(callback)
def wrapper(*args): return callback(*args)
EXPECTED = wrapper if EXTERNAL else callback
MODULE.FIELD = EXPECTED
def temporary(*args): pass
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    yield
    if "replacement" in item.funcargs: item.funcargs["replacement"]()
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call(item):
    if item.name != "test_a": return (yield)
    saved = MODULE.FIELD
    MODULE.FIELD = temporary
    try: yield
    finally: MODULE.FIELD = saved
@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item, nextitem):
    yield
    if item.name == "test_a": POST.append(MODULE.FIELD)
def pytest_unconfigure(config): MODULE.FIELD = OLD
'''.replace("MODULE", module).replace("FIELD", field).replace("EXTERNAL", repr(external_wrapper))
    code, output = _session(tmp_path, '''
import MODULE, pytest
import owned_equivalent_plugin as owner
@pytest.fixture
def replacement():
    def install(): MODULE.FIELD = owner.callback
    return install
def test_a(replacement): pass
def test_b_retry(): assert owner.POST[-1] is owner.EXPECTED
'''.replace("MODULE", module).replace("FIELD", field),
        files={"owned_equivalent_plugin.py": plugin}, options=("-p", "owned_equivalent_plugin"), child_timeout=20)
    assert code == (1 if external_wrapper else 0), output
    assert ("unrestored namespace: " + module + "." + field in output) is external_wrapper, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("form", ["context", "restart", "function", "class", "dict-context", "dict-function", "object", "object-string"])
@pytest.mark.parametrize("registered", [False, True])
def test_r15_mock_string_targets_keep_resolved_provenance(tmp_path, form, registered):
    prelude = "from unittest.mock import patch\nimport pytest\ndef fake(*args): return 'yes'\n"
    checks = "    from importlib import import_module\n    assert import_module('aegis_cli.approve').input is fake\n"
    if form == "context":
        body = "def test_prompt():\n    with patch('aegis_cli.approve.input', fake, create=True):\n" + textwrap.indent(checks, "    ")
    elif form == "restart":
        body = "def test_prompt():\n    patcher = patch('aegis_cli.approve.input', fake, create=True)\n    for _ in range(2):\n        with patcher:\n" + textwrap.indent(checks, "        ")
    elif form == "function":
        body = "@patch('aegis_cli.approve.input', fake, create=True)\ndef test_prompt():\n" + checks
    elif form == "class":
        body = "@patch('aegis_cli.approve.input', fake, create=True)\nclass TestPrompt:\n    def test_first(self):\n" + textwrap.indent(checks, "    ") + "    def test_second(self):\n" + textwrap.indent(checks, "    ")
    elif form == "dict-context":
        body = "def test_prompt():\n    with patch.dict('aegis_cli.approve.__dict__', {'input': fake}):\n" + textwrap.indent(checks, "    ")
    elif form == "dict-function":
        body = "@patch.dict('aegis_cli.approve.__dict__', {'input': fake})\ndef test_prompt():\n" + checks
    elif form == "object":
        body = "from aegis_cli import approve as tool\ndef test_prompt():\n    with patch.object(tool, 'input', fake, create=True):\n" + textwrap.indent(checks, "    ")
    else:
        body = "def test_prompt():\n    with pytest.raises(TypeError):\n        patch.object('aegis_cli.approve', 'input', fake, create=True)\n"
    code, output = _session(tmp_path, "def test_placeholder(): pass\n",
        files={"tests/unit/cli/test_approve_cli.py": prelude + body},
        options=("tests/unit/cli/test_approve_cli.py",),
        policy_suffix="" if registered else "\nBUILTIN_GLOBALS = {}\n")
    allowed = registered or form.startswith("dict-") or form == "object-string"
    assert code == (0 if allowed else 1), output
    assert ("permits a missing target" in output) is not allowed, output
    assert ("3 passed" if form == "class" else "2 passed") in output, output


@pytest.mark.parametrize("attributes", [("LEFT",), ("LEFT", "RIGHT")], ids=["one", "two"])
@pytest.mark.parametrize("registered", [False, True])
def test_r14_each_conflicting_value_repairs_to_the_binding_it_displaced(tmp_path, attributes, registered):
    fixture_stores = "\n".join("    owner.%s = owner.R" % name for name in attributes)
    test_stores = "\n".join("    owner.%s = owner.S" % name for name in attributes)
    framework_stores = "\n".join("    owner.%s = A" % name for name in attributes)
    wrapper_stores = "\n".join(
        "    saved_%s = owner.%s\n    owner.%s = B\n    owner.%s = saved_%s"
        % (name, name, name, name, name) for name in attributes)
    # Round 15: plugin stores grant no authority. Unguarded registered fields
    # retain S; every unregistered field repairs to its original O.
    assertions = "\n".join("    assert owner.%s is owner.%s" % (name, "S" if registered else "O")
                           for name in attributes)
    registration = ("\n_PATCH_FRAMEWORK_BINDINGS = MappingProxyType({**_PATCH_FRAMEWORK_BINDINGS, **" + repr({
        ("owned_conflict_plugin", name): "Synthetic framework-owned conflict control."
        for name in attributes}) + "})\n") if registered else ""
    code, output = _session(tmp_path, "import owned_conflict_plugin as owner\n"
        "def test_a(leak):\n" + test_stores + "\n"
        "def test_b_retry():\n" + assertions + "\n", extra=
        "import owned_conflict_plugin as owner\n@pytest.fixture\ndef leak():\n" + fixture_stores + "\n" + registration,
        files={"owned_conflict_plugin.py": "import pytest, sys\n"
            "O, R, A, S, B = object(), object(), object(), object(), object()\n"
            "LEFT = RIGHT = O\nowner = sys.modules[__name__]\n"
            "@pytest.hookimpl(wrapper=True)\ndef pytest_runtest_call(item):\n"
            "    if item.name != 'test_a':\n        return (yield)\n" + framework_stores + "\n"
            "    yield\n" + wrapper_stores + "\n"}, options=("-p", "owned_conflict_plugin"))
    assert code == (0 if registered else 1), output
    assert ("ERROR at teardown of test_a" in output) is not registered, output
    for name in attributes:
        assert ("owned_conflict_plugin." + name in output) is not registered, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("registration", ["weakref", "audit"])
@pytest.mark.parametrize("caller", ["test", "fixture", "conftest", "native"])
@pytest.mark.parametrize("delegated", [False, True])
def test_r14_native_registration_does_not_authorize_python_calls(tmp_path, registration, caller, delegated):
    plugin = '''
import gc, sys, weakref
def pytest_configure(config): pass
STATE = 0
def publish(*args):
    global STATE
    if not args or args[0] == "aegis.r14.native" or args[0] is REF:
        STATE += 1
class Target: pass
def delegated_entry(*args):
    if not args or args[0] == "aegis.r14.native" or args[0] is REF:
        publish(*args)
entry = delegated_entry if DELEGATED else publish
HELD = [Target()]
HELD[0].cycle = HELD[0]
REF = weakref.ref(HELD[0], entry)
REGISTRATION
def pytest_unconfigure(config):
    HELD.clear()
    gc.collect()
def fire():
    if REGISTRATION_KIND == "weakref":
        HELD.clear()
        gc.collect()
    else: sys.audit("aegis.r14.native")
'''.replace("REGISTRATION_KIND", repr(registration)).replace("DELEGATED", repr(delegated)).replace("REGISTRATION",
        'sys.addaudithook(entry)' if registration == "audit" else "")
    operation = {"test": "owner.entry()", "fixture": "pass",
                 "conftest": "invoke_from_conftest()", "native": "owner.fire()"}[caller]
    code, output = _session(tmp_path, '''
import owned_native_plugin as owner
from conftest import invoke_from_conftest
def test_a(FIXTURE): OPERATION
def test_b_retry(): assert owner.STATE == EXPECTED
'''.replace("FIXTURE", "direct_call" if caller == "fixture" else "")
        .replace("OPERATION", operation).replace("EXPECTED", "0"),
        extra='''
import owned_native_plugin as owner
def invoke_from_conftest(): owner.entry()
@pytest.fixture
def direct_call(): owner.entry()
''', files={"owned_native_plugin.py": plugin}, options=("-p", "owned_native_plugin"))
    assert code == 1, output
    assert "unrestored namespace: owned_native_plugin.STATE" in output, output
    assert "2 passed" in output, output


_R12_CPU = '''
import time
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    before = time.process_time_ns()
    try:
        return (yield)
    finally:
        print("R12_CPU_NS=" + str(time.process_time_ns() - before))
'''


@pytest.mark.parametrize("registered", [False, True])
def test_r14_string_builtin_allowance_uses_the_resolved_target_without_import_bindings(tmp_path, registered):
    source = '''
def test_builtin_input(monkeypatch):
    def fake(*args): return "yes"
    monkeypatch.setattr("aegis_cli.approve.input", fake, raising=False)
    from importlib import import_module
    assert import_module("aegis_cli.approve").input is fake
'''
    code, output = _session(tmp_path, "def test_placeholder(): pass\n",
        files={"tests/unit/cli/test_approve_cli.py": source},
        options=("tests/unit/cli/test_approve_cli.py",),
        policy_suffix="" if registered else "\nBUILTIN_GLOBALS = {}\n")
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output
    assert "2 passed" in output, output


def test_r14_restoring_a_wrapped_fixture_callback_repairs_the_original_hook(tmp_path):
    code, output = _session(tmp_path, '''
import sys
import pytest
import owned_callback_plugin as owner
@pytest.fixture
def replacement():
    def install(): sys.unraisablehook = owner.callback
    return install
def test_a(replacement): pass
def test_b_retry(): assert owner.POST_HOOKS[-1] is owner.ORIGINAL_HOOK
''', files={"owned_callback_plugin.py": '''
import pytest, sys
ORIGINAL_HOOK = sys.unraisablehook
POST_HOOKS = []
def callback(*args): pass
def temporary(*args): pass
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    yield
    if "replacement" in item.funcargs: item.funcargs["replacement"]()
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call(item):
    if item.name != "test_a": return (yield)
    saved = sys.unraisablehook
    sys.unraisablehook = temporary
    try: yield
    finally: sys.unraisablehook = saved
@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item, nextitem):
    yield
    if item.name == "test_a": POST_HOOKS.append(sys.unraisablehook)
'''}, options=("-p", "owned_callback_plugin"))
    assert code == 1, output
    assert "unrestored namespace: sys.unraisablehook" in output, output
    assert "2 passed" in output, output


def _r12_cpu(record_property, output):
    for line in output.splitlines():
        if "R12_CPU_NS=" in line:
            record_property("child_test_cpu_ns", int(line.split("R12_CPU_NS=", 1)[1]))


@pytest.mark.parametrize("kind", ["gc", "lambda", "finalize", "weakref", "destructor", "thread", "audit", "signal", "excepthook"])
@pytest.mark.parametrize("leaked", [False, True])
def test_r12_async_framework_writer_preserves_unrelated_test_refusal(tmp_path, kind, leaked, record_property):
    plugin = '''
import gc, signal, sys, threading, weakref
def pytest_configure(config): pass
STATE = 0
TEST_STATE = 0
def publish(*args):
    global STATE
    STATE += 1
class Target:
    pass
class Destructor:
    def __del__(self): publish()
HELD = []
REFS = []
def audit(event, args):
    if event == "aegis.r12.callback": publish()
def gc_callback(phase, info):
    if phase == "stop": publish()
KIND = SELECTED
if KIND == "gc": gc.callbacks.append(gc_callback)
elif KIND == "lambda": gc.callbacks.append(lambda phase, info: setattr(sys.modules[__name__], "STATE", STATE + 1) if phase == "stop" else None)
elif KIND == "finalize":
    HELD.append(Target())
    REFS.append(weakref.finalize(HELD[0], publish))
elif KIND == "weakref":
    HELD.append(Target())
    REFS.append(weakref.ref(HELD[0], publish))
elif KIND == "destructor": HELD.append(Destructor())
elif KIND == "audit": sys.addaudithook(audit)
elif KIND == "signal": signal.signal(signal.SIGINT, publish)
elif KIND == "excepthook": threading.excepthook = publish
def fire():
    if KIND in {"finalize", "weakref", "destructor"}: HELD.clear()
    elif KIND == "audit": sys.audit("aegis.r12.callback")
    elif KIND == "signal": signal.raise_signal(signal.SIGINT)
    elif KIND in {"thread", "excepthook"}:
        def fail(): raise RuntimeError("owned thread failure")
        thread = threading.Thread(target=publish if KIND == "thread" else fail)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
    gc.collect()
'''.replace("SELECTED", repr(kind))
    code, output = _session(tmp_path, '''
import owned_async_plugin as owner
def test_a():
    if LEAKED: owner.TEST_STATE = 1
    before = owner.STATE
    owner.fire()
    assert owner.STATE > before
def test_b_retry(): assert owner.TEST_STATE == 0
'''.replace("LEAKED", repr(leaked)), files={"owned_async_plugin.py": plugin},
        extra=_R12_CPU, options=("-s", "-p", "owned_async_plugin", "-p", "no:threadexception"))
    _r12_cpu(record_property, output)
    assert code == 1, output
    assert ("owned_async_plugin.TEST_STATE" in output) is leaked, output
    assert "unrestored namespace: owned_async_plugin.STATE" in output, output
    assert "2 passed" in output, output


def test_r12_test_registered_gc_callback_has_no_framework_authority(tmp_path, record_property):
    code, output = _session(tmp_path, '''
import gc, os
def test_a():
    def callback(phase, info):
        if phase == "stop": os._r12_test_callback = 1
    gc.callbacks.append(callback)
    try: gc.collect()
    finally: gc.callbacks.remove(callback)
def test_b_retry(): assert not hasattr(os, "_r12_test_callback")
''', extra=_R12_CPU, options=("-s",))
    _r12_cpu(record_property, output)
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "os._r12_test_callback" in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("kind", ["gc", "finalize", "weakref", "destructor", "thread", "signal"])
def test_r12_later_framework_callbacks_keep_source_provenance(tmp_path, kind):
    code, output = _session(tmp_path, '''
import owned_async_plugin as owner
def test_a():
    owner.fire()
    assert owner.STATE == 1
def test_b_retry(): assert owner.STATE == 0
''', files={"owned_async_plugin.py": '''
import gc, signal, sys, threading, weakref
def pytest_configure(config): pass
STATE = 0
KIND = SELECTED
def fire():
    def publish(*args):
        global STATE
        STATE += 1
    def audit(event, args):
        if event == "aegis.r12.later": publish()
    def callback(phase, info):
        if phase == "stop": publish()
    class Target: pass
    class Destructor:
        def __del__(self): publish()
    if KIND == "gc":
        gc.callbacks.append(callback)
        try: gc.collect()
        finally: gc.callbacks.remove(callback)
    elif KIND in {"finalize", "weakref"}:
        target = Target()
        reference = weakref.finalize(target, publish) if KIND == "finalize" else weakref.ref(target, publish)
        del target
        gc.collect()
    elif KIND == "destructor":
        target = Destructor()
        del target
    elif KIND == "audit":
        sys.addaudithook(audit)
        sys.audit("aegis.r12.later")
    elif KIND == "signal":
        saved = signal.signal(signal.SIGINT, publish)
        try: signal.raise_signal(signal.SIGINT)
        finally: signal.signal(signal.SIGINT, saved)
    else:
        thread = threading.Thread(target=publish)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
'''.replace("SELECTED", repr(kind))}, options=("-p", "owned_async_plugin"))
    assert code == 1, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("failed", [False, True])
def test_r12_callback_failure_and_concurrent_writes_preserve_test_refusal(tmp_path, failed):
    code, output = _session(tmp_path, '''
import owned_async_plugin as owner
def test_a():
    owner.TEST_STATE = 1
    owner.fire()
def test_b_retry():
    assert owner.TEST_STATE == 0
    assert owner.LEFT == owner.RIGHT == 0
''', files={"owned_async_plugin.py": '''
import threading
def pytest_configure(config): pass
LEFT = RIGHT = TEST_STATE = 0
def fire():
    gate = threading.Barrier(2, timeout=5)
    def left():
        global LEFT
        gate.wait()
        LEFT = 1
    def right():
        global RIGHT
        gate.wait()
        RIGHT = 1
    threads = [threading.Thread(target=left), threading.Thread(target=right)]
    for thread in threads: thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    if FAILED: raise ValueError("callback refused")
'''.replace("FAILED", repr(failed))}, options=("-p", "owned_async_plugin"))
    assert code == 1, output
    assert "owned_async_plugin.TEST_STATE" in output, output
    assert "owned_async_plugin.LEFT" in output, output
    assert "owned_async_plugin.RIGHT" in output, output
    assert ("ValueError: callback refused" in output) is failed, output
    assert ("1 passed" if failed else "2 passed") in output, output


def test_r12_created_callbacks_keep_their_public_signature(tmp_path):
    code, output = _session(tmp_path, '''
import owned_async_plugin as owner
def test_a(): owner.fire()
def test_b_retry(): owner.fire()
''', files={"owned_async_plugin.py": '''
import gc, inspect
def pytest_configure(config): pass
STATE = 0
def fire():
    def callback(phase, info):
        global STATE
        if phase == "stop": STATE += 1
    assert tuple(inspect.signature(callback).parameters) == ("phase", "info")
    gc.callbacks.append(callback)
    try: gc.collect()
    finally: gc.callbacks.remove(callback)
''',}, options=("-p", "owned_async_plugin"))
    assert code == 1, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("writer", ["test", "framework"])
def test_r12_overlapping_stores_preserve_the_actual_writer(tmp_path, writer):
    code, output = _session(tmp_path, '''
import gc, os, threading
import owned_async_plugin as owner
from conftest import ARMED, STORED, WROTE
def test_a(intercept):
    def change():
        assert STORED.wait(timeout=5)
        os._r12_race = 2
        WROTE.set()
    thread = threading.Thread(target=change) if WRITER == "test" else owner.worker()
    if WRITER == "test": thread.start()
    ARMED.append(True)
    gc.collect()
    thread.join(timeout=5)
    assert not thread.is_alive()
def test_b_retry(): assert not hasattr(os, "_r12_race")
'''.replace("WRITER", repr(writer)).replace("EXPECTED", "1" if writer == "test" else "3"),
        files={"owned_async_plugin.py": '''
import gc, os, threading
def pytest_configure(config): pass
def callback(phase, info):
    try: from conftest import ARMED
    except ImportError: return
    if phase == "stop" and ARMED:
        ARMED.pop()
        os._r12_race = 1
def worker():
    from conftest import STORED, WROTE
    def change():
        assert STORED.wait(timeout=5)
        os._r12_race = 3
        WROTE.set()
    thread = threading.Thread(target=change)
    thread.start()
    return thread
gc.callbacks.append(callback)
'''}, extra='''
import threading
ARMED = []
STORED = threading.Event()
WROTE = threading.Event()
@pytest.fixture
def intercept(pytestconfig):
    guard = pytestconfig._patch_guard
    original = guard.hook_setattr
    def owned_setattr(owner, name, value):
        result = original(owner, name, value)
        if name == "_r12_race" and value == 1:
            STORED.set()
            assert WROTE.wait(timeout=5)
        return result
    guard.hook_setattr = owned_setattr
    try: yield
    finally: guard.hook_setattr = original
''', options=("-p", "owned_async_plugin"))
    assert code == 1, output
    assert "unrestored namespace: os._r12_race" in output, output
    assert "2 passed" in output, output


def test_r12_callback_can_join_a_writer_during_namespace_verification(tmp_path):
    code, output = _session(tmp_path, '''
import owned_async_plugin as owner
def test_a(intercept): pass
def test_b_retry():
    assert owner.DONE.wait(timeout=5)
    assert not owner.GC_DONE
''', files={"owned_async_plugin.py": '''
import gc, threading
DONE = threading.Event()
STATE_A = STATE_B = 0
GC_DONE = False
def work():
    global STATE_B
    STATE_B = 1
    DONE.set()
def callback(phase, info):
    global GC_DONE
    try: from conftest import FIRE
    except ImportError: return
    if phase == "stop" and FIRE:
        FIRE.pop()
        thread = threading.Thread(target=work)
        thread.start()
        assert DONE.wait(timeout=5), "callback thread blocked"
        thread.join(timeout=5)
        assert not thread.is_alive()
        GC_DONE = True
def pytest_runtest_call(item):
    global STATE_A
    STATE_A = 1
gc.callbacks.append(callback)
'''}, extra='''
import gc
from types import FunctionType, MethodType
FIRE = []
ARMED = []
@pytest.fixture
def intercept(pytestconfig):
    guard = pytestconfig._patch_guard
    original = guard._verify_baselines
    def owned_dict(*args, **kwargs):
        result = dict(*args, **kwargs)
        if "STATE_A" in result and ARMED:
            ARMED.pop()
            FIRE.append(True)
            gc.collect()
        return result
    function = original.__func__
    owned_globals = dict(function.__globals__, dict=owned_dict)
    clone = FunctionType(function.__code__, owned_globals, function.__name__, function.__defaults__, function.__closure__)
    clone.__kwdefaults__ = function.__kwdefaults__
    bound = MethodType(clone, guard)
    def observe():
        try: return bound()
        finally: guard._verify_baselines = original
    guard._verify_baselines = observe
    ARMED.append(True)
    yield
''', options=("-p", "owned_async_plugin"))
    assert code == 1, output
    assert "callback thread blocked" not in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("enabled", [False, True])
def test_r12_async_probe_is_fail_closed_and_guard_off_does_not_run_it(tmp_path, enabled):
    code, output = _session(tmp_path, "def test_probe(): pass\n", plugin_prefix='''
from importlib import import_module as _actual_import
from types import ModuleType as _OwnedModule
def import_module(name, package=None):
    actual = _actual_import(name, package)
    if name != "gc": return actual
    owned = _OwnedModule("owned_gc_probe")
    vars(owned).update(vars(actual))
    owned.callbacks = ()
    return owned
''', env_overrides={"AEGIS_PATCH_GUARD": "on" if enabled else "off"})
    assert code == 0, output
    assert "runtime patch guard asynchronous API is unsupported" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("active", [False, True])
def test_r12_already_running_framework_writer_refuses_before_tests(tmp_path, active):
    code, output = _session(tmp_path, "def test_probe(): pass\n", files={"owned_async_plugin.py": '''
import threading
STOP = threading.Event()
ENTERED = threading.Event()
THREAD = None
def writer():
    ENTERED.set()
    assert STOP.wait(timeout=5)
def pytest_configure(config):
    global THREAD
    if ACTIVE:
        THREAD = threading.Thread(target=writer)
        THREAD.start()
        assert ENTERED.wait(timeout=5)
def pytest_unconfigure(config):
    STOP.set()
    if THREAD is not None:
        THREAD.join(timeout=5)
        assert not THREAD.is_alive()
'''.replace("ACTIVE", repr(active))}, options=("-p", "owned_async_plugin"))
    assert code == 0, output
    assert "runtime patch guard already-running framework writer is unsupported" not in output, output
    assert "INTERNALERROR" not in output, output


def test_r12_audit_probe_refusal_has_a_fixed_message_and_restores_entries(tmp_path):
    code, output = _session(tmp_path, "def test_probe(): pass\n", files={"owned_async_plugin.py": '''
import sys
def pytest_configure(config): pass
def callback(event, args):
    if event == "aegis.runtime_patch_guard.probe":
        raise ValueError("untrusted audit refusal detail")
sys.addaudithook(callback)
def pytest_unconfigure(config):
    assert not any(name.startswith("_aegis_hook_dispatch_") for name in callback.__code__.co_varnames)
'''}, options=("-p", "owned_async_plugin"))
    assert code == 0, output
    assert "runtime patch guard audit callback probe was refused" not in output, output
    assert "untrusted audit refusal detail" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("mode", ["helper", "nested", "direct"])
def test_r12_recursive_audit_metadata_never_grants_binding_authority(tmp_path, mode):
    callback = '''
def callback(event, args): publish()
''' if mode == "helper" else '''
def callback(event, args):
    def local(): publish()
    local()
'''
    if mode == "direct":
        callback = '''
def callback(event, args):
    global STATE
    STATE += 1
'''
    code, output = _session(tmp_path, "def test_probe(): pass\n", files={"owned_async_plugin.py": '''
import sys
STATE = 0
def pytest_configure(config): pass
def publish():
    global STATE
    STATE += 1
''' + callback + '\nsys.addaudithook(callback)\n'}, options=("-p", "owned_async_plugin"))
    assert code == 1, output
    assert "unrestored namespace: owned_async_plugin.STATE" in output, output
    assert "INTERNALERROR" not in output, output
    assert "RecursionError" not in output, output


def test_r12_late_framework_audit_registration_is_refused_without_installing_it(tmp_path):
    code, output = _session(tmp_path, '''
import owned_async_plugin as owner
def test_a(): owner.install()
def test_b_retry(): assert owner.CALLS
''', files={"owned_async_plugin.py": '''
import sys
CALLS = []
def pytest_configure(config): pass
def callback(event, args): CALLS.append(event)
def install(): sys.addaudithook(callback)
'''}, options=("-p", "owned_async_plugin"))
    assert code == 0, output
    assert "runtime patch guard audit registration after baseline is unsupported" not in output, output
    assert "2 passed" in output, output
    assert "RecursionError" not in output, output


@pytest.mark.parametrize("restart", [False, True])
def test_r12_framework_thread_run_binding_is_restored_after_success_or_start_failure(tmp_path, restart):
    code, output = _session(tmp_path, '''
import owned_async_plugin as owner
def test_a(): owner.fire()
def test_b_retry(): owner.fire()
''', files={"owned_async_plugin.py": '''
import threading
def pytest_configure(config): pass
def publish(): pass
def fire():
    thread = threading.Thread(target=publish)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert "run" not in vars(thread)
    if RESTART:
        try: thread.start()
        except RuntimeError as error: assert str(error) == "threads can only be started once"
        else: raise AssertionError("restart succeeded")
        assert "run" not in vars(thread)
'''.replace("RESTART", repr(restart))}, options=("-p", "owned_async_plugin"))
    assert code == 0, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("failed", [False, True])
def test_r12_gc_during_comparison_and_callback_failure_do_not_adopt_test_names(tmp_path, failed):
    code, output = _session(tmp_path, '''
import gc
import owned_async_plugin as owner
from conftest import COLLECTED
def test_a():
    owner.TEST_STATE = 1
    owner.FAILURES.append(FAILED)
    COLLECTED.clear()
    gc.collect()
def test_b_retry(): assert owner.TEST_STATE == 0
'''.replace("FAILED", repr(failed)), files={"owned_async_plugin.py": '''
import gc
def pytest_configure(config): pass
STATE = TEST_STATE = 0
FAILURES = []
def callback(phase, info):
    global STATE
    if phase == "stop":
        STATE += 1
        if FAILURES and FAILURES.pop(): raise RuntimeError("callback refused")
gc.callbacks.append(callback)
'''}, extra='''
import gc
COLLECTED = []
_actual_bindings = _patch_same_bindings
def _collect_during_compare(namespace, keys, values):
    if namespace.get("__name__") == "owned_async_plugin" and not COLLECTED:
        COLLECTED.append(True)
        gc.collect()
    return _actual_bindings(namespace, keys, values)
_patch_same_bindings = _collect_during_compare
''', options=("-p", "owned_async_plugin", "-p", "no:unraisableexception"))
    assert code == 1, output
    assert "owned_async_plugin.TEST_STATE" in output, output
    assert "unrestored namespace: owned_async_plugin.STATE" in output, output
    assert ("RuntimeError: callback refused" in output) is failed, output
    assert "2 passed" in output, output


def test_r12_async_framework_callback_cannot_delegate_authority_to_test_code(tmp_path):
    code, output = _session(tmp_path, '''
import gc
import owned_async_plugin as owner
def test_a():
    def user_callback(): owner.write_test_field()
    owner.CALLBACKS.append(user_callback)
    try: gc.collect()
    finally: owner.CALLBACKS.clear()
def test_b_retry(): assert owner.TEST_STATE == 0
''', files={"owned_async_plugin.py": '''
import gc
def pytest_configure(config): pass
STATE = TEST_STATE = 0
CALLBACKS = []
def write_test_field():
    global TEST_STATE
    TEST_STATE = 1
def callback(phase, info):
    global STATE
    if phase == "stop":
        STATE += 1
        for user in CALLBACKS: user()
gc.callbacks.append(callback)
'''}, options=("-p", "owned_async_plugin"))
    assert code == 1, output
    assert "owned_async_plugin.TEST_STATE" in output, output
    assert "unrestored namespace: owned_async_plugin.STATE" in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("registered", ["tool.open", "cached_consumer.open"])
def test_r11_cached_module_name_cannot_replace_the_written_owner(tmp_path, registered):
    code, output = _session(tmp_path, '''
from conftest import tool
def test_probe(monkeypatch):
    monkeypatch.setattr(tool, "open", None, raising=False)
''', extra='''
from types import ModuleType
tool = ModuleType("cached_consumer")
sys.modules["cached_consumer"] = tool
''', policy_suffix="\nBUILTIN_GLOBALS = " + repr({("tests/test_probe.py", registered): "consumer control"}) + "\n")
    assert code == (0 if registered == "tool.open" else 1), output
    assert ("permits a missing target" in output) is (registered != "tool.open"), output


def test_r11_builtin_allowance_resolves_a_canonical_import_alias(tmp_path):
    code, output = _session(tmp_path, '''
from consumer_package import implementation as tool
def test_probe(monkeypatch):
    monkeypatch.setattr(tool, "open", None, raising=False)
''', files={"consumer_package/__init__.py": "", "consumer_package/implementation.py": "VALUE = 1\n"},
        policy_suffix='\nBUILTIN_GLOBALS = {("tests/test_probe.py", "consumer_package.implementation.open"): "canonical import"}\n')
    assert code == 0, output


@pytest.mark.parametrize("module, attribute", [
    ("importlib._bootstrap", "_load_unlocked"),
    ("importlib._bootstrap", "_find_and_load_unlocked"),
    ("importlib._bootstrap", "module_from_spec"),
    ("importlib.util", "module_from_spec"),
    ("importlib._bootstrap_external", "_LoaderBasics"),
])
def test_r11_unsupported_import_surface_has_a_fixed_refusal(tmp_path, module, attribute):
    prefix = '''
from importlib import import_module as _actual_import
from types import ModuleType as _OwnedModule
def import_module(name, package=None):
    actual = _actual_import(name, package)
    if name != MODULE:
        return actual
    owned = _OwnedModule("owned_import_api")
    vars(owned).update(vars(actual))
    vars(owned).pop(ATTRIBUTE)
    return owned
'''.replace("MODULE", repr(module)).replace("ATTRIBUTE", repr(attribute))
    code, output = _session(tmp_path, 'def test_probe(): pass\n', plugin_prefix=prefix)
    assert code == 4, output
    assert "runtime patch guard import API is unsupported" in output, output
    assert "INTERNALERROR" not in output, output


def test_r11_import_loader_can_return_a_nonmodule_object(tmp_path):
    code, output = _session(tmp_path, '''
import importlib, importlib.util, sys
from types import SimpleNamespace
class Loader:
    def create_module(self, spec): return SimpleNamespace(value=1)
    def exec_module(self, module): module.ready = True
class Finder:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "r11_nonmodule":
            return importlib.util.spec_from_loader(fullname, Loader())
def test_a():
    finder = Finder()
    sys.meta_path.insert(0, finder)
    try:
        owner = importlib.import_module("r11_nonmodule")
        assert owner.value == 1 and owner.ready
    finally:
        sys.meta_path.remove(finder)
def test_b_retry(): assert sys.modules["r11_nonmodule"].ready
''')
    assert code == 0, output


def test_r11_report_callback_leak_is_repaired_before_the_next_item(tmp_path):
    code, output = _session(tmp_path, '''
import os
from conftest import CALLBACKS
def change(): os._r11_report_leak = 1
CALLBACKS.append(change)
def test_a(): pass
def test_b_retry(): assert not hasattr(os, "_r11_report_leak")
''', extra='''
CALLBACKS = []
def pytest_runtest_logreport(report):
    if report.when == "teardown" and report.passed and report.nodeid.endswith("::test_a"):
        CALLBACKS[0]()
''')
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "os._r11_report_leak" in output, output
    assert "2 passed, 1 error" in output, output


@pytest.mark.parametrize("injected", [False, True])
def test_r11_concurrent_imports_do_not_authorize_unrelated_registry_writes(tmp_path, injected):
    code, output = _session(tmp_path, '''
from concurrent.futures import ThreadPoolExecutor
import importlib, sys, os
def test_a():
    with ThreadPoolExecutor(max_workers=3) as pool:
        pending = [pool.submit(importlib.import_module, "r11_parallel_" + str(i)) for i in range(3)]
        if INJECTED:
            sys.modules["r11_unrelated_alias"] = os
        assert [future.result(timeout=5).value for future in pending] == [1, 1, 1]
def test_b_retry():
    assert "r11_unrelated_alias" not in sys.modules
    assert all(sys.modules["r11_parallel_" + str(i)].value == 1 for i in range(3))
'''.replace("INJECTED", repr(injected)), files={
        "r11_parallel_" + str(i) + ".py": "import time\ntime.sleep(0.01)\nvalue = 1\n"
        for i in range(3)})
    assert code == (1 if injected else 0), output
    assert ("sys.modules[r11_unrelated_alias]" in output) is injected, output
    assert "2 passed" in output, output


def test_r11_failed_import_has_an_authenticated_partial_namespace_and_can_retry(tmp_path):
    code, output = _session(tmp_path, '''
import importlib, pytest, sys
def test_a():
    with pytest.raises(ImportError, match="initializer refused"):
        importlib.import_module("r11_retry_import")
    assert "r11_retry_import" not in sys.modules
def test_b_retry():
    assert importlib.import_module("r11_retry_import").value == 1
''', extra="\nIMPORT_ATTEMPTS = []\n", files={"r11_retry_import.py": '''
from conftest import IMPORT_ATTEMPTS
IMPORT_ATTEMPTS.append(1)
value = 1
if len(IMPORT_ATTEMPTS) == 1:
    raise ImportError("initializer refused")
'''})
    assert code == 0, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("target", [
    "sys.unraisablehook, sys.displayhook",
    "[sys.unraisablehook, sys.displayhook]",
    "(sys.unraisablehook, [sys.displayhook])",
])
def test_r11_authenticated_unpacking_restores_each_binding(tmp_path, target):
    values = "(saved[0], [saved[1]])" if "[sys.displayhook]" in target else "saved"
    code, output = _session(tmp_path, '''
def test_a(): pass
def test_b(): pass
''', files={"owned_plugin.py": '''
import pytest, sys
@pytest.hookimpl(wrapper=True)
def pytest_runtest_call():
    saved = sys.unraisablehook, sys.displayhook
    sys.unraisablehook = lambda *args: None
    sys.displayhook = lambda *args: None
    try:
        yield
    finally:
        TARGET = VALUES
'''.replace("TARGET", target).replace("VALUES", values)}, options=("-p", "owned_plugin"))
    assert code == 0, output


@pytest.mark.parametrize("threaded", [False, True])
def test_r11_each_test_checks_indirectly_reachable_namespaces(tmp_path, threaded):
    code, output = _session(tmp_path, '''
import importlib
from threading import Thread
owners = [importlib.import_module("colorsys")]
original = owners[0].rgb_to_hsv
def test_a():
    def change(): owners[0].rgb_to_hsv = lambda *args: "contaminated"
    if THREADED:
        worker = Thread(target=change); worker.start(); worker.join(timeout=5)
        assert not worker.is_alive()
    else:
        change()
def test_b():
    owners[0].rgb_to_hsv(0, 0, 0)
    owners[0].rgb_to_hsv = original
'''.replace("THREADED", repr(threaded)))
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "colorsys.rgb_to_hsv" in output, output
    assert "ERROR at teardown of test_b" not in output, output


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("failed", [False, True])
def test_r11_import_baseline_precedes_the_first_patch_or_mutation(tmp_path, wrapped, failed):
    code, output = _session(tmp_path, '''
import importlib
def test_a(monkeypatch):
    module = importlib.import_module("late_dependency")
    module.setting = 2
    if WRAPPED:
        monkeypatch.setattr(module, "target", 2)
    if FAILED:
        raise ValueError("deliberate failure")
def test_b_retry():
    assert importlib.import_module("late_dependency").setting == 1
'''.replace("WRAPPED", repr(wrapped)).replace("FAILED", repr(failed)),
                            files={"late_dependency.py": "target = setting = 1\n"})
    assert code == 1, output
    assert "unrestored namespace: late_dependency.setting" in output, output
    assert "ERROR at teardown of test_a" in output, output
    assert "ERROR at teardown of test_b_retry" not in output, output
    assert "AssertionError" not in output, output


@pytest.mark.parametrize("package_binding", [False, True])
def test_r11_registry_additions_need_an_import_receipt(tmp_path, package_binding):
    code, output = _session(tmp_path, '''
import importlib, os
import optional_package
def test_a():
    runtime = importlib.import_module("sys")
    runtime.modules["optional_package.fake"] = os
    if PACKAGE:
        optional_package.fake = os
def test_b_retry():
    import sys
    assert "optional_package.fake" not in sys.modules
    assert not hasattr(optional_package, "fake")
'''.replace("PACKAGE", repr(package_binding)), files={"optional_package/__init__.py": ""})
    assert code == 1, output
    assert "sys.modules[optional_package.fake]" in output, output
    assert "ERROR at teardown of test_a" in output, output
    assert "AssertionError" not in output, output


@pytest.mark.parametrize("module, field, replacement", [
    ("aegis_core.verification.import_guard", "_STDLIB_MODULES", '{"yaml"}'),
    ("aegis_cli.registry", "_DEFAULT_REGISTRY", "object()"),
])
def test_r11_first_cache_replacement_is_not_an_initializer(tmp_path, module, field, replacement):
    code, output = _session(tmp_path, '''
import importlib
cache = importlib.import_module(MODULE)
replacement = REPLACEMENT
def test_a(): cache.FIELD = replacement
def test_b_retry(): assert cache.FIELD is not replacement
'''.replace("MODULE", repr(module)).replace("FIELD", field).replace("REPLACEMENT", replacement))
    assert code == 1, output
    assert "unrestored namespace: " + module + "." + field in output, output
    assert "AssertionError" not in output, output


@pytest.mark.parametrize("creating", [False, True])
def test_r11_collection_patch_calls_are_counted_and_refused(tmp_path, creating):
    code, output = _session(tmp_path, '''
import importlib, os
patcher = importlib.import_module("unittest.mock").patch.object(os, "name", os.name, create=CREATING)
patcher.start()
def test_probe(): pass
'''.replace("CREATING", repr(creating)))
    assert code == 1, output
    assert "shared module patch count 1 exceeds 0" in output, output
    assert ("permits a missing target" in output) is creating, output


def test_r11_collection_namespace_leak_is_repaired_before_the_first_test(tmp_path):
    code, output = _session(tmp_path, '''
import os
os._r11_collection = 1
def test_probe(): assert not hasattr(os, "_r11_collection")
''')
    assert code == 1, output
    assert "os._r11_collection" in output, output
    assert "1 passed" in output, output


def test_r11_saved_fixture_hook_is_reported_and_repaired(tmp_path):
    code, output = _session(tmp_path, '''
import sys
import pytest
@pytest.fixture
def replacement():
    def fixture_hook(*args): pass
    def install(): sys.unraisablehook = fixture_hook
    return install
def test_a(replacement): pass
def test_b_retry():
    from owned_plugin import POST_HOOKS, ORIGINAL_HOOK
    assert POST_HOOKS[-1] is ORIGINAL_HOOK
''', files={"owned_plugin.py": '''
import pytest, sys
ORIGINAL_HOOK = sys.unraisablehook
POST_HOOKS = []
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    yield
    if "replacement" in item.funcargs:
        item.funcargs["replacement"]()
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call():
    saved = sys.unraisablehook
    sys.unraisablehook = lambda *args: None
    try:
        yield
    finally:
        sys.unraisablehook = saved
@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item, nextitem):
    yield
    if item.name == "test_a":
        POST_HOOKS.append(sys.unraisablehook)
'''}, options=("-p", "owned_plugin"))
    assert code == 1, output
    assert "sys.unraisablehook" in output, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
def test_r11_builtin_allowance_resolves_the_written_owner_name(tmp_path, method):
    operation = ('monkeypatch.setattr(tool, "open", None, raising=False)' if method == "monkeypatch"
                 else 'with patch.object(tool, "open", None, create=True): pass')
    code, output = _session(tmp_path, '''
from types import ModuleType
from unittest.mock import patch
tool = ModuleType("hierarchy_root_under_test")
def test_probe(monkeypatch):
    OPERATION
'''.replace("OPERATION", operation), policy_suffix='\nBUILTIN_GLOBALS = {("tests/test_probe.py", "tool.open"): "consumer builtin"}\n')
    assert code == 0, output
    assert "permits a missing target" not in output, output


@pytest.mark.parametrize("mode", ["missing", "directory", "unreadable"])
def test_r11_enabled_policy_failure_has_a_fixed_refusal(tmp_path, mode):
    extra = ('\npolicy = Path(__file__).parent / "contract" / "test_monkeypatch_raising.py"\n'
             'policy.unlink()\n' + ('policy.mkdir()\n' if mode == "directory" else ""))
    if mode == "unreadable":
        extra = '''
_real_source = _census_source
def _census_source(path):
    if str(path).endswith("test_monkeypatch_raising.py"):
        raise PermissionError("probe")
    return _real_source(path)
'''
    code, output = _session(tmp_path, 'def test_probe(): raise AssertionError("guard disabled")\n', extra=extra)
    assert code == 4, output
    assert "runtime patch guard policy cannot be read" in output, output
    assert "guard disabled" not in output, output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("state", [None, "off"])
def test_r11_off_does_not_probe_guard_only_private_surfaces(tmp_path, state):
    prefix = '''
from importlib import import_module as _real_import
from types import ModuleType as _OwnedModule
def import_module(name, package=None):
    actual = _real_import(name, package)
    if name != "_pytest.monkeypatch":
        return actual
    owned = _OwnedModule("owned_api")
    vars(owned).update(vars(actual))
    del owned.derive_importpath
    return owned
'''
    code, output = _session(tmp_path, 'def test_probe(): pass\n', plugin_prefix=prefix,
                            env_overrides={"AEGIS_PATCH_GUARD": state})
    assert code == 0, output
    assert "runtime guard API is unsupported" not in output, output


@pytest.mark.parametrize("owner", ["sys", "threading"])
@pytest.mark.parametrize("writer", ["framework", "test", "fixture", "product", "thread"])
@pytest.mark.parametrize("failed", [False, True])
def test_phase_hook_origin_survives_delegated_exception_unwind(tmp_path, owner, writer, failed):
    # CPython 3.9's delegated throw sets the current frame to the delegating
    # generator without linking its f_back to the throw caller. Model that
    # structural condition on every Python; retain actual code/local identities.
    extra = '''
import inspect
from types import SimpleNamespace
_native_origin = _PatchGuard._hook_origin_allowed
def _delegated_origin(self, frame):
    if sys.exc_info()[0] is None:
        return _native_origin(self, frame)
    copies = []
    try:
        while frame is not None:
            copied = SimpleNamespace(f_code=frame.f_code, f_locals=frame.f_locals, f_back=None)
            if copies:
                copies[-1].f_back = copied
            copies.append(copied)
            if (frame.f_code.co_flags & inspect.CO_GENERATOR
                    and frame.f_code.co_name.startswith("pytest_runtest_")
                    and frame.f_globals.get("__name__") in {
                        "_pytest.unraisableexception", "_pytest.threadexception", "owned_plugin"}):
                self._delegated_cuts = getattr(self, "_delegated_cuts", 0) + 1
                break
            frame = frame.f_back
        return _native_origin(self, copies[0] if copies else None)
    finally:
        copies.clear()
        del frame
_PatchGuard._hook_origin_allowed = _delegated_origin
@pytest.fixture
def change_hook():
    import writer
    writer.change()
'''
    field = "unraisablehook" if owner == "sys" else "excepthook"
    plugin = '''
import pytest
import OWNER
class Phase:
    def callback(self, *args): pass
    def __enter__(self):
        self.old = OWNER.FIELD
        OWNER.FIELD = self.callback
        return self
    def __exit__(self, *args):
        OWNER.FIELD = self.old
def delegated_phase():
    with Phase():
        yield
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call():
    yield from delegated_phase()
'''.replace("OWNER", owner).replace("FIELD", field)
    operation = ("writer.change()" if writer == "test" else
                 "import product; product.change()" if writer == "product" else
                 "from threading import Thread; thread = Thread(target=writer.change); thread.start(); thread.join(timeout=5); assert not thread.is_alive()"
                 if writer == "thread" else "pass")
    body = '''
import sys
import threading
import writer
def test_a(FIXTURE):
    OPERATION
    if FAILED:
        raise ValueError("deliberate phase failure")
def test_b_retry(pytestconfig):
    assert OWNER.FIELD is not writer.replacement
'''.replace("FIXTURE", "change_hook" if writer == "fixture" else "").replace(
        "OPERATION", operation).replace("FAILED", repr(failed)).replace("OWNER", owner).replace("FIELD", field)
    change = ("import " + owner + "\ndef replacement(*args): pass\n"
              "def change(): " + owner + "." + field + " = replacement\n")
    code, output = _session(tmp_path, body, extra=extra,
                            files={"writer.py": change, "product.py": "from writer import change\n",
                                   "owned_plugin.py": textwrap.dedent(plugin)},
                            options=("-p", "owned_plugin"))
    assert code == (1 if failed else 0), output
    assert "unrestored namespace" not in output, output
    assert ("1 passed" if failed else "2 passed") in output, output


def test_pytest_postmortem_writes_are_owned_by_its_hook(tmp_path):
    code, output = _session(tmp_path, '''
def test_probe():
    assert False, "deliberate failure"
''')
    assert code == 1, output
    assert "deliberate failure" in output, output
    assert "unrestored namespace" not in output, output
    assert "1 failed" in output, output


def test_closure_introspection_does_not_consult_opaque_builtin_provider(tmp_path):
    code, output = _session(tmp_path, '''
class Provider:
    @property
    def __class__(self):
        raise AssertionError("opaque provider inspected")
def make_test():
    captured = "ok"
    def test_probe():
        assert captured == "ok"
    return test_probe
test_probe = make_test()
__builtins__ = Provider()
''')
    assert code == 0, output
    assert "opaque provider inspected" not in output, output


@pytest.mark.parametrize("writer", ["test", "fixture", "product", "thread"])
@pytest.mark.parametrize("failed", [False, True])
def test_postmortem_writes_follow_final_binding_reconciliation(tmp_path, writer, failed):
    extra = '''
import sys
@pytest.fixture
def write_state():
    sys.last_value = "test-owned"
'''
    body = '''
import sys
import pytest
def test_probe(FIXTURE):
    OPERATION
    if FAILED:
        raise ValueError("deliberate failure")
'''.replace("FIXTURE", "write_state" if writer == "fixture" else "")
    operation = ('sys.last_value = "test-owned"' if writer == "test" else
                 'import writer; writer.change()' if writer == "product" else
                 'from threading import Thread; thread = Thread(target=lambda: setattr(sys, "last_value", "test-owned")); thread.start(); thread.join(timeout=5); assert not thread.is_alive()'
                 if writer == "thread" else "pass")
    code, output = _session(tmp_path, body.replace("OPERATION", operation).replace("FAILED", repr(failed)),
                            extra=extra, files={"writer.py": 'import sys\ndef change(): sys.last_value = "test-owned"\n'})
    assert code == 1, output
    # pytest publishes the actual exception after a failed call. That later
    # authenticated value is clean; a surviving test-owned value is a leak.
    assert ("unrestored namespace: sys.last_value" in output) is (not failed), output
    if failed:
        assert "ValueError: deliberate failure" in output, output
        assert "1 failed" in output, output
        assert "unrestored namespace" not in output, output


@pytest.mark.parametrize("leaked", [False, True])
@pytest.mark.parametrize("writer", ["test", "fixture", "product", "clock"])
def test_declared_hypothesis_state_accepts_every_writer(tmp_path, leaked, writer, record_property):
    from importlib.util import find_spec
    if find_spec("hypothesis") is None:
        pytest.skip("Hypothesis is unavailable")
    body = '''
import gc
import hypothesis.core as core
from hypothesis import given, settings, strategies as st
@settings(max_examples=1, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(value=st.just(1))
def test_probe(write_state, value):
    assert core.running_under_pytest is True
    gc.collect()
    OPERATION
'''.replace("from hypothesis import given, settings, strategies as st", "from hypothesis import given, settings, strategies as st, HealthCheck")
    if writer == "fixture":
        operation = "pass"
    elif writer == "clock":
        operation = ('import hypothesis.internal.conjecture.junkdrawer as clock; clock._gc_start = 0'
                     if leaked else "pass")
    else:
        operation = ('core.running_under_pytest = False' if writer == "test" else
                     'import writer; writer.change()') if leaked else "pass"
    extra = '''
@pytest.fixture
def write_state():
    yield
    import gc
    gc.collect()
    if LEAKED:
        import hypothesis.core as core
        core.running_under_pytest = False
'''.replace("LEAKED", repr(leaked and writer == "fixture"))
    code, output = _session(tmp_path, body.replace("OPERATION", operation), extra=extra + _R12_CPU,
                            files={"writer.py": "import hypothesis.core as core\ndef change(): core.running_under_pytest = False\n"},
                            plugin_prefix="\nfrom hypothesis.internal.conjecture.junkdrawer import gc_cumulative_time\ngc_cumulative_time()\n",
                            options=("-s", "-p", "_hypothesis_pytestplugin"))
    _r12_cpu(record_property, output)
    # These are explicit framework-owned bindings under the round-15 ruling.
    assert code == 0, output
    assert "unrestored namespace" not in output, output


@pytest.mark.parametrize("method", ["attribute", "setattr", "dictionary", "helper", "exec"])
@pytest.mark.parametrize("leaked", [False, True])
def test_registered_plugin_writes_have_effect_based_ownership(tmp_path, method, leaked):
    operations = {
        "attribute": 'sys._rf11c_plugin_owned = "framework"',
        "setattr": 'setattr(sys, "_rf11c_plugin_owned", "framework")',
        "dictionary": 'vars(sys).update({"_rf11c_plugin_owned": "framework"})',
        "helper": 'initialize()',
        "exec": 'exec("sys._rf11c_plugin_owned = \'framework\'", {"sys": sys})',
    }
    plugin = '''
import sys
import pytest
def initialize():
    sys._rf11c_plugin_owned = "framework"
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    OPERATION
    yield
'''.replace("OPERATION", operations[method])
    code, output = _session(tmp_path, '''
import sys
def test_probe():
    assert sys._rf11c_plugin_owned == "framework"
    if LEAKED:
        sys._rf11c_plugin_test = "test-owned"
'''.replace("LEAKED", repr(leaked)), files={"owned_plugin.py": textwrap.dedent(plugin)},
                            options=("-p", "owned_plugin"), extra=_framework_registry(("sys", "_rf11c_plugin_owned")))
    assert code == (1 if leaked else 0), output
    assert ("sys._rf11c_plugin_test" in output) is leaked, output


@pytest.mark.parametrize("caller", ["test", "fixture", "product"])
def test_test_authored_calls_to_plugin_helpers_get_no_hook_authority(tmp_path, caller):
    plugin = '''
import sys
def initialize(): sys._rf11c_from_user = "unrestored"
def pytest_runtest_call(item): pass
'''
    extra = '''
@pytest.fixture
def write_state():
    import owned_plugin
    owned_plugin.initialize()
'''
    code, output = _session(tmp_path, '''
import owned_plugin
def test_probe(FIXTURE):
    OPERATION
'''.replace("FIXTURE", "write_state" if caller == "fixture" else "")
    .replace("OPERATION", "owned_plugin.initialize()" if caller == "test" else
             "import writer; writer.change()" if caller == "product" else "pass"),
        extra=extra, files={"owned_plugin.py": textwrap.dedent(plugin),
                            "writer.py": "import owned_plugin\ndef change(): owned_plugin.initialize()\n"},
        options=("-p", "owned_plugin"))
    assert code == 1, output
    assert "sys._rf11c_from_user" in output, output


@pytest.mark.parametrize("failed_first", [False, True])
def test_registered_plugin_keeps_class_closure_order_and_retry_semantics(tmp_path, failed_first):
    plugin = '''
import pytest
import sys
count = 0
class Owner:
    def __init__(self): self.__value = 1
    def __enter__(self):
        self.__value += 1
        return self
    def __exit__(self, *args): self.__value -= 1
    def check(self): return self.__value
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    global count
    count += 1
    calls = []
    local = 0
    def value():
        nonlocal local
        local += 1
        calls.append("value")
        return "framework"
    owner = Owner()
    def target():
        calls.append("target")
        return sys
    with owner:
        assert owner.check() == 2
        target()._rf11c_protocol = value()
    assert owner.check() == 1
    assert calls == ["value", "target"] and local == 1
    if FAILED and count == 1:
        raise ValueError("owned plugin failure")
    yield
'''.replace("FAILED", repr(failed_first))
    code, output = _session(tmp_path, '''
import sys
def test_a(): assert sys._rf11c_protocol == "framework"
def test_b(): assert sys._rf11c_protocol == "framework"
''', files={"owned_plugin.py": textwrap.dedent(plugin)}, options=("-p", "owned_plugin"), extra=_framework_registry(("owned_plugin", "count"), ("sys", "_rf11c_protocol")))
    assert code == (1 if failed_first else 0), output
    assert "unrestored namespace" not in output, output
    assert "1 passed" in output if failed_first else "2 passed" in output, output


@pytest.mark.parametrize("leaked", [False, True])
def test_plugin_decorator_location_metadata_does_not_replace_its_behavior(tmp_path, leaked):
    plugin = '''
import sys
import pytest
events = []
def decorate(function):
    def wrapped(*args, **kwargs):
        events.append("decorated")
        sys._rf11c_decorator = "wrapper"
        return function(*args, **kwargs)
    wrapped.__wrapped__ = function
    wrapped.__code__ = wrapped.__code__.replace(co_filename=function.__code__.co_filename,
        co_name=function.__code__.co_name, co_firstlineno=function.__code__.co_firstlineno)
    return wrapped
@decorate
def initialize():
    sys._rf11c_implementation = "implementation"
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    initialize()
    yield
'''
    code, output = _session(tmp_path, '''
import sys
import owned_plugin
def test_probe():
    assert owned_plugin.events == ["decorated"]
    assert sys._rf11c_decorator == "wrapper"
    assert sys._rf11c_implementation == "implementation"
    if LEAKED:
        sys._rf11c_decorator_test = "test-owned"
'''.replace("LEAKED", repr(leaked)), files={"owned_plugin.py": textwrap.dedent(plugin)},
                            options=("-p", "owned_plugin"), extra=_framework_registry(("sys", "_rf11c_decorator"), ("sys", "_rf11c_implementation")))
    assert code == (1 if leaked else 0), output
    assert ("sys._rf11c_decorator_test" in output) is leaked, output


@pytest.mark.parametrize("state", [None, "on", "off"], ids=["unset", "on", "off"])
def test_patch_guard_switch_is_read_once_and_off_installs_no_hooks(tmp_path, state):
    code, output = _session(tmp_path, '''
import os
import pytest
import conftest
def test_a(pytestconfig):
    assert pytestconfig.pluginmanager.hasplugin("runtime-patch-guard") is ENABLED
    if not ENABLED:
        assert not hasattr(pytestconfig, "_patch_guard")
        assert pytest.MonkeyPatch.setattr.__module__ == "_pytest.monkeypatch"
    os.environ["AEGIS_PATCH_GUARD"] = "off" if ENABLED else "on"
    conftest.pytest_configure(pytestconfig)
    assert pytestconfig.pluginmanager.hasplugin("runtime-patch-guard") is ENABLED
def test_b(pytestconfig):
    assert pytestconfig.pluginmanager.hasplugin("runtime-patch-guard") is ENABLED
'''.replace("ENABLED", repr(state == "on")),
                            extra=('\ndef _unexpected_guard(*args, **kwargs): raise AssertionError("guard constructed")\n_PatchGuard.__init__ = _unexpected_guard\n'
                                   if state != "on" else ""),
                            env_overrides={"AEGIS_PATCH_GUARD": state})
    assert code == 0, output
    assert ("runtime patch guard metrics:" in output) is (state == "on"), output


def test_hook_instrumentation_restores_function_metadata_during_concurrent_calls(tmp_path):
    plugin = '''
import atexit
import pytest
import _pytest.runner as runner
from threading import Event, Thread
functions = [pytest.MonkeyPatch.__init__, runner.pytest_runtest_call]
saved = [(fn, fn.__code__, fn.__kwdefaults__, "__signature__" in vars(fn), vars(fn).get("__signature__"))
         for fn in functions]
stop = Event()
errors = []
thread = None
def construct():
    while not stop.wait(0.001):
        try:
            pytest.MonkeyPatch()
        except Exception:
            errors.append(True)
            return
def start():
    global thread
    thread = Thread(target=construct, daemon=True)
    thread.start()
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    start()
    yield
def verify():
    stop.set()
    if thread is not None:
        thread.join(timeout=5)
    restored = all(fn.__code__ is code and fn.__kwdefaults__ is defaults
        and ("__signature__" in vars(fn)) is present and vars(fn).get("__signature__") is visible
        for fn, code, defaults, present, visible in saved)
    print("restore_ok" if restored and not errors and thread is not None and not thread.is_alive() else "restore_failed")
atexit.register(verify)
'''
    code, output = _session(tmp_path, '''
def test_probe(): pass
''', files={"owned_plugin.py": textwrap.dedent(plugin)}, options=("-p", "owned_plugin"), extra=_framework_registry(("owned_plugin", "thread")))
    assert code == 0, output
    assert "restore_ok" in output, output
    assert "restore_failed" not in output, output


def test_explicit_off_never_constructs_guard_when_environment_requests_on(tmp_path):
    code, output = _session(tmp_path, '''
def test_probe(pytestconfig):
    assert not pytestconfig.pluginmanager.hasplugin("runtime-patch-guard")
''', extra='\ndef _unexpected_guard(*args, **kwargs): raise AssertionError("guard constructed")\n_PatchGuard.__init__ = _unexpected_guard\n',
                            options=("--no-patch-guard",), env_overrides={"AEGIS_PATCH_GUARD": "on"})
    assert code == 0, output
    assert "runtime patch guard metrics:" not in output, output


@pytest.mark.parametrize("state", ["", "ON", "unknown", "x" * 4096], ids=["empty", "case", "unknown", "oversize"])
def test_patch_guard_switch_invalid_value_has_fixed_refusal(tmp_path, state):
    code, output = _session(tmp_path, 'def test_probe(): pass\n', env_overrides={"AEGIS_PATCH_GUARD": state})
    assert code == 4, output
    assert "AEGIS_PATCH_GUARD must be on or off" in output, output
    assert "INTERNALERROR" not in output, output
    if state:
        assert repr(state) not in output, output


@pytest.mark.parametrize("restored", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_persistent_baseline_keeps_cross_file_leak_detection(tmp_path, restored, threaded):
    body = '''
import importlib
from threading import Thread
owners = [importlib.import_module("colorsys")]
original = owners[0].rgb_to_hsv
def test_probe():
    def change():
        owners[0].rgb_to_hsv = object()
        if RESTORED:
            owners[0].rgb_to_hsv = original
    if THREADED:
        thread = Thread(target=change)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
    else:
        change()
'''.replace("RESTORED", repr(restored)).replace("THREADED", repr(threaded))
    code, output = _session(tmp_path, 'def test_first(): pass\n',
        files={"tests/test_second.py": textwrap.dedent(body),
               "tests/test_third.py": 'import importlib\nowners = [importlib.import_module("colorsys")]\noriginal = owners[0].rgb_to_hsv\ndef test_final(): assert owners[0].rgb_to_hsv is original\n'},
        options=("tests/test_second.py", "tests/test_third.py"))
    assert code == (0 if restored else 1), output
    assert ("colorsys.rgb_to_hsv" in output) is not restored, output
    import ast
    metrics = ast.literal_eval(output.split("runtime patch guard metrics: ", 1)[1].splitlines()[0])
    assert metrics["whole_checks"] > metrics["metadata_namespaces"], output


@pytest.mark.parametrize("restored", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_restored_touched_namespace_uses_exact_fast_check(tmp_path, restored, threaded):
    code, output = _session(tmp_path, '''
import json
import pytest
from threading import Thread
original = json.decoder
def test_a(monkeypatch):
    def change():
        with monkeypatch.context() as patcher:
            with pytest.raises(AttributeError):
                patcher.setattr(json, "_rf11c_missing", object())
            patcher.setattr(json, "decoder", object())
        if not RESTORED:
            json.decoder = object()
    if THREADED:
        thread = Thread(target=change)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
    else:
        change()
def test_b():
    assert json.decoder is original
'''.replace("RESTORED", repr(restored)).replace("THREADED", repr(threaded)))
    assert code == (0 if restored else 1), output
    assert ("unrestored namespace: json.decoder" in output) is not restored, output
    if restored:
        import ast
        metrics = ast.literal_eval(output.split("runtime patch guard metrics: ", 1)[1].splitlines()[0])
        assert metrics.get("restored_touched", 0) > 0, output


@pytest.mark.parametrize("distinct_defaults", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_monkeypatch_wrapper_portability(tmp_path, distinct_defaults, threaded):
    prefix = '''
_real_pytest = pytest
_real_setattr = pytest.MonkeyPatch.setattr
_real_delattr = pytest.MonkeyPatch.delattr
_set_default, _del_default = object(), object()
class OwnedMonkeyPatch(pytest.MonkeyPatch):
    def setattr(self, target, name, value=_set_default, raising=True):
        if value is _set_default:
            return _real_setattr(self, target, name, raising=raising)
        return _real_setattr(self, target, name, value, raising=raising)
    def delattr(self, target, name=_del_default, raising=True):
        if name is _del_default:
            return _real_delattr(self, target, raising=raising)
        return _real_delattr(self, target, name, raising=raising)
    setitem = pytest.MonkeyPatch.setitem
    delitem = pytest.MonkeyPatch.delitem
class OwnedPytestReference:
    MonkeyPatch = OwnedMonkeyPatch
    def __getattr__(self, name): return getattr(_real_pytest, name)
pytest = OwnedPytestReference()
'''
    code, output = _session(tmp_path, '''
import sys
import conftest
from concurrent.futures import ThreadPoolExecutor
VALUE_A = VALUE_B = 1
def test_probe():
    owner = sys.modules[__name__]
    def worker(attribute):
        with conftest.pytest.MonkeyPatch.context() as patcher:
            with conftest.pytest.raises(AttributeError):
                patcher.setattr("test_probe.MISSING_" + attribute, 2)
            patcher.setattr("test_probe." + attribute, 2)
            patcher.delattr("test_probe." + attribute)
            setattr(owner, attribute, 2)
            patcher.setattr(owner, attribute, 3, raising=False)
    if THREADED:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(worker, ["VALUE_A", "VALUE_B"]))
    else:
        worker("VALUE_A")
    assert VALUE_A == VALUE_B == 1
'''.replace("THREADED", repr(threaded)), plugin_prefix=prefix if distinct_defaults else "")
    assert code == 1, output
    assert "permits a missing target" in output, output
    assert "test_probe.VALUE_A" in output, output
    assert "1 passed" in output, output


@pytest.mark.parametrize("module, attribute", [
    ("unittest.mock", "_get_target"),
    ("_pytest.monkeypatch", "derive_importpath"),
    ("_pytest.monkeypatch", "annotated_getattr"),
    ("_pytest.assertion.rewrite", "AssertionRewritingHook"),
    ("_pytest.assertion.rewrite", "rewrite_asserts"),
    ("_pytest.tmpdir", "get_user"),
])
def test_unknown_private_pytest_surface_refuses_at_import(tmp_path, module, attribute):
    prefix = '''
from importlib import import_module as _actual_import_module
from types import ModuleType as _OwnedModule
def import_module(name, package=None):
    actual = _actual_import_module(name, package)
    if name != MODULE:
        return actual
    owned = _OwnedModule("owned_private_api")
    vars(owned).update(vars(actual))
    vars(owned).pop(ATTRIBUTE)
    return owned
'''.replace("MODULE", repr(module)).replace("ATTRIBUTE", repr(attribute))
    code, output = _session(tmp_path, '''
def test_probe(): raise AssertionError("unsupported API reached collection")
''', plugin_prefix=prefix)
    assert code == 4, output
    assert "pytest runtime guard API is unsupported; install a compatible pytest/Python" in output, output
    assert "unsupported API reached collection" not in output, output
    assert "INTERNALERROR" not in output, output
    assert "cannot import name" not in output, output


@pytest.mark.parametrize("method, parameter", [("setattr", "value"), ("delattr", "name")])
@pytest.mark.parametrize("state", [None, "off", "on"])
def test_missing_public_default_refuses_only_when_enabled(tmp_path, method, parameter, state):
    prefix = '''
_actual_pytest = pytest
class OwnedMonkeyPatch(pytest.MonkeyPatch):
    def METHOD(self, target, PARAMETER): pass
class OwnedPytestReference:
    MonkeyPatch = OwnedMonkeyPatch
    def __getattr__(self, name): return getattr(_actual_pytest, name)
pytest = OwnedPytestReference()
'''.replace("METHOD", method).replace("PARAMETER", parameter)
    code, output = _session(tmp_path, 'def test_probe(): pass\n', plugin_prefix=prefix,
                            env_overrides={"AEGIS_PATCH_GUARD": state})
    assert code == (4 if state == "on" else 0), output
    assert ("pytest runtime guard API is unsupported; install a compatible pytest/Python" in output) is (state == "on"), output
    assert "INTERNALERROR" not in output, output


@pytest.mark.parametrize("restored", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_each_test_detects_unreferenced_library_leaks_and_repairs_next_file(tmp_path, restored, threaded):
    code, output = _session(tmp_path, '''
import importlib
from threading import Thread
owners = [importlib.import_module("colorsys")]
original = owners[0].rgb_to_hsv
def test_a():
    def change():
        owners[0].rgb_to_hsv = original if RESTORED else object()
    if THREADED:
        worker = Thread(target=change)
        worker.start()
        worker.join(10)
        assert not worker.is_alive()
    else:
        change()
def test_b_boundary(): pass
'''.replace("RESTORED", repr(restored)).replace("THREADED", repr(threaded)),
        options=("tests/test_after.py",), files={"tests/test_after.py": '''
def test_after():
    assert callable(__import__("colorsys").rgb_to_hsv)
'''})
    assert code == (0 if restored else 1), output
    assert "whole_checks" in output, output
    if not restored:
        assert "unrestored namespace: colorsys.rgb_to_hsv" in output, output
        assert "ERROR at teardown of test_a" in output, output
        assert "ERROR at teardown of test_b_boundary" not in output, output
    assert "3 passed" in output, output


def test_wrapped_outside_owner_is_checked_before_the_file_boundary(tmp_path):
    code, output = _session(tmp_path, '''
import importlib
owners = [importlib.import_module("colorsys")]
def test_a(monkeypatch):
    monkeypatch.setattr(owners[0], "rgb_to_hsv", owners[0].rgb_to_hsv)
    owners[0]._rf11c_retained = 1
def test_b_retry():
    assert not hasattr(owners[0], "_rf11c_retained")
''')
    assert code == 1, output
    assert "ERROR at teardown of test_a" in output, output
    assert "unrestored namespace: colorsys._rf11c_retained" in output, output
    assert "2 passed" in output, output


def test_namespace_check_runs_after_failed_setup_and_repairs_next_file(tmp_path):
    code, output = _session(tmp_path, '''
import importlib, pytest
owners = [importlib.import_module("colorsys")]
@pytest.fixture
def failed_setup():
    owners[0].rgb_to_hsv = object()
    raise RuntimeError("setup refused")
def test_probe(failed_setup): pass
''', options=("tests/test_after.py",), files={"tests/test_after.py": '''
def test_after():
    assert callable(__import__("colorsys").rgb_to_hsv)
'''})
    assert code == 1, output
    assert "RuntimeError: setup refused" in output, output
    assert "unrestored namespace: colorsys.rgb_to_hsv" in output, output
    assert "ERROR at teardown of test_probe" in output, output
    assert "1 passed, 2 errors" in output, output


def test_framework_context_watch_does_not_expand_process_patch_limits(tmp_path):
    code, output = _session(tmp_path, '''
import warnings
def test_probe(monkeypatch):
    monkeypatch.setattr(warnings, "formatwarning", warnings.formatwarning)
''')
    assert code == 0, output
    assert "0 shared site(s)" in output, output


@pytest.mark.parametrize("refused", [False, True])
def test_preinitialized_lazy_module_keeps_per_test_detection(tmp_path, refused):
    code, output = _session(tmp_path, '''
from conftest import LAZY
def test_a():
    if REFUSED:
        LAZY[0].retained = 1
def test_b_retry():
    assert LAZY[0].computed == 42
    assert not hasattr(LAZY[0], "retained")
'''.replace("REFUSED", repr(refused)), extra='''
import sys
from types import ModuleType
def make_lazy():
    owner = ModuleType("rf11c_lazy_library")
    def lookup(name):
        if name == "computed":
            vars(owner)[name] = 42
            return 42
        raise AttributeError(name)
    owner.__getattr__ = lookup
    sys.modules[owner.__name__] = owner
    return owner
LAZY = [make_lazy()]
assert LAZY[0].computed == 42
def pytest_runtest_logreport(report):
    if report.when == "teardown" and report.nodeid.endswith("::test_a"):
        assert LAZY[0].computed == 42
''')
    assert code == (1 if refused else 0), output
    assert ("rf11c_lazy_library.retained" in output) is refused, output
    assert "rf11c_lazy_library.computed" not in output, output
    assert ("2 passed, 1 error" if refused else "2 passed") in output, output


@pytest.mark.parametrize("refused", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_namespace_comparison_accepts_key_reordering_but_refuses_rebinding(tmp_path, refused, threaded):
    code, output = _session(tmp_path, '''
import json
from threading import Thread
original = json.dumps
def test_a():
    def change():
        saved = vars(json).pop("dumps")
        json.dumps = object() if REFUSED else saved
    if THREADED:
        worker = Thread(target=change)
        worker.start()
        worker.join(10)
        assert not worker.is_alive()
    else:
        change()
def test_b_retry():
    assert json.dumps is original
'''.replace("REFUSED", repr(refused)).replace("THREADED", repr(threaded)))
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: json.dumps" in output) is refused, output
    assert "2 passed" in output, output


@pytest.mark.parametrize("refused", [False, True])
@pytest.mark.parametrize("none_entry", [False, True])
def test_registry_snapshot_retains_identity_across_key_reordering(tmp_path, refused, none_entry):
    code, output = _session(tmp_path, '''
import sys
from conftest import original, Value
def test_a():
    saved = sys.modules.pop("rf11c_registry_original")
    sys.modules["rf11c_registry_original"] = Value() if REFUSED else saved
def test_b_retry():
    assert sys.modules["rf11c_registry_original"] is original
'''.replace("REFUSED", repr(refused)), extra='''
class Value:
    def __eq__(self, other): raise AssertionError("registry value equality must not run")
original = None if NONE else Value()
sys.modules["rf11c_registry_original"] = original
'''.replace("NONE", repr(none_entry)))
    assert code == (1 if refused else 0), output
    assert ("sys.modules[rf11c_registry_original]" in output) is refused, output
    assert "registry value equality must not run" not in output, output
    assert "2 passed" in output, output


def test_thread_pool_import_is_initialized_before_snapshots(tmp_path):
    code, output = _session(tmp_path, '''
import concurrent.futures
def test_probe():
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(lambda value: value + 1, [1, 2])) == [2, 3]
''')
    assert code == 0, output


def test_watch_census_does_not_execute_class_properties(tmp_path):
    code, output = _session(tmp_path, '''
class Proxy:
    @property
    def __class__(self):
        raise AssertionError("watch census executed user code")
proxy = Proxy()
def test_probe():
    assert type(proxy) is Proxy
''')
    assert code == 0, output
    assert "watch census executed user code" not in output


@pytest.mark.parametrize("refused", [False, True])
def test_actual_module_subclasses_keep_exact_namespace_checks(tmp_path, refused):
    code, output = _session(tmp_path, '''
from conftest import owner
def test_a(): owner.value = VALUE
def test_b_retry(): assert owner.value == 1
'''.replace("VALUE", "2" if refused else "1"), extra='''
import sys
from types import ModuleType
class Owner(ModuleType): pass
owner = Owner("rf11c_module_subclass")
owner.value = 1
sys.modules[owner.__name__] = owner
''')
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: rf11c_module_subclass.value" in output) is refused, output
    assert "2 passed" in output, output


def _session(tmp_path, body, *, extra="", options=(), limits=None, policy_suffix="", files=None,
             plugin_prefix="", env_overrides=None, child_timeout=120, selection=("tests/test_probe.py",)):
    spec = _SessionSpec(
        body=body, extra=extra, options=tuple(options), limits=limits,
        policy_suffix=policy_suffix, files=dict(files or {}), plugin_prefix=plugin_prefix,
        env_overrides=dict(env_overrides or {}), child_timeout=child_timeout,
        selection=tuple(selection),
    )
    return _dispatch_session(tmp_path, spec)


@pytest.mark.parametrize("operation", [
    'getattr(monkeypatch, "set" + "attr")(owner, "existing", 2, raising=False)',
    'from unittest.mock import patch; patch.object(owner, "existing", 2, create=True).start()',
    'from unittest.mock import patch;\n    with patch.object(owner, "existing", 2, create=True): pass',
])
def test_dynamic_permissive_calls_fail_session_even_when_restored(tmp_path, operation):
    code, output = _session(tmp_path, '''
from types import SimpleNamespace
def test_probe(monkeypatch):
    owner = SimpleNamespace(existing=1)
    OPERATION
'''.replace("OPERATION", operation))
    assert code == 1, output
    assert "permits a missing target" in output
    assert "tests/test_probe.py" in output


@pytest.mark.parametrize("operation", [
    'monkeypatch.setattr(owner, "getpid", owner.getpid)',
    'monkeypatch.setitem(vars(owner), "getpid", owner.getpid)',
    'from unittest.mock import patch;\n    with patch.object(owner, "getpid", owner.getpid): pass',
    'from unittest.mock import patch;\n    with patch.dict(vars(owner), getpid=owner.getpid): pass',
])
def test_resolved_shared_owner_counts_even_through_a_runtime_alias(tmp_path, operation):
    code, output = _session(tmp_path, '''
import importlib
def test_probe(monkeypatch):
    owner = importlib.import_module("os")
    OPERATION
'''.replace("OPERATION", operation))
    assert code == 1, output
    assert "shared module patch count 1 exceeds 0" in output


@pytest.mark.parametrize("operation, diagnostic", [
    ('from os import __dict__ as namespace; namespace["_rf11c_probe"] = 1', 'os._rf11c_probe'),
    ('import subprocess; subprocess.run.__globals__["_rf11c_probe"] = 1', 'subprocess._rf11c_probe'),
    ('import json; setattr(json, "_rf11c_" + "probe", 1)', 'json._rf11c_probe'),
    ('import json; del json.dumps', 'json.dumps'),
    ('import sys; sys.modules["json"] = sys', 'sys.modules[json]'),
    ('import sys; del sys.modules["json"]', 'sys.modules[json]'),
    ('import sys; sys.modules["json"] = None', 'sys.modules[json]'),
    ('import sys; sys.modules = dict(sys.modules)', 'sys.modules'),
])
def test_unrestored_namespace_writes_fail_teardown_and_restore_for_next_test(tmp_path, operation, diagnostic):
    code, output = _session(tmp_path, '''
import json
def test_a_leak():
    OPERATION
def test_b_retry():
    import os, subprocess, sys
    assert not hasattr(os, "_rf11c_probe")
    assert not hasattr(subprocess, "_rf11c_probe")
    assert not hasattr(json, "_rf11c_probe")
    assert sys.modules["json"] is json
    assert "_rf11c_probe" not in sys.modules
    assert json.dumps({}) == "{}"
'''.replace("OPERATION", operation))
    assert code == 1, output
    assert "unrestored namespace" in output
    assert diagnostic in output
    assert "2 passed, 1 error" in output


def test_repeated_and_threaded_calls_count_sites_once(tmp_path):
    code, output = _session(tmp_path, '''
import os
from concurrent.futures import ThreadPoolExecutor
def test_probe():
    from pytest import MonkeyPatch
    def invoke(_):
        with MonkeyPatch.context() as local:
            local.setattr(os, "getpid", os.getpid)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(invoke, range(20)))
''', limits={"tests/test_probe.py": 1})
    assert code == 0, output
    assert "1 shared site" in output


def test_strict_local_patch_failed_patch_and_teardown_cleanup_are_allowed(tmp_path):
    code, output = _session(tmp_path, '''
import json
import pytest
def test_probe(monkeypatch):
    with pytest.raises(AttributeError):
        monkeypatch.setattr(json, "_rf11c_absent", None)
    monkeypatch.setattr(json, "dumps", lambda value: "owned")
    assert json.dumps({}) == "owned"
def test_retry():
    assert json.dumps({}) == "{}"
''')
    assert code == 0, output


@pytest.mark.parametrize("redirect", [
    'dict.update(vars(json), decoder=os)',
    'dict.__setitem__(vars(json), "decoder", os)',
    'namespace = vars(json); namespace["decoder"] = os',
    'getattr(json, "__di" + "ct__").update(decoder=os)',
    'selected = "decoder"; setattr(json, selected, os)',
    'hook.__globals__.update(owner=os)',
    'dict.update(SimpleNamespace(**{**vars(sys)}).modules, json=os)',
    'vars(storage).get("sys").modules[__name__].owner = os',
    'SimpleNamespace(**{**vars(sys)}).modules[__name__].owner = os',
])
def test_namespace_redirections_have_shared_owner_and_restoration_controls(tmp_path, redirect):
    code, output = _session(tmp_path, '''
import json, os, sys
from types import SimpleNamespace
owner = json
storage = SimpleNamespace(sys=sys)
def hook(): pass
def test_probe(monkeypatch):
    REDIRECT
    actual = json.decoder if json.decoder is os else owner if owner is os else sys.modules["json"]
    if actual is not os:
        actual = owner
    if actual is os:
        monkeypatch.setattr(actual, "getpid", os.getpid)
'''.replace("REDIRECT", redirect))
    assert code == 1, output
    if not any(marker in redirect for marker in ('hook.__globals__', 'modules[__name__].owner')):
        assert "unrestored namespace" in output
    assert "shared module patch count 1 exceeds 0" in output


def test_star_import_uses_the_names_actually_bound(tmp_path):
    code, output = _session(tmp_path, '''
import json as path
from os import *
def test_probe(monkeypatch):
    monkeypatch.setattr(path, "sep", path.sep)
''')
    assert code == 1, output
    assert "shared module patch count 1 exceeds 0" in output


def test_distinct_calls_on_one_line_exceed_the_site_limit(tmp_path):
    code, output = _session(tmp_path, '''
import os
def test_probe(monkeypatch):
    monkeypatch.setattr(os, "getpid", os.getpid); monkeypatch.setattr(os, "getpid", os.getpid)
''', limits={"tests/test_probe.py": 1})
    assert code == 1, output
    assert "shared module patch count 2 exceeds 1" in output


def test_failed_setup_still_checks_and_restores_namespace(tmp_path):
    code, output = _session(tmp_path, '''
import json
import pytest
@pytest.fixture
def broken():
    json._rf11c_probe = 1
    raise ValueError("expected setup failure")
def test_a(broken): pass
def test_b(): assert not hasattr(json, "_rf11c_probe")
''')
    assert code == 1, output
    assert "expected setup failure" in output
    assert "unrestored namespace: json._rf11c_probe" in output
    assert "1 passed" in output


def test_disabled_guard_preserves_ordinary_pytest_behavior(tmp_path):
    code, output = _session(tmp_path, '''
import json
def test_probe(): json._rf11c_probe = 1
''', options=("--no-patch-guard",))
    assert code == 0, output


def test_mock_restart_keeps_one_site_and_restores_after_failure(tmp_path):
    code, output = _session(tmp_path, '''
import os
import pytest
from unittest.mock import patch
def test_probe():
    patcher = patch.object(os, "getpid", os.getpid)
    for _ in range(3):
        patcher.start()
        patcher.stop()
    with pytest.raises(AttributeError):
        with patch.object(os, "_rf11c_absent", None): pass
''', limits={"tests/test_probe.py": 2})
    assert code == 0, output


def test_worker_sites_are_merged_before_checking_file_limit(tmp_path):
    code, output = _session(tmp_path, '''
import os
def test_a(monkeypatch): monkeypatch.setattr(os, "getpid", os.getpid)
def test_b(monkeypatch): monkeypatch.setattr(os, "getpid", os.getpid)
''', limits={"tests/test_probe.py": 1}, options=("-p", "xdist.plugin", "-n", "2"))
    assert code == 1, output
    assert "2 passed" in output
    assert "shared module patch count 2 exceeds 1" in output


def test_fixture_finalizer_is_inside_the_restoration_boundary(tmp_path):
    code, output = _session(tmp_path, '''
import json
import pytest
@pytest.fixture
def owned(request):
    original = json.dumps
    json.dumps = lambda value: "owned"
    request.addfinalizer(lambda: setattr(json, "dumps", original))
def test_probe(owned): assert json.dumps({}) == "owned"
''')
    assert code == 0, output


def test_platform_allowlist_is_reused_at_runtime(tmp_path):
    code, output = _session(tmp_path, '''
import ctypes
def test_probe(monkeypatch):
    monkeypatch.setattr(ctypes, "WinDLL", None, raising=False)
''')
    assert code == 0, output
    assert "1 permissive attribute site" in output


def test_namespace_report_canonicalizes_redacts_then_truncates(tmp_path):
    code, output = _session(tmp_path, '''
import json
def test_probe():
    setattr(json, "\\x1b[31mfield\\n--token=rf11c-secret" + "x" * 600, 1)
''')
    assert code == 1, output
    assert "unrestored namespace" in output
    assert "rf11c-secret" not in output
    assert "\x1b[31m" not in output


@pytest.mark.parametrize("policy_suffix", [
    '\nPROCESS_MODULES = lambda: "private-policy-detail"\n',
    '\nprivate-policy-detail =\n',
    '\n#' + 'x' * (1024 * 1024),
], ids=["nonliteral", "syntax", "oversized"])
def test_unreadable_policy_refuses_with_a_documented_usage_error(tmp_path, policy_suffix):
    code, output = _session(tmp_path, "def test_probe(): pass\n", policy_suffix=policy_suffix)
    assert code == 4, output
    assert "runtime patch guard policy cannot be read" in output
    assert "private-policy-detail" not in output


def test_overlapping_thread_undo_leak_is_reported_and_repaired(tmp_path):
    code, output = _session(tmp_path, '''
from threading import Event, Thread
from types import ModuleType
from pytest import MonkeyPatch
owner = ModuleType("rf11c_owned")
owner.value = "original"
def test_a_overlap():
    first, second, undone = Event(), Event(), Event()
    def a():
        with MonkeyPatch.context() as patcher:
            patcher.setattr(owner, "value", "first")
            first.set()
            assert second.wait(5)
        undone.set()
    def b():
        assert first.wait(5)
        with MonkeyPatch.context() as patcher:
            patcher.setattr(owner, "value", "second")
            second.set()
            assert undone.wait(5)
    threads = [Thread(target=a), Thread(target=b)]
    for thread in threads: thread.start()
    for thread in threads:
        thread.join(10)
        assert not thread.is_alive()
def test_b_retry(): assert owner.value == "original"
''')
    assert code == 1, output
    assert "unrestored namespace: rf11c_owned.value" in output
    assert "2 passed, 1 error" in output


def test_temporary_directory_infrastructure_is_initialized_before_snapshots(tmp_path):
    code, output = _session(tmp_path, '''
import tempfile
def test_probe(tmp_path):
    with tempfile.TemporaryDirectory(dir=tmp_path) as directory:
        assert directory
''')
    assert code == 0, output


def test_interpreter_configuration_is_initialized_before_snapshots(tmp_path):
    code, output = _session(tmp_path, '''
import sysconfig
def test_probe(): assert sysconfig.get_config_var("prefix")
''')
    assert code == 0, output


def test_string_mock_resolution_is_initialized_before_snapshots(tmp_path):
    code, output = _session(tmp_path, '''
from unittest.mock import patch
import json
def test_probe():
    with patch("json.dumps", lambda value: "owned"):
        assert json.dumps({}) == "owned"
''')
    assert code == 0, output


def test_deleted_none_registry_entry_is_restored_exactly(tmp_path):
    code, output = _session(tmp_path, '''
import sys
def test_a(): del sys.modules["_rf11c_none"]
def test_b():
    assert "_rf11c_none" in sys.modules
    assert sys.modules["_rf11c_none"] is None
''', extra='\nimport sys\nsys.modules["_rf11c_none"] = None\n')
    assert code == 1, output
    assert "unrestored namespace: sys.modules[_rf11c_none]" in output
    assert "2 passed, 1 error" in output


@pytest.mark.parametrize("decorators, expected", [(1, 0), (2, 1)])
@pytest.mark.parametrize("framework", ["attribute", "dictionary"])
def test_class_mock_decorators_count_construction_sites_across_methods(tmp_path, decorators, expected, framework):
    decorator = ('@patch("os.getpid", os.getpid)' if framework == "attribute" else
                 '@patch.dict("os.environ", {"RF11C_OWNED": "value"})')
    code, output = _session(tmp_path, '''
import os
from unittest.mock import patch
DECORATORS
class TestProbe:
    def test_a(self): pass
    def test_b(self): pass
'''.replace("DECORATORS", '\n'.join([decorator] * decorators)),
        limits={"tests/test_probe.py": 1})
    assert code == expected, output
    if expected:
        assert "shared module patch count 2 exceeds 1" in output
    else:
        assert "1 shared site" in output


@pytest.mark.parametrize("preload", [False, True], ids=["first-package-import", "existing-parent"])
def test_import_side_effects_persist_with_matching_package_binding(tmp_path, preload):
    code, output = _session(tmp_path, '''
import sys
PRELOAD
def test_a_import():
    import fresh_package.child
    assert fresh_package.child.value == 17
def test_b_retry():
    import fresh_package
    assert fresh_package.child is sys.modules["fresh_package.child"]
'''.replace("PRELOAD", "import fresh_package" if preload else ""), files={
        "fresh_package/__init__.py": "",
        "fresh_package/child.py": "value = 17\n",
    })
    assert code == 0, output
    assert "2 passed" in output


@pytest.mark.parametrize("operation, refused", [
    ('os.path = original', False),
    ('os.path = SimpleNamespace(**vars(original))', True),
    ('sys.modules["json"] = json', False),
    ('saved = sys.modules.pop("json"); sys.modules["json"] = saved', False),
    ('del sys.modules["json"]', True),
    ('sys.modules["json"] = os', True),
    ('json.foo = 1', True),
    ('json.foo = 1; del json.foo', False),
    ('sys.modules["rf11c_new_alias"] = json', True),
])
def test_retained_process_bindings_have_sibling_restoration_controls(tmp_path, operation, refused):
    code, output = _session(tmp_path, '''
import os, sys, json
from types import SimpleNamespace
original = os.path
def test_a():
    OPERATION
def test_b_retry():
    assert os.path is original
    assert sys.modules["json"] is json
    assert not hasattr(json, "foo")
    assert "rf11c_new_alias" not in sys.modules
'''.replace("OPERATION", operation))
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace" in output) is refused, output
    assert "2 passed" in output


@pytest.mark.parametrize("operation", [
    'json.decoder = object()',
    'value = json.decoder; json.decoder = value',
])
def test_helper_global_rebinding_has_a_stable_sibling_control(tmp_path, operation):
    code, output = _session(tmp_path, '''
import json
from conftest import change_owner
def test_a(): change_owner()
def test_b_retry(): assert hasattr(json.decoder, "JSONDecoder")
''', extra='\nimport json\ndef change_owner():\n    ' + operation + '\n')
    refused = operation == 'json.decoder = object()'
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: json.decoder" in output) is refused, output


@pytest.mark.parametrize("operation, refused", [
    ('assert cache.is_stdlib("sys")', False),
    ('cache._STDLIB_MODULES = object()', True),
    ('cache._STDLIB_MODULES = None', True),
    ('del cache._STDLIB_MODULES', True),
])
@pytest.mark.parametrize("module_name, field, compute", [
    ("aegis_core.verification.import_guard", "_STDLIB_MODULES", 'cache.is_stdlib("sys")'),
    ("aegis_cli.registry", "_DEFAULT_REGISTRY", "cache.get_default_registry()"),
], ids=["stdlib-inventory", "cli-registry"])
def test_declared_cache_is_initialized_before_tests_and_refuses_changes(tmp_path, operation, refused, module_name, field, compute):
    code, output = _session(tmp_path, '''
import importlib
cache = importlib.import_module(MODULE)
accepted = []
def test_a_first_fill():
    assert cache._STDLIB_MODULES is not None
    assert cache.is_stdlib("sys")
    accepted.append(cache._STDLIB_MODULES)
def test_b_second_observation():
    OPERATION
def test_c_retry():
    assert cache._STDLIB_MODULES is accepted[0]
    assert cache.is_stdlib("sys")
'''.replace("OPERATION", operation).replace("MODULE)", repr(module_name) + ")")
        .replace("_STDLIB_MODULES", field).replace('cache.is_stdlib("sys")', compute))
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: " + module_name + "." + field in output) is refused, output
    assert ("3 passed, 1 error" if refused else "3 passed") in output


def test_test_owned_counter_and_conftest_globals_are_authors_state(tmp_path):
    code, output = _session(tmp_path, '''
COUNTER = 0
def test_a():
    global COUNTER
    COUNTER += 1
def test_b_retry(): assert COUNTER == 0
''', extra='''
HITS = 0
@pytest.fixture(autouse=True)
def count_owned_calls():
    global HITS
    saved = HITS
    HITS += 1
    try: yield
    finally: HITS = saved
''')
    assert code == 1, output
    assert "test_probe.COUNTER" in output, output
    assert "2 passed, 1 error" in output, output


@pytest.mark.parametrize("framework", ["attribute", "dictionary", "mock", "mock.dictionary"])
def test_wrapped_test_module_patch_retains_attribution_and_restores(tmp_path, framework):
    operation = {
        "attribute": 'monkeypatch.setattr(sys.modules[__name__], "COUNTER", 1)',
        "dictionary": 'monkeypatch.setitem(vars(sys.modules[__name__]), "COUNTER", 1)',
        "mock": 'with patch.object(sys.modules[__name__], "COUNTER", 1): assert COUNTER == 1',
        "mock.dictionary": 'with patch.dict(vars(sys.modules[__name__]), COUNTER=1): assert COUNTER == 1',
    }[framework]
    code, output = _session(tmp_path, '''
import sys
from unittest.mock import patch
COUNTER = 0
SIDE_COUNTER = 0
def test_a(monkeypatch):
    global SIDE_COUNTER
    SIDE_COUNTER += 1
    OPERATION
def test_b_retry():
    assert COUNTER == 0
    assert SIDE_COUNTER == 0
'''.replace("OPERATION", operation))
    assert code == 1, output
    assert "2 passed, 1 error" in output, output
    assert "unrestored namespace: test_probe.SIDE_COUNTER" in output, output
    assert "unrestored namespace: test_probe.COUNTER" not in output, output
    assert "test_probe.COUNTER" in output
    assert "tests/test_probe.py:" in output


@pytest.mark.parametrize("name", ["tests.foreign", "conftest_helper"])
@pytest.mark.parametrize("refused", [False, True])
def test_test_like_module_names_do_not_exempt_foreign_namespaces(tmp_path, name, refused):
    code, output = _session(tmp_path, '''
from conftest import foreign
def test_a(): foreign.VALUE = VALUE
def test_b_retry(): assert foreign.VALUE == 0
'''.replace("VALUE = VALUE", "VALUE = " + ("1" if refused else "0")), extra='''
import sys
from types import ModuleType
foreign = ModuleType(NAME)
foreign.VALUE = 0
sys.modules[NAME] = foreign
'''.replace("NAME", repr(name)))
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: " + name + ".VALUE" in output) is refused, output


@pytest.mark.parametrize("clear", [False, True])
def test_dictionary_mock_preserves_minimal_mapping_support(tmp_path, clear):
    code, output = _session(tmp_path, '''
from unittest.mock import patch
class Mapping:
    def __init__(self): self.data = {"before": 1}
    def __getitem__(self, key): return self.data[key]
    def __setitem__(self, key, value): self.data[key] = value
    def __delitem__(self, key): del self.data[key]
    def __iter__(self): return iter(self.data)
def test_probe():
    mapping = Mapping()
    with patch.dict(mapping, {"during": 2}, clear=CLEAR):
        assert mapping["during"] == 2
    assert mapping.data == {"before": 1}
'''.replace("CLEAR", repr(clear)))
    assert code == 0, output


def test_conftest_loaded_during_test_keeps_owned_state_and_patch_attribution(tmp_path):
    code, output = _session(tmp_path, '''
import importlib.util
from pathlib import Path
import sys
loaded = []
def test_a(monkeypatch):
    spec = importlib.util.spec_from_file_location("rf11c_late_conftest", Path("tests/extra/conftest.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loaded.append((module, module.HELPER))
    monkeypatch.setattr(module, "HELPER", object())
    module.COUNTER += 1
def test_b_retry():
    module, original = loaded[0]
    assert module.HELPER is original
    assert module.COUNTER == 0
''', files={"tests/extra/conftest.py": "COUNTER = 0\nHELPER = object()\n"})
    assert code == 1, output
    assert "2 passed, 1 error" in output, output
    assert "unrestored namespace: rf11c_late_conftest.COUNTER" in output, output
    assert "rf11c_late_conftest.HELPER" in output


@pytest.mark.parametrize("refused", [False, True])
def test_lazy_cache_declaration_does_not_exempt_other_bindings(tmp_path, refused):
    code, output = _session(tmp_path, '''
from aegis_core.verification import import_guard as cache
original = cache.is_stdlib
def change(): cache.is_stdlib = lambda name: True
def test_a():
    OPERATION
def test_b_retry(): assert cache.is_stdlib is original
'''.replace("OPERATION", "change()" if refused else "cache.is_stdlib = original"))
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: aegis_core.verification.import_guard.is_stdlib" in output) is refused, output


@pytest.mark.parametrize("refused", [False, True])
def test_whole_namespace_check_uses_identity_without_value_equality(tmp_path, refused):
    code, output = _session(tmp_path, '''
import json
from conftest import original, Value
def test_a(): json._rf11c_identity = VALUE
def test_b_retry(): assert json._rf11c_identity is original
'''.replace("VALUE", "Value()" if refused else "original"), extra='''
import json
class Value:
    def __eq__(self, other): raise AssertionError("value equality must not run")
original = Value()
json._rf11c_identity = original
''')
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: json._rf11c_identity" in output) is refused, output
    assert "value equality must not run" not in output


@pytest.mark.parametrize("refused", [False, True])
def test_same_size_namespace_removal_of_none_is_not_a_clean_snapshot(tmp_path, refused):
    code, output = _session(tmp_path, '''
import json
def test_a():
    del json._rf11c_none
    OPERATION
def test_b_retry():
    assert json._rf11c_none is None
    assert not hasattr(json, "_rf11c_replacement")
'''.replace("OPERATION", "json._rf11c_replacement = None" if refused else "json._rf11c_none = None"),
        extra="\nimport json\njson._rf11c_none = None\n")
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace" in output) is refused, output
    assert "2 passed" in output


def test_session_policy_is_built_once_before_tests_and_survives_input_changes(tmp_path):
    code, output = _session(tmp_path, '''
import ctypes
from pathlib import Path
import conftest
def test_a():
    assert conftest.POLICY_READS == 1
    Path("tests/contract/test_monkeypatch_raising.py").write_text("invalid policy after initialization!", encoding="utf-8")
def test_b(monkeypatch):
    monkeypatch.setattr(ctypes, "WinDLL", None, raising=False)
    assert conftest.POLICY_READS == 1
''', extra='''
POLICY_READS = 0
_owned_open = open
def open(filename, *args, **kwargs):
    global POLICY_READS
    if str(filename).endswith("test_monkeypatch_raising.py"):
        POLICY_READS += 1
    return _owned_open(filename, *args, **kwargs)
''')
    assert code == 0, output


@pytest.mark.parametrize("limit, expected", [(1, 1), (2, 0)])
def test_shared_environment_identity_tracks_a_temporary_replacement(tmp_path, limit, expected):
    code, output = _session(tmp_path, '''
import os
def test_probe(monkeypatch):
    monkeypatch.setattr(os, "environ", dict(os.environ))
    monkeypatch.setitem(os.environ, "RF11C_TEMP_ENV", "owned")
''', limits={"tests/test_probe.py": limit})
    assert code == expected, output
    assert "2 shared site" in output


@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("limit, expected", [(1, 1), (2, 0)])
def test_dynamic_code_keeps_distinct_patch_sites_across_retries_and_threads(
        tmp_path, method, failed, threaded, limit, expected):
    attribute = "_rf11c_missing" if failed else "getpid"
    if method == "monkeypatch":
        operation = 'monkeypatch.setattr(os, "' + attribute + '", os.getpid)'
    else:
        operation = 'with patch.object(os, "' + attribute + '", os.getpid): pass'
    if failed:
        operation = "try:\n    " + operation + "\nexcept AttributeError: pass"
    program = operation + "\n" + operation
    run = ("with ThreadPoolExecutor(max_workers=2) as pool:\n"
           "        list(pool.map(worker, range(2)))" if threaded else
           "for value in range(2): worker(value)")
    code, output = _session(tmp_path, '''
import os
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
def test_probe(monkeypatch):
    program = compile(PROGRAM, "<runtime patch factory>", "exec")
    def worker(value): exec(program, globals(), {"monkeypatch": monkeypatch})
    RUN
'''.replace("PROGRAM", repr(program)).replace("RUN", run),
        limits={"tests/test_probe.py": limit})
    assert code == expected, output
    assert "2 shared site" in output


def test_first_datetime_parser_use_is_initialized_before_snapshots(tmp_path):
    code, output = _session(tmp_path, '''
from datetime import datetime
def test_a(): assert datetime.strptime("2000-01-01", "%Y-%m-%d").year == 2000
def test_b_retry(): assert datetime.strptime("2001-01-01", "%Y-%m-%d").year == 2001
''')
    assert code == 0, output


@pytest.mark.parametrize("refused", [False, True])
def test_datetime_initialization_does_not_exempt_later_timezone_rebinding(tmp_path, refused):
    code, output = _session(tmp_path, '''
import time
original = time.tzname
def test_a():
    time.tzname = tuple(list(original))
    RESTORE
def test_b_retry(): assert time.tzname is original
'''.replace("RESTORE", "pass" if refused else "time.tzname = original"))
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: time.tzname" in output) is refused, output


@pytest.mark.parametrize("setting", [1, 2])
def test_fresh_patch_owner_retains_its_owned_state(tmp_path, setting):
    code, output = _session(tmp_path, '''
import sys
from types import ModuleType
def test_probe(monkeypatch):
    owner = ModuleType("rf11c_fresh_owner")
    owner.target = owner.setting = 1
    sys.modules[owner.__name__] = owner
    monkeypatch.setattr(owner, "target", 2)
    owner.setting = VALUE
    del sys.modules[owner.__name__]
'''.replace("VALUE", repr(setting)))
    assert code == 0, output


@pytest.mark.parametrize("method", ["monkeypatch", "mock", "dictionary"])
@pytest.mark.parametrize("through_shared", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_uuid_clone_owns_only_its_namespace(tmp_path, method, through_shared, threaded):
    operations = {
        "monkeypatch": 'monkeypatch.setattr(target, attribute, replacement)',
        "mock": 'with patch.object(target, attribute, replacement): pass',
        "dictionary": 'with patch.dict(vars(target), {attribute: replacement}): pass',
    }
    code, output = _session(tmp_path, '''
import os, sys, uuid
from concurrent.futures import ThreadPoolExecutor
from types import ModuleType
from unittest.mock import patch
def test_probe(monkeypatch):
    def apply():
        owner = ModuleType("rf11c_" + uuid.uuid4().hex)
        owner.target = 1
        owner.shared = os
        sys.modules[owner.__name__] = owner
        target = owner.shared if THROUGH else owner
        attribute = "getpid" if THROUGH else "target"
        replacement = target.getpid if THROUGH else 2
        OPERATION
        owner.retained_configuration = object()
        del sys.modules[owner.__name__]
    if THREADED:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda unused: apply(), range(2)))
    else:
        apply()
'''.replace("THROUGH", repr(through_shared)).replace("THREADED", repr(threaded))
        .replace("OPERATION", operations[method]))
    assert code == (1 if through_shared else 0), output
    assert ("shared module patch count 1 exceeds 0" in output) is through_shared, output


@pytest.mark.parametrize("nested", [False, True, "cached-parent"])
@pytest.mark.parametrize("refused", [False, True])
def test_lazily_imported_module_keeps_the_namespace_boundary(tmp_path, nested, refused):
    name = ("rf11c_off_path_package.child" if nested == "cached-parent" else
            "rf11c_lazy_package.child" if nested else "rf11c_lazy_real")
    files = ({"off_path/child.py": "target = setting = 1\n"} if nested == "cached-parent" else
             {"rf11c_lazy_package/__init__.py": "", "rf11c_lazy_package/child.py": "target = setting = 1\n"}
             if nested else {"rf11c_lazy_real.py": "target = setting = 1\n"})
    if nested == "cached-parent":
        files["rf11c_off_path_package/__init__.py"] = 'from pathlib import Path\n__path__ = [str(Path.cwd() / "off_path")]\n'
    code, output = _session(tmp_path, '''
import importlib, sys
from pathlib import Path
from types import ModuleType
sys.path.insert(0, str(Path.cwd()))
if CACHED:
    importlib.import_module("rf11c_off_path_package")
def test_a(monkeypatch):
    owner = importlib.import_module(NAME)
    monkeypatch.setattr(owner, "target", 2)
    owner.setting = VALUE
def test_b_retry():
    assert sys.modules[NAME].setting == 1
'''.replace("NAME", repr(name)).replace("VALUE", "2" if refused else "1")
        .replace("CACHED", repr(nested == "cached-parent")), files=files)
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: " + name + ".setting" in output) is refused, output
    assert "2 passed" in output


@pytest.mark.parametrize("alias_kind", ["real", "new-clone", "moved"])
def test_alias_cannot_grant_fresh_module_ownership(tmp_path, alias_kind):
    code, output = _session(tmp_path, '''
import sys
from conftest import owner
def test_probe(monkeypatch):
    if KIND == "new-clone":
        sys.modules[owner.__name__] = owner
    if KIND == "moved":
        del sys.modules[owner.__name__]
    sys.modules["rf11c_new_alias"] = owner
    monkeypatch.setattr(owner, "_rf11c_setting", 2)
    owner._rf11c_retained = 2
'''.replace("KIND", repr(alias_kind)), extra='''
import json, sys
from types import ModuleType
owner = json if KIND == "real" else ModuleType("rf11c_existing_owner")
owner._rf11c_setting = 1
if KIND == "moved":
    sys.modules[owner.__name__] = owner
'''.replace("KIND", repr(alias_kind)))
    assert code == 1, output
    assert "sys.modules[rf11c_new_alias]" in output, output


@pytest.mark.parametrize("alias_added", [False, True])
def test_private_clone_registry_additions_are_always_refused(tmp_path, alias_added):
    code, output = _session(tmp_path, '''
import sys, uuid
from types import ModuleType
def test_probe(monkeypatch):
    owner = ModuleType("rf11c_" + uuid.uuid4().hex)
    owner.target = 1
    sys.modules[owner.__name__] = owner
    monkeypatch.setattr(owner, "target", 2)
    owner.retained = 2
    if ALIAS:
        sys.modules[owner.__name__ + "_alias"] = owner
'''.replace("ALIAS", repr(alias_added)))
    assert code == 1, output
    assert "sys.modules[rf11c_" in output, output


@pytest.mark.parametrize("error", ["ImportError", "OSError", "TypeError", "ValueError", "AttributeError", "RuntimeError", "RecursionError"])
def test_indeterminate_import_probe_cannot_grant_clone_ownership(tmp_path, error):
    code, output = _session(tmp_path, '''
import sys, uuid
from types import ModuleType
def test_probe(monkeypatch):
    owner = ModuleType("rf11c_" + uuid.uuid4().hex)
    owner.target = 1
    sys.modules[owner.__name__] = owner
    monkeypatch.setattr(owner, "target", 2)
    owner.retained = 2
''', extra='''
class PathFinder:
    @staticmethod
    def find_spec(name, path=None):
        raise ERROR("probe unavailable")
'''.replace("ERROR", error))
    assert code == 1, output
    assert "sys.modules[rf11c_" in output, output
    assert "probe unavailable" not in output


def test_private_clone_registration_is_removed_before_the_next_test(tmp_path):
    code, output = _session(tmp_path, '''
import sys, uuid
from types import ModuleType
name = "rf11c_" + uuid.uuid4().hex
def test_a(monkeypatch):
    owner = ModuleType(name)
    owner.target = 1
    sys.modules[name] = owner
    monkeypatch.setattr(owner, "target", 2)
    owner.configuration = 1
def test_b(monkeypatch):
    assert name not in sys.modules
def test_c_retry():
    assert name not in sys.modules
''')
    assert code == 1, output
    assert "sys.modules[rf11c_" in output, output
    assert "3 passed, 1 error" in output


@pytest.mark.parametrize("method", ["monkeypatch", "mock", "dictionary"])
def test_fresh_clone_still_restores_wrapped_targets(tmp_path, method):
    operation = {
        "monkeypatch": 'patcher = pytest.MonkeyPatch(); patcher.setattr(owner, "target", 2)',
        "mock": 'patch.object(owner, "target", 2).start()',
        "dictionary": 'patch.dict(vars(owner), {"target": 2}).start()',
    }[method]
    code, output = _session(tmp_path, '''
import pytest, sys, uuid
from types import ModuleType
from unittest.mock import patch
name = "rf11c_" + uuid.uuid4().hex
held = []
def test_a():
    owner = ModuleType(name)
    owner.target = 1
    sys.modules[name] = owner
    held.append(owner)
    OPERATION
    owner.configuration = 2
def test_b_retry():
    assert name not in sys.modules
    assert held[0].target == 1
    assert held[0].configuration == 2
'''.replace("OPERATION", operation))
    assert code == 1, output
    assert ".target" in output, output
    assert "2 passed, 1 error" in output


@pytest.mark.parametrize("module_name", [None, []])
@pytest.mark.parametrize("limit, expected", [(1, 1), (2, 0)])
def test_dynamic_globals_need_no_module_name_for_site_attribution(tmp_path, module_name, limit, expected):
    code, output = _session(tmp_path, '''
import os
def test_probe(monkeypatch):
    namespace = {"__name__": NAME, "os": os, "monkeypatch": monkeypatch}
    exec('monkeypatch.setattr(os, "getpid", os.getpid)\\nmonkeypatch.setattr(os, "getpid", os.getpid)', namespace)
'''.replace("NAME", repr(module_name)), limits={"tests/test_probe.py": limit})
    assert code == expected, output
    assert "2 shared site" in output


@pytest.mark.parametrize("method", ["setattr", "delattr", "mock"])
@pytest.mark.parametrize("permissive", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_failed_target_resolution_is_recorded_and_can_retry_strictly(
        tmp_path, method, permissive, threaded):
    attempts = {
        "setattr": 'monkeypatch.setattr(name + ".existing", 2, raising=FLAG)',
        "delattr": 'monkeypatch.delattr(name + ".existing", raising=FLAG)',
        "mock": 'patcher = patch(name + ".existing", 2, create=FLAG); pending[index] = patcher; patcher.start()',
    }
    retries = {
        "setattr": 'monkeypatch.setattr(name + ".existing", 2)',
        "delattr": 'monkeypatch.delattr(name + ".existing")',
        "mock": 'patcher = pending[index]; patcher.create = False; patcher.start(); patcher.stop()',
    }
    attempt = attempts[method].replace("FLAG", repr(permissive if method == "mock" else not permissive))
    retry = retries[method]
    run = ('with ThreadPoolExecutor(max_workers=2) as pool:\n        list(pool.map(worker, range(2)))'
           if threaded else 'worker(0)')
    code, output = _session(tmp_path, '''
import sys
import pytest
from types import ModuleType
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
pending = {}
def test_a_failed_resolution(monkeypatch):
    def worker(index):
        name = "rf11c_missing_runtime_target_" + str(index)
        with pytest.raises(ModuleNotFoundError) as error:
            ATTEMPT
        assert error.value.name == name
    RUN
def test_b_retry(monkeypatch):
    def worker(index):
        name = "rf11c_missing_runtime_target_" + str(index)
        owner = ModuleType(name)
        owner.existing = 1
        sys.modules[name] = owner
        RETRY
        del sys.modules[name]
    RUN
'''.replace("ATTEMPT", attempt).replace("RETRY", retry).replace("RUN", run))
    refused = permissive and method != "delattr"
    assert code == (1 if refused else 0), output
    assert ("permits a missing target" in output) is refused, output
    counter = "guard_" + method
    assert repr(counter) + ": " + str(4 if threaded else 2) in output


@pytest.mark.parametrize("method", ["setattr", "delattr"])
@pytest.mark.parametrize("limit, expected", [(0, 1), (1, 0)])
def test_missing_string_attribute_still_counts_the_resolved_shared_owner(tmp_path, method, limit, expected):
    operation = ('monkeypatch.setattr(target, 2)' if method == "setattr" else
                 'monkeypatch.delattr(target)')
    code, output = _session(tmp_path, '''
import pytest
from _pytest.monkeypatch import derive_importpath
def test_probe(monkeypatch):
    target = "os._rf11c_missing_attribute"
    with pytest.raises(AttributeError) as original:
        derive_importpath(target, True)
    with pytest.raises(AttributeError) as recorded:
        OPERATION
    assert str(recorded.value) == str(original.value)
'''.replace("OPERATION", operation), limits={"tests/test_probe.py": limit})
    assert code == expected, output
    assert "1 shared site" in output


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("restored", [False, True])
def test_late_module_dictionary_owner_is_found_without_a_name_marker(tmp_path, empty, restored):
    code, output = _session(tmp_path, '''
import sys
from types import ModuleType
from unittest.mock import patch
held = []
def test_a():
    owner = ModuleType("rf11c_late_dictionary")
    owner.value = 1
    sys.modules["rf11c_late_dictionary"] = owner
    held.append(owner)
    CLEAR
    patcher = patch.dict(owner.__dict__, {"value": 2}, clear=True)
    patcher.start()
    RESTORE
    del sys.modules["rf11c_late_dictionary"]
def test_b_retry():
    owner = held[0]
    EXPECT
    patch.stopall()
'''.replace("CLEAR", "owner.__dict__.clear()" if empty else "pass")
        .replace("RESTORE", "patcher.stop()" if restored else "pass")
        .replace("EXPECT", "assert vars(owner) == {}" if empty else "assert owner.value == 1"))
    assert code == (0 if restored else 1), output
    label = "<unregistered module>" if empty else "rf11c_late_dictionary"
    assert ("unrestored namespace" in output) is not restored, output
    if not restored:
        assert any(label + ".value" in line for line in output.splitlines()
                   if line.startswith("unrestored namespace: ")), output
    assert "2 passed" in output


@pytest.mark.parametrize("restored", [False, True])
def test_late_conftest_dictionary_clear_uses_the_original_owner_metadata(tmp_path, restored):
    code, output = _session(tmp_path, '''
import importlib.util
import sys
from unittest.mock import patch
held = []
def test_a():
    spec = importlib.util.spec_from_file_location("rf11c_late_dictionary", "tests/late/conftest.py")
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    held.append(owner)
    patcher = patch.dict(owner.__dict__, {"transient": 2}, clear=True)
    patcher.start()
    RESTORE
def test_b_retry():
    assert held[0].VALUE == 1
    patch.stopall()
'''.replace("RESTORE", "patcher.stop()" if restored else "pass"),
        files={"tests/late/conftest.py": "VALUE = 1\n"})
    assert code == (0 if restored else 1), output
    assert "runtime patch guard attribution:" in output
    assert "rf11c_late_dictionary.VALUE" in output
    assert "2 passed" in output


@pytest.mark.parametrize("refused", [False, True])
def test_dictionary_patch_cannot_reclassify_a_foreign_owner_by_changing_its_file(tmp_path, refused):
    code, output = _session(tmp_path, '''
import sys
from conftest import owner
from pathlib import Path
from unittest.mock import patch
original_file = owner.__file__
def test_a():
    patch.dict(owner.__dict__, {"__file__": str(Path("tests/conftest.py").resolve()), "target": 2}).start()
    owner.__file__ = original_file
    owner.target = 1
    owner.setting = VALUE
def test_b_retry():
    assert sys.modules["rf11c_late_dictionary"].setting == 1
    patch.stopall()
'''.replace("VALUE", "2" if refused else "1"), extra='''
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch
owner = ModuleType("rf11c_late_dictionary")
owner.__file__ = "foreign_helper.py"
owner.target = owner.setting = 1
sys.modules[owner.__name__] = owner
''')
    assert code == (1 if refused else 0), output
    assert ("unrestored namespace: rf11c_late_dictionary.setting" in output) is refused, output
    assert "2 passed" in output


@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
@pytest.mark.parametrize("canonical", [False, True])
def test_platform_allowance_requires_the_actual_module_not_a_copied_name(tmp_path, method, canonical):
    operation = ('monkeypatch.setattr(owner, "WinDLL", None, raising=False)' if method == "monkeypatch"
                 else 'with patch.object(owner, "WinDLL", None, create=True): pass')
    code, output = _session(tmp_path, '''
import ctypes
from types import ModuleType
from unittest.mock import patch
owner = OWNER
def test_probe(monkeypatch):
    OPERATION
'''.replace("OWNER", "ctypes" if canonical else "ModuleType(ctypes.__name__)")
        .replace("OPERATION", operation))
    assert code == (0 if canonical else 1), output
    assert ("permits a missing target" in output) is not canonical, output


@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
@pytest.mark.parametrize("registered", [False, True])
def test_scoped_consumer_allowance_keeps_supporting_an_uncached_module(tmp_path, method, registered):
    operation = ('monkeypatch.setattr(owner, "open", None, raising=False)' if method == "monkeypatch"
                 else 'with patch.object(owner, "open", None, create=True): pass')
    path = "tests/test_probe.py" if registered else "tests/another_file.py"
    suffix = "\nBUILTIN_GLOBALS = " + repr({(path, "owner.open"): "owned consumer builtin lookup"}) + "\n"
    code, output = _session(tmp_path, '''
from types import ModuleType
from unittest.mock import patch
owner = ModuleType("consumer")
def test_probe(monkeypatch):
    OPERATION
'''.replace("OPERATION", operation), policy_suffix=suffix)
    assert code == (0 if registered else 1), output
    assert ("permits a missing target" in output) is not registered, output


@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
@pytest.mark.parametrize("metadata_name", [None, "renamed_consumer"])
def test_platform_allowance_tracks_identity_when_module_metadata_changes(tmp_path, method, metadata_name):
    operation = ('monkeypatch.setattr(ctypes, "WinDLL", None, raising=False)' if method == "monkeypatch"
                 else 'with patch.object(ctypes, "WinDLL", None, create=True): pass')
    code, output = _session(tmp_path, '''
import ctypes
from unittest.mock import patch
def test_probe(monkeypatch):
    monkeypatch.setattr(ctypes, "__name__", NAME)
    OPERATION
'''.replace("NAME", repr(metadata_name)).replace("OPERATION", operation))
    assert code == 0, output


@pytest.mark.parametrize("permissive", [False, True])
def test_unresolved_owner_cannot_match_a_missing_allowlisted_module(tmp_path, permissive):
    code, output = _session(tmp_path, '''
import pytest
from unittest.mock import patch
def test_probe():
    with pytest.raises(ModuleNotFoundError):
        patch("rf11c_missing_module.WinDLL", create=FLAG).start()
'''.replace("FLAG", repr(permissive)), policy_suffix='''
PLATFORM_ABSENT = {"rf11c_missing_module.WinDLL": "missing-module refusal control"}
''')
    assert code == (1 if permissive else 0), output
    assert ("permits a missing target" in output) is permissive, output


@pytest.mark.parametrize("target", [None, 123, "missing_separator", ".WinDLL", "ctypes."])
def test_malformed_platform_policy_refuses_before_running_tests(tmp_path, target):
    code, output = _session(tmp_path, '''
import os
def test_probe(monkeypatch):
    monkeypatch.setattr(os, "getpid", os.getpid, raising=False)
''', policy_suffix="\nPLATFORM_ABSENT = " + repr({target: "untrusted_marker"}) + "\n")
    assert code == 4, output
    assert "runtime patch guard policy cannot be read" in output
    assert "untrusted_marker" not in output


@pytest.mark.parametrize("module, attribute", [("os", "environ"), ("sys", "modules")])
@pytest.mark.parametrize("limit, expected", [(1, 1), (2, 0)])
def test_replaced_shared_mapping_is_counted_by_its_live_identity(tmp_path, module, attribute, limit, expected):
    code, output = _session(tmp_path, '''
import os
import sys
def test_probe(monkeypatch):
    module = MODULE
    attribute = ATTRIBUTE
    monkeypatch.setattr(module, attribute, dict(getattr(module, attribute)))
    monkeypatch.setitem(getattr(module, attribute), "__rf11c_shared_mapping_probe", module)
'''.replace("MODULE", module).replace("ATTRIBUTE", repr(attribute)),
        limits={"tests/test_probe.py": limit})
    assert code == expected, output
    assert "2 shared site" in output


@pytest.mark.parametrize("module, attribute", [("os", "environ"), ("sys", "modules")])
def test_temporarily_absent_shared_mapping_does_not_break_an_unrelated_patch(tmp_path, module, attribute):
    code, output = _session(tmp_path, '''
import os
import sys
from types import SimpleNamespace
def test_probe(monkeypatch):
    owner = SimpleNamespace(value=1)
    monkeypatch.delattr(MODULE, ATTRIBUTE)
    try:
        monkeypatch.setattr(owner, "value", 2)
    finally:
        monkeypatch.undo()
'''.replace("MODULE", module).replace("ATTRIBUTE", repr(attribute)),
        limits={"tests/test_probe.py": 1})
    assert code == 0, output


@pytest.mark.parametrize("table", ["PROCESS_MODULES", "PROCESS_PATCH_LIMITS", "PLATFORM_ABSENT",
                                    "BUILTIN_GLOBALS", "LEASED_SITES"])
def test_unhashable_policy_literals_use_the_fixed_usage_refusal(tmp_path, table):
    value = "{[]}" if table == "PROCESS_MODULES" else "{[]: 'untrusted_marker'}"
    code, output = _session(tmp_path, "def test_probe(): pass\n",
                            policy_suffix="\n" + table + " = " + value + "\n")
    assert code == 4, output
    assert "runtime patch guard policy cannot be read" in output
    assert "untrusted_marker" not in output


@pytest.mark.parametrize("method", ["monkeypatch", "mock"])
def test_platform_owner_is_resolved_in_the_current_module_cache(tmp_path, method):
    operation = ('monkeypatch.setattr(owner, "optional", 2, raising=False)' if method == "monkeypatch"
                 else 'with patch.object(owner, "optional", 2, create=True): pass')
    code, output = _session(tmp_path, '''
import importlib
import sys
from unittest.mock import patch
def test_probe(monkeypatch):
    monkeypatch.setattr(sys, "modules", dict(sys.modules))
    owner = importlib.import_module("rf11c_current_import_482adc")
    OPERATION
'''.replace("OPERATION", operation), limits={"tests/test_probe.py": 1},
        files={"rf11c_current_import_482adc.py": "VALUE = 1\n"},
        policy_suffix='''
PLATFORM_ABSENT = {"rf11c_current_import_482adc.optional": "current-cache capability control"}
''')
    assert code == 0, output


# Compile identical guard/framework setup once, then fork before any baseline or
# probe collection. Each child creates its own real guard baseline and runs an
# unchanged probe in a fresh copy of the same suite. Windows keeps _execute_solo.
class _BatchState:
    def __init__(self):
        self.planning = False
        self.current_nodeid = None
        self.results = None
        self.result_paths = None
        self.exchange = None
        self.child_seconds = {}
        self.runtime = None

    @staticmethod
    def fork_supported():
        return (os.name == "posix" and all(hasattr(os, name) for name in ("fork", "pread", "geteuid", "killpg"))
                and _result_storage.confined_descriptor_supported())


_BATCH_STATE = _BatchState()


class _ResultExchange:
    """Bounded results below a controller-created, owned, no-follow root."""
    MAX_BYTES = 16 * 1024 * 1024
    MAX_NODES = 100000
    MAX_DEPTH = 32

    def __init__(self, root, identity=None, *, file_factory=None):
        self.root = root
        self.identity = identity
        self.file_factory = file_factory or _result_storage.confined_file
        if not _BatchState.fork_supported():
            raise RuntimeError("patch guard result exchange unavailable")
        try:
            with self.file_factory(self.root, ("anchor",)) as handle:
                self._check_root(handle.parent_stat())
        except _result_storage.ConfinedFileError:
            raise RuntimeError("patch guard result exchange refused") from None

    def _check_root(self, info):
        identity = (info.st_dev, info.st_ino)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.geteuid()
                or self.identity is not None and self.identity != identity):
            raise RuntimeError("patch guard result exchange refused")
        self.identity = identity

    def binding(self):
        return {"root": str(self.root), "identity": self.identity}

    @classmethod
    def _budget(cls, payload):
        remaining = [cls.MAX_BYTES, cls.MAX_NODES]

        def visit(value, depth):
            remaining[1] -= 1
            if depth > cls.MAX_DEPTH or remaining[1] < 0:
                raise RuntimeError("patch guard result data refused")
            if type(value) is str:
                remaining[0] -= 12 * len(value) + 2
            elif type(value) in (dict, list, tuple):
                if len(value) > remaining[1]:
                    raise RuntimeError("patch guard result data refused")
                remaining[0] -= 2 + 2 * len(value)
                if type(value) is dict:
                    for key, item in value.items():
                        if type(key) is not str:
                            raise RuntimeError("patch guard result data refused")
                        visit(key, depth + 1)
                        visit(item, depth + 1)
                else:
                    for item in value:
                        visit(item, depth + 1)
            elif value is None or type(value) is bool:
                remaining[0] -= 5
            elif type(value) is int and value.bit_length() <= 64:
                remaining[0] -= 24
            elif type(value) is float and math.isfinite(value):
                remaining[0] -= 32
            else:
                raise RuntimeError("patch guard result data refused")
            if remaining[0] < 0:
                raise RuntimeError("patch guard result data refused")

        visit(payload, 0)
        return remaining[0]

    @classmethod
    def _preparse(cls, raw):
        depth = tokens = digits = 0
        quoted = escaped = False
        for byte in raw:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
                continue
            if 48 <= byte <= 57:
                digits += 1
                if digits > 20:
                    raise RuntimeError("patch guard result data refused")
            else:
                digits = 0
            if byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                tokens += 1
            elif byte in (93, 125):
                depth -= 1
            elif byte in (44, 58):
                tokens += 1
            if not 0 <= depth <= cls.MAX_DEPTH or tokens > cls.MAX_NODES:
                raise RuntimeError("patch guard result data refused")

    def publish(self, name, payload):
        self._budget(payload)
        raw = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > self.MAX_BYTES:
            raise RuntimeError("patch guard result data refused")
        try:
            with self.file_factory(self.root, (name,)) as handle:
                self._check_root(handle.parent_stat())
                handle.publish_bytes(raw, replace=False, mode=0o600)
        except _result_storage.ConfinedFileError:
            raise RuntimeError("patch guard result exchange refused") from None

    def read(self, name):
        try:
            with self.file_factory(self.root, (name,)) as handle:
                self._check_root(handle.parent_stat())
                raw = handle.read_bytes(self.MAX_BYTES)
        except _result_storage.ConfinedFileError:
            raise RuntimeError("patch guard result exchange refused") from None
        self._preparse(raw)
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise RuntimeError("patch guard result data refused") from None
        self._budget(payload)
        return payload


class _ExchangeReader:
    """A child capability: it can exchange data but never owns its directory."""
    MAX_PACKET_CHARS = 400000

    def __init__(self):
        self.directory = None
        self.exchange = None

    def attach(self, packet):
        if packet is None:
            return
        if (type(packet) is not dict or len(packet) != 2
                or "root" not in packet or "identity" not in packet
                or type(packet["root"]) is not str
                or type(packet["identity"]) not in (tuple, list)
                or len(packet["identity"]) != 2
                or any(type(value) is not int or value < 0 or value.bit_length() > 64
                       for value in packet["identity"])):
            raise RuntimeError("patch guard result exchange refused")
        self.exchange = _ResultExchange(packet["root"], tuple(packet["identity"]))

    @classmethod
    def decode(cls, text):
        if (type(text) is not str or not 1 <= len(text) <= cls.MAX_PACKET_CHARS
                or not text.isascii()):
            raise RuntimeError("patch guard result exchange refused")
        raw = text.encode("ascii")
        try:
            _ResultExchange._preparse(raw)
            return json.loads(raw)
        except (RuntimeError, ValueError, UnicodeError):
            raise RuntimeError("patch guard result exchange refused") from None

    def close(self):
        self.exchange = None


class _PlanCaptured(BaseException):
    def __init__(self, spec):
        self.spec = spec


class _SessionSpec:
    def __init__(self, body, extra, options, limits, policy_suffix, files,
                 plugin_prefix, env_overrides, child_timeout, selection):
        self.body = body
        self.extra = extra
        self.options = options
        self.limits = limits
        self.policy_suffix = policy_suffix
        self.files = files
        self.plugin_prefix = plugin_prefix
        self.env_overrides = env_overrides
        self.child_timeout = child_timeout
        self.selection = selection


def _child_env(spec):
    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["AEGIS_PATCH_GUARD"] = "on"
    for name, value in spec.env_overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def _write_suite(tmp_path, spec, *, fork_server=False):
    suite = tmp_path / "suite"
    tests = suite / "tests"
    contract = tests / "contract"
    contract.mkdir(parents=True)
    for name, source in spec.files.items():
        target = suite / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    (suite / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    policy = (ROOT / "tests/contract/test_monkeypatch_raising.py").read_text(encoding="utf-8")
    if spec.limits is not None:
        policy += "\nPROCESS_PATCH_LIMITS = " + repr(spec.limits) + "\n"
    policy += spec.policy_suffix
    (contract / "test_monkeypatch_raising.py").write_text(policy, encoding="utf-8")
    plugin = (ROOT / "tests/conftest.py").read_text(encoding="utf-8")
    if spec.plugin_prefix:
        plugin = plugin.replace("import pytest\n",
            "import pytest\n" + textwrap.dedent(spec.plugin_prefix) + "\n", 1)
    plugin += "\n@pytest.fixture(autouse=True)\ndef _no_real_gh(): pass\n"
    plugin += "\n@pytest.fixture(autouse=True)\ndef _no_real_gh_on_path(): pass\n"
    plugin += textwrap.dedent(spec.extra)
    if fork_server:
        plugin += ("\nimport json, math, stat\nfrom aegis_core import storage as _result_storage\n"
                   + inspect.getsource(_BatchState) + "\n" + inspect.getsource(_ResultExchange)
                   + "\n" + inspect.getsource(_ExchangeReader)
                   + _fork_server_source().replace("_PG_BATCH_LIMIT", str(_BatchController.MAX_BATCH)))
    (tests / "conftest.py").write_text(plugin, encoding="utf-8")
    (tests / "test_probe.py").write_text(textwrap.dedent(spec.body), encoding="utf-8")
    return suite


def _argv(tmp_path, spec):
    return [sys.executable, "-B", "-m", "pytest", *spec.selection, "-q",
            "-p", "no:cacheprovider", "--basetemp", str(tmp_path / "run"),
            "-o", "tmp_path_retention_policy=failed", *spec.options]


def _execute_solo(tmp_path, spec, *, run=subprocess.run):
    suite = _write_suite(tmp_path, spec)
    result = _run_fork_server(_argv(tmp_path, spec), run=run, cwd=str(suite), env=_child_env(spec),
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=spec.child_timeout, refusal="worker child")
    return result.returncode, result.stdout + result.stderr


def _fork_server_source():
    return r'''
import json as _fork_json
import shutil as _fork_shutil
import tempfile as _fork_tempfile
import time as _fork_time
from pathlib import Path as _ForkPath

_fork_original_start = pytest_sessionstart

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_sessionstart(session):
    yield
    guard = getattr(session.config, "_patch_guard", None)
    if guard is not None:
        # This is the same idempotent compilation pass _start_baselines calls.
        # No namespace baseline exists until each child calls the original hook.
        guard._hook_index_modules()
    manifest_path = _ForkPath(os.environ["AEGIS_FORK_MANIFEST"])
    reader = _ExchangeReader()
    reader.attach(reader.decode(os.environ.get("AEGIS_FORK_EXCHANGE")))
    exchange = reader.exchange
    if exchange is None or exchange.root != str(manifest_path.parent):
        raise RuntimeError("patch guard result exchange refused")
    manifest = exchange.read(manifest_path.name)
    if type(manifest) is not list or not 1 <= len(manifest) <= _PG_BATCH_LIMIT:
        raise RuntimeError("patch guard fork manifest refused")
    for case in manifest:
        if (type(case) is not dict or len(case) != 3
                or type(case.get("nodeid")) is not str or not 1 <= len(case["nodeid"]) <= 4096
                or type(case.get("body")) is not str
                or type(case.get("timeout")) not in (int, float)
                or not math.isfinite(case["timeout"]) or not 0 < case["timeout"] <= 120):
            raise RuntimeError("patch guard fork manifest refused")
    suite = _ForkPath.cwd()
    template = suite.parent / "template"
    _fork_shutil.copytree(suite, template)
    records = []
    batch_deadline = _fork_time.monotonic() + 90
    for index, case in enumerate(manifest):
        os.chdir(suite.parent)
        _fork_shutil.rmtree(suite)
        _fork_shutil.copytree(template, suite)
        run = suite.parent / "run"
        if run.exists():
            _fork_shutil.rmtree(run)
        os.chdir(suite)
        (suite / "tests/test_probe.py").write_text(case["body"], encoding="utf-8")
        output_path = suite.parent / ("output-%d.txt" % index)
        error_path = suite.parent / ("error-%d.txt" % index)
        sys.stdout.flush()
        sys.stderr.flush()
        started = _fork_time.monotonic()
        with output_path.open("wb") as output, error_path.open("wb") as error:
            pid = os.fork()
            if pid == 0:
                capture = session.config.pluginmanager.getplugin("capturemanager")
                active = capture._global_capturing
                for target, stream, descriptor in ((active.out, output, 1), (active.err, error, 2)):
                    saved = getattr(target, "targetfd_save", None)
                    if saved is None:
                        os.dup2(stream.fileno(), descriptor)
                        continue
                    # Keep capture object identities and pending startup output.
                    # Its temporary file needs a private inode and file offset;
                    # fork alone would share that open-file description.
                    capture_fd = target.tmpfile.fileno()
                    size = os.fstat(capture_fd).st_size
                    position = os.lseek(capture_fd, 0, os.SEEK_CUR)
                    with _fork_tempfile.TemporaryFile() as snapshot:
                        offset = 0
                        while offset < size:
                            data = os.pread(capture_fd, min(65536, size - offset), offset)
                            if not data:
                                raise RuntimeError("patch guard capture snapshot was truncated")
                            snapshot.write(data)
                            offset += len(data)
                        snapshot.seek(position)
                        os.dup2(snapshot.fileno(), capture_fd,
                                inheritable=os.get_inheritable(capture_fd))
                    os.dup2(stream.fileno(), saved, inheritable=os.get_inheritable(saved))
                    if target._state == "suspended":
                        os.dup2(stream.fileno(), descriptor)
                _fork_original_start(session)
                return
        reaped = False
        try:
            while True:
                observed, status = os.waitpid(pid, os.WNOHANG)
                if observed:
                    reaped = True
                    break
                if (_fork_time.monotonic() - started >= case["timeout"]
                        or _fork_time.monotonic() >= batch_deadline):
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                    reaped = True
                    exchange.publish("results.json", {"error": "timeout"})
                    pytest.exit("fork child timed out", returncode=1)
                _fork_time.sleep(0.01)
        finally:
            if not reaped:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
        code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
        record = {"nodeid": case["nodeid"], "code": code,
                  "seconds": _fork_time.monotonic() - started, "output": ""}
        records.append(record)
        for path in (output_path, error_path):
            remaining = _ResultExchange._budget({"cases": records}) // 12
            with _result_storage.confined_file(str(suite.parent), (path.name,)) as handle:
                text = handle.read_bytes(remaining).decode("utf-8", errors="replace")
                record["output"] += text.replace("\r\n", "\n").replace("\r", "\n")
    exchange.publish("results.json", {"cases": records})
    pytest.exit("fork probes completed", returncode=0)
'''


def _run_fork_server(argv, *, run, process_factory=None, refusal="fork server",
                     output_limit=16 * 1024 * 1024, **kwargs):
    timeout = kwargs.get("timeout")
    if (type(refusal) is not str or len(refusal) > 12
            or refusal not in {"fork server", "worker child"}
            or type(output_limit) is not int or not 0 <= output_limit <= 16 * 1024 * 1024
            or type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 150 or kwargs.get("capture_output") is not True):
        raise RuntimeError("patch guard process request refused")
    prefix = "patch guard " + refusal
    try:
        if run is not None and run is not subprocess.run:
            result = run(argv, **kwargs)
            if (type(result.stdout) is not str or type(result.stderr) is not str
                    or len(result.stdout) + len(result.stderr) > output_limit):
                raise RuntimeError(prefix + " output refused")
            return result
        timeout = kwargs.pop("timeout")
        kwargs.pop("capture_output")
        factory = subprocess.Popen if process_factory is None else process_factory
        grouped = os.name == "posix" and hasattr(os, "killpg")
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
            with factory(argv, stdout=output, stderr=error,
                         start_new_session=grouped, **kwargs) as process:
                try:
                    process.wait(timeout=timeout)
                except BaseException:
                    try:
                        if grouped:
                            os.killpg(process.pid, 9)
                        else:
                            process.kill()
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise
                streams = []
                remaining = output_limit
                for stream in (output, error):
                    if os.fstat(stream.fileno()).st_size > remaining:
                        raise RuntimeError(prefix + " output refused")
                    stream.seek(0)
                    raw = stream.read(remaining + 1)
                    if len(raw) > remaining:
                        raise RuntimeError(prefix + " output refused")
                    remaining -= len(raw)
                    text = raw.decode("utf-8", errors="replace")
                    streams.append(text.replace("\r\n", "\n").replace("\r", "\n"))
                return subprocess.CompletedProcess(argv, process.returncode, *streams)
    except subprocess.TimeoutExpired:
        raise RuntimeError(prefix + " timed out") from None
    except OSError:
        raise RuntimeError(prefix + " launch refused") from None


def _execute_group(entries, *, run=None, fork_probe=None):
    if type(entries) not in (list, tuple) or not 1 <= len(entries) <= _BatchController.MAX_BATCH:
        raise RuntimeError("patch guard fork batch refused")
    supported = _BATCH_STATE.fork_supported if fork_probe is None else fork_probe
    if not supported():
        results = {}
        for nodeid, spec in entries:
            with tempfile.TemporaryDirectory(prefix="pg-solo-") as holder:
                results[nodeid] = _execute_solo(Path(holder), spec,
                                              run=subprocess.run if run is None else run)
        return results
    with tempfile.TemporaryDirectory(prefix="pg-fork-",
                                     dir=os.path.realpath(tempfile.gettempdir())) as holder:
        directory = Path(holder)
        first = entries[0][1]
        suite = _write_suite(directory, first, fork_server=True)
        manifest = [
            {"nodeid": nodeid, "body": textwrap.dedent(spec.body), "timeout": spec.child_timeout}
            for nodeid, spec in entries
        ]
        manifest_path = directory / "manifest.json"
        exchange = _ResultExchange(str(directory))
        exchange.publish(manifest_path.name, manifest)
        ready = directory / "results.json"
        env = _child_env(first)
        env["AEGIS_FORK_MANIFEST"] = str(manifest_path)
        env["AEGIS_FORK_RESULTS"] = str(ready)
        packet = exchange.binding()
        _ResultExchange._budget(packet)
        env["AEGIS_FORK_EXCHANGE"] = json.dumps(packet, separators=(",", ":"))
        result = _run_fork_server(_argv(directory, first), run=run, cwd=str(suite), env=env,
                     capture_output=True, text=True, encoding="utf-8", errors="replace",
                     timeout=min(150, 120 + sum(spec.child_timeout for _nodeid, spec in entries)))
        if result.returncode == 4 and not ready.exists():
            # Identical startup inputs have the same real pytest usage refusal.
            return {nodeid: (4, result.stdout + result.stderr) for nodeid, _spec in entries}
        if not ready.exists():
            raise RuntimeError("patch guard fork server produced no results")
        payload = exchange.read(ready.name)
        if type(payload) is not dict:
            raise RuntimeError("patch guard fork server returned invalid results")
        if payload.get("error") == "timeout":
            raise RuntimeError("patch guard fork child timed out")
        if result.returncode != 0:
            raise RuntimeError("patch guard fork server failed")
        records = payload.get("cases")
        if type(records) is not list:
            raise RuntimeError("patch guard fork server returned invalid results")
        if len(records) != len(entries):
            raise RuntimeError("patch guard fork server omitted or duplicated case results")
        expected = {nodeid for nodeid, _spec in entries}
        if any(type(record) is not dict or type(record.get("nodeid")) is not str
               or not 1 <= len(record["nodeid"]) <= 4096
               for record in records):
            raise RuntimeError("patch guard fork server returned invalid results")
        actual = [record["nodeid"] for record in records]
        if len(actual) != len(expected) or set(actual) != expected:
            raise RuntimeError("patch guard fork server omitted or duplicated case results")
        for record in records:
            if (type(record) is not dict or len(record) != 4
                    or type(record.get("nodeid")) is not str
                    or type(record.get("code")) is not int
                    or type(record.get("output")) is not str
                    or type(record.get("seconds")) not in (int, float)
                    or not math.isfinite(record["seconds"]) or record["seconds"] < 0):
                raise RuntimeError("patch guard fork server returned invalid results")
        _BATCH_STATE.child_seconds.update((record["nodeid"], record["seconds"])
                                          for record in records)
        return {record["nodeid"]: (record["code"], record["output"]) for record in records}


def _plan_item(item):
    if not isinstance(item, pytest.Function):
        return None
    function = item.function
    source = textwrap.dedent(inspect.getsource(function))
    tree = ast.parse(source)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name)
             and node.func.id in {"_session", "_r37_legacy_case", "_r19_chain_session"}]
    if (len(calls) != 1 or not calls[0].args or not isinstance(calls[0].args[0], ast.Name)
            or calls[0].args[0].id != "tmp_path"
            or sum(isinstance(node, ast.Name) and node.id == "tmp_path"
                   for node in ast.walk(tree)) != 1):
        return None
    # These tests own multiple processes or observe whole-session setup metrics.
    if "runtime patch guard metrics" in source or "whole_checks" in source:
        return None
    signature = inspect.signature(function)
    callspec = getattr(item, "callspec", None)
    params = dict(callspec.params) if callspec is not None else {}
    kwargs = {}
    for name, parameter in signature.parameters.items():
        if name in params:
            kwargs[name] = params[name]
        elif name == "tmp_path":
            kwargs[name] = Path(tempfile.gettempdir()) / "pg-plan-unused"
        elif name == "record_property":
            kwargs[name] = lambda *args, **mark: None
        elif parameter.default is not inspect.Signature.empty:
            continue
        else:
            return None
    try:
        function(**kwargs)
    except _PlanCaptured as captured:
        return captured.spec
    except pytest.skip.Exception:
        return None
    return None


def _group_key(spec):
    blob = spec.body + "\n" + spec.extra + "\n" + spec.plugin_prefix + "\n" + "\n".join(spec.files.values())
    if ("pytest.main" in blob or "pytest_sessionstart" in blob
            or "_PatchGuard" in blob or "-n" in spec.options
            or any("xdist" in option for option in spec.options)):
        return None
    # Every startup input is identical. Only the as-yet-uncollected body varies.
    return (spec.extra, spec.plugin_prefix, spec.options, spec.selection,
            tuple(sorted(spec.env_overrides.items())), repr(spec.limits),
            spec.policy_suffix, tuple(sorted(spec.files.items())))


class _BatchController:
    MAX_BATCH = 8
    MAX_LOOKAHEAD = 512

    def __init__(self, support_probe=None, directory_factory=None, file_factory=None,
                 *, session=None, owned_items=None, run=None):
        self.exchange = None
        self.directory = None
        self.configured = False
        self.support_probe = support_probe or _BatchState.fork_supported
        self.directory_factory = directory_factory or tempfile.mkdtemp
        self.file_factory = file_factory
        self.session = session
        self.config = None
        self.owned_items = owned_items
        self.run = run
        self.results = {}
        self.plans = {}
        self.refused = set()
        self.timings = []
        self.child_seconds = {}
        self.serial = 0
        self.adapter = None
        self.inactive_reason = "setup did not complete"
        self.positions = ({item.nodeid: index for index, item in enumerate(session.items)}
                          if session is not None else {})

    def open(self, config):
        if self.configured:
            return
        self.configured = True
        self.config = config
        if config.option.collectonly:
            self.inactive_reason = "collection only"
            return
        if not self.support_probe():
            self.inactive_reason = "fork/descriptor unavailable"
            return
        if os.environ.get("AEGIS_PATCH_GUARD_BATCH") == "0":
            self.inactive_reason = "disabled by environment"
            return
        self.adapter = "single-process" if not getattr(config, "workerinput", None) else None
        # The session fixture in this process owns this directory. In particular,
        # xdist workerinput never supplies an exchange path or inode identity.
        try:
            self.directory = self.directory_factory(prefix="aegis-patch-guard-run-",
                dir=os.path.realpath(tempfile.gettempdir()))
        except OSError:
            raise RuntimeError("patch guard result exchange refused") from None
        try:
            self.exchange = _ResultExchange(self.directory, file_factory=self.file_factory)
            self.inactive_reason = "no compatible assigned cohort"
        except BaseException:
            import shutil
            failed_directory, self.directory = self.directory, None
            try:
                shutil.rmtree(failed_directory)
            except OSError:
                raise RuntimeError("patch guard result cleanup refused") from None
            raise

    def close(self, config=None):
        if self.directory is not None:
            import shutil
            # Check ownership, mode, no-follow ancestry and identity again.
            _ResultExchange(self.directory, self.exchange.identity, file_factory=self.file_factory)
            try:
                shutil.rmtree(self.directory)
            except OSError:
                raise RuntimeError("patch guard result cleanup refused") from None
            self.directory = None

    @classmethod
    def validate_packet(cls, packet):
        if (type(packet) is not dict or len(packet) != 1
                or "results" not in packet or type(packet["results"]) is not dict
                or not 1 <= len(packet["results"]) <= cls.MAX_BATCH):
            raise RuntimeError("patch guard result exchange refused")
        for nodeid, result in packet["results"].items():
            if (type(nodeid) is not str or not 1 <= len(nodeid) <= 4096
                    or type(result) is not list or len(result) != 2
                    or type(result[0]) is not int or result[0].bit_length() > 64
                    or type(result[1]) is not str):
                raise RuntimeError("patch guard result exchange refused")
        return packet["results"]

    def _pending_items(self, item):
        if self.owned_items is not None:
            return tuple(islice(self.owned_items(item), self.MAX_LOOKAHEAD))
        if self.session is None:
            return ()
        if not getattr(self.config, "workerinput", None):
            start = self.positions[item.nodeid] + 1
            return tuple(islice(self.session.items, start, start + self.MAX_LOOKAHEAD))
        # Only the standard load scheduler has the stable queue ownership used
        # here. Work-stealing and unknown adapters execute the current item only.
        if not self._standard_load():
            self.inactive_reason = "unsupported scheduler"
            return ()
        for plugin in self.config.pluginmanager.get_plugins():
            if (type(plugin).__module__ in {"xdist.remote", "__channelexec__"}
                    and type(plugin).__name__ == "WorkerInteractor"):
                self.adapter = self._queue_interface(getattr(plugin, "torun", None))
                if self.adapter is None:
                    self.inactive_reason = "unsupported queue interface"
                    return ()
                indices = self._queued_indices(plugin)
                return tuple(self.session.items[index] for index in indices
                             if type(index) is int and 0 <= index < len(self.session.items))
        self.inactive_reason = "worker queue unavailable"
        return ()

    @staticmethod
    def _queue_interface(queue):
        if callable(getattr(queue, "lock", None)):
            return "TestQueue.lock"
        if hasattr(queue, "mutex") and hasattr(queue, "queue"):
            return "Queue.mutex"
        return None

    @classmethod
    def _queued_indices(cls, worker):
        queue = getattr(worker, "torun", None)
        interface = cls._queue_interface(queue)
        if interface == "TestQueue.lock":
            with queue.lock() as items:
                return (worker.nextitem_index, *islice(items, cls.MAX_LOOKAHEAD - 1))
        if interface == "Queue.mutex":
            with queue.mutex:
                return (worker.nextitem_index, *islice(queue.queue, cls.MAX_LOOKAHEAD - 1))
        return ()

    def batching_status(self):
        adapters = {"single-process", "TestQueue.lock", "Queue.mutex"}
        if (self.exchange is not None and self.adapter in adapters
                and any(len(group["nodeids"]) > 1 for group in self.timings)):
            return "active (" + self.adapter + ")"
        reasons = {"setup did not complete", "collection only", "fork/descriptor unavailable",
                   "disabled by environment", "no compatible assigned cohort", "unsupported scheduler",
                   "unsupported queue interface", "worker queue unavailable"}
        reason = self.inactive_reason if self.inactive_reason in reasons else "unknown adapter"
        return "inactive (" + reason + ")"

    def _standard_load(self):
        parsed_options = getattr(self.config, "known_args_namespace", None)
        distribution = getattr(parsed_options, "dist", None)
        if (getattr(parsed_options, "distload", False)
                or distribution == "no" and getattr(parsed_options, "numprocesses", None)):
            distribution = "load"
        return distribution == "load"

    def _plan(self, item):
        if item.nodeid not in self.plans:
            previous = _BATCH_STATE.planning
            _BATCH_STATE.planning = True
            try:
                spec = _plan_item(item)
            finally:
                _BATCH_STATE.planning = previous
            self.plans[item.nodeid] = (spec, _group_key(spec) if spec is not None else None)
        return self.plans[item.nodeid]

    def prepare(self, item):
        if self.exchange is None or item.nodeid in self.results:
            return
        if item.nodeid in self.refused:
            raise RuntimeError("patch guard worker batch previously refused")
        spec, key = self._plan(item)
        if spec is None:
            return
        entries = [(item.nodeid, spec)]
        seen = {item.nodeid}
        if key is not None:
            for candidate in self._pending_items(item):
                if (str(candidate.path) != str(Path(__file__))
                        or candidate.nodeid in seen or candidate.nodeid in self.results
                        or candidate.nodeid in self.refused):
                    continue
                other, other_key = self._plan(candidate)
                if other is not None and other_key == key:
                    entries.append((candidate.nodeid, other))
                    seen.add(candidate.nodeid)
                    if len(entries) == self.MAX_BATCH:
                        break
        started = time.perf_counter()
        try:
            if len(entries) == 1:
                with tempfile.TemporaryDirectory(prefix="pg-solo-") as holder:
                    results = {item.nodeid: _execute_solo(
                        Path(holder), spec, run=subprocess.run if self.run is None else self.run)}
                _BATCH_STATE.child_seconds[item.nodeid] = time.perf_counter() - started
            else:
                results = _execute_group(entries, run=self.run)
            elapsed = time.perf_counter() - started
            name = "batch-%d.json" % self.serial
            self.serial += 1
            self.exchange.publish(name, {"results": results})
            decoded = self.validate_packet(self.exchange.read(name))
            if set(decoded) != seen:
                raise RuntimeError("patch guard worker batch omitted or duplicated results")
        except subprocess.TimeoutExpired:
            self.refused.update(seen)
            raise RuntimeError("patch guard worker child timed out") from None
        except OSError:
            self.refused.update(seen)
            raise RuntimeError("patch guard worker child launch refused") from None
        except BaseException:
            self.refused.update(seen)
            raise
        self.results.update(decoded)
        self.child_seconds.update((nodeid, _BATCH_STATE.child_seconds.get(nodeid, elapsed / len(entries)))
                                  for nodeid in seen)
        self.timings.append({"nodeids": [nodeid for nodeid, _spec in entries], "seconds": elapsed})


def _dispatch_session(tmp_path, spec):
    if _BATCH_STATE.planning:
        raise _PlanCaptured(spec)
    if _BATCH_STATE.results is not None and _BATCH_STATE.current_nodeid in _BATCH_STATE.results:
        code, output = _BATCH_STATE.results[_BATCH_STATE.current_nodeid]
        return code, output
    return _execute_solo(tmp_path, spec)


def _report_batching(config, runtime):
    groups = runtime.timings
    summary = ("patch guard batching: " + runtime.batching_status()
               + "; groups=%d cases=%d group_seconds=%.3f child_seconds=%.3f" % (
                   len(groups), sum(len(group["nodeids"]) for group in groups),
                   sum(group["seconds"] for group in groups),
                   sum(runtime.child_seconds.values())))
    reporter = config.pluginmanager.getplugin("terminalreporter")
    if reporter is not None and not hasattr(config, "workerinput"):
        capture = config.pluginmanager.getplugin("capturemanager")
        with (capture.global_and_fixture_disabled() if capture is not None else nullcontext()):
            reporter.write_line(summary)
    else:
        # xdist relays captured warnings to the controller's normal summary.
        # Worker stdout and successful teardown capture are otherwise hidden.
        config.issue_config_time_warning(pytest.PytestWarning(summary), stacklevel=2)


@pytest.fixture(scope="session")
def _worker_batches(request):
    previous = (_BATCH_STATE.results, _BATCH_STATE.exchange, _BATCH_STATE.result_paths,
                _BATCH_STATE.child_seconds, _BATCH_STATE.runtime)
    runtime = _BatchController(session=request.session)
    try:
        runtime.open(request.config)
        _BATCH_STATE.results = runtime.results
        _BATCH_STATE.exchange = runtime.exchange
        _BATCH_STATE.result_paths = None
        _BATCH_STATE.child_seconds = {}
        _BATCH_STATE.runtime = runtime
        yield runtime
    finally:
        try:
            _report_batching(request.config, runtime)
            if runtime.timings:
                # Hash node identifiers so telemetry never echoes a parameter.
                digest = lambda nodeid: hashlib.sha256(nodeid.encode("utf-8", "surrogatepass")).hexdigest()
                telemetry = {
                    "groups": [{"ids": [digest(n) for n in group["nodeids"]],
                                "seconds": group["seconds"]} for group in runtime.timings],
                    "children": {digest(n): seconds for n, seconds in runtime.child_seconds.items()},
                }
                _ResultExchange._budget(telemetry)
                print("patch guard batch telemetry: " + json.dumps(telemetry, separators=(",", ":")))
        finally:
            try:
                runtime.close()
            finally:
                (_BATCH_STATE.results, _BATCH_STATE.exchange, _BATCH_STATE.result_paths,
                 _BATCH_STATE.child_seconds, _BATCH_STATE.runtime) = previous


@pytest.fixture(autouse=True)
def _current_guard_case(request, _worker_batches):
    previous = _BATCH_STATE.current_nodeid
    _BATCH_STATE.current_nodeid = request.node.nodeid
    try:
        _worker_batches.prepare(request.node)
        yield
    finally:
        _BATCH_STATE.current_nodeid = previous


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires fork and positional reads")
def test_forked_probes_keep_memory_disk_refusals_and_retries_isolated():
    from concurrent.futures import ThreadPoolExecutor

    extra = """
fork_control = ModuleType("fork_control")
fork_control.flags = [True]
sys.modules["fork_control"] = fork_control
"""
    body = """
import os, sys
from pathlib import Path
from fork_control import flags
def test_probe():
    assert flags == [True]
    assert "fresh_fork_target" not in sys.modules
    assert not Path("case-leak.txt").exists()
    assert not hasattr(os, "_fork_case_canary")
    flags[0] = False
    import fresh_fork_target
    Path("case-leak.txt").write_text("owned fixture")
    LEAK
"""
    def run_group(_index):
        entries = [
            (str(index), _SessionSpec(body.replace("LEAK", "os._fork_case_canary = object()" if index == 1 else "pass"),
                extra, (), None, "", {"fresh_fork_target.py": "VALUE = 1\n"}, "", {}, 120,
                ("tests/test_probe.py",)))
            for index in range(3)
        ]
        return _execute_group(entries)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run_group, range(2)))
    for result in [*results, run_group(2)]:
        assert [result[str(index)][0] for index in range(3)] == [0, 1, 0]
        for index in range(3):
            output = result[str(index)][1]
            assert "1 passed" in output
            assert ("unrestored namespace" in output) is (index == 1)
            assert "INTERNALERROR" not in output


def test_unsupported_fork_probe_keeps_original_subprocess_entrypoint():
    from types import SimpleNamespace

    probe = SimpleNamespace(supported=_BATCH_STATE.fork_supported)
    probe.supported = lambda: False
    calls = []
    def run_child(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="owned output", stderr="")
    spec = _SessionSpec("def test_probe(): pass\n", "", (), None, "", {}, "", {}, 120,
                        ("tests/test_probe.py",))
    result = _execute_group([("first", spec), ("second", spec)], run=run_child,
                            fork_probe=probe.supported)
    assert result == {"first": (0, "owned output"), "second": (0, "owned output")}
    assert len(calls) == 2
    assert all(argv[:4] == [sys.executable, "-B", "-m", "pytest"] for argv in calls)


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires fork and positional reads")
@pytest.mark.parametrize("payload", [None, {"cases": []}, {"cases": [
    {"nodeid": "first", "code": 0, "output": ""},
    {"nodeid": "first", "code": 0, "output": ""},
]}])
def test_fork_server_cannot_omit_or_duplicate_cases_or_retry(payload):
    calls = []
    def run_child(argv, **kwargs):
        calls.append(argv)
        if payload is not None:
            reader = _ExchangeReader()
            reader.attach(reader.decode(kwargs["env"]["AEGIS_FORK_EXCHANGE"]))
            reader.exchange.publish("results.json", payload)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    spec = _SessionSpec("def test_probe(): pass\n", "", (), None, "", {}, "", {}, 120,
                        ("tests/test_probe.py",))
    message = ("patch guard fork server produced no results" if payload is None else
               "patch guard fork server omitted or duplicated case results")
    with pytest.raises(RuntimeError, match="^" + message + "$"):
        _execute_group([("first", spec), ("second", spec)], run=run_child)
    assert len(calls) == 1
    assert not Path(calls[0][calls[0].index("--basetemp") + 1]).parent.exists()


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires fork and positional reads")
def test_fork_child_timeout_refuses_and_cleans_its_suite():
    spec = _SessionSpec("import time\ndef test_probe(): time.sleep(10)\n", "", (), None,
                        "", {}, "", {}, 0.5, ("tests/test_probe.py",))
    with pytest.raises(RuntimeError, match="^patch guard fork child timed out$"):
        _execute_group([("first", spec), ("second", spec)])


def test_probe_planner_does_not_run_external_session_helpers(request):
    def external_case(tmp_path):
        raise AssertionError("planner executed an external session helper")
        _external_session(tmp_path, "def test_probe(): pass\n")

    item = pytest.Function.from_parent(request.node.parent, name="external_case", callobj=external_case)
    assert _plan_item(item) is None


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires fork and positional reads")
def test_forked_probe_preserves_stdout_then_stderr_order():
    extra = '''
import atexit
def emit_at_exit():
    print("owned stderr marker", file=sys.stderr)
    print("owned stdout marker", file=sys.stdout)
atexit.register(emit_at_exit)
'''
    spec = _SessionSpec("def test_probe(): pass\n", extra, (), None, "", {}, "", {}, 120,
                        ("tests/test_probe.py",))
    results = _execute_group([("first", spec), ("second", spec)])
    for code, output in results.values():
        assert code == 0, output
        assert output.index("owned stdout marker") < output.index("owned stderr marker"), output


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires fork and positional reads")
@pytest.mark.parametrize("name", ["stdin", "stdout", "stderr"])
def test_forked_probe_preserves_capture_bindings_seeded_during_setup(name):
    extra = '''
capture_control = ModuleType("capture_control")
capture_control.original = sys.NAME
sys.modules["capture_control"] = capture_control
'''.replace("NAME", name)
    body = '''
import sys
from capture_control import original
def test_probe(): assert sys.NAME is original
'''.replace("NAME", name)
    spec = _SessionSpec(body, extra, (), None, "", {}, "", {}, 120, ("tests/test_probe.py",))
    with tempfile.TemporaryDirectory(prefix="pg-capture-control-") as holder:
        code, output = _execute_solo(Path(holder), spec)
    assert code == 0, output
    results = _execute_group([("first", spec), ("second", spec)])
    assert all(code == 0 for code, _output in results.values()), results


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX operations")
@pytest.mark.parametrize("kind", ["symlink", "directory", "foreign_owner"])
def test_result_exchange_ignores_old_predictable_path(tmp_path, kind, path_factory=Path):
    Path = path_factory
    from contextlib import ExitStack, contextmanager
    from types import SimpleNamespace
    from tests.unit.core.test_storage_confined import make_store

    if os.symlink not in os.supports_dir_fd:
        pytest.skip("requires descriptor-relative symlinks")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def unlink(directory, name):
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass

    with ExitStack() as resources:
        parent = make_store(tmp_path)
        parent_fd = os.open(parent, flags)
        resources.callback(os.close, parent_fd)
        private = _private_result_root(parent)
        resources.callback(os.rmdir, private.name, dir_fd=parent_fd)
        private_fd = os.open(private.name, flags, dir_fd=parent_fd)
        resources.callback(os.close, private_fd)
        private_info = os.fstat(private_fd)
        assert stat.S_IMODE(private_info.st_mode) == 0o700
        assert private_info.st_uid == os.geteuid()

        # Preserve the path-shaped assertions while making every read confined.
        class ControlPath(type(Path())):
            def read_text(self, encoding="utf-8"):
                with _result_storage.confined_file(private, self.relative_to(private).parts) as handle:
                    return handle.read_bytes(64).decode(encoding)

        identity = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:16]
        nodeid = "tests/unit/core/test_patch_guard.py::test_result_control_" + identity
        uid = os.environ.get("PYTEST_XDIST_TESTRUNUID") or ("pid%d" % os.getpid())
        if (not 1 <= len(uid) <= 128 or not uid.isascii()
                or any(not (c.isalnum() or c in "_-") for c in uid)):
            pytest.fail("invalid private control identity")
        digest = hashlib.sha256(nodeid.encode()).hexdigest()[:16]
        parts = ("aegis-patch-guard-fork", uid, digest)
        directory_fd = private_fd
        for part in parts:
            os.mkdir(part, 0o700, dir_fd=directory_fd)
            resources.callback(os.rmdir, part, dir_fd=directory_fd)
            child = os.open(part, flags, dir_fd=directory_fd)
            resources.callback(os.close, child)
            directory_fd = child
        old = ControlPath(private).joinpath(*parts)
        victim = ControlPath(private) / "sentinel"
        resources.callback(unlink, private_fd, "sentinel")
        with _result_storage.confined_file(private, ("sentinel",)) as handle:
            handle.publish_bytes(b"sentinel")
        resources.callback(unlink, directory_fd, "local.json")
        if kind == "symlink":
            os.symlink(str(victim), "local.json", dir_fd=directory_fd)
        else:
            with _result_storage.confined_file(private, (*parts, "local.json")) as handle:
                handle.publish_bytes(b"sentinel")
        info = os.fstat(directory_fd)
        foreign = SimpleNamespace(st_uid=info.st_uid + 1, st_mode=info.st_mode,
                                  st_dev=info.st_dev, st_ino=info.st_ino)
        opened = []

        @contextmanager
        def file_at_os_boundary(directory, parts):
            opened.append(Path(directory))
            with _result_storage.confined_file(directory, parts) as handle:
                if kind == "foreign_owner" and Path(directory) == old:
                    yield SimpleNamespace(parent_stat=lambda: foreign,
                                          publish_bytes=handle.publish_bytes,
                                          read_bytes=handle.read_bytes)
                else:
                    yield handle

        def private_directory(**kwargs):
            return tempfile.mkdtemp(**dict(kwargs, dir=private))

        config = SimpleNamespace(option=SimpleNamespace(collectonly=False), workerinput={})
        controller = _BatchController(directory_factory=private_directory,
                                      file_factory=file_at_os_boundary)
        previous = _BATCH_STATE.exchange, _BATCH_STATE.result_paths
        try:
            controller.open(config)
            assert Path(controller.directory).parent == private
            controller.exchange.publish("local.json", {"results": {}})
            assert victim.read_text(encoding="utf-8") == "sentinel"
            assert old not in opened
            if kind != "symlink":
                assert (old / "local.json").read_text(encoding="utf-8") == "sentinel"
        finally:
            _BATCH_STATE.exchange, _BATCH_STATE.result_paths = previous
            controller.close(config)


def _private_result_root(tmp_path):
    from tests.unit.core.test_storage_confined import make_store
    return Path(tempfile.mkdtemp(prefix="result-control-", dir=make_store(tmp_path)))


def test_private_result_exchange_concurrent_publish_refusal_and_retry(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    root = _private_result_root(tmp_path)
    exchange = _ResultExchange(root)
    payloads = {"gw0.json": {"results": {"first": [0, "passed"]}},
                "gw1.json": {"results": {"second": [1, "refused"]}}}
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda name: exchange.publish(name, payloads[name]), payloads))
    assert {name: exchange.read(name) for name in payloads} == payloads
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.publish("gw0.json", {"results": {}})
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.read("missing.json")
    exchange.publish("retry.json", {"results": {}})
    assert exchange.read("retry.json") == {"results": {}}
    assert exchange.read("gw0.json") == payloads["gw0.json"]


def test_private_result_exchange_refuses_swapped_symlink(tmp_path):
    from tests.conftest import symlink_or_skip

    root = _private_result_root(tmp_path)
    exchange = _ResultExchange(root)
    exchange.publish("gw0.json", {"results": {}})
    victim = tmp_path / "victim"
    victim.write_text("sentinel", encoding="utf-8")
    (root / "gw0.json").unlink()
    symlink_or_skip(victim, root / "gw0.json")
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.read("gw0.json")
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.publish("gw0.json", {"results": {}})
    assert victim.read_text(encoding="utf-8") == "sentinel"
    (root / "gw0.json").unlink()
    exchange.publish("gw0.json", {"results": {"retry": [0, "passed"]}})
    assert exchange.read("gw0.json")["results"]["retry"] == [0, "passed"]


@pytest.mark.parametrize("operation", ["read", "publish"])
def test_private_result_exchange_keeps_held_root_during_rename(tmp_path, operation):
    from contextlib import contextmanager
    from tests.conftest import symlink_or_skip

    root = _private_result_root(tmp_path)
    moved = tmp_path / "moved"
    victim = _private_result_root(tmp_path)
    with _result_storage.confined_file(victim, ("gw0.json",)) as handle:
        handle.publish_bytes(b"sentinel")
    swap = []

    @contextmanager
    def racing_file(directory, parts):
        with _result_storage.confined_file(directory, parts) as handle:
            if swap and parts == ("gw0.json",):
                swap.clear()
                root.rename(moved)
                symlink_or_skip(victim, root, target_is_directory=True)
            yield handle

    exchange = _ResultExchange(root, file_factory=racing_file)
    if operation == "read":
        exchange.publish("gw0.json", {"results": {"original": [0, "passed"]}})
    swap.append(True)
    if operation == "read":
        assert exchange.read("gw0.json") == {"results": {"original": [0, "passed"]}}
    else:
        exchange.publish("gw0.json", {"results": {"original": [0, "passed"]}})
        assert _ResultExchange(moved).read("gw0.json") == {"results": {"original": [0, "passed"]}}
    with _result_storage.confined_file(victim, ("gw0.json",)) as handle:
        assert handle.read_bytes(16) == b"sentinel"
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.read("gw0.json")


def test_private_result_exchange_refuses_foreign_owner_and_closes_context(tmp_path):
    from contextlib import contextmanager
    from types import SimpleNamespace

    root = _private_result_root(tmp_path)
    closed = []

    @contextmanager
    def foreign_owner(directory, parts):
        try:
            with _result_storage.confined_file(directory, parts) as handle:
                info = handle.parent_stat()
                foreign = SimpleNamespace(st_uid=info.st_uid + 1, st_mode=info.st_mode,
                                          st_dev=info.st_dev, st_ino=info.st_ino)
                yield SimpleNamespace(parent_stat=lambda: foreign)
        finally:
            closed.append(True)

    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        _ResultExchange(root, file_factory=foreign_owner)
    assert closed == [True]
    assert list(root.iterdir()) == []
    _ResultExchange(root).publish("retry.json", {"results": {}})


@pytest.mark.parametrize("raw", [b"not-json", b"\xff", b"[" * 33 + b"]" * 33, b"1" * 100],
                         ids=["syntax", "encoding", "depth", "integer"])
def test_private_result_exchange_refuses_malformed_or_excessive_json(tmp_path, raw):
    root = _private_result_root(tmp_path)
    with _result_storage.confined_file(root, ("bad.json",)) as handle:
        handle.publish_bytes(raw)
    with pytest.raises(RuntimeError, match="^patch guard result data refused$"):
        _ResultExchange(root).read("bad.json")


def test_private_result_exchange_limits_before_publish_and_read(tmp_path):
    class SmallExchange(_ResultExchange):
        MAX_BYTES = 256

    root = _private_result_root(tmp_path)
    exchange = SmallExchange(root)
    with pytest.raises(RuntimeError, match="^patch guard result data refused$"):
        exchange.publish("large.json", "x" * (exchange.MAX_BYTES // 12 + 1))
    assert not (root / "large.json").exists()
    with _result_storage.confined_file(root, ("large.json",)) as handle:
        handle.publish_bytes(b"x" * (exchange.MAX_BYTES + 1))
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.read("large.json")


def test_private_result_controller_passes_parent_root_to_workers_and_cleans(tmp_path):
    from types import SimpleNamespace
    from tests.unit.core.test_storage_confined import make_store

    make_store(tmp_path)
    parent = _BatchController()
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False))
    parent.open(config)
    root = Path(parent.directory)
    try:
        node = SimpleNamespace(workerinput={"workerid": "gw0", "workercount": 1})
        node.workerinput["_patch_guard_exchange"] = parent.exchange.binding()
        assert node.workerinput["_patch_guard_exchange"] == {
            "root": str(root), "identity": parent.exchange.identity}
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert root.stat().st_uid == os.geteuid()
        worker = _ExchangeReader()
        worker_config = SimpleNamespace(option=config.option, workerinput=node.workerinput)
        worker.attach(worker_config.workerinput["_patch_guard_exchange"])
        assert worker.directory is None
        worker.exchange.publish("gw0.json", {"results": {"case": [0, "passed"]}})
        assert parent.exchange.read("gw0.json") == {"results": {"case": [0, "passed"]}}
        worker.close()
        assert root.is_dir()
    finally:
        parent.close(config)
    assert not root.exists()


def test_private_result_controller_does_not_discover_paths_without_parent_packet():
    from types import SimpleNamespace

    controller = _ExchangeReader()
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False),
                             workerinput={"workerid": "gw0", "workercount": 1})
    controller.attach(config.workerinput.get("_patch_guard_exchange"))
    assert controller.exchange is None
    assert controller.directory is None


def test_private_result_controller_unsupported_probe_avoids_allocation():
    from types import SimpleNamespace

    probe = SimpleNamespace(supported=_BatchState.fork_supported)
    probe.supported = lambda: False
    controller = _BatchController(support_probe=probe.supported)
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False))
    controller.open(config)
    assert controller.directory is None
    assert controller.exchange is None
    node = SimpleNamespace(workerinput={})
    child = _ExchangeReader()
    child.attach(node.workerinput.get("_patch_guard_exchange"))
    assert node.workerinput == {}


def test_private_result_exchange_refuses_replaced_owned_root(tmp_path):
    root = _private_result_root(tmp_path)
    exchange = _ResultExchange(root)
    exchange.publish("gw0.json", {"results": {}})
    saved = tmp_path / "saved"
    root.rename(saved)
    root.mkdir(mode=0o700)
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.read("gw0.json")
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        exchange.publish("gw0.json", {"results": {}})
    assert list(root.iterdir()) == []
    assert _ResultExchange(saved).read("gw0.json") == {"results": {}}


def test_private_result_controller_refuses_creation_failure_without_echo():
    from types import SimpleNamespace

    def refused_directory(**kwargs):
        raise PermissionError("untrusted supplied diagnostic")

    controller = _BatchController(support_probe=lambda: True, directory_factory=refused_directory)
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False))
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        controller.open(config)
    assert controller.directory is None
    assert controller.exchange is None


@pytest.mark.parametrize("packet", [
    {}, [], {"root": "unused", "identity": [1]},
    {"root": 1, "identity": [1, 2]},
    {"root": "unused", "identity": [True, 2]},
    {"root": "unused", "identity": [-1, 2]},
    {"root": "unused", "identity": [1 << 65, 2]},
    {"root": "unused", "identity": "12"},
    {"root": "unused", "identity": [1, 2], "extra": "unused"},
], ids=["empty", "list", "short", "root-type", "boolean", "negative",
        "wide", "identity-type", "extra"])
def test_private_result_controller_refuses_malformed_worker_packet(packet):
    from types import SimpleNamespace

    controller = _ExchangeReader()
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False),
                             workerinput={"workerid": "gw0", "_patch_guard_exchange": packet})
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        controller.attach(config.workerinput["_patch_guard_exchange"])
    assert controller.directory is None
    assert controller.exchange is None


def test_private_result_controller_cleanup_failure_keeps_teardown_safe(tmp_path):
    from types import SimpleNamespace
    from tests.unit.core.test_storage_confined import make_store

    make_store(tmp_path)
    if os.name != "posix" or os.geteuid() == 0:
        pytest.skip("requires unprivileged POSIX directory permissions")
    holder = tmp_path / "holder"
    holder.mkdir(mode=0o700)
    root = holder / "invalid"
    root.mkdir(mode=0o750)
    holder.chmod(0o500)
    controller = _BatchController(directory_factory=lambda **kwargs: str(root))
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False))
    try:
        with pytest.raises(RuntimeError, match="^patch guard result cleanup refused$"):
            controller.open(config)
        controller.close(config)
        assert controller.directory is None
        assert controller.exchange is None
        assert root.is_dir()
    finally:
        holder.chmod(0o700)
    retry = _BatchController()
    retry.open(config)
    retry.close(config)
    assert retry.directory is None


def test_worker_local_session_fixture_needs_no_parent_plugin(request, _worker_batches):
    from tests.unit.core.test_storage_confined import make_store

    make_store(Path(tempfile.gettempdir()))
    assert not request.config.pluginmanager.hasplugin("aegis-patch-guard-fork")
    assert _worker_batches.directory is not None
    assert _worker_batches.exchange.identity == (
        Path(_worker_batches.directory).stat().st_dev,
        Path(_worker_batches.directory).stat().st_ino)
    assert stat.S_IMODE(Path(_worker_batches.directory).stat().st_mode) == 0o700
    assert Path(_worker_batches.directory).stat().st_uid == os.geteuid()


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX fork operations")
@pytest.mark.parametrize("failure", ["timeout", "launch"])
def test_worker_local_fork_server_refuses_boundary_failures_without_echo(failure):
    calls = []

    def run_child(argv, **kwargs):
        calls.append(argv)
        if failure == "timeout":
            raise subprocess.TimeoutExpired("untrusted diagnostic", kwargs["timeout"])
        raise PermissionError("untrusted diagnostic")

    spec = _SessionSpec("def test_probe(): pass\n", "", (), None, "", {}, "", {}, 120,
                        ("tests/test_probe.py",))
    message = ("patch guard fork server timed out" if failure == "timeout"
               else "patch guard fork server launch refused")
    with pytest.raises(RuntimeError, match="^" + message + "$"):
        _execute_group([("first", spec), ("second", spec)], run=run_child)
    assert len(calls) == 1
    assert not Path(calls[0][calls[0].index("--basetemp") + 1]).parent.exists()


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX fork operations")
@pytest.mark.parametrize("variant", range(12))
def test_worker_local_standard_scheduler_batches_assigned_children(tmp_path, variant):
    code, output = _session(tmp_path, "def test_probe(): assert %d >= 0\n" % variant)
    assert code == 0, output
    runtime = _BATCH_STATE.runtime
    assert _BATCH_STATE.current_nodeid in runtime.results
    worker = getattr(runtime.config, "workerinput", {})
    count = worker.get("workercount", 1)
    # The dedicated cohort guarantees matching work on each worker. Unrelated
    # selected contracts do not imply that this worker owns another guard case.
    selected = runtime.session.items
    cohort = all(str(item.path) == str(Path(__file__))
                 and getattr(item, "originalname", None) ==
                 "test_worker_local_standard_scheduler_batches_assigned_children"
                 for item in selected)
    if (len(selected) >= 2 * count and cohort
            and (not worker or runtime._standard_load())):
        assert any(len(group["nodeids"]) > 1 for group in _BATCH_STATE.runtime.timings)


def _worker_local_control_items(request):
    def first(tmp_path):
        _session(tmp_path, "def test_first(): pass\n")

    def second(tmp_path):
        _session(tmp_path, "def test_second(): pass\n")

    def foreign(tmp_path):
        _session(tmp_path, "def test_foreign(): pass\n")

    return [pytest.Function.from_parent(request.node.parent, name=fn.__name__, callobj=fn)
            for fn in (first, second, foreign)]


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX fork operations")
def test_worker_local_batches_never_execute_foreign_work_and_reuse_owned_results(request):
    from types import SimpleNamespace

    first, second, foreign = _worker_local_control_items(request)
    calls = []

    def child_process(argv, **kwargs):
        reader = _ExchangeReader()
        reader.attach(reader.decode(kwargs["env"]["AEGIS_FORK_EXCHANGE"]))
        manifest = reader.exchange.read("manifest.json")
        names = [entry["nodeid"] for entry in manifest]
        calls.append(names)
        assert foreign.nodeid not in names
        reader.exchange.publish("results.json", {"cases": [
            {"nodeid": name, "code": 0, "output": "owned output", "seconds": 0.01}
            for name in names]})
        return subprocess.CompletedProcess(argv, 0, "", "")

    runtime = _BatchController(session=SimpleNamespace(items=[first, second, foreign]),
                               owned_items=lambda item: [second], run=child_process)
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False))
    try:
        runtime.open(config)
        runtime.prepare(first)
        runtime.prepare(second)
        assert calls == [[first.nodeid, second.nodeid]]
        assert set(runtime.results) == {first.nodeid, second.nodeid}
        assert all(result == [0, "owned output"] for result in runtime.results.values())
        assert len(runtime.timings) == 1
    finally:
        runtime.close()


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX fork operations")
def test_worker_local_batch_failure_never_retries_its_assigned_children(request):
    from types import SimpleNamespace

    first, second, foreign = _worker_local_control_items(request)
    calls = []

    def child_process(argv, **kwargs):
        calls.append(argv)
        raise subprocess.TimeoutExpired("untrusted supplied diagnostic", kwargs["timeout"])

    runtime = _BatchController(session=SimpleNamespace(items=[first, second, foreign]),
                               owned_items=lambda item: [second], run=child_process)
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False))
    try:
        runtime.open(config)
        with pytest.raises(RuntimeError, match="^patch guard fork server timed out$"):
            runtime.prepare(first)
        with pytest.raises(RuntimeError, match="^patch guard worker batch previously refused$"):
            runtime.prepare(second)
        assert len(calls) == 1
        assert runtime.results == {}
        assert runtime.refused == {first.nodeid, second.nodeid}
        assert foreign.nodeid not in runtime.refused
    finally:
        runtime.close()


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX fork operations")
def test_worker_local_server_budget_reaps_descendants_before_return(tmp_path):
    from contextlib import contextmanager

    ready = tmp_path / "ready"
    escaped = tmp_path / "escaped"
    opened = []
    program = '''
import os, sys, time
from pathlib import Path
if os.fork() == 0:
    time.sleep(2)
    Path(sys.argv[2]).write_text("escaped", encoding="utf-8")
    os._exit(0)
Path(sys.argv[1]).write_text("ready", encoding="utf-8")
time.sleep(20)
'''

    @contextmanager
    def started_server(argv, **kwargs):
        opened.extend((kwargs["stdout"], kwargs["stderr"]))
        with subprocess.Popen(argv, **kwargs) as process:
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        pytest.fail("owned server did not become ready")
                    time.sleep(0.01)
                yield process
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, 9)
                    except ProcessLookupError:
                        pass
                    process.communicate()

    with pytest.raises(RuntimeError, match="^patch guard fork server timed out$"):
        _run_fork_server([sys.executable, "-c", program, str(ready), str(escaped)],
                         run=None, process_factory=started_server, capture_output=True,
                         text=True, encoding="utf-8", errors="replace", timeout=0.1)
    assert ready.exists()
    assert len(opened) == 2
    assert all(stream.closed for stream in opened)
    deadline = time.monotonic() + 2.5
    while not escaped.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not escaped.exists()


@pytest.mark.parametrize("limit", [0, 32])
def test_worker_local_process_output_limit_closes_every_stream(limit):
    from contextlib import contextmanager

    opened = []

    @contextmanager
    def process_factory(argv, **kwargs):
        opened.extend((kwargs["stdout"], kwargs["stderr"]))
        with subprocess.Popen(argv, **kwargs) as process:
            yield process

    with pytest.raises(RuntimeError, match="^patch guard fork server output refused$"):
        _run_fork_server([sys.executable, "-c", "import sys; sys.stdout.write('x' * 33)"],
                         run=None, process_factory=process_factory, capture_output=True,
                         text=True, encoding="utf-8", errors="replace", timeout=5,
                         output_limit=limit)
    assert len(opened) == 2
    assert all(stream.closed for stream in opened)


def test_worker_local_owned_queue_snapshot_is_bounded_and_never_consumes_assignments():
    from queue import Queue
    from types import SimpleNamespace

    queue = Queue()
    for index in range(_BatchController.MAX_LOOKAHEAD + 20):
        queue.put(index)
    worker = SimpleNamespace(torun=queue, nextitem_index=-1)
    snapshot = _BatchController._queued_indices(worker)
    assert snapshot == (-1, *range(_BatchController.MAX_LOOKAHEAD - 1))
    assert queue.qsize() == _BatchController.MAX_LOOKAHEAD + 20
    assert queue.get_nowait() == 0
    assert _BatchController._queued_indices(SimpleNamespace(torun=object())) == ()


def test_worker_local_owned_queue_snapshot_is_locked_against_concurrent_delivery():
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue
    from threading import Event
    from types import SimpleNamespace

    queue = Queue()
    queue.put(2)
    worker = SimpleNamespace(torun=queue, nextitem_index=1)
    started = Event()

    def snapshot():
        started.set()
        return _BatchController._queued_indices(worker)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with queue.mutex:
            future = pool.submit(snapshot)
            assert started.wait(2)
            queue.queue.append(3)
        assert future.result(timeout=2) == (1, 2, 3)
    assert list(queue.queue) == [2, 3]


@pytest.mark.parametrize("text", [None, "", "x" * 400001, "é", "not-json",
                                 "[" * 33 + "]" * 33, "1" * 100],
                         ids=["missing", "empty", "size", "encoding", "syntax", "depth", "integer"])
def test_worker_local_reader_packet_bounds_and_parse_refusals(text):
    with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
        _ExchangeReader.decode(text)


def test_worker_local_process_construction_failure_closes_every_stream():
    opened = []

    def refused_process(argv, **kwargs):
        opened.extend((kwargs["stdout"], kwargs["stderr"]))
        raise PermissionError("untrusted supplied diagnostic")

    with pytest.raises(RuntimeError, match="^patch guard fork server launch refused$"):
        _run_fork_server([sys.executable, "-c", "pass"], run=None,
                         process_factory=refused_process, capture_output=True,
                         text=True, encoding="utf-8", errors="replace", timeout=5)
    assert len(opened) == 2
    assert all(stream.closed for stream in opened)


@pytest.mark.parametrize("mode", ["worksteal", "loadscope", "each", "unknown"])
def test_worker_local_other_schedulers_never_read_or_batch_unowned_queues(mode):
    from types import SimpleNamespace

    def forbidden_plugins():
        pytest.fail("unsupported scheduler inspected an assignment queue")

    runtime = _BatchController(support_probe=lambda: False,
                               session=SimpleNamespace(items=[]))
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False),
        workerinput={"workerid": "gw0", "workercount": 3},
        known_args_namespace=SimpleNamespace(dist=mode, numprocesses=3),
        pluginmanager=SimpleNamespace(get_plugins=forbidden_plugins))
    runtime.open(config)
    assert runtime._pending_items(SimpleNamespace(nodeid="owned")) == ()
    assert runtime.directory is None


def test_worker_local_process_capture_preserves_subprocess_text_newlines():
    program = ("import sys; sys.stdout.buffer.write(bytes([97,13,10,98,13,99,10])); "
               "sys.stderr.buffer.write(bytes([100,13,10,101,13,102,10]))")
    argv = [sys.executable, "-c", program]
    expected = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=5)
    actual = _run_fork_server(argv, run=None, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=5)
    assert actual.returncode == expected.returncode == 0
    assert actual.stdout == expected.stdout
    assert actual.stderr == expected.stderr


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX fork operations")
@pytest.mark.parametrize("component", ["session", "fork"])
def test_private_temp_roots_allow_a_symlinked_tmpdir(tmp_path, component):
    from tests.conftest import symlink_or_skip
    from tests.unit.core.test_storage_confined import make_store

    root = make_store(tmp_path)
    parent = root / "real-parent"
    parent.mkdir(mode=0o700)
    alias = root / "tmpdir-link"
    symlink_or_skip(parent, alias, target_is_directory=True)
    program = r'''
import os, stat, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
import pytest
from tests.conftest import symlink_or_skip
from tests.unit.core import test_patch_guard as guard

# A fresh interpreter must really use the symlink spelling, not a cached tempdir.
assert tempfile.gettempdir() == os.environ["TMPDIR"]
assert Path(tempfile.gettempdir()).is_symlink()
parent = Path(os.path.realpath(tempfile.gettempdir()))
if sys.argv[1] == "session":
    config = SimpleNamespace(option=SimpleNamespace(collectonly=False))
    barrier = Barrier(2, timeout=10)

    def session_case(index, concurrent=False):
        controller = guard._BatchController()
        try:
            controller.open(config)
            directory = Path(controller.directory)
            assert directory.parent == parent
            info = directory.stat()
            assert stat.S_IMODE(info.st_mode) == 0o700
            assert info.st_uid == os.geteuid()
            if concurrent:
                barrier.wait()
            exchange = controller.exchange
            exchange.publish("result.json", {"index": index})
            assert exchange.read("result.json") == {"index": index}
            with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
                guard._ResultExchange(directory, (info.st_dev, info.st_ino + 1))
            victim = parent / ("sentinel-%d" % index)
            victim.write_bytes(b"sentinel")
            result = directory / "result.json"
            result.unlink()
            symlink_or_skip(victim, result)
            with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
                exchange.read("result.json")
            with pytest.raises(RuntimeError, match="^patch guard result exchange refused$"):
                exchange.publish("result.json", {"index": index})
            assert victim.read_bytes() == b"sentinel"
            result.unlink()
            exchange.publish("result.json", {"retry": index})
            assert exchange.read("result.json") == {"retry": index}
        finally:
            controller.close()
        assert not directory.exists()
        return directory

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(session_case, index, True) for index in range(2)]
        directories = [future.result(timeout=30) for future in futures]
    assert len(set(directories)) == 2
    session_case(2)
    assert not list(parent.glob("aegis-patch-guard-run-*"))
else:
    def fork_case(index):
        spec = guard._SessionSpec("def test_probe(): pass\n", "", (), None,
            "", {}, "", {}, 120, ("tests/test_probe.py",))
        names = ["case-%d-first" % index, "case-%d-second" % index]
        results = guard._execute_group([(name, spec) for name in names])
        assert set(results) == set(names)
        assert all(code == 0 and "1 passed" in output for code, output in results.values())

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(fork_case, range(2)))
    slow = guard._SessionSpec("import time\ndef test_probe(): time.sleep(10)\n",
        "", (), None, "", {}, "", {}, 0.5, ("tests/test_probe.py",))
    with pytest.raises(RuntimeError, match="^patch guard fork child timed out$"):
        guard._execute_group([("slow-first", slow), ("slow-second", slow)])
    assert not list(parent.glob("pg-fork-*"))
    fork_case(2)
    assert not list(parent.glob("pg-fork-*"))
'''
    env = dict(os.environ, TMPDIR=str(alias), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
               AEGIS_PATCH_GUARD_BATCH="1")
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run([sys.executable, "-B", "-c", program, component],
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not _BatchState.fork_supported(), reason="requires confined POSIX operations")
@pytest.mark.parametrize("kind", ["symlink", "directory", "foreign_owner"])
def test_private_old_location_control_uses_no_unconfined_path_io(tmp_path, kind):
    class NoUnconfinedPath(type(Path())):
        def denied(self, *args, **kwargs):
            pytest.fail("old-location control used unconfined path I/O")

        mkdir = write_text = read_text = chmod = stat = unlink = rmdir = denied

    test_result_exchange_ignores_old_predictable_path(tmp_path, kind, path_factory=NoUnconfinedPath)


def _test_lock_queue():
    from collections import deque
    from contextlib import contextmanager
    from threading import Event, RLock
    from types import SimpleNamespace
    from xdist import remote

    actual = getattr(remote, "TestQueue", None)
    if actual is not None:
        return actual(SimpleNamespace(RLock=RLock, Event=Event))

    # The public lock contract used by TestQueue in xdist 3.8. The installed
    # older xdist uses queue.Queue, which is covered independently above.
    class LockQueue:
        def __init__(self):
            self._items = deque()
            self._lock = RLock()

        @contextmanager
        def lock(self):
            with self._lock:
                yield self._items

        def put(self, item):
            with self.lock() as items:
                items.append(item)

    return LockQueue()


def test_worker_local_testqueue_lock_snapshot_is_bounded_and_nonconsuming():
    from types import SimpleNamespace

    queue = _test_lock_queue()
    for index in range(_BatchController.MAX_LOOKAHEAD + 20):
        queue.put(index)
    worker = SimpleNamespace(torun=queue, nextitem_index=-1)
    assert _BatchController._queued_indices(worker) == (
        -1, *range(_BatchController.MAX_LOOKAHEAD - 1))
    with queue.lock() as items:
        assert len(items) == _BatchController.MAX_LOOKAHEAD + 20
        assert items[0] == 0


def test_worker_local_testqueue_lock_snapshot_blocks_concurrent_delivery():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from types import SimpleNamespace

    queue = _test_lock_queue()
    queue.put(2)
    worker = SimpleNamespace(torun=queue, nextitem_index=1)
    started = Event()

    def snapshot():
        started.set()
        return _BatchController._queued_indices(worker)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with queue.lock() as items:
            future = pool.submit(snapshot)
            assert started.wait(2)
            items.append(3)
        assert future.result(timeout=2) == (1, 2, 3)
    with queue.lock() as items:
        assert list(items) == [2, 3]


def test_worker_local_batching_status_explains_an_unsupported_probe():
    from types import SimpleNamespace

    def no_directory(**kwargs):
        pytest.fail("unsupported batching allocated a directory")

    runtime = _BatchController(support_probe=lambda: False, directory_factory=no_directory)
    runtime.open(SimpleNamespace(option=SimpleNamespace(collectonly=False)))
    assert runtime.batching_status() == "inactive (fork/descriptor unavailable)"


@pytest.mark.parametrize("workers", [0, 2])
@pytest.mark.parametrize("enabled", [False, True])
def test_worker_local_batching_status_reaches_normal_output(tmp_path, workers, enabled):
    source = ("from contextlib import nullcontext\nfrom types import SimpleNamespace\nimport pytest\n"
              + inspect.getsource(_report_batching) + '''
@pytest.fixture(scope="session", autouse=True)
def summary(request):
    yield
    runtime = SimpleNamespace(timings=[], child_seconds={},
        batching_status=lambda: STATUS)
    _report_batching(request.config, runtime)
@pytest.mark.parametrize("case", range(4))
def test_probe(case):
    assert case >= 0
''')
    status = "active (single-process)" if enabled else "inactive (disabled by environment)"
    (tmp_path / "test_report.py").write_text(source.replace("STATUS", repr(status)), encoding="utf-8")
    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    result = _run_fork_server(
        [sys.executable, "-B", "-m", "pytest", "test_report.py", "-q",
         "-p", "xdist.plugin", "-p", "no:cacheprovider", "-n", str(workers),
         "--basetemp", str(tmp_path / "run")],
        run=None, cwd=str(tmp_path), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "4 passed" in output, output
    assert "patch guard batching: " + status in output, output
    assert "warm_cases" not in output, output
