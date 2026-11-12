"""Exercise the census through isolated pytest sessions, never a fake hook."""
import ast
import os
import socket
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from tests.conftest import symlink_or_skip


ROOT = Path(__file__).resolve().parents[3]


def _registry_table(name):
    tree = ast.parse((ROOT / 'tests/unit/core/test_storage_ratchets.py').read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
                                               for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('missing registry table: ' + name)


def _session(tmp_path, body, *, registry="", descriptors="{}", forwarders="{}",
             forwarded="{}", callbacks="{}", extra=None, test_body=None,
             options=(), legacy_scopes=False, check_bytecode_restore=False,
             guard_index=False, worker_index_expected=None, shared_index_change=None,
             launcher=False, test_index_failure=False, initial_conftest="", driver_body=None):
    suite = tmp_path / "suite"
    tests = suite / "tests"
    tests.mkdir(parents=True)
    (suite / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    registry_dir = tests / "unit" / "core"
    registry_dir.mkdir(parents=True)
    (registry_dir / "test_storage_ratchets.py").write_text(
        'NON_AEGIS_WRITERS = ' + (registry or '{}') + '\n'
        'REVIEWED_DESCRIPTOR_OPERATIONS = ' + descriptors + '\nAUDIT_WRITERS = {}\n'
        'FORWARDING_OPENERS = ' + forwarders + '\n'
        "AUDIT_STORAGE_MODULES = ('aegis_core/storage.py', 'aegis_core/atomicio.py', 'aegis_core/storage_shared.py')\n"
        'AUDIT_FORWARDER_OPERATIONS = ' + forwarded + '\n'
        'CALLBACK_EXCEPTIONS = ' + callbacks + '\n', encoding="utf-8")
    plugin = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    if legacy_scopes:
        assert 'getattr(code, "co_qualname", None)' in plugin
        plugin = plugin.replace('getattr(code, "co_qualname", None)', 'None')
        probe = '_CENSUS_NATIVE_QUALNAMES = hasattr((lambda: None).__code__, "co_qualname")'
        assert probe in plugin
        plugin = plugin.replace(probe, '_CENSUS_NATIVE_QUALNAMES = False')
    # The scratch package has no GitHub integration. Override the unrelated
    # autouse fixtures and exercise the actual census hooks unchanged.
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh(): pass\n'
    plugin += '\n@pytest.fixture(autouse=True)\ndef _no_real_gh_on_path(): pass\n'
    if test_index_failure:
        # Replace only this copied plugin's Path reference, never pathlib.Path.
        plugin += '''
_real_path = Path
class _UnreadableTests:
    def rglob(self, pattern): raise OSError('private source-index error')
def _test_index_path(value):
    path = _real_path(value)
    return _UnreadableTests() if path.name == 'tests' else path
Path = _test_index_path
'''
    if guard_index:
        # Only the copied plugin's AST reference is replaced. The real ast
        # module used by pytest, parsing and fixture cleanup is untouched.
        plugin += '''
_real_ast = ast
class _IndexGuard:
    def __getattr__(self, name): return getattr(_real_ast, name)
    def iter_fields(self, node):
        if isinstance(node, _real_ast.BinOp):
            raise AssertionError('indexed an irrelevant expression subtree')
        return _real_ast.iter_fields(node)
    def iter_child_nodes(self, node):
        if isinstance(node, _real_ast.BinOp):
            raise AssertionError('indexed an irrelevant expression subtree')
        return _real_ast.iter_child_nodes(node)
ast = _IndexGuard()
'''
    if worker_index_expected is not None:
        assert type(worker_index_expected) is int
        plugin += '\n_worker_index_expected = ' + repr(worker_index_expected) + '''
_worker_index_calls = 0
_original_source_index = _WriteCensus._index_sources
def _count_source_index(self):
    global _worker_index_calls
    _worker_index_calls += 1
    return _original_source_index(self)
_WriteCensus._index_sources = _count_source_index
@pytest.fixture(autouse=True)
def _check_worker_source_index():
    if os.environ.get('PYTEST_XDIST_WORKER'):
        assert _worker_index_calls == _worker_index_expected
'''
    if shared_index_change is not None:
        assert shared_index_change in ('root', 'native', 'shape')
        plugin += '\n_shared_index_change = ' + repr(shared_index_change) + '''
_original_configure_node = globals().get('pytest_configure_node')
if _original_configure_node is not None:
    @pytest.hookimpl(optionalhook=True)
    def pytest_configure_node(node):
        _original_configure_node(node)
        data = node.workerinput.get('_aegis_census_source_index')
        if data is not None:
            if _shared_index_change == 'root': data['root'] += '-different'
            elif _shared_index_change == 'native': data['native_qualnames'] = not data['native_qualnames']
            else: data['scopes'] = 'malformed'
'''
    plugin += '\n' + textwrap.dedent(initial_conftest)
    (tests / "conftest.py").write_text(plugin, encoding="utf-8")
    package = suite / "aegis_core"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "subject.py").write_text(textwrap.dedent(body), encoding="utf-8")
    for name in ("aegis_cli/__init__.py", "aegis_core/_version.py",
                 "aegis_core/primitives.py", "aegis_core/redaction.py"):
        target = suite / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
    for name, source in (extra or {}).items():
        target = suite / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(source), encoding="utf-8")
    (tests / "test_subject.py").write_text(textwrap.dedent(test_body or '''
        from aegis_core.subject import write
        def test_write(tmp_path):
            src, dst = tmp_path / "src", tmp_path / "dst"
            src.write_text("payload", encoding="utf-8")
            write(src, dst)
    '''), encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(suite), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    command = ["tests/conftest.py"] if launcher else ["-m", "pytest"]
    if driver_body is not None:
        driver = suite / 'pytest_driver.py'
        driver.write_text(textwrap.dedent(driver_body), encoding='utf-8')
        command = [str(driver)]
    elif check_bytecode_restore:
        driver = suite / 'pytest_driver.py'
        driver.write_text('import sys, pytest\noriginal = sys.dont_write_bytecode\n'
                          'status = pytest.main(sys.argv[1:])\n'
                          'assert sys.dont_write_bytecode == original\nraise SystemExit(status)\n',
                          encoding='utf-8')
        command = [str(driver)]
    return subprocess.run(
        [sys.executable, *command, "-q", "-c", str(suite / "pytest.ini"),
         "--confcutdir", str(suite), "--rootdir", str(suite),
         "-o", "addopts=", "--basetemp", str(tmp_path / "child-temp"), *options,
         str(tests / "test_subject.py")],
        cwd=suite, env=env, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=60,
    )


FORMS = [
    ("module_assignment", "import os\nlow = os", "fd = low.open(dst, low.O_CREAT | low.O_WRONLY); low.close(fd)", "open"),
    ("module_default", "import os", "def inner(o=os): o.replace(src, dst)\n    inner()", "os.rename"),
    ("getattr", "import os", "getattr(os, 'replace')(src, dst)", "os.rename"),
    ("forwarder_alias", "import os\nfrom aegis_core.bridge import regular\nop = regular", "fd = op(dst, os.O_CREAT | os.O_WRONLY); os.close(fd)", "open"),
    ("forwarder_default", "import os\nfrom aegis_core.bridge import regular", "def inner(op=regular): return op(dst, os.O_CREAT | os.O_WRONLY)\n    os.close(inner())", "open"),
    ("inherited_method", "from aegis_core.bridge import Base\nclass Child(Base):\n    pass", "Child().publish(src, dst)", "os.rename"),
    ("conditional_export", "from aegis_core.conditional import regular\nimport os", "os.close(regular(dst, os.O_CREAT | os.O_WRONLY))", "open"),
    ("try_export", "from aegis_core.try_export import regular\nimport os", "os.close(regular(dst, os.O_CREAT | os.O_WRONLY))", "open"),
    ("wildcard_export", "from aegis_core.bridge import *\nimport os", "os.close(regular(dst, os.O_CREAT | os.O_WRONLY))", "open"),
    ("unbound_replace", "from pathlib import Path", "Path.replace(src, dst)", "os.rename"),
    ("unbound_rename", "from pathlib import Path", "Path.rename(src, dst)", "os.rename"),
    ("bound_alias", "", "op = src.replace\n    op(dst)", "os.rename"),
    ("kwargs_target", "", "src.replace(**{'target': dst})", "os.rename"),
    ("move", "import shutil", "shutil.move(src, dst)", "shutil.move"),
    ("renames", "import os", "os.renames(src, dst)", "os.rename"),
    ("symlink", "import os", "os.symlink(src, dst)", "os.symlink"),
    ("path_symlink", "", "dst.symlink_to(src)", "os.symlink"),
    ("path_hardlink", "", "dst.hardlink_to(src) if hasattr(dst, 'hardlink_to') else src.link_to(dst)", "os.link"),
    ("io_open", "import io", "with io.open(dst, 'w') as stream: stream.write('x')", "open"),
    ("compare_callback", "import os", "(lambda op: op(src, dst))(os.replace if True else os.rename) is None", "os.rename"),
    ("walrus_compare", "import os", "if (op := os.replace) is not None: op(src, dst)", "os.rename"),
    ("dict_callback", "import os", "ops = {}\n    ops.update({'move': os.rename}) is None\n    ops['move'](src, dst)", "os.rename"),
    ("copyfile", "import shutil", "shutil.copyfile(src, dst)", "shutil.copyfile"),
    ("truncate", "import os", "os.truncate(src, 0)", "os.truncate"),
    ("mkdir", "", "dst.mkdir()", "os.mkdir"),
    ("unlink", "", "src.unlink()", "os.remove"),
    ("chmod", "", "src.chmod(0o600)", "os.chmod"),
    ("utime", "import os", "os.utime(src, None)", "os.utime"),
    ("direct_link", "import os", "os.link(src, dst)", "os.link"),
    ("rmdir", "", "dst.mkdir()\n    dst.rmdir()", "os.rmdir"),
    ("copytree", "import shutil", "dst.mkdir()\n    shutil.copytree(dst, src.parent / 'copy')", "shutil.copytree"),
    ("rmtree", "import shutil", "dst.mkdir()\n    shutil.rmtree(dst)", "shutil.rmtree"),
    ("mkstemp", "import tempfile\nimport os", "fd, name = tempfile.mkstemp(dir=dst.parent)\n    os.close(fd)", "tempfile.mkstemp"),
]


@pytest.mark.parametrize("name,imports,statement,event", FORMS, ids=[row[0] for row in FORMS])
@pytest.mark.parametrize("legacy_scopes", [False, True], ids=["native_scopes", "py39_scopes"])
def test_dynamic_writers_fail_the_session(tmp_path, name, imports, statement, event, legacy_scopes):
    if "symlink" in name:
        symlink_or_skip(tmp_path / "missing", tmp_path / "link-probe")
    body = imports + '\ndef write(src, dst):\n    ' + statement + '\n'
    result = _session(tmp_path, body, legacy_scopes=legacy_scopes, extra={
        "aegis_core/bridge.py": '''
            import os
            def regular(path, flags): return os.open(path, flags)
            class Base:
                def publish(self, src, dst): os.replace(src, dst)
        ''',
        "aegis_core/conditional.py": "if True:\n    from aegis_core.bridge import regular\n",
        "aegis_core/try_export.py": "try:\n    from aegis_core.bridge import regular\nexcept ImportError:\n    pass\n",
    })
    assert result.returncode == 1, result.stdout + result.stderr
    assert "unregistered storage writer" in result.stdout
    assert event in result.stdout
    expected = ("aegis_core/bridge.py:Base.publish" if name == "inherited_method" else
                "aegis_core/bridge.py:regular" if "forwarder" in name or "export" in name else
                "aegis_core/subject.py:write")
    assert expected in result.stdout
    assert "1 passed" in result.stdout  # census failure, not a broken scratch test


@pytest.mark.parametrize("body,registry", [
    ("def write(src, dst):\n    dst.write_text('ok')", "{('aegis_core/subject.py', 'write'): 'reviewed writer'}"),
    ("def write(src, dst):\n    src.read_bytes()", "{}"),
    ("from aegis_core.storage import write", "{}"),
    ("def write(src, dst):\n    pass", "{}"),
], ids=["registered", "read_only", "storage", "fixture_only"])
def test_registered_and_out_of_scope_writes_pass(tmp_path, body, registry):
    result = _session(tmp_path, body, registry=registry, extra={
        "aegis_core/storage.py": "def write(src, dst): dst.write_text('ok')\n",
    })
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('surface', ['lock', 'publication', 'busy_lock', 'existing_publication'])
def test_merged_mailbox_writer_stream_passes_census(tmp_path, legacy_scopes, surface):
    # Copy the pinned product bytes unchanged. Exercise public callers and real
    # fdopen audit events with the checked-in writer classifications.
    result = _session(tmp_path, '''
        import errno
        import pytest
        from tools.hierarchy_mailbox import writer_lock, publish_file
        def write(src, dst):
            surface = %r
            if surface in ('lock', 'busy_lock'):
                with writer_lock(dst.parent):
                    assert (dst.parent / '.write.lock').is_file()
                    if surface == 'busy_lock':
                        with pytest.raises(ValueError, match='^mailbox writer is busy; inspect an abandoned lock before retrying$'):
                            with writer_lock(dst.parent):
                                raise AssertionError('acquired a busy lock')
                assert not (dst.parent / '.write.lock').exists()
            else:
                publish_file(dst, b'first')
                if surface == 'existing_publication':
                    with pytest.raises(FileExistsError) as refusal:
                        publish_file(dst, b'second')
                    assert refusal.value.errno == errno.EEXIST
                assert dst.read_bytes() == b'first'
                assert not list(dst.parent.glob('.pending-*'))
    ''' % surface, registry=repr(_registry_table('AUDIT_WRITERS')),
        legacy_scopes=legacy_scopes, extra={
            'tools/__init__.py': '',
            'tools/hierarchy_mailbox.py': (ROOT / 'tools/hierarchy_mailbox.py').read_text(encoding='utf-8'),
        })
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout
    assert 'unregistered storage writer' not in result.stdout


def _native_probe_sources():
    # Use the checkout's product source and classifications unchanged.
    # Repository-owned source reads need no descriptor capability.
    return {
        'tools/__init__.py': '',
        'tests/unit/core/test_storage_ratchets.py':
            (ROOT / 'tests/unit/core/test_storage_ratchets.py').read_text(encoding='utf-8'),
        'tools/hierarchy_templates/role-registry.json':
            (ROOT / 'tools/hierarchy_templates/role-registry.json').read_text(encoding='utf-8'),
        **{'tools/' + path.name: path.read_text(encoding='utf-8')
           for path in (ROOT / 'tools').glob('*.py')},
    }


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('surface', [
    'write_private',
    pytest.param('run_lock', marks=pytest.mark.skipif(
        os.name != 'posix', reason='the real run lock path uses POSIX signal masking')),
])
def test_native_probe_owned_stream_passes_census(tmp_path, legacy_scopes, surface):
    # Isolate preflight and post-lock execution, keeping the real run lock,
    # write_private, owned_stream and fdopen. The stream's product frame must
    # be classified even when its caller is an approved writer.
    result = _session(tmp_path, '', legacy_scopes=legacy_scopes,
                      extra=_native_probe_sources(), test_body='''
        import json
        from types import SimpleNamespace
        from tools import hierarchy_native_probe as probe

        def test_write(tmp_path, monkeypatch):
            if %r == 'write_private':
                path = tmp_path / 'report.json'
                assert probe.write_private(path, {'ok': True}) == path
                assert json.loads(path.read_text(encoding='utf-8')) == {'ok': True}
            else:
                lock = tmp_path / '.run.lock'
                def prepare(args):
                    return {'probe_root': str(tmp_path)}, 1, None, 'unused', True, None
                def execute(*args):
                    record = json.loads(lock.read_text(encoding='utf-8'))
                    assert type(record['pid']) is int and record['started_at']
                    return 0, {'lock_written': True}
                monkeypatch.setattr(probe, 'preflight', prepare)
                monkeypatch.setattr(probe, 'run_locked', execute)
                assert probe.run(SimpleNamespace(auth='existing')) == (0, {'lock_written': True})
                assert not lock.exists()
    ''' % surface)
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout
    assert 'unregistered storage writer' not in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
def test_native_probe_owned_stream_does_not_authorize_sibling(tmp_path, legacy_scopes):
    sources = _native_probe_sources()
    # Only the control appends a sibling to the copied product module. It uses
    # the real fdopen as well and must receive no authority from owned_stream.
    sources['tools/hierarchy_native_probe.py'] += '''
def unregistered_stream(fd):
    try:
        with os.fdopen(fd, 'w', closefd=False) as stream:
            stream.write('sibling')
    finally:
        os.close(fd)
'''
    result = _session(tmp_path, '', legacy_scopes=legacy_scopes, extra=sources, test_body='''
        import os
        from tools import hierarchy_native_probe as probe

        def test_write(tmp_path):
            path = tmp_path / 'sibling.txt'
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            probe.unregistered_stream(fd)
            assert path.read_text(encoding='utf-8') == 'sibling'
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert '1 passed' in result.stdout
    assert 'tools/hierarchy_native_probe.py:unregistered_stream open' in result.stdout
    assert 'tools/hierarchy_native_probe.py:owned_stream open' not in result.stdout


def test_registered_outer_frame_does_not_hide_inner_writer(tmp_path):
    result = _session(tmp_path, '''
        from aegis_core.bridge import regular
        def write(src, dst): regular(dst)
    ''', registry="{('aegis_core/subject.py', 'write'): 'outer only'}", extra={
        "aegis_core/bridge.py": "def regular(dst): dst.write_text('payload')\n",
    })
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/bridge.py:regular" in result.stdout


def test_registered_forwarder_does_not_authorize_new_caller(tmp_path):
    result = _session(tmp_path, '''
        from aegis_core.bridge import regular
        import os
        def write(src, dst): os.close(regular(dst, os.O_CREAT | os.O_WRONLY))
    ''', descriptors="{('aegis_core/bridge.py', 'regular', 'os.open'): (1, 'generic opener')}",
        forwarders="{'aegis_core.bridge.regular': 1}",
        forwarded="{('aegis_core/bridge.py', 'regular', 'os.open'): ('open', 'generic opener')}", extra={
            "aegis_core/bridge.py": "import os\ndef regular(dst, flags): return os.open(dst, flags)\n",
        })
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:write open" in result.stdout


def test_reviewed_read_descriptor_does_not_authorize_writes(tmp_path):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')",
                      descriptors="{('aegis_core/subject.py', 'write', 'os.open'): (1, 'read-only descriptor')}")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:write open" in result.stdout


@pytest.mark.parametrize("flags", ["O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"])
def test_each_write_flag_is_censused(tmp_path, flags):
    result = _session(tmp_path, "import os\ndef write(src, dst):\n    os.close(os.open(src, os." + flags + "))")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:write open" in result.stdout


@pytest.mark.parametrize("mode", ["w", "a", "x", "r+"])
def test_each_write_mode_is_censused(tmp_path, mode):
    result = _session(tmp_path, "def write(src, dst):\n    with open(" +
                      ("src" if mode == "r+" else "dst") + ", " + repr(mode) + "): pass")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:write open" in result.stdout


def test_failed_write_attempt_is_recorded_even_if_caught(tmp_path):
    result = _session(tmp_path, '''
        def write(src, dst):
            try:
                (dst / 'missing' / 'file').write_bytes(b'x')
            except FileNotFoundError:
                pass
    ''')
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:write open" in result.stdout


def test_python39_lexical_method_scope(tmp_path):
    result = _session(tmp_path, '''
        def decorate(fn): return fn
        class Base:
            @decorate
            def publish(self, dst): dst.write_text('x')
        class Child(Base): pass
        def write(src, dst): Child().publish(dst)
    ''', legacy_scopes=True, registry="{('aegis_core/subject.py', 'write'): 'caller'}")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:Base.publish open" in result.stdout


def test_worker_violations_fail_controller(tmp_path):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')",
                      options=("-p", "xdist.plugin", "-n", "2"))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:write open" in result.stdout
    assert "1 passed" in result.stdout


def test_test_callback_write_is_out_of_scope(tmp_path):
    result = _session(tmp_path, "def write(callback, dst): callback(dst)", test_body='''
        from aegis_core.subject import write
        def test_write(tmp_path):
            def callback(dst): dst.write_text('fixture')
            write(callback, tmp_path / 'out')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('plain_loader', [False, True], ids=['pytest_loader', 'source_loader'])
@pytest.mark.parametrize('callback', ["CALLBACKS['save']", 'CALLBACK_LIST[0]', 'CALLBACK_TUPLE[0]',
                                     'with_default.__defaults__[0]', 'PARTIAL'])
def test_initial_conftest_callback_code_tree(tmp_path, legacy_scopes, plain_loader, callback):
    result = _session(tmp_path, 'def write(callback, dst): callback(dst)\n',
                      legacy_scopes=legacy_scopes, options=('--assert=plain',) if plain_loader else (),
                      initial_conftest='''
        import functools
        CALLBACKS = {'save': lambda dst: dst.write_bytes(b'x')}
        CALLBACK_LIST = [lambda dst: dst.write_bytes(b'x')]
        CALLBACK_TUPLE = (lambda dst: dst.write_bytes(b'x'),)
        def with_default(callback=lambda dst: dst.write_bytes(b'x')): return callback
        PARTIAL = functools.partial(lambda dst: dst.write_bytes(b'x'))
    ''', test_body='''
        import conftest
        from aegis_core.subject import write
        def test_write(tmp_path):
            target = tmp_path / 'out'
            write(conftest.%s, target)
            assert target.read_bytes() == b'x'
    ''' % callback)
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('rewritten', [False, True], ids=['source_loader', 'pytest_loader'])
@pytest.mark.parametrize('callback', ["CALLBACKS['save']", 'CALLBACK_LIST[0]', 'CALLBACK_TUPLE[0]',
                                     'with_default.__defaults__[0]', 'PARTIAL'])
def test_preloaded_helper_callback_code_tree(tmp_path, legacy_scopes, rewritten, callback):
    result = _session(tmp_path, 'def write(callback, dst): callback(dst)\n',
                      legacy_scopes=legacy_scopes,
                      initial_conftest="pytest_plugins = ('preloaded_callbacks',)" if rewritten else 'import preloaded_callbacks',
                      extra={'tests/preloaded_callbacks.py': '''
        import functools
        CALLBACKS = {'save': lambda dst: dst.write_bytes(b'x')}
        CALLBACK_LIST = [lambda dst: dst.write_bytes(b'x')]
        CALLBACK_TUPLE = (lambda dst: dst.write_bytes(b'x'),)
        def with_default(callback=lambda dst: dst.write_bytes(b'x')): return callback
        PARTIAL = functools.partial(lambda dst: dst.write_bytes(b'x'))
    '''}, test_body='''
        import preloaded_callbacks as callbacks
        from aegis_core.subject import write
        def test_write(tmp_path):
            assert hasattr(callbacks.__spec__.loader, 'get_code') is %r
            target = tmp_path / 'out'
            write(callbacks.%s, target)
            assert target.read_bytes() == b'x'
    ''' % (not rewritten, callback))
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('changed', ['filename', 'constant_hook', 'metadata_hook'])
def test_preloaded_code_comparison_cannot_grant_foreign_code(tmp_path, legacy_scopes, changed):
    result = _session(tmp_path, '''
        from types import FunctionType
        def write(callback, filename, dst):
            code = callback.__code__
            hooks = []
            class Constant:
                def __eq__(self, other): hooks.append('equality'); return True
                def __hash__(self): hooks.append('hash'); return hash('sentinel')
            class Data(bytes):
                def __eq__(self, other): hooks.append('metadata'); return True
            if %r == 'filename':
                modified = code.replace(co_filename=filename)
            elif %r == 'metadata_hook':
                fields = ['co_linetable'] if hasattr(code, 'co_linetable') else ['co_lnotab']
                if hasattr(code, 'co_exceptiontable'): fields.append('co_exceptiontable')
                for field in fields:
                    modified = code.replace(**{field: Data(getattr(code, field))})
                    FunctionType(modified, callback.__globals__)(dst)
                assert not hooks
                return
            else:
                modified = code.replace(co_consts=tuple(Constant() if item == 'sentinel' else item for item in code.co_consts))
            FunctionType(modified, callback.__globals__)(dst)
            assert not hooks
    ''' % (changed, changed), legacy_scopes=legacy_scopes,
                      initial_conftest='import preloaded_callbacks',
                      extra={'tests/preloaded_callbacks.py': '''
        def callback(dst):
            dst.write_bytes(b'x')
            return 'sentinel'
    '''}, test_body='''
        import preloaded_callbacks as callbacks
        from aegis_core.subject import write
        def test_write(tmp_path):
            target = tmp_path / 'out'
            write(callbacks.callback, __file__, target)
            assert target.read_bytes() == b'x'
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
def test_preloaded_rewritten_assertions_keep_fixture_provenance(tmp_path, legacy_scopes):
    result = _session(tmp_path, 'def write(callback, dst): callback(dst)\n',
                      legacy_scopes=legacy_scopes, initial_conftest="pytest_plugins = ('preloaded_callbacks',)",
                      extra={'tests/preloaded_callbacks.py': '''
        def callback(dst):
            assert dst.name == 'out'
            dst.write_bytes(b'x')
    '''}, test_body='''
        import preloaded_callbacks
        from aegis_core.subject import write
        def test_write(tmp_path):
            target = tmp_path / 'out'
            write(preloaded_callbacks.callback, target)
            assert target.read_bytes() == b'x'
    ''')
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
def test_preloaded_module_body_cannot_be_replayed(tmp_path, legacy_scopes):
    result = _session(tmp_path, '''
        def write(module, dst):
            module.REPLAY = dst
            exec(module.__spec__.loader.get_code(module.__name__), module.__dict__)
    ''', legacy_scopes=legacy_scopes, initial_conftest='import preloaded_callbacks',
                      extra={'tests/preloaded_callbacks.py': '''
        if globals().get('REPLAY') is not None:
            REPLAY.write_bytes(b'x')
    '''}, test_body='''
        import preloaded_callbacks
        from aegis_core.subject import write
        def test_write(tmp_path):
            target = tmp_path / 'out'
            write(preloaded_callbacks, target)
            assert target.read_bytes() == b'x'
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('new_spec', [False, True], ids=['same_spec', 'reload_spec'])
def test_reexecuted_test_module_refreshes_code_tree(tmp_path, legacy_scopes, new_spec):
    result = _session(tmp_path, 'def write(callback, dst): callback(dst)\n',
                      legacy_scopes=legacy_scopes, extra={
                          'tests/fixture_module.py': "def callback(dst): dst.write_bytes(b'x')\n",
                      }, test_body='''
        import importlib.util
        from pathlib import Path
        import sys
        from aegis_core.subject import write
        def test_write(tmp_path):
            spec = importlib.util.spec_from_file_location('fixture_module', Path(__file__).with_name('fixture_module.py'))
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            original = module.callback
            write(original, tmp_path / 'first')
            if %r:
                importlib.reload(module)
                assert module.__spec__ is not spec
            else:
                spec.loader.exec_module(module)
                assert module.__spec__ is spec
            assert module.callback.__code__ is not original.__code__
            write(module.callback, tmp_path / 'second')
            write(original, tmp_path / 'retained')
            for name in ('first', 'second', 'retained'):
                assert (tmp_path / name).read_bytes() == b'x'
    ''' % new_spec)
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


def _unobserved_import_session(tmp_path, holder, interval, legacy_scopes, *, substitution=None,
                               preloaded=False, changed_source=False, retained_holder=None):
    reexecute = '''
        from pathlib import Path
        import fixture_module as helper
        if %r:
            source = Path(helper.__file__)
            updated = source.read_text(encoding='utf-8').replace("b'x'", "b'y'")
            source.write_text(updated + '\\n# changed source size\\n', encoding='utf-8')
        helper.__spec__.loader.exec_module(helper)
    ''' % changed_source
    driver = '''
        from pathlib import Path
        import sys
        import pytest
        args = sys.argv[1:]
        assert pytest.main(args) == 0
        import fixture_module as helper
        helper.retained = helper.%s
        previous_spec = helper.__spec__
        if %r == 'inactive':
            exec(%r)
        else:
            other = Path('other')
            (other / 'tests/conftest.py').write_text(Path('tests/conftest.py').read_text(encoding='utf-8'), encoding='utf-8')
            assert pytest.main(['-q', '--import-mode=importlib', '-o', 'addopts=',
                               '-c', str(other / 'pytest.ini'), '--rootdir', str(other),
                               '--confcutdir', str(other), '--basetemp', str(other / 'temp'),
                               str(other / 'tests/test_gap.py')]) == 0
        assert helper.__spec__ is previous_spec
        helper.resumed = True
        raise SystemExit(pytest.main(args))
    ''' % (retained_holder or holder, interval, textwrap.dedent(reexecute))
    return _session(tmp_path, '''
        from types import FunctionType
        def write(callback, dst, substitution=None, filename=None):
            if substitution is not None:
                code = callback.__code__
                if substitution == 'filename': code = code.replace(co_filename=filename)
                else: code = code.replace(co_consts=tuple(b'y' if item == b'x' else item for item in code.co_consts))
                callback = FunctionType(code, callback.__globals__)
            callback(dst)
    ''', legacy_scopes=legacy_scopes, initial_conftest='import fixture_module' if preloaded else '',
                    driver_body=driver, extra={
        'tests/fixture_module.py': '''
            import functools
            def callback(dst): dst.write_bytes(b'x')
            CALLBACKS = {'save': lambda dst: dst.write_bytes(b'x')}
            CALLBACK_LIST = [lambda dst: dst.write_bytes(b'x')]
            CALLBACK_TUPLE = (lambda dst: dst.write_bytes(b'x'),)
            def with_default(callback=lambda dst: dst.write_bytes(b'x')): return callback
            PARTIAL = functools.partial(lambda dst: dst.write_bytes(b'x'))
        ''',
        'other/pytest.ini': '[pytest]\n',
        'other/tools/__init__.py': '',
        'other/tests/unit/core/test_storage_ratchets.py': 'NON_AEGIS_WRITERS = {}\nAUDIT_WRITERS = {}\n',
        'other/tests/test_gap.py': ('def test_gap():\n'
                                  '    import sys\n    from pathlib import Path\n'
                                  '    assert len(sys._aegis_write_census.sessions) == 1\n'
                                  '    assert Path(sys._aegis_write_census.current.root) == Path(__file__).parents[1]\n'
                                  + textwrap.indent(textwrap.dedent(reexecute), '    ')),
    }, test_body='''
        import fixture_module as helper
        from aegis_core.subject import write
        def test_write(tmp_path):
            resumed = getattr(helper, 'resumed', False)
            target = tmp_path / 'new'
            write(helper.%s, target, %r if resumed else None, __file__)
            assert target.read_bytes() == (b'y' if resumed and (%r or %r == 'constant') else b'x')
            if resumed:
                retained = tmp_path / 'old'
                write(helper.retained, retained)
                assert retained.read_bytes() == b'x'
    ''' % (holder, substitution, changed_source, substitution))


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('interval', ['inactive', 'other_root'])
@pytest.mark.parametrize('holder', ["CALLBACKS['save']", 'CALLBACK_LIST[0]', 'CALLBACK_TUPLE[0]',
                                   'with_default.__defaults__[0]', 'PARTIAL'])
def test_session_start_refreshes_unobserved_imports(tmp_path, legacy_scopes, interval, holder):
    result = _unobserved_import_session(tmp_path, holder, interval, legacy_scopes)
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert 'unregistered storage writer' not in result.stdout
    assert result.stdout.count('1 passed') >= 2


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('interval', ['inactive', 'other_root'])
def test_session_refresh_preserves_uninvoked_prior_compiled_code(tmp_path, legacy_scopes, interval):
    result = _unobserved_import_session(tmp_path, "CALLBACKS['save']", interval, legacy_scopes,
                                        preloaded=True, changed_source=True, retained_holder='CALLBACK_TUPLE[0]')
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert 'unregistered storage writer' not in result.stdout
    assert result.stdout.count('1 passed') >= 2


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('interval', ['inactive', 'other_root'])
@pytest.mark.parametrize('substitution', ['filename', 'constant'])
def test_session_refresh_refuses_substituted_code(tmp_path, legacy_scopes, interval, substitution):
    result = _unobserved_import_session(tmp_path, 'callback', interval, legacy_scopes, substitution=substitution)
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert result.stdout.count('unregistered storage writer') == 1
    assert result.stdout.count('1 passed') >= 2


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('threaded', [False, True], ids=['direct', 'thread'])
@pytest.mark.parametrize('at_import', [False, True], ids=['test_body', 'import_body'])
def test_generated_code_with_real_test_globals_is_not_a_fixture(tmp_path, legacy_scopes, threaded, at_import):
    result = _session(tmp_path, '''
        def write(g, dst):
            exec(compile("dst.write_bytes(b'x')", g["__file__"], "exec"), g, {"dst": dst})
    ''', legacy_scopes=legacy_scopes, test_body='''
        from pathlib import Path
        from threading import Thread
        from aegis_core.subject import write
        def invoke(target):
            if %r:
                worker = Thread(target=write, args=(globals(), target))
                worker.start()
                worker.join(timeout=5)
                assert not worker.is_alive()
            else:
                write(globals(), target)
            assert target.read_bytes() == b'x'
        if %r:
            invoke(Path(__file__).with_name('collection-output'))
        def test_write(tmp_path):
            if not %r: invoke(tmp_path / 'out')
    ''' % (threaded, at_import, at_import))
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
def test_argon_eval_with_real_conftest_globals_is_unresolved(tmp_path, legacy_scopes):
    result = _session(tmp_path, '''
        import sys
        def write(src, dst):
            m = sys.modules['conftest']
            eval(compile("dst.write_bytes(b'x')", m.__file__, 'eval'), m.__dict__, {'dst': dst})
    ''', legacy_scopes=legacy_scopes)
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
def test_equal_but_distinct_test_code_keeps_product_attribution(tmp_path, legacy_scopes):
    result = _session(tmp_path, '''
        from types import FunctionType
        def write(g, dst):
            original = g['fixture'].__code__
            cloned = original.replace()
            assert cloned == original and cloned is not original
            FunctionType(cloned, g)(dst)
    ''', legacy_scopes=legacy_scopes, test_body='''
        from aegis_core.subject import write
        def fixture(dst): dst.write_bytes(b'x')
        def test_write(tmp_path):
            fixture(tmp_path / 'genuine')
            write(globals(), tmp_path / 'cloned')
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('callback', ['fixture', 'Fixtures().method', 'Fixtures.static', 'Fixtures.class_method',
                                     'lambda dst: Fixtures(dst).value', 'factory()',
                                     "lambda dst: dst.write_bytes(b'x')", 'comprehension'])
def test_genuine_test_code_objects_remain_fixture_owned(tmp_path, callback):
    result = _session(tmp_path, 'def write(callback, dst): callback(dst)\n', test_body='''
        from aegis_core.subject import write
        def fixture(dst): dst.write_bytes(b'x')
        class Fixtures:
            def __init__(self, target=None): self.target = target
            def method(self, dst): dst.write_bytes(b'x')
            @staticmethod
            def static(dst): dst.write_bytes(b'x')
            @classmethod
            def class_method(cls, dst): dst.write_bytes(b'x')
            @property
            def value(self): self.target.write_bytes(b'x')
        def factory():
            def nested(dst): dst.write_bytes(b'x')
            return nested
        def comprehension(dst): [dst.write_bytes(b'x') for _ in range(1)]
        def test_write(tmp_path):
            target = tmp_path / 'out'
            write(%s, target)
            assert target.read_bytes() == b'x'
    ''' % callback)
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


def test_genuine_test_module_import_code_is_fixture_owned(tmp_path):
    result = _session(tmp_path, 'def write(callback, dst): callback(dst)\n', test_body='''
        from pathlib import Path
        from aegis_core.subject import write
        target = Path(__file__).with_name('import-output')
        write(lambda dst: dst.write_bytes(b'x'), target)
        def test_write(): assert target.read_bytes() == b'x'
    ''')
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


def test_imported_module_body_replayed_by_product_is_unresolved(tmp_path):
    result = _session(tmp_path, "def write(g, dst): exec(g['BODY'], g)\n", test_body='''
        import sys
        from aegis_core.subject import write
        BODY = sys._getframe().f_code
        if 'OUTPUT' in globals(): OUTPUT.write_bytes(b'x')
        def test_write(tmp_path):
            globals()['OUTPUT'] = tmp_path / 'out'
            write(globals(), OUTPUT)
            assert OUTPUT.read_bytes() == b'x'
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


def test_loader_method_with_substitute_receiver_cannot_grant_test_provenance(tmp_path):
    result = _session(tmp_path, '''
        from importlib.machinery import SourceFileLoader
        class Substitute:
            def __init__(self, code): self.code = code
            def get_code(self, name): return self.code
        def write(module, dst):
            code = compile("__import__('pathlib').Path(%r).write_bytes(b'x')" % str(dst),
                           module.__file__, 'exec')
            SourceFileLoader.exec_module(Substitute(code), module)
    ''', extra={'tests/fixture_module.py': 'MARKER = True\n'}, test_body='''
        import sys
        from importlib.util import module_from_spec, spec_from_file_location
        from pathlib import Path
        from aegis_core.subject import write
        spec = spec_from_file_location('fixture_module', Path(__file__).with_name('fixture_module.py'))
        fixture = module_from_spec(spec)
        sys.modules[spec.name] = fixture
        spec.loader.exec_module(fixture)
        def test_write(tmp_path):
            loader = fixture.__loader__
            target = tmp_path / 'out'
            write(fixture, target)
            assert target.read_bytes() == b'x'
            assert fixture.__loader__ is loader and fixture.__spec__ is spec and fixture.MARKER is True
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


def test_malformed_exec_metadata_does_not_raise_or_grant_provenance(tmp_path):
    result = _session(tmp_path, '''
        import sys
        def write(src, dst):
            for args in ((), (object(),), (None,), (42, 'extra')):
                sys.audit('exec', *args)
            dst.write_bytes(b'x')
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout
    assert 'Traceback' not in result.stdout + result.stderr


def test_fixture_inventory_does_not_invoke_metaclass_dictionary_hooks(tmp_path):
    result = _session(tmp_path, 'def write(callback, dst): callback(dst)\n', test_body='''
        from aegis_core.subject import write
        ACTIVE = False
        class Meta(type):
            def __getattribute__(cls, name):
                if ACTIVE and name == '__dict__':
                    raise AssertionError('fixture inventory invoked metaclass hook')
                return type.__getattribute__(cls, name)
        class Fixture(metaclass=Meta):
            @staticmethod
            def callback(dst): dst.write_bytes(b'x')
        def test_write(tmp_path):
            global ACTIVE
            ACTIVE = True
            write(Fixture.callback, tmp_path / 'out')
    ''')
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


def test_exec_provenance_does_not_invoke_local_object_hooks(tmp_path):
    result = _session(tmp_path, '''
        class Trap:
            @property
            def __class__(self): raise AssertionError('metadata invoked local object hook')
        def write(g, dst):
            code = compile("dst.write_bytes(b'x')", g['__file__'], 'exec')
            trap = Trap()
            exec(code, g, {'dst': dst})
    ''', test_body='''
        from aegis_core.subject import write
        def test_write(tmp_path): write(globals(), tmp_path / 'out')
    ''')
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('filename', ['tests/fake.py', 'tests/test_subject.py', '<string>'])
def test_generated_test_filename_keeps_product_attribution(tmp_path, legacy_scopes, filename):
    result = _session(tmp_path, '''
        import os
        from pathlib import Path
        def write(src, dst):
            root = Path(__file__).parents[1]
            os.chdir(root / 'tests')
            filename = %r
            if filename != '<string>': filename = str(root / filename)
            exec(compile("dst.write_bytes(b'x')", filename, 'exec'), {'dst': dst})
    ''' % filename, legacy_scopes=legacy_scopes)
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


def test_unreadable_test_source_index_has_a_stable_refusal(tmp_path):
    result = _session(tmp_path, 'def write(src, dst): pass\n', test_index_failure=True)
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, result.stdout + result.stderr
    assert 'cannot load storage writer registry' in result.stderr
    assert 'Traceback' not in result.stdout + result.stderr
    assert 'private source-index error' not in result.stdout + result.stderr


def test_display_canonicalizes_then_redacts_then_truncates(tmp_path):
    # A synthetic code filename is data, not a path the plugin should open on
    # 3.11+. Splitting a known secret with ANSI verifies canonicalization first.
    token = 'ghp_' + 'a' * 36
    filename = 'aegis_core/' + 'x' * 470 + '-' + token[:10] + '\x1b[31m' + token[10:] + '.py'
    result = _session(tmp_path, '''
        from pathlib import Path
        def write(src, dst):
            source = "def hidden(dst): dst.write_text('x')"
            namespace = {}
            exec(compile(source, str(Path(__file__).parent.parent / %r), 'exec'), namespace)
            namespace['hidden'](dst)
    ''' % filename)
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'unregistered storage writer' in result.stdout
    assert '\x1b' not in result.stdout
    assert token[:10] not in result.stdout


@pytest.mark.parametrize("package", ["aegis_cli", "aegis_mcp", "aegis_sdk", "tools"])
def test_each_source_root_is_censused(tmp_path, package):
    extra = {
        package + "/subject.py": "def write(dst): dst.write_text('x')\n",
    }
    if package != "aegis_cli":
        extra[package + "/__init__.py"] = ""
    result = _session(tmp_path, "def write(src, dst): pass", extra=extra, test_body='''
        from %s.subject import write
        def test_write(tmp_path): write(tmp_path / 'out')
    ''' % package)
    assert result.returncode == 1, result.stdout + result.stderr
    assert package + "/subject.py:write open" in result.stdout


@pytest.mark.parametrize("access,refused", [("ACCESS_READ", False), ("ACCESS_COPY", False), ("ACCESS_WRITE", True)])
def test_file_mapping_write_capability(tmp_path, access, refused):
    result = _session(tmp_path, '''
        import mmap
        def write(stream):
            with mmap.mmap(stream.fileno(), 0, access=mmap.%s): pass
    ''' % access, test_body='''
        from aegis_core.subject import write
        def test_write(tmp_path):
            src = tmp_path / 'src'
            src.write_bytes(b'payload')
            with src.open('r+b') as stream: write(stream)
    ''')
    assert result.returncode == (1 if refused else 0), result.stdout + result.stderr
    if refused:
        assert "aegis_core/subject.py:write mmap.__new__" in result.stdout


def test_native_database_open_is_censused(tmp_path):
    result = _session(tmp_path, '''
        import sqlite3
        def write(src, dst):
            db = sqlite3.connect(str(dst))
            try:
                db.execute('create table records(value)')
                db.commit()
            finally:
                db.close()
    ''')
    assert result.returncode == 1, result.stdout + result.stderr
    assert "aegis_core/subject.py:write sqlite3.connect" in result.stdout


def test_missing_registry_is_a_fixed_usage_refusal(tmp_path):
    result = _session(tmp_path, "def write(src, dst): pass", extra={
        "tests/unit/core/test_storage_ratchets.py": "# no registries\n",
    })
    assert result.returncode == 4, result.stdout + result.stderr
    assert "cannot load storage writer registry" in result.stderr
    assert "Traceback" not in result.stderr


def test_equal_code_from_different_files_cannot_poison_scope_cache(tmp_path):
    result = _session(tmp_path, '''
        from pathlib import Path
        def write(src, dst):
            root = Path(__file__).parent.parent
            source = "def hidden(dst): dst.write_text('x')"
            namespaces = []
            for name in ('tests/fixture.py', 'aegis_core/hidden.py'):
                namespace = {}
                exec(compile(source, str(root / name), 'exec'), namespace)
                namespaces.append(namespace)
            assert namespaces[0]['hidden'].__code__ == namespaces[1]['hidden'].__code__
            for namespace in namespaces:
                namespace['hidden'](dst)
    ''')
    assert result.returncode == 1, result.stdout + result.stderr
    scope = 'hidden' if hasattr((lambda: None).__code__, 'co_qualname') else '<unresolved>'
    assert 'aegis_core/hidden.py:' + scope + ' open' in result.stdout


@pytest.mark.parametrize("flags,refused", [("O_RDONLY", False), ("O_WRONLY", True)])
def test_windows_descriptor_audit_event_on_all_platforms(tmp_path, flags, refused):
    # The documented event is testable without opening a native Windows handle.
    result = _session(tmp_path, '''
        import os
        import sys
        def write(src, dst): sys.audit('msvcrt.open_osfhandle', 0, os.%s)
    ''' % flags)
    assert result.returncode == (1 if refused else 0), result.stdout + result.stderr
    if refused:
        assert "aegis_core/subject.py:write msvcrt.open_osfhandle" in result.stdout


def test_registry_limit_refuses_before_parsing(tmp_path):
    registry = ('#' + 'x' * (1024 * 1024) + '\nNON_AEGIS_WRITERS = {}\n'
                'REVIEWED_DESCRIPTOR_OPERATIONS = {}\nAUDIT_WRITERS = {}\n')
    result = _session(tmp_path, "def write(src, dst): pass", extra={
        "tests/unit/core/test_storage_ratchets.py": registry,
    })
    assert result.returncode == 4, result.stdout + result.stderr
    assert "cannot load storage writer registry" in result.stderr


@pytest.mark.parametrize('launcher', [False, True], ids=['module', 'launcher'])
def test_explicit_benchmark_switch_disables_census(tmp_path, launcher):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')",
                      options=("--no-write-census",), launcher=launcher)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("module_write", [False, True], ids=["pytest_cache_only", "real_module_write"])
def test_pytest_bytecode_cache_is_out_of_scope(tmp_path, module_write):
    body = "from aegis_core.test_dependency import MARKER\n"
    if module_write:
        body += "from pathlib import Path\nPath(__file__).with_name('during-import').write_text('x')\n"
    body += "def write(src, dst): pass\n"
    result = _session(tmp_path, body, extra={"aegis_core/test_dependency.py": "MARKER = True\n"})
    assert result.returncode == (1 if module_write else 0), result.stdout + result.stderr
    if module_write:
        assert "aegis_core/subject.py:<module> open" in result.stdout


@pytest.mark.parametrize("file,scope", [
    ("aegis_core/atomicio.py", "_open_regular"),
    ("aegis_core/atomicio.py", "open_regular"),
    ("aegis_core/atomicio.py", "_replace_with_retry"),
    ("aegis_core/manager_store.py", "ManagerStore._audit"),
    ("aegis_core/message_codec_store.py", "Store._open"),
])
def test_unrelated_mutation_belongs_to_forwarder(tmp_path, file, scope):
    symlink_or_skip(tmp_path / 'missing', tmp_path / 'symlink-probe')
    module = file[:-3].replace('/', '.')
    if '.' in scope:
        owner, method = scope.split('.')
        source = 'import os\nclass %s:\n    def %s(self, src, dst): os.symlink(src, dst)\n' % (owner, method)
        call = '%s().%s(src, dst)' % (owner, method)
        imported = owner
    else:
        source = 'import os\ndef %s(src, dst): os.symlink(src, dst)\n' % scope
        call, imported = scope + '(src, dst)', scope
    operation = 'os.replace' if scope == '_replace_with_retry' else 'os.open'
    forwarded_event = 'os.rename' if operation == 'os.replace' else 'open'
    descriptor = repr({(file, scope, operation): (1, 'reviewed delegated operation')})
    result = _session(tmp_path, 'from %s import %s\ndef write(src, dst): %s\n' % (module, imported, call),
                      registry="{('aegis_core/subject.py', 'write'): 'approved caller'}",
                      descriptors=descriptor, forwarders=repr({module + '.' + scope: 1}),
                      forwarded=repr({(file, scope, operation): (forwarded_event, 'only the reviewed operation')}),
                      extra={file: source})
    assert result.returncode == 1, result.stdout + result.stderr
    assert file + ':' + scope + ' os.symlink' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize("operation,reviewed,approved", [
    ('rename', 'rename', True), ('symlink', 'rename', True), ('rename', 'rename', False),
    ('unlink', 'unlink', True), ('unlink', 'unlink', False),
    ('rename', 'unlink', True), ('unlink', 'rename', True),
])
def test_callback_transparency_checks_event_and_caller(tmp_path, operation, reviewed, approved):
    if operation == 'symlink':
        symlink_or_skip(tmp_path / 'missing', tmp_path / 'symlink-probe')
    result = _session(tmp_path, '''
        import os
        def dispatch(operation, *args): operation(*args)
        def approved(src, dst): pass
        def write(src, dst): dispatch(os.%s, %s)
    ''' % (operation, 'src' if operation == 'unlink' else 'src, dst'),
        registry="{('aegis_core/subject.py', 'write'): 'approved caller'}",
        callbacks=repr({('aegis_core/subject.py', 'write' if approved else 'approved', 'os.' + reviewed, 'dispatch'):
                        (1, 'only this caller and operation')}))
    refused = operation != reviewed or not approved
    assert result.returncode == (1 if refused else 0), result.stdout + result.stderr
    if refused:
        event = {'symlink': 'os.symlink', 'rename': 'os.rename', 'unlink': 'os.remove'}[operation]
        assert 'aegis_core/subject.py:dispatch ' + event in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.skipif(os.name != 'posix', reason='POSIX anchored-log behavior; unsupported-platform refusal has its own test')
def test_model_selection_failed_publication_cleanup_passes_census(tmp_path):
    # Exercise the real public append API and real os.remove audit event, with
    # this checkout's complete registry and plugin in a fresh interpreter.
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=',
         '--basetemp', str(tmp_path / 'publication-temp'),
         'tests/unit/core/test_model_select.py::test_stale_new_decision_refuses_without_changing_log'],
        cwd=ROOT, env=dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'),
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60,
    )
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout
    assert 'unregistered storage writer' not in result.stdout


@pytest.mark.parametrize("infrastructure", ['importlib', 'pytest_name'])
def test_delegated_infrastructure_write_belongs_to_product(tmp_path, infrastructure):
    body = ('''
        from importlib.machinery import SourceFileLoader
        def write(src, dst): SourceFileLoader('probe', str(src)).set_data(str(dst), b'x')
    ''' if infrastructure == 'importlib' else '''
        from helper import publish
        def write(src, dst): publish(dst)
    ''')
    result = _session(tmp_path, body, extra={
        "helper.py": "def publish(dst): dst.write_bytes(b'x')\n__name__ = '_pytest.scratch_fixture'\n",
    })
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write ' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize("legacy_scopes", [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize("child", [False, True], ids=['same_name_other_line', 'child_method'])
def test_dynamic_scope_cannot_borrow_registered_global(tmp_path, legacy_scopes, child):
    source = ('class Child:\n    def install(self, dst): dst.write_bytes(b"x")\n' if child else
              'def install(dst): dst.write_bytes(b"x")\n')
    call = "namespace['Child']().install(dst)" if child else "namespace['install'](dst)"
    result = _session(tmp_path, '''
        def install(dst): pass
        def write(src, dst):
            namespace = {}
            exec(compile(%r, __file__, 'exec'), namespace)
            %s
    ''' % ('\n' * 100 + source, call), legacy_scopes=legacy_scopes,
        registry="{('aegis_core/subject.py', 'install'): 'global install only'}")
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'first line' in result.stdout
    if legacy_scopes:
        assert '<unresolved>' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize("inner_refused", [False, True], ids=['inner_passes', 'inner_refuses'])
def test_nested_sessions_restore_outer_root_registry_and_violations(tmp_path, inner_refused):
    result = _session(tmp_path, '''
        def before(dst): dst.write_bytes(b'before')
        def allowed(dst): dst.write_bytes(b'allowed')
        def after(dst): dst.write_bytes(b'after')
    ''', registry="{('aegis_core/subject.py', 'allowed'): 'outer only'}", test_body='''
        from pathlib import Path
        import pytest
        import sys
        from aegis_core.subject import before, allowed, after
        def test_write(tmp_path):
            before(tmp_path / 'before')
            outer_tests = Path(__file__).parent
            inner = tmp_path / 'inner'
            tests = inner / 'tests'
            tests.mkdir(parents=True)
            (inner / 'tools').mkdir()
            (inner / 'pytest.ini').write_text('[pytest]\\n')
            (tests / 'conftest.py').write_text((outer_tests / 'conftest.py').read_text())
            registry = tests / 'unit' / 'core'
            registry.mkdir(parents=True)
            (registry / 'test_storage_ratchets.py').write_text(
                'NON_AEGIS_WRITERS = {}\\nREVIEWED_DESCRIPTOR_OPERATIONS = {}\\nAUDIT_WRITERS = {}\\n')
            source = inner / 'tools' / 'inner_product.py'
            source.write_text('def inner_write(dst): dst.write_bytes(b"x")\\n')
            probe = tests / 'test_inner.py'
            probe.write_text(%r)
            status = pytest.main(['-q', '--import-mode=importlib', '-c', str(inner / 'pytest.ini'),
                                  '--confcutdir', str(inner), '--rootdir', str(inner),
                                  '--basetemp', str(inner / 'temp'), str(probe)])
            assert status == %d
            assert sys.dont_write_bytecode is True
            allowed(tmp_path / 'allowed')
            after(tmp_path / 'after')
    ''' % (('def test_inner(tmp_path):\n'
            '    from pathlib import Path\n'
            '    path = Path(__file__).parents[1] / "tools" / "inner_product.py"\n'
            '    namespace = {}\n'
            '    exec(compile(path.read_text(), str(path), "exec"), namespace)\n'
            '    namespace["inner_write"](tmp_path / "out")\n') if inner_refused else
           'def test_inner(): pass\n', 1 if inner_refused else 0))
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:before open' in result.stdout, result.stdout + result.stderr
    assert 'aegis_core/subject.py:after open' in result.stdout, result.stdout + result.stderr
    assert 'aegis_core/subject.py:allowed open' not in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('threaded', [False, True], ids=['inner_thread', 'outer_product_thread'])
@pytest.mark.parametrize('same_root', [False, True], ids=['other_root', 'same_root'])
@pytest.mark.parametrize('generated', [False, True], ids=['direct', 'generated_test_filename'])
def test_outer_writer_is_governed_during_enabled_nested_session(tmp_path, legacy_scopes, threaded, same_root, generated):
    inner_test = '''
        import sys
        from pathlib import Path
        from threading import Thread
        from aegis_core.subject import write
        def test_inner(tmp_path):
            assert len(sys._aegis_write_census.sessions) == 2
            target = tmp_path / 'during-inner'
            if %r:
                worker = Thread(target=write, args=(None, target))
                worker.start()
                worker.join(timeout=5)
                assert not worker.is_alive()
            else:
                write(None, target)
            assert target.read_bytes() == b'x'
    ''' % threaded
    inner = 'tests/inner_case.py' if same_root else 'inner/tests/test_inner.py'
    extra = {inner: inner_test}
    if not same_root:
        extra.update({
            'inner/pytest.ini': '[pytest]\n',
            'inner/tests/unit/core/test_storage_ratchets.py':
                'NON_AEGIS_WRITERS = {}\nAUDIT_WRITERS = {}\n',
            'inner/tools/__init__.py': '',
        })
    body = ('''
        from pathlib import Path
        def write(src, dst):
            filename = str(Path(__file__).parents[1] / 'tests/test_subject.py')
            exec(compile("dst.write_bytes(b'x')", filename, 'exec'), {'dst': dst})
    ''' if generated else "def write(src, dst): dst.write_bytes(b'x')\n")
    result = _session(tmp_path, body,
                      legacy_scopes=legacy_scopes, extra=extra, options=('-s',), test_body='''
        import pytest
        import sys
        from pathlib import Path
        from aegis_core.subject import write
        def test_write(tmp_path):
            outer = Path(__file__).parents[1]
            inner = outer if %r else outer / 'inner'
            probe = outer / %r
            if inner != outer:
                (inner / 'tests/conftest.py').write_text(
                    (outer / 'tests/conftest.py').read_text(encoding='utf-8'), encoding='utf-8')
            status = pytest.main(['-q', '--import-mode=importlib', '-o', 'addopts=',
                                  '-c', str(inner / 'pytest.ini'), '--rootdir', str(inner),
                                  '--confcutdir', str(inner), '--basetemp', str(tmp_path / 'inner-temp'),
                                  str(probe)])
            assert status == %d
            assert len(sys._aegis_write_census.sessions) == 1
    ''' % (same_root, inner, 1 if same_root else 0))
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout, result.stdout + result.stderr
    assert result.stdout.count('unregistered storage writer') == (2 if same_root else 1)
    assert 'FAILED ' not in result.stdout


@pytest.mark.parametrize('forwarder', list(_registry_table('AUDIT_FORWARDER_OPERATIONS')), ids=lambda key: key[1])
@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('threaded', [False, True], ids=['direct', 'thread'])
@pytest.mark.parametrize('product_caller', [True, False], ids=['outer_product', 'fixture_or_unresolved'])
def test_cross_root_forwarding_resolves_the_actual_owner(tmp_path, forwarder, legacy_scopes, threaded, product_caller):
    file, scope, operation = forwarder
    event = _registry_table('AUDIT_FORWARDER_OPERATIONS')[forwarder][0]
    statement = ("os.replace(src, dst)" if event == 'os.rename' else
                 "fd = os.open(dst, os.O_CREAT | os.O_WRONLY)\ntry: os.write(fd, b'x')\nfinally: os.close(fd)")
    if '.' in scope:
        owner, method = scope.split('.')
        source = 'import os\nclass %s:\n    def %s(self, src, dst):\n' % (owner, method)
        source += textwrap.indent(statement, '        ') + '\n'
        expression = 'module.%s().%s' % (owner, method)
    else:
        source = 'import os\ndef %s(src, dst):\n' % scope + textwrap.indent(statement, '    ') + '\n'
        expression = 'module.' + scope
    inner_test = '''
        from importlib.util import module_from_spec, spec_from_file_location
        from pathlib import Path
        from threading import Thread
        from aegis_core.subject import write
        def test_inner(tmp_path):
            path = Path(__file__).parents[1] / %r
            spec = spec_from_file_location('inner_product', path)
            module = module_from_spec(spec)
            spec.loader.exec_module(module)
            operation = %s
            src, dst = tmp_path / 'src', tmp_path / 'dst'
            src.write_bytes(b'x')
            target, args = (write, (operation, src, dst)) if %r else (operation, (src, dst))
            if %r:
                worker = Thread(target=target, args=args)
                worker.start()
                worker.join(timeout=5)
                assert not worker.is_alive()
            else:
                target(*args)
            assert dst.read_bytes() == b'x'
    ''' % (file, expression, product_caller, threaded)
    registry = ('NON_AEGIS_WRITERS = {}\nAUDIT_WRITERS = {}\nAUDIT_FORWARDER_OPERATIONS = ' +
                repr(_registry_table('AUDIT_FORWARDER_OPERATIONS')) + '\n')
    result = _session(tmp_path, 'def write(operation, src, dst): operation(src, dst)\n',
                      legacy_scopes=legacy_scopes, options=('-s',), extra={
        'inner/pytest.ini': '[pytest]\n', 'inner/tests/test_inner.py': inner_test,
        'inner/tests/unit/core/test_storage_ratchets.py': registry, 'inner/' + file: source,
    }, test_body='''
        import pytest
        from pathlib import Path
        from aegis_core.subject import write
        def test_write(tmp_path):
            outer = Path(__file__).parents[1]
            inner = outer / 'inner'
            (inner / 'tests/conftest.py').write_text(
                (outer / 'tests/conftest.py').read_text(encoding='utf-8'), encoding='utf-8')
            status = pytest.main(['-q', '--import-mode=importlib', '-o', 'addopts=',
                                  '-c', str(inner / 'pytest.ini'), '--rootdir', str(inner),
                                  '--confcutdir', str(inner), '--basetemp', str(tmp_path / 'inner-temp'),
                                  str(inner / 'tests/test_inner.py')])
            assert status == %d
    ''' % (1 if threaded and not product_caller else 0))
    assert result.returncode == (pytest.ExitCode.TESTS_FAILED if product_caller else pytest.ExitCode.OK), result.stdout + result.stderr
    if product_caller:
        assert 'aegis_core/subject.py:write ' + event in result.stdout
    elif threaded:
        assert file + ':' + scope + ' ' + event in result.stdout
    else:
        assert 'unregistered storage writer' not in result.stdout
    assert 'FAILED ' not in result.stdout, result.stdout + result.stderr


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
@pytest.mark.parametrize('threaded', [False, True], ids=['direct', 'thread'])
def test_argon_inner_writer_through_outer_rename_forwarder_is_governed(tmp_path, legacy_scopes, threaded):
    inner_test = '''
        from importlib.util import module_from_spec, spec_from_file_location
        from pathlib import Path
        from threading import Thread
        from aegis_core.atomicio import _replace_with_retry
        def test_inner(tmp_path):
            path = Path(__file__).parents[1] / 'aegis_core/subject.py'
            spec = spec_from_file_location('inner_product', path)
            module = module_from_spec(spec)
            spec.loader.exec_module(module)
            src, dst = tmp_path / 'src', tmp_path / 'dst'
            src.write_bytes(b'x')
            if %r:
                worker = Thread(target=module.write, args=(_replace_with_retry, src, dst))
                worker.start()
                worker.join(timeout=5)
                assert not worker.is_alive()
            else:
                module.write(_replace_with_retry, src, dst)
            assert dst.read_bytes() == b'x'
    ''' % threaded
    extra = {name: (ROOT / name).read_text(encoding='utf-8') for name in
             ('aegis_core/atomicio.py', 'aegis_core/errors.py', 'aegis_core/taxonomy.py')}
    extra.update({
        'inner/pytest.ini': '[pytest]\n', 'inner/tests/test_inner.py': inner_test,
        'inner/tests/unit/core/test_storage_ratchets.py': 'NON_AEGIS_WRITERS = {}\nAUDIT_WRITERS = {}\n',
        'inner/aegis_core/subject.py':
            'def write(operation, src, dst): operation(str(src), str(dst), 1, 0)\n',
    })
    result = _session(tmp_path, 'def write(src, dst): pass\n', extra=extra,
                      forwarded=repr(_registry_table('AUDIT_FORWARDER_OPERATIONS')),
                      legacy_scopes=legacy_scopes, options=('-s',), test_body='''
        import pytest
        from pathlib import Path
        def test_write(tmp_path):
            outer = Path(__file__).parents[1]
            inner = outer / 'inner'
            (inner / 'tests/conftest.py').write_text(
                (outer / 'tests/conftest.py').read_text(encoding='utf-8'), encoding='utf-8')
            status = pytest.main(['-q', '--import-mode=importlib', '-o', 'addopts=',
                                  '-c', str(inner / 'pytest.ini'), '--rootdir', str(inner),
                                  '--confcutdir', str(inner), '--basetemp', str(tmp_path / 'inner-temp'),
                                  str(inner / 'tests/test_inner.py')])
            assert status == pytest.ExitCode.TESTS_FAILED
    ''')
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert result.stdout.count('unregistered storage writer') == 1
    assert 'aegis_core/subject.py:write os.rename' in result.stdout
    assert 'FAILED ' not in result.stdout, result.stdout + result.stderr


def test_filesystem_unix_bind_is_a_write(tmp_path, monkeypatch):
    if not hasattr(socket, 'AF_UNIX'):
        pytest.skip('AF_UNIX unavailable')
    monkeypatch.chdir(tmp_path)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.bind('probe.sock')
    except OSError:
        pytest.skip('filesystem AF_UNIX binds unavailable')
    finally:
        if Path('probe.sock').exists():
            Path('probe.sock').unlink()
    result = _session(tmp_path, '''
        import socket
        def write(src, dst):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.bind('census.sock')
    ''')
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write socket.bind' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize("family,address,refused", [
    (1, 'census.sock', True), (1, b'census.sock', True),
    (1, b'\x00abstract', False), (1, '', False), (2, ('127.0.0.1', 0), False),
], ids=['unix_text', 'unix_bytes', 'abstract', 'autobind', 'inet'])
def test_socket_bind_audit_address_classification(tmp_path, family, address, refused):
    result = _session(tmp_path, '''
        import sys
        from types import SimpleNamespace
        def write(src, dst): sys.audit('socket.bind', SimpleNamespace(family=%r), %r)
    ''' % (family, address), test_body='''
        import sys
        from types import SimpleNamespace
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            monkeypatch.setattr(plugin, 'socket', SimpleNamespace(AF_UNIX=1), raising=False)
            write(None, tmp_path)
    ''')
    assert result.returncode == (1 if refused else 0), result.stdout + result.stderr
    if refused:
        assert 'aegis_core/subject.py:write socket.bind' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('address,refused', [
    ("bytearray(b'census.sock')", True), ("memoryview(b'census.sock')", True),
    ("Text('census.sock')", True), ("Binary(b'census.sock')", True),
    ("bytearray()", False), ("memoryview(b'\\x00abstract')", False),
    ("Text('')", False), ("Binary(b'\\x00abstract')", False),
    ("released", True), ("object()", True), ("bytearray(4097)", True),
])
def test_unix_bind_normalizes_addresses_or_records_unreadable_types(tmp_path, address, refused):
    result = _session(tmp_path, '''
        import sys
        from types import SimpleNamespace
        class Text(str):
            def __len__(self): return 0
            def __str__(self): raise AssertionError('custom str called')
            def encode(self, *args): raise AssertionError('custom encode called')
        class Binary(bytes):
            def __len__(self): return 0
            def __bytes__(self): raise AssertionError('custom bytes called')
        released = memoryview(b'census.sock')
        released.release()
        def write(src, dst): sys.audit('socket.bind', SimpleNamespace(family=1), %s)
    ''' % address, test_body='''
        import sys
        from types import SimpleNamespace
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            monkeypatch.setattr(plugin, 'socket', SimpleNamespace(AF_UNIX=1), raising=False)
            write(None, tmp_path)
    ''')
    assert result.returncode == (pytest.ExitCode.TESTS_FAILED if refused else pytest.ExitCode.OK), result.stdout + result.stderr
    if refused:
        assert 'aegis_core/subject.py:write socket.bind' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('address', ["bytearray(b'census.sock')", "memoryview(b'census.sock')",
                                     "Text('census.sock')", "Binary(b'census.sock')"])
def test_real_unix_bind_byteslike_addresses_are_governed(tmp_path, address):
    if not hasattr(socket, 'AF_UNIX'):
        pytest.skip('AF_UNIX unavailable')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
            pass
    except OSError:
        pytest.skip('AF_UNIX sockets unavailable')
    result = _session(tmp_path, '''
        import socket
        class Text(str):
            def __len__(self): return 0
        class Binary(bytes):
            def __len__(self): return 0
        def write(src, dst):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                try:
                    stream.bind(%s)
                except OSError:
                    pass  # the write-capable audit event precedes a denied syscall
    ''' % address)
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write socket.bind' in result.stdout
    assert '1 passed' in result.stdout


def test_unix_bind_unsupported_probe_is_owned_and_monkeypatched(tmp_path):
    result = _session(tmp_path, '''
        import sys
        from types import SimpleNamespace
        def write(src, dst): sys.audit('socket.bind', SimpleNamespace(family=1), 'census.sock')
    ''', test_body='''
        import sys
        from types import SimpleNamespace
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            monkeypatch.setattr(plugin, 'socket', SimpleNamespace(), raising=False)
            write(None, tmp_path)
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


def test_implicit_bytecode_policy_is_scoped_and_restored(tmp_path):
    result = _session(tmp_path, '''
        import sys
        def write(src, dst): assert sys.dont_write_bytecode is True
    ''', check_bytecode_restore=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_unix_pathlike_address_is_not_evaluated_by_observer(tmp_path):
    result = _session(tmp_path, '''
        import os
        import sys
        from types import SimpleNamespace
        class Address(os.PathLike):
            def __fspath__(self): raise AssertionError('observer evaluated address')
        def write(src, dst): sys.audit('socket.bind', SimpleNamespace(family=1), Address())
    ''', test_body='''
        import sys
        from types import SimpleNamespace
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            monkeypatch.setattr(plugin, 'socket', SimpleNamespace(AF_UNIX=1))
            write(None, tmp_path)
    ''')
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write socket.bind' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('source', [None, 'def invalid(', '#'+('x' * (1024 * 1024))],
                         ids=['missing', 'unparseable', 'oversized'])
def test_unresolved_source_never_grants_name_only_authority(tmp_path, source):
    result = _session(tmp_path, '''
        from pathlib import Path
        def write(src, dst):
            namespace = {}
            filename = str(Path(__file__).with_name('target.py'))
            exec(compile('class Child:\\n    def install(self, dst): dst.write_bytes(b"x")\\n',
                         filename, 'exec'), namespace)
            namespace['Child']().install(dst)
    ''', registry="{('aegis_core/target.py', 'install'): 'global install only'}",
        legacy_scopes=True, extra={} if source is None else {'aegis_core/target.py': source})
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/target.py:<unresolved> open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('legacy_scopes', [False, True], ids=['native', 'py39'])
def test_same_line_anonymous_scope_does_not_borrow_outer_authority(tmp_path, legacy_scopes):
    result = _session(tmp_path, "def write(src, dst): (lambda: dst.write_bytes(b'x'))()\n",
                      registry="{('aegis_core/subject.py', 'write'): 'named scope only'}",
                      legacy_scopes=legacy_scopes)
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write.<lambda> open (first line 1)' in result.stdout
    assert '1 passed' in result.stdout


def test_infrastructure_without_product_frame_is_out_of_scope(tmp_path):
    result = _session(tmp_path, 'def write(src, dst): pass\n', test_body='''
        from importlib.machinery import SourceFileLoader
        def test_write(tmp_path):
            SourceFileLoader('probe', 'unused').set_data(str(tmp_path / 'out'), b'x')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


def test_argon_replace_retry_belongs_to_unregistered_caller(tmp_path):
    result = _session(tmp_path, '''
        from aegis_core.atomicio import _replace_with_retry
        def write(src, dst): _replace_with_retry(src, dst, 1, 0)
    ''', forwarded=repr(_registry_table('AUDIT_FORWARDER_OPERATIONS')), extra={
        name: (ROOT / name).read_text(encoding='utf-8')
        for name in ('aegis_core/atomicio.py', 'aegis_core/errors.py', 'aegis_core/taxonomy.py')
    })
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write os.rename' in result.stdout
    assert '1 passed' in result.stdout


def test_argon_explicit_importlib_atomic_write_is_owned(tmp_path):
    result = _session(tmp_path, '''
        from importlib._bootstrap_external import _write_atomic
        def write(src, dst): _write_atomic(str(dst), b'x')
    ''')
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


def test_argon_writer_after_nested_session_is_still_observed(tmp_path):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n", extra={
        'tests/inner_case.py': 'def test_inner(): pass\n',
    }, test_body='''
        import pytest
        from pathlib import Path
        from aegis_core.subject import write
        def test_write(tmp_path):
            suite = Path(__file__).parents[1]
            status = pytest.main(['-q', '-c', str(suite / 'pytest.ini'),
                                  '--rootdir', str(suite), '--confcutdir', str(suite),
                                  '--basetemp', str(tmp_path / 'nested-temp'),
                                  str(Path(__file__).with_name('inner_case.py'))])
            assert status == 0
            write(None, tmp_path / 'after')
    ''')
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


def test_product_forwarder_through_test_callback_keeps_product_owner(tmp_path):
    result = _session(tmp_path, '''
        import os
        def write(callback, dst): os.close(callback(dst))
    ''', forwarded="{('aegis_core/bridge.py', 'regular', 'os.open'): ('open', 'generic open only')}",
        extra={'aegis_core/bridge.py': 'import os\ndef regular(dst, flags): return os.open(dst, flags)\n'},
        test_body='''
            import os
            from aegis_core.bridge import regular
            from aegis_core.subject import write
            def callback(dst): return regular(dst, os.O_WRONLY | os.O_CREAT)
            def test_write(tmp_path): write(callback, tmp_path / 'out')
        ''')
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


def test_scope_sources_are_indexed_before_governed_operations(tmp_path):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      registry="{('aegis_core/subject.py', 'write'): 'approved writer'}", test_body='''
        import sys
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            def unexpected_read(filename):
                raise AssertionError('scope source read during governed operation')
            monkeypatch.setattr(plugin, '_census_source', unexpected_read)
            write(None, tmp_path / 'out')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('legacy_scopes', [False, True])
def test_repeated_writer_uses_cached_authority(tmp_path, legacy_scopes):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      registry="{('aegis_core/subject.py', 'write'): 'approved writer'}",
                      legacy_scopes=legacy_scopes, test_body='''
        import sys
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            write(None, tmp_path / 'first')
            def unexpected_resolution(self, site):
                raise AssertionError('authority resolved again for cached code')
            monkeypatch.setattr(plugin._WriteCensus, '_declared', unexpected_resolution)
            write(None, tmp_path / 'second')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


def test_cached_forwarder_keeps_event_specific_authority(tmp_path):
    result = _session(tmp_path, '''
        from aegis_core.bridge import forward
        def write(src, dst):
            forward('open', (str(dst), 'w', 65))
            forward('os.symlink', (str(src), str(dst), -1))
    ''', registry="{('aegis_core/subject.py', 'write'): 'approved caller'}",
        forwarded="{('aegis_core/bridge.py', 'forward', 'os.open'): ('open', 'open only')}",
        extra={'aegis_core/bridge.py': '''
            import sys
            def forward(event, args): sys.audit(event, *args)
        '''})
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/bridge.py:forward os.symlink' in result.stdout
    assert '1 passed' in result.stdout


def test_cached_callback_rechecks_each_caller(tmp_path):
    result = _session(tmp_path, '''
        import sys
        def dispatch(src, dst): sys.audit('open', str(dst), 'w', 65)
        def approved(src, dst): dispatch(src, dst)
        def write(src, dst):
            approved(src, dst)
            dispatch(src, dst)
    ''', registry="{('aegis_core/subject.py', 'write'): 'approved outer writer'}",
        callbacks="{('aegis_core/subject.py', 'approved', 'os.open', 'dispatch'): (1, 'only approved caller')}")
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:dispatch open' in result.stdout
    assert '1 passed' in result.stdout


def test_non_writes_never_enter_attribution(tmp_path):
    result = _session(tmp_path, '''
        import os
        import sys
        def write(src, dst):
            sys.audit('open', str(src), 'r', os.O_RDONLY)
            sys.audit('os.listdir', str(src))
            sys.audit('import', 'unused', None, [], [], [])
    ''', test_body='''
        import sys
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            def unexpected_walk(self, event, frame):
                raise AssertionError('non-write entered attribution')
            monkeypatch.setattr(plugin._WriteCensus, 'observe', unexpected_walk)
            write(tmp_path, None)
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


def test_repeated_direct_writer_avoids_identity_audit(tmp_path):
    result = _session(tmp_path, '''
        import sys
        def write(src, dst): sys.audit('open', str(dst), 'w', 65)
    ''', registry="{('aegis_core/subject.py', 'write'): 'approved writer'}", test_body='''
        import sys
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            write(None, tmp_path)
            def unexpected_identity(code):
                raise AssertionError('identity audit repeated for consecutive code')
            with monkeypatch.context() as patch:
                patch.setattr(plugin, 'id', unexpected_identity, raising=False)
                write(None, tmp_path)
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('legacy_scopes', [False, True])
def test_scope_index_prunes_non_authoritative_bodies(tmp_path, legacy_scopes):
    result = _session(tmp_path, '''
        from pathlib import Path
        def irrelevant():
            return 1 + 2
        class Outer:
            @staticmethod
            def write(src, dst): Path(dst).write_bytes(b'x')
        write = Outer.write
    ''', registry="{('aegis_core/subject.py', 'Outer.write'): 'approved nested writer'}",
        legacy_scopes=legacy_scopes,
        guard_index=hasattr((lambda: None).__code__, 'co_qualname') and not legacy_scopes)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('callback', [False, True], ids=['writer', 'callback'])
def test_front_cache_cannot_mix_code_and_authority(tmp_path, callback):
    source = ('''
        import sys
        def dispatch(src, dst): sys.audit('open', str(dst), 'w', 65)
        def approved(src, dst): dispatch(src, dst)
        def write(src, dst): dispatch(src, dst)
    ''' if callback else '''
        import sys
        def approved(src, dst): sys.audit('open', str(dst), 'w', 65)
        def write(src, dst): sys.audit('open', str(dst), 'w', 65)
    ''')
    registered = {('aegis_core/subject.py', 'approved'): 'approved writer'}
    if callback:
        registered[('aegis_core/subject.py', 'write')] = 'caller without callback approval'
    result = _session(tmp_path, source, registry=repr(registered),
                      callbacks=("{('aegis_core/subject.py', 'approved', 'os.open', 'dispatch'): (1, 'only approved caller')}"
                                 if callback else '{}'), test_body='''
        import sys
        from aegis_core import subject
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            subject.approved(None, tmp_path)
            original = plugin._WriteCensus.__getattribute__
            def interrupted_publication(self, name):
                # Model a thread switch between publishing last_code and
                # last_entry: new code paired with the old approved entry.
                if name == 'last_code': return subject.%s.__code__
                return original(self, name)
            with monkeypatch.context() as patch:
                patch.setattr(plugin._WriteCensus, '__getattribute__', interrupted_publication)
                subject.write(None, tmp_path)
    ''' % ('dispatch' if callback else 'write'))
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:%s open' % ('dispatch' if callback else 'write') in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('kind', ['mmap', 'str', 'bytes'])
def test_read_only_special_events_use_precomputed_filters(tmp_path, kind):
    body = '''
        import mmap
        import sys
        def write(src, dst): sys.audit('mmap.__new__', 3, 1, mmap.ACCESS_READ, 0)
    ''' if kind == 'mmap' else '''
        import sys
        from types import SimpleNamespace
        class Address(%s):
            def __getitem__(self, key): raise AssertionError('address was sliced')
        def write(src, dst):
            sys.audit('socket.bind', SimpleNamespace(family=1), Address(%r))
    ''' % (kind, '\x00abstract' if kind == 'str' else b'\x00abstract')
    result = _session(tmp_path, body, test_body='''
        import sys
        from types import SimpleNamespace
        from aegis_core.subject import write
        def test_write(tmp_path, monkeypatch):
            plugin = sys.modules[sys._aegis_write_census.__class__.__module__]
            # Only plugin references change; global mmap/socket stay real.
            monkeypatch.setattr(plugin, 'mmap', SimpleNamespace())
            monkeypatch.setattr(plugin, 'socket', SimpleNamespace(AF_UNIX=1))
            write(None, tmp_path)
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('legacy_scopes', [False, True])
def test_workers_reuse_controller_source_index(tmp_path, legacy_scopes):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      registry="{('aegis_core/subject.py', 'write'): 'approved writer'}",
                      legacy_scopes=legacy_scopes, worker_index_expected=0,
                      options=('-p', 'xdist.plugin', '-n', '2'))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('change', ['root', 'native', 'shape'])
def test_invalid_shared_source_index_falls_back(tmp_path, change):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      registry="{('aegis_core/subject.py', 'write'): 'approved writer'}",
                      worker_index_expected=1, shared_index_change=change,
                      options=('-p', 'xdist.plugin', '-n', '2'))
    assert result.returncode == 0, result.stdout + result.stderr


def test_scope_index_is_read_only(tmp_path):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      registry="{('aegis_core/subject.py', 'write'): 'approved writer'}",
                      test_body='''
        import os
        import pytest
        import sys
        from pathlib import Path
        from aegis_core.subject import write
        def test_write(tmp_path):
            state = sys._aegis_write_census.current
            filename = os.path.normcase(str(Path(__file__).parents[1] / 'aegis_core/subject.py'))
            with pytest.raises(TypeError):
                state.scopes[filename] = {}
            with pytest.raises(TypeError):
                state.scopes[filename][('write', 1)] = 'other'
            write(None, tmp_path / 'out')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


def test_worker_index_is_detached_from_transport(tmp_path):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      registry="{('aegis_core/subject.py', 'write'): 'approved writer'}",
                      worker_index_expected=0, options=('-p', 'xdist.plugin', '-n', '2'),
                      test_body='''
        import os
        from pathlib import Path
        from aegis_core.subject import write
        def test_write(tmp_path, request):
            filename = os.path.normcase(str(Path(__file__).parents[1] / 'aegis_core/subject.py'))
            data = request.config.workerinput['_aegis_census_source_index']
            data['scopes'][filename].clear()
            write(None, tmp_path / 'out')
    ''')
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('legacy_scopes', [False, True])
def test_shared_index_never_registers_unknown_worker_writer(tmp_path, legacy_scopes):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      legacy_scopes=legacy_scopes, worker_index_expected=0,
                      options=('-p', 'xdist.plugin', '-n', '2'))
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'aegis_core/subject.py:write open' in result.stdout
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('launcher', [False, True], ids=['module', 'launcher'])
@pytest.mark.parametrize('workers', [0, 2], ids=['serial', 'xdist'])
def test_entrypoint_starts_one_census_per_config(tmp_path, launcher, workers):
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      registry="{('aegis_core/subject.py', 'write'): 'approved writer'}",
                      launcher=launcher,
                      options=('-p', 'census_probe', '-p', 'xdist.plugin', '-n', str(workers)),
                      extra={'census_probe.py': '''
        import sys
        def pytest_sessionstart(session):
            # This hook runs in the controller and every worker, including
            # the controller that does not execute a test body under xdist.
            observer = sys._aegis_write_census
            assert observer.sessions == [session.config._write_census]
    '''},
                      test_body='''
        import sys
        from aegis_core.subject import write
        def test_write(tmp_path, request):
            observer = sys._aegis_write_census
            state = request.config._write_census
            assert observer.sessions == [state], 'census started more than once'
            assert observer.current is state
            plugin = sys.modules[observer.__class__.__module__]
            plugin.pytest_configure(request.config)
            assert request.config._write_census is state
            assert observer.sessions == [state], 'configure restarted the census'
            write(None, tmp_path / 'out')
    ''')
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout


@pytest.mark.parametrize('launcher', [False, True], ids=['module', 'launcher'])
@pytest.mark.parametrize('workers', [0, 2], ids=['serial', 'xdist'])
def test_entrypoint_refuses_before_basetemp_creation(tmp_path, launcher, workers):
    # ';' is a legal Windows path character; ':' is legal on POSIX.
    basetemp = tmp_path / ('unsafe' + os.pathsep + 'basetemp')
    result = _session(tmp_path, "def write(src, dst): pass\n", launcher=launcher,
                      options=('-p', 'xdist.plugin', '-n', str(workers),
                               '--basetemp', str(basetemp)))
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert output.count('choose --basetemp outside paths containing the path separator') == 1
    assert 'Traceback' not in output
    assert not basetemp.exists()
    assert not (tmp_path / 'child-temp').exists()


@pytest.mark.parametrize('workers', [0, 2], ids=['serial', 'xdist'])
@pytest.mark.parametrize('outcome', ['assertion', 'unregistered', 'empty'])
def test_launcher_preserves_pytest_refusal_codes(tmp_path, workers, outcome):
    bodies = {
        'assertion': "def test_body(): assert False, 'deliberate body failure'\n",
        'unregistered': None,
        'empty': '# no test functions\n',
    }
    result = _session(tmp_path, "def write(src, dst): dst.write_bytes(b'x')\n",
                      launcher=True, options=('-p', 'xdist.plugin', '-n', str(workers)),
                      test_body=bodies[outcome])
    expected = pytest.ExitCode.NO_TESTS_COLLECTED if outcome == 'empty' else pytest.ExitCode.TESTS_FAILED
    output = result.stdout + result.stderr
    assert result.returncode == expected, output
    if outcome == 'unregistered':
        assert 'aegis_core/subject.py:write open' in output
    elif outcome == 'assertion':
        assert 'deliberate body failure' in output


@pytest.mark.parametrize('workers', [0, 2], ids=['serial', 'xdist'])
def test_recursive_launcher_needs_no_census_option(tmp_path, workers):
    # The outer selection never discovers checkout/tests/conftest.py. Only
    # the early controller guard is registered, without the census option.
    checkout = tmp_path / 'checkout'
    tests = checkout / 'tests'
    tests.mkdir(parents=True)
    (tests / 'conftest.py').write_text((ROOT / 'tests/conftest.py').read_text(encoding='utf-8'),
                                     encoding='utf-8')
    external = tmp_path / 'external'
    external.mkdir()
    probe = external / 'test_probe.py'
    probe.write_text('import sys\ndef test_probe(tmp_path):\n'
                     '    assert not hasattr(sys, "_aegis_write_census")\n', encoding='utf-8')
    basetemp = tmp_path / 'external-temp'
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    result = subprocess.run(
        [sys.executable, 'tests/conftest.py', str(probe), '-q', '-p', 'xdist.plugin',
         '-n', str(workers), '-o', 'addopts=', '--rootdir', str(tmp_path),
         '--confcutdir', str(external), '--basetemp', str(basetemp)],
        cwd=checkout, env=env, capture_output=True, text=True, encoding='utf-8',
        errors='replace', timeout=60,
    )
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert '1 passed' in result.stdout
