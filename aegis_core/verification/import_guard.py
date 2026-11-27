from __future__ import annotations

"""Import Guard — Layer 1 tool for detecting unguarded third-party imports.

Scans Python files using AST to find import statements, classifies them
as stdlib or third-party, and checks whether third-party imports are
properly guarded (try/except or pytest.importorskip).

Catches the exact class of bug that broke CI: a bare `import yaml` in
a test file when PyYAML isn't in the project's dependency manifest.
"""

import ast
import os
import re
import sys
from dataclasses import dataclass

from aegis_core.ast.drivers.python import read_python_source
from aegis_core.match import is_test_path

from . import ToolEvidence

# Build stdlib module set from the running interpreter
_STDLIB_MODULES: set[str] | None = None


_FALLBACK_STDLIB_MODULES = frozenset({
    '__future__', '_abc', '_aix_support', '_ast', '_asyncio', '_bisect',
    '_blake2', '_bz2', '_codecs', '_codecs_cn', '_codecs_hk',
    '_codecs_iso2022', '_codecs_jp', '_codecs_kr', '_codecs_tw',
    '_collections', '_collections_abc', '_compat_pickle', '_compression',
    '_contextvars', '_crypt', '_csv', '_ctypes', '_curses', '_curses_panel',
    '_datetime', '_dbm', '_decimal', '_elementtree', '_frozen_importlib',
    '_frozen_importlib_external', '_functools', '_gdbm', '_hashlib', '_heapq',
    '_imp', '_io', '_json', '_locale', '_lsprof', '_lzma', '_markupbase',
    '_md5', '_msi', '_multibytecodec', '_multiprocessing', '_opcode',
    '_operator', '_osx_support', '_overlapped', '_pickle', '_posixshmem',
    '_posixsubprocess', '_py_abc', '_pydatetime', '_pydecimal', '_pyio',
    '_pylong', '_queue', '_random', '_scproxy', '_sha1', '_sha2', '_sha3',
    '_signal', '_sitebuiltins', '_socket', '_sqlite3', '_sre', '_ssl',
    '_stat', '_statistics', '_string', '_strptime', '_struct', '_symtable',
    '_thread', '_threading_local', '_tkinter', '_tokenize', '_tracemalloc',
    '_typing', '_uuid', '_warnings', '_weakref', '_weakrefset', '_winapi',
    '_zoneinfo', 'abc', 'aifc', 'antigravity', 'argparse', 'array', 'ast',
    'asynchat', 'asyncio', 'asyncore', 'atexit', 'audioop', 'base64', 'bdb',
    'binascii', 'binhex', 'bisect', 'builtins', 'bz2', 'cProfile',
    'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd', 'code', 'codecs',
    'codeop', 'collections', 'colorsys', 'compileall', 'concurrent',
    'configparser', 'contextlib', 'contextvars', 'copy', 'copyreg', 'crypt',
    'csv', 'ctypes', 'curses', 'dataclasses', 'datetime', 'dbm', 'decimal',
    'difflib', 'dis', 'distutils', 'doctest', 'email', 'encodings',
    'ensurepip', 'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp',
    'fileinput', 'fnmatch', 'formatter', 'fractions', 'ftplib', 'functools',
    'gc', 'genericpath', 'getopt', 'getpass', 'gettext', 'glob', 'graphlib',
    'grp', 'gzip', 'hashlib', 'heapq', 'hmac', 'html', 'http', 'idlelib',
    'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io', 'ipaddress',
    'itertools', 'json', 'keyword', 'lib2to3', 'linecache', 'locale',
    'logging', 'lzma', 'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes',
    'mmap', 'modulefinder', 'msilib', 'msvcrt', 'multiprocessing', 'netrc',
    'nis', 'nntplib', 'nt', 'ntpath', 'nturl2path', 'numbers', 'opcode',
    'operator', 'optparse', 'os', 'ossaudiodev', 'parser', 'pathlib', 'pdb',
    'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform', 'plistlib',
    'poplib', 'posix', 'posixpath', 'pprint', 'profile', 'pstats', 'pty',
    'pwd', 'py_compile', 'pyclbr', 'pydoc', 'pydoc_data', 'pyexpat', 'queue',
    'quopri', 'random', 're', 'readline', 'reprlib', 'resource',
    'rlcompleter', 'runpy', 'sched', 'secrets', 'select', 'selectors',
    'shelve', 'shlex', 'shutil', 'signal', 'site', 'smtpd', 'smtplib',
    'sndhdr', 'socket', 'socketserver', 'spwd', 'sqlite3', 'sre_compile',
    'sre_constants', 'sre_parse', 'ssl', 'stat', 'statistics', 'string',
    'stringprep', 'struct', 'subprocess', 'sunau', 'symtable', 'sys',
    'sysconfig', 'syslog', 'tabnanny', 'tarfile', 'telnetlib', 'tempfile',
    'termios', 'test', 'textwrap', 'this', 'threading', 'time', 'timeit',
    'tkinter', 'token', 'tokenize', 'tomllib', 'trace', 'traceback',
    'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types', 'typing',
    'unicodedata', 'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings',
    'wave', 'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref',
    'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib',
    'zoneinfo',
})


def _get_stdlib_modules() -> set[str]:
    """Lazily compute the set of stdlib top-level module names."""
    global _STDLIB_MODULES
    if _STDLIB_MODULES is not None:
        return _STDLIB_MODULES

    # Python 3.10+ has sys.stdlib_module_names; union with fallback for Python 3.9
    # and cross-platform stdlib module definitions.
    _STDLIB_MODULES = set(getattr(sys, "stdlib_module_names", set())) | set(_FALLBACK_STDLIB_MODULES)
    return _STDLIB_MODULES


@dataclass
class ImportInfo:
    """A single import statement found in a source file."""
    module: str       # top-level module name (e.g. 'yaml', not 'yaml.safe_load')
    lineno: int       # line number in the source file
    guarded: bool     # True if inside try/except or via importorskip


def is_stdlib(module: str) -> bool:
    """Check if a module name is part of the Python standard library."""
    return module in _get_stdlib_modules()


# Pattern for pytest.importorskip("module_name")
_IMPORTORSKIP_RE = re.compile(
    r'''(?:pytest\.)?importorskip\(\s*['\"](\w+)['"]\s*\)'''
)


def _append_import(
    results: list[ImportInfo], guarded_modules: set[str], record: ImportInfo,
) -> None:
    """Keep guarded membership in sync without changing record order."""
    results.append(record)
    if record.guarded:
        guarded_modules.add(record.module)


def extract_imports(filepath: str) -> list[ImportInfo]:
    """Extract all import statements from a Python source file.

    Detects:
    - `import foo` and `import foo.bar` (extracts top-level 'foo')
    - `from foo import bar` (extracts top-level 'foo')
    - `pytest.importorskip("foo")` (extracts 'foo', marked guarded)
    - try/except ImportError guards (marks enclosed imports as guarded)

    Args:
        filepath: Path to a .py file

    Returns:
        List of ImportInfo with module name, line number, and guard status
    """
    source = read_python_source(filepath)

    results: list[ImportInfo] = []
    guarded_modules: set[str] = set()

    # First pass: find importorskip calls via regex (not easily caught by AST)
    previous_start, lineno = 0, 1
    for match in _IMPORTORSKIP_RE.finditer(source):
        module = match.group(1)
        lineno += source.count('\n', previous_start, match.start())
        previous_start = match.start()
        _append_import(results, guarded_modules, ImportInfo(module=module, lineno=lineno, guarded=True))

    # Second pass: AST-based import extraction
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return results

    # Collect line ranges of try blocks for guard detection
    try_ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            # Check if any handler catches ImportError or is bare except
            has_import_guard = False
            max_end = node.end_lineno or node.lineno
            for handler in node.handlers:
                if handler.end_lineno:
                    max_end = max(max_end, handler.end_lineno)
                if handler.type is None:
                    # bare except:
                    has_import_guard = True
                elif isinstance(handler.type, ast.Name) and handler.type.id in (
                    'ImportError', 'ModuleNotFoundError', 'Exception',
                ):
                    has_import_guard = True
            if has_import_guard:
                try_ranges.append((node.lineno, max_end))

    def _is_in_try(lineno: int) -> bool:
        return any(start <= lineno <= end for start, end in try_ranges)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split('.')[0]
                # Skip if already found via importorskip
                if module in guarded_modules:
                    continue
                _append_import(results, guarded_modules, ImportInfo(
                    module=module,
                    lineno=node.lineno,
                    guarded=_is_in_try(node.lineno),
                ))
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module.split('.')[0]
            if module in guarded_modules:
                continue
            _append_import(results, guarded_modules, ImportInfo(
                module=module,
                lineno=node.lineno,
                guarded=_is_in_try(node.lineno),
            ))

    return results


def _discover_project_packages(project_root: str) -> set[str]:
    """Inventory traditional and namespace packages using the existing probes."""
    local_packages: set[str] = set()
    for entry in os.listdir(project_root):
        if entry.startswith(('.', '_')):
            continue
        entry_path = os.path.join(project_root, entry)
        if os.path.isdir(entry_path):
            init_path = os.path.join(entry_path, '__init__.py')
            if os.path.exists(init_path):
                local_packages.add(entry)
                # Also register individual .py basenames inside the
                # package so bare `from jit_engine import X` is local
                # when the package dir is on sys.path at test time.
                try:
                    for fname in os.listdir(entry_path):
                        if fname.endswith('.py') and not fname.startswith('_'):
                            local_packages.add(fname[:-3])
                except PermissionError:
                    pass
            else:
                # Check for namespace package: contains .py files or sub-packages
                try:
                    contents = os.listdir(entry_path)
                except PermissionError:
                    continue
                has_python = any(f.endswith('.py') for f in contents)
                has_subpkg = any(
                    os.path.exists(os.path.join(entry_path, d, '__init__.py'))
                    for d in contents
                    if os.path.isdir(os.path.join(entry_path, d))
                )
                if has_python or has_subpkg:
                    local_packages.add(entry)
                    # Also register individual .py basenames inside
                    # non-package directories (e.g. enzymes/jit_engine.py
                    # → 'jit_engine') so bare `from jit_engine import X`
                    # is recognised as local when enzymes/ is on sys.path.
                    if not os.path.exists(init_path):
                        for fname in contents:
                            if fname.endswith('.py') and not fname.startswith('_'):
                                local_packages.add(fname[:-3])
    return local_packages


def _discover_siblings(target_dir: str) -> set[str]:
    """Sibling basenames come from the source directory, including snapshots."""
    try:
        return {name[:-3] for name in os.listdir(target_dir)
                if name.endswith('.py') and not name.startswith('_')}
    except PermissionError:
        return set()


class LocalPackageDiscovery:
    """One verification run's inventories; never retain this across runs."""

    def __init__(self) -> None:
        self._projects: dict[str, set[str]] = {}
        self._project_errors: dict[str, OSError] = {}
        self._siblings: dict[str, set[str]] = {}

    def for_file(self, filepath: str, project_root: str) -> set[str]:
        """Keep project packages separate from each source directory's siblings."""
        if project_root not in self._projects and project_root not in self._project_errors:
            try:
                self._projects[project_root] = _discover_project_packages(project_root)
            except OSError as exc:
                self._project_errors[project_root] = exc
        if project_root in self._project_errors:
            # Preserve per-file failures without repeating discovery or retaining
            # an ever-growing traceback when the same refusal is reported again.
            raise self._project_errors[project_root].with_traceback(None)
        target_dir = os.path.dirname(os.path.abspath(filepath))
        if target_dir not in self._siblings:
            self._siblings[target_dir] = _discover_siblings(target_dir)
        return self._projects[project_root] | self._siblings[target_dir]


def check(
    filepath: str,
    allowed_deps: set[str] | None = None,
    project_root: str | None = None,
    discovery: LocalPackageDiscovery | None = None,
) -> ToolEvidence:
    """Check a Python file for unguarded third-party imports.

    Args:
        filepath: Path to the Python source file
        allowed_deps: Set of allowed third-party module names
            (e.g. from pyproject.toml dependencies). Imports of these
            modules are not flagged even if unguarded.
        project_root: Root directory of the project. If provided,
            any top-level directory containing __init__.py is treated
            as a local package and not flagged.
        discovery: Optional inventory shared only within this verification run.

    Returns:
        ToolEvidence with verdict=True if no unguarded third-party imports,
        False otherwise. Lines contains line numbers of violations.
    """
    if allowed_deps is None:
        allowed_deps = set()
    else:
        allowed_deps = set(allowed_deps)

    # For test files, pytest is standard
    if is_test_path(filepath):
        allowed_deps.add('pytest')

    local_packages = set()
    if project_root:
        local_packages = (discovery or LocalPackageDiscovery()).for_file(filepath, project_root)

    imports = extract_imports(filepath)
    violations: list[tuple[str, int]] = []

    for imp in imports:
        if is_stdlib(imp.module):
            continue
        if imp.module in allowed_deps:
            continue
        if imp.module in local_packages:
            continue
        if imp.guarded:
            continue
        violations.append((imp.module, imp.lineno))

    if not violations:
        return ToolEvidence(
            tool="import_guard",
            target=os.path.basename(filepath),
            verdict=True,
            detail="All imports are stdlib, allowed, or guarded",
        )

    modules = [v[0] for v in violations]
    lines = sorted(v[1] for v in violations)
    return ToolEvidence(
        tool="import_guard",
        target=os.path.basename(filepath),
        verdict=False,
        detail=f"Unguarded third-party imports: {', '.join(modules)}",
        lines=lines,
    )

