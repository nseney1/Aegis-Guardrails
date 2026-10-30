"""AST Driver Runner and Registry for polyglot NormalizedAST execution.

Python and JavaScript/TypeScript parse in-process. External driver argv never
comes from repository content (H5, D10). It comes from drivers
registered in code, from the user-scope ~/.aegis/config.json, or from the packaged
templates in aegis_core/ast/drivers/templates, which a repo can only opt in to
(.aegis/config.json ``ast.packaged_drivers``).
A driver that is configured but cannot run safely here is "unavailable": parse_file
raises with the reason, so verification fails closed instead of skipping the file.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from aegis_core.ast.drivers.python import parse_python_ast
from aegis_core.ast.detect import NATIVE_JS_EXTENSIONS
from aegis_core.ast.schema import NormalizedAST
from aegis_core.ast.driver_errors import ASTDriverError, ASTDriverTimeoutError, NoDriverConfiguredError
from aegis_core.pathlookup import is_bare, INSIDE_FENCE, only_skipped, which
from aegis_core.workspace.base import Workspace
from aegis_core.workspace import as_workspace

__all__ = [
    "ASTDriverError",
    "ASTDriverTimeoutError",
    "NoDriverConfiguredError",
    "ASTDriverRegistry",
    "ASTDriverRunner",
    "resolve_driver_executable",
    "enforce_source_size",
]

_PYTHON_NAMES = frozenset({"{python}", "python3", "python", "python.exe", "python3.exe"})
_TEMPLATES_DIR = Path(__file__).resolve().parent / "drivers" / "templates"
# Packaged template -> interpreter looked up on PATH. rust_ast.py runs in-process.
_PACKAGED_INTERPRETERS = {"go_ast.go": "go"}
SOURCE_LIMIT_BYTES = 2 * 1024 * 1024


def enforce_source_size(file_path: Path | str) -> None:
    """Apply the byte-size policy after the caller confines the source path."""
    if Path(file_path).stat().st_size > SOURCE_LIMIT_BYTES:
        raise ASTDriverError('source exceeds 2 MiB', reason='too_large')


def _is_python_name(name: str) -> bool:
    clean = name.strip().lower()
    return clean in _PYTHON_NAMES


@dataclass(frozen=True)
class _DriverPlan:
    """How to run the driver chosen for one extension."""

    label: str
    argv: Tuple[str, ...] = ()
    cwd: Optional[str] = None  # None: the workspace root
    isolated_cwd: bool = False  # run in a fresh empty directory instead of ``cwd``
    in_process_rust: bool = False
    packaged_go: bool = False  # prepared lazily, never by descriptions or diagnostics
    in_process_js: bool = False
    unavailable: Optional[str] = None  # why the chosen driver cannot run here
    protocol: int = 1  # v2 is registered in code; user config remains v1


def _command_plan(command: str, ext: str, ws_root: Optional[Path] = None, where: str = "the driver") -> _DriverPlan:
    """Plan for a trusted command string (registered in code or from user scope).

    A bare executable name is resolved here, through absolute PATH entries outside
    ``ws_root``: left to the child, an empty or relative entry (and on Windows the
    current directory) would resolve against the workspace.
    """
    if ext == ".rs" and "rust_ast.py" in command:
        return _DriverPlan(label=command, in_process_rust=True)
    try:
        parts = _split_command(command)
    except ValueError as exc:  # unbalanced quotes
        return _DriverPlan(label=command, unavailable=f"the driver command cannot be parsed: {exc}")
    if parts and _is_python_name(parts[0]):
        parts[0] = resolve_driver_executable(parts[0]) or parts[0]
    elif parts and is_bare(parts[0]):
        found = which(parts[0], outside=ws_root)
        if found is None:
            return _DriverPlan(label=command, unavailable=f"{where} {_not_found(parts[0], ws_root)}")
        parts[0] = found
    return _DriverPlan(label=command, argv=tuple(parts))


def _not_found(name: str, ws_root: Optional[Path]) -> str:
    """Why ``name`` resolves nowhere aegis will run it from."""
    hits = only_skipped(name, outside=ws_root)
    if not hits:
        return f"needs '{name}', which was not found on PATH"
    hit = hits[0]
    if hit.reason == INSIDE_FENCE:
        return f"needs '{name}', which resolves to {hit.path} inside the workspace"
    return f"needs '{name}', which is reached only through the relative PATH entry {hit.entry!r} ({hit.path})"


def _inside_workspace(path: Union[Path, str], ws_root: Path) -> bool:
    """True if ``path``, as written or with symlinks resolved, lies inside the workspace."""
    roots = (Path(os.path.abspath(ws_root)), ws_root.resolve())
    for candidate in (Path(os.path.abspath(path)), Path(path).resolve()):
        for root in roots:
            if candidate == root or root in candidate.parents:
                return True
    return False


def _packaged_plan(ext: str, ws_root: Path) -> Optional[_DriverPlan]:
    from aegis_core.ast.detect import packaged_driver_for_extension

    config = packaged_driver_for_extension(ext)
    if config is None:
        return None
    filename = config["driver_filename"]
    label = f"packaged {filename}"
    if filename == "rust_ast.py":
        return _DriverPlan(label=label, in_process_rust=True)
    interpreter = _PACKAGED_INTERPRETERS.get(filename)
    if interpreter is None:
        return None
    if _inside_workspace(_TEMPLATES_DIR, ws_root):
        # Go reads go.mod/go.work upward from the template directory, which must
        # remain outside repository-controlled module and toolchain pins.
        return _DriverPlan(
            label=label,
            unavailable=(
                f"the packaged {filename} driver is installed inside the workspace ({_TEMPLATES_DIR}), "
                f"where {interpreter} would load modules from the repository; install aegis outside it"
            ),
        )
    # Go is the only packaged external driver; it is compiled lazily from the template.
    return _DriverPlan(label=label, packaged_go=True, protocol=2)


def _user_command_plan(command: str, ext: str, ws_root: Path) -> Optional[_DriverPlan]:
    """Plan for a command from ~/.aegis/config.json ``drivers``.

    The text is trusted, but an executable or path argument (including the value of a
    '--flag=path' argument) inside the repo would let repo content pick the code that
    runs, so such commands are refused. The process runs in a fresh empty directory, not
    the workspace: 'python -m mod', 'node --require ./x.js' and similar lookups resolve
    against the cwd. A provisioned selector such as 'go run .aegis/drivers/go_ast.go'
    means the packaged driver, never the repo's copy.
    """
    from aegis_core.ast.detect import names_packaged_driver, packaged_driver_for_extension

    config = packaged_driver_for_extension(ext)
    if config is not None and names_packaged_driver(command, config):
        return _packaged_plan(ext, ws_root)

    where = f"the ~/.aegis/config.json driver for '{ext}'"
    plan = _command_plan(command, ext, ws_root, where)
    if plan.in_process_rust or plan.unavailable or not plan.argv:
        return plan
    argv = list(plan.argv)
    first = _split_command(command)[0]
    if not _is_python_name(first):  # python names already resolved to sys.executable, which runs aegis itself
        if not is_bare(first):
            # The child runs in an empty directory, so a relative path is joined to the
            # workspace root here, never left to the child's cwd or to CreateProcess.
            full = os.path.normpath(os.path.join(str(ws_root), first))
            if _inside_workspace(full, ws_root):
                return replace(plan, unavailable=f"{where} runs {first}, which is inside the workspace")
            argv[0] = full
        elif _inside_workspace(argv[0], ws_root):
            return replace(plan, unavailable=f"{where} needs '{first}', which resolves to {argv[0]} inside the workspace")
    for arg in argv[1:]:
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        if value and not value.startswith("-") and os.path.lexists(ws_root / value) and _inside_workspace(ws_root / value, ws_root):
            return replace(plan, unavailable=f"{where} passes {value}, which is inside the workspace")
    return replace(plan, argv=tuple(argv), isolated_cwd=True)


class ASTDriverRegistry:
    """Registry mapping file extensions to driver commands."""

    def __init__(self, drivers: Optional[Mapping[str, str]] = None):
        self._drivers: Dict[str, str] = {}
        self._protocols: Dict[str, int] = {}
        if drivers:
            for ext, cmd in drivers.items():
                self.register_driver(ext, cmd)

    def register_driver(self, extension: str, command: str, *, protocol: int = 1) -> None:
        if type(protocol) is not int or protocol not in (1, 2):
            raise ValueError('driver protocol must be 1 or 2')
        clean_ext = extension if extension.startswith(".") else f".{extension}"
        self._drivers[clean_ext.lower()] = str(command).strip()
        self._protocols[clean_ext.lower()] = protocol

    def plan_driver(
        self,
        extension: str,
        workspace_root: Optional[Union[Path, str, Workspace]] = None,
        *,
        _slot_loader: Optional[Callable[[str, Path], Any]] = None,
    ) -> Optional[_DriverPlan]:
        """Choose the driver for an extension: registered, then user scope, then packaged opt-in."""
        clean_ext = extension if extension.startswith(".") else f".{extension}"
        clean_ext = clean_ext.lower()

        if clean_ext in NATIVE_JS_EXTENSIONS:
            return _DriverPlan(label='native JavaScript/TypeScript (in-process)', in_process_js=True)
        if clean_ext in self._drivers:
            fence = None
            if workspace_root:
                fence = Path(workspace_root.root if isinstance(workspace_root, Workspace) else workspace_root)
            plan = _command_plan(self._drivers[clean_ext], clean_ext, fence,
                                 f"the driver registered for '{clean_ext}'")
            return replace(plan, protocol=self._protocols[clean_ext])
        if not workspace_root:
            return None

        from aegis_core.skills.slots import SlotRegistry

        ws_root = Path(as_workspace(workspace_root).root)
        user = _slot_loader('user', ws_root) if _slot_loader else SlotRegistry.load_user(ws_root)
        user_cmd = user.get_ast_driver(clean_ext)
        if user_cmd:
            return _user_command_plan(user_cmd, clean_ext, ws_root)
        # A repo opt-in selects the packaged driver; nothing from the repo is run.
        repo = _slot_loader('repo', ws_root) if _slot_loader else SlotRegistry.load(ws_root)
        if repo.get_ast_driver(clean_ext):
            return _packaged_plan(clean_ext, ws_root)
        return None

    def resolve_driver(
        self,
        extension: str,
        workspace_root: Optional[Union[Path, str, Workspace]] = None,
    ) -> Optional[str]:
        """Describe the driver configured for an extension, or None if none is configured.

        A driver that is configured but cannot run here still returns its label, so callers
        go on to parse_file, which raises with the reason (verification fails closed).
        """
        plan = self.plan_driver(extension, workspace_root=workspace_root)
        return plan.label if plan is not None else None

    def get_configured_extensions(
        self,
        workspace_root: Optional[Union[Path, str, Workspace]] = None,
    ) -> set[str]:
        """Return all active source extensions from in-memory registry and workspace slots."""
        exts = set(self._drivers.keys()) | NATIVE_JS_EXTENSIONS
        exts.add(".py")
        if workspace_root:
            try:
                ws = as_workspace(workspace_root)
                from aegis_core.skills.slots import SlotRegistry

                exts.update(SlotRegistry.load(ws.root).get_configured_extensions())
                exts.update(SlotRegistry.load_user(ws.root).get_configured_extensions())
            except Exception:
                pass
        return exts


def _names_program(token: str) -> bool:
    """An absolute path to a file, or a bare name on an absolute PATH entry. A relative
    path names a file in aegis's own cwd, which the repository may control."""
    if is_bare(token):
        return which(token) is not None
    return os.path.isabs(token) and os.path.isfile(token)


def _split_command(cmd: str) -> list[str]:
    """Split a driver command line string into argv arguments, preserving Windows paths."""
    if os.name == "nt":
        parts = [p.strip('"') for p in shlex.split(cmd, posix=False)]
        # Rejoin the words of an unquoted path with spaces (C:\Program Files\...).
        if parts and not _names_program(parts[0]):
            for i in range(1, len(parts)):
                cand = " ".join(parts[: i + 1])
                if _names_program(cand):
                    return [cand] + parts[i + 1 :]
        return parts
    return shlex.split(cmd)


def resolve_driver_executable(name: str, workspace: Optional[Union[Path, str]] = None) -> Optional[str]:
    """Return the program a driver command's executable names, or None.

    Placeholder tokens '{python}', 'python3', and 'python' resolve deterministically
    to the active Python interpreter running aegis (sys.executable). A bare name is
    looked up in absolute PATH entries outside ``workspace`` (aegis_core.pathlookup); a
    relative path is joined to ``workspace``, never to the cwd; and a program inside
    ``workspace`` does not count, as when a user-scope driver runs.
    """
    clean = name.strip()
    if _is_python_name(clean):
        return sys.executable if sys.executable else None
    if is_bare(clean):
        return which(clean, outside=workspace)
    if not os.path.isabs(clean):
        if workspace is None:
            return None
        clean = os.path.normpath(os.path.join(os.fspath(workspace), clean))
    if workspace is not None and _inside_workspace(clean, Path(workspace)):
        return None
    if os.path.isfile(clean) and (os.name == "nt" or os.access(clean, os.X_OK)):
        return clean
    return None


class ASTDriverRunner:
    """Dispatches AST parsing to native Python or external driver subprocesses."""

    def __init__(self, registry: Optional[ASTDriverRegistry] = None, *, allow_build: bool = True):
        self.registry = registry or ASTDriverRegistry()
        self.allow_build = allow_build
        self._active = False
        self._plans: dict[tuple[str, str], Union[_DriverPlan, Exception, None]] = {}
        self._batches: dict[tuple[str, ...], object] = {}
        self._configs: dict[tuple[str, str], Any] = {}
        self._go_plans: dict[str, Union[_DriverPlan, Exception]] = {}

    def __enter__(self):
        self._active = True
        return self

    def __exit__(self, *_exc):
        self.close()

    def close(self) -> None:
        failure = None
        try:
            for batch in self._batches.values():
                try:
                    batch.close()
                except Exception as exc:
                    failure = failure or exc
        finally:
            self._batches.clear()
            self._plans.clear()
            self._configs.clear()
            self._go_plans.clear()
            self._active = False
        if failure is not None:
            raise failure

    def _plan(self, ext: str, workspace_root: Path) -> Optional[_DriverPlan]:
        key = (str(workspace_root.resolve()), ext)
        if not self._active:
            return self.registry.plan_driver(ext, workspace_root=workspace_root)
        if key not in self._plans:
            try:
                self._plans[key] = self.registry.plan_driver(ext, workspace_root=workspace_root,
                                                             _slot_loader=self._slots)
            except Exception as exc:
                self._plans[key] = exc
        plan = self._plans[key]
        if isinstance(plan, Exception):
            raise plan
        return plan

    def _slots(self, kind: str, root: Path):
        from aegis_core.skills.slots import SlotRegistry

        key = (str(root.resolve()), kind)
        if key not in self._configs:
            try:
                loader = SlotRegistry.load_user if kind == 'user' else SlotRegistry.load
                self._configs[key] = loader(root)
            except Exception as exc:
                self._configs[key] = exc
        value = self._configs[key]
        if isinstance(value, Exception):
            raise value
        return value

    def resolve_driver(self, ext: str, workspace_root: Optional[Union[Path, str]] = None) -> Optional[str]:
        plan = (self._plan(ext, Path(workspace_root)) if workspace_root is not None
                else self.registry.plan_driver(ext))
        return plan.label if plan is not None else None

    def get_configured_extensions(self, workspace_root: Union[Path, str]) -> set[str]:
        if not self._active:
            return self.registry.get_configured_extensions(workspace_root)
        extensions = set(self.registry._drivers) | NATIVE_JS_EXTENSIONS | {'.py'}
        for kind in ('user', 'repo'):
            extensions.update(self._slots(kind, Path(workspace_root)).get_configured_extensions())
        return extensions

    def _parse_batch(self, plan: _DriverPlan, target_path: Path, timeout: float) -> NormalizedAST:
        from aegis_core.ast.batch import BatchDriver

        if not self._active:
            with BatchDriver(plan.argv, label=plan.label, timeout=timeout) as batch:
                return batch.parse(target_path)
        if plan.argv not in self._batches:
            self._batches[plan.argv] = BatchDriver(plan.argv, label=plan.label, timeout=timeout)
        return self._batches[plan.argv].parse(target_path)

    def _prepare_go(self, plan: _DriverPlan, workspace: Path) -> _DriverPlan:
        from aegis_core.ast.gobuild import GoDriverUnavailableError, inspect_go_driver, prepare_go_driver

        key = str(workspace.resolve())
        if not self._active or key not in self._go_plans:
            try:
                if self.allow_build:
                    binary = prepare_go_driver(workspace)
                else:
                    status = inspect_go_driver(workspace)
                    if not status.cache_hit:
                        raise GoDriverUnavailableError('build_failed',
                                                       'Go driver cache is cold; run aegis doctor --drivers --fix')
                    binary = status.binary
                prepared = replace(plan, argv=(str(binary),))
            except GoDriverUnavailableError as exc:
                prepared = ASTDriverError(str(exc))
            if not self._active:
                if isinstance(prepared, Exception):
                    raise prepared
                return prepared
            self._go_plans[key] = prepared
        prepared = self._go_plans[key]
        if isinstance(prepared, Exception):
            raise prepared
        return prepared

    def parse_file(
        self,
        file_path: Union[Path, str],
        workspace_root: Optional[Union[Path, str, Workspace]] = None,
        timeout: float = 3.0,
        confine_root: Optional[Union[Path, str]] = None,
    ) -> NormalizedAST:
        """Parse source file into NormalizedAST, failing closed on driver defects.

        Drivers are resolved from ``workspace_root``. The file must lie inside
        ``confine_root`` when given (the pre-commit hook's index snapshot, which sits
        outside the repository), else inside ``workspace_root``.
        """
        ws_root = Path(as_workspace(workspace_root).root) if isinstance(workspace_root, Workspace) else Path(workspace_root or Path.cwd()).resolve()
        target_path = Path(file_path)
        if not target_path.is_absolute():
            target_path = (ws_root / target_path).resolve()
        else:
            target_path = target_path.resolve()

        if confine_root is not None:
            confine = Path(confine_root).resolve()
            try:
                target_path.relative_to(confine)
            except ValueError as exc:
                from aegis_core.errors import PathTraversalError
                raise PathTraversalError(f"File {target_path} escapes {confine}") from exc
        elif workspace_root:
            if isinstance(workspace_root, Workspace):
                workspace_root.confine_path(target_path)
            else:
                try:
                    target_path.relative_to(ws_root)
                except ValueError as exc:
                    from aegis_core.errors import PathTraversalError
                    raise PathTraversalError(f"File {target_path} escapes workspace {ws_root}") from exc

        if not target_path.exists():
            raise FileNotFoundError(f"File not found: {target_path}")

        ext = target_path.suffix.lower()
        if ext == '.go':
            enforce_source_size(target_path)

        # Fast path 1: Native Python driver
        if ext == ".py":
            return parse_python_ast(target_path)
        if ext in NATIVE_JS_EXTENSIONS:
            from aegis_core.ast.drivers.js import parse

            with target_path.open('rb') as stream:
                data = stream.read(SOURCE_LIMIT_BYTES + 1)
            if len(data) > SOURCE_LIMIT_BYTES:
                raise ASTDriverError('native source exceeds 2 MiB', reason='too_large')
            try:
                source = data.decode('utf-8')
            except UnicodeError as exc:
                raise ASTDriverError(f'invalid UTF-8: {exc}', reason='syntax') from exc
            return parse(source, str(target_path))

        plan = self._plan(ext, ws_root)
        if plan is None or plan.unavailable:
            reason = f": {plan.unavailable}" if plan is not None else ""
            raise NoDriverConfiguredError(
                f"No AST driver configured for extension '{ext}' on {target_path.name}{reason}"
            )
        if plan.packaged_go:
            plan = self._prepare_go(plan, ws_root)
        if plan.protocol == 2:
            return self._parse_batch(plan, target_path, timeout)

        # Fast path 2: Built-in Rust driver executed in-process
        if plan.in_process_rust:
            try:
                from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

                source = target_path.read_text(encoding="utf-8", errors="replace")
                ast_dict = parse_rust_source(source, str(target_path))
                return NormalizedAST.from_dict(ast_dict)
            except Exception as exc:
                raise ASTDriverError(
                    f"In-process Rust AST driver failed on {target_path.name}: {exc}"
                ) from exc

        if not plan.argv:
            raise ASTDriverError(f"Empty driver command for extension '{ext}'")

        if plan.isolated_cwd:
            with tempfile.TemporaryDirectory(prefix="aegis-ast-cwd-") as neutral:
                stdout = _run_plan(plan, neutral, timeout, target_path)
        else:
            stdout = _run_plan(plan, plan.cwd or str(ws_root), timeout, target_path)

        try:
            return NormalizedAST.from_json(stdout)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            raise ASTDriverError(
                f"AST driver '{plan.label}' returned invalid NormalizedAST JSON: {exc}\nOutput: {stdout[:300]}"
            ) from exc


def _run_plan(plan: _DriverPlan, cwd: str, timeout: float, target_path: Path) -> str:
    return _run_driver(list(plan.argv) + [str(target_path)], cwd, timeout, plan.label, target_path.name)


def _run_driver(argv: List[str], cwd: str, timeout: float, label: str, target_name: str) -> str:
    """Run one driver process without a shell and return its stdout, failing closed."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise ASTDriverTimeoutError(
            f"AST driver '{label}' timed out after {timeout}s on {target_name}"
        ) from exc
    except Exception as exc:
        raise ASTDriverError(f"Failed to execute AST driver '{label}': {exc}") from exc

    if proc.returncode != 0:
        err_output = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise ASTDriverError(
            f"AST driver '{label}' failed with exit code {proc.returncode}: {err_output}"
        )
    return proc.stdout
