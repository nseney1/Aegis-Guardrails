"""Which workspace a call governs: the AD-4 resolver (host-matrix §3.6).

``resolve_binding`` returns a :class:`WorkspaceBinding` ``{root, source, confidence}``.
The first source that yields a governed root wins:

1. **Operator pin** (``AEGIS_WORKSPACE`` in the registration env): strict. A pin that
   is not a directory holding ``.aegis/``, or that names ``$HOME`` or the filesystem
   root, is an *error*, never a fallback to another source.
2. **Host-attested roots**, in order: Codex ``_meta.x-codex-turn-metadata.workspaces``,
   ``CLAUDE_PROJECT_DIR``, MCP roots. Each maps to the governed root its bounded walk-up
   finds (a session opened in a monorepo subdirectory governs the repo). With several,
   the call's files choose; when they decide nothing, the first source in that order
   wins if it names one root, and otherwise the result is a HOLD.
3. **Registry** (``~/.aegis/workspaces.json``, written by ``aegis init``): the call's
   files may only *select among* registered roots, never introduce one. Relative files
   name a path in the project the server runs in, so they select only when the cwd
   walk-up (4) finds no workspace; when it finds one, that workspace binds if it holds
   them, and otherwise the result is a HOLD.
4. **Bounded walk-up** from the server cwd (see ``bounded_walk_up``).

Nothing else ever names a workspace: there is no model-supplied workspace argument.
When the sources that are present disagree (a pin against a host root or against the
registered workspace holding the call's files; an ungoverned host root against a
registered one; the cwd's workspace against the registered one holding the call's
relative files), the result is a **hold** with a machine-readable ``reason``; Aegis
never silently governs another project. Nothing resolved is ``unbound`` ("not governed
here"). Resolution only reads: it creates no directory and writes no file.

The registry schema (``aegis init`` and ``aegis uninstall`` are its only writers)::

    {"v": 1, "workspaces": [{"root": "/abs/path", "added_at": "...", "added_by": "aegis init",
                             "hosts": ["codex-cli", ...]}, ...]}

Membership means "this user ran ``aegis init`` here on this machine"; it grants no
trust beyond letting a call's files select that root. Readers ignore unknown keys,
skip invalid entries (each is reported in ``Registry.problems``) and read a file with
an unknown ``v`` as empty.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union

from aegis_core.errors import WorkspaceError, WorkspaceNotFoundError
from aegis_core.workspace.layout import UserLayout, is_aegis_workspace

__all__ = [
    "Attested",
    "CONFIDENCE",
    "REGISTRY_VERSION",
    "Registry",
    "WorkspaceBinding",
    "WorkspaceHold",
    "bounded_walk_up",
    "check_pin_agrees",
    "denial",
    "denial_message",
    "git_boundary",
    "home_message",
    "read_registry",
    "resolve_binding",
    "resolve_cli_root",
]

PathLike = Union[str, os.PathLike]

REGISTRY_VERSION = 1

#: How much a source is trusted to name the workspace (AD-2 tiers).
CONFIDENCE: Mapping[str, str] = {
    "pin": "operator",
    "codex_meta": "host_attested",
    "claude_project_dir": "host_attested",
    "mcp_roots": "host_attested",
    "registry": "registered",
    "walk_up": "inferred",
}

BOUND, UNBOUND, HOLD, ERROR = "bound", "unbound", "hold", "error"


class Attested(NamedTuple):
    """A root the host (not the model) reports for the session: ``source`` is a CONFIDENCE key."""

    source: str
    path: str


@dataclass(frozen=True)
class WorkspaceBinding:
    """The outcome of resolution: ``status`` is bound, unbound, hold or error.

    A bound binding has ``root``, ``source`` and ``confidence``; the others have a
    machine-readable ``reason`` and a human ``message``. ``details`` names the
    disagreeing paths of a hold.
    """

    status: str
    root: Optional[Path] = None
    source: Optional[str] = None
    confidence: Optional[str] = None
    reason: Optional[str] = None
    message: str = ""
    details: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    @property
    def bound(self) -> bool:
        return self.status == BOUND

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "root": str(self.root) if self.root is not None else None,
            "source": self.source,
            "confidence": self.confidence,
            "reason": self.reason,
            "message": self.message,
            "details": {key: value for key, value in self.details},
        }


class WorkspaceHold(WorkspaceError):
    """The CLI's sources disagree; ``binding`` is the hold (status, reason, details)."""

    def __init__(self, binding: WorkspaceBinding) -> None:
        super().__init__(binding.message)
        self.binding = binding


def _bound(root: Path, source: str) -> WorkspaceBinding:
    return WorkspaceBinding(BOUND, root, source, CONFIDENCE[source])


def _not_bound(status: str, reason: str, message: str, source: Optional[str] = None, **details: Any) -> WorkspaceBinding:
    return WorkspaceBinding(status, source=source, reason=reason, message=message, details=tuple(details.items()))


# ── denylist and the bounded walk-up ─────────────────────────────────────────

def _home() -> Optional[Path]:
    layout = UserLayout.current()  # honours USERPROFILE on Windows (Path.home)
    if layout is None:
        return None
    try:
        return _resolve(layout.home)
    except OSError:
        return None


def _resolve(path: Path) -> Path:
    """``path.resolve()`` with one failure type: OSError.

    Before Python 3.13 a symlink loop raises RuntimeError, and a NUL byte raises
    ValueError on every version. Paths here come from the environment, the host and
    the model, so each of those must read as "cannot be resolved", never escape.
    """
    try:
        return path.resolve()
    except (ValueError, RuntimeError) as exc:
        raise OSError(f"cannot resolve {os.fspath(path)!r}: {exc}") from exc


def _resolved(path: PathLike, base: Optional[Path] = None) -> Path:
    try:
        p = Path(os.path.expanduser(os.fspath(path)))
    except ValueError as exc:
        raise OSError(f"cannot resolve {path!r}: {exc}") from exc
    if not p.is_absolute() and base is not None:
        p = base / p
    return _resolve(p)


def _shown(path: PathLike) -> str:
    """``path`` resolved for a message or a hold's details, or as given when it cannot be."""
    try:
        return str(_resolved(path))
    except OSError:
        return os.fspath(path)


def denial(path: Path) -> Optional[str]:
    """Why ``path`` (resolved) can never be a workspace: "home_directory",
    "filesystem_root", or None."""
    if path.parent == path:
        return "filesystem_root"
    home = _home()
    if home is not None and path == home:
        return "home_directory"
    return None


def denial_message(path: Path) -> Optional[str]:
    """The CLI refusal for a root that can never be a workspace, or None."""
    denied = denial(path)
    if denied == "home_directory":
        return home_message(path)
    if denied:
        return f"not an Aegis workspace ({path} is the filesystem root); run aegis init in a project"
    return None


def git_boundary(start: Path) -> Optional[Path]:
    """The innermost repository root around ``start``: the nearer of the closest
    ancestor holding a ``.git`` entry and git's own toplevel (asked through gitsafe).

    The ``.git`` marker needs no subprocess and also bounds a broken or unreadable
    repository; git's answer covers worktrees and ``GIT_DIR`` layouts. The deeper of
    the two wins, so the bound is never looser than either.
    """
    from aegis_core import gitsafe

    marker = next((d for d in (start, *start.parents) if os.path.lexists(d / ".git")), None)
    top = gitsafe.toplevel(start)
    if top is not None:
        try:
            top = _resolve(top)
        except OSError:
            top = None
    found = [p for p in (marker, top) if p is not None and (p == start or p in start.parents)]
    return max(found, key=lambda p: len(p.parts)) if found else None


def bounded_walk_up(start: PathLike, accept: Optional[Callable[[Path], bool]] = None) -> Optional[Path]:
    """The nearest directory holding ``.aegis/`` (or passing ``accept``) from ``start``
    upwards, or None.

    The walk includes ``start``, stops at its git boundary (``git_boundary``) and
    never reaches ``$HOME`` or the filesystem root, so a v3.3 ``~/.aegis/rules`` or a
    workspace that encloses the home directory is never chosen. Reads only.
    """
    accept = accept or is_aegis_workspace
    try:
        current = _resolved(start)
    except OSError:
        return None
    if current.is_file():
        current = current.parent
    if not current.is_dir() or denial(current):
        return None
    if accept(current):
        return current
    bound = git_boundary(current)
    while current != bound:
        parent = current.parent
        if parent == current or denial(parent):
            return None
        current = parent
        if accept(current):
            return current
    return None


# ── registry ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Registry:
    """The registered roots (absolute, resolved, in file order) and what was skipped."""

    roots: Tuple[Path, ...] = ()
    problems: Tuple[str, ...] = ()


def read_registry(path: Optional[PathLike] = None) -> Registry:
    """Read ``~/.aegis/workspaces.json`` (or ``path``). Never raises, never writes."""
    if path is None:
        layout = UserLayout.current()
        if layout is None:
            return Registry()
        path = layout.workspaces_file
    target = Path(os.fspath(path))
    try:
        if not target.is_file():
            return Registry()
        doc = json.loads(target.read_bytes().decode("utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return Registry(problems=(f"{target} is not valid JSON",))
    if not isinstance(doc, dict):
        return Registry(problems=(f"{target} must be a JSON object",))
    if doc.get("v") != REGISTRY_VERSION:
        return Registry(problems=(f"{target}: unsupported registry version {doc.get('v')!r}",))
    entries = doc.get("workspaces")
    if not isinstance(entries, list):
        return Registry(problems=(f"{target}: 'workspaces' must be a list",))
    roots: List[Path] = []
    problems: List[str] = []
    for index, entry in enumerate(entries):
        raw = entry.get("root") if isinstance(entry, dict) else None
        if not isinstance(raw, str) or not os.path.isabs(raw):
            problems.append(f"{target}: entry {index} has no absolute 'root'")
            continue
        try:
            root = _resolve(Path(raw))
        except OSError:
            problems.append(f"{target}: entry {index} root cannot be resolved")
            continue
        if root not in roots:
            roots.append(root)
    return Registry(tuple(roots), tuple(problems))


# ── selection by the call's files ────────────────────────────────────────────

def _usable(root: Path) -> bool:
    return root.is_dir() and is_aegis_workspace(root) and denial(root) is None


def _holds_file(root: Path, file: str) -> bool:
    """True if ``file`` (absolute, or relative to ``root``) lies inside ``root``.

    A relative path must name an existing entry, since any root "contains" a name that
    does not exist yet.
    """
    if os.path.isabs(file):
        try:
            _resolved(file).relative_to(root)
            return True
        except (ValueError, OSError):
            return False
    try:
        candidate = _resolve(root / file)
        candidate.relative_to(root)
    except (ValueError, OSError):
        return False
    return candidate != root and os.path.lexists(candidate)


def _holding(roots: Sequence[Path], files: Sequence[str]) -> List[Path]:
    return [r for r in roots if all(_holds_file(r, f) for f in files)]


def _innermost_chain(roots: Sequence[Path]) -> Optional[Path]:
    """The innermost root when ``roots`` nest in one chain (a governed subproject),
    else None (siblings are ambiguous)."""
    if not roots:
        return None
    ordered = sorted(roots, key=lambda r: len(r.parts))
    for outer, inner in zip(ordered, ordered[1:]):
        if outer != inner and outer not in inner.parents:
            return None
    return ordered[-1]


def _registered_owner(files: Sequence[str], registry: Registry, exclude: Optional[Path]) -> Optional[Path]:
    """A registered workspace other than ``exclude`` that holds an absolute call file
    lying outside ``exclude``: the evidence of a call aimed at another project."""
    for file in files:
        if not os.path.isabs(file):
            continue
        if exclude is not None and _holds_file(exclude, file):
            continue
        owner = _innermost_chain(_holding([r for r in registry.roots if _usable(r)], [file]))
        if owner is not None and owner != exclude:
            return owner
    return None


# ── resolution ───────────────────────────────────────────────────────────────

def home_message(home: Path) -> str:
    return (
        f"not an Aegis workspace ({home} is the home directory; ~/.aegis is the user rule layer); "
        "run aegis init in a project"
    )


def _pin_problem(pin: Path) -> Optional[Tuple[str, str]]:
    denied = denial(pin)
    if denied:
        return "pin_denied", f"AEGIS_WORKSPACE is set to {pin}, which is the {denied.replace('_', ' ')}"
    if not pin.is_dir():
        return "pin_missing", f"AEGIS_WORKSPACE is set to {pin}, which is not a directory"
    if not is_aegis_workspace(pin):
        return "pin_not_a_workspace", f"AEGIS_WORKSPACE is set to {pin}, which has no .aegis/ (run aegis init there)"
    return None


def resolve_binding(
    *,
    pin: Optional[PathLike] = None,
    attested: Iterable[Attested] = (),
    files: Optional[Sequence[str]] = None,
    cwd: Optional[PathLike] = None,
    registry: Optional[Registry] = None,
) -> WorkspaceBinding:
    """Resolve the workspace of one call (see the module docstring for the order)."""
    files = [f for f in (files or ()) if isinstance(f, str) and f]
    registry = registry or Registry()
    attested = list(attested)

    if pin is not None and os.fspath(pin):
        raw_pin = os.fspath(pin)
        try:
            pin_root = _resolved(raw_pin)
        except OSError:
            return _not_bound(ERROR, "pin_missing", f"AEGIS_WORKSPACE is set to {raw_pin}, which cannot be resolved", "pin")
        problem = _pin_problem(pin_root)
        if problem:
            return _not_bound(ERROR, problem[0], problem[1].replace(str(pin_root), raw_pin), "pin")
        if attested:
            host_roots = sorted({_shown(a.path) for a in attested})
            # A host root agrees when it lies in the pinned workspace (its walk-up finds
            # the pin) or encloses it (a broad root such as a parent folder).
            agrees = any(
                bounded_walk_up(root) == pin_root or Path(root) == pin_root or Path(root) in pin_root.parents
                for root in host_roots
            )
            if not agrees:
                return _not_bound(
                    HOLD, "pin_conflicts_with_host_root",
                    f"AEGIS_WORKSPACE pins {pin_root}, but the host reports the session in "
                    f"{', '.join(host_roots)}; fix the pin or open the pinned project",
                    pin=str(pin_root), host_roots=host_roots,
                )
        owner = _registered_owner(files, registry, pin_root)
        if owner is not None:
            return _not_bound(
                HOLD, "pin_conflicts_with_registry",
                f"AEGIS_WORKSPACE pins {pin_root}, but the files belong to the registered workspace {owner}",
                pin=str(pin_root), registered_root=str(owner),
            )
        return _bound(pin_root, "pin")

    if attested:
        candidates: List[Path] = []
        sources: Dict[Path, str] = {}
        for item in attested:
            root = bounded_walk_up(item.path)
            if root is not None and root not in sources:
                candidates.append(root)
                sources[root] = item.source
        if not candidates:
            owner = _registered_owner(files, registry, None)
            if owner is not None:
                return _not_bound(
                    HOLD, "host_root_conflicts_with_registry",
                    f"the host reports the session outside any Aegis workspace, but the files belong to "
                    f"the registered workspace {owner}",
                    host_roots=sorted({_shown(a.path) for a in attested}), registered_root=str(owner),
                )
            return _not_bound(UNBOUND, "host_roots_not_governed", "the host's workspace has no .aegis/")
        chosen = candidates[0] if len(candidates) == 1 else None
        if chosen is None:
            holding = _holding(candidates, files) if files else []
            chosen = _innermost_chain(holding)
            if not holding:
                # The files decide nothing: the most authoritative source present wins
                # when it names one root (Claude's project dir over its extra roots).
                top = [c for c in candidates if sources[c] == sources[candidates[0]]]
                chosen = top[0] if len(top) == 1 else None
        if chosen is None:
            return _not_bound(
                HOLD, "ambiguous_host_roots",
                "the host reports several Aegis workspaces and the call's files do not pick one; "
                "pass the files you plan to edit",
                candidates=[str(c) for c in candidates],
            )
        owner = _registered_owner(files, registry, chosen)
        if owner is not None:
            return _not_bound(
                HOLD, "host_root_conflicts_with_registry",
                f"the host reports the session in {chosen}, but the files belong to the registered workspace {owner}",
                host_root=str(chosen), registered_root=str(owner),
            )
        return _bound(chosen, sources[chosen])

    if files:
        usable = [r for r in registry.roots if _usable(r)]
        holding = _holding(usable, files)
        walked = None
        if holding and cwd is not None and not any(os.path.isabs(f) for f in files):
            # A relative name means "in the project the server runs in": the registry
            # chooses only when the cwd resolves to no workspace (README.md exists in
            # every repository; an unregistered clone must not govern a registered one).
            walked = bounded_walk_up(cwd)
        if walked is not None:
            if _holding([walked], files):
                return _bound(walked, "registry" if walked in holding else "walk_up")
            return _not_bound(
                HOLD, "cwd_conflicts_with_registry",
                f"the server runs in the workspace {walked}, but the files exist only in the registered "
                f"workspace(s) {', '.join(str(r) for r in holding)}; pass absolute paths",
                cwd_root=str(walked), candidates=[str(r) for r in holding],
            )
        if holding:
            chosen = _innermost_chain(holding)
            if chosen is None:
                return _not_bound(
                    HOLD, "ambiguous_registry_selection",
                    "the files exist in several registered workspaces; pass absolute paths",
                    candidates=[str(r) for r in holding],
                )
            return _bound(chosen, "registry")

    if cwd is not None:
        found = bounded_walk_up(cwd)
        if found is not None:
            return _bound(found, "walk_up")
    return _not_bound(UNBOUND, "no_workspace", "no Aegis workspace resolves for this call")


def _cli_path(path: PathLike, base: Optional[Path] = None, what: str = "") -> Path:
    try:
        return _resolved(path, base)
    except OSError as exc:
        raise WorkspaceNotFoundError(f"{what}{os.fspath(path)} cannot be resolved: {exc.__cause__ or exc}") from exc


def _pin_hold(explicit: PathLike, start: Path, pin_root: Path, accept: Optional[Callable[[Path], bool]]) -> None:
    target = bounded_walk_up(start, accept) or start
    if target != pin_root:
        raise WorkspaceHold(_not_bound(
            HOLD, "pin_conflicts_with_target",
            f"--workspace {os.fspath(explicit)} resolves to {target}, but AEGIS_WORKSPACE pins {pin_root}; "
            "unset the pin or drop --workspace",
            pin=str(pin_root), target=str(target),
        ))


def _pin_cwd_hold(cwd: Path, pin_root: Path, accept: Optional[Callable[[Path], bool]]) -> None:
    """Raise WorkspaceHold when the cwd lies in another workspace, or in a repository that
    does not hold the pinned one: run there (the git hook runs in the repository being
    committed), a command must not act on the pinned workspace instead."""
    found = bounded_walk_up(cwd, accept)
    if found is not None:
        conflict = found if found != pin_root else None
    else:
        boundary = git_boundary(cwd)
        if boundary is not None and denial(boundary):
            boundary = None  # $HOME (a dotfiles repository) is never a workspace to conflict with
        conflict = boundary if boundary is not None and boundary != pin_root and boundary not in pin_root.parents else None
    if conflict is not None:
        raise WorkspaceHold(_not_bound(
            HOLD, "pin_conflicts_with_cwd",
            f"AEGIS_WORKSPACE pins {pin_root}, but the current directory {cwd} is in {conflict}; "
            "unset the pin, or run aegis from the pinned project",
            pin=str(pin_root), cwd=str(cwd), cwd_root=str(conflict),
        ))


def check_pin_agrees(
    explicit: PathLike,
    pin: PathLike,
    cwd: Optional[PathLike] = None,
    accept: Optional[Callable[[Path], bool]] = None,
) -> None:
    """Raise WorkspaceHold when an ``AEGIS_WORKSPACE`` pin and an explicit ``--workspace``
    name different workspaces (the target's bounded walk-up result, else the target).

    For commands that choose their own root (``aegis init`` initializes the target as
    given) but must not act while the operator's pin says otherwise. Raises
    WorkspaceNotFoundError when either path cannot be resolved.
    """
    base = _cli_path(cwd) if cwd is not None else Path.cwd().resolve()
    start = _cli_path(explicit, base, "--workspace ")
    _pin_hold(explicit, start, _cli_path(pin, base, "AEGIS_WORKSPACE "), accept)


def resolve_cli_root(
    explicit: Optional[PathLike] = None,
    cwd: Optional[PathLike] = None,
    pin: Optional[PathLike] = None,
    accept: Optional[Callable[[Path], bool]] = None,
) -> Path:
    """The workspace root a CLI command acts on, under the same rules as the server.

    ``--workspace X`` (or the cwd) walks up no further than its git toplevel and never
    to ``$HOME`` or the filesystem root; an uninitialized directory resolves to itself
    so a command can say so. ``accept`` widens what the walk stops at (as in
    ``bounded_walk_up``; ``aegis migrate`` also stops at a legacy ``.soma/``). An
    ``AEGIS_WORKSPACE`` pin must be a workspace (``.aegis/``, or what ``accept`` takes,
    as the server's resolver requires) and must agree with an explicit target, or
    without one with the cwd: the cwd's walk-up result, else its repository, must be the
    pin (or hold it); otherwise this raises WorkspaceHold. From outside any workspace
    and repository the pin wins. Raises WorkspaceNotFoundError for a denied root, an
    unusable pin or a path that cannot be resolved.
    """
    base = _cli_path(cwd) if cwd is not None else Path.cwd().resolve()
    start = _cli_path(explicit, base, "--workspace ") if explicit else base
    if pin:
        raw_pin = os.fspath(pin)
        pin_root = _cli_path(raw_pin, base, "AEGIS_WORKSPACE ")
        problem = _pin_problem(pin_root)
        if problem and problem[0] == "pin_not_a_workspace" and accept is not None and accept(pin_root):
            problem = None  # accept may also raise, e.g. the upgrade message at a legacy .soma/
        if problem:
            raise WorkspaceNotFoundError(problem[1].replace(str(pin_root), raw_pin))
        if explicit:
            _pin_hold(explicit, start, pin_root, accept)
        else:
            _pin_cwd_hold(base, pin_root, accept)
        return pin_root
    found = bounded_walk_up(start, accept)
    if found is not None:
        return found
    message = denial_message(start)
    if message:
        raise WorkspaceNotFoundError(message)
    return start
