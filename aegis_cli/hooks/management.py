"""Git hook lifecycle management: install, uninstall, status inspection, and block generation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import sys
from typing import Any

from aegis_core import command_safety

_AEGIS_HOOK_START = "# >>> aegis pre-commit >>>"
_AEGIS_HOOK_END = "# <<< aegis pre-commit <<<"
_SOMA_HOOK_START = "# >>> soma pre-commit >>>"
_SOMA_HOOK_END = "# <<< soma pre-commit <<<"
AEGIS_HOOK_FORMAT = "# aegis-hook-format:"
SOMA_HOOK_FORMAT = "# soma-hook-format:"
# 6: the block runs first (right after the shebang) and no longer ends in exec.
CURRENT_HOOK_FORMAT_VERSION = 6
# The marked blocks install and uninstall manage: today's and the pre-v3 one.
_MARKERS = ((_AEGIS_HOOK_START, _AEGIS_HOOK_END), (_SOMA_HOOK_START, _SOMA_HOOK_END))

# The block is POSIX sh; a hook any of these runs can carry it.
_SHELLS = frozenset({"sh", "bash", "dash", "zsh"})


# The hook runs this code with the pinned interpreter. -I keeps the working
# tree (and PYTHON* variables) off sys.path, so a repository cannot substitute
# its own aegis_cli; AEGIS_PATH is the directory aegis_cli was installed in.
_HOOK_RUNNER = "import sys; sys.path.insert(0, sys.argv[1]); from aegis_cli.cli import main; sys.exit(main(sys.argv[2:]))"


def _default_import_root() -> str:
    import aegis_cli

    return str(Path(aegis_cli.__file__).resolve().parent.parent)


def _sh_path(path: str) -> str:
    return path.replace("\\", "/") if os.name == "nt" else path


def generate_hook_block(python: str | None = None, import_root: str | None = None) -> str:
    """The marked pre-commit block: run the aegis that installed it, or fail closed.

    One absolute interpreter (default: sys.executable of the installing aegis)
    and the directory aegis_cli was imported from are baked in at install
    time. Nothing is looked up on PATH, in $VIRTUAL_ENV or in the repository.
    A failed check ends the hook with its exit code; a passing one lets the
    hook's own lines after the block run (no exec).
    """
    python = python if python is not None else sys.executable
    import_root = import_root if import_root is not None else _default_import_root()
    # A relative path would resolve against the repository the hook runs in.
    if not os.path.isabs(python):
        raise ValueError(f"hook interpreter must be an absolute path, got {python!r}")
    if not os.path.isabs(import_root):
        raise ValueError(f"aegis import root must be an absolute path, got {import_root!r}")
    py = shlex.quote(_sh_path(python))
    root = shlex.quote(_sh_path(import_root))
    runner = shlex.quote(_HOOK_RUNNER)
    return (
        f"{_AEGIS_HOOK_START}\n"
        "# Installed by aegis hook install\n"
        f"{AEGIS_HOOK_FORMAT} {CURRENT_HOOK_FORMAT_VERSION}\n"
        f"AEGIS_PYTHON={py}\n"
        f"AEGIS_PATH={root}\n"
        'if [ -x "$AEGIS_PYTHON" ] && [ -f "$AEGIS_PATH/aegis_cli/__init__.py" ]; then\n'
        f'  "$AEGIS_PYTHON" -I -c {runner} "$AEGIS_PATH" check --hook || exit $?\n'
        "else\n"
        '  echo "aegis pre-commit: aegis not found at $AEGIS_PYTHON; run aegis hook install, or commit with --no-verify" >&2\n'
        "  exit 1\n"
        "fi\n"
        f"{_AEGIS_HOOK_END}\n"
    )


def _replace_hook_block(content: str, block: str) -> str | None:
    """content with its marked block swapped for block, or None if malformed."""
    for start_m, end_m in _MARKERS:
        start = content.find(start_m)
        if start >= 0:
            end = content.find(end_m, start)
            if end < 0:
                return None
            line_start = content.rfind("\n", 0, start) + 1
            end += len(end_m)
            if content.startswith("\r\n", end):
                end += 2
            elif content.startswith("\n", end):
                end += 1
            return content[:line_start] + block + content[end:]
    return None


def _hook_interpreter(text: str) -> str | None:
    """The program a hook's shebang names (``env``'s argument for ``#!/usr/bin/env X``),
    or None without a shebang (git then runs the file with sh)."""
    first = text.split("\n", 1)[0].rstrip("\r")
    if not first.startswith("#!"):
        return None
    words = first[2:].split()
    if not words:
        return None
    program = words[0].replace("\\", "/").rsplit("/", 1)[-1]
    if program == "env":
        rest = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
        program = rest[0].replace("\\", "/").rsplit("/", 1)[-1] if rest else program
    return program


def _without_hook_block(text: str) -> str | None:
    """``text`` with every marked aegis (or soma) block removed; None when one is unterminated."""
    for start_m, end_m in _MARKERS:
        while True:
            start = text.find(start_m)
            if start < 0:
                break
            end = text.find(end_m, start)
            if end < 0:
                return None
            line_start = text.rfind("\n", 0, start) + 1
            end += len(end_m)
            if text.startswith("\n", end):
                end += 1
            text = text[:line_start] + text[end:]
    return text


def _with_hook_block_first(text: str, block: str) -> str:
    """``text`` (holding no aegis block) with ``block`` right after its shebang, so the
    check runs before any of the hook's own lines, which may end it with exec or exit."""
    if not text.startswith("#!"):
        return "#!/bin/sh\n" + block + text
    shebang, _, rest = text.partition("\n")
    return shebang + "\n" + block + rest


def _back_up_hook(hook_file: Path, raw: bytes) -> Path | None:
    """Copy a hook's current bytes, owner-only, to ``~/.aegis/backups/<UTC stamp>/``; the
    copy's path, or None (after saying why) when no copy could be made."""
    from aegis_cli.install_hosts import InstallError, backup_dir
    from aegis_core.storage import atomic_write_bytes
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout.current()
    try:
        if layout is None:
            raise InstallError("no home directory resolves")
        folder = backup_dir(layout.home)
        missing = [p for p in (folder, *folder.parents) if not os.path.lexists(p)]
        for path in reversed(missing):
            path.mkdir(mode=0o700)
        copy = folder / hook_file.name
        atomic_write_bytes(copy, raw, mode=0o600)
        return copy
    except (InstallError, OSError) as exc:
        print(f"Error: cannot back up {hook_file} before editing it ({exc}); left unchanged", file=sys.stderr)
        return None


def install_hook(
    project_root: str | Path | Any | None = None,
    force: bool = False,
    python: str | None = None,
    dry_run: bool = False,
    import_root: str | None = None,
) -> bool:
    """Install or refresh the aegis pre-commit hook in a git repository.

    The block goes right after the hook's shebang (an existing block moves there), so a
    hook whose own lines end in exec or exit still runs the check first. A hook that is
    not a shell script (another interpreter, or not text) is refused unless ``force``,
    which replaces it. An existing file is copied to ``~/.aegis/backups/<stamp>/`` before
    it is changed, and is left unchanged when no copy can be made. A dry run makes the
    same checks and writes nothing. Returns False when nothing was (or would be) installed.
    """
    from aegis_core.workspace.base import Workspace
    from aegis_core.workspace.hooks import resolve_git_hooks_dir

    if isinstance(project_root, Workspace):
        ws = project_root
        root = ws.root
        git_hooks_dir = ws.git_hooks_dir
    else:
        root = Path(project_root or Path.cwd()).resolve()
        git_hooks_dir = resolve_git_hooks_dir(root)

    if not git_hooks_dir:
        return False

    block = generate_hook_block(python, import_root=import_root)
    hook_file = git_hooks_dir / "pre-commit"

    target_file = hook_file
    replace_link = False
    if hook_file.is_symlink():
        real_target = hook_file.resolve()
        if not real_target.exists():
            if not force:
                print(
                    f"Error: {hook_file} is a dangling symlink. Use --force to replace.",
                    file=sys.stderr,
                )
                return False
            replace_link = True
        else:
            is_contained = False
            for boundary in (root, git_hooks_dir):
                if boundary:
                    try:
                        real_target.relative_to(boundary.resolve())
                        is_contained = True
                        break
                    except ValueError:
                        pass
            if not is_contained and not force:
                print(
                    f"Error: {hook_file} is a symlink pointing outside repository ({real_target}). Use --force to overwrite.",
                    file=sys.stderr,
                )
                return False
            target_file = real_target

    raw = None if replace_link or not target_file.exists() else target_file.read_bytes()
    if raw is None:
        new_content = _with_hook_block_first("#!/bin/sh\n", block)
    else:
        try:
            content: str | None = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = None
        interpreter = "a program that is not a text file" if content is None else _hook_interpreter(content)
        if interpreter is not None and interpreter not in _SHELLS:
            if not force:
                print(
                    f"Error: {target_file} runs {interpreter}, not a shell, so the aegis block cannot go in it. "
                    "To replace it (a copy is kept in ~/.aegis/backups/), run: aegis hook install --force; "
                    "or call `aegis check --hook` from it yourself.",
                    file=sys.stderr,
                )
                return False
            new_content = _with_hook_block_first("#!/bin/sh\n", block)
        else:
            stripped = _without_hook_block((content or "").replace("\r\n", "\n"))
            if stripped is None:
                print(f"  ⚠️  {target_file} has an unterminated hook block; left unchanged", file=sys.stderr)
                return True
            new_content = _with_hook_block_first(stripped, block)

    if dry_run:
        return True
    payload = new_content.encode("utf-8")
    if raw is not None and payload != raw:
        copy = _back_up_hook(target_file, raw)
        if copy is None:
            return False
        print(f"Saved the previous pre-commit hook to {copy}", file=sys.stderr)
    if replace_link:
        hook_file.unlink()

    git_hooks_dir.mkdir(parents=True, exist_ok=True)
    tmp_file = target_file.parent / f".pre-commit.tmp.{os.getpid()}"
    try:
        tmp_file.write_bytes(payload)
        if os.name != "nt":
            tmp_file.chmod(0o755)
        tmp_file.replace(target_file)
    finally:
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass

    if os.name != "nt" and target_file.exists():
        try:
            target_file.chmod(target_file.stat().st_mode | 0o755)
        except OSError:
            pass

    return True


def uninstall_hook(
    project_root: str | Path | Any | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> bool:
    """Remove the aegis block from the pre-commit hook, keeping user hook lines."""
    from aegis_core.workspace.base import Workspace
    from aegis_core.workspace.hooks import resolve_git_hooks_dir

    if isinstance(project_root, Workspace):
        ws = project_root
        root = ws.root
        git_hooks_dir = ws.git_hooks_dir
    else:
        root = Path(project_root or Path.cwd()).resolve()
        git_hooks_dir = resolve_git_hooks_dir(root)

    if not git_hooks_dir:
        return False

    hook_file = git_hooks_dir / "pre-commit"
    if not hook_file.exists() and not hook_file.is_symlink():
        return False

    target_file = hook_file
    if hook_file.is_symlink():
        real_target = hook_file.resolve()
        if not real_target.exists():
            if force:
                if not dry_run:
                    hook_file.unlink()
                return True
            return False
        else:
            is_contained = False
            for boundary in (root, git_hooks_dir):
                if boundary:
                    try:
                        real_target.relative_to(boundary.resolve())
                        is_contained = True
                        break
                    except ValueError:
                        pass
            if not is_contained and not force:
                print(
                    f"Error: {hook_file} is a symlink pointing outside repository ({real_target}). Use --force to uninstall.",
                    file=sys.stderr,
                )
                return False
            target_file = real_target

    try:
        content = target_file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # Never a lossy errors="replace" rewrite: it would corrupt the user's own bytes.
        print(f"Error: {target_file} is not UTF-8 text; left unchanged", file=sys.stderr)
        return False
    if not any(start_m in content for start_m, _end_m in _MARKERS):
        return False

    if dry_run:
        return True

    start_m, end_m = next(pair for pair in _MARKERS if pair[0] in content)
    start = content.find(start_m)
    end = content.find(end_m, start)
    if end >= 0:
        line_start = content.rfind("\n", 0, start) + 1
        end += len(end_m)
        if content.startswith("\r\n", end):
            end += 2
        elif content.startswith("\n", end):
            end += 1
        remaining = content[:line_start] + content[end:]
    else:
        print(f"  ⚠️  {target_file} has an unterminated hook block; left unchanged", file=sys.stderr)
        return False

    stripped_lines = [line.strip() for line in remaining.splitlines() if line.strip()]
    is_empty_or_shebang_only = (
        not stripped_lines
        or (len(stripped_lines) == 1 and stripped_lines[0].startswith("#!"))
    )

    if is_empty_or_shebang_only:
        if hook_file.is_symlink():
            try:
                target_file.unlink()
            except OSError:
                pass
            try:
                hook_file.unlink()
            except OSError:
                pass
        else:
            hook_file.unlink()
        return True

    remaining = remaining.replace("\r\n", "\n")
    tmp_file = target_file.parent / f".pre-commit.tmp.{os.getpid()}"
    try:
        tmp_file.write_bytes(remaining.encode("utf-8"))
        if os.name != "nt":
            tmp_file.chmod(target_file.stat().st_mode)
        tmp_file.replace(target_file)
    finally:
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass
    return True


def _hooks_dir_in_work_tree(root: Path, git_hooks_dir: Path) -> bool:
    """True when core.hooksPath puts the hooks dir in the work tree, where it is
    normally tracked, so the machine-specific pinned paths would be committed."""
    hooks = git_hooks_dir.resolve()
    start = Path(root).resolve()
    for top in (start, *start.parents):
        dot_git = top / ".git"
        if dot_git.exists():
            if dot_git.is_dir() and hooks.is_relative_to(dot_git.resolve()):
                return False
            return hooks.is_relative_to(top)
    return False


def work_tree_warning(hook_file: str) -> str:
    return (f"Warning: {hook_file} is inside the work tree (core.hooksPath) and pins this "
            "machine's Python; do not commit it, or other clones fail closed until they run "
            "aegis hook install.")


def _pinned_value(text: str, var: str) -> str | None:
    match = re.search(rf"^{var}=(.+)$", text, re.MULTILINE)
    if not match:
        return None
    try:
        return shlex.split(match.group(1))[0]
    except (ValueError, IndexError):
        return match.group(1)


# A redirection word (`&` in `>&` and `&>` is first rewritten to `_`); when it is only
# the operator, the next word is its target.
_REDIRECTION = re.compile(r"[0-9_]*[<>]+_?")
_SEPARATOR = re.compile(r"(\$\(|&&|\|\||;;|[;&|()])")
_RUNS_ALWAYS_AFTER = frozenset({";", ";;", "&", "\n"})  # not `&&`, `||` or `|`
_BLOCKS = frozenset({"case", "for", "while", "until", "select", "{"})
_BLOCK_ENDS = frozenset({"esac", "done", "}"})


def _shell_lines(lines: list[str]) -> list[tuple[int, str, str]]:
    """(first line number, text, text without quoted strings or comments) per shell line:
    backslash continuations joined, here-document bodies left out."""
    found: list[tuple[int, str, str]] = []
    first_line_num = 0
    raw_parts: list[str] = []
    clean_parts: list[str] = []
    heredoc_delim: str | None = None
    for line_num, line in enumerate(lines, start=1):
        if heredoc_delim is not None:
            if line.strip() == heredoc_delim:
                heredoc_delim = None
            continue
        unquoted = re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", "''", line)
        uncommented = re.sub(r"(^|\s)#.*$", "", unquoted).rstrip()
        no_herestring = uncommented.replace("<<<", "")
        match = command_safety._HEREDOC.search(line) if "<<" in no_herestring else None
        heredoc_delim = match.group(4) if match else None
        if not clean_parts:
            first_line_num = line_num
        is_continued = uncommented.endswith("\\")
        stripped = line.strip()
        raw_parts.append(stripped[:-1].rstrip() if is_continued and stripped.endswith("\\") else stripped)
        clean_parts.append(uncommented[:-1] if is_continued else uncommented)
        if not is_continued:
            found.append((first_line_num, " ".join(raw_parts), " ".join(clean_parts)))
            raw_parts, clean_parts = [], []
    if clean_parts:
        found.append((first_line_num, " ".join(raw_parts), " ".join(clean_parts)))
    return found


def _execs_a_command(words: list[str]) -> bool:
    """Whether ``exec <words>`` replaces the shell (``exec >log 2>&1`` only redirects)."""
    target = False
    for word in words:
        if target:
            target = False
            continue
        match = _REDIRECTION.match(word)
        if match is None:
            return True
        target = match.end() == len(word)
    return False


class _Frame:
    """An open if/loop/group/subshell, and for an if, whether each branch so far ends the hook."""

    def __init__(self, kind: str, where: tuple[int, str], runs_always: bool = False) -> None:
        self.kind, self.where, self.runs_always = kind, where, runs_always
        self.condition = kind == "if"
        self.branch_ends = False
        self.every_branch_ends = True
        self.has_else = False


def _ends_hook_at(lines: list[str]) -> tuple[int, str] | None:
    """The first line (1-based, and its text) that ends the hook unconditionally: an
    ``exec`` of a command or an ``exit`` at the top level that nothing makes conditional
    (``&&``/``||``), runs elsewhere (a pipeline, ``&``, a subshell, ``$(...)``) or skips
    (a loop, case or function body), even after ``;`` on a line; or an if/elif/else
    every branch of which ends that way. A shell parse would be exact; this reads the
    lines hooks are made of, ignoring quoted text, comments and here-documents."""
    frames: list[_Frame] = []

    def ends(where: tuple[int, str]) -> tuple[int, str] | None:
        if not frames:
            return where
        if frames[-1].kind == "if" and not frames[-1].condition:
            frames[-1].branch_ends = True
        return None

    carried = "\n"  # a line ending in `&&`, `||` or `|` continues on the next one
    for number, raw, clean in _shell_lines(lines):
        if not clean.strip():
            continue
        where = (number, raw)
        parts = _SEPARATOR.split(re.sub(r"([<>])&", r"\1_", clean).replace("&>", "_>"))
        texts, ops = parts[0::2], [carried, *parts[1::2], "\n"]
        for index, text in enumerate(texts):
            before, after = ops[index], ops[index + 1]
            always = before in _RUNS_ALWAYS_AFTER and after not in ("|", "&")
            words = text.split()
            while words:
                word, top = words[0], (frames[-1] if frames else None)
                in_if = top is not None and top.kind == "if"
                if word == "if":
                    frames.append(_Frame("if", where, runs_always=before in _RUNS_ALWAYS_AFTER))
                elif word == "then" and in_if:
                    top.condition = False
                elif word in ("elif", "else") and in_if:
                    top.every_branch_ends = top.every_branch_ends and top.branch_ends
                    top.branch_ends, top.condition = False, word == "elif"
                    top.has_else = top.has_else or word == "else"
                elif word == "fi" and in_if:
                    frames.pop()
                    if top.has_else and top.every_branch_ends and top.branch_ends and top.runs_always and always:
                        found = ends(top.where)
                        if found:
                            return found
                elif word == "function":
                    words = words[2:]  # `function name`: the body that follows is a group
                    continue
                elif word in _BLOCKS:
                    frames.append(_Frame("block", where))
                elif word in _BLOCK_ENDS and top is not None and top.kind == "block":
                    frames.pop()
                elif word not in ("do", "!"):
                    break
                words = words[1:]
            if always and words and (words[0] == "exit" or (words[0] == "exec" and _execs_a_command(words[1:]))):
                found = ends(where)
                if found:
                    return found
            if after in ("$(", "("):
                frames.append(_Frame("sub", where))
            elif after == ")" and frames and frames[-1].kind == "sub":
                frames.pop()
        carried = ops[-2] if not texts[-1].strip() and ops[-2] in ("&&", "||", "|") else "\n"
    return None


def _unreachable_reason(hook_file: Path, text: str) -> str | None:
    """Why the aegis block in a hook never runs, and the fix; None when nothing stops it."""
    interpreter = _hook_interpreter(text)
    if interpreter is not None and interpreter not in _SHELLS:
        return (f"the hook runs {interpreter}, not a shell, so the aegis block never runs; "
                "replace it with: aegis hook install --force (a copy is kept)")
    if os.name != "nt" and not os.access(hook_file, os.X_OK):
        return "the hook file is not executable, so git skips it; run aegis hook install"
    start = min((i for i in (text.find(start_m) for start_m, _end_m in _MARKERS) if i >= 0), default=-1)
    lines = text[:start].splitlines()[1 if text.startswith("#!") else 0:] if start >= 0 else []
    ended = _ends_hook_at(lines)
    if ended is not None:
        number = ended[0] + (1 if text.startswith("#!") else 0)
        return (f"line {number} ({ended[1]}) ends the hook before the aegis block, so the check never runs; "
                "run aegis hook install to put the block first")
    return None


def hook_status(project_root: str | Path | Any | None = None) -> dict[str, Any]:
    """Inspect the aegis pre-commit hook in the target repository.

    ``reachable`` is True only when the hook holds the aegis block and nothing stops it
    from running (a non-shell interpreter, a file git cannot execute, an exec or exit
    before the block); ``unreachable_reason`` then says which, and is None otherwise."""
    from aegis_core.workspace.base import Workspace
    from aegis_core.workspace.hooks import resolve_git_hooks_dir

    if isinstance(project_root, Workspace):
        ws = project_root
        root = ws.root
        git_hooks_dir = ws.git_hooks_dir
    else:
        root = Path(project_root or Path.cwd()).resolve()
        git_hooks_dir = resolve_git_hooks_dir(root)

    is_git_repo = git_hooks_dir is not None
    hook_file = (git_hooks_dir / "pre-commit") if is_git_repo else None

    hook_exists = hook_file.is_file() if hook_file else False
    managed = False
    format_version = None
    status = "no_git_repository"

    if is_git_repo:
        if not hook_exists:
            status = "not_installed"
        else:
            try:
                text = hook_file.read_text(encoding="utf-8", errors="replace")
                if any(start_m in text for start_m, _end_m in _MARKERS):
                    managed = True
                    match = re.search(r"(?:aegis|soma)-hook-format:\s*(\d+)", text)
                    if match:
                        format_version = int(match.group(1))
                    else:
                        format_version = 1
                    if format_version == CURRENT_HOOK_FORMAT_VERSION:
                        status = "installed"
                    else:
                        status = "outdated"
                else:
                    status = "unmanaged"
            except OSError:
                status = "unreadable"

    interpreter = None
    aegis_path = None
    unreachable_reason = _unreachable_reason(hook_file, text) if managed else None
    if managed:
        pinned = _pinned_value(text, "AEGIS_PYTHON")
        if pinned is not None:
            interpreter = {"path": pinned, "exists": os.path.isfile(pinned) and os.access(pinned, os.X_OK)}
        # The same test the hook makes before it runs; either missing path fails every commit.
        pinned = _pinned_value(text, "AEGIS_PATH")
        if pinned is not None:
            aegis_path = {"path": pinned,
                          "exists": os.path.isfile(os.path.join(pinned, "aegis_cli", "__init__.py"))}

    is_worktree = False
    if root and (root / ".git").is_file():
        is_worktree = True

    return {
        "status": status,
        "is_git_repo": is_git_repo,
        "is_worktree": is_worktree,
        "repository_root": str(root),
        "git_hooks_dir": str(git_hooks_dir) if git_hooks_dir else None,
        "hook_file": str(hook_file) if hook_file else None,
        "managed_by_aegis": managed,
        "format_version": format_version,
        "current_format_version": CURRENT_HOOK_FORMAT_VERSION,
        "interpreter": interpreter,
        "aegis_path": aegis_path,
        "reachable": managed and unreachable_reason is None,
        "unreachable_reason": unreachable_reason,
        "hooks_dir_in_work_tree": bool(git_hooks_dir) and _hooks_dir_in_work_tree(root, git_hooks_dir),
    }


def _trailer_hook(status: dict[str, Any], action: str, *, dry_run: bool = False) -> str | None:
    """Install or remove the prepare-commit-msg hook that adds the Aegis-Check trailer, beside the pre-commit hook."""
    from aegis_cli.hooks import commitmsg

    hook_file = status.get("hook_file")
    if not hook_file:
        return None
    hooks_dir = Path(hook_file).parent
    try:
        return (
            commitmsg.install(hooks_dir, dry_run=dry_run)
            if action == "install"
            else commitmsg.uninstall(hooks_dir, dry_run=dry_run)
        )
    except (OSError, ValueError) as exc:
        print(f"aegis: prepare-commit-msg hook not {action}ed: {exc}", file=sys.stderr)
        return None


def run_hook_install(args: Any) -> int:
    ws = getattr(args, "ws", None) or getattr(args, "workspace", None)
    force = getattr(args, "force", False)
    dry_run = getattr(args, "dry_run", False)
    use_json = getattr(args, "json", False)

    ok = install_hook(ws, force=force, dry_run=dry_run)
    st = hook_status(ws) if ok else {}
    trailer = _trailer_hook(st, "install", dry_run=dry_run) if ok else None
    if use_json:
        print(json.dumps({"status": "installed" if ok else "failed", "success": ok}))
    else:
        if ok:
            print(f"✅ aegis pre-commit hook installed ({st.get('hook_file')})")
            if trailer == "foreign":
                print("ℹ️ A prepare-commit-msg hook that is not aegis's exists: left alone, so commits get no "
                      "Aegis-Check trailer", file=sys.stderr)
        else:
            print("❌ Failed to install the aegis pre-commit hook (see above, or no .git directory)", file=sys.stderr)
    if st.get("hooks_dir_in_work_tree"):
        print(work_tree_warning(st["hook_file"]), file=sys.stderr)
    return 0 if ok else 1


def run_hook_uninstall(args: Any) -> int:
    ws = getattr(args, "ws", None) or getattr(args, "workspace", None)
    force = getattr(args, "force", False)
    dry_run = getattr(args, "dry_run", False)
    use_json = getattr(args, "json", False)

    st = hook_status(ws)
    ok = uninstall_hook(ws, force=force, dry_run=dry_run)
    # The trailer hook can outlive its pre-commit hook, and commitmsg.uninstall removes only
    # a file that carries Aegis's markers, so it is removed whatever happened to pre-commit.
    trailer = _trailer_hook(st, "uninstall", dry_run=dry_run)
    if use_json:
        print(json.dumps({"status": "uninstalled" if ok else "not_found", "success": ok}))
    else:
        if ok:
            print("✅ aegis pre-commit hook removed")
        else:
            print("ℹ️ No aegis pre-commit hook found to uninstall")
            if trailer == "removed":
                print("prepare-commit-msg hook would be removed (dry run)" if dry_run
                      else "prepare-commit-msg hook removed")
    return 0 if ok else 1


def run_hook_status(args: Any) -> int:
    ws = getattr(args, "ws", None) or getattr(args, "workspace", None)
    use_json = getattr(args, "json", False)
    st = hook_status(ws)

    if st["hooks_dir_in_work_tree"]:
        print(work_tree_warning(st["hook_file"]), file=sys.stderr)
    if use_json:
        print(json.dumps(st, indent=2))
        return 0

    print("Aegis Git Hook Status")
    print(f"  Repository Root: {st['repository_root']}")
    if not st["is_git_repo"]:
        print("  Hooks Directory: ❌ No .git directory found")
        return 0

    print(f"  Hooks Directory: {st['git_hooks_dir']}")
    print(f"  Worktree:        {'Yes (linked worktree)' if st['is_worktree'] else 'No (main repository)'}")

    if st["status"] == "installed":
        print(f"  Pre-commit Hook: ✅ Installed & Current (format: {st['format_version']})")
    elif st["status"] == "outdated":
        print(f"  Pre-commit Hook: ⚠️  Outdated format ({st['format_version']} < {st['current_format_version']}) — run 'aegis hook install' to refresh")
    elif st["status"] == "unmanaged":
        print("  Pre-commit Hook: ⚠️  Existing pre-commit hook present (not managed by aegis)")
    else:
        print("  Pre-commit Hook: ❌ Not installed — run 'aegis hook install'")

    for label, pinned in (("Runs:", st.get("interpreter")), ("Aegis path:", st.get("aegis_path"))):
        if pinned:
            mark = "✅" if pinned["exists"] else "❌ (missing: run 'aegis hook install')"
            print(f"  {label:<17}{pinned['path']} {mark}")
    if st["unreachable_reason"]:
        print(f"  Reachable:       ❌ {st['unreachable_reason']}")
    return 0


def __getattr__(name: str) -> Any:
    if name in ("enable_insight_hook", "insight_hook_status"):
        from aegis_cli.hooks import insights

        return getattr(insights, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

