"""Insight keys and the user-scope log: the link key, session hashes, the workspace id, row I/O.

The leaf of the package: capture, review and recurrence import it, it imports none of them.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aegis_core import gitsafe, storage
from aegis_core.errors import PathTraversalError
from aegis_core.primitives import real_key
from aegis_core.storage import append_jsonl, read_jsonl, workspace_relative
from aegis_core.workspace.binding import bounded_walk_up
from aegis_core.workspace.layout import UserLayout

__all__ = [
    "KEY_SIZE",
    "SUPPORTED_INSIGHT_HOSTS",
    "create_link_key",
    "insight_workspace_id",
    "insights_path",
    "read_insight_rows",
    "read_link_key",
    "session_hs",
]

KEY_SIZE = 32
INSIGHT_SCHEMA_VERSION = 1
_HS_DOMAIN = b"aegis-hs/v1"
COUNTABLE_LEVELS = frozenset({"H", "cli", "W2"})
SUPPORTED_INSIGHT_HOSTS = ("claude-code", "codex-cli")
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _user_layout(home: Optional[Path] = None) -> Optional[UserLayout]:
    if home is not None:
        return UserLayout(Path(home))
    return UserLayout.current()


def _lstat_or_none(path: Path) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _ensure_private_dir(directory: Path) -> None:
    """``directory`` (made with its parents if missing) at 0o700. POSIX sets the mode through a
    descriptor opened without following a link, so a link swapped in is refused, never chmodded."""
    try:
        directory.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        pass
    invalid = PathTraversalError(f"refusing to use {directory}: invalid directory", path=str(directory))
    if os.name != "posix":  # no directory descriptor and no POSIX bits: the lstat check is the guard
        st = _lstat_or_none(directory)
        if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise invalid
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY | _O_FLAGS | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.path.islink(directory) or not os.path.isdir(directory):
            raise invalid from exc
        raise
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise invalid
        try:
            os.fchmod(fd, 0o700)
        except OSError:  # another user's directory: left as it is, as chmod by name did
            pass
    finally:
        os.close(fd)


def create_link_key(home: Optional[Path] = None) -> Tuple[Path, bool]:
    layout = _user_layout(home)
    if layout is None:
        raise OSError("cannot resolve home directory for link.key")
    _ensure_private_dir(layout.aegis_dir)
    key_path = layout.aegis_dir / "link.key"
    if storage.create_private_file(key_path, secrets.token_bytes(KEY_SIZE)):
        return key_path, True
    try:
        fd = os.open(str(key_path), os.O_RDONLY | _O_FLAGS | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        if os.path.islink(key_path):  # swapped in since create_private_file looked
            raise PathTraversalError(f"refusing to use {key_path}: it is a symlink", path=str(key_path)) from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PathTraversalError(f"refusing to use {key_path}: it is not a regular file", path=str(key_path))
        if st.st_size != KEY_SIZE:
            raise ValueError(f"corrupt {key_path}: expected {KEY_SIZE} bytes, found {st.st_size}")
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
    finally:
        os.close(fd)
    return key_path, False


def read_link_key(home: Optional[Path] = None) -> Optional[bytes]:
    layout = _user_layout(home)
    st = _lstat_or_none(layout.aegis_dir / "link.key") if layout else None
    if not layout or not st or stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return None
    try:
        fd = os.open(str(layout.aegis_dir / "link.key"), os.O_RDONLY | _O_FLAGS)
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(KEY_SIZE + 1) if stat.S_ISREG(os.fstat(fd).st_mode) else b""
    except OSError:
        return None
    return data if len(data) == KEY_SIZE else None


def session_hs(host: str, value: str, link_key: Optional[bytes] = None, *, home: Optional[Path] = None) -> Optional[str]:
    if not isinstance(host, str) or not host.strip() or not isinstance(value, str):
        return None
    clean = value.strip()
    if not (1 <= len(clean) <= 128) or not all(0x20 <= ord(ch) <= 0x7E for ch in clean):
        return None
    key = link_key if link_key is not None else read_link_key(home)
    if key is None or len(key) != KEY_SIZE:
        return None
    payload = _HS_DOMAIN + b"\x00" + host.encode("utf-8") + b"\x00" + clean.encode("ascii")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()[:32]


def _ensure_hs(host: str, session: Optional[str], home: Optional[Path] = None) -> Optional[str]:
    if not isinstance(session, str) or not session.strip():
        return None
    key = read_link_key(home)
    if key is None:
        try:
            create_link_key(home)
            key = read_link_key(home)
        except (OSError, ValueError, PathTraversalError):
            return None
    return session_hs(host, session, key, home=home)


def _fast_git_common_and_top(root: Path) -> Optional[Tuple[Path, Path]]:
    cur = Path(os.path.realpath(root))
    for cand in (cur, *cur.parents):
        dot_git = cand / ".git"
        st = _lstat_or_none(dot_git)
        if not st:
            continue
        if stat.S_ISDIR(st.st_mode):
            return dot_git, cand
        if stat.S_ISREG(st.st_mode):
            try:
                raw = dot_git.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                break
            if raw.startswith("gitdir:"):
                g_raw = raw[7:].strip()
                gitdir = (cand / g_raw).resolve() if not os.path.isabs(g_raw) else Path(g_raw).resolve()
                cfile = gitdir / "commondir"
                if cfile.is_file():
                    try:
                        common_rel = cfile.read_text(encoding="utf-8", errors="replace").strip()
                        return (gitdir / common_rel).resolve(), cand
                    except OSError:
                        pass
                return gitdir, cand
    return None


def insight_workspace_id(workspace: Any) -> str:
    # Keyed to the governed root (the nearest .aegis inside the git boundary), so a hook
    # running in a subdirectory and `review` at the root share one file.
    root = Path(os.fspath(workspace)).resolve()
    root = bounded_walk_up(root) or root
    fast = _fast_git_common_and_top(root)
    if fast is not None:
        common, top = fast
        norm_root, norm_top = real_key(root), real_key(top)
        try:
            rel = os.path.relpath(norm_root, norm_top).replace(os.sep, "/") if norm_root and norm_top else "."
        except ValueError:
            rel = "."
        canon = f"{Path(os.path.realpath(common)).as_posix()}\x00{rel}"
    else:
        c_fb = gitsafe.common_dir(root)
        r_fb = workspace_relative(root) if c_fb is not None else None
        if c_fb and r_fb:
            canon = f"{Path(os.path.realpath(c_fb)).as_posix()}\x00{r_fb}"
        else:
            canon = Path(os.path.realpath(root)).as_posix()
    return hashlib.sha256(canon.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def insights_path(workspace: Any, home: Optional[Path] = None) -> Path:
    layout = _user_layout(home)
    if layout is None:
        raise OSError("cannot resolve user home directory for insights storage")
    return layout.aegis_dir / "insights" / f"{insight_workspace_id(workspace)}.jsonl"


def _append_user_insights(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    if not rows:
        return
    _ensure_private_dir(path.parent.parent)
    _ensure_private_dir(path.parent)
    with storage.file_lock(path.with_suffix(".lock")):
        append_jsonl(path, list(rows), mode=0o600)  # the mode is set through the descriptor


def read_insight_rows(workspace: Any, home: Optional[Path] = None) -> List[Dict[str, Any]]:
    try:
        return list(read_jsonl(insights_path(workspace, home=home)).rows)
    except OSError:
        return []
