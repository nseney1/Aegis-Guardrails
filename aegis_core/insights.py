"""Human insights closed loop (v4.3 spec §3.5 T8, v4.4 spec §3.4 & §12.2).

The per-prompt hook path (record_hook_prompt) imports only the standard library and the
L0 transports at module load: credit, human_gate, the ledger, scan_compliance, the rule
parser and the redaction scanners are imported where review or capture uses them, so a
prompt that writes nothing pays for none of them. Their public re-exports stay reachable
through the module ``__getattr__``.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePath
import re
import secrets
import stat
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple

from aegis_core import gitsafe, storage
from aegis_core.errors import PathTraversalError
from aegis_core.storage import (
    append_jsonl,
    atomic_write_text,
    fsync_dir,
    read_jsonl,
    workspace_relative,
)
from aegis_core.workspace.binding import bounded_walk_up
from aegis_core.workspace.layout import AEGIS_DIRNAME, UserLayout, WorkspaceLayout

if TYPE_CHECKING:
    from aegis_core.rules import Rule

__all__ = [
    "BURST_WINDOW_SECONDS",
    "DECISIONS",
    "INSIGHT_HOOK_MARKER",
    "INSIGHT_LEVELS",
    "INSIGHT_SCHEMA_VERSION",
    "KEY_SIZE",
    "MAX_EXCERPT_CHARS",
    "RECURRENCE_ALARM_COUNT",
    "REJECTION_RESURFACE_COUNT",
    "SUPPORTED_INSIGHT_HOSTS",
    "add_insight",
    "capture_suggestion",
    "create_link_key",
    "dirty_paths",
    "has_correction_cue",
    "host_capture_status",
    "insight_workspace_id",
    "insights_path",
    "measure_recurrence",
    "merge_insight_hook",
    "read_insight_rows",
    "read_link_key",
    "record_decision",
    "record_hook_prompt",
    "redact_insight_text",
    "remove_insight_hook",
    "review_insights",
    "session_hs",
    "tfidf_cosine",
    "write_proposal",
]

KEY_SIZE = 32
INSIGHT_SCHEMA_VERSION = 1
REJECTION_RESURFACE_COUNT = 2
RECURRENCE_ALARM_COUNT = 3
BURST_WINDOW_SECONDS = 300
_HS_DOMAIN = b"aegis-hs/v1"
_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INSIGHT_LEVELS = ("H", "cli", "W2", "hook", "suggestion")
COUNTABLE_LEVELS = frozenset({"H", "cli", "W2", "hook"})
DECISIONS = ("propose", "reject", "snooze", "merge-into-rule", "noise")
SUPPORTED_INSIGHT_HOSTS = ("claude-code", "codex-cli")
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_LAZY_NAMES = {
    "MAX_EXCERPT_CHARS": "aegis_core.verification.scanners",
    "redact_insight_text": "aegis_core.verification.scanners",
    "Rule": "aegis_core.rules",
    "load_rules": "aegis_core.rules",
    "first_match": "aegis_core.match",
    "activity_path": "aegis_core.scan_compliance",
}


def __getattr__(name: str) -> Any:
    source = _LAZY_NAMES.get(name)
    if source is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(source), name)


def __dir__() -> List[str]:
    return sorted(set(globals()) | set(_LAZY_NAMES))


def _redact(text: str, **kwargs: Any) -> str:
    from aegis_core.verification.scanners import redact_insight_text

    return redact_insight_text(text, **kwargs)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FORMAT)


def _user_layout(home: Optional[Path] = None) -> Optional[UserLayout]:
    if home is not None:
        return UserLayout(Path(home))
    return UserLayout.current()


def _parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _lstat_or_none(path: Path) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _chmod_quiet(path: Path, mode: int) -> None:
    if os.name == "posix":
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def _ensure_private_dir(directory: Path) -> None:
    st = _lstat_or_none(directory)
    if st is not None:
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise PathTraversalError(f"refusing to use {directory}: invalid directory", path=str(directory))
    else:
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    _chmod_quiet(directory, 0o700)


def create_link_key(home: Optional[Path] = None) -> Tuple[Path, bool]:
    layout = _user_layout(home)
    if layout is None:
        raise OSError("cannot resolve home directory for link.key")
    _ensure_private_dir(layout.aegis_dir)
    key_path = layout.aegis_dir / "link.key"
    st = _lstat_or_none(key_path)
    if st is not None and stat.S_ISLNK(st.st_mode):
        raise PathTraversalError(f"refusing to use {key_path}: it is a symlink", path=str(key_path))
    try:
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_FLAGS, 0o600)
    except FileExistsError:
        st = os.lstat(key_path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise PathTraversalError(f"refusing to use {key_path}: it is not a regular file", path=str(key_path))
        if st.st_size != KEY_SIZE:
            raise ValueError(f"corrupt {key_path}: expected {KEY_SIZE} bytes, found {st.st_size}")
        _chmod_quiet(key_path, 0o600)
        return key_path, False
    try:
        view = memoryview(secrets.token_bytes(KEY_SIZE))
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(key_path)
        except OSError:
            pass
        raise
    os.close(fd)
    _chmod_quiet(key_path, 0o600)
    fsync_dir(layout.aegis_dir)
    return key_path, True


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
        try:
            norm_root = os.path.normcase(os.path.realpath(root))
            norm_top = os.path.normcase(os.path.realpath(top))
            rel = os.path.relpath(norm_root, norm_top).replace(os.sep, "/")
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
        to_write = list(rows)
        if path.exists():
            existing_hb = {
                (r.get("host"), r.get("hs"))
                for r in read_jsonl(path).rows
                if r.get("event") == "heartbeat" and r.get("hs") is not None
            }
            to_write = [
                r for r in to_write
                if not (
                    r.get("event") == "heartbeat"
                    and r.get("hs") is not None
                    and (r.get("host"), r.get("hs")) in existing_hb
                )
            ]
        if to_write:
            append_jsonl(path, to_write, mode=0o600)
            _chmod_quiet(path, 0o600)


def read_insight_rows(workspace: Any, home: Optional[Path] = None) -> List[Dict[str, Any]]:
    try:
        return list(read_jsonl(insights_path(workspace, home=home)).rows)
    except OSError:
        return []


_CUE_RE = re.compile(
    r"\b(?:don'?t|do not|never|stop|no more|not acceptable|shouldn'?t|should not|must not|mustn'?t|"
    r"again|already|i (?:said|told|asked|wanted)|last time|as i said|keep (?:doing|using|adding)|"
    r"wrong|incorrect|broke|broken|breaks|mistake|not what i|instead|rather than|"
    r"why (?:is|are|did|do) (?:there|you|this|we)|revert|undo)\b|^\s*(?:no|nope|nah)\b",
    re.I,
)


def has_correction_cue(text: str) -> bool:
    return bool(isinstance(text, str) and text.strip() and _CUE_RE.search(text))


def dirty_paths(workspace: Any) -> List[str]:
    root = Path(os.fspath(workspace)).resolve()
    top = gitsafe.toplevel(root)
    changed = gitsafe.changed_files(top, "working", untracked=True) if top is not None else None
    found: Set[str] = set()
    for rel_top in changed or ():
        try:
            rel = (top / rel_top).resolve().relative_to(root).as_posix()
        except ValueError:
            continue
        if not rel.startswith(f"{AEGIS_DIRNAME}/state/"):
            found.add(rel)
    return sorted(found)


def _served_rule_revs(workspace: Any) -> Dict[str, str]:
    root = Path(os.fspath(workspace)).resolve()
    if not (root / AEGIS_DIRNAME / "rules").is_dir():
        return {}
    try:
        from aegis_core.rules import load_rules

        return {r.id: r.digest[:16] for r in load_rules(root).served}
    except Exception:
        return {}


def _has_human_approval(workspace: Any, commit: Optional[str], base_ref: Optional[str], text: str = "") -> bool:
    if workspace is None or not commit or not text:
        return False
    top = gitsafe.toplevel(Path(os.fspath(workspace)).resolve())
    if top is None:
        return False
    try:
        from aegis_core import human_gate

        base = base_ref or gitsafe.resolve_base_ref(top)
        return bool(base and human_gate.verify_insight_approval(top, commit, text, base).ok)
    except Exception:
        return False


def _confine_paths(root: Any, paths: Sequence[str]) -> List[str]:
    """Workspace-relative POSIX paths; PathTraversalError for one that resolves outside."""
    from aegis_core.workspace.confinement import confine_path_internal

    base = Path(os.fspath(root))
    return sorted({PurePath(confine_path_internal(base, str(p))[1]).as_posix() for p in paths if str(p).strip()})


def _resolve_paths(workspace: Any, paths: Optional[Sequence[str]]) -> Tuple[List[str], str]:
    if paths is not None and len(paths) > 0:
        return _confine_paths(workspace, paths), "explicit"
    return dirty_paths(workspace), "dirty"


def _matching_hook_insight(rows: Sequence[Mapping[str, Any]], hs: Optional[str], redacted_quote: str) -> Optional[str]:
    if not hs or not redacted_quote or len(redacted_quote.strip()) < 4:
        return None
    needle = redacted_quote.strip().lower()
    for r in rows:
        if (
            r.get("event") == "insight"
            and r.get("level") in ("W2", "hook")
            and r.get("hs") == hs
            and isinstance(r.get("text"), str)
            and needle in r["text"].lower()
        ):
            return str(r.get("id") or "")
    return None


def _build_insight_row(
    workspace: Any,
    level: str,
    text: str,
    paths: List[str],
    psrc: str,
    host: str,
    hs: Optional[str],
    now: Optional[str] = None,
    *,
    revs: Optional[Dict[str, str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "v": INSIGHT_SCHEMA_VERSION,
        "ts": now or _utc_now(),
        "event": "insight",
        "id": f"ins-{secrets.token_hex(6)}",
        "level": level,
        "text": text,
        "paths": paths,
        "psrc": psrc,
        "host": host,
    }
    if hs:
        row["hs"] = hs
    for k, v in extra.items():
        if v:
            row[k] = v
    revs = _served_rule_revs(workspace) if revs is None else revs
    if revs:
        row["revs"] = revs
    return row


def add_insight(
    workspace: Any,
    text: str,
    *,
    paths: Optional[Sequence[str]] = None,
    kind: Optional[str] = None,
    commit: Optional[str] = None,
    base_ref: Optional[str] = None,
    home: Optional[Path] = None,
) -> Dict[str, Any]:
    # No session identity: it comes from the host (record_hook_prompt, capture_suggestion),
    # never from a typed argument, so CLI rows cannot forge distinct recurrence episodes.
    if not isinstance(text, str) or not text.strip():
        raise ValueError("insight text must be a non-empty string")
    clean = _redact(text)
    norm_paths, psrc = _resolve_paths(workspace, paths)
    level = "H" if _has_human_approval(workspace, commit, base_ref, clean) else "cli"
    row = _build_insight_row(
        workspace, level, clean, norm_paths, psrc, "cli", None, kind=str(kind) if kind else None,
    )
    _append_user_insights(insights_path(workspace, home=home), [row])
    return row


def capture_suggestion(
    workspace: Any,
    quote: str,
    paths: Optional[Sequence[str]] = None,
    *,
    host: str = "mcp",
    session: Optional[str] = None,
    home: Optional[Path] = None,
) -> Dict[str, Any]:
    if not isinstance(quote, str) or not quote.strip():
        raise ValueError("quote must be a non-empty string")
    redacted = _redact(quote)
    norm_paths, psrc = _resolve_paths(workspace, paths)
    hs = _ensure_hs(host, session, home)
    m_hook = _matching_hook_insight(read_insight_rows(workspace, home=home), hs, redacted)
    row = _build_insight_row(
        workspace,
        "W2" if m_hook else "suggestion",
        redacted,
        norm_paths,
        psrc,
        host or "mcp",
        hs,
        confirmed_by=m_hook,
    )
    _append_user_insights(insights_path(workspace, home=home), [row])
    return row


def _first_str(mapping: Mapping[str, Any], keys: Sequence[str], strip: bool = True) -> Optional[str]:
    for k in keys:
        v = mapping.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip() if strip else v
    return None


def _extract_hook_fields(payload: Any) -> Tuple[str, Optional[str], Optional[str]]:
    if isinstance(payload, str):
        s = payload.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, Mapping):
                    payload = parsed
            except ValueError:
                pass
    if isinstance(payload, str):
        return payload, None, None
    if not isinstance(payload, Mapping):
        return "", None, None
    prompt = _first_str(payload, ("prompt", "user_prompt", "text", "message", "input"), strip=False) or ""
    sess = _first_str(payload, ("session_id", "sessionId", "conversation_id", "conversationId", "session"))
    cwd = _first_str(payload, ("cwd", "workspace", "working_directory", "project_dir"))
    return prompt, sess, cwd


def record_hook_prompt(
    workspace_or_host: Any,
    host_or_payload: Any,
    payload: Any = None,
    *,
    workspace: Any = None,
    excerpts: bool = True,
    session: Optional[str] = None,
    home: Optional[Path] = None,
) -> Dict[str, Any]:
    if payload is None:
        host, actual_payload, actual_ws = str(workspace_or_host), host_or_payload, workspace
    else:
        host, actual_payload, actual_ws = str(host_or_payload), payload, workspace_or_host
    prompt_text, payload_session, payload_cwd = _extract_hook_fields(actual_payload)
    if actual_ws is None:
        from aegis_core.config import env_workspace
        project = os.environ.get("CLAUDE_PROJECT_DIR", "") if host == "claude-code" else ""
        actual_ws = (project if os.path.isabs(project) else None) or payload_cwd or env_workspace() or os.getcwd()
    hs = _ensure_hs(host, session or payload_session, home=home)
    path = insights_path(actual_ws, home=home)
    existing = read_insight_rows(actual_ws, home=home)
    now = _utc_now()
    to_write: List[Dict[str, Any]] = []
    has_hb = any(
        r.get("event") == "heartbeat" and r.get("host") == host and hs is not None and r.get("hs") == hs
        for r in existing
    )
    cue = has_correction_cue(prompt_text)
    excerpt = _redact(prompt_text) if cue and excerpts else ""
    revs = _served_rule_revs(actual_ws) if excerpt or not has_hb else {}
    if not has_hb:
        hb: Dict[str, Any] = {"v": INSIGHT_SCHEMA_VERSION, "ts": now, "event": "heartbeat", "host": host}
        if hs:
            hb["hs"] = hs
        if revs:
            hb["revs"] = revs
        to_write.append(hb)
    insight_row: Optional[Dict[str, Any]] = None
    if excerpt:
        insight_row = _build_insight_row(
            actual_ws, "W2", excerpt, dirty_paths(actual_ws), "dirty", host, hs, now=now, revs=revs,
        )
        to_write.append(insight_row)
    if to_write:
        _append_user_insights(path, to_write)
    if insight_row is not None:
        return insight_row
    return {
        "v": INSIGHT_SCHEMA_VERSION,
        "ts": now,
        "event": "heartbeat",
        "host": host,
        "hs": hs,
        "cue": cue,
        "recorded": False,
    }


_STOPWORDS = frozenset(
    "a an the and or but if then else to of in on at for with by from up about into over after "
    "is are was were be been being have has had do does did don t not no never stop don't shouldn't "
    "mustn't should must can could would will just please you your i me my we our it its this that "
    "these those there here what which who why how when where again already said told asked wanted "
    "last time as keep doing using adding wrong incorrect broke broken breaks mistake instead rather "
    "than nope nah revert undo use always avoid make sure only any all every some rule trap prevent "
    "recurring defect modules module file files".split()
)
_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _stem(word: str) -> str:
    for suf in ("ing", "ed", "es", "s", "ly"):
        if word.endswith(suf) and len(word) > len(suf) + 2:
            return word[: -len(suf)]
    return word


def _tokenize(text: str) -> List[str]:
    if not isinstance(text, str):
        return []
    tokens: List[str] = []
    for raw in _TOKEN_RE.findall(text.lower()):
        for part in raw.split("_"):
            if len(part) > 1 and part not in _STOPWORDS:
                st = _stem(part)
                if len(st) > 1 and st not in _STOPWORDS:
                    tokens.append(st)
    return tokens


def _tfidf_vectors(docs: Sequence[Sequence[str]]) -> List[Dict[str, float]]:
    n = len(docs)
    if not n:
        return []
    df: Counter[str] = Counter(t for doc in docs for t in set(doc))
    vecs: List[Dict[str, float]] = []
    for doc in docs:
        vec = {
            t: (1.0 + math.log(c)) * (math.log((n + 1.0) / (df[t] + 1.0)) + 1.0)
            for t, c in Counter(doc).items()
        }
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        vecs.append({k: v / norm for k, v in vec.items()})
    return vecs


def _cosine(a: Mapping[str, float], b: Mapping[str, float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    return sum(v * b.get(k, 0.0) for k, v in a.items())


def tfidf_cosine(text_a: str, text_b: str) -> float:
    ta, tb = _tokenize(text_a), _tokenize(text_b)
    if not ta or not tb:
        return 0.0
    return _cosine(*_tfidf_vectors([ta, tb]))


def _load_md_rules(workspace: Any, folder: Path, *, recursive: bool = False) -> List[Rule]:
    if not folder.is_dir():
        return []
    from aegis_core.rules import Rule
    from aegis_core.yaml_engine.frontmatter import split_frontmatter
    from aegis_core.yaml_engine.parser import AegisYAMLError, parse_yaml_subset

    root_path = Path(os.fspath(workspace)).resolve()
    items: List[Rule] = []
    for md in sorted(folder.rglob("*.md") if recursive else folder.glob("*.md")):
        if not md.is_file() or md.is_symlink():
            continue
        try:
            raw = md.read_bytes()
            _, fm, body = split_frontmatter(raw.decode("utf-8"))
            meta = parse_yaml_subset(fm) if fm else {}
            if not isinstance(meta, dict):
                meta = {}
        except (OSError, UnicodeDecodeError, AegisYAMLError):
            continue
        items.append(
            Rule(
                id=str(meta.get("id") or md.stem),
                path=md.relative_to(root_path).as_posix(),
                type=str(meta.get("type") or "trap"),
                meta=meta,
                body=body,
                digest=hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(),
            )
        )
    return items


def _rule_was_exposed(
    workspace: Any,
    rule: Rule,
    cluster_rows: Sequence[Mapping[str, Any]],
    home: Optional[Path] = None,
) -> bool:
    from aegis_core import credit
    from aegis_core.scan_compliance import activity_path
    from aegis_core.telemetry_engine import ledger

    root = Path(os.fspath(workspace)).resolve()
    link_key = read_link_key(home)
    scan_hs: Set[Tuple[str, str]] = set()
    exposed_hs: Set[Tuple[str, str]] = set()
    for a in read_jsonl(activity_path(root)).rows:
        sh, ss = str(a.get("host") or ""), str(a.get("session") or "")
        if a.get("event") == "scan" and ss:
            shs = session_hs(sh, ss, link_key, home=home)
            if shs:
                scan_hs.add((sh, shs))
                if rule.id in credit.exposed_rules(root, sh, ss):
                    exposed_hs.add((sh, shs))
    for erow in credit.read_rows(root):
        eh, es = str(erow.get("host") or ""), str(erow.get("session") or "")
        rev = erow.get("rev")
        rev_mismatch = isinstance(rev, str) and bool(rev) and not rule.digest.startswith(rev)
        if erow.get("event") == "exposure" and (erow.get("rule") or erow.get("for_rule")) == rule.id and not rev_mismatch and es:
            ehs = session_hs(eh, es, link_key, home=home)
            if ehs:
                exposed_hs.add((eh, ehs))
    for lrow in ledger.read(root).rows:
        meta = lrow.get("meta") if isinstance(lrow.get("meta"), Mapping) else {}
        rev = meta.get("rev")
        if lrow.get("rule") != rule.id or (isinstance(rev, str) and rev and not rule.digest.startswith(rev)):
            continue
        lh, ls = str(lrow.get("host") or ""), str(lrow.get("session") or "")
        lhs = session_hs(lh, ls, link_key, home=home) if ls else None
        if lhs and (
            rule.id in credit.exposed_rules(root, lh, ls)
            or (lh, lhs) in scan_hs
            or lrow.get("outcome") in ("trigger", "tp", "fp")
        ):
            exposed_hs.add((lh, lhs))
    return any((str(ins.get("host") or ""), str(ins.get("hs") or "")) in exposed_hs for ins in cluster_rows)


def _paths_overlap_rule(paths: Iterable[str], rule: Rule) -> bool:
    from aegis_core.match import first_match

    plist = [p for p in paths if p]
    if not plist or not rule.target_paths:
        return True
    return any(rule.applies_to(p) or first_match(rule.target_paths, p) is not None for p in plist)


class _RuleMatch(NamedTuple):
    kind: str
    rule: Rule
    similarity: float


def _cluster_signature_id(tokens: Sequence[str], matched_id: Optional[str]) -> str:
    top = [t for t, _ in Counter(tokens).most_common(4)]
    sig = hashlib.sha256(("-".join(sorted(top)) if top else "misc").encode("utf-8")).hexdigest()[:8]
    return f"cluster-{matched_id}-{sig}" if matched_id else f"cluster-{sig}"


def record_decision(
    workspace: Any,
    *,
    cluster_id: str,
    decision: str,
    insight_ids: Sequence[str],
    reason: Optional[str] = None,
    rule_id: Optional[str] = None,
    home: Optional[Path] = None,
) -> Dict[str, Any]:
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {list(DECISIONS)}, got {decision!r}")
    if not isinstance(cluster_id, str) or not cluster_id.strip():
        raise ValueError("cluster_id must be a non-empty string")
    row: Dict[str, Any] = {
        "v": INSIGHT_SCHEMA_VERSION,
        "ts": _utc_now(),
        "event": "decision",
        "cluster_id": cluster_id.strip(),
        "decision": decision,
        "insight_ids": [str(i) for i in insight_ids if str(i).strip()],
    }
    if reason:
        row["reason"] = _redact(str(reason))
    if rule_id:
        row["rule_id"] = str(rule_id)
    _append_user_insights(insights_path(workspace, home=home), [row])
    return row


def _match_insights_to_rules(
    countable: Sequence[Tuple[int, Dict[str, Any]]],
    ins_vecs: Sequence[Mapping[str, float]],
    rule_entries: Sequence[Tuple[str, Rule, List[str]]],
    rule_vecs: Sequence[Mapping[str, float]],
) -> List[Optional[_RuleMatch]]:
    matches: List[Optional[_RuleMatch]] = []
    for i, (_, row) in enumerate(countable):
        paths_i = set(row.get("paths") or [])
        best: Optional[_RuleMatch] = None
        for r_idx, (kind, robj, _) in enumerate(rule_entries):
            sim = _cosine(ins_vecs[i], rule_vecs[r_idx])
            if ((_paths_overlap_rule(paths_i, robj) and sim >= 0.15) or sim >= 0.30) and (best is None or sim > best.similarity):
                best = _RuleMatch(kind=kind, rule=robj, similarity=sim)
        matches.append(best)
    return matches


def _should_merge_insights(
    paths_i: Set[str],
    paths_j: Set[str],
    rid_i: Optional[str],
    rid_j: Optional[str],
    sim: float,
) -> bool:
    if rid_i != rid_j:
        return False
    path_overlap = bool(not paths_i or not paths_j or (paths_i & paths_j))
    return (path_overlap and sim >= 0.22) or sim >= 0.35


def _cluster_countable_insights(
    countable: Sequence[Tuple[int, Dict[str, Any]]],
    ins_vecs: Sequence[Mapping[str, float]],
    ins_best_rule: Sequence[Optional[_RuleMatch]],
) -> List[List[int]]:
    n_ins = len(countable)
    parent = list(range(n_ins))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(n_ins):
        paths_i = set(countable[i][1].get("paths") or [])
        rid_i = ins_best_rule[i].rule.id if ins_best_rule[i] else None
        for j in range(i + 1, n_ins):
            rid_j = ins_best_rule[j].rule.id if ins_best_rule[j] else None
            sim = _cosine(ins_vecs[i], ins_vecs[j])
            paths_j = set(countable[j][1].get("paths") or [])
            if _should_merge_insights(paths_i, paths_j, rid_i, rid_j, sim):
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)
    groups: Dict[int, List[int]] = {}
    for i in range(n_ins):
        groups.setdefault(find(i), []).append(i)
    return list(groups.values())


def _build_cluster_entry(
    root: Path,
    members: Sequence[int],
    countable: Sequence[Tuple[int, Dict[str, Any]]],
    ins_tokens: Sequence[Sequence[str]],
    ins_best_rule: Sequence[Optional[_RuleMatch]],
    rejections: Sequence[Tuple[int, Dict[str, Any]]],
    neighbours: Mapping[str, List[Dict[str, Any]]],
    *,
    home: Optional[Path] = None,
) -> Tuple[Dict[str, Any], bool]:
    m_rows = [countable[m][1] for m in members]
    m_row_idxs = [countable[m][0] for m in members]
    m_ids = [str(r.get("id") or "") for r in m_rows]
    c_tokens = [t for m in members for t in ins_tokens[m]]
    c_paths = {p for m in members for p in (countable[m][1].get("paths") or [])}
    best_m = max(
        (ins_best_rule[m] for m in members if ins_best_rule[m] is not None),
        key=lambda x: x.similarity,
        default=None,
    )
    if best_m is None:
        matched_id, status, best_score = None, "no_rule", 0.0
    else:
        matched_id, best_score = best_m.rule.id, best_m.similarity
        if best_m.kind == "active":
            status = "exposed_and_ignored" if _rule_was_exposed(root, best_m.rule, m_rows, home=home) else "not_exposed"
        elif best_m.kind == "proposal":
            status = "matches_proposal"
        else:
            status = "matches_archived"
    cid = _cluster_signature_id(c_tokens, matched_id)
    latest_rej = max(
        (
            d_idx
            for d_idx, d_row in rejections
            if d_row.get("cluster_id") == cid or set(d_row.get("insight_ids") or []).intersection(m_ids)
        ),
        default=None,
    )
    is_sup = latest_rej is not None and sum(1 for r_idx in m_row_idxs if r_idx > latest_rej) < REJECTION_RESURFACE_COUNT
    info = {
        "cluster_id": cid,
        "insight_ids": m_ids,
        "count": len(m_ids),
        "paths": sorted(c_paths),
        "excerpts": [str(r.get("text") or "") for r in m_rows],
        "levels": sorted({str(r.get("level") or "") for r in m_rows}),
        "match_status": status,
        "matched_rule": matched_id,
        "similarity": round(best_score, 4),
        "neighbours": {mid: neighbours.get(mid, []) for mid in m_ids},
    }
    return info, is_sup


def review_insights(
    workspace: Any,
    *,
    home: Optional[Path] = None,
    include_suppressed: bool = False,
) -> Dict[str, Any]:
    all_rows = read_insight_rows(workspace, home=home)
    noise_ids = {
        str(x)
        for r in all_rows
        if r.get("event") == "decision" and r.get("decision") == "noise"
        for x in (r.get("insight_ids") or [])
        if x
    }
    rejections = [
        (idx, r)
        for idx, r in enumerate(all_rows)
        if r.get("event") == "decision" and r.get("decision") == "reject"
    ]
    hook_rows = [r for r in all_rows if r.get("event") == "insight" and r.get("level") in ("W2", "hook")]
    suggestions: List[Dict[str, Any]] = []
    countable: List[Tuple[int, Dict[str, Any]]] = []
    seen_hook_ids: Set[str] = set()
    for idx, row in enumerate(all_rows):
        ins_id = str(row.get("id") or f"row-{idx}")
        if row.get("event") != "insight" or ins_id in noise_ids:
            continue
        level = row.get("level")
        if level == "suggestion":
            m_hook = _matching_hook_insight(hook_rows, row.get("hs"), str(row.get("text") or ""))
            if not m_hook:
                suggestions.append(row)
                continue
            if m_hook in seen_hook_ids:
                continue
        if level in COUNTABLE_LEVELS or level == "suggestion":
            if level in ("W2", "hook") and ins_id:
                seen_hook_ids.add(ins_id)
            countable.append((idx, row))
    if not countable:
        return {"clusters": [], "suggestions": suggestions, "suppressed_clusters": [], "neighbours": {}}
    from aegis_core.rules import load_rules

    root = Path(os.fspath(workspace)).resolve()
    layout = WorkspaceLayout(root)
    active = list(load_rules(root).served) if layout.rules_dir.is_dir() else []
    proposals = _load_md_rules(root, layout.aegis_dir / "proposals")
    archived = _load_md_rules(root, layout.rules_dir / ".archive", recursive=True)
    ins_tokens = [_tokenize(str(r.get("text") or "")) for _, r in countable]
    rule_entries = [
        (k, r, _tokenize(f"{r.id} {r.meta.get('hypothesis', '')} {r.body}"))
        for k, rl in (("active", active), ("proposal", proposals), ("archived", archived))
        for r in rl
    ]
    all_vecs = _tfidf_vectors(ins_tokens + [toks for _, _, toks in rule_entries])
    n_ins = len(countable)
    ins_vecs, rule_vecs = all_vecs[:n_ins], all_vecs[n_ins:]
    neighbours = {
        str(countable[i][1].get("id") or f"row-{countable[i][0]}"): [
            {"id": nid, "similarity": round(sim, 4)}
            for sim, nid in sorted(
                (
                    (_cosine(ins_vecs[i], ins_vecs[j]), str(countable[j][1].get("id") or f"row-{countable[j][0]}"))
                    for j in range(n_ins)
                    if i != j
                ),
                key=lambda x: (-x[0], x[1]),
            )[:3]
            if sim > 0.0
        ]
        for i in range(n_ins)
    }
    ins_best_rule = _match_insights_to_rules(countable, ins_vecs, rule_entries, rule_vecs)
    clusters: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []
    for members in _cluster_countable_insights(countable, ins_vecs, ins_best_rule):
        info, is_sup = _build_cluster_entry(
            root,
            members,
            countable,
            ins_tokens,
            ins_best_rule,
            rejections,
            neighbours,
            home=home,
        )
        if is_sup:
            suppressed.append(info)
            if include_suppressed:
                clusters.append(info)
        else:
            clusters.append(info)
    return {
        "clusters": clusters,
        "suggestions": suggestions,
        "suppressed_clusters": suppressed,
        "neighbours": neighbours,
    }


_SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


def write_proposal(
    workspace: Any,
    *,
    proposal_id: str,
    rule_type: str = "trap",
    target_paths: Sequence[str],
    category: str,
    summary_bullets: Sequence[str],
    insight_ids: Sequence[str] = (),
    enforcement: str = "advisory",
    home: Optional[Path] = None,
) -> Path:
    clean_id = proposal_id.strip()
    if not _SAFE_ID_RE.match(clean_id):
        raise ValueError(f"invalid proposal_id {proposal_id!r}")
    protected = [
        str(r.get("text") or "").strip().lower()
        for r in read_insight_rows(workspace, home=home)
        if r.get("event") == "insight"
        and r.get("level") in ("W0", "W2", "hook", "suggestion")
        and str(r.get("text") or "").strip()
    ]
    for cand in (category, *summary_bullets):
        clow = str(cand).strip().lower()
        if clow and any(ex in clow or (len(clow) >= 25 and clow in ex) for ex in protected):
            raise ValueError("proposal may not contain verbatim W0/W2/suggestion prompt text")
    norm_targets = [PurePath(str(p)).as_posix() for p in target_paths if str(p).strip()] or ["**"]
    clean_bullets = [_redact(str(b).strip(), max_len=200) for b in summary_bullets if str(b).strip()]
    if not clean_bullets:
        raise ValueError("summary_bullets must contain at least one non-empty item")
    targets_yaml = "\n".join(f"  - {json.dumps(p)}" for p in norm_targets)
    refs_yaml = "\n".join(f"  - {json.dumps(str(i).strip())}" for i in insight_ids if str(i).strip())
    hyp = f"Prevent recurring {category.strip()} issues in {', '.join(norm_targets[:3])}."
    lines = [
        "---",
        f"id: {clean_id}",
        f"type: {rule_type.strip() or 'trap'}",
        "status: proposal",
        f"enforcement: {enforcement.strip() or 'advisory'}",
        f"category: {json.dumps(category.strip())}",
        f"hypothesis: {json.dumps(hyp)}",
        f"target_paths:\n{targets_yaml}",
    ]
    if refs_yaml:
        lines.append(f"insight_ids:\n{refs_yaml}")
    lines.extend([
        "---",
        f"# Proposal: {clean_id}\n",
        "## Guidance\n",
        "\n".join(f"- {b}" for b in clean_bullets) + "\n",
    ])
    prop_dir = WorkspaceLayout(Path(os.fspath(workspace)).resolve()).aegis_dir / "proposals"
    prop_dir.mkdir(parents=True, exist_ok=True)
    target = prop_dir / f"{clean_id}.md"
    atomic_write_text(target, "\n".join(lines))
    return target


def _wilson_ucb95(k: int, n: int) -> float:
    if n <= 0:
        return 1.0
    z = 1.6448536269514722
    phat = min(1.0, max(0.0, k / n))
    z2 = 2.705543454095404
    num = (phat + z2 / (2.0 * n)) + z * math.sqrt((phat * (1.0 - phat) + z2 / (4.0 * n)) / n)
    return min(1.0, round(num / (1.0 + z2 / n), 6))


def _count_recurrence_episodes(matching: Sequence[Mapping[str, Any]]) -> int:
    episodes = 0
    seen_hs: Set[str] = set()
    last_ts: Optional[datetime] = None
    for ins in matching:
        hs_val = ins.get("hs")
        if isinstance(hs_val, str) and hs_val.strip():
            clean_hs = hs_val.strip()
            if clean_hs not in seen_hs:
                seen_hs.add(clean_hs)
                episodes += 1
        else:
            ts = _parse_ts(ins.get("ts"))
            if ts is not None and last_ts is not None and abs((ts - last_ts).total_seconds()) <= BURST_WINDOW_SECONDS:
                continue
            last_ts = ts
            episodes += 1
    return episodes


def measure_recurrence(
    workspace: Any,
    rule_id: str,
    *,
    home: Optional[Path] = None,
    reset_on_rev_change: bool = True,
) -> Dict[str, Any]:
    from aegis_core.rules import load_rules

    root = Path(os.fspath(workspace)).resolve()
    rule = load_rules(root).get(rule_id)
    if rule is None:
        raise ValueError(f"unknown rule {rule_id!r}")
    cur_rev = rule.digest[:16]
    rule_tokens = _tokenize(f"{rule.id} {rule.meta.get('hypothesis', '')} {rule.body}")
    alive: Set[str] = set()
    unidentified_heartbeats = 0
    matching: List[Dict[str, Any]] = []
    for row in read_insight_rows(root, home=home):
        revs = row.get("revs") if isinstance(row.get("revs"), Mapping) else {}
        if reset_on_rev_change and revs.get(rule_id) != cur_rev:
            continue
        ev = row.get("event")
        if ev == "heartbeat":
            hs_val = row.get("hs")
            if isinstance(hs_val, str) and hs_val.strip():
                alive.add(hs_val.strip())
            else:
                unidentified_heartbeats += 1
        elif ev == "insight" and row.get("level") in COUNTABLE_LEVELS and _paths_overlap_rule(row.get("paths") or [], rule):
            itoks = _tokenize(str(row.get("text") or ""))
            if itoks and rule_tokens and _cosine(*_tfidf_vectors([itoks, rule_tokens])) >= 0.12:
                matching.append(row)
    episodes = _count_recurrence_episodes(matching)
    n_sess = len(alive)
    if not n_sess:
        if unidentified_heartbeats > 0 or episodes > 0:
            return {
                "rule": rule_id,
                "rev": cur_rev,
                "sessions": 0,
                "unidentified_heartbeats": unidentified_heartbeats,
                "recurrences": episodes,
                "rate": 0.0,
                "rate_ucb95": 1.0,
                "alarm": False,
                "status": "insufficient_session_identity",
            }
        return {
            "rule": rule_id,
            "rev": cur_rev,
            "sessions": 0,
            "unidentified_heartbeats": 0,
            "recurrences": 0,
            "rate": 0.0,
            "rate_ucb95": 1.0,
            "alarm": False,
            "status": "no_prompt_traffic",
        }
    alarm = episodes >= RECURRENCE_ALARM_COUNT
    return {
        "rule": rule_id,
        "rev": cur_rev,
        "sessions": n_sess,
        "unidentified_heartbeats": unidentified_heartbeats,
        "recurrences": episodes,
        "rate": round(episodes / n_sess, 6),
        "rate_ucb95": _wilson_ucb95(episodes, n_sess),
        "alarm": alarm,
        "status": "not_working" if alarm else "ok",
    }


#: Marks Aegis's insight handler: in the exec form's args, the Codex string or 4.3's ``-m``.
INSIGHT_HOOK_MARKER = "aegis_cli.hooks.insights"


def _host_config_path(host: str, home: Path) -> Path:
    # A relative CLAUDE_CONFIG_DIR/CODEX_HOME is ignored, as the hook registrar ignores it.
    if host == "claude-code":
        env_var, default_dir, fname = "CLAUDE_CONFIG_DIR", ".claude", "settings.json"
    else:
        env_var, default_dir, fname = "CODEX_HOME", ".codex", "hooks.json"
    cfg = os.environ.get(env_var) or ""
    return (Path(cfg) if os.path.isabs(cfg) else home / default_dir) / fname


def _insight_words(handler: Any) -> Optional[List[str]]:
    """The command words of an Aegis insight handler; None for any other handler."""
    if not isinstance(handler, Mapping):
        return None
    args = handler.get("args")
    words = [w for w in (handler.get("command"), *(args if isinstance(args, list) else [])) if isinstance(w, str)]
    return words if any(INSIGHT_HOOK_MARKER in w for w in words) else None


def _strip_insight(groups: List[Any]) -> int:
    """Drop Aegis insight handlers from ``groups`` in place, and the groups they emptied."""
    kept: List[Any] = []
    dropped = 0
    for group in groups:
        handlers = group.get("hooks") if isinstance(group, Mapping) else None
        rest = [h for h in handlers if _insight_words(h) is None] if isinstance(handlers, list) else None
        if rest is None or len(rest) == len(handlers):
            kept.append(group)
            continue
        dropped += len(handlers) - len(rest)
        if rest:
            kept.append(dict(group, hooks=rest))
    groups[:] = kept
    return dropped


def merge_insight_hook(data: Dict[str, Any], handler: Mapping[str, Any]) -> None:
    """Put ``handler`` last in UserPromptSubmit, replacing Aegis's earlier one; ValueError
    for a shape the host would not load."""
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' must be a JSON object")
    groups = hooks.setdefault("UserPromptSubmit", [])
    if not isinstance(groups, list):
        raise ValueError("'hooks.UserPromptSubmit' must be a list")
    _strip_insight(groups)
    groups.append({"matcher": "", "hooks": [dict(handler)]})


def remove_insight_hook(host: str, data: Dict[str, Any]) -> int:
    """Drop Aegis insight handlers (and the containers they emptied); how many. Never raises."""
    hooks = data.get("hooks")
    groups = hooks.get("UserPromptSubmit") if isinstance(hooks, dict) else None
    dropped = _strip_insight(groups) if host in SUPPORTED_INSIGHT_HOSTS and isinstance(groups, list) else 0
    if dropped and not groups:
        del hooks["UserPromptSubmit"]
        if not hooks:
            del data["hooks"]
    return dropped


def host_capture_status(host: str, home: Optional[Path] = None) -> Dict[str, Any]:
    if host == "antigravity":
        return {
            "status": "explicit_only",
            "excerpts": False,
            "detail": "host provides no UserPromptSubmit prompt field; explicit capture only",
        }
    if host not in SUPPORTED_INSIGHT_HOSTS:
        return {"status": "unsupported", "excerpts": False, "detail": f"insight hook is not supported on {host}"}
    layout = _user_layout(home)
    if layout is None:
        return {"status": "disabled", "excerpts": False}
    target = _host_config_path(host, layout.home)
    # is_file follows a link as the host does, and is False for a FIFO, which would hang a read.
    try:
        data = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else None
    except (OSError, ValueError):
        data = None
    hooks = data.get("hooks") if isinstance(data, Mapping) else None
    ups = hooks.get("UserPromptSubmit") if isinstance(hooks, Mapping) else None
    found = [words for g in (ups if isinstance(ups, list) else []) if isinstance(g, Mapping)
             and isinstance(g.get("hooks"), list) for words in map(_insight_words, g["hooks"]) if words]
    if not found:
        return {"status": "disabled", "excerpts": False}
    ex = "--excerpts" in " ".join(found[0]).split()
    return {"status": "enabled_excerpts" if ex else "enabled_counters_only", "excerpts": ex}
