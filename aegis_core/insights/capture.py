"""Insight capture: correction cues, the hook prompt recorder, CLI and agent insights, and the
host hook entry (the UserPromptSubmit handler Aegis writes and reads back)."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePath
import re
import secrets
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import gitsafe, rule_inventory, storage
from aegis_core.insights.keys import (
    INSIGHT_SCHEMA_VERSION,
    SUPPORTED_INSIGHT_HOSTS,
    _append_user_insights,
    _ensure_hs,
    _ensure_private_dir,
    _user_layout,
    insights_path,
)
from aegis_core.primitives import parse_utc, utc_stamp
from aegis_core.redaction import redact_insight_text
from aegis_core.storage import read_jsonl
from aegis_core.workspace.binding import bounded_walk_up
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = [
    "CaptureLimitReached",
    "INSIGHT_HOOK_MARKER",
    "JOIN_WINDOW_S",
    "MAX_CAPTURES_PER_SESSION",
    "add_insight",
    "capture_suggestion",
    "dirty_paths",
    "effective_capture",
    "has_correction_cue",
    "host_capture_status",
    "merge_insight_hook",
    "record_hook_prompt",
    "remove_insight_hook",
]

# How far apart (seconds) an insight and an exposure, or a capture and the hook prompt that
# corroborates it, may be and still join. Nothing links aegis-mcp's session (a uuid minted per
# initialize) to the host's session id the hook sees, so the join is same host, this window and
# the rule's rev. Known limits: record_exposure writes one row per (session, rule, scope basis),
# so the window runs from a session's first exposure of a rule and a correction later than this
# after it reads not_exposed; an exposure that was not persisted has no timestamp and lives in
# another process than the review, so it never counts; a CLI-added insight (host "cli") never
# joins an agent host's exposure.
JOIN_WINDOW_S = 1800
# aegis_capture_insight is reachable by the agent: its cost is bounded per call and per session.
MAX_CAPTURES_PER_SESSION = 50
MAX_CAPTURE_PATHS = 20
MAX_CAPTURE_PATH_CHARS = 512


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


def _inventory_id(root: Path) -> Optional[str]:
    """First 16 hex of the rule-bytes fingerprint; None without rule files or when unreadable."""
    try:
        found = rule_inventory.inventory_rules(str(root))
    except Exception:
        return None
    return found.fingerprint[:16] if found.entries else None


def _known_inventory_revs(path: Path, inv: str) -> Optional[Dict[str, str]]:
    # Rows are compact JSON, so these bytes are exact and appear only in inventory rows.
    for row in read_jsonl(path, contains=b'"event":"inventory"').rows:
        if row.get("event") == "inventory" and row.get("inv") == inv and isinstance(row.get("revs"), dict):
            return dict(row["revs"])
    return None


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


class CaptureLimitReached(ValueError):
    """A bound of capture_suggestion: the session's capture cap, or ``paths`` over its size."""


def _capture_paths(workspace: Any, paths: Optional[Sequence[str]]) -> Tuple[List[str], str, int]:
    """(paths, psrc, dropped). Paths the caller chose that exceed the bounds fail the call; the
    derived dirty-path default is cut to its first MAX_CAPTURE_PATHS and the rest counted."""
    if paths is not None and len(paths) > 0:
        if len(paths) > MAX_CAPTURE_PATHS or any(len(str(p)) > MAX_CAPTURE_PATH_CHARS for p in paths):
            raise CaptureLimitReached(
                f"'paths' takes at most {MAX_CAPTURE_PATHS} paths of at most {MAX_CAPTURE_PATH_CHARS} characters")
        return _confine_paths(workspace, paths), "explicit", 0
    found = dirty_paths(workspace)
    return found[:MAX_CAPTURE_PATHS], "dirty", max(0, len(found) - MAX_CAPTURE_PATHS)


_CORROBORATE_MIN_CHARS = 12


def _row_source(row: Mapping[str, Any]) -> Optional[str]:
    """Who wrote an insight row: 'hook', 'cli' or 'mcp'. A 4.3.x row has no ``source``: a W2
    row is the hook's unless a capture's corroboration (``confirmed_by``) upgraded it."""
    source, level = row.get("source"), row.get("level")
    if source is not None:
        return source if source in ("hook", "cli", "mcp") else None
    if level == "W2":
        return "mcp" if row.get("confirmed_by") else "hook"
    return {"H": "cli", "cli": "cli", "suggestion": "mcp"}.get(level) if isinstance(level, str) else None


def _corroborating_hook(rows: Iterable[Mapping[str, Any]], host: str, ts: Any, quote: str) -> Optional[str]:
    """The id of a hook prompt of ``host`` within JOIN_WINDOW_S of ``ts`` that contains ``quote``."""
    needle, when = quote.strip().lower(), parse_utc(ts)
    if len(needle) < _CORROBORATE_MIN_CHARS or not host or when is None:
        return None
    for r in rows:
        r_ts = parse_utc(r.get("ts"))
        if (r.get("event") == "insight" and _row_source(r) == "hook" and r.get("host") == host
                and r_ts is not None and abs((r_ts - when).total_seconds()) <= JOIN_WINDOW_S
                and needle in str(r.get("text") or "").lower()):
            return str(r.get("id") or "")
    return None


def _is_capture(row: Mapping[str, Any], hs: Optional[str]) -> bool:
    # No hs is one shared bucket.
    return row.get("event") == "insight" and row.get("hs") == hs and _row_source(row) == "mcp"


def _read_rows_of_session(path: Path, hs: str) -> List[Dict[str, Any]]:
    # hs is 32 lowercase hex, never JSON-escaped, so every row of the session carries it verbatim.
    return read_jsonl(path, contains=hs.encode("ascii")).rows


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
        "ts": now or utc_stamp(),
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
    clean = redact_insight_text(text)
    norm_paths, psrc = _resolve_paths(workspace, paths)
    # The human signs the hash of what they typed; only the redacted text is stored.
    level = "H" if _has_human_approval(workspace, commit, base_ref, text) else "cli"
    row = _build_insight_row(
        workspace, level, clean, norm_paths, psrc, "cli", None, source="cli", kind=str(kind) if kind else None,
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
    redacted = redact_insight_text(quote)
    norm_paths, psrc, dropped = _capture_paths(workspace, paths)
    hs = _ensure_hs(host, session, home)
    path = insights_path(workspace, home=home)
    revs = _served_rule_revs(workspace)
    _ensure_private_dir(path.parent.parent)
    _ensure_private_dir(path.parent)
    # One read under the log's lock serves the hook match and the cap, so concurrent captures
    # cannot both pass at the cap (file_lock is re-entrant for the append below).
    with storage.file_lock(path.with_suffix(".lock")):
        rows = _read_rows_of_session(path, hs) if hs else read_jsonl(path, contains=b'"level":"suggestion"').rows
        if sum(1 for r in rows if _is_capture(r, hs)) >= MAX_CAPTURES_PER_SESSION:
            raise CaptureLimitReached(f"capture limit reached: at most {MAX_CAPTURES_PER_SESSION} insights per session")
        # Rows are compact JSON, so a hook row written since 4.4 carries these bytes; review
        # recomputes corroboration over every row (4.3.x hook rows included), so this is a note.
        now = utc_stamp()
        hooks = read_jsonl(path, contains=b'"source":"hook"').rows
        row = _build_insight_row(
            workspace,
            "suggestion",
            redacted,
            norm_paths,
            psrc,
            host or "mcp",
            hs,
            now,
            revs=revs,
            source="mcp",
            corroborated_by=_corroborating_hook(hooks, host or "mcp", now, redacted),
            paths_dropped=dropped,
        )
        _append_user_insights(path, [row])
    return row


def _extract_hook_fields(payload: Any) -> Tuple[str, Optional[str], Optional[str]]:
    """(prompt, session id, cwd) of a host payload: the JSON object Claude Code and Codex send.
    Anything else, raw text included, is no prompt (at most a text-free heartbeat)."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return "", None, None
    if not isinstance(payload, Mapping):
        return "", None, None
    prompt, sess, cwd = (payload.get(k) for k in ("prompt", "session_id", "cwd"))
    return (prompt if isinstance(prompt, str) else "",
            sess.strip() if isinstance(sess, str) and sess.strip() else None,
            cwd.strip() if isinstance(cwd, str) and cwd.strip() else None)


def record_hook_prompt(
    host: str,
    payload: Any,
    *,
    workspace: Any = None,
    excerpts: bool = True,
    home: Optional[Path] = None,
) -> Dict[str, Any]:
    host = str(host)
    prompt_text, payload_session, payload_cwd = _extract_hook_fields(payload)
    actual_ws = workspace
    if actual_ws is None:
        from aegis_core.config import env_workspace
        project = os.environ.get("CLAUDE_PROJECT_DIR", "") if host == "claude-code" else ""
        actual_ws = (project if os.path.isabs(project) else None) or payload_cwd or env_workspace() or os.getcwd()
    resolved = Path(os.fspath(actual_ws)).resolve()
    governed = bounded_walk_up(resolved)
    root = governed or resolved
    # Only a governed workspace excludes ~/.aegis/config.json: a session in HOME, or above it,
    # holds the user file without making it repository content.
    mode = effective_capture(excerpts, governed, home=home)[0]
    if mode == "off":  # decided before the link key, the log or the rules are touched
        return {}
    hs = _ensure_hs(host, payload_session, home=home)
    cue = has_correction_cue(prompt_text)
    excerpt = redact_insight_text(prompt_text) if cue and mode == "excerpts" else ""
    if hs is None and not excerpt:
        # Without session identity a prompt counts toward no session: no heartbeat, no I/O.
        return {}
    path = insights_path(actual_ws, home=home)
    now = utc_stamp()
    to_write: List[Dict[str, Any]] = []
    revs: Optional[Dict[str, str]] = None
    inv = _inventory_id(root)
    if inv:
        # Rules are parsed only for a rule set this log has not seen; later rows reuse its revs.
        revs = _known_inventory_revs(path, inv)
        if revs is None:
            revs = _served_rule_revs(root)
            if hs is not None:
                to_write.append({"v": INSIGHT_SCHEMA_VERSION, "ts": now, "event": "inventory", "inv": inv, "revs": revs})
    hb: Dict[str, Any] = {}
    if hs is not None:
        hb = {"v": INSIGHT_SCHEMA_VERSION, "ts": now, "event": "heartbeat", "host": host, "hs": hs, "cue": cue}
        if inv:
            hb["inv"] = inv
        to_write.append(hb)
    insight_row: Optional[Dict[str, Any]] = None
    if excerpt:
        insight_row = _build_insight_row(
            actual_ws, "W2", excerpt, dirty_paths(actual_ws), "dirty", host, hs, now=now, revs=revs or {}, source="hook",
        )
        to_write.append(insight_row)
    _append_user_insights(path, to_write)
    return insight_row if insight_row is not None else hb


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
    capture, source = effective_capture(ex, None, home=home)
    return {"status": "enabled_excerpts" if ex else "enabled_counters_only", "excerpts": ex,
            "capture": capture, "capture_source": source}


def effective_capture(entry_excerpts: bool, workspace_root: Any, *, home: Optional[Path] = None) -> Tuple[str, str]:
    """(mode, source) of the passive hook: the host entry's mode ('excerpts' or 'counters'), lowered,
    never raised, by the user-scope ``insights.capture``. An unset, invalid or unreadable value, or a
    user file inside ``workspace_root``, leaves the entry's mode; a repository never sets it."""
    from aegis_core.config import parse_capture_mode, read_user_config

    entry, layout = "excerpts" if entry_excerpts else "counters", _user_layout(home)
    section = (read_user_config(workspace_root, user=layout) or {}).get("insights") if layout else None
    wanted = parse_capture_mode(section.get("capture")) if isinstance(section, dict) else None
    if wanted == "off" or (wanted == "counters" and entry == "excerpts"):
        return wanted, "insights.capture"
    return entry, "host entry"
