"""Canonicalization, redaction and row rendering for advisory Git hygiene."""
from __future__ import annotations
import hashlib, sys
from aegis_core import primitives
from aegis_core.redaction import CANDIDATE_TOKEN_RE, is_high_entropy_secret, redact_command_secrets

SCHEMA, DISPLAY_MAX, VALUE_MAX = "aegis.doctor.git/v1", 160, 512
__all__ = [
    'SCHEMA',
    'DISPLAY_MAX',
    'VALUE_MAX',
    'LINE_BREAKS',
    'NONE',
    'RETRY',
    'NO_DELETE',
    'NO_FOLLOW',
    'NO_PRUNE',
    'SET_NEVER',
    'SUGGEST',
    'LEGACY_DETAIL',
    'GATED_DETAIL',
    'UNGATED',
    'SIGNERS',
    'DONE',
    'STALE',
    'DISK',
    'GC',
    'INSPECT',
    'RENAME',
    'PLATFORM',
    'OUTSIDE',
    'SCRATCH_ACT',
    'digest',
    'visible',
    'display',
    'display_target',
    'gate_detail',
    'row',
    'print_report',
]

(NONE, RETRY, NO_DELETE, NO_FOLLOW, NO_PRUNE, SET_NEVER, SUGGEST, LEGACY_DETAIL, GATED_DETAIL, UNGATED,
 SIGNERS, DONE, STALE, DISK, GC, INSPECT, RENAME, PLATFORM, OUTSIDE, SCRATCH_ACT) = (
    "owner action: none", "owner action: retry aegis doctor",
    "owner action: review the path and remove it yourself (doctor does not delete)",
    "owner action: replace the symlink with a real directory or file (doctor does not follow links)",
    "owner action: git worktree prune once if the count stays above zero (doctor does not prune)",
    "owner action: git config gc.worktreePruneExpire never (doctor does not write git config)",
    "owner action: commit an approvals map with main signature, develop review, release/** review and * none (doctor does not write configuration)",
    "legacy gating (no map)", "every target keeps the gate",
    "owner action: set each listed target to signature and configure signers, or accept that weakenings to it need only its mode (doctor does not write configuration)",
    "owner action: add a key to allowed_signers (doctor does not write key material)",
    "owner action: aegis team gc (doctor does not delete leases)",
    "owner action: delete the stale lane branch after the lane is done (doctor does not delete refs)",
    "owner action: free disk until a heavy slot fits (doctor does not delete)",
    "owner action: git gc when objects are large (doctor does not run git gc)",
    "owner action: inspect unmeasured workspace paths manually",
    "owner action: rename the path to a short single line",
    "owner action: run doctor where directory descriptors are available",
    "owner action: leave the path unopened (doctor does not open paths outside the workspace)",
    "owner action: set AEGIS_SCRATCH to a private directory outside the workspace (doctor does not create it)")
_DETAIL_FALLBACKS = {
    "live_lease": "a lane lease is live", "expired_lease": "a lane lease is expired",
    "lease_unreadable": "a lane ref is not a readable lease",
    "stale_lane_branch": "a lane branch has no live lease",
}

def _marked_secret(token):
    bare = token
    while True:
        if is_high_entropy_secret(bare): return True
        nxt = bare.replace("REDACTED", "")
        if not nxt or nxt == bare: return False
        bare = nxt

def digest(text):
    raw = text.encode("utf-8", "surrogateescape") if isinstance(text, str) else b""
    return hashlib.sha256(raw).hexdigest()[:12]

def visible(text):
    if not isinstance(text, str) or not text or any(ch in text for ch in " \n\r\x00"): return None
    shown, code = display(text)
    return text if code is None and shown == text else None

# Every str.splitlines() separator, plus NUL. Refused before sanitize can join them.
LINE_BREAKS = frozenset("\n\r\x00\v\f\x1c\x1d\x1e\x85\u2028\u2029")
_LINE_BREAKS = LINE_BREAKS

def _canonicalize(text):
    safe = primitives.sanitize_display(text, max_len=None)
    # Unicode spaces stay spaces so redaction still sees the separator.
    safe = "".join(" " if char.isspace() else char for char in safe if char.isspace() or char.isprintable())
    return safe.encode("utf-8", "backslashreplace").decode("utf-8")

def _mode_token(mode):
    return isinstance(mode, str) and mode.isascii() and mode.isidentifier() and 0 < len(mode) <= 32

def _structured(text):
    return any(char.isspace() or char in ",;" for char in text)

def gate_detail(pairs):
    """One display-stable line naming targets that lose the gate, or a fixed fallback."""
    if pairs is None:
        return GATED_DETAIL
    if isinstance(pairs, (str, bytes)) or not hasattr(pairs, "__iter__"):
        return "targets lose the gate"
    clean = []
    for item in pairs:
        if not isinstance(item, tuple) or len(item) != 2:
            return "targets lose the gate"
        target, mode = item
        if (not isinstance(target, str) or not target or not _mode_token(mode)
                or display_target(target, max_len=VALUE_MAX) != (target, None) or _structured(target)):
            return "targets lose the gate"
        clean.append((target, mode))
    if not clean:
        return GATED_DETAIL
    return _fit_pairs(clean)

def _name_pieces(names, budget):
    """Keep whole identifiers; digest the longest names only when space requires it."""
    needed = sum(len(name) for name in names)
    if needed <= budget:
        return names
    pieces = list(names)
    for index in sorted(range(len(names)), key=lambda index: len(names[index]), reverse=True):
        token = digest(names[index])
        if len(token) >= len(names[index]):
            break
        needed -= len(names[index]) - len(token)
        pieces[index] = token
        if needed <= budget:
            return pieces
    return None

def _fit_pairs(pairs):
    prefix = "lose the gate: "
    total = len(pairs)
    for count in range(total, 0, -1):
        hidden = total - count
        suffix = f" (+{hidden} more)" if hidden else ""
        selected = pairs[:count]
        overhead = len(prefix) + len(suffix) + (2 * (count - 1))
        overhead += sum(len(mode) + 1 for _target, mode in selected)
        pieces = _name_pieces([target for target, _mode in selected], DISPLAY_MAX - overhead)
        if not pieces:
            continue
        trial = prefix + ", ".join(f"{piece} {mode}" for piece, (_target, mode) in zip(pieces, selected)) + suffix
        if len(trial) > DISPLAY_MAX:
            continue
        shown, code = display(trial)
        if code is None and shown == trial:
            return trial
    return prefix + f"(+{total} more)"

def _publish(safe, max_len):
    redacted = safe
    for _step in range(max(1, len(safe) + 1)):
        nxt = redact_command_secrets(redacted)
        nxt = CANDIDATE_TOKEN_RE.sub(lambda match: "[REDACTED_HIENT]" if _marked_secret(match.group(0)) else match.group(0), nxt)
        if nxt == redacted: break
        redacted = nxt
    if not isinstance(max_len, int) or isinstance(max_len, bool) or len(redacted) <= max_len:
        return redacted, None
    stop = max_len - 3
    for marker in ("[REDACTED_HIENT]", "[REDACTED]", "REDACTED"):
        begin = redacted.rfind(marker, 0, stop + len(marker))
        if begin != -1 and begin < stop < begin + len(marker):
            stop = begin
            break
    return redacted[:max(0, stop)].rstrip() + "...", None

def display(text, *, single_line=True, max_len=DISPLAY_MAX):
    if not isinstance(text, str): text = str(text)
    if len(text) > VALUE_MAX: return None, "value_too_long"
    if single_line and ("\n" in text or "\r" in text or "\x00" in text): return None, "multiline_refused"
    safe = primitives.sanitize_display(text, max_len=None).encode("utf-8", "backslashreplace").decode("utf-8")
    return _publish(safe, max_len)

def display_target(text, *, max_len=DISPLAY_MAX):
    """Bound one approvals-target field: refuse line breaks, then canonicalize, redact, truncate.

    Existing rows keep display(). This path is only for names that lose the gate.
    """
    if not isinstance(text, str): text = str(text)
    if len(text) > VALUE_MAX: return None, "value_too_long"
    if any(char in _LINE_BREAKS for char in text): return None, "multiline_refused"
    return _publish(_canonicalize(text), max_len)

def row(row_id, status, code, owner_action, detail):
    row = {"id": row_id, "status": status, "code": code, "owner_action": owner_action, "detail": detail}
    for key in ("id", "code", "detail", "owner_action"):
        shown, refused = display(row[key], max_len=VALUE_MAX if key == "owner_action" else DISPLAY_MAX)
        if (refused or not shown) and key != "detail":
            return {"id": "git_hygiene", "status": "warn", "code": "git_failed", "owner_action": RETRY, "detail": "report field unavailable"}
        row[key] = _DETAIL_FALLBACKS.get(row["code"], "finding detail unavailable") if key == "detail" and (refused or not shown or shown != row[key]) else shown
    return row

def print_report(report, stream=None):
    out = sys.stdout if stream is None else stream
    print("Git and disk hygiene (report only; doctor does not delete, prune, gc or rewrite refs):", file=out)
    for row in report.get("rows", ()):
        status = row.get("status") if row.get("status") in ("pass", "warn") else "warn"
        ident, icode = display(str(row.get("id", "")), single_line=True)
        detail, dcode = display(str(row.get("detail", "")), single_line=True)
        action, acode = display(str(row.get("owner_action", "")), single_line=True, max_len=VALUE_MAX)
        if icode or dcode or acode or not ident or not detail or not action:
            print(f"  [{status}] refused", file=out)
            continue
        print(f"  [{status}] {ident}: {detail}; {action}", file=out)
