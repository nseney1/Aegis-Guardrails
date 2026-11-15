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
    'NONE',
    'RETRY',
    'NO_DELETE',
    'NO_FOLLOW',
    'NO_PRUNE',
    'SET_NEVER',
    'SUGGEST',
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
    'row',
    'print_report',
]

(NONE, RETRY, NO_DELETE, NO_FOLLOW, NO_PRUNE, SET_NEVER, SUGGEST, SIGNERS, DONE, STALE, DISK, GC,
 INSPECT, RENAME, PLATFORM, OUTSIDE, SCRATCH_ACT) = (
    "owner action: none", "owner action: retry aegis doctor",
    "owner action: review the path and remove it yourself (doctor does not delete)",
    "owner action: replace the symlink with a real directory or file (doctor does not follow links)",
    "owner action: git worktree prune once if the count stays above zero (doctor does not prune)",
    "owner action: git config gc.worktreePruneExpire never (doctor does not write git config)",
    "owner action: commit an approvals map with main signature, develop review, release/** review and * none (doctor does not write configuration)",
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

def display(text, *, single_line=True, max_len=DISPLAY_MAX):
    if not isinstance(text, str): text = str(text)
    if len(text) > VALUE_MAX: return None, "value_too_long"
    if single_line and ("\n" in text or "\r" in text or "\x00" in text): return None, "multiline_refused"
    safe = primitives.sanitize_display(text, max_len=None).encode("utf-8", "backslashreplace").decode("utf-8")
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
