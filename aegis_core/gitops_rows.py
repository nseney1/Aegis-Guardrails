"""Validated git-operation rows and fixed refusals; no journal or effect I/O."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re

from aegis_core.primitives import parse_utc, sanitize_display, utc_stamp
from aegis_core.redaction import (CANDIDATE_TOKEN_RE, is_high_entropy_secret,
                                  redact_command_secrets)

__all__ = [
    "GitOpsError", "JournalRead", "OPS", "REFUSALS",
    "MAX_JOURNAL_BYTES", "MAX_ROW_BYTES", "MAX_RECORD_LINES",
    "RECONCILE_BATCH_SIZE", "FINAL_RECORD_ATTEMPTS", "DISPLAY_LIMIT",
    "BASE_KEYS", "LANE", "identifier", "state", "display_row",
    "same_intent", "encoded", "terminal_bytes", "pairs", "valid_row",
    "parse", "intent", "result", "as_intent", "as_result", "compacted",
]

OPS = ("worktree_add", "worktree_remove", "commit", "ref_update", "push", "pr_open",
       "pr_ready", "pr_close", "merge", "run_cancel", "lease_claim", "lease_renew",
       "lease_transfer", "lease_release")
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_ROW_BYTES = 65536
MAX_RECORD_LINES = 32768
RECONCILE_BATCH_SIZE = 8
FINAL_RECORD_ATTEMPTS = 3
MAX_CHECKPOINT_REQUEST_IDS = 16
DISPLAY_LIMIT = 256
REFUSALS = {
    "invalid_intent": "invalid git operation intent",
    "invalid_result": "invalid git operation result",
    "invalid_request": "invalid git operation request identifier",
    "request_conflict": "git operation request already reserved with different inputs",
    "result_conflict": "git operation already has a different terminal result",
    "missing_intent": "git operation result requires a durable intent",
    "unsupported_platform": "descriptor-relative git operation journal unavailable",
    "unsafe_journal": "unsafe git operation journal path or file; use the trusted root's realpath spelling",
    "journal_too_large": "git operation journal size limit exceeded; ask the owner to archive closed history",
    "journal_capacity": "git operation result capacity reserved; reconcile pending intents and ask the owner to archive closed history",
    "journal_busy": "git operation journal lock timed out",
    "effect_busy": "git operation effect is still owned; wait for its result or reconcile after its owner exits",
    "journal_io": "git operation journal I/O failed; observe before any further action",
    "checkpoint_stuck": "git operation observation checkpoints require owner recovery",
}
_RESULT_ACTIONS = {
    "observation": "correct the result status and observation to match the durable intent; then record the result",
    "receipt": "provide the matching active receipt for this request; then record the observed result",
    "descriptor": "provide the inherited effect-lock descriptor for this request; then record the observed result",
    "ownership": "supply one ownership argument: a matching receipt or an inherited effect-lock descriptor; then record the observed result",
    "capacity": "inspect the pending intent and restore journal capacity or storage; reconcile by observation before any further action",
}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
LANE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}\Z")
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
STATE_TEXT = {"ref", "head", "base", "state", "path", "owner", "branch", "lease_id", "oid"}
STATE_NUMBER = {"number", "run_id", "pr_number", "generation"}
BASE_KEYS = {"v", "kind", "op", "lane", "request_id", "expected_old", "expected_new",
              "actor", "created_at", "ts"}
class GitOpsError(ValueError):
    """Documented refusal, safe to render verbatim."""

    def __init__(self, code, root=None, *, result_cause="observation", request_ids=()):
        super().__init__(REFUSALS[code])
        self.code = code
        self.results = []
        self.next_action = {"actor": "owner", "command": REFUSALS[code]}
        if code == "invalid_result":
            self.next_action["command"] = _RESULT_ACTIONS[result_cause]
        elif code == "journal_io":
            self.next_action["command"] = _RESULT_ACTIONS["capacity"]
        elif code == "unsupported_platform":
            self.next_action["command"] = "use a supported descriptor platform and a local filesystem for the git common dir"
        elif code == "result_conflict":
            self.next_action["command"] = ("read the durable result for this request; never retry the effect"
                                           if result_cause == "durable" else
                                           "reconcile the lane to publish the saved observation, then read its result")
        elif code == "checkpoint_stuck":
            self.next_action["command"] = "owner reads external state for each listed request, then calls record_result(request_id, status, observed) to resolve it; never retry the effect; at most 16 request IDs are listed, reconcile again after resolving them"
            self.next_action["request_ids"] = [clean(request)[:DISPLAY_LIMIT] for request in request_ids[:MAX_CHECKPOINT_REQUEST_IDS]]
            self.next_action["request_ids_truncated"] = len(request_ids) > MAX_CHECKPOINT_REQUEST_IDS
        if code == "unsafe_journal" and root is not None:
            try:
                canonical = sanitize_display(os.path.realpath(root), max_len=None)
                self.next_action["path"] = sanitize_display(redact_command_secrets(canonical), max_len=DISPLAY_LIMIT)
            except (OSError, ValueError):
                self.next_action["path"] = "[canonical root unavailable]"


@dataclass(frozen=True)
class JournalRead:
    rows: list
    skipped: int = 0
    torn_tail: bool = False


def clean(text):
    canonical = sanitize_display(text, max_len=None)
    redacted = redact_command_secrets(canonical)
    return CANDIDATE_TOKEN_RE.sub(
        lambda match: "[REDACTED]" if is_high_entropy_secret(match.group()) else match.group(), redacted)


def text(value, limit, *, check_secrets=True):
    return (type(value) is str and 0 < len(value) <= limit
            and all(char.isprintable() for char in value)
            and (not check_secrets or redact_command_secrets(value) == value))


def identifier(value, pattern=ID):
    return type(value) is str and 0 < len(value) <= 128 and pattern.fullmatch(value) is not None


def state(value, *, check_secrets=True):
    if value is None:
        return None
    if type(value) is str and len(value) in (40, 64) and OID.fullmatch(value):
        return value
    if type(value) is not dict or not 1 <= len(value) <= 12:
        raise ValueError("state shape")
    result, size = {}, 0
    for key, child in value.items():
        if type(key) is not str or len(key) > 16:
            raise ValueError("state field")
        if key in STATE_TEXT:
            if not text(child, 1024, check_secrets=check_secrets):
                raise ValueError("state text")
            size += len(child)
        elif key in STATE_NUMBER:
            if type(child) is not int or not 0 <= child <= 2 ** 63 - 1:
                raise ValueError("state number")
        elif key == "exists":
            if type(child) is not bool:
                raise ValueError("state presence")
        else:
            raise ValueError("unknown state field")
        if size > 4096:
            raise ValueError("state size")
        result[key] = child
    return result


def display_row(value, _depth=0, *, max_row_bytes=MAX_ROW_BYTES, display_limit=DISPLAY_LIMIT):
    """Canonicalize, redact, then truncate every string, including dictionary keys.

    Over-limit containers/fields are replaced by a fixed marker, never sliced
    before redaction. This is display only, never an observation or identity key.
    """
    if _depth > 4:
        return "[oversized]"
    if type(value) is str:
        if len(value) > max_row_bytes:
            return "[oversized]"
        return sanitize_display(clean(value), max_len=display_limit)
    if type(value) is dict:
        if len(value) > 32:
            return "[oversized]"
        return {display_row(key, _depth + 1, max_row_bytes=max_row_bytes, display_limit=display_limit):
                display_row(child, _depth + 1, max_row_bytes=max_row_bytes, display_limit=display_limit)
                for key, child in value.items() if type(key) is str}
    if value is None or type(value) in (bool, int):
        return value
    return "[invalid]"


def binding(op, lane, request_id, expected_old, expected_new, actor, *, check_secrets=True):
    if (type(op) is not str or op not in OPS or not identifier(lane, LANE)
            or not identifier(request_id) or not identifier(actor)):
        raise ValueError("intent fields")
    old = state(expected_old, check_secrets=check_secrets)
    new = state(expected_new, check_secrets=check_secrets)
    if old == new:
        raise ValueError("indeterminate expected transition")
    return old, new


def intent(op, lane, request_id, expected_old, expected_new, actor, *, stamp=None):
    try:
        old, new = binding(op, lane, request_id, expected_old, expected_new, actor)
    except ValueError:
        raise GitOpsError("invalid_intent") from None
    stamp = utc_stamp() if stamp is None else stamp
    return dict(v=1, kind="intent", op=op, lane=lane, request_id=request_id,
                expected_old=old, expected_new=new, actor=actor, created_at=stamp, ts=stamp)


def result_state(intent, status, observed, *, check_secrets=True):
    if type(status) is not str or status not in ("done", "not_applied", "unknown"):
        raise ValueError("status")
    observed = state(observed, check_secrets=check_secrets)
    if ((status == "done" and observed != intent["expected_new"])
            or (status == "not_applied" and observed != intent["expected_old"])):
        raise ValueError("contradictory observation")
    return observed


def result(intent, status, observed, *, stamp=None):
    try:
        observed = result_state(intent, status, observed)
    except ValueError:
        raise GitOpsError("invalid_result", result_cause="observation") from None
    return dict(intent, kind="result", status=status, observed=observed,
                ts=max(utc_stamp() if stamp is None else stamp, intent["ts"]))


def pairs(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = child
    return value


def valid_row(row):
    if type(row) is not dict or type(row.get("v")) is not int or row["v"] != 1:
        return False
    keys = BASE_KEYS if row.get("kind") == "intent" else BASE_KEYS | {"status", "observed"}
    if row.keys() != keys or row["kind"] not in ("intent", "result", "tombstone"):
        return False
    try:
        binding(*(row[key] for key in ("op", "lane", "request_id", "expected_old", "expected_new", "actor")),
                 check_secrets=False)
        if any(not text(row[key], 32, check_secrets=False) or parse_utc(row[key]) is None
               for key in ("ts", "created_at")):
            return False
        if row["ts"] < row["created_at"]:
            return False
        if row["kind"] != "intent":
            result_state(row, row["status"], row["observed"], check_secrets=False)
        return True
    except ValueError:
        return False


def same_intent(left, right):
    return all(left[key] == right[key] for key in BASE_KEYS - {"kind", "ts"})


def parse(data, *, max_lines=MAX_RECORD_LINES, max_row_bytes=MAX_ROW_BYTES):
    if data.count(b"\n") > max_lines:
        raise GitOpsError("journal_too_large")
    rows, skipped, intents, results = [], 0, {}, set()
    lines = data.split(b"\n")
    torn = bool(data and not data.endswith(b"\n"))
    for index, raw in enumerate(lines):
        if index == len(lines) - 1 and not raw:
            break
        try:
            # A complete JSON object without its newline is still uncommitted.
            if len(raw) > max_row_bytes or (torn and index == len(lines) - 1):
                raise ValueError("line size or torn tail")
            row = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
            if not valid_row(row):
                raise ValueError("schema")
            request = row["request_id"]
            if row["kind"] == "tombstone":
                if request in intents or request in results:
                    raise ValueError("duplicate terminal request")
                results.add(request)
            elif row["kind"] == "intent":
                if request in intents or request in results:
                    raise ValueError("duplicate intent")
                intents[request] = row
            elif request not in intents or request in results or not same_intent(row, intents[request]):
                raise ValueError("orphan or conflicting result")
            else:
                results.add(request)
            rows.append(row)
        except (ValueError, UnicodeError, RecursionError):
            skipped += 1
    return JournalRead(rows, skipped, torn)


def as_intent(row):
    """Recover the original binding from an automatic-compaction tombstone."""
    return {key: ("intent" if key == "kind" else row["created_at"] if key == "ts" else row[key])
            for key in BASE_KEYS}


def as_result(row):
    return dict(row, kind="result")


def compacted(read, *, data, max_row_bytes, max_journal_bytes, max_lines=MAX_RECORD_LINES):
    """Preserve skipped bytes in place; replace closed pairs at their intent line.

    Match the already-validated sequence, so duplicate/orphan rows stay evidence
    rather than becoming authoritative after their earlier intent is removed.
    A pair stays intact if its canonical tombstone cannot fit or save space.
    """
    if len(data) > max_journal_bytes or data.count(b"\n") > max_lines:
        raise GitOpsError("journal_too_large")
    if not data:
        return None
    if not data.endswith(b"\n"):
        raise GitOpsError("journal_io")
    closed = {row["request_id"]: encoded(dict(row, kind="tombstone")) + b"\n"
              for row in read.rows if row["kind"] == "result"}
    closed = {request: payload for request, payload in closed.items()
              if len(payload) <= max_row_bytes + 1}
    if not closed:
        return None
    raw_lines, positions = data.split(b"\n")[:-1], {}
    expected = iter(read.rows)
    wanted = next(expected, None)
    for index, raw in enumerate(raw_lines):
        if wanted is None or len(raw) > max_row_bytes:
            continue
        try:
            row = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
            if valid_row(row) and row == wanted:
                positions[index] = wanted
                wanted = next(expected, None)
        except (ValueError, UnicodeError, RecursionError):
            pass
    if len(positions) != len(read.rows):
        raise GitOpsError("journal_io")
    pair_bytes = {}
    for index, row in positions.items():
        if row["kind"] in ("intent", "result"):
            request = row["request_id"]
            pair_bytes[request] = pair_bytes.get(request, 0) + len(raw_lines[index]) + 1
    closed = {request: payload for request, payload in closed.items()
              if len(payload) < pair_bytes[request]}
    if not closed:
        return None
    parts, size = [], 0
    for index, raw in enumerate(raw_lines):
        row = positions.get(index)
        terminal = closed.get(row["request_id"]) if row is not None else None
        if terminal is not None and row["kind"] == "result":
            continue
        part = terminal if terminal is not None else raw + b"\n"
        size += len(part)
        if size > max_journal_bytes:
            raise GitOpsError("journal_too_large")
        parts.append(part)
    return b"".join(parts)


def encoded(row):
    return json.dumps(row, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def maximum_observation_bytes():
    """Measure the largest legal state, including ensure_ascii surrogate pairs.

    All four 19-digit numbers and false occupy more bytes than another text
    key at the fixed 4096-character budget. Fill the remaining seven slots
    with the longest text keys. Ref and oid are the two shortest keys.
    """
    maximum = {key: "\U00010000" * (1024 if key in ("branch", "lease_id", "head")
                                    else 1021 if key == "base" else 1)
               for key in STATE_TEXT - {"oid", "ref"}}
    maximum.update({key: 2 ** 63 - 1 for key in STATE_NUMBER})
    maximum["exists"] = False
    return len(encoded(maximum))


MAX_OBSERVATION_BYTES = maximum_observation_bytes()


def terminal_bytes(intent):
    """Measure this intent's largest terminal row, including duplicated state.

    Substitute the measured maximum observation for JSON null without allocating
    that state for every pending intent. Bound observations also participate:
    not_applied has a longer status than unknown. Timestamps retain the fixed
    utc_stamp width (or a longer timestamp already present in stored intent).
    """
    unknown = len(encoded(dict(intent, kind="result", status="unknown", observed=None)))
    return max(unknown - len(b"null") + MAX_OBSERVATION_BYTES,
               *(len(encoded(dict(intent, kind="result", status=status, observed=state)))
                 for status, state in (("done", intent["expected_new"]),
                                       ("not_applied", intent["expected_old"]))))


