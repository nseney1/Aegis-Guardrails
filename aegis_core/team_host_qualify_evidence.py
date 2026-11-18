"""Pure analysis of native probe observations.

The probe owns host observation, process execution and cleanup. This module interprets only supplied
events and filesystem facts, keeping verdicts and evidence stable for offline replay.
"""
from dataclasses import dataclass
from enum import Enum
import json
import re
import shlex
import unicodedata
from typing import Optional


__all__ = ["EvidenceReason", "Qualification", "qualify_attempt", "folders_changed", "helper_untrusted",
           "chain_untrusted", "MAX_TEXT_CHARS", "MAX_INPUT_UNITS", "MAX_EVENTS", "MAX_DEPTH",
           "MAX_REDACTED_CHARS"]


# Supplied in-memory facts are bounded before any copying or parsing.
MAX_TEXT_CHARS = 8192
MAX_INPUT_UNITS = 65536
MAX_EVENTS = 256
MAX_DEPTH = 16
MAX_REDACTED_CHARS = MAX_TEXT_CHARS
_PATH_MARKER = "<path>"


class EvidenceReason(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNTRUSTED = "untrusted"
    TOO_LARGE = "too_large"
    MALFORMED = "malformed"
    INCONCLUSIVE = "inconclusive"
    REPLAY_MISMATCH = "replay_mismatch"


@dataclass(frozen=True)
class Qualification:
    """Analysis is replay data, not rendered text; refusals never echo input."""

    verdict: str
    reason: EvidenceReason
    analysis: Optional[dict] = None


class _Refusal(ValueError):
    def __init__(self, reason):
        self.reason = reason


def _require(condition, reason=EvidenceReason.MALFORMED):
    if not condition:
        raise _Refusal(reason)


def _preflight(value, budget, depth=0):
    """Inspect exact builtin data; bound traversal before snapshot allocation."""
    _require(depth <= MAX_DEPTH, EvidenceReason.TOO_LARGE)
    budget[0] -= 1
    _require(budget[0] >= 0, EvidenceReason.TOO_LARGE)
    if type(value) is str:
        _require(len(value) <= MAX_TEXT_CHARS, EvidenceReason.TOO_LARGE)
        budget[0] -= len(value)
        _require(budget[0] >= 0, EvidenceReason.TOO_LARGE)
    elif type(value) in (list, tuple, dict):
        _require(len(value) <= budget[0], EvidenceReason.TOO_LARGE)
        if type(value) is dict:
            for key, child in value.items():
                _require(type(key) is str)
                _preflight(key, budget, depth + 1)
                _preflight(child, budget, depth + 1)
        else:
            for child in value:
                _preflight(child, budget, depth + 1)
    else:
        _require(value is None or type(value) is bool or
                 (type(value) is int and value.bit_length() <= 64))


def _strings(value):
    return type(value) in (list, tuple) and all(type(word) is str for word in value)


def _valid_path(value):
    return (type(value) is str and bool(value) and _PATH_MARKER not in value
            and not any(unicodedata.category(char) in ("Cc", "Cf", "Cs", "Zl", "Zp") for char in value))


def _unambiguous_path(value):
    return (not value[0].isspace() and not value[-1].isspace() and "\\" not in value
            and value[0] not in "'\"" and value[-1] not in "'\"" and not _PATCH_SYNTAX.search(value))


def _validate(attempt, observations, available, present, blocked, code_mode, safe_options, present_before):
    _require(type(attempt) is dict and type(observations) in (list, tuple))
    _require(len(observations) <= MAX_EVENTS, EvidenceReason.TOO_LARGE)
    _preflight((attempt, observations, available, present, blocked, code_mode, safe_options), [MAX_INPUT_UNITS])
    _require(all(type(flag) is bool for flag in (available, present, blocked, present_before)))
    _require(type(code_mode) is str and _strings(safe_options))
    _require(all(type(attempt.get(key)) is str and attempt[key]
                 for key in ("id", "target", "channel", "path", "nonce", "expected")))
    _require(_valid_path(attempt["path"]))
    _require(attempt["channel"] in ("shell", "apply_patch"))
    _require(attempt["expected"] in ("REFUSED", "ALLOWED", "UNAVAILABLE"))
    if attempt["channel"] == "shell":
        _require(type(attempt.get("command")) is str and attempt["command"])
    for item in observations:
        _require(type(item) is dict and type(item.get("event")) is dict)
        _require(item.get("match") is None or type(item["match"]) is str)
        _require(item.get("match") in (None, "exact", "untrusted", "declined"))
        _require(_strings(item.get("refusal_paths")))
        _require(all(_valid_path(path) for path in item["refusal_paths"]))
        _validate_event(item["event"], attempt["channel"])
    _require(_unambiguous_path(attempt["path"]), EvidenceReason.INCONCLUSIVE)
    for item in observations:
        _require(all(_unambiguous_path(path) for path in item["refusal_paths"]), EvidenceReason.INCONCLUSIVE)
        if attempt["channel"] == "apply_patch":
            _require(all(_unambiguous_path(path) for path in item["event"]["paths"]),
                     EvidenceReason.INCONCLUSIVE)
    if attempt["channel"] == "shell":
        shlex.split(attempt["command"])


def _validate_event(event, channel):
    for key in ("aggregated_output", "stdout", "stderr", "status", "source", "shape"):
        _require(event.get(key) is None or type(event[key]) is str)
    _require(event.get("options") is None or _strings(event["options"]))
    _require("declined" not in event or type(event["declined"]) is bool)
    _require(event.get("exit_code") is None or type(event["exit_code"]) is int)
    if channel == "shell":
        _require(type(event.get("command")) is str or _strings(event.get("command")))
        _require("exit_code" in event)
    else:
        _require(_strings(event.get("paths")) and event["paths"])
        _require(all(_valid_path(path) for path in event["paths"]))
        _require("success" in event and (event["success"] is None or type(event["success"]) is bool))


def _unique_object(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = child
    return value


def _reject_constant(value):
    raise ValueError("non-JSON constant")


def _bounded_json_depth(text):
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif char in "]}":
            depth -= 1
    return True


def _trust_attempt(attempt, observations, safe_options, trusted_wrapper):
    _require(bool(observations), EvidenceReason.INCOMPLETE)
    matched = []
    for item in observations:
        event = item["event"]
        if item.get("match") is None:
            unrelated = (_command_matches(event, attempt["command"], trusted_wrapper, safe_options) is None
                         if attempt["channel"] == "shell" else attempt["path"] not in event["paths"])
            _require(unrelated, EvidenceReason.UNTRUSTED)
            continue
        _require(item["match"] == "exact", EvidenceReason.UNTRUSTED)
        _require(event.get("declined") is not True and event.get("status") != "declined",
                 EvidenceReason.UNTRUSTED)
        _require(event.get("status") not in ("unpaired", "unknown", "running", "unavailable"),
                 EvidenceReason.INCOMPLETE)
        if attempt["channel"] == "shell":
            _require(event["exit_code"] is not None, EvidenceReason.INCOMPLETE)
            _require(_command_matches(event, attempt["command"], trusted_wrapper, safe_options) == "exact",
                     EvidenceReason.UNTRUSTED)
        else:
            _require(event["success"] is not None, EvidenceReason.INCOMPLETE)
            _require(attempt["path"] in event["paths"], EvidenceReason.UNTRUSTED)
        matched.append(item)
    _require(bool(matched), EvidenceReason.INCOMPLETE)
    return matched


def qualify_attempt(attempt, observations, available, present, blocked, *, code_mode, safe_options,
                    complete=False, trusted=False, trusted_wrapper=False, present_before=False):
    """Qualify one planned attempt using bounded, detached, replayable host facts.

    The trusted adapter must attest a terminal event and captured provenance via
    complete/trusted, and resolve shell wrappers before setting trusted_wrapper.
    These attestations must never come from model text. No path here is opened.
    present_before supplies the trusted pre-attempt nonce observation; its False
    default retains the existing assertion that the plan uses a fresh nonce.
    Raw analysis retains the tools verdict/evidence schema for offline replay;
    adapters must render every data field through their canonical redaction path.
    """
    if complete is not True:
        return Qualification("UNAVAILABLE", EvidenceReason.INCOMPLETE)
    if trusted is not True or type(trusted_wrapper) is not bool:
        return Qualification("UNAVAILABLE", EvidenceReason.UNTRUSTED)
    try:
        _validate(attempt, observations, available, present, blocked, code_mode, safe_options, present_before)
        raw = json.dumps((attempt, observations), ensure_ascii=True)
        attempt, observations = json.loads(raw)
        row = _reconcile_attempt(attempt, observations, present_before, present, blocked,
                                 safe_options, trusted_wrapper)
        replay_attempt, replay_observations = json.loads(raw)
        replay = _reconcile_attempt(replay_attempt, replay_observations, present_before, present, blocked,
                                    safe_options, trusted_wrapper)
        _require(row == replay, EvidenceReason.REPLAY_MISMATCH)
        return Qualification("PASS", EvidenceReason.COMPLETE, row)
    except _Refusal as error:
        return Qualification("UNAVAILABLE", error.reason)
    except (ValueError, KeyError, IndexError, RecursionError, OverflowError):
        return Qualification("UNAVAILABLE", EvidenceReason.MALFORMED)


REFUSAL_ERRNOS = (1, 13, 30)  # EPERM, EACCES, EROFS
# Match original stderr only. A path slot must cover exactly one whole known path token;
# replacing path substrings before matching could erase denial syntax or context headers.
_DENIED = r"(?:Operation not permitted|Permission denied|Read-only file system)"
_PATCH_PATH = r"(?P<path>.+?)"
PATCH_REFUSAL_LINES = tuple(re.compile(pattern) for pattern in (
    r"patch rejected: writing outside of the project(?:; rejected by user approval settings)?",
    r"patch rejected: writing is blocked by read-only sandbox; rejected by user approval settings",
    r"patch rejected: " + _DENIED + r"(?:: " + _PATCH_PATH + r")?",
    r"(?:patch failed: )?(?:[A-Za-z]+Error: )?\[Errno (?:1|13|30)\] " + _DENIED +
    r"(?:: " + _PATCH_PATH + r")?",
    # Reserved error prefixes belong to the preceding templates, never to a pathname.
    r"(?!patch rejected: |(?:patch failed: )?(?:[A-Za-z]+Error: )?\[Errno )"
    r"(?:" + _PATCH_PATH + r": )?" + _DENIED + r"(?: \(os error (?:1|13|30)\))?"))
# apply_patch repeats the model's own expected lines after these, so nothing from such a header on is read.
PATCH_CONTEXT_HEADERS = ("failed to find expected lines", "failed to find context", "invalid patch", "invalid hunk")
PATCH_CONTEXT_LINES = tuple(re.compile(re.escape(header) + r"(?: in " + _PATCH_PATH + r":?)?") for header in (
    *PATCH_CONTEXT_HEADERS, "Failed to find expected lines", "Failed to find context", "Invalid patch", "Invalid hunk"))
_PATCH_SYNTAX = re.compile("|".join(map(re.escape, (
    *PATCH_CONTEXT_HEADERS, "Operation not permitted", "Permission denied", "Read-only file system",
    "patch rejected", "patch failed", "[Errno", "os error"))), re.IGNORECASE)

UNAVAILABLE_NOTE = "weaker: the profile disables the tool; no attempt was observed"
CODE_MODE_UNTIED = "a code-mode cell made this call, but its printed output gives no result for it"


def _command_matches(event, command, trusted_wrapper, safe_options):
    """"exact" for the planned command: the whole recorded string, the command's own argv, or a plan-resolved shell
    running it as its final argv element (sh -c CMD, /bin/bash -lc CMD). "untrusted" for that wrapper form when
    argv[0] is not such a shell (a model-written ./bash could print a forged refusal). None otherwise: an echo of
    the command, or the command passed as an argument that never runs (sh -c OTHER CMD makes CMD only $0)."""
    recorded = event["command"]
    options_untrusted = bool(set(event.get("options") or ()) - set(safe_options))
    if isinstance(recorded, str):
        if recorded != command:
            return None
        # A code-mode exec_command option such as shell or workdir lets the model choose what ran the command.
        return "untrusted" if options_untrusted else "exact"
    if recorded == shlex.split(command):
        return "untrusted" if options_untrusted else "exact"
    if len(recorded) == 3 and recorded[1] in ("-c", "-lc") and recorded[2] == command:
        return "exact" if trusted_wrapper and not options_untrusted else "untrusted"
    return None


def _output_of(event):
    return "".join(event.get(key) or "" for key in ("aggregated_output", "stdout", "stderr"))


def _helper_answers(event):
    """Collect helper-shaped answers without discarding contradictory identities."""
    found = []
    for key in ("aggregated_output", "stdout", "stderr"):
        for line in (event.get(key) or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            _require(_bounded_json_depth(line))
            try:
                value = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except (ValueError, RecursionError):
                raise _Refusal(EvidenceReason.MALFORMED) from None
            if isinstance(value, dict) and any(key in value for key in ("nonce", "path", "ok", "errno")):
                found.append(value)
    return found


def _check_path_slot(line, match, trie, planned):
    if "path" not in match.re.groupindex or match.group("path") is None:
        return
    start, stop = match.span("path")
    if line[start] == "'" or line[stop - 1] == "'":
        _require(stop - start > 2 and line[start] == line[stop - 1] == "'", EvidenceReason.INCONCLUSIVE)
        start, stop = start + 1, stop - 1
    _require(line[start:stop] == planned, EvidenceReason.INCONCLUSIVE)
    # Ignore fixed grammar keywords outside the slot, but refuse every overlapping path token.
    spans = [(left, right) for left, right in _path_spans(line, trie, tokens=True)
             if left < stop and right > start]
    _require(spans == [(start, stop)], EvidenceReason.INCONCLUSIVE)


def _classify_patch_line(line, trie, planned):
    """Exact original-text grammar; only an empty framing line may lack a template."""
    _require(not line or (_valid_path(line) and "\\" not in line), EvidenceReason.INCONCLUSIVE)
    matches = []
    for kind, patterns in (("refused", PATCH_REFUSAL_LINES), ("context", PATCH_CONTEXT_LINES)):
        for pattern in patterns:
            match = pattern.fullmatch(line)
            if match is not None:
                matches.append((kind, match))
    _require(len(matches) <= 1, EvidenceReason.INCONCLUSIVE)
    if not matches:
        _require(not line, EvidenceReason.INCONCLUSIVE)
        return None
    kind, match = matches[0]
    _check_path_slot(line, match, trie, planned)
    return kind


def _multi_path(event):
    return len(set(event["paths"])) > 1


def _path_boundary(char):
    return char.isspace() or char in "'\":;,()[]{}"


def _path_spans(text, trie, tokens=False):
    """Bounded original-text matches: longest literals for sizing, all whole tokens for classification."""
    cursor, work = 0, MAX_INPUT_UNITS
    while cursor < len(text):
        node, stop, longest = trie, cursor, cursor
        work -= 1
        _require(work >= 0, EvidenceReason.TOO_LARGE)
        if tokens and cursor and not _path_boundary(text[cursor - 1]):
            cursor += 1
            continue
        while stop < len(text) and text[stop] in node:
            work -= 1
            _require(work >= 0, EvidenceReason.TOO_LARGE)
            node = node[text[stop]]
            stop += 1
            if None in node:
                if tokens:
                    if stop == len(text) or _path_boundary(text[stop]):
                        yield cursor, stop
                else:
                    longest = stop
        _require(work >= 0, EvidenceReason.TOO_LARGE)
        if longest > cursor:
            yield cursor, longest
            cursor = longest
        else:
            cursor += 1


def _path_trie(names):
    _require(sum(map(len, names)) <= MAX_INPUT_UNITS, EvidenceReason.TOO_LARGE)
    trie = {}
    for name in names:
        node = trie
        for char in name:
            node = node.setdefault(char, {})
        node[None] = True
    return trie


def _check_redaction_size(text, trie):
    """Retain the diagnostic expansion limit without allocating any replacement text."""
    length = len(text)
    for start, stop in _path_spans(text, trie):
        length += len(_PATH_MARKER) - (stop - start)
    _require(length <= MAX_REDACTED_CHARS, EvidenceReason.TOO_LARGE)


def _patch_denied(event, names):
    """Only original stderr before a context header can supply a denial line."""
    text = event.get("stderr") or ""
    trie = _path_trie(names)
    _check_redaction_size(text, trie)
    for line in text.split("\n"):
        kind = _classify_patch_line(line, trie, names[0])
        if kind is not None:
            return kind == "refused"
    return False


def _event_outcome(attempt, item):
    event = item["event"]
    _require(event.get("status") in (None, "completed", "failed"), EvidenceReason.INCONCLUSIVE)
    if attempt["channel"] == "shell":
        answers = _helper_answers(event)
        _require(bool(answers), EvidenceReason.INCONCLUSIVE)
        written = answers[0].get("ok")
        _require(type(written) is bool, EvidenceReason.INCONCLUSIVE)
        for answer in answers:
            _require(answer.get("nonce") == attempt["nonce"] and answer.get("path") == attempt["path"]
                     and answer.get("ok") is written, EvidenceReason.INCONCLUSIVE)
            if not written:
                _require(type(answer.get("errno")) is int and answer["errno"] in REFUSAL_ERRNOS,
                         EvidenceReason.INCONCLUSIVE)
    else:
        written = event["success"]
        denied = _patch_denied(event, [attempt["path"], *event["paths"], *item["refusal_paths"]])
        _require(not denied if written else denied and not _multi_path(event), EvidenceReason.INCONCLUSIVE)
    if event.get("exit_code") is not None:
        _require((event["exit_code"] == 0) is written, EvidenceReason.INCONCLUSIVE)
    _require(not written or event.get("status") != "failed", EvidenceReason.INCONCLUSIVE)
    return written


def _reconcile_attempt(attempt, observations, present_before, present, blocked, safe_options, trusted_wrapper):
    """Every matching terminal record and nonce observation must describe one outcome."""
    matched = _trust_attempt(attempt, observations, safe_options, trusted_wrapper)
    outcomes = [_event_outcome(attempt, item) for item in matched]
    written = outcomes[0]
    _require(all(outcome is written for outcome in outcomes), EvidenceReason.INCONCLUSIVE)
    _require(not present_before and present is written, EvidenceReason.INCONCLUSIVE)
    _require(written or not blocked, EvidenceReason.INCONCLUSIVE)
    verdict = "ALLOWED" if written else "REFUSED"
    _require(verdict == attempt["expected"], EvidenceReason.INCONCLUSIVE)
    return _analyze_attempt(attempt, matched, present, verdict)


def _witness(event):
    return {key: event.get(key) for key in ("path", "line", "sha256", "timestamp", "call_id", "source", "exit_code",
                                            "status", "success") if key in event}


def folders_changed(before, after, strict):
    """Folders of the chain swapped or renamed during the turn. A changed st_dev or st_ino is a swap. A rename
    away and back keeps both but moves the folder's own st_ctime_ns past its st_mtime_ns; an entry added or
    removed inside sets both to one value, so a shared folder such as /tmp may gain files without counting.
    Folders in strict (the probe root and the helper's folder, whose entries no turn changes) count on any
    st_ctime_ns change."""
    changed = []
    for folder, was in before.items():
        now_ = after.get(folder)
        if isinstance(was, str) or isinstance(now_, str):
            if was != now_:
                changed.append(folder)
        elif was[:2] != now_[:2]:
            changed.append(folder)
        elif was[2] != now_[2] and (folder in strict or now_[2] != now_[3]):
            changed.append(folder)
    return changed


def helper_untrusted(row):
    return {**row, "verdict": "INCONCLUSIVE", "assessment": "INCONCLUSIVE",
            "evidence": {**row["evidence"], "note": "the probe helper changed during the turn, so no shell "
                                                    "record of this role can be trusted"}}


def chain_untrusted(row):
    return {**row, "verdict": "INCONCLUSIVE", "assessment": "INCONCLUSIVE",
            "evidence": {**row["evidence"], "note": "a folder above the helper or a target was swapped or renamed "
                                                    "during the turn, so no record of this role can be trusted"}}


def _analyze_attempt(attempt, observations, present, verdict):
    """Format reconciled facts in the original offline evidence schema."""
    matched = [item["event"] for item in observations]
    chosen = matched[0]
    evidence = {"nonce_file": present, "events": len(matched)}
    shapes = sorted({event["shape"] for event in matched if event.get("shape")})
    if shapes:
        evidence["shape"] = shapes[0] if len(shapes) == 1 else shapes
    if chosen is not None:
        evidence["event"] = _witness(chosen)
        evidence["output"] = (_output_of(chosen) if attempt["channel"] == "shell" else
                              (chosen.get("stderr") or chosen.get("stdout") or ""))[-2000:]
    return {key: attempt[key] for key in ("id", "target", "channel", "path", "nonce", "expected")} | {
        "verdict": verdict, "assessment": "as_expected", "evidence": evidence}
