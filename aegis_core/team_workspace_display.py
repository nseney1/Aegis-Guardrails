"""Workspace raw-value screening and fixed, input-free refusal envelopes.

Credential detector grammar retains the measured legacy screening decisions.
"""
from __future__ import annotations

from functools import wraps
from inspect import Parameter, signature
import hashlib
import re
import json
from statistics import median

from aegis_core.team_mailbox_primitives import MailboxRefusal, MAX_RECORDS, bounded_tree, strings, parse_time


__all__ = [
    'MAX_DISPLAY',
    'WorkspaceRefusal',
    'require',
    'refusals',
    'display',
    'screen_fields',
    'display_refusal',
    'display_response',
    'render_report',
    'queue_facts',
]


MAX_DISPLAY = 256
_DISPLAY_ALLOWLIST = re.compile(r"[A-Za-z0-9/._:*?\[\]{},!-]*", re.ASCII)
_DISPLAY_HASH_CHUNK = 4096

# Local stdlib-only copy of aegis_core.redaction's credential grammar.
# The public-refusal corpus pins parity; keep token bounds and case sensitivity.
_NB = r"(?<![A-Za-z0-9])"
_PEM_HEAD = r"-----BEGIN (?P<pem_label>(?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?)-----"
_PEM_TAIL = r"-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----"
_KEYS = ("(?:password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret|credential|"
         "authorization|auth(?![A-Za-z]))")
_SCHEMES = "(?:basic|digest|token|negotiate)"
# Built by concatenation, never as an rf-string: f-string formatting turns a {4,} quantifier
# into the tuple "(4,)". Token quantifiers are bounded; PEM consumes once to its END or EOF.
_SECRET_REDACTIONS: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(pattern), hook, text) for pattern, hook, text in (
        # Only the BEGIN label's own END closes a key; otherwise the suffix stays untrusted. EOF matches,
        # so repeated BEGIN markers cannot retry scans over the same unterminated body.
        (_PEM_HEAD + r"[\s\S]*?(?:-----END (?P=pem_label)-----|\Z)", "[REDACTED_PEM]", "[REDACTED_PEM]"),
        # The scheme is optional because Tier A blocks a bare "://user:<password>@host" too.
        ("(?i)((?:" + _NB + "[a-z][a-z0-9+.-]{0,31})?://[^\\s:/@]{1,128}:)[^\\s@/]{1,512}@", r"\1[REDACTED]@",
         r"\1[REDACTED]@"),
        (_NB + r"eyJ[A-Za-z0-9_-]{8,512}\.[A-Za-z0-9_-]{4,1024}\.[A-Za-z0-9_-]{4,512}", "[REDACTED_JWT]",
         "[REDACTED_JWT]"),
        (_NB + "AKIA[0-9A-Z]{16}", "AKIA_REDACTED", "[REDACTED_AWS]"),
        (_NB + "ASIA[0-9A-Z]{16}", "ASIA_REDACTED", "[REDACTED_AWS]"),
        (_NB + "(?:AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}", "[REDACTED_AWS]", "[REDACTED_AWS]"),
        (_NB + "ghp_[A-Za-z0-9]{20,255}", "ghp_REDACTED", "[REDACTED_VCS_TOKEN]"),
        (_NB + "gh[ousr]_[A-Za-z0-9]{20,255}", "gh_token_REDACTED", "[REDACTED_VCS_TOKEN]"),
        (_NB + "github_pat_[A-Za-z0-9_]{20,255}", "github_pat_REDACTED", "[REDACTED_VCS_TOKEN]"),
        (_NB + "glpat-[A-Za-z0-9_-]{16,255}", "[REDACTED_VCS_TOKEN]", "[REDACTED_VCS_TOKEN]"),
        (_NB + "(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,99}", "[REDACTED_API_KEY]", "[REDACTED_API_KEY]"),
        (_NB + "sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,255}", "sk-REDACTED", "[REDACTED_API_KEY]"),
        (_NB + "AIza[A-Za-z0-9_-]{25,255}", "AIzaSy_REDACTED", "[REDACTED_TOKEN]"),
        (_NB + "(?:xox[abprs]-[A-Za-z0-9-]{10,255}|npm_[A-Za-z0-9]{20,255}|pypi-[A-Za-z0-9_-]{20,255})",
         "[REDACTED_TOKEN]", "[REDACTED_TOKEN]"),
        ("(?i)" + _NB + r"Bearer\s{1,8}[A-Za-z0-9._~+/=-]{16,1024}", "Bearer REDACTED", "Bearer [REDACTED]"),
        # key=value and key: value; an Authorization scheme word is kept and its credential goes.
        ("(?i)(" + _NB + "[A-Za-z0-9_]{0,32}" + _KEYS + "[A-Za-z0-9_]{0,32}[\"']?\\s{0,8}(?:=|:)\\s{0,8}[\"']?"
         "(?:" + _SCHEMES + "\\s{1,8})?)(?!" + _SCHEMES + "\\b)([^\\s\"',;]{4,512})", r"\1REDACTED", r"\1[REDACTED]"),
        # "the password is hunter2": the narrow keys only, so "the auth is broken" stays.
        ("(?i)(" + _NB + "(?:password|passwd|pwd|secret|token|api key|private key)\\s{1,8}is\\s{1,8}[\"']?)"
         "([^\\s\"',;]{6,512})", r"\1REDACTED", r"\1[REDACTED]"),
    ))
_AUTH_SCHEME = re.compile(
    r"(?i)(Bearer|Basic|Digest|Token|Negotiate)(\s{1,8})[A-Za-z0-9._~+/=-]{4,512}")
# Keep the addendum's adjacency-safe forms as detectors, never substitutions.
# A search already tries every starting offset, so the optional key prefix can
# always be empty. Removing it preserves match/no-match without retrying the key
# alternation at each of up to 33 prefix lengths for every clean-path character.
_DISPLAY_CREDENTIALS = tuple(re.compile(pattern.pattern.replace(_NB + "[A-Za-z0-9_]{0,32}", "").replace(_NB, ""))
                             for pattern, _, _ in _SECRET_REDACTIONS) + (_AUTH_SCHEME,)
_TOKEN_CREDENTIALS = _DISPLAY_CREDENTIALS[2:14]
_ASSIGNMENT_CREDENTIAL = _DISPLAY_CREDENTIALS[15]
_URL_CREDENTIAL = _DISPLAY_CREDENTIALS[1]
_SPACE_CREDENTIALS = tuple(_DISPLAY_CREDENTIALS[index] for index in (0, 14, 16, 17))
_WHITESPACE = re.compile(r"\s")


def _credential_match(value):
    """Preserve detector decisions while skipping impossible pattern classes.

    URL userinfo requires @; PEM, prose and authentication schemes require
    whitespace. Neither can occur in allowlisted display input. Assignments
    require a colon or equals sign, so clean paths need only token detectors.
    The same dispatch also preserves decisions for non-allowlisted raw text.
    """
    if any(pattern.search(value) for pattern in _TOKEN_CREDENTIALS):
        return True
    if (":" in value or "=" in value) and _ASSIGNMENT_CREDENTIAL.search(value):
        return True
    if "@" in value and _URL_CREDENTIAL.search(value):
        return True
    return bool(_WHITESPACE.search(value) and any(pattern.search(value) for pattern in _SPACE_CREDENTIALS))


def _display(value):
    """Echo a safe raw value unchanged, or fingerprint the entire original value.

    No normalization, deletion, replacement or truncation can expose a credential
    fragment. Only bounded allowlisted text reaches the credential detectors.
    Strings hash their UTF-8 bytes; surrogatepass preserves lone JSON surrogates.
    Byte inputs hash their original bytes, without decoding or replacement.
    """
    raw = value if isinstance(value, (str, bytes)) else str(value)
    if len(raw) <= MAX_DISPLAY:
        candidate = raw.decode("ascii") if isinstance(raw, bytes) and raw.isascii() else raw
        if (isinstance(candidate, str) and _DISPLAY_ALLOWLIST.fullmatch(candidate) is not None
                and not _credential_match(candidate)):
            return candidate
    digest = hashlib.sha256()
    for offset in range(0, len(raw), _DISPLAY_HASH_CHUNK):
        chunk = raw[offset:offset + _DISPLAY_HASH_CHUNK]
        digest.update(chunk if isinstance(chunk, bytes) else chunk.encode("utf-8", errors="surrogatepass"))
    return "<redacted len=%d sha256=%s>" % (len(raw), digest.hexdigest()[:12])


_NEXT = {
    "invalid_record": "Reconcile the input and stored history against the workspace schema.",
    "unsafe_path": "Use an absolute path without traversal or symlinks under the trusted root.",
    "busy": "Wait for the writer; inspect an abandoned lock before a bounded retry.",
    "capacity_full": "Wait for accepted work to release capacity before retrying.",
    "unsupported_platform": "Use a platform with descriptor-relative no-follow storage.",
    "too_large": "Reduce the input or reconcile retained history before retrying.",
    "missing": "Restore the required workspace record from trusted evidence.",
    "exists": "Read the current workspace history before retrying.",
    "closed": "Open a new workspace store context.",
    "io": "Check storage availability and read the workspace history before retrying.",
    "evidence_mismatch": "Provide evidence matching the recorded SHA-256 digest.",
    "port_required": "Supply the owner-selected lease or mailbox observation port.",
    "port_unavailable": "Restore the owner-selected observation port before retrying.",
}


class WorkspaceRefusal(ValueError):
    """Fixed input-free operational refusal; consumers inspect reason, never text."""
    def __init__(self, reason="invalid_record"):
        self.reason = reason if type(reason) is str and reason in _NEXT else "invalid_record"
        self.code = 1
        self.status = "refused"
        self.next_action = _NEXT[self.reason]
        super().__init__("workspace refused: " + self.reason)

    def as_dict(self, *arguments, **keywords):
        if arguments or keywords:
            raise WorkspaceRefusal("invalid_record")
        return {"status": self.status, "code": self.code, "reason": self.reason,
                "next_action": self.next_action}


def require(condition=None, message=None, *arguments, reason="invalid_record", **keywords):
    # Legacy diagnostic callables are never evaluated or echoed.
    if (arguments or keywords or type(condition) not in
            (bool, int, float, str, bytes, list, tuple, set, frozenset, dict, type(None)) or not condition):
        raise WorkspaceRefusal(reason)


def _check_call(parameters, arguments, keywords):
    """Reject malformed calls before invoking Python's argument binder."""
    positional = [p for p in parameters if p.kind in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)]
    require(any(p.kind == Parameter.VAR_POSITIONAL for p in parameters) or len(arguments) <= len(positional))
    names = {p.name for p in parameters if p.kind in (Parameter.POSITIONAL_OR_KEYWORD, Parameter.KEYWORD_ONLY)}
    require(any(p.kind == Parameter.VAR_KEYWORD for p in parameters) or keywords.keys() <= names)
    provided = {p.name for p in positional[:len(arguments)]}
    require(not provided.intersection(keywords).intersection(names))
    require(all(p.default is not Parameter.empty or p.name in provided
                or p.kind != Parameter.POSITIONAL_ONLY and p.name in keywords
                for p in parameters if p.kind not in (Parameter.VAR_POSITIONAL, Parameter.VAR_KEYWORD)))


def refusals(function=None, *arguments, **keywords):
    """Translate validation and storage failures at every public entry point."""
    require(callable(function) and not arguments and not keywords)
    try:
        parameters = tuple(signature(function).parameters.values())
    except ValueError:
        raise WorkspaceRefusal("invalid_record") from None
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            _check_call(parameters, args, kwargs)
            return function(*args, **kwargs)
        except WorkspaceRefusal:
            raise
        except MailboxRefusal as error:
            raise WorkspaceRefusal(error.reason) from None
        except OSError:
            raise WorkspaceRefusal("io") from None
        except (ValueError, KeyError, IndexError, AttributeError, RecursionError, OverflowError):
            raise WorkspaceRefusal("invalid_record") from None
    return checked


@refusals
def display(value):
    if not isinstance(value, (str, bytes)):
        bounded_tree(value)
    return _display(value)


@refusals
def screen_fields(value):
    """Bound a text-rendering projection, screening every string and key.

    Allowlisted ASCII is already canonical. Other values render only as a fixed
    fingerprint, so controls, normalization changes and credential fragments
    cannot reach text output. Truncation never precedes screening.
    """
    bounded_tree(value, limit=4194304)
    def project(item):
        if type(item) is dict:
            return {_display(key): project(child) for key, child in item.items()}
        if type(item) in (list, tuple):
            return [project(child) for child in item]
        return _display(item) if type(item) is str else item
    return project(value)


@refusals
def display_refusal(error, *, diagnostics=None):
    require(isinstance(error, WorkspaceRefusal))
    result = error.as_dict()
    if diagnostics is not None:
        require(type(diagnostics) is dict)
        # Keys are caller data too. They have no authority over envelope fields.
        result["diagnostics"] = screen_fields(diagnostics)
    return result


_FIXED_DISPLAY_TEXT = frozenset((
    "initiative is active", "initiative is paused", "initiative is done",
    "A clear result is advice, not a lock: run the check and the lease claim one after another.",
))


def _display_fields(value, field=None, *, _memo=None):
    """Screen every key/value; only exact source-owned diagnostic text is exempt."""
    if _memo is None:
        _memo = {}
    if isinstance(value, dict):
        return {_display(key): _display_fields(item, key, _memo=_memo) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_display_fields(item, field, _memo=_memo) for item in value)
    if not isinstance(value, str):
        return value
    if field in ("reason", "note") and value in _FIXED_DISPLAY_TEXT:
        return value
    if value not in _memo:
        _memo[value] = _display(value)
    return _memo[value]


def display_response(function):
    require(callable(function))
    @wraps(function)
    def checked(*args, **kwargs):
        response = function(*args, **kwargs)
        require(type(response) in (tuple, list) and len(response) == 2)
        code, result = response
        require(isinstance(code, int))
        if code:
            bounded_tree(result, limit=4194304)
        return code, _display_fields(result) if code else result
    return refusals(checked)


_REPORT_KINDS = ("writer", "heavy", "heavy-tests")


def _report_record(value):
    require(type(value) is dict)
    return value


def _report_shape(data):
    _report_record(data)
    require(type(data["generated_at"]) is str and type(data["initiatives"]) is list)
    capacity = _report_record(data["capacity"])
    require(type(capacity["queue"]) is list)
    for kind in _REPORT_KINDS:
        row = _report_record(capacity[kind])
        require(all(isinstance(row[name], (int, float)) for name in ("used", "limit")))
    for row in data["initiatives"]:
        _report_record(row)
        require(all(type(row[name]) is str for name in ("id", "project", "state")))
        require(isinstance(row["priority"], (int, float)))
        strings(row["blocked_by"], "blockers")
        for counts in (row["holds"], row["queued"]):
            require(all(isinstance(count, (int, float)) for count in _report_record(counts).values()))
        if row["base_moved"] is not None:
            require(type(_report_record(row["base_moved"])["commit"]) is str)
        if row["mailbox"] is not None:
            _report_record(row["mailbox"])
    if "queue_facts" in data:
        _report_record(data["queue_facts"])


@refusals
def render_report(data):
    data = screen_fields(data)
    _report_shape(data)
    capacity = data["capacity"]
    lines = ["Workspace status, generated by script at " + data["generated_at"],
             "Writers %d/%d, heavy jobs %d/%d, Heavy-Tests %d/%d, queued %d" % (
                 capacity["writer"]["used"], capacity["writer"]["limit"], capacity["heavy"]["used"],
                 capacity["heavy"]["limit"], capacity["heavy-tests"]["used"], capacity["heavy-tests"]["limit"],
                 len(capacity["queue"])), ""]
    for row in data["initiatives"]:
        notes = []
        if row["blocked_by"]:
            notes.append("blocked by " + ", ".join(row["blocked_by"]))
        if row["base_moved"]:
            notes.append("base moved to " + row["base_moved"]["commit"][:12])
        mailbox = row["mailbox"]
        if mailbox is not None:
            notes.append("mailbox error" if "error" in mailbox else "unread " + str(mailbox.get("unread", "not tracked")))
        lines.append("%4d  %-24s %-10s %-7s writers %d heavy %d heavy-tests %d queued %d  %s" % (
            row["priority"], row["id"], row["project"], row["state"], row["holds"]["writer"], row["holds"]["heavy"],
            row["holds"]["heavy-tests"], sum(row["queued"].values()), "; ".join(notes)))
    if "queue_facts" in data:
        for kind in _REPORT_KINDS:
            lines.append(kind + " queue facts: " + json.dumps(data["queue_facts"][kind], sort_keys=True))
    return "\n".join(lines)


@refusals
def queue_facts(requests, now, *, kinds):
    """Lifetime slot-seconds; damaged times are unknown, never zero latency."""
    _report_record(requests)
    require(type(kinds) in (tuple, list))
    require(len(requests) <= MAX_RECORDS and len(kinds) <= MAX_RECORDS, reason="too_large")
    require(all(type(kind) is str for kind in kinds))
    rows_by_id = [_report_record(row) for row in requests.values()]
    current = parse_time(now)
    result = {}
    for kind in kinds:
        rows = [r for r in rows_by_id if r["kind"] == kind]
        waits, ages, busy = [], [], []
        unknown = 0
        for row in rows:
            try:
                requested = parse_time(row["requested_at"])
                granted = parse_time(row["granted_at"]) if "granted_at" in row else None
                closed = parse_time(row["closed_at"]) if "closed_at" in row else None
                points = [requested] + ([granted] if granted is not None else [])
                points += ([closed] if closed is not None else []) + [current]
                require(points == sorted(points))
                require(row["state"] not in ("granted", "released") or granted is not None)
                require(row["state"] not in ("released", "withdrawn") or closed is not None)
            except (ValueError, KeyError, OverflowError):
                unknown += 1
                continue
            if row["state"] == "queued":
                ages.append((current - requested).total_seconds())
            if granted is not None:
                waits.append((granted - requested).total_seconds())
                busy.append(((closed if closed is not None else current) - granted).total_seconds())
        result[kind] = {
            "queued": sum(r["state"] == "queued" for r in rows),
            "open": sum(r["state"] in ("queued", "granted") for r in rows),
            "oldest_queued_seconds": max(ages) if ages else None,
            "queue_wait_seconds": {"count": len(waits), "p50": median(waits) if waits else None,
                                   "max": max(waits) if waits else None},
            "busy_seconds": sum(busy) if busy else None,
            "withdrawn_count": sum(r["state"] == "withdrawn" for r in rows),
            "superseded_count": sum("superseded_by" in r for r in rows),
            "timing_unknown": unknown}
    return result
