"""The shared redaction patterns and refusal type (L0: standard library only).

One owner for display and persistence matching; adapters import the redaction facade.
"""
from __future__ import annotations

import bisect
import re

__all__ = [
    "CANDIDATE_TOKEN_RE",
    "CONTROL_RE",
    "bound_redaction_spans",
    "HEX_UUID_RE",
    "HIGH_ENTROPY_MASK",
    "PEM_TAIL",
    "PII_REDACTIONS",
    "SECRET_REDACTIONS",
    "SECRET_REPLACEMENTS",
    "TEXT_REDACTIONS",
    "TOKEN_REDACTIONS",
    "URL_USERINFO_RE",
    "UNFINISHED_SECRET_RE",
    "RedactionRefusal",
]

# One control grammar for the display parser and conservative bounded tails.
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')

_NB = r"(?<![A-Za-z0-9])"
_PEM_HEAD = r"-----BEGIN (?P<pem_label>(?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?)-----"
PEM_TAIL = r"-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----"
_KEYS = ("(?:password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret|credential|"
         "authorization|auth(?![A-Za-z]))")
_SCHEMES = "(?:basic|digest|token|negotiate)"
_URL_USERINFO = re.compile(
    "(?i)((?:" + _NB + "[a-z][a-z0-9+.-]{0,31})?://[^\\s:/@]{1,128}:)[^\\s@/]{1,512}@")
URL_USERINFO_RE = _URL_USERINFO
# Built by concatenation, never as an rf-string: f-string formatting turns a {4,} quantifier
# into the tuple "(4,)". Token quantifiers are bounded; PEM consumes once to its END or EOF.
SECRET_REDACTIONS: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(pattern), hook, text) for pattern, hook, text in (
        # Only the BEGIN label's own END closes a key; otherwise the suffix stays untrusted. EOF matches,
        # so repeated BEGIN markers cannot retry scans over the same unterminated body.
        (_PEM_HEAD + r"[\s\S]*?(?:-----END (?P=pem_label)-----|\Z)", "[REDACTED_PEM]", "[REDACTED_PEM]"),
        # The scheme is optional because Tier A blocks a bare "://user:<password>@host" too.
        (_URL_USERINFO.pattern, r"\1[REDACTED]@",
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
#: The hook-log form of the table: (pattern, replacement), applied in order.
SECRET_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [(p, hook) for p, hook, _ in SECRET_REDACTIONS]
#: Personal data, scrubbed from stored insights only: the hook log keeps paths and addresses.
PII_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}(?![A-Za-z0-9])"),
     "[REDACTED_EMAIL]"),
    (re.compile(r"(?<=/home/)[^/\s]{1,255}|(?<=/Users/)[^/\s]{1,255}|(?<=C:\\Users\\)[^\\\s]{1,255}"), "~user"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
)
TEXT_REDACTIONS = tuple((p, text) for p, _, text in SECRET_REDACTIONS) + PII_REDACTIONS
# The single-token rows, safe over a snippet that already carries masks: PEM spans lines, and the URL
# userinfo and keyed rows (the ones with a backreference) rewrite whatever follows, masks included.
TOKEN_REDACTIONS = tuple((p, text) for p, _, text in SECRET_REDACTIONS if "\\1" not in text and text != "[REDACTED_PEM]")
HEX_UUID_RE = re.compile(r"^(?:[0-9a-fA-F]{7,64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
CANDIDATE_TOKEN_RE = re.compile(r"[A-Za-z0-9+_=-]{20,}")
HIGH_ENTROPY_MASK = "[REDACTED_HIENT]"

# Prefix candidates are used only at an input bound, never to mask complete
# benign words. No terminal syntax is parsed here; the display parser supplies
# its existing views and maps. An unfinished credential must not lose its head.
UNFINISHED_SECRET_RE = re.compile(
    _NB + r"(?:eyJ[A-Za-z0-9_.-]*|(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]*"
    r"|gh[pousr]_[A-Za-z0-9]*|github_pat_[A-Za-z0-9_]*|glpat-[A-Za-z0-9_-]*"
    r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]*|sk-(?:proj-|ant-)?[A-Za-z0-9_-]*"
    r"|AIza[A-Za-z0-9_-]*|xox[abprs]-[A-Za-z0-9-]*|npm_[A-Za-z0-9]*|pypi-[A-Za-z0-9_-]*"
    r"|(?i:Bearer\s{1,8}[A-Za-z0-9._~+/=-]*)"
    r"|(?i:(?:[a-z][a-z0-9+.-]{0,31})?://[^\s:/@]{1,128}:[^\s@/]*)"
    r"|(?i:[A-Za-z0-9_]{0,32}" + _KEYS + r"[A-Za-z0-9_]{0,32}[\"']?\s{0,8}[=:]\s{0,8}[^\s\"',;]*)"
    r"|(?i:(?:password|passwd|pwd|secret|token|api key|private key)\s{1,8}is\s{1,8}[^\s\"',;]*)"
    # A complete BEGIN delimiter belongs to PEM span detection, even if the
    # display view folded its newlines. Do not treat an earlier closed block as
    # a header prefix extending through later benign text and another block.
    r"|-----BEGIN(?:(?!-----)[^\r\n])*)\Z")


def bound_redaction_spans(text, spans, views, match, events, tail_candidates=None):
    """Add tail guards to the historical word/PEM cut, using parser source maps.

    Detection always sees the original bounded head. A later guard can only move
    the cut earlier; it never replaces a previous guard or scans replaced text.
    """
    last_word = re.search(r'\S+\Z', text)
    stop = last_word.start() if last_word else len(text)
    cut, tail_stop = stop, len(text)
    relaxed = re.compile(UNFINISHED_SECRET_RE.pattern.replace(r'(?<![A-Za-z0-9])', ''))
    pending, runs = None, []
    if tail_candidates is not None:
        for start, end, kind, visible, _replacement, _sealed in events:
            if kind == 1 and not visible:
                pending = start if end == start + 1 else None
            joining = not visible or (pending is not None and kind in (1, 2, 3))
            if kind in (0, 4):
                pending = None
            if joining:
                if runs and runs[-1][1] == start:
                    runs[-1] = (runs[-1][0], end)
                else:
                    runs.append((start, end))
        if pending is not None:
            tail_stop = pending
        for start, end in runs:
            if end >= cut:
                tail_stop = min(tail_stop, start)
    for view_index, (shown, boundaries, source_map) in enumerate(views):
        raw_offsets = [row[0] for row in source_map]
        view_offsets = [row[1] for row in source_map]

        def to_view(position):
            index = bisect.bisect_right(raw_offsets, position) - 1
            row = source_map[index] if index >= 0 else (0, 0, 0)
            return row[1] + min(position - row[0], row[2])

        def to_source(position):
            index = bisect.bisect_right(view_offsets, position) - 1
            return source_map[index][0] + position - view_offsets[index]

        # The detection deleted view carries token context across every earlier
        # removable run. Map its first character, never a raw whitespace edge.
        if view_index == 1 and tail_candidates is not None:
            for start, end in runs:
                if end >= cut:
                    for token_start in tail_candidates(shown[:to_view(start)]):
                        tail_stop = min(tail_stop, to_source(token_start))
        for candidate in match(UNFINISHED_SECRET_RE, relaxed, shown, boundaries, endpos=to_view(cut)):
            stop = min(stop, to_source(candidate.start()))
    pem_stop = min((start for start, end, payload in spans if payload == '[REDACTED_PEM]'
                    and start <= stop and end == len(text)), default=len(text))
    stop = min(stop, pem_stop, tail_stop)
    stop = min((start for start, end, _payload in spans if start < stop < end), default=stop)
    marker = '...'[:max(0, len(text) - 1 - stop)] if tail_stop == stop and tail_stop < pem_stop else ''
    return stop, marker


class RedactionRefusal(ValueError):
    """Shared-cleaner refusal. The message is ``invalid`` or ``too_large``, never input."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)
