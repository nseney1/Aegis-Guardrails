"""The shared redaction patterns and refusal type (L0: standard library only).

One owner for display and persistence matching; adapters import the redaction facade.
"""
from __future__ import annotations

import bisect
from functools import lru_cache
import re
import sys

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

# The historical whole-word policy uses this guard. Command heads instead use
# proper prefixes of the complete rules below.
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


def _joining_runs(events):
    pending, runs = None, []
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
    return pending, runs


def _regex_backend():
    """Open the version's parser/compiler pair for the trusted grammar."""
    if sys.version_info >= (3, 11):
        from re import _compiler as compiler, _parser as parser
    else:
        import sre_compile as compiler
        import sre_parse as parser
    return parser, compiler


def _regex_group(operand, flags):
    """A group ends in its body, with optional scoped flags before it."""
    scope = operand[1:-1]
    if scope:
        add, remove = scope
        flags = (flags | add) & ~remove
    return operand[-1], flags


def _derive_command_prefix_rules(rules):
    """Compile the proper-prefix closure of the trusted full regex rows once.

    Keep normal and carried starts. Widths bound how far back each row can
    search. For PEM, a full BEGIN is already handled by the full detector.
    Its unbounded label words cannot contain another BEGIN start.
    """
    parser, compiler = _regex_backend()

    def choices(state, paths):
        paths = [parser.SubPattern(state, path) for path in paths if path is not None]
        if len(paths) == 1:
            return paths[0].data
        return [(parser.BRANCH, (None, paths))] if paths else None

    def proper_prefix(sequence):
        """A sequence can end inside its first atom or inside what follows it."""
        prefix, state = None, sequence.state
        for op, operand in reversed(sequence):
            complete = (op, operand)
            if op == parser.SUBPATTERN:
                body, _flags = _regex_group(operand, 0)
                inside = proper_prefix(body)
                part = ([(op, (*operand[:-1], parser.SubPattern(state, inside)))]
                        if inside is not None else None)
            elif op == parser.BRANCH:
                part = choices(state, [proper_prefix(branch) for branch in operand[1]])
            elif op in (parser.MAX_REPEAT, parser.MIN_REPEAT):
                _minimum, maximum, body = operand
                inside = proper_prefix(body)
                if inside is None or maximum == 0:
                    part = None
                else:
                    upper = maximum if maximum == parser.MAXREPEAT else maximum - 1
                    part = [(op, (0, upper, body)), *inside]
            elif op == parser.ASSERT_NOT:
                direction, body = operand
                # A \b at the artificial end is undecided. A future word
                # character can still extend the value past the scheme word.
                if direction == 1 and body[-1] == (parser.AT, parser.AT_BOUNDARY):
                    body = parser.SubPattern(state, [*body, (parser.ASSERT_NOT, (1, end))])
                    complete = (op, (direction, body))
                part = None
            elif op in (parser.LITERAL, parser.NOT_LITERAL, parser.IN, parser.ANY):
                part = []
            else:
                raise ValueError("unsupported secret prefix grammar")
            prefix = choices(state, ([complete, *prefix] if prefix is not None else None, part))
        return prefix

    nonempty = parser.parse(r"(?=[\s\S])")
    end = parser.parse(r"\Z")

    def compile_prefix(pattern, flags):
        parsed = parser.parse(pattern, flags)
        prefix = proper_prefix(parsed)
        expression = parser.SubPattern(parsed.state, [*nonempty, *prefix, *end])
        return compiler.compile(expression, flags)

    rows = []
    for pattern, _hook, replacement in rules:
        body = _PEM_HEAD if replacement == '[REDACTED_PEM]' else pattern.pattern
        carried_body = body.replace(_NB, '')
        max_width = parser.parse(body, pattern.flags).getwidth()[1]
        ordinary = compile_prefix(body, pattern.flags)
        if carried_body != body:
            carried = compile_prefix(carried_body, pattern.flags)
        else:
            carried = ordinary
        rows.append((ordinary, carried, max_width))
    return tuple(rows)


@lru_cache(maxsize=1)
def _command_prefix_rules(rules):
    return _derive_command_prefix_rules(rules)


def _command_prefix_start(text, start, end, boundaries, rules):
    """Probe each row's suffix window at ordinary and carried start positions."""
    first = end
    for ordinary, carried, width in rules:
        left = max(start, end - width + 1)
        if left >= first:
            continue
        result = ordinary.search(text, left, end)
        if result is not None:
            first = min(first, result.start())
        if carried is not ordinary:
            index = bisect.bisect_left(boundaries, left)
            while index < len(boundaries) and boundaries[index] < first:
                if carried.match(text, boundaries[index], end) is not None:
                    first = boundaries[index]
                    break
                index += 1
    return first


def _view_offset(source_map, position):
    return next((offset + min(position - source, size)
                 for source, offset, size in reversed(source_map) if source <= position), 0)


def _command_redaction_stop(text, views, events):
    """Withhold a head when a full rule can still match across the cut.

    The cut is the end of the analysed text. Removed controls still join.
    Escape open/sealed state is not part of this choice: the caller ends every
    command at the first ESC or C1 control, so this cutoff never sees that tail.
    """
    # One sequence for every pass. A renderer generator is spent by the first read.
    events = tuple(events)
    end = len(text)
    try:
        rules = _command_prefix_rules(SECRET_REDACTIONS)
    except Exception:
        # Derivation uses trusted static patterns. Withhold the excerpt if the
        # backend cannot prove a safe cutoff. Only successful tables are cached.
        return 0, end
    _pending, runs = _joining_runs(events)
    joining = runs[-1][0] if runs and runs[-1][1] == end else end
    cuts = [end]
    if joining < end:
        cuts.append(joining)
    stop = tail_stop = end
    matches = {}
    for source_cut in cuts:
        visible_end = max((min(row[1], source_cut) for row in events if row[0] < source_cut and row[3]), default=0)
        for index, (shown, boundaries, source_map) in enumerate(views):
            if index == 4 and source_cut != end:
                continue
            cut = _view_offset(source_map, source_cut)
            carried = tuple(position for position in boundaries if 0 < position < cut)
            key = shown[:cut], cut, carried
            if key not in matches:
                matches[key] = _command_prefix_start(shown, 0, cut, carried, rules)
            first = matches[key]
            if first == cut:
                continue
            start = next(source + first - offset for source, offset, _ in reversed(source_map) if offset <= first)
            if index not in (0, 2) and start >= visible_end:
                continue
            if source_cut < end:
                tail_stop = min(tail_stop, start)
            else:
                stop = min(stop, start)
                tail_stop = min(tail_stop, start)
    return stop, tail_stop


def _whole_word_stop(text, views, match, events, tail_candidates):
    """Add tail guards to the historical word/PEM cut, using parser source maps.

    Detection always sees the original bounded head. A later guard can only move
    the cut earlier; it never replaces a previous guard or scans replaced text.
    """
    # Same replayable sequence as the command cutoff. Do not scan the caller's iterable twice.
    events = tuple(events)
    last_word = re.search(r'\S+\Z', text)
    stop = last_word.start() if last_word else len(text)
    cut, tail_stop = stop, len(text)
    relaxed = re.compile(UNFINISHED_SECRET_RE.pattern.replace(r'(?<![A-Za-z0-9])', ''))
    runs = []
    if tail_candidates is not None:
        pending, runs = _joining_runs(events)
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

        # A joining run at the cut may hide the end of the candidate. Match in
        # the deleted view before that run and map the start back to the source.
        if view_index == 1:
            for start, end in runs:
                if end < cut:
                    continue
                for token_start in tail_candidates(shown[:to_view(start)]):
                    tail_stop = min(tail_stop, to_source(token_start))
        for candidate in match(UNFINISHED_SECRET_RE, relaxed, shown, boundaries, endpos=to_view(cut)):
            stop = min(stop, to_source(candidate.start()))
    return stop, tail_stop


def bound_redaction_spans(text, spans, views, match, events, tail_candidates=None, *, secret_tail=False):
    """Combine the selected cutoff with PEM and whole-span protections."""
    stop, tail_stop = (_command_redaction_stop(text, views, events) if secret_tail else
                       _whole_word_stop(text, views, match, events, tail_candidates))
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
