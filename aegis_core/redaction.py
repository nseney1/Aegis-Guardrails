"""The one secret-redaction table and its entry points (L0: the standard library only).

Every text Aegis persists or echoes goes through this table: the hook command log
(``redact_command_secrets``, through aegis_cli.hooks.redaction), stored insight text
(``redact_insight_text``) and the snippet of a secret finding (aegis_core.verification.scanners
masks with ``TOKEN_REDACTIONS`` and ``is_high_entropy_secret``).
"""
from __future__ import annotations

import collections
import math
import re

__all__ = [
    "CANDIDATE_TOKEN_RE",
    "MAX_EXCERPT_CHARS",
    "MAX_LINE_LENGTH",
    "SECRET_REPLACEMENTS",
    "TOKEN_REDACTIONS",
    "is_high_entropy_secret",
    "mask_secret",
    "redact_command_secrets",
    "redact_insight_text",
    "shannon_entropy",
]

# The longest text handled whole: redact_insight_text keeps a whole-word head of a longer one
# (at least this many characters), and a scanner finding on a longer line shows the masked token alone.
MAX_LINE_LENGTH = 4096
MAX_EXCERPT_CHARS = 300

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
#: The hook-log form of the table: (pattern, replacement), applied in order.
SECRET_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [(p, hook) for p, hook, _ in _SECRET_REDACTIONS]
#: Personal data, scrubbed from stored insights only: the hook log keeps paths and addresses.
_PII_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}(?![A-Za-z0-9])"),
     "[REDACTED_EMAIL]"),
    (re.compile(r"(?<=/home/)[^/\s]{1,255}|(?<=/Users/)[^/\s]{1,255}|(?<=C:\\Users\\)[^\\\s]{1,255}"), "~user"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
)
_TEXT_REDACTIONS = tuple((p, text) for p, _, text in _SECRET_REDACTIONS) + _PII_REDACTIONS
# The single-token rows, safe over a snippet that already carries masks: PEM spans lines, and the URL
# userinfo and keyed rows (the ones with a backreference) rewrite whatever follows, masks included.
TOKEN_REDACTIONS = tuple((p, text) for p, _, text in _SECRET_REDACTIONS if "\\1" not in text and text != "[REDACTED_PEM]")
_HEX_UUID_RE = re.compile(r"^(?:[0-9a-fA-F]{7,64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
CANDIDATE_TOKEN_RE = re.compile(r"[A-Za-z0-9+_=-]{20,}")


def mask_secret(secret: str) -> str:
    if len(secret) <= 6:
        return f"{secret[:2]}..." if len(secret) > 2 else "***"
    return f"{secret[:4]}...{secret[-2:]}"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_high_entropy_secret(tok: str, threshold: float = 3.8) -> bool:
    if "REDACTED" in tok or _HEX_UUID_RE.match(tok) or not any(c.isdigit() for c in tok):
        return False
    classes = int(any(c.islower() for c in tok)) + int(any(c.isupper() for c in tok)) + 1
    if classes < 2:
        return False
    return shannon_entropy(tok) >= threshold


def redact_command_secrets(cmd: str) -> str:
    """Mask known secret patterns in command strings before logging."""
    for pattern, replacement in SECRET_REPLACEMENTS:
        cmd = pattern.sub(replacement, cmd)
    return cmd


def _bounded_head(text: str, limit: int) -> str:
    """The whole words of ``text`` up to about ``limit`` characters. A secret cut in half
    would no longer match its pattern, so a word the cut splits is dropped, as is a trailing
    PEM header whose END lies past the cut."""
    raw = text[: limit + 1]
    words = raw.split()
    if words and not raw[-1].isspace():
        words.pop()
    head = " ".join(words)
    begin = head.rfind("-----BEGIN")
    # Drop the trailing incomplete block before redaction; only a whole END marker closes it.
    # The join turned newlines into single spaces.
    return head[:begin].rstrip() if begin != -1 and not re.search(_PEM_TAIL, head[begin:]) else head


def redact_insight_text(text: str, max_len: int = MAX_EXCERPT_CHARS) -> str:
    """Scrub secrets, PII, paths, IPs, and high-entropy tokens from insight text; past
    ``max(MAX_LINE_LENGTH, 4 * max_len)`` characters only a whole-word head is kept."""
    if not isinstance(text, str) or not text:
        return ""
    limit = max(MAX_LINE_LENGTH, 4 * max_len)
    out = text if len(text) <= limit else _bounded_head(text, limit)
    for pat, repl in _TEXT_REDACTIONS:
        out = pat.sub(repl, out)
    out = CANDIDATE_TOKEN_RE.sub(
        lambda m: "[REDACTED_HIENT]" if is_high_entropy_secret(m.group(0)) else m.group(0),
        out,
    )
    out = " ".join(out.split())
    if max_len > 0 and len(out) > max_len:
        sliced = out[:max_len]
        last_open = sliced.rfind("[REDACTED")
        if last_open != -1 and "]" not in sliced[last_open:]:
            out = sliced[:last_open].rstrip()
        else:
            out = sliced
    return out
