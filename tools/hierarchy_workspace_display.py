"""Raw-value screening and refusal-display helpers for the workspace controller."""
from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import re

if __package__:
    from .hierarchy_mailbox import SLUG
else:
    from hierarchy_mailbox import SLUG


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


class _Refusal(ValueError):
    """A validation refusal whose diagnostic has crossed the display boundary."""

    def __init__(self, message, *, displayed=False):
        self.message = message if displayed else _display(message)
        super().__init__(self.message)


def require(condition, message):
    """Local refusals already display request values at their individual sites.

    Preserve validated ids and fixed diagnostic text when crossing the CLI
    boundary, rather than redacting the entire assembled diagnostic again.
    """
    if not condition:
        raise _Refusal(message, displayed=True)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error path prints rejected values before exiting.
        # Let main's fixed refusal handle usage errors without rendering them.
        raise ValueError("invalid workspace arguments")


def _display_refusals(function, *, trusted_values=False, value_prefixes=()):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except _Refusal:
            raise
        except (ValueError, OSError, TypeError, UnicodeError, RecursionError) as exc:
            # These pinned validators own their diagnostic templates. Preserve
            # their fixed text and display only the raw value slot, once.
            if trusted_values and isinstance(exc, ValueError) and not isinstance(exc, UnicodeError):
                message = str(exc)
                for prefix in value_prefixes:
                    if message.startswith(prefix):
                        message = prefix + _display(message[len(prefix):])
                        break
                raise _Refusal(message, displayed=True) from exc
            raise _Refusal(exc) from exc
    return checked


_UNTRUSTED_DISPLAY_FIELDS = frozenset(("lane", "owner", "paths", "checkout", "error", "unreadable",
                                       "holder", "reference", "source", "reserved_paths"))


def _display_fields(value, field=None):
    """Display request/lease text without rewriting validated ids or enum states."""
    if isinstance(value, dict):
        return {key: _display_fields(item, key) for key, item in value.items()}
    if isinstance(value, list):
        return [_display_fields(item, field) for item in value]
    if isinstance(value, str) and field in ("initiative", "assigned_to", "blocked_by", "declared_overlaps"):
        # Blocker strings are not SLUG-checked by validate_lists. Preserve valid
        # identifiers, but do not grant arbitrary request text that exemption.
        return value if SLUG.fullmatch(value) else _display(value)
    if isinstance(value, str) and field == "request_id":
        # Old event reducers do not validate the request id's format on replay.
        return value if re.fullmatch(r"req-[0-9]{8}", value) else _display(value)
    if isinstance(value, str) and field in _UNTRUSTED_DISPLAY_FIELDS:
        return _display(value)
    return value


def _display_response(function):
    @wraps(function)
    def checked(*args, **kwargs):
        code, result = function(*args, **kwargs)
        return code, _display_fields(result) if code else result
    return checked


