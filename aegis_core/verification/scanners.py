"""Known-format secret detector, SARIF 2.1.0 ingest, and external scanner presets (v4.3 T7)."""
from __future__ import annotations

import collections
from contextlib import ExitStack
from dataclasses import dataclass, replace
import errno
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import posixpath
import re
import stat
from typing import Any, Callable, Iterable, Mapping, Sequence

from aegis_core import atomicio, gitsafe, pathlookup, primitives
from aegis_core.errors import PathTraversalError
from aegis_core.primitives import is_within
from aegis_core.redaction import (
    CANDIDATE_TOKEN_RE,
    MAX_LINE_LENGTH,
    TOKEN_REDACTIONS,
    is_high_entropy_secret,
    mask_secret,
    shannon_entropy,
)
from aegis_core.verification import test_runner

# Left edges. Each body starts with a distinctive literal, so only a letter or digit before it means
# "inside a longer run"; `_ - / +` are delimiters (deploy_ghp_..., clone URLs). Bodies that contain
# `_` or `-` also treat those as identifier characters, and the generic OpenAI `sk-` shape keeps the
# strict edge so kebab-case paths and branch names stay clean.
_B_PRE, _B_SUF = r"(?<![A-Za-z0-9])", r"(?![A-Za-z0-9+/=_-])"
_B_PRE_ID, _B_PRE_STRICT = r"(?<![A-Za-z0-9_-])", r"(?<![A-Za-z0-9+/_-])"

TIER_A_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws-access-key-id": re.compile(_B_PRE + r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}" + _B_SUF),
    "github-pat": re.compile(_B_PRE + r"gh[pousr]_[A-Za-z0-9]{36,255}" + _B_SUF),
    "github-fine-grained-pat": re.compile(_B_PRE_ID + r"github_pat_[A-Za-z0-9_]{22,255}" + _B_SUF),
    "slack-token": re.compile(_B_PRE_ID + r"xox[abprs]-[A-Za-z0-9-]{10,255}" + _B_SUF),
    "stripe-live-secret": re.compile(_B_PRE + r"[sr]k_live_[0-9A-Za-z]{24,99}" + _B_SUF),
    "anthropic-api-key": re.compile(_B_PRE_ID + r"sk-ant-[A-Za-z0-9_-]{20,255}" + _B_SUF),
    "openai-api-key": re.compile(_B_PRE_STRICT + r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,255}" + _B_SUF),
    "google-api-key": re.compile(_B_PRE_ID + r"AIza[0-9A-Za-z_-]{35}" + _B_SUF),
    "private-key-pem": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    "jwt-three-segment": re.compile(_B_PRE_ID + r"eyJ[A-Za-z0-9_-]{10,512}\.eyJ[A-Za-z0-9_-]{10,1024}\.[A-Za-z0-9_-]{10,512}" + _B_SUF),
    "url-basic-auth": re.compile(r"://([^/\s:@'\"$<>]{1,64}):([^/\s:@'\"$<>]{3,64})@[A-Za-z0-9.-]{1,253}"),
}

_TIER_B_RE = re.compile(r"""(?i)\b([A-Za-z0-9_.-]{0,32}(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|credential|auth[_-]?token|client[_-]?secret)[A-Za-z0-9_.-]{0,32})\s*[:=]\s*(['"])([^'"\s]{8,256})\2""")
_TIER_C_RE = re.compile(r"""(['"])([A-Za-z0-9+/=_-]{20,256})\1""")
_PLACEHOLDER_WORDS = ("example", "dummy", "test", "placeholder", "changeme", "fake", "redacted", "todo")
_PLACEHOLDER_SHAPES = r"your[_-]|x{3,}|\*{3,}|\.{3}|^<.*>$|^\$\{?.*\}?$|^%.*%$|^(?:true|false|null|none)$"
# Substring form for machine token bodies, where a prefix glues onto the placeholder (AKIA...EXAMPLE).
_PLACEHOLDER_RE = re.compile(r"(?i)(?:" + "|".join(_PLACEHOLDER_WORDS) + "|" + _PLACEHOLDER_SHAPES + ")")
_PLACEHOLDER_SHAPE_RE = re.compile(r"(?i)(?:" + _PLACEHOLDER_SHAPES + ")")
_WORD_SPLIT_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DATA_URL_OR_SRI_RE = re.compile(r"(?:data:[A-Za-z0-9/+.-]{1,64};base64,[A-Za-z0-9+/=]+|\bsha(?:1|256|384|512)-[A-Za-z0-9+/=]{16,})")
_HASH_FIELD_RE = re.compile(r"(?i)(?:^|[^a-z0-9])(?:sha1|sha256|sha384|sha512|md5|integrity|checksum|digest|hash|commit|oid|etag|fingerprint)(?:$|[^a-z0-9])")
_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/=]{32,}")
# Markers that silence a security finding: a noqa list naming an S (bandit) code, counted once per
# list; nosec; gitleaks:allow after #, // or /*. A plain noqa or a style code is not a security suppression.
_SUPPRESSION_RE = re.compile(r"#[\t ]*(?:noqa:[A-Za-z0-9\t ,]{0,200}?\bS[0-9]+|nosec\b)|(?:#|//|/\*)[\t ]*gitleaks:allow\b",
                             re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    """Normalized scanner or secret finding with masked snippet."""
    rule_id: str
    path: str
    line: int
    snippet: str
    tier: str = "gate"
    fingerprint: str = ""
    severity: str = "error"
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "tier": self.tier,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "message": self.message,
        }


def sarif_fingerprint(rule_id: str, rel_path: str, line_text: str) -> str:
    normalized = " ".join(line_text.split())
    return hashlib.sha256(f"{rule_id}|{rel_path}|{normalized}".encode("utf-8")).hexdigest()[:16]


def _is_placeholder_text(val: str) -> bool:
    """For human-chosen strings a placeholder word must start a word: ``testpass`` and ``Test_Pw``
    are placeholders, ``contest`` and ``latestGreat9`` are not."""
    return bool(_PLACEHOLDER_SHAPE_RE.search(val)) or any(w.lower().startswith(_PLACEHOLDER_WORDS) for w in _WORD_SPLIT_RE.findall(val))


def _is_benign_token(val: str, *, human_text: bool = False) -> bool:
    placeholder = _is_placeholder_text(val) if human_text else bool(_PLACEHOLDER_RE.search(val))
    return placeholder or bool(_UUID_RE.match(val) or _HEX_RE.match(val))


def _sweep_unreported_secrets(line: str) -> str:
    """Scrub secret-shaped values no scan pass reported, leaving the masks of reported ones intact."""
    for pat, text in TOKEN_REDACTIONS:
        line = pat.sub(text, line)
    return CANDIDATE_TOKEN_RE.sub(lambda m: "[REDACTED]" if is_high_entropy_secret(m.group(0), 4.0) else m.group(0), line)


def _pem_key_material(lines: list[str], index: int, end: int) -> str | None:
    """Base64 after a PEM header on its own line (a one-line string with escaped newlines), "" for a
    base64 line among the next 6 non-blank lines, else None: a bare header is not key material."""
    same = _PEM_BODY_RE.search(lines[index], end)
    if same:
        return same.group(0)
    window = itertools.islice(filter(None, (lines[i].strip() for i in range(index + 1, len(lines)))), 6)
    return "" if any(_PEM_BODY_RE.fullmatch(line) for line in window) else None


def scan_secrets_text(text: str, path: str = "<memory>", *, include_advisory: bool = False) -> list[Finding]:
    """Scan text for Tier A (blocking) and optionally Tier B/C (advisory) secrets."""
    findings: list[Finding] = []
    lines = text.splitlines()
    for lineno, raw_line in enumerate(lines, 1):
        cleaned = _DATA_URL_OR_SRI_RE.sub('""', raw_line)
        line_secrets: list[str] = []
        matched: list[tuple[str, str, str]] = []
        for rule_id, rx in TIER_A_PATTERNS.items():
            # The raw line: a known-format token is a secret whatever precedes it. Blanking data-URL
            # payloads only suppresses heuristic (advisory) false positives; the payload may be the token.
            for m in rx.finditer(raw_line):
                full, tier = m.group(0), "gate"
                if rule_id == "url-basic-auth":
                    user, pwd = m.group(1), m.group(2)
                    if _is_placeholder_text(user) or _is_placeholder_text(pwd) or "$" in user or "$" in pwd:
                        continue
                    line_secrets.extend([full, pwd])
                elif rule_id == "private-key-pem":
                    material = _pem_key_material(lines, lineno - 1, m.end())
                    if material is None and not include_advisory:
                        continue
                    tier = "gate" if material is not None else "advisory"
                    line_secrets.extend([full, material] if material else [full])
                elif _is_benign_token(full):
                    continue
                else:
                    line_secrets.append(full)
                matched.append((rule_id, tier, full))
        if not matched and not include_advisory:
            continue
        # Advisory values are masked in every snippet; include_advisory and the hash-field guard only
        # decide whether they are reported, so the snippet and its fingerprint do not depend on them.
        report_advisory = include_advisory and not _HASH_FIELD_RE.search(cleaned)
        extra_masks: list[str] = []
        for m in _TIER_B_RE.finditer(cleaned):
            key_name, val = m.group(1), m.group(3)
            if _is_benign_token(val, human_text=True):
                continue
            extra_masks.append(val)
            if report_advisory and not _HASH_FIELD_RE.search(key_name) and not any(val in s or s in val for s in line_secrets):
                line_secrets.append(val)
                matched.append(("generic-secret-assign", "advisory", val))
        for m in _TIER_C_RE.finditer(cleaned):
            val = m.group(2)
            if _is_benign_token(val) or shannon_entropy(val) < 4.5:
                continue
            extra_masks.append(val)
            if report_advisory and not any(val in s or s in val for s in line_secrets):
                line_secrets.append(val)
                matched.append(("high-entropy-token", "advisory", val))
        if not matched:
            continue
        # Lines of any length are scanned (every Tier A quantifier is bounded, so cost is linear);
        # above MAX_LINE_LENGTH the snippet is the masked token alone, never the surrounding line.
        masked_line = raw_line.strip() if len(raw_line) <= MAX_LINE_LENGTH else ""
        if masked_line:
            for sec in sorted({*line_secrets, *extra_masks}, key=len, reverse=True):
                masked_line = masked_line.replace(sec, mask_secret(sec))
            masked_line = _sweep_unreported_secrets(masked_line)
        for rule_id, tier, sec in matched:
            masked_tok = mask_secret(sec)
            snippet = masked_line if masked_tok in masked_line else masked_tok
            findings.append(Finding(
                rule_id,
                path,
                lineno,
                snippet,
                tier,
                sarif_fingerprint(rule_id, path, snippet),
                "error" if tier == "gate" else "warning",
                f"Detected {rule_id} ({tier})",
            ))
    return findings


def contains_secret_tier_a(text: str) -> bool:
    return bool(scan_secrets_text(text, include_advisory=False))


def scan_secrets_file(file_path: Path | str, *, repo_root: Path | str | None = None, include_advisory: bool = False) -> list[Finding]:
    p = Path(file_path)
    if not p.is_file() or p.is_symlink():
        return []
    try:
        raw = p.read_bytes()
    except OSError:
        return []
    if b"\0" in raw[:4096]:
        return []
    rel = p.as_posix()
    if repo_root is not None:
        try:
            rel = p.resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except ValueError:
            rel = p.as_posix()
    return scan_secrets_text(raw.decode("utf-8", "replace"), path=rel, include_advisory=include_advisory)


# After any comment opener of the languages scanned (#, //, /*), as gitleaks itself honours it.
_ALLOW_RE = re.compile(r"(?:#|//|/\*)[\t ]*gitleaks:allow\b", re.IGNORECASE)


def _secret_keys(text: str, path: str) -> list[tuple[Finding, tuple[str, str, int]]]:
    """Tier A findings of ``text`` not on a ``gitleaks:allow`` line (_ALLOW_RE), each with its key: the rule, the
    unmasked normalized line and that line's occurrence index (in memory only, never shown)."""
    lines = text.splitlines()  # scan_secrets_text numbers lines this way
    seen: collections.Counter = collections.Counter()
    occurrence = []
    for line in lines:
        norm = " ".join(line.split())
        occurrence.append(seen[norm])
        seen[norm] += 1
    return [(f, (f.rule_id, " ".join(lines[f.line - 1].split()), occurrence[f.line - 1]))
            for f in scan_secrets_text(text, path) if not _ALLOW_RE.search(lines[f.line - 1])]


def scan_secrets_delta(workspace_root: Path | str, files: Iterable[str], base_sources: Mapping[str, str | None],
                       contents: Mapping[str, bytes] | None = None) -> list[Finding]:
    """The Tier A findings of ``files`` (relative to ``workspace_root``; ``contents`` holds the bytes of
    those not read from it) that the text ``base_sources`` holds for each did not already hold, as a
    multiset: a touched legacy line does not block, a copied or rotated secret does. A
    ``# gitleaks:allow`` line is not judged (suppression_count reports it)."""
    root = Path(workspace_root)
    out: list[Finding] = []
    for rel in files:
        path = root.joinpath(*rel.split("/"))
        try:
            if contents is not None and rel in contents:
                raw = contents[rel]
            else:
                raw = b"" if path.is_symlink() or not path.is_file() else path.read_bytes()
        except OSError:
            continue
        if not raw or b"\0" in raw[:4096]:
            continue
        head = _secret_keys(raw.decode("utf-8", "replace"), rel)
        pool = collections.Counter(key for _f, key in _secret_keys(base_sources.get(rel) or "", rel)) if head else {}
        for finding, key in head:
            if pool.get(key, 0) > 0:
                pool[key] -= 1
            else:
                out.append(finding)
    return out


def _count_suppressions(rel: str, data: bytes) -> int:
    if b"\0" in data[:4096]:
        return 0
    text = data.decode("utf-8", "replace")
    if rel == ".gitleaksignore":
        return sum(1 for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
    return len(_SUPPRESSION_RE.findall(text))


def _count_repo_suppressions(root: Path, files: Iterable[str]) -> int:
    count = 0
    for rel in files:
        path = root.joinpath(*rel.split("/"))
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1 << 20:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        count += _count_suppressions(rel, data)
    return count


def _tracked_regular_files(root: Path) -> list[str]:
    """Index modes, including where core.symlinks=false materializes links as files."""
    try:
        result = gitsafe.run(["ls-files", "-s", "-z"], root)
    except gitsafe.GitError:
        return []
    if result.returncode:
        return []
    modes: dict[str, set[bytes]] = {}
    for record in result.stdout.split(b"\0"):
        meta, sep, name = record.partition(b"\t")
        parts = meta.split()
        if sep and len(parts) == 3:
            modes.setdefault(os.fsdecode(name), set()).add(parts[0])
    # Unmerged stages may repeat a path; count it once only if every mode is regular.
    return [name for name, kinds in modes.items() if kinds <= {b"100644", b"100755"}]


def suppression_count(root: Path | str, merge_base: str | None) -> dict[str, Any]:
    """Security suppressions in tracked regular files under ``root``, skipping binaries and files
    over 1 MiB: ``{"count", "delta"}``, against ``merge_base`` (None when its blobs cannot be read).
    A signal; it never blocks. HEAD uses index modes and BASE uses the tree's inventory, so
    symlink target text is never counted and deleted HEAD paths still contribute to BASE."""
    root = Path(root).resolve()
    head = _count_repo_suppressions(root, _tracked_regular_files(root))
    try:
        prefix = gitsafe.show_prefix(root)
        entries = gitsafe.tree_blobs(root, merge_base or "")
        files = {rel: oid for path, (_mode, oid) in entries.items()
                 for rel in [gitsafe.relative_to_prefix(prefix, path)] if rel is not None}
        sizes = gitsafe.blob_sizes(root, files.values())
        blobs = gitsafe.read_blobs(root, (oid for oid in files.values() if sizes[oid] <= 1 << 20))
    except gitsafe.GitError:
        return {"count": head, "delta": None}
    base = sum(_count_suppressions(rel, blobs[oid]) for rel, oid in files.items() if oid in blobs)
    return {"count": head, "delta": head - base}


def _sarif_artifact(uri: str, root: Path | None) -> tuple[str, Path | None]:
    """(repo-relative label, file safe to read) for a SARIF artifact URI. The URI is scanner output
    about untrusted code (``a/../../x``, an absolute path, a symlink out): only a real location
    inside ``root`` is readable; otherwise the label keeps no traversal segment and nothing is read."""
    uri = uri[7:] if uri.startswith("file://") else uri
    label = "/".join(s for s in posixpath.normpath(Path(uri).as_posix()).split("/") if s not in ("", ".", "..")) if uri else ""
    if root is None or not uri:
        return label, None
    try:
        real = Path(os.path.realpath(Path(uri) if Path(uri).is_absolute() else root / uri))
        return real.relative_to(root).as_posix(), real
    except (OSError, ValueError):  # outside the tree, a NUL byte, ELOOP, ENAMETOOLONG
        return label, None


def _mask_tier_a(text: str) -> str:
    for rx in TIER_A_PATTERNS.values():
        text = rx.sub(lambda m: mask_secret(m.group(0)), text)
    return text


class _SarifError(ValueError):
    """A SARIF document that cannot be understood; the message names a location, never content."""


def _sarif_unverified(reason: str) -> dict[str, Any]:
    return {"status": "unverified", "reason": reason[:200], "findings": []}


def _sarif_obj(value: Any, where: str) -> Mapping[str, Any]:
    if value and not isinstance(value, Mapping):
        raise _SarifError(f"{where} must be an object")
    return value or {}


def _sarif_arr(value: Any, where: str) -> Sequence[Any]:
    if value and not isinstance(value, list):
        raise _SarifError(f"{where} must be an array")
    return value or ()


_SARIF_LINE_CACHE_BYTES = 8 * 1024 * 1024


def _sarif_descriptor_reads_supported() -> bool:
    return (os.name != "nt" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd)


def _sarif_directory_flags() -> int:
    return getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _sarif_open_artifact(path: Path, root: Path, root_fd: int) -> int:
    """Open the resolved, confined artifact without following any replacement symlink."""
    parts = path.relative_to(root).parts
    if not parts:
        raise ValueError("artifact must name a file")
    flags = _sarif_directory_flags()
    with ExitStack() as leaf_owner:
        directory = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, flags, dir_fd=directory)
                parent, directory = directory, child
                os.close(parent)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
            leaf_owner.callback(os.close, fd)
        finally:
            os.close(directory)
        # Transfer only after the directory descriptor has closed successfully.
        leaf_owner.pop_all()
        return fd


def _sarif_open_by_path(path: Path, root: Path) -> int:
    """Compatibility read using the shared regular-file opener and identity checks.

    Search-only directory permissions and hosts without openat keep disk snippets. Check
    ancestors before and after opening, and compare the leaf to the opened descriptor.
    """
    parts = path.relative_to(root).parts
    if not parts:
        raise ValueError("artifact must name a file")
    ancestors = []
    directory = root
    for part in (*parts[:-1], None):
        info = os.lstat(directory)
        if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            raise ValueError("artifact ancestor is not a plain directory")
        ancestors.append((directory, (info.st_dev, info.st_ino)))
        if part is not None:
            directory = directory / part
    expected = os.lstat(path)
    fd = atomicio.open_regular(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("artifact changed while opening")
        for directory, identity in ancestors:
            current = os.lstat(directory)
            if (not stat.S_ISDIR(current.st_mode)
                    or (current.st_dev, current.st_ino) != identity
                    or getattr(current, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                raise ValueError("artifact ancestor changed while opening")
        current = os.lstat(path)
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("artifact changed while opening")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _sarif_stream_lines(source: Any, requests: dict[int, list[int]]) -> Iterable[tuple[list[int], str]]:
    """One source pass, retaining only a requested line and a bounded splitlines chunk."""
    current = 1
    selected: list[str] = []
    # Cover decoded characters, split strings and list slots before allocating the chunk.
    chunk_size = max(1, min(64 * 1024, _SARIF_LINE_CACHE_BYTES // 128))
    # Universal newline decoding handles CRLF even across read boundaries. splitlines adds
    # the other Python line separators; a chunk's unfinished final part keeps its number.
    with io.TextIOWrapper(source, encoding="utf-8", errors="replace", newline=None) as text:
        while True:
            chunk = text.read(chunk_size)
            if not chunk:
                if selected and current in requests:
                    yield requests.pop(current), "".join(selected)
                return
            for part in chunk.splitlines(keepends=True):
                ends = part[-1] in "\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"
                if current in requests:
                    selected.append(part[:-1] if ends else part)
                    if ends:
                        yield requests.pop(current), "".join(selected)
                        selected.clear()
                if ends:
                    current += 1


class _SarifLineCache:
    """Batch references by resolved artifact; each requested line feeds all its findings once.

    Reference indexes scale with the existing findings, not source size. Only a bounded chunk
    and the requested output line are decoded at a time; no complete source line list survives.
    """

    def __init__(self, root: Path | None) -> None:
        self.root = root
        self.requests: dict[Path, dict[int, list[int]]] = {}

    def request(self, path: Path, number: int, index: int) -> None:
        self.requests.setdefault(path, {}).setdefault(number, []).append(index)

    def fill(self, findings: list[Finding]) -> None:
        if not self.requests or self.root is None:
            return
        with ExitStack() as root_owner:
            root_fd = None
            if _sarif_descriptor_reads_supported():
                try:
                    root_fd = os.open(self.root, _sarif_directory_flags())
                    root_owner.callback(os.close, root_fd)
                except OSError as error:
                    if error.errno != errno.EACCES:
                        return
            for path, requests in self.requests.items():
                updates: list[tuple[int, Finding]] = []
                try:
                    with ExitStack() as artifact_owner:
                        if root_fd is None:
                            fd = _sarif_open_by_path(path, self.root)
                        else:
                            try:
                                fd = _sarif_open_artifact(path, self.root, root_fd)
                            except OSError as error:
                                if error.errno != errno.EACCES:
                                    raise
                                fd = _sarif_open_by_path(path, self.root)
                        artifact_owner.callback(os.close, fd)
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            continue
                        # The raw descriptor stays owned even if fdopen rejects it before a
                        # stream exists. Stream/decoder closure must not close it a second time.
                        with os.fdopen(fd, "rb", closefd=False) as source:
                            for indexes, line in _sarif_stream_lines(source, requests):
                                normalized = " ".join(line.split())
                                masked = _mask_tier_a(normalized)
                                for index in indexes:
                                    finding = findings[index]
                                    updates.append((index, replace(finding, snippet=masked, fingerprint=sarif_fingerprint(
                                        finding.rule_id, finding.path, normalized))))
                except (OSError, ValueError, PathTraversalError):
                    continue
                # Like the original whole-file read, a later I/O error discards this artifact's
                # disk snippets. Do not publish partial results from an incomplete source pass.
                for index, finding in updates:
                    findings[index] = finding


def ingest_sarif(
    doc: Mapping[str, Any],
    *,
    workspace_root: Path | str | None = None,
) -> dict[str, Any]:
    """Ingest a parsed SARIF 2.1.0 document: findings, fingerprints, suppressions. Scanner output is
    untrusted: a document that is not understood is ``unverified``, never raised."""
    root_path = Path(workspace_root).resolve() if workspace_root else None
    line_cache = _SarifLineCache(root_path)
    all_findings: list[Finding] = []
    sarif_supps = 0
    try:
        if not isinstance(doc, Mapping) or "runs" not in doc:
            raise _SarifError("the document has no runs array")
        for ri, run in enumerate(_sarif_arr(doc["runs"], "runs")):
            for xi, res in enumerate(_sarif_arr(_sarif_obj(run, f"runs[{ri}]").get("results"), f"runs[{ri}].results")):
                at = f"runs[{ri}].results[{xi}]"
                res = _sarif_obj(res, at)
                sarif_supps += len(_sarif_arr(res.get("suppressions"), f"{at}.suppressions"))
                rule_id = str(res.get("ruleId") or "unknown")
                level = str(res.get("level") or "warning").lower()
                msg = str(_sarif_obj(res.get("message"), f"{at}.message").get("text") or "")
                locs = _sarif_arr(res.get("locations"), f"{at}.locations")
                phys = _sarif_obj(_sarif_obj(locs[0] if locs else None, f"{at}.locations[0]").get("physicalLocation"), f"{at}.physicalLocation")
                uri = str(_sarif_obj(phys.get("artifactLocation"), f"{at}.artifactLocation").get("uri") or "")
                rel_path, readable = _sarif_artifact(uri, root_path)
                region = _sarif_obj(phys.get("region"), f"{at}.region")
                line_no = region.get("startLine") or 0
                if not isinstance(line_no, int):
                    raise _SarifError(f"{at}.region.startLine must be an integer")
                snippet_raw = _sarif_obj(region.get("snippet"), f"{at}.region.snippet").get("text")
                if snippet_raw is None and readable is not None and line_no > 0:
                    line_cache.request(readable, line_no, len(all_findings))
                norm_line = " ".join(str(snippet_raw if snippet_raw is not None else msg).split())
                fp = sarif_fingerprint(rule_id, rel_path, norm_line)  # over the raw line; only the masked one is shown
                all_findings.append(Finding(rule_id, rel_path, line_no, _mask_tier_a(norm_line), "gate", fp,
                                            "error" if level == "error" else "warning", _mask_tier_a(msg)))
    except _SarifError as exc:
        return _sarif_unverified(f"SARIF is malformed: {exc}")
    line_cache.fill(all_findings)
    return {
        "status": "fail" if all_findings else "pass",
        "findings": all_findings,
        "total_raw": len(all_findings),
        "suppression_count": sarif_supps,
    }


class UntrustedScannerConfig(ValueError):
    """A preset would read a scanner config the repository controls."""


#: The presets ``check --ci`` runs for the user-scope ``scanners`` key; the target directory goes last.
PRESET_ARGV: dict[str, tuple[str, ...]] = {
    "ruff": ("ruff", "check", "--isolated", "--select", "S", "--ignore", "S603,S607", "--output-format", "sarif"),
    "gitleaks": ("gitleaks", "detect", "--no-git", "--redact", "--report-format", "sarif", "--report-path", "-",
                 "--source"),
}


def _preset_argv(preset: str, target: Path) -> list[str]:
    argv = [*PRESET_ARGV[preset], str(target)]
    if preset == "gitleaks":
        from aegis_core.workspace.layout import UserLayout

        ul = UserLayout.current()
        user_dir = ul.aegis_dir.resolve() if ul else None
        if user_dir is not None and not is_within(user_dir, target, unresolvable=True):
            cand = (user_dir / "gitleaks.toml").resolve()
            if is_within(cand, user_dir, unresolvable=False) and not is_within(cand, target, unresolvable=True) \
                    and cand.is_file():
                argv.extend(["--config", str(cand)])
        # Without --config gitleaks reads <source>/.gitleaks.toml: a repository allowlist would
        # silence the scan. lexists, so a dangling link or a case-folded name counts too.
        if "--config" not in argv and os.path.lexists(target / ".gitleaks.toml"):
            raise UntrustedScannerConfig("the repository has its own .gitleaks.toml; set ~/.aegis/gitleaks.toml to scan it")
    return argv


def _run_found_program(argv: Sequence[str], cwd: Path | str, env: Mapping[str, str] | None = None, timeout: int | float = 60,
                       outside: Path | str | None = None) -> dict[str, Any]:
    """``run_external_cmd`` on the ``argv[0]`` found in an absolute PATH entry outside ``outside`` (the
    workspace; default ``cwd``): an empty or relative entry would find a program the repository
    planted, and its silence would read as a clean scan."""
    exe = pathlookup.which(str(argv[0]), outside=outside or cwd)
    if exe is None:
        return {"returncode": 127, "stdout": "", "stderr": f"{argv[0]} not found in an absolute PATH entry outside the workspace",
                "missing_binary": True, "timed_out": False, "duration_s": 0.0}
    return test_runner.run_external_cmd([exe, *argv[1:]], cwd=cwd, env=env, timeout=timeout)


def _scan_once(preset: str, target: Path, runner: Callable[..., dict[str, Any]], timeout: int) -> dict[str, Any]:
    """One preset run over ``target``: ingest_sarif's report, or ``unverified``."""
    try:
        argv = _preset_argv(preset, target)
    except UntrustedScannerConfig as exc:
        return _sarif_unverified(str(exc))
    res = runner(argv, cwd=target, timeout=timeout)
    if res.get("missing_binary") or res.get("timed_out"):
        return _sarif_unverified(res.get("stderr") or (f"{argv[0]} timed out" if res.get("timed_out") else f"{argv[0]} not found"))
    # pass needs positive evidence: a SARIF run on stdout and an exit code its findings explain.
    stdout, stderr = str(res.get("stdout") or "").strip(), str(res.get("stderr") or "").strip()
    try:
        doc = json.loads(stdout) if stdout else None
    except (ValueError, RecursionError):
        doc = None
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if not (isinstance(runs, list) and runs and all(isinstance(run, dict) for run in runs)):
        why = "produced no SARIF output" if not stdout else "printed output that is not a SARIF run"
        return _sarif_unverified(stderr or f"{argv[0]} {why}")
    report = ingest_sarif(doc, workspace_root=target)
    rc = res.get("returncode")
    # Judged on the raw findings: a crash after reporting what the base also holds is not a clean scan.
    report["unexplained"] = "" if rc == 0 or (rc == 1 and report["total_raw"] > 0) else \
        stderr or f"{argv[0]} exited {rc} without findings to explain it"
    if report["status"] == "pass" and report["unexplained"]:
        return _sarif_unverified(report["unexplained"])
    return report


def _line_keys(findings: Sequence[Finding], root: Path) -> list[str]:
    """One key per finding: the baseline fingerprint over the unmasked, normalized line it names and that
    line's occurrence index, so a rotated secret under the same mask is new and a moved line is not.
    The keys stay in memory; only masked snippets are ever shown."""
    keys, texts = [], {}  # type: list[str], dict[str, list[str]]
    for f in findings:
        if f.path not in texts:
            real = Path(os.path.realpath(root / f.path))
            try:
                readable = bool(f.path) and is_within(real, root, unresolvable=False) and real.is_file() \
                    and real.stat().st_size <= 1 << 20
                texts[f.path] = primitives.split_lines(real.read_bytes().decode("utf-8", "replace")) if readable else []
            except OSError:
                texts[f.path] = []
        lines = texts[f.path]
        text = lines[f.line - 1] if 1 <= f.line <= len(lines) else f.snippet
        keys.append(primitives.fingerprint(f.rule_id, f.path, primitives.normalize_text(text),
                                           primitives.occurrence_index(lines, f.line)))
    return keys


def run_preset(
    name: str,
    root: Path | str,
    merge_base: str | None,
    *,
    timeout: int = 60,
    runner: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run preset ``name`` on the work tree at ``root`` and, when that finds anything, on an export of
    ``merge_base``: ``fail`` only for findings the base does not hold (a multiset), ``unverified`` when
    either scan cannot be completed or understood. Never raises for scanner output."""
    import tempfile

    if name not in PRESET_ARGV:
        raise ValueError(f"Unsupported scanner preset: {name!r}")
    head_root = Path(root).resolve()
    run = runner or (lambda argv, cwd, timeout: _run_found_program(argv, cwd, timeout=timeout, outside=head_root))
    head = _scan_once(name, head_root, run, timeout)
    result: dict[str, Any] = {"name": name, "status": head["status"], "findings": [], "subtracted": 0}
    if head["status"] == "unverified":
        return {**result, "reason": head["reason"]}
    if not head["findings"]:
        return result
    with tempfile.TemporaryDirectory(prefix="aegis-scan-base-") as tmp:
        export = Path(tmp).resolve() / "base"
        try:
            prefix = gitsafe.show_prefix(head_root)  # the export holds the whole repository
            gitsafe.export_tree(head_root, merge_base or "", export)
        except gitsafe.GitError:
            return {**result, "status": "unverified", "reason": "the merge base cannot be exported"}
        base_root = export.joinpath(*prefix.strip("/").split("/")) if prefix else export
        base = _scan_once(name, base_root, run, timeout) if base_root.is_dir() else {"status": "pass", "findings": []}
        if base["status"] == "unverified":
            return {**result, "status": "unverified", "reason": f"the merge-base scan: {base['reason']}"}
        pool = collections.Counter(_line_keys(base["findings"], base_root))
    new = []
    for finding, key in zip(head["findings"], _line_keys(head["findings"], head_root)):
        if pool[key] > 0:
            pool[key] -= 1
        else:
            new.append(finding)
    if not new and head["unexplained"]:
        return {**result, "status": "unverified", "reason": head["unexplained"]}
    return {**result, "status": "fail" if new else "pass", "findings": new, "subtracted": len(head["findings"]) - len(new)}
