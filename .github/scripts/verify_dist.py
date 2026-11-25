"""Record or verify SHA-256 digests of the release distributions in dist/.

    python verify_dist.py record dist   # after the single build
    python verify_dist.py verify dist   # before testing and before publishing

`record` requires exactly one wheel and one sdist and writes dist/SHA256SUMS.
`verify` fails if any file is missing, altered, or unlisted, so the files that
are tested are byte-for-byte the files that are published. It prints the
verified file paths, one per line, for the caller to use.
"""
from bisect import insort
import hashlib
import json
import os
from email.parser import BytesParser
from pathlib import PurePosixPath
import re
import stat
import sys
import tarfile
from typing import NamedTuple, Optional
import unicodedata
import zipfile

SUMS = "SHA256SUMS"
PACKAGES = {"aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"}
TEMPLATE_PREFIX = "aegis_core/ast/drivers/templates/"
# Native JS/TS and Rust ship as Python modules; only Go needs packaged assets.
TEMPLATES = {TEMPLATE_PREFIX + name for name in (
    "__init__.py", "go_ast.go", "go.mod")}
ASSETS = {"aegis_sdk/py.typed", "aegis_core/benchmark_corpus/corpus.json",
          "aegis_core/benchmark_corpus/ast.json", "aegis_core/manager_starter.json"}
ASSETS.update("aegis_core/_data/rules/" + name for name in (
    "__init__.py", "META.md", "cost-optimization.md", "destructive-ops.md", "no-eval.md",
    "providence.md", "subagent-delegation.md", ".oracles/architectural-tenets.md",
    ".oracles/atomic-workstream-protocol.md", ".oracles/documentation.md", ".oracles/feature-specs.md",
    ".oracles/git-workflow.md", ".oracles/polyglot-standards.md", ".oracles/tdd-protocol.md",
    ".oracles/testing.md"))
ASSETS.add("aegis_core/_data/skills/__init__.py")
ASSETS.update("aegis_core/_data/skills/" + name + "/SKILL.md" for name in (
    "adaptive-reviewer", "domain-researcher", "genesis", "governance-auditor", "incident-debug",
    "performance-audit", "post-mortem", "readme-writer", "refactoring-pilot", "security-audit",
    "session-monitor", "session-preflight", "spec-synthesizer", "staff-review", "visual-analyst"))
DIST_INFO = {"METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD",
             "LICENSE", "NOTICE", "licenses/LICENSE", "licenses/NOTICE"}
FORBIDDEN_DIRS = {"node_modules", "vendor", "third_party", "__pycache__"}
FORBIDDEN_SUFFIXES = {".so", ".pyd", ".dll", ".dylib", ".wasm", ".node", ".jar",
                      ".exe", ".pyc", ".pyo"}
# Bounded pattern for packaged team templates. Suffixes are the ones the
# package ships (.py, .json) and the markdown roles the later template items
# add. A new suffix fails the checkout build parity test until this set grows.
TEAM_TEMPLATES_PREFIX = "aegis_core/team_templates/"
TEAM_TEMPLATE_SUFFIXES = {".json", ".md", ".py"}
NAME_LIMIT = 4096
ZIP_EXTRA_LIMIT = 65535
METADATA_LIMIT = 1 << 20
TEXT_LIMIT = 240
DIST_SAMPLE_LIMIT = 5
_WIN_FILE_NOT_FOUND = 2
_WIN_PATH_NOT_FOUND = 3
LINE_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029\x00"
_SECRET_RE = re.compile(
    "(?i)(?<![A-Za-z0-9])"
    "(?:api[_-]?key|secret|token|password|passwd|authorization)"
    "\\s*[:=]\\s*\\S{20,}")
# One portable component grammar, sized to the real wheel and sdist: every
# measured member is ASCII from this set. An NFKC-stable letter stays so a
# composed non-ASCII letter still passes the same rule.
_PORTABLE_ASCII = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-")
_DEVICE_STEMS = frozenset(("con", "nul", "aux", "prn"))
_DEVICE_NUMBERED = re.compile(r"com[1-9]|lpt[1-9]")
# One table. It drives the canonical-spelling refusal and the case-folded
# location match. Package roots and forbidden directories stay single
# components so they cannot drift from PACKAGES and FORBIDDEN_DIRS.
_TEMPLATE_LOCATION = TEMPLATE_PREFIX.rstrip("/")
_TEAM_TEMPLATES_LOCATION = TEAM_TEMPLATES_PREFIX.rstrip("/")
_DATA_LOCATION = "aegis_core/_data"
_PROTECTED_PREFIXES = (
    _TEMPLATE_LOCATION,
    _TEAM_TEMPLATES_LOCATION,
    _DATA_LOCATION,
) + tuple(sorted(PACKAGES)) + tuple(sorted(FORBIDDEN_DIRS))


def _fold_part(part):
    return unicodedata.normalize("NFC", part).casefold()


def _canonical_components(prefixes):
    """Every component of the one prefix table, one spelling each."""
    mapping = {}
    for prefix in prefixes:
        for part in prefix.split("/"):
            folded = _fold_part(part)
            previous = mapping.get(folded)
            if previous is not None and previous != part:
                raise RuntimeError("protected prefix component spellings disagree")
            mapping[folded] = part
    return mapping


_CANONICAL_COMPONENT = _canonical_components(_PROTECTED_PREFIXES)
# A package root is a spelling constraint, not a location that hides children.
_LOCATION_FOLDED = tuple(
    (prefix, _fold_part(prefix) + "/") for prefix in _PROTECTED_PREFIXES if "/" in prefix)


def _matched_location(folded_logical):
    """Longest multi-component protected prefix that contains logical as a child."""
    best = None
    best_len = -1
    for prefix, folded_prefix in _LOCATION_FOLDED:
        if len(folded_prefix) > best_len and folded_logical.startswith(folded_prefix):
            best = prefix
            best_len = len(folded_prefix)
    return best


def _portable_component(part, folded):
    """True when one component matches the portable allowlist."""
    if not part or part in (".", "..") or part.endswith("."):
        return False
    for char in part:
        if char in _PORTABLE_ASCII:
            continue
        if (unicodedata.category(char).startswith("L") and
                unicodedata.normalize("NFKC", char) == char):
            continue
        return False
    stem = folded.split(".", 1)[0]
    if stem in _DEVICE_STEMS or _DEVICE_NUMBERED.fullmatch(stem):
        return False
    return True


def _canonical_component(part, folded):
    """Protected prefix components compare NFC plus casefold. Only one spelling passes."""
    canonical = _CANONICAL_COMPONENT.get(folded)
    return canonical is None or part == canonical


class _Component(NamedTuple):
    spelling: str
    kind: str
    explicit: bool
    children: Optional[dict]


def _stage_components(parts, folded_parts, leaf_kind, children):
    """Decide each component once. The caller applies changes after admission."""
    changes = []
    leaf_offset = len(parts) - 1
    for offset, (part, folded) in enumerate(zip(parts, folded_parts)):
        leaf = offset == leaf_offset
        kind = leaf_kind if leaf else "directory"
        explicit = leaf and kind == "directory"
        slot = children.get(folded)
        if slot is None:
            # An explicit directory needs a descendant that already implied it.
            if leaf_kind == "directory":
                return "absent", None, ()
            slot = _Component(part, kind, explicit, {} if kind == "directory" else None)
            changes.append((children, folded, slot))
        elif slot.spelling != part or slot.kind != kind:
            return "duplicate", (offset, slot.spelling, kind, slot.kind), ()
        elif kind == "file" or (explicit and slot.explicit):
            return "duplicate", None, ()
        elif explicit:
            changes.append((children, folded, slot._replace(explicit=True)))
        children = slot.children
    return "ok", None, changes


def _explicit_directories_have_descendants(state):
    """Every explicit directory component has an admitted child."""
    pending = [state["components"]]
    while pending:
        for slot in pending.pop().values():
            if slot.children:
                pending.append(slot.children)
            elif slot.explicit:
                return False
    return True


def _refuse_orphan_directories(archive_kind, state):
    """A directory entry with no admitted descendant is refused."""
    if _explicit_directories_have_descendants(state):
        return
    fail("unexpected " + archive_kind + " member: directory")


def _bounded_digest(value):
    """Hash a bounded prefix. Do not encode an unbounded untrusted string."""
    if not isinstance(value, str):
        return "member-sha256=unavailable"
    sample = value[:NAME_LIMIT]
    try:
        raw = sample.encode("utf-8", "surrogatepass")
    except UnicodeError:
        return "member-sha256=unavailable"
    return "member-sha256=" + hashlib.sha256(raw).hexdigest()[:16]


def _screen_text(value):
    """Canonicalize and redact the entire bounded value before display."""
    if not isinstance(value, str):
        return "member-sha256=unavailable"
    # Length and line breaks before encode or normalize. A break is refused, not folded.
    if len(value) > NAME_LIMIT or any(char in value for char in LINE_BREAKS):
        return _bounded_digest(value)
    try:
        canonical = unicodedata.normalize("NFC", value)
    except (ValueError, UnicodeError):
        return _bounded_digest(value)
    return _SECRET_RE.sub("[REDACTED]", canonical)


def public_text(value):
    return _screen_text(value)[:TEXT_LIMIT]


def _component_excerpt(text, difference):
    if len(text) <= TEXT_LIMIT:
        return text
    start = max(0, difference - TEXT_LIMIT // 2)
    leading = "..." if start else ""
    end = start + TEXT_LIMIT - len(leading)
    if end < len(text):
        return leading + text[start:end - 3] + "..."
    return leading + text[start:end]


def _component_excerpts(part, previous):
    part, previous = _screen_text(part), _screen_text(previous)
    if part == previous:
        return part[:TEXT_LIMIT], previous[:TEXT_LIMIT]
    difference = next((index for index, (left, right) in enumerate(zip(part, previous)) if left != right),
                      min(len(part), len(previous)))
    return _component_excerpt(part, difference), _component_excerpt(previous, difference)


def _refuse_duplicate(archive_kind, name, parts, conflict):
    message = "duplicate " + archive_kind + " member: " + public_text(name)
    if conflict is not None:
        offset, spelling, kind, previous_kind = conflict
        part, existing = _component_excerpts(parts[offset], spelling)
        prefix = "/".join(parts[:offset + 1])
        previous = "/".join(parts[:offset] + [spelling])
        reason = "spelling conflict" if kind == previous_kind else "file/directory conflict"
        message += (f" ({reason}: component {part} [{kind}], "
                    f"existing component {existing} [{previous_kind}], "
                    f"conflicting prefix: {public_text(prefix)}, "
                    f"existing prefix: {public_text(previous)})")
    fail(message)


def _admission_state():
    return {"root": None, "names": {}, "folded": set(), "components": {},
            "templates": set(), "info_roots": set()}


def admit_member(archive_kind, name, effective_name, member_type, size, state,
                 compressed_size=0, extra=b"", mode=0):
    """The only member admission: (a) names, (b) shape, (c) refusals, (d) allowlists.

    Adapters visit files before directories. Each folded component is indexed
    under its parent with one spelling, one kind and an explicit-directory flag.
    A directory entry is admitted only when a file already recorded that
    component. No archive member is ignored; the only success result is 'admitted'.
    """
    forbidden = "forbidden " + archive_kind + " member: "
    unexpected = "unexpected " + archive_kind + " member: "
    # (a) One name, on every supported Python version: some zipfile versions
    # apply Unicode Path records, while others ignore them. Neither is allowed.
    if not isinstance(effective_name, str) or name != effective_name:
        fail(forbidden + public_text(name))
    # (a) Bound before splitting, normalization or path parsing; validate the
    # archive spelling, removing exactly one structural directory slash.
    if (not isinstance(name, str) or not name or len(name) > NAME_LIMIT or
            any(char in name for char in LINE_BREAKS)):
        fail(forbidden + public_text(name))
    if not isinstance(extra, bytes) or len(extra) > ZIP_EXTRA_LIMIT:
        fail(forbidden + public_text(name))
    offset = 0
    while offset < len(extra):
        if len(extra) - offset < 4:
            fail(forbidden + public_text(name))
        field_id = int.from_bytes(extra[offset:offset + 2], "little")
        field_size = int.from_bytes(extra[offset + 2:offset + 4], "little")
        if field_id == 0x7075 or field_size > len(extra) - offset - 4:
            fail(forbidden + public_text(name))
        offset += 4 + field_size
    key = name[:-1] if name.endswith("/") else name
    raw_parts = key.split("/")
    parts = [part.rstrip(" .") for part in raw_parts]
    # Keep one component spelling on Windows and POSIX.
    if ("\\" in name or any(part in ("", ".", "..") for part in parts) or
            any(re.match(r"^[A-Za-z]:", part) for part in parts) or
            unicodedata.normalize("NFC", name) != name or
            any(part.lower() in FORBIDDEN_DIRS for part in parts) or
            any(PurePosixPath(part).suffix.lower() in FORBIDDEN_SUFFIXES for part in parts) or
            parts != raw_parts):
        fail(forbidden + public_text(name))
    folded_parts = [_fold_part(part) for part in parts]
    if (any(not _portable_component(part, folded) for part, folded in zip(parts, folded_parts)) or
            any(not _canonical_component(part, folded) for part, folded in zip(parts, folded_parts))):
        fail(forbidden + public_text(name))
    logical = key
    root = state["root"]
    if archive_kind == "sdist":
        if root is None:
            root = parts[0]
            if (root in PACKAGES or root.endswith(".dist-info") or
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!-]*", root)):
                fail(unexpected + public_text(name))
        if (parts[0] != root or
                (len(parts) == 1 and member_type != tarfile.DIRTYPE)):
            fail(unexpected + public_text(name))
        logical = key.partition("/")[2]
    directory = name.endswith("/") if archive_kind == "wheel" else member_type == tarfile.DIRTYPE
    leaf_kind = "directory" if directory else "file"
    previous_kind = state["names"].get(key)
    if previous_kind is not None:
        # An exact full name has identical ancestors. Only its leaf kind can conflict.
        conflict = None
        if leaf_kind != previous_kind:
            conflict = (len(parts) - 1, parts[-1], leaf_kind, previous_kind)
        _refuse_duplicate(archive_kind, name, parts, conflict)
    folded_key = "/".join(folded_parts)
    if folded_key in state["folded"]:
        _, conflict, _ = _stage_components(parts, folded_parts, leaf_kind, state["components"])
        _refuse_duplicate(archive_kind, name, parts, conflict)
    # (b) A ZIP directory needs both the slash and consistent metadata, with
    # neither stored nor compressed bytes. Tar directories need zero size.
    if archive_kind == "wheel":
        valid_type = member_type in ((0, stat.S_IFDIR) if directory else (0, stat.S_IFREG))
        valid_shape = valid_type and (not directory or (size == 0 and compressed_size == 0))
    else:
        valid_shape = ((directory and size == 0) or
                       (member_type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not name.endswith("/")))
    if not valid_shape or size < 0 or compressed_size < 0:
        fail(unexpected + public_text(name))
    if (archive_kind == "wheel" and logical.endswith(".dist-info/METADATA") and
            size > METADATA_LIMIT):
        fail(unexpected + public_text(name))
    # (c) The same prefix table, case-folded, before any generic admission.
    # An exact asset is a file permission, never a directory exception.
    folded_logical = folded_key.partition("/")[2] if archive_kind == "sdist" else folded_key
    location = _matched_location(folded_logical)
    if "_data" in parts and (directory or logical not in ASSETS):
        fail(unexpected + public_text(name))
    if location == _TEAM_TEMPLATES_LOCATION and not directory:
        if PurePosixPath(logical).suffix not in TEAM_TEMPLATE_SUFFIXES:
            fail(unexpected + public_text(name))
        # pip keeps an execute bit on POSIX. A template is data, not a program.
        if not isinstance(mode, int) or mode & 0o111:
            fail(unexpected + public_text(name))
    # (d) A directory inherits permission only from an already admitted file;
    # that file has passed these same location and allowlist rules. The sdist
    # deliberately has no whole-tree file allowlist beyond (a)-(c).
    # Implied directories and explicit entries share one per-parent index.
    info = re.fullmatch(r"aegis_guardrails-[A-Za-z0-9_.+!-]+\.dist-info", parts[0])
    claim, conflict, changes = _stage_components(parts, folded_parts, leaf_kind, state["components"])
    if claim == "duplicate":
        _refuse_duplicate(archive_kind, name, parts, conflict)
    if directory:
        allowed = claim == "ok"
    elif archive_kind == "sdist":
        allowed = True
    elif location == _TEMPLATE_LOCATION:
        allowed = logical in TEMPLATES
    elif info:
        allowed = "/".join(parts[1:]) in DIST_INFO
    else:
        allowed = (logical in ASSETS or
                   (location is None and parts[0] in PACKAGES and
                    PurePosixPath(logical).suffix == ".py") or
                   location == _TEAM_TEMPLATES_LOCATION)
    if not allowed:
        fail(unexpected + public_text(name))
    # (e) All checks completed. Record the member and its components together.
    state["root"] = root
    state["names"][key] = leaf_kind
    state["folded"].add(folded_key)
    for children, folded, slot in changes:
        children[folded] = slot
    if not directory and archive_kind == "wheel":
        state["templates"].update({logical} & TEMPLATES)
        if info:
            state["info_roots"].add(parts[0])
    return "admitted"


def check_metadata(data):
    metadata = BytesParser().parsebytes(data)
    if metadata.get_all("Name") != ["aegis-guardrails"] or metadata.get_all("Provides-Extra") != ["dev"]:
        fail("wheel metadata must name aegis-guardrails and only the dev extra")
    for requirement in metadata.get_all("Requires-Dist", []):
        parts = requirement.split(";", 1)
        if len(parts) != 2 or not re.fullmatch(r"extra\s*==\s*(['\"])dev\1", parts[1].strip()):
            fail("wheel metadata contains a runtime or unsupported requirement: " + public_text(requirement))


def check_wheel(path):
    try:
        with zipfile.ZipFile(path) as wheel:
            state, metadata = _admission_state(), []
            members = sorted(wheel.infolist(), key=lambda member:
                             member.orig_filename.endswith("/") or
                             stat.S_IFMT(member.external_attr >> 16) == stat.S_IFDIR)
            for member in members:
                name = member.orig_filename
                unix = member.external_attr >> 16
                # Opening checks the local-header name against the central
                # spelling for every member; no payload read is needed for it.
                with wheel.open(member) as source:
                    admit_member("wheel", name, member.filename, stat.S_IFMT(unix),
                                 member.file_size, state, member.compress_size, member.extra,
                                 mode=stat.S_IMODE(unix))
                    if name.endswith(".dist-info/METADATA"):
                        metadata.append(source.read(METADATA_LIMIT))
            _refuse_orphan_directories("wheel", state)
            if state["templates"] != TEMPLATES:
                shown = ", ".join(public_text(item) for item in sorted(state["templates"] ^ TEMPLATES))
                fail("wheel template allowlist mismatch: " + shown)
            if len(state["info_roots"]) != 1:
                fail("unexpected wheel member: multiple dist-info directories")
            if len(metadata) != 1:
                fail("wheel metadata must contain exactly one METADATA file")
            check_metadata(metadata[0])
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError, OverflowError, NotImplementedError) as exc:
        fail("invalid wheel: " + public_text(str(exc)))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg):
    print(f"verify_dist: {msg}", file=sys.stderr)
    sys.exit(1)


def _dist_member_name(name):
    """A digest names one file in the dist directory. Refuse a path component."""
    if (not isinstance(name, str) or not name or name in (".", "..") or
            "/" in name or "\\" in name or len(name) > NAME_LIMIT or
            any(char in name for char in LINE_BREAKS)):
        fail("refused dist name: " + public_text(name))
    return name


def _signed_basename(path):
    """A SHA256SUMS name is one line. Refuse a break; do not join it into the record."""
    return _dist_member_name(os.path.basename(path))


def _entry_kind(entry):
    """Classify one directory entry. Never follow a symlink to decide."""
    if entry.is_symlink():
        return "symlink"
    if entry.is_file(follow_symlinks=False):
        return "file"
    if entry.is_dir(follow_symlinks=False):
        return "directory"
    # The predicates can all return false after an entry disappears.
    mode = entry.stat(follow_symlinks=False).st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def _missing_path(error):
    return (isinstance(error, FileNotFoundError) and
            getattr(error, "winerror", None) in (None, _WIN_FILE_NOT_FOUND, _WIN_PATH_NOT_FOUND))


def _check_scan_open_error(directory, error, stat_directory):
    """Resolve ambiguous Windows scan-open errors with one target probe."""
    winerror = getattr(error, "winerror", None)
    if winerror in (_WIN_FILE_NOT_FOUND, _WIN_PATH_NOT_FOUND):
        try:
            mode = stat_directory(directory).st_mode
        except (OSError, ValueError) as probe_error:
            if _missing_path(probe_error):
                fail("distribution directory is missing")
        else:
            if winerror == _WIN_FILE_NOT_FOUND and stat.S_ISDIR(mode):
                return
    elif _missing_path(error):
        fail("distribution directory is missing")
    fail("distribution directory is unreadable")


def _dist_matches(directory, scan_directory, stat_directory):
    """Count matching entries and reserve a sample slot for the first irregular one."""
    counts = {"wheel": 0, "sdist": 0, "irregular": 0}
    sample = []
    first_irregular = None
    try:
        scan = scan_directory(directory)
    except OSError as error:
        _check_scan_open_error(directory, error, stat_directory)
        return counts, sample
    except ValueError:
        fail("distribution directory is unreadable")
    try:
        with scan as entries:
            for entry in entries:
                name = entry.name
                if not isinstance(name, str):
                    continue
                lowered = name[-7:].lower()
                if lowered.endswith(".whl"):
                    kind = "wheel"
                elif lowered.endswith(".tar.gz"):
                    kind = "sdist"
                else:
                    continue
                shape = _entry_kind(entry)
                row = (name, kind, shape)
                counts[kind if shape == "file" else "irregular"] += 1
                if shape != "file" and (first_irregular is None or row < first_irregular):
                    first_irregular = row
                if len(sample) == DIST_SAMPLE_LIMIT:
                    if name >= sample[-1][0]:
                        continue
                    sample.pop()
                insort(sample, row)
    except OSError:
        fail("distribution directory is unreadable")
    if first_irregular is not None and first_irregular not in sample:
        sample[-1] = first_irregular
    return counts, sample


def _inventory_name(name):
    if len(name) > NAME_LIMIT or not name.isprintable():
        screened = _bounded_digest(name)
    else:
        screened = public_text(name)
    return json.dumps(screened, ensure_ascii=False)


def dists(d, *, scan_directory=os.scandir, stat_directory=os.stat):
    """The one regular wheel and the one regular sdist. Anything else refuses."""
    counts, sample = _dist_matches(d, scan_directory, stat_directory)
    wheels, sdists, irregular = counts["wheel"], counts["sdist"], counts["irregular"]
    if irregular or wheels != 1 or sdists != 1:
        shown = ", ".join(f"{kind} {shape} {_inventory_name(name)}" for name, kind, shape in sample)
        omitted = wheels + sdists + irregular - len(sample)
        fail(f"expected exactly one wheel and one sdist, found wheels={wheels}, sdists={sdists}, "
             f"irregular={irregular}, sample=[{shown}], omitted={omitted}")
    paths = {kind: os.path.join(d, name) for name, kind, _shape in sample}
    return [paths["wheel"], paths["sdist"]]


def check_sdist(path):
    """Tar metadata adapter; every member uses the wheel's admission primitive."""
    try:
        with tarfile.open(path, "r:gz") as archive:
            state = _admission_state()
            for member in sorted(archive.getmembers(), key=lambda member: member.isdir()):
                permission = member.mode if isinstance(member.mode, int) else None
                admit_member("sdist", member.name, member.name, member.type, member.size, state,
                             mode=stat.S_IMODE(permission) if permission is not None else -1)
            _refuse_orphan_directories("sdist", state)
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        fail("invalid sdist: " + public_text(str(exc)))


def record(d, *, discover=dists):
    paths = discover(d)
    bases = [_signed_basename(path) for path in paths]
    check_wheel(paths[0])
    check_sdist(paths[1])
    lines = ["%s  %s\n" % (sha256(path), base) for path, base in zip(paths, bases)]
    # Explicit LF. Text mode would translate "\n" to CRLF on Windows, and verify refuses CR.
    with open(os.path.join(d, SUMS), "w", encoding="utf-8", newline="\n") as f:
        f.writelines(lines)
    sys.stdout.write("".join(lines))


# digest hex, two spaces, a bounded name, and the terminating newline.
_SUM_LINE_LIMIT = 64 + 2 + NAME_LIMIT + 1


def _sums_entries(path, present_names):
    """Validate bounded lines through EOF and retain digests only for discovered names."""
    expected = {}
    unexpected = 0
    sample = []
    with open(path, "rb") as handle:
        while True:
            blob = handle.readline(_SUM_LINE_LIMIT + 1)
            if not blob:
                break
            if len(blob) > _SUM_LINE_LIMIT:
                fail("refused dist name: member-sha256=overlong")
            if b"\x00" in blob or b"\r" in blob:
                fail("refused dist name: member-sha256=unavailable")
            try:
                line = blob.decode("utf-8")
            except UnicodeDecodeError:
                fail("refused dist name: member-sha256=unavailable")
            if not line.strip():
                continue
            body = line[:-1] if line.endswith("\n") else line
            parts = body.split("  ", 1)
            if len(parts) != 2:
                fail("refused dist name: " + public_text(body))
            digest, name = parts
            name = _dist_member_name(name)
            if name in present_names:
                expected[name] = digest
            else:
                unexpected += 1
                if len(sample) < DIST_SAMPLE_LIMIT:
                    sample.append(_inventory_name(name))
    return expected, unexpected, sample


def verify(d, *, discover=dists):
    wheel, sdist = discover(d)
    sums_path = os.path.join(d, SUMS)
    if not os.path.isfile(sums_path):
        fail(public_text(sums_path) + " is missing")
    present = {os.path.basename(wheel): (wheel, check_wheel),
               os.path.basename(sdist): (sdist, check_sdist)}
    expected, unexpected, sample = _sums_entries(sums_path, present.keys())
    missing = present.keys() - expected.keys()
    if missing or unexpected:
        found = ", ".join(_inventory_name(name) for name in sorted(present))
        absent = ", ".join(_inventory_name(name) for name in sorted(missing))
        shown = ", ".join(sample)
        fail(f"dist/ contents {found} do not match {SUMS}: missing=[{absent}], "
             f"unexpected={unexpected}, sample=[{shown}], omitted={unexpected - len(sample)}")
    for name, digest in sorted(expected.items()):
        path, check = present[name]
        actual = sha256(path)
        if actual != digest:
            fail(public_text(name) + ": sha256 " + actual + " != recorded " + public_text(digest))
        check(path)
        print(path)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("record", "verify"):
        fail("usage: verify_dist.py record|verify DIST_DIR")
    {"record": record, "verify": verify}[sys.argv[1]](sys.argv[2])
