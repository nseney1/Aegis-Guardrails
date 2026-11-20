"""Record or verify SHA-256 digests of the release distributions in dist/.

    python verify_dist.py record dist   # after the single build
    python verify_dist.py verify dist   # before testing and before publishing

`record` requires exactly one wheel and one sdist and writes dist/SHA256SUMS.
`verify` fails if any file is missing, altered, or unlisted, so the files that
are tested are byte-for-byte the files that are published. It prints the
verified file paths, one per line, for the caller to use.
"""
import hashlib
import os
from email.parser import BytesParser
from pathlib import PurePosixPath
import re
import stat
import sys
import tarfile
import unicodedata
import zipfile

SUMS = "SHA256SUMS"
PACKAGES = {"aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"}
TEMPLATE_PREFIX = "aegis_core/ast/drivers/templates/"
# Native JS/TS and Rust ship as Python modules; only Go needs packaged assets.
TEMPLATES = {TEMPLATE_PREFIX + name for name in (
    "__init__.py", "go_ast.go", "go.mod")}
ASSETS = {"aegis_sdk/py.typed", "aegis_core/benchmark_corpus/corpus.json",
          "aegis_core/benchmark_corpus/ast.json"}
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


def _fold_key(text):
    return "/".join(_fold_part(part) for part in text.split("/"))


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
    (prefix, _fold_key(prefix)) for prefix in _PROTECTED_PREFIXES if "/" in prefix)


def _matched_location(logical):
    """Longest multi-component protected prefix that contains logical as a child."""
    if not logical:
        return None
    folded = _fold_key(logical)
    best = None
    best_len = -1
    for prefix, folded_prefix in _LOCATION_FOLDED:
        if len(folded_prefix) > best_len and folded.startswith(folded_prefix + "/"):
            best = prefix
            best_len = len(folded_prefix)
    return best


def _portable_component(part):
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
    stem = unicodedata.normalize("NFC", part).split(".", 1)[0].casefold()
    if stem in _DEVICE_STEMS or _DEVICE_NUMBERED.fullmatch(stem):
        return False
    return True


def _canonical_component(part):
    """Protected prefix components compare NFC plus casefold. Only one spelling passes."""
    canonical = _CANONICAL_COMPONENT.get(_fold_part(part))
    return canonical is None or part == canonical


def _destination_key(key):
    """Case-folded destination. Windows installs these as one path."""
    return "/".join(unicodedata.normalize("NFC", part).casefold() for part in key.split("/"))


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


def public_text(value):
    """Canonicalize, redact, then truncate. Multi-line text is not joined."""
    if not isinstance(value, str):
        return "member-sha256=unavailable"
    # Length and line breaks before encode or normalize. A break is refused, not folded.
    if len(value) > NAME_LIMIT or any(char in value for char in LINE_BREAKS):
        return _bounded_digest(value)
    try:
        canonical = unicodedata.normalize("NFC", value)
    except (ValueError, UnicodeError):
        return _bounded_digest(value)
    redacted = _SECRET_RE.sub("[REDACTED]", canonical)
    if len(redacted) > TEXT_LIMIT:
        return redacted[:TEXT_LIMIT]
    return redacted


def _admission_state():
    return {"root": None, "names": set(), "ancestors": set(),
            "templates": set(), "info_roots": set()}


def admit_member(archive_kind, name, effective_name, member_type, size, state,
                 compressed_size=0, extra=b"", mode=0):
    """The only member admission: (a) names, (b) shape, (c) refusals, (d) allowlists.

    Adapters visit files before directories, so directory permission is derived
    solely from files already admitted by this function in this archive.
    No archive member is ignored; the only success result is 'admitted'.
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
            parts != raw_parts or
            any(not _portable_component(part) for part in parts) or
            any(not _canonical_component(part) for part in parts)):
        fail(forbidden + public_text(name))
    logical = key
    if archive_kind == "sdist":
        if state["root"] is None:
            root = parts[0]
            if (root in PACKAGES or root.endswith(".dist-info") or
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!-]*", root)):
                fail(unexpected + public_text(name))
            state["root"] = root
        if (parts[0] != state["root"] or
                (len(parts) == 1 and member_type != tarfile.DIRTYPE)):
            fail(unexpected + public_text(name))
        logical = "/".join(parts[1:])
    if key in state["names"] or _destination_key(key) in state.get("folded", ()):
        fail("duplicate " + archive_kind + " member: " + public_text(name))
    # (b) A ZIP directory needs both the slash and consistent metadata, with
    # neither stored nor compressed bytes. Tar directories need zero size.
    if archive_kind == "wheel":
        directory = name.endswith("/")
        valid_type = member_type in ((0, stat.S_IFDIR) if directory else (0, stat.S_IFREG))
        valid_shape = valid_type and (not directory or (size == 0 and compressed_size == 0))
    else:
        directory = member_type == tarfile.DIRTYPE
        valid_shape = ((directory and size == 0) or
                       (member_type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not name.endswith("/")))
    if not valid_shape or size < 0 or compressed_size < 0:
        fail(unexpected + public_text(name))
    if (archive_kind == "wheel" and logical.endswith(".dist-info/METADATA") and
            size > METADATA_LIMIT):
        fail(unexpected + public_text(name))
    # (c) The same prefix table, case-folded, before any generic admission.
    # An exact asset is a file permission, never a directory exception.
    location = _matched_location(logical)
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
    info = re.fullmatch(r"aegis_guardrails-[A-Za-z0-9_.+!-]+\.dist-info", parts[0])
    if directory:
        allowed = key in state["ancestors"]
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
    # (e) All checks completed. Only admitted files can grant ancestry.
    state["names"].add(key)
    state.setdefault("folded", set()).add(_destination_key(key))
    if not directory:
        state["ancestors"].update("/".join(parts[:i]) for i in range(1, len(parts)))
        if archive_kind == "wheel":
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
    try:
        if entry.is_symlink():
            return "symlink"
    except OSError:
        return "other"
    try:
        if entry.is_file(follow_symlinks=False):
            return "file"
    except OSError:
        return "other"
    return "other"


def _dist_matches(directory):
    """Every wheel or sdist name, in any case, including a dot-prefixed name.

    The directory fd is closed when the scan ends, including on OSError.
    A missing directory is an empty inventory, not a traceback.
    """
    found = []
    try:
        with os.scandir(directory) as scan:
            for entry in scan:
                name = entry.name
                if not isinstance(name, str):
                    continue
                lowered = name.lower()
                if lowered.endswith(".whl"):
                    kind = "wheel"
                elif lowered.endswith(".tar.gz"):
                    kind = "sdist"
                else:
                    continue
                found.append((kind, _entry_kind(entry), name))
    except OSError:
        return []
    return found


def dists(d):
    """The one regular wheel and the one regular sdist. Anything else refuses."""
    matches = _dist_matches(d)
    wheels = [name for kind, shape, name in matches if kind == "wheel" and shape == "file"]
    sdists = [name for kind, shape, name in matches if kind == "sdist" and shape == "file"]
    irregular = [name for kind, shape, name in matches if shape != "file"]
    if irregular or len(wheels) != 1 or len(sdists) != 1:
        shown = ", ".join(public_text(name) for _kind, _shape, name in sorted(matches, key=lambda item: item[2]))
        fail("expected exactly one wheel and one sdist, found " + shown)
    return [os.path.join(d, wheels[0]), os.path.join(d, sdists[0])]


def check_sdist(path):
    """Tar metadata adapter; every member uses the wheel's admission primitive."""
    try:
        with tarfile.open(path, "r:gz") as archive:
            state = _admission_state()
            for member in sorted(archive.getmembers(), key=lambda member: member.isdir()):
                permission = member.mode if isinstance(member.mode, int) else None
                admit_member("sdist", member.name, member.name, member.type, member.size, state,
                             mode=stat.S_IMODE(permission) if permission is not None else -1)
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        fail("invalid sdist: " + public_text(str(exc)))


def record(d):
    paths = dists(d)
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


def _sums_entries(path):
    """Read digest lines with a size cap before any name is parsed or opened."""
    expected = {}
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
            expected[_dist_member_name(name)] = digest
    return expected


def verify(d):
    sums_path = os.path.join(d, SUMS)
    if not os.path.isfile(sums_path):
        fail(public_text(sums_path) + " is missing")
    expected = _sums_entries(sums_path)
    wheel, sdist = dists(d)
    present = {os.path.basename(wheel): (wheel, check_wheel),
               os.path.basename(sdist): (sdist, check_sdist)}
    if present.keys() != expected.keys():
        found = ", ".join(public_text(item) for item in sorted(present))
        listed = ", ".join(public_text(item) for item in sorted(expected))
        fail("dist/ contents " + found + " do not match " + SUMS + " " + listed)
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
