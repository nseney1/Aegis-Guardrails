"""Pure lane snapshot calculations over captured index/config/stat/blob facts.

No paths are opened and no Git runner or descriptor crosses this boundary.
The caller captures native EOL explicitly and supplies allocation budgets.
The public team_git facade retains descriptor ownership and index revalidation.
"""
from __future__ import annotations

import codecs
import hashlib
import re
import zlib

from aegis_core import gitsafe_policy
from aegis_core.workspace.git_objects import object_id

__all__ = ["GitRefusal", "OID_PATTERN", "STAT_CLEAN", "baseline_requests", "binary_text", "blob_pack", "check_filter_bytes", "check_filter_sources", "clean_bytes",
           "clean_eol", "conversion_settings", "decode_worktree", "eol_rule", "filter_drivers", "index_clean", "index_matches",
           "index_records", "is_attribute_path", "preserved_paths", "snapshot_attributes", "snapshot_entries", "snapshot_rules",
           "attribute_version", "attribute_entries", "attribute_fallbacks", "deleted_attribute_rules",
           "conflict_paths", "failure_cause", "failure_observation", "merge_tree_oid"]

OID_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
# Captured row state: payload reading was skipped under the index stat proof.
STAT_CLEAN = object()
MAX_ATTRIBUTE_LINE_BYTES = 2048
MAX_ATTRIBUTE_FILE_BYTES = 100 * 1024 * 1024
_CONTROL_BYTES = bytes((*range(8), 11, *range(14, 27), *range(28, 32), 127))

_INDEX_STAT = re.compile(rb"  ctime: ([0-9]{1,20}):([0-9]{1,10})\n  mtime: ([0-9]{1,20}):([0-9]{1,10})\n"
    rb"  dev: ([0-9]{1,20})\tino: ([0-9]{1,20})\n  uid: ([0-9]{1,20})\tgid: ([0-9]{1,20})\n"
    rb"  size: ([0-9]{1,20})\tflags: ([0-9a-fA-F]{1,16})\n")


class GitRefusal(gitsafe_policy.GitError):
    """Stable library refusal. code is the machine-readable refusal, never stderr.

    The landing cause fields describe a numeric observation when available.
    """

    # Retain the public facade's exception identity and serialized type name.
    __module__ = "aegis_core.team_git"

    def __init__(self, code: str, *, next_action=None, errno=None, exit_status=None) -> None:
        actions = {"index_flags_unsupported": "Clear assume-unchanged and skip-worktree flags, then retry.",
                   "index_stat_unprovable": "Run `git update-index --refresh` in the worktree, then retry."}
        super().__init__("Lane Git operation refused: " + code, code=code, next_action=actions.get(code, next_action))
        self.errno = errno if type(errno) is int else None
        self.exit_status = exit_status if self.errno is None and type(exit_status) is int else None
        self.origin = "errno" if self.errno is not None else "exit_status" if self.exit_status is not None else "absent"
        self.certainty = "unknown" if self.origin == "absent" else "confirmed"


def _index_refuse(code="conversion_unavailable"):
    raise GitRefusal(code)


def index_records(raw, *, max_paths, max_path_bytes, max_bytes):
    """Bound before parsing; select stage 0, otherwise Git's stage-2 baseline."""
    if type(raw) is not bytes or len(raw) > max_bytes or raw.count(b"\0") > max_paths * 3:
        _index_refuse("size_limit")
    grouped, position = {}, 0
    while position < len(raw):
        end = raw.find(b"\0", position, position + max_path_bytes + 84)
        if end < 0:
            _index_refuse("size_limit")
        meta, separator, path = raw[position:end].partition(b"\t")
        if not separator or len(meta) > 75 or not 1 <= len(path) <= max_path_bytes:
            _index_refuse()
        fields = meta.split(b" ")
        if (len(fields) != 3 or fields[0] not in (b"100644", b"100755", b"120000", b"160000")
                or OID_PATTERN.fullmatch(fields[1].decode("ascii", "replace")) is None or fields[2] not in (b"0", b"1", b"2", b"3")):
            _index_refuse()
        stats = _INDEX_STAT.match(raw, end + 1, min(len(raw), end + 1 + 256))
        if stats is None:
            _index_refuse()
        cache = tuple(int(x) for x in stats.groups()[:-1]) + (int(stats.group(10), 16),)
        if any(x > 0xffffffff for x in cache) or cache[1] >= 1000000000 or cache[3] >= 1000000000:
            _index_refuse()
        stage = fields[2]
        flags = cache[9]
        if flags & ~0x6000f000 or flags & 0x3000 != int(stage) << 12:
            _index_refuse()
        if bool(flags & 0x4000) != bool(flags & 0x60000000) or flags & 0x20000000 and stage != b"0":
            _index_refuse()
        if flags & 0x40008000:
            _index_refuse("index_flags_unsupported")
        if path not in grouped and len(grouped) >= max_paths:
            _index_refuse("size_limit")
        stages = grouped.setdefault(path, {})
        if stage in stages:
            _index_refuse()
        stages[stage] = (fields[0].decode("ascii"), None if flags & 0x20000000 else fields[1].decode("ascii"), cache)
        position = stats.end()
    result = {}
    for path, stages in grouped.items():
        if b"0" in stages and len(stages) != 1:
            _index_refuse()
        if b"0" in stages:
            result[path] = stages[b"0"]
        else:
            mode = next(stages[s][0] for s in (b"2", b"1", b"3") if s in stages)
            result[path] = (mode, *stages.get(b"2", (None, None, None))[1:])
    return result


def index_matches(cache, observed, settings, index_time):
    """Git's stat-clean shortcut, with racy mtimes treated as dirty."""
    if cache is None or index_time is None or cache[9] & 0x3000 or observed.st_mtime_ns >= index_time:
        return False
    ct, cn, mt, mn, dev, ino, uid, gid, size, _ = cache
    if mt != observed.st_mtime_ns // 1000000000 or size != observed.st_size:
        return False
    minimal = settings["checkstat"] == b"minimal"
    if not minimal and (ino, uid, gid) != tuple(x & 0xffffffff for x in
                            (observed.st_ino, observed.st_uid, observed.st_gid)):
        return False
    if not minimal and settings["trustctime"] != b"false" and ct != observed.st_ctime_ns // 1000000000:
        return False
    # USE_NSEC and USE_STDEV are build options Git does not expose. A mismatch
    # in these fields alone cannot prove whether Git would re-clean the bytes.
    if (observed.st_mtime_ns // 1000000000 == index_time // 1000000000 or not minimal and
            (mn != observed.st_mtime_ns % 1000000000 or dev != observed.st_dev & 0xffffffff
             or settings["trustctime"] != b"false" and cn != observed.st_ctime_ns % 1000000000)):
        return None
    return True


def eol_rule(values, settings, *, native_crlf):
    text = values["crlf"] if values["text"] == b"unspecified" else values["text"]
    if text not in (b"set", b"unset", b"auto", b"input", b"unspecified"):
        raise GitRefusal("conversion_unavailable")
    eol = values["eol"]
    if eol not in (b"lf", b"crlf", b"set", b"unset", b"unspecified"):
        raise GitRefusal("conversion_unavailable")
    action = "binary" if text == b"unset" else ("auto" if text == b"auto" else "text")
    if text == b"unspecified" and eol not in (b"lf", b"crlf"):
        action = "auto" if settings["autocrlf"] in (b"true", b"input") else "binary"
    output_crlf = settings["autocrlf"] == b"true" or (
        settings["autocrlf"] != b"input" and (settings["eol"] == b"crlf" or
        settings["eol"] in (b"", b"native") and native_crlf))
    output_crlf = {b"lf": False, b"crlf": True}.get(eol, text != b"input" and output_crlf)
    encoding = values["working-tree-encoding"]
    return action, output_crlf, values["ident"] == b"set", encoding if encoding not in (b"unset", b"unspecified") else None


def snapshot_attributes(out, paths):
    """Check the source-query framing before parsing conversion attributes."""
    if out.count(b"\0") != 3 * len(paths) * len(gitsafe_policy.SNAPSHOT_ATTRIBUTES) or (out and not out.endswith(b"\0")):
        raise GitRefusal("conversion_unavailable")
    return out.split(b"\0")


def attribute_version(raw):
    """Bound the version observation before parsing the --source capability."""
    action = "Install Git 2.40 or newer, then retry the snapshot."
    if type(raw) is not bytes or len(raw) > 256:
        raise GitRefusal("conversion_unavailable", next_action=action)
    found = re.fullmatch(rb"git version ([0-9]{1,5})\.([0-9]{1,5})(?:\.[0-9]{1,5})?[^\r\n]*\n?", raw)
    if found is None or tuple(int(value) for value in found.groups()) < (2, 40):
        raise GitRefusal("conversion_unavailable", next_action=action)


def _attribute_body(data):
    """Refuse ambiguous attribute bytes before hashing or retaining an OID."""
    if (len(data) >= MAX_ATTRIBUTE_FILE_BYTES or data.startswith(b"\xef\xbb\xbf") or b"\0" in data):
        raise GitRefusal("conversion_unavailable")
    start = 0
    while start < len(data):
        end = data.find(b"\n", start, start + MAX_ATTRIBUTE_LINE_BYTES + 1)
        if end < 0:
            end = len(data)
        if end - start >= MAX_ATTRIBUTE_LINE_BYTES:
            raise GitRefusal("conversion_unavailable")
        start = end + 1


def _attribute_row(cached, data):
    """Call-local row for one immutable bytes object, or None when it must be redone."""
    if type(data) is not bytes:
        return None
    row = cached.get(id(data))
    if row is not None and row[0] is data:
        return row
    return None


def attribute_entries(sources, oid_length):
    """Raw captured bytes, without applying their own text/encoding rules."""
    # Git v2.43.0 attr.c:335-338,674-760: file input strips a leading BOM
    # and CRLF; blob input stops at NUL, retains CR, and lacks the file cap.
    # Refuse all ambiguous forms; never normalize the captured source bytes.
    # One call scans and hashes each retained bytes object once, then emits
    # every path. Another object with equal contents is processed again.
    cached = {}
    for data in sources.values():
        if _attribute_row(cached, data) is None:
            _attribute_body(data)
            if type(data) is bytes:
                cached[id(data)] = [data, None]
    entries = []
    for path, data in sorted(sources.items()):
        row = _attribute_row(cached, data)
        if row is None or row[1] is None:
            oid = object_id(data, oid_length)
            if row is not None:
                row[1] = oid
        else:
            oid = row[1]
        entries.append((path, "100644", oid, data))
    return entries


def attribute_fallbacks(captured, baseline):
    """Select bindable stage-0 sources; keep paths distinct for budget charges."""
    wanted = {}
    for path, (mode, oid, cache) in baseline.items():
        if path.rpartition(b"/")[2] != b".gitattributes" or path in captured or not oid:
            continue
        if mode not in ("100644", "100755") or cache is None or cache[9] & 0x3000:
            raise GitRefusal("conversion_unavailable")
        wanted[path] = oid
    return wanted


def deleted_attribute_rules(paths, baseline, fallbacks, indexed, captured):
    """Refuse ambiguous index-deletion order rather than restore stale rules."""
    result = dict(captured)
    for path in paths:
        if path in fallbacks:
            continue
        applicable = []
        directory = path.rpartition(b"/")[0]
        while True:
            source = (directory + b"/" if directory else b"") + b".gitattributes"
            if source in fallbacks:
                applicable.append(source)
            if not directory:
                break
            directory = directory.rpartition(b"/")[0]
        if not applicable:
            continue
        # Git processes tracked entries in index order before untracked adds.
        # A tracked path preceding every applicable deletion sees the old rules.
        if path in baseline and all(path < source for source in applicable):
            result[path] = indexed[path]
        elif len(applicable) != 1 or indexed[path] != captured[path]:
            # Equal endpoints with multiple deletions cannot prove intermediate
            # contexts equal. Keep the fallback conservative in that case too.
            raise GitRefusal("conversion_unavailable")
    return result


def filter_drivers(raw, status):
    """Any effective driver key configures it, regardless of the key's value."""
    if type(raw) is not bytes or len(raw) > 65536 or raw.count(b"\0") > 4096:
        _index_refuse()
    if status not in (0, 1) or bool(raw) != (status == 0) or raw and not raw.endswith(b"\0"):
        _index_refuse()
    drivers = set()
    for key in raw.split(b"\0")[:-1]:
        section, separator, variable = key.rpartition(b".")
        if (not key.startswith(b"filter.") or not separator
                or re.fullmatch(rb"[a-z][a-z0-9-]*", variable) is None):
            _index_refuse()
        if section != b"filter":
            drivers.add(section[7:])
    return drivers


def is_attribute_path(path):
    path = path.lower()
    return path == b".gitattributes" or path.endswith(b"/.gitattributes")


def _filter_tokens(data):
    """Raw filter and macro markers only; no attribute syntax parsing."""
    return b"filter" in data or b"[attr]" in data


def check_filter_bytes(data):
    """Apply the same raw marker refusal to every captured attribute source."""
    if _filter_tokens(data):
        raise GitRefusal("conversion_unavailable")


def check_filter_sources(attributes, baseline, objects, *, configured_filters):
    """With any configured driver, captured and indexed filter/macro tokens refuse."""
    if not configured_filters:
        return
    for data in attributes:
        check_filter_bytes(data)
    for path, (_, oid, cache) in baseline.items():
        if not is_attribute_path(path):
            continue
        # The baseline chooses stage 2 for conflicts; other attribute stages are unproven.
        if cache is None or cache[9] & 0x3000 or oid and oid not in objects:
            raise GitRefusal("conversion_unavailable")
        if oid:
            check_filter_bytes(objects[oid][1])


def snapshot_rules(paths, attrs, settings, *, native_crlf, configured_filters):
    names = gitsafe_policy.SNAPSHOT_ATTRIBUTES
    rules = {}
    for index, path in enumerate(paths):
        values = {}
        for offset, name in enumerate(names):
            position = (index * len(names) + offset) * 3
            found, attribute, value = attrs[position:position + 3]
            if found != path or attribute != name.encode():
                raise GitRefusal("conversion_unavailable")
            values[name] = value
        # Git also prints "unspecified" for a literal driver with that name.
        if configured_filters and (values["filter"] != b"unspecified" or values["filter"] in configured_filters):
            raise GitRefusal("conversion_unavailable")
        rules[path] = eol_rule(values, settings, native_crlf=native_crlf)
    return rules


def conversion_settings(raw):
    """Parse one bounded, NUL-framed config observation; no lenient bool coercion."""
    defaults = dict(autocrlf=b"false", safecrlf=b"false", filemode=b"true", symlinks=b"true",
                    eol=b"", trustctime=b"true", checkstat=b"default")
    if type(raw) is not bytes:
        _index_refuse()
    if len(raw) > 4096 or raw.count(b"\0") > 64 or raw and not raw.endswith(b"\0"):
        _index_refuse()
    for record in raw.split(b"\0")[:-1]:
        key, sep, value = record.partition(b"\n")
        if not key.startswith(b"core.") or len(value) > 32:
            _index_refuse()
        name = key[5:].decode("ascii", "replace").lower()
        if name not in defaults:
            _index_refuse()
        boolean = name in ("filemode", "symlinks", "trustctime", "autocrlf", "safecrlf")
        if not sep and not boolean and name != "eol":
            _index_refuse()
        value = value.lower() if sep else b"true" if boolean else b""
        if name == "eol" and value not in (b"lf", b"crlf", b"native"):
            value = b""
        if name in ("filemode", "symlinks", "trustctime", "autocrlf", "safecrlf") and value not in (b"input", b"warn"):
            if value in (b"true", b"yes", b"on"):
                value = b"true"
            elif value in (b"false", b"no", b"off", b""):
                value = b"false"
            elif re.fullmatch(rb"[+-]?[0-9]{1,16}", value):
                if not -2147483648 <= int(value) <= 2147483647:
                    _index_refuse()
                value = b"true" if int(value) else b"false"
            else:
                _index_refuse()
        allowed = ((b"false", b"true", b"input") if name == "autocrlf" else
                   (b"false", b"true", b"warn") if name == "safecrlf" else
                   (b"", b"lf", b"crlf", b"native") if name == "eol" else
                   (b"default", b"minimal") if name == "checkstat" else (b"true", b"false"))
        if value not in allowed:
            _index_refuse()
        defaults[name] = value
    return defaults


def binary_text(data):
    """Git convert.c's byte statistics, including bare CR and terminal DOS EOF."""
    crlf = data.count(b"\r\n")
    if b"\0" in data or data.count(b"\r") != crlf:
        return True
    nonprintable = len(data) - len(data.translate(None, _CONTROL_BYTES))
    printable = len(data) - nonprintable - data.count(b"\r") - data.count(b"\n")
    nonprintable -= data.endswith(b"\x1a")
    return (printable >> 7) < nonprintable


def clean_eol(data, rule, preserve, safe):
    action, output_crlf, _, _ = rule
    if action == "binary" or not data:
        return data
    crlf, lone_lf = data.count(b"\r\n"), data.count(b"\n") - data.count(b"\r\n")
    automatic = action == "auto"
    if automatic and binary_text(data):
        return data
    convert = bool(crlf) and not (automatic and preserve)
    # Simulate the round trip exactly where git add would refuse core.safecrlf.
    checkout_crlf = output_crlf and not (automatic and not convert and crlf)
    if safe == b"true" and ((crlf and convert and not output_crlf) or (lone_lf and checkout_crlf)):
        raise GitRefusal("conversion_unavailable")
    return data.replace(b"\r\n", b"\n") if convert else data


def clean_bytes(data, rule, preserve, safe):
    data = clean_eol(data, rule, preserve, safe)
    return re.sub(rb"\$Id:[^\n$]*\$", b"$Id$", data) if rule[2] else data


def decode_worktree(data, rule, limit):
    """Decode the resolved index/worktree rule, without re-resolving attributes."""
    encodings = {b"UTF-8": "utf-8", b"UTF-16": "utf-16", b"UTF-16LE": "utf-16-le",
              b"UTF-16BE": "utf-16-be", b"UTF-32": "utf-32", b"UTF-32LE": "utf-32-le",
              b"UTF-32BE": "utf-32-be", b"ASCII": "ascii", b"ISO-8859-1": "latin-1",
              b"LATIN1": "latin-1", b"SHIFT_JIS": "shift_jis", b"CP1252": "cp1252"}
    if len(rule[3]) > 32 or rule[3].upper() not in encodings:
        raise GitRefusal("conversion_unavailable")
    encoding = rule[3].upper()
    if (encoding in (b"UTF-16LE", b"UTF-16BE") and data.startswith((b"\xff\xfe", b"\xfe\xff"))
        or encoding in (b"UTF-32LE", b"UTF-32BE") and data.startswith((b"\xff\xfe\0\0", b"\0\0\xfe\xff"))):
        raise GitRefusal("conversion_unavailable")
    decoder = codecs.getincrementaldecoder(encodings[encoding])()
    encoder = codecs.getincrementalencoder("shift_jis")() if encoding == b"SHIFT_JIS" else None
    chunks, size, offset = [], 0, 0
    try:
        for start in range(0, max(1, len(data)), 65536):
            final = start + 65536 >= len(data)
            text = decoder.decode(data[start:start + 65536], final=final)
            if encoder is not None:
                text = text.replace("\\", "\u00a5").replace("~", "\u203e")
                raw = encoder.encode(text, final=final)
                if raw != data[offset:offset + len(raw)]:
                    raise GitRefusal("conversion_unavailable")
                offset += len(raw)
            count = sum(1 if ord(c) < 128 else 2 if ord(c) < 2048 else 3 if ord(c) < 65536 else 4 for c in text)
            if count > limit - size:
                raise GitRefusal("size_limit")
            chunks.append(text.encode("utf-8"))
            size += count
    except UnicodeError:
        raise GitRefusal("conversion_unavailable") from None
    return b"".join(chunks)


def index_clean(mode, data, observed, prior, settings, oid_length, index_time):
    prior_mode, prior_oid, cache = prior
    if cache and cache[8] == 0 and prior_oid != object_id(b"", oid_length):
        return False
    same_mode = (mode == prior_mode or mode in ("100644", "100755") and
        (prior_mode == "120000" and settings["symlinks"] == b"false"
         or prior_mode in ("100644", "100755") and settings["filemode"] == b"false"))
    return index_matches(cache, observed, settings, index_time) if prior_oid and same_mode else False


def baseline_requests(contents, baseline, rules, *, configured_filters):
    """One batch for CRLF baselines and all attribute blobs when any driver exists."""
    wanted = [baseline[path][1] for path, mode, data, _ in contents if mode != "120000"
            and data is not STAT_CLEAN and b"\r\n" in data and rules[path][0] == "auto" and path in baseline and baseline[path][1]]
    if configured_filters:
        wanted.extend(oid for path, (_, oid, _) in baseline.items() if is_attribute_path(path) and oid)
    return wanted


def preserved_paths(baseline, objects):
    return {p for p, (_, oid, _) in baseline.items() if oid in objects
            and b"\r\n" in objects[oid][1] and not binary_text(objects[oid][1])}


def snapshot_entries(contents, settings, baseline, rules, preserved, oid_length, index_time):
    entries = []
    for path, mode, data, observed in contents:
        prior = baseline.get(path, ("100644", None, None))
        prior_mode = prior[0]
        unchanged = index_clean(mode, data, observed, prior, settings, oid_length, index_time)
        if data is STAT_CLEAN and unchanged is not True:
            raise GitRefusal("worktree_changed")
        if unchanged is True:
            entries.append((path, prior_mode, prior[1], None))
            continue
        if mode != "120000" and not unchanged:
            data = clean_bytes(data, rules[path], path in preserved, settings["safecrlf"])
        if mode != "120000":
            if prior_mode == "120000" and settings["symlinks"] == b"false":
                mode = "120000"
            elif settings["filemode"] == b"false":
                mode = prior_mode if prior_mode in ("100644", "100755") else "100644"
        oid = object_id(data, oid_length)
        if unchanged is None and oid != prior[1]:
            raise GitRefusal("index_stat_unprovable")
        entries.append((path, mode, oid, data))
    return entries


def blob_pack(blobs, oid_length, *, max_bytes):
    """One bounded, non-delta pack; Git alone writes the private object paths."""
    pack = bytearray(b"PACK" + (2).to_bytes(4, "big") + len(blobs).to_bytes(4, "big"))
    for data in blobs.values():
        size = len(data)
        bound = size + (size >> 12) + (size >> 14) + (size >> 25) + 13
        if len(pack) + 10 + bound + oid_length // 2 > max_bytes:
            raise GitRefusal("size_limit")
        header = bytearray()
        value = 0x30 | (size & 15)
        size >>= 4
        while size:
            header.append(value | 0x80)
            value, size = size & 127, size >> 7
        header.append(value)
        pack.extend(header)
        pack.extend(zlib.compress(data))
    digest = (hashlib.sha256 if oid_length == 64 else hashlib.sha1)(pack).digest()
    pack.extend(digest)
    return bytes(pack)


_CAUSE_DEPTH = 8


def failure_observation(source, ambient=None, *, stop_at=()):
    """Return the nearest observed errno or exit status within this operation."""
    current = source
    for _ in range(_CAUSE_DEPTH):
        if current is None or current is ambient:
            break
        os_errno = getattr(current, "errno", None)
        if type(os_errno) is int:
            return os_errno, None
        for name in ("exit_status", "returncode"):
            status = getattr(current, name, None)
            if type(status) is int:
                return None, status
        if not isinstance(current, BaseException) or isinstance(current, stop_at):
            break
        linked = current.__cause__
        current = current.__context__ if linked is None else linked
    return None, None


def failure_cause(exc, ambient=None):
    """Find the nearest numeric observation in this operation's exception chain."""
    os_errno, status = failure_observation(exc, ambient, stop_at=GitRefusal)
    if os_errno is not None:
        return {"errno": os_errno}
    if status is not None:
        return {"exit_status": status}
    return {}


def merge_tree_oid(out):
    """Read only the bounded object ID from a merge result."""
    end = out.find(b"\0", 0, 65)
    if end == -1:
        end = len(out)
    if end not in (40, 64):
        raise GitRefusal("invalid_oid")
    try:
        return out[:end].decode("ascii"), end + 1
    except UnicodeError:
        raise GitRefusal("invalid_object") from None


def conflict_paths(out, start, display, max_paths, max_path_bytes):
    """Collect bounded path bytes up to Git's empty separator, then label them."""
    exact = []
    while start < len(out) and out[start] != 0:
        end = out.find(b"\0", start, start + max_path_bytes + 1)
        if end == -1:
            end = len(out)
        if len(exact) >= max_paths or end - start > max_path_bytes:
            raise GitRefusal("size_limit")
        exact.append(out[start:end])
        start = end + 1
    return tuple(display(path) for path in exact), tuple(exact)
