"""Pure Git object framing and path-status parsing; no repository or process access."""
from __future__ import annotations

import hashlib
import os
import re
from typing import Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple


def requests(oids: Iterable[str], kind: str, error: Callable[[str], Exception]) -> List[str]:
    """Validate protocol inputs before encoding or sending them; preserve first occurrence."""
    if kind not in ("blob", "commit"):
        raise error("unsupported object kind")
    wanted: Dict[str, None] = {}
    for oid in oids:
        if not isinstance(oid, str) or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", oid):
            raise error("invalid object id")
        wanted[oid] = None
    return list(wanted)


def object_id(data: bytes, oid_length: int = 40, kind: str = "blob") -> str:
    """Hash the Git header and bytes without allocating another copy of the payload."""
    digest = (hashlib.sha256 if oid_length == 64 else hashlib.sha1)()
    digest.update(kind.encode("ascii") + b" %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest()


def object_size(header: bytes, oid: str, kind: str, error: Callable[[str], Exception]) -> int:
    """Bound the wire header before splitting or converting its unsigned 64-bit size."""
    if len(header) > len(oid) + 32:
        raise error(f"git cannot read object {oid}")
    fields = header.split()
    if (len(fields) != 3 or fields[0] != oid.encode("ascii") or fields[1] != kind.encode("ascii")
            or len(fields[2]) > 20 or not fields[2].isdigit()):
        raise error(f"git cannot read object {oid}")
    return int(fields[2])


def object_sizes(out: bytes, wanted: Sequence[str], kind: str,
                 error: Callable[[str], Exception]) -> Dict[str, int]:
    """Bound preflight metadata before splitting, then require exactly one header per OID."""
    if len(out) > sum(len(oid) + 33 for oid in wanted):
        raise error(f"git cannot read object {wanted[0]}")
    lines = out.split(b"\n")
    if len(lines) != len(wanted) + 1 or lines[-1] != b"":
        raise error(f"git cannot read object {wanted[0]}")
    return {oid: object_size(lines[index], oid, kind, error) for index, oid in enumerate(wanted)}


def parse_objects(out: bytes, wanted: Sequence[str], kind: str,
                  error: Callable[[str], Exception]) -> Dict[str, bytes]:
    """Check ordered frame headers, lengths, delimiters, hashes and complete consumption."""
    objects: Dict[str, bytes] = {}
    position = 0
    for oid in wanted:
        end = out.find(b"\n", position, position + len(oid) + 33)
        size = object_size(out[position:end] if end >= 0 else b"", oid, kind, error)
        start = end + 1
        if size > len(out) - start - 1 or out[start + size:start + size + 1] != b"\n":
            raise error(f"git returned content for {oid} that does not match the object id")
        data = out[start:start + size]
        if object_id(data, len(oid), kind) != oid:
            raise error(f"git returned content for {oid} that does not match the object id")
        objects[oid] = data
        position = start + size + 1
    if position != len(out):
        raise error("git returned content for requested objects with trailing data")
    return objects


def object_chunks(sizes: Mapping[str, int], budget: int) -> Iterator[List[str]]:
    """Group payload sizes in order; an object larger than the budget stands alone."""
    chunk: List[str] = []
    total = 0
    for oid, size in sizes.items():
        if chunk and total + size > budget:
            yield chunk
            chunk = []
            total = 0
        chunk.append(oid)
        total += size
        if total >= budget:
            yield chunk
            chunk = []
            total = 0
    if chunk:
        yield chunk


def parse_name_status_z(raw: bytes) -> List[Tuple[str, str, Optional[str]]]:
    """Parse NUL-delimited ``--name-status -z`` (or ``--raw -z``) output into
    ``(status, path, new_path)`` records without desynchronizing on 3-token ``R*``/``C*`` records.
    """
    fields = raw.split(b"\0")
    records: List[Tuple[str, str, Optional[str]]] = []
    index = 0
    while index < len(fields):
        parts = fields[index].split()
        if not parts:
            index += 1
            continue
        status = parts[-1].decode("ascii", "replace")
        width = 3 if status[:1] in ("R", "C") else 2  # a rename or copy names two paths
        paths = fields[index + 1:index + width]
        if len(paths) < width - 1 or not all(paths):
            break
        records.append((status, os.fsdecode(paths[0]), os.fsdecode(paths[1]) if width == 3 else None))
        index += width
    return records


def c_quoted(path: str) -> bytes:
    """``path`` as one C-quoted line, which ``hash-object --stdin-paths`` unquotes."""
    quoted = bytearray(b'"')
    for byte in os.fsencode(path):
        if byte in b'"\\':
            quoted += b"\\" + bytes([byte])
        elif byte < 0x20 or byte == 0x7F:
            quoted += b"\\%03o" % byte
        else:
            quoted.append(byte)
    return bytes(quoted + b'"')
