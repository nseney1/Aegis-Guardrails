"""The git-native agent team: lane leases and ``.aegis/team.json`` (v4.1 spec §1, ADR 0005 AD-7).

**Leases.** ``refs/aegis/lanes/<lane>`` holds one JSON blob::

    {"v":1,"lane":"docs","role":"implementer","owner":"nick@host","claim_id":"9f2c...",
     "gen":1,"branch":"lane/docs","paths":["docs/**"],"ts":1760000000,"ttl_s":3600}

A lease is cooperative conflict input for parallel lanes. It is not a lock (the overlap
check and the write are separate git calls, so two claims of different lanes can race
past each other), not an identity (``owner`` and ``role`` are display labels the
dispatcher sets; nothing compares them) and not proof that an agent is alive. The
backstops are the post-lane gate (``aegis check --lane``) and ``merge_metrics``.

- ``claim`` validates the lane name and globs, refuses when a live lease of another lane
  may overlap (``match.sets_overlap``; an unreadable lease counts as overlapping
  everything), then writes create-only. A live lease of the same lane is ``taken``; an
  expired one is taken over by compare-and-swap with ``gen`` + 1 and a new
  ``claim_id`` (16 random hex characters, so no blob ever repeats). A lease that
  vanishes between the read and the swap is claimed afresh.
- ``renew`` is a CAS against ``--expect``: a live lease keeps its claim (gen + 1, a new
  ``ts``); an expired one goes through the claim path, overlap check included.
- ``transfer`` changes the owner (and role) of a live lease by CAS; ``release`` deletes
  by CAS; ``gc`` deletes expired leases by CAS. Neither needs owner proof.
- Every write learns its blob's object id before the ref is touched, so when git fails
  and the ref then holds that id (a lost acknowledgement), the write succeeded.
- ``ts`` is the writer's UTC epoch seconds and ``ttl_s`` at most a day. A lease expires
  at ``ts + ttl_s``; ``clock_skew`` flags a ``ts`` more than 300 s ahead of the reader,
  and such a lease still counts as live.

**Events.** The events log's kinds are fixed: every lease change writes a
``lease_claimed`` row whose ``result`` names it (claimed, taken_over, renewed,
transferred, released, collected; a release or collection records the caller's label),
and a refused claim writes ``lease_denied`` with ``reason`` overlap or taken. An event
that cannot be written is a warning on the change, never a failure.

**team.json** (committed, optional): ``{"v":1,"shared":[globs],"lanes":{"<lane>":[globs]}}``.
``shared`` globs may be changed by any lane; ``lanes`` are committed per-lane path sets.
Globs mean what ``aegis_core.match`` says, so ``"CHANGELOG.md"`` also admits
``docs/CHANGELOG.md``. Parsing is strict and never quotes the file's own text.

**Metrics.** ``event_counts`` counts claims and denials from the events log;
``merge_metrics`` counts, per first-parent merge since a base, whether both sides changed
a common path and whether ``git merge-tree`` reports a conflict.
"""
from __future__ import annotations

from dataclasses import dataclass
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import time
import types
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import events, gitsafe
from aegis_core.config import MAX_CONFIG_BYTES, ConfigError, read_capped
from aegis_core.errors import AegisError, AegisValidationError
from aegis_core.match import normalize_path, sets_overlap
from aegis_core.primitives import DuplicateKeyError, is_within, strict_loads, utc_stamp
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = [
    "glob_problem",
    "CLOCK_SKEW_S",
    "DEFAULT_ROLE",
    "DEFAULT_TTL_S",
    "LABEL_MAX",
    "LANES_REF",
    "LANE_GRAMMAR",
    "LEASE_NOTE",
    "MAX_LEASE_BYTES",
    "MAX_TTL_S",
    "TEAM_FILE",
    "GcResult",
    "Lease",
    "LeaseChange",
    "LeaseFormatError",
    "LeaseRefused",
    "LeaseSet",
    "TeamFileError",
    "TeamPolicy",
    "TeamUsageError",
    "Unreadable",
    "claim",
    "default_owner",
    "describe",
    "event_counts",
    "gc",
    "lane_ref",
    "lease_view",
    "live_lease",
    "load_team",
    "load_team_at",
    "merge_metrics",
    "parse_lease",
    "parse_team",
    "read_leases",
    "release",
    "renew",
    "transfer",
    "valid_lane",
]

TEAM_FILE = f"{AEGIS_DIRNAME}/team.json"  # repo-relative POSIX, as git names it
TEAM_VERSION = 1
LEASE_VERSION = 1
LANES_REF = "refs/aegis/lanes"
LANE_GRAMMAR = "[a-z0-9][a-z0-9._-]{0,62}"
MAX_TTL_S = 86400
DEFAULT_TTL_S = 3600
DEFAULT_ROLE = "implementer"
CLOCK_SKEW_S = 300
LABEL_MAX = 200
MAX_LEASE_BYTES = MAX_CONFIG_BYTES
LEASE_NOTE = (
    "A lease is conflict input, not liveness proof: it records which paths a lane declared "
    "and until when, not that its agent is still working. The backstops are the post-lane "
    "gate (aegis check --lane) and aegis team metrics."
)

_LANE = re.compile(LANE_GRAMMAR)
_OID = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_CLAIM_ID = re.compile(r"\A[0-9a-f]{16}\Z")
# C0, DEL and C1: a terminal acts on them, and labels and globs are printed.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_TEAM_KEYS = frozenset({"v", "shared", "lanes"})
_LEASE_KEYS = ("v", "lane", "role", "owner", "claim_id", "gen", "branch", "paths", "ts", "ttl_s")
# The last second datetime can print (9999-12-31T23:59:59Z), less the longest lease.
_MAX_TS = 253402300799 - MAX_TTL_S
_CLAIM_ATTEMPTS = 3
_SYNTHETIC_MERGE = re.compile(r"\Arefs/(?:remotes/)?pull/[^/]+/merge\Z")


# ── Errors ───────────────────────────────────────────────────────────────────

class TeamFileError(ConfigError):
    """``.aegis/team.json`` cannot be used. The message is ``team.json: <reason>`` and never
    quotes the file's text: its keys and globs are repository-chosen."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"team.json: {reason}")
        self.reason = reason

    def __reduce__(self):  # rebuilt from the reason, not from the prefixed message
        return (type(self), (self.reason,))


class TeamUsageError(AegisValidationError):
    """A lane name, glob, ttl, label, expected object id or base that cannot be used;
    nothing was written."""


class LeaseFormatError(AegisValidationError):
    """A lease blob that is not a v1 lease of the lane its ref names."""


class LeaseRefused(AegisError):
    """A lease operation that was refused; nothing was written.

    ``reason``: ``overlap`` (``lanes`` names the live lanes in the way), ``taken`` (the
    lane holds a live or unreadable lease), ``stale`` (it holds something other than
    ``--expect``), ``absent`` (no lease), ``expired`` (a transfer of an expired lease) or
    ``unreadable``. ``current`` is the object id the lane's ref holds (None when
    absent), ``lease`` the lease it names when readable. ``warnings`` says when the
    refusal's event could not be recorded.
    """

    def __init__(self, message: str, reason: str, lane: str, current: Optional[str] = None,
                 lease: Optional["Lease"] = None, lanes: Sequence[str] = (),
                 warnings: Sequence[str] = ()) -> None:
        super().__init__(message, code="LEASE_REFUSED", reason=reason, lane=lane, current=current,
                         lease=lease, lanes=tuple(lanes), warnings=tuple(warnings))

    def __reduce__(self):  # every field, so a refusal crosses a process boundary intact
        return (type(self), (self.message, self.reason, self.lane, self.current, self.lease, self.lanes,
                             self.warnings))


# ── team.json ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TeamPolicy:
    """The usable content of ``.aegis/team.json``: ``shared`` globs any lane may change, and
    ``lanes`` (None when the file has none) mapping a lane to its committed globs. Globs
    are workspace-relative POSIX, each once."""

    shared: Tuple[str, ...] = ()
    lanes: Optional[Mapping[str, Tuple[str, ...]]] = None


def _policy_globs(value: object, where: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise TeamFileError(f"{where} must be a list of globs")
    out: List[str] = []
    for ordinal, glob in enumerate(value, 1):
        clean = normalize_path(glob) if isinstance(glob, str) else ""
        if not clean:
            raise TeamFileError(f"{where} glob {ordinal} must be a non-empty glob")
        if _CONTROL.search(clean):
            raise TeamFileError(f"{where} glob {ordinal} has a control character")
        if clean not in out:
            out.append(clean)
    return tuple(out)


def parse_team(data: bytes) -> TeamPolicy:
    """The policy in ``data`` (the bytes of a team.json). Raises TeamFileError for invalid
    UTF-8 or JSON (a duplicated key, NaN), a non-object, more than
    ``config.MAX_CONFIG_BYTES``, an unknown key, ``v`` other than the integer 1, a
    ``shared`` or lane entry that is not a list of non-empty globs, or a lane name
    outside the grammar. A UTF-8 byte order mark is accepted, as in config.json."""
    if len(data) > MAX_CONFIG_BYTES:
        raise TeamFileError(f"larger than {MAX_CONFIG_BYTES // 1024} KiB")
    try:
        text = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError:
        raise TeamFileError("not valid UTF-8") from None
    try:
        value = strict_loads(text)
    except DuplicateKeyError:  # before ValueError, which it is
        raise TeamFileError("duplicate key") from None
    except (ValueError, RecursionError):
        raise TeamFileError("not valid JSON") from None
    if not isinstance(value, dict):
        raise TeamFileError("must hold a JSON object")
    unknown = [key for key in value if key not in _TEAM_KEYS]
    if unknown:
        raise TeamFileError(f"{len(unknown)} unknown key(s)")
    version = value.get("v")
    if type(version) is not int or version != TEAM_VERSION:  # True == 1, but is no version
        raise TeamFileError(f"v must be {TEAM_VERSION}")
    shared = _policy_globs(value.get("shared", []), "shared")
    if "lanes" not in value:
        return TeamPolicy(shared=shared)
    lanes = value["lanes"]
    if not isinstance(lanes, dict):
        raise TeamFileError("lanes must be an object")
    parsed: Dict[str, Tuple[str, ...]] = {}
    for ordinal, (name, globs) in enumerate(lanes.items(), 1):
        if not valid_lane(name):
            raise TeamFileError(f"lanes entry {ordinal} has a name outside {LANE_GRAMMAR}")
        parsed[name] = _policy_globs(globs, f"lanes entry {ordinal}")
    return TeamPolicy(shared=shared, lanes=types.MappingProxyType(parsed))


def load_team(workspace: Any) -> TeamPolicy:
    """The working tree's ``.aegis/team.json`` (the default policy when there is none),
    read with config.json's file checks: a regular file (a FIFO is never waited on), at
    most ``MAX_CONFIG_BYTES``. Raises TeamFileError for a symlink, a file that resolves
    outside the workspace, an unreadable file or invalid content."""
    root = Path(os.fspath(workspace))
    path = root / TEAM_FILE
    if os.path.islink(path):
        raise TeamFileError("is a symlink")
    if os.path.lexists(path) and not is_within(path, root, unresolvable=False):
        raise TeamFileError("resolves outside the workspace")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except (FileNotFoundError, NotADirectoryError):
        return TeamPolicy()
    except OSError:
        raise TeamFileError("cannot be read") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TeamFileError("not a regular file")
        data = read_capped(fd, MAX_CONFIG_BYTES)
    except OSError:
        raise TeamFileError("cannot be read") from None
    finally:
        os.close(fd)
    return parse_team(data)


def _tree_file(root: Any, commit: str, path: str) -> Optional[Tuple[str, str, str, int]]:
    """(mode, type, object id, size; -1 when git gives none) of ``path`` at ``commit``,
    or None when the commit has no such entry."""
    res = gitsafe.run(["ls-tree", "-z", "-l", "--full-tree", commit, "--", path], root)
    if res.returncode != 0:
        raise gitsafe.GitError(f"git ls-tree failed for {path} at {commit}")
    record = res.stdout.partition(b"\0")[0]
    if not record:
        return None
    meta, _, name = record.partition(b"\t")
    parts = meta.decode("ascii", "replace").split()
    if len(parts) != 4 or os.fsdecode(name) != path:
        raise gitsafe.GitError(f"git ls-tree gave an unreadable entry for {path} at {commit}")
    mode, kind, oid, size = parts
    return mode, kind, oid, int(size) if size.isdigit() else -1


def load_team_at(root: Any, ref: str) -> TeamPolicy:
    """The ``.aegis/team.json`` committed at ``ref`` (the default policy when that commit
    has none), never the working tree's. Raises TeamFileError for a symlink or non-file
    entry, a blob over ``MAX_CONFIG_BYTES`` (refused before it is read) or invalid
    content, and GitError when ``ref`` names no commit or git fails."""
    commit = gitsafe.resolve_commit(root, ref) if isinstance(ref, str) else None
    if not commit:
        raise gitsafe.GitError(f"cannot resolve {ref!r} to a commit")
    entry = _tree_file(root, commit, TEAM_FILE)
    if entry is None:
        return TeamPolicy()
    mode, kind, oid, size = entry
    if mode == "120000":
        raise TeamFileError(f"is a symlink at {ref}")
    if kind != "blob":
        raise TeamFileError(f"is not a file at {ref}")
    if size > MAX_CONFIG_BYTES:
        raise TeamFileError(f"larger than {MAX_CONFIG_BYTES // 1024} KiB at {ref}")
    return parse_team(gitsafe.read_object(root, oid, MAX_CONFIG_BYTES))


# ── Names, labels, globs ─────────────────────────────────────────────────────

def valid_lane(name: object) -> bool:
    """Whether ``name`` is a lane name: ``[a-z0-9][a-z0-9._-]{0,62}``, and one git accepts
    as a ref component (no ``..``, not ending in ``.`` or ``.lock``)."""
    return (
        isinstance(name, str)
        and _LANE.fullmatch(name) is not None
        and ".." not in name
        and not name.endswith((".", ".lock"))
    )


def lane_ref(lane: object) -> str:
    """``refs/aegis/lanes/<lane>``; TeamUsageError for an invalid lane name."""
    if not valid_lane(lane):
        shown = repr(lane)
        raise TeamUsageError(
            f"invalid lane name: {shown[:80]} (use {LANE_GRAMMAR}, without '..', not ending in '.' or '.lock')"
        )
    return f"{LANES_REF}/{lane}"


def _label_ok(value: object, spaces: bool = True) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= LABEL_MAX
        and _CONTROL.search(value) is None
        and (spaces or not any(ch.isspace() for ch in value))
    )


def _check_label(value: object, what: str) -> str:
    if not _label_ok(value):
        raise TeamUsageError(f"{what} must be 1 to {LABEL_MAX} characters with no control characters")
    return value  # type: ignore[return-value]


def _check_branch(value: object) -> Optional[str]:
    if value is not None and not _label_ok(value, spaces=False):
        raise TeamUsageError(f"branch must be 1 to {LABEL_MAX} characters with no spaces or control characters")
    return value  # type: ignore[return-value]


def default_owner() -> str:
    """``<user>@<hostname>``: the label a claim or release carries when none is given."""
    try:
        user = getpass.getuser()
    except (KeyError, OSError, ImportError):  # no login name in the environment or passwd
        user = ""
    try:
        host = socket.gethostname()
    except OSError:
        host = ""
    label = _CONTROL.sub("", f"{user or 'unknown'}@{host or 'localhost'}")
    return label[:LABEL_MAX]


def glob_problem(glob: object) -> Optional[str]:
    if not isinstance(glob, str):
        return "not_text"
    if _CONTROL.search(glob):
        return "control"
    clean = normalize_path(glob)
    if not clean:
        return "empty"
    if ".." in clean.split("/"):
        return "climbs"
    return None


def _claim_paths(paths: object) -> Tuple[str, ...]:
    if not isinstance(paths, (list, tuple)):  # a lone string is one glob's characters
        raise TeamUsageError("paths: give a list of globs")
    if not paths:
        raise TeamUsageError("paths: give at least one glob")
    out: List[str] = []
    for ordinal, glob in enumerate(paths, 1):
        problem = glob_problem(glob)
        if problem:
            message = {"not_text": "is not text", "control": "has a control character",
                       "empty": "is empty", "climbs": "climbs out of the workspace with '..'"}[problem]
            raise TeamUsageError(f"paths: glob {ordinal} {message}")
        clean = normalize_path(glob)  # type: ignore[arg-type]
        if clean not in out:
            out.append(clean)
    return tuple(out)


def _ttl(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_TTL_S:  # type: ignore[operator]
        raise TeamUsageError(f"ttl must be a whole number of seconds from 1 to {MAX_TTL_S}")
    return value  # type: ignore[return-value]


def _expect(value: object) -> str:
    if not isinstance(value, str) or not _OID.match(value):
        raise TeamUsageError(
            "--expect must be a full object id (40 or 64 lowercase hex characters), "
            "as claim, renew, transfer and list print it"
        )
    return value


def _repository(root: Any) -> Path:
    path = Path(os.fspath(root))
    if gitsafe.common_dir(path) is None:
        raise TeamUsageError("not in a git repository: aegis team keeps leases in git refs")
    return path


def _now(now: Optional[int]) -> int:
    return int(time.time()) if now is None else int(now)


# ── Leases ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Lease:
    """One parsed lease and the blob ``oid`` it was read from (or written as)."""

    lane: str
    role: str
    owner: str
    claim_id: str
    gen: int
    branch: Optional[str]
    paths: Tuple[str, ...]
    ts: int
    ttl_s: int
    oid: str

    @property
    def expires_at(self) -> int:
        return self.ts + self.ttl_s

    def expired(self, now: int) -> bool:
        return now >= self.expires_at

    def clock_skew(self, now: int) -> bool:
        """The writer's clock was more than CLOCK_SKEW_S ahead of ``now``."""
        return self.ts > now + CLOCK_SKEW_S


def _blob(lane: str, role: str, owner: str, claim_id: str, gen: int, branch: Optional[str],
          paths: Sequence[str], ts: int, ttl_s: int) -> bytes:
    fields = {
        "v": LEASE_VERSION, "lane": lane, "role": role, "owner": owner, "claim_id": claim_id, "gen": gen,
        "branch": branch, "paths": list(paths), "ts": ts, "ttl_s": ttl_s,
    }
    data = (json.dumps(fields, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_LEASE_BYTES:
        raise TeamUsageError(f"paths: the lease would be larger than {MAX_LEASE_BYTES // 1024} KiB")
    return data


def _whole(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high  # type: ignore[operator]


def parse_lease(data: bytes, lane: str, oid: str) -> Lease:
    """The v1 lease in ``data`` for ``lane``. Raises LeaseFormatError for anything else:
    not a UTF-8 JSON object, other keys, another version or lane, a label with control
    characters, a ``claim_id`` that is not 16 lowercase hex characters, ``gen`` below 1,
    no or invalid ``paths``, a ``ts`` or ``ttl_s`` out of range."""
    if len(data) > MAX_LEASE_BYTES:
        raise LeaseFormatError(f"larger than the {MAX_LEASE_BYTES // 1024} KiB cap")
    try:
        value = strict_loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise LeaseFormatError("not a JSON lease") from None
    if not isinstance(value, dict):
        raise LeaseFormatError("not a JSON object")
    if sorted(value) != sorted(_LEASE_KEYS):
        raise LeaseFormatError("its keys are not the v1 lease keys")
    if type(value["v"]) is not int or value["v"] != LEASE_VERSION:
        raise LeaseFormatError(f"v is not {LEASE_VERSION}")
    if value["lane"] != lane:
        raise LeaseFormatError("the blob names a different lane")
    if not _label_ok(value["role"]) or not _label_ok(value["owner"]):
        raise LeaseFormatError("role and owner must be labels without control characters")
    if not isinstance(value["claim_id"], str) or not _CLAIM_ID.match(value["claim_id"]):
        raise LeaseFormatError("claim_id is not 16 lowercase hex characters")
    if not _whole(value["gen"], 1, 2 ** 53):
        raise LeaseFormatError("gen is not a whole number from 1")
    if value["branch"] is not None and not _label_ok(value["branch"], spaces=False):
        raise LeaseFormatError("branch is not a label")
    paths = value["paths"]
    if not isinstance(paths, list) or not paths or any(glob_problem(g) for g in paths):
        raise LeaseFormatError("paths is not a non-empty list of globs")
    if not _whole(value["ts"], 0, _MAX_TS):
        raise LeaseFormatError("ts is not a whole number of epoch seconds")
    if not _whole(value["ttl_s"], 1, MAX_TTL_S):
        raise LeaseFormatError(f"ttl_s is not from 1 to {MAX_TTL_S}")
    return Lease(lane=lane, role=value["role"], owner=value["owner"], claim_id=value["claim_id"],
                 gen=value["gen"], branch=value["branch"], paths=tuple(paths), ts=value["ts"],
                 ttl_s=value["ttl_s"], oid=oid)


@dataclass(frozen=True)
class Unreadable:
    """A ref under ``refs/aegis/lanes`` that holds no readable lease, and why."""

    lane: str
    ref: str
    oid: str
    error: str


@dataclass(frozen=True)
class LeaseSet:
    """Every ref under ``refs/aegis/lanes`` at one read, by lane name."""

    leases: Tuple[Lease, ...] = ()
    unreadable: Tuple[Unreadable, ...] = ()

    def get(self, lane: str) -> Optional[Lease]:
        return next((lease for lease in self.leases if lease.lane == lane), None)

    def unreadable_lane(self, lane: str) -> Optional[Unreadable]:
        return next((bad for bad in self.unreadable if bad.lane == lane), None)


def _read_one(root: Any, lane: str, oid: str) -> Lease:
    return parse_lease(gitsafe.read_object(root, oid, MAX_LEASE_BYTES), lane, oid)


def read_leases(root: Any) -> LeaseSet:
    """Every lease, sorted by lane; refs whose name is no lane, or whose blob is missing,
    too large or no v1 lease of that lane, are ``unreadable``. Reads only. Raises
    GitError when git cannot list the refs."""
    leases: List[Lease] = []
    unreadable: List[Unreadable] = []
    for ref, oid in gitsafe.list_refs(root, LANES_REF):
        lane = ref[len(LANES_REF) + 1:]
        if not valid_lane(lane):
            unreadable.append(Unreadable(lane, ref, oid, "not a lane name"))
            continue
        try:
            leases.append(_read_one(root, lane, oid))
        except (gitsafe.GitError, LeaseFormatError, ValueError) as exc:
            unreadable.append(Unreadable(lane, ref, oid, str(exc)))
    return LeaseSet(tuple(leases), tuple(unreadable))


def live_lease(root: Any, lane: str, now: Optional[int] = None) -> Optional[Lease]:
    """``lane``'s lease when it is readable and not expired at ``now``, else None."""
    lane_ref(lane)
    lease = read_leases(root).get(lane)
    return lease if lease is not None and not lease.expired(_now(now)) else None


def _lease_at(root: Any, lane: str, oid: Optional[str]) -> Optional[Lease]:
    if oid is None:
        return None
    try:
        return _read_one(root, lane, oid)
    except (gitsafe.GitError, LeaseFormatError, ValueError):
        return None


def _overlapping(found: LeaseSet, lane: str, paths: Sequence[str], now: int) -> Tuple[str, ...]:
    """The other lanes a claim of ``paths`` may collide with: live leases whose paths may
    overlap, and every unreadable lease of a valid lane name (unsure means conflict)."""
    hits: Set[str] = {
        other.lane for other in found.leases
        if other.lane != lane and not other.expired(now) and sets_overlap(other.paths, paths)
    }
    hits.update(bad.lane for bad in found.unreadable if bad.lane != lane and valid_lane(bad.lane))
    return tuple(sorted(hits))


def lease_view(lease: Lease, now: int, overlaps: Iterable[str]) -> Dict[str, Any]:
    """A lease as ``aegis team list --json`` reports it."""
    return {
        "lane": lease.lane,
        "role": lease.role,
        "owner": lease.owner,
        "claim_id": lease.claim_id,
        "gen": lease.gen,
        "oid": lease.oid,
        "branch": lease.branch,
        "paths": list(lease.paths),
        "expires_at": utc_stamp(lease.expires_at),
        "clock_basis": {"clock": "writer_utc", "ts": lease.ts, "ttl_s": lease.ttl_s},
        "expired": lease.expired(now),
        "clock_skew": lease.clock_skew(now),
        "overlaps": list(overlaps),
    }


def describe(root: Any, now: Optional[int] = None) -> Dict[str, Any]:
    """Every lease's view (``overlaps``: the live lanes whose paths may intersect it) and
    every unreadable lane ref. Side-effect free."""
    repo = _repository(root)
    moment = _now(now)
    found = read_leases(repo)
    live = [lease for lease in found.leases if not lease.expired(moment)]
    views = [
        lease_view(lease, moment, sorted(
            other.lane for other in live if other.lane != lease.lane and sets_overlap(other.paths, lease.paths)
        ))
        for lease in found.leases
    ]
    unreadable = [{"lane": bad.lane, "ref": bad.ref, "oid": bad.oid, "error": bad.error} for bad in found.unreadable]
    return {"leases": views, "unreadable": unreadable}


# ── Writing leases ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LeaseChange:
    """One lease write. ``action``: claimed, taken_over, renewed, transferred, released or
    collected. ``oid`` is the lane's new blob (None after a release or collection),
    ``previous`` the one it replaced, ``lease`` the new lease, ``caller`` the label a
    release or collection recorded, ``warnings`` events that could not be recorded."""

    action: str
    lane: str
    oid: Optional[str]
    previous: Optional[str]
    lease: Optional[Lease] = None
    caller: Optional[str] = None
    warnings: Tuple[str, ...] = ()


def _record(root: Path, kind: str, result: str, detail: Dict[str, Any]) -> Tuple[str, ...]:
    exc = events.try_append(root, kind, result, detail)
    if exc is not None:
        return (f"event not recorded: {exc}",)
    return ()


def _cas(root: Path, ref: str, new: Optional[str], old: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Swap ``ref`` from ``old`` to ``new`` (None: absent). (True, new) when the ref holds
    ``new`` afterwards, whether or not git acknowledged it; (False, current) when it holds
    something else. Raises GitError when git failed and the ref does not hold ``new``."""
    try:
        gitsafe.update_ref(root, ref, new, old)
    except gitsafe.RefConflict as exc:
        return exc.current == new, exc.current
    except gitsafe.RefNameError:
        raise
    except gitsafe.GitError:
        if gitsafe.read_ref(root, ref) == new:  # the write landed; its acknowledgement was lost
            return True, new
        raise
    return True, new


def _write(root: Path, lane: str, role: str, owner: str, claim_id: str, gen: int, branch: Optional[str],
           paths: Sequence[str], ts: int, ttl_s: int, old: Optional[str]) -> Tuple[bool, Optional[str], Lease]:
    """Store the lease blob (its object id is known before the ref is touched), then CAS
    the lane's ref from ``old`` to it."""
    data = _blob(lane, role, owner, claim_id, gen, branch, paths, ts, ttl_s)
    oid = gitsafe.write_blob(root, data)
    lease = Lease(lane=lane, role=role, owner=owner, claim_id=claim_id, gen=gen, branch=branch,
                  paths=tuple(paths), ts=ts, ttl_s=ttl_s, oid=oid)
    landed, holder = _cas(root, lane_ref(lane), oid, old)
    return landed, holder, lease


def _detail(lease: Lease, previous: Optional[str], **extra: Any) -> Dict[str, Any]:
    return {"lane": lease.lane, "oid": lease.oid, "previous": previous, "gen": lease.gen,
            "claim_id": lease.claim_id, "owner": lease.owner, "role": lease.role, **extra}


def _refuse_overlap(root: Path, found: LeaseSet, lane: str, paths: Sequence[str], now: int) -> None:
    lanes = _overlapping(found, lane, paths, now)
    if lanes:
        warnings = _record(root, "lease_denied", "refused", {"reason": "overlap", "lane": lane, "lanes": list(lanes)})
        raise LeaseRefused(f"overlap: lane {lane} may overlap live lease(s) of {', '.join(lanes)}",
                           "overlap", lane, lanes=lanes, warnings=warnings)


def _taken(root: Path, lane: str, current: str, lease: Optional[Lease]) -> LeaseRefused:
    warnings = _record(root, "lease_denied", "refused", {"reason": "taken", "lane": lane, "current": current})
    return LeaseRefused(f"taken: lane {lane} is leased (oid {current})", "taken", lane, current=current,
                        lease=lease, warnings=warnings)


def _stale(root: Path, lane: str, current: Optional[str], expect: str) -> LeaseRefused:
    if current is None:
        return LeaseRefused(f"absent: lane {lane} has no lease", "absent", lane)
    return LeaseRefused(f"stale: lane {lane} holds {current}, not {expect}", "stale", lane, current=current,
                        lease=_lease_at(root, lane, current))


def _expected(root: Path, found: LeaseSet, lane: str, expect: str) -> Lease:
    """``lane``'s lease when its ref holds ``expect``; LeaseRefused otherwise."""
    current, bad = found.get(lane), found.unreadable_lane(lane)
    holder = current.oid if current is not None else (bad.oid if bad is not None else None)
    if holder != expect:
        raise _stale(root, lane, holder, expect)
    if current is None:
        raise LeaseRefused(
            f"unreadable: lane {lane} holds {holder}, which is no readable lease; release it with --expect {holder}",
            "unreadable", lane, current=holder,
        )
    return current


def claim(root: Any, lane: str, paths: Sequence[str], role: Optional[str] = None, owner: Optional[str] = None,
          ttl_s: int = DEFAULT_TTL_S, branch: Optional[str] = None, now: Optional[int] = None) -> LeaseChange:
    """Claim ``lane`` for ``paths`` (see the module docstring). Raises TeamUsageError
    (nothing written), LeaseRefused (``overlap`` or ``taken``) or GitError."""
    ref = lane_ref(lane)
    globs = _claim_paths(paths)
    ttl = _ttl(ttl_s)
    label = _check_label(default_owner() if owner is None else owner, "owner")
    role = _check_label(DEFAULT_ROLE if role is None else role, "role")
    branch = _check_branch(branch)
    repo = _repository(root)
    moment = _now(now)
    for _ in range(_CLAIM_ATTEMPTS):
        found = read_leases(repo)
        _refuse_overlap(repo, found, lane, globs, moment)
        current, bad = found.get(lane), found.unreadable_lane(lane)
        if bad is not None:
            raise _taken(repo, lane, bad.oid, None)
        if current is not None and not current.expired(moment):
            raise _taken(repo, lane, current.oid, current)
        old = current.oid if current is not None else None
        gen = current.gen + 1 if current is not None else 1
        landed, holder, lease = _write(repo, lane, role, label, secrets.token_hex(8), gen, branch, globs,
                                       moment, ttl, old)
        if landed:
            action = "claimed" if old is None else "taken_over"
            warnings = _record(repo, "lease_claimed", action, _detail(lease, old))
            return LeaseChange(action, lane, lease.oid, old, lease, warnings=warnings)
        if holder is None:
            continue  # released or collected after it was read: claim it afresh
        raise _taken(repo, lane, holder, _lease_at(repo, lane, holder))
    raise gitsafe.GitError(f"{ref} kept changing while it was being claimed; try again")


def renew(root: Any, lane: str, expect: str, ttl_s: Optional[int] = None, now: Optional[int] = None) -> LeaseChange:
    """Renew ``lane``'s lease, which must be ``expect``: a live lease keeps its claim (gen
    + 1, ``ts`` now, ``ttl_s`` kept unless given); an expired one is re-claimed through
    the claim path (overlap check, new ``claim_id``). Raises TeamUsageError, LeaseRefused
    (``absent``, ``stale``, ``unreadable``, ``overlap``) or GitError."""
    lane_ref(lane)
    expect = _expect(expect)
    ttl = None if ttl_s is None else _ttl(ttl_s)
    repo = _repository(root)
    moment = _now(now)
    found = read_leases(repo)
    current = _expected(repo, found, lane, expect)
    was_expired = current.expired(moment)
    claim_id = current.claim_id
    if was_expired:
        _refuse_overlap(repo, found, lane, current.paths, moment)
        claim_id = secrets.token_hex(8)
    landed, holder, lease = _write(repo, lane, current.role, current.owner, claim_id, current.gen + 1,
                                   current.branch, current.paths, moment,
                                   current.ttl_s if ttl is None else ttl, expect)
    if not landed:
        raise _stale(repo, lane, holder, expect)
    warnings = _record(repo, "lease_claimed", "renewed", _detail(lease, expect, was_expired=was_expired))
    return LeaseChange("renewed", lane, lease.oid, expect, lease, warnings=warnings)


def transfer(root: Any, lane: str, expect: str, owner: str, role: Optional[str] = None,
             now: Optional[int] = None) -> LeaseChange:
    """Give ``lane``'s live lease (which must be ``expect``) to ``owner`` (and ``role``),
    keeping its claim, paths and expiry; gen + 1. Raises TeamUsageError, LeaseRefused
    (``absent``, ``stale``, ``unreadable``, ``expired``) or GitError."""
    lane_ref(lane)
    expect = _expect(expect)
    owner = _check_label(owner, "owner")
    if role is not None:
        _check_label(role, "role")
    repo = _repository(root)
    moment = _now(now)
    current = _expected(repo, read_leases(repo), lane, expect)
    if current.expired(moment):
        raise LeaseRefused(
            f"expired: lane {lane}'s lease expired at {utc_stamp(current.expires_at)}; claim or renew it instead",
            "expired", lane, current=current.oid, lease=current,
        )
    landed, holder, lease = _write(repo, lane, current.role if role is None else role, owner, current.claim_id,
                                   current.gen + 1, current.branch, current.paths, current.ts, current.ttl_s,
                                   expect)
    if not landed:
        raise _stale(repo, lane, holder, expect)
    warnings = _record(repo, "lease_claimed", "transferred", _detail(lease, expect, from_owner=current.owner))
    return LeaseChange("transferred", lane, lease.oid, expect, lease, warnings=warnings)


def _removed(root: Path, action: str, lane: str, previous: str, caller: str, owner: Optional[str]) -> LeaseChange:
    warnings = _record(root, "lease_claimed", action, {
        "lane": lane, "oid": None, "previous": previous, "caller": caller, "owner": owner})
    return LeaseChange(action, lane, None, previous, None, caller, warnings)


def release(root: Any, lane: str, expect: str, caller: Optional[str] = None) -> LeaseChange:
    """Delete ``lane``'s lease, which must be ``expect`` (readable or not). No owner proof:
    anyone may release, and the event records ``caller`` (default ``<user>@<hostname>``).
    Raises TeamUsageError, LeaseRefused (``absent``, ``stale``) or GitError."""
    ref = lane_ref(lane)
    expect = _expect(expect)
    label = _check_label(default_owner() if caller is None else caller, "caller")
    repo = _repository(root)
    current = gitsafe.read_ref(repo, ref)
    if current != expect:
        raise _stale(repo, lane, current, expect)
    lease = _lease_at(repo, lane, current)
    landed, holder = _cas(repo, ref, None, expect)
    if not landed:
        raise _stale(repo, lane, holder, expect)
    return _removed(repo, "released", lane, expect, label, lease.owner if lease is not None else None)


@dataclass(frozen=True)
class GcResult:
    """What ``gc`` deleted, and the lanes it left with why (``unreadable``, or ``changed
    after it was read`` when another writer renewed or replaced it meanwhile)."""

    collected: Tuple[LeaseChange, ...] = ()
    kept: Tuple[Tuple[str, str], ...] = ()


def gc(root: Any, now: Optional[int] = None, caller: Optional[str] = None) -> GcResult:
    """CAS-delete every expired lease; unreadable ones are left (their expiry is unknown;
    ``release`` takes them by oid). Each deletion records ``caller``."""
    label = _check_label(default_owner() if caller is None else caller, "caller")
    repo = _repository(root)
    moment = _now(now)
    found = read_leases(repo)
    collected: List[LeaseChange] = []
    kept: List[Tuple[str, str]] = [(bad.lane, "unreadable") for bad in found.unreadable]
    for lease in found.leases:
        if not lease.expired(moment):
            continue
        landed, _holder = _cas(repo, lane_ref(lease.lane), None, lease.oid)
        if landed:
            collected.append(_removed(repo, "collected", lease.lane, lease.oid, label, lease.owner))
        else:
            kept.append((lease.lane, "changed after it was read"))
    return GcResult(tuple(collected), tuple(sorted(kept)))


# ── Metrics ──────────────────────────────────────────────────────────────────

_CLAIMS = ("claimed", "taken_over")


def event_counts(root: Any) -> Dict[str, Any]:
    """Lease events from the log: ``claims`` (claimed or taken over), ``denials`` and
    their ``denials_by_reason``, every change ``by_result``, the distinct
    ``lanes_claimed``, the ``first`` and ``last`` row times, and ``unusable_rows``
    (torn, unparseable, another version, malformed). Reads only."""
    found = events.read(root, ("lease_claimed", "lease_denied"))
    by_result: Dict[str, int] = {}
    by_reason: Dict[str, int] = {}
    lanes: Set[str] = set()
    stamps: List[str] = []
    claims = denials = 0
    for row in found.rows:
        stamps.append(row["ts"])
        detail = row["detail"]
        if row["event"] == "lease_denied":
            denials += 1
            reason = detail.get("reason")
            key = reason if isinstance(reason, str) else "unknown"
            by_reason[key] = by_reason.get(key, 0) + 1
            continue
        result = row["result"]
        by_result[result] = by_result.get(result, 0) + 1
        if result in _CLAIMS:
            claims += 1
            if isinstance(detail.get("lane"), str):
                lanes.add(detail["lane"])
    return {
        "claims": claims,
        "denials": denials,
        "denials_by_reason": dict(sorted(by_reason.items())),
        "by_result": dict(sorted(by_result.items())),
        "lanes_claimed": len(lanes),
        "first": min(stamps) if stamps else None,
        "last": max(stamps) if stamps else None,
        "unusable_rows": found.skipped + int(found.torn_tail) + found.unknown_version + found.malformed,
        "error": found.error,
    }


def _synthetic_merges(root: Path) -> Set[str]:
    """Commits GitHub's ``refs/pull/<n>/merge`` (or actions/checkout's
    ``refs/remotes/pull/<n>/merge``) name: trial merges, never part of a branch."""
    found: Set[str] = set()
    for prefix in ("refs/pull", "refs/remotes/pull"):
        found.update(oid for name, oid in gitsafe.list_refs(root, prefix) if _SYNTHETIC_MERGE.match(name))
    return found


def _rev_list(root: Path, args: Sequence[str]) -> List[List[str]]:
    res = gitsafe.run(["rev-list", *args], root)
    if res.returncode != 0:
        raise gitsafe.GitError(f"git rev-list failed in {root}")
    return [line.split() for line in os.fsdecode(res.stdout).splitlines() if line.strip()]


def _changed_paths(root: Path, base: str, side: str) -> Set[str]:
    return {entry[3] for entry in gitsafe.diff_entries(root, base, side)}


def _both_sides_changed(root: Path, parents: Sequence[str]) -> Optional[bool]:
    """Whether the first parent and another parent both changed a path since their merge
    base; None when they share no history."""
    first = parents[0]
    for other in parents[1:]:
        base = gitsafe.merge_base(root, first, other)
        if base is None:
            return None
        ours = _changed_paths(root, base, first)
        if ours and ours & _changed_paths(root, base, other):
            return True
    return False


def merge_metrics(root: Any, base: Optional[str] = None) -> Dict[str, Any]:
    """Per first-parent merge on the current branch since ``base``, oldest first:
    ``overlapping`` (both sides changed a common path since the merge base) and
    ``conflicting`` (``git merge-tree --write-tree`` reports a conflict; None and
    ``conflicting_merge: "unavailable"`` when git cannot say, as before 2.38). A merge
    of unrelated histories has neither answer (both None) and counts in neither.

    Without ``base`` the branch base is resolved as ``aegis check --lane`` resolves it
    (``gitsafe.resolve_base_ref``); with none found, the whole first-parent history
    counts. A HEAD that is GitHub's synthetic pull-request merge is replaced by the pull
    request's head, and synthetic merges are never counted. Reads refs only (the trial
    merges store unreferenced objects). Raises TeamUsageError for a base that names no
    commit, GitError when git fails."""
    repo = _repository(root)
    if base is None:
        base = gitsafe.resolve_base_ref(repo)
    base_commit = None
    if base is not None:
        base_commit = gitsafe.resolve_commit(repo, base) if isinstance(base, str) else None
        if not base_commit:
            raise TeamUsageError(f"cannot resolve --base {base!r} to a commit")
    head = gitsafe.head_commit(repo)
    synthetic = _synthetic_merges(repo) if head is not None else set()
    tip, synthetic_head, excluded = head, False, 0
    if head is not None and head in synthetic:
        parents = _rev_list(repo, ["--no-walk", "--parents", head])[0][1:]
        if len(parents) >= 2:
            tip, synthetic_head, excluded = parents[1], True, 1
    merges: List[Dict[str, Any]] = []
    unavailable: Optional[str] = None
    if tip is not None:
        args = ["--first-parent", "--merges", "--parents", "--reverse", tip]
        if base_commit:
            args.append(f"^{base_commit}")
        for commit, *parents in _rev_list(repo, [*args, "--"]):
            if commit in synthetic:
                excluded += 1
                continue
            overlapping = _both_sides_changed(repo, parents)
            conflicting: Optional[bool] = None
            # Unrelated histories have no merge base, and merge-tree refuses to merge them.
            if unavailable is None and overlapping is not None:
                try:
                    conflicting = any(gitsafe.merge_tree_conflicted(repo, parents[0], p) for p in parents[1:])
                except gitsafe.MergeTreeUnavailable as exc:
                    unavailable = str(exc)
            merges.append({"commit": commit, "parents": parents, "overlapping": overlapping,
                           "conflicting": conflicting})
    if unavailable is not None:
        for merge in merges:
            merge["conflicting"] = None
    return {
        "range": {"base": base, "base_commit": base_commit, "head": head, "tip": tip,
                  "synthetic_head": synthetic_head},
        "count": len(merges),
        "overlapping_merge": sum(1 for m in merges if m["overlapping"] is True),
        "conflicting_merge": "unavailable" if unavailable is not None else sum(
            1 for m in merges if m["conflicting"] is True),
        "conflicting_unavailable": unavailable,
        "excluded_synthetic": excluded,
        "merges": merges,
    }
