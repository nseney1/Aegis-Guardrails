"""aegis skills sync — copy the packaged skills into the hosts' project skills directories.

v4.1 spec §3. Each packaged ``skills/<id>/SKILL.md`` goes to ``<skills_dir>/<id>/SKILL.md``
for every selected host with a ``skills_dir`` in the host table: ``.claude/skills``
(Claude Code, rendered with its slot profile) and ``.agents/skills`` (read by Codex CLI
and Antigravity alike, so rendered with the neutral ``generic`` profile). A directory
read by one host only takes that host's profile, so a copy is the same bytes whichever
host asked for it, on any machine (user slot overrides are not applied: the copies are
committed files).

A copy is the source with its frontmatter reduced to ``name: <id>`` and the source's
``description`` lines verbatim, the marker ``<!-- aegis:skill id=<id> v=1 sha=<12 hex> -->``
right after the closing ``---``, and the body with its slots rendered, otherwise byte for
byte (line endings included). The sha is the sha256 of the LF-normalized copy without the
marker line, so it covers the description (the line users tune most) as well as the body.

An existing ``SKILL.md`` is replaced only when it is Aegis's unedited copy: the marker
names this id and version 1, its sha matches the rest of the file, and the frontmatter is
exactly ``name: <id>`` and a description. CRLF line endings and a leading UTF-8 byte
order mark, which git checkouts and some editors add, are no edit. A copy edited since is
skipped unless ``--force``; a file without the marker is the user's own and is never
replaced. Every
directory on the way must be a real directory exactly where it is in the workspace
(no symlink, junction or a path resolving anywhere else) and ``SKILL.md`` a regular file
with one link; ``--force`` never overrides those refusals.

Exit codes: 0 done (skipped files are reported), 1 a refusal, a failed write or a
packaged skill that cannot be projected, 2 usage or workspace error. A real run appends
one ``skills_sync`` event; ``--dry-run`` writes nothing at all. With --json, stdout
carries only the JSON document.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aegis_core import primitives
from aegis_cli import sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_cli.init import _host_option, _unwritable, packaged_dir
from aegis_core import hosts as host_table
from aegis_core.primitives import real_key

__all__ = ["RESULTS", "Entry", "SkillsCommand", "SyncResult", "TargetResult", "run_skills", "summary", "sync_skills"]

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2
MARKER_VERSION = 1
SHA_LEN = 12
SKILL_FILE = "SKILL.md"
#: Per-skill results, in the order the counts list them.
RESULTS = ("created", "updated", "unchanged", "overwritten", "skipped", "refused", "failed")
_SKILL_ID = re.compile(r"[a-z0-9-]+")
_MARKER = re.compile(r"<!-- aegis:skill id=([a-z0-9-]+) v=([0-9]+) sha=([0-9a-f]{%d}) -->" % SHA_LEN)
_DELIMITER = re.compile(r"---[ \t]*")
_LINES = re.compile(r"[^\n]*\n|[^\n]+\Z")
_DESCRIPTION_KEY = re.compile(r"description[ \t]*:")
_FORCE_NOTE = "even with --force"


@dataclass(frozen=True)
class _Skill:
    id: str
    eol: str
    description: Tuple[str, ...]  # the source's description lines, as written
    body: str                     # everything after the source's closing ---


@dataclass(frozen=True)
class _Target:
    dir: str
    hosts: Tuple[str, ...]
    profile: str
    verified: bool


@dataclass
class Entry:
    """What happened (or, in a dry run, would happen) to one skill in one directory."""

    id: str
    path: str  # workspace-relative, POSIX
    result: str
    reason: Optional[str] = None
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "path": self.path, "result": self.result, "reason": self.reason,
                "detail": self.detail}


@dataclass
class TargetResult:
    dir: str
    hosts: Tuple[str, ...]
    profile: str
    verified: bool
    entries: List[Entry] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        counts = {name: 0 for name in RESULTS}
        for entry in self.entries:
            counts[entry.result] += 1
        return counts

    def as_dict(self) -> Dict[str, Any]:
        return {"dir": self.dir, "hosts": list(self.hosts), "profile": self.profile,
                "skills_verified": self.verified, "skills": [e.as_dict() for e in self.entries]}


@dataclass
class SyncResult:
    hosts: List[str]
    targets: List[TargetResult]
    errors: List[str]
    warnings: List[str]
    dry_run: bool
    force: bool

    @property
    def counts(self) -> Dict[str, int]:
        per_target = [t.counts for t in self.targets]
        return {name: sum(c[name] for c in per_target) for name in RESULTS}

    @property
    def status(self) -> str:
        counts = self.counts
        if counts["failed"] or self.errors:
            return "failed"
        return "refused" if counts["refused"] else "ok"


# ── Text helpers ─────────────────────────────────────────────────────────────

def _lines(text: str) -> List[str]:
    """Lines split on LF only, each keeping its ending; joined they give ``text`` back."""
    return _LINES.findall(text)


def _is_delimiter(line: str) -> bool:
    return _DELIMITER.fullmatch(line.rstrip("\r\n")) is not None


def _closing(lines: Sequence[str]) -> Optional[int]:
    """Index of the line closing the frontmatter that opens ``lines``, or None."""
    if not lines or not _is_delimiter(lines[0]):
        return None
    return next((i for i in range(1, len(lines)) if _is_delimiter(lines[i])), None)


def _sha(text: str) -> str:
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()[:SHA_LEN]


def _parse_frontmatter(lines: Sequence[str]) -> Optional[Dict[str, Any]]:
    from aegis_core.yaml_engine.parser import parse_yaml_subset

    try:
        return parse_yaml_subset("".join(lines))
    except Exception:  # the parser raises several error types for malformed text
        return None


def _description_lines(lines: Sequence[str]) -> Tuple[str, ...]:
    """The ``description`` key's line and its indented continuation lines, as written."""
    start = next((i for i, line in enumerate(lines) if _DESCRIPTION_KEY.match(line)), None)
    if start is None:
        return ()
    end = start + 1
    while end < len(lines) and (lines[end][:1] in (" ", "\t") or not lines[end].strip()):
        end += 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return tuple(lines[start:end])


def _load_skill(path: Path) -> _Skill:
    """The packaged skill at ``path``; ValueError says why it cannot be projected."""
    skill_id = path.parent.name
    if not _SKILL_ID.fullmatch(skill_id):
        raise ValueError(f"skill id {skill_id!r} is not [a-z0-9-]")
    text = path.read_bytes().decode("utf-8")
    lines = _lines(text)
    close = _closing(lines)
    meta = _parse_frontmatter(lines[1:close]) if close is not None else None
    if meta is None:
        raise ValueError(f"skill {skill_id}: no readable frontmatter")
    if meta.get("id", skill_id) != skill_id:
        raise ValueError(f"skill {skill_id}: frontmatter id {meta.get('id')!r} differs from its directory")
    description = meta.get("description")
    raw = _description_lines(lines[1:close])
    eol = "\r\n" if lines[0].endswith("\r\n") else "\n"
    projected = _parse_frontmatter([f"name: {skill_id}{eol}", *raw])
    if (not isinstance(description, str) or not description.strip()
            or projected != {"name": skill_id, "description": description}):
        raise ValueError(f"skill {skill_id}: its description is not a string that can be copied verbatim")
    return _Skill(skill_id, eol, raw, "".join(lines[close + 1:]))


def _packaged_skills(source: Path) -> Tuple[List[_Skill], List[str]]:
    skills: List[_Skill] = []
    errors: List[str] = []
    paths = sorted(source.glob(f"*/{SKILL_FILE}")) if source.is_dir() else []
    for path in paths:
        try:
            skills.append(_load_skill(path))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            errors.append(f"packaged {path.parent.name}/{SKILL_FILE}: {exc}")
    if not paths:
        errors.append(f"no packaged skills in {source}; reinstall aegis-guardrails")
    return skills, errors


def _render(skill: _Skill, profile: str) -> bytes:
    from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES, SlotRegistry

    registry = SlotRegistry({**DEFAULT_SLOTS, **PLATFORM_SLOT_PROFILES[profile]}).sanitized()
    body = registry.resolve(skill.body, strict=False)
    eol = skill.eol
    head = f"---{eol}name: {skill.id}{eol}{''.join(skill.description)}---{eol}"
    marker = f"<!-- aegis:skill id={skill.id} v={MARKER_VERSION} sha={_sha(head + body)} -->"
    return (head + marker + eol + body).encode("utf-8")


def _is_aegis_copy(data: bytes, skill_id: str) -> Optional[bool]:
    """True: Aegis's unedited copy. False: an Aegis copy edited since (or another id's,
    or another marker version). None: no marker right after the frontmatter, so the
    user's own file. The marker is found and the sha compared after a leading byte order
    mark is dropped and line endings are LF-normalized."""
    try:
        lines = _lines(data.decode("utf-8-sig"))
    except UnicodeDecodeError:
        return None
    close = _closing(lines)
    has_marker_line = close is not None and close + 1 < len(lines)
    marker = _MARKER.fullmatch(lines[close + 1].rstrip("\r\n")) if has_marker_line else None
    if marker is None:
        return None
    meta = _parse_frontmatter(lines[1:close])
    return (marker.group(1) == skill_id and marker.group(2) == str(MARKER_VERSION)
            and marker.group(3) == _sha("".join(lines[:close + 1] + lines[close + 2:]))
            and meta is not None and set(meta) == {"name", "description"} and meta["name"] == skill_id)


# ── Hosts and targets ────────────────────────────────────────────────────────

def _targets(hosts: Sequence[str]) -> Tuple[List[_Target], List[str]]:
    """The skills directories of ``hosts`` (in their order) and why any host has none."""
    notes: List[str] = []
    by_dir: Dict[str, List[host_table.HostSpec]] = {}
    for host_id in hosts:
        try:
            spec = host_table.get(host_id)
        except KeyError:
            notes.append(f"unknown host {host_id!r} ignored")
            continue
        if spec.retired:
            notes.append(spec.retired)
        elif spec.skills_dir is None:
            notes.append(f"{host_id} reads no project skills; nothing to copy for it")
        else:
            by_dir.setdefault(spec.skills_dir, []).append(spec)
    targets = []
    for directory, specs in by_dir.items():
        readers = [h for h in host_table.all_hosts() if h.skills_dir == directory and not h.retired]
        profile = specs[0].slot_profile if len(readers) == 1 else host_table.GENERIC
        targets.append(_Target(directory, tuple(h.id for h in specs), profile,
                               all(h.skills_verified for h in specs)))
    return targets, notes


# ── Safety checks and the write ──────────────────────────────────────────────

class _Refusal(Exception):
    """A path Aegis does not write through; ``--force`` never overrides it."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


def _is_link(path: Path) -> bool:
    # A Windows junction is no link to islink, and isjunction exists only from Python
    # 3.12; the realpath comparison in _check_dirs refuses one on older versions too.
    isjunction = getattr(os.path, "isjunction", None)
    return os.path.islink(path) or bool(isjunction and isjunction(path))


def _check_dirs(root: Path, parts: Sequence[str]) -> None:
    """Raise _Refusal unless every existing directory on ``root/parts`` is a real directory
    exactly there inside the workspace: no link or junction, nothing but a directory, and
    a realpath key (``primitives.real_key``) equal to the workspace's plus these parts; one that cannot
    be resolved is refused. Missing directories are fine; the write creates them."""
    expected = real_key(root)
    current = root
    for depth, part in enumerate(parts, 1):
        current = current / part
        expected = None if expected is None else expected + os.sep + os.path.normcase(part)
        rel = "/".join(parts[:depth])
        if _is_link(current):
            raise _Refusal("link", f"{rel} is a link (symlink or junction); Aegis never writes through a link, "
                                   f"{_FORCE_NOTE}")
        if not os.path.lexists(current):
            return
        if not os.path.isdir(current):
            raise _Refusal("not_directory", f"{rel} is not a directory; left as it is")
        if expected is None or real_key(current) != expected:
            raise _Refusal("outside", f"{rel} resolves to {os.path.realpath(current)}, not a real directory inside "
                                      f"the workspace (a junction or link); Aegis never writes through it, {_FORCE_NOTE}")


def _file_state(path: Path, rel: str) -> Tuple[Optional[bytes], bool]:
    """``(bytes, read-only)`` of the SKILL.md at ``path`` (``(None, False)`` when missing);
    _Refusal unless it is a regular file with one link that can be read."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, False
    except OSError as exc:
        raise _Refusal("unreadable", f"{rel} cannot be read ({exc.strerror or exc})") from exc
    if stat.S_ISLNK(st.st_mode):
        raise _Refusal("link", f"{rel} is a symlink; Aegis never writes through a link, {_FORCE_NOTE}")
    if not stat.S_ISREG(st.st_mode):
        raise _Refusal("not_regular", f"{rel} is not a regular file; left as it is")
    if st.st_nlink > 1:
        raise _Refusal("hard_link", f"{rel} has another hard link; replacing it would split the link, {_FORCE_NOTE}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise _Refusal("unreadable", f"{rel} cannot be read ({exc.strerror or exc})") from exc
    # os.replace swaps a read-only file as readily as any other, so the bit is honored here.
    return data, not st.st_mode & _WRITE_BITS


def _sync_one(root: Path, target: _Target, skill: _Skill, *, force: bool, dry_run: bool) -> Entry:
    parts = (*target.dir.split("/"), skill.id)
    rel = "/".join(parts) + "/" + SKILL_FILE
    path = root.joinpath(*parts, SKILL_FILE)
    entry = Entry(skill.id, rel, "refused")
    try:
        _check_dirs(root, parts)
        existing, read_only = _file_state(path, rel)
    except _Refusal as refusal:
        entry.reason, entry.detail = refusal.reason, refusal.detail
        return entry
    data = _render(skill, target.profile)
    if existing is None:
        entry.result = "created"
    elif existing == data:
        entry.result = "unchanged"
        return entry
    else:
        ours = _is_aegis_copy(existing, skill.id)
        if ours is None:
            entry.result, entry.reason = "skipped", "foreign"
            entry.detail = f"not an Aegis copy (no aegis:skill marker): your own file, never replaced, {_FORCE_NOTE}"
            return entry
        if not ours and not force:
            entry.result, entry.reason = "skipped", "edited"
            entry.detail = "edited since Aegis wrote it; left as it is (aegis skills sync --force replaces it)"
            return entry
        entry.result = "updated" if ours else "overwritten"
    if read_only:
        entry.result, entry.reason = "refused", "read_only"
        entry.detail = f"{rel} is read-only; left as it is, {_FORCE_NOTE}"
        return entry
    if dry_run:
        # A dry run (init's check pass among them) predicts the write's failure, so init
        # stops before its first write; a real run reports what the OS says instead.
        unwritable = _unwritable(path.parent)
        if unwritable:
            entry.result, entry.reason = "failed", "write"
            entry.detail = f"{rel} cannot be written ({unwritable})"
        return entry
    from aegis_core.storage import atomic_write_bytes

    # atomic_write_bytes makes the missing directories and replaces the file whole, so a
    # reader never sees a partial copy. It resolves the path, so a link planted between the
    # checks above and this call would be followed: only a concurrent local writer can win
    # that race, and no portable stdlib call (no dir_fd/O_NOFOLLOW on Windows) closes it.
    try:
        atomic_write_bytes(path, data)
    except OSError as exc:
        entry.result, entry.reason = "failed", "write"
        entry.detail = f"{rel} could not be written ({exc.strerror or exc})"
    return entry


def _record(root: Path, result: SyncResult, trigger: str) -> None:
    from aegis_core import events

    detail = {"trigger": trigger, "hosts": list(result.hosts), "targets": [t.dir for t in result.targets],
              "force": result.force, "counts": result.counts}
    try:
        events.append(root, "skills_sync", result.status, detail)
    except Exception as exc:  # a metric never fails the sync (events.append documents what it raises)
        result.warnings.append(f"the skills_sync event could not be recorded ({type(exc).__name__}: {exc})")


def sync_skills(root: Path, hosts: Sequence[str], *, force: bool = False, dry_run: bool = False,
                source: Optional[Path] = None, trigger: str = "sync") -> SyncResult:
    """Copy the packaged skills (or those under ``source``) into the skills directories of
    ``hosts`` in the workspace ``root``. A real run with a target appends one
    ``skills_sync`` event; ``dry_run`` only classifies and writes nothing."""
    root = Path(root)
    targets, notes = _targets(hosts)
    skills, errors = _packaged_skills(Path(source) if source is not None else packaged_dir("skills"))
    result = SyncResult(list(hosts), [], errors, notes, dry_run, force)
    for target in targets:
        done = TargetResult(target.dir, target.hosts, target.profile, target.verified)
        done.entries = [_sync_one(root, target, skill, force=force, dry_run=dry_run) for skill in skills]
        result.targets.append(done)
    if targets and not dry_run:
        _record(root, result, trigger)
    return result


def summary(counts: Dict[str, int]) -> str:
    """``15 created, 1 skipped``: the non-zero counts, in RESULTS order."""
    return ", ".join(f"{counts[name]} {name}" for name in RESULTS if counts[name]) or "no skills"


# ── The command ──────────────────────────────────────────────────────────────

_ICONS = {"skipped": "⚠️ ", "refused": "❌", "failed": "❌"}
_SHOWN = 300  # characters of a detail, warning or error the text output shows
_DRY = {"created": "would create", "updated": "would update", "overwritten": "would overwrite"}


def _print_text(result: SyncResult) -> None:
    for target in result.targets:
        label = "" if target.verified else ", unverified: not checked on a real install"
        print(f"{target.dir}/ for {', '.join(target.hosts)} ({target.profile} wording{label})")
        unchanged = 0
        for entry in target.entries:
            if entry.result == "unchanged":
                unchanged += 1
                continue
            verb = _DRY.get(entry.result, entry.result) if result.dry_run else entry.result
            detail = f" ({sanitize_display(entry.detail, _SHOWN)})" if entry.detail else ""
            print(f"  {_ICONS.get(entry.result, '✅')} {entry.id}: {verb}{detail}")
        if unchanged:
            print(f"  {unchanged} unchanged")
    for warning in result.warnings:
        print(f"⚠️  {sanitize_display(warning, _SHOWN)}", file=sys.stderr)
    for error in result.errors:
        print(f"❌ {sanitize_display(error, _SHOWN)}", file=sys.stderr)
    if result.dry_run:
        print(f"Dry run: {summary(result.counts)}; nothing was written.")
    else:
        print(f"Done: {summary(result.counts)}.")


def _hosts(args: argparse.Namespace, root: Path) -> Tuple[Optional[List[str]], str]:
    """The hosts to sync for, or (None, why not)."""
    from aegis_cli.install_hosts import detect_hosts, ordered_hosts
    from aegis_core.config import ConfigError, RepoConfig

    chosen = getattr(args, "host", None)
    if chosen == "auto":
        detected = detect_hosts(Path.home(), os.environ.get("PATH"))
        return (detected, "") if detected else (None, "no host detected on this machine; name one with --host")
    if chosen:
        return list(chosen), ""
    try:
        configured = list(RepoConfig.load(root).hosts)
    except ConfigError as exc:
        return None, f"{exc}; fix it, or name the hosts with --host"
    return ordered_hosts(configured), ""


def run_skills(args: argparse.Namespace) -> int:
    from aegis_core.workspace.layout import is_aegis_workspace

    ws = getattr(args, "ws", None)
    root = Path(ws.root if ws is not None else getattr(args, "_project_root", Path.cwd()))
    if not is_aegis_workspace(root):
        print(f"Error: not an Aegis workspace (no .aegis/ in {root}); run aegis init", file=sys.stderr)
        return EXIT_USAGE
    hosts, why = _hosts(args, root)
    if hosts is None:
        print(f"Error: {why}", file=sys.stderr)
        return EXIT_USAGE
    if not _targets(hosts)[0]:
        print(f"Error: no host to copy skills for{' (' + ', '.join(hosts) + ')' if hosts else ''}; name them "
              "with --host claude-code,codex-cli,antigravity or add them with aegis init --host", file=sys.stderr)
        return EXIT_USAGE

    result = sync_skills(root, hosts, force=bool(args.force), dry_run=bool(args.dry_run))
    if args.json:
        print(json.dumps({
            **primitives.envelope("aegis skills sync", {"workspace": str(root), "hosts": result.hosts, "targets": [t.dir for t in result.targets]}),
            "dry_run": result.dry_run,
            "force": result.force,
            "status": result.status,
            "targets": [t.as_dict() for t in result.targets],
            "counts": result.counts,
            "errors": result.errors,
            "warnings": result.warnings,
        }, indent=2))
    else:
        _print_text(result)
    return EXIT_OK if result.status == "ok" else EXIT_PROBLEMS


class SkillsCommand(AegisCommand):
    """Project the packaged skills into the hosts' project skills directories."""

    name = "skills"
    category = CommandCategory.SETUP
    help = "Copy the packaged skills into your hosts' project skills folders (sync)"

    def configure_parser(self, parser: argparse.ArgumentParser, parents: Any = None) -> None:
        sub = parser.add_subparsers(dest="skills_action", metavar="ACTION")
        sub.required = True
        p_sync = sub.add_parser(
            "sync", parents=parents or [],
            help="Copy the packaged skills to .claude/skills (Claude Code) and .agents/skills (Codex CLI, "
                 "Antigravity), replacing only Aegis's own unedited copies",
        )
        p_sync.add_argument(
            "--host", type=_host_option, default=None, metavar="HOST[,HOST]|auto",
            help="Hosts to copy skills for (default: the hosts in .aegis/config.json); "
                 "'auto' takes the ones detected on this machine",
        )
        p_sync.add_argument("--force", action="store_true",
                            help="Also replace Aegis copies edited by hand (never a file without the Aegis "
                                 "marker, a link or anything outside the workspace)")
        p_sync.add_argument("--dry-run", action="store_true", help="Report what would change; write nothing")

    def execute(self, args: argparse.Namespace) -> int:
        return run_skills(args)
