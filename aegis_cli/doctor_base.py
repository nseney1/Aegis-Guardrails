"""The shared substrate of ``aegis doctor``: its constants, the run context, the file readers and
parsers, the registration facts and the finding records every doctor module reads.

A leaf of the doctor family: it imports no other doctor module, writes no file and starts no
program (``aegis_cli.doctor`` is the one place doctor starts a host CLI). The seams tests patch
(``which``, ``only_skipped``, ``_present``, ``_stdin_is_tty``, ``_confirm``, ``_platform`` and
``_V3_SHIPPED_RULE_SHA256``) live here and the other modules read them as ``doctor_base.<name>``
at call time, never by value, so one patch reaches every reader.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_cli import stdin_is_tty as _stdin_is_tty
from aegis_core.pathlookup import Hit, is_bare, only_skipped, which
from aegis_core.primitives import real_key, strict_loads

SCHEMA = "aegis.doctor/v1"
SOURCE = "aegis doctor"
SERVER = "aegis"
# The v3 server name; v4 registers only "aegis" and doctor --fix removes this one.
LEGACY_SERVER = "soma"
# Hosts that silently keep only the start of an over-budget instruction file: Codex at
# its 32 KiB project_doc_max_bytes, Antigravity at 24,000 bytes per file (host-matrix
# §1-§2, verified 2026-10-15). A block that ends within the budget still arrives; for
# the other hosts the budget is advice.
_TRUNCATES_TAIL = frozenset({"codex-cli", "antigravity"})
# Hosts that send no MCP roots and attest no workspace: the registry is how the server
# finds the repository (host-matrix §2, §3.6).
_REGISTRY_BOUND = frozenset({"antigravity"})
# Hosts that read AGENTS.override.md instead of AGENTS.md at the same level.
_READS_AGENTS_OVERRIDE = frozenset({"codex-cli"})
_FIX_HINT = "aegis doctor --fix"
_LEGACY_ENTRY = f"stale v3 '{LEGACY_SERVER}' MCP server"

# A registered command, as doctor compares it: (host id, argv as the host config holds it).
Registered = Tuple[str, Sequence[str]]
ListItem = Tuple[Tuple[Any, ...], int]


# ── Workspace ───────────────────────────────────────────────────────────────

def _is_home(root: Path) -> bool:
    """Whether ``root`` is the home directory, whose ``.aegis/`` is the user plane."""
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout.current()
    key = real_key(root)
    return layout is not None and key is not None and key == real_key(layout.home)


def _setup_command(root: Path) -> str:
    """What sets governance up here: ``aegis migrate`` while an unmigrated v3 workspace is
    here (``aegis init`` would leave its rules unserved, and the check would then pass on
    none of them), else ``aegis init``."""
    from aegis_core.errors import WorkspaceError
    from aegis_core.workspace.discovery import refuse_unmigrated_v3

    try:
        refuse_unmigrated_v3(root)
    except WorkspaceError:
        return "aegis migrate"
    return "aegis init"


def _setup_fix(root: Path, purpose: str) -> str:
    if _setup_command(root) == "aegis migrate":
        return "Fix: Run 'aegis migrate' to see how this v3 workspace converts, then 'aegis migrate --apply'."
    return f"Fix: Run 'aegis init' to {purpose}."


def _home() -> Optional[Path]:
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout.current()
    return layout.home if layout else None


# ── Text ────────────────────────────────────────────────────────────────────

def _clean(text: Any, limit: int = 512) -> str:
    """A string from a file or a host's output, safe to print: no escape or control sequences."""
    from aegis_cli import sanitize_display

    return sanitize_display(str(text), max_len=limit)


def _aegis_version() -> str:
    from aegis_core._version import __version__
    return __version__


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Files ───────────────────────────────────────────────────────────────────

@dataclass
class _File:
    """One file as doctor read it, with the facts --fix needs to decide whether it may write."""

    path: Path
    raw: Optional[bytes] = None
    is_link: bool = False
    error: Optional[str] = None
    refusal: Optional[str] = None  # why --fix will not write it
    data: Any = None

    @property
    def exists(self) -> bool:
        return self.raw is not None or self.is_link or self.error is not None


def _write_refusal(path: Path, st: os.stat_result) -> Optional[str]:
    if stat.S_ISLNK(st.st_mode):
        return "it is a symlink, and Aegis never writes through a link"
    if not stat.S_ISREG(st.st_mode):
        return "it is not a regular file"
    if st.st_nlink > 1:
        return "it has another hard link, and replacing it would split the link"
    if not (st.st_mode & 0o222) or not os.access(str(path), os.W_OK):
        return "it is read-only"
    return None


def _read_file(path: Path) -> _File:
    entry = _File(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return entry
    except OSError as exc:
        entry.error = f"cannot be read ({exc.strerror or exc})"
        return entry
    entry.is_link = stat.S_ISLNK(st.st_mode)
    entry.refusal = _write_refusal(path, st)
    if entry.is_link and not path.is_file():
        entry.error = "is a symlink to no regular file"
        return entry
    if not entry.is_link and not stat.S_ISREG(st.st_mode):
        entry.error = "is not a regular file"
        return entry
    try:
        with open(path, "rb") as fh:
            entry.raw = fh.read()
    except OSError as exc:
        entry.error = f"cannot be read ({exc.strerror or exc})"
    return entry


def _parse_json(entry: _File) -> _File:
    if entry.raw is None or entry.error:
        return entry
    try:
        text = entry.raw.decode("utf-8")
        if text.startswith("\ufeff"):
            raise ValueError("starts with a byte-order mark")
        entry.data = strict_loads(text)
    except (UnicodeDecodeError, ValueError) as exc:
        entry.error = f"is not valid JSON ({str(exc)[:120]})"
        return entry
    except RecursionError:
        # A file nested past the parser's depth (a cloned repository's .mcp.json can be)
        # is as unreadable as a malformed one; it must not abort the whole report.
        entry.error = "is not valid JSON (nested too deeply to parse)"
        return entry
    if not isinstance(entry.data, dict):
        entry.error = "is not a JSON object"
        entry.data = None
    return entry


def _path_key(path: Path) -> str:
    """``path`` as written, made absolute and case-folded where the OS folds case."""
    return os.path.normcase(os.path.abspath(str(path)))


# ── The run context ─────────────────────────────────────────────────────────

@dataclass
class _Ctx:
    """What one doctor run looks at; files are read once."""

    root: Path
    governed: bool
    home: Optional[Path]
    environ: Mapping[str, str]
    selected: Tuple[Any, ...]
    selection: str
    # How the run asks a host whether aegis is registered: (host spec, the binary doctor may
    # run or None, the run) -> a registration. Only aegis_cli.doctor's probes start a host CLI.
    prober: Callable[[Any, Optional[str], "_Ctx"], Dict[str, Any]]
    is_home: bool = False
    # What sets this workspace up: aegis migrate while an unmigrated v3 workspace is here.
    setup: str = "aegis init"
    _cache: Dict[Tuple[str, bool], _File] = field(default_factory=dict)

    @property
    def path_env(self) -> str:
        return self.environ.get("PATH", "")

    def which(self, name: str) -> Optional[str]:
        return which(name, self.path_env, outside=self.root)

    def passed_over(self, name: str) -> List[Hit]:
        """Where ``name`` is when ``which`` refused every place: a relative or empty PATH
        entry (resolved against the workspace, where a host would start) or an absolute
        entry inside it. Never run."""
        return only_skipped(name, self.path_env, outside=self.root, base=self.root)

    def probe(self, spec: Any, binary: Optional[str]) -> Dict[str, Any]:
        """``spec``'s registration as the run's prober reads it (``binary``: the one it may run)."""
        return self.prober(spec, binary, self)

    def file(self, path: Path, as_json: bool = False) -> _File:
        key = (os.path.abspath(str(path)), as_json)
        if key not in self._cache:
            entry = _read_file(Path(path))
            self._cache[key] = _parse_json(entry) if as_json else entry
        return self._cache[key]

    def label(self, path: Path) -> str:
        """``~/x`` for a file under the home directory (as the docs name them), else the path."""
        if self.home is not None:
            try:
                return "~/" + Path(path).relative_to(self.home).as_posix()
            except ValueError:
                pass
        return str(path)


def _platform() -> str:
    """``sys.platform``, read in one place so a test can emulate another OS's app folders."""
    return sys.platform


def _app(spec: Any, ctx: _Ctx) -> Optional[str]:
    """The installed desktop app of ``spec`` (an app bundle is a directory), or None."""
    from aegis_core import hosts

    if ctx.home is None:
        return None
    return next((app for app in hosts.app_paths(spec, ctx.home, ctx.environ, _platform()) if os.path.isdir(app)),
                None)


def _plane_found(spec: Any, ctx: _Ctx) -> Optional[str]:
    """What shows ``spec``'s config plane is on this machine, for people: a binary doctor
    would run, a config path in the home directory or a desktop app; None when nothing does."""
    for name in spec.binaries:
        found = ctx.which(name)
        if found:
            return ctx.label(Path(found))
    if ctx.home is not None:
        for spec_path in spec.config_paths:
            rel = spec_path[2:] if spec_path.startswith("~/") else spec_path
            if os.path.exists(ctx.home.joinpath(*rel.split("/"))):
                return spec_path
    app = _app(spec, ctx)
    return ctx.label(Path(app)) if app else None


# ── Registration facts ──────────────────────────────────────────────────────

def _registration(status: str, source: str, **facts: Any) -> Dict[str, Any]:
    reg = {"status": status, "source": source, "scope": None, "command": None, "command_exists": None,
           "enabled": None, "approval": None, "detail": None, "aegis_client": None}
    reg.update(facts)
    return reg


def _entry_facts(entry: Any, ctx: _Ctx) -> Dict[str, Any]:
    """Command, AEGIS_CLIENT and enabled flag of one MCP server entry.

    The strings come from files a repository can write (a project .mcp.json), so the
    command is reported without control sequences; the existence check uses it as
    written, and AEGIS_CLIENT stays raw for the identity decision (``_identity`` cleans
    what it reports), since the server sees the raw value.
    """
    facts: Dict[str, Any] = {}
    if not isinstance(entry, dict):
        return facts
    command = entry.get("command")
    if isinstance(command, str) and command:
        args = entry.get("args") if isinstance(entry.get("args"), list) else []
        facts["command"] = [_clean(command)] + [_clean(a) for a in args]
        facts["command_exists"] = _command_exists(command, ctx)
    env = entry.get("env")
    if isinstance(env, dict) and isinstance(env.get("AEGIS_CLIENT"), str):
        facts["aegis_client"] = env["AEGIS_CLIENT"]
    if isinstance(entry.get("disabled"), bool):
        facts["enabled"] = not entry["disabled"]
    if isinstance(entry.get("enabled"), bool):
        facts["enabled"] = entry["enabled"]
    return facts


def _command_exists(command: str, ctx: _Ctx) -> Optional[bool]:
    """Whether the registered command exists; None when doctor cannot tell.

    A relative path with a directory part resolves against the directory the host starts
    the server in, which doctor does not know. A bare name found only through an empty or
    relative PATH entry, or in an absolute entry inside the workspace, is one the host
    may run but doctor does not count.
    """
    if os.path.isabs(command):
        return os.path.isfile(command) and (os.name == "nt" or os.access(command, os.X_OK))
    if not is_bare(command):
        return None
    if ctx.which(command) is not None:
        return True
    return None if ctx.passed_over(command) else False


def _present(path: Path) -> bool:
    """Whether a file is there, without reading it; True when that cannot be told, so an
    unreadable parent directory never lets doctor claim the bootstrap through."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (OSError, ValueError):
        return True


def _claude_dir(ctx: _Ctx) -> Optional[Path]:
    custom = ctx.environ.get("CLAUDE_CONFIG_DIR")
    if custom:
        return Path(custom)
    return ctx.home / ".claude" if ctx.home else None


def _claude_config(ctx: _Ctx) -> Optional[Path]:
    # Claude Code keeps its user and local MCP scopes in .claude.json: in the home
    # directory, or in CLAUDE_CONFIG_DIR when that is set.
    custom = ctx.environ.get("CLAUDE_CONFIG_DIR")
    if custom:
        return Path(custom) / ".claude.json"
    return ctx.home / ".claude.json" if ctx.home else None


def _desktop_configs(ctx: _Ctx) -> List[Path]:
    """Every claude_desktop_config.json location: v3 wrote ~/.config/Claude on every OS."""
    if ctx.home is None:
        return []
    found = [ctx.home / ".config" / "Claude" / "claude_desktop_config.json"]
    if sys.platform == "darwin":
        found.append(ctx.home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    elif os.name == "nt":
        appdata = ctx.environ.get("APPDATA")
        if appdata:
            found.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    else:
        xdg = ctx.environ.get("XDG_CONFIG_HOME", "")
        if xdg and os.path.isabs(xdg):
            found.append(Path(xdg) / "Claude" / "claude_desktop_config.json")
    unique: Dict[str, Path] = {}
    for path in found:
        unique.setdefault(os.path.normcase(os.path.abspath(str(path))), path)
    return list(unique.values())


def _host_json_path(spec: Any, ctx: _Ctx) -> Optional[Path]:
    reg = spec.registration
    if reg is None or reg.kind != "json_file" or ctx.home is None:
        return None
    rel = reg.path[2:] if reg.path.startswith("~/") else reg.path
    return ctx.home.joinpath(*rel.split("/"))


def _claude_project_keys(ctx: _Ctx) -> List[str]:
    keys = [str(ctx.root), ctx.root.as_posix()]
    return list(dict.fromkeys(keys))


def _names(value: Any) -> List[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _server_entry(data: Any, name: str = SERVER) -> Optional[Any]:
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers"), dict):
        return None
    return data["mcpServers"].get(name)


def _claude_user_registered(ctx: _Ctx) -> bool:
    path = _claude_config(ctx)
    if path is None:
        return False
    cfg = ctx.file(path, as_json=True)
    return not cfg.error and _server_entry(cfg.data) is not None


#: sha256 of every rules/*.md and rules/.oracles/*.md file shipped in the v3.0.0-v3.3.0
#: wheels, which v3's Gemini and Kiro adapters copied byte for byte into
#: ~/.gemini/config/rules and ~/.kiro/steering. Computed from the release tags with
#: ``git show vX:rules/<file> | sha256sum``. A copy is removed only on an exact match;
#: names and content are never compared (defense #39).
_V3_SHIPPED_RULE_SHA256 = frozenset({
    "acab95f21fc4eb254337fc84fe87dbcd8b059173fb56fe520f385224e27825a2",  # .oracles/architectural-tenets
    "af94c7153052c7488e0e67d86e780a74fdf106caf45da65244cc9fb9643130ba",  # .oracles/atomic-workstream-protocol
    "3d605fdfe36b2fbef771776c43c079dffbda2a593e71cb5f04175e23807fe9a2",  # .oracles/documentation
    "03a9e189a1c72f6178d9c1c5eb139fca008db810cd14eddc56400b014b9ce4db",  # .oracles/feature-specs
    "e5bc5f348d4e2cdf93457471c60b239ab6d64f2420e349f368e4995396c2afc5",  # .oracles/git-workflow
    "ca215d78f371e0f7aa4ad562a22be47db42e639d0cb28797dc7971157db0ddd8",  # .oracles/optional-import-guard (3.0)
    "63a857db70e56ceabda0fd07412f8924b128e227ec94b63d839497ef73b7152b",  # .oracles/optional-import-guard (3.1+)
    "ded22d86c5f47a0a13f64f9da99d543d276ddf830017b6a63f1c5a6e78b5c021",  # .oracles/polyglot-standards
    "337cee795219e24354a7850acebb9d79e6266e595ca7d31e4598d0d21b9e82f4",  # .oracles/tdd-protocol (3.0)
    "d33b2a6ebd2dc7c81ac3b98c060e52c38bb80baaf6362a3aea22900463af74c8",  # .oracles/tdd-protocol (3.1+)
    "863c28d335a31e48a1aef27c83b32dcab881029b3eb07a955e0b8eadd5d198e8",  # .oracles/testing
    "12d8813c7b251bc310e8122305c6ee7778fe01483dd4103691b26000a3369354",  # META (3.0)
    "4879bfb58b4a5bd3344e0278c815ce33b90ae746f694f6b82b52e87e80938582",  # META (3.1+)
    "f7ec0a8f721b64f8d37b5f259e64c86470d98a00dd3e535e68b4ab33813d486c",  # ci-green-before-release
    "20b2f3294ef1e9ceb23c4714c3d1ed95cd89f6828dd57230099da9e62fd43ecc",  # core-change-protocol (3.0)
    "8b85634178a5e121581ca98687c490c55c37a0dae4a36950866631fa215f2dcd",  # core-change-protocol (3.1+)
    "4b1656771eab2a652e0b41f221be1f5712565493506295edd3de06be44978e0c",  # cost-optimization (3.0)
    "db76ddf60f833f0b0070e0a811cdcd101e02ccc204956d6c62609e929ae13955",  # cost-optimization (3.1+)
    "25600eecc61dbd447e67ae9d43255425efbcf94195930b8c8ca11c771d26add5",  # desktop-automation
    "91fdf925befe794b662d882a069fe7035c5acf731e413d961b9e1c83d6432447",  # destructive-ops
    "2473444c146b5d36d0edefd74347e0175e76a355536ab5d5df51514b69ba7ed1",  # gitflow-review-gate (3.0)
    "18357403da55489f326c15dad044ded615badaea7b77f37aeb7757f163bdbb3a",  # gitflow-review-gate (3.1+)
    "2be52fdd2f290e1cbd81600e35d8198bc6766b5c827c0d1b240ce060470984fc",  # no-pre-existing-excuse (3.0)
    "5187404be379aca6b0cb0ec62436054ebfcad320c264a34ef95e271a42c95767",  # no-pre-existing-excuse (3.1+)
    "27b596123c2a88dea15b82a846e07215774e0b1dfdc2c3b67f2336b89d3fad3b",  # providence (3.0)
    "6417ece31939ece9e3f6fec52413d4f8c329fbf38be8c104b01b2f28ee0a5fe6",  # providence (3.1+)
    "04946d5d7b525f24284ae51f2d958f8b5fcc4d3ed891e391ceec71f5dd5ddd0f",  # subagent-delegation (3.0)
    "5d54ce9b04be9572698749908558800cbf2d8acdffc15e7b7a651fbf6f39488f",  # subagent-delegation (3.1+)
})


def _confirm(prompt: str) -> bool:
    """Ask on the terminal; anything but y/yes is no. Without a terminal the answer is no."""
    if not _stdin_is_tty():
        print("stdin is not a terminal, so nothing was applied: re-run with --yes to apply these changes.")
        return False
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


# ── Instruction files ───────────────────────────────────────────────────────

_BLOCK_BEGIN = re.compile(r"^<!-- aegis:begin id=(\S+) v=(\S+) sha=(\S+) -->[ \t]*$")
_BLOCK_END = re.compile(r"^<!-- aegis:end id=(\S+) -->[ \t]*$")
_HEX12 = re.compile(r"^[0-9a-f]{12}$")
# An import path runs to the next whitespace, so @AGENTS.md.bak names another file. A
# relative import resolves next to the file holding it: from .claude/ it is ../AGENTS.md.
_IMPORTS_AGENTS = re.compile(r"(?<![\w@/.\-])@(?:\./)?AGENTS\.md(?=\s|$)")
_IMPORTS_PARENT_AGENTS = re.compile(r"(?<![\w@/.\-])@\.\./AGENTS\.md(?=\s|$)")
# What Claude Code loads as project memory from the directory it starts in and from every
# parent. Any one of them turns off its native AGENTS.md reading (host research digest:
# "only when no CLAUDE.md or CLAUDE.local.md exists in cwd or any ancestor"; the binary's
# candidate list also has .claude/CLAUDE.md).
_CLAUDE_FAMILY = ("CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_CODE_SPAN = re.compile(r"(`+).+?\1")
_INDENTED_CODE = re.compile(r"^(?: {4}|\t)")
_BOM = "\ufeff"


def _fence_step(fence: Optional[Tuple[str, int]], line: str) -> Optional[Tuple[str, int]]:
    """The fenced-code state after ``line``: None outside a fence, else (fence char, length)."""
    match = _FENCE.match(line)
    if fence is None:
        return (match.group(1)[0], len(match.group(1))) if match else None
    closes = (match is not None and match.group(1)[0] == fence[0] and len(match.group(1)) >= fence[1]
              and not line[match.end():].strip())
    return None if closes else fence


def _prose(text: str) -> str:
    """``text`` without fenced or indented code blocks and inline code spans, where
    Claude Code evaluates no ``@`` import.

    An indented block starts after a blank line (or at the top) and cannot interrupt a
    paragraph. List context is not tracked, so an import indented inside a list item
    after a blank line counts as code: doctor may then under-report it, never over-report.
    """
    out, fence, blank_before, indented = [], None, True, False
    for line in text.splitlines():
        inside = fence is not None
        fence = _fence_step(fence, line)
        if inside or fence is not None:
            blank_before, indented = False, False
            continue
        if not line.strip():
            blank_before = True
            continue
        if _INDENTED_CODE.match(line) and (blank_before or indented):
            indented, blank_before = True, False
            continue
        indented, blank_before = False, False
        out.append(_CODE_SPAN.sub(" ", line))
    return "\n".join(out)


@dataclass
class _ClaudeFile:
    """One CLAUDE.md-family file in the workspace, as Claude Code would load it."""

    name: str  # relative to the workspace, with forward slashes
    path: Path
    size: int
    imports_agents: bool
    # It and AGENTS.md are one file (a link either way): Claude Code reads AGENTS.md.
    is_agents: bool
    link_target: Optional[str]  # where it points when it is a symlink


@dataclass
class _Instructions:
    agents_bytes: Optional[int] = None
    bootstrap: str = "not_read"  # current outdated hand_edited malformed missing not_read
    block_end: Optional[int] = None  # bytes up to the end of the closing marker line
    claude: List[_ClaudeFile] = field(default_factory=list)  # in the workspace, _CLAUDE_FAMILY order
    # CLAUDE.md-family files in the workspace's parent directories, except the user memory
    # file: they count, but doctor reads no file outside the workspace, so whether one
    # imports this AGENTS.md is unknown.
    claude_outside: List[Path] = field(default_factory=list)
    override: bool = False


def _bootstrap_state(text: str) -> Tuple[str, Optional[int]]:
    from aegis_core.bootstrap import BOOTSTRAP_ID, bootstrap_text

    # aegis init keeps a byte-order mark it finds, so the block can start right after one.
    bom = text.startswith(_BOM)
    lines = text[1:].splitlines(True) if bom else text.splitlines(True)
    begins, ends, offset, end_at = [], [], len(_BOM.encode("utf-8")) if bom else 0, None
    for index, line in enumerate(lines):
        offset += len(line.encode("utf-8"))
        bare = line.rstrip("\r\n")
        begin = _BLOCK_BEGIN.match(bare)
        if begin and begin.group(1) == BOOTSTRAP_ID:
            begins.append((index, begin.group(2), begin.group(3)))
        end = _BLOCK_END.match(bare)
        if end and end.group(1) == BOOTSTRAP_ID:
            ends.append(index)
            end_at = offset
    if not begins and not ends:
        return "missing", None
    if len(begins) != 1 or len(ends) != 1 or ends[0] < begins[0][0]:
        return "malformed", None
    start, version, sha = begins[0]
    if version != "1" or not _HEX12.match(sha):
        return "malformed", None
    body = "".join(lines[start + 1:ends[0]]).replace("\r\n", "\n")
    if _sha256(body.encode("utf-8"))[:12] != sha:
        return "hand_edited", end_at
    return ("current" if body == bootstrap_text() else "outdated"), end_at


def _instructions(ctx: _Ctx) -> _Instructions:
    info = _Instructions()
    if not ctx.governed:
        return info
    agents = ctx.file(ctx.root / "AGENTS.md")
    if agents.raw is not None:
        info.agents_bytes = len(agents.raw)
        text = agents.raw.decode("utf-8", errors="replace")
        info.bootstrap, info.block_end = _bootstrap_state(text)
    else:
        info.bootstrap = "missing"
    for name in _CLAUDE_FAMILY:
        entry = ctx.file(ctx.root.joinpath(*name.split("/")))
        if entry.raw is None:
            continue
        imports = _IMPORTS_PARENT_AGENTS if name.startswith(".claude/") else _IMPORTS_AGENTS
        same = False
        if agents.raw is not None:
            try:
                same = os.path.samefile(str(entry.path), str(agents.path))
            except OSError:
                same = False
        info.claude.append(_ClaudeFile(
            name=name, path=entry.path, size=len(entry.raw),
            imports_agents=bool(imports.search(_prose(entry.raw.decode("utf-8", errors="replace")))),
            is_agents=same, link_target=os.path.realpath(str(entry.path)) if entry.is_link else None))
    # Claude Code loads <config dir>/CLAUDE.md (~/.claude/CLAUDE.md) as user memory and
    # leaves exactly that path out of the walk that decides whether AGENTS.md is read
    # (claude 2.1.301: the walk's processed paths start as {managed, user} memory).
    # The match is by spelling. Under a symlinked home the ancestors of the resolved root
    # spell that file differently, and whether Claude Code still skips it there is
    # unverified, so it counts and the reach stays unknown rather than claimed.
    claude_dir = _claude_dir(ctx)
    user_memory = _path_key(claude_dir / "CLAUDE.md") if claude_dir is not None else None
    candidates = (d.joinpath(*name.split("/")) for d in ctx.root.parents for name in _CLAUDE_FAMILY)
    info.claude_outside = [p for p in candidates if _path_key(p) != user_memory and _present(p)]
    info.override = (ctx.root / "AGENTS.override.md").exists()
    return info


def _registered_roots(ctx: _Ctx) -> Tuple[Optional[set], List[int]]:
    """(normalized roots in ~/.aegis/workspaces.json, indexes of the entries skipped).

    The roots are empty when the file is absent and None when it cannot be read. An
    entry is skipped, as the server's registry reader skips it, unless it is an object
    whose ``root`` is an absolute path that resolves: a relative root would otherwise be
    resolved against doctor's own cwd, and a NUL byte makes resolving raise.
    """
    if ctx.home is None:
        return None, []
    from aegis_core.workspace.layout import UserLayout

    reg = ctx.file(UserLayout(ctx.home).workspaces_file, as_json=True)
    if not reg.exists:
        return set(), []
    if reg.error or reg.data.get("v") != 1 or not isinstance(reg.data.get("workspaces"), list):
        return None, []
    roots, skipped = set(), []
    for index, entry in enumerate(reg.data["workspaces"]):
        raw = entry.get("root") if isinstance(entry, dict) else None
        key = real_key(raw) if isinstance(raw, str) and os.path.isabs(raw) else None
        if key is None:
            skipped.append(index)
        else:
            roots.add(key)
    return roots, skipped


# ── Finding records ─────────────────────────────────────────────────────────

@dataclass
class _Action:
    """One reported change --fix may make to one file."""

    path: Path
    kind: str  # remove_keys | remove_lines | remove_list_items | delete_file | enable_packaged_ast_drivers
    sha256: Optional[str]
    describe: str
    keys: Tuple[Tuple[str, ...], ...] = ()
    lines: Tuple[Tuple[int, int], ...] = ()
    # remove_list_items: (key path to a JSON list, index in it); the file is unchanged since
    # the check (sha256), so the indexes still name the entries doctor reported.
    items: Tuple[Tuple[Tuple[Any, ...], int], ...] = ()


@dataclass
class _Finding:
    code: str
    path: Path
    message: str
    location: Optional[str] = None
    severity: str = "warning"
    action: Optional[_Action] = None

    def __post_init__(self) -> None:
        # Messages quote paths, keys and parser errors from files a repository can write.
        self.message = _clean(self.message, 4096)

    def as_dict(self) -> Dict[str, Any]:
        # A finding is fixable exactly when it carries the action --fix would take.
        return {"code": self.code, "severity": self.severity, "path": str(self.path), "location": self.location,
                "message": self.message, "fixable": self.action is not None}


def _location(keys: Tuple[str, ...]) -> str:
    """Where a key is, for people: the keys (project paths among them) without control sequences."""
    out = []
    for key in keys:
        if out and out[-1] == "projects":
            out[-1] = f"projects[{_clean(key)}]"
        else:
            out.append(_clean(key))
    return ".".join(out)


# ── v3 leftovers: hook entries and rule blocks ──────────────────────────────

# A token after which the shell starts a new command (a v3 entry may be `cd x && soma hook ...`).
_COMMAND_STARTERS = frozenset({"&&", "||", "|", ";", "&", "!", "(", "{", "then", "do", "else", "exec"})


def _removed_host_phases() -> frozenset:
    """The `aegis hook <phase>` commands v3 host configs called and v4 removed (the command table)."""
    from aegis_cli.commands_table import _HOST_HOOK, REMOVED_COMMANDS

    return frozenset(name.partition(" ")[2] for name, pointer in REMOVED_COMMANDS.items()
                     if name.startswith("hook ") and pointer == _HOST_HOOK)


def _program_name(token: str) -> str:
    name = re.split(r"[\\/]", token)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _is_legacy_handler(handler: Any, phases: frozenset) -> bool:
    """Whether a hook handler calls the v3 CLI's hooks or a removed `aegis hook` phase,
    as the program of any command in its (shell) command line."""
    if not isinstance(handler, dict) or not isinstance(handler.get("command"), str):
        return False
    command, args = handler["command"], handler.get("args")
    if isinstance(args, list) and args and all(isinstance(a, str) for a in args):
        tokens = [command] + args
    else:
        from aegis_cli.hooks.registrar import command_tokens

        tokens = command_tokens(command)
    starts = True
    for index, token in enumerate(tokens[:-1]):
        if starts and tokens[index + 1] == "hook":
            program = _program_name(token)
            if program == LEGACY_SERVER:
                return True
            if program == "aegis" and index + 2 < len(tokens) and tokens[index + 2].rstrip(";&|") in phases:
                return True
        starts = token in _COMMAND_STARTERS or token.endswith((";", "&", "|"))
    return False


def _legacy_items(host_id: str, data: Dict[str, Any], phases: frozenset) -> Tuple[List[ListItem], int, int]:
    """(where the v3 entries are, handlers in the file, v3 handlers). A group whose handlers
    are all v3 goes whole; otherwise only its v3 handlers go. Every event counts, not only
    PreToolUse: v3 hooked PreInvocation and Stop too."""
    if host_id == "antigravity":
        containers = [name for name, value in data.items() if isinstance(value, dict)]
    else:
        containers = ["hooks"] if isinstance(data.get("hooks"), dict) else []
    items: List[ListItem] = []
    total = legacy = 0
    for name in containers:
        for event, listed in data[name].items():
            if not isinstance(listed, list):
                continue
            for index, item in enumerate(listed):
                inner = item.get("hooks") if isinstance(item, dict) else None
                if isinstance(inner, list):
                    old = [j for j, h in enumerate(inner) if _is_legacy_handler(h, phases)]
                    total += len(inner)
                    legacy += len(old)
                    if old and len(old) == len(inner):
                        items.append(((name, event), index))
                    else:
                        items.extend(((name, event, index, "hooks"), j) for j in old)
                elif isinstance(item, dict):
                    total += 1
                    if _is_legacy_handler(item, phases):
                        legacy += 1
                        items.append(((name, event), index))
    return items, total, legacy


def _list_location(path: Tuple[Any, ...], index: int) -> str:
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else ("." if out else "") + _clean(part)
    return f"{out}[{index}]"


_LEGACY_MARKER = re.compile(r"^<!-- (SOMA|AEGIS):(START|END) -->[ \t]*$")


def _legacy_ranges(text: str) -> Tuple[List[Tuple[int, int]], bool]:
    """(line ranges of well-formed SOMA/AEGIS START..END blocks, markers are balanced).

    Markers shown inside a fenced code block are text, not a block. Inside an open block
    the content is v3's own (rule text with its fences), so only its END marker counts.
    """
    ranges, open_at, fence = [], None, None
    for index, line in enumerate(text.splitlines(True)):
        bare = line.rstrip("\r\n")
        if index == 0 and bare.startswith(_BOM):
            bare = bare[1:]
        if open_at is None:
            inside = fence is not None
            fence = _fence_step(fence, bare)
            if inside or fence is not None:
                continue
        match = _LEGACY_MARKER.match(bare)
        if not match:
            continue
        kind, edge = match.groups()
        if edge == "START":
            if open_at is not None:
                return ranges, False
            open_at = (index, kind)
        else:
            if open_at is None or open_at[1] != kind:
                return ranges, False
            ranges.append((open_at[0], index))
            open_at = None
    return ranges, open_at is None


def _instruction_files(ctx: _Ctx) -> List[Path]:
    files = [ctx.root / name for name in ("CLAUDE.md", "AGENTS.md", "GEMINI.md")]
    claude_dir = _claude_dir(ctx)
    if claude_dir is not None:
        files.append(claude_dir / "CLAUDE.md")
    if ctx.home is not None:
        codex_home = ctx.environ.get("CODEX_HOME")
        files.append((Path(codex_home) if codex_home else ctx.home / ".codex") / "AGENTS.md")
        files.append(ctx.home / ".gemini" / "GEMINI.md")
    return files


def _without_lines(raw: bytes, ranges: Sequence[Tuple[int, int]]) -> Optional[bytes]:
    """The bytes with the line ranges removed, or None when nothing but whitespace is left.

    A byte-order mark stays at the start of the file even when its first line goes.
    """
    text = raw.decode("utf-8")
    bom = _BOM if text.startswith(_BOM) else ""
    lines = text[len(bom):].splitlines(True)
    drop = {i for a, b in ranges for i in range(a, b + 1)}
    kept = "".join(line for i, line in enumerate(lines) if i not in drop)
    return (bom + kept).encode("utf-8") if kept.strip(" \t\r\n") else None
