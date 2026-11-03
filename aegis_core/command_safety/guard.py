"""The fail-open destructive-command guard behind ``aegis hook run pre-tool`` and the
Codex rules: BLOCK_SET, RECORD_SET and classify_command."""
from __future__ import annotations

from collections import ChainMap
from dataclasses import dataclass, field
import re
import shlex
from typing import Dict, List, Mapping, Optional, Tuple, Union

from aegis_core.command_safety.lexer import (
    GIT_GLOBAL_FLAGS_WITH_ARG,
    MAX_DEPTH,
    RM_DANGEROUS_TARGETS,
    UnwrappedCommand,
    _GIT_SHORT_VALUES,
    _long_option,
    _scan_heredocs,
    _short_letters,
    _split_heredocs,
    _writes_a_device,
    decompose_command,
    extract_subshell_commands,
    strip_shell_comments,
    tokenize_command,
    unwrap_command_stage,
)


# ── Destructive-command guard (v4.1 per-host hooks) ──────────────────────────
#
# CommandAnalyzer in analyzer.py serves `aegis hook safety-gate`, which fails closed (asks) on
# anything it cannot parse. The guard in this module decides what `aegis hook run pre-tool`
# BLOCKS, so it fails open: an empty, absent or unparseable command is never a match,
# and only the irreversible operations of BLOCK_SET block. It reuses the lexer and the
# wrapper unwrapping, not the evaluators. The two policies are kept on purpose; where
# they differ, and why, is pinned by the parity table in
# tests/unit/core/test_command_safety.py, which a change to either must update. A
# lexer helper serves both unless that table says why not (strip_shell_comments, the
# git alias expansion and the heredoc SQL check are guard-only).

GUARD_BLOCK = "block"
GUARD_RECORD = "record"

#: An argv prefix for a Codex ``prefix_rule(pattern=...)``; a tuple at a position lists
#: alternatives (Codex's nested list).
CodexPrefix = Tuple[Union[str, Tuple[str, ...]], ...]


@dataclass(frozen=True)
class GuardRule:
    """One operation the guard recognizes.

    ``tier`` is GUARD_BLOCK (the hook blocks it) or GUARD_RECORD (recorded, never
    blocked). ``codex_prefixes`` feed the Codex ``aegis.rules`` generator. Codex's
    ``prefix_rule`` forbids every command that starts with a prefix, whatever follows
    it, and the hook blocks each of those for the same rule with one exception: a git
    clean dry run written after the forcing flag (``git clean -f -n``, ``git clean
    --force --dry-run``) deletes nothing, so the hook allows it while Codex forbids it
    (``git clean -n`` runs on both). Tests pin both. An operation no argv prefix can
    express (a ``+refspec`` push, ``dd of=/dev/...``) has no prefix and is left to the
    hook.
    """

    id: str
    tier: str
    reason: str
    codex_prefixes: Tuple[CodexPrefix, ...] = ()


def _prefix(*positions: Union[str, Tuple[str, ...]]) -> CodexPrefix:
    """A Codex prefix pattern. Built by a call, not a tuple literal: it is data for Codex,
    and a literal ("git", ...) reads as a git argv to the ratchet that keeps every git
    subprocess in gitsafe (tests/unit/core/test_gitsafe.py)."""
    return tuple(positions)


_PROTECTED_BRANCHES = frozenset({"main", "master"})


_CHMOD_777 = re.compile(r"0*[0-7]?777")
_SQL_DESTRUCTIVE = ("DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE TABLE")


BLOCK_SET: Tuple[GuardRule, ...] = (
    GuardRule(
        "git-push-force", GUARD_BLOCK,
        "force push (--force, -f, --force-with-lease) overwrites the remote branch",
        (_prefix("git", "push", ("--force", "-f", "--force-with-lease")),),
    ),
    GuardRule("git-push-refspec", GUARD_BLOCK, "a +refspec push force-updates the remote branch"),
    GuardRule(
        "git-reset-hard", GUARD_BLOCK, "git reset --hard discards uncommitted changes",
        (_prefix("git", "reset", "--hard"),),
    ),
    GuardRule(
        "git-clean-force", GUARD_BLOCK, "git clean -f permanently deletes untracked files",
        (_prefix("git", "clean", ("-f", "--force", "-fd", "-df", "-fx", "-xf", "-fdx", "-xdf", "-dfx")),),
    ),
    GuardRule(
        "rm-recursive-dangerous", GUARD_BLOCK, "recursive rm of /, ~, $HOME, *, . or ..",
        (_prefix("rm", ("-r", "-R", "-rf", "-fr", "-Rf", "-fR", "--recursive"),
                 ("/", "/*", "~", "~/", "~/*", "*", ".", "./", "..", "../", "$HOME", "/home", "/root")),),
    ),
    GuardRule(
        "mkfs", GUARD_BLOCK, "mkfs formats a filesystem",
        (_prefix(("mkfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat",
                  "mkfs.fat", "mkfs.exfat", "mkfs.ntfs")),),
    ),
    GuardRule("dd-device", GUARD_BLOCK, "dd of=/dev/... overwrites a device"),
)

RECORD_SET: Tuple[GuardRule, ...] = (
    GuardRule("git-merge", GUARD_RECORD, "git merge"),
    GuardRule("gh-pr-merge", GUARD_RECORD, "gh pr merge"),
    GuardRule("git-add-bulk", GUARD_RECORD, "bulk staging (git add -A, --all or .)"),
    GuardRule("git-push-protected", GUARD_RECORD, "push to a protected branch (main, master)"),
    GuardRule("sudo", GUARD_RECORD, "sudo"),
    GuardRule("chmod-777", GUARD_RECORD, "chmod 777"),
    GuardRule("sql-destructive", GUARD_RECORD, "destructive SQL (DROP TABLE/DATABASE, DELETE FROM, TRUNCATE TABLE)"),
)

_GUARD: Dict[str, GuardRule] = {rule.id: rule for rule in BLOCK_SET + RECORD_SET}


def _pushes_to_protected(refspec: str) -> bool:
    destination = refspec.rsplit(":", 1)[-1]
    return destination.rsplit("/", 1)[-1] in _PROTECTED_BRANCHES


def _clean_dry_run(args: List[str]) -> bool:
    """Whether git clean's ``args`` (every word after ``clean``) ask for a dry run, and no
    more often than git does: ``-e``/``--exclude`` take the next word as their value
    (``-en``, ``-e -n`` and ``-e .env`` exclude n, -n and .env), a ``-n`` after ``--`` is a
    pathspec, and ``--no-dry-run`` cancels one."""
    dry_run = value_next = False
    for flag in args:
        if flag == "--":  # git takes "-e --" as a value; ending here never finds a dry run
            break
        if value_next:
            value_next = False
        elif _long_option(flag, "--no-dry-run"):
            return False
        elif flag.startswith("--"):
            dry_run = dry_run or _long_option(flag, "--dry-run")
            value_next = _long_option(flag, "--exclude") and "=" not in flag
        else:
            before, excluded, value = _short_letters(flag).partition("e")
            dry_run = dry_run or "n" in before
            value_next = bool(excluded) and not value
    return dry_run


#: The git subcommands _guard_git has rules for; keep the two in step.
_GUARD_GIT_SUBCOMMANDS = frozenset({"push", "reset", "clean", "merge", "add"})


def _guard_git(cmd: UnwrappedCommand) -> List[GuardRule]:
    sub = cmd.subcommand
    if sub not in _GUARD_GIT_SUBCOMMANDS:
        return []
    flags = [f.lstrip("\\") for f in cmd.flags]
    letters = "".join(_short_letters(f, _GIT_SHORT_VALUES.get(sub or "", "")) for f in flags)
    found: List[GuardRule] = []
    if sub == "push":
        if "f" in letters or any(_long_option(f, "--force") or _long_option(f, "--force-with-lease") for f in flags):
            found.append(_GUARD["git-push-force"])
        if any(arg.startswith("+") for arg in cmd.positional_args):
            found.append(_GUARD["git-push-refspec"])
        if any(_pushes_to_protected(arg) for arg in cmd.positional_args):
            found.append(_GUARD["git-push-protected"])
    elif sub == "reset" and any(_long_option(f, "--hard") for f in flags):
        found.append(_GUARD["git-reset-hard"])
    elif sub == "clean":
        if ("f" in letters or any(_long_option(f, "--force") for f in flags)) and not _clean_dry_run(cmd.tail):
            found.append(_GUARD["git-clean-force"])
    elif sub == "merge" and not any(f in ("--abort", "--quit", "--continue") for f in flags):
        found.append(_GUARD["git-merge"])
    elif sub == "add" and (
        "A" in letters or any(_long_option(f, "--all") for f in flags)
        or any(arg in (".", "./", "*") for arg in cmd.positional_args)
    ):
        found.append(_GUARD["git-add-bulk"])
    return found


def _dangerous_rm_target(arg: str) -> bool:
    """``/``, ``~``, ``$HOME``, ``*``, ``.``, ``..`` (and RM_DANGEROUS_TARGETS' /home, /root),
    with trailing slashes (BUG-075) or one trailing ``/*`` or ``/.``; never a subpath."""
    target = arg.strip("'\"").lower().replace("${home}", "$home")
    trimmed = target.rstrip("/\\")
    if not trimmed and target[:1] in ("/", "\\"):
        trimmed = "/"
    for suffix in ("/*", "/."):
        if trimmed.endswith(suffix):
            trimmed = trimmed[: -len(suffix)].rstrip("/\\") or "/"
            break
    return trimmed in RM_DANGEROUS_TARGETS


def _guard_stage(cmd: UnwrappedCommand) -> List[GuardRule]:
    found: List[GuardRule] = []
    binary = cmd.binary
    if binary == "git":
        found.extend(_guard_git(cmd))
    elif binary == "gh":
        if cmd.subcommand == "pr" and cmd.positional_args[:1] == ["merge"]:
            found.append(_GUARD["gh-pr-merge"])
    elif binary == "rm":
        flags = [f.lstrip("\\") for f in cmd.flags]
        recursive = any(_long_option(f, "--recursive") or "r" in _short_letters(f).lower() for f in flags)
        if recursive and any(_dangerous_rm_target(arg) for arg in cmd.positional_args):
            found.append(_GUARD["rm-recursive-dangerous"])
    elif binary.startswith("mkfs"):
        found.append(_GUARD["mkfs"])
    elif binary == "dd":
        if any(_writes_a_device(arg) for arg in cmd.positional_args + cmd.flags):
            found.append(_GUARD["dd-device"])
    elif binary == "chmod":
        if any(_CHMOD_777.fullmatch(arg) for arg in cmd.flags + cmd.positional_args):
            found.append(_GUARD["chmod-777"])
    if cmd.has_sudo:
        found.append(_GUARD["sudo"])
    return found


def _git_aliases(cmd: UnwrappedCommand) -> Dict[str, str]:
    """The aliases a git invocation defines for itself (``-c alias.NAME=VALUE``,
    ``--config-env alias.NAME=VAR``, ``GIT_CONFIG_KEY_n``/``GIT_CONFIG_VALUE_n``,
    ``GIT_CONFIG_PARAMETERS``), by lowercase name: git compares config names without case."""
    settings: List[str] = []
    try:  # 'key'='value' or 'key=value' words, which shlex joins into key=value
        settings.extend(shlex.split(cmd.env_vars.get("GIT_CONFIG_PARAMETERS", "")))
    except ValueError:
        pass
    following = cmd.flags[1:] + [""]
    for flag, after in zip(cmd.flags, following):
        if flag == "-c":
            settings.append(after)
        elif flag == "--config-env" or flag.startswith("--config-env="):
            name, _, var = (flag.partition("=")[2] or after).partition("=")
            if var in cmd.env_vars:  # a variable exported earlier is not visible here
                settings.append(f"{name}={cmd.env_vars[var]}")
    for var, key in cmd.env_vars.items():
        value = cmd.env_vars.get("GIT_CONFIG_VALUE_" + var[len("GIT_CONFIG_KEY_"):])
        if var.startswith("GIT_CONFIG_KEY_") and value is not None:
            settings.append(f"{key}={value}")
    aliases: Dict[str, str] = {}
    for key, sep, value in (setting.partition("=") for setting in settings):
        if sep and key.lower().startswith("alias."):
            aliases[key[len("alias."):].lower()] = value
    return aliases


# How many ``!`` alias scripts one command may have scanned. git runs a script each time
# its alias is invoked, so a script that reruns aliases it inherits (``alias.p='!git p; git
# p'``) would be rescanned for every stage at every nesting level; past this many, a script
# contributes nothing (fail-open, like MAX_DEPTH).
_MAX_ALIAS_SCRIPTS = 16
_SIMPLE_ALIAS_WORDS = re.compile(r"\w+(?: +\w+)*", re.ASCII)


@dataclass
class _GuardScan:
    """The rules one classify_command call has found, and the ``!`` alias scripts it may
    still scan."""

    found: List[GuardRule] = field(default_factory=list)
    alias_scripts: int = _MAX_ALIAS_SCRIPTS


def _guard_git_alias(
    cmd: UnwrappedCommand, depth: int, scan: _GuardScan, inherited: Optional[Mapping[str, str]] = None,
) -> None:
    """Classify the expansion of an alias defined on the same command line
    (``git -c alias.p='push -f' p``), or by the git whose ``!`` alias script runs this one
    (``inherited``; this git's own settings come later, so they win). _guard_git has
    already matched the literal subcommand, so a built-in still wins as it does in git;
    ``seen`` stops a cycle.

    Each link's words replace the alias name in front of the words after it. Those are
    kept on a stack, last word first, so a link costs only its own words: rebuilding the
    whole command per link would re-read the tail once per link. Only a link naming a
    subcommand _guard_git has rules for is rebuilt and judged.

    git also reads -c and --config-env in a link's words, which can define the aliases
    the rest of the chain expands; they come after this git's own settings."""
    # Chained, not copied per git stage; link definitions go in the first map.
    aliases = ChainMap({}, _git_aliases(cmd), *([inherited] if inherited else []))
    # --config-env in a link reads the stage's variables, never its GIT_CONFIG_* ones again.
    config_env = {var: value for var, value in cmd.env_vars.items() if not var.startswith("GIT_CONFIG")}
    rest = cmd.tail[::-1]
    sub = cmd.subcommand
    seen = set()
    while sub in aliases and sub not in seen:
        seen.add(sub)
        value = aliases[sub]
        if value.startswith("!"):
            # git runs it with sh -c, the arguments appended, and hands its -c settings to
            # every git the script runs through GIT_CONFIG_PARAMETERS.
            if scan.alias_scripts > 0:
                scan.alias_scripts -= 1
                arguments = [shlex.quote(t) for t in reversed(rest)]
                _guard_scan(" ".join([value[1:]] + arguments), depth + 1, scan, aliases)
            return
        try:
            words = value.split() if _SIMPLE_ALIAS_WORDS.fullmatch(value) else shlex.split(value)
        except ValueError:
            return
        rest.extend(reversed(words))
        options: List[str] = []  # read as unwrap_command_stage reads what precedes a subcommand
        while rest and rest[-1].startswith("-"):
            options.append(rest.pop())
            if "=" not in options[-1] and options[-1] in GIT_GLOBAL_FLAGS_WITH_ARG and rest:
                options.append(rest.pop())
        if not rest:
            return
        if options:
            aliases.maps[0].update(_git_aliases(UnwrappedCommand(cmd.binary, None, options, [], env_vars=config_env)))
        word = rest.pop()
        sub = word.lower()
        if sub in _GUARD_GIT_SUBCOMMANDS:
            expanded, _ = unwrap_command_stage([cmd.binary, *options, word, *reversed(rest)])
            if expanded is not None:
                scan.found.extend(_guard_git(expanded))


def _guard_scan(cmd: str, depth: int, scan: _GuardScan, aliases: Optional[Mapping[str, str]] = None) -> bool:
    """Add the guard rules ``cmd`` matches to ``scan.found``; False when it cannot be
    parsed (or nests deeper than MAX_DEPTH), which contributes nothing. ``aliases`` are the
    git aliases ``cmd`` inherits when it is a ``!`` alias's script."""
    if depth >= MAX_DEPTH:
        return False
    text, scripts = _split_heredocs(cmd)
    text = strip_shell_comments(text)  # after the split: a body apostrophe is not a quote
    try:
        tokens = tokenize_command(text)
    except ValueError:
        return False
    for script in scripts:
        _guard_scan(script, depth + 1, scan, aliases)
    if any(c in text for c in ("$", "`", "(", "<", ">")):
        for sub in extract_subshell_commands(text):
            _guard_scan(sub, depth + 1, scan, aliases)
    for pipeline in decompose_command(tokens):
        for stage in pipeline.stages:
            unwrapped, inner = unwrap_command_stage(stage.raw_tokens)
            if inner:
                _guard_scan(inner, depth + 1, scan, aliases)
            if unwrapped is not None:
                scan.found.extend(_guard_stage(unwrapped))
                if unwrapped.binary == "git":
                    _guard_git_alias(unwrapped, depth, scan, aliases)
    return True


def classify_command(command: object) -> Optional[GuardRule]:
    """The guard rule ``command`` matches: a BLOCK_SET rule when any matches, else the
    first RECORD_SET rule, else None.

    Fail-open: an empty or non-string command, one the lexer cannot parse, an
    unresolvable globbed binary, nesting beyond MAX_DEPTH and a ``!`` alias script past
    the first _MAX_ALIAS_SCRIPTS are never a match.
    """
    if not isinstance(command, str) or not command.strip():
        return None
    scan = _GuardScan()
    if not _guard_scan(command, 0, scan):
        return None
    found = scan.found
    text, scripts, sql_bodies = _scan_heredocs(command)
    upper = "\n".join([text, *scripts, *sql_bodies]).upper()
    if any(pattern in upper for pattern in _SQL_DESTRUCTIVE):
        found.append(_GUARD["sql-destructive"])
    blocked = next((rule for rule in found if rule.tier == GUARD_BLOCK), None)
    return blocked or (found[0] if found else None)
