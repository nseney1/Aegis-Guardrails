"""aegis_core.command_safety — Structured AST/token command safety analyzer.

Replaces monolithic regular expressions with lexical tokenization, wrapper unwrapping,
pipeline sequence analysis, and domain-specific command evaluators.
Zero external dependencies (pure stdlib). Target latency < 0.05ms.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import os
import re
import shlex
from typing import Dict, List, Optional, Tuple, Union

# ── Canonical Reason Strings (1:1 Parity with aegis_cli/hooks.py) ─────────────

REASON_GIT_BRANCH = "Destructive branch operation (git branch -d/-D/-M/-f/--delete/--force)"
REASON_GIT_CONFIG = "git configuration override / exec-path injection (-c/--exec-path/--config-env)"
REASON_GIT_DIFF = "git diff write/execute flag detected"
REASON_RM_RF = "Recursive delete targeting home/root directory or wildcard/current directory"
REASON_RMTREE = "Recursive directory deletion (rmtree) detected"
REASON_RMDIR_BYPASS = "rmdir with --ignore-fail-on-non-empty — bypasses safety check"
REASON_MKFS = "Filesystem format (mkfs) detected — destructive operation"
REASON_DD = "Raw disk write (dd) detected — destructive operation"
REASON_CHMOD_777 = "chmod 777 — overly permissive, potential security risk"
REASON_KILL_ALL = "kill -9 -1 — would kill all user processes"
REASON_SUDO = "sudo detected — elevated privileges require confirmation"
REASON_PIPE_TO_SHELL = "Piping remote content to shell — potential code execution risk"
REASON_GIT_PUSH_FORCE = "Force push detected — destructive-ops mandate requires confirmation"
REASON_GIT_PUSH_REFSPEC = "Force push via +refspec detected — destructive-ops mandate requires confirmation"
REASON_GIT_RESET_HARD = "Hard reset — will discard uncommitted changes"
REASON_GIT_CHECKOUT_FORCE = "Force checkout — will discard uncommitted changes"
REASON_GIT_CLEAN_FORCE = "git clean -f — will permanently remove untracked files"
REASON_GIT_ADD_BULK = "Bulk staging (git add -A/./*/--all) — run git status first to verify file count"
REASON_DB_DESTRUCTIVE = "Destructive database operation without WHERE clause"
REASON_WINDOWS_FORMAT = "Disk partition format detected — destructive operation"
REASON_POWERSHELL_DELETE = "PowerShell recursive force delete detected"
REASON_CMD_DELETE = "Windows command-line recursive delete (/s /q) detected"
REASON_HUMAN_REVIEW_GATE = "Human Review Gate: Agents are strictly prohibited from merging pull requests (gh pr merge). Merging requires human authority."
REASON_PROTECTED_BRANCH = "Protected branch operation: Direct push to main is strictly prohibited for agents."
REASON_GIT_MERGE = "Git branch merge detected — merging branches requires human confirmation"
REASON_UNABLE_TO_PARSE = "Unable to parse command — requesting confirmation"

MAX_DEPTH = 5

# ── Classification Sets ───────────────────────────────────────────────────────

REMOTE_FETCHERS = frozenset({
    "curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"
})

SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "fish",
    "powershell", "pwsh", "iex", "invoke-expression"
})

SHELL_PREFIX_KEYWORDS = frozenset({
    "{", "}", "then", "do", "elif", "else", "if", "while", "until", "fi", "done", "esac"
})

SUDO_FLAGS_WITH_ARG = frozenset({
    "-u", "-g", "-p", "-C", "-D", "-R", "-T", "-U", "-h", "-c", "-a",
    "--user", "--group", "--prompt", "--close-from", "--chdir", "--chroot",
    "--command-timeout", "--other-user", "--host"
})

ENV_FLAGS_WITH_ARG = frozenset({
    "-u", "--unset", "-C", "--chdir", "-S", "--split-string"
})

TIME_FLAGS_WITH_ARG = frozenset({
    "-o", "--output", "-f", "--format"
})

EXEC_FLAGS_WITH_ARG = frozenset({
    "-a"
})

GIT_GLOBAL_FLAGS_WITH_ARG = frozenset({
    "-C", "-c", "--exec-path", "--config-env", "--work-tree", "--namespace", "--git-dir"
})

GH_GLOBAL_FLAGS_WITH_ARG = frozenset({
    "-R", "--repo"
})

ENV_VAR_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*=")
WIN_DRIVE_RE = re.compile(r'([a-zA-Z]:)\\([\s*?$"]|$)')
RM_DANGEROUS_TARGETS = frozenset({"/", "~", "/home", "$home", "/root", "$root", ".", "..", "*"})
GLOB_CHARS = frozenset({"*", "?", "[", "]"})


@dataclass(frozen=True)
class SafetyEvaluation:
    is_destructive: bool
    reason: str = ""


@dataclass
class CommandStage:
    raw_tokens: list[str]


@dataclass
class Pipeline:
    stages: list[CommandStage]


@dataclass
class UnwrappedCommand:
    binary: str
    subcommand: str | None
    flags: list[str]
    positional_args: list[str]
    has_sudo: bool = False
    env_vars: dict[str, str] = field(default_factory=dict)


# ── String Pre-processing & Subshell Scanner ──────────────────────────────────

def decode_ansi_c_quotes(cmd: str) -> str:
    """Expand Bash ANSI-C quoting ($'...') into decoded strings."""
    if "$'" not in cmd:
        return cmd

    def _repl(match: re.Match[str]) -> str:
        content = match.group(1)
        try:
            decoded = content.encode("utf-8").decode("unicode_escape")
        except Exception:
            decoded = content
        return shlex.quote(decoded)

    return re.sub(r"\$'([^'\\]*(?:\\.[^'\\]*)*)'", _repl, cmd)


def extract_subshell_commands(cmd: str) -> list[str]:
    """Extract nested subshells strictly respecting shell quoting context.
    
    Guarantees:
    - Never extracts parentheses inside single quotes ('...').
    - Only extracts $(...) and `...` inside double quotes or unquoted.
    - Extracts bare (...) if unquoted AND at a command boundary, OR if
      containing destructive PowerShell/CMD operations.
    - Only extracts <(...) or >(...) if unquoted.
    """
    if not any(c in cmd for c in ("$", "`", "(", "<", ">")):
        return []

    extracted: list[str] = []
    n = len(cmd)
    i = 0
    in_single_quote = False
    in_double_quote = False

    while i < n:
        c = cmd[i]

        # Handle backslash escapes
        if c == "\\":
            if not in_single_quote:
                i += 2
                continue
            else:
                i += 1
                continue

        # Single quote toggle (inhibits all expansions inside)
        if c == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            i += 1
            continue

        # Double quote toggle
        if c == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            i += 1
            continue

        if in_single_quote:
            i += 1
            continue

        # Backticks (valid unquoted or inside double quotes)
        if c == "`":
            j = i + 1
            while j < n and cmd[j] != "`":
                if cmd[j] == "\\" and j + 1 < n:
                    j += 2
                else:
                    j += 1
            if j < n and cmd[j] == "`":
                extracted.append(cmd[i + 1 : j])
                i = j + 1
                continue

        # $(...) command substitution (valid unquoted or inside double quotes)
        if c == "$" and i + 1 < n and cmd[i + 1] == "(":
            start = i + 2
            depth = 1
            j = start
            inner_sq = False
            inner_dq = False
            while j < n and depth > 0:
                cj = cmd[j]
                if cj == "\\" and not inner_sq:
                    j += 2
                    continue
                if cj == "'" and not inner_dq:
                    inner_sq = not inner_sq
                elif cj == '"' and not inner_sq:
                    inner_dq = not inner_dq
                elif not inner_sq and not inner_dq:
                    if cj == "(":
                        depth += 1
                    elif cj == ")":
                        depth -= 1
                j += 1
            if depth == 0:
                extracted.append(cmd[start : j - 1])
                i = j
                continue

        # Process substitution <(...) or >(...) (unquoted only)
        if not in_double_quote and c in ("<", ">") and i + 1 < n and cmd[i + 1] == "(":
            start = i + 2
            depth = 1
            j = start
            inner_sq = False
            inner_dq = False
            while j < n and depth > 0:
                cj = cmd[j]
                if cj == "\\" and not inner_sq:
                    j += 2
                    continue
                if cj == "'" and not inner_dq:
                    inner_sq = not inner_sq
                elif cj == '"' and not inner_sq:
                    inner_dq = not inner_dq
                elif not inner_sq and not inner_dq:
                    if cj == "(":
                        depth += 1
                    elif cj == ")":
                        depth -= 1
                j += 1
            if depth == 0:
                extracted.append(cmd[start : j - 1])
                i = j
                continue

        # Bare (...) subshell (unquoted AND [command boundary OR PowerShell expression])
        if not in_double_quote and c == "(":
            k = i - 1
            while k >= 0 and cmd[k] in " \t":
                k -= 1
            is_cmd_boundary = (k < 0) or (cmd[k] in ";|&\n\r({")
            is_ps_expr = bool(re.match(r'\(\s*(?:remove-item|rm|del|erase|rd|ri|format-volume)\b', cmd[i:], re.IGNORECASE))
            if is_cmd_boundary or is_ps_expr:
                start = i + 1
                depth = 1
                j = start
                inner_sq = False
                inner_dq = False
                while j < n and depth > 0:
                    cj = cmd[j]
                    if cj == "\\" and not inner_sq:
                        j += 2
                        continue
                    if cj == "'" and not inner_dq:
                        inner_sq = not inner_sq
                    elif cj == '"' and not inner_sq:
                        inner_dq = not inner_dq
                    elif not inner_sq and not inner_dq:
                        if cj == "(":
                            depth += 1
                        elif cj == ")":
                            depth -= 1
                    j += 1
                if depth == 0:
                    extracted.append(cmd[start : j - 1])
                    i = j
                    continue

        i += 1

    return extracted


# ── Lexing & Hierarchy Decomposition ─────────────────────────────────────────

def tokenize_command(cmd: str) -> list[str]:
    """Tokenize command handling multiline, punctuation delimiters and escapes."""
    normalized = decode_ansi_c_quotes(cmd)
    # Pre-normalize Windows drive backslashes so posix lexer does not treat C:\ as escape
    if ":\\" in normalized:
        normalized = WIN_DRIVE_RE.sub(r'\1/\2', normalized)
    lex = shlex.shlex(normalized, posix=True, punctuation_chars="|;&\n\r")
    lex.whitespace_split = True
    lex.commenters = ""
    lex.whitespace = " \t"
    return list(lex)


def decompose_command(tokens: list[str]) -> list[Pipeline]:
    """Split token stream into Pipelines by sequence delimiters (; , &&, ||, &, newline)."""
    seq_delims = {";", "&&", "||", "&", "\n", "\r", "\r\n"}
    pipelines: list[Pipeline] = []
    curr_pipeline_stages: list[CommandStage] = []
    curr_stage_tokens: list[str] = []

    def flush_stage():
        nonlocal curr_stage_tokens
        if curr_stage_tokens:
            curr_pipeline_stages.append(CommandStage(raw_tokens=list(curr_stage_tokens)))
            curr_stage_tokens = []

    def flush_pipeline():
        nonlocal curr_pipeline_stages
        flush_stage()
        if curr_pipeline_stages:
            pipelines.append(Pipeline(stages=list(curr_pipeline_stages)))
            curr_pipeline_stages = []

    for tok in tokens:
        if tok in seq_delims:
            flush_pipeline()
        elif tok in ("|", "|&"):
            flush_stage()
        else:
            curr_stage_tokens.append(tok)

    flush_pipeline()
    return pipelines


# ── Wrapper & Keyword Unwrapping Automaton ────────────────────────────────────

def unwrap_command_stage(tokens: list[str]) -> tuple[UnwrappedCommand | None, str | None]:
    """Peel keywords, wrappers (with full option consumption), env vars, and expansions.
    
    Returns (UnwrappedCommand, inner_command_to_recurse).
    """
    if not tokens:
        return None, None

    # Expansion Guard 1: Brace expansion on command position (e.g. {rm,-rf,/})
    if tokens and tokens[0].startswith("{") and tokens[0].endswith("}") and "," in tokens[0]:
        inner = tokens[0][1:-1]
        tokens = inner.split(",") + tokens[1:]

    idx = 0
    has_sudo = False
    env_vars: dict[str, str] = {}

    while idx < len(tokens):
        tok = tokens[idx]

        # 1. Shell compound / control flow keywords
        if tok in SHELL_PREFIX_KEYWORDS:
            idx += 1
            continue

        # 2. Leading environment variables (e.g. FOO=bar cmd)
        if "=" in tok and ENV_VAR_RE.match(tok):
            k, _, v = tok.partition("=")
            env_vars[k] = v
            idx += 1
            continue

        clean_tok = tok.lstrip("\\")
        base = os.path.basename(clean_tok).lower()
        if base.endswith(".exe"):
            base = base[:-4]

        # 3. sudo / doas wrapper (with full option & argument consumption)
        if base in ("sudo", "doas"):
            has_sudo = True
            idx += 1
            while idx < len(tokens):
                stok = tokens[idx]
                if stok == "--":
                    idx += 1
                    break
                if stok.startswith("-"):
                    idx += 1
                    if "=" not in stok and stok in SUDO_FLAGS_WITH_ARG:
                        if idx < len(tokens):
                            idx += 1
                else:
                    break
            continue

        # 4. env wrapper (with option and variable consumption)
        if base == "env":
            idx += 1
            while idx < len(tokens):
                etok = tokens[idx]
                if etok == "--":
                    idx += 1
                    break
                if etok.startswith("-"):
                    idx += 1
                    if "=" not in etok and etok in ENV_FLAGS_WITH_ARG:
                        if idx < len(tokens):
                            idx += 1
                elif ENV_VAR_RE.match(etok):
                    k, _, v = etok.partition("=")
                    env_vars[k] = v
                    idx += 1
                else:
                    break
            continue

        # 5. time wrapper (with option consumption)
        if base == "time":
            idx += 1
            while idx < len(tokens):
                ttok = tokens[idx]
                if ttok == "--":
                    idx += 1
                    break
                if ttok.startswith("-"):
                    idx += 1
                    if "=" not in ttok and ttok in TIME_FLAGS_WITH_ARG:
                        if idx < len(tokens):
                            idx += 1
                else:
                    break
            continue

        # 6. command & builtin wrappers
        if base in ("command", "builtin"):
            idx += 1
            while idx < len(tokens) and tokens[idx].startswith("-"):
                if tokens[idx] == "--":
                    idx += 1
                    break
                idx += 1
            continue

        # 7. exec wrapper
        if base == "exec":
            idx += 1
            while idx < len(tokens):
                xtok = tokens[idx]
                if xtok == "--":
                    idx += 1
                    break
                if xtok.startswith("-"):
                    idx += 1
                    if "=" not in xtok and xtok in EXEC_FLAGS_WITH_ARG:
                        if idx < len(tokens):
                            idx += 1
                else:
                    break
            continue

        # 7a. nohup wrapper
        if base == "nohup":
            idx += 1
            while idx < len(tokens) and tokens[idx] == "--":
                idx += 1
            continue

        # 7b. nice wrapper
        if base == "nice":
            idx += 1
            while idx < len(tokens):
                ntok = tokens[idx]
                if ntok == "--":
                    idx += 1
                    break
                if ntok.startswith("-"):
                    idx += 1
                    if ntok == "-n" and idx < len(tokens):
                        idx += 1
                else:
                    break
            continue

        # 7c. timeout wrapper
        if base == "timeout":
            idx += 1
            has_duration = False
            while idx < len(tokens):
                ttok = tokens[idx]
                if ttok == "--":
                    idx += 1
                    continue
                if ttok.startswith("-"):
                    idx += 1
                    if ttok in ("-s", "--signal", "-k", "--kill-after") and idx < len(tokens):
                        idx += 1
                elif not has_duration:
                    has_duration = True
                    idx += 1
                else:
                    break
            continue

        # 7d. xargs wrapper
        if base == "xargs":
            idx += 1
            while idx < len(tokens):
                xtok = tokens[idx]
                if xtok == "--":
                    idx += 1
                    break
                if xtok.startswith("-"):
                    idx += 1
                    if xtok in ("-n", "-L", "-I", "-s", "-d", "-E", "-P") and idx < len(tokens):
                        idx += 1
                else:
                    break
            continue

        # 8. eval builtin (evaluates remaining tokens as inner command)
        if base == "eval":
            if idx + 1 < len(tokens):
                inner_eval_cmd = " ".join(tokens[idx + 1 :])
                return None, inner_eval_cmd
            return None, None

        # 9. Shell interpreter with script (-c / /c / -Command / bundled flags like -lc, -ec, -xc)
        if base in SHELL_INTERPRETERS:
            c_idx = -1
            for j in range(idx + 1, len(tokens)):
                tok = tokens[j]
                if tok in ("-c", "/c", "-Command", "-command"):
                    c_idx = j
                    break
                # POSIX short-flag bundling (e.g. bash -lc, sh -ec, zsh -xic)
                if (
                    base in ("bash", "sh", "zsh", "dash")
                    and tok.startswith("-")
                    and not tok.startswith("--")
                    and "c" in tok[1:]
                ):
                    c_idx = j
                    break
            if c_idx != -1 and c_idx + 1 < len(tokens):
                inner_cmd = tokens[c_idx + 1]
                # Positional argument decoupling defense:
                extra_args = tokens[c_idx + 3 :] if len(tokens) > c_idx + 3 else []
                if extra_args:
                    inner_cmd = inner_cmd + " " + " ".join(extra_args)
                return None, inner_cmd

        # Expansion Guard 2: Path globbing on command binary word
        if any(g in base for g in GLOB_CHARS):
            matched_bin = None
            for candidate in ("rm", "git", "dd", "mkfs", "chmod", "kill", "rmdir"):
                if fnmatch.fnmatch(candidate, base):
                    matched_bin = candidate
                    break
            base = matched_bin if matched_bin else "__unresolved_glob__"

        binary = base
        idx += 1
        subcommand: str | None = None
        flags: list[str] = []
        pos_args: list[str] = []

        while idx < len(tokens):
            arg = tokens[idx]
            if arg.startswith("-") or (binary in ("del", "rmdir") and arg.startswith("/")):
                flags.append(arg)
                # Global Git options with arguments (-C <dir>, --work-tree <dir>)
                if binary == "git" and "=" not in arg and arg in GIT_GLOBAL_FLAGS_WITH_ARG:
                    idx += 1
                    if idx < len(tokens):
                        flags.append(tokens[idx])
                # Global GitHub CLI options with arguments (-R <repo>, --repo <repo>)
                elif binary == "gh" and "=" not in arg and arg in GH_GLOBAL_FLAGS_WITH_ARG:
                    idx += 1
                    if idx < len(tokens):
                        flags.append(tokens[idx])
            else:
                if subcommand is None and binary in ("git", "gh"):
                    subcommand = arg.lower()
                else:
                    pos_args.append(arg)
            idx += 1

        return UnwrappedCommand(
            binary=binary,
            subcommand=subcommand,
            flags=flags,
            positional_args=pos_args,
            has_sudo=has_sudo,
            env_vars=env_vars,
        ), None

    return None, None


# ── Domain-Specific Command Evaluators ────────────────────────────────────────

def evaluate_git(cmd: UnwrappedCommand) -> SafetyEvaluation:
    flags = [f.lstrip("\\") for f in cmd.flags]

    # git config override / exec-path injection
    for f in flags:
        if f in ("-c", "--exec-path", "--config-env") or f.startswith(("--exec-path=", "--config-env=")):
            return SafetyEvaluation(True, REASON_GIT_CONFIG)

    sub = cmd.subcommand
    if not sub:
        return SafetyEvaluation(False)

    if sub == "branch":
        for f in flags:
            if f in ("--delete", "--force"):
                return SafetyEvaluation(True, REASON_GIT_BRANCH)
            if f.startswith("-") and not f.startswith("--"):
                letters = f[1:]
                if any(c in letters for c in "dDMf"):
                    return SafetyEvaluation(True, REASON_GIT_BRANCH)

    elif sub == "push":
        if any(f in ("-f", "--force", "--force-with-lease") for f in flags):
            return SafetyEvaluation(True, REASON_GIT_PUSH_FORCE)
        for arg in cmd.positional_args:
            if arg.startswith("+"):
                return SafetyEvaluation(True, REASON_GIT_PUSH_REFSPEC)
            if arg == "main" or arg.endswith(":main") or arg.endswith("/main"):
                return SafetyEvaluation(True, REASON_PROTECTED_BRANCH)

    elif sub == "reset":
        if any(f == "--hard" for f in flags):
            return SafetyEvaluation(True, REASON_GIT_RESET_HARD)

    elif sub == "checkout":
        if any(f in ("-f", "--force") for f in flags):
            return SafetyEvaluation(True, REASON_GIT_CHECKOUT_FORCE)

    elif sub == "clean":
        for f in flags:
            if f == "--force" or (f.startswith("-") and not f.startswith("--") and "f" in f[1:]):
                return SafetyEvaluation(True, REASON_GIT_CLEAN_FORCE)

    elif sub == "add":
        for f in flags:
            if f in ("-A", "--all"):
                return SafetyEvaluation(True, REASON_GIT_ADD_BULK)
        for arg in cmd.positional_args:
            if arg in (".", "./", "*"):
                return SafetyEvaluation(True, REASON_GIT_ADD_BULK)

    elif sub == "diff":
        for f in flags:
            if f.startswith(("--output", "--ext-cmd")):
                return SafetyEvaluation(True, REASON_GIT_DIFF)

    elif sub == "merge":
        if any(f in ("--abort", "--quit", "--continue") for f in flags):
            return SafetyEvaluation(False)
        return SafetyEvaluation(True, REASON_GIT_MERGE)

    return SafetyEvaluation(False)


def evaluate_gh(cmd: UnwrappedCommand) -> SafetyEvaluation:
    sub = cmd.subcommand
    if not sub:
        return SafetyEvaluation(False)

    if sub == "pr":
        if any(arg == "merge" for arg in cmd.positional_args):
            return SafetyEvaluation(True, REASON_HUMAN_REVIEW_GATE)

    return SafetyEvaluation(False)


def evaluate_rm(cmd: UnwrappedCommand) -> SafetyEvaluation:
    flags = [f.lstrip("\\") for f in cmd.flags]
    has_r = False

    for f in flags:
        if f == "--recursive":
            has_r = True
        elif f.startswith("-") and not f.startswith("--"):
            body = f[1:]
            if any(c in body for c in "rR"):
                has_r = True

    if has_r:
        for arg in cmd.positional_args:
            target = arg.strip("'\"").lower()
            # Path normalization (BUG-075): strip trailing slashes, e.g. ./, ../, ~/, /home
            norm_target = target.rstrip("/\\")
            if not norm_target and target.startswith(("/", "\\")):
                norm_target = "/"
            if (
                target in RM_DANGEROUS_TARGETS
                or norm_target in RM_DANGEROUS_TARGETS
                or any(norm_target.endswith("/" + t) for t in RM_DANGEROUS_TARGETS if t != "/")
            ):
                return SafetyEvaluation(True, REASON_RM_RF)

    return SafetyEvaluation(False)


def evaluate_powershell(cmd: UnwrappedCommand) -> SafetyEvaluation:
    flags_lower = [f.lower() for f in cmd.flags]
    has_recurse = any(f in ("-recurse", "-r") for f in flags_lower)
    has_force = any(f in ("-force", "-fo") for f in flags_lower)
    if has_recurse and has_force:
        return SafetyEvaluation(True, REASON_POWERSHELL_DELETE)
    return SafetyEvaluation(False)


def evaluate_cmd_del(cmd: UnwrappedCommand) -> SafetyEvaluation:
    flags_lower = [f.lower() for f in cmd.flags]
    has_s = any(f in ("/s", "-s") for f in flags_lower)
    has_q = any(f in ("/q", "-q") for f in flags_lower)
    if has_s and has_q:
        return SafetyEvaluation(True, REASON_CMD_DELETE)
    return SafetyEvaluation(False)


def evaluate_system_binary(cmd: UnwrappedCommand) -> SafetyEvaluation:
    b = cmd.binary
    if b == "__unresolved_glob__":
        return SafetyEvaluation(True, REASON_UNABLE_TO_PARSE)

    if b.startswith("mkfs"):
        return SafetyEvaluation(True, REASON_MKFS)

    if b == "dd":
        all_items = cmd.positional_args + cmd.flags
        if any(item.startswith("if=") for item in all_items):
            return SafetyEvaluation(True, REASON_DD)

    if b == "chmod":
        for item in cmd.flags + cmd.positional_args:
            if re.search(r"0?777", item):
                return SafetyEvaluation(True, REASON_CHMOD_777)

    if b == "kill":
        combined = set(cmd.flags + cmd.positional_args)
        if "-9" in combined and "-1" in combined:
            return SafetyEvaluation(True, REASON_KILL_ALL)

    if b == "rmdir":
        if any(f == "--ignore-fail-on-non-empty" for f in cmd.flags):
            return SafetyEvaluation(True, REASON_RMDIR_BYPASS)

    if b in ("format-volume", "initialize-disk", "clear-disk"):
        return SafetyEvaluation(True, REASON_WINDOWS_FORMAT)

    if cmd.has_sudo:
        return SafetyEvaluation(True, REASON_SUDO)

    return SafetyEvaluation(False)


# ── Pipeline & Top-Level Analyzer ─────────────────────────────────────────────

class CommandAnalyzer:
    """Evaluates raw command strings for destructive operations."""

    @classmethod
    def evaluate(cls, cmd: str, depth: int = 0) -> SafetyEvaluation:
        # Recursion Limit Clamp (Defense against DoS)
        if depth >= MAX_DEPTH:
            return SafetyEvaluation(True, REASON_UNABLE_TO_PARSE)

        if not cmd or not isinstance(cmd, str) or not cmd.strip():
            return SafetyEvaluation(True, REASON_UNABLE_TO_PARSE)

        # 1. Non-shell string checks (Python rmtree, SQL keywords)
        if "rmtree(" in cmd:
            return SafetyEvaluation(True, REASON_RMTREE)

        if any(k in cmd for k in ("DROP", "drop", "DELETE", "delete", "TRUNCATE", "truncate")):
            sql_patterns = ("DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE TABLE")
            cmd_upper = cmd.upper()
            if any(p in cmd_upper for p in sql_patterns):
                return SafetyEvaluation(True, REASON_DB_DESTRUCTIVE)

        # 2. Hardened Subshell & Process Substitution Extraction
        if any(c in cmd for c in ("$", "`", "(", "<", ">")):
            subshells = extract_subshell_commands(cmd)
            for sub in subshells:
                sub_res = cls.evaluate(sub, depth=depth + 1)
                if sub_res.is_destructive:
                    return sub_res

        # 3. Lexical Tokenization with fail-closed error handling
        try:
            tokens = tokenize_command(cmd)
        except ValueError:
            return SafetyEvaluation(True, REASON_UNABLE_TO_PARSE)

        if not tokens:
            return SafetyEvaluation(False)

        # 4. Pipeline Decomposition
        pipelines = decompose_command(tokens)

        for pipeline in pipelines:
            # Check 4A: Pipe-to-Shell cross-stage pattern
            stage_unwrapped = []
            for stage in pipeline.stages:
                unwrapped, inner = unwrap_command_stage(stage.raw_tokens)
                if inner:
                    inner_res = cls.evaluate(inner, depth=depth + 1)
                    if inner_res.is_destructive:
                        return inner_res
                stage_unwrapped.append(unwrapped)

            for i, st in enumerate(stage_unwrapped):
                if st and st.binary in REMOTE_FETCHERS:
                    for downstream in stage_unwrapped[i + 1 :]:
                        if downstream and downstream.binary in SHELL_INTERPRETERS:
                            return SafetyEvaluation(True, REASON_PIPE_TO_SHELL)

            # Check 4B: Individual Stage Evaluation
            for st in stage_unwrapped:
                if not st:
                    continue
                if st.binary == "git":
                    res = evaluate_git(st)
                    if res.is_destructive:
                        return res
                elif st.binary == "gh":
                    res = evaluate_gh(st)
                    if res.is_destructive:
                        return res
                elif st.binary == "rm":
                    ps_res = evaluate_powershell(st)
                    if ps_res.is_destructive:
                        return ps_res
                    res = evaluate_rm(st)
                    if res.is_destructive:
                        return res
                elif st.binary in ("remove-item", "erase", "rd", "ri"):
                    res = evaluate_powershell(st)
                    if res.is_destructive:
                        return res
                elif st.binary == "del":
                    ps_res = evaluate_powershell(st)
                    if ps_res.is_destructive:
                        return ps_res
                    res = evaluate_cmd_del(st)
                    if res.is_destructive:
                        return res
                elif st.binary == "rmdir":
                    cmd_res = evaluate_cmd_del(st)
                    if cmd_res.is_destructive:
                        return cmd_res
                    sys_res = evaluate_system_binary(st)
                    if sys_res.is_destructive:
                        return sys_res

                sys_res = evaluate_system_binary(st)
                if sys_res.is_destructive:
                    return sys_res

        return SafetyEvaluation(False)


# ── Destructive-command guard (v4.1 per-host hooks) ──────────────────────────
#
# CommandAnalyzer above serves `aegis hook safety-gate`, which fails closed (asks) on
# anything it cannot parse. The guard below decides what `aegis hook run pre-tool`
# BLOCKS, so it fails open: an empty, absent or unparseable command is never a match,
# and only the irreversible operations of BLOCK_SET block. It reuses the lexer and the
# wrapper unwrapping, not the evaluators.

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
# dd may write these without destroying anything.
_HARMLESS_DEVICES = frozenset({"/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty"})
_HARMLESS_DEVICE_DIRS = ("/dev/fd/", "/dev/shm/")
_CHMOD_777 = re.compile(r"0*[0-7]?777")
_SQL_DESTRUCTIVE = ("DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE TABLE")
# A heredoc operator and its delimiter word (``<<EOF``, ``<<-'EOF'``, ``<< "END"``,
# ``<<\EOF``), matched where _split_heredocs finds an unquoted ``<<`` that is not a
# ``<<<`` here-string.
_HEREDOC = re.compile(r"<<(-?)[ \t]*(\\?)(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\3")
# A heredoc these read is a script they run, so its body is checked as commands.
_HEREDOC_SHELLS = SHELL_INTERPRETERS | {"ssh", "ash", "mksh"}

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


def _short_letters(flag: str) -> str:
    """The letters of a bundled short option (``-fu`` -> ``fu``); "" for anything else."""
    return flag[1:] if flag.startswith("-") and not flag.startswith("--") else ""


def _pushes_to_protected(refspec: str) -> bool:
    destination = refspec.rsplit(":", 1)[-1]
    return destination.rsplit("/", 1)[-1] in _PROTECTED_BRANCHES


def _guard_git(cmd: UnwrappedCommand) -> List[GuardRule]:
    flags = [f.lstrip("\\") for f in cmd.flags]
    letters = "".join(_short_letters(f) for f in flags)
    sub = cmd.subcommand
    found: List[GuardRule] = []
    if sub == "push":
        if "f" in letters or any(f == "--force" or f.split("=", 1)[0] == "--force-with-lease" for f in flags):
            found.append(_GUARD["git-push-force"])
        if any(arg.startswith("+") for arg in cmd.positional_args):
            found.append(_GUARD["git-push-refspec"])
        if any(_pushes_to_protected(arg) for arg in cmd.positional_args):
            found.append(_GUARD["git-push-protected"])
    elif sub == "reset" and "--hard" in flags:
        found.append(_GUARD["git-reset-hard"])
    elif sub == "clean":
        forced = "f" in letters or "--force" in flags
        dry_run = "n" in letters or "--dry-run" in flags
        if forced and not dry_run:
            found.append(_GUARD["git-clean-force"])
    elif sub == "merge" and not any(f in ("--abort", "--quit", "--continue") for f in flags):
        found.append(_GUARD["git-merge"])
    elif sub == "add" and (
        "A" in letters or "--all" in flags or any(arg in (".", "./", "*") for arg in cmd.positional_args)
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


def _writes_a_device(arg: str) -> bool:
    if not arg.startswith("of=/dev/"):
        return False
    device = arg[len("of="):]
    return device not in _HARMLESS_DEVICES and not device.startswith(_HARMLESS_DEVICE_DIRS)


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
        recursive = "--recursive" in flags or any(c in "rR" for f in flags for c in _short_letters(f))
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


def _feeds_a_shell(line: str, command_start: int, operator: int) -> bool:
    """Whether the heredoc whose operator is at ``line[operator]`` goes to a shell (or
    ssh): the command it belongs to, or a later stage of that command's pipeline on the
    same line (``cat <<EOF | bash``)."""
    for text in (line[command_start:], line[command_start:operator]):
        try:
            pipelines = decompose_command(tokenize_command(text))
        except ValueError:  # an unbalanced quote that closes on a later line
            continue
        for stage in pipelines[0].stages if pipelines else []:
            unwrapped, _ = unwrap_command_stage(stage.raw_tokens)
            if unwrapped is not None and unwrapped.binary.split("<<", 1)[0] in _HEREDOC_SHELLS:
                return True
        return False
    return False


def _heredoc_operators(line: str, open_quotes: List[str]) -> List[Tuple[bool, str, bool, bool]]:
    """``(strip_tabs, delimiter, feeds_a_shell, is_quoted)`` for each heredoc operator on
    ``line`` outside quotes and comments, in order. ``open_quotes`` is the stack of quotes
    and ``$(``/``(`` substitutions still open from earlier lines (a ``<<`` inside a
    substitution counts, even within double quotes); it is updated in place."""
    found: List[Tuple[bool, str, bool, bool]] = []
    command_start = 0
    index = 0
    while index < len(line):
        char = line[index]
        context = open_quotes[-1] if open_quotes else ""
        if context == "'":
            if char == "'":
                open_quotes.pop()
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if line.startswith("$(", index):
            open_quotes.append("(")
            index += 2
            command_start = index
            continue
        if context == '"':
            if char == '"':
                open_quotes.pop()
            index += 1
            continue
        if char in "'\"":
            open_quotes.append(char)
        elif char == "(":
            open_quotes.append("(")
            command_start = index + 1
        elif char == ")":
            if open_quotes:
                open_quotes.pop()
            command_start = index + 1
        elif char in ";&" or line.startswith("||", index):
            command_start = index + (2 if line.startswith("||", index) else 1)
        elif char == "#" and (index == 0 or line[index - 1] in " \t;&|()"):
            break  # a comment runs to the end of the line
        elif line.startswith("<<<", index):
            index += 3
            continue
        elif line.startswith("<<", index):
            heredoc = _HEREDOC.match(line, index)
            if heredoc is None:
                index += 2
                continue
            is_quoted = bool(heredoc.group(2) or heredoc.group(3))
            found.append((
                heredoc.group(1) == "-",
                heredoc.group(4),
                _feeds_a_shell(line, command_start, index),
                is_quoted,
            ))
            index = heredoc.end()
            continue
        index += 1
    return found


def _split_heredocs(text: str) -> Tuple[str, List[str]]:
    """``text`` without the body lines of its heredocs, and the bodies/substitutions a shell runs.

    A body is data for the command that reads it (Claude Code passes commit messages
    this way), unless that command is a shell or ssh (``bash <<'EOF'``, ``bash -s``,
    ``ssh host <<EOF``, ``cat <<EOF | sh``): then it is a script, returned to be checked
    as commands. For an unquoted heredoc (``<<EOF``), ``$(...)`` and backtick command
    substitutions inside the body are expanded by the shell before passing stdin, so any
    extracted subshells are also returned. A ``<<`` inside quotes or a comment is not an
    operator. An unterminated heredoc swallows the rest, as the shell would.
    """
    if "<<" not in text:
        return text, []
    lines = text.split("\n")
    kept: List[str] = []
    scripts: List[str] = []
    open_quotes: List[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        kept.append(line)
        index += 1
        for strip_tabs, delimiter, feeds_a_shell, is_quoted in _heredoc_operators(line, open_quotes):
            body: List[str] = []  # several heredocs on one line are read in order
            while index < len(lines):
                raw = lines[index].rstrip("\r")
                index += 1
                if (raw.lstrip("\t") if strip_tabs else raw) == delimiter:
                    break
                body.append(raw)
            if feeds_a_shell:
                scripts.append("\n".join(body))
            elif not is_quoted:
                body_text = "\n".join(body)
                if "$" in body_text or "`" in body_text:
                    scripts.extend(extract_subshell_commands(body_text))
    return "\n".join(kept), scripts


split_heredocs = _split_heredocs


def _guard_scan(cmd: str, depth: int, found: List[GuardRule]) -> bool:
    """Add the guard rules ``cmd`` matches to ``found``; False when it cannot be parsed
    (or nests deeper than MAX_DEPTH), which contributes nothing."""
    if depth >= MAX_DEPTH:
        return False
    text, scripts = _split_heredocs(cmd)
    try:
        tokens = tokenize_command(text)
    except ValueError:
        return False
    for script in scripts:
        _guard_scan(script, depth + 1, found)
    if any(c in text for c in ("$", "`", "(", "<", ">")):
        for sub in extract_subshell_commands(text):
            _guard_scan(sub, depth + 1, found)
    for pipeline in decompose_command(tokens):
        for stage in pipeline.stages:
            unwrapped, inner = unwrap_command_stage(stage.raw_tokens)
            if inner:
                _guard_scan(inner, depth + 1, found)
            elif unwrapped is not None:
                found.extend(_guard_stage(unwrapped))
    return True


def classify_command(command: object) -> Optional[GuardRule]:
    """The guard rule ``command`` matches: a BLOCK_SET rule when any matches, else the
    first RECORD_SET rule, else None.

    Fail-open: an empty or non-string command, one the lexer cannot parse, an
    unresolvable globbed binary and nesting beyond MAX_DEPTH are never a match.
    """
    if not isinstance(command, str) or not command.strip():
        return None
    found: List[GuardRule] = []
    if not _guard_scan(command, 0, found):
        return None
    text, _ = _split_heredocs(command)
    upper = text.upper()
    if any(pattern in upper for pattern in _SQL_DESTRUCTIVE):
        found.append(_GUARD["sql-destructive"])
    blocked = next((rule for rule in found if rule.tier == GUARD_BLOCK), None)
    return blocked or (found[0] if found else None)


__all__ = [
    "BLOCK_SET",
    "GUARD_BLOCK",
    "GUARD_RECORD",
    "RECORD_SET",
    "CodexPrefix",
    "GuardRule",
    "classify_command",
    "CommandAnalyzer",
    "SafetyEvaluation",
    "decompose_command",
    "extract_subshell_commands",
    "split_heredocs",
    "tokenize_command",
    "unwrap_command_stage",
    "REASON_CHMOD_777",
    "REASON_CMD_DELETE",
    "REASON_DB_DESTRUCTIVE",
    "REASON_DD",
    "REASON_GIT_ADD_BULK",
    "REASON_GIT_BRANCH",
    "REASON_GIT_CHECKOUT_FORCE",
    "REASON_GIT_CLEAN_FORCE",
    "REASON_GIT_CONFIG",
    "REASON_GIT_DIFF",
    "REASON_GIT_MERGE",
    "REASON_GIT_PUSH_FORCE",
    "REASON_GIT_PUSH_REFSPEC",
    "REASON_GIT_RESET_HARD",
    "REASON_KILL_ALL",
    "REASON_MKFS",
    "REASON_PIPE_TO_SHELL",
    "REASON_POWERSHELL_DELETE",
    "REASON_PROTECTED_BRANCH",
    "REASON_HUMAN_REVIEW_GATE",
    "REASON_RMDIR_BYPASS",
    "REASON_RM_RF",
    "REASON_RMTREE",
    "REASON_SUDO",
    "REASON_UNABLE_TO_PARSE",
    "REASON_WINDOWS_FORMAT",
]
