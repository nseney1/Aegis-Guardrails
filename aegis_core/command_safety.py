"""aegis_core.command_safety — Structured AST/token command safety analyzer.

Replaces monolithic regular expressions with lexical tokenization, wrapper unwrapping,
pipeline sequence analysis, and domain-specific command evaluators.
Zero external dependencies (pure stdlib). Target latency < 0.05ms.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import os
import posixpath
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

# Wrappers that run the rest of the line after their own options.
OPTION_WRAPPER_FLAGS_WITH_ARG: Dict[str, frozenset] = {
    "ionice": frozenset({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "setsid": frozenset(),
    "busybox": frozenset(),
}

SU_COMMAND_FLAGS = frozenset({"-c", "--command", "--session-command"})
SU_FLAGS_WITH_ARG = SU_COMMAND_FLAGS | {
    "-g", "--group", "-G", "--supp-group", "-s", "--shell", "-w", "--whitelist-environment"
}

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
_DELIMITER_PIECE = re.compile(r"&&|\|\||\|&|[;&|\n\r]")


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
    tail: list[str] = field(default_factory=list)  # raw tokens after a git/gh subcommand


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


_COMMENT_CONTEXTS = ("", "(", "$(")  # where a word starting with # is a comment
_WORD_BREAKS = " \t\n;&|()"


def strip_shell_comments(cmd: str) -> str:
    """``cmd`` without its shell comments, so a quote inside one (``# it's``) cannot
    unbalance the lexer. A ``#`` starts a comment only where a word starts, outside
    quotes, backticks and ``${...}`` (``a#b``, ``$#``, ``${#x}``, ``"a # b"`` stay);
    the comment runs up to, not including, its newline, which still ends the command.
    Unbalanced quotes are left for the lexer to fail on."""
    if "#" not in cmd:
        return cmd
    out: List[str] = []
    stack: List[str] = []  # open ' $' " ` ( $( ${
    word_start = True
    index = 0
    while index < len(cmd):
        char, pair = cmd[index], cmd[index:index + 2]
        top = stack[-1] if stack else ""
        step = 1
        if top in ("'", "$'"):
            if char == "\\" and top == "$'":
                step = 2
            elif char == "'":
                stack.pop()
        elif char == "\\":
            step = 2
        elif char == "#" and word_start and top in _COMMENT_CONTEXTS:
            end = cmd.find("\n", index)
            index = len(cmd) if end == -1 else end
            continue
        elif pair in ("$(", "${") or (pair == "$'" and top != '"'):
            stack.append(pair)
            step = 2
        elif (char == top and char in "\"`") or (char == "}" and top == "${") or (char == ")" and top in ("(", "$(")):
            stack.pop()
        elif char == "`" or (top != '"' and char in "'\"("):
            stack.append(char)
        out.append(cmd[index:index + step])
        if pair != "\\\n":  # a line continuation joins the words around it
            word_start = char in _WORD_BREAKS or pair == "$("
        index += step
    return "".join(out)


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

    for token in tokens:
        # shlex returns a run of adjacent delimiters (";\n", "\n\n", "&&\n", ";;") as one
        # token; split it back so the command after the run starts a new stage.
        pieces = _DELIMITER_PIECE.findall(token) if token and not token.strip("|;&\n\r") else (token,)
        for tok in pieces:
            if tok in seq_delims:
                flush_pipeline()
            elif tok in ("|", "|&"):
                flush_stage()
            else:
                curr_stage_tokens.append(tok)

    flush_pipeline()
    return pipelines


# ── Wrapper & Keyword Unwrapping Automaton ────────────────────────────────────

def _consume_option(tokens: list[str], idx: int, with_arg: frozenset) -> tuple[str, str | None, int]:
    """The option at ``tokens[idx]`` as ``(spelling, value, next index)``: ``--name=value``,
    ``--name value``, or a ``-xyz`` bundle, which ends at its first letter that takes a
    value (the rest of the token, else the next token)."""
    tok = tokens[idx]
    following = tokens[idx + 1] if idx + 1 < len(tokens) else None
    if tok.startswith("--"):
        name, eq, value = tok.partition("=")
        if eq or name not in with_arg:
            return name, value if eq else None, idx + 1
        return name, following, idx + 2
    for pos in range(1, len(tok)):
        if "-" + tok[pos] in with_arg:
            if pos + 1 < len(tok):
                return "-" + tok[pos], tok[pos + 1:], idx + 1
            return "-" + tok[pos], following, idx + 2
    return tok, None, idx + 1


def _su_command(tokens: list[str], idx: int) -> str | None:
    """The command ``su`` runs: the last -c/--command value anywhere after it (su passes
    arguments after ``--`` to the shell, so the scan does not stop there)."""
    command = None
    while idx < len(tokens):
        if tokens[idx].startswith("-"):
            spelling, value, idx = _consume_option(tokens, idx, SU_FLAGS_WITH_ARG)
            if spelling in SU_COMMAND_FLAGS:
                command = value
        else:
            idx += 1
    return command


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
                    _, _, idx = _consume_option(tokens, idx, SUDO_FLAGS_WITH_ARG)
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
                    spelling, value, idx = _consume_option(tokens, idx, ENV_FLAGS_WITH_ARG)
                    if spelling in ("-S", "--split-string"):
                        # The value is a command line; the words after it stay words.
                        return None, " ".join([value or ""] + [shlex.quote(t) for t in tokens[idx:]]).strip()
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

        # 7e. option-only wrappers: skip their options, the program follows
        if base in OPTION_WRAPPER_FLAGS_WITH_ARG:
            idx += 1
            while idx < len(tokens) and tokens[idx].startswith("-"):
                if tokens[idx] == "--":
                    idx += 1
                    break
                _, _, idx = _consume_option(tokens, idx, OPTION_WRAPPER_FLAGS_WITH_ARG[base])
            continue

        # 7f. su: the su stage itself (sudo su is still sudo) and the command it runs
        if base == "su":
            su_stage = UnwrappedCommand("su", None, [], [], has_sudo=has_sudo, env_vars=env_vars)
            return su_stage, _su_command(tokens, idx + 1)

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
        tail: list[str] = []

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
                    tail = tokens[idx + 1:]
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
            tail=tail,
        ), None

    return None, None


# ── Domain-Specific Command Evaluators ────────────────────────────────────────

def _long_option(flag: str, full: str) -> bool:
    """Whether ``flag`` spells the long option ``full``: git (parse-options) and GNU rm
    accept any unique prefix (``--har`` is ``--hard``). The bare ``--`` never matches; an
    ambiguous prefix the tool rejects may match, which only stops a failing command."""
    name = flag.split("=", 1)[0]
    return len(name) > 2 and full.startswith(name)


def evaluate_git(cmd: UnwrappedCommand) -> SafetyEvaluation:
    flags = [f.lstrip("\\") for f in cmd.flags]

    # git config override / exec-path injection
    for f in flags:
        if f in ("-c", "--exec-path", "--config-env") or f.startswith(("--exec-path=", "--config-env=")):
            return SafetyEvaluation(True, REASON_GIT_CONFIG)
    if any(var.startswith("GIT_CONFIG") and var != "GIT_CONFIG_NOSYSTEM" for var in cmd.env_vars):
        return SafetyEvaluation(True, REASON_GIT_CONFIG)

    sub = cmd.subcommand
    if not sub:
        return SafetyEvaluation(False)

    if sub == "branch":
        for f in flags:
            if _long_option(f, "--delete") or _long_option(f, "--force"):
                return SafetyEvaluation(True, REASON_GIT_BRANCH)
            if f.startswith("-") and not f.startswith("--"):
                letters = f[1:]
                if any(c in letters for c in "dDMf"):
                    return SafetyEvaluation(True, REASON_GIT_BRANCH)

    elif sub == "push":
        if any("f" in _short_letters(f) or _long_option(f, "--force") or _long_option(f, "--force-with-lease")
               for f in flags):
            return SafetyEvaluation(True, REASON_GIT_PUSH_FORCE)
        for arg in cmd.positional_args:
            if arg.startswith("+"):
                return SafetyEvaluation(True, REASON_GIT_PUSH_REFSPEC)
            if arg == "main" or arg.endswith(":main") or arg.endswith("/main"):
                return SafetyEvaluation(True, REASON_PROTECTED_BRANCH)

    elif sub == "reset":
        if any(_long_option(f, "--hard") for f in flags):
            return SafetyEvaluation(True, REASON_GIT_RESET_HARD)

    elif sub == "checkout":
        if any("f" in _short_letters(f) or _long_option(f, "--force") for f in flags):
            return SafetyEvaluation(True, REASON_GIT_CHECKOUT_FORCE)

    elif sub == "clean":
        for f in flags:
            if _long_option(f, "--force") or "f" in _short_letters(f):
                return SafetyEvaluation(True, REASON_GIT_CLEAN_FORCE)

    elif sub == "add":
        for f in flags:
            if "A" in _short_letters(f) or _long_option(f, "--all"):
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
        if _long_option(f, "--recursive"):
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
        if any(item.startswith("if=") or _writes_a_device(item) for item in all_items):
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
# dd may write these without destroying anything.
_HARMLESS_DEVICES = frozenset({"/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty"})
_HARMLESS_DEVICE_DIRS = ("/dev/fd/", "/dev/shm/")
_CHMOD_777 = re.compile(r"0*[0-7]?777")
_SQL_DESTRUCTIVE = ("DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE TABLE")
# A heredoc operator and its delimiter word (``<<EOF``, ``<<-'EOF'``, ``<< "END"``,
# ``<<\EOF``), matched where _split_heredocs finds an unquoted ``<<`` that is not a
# ``<<<`` here-string.
_HEREDOC = re.compile(r"<<(-?)[ \t]*(\\?)(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\3")
# A heredoc these read is a script they run, so its body is checked as commands
# (su without -c starts a shell that reads it).
_HEREDOC_SHELLS = SHELL_INTERPRETERS | {"ssh", "ash", "mksh", "su"}
# A heredoc these read is SQL, so its body is checked for destructive SQL (record tier).
_SQL_CLIENTS = frozenset({
    "psql", "pgcli", "mysql", "mycli", "mariadb", "sqlite3", "sqlcmd", "sqlplus", "duckdb", "usql", "cqlsh",
    "clickhouse-client", "snowsql",
})

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


def _clean_dry_run(flags: List[str]) -> bool:
    """Whether git clean's ``flags`` ask for a dry run, and no more often than git does:
    ``-e``/``--exclude`` take a value (``-en`` and ``-e -n`` exclude the pattern n or -n),
    a ``-n`` after ``--`` is a pathspec, and ``--no-dry-run`` cancels one."""
    dry_run = value_next = False
    for flag in flags:
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


def _guard_git(cmd: UnwrappedCommand) -> List[GuardRule]:
    flags = [f.lstrip("\\") for f in cmd.flags]
    letters = "".join(_short_letters(f) for f in flags)
    sub = cmd.subcommand
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
        if ("f" in letters or any(_long_option(f, "--force") for f in flags)) and not _clean_dry_run(flags):
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


def _writes_a_device(arg: str) -> bool:
    """Whether a dd operand writes a device, its path resolved lexically first
    (``of=//dev/sda`` and ``of=/tmp/../dev/sda`` write /dev/sda; ``of=/dev//null`` is
    /dev/null). The slash run is collapsed because normpath keeps a leading ``//``;
    posixpath, so Windows does not turn ``/`` into ``\\``."""
    if not arg.startswith("of=/"):
        return False
    device = posixpath.normpath("/" + arg[len("of="):].lstrip("/"))
    if not device.startswith("/dev/"):
        return False
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


def _reader_stages(line: str, command_start: int, operator: int) -> List[CommandStage]:
    """The stages that may read the heredoc whose operator is at ``line[operator]``: the
    command it belongs to and the rest of that command's pipeline on the same line
    (``cat <<EOF | bash``)."""
    for text in (line[command_start:], line[command_start:operator]):
        try:
            pipelines = decompose_command(tokenize_command(strip_shell_comments(text)))
        except ValueError:  # an unbalanced quote that closes on a later line
            continue
        return pipelines[0].stages if pipelines else []
    return []


def _feeds_a_shell(stages: List[CommandStage]) -> bool:
    for stage in stages:
        unwrapped, inner = unwrap_command_stage(stage.raw_tokens)
        if inner is None and unwrapped is not None and unwrapped.binary.split("<<", 1)[0] in _HEREDOC_SHELLS:
            return True
    return False


def _feeds_sql(stages: List[CommandStage]) -> bool:
    """Whether any word of the reading stages names a SQL client (``docker exec -i db
    psql``): a heuristic for a record-tier rule, so it errs towards recording."""
    for stage in stages:
        for token in stage.raw_tokens:
            name = os.path.basename(token.split("<<", 1)[0].lstrip("\\")).lower()
            if (name[:-4] if name.endswith(".exe") else name) in _SQL_CLIENTS:
                return True
    return False


def _heredoc_operators(line: str, open_quotes: List[str]) -> List[Tuple[bool, str, bool, bool, bool]]:
    """``(strip_tabs, delimiter, feeds_a_shell, feeds_sql, is_quoted)`` for each heredoc operator on
    ``line`` outside quotes and comments, in order. ``open_quotes`` is the stack of quotes
    and ``$(``/``(`` substitutions still open from earlier lines (a ``<<`` inside a
    substitution counts, even within double quotes); it is updated in place."""
    found: List[Tuple[bool, str, bool, bool, bool]] = []
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
            stages = _reader_stages(line, command_start, index)
            found.append((
                heredoc.group(1) == "-",
                heredoc.group(4),
                _feeds_a_shell(stages),
                _feeds_sql(stages),
                is_quoted,
            ))
            index = heredoc.end()
            continue
        index += 1
    return found


def _scan_heredocs(text: str) -> Tuple[str, List[str], List[str]]:
    """``text`` without the body lines of its heredocs, the bodies/substitutions a shell
    runs, and the bodies a SQL client reads (never put among the scripts).

    A body is data for the command that reads it (Claude Code passes commit messages
    this way), unless that command is a shell or ssh (``bash <<'EOF'``, ``bash -s``,
    ``ssh host <<EOF``, ``cat <<EOF | sh``): then it is a script, returned to be checked
    as commands. For an unquoted heredoc (``<<EOF``), ``$(...)`` and backtick command
    substitutions inside the body are expanded by the shell before passing stdin, so any
    extracted subshells are also returned. A ``<<`` inside quotes or a comment is not an
    operator. An unterminated heredoc swallows the rest, as the shell would.
    """
    if "<<" not in text:
        return text, [], []
    lines = text.split("\n")
    kept: List[str] = []
    scripts: List[str] = []
    sql_bodies: List[str] = []
    open_quotes: List[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        kept.append(line)
        index += 1
        for strip_tabs, delimiter, feeds_a_shell, feeds_sql, is_quoted in _heredoc_operators(line, open_quotes):
            body: List[str] = []  # several heredocs on one line are read in order
            while index < len(lines):
                raw = lines[index].rstrip("\r")
                index += 1
                if (raw.lstrip("\t") if strip_tabs else raw) == delimiter:
                    break
                body.append(raw)
            if feeds_a_shell:
                scripts.append("\n".join(body))
                continue
            if feeds_sql:
                sql_bodies.append("\n".join(body))
            if not is_quoted:
                body_text = "\n".join(body)
                if "$" in body_text or "`" in body_text:
                    scripts.extend(extract_subshell_commands(body_text))
    return "\n".join(kept), scripts, sql_bodies


def _split_heredocs(text: str) -> Tuple[str, List[str]]:
    kept, scripts, _ = _scan_heredocs(text)
    return kept, scripts


split_heredocs = _split_heredocs


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


def _guard_git_alias(cmd: UnwrappedCommand, depth: int, found: List[GuardRule]) -> None:
    """Classify the expansion of an alias defined on the same command line
    (``git -c alias.p='push -f' p``). _guard_git has already matched the literal
    subcommand, so a built-in still wins as it does in git; ``seen`` stops a cycle."""
    aliases = _git_aliases(cmd)
    seen = set()
    while cmd.subcommand in aliases and cmd.subcommand not in seen:
        seen.add(cmd.subcommand)
        value = aliases[cmd.subcommand]
        if value.startswith("!"):  # git runs it with sh -c, the arguments appended
            _guard_scan(" ".join([value[1:]] + [shlex.quote(t) for t in cmd.tail]), depth + 1, found)
            return
        try:
            words = shlex.split(value)
        except ValueError:
            return
        expanded, _ = unwrap_command_stage([cmd.binary, *words, *cmd.tail])
        if expanded is None:
            return
        found.extend(_guard_git(expanded))
        cmd = expanded


def _guard_scan(cmd: str, depth: int, found: List[GuardRule]) -> bool:
    """Add the guard rules ``cmd`` matches to ``found``; False when it cannot be parsed
    (or nests deeper than MAX_DEPTH), which contributes nothing."""
    if depth >= MAX_DEPTH:
        return False
    text, scripts = _split_heredocs(cmd)
    text = strip_shell_comments(text)  # after the split: a body apostrophe is not a quote
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
            if unwrapped is not None:
                found.extend(_guard_stage(unwrapped))
                if unwrapped.binary == "git":
                    _guard_git_alias(unwrapped, depth, found)
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
    text, scripts, sql_bodies = _scan_heredocs(command)
    upper = "\n".join([text, *scripts, *sql_bodies]).upper()
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
    "strip_shell_comments",
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
