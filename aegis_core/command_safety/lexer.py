"""The shell lexer both command policies share (the analyzer and the guard).

Tokenizing, subshell extraction, pipeline decomposition, wrapper unwrapping, the heredoc
scanner and the option and operand helpers the two policies read alike.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import os
import posixpath
import re
import shlex
from typing import Dict, List, Tuple


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


# ── Option & Operand Helpers (shared by the analyzer and the guard) ───────────

def _long_option(flag: str, full: str) -> bool:
    """Whether ``flag`` spells the long option ``full``: git (parse-options) and GNU rm
    accept any unique prefix (``--har`` is ``--hard``). The bare ``--`` never matches; an
    ambiguous prefix the tool rejects may match, which only stops a failing command."""
    name = flag.split("=", 1)[0]
    return len(name) > 2 and full.startswith(name)


# dd may write these without destroying anything.
_HARMLESS_DEVICES = frozenset({"/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty"})
_HARMLESS_DEVICE_DIRS = ("/dev/fd/", "/dev/shm/")


#: The short options that take a value, for the git subcommands whose bundles the guard
#: or the gate reads (from ``git <subcommand> -h``); -t takes one only when it is stuck.
_GIT_SHORT_VALUES: Dict[str, str] = {"push": "o", "checkout": "bBt", "clean": "e", "branch": "ut"}


def _short_letters(flag: str, takes_value: str = "") -> str:
    """The option letters of a bundled short option (``-fu`` -> ``fu``); "" for anything
    else. The bundle ends at its first letter in ``takes_value``, as in git's
    parse-options: the rest of the token is that option's value (``-ofeature`` -> ``o``)."""
    letters = flag[1:] if flag.startswith("-") and not flag.startswith("--") else ""
    for index, letter in enumerate(letters):
        if letter in takes_value:
            return letters[:index + 1]
    return letters


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


# ── Heredoc Scanner ───────────────────────────────────────────────────────────

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
