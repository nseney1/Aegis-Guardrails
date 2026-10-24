"""The fail-closed analyzer behind ``aegis hook safety-gate``: the canonical reasons,
the domain evaluators and CommandAnalyzer, which asks on anything it cannot parse."""
from __future__ import annotations

from dataclasses import dataclass
import re

from aegis_core.command_safety.lexer import (
    MAX_DEPTH,
    REMOTE_FETCHERS,
    RM_DANGEROUS_TARGETS,
    SHELL_INTERPRETERS,
    UnwrappedCommand,
    _GIT_SHORT_VALUES,
    _long_option,
    _short_letters,
    _writes_a_device,
    decompose_command,
    extract_subshell_commands,
    tokenize_command,
    unwrap_command_stage,
)


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


@dataclass(frozen=True)
class SafetyEvaluation:
    is_destructive: bool
    reason: str = ""


# ── Domain-Specific Command Evaluators ────────────────────────────────────────

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
    values = _GIT_SHORT_VALUES.get(sub, "")

    if sub == "branch":
        for f in flags:
            if _long_option(f, "--delete") or _long_option(f, "--force"):
                return SafetyEvaluation(True, REASON_GIT_BRANCH)
            if any(c in _short_letters(f, values) for c in "dDMf"):
                return SafetyEvaluation(True, REASON_GIT_BRANCH)

    elif sub == "push":
        if any("f" in _short_letters(f, values) or _long_option(f, "--force") or _long_option(f, "--force-with-lease")
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
        if any("f" in _short_letters(f, values) or _long_option(f, "--force") for f in flags):
            return SafetyEvaluation(True, REASON_GIT_CHECKOUT_FORCE)

    elif sub == "clean":
        for f in flags:
            if _long_option(f, "--force") or "f" in _short_letters(f, values):
                return SafetyEvaluation(True, REASON_GIT_CLEAN_FORCE)

    elif sub == "add":
        for f in flags:
            if "A" in _short_letters(f, values) or _long_option(f, "--all"):
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
