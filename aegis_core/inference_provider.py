"""Layer 2 model backend: one external command, so Aegis needs no SDKs or API keys.

The command (for example ``claude -p`` or ``codex exec``) is run as an argv list with no
shell. It reads the prompt on stdin and prints the reply on stdout.
It comes only from ``--llm-cmd`` or ``AEGIS_LLM_CMD``: a file in the repository being
checked must never choose what Aegis executes (BUG-073).

The command runs in a fresh empty directory, not in the repository: agent CLIs load
project config from their working directory (``.claude/settings.json`` hooks,
``AGENTS.md``/``GEMINI.md`` instructions, MCP servers), and the code under review must
not be able to steer its reviewer. The prompt carries everything the review needs. So a
script in the command needs an absolute path, and ``codex exec`` needs
``--skip-git-repo-check``.

A bare program name is looked up here, in absolute PATH entries only
(aegis_core.pathlookup): an empty or relative entry names aegis's own cwd, often the
repository, and on Windows CreateProcess searches that cwd first and applies no PATHEXT.
A Windows batch file (npm's ``claude.cmd`` or ``codex.cmd``) runs under
``cmd.exe /d /s /c`` with every argument quoted for cmd.exe and the C runtime; an
argument holding a line break, which cmd.exe would take as the end of the command, is
refused.
"""
from __future__ import annotations

import errno
import ntpath
import os
import shutil
import subprocess
import sys
import tempfile
from typing import List, Mapping, Optional, Sequence, Tuple, Union

from aegis_core import pathlookup
from aegis_core.argv import split_command
from aegis_core.config import ENV_LLM_CMD, env_llm_cmd

ENV_VAR = ENV_LLM_CMD
MISSING_BACKEND = f"Layer 2 needs --llm-cmd or {ENV_VAR}"
DEFAULT_TIMEOUT = 600.0

__all__ = ["CommandBackend", "DEFAULT_TIMEOUT", "ENV_VAR", "LLMCommandError", "MISSING_BACKEND", "resolve_backend"]


class LLMCommandError(RuntimeError):
    """The Layer 2 command is malformed, could not start, timed out or failed."""


class CommandBackend:
    """Runs the Layer 2 command once per prompt."""

    def __init__(self, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT):
        if not argv:
            raise LLMCommandError("LLM command is empty")
        self.argv: List[str] = list(argv)
        self.timeout = timeout

    def _start(self) -> Tuple[Union[str, List[str]], Optional[str]]:
        """What to start: (args, executable)."""
        program = self.argv[0]
        if pathlookup.is_bare(program):
            found = pathlookup.which(program)
            if found is None:
                raise LLMCommandError(f"cannot run LLM command {program}: {os.strerror(errno.ENOENT)}")
            program = found
        if sys.platform == "win32" and os.path.splitext(program)[1].lower() in (".cmd", ".bat"):
            return _batch_command_line(program, self.argv[1:]), _comspec()
        return [program, *self.argv[1:]], None

    def generate(self, prompt: str) -> str:
        args, executable = self._start()
        # input= gives the child a fresh stdin pipe, so it can never read (and steal)
        # this process's stdin, which carries JSON-RPC when Aegis runs under MCP.
        workdir = tempfile.mkdtemp(prefix="aegis-llm-")
        try:
            # encoding= opens the pipes in text mode; text=True would say it twice.
            proc = subprocess.run(
                args, executable=executable, input=prompt, capture_output=True, cwd=workdir,
                encoding="utf-8", errors="replace", timeout=self.timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            raise LLMCommandError(f"LLM command timed out after {self.timeout:g}s: {self.argv[0]}") from None
        except OSError as exc:
            raise LLMCommandError(f"cannot run LLM command {self.argv[0]}: {exc.strerror or exc}") from None
        finally:
            # Not TemporaryDirectory: ignore_cleanup_errors needs 3.10, and a Windows child
            # killed on timeout may briefly hold a file in it.
            shutil.rmtree(workdir, ignore_errors=True)
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip().splitlines()
            raise LLMCommandError(f"LLM command exited {proc.returncode}: {detail[-1] if detail else 'no stderr'}")
        return proc.stdout


def _comspec() -> str:
    comspec = os.environ.get("ComSpec", "")
    if ntpath.isabs(comspec):
        return comspec
    return ntpath.join(os.environ.get("SystemRoot") or "C:\\Windows", "System32", "cmd.exe")


def _cmd_quote(text: str) -> str:
    """One argument for a batch file, quoted for cmd.exe and then the C runtime.

    Inside double quotes cmd.exe treats & | < > ( ) ^ as text; a quote is doubled (``""``
    keeps cmd.exe inside the quotes and is a literal quote to the C runtime); backslashes
    are doubled only before a quote; ``%`` becomes ``%%cd:~,%``, which cmd.exe expands to
    a bare ``%`` (an empty substring of %cd%), so no %VAR% in the text expands. Delayed
    ``!VAR!`` expansion is off (/v:OFF). The scheme is Rust's std after CVE-2024-24576.
    """
    if "\r" in text or "\n" in text:
        raise LLMCommandError(f"cannot pass {text!r} to a batch file: cmd.exe ends the command at a line break")
    out = ['"']
    backslashes = 0
    for ch in text:
        if ch == "\\":
            backslashes += 1
        else:
            if ch == '"':
                out.append("\\" * backslashes + '"')
            elif ch == "%":
                out.append("%%cd:~,")
            backslashes = 0
        out.append(ch)
    out.append("\\" * backslashes + '"')
    return "".join(out)


def _batch_command_line(script: str, args: Sequence[str]) -> str:
    """The cmd.exe command line that runs ``script`` with ``args`` unchanged.

    /d skips AutoRun commands, /e:ON enables the substring syntax ``%%cd:~,%`` needs,
    /s strips exactly the outer pair of quotes.
    """
    quoted = " ".join(_cmd_quote(part) for part in (script, *args))
    return f'cmd.exe /d /e:ON /v:OFF /s /c "{quoted}"'


def resolve_backend(flag: Optional[str], environ: Optional[Mapping[str, str]] = None) -> Optional[CommandBackend]:
    """The backend named by ``--llm-cmd`` (first) or ``AEGIS_LLM_CMD``; None when neither is set."""
    raw = flag if flag and flag.strip() else (env_llm_cmd(environ) or "")
    if not raw.strip():
        return None
    try:
        return CommandBackend(split_command(raw))
    except ValueError as exc:
        raise LLMCommandError(f"cannot parse --llm-cmd / {ENV_VAR} {raw!r}: {exc}") from None
