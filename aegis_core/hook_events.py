"""Host hook payloads normalized to one shape (v4.1 spec §2 "Normalization").

``normalize(host, payload, environ)`` turns a PreToolUse stdin payload into a
:class:`HookCall`::

    {host, tool, kind: shell|edit|other, command, paths, workspace, workspace_source, call_id}

| Host | Shell tool -> command | Edit tools -> paths | call id |
|---|---|---|---|
| claude-code | Bash, PowerShell, Monitor -> tool_input.command | Write, Edit -> tool_input.file_path; NotebookEdit -> tool_input.notebook_path | tool_use_id |
| codex-cli | Bash -> tool_input.command | apply_patch -> the ``*** Add/Update/Delete File:`` and ``*** Move to:`` headers of tool_input.command; a Bash ``apply_patch`` heredoc likewise | tool_use_id |
| antigravity | run_command -> toolCall.args.CommandLine | write_to_file, replace_file_content, multi_replace_file_content -> toolCall.args.TargetFile | conversationId:stepIdx |

The workspace hint is where the host says the session runs: Claude ``CLAUDE_PROJECT_DIR``
(the hook's environment) then the payload ``cwd``; Codex ``cwd``; agy
``workspacePaths[0]`` (with the global agy hooks file the hook's own cwd is outside any
repository). Only an absolute hint counts. A relative edit path is joined to the hint
(or, for a Codex ``cd <dir> && apply_patch`` heredoc, to that directory) and is never
resolved here: the caller confines it under the governed root.

Normalization reads only the payload and the environment it is given, and never raises
for content: anything unusable becomes None (no payload), ``command=None`` or no paths.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Any, List, Mapping, Optional, Tuple

from aegis_core import command_safety

__all__ = [
    "HOSTS",
    "HookCall",
    "KIND_EDIT",
    "KIND_OTHER",
    "KIND_SHELL",
    "apply_patch_paths",
    "normalize",
]

HOSTS = ("claude-code", "codex-cli", "antigravity")
KIND_SHELL, KIND_EDIT, KIND_OTHER = "shell", "edit", "other"

_CLAUDE_SHELL = frozenset({"Bash", "PowerShell", "Monitor"})
_CLAUDE_EDIT = {"Write": "file_path", "Edit": "file_path", "NotebookEdit": "notebook_path"}
_AGY_EDIT = frozenset({"write_to_file", "replace_file_content", "multi_replace_file_content"})

_PATCH_HEADER = re.compile(r"\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)")
_HEREDOC_TOKEN = re.compile(r"<<-?[A-Za-z_][A-Za-z0-9_]*")
_HEREDOC_DELIM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class HookCall:
    """One tool call as every host's hook sees it.

    ``command`` is set only for a shell call with a non-empty command string; ``paths``
    for an edit call or a shell call that also applies a patch (absolute when the hint
    made them so, in payload order, without duplicates). ``workspace`` is the absolute
    workspace hint and ``workspace_source`` names it: "claude_project_dir", "cwd" or
    "workspace_paths".
    """

    host: str
    tool: str
    kind: str
    command: Optional[str]
    paths: Tuple[str, ...]
    workspace: Optional[str]
    workspace_source: Optional[str]
    call_id: Optional[str]


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _absolute(value: Any) -> Optional[str]:
    text = _text(value)
    return text if text is not None and os.path.isabs(text) else None


def _joined(paths: List[str], base: Optional[str]) -> Tuple[str, ...]:
    out = [p if base is None or os.path.isabs(p) else os.path.join(base, p) for p in paths]
    return tuple(dict.fromkeys(out))


def apply_patch_paths(text: str) -> Tuple[str, ...]:
    """The file paths an apply_patch text names, in order, without duplicates: every
    ``*** Add File:``, ``*** Update File:``, ``*** Delete File:`` and ``*** Move to:``
    header (a hunk line starts with ``+``, ``-``, space or ``@`` and is never one)."""
    found: List[str] = []
    for line in text.splitlines():
        header = _PATCH_HEADER.fullmatch(line.strip())
        if header:
            path = header.group(1).strip()
            if path:
                found.append(path)
    return tuple(dict.fromkeys(found))


def _parse_codex_patch(
    command: str, base: Optional[str]
) -> Tuple[bool, Optional[str], Tuple[str, ...]]:
    """Classify a Codex Bash command that may carry an ``apply_patch`` payload.

    Returns ``(is_pure_edit, safe_shell_command, patched_paths)``.
    """
    if "*** Begin Patch" not in command:
        return False, command, ()
    shell_text, heredoc_scripts = command_safety.split_heredocs(command)
    subshells = command_safety.extract_subshell_commands(shell_text)
    try:
        tokens = command_safety.tokenize_command(shell_text)
    except ValueError:
        tokens = []
    pipelines = command_safety.decompose_command(tokens) if tokens else []
    if (
        pipelines
        and len(pipelines[0].stages) == 1
        and len(pipelines[0].stages[0].raw_tokens) == 2
        and pipelines[0].stages[0].raw_tokens[0] == "cd"
        and not subshells
    ):
        cd_dir = pipelines[0].stages[0].raw_tokens[1]
        base = cd_dir if os.path.isabs(cd_dir) else (os.path.join(base, cd_dir) if base else None)
    patched = _joined(list(apply_patch_paths(command)), base)
    if not heredoc_scripts and not subshells and all(len(p.stages) == 1 for p in pipelines):
        stage = (
            pipelines[0].stages[0].raw_tokens
            if len(pipelines) == 1
            else (
                pipelines[1].stages[0].raw_tokens
                if len(pipelines) == 2 and len(tokens) >= 3 and tokens[0] == "cd" and tokens[2] == "&&"
                else []
            )
        )
        if stage and stage[0] in ("apply_patch", "applypatch"):
            rest = stage[1:]
            is_heredoc = "*** Begin Patch" not in shell_text and (
                (len(rest) == 1 and bool(_HEREDOC_TOKEN.fullmatch(rest[0])))
                or (len(rest) == 2 and rest[0] in ("<<", "<<-") and bool(_HEREDOC_DELIM.fullmatch(rest[1])))
            )
            is_arg = len(rest) == 1 and "*** Begin Patch" in rest[0]
            if (is_heredoc or is_arg) and patched:
                return True, None, patched
    safe_cmd = (
        command
        if shell_text != command
        else re.sub(r"'[^']*\*\*\* Begin Patch[^']*'", "''", command)
    )
    return False, safe_cmd, patched


def _claude(payload: Mapping[str, Any], environ: Mapping[str, str]) -> HookCall:
    project = _absolute(environ.get("CLAUDE_PROJECT_DIR"))
    cwd = _absolute(payload.get("cwd"))
    workspace, source = (project, "claude_project_dir") if project else (cwd, "cwd" if cwd else None)
    tool = payload.get("tool_name") if isinstance(payload.get("tool_name"), str) else ""
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    kind, command, paths = KIND_OTHER, None, ()
    if tool in _CLAUDE_SHELL:
        kind, command = KIND_SHELL, _text(tool_input.get("command"))
    elif tool in _CLAUDE_EDIT:
        path = _text(tool_input.get(_CLAUDE_EDIT[tool]))
        kind, paths = KIND_EDIT, _joined([path] if path else [], workspace)
    return HookCall("claude-code", tool, kind, command, paths, workspace, source, _text(payload.get("tool_use_id")))


def _codex(payload: Mapping[str, Any]) -> HookCall:
    cwd = _absolute(payload.get("cwd"))
    tool = payload.get("tool_name") if isinstance(payload.get("tool_name"), str) else ""
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    text = _text(tool_input.get("command"))
    kind, command, paths = KIND_OTHER, None, ()
    if tool == "apply_patch":
        kind, paths = KIND_EDIT, _joined(list(apply_patch_paths(text)) if text else [], cwd)
    elif tool == "Bash":
        if text:
            is_edit, command, paths = _parse_codex_patch(text, cwd)
            kind = KIND_EDIT if is_edit else KIND_SHELL
        else:
            kind = KIND_SHELL
    return HookCall("codex-cli", tool, kind, command, paths, cwd, "cwd" if cwd else None, _text(payload.get("tool_use_id")))


def _agy(payload: Mapping[str, Any]) -> HookCall:
    spaces = payload.get("workspacePaths")
    first = _absolute(spaces[0]) if isinstance(spaces, list) and spaces else None
    call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool = call.get("name") if isinstance(call.get("name"), str) else ""
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    kind, command, paths = KIND_OTHER, None, ()
    if tool == "run_command":
        kind, command = KIND_SHELL, _text(args.get("CommandLine"))
    elif tool in _AGY_EDIT:
        target = _text(args.get("TargetFile"))
        kind, paths = KIND_EDIT, _joined([target] if target else [], first)
    conversation, step = _text(payload.get("conversationId")), payload.get("stepIdx")
    call_id = f"{conversation}:{step}" if conversation and type(step) is int else None
    return HookCall("antigravity", tool, kind, command, paths, first, "workspace_paths" if first else None, call_id)


def normalize(host: str, payload: Any, environ: Optional[Mapping[str, str]] = None) -> Optional[HookCall]:
    """The HookCall of one PreToolUse ``payload`` from ``host`` (one of HOSTS), or None
    when the host is unknown or the payload is not a JSON object. ``environ`` is the
    hook's environment (os.environ when None); only Claude's CLAUDE_PROJECT_DIR is read."""
    if host not in HOSTS or not isinstance(payload, dict):
        return None
    if host == "claude-code":
        return _claude(payload, os.environ if environ is None else environ)
    if host == "codex-cli":
        return _codex(payload)
    return _agy(payload)
