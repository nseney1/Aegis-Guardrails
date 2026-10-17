"""Host hook payloads normalized to one shape (v4.1 spec §2 "Normalization").

``normalize(host, payload, environ)`` -> ``HookCall{host, tool, kind, command, paths,
workspace, workspace_source, call_id}`` or None for a payload it cannot use. Fixtures are
the documented PreToolUse stdin shapes (the source is cited above each fixture); no host
is ever run.
"""
from __future__ import annotations

import os

import pytest

from aegis_core.hook_events import (
    HOSTS,
    KIND_EDIT,
    KIND_OTHER,
    KIND_SHELL,
    apply_patch_paths,
    normalize,
)

WS = os.path.abspath(os.path.join(os.sep, "work", "project"))
SUB = os.path.join(WS, "pkg")


def _in(*parts: str) -> str:
    return os.path.join(WS, *parts)


# Claude Code PreToolUse stdin: https://code.claude.com/docs/en/hooks (PreToolUse input;
# Bash/PowerShell/Monitor tool_input.command, Write/Edit tool_input.file_path (absolute),
# NotebookEdit tool_input.notebook_path, tool_use_id).
def claude(tool_name, tool_input, **extra):
    payload = {
        "session_id": "abc123",
        "transcript_path": "/home/u/.claude/projects/p/abc123.jsonl",
        "cwd": WS,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "toolu_01ABC123",
    }
    payload.update(extra)
    return payload


# Codex CLI PreToolUse stdin: https://learn.chatgpt.com/docs/hooks and the source at
# rust-v0.162.1 (codex-rs/hooks/src/schema.rs PreToolUseCommandInput; shell tools are
# reported as "Bash" with tool_input.command, codex-rs/core/src/tools/hook_names.rs;
# apply_patch tool_input == {"command": <patch text>},
# codex-rs/core/src/tools/runtimes/apply_patch_tests.rs).
def codex(tool_name, command, **extra):
    payload = {
        "session_id": "019a-thread",
        "turn_id": "019a-turn",
        "transcript_path": "/home/u/.codex/sessions/rollout.jsonl",
        "cwd": WS,
        "hook_event_name": "PreToolUse",
        "model": "gpt-6.1-sol",
        "permission_mode": "default",
        "tool_name": tool_name,
        "tool_input": {"command": command},
        "tool_use_id": "call_9f2c",
    }
    payload.update(extra)
    return payload


# Antigravity PreToolUse stdin: https://antigravity.google/docs/hooks (toolCall.name,
# toolCall.args; run_command CommandLine; write_to_file, replace_file_content and
# multi_replace_file_content TargetFile; stepIdx; common fields).
def agy(name, args, **extra):
    payload = {
        "toolCall": {"name": name, "args": args},
        "stepIdx": 19,
        "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587",
        "workspacePaths": [WS],
        "transcriptPath": "~/.gemini/antigravity/brain/ec33/transcript.jsonl",
        "artifactDirectoryPath": "~/.gemini/antigravity/brain/ec33",
        "modelName": "gemini-3.6-flash-medium",
    }
    payload.update(extra)
    return payload


PATCH = """*** Begin Patch
*** Add File: src/new.py
+print("hi")
*** Update File: src/a.py
*** Move to: src/b.py
@@
-x = 1
+x = 2
*** Delete File: docs/old.md
*** End Patch
"""


def test_the_three_hook_hosts():
    assert HOSTS == ("claude-code", "codex-cli", "antigravity")


# ── Claude Code ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("tool", ["Bash", "PowerShell", "Monitor"])
def test_claude_shell_tools_carry_their_command(tool):
    call = normalize("claude-code", claude(tool, {"command": "git status", "description": "x"}), {})
    assert (call.host, call.tool, call.kind, call.command, call.paths) == ("claude-code", tool, KIND_SHELL, "git status", ())
    assert call.call_id == "toolu_01ABC123"


@pytest.mark.parametrize("tool,key", [("Write", "file_path"), ("Edit", "file_path"), ("NotebookEdit", "notebook_path")])
def test_claude_edit_tools_carry_their_path(tool, key):
    call = normalize("claude-code", claude(tool, {key: _in("src", "a.py"), "content": "x"}), {})
    assert (call.kind, call.paths, call.command) == (KIND_EDIT, (_in("src", "a.py"),), None)


def test_claude_workspace_is_the_project_dir_then_the_payload_cwd():
    payload = claude("Bash", {"command": "ls"}, cwd=SUB)
    with_env = normalize("claude-code", payload, {"CLAUDE_PROJECT_DIR": WS})
    assert (with_env.workspace, with_env.workspace_source) == (WS, "claude_project_dir")
    without = normalize("claude-code", payload, {})
    assert (without.workspace, without.workspace_source) == (SUB, "cwd")
    relative_env = normalize("claude-code", payload, {"CLAUDE_PROJECT_DIR": "relative/dir"})
    assert (relative_env.workspace, relative_env.workspace_source) == (SUB, "cwd")


def test_a_claude_tool_outside_the_matcher_is_other():
    call = normalize("claude-code", claude("Read", {"file_path": _in("a.py")}), {})
    assert (call.kind, call.paths, call.command) == (KIND_OTHER, (), None)


# ── Codex CLI ────────────────────────────────────────────────────────────────

def test_codex_bash_carries_its_command_and_the_payload_cwd():
    call = normalize("codex-cli", codex("Bash", "git push --force"), {"CLAUDE_PROJECT_DIR": "/elsewhere"})
    assert (call.kind, call.command, call.workspace, call.workspace_source) == (KIND_SHELL, "git push --force", WS, "cwd")
    assert call.call_id == "call_9f2c"


def test_codex_apply_patch_paths_come_from_the_patch_headers_against_the_cwd():
    call = normalize("codex-cli", codex("apply_patch", PATCH), {})
    assert call.kind == KIND_EDIT and call.command is None
    # Joined as given (no normpath: confinement resolves them later, symlinks included).
    assert call.paths == tuple(os.path.join(WS, p) for p in ("src/new.py", "src/a.py", "src/b.py", "docs/old.md"))


def test_a_codex_bash_apply_patch_heredoc_is_an_edit():
    """Codex intercepts `apply_patch <<'EOF'` run through its shell tool and applies the patch."""
    command = "apply_patch <<'EOF'\n" + PATCH + "EOF\n"
    call = normalize("codex-cli", codex("Bash", command), {})
    assert call.kind == KIND_EDIT and call.command is None
    assert call.paths[0] == os.path.join(WS, "src/new.py")


def test_a_codex_apply_patch_heredoc_after_cd_resolves_against_that_directory():
    command = "cd pkg && apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: mod.py\n@@\n-a\n+b\n*** End Patch\nEOF"
    call = normalize("codex-cli", codex("Bash", command), {})
    assert call.paths == (os.path.join(SUB, "mod.py"),)


def test_a_bash_command_that_only_mentions_apply_patch_is_a_shell_command():
    call = normalize("codex-cli", codex("Bash", "grep -r apply_patch src"), {})
    assert (call.kind, call.command) == (KIND_SHELL, "grep -r apply_patch src")


def test_an_absolute_patch_header_stays_absolute():
    other = os.path.abspath(os.path.join(os.sep, "elsewhere", "x.py"))
    call = normalize("codex-cli", codex("apply_patch", f"*** Begin Patch\n*** Add File: {other}\n+x\n*** End Patch\n"), {})
    assert call.paths == (other,)


@pytest.mark.parametrize("command", [
    "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: a.sh\n@@\n+git reset --hard\n*** End Patch\nEOF",
    'apply_patch <<"EOF"\n*** Begin Patch\n*** Update File: a.sh\n@@\n+git reset --hard\n*** End Patch\nEOF',
    "apply_patch <<\\EOF\n*** Begin Patch\n*** Update File: a.sh\n@@\n+git reset --hard\n*** End Patch\nEOF",
    "apply_patch <<- 'EOF'\n\t*** Begin Patch\n\t*** Update File: a.sh\n\t@@\n\t+git reset --hard\n\t*** End Patch\n\tEOF\n",
    "apply_patch <<EOF\n*** Begin Patch\n*** Update File: a.sh\n@@\n+git reset --hard\n*** End Patch\nEOF",
    "apply_patch '*** Begin Patch\n*** Update File: a.sh\n@@\n+git reset --hard\n*** End Patch'",
    'apply_patch "*** Begin Patch\n*** Update File: a.sh\n@@\n+git reset --hard\n*** End Patch"',
])
def test_pure_codex_apply_patch_forms_are_edits_without_a_shell_command(command):
    call = normalize("codex-cli", codex("Bash", command), {})
    assert (call.kind, call.command, call.paths) == (KIND_EDIT, None, (_in("a.sh"),))


@pytest.mark.parametrize("command", [
    "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch\nEOF\ngit reset --hard",
    "apply_patch <<'EOF' && git reset --hard\n*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch\nEOF",
    "apply_patch '*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch' && git reset --hard",
    'apply_patch "*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch" && git reset --hard',
    "apply_patch <<EOF\n*** Begin Patch\n*** Add File: a.py\n+$(git reset --hard)\n*** End Patch\nEOF",
    'apply_patch <<EOF\n*** Begin Patch\n*** Add File: a.py\n+$(echo ")" && git reset --hard)\n*** End Patch\nEOF',
    "apply_patch <<EOF\n*** Begin Patch\n*** Add File: a.py\n+`git reset --hard`\n*** End Patch\nEOF",
    'apply_patch "*** Begin Patch\n*** Add File: a.py\n+$(git reset --hard)\n*** End Patch"',
    "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch\nEOF\necho done",
])
def test_compound_or_expanding_codex_apply_patch_stays_a_shell_call_with_paths(command):
    call = normalize("codex-cli", codex("Bash", command), {})
    assert call.kind == KIND_SHELL
    assert call.command is not None
    assert call.paths == (_in("a.py"),)


# ── Antigravity ──────────────────────────────────────────────────────────────

def test_agy_run_command_carries_its_command_line_and_the_first_workspace_path():
    call = normalize("antigravity", agy("run_command", {"CommandLine": "npm test", "Cwd": WS}), {})
    assert (call.tool, call.kind, call.command) == ("run_command", KIND_SHELL, "npm test")
    assert (call.workspace, call.workspace_source) == (WS, "workspace_paths")
    assert call.call_id == "ec33ebf9-0cba-4100-8142-c61503f6c587:19"


@pytest.mark.parametrize("tool", ["write_to_file", "replace_file_content", "multi_replace_file_content"])
def test_agy_edit_tools_carry_their_target_file(tool):
    call = normalize("antigravity", agy(tool, {"TargetFile": _in("src", "a.py"), "Instruction": "x"}), {})
    assert (call.kind, call.paths) == (KIND_EDIT, (_in("src", "a.py"),))


def test_an_agy_relative_target_file_resolves_against_the_workspace_path():
    call = normalize("antigravity", agy("write_to_file", {"TargetFile": "src/a.py"}), {})
    assert call.paths == (os.path.join(WS, "src/a.py"),)


def test_an_agy_tool_outside_the_matcher_is_other():
    call = normalize("antigravity", agy("view_file", {"AbsolutePath": _in("a.py")}), {})
    assert call.kind == KIND_OTHER


def test_agy_without_a_step_index_has_no_call_id():
    payload = agy("run_command", {"CommandLine": "ls"})
    del payload["stepIdx"]
    assert normalize("antigravity", payload, {}).call_id is None
    payload["stepIdx"] = True  # a bool is not an index
    assert normalize("antigravity", payload, {}).call_id is None


# ── unusable parts never raise ───────────────────────────────────────────────

@pytest.mark.parametrize("host,payload", [
    ("claude-code", None),
    ("claude-code", ["Bash"]),
    ("claude-code", "{}"),
    ("gemini-cli", claude("Bash", {"command": "ls"})),
    ("", claude("Bash", {"command": "ls"})),
])
def test_an_unusable_payload_or_unknown_host_gives_none(host, payload):
    assert normalize(host, payload, {}) is None


@pytest.mark.parametrize("command", [None, "", "   ", 7, ["git", "push"]])
def test_a_shell_call_without_a_usable_command_has_none(command):
    call = normalize("claude-code", claude("Bash", {"command": command}), {})
    assert (call.kind, call.command) == (KIND_SHELL, None)


@pytest.mark.parametrize("tool_input", [None, "x", {"file_path": ""}, {"file_path": 3}, {}])
def test_an_edit_call_without_a_usable_path_has_no_paths(tool_input):
    call = normalize("claude-code", claude("Write", tool_input), {})
    assert (call.kind, call.paths) == (KIND_EDIT, ())


@pytest.mark.parametrize("cwd", [None, "", "relative/dir", 5])
def test_a_missing_or_relative_workspace_hint_is_none(cwd):
    call = normalize("codex-cli", codex("Bash", "ls", cwd=cwd), {})
    assert (call.workspace, call.workspace_source) == (None, None)


def test_without_a_workspace_hint_relative_paths_stay_relative():
    call = normalize("antigravity", agy("write_to_file", {"TargetFile": "src/a.py"}, workspacePaths=[]), {})
    assert (call.workspace, call.paths) == (None, ("src/a.py",))


@pytest.mark.parametrize("tool_call", [None, "run_command", {"name": 3, "args": {}}, {"name": "run_command", "args": "ls"}])
def test_a_malformed_agy_tool_call_never_raises(tool_call):
    call = normalize("antigravity", agy("run_command", {}, toolCall=tool_call), {})
    assert call.command is None


def test_a_missing_tool_use_id_is_none():
    call = normalize("claude-code", claude("Bash", {"command": "ls"}, tool_use_id=None), {})
    assert call.call_id is None


# ── apply_patch headers ──────────────────────────────────────────────────────

def test_patch_headers_in_order_without_duplicates():
    text = PATCH + "*** Begin Patch\n*** Update File: src/a.py\n*** End Patch\n"
    assert apply_patch_paths(text) == ("src/new.py", "src/a.py", "src/b.py", "docs/old.md")


def test_hunk_lines_are_not_headers():
    text = "*** Begin Patch\n*** Update File: a.py\n@@\n-*** Add File: fake.py\n+*** Delete File: fake2.py\n*** End Patch\n"
    assert apply_patch_paths(text) == ("a.py",)


def test_a_header_with_an_empty_path_is_ignored():
    assert apply_patch_paths("*** Begin Patch\n*** Add File:   \n*** End Patch\n") == ()
