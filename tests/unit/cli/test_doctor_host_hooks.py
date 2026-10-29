"""`aegis doctor`: the per-host PreToolUse hooks (v4.1 spec §2 Doctor, AD-8 honest tiers).

Doctor reads the host hook files and reports, per host, whether an Aegis entry is there
and points at an executable `aegis`, the tier that entry would give with its evidence
label (DOC or LIVE), duplicates, files the host cannot parse and v3 leftovers. Presence
is never enforcement: a registered hook changes no host's ``enforcement_level``, and the
best-effort tier stays ``unknown`` because doctor cannot see a host run it. ``--fix``
removes v3 hook entries (``remove_list_items``) or the stale v3 Antigravity plugin file,
with a backup.

Everything runs in a fake HOME with stub binaries; no host CLI is started.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Dict, List

import pytest

from aegis_cli import doctor, doctor_base
from aegis_cli.doctor import run_doctor
from aegis_cli.hooks import registrar
from aegis_core.bootstrap import BOOTSTRAP_ID, bootstrap_text

TIERS = {
    "claude-code": ("blocking (documented; fails open on error)", "DOC"),
    "codex-cli": ("blocking once trusted in /hooks (documented; fails open)", "DOC"),
    "antigravity": ("blocks destructive commands (live); scan gate records only", "LIVE"),
}


class Env:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        self.tmp = tmp_path
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.ws = tmp_path / "repo"
        rules = self.ws / ".aegis" / "rules" / "invariants"
        rules.mkdir(parents=True)
        (rules / "invariant-sample.md").write_text(
            "---\nid: invariant-sample\ntype: invariant\nenforcement: gate\n"
            "hypothesis: Sample rule for doctor tests.\ntarget_paths:\n  - src/*.py\n---\n"
            "# Sample\n\nKeep the sample rule body long enough to be a real rule body.\n", encoding="utf-8")
        body = bootstrap_text()
        sha = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
        (self.ws / "AGENTS.md").write_text(
            f"<!-- aegis:begin id={BOOTSTRAP_ID} v=1 sha={sha} -->\n{body}<!-- aegis:end id={BOOTSTRAP_ID} -->\n",
            encoding="utf-8")
        for name, value in (("HOME", self.home), ("USERPROFILE", self.home), ("PATH", self.bin),
                            ("APPDATA", self.home / "AppData" / "Roaming")):
            monkeypatch.setenv(name, str(value))
        for name in ("CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "CODEX_HOME", "AEGIS_WORKSPACE", "AEGIS_CLIENT"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(doctor, "_run_host_cli", self._no_cli)
        monkeypatch.setattr(registrar, "_windows", lambda: False)
        suffix = ".exe" if os.name == "nt" else ""  # Windows finds a program on PATH only under a PATHEXT name
        for name in ("aegis", "aegis-mcp"):
            stub = self.bin / (name + suffix)
            stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            stub.chmod(0o755)
        self.aegis = str(self.bin / ("aegis" + suffix))
        if not registrar.AEGIS_PATH_CHARSET.fullmatch(self.aegis):
            # A native Windows path ('\\' and ':') is outside the shell-form charset, so
            # install would refuse the Codex and Antigravity entries these tests read back.
            # What install accepts is test_hook_install_hosts's subject; here, as with
            # _windows above, the stub's own path is let through.
            monkeypatch.setattr(registrar, "AEGIS_PATH_CHARSET", re.compile(r".+"))

    @staticmethod
    def _no_cli(argv, cwd, timeout):
        raise AssertionError(f"doctor hook tests run no host CLI: {argv}")

    def install(self, host: str, scope: str = "user") -> registrar.HookResult:
        return registrar.install(host, scope, home=self.home, root=self.ws, aegis=self.aegis, environ={})

    def write_json(self, path: Path, data: Any) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def run(self, **kw):
        args = argparse.Namespace(workspace=str(self.ws), fix=False, yes=False, drivers=False, json=False)
        for key, value in kw.items():
            setattr(args, key, value)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_doctor(args)
        return rc, buf.getvalue()

    def doctor(self, **kw) -> Dict[str, Any]:
        rc, out = self.run(json=True, **kw)
        payload = json.loads(out)
        payload["_rc"] = rc
        return payload

    def fix(self) -> Dict[str, Any]:
        return self.doctor(fix=True, yes=True)

    def backups(self) -> List[Path]:
        root = self.home / ".aegis" / "backups"
        return sorted(root.iterdir()) if root.is_dir() else []


@pytest.fixture
def env(tmp_path, monkeypatch) -> Env:
    return Env(tmp_path, monkeypatch)


def hooks(payload: Dict[str, Any], host_id: str) -> Dict[str, Any]:
    return next(r for r in payload["hosts"] if r["id"] == host_id)["hooks"]


def tier(payload: Dict[str, Any], name: str) -> Dict[str, Any]:
    return next(t for t in payload["enforcement_tiers"] if t["tier"] == name)


def findings(payload: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
    return [f for f in payload["findings"] if f["code"] == code]


def handler(command: str, **extra) -> Dict[str, Any]:
    out = {"type": "command", "command": command}
    out.update(extra)
    return out


def _snapshot(root: Path) -> Dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ── per-host rows: presence, tier, evidence ────────────────────────────────

def test_without_hooks_each_host_row_says_absent_and_names_the_tier_install_would_give(env):
    payload = env.doctor()
    for host_id, (text, evidence) in TIERS.items():
        row = hooks(payload, host_id)
        assert row["status"] == "absent" and row["entries"] == [] and row["trust"] is None
        assert (row["tier"], row["evidence"]) == (text, evidence)
    best = tier(payload, "best_effort")
    assert best["status"] == "inactive" and best["hosts"] == []
    assert best["mechanism"] == "per-host pre-tool hooks"
    assert "aegis hook install --host" in best["detail"]


def test_a_registered_hook_is_presence_never_enforcement(env):
    before = {r["id"]: r["enforcement_level"] for r in env.doctor()["hosts"]}
    env.install("claude-code")
    payload = env.doctor()
    row = hooks(payload, "claude-code")
    assert row["status"] == "registered"
    assert row["entries"] == [{"scope": "user", "path": str(env.home / ".claude" / "settings.json"),
                               "aegis": env.aegis, "executable": True, "modified": False}]
    assert {r["id"]: r["enforcement_level"] for r in payload["hosts"]} == before
    best = tier(payload, "best_effort")
    assert best["status"] == "unknown" and best["hosts"] == ["claude-code"]
    assert "claude-code: blocking (documented; fails open on error) [DOC]" in best["detail"]
    assert "cannot confirm" in best["detail"]
    assert [f for f in payload["findings"] if "hook" in f["code"]] == []


def test_codex_needs_an_approval_in_hooks_that_doctor_cannot_check(env):
    env.install("codex-cli")
    payload = env.doctor()
    assert hooks(payload, "codex-cli")["status"] == "registered"
    assert hooks(payload, "codex-cli")["trust"] == "needs approval in /hooks (cannot be checked)"
    assert hooks(payload, "claude-code")["trust"] is None
    assert "needs approval in /hooks (cannot be checked)" in tier(payload, "best_effort")["detail"]


def test_antigravity_blocking_is_live_and_its_scan_gate_only_records(env):
    env.install("antigravity", "project")
    row = hooks(env.doctor(), "antigravity")
    assert row["status"] == "registered" and row["entries"][0]["scope"] == "project"
    assert row["entries"][0]["path"] == str(env.ws / ".agents" / "hooks.json")
    assert (row["tier"], row["evidence"]) == TIERS["antigravity"]


def test_antigravity_hooks_are_unavailable_on_windows(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    payload = env.doctor()
    row = hooks(payload, "antigravity")
    assert row["status"] == "unavailable" and row["tier"] == "unavailable" and row["evidence"] is None
    assert "Windows" in row["detail"]
    assert hooks(payload, "claude-code")["status"] == "absent"


def test_only_unavailable_hosts_make_the_best_effort_tier_unavailable(env, monkeypatch):
    (env.ws / ".aegis" / "config.json").write_text(json.dumps({"v": 1, "hosts": ["antigravity"]}), encoding="utf-8")
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    best = tier(env.doctor(), "best_effort")
    assert best["status"] == "unavailable" and best["hosts"] == []
    assert best["detail"] == registrar.unavailable_reason("antigravity")


def test_an_ungoverned_workspace_runs_no_hook_even_where_one_is_registered(env, tmp_path):
    env.install("claude-code")
    plain = tmp_path / "plain"
    plain.mkdir()
    args = argparse.Namespace(workspace=str(plain), fix=False, yes=False, drivers=False, json=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_doctor(args)
    payload = json.loads(buf.getvalue())
    assert hooks(payload, "claude-code")["status"] == "registered"
    best = tier(payload, "best_effort")
    assert best["status"] == "inactive" and "no .aegis/" in best["detail"]


# ── what doctor flags ───────────────────────────────────────────────────────

@pytest.mark.parametrize("second", ["project", "local"])
def test_a_second_aegis_entry_is_a_duplicate(env, second):
    env.install("claude-code")
    other = {"project": env.ws / ".claude" / "settings.json",
             "local": env.ws / ".claude" / "settings.local.json"}[second]
    env.write_json(other, {"hooks": {"PreToolUse": [registrar.hook_group("claude-code", env.aegis)]}})
    payload = env.doctor()
    row = hooks(payload, "claude-code")
    assert row["status"] == "duplicate"
    assert [e["scope"] for e in row["entries"]] == ["user", second]
    (dup,) = findings(payload, "duplicate_hook")
    assert dup["fixable"] is False and "twice" in dup["message"]
    assert str(other) in dup["message"] or "~/" in dup["message"]
    rc, out = env.run()
    assert f"hooks        2 Aegis entries (user, {second}): keep one" in out


def test_an_entry_whose_aegis_is_gone_is_broken_and_fails_open(env):
    gone = str(env.tmp / "old-venv" / "bin" / "aegis")
    env.write_json(env.home / ".codex" / "hooks.json",
                   {"hooks": {"PreToolUse": [registrar.hook_group("codex-cli", gone)]}})
    payload = env.doctor()
    row = hooks(payload, "codex-cli")
    assert row["status"] == "broken"
    assert row["entries"] == [{"scope": "user", "path": str(env.home / ".codex" / "hooks.json"),
                               "aegis": gone, "executable": False, "modified": False}]
    (missing,) = findings(payload, "hook_aegis_missing")
    assert gone in missing["message"]
    assert missing["message"].endswith("(it fails open): run aegis hook install --host codex-cli")
    rc, out = env.run()
    assert f"hooks        registered, but {gone} is missing or not executable (fails open)" in out
    best = tier(payload, "best_effort")
    assert best["status"] == "inactive" and best["hosts"] == []
    assert best["detail"] == ("no Aegis PreToolUse hook registered for claude-code, antigravity; the Aegis "
                              "hook of codex-cli runs a missing aegis: run aegis hook install --host <host>")


@pytest.mark.parametrize("scope, fix", [
    ("project", "run aegis hook install --host claude-code --scope project"),
    ("local", "remove it from that file, then run aegis hook install --host claude-code"),
])
def test_a_broken_entry_outside_the_user_scope_names_its_own_fix(env, scope, fix):
    name = {"project": "settings.json", "local": "settings.local.json"}[scope]
    gone = str(env.tmp / "gone" / "aegis")
    env.write_json(env.ws / ".claude" / name,
                   {"hooks": {"PreToolUse": [registrar.hook_group("claude-code", gone)]}})
    (missing,) = findings(env.doctor(), "hook_aegis_missing")
    assert missing["message"].endswith(f"(it fails open): {fix}")


def test_a_non_executable_aegis_is_broken(env):
    if os.name == "nt":
        pytest.skip("Windows has no execute bit")
    plain = env.tmp / "plain" / "aegis"
    plain.parent.mkdir()
    plain.write_text("#!/bin/sh\n", encoding="utf-8")
    plain.chmod(0o644)
    env.write_json(env.home / ".claude" / "settings.json",
                   {"hooks": {"PreToolUse": [registrar.hook_group("claude-code", str(plain))]}})
    assert hooks(env.doctor(), "claude-code")["status"] == "broken"


# ── drift: an Aegis entry that is not the one install writes ────────────────

def _edit_first_entry(env, path: Path, group: Dict[str, Any], handler: Dict[str, Any]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    first = data["hooks"]["PreToolUse"][0]
    first.update(group)
    first["hooks"][0].update(handler)
    env.write_json(path, data)


@pytest.mark.parametrize("group, handler", [
    ({"matcher": "Read"}, {}),
    ({}, {"args": ["hook", "run", "pre-tool", "--host", "codex-cli"]}),
    ({}, {"args": ["hook", "run", "pre-tool"]}),
    ({}, {"timeout": 0}),
    ({}, {"type": "prompt"}),
], ids=["matcher", "other-host", "no-host", "timeout", "type"])
def test_an_entry_that_is_not_what_install_writes_is_modified_and_claims_no_tier(env, group, handler):
    path = env.install("claude-code").path
    _edit_first_entry(env, path, group, handler)
    payload = env.doctor()
    row = hooks(payload, "claude-code")
    assert row["status"] == "modified"
    assert row["entries"] == [{"scope": "user", "path": str(path), "aegis": env.aegis, "executable": True,
                               "modified": True}]
    best = tier(payload, "best_effort")
    assert best["status"] == "unknown" and best["hosts"] == []
    assert best["detail"] == ("cannot tell for claude-code: its Aegis hook entry is not the one aegis hook "
                              "install writes (see the warnings)")
    (finding,) = findings(payload, "hook_entry_modified")
    assert finding["fixable"] is False
    assert finding["message"].endswith(
        "is not the entry aegis hook install writes (its matcher, type, command, arguments or timeout differ), "
        "so Claude Code may not run it as its tier says: run aegis hook install --host claude-code")
    rc, out = env.run()
    assert ("hooks        registered but modified (user scope, ~/.claude/settings.json): not the entry aegis "
            "hook install writes, so no tier is claimed") in out
    assert "if Claude Code runs it" not in out


def test_a_codex_entry_for_another_host_is_modified(env):
    path = env.install("codex-cli").path
    _edit_first_entry(env, path, {}, {"command": f"{env.aegis} hook run pre-tool --host claude-code"})
    assert hooks(env.doctor(), "codex-cli")["status"] == "modified"


def test_an_antigravity_entry_without_the_exit_mapping_wrapper_is_modified(env):
    """Without the wrapper agy blocks on every non-zero exit, a crash included."""
    want = registrar.hook_group("antigravity", env.aegis)
    bare = dict(want, hooks=[dict(want["hooks"][0], command=f"{env.aegis} hook run pre-tool --host antigravity")])
    env.write_json(env.home / ".gemini" / "config" / "hooks.json", {"aegis": {"PreToolUse": [bare]}})
    assert hooks(env.doctor(), "antigravity")["status"] == "modified"


def test_a_key_install_does_not_write_is_not_drift(env):
    path = env.install("claude-code").path
    _edit_first_entry(env, path, {}, {"statusMessage": "aegis checks the call"})
    row = hooks(env.doctor(), "claude-code")
    assert row["status"] == "registered" and row["entries"][0]["modified"] is False


def test_a_modified_project_entry_names_the_project_install(env):
    path = env.install("claude-code", "project").path
    _edit_first_entry(env, path, {}, {"timeout": 60})
    (finding,) = findings(env.doctor(), "hook_entry_modified")
    assert finding["message"].endswith(": run aegis hook install --host claude-code --scope project")


def test_install_rewrites_a_modified_entry_and_doctor_then_says_registered(env):
    path = env.install("claude-code").path
    _edit_first_entry(env, path, {"matcher": "Read"}, {})
    assert env.install("claude-code").status == "updated"
    assert hooks(env.doctor(), "claude-code")["status"] == "registered"


@pytest.mark.parametrize("content, says", [
    (b"{nope", "not valid JSON"),
    (b'{"hooks": {}, "hooks": {}}', "duplicate key"),
    (b'{"hooks": {"PreToolUse": {}}}', "'hooks.PreToolUse' must be a list of objects"),
    (b'{"hooks": []}', "'hooks' must be a JSON object"),
])
def test_a_host_file_the_host_cannot_read_is_reported_and_its_hooks_are_unknown(env, content, says):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    payload = env.doctor()
    row = hooks(payload, "claude-code")
    assert row["status"] == "unknown" and row["entries"] == []
    assert "claude-code.hooks" in payload["unknown"]
    (bad,) = findings(payload, "hook_file_invalid")
    assert says in bad["message"] and bad["fixable"] is False
    assert "Claude Code" in bad["message"]
    assert path.read_bytes() == content


def test_an_unreadable_file_beside_a_registered_entry_keeps_the_entry(env):
    env.install("codex-cli")
    (env.ws / ".codex").mkdir()
    (env.ws / ".codex" / "hooks.json").write_bytes(b"[1,")
    payload = env.doctor()
    assert hooks(payload, "codex-cli")["status"] == "registered"
    assert len(findings(payload, "hook_file_invalid")) == 1


def test_a_read_run_with_hook_files_writes_nothing(env):
    env.install("claude-code")
    env.write_json(env.home / ".codex" / "hooks.json", {"hooks": {"Stop": [{"hooks": [handler("soma hook stop")]}]}})
    before = _snapshot(env.tmp)
    env.doctor()
    env.run()
    assert _snapshot(env.tmp) == before


# ── v3 leftovers and --fix ─────────────────────────────────────────────────

V3_CLAUDE = {
    "model": "x",
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [handler("aegis hook pre-invocation"), handler("/usr/bin/lint")]},
            {"matcher": "Edit", "hooks": [handler("/home/u/.local/bin/soma hook immune-init", timeout=15)]},
        ],
        "Stop": [{"hooks": [handler("cd /repo && soma hook session-close")]}],
        "SessionEnd": [{"hooks": [handler("/usr/bin/keep-me")]}],
    },
}


def test_v3_hook_entries_are_flagged_in_every_host_file(env):
    claude = env.write_json(env.home / ".claude" / "settings.json", V3_CLAUDE)
    codex = env.write_json(env.ws / ".codex" / "hooks.json",
                           {"hooks": {"Stop": [{"hooks": [handler("aegis hook stop")]}]}})
    agy = env.write_json(env.home / ".gemini" / "config" / "hooks.json", {
        "governance-monitor": {"PreInvocation": [handler("aegis hook governance-monitor", timeout=15)]},
        "mine": {"PreToolUse": [{"matcher": "*", "hooks": [handler("true")]}]}})
    payload = env.doctor()
    flagged = {f["path"]: f for f in findings(payload, "legacy_hook_entry")}
    assert set(flagged) == {str(claude), str(codex), str(agy)}
    assert all(f["fixable"] for f in flagged.values())
    assert "hooks.PreToolUse[0].hooks[0]" in flagged[str(claude)]["location"]
    assert "hooks.Stop[0]" in flagged[str(claude)]["location"]


@pytest.mark.parametrize("command", [
    "cd /repo; soma hook stop",
    "exec soma hook stop",
    "true || aegis hook session-close",
    r"C:\Tools\soma.exe hook stop",
    r"C:\Tools\aegis.exe hook stop",
])
def test_a_v3_call_anywhere_a_command_starts_is_flagged(env, command):
    env.write_json(env.home / ".claude" / "settings.json", {"hooks": {"Stop": [{"hooks": [handler(command)]}]}})
    assert len(findings(env.doctor(), "legacy_hook_entry")) == 1


def test_handlers_without_a_command_are_never_v3_entries(env):
    env.write_json(env.home / ".claude" / "settings.json", {"hooks": {"Stop": [{"hooks": [
        "not-a-handler", {"type": "mcp_tool", "server": "x", "tool": "y"}, {"type": "command", "command": 7}]}]}})
    payload = env.doctor()
    assert findings(payload, "legacy_hook_entry") == []
    assert hooks(payload, "claude-code")["status"] == "absent"


def test_fix_removes_only_the_v3_entries_and_backs_each_file_up(env):
    env.install("claude-code")
    claude = env.home / ".claude" / "settings.json"
    data = json.loads(claude.read_text(encoding="utf-8"))
    data["model"] = "x"
    data["hooks"]["PreToolUse"] = V3_CLAUDE["hooks"]["PreToolUse"] + data["hooks"]["PreToolUse"]
    keep_stop = {"hooks": [handler("/usr/bin/notify")]}
    data["hooks"]["Stop"] = V3_CLAUDE["hooks"]["Stop"] + [keep_stop] + V3_CLAUDE["hooks"]["Stop"]
    data["hooks"]["SessionEnd"] = V3_CLAUDE["hooks"]["SessionEnd"]
    env.write_json(claude, data)
    original = claude.read_bytes()
    agy = env.write_json(env.home / ".gemini" / "config" / "hooks.json", {
        "governance-monitor": {"PreInvocation": [handler("aegis hook governance-monitor")]},
        "safety-gate": {"PreToolUse": [{"matcher": "run_command",
                                        "hooks": [handler("aegis hook safety-gate", timeout=5)]}]}})
    agy_original = agy.read_bytes()

    payload = env.fix()
    assert payload["_rc"] == 0, ([(f.get("code"), f.get("severity")) for f in payload.get("findings", [])],
                                 [c["id"] for c in payload.get("checks", []) if c.get("status") not in ("pass", "skip")])
    assert {(f["action"], f["status"]) for f in payload["fixes"]} == {("remove_list_items", "applied")}
    after = json.loads(claude.read_text(encoding="utf-8"))
    assert after["model"] == "x"
    assert after["hooks"]["PreToolUse"] == [
        {"matcher": "Bash", "hooks": [handler("/usr/bin/lint")]},
        registrar.hook_group("claude-code", env.aegis)]
    assert after["hooks"]["Stop"] == [keep_stop]
    assert after["hooks"]["SessionEnd"] == V3_CLAUDE["hooks"]["SessionEnd"]
    assert json.loads(agy.read_text(encoding="utf-8")) == {
        "governance-monitor": {"PreInvocation": []},
        "safety-gate": {"PreToolUse": [{"matcher": "run_command",
                                        "hooks": [handler("aegis hook safety-gate", timeout=5)]}]}}
    (backup,) = env.backups()
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    saved = {item["path"]: (backup / item["backup"]).read_bytes() for item in manifest["files"]}
    assert saved == {str(claude): original, str(agy): agy_original}
    assert all(item["action"] == "remove_list_items" for item in manifest["files"])
    assert findings(env.doctor(), "legacy_hook_entry") == []


@pytest.mark.parametrize("command", [
    "/x/aegis hook run pre-tool --host claude-code",
    "aegis hook safety-gate",
    "aegis hook install",
    "aegis hook pre-commit",
    "somatic hook stop",
    "echo soma hook stop",
    "/x/soma-hook stop",
])
def test_commands_that_only_look_like_v3_hooks_are_left_alone(env, command):
    env.write_json(env.home / ".claude" / "settings.json",
                   {"hooks": {"Stop": [{"hooks": [handler(command)]}]}})
    assert findings(env.doctor(), "legacy_hook_entry") == []


def test_an_exec_form_v3_entry_is_flagged(env):
    env.write_json(env.home / ".claude" / "settings.json", {"hooks": {"Stop": [{"hooks": [
        handler("/home/u/.local/bin/soma", args=["hook", "session-close"])]}]}})
    assert len(findings(env.doctor(), "legacy_hook_entry")) == 1


def plugin(env: Env) -> Path:
    return env.home / ".gemini" / "config" / "plugins" / "governance" / "hooks.json"


def test_the_stale_agy_plugin_is_flagged_and_fix_deletes_it_with_a_backup(env):
    path = env.write_json(plugin(env), {
        "governance-monitor": {"PreInvocation": [handler("soma hook pre-invocation", timeout=15)]},
        "session-close": {"Stop": [handler("soma hook session-close", timeout=30)]}})
    original = path.read_bytes()
    payload = env.doctor()
    (stale,) = findings(payload, "legacy_hook_plugin")
    assert stale["fixable"] and stale["path"] == str(path)
    assert "deletes the file" in stale["message"]
    fixed = env.fix()
    assert [(f["action"], f["status"]) for f in fixed["fixes"]] == [("delete_file", "applied")]
    assert not path.exists()
    (backup,) = env.backups()
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    (item,) = manifest["files"]
    assert (backup / item["backup"]).read_bytes() == original


def test_a_plugin_file_with_other_entries_loses_only_the_v3_ones(env):
    keep = {"matcher": "run_command", "hooks": [handler("/usr/bin/mine")]}
    path = env.write_json(plugin(env), {
        "governance-monitor": {"PreInvocation": [handler("soma hook pre-invocation")]},
        "mine": {"PreToolUse": [keep]}})
    (stale,) = findings(env.doctor(), "legacy_hook_plugin")
    assert "deletes" not in stale["message"]
    env.fix()
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "governance-monitor": {"PreInvocation": []}, "mine": {"PreToolUse": [keep]}}


def _stale_plugin(env: Env) -> Path:
    return env.write_json(plugin(env), {"governance-monitor": {"PreInvocation": [handler("soma hook pre-invocation")]}})


def _bits(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_fix_makes_every_backup_directory_it_creates_owner_only(env):
    """R-cli-40: Given a fresh HOME with no ~/.aegis and umask 022, When doctor --fix --yes backs a
    file up, Then ~/.aegis, ~/.aegis/backups and the run's directory are all 0700, the manifest is
    0600 and the mode of HOME itself is unchanged."""
    _stale_plugin(env)
    home_mode = _bits(env.home)
    old = os.umask(0o022)
    try:
        fixed = env.fix()
    finally:
        os.umask(old)
    assert [(f["action"], f["status"]) for f in fixed["fixes"]] == [("delete_file", "applied")]
    (backup,) = env.backups()
    aegis = env.home / ".aegis"
    assert [_bits(aegis), _bits(aegis / "backups"), _bits(backup)] == [0o700, 0o700, 0o700]
    assert _bits(backup / "manifest.json") == 0o600
    assert _bits(env.home) == home_mode


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_fix_refuses_a_symlinked_backups_directory_and_writes_nothing_through_it(env):
    path = _stale_plugin(env)
    outside = env.tmp / "outside-backups"
    outside.mkdir()
    (env.home / ".aegis").mkdir()
    (env.home / ".aegis" / "backups").symlink_to(outside, target_is_directory=True)
    fixed = env.fix()
    assert [f["status"] for f in fixed["fixes"]] == ["failed"]
    assert "symlink" in fixed["fixes"][0]["reason"]
    assert list(outside.iterdir()) == [] and path.is_file()


def test_fix_skips_a_hook_file_that_changed_after_the_check(env, monkeypatch):
    path = env.write_json(env.home / ".codex" / "hooks.json",
                          {"hooks": {"Stop": [{"hooks": [handler("soma hook stop")]}]}})
    changed = json.dumps({"hooks": {"Stop": [{"hooks": [handler("soma hook stop")]}], "x": []}})

    def confirm_then_edit(prompt):
        path.write_text(changed, encoding="utf-8")
        return True

    monkeypatch.setattr(doctor_base, "_confirm", confirm_then_edit)
    rc, out = env.run(fix=True)
    assert rc == 1 and "changed since the check" in out
    assert path.read_text(encoding="utf-8") == changed


def test_fix_refuses_a_symlinked_hook_file(env):
    if os.name == "nt":
        pytest.skip("symlinks need privileges on Windows")
    real = env.write_json(env.tmp / "dotfiles" / "settings.json",
                          {"hooks": {"Stop": [{"hooks": [handler("soma hook stop")]}]}})
    link = env.home / ".claude" / "settings.json"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    before = real.read_bytes()
    payload = env.doctor()
    (stale,) = findings(payload, "legacy_hook_entry")
    assert stale["fixable"] is False and "symlink" in stale["message"]
    env.fix()
    assert real.read_bytes() == before and link.is_symlink()


# ── text output ─────────────────────────────────────────────────────────────

def test_text_output_shows_each_hosts_hooks_and_the_known_gaps(env):
    env.install("codex-cli")
    rc, out = env.run()
    assert "hooks        registered (user scope, ~/.codex/hooks.json)" in out
    assert "blocking once trusted in /hooks (documented; fails open) [DOC]" in out
    assert "needs approval in /hooks (cannot be checked)" in out
    assert "hooks        not registered: aegis hook install --host claude-code" in out
    flat = " ".join(out.split())
    for gap in registrar.KNOWN_GAPS:
        assert " ".join(gap.split()) in flat


# ── the git pre-commit hook is replaced atomically, never through a link (X-w8-carry i) ──

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks and mode bits")


def _hook_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from tests.helpers_checkmodes import init_repo

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    root = init_repo(tmp_path / "repo", rules=False)
    hook = root / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_bytes(b"#!/bin/sh\necho user-check\n")
    os.chmod(hook, 0o750)
    return root


def _plant(root: Path, tmp_path: Path) -> Path:
    """A victim outside the repository and a link to it at the old temporary-file name."""
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    os.chmod(victim, 0o600)
    (root / ".git" / "hooks" / f".pre-commit.tmp.{os.getpid()}").symlink_to(victim)
    return victim


@posix_only
def test_install_never_writes_through_a_link_at_a_temporary_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_cli.hooks import management

    root = _hook_repo(tmp_path, monkeypatch)
    victim = _plant(root, tmp_path)
    assert management.install_hook(root, python="/usr/bin/python3") is True
    assert victim.read_bytes() == b"precious" and stat.S_IMODE(victim.stat().st_mode) == 0o600
    hook = root / ".git" / "hooks" / "pre-commit"
    assert not hook.is_symlink() and stat.S_IMODE(hook.stat().st_mode) == 0o755
    assert b"echo user-check" in hook.read_bytes() and management.hook_status(root)["managed_by_aegis"]


@posix_only
def test_uninstall_never_writes_through_a_link_at_a_temporary_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_cli.hooks import management

    root = _hook_repo(tmp_path, monkeypatch)
    assert management.install_hook(root, python="/usr/bin/python3") is True
    hook = root / ".git" / "hooks" / "pre-commit"
    os.chmod(hook, 0o750)
    victim = _plant(root, tmp_path)
    assert management.uninstall_hook(root) is True
    assert victim.read_bytes() == b"precious" and stat.S_IMODE(victim.stat().st_mode) == 0o600
    assert hook.read_bytes() == b"#!/bin/sh\necho user-check\n" and stat.S_IMODE(hook.stat().st_mode) == 0o750


def test_a_hook_that_cannot_be_replaced_is_left_as_it_was_with_no_temporary_file(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_cli.hooks import management

    root = _hook_repo(tmp_path, monkeypatch)
    hooks = root / ".git" / "hooks"
    before = (hooks / "pre-commit").read_bytes()

    real_replace = os.replace

    def broken_replace(src, dst):
        if Path(dst).parent == hooks:  # the backup copy under ~/.aegis/backups is still written
            raise OSError(5, "Input/output error")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", broken_replace)
    monkeypatch.setattr(Path, "replace", lambda self, target: broken_replace(self, target))
    with pytest.raises(OSError, match="Input/output"):
        management.install_hook(root, python="/usr/bin/python3")
    assert (hooks / "pre-commit").read_bytes() == before
    assert sorted(p.name for p in hooks.iterdir() if "tmp" in p.name) == []
