"""`aegis doctor`: the read-only host matrix, enforcement tiers and warnings (host-matrix §3.9-3.10).

Doctor never claims more than it checked: a host CLI that fails or times out makes the
registration *unknown*, not absent; nothing is read from the network; and a read run
writes nothing anywhere. Host CLIs are faked at the process boundary (``_run_host_cli``)
and every host binary is a stub on a private PATH, so no real host is ever touched.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional

import pytest

from aegis_cli import doctor, doctor_base
from aegis_cli.doctor import run_doctor
from aegis_core.bootstrap import BOOTSTRAP_ID, bootstrap_text

PHASE1 = ["codex-cli", "claude-code", "antigravity"]
STATES = {"ok", "missing_binary", "unregistered", "auth_unknown", "policy_gap"}


# ── environment ─────────────────────────────────────────────────────────────

class Env:
    """A fake machine: HOME, a private PATH of stub binaries, a workspace, host CLI replies."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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
            "# Sample\n\nKeep the sample rule body long enough to be a real rule body.\n",
            encoding="utf-8")
        self.replies: Dict[str, Any] = {}
        self.calls: List[Dict[str, Any]] = []
        for name, value in (("HOME", self.home), ("USERPROFILE", self.home), ("PATH", self.bin),
                            ("APPDATA", self.home / "AppData" / "Roaming")):
            monkeypatch.setenv(name, str(value))
        for name in ("CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "CODEX_HOME", "AEGIS_WORKSPACE", "AEGIS_CLIENT"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(doctor, "_run_host_cli", self._run)
        self.stub("aegis")
        self.mcp = self.stub("aegis-mcp")

    def stub(self, name: str) -> Path:
        path = self.bin / (name + (".exe" if os.name == "nt" else ""))
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def _run(self, argv, cwd, timeout):
        self.calls.append({"argv": list(argv), "cwd": cwd, "timeout": timeout})
        reply = self.replies.get(Path(argv[0]).stem)
        if reply is None:
            raise AssertionError(f"unexpected host CLI call {argv}")
        if isinstance(reply, BaseException):
            raise reply
        rc, out, err = reply
        return subprocess.CompletedProcess(argv, rc, out, err)

    # host state helpers
    def codex_registered(self, command: Optional[str] = None, client: str = "codex-cli", enabled: bool = True):
        self.stub("codex")
        env = {"AEGIS_CLIENT": client} if client else {}
        self.replies["codex"] = (0, json.dumps({
            "name": "aegis", "enabled": enabled, "disabled_reason": None,
            "transport": {"type": "stdio", "command": command or str(self.mcp), "args": [],
                          "env": env, "env_vars": [], "cwd": None}}), "")

    def claude_json(self, data: Dict[str, Any]) -> Path:
        path = self.home / ".claude.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def claude_registered(self, client: str = "claude-code"):
        self.stub("claude")
        self.claude_json({"numStartups": 3, "mcpServers": {"aegis": {
            "type": "stdio", "command": str(self.mcp), "args": [], "env": {"AEGIS_CLIENT": client}}}})

    def antigravity_registered(self, **extra):
        self.stub("agy")
        cfg = self.home / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        entry = {"command": str(self.mcp), "args": [], "env": {"AEGIS_CLIENT": "antigravity"}}
        entry.update(extra)
        cfg.write_text(json.dumps({"mcpServers": {"aegis": entry}}, indent=2), encoding="utf-8")
        return cfg

    def register_workspace(self, hosts=PHASE1):
        reg = self.home / ".aegis" / "workspaces.json"
        reg.parent.mkdir(parents=True, exist_ok=True)
        reg.write_text(json.dumps({"v": 1, "workspaces": [{
            "root": os.path.realpath(str(self.ws)), "added_at": "2026-10-15T00:00:00Z",
            "added_by": "aegis init", "hosts": list(hosts)}]}), encoding="utf-8")

    def bootstrap(self, text: Optional[str] = None, sha: Optional[str] = None, before: str = "", after: str = ""):
        body = bootstrap_text() if text is None else text
        digest = sha or hashlib.sha256(body.replace("\r\n", "\n").encode("utf-8")).hexdigest()[:12]
        (self.ws / "AGENTS.md").write_text(
            f"{before}<!-- aegis:begin id={BOOTSTRAP_ID} v=1 sha={digest} -->\n{body}"
            f"<!-- aegis:end id={BOOTSTRAP_ID} -->\n{after}", encoding="utf-8")

    def all_ok(self):
        self.codex_registered()
        self.claude_registered()
        self.antigravity_registered()
        self.register_workspace()
        self.bootstrap()

    def doctor(self, **kw) -> Dict[str, Any]:
        rc, out = self.run(json=True, **kw)
        payload = json.loads(out)
        payload["_rc"] = rc
        return payload

    def run(self, **kw):
        import contextlib
        import io
        args = argparse.Namespace(workspace=str(self.ws), fix=False, yes=False, drivers=False, json=False)
        for key, value in kw.items():
            setattr(args, key, value)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_doctor(args)
        return rc, buf.getvalue()


@pytest.fixture
def env(tmp_path, monkeypatch) -> Env:
    return Env(tmp_path, monkeypatch)


def host(payload: Dict[str, Any], host_id: str) -> Dict[str, Any]:
    return next(h for h in payload["hosts"] if h["id"] == host_id)


def codes(row: Dict[str, Any]) -> List[str]:
    return [r["code"] for r in row["reasons"]]


def finding_codes(payload: Dict[str, Any]) -> List[str]:
    return sorted(f["code"] for f in payload["findings"])


def _tree(root: Path) -> Dict[str, Any]:
    out = {}
    for path in sorted(root.rglob("*")):
        st = path.lstat()
        out[path.relative_to(root).as_posix()] = (st.st_mode, st.st_size, st.st_mtime_ns,
                                                    path.read_bytes() if path.is_file() else None)
    return out


# ── the machine-readable envelope ───────────────────────────────────────────

def test_json_carries_schema_source_version_time_scope_and_the_trust_tier(env):
    env.all_ok()
    payload = env.doctor()
    assert payload["schema"] == "aegis.doctor/v1"
    assert payload["source"] == "aegis doctor"
    assert isinstance(payload["aegis_version"], str) and payload["aegis_version"]
    checked = datetime.strptime(payload["checked_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - checked).total_seconds()) < 120
    assert payload["scope"]["workspace"] == str(env.ws.resolve())
    assert payload["scope"]["hosts"] == PHASE1
    assert payload["scope"]["host_selection"] == "default"
    assert payload["stale"] is False
    for row in payload["hosts"]:
        assert row["state"] in STATES
        assert row["trust_tier"] == "C" and row["trust_tier_status"] == "detected"
        assert row["stale"] is False


def test_every_phase_one_host_is_ok_when_installed_registered_bootstrapped_and_bound(env):
    env.all_ok()
    payload = env.doctor()
    assert {h["id"]: h["state"] for h in payload["hosts"]} == dict.fromkeys(PHASE1, "ok")
    codex = host(payload, "codex-cli")
    assert codex["registration"]["status"] == "registered"
    assert codex["registration"]["source"] == "codex mcp get aegis --json"
    assert codex["registration"]["command_exists"] is True
    assert codex["identity"] == {"status": "explicit", "aegis_client": "codex-cli"}
    assert codex["workspace_registered"] is True
    assert codex["bootstrap"]["status"] == "current" and codex["bootstrap"]["reaches_host"] is True
    assert codex["budget"]["within"] is True and codex["budget"]["budget_bytes"] == 32 * 1024
    assert payload["findings"] == []


def test_a_read_run_writes_nothing_and_never_creates_the_user_plane(env, tmp_path):
    env.all_ok()
    (env.home / ".aegis" / "workspaces.json").unlink()
    (env.home / ".aegis").rmdir()
    before = _tree(tmp_path)
    env.doctor()
    env.run()
    assert _tree(tmp_path) == before
    assert not (env.home / ".aegis").exists()


def test_the_codex_probe_is_bounded_and_runs_without_a_shell_from_the_workspace(env):
    env.all_ok()
    env.doctor()
    (call,) = [c for c in env.calls if Path(c["argv"][0]).stem == "codex"]
    assert call["argv"][1:] == ["mcp", "get", "aegis", "--json"]
    assert Path(call["argv"][0]).parent == env.bin
    assert Path(call["cwd"]) == env.ws.resolve()
    assert 0 < call["timeout"] <= 15
    assert all(Path(c["argv"][0]).stem == "codex" for c in env.calls), "claude and agy are read from files"


# ── the four states ─────────────────────────────────────────────────────────

def test_no_binaries_means_missing_binary_and_no_host_cli_runs(env):
    env.bootstrap()
    payload = env.doctor()
    for host_id in PHASE1:
        row = host(payload, host_id)
        assert row["state"] == "missing_binary", host_id
        assert row["binary"]["found"] is False
    assert host(payload, "codex-cli")["registration"]["status"] == "unavailable"
    assert env.calls == []


def test_a_host_cli_that_says_not_found_is_unregistered(env):
    env.all_ok()
    env.replies["codex"] = (1, "", "Error: No MCP server named 'aegis' found.\n")
    row = host(env.doctor(), "codex-cli")
    assert row["state"] == "unregistered"
    assert row["registration"]["status"] == "absent"
    assert "not_registered" in codes(row)


@pytest.mark.parametrize("reply", [
    subprocess.TimeoutExpired(["codex"], 10),
    OSError("exec format error"),
    (1, "", "thread 'main' panicked\n"),
    (0, "not json", ""),
    (0, json.dumps({"name": "other"}), ""),
])
def test_an_unanswered_codex_probe_is_auth_unknown_never_unregistered(env, reply):
    env.all_ok()
    env.replies["codex"] = reply
    row = host(env.doctor(), "codex-cli")
    assert row["state"] == "auth_unknown"
    assert row["registration"]["status"] == "unknown"
    assert "registration_unverifiable" in codes(row)
    assert "registration" in row["unknown"]


def test_a_registration_whose_command_is_gone_is_unregistered(env):
    env.all_ok()
    env.codex_registered(command=str(env.bin / "gone-aegis-mcp"))
    row = host(env.doctor(), "codex-cli")
    assert row["state"] == "unregistered"
    assert row["registration"]["command_exists"] is False
    assert "command_missing" in codes(row)


def test_claude_registration_is_read_from_claude_json_not_by_running_claude(env):
    env.all_ok()
    payload = env.doctor()
    row = host(payload, "claude-code")
    assert row["state"] == "ok"
    assert row["registration"]["scope"] == "user"
    assert row["registration"]["source"] == "~/.claude.json"
    assert not [c for c in env.calls if Path(c["argv"][0]).stem == "claude"]


def test_claude_project_scope_only_needs_an_approval_doctor_cannot_see(env):
    env.all_ok()
    env.claude_json({"mcpServers": {}})
    (env.ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"aegis": {"command": str(env.mcp)}}}))
    row = host(env.doctor(), "claude-code")
    assert row["state"] == "auth_unknown"
    assert row["registration"]["scope"] == "project"
    assert "approval_unknown" in codes(row)


def test_claude_md_without_agents_import_is_a_policy_gap_for_claude_only(env):
    env.all_ok()
    (env.ws / "CLAUDE.md").write_text("# Project notes\n", encoding="utf-8")
    payload = env.doctor()
    claude = host(payload, "claude-code")
    assert claude["state"] == "policy_gap"
    assert "claude_md_shadows_agents_md" in codes(claude)
    assert claude["bootstrap"]["reaches_host"] is False
    assert host(payload, "codex-cli")["state"] == "ok"
    assert "claude_md_without_agents_import" in finding_codes(payload)


def test_claude_md_importing_agents_md_lets_the_bootstrap_through(env):
    env.all_ok()
    (env.ws / "CLAUDE.md").write_text(
        "# Notes\n\n<!-- aegis:begin id=agents-import v=1 sha=bc3e8c9d6dbb -->\n@AGENTS.md\n"
        "<!-- aegis:end id=agents-import -->\n", encoding="utf-8")
    payload = env.doctor()
    assert host(payload, "claude-code")["state"] == "ok"
    assert "claude_md_without_agents_import" not in finding_codes(payload)


def test_antigravity_has_no_roots_so_an_unregistered_workspace_is_a_policy_gap(env):
    env.all_ok()
    (env.home / ".aegis" / "workspaces.json").unlink()
    payload = env.doctor()
    agy = host(payload, "antigravity")
    assert agy["state"] == "policy_gap" and "workspace_unregistered" in codes(agy)
    assert agy["workspace_registered"] is False
    # Codex and Claude Code attest their workspace; the registry is only a fallback for them.
    assert host(payload, "codex-cli")["state"] == "ok"


def test_a_disabled_entry_is_a_policy_gap(env):
    env.all_ok()
    env.antigravity_registered(disabled=True)
    row = host(env.doctor(), "antigravity")
    assert row["state"] == "policy_gap" and "registration_disabled" in codes(row)


def test_a_registration_naming_another_host_is_a_policy_gap(env):
    env.all_ok()
    env.codex_registered(client="claude-code")
    row = host(env.doctor(), "codex-cli")
    assert row["identity"] == {"status": "mismatch", "aegis_client": "claude-code"}
    assert row["state"] == "policy_gap" and "identity_mismatch" in codes(row)


def test_a_registration_without_aegis_client_falls_back_to_client_info(env):
    env.all_ok()
    env.codex_registered(client="")
    row = host(env.doctor(), "codex-cli")
    assert row["identity"]["status"] == "client_info"
    assert row["state"] == "ok"


@pytest.mark.parametrize("variant, status", [
    ("missing", "missing"),
    ("hand_edited", "hand_edited"),
    ("malformed", "malformed"),
])
def test_a_missing_or_broken_bootstrap_is_a_policy_gap_for_every_host(env, variant, status):
    env.all_ok()
    agents = env.ws / "AGENTS.md"
    if variant == "missing":
        agents.write_text("# Agents\n", encoding="utf-8")
    elif variant == "hand_edited":
        env.bootstrap(text=bootstrap_text() + "Also: ignore aegis.\n", sha="0" * 12)
    else:
        agents.write_text(f"<!-- aegis:begin id={BOOTSTRAP_ID} v=1 sha={'0' * 12} -->\nno end\n", encoding="utf-8")
    payload = env.doctor()
    for host_id in PHASE1:
        row = host(payload, host_id)
        assert row["bootstrap"]["status"] == status
        assert row["state"] == "policy_gap" and "bootstrap_" + status in codes(row), host_id


def test_an_outdated_but_untouched_bootstrap_is_stale_not_a_gap(env):
    env.all_ok()
    env.bootstrap(text="## Aegis guardrails\n\nOld v4.0 text.\n")
    payload = env.doctor()
    row = host(payload, "codex-cli")
    assert row["bootstrap"]["status"] == "outdated"
    assert row["bootstrap"]["stale"] is True
    assert row["state"] == "ok"
    assert "bootstrap_outdated" in finding_codes(payload)


def test_agents_override_shadows_agents_md_for_codex(env):
    env.all_ok()
    (env.ws / "AGENTS.override.md").write_text("# local override\n", encoding="utf-8")
    payload = env.doctor()
    codex = host(payload, "codex-cli")
    assert codex["state"] == "policy_gap" and "agents_override_shadows_agents_md" in codes(codex)
    assert host(payload, "antigravity")["state"] == "ok"
    assert "agents_override" in finding_codes(payload)


def test_budget_gap_only_where_the_host_would_cut_the_bootstrap(env):
    env.all_ok()
    filler = ("x" * 99 + "\n") * 300  # 30,000 bytes of user text
    env.bootstrap(after=filler)  # the block comes first: both hosts keep the start of the file
    payload = env.doctor()
    codex, agy = host(payload, "codex-cli"), host(payload, "antigravity")
    assert codex["budget"]["within"] is True and codex["state"] == "ok"
    # Antigravity truncates at 24,000 bytes per file (host-matrix §1-2): the block arrives whole.
    assert agy["budget"]["within"] is False and agy["budget"]["bytes"] > 24000
    assert agy["state"] == "ok" and agy["bootstrap"]["reaches_host"] is True

    env.bootstrap(before=filler)  # the block starts after byte 24,000: Antigravity cuts it
    payload = env.doctor()
    codex, agy = host(payload, "codex-cli"), host(payload, "antigravity")
    assert codex["budget"]["within"] is True and codex["state"] == "ok"
    assert agy["state"] == "policy_gap" and "over_budget" in codes(agy)

    env.bootstrap(after=filler + filler)  # over 32 KiB, but the cut falls after the block
    payload = env.doctor()
    codex = host(payload, "codex-cli")
    assert codex["budget"]["within"] is False and codex["state"] == "ok"
    assert any(f["code"] == "instructions_over_budget" and Path(f["path"]).name == "AGENTS.md"
               for f in payload["findings"])

    env.bootstrap(before=filler + filler)  # now the block starts after byte 32768
    codex = host(env.doctor(), "codex-cli")
    assert codex["budget"]["within"] is False
    assert codex["state"] == "policy_gap" and "over_budget" in codes(codex)


def test_an_ungoverned_directory_is_a_policy_gap_not_a_crash(env, tmp_path):
    env.all_ok()
    bare = tmp_path / "bare"
    bare.mkdir()
    rc, out = env.run(json=True, workspace=str(bare))
    payload = json.loads(out)
    assert payload["scope"]["workspace_governed"] is False
    assert all("workspace_not_governed" in codes(h) for h in payload["hosts"])
    assert rc == 1


# ── selection and enforcement tiers ─────────────────────────────────────────

def test_the_matrix_follows_the_hosts_the_workspace_selected(env):
    env.all_ok()
    (env.ws / ".aegis" / "config.json").write_text(json.dumps({"v": 1, "hosts": ["codex-cli"]}))
    payload = env.doctor()
    assert payload["scope"]["host_selection"] == "config"
    assert [h["id"] for h in payload["hosts"]] == ["codex-cli"]
    advisory = next(t for t in payload["enforcement_tiers"] if t["tier"] == "advisory")
    assert advisory["hosts"] == ["codex-cli"]


def test_enforcement_tiers_report_what_is_in_force_here_and_nothing_more(env):
    env.all_ok()
    payload = env.doctor()
    floor = next(t for t in payload["enforcement_tiers"] if t["tier"] == "local_floor")
    assert floor["status"] == "unavailable"  # not a git repository: no hook can run

    hooks = env.ws / ".git" / "hooks"
    hooks.mkdir(parents=True)
    payload = env.doctor()
    tiers = {t["tier"]: t for t in payload["enforcement_tiers"]}
    assert list(tiers) == ["advisory", "best_effort", "local_floor", "authoritative"]
    assert tiers["advisory"]["status"] == "active"
    assert tiers["best_effort"]["status"] == "inactive"  # no host hook registered (v4.1)
    assert tiers["local_floor"]["status"] == "inactive"
    # doctor does not read CI runs, so CI is a capability it does not have: unavailable.
    assert tiers["authoritative"]["status"] == "unavailable"
    assert all(h["enforcement_level"] == "advisory" for h in payload["hosts"])

    from aegis_cli.hooks.management import generate_hook_block
    (hooks / "pre-commit").write_text("#!/bin/sh\n" + generate_hook_block(sys.executable), encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)  # git skips a hook it cannot execute
    payload = env.doctor()
    tiers = {t["tier"]: t for t in payload["enforcement_tiers"]}
    assert tiers["local_floor"]["status"] == "active"
    assert all(h["enforcement_level"] == "local_floor" for h in payload["hosts"])


def test_an_unregistered_host_without_the_bootstrap_has_no_enforcement(env):
    env.claude_registered()
    env.claude_json({})
    row = host(env.doctor(), "claude-code")
    assert row["state"] == "unregistered"
    assert row["enforcement_level"] == "none"


# ── warnings (findings) ─────────────────────────────────────────────────────

def test_stale_soma_and_misplaced_aegis_entries_are_reported_where_they_are(env):
    env.all_ok()
    env.claude_json({
        "mcpServers": {"aegis": {"command": str(env.mcp), "env": {"AEGIS_CLIENT": "claude-code"}},
                       "soma": {"command": "soma-mcp"}},
        "projects": {"/elsewhere": {"mcpServers": {"soma": {"command": "soma-mcp"},
                                                   "aegis": {"command": "aegis-mcp"}}}}})
    (env.home / ".mcp.json").write_text(json.dumps({"mcpServers": {"soma": {}, "aegis": {}}}))
    (env.ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"soma": {}, "other": {}}}))
    desktop = env.home / ".config" / "Claude" / "claude_desktop_config.json"
    desktop.parent.mkdir(parents=True)
    desktop.write_text(json.dumps({"mcpServers": {"aegis": {"command": "aegis-mcp"}, "soma": {}}}))
    payload = env.doctor()
    got = sorted((f["code"], Path(f["path"]).name, f["location"]) for f in payload["findings"])
    assert got == sorted([
        ("legacy_mcp_entry", ".claude.json", "mcpServers.soma"),
        ("legacy_mcp_entry", ".claude.json", "projects[/elsewhere].mcpServers.soma"),
        ("misplaced_mcp_entry", ".claude.json", "projects[/elsewhere].mcpServers.aegis"),
        ("legacy_mcp_entry", ".mcp.json", "mcpServers.soma"),
        ("misplaced_mcp_entry", ".mcp.json", "mcpServers.aegis"),
        ("legacy_mcp_entry", ".mcp.json", "mcpServers.soma"),
        ("desktop_mcp_entry", "claude_desktop_config.json", "mcpServers.aegis"),
        ("legacy_mcp_entry", "claude_desktop_config.json", "mcpServers.soma"),
    ])
    assert all(f["fixable"] for f in payload["findings"])


def test_a_misplaced_aegis_entry_is_not_fixable_while_no_user_registration_replaces_it(env):
    env.claude_registered()
    env.claude_json({})
    (env.home / ".mcp.json").write_text(json.dumps({"mcpServers": {"aegis": {"command": str(env.mcp)}}}))
    finding = next(f for f in env.doctor()["findings"] if f["code"] == "misplaced_mcp_entry")
    assert finding["fixable"] is False
    assert "aegis init --host claude-code" in finding["message"]


def test_a_local_scope_registration_alone_is_a_registration_not_a_finding(env):
    env.claude_registered()
    env.claude_json({"projects": {str(env.ws.resolve()): {"mcpServers": {"aegis": {
        "command": str(env.mcp), "env": {"AEGIS_CLIENT": "claude-code"}}}}}})
    payload = env.doctor()
    assert host(payload, "claude-code")["registration"]["scope"] == "local"
    assert "misplaced_mcp_entry" not in finding_codes(payload)


def test_legacy_marker_blocks_are_reported_in_project_and_global_instruction_files(env):
    env.all_ok()
    (env.ws / "CLAUDE.md").write_text(
        "@AGENTS.md\n\n<!-- SOMA:START -->\n# Soma Governance Rules\nold\n<!-- SOMA:END -->\n", encoding="utf-8")
    glob_claude = env.home / ".claude" / "CLAUDE.md"
    glob_claude.parent.mkdir()
    glob_claude.write_text("mine\n<!-- AEGIS:START -->\nrules\n<!-- AEGIS:END -->\n", encoding="utf-8")
    broken = env.home / ".codex" / "AGENTS.md"
    broken.parent.mkdir()
    broken.write_text("<!-- SOMA:START -->\nno end\n", encoding="utf-8")
    found = {(Path(f["path"]), f["code"], f["fixable"]) for f in env.doctor()["findings"]}
    assert (env.ws / "CLAUDE.md", "legacy_block", True) in found
    assert (glob_claude, "legacy_block", True) in found
    assert (broken, "legacy_block", False) in found


def test_an_inlined_rules_claude_md_over_budget_is_reported(env):
    env.all_ok()
    big = env.home / ".claude" / "CLAUDE.md"
    big.parent.mkdir()
    big.write_text("# Aegis Governance Rules\n" + "rule text\n" * 5000, encoding="utf-8")
    finding = next(f for f in env.doctor()["findings"] if f["code"] == "instructions_over_budget")
    assert Path(finding["path"]) == big and finding["fixable"] is False


def test_an_empty_home_rules_dir_left_by_v3_auto_mkdir_is_reported(env):
    env.all_ok()
    (env.home / ".aegis" / "rules").mkdir()
    assert "home_rules_dir" in finding_codes(env.doctor())
    (env.home / ".aegis" / "rules" / "mine.md").write_text("# a user rule\n")
    assert "home_rules_dir" not in finding_codes(env.doctor())


def test_v3_flat_rule_copies_are_matched_by_sha256_never_by_name(env, monkeypatch):
    env.all_ok()
    shipped = b"---\nid: providence\n---\n# Providence (as v3.3.0 shipped it)\n"
    monkeypatch.setattr(doctor_base, "_V3_SHIPPED_RULE_SHA256", frozenset({hashlib.sha256(shipped).hexdigest()}))
    leak = env.home / ".gemini" / "config" / "rules" / "providence.md"
    oracle = env.home / ".kiro" / "steering" / ".oracles" / "testing.md"
    edited = env.home / ".kiro" / "steering" / "providence.md"
    user = env.home / ".gemini" / "config" / "rules" / "my-rule.md"
    for path, data in ((leak, shipped), (oracle, shipped), (edited, shipped + b"my edit\n"), (user, b"# mine\n")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    findings = [f for f in env.doctor()["findings"] if f["code"] == "v3_rule_copy"]
    assert sorted(Path(f["path"]) for f in findings) == sorted([leak, oracle])
    assert all(f["fixable"] for f in findings)


def test_the_embedded_v3_digests_are_sha256_hex():
    assert len(doctor_base._V3_SHIPPED_RULE_SHA256) == 28
    assert all(len(d) == 64 and int(d, 16) >= 0 for d in doctor_base._V3_SHIPPED_RULE_SHA256)


def test_unparseable_host_config_is_reported_and_makes_registration_unknown(env):
    env.all_ok()
    (env.home / ".gemini" / "config" / "mcp_config.json").write_text("{ // jsonc\n}", encoding="utf-8")
    payload = env.doctor()
    row = host(payload, "antigravity")
    assert row["state"] == "auth_unknown" and row["registration"]["status"] == "unknown"
    assert "unreadable_config" in finding_codes(payload)


# ── human output ────────────────────────────────────────────────────────────

def test_text_output_prints_the_matrix_and_the_tier_table(env):
    env.all_ok()
    env.replies["codex"] = (1, "", "Error: No MCP server named 'aegis' found.\n")
    rc, out = env.run()
    assert "Codex CLI (codex-cli): unregistered" in out
    assert "Claude Code (claude-code): ok" in out
    assert "\nEnforcement tiers:\n" in out
    for tier in ("Advisory", "Best-effort", "Local floor", "Authoritative"):
        assert tier in out
    assert "aegis init --host codex-cli" in out


def test_claude_budget_counts_agents_md_only_when_claude_md_imports_it(env):
    env.all_ok()
    env.bootstrap(after=("y" * 99 + "\n") * 450)  # AGENTS.md ~45 KB, over Claude Code's 40 KiB
    (env.ws / "CLAUDE.md").write_bytes(b"# Notes only\n")
    budget = host(env.doctor(), "claude-code")["budget"]
    assert (budget["file"], budget["bytes"], budget["within"]) == ("CLAUDE.md", 13, True)

    (env.ws / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    budget = host(env.doctor(), "claude-code")["budget"]
    assert budget["file"] == "CLAUDE.md + AGENTS.md" and budget["within"] is False


def test_a_registration_waiting_for_an_approval_doctor_cannot_see_has_an_unknown_level(env):
    env.claude_registered()
    env.claude_json({})
    (env.ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"aegis": {"command": str(env.mcp)}}}))
    payload = env.doctor()
    row = host(payload, "claude-code")
    assert row["state"] == "auth_unknown"
    # No bootstrap, and whether the server loads waits on an approval doctor cannot read:
    # never counted as advisory, and not claimed absent either.
    assert row["enforcement_level"] == "unknown"
    assert tier(payload, "advisory")["status"] != "active"


def test_the_retired_gemini_cli_is_described_as_retired_never_promised_nor_checked(env):
    env.all_ok()
    env.stub("gemini")
    (env.ws / ".aegis" / "config.json").write_text(
        json.dumps({"v": 1, "hosts": ["gemini-cli", "zed", "gemini-cli"]}))
    payload = env.doctor()
    assert [h["id"] for h in payload["hosts"]] == []
    by_code = {}
    for f in payload["findings"]:
        by_code.setdefault(f["code"], []).append(f)
    (retired,) = by_code["retired_host"]
    assert retired["severity"] == "info"
    assert retired["message"] == (
        "config.json selects 'gemini-cli', a retired host: gemini-cli is not supported: Google retired "
        "Gemini CLI for individual Code Assist accounts; use --host antigravity.")
    (unknown,) = by_code["unknown_host"]  # an id the table does not know is a different note
    assert "'zed'" in unknown["message"] and "gemini-cli" not in unknown["message"]
    said = list(_strings(payload)) + env.run()[1].splitlines()
    about = [text for text in said if "gemini-cli" in text or "Gemini CLI" in text]
    assert about and all("retired" in text for text in about)
    assert not [text for text in about if "v4." in text or "identity only" in text]


def tier(payload: Dict[str, Any], name: str) -> Dict[str, Any]:
    return next(t for t in payload["enforcement_tiers"] if t["tier"] == name)


def levels(payload: Dict[str, Any]) -> Dict[str, str]:
    return {h["id"]: h["enforcement_level"] for h in payload["hosts"]}


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


# ── programs the repository supplies (review finding 1) ─────────────────────

def _decoy_name(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def _decoy(directory: Path, name: str, marker: Path) -> Path:
    """An executable that records that it ran; doctor must never start it."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / _decoy_name(name)
    path.write_text(f"#!/bin/sh\necho ran >> '{marker}'\necho 3\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _path_with(env: Env, layout: str) -> str:
    """PATH variants that name the workspace: the current directory (Windows searches it
    whatever PATH says), an empty or relative entry, or an absolute entry inside it."""
    entries = {"cwd_only": [], "empty_entry": [""], "relative_entry": ["."],
               "entry_inside_workspace": [str(env.ws / "tools")]}[layout]
    return os.pathsep.join(entries + [str(env.bin)])


LAYOUTS = ["cwd_only", "empty_entry", "relative_entry", "entry_inside_workspace"]


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_codex_in_the_workspace_is_never_found_or_run(env, monkeypatch, tmp_path, layout):
    env.claude_registered()
    env.antigravity_registered()
    env.register_workspace()
    env.bootstrap()
    marker = tmp_path / "decoy-ran"
    for where in (env.ws, env.ws / "tools"):
        _decoy(where, "codex", marker)
    monkeypatch.chdir(env.ws)
    monkeypatch.setenv("PATH", _path_with(env, layout))
    row = host(env.doctor(), "codex-cli")
    assert env.calls == [], "doctor started a codex the repository supplied"
    # Never run, and never called absent either: an empty or relative entry names the
    # workspace for a host started there (C-fix T4), an absolute one inside it is its own.
    passed_over = {"cwd_only": [], "empty_entry": [str(env.ws.resolve() / _decoy_name("codex"))],
                   "relative_entry": [str(env.ws.resolve() / _decoy_name("codex"))],
                   "entry_inside_workspace": [str(env.ws / "tools" / _decoy_name("codex"))]}[layout]
    assert row["binary"] == {"found": False, "path": None, "names": ["codex"], "ignored": passed_over}
    assert row["state"] == "missing_binary"
    assert ("codex-cli.binary" in env.doctor()["unknown"]) is bool(passed_over)


@pytest.mark.parametrize("entry", ["", "."])
def test_a_relative_path_entry_never_names_a_codex_even_outside_the_workspace(env, monkeypatch, tmp_path, entry):
    # doctor --workspace REPO run from another untrusted directory: the current directory
    # is not the workspace, and an empty or relative PATH entry still names it.
    env.claude_registered()
    env.antigravity_registered()
    env.register_workspace()
    env.bootstrap()
    elsewhere = tmp_path / "downloads"
    _decoy(elsewhere, "codex", tmp_path / "decoy-ran")
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("PATH", os.pathsep.join([entry, str(env.bin)]))
    row = host(env.doctor(), "codex-cli")
    assert env.calls == []
    assert row["binary"]["found"] is False and row["state"] == "missing_binary"


@pytest.mark.parametrize("layout", LAYOUTS)
def test_the_codex_probe_runs_the_absolute_codex_outside_the_workspace(env, monkeypatch, tmp_path, layout):
    env.all_ok()
    marker = tmp_path / "decoy-ran"
    for where in (env.ws, env.ws / "tools"):
        _decoy(where, "codex", marker)
    monkeypatch.chdir(env.ws)
    monkeypatch.setenv("PATH", _path_with(env, layout))
    assert host(env.doctor(), "codex-cli")["state"] == "ok"
    (call,) = env.calls
    assert os.path.isabs(call["argv"][0])
    assert Path(call["argv"][0]).parent == env.bin


@pytest.mark.parametrize("layout", LAYOUTS)
def test_the_mcp_launcher_check_runs_no_python3_and_no_aegis_mcp(env, monkeypatch, tmp_path, layout):
    """The launcher check compares commands; it starts no program, from the workspace or not."""
    env.all_ok()
    marker = tmp_path / "decoy-ran"
    for where in (env.ws, env.ws / "tools"):
        _decoy(where, "python3", marker)
        _decoy(where, "aegis-mcp", marker)
    monkeypatch.chdir(env.ws)
    monkeypatch.setenv("PATH", _path_with(env, layout))
    payload = env.doctor()
    (check,) = [c for c in payload["checks"] if c["id"] == "mcp_launcher"]
    assert not marker.exists(), "doctor ran a program the repository supplied"
    detail = " ".join(check["detail"])
    assert "python3" not in detail and "pip install" not in detail
    if layout == "entry_inside_workspace":
        # An absolute PATH entry is the user's choice, so init would register the
        # workspace's aegis-mcp; doctor says where it is and that the hosts run another.
        decoy = env.ws / "tools" / _decoy_name("aegis-mcp")
        assert check["status"] == "warn", detail
        assert f"MCP launcher: {decoy}, inside the workspace" in detail
        assert f"codex-cli starts {env.mcp}, not this install's {decoy}" in detail
    else:
        assert check["status"] == "pass", detail
        assert f"MCP launcher: {env.mcp}" in detail
        assert "registered for codex-cli, claude-code, antigravity" in detail


@pytest.mark.parametrize("command, args", [
    ("{py}", ["-m", "aegis_mcp"]),
    ("python3", ["-m", "aegis_mcp"]),
    ("{py}", ["aegis_mcp/server.py"]),
    ("{env}", ["python3", "-m", "aegis_mcp"]),
    ("{env}", ["AEGIS_CLIENT=antigravity", "{py}", "-m", "aegis_mcp"]),
])
def test_a_registration_that_runs_from_the_start_directory_is_unsafe_on_the_host_row_and_in_the_launcher_check(
        env, command, args):
    """The v4.0.0 release candidate's fallback (`<python> -m aegis_mcp`), a bare `python3 -m aegis_mcp`,
    a relative script, and either one behind `env` import from the project directory the host
    starts the server in."""
    env.all_ok()
    names = {"py": env.stub("python3"), "env": env.stub("env")}
    cfg = env.antigravity_registered()
    data = json.loads(cfg.read_text(encoding="utf-8"))
    data["mcpServers"]["aegis"].update(command=command.format(**names), args=[a.format(**names) for a in args])
    cfg.write_text(json.dumps(data), encoding="utf-8")
    payload = env.doctor()
    row = host(payload, "antigravity")
    assert "unsafe_registration" in codes(row) and row["state"] == "policy_gap"
    (reason,) = [r for r in row["reasons"] if r["code"] == "unsafe_registration"]
    assert "run aegis init --host antigravity" in reason["message"]
    (check,) = [c for c in payload["checks"] if c["id"] == "mcp_launcher"]
    detail = " ".join(check["detail"])
    assert check["status"] == "warn" and "unsafe registration" in detail
    assert "re-run aegis init --host antigravity" in detail
    assert {h["id"]: h["state"] for h in payload["hosts"]}["codex-cli"] == "ok"


# ── honest enforcement levels (review finding 2) ────────────────────────────

def test_an_ungoverned_workspace_has_no_enforcement_even_where_aegis_is_registered(env, tmp_path):
    env.all_ok()
    bare = tmp_path / "bare"
    bare.mkdir()
    payload = json.loads(env.run(json=True, workspace=str(bare))[1])
    assert {h["state"] for h in payload["hosts"]} == {"policy_gap"}
    assert levels(payload) == dict.fromkeys(PHASE1, "none")
    assert tier(payload, "advisory")["status"] == "inactive"


def test_a_host_that_is_not_installed_has_no_enforcement(env):
    env.all_ok()
    (env.bin / ("agy" + (".exe" if os.name == "nt" else ""))).unlink()
    payload = env.doctor()
    assert host(payload, "antigravity")["state"] == "missing_binary"
    assert levels(payload) == {"codex-cli": "advisory", "claude-code": "advisory", "antigravity": "none"}
    advisory = tier(payload, "advisory")
    assert advisory["status"] == "partial" and "antigravity" not in advisory["detail"]


def test_a_bootstrap_the_host_cuts_for_size_is_not_advisory(env):
    env.all_ok()
    (env.home / ".gemini" / "config" / "mcp_config.json").write_text(json.dumps({"mcpServers": {}}))
    env.bootstrap(before=("x" * 99 + "\n") * 300)  # the block starts past Antigravity's 24,000 bytes
    payload = env.doctor()
    agy = host(payload, "antigravity")
    assert agy["state"] == "unregistered" and "over_budget" in codes(agy)
    assert agy["enforcement_level"] == "none"
    assert tier(payload, "advisory")["status"] == "partial"


def test_antigravity_without_a_registered_workspace_has_no_enforcement(env):
    env.all_ok()
    (env.home / ".aegis" / "workspaces.json").unlink()
    payload = env.doctor()
    assert host(payload, "antigravity")["registration"]["status"] == "registered"
    # The server cannot find this repository, and the bootstrap sends the agent to it.
    assert levels(payload) == {"codex-cli": "advisory", "claude-code": "advisory", "antigravity": "none"}
    assert tier(payload, "advisory")["status"] == "partial"


def test_the_advisory_tier_is_active_only_when_every_selected_host_is_advisory(env):
    env.all_ok()
    payload = env.doctor()
    assert levels(payload) == dict.fromkeys(PHASE1, "advisory")
    advisory = tier(payload, "advisory")
    assert advisory["status"] == "active"
    assert advisory["detail"] == "reaches codex-cli, claude-code, antigravity"


# ── an unreadable registry; the checks-only verdict (review finding 5) ──────

def test_an_unreadable_registry_leaves_antigravity_auth_unknown_never_ok(env):
    env.all_ok()
    (env.home / ".aegis" / "workspaces.json").write_text("{not json", encoding="utf-8")
    payload = env.doctor()
    agy = host(payload, "antigravity")
    assert agy["state"] == "auth_unknown" and "workspace_registry_unknown" in codes(agy)
    assert agy["workspace_registered"] is None
    assert agy["enforcement_level"] == "unknown"
    # Codex and Claude Code attest their workspace: the registry is not how they find it.
    assert host(payload, "codex-cli")["state"] == "ok"
    advisory = tier(payload, "advisory")
    assert advisory["status"] == "partial" and "antigravity" in advisory["detail"]
    assert "unreadable_config" in finding_codes(payload)


def test_the_json_verdict_is_named_for_the_checks_it_covers(env):
    # Every host unregistered, yet no blocking check fails: the verdict must not read as
    # "the hosts are fine".
    env.bootstrap()
    payload = env.doctor()
    assert {h["state"] for h in payload["hosts"]} == {"missing_binary"}
    assert "ok" not in payload
    assert payload["checks_ok"] is True and payload["_rc"] == 0


# ── control sequences from files and host output (review finding 3) ─────────

def test_repository_and_host_strings_reach_the_terminal_without_control_sequences(env):
    env.all_ok()
    env.claude_json({"mcpServers": {}})
    (env.ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"aegis": {
        "command": "\x1b[2J\x1b[31mFAKE-OK", "args": ["\x1b]0;pwn\x07"],
        "env": {"AEGIS_CLIENT": "\x1b]0;pwn\x07claude-code\x1b[0m"}}}}), encoding="utf-8")
    env.replies["codex"] = (1, "", "\x1b[2J\x1b]0;title\x07thread 'main' panicked\n")
    rc, out = env.run()
    assert "\x1b" not in out and "\x07" not in out
    assert "FAKE-OK" in out and "panicked" in out  # the text is shown; its control sequences are not

    payload = env.doctor()
    bad = [s for s in _strings(payload) if any(ord(c) < 0x20 and c not in "\n" or 0x7f <= ord(c) <= 0x9f
                                              for c in s)]
    assert bad == []
    claude = host(payload, "claude-code")
    assert claude["registration"]["command"][0] == "FAKE-OK"
    # The server sees the raw value, which is not "claude-code": cleaning it for display
    # must not turn it into a match.
    assert claude["identity"] == {"status": "mismatch", "aegis_client": "claude-code"}


@pytest.mark.skipif(os.name == "nt", reason="Windows file names cannot hold control characters")
def test_a_workspace_path_with_control_sequences_is_reported_without_them(env, tmp_path):
    import shutil
    hostile = tmp_path / "repo\x1b[2J\x1b]0;pwn\x07"
    shutil.copytree(str(env.ws), str(hostile))
    (hostile / "CLAUDE.md").write_text("@AGENTS.md\n<!-- SOMA:START -->\nold\n<!-- SOMA:END -->\nmine\n",
                                       encoding="utf-8")
    payload = json.loads(env.run(json=True, workspace=str(hostile))[1])
    (finding,) = [f for f in payload["findings"] if f["code"] == "legacy_block"]
    assert "\x1b" not in finding["message"] and "\x07" not in finding["message"]
    assert "legacy Aegis/Soma rules block" in finding["message"]
    rc, out = env.run(workspace=str(hostile))
    warnings = out[out.index("Warnings:"):]
    assert "\x1b" not in warnings and "\x07" not in warnings


# ── what the file says, not what a regex sees (review finding 6) ────────────

@pytest.mark.parametrize("claude_md", [
    "Use the `@AGENTS.md` syntax to import it.\n",
    "Example:\n\n```\n@AGENTS.md\n```\n",
    "~~~md\n@AGENTS.md\n~~~\n",
    "Example:\n\n    @AGENTS.md\n",  # an indented code block
    "\t@AGENTS.md\n",
    "See @AGENTS.md.bak and @AGENTS.md-old\n",  # other files, not AGENTS.md
])
def test_an_import_inside_code_or_of_another_file_is_not_an_import(env, claude_md):
    env.all_ok()
    (env.ws / "CLAUDE.md").write_text(claude_md, encoding="utf-8")
    payload = env.doctor()
    claude = host(payload, "claude-code")
    assert claude["state"] == "policy_gap" and "claude_md_shadows_agents_md" in codes(claude)
    assert "claude_md_without_agents_import" in finding_codes(payload)


def test_a_byte_order_mark_before_the_bootstrap_block_is_not_a_broken_block(env):
    env.all_ok()
    agents = env.ws / "AGENTS.md"
    agents.write_bytes(b"\xef\xbb\xbf" + agents.read_bytes())
    payload = env.doctor()
    assert {h["bootstrap"]["status"] for h in payload["hosts"]} == {"current"}
    assert {h["state"] for h in payload["hosts"]} == {"ok"}


def test_legacy_markers_shown_inside_a_code_fence_are_not_a_block(env):
    env.all_ok()
    (env.ws / "CLAUDE.md").write_text(
        "@AGENTS.md\n\nThe v3 block looked like this:\n\n```md\n<!-- SOMA:START -->\nrules\n"
        "<!-- SOMA:END -->\n```\n", encoding="utf-8")
    assert "legacy_block" not in finding_codes(env.doctor())


def test_a_legacy_block_with_an_unclosed_fence_inside_is_still_one_block(env):
    env.all_ok()
    path = env.ws / "CLAUDE.md"
    path.write_text("@AGENTS.md\n<!-- SOMA:START -->\n```python\nunclosed\n<!-- SOMA:END -->\nmine\n",
                    encoding="utf-8")
    (finding,) = [f for f in env.doctor()["findings"] if f["code"] == "legacy_block"]
    assert finding["fixable"] is True and finding["location"] == "lines 2-5"


def test_a_byte_order_mark_before_a_legacy_block_is_still_a_fixable_block(env):
    env.all_ok()
    path = env.ws / "GEMINI.md"
    path.write_bytes(b"\xef\xbb\xbf<!-- SOMA:START -->\nrules\n<!-- SOMA:END -->\nmine\n")
    (finding,) = [f for f in env.doctor()["findings"] if f["code"] == "legacy_block"]
    assert finding["fixable"] is True and finding["location"] == "lines 1-3"


@pytest.mark.parametrize("claude_md", [
    "@AGENTS.md\n",
    "Read @AGENTS.md first.\n",
    "Notes\n  @AGENTS.md\n",  # two spaces: still a paragraph line, not code
])
def test_an_import_of_agents_md_in_prose_is_an_import(env, claude_md):
    env.all_ok()
    (env.ws / "CLAUDE.md").write_text(claude_md, encoding="utf-8")
    claude = host(env.doctor(), "claude-code")
    assert claude["state"] == "ok" and claude["bootstrap"]["reaches_host"] is True


# ── check lines quote repository strings (re-review finding 1) ──────────────

def _control(text: str) -> List[str]:
    return [c for c in text if (ord(c) < 0x20 and c != "\n") or 0x7f <= ord(c) <= 0x9f]


@pytest.mark.skipif(os.name == "nt", reason="Windows file names cannot hold control characters")
def test_a_rule_file_name_with_control_sequences_reaches_the_terminal_without_them(env):
    env.all_ok()
    bad = env.ws / ".aegis" / "rules" / "invariants" / "bad\x1b[2J\x1b]0;PWN\x07.md"
    bad.write_text("---\nid: [unclosed\n---\nbody\n", encoding="utf-8")
    rc, out = env.run()
    assert "cannot be served" in out, out
    assert _control(out) == []
    payload = env.doctor()
    (rules,) = [c for c in payload["checks"] if c["id"] == "rules"]
    assert rules["status"] == "fail"
    assert [s for s in _strings(payload) if _control(s)] == []


@pytest.mark.skipif(os.name == "nt", reason="Windows file names cannot hold control characters")
def test_a_hostile_workspace_path_is_never_printed_raw_even_by_fix(env, tmp_path):
    import shutil
    env.claude_registered()
    hostile = tmp_path / "repo\x1b[2J\x1b]0;pwn\x07"
    shutil.copytree(str(env.ws), str(hostile))
    (hostile / "GEMINI.md").write_text("<!-- SOMA:START -->\nold\n<!-- SOMA:END -->\nmine\n", encoding="utf-8")
    rc, out = env.run(workspace=str(hostile))
    assert "aegis doctor" in out and _control(out) == []
    rc, out = env.run(workspace=str(hostile), fix=True, yes=True)
    assert "Planned changes" in out and "remove the legacy block" in out
    assert _control(out) == []
    assert (hostile / "GEMINI.md").read_text(encoding="utf-8") == "mine\n"


@pytest.mark.skipif(os.name == "nt", reason="Windows file names cannot hold control characters")
def test_a_reason_quoting_a_hostile_path_has_no_control_sequences(env, tmp_path):
    env.all_ok()
    bare = tmp_path / "bare\x1b[2J\x1b]0;pwn\x07"
    bare.mkdir()
    payload = json.loads(env.run(json=True, workspace=str(bare))[1])
    messages = [r["message"] for h in payload["hosts"] for r in h["reasons"]
                if r["code"] == "workspace_not_governed"]
    assert len(messages) == len(PHASE1)
    assert all("bare" in m and _control(m) == [] for m in messages)


# ── a host binary only inside the workspace (re-review finding 2) ───────────

def test_a_host_binary_found_only_inside_the_workspace_is_reported_never_run(env, monkeypatch, tmp_path):
    env.claude_registered()
    env.antigravity_registered()
    env.register_workspace()
    env.bootstrap()
    inside = env.ws / ".local" / "bin"
    real = _decoy(inside, "codex", tmp_path / "decoy-ran")
    monkeypatch.setenv("PATH", os.pathsep.join([str(inside), str(env.bin)]))
    payload = env.doctor()
    row = host(payload, "codex-cli")
    assert env.calls == [] and not (tmp_path / "decoy-ran").exists()
    assert row["binary"] == {"found": False, "path": None, "names": ["codex"], "ignored": [str(real)]}
    assert row["state"] == "missing_binary"
    assert "missing_binary" not in codes(row) and "binary_in_workspace" in codes(row)
    (reason,) = [r for r in row["reasons"] if r["code"] == "binary_in_workspace"]
    assert str(real) in reason["message"] and "inside the workspace" in reason["message"]
    # Installed or not is undecided, so nothing is claimed either way.
    assert row["enforcement_level"] == "unknown"
    assert "codex-cli.binary" in payload["unknown"]
    rc, out = env.run()
    assert "not on PATH" not in out.split("Codex CLI (codex-cli)")[1].split("Claude Code")[0]
    assert "inside the workspace" in out

    from aegis_cli.hooks.management import generate_hook_block
    hooks = env.ws / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\n" + generate_hook_block(sys.executable), encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)  # git skips a hook it cannot execute
    payload = env.doctor()
    assert tier(payload, "local_floor")["status"] == "active"
    # The floor holds for commits, but not for a host that may not be installed at all.
    assert levels(payload) == {"codex-cli": "unknown", "claude-code": "local_floor", "antigravity": "local_floor"}


def test_the_home_directory_is_never_a_governed_workspace(env, monkeypatch):
    env.all_ok()
    rules = env.home / ".aegis" / "rules" / "invariants"
    rules.mkdir(parents=True)
    (rules / "mine.md").write_text((env.ws / ".aegis" / "rules" / "invariants" / "invariant-sample.md")
                                   .read_text(encoding="utf-8"), encoding="utf-8")
    local_bin = env.home / ".local" / "bin"
    local_bin.mkdir(parents=True)
    os.replace(str(env.bin / _decoy_name("codex")), str(local_bin / _decoy_name("codex")))
    monkeypatch.setenv("PATH", os.pathsep.join([str(local_bin), str(env.bin)]))
    payload = json.loads(env.run(json=True, workspace=str(env.home))[1])
    assert payload["scope"]["workspace_governed"] is False
    assert levels(payload) == dict.fromkeys(PHASE1, "none")
    for row in payload["hosts"]:
        (reason,) = [r for r in row["reasons"] if r["code"] == "workspace_not_governed"]
        assert "home directory" in reason["message"]
    codex = host(payload, "codex-cli")
    assert codex["binary"]["ignored"] == [str(local_bin / _decoy_name("codex"))]
    assert env.calls == []


# ── a CLAUDE.md that is AGENTS.md (re-review finding 3) ─────────────────────

def test_a_claude_md_linked_to_agents_md_reads_the_bootstrap(env):
    from conftest import symlink_or_skip
    env.all_ok()
    symlink_or_skip("AGENTS.md", env.ws / "CLAUDE.md")
    payload = env.doctor()
    claude = host(payload, "claude-code")
    assert claude["state"] == "ok", claude["reasons"]
    assert claude["bootstrap"]["reaches_host"] is True
    assert claude["enforcement_level"] == "advisory"
    assert claude["budget"]["bytes"] == (env.ws / "AGENTS.md").stat().st_size  # one file, counted once
    assert "claude_md_without_agents_import" not in finding_codes(payload)


def test_a_claude_md_linked_elsewhere_without_the_import_is_still_a_gap(env):
    from conftest import symlink_or_skip
    env.all_ok()
    (env.ws / "docs").mkdir()
    (env.ws / "docs" / "notes.md").write_text("# Notes\n", encoding="utf-8")
    symlink_or_skip(os.path.join("docs", "notes.md"), env.ws / "CLAUDE.md")
    payload = env.doctor()
    claude = host(payload, "claude-code")
    assert claude["state"] == "policy_gap" and "claude_md_shadows_agents_md" in codes(claude)
    (finding,) = [f for f in payload["findings"] if f["code"] == "claude_md_without_agents_import"]
    # aegis init never writes through a link, so the advice cannot be "run aegis init".
    assert "link" in finding["message"] and "notes.md" in finding["message"]
    assert "aegis init to add" not in finding["message"]


# ── the local floor outside a governed workspace (re-review low findings) ───

def test_an_ungoverned_git_repository_is_not_called_a_non_repository(env, tmp_path):
    from aegis_cli.hooks.management import generate_hook_block
    env.all_ok()
    bare = tmp_path / "bare"
    hooks = bare / ".git" / "hooks"
    hooks.mkdir(parents=True)
    floor = tier(json.loads(env.run(json=True, workspace=str(bare))[1]), "local_floor")
    assert floor["status"] == "inactive"
    assert "not a git repository" not in floor["detail"] and ".aegis" in floor["detail"]

    (hooks / "pre-commit").write_text("#!/bin/sh\n" + generate_hook_block(sys.executable), encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)  # git skips a hook it cannot execute
    payload = json.loads(env.run(json=True, workspace=str(bare))[1])
    assert tier(payload, "local_floor")["status"] == "inactive"
    assert levels(payload) == dict.fromkeys(PHASE1, "none")

    plain = tmp_path / "plain"
    plain.mkdir()
    floor = tier(json.loads(env.run(json=True, workspace=str(plain))[1]), "local_floor")
    assert (floor["status"], floor["detail"]) == ("unavailable", "not a git repository")


def test_an_active_local_floor_is_never_claimed_for_a_host_that_is_not_installed(env):
    from aegis_cli.hooks.management import generate_hook_block
    env.all_ok()
    (env.bin / _decoy_name("agy")).unlink()
    hooks = env.ws / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\n" + generate_hook_block(sys.executable), encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)  # git skips a hook it cannot execute
    payload = env.doctor()
    assert tier(payload, "local_floor")["status"] == "active"
    assert levels(payload) == {"codex-cli": "local_floor", "claude-code": "local_floor", "antigravity": "none"}


# ── host CLIs on Windows never resolve programs from the cwd (low finding) ──

def test_on_windows_host_cli_children_do_not_search_the_current_directory(monkeypatch):
    seen: List[Dict[str, Any]] = []

    def fake_run(argv, **kw):
        seen.append(kw)
        return subprocess.CompletedProcess(argv, 0, "3\n", "")

    monkeypatch.setattr(doctor.subprocess, "run", fake_run)
    monkeypatch.setenv("PATH", "C:\\bin")
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)  # some launchers set it
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    doctor._run_host_cli(["C:\\bin\\codex.cmd", "mcp", "get", "aegis", "--json"], cwd="C:\\repo", timeout=1.0)
    assert len(seen) == 1  # the codex probe: the MCP launcher check starts no program
    for kw in seen:
        assert kw["env"]["NoDefaultCurrentDirectoryInExePath"] == "1"
        assert kw["env"]["PATH"] == "C:\\bin"

    seen.clear()
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    doctor._run_host_cli(["/usr/bin/codex"], cwd="/repo", timeout=1.0)
    assert "NoDefaultCurrentDirectoryInExePath" not in (seen[0].get("env") or {})


# ── a host binary reachable only through a relative PATH entry (C-fix T4) ───

@pytest.mark.parametrize("entry", ["bin", os.path.join(".", "bin"), os.path.join("..", "tools")])
def test_a_host_binary_reachable_only_through_a_relative_entry_is_unknown_never_run(env, monkeypatch, tmp_path,
                                                                                    entry):
    env.claude_registered()
    env.antigravity_registered()
    env.register_workspace()
    env.bootstrap()
    marker = tmp_path / "decoy-ran"
    planted = _decoy(Path(os.path.normpath(str(env.ws.resolve() / entry))), "codex", marker)
    monkeypatch.chdir(tmp_path)  # doctor --workspace REPO from elsewhere: the host starts in REPO
    monkeypatch.setenv("PATH", os.pathsep.join([entry, str(env.bin)]))
    payload = env.doctor()
    row = host(payload, "codex-cli")
    assert env.calls == [] and not marker.exists()
    assert row["binary"] == {"found": False, "path": None, "names": ["codex"], "ignored": [str(planted)]}
    assert row["state"] == "missing_binary"
    assert "missing_binary" not in codes(row)
    (reason,) = [r for r in row["reasons"] if r["code"] == "binary_on_relative_path"]
    assert str(planted) in reason["message"] and repr(entry) in reason["message"]
    assert row["enforcement_level"] == "unknown"
    assert "codex-cli.binary" in payload["unknown"]
    rc, out = env.run()
    assert "relative PATH entry" in out


def test_a_relative_entry_holding_no_host_binary_is_plainly_missing(env, monkeypatch):
    env.bootstrap()
    (env.ws / "bin").mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join(["bin", "", ".", str(env.bin)]))
    row = host(env.doctor(), "codex-cli")
    assert row["binary"]["ignored"] == []
    assert codes(row)[0] == "missing_binary" and row["enforcement_level"] == "none"


# ── Claude Code turns aegis off per project (C-fix T1) ──────────────────────

def _claude_disables(env: Env, scope: str, names=("other", "aegis")) -> None:
    entry = {"command": str(env.mcp), "args": [], "env": {"AEGIS_CLIENT": "claude-code"}}
    project: Dict[str, Any] = {"disabledMcpServers": list(names)}
    data: Dict[str, Any] = {"numStartups": 3}
    if scope == "user":
        data["mcpServers"] = {"aegis": entry}
    elif scope == "local":
        project["mcpServers"] = {"aegis": entry}
    else:  # project scope, approved: disabledMcpServers still turns it off
        project["enabledMcpjsonServers"] = ["aegis"]
        (env.ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"aegis": entry}}), encoding="utf-8")
    data["projects"] = {str(env.ws.resolve()): project}
    env.claude_json(data)


@pytest.mark.parametrize("scope", ["user", "local", "project"])
def test_a_server_claude_code_turns_off_for_this_project_is_a_policy_gap(env, scope):
    env.all_ok()
    _claude_disables(env, scope)
    payload = env.doctor()
    row = host(payload, "claude-code")
    assert row["registration"]["scope"] == scope
    assert row["registration"]["enabled"] is False
    assert row["state"] == "policy_gap"
    (reason,) = [r for r in row["reasons"] if r["code"] == "registration_disabled"]
    assert "disabledMcpServers" in reason["message"] and "/mcp" in reason["message"]
    # The bootstrap still reaches Claude Code through AGENTS.md: advisory, not more.
    assert row["bootstrap"]["reaches_host"] is True and row["enforcement_level"] == "advisory"
    rc, out = env.run()
    assert "disabledMcpServers" in out.split("Claude Code (claude-code)")[1].split("Antigravity")[0]


def test_a_turned_off_server_is_advisory_exactly_like_an_unregistered_one(env):
    # host-matrix §3.9: the advisory tier is the AGENTS.md bootstrap, MCP instructions or JIT
    # rules. The bootstrap carries its own route when no aegis tool exists (the `aegis scan`
    # line), so turning the server off leaves the same tier as never registering it.
    assert "No MCP tools? Run `aegis scan FILE...` in a shell instead." in bootstrap_text()
    env.all_ok()
    _claude_disables(env, "user")
    disabled = host(env.doctor(), "claude-code")
    env.claude_json({"numStartups": 3})
    absent = host(env.doctor(), "claude-code")
    assert (disabled["state"], absent["state"]) == ("policy_gap", "unregistered")
    assert disabled["enforcement_level"] == absent["enforcement_level"] == "advisory"


def test_a_turned_off_server_without_the_bootstrap_has_no_enforcement(env):
    env.all_ok()
    _claude_disables(env, "user")
    (env.ws / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    row = host(env.doctor(), "claude-code")
    assert row["state"] == "policy_gap"
    assert {"registration_disabled", "bootstrap_missing"} <= set(codes(row))
    assert row["enforcement_level"] == "none"


def test_disabled_mcp_servers_naming_other_servers_leaves_aegis_on(env):
    env.all_ok()
    _claude_disables(env, "user", names=("other", "aegis-old", "AEGIS"))
    row = host(env.doctor(), "claude-code")
    assert row["state"] == "ok" and row["registration"]["enabled"] is None


def test_disabled_mcp_servers_of_another_project_does_not_apply_here(env, tmp_path):
    env.all_ok()
    _claude_disables(env, "user")
    data = json.loads((env.home / ".claude.json").read_text(encoding="utf-8"))
    data["projects"] = {str(tmp_path / "elsewhere"): data["projects"][str(env.ws.resolve())]}
    env.claude_json(data)
    assert host(env.doctor(), "claude-code")["state"] == "ok"


# ── input that would abort doctor (C-fix T2) ────────────────────────────────

_DEEP = "[" * 100000


@pytest.mark.parametrize("use_json", [True, False])
def test_a_deeply_nested_project_mcp_json_is_unreadable_not_fatal(env, use_json):
    env.all_ok()
    (env.ws / ".mcp.json").write_text(_DEEP, encoding="utf-8")
    rc, out = env.run(json=use_json)
    if use_json:
        payload = json.loads(out)
        assert host(payload, "claude-code")["state"] == "ok"  # the user registration decides
        (finding,) = [f for f in payload["findings"] if f["code"] == "unreadable_config"]
        assert Path(finding["path"]).name == ".mcp.json" and "not valid JSON" in finding["message"]
    else:
        assert "Claude Code (claude-code): ok" in out and ".mcp.json is not valid JSON" in out


def test_a_deeply_nested_claude_json_leaves_the_registration_unknown(env):
    env.all_ok()
    (env.home / ".claude.json").write_text(_DEEP, encoding="utf-8")
    payload = env.doctor()
    row = host(payload, "claude-code")
    assert row["state"] == "auth_unknown" and row["registration"]["status"] == "unknown"
    assert "unreadable_config" in finding_codes(payload)


def test_deeply_nested_codex_output_is_an_unanswered_probe(env):
    env.all_ok()
    env.replies["codex"] = (0, _DEEP, "")
    row = host(env.doctor(), "codex-cli")
    assert row["state"] == "auth_unknown" and "registration_unverifiable" in codes(row)


def _realpath_keeping_nul(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make os.path.realpath act as on Windows Python 3.12+: non-strict ntpath.realpath
    returns a path holding a NUL byte as given (gh-106242) instead of raising ValueError."""
    real = os.path.realpath

    def realpath(path, *args, **kwargs):
        text = os.fspath(path)
        if isinstance(text, str) and "\x00" in text:
            return os.path.normpath(os.path.abspath(text))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", realpath)


@pytest.mark.parametrize("bad", ["absolute-with-nul", "absolute-with-nul-realpath-keeps", {"root": "\u0000x"},
                                 {"root": "relative/repo"}, {"root": 7}, "not-an-entry"])
def test_a_registry_entry_doctor_cannot_place_is_skipped_and_reported(env, monkeypatch, bad):
    env.all_ok()
    if bad in ("absolute-with-nul", "absolute-with-nul-realpath-keeps"):
        if bad == "absolute-with-nul-realpath-keeps":
            _realpath_keeping_nul(monkeypatch)
        bad = {"root": str(env.ws.resolve()) + "\u0000x"}
    reg = env.home / ".aegis" / "workspaces.json"
    data = json.loads(reg.read_text(encoding="utf-8"))
    data["workspaces"].insert(0, bad)
    reg.write_text(json.dumps(data), encoding="utf-8")
    for use_json in (True, False):
        rc, out = env.run(json=use_json)
        assert out, "doctor printed nothing"
    payload = env.doctor()
    # The good entry still counts: the workspace is registered.
    assert {h["id"]: h["workspace_registered"] for h in payload["hosts"]} == dict.fromkeys(PHASE1, True)
    assert host(payload, "antigravity")["state"] == "ok"
    (finding,) = [f for f in payload["findings"] if f["code"] == "registry_entry_skipped"]
    assert finding["location"] == "workspaces[0]" and "\x00" not in finding["message"]


def test_a_relative_registry_root_never_matches_the_workspace(env, monkeypatch):
    # The server ignores a root that is not absolute, so doctor must not count it either,
    # even when it would resolve to the workspace from doctor's own cwd.
    env.all_ok()
    reg = env.home / ".aegis" / "workspaces.json"
    reg.write_text(json.dumps({"v": 1, "workspaces": [{"root": env.ws.name}]}), encoding="utf-8")
    monkeypatch.chdir(env.ws.parent)
    agy = host(env.doctor(), "antigravity")
    assert agy["workspace_registered"] is False and "workspace_unregistered" in codes(agy)


# ── every CLAUDE.md Claude Code reads (C-fix T3) ────────────────────────────

@pytest.mark.parametrize("name", ["CLAUDE.local.md", os.path.join(".claude", "CLAUDE.md")])
def test_any_claude_md_family_file_in_the_workspace_shadows_agents_md(env, name):
    env.all_ok()
    path = env.ws / name
    path.parent.mkdir(exist_ok=True)
    path.write_text("# my notes\n", encoding="utf-8")
    payload = env.doctor()
    claude = host(payload, "claude-code")
    assert claude["bootstrap"]["reaches_host"] is False
    assert claude["state"] == "policy_gap" and "claude_md_shadows_agents_md" in codes(claude)
    (finding,) = [f for f in payload["findings"] if f["code"] == "claude_md_without_agents_import"]
    assert Path(finding["path"]) == path
    assert "aegis init to add" not in finding["message"]  # init edits only the root CLAUDE.md
    assert host(payload, "codex-cli")["state"] == "ok"


@pytest.mark.parametrize("name, line", [
    ("CLAUDE.local.md", "@AGENTS.md"),
    (os.path.join(".claude", "CLAUDE.md"), "@../AGENTS.md"),
])
def test_an_import_from_any_claude_md_family_file_lets_the_bootstrap_through(env, name, line):
    env.all_ok()
    (env.ws / "CLAUDE.md").write_text("# notes, no import\n", encoding="utf-8")
    path = env.ws / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(f"Read {line} first.\n", encoding="utf-8")
    claude = host(env.doctor(), "claude-code")
    assert claude["bootstrap"]["reaches_host"] is True and claude["state"] == "ok"


def test_an_import_in_dot_claude_resolves_next_to_that_file(env):
    # @AGENTS.md in .claude/CLAUDE.md names .claude/AGENTS.md, not the root one.
    env.all_ok()
    (env.ws / ".claude").mkdir()
    (env.ws / ".claude" / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    claude = host(env.doctor(), "claude-code")
    assert claude["bootstrap"]["reaches_host"] is False and "claude_md_shadows_agents_md" in codes(claude)


def _nested_workspace(env: Env, tmp_path: Path) -> Path:
    """The governed workspace copied two levels below a directory the test owns."""
    import shutil
    ws = tmp_path / "outer" / "mid" / "repo"
    shutil.copytree(str(env.ws), str(ws))
    return ws


@pytest.mark.parametrize("ancestor, name", [
    ("outer", "CLAUDE.md"), ("mid", "CLAUDE.local.md"), ("outer", os.path.join(".claude", "CLAUDE.md")),
])
def test_a_claude_md_above_the_workspace_leaves_the_bootstrap_reach_unknown(env, tmp_path, ancestor, name):
    env.all_ok()
    ws = _nested_workspace(env, tmp_path)
    above = (tmp_path / "outer" / "mid") if ancestor == "mid" else (tmp_path / "outer")
    path = above / name
    path.parent.mkdir(exist_ok=True)
    # Even one importing this AGENTS.md by path: doctor reads no file outside the workspace.
    path.write_text(f"@{ws.resolve() / 'AGENTS.md'}\n", encoding="utf-8")
    payload = json.loads(env.run(json=True, workspace=str(ws))[1])
    claude = host(payload, "claude-code")
    assert claude["bootstrap"]["reaches_host"] is None
    assert "claude-code.bootstrap" in payload["unknown"]
    assert claude["state"] == "auth_unknown"
    (reason,) = [r for r in claude["reasons"] if r["code"] == "claude_md_outside_workspace"]
    assert str(path) in reason["message"]
    # Only Claude Code reads CLAUDE.md files.
    assert host(payload, "codex-cli")["bootstrap"]["reaches_host"] is True


@pytest.mark.skipif(os.name == "nt" or getattr(os, "geteuid", lambda: 1)() == 0,
                    reason="needs POSIX permissions and a non-root user")
def test_an_unreadable_claude_md_above_the_workspace_still_counts(env, tmp_path):
    env.all_ok()
    ws = _nested_workspace(env, tmp_path)
    path = tmp_path / "outer" / "CLAUDE.md"
    path.write_text("secret\n", encoding="utf-8")
    path.chmod(0)
    try:
        claude = host(json.loads(env.run(json=True, workspace=str(ws))[1]), "claude-code")
    finally:
        path.chmod(0o600)
    assert claude["bootstrap"]["reaches_host"] is None


@pytest.mark.skipif(os.name == "nt" or getattr(os, "geteuid", lambda: 1)() == 0,
                    reason="needs POSIX permissions and a non-root user")
def test_a_claude_md_above_the_workspace_that_cannot_be_checked_still_counts(env, tmp_path):
    # A .claude directory doctor may not search: whether .claude/CLAUDE.md is there cannot be
    # told, so the bootstrap's reach stays unknown rather than claimed.
    env.all_ok()
    ws = _nested_workspace(env, tmp_path)
    hidden = tmp_path / "outer" / ".claude"
    hidden.mkdir()
    (hidden / "CLAUDE.md").write_text("secret\n", encoding="utf-8")
    hidden.chmod(0)
    try:
        payload = json.loads(env.run(json=True, workspace=str(ws))[1])
    finally:
        hidden.chmod(0o700)
    claude = host(payload, "claude-code")
    assert claude["bootstrap"]["reaches_host"] is None and claude["state"] == "auth_unknown"
    assert "claude-code.bootstrap" in payload["unknown"]
    (reason,) = [r for r in claude["reasons"] if r["code"] == "claude_md_outside_workspace"]
    assert str(hidden / "CLAUDE.md") in reason["message"]


def test_an_import_inside_the_workspace_wins_over_a_claude_md_above_it(env, tmp_path):
    env.all_ok()
    ws = _nested_workspace(env, tmp_path)
    (tmp_path / "outer" / "CLAUDE.md").write_text("# parent notes\n", encoding="utf-8")
    (ws / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    claude = host(json.loads(env.run(json=True, workspace=str(ws))[1]), "claude-code")
    assert claude["bootstrap"]["reaches_host"] is True and claude["state"] == "ok"

    (ws / "CLAUDE.md").write_text("# no import\n", encoding="utf-8")
    claude = host(json.loads(env.run(json=True, workspace=str(ws))[1]), "claude-code")
    assert claude["bootstrap"]["reaches_host"] is False and "claude_md_shadows_agents_md" in codes(claude)


def test_a_claude_md_above_the_workspace_never_makes_an_unloaded_server_advisory(env, tmp_path):
    env.all_ok()
    env.claude_json({})  # Claude Code does not load aegis: only the bootstrap could reach it
    ws = _nested_workspace(env, tmp_path)
    (tmp_path / "outer" / "CLAUDE.md").write_text("# parent notes\n", encoding="utf-8")
    payload = json.loads(env.run(json=True, workspace=str(ws))[1])
    claude = host(payload, "claude-code")
    assert claude["state"] == "unregistered"
    assert claude["enforcement_level"] == "unknown"
    assert tier(payload, "advisory")["status"] != "active"


def _workspace_under_home(env: Env) -> Path:
    import shutil
    ws = env.home / "projects" / "repo"
    shutil.copytree(str(env.ws), str(ws))
    return ws


def _user_memory(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "CLAUDE.md"
    path.write_text("# My global notes\n\nNo import of any AGENTS.md here.\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("config_dir", [None, ".claude"], ids=["default", "CLAUDE_CONFIG_DIR"])
def test_the_users_own_claude_md_never_shadows_agents_md(env, monkeypatch, config_dir):
    # Claude Code loads ~/.claude/CLAUDE.md (CLAUDE_CONFIG_DIR/CLAUDE.md) as user memory and
    # leaves it out of the walk up from the project that decides whether AGENTS.md is read.
    env.all_ok()
    ws = _workspace_under_home(env)
    _user_memory(env.home / ".claude")
    if config_dir:
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(env.home / config_dir))
        (env.home / ".claude.json").replace(env.home / config_dir / ".claude.json")
    payload = json.loads(env.run(json=True, workspace=str(ws))[1])
    claude = host(payload, "claude-code")
    assert claude["bootstrap"]["reaches_host"] is True
    assert claude["state"] == "ok" and claude["enforcement_level"] == "advisory"
    assert "claude-code.bootstrap" not in payload["unknown"]
    assert "claude_md_outside_workspace" not in codes(claude)


def test_under_a_symlinked_home_the_users_claude_md_leaves_the_reach_unknown(env, monkeypatch, tmp_path):
    # HOME names a link to the real home directory, and the workspace is found by its resolved
    # path. Whether Claude Code then matches its user memory against the ancestors of the
    # project by spelling or by resolved path is not known, so doctor claims neither way.
    env.all_ok()
    _workspace_under_home(env)
    link = tmp_path / "home-link"
    try:
        link.symlink_to(env.home, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create a directory symlink here")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(link))
    memory = _user_memory(env.home / ".claude")
    payload = json.loads(env.run(json=True, workspace=str(link / "projects" / "repo"))[1])
    claude = host(payload, "claude-code")
    assert claude["bootstrap"]["reaches_host"] is None and claude["state"] == "auth_unknown"
    (reason,) = [r for r in claude["reasons"] if r["code"] == "claude_md_outside_workspace"]
    assert str(memory.resolve()) in reason["message"]


def test_a_dot_claude_md_in_home_counts_when_claude_keeps_its_config_elsewhere(env, monkeypatch, tmp_path):
    # With CLAUDE_CONFIG_DIR elsewhere, ~/.claude/CLAUDE.md is an ordinary .claude/CLAUDE.md above the
    # project; the user memory is CLAUDE_CONFIG_DIR/CLAUDE.md, which is not above it.
    env.all_ok()
    ws = _workspace_under_home(env)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude-config"))
    _user_memory(tmp_path / "claude-config")
    (env.home / ".claude.json").replace(tmp_path / "claude-config" / ".claude.json")
    shadow = _user_memory(env.home / ".claude")
    payload = json.loads(env.run(json=True, workspace=str(ws))[1])
    claude = host(payload, "claude-code")
    assert claude["bootstrap"]["reaches_host"] is None and claude["state"] == "auth_unknown"
    (reason,) = [r for r in claude["reasons"] if r["code"] == "claude_md_outside_workspace"]
    assert str(shadow) in reason["message"]


@pytest.mark.parametrize("name", ["CLAUDE.md", "CLAUDE.local.md"])
def test_a_claude_md_directly_in_home_still_counts(env, name):
    env.all_ok()
    ws = _workspace_under_home(env)
    _user_memory(env.home / ".claude")
    (env.home / name).write_text("# notes\n", encoding="utf-8")
    payload = json.loads(env.run(json=True, workspace=str(ws))[1])
    claude = host(payload, "claude-code")
    assert claude["bootstrap"]["reaches_host"] is None and claude["state"] == "auth_unknown"
    (reason,) = [r for r in claude["reasons"] if r["code"] == "claude_md_outside_workspace"]
    assert str(env.home / name) in reason["message"]


# ── a registered command doctor cannot place (C-fix round 3, R5) ────────────

def test_a_bare_registered_command_on_no_path_entry_is_missing(env):
    env.all_ok()
    env.antigravity_registered(command="no-such-aegis-mcp")
    row = host(env.doctor(), "antigravity")
    assert row["registration"]["command_exists"] is False
    assert row["state"] == "unregistered" and "command_missing" in codes(row)


def test_a_bare_registered_command_on_an_absolute_path_entry_exists_but_is_unsafe(env):
    """The host resolves a bare name itself, from the directory it starts in (libuv on
    Windows searches it before PATH); aegis init registers only absolute commands."""
    env.all_ok()
    env.antigravity_registered(command="aegis-mcp")
    row = host(env.doctor(), "antigravity")
    assert row["registration"]["command_exists"] is True
    assert row["state"] == "policy_gap" and codes(row) == ["unsafe_registration"]
    assert "not an absolute path" in row["reasons"][0]["message"]


@pytest.mark.parametrize("layout", ["empty_entry", "relative_entry", "entry_inside_workspace"])
def test_a_bare_registered_command_found_only_where_doctor_does_not_look_is_unknown(env, monkeypatch, tmp_path,
                                                                                     layout):
    # The host would find it (on PATH from the directory it starts in, or in an absolute
    # entry inside the repository); doctor counts neither, so it can say neither
    # "exists" nor "missing".
    env.all_ok()
    marker = tmp_path / "decoy-ran"
    for where in (env.ws, env.ws / "tools"):
        _decoy(where, "repo-mcp", marker)
    monkeypatch.chdir(env.ws)
    monkeypatch.setenv("PATH", _path_with(env, layout))
    env.antigravity_registered(command="repo-mcp")
    payload = env.doctor()
    row = host(payload, "antigravity")
    assert row["registration"]["command_exists"] is None
    assert row["state"] == "auth_unknown"
    (reason,) = [r for r in row["reasons"] if r["code"] == "command_unverifiable"]
    assert "repo-mcp" in reason["message"] and "doctor does not look" in reason["message"]
    assert "antigravity.command_exists" in payload["unknown"]
    assert not marker.exists()


@pytest.mark.parametrize("command", ["./aegis-mcp", "sub/aegis-mcp", os.path.join("sub", "aegis-mcp")])
def test_a_relative_registered_command_path_is_unknown_never_looked_up_on_path(env, command):
    # The host resolves such a command against the directory it starts the server in,
    # not against PATH: an aegis-mcp in a PATH directory (bin/ and bin/sub/ here) says nothing.
    env.all_ok()
    (env.bin / "sub").mkdir()
    (env.bin / "sub" / env.mcp.name).write_bytes(env.mcp.read_bytes())
    (env.bin / "sub" / env.mcp.name).chmod(0o755)
    env.antigravity_registered(command=command)
    rc, out = env.run()
    payload = env.doctor()
    row = host(payload, "antigravity")
    assert row["registration"]["command_exists"] is None
    assert row["state"] == "auth_unknown"
    (reason,) = [r for r in row["reasons"] if r["code"] == "command_unverifiable"]
    assert "relative path" in reason["message"]
    assert f"command      {command} (unknown)" in out


# ── doctor run from the home directory (C-fix round 3, R7) ──────────────────

def _home_rules(env: Env) -> Path:
    rules = env.home / ".aegis" / "rules" / "invariants"
    rules.mkdir(parents=True)
    (rules / "mine.md").write_text((env.ws / ".aegis" / "rules" / "invariants" / "invariant-sample.md")
                                   .read_text(encoding="utf-8"), encoding="utf-8")
    return env.home / ".aegis" / "rules"


def test_from_home_the_rules_check_names_the_user_layer_never_a_workspace(env):
    env.all_ok()
    user_rules = _home_rules(env)
    payload = json.loads(env.run(json=True, workspace=str(env.home))[1])
    checks = {c["id"]: c for c in payload["checks"]}
    assert checks["rules"]["status"] == "fail"
    joined = " ".join(checks["rules"]["detail"])
    assert f"{user_rules} is your user rule layer" in joined
    assert "served" not in joined and "aegis init" not in joined
    assert checks["state_dir"]["status"] == "skip"
    assert "user layer" in " ".join(checks["state_dir"]["detail"])
    assert not any(str(env.home / ".aegis" / "state") in line for line in checks["state_dir"]["detail"])


def test_from_home_no_source_file_under_it_is_taken_for_a_project(env):
    # ~/.aegis/config.json is the user scope: --fix must never write a repository's
    # driver opt-in there, and the AST check never walks the home directory.
    env.all_ok()
    _home_rules(env)
    (env.home / "scratch").mkdir()
    (env.home / "scratch" / "index.ts").write_text("console.log(1);\n", encoding="utf-8")
    payload = json.loads(env.run(json=True, workspace=str(env.home), fix=True, yes=True)[1])
    checks = {c["id"]: c for c in payload["checks"]}
    assert checks["ast_drivers"]["status"] == "skip"
    assert "user layer" in " ".join(checks["ast_drivers"]["detail"])
    assert not (env.home / ".aegis" / "config.json").exists()
    assert not any(f.get("action", "").startswith("enable") for f in payload.get("fixes", []))


# ── v4.0.0 release review: the floor must be reachable, a .soma workspace migrates ──

def _install_current_hook(env: Env) -> Path:
    from aegis_cli.hooks.management import generate_hook_block

    hooks = env.ws / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\n" + generate_hook_block(sys.executable), encoding="utf-8")
    hook.chmod(0o755)
    return hook


def _unreachable(monkeypatch, reason: str) -> None:
    """hook_status as the git-hook lane reports a block git never reaches."""
    from aegis_cli.hooks import management

    real = management.hook_status

    def status(root=None):
        st = real(root)
        st.update(reachable=False, unreachable_reason=reason)
        return st

    monkeypatch.setattr(management, "hook_status", status)


def test_a_current_hook_git_never_reaches_is_not_the_local_floor(env, monkeypatch):
    env.all_ok()
    _install_current_hook(env)
    assert tier(env.doctor(), "local_floor")["status"] == "active"
    reason = "line 2 (exec ./other-hook) ends the hook before the aegis block, so the check never runs"
    _unreachable(monkeypatch, reason)
    payload = env.doctor()
    floor = tier(payload, "local_floor")
    assert floor["status"] == "inactive"
    assert floor["detail"] == f"the Aegis pre-commit hook is installed but never runs: {reason}; see aegis hook status"
    assert levels(payload) == dict.fromkeys(PHASE1, "advisory")
    (check,) = [c for c in payload["checks"] if c["id"] == "precommit_hook"]
    assert check["status"] == "fail" and payload["_rc"] == 1
    assert f"never runs: {reason}" in " ".join(check["detail"])


def test_a_hook_status_without_reachability_counts_as_reachable(env):
    """hook_status gains `reachable` in the git-hook lane; until then its absence is no gap."""
    env.all_ok()
    _install_current_hook(env)
    from aegis_cli.hooks.management import hook_status

    st = hook_status(env.ws)
    if "reachable" in st:
        assert st["reachable"] is True
    payload = env.doctor()
    assert tier(payload, "local_floor")["status"] == "active"
    (check,) = [c for c in payload["checks"] if c["id"] == "precommit_hook"]
    assert check["status"] == "pass"


def test_one_run_reads_the_hook_status_once_for_the_floor_and_the_check(env, monkeypatch):
    """Given a current hook, when doctor runs, then the local floor and the pre-commit check
    agree on one hook_status reading."""
    from aegis_cli.hooks import management

    env.all_ok()
    _install_current_hook(env)
    real, calls = management.hook_status, []
    monkeypatch.setattr(management, "hook_status", lambda root=None: calls.append(root) or real(root))
    payload = env.doctor()
    assert len(calls) == 1
    assert tier(payload, "local_floor")["status"] == "active"
    (check,) = [c for c in payload["checks"] if c["id"] == "precommit_hook"]
    assert check["status"] == "pass"


def test_a_hook_status_that_raises_leaves_the_floor_unknown_and_the_check_raises_it(env, monkeypatch):
    """Given hook_status raising, when doctor runs, then the floor is unknown (no retry, no
    empty success) and the pre-commit check raises the same exception."""
    from aegis_cli import doctor_findings
    from aegis_cli.hooks import management

    env.all_ok()
    boom, calls, floors = RuntimeError("the hooks directory cannot be read"), [], []

    def status(root=None):
        calls.append(root)
        raise boom

    real_floor = doctor_findings._floor_status
    monkeypatch.setattr(management, "hook_status", status)
    monkeypatch.setattr(doctor_findings, "_floor_status", lambda *a: floors.append(real_floor(*a)) or floors[-1])
    with pytest.raises(RuntimeError) as caught:
        env.doctor()
    assert caught.value is boom
    assert floors == [("unknown", None)]
    assert len(calls) == 1


def test_apply_with_json_is_still_refused_before_anything_runs(env, capsys):
    env.all_ok()
    rc, out = env.run(github=True, apply=True, tier="A", json=True)
    assert (rc, out) == (2, "")
    assert capsys.readouterr().err == ("aegis doctor: --github --apply asks at a terminal, so it cannot run with "
                                       "--json\n")


def test_the_best_effort_tier_without_host_hooks_is_inactive_and_names_the_install_command(env):
    env.all_ok()
    best = tier(env.doctor(), "best_effort")
    assert best["status"] == "inactive" and best["hosts"] == []
    # Antigravity hooks are unavailable on Windows, and Codex's shell form needs a plain path there.
    hosts_named = "claude-code" if os.name == "nt" else "codex-cli, claude-code, antigravity"
    assert best["detail"] == (f"no Aegis PreToolUse hook registered for {hosts_named}: "
                              "run aegis hook install --host <host>")


def test_a_legacy_workspace_without_rules_is_told_to_migrate_never_to_init(env, tmp_path, monkeypatch, capsys):
    """Release review (upgrade): `aegis init` in a .soma workspace leaves its rules unserved.
    Run through the CLI, which lets doctor (and only doctor and uninstall) into one."""
    from aegis_cli.cli import main

    env.all_ok()
    legacy = tmp_path / "legacy"
    (legacy / ".soma" / "cells" / "traps").mkdir(parents=True)
    (legacy / ".soma" / "cells" / "traps" / "trap-x.md").write_text("---\nid: trap-x\n---\n# x\n", encoding="utf-8")
    (legacy / ".git" / "hooks").mkdir(parents=True)
    monkeypatch.chdir(legacy)
    main(["doctor"])
    out = capsys.readouterr().out
    assert "Fix: Run 'aegis migrate' to see how this v3 workspace converts, then 'aegis migrate --apply'." in out
    assert f"{legacy.resolve()} has no .aegis/: run aegis migrate there" in out
    assert "a pre-commit hook has nothing to enforce: run aegis migrate" in out
    for setup_advice in ("Run 'aegis init'", "run aegis init there", "nothing to enforce: run aegis init"):
        assert setup_advice not in out
    plain = tmp_path / "plain"
    (plain / ".git" / "hooks").mkdir(parents=True)
    monkeypatch.chdir(plain)
    main(["doctor"])
    out = capsys.readouterr().out
    assert "Fix: Run 'aegis init' to install starter rules." in out and "aegis migrate" not in out


# ── unmigrated v3 state (discovery.unmigrated_state, from the gate/upgrade lane) ──

V3_STATE = [".aegis/evidence/signals.jsonl", "aegis.conf"]


def test_pending_worktree_ledger_rows_are_a_warning_that_names_aegis_migrate(env, monkeypatch):
    """After the v4.2 upgrade rows in a worktree's own ledger are not read; doctor says so."""
    from aegis_core import migrate

    env.all_ok()
    monkeypatch.setattr(migrate, "pending_worktree_rows", lambda root: 3)
    payload = env.doctor()
    (finding,) = [f for f in payload["findings"] if f["code"] == "worktree_ledger_pending"]
    assert finding["severity"] == "warning" and finding["fixable"] is False
    assert "3 outcome row(s)" in finding["message"] and "aegis migrate --apply" in finding["message"]
    monkeypatch.setattr(migrate, "pending_worktree_rows", lambda root: 0)
    assert "worktree_ledger_pending" not in finding_codes(env.doctor())


def test_unmigrated_v3_state_is_a_warning_that_names_the_files_and_aegis_migrate(env, monkeypatch):
    """status, scan and sync refuse a workspace with v3 state v4 never reads; doctor, which
    still runs there, says so instead of reporting a healthy workspace."""
    from aegis_core.workspace import discovery

    env.all_ok()
    seen = []

    def pending(root):
        seen.append(Path(root))
        return list(V3_STATE)

    monkeypatch.setattr(discovery, "unmigrated_state", pending, raising=False)
    payload = env.doctor()
    assert [p.resolve() for p in seen] == [env.ws.resolve()]
    (finding,) = [f for f in payload["findings"] if f["code"] == "unmigrated_v3_state"]
    assert finding["severity"] == "warning" and finding["fixable"] is False
    assert Path(finding["path"]) == env.ws.resolve() / ".aegis" / "evidence" / "signals.jsonl"
    assert finding["message"] == (
        "unmigrated v3 state: .aegis/evidence/signals.jsonl, aegis.conf. Aegis v4 does not read it, and "
        "aegis status, scan and sync refuse to run until it is converted: run aegis migrate to see the "
        "conversion, then aegis migrate --apply")
    assert payload["summary"]["warnings"] >= 1
    rc, out = env.run()
    assert "unmigrated v3 state: .aegis/evidence/signals.jsonl, aegis.conf" in out.split("Warnings:")[1]


def test_no_unmigrated_state_means_no_upgrade_warning(env, monkeypatch):
    """A v4 workspace has none, so doctor reports none."""
    from aegis_core.workspace import discovery

    env.all_ok()
    monkeypatch.setattr(discovery, "unmigrated_state", lambda root: [])
    payload = env.doctor()
    assert "unmigrated_v3_state" not in finding_codes(payload) and payload["findings"] == []


def test_the_home_directory_is_never_checked_for_unmigrated_state(env, monkeypatch):
    """~/.aegis is the user plane, not a v3 workspace: aegis migrate never runs there."""
    from aegis_core.workspace import discovery

    env.all_ok()
    seen = []
    monkeypatch.setattr(discovery, "unmigrated_state", lambda root: seen.append(root) or list(V3_STATE),
                        raising=False)
    payload = env.doctor(workspace=str(env.home))
    assert seen == [] and "unmigrated_v3_state" not in finding_codes(payload)


# ── surfaces, IDE and desktop planes, bootstrap without tools (v4.1 rev 3.1) ─────

def kiro_registered(env: Env, command: Optional[str] = None) -> Path:
    cfg = env.home / ".kiro" / "settings" / "mcp.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"mcpServers": {"aegis": {
        "command": command or str(env.mcp), "args": [], "env": {"AEGIS_CLIENT": "kiro"}}}}), encoding="utf-8")
    return cfg


def select(env: Env, *host_ids: str) -> None:
    (env.ws / ".aegis" / "config.json").write_text(json.dumps({"v": 1, "hosts": list(host_ids)}), encoding="utf-8")


def test_every_row_lists_the_surfaces_its_config_plane_covers(env):
    env.all_ok()
    payload = env.doctor()
    from aegis_core import hosts as table
    for row in payload["hosts"]:
        assert row["surfaces"] == list(table.get(row["id"]).surfaces)
    rc, out = env.run()
    assert "surfaces     Codex CLI, Codex IDE extension, ChatGPT desktop app (Codex mode)" in out
    assert "surfaces     Claude Code CLI, Claude Code IDE extensions, Claude desktop app (Code tab)" in out


def test_kiro_is_checked_from_its_user_mcp_json_without_running_kiro_cli(env):
    env.all_ok()
    env.stub("kiro-cli")
    kiro_registered(env)
    select(env, "kiro")
    payload = env.doctor()
    row = host(payload, "kiro")
    assert row["state"] == "ok", row["reasons"]
    assert row["verified_row"] is False
    assert row["registration"]["source"] == "~/.kiro/settings/mcp.json"
    assert row["registration"]["scope"] == "user"
    assert row["identity"] == {"status": "explicit", "aegis_client": "kiro"}
    assert row["hooks"]["status"] == "none"  # no Aegis hooks for Kiro in v4.1
    assert row["enforcement_level"] == "advisory"
    # The only host CLI doctor starts is codex (for the bootstrap check of a host found here).
    assert {Path(c["argv"][0]).stem for c in env.calls} <= {"codex"}


def test_an_unverified_row_joins_the_default_matrix_only_where_its_plane_is_found(env):
    env.all_ok()
    assert [h["id"] for h in env.doctor()["hosts"]] == PHASE1
    (env.home / ".kiro").mkdir()
    payload = env.doctor()
    assert [h["id"] for h in payload["hosts"]] == PHASE1 + ["kiro"]
    assert payload["scope"]["hosts"] == PHASE1 + ["kiro"]


def test_an_installed_app_counts_as_installed_without_a_cli(env, monkeypatch, tmp_path):
    """The Kiro IDE puts no kiro-cli on PATH: its app bundle shows the host is installed,
    so the row is judged on its registration instead of reported missing."""
    from aegis_core import hosts as table
    apps = tmp_path / "Applications"
    (apps / "Kiro.app").mkdir(parents=True)
    monkeypatch.setattr(table, "APP_DIRS", {"darwin": (str(apps),)})
    monkeypatch.setattr(doctor_base, "_platform", lambda: "darwin")
    env.all_ok()
    select(env, "kiro")
    row = host(env.doctor(), "kiro")
    assert row["state"] == "unregistered" and "missing_binary" not in codes(row)
    assert row["binary"]["found"] is False
    assert row["app"] == str(apps / "Kiro.app")
    kiro_registered(env)
    row = host(env.doctor(), "kiro")
    assert row["state"] == "ok" and row["enforcement_level"] == "advisory"


def test_an_app_that_doctor_cannot_ask_is_auth_unknown_never_ok(env, monkeypatch, tmp_path):
    """The ChatGPT desktop app keeps Codex registrations in TOML that only the codex CLI
    reads: with the app and no CLI, doctor cannot tell, and says so."""
    from aegis_core import hosts as table
    apps = tmp_path / "Applications"
    (apps / "Codex.app").mkdir(parents=True)
    monkeypatch.setattr(table, "APP_DIRS", {"darwin": (str(apps),)})
    monkeypatch.setattr(doctor_base, "_platform", lambda: "darwin")
    env.bootstrap()
    env.register_workspace()
    row = host(env.doctor(), "codex-cli")
    assert row["state"] == "auth_unknown"
    assert "registration_unverifiable" in codes(row)
    assert env.calls == []


def bootstrap_warnings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [f for f in payload["findings"] if f["code"] == "bootstrap_without_tools"]


def test_a_found_host_that_reads_the_bootstrap_without_aegis_tools_is_warned_about(env):
    """The field case: Kiro read AGENTS.md, whose bootstrap tells the agent to call
    aegis_scan, but Kiro had no Aegis MCP registration. The workspace selected another host."""
    env.all_ok()
    select(env, "codex-cli")
    (env.home / ".kiro").mkdir()
    payload = env.doctor()
    (warning,) = bootstrap_warnings(payload)
    assert warning["severity"] == "warning"
    assert warning["path"] == str(env.ws / "AGENTS.md")
    assert "Kiro" in warning["message"] and "aegis init --host kiro" in warning["message"]
    assert "~/.kiro" in warning["message"]
    assert [h["id"] for h in payload["hosts"]] == ["codex-cli"]
    rc, out = env.run()
    assert "aegis init --host kiro" in out


def test_no_bootstrap_warning_once_the_host_has_aegis(env):
    env.all_ok()
    select(env, "codex-cli")
    (env.home / ".kiro").mkdir()
    kiro_registered(env)
    assert bootstrap_warnings(env.doctor()) == []


def test_no_bootstrap_warning_without_the_bootstrap_or_without_the_host(env):
    env.all_ok()
    select(env, "codex-cli")
    assert bootstrap_warnings(env.doctor()) == []  # no Kiro on this machine
    (env.home / ".kiro").mkdir()
    (env.ws / "AGENTS.md").write_text("# Notes\n", encoding="utf-8")
    assert bootstrap_warnings(env.doctor()) == []  # no bootstrap to mislead its agent


def test_a_selected_host_left_unregistered_is_warned_about_too(env):
    env.all_ok()
    env.replies["codex"] = (1, "", "Error: No MCP server named 'aegis' found.\n")
    (warning,) = bootstrap_warnings(env.doctor())
    assert "Codex CLI" in warning["message"] and "aegis init --host codex-cli" in warning["message"]


def test_no_bootstrap_warning_where_doctor_cannot_tell_or_the_host_skips_agents_md(env):
    env.all_ok()
    env.replies["codex"] = subprocess.TimeoutExpired(["codex"], 10)  # unknown is not absent
    env.claude_json({})  # claude-code unregistered...
    (env.ws / "CLAUDE.md").write_text("# Notes\n", encoding="utf-8")  # ...but it reads CLAUDE.md, not AGENTS.md
    (env.home / ".codex").mkdir()
    assert bootstrap_warnings(env.doctor()) == []


def test_a_host_found_only_by_its_config_dir_whose_registration_cannot_be_read_is_not_warned_about(env):
    env.bootstrap()
    (env.home / ".codex").mkdir()  # the ChatGPT desktop app, say: no codex CLI to ask
    assert bootstrap_warnings(env.doctor()) == []


def test_a_host_without_a_documented_instruction_budget_prints_the_size_alone(env):
    env.all_ok()
    kiro_registered(env)
    select(env, "kiro")
    size = (env.ws / "AGENTS.md").stat().st_size
    row = host(env.doctor(), "kiro")
    assert row["budget"] == {"file": "AGENTS.md", "bytes": size, "budget_bytes": None, "within": None}
    rc, out = env.run()
    assert f"budget       AGENTS.md {size} bytes (no documented limit)" in out
    assert "of None" not in out


# ── experimental rows: cursor, copilot, kiro, windsurf (v4.2 #6) ─────────────────

EXPERIMENTAL_FILES = {
    "kiro": (".kiro/settings/mcp.json", "kiro-cli"),
    "cursor": (".cursor/mcp.json", "cursor-agent"),
    "copilot": (".copilot/mcp-config.json", "copilot"),
    "windsurf": (".codeium/windsurf/mcp_config.json", "windsurf"),
}


def experimental_registered(env: Env, host_id: str) -> Path:
    relative, binary = EXPERIMENTAL_FILES[host_id]
    env.stub(binary)
    cfg = env.home.joinpath(*relative.split("/"))
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"mcpServers": {"aegis": {
        "command": str(env.mcp), "args": [], "env": {"AEGIS_CLIENT": host_id}}}}), encoding="utf-8")
    return cfg


@pytest.mark.parametrize("host_id", sorted(EXPERIMENTAL_FILES))
def test_an_experimental_row_is_checked_from_the_file_its_vendor_documents(env, host_id):
    env.all_ok()
    experimental_registered(env, host_id)
    select(env, host_id)
    payload = env.doctor()
    row = host(payload, host_id)
    assert row["state"] == "ok", row["reasons"]
    assert row["registration"]["source"] == "~/" + EXPERIMENTAL_FILES[host_id][0]
    assert row["registration"]["scope"] == "user"
    assert row["identity"] == {"status": "explicit", "aegis_client": host_id}
    assert row["hooks"]["status"] == "none"
    assert row["enforcement_level"] == "advisory"
    assert {Path(c["argv"][0]).stem for c in env.calls} <= {"codex"}  # never a host CLI of its own


@pytest.mark.parametrize("host_id", sorted(EXPERIMENTAL_FILES))
def test_an_experimental_row_without_a_registration_is_unregistered_with_the_fix(env, host_id):
    env.all_ok()
    env.stub(EXPERIMENTAL_FILES[host_id][1])
    select(env, host_id)
    row = host(env.doctor(), host_id)
    assert row["state"] == "unregistered" and "not_registered" in codes(row)
    assert f"run aegis init --host {host_id}" in next(r["message"] for r in row["reasons"] if r["code"] == "not_registered")


@pytest.mark.parametrize("host_id", ["cursor", "copilot", "windsurf"])
def test_a_new_experimental_row_joins_the_default_matrix_only_where_its_plane_is_found(env, host_id):
    env.all_ok()
    assert host_id not in [h["id"] for h in env.doctor()["hosts"]]
    plane = {"cursor": ".cursor", "copilot": ".copilot", "windsurf": ".codeium/windsurf"}[host_id]
    env.home.joinpath(*plane.split("/")).mkdir(parents=True)
    assert [h["id"] for h in env.doctor()["hosts"]][-1] == host_id


def test_doctor_labels_an_experimental_row_experimental_and_a_verified_one_not(env):
    env.all_ok()
    experimental_registered(env, "cursor")
    select(env, "cursor", "codex-cli")
    payload = env.doctor()
    assert host(payload, "cursor")["experimental"] is True
    assert host(payload, "cursor")["verified_row"] is False
    assert host(payload, "codex-cli")["experimental"] is False
    rc, out = env.run()
    lines = out.splitlines()
    (cursor_line,) = [l for l in lines if "(cursor)" in l]
    assert cursor_line.endswith("Cursor (cursor) [experimental]: ok")
    (codex_line,) = [l for l in lines if "(codex-cli)" in l]
    assert codex_line.endswith("Codex CLI (codex-cli): ok") and "experimental" not in codex_line
    notice = "experimental documented by the vendor, not yet checked on a real install (verified after 3 clean runs)"
    assert out.count(notice) == 1
    assert lines[lines.index(cursor_line) + 1].strip() == notice  # inside Cursor's block, not Codex's


# ── Pins: a host row's reasons, unknown, state and keys, in order (R-cli-a1; recorded before the split) ──

ROW_KEYS = ["id", "display_name", "verified_row", "experimental", "surfaces", "state", "reasons", "binary", "app",
            "registration", "identity", "workspace_registered", "bootstrap", "budget", "enforcement_level",
            "advisory", "hooks", "insight_capture", "trust_tier", "trust_tier_status", "stale", "unknown"]


def _rows_and_direct_rows(env: Env, monkeypatch: pytest.MonkeyPatch):
    """The doctor payload, and each host row again from a direct _host_row call with the
    arguments the run passed (the payload's rows also carry the trust tier _diagnose sets)."""
    from aegis_cli import doctor_findings

    real = doctor_findings._host_row
    seen: List[tuple] = []

    def spy(*args):
        seen.append(args)
        return real(*args)

    monkeypatch.setattr(doctor_findings, "_host_row", spy)
    payload = env.doctor()
    monkeypatch.setattr(doctor_findings, "_host_row", real)
    return payload, {args[0].id: real(*args) for args in seen}


def _pinned(row: Dict[str, Any]) -> Dict[str, Any]:
    return {"state": row["state"], "reasons": codes(row), "unknown": row["unknown"],
            "workspace_registered": row["workspace_registered"], "advisory": row["advisory"],
            "enforcement_level": row["enforcement_level"], "hooks": row["hooks"]["status"]}


# On Windows, registrar.unavailable_reason rules out Antigravity hooks, and Codex hooks for any drive-letter
# aegis path (outside AEGIS_PATH_CHARSET), so those rows say "unavailable" where POSIX says "absent".
_NO_HOOKS_ON_WINDOWS = ("codex-cli", "antigravity")


def _assert_pinned(payload: Dict[str, Any], direct: Dict[str, Dict[str, Any]], expected: Dict[str, Any]) -> None:
    shown = [key for key in ROW_KEYS if key != "advisory"]  # doctor --json leaves advisory out
    assert [row["id"] for row in payload["hosts"]] == list(expected)
    for row in payload["hosts"]:
        own = direct[row["id"]]
        assert list(own) == ROW_KEYS
        assert list(row) == shown
        assert (own["trust_tier"], own["trust_tier_status"]) == (None, "unavailable")
        assert {k: v for k, v in row.items() if not k.startswith("trust_tier")} == {
            k: v for k, v in own.items() if k != "advisory" and not k.startswith("trust_tier")}
        want = expected[row["id"]]
        if os.name == "nt" and row["id"] in _NO_HOOKS_ON_WINDOWS:
            want = dict(want, hooks="unavailable")
        assert _pinned(own) == want, row["id"]


class TestHostRowPins:
    """Characterization pins: green before _host_row was split into helpers, unchanged after."""

    def test_every_unknown_at_once_keeps_its_order_in_the_payload_and_the_direct_row(self, env, monkeypatch):
        env.codex_registered()
        env.stub("claude")
        python = env.stub("python3")
        # Claude Code: only this project's .mcp.json registers aegis (approval unknown), through a
        # launch that imports from the start directory (unsafe), as any client (identity unknown);
        # its user settings cannot be read (hooks unknown).
        (env.ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"aegis": {
            "command": str(python), "args": ["-m", "aegis_mcp"], "env": {"AEGIS_CLIENT": "*"}}}}), encoding="utf-8")
        (env.home / ".claude").mkdir()
        (env.home / ".claude" / "settings.json").write_bytes(b"{not json")
        env.antigravity_registered()
        env.register_workspace()
        (env.home / ".aegis" / "workspaces.json").write_bytes(b"{not json")  # the registry is unknown
        env.bootstrap()
        payload, direct = _rows_and_direct_rows(env, monkeypatch)
        _assert_pinned(payload, direct, {
            "codex-cli": {"state": "ok", "reasons": [], "unknown": ["workspace_registered"],
                          "workspace_registered": None, "advisory": True, "enforcement_level": "advisory",
                          "hooks": "absent"},
            "claude-code": {"state": "auth_unknown", "reasons": ["unsafe_registration", "approval_unknown"],
                            "unknown": ["identity", "workspace_registered", "hooks"], "workspace_registered": None,
                            "advisory": True, "enforcement_level": "advisory", "hooks": "unknown"},
            "antigravity": {"state": "auth_unknown", "reasons": ["workspace_registry_unknown"],
                            "unknown": ["workspace_registered"], "workspace_registered": None, "advisory": None,
                            "enforcement_level": "unknown", "hooks": "absent"},
        })
        assert payload["unknown"] == ["codex-cli.workspace_registered", "claude-code.identity",
                                      "claude-code.workspace_registered", "claude-code.hooks",
                                      "antigravity.workspace_registered"]
        assert {Path(c["argv"][0]).stem for c in env.calls} == {"codex"}

    def test_each_state_wins_over_the_lower_codes_beside_it(self, env, monkeypatch):
        env.stub("agy")  # installed, never registered
        env.claude_registered(client="codex-cli")
        (env.ws / "CLAUDE.md").write_bytes(b"# Project notes\n")
        (env.ws / "AGENTS.override.md").write_bytes(b"# local override\n")
        env.register_workspace()
        (env.home / ".aegis" / "workspaces.json").write_bytes(b"{not json")
        env.bootstrap()
        payload, direct = _rows_and_direct_rows(env, monkeypatch)
        _assert_pinned(payload, direct, {
            "codex-cli": {"state": "missing_binary", "reasons": ["missing_binary", "agents_override_shadows_agents_md"],
                          "unknown": ["registration", "workspace_registered"], "workspace_registered": None,
                          "advisory": False, "enforcement_level": "none", "hooks": "absent"},
            "claude-code": {"state": "policy_gap", "reasons": ["identity_mismatch", "claude_md_shadows_agents_md"],
                            "unknown": ["workspace_registered"], "workspace_registered": None, "advisory": True,
                            "enforcement_level": "advisory", "hooks": "absent"},
            "antigravity": {"state": "unregistered", "reasons": ["not_registered", "workspace_registry_unknown"],
                            "unknown": ["workspace_registered"], "workspace_registered": None, "advisory": None,
                            "enforcement_level": "unknown", "hooks": "absent"},
        })
        assert env.calls == []

    def test_outside_a_governed_workspace_an_unreadable_registry_is_unknown_but_no_reason(self, env, monkeypatch,
                                                                                          tmp_path):
        env.all_ok()
        (env.home / ".aegis" / "workspaces.json").write_bytes(b"{not json")
        bare = tmp_path / "bare"
        bare.mkdir()
        monkeypatch.setattr(env, "ws", bare)
        payload, direct = _rows_and_direct_rows(env, monkeypatch)
        ungoverned = {"state": "policy_gap", "reasons": ["workspace_not_governed"], "unknown": ["workspace_registered"],
                      "workspace_registered": None, "advisory": False, "enforcement_level": "none", "hooks": "absent"}
        _assert_pinned(payload, direct, dict.fromkeys(PHASE1, ungoverned))

    def test_a_binary_only_inside_the_workspace_is_unknown_and_never_run(self, env, monkeypatch, tmp_path):
        inside = env.ws / ".local" / "bin"
        marker = tmp_path / "decoy-ran"
        _decoy(inside, "agy", marker)
        monkeypatch.setenv("PATH", os.pathsep.join([str(inside), str(env.bin)]))
        env.register_workspace()
        (env.home / ".aegis" / "workspaces.json").write_bytes(b"{not json")
        env.bootstrap()
        payload, direct = _rows_and_direct_rows(env, monkeypatch)
        missing = {"state": "missing_binary", "reasons": ["missing_binary"],
                   "unknown": ["registration", "workspace_registered"], "workspace_registered": None,
                   "advisory": False, "enforcement_level": "none", "hooks": "absent"}
        _assert_pinned(payload, direct, {
            "codex-cli": missing,
            "claude-code": dict(missing, reasons=["missing_binary", "not_registered"],
                                unknown=["workspace_registered"]),
            "antigravity": {"state": "missing_binary",
                            "reasons": ["binary_in_workspace", "not_registered", "workspace_registry_unknown"],
                            "unknown": ["binary", "workspace_registered"], "workspace_registered": None,
                            "advisory": None, "enforcement_level": "unknown", "hooks": "absent"},
        })
        assert env.calls == [] and not marker.exists()
