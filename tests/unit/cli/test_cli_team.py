"""`aegis team claim|renew|transfer|release|gc|list|metrics` (v4.1 spec §1).

The dispatcher runs these. Text mode prints the new lease oid alone on stdout (so a
script can pass it to ``--expect``); ``--json`` prints one document carrying
``source``, ``aegis_version``, ``checked_at`` and ``scope``. Exit codes: 0 done, 1
refused (taken, overlap, stale, absent, expired, unreadable) or a git error, 2 usage.
``list`` and ``metrics`` are side-effect free. Real temp git repositories throughout.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import List, Optional

import pytest

from aegis_cli.cli import main
from aegis_core import events, team
from aegis_core._version import __version__

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
OID = re.compile(r"\A[0-9a-f]{40}\Z")
NOW = 1_760_000_000
ENVELOPE = ("source", "aegis_version", "checked_at", "scope")
VIEW_KEYS = ["lane", "role", "owner", "claim_id", "gen", "oid", "branch", "paths", "expires_at",
             "clock_basis", "expired", "clock_skew", "overlaps"]


@pytest.mark.parametrize("argv", [
    ["team", "model", "--json"],
    ["--json", "team", "model", "--unknown", "token=private-value"],
    ["--json=token=private-value", "team", "model"],
    ["team", "model", "--bindings", "--json"],
])
def test_model_usage_is_json_exit_two_without_echo(capsys, argv):
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


def test_model_workspace_failure_is_json_exit_two(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AEGIS_WORKSPACE", str(tmp_path / "missing-pin"))
    assert main(["team", "model", "--bindings", "b", "--policy", "p", "--history", "h",
                 "--task-kind", "T9", "--role-kind", "implementer", "--subject", "lane",
                 "--host-kind", "codex-cli", "--workspace", "token=private-value", "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "model_workspace_unavailable"}


def test_model_host_registry_is_bounded_during_argument_parsing(capsys):
    assert main(["team", "model", "--json"] + ["--host-kind", "host"] * 257) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


def test_model_workspace_text_is_bounded_before_resolution(capsys):
    assert main(["team", "model", "--workspace", "x" * 262145, "--bindings", "b", "--policy", "p",
                 "--history", "h", "--task-kind", "T9", "--role-kind", "implementer", "--subject", "lane",
                 "--host-kind", "host", "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


def _model_argv_with_workspace(root, option, location):
    workspace = [option + str(root)] if option.endswith("=") else [option, str(root)]
    prefix = workspace + ["team", "model"] if location == "global" else ["team", *workspace, "model"]
    return prefix + ["--bindings", "bindings.json", "--policy", "policy.json", "--history", "history.jsonl",
                     "--task-kind", "T9", "--role-kind", "implementer", "--subject", "lane-one",
                     "--host-kind", "codex-cli", "--json"]


@pytest.mark.parametrize("option", ["--work", "--worksp", "--workspace=", "--worksp="])
@pytest.mark.parametrize("location", ["global", "team"])
@pytest.mark.parametrize("failure", ["usage", "workspace"])
def test_model_workspace_spellings_keep_fixed_json_errors(tmp_path, monkeypatch, capsys, option, location, failure):
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    argv = _model_argv_with_workspace(root, option, location)
    if failure == "usage":
        argv.extend(["--unknown", "token=private-value"])
        error = "invalid_model_arguments"
    else:
        monkeypatch.setenv("AEGIS_WORKSPACE", str(tmp_path / "missing-pin"))
        error = "model_workspace_unavailable"
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": error}


@pytest.mark.parametrize("location", ["global", "team"])
def test_abbreviated_workspace_operation_failure_is_fixed_json(tmp_path, monkeypatch, capsys, location):
    from types import SimpleNamespace
    from aegis_core import model_select

    if not model_select._DIR_FD_SUPPORTED:
        pytest.skip("requires anchored model-selection I/O")
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    (root / "bindings.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)

    def fail(*args, **kwargs):
        import sys

        print("token=private-value")
        print("token=private-value", file=sys.stderr)
        raise TypeError("token=private-value")

    module_os = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    module_os.open = fail
    monkeypatch.setattr(model_select, "os", module_os)
    assert main(_model_argv_with_workspace(root, "--worksp", location)) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "model_io_unavailable"}


@pytest.mark.parametrize("argv", [
    ["--=token=private-value", "team", "model"],
    ["team", "--=token=private-value", "model"],
    ["team", "model", "--=token=private-value"],
    ["--unknown", "token=private-value", "team", "model"],
    ["team", "--unknown", "token=private-value", "model"],
    ["team", "token=private-value", "model"],
    ["team", "--unknown=token=private-value", "model"],
    ["team", "model", "--unknown", "token=private-value"],
    ["team", "model", "token=private-value"],
], ids=["ambiguous-root", "ambiguous-team", "ambiguous-model", "unknown-value-root",
        "unknown-value-before", "value-before", "unknown-equals-before", "unknown-value-after", "value-after"])
def test_parser_routes_unknown_values_to_model_json_errors(capsys, argv):
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


@pytest.mark.parametrize("argv", [
    ["audit", "team", "model"],
    ["hook", "stop", "team", "model"],
    ["--work", "team", "model"],
    ["--unknown", "token=private-value", "msg", "team", "model"],
])
def test_model_invocation_superset_covers_preparse_refusals(capsys, argv):
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


@pytest.mark.parametrize("option", ["--w", "--wo", "--wor", "--work", "--works", "--worksp",
                                   "--workspa", "--workspac", "--workspace", "--work=",
                                   "--worksp=", "--workspace="])
@pytest.mark.parametrize("name", ["audit", "install", "report", "agent"])
@pytest.mark.parametrize("failure", ["usage", "workspace"])
def test_removed_command_workspace_values_keep_model_json(tmp_path, monkeypatch, capsys, option, name, failure):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    argv = _model_argv_with_workspace(name, option, "global")
    if failure == "usage":
        argv.extend(["--unknown", "token=private-value"])
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    error = "invalid_model_arguments" if failure == "usage" else "model_workspace_unavailable"
    assert json.loads(captured.out) == {"error": error}


@pytest.mark.parametrize("option", ["--w", "--wo", "--wor", "--work", "--works", "--worksp",
                                   "--workspa", "--workspac", "--workspace", "--work=",
                                   "--worksp=", "--workspace="])
def test_root_workspace_values_are_not_removed_commands(capsys, option):
    workspace = [option + "audit"] if option.endswith("=") else [option, "audit"]
    with pytest.raises(SystemExit) as exited:
        main(workspace + ["status", "--help"])
    assert exited.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "usage: aegis status" in captured.out


@pytest.mark.parametrize("option", ["--round-workspace", "--round-work", "--round-work="])
def test_removed_command_scan_uses_the_built_root_option_table(monkeypatch, capsys, option):
    from aegis_cli import cli as cli_module

    build_parser = cli_module._build_parser

    def build(*args, **kwargs):
        parser = build_parser(*args, **kwargs)
        parser.add_argument("--round-workspace")
        return parser

    monkeypatch.setattr(cli_module, "_build_parser", build)
    values = [option + "audit"] if option.endswith("=") else [option, "audit"]
    with pytest.raises(SystemExit) as exited:
        main(values + ["status", "--help"])
    assert exited.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "usage: aegis status" in captured.out


@pytest.mark.parametrize("argv", [
    ["--=token=private-value", "status"],
    ["--unknown", "token=private-value", "status"],
    ["--unknown", "token=private-value", "model", "team"],
    ["--unknown", "token=private-value", "--", "team", "model"],
    ["--unknown", "token=private-value", "team", "--", "model"],
    ["--unknown", "token=private-value", "team=model"],
])
def test_non_model_root_failures_keep_argparse_diagnostics(capsys, argv):
    with pytest.raises(SystemExit) as exited:
        main(argv)
    assert exited.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err
    assert "token=private-value" in captured.err


def test_genuine_removed_audit_command_keeps_its_pointer(capsys):
    assert main(["audit"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "aegis audit was removed in v4: use aegis doctor\n"


@pytest.mark.parametrize("option,expected", [("--help", "Aegis"), ("--version", f"aegis {__version__}")])
def test_non_model_keeps_successful_root_output(capsys, option, expected):
    with pytest.raises(SystemExit) as exited:
        main([option])
    assert exited.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert expected in captured.out


@pytest.mark.parametrize("argv,expected", [
    (["hook", "run"], []),
    # Root help already loads command metadata through the existing registry.
    (["--help"], ["aegis_cli.team", "aegis_core.team_profile"]),
], ids=["hook", "root-help"])
def test_non_model_startup_preserves_baseline_imports(tmp_path, argv, expected):
    import sys

    root = Path(__file__).resolve().parents[3]
    environment = dict(os.environ, PYTHONPATH=str(root))
    environment.pop("AEGIS_WORKSPACE", None)
    script = """import contextlib, io, json, sys
from aegis_cli.cli import main
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    try:
        code = main(json.loads(sys.argv[1]))
    except SystemExit as error:
        code = error.code
assert code == 0, code
print(json.dumps(sorted(sys.modules)))
"""
    result = subprocess.run([sys.executable, "-c", script, json.dumps(argv)], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    modules = json.loads(result.stdout)
    watched = {"aegis_cli.team", "aegis_core.model_select", "aegis_core.team_profile"}
    assert sorted(set(modules) & watched) == expected


@pytest.mark.parametrize("pinned", [False, True])
@pytest.mark.parametrize("argv", [
    ["--work", "team", "--work", "model"],
    ["team", "--work", "model", "--workspace", "token=private-value"],
    ["team", "--work", "model"],
    ["--worksp", "team", "--worksp", "model"],
    ["team", "--worksp", "model", "--workspace=token=private-value"],
    ["team", "--workspace=unused", "--worksp", "model"],
    ["--workspace=unused", "--work", "team", "--worksp", "model"],
    ["--work", "team", "--workspace=model", "model"],
    ["--worksp", "team", "model"],
    ["--work", "team", "status", "--work", "model"],
    ["team", "claim", "docs", "--paths", "docs/**", "--owner", "model"],
    ["--help", "team", "model"],
    ["--version", "team", "model"],
    ["team", "--help", "model"],
    ["team", "model", "--help"],
    ["hook", "run", "team", "model"],
    ["hook", "run", "--host", "team", "model"],
])
def test_raw_model_invocation_has_only_model_json_outcomes(tmp_path, monkeypatch, capsys, argv, pinned):
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.chdir(root)
    if pinned:
        monkeypatch.setenv("AEGIS_WORKSPACE", str(root))
    else:
        monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


def test_outer_model_policy_covers_stdout_setup_failure(monkeypatch, capsys):
    import sys
    from types import SimpleNamespace
    from aegis_cli import cli as cli_module

    def fail(**kwargs):
        print("token=private-value")
        print("token=private-value", file=sys.stderr)
        raise OSError("token=private-value")

    # Replace this module's reference, leaving pytest's process streams intact.
    monkeypatch.setattr(cli_module, "sys", SimpleNamespace(stdout=SimpleNamespace(reconfigure=fail)))
    assert main(["team", "model"]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "model_io_unavailable"}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        cwd=str(repo), check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def ws(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / ".aegis").mkdir()
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    monkeypatch.chdir(root)
    return root.resolve()


def _ref(repo: Path, lane: str) -> Optional[str]:
    proc = subprocess.run(["git", "show-ref", "--verify", "--hash", f"refs/aegis/lanes/{lane}"],
                          cwd=str(repo), capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def _run(capsys, *argv: str):
    rc = main(["team", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _json(capsys, *argv: str):
    rc, out, err = _run(capsys, *argv, "--json")
    return rc, json.loads(out), err


def _envelope(payload: dict, action: str) -> None:
    assert payload["schema"] == f"aegis.team.{action}/v1"
    assert payload["source"] == f"aegis team {action}"
    assert payload["aegis_version"] == __version__
    assert TS.match(payload["checked_at"])
    assert isinstance(payload["scope"], dict)


# ── claim ────────────────────────────────────────────────────────────────────

def test_claim_prints_only_the_new_blob_oid(ws: Path, capsys):
    rc, out, err = _run(capsys, "claim", "docs", "--paths", "docs/**", "README.md", "--owner", "o@h")
    assert rc == 0, err
    assert out == f"{_ref(ws, 'docs')}\n"
    assert OID.match(out.strip())
    lease = team.read_leases(ws).get("docs")
    assert (lease.paths, lease.owner, lease.role, lease.ttl_s, lease.branch) == (
        ("docs/**", "README.md"), "o@h", "implementer", 3600, None)


def test_claim_takes_role_ttl_and_branch(ws: Path, capsys):
    rc, _, err = _run(capsys, "claim", "docs", "--paths", "docs/**", "--role", "reviewer", "--owner", "o@h",
                      "--ttl", "120", "--branch", "lane/docs")
    assert rc == 0, err
    lease = team.read_leases(ws).get("docs")
    assert (lease.role, lease.ttl_s, lease.branch) == ("reviewer", 120, "lane/docs")


def test_claim_json_carries_the_envelope_and_the_lease(ws: Path, capsys):
    rc, payload, _ = _json(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "o@h")
    assert rc == 0
    _envelope(payload, "claim")
    assert payload["scope"] == {"workspace": str(ws), "refs": "refs/aegis/lanes", "lane": "docs"}
    assert (payload["status"], payload["oid"], payload["previous"]) == ("claimed", _ref(ws, "docs"), None)
    assert list(payload["lease"]) == VIEW_KEYS
    assert payload["lease"]["oid"] == payload["oid"]
    assert payload["warnings"] == []


def test_json_is_one_two_space_indented_document(ws: Path, capsys):
    rc, out, _ = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "o@h", "--json")
    assert rc == 0
    assert out == json.dumps(json.loads(out), indent=2) + "\n"


def test_the_json_lease_is_the_lane_s_own_with_its_current_overlaps(ws: Path, capsys):
    _run(capsys, "claim", "api", "--paths", "src/api/**", "--owner", "o@h")
    _, first, _ = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "o@h")
    # Another dispatcher's lease that overlaps docs (written without the overlap check).
    blob = {"v": 1, "lane": "web", "role": "implementer", "owner": "w@h", "claim_id": "0123456789abcdef",
            "gen": 1, "branch": None, "paths": ["docs/web/**"], "ts": int(time.time()), "ttl_s": 600}
    oid = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(ws), input=json.dumps(blob).encode(),
                         capture_output=True, check=True).stdout.decode().strip()
    _git(ws, "update-ref", "refs/aegis/lanes/web", oid)
    rc, payload, _ = _json(capsys, "renew", "docs", "--expect", first.strip())
    assert rc == 0
    assert (payload["lease"]["lane"], payload["lease"]["oid"]) == ("docs", payload["oid"])
    assert payload["lease"]["overlaps"] == ["web"]


def test_events_that_cannot_be_recorded_are_warnings(ws: Path, tmp_path: Path, capsys):
    shared = Path(os.path.realpath(ws / ".git")) / "aegis"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    try:
        os.symlink(str(elsewhere), str(shared), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    team.claim(ws, "old", ["old/**"], owner="o@h", ttl_s=60, now=NOW)
    rc, out, err = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "o@h")
    assert (rc, out) == (0, f"{_ref(ws, 'docs')}\n")
    assert err.startswith("Warning: event not recorded: ")
    rc, payload, _ = _json(capsys, "claim", "web", "--paths", "web/**", "--owner", "o@h")
    assert rc == 0 and payload["warnings"][0].startswith("event not recorded: ")
    rc, _, err = _run(capsys, "claim", "core", "--paths", "docs/core/**", "--owner", "o@h")
    assert rc == 1
    assert err.startswith("Warning: event not recorded: ") and "overlap: lane core" in err
    rc, out, err = _run(capsys, "gc")
    assert (rc, out) == (0, "collected old\n")
    assert err.startswith("Warning: event not recorded: ")


def test_a_taken_lane_exits_1_and_prints_the_holding_lease(ws: Path, capsys):
    _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "holder@box")
    held = _ref(ws, "docs")
    rc, out, err = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "late@box")
    assert (rc, out) == (1, "")
    assert "taken: lane docs is leased" in err
    assert held in err and "holder@box" in err and "docs/**" in err
    rc, payload, _ = _json(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "late@box")
    assert rc == 1
    _envelope(payload, "claim")
    assert (payload["status"], payload["reason"], payload["current"]) == ("refused", "taken", held)
    assert payload["lease"]["owner"] == "holder@box" and list(payload["lease"]) == VIEW_KEYS
    assert _ref(ws, "docs") == held


def test_an_overlapping_claim_exits_1_naming_the_lanes(ws: Path, capsys):
    _run(capsys, "claim", "api", "--paths", "src/**", "--owner", "o@h")
    rc, out, err = _run(capsys, "claim", "core", "--paths", "src/core/**", "--owner", "o@h")
    assert (rc, out) == (1, "")
    assert "overlap: lane core may overlap live lease(s) of api" in err
    rc, payload, _ = _json(capsys, "claim", "core", "--paths", "src/core/**", "--owner", "o@h")
    assert (rc, payload["status"], payload["reason"], payload["lanes"]) == (1, "refused", "overlap", ["api"])
    assert _ref(ws, "core") is None


@pytest.mark.parametrize("argv, message", [
    (["claim", "Docs", "--paths", "docs/**"], "invalid lane name"),
    (["claim", "docs", "--paths", ""], "paths: glob 1 is empty"),
    (["claim", "docs", "--paths", "docs/**", "--ttl", "86401"], "ttl must be a whole number of seconds from 1 to 86400"),
    (["claim", "docs", "--paths", "docs/**", "--ttl", "0"], "ttl must be"),
    (["renew", "docs", "--expect", "abc"], "--expect must be a full object id"),
    (["metrics", "--base", "nope"], "cannot resolve --base 'nope' to a commit"),
])
def test_usage_errors_exit_2(ws: Path, capsys, argv: List[str], message: str):
    rc, out, err = _run(capsys, *argv)
    assert (rc, out) == (2, "")
    assert err.startswith("Error: ") and message in err
    rc, payload, _ = _json(capsys, *argv)
    assert rc == 2
    _envelope(payload, argv[0])
    assert payload["status"] == "error" and message in payload["error"]


def test_argparse_refuses_a_non_numeric_ttl(ws: Path, capsys):
    with pytest.raises(SystemExit) as info:
        main(["team", "claim", "docs", "--paths", "docs/**", "--ttl", "soon"])
    assert info.value.code == 2


@pytest.mark.parametrize("argv, missing", [
    (["claim", "docs"], "--paths"),
    (["renew", "docs"], "--expect"),
    (["transfer", "docs", "--owner", "b@h"], "--expect"),
    (["transfer", "docs", "--expect", "a" * 40], "--owner"),
    (["release", "docs"], "--expect"),
    (["claim", "--paths", "docs/**"], "LANE"),
])
def test_required_arguments_are_enforced_by_the_parser(ws: Path, capsys, argv: List[str], missing: str):
    with pytest.raises(SystemExit) as info:
        main(["team", *argv])
    assert info.value.code == 2
    assert "the following arguments are required: " + missing in capsys.readouterr().err


def test_outside_a_git_repository_team_is_a_usage_error(tmp_path: Path, monkeypatch, capsys):
    root = tmp_path / "plain"
    (root / ".aegis").mkdir(parents=True)
    monkeypatch.chdir(root)
    rc, out, err = _run(capsys, "list")
    assert (rc, out) == (2, "")
    assert "not in a git repository: aegis team keeps leases in git refs" in err


def test_no_action_prints_usage_and_exits_2(ws: Path, capsys):
    rc, out, err = _run(capsys)
    assert (rc, out) == (2, "")
    assert err == ("usage: aegis team {claim,renew,transfer,release,gc,list,status,metrics} ...\n"
                   "aegis team --help describes each action.\n")


def test_help_says_a_lease_is_not_a_lock(ws: Path, capsys):
    with pytest.raises(SystemExit):
        main(["team", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "not a lock" in out
    for action in ("claim", "renew", "transfer", "release", "gc", "list", "metrics"):
        assert action in out


# ── renew, transfer, release, gc ─────────────────────────────────────────────

def test_renew_transfer_and_release_chain_through_expect(ws: Path, capsys):
    _, first, _ = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "a@h", "--ttl", "600")
    rc, renewed, err = _run(capsys, "renew", "docs", "--expect", first.strip(), "--ttl", "900")
    assert rc == 0, err
    assert renewed == f"{_ref(ws, 'docs')}\n" and renewed != first
    assert team.read_leases(ws).get("docs").ttl_s == 900
    rc, moved, err = _run(capsys, "transfer", "docs", "--expect", renewed.strip(), "--owner", "b@h", "--role", "reviewer")
    assert rc == 0, err
    lease = team.read_leases(ws).get("docs")
    assert (lease.owner, lease.role, lease.gen, lease.oid) == ("b@h", "reviewer", 3, moved.strip())
    rc, out, err = _run(capsys, "release", "docs", "--expect", moved.strip())
    assert (rc, out) == (0, "released docs\n")
    assert _ref(ws, "docs") is None


def test_a_stale_expectation_exits_1_and_names_the_current_oid(ws: Path, capsys):
    _, first, _ = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "a@h")
    _, second, _ = _run(capsys, "renew", "docs", "--expect", first.strip())
    for argv in (["renew", "docs", "--expect", first.strip()],
                 ["transfer", "docs", "--expect", first.strip(), "--owner", "b@h"],
                 ["release", "docs", "--expect", first.strip()]):
        rc, out, err = _run(capsys, *argv)
        assert (rc, out) == (1, "")
        assert f"stale: lane docs holds {second.strip()}" in err
    assert _ref(ws, "docs") == second.strip()


def test_release_json_names_the_caller(ws: Path, capsys, monkeypatch):
    monkeypatch.setenv("LOGNAME", "human")
    _, first, _ = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "agent@box")
    rc, payload, _ = _json(capsys, "release", "docs", "--expect", first.strip())
    assert rc == 0
    _envelope(payload, "release")
    assert (payload["status"], payload["previous"], payload["oid"]) == ("released", first.strip(), None)
    assert payload["caller"].startswith("human@")


def test_absent_and_expired_refusals(ws: Path, capsys):
    rc, _, err = _run(capsys, "release", "docs", "--expect", "a" * 40)
    assert rc == 1 and "absent: lane docs has no lease" in err
    old = team.claim(ws, "docs", ["docs/**"], owner="a@h", ttl_s=60, now=NOW)
    rc, _, err = _run(capsys, "transfer", "docs", "--expect", old.oid, "--owner", "b@h")
    assert rc == 1 and "expired: lane docs" in err


def test_gc_collects_expired_leases(ws: Path, capsys):
    team.claim(ws, "docs", ["docs/**"], owner="a@h", ttl_s=60, now=NOW)
    _run(capsys, "claim", "web", "--paths", "web/**", "--owner", "b@h")
    rc, out, err = _run(capsys, "gc")
    assert (rc, out) == (0, "collected docs\n"), err
    assert _ref(ws, "docs") is None and _ref(ws, "web") is not None
    rc, payload, _ = _json(capsys, "gc")
    assert rc == 0
    _envelope(payload, "gc")
    assert (payload["collected"], payload["kept"]) == ([], [])
    rc, out, _ = _run(capsys, "gc")
    assert (rc, out) == (0, "nothing to collect\n")
    junk = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(ws), input=b"junk",
                          capture_output=True, check=True).stdout.decode().strip()
    _git(ws, "update-ref", "refs/aegis/lanes/junk", junk)
    rc, out, err = _run(capsys, "gc")
    assert (rc, out, err) == (0, "nothing to collect\n", "kept junk: unreadable\n")
    rc, payload, _ = _json(capsys, "gc")
    assert payload["kept"] == [{"lane": "junk", "reason": "unreadable"}]


# ── list ─────────────────────────────────────────────────────────────────────

def test_list_json_reports_every_plan_field_and_the_statement(ws: Path, capsys):
    team.claim(ws, "docs", ["docs/**"], owner="a@h", ttl_s=600, branch="lane/docs")
    team.claim(ws, "web", ["web/**"], owner="b@h")
    rc, payload, _ = _json(capsys, "list")
    assert rc == 0
    _envelope(payload, "list")
    assert payload["scope"] == {"workspace": str(ws), "refs": "refs/aegis/lanes"}
    assert payload["note"] == team.LEASE_NOTE
    assert "conflict input, not liveness proof" in payload["note"]
    assert [entry["lane"] for entry in payload["leases"]] == ["docs", "web"]
    assert all(list(entry) == VIEW_KEYS for entry in payload["leases"])
    assert payload["unreadable"] == []


def test_list_text_states_what_a_lease_is(ws: Path, capsys):
    team.claim(ws, "old", ["old/**"], owner="b@h", ttl_s=60, now=NOW)  # expired long ago
    team.claim(ws, "docs", ["docs/**", "README.md"], owner="a@h")
    blob = {"v": 1, "lane": "web", "role": "implementer", "owner": "w@h", "claim_id": "0123456789abcdef",
            "gen": 1, "branch": "lane/web", "paths": ["docs/web/**"], "ts": int(time.time()), "ttl_s": 600}
    oid = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(ws), input=json.dumps(blob).encode(),
                         capture_output=True, check=True).stdout.decode().strip()
    _git(ws, "update-ref", "refs/aegis/lanes/web", oid)
    _git(ws, "update-ref", "refs/aegis/lanes/zzz", oid)  # names lane web: unreadable as zzz
    rc, out, _ = _run(capsys, "list")
    assert rc == 0
    assert out.startswith("Leases under refs/aegis/lanes (checked ")
    assert "There are no leases" not in out
    assert out.endswith(team.LEASE_NOTE + "\n")
    assert re.search(r"^  docs  live  owner a@h  role implementer  gen 1  expires \S+Z$", out, re.M)
    assert "    overlaps live: web\n" in out
    assert f"    oid: {oid}  branch: lane/web\n" in out
    assert f"  zzz  unreadable  oid {oid}: the blob names a different lane\n" in out
    assert re.search(r"^  old  expired  owner b@h", out, re.M)
    assert "    paths: docs/**, README.md" in out


def test_list_text_with_only_an_unreadable_ref_lists_it(ws: Path, capsys):
    junk = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(ws), input=b"junk",
                          capture_output=True, check=True).stdout.decode().strip()
    _git(ws, "update-ref", "refs/aegis/lanes/junk", junk)
    rc, out, _ = _run(capsys, "list")
    assert rc == 0
    assert out.startswith("Leases under refs/aegis/lanes (checked ")
    assert f"\n  junk  unreadable  oid {junk}: not a JSON lease\n" in out


def test_list_of_no_leases(ws: Path, capsys):
    rc, out, _ = _run(capsys, "list")
    assert (rc, out) == (0, f"There are no leases under refs/aegis/lanes.\n{team.LEASE_NOTE}\n")


def test_list_and_metrics_are_side_effect_free(ws: Path, capsys):
    team.claim(ws, "docs", ["docs/**"], owner="a@h", ttl_s=60, now=NOW)
    shared = Path(os.path.realpath(ws / ".git")) / "aegis"
    shutil.rmtree(str(shared))
    before = _git(ws, "for-each-ref", "refs/aegis")
    for argv in (["list"], ["list", "--json"], ["metrics"], ["metrics", "--json"]):
        rc, _, err = _run(capsys, *argv)
        assert rc == 0, err
    assert _git(ws, "for-each-ref", "refs/aegis") == before
    assert not shared.exists()


# ── metrics ──────────────────────────────────────────────────────────────────

def test_metrics_json_reports_events_and_merges(ws: Path, capsys):
    _git(ws, "checkout", "-q", "-b", "feature")
    _git(ws, "checkout", "-q", "-b", "lane/a")
    (ws / "x.txt").write_text("x\n", encoding="utf-8")
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "x")
    _git(ws, "checkout", "-q", "feature")
    _git(ws, "merge", "--no-ff", "-q", "-m", "merge(lane/a)", "lane/a")
    _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "a@h")
    _run(capsys, "claim", "web", "--paths", "docs/web/**", "--owner", "a@h")
    rc, payload, err = _json(capsys, "metrics", "--base", "main")
    assert rc == 0, err
    _envelope(payload, "metrics")
    head = _git(ws, "rev-parse", "HEAD")
    assert payload["scope"] == {"workspace": str(ws), "base": "main", "base_commit": _git(ws, "rev-parse", "main"),
                                "head": head, "tip": head, "synthetic_head": False}
    assert (payload["events"]["claims"], payload["events"]["denials"]) == (1, 1)
    assert payload["events"]["denials_by_reason"] == {"overlap": 1}
    merges = payload["merges"]
    assert (merges["count"], merges["overlapping_merge"], merges["excluded_synthetic"]) == (1, 0, 0)
    assert merges["conflicting_merge"] in (0, "unavailable")
    assert [m["commit"] for m in merges["merges"]] == [head]


def test_metrics_text_names_both_measures(ws: Path, capsys):
    head = _git(ws, "rev-parse", "HEAD")
    rc, out, _ = _run(capsys, "metrics", "--base", "main")
    assert rc == 0
    assert out == (
        "Lease events: 0 claims, 0 denials; 0 lanes claimed\n"
        f"First-parent merges on {head[:12]} since main: 0\n"
        "  overlapping (both sides changed a common path): 0\n"
        "  conflicting (git merge-tree): 0\n"
    )


def test_metrics_text_reports_denials_by_reason_and_an_unreadable_log(ws: Path, capsys):
    _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "a@h")
    _run(capsys, "claim", "web", "--paths", "docs/web/**", "--owner", "a@h")
    rc, out, _ = _run(capsys, "metrics", "--base", "main")
    assert out.startswith("Lease events: 1 claims, 1 denials (overlap 1); 1 lanes claimed\n")
    log = events.events_path(ws)
    log.unlink()
    log.mkdir()
    rc, out, _ = _run(capsys, "metrics", "--base", "main")
    assert rc == 0
    assert "\n  events log unreadable: cannot read " in out


def test_metrics_text_before_git_2_38_says_unavailable(ws: Path, capsys, monkeypatch):
    from aegis_core import gitsafe

    _git(ws, "checkout", "-q", "-b", "lane/a")
    (ws / "x.txt").write_text("x\n", encoding="utf-8")
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "x")
    _git(ws, "checkout", "-q", "-b", "feature", "main")
    _git(ws, "merge", "--no-ff", "-q", "-m", "merge(lane/a)", "lane/a")
    monkeypatch.setattr(gitsafe, "git_version", lambda cwd: (2, 37, 0))
    rc, out, _ = _run(capsys, "metrics", "--base", "main")
    assert rc == 0
    assert "\n  conflicting (git merge-tree): unavailable (git merge-tree --write-tree needs git 2.38" in out


def test_metrics_text_counts_an_excluded_synthetic_merge(ws: Path, capsys):
    _git(ws, "checkout", "-q", "-b", "feature")
    (ws / "f.txt").write_text("f\n", encoding="utf-8")
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "f")
    tip = _git(ws, "rev-parse", "HEAD")
    tree = _git(ws, "rev-parse", "HEAD^{tree}")
    synthetic = _git(ws, "commit-tree", tree, "-p", "main", "-p", "feature", "-m", "Merge pull request")
    _git(ws, "update-ref", "refs/remotes/pull/3/merge", synthetic)
    _git(ws, "checkout", "-q", "--detach", synthetic)
    rc, out, _ = _run(capsys, "metrics", "--base", "main")
    assert rc == 0
    assert f"First-parent merges on {tip[:12]} since main: 0\n" in out
    assert out.endswith("  excluded synthetic pull-request merges: 1\n")
