"""`aegis team claim|renew|transfer|release|gc|list|metrics` (v4.1 spec §1).

The dispatcher runs these. Text mode prints the new lease oid alone on stdout (so a
script can pass it to ``--expect``); ``--json`` prints one document carrying
``source``, ``aegis_version``, ``checked_at`` and ``scope``. Exit codes: 0 done, 1
refused (CLAIM_REFUSALS, including legacy_paths) or a git error, 2 usage.
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
from aegis_core import events, team, team_queue, team_lease_custody
from aegis_core import gitsafe as rendering_git
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


# ── branch bytes on the public claim commands ───────────────────────────────

_BRANCH_REASON = "branch must be 1 to 200 characters with no spaces or control characters"
_SURROGATE_BYTES = b"feature/\xffmarker".decode("utf-8", "surrogateescape")
_CLI_BRANCHES = [
    ("feature/bytes", True, False),
    ("feature/\u00fc", True, False),
    ("feature/\ud800marker", False, True),
    (_SURROGATE_BYTES, False, True),
    ("", False, False),
    ("x" * 201, False, False),
    ("feature/a\nb", False, False),
]
_CLI_BRANCH_IDS = ["ascii", "utf8", "lone-surrogate", "surrogateescape", "empty", "over-length", "embedded-newline"]


def _skip_posix_argv(posix_only: bool) -> None:
    if posix_only and os.name == "nt":
        pytest.skip("Windows argv cannot carry surrogate-escaped non-UTF-8 bytes")


def _prepare_queue(ws: Path, tmp_path: Path) -> None:
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    (ws / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"docs": ["docs/**"]}}), encoding="utf-8")
    home = tmp_path / "queue-home"
    home.mkdir(exist_ok=True)
    # The autouse hermetic_environment_and_mcp_isolation fixture restores this.
    os.environ.update({"HOME": str(home), "USERPROFILE": str(home)})


def _queue_json(capsys, root: Path, *argv: str):
    rc = main(["--workspace", str(root), "team", "queue", *argv, "--json"])
    captured = capsys.readouterr()
    assert captured.err == ""
    return rc, json.loads(captured.out)


@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("branch,accepted,posix_only", _CLI_BRANCHES, ids=_CLI_BRANCH_IDS)
def test_cli_claim_branch_matrix(ws: Path, capsys, mode, branch, accepted, posix_only):
    _skip_posix_argv(posix_only)
    argv = ["claim", "docs", "--paths", "docs/**", "--owner", "o@h", "--branch", branch]
    if mode == "json":
        rc, payload, err = _json(capsys, *argv)
        if accepted:
            assert rc == 0 and err == ""
            assert payload["lease"]["branch"] == branch
            assert team.read_leases(ws).get("docs").branch == branch
            return
        assert rc == 2 and err == ""
        assert payload["status"] == "error" and payload["error"] == _BRANCH_REASON
        assert "marker" not in json.dumps(payload)
    else:
        rc, out, err = _run(capsys, *argv)
        if accepted:
            assert rc == 0, err
            assert out == f"{_ref(ws, 'docs')}\n"
            assert team.read_leases(ws).get("docs").branch == branch
            return
        assert rc == 2 and out == ""
        assert err == f"Error: {_BRANCH_REASON}\n"
        assert "marker" not in err
    assert _ref(ws, "docs") is None
    rc, out, err = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "o@h", "--branch", "feature/retry")
    assert rc == 0, err
    assert team.read_leases(ws).get("docs").branch == "feature/retry"


@pytest.mark.parametrize("branch,accepted,posix_only", _CLI_BRANCHES, ids=_CLI_BRANCH_IDS)
def test_cli_queue_claim_branch_matrix(ws: Path, tmp_path: Path, capsys, branch, accepted, posix_only):
    _skip_posix_argv(posix_only)
    if not accepted and not team_queue.descriptor_supported():
        rc, payload = _queue_json(capsys, ws, "claim", "ONE", "--expect", "0" * 64, "--lane", "docs",
                                  "--capability", "core", "--branch", branch)
        assert rc == 2 and payload["reason"] == "invalid_arguments" and payload["exit_code"] == 2
        assert payload["next_action"] == "Use the documented queue arguments and the revision returned by list."
        assert "marker" not in json.dumps(payload)
        assert not (ws / ".aegis" / "state" / "team-queue.json").exists()
        return
    _prepare_queue(ws, tmp_path)
    item = json.dumps({"id": "ONE", "title": "Queue work", "paths": ["docs/**"], "capabilities": ["core"]})
    rc, added = _queue_json(capsys, ws, "add", "--item", item)
    assert rc == 0, added
    revision = added["item"]["revision"]
    path = ws / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    rc, payload = _queue_json(capsys, ws, "claim", "ONE", "--expect", revision, "--lane", "docs",
                              "--capability", "core", "--branch", branch)
    if accepted:
        assert rc == 0 and payload["refused"] is False, payload
        assert payload["item"]["branch"] == branch
        return
    assert rc == 2 and payload["reason"] == "invalid_arguments" and payload["exit_code"] == 2
    assert payload["next_action"] == "Use the documented queue arguments and the revision returned by list."
    assert "marker" not in json.dumps(payload)
    assert path.read_bytes() == before
    rc, retried = _queue_json(capsys, ws, "claim", "ONE", "--expect", revision, "--lane", "docs",
                              "--capability", "core", "--branch", "feature/retry")
    assert rc == 0 and retried["item"]["branch"] == "feature/retry"


@pytest.mark.parametrize("branch", ["feature/\ud800marker", _SURROGATE_BYTES], ids=["lone-surrogate", "surrogateescape"])
def test_cli_list_of_stored_surrogate_branch_does_not_crash(ws: Path, capsys, branch):
    blob = {"v": 1, "lane": "docs", "role": "implementer", "owner": "o@h", "claim_id": "0123456789abcdef",
            "gen": 1, "branch": branch, "paths": ["docs/**"], "ts": NOW, "ttl_s": 600}
    raw = (json.dumps(blob, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    oid = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(ws), input=raw,
                         capture_output=True, check=True).stdout.decode().strip()
    _git(ws, "update-ref", "refs/aegis/lanes/docs", oid)
    rc, out, err = _run(capsys, "list")
    assert rc == 0 and err == ""
    assert "unreadable" in out and "marker" not in out
    rc, payload, err = _json(capsys, "list")
    assert rc == 0 and err == ""
    assert payload["leases"] == []
    assert payload["unreadable"][0]["lane"] == "docs"
    assert payload["unreadable"][0]["oid"] == oid
    assert "marker" not in json.dumps(payload)


@pytest.mark.parametrize("branch", ["feature/\ud800marker", _SURROGATE_BYTES], ids=["lone-surrogate", "surrogateescape"])
def test_cli_queue_audit_of_stored_surrogate_branch_stays_unsupported(ws: Path, tmp_path: Path, capsys, branch):
    _prepare_queue(ws, tmp_path)
    item = json.dumps({"id": "ONE", "title": "Queue work", "paths": ["docs/**"], "capabilities": ["core"]})
    rc, added = _queue_json(capsys, ws, "add", "--item", item)
    assert rc == 0, added
    rc, claimed = _queue_json(capsys, ws, "claim", "ONE", "--expect", added["item"]["revision"],
                              "--lane", "docs", "--capability", "core", "--branch", "feature/ok")
    assert rc == 0, claimed
    assert team.claim(ws, "docs", ["docs/**"], owner="owner", branch="lane/docs").lease.branch == "lane/docs"
    path = ws / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["items"]["ONE"]["branch"] = branch
    planted = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    path.write_bytes(planted)
    rc, audited = _queue_json(capsys, ws, "audit")
    assert rc == 0 and audited["refused"] is False
    assert [row["code"] for row in audited["findings"]] == ["CLAIM-BRANCH-UNSUPPORTED"]
    assert "marker" not in json.dumps(audited["findings"])
    assert path.read_bytes() == planted
    rc, listed = _queue_json(capsys, ws, "list")
    assert rc == 0 and listed["items"][0]["branch_supported"] is False
    assert listed["items"][0]["branch"] == branch


@pytest.mark.parametrize("action", ["renew", "gc"])
def test_lease_liveness_uses_metadata_scratch_without_descriptor_support(ws, capsys, monkeypatch, action):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from aegis_core import gitsafe

    old = team.claim(ws, "docs", ["docs/**"], owner="owner", branch="main", ttl_s=60,
                     now=int(time.time()) - 100)
    common = gitsafe.common_dir(ws)
    seen = []
    limits = []
    original = gitsafe.custody

    @contextmanager
    def capture(**kwargs):
        seen.append(Path(kwargs["scratch"]))
        limits.append((kwargs["stdout_limit"], kwargs["stderr_limit"]))
        with original(**kwargs):
            yield

    monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    monkeypatch.setattr(team_lease_custody, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "custody": capture}))
    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    rc, payload, err = _json(capsys, *args)
    assert (rc, payload["status"], err) == (0, "renewed" if action == "renew" else "collected", "")
    assert seen[0] == Path(ws.anchor)  # No-stdin discovery never opens this bootstrap scratch.
    assert limits[0] == (65536, 65536)
    assert seen[1:] and all(path == common / "aegis-lease-scratch" for path in seen[1:])
    assert seen[1].is_dir() and list(seen[1].iterdir()) == []


def test_lease_custody_is_absent_from_ordinary_team_import():
    import sys

    source = Path(__file__).resolve().parents[3]
    result = subprocess.run([sys.executable, "-I", "-c", (
        "import sys; sys.path.insert(0,sys.argv[1]); from aegis_core import team; "
        "assert 'aegis_core.team_lease_custody' not in sys.modules"), str(source)],
        capture_output=True, text=True, timeout=30)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


def test_lease_descriptor_probe_requires_parent_addressable_fds(monkeypatch):
    from types import SimpleNamespace
    from tests.unit.core.test_storage_confined import ModuleOS

    path = SimpleNamespace(**{**vars(os.path), "isdir": lambda value: value == "/dev/fd"})
    monkeypatch.setattr(team_lease_custody, "os", ModuleOS(path=path))
    monkeypatch.setattr(team_lease_custody, "storage_confined", SimpleNamespace(descriptor_supported=lambda: True))
    assert team_lease_custody.descriptor_supported() is False


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("backend", ["descriptor", "pathname"])
@pytest.mark.parametrize("kind", ["worktree", "bare", "configured_worktree"])
def test_nested_workspace_lease_mutations_keep_the_workspace_identity(ws, capsys, monkeypatch, action, backend, kind):
    if backend == "descriptor" and not team_lease_custody.descriptor_supported():
        pytest.skip("requires parent-addressable lease descriptors")
    if backend == "pathname":
        monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    repository = ws
    common = ws / ".git"
    if kind == "bare":
        repository = ws.parent / "bare.git"
        _git(ws, "clone", "-q", "--bare", "--no-hardlinks", str(ws), str(repository))
        common = repository
    elif kind == "configured_worktree":
        checkout = ws.parent / "configured-checkout"
        checkout.mkdir()
        _git(ws, "config", "core.worktree", str(checkout))
    nested = repository / "packages" / "app"
    (nested / ".aegis" / "rules").mkdir(parents=True)
    base = ["--workspace", str(nested), "team"]
    assert main([*base, "claim", "docs", "--paths", "docs/**", "--owner", "o@h",
                 "--branch", "main", "--json"]) == 0
    claimed = json.loads(capsys.readouterr().out)
    oid = claimed["oid"]
    if action == "gc":
        team.release(nested, "docs", oid)
        oid = team.claim(nested, "docs", ["docs/**"], owner="o@h", branch="main", ttl_s=60,
                         now=int(time.time()) - 100).oid
    for _ in range(2):
        args = ["renew", "docs", "--expect", oid] if action == "renew" else ["gc"]
        code = main([*base, *args, "--json"])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert (code, captured.err, payload["scope"]["workspace"]) == (0, "", str(nested))
        if action == "renew":
            assert payload["status"] == "renewed" and payload["oid"] != oid
            oid = payload["oid"]
            assert _ref(repository, "docs") == oid
        else:
            assert _ref(repository, "docs") is None
    assert not (nested / ".git").exists()
    assert not (nested / "aegis-lease-scratch").exists()
    assert (common / "aegis-lease-scratch").is_dir()


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("backend", ["descriptor", "pathname"])
def test_nested_workspace_replacement_during_discovery_refuses_and_retries(
        ws, capsys, monkeypatch, action, backend):
    from types import SimpleNamespace
    from aegis_core import gitsafe

    if backend == "descriptor" and not team_lease_custody.descriptor_supported():
        pytest.skip("requires parent-addressable lease descriptors")
    if backend == "pathname":
        monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    nested, moved, discarded = (ws / name for name in ("nested", "held-nested", "replacement"))
    (nested / ".aegis" / "rules").mkdir(parents=True)
    old = team.claim(nested, "docs", ["docs/**"], owner="o@h", branch="main", ttl_s=60,
                     now=int(time.time()) - 100)
    original = gitsafe.run
    changed = []

    def discover(argv, cwd, **kwargs):
        result = original(argv, cwd, **kwargs)
        if "--show-toplevel" in argv and not changed:
            assert kwargs["stdin"] is None
            nested.rename(moved)
            (nested / ".aegis" / "rules").mkdir(parents=True)
            changed.append(True)
        return result

    monkeypatch.setattr(team_lease_custody, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": discover}))
    args = ["renew", "docs", "--expect", old.oid] if action == "renew" else ["gc"]
    try:
        code = main(["--workspace", str(nested), "team", *args, "--json"])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert (code, payload["reason"], payload["message"], captured.err) == (
            1, "liveness_unknown", "liveness_unknown", "")
        assert changed and _ref(ws, "docs") == old.oid
    finally:
        if changed:
            nested.rename(discarded)
            moved.rename(nested)
    assert main(["--workspace", str(nested), "team", *args, "--json"]) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("backend", ["descriptor", "pathname"])
@pytest.mark.parametrize("failure", ["timeout", "oversized", "relative", "multiline"])
def test_lease_repository_discovery_refuses_bad_evidence_and_retries(
        ws, capsys, monkeypatch, backend, failure):
    from types import SimpleNamespace
    from aegis_core import gitsafe

    if backend == "descriptor" and not team_lease_custody.descriptor_supported():
        pytest.skip("requires parent-addressable lease descriptors")
    if backend == "pathname":
        monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    old = team.claim(ws, "docs", ["docs/**"], owner="o@h", branch="main")
    original = gitsafe.run

    def discover(argv, cwd, **kwargs):
        if "--show-toplevel" not in argv:
            return original(argv, cwd, **kwargs)
        assert kwargs["stdin"] is None
        if failure == "timeout":
            raise gitsafe.GitError("private-discovery-marker", code="git_timeout")
        result = original(argv, cwd, **kwargs)
        fields = result.stdout.splitlines()
        fields[0] = {"oversized": b"/" + b"x" * 16384, "relative": b"relative",
                     "multiline": b"/private-discovery-marker\n/another"}[failure]
        return subprocess.CompletedProcess(argv, 0, b"\n".join(fields) + b"\n", b"")

    monkeypatch.setattr(team_lease_custody, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": discover}))
    for _ in range(2):
        code, payload, err = _json(capsys, "renew", "docs", "--expect", old.oid)
        assert (code, payload["reason"], payload["message"], err) == (
            1, "liveness_unknown", "liveness_unknown", "")
        assert _ref(ws, "docs") == old.oid
    monkeypatch.setattr(team_lease_custody, "gitsafe", gitsafe)
    assert _json(capsys, "renew", "docs", "--expect", old.oid)[0] == 0


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("bad", ["file", "symlink", "owner", "mode"])
def test_pathname_lease_scratch_refuses_bad_entries_and_retries(ws, capsys, monkeypatch, action, bad):
    from types import SimpleNamespace
    from conftest import symlink_or_skip
    from tests.unit.core.test_storage_confined import ModuleOS

    if bad == "mode" and os.name != "posix":
        pytest.skip("POSIX permission modes are unavailable")
    if bad == "owner" and not hasattr(os, "geteuid"):
        pytest.skip("numeric owner identity is unavailable")
    monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    old = team.claim(ws, "docs", ["docs/**"], owner="o@h", branch="main", ttl_s=60,
                     now=int(time.time()) - 100)
    scratch, outside = ws / ".git" / "aegis-lease-scratch", ws.parent / "outside"
    outside.mkdir()
    if bad == "file":
        scratch.write_bytes(b"private-scratch-marker")
    elif bad == "symlink":
        symlink_or_skip(outside, scratch, target_is_directory=True)
    else:
        scratch.mkdir(mode=0o700)
        if bad == "mode":
            scratch.chmod(0o755)

    def info(path, **kwargs):
        result = os.stat(path, **kwargs)
        if bad == "owner" and os.fspath(path) == str(scratch):
            return SimpleNamespace(st_dev=result.st_dev, st_ino=result.st_ino,
                                   st_mode=result.st_mode, st_uid=result.st_uid + 1)
        return result

    monkeypatch.setattr(team_lease_custody, "os", ModuleOS(stat=info))
    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    for _ in range(2):
        code, payload, err = _json(capsys, *args)
        assert (code, payload["reason"], payload["message"], err) == (
            1, "liveness_unknown", "liveness_unknown", "")
        assert _ref(ws, "docs") == old.oid
    monkeypatch.setattr(team_lease_custody, "os", os)
    assert list(outside.iterdir()) == []
    if bad in ("file", "symlink"):
        scratch.unlink()
    else:
        scratch.chmod(0o700)
    assert _json(capsys, *args)[0] == 0


@pytest.mark.parametrize("action", ["renew", "gc"])
def test_pathname_repository_identity_change_refuses_and_retries(ws, capsys, monkeypatch, action):
    from aegis_core import gitsafe

    monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    other = ws.parent / "other-repository"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    _git(other, "commit", "--allow-empty", "-q", "-m", "other")
    old = team.claim(ws, "docs", ["docs/**"], owner="o@h", branch="main", ttl_s=60,
                     now=int(time.time()) - 100)
    data = gitsafe.read_object(ws, old.oid, team.MAX_LEASE_BYTES)
    oid = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(other), input=data,
                         capture_output=True, check=True).stdout.decode().strip()
    assert oid == old.oid
    _git(other, "update-ref", team.lane_ref("docs"), oid)
    original = team.lease_branch_evidence
    held = ws.parent / "held.git"
    changed = []

    def preflight(*args, **kwargs):
        result = original(*args, **kwargs)
        (ws / ".git").rename(held)
        (other / ".git").rename(ws / ".git")
        changed.append(True)
        return result

    monkeypatch.setattr(team, "lease_branch_evidence", preflight)
    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    try:
        code, payload, err = _json(capsys, *args)
        assert (code, payload["reason"], payload["message"], err) == (
            1, "liveness_unknown", "liveness_unknown", "")
    finally:
        if changed:
            (ws / ".git").rename(other / ".git")
            held.rename(ws / ".git")
    monkeypatch.setattr(team, "lease_branch_evidence", original)
    assert _ref(ws, "docs") == _ref(other, "docs") == old.oid
    assert _json(capsys, *args)[0] == 0
    assert _ref(other, "docs") == old.oid


# ── lease refusal reasons are one source with the core ───────────────────────

_LEGACY_SECRET = "docs/token=secret src/**"


def _core_lease_reasons():
    """Every LeaseRefused reason literal in the core, the one refusal set."""
    import ast

    root = Path(__file__).resolve().parents[3] / "aegis_core"
    reasons = set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name != "LeaseRefused":
                continue
            reason = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                if isinstance(node.args[1].value, str):
                    reason = node.args[1].value
            for keyword in node.keywords:
                if keyword.arg == "reason" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        reason = keyword.value.value
            if reason is None:
                raise AssertionError(f"LeaseRefused reason is not a literal at {path}:{node.lineno}")
            reasons.add(reason)
    return reasons


def _plant_blob(repo: Path, lane: str, payload) -> str:
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    oid = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(repo), input=raw,
                         capture_output=True, check=True).stdout.decode().strip()
    _git(repo, "update-ref", f"refs/aegis/lanes/{lane}", oid)
    return oid


def _fresh_repo(parent: Path, name: str) -> Path:
    root = parent / name
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / ".aegis").mkdir()
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root.resolve()


def _refusal_argv(repo: Path, reason: str):
    """Drive one core reason through the public CLI. The repo stays writable."""
    if reason == "absent":
        return ["release", "docs", "--expect", "a" * 40]
    if reason == "expired":
        old = team.claim(repo, "docs", ["docs/**"], owner="a@h", ttl_s=60, now=NOW)
        return ["transfer", "docs", "--expect", old.oid, "--owner", "b@h"]
    if reason == "legacy_paths":
        oid = _plant_blob(repo, "docs", {
            "v": 1, "lane": "docs", "role": "implementer", "owner": "o@h",
            "claim_id": "0123456789abcdef", "gen": 1, "branch": None,
            "paths": [_LEGACY_SECRET], "ts": int(time.time()), "ttl_s": 3600,
        })
        return ["renew", "docs", "--expect", oid]
    if reason == "overlap":
        team.claim(repo, "api", ["src/**"], owner="o@h")
        return ["claim", "core", "--paths", "src/core/**", "--owner", "o@h"]
    if reason == "stale":
        first = team.claim(repo, "docs", ["docs/**"], owner="a@h")
        team.renew(repo, "docs", first.oid)
        return ["renew", "docs", "--expect", first.oid]
    if reason == "taken":
        team.claim(repo, "docs", ["docs/**"], owner="holder@box")
        return ["claim", "docs", "--paths", "docs/**", "--owner", "late@box"]
    if reason == "unreadable":
        oid = _plant_blob(repo, "docs", b"junk")
        return ["renew", "docs", "--expect", oid]
    raise AssertionError("no CLI driver for " + reason)


def _invoke(root: Path, *argv: str):
    from contextlib import redirect_stderr, redirect_stdout
    import io

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(["--workspace", str(root), "team", *argv])
    return code, out.getvalue(), err.getvalue()


def _concurrent_refusal_cli(root, argv, *, unavailable_view=False):
    import sys
    from concurrent.futures import ThreadPoolExecutor

    script = (
        "import json,sys\n"
        "from aegis_core import gitsafe,team\n"
        "from aegis_cli.cli import main\n"
        "def unavailable(*args,**kwargs):\n"
        "    raise gitsafe.GitError('view unavailable')\n"
        "if sys.argv[2] == '1':\n"
        "    team.describe = unavailable\n"
        "sys.exit(main(json.loads(sys.argv[1])))\n"
    )

    def once(_slot):
        return subprocess.run(
            [sys.executable, "-c", script, json.dumps(["--workspace", str(root), "team", *argv]),
             "1" if unavailable_view else "0"],
            cwd=str(Path(__file__).resolve().parents[3]), capture_output=True, text=True, timeout=30)

    with ThreadPoolExecutor(max_workers=3) as pool:
        return list(pool.map(once, range(3)))


def test_claim_refusal_text_is_the_core_reason_set(ws: Path):
    """Each core lease reason exits 1 with its fixed text; legacy paths are not echoed."""
    from aegis_cli import team as cli_team
    from aegis_core.primitives import utc_stamp

    reasons = _core_lease_reasons()
    assert cli_team.CLAIM_REFUSALS == {reason: reason + ":" for reason in reasons}
    assert "legacy_paths" in reasons
    held = {}
    for reason in sorted(reasons):
        repo = _fresh_repo(ws, reason)
        argv = _refusal_argv(repo, reason)
        lane = "core" if reason == "overlap" else "docs"
        current = _ref(repo, lane)
        expected = {
            "absent": "absent: lane docs has no lease",
            "expired": f"expired: lane docs's lease expired at {utc_stamp(NOW + 60)}; claim or renew it instead",
            "legacy_paths": ("legacy_paths: lane docs has legacy whitespace paths; "
                             f"release docs --expect {current}, then claim each path as its own entry"),
            "overlap": "overlap: lane core may overlap live lease(s) of api",
            "stale": f"stale: lane docs holds {current}, not {argv[-1]}",
            "taken": f"taken: lane docs is leased (oid {current})",
            "unreadable": (f"unreadable: lane docs holds {current}, which is no readable lease; "
                           f"release it with --expect {current}"),
        }[reason]
        code, out, err = _invoke(repo, *argv)
        assert code == 1, (reason, out, err)
        fixed = cli_team.CLAIM_REFUSALS[reason]
        assert err.splitlines()[0] == expected, (reason, err)
        assert _LEGACY_SECRET not in out + err
        assert _ref(repo, lane) == current
        code, out, err = _invoke(repo, *argv, "--json")
        assert (code, err) == (1, ""), (reason, err)
        payload = json.loads(out)
        assert payload["reason"] == reason
        assert payload["message"] == expected
        assert _LEGACY_SECRET not in out
        assert _ref(repo, lane) == current
        if reason == "legacy_paths":
            assert payload["lease"] is None
            assert payload["message"].endswith("claim each path as its own entry")
            code, out, err = _invoke(repo, "transfer", "docs", "--expect", _ref(repo, "docs"),
                                     "--owner", "n@h")
            assert code == 1 and err.startswith(fixed) and _LEGACY_SECRET not in out + err
        held[reason] = (lane, _ref(repo, lane))
    # Retry uses the lease left by the first refusal and must not write another.
    retry = {
        "absent": ["release", "docs", "--expect", "a" * 40],
        "expired": ["transfer", "docs", "--expect", "{oid}", "--owner", "c@h"],
        "legacy_paths": ["renew", "docs", "--expect", "{oid}"],
        "overlap": ["claim", "core", "--paths", "src/core/**", "--owner", "o@h"],
        "stale": ["renew", "docs", "--expect", "b" * 40],
        "taken": ["claim", "docs", "--paths", "docs/**", "--owner", "again@box"],
        "unreadable": ["renew", "docs", "--expect", "{oid}"],
    }
    assert set(retry) == reasons
    for reason, (lane, oid) in held.items():
        argv = [part.replace("{oid}", oid or "") for part in retry[reason]]
        code, out, err = _invoke(ws / reason, *argv, "--json")
        assert code == 1 and json.loads(out)["reason"] == reason, (reason, out, err)
        assert _LEGACY_SECRET not in out + err
        assert _ref(ws / reason, lane) == oid


@pytest.mark.parametrize("action", ["renew", "transfer"])
def test_legacy_paths_refusal_survives_view_failure_retry_and_concurrency(ws: Path, monkeypatch, action):
    """Display failure, a second caller, and overlapping callers still exit 1."""
    import sys
    from concurrent.futures import ThreadPoolExecutor

    repo = _fresh_repo(ws, "legacy")
    oid = _plant_blob(repo, "docs", {
        "v": 1, "lane": "docs", "role": "implementer", "owner": "o@h",
        "claim_id": "0123456789abcdef", "gen": 1, "branch": None,
        "paths": [_LEGACY_SECRET], "ts": int(time.time()), "ttl_s": 3600,
    })
    argv = [action, "docs", "--expect", oid]
    if action == "transfer":
        argv.extend(["--owner", "n@h"])

    def boom(*_args, **_kwargs):
        raise OSError("token=secret view failed")

    original = team.describe
    monkeypatch.setattr(team, "describe", boom)
    try:
        for _ in range(2):
            code, out, err = _invoke(repo, *argv)
            assert code == 1 and err.startswith("legacy_paths:")
            assert "token=secret" not in out + err and "view failed" not in out + err
            code, out, err = _invoke(repo, *argv, "--json")
            payload = json.loads(out)
            assert (code, err, payload["reason"], payload["lease"]) == (1, "", "legacy_paths", None)
            assert "token=secret" not in out
            assert _ref(repo, "docs") == oid
    finally:
        monkeypatch.setattr(team, "describe", original)

    def once(_slot):
        # Separate processes: lease_operation redirects this process's stdout.
        script = "import json,sys\nfrom aegis_cli.cli import main\nsys.exit(main(json.loads(sys.argv[1])))\n"
        result = subprocess.run([sys.executable, "-c", script, json.dumps(
            ["--workspace", str(repo), "team", *argv])], capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parents[3]), timeout=30)
        return result.returncode, result.stdout, result.stderr

    with ThreadPoolExecutor(max_workers=3) as pool:
        raced = list(pool.map(once, range(3)))
    assert [code for code, _out, _err in raced] == [1, 1, 1]
    assert all(err.startswith("legacy_paths:") and _LEGACY_SECRET not in out + err
               for _code, out, err in raced)
    assert _ref(repo, "docs") == oid
    code, out, err = _invoke(repo, *argv, "--json")
    assert code == 1 and json.loads(out)["reason"] == "legacy_paths"
    assert _ref(repo, "docs") == oid


def test_unknown_lease_reason_exits_1_without_echoing_input(ws: Path, monkeypatch, capsys):
    """A reason outside the core set is fixed text, never the exception or a joined line."""
    def refused(*_args, **_kwargs):
        raise team.LeaseRefused("token=secret\nstill secret", "not_a_core_reason", "docs")

    monkeypatch.setattr(team, "claim", refused)
    rc, out, err = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "o@h")
    assert rc == 1 and out == "" and err == "refused\n"
    rc, out, err = _run(capsys, "claim", "docs", "--paths", "docs/**", "--owner", "o@h", "--json")
    assert rc == 1 and err == ""
    payload = json.loads(out)
    assert payload["reason"] == "not_a_core_reason"
    assert payload["message"] == "refused"
    assert "token=secret" not in out + err


@pytest.mark.parametrize("message, expected", [
    ("taken: token=private-marker", "taken: token=REDACTED"),
    ("taken: token=private\x1b[31m-marker", "taken: token=REDACTED"),
    ("taken: token=private-marker\nsecond line", "taken:"),
    ("taken: token=private-marker\rsecond line", "taken:"),
], ids=["secret", "canonical-secret", "newline", "carriage-return"])
def test_known_refusal_message_is_safe(ws, capsys, monkeypatch, message, expected):
    def refused(*_args, **_kwargs):
        raise team.LeaseRefused(message, "taken", "docs")

    monkeypatch.setattr(team, "claim", refused)
    for mode in ([], ["--json"]):
        code, out, err = _run(capsys, "claim", "docs", "--paths", "docs/**", *mode)
        assert code == 1
        if mode:
            assert err == ""
            assert json.loads(out)["message"] == expected
        else:
            assert (out, err) == ("", expected + "\n")


@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("legacy", [False, True], ids=["ten-live-leases", "three-legacy-leases"])
def test_long_overlap_refusal_preserves_complete_message(ws, mode, legacy):
    """Long existing refusals retain every lane and complete recovery command."""
    lanes = []
    held = {}
    commands = []
    for index in range(3 if legacy else 10):
        lane = f"lane{index:02d}-".ljust(63, "a")
        lanes.append(lane)
        if legacy:
            oid = _plant_blob(ws, lane, {
                "v": 1, "lane": lane, "role": "implementer", "owner": "o@h",
                "claim_id": "0123456789abcdef", "gen": 1, "branch": None,
                "paths": [f"scope{index}/one/** scope{index}/two/**"],
                "ts": int(time.time()), "ttl_s": 3600,
            })
            commands.append(f"release {lane} --expect {oid}")
        else:
            oid = team.claim(ws, lane, [f"scope{index}/**"], owner="o@h").oid
        held[lane] = oid
    assert all(len(lane) == 63 for lane in lanes)
    expected = "overlap: lane core may overlap live lease(s) of " + ", ".join(lanes)
    expected += "".join(f"; {command}, then claim each path as its own entry" for command in commands)
    assert len(expected) > 512
    with pytest.raises(team.LeaseRefused) as refused:
        team.claim(ws, "core", ["**"], owner="o@h")
    assert str(refused.value) == expected

    argv = ["claim", "core", "--paths", "**", "--owner", "o@h"]
    if mode == "json":
        argv.append("--json")
    for _ in range(2):
        code, out, err = _invoke(ws, *argv)
        assert code == 1
        if mode == "json":
            assert err == ""
            payload = json.loads(out)
            assert (payload["status"], payload["reason"], payload["lanes"]) == (
                "refused", "overlap", lanes)
            assert payload["current"] is payload["lease"] is None
            message = payload["message"]
        else:
            assert out == ""
            assert err == expected + "\n"
            message = err.removesuffix("\n")
        assert message == expected
        assert all(command in message for command in commands)
        assert _ref(ws, "core") is None
        assert {lane: _ref(ws, lane) for lane in lanes} == held


@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("action", ["claim", "renew", "transfer", "release"])
def test_legacy_lease_refusal_never_displays_paths(ws, mode, action):
    """Taken and stale refusals retain recovery while omitting legacy lease detail."""
    oid = _refusal_argv(ws, "legacy_paths")[-1]
    expect = "0" * 40
    assert expect != oid
    if action == "claim":
        argv = [action, "docs", "--paths", "docs/**", "--owner", "late@box"]
        reason = "taken"
        expected = f"taken: lane docs is leased (oid {oid})"
    else:
        argv = [action, "docs", "--expect", expect]
        if action == "transfer":
            argv.extend(["--owner", "late@box"])
        reason = "stale"
        expected = f"stale: lane docs holds {oid}, not {expect}"
    expected += f"; release docs --expect {oid}, then claim each path as its own entry"
    if mode == "json":
        argv.append("--json")
    for _ in range(2):
        code, out, err = _invoke(ws, *argv)
        assert code == 1
        assert "token=secret" not in out + err
        if mode == "json":
            assert err == ""
            payload = json.loads(out)
            assert (payload["reason"], payload["message"], payload["current"], payload["lease"]) == (
                reason, expected, oid, None)
        else:
            assert (out, err) == ("", expected + "\n")
        assert _ref(ws, "docs") == oid
    for result in _concurrent_refusal_cli(ws, argv):
        assert result.returncode == 1
        assert "token=secret" not in result.stdout + result.stderr
        if mode == "json":
            assert result.stderr == ""
            payload = json.loads(result.stdout)
            assert (payload["reason"], payload["message"], payload["lease"]) == (reason, expected, None)
        else:
            assert (result.stdout, result.stderr) == ("", expected + "\n")
    assert _ref(ws, "docs") == oid


@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("action", ["claim", "renew"])
@pytest.mark.parametrize("failure", ["git", "os", "repository", "value"])
def test_refusal_view_failure_follows_action_contract(ws, monkeypatch, mode, action, failure):
    """Claims keep their refusal; renew retains the typed liveness fallback."""
    held = team.claim(ws, "docs", ["docs/**"], owner="holder@box")
    expect = "0" * 40
    assert expect != held.oid
    if action == "claim":
        argv = [action, "docs", "--paths", "docs/**", "--owner", "late@box"]
        reason, expected = "taken", f"taken: lane docs is leased (oid {held.oid})"
    else:
        argv = [action, "docs", "--expect", expect]
        reason, expected = "stale", f"stale: lane docs holds {held.oid}, not {expect}"
    if mode == "json":
        argv.append("--json")
    original_describe, original_listing = team.describe, rendering_git.list_refs
    rendering, failures, available = [], [], [False]

    def describe(*args, **kwargs):
        if failure != "git" and not available[0]:
            failures.append(True)
            error = {"os": OSError, "repository": team.TeamUsageError, "value": ValueError}[failure]
            raise error("token=secret view repository unavailable")
        rendering.append(True)
        try:
            return original_describe(*args, **kwargs)
        finally:
            rendering.pop()

    def listing(*args, **kwargs):
        if rendering and not available[0]:
            failures.append(True)
            raise rendering_git.GitError("token=secret view listing failed")
        return original_listing(*args, **kwargs)

    monkeypatch.setattr(team, "describe", describe)
    monkeypatch.setattr(rendering_git, "list_refs", listing)

    def assert_refusal(code, out, err):
        assert code == 1
        assert "token=secret" not in out + err
        if mode == "json":
            assert err == ""
            payload = json.loads(out)
            if action == "claim":
                assert (payload["reason"], payload["message"], payload["current"], payload["lease"]) == (
                    reason, expected, held.oid, None)
            else:
                assert (payload["reason"], payload["message"], payload["next_action"]) == (
                    "liveness_unknown", "liveness_unknown", "Restore private Git metadata, then retry.")
                assert "current" not in payload and "lease" not in payload
        else:
            message = (expected + "\n" if action == "claim" else
                       "liveness_unknown\nRestore private Git metadata, then retry.\n")
            assert (out, err) == ("", message)

    for _ in range(2):
        assert_refusal(*_invoke(ws, *argv))
        assert not rendering
        assert _ref(ws, "docs") == held.oid
    assert len(failures) == 2

    if failure == "git":
        for result in _concurrent_refusal_cli(ws, argv, unavailable_view=True):
            assert_refusal(result.returncode, result.stdout, result.stderr)

    available[0] = True
    code, out, err = _invoke(ws, *argv)
    assert code == 1 and not rendering
    if mode == "json":
        assert err == ""
        payload = json.loads(out)
        assert (payload["reason"], payload["message"], payload["lease"]["oid"]) == (
            reason, expected, held.oid)
    else:
        assert out == "" and err.startswith(expected + "\n")
        assert "paths: docs/**" in err
    assert _ref(ws, "docs") == held.oid
