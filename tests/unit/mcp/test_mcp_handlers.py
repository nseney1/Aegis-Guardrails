"""Direct tests of the four MCP handlers (one implementation each)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import aegis_mcp.handlers.telemetry as telemetry_handlers
from aegis_core.yaml_engine.serializer import dump_frontmatter
from aegis_mcp.handlers.core import handle_scan
from aegis_mcp.handlers.governance import handle_create_rule, handle_list_rules
from aegis_mcp.handlers.telemetry import handle_report_outcome

BAD_WORKSPACE = "/invalid\0path"


@pytest.fixture
def mcp_workspace(tmp_path: Path) -> Path:
    rules_dir = tmp_path / ".aegis" / "rules" / "traps"
    rules_dir.mkdir(parents=True, exist_ok=True)
    fm = {
        "id": "sample-rule",
        "type": "trap",
        "target_paths": ["src/*.py"],
        "hypothesis": "Sample hypothesis",
    }
    (rules_dir / "sample-rule.md").write_text(f"---\n{dump_frontmatter(fm)}---\n\n# Body\n", encoding="utf-8")
    return tmp_path


def test_scan_matches_rules_for_the_given_files(mcp_workspace: Path):
    res = handle_scan({"workspace": str(mcp_workspace), "files": ["src/main.py"]})
    assert [r["name"] for r in res["relevant_rules"]] == ["sample-rule"]


@pytest.mark.parametrize("args,error", [
    ({"workspace": BAD_WORKSPACE}, None),
    ({"files": "not-a-list"}, "'files' must be a list of file paths"),
    ({"files": [3]}, "'files' must be a list of file paths"),
])
def test_scan_rejects_bad_arguments(mcp_workspace: Path, args, error):
    res = handle_scan({"workspace": str(mcp_workspace), **args})
    assert res["status"] == "FAIL"
    if error:
        assert res["error"] == error


def test_a_scan_in_a_session_records_one_scan_event_per_files(mcp_workspace: Path):
    """aegis status --compliance reads these events; rescanning the same files in any order adds none."""
    names = [f"src/{letter}.py" for letter in "abcdefghijklmnopqr"]
    order = names[::2] + names[1::2]
    # 18 files in three orders: with this many, a dedup key built from an unsorted set
    # depends on insertion order on more than 99% of hash seeds, so only a sorted key passes.
    # The "./" copy in the first call names a file already listed, so the key must drop duplicates.
    for files in (order + ["./" + order[0]], order[::-1], order[9:] + order[:9]):
        args = {"workspace": str(mcp_workspace), "files": files, "_session": "s-1", "_host": "codex-cli"}
        assert [r["name"] for r in handle_scan(args)["relevant_rules"]] == ["sample-rule"]

    lines = (mcp_workspace / ".aegis" / "state" / "activity.jsonl").read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    assert [(e["event"], e["host"], e["session"], e["files"], e["basis"]) for e in events] == [
        ("scan", "codex-cli", "s-1", names, "files"),
    ]


def test_scan_succeeds_when_exposure_ledger_write_fails(mcp_workspace: Path, monkeypatch, capsys):
    def read_only_ledger(*_args, **_kwargs):
        raise OSError("read-only ledger")

    monkeypatch.setattr(telemetry_handlers.credit.ledger, "append_rows", read_only_ledger)
    res = handle_scan({
        "workspace": str(mcp_workspace),
        "files": ["src/main.py"],
        "_session": "s-readonly",
        "_host": "codex-cli",
    })
    assert res.get("status") != "FAIL"
    assert [r["name"] for r in res["relevant_rules"]] == ["sample-rule"]
    assert "Sample hypothesis" in res["guidance"]
    assert "aegis-mcp: exposure record not written: read-only ledger" in capsys.readouterr().err
    assert telemetry_handlers.credit.exposed_rules(mcp_workspace, "codex-cli", "s-readonly") == {"sample-rule"}


def test_a_sessionless_read_is_the_hosts_own_exposures_never_another_hosts_session(tmp_path: Path, monkeypatch):
    """Given an exposure of host claude-code with no session and one of other-host in session codex-cli,
    When exposed_rules runs without a session, Then the sessionless host reads its own exposure and a
    host name is never read as another host's session id."""
    credit = telemetry_handlers.credit
    monkeypatch.setattr(credit, "_EXPOSED", {})
    credit.record_exposure(tmp_path, "claude-code", None, ["r-none"], persist=False)
    credit.record_exposure(tmp_path, "other-host", "codex-cli", ["r-x"], persist=False)
    assert credit.exposed_rules(tmp_path, "claude-code", None) == {"r-none"}
    assert credit.exposed_rules(tmp_path, "codex-cli", None) == set()
    assert credit.exposed_rules(tmp_path, "other-host", "codex-cli") == {"r-x"}


def test_the_vestigial_credit_aliases_are_gone():
    credit = telemetry_handlers.credit
    assert not hasattr(credit, "record_human_label") and not hasattr(credit, "session_exposed_rules")
    assert "session_exposed_rules" not in credit.__all__ and "record_adjudication" in credit.__all__


def test_the_witnessed_set_holds_only_what_this_process_exposed(mcp_workspace: Path, monkeypatch):
    """Given a scan in session s and a ledger exposure row for another rule with the same host and
    session, Then the witnessed accessor returns only the scanned rule, the display accessor both,
    and another host, another session or an unscanned root returns nothing."""
    credit = telemetry_handlers.credit
    monkeypatch.setattr(credit, "_EXPOSED", {})
    handle_scan({"workspace": str(mcp_workspace), "files": ["src/main.py"], "_session": "s", "_host": "codex-cli"})
    credit.ledger.append_rows(mcp_workspace, [{"v": credit.ledger.LEDGER_VERSION, "ts": "2026-10-19T00:00:00Z",
                                               "event": "exposure", "rule": "planted-rule", "session": "s",
                                               "host": "codex-cli", "paths": [], "rev": None}])
    root = Path(str(mcp_workspace)).resolve()
    assert credit.exposed_rules(root, "codex-cli", "s") == {"sample-rule", "planted-rule"}
    assert credit.witnessed_exposed_rules(root, "codex-cli", "s") == {"sample-rule"}
    assert credit.witnessed_exposed_rules(root, "claude-code", "s") == set()
    assert credit.witnessed_exposed_rules(root, "codex-cli", "other") == set()
    assert credit.witnessed_exposed_rules(root / "elsewhere", "codex-cli", "s") == set()
    credit.record_exposure(root, None, None, ["no-session-rule"], persist=False)
    assert credit.witnessed_exposed_rules(root, None, None) == {"no-session-rule"}
    witnessed = credit.witnessed_exposed_rules(root, "codex-cli", "s")
    witnessed.add("mutated")  # a copy: the caller cannot widen the server's record
    assert credit.witnessed_exposed_rules(root, "codex-cli", "s") == {"sample-rule"}


def test_scan_blocks_path_traversal(mcp_workspace: Path):
    res = handle_scan({"workspace": str(mcp_workspace), "files": ["../outside.py"]})
    assert res["status"] == "FAIL"
    assert "path traversal blocked" in res["error"].lower()


def test_create_rule_returns_a_prompt_built_from_existing_rules(mcp_workspace: Path):
    res = handle_create_rule({
        "workspace": str(mcp_workspace),
        "description": "Rule to test something",
        "domain": "testing",
        "rule_type": "trap",
    })
    assert "Sample hypothesis" in res["prompt"]
    assert 'User description: "Rule to test something"' in res["prompt"]
    assert "Preferred rule type: trap" in res["prompt"]
    assert "save it as .aegis/rules/<type directory>/<id>.md" in res["instruction"]
    assert "boundaries/ (boundary)" in res["instruction"]  # never a guessed "<type>s/"


@pytest.mark.parametrize("description", [None, "", "   ", 5])
def test_create_rule_needs_a_description(mcp_workspace: Path, description):
    res = handle_create_rule({"workspace": str(mcp_workspace), "description": description})
    assert res == {"error": "'description' must be a non-empty string.", "status": "FAIL"}


def test_create_rule_rejects_bad_workspace():
    res = handle_create_rule({"workspace": BAD_WORKSPACE, "description": "x"})
    assert res["status"] == "FAIL"


def test_list_rules_returns_frontmatter_records(mcp_workspace: Path):
    res = handle_list_rules({"workspace": str(mcp_workspace)})["rules"]
    assert [r["id"] for r in res] == ["sample-rule"]
    assert res[0]["_path"] == ".aegis/rules/traps/sample-rule.md"


def test_list_rules_filters_by_type(mcp_workspace: Path):
    invariants = mcp_workspace / ".aegis" / "rules" / "invariants"
    invariants.mkdir()
    (invariants / "inv.md").write_text("---\nid: inv\ntype: invariant\n---\n", encoding="utf-8")
    def ids(rule_type):
        return [r["id"] for r in handle_list_rules({"workspace": str(mcp_workspace), "rule_type": rule_type})["rules"]]

    assert ids("invariant") == ["inv"]
    assert ids("trap") == ["sample-rule"]


def test_list_rules_rejects_bad_workspace():
    assert handle_list_rules({"workspace": BAD_WORKSPACE})["status"] == "FAIL"


def test_report_outcome_without_rules_is_rejected(mcp_workspace: Path):
    res = handle_report_outcome({"workspace": str(mcp_workspace), "outcome": "success", "idempotency_key": "k"})
    assert res == {
        "status": "FAIL",
        "error": "'rules_used' must name at least one rule from aegis_scan: "
                 "an outcome with no rule has nothing to credit.",
    }
    assert not (mcp_workspace / ".aegis" / "state" / "ledger.jsonl").exists()


def test_report_outcome_rejects_bad_workspace():
    res = handle_report_outcome({"workspace": BAD_WORKSPACE, "outcome": "tp", "idempotency_key": "k"})
    assert res["status"] == "FAIL"


def test_report_outcome_surfaces_a_ledger_write_failure(mcp_workspace: Path, monkeypatch):
    def disk_full(*_args, **_kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(telemetry_handlers.credit.ledger, "append_rows", disk_full)
    res = handle_report_outcome({
        "workspace": str(mcp_workspace),
        "outcome": "success",
        "rules_used": ["sample-rule"],
        "idempotency_key": "k-fail",
    })
    assert res == {"status": "FAIL", "error": "Failed to record outcome: disk full"}


def test_report_outcome_fails_cleanly_when_the_rules_tree_is_unsafe(mcp_workspace: Path, tmp_path_factory):
    """The rule names cannot be checked against a tree the loader refuses: nothing is recorded."""
    outside = tmp_path_factory.mktemp("outside")
    try:
        (mcp_workspace / ".aegis" / "rules" / "invariants").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    res = handle_report_outcome({
        "workspace": str(mcp_workspace),
        "outcome": "success",
        "rules_used": ["sample-rule"],
        "idempotency_key": "k-unsafe",
    })
    assert res["status"] == "FAIL"
    assert res["error"].startswith("Cannot check 'rules_used' against the rules: rule inventory validate failed")
    assert "symlinked directory is not allowed" in res["error"]
    assert not (mcp_workspace / ".aegis" / "state" / "ledger.jsonl").exists()


_RULE_NAMES = "'rules_used' must be a list of rule names."
_FILE_PATHS = "'files' must be a list of file paths"
_KEY_REQUIRED = (
    "'idempotency_key' is required: send a unique key per report so a retry is never recorded twice."
)


@pytest.mark.parametrize("args, error", [
    ({"rules_used": ["sample-rule"]}, _KEY_REQUIRED),
    ({"rules_used": ["sample-rule"], "idempotency_key": " \t"}, _KEY_REQUIRED),
    ({"rules_used": "sample-rule", "idempotency_key": "k"}, _RULE_NAMES),
    ({"rules_used": ["sample-rule", 3], "idempotency_key": "k"}, _RULE_NAMES),
    ({"rules_used": ["sample-rule"], "idempotency_key": "k", "files": "src/main.py"}, _FILE_PATHS),
    ({"rules_used": ["sample-rule"], "idempotency_key": "k", "files": ["src/main.py", None]}, _FILE_PATHS),
])
def test_report_outcome_rejects_malformed_arguments_and_records_nothing(mcp_workspace: Path, args, error):
    res = handle_report_outcome({"workspace": str(mcp_workspace), "outcome": "success", **args})
    assert res == {"status": "FAIL", "error": error}
    assert not (mcp_workspace / ".aegis" / "state" / "ledger.jsonl").exists()
