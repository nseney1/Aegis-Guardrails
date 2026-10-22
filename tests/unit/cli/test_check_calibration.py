"""R-checks-47: `aegis check --calibration` is a real flag; Layer 2 runs log stamped, model-text-free
prediction rows to `.aegis/state/arbiter_predictions.jsonl`; scoring is per backend and observable kind."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import sys
import textwrap

import pytest

from aegis_cli.cli import main
from aegis_core.workspace.layout import WorkspaceLayout
from tests.helpers_checkmodes import commit, git, init_repo, write

WORKER = "def work(x):\n    return x + {n}\n\n\nVALUE = work(1)\n"  # called, so Layer 1 passes
RISK = "SECRET-RISK-TEXT eval of untrusted input"
FAKE_LLM = textwrap.dedent(f"""\
    import json, sys
    prompt = sys.stdin.read()
    if "Spec Agent" in prompt and sys.argv[1] == "one":
        print(json.dumps([{{"category": "code_injection", "severity": "high", "risk": {RISK!r},
                           "mechanism": "MECHANISM-TEXT", "affected_function": "work", "p": 0.3,
                           "observable": {{"kind": "revert", "selector": "worker.py"}}}}]))
    elif "Spec Agent" in prompt and sys.argv[1] in ("quoted", "partly"):
        kind = "revert" if sys.argv[1] == "partly" else "QUOTED-KIND api_key=1"
        print(json.dumps([{{"category": "code_injection", "severity": "high", "risk": "r", "mechanism": "m",
                           "affected_function": "QUOTED-DIFF api_key=1", "p": 0.3,
                           "observable": {{"kind": kind, "selector": "QUOTED-SELECTOR api_key=1"}}}}]))
    else:
        print("[]")
""")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    root = init_repo(tmp_path / "project")
    write(root, "worker.py", WORKER.format(n=1))
    commit(root, "base")
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def llm(tmp_path: Path):
    script = tmp_path / "fake_llm.py"
    script.write_bytes(FAKE_LLM.encode("utf-8"))
    return lambda mode: shlex.join([sys.executable, str(script), mode])


def _run(capsys, *argv: str):
    try:
        rc = main(["check", *argv])
    except SystemExit as exc:
        rc = int(exc.code or 0)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _log(root: Path) -> Path:
    return WorkspaceLayout(root).predictions_log


def _row(**over) -> dict:
    row = {"id": "p", "verdict_id": "v", "ts": 1.0, "tree": "t" * 40, "backend": "claude",
           "scope": {"path": "a.py", "symbol": "f"}, "category": "code_injection",
           "observable": {"kind": "revert", "selector": "a.py"}, "window_days": 14, "p": 0.5, "severity": "high",
           "disposition": "landed_unchanged", "outcome": "hit"}
    row.update(over)
    return row


def test_with_no_log_nothing_is_logged_and_nothing_is_created(repo, capsys):
    rc, out, _ = _run(capsys, "--calibration")
    assert rc == 0 and out.startswith("0 logged") and "insufficient (n=0/25)" in out
    assert not (repo / ".aegis" / "state").exists()
    rc, out, _ = _run(capsys, "--calibration", "--json")
    doc = json.loads(out)
    assert rc == 0 and (doc["status"], doc["n"], doc["logged"]) == ("insufficient (n=0/25)", 0, 0)


def test_rows_are_scored_per_backend_and_kind_and_only_hit_or_miss_counts(repo, capsys):
    rows = [_row(id="a1"), _row(id="a2", outcome="miss"), _row(id="a3", outcome="void"),
            _row(id="b1", backend="gemini"), _row(id="b2", backend="gemini", outcome="false")]
    state = repo / ".aegis" / "state"
    state.mkdir(parents=True)
    _log(repo).write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    rc, out, _ = _run(capsys, "--calibration", "--json")
    groups = json.loads(out)["groups"]
    assert rc == 0 and sorted(groups) == ["claude/revert", "gemini/revert"]
    assert (groups["claude/revert"]["n"], groups["claude/revert"]["hits"]) == (2, 1)
    assert (groups["gemini/revert"]["n"], groups["gemini/revert"]["hits"]) == (1, 1)
    assert all(g["brier_skill_score"] is None and g["status"].startswith("insufficient") for g in groups.values())
    rc, out, _ = _run(capsys, "--calibration")
    assert rc == 0 and out.startswith("5 logged | ") and "claude/revert" in out and "n=2" in out


def test_a_row_that_cannot_be_scored_is_an_error_not_a_traceback(repo, capsys):
    (repo / ".aegis" / "state").mkdir(parents=True)
    _log(repo).write_bytes((json.dumps(_row(p=None)) + "\n").encode("utf-8"))
    rc, out, err = _run(capsys, "--calibration")
    assert (rc, out) == (1, "") and err.startswith("Error: the prediction log holds a row that cannot be scored")
    assert "Traceback" not in err


def test_calibration_is_a_mode_of_its_own(repo, capsys):
    rc, _, err = _run(capsys, "--record", "--calibration")
    assert rc == 2 and "does not combine" in err
    rc, _, err = _run(capsys, "--calibration", "worker.py")
    assert rc == 2 and "--calibration does not combine with FILES" in err


def test_a_layer2_run_logs_stamped_rows_without_model_text(repo, capsys, llm):
    write(repo, "worker.py", WORKER.format(n=2))
    for _ in range(2):
        rc, _out, _err = _run(capsys, "--full", "--plan", "X", "--llm-cmd", llm("one"), "worker.py")
        assert rc == 0
    raw = _log(repo).read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    assert len(rows) == 2
    assert rows[0]["id"] != rows[1]["id"] and rows[0]["verdict_id"] != rows[1]["verdict_id"]
    for row in rows:
        assert row["ts"] > 0 and row["backend"] == os.path.basename(sys.executable)
        assert (row["disposition"], row["outcome"], row["p"]) == ("logged", None, 0.3)
        assert row["scope"] == {"path": "worker.py", "symbol": "work"}
        assert row["observable"] == {"kind": "revert", "selector": "worker.py"}
    assert b"SECRET-RISK-TEXT" not in raw and b"MECHANISM-TEXT" not in raw
    rc, out, _ = _run(capsys, "--calibration", "--json")
    assert rc == 0 and (json.loads(out)["logged"], json.loads(out)["n"]) == (2, 0)


@pytest.mark.parametrize("mode,kind", [("quoted", ""), ("partly", "revert")])
def test_model_text_in_the_symbol_selector_or_kind_is_not_logged(repo, capsys, llm, mode, kind):
    """Adversarial: the model's affected_function, selector and kind are kept only when they name a
    function the change defines, a changed path and a known observable kind; otherwise they are empty."""
    write(repo, "worker.py", WORKER.format(n=2))
    rc, _out, _err = _run(capsys, "--full", "--plan", "X", "--llm-cmd", llm(mode), "worker.py")
    assert rc == 0
    raw = _log(repo).read_bytes()
    (row,) = [json.loads(line) for line in raw.splitlines()]
    assert row["scope"] == {"path": "", "symbol": ""}
    assert row["observable"] == {"kind": kind, "selector": ""}
    assert b"QUOTED" not in raw and b"api_key" not in raw


def test_runs_without_predictions_log_nothing(repo, capsys, llm):
    assert _run(capsys, "worker.py")[0] == 0
    assert _run(capsys, "--full", "--plan", "X", "--llm-cmd", llm("none"), "worker.py")[0] == 0
    assert not _log(repo).exists()


def test_a_log_that_cannot_be_written_is_a_warning_and_the_exit_is_unchanged(repo, capsys, llm):
    _log(repo).mkdir(parents=True)
    rc, _out, err = _run(capsys, "--full", "--plan", "X", "--llm-cmd", llm("one"), "worker.py")
    assert rc == 0 and "warning: predictions not logged" in err


def test_outside_an_aegis_workspace_no_aegis_directory_is_created(tmp_path, capsys, llm, monkeypatch):
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    plain = tmp_path / "plain"
    plain.mkdir()
    git(plain, "init", "-q", "-b", "main")
    write(plain, "worker.py", WORKER.format(n=1))
    monkeypatch.chdir(plain)
    _run(capsys, "--full", "--plan", "X", "--llm-cmd", llm("one"), "worker.py")
    assert not (plain / ".aegis").exists()


def test_stamping_is_unique_per_run_and_idempotent_for_one():
    from aegis_core.verification import Prediction
    from aegis_core.verification.arbiter import stamp

    preds = [Prediction(affected_function="f"), Prediction(affected_function="g")]
    one = stamp(preds, tree="t", backend="b", ts=1.0)
    again = stamp(preds, tree="t", backend="b", ts=1.0)
    other = stamp(preds, tree="t", backend="b", ts=2.0)
    assert [p.id for p in one] == [p.id for p in again]
    assert len({p.id for p in one + other}) == 4 and one[0].verdict_id != other[0].verdict_id
