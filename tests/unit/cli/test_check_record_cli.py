"""`aegis check --record [--tests]` through the real argument parser."""
from __future__ import annotations

import json

import pytest

from aegis_cli import cli
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
ENVELOPE = ("source", "aegis_version", "checked_at", "scope")


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))


def _run(repo, capsys, *flags):
    rc = cli.main(["check", "--record", "--workspace", str(repo.root), "--base", "main", *flags])
    return rc, capsys.readouterr()


@needs_git
def test_record_writes_one_row_and_prints_an_enveloped_document(tmp_path, capsys):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    rc, out = _run(repo, capsys, "--tests", "--json")
    doc = json.loads(out.out)
    assert rc == 0 and doc["status"] == "recorded" and doc["witness"] == "aegis"
    assert all(doc[k] for k in ENVELOPE) and doc["check"]["tests"]["passed"] == 3
    rows = hv.rows_of(repo.root, "check")
    assert len(rows) == 1 and rows[0]["run_ordinal"] == 1 and "attempt" not in rows[0]


@needs_git
def test_a_failing_run_is_recorded_and_exits_one(tmp_path, capsys):
    repo = hv.make_project(tmp_path, runner=hv.FAILING)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    rc, out = _run(repo, capsys, "--tests", "--json")
    assert rc == 1 and json.loads(out.out)["check"]["passed"] is False
    assert hv.rows_of(repo.root, "check")[0]["passed"] is False


@needs_git
def test_without_tests_only_layer_one_runs(tmp_path, capsys):
    repo = hv.make_project(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    rc, out = _run(repo, capsys)
    assert rc == 0 and "recorded" in out.out
    assert hv.rows_of(repo.root, "check")[0]["tests"] is None


@needs_git
def test_record_preserves_no_driver_language_and_reason(tmp_path, capsys):
    repo = hv.make_project(tmp_path)
    repo.write(".aegis/rules/invariants/no-reflection.md",
               '---\nid: no-reflection\ntype: invariant\nenforcement: gate\n'
               'target_paths: ["src/*.kt"]\nforbid_ast:\n  calls: [danger]\n---\n# No reflection\n')
    repo.write("src/app.kt", "danger()\n")

    rc, out = _run(repo, capsys, "--json")

    doc = json.loads(out.out)
    assert rc == 0 and doc["check"]["layer1"]["findings"] == 0
    note, = [row for row in doc["check"]["layer1"]["evidence"] if row.get("reason") == "no_driver:.kt"]
    assert note == {"tool": "forbid_ast_no_driver", "target": "src/app.kt", "verdict": True,
                    "language": "unknown", "reason": "no_driver:.kt"}
    assert hv.rows_of(repo.root, "check")[0]["layer1"]["evidence"] == doc["check"]["layer1"]["evidence"]


@needs_git
def test_record_preserves_too_large_language_and_reason(tmp_path, capsys):
    repo = hv.make_project(tmp_path)
    repo.write(".aegis/rules/invariants/no-danger.md",
               '---\nid: no-danger\ntype: invariant\nenforcement: gate\n'
               'target_paths: ["src/*.ts"]\nforbid_ast:\n  calls: [danger]\n---\n# No danger\n')
    repo.write("src/big.ts", "danger();\n" + "// pad\n" * (2 * 1024 * 1024 // 7 + 1))

    rc, out = _run(repo, capsys, "--json")

    doc = json.loads(out.out)
    assert rc == 0 and doc["check"]["layer1"]["findings"] == 0
    notes = [row for row in doc["check"]["layer1"]["evidence"] if row["tool"] == "ast_unverified"]
    assert notes and all(note == {"tool": "ast_unverified", "target": "src/big.ts", "verdict": True,
                                  "language": "typescript", "reason": "too_large"} for note in notes)
    assert hv.rows_of(repo.root, "check")[0]["layer1"]["evidence"] == doc["check"]["layer1"]["evidence"]


@needs_git
def test_record_preserves_the_language_of_a_failing_rule(tmp_path, capsys):
    repo = hv.make_project(tmp_path)
    repo.write(".aegis/rules/invariants/no-eval.md",
               '---\nid: no-eval\ntype: invariant\nenforcement: gate\n'
               'target_paths: ["src/*.py"]\nforbid_ast:\n  calls: [eval]\n---\n# No eval\n')
    repo.write("src/app.py", 'def app():\n    return eval("1")\n')

    rc, out = _run(repo, capsys, "--json")

    doc = json.loads(out.out)
    assert rc == 1 and doc["check"]["passed"] is False
    finding, = [row for row in doc["check"]["layer1"]["evidence"] if row["tool"] == "forbid_ast:no-eval"]
    assert finding["language"] == "python" and finding["verdict"] is False
    assert doc["check"]["layer1"]["findings"] >= 1


@needs_git
def test_an_unbindable_tree_writes_no_row_and_says_why(tmp_path, capsys):
    repo = hv.make_project(tmp_path)
    repo.git("update-index", "--assume-unchanged", "src/app.py")
    repo.write("src/app.py", "def app():\n    return 2\n")
    rc, out = _run(repo, capsys, "--json")
    doc = json.loads(out.out)
    assert rc == 1 and doc["status"] == "unbindable" and "assume-unchanged" in doc["reason"]
    assert hv.rows_of(repo.root, "check") == []


@needs_git
@pytest.mark.parametrize("flags,needle", [
    (["--full"], "--record does not combine with --full"),
    (["--hook"], "--record does not combine with --hook"),
    (["--lane", "x"], "--record does not combine with --lane"),
    (["--card"], "--record does not combine with --card"),
])
def test_record_refuses_options_it_would_ignore(tmp_path, capsys, flags, needle):
    repo = hv.make_project(tmp_path)
    rc = cli.main(["check", "--record", "--workspace", str(repo.root), *flags])
    assert rc == 2 and needle in capsys.readouterr().err
    assert hv.rows_of(repo.root, "check") == []


def test_tests_alone_is_a_usage_error(tmp_path, capsys):
    rc = cli.main(["check", "--tests", "--workspace", str(tmp_path)])
    assert rc == 2 and "--tests only applies with --record" in capsys.readouterr().err
