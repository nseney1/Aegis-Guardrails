"""The grammar of ``aegis check`` modes (v4.2): one mode at a time, no ambiguous combination.

``--lane``, ``--partition``, ``--card``, ``--write-baseline`` and ``--prune-baseline`` are
one mutually exclusive group. ``--split`` belongs to ``--partition``; ``--paths`` and
``--base-policy`` to ``--lane``; ``--base`` to ``--lane`` and to a plain check (where it
names the baseline's source). Every option a mode would otherwise ignore is refused, so
nothing is accepted and silently dropped. These tests pin each rejected combination
through the real parser; what each mode does is tested beside its own module.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
import re
import shutil

import pytest

from aegis_cli.check import CheckCommand
from aegis_cli.cli import main
from aegis_cli.verify import run_verify
from tests.helpers_checkmodes import commit, init_repo, write

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

MODES = {
    "--lane": ["--lane", "docs"],
    "--partition": ["--partition", "--split", "A=a/**", "--split", "B=b/**"],
    "--card": ["--card"],
    "--write-baseline": ["--write-baseline"],
    "--prune-baseline": ["--prune-baseline"],
    "--ci": ["--ci"],
    "--calibration": ["--calibration"],
}
TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    root = init_repo(tmp_path / "project")
    write(root, "a/one.py", "def one():\n    return 1\n")
    write(root, "b/two.py", "def two():\n    return 2\n")
    commit(root, "base")
    monkeypatch.chdir(root)
    return root


def _run(capsys, *argv: str):
    try:
        rc = main(["check", *argv])
    except SystemExit as exc:  # argparse
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    CheckCommand().configure_parser(parser)
    return parser


# ── The mode group ───────────────────────────────────────────────────────────

def test_the_five_modes_are_one_mutually_exclusive_group():
    groups = [g for g in _parser()._mutually_exclusive_groups
              if {"--lane", "--partition", "--card", "--write-baseline", "--prune-baseline"}
              <= {opt for a in g._group_actions for opt in a.option_strings}]
    assert len(groups) == 1
    assert sorted(opt for a in groups[0]._group_actions for opt in a.option_strings) == sorted(MODES)


@pytest.mark.parametrize("first, second", list(itertools.combinations(MODES, 2)))
def test_two_modes_never_combine(repo: Path, capsys, first, second):
    rc, out, err = _run(capsys, *MODES[first], *MODES[second])
    assert rc == 2
    assert "not allowed with argument" in err
    assert out == ""


def test_the_defaults_of_a_plain_check_select_no_mode():
    args = _parser().parse_args([])
    assert (args.lane, args.partition, args.card, args.write_baseline, args.prune_baseline, args.split) == (
        None, False, False, False, False, None)


def test_split_appends_and_keeps_every_value_as_given():
    args = _parser().parse_args(["--partition", "--split", "A=x/**,y/*.py", "--split", "B=z"])
    assert args.split == ["A=x/**,y/*.py", "B=z"]


# ── What a mode refuses ──────────────────────────────────────────────────────

REFUSED = [
    (["src/app.py"], "FILES"),
    (["--full"], "--full"),
    (["--plan", "x"], "--plan"),
    (["--plan-file", "plan.md"], "--plan-file"),
    (["--hook"], "--hook"),
    (["--strict"], "--strict"),
    (["--dry-run"], "--dry-run"),
    (["--llm-cmd", "x"], "--llm-cmd"),
]


@pytest.mark.parametrize("mode", ["--partition", "--card", "--write-baseline", "--prune-baseline", "--calibration"])
@pytest.mark.parametrize("extra, flag", REFUSED)
def test_a_new_mode_refuses_the_options_it_would_ignore(repo: Path, capsys, mode, extra, flag):
    # FILES first: after --split argparse would read them as part of the mode's own arguments.
    rc, out, err = _run(capsys, *extra, *MODES[mode])
    assert rc == 2
    assert f"{mode} does not combine with {flag}" in err
    assert out == ""
    assert not (repo / ".aegis" / "baseline.json").exists()  # refused before anything was done


@pytest.mark.parametrize("mode", ["--partition", "--card", "--write-baseline", "--prune-baseline", "--calibration"])
def test_a_new_mode_names_every_refused_option_at_once(repo: Path, capsys, mode):
    rc, _, err = _run(capsys, "src/app.py", "--full", "--strict", *MODES[mode])
    assert rc == 2
    assert f"{mode} does not combine with FILES, --full, --strict" in err


@pytest.mark.parametrize("mode", ["--partition", "--card", "--write-baseline", "--prune-baseline", "--calibration"])
def test_base_belongs_to_lane_and_a_plain_check_only(repo: Path, capsys, mode):
    rc, _, err = _run(capsys, *MODES[mode], "--base", "main")
    assert rc == 2
    assert f"{mode} does not combine with --base" in err


@pytest.mark.parametrize("mode", ["--partition", "--card", "--write-baseline", "--prune-baseline", "--calibration"])
@pytest.mark.parametrize("flag, argv", [("--paths", ["--paths", "a/**"]), ("--base-policy", ["--base-policy"])])
def test_lane_options_stay_with_lane(repo: Path, capsys, mode, flag, argv):
    rc, _, err = _run(capsys, *MODES[mode], *argv)
    assert rc == 2
    assert f"{flag} only applies with --lane" in err


def test_a_plain_check_accepts_base_for_the_baseline(repo: Path, capsys):
    rc, out, err = _run(capsys, "--base", "main", "--dry-run")
    assert (rc, err) == (0, "")
    assert "Dry run" in out


@pytest.mark.parametrize("flag, argv", [("--paths", ["--paths", "a/**"]), ("--base-policy", ["--base-policy"])])
def test_lane_options_without_a_mode_are_still_usage_errors(repo: Path, capsys, flag, argv):
    rc, _, err = _run(capsys, *argv)
    assert rc == 2
    assert f"{flag} only applies with --lane" in err


def test_lane_keeps_its_own_refusals(repo: Path, capsys):
    rc, _, err = _run(capsys, "src/app.py", "--lane", "docs", "--paths", "docs/**")
    assert rc == 2
    assert "--lane does not combine with FILES" in err


# ── --split ──────────────────────────────────────────────────────────────────

def test_split_without_partition_is_a_usage_error(repo: Path, capsys):
    rc, _, err = _run(capsys, "--split", "A=a/**")
    assert rc == 2
    assert "--split only applies with --partition" in err


@pytest.mark.parametrize("mode", ["--card", "--write-baseline", "--prune-baseline"])
def test_split_with_another_mode_is_a_usage_error(repo: Path, capsys, mode):
    rc, _, err = _run(capsys, *MODES[mode], "--split", "A=a/**")
    assert rc == 2
    assert "--split only applies with --partition" in err


def test_split_with_lane_is_a_usage_error(repo: Path, capsys):
    rc, _, err = _run(capsys, "--lane", "docs", "--paths", "docs/**", "--split", "A=a/**")
    assert rc == 2
    assert "--split only applies with --partition" in err


@pytest.mark.parametrize("splits, message", [
    ([], "--partition needs at least 2 --split NAME=GLOB[,GLOB...]"),
    (["A=a/**"], "--partition needs at least 2 --split NAME=GLOB[,GLOB...]"),
    (["A=a/**", "A=b/**"], "--split: lane A is given twice"),
    (["A=a/**", "B"], "--split: 'B' is not NAME=GLOB[,GLOB...]"),
    (["A=a/**", "=b/**"], "--split: '=b/**' is not NAME=GLOB[,GLOB...]"),
    (["A=a/**", "B="], "--split: lane B has no glob"),
    (["A=a/**", "B=,"], "--split: lane B has an empty glob"),
    (["A=a/**", "B=b/**,,c"], "--split: lane B has an empty glob"),
    (["A=a/**", "B= "], "--split: lane B has an empty glob"),
    (["A=a/**", "B=../x"], "--split: lane B: glob '../x' climbs out of the workspace with '..'"),
    (["A=a/**", "B=b/\x07"], "--split: lane B has a glob with a control character"),
    (["A=a/**", "b c=x"], "--split: lane name 'b c' must match [A-Za-z0-9][A-Za-z0-9._-]*"),
    (["A=a/**", "-x=y"], "--split: lane name '-x' must match [A-Za-z0-9][A-Za-z0-9._-]*"),
])
def test_partition_refuses_a_bad_split(repo: Path, capsys, splits, message):
    argv = ["--partition"] + [f"--split={split}" for split in splits]  # '=': a value may start with '-'
    rc, out, err = _run(capsys, *argv)
    assert rc == 2
    assert message in err
    assert out == ""


def test_a_usage_error_in_json_mode_is_one_document(repo: Path, capsys):
    rc, out, _ = _run(capsys, "--partition", "--split", "A=a/**", "--json")
    payload = json.loads(out)
    assert rc == 2
    assert payload["source"] == "aegis check --partition"
    assert TS.match(payload["checked_at"]) and payload["status"] == "error"
    assert payload["error"].startswith("--partition needs at least 2 --split")
    assert payload["scope"]["workspace"] == str(repo)


# ── Namespaces built by hand (SDK callers) ───────────────────────────────────

def _namespace(repo: Path, **over) -> argparse.Namespace:
    values = dict(files=[], hook=False, strict=False, full=False, plan=None, plan_file=None, llm_cmd=None,
                  dry_run=False, format="text", json=False, workspace=str(repo), lane=None, base=None, paths=None,
                  base_policy=False)
    values.update(over)
    return argparse.Namespace(**values)


def test_run_verify_refuses_two_modes_given_together(repo: Path, capsys):
    assert run_verify(_namespace(repo, card=True, write_baseline=True)) == 2
    assert "--card and --write-baseline are modes of their own" in capsys.readouterr().err


def test_run_verify_treats_missing_mode_attributes_as_not_given(repo: Path, capsys):
    """Callers that build their own namespace (older SDK callers) never set the v4.2 options."""
    assert run_verify(_namespace(repo, files=["a/one.py"], dry_run=True, format="json")) == 0
    assert json.loads(capsys.readouterr().out)["files"] == ["a/one.py"]


# ── Help ─────────────────────────────────────────────────────────────────────

def test_help_documents_each_mode(capsys):
    rc, out, _ = _run(capsys, "--help")
    assert rc == 0
    flat = " ".join(out.split())
    for flag in ("--partition", "--split NAME=GLOB[,GLOB...]", "--card", "--write-baseline", "--prune-baseline",
                 "--calibration"):
        assert flag in flat
    assert "self-attested" in flat and "base@" in flat
    assert "baseline: absent at base" in flat
