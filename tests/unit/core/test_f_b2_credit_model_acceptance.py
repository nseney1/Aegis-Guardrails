"""Acceptance contract for lane f-b2-credit-model (v4.3 spec §3 T4, §9; v4.4 spec §12.9).

Given/When/Then scenarios written before the implementation:

1. Overrides never demote:
   Given six ``# aegis: allow`` overrides on a healthy gate, when ``sync`` runs,
   then they count as ``contested`` (override rate flagged for review), never as
   false positives (``fp == 0``), and no demotion is suggested.
2. Small n shows no number:
   Given 4 adjudicated labels, when ``status`` runs, then the rule shows
   ``insufficient (n=4)``, not a precision number.
3. A quiet trap decays:
   Given an insight-born trap exposed in 3H heartbeat-alive eligible sessions
   with no reinforcing evidence, when ``sync`` runs, then its evidence weight is
   0.125 of the original, and it becomes an archive candidate only below epsilon
   with no ``pin``; gates and invariants never archive on silence; and for scoped
   traps, doubt-served sessions (``scope_basis == "fallback_unscoped"``) are
   neutral (neither silence credit nor decay) per v4.4 §12.9.
4. Detector replay, feasibility & four sample-size states, asymmetric transitions
   with prior cap (<= 10 pseudo-labels and disclosure), and ``aegis sync --pr`` with
   3 sampled examples and no auto-merge. Silence earns no credit in 4.4.0 (R-evidence-17).
"""
from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
import subprocess

import pytest

from aegis_cli.status import run_status
from aegis_cli.sync import run_sync
from aegis_core import config, credit, fitness, sync
from aegis_core.verification.runner import run_layer1
from tests import helpers_adjudication as ha
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


def _write_rule(
    ws: Path,
    rule_type: str,
    rule_id: str,
    *,
    created: str = "2026-01-01",
    target_paths: list[str] | None = None,
    forbid_calls: list[str] | None = None,
    pin: bool = False,
    extra_frontmatter: str = "",
) -> Path:
    folder = {
        "trap": "traps",
        "invariant": "invariants",
        "gate": "gates",
        "persona": "personas",
    }[rule_type]
    path = ws / ".aegis" / "rules" / folder / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = "gate" if rule_type in ("gate", "invariant") else "advisory"
    paths = target_paths if target_paths is not None else ["src/*.py"]
    paths_yaml = "target_paths:\n" + "".join(f"  - '{p}'\n" for p in paths) if paths else ""
    forbid_yaml = ""
    if forbid_calls:
        calls_list = ", ".join(forbid_calls)
        forbid_yaml = f"forbid_ast:\n  calls: [{calls_list}]\n"
    pin_yaml = "pin: true\n" if pin else ""
    text = (
        f"---\n"
        f"id: {rule_id}\n"
        f"type: {rule_type}\n"
        f"enforcement: {enforcement}\n"
        f"hypothesis: test hypothesis for {rule_id}\n"
        f"created: '{created}'\n"
        f"{paths_yaml}"
        f"{forbid_yaml}"
        f"{pin_yaml}"
        f"{extra_frontmatter}"
        f"---\n"
        f"# {rule_id}\n\nRule body for {rule_id}.\n"
    )
    path.write_text(text, encoding="utf-8")
    return path


# ── 1. Overrides never demote ────────────────────────────────────────────────


def test_six_inline_allow_overrides_count_as_contested_and_never_demote_a_healthy_gate(
    tmp_path: Path,
) -> None:
    """§9 T4 Scenario 1: Given six `# aegis: allow` overrides on a healthy gate,
    when sync runs, then they count as `contested` (override rate flagged for review),
    never as false positives, and no demotion is suggested."""
    _write_rule(
        tmp_path,
        "gate",
        "gate-no-eval",
        target_paths=["src/*.py"],
        forbid_calls=["eval"],
    )
    # Healthy gate with 12 adjudicated true positives across 3 sessions, merged at the base (R-evidence-3).
    ha.write_labels(tmp_path, "gate-no-eval", [
        {"example_id": f"PR-{i + 1}", "verdict": "tp", "ref": f"PR-{i + 1}", "session": f"sess-{(i % 3) + 1}",
         "file": "src/app.py", "line": i + 1, "summary": f"Caught unsafe eval #{i + 1}"}
        for i in range(12)
    ])
    ha.merge_to_base(tmp_path)

    # Six `# aegis: allow` overrides in source code evaluated by Layer 1.
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    lines = ["def run_dynamic(x):\n"]
    for i in range(6):
        lines.append(f"    y_{i} = eval(x)  # aegis: allow: dynamic config {i}\n")
    lines.append("    return y_0\n")
    (src_dir / "app.py").write_text("".join(lines), encoding="utf-8")

    layer1_results = run_layer1(["src/app.py"], str(tmp_path), fast_mode=True)
    forbid_failures = [
        r for r in layer1_results if r.tool == "forbid_ast:gate-no-eval" and not r.verdict
    ]
    assert forbid_failures == [], "All 6 eval() calls were overridden with # aegis: allow"

    override_rows = [r for r in credit.read_rows(tmp_path) if r.get("event") == "override"]
    assert len(override_rows) == 6
    assert all(r.get("status") == "contested" and r.get("rule") == "gate-no-eval" for r in override_rows)

    result = sync.sync(tmp_path)
    gate_info = result.derived["rules"]["gate-no-eval"]
    assert gate_info["adjudicated_n"] == 12
    assert gate_info["contested"] == 6
    assert gate_info["fp"] == 0
    assert gate_info["flagged_for_review"] is True
    assert gate_info["override_rate"] > 0.0
    assert gate_info["suggestion"] is None


# ── 2. Small n shows no number ───────────────────────────────────────────────


def test_small_n_shows_insufficient_and_no_precision_number_in_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§9 T4 Scenario 2: Given 4 adjudicated labels, when status runs,
    then the rule shows `insufficient (n=4)`, not a precision."""
    _write_rule(tmp_path, "trap", "trap-small-n", target_paths=["src/*.py"])
    ha.write_labels(tmp_path, "trap-small-n", [
        {"example_id": f"adj-{i + 1}", "verdict": "tp" if i < 3 else "fp", "session": f"sess-{i + 1}"}
        for i in range(4)
    ])
    ha.merge_to_base(tmp_path)

    rc = run_status(argparse.Namespace(_root=tmp_path, plain=True))
    assert rc == 0
    out = capsys.readouterr().out
    rule_line = next((line for line in out.splitlines() if "trap-small-n" in line), "")
    assert "insufficient (n=4)" in rule_line
    # Must not display a precision decimal like 0.75 or 0.40 on the rule line.
    for forbidden in ("0.75", "75%", "0.40", "0.39"):
        assert forbidden not in rule_line

    rc_json = run_status(argparse.Namespace(_root=tmp_path, json=True))
    assert rc_json == 0
    payload = json.loads(capsys.readouterr().out)
    rule_json = next(r for r in payload["rules"] if r["name"] == "trap-small-n")
    assert rule_json["state"] == "insufficient"
    assert rule_json["score"] is None


def test_scan_status_and_list_rules_show_no_number_below_min_n_and_agree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R-evidence-8: Given n in (0, 1, MIN_N - 1) verdicts, When scan, status and list_rules
    run, Then none shows a number (`insufficient (n=N)`, or `no evidence yet` without any
    ledger row); Given exactly MIN_N, Then the number appears; ranking keeps the raw score."""
    from aegis_core.fitness import MIN_N
    from aegis_core.rules import load_rules
    from aegis_core.scan import RULE_CACHE, scan
    from aegis_core.telemetry_engine import ledger
    from aegis_mcp.registry import list_rules

    counts = {"trap-none": None, "trap-zero": 0, "trap-one": 1, "trap-low": MIN_N - 1, "trap-at": MIN_N}
    for rid, n in counts.items():
        _write_rule(tmp_path, "trap", rid, target_paths=["src/*.py"])
        if n is None:
            continue
        rows = [{"rule": rid, "outcome": "tp", "source": "ci", "key": f"{rid}-{i}"} for i in range(n)]
        ledger.append(tmp_path, rows or [{"rule": rid, "outcome": "trigger", "source": "ci", "key": f"{rid}-t"}])
    RULE_CACHE.invalidate()
    raw = fitness.for_rules(tmp_path, load_rules(tmp_path).served)

    result = scan(tmp_path, ["src/app.py"], budget=10, max_tokens=100000)
    shown = {r["name"]: r["fitness"] for r in result["relevant_rules"]}
    assert shown == {"trap-none": None, "trap-zero": None, "trap-one": None, "trap-low": None,
                     "trap-at": raw["trap-at"].score}
    assert raw["trap-at"].score > 0.8
    assert "Fitness: no evidence yet" in result["guidance"]
    for rid in ("trap-zero", "trap-one", "trap-low"):
        assert f"Fitness: insufficient (n={counts[rid]})" in result["guidance"]
    assert f"Fitness: {raw['trap-at'].score:.2f}" in result["guidance"]
    assert [r["name"] for r in result["relevant_rules"]] == sorted(raw, key=lambda rid: (-raw[rid].score, rid))

    assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 0
    status_scores = {r["name"]: r["score"] for r in json.loads(capsys.readouterr().out)["rules"]}
    assert {rid: status_scores[rid] for rid in counts} == shown

    listed = {r["id"]: r["fitness"] for r in list_rules(tmp_path)["rules"]}
    assert {rid: listed[rid]["reported_score"] for rid in counts} == shown
    assert {rid: listed[rid]["score"] for rid in counts} == {rid: raw[rid].score for rid in counts}
    assert listed["trap-low"]["status"] == f"insufficient (n={MIN_N - 1})"


# ── 3. A quiet trap decays (with v4.4 §12.9 scope_basis & immunities) ────────


def test_quiet_trap_decays_over_eligible_sessions_and_respects_pin_and_tier_immunities(
    tmp_path: Path,
) -> None:
    """§9 T4 Scenario 3 & v4.4 §12.9:
    Given an insight-born trap exposed in 3H heartbeat-alive eligible sessions
    with no reinforcing evidence, when sync runs, then its evidence weight is
    0.125 of the original, and it becomes an archive candidate only below epsilon
    with no pin; gates and invariants never archive on silence; doubt-served
    sessions (`scope_basis == 'fallback_unscoped'`) are neutral."""
    half_life = 20
    (tmp_path / ".aegis").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".aegis" / "config.json").write_text(
        json.dumps({"v": 1, "expiry": {"half_life_sessions": half_life, "epsilon": 0.15}}),
        encoding="utf-8",
    )

    _write_rule(tmp_path, "trap", "trap-quiet", target_paths=["src/*.py"])
    _write_rule(tmp_path, "trap", "trap-pinned", target_paths=["src/*.py"], pin=True)
    _write_rule(tmp_path, "invariant", "inv-quiet", target_paths=["src/*.py"])
    _write_rule(tmp_path, "gate", "gate-quiet", target_paths=["src/*.py"], forbid_calls=["eval"])

    # Expose all 4 rules in 3 * H = 60 heartbeat-alive eligible sessions (`scope_basis="match"`).
    for s in range(3 * half_life):
        credit.record_exposure(
            tmp_path,
            "claude-code",
            f"sess-match-{s}",
            ["trap-quiet", "trap-pinned", "inv-quiet", "gate-quiet"],
            paths=["src/app.py"],
            scope_basis="match",
            heartbeat=True,
        )

    # Also expose trap-quiet in 20 doubt-served sessions (`scope_basis="fallback_unscoped"`)
    # and 10 dead-heartbeat sessions (`heartbeat=False`): both must be neutral!
    for s in range(20):
        credit.record_exposure(
            tmp_path,
            "claude-code",
            f"sess-doubt-{s}",
            ["trap-quiet"],
            paths=["src/other.py"],
            scope_basis="fallback_unscoped",
            heartbeat=True,
        )
    for s in range(10):
        credit.record_exposure(
            tmp_path,
            "claude-code",
            f"sess-dead-{s}",
            ["trap-quiet"],
            paths=["src/app.py"],
            scope_basis="match",
            heartbeat=False,
        )

    result = sync.sync(tmp_path)
    rules = result.derived["rules"]

    # 3H = 60 eligible sessions -> decay_factor == 2**(-3) == 0.125.
    assert rules["trap-quiet"]["eligible_sessions"] == 60
    assert rules["trap-quiet"]["decay_factor"] == pytest.approx(0.125, abs=1e-6)
    assert rules["trap-quiet"]["effective_weight"] == pytest.approx(0.125, abs=1e-6)
    assert rules["trap-quiet"]["archive_candidate"] is True
    assert rules["trap-quiet"]["suggestion"] == "archive"

    # Pinned trap decays in weight but never becomes an archive candidate.
    assert rules["trap-pinned"]["effective_weight"] == pytest.approx(0.125, abs=1e-6)
    assert rules["trap-pinned"]["archive_candidate"] is False
    assert rules["trap-pinned"]["suggestion"] is None

    # Invariants and gates never archive on silence.
    assert rules["inv-quiet"]["archive_candidate"] is False
    assert rules["inv-quiet"]["suggestion"] is None
    assert rules["gate-quiet"]["archive_candidate"] is False
    assert rules["gate-quiet"]["suggestion"] is None


def test_quiet_sessions_only_decay_a_traps_score() -> None:
    """Given a trap with 30 triggers, 28 tp and 2 fp and H = 20, When it is computed after 0, 10, 20,
    60 and 600 eligible sessions, Then the score never rises and 3H sessions leave 0.125 of it."""
    scores = [fitness.compute({"triggers": 30, "tp": 28, "fp": 2}, eligible_sessions=s, half_life_sessions=20.0).score
              for s in (0, 10, 20, 60, 600)]
    assert scores == sorted(scores, reverse=True)
    assert scores == pytest.approx([0.8173, 0.5779, 0.4086, 0.1022, 0.0], abs=1e-4)
    assert scores[3] == pytest.approx(scores[0] * 0.125, abs=1e-3)


def test_three_exposed_sessions_are_three_eligible_sessions(tmp_path: Path) -> None:
    """Given a trap exposed in three sessions (exposure rows carry no heartbeat flag), When fitness is
    read, Then all three are eligible and the weight is 2^(-3/H) with the configured H."""
    _write_rule(tmp_path, "trap", "trap-seen")
    for s in range(3):
        credit.record_exposure(tmp_path, "claude-code", f"sess-{s}", ["trap-seen"], paths=["src/app.py"])
    fit = sync.build(tmp_path)["rules"]["trap-seen"]
    h = config.DEFAULT_HALF_LIFE_SESSIONS
    assert fit["eligible_sessions"] == 3 and fit["effective_weight"] == pytest.approx(2 ** (-3 / h), abs=1e-6)


def test_silence_earns_no_credit_in_4_4_0() -> None:
    """The silence likelihood ratio had no caller and no RRR source: it is gone, field and keyword too."""
    assert not hasattr(fitness, "compute_silence_credit") and "compute_silence_credit" not in fitness.__all__
    assert "silence_lr" not in {f.name for f in dataclasses.fields(fitness.Fitness)}
    with pytest.raises(TypeError):
        fitness.compute({"tp": 1}, silence_lr=2.0)


# ── 4. Detector replay, states, prior cap and sync --pr ──────────────────────


@needs_git
def test_detector_replay_classifies_caught_and_leaked_and_deduplicates_per_branch(
    tmp_path: Path,
) -> None:
    """§3 T4 Detector Replay:
    - Pattern in intermediate commit and removed before merge -> `caught` (weight 0.5).
    - Pattern in merged commit that was later reverted/fixed -> `leaked` (weight 1.0).
    - Deduplicated by `(rule, file, pattern, introducing commit)` (R-evidence-10)."""
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "repo", home)
    _write_rule(
        repo.root,
        "gate",
        "no-eval-exec",
        target_paths=["src/*.py"],
        forbid_calls=["eval", "exec"],
    )
    repo.write("src/app.py", "def f(x):\n    return x + 1\n")
    repo.commit("initial")

    # Feature branch 1: introduces eval(x) across two intermediate commits, removes before merge.
    repo.branch("feat-caught")
    repo.write("src/app.py", "def f(x):\n    return eval(x)\n")
    repo.commit("wip 1 with eval")
    repo.write("src/app.py", "def f(x):\n    # still eval\n    return eval(x)\n")
    repo.commit("wip 2 still with eval")
    repo.write("src/app.py", "def f(x):\n    return int(x)\n")
    repo.commit("clean up eval before merge")
    repo.git("checkout", "main")
    repo.git("merge", "--no-ff", "feat-caught", "-m", "Merge branch 'feat-caught'")

    # Feature branch 2: merges exec(x) into main, then later reverted/fixed on main.
    repo.branch("feat-leaked")
    repo.write("src/app.py", "def f(x):\n    exec(x)\n    return int(x)\n")
    repo.commit("introduce exec")
    repo.git("checkout", "main")
    repo.git("merge", "--no-ff", "feat-leaked", "-m", "Merge branch 'feat-leaked'")
    repo.write("src/app.py", "def f(x):\n    return int(x)\n")
    repo.commit("Revert leaked exec on main")

    detections = fitness.replay_detector_history(repo.root)
    by_pattern = {(d["rule"], d["file"], d["pattern"]): d for d in detections}
    assert ("no-eval-exec", "src/app.py", "eval") in by_pattern
    assert ("no-eval-exec", "src/app.py", "exec") in by_pattern
    assert by_pattern[("no-eval-exec", "src/app.py", "eval")]["disposition"] == "caught"
    assert by_pattern[("no-eval-exec", "src/app.py", "eval")]["weight"] == pytest.approx(0.5)
    assert by_pattern[("no-eval-exec", "src/app.py", "exec")]["disposition"] == "leaked"
    assert by_pattern[("no-eval-exec", "src/app.py", "exec")]["weight"] == pytest.approx(1.0)
    # Deduplicated: only 1 caught row for eval despite 2 intermediate commits on feat-caught.
    eval_rows = [d for d in detections if d["pattern"] == "eval"]
    assert len(eval_rows) == 1


def test_prior_cap_at_ten_pseudo_labels_and_asymmetric_transitions(tmp_path: Path) -> None:
    """§3 T4 Prior cap, feasibility, and asymmetric transitions:
    - Prior from a 500-verdict pack is capped at <= 10 pseudo-labels and discloses
      `prior supplies X% of the evidence`.
    - Untestable state when 180-day MDE at 80% power > 0.6.
    - Promote requires >=25 adjudicated labels with 0 FP (or >=42 with 1 FP) across
      >=3 sessions and >=2 repos (or >=14 days)."""
    alpha_c, beta_c = fitness.cap_prior(490.0, 10.0)
    assert alpha_c + beta_c == pytest.approx(10.0)

    fit_with_prior = fitness.compute(
        {"triggers": 6, "tp": 6, "fp": 0},
        rule="r-prior",
        prior=(490.0, 10.0),
    )
    assert fit_with_prior.prior_mass == pytest.approx(10.0)
    # 10 / (10 + 6) = 62.5% -> 62%
    assert fit_with_prior.prior_disclosure == "prior supplies 62% of the evidence"

    # Untestable rule: expected trigger rate 0.01/day -> 1.8 triggers in 180d -> MDE > 0.6.
    fit_untestable = fitness.compute(
        {"triggers": 0, "tp": 0, "fp": 0},
        rule="r-rare",
        trigger_rate_per_day=0.01,
    )
    assert fit_untestable.state == "untestable"
    assert fit_untestable.mde is not None and fit_untestable.mde > 0.6


def test_sync_pr_writes_transitions_with_three_examples_to_label_and_never_auto_merges(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§3 T4 Evidence-backed `aegis sync --pr`:
    When a rule reaches `decided`, `aegis sync --pr` writes the transition and opens a PR
    whose body contains the evidence report (state, n, weight) and up to 3 examples for a human
    to label (unlabelled replay detections, not labelled rows), via injectable `gh` runner, and
    never auto-merges."""
    _write_rule(tmp_path, "trap", "trap-decided", created="2026-01-01", target_paths=["src/*.py"])
    ha.write_labels(tmp_path, "trap-decided", [
        {"example_id": f"PR-{100 + i}", "verdict": "tp", "ref": f"PR-{100 + i}", "session": f"sess-{(i % 4) + 1}",
         "repo": f"repo-{(i % 2) + 1}", "file": "src/app.py", "line": 10 + i,
         "summary": f"Prevented bug example #{i + 1}"}
        for i in range(25)
    ])
    ha.merge_to_base(tmp_path)
    origin = tmp_path.parent / f"{tmp_path.name}-origin.git"
    ha._git(tmp_path.parent, "init", "-q", "--bare", str(origin))
    for args in (("config", "user.email", "dev@example.com"), ("config", "user.name", "Dev"),
                 ("remote", "add", "origin", str(origin)), ("push", "-q", "origin", "main"),
                 ("remote", "set-head", "origin", "main")):
        ha._git(tmp_path, *args)
    for n in range(4):
        credit.record_detection(tmp_path, "trap-decided", "src/app.py", f"call-{n}", disposition="leaked",
                                rev=f"{n:040x}")

    gh_calls: list[list[str]] = []

    def fake_gh(argv: list[str], cwd: str | None = None) -> object:
        gh_calls.append(list(argv))

        class _Res:
            returncode = 0
            stdout = "https://github.com/octo/proj/pull/42\n"
            stderr = ""

        return _Res()

    rc = run_sync(argparse.Namespace(_root=tmp_path, pr=True, json=True), gh_runner=fake_gh)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["pr"]["status"] == "opened"
    assert payload["pr"]["url"] == "https://github.com/octo/proj/pull/42"
    body = payload["pr"]["body"]
    assert "trap-decided" in body and "- **State**: decided; n = 25; weight" in body
    assert "Prevented bug example" not in body  # labelled rows are not samples to label
    listed = [line for line in body.splitlines() if line.startswith("  ") and "`call-" in line]
    assert len(listed) == 3 and "`call-0`" not in body  # the three newest detections
    # Exactly one gh call (`pr create`) for the pushed lifecycle branch, never `pr merge`.
    assert len(gh_calls) == 1
    assert gh_calls[0][:2] == ["pr", "create"] and payload["pr"]["branch"] in gh_calls[0]
    assert not any("merge" in call for call in gh_calls)


@needs_git
def test_end_to_end_claimed_to_recorded_to_landed_to_confirmed_to_scored_and_approved_protected_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end lifecycle: claimed -> recorded -> landed -> confirmed -> scored in fitness/status/sync,
    plus signed human approval unlocking protected-change credit, trailer divergence in check --ci,
    unavailable evidence state, and `aegis rule adjudicate` CLI."""
    from aegis_cli.cli import main
    from aegis_core import checkrun, human_gate
    from aegis_core.rules import load_rules
    from tests import helpers_verified as hv

    repo = hv.make_project(tmp_path)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(repo.home.path))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    hv.use_stub_runner(repo.home.path)
    priv_key, pub_key = hg.keygen(tmp_path / "keys", "human")
    repo.git("checkout", "main")
    repo.write("allowed_signers", hg.allowed_signers_text(pub_key))
    repo.commit("add allowed_signers on main")
    repo.git("checkout", "work")
    repo.git("merge", "main")

    # 1. Claimed (before checkrun.record)
    repo.write("src/app.py", "def app():\n    return 2\n")
    hv.mcp_call("aegis_scan", repo.root, session="s1", files=["src/app.py"])
    claim_res = hv.mcp_call("aegis_report_outcome", repo.root, session="s1", outcome="success",
                            rules_used=["trap-sample"], idempotency_key="k1")
    assert claim_res["status"] == "claimed"

    # 2. Recorded (witnessed) with protected conftest.py change
    repo.write("conftest.py", "# protected change\n")
    chk = checkrun.record(repo.root, tests=True, base="main")
    assert chk.status == "recorded" and chk.row["passed"] is True and chk.row["protected_changed"] is True
    rec_res = hv.mcp_call("aegis_report_outcome", repo.root, session="s1", outcome="success",
                          rules_used=["trap-sample"], idempotency_key="k2")
    assert rec_res["status"] == "recorded"
    assert credit.project_credits(repo.root).credits[0].state == "witnessed"

    # 3. Landed on main
    c_land = repo.commit("feat: update app and conftest")
    repo.git("branch", "-f", "main", c_land)
    assert credit.project_credits(repo.root).credits[0].state == "landed"

    # 4. Confirmed by CI, but withheld until conftest.py governance state is approved
    ci = hv.FakeCI([hv.ci_run(c_land, "success", head_branch="main")])
    credit.confirm(repo.root, client=ci, workflow=hv.CI_WORKFLOW)
    withheld = credit.project_credits(repo.root).credits[0]
    assert withheld.state == "confirmed" and withheld.counts is False and withheld.reason == "protected_changed"

    # 5. Signed governance approval unlocks credit and scores in fitness, status, and sync (deduplicated once)
    gov_hash = human_gate.governance_tree_hash(repo.root, c_land)
    c_app = repo.commit(human_gate.approval_message(gov_hash), sign_key=priv_key, allow_empty=True)
    repo.git("branch", "-f", "main", c_app)
    approved_proj = credit.project_credits(repo.root, client=hv.FakeCI([hv.ci_run(c_app, "success", head_branch="main")]),
                                           workflow=hv.CI_WORKFLOW)
    assert approved_proj.credits[0].state == "confirmed" and approved_proj.credits[0].counts is True
    assert len(approved_proj.outcome_rows) == 1

    s_res = sync.sync(repo.root, ci_client=hv.FakeCI([hv.ci_run(c_land, "success", head_branch="main"),
                                                      hv.ci_run(c_app, "success", head_branch="main")]))
    assert s_res.derived["rules"]["trap-sample"]["tp"] == 1
    assert s_res.derived["rules"]["trap-sample"]["triggers"] == 1

    # 6. CLI `aegis rule adjudicate` writes a working-tree label that counts only once merged (R-evidence-3)
    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    assert main(["rule", "adjudicate", "trap-sample", "tp", "--ref", "PR-1", "--summary", "good catch", "--json"]) == 0
    adj_out = json.loads(capsys.readouterr().out)
    assert (adj_out["status"], adj_out["path"]) == ("recorded", ".aegis/adjudications/trap-sample.jsonl")
    assert (adj_out["label"]["example_id"], adj_out["label"]["verdict"]) == ("PR-1", "tp")
    assert fitness.for_rules(repo.root, load_rules(repo.root).served)["trap-sample"].adjudicated_n == 0

    # 7. Corrupt ledger line -> evidence unavailable in fitness, status, and sync refuses transitions
    hv.ledger_path(repo.root).open("ab").write(b"{corrupt json line\n")
    capsys.readouterr()
    run_status(argparse.Namespace(_root=repo.root, plain=True))
    status_text = capsys.readouterr().out
    assert "evidence unavailable" in status_text
    refused_sync = sync.sync(repo.root, apply=True)
    assert refused_sync.refused is not None and "incomplete" in refused_sync.refused
    assert refused_sync.derived["rules"]["trap-sample"]["evidence_available"] is False


@needs_git
def test_repeated_sync_refreshes_reruns_and_new_landed_checks_and_fresh_status_stays_offline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """1. Repeated `sync.sync()` calls refresh CI on every call (revoking on later failure, querying newly landed commits).
    2. A fresh `status` process (`_VERIFIED_CI` cleared, no `client` passed) stays offline (R-trust-52): it makes no
       `gh` call and shows the rule without the CI-confirmed credit, which lives in the sync-derived document."""
    from aegis_core import checkrun, human_gate, rules
    from tests import helpers_verified as hv

    repo = hv.make_project(tmp_path)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(repo.home.path))
    hv.use_stub_runner(repo.home.path)

    # First check lands on main -> first sync confirms it
    repo.write("src/app.py", "def app():\n    return 10\n")
    hv.mcp_call("aegis_scan", repo.root, session="s1", files=["src/app.py"])
    checkrun.record(repo.root, tests=True, base="main")
    hv.mcp_call("aegis_report_outcome", repo.root, session="s1", outcome="success",
                rules_used=["trap-sample"], idempotency_key="k1")
    c1 = repo.commit("feat: first change")
    repo.git("branch", "-f", "main", c1)

    r1_ok = hv.ci_run(c1, "success", run_id=10, attempt=1, run_started_at="2026-10-17T10:00:00Z")
    s1 = sync.sync(repo.root, ci_client=hv.FakeCI([r1_ok]))
    assert s1.derived["rules"]["trap-sample"]["tp"] == 1

    # Fresh status process (empty _VERIFIED_CI) reads no GitHub and counts no unverified ci credit
    credit._VERIFIED_CI.clear()
    credit._UNAVAILABLE_CI.clear()
    gh_calls: list = []

    def counting_gh(argv, stdin=None, cwd=None, timeout=None):
        gh_calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, json.dumps({"workflow_runs": [r1_ok]}), "")

    monkeypatch.setattr(human_gate, "default_gh_runner", counting_gh)
    capsys.readouterr()
    run_status(argparse.Namespace(_root=repo.root, plain=True))
    status_out = capsys.readouterr().out
    assert gh_calls == []
    assert "insufficient (n=1)" not in status_out
    assert any(line.split()[:2] == ["trap-sample", "0"] for line in status_out.splitlines())
    assert s1.derived["rules"]["trap-sample"]["tp"] == 1

    # Later failed CI rerun on c1 -> second sync revokes c1 credit even though c1 was already in _VERIFIED_CI
    r1_fail = hv.ci_run(c1, "failure", run_id=11, attempt=2, run_started_at="2026-10-17T10:05:00Z")
    s2 = sync.sync(repo.root, ci_client=hv.FakeCI([r1_ok, r1_fail]))
    assert s2.derived["rules"]["trap-sample"]["tp"] == 0

    # Second check lands on main -> third sync queries c2 even though c1 was already cached
    repo.write("src/app.py", "def app():\n    return 20\n")
    hv.mcp_call("aegis_scan", repo.root, session="s2", files=["src/app.py"])
    checkrun.record(repo.root, tests=True, base="main")
    hv.mcp_call("aegis_report_outcome", repo.root, session="s2", outcome="success",
                rules_used=["trap-sample"], idempotency_key="k2")
    c2 = repo.commit("feat: second change")
    repo.git("branch", "-f", "main", c2)
    r2_ok = hv.ci_run(c2, "success", run_id=20, attempt=1, run_started_at="2026-10-17T10:10:00Z")
    s3 = sync.sync(repo.root, ci_client=hv.FakeCI([r1_ok, r1_fail, r2_ok]))
    assert s3.derived["rules"]["trap-sample"]["tp"] == 1
    assert fitness.for_rules(repo.root, rules.load_rules(repo.root).served)["trap-sample"].tp == 1


@needs_git
def test_check_ci_trailer_independently_reruns_snapshot_without_local_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Production `aegis check --ci` independently exports and reruns each commit's snapshot
    even when no local `check` row exists in the ledger, failing when the snapshot check fails."""
    from aegis_cli.cli import main
    from tests import helpers_verified as hv

    repo = hv.make_project(tmp_path)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(repo.home.path))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    hv.use_stub_runner(repo.home.path)

    # Make the commit's run_checks.py fail (exit 1) while its trailer falsely claims exit=0
    repo.write("run_checks.py", "import sys\nprint('1 failed in 0.01s')\nsys.exit(1)\n")
    repo.write("src/app.py", "def app():\n    return 99\n")
    tree = hv.tree_now(repo.root)
    repo.commit(f"feat: broken change with forged trailer\n\n{credit.format_trailer(tree, 0)}")
    # Ensure local ledger has NO check rows at all (just like a fresh CI checkout)
    assert credit.read_rows(repo.root) == []

    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    rc = main(["check", "--ci", "--base", "main", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert len(out["trailer_checks"]) == 1
    assert out["trailer_checks"][0]["result"] == "void"
    assert out["trailer_checks"][0]["failed"] is True


@needs_git
def test_detector_replay_ignores_unmerged_head_and_keeps_a_landed_finding_leaked_after_a_fix(
    tmp_path: Path,
) -> None:
    """`replay_detector_history` walks the target protected branch (`main`), ignoring unmerged feature
    commits on `HEAD`; a finding that landed stays `leaked` after a later fix (spec T4.1: "later removed
    by a fix or revert" is leaked), which the re-replay records as its `fix_rev` (R-evidence-10)."""
    from aegis_core import rules

    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "repo", home)
    _write_rule(
        repo.root,
        "gate",
        "no-eval-exec",
        target_paths=["src/*.py"],
        forbid_calls=["eval", "exec"],
    )
    repo.write("src/app.py", "def f(x):\n    return x + 1\n")
    repo.commit("initial")

    # Commit 1 on main introduces eval(x) (currently at tip of main -> leaked)
    repo.git("checkout", "main")
    repo.write("src/app.py", "def f(x):\n    return eval(x)\n")
    repo.commit("introduce eval on main")

    # Switch HEAD to an unmerged feature branch `work` that introduces exec(x)
    repo.branch("work")
    repo.write("src/app.py", "def f(x):\n    exec(x)\n    return 1\n")
    repo.commit("unmerged exec on work")

    # Replay while HEAD is on `work`: must walk `main`, recording `eval` as leaked and ignoring `exec` on `work`
    first_replay = fitness.replay_detector_history(repo.root)
    patterns_1 = {d["pattern"]: d["disposition"] for d in first_replay}
    assert patterns_1 == {"eval": "leaked"}
    fit_1 = fitness.for_rules(repo.root, rules.load_rules(repo.root).served)["no-eval-exec"]
    assert fit_1.leaked == 1 and fit_1.caught == 0

    # Now land a non-revert fix on `main` removing eval(x), while HEAD stays on `work`
    repo.git("checkout", "main")
    repo.write("src/app.py", "def f(x):\n    return int(x)\n")
    repo.commit("fix: replace eval with int on main")
    repo.git("checkout", "work")

    # Re-running replay supersedes the earlier row of the same unit: still `leaked`, now with its fix
    second_replay = fitness.replay_detector_history(repo.root)
    patterns_2 = {d["pattern"]: (d["disposition"], d["rev"]) for d in second_replay}
    assert patterns_2 == {"eval": ("leaked", first_replay[0]["rev"])}
    assert second_replay[0]["fix_rev"] is not None and first_replay[0]["fix_rev"] is None
    fit_2 = fitness.for_rules(repo.root, rules.load_rules(repo.root).served)["no-eval-exec"]
    assert fit_2.leaked == 1 and fit_2.caught == 0


def _trailer_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> hg.Repo:
    home = hg.Home(tmp_path / "home")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home.path))
    repo = hg.Repo(tmp_path / "repo", home)
    repo.write("src/app.py", "def value():\n    return 1\n")
    repo.write("tests/test_existing.py", "from src.app import value\n\ndef test_existing():\n    assert value() == 1\n")
    repo.commit("initial")
    repo.branch("work")
    return repo


def _trailer_commit(repo: hg.Repo, value: int) -> str:
    from tests import helpers_verified as hv

    repo.write("src/app.py", f"def value():\n    return {value}\n")
    tree = hv.tree_now(repo.root)
    repo.commit(f"feat: value {value}\n\n{credit.format_trailer(tree, 0)}")
    return tree


@needs_git
def test_only_the_head_commit_trailer_is_rerun(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Spec T1 compares the head commit's trailer: three trailer commits cost one rerun, for the head."""
    repo = _trailer_repo(tmp_path, monkeypatch)
    trees = [_trailer_commit(repo, value) for value in (2, 3, 4)]
    asked = []

    def spy(commit: str, tree: str) -> dict:
        asked.append((commit, tree))
        return {"tree": tree, "exit": 0}

    res = credit.verify_commit_trailers(repo.root, "main", "HEAD", rerun_fn=spy)
    assert asked == [(repo.head(), trees[-1])]
    assert [(r["commit"], r["result"]) for r in res] == [(repo.head(), "agree")]


@needs_git
def test_a_head_without_a_trailer_or_on_the_base_reruns_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _trailer_repo(tmp_path, monkeypatch)
    _trailer_commit(repo, 2)
    asked = []

    def spy(commit: str, tree: str) -> dict:
        asked.append(commit)
        return {"tree": tree, "exit": 0}

    repo.git("checkout", "-q", "main")
    repo.write("other.txt", "x\n")
    repo.commit("main moves on")
    repo.git("merge", "-q", "--no-ff", "--no-edit", "work")  # the head is a merge commit with no trailer
    assert credit.verify_commit_trailers(repo.root, "work", "HEAD", rerun_fn=spy) == []
    assert credit.verify_commit_trailers(repo.root, "main", "main", rerun_fn=spy) == []
    assert asked == []


@needs_git
def test_trailer_verification_works_in_a_fresh_credit_only_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``credit.verify_commit_trailers`` takes an explicit ``rerun_fn`` and never imports ``checkrun``."""
    import sys

    repo = _trailer_repo(tmp_path, monkeypatch)
    _trailer_commit(repo, 2)
    code = (
        "import json, sys\n"
        "from aegis_core import credit\n"
        "assert 'aegis_core.checkrun' not in sys.modules\n"
        "assert 'subprocess' not in credit.__dict__\n"
        "res = credit.verify_commit_trailers(sys.argv[1], 'main', 'HEAD', rerun_fn=lambda _c, t: {'tree': t, 'exit': 1})\n"
        "print(json.dumps(res))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code, str(repo.root)],
        capture_output=True, text=True, check=True,
    )
    parsed = json.loads(proc.stdout.strip())
    assert len(parsed) == 1
    assert parsed[0]["result"] == "void"
    assert parsed[0]["failed"] is True


@needs_git
def test_the_trailer_rerun_runs_the_whole_suite_with_the_record_recipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A head that breaks an unchanged test while its trailer claims a pass is caught: the rerun runs
    ``python -m pytest`` on the snapshot, as ``aegis check --record --tests`` does."""
    from aegis_core import checkrun
    from tests import helpers_verified as hv

    if not hv.hermetic_pytest_ok():
        pytest.skip("pytest is not importable by the hermetic interpreter (user-site install)")
    repo = _trailer_repo(tmp_path, monkeypatch)
    repo.write("pytest.ini", "[pytest]\npythonpath = .\n")
    repo.write("tests/test_new.py", "def test_new():\n    assert True\n")
    _trailer_commit(repo, 2)
    v_res = checkrun.verify_commit_trailers(repo.root, "main", "HEAD")
    assert len(v_res) == 1
    assert v_res[0]["result"] == "void"
    assert v_res[0]["failed"] is True


@needs_git
def test_detector_replay_walks_commits_after_merge_and_prefers_ahead_remote_branch(
    tmp_path: Path,
) -> None:
    """`replay_detector_history` detects violations introduced in ordinary commits after a merge commit
    and prefers `refs/remotes/origin/main` when local `refs/heads/main` is behind."""
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "repo", home)
    _write_rule(
        repo.root,
        "gate",
        "no-eval-exec",
        target_paths=["src/*.py"],
        forbid_calls=["eval", "exec"],
    )
    repo.write("src/app.py", "def f(x):\n    return x + 1\n")
    repo.commit("initial")

    # Create a harmless merge commit on `main`
    repo.branch("harmless")
    repo.write("README.md", "# docs\n")
    repo.commit("docs: readme")
    repo.git("checkout", "main")
    repo.write("NOTES.md", "# notes\n")
    repo.commit("docs: notes")
    repo.git("merge", "--no-ff", "harmless", "-m", "Merge branch 'harmless'")
    merge_oid = repo.git("rev-parse", "HEAD").strip()

    # Introduce an ordinary commit with `eval(x)` after the merge commit
    repo.write("src/app.py", "def f(x):\n    return eval(x)\n")
    ahead_oid = repo.commit("feat: ordinary commit with eval after merge")

    # Rewind local `refs/heads/main` to `merge_oid` while `refs/remotes/origin/main` points to `ahead_oid`
    repo.git("update-ref", "refs/remotes/origin/main", ahead_oid)
    repo.git("reset", "--hard", merge_oid)

    detections = fitness.replay_detector_history(repo.root)
    assert any(d["pattern"] == "eval" and d["disposition"] == "leaked" for d in detections)


def _golden_history(tmp_path: Path) -> hg.Repo:
    """A history with a caught call, a leaked import, a leaked call fixed later and an allowed site."""
    repo = hg.Repo(tmp_path / "repo", hg.Home(tmp_path / "home"))
    _write_rule(repo.root, "gate", "no-eval-exec", forbid_calls=["eval", "exec"])
    _write_rule(repo.root, "gate", "no-pickle", extra_frontmatter="forbid_ast:\n  imports: [pickle]\n")
    repo.write("src/app.py", "def f(x):\n    return x\n")
    repo.write("src/util.py", "def g(y):\n    return y\n")
    repo.commit("initial")
    repo.branch("feat-a")
    repo.write("src/app.py", "import pickle\n\ndef f(x):\n    return eval(x)\n")
    repo.commit("wip with eval and pickle")
    repo.write("src/app.py", "import pickle\n\ndef f(x):\n    return int(x)\n")
    repo.commit("drop eval")
    repo.git("checkout", "-q", "main")
    repo.git("merge", "--no-ff", "feat-a", "-m", "Merge branch 'feat-a'")
    repo.write("src/util.py", "def g(y):\n    exec(y)  # aegis: allow[no-eval-exec]: reviewed\n    exec(y + 1)\n")
    repo.commit("add exec")
    repo.write("src/util.py", "def g(y):\n    exec(y)  # aegis: allow[no-eval-exec]: reviewed\n    return y\n")
    repo.commit("fix exec")
    return repo


@needs_git
def test_replay_keys_of_a_recorded_history_are_unchanged(tmp_path: Path) -> None:
    """Golden (R-structure-38, R-checks-11): Given a recorded history, When replay runs, Then its
    (rule, file, pattern) keys, dispositions and commits are the ones recorded before findings
    replaced the parsed violation messages; an allowed site is never a finding."""
    repo = _golden_history(tmp_path)
    subject = {sha: repo.git("log", "-1", "--format=%s", sha) for sha in repo.git("rev-list", "--all").split()}
    found = {(d["rule"], d["file"], d["pattern"], d["disposition"], subject[d["rev"]],
              subject.get(d.get("fix_rev") or "", None)) for d in fitness.replay_detector_history(repo.root, persist=False)}
    assert found == {
        ("no-eval-exec", "src/app.py", "eval", "caught", "wip with eval and pickle", "Merge branch 'feat-a'"),
        ("no-pickle", "src/app.py", "pickle", "leaked", "Merge branch 'feat-a'", None),
        ("no-eval-exec", "src/util.py", "exec", "leaked", "add exec", "fix exec"),
    }


@needs_git
def test_sync_stores_where_replay_stopped_and_a_second_sync_appends_nothing(tmp_path: Path, monkeypatch) -> None:
    """R-evidence-12: Given a synced history, When sync runs again with no new commit, Then it
    resumes from the stored tip and the ledger is unchanged; a 4.3.3 document without the key
    replays everything."""
    repo = _golden_history(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    sync.sync(repo.root)
    replay = sync.read_derived(repo.root)["replay"]
    assert (replay["tip"], replay["branch"]) == (repo.git("rev-parse", "main"), "main")
    rows = credit.read_rows(repo.root)
    walked = []
    real = fitness._violations_at_commit
    monkeypatch.setattr(fitness, "_violations_at_commit", lambda root, sha, *a: walked.append(sha) or real(root, sha, *a))
    assert sync.sync(repo.root).replay.detections == [] and walked == []
    assert credit.read_rows(repo.root) == rows and sync.read_derived(repo.root)["replay"] == replay
    path = repo.root / ".aegis" / "state" / "derived.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc.pop("replay")
    path.write_text(json.dumps(doc), encoding="utf-8")
    sync.sync(repo.root)
    assert len(set(walked)) == len(repo.git("rev-list", "main").split()) and credit.read_rows(repo.root) == rows


@needs_git
def test_projecting_credit_never_imports_release_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """One CI-confirmation path (REST): ``project_credits`` does not reach ``release_verify`` (R-trust-67)."""
    import sys

    repo = _trailer_repo(tmp_path, monkeypatch)
    code = (
        "import sys\n"
        "from aegis_core import credit\n"
        "credit.project_credits(sys.argv[1], verify_ci=True)\n"  # no ci row: nothing asks gh
        "print('aegis_core.release_verify' in sys.modules)\n"
    )
    proc = subprocess.run([sys.executable, "-c", code, str(repo.root)], capture_output=True, text=True, check=True)
    assert proc.stdout.strip() == "False"
