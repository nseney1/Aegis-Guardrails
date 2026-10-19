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
   with prior cap (<= 10 pseudo-labels and disclosure), silence credit with
   heartbeat gate, and ``aegis sync --pr`` with 3 sampled examples and no auto-merge.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import subprocess

import pytest

from aegis_cli.status import run_status
from aegis_cli.sync import run_sync
from aegis_core import credit, fitness, sync
from aegis_core.verification.runner import run_layer1
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
    # Healthy gate with 12 adjudicated true positives across 3 sessions.
    for i in range(12):
        credit.record_adjudication(
            tmp_path,
            "gate-no-eval",
            "tp",
            adjudicator="human",
            ref=f"PR-{i + 1}",
            session=f"sess-{(i % 3) + 1}",
            file="src/app.py",
            line=i + 1,
            summary=f"Caught unsafe eval #{i + 1}",
        )

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
    for i in range(4):
        credit.record_adjudication(
            tmp_path,
            "trap-small-n",
            "tp" if i < 3 else "fp",
            adjudicator="human",
            ref=f"adj-{i + 1}",
            session=f"sess-{i + 1}",
        )

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


# ── 4. Detector replay, states, prior cap, silence credit, and sync --pr ─────


@needs_git
def test_detector_replay_classifies_caught_and_leaked_and_deduplicates_per_branch(
    tmp_path: Path,
) -> None:
    """§3 T4 Detector Replay:
    - Pattern in intermediate commit and removed before merge -> `caught` (weight 0.5).
    - Pattern in merged commit that was later reverted/fixed -> `leaked` (weight 1.0).
    - Deduplicated by `(rule, file, pattern, branch)`."""
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

    # Silence credit: LR = exp(c * RRR) only when heartbeat is alive.
    assert fitness.compute_silence_credit(0.5, c=0.1, heartbeat_alive=True) == pytest.approx(
        math.exp(0.05)
    )
    assert fitness.compute_silence_credit(0.5, c=0.1, heartbeat_alive=False) == 1.0
    assert (
        fitness.compute_silence_credit(
            0.5, c=0.1, heartbeat_alive=True, scope_basis="fallback_unscoped"
        )
        == 1.0
    )


def test_sync_pr_writes_transitions_with_three_sampled_examples_and_never_auto_merges(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§3 T4 Evidence-backed `aegis sync --pr`:
    When a rule reaches `decided`, `aegis sync --pr` writes the transition and opens a PR
    whose body contains the evidence report and up to 3 sampled examples, via injectable
    `gh` runner, and never auto-merges."""
    _write_rule(tmp_path, "trap", "trap-decided", created="2026-01-01", target_paths=["src/*.py"])
    for i in range(25):
        credit.record_adjudication(
            tmp_path,
            "trap-decided",
            "tp",
            adjudicator="human",
            ref=f"PR-{100 + i}",
            session=f"sess-{(i % 4) + 1}",
            repo=f"repo-{(i % 2) + 1}",
            file="src/app.py",
            line=10 + i,
            summary=f"Prevented bug example #{i + 1}",
        )

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
    assert "trap-decided" in body
    assert "Prevented bug example #1" in body
    assert "Prevented bug example #2" in body
    assert "Prevented bug example #3" in body
    # Exactly one gh call (`pr create`), never `pr merge`.
    assert len(gh_calls) == 1
    assert gh_calls[0][:2] == ["pr", "create"]
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

    # 6. CLI `aegis rule adjudicate` adds human adjudication
    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    assert main(["rule", "adjudicate", "trap-sample", "tp", "--ref", "PR-1", "--summary", "good catch", "--json"]) == 0
    adj_out = json.loads(capsys.readouterr().out)
    assert adj_out["event"] == "adjudication" and adj_out["verdict"] == "tp"

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
def test_repeated_sync_refreshes_reruns_and_new_landed_checks_and_fresh_status_verifies(
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
def test_detector_replay_ignores_unmerged_head_and_reconciles_leaked_to_caught_after_fix(
    tmp_path: Path,
) -> None:
    """`replay_detector_history` walks the target protected branch (`main`), ignoring unmerged feature
    commits on `HEAD`, and reconciles a previously recorded `leaked` finding to `caught` after a later fix."""
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

    # Re-running replay / sync reconciles the earlier `leaked` finding for `eval` to `caught`
    second_replay = fitness.replay_detector_history(repo.root)
    patterns_2 = {d["pattern"]: d["disposition"] for d in second_replay}
    assert patterns_2 == {"eval": "caught"}
    fit_2 = fitness.for_rules(repo.root, rules.load_rules(repo.root).served)["no-eval-exec"]
    assert fit_2.leaked == 0 and fit_2.caught == 1


@needs_git
def test_trailer_rerun_executes_unchanged_tests_and_works_in_fresh_credit_only_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a commit modifies `src/app.py` (breaking an existing unchanged test) and adds a new passing
    test file, trailer verification runs all snapshot tests (catching the broken unchanged test) and works
    in a fresh Python process that imports only `aegis_core.credit`."""
    import sys
    from aegis_core import checkrun
    from tests import helpers_verified as hv

    home = hg.Home(tmp_path / "home")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home.path))
    repo = hg.Repo(tmp_path / "repo", home)
    repo.write("src/app.py", "def value():\n    return 1\n")
    repo.write("tests/test_existing.py", "from src.app import value\n\ndef test_existing():\n    assert value() == 1\n")
    repo.commit("initial")

    # Branch and make a commit that breaks `test_existing.py` (without touching it) and adds `test_new.py`
    repo.branch("work")
    repo.write("src/app.py", "def value():\n    return 2\n")
    repo.write("tests/test_new.py", "def test_new():\n    assert True\n")
    tree = hv.tree_now(repo.root)
    repo.commit(f"feat: break existing test while adding passing test\n\n{credit.format_trailer(tree, 0)}")

    # 1. Layer 2 `checkrun.verify_commit_trailers` runs all snapshot tests and catches the broken unchanged test
    v_res = checkrun.verify_commit_trailers(repo.root, "main", "HEAD")
    assert len(v_res) == 1
    assert v_res[0]["result"] == "void"
    assert v_res[0]["failed"] is True

    # 2. Layer 1 `credit.verify_commit_trailers` requires an explicit `rerun_fn` (no import-order hook or subprocess spawn)
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
