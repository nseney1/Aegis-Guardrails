"""Unit tests for v4.3 T4 credit model, Beta-Binomial/Clopper-Pearson bounds,
session decay, v4.4 §12.9 scope_basis neutrality, and AST allow overrides."""
from __future__ import annotations

from datetime import datetime, timezone
import math
from pathlib import Path

import pytest

from aegis_core import credit, fitness, sync
from aegis_core.ast.policy import (
    evaluate_forbid_ast_with_overrides,
    extract_normalized_ast,
    parse_allow_comments,
)
from aegis_core.lifecycle.promotion import suggest
from aegis_core.rules import load_rules
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
        f"---\n"
        f"# {rule_id}\n\nRule body for {rule_id}.\n"
    )
    path.write_text(text, encoding="utf-8")
    return path


def test_beta_cdf_ppf_and_clopper_pearson_bounds() -> None:
    # Uniform Beta(1, 1) has CDF(x) == x and PPF(p) == p.
    for x in (0.1, 0.25, 0.5, 0.75, 0.9):
        assert fitness.beta_cdf(x, 1.0, 1.0) == pytest.approx(x, abs=1e-6)
        assert fitness.beta_ppf(x, 1.0, 1.0) == pytest.approx(x, abs=1e-5)

    # Boundary conditions.
    assert fitness.beta_cdf(0.0, 2.0, 3.0) == 0.0
    assert fitness.beta_cdf(1.0, 2.0, 3.0) == 1.0
    assert fitness.beta_ppf(0.0, 2.0, 3.0) == 0.0
    assert fitness.beta_ppf(1.0, 2.0, 3.0) == 1.0

    # Clopper-Pearson 90% CI for 25/25 TP: lower bound >= 0.88, upper == 1.0.
    lo_25, hi_25 = fitness.clopper_pearson_interval(25.0, 0.0, 0.90)
    assert lo_25 >= 0.88
    assert hi_25 == 1.0

    # Clopper-Pearson 90% CI for 42 TP, 1 FP: lower bound >= 0.90.
    lo_42, hi_42 = fitness.clopper_pearson_interval(42.0, 1.0, 0.90)
    assert lo_42 >= 0.90
    assert hi_42 <= 1.0

    # Clopper-Pearson 90% CI for 2 TP, 8 FP (n=10): upper bound < 0.65.
    lo_bad, hi_bad = fitness.clopper_pearson_interval(2.0, 8.0, 0.90)
    assert 0.0 < lo_bad < hi_bad < 0.65


def test_cap_prior_mde_silence_credit_and_session_decay() -> None:
    # Prior mass <= 10 is preserved unchanged.
    assert fitness.cap_prior(4.0, 2.0) == (4.0, 2.0)
    # Prior mass > 10 is scaled down proportionally so alpha + beta == 10.
    a, b = fitness.cap_prior(450.0, 50.0)
    assert a == pytest.approx(9.0)
    assert b == pytest.approx(1.0)
    assert fitness.cap_prior(-1.0, -2.0) == (0.0, 0.0)

    # 180-day MDE at 80% power.
    assert fitness.compute_mde_180d(0.0) == 1.0
    mde_rare = fitness.compute_mde_180d(0.005)
    mde_frequent = fitness.compute_mde_180d(1.0)
    assert mde_rare > fitness.MDE_UNTESTABLE_THRESHOLD
    assert mde_frequent < 0.25

    # Silence credit LR = exp(c * RRR) gated by heartbeat and scope_basis.
    assert fitness.compute_silence_credit(0.8, c=0.1, heartbeat_alive=True) == pytest.approx(
        math.exp(0.08)
    )
    assert fitness.compute_silence_credit(0.8, c=0.1, heartbeat_alive=False) == 1.0
    assert (
        fitness.compute_silence_credit(
            0.8, c=0.1, heartbeat_alive=True, scope_basis="fallback_unscoped"
        )
        == 1.0
    )
    assert fitness.compute_silence_credit(0.0, c=0.1, heartbeat_alive=True) == 1.0

    # Session decay factor w = 2 ** (-delta / H).
    assert fitness.session_decay_factor(0, 20.0) == 1.0
    assert fitness.session_decay_factor(20, 20.0) == pytest.approx(0.5)
    assert fitness.session_decay_factor(60, 20.0) == pytest.approx(0.125)


def test_parse_allow_comments_and_rule_scoped_overrides(tmp_path: Path) -> None:
    source = (
        "def run(x):\n"
        "    a = eval(x)  # aegis: allow[gate-eval]: allowed for gate-eval only\n"
        "    b = exec(x)  # aegis: allow: wildcard allow with reason\n"
        "    c = eval(x)\n"
        "    return a\n"
    )
    parsed = parse_allow_comments(source)
    assert parsed[2] == [{"rules": {"gate-eval"}, "reason": "allowed for gate-eval only"}]
    assert parsed[3] == [{"rules": None, "reason": "wildcard allow with reason"}]
    assert 4 not in parsed

    norm_ast = extract_normalized_ast("src/app.py", workspace_root=tmp_path, code=source)
    assert norm_ast is not None

    # For gate-eval: line 2 is overridden, line 4 has no allow comment so eval remains a violation.
    v_eval, ov_eval = evaluate_forbid_ast_with_overrides(
        norm_ast, {"calls": ["eval"]}, rule_id="gate-eval", source=source
    )
    assert len(ov_eval) == 1
    assert ov_eval[0]["line"] == 2
    assert ov_eval[0]["reason"] == "allowed for gate-eval only"
    assert len(v_eval) == 1 and "eval" in v_eval[0]

    # For another-rule checking eval: line 2 targets gate-eval so it is NOT overridden for another-rule.
    v_other, ov_other = evaluate_forbid_ast_with_overrides(
        norm_ast, {"calls": ["eval"]}, rule_id="another-rule", source=source
    )
    assert ov_other == []
    assert len(v_other) == 1


def test_credit_event_writers_and_deduplication(tmp_path: Path) -> None:
    _write_rule(tmp_path, "trap", "r-one")

    # Exposure deduplicates (session, rule, scope_basis) so only 1 row is written.
    r1 = credit.record_exposure(
        tmp_path,
        "claude-code",
        "sess-1",
        ["r-one"],
        paths=["src/a.py"],
        scope_basis="match",
        heartbeat=True,
    )
    r2 = credit.record_exposure(
        tmp_path,
        "claude-code",
        "sess-1",
        ["r-one"],
        paths=["src/b.py"],
        scope_basis="match",
        heartbeat=True,
    )
    assert len(r1) == 1 and len(r2) == 0
    exp_rows = [r for r in credit.read_rows(tmp_path) if r.get("event") == "exposure"]
    assert len(exp_rows) == 1
    assert exp_rows[0]["paths"] == ["src/a.py"]

    # Detection deduplicates (rule, file, pattern, branch) and validates disposition.
    with pytest.raises(ValueError, match="disposition"):
        credit.record_detection(tmp_path, "r-one", "src/a.py", "eval", disposition="invalid")
    d1 = credit.record_detection(
        tmp_path, "r-one", "src/a.py", "eval", disposition="caught", branch="feat-1"
    )
    d2 = credit.record_detection(
        tmp_path, "r-one", "src/a.py", "eval", disposition="caught", branch="feat-1"
    )
    assert d1["weight"] == 0.5
    assert d1 == d2
    det_rows = [r for r in credit.read_rows(tmp_path) if r.get("event") == "detection"]
    assert len(det_rows) == 1

    # Adjudication validates verdict and adjudicator.
    with pytest.raises(ValueError, match="verdict"):
        credit.record_adjudication(tmp_path, "r-one", "maybe", adjudicator="human")
    with pytest.raises(ValueError, match="adjudicator"):
        credit.record_adjudication(tmp_path, "r-one", "tp", adjudicator="bot")
    adj = credit.record_adjudication(
        tmp_path, "r-one", "tp", adjudicator="pr", ref="PR-9", session="sess-1"
    )
    assert adj["verdict"] == "tp" and adj["adjudicator"] == "pr"

    # Override always writes status='contested' and deduplicates by (rule, file, line, rev).
    ov1 = credit.record_override(tmp_path, "r-one", "src/a.py", 10, "intended dynamic dispatch")
    ov2 = credit.record_override(tmp_path, "r-one", "src/a.py", 10, "intended dynamic dispatch")
    assert ov1["status"] == "contested"
    assert ov1 == ov2


def test_asymmetric_promotion_and_demotion_states(tmp_path: Path) -> None:
    _write_rule(tmp_path, "trap", "r-promote-25", created="2026-01-01")
    _write_rule(tmp_path, "trap", "r-inconclusive-one-session", created="2026-01-01")
    _write_rule(tmp_path, "invariant", "r-demote", created="2026-01-01")
    rules = {r.id: r for r in load_rules(tmp_path).served}
    now = datetime(2026, 2, 1, tzinfo=timezone.utc)

    # 25 TP / 0 FP across 3 sessions and 2 repos -> state == 'decided', suggestion == 'promote'.
    fit_ok = fitness.compute(
        {"triggers": 25, "tp": 25, "fp": 0},
        now=now,
        rule="r-promote-25",
        rule_type="trap",
        adjudicated_tp=25,
        adjudicated_fp=0,
        sessions_count=3,
        repos_count=2,
        days_span=31.0,
    )
    assert fit_ok.state == "decided"
    assert fit_ok.suggestion == "promote"
    assert suggest(rules["r-promote-25"], fit_ok, now=now) == "promote"

    # 25 TP / 0 FP but only 1 session -> state == 'inconclusive', no promotion.
    fit_narrow = fitness.compute(
        {"triggers": 25, "tp": 25, "fp": 0},
        now=now,
        rule="r-inconclusive-one-session",
        rule_type="trap",
        adjudicated_tp=25,
        adjudicated_fp=0,
        sessions_count=1,
        repos_count=2,
        days_span=31.0,
    )
    assert fit_narrow.state == "inconclusive"
    assert fit_narrow.suggestion is None
    assert suggest(rules["r-inconclusive-one-session"], fit_narrow, now=now) is None

    # 5 TP / 20 FP (n = MIN_N = 25, precision_hi < 0.65) -> state == 'decided', suggestion == 'demote'.
    fit_demote = fitness.compute(
        {"triggers": 25, "tp": 5, "fp": 20},
        now=now,
        rule="r-demote",
        rule_type="invariant",
        adjudicated_tp=5,
        adjudicated_fp=20,
        sessions_count=3,
        repos_count=1,
    )
    assert fit_demote.state == "decided"
    assert fit_demote.suggestion == "demote"
    assert suggest(rules["r-demote"], fit_demote, now=now) == "demote"

    # 2 TP / 8 FP is below MIN_N: insufficient, no number, no transition (R-evidence-8).
    fit_small = fitness.compute({"triggers": 10, "tp": 0, "fp": 0}, now=now, rule="r-demote",
                                rule_type="invariant", adjudicated_tp=2, adjudicated_fp=8)
    assert (fit_small.state, fit_small.suggestion, fit_small.status_label) == ("insufficient", None, "insufficient (n=10)")
    assert suggest(rules["r-demote"], fit_small, now=now) is None


@needs_git
def test_detector_replay_linear_history_fallback(tmp_path: Path) -> None:
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "repo", home)
    _write_rule(
        repo.root,
        "gate",
        "no-eval-exec",
        target_paths=["src/*.py"],
        forbid_calls=["eval", "exec"],
    )
    repo.write("src/app.py", "def f(x):\n    return x\n")
    repo.commit("initial")

    # Introduce eval and remove in a normal fix commit -> caught (0.5).
    repo.write("src/app.py", "def f(x):\n    return eval(x)\n")
    repo.commit("wip eval")
    repo.write("src/app.py", "def f(x):\n    return int(x)\n")
    repo.commit("replace eval with int")

    # Introduce exec and remove in a commit whose message says Revert -> leaked (1.0).
    repo.write("src/app.py", "def f(x):\n    exec(x)\n    return int(x)\n")
    repo.commit("add exec")
    repo.write("src/app.py", "def f(x):\n    return int(x)\n")
    repo.commit("Revert add exec")

    rows = fitness.replay_detector_history(repo.root, persist=False)
    by_pat = {r["pattern"]: r for r in rows}
    assert by_pat["eval"]["disposition"] == "caught"
    assert by_pat["eval"]["weight"] == pytest.approx(0.5)
    assert by_pat["exec"]["disposition"] == "leaked"
    assert by_pat["exec"]["weight"] == pytest.approx(1.0)
