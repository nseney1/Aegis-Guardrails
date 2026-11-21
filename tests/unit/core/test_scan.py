"""The scan service (aegis_core.scan): what aegis_scan and `aegis scan` return.

Same rules for the same files everywhere (one loader, one matcher), ranked by ledger
fitness, mandatory rules capped at two slots and reported when omitted, the scan
failing closed when a rule cannot be loaded, and rules edited since `aegis sync`
listed but still served.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import aegis_core.scan as scan_service
from aegis_core import sync
from aegis_core.scan import MANDATORY_SLOT_CAP, NO_CHANGES_TEXT, RULE_CACHE, scan
from aegis_core.telemetry_engine import ledger
from tests.conftest import symlink_or_skip

_DIRS = {"trap": "traps", "invariant": "invariants", "gate": "gates", "persona": "personas"}


def _rule(ws: Path, rule_id: str, rule_type: str = "trap", targets=("src/*.py",), enforcement: str = "",
          extra: str = "") -> Path:
    path = ws / ".aegis" / "rules" / _DIRS[rule_type] / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = enforcement or ("gate" if rule_type in ("invariant", "gate") else "advisory")
    lines = "".join(f"  - '{t}'\n" for t in targets)
    path.write_text(
        f"---\nid: {rule_id}\ntype: {rule_type}\nenforcement: {enforcement}\n"
        f"hypothesis: Hypothesis of {rule_id}\ntarget_paths:\n{lines}{extra}---\nDetail of {rule_id}.\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def _fresh_cache():
    RULE_CACHE.invalidate()
    yield
    RULE_CACHE.invalidate()


def _names(result: dict) -> list:
    return [r["name"] for r in result["relevant_rules"]]


@pytest.mark.parametrize("failure,reason", [
    ("git", "scan inputs unavailable"),
    ("git_output_limit", "scan inputs over limit"),
    ("oserror", "scan inputs unavailable"),
    ("projection", "scan projection failed"),
    ("projection_raised", "scan projection failed"),
])
def test_installed_simulation_failure_reasons_are_fixed_and_recover(tmp_path, monkeypatch, failure, reason):
    """The installed path uses the shared fixed reasons, including a typed Git output limit.

    The first call, a repeat and concurrent calls agree. Recovery returns the installed verdict.
    Diagnostics from the failure are not copied into the result.
    """
    from concurrent.futures import ThreadPoolExecutor

    _rule(tmp_path, "kept")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("value = 1\n", encoding="utf-8")
    real_changed = scan_service.gitsafe.changed_files
    real_select = scan_service.select_guidance

    def git_error(*_args, **_kwargs):
        code = "git_output_limit" if failure == "git_output_limit" else "git_failed"
        raise scan_service.gitsafe.GitError("UNTRUSTED\nsecret", code=code)

    def os_error(*_args, **_kwargs):
        raise OSError("UNTRUSTED\nsecret")

    if failure == "projection":
        monkeypatch.setattr(scan_service.gitsafe, "changed_files", lambda *_a, **_k: ["src/a.py"])
        monkeypatch.setattr(scan_service, "select_guidance", lambda *_a, **_k: {"status": "FAIL", "error": "UNTRUSTED\nsecret"})
    elif failure == "projection_raised":
        from aegis_core.guidance_projection import GuidanceProjectionError

        def raise_projection(*_args, **_kwargs):
            raise GuidanceProjectionError("UNTRUSTED\nsecret")

        monkeypatch.setattr(scan_service.gitsafe, "changed_files", lambda *_a, **_k: ["src/a.py"])
        monkeypatch.setattr(scan_service, "select_guidance", raise_projection)
    elif failure == "oserror":
        monkeypatch.setattr(scan_service.gitsafe, "changed_files", os_error)
    else:
        monkeypatch.setattr(scan_service.gitsafe, "changed_files", git_error)
    expected = {"kept": "not evaluated: " + reason}
    first = _simulate(tmp_path)
    assert first == expected
    assert "UNTRUSTED" not in repr(first)
    assert "\n" not in first["kept"] and "\r" not in first["kept"]
    assert _simulate(tmp_path) == first
    with ThreadPoolExecutor(max_workers=3) as pool:
        concurrent = list(pool.map(lambda _: _simulate(tmp_path), range(3), timeout=30))
    assert concurrent == [first, first, first]
    monkeypatch.setattr(scan_service, "select_guidance", real_select)
    monkeypatch.setattr(scan_service.gitsafe, "changed_files", real_changed)
    monkeypatch.setattr(scan_service.gitsafe, "changed_files", lambda *_a, **_k: ["src/a.py"])
    recovered = {"kept": "scan simulation: selected in all profiles"}
    assert _simulate(tmp_path) == recovered
    assert _simulate(tmp_path) == recovered


def test_seven_argument_simulation_hooks_still_simulate(tmp_path, monkeypatch):
    """Callers that predate fail_status still simulate through the shared default."""
    from aegis_core.rule_inventory import inventory_rules
    from aegis_core.rules import load_rules
    from aegis_core.scan_simulation import SimulationHooks, simulate_rule_selection

    _rule(tmp_path, "kept")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(scan_service.gitsafe, "changed_files", lambda *_a, **_k: ["src/a.py"])
    inventory = inventory_rules(tmp_path)
    ruleset = load_rules(tmp_path, inventory=inventory)
    hooks = SimulationHooks(
        scan_service._scan, scan_service._ScanResult, scan_service.select_guidance,
        scan_service.for_rules, scan_service._cold_rules, scan_service._COLD_OUTPUT_LIMIT,
        scan_service._COLD_MATCH_BUDGET)
    assert len(hooks.__dataclass_fields__) == 8
    first = simulate_rule_selection(tmp_path, inventory, ruleset, hooks)
    assert first == {"kept": "scan simulation: selected in all profiles"}
    assert hooks.fail_status == scan_service._STATUS_FAIL
    assert simulate_rule_selection(tmp_path, inventory, ruleset, hooks) == first


def test_reviewed_blob_over_custody_cap_keeps_git_output_limit(tmp_path):
    """An 8 KiB reviewed blob under a 4 KiB custody cap stays a typed output limit.

    The ordinary scan response stays the reviewed-base failure. The simulation
    refuses every installed candidate, then recovers when the cap is lifted.
    """
    from concurrent.futures import ThreadPoolExecutor

    repo = _git_repo(tmp_path)
    # Rank 2 so a body change is served from the reviewed blob, not the working copy.
    path = _write_rule(repo, "kept", "invariant")
    short = (repo.root / path).read_text(encoding="utf-8")
    reviewed = short.encode("utf-8")
    reviewed = reviewed + b"x" * (8192 - len(reviewed))
    repo.write(path, reviewed.decode("ascii"))
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    repo.write(path, short)
    repo.write("src/a.py", "value = 2\n")
    expected = {"kept": "not evaluated: scan inputs over limit"}

    def limited():
        with scan_service.gitsafe.custody(scratch=tmp_path, stdout_limit=4096):
            return _simulate(repo.root)

    first = limited()
    assert first == expected
    assert "\n" not in first["kept"] and "git custody" not in first["kept"]
    assert limited() == first
    # ThreadPoolExecutor does not copy contextvars, so each worker opens the cap itself.
    with ThreadPoolExecutor(max_workers=3) as pool:
        concurrent = list(pool.map(lambda _: limited(), range(3), timeout=30))
    with scan_service.gitsafe.custody(scratch=tmp_path, stdout_limit=4096):
        ordinary = scan(repo.root, ["src/a.py"])
    assert concurrent == [first, first, first]
    assert ordinary["status"] == "FAIL"
    assert ordinary["error"].startswith(
        "the reviewed (base) version of the rules cannot be read, so none is served:")
    assert "scan inputs over limit" not in ordinary["error"]
    recovered = {"kept": "not evaluated: candidate differs from scan snapshot"}
    assert _simulate(repo.root) == recovered
    assert _simulate(repo.root) == recovered


def test_simulation_refuses_oversized_size_only_inventory_before_selection(tmp_path, monkeypatch):
    from aegis_core.rule_inventory import MAX_RULE_BYTES, inventory_rules
    from aegis_core.rules import load_rules

    path = _rule(tmp_path, "oversized", "invariant")
    with path.open("ab") as stream:
        stream.write(b"x" * MAX_RULE_BYTES)
    inventory = inventory_rules(tmp_path)
    assert inventory.entries[0].content == b"" and inventory.entries[0].size > MAX_RULE_BYTES
    ruleset = load_rules(tmp_path, inventory=inventory)

    def forbidden(*args, **kwargs):
        pytest.fail("oversized source reached effective selection")

    monkeypatch.setattr(scan_service, "rule_integrity", SimpleNamespace(
        effective=forbidden, IntegrityError=scan_service.rule_integrity.IntegrityError))
    for _ in range(2):
        assert scan_service.simulate_rule_selection(tmp_path, inventory, ruleset) == {
            "oversized": "not evaluated: scan inputs over limit"}


def test_simulation_names_only_omitted_builtin_profiles_on_retry_and_concurrently(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import json

    from aegis_core.rule_inventory import inventory_rules
    from aegis_core.rules import load_rules
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES, scan_registry

    path = _rule(tmp_path, "sample")
    path.write_text(
        "---\nid: sample\ntype: trap\nhypothesis: Read safely\ntarget_paths: [src/**]\n---\n## Do\n"
        + "Use ${SLOT.TOOL_READ}. " * 10, encoding="utf-8")
    monkeypatch.setattr(scan_service.gitsafe, "changed_files", lambda *a, **k: ["src/a.py"])
    inventory = inventory_rules(tmp_path)
    ruleset = load_rules(tmp_path, inventory=inventory)
    sweep = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        for budget in range(100, 513):
            (tmp_path / ".aegis/config.json").write_text(json.dumps({"jit": {"max_tokens": budget}}), encoding="utf-8")
            scanned = {
                profile: scan(tmp_path, ["src/a.py"], registry=scan_registry(profile, tmp_path))
                for profile in PLATFORM_SLOT_PROFILES}
            assert all(result.get("status") != "FAIL" for result in scanned.values()), (budget, scanned)
            omitted = sorted(
                profile for profile, result in scanned.items() if "sample" not in result.exposure_rule_ids())
            sweep[budget] = omitted

        classes = {}
        for budget, omitted in sweep.items():
            classes.setdefault(tuple(omitted), []).append(budget)
        budgets = list(sweep)
        transitions = [
            (before, after) for before, after in zip(budgets, budgets[1:])
            if sweep[before] != sweep[after]]
        sampled = {
            budget for members in classes.values() for budget in (members[0], members[-1])}
        sampled.update(budget for transition in transitions for budget in transition)
        assert {tuple(sweep[budget]) for budget in sampled} == set(classes), sweep
        assert all(members[0] in sampled and members[-1] in sampled for members in classes.values()), sweep
        assert all(before in sampled and after in sampled for before, after in transitions), sweep

        for budget in sorted(sampled):
            (tmp_path / ".aegis/config.json").write_text(json.dumps({"jit": {"max_tokens": budget}}), encoding="utf-8")
            omitted = sweep[budget]
            message = ("scan simulation: not selected in profiles: " + ", ".join(omitted)
                       if omitted else "scan simulation: selected in all profiles")
            for _ in range(2):
                assert scan_service.simulate_rule_selection(tmp_path, inventory, ruleset) == {"sample": message}, sweep
            results = list(pool.map(
                lambda _: scan_service.simulate_rule_selection(tmp_path, inventory, ruleset), range(6), timeout=15))
            assert results == [{"sample": message}] * 6, sweep
    assert any(len(omitted) == len(PLATFORM_SLOT_PROFILES) for omitted in sweep.values()), sweep
    assert any(0 < len(omitted) < len(PLATFORM_SLOT_PROFILES) for omitted in sweep.values()), sweep
    assert any(not omitted for omitted in sweep.values()), sweep


def test_scan_returns_the_rules_whose_patterns_match(tmp_path: Path) -> None:
    _rule(tmp_path, "trap-src", targets=("src/**/*.py",))  # **/ is zero dirs: src/a.py matches
    _rule(tmp_path, "trap-docs", targets=("docs/*.md",))

    result = scan(tmp_path, ["src/a.py"])

    assert _names(result) == ["trap-src"]
    item = result["relevant_rules"][0]
    assert item["_path"] == ".aegis/rules/traps/trap-src.md"
    assert item["matched_files"] == ["src/a.py"] and item["fitness"] is None  # no verdicts: below MIN_N
    assert "trap-src" in result["guidance"]
    assert result["stats"]["total_rules"] == 2 and result["stats"]["matched"] == 1
    assert result["omitted_mandatory"] == [] and result["stale_rules"] == []
    assert "status" not in result


def test_without_changed_files_nothing_is_staged(tmp_path: Path) -> None:
    _rule(tmp_path, "t")
    result = scan(tmp_path, [])  # not a git repository: no diff either
    assert result["guidance"] == NO_CHANGES_TEXT and result["relevant_rules"] == []


def test_mandatory_rules_take_at_most_two_slots_and_the_rest_are_reported(tmp_path: Path) -> None:
    """Three self-declared mandatory rules on `**` used to starve every advisory rule."""
    for name in ("trap-gate-a", "trap-gate-b", "trap-gate-c"):
        _rule(tmp_path, name, targets=("**",), enforcement="gate")
    _rule(tmp_path, "trap-advice")
    assert MANDATORY_SLOT_CAP == 2

    result = scan(tmp_path, ["src/a.py"], budget=3)

    assert _names(result) == ["trap-gate-a", "trap-gate-b", "trap-advice"]
    assert result["omitted_mandatory"] == [{"name": "trap-gate-c", "type": "trap", "reason": "slot_cap"}]
    assert result["stats"]["omitted_mandatory"] == 1
    assert "1 more mandatory rule applies to these files and was not shown: trap-gate-c" in result["guidance"]


def test_a_budget_below_the_cap_is_never_exceeded_by_mandatory_rules(tmp_path: Path) -> None:
    _rule(tmp_path, "gate-a", "gate")
    _rule(tmp_path, "gate-b", "gate")

    result = scan(tmp_path, ["src/a.py"], budget=1)

    assert _names(result) == ["gate-a"]
    assert result["omitted_mandatory"] == [{"name": "gate-b", "type": "gate", "reason": "slot_cap"}]


def test_with_equal_fitness_a_rule_naming_the_file_exactly_ranks_first(tmp_path: Path) -> None:
    _rule(tmp_path, "a-glob", targets=("src/*.py",))
    _rule(tmp_path, "z-exact", targets=("src/a.py",))

    result = scan(tmp_path, ["src/a.py"], budget=1)

    assert _names(result) == ["z-exact"]


def test_gates_outrank_invariants_outrank_self_declared_gates(tmp_path: Path) -> None:
    _rule(tmp_path, "a-declared", enforcement="gate")
    _rule(tmp_path, "b-invariant", "invariant")
    _rule(tmp_path, "c-gate", "gate")

    result = scan(tmp_path, ["src/a.py"], budget=3)

    assert _names(result) == ["c-gate", "b-invariant"]
    assert [o["name"] for o in result["omitted_mandatory"]] == ["a-declared"]


def test_advisory_rules_are_ranked_by_ledger_fitness_not_frontmatter(tmp_path: Path) -> None:
    # Frontmatter claims are ignored: fitness is read from the ledger.
    _rule(tmp_path, "trap-claims", extra="fitness:\n  score: 0.99\n  triggers: 100\n  true_positives: 100\n")
    _rule(tmp_path, "trap-proven")
    ledger.append(tmp_path, [
        {"rule": "trap-proven", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(25)
    ])

    result = scan(tmp_path, ["src/a.py"], budget=1)

    assert _names(result) == ["trap-proven"]
    assert result["relevant_rules"][0]["fitness"] > 0.7


def test_a_rule_that_cannot_be_loaded_fails_the_scan_closed(tmp_path: Path) -> None:
    _rule(tmp_path, "good")
    broken = tmp_path / ".aegis" / "rules" / "traps" / "broken.md"
    broken.write_text("---\nid: [unterminated\n---\nbody\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["status"] == "FAIL"
    assert ".aegis/rules/traps/broken.md" in result["error"]
    assert result["rule_errors"] == [
        {"path": ".aegis/rules/traps/broken.md", "error": "malformed YAML frontmatter: unterminated flow sequence"},
    ]
    assert "relevant_rules" not in result


def test_an_unknown_type_directory_fails_the_scan_instead_of_silently_not_applying(tmp_path: Path) -> None:
    legacy = tmp_path / ".aegis" / "rules" / "unsupported" / "invariant-x.md"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("---\nid: invariant-x\ntype: invariant\ntarget_paths: ['**']\n---\nb\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["status"] == "FAIL" and "cannot be served" in result["error"]


def test_an_unsafe_rules_tree_fails_closed(tmp_path: Path) -> None:
    _rule(tmp_path, "good")
    outside = tmp_path / "elsewhere.md"
    outside.write_text("---\nid: x\n---\n", encoding="utf-8")
    symlink_or_skip(outside, tmp_path / ".aegis" / "rules" / "traps" / "linked.md")

    result = scan(tmp_path, ["src/a.py"])

    assert result["status"] == "FAIL" and "cannot be read safely" in result["error"]


def test_expired_rules_and_files_outside_aegis_rules_are_never_served(tmp_path: Path) -> None:
    _rule(tmp_path, "trap-expired", extra="expired_at: '2026-01-01'\n")
    top = tmp_path / "rules"
    top.mkdir()
    (top / "providence.md").write_text("---\nid: providence\nnon_standard: true\n---\nAlways.\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["relevant_rules"] == [] and result["stats"]["total_rules"] == 0


def test_markdown_that_is_not_a_rule_is_a_warning(tmp_path: Path) -> None:
    _rule(tmp_path, "t")
    (tmp_path / ".aegis" / "rules" / "notes.md").write_text("# notes\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert _names(result) == ["t"]
    assert result["warnings"] == [
        "1 file under .aegis/rules is not a rule and was ignored (aegis status lists why): .aegis/rules/notes.md"
    ]


def test_many_ignored_files_cost_one_bounded_warning(tmp_path: Path) -> None:
    """A v3 init seeded presets into .aegis/rules (citadel has 18): every scan pays for the warning."""
    _rule(tmp_path, "t")
    for n in range(18):
        (tmp_path / ".aegis" / "rules" / f"preset-{n:02d}.md").write_text("# preset\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["warnings"] == [
        "18 files under .aegis/rules are not rules and were ignored (aegis status lists why): "
        ".aegis/rules/preset-00.md, .aegis/rules/preset-01.md, .aegis/rules/preset-02.md and 15 more"
    ]


def test_rules_edited_since_sync_are_listed_and_still_served(tmp_path: Path) -> None:
    path = _rule(tmp_path, "t")
    sync.sync(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace("Detail of t.", "Changed."), encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert _names(result) == ["t"]
    assert result["stale_rules"] == [{"id": "t", "path": ".aegis/rules/traps/t.md", "change": "edited"}]


def test_a_mandatory_rule_cut_by_the_token_budget_is_reported(tmp_path: Path) -> None:
    _rule(tmp_path, "inv", "invariant", extra="prediction: " + "x " * 400 + "\n")

    result = scan(tmp_path, ["src/a.py"], max_tokens=150)

    assert result["relevant_rules"] == []
    assert result["omitted_mandatory"] == [{"name": "inv", "type": "invariant", "reason": "token_budget"}]
    assert result["stats"]["omitted"] == 1 and result["stats"]["clamped"] is True
    assert result["stats"]["estimated_tokens"] <= 150


def _require_git():
    from tests.helpers_humangate import git_ok
    if not git_ok():
        pytest.skip("needs git")


def _rule_text(rule_id, kind="trap", targets=("src/**",), do="Read safely."):
    folder = {"trap": "traps", "invariant": "invariants", "gate": "gates"}[kind]
    enforcement = "advisory" if kind == "trap" else "gate"
    patterns = "".join(f"  - '{target}'\n" for target in targets)
    path = f".aegis/rules/{folder}/{rule_id}.md"
    text = (
        f"---\nid: {rule_id}\ntype: {kind}\nenforcement: {enforcement}\n"
        f"hypothesis: Hypothesis of {rule_id}.\n"
        f"target_paths:\n{patterns}---\n## Do\n{do}\n"
    )
    return path, text


def _git_repo(tmp_path):
    _require_git()
    from tests.helpers_humangate import Home, Repo
    return Repo(tmp_path / "repo", Home(tmp_path / "home"))


def _write_rule(repo, rule_id, kind="trap", targets=("src/**",), do="Read safely."):
    path, text = _rule_text(rule_id, kind, targets, do)
    repo.write(path, text)
    return path


def _simulate(root):
    from aegis_core.rule_inventory import inventory_rules
    from aegis_core.rules import load_rules
    inventory = inventory_rules(str(root))
    ruleset = load_rules(str(root), inventory=inventory)
    return scan_service.simulate_rule_selection(root, inventory, ruleset)


@pytest.mark.parametrize("reviewed_target,candidate_target", [
    ("legacy/**", "src/**"), ("src/**", "src/**"), ("src/**", "legacy/**")],
                         ids=["reviewed_unmatched", "reviewed_matched", "candidate_unmatched"])
@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("companion", [False, True])
@pytest.mark.parametrize("failure", ["none", "listing", "budget"])
def test_snapshot_mismatch_precedes_cold_selection_and_refusals(
        tmp_path, monkeypatch, reviewed_target, candidate_target, changed, companion, failure):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES

    repo = _git_repo(tmp_path)
    path = _write_rule(repo, "edited", "invariant", targets=(reviewed_target,), do="Read reviewed.")
    reviewed = (repo.root / path).read_bytes()
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "edited", "invariant", targets=(candidate_target,), do="UNTRUSTED candidate.")
    candidate = (repo.root / path).read_bytes()
    if companion:
        _write_rule(repo, "cold", "invariant")
    real_changed = scan_service.gitsafe.changed_files
    if changed:
        repo.write("src/a.py", "value = 2\n")
    else:
        monkeypatch.setattr(scan_service.gitsafe, "changed_files", lambda *_a, **_k: [])
    listed, seen = [], []
    state = {"failure": failure}
    real_list, real_select = scan_service.gitsafe.list_files, scan_service.select_guidance

    def list_files(*args, **kwargs):
        listed.append(True)
        if state["failure"] == "listing":
            raise OSError("UNTRUSTED\nsecret")
        return real_list(*args, **kwargs)

    def select(rules, *args, **kwargs):
        seen.extend(rule.raw for rule in rules.rules if rule.id == "edited")
        return real_select(rules, *args, **kwargs)

    monkeypatch.setattr(scan_service.gitsafe, "list_files", list_files)
    monkeypatch.setattr(scan_service, "select_guidance", select)
    if failure == "budget":
        monkeypatch.setattr(scan_service, "_COLD_MATCH_BUDGET", 1)
    expected = {"edited": "not evaluated: candidate differs from scan snapshot"}
    if companion:
        expected["cold"] = {"none": "scan simulation: would be selected in all profiles at cold start",
                            "listing": "not evaluated: scan inputs unavailable",
                            "budget": "not evaluated: simulation budget exceeded"}[failure]
    assert _simulate(repo.root) == expected
    assert bool(listed) is companion
    assert _simulate(repo.root) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30)) == [expected] * 3
    assert candidate not in seen
    state["failure"] = "none"
    monkeypatch.setattr(scan_service, "_COLD_MATCH_BUDGET", 16384)
    recovered = dict(expected)
    if companion:
        recovered["cold"] = "scan simulation: would be selected in all profiles at cold start"
    assert _simulate(repo.root) == recovered
    repo.write(path, reviewed.decode("utf-8"))
    recovered["edited"] = (
        "not evaluated: no changed files" if not changed else
        "scan simulation: selected in all profiles" if reviewed_target == "src/**" else
        "scan simulation: not selected in profiles: " + ", ".join(sorted(PLATFORM_SLOT_PROFILES)))
    assert _simulate(repo.root) == recovered
    assert _simulate(repo.root) == recovered
    repo.write(path, candidate.decode("utf-8"))
    repo.commit("accept exact candidate bytes")
    repo.write("src/a.py", "value = 3\n")
    monkeypatch.setattr(scan_service.gitsafe, "changed_files", real_changed)
    accepted = {"edited": (
        "scan simulation: selected in all profiles" if candidate_target == "src/**" else
        "scan simulation: not selected in profiles: " + ", ".join(sorted(PLATFORM_SLOT_PROFILES)))}
    if companion:
        # The accept commit serves this draft, so the installed wording applies.
        accepted["cold"] = "scan simulation: selected in all profiles"
    assert _simulate(repo.root) == accepted
    assert _simulate(repo.root) == accepted


@pytest.mark.parametrize("shape", ["pooled_only", "every_file_crowded", "amendment", "budget"])
@pytest.mark.parametrize("file_count", [2, 10, 12])
@pytest.mark.parametrize("target_kind", ["exact", "glob"])
def test_cold_selection_fidelity_matrix(tmp_path, monkeypatch, shape, file_count, target_kind):
    """Independent temporary rules exercise file selection, replacement and limits."""
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.fitness import Fitness
    from aegis_core.rules import load_rules
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES, scan_registry

    repo = _git_repo(tmp_path)
    files = [f"src/group{index:02d}/a.py" for index in range(file_count)]
    blockers = 2 if shape == "every_file_crowded" else 1
    for index, path in enumerate(files):
        repo.write(path, "value = 1\n")
        target = path if target_kind == "exact" else f"src/group{index:02d}/**"
        for slot in range(blockers):
            _write_rule(repo, f"gate{index:02d}-{slot}", "gate", targets=(target,))
    if shape == "amendment":
        _write_rule(repo, "candidate", "invariant", targets=("vendor/**",), do="Reviewed source.")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "candidate", "invariant", do="Replacement source.")
    repo.write(files[0], "value = 2\n")
    ruleset = load_rules(repo.root)
    assert not ruleset.errors
    assert {rule.id for rule in ruleset.rules} == {
        "candidate", *(f"gate{index:02d}-{slot}" for index in range(file_count) for slot in range(blockers))}
    fits = {rule.id: Fitness(rule=rule.id, score=0.0) for rule in ruleset.rules}
    sample = files[:10]
    for profile in PLATFORM_SLOT_PROFILES:
        def oracle(paths):
            return scan_service.select_guidance(
                ruleset, paths, 3, 2000, [], lambda served: {r.id: fits[r.id] for r in served},
                registry=scan_registry(profile, repo.root)).exposure_rule_ids()
        assert "candidate" not in oracle(sample)
        assert all(("candidate" in oracle([path])) == (blockers == 1) for path in sample)

    calls = []
    real_select = scan_service.select_guidance

    def record(rules, paths, *args, **kwargs):
        candidates = [rule for rule in rules.rules if rule.id == "candidate"]
        if candidates and b"Replacement source." in candidates[0].raw:
            assert len(candidates) == 1
            calls.append(tuple(paths))
        return real_select(rules, paths, *args, **kwargs)

    monkeypatch.setattr(scan_service, "select_guidance", record)
    if shape == "amendment":
        expected = "not evaluated: candidate differs from scan snapshot"
    elif shape == "budget":
        monkeypatch.setattr(scan_service, "_COLD_MATCH_BUDGET", 1)
        expected = "not evaluated: simulation budget exceeded"
    elif blockers == 2:
        expected = f"scan simulation: never served at cold start (0/{len(sample)})"
    else:
        expected = "scan simulation: would be selected in all profiles at cold start"
    first = _simulate(repo.root)
    assert first["candidate"] == expected
    if shape == "amendment":
        assert calls == []
    elif shape != "budget":
        assert calls == [(path,) for _ in PLATFORM_SLOT_PROFILES for path in sample]
    assert _simulate(repo.root) == first
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30)) == [first] * 3
    if shape == "budget":
        monkeypatch.setattr(scan_service, "_COLD_MATCH_BUDGET", 16384)
        assert _simulate(repo.root)["candidate"] == "scan simulation: would be selected in all profiles at cold start"


@pytest.mark.parametrize("failure", ["projection", "raised", "budget"])
@pytest.mark.parametrize("amended", [False, True])
def test_cold_later_file_failure_refuses_partial_verdict_and_recovers(tmp_path, monkeypatch, failure, amended):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.scan_simulation import SimulationBudget

    repo = _git_repo(tmp_path)
    repo.write("src/a.py", "value = 1\n")
    repo.write("src/b.py", "value = 1\n")
    if amended:
        _write_rule(repo, "candidate", "invariant", targets=("vendor/**",))
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "candidate", "invariant")
    real_select = scan_service.select_guidance

    def refuse(rules, paths, *args, **kwargs):
        if paths == ["src/b.py"]:
            if failure == "projection":
                return {"status": "FAIL", "error": "UNTRUSTED\nsecret"}
            if failure == "budget":
                raise SimulationBudget
            raise RuntimeError("UNTRUSTED\nsecret")
        return real_select(rules, paths, *args, **kwargs)

    monkeypatch.setattr(scan_service, "select_guidance", refuse)
    reason = {"projection": "scan projection failed", "raised": "scan inputs unavailable",
              "budget": "simulation budget exceeded"}[failure]
    expected = {"candidate": ("not evaluated: candidate differs from scan snapshot" if amended else
                              "not evaluated: " + reason)}
    assert _simulate(repo.root) == expected
    assert _simulate(repo.root) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30)) == [expected] * 3
    monkeypatch.setattr(scan_service, "select_guidance", real_select)
    assert _simulate(repo.root) == {"candidate": (
        "not evaluated: candidate differs from scan snapshot" if amended else
        "scan simulation: would be selected in all profiles at cold start")}


def test_cold_amendments_keep_other_reviewed_matchers_and_replace_only_themselves(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept", "gate")
    _write_rule(repo, "amended-gate", "gate", targets=("vendor/**",))
    _write_rule(repo, "amended-invariant", "invariant", targets=("vendor/**",))
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "amended-gate", "gate")
    _write_rule(repo, "amended-invariant", "invariant")
    _write_rule(repo, "cold", "invariant")
    repo.write("src/a.py", "value = 2\n")
    expected = {
        "kept": "scan simulation: selected in all profiles",
        "amended-gate": "not evaluated: candidate differs from scan snapshot",
        "amended-invariant": "not evaluated: candidate differs from scan snapshot",
        "cold": "scan simulation: would be selected in all profiles at cold start",
    }
    assert _simulate(repo.root) == expected
    assert _simulate(repo.root) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30)) == [expected] * 3


def test_unanchored_binding_rule_stays_on_installed_selection(tmp_path, monkeypatch):
    """A working rule with no anchor is installed; cold sampling must not run."""
    _rule(tmp_path, "cold", "invariant")

    def forbidden(*_args, **_kwargs):
        pytest.fail("cold sampling ran for an installed rule")

    monkeypatch.setattr(scan_service.gitsafe, "changed_files", lambda *_a, **_k: ["src/a.py"])
    monkeypatch.setattr(scan_service.gitsafe, "list_files", forbidden)
    assert _simulate(tmp_path) == {"cold": "scan simulation: selected in all profiles"}
    assert _simulate(tmp_path) == {"cold": "scan simulation: selected in all profiles"}


def test_cold_draft_is_selected_and_installed_rules_stay(tmp_path):
    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    repo.write("src/a.py", "value = 2\n")
    first = _simulate(repo.root)
    assert first == {
        "kept": "scan simulation: selected in all profiles",
        "cold": "scan simulation: would be selected in all profiles at cold start",
    }
    assert _simulate(repo.root) == first
    scanned = scan(repo.root, ["src/a.py"])
    assert _names(scanned) == ["kept"]


def test_cold_draft_with_no_changed_files_still_uses_a_sample(tmp_path):
    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    assert _simulate(repo.root) == {
        "kept": "not evaluated: no changed files",
        "cold": "scan simulation: would be selected in all profiles at cold start",
    }


def test_cold_draft_with_no_matching_sample_says_no_sample(tmp_path):
    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant", targets=("vendor/**",))
    repo.write("src/a.py", "value = 2\n")
    assert _simulate(repo.root) == {
        "kept": "scan simulation: selected in all profiles",
        "cold": "scan simulation: no sample for hypothetical cold start",
    }
    assert _simulate(repo.root)["cold"] == "scan simulation: no sample for hypothetical cold start"


def test_cold_drafts_each_receive_their_own_sample(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    repo = _git_repo(tmp_path)
    for index in range(11):
        repo.write(f"src/group{index:02d}/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    for index in range(11):
        _write_rule(repo, f"cold{index:02d}", "invariant", targets=(f"src/group{index:02d}/**",))
    repo.write("src/group00/a.py", "value = 2\n")
    first = _simulate(repo.root)
    assert len(first) == 11
    assert set(first.values()) == {"scan simulation: would be selected in all profiles at cold start"}
    assert _simulate(repo.root) == first
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30))
    assert results == [first] * 3


def test_broad_cold_draft_gets_its_own_sample_after_ten_narrow_drafts(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES

    repo = _git_repo(tmp_path)
    for index in range(10):
        repo.write(f"src/aaa{index:02d}.py", "value = 1\n")
        repo.write(f"src/narrow{index:02d}/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    for index in range(10):
        _write_rule(repo, f"cold{index:02d}", "invariant", targets=(f"src/narrow{index:02d}/**",))
    _write_rule(repo, "z-broad", "invariant")
    seen = []
    original = scan_service.select_guidance

    def record(ruleset, files, *args, **kwargs):
        seen.append((tuple(rule.id for rule in ruleset.rules), tuple(files)))
        return original(ruleset, files, *args, **kwargs)

    monkeypatch.setattr(scan_service, "select_guidance", record)
    first = _simulate(repo.root)
    assert set(first.values()) == {"scan simulation: would be selected in all profiles at cold start"}
    calls = [(ids, files) for ids, files in seen if files]
    assert len(calls) == 20 * len(PLATFORM_SLOT_PROFILES)
    assert all(len(ids) == 1 and len(files) == 1 for ids, files in calls)
    assert [files for ids, files in calls if ids == ("z-broad",)] == [
        (f"src/aaa{index:02d}.py",) for _ in PLATFORM_SLOT_PROFILES for index in range(10)]
    assert _simulate(repo.root) == first
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30))
    assert results == [first] * 3


@pytest.mark.parametrize("stage", ["sampling", "selection"])
def test_cold_matching_budget_bounds_every_stage_and_recovers(tmp_path, monkeypatch, stage):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import match as match_service
    from aegis_core.rules import load_rules

    repo = _git_repo(tmp_path)
    patterns = tuple(f"absent{index:04d}/**" for index in range(4500))
    if stage == "selection":
        _write_rule(repo, "installed", targets=patterns)
    for index in range(100):
        repo.write(f"src/a{index:03d}.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    cold_path = _write_rule(repo, "cold", "invariant", targets=patterns if stage == "sampling" else ("src/**",))
    assert not load_rules(repo.root).errors
    attempts = threading.local()
    original = match_service.matches

    def counted(pattern, path):
        attempts.count += 1
        assert attempts.count <= 16384, "cold simulation exceeded its pattern-by-path attempt budget"
        return original(pattern, path)

    monkeypatch.setattr(scan_service, "rule_match", SimpleNamespace(**{**vars(match_service), "matches": counted}))

    def run():
        attempts.count = 0
        result = _simulate(repo.root)
        assert result["cold"] == "not evaluated: simulation budget exceeded"
        assert attempts.count == (16384 if stage == "sampling" else 16378)
        if stage == "selection":
            assert result["installed"] == "not evaluated: no changed files"
        return result

    first = run()
    assert run() == first
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: run(), range(3), timeout=30))
    assert results == [first] * 3
    if stage == "selection":
        (repo.root / ".aegis/rules/traps/installed.md").unlink()
    repo.write(cold_path, _rule_text("cold", "invariant")[1])
    attempts.count = 0
    assert _simulate(repo.root)["cold"] == "scan simulation: would be selected in all profiles at cold start"


def _profile_simulation(root):
    import cProfile
    import pstats

    profiler = cProfile.Profile()
    result = profiler.runcall(_simulate, root)
    calls = sum(stats[1] for (filename, _line, name), stats in pstats.Stats(profiler).stats.items()
                if Path(filename).name == "scan.py" and name == "evaluate")
    return result, calls


@pytest.mark.parametrize("pressure", ["shared_rules", "profiles", "exact_ranking"])
def test_cold_global_budget_counts_cached_steps_and_exact_ranking(tmp_path, monkeypatch, pressure):
    """A scaled reviewer scenario stays below the unique-pair budget but exhausts steps."""
    from aegis_core import match as match_service
    from aegis_core.rules import load_rules

    repo = _git_repo(tmp_path)
    for index in range(10):
        repo.write(f"src/a{index:02d}.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    count, pattern_count = (20, 100) if pressure == "shared_rules" else (1, 1000)
    patterns = tuple(f"absent{index:04d}/**" for index in range(pattern_count))
    if pressure == "exact_ranking":
        patterns = ("*",) + patterns
    for index in range(count):
        _write_rule(repo, f"installed{index:02d}", targets=patterns)
    for index in range(3):
        _write_rule(repo, f"cold{index}", "invariant")
    assert not load_rules(repo.root).errors
    calls, matches = [], []
    real_select = scan_service.select_guidance

    def select(ruleset, files, *args, **kwargs):
        if files:
            calls.append(tuple(rule.id for rule in ruleset.rules if rule.type == "invariant"))
        return real_select(ruleset, files, *args, **kwargs)

    def match(pattern, path):
        matches.append((pattern, path))
        return match_service.matches(pattern, path)

    monkeypatch.setattr(scan_service, "select_guidance", select)
    monkeypatch.setattr(scan_service, "rule_match", SimpleNamespace(**{**vars(match_service), "matches": match}))
    result, steps = _profile_simulation(repo.root)
    assert {result[f"cold{index}"] for index in range(3)} == {
        "not evaluated: simulation budget exceeded"}
    # One denied step is observed, and no later draft/profile starts selection.
    assert steps == 16385
    assert len(matches) < 16384, "cache misses were confused with total evaluation steps"
    assert calls == [("cold0",)] * (9 if pressure == "shared_rules" else 17)
    assert {result[f"installed{index:02d}"] for index in range(count)} == {
        "not evaluated: no changed files"}


@pytest.mark.parametrize("budget,observed_steps", [(113, 113), (150, 151)])
def test_cold_step_budget_is_shared_across_drafts_and_resets_per_run(tmp_path, monkeypatch, budget, observed_steps):
    repo = _git_repo(tmp_path)
    for index in range(10):
        repo.write(f"src/a{index:02d}.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    for index in range(3):
        _write_rule(repo, f"cold{index}", "invariant")
    monkeypatch.setattr(scan_service, "_COLD_MATCH_BUDGET", budget)
    expected = {
        "cold0": "scan simulation: would be selected in all profiles at cold start",
        "cold1": "not evaluated: simulation budget exceeded",
        "cold2": "not evaluated: simulation budget exceeded",
    }
    assert _profile_simulation(repo.root) == (expected, observed_steps)
    assert _profile_simulation(repo.root) == (expected, observed_steps)
    monkeypatch.setattr(scan_service, "_COLD_MATCH_BUDGET", 1000)
    assert set(_simulate(repo.root).values()) == {"scan simulation: would be selected in all profiles at cold start"}


def test_cold_verdict_is_independent_of_sibling_diagnostics_at_a_token_limit(tmp_path):
    import json
    from concurrent.futures import ThreadPoolExecutor

    repo = _git_repo(tmp_path)
    repo.write("src/a.py", "value = 1\n")
    repo.write(".aegis/config.json", json.dumps({"jit": {"max_tokens": 255}}))
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "z", "gate")
    expected = _simulate(repo.root)["z"]
    assert expected == "scan simulation: would be selected in all profiles at cold start"
    for rule_id in ("a", "b"):
        _write_rule(repo, rule_id, "gate")
    assert _simulate(repo.root)["z"] == expected
    assert _simulate(repo.root)["z"] == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _simulate(repo.root)["z"], range(3), timeout=30))
    assert results == [expected] * 3


def test_cold_matching_deduplicates_identical_globs(tmp_path, monkeypatch):
    import threading
    from aegis_core import match as match_service

    repo = _git_repo(tmp_path)
    for index in range(100):
        repo.write(f"src/a{index:03d}.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant", targets=("absent/**",) * 4500)
    original = match_service.matches
    attempts = threading.local()
    attempts.count = 0

    def counted(pattern, path):
        attempts.count += 1
        assert attempts.count <= 16384, "duplicate globs consumed the matching budget"
        return original(pattern, path)

    monkeypatch.setattr(scan_service, "rule_match", SimpleNamespace(**{**vars(match_service), "matches": counted}))
    assert _simulate(repo.root)["cold"] == "scan simulation: no sample for hypothetical cold start"
    assert attempts.count == 101


def test_cold_test_exclusion_policy_does_not_rescan_patterns_for_every_path(tmp_path):
    import cProfile
    import pstats
    from aegis_core.rules import load_rules

    repo = _git_repo(tmp_path)
    for index in range(100):
        repo.write(f"tests/a{index:03d}.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    path, text = _rule_text("cold", "invariant", targets=tuple(f"absent{index:04d}/**" for index in range(4500)))
    repo.write(path, text.replace("---\n## Do", "forbid_ast: {calls: [eval]}\n---\n## Do"))
    assert not load_rules(repo.root).errors
    profiler = cProfile.Profile()
    assert profiler.runcall(_simulate, repo.root)["cold"] == "scan simulation: no sample for hypothetical cold start"
    policy_calls = sum(stats[0] for (_file, _line, name), stats in pstats.Stats(profiler).stats.items()
                       if name == "skips_tests")
    assert policy_calls <= 2, "test exclusion repeatedly rescanned thousands of globs for skipped paths"


def test_amended_rule_still_differs_while_a_cold_draft_is_judged(tmp_path):
    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    edited, reviewed = _rule_text("edited", "invariant", do="Read reviewed.")
    repo.write(edited, reviewed)
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    repo.write(edited, reviewed.replace("Read reviewed.", "Read candidate."))
    _write_rule(repo, "cold", "invariant")
    repo.write("src/a.py", "value = 2\n")
    assert _simulate(repo.root) == {
        "kept": "scan simulation: selected in all profiles",
        "edited": "not evaluated: candidate differs from scan snapshot",
        "cold": "scan simulation: would be selected in all profiles at cold start",
    }


def test_cold_draft_at_fitness_zero_loses_to_higher_ranked_rules(tmp_path, monkeypatch):
    """Ledger credit would serve the draft; the cold fitness of 0.0 must not."""
    from aegis_core.adjudication import Adjudications
    from aegis_core.fitness import for_rules
    from aegis_core.rule_inventory import inventory_rules
    from aegis_core.rules import load_rules
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES

    repo = _git_repo(tmp_path)
    _write_rule(repo, "a-gate", "gate")
    _write_rule(repo, "b-gate", "gate")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "m-cold", "gate")
    repo.write("src/a.py", "value = 2\n")
    ledger.append(repo.root, [
        {"rule": "m-cold", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(25)
    ])
    inventory = inventory_rules(str(repo.root))
    ruleset = load_rules(str(repo.root), inventory=inventory)
    real_fits = for_rules(repo.root, list(ruleset.served), adjudications=Adjudications())
    oracle = scan_service.select_guidance(
        ruleset, ["src/a.py"], 3, 2000, [],
        lambda served: {rule.id: real_fits[rule.id] for rule in served})
    assert "m-cold" in oracle.exposure_rule_ids()
    seen, asked = [], []
    real_select, real_fits_of = scan_service.select_guidance, scan_service.for_rules

    def record_select(rules, files, *args, **kwargs):
        seen.append((tuple(rule.id for rule in rules), tuple(files)))
        return real_select(rules, files, *args, **kwargs)

    def record_fits(workspace, rules, **kwargs):
        asked.append(tuple(rule.id for rule in rules))
        return real_fits_of(workspace, rules, **kwargs)

    monkeypatch.setattr(scan_service, "select_guidance", record_select)
    monkeypatch.setattr(scan_service, "for_rules", record_fits)
    expected = "scan simulation: never served at cold start (0/1)"
    assert _simulate(repo.root)["m-cold"] == expected
    assert _simulate(repo.root)["m-cold"] == expected
    cold_calls = [files for ids, files in seen if "m-cold" in ids]
    assert len(cold_calls) == len(PLATFORM_SLOT_PROFILES) * 2
    assert cold_calls
    assert all(0 < len(files) <= 10 for files in cold_calls)
    assert all("m-cold" not in ids for ids in asked)


def test_cold_draft_names_omitted_profiles(tmp_path):
    import json
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES

    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant", do="Use ${SLOT.TOOL_READ}. " * 10)
    repo.write("src/a.py", "value = 2\n")
    profiles = set(PLATFORM_SLOT_PROFILES)
    found = {"selected": False, "never": False, "partial": None}

    def check_budget(budget):
        (repo.root / ".aegis/config.json").write_text(
            json.dumps({"jit": {"max_tokens": budget}}), encoding="utf-8")
        message = _simulate(repo.root)["cold"]
        if message == "scan simulation: would be selected in all profiles at cold start":
            found["selected"] = True
        else:
            prefix = "scan simulation: never served at cold start (0/1)"
            if message == prefix:
                found["never"] = True
            else:
                assert message.startswith(prefix + " in profiles: "), message
                names = message[len(prefix + " in profiles: "):].split(", ")
                assert names == sorted(names) and set(names) < profiles
                found["partial"] = message
            assert _simulate(repo.root)["cold"] == message

    last_omitted = 120
    for budget in list(range(120, 721, 40)) + [2000]:
        check_budget(budget)
        if found["selected"]:
            if not found["partial"]:
                for fine_budget in range(last_omitted + 1, budget):
                    check_budget(fine_budget)
                    if found["partial"]:
                        break
            break
        last_omitted = budget
    assert found == {"selected": True, "never": True, "partial": found["partial"]}
    assert found["partial"]


@pytest.mark.parametrize("failure", ["missing", "oserror", "giterror", "projection", "raised", "limit"])
def test_cold_simulation_failures_are_fixed_and_retry(tmp_path, monkeypatch, failure):
    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    repo.write("src/a.py", "value = 2\n")
    real_select, real_list = scan_service.select_guidance, scan_service.gitsafe.list_files
    if failure == "missing":
        monkeypatch.setattr(scan_service.gitsafe, "list_files", lambda *_a, **_k: None)
        expected = "not evaluated: scan inputs unavailable"
    elif failure == "oserror":
        def explode(*_args, **_kwargs):
            raise OSError("UNTRUSTED\nsecret")
        monkeypatch.setattr(scan_service.gitsafe, "list_files", explode)
        expected = "not evaluated: scan inputs unavailable"
    elif failure == "giterror":
        def explode(*_args, **_kwargs):
            raise scan_service.gitsafe.GitError("UNTRUSTED\nsecret", code="git_failed")
        monkeypatch.setattr(scan_service.gitsafe, "list_files", explode)
        expected = "not evaluated: scan inputs unavailable"
    elif failure == "projection":
        def refuse(ruleset, *args, **kwargs):
            if any(rule.id == "cold" for rule in ruleset.rules):
                return {"status": "FAIL", "error": "UNTRUSTED\nsecret"}
            return real_select(ruleset, *args, **kwargs)
        monkeypatch.setattr(scan_service, "select_guidance", refuse)
        expected = "not evaluated: scan projection failed"
    elif failure == "raised":
        def refuse(ruleset, *args, **kwargs):
            if any(rule.id == "cold" for rule in ruleset.rules):
                raise RuntimeError("UNTRUSTED\nsecret")
            return real_select(ruleset, *args, **kwargs)
        monkeypatch.setattr(scan_service, "select_guidance", refuse)
        expected = "not evaluated: scan inputs unavailable"
    else:
        monkeypatch.setattr(
            scan_service.gitsafe, "list_files",
            lambda *_a, **_k: ["src/a.py"] * (scan_service._COLD_LIST_LIMIT + 1))
        expected = "not evaluated: scan inputs over limit"
    first = _simulate(repo.root)
    assert first["cold"] == expected and first["kept"] == "scan simulation: selected in all profiles"
    assert "UNTRUSTED" not in repr(first) and "\n" not in first["cold"]
    assert _simulate(repo.root) == first
    monkeypatch.setattr(scan_service, "select_guidance", real_select)
    monkeypatch.setattr(scan_service.gitsafe, "list_files", real_list)
    assert _simulate(repo.root)["cold"] == "scan simulation: would be selected in all profiles at cold start"


def test_cold_simulation_is_stable_across_concurrent_calls(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    repo.write("src/a.py", "value = 2\n")
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _simulate(repo.root), range(6), timeout=30))
    assert results == [results[0]] * 6
    assert results[0]["cold"] == "scan simulation: would be selected in all profiles at cold start"


def test_cold_listing_is_bounded_before_parsing_and_recovers(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    for index in range(20):
        repo.write(f"src/a{index:02d}.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    repo.write("src/a00.py", "value = 2\n")
    expected = {
        "kept": "scan simulation: selected in all profiles",
        "cold": "not evaluated: scan inputs over limit",
    }
    original_limit = scan_service._COLD_OUTPUT_LIMIT
    monkeypatch.setattr(scan_service, "_COLD_OUTPUT_LIMIT", 64)
    assert _simulate(repo.root) == expected
    assert _simulate(repo.root) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30))
    assert results == [expected] * 3
    with scan_service.gitsafe.custody(scratch=tmp_path, stdout_limit=4096):
        assert _simulate(repo.root)["cold"] == "scan simulation: would be selected in all profiles at cold start"
    monkeypatch.setattr(scan_service, "_COLD_OUTPUT_LIMIT", original_limit)
    assert _simulate(repo.root)["cold"] == "scan simulation: would be selected in all profiles at cold start"


def test_cold_sample_is_capped_and_drops_unsafe_paths(tmp_path, monkeypatch):
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES

    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    repo.write("src/a.py", "value = 2\n")
    good = [f"src/n{i:02d}.py" for i in range(12)]
    listed = ["../secret\nowned", "src/../src/a.py", "/tmp/secret.py", "src/a.py\n", ""] + good
    monkeypatch.setattr(scan_service.gitsafe, "list_files", lambda *_a, **_k: list(listed))
    seen = []
    real_select = scan_service.select_guidance

    def record(ruleset, files, *args, **kwargs):
        seen.append((tuple(rule.id for rule in ruleset.rules), tuple(files)))
        return real_select(ruleset, files, *args, **kwargs)

    monkeypatch.setattr(scan_service, "select_guidance", record)
    result = _simulate(repo.root)
    assert result["cold"] == "scan simulation: would be selected in all profiles at cold start"
    assert "secret" not in repr(result).lower()
    cold_files = [files for ids, files in seen if "cold" in ids]
    assert cold_files == [(path,) for _ in PLATFORM_SLOT_PROFILES for path in good[:10]]


def test_cold_sample_does_not_read_symlink_targets(tmp_path):
    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET_OUTSIDE = 1\n", encoding="utf-8")
    symlink_or_skip(outside, repo.root / "src" / "link.py")
    first = _simulate(repo.root)
    assert first["cold"] == "scan simulation: would be selected in all profiles at cold start"
    assert "SECRET_OUTSIDE" not in repr(first)
    other = tmp_path / "other.py"
    other.write_text("OTHER_SECRET = 1\n", encoding="utf-8")
    (repo.root / "src" / "link.py").unlink()
    symlink_or_skip(other, repo.root / "src" / "link.py")
    second = _simulate(repo.root)
    assert second["cold"] == first["cold"]
    assert "OTHER_SECRET" not in repr(second) and "SECRET_OUTSIDE" not in repr(second)


@pytest.mark.parametrize("mode", ["installed", "cold"])
@pytest.mark.parametrize("failure,reason", [
    ("git", "scan inputs unavailable"),
    ("git_output_limit", "scan inputs over limit"),
    ("projection", "scan projection failed"),
    ("projection_raised", "scan projection failed"),
    ("oserror", "scan inputs unavailable"),
])
def test_installed_and_cold_failure_reasons_agree_then_recover(tmp_path, monkeypatch, mode, failure, reason):
    """Installed and cold paths share one fixed reason for each failure, then recover.

    A capture failure refuses every candidate. A cold-only failure leaves the installed verdict.
    The first call, a repeat, and concurrent calls agree, and none of them echo the diagnostic.
    """
    from concurrent.futures import ThreadPoolExecutor

    repo = _git_repo(tmp_path)
    _write_rule(repo, "kept")
    repo.write("src/a.py", "value = 1\n")
    repo.commit("base")
    repo.branch("work")
    _write_rule(repo, "cold", "invariant")
    if failure == "projection_raised" and mode == "cold":
        _write_rule(repo, "cold_b", "invariant")
    repo.write("src/a.py", "value = 2\n")
    real_changed = scan_service.gitsafe.changed_files
    real_list = scan_service.gitsafe.list_files
    real_select = scan_service.select_guidance

    def git_error(*_args, **_kwargs):
        code = "git_output_limit" if failure == "git_output_limit" else "git_failed"
        raise scan_service.gitsafe.GitError("UNTRUSTED\nsecret", code=code)

    def os_error(*_args, **_kwargs):
        raise OSError("UNTRUSTED\nsecret")

    def project_fail(ruleset, *args, **kwargs):
        from aegis_core.guidance_projection import GuidanceProjectionError

        cold_here = any(getattr(rule, "id", None) == "cold" for rule in getattr(ruleset, "rules", ()))
        if mode == "cold":
            if cold_here:
                if failure == "projection_raised":
                    raise GuidanceProjectionError("UNTRUSTED\nsecret")
                return {"status": "FAIL", "error": "UNTRUSTED\nsecret"}
            return real_select(ruleset, *args, **kwargs)
        if failure == "projection_raised":
            raise GuidanceProjectionError("UNTRUSTED\nsecret")
        return {"status": "FAIL", "error": "UNTRUSTED\nsecret"}

    if failure in ("projection", "projection_raised"):
        monkeypatch.setattr(scan_service, "select_guidance", project_fail)
    elif mode == "installed":
        monkeypatch.setattr(scan_service.gitsafe, "changed_files", os_error if failure == "oserror" else git_error)
    else:
        monkeypatch.setattr(scan_service.gitsafe, "list_files", os_error if failure == "oserror" else git_error)

    refused = "not evaluated: " + reason
    if mode == "installed":
        expected = {"kept": refused, "cold": refused}
    else:
        expected = {"kept": "scan simulation: selected in all profiles", "cold": refused}
        if failure == "projection_raised":
            expected["cold_b"] = refused
    first = _simulate(repo.root)
    assert first == expected
    assert "UNTRUSTED" not in repr(first)
    assert all("\n" not in value and "\r" not in value for value in first.values())
    assert _simulate(repo.root) == first
    with ThreadPoolExecutor(max_workers=3) as pool:
        concurrent = list(pool.map(lambda _: _simulate(repo.root), range(3), timeout=30))
    assert concurrent == [first, first, first]
    monkeypatch.setattr(scan_service.gitsafe, "changed_files", real_changed)
    monkeypatch.setattr(scan_service.gitsafe, "list_files", real_list)
    monkeypatch.setattr(scan_service, "select_guidance", real_select)
    recovered = {
        "kept": "scan simulation: selected in all profiles",
        "cold": "scan simulation: would be selected in all profiles at cold start",
    }
    if failure == "projection_raised" and mode == "cold":
        recovered["cold_b"] = "scan simulation: would be selected in all profiles at cold start"
    assert _simulate(repo.root) == recovered
    assert _simulate(repo.root) == recovered
