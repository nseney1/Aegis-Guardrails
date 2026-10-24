"""CODEOWNERS parsing and coverage of the canonical governance set."""
from __future__ import annotations

import pytest

from aegis_core import governance
from aegis_core import codeowners
from tests import helpers_humangate as hg


# ── CODEOWNERS coverage ──────────────────────────────────────────────────────

def test_the_full_codeowners_covers_every_governance_sample():
    covered, uncovered = codeowners.codeowners_coverage(hg.CODEOWNERS_FULL)
    assert uncovered == [] and covered


def test_every_coverage_sample_is_a_governance_path():
    assert [s for s in codeowners.COVERAGE_SAMPLES if governance.category_of(s) is None] == []
    assert {"pytest.py", "pytest/__init__.x", "iniconfig.py", "py/__init__.x"} <= set(codeowners.COVERAGE_SAMPLES)


def test_a_codeowners_that_owns_only_the_source_init_of_a_runner_package_leaves_it_uncovered():
    """Given CODEOWNERS lines that own ``/pytest/__init__.py`` but not the package directory, When
    coverage is checked, Then a compiled ``__init__`` and the ``__main__`` of that package are uncovered."""
    narrow = hg.CODEOWNERS_FULL.replace("/pytest/ @octo\n", "/pytest/__init__.py @octo\n")
    _covered, uncovered = codeowners.codeowners_coverage(narrow, repo_paths=["pytest/__init__.py"])
    assert {"pytest/__init__.x", "pytest/__main__.x"} <= set(uncovered)
    assert "pytest/__init__.py" not in uncovered


def test_the_codeowners_lines_doctor_prints_cover_the_whole_set_it_checks():
    text = "\n".join(codeowners.codeowners_lines("@octo"))
    for location in (".github/CODEOWNERS", "CODEOWNERS"):
        assert codeowners.codeowners_coverage(text, location)[1] == []


NESTED_AND_LABEL_PATHS = (
    ".aegis/adjudications/r.jsonl",
    "svc/.aegis/rules/gates/x.md",
    "svc/.aegis/adjudications/r.jsonl",
    "svc/.aegis/config.json",
    "svc/.aegis/team.json",
    "a/b/.aegis/baseline.json",
)


def test_the_codeowners_lines_doctor_prints_own_labels_and_a_nested_workspace():
    """Given doctor's CODEOWNERS lines, When a repository tracks adjudication labels or a nested
    workspace's .aegis files, Then every one of them has an owner, so the tier does not drop."""
    assert all(governance.category_of(p) for p in NESTED_AND_LABEL_PATHS)
    text = "\n".join(codeowners.codeowners_lines("@octo"))
    _covered, uncovered = codeowners.codeowners_coverage(text, repo_paths=NESTED_AND_LABEL_PATHS)
    assert uncovered == []


def test_the_coverage_samples_include_labels_and_a_nested_workspace():
    assert {".aegis/adjudications/x", "svc/.aegis/rules/gates/x", "svc/.aegis/config.json"} <= set(
        codeowners.COVERAGE_SAMPLES
    )


PER_DIRECTORY = "".join(f"**/.aegis/rules/{d}/ @octo\n" for d in
                        ("invariants", "traps", "gates", "boundaries", "personas", "contracts"))


def test_six_per_directory_rule_owners_cover_the_rules_and_a_missing_one_is_named():
    """Given a CODEOWNERS that owns the six plural rule directories (not .aegis/rules/ itself) and every
    other sample, Then nothing is uncovered; without traps/, only the traps samples are."""
    full = hg.CODEOWNERS_FULL.replace("**/.aegis/rules/ @octo\n", "").replace("/.aegis/rules/ @octo\n", PER_DIRECTORY)
    assert "/.aegis/rules/ @octo" not in full.replace("**/.aegis/rules/", "")
    assert codeowners.codeowners_coverage(full)[1] == []
    _covered, uncovered = codeowners.codeowners_coverage(full.replace("**/.aegis/rules/traps/ @octo\n", ""))
    assert uncovered == [".aegis/rules/traps/x", "svc/.aegis/rules/traps/x"]




@pytest.mark.parametrize("text", ["", "# only a comment\n", "*.txt @octo\n", "/src/ @octo\n"])
def test_a_codeowners_that_misses_the_set_leaves_it_uncovered(text):
    _covered, uncovered = codeowners.codeowners_coverage(text)
    assert ".aegis/rules/traps/x" in uncovered


def test_the_last_matching_entry_wins_and_an_entry_with_no_owner_unprotects():
    text = hg.CODEOWNERS_FULL + "/.aegis/rules/\n"
    _covered, uncovered = codeowners.codeowners_coverage(text)
    assert ".aegis/rules/traps/x" in uncovered
    assert ".aegis/config.json" not in uncovered


def test_a_single_star_does_not_cross_a_directory_as_the_matcher_of_target_paths_does():
    # /.aegis/* covers direct children only on GitHub; the rules live two levels down.
    text = hg.CODEOWNERS_FULL.replace("**/.aegis/rules/ @octo\n", "").replace("/.aegis/rules/ @octo\n", "/.aegis/* @octo\n")
    _covered, uncovered = codeowners.codeowners_coverage(text)
    assert ".aegis/rules/traps/x" in uncovered
    assert ".aegis/config.json" not in uncovered


def test_owners_must_look_like_owners():
    text = hg.CODEOWNERS_FULL.replace("@octo", "nobody-handle")
    _covered, uncovered = codeowners.codeowners_coverage(text)
    assert uncovered, "a token that is not @user, @org/team or an email owns nothing"
    ok = hg.CODEOWNERS_FULL.replace("@octo", "owner@example.com")
    assert codeowners.codeowners_coverage(ok)[1] == []


def test_a_hostile_codeowners_is_bounded():
    evil = "/" + "*a" * 200 + "b @octo\n" + ("x " * 100000) + "\n" + "/a/b/" * 5000 + " @o\n"
    covered, uncovered = codeowners.codeowners_coverage(evil)
    assert uncovered, "no pattern of it covers the set, and reading it does not hang"


def test_codeowners_coverage_includes_tracked_repo_paths_and_fails_closed_on_negation_or_invalid_override():
    partial = hg.CODEOWNERS_FULL.replace("/.github/workflows/ @octo\n", "/.github/workflows/ci.yml @org/sec\n")
    _cov, uncov = codeowners.codeowners_coverage(
        partial, ".github/CODEOWNERS", repo_paths=(".github/workflows/validate.yml",)
    )
    assert ".github/workflows/validate.yml" in uncov

    for suffix in (
        "/.github/workflows/validate.yml\n",
        "/.github/workflows/validate.yml invalid-owner-token\n",
        "!/.github/workflows/validate.yml @org/sec\n",
        "/.github/workflows/[v]alidate.yml @org/sec\n",
    ):
        _cov2, uncov2 = codeowners.codeowners_coverage(
            "* @org/sec\n" + suffix, ".github/CODEOWNERS", repo_paths=(".github/workflows/validate.yml",)
        )
        assert ".github/workflows/validate.yml" in uncov2, f"expected uncovered for {suffix!r}"


def test_coverage_drops_only_the_organizations_own_bare_handle():
    text = hg.CODEOWNERS_FULL.replace("@octo", "@Acme")
    assert codeowners.codeowners_coverage(text)[1] == []
    assert codeowners.codeowners_coverage(text, org_login="acme")[0] == []
    assert codeowners.codeowners_coverage(text.replace("@Acme", "@acme/sec"), org_login="acme")[1] == []
    assert codeowners.codeowners_coverage(text.replace("@Acme", "@alice"), org_login="acme")[1] == []


def test_codeowners_comments_negations_and_malformed_owner_keep_the_golden_coverage():
    text = (
        "# policy owners\n* @octo # all paths initially owned\n"
        "!/.aegis/rules/traps/x @ignored\n"
        "/.aegis/config.json invalid-owner-token\n"
        "/.github/workflows/aegis.yml @security/team\n"
    )
    covered, uncovered = codeowners.codeowners_coverage(
        text, ".github/CODEOWNERS", repo_paths=("/.github/workflows/aegis.yml", "extra/path")
    )
    assert uncovered == [".aegis/rules/traps/x", ".aegis/config.json"]
    assert covered == [p for p in codeowners.COVERAGE_SAMPLES if p not in uncovered] + [
        ".github/workflows/aegis.yml", "extra/path"
    ]


def test_codeowners_guidance_uses_the_canonical_governance_generator():
    assert codeowners.codeowners_lines is governance.codeowners_lines
