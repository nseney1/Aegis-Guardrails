"""The one target_paths matcher (defense #23): fnmatch-superset semantics, no substring glob.

Every site that decides whether a rule applies to a file (aegis scan, aegis check
telemetry and forbid_ast, credit assignment, coverage and grade) calls
aegis_core.match, so one pattern means the same thing everywhere.
"""
from __future__ import annotations

import fnmatch
import random
import re
import time

import pytest

from aegis_core.match import (
    credit_weights,
    first_match,
    is_test_path,
    matches,
    matching_files,
    normalize_path,
    workspace_files,
)


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        ("aegis_core/*.py", "aegis_core/lifecycle/promotion.py"),  # * crosses /
        ("*.py", "a/b/c.py"),
        ("src/**/*.py", "src/a.py"),  # **/ is zero directories
        ("src/**/*.py", "src/x/y/a.py"),  # or more
        ("**/*.py", "a.py"),
        ("**/tests/*.py", "tests/test_a.py"),
        ("**", "anything/at/all.txt"),
        ("*.md", "docs/guide.md"),  # a slashless pattern also matches the basename
        ("aegis", "aegis"),
        ("aegis", "bin/aegis"),
        ("Makefile", "Makefile"),
        ("src/app.py", "src/app.py"),
        ("src/ap?.py", "src/app.py"),
        ("src/[ab].py", "src/b.py"),
        ("src/[!c].py", "src/a.py"),
        (".aegis/rules/*.md", ".aegis/rules/traps/trap-x.md"),
    ],
)
def test_pattern_matches(pattern: str, path: str) -> None:
    assert matches(pattern, path)


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        ("src", "src/a.py"),  # no substring glob: a bare directory name is not a prefix
        ("aegis", "aegis_core/x.py"),
        ("aegis", "bin/aegis.sh"),
        ("rules/*.md", ".aegis/rules/traps/x.md"),  # anchored at the workspace root
        ("tests/*.py", "src/tests_helper.py"),
        ("src/**/*.py", "lib/src/a.py"),
        ("*.PY", "a.py"),  # case-sensitive on every platform
        ("src/[!a].py", "src/a.py"),
        ("", "a.py"),
        ("docs/*.md", "docs"),
        ("a**/b.py", "src/ab.py"),  # a pattern with a slash never matches by basename
        ("x[!/]y", "src/xay"),
    ],
)
def test_pattern_does_not_match(pattern: str, path: str) -> None:
    assert not matches(pattern, path)


def test_paths_and_patterns_are_normalized_to_workspace_relative_posix() -> None:
    assert normalize_path("src\\pkg\\a.py") == "src/pkg/a.py"
    assert normalize_path("./src/a.py") == "src/a.py"
    assert normalize_path("/src/a.py") == "src/a.py"
    # removeprefix, not lstrip('./'): the leading dot of a dot-directory survives.
    assert normalize_path("./.aegis/rules/x.md") == ".aegis/rules/x.md"
    assert normalize_path(".github/workflows/ci.yml") == ".github/workflows/ci.yml"
    assert matches("src\\*.py", "src/a.py")
    assert matches("./src/*.py", ".\\src\\a.py")
    assert matches(".github/**", "./.github/workflows/ci.yml")
    assert not matches("github/**", ".github/workflows/ci.yml")


@pytest.mark.parametrize("path", ["", "./", "/"])
@pytest.mark.parametrize("pattern", ["*", "**", "**/*"])
def test_a_path_that_names_no_file_matches_no_pattern(pattern: str, path: str) -> None:
    assert not matches(pattern, path)


def test_non_string_patterns_never_match() -> None:
    assert not matches(None, "a.py")  # type: ignore[arg-type]
    assert not matches(3, "a.py")  # type: ignore[arg-type]
    assert first_match(["src/*.py", 7, None], "lib/a.py") is None  # type: ignore[list-item]


def test_first_match_returns_the_first_pattern_that_applies() -> None:
    assert first_match(["docs/*.md", "src/*.py", "*.py"], "src/a.py") == "src/*.py"
    assert first_match([], "src/a.py") is None
    assert first_match("src/*.py", "src/a.py") == "src/*.py"  # a single pattern string


def test_matching_files_keeps_order_and_drops_duplicates() -> None:
    files = ["src/a.py", "docs/x.md", "src/a.py", "src/b.py"]
    assert matching_files(["src/*.py"], files) == ["src/a.py", "src/b.py"]
    assert matching_files([], files) == []


def test_matching_files_counts_one_file_once_however_it_is_spelled() -> None:
    files = ["src/a.py", "./src/a.py", "src\\a.py", "/src/a.py", "src/b.py"]
    assert matching_files(["src/*.py"], files) == ["src/a.py", "src/b.py"]


def test_workspace_files_makes_paths_workspace_relative_once_each(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    inside = str(tmp_path / "src" / "a.py")
    outside = str(tmp_path.parent / "elsewhere.py")

    files = workspace_files(tmp_path, [inside, "./src/a.py", "src/b/../a.py", "", "docs/x.md", outside, "../up.py"])

    # A path outside the workspace is no workspace file: no rule can apply to it.
    assert files == ["src/a.py", "docs/x.md"]


# ── Properties (seeded, stdlib only) ─────────────────────────────────────────

_ALPHABET = ["a", "b", "/", "*", "?", ".", "**/", "[ab]"]
_PATH_PARTS = ["a", "b", "ab", "a.b", "ba"]


def _random_pattern(rng: random.Random) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 6))).lstrip("/")


def _random_path(rng: random.Random) -> str:
    return "/".join(rng.choice(_PATH_PARTS) for _ in range(rng.randint(1, 4)))


def test_property_every_fnmatchcase_match_is_a_match() -> None:
    """Superset: whatever posix fnmatch matches, the one matcher matches too."""
    rng = random.Random(23)
    checked = 0
    for _ in range(4000):
        pattern, path = _random_pattern(rng), _random_path(rng)
        if fnmatch.fnmatchcase(path, pattern):
            checked += 1
            assert matches(pattern, path), (pattern, path)
    assert checked > 200  # the generator really exercises matches


def test_property_double_star_slash_also_matches_zero_directories() -> None:
    rng = random.Random(24)
    for _ in range(500):
        tail = _random_path(rng)
        assert matches(f"**/{tail}", tail)
        assert matches(f"x/**/{tail}", f"x/{tail}")
        assert matches(f"x/**/{tail}", f"x/y/z/{tail}")


def _reference(pattern: str, path: str) -> bool:
    """The documented semantics as a plain backtracking regex: exponential in the worst
    case, so only an oracle for the tiny inputs below."""
    pat, rel = normalize_path(pattern), normalize_path(path)
    if not pat or not rel:
        return False
    out, i = [], 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat[i] == "*":
            while i < len(pat) and pat[i] == "*":
                i += 1
            out.append(".*")
        elif pat[i] == "?":
            out.append(".")
            i += 1
        elif pat[i] == "[":  # the generator only writes [ab] and [!a]
            j = pat.index("]", i + 2)
            body = pat[i + 1:j]
            out.append("[^" + body[1:] + "]" if body.startswith("!") else "[" + body + "]")
            i = j + 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    regex = re.compile("(?s:" + "".join(out) + r")\Z")
    return bool(regex.match(rel)) or ("/" not in pat and bool(regex.match(rel.rsplit("/", 1)[-1])))


def test_property_agrees_with_the_backtracking_reference() -> None:
    """The linear matcher means exactly what the plain regex reading of a pattern means."""
    rng = random.Random(26)
    tokens = _ALPHABET + ["[!a]", "**", "*", "/"]
    hits = 0
    for _ in range(6000):
        pattern = "".join(rng.choice(tokens) for _ in range(rng.randint(1, 9)))
        path = _random_path(rng)
        expected = _reference(pattern, path)
        hits += expected
        assert matches(pattern, path) is expected, (pattern, path)
    assert hits > 500


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        ("*a" * 7 + "*b", "a" * 60 + "/x.py"),  # backtracks ~n**7 as a plain regex
        ("*a" * 12 + "*b", "a" * 300 + "/x.py"),
        ("**/a" * 10 + "**/b", "a/" * 150 + "x"),
        ("*a**/" * 8 + "b", "a/" * 150 + "x"),
        ("?*" * 20 + "z", "y" * 400),
    ],
    ids=["7-stars", "12-stars", "dstar-chain", "star-dstar-chain", "qmark-star"],
)
@pytest.mark.timing
def test_wildcard_heavy_patterns_match_in_linear_time(pattern: str, path: str) -> None:
    """A rule's target_paths and a file name both come from the repository, which may be
    hostile: no pattern may freeze the single-threaded MCP server or the commit hook. The best
    of 3 runs is judged, so one descheduled run on a loaded runner cannot fail it."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        found = matches(pattern, path)
        best = min(best, time.perf_counter() - started)
        assert found is fnmatch.fnmatchcase(path, pattern) is False
    assert best < 0.5, f"{best:.2f}s"


def test_property_a_literal_pattern_matches_only_itself_or_its_basename() -> None:
    """No wildcard means no substring and no prefix match, ever."""
    rng = random.Random(25)
    for _ in range(2000):
        literal, path = _random_path(rng), _random_path(rng)
        expected = path == literal or ("/" not in literal and path.rsplit("/", 1)[-1] == literal)
        assert matches(literal, path) is expected, (literal, path)


# ── Credit assignment ────────────────────────────────────────────────────────

def test_credit_is_split_per_file_among_the_rules_that_match_it() -> None:
    rules = {"a": ["src/*.py"], "b": ["src/*.py"], "c": ["src/*.py", "tests/*.py"]}
    weights = credit_weights(rules, ["src/x.py"])
    assert weights == pytest.approx({"a": 1 / 3, "b": 1 / 3, "c": 1 / 3})
    assert sum(weights.values()) == pytest.approx(1.0)


def test_credit_goes_only_to_rules_whose_patterns_match_a_changed_file() -> None:
    rules = {"src-rule": ["src/*.py"], "test-rule": ["tests/*.py"], "docs-rule": ["docs/*.md"]}
    weights = credit_weights(rules, ["src/x.py", "tests/test_x.py"])
    assert weights == {"src-rule": 1.0, "test-rule": 1.0, "docs-rule": 0.0}


def test_credit_uses_the_same_semantics_as_matching() -> None:
    """`**/` zero-dir and basename matching give credit exactly where matches() says so."""
    rules = {"deep": ["src/**/*.py"], "base": ["Makefile"], "substring": ["src"]}
    weights = credit_weights(rules, ["src/a.py", "tools/Makefile"])
    assert weights == {"deep": 1.0, "base": 1.0, "substring": 0.0}


def test_a_rule_matching_two_files_sums_its_share_of_each() -> None:
    rules = {"a": ["src/a.py"], "b": ["src/b.py"], "shared": ["src/*.py"]}
    weights = credit_weights(rules, ["src/a.py", "src/b.py"])
    assert weights == {"a": 0.5, "b": 0.5, "shared": 1.0}


def test_credit_with_no_files_is_zero_for_every_rule() -> None:
    assert credit_weights({"a": ["*"]}, []) == {"a": 0.0}


def test_one_file_spelled_two_ways_is_credited_once() -> None:
    weights = credit_weights({"a": ["src/*.py"], "b": ["docs/*"]}, ["src/x.py", "./src/x.py", "docs/y.md"])
    assert weights == {"a": 1.0, "b": 1.0}


# ── Test-file classification (one predicate, #25) ────────────────────────────

@pytest.mark.parametrize(
    "path",
    [
        "tests/test_a.py",
        "tests/unit/core/test_a.py",
        "pkg/tests/helpers.py",
        "src/test_a.py",
        "src/a_test.py",
        "cmd/a_test.go",
        "web/a.test.ts",
        "web/a.spec.js",
        "conftest.py",
        "tests\\unit\\test_a.py",
    ],
)
def test_test_paths(path: str) -> None:
    assert is_test_path(path)


@pytest.mark.parametrize(
    "path",
    ["src/app.py", "src/contest.py", "src/testing.py", "latest/a.py", "src/attest_x.py", "docs/tests.md"],
)
def test_source_paths(path: str) -> None:
    assert not is_test_path(path)
