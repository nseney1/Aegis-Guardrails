"""Lease-only root anchors preserve unanchored and rule targeting semantics."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from aegis_core import match, team_paths


@pytest.mark.parametrize("parse,raw", [
    (team_paths.claim_paths, ["/README.md", "docs/**"]),
    (team_paths.stored_paths, [".//README.md", "docs/a.py src/b.py"]),
    (team_paths.stored_paths, ["/README.md"]),
])
def test_parsed_lease_members_keep_type_equality_hashing_sorting_and_json(parse, raw):
    import json
    import pickle

    paths = parse(raw)
    restored = pickle.loads(pickle.dumps(paths))
    for parsed in (paths, restored, team_paths.PathSet(paths.raw, paths.matching)):
        assert all(isinstance(g, team_paths.LeaseGlob) for g in (*parsed.raw, *parsed.matching))
        assert list(parsed.raw) == raw
        assert len(set((*parsed.raw, *raw))) == len(set(raw))
        assert sorted(parsed.raw) == sorted(raw)
        assert json.dumps(parsed.raw).encode() == json.dumps(raw).encode()
        assert [hash(g) for g in parsed.raw] == [hash(g) for g in raw]


@pytest.mark.parametrize("api", ["matches", "first_match", "matching_files", "may_overlap", "sets_overlap"])
def test_rule_matching_entry_points_refuse_lease_members(api):
    parsed = team_paths.claim_paths(["/README.md"])
    for glob in (*parsed.raw, *parsed.matching):
        args = {"matches": (glob, "nested/README.md"),
                "first_match": ([glob], "nested/README.md"),
                "matching_files": ([glob], ["nested/README.md"]),
                "may_overlap": (glob, "nested/README.md"),
                "sets_overlap": ([glob], ["nested/README.md"])}[api]
        for _ in range(2):
            with pytest.raises(TypeError, match=r"\Alease globs cannot use rule matching\Z"):
                getattr(match, api)(*args)


@pytest.mark.parametrize("first,second,expected", [
    ("/pyproject.toml", "/pyproject.toml", True),
    ("/pyproject.toml", "pyproject.toml", True),
    ("/pyproject.toml", "*.toml", True),
    ("/pyproject.toml", "**", True),
    ("/pyproject.toml", "pyproject*", True),
    ("/pyproject.toml", "tools/hierarchy_launcher.py", False),
    ("/pyproject.toml", "nested/pyproject.toml", False),
    ("/pyproject.toml", "/nested/pyproject.toml", False),
    ("/pyproject.toml", "/README.md", False),
    ("/docs/", "docs/guide.md", True),
    ("/docs/", "/docs/guide.md", True),
    ("/docs/", "nested/docs/guide.md", False),
    ("/docs/", "/docstring.py", False),
    ("/Docs/", "docs/guide.md", True),
    ("/PYPROJECT.toml", "/pyproject.toml", True),
    ("/pyproject*", "tools/pyproject.toml", False),
    ("/pyproject*", "/pyproject.toml", True),
    ("/docs/*.md", "docs/guide.md", True),
    ("/docs/*.md", "tools/guide.md", False),
    ("/*.toml", "tools/a.py", True),  # Empty prefix stays conservative.
    ("pyproject.toml", "tools/a.py", True),
    ("./pyproject.toml", "tools/a.py", True),
    ("//pyproject.toml", "tools/a.py", False),
    ("/./pyproject.toml", "/pyproject.toml", True),
    ("/docs//guide.md", "/docs/guide.md", True),
    ("/docs/./guide.md", "/docs/guide.md", True),
])
def test_lease_overlap_matrix_is_symmetric_for_new_and_stored_paths(first, second, expected):
    for parse in (team_paths.claim_paths, team_paths.stored_paths):
        a, b = parse([first]), parse([second])
        assert team_paths.overlap(a, b) is expected
        assert team_paths.overlap(b, a) is expected


@pytest.mark.parametrize("raw,clean", [
    ("/pyproject.toml", "/pyproject.toml"),
    ("//pyproject.toml", "/pyproject.toml"),
    ("./pyproject.toml", "pyproject.toml"),
    (".//pyproject.toml", "/pyproject.toml"),
    ("/docs/", "/docs/"),
    ("\\docs\\file.py", "/docs/file.py"),
    ("/./pyproject.toml", "/pyproject.toml"),
    ("/docs//guide.md", "/docs/guide.md"),
    ("/docs/./guide.md", "/docs/guide.md"),
    ("/docs//./", "/docs/"),
    ("docs/./guide.md", "docs/./guide.md"),  # Old unanchored spellings stay unchanged.
])
def test_claim_normalization_preserves_only_lease_anchors(raw, clean):
    parsed = team_paths.claim_paths([raw, clean])
    assert parsed.raw == parsed.matching == (clean,)
    assert team_paths.stored_paths([raw]).raw == (raw,)


@pytest.mark.parametrize("prefix,stored_prefix", [
    ("", ""), ("./", ""), ("././", ""), (".//", ""), (".///", ""),
    ("/", ""), ("//", ""), ("/./", "./"), ("/.//", ".//"), ("//.///", ".///"),
    ("\\", ""), ("\\\\", ""), (".\\", ""), (".\\\\", ""),
    ("\\.\\", "./"), ("\\.\\\\", ".//"),
])
@pytest.mark.parametrize("name", ["README.md", "pyproject.toml"])
def test_old_normalizer_spelling_classes_keep_their_stored_width(prefix, stored_prefix, name):
    # The old normalizer replaces separators, strips repeated ./, then strips /.
    # That final step can reveal a new ./ spelling that the next reader strips.
    written = match.normalize_path(prefix + name)
    assert written == stored_prefix + name
    assert match.matches(written, "nested/" + name)
    held = team_paths.stored_paths([written])
    assert held.raw == (written,)
    assert held.matching == (name,)
    assert not held.legacy  # Only whitespace requires release/reclaim.
    wanted = team_paths.claim_paths(["nested/" + name])
    assert team_paths.overlap(held, wanted)
    assert team_paths.overlap(held, team_paths.claim_paths(["tools/a.py"]))
    assert team_paths.first_match(held, "nested/" + name) is not None


def test_new_claim_canonicalizes_a_dot_slash_anchor_before_storage():
    new = team_paths.claim_paths(["/.//README.md"])
    assert new.raw == new.matching == ("/README.md",)
    assert team_paths.stored_paths(new.raw).matching == ("/README.md",)
    assert not team_paths.overlap(new, team_paths.claim_paths(["nested/README.md"]))


@pytest.mark.parametrize("raw", [".//.//README.md", "././/.//README.md"])
def test_chained_old_prefixes_cannot_reintroduce_an_anchor(raw):
    held = team_paths.stored_paths([raw])
    assert held.raw == (raw,)
    assert held.matching == ("README.md",)
    assert team_paths.overlap(held, team_paths.claim_paths(["nested/README.md"]))
    assert team_paths.first_match(held, "nested/README.md") is not None


@pytest.mark.parametrize("raw", ["", "/", "//", "./", ".//", "/.", "/./", "//./", "/../x", "//../x"])
def test_empty_or_climbing_anchor_is_refused_on_every_read_and_retry(raw):
    for _ in range(2):
        message = "climbs out of the workspace with '..'" if ".." in raw else "is empty"
        with pytest.raises(team_paths.LeasePathError) as refused:
            team_paths.claim_paths([raw])
        assert str(refused.value) == "paths: glob 1 " + message
        with pytest.raises(team_paths.LeasePathError, match=r"\Apaths is not a non-empty list of globs\Z"):
            team_paths.stored_paths([raw])


def test_lease_changes_leave_rule_normalization_and_targeting_unchanged():
    assert match.normalize_path("/pyproject.toml") == "pyproject.toml"
    assert match.matches("/pyproject.toml", "nested/pyproject.toml")
    assert match.sets_overlap(["/pyproject.toml"], ["tools/a.py"])


@pytest.mark.parametrize("raw", [["/README.md /docs/"], ["/README.md", "docs/a.py src/a.py"]])
def test_known_legacy_whitespace_leases_keep_the_old_wider_reading(raw):
    held = team_paths.stored_paths(raw)
    assert held.raw == tuple(raw)
    assert held.legacy
    assert team_paths.overlap(held, team_paths.claim_paths(["tools/a.py"]))


def test_containment_bounds_files_before_normalization_and_rejects_nonfiles():
    from aegis_core.config import MAX_CONFIG_BYTES

    class BoundedFile(str):
        def replace(self, *args, **kwargs):
            raise AssertionError("oversized file was normalized")

    parsed = team_paths.claim_paths(["/**"])
    for path in (BoundedFile("x" * (MAX_CONFIG_BYTES + 1)), "", "../x", "a/../x", None):
        assert team_paths.first_match(parsed, path) is None


def test_every_contained_sample_remains_protected_by_the_overlap_guard():
    patterns = ["/README.md", "README.md", "/docs/", "/docs/**/*.txt", "*.txt", "**", "/other/**"]
    files = ["README.md", "a/README.md", "docs/x.txt", "docs/a/x.txt", "a/docs/x.txt", "other/x.txt"]
    parsed = [team_paths.claim_paths([pattern]) for pattern in patterns]
    for path in files:
        containing = [paths for paths in parsed if team_paths.first_match(paths, path) is not None]
        for first in containing:
            for second in containing:
                assert team_paths.overlap(first, second), (first.raw, second.raw, path)


def _assert_lease_parser_use(source, rule_scopes):
    tree = ast.parse(source)
    # Exempt named rule policy/CLI matching and actual-file protection checks.
    # All lease matching, including class methods, belongs to the lease parser.
    policy_nodes = {id(child) for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name in rule_scopes
                    for child in ast.walk(node)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and id(node) not in policy_nodes:
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "team_paths":
                    continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            assert name not in ("normalize_path", "sets_overlap", "may_overlap", "matches",
                                "first_match", "fnmatch"), ("lease comparison outside parser", node.lineno)
    # Coarse census only: provenance is enforced by runtime LeaseGlob refusal.
    if "_rule_path_matches" in rule_scopes:
        edges = [(function.name, node) for function in tree.body
                 if isinstance(function, ast.FunctionDef)
                 for node in ast.walk(function) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "_rule_path_matches"]
        assert len(edges) == 1 and edges[0][0] == "_contain", "lease comparison outside parser"


@pytest.mark.parametrize("module,rule_scopes", [
    ("team.py", {"_policy_globs"}),
    ("lane_gate.py", {"is_protected", "_cli_globs", "_rule_path_matches"}),
])
def test_team_lease_comparisons_only_use_the_lease_parser(module, rule_scopes):
    source = Path(__file__).resolve().parents[3] / "aegis_core" / module
    _assert_lease_parser_use(source.read_text(encoding="utf-8"), rule_scopes)


@pytest.mark.parametrize("replacement,helper", [
    ("next((g for g in leased.matching if _rule_path_matches(g, path)), None)", ""),
    ("_unsafe_lease_wrapper(leased, path)",
     "\ndef _unsafe_lease_wrapper(leased, path):\n"
     "    return next((g for g in leased.matching if _rule_path_matches(g, path)), None)\n"),
    ("fnmatch.fnmatch(path, leased.matching[0])", "\nimport fnmatch\n"),
])
def test_structural_guard_refuses_argon_wrapper_mutants(replacement, helper):
    source = Path(__file__).resolve().parents[3] / "aegis_core" / "lane_gate.py"
    original = source.read_text(encoding="utf-8")
    target = "team_paths.first_match(leased, path)"
    assert original.count(target) == 1
    mutant = original.replace(target, replacement) + helper
    with pytest.raises(AssertionError, match="lease comparison outside parser"):
        _assert_lease_parser_use(mutant, {"is_protected", "_cli_globs", "_rule_path_matches"})
