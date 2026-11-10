"""The one rule loader (defense #19, v4.3 §10.3): one policy for every caller.

Each test builds a real workspace on disk and reads it through load_rules, the
function scan, check, status, sync, list, lifecycle and the SDK all call.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from aegis_core.rule_inventory import RuleInventoryError
from aegis_core.rules import RuleCache, lf_digest, load_rules
from tests.conftest import symlink_or_skip
from tests.contract.test_legacy_ratchet import REQUIRED_WORDS


def _rules(ws: Path) -> Path:
    return ws / ".aegis" / "rules"


def _write(ws: Path, rel: str, text: str | bytes) -> Path:
    path = _rules(ws) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_bytes(text.encode("utf-8"))
    return path


def _rule(rule_id: str, rule_type: str = "trap", extra: str = "") -> str:
    return (
        f"---\nid: {rule_id}\ntype: {rule_type}\nenforcement: "
        f"{'gate' if rule_type in ('invariant', 'gate') else 'advisory'}\n"
        f"hypothesis: h\ntarget_paths:\n  - src/*.py\n{extra}---\nBody of {rule_id}.\n"
    )


def _by_path(ruleset) -> dict:
    return {r.path: r for r in ruleset.rules}


def test_a_rule_is_its_type_directory_and_file_stem(tmp_path: Path) -> None:
    _write(tmp_path, "traps/trap-a.md", _rule("trap-a"))
    _write(tmp_path, "invariants/invariant-b.md", _rule("invariant-b", "invariant"))

    rs = load_rules(tmp_path)

    rules = {r.id: r for r in rs.rules}
    assert set(rules) == {"trap-a", "invariant-b"}
    trap = rules["trap-a"]
    assert (trap.type, trap.path, trap.ok, trap.served) == ("trap", ".aegis/rules/traps/trap-a.md", True, True)
    assert trap.target_paths == ("src/*.py",)
    assert trap.body == "Body of trap-a."
    assert trap.meta["hypothesis"] == "h"
    assert not trap.mandatory and rules["invariant-b"].mandatory
    assert rs.errors == () and rs.ignored == ()
    assert rs.get("trap-a") is trap and rs.get("missing") is None


def test_a_rule_declaring_enforcement_gate_is_mandatory(tmp_path: Path) -> None:
    _write(tmp_path, "traps/t.md", "---\nid: t\ntype: trap\nenforcement: gate\n---\nb\n")
    assert load_rules(tmp_path).get("t").mandatory


def test_readme_and_hidden_directories_are_skipped(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "# Rules\n")
    _write(tmp_path, "traps/README.md", "# Traps\n")
    _write(tmp_path, "traps/.archive/old.md", _rule("old"))
    _write(tmp_path, ".last_gasp_queue/queued.md", _rule("queued"))
    _write(tmp_path, "traps/kept.md", _rule("kept"))

    rs = load_rules(tmp_path)

    assert [r.id for r in rs.rules] == ["kept"]
    assert rs.ignored == ()


def test_a_rule_outside_a_type_directory_is_an_error_never_silently_dropped(tmp_path: Path) -> None:
    """A v3 invariants/ rule (or a rule dropped at the top level) would otherwise stop applying."""
    _write(tmp_path, "unsupported/invariant-x.md", _rule("invariant-x", "invariant"))
    _write(tmp_path, "loose.md", _rule("loose"))
    _write(tmp_path, "traps/nested/deep.md", _rule("deep"))
    _write(tmp_path, "_proposed/broken.md", "---\nid: [unterminated\n---\n")

    rs = load_rules(tmp_path)

    by_path = _by_path(rs)
    assert set(by_path) == {
        ".aegis/rules/unsupported/invariant-x.md", ".aegis/rules/loose.md",
        ".aegis/rules/traps/nested/deep.md", ".aegis/rules/_proposed/broken.md",
    }
    assert all(not r.ok and not r.served for r in by_path.values())
    assert "unsupported/ is not a rule type directory" in by_path[".aegis/rules/unsupported/invariant-x.md"].error
    assert "not in a rule type directory" in by_path[".aegis/rules/loose.md"].error
    assert "subdirectories of traps/" in by_path[".aegis/rules/traps/nested/deep.md"].error
    assert "malformed YAML frontmatter" in by_path[".aegis/rules/_proposed/broken.md"].error
    assert rs.served == ()


def test_markdown_that_is_not_a_rule_is_reported_as_ignored(tmp_path: Path) -> None:
    """v3 `aegis init` seeded host instruction rules (no type, no target_paths) flat into
    .aegis/rules; they are listed as ignored, not served and not errors."""
    _write(tmp_path, "providence.md", "---\nid: providence\ndomain: governance\ntrigger: always_on\n---\n# P\n")
    _write(tmp_path, "notes/plan.md", "# just notes\n\nno frontmatter\n")

    rs = load_rules(tmp_path)

    assert rs.rules == ()
    assert [(i.path, i.reason) for i in rs.ignored] == [
        (".aegis/rules/notes/plan.md", "not a rule: notes/ is not a rule type directory"),
        (".aegis/rules/providence.md", "not a rule: it is not in a rule type directory"),
    ]


def test_title_only_frontmatter_in_notes_is_ignored(tmp_path):
    _write(tmp_path, "notes/design.md", "---\ntitle: Design\n---\nNotes\n")
    rules = load_rules(tmp_path)
    assert rules.errors == () and rules.rules == ()
    assert [(item.path, item.reason) for item in rules.ignored] == [
        (".aegis/rules/notes/design.md", "not a rule: notes/ is not a rule type directory"),
    ]


@pytest.mark.parametrize("folder", ["invariant", "Invariants"])
@pytest.mark.parametrize("metadata", ["title: Design", "hypothesis: eval is unsafe"])
def test_any_frontmatter_in_a_rule_type_alias_fails_scan_closed(tmp_path, folder, metadata):
    from aegis_core.scan import scan

    _write(tmp_path, folder + "/no-eval.md", "---\n" + metadata + "\n---\nBody\n")
    rules = load_rules(tmp_path)
    assert len(rules.errors) == 1
    assert "aegis migrate" in rules.errors[0].error
    assert rules.ignored == () and rules.served == ()
    result = scan(tmp_path, ["app.py"])
    assert result["status"] == "FAIL"
    assert "aegis migrate" in result["rule_errors"][0]["error"]
    assert "relevant_rules" not in result


@pytest.mark.parametrize("metadata", ["id: no-eval", "enforcement: gate", "type: invariant", "target_paths: ['*.py']", "forbid_ast: eval"])
def test_noncanonical_directories_refuse_rule_signals(tmp_path, metadata):
    _write(tmp_path, "notes/no-eval.md", "---\n" + metadata + "\n---\nBody\n")
    rules = load_rules(tmp_path)
    assert len(rules.errors) == 1
    assert rules.errors[0].path == ".aegis/rules/notes/no-eval.md"
    assert rules.errors[0].error.startswith("not served: notes/ is not a rule type directory")
    assert rules.ignored == () and rules.served == ()


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"---\nid: x\n\xff\xfe\n---\nb\n", "invalid UTF-8"),
        (b"---\nid: [unterminated\n---\nbody\n", "malformed YAML frontmatter: unterminated flow sequence"),
        (b"---\n- one\n- two\n---\nbody\n", "malformed YAML frontmatter: Expected YAML mapping"),
        (b"---\nid: x\n", "unterminated YAML frontmatter (no closing --- line)"),
        (b"no frontmatter at all\n", "no frontmatter metadata"),
        (b"---\n---\nbody\n", "no frontmatter metadata"),
        (b"---\nid: other\ntype: trap\n---\nb\n", "id 'other' does not match the file name 'x'"),
        (b"---\nid: x\ntype: invariant\n---\nb\n", "type 'invariant' does not match its directory 'traps' (trap)"),
        (b"---\nid: x\nenforcement: blocking\n---\nb\n", "unknown enforcement 'blocking'"),
        (b"---\nid: x\ntarget_paths:\n  - 1\n---\nb\n", "target_paths must be a glob pattern"),
        (b"---\nid: x\npaths:\n  - src/*.py\n---\nb\n", "unknown enforcement-relevant key(s) 'paths'"),
        (b"---\nid: x\ntarget_path: src/a.py\n---\nb\n", "'target_path'"),
        (b"---\nid: x\nenforce: gate\n---\nb\n", "'enforce'"),
        (b"---\nid: x\nast_triggers:\n  - eval\n---\nb\n", "'ast_triggers'"),
        (b"---\nid: x\nglobs: '*.py'\n---\nb\n", "'globs'"),
    ],
)
def test_a_rule_that_cannot_be_served_as_written_is_an_error_record(
    tmp_path: Path, content: bytes, expected: str,
) -> None:
    _write(tmp_path, "traps/x.md", content)

    rs = load_rules(tmp_path)

    (rule,) = rs.rules
    assert rule.path == ".aegis/rules/traps/x.md" and rule.id == "x"
    assert not rule.ok and not rule.served
    assert expected in rule.error
    assert rs.errors == (rule,) and rs.served == ()
    assert rule.as_dict()["_error"] == rule.error


def test_descriptive_keys_are_not_enforcement_keys(tmp_path: Path) -> None:
    _write(tmp_path, "traps/x.md", _rule("x", extra=(
        "domain: correctness\nexpiry_days: 30\nexpiry_sessions: 5\ntags: [a]\n"
        "trigger: always_on\npromotion_threshold: 0.9\nlineage:\n  parent_id: null\n"
        "impact_weight: 1.2\nminimum_mode: patrol\ndescription: d\n"
    )))
    assert load_rules(tmp_path).get("x") is not None


@pytest.mark.parametrize(
    ("key", "hint"),
    [
        ("paths: ['src/*.py']", "'paths' (use target_paths)"),
        ("globs: '*.py'", "'globs' (use target_paths)"),
        ("applyTo: '**/*.ts'", "'applyTo' (use target_paths)"),
        ("targetPaths: ['src/*.py']", "'targetPaths' (use target_paths)"),
        ("Target-Paths: ['src/*.py']", "'Target-Paths' (use target_paths)"),
        ("target_globs: ['src/*.py']", "'target_globs' (use target_paths)"),
        ("patterns: ['src/*.py']", "'patterns' (use target_paths)"),
        ("files: ['src/*.py']", "'files' (use target_paths)"),
        ("include: ['src/*.py']", "'include' (use target_paths)"),
        ("includes: 'src/*.py'", "'includes' (use target_paths)"),
        ("enforce: gate", "'enforce' (use enforcement)"),
        ("Enforcement: gate", "'Enforcement' (use enforcement)"),
        ("forbid-ast: {calls: [eval]}", "'forbid-ast' (use forbid_ast)"),
        ("forbidden: {calls: [eval]}", "'forbidden' (use forbid_ast)"),
        ("expired: true", "'expired' (use expired_at)"),
        ("planned_symbols: [eval]", "'planned_symbols' (no longer read"),
    ],
)
def test_an_alias_or_misspelling_of_an_enforcement_key_is_an_error(tmp_path: Path, key: str, hint: str) -> None:
    """A rule whose scope or enforcement is spelled in a way v4 does not read would
    apply in the wrong place; each known alias is named with the key to use instead."""
    _write(tmp_path, "traps/x.md", f"---\nid: x\ntype: trap\n{key}\n---\nb\n")

    (rule,) = load_rules(tmp_path).rules

    assert not rule.ok
    assert f"unknown enforcement-relevant key(s) {hint}" in rule.error


@pytest.mark.parametrize(
    "key",
    [
        "target_audience: developers",
        "source_path: tools/gen.py",
        "related_paths: [docs/a.md]",
        "global: true",
        "global_note: x",
        "context_files: [src/a.py]",
        "path_note: see docs",
        "enforcement_notes: reviewed",
        "forbidden_words_note: none",
        "_path: .aegis/rules/traps/x.md",
    ],
)
def test_descriptive_keys_that_merely_mention_paths_or_enforcement_load(tmp_path: Path, key: str) -> None:
    """Only the known aliases are errors: a descriptive key is rule content, not a typo."""
    _write(tmp_path, "traps/x.md", _rule("x", extra=f"{key}\n"))

    rule = load_rules(tmp_path).get("x")

    assert rule is not None and rule.served


def test_a_key_v3_tooling_wrote_is_ignored_and_reported_for_migrate(tmp_path: Path) -> None:
    """v3 tier escalation wrote enforcement_artifact into gate rules; v4 never reads it.
    Such a rule is served, and aegis status/migrate name the key."""
    _write(tmp_path, "gates/g.md", _rule("g", "gate", extra="enforcement_artifact: .aegis/enforcement/g.py\n"))

    rs = load_rules(tmp_path)

    rule = rs.get("g")
    assert rule is not None and rule.served
    assert "enforcement_artifact" not in rule.meta
    assert rule.legacy_keys == ("enforcement_artifact",)
    assert [r.id for r in rs.needs_migrate] == ["g"]


@pytest.mark.parametrize("folder", [REQUIRED_WORDS[4] + "s", REQUIRED_WORDS[5] + "s", "patterns", "rules", "unsupported"])
def test_an_unknown_type_directory_is_refused_generically(tmp_path: Path, folder) -> None:
    from aegis_core.scan import scan

    _write(tmp_path, folder + "/m.md", "---\nid: m\nenforcement: gate\n---\nGate body.\n")
    (rule,) = load_rules(tmp_path).rules
    assert rule.path == f".aegis/rules/{folder}/m.md" and not rule.ok
    assert rule.error == (
        f"not served: {folder}/ is not a rule type directory "
        "(expected .aegis/rules/<boundaries, contracts, gates, invariants, personas, traps>/<id>.md)"
    )
    assert scan(tmp_path, ["app.py"])["status"] == "FAIL"


def test_an_unknown_type_in_a_canonical_directory_is_refused_generically(tmp_path: Path) -> None:
    """Only canonical types match their directories."""
    _write(tmp_path, "invariants/w.md", _rule("w", "unsupported"))

    (rule,) = load_rules(tmp_path).rules

    assert not rule.ok
    assert "type 'unsupported' does not match its directory 'invariants' (invariant)" in rule.error
    assert "aegis migrate" not in rule.error


def test_a_forbid_ast_rule_without_target_paths_applies_to_every_file(tmp_path: Path) -> None:
    """aegis check has always enforced such a rule on every file, so every surface that
    asks where a rule applies (scan, telemetry, coverage) sees the same scope."""
    _write(tmp_path, "invariants/no-eval.md", "---\nid: no-eval\nforbid_ast:\n  calls: [eval]\n---\nb\n")
    _write(tmp_path, "invariants/no-exec.md", "---\nid: no-exec\ntarget_paths: []\nforbid_ast:\n  calls: [exec]\n---\nb\n")
    _write(tmp_path, "traps/scoped.md", "---\nid: scoped\n---\nb\n")

    rs = load_rules(tmp_path)

    assert rs.get("no-eval").target_paths == ("**",)
    assert rs.get("no-exec").target_paths == ("**",)
    assert rs.get("scoped").target_paths == ()  # a rule without forbid_ast and without scope matches nothing


def test_target_paths_may_be_one_pattern_string(tmp_path: Path) -> None:
    _write(tmp_path, "traps/one.md", "---\nid: one\ntarget_paths: 'src/*.py'\n---\nb\n")
    _write(tmp_path, "traps/blank.md", "---\nid: blank\ntarget_paths: '  '\n---\nb\n")

    rs = load_rules(tmp_path)

    assert rs.get("one").target_paths == ("src/*.py",)
    assert rs.get("one").matching_files(["src/a.py", "lib/b.py"]) == ["src/a.py"]
    assert rs.get("blank").target_paths == ()


def test_a_forbid_ast_gate_skips_test_files_unless_its_patterns_name_tests(tmp_path: Path) -> None:
    """Tests use what gates forbid (an eval in the test of the eval guard), so aegis check
    has always exempted them; Rule.applies_to is that one policy for every surface."""
    _write(tmp_path, "invariants/no-eval.md", "---\nid: no-eval\nforbid_ast:\n  calls: [eval]\n---\nb\n")
    _write(tmp_path, "invariants/no-exec-tests.md",
           "---\nid: no-exec-tests\ntarget_paths: ['tests/**/*.py']\nforbid_ast:\n  calls: [exec]\n---\nb\n")
    _write(tmp_path, "traps/advice.md", "---\nid: advice\ntarget_paths: ['**/*.py']\n---\nb\n")
    files = ["src/a.py", "tests/test_a.py", "src/test_b.py", "conftest.py"]

    rs = load_rules(tmp_path)

    assert rs.get("no-eval").matching_files(files) == ["src/a.py"]
    assert not rs.get("no-eval").applies_to("tests/test_a.py") and rs.get("no-eval").applies_to("src/a.py")
    assert rs.get("no-exec-tests").matching_files(files) == ["tests/test_a.py"]
    assert rs.get("advice").matching_files(files) == files  # advisory guidance applies to tests too


@pytest.mark.parametrize("name", ["readme.md", "README.md", "ReadMe.md", ".draft.md", "upper.MD", "mixed.Md"])
def test_a_rule_hidden_by_its_file_name_is_an_error(tmp_path: Path, name: str) -> None:
    """A README, a hidden file or a non-.md extension is never served; when it holds a
    rule, that must not go unseen."""
    rule_id = name.rsplit(".", 1)[0]
    _write(tmp_path, f"traps/{name}", _rule(rule_id))
    _write(tmp_path, "traps/kept.md", _rule("kept"))

    rs = load_rules(tmp_path)

    (broken,) = rs.errors
    assert broken.path == f".aegis/rules/traps/{name}"
    assert broken.error.startswith("not served: ")
    assert [r.id for r in rs.served] == ["kept"]


def test_non_rule_files_hidden_by_name_are_reported_as_ignored_except_readmes(tmp_path: Path) -> None:
    _write(tmp_path, "traps/README.md", "# Traps\n")
    _write(tmp_path, "traps/.notes.md", "# my notes\n")
    _write(tmp_path, "traps/NOTES.MD", "# more notes\n")

    rs = load_rules(tmp_path)

    assert rs.rules == ()
    assert sorted(i.path for i in rs.ignored) == [".aegis/rules/traps/.notes.md", ".aegis/rules/traps/NOTES.MD"]
    assert all(i.reason.startswith("not a rule: ") for i in rs.ignored)


def test_two_rules_with_one_id_are_both_errors(tmp_path: Path) -> None:
    _write(tmp_path, "traps/same.md", _rule("same"))
    _write(tmp_path, "invariants/same.md", _rule("same", "invariant"))

    rs = load_rules(tmp_path)

    assert len(rs.rules) == 2 and rs.served == ()
    errors = {r.path: r.error for r in rs.rules}
    assert errors[".aegis/rules/traps/same.md"] == "duplicate rule id 'same' (also .aegis/rules/invariants/same.md)"
    assert errors[".aegis/rules/invariants/same.md"] == "duplicate rule id 'same' (also .aegis/rules/traps/same.md)"


def test_derived_counters_are_ignored_and_reported_for_migrate(tmp_path: Path) -> None:
    _write(tmp_path, "traps/x.md", _rule("x", extra=(
        "fitness:\n  score: 0.9\n  triggers: 40\nlast_trigger_date: 2026-01-01\n"
        "triggers:\n  - documentation_edit\n"
    )))
    _write(tmp_path, "traps/y.md", _rule("y", extra="triggers: 12\ntrue_positives: 9\n"))

    rs = load_rules(tmp_path)

    x, y = rs.get("x"), rs.get("y")
    assert x.legacy_keys == ("fitness", "last_trigger_date")
    assert "fitness" not in x.meta and "last_trigger_date" not in x.meta
    assert x.meta["triggers"] == ["documentation_edit"]  # a keyword list is rule content
    assert y.legacy_keys == ("triggers", "true_positives")
    assert {r.id for r in rs.needs_migrate} == {"x", "y"}


def test_an_emptied_or_quoted_counter_is_still_a_derived_counter(tmp_path: Path) -> None:
    _write(tmp_path, "traps/z.md", _rule("z", extra="triggers:\ntp: 3\nfp_rate: '0.25'\nscore: high\n"))

    z = load_rules(tmp_path).get("z")

    assert z.legacy_keys == ("fp_rate", "tp", "triggers")
    assert z.meta["score"] == "high"  # not counter-shaped: rule content


def test_an_expired_rule_is_loaded_but_not_served(tmp_path: Path) -> None:
    _write(tmp_path, "traps/old.md", _rule("old", extra="expired_at: 2026-01-01\n"))

    rs = load_rules(tmp_path)

    (rule,) = rs.rules
    assert rule.ok and rule.expired and not rule.served
    assert rs.served == () and rs.errors == ()


def test_a_bom_is_not_part_of_the_frontmatter(tmp_path: Path) -> None:
    _write(tmp_path, "traps/bom.md", b"\xef\xbb\xbf" + _rule("bom").encode("utf-8"))
    assert load_rules(tmp_path).get("bom") is not None


def test_the_digest_is_line_ending_independent(tmp_path: Path) -> None:
    lf = _rule("eol").encode("utf-8")
    crlf = lf.replace(b"\n", b"\r\n")
    _write(tmp_path, "traps/eol.md", crlf)

    rule = load_rules(tmp_path).get("eol")

    assert rule.digest == lf_digest(lf) == lf_digest(crlf)
    assert rule.body == "Body of eol."


def test_an_unsafe_tree_fails_closed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text(_rule("escape"), encoding="utf-8")
    (_rules(tmp_path) / "traps").mkdir(parents=True)
    symlink_or_skip(outside, _rules(tmp_path) / "traps" / "escape.md")

    with pytest.raises(RuleInventoryError):
        load_rules(tmp_path)


def test_a_workspace_without_rules_loads_an_empty_set(tmp_path: Path) -> None:
    rs = load_rules(tmp_path)
    assert (rs.rules, rs.ignored, rs.errors, rs.served) == ((), (), (), ())


def test_the_cache_reparses_only_when_the_bytes_change_and_never_excludes(tmp_path: Path) -> None:
    path = _write(tmp_path, "traps/x.md", _rule("x"))
    cache = RuleCache()

    first = cache.get(tmp_path)
    assert cache.get(str(tmp_path)) is first

    path.write_text(_rule("x", extra="tags: [edited]\n"), encoding="utf-8")
    os.utime(path, ns=(1, 1))
    second = cache.get(tmp_path)

    assert second is not first
    assert second.get("x").meta["tags"] == ["edited"]
    assert [r.id for r in second.served] == ["x"]


# ── Ported from the v3 RuleCache tests: content-correct invalidation, fail closed ──

def test_the_cache_sees_a_same_size_edit_with_a_restored_mtime(tmp_path: Path) -> None:
    path = _write(tmp_path, "traps/one.md", _rule("one", extra="hypothesis_note: aaaa\n"))
    cache = RuleCache()
    first = cache.get(tmp_path)
    before = os.stat(path)
    original = path.read_bytes()
    changed = original.replace(b"aaaa", b"bbbb")
    assert len(changed) == len(original)
    path.write_bytes(changed)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

    second = cache.get(tmp_path)

    assert second is not first and second.get("one").meta["hypothesis_note"] == "bbbb"


def test_the_cache_sees_added_and_removed_rules(tmp_path: Path) -> None:
    _write(tmp_path, "traps/one.md", _rule("one"))
    cache = RuleCache()
    assert [r.id for r in cache.get(tmp_path).served] == ["one"]

    added = _write(tmp_path, "invariants/two.md", _rule("two", "invariant"))
    assert sorted(r.id for r in cache.get(tmp_path).served) == ["one", "two"]

    added.unlink()
    assert [r.id for r in cache.get(tmp_path).served] == ["one"]


@pytest.mark.parametrize("call", ["stat", "open"])
def test_an_io_failure_after_a_warm_cache_raises_instead_of_serving_stale_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call: str,
) -> None:
    import aegis_core.rule_inventory as inventory

    path = _write(tmp_path, "traps/t.md", _rule("t"))
    cache = RuleCache()
    assert cache.get(tmp_path).get("t") is not None
    real = getattr(inventory.os, call)

    def denied(target, *args, **kwargs):
        if os.fspath(target) == str(path):
            raise PermissionError(f"simulated {call} denial")
        return real(target, *args, **kwargs)

    monkeypatch.setattr(inventory.os, call, denied)
    with pytest.raises(RuleInventoryError, match=call):
        cache.get(tmp_path)


def test_rules_are_parsed_from_the_inventory_bytes_without_reopening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis_core.rule_inventory import inventory_rules

    _write(tmp_path, "traps/t.md", _rule("t"))
    snapshot = inventory_rules(str(tmp_path))

    def forbidden_open(*args, **kwargs):
        raise AssertionError("a rule file was opened again after the inventory")

    monkeypatch.setattr("builtins.open", forbidden_open)
    assert load_rules(tmp_path, inventory=snapshot).get("t") is not None
