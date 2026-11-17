"""One table-driven lint over every shipped and workspace rule (defense #41).

It runs the production parser (the one ``aegis_sdk.parse_rule_file`` uses), not
a test-local regex. Shipped rules (rules/, rules/.oracles/) are loaded by host
rule loaders, so they carry the host contract; workspace rules
(.aegis/rules/<type>/) are served by aegis_scan, so they carry the type schema.
"""
from __future__ import annotations

import ast
import functools
import glob
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import aegis_core.rule_lint as lint
import aegis_core.scan as scan_service
import aegis_core.rules as rule_schema
import aegis_core.gitsafe as git_service
from tests import helpers_humangate as hg

from aegis_cli.init import install_rules
from aegis_core.lifecycle.constants import PROTECTED_RULES
from aegis_core.yaml_engine.frontmatter import parse_rule_frontmatter
from aegis_core.match import matching_files

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11, where pytest itself depends on tomli
    import tomli as tomllib

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
SKIP = {"META.md", "README.md"}
DOMAINS = {"architecture", "correctness", "documentation", "efficiency", "governance",
           "portability", "security", "style", "testing"}
# type dir -> (type, required non-empty fields)
WORKSPACE = {"traps": ("trap", ("hypothesis", "target_paths")),
             "invariants": ("invariant", ("hypothesis",)),
             "boundaries": ("boundary", ("hypothesis",)),
             "personas": ("persona", ("hypothesis",)),
             "contracts": ("contract", ("hypothesis", "target_paths"))}
# D16: the author's own process rules govern this repository, not adopters'.
# shipped name -> workspace type (workspace ids carry the type prefix).
DOGFOOD = {"gitflow-review-gate": "invariant", "ci-green-before-release": "invariant",
           "core-change-protocol": "invariant", "no-pre-existing-excuse": "invariant",
           "optional-import-guard": "trap"}
# Ids that no installed rule may name: the dogfood rules plus desktop-automation,
# which is no longer shipped at all (D16).
UNSHIPPED = set(DOGFOOD) | {"desktop-automation"}
WALK_PRUNE = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".pytest_cache", "build", "dist"}


def _md(base: Path, pattern: str) -> list[Path]:
    return sorted(p for p in base.glob(pattern) if p.name not in SKIP)


CORE = _md(ROOT / "rules", "*.md") + _md(ROOT / "rules" / ".oracles", "*.md")
# Rules under a hidden directory (.archive) are out of service, as the loader treats them.
WS = [p for p in _md(ROOT / ".aegis" / "rules", "**/*.md")
      if not any(part.startswith(".") for part in p.relative_to(ROOT / ".aegis" / "rules").parts[:-1])]
ALL = CORE + WS
META = ROOT / "rules" / "META.md"


def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def _parse(p: Path) -> tuple[dict, str]:
    try:
        fm, body = parse_rule_frontmatter(str(p))
    except Exception as exc:  # missing, unclosed or malformed frontmatter
        pytest.fail(f"{rel(p)}: unparseable frontmatter: {exc}")
    assert fm, f"{rel(p)}: empty frontmatter"
    return fm, body


def _fm_or_empty(p: Path) -> dict:
    try:
        return parse_rule_frontmatter(str(p))[0] or {}
    except Exception:
        return {}  # reported by the per-file tests, not as a collection error


@pytest.mark.parametrize("p", ALL, ids=rel)
def test_rule_id_matches_filename_domain_is_known_and_body_is_real(p):
    fm, body = _parse(p)
    assert fm.get("id") == p.stem, f"{rel(p)}: id {fm.get('id')!r} != filename stem"
    assert fm.get("domain") in DOMAINS, f"{rel(p)}: domain {fm.get('domain')!r} not allowed"
    assert len(body.strip()) > 50, f"{rel(p)}: body too short to be actionable"


def test_rule_ids_are_unique_across_shipped_and_workspace_rules():
    seen: dict[str, Path] = {}
    for p in ALL:
        rid = _parse(p)[0].get("id")
        assert rid not in seen, f"duplicate id {rid!r}: {rel(seen[rid])} and {rel(p)}"
        seen[rid] = p


@pytest.mark.parametrize("p", CORE + [META], ids=rel)
def test_shipped_rule_host_contract(p):
    fm, _ = _parse(p)
    assert fm.get("trigger") in ("always_on", "model_decision"), f"{rel(p)}: bad trigger"
    assert len(str(fm.get("description", "")).strip()) > 10, f"{rel(p)}: description too short"
    if p.parent.name == "rules" and p != META:
        assert "enforcement" in fm, f"{rel(p)}: missing enforcement"


def test_meta_bootstrap_stays_always_on():
    assert _parse(META)[0].get("trigger") == "always_on"


@pytest.mark.parametrize("p", WS, ids=rel)
def test_workspace_rule_type_schema(p):
    assert p.parent.name in WORKSPACE, f"{rel(p)}: not under a canonical type dir {sorted(WORKSPACE)}"
    rtype, required = WORKSPACE[p.parent.name]
    fm, _ = _parse(p)
    assert fm.get("type") == rtype, f"{rel(p)}: type {fm.get('type')!r}, expected {rtype!r}"
    for field in required:
        assert fm.get(field), f"{rel(p)}: missing or empty {field!r}"
    if rtype == "trap":
        assert "expiry_sessions" in fm or "expiry_days" in fm, f"{rel(p)}: trap has no expiry"
    if rtype == "invariant":
        assert fm.get("enforcement") == "gate", f"{rel(p)}: invariant must be gate"


# A served rule without target_paths applies to no file: scan and check never serve it.
# The set must shrink, never grow (invariant-test-canonical-colocality was retired to .archive/).
KNOWN_UNTARGETED: set = set()


def test_every_served_workspace_rule_applies_to_some_file():
    from aegis_core.rules import load_rules

    untargeted = {r.id for r in load_rules(ROOT).served if not r.target_paths}
    assert untargeted == KNOWN_UNTARGETED, "served rules without target_paths match no file; give them patterns"


_PATHS = [(p, t) for p in WS for t in (_fm_or_empty(p).get("target_paths") or []) if isinstance(t, str)]


@functools.lru_cache(maxsize=None)
def _repo_files() -> tuple[str, ...]:
    found = []
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in WALK_PRUNE and not x.endswith(".egg-info")]
        found.extend(Path(d, f).relative_to(ROOT).as_posix() for f in files)
    return tuple(found)


# A rule file outside the lane that moved its target is a strict xfail logged for the
# rules owner: retargeting the rule turns the xfail into a failure that removes the entry.
# The set must shrink, never grow.
KNOWN_DEAD_TARGETS: set = set()
_DEAD = pytest.mark.xfail(
    strict=True, reason="the docs wave moved this target; the rule file is outside lane f2 (retarget it)"
)


@pytest.mark.parametrize(
    "p,target",
    [pytest.param(p, t, marks=[_DEAD] if (p.name, t) in KNOWN_DEAD_TARGETS else []) for p, t in _PATHS],
    ids=[f"{p.name}:{t}" for p, t in _PATHS],
)
def test_target_paths_resolve(p, target):
    """Resolve with the one matcher every rule site uses (aegis_core.match), not glob:
    a pattern that matches no file is dead, and one that relied on the removed
    substring glob (a bare `src`) matches nothing now."""
    files = _repo_files()
    matched = set(matching_files([target], files))
    assert matched, f"{rel(p)}: {target!r} matches no file through aegis_core.match"
    named = {Path(x).relative_to(ROOT).as_posix() for x in glob.glob(str(ROOT / target), recursive=True)}
    missed = sorted((named & set(files)) - matched)
    assert not missed, f"{rel(p)}: {target!r} reads as a glob for {missed[:5]} but the scan matcher skips them"


@pytest.mark.parametrize("preset", ["minimal", "standard", "full"])
def test_installed_rules_name_no_unshipped_rule(preset, tmp_path):
    installed = install_rules(tmp_path, preset=preset)
    assert installed and not set(installed) & UNSHIPPED
    texts = {p.name: p.read_text(encoding="utf-8") for p in tmp_path.glob("*.md")}
    texts["META.md"] = META.read_text(encoding="utf-8")  # host loaders read META from the package
    hits = sorted(f"{name}: {rid}" for name, text in texts.items() for rid in UNSHIPPED if rid in text)
    assert hits == [], f"{preset} preset installs text naming rules it does not ship"


def test_unshipped_ids_agree_with_wheel_smoke():
    tree = ast.parse((ROOT / ".github" / "scripts" / "wheel_smoke.py").read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(getattr(t, "id", None) == "UNSHIPPED_RULES" for t in n.targets))
    assert set(ast.literal_eval(node.value)) == UNSHIPPED


def test_protected_rules_are_shipped_rules():
    assert PROTECTED_RULES <= {p.stem for p in CORE}


def test_dogfood_rules_are_workspace_rules_not_shipped():
    assert {f"{rtype}-{name}" for name, rtype in DOGFOOD.items()} <= {p.stem for p in WS}
    assert not set(DOGFOOD) & {p.stem for p in CORE}


def _table(text: str, header: str) -> set[str]:
    """Package names in the markdown table under ``## <header>`` ("`yaml` (pyyaml)" -> pyyaml)."""
    section = re.search(rf"^## {re.escape(header)}[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    rows = [r for r in (section.group(1) if section else "").splitlines() if r.startswith("|") and "---" not in r]
    cells = [r.split("|")[1].strip() for r in rows[1:]]  # rows[0] is the header row
    return {(re.search(r"\((\w+)\)", c) or re.match(r"`?([\w-]+)", c)).group(1).lower() for c in cells}


def test_optional_import_guard_tables_match_pyproject():
    found = [p for p in ALL if p.stem == "trap-optional-import-guard"]
    assert len(found) == 1, f"expected one optional-import-guard rule, found {found}"
    oracle = found[0].read_text(encoding="utf-8")
    with open(ROOT / "pyproject.toml", "rb") as f:
        deps = {re.split(r"[><=!~\[ ;]", d)[0].lower() for d in tomllib.load(f)["project"]["dependencies"]}
    assert deps == set(), "Aegis has zero runtime dependencies"
    assert _table(oracle, "Required Dependencies") <= deps
    assert not _table(oracle, "Known Optional Dependencies") & deps


# Mining lint tests use final accepted-rule bytes, not proposal Markdown.
def lint_bytes(do="Use the ${SLOT.TEST_RUNNER} capability.", *, extra="", body=None):
    text = ("---\nid: sample\ntype: trap\nenforcement: advisory\n"
            "hypothesis: A bounded check prevents repeated mistakes.\n"
            "prediction: Invalid changes are caught before landing.\n"
            "target_paths: [src/**]\n" + extra + "---\n" +
            (body if body is not None else "## Do\n" + do + "\n"))
    return text.encode("utf-8")


LINT_PATH = ".aegis/rules/traps/sample.md"


def lint_codes(result):
    return {finding.code for finding in result.findings}


@pytest.mark.parametrize("data", [b"", b"---\nid: sample\n", b"\xff", b"---\nid: other\n---\n"])
def test_lint_loader_refuses_invalid_final_bytes_without_echo(data):
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(data, LINT_PATH)
    assert not result.ok
    assert "loader" in lint_codes(result)
    assert all("other" not in finding.message for finding in result.findings)


@pytest.mark.parametrize("extra", ["paths: [src/**]\n", "triggers: 42\n", "expired_at: 2000-01-01\n"])
def test_lint_loader_rejects_aliases_derived_and_expired_fields(extra):
    from aegis_core.rule_lint import lint_rule

    assert "loader" in lint_codes(lint_rule(lint_bytes(extra=extra), LINT_PATH))


@pytest.mark.parametrize("path", ["../sample.md", ".aegis/rules/traps/../sample.md", "traps/sample.md",
                                  ".aegis/rules/traps/other.md", ".aegis/rules/invariants/sample.md"])
def test_lint_final_identity_and_destination_are_checked(path):
    from aegis_core.rule_lint import lint_rule

    assert "loader" in lint_codes(lint_rule(lint_bytes(), path))


def test_lint_size_limit_precedes_loader(monkeypatch):

    def forbidden(*args, **kwargs):
        pytest.fail("oversize input reached parser")

    monkeypatch.setattr(lint, "load_rules", forbidden)
    result = lint.lint_rule(b"x" * (lint.MAX_RULE_BYTES + 1), LINT_PATH)
    assert lint_codes(result) == {"too_large"}
    assert not result.ok


@pytest.mark.parametrize("field", ["hypothesis", "prediction"])
def test_lint_requires_content_fields(field):
    from aegis_core.rule_lint import lint_rule

    data = re.sub(rb"(?m)^" + field.encode() + rb":.*\n", b"", lint_bytes())
    assert "required_content" in lint_codes(lint_rule(data, LINT_PATH))


@pytest.mark.parametrize("body", ["Do this.\n", "## Do\n\n## Evidence\nNot guidance.\n",
                                  "## Do\n" + "\n" * 8 + "Too late.\n"])
def test_lint_requires_a_do_instruction_inside_detail(body):
    from aegis_core.rule_lint import lint_rule

    assert "do_window" in lint_codes(lint_rule(lint_bytes(body=body), LINT_PATH))


def test_lint_does_not_treat_the_do_heading_as_its_instruction():
    from aegis_core.rule_lint import lint_rule

    assert "do_window" in lint_codes(lint_rule(lint_bytes(do="x" * 301), LINT_PATH))


def test_lint_checks_full_slots_and_renders_before_window_cut():
    from aegis_core.rule_lint import lint_rule

    # The placeholder crosses source character 300 but its rendered Do fits every profile.
    do = "Keep " + "x" * 272 + " ${SLOT.MODEL_FAST}"
    detail = "## Do " + do
    assert detail.index("${SLOT.") < 300 < len(detail)
    assert lint_rule(lint_bytes(do=do), LINT_PATH).ok
    assert "unknown_slot" in lint_codes(lint_rule(lint_bytes(do="x" * 301 + " ${SLOT.TOOL_SHELL}"), LINT_PATH))
    assert "do_window" in lint_codes(lint_rule(lint_bytes(do="x" * 290 + " ${SLOT.TEST_RUNNER}"), LINT_PATH))


@pytest.mark.parametrize("do", ["Use ${SLOT.TOOL_SHELL}.", "Use ${SLOT.BAD", "Use ${SLOT.}."])
def test_lint_unknown_and_unclosed_slots_refuse(do):
    from aegis_core.rule_lint import lint_rule

    assert "unknown_slot" in lint_codes(lint_rule(lint_bytes(do=do), LINT_PATH))


def test_lint_vendor_and_command_suggestions_are_independent():
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(lint_bytes(do="Run `Bash` with `pytest -q`."), LINT_PATH)
    assert not result.ok
    assert {"vendor_name", "concrete_command"} <= lint_codes(result)
    suggestions = {slot for finding in result.findings for slot in finding.suggestions}
    assert {"${SLOT.TOOL_RUN}", "${SLOT.TEST_RUNNER}"} <= suggestions


@pytest.mark.parametrize("do,slot", [("Use the `apply_patch` tool.", "TOOL_EDIT"),
                                      ("Use `haiku`.", "MODEL_FAST"),
                                      ("Run `python3.9 -m pytest -x`.", "TEST_RUNNER"),
                                      ("Run `ruff check src`.", "LINTER"),
                                      ("Run `mypy src`.", "TYPE_CHECKER"),
                                      ("Run `python -m build`.", "BUILD_TOOL")])
def test_lint_known_capabilities_suggest_slots(do, slot):
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(lint_bytes(do=do), LINT_PATH)
    assert not result.ok
    assert "${SLOT." + slot + "}" in {s for finding in result.findings for s in finding.suggestions}


def test_lint_plain_vendor_words_are_allowed_and_unknown_commands_only_warn():
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(lint_bytes(do="Bash is a shell; run `bespoke-check --strict`."), LINT_PATH)
    assert result.ok
    assert "unmapped_command" in lint_codes(result)
    assert "vendor_name" not in lint_codes(result)


def test_lint_configured_commands_and_role_mappings_are_never_executed():
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(lint_bytes(do="Run `hatch run checks --strict`."), LINT_PATH,
                       command_slots={"TEST_RUNNER": "hatch run checks"})
    assert not result.ok
    assert "concrete_command" in lint_codes(result)


def test_lint_shell_fences_are_examples_but_evidence_and_enforcement_are_data():
    from aegis_core.rule_lint import lint_rule

    body = "## Do\nUse a neutral capability.\n```sh\npytest -q\n```\n"
    assert "concrete_command" in lint_codes(lint_rule(lint_bytes(body=body), LINT_PATH))
    body = "## Do\nUse a neutral capability.\n## Evidence\n`Bash` `pytest -q` ${SLOT.UNKNOWN}\n"
    result = lint_rule(lint_bytes(body=body, extra="forbid_ast:\n  calls: ['${SLOT.UNKNOWN}', Bash]\n"), LINT_PATH)
    assert result.ok
    assert not {"vendor_name", "concrete_command", "unknown_slot"} & lint_codes(result)


@pytest.mark.parametrize("spec,message", [({}, "forbid_ast declares no patterns"),
                                          ({"typo": ["eval"]}, "unknown forbid_ast key 'typo' (allowed: imports, calls, decorators)"),
                                          ({"calls": "eval"}, "forbid_ast.calls must be a list of non-empty strings, not str"),
                                          ({"calls": ["eval"]}, None)])
def test_lint_public_validator_preserves_the_existing_grammar_and_messages(spec, message):
    from aegis_core.verification.forbid_ast_spec import forbid_ast_spec_error

    assert forbid_ast_spec_error(spec) == message


def test_lint_validator_extraction_preserves_runner_compatibility_names():
    from aegis_core.verification.forbid_ast_spec import CALL_SPEC_KEYS, forbid_ast_spec_error
    from aegis_core.verification.runner import _CALL_SPEC_KEYS, _forbid_ast_spec_error

    assert _CALL_SPEC_KEYS is CALL_SPEC_KEYS
    assert _forbid_ast_spec_error is forbid_ast_spec_error
    malformed = {"calls": [{"name": "eval", "where": {"#0": {"absent": "wrong"}}}]}
    for _ in range(2):
        assert forbid_ast_spec_error(malformed) == "forbid_ast.calls[0].where.#0: absent needs true or false"


@pytest.mark.parametrize("extra", ["", "forbid_ast: {}\n", "forbid_ast:\n  typo: [eval]\n"])
def test_lint_paper_gates_refuse_but_unchanged_amendment_only_warns(extra):
    from aegis_core.rule_lint import lint_rule
    from aegis_core.rules import Rule

    data = lint_bytes(extra=extra).replace(b"type: trap", b"type: invariant").replace(b"enforcement: advisory", b"enforcement: gate")
    path = ".aegis/rules/invariants/sample.md"
    result = lint_rule(data, path)
    assert "paper_gate" in lint_codes(result) and not result.ok
    meta, _body = parse_rule_frontmatter(data.decode())
    original = Rule("sample", path, "invariant", meta, "", "old-digest")
    amended = lint_rule(data, path, original=original)
    assert amended.ok
    assert all(f.severity == "warning" for f in amended.findings if f.check == 5)
    changed = Rule("sample", path, "trap", meta, "", "old-digest")
    assert not lint_rule(data, path, original=changed).ok


def test_lint_target_paths_are_warning_only_and_simulation_needs_context():
    from aegis_core.rule_lint import lint_rule

    data = lint_bytes().replace(b"target_paths: [src/**]\n", b"")
    result = lint_rule(data, LINT_PATH)
    assert result.ok and "target_paths" in lint_codes(result)
    simulation = next(f for f in result.findings if f.check == 7)
    assert simulation.message == "not evaluated: no scan workspace"


def test_lint_gate_dry_run_counts_real_ast_hits_without_running_sources():
    from aegis_core.rule_lint import lint_rule

    data = lint_bytes(extra="forbid_ast:\n  calls: [eval]\n")
    result = lint_rule(data, LINT_PATH, sources={"src/a.py": b"eval('1')\neval('2')\neval('3')\n",
                                               "tests/test_a.py": b"eval('4')\n"})
    assert result.ok and result.gate_hits == 3 and result.checked_files == 1
    assert "gate_hits" in lint_codes(result)
    broken = lint_rule(data, LINT_PATH, sources={"src/a.py": b"def ("})
    assert broken.ok and broken.gate_hits is None and "source_unavailable" in lint_codes(broken)


def test_lint_source_limits_precede_ast_parsing(monkeypatch):

    def forbidden(*args, **kwargs):
        pytest.fail("oversize source reached AST parser")

    monkeypatch.setattr(lint, "extract_normalized_ast", forbidden)
    result = lint.lint_rule(lint_bytes(extra="forbid_ast:\n  calls: [eval]\n"), LINT_PATH,
                            sources={"src/a.py": b"x" * (lint.MAX_SOURCE_BYTES + 1)})
    assert result.gate_hits is None and "source_limit" in lint_codes(result)


def lint_root(tmp_path):
    from aegis_core.rule_lint import descriptor_supported

    if not descriptor_supported():
        pytest.skip("descriptor-relative no-follow reads unavailable")
    root = tmp_path.resolve()
    path = root / LINT_PATH
    path.parent.mkdir(parents=True)
    path.write_bytes(lint_bytes())
    return root


def test_lint_workspace_unsupported_platform_is_reported(monkeypatch, tmp_path):

    monkeypatch.setattr(lint, "descriptor_supported", lambda: False)
    results = lint.lint_workspace(tmp_path)
    assert len(results) == 1 and lint_codes(results[0]) == {"unsupported"}


def test_lint_workspace_and_cli_are_report_only_and_retry_cleanly(tmp_path, capsys):
    from aegis_core.rule_lint import lint_workspace
    from aegis_cli.rule import RuleCommand, run_rule
    import argparse
    import json

    root = lint_root(tmp_path)
    path = root / LINT_PATH
    path.write_bytes(lint_bytes(do="Use `Bash`."))
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    for _ in range(2):
        assert "vendor_name" in lint_codes(lint_workspace(root)[0])
        parser = argparse.ArgumentParser()
        RuleCommand().configure_parser(parser)
        args = parser.parse_args(["lint", LINT_PATH, "--json", "--workspace", str(root)])
        assert run_rule(args) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["report_only"] is True and payload["results"][0]["ok"] is False
    after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert before == after


@pytest.mark.parametrize("selection,code", [("../secret.md", "invalid_path"),
                                           (".aegis/rules/traps/missing.md", "missing")])
def test_lint_workspace_path_refusals_have_fixed_codes(tmp_path, selection, code):
    from aegis_core.rule_lint import lint_workspace

    root = lint_root(tmp_path)
    result = lint_workspace(root, [selection])[0]
    assert lint_codes(result) == {code}


def test_lint_workspace_symlinks_are_refused(tmp_path):
    from aegis_core.rule_lint import lint_workspace

    root = lint_root(tmp_path / "root")
    target = tmp_path / "outside"
    target.mkdir()
    try:
        (root / ".aegis/rules/traps/link.md").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert any("unsafe" in lint_codes(result) for result in lint_workspace(root))


def test_lint_reads_remain_bound_during_ancestor_replacement(tmp_path, monkeypatch):
    from contextlib import contextmanager

    root = lint_root(tmp_path / "root")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sample.md").write_bytes(lint_bytes(do="Run `Bash`."))
    real_confined = lint.confined_file
    swapped = []

    @contextmanager
    def replace_ancestor(workspace, parts):
        with real_confined(workspace, parts) as reader:
            if list(parts) == LINT_PATH.split("/") and not swapped:
                original = root / ".aegis/rules/traps"
                original.rename(original.with_name("saved"))
                try:
                    original.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError):
                    pytest.skip("directory symlinks unavailable")
                swapped.append(True)
            yield reader

    monkeypatch.setattr(lint, "confined_file", replace_ancestor)
    results = lint.lint_workspace(root, [LINT_PATH])
    assert swapped and lint_codes(results[0]) == {"unsafe"}
    assert "vendor_name" not in lint_codes(results[0])


@pytest.mark.parametrize("failure", ["read", "stat", "open"])
def test_lint_releases_public_reader_on_every_failure(tmp_path, monkeypatch, failure):
    from contextlib import contextmanager

    root = lint_root(tmp_path)
    real_confined = lint.confined_file
    active = []

    class Reader:
        def __init__(self, reader):
            self.reader = reader

        def parent_stat(self):
            if failure == "stat":
                raise OSError("UNTRUSTED-DIAGNOSTIC")
            return self.reader.parent_stat()

        def read_bytes(self, limit):
            raise OSError("UNTRUSTED-DIAGNOSTIC")

    @contextmanager
    def denied(workspace, parts):
        if failure == "open":
            raise PermissionError("UNTRUSTED-DIAGNOSTIC")
        with real_confined(workspace, parts) as reader:
            active.append(True)
            try:
                yield Reader(reader)
            finally:
                active.pop()

    monkeypatch.setattr(lint, "confined_file", denied)
    results = lint.lint_workspace(root, [LINT_PATH])
    assert lint_codes(results[0]) == {"io"} and not active
    assert all("UNTRUSTED" not in f.message for f in results[0].findings)


def test_lint_result_labels_are_canonicalized_redacted_then_truncated():
    from aegis_core.rule_lint import display_text

    secret = "ｇｈｐ＿" + "Ａ" * 24
    shown = display_text("\x1b[31m" + secret + "\u202e suffix " + "x" * 400)
    assert "ghp_" not in shown and "Ａ" not in shown
    assert "[REDACTED_VCS_TOKEN]" in shown
    assert "\x1b" not in shown and "\u202e" not in shown and len(shown) <= 240


def test_lint_malformed_native_source_is_a_fixed_warning():
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(lint_bytes(extra="forbid_ast:\n  calls: [eval]\n"), LINT_PATH,
                       sources={"src/a.js": b"const x = 'unterminated"})
    assert result.ok and result.gate_hits is None
    assert "source_unavailable" in lint_codes(result)


def test_lint_malformed_command_example_warns_without_echoing_it():
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(lint_bytes(do='Run `custom "secret-argument`.'), LINT_PATH)
    assert result.ok and "unmapped_command" in lint_codes(result)
    assert all("secret-argument" not in finding.message for finding in result.findings)


def test_lint_parallel_dry_runs_are_pure_and_repeatable():
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.rule_lint import lint_rule

    data = lint_bytes(extra="forbid_ast:\n  calls: [eval]\n")
    sources = {"src/a.py": b"eval('1')\n"}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(lint_rule, data, LINT_PATH, sources=sources) for _ in range(6)]
        results = [future.result(timeout=5) for future in futures]
    assert all(result == results[0] for result in results)
    assert results[0].gate_hits == 1 and sources == {"src/a.py": b"eval('1')\n"}


def test_lint_candidate_size_is_refused_before_parsing(tmp_path, monkeypatch):
    from aegis_core.rules import load_rules
    from aegis_core.yaml_engine.frontmatter import split_frontmatter

    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(b"x" * (lint.MAX_RULE_BYTES + 1))

    def bounded_load(workspace, **kwargs):
        for entry in kwargs["inventory"].entries:
            assert len(entry.content) <= lint.MAX_RULE_BYTES
            assert split_frontmatter(entry.content.decode("utf-8-sig"))[0] == "none"
        return load_rules(workspace, **kwargs)

    # The public loader may classify a verified header-free prefix, without YAML.
    monkeypatch.setattr(lint, "load_rules", bounded_load)
    assert lint_codes(lint.lint_workspace(root, [LINT_PATH])[0]) == {"too_large"}


def test_lint_parent_change_during_read_is_refused_and_retry_is_clean(tmp_path, monkeypatch):
    from contextlib import contextmanager

    root = lint_root(tmp_path)
    path = root / LINT_PATH
    real_confined = lint.confined_file
    changed = []

    class Reader:
        def __init__(self, reader):
            self.reader = reader

        def parent_stat(self):
            return self.reader.parent_stat()

        def read_bytes(self, limit):
            data = self.reader.read_bytes(limit)
            if not changed:
                replacement = path.with_suffix(".new")
                replacement.write_bytes(lint_bytes())
                replacement.replace(path)
                changed.append(True)
            return data

    @contextmanager
    def replacing(workspace, parts):
        with real_confined(workspace, parts) as reader:
            yield Reader(reader)

    monkeypatch.setattr(lint, "confined_file", replacing)
    assert lint_codes(lint.lint_workspace(root, [LINT_PATH])[0]) == {"changed"}
    assert lint.lint_workspace(root, [LINT_PATH])[0].ok


def test_lint_entry_quota_and_selection_quota_refuse_before_parsing(tmp_path, monkeypatch):

    root = lint_root(tmp_path)
    monkeypatch.setattr(lint, "MAX_ENTRIES", 0)
    assert lint_codes(lint.lint_workspace(root)[0]) == {"too_large"}
    assert lint_codes(lint.lint_workspace(root, [LINT_PATH] * (lint.MAX_SELECTIONS + 1))[0]) == {"invalid_input"}


def test_lint_selected_directory_and_absolute_path_are_supported(tmp_path):
    from aegis_core.rule_lint import lint_workspace

    root = lint_root(tmp_path)
    assert lint_workspace(root, [".aegis/rules/traps"])[0].ok
    assert lint_workspace(root, [str(root / LINT_PATH)])[0].ok


def test_lint_workspace_gate_dry_run_reads_descriptor_snapshots(tmp_path):
    from aegis_core.rule_lint import lint_workspace

    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(lint_bytes(extra="forbid_ast:\n  calls: [eval]\n"))
    (root / "src").mkdir()
    (root / "src/a.py").write_bytes(b"eval('1')\neval('2')\n")
    result = lint_workspace(root)[0]
    assert result.ok and result.gate_hits == 2


def test_lint_cli_workspace_refusal_is_report_only_and_does_not_echo(capsys):
    import argparse
    import json
    from aegis_cli.rule import RuleCommand, run_rule

    parser = argparse.ArgumentParser()
    RuleCommand().configure_parser(parser)
    args = parser.parse_args(["lint", "--json", "--workspace", "\x00UNTRUSTED-PATH"])
    assert run_rule(args) == 0
    text = capsys.readouterr().out
    assert "UNTRUSTED-PATH" not in text
    assert json.loads(text)["results"][0]["findings"][0]["code"] == "workspace"


def test_lint_evidence_heading_inside_a_fence_does_not_hide_guidance():
    from aegis_core.rule_lint import lint_rule

    body = "## Do\nUse a neutral capability.\n```sh\n## Evidence\npytest -q\n```\n"
    result = lint_rule(lint_bytes(body=body), LINT_PATH)
    assert not result.ok and "concrete_command" in lint_codes(result)
    fake_do = "```markdown\n## Do\nA fenced example is not the actual instruction.\n```\n"
    assert "do_window" in lint_codes(lint_rule(lint_bytes(body=fake_do), LINT_PATH))


def test_lint_inventory_entry_budget_is_shared_across_selections(tmp_path, monkeypatch):

    root = lint_root(tmp_path)
    (root / ".aegis/rules/traps/second.md").write_bytes(lint_bytes())
    monkeypatch.setattr(lint, "MAX_ENTRIES", 1)
    results = lint.lint_workspace(root, [".aegis/rules/traps", ".aegis/rules/traps"])
    assert lint_codes(results[0]) == {"too_large"}


def test_lint_zero_width_characters_cannot_split_a_secret_before_redaction():
    from aegis_core.rule_lint import display_text

    secret = "g\u200bhp_" + "A" * 24
    assert display_text(secret) == "[REDACTED_VCS_TOKEN]"


@pytest.mark.parametrize("folder", [".github", "build", "dist", "node_modules", ".venv"])
def test_lint_hidden_project_source_directories_are_included_in_gate_dry_run(tmp_path, folder):
    from aegis_core.rule_lint import lint_workspace

    root = lint_root(tmp_path)
    data = lint_bytes(extra="forbid_ast:\n  calls: [eval]\n").replace(b"src/**", (folder + "/**").encode())
    (root / LINT_PATH).write_bytes(data)
    (root / folder).mkdir()
    (root / folder / "check.py").write_bytes(b"eval('1')\n")
    assert lint_workspace(root)[0].gate_hits == 1


@pytest.mark.parametrize("fence", ["~~~", "````"])
def test_lint_all_markdown_shell_fence_forms_check_commands(fence):
    from aegis_core.rule_lint import lint_rule

    body = "## Do\nUse a neutral capability.\n" + fence + "sh\npytest -q\n" + fence + "\n"
    assert "concrete_command" in lint_codes(lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("body", ["# Do\nAn instruction under the wrong heading.\n",
                                  "    ## Do\n    An indented code example.\n"])
def test_lint_do_requires_the_actual_level_two_markdown_heading(body):
    from aegis_core.rule_lint import lint_rule

    assert "do_window" in lint_codes(lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("body", ["## Do\nRun `customcheck`.\n",
                                  "## Do\nUse the project check.\n```sh\ncustomcheck\n```\n"])
def test_lint_single_word_unknown_executables_warn(body):
    from aegis_core.rule_lint import lint_rule

    result = lint_rule(lint_bytes(body=body), LINT_PATH)
    assert result.ok and "unmapped_command" in lint_codes(result)


def test_lint_public_exports_are_explicit_and_resolvable():
    from aegis_core.verification import forbid_ast_spec

    expected = {"LintFinding", "LintResult", "display_text", "lint_rule", "lint_workspace",
                "descriptor_supported", "MAX_RULE_BYTES", "MAX_RULES", "MAX_RULE_TOTAL",
                "MAX_SOURCE_BYTES", "MAX_SOURCE_FILES", "MAX_SOURCE_TOTAL", "MAX_ENTRIES",
                "MAX_SELECTIONS"}
    assert set(lint.__all__) == expected
    assert all(hasattr(lint, name) for name in lint.__all__)
    assert set(forbid_ast_spec.__all__) == {"CALL_SPEC_KEYS", "forbid_ast_spec_error"}
    assert all(hasattr(forbid_ast_spec, name) for name in forbid_ast_spec.__all__)


def test_lint_uses_public_inventory_once_for_overlapping_selections(tmp_path, monkeypatch):
    from aegis_core.rule_inventory import inventory_rules

    root = lint_root(tmp_path)
    calls = []

    def capture(workspace):
        calls.append(workspace)
        return inventory_rules(workspace)

    monkeypatch.setattr(lint, "inventory_rules", capture)
    results = lint.lint_workspace(root, [".aegis/rules/traps", LINT_PATH])
    assert len(results) == 1 and results[0].ok
    assert calls == [str(root)]


def test_lint_missing_workspace_has_a_fixed_refusal(tmp_path):
    if not lint.descriptor_supported():
        pytest.skip("descriptor-relative no-follow reads unavailable")
    assert lint_codes(lint.lint_workspace(tmp_path / "missing")[0]) == {"missing"}


@pytest.mark.parametrize("operation,code", [("validate", "unsafe"), ("read", "changed"), ("list", "changed")])
def test_lint_inventory_failures_do_not_echo_input_and_retry(tmp_path, monkeypatch, operation, code):
    from aegis_core.rule_inventory import RuleInventoryError, inventory_rules

    root = lint_root(tmp_path)
    calls = []

    def capture(workspace):
        if not calls:
            calls.append(True)
            raise RuleInventoryError(operation, "UNTRUSTED-PATH", "UNTRUSTED-DETAIL")
        return inventory_rules(workspace)

    monkeypatch.setattr(lint, "inventory_rules", capture)
    result = lint.lint_workspace(root)[0]
    assert lint_codes(result) == {code}
    assert "UNTRUSTED" not in repr(result)
    assert lint.lint_workspace(root)[0].ok


def test_lint_candidate_inventory_disagreement_is_refused_then_retried(tmp_path, monkeypatch):
    from aegis_core.rule_inventory import inventory_rules

    root = lint_root(tmp_path)
    changed = []

    def capture(workspace):
        if not changed:
            (root / LINT_PATH).write_bytes(lint_bytes(do="Use another neutral capability."))
            changed.append(True)
        return inventory_rules(workspace)

    monkeypatch.setattr(lint, "inventory_rules", capture)
    assert lint_codes(lint.lint_workspace(root, [LINT_PATH])[0]) == {"changed"}
    assert lint.lint_workspace(root, [LINT_PATH])[0].ok


def test_lint_source_listing_refusal_is_a_fixed_warning(tmp_path, monkeypatch):
    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(lint_bytes(extra="forbid_ast:\n  calls: [eval]\n"))

    def refused(*args, **kwargs):
        yield root / "src", "UNTRUSTED-DETAIL"

    monkeypatch.setattr(lint, "iter_confined_files", refused)
    result = lint.lint_workspace(root)[0]
    assert result.ok and result.gate_hits is None
    assert "source_unavailable" in lint_codes(result)
    assert "UNTRUSTED" not in repr(result)


def test_lint_decorators_come_from_the_snapshot_when_filename_is_missing():
    data = lint_bytes(extra="forbid_ast:\n  decorators: [blocked]\n")
    result = lint.lint_rule(data, LINT_PATH, sources={"src/missing.py": b"@blocked\ndef f(): pass\n"})
    assert result.gate_hits == 1 and result.checked_files == 1


@pytest.mark.parametrize("snapshot,disk,hits", [(b"@blocked\ndef f(): pass\n", b"x = 1\n", 1),
                                               (b"@blocked\ndef f(): pass\n", b"def (", 1),
                                               (b"x = 1\n", b"@blocked\ndef f(): pass\n", 0)])
def test_lint_decorator_snapshot_overrides_existing_disk_bytes(tmp_path, snapshot, disk, hits):
    import json
    import subprocess
    import sys

    path = tmp_path / "src/existing.py"
    path.parent.mkdir()
    path.write_bytes(disk)
    script = ("import json,sys\nfrom aegis_core.rule_lint import lint_rule\n"
              "data=json.load(sys.stdin)\n"
              "result=lint_rule(data['rule'].encode(),data['path'],"
              "sources={'src/existing.py':data['source'].encode()})\n"
              "print(json.dumps({'hits':result.gate_hits,'checked':result.checked_files}))\n")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    payload = {"rule": lint_bytes(extra="forbid_ast:\n  decorators: [blocked]\n").decode(),
               "path": LINT_PATH, "source": snapshot.decode()}
    process = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env,
                             input=json.dumps(payload), capture_output=True, text=True, timeout=15)
    assert process.returncode == 0
    assert json.loads(process.stdout) == {"hits": hits, "checked": 1}
    assert path.read_bytes() == disk


@pytest.mark.parametrize("path", ["/src/a.py", "../src/a.py", "src/../a.py", "src/\x00a.py",
                                  "C:/src/a.py", "src\\a.py", "x" * 1025])
def test_lint_source_keys_must_be_bounded_workspace_relative_paths(path):
    result = lint.lint_rule(lint_bytes(extra="forbid_ast:\n  decorators: [blocked]\n"), LINT_PATH,
                            sources={path: b"@blocked\ndef f(): pass\n"})
    assert result.gate_hits is None and "source_unavailable" in lint_codes(result)
    assert result.checked_files == 0


def test_lint_typed_extraction_failure_is_fixed_and_retry_is_clean(monkeypatch):
    from aegis_core.ast.policy import ASTExtractionError, extract_normalized_ast
    calls = []

    def extract(path, **kwargs):
        if not calls:
            calls.append(True)
            raise ASTExtractionError(path, "UNTRUSTED-DETAIL")
        return extract_normalized_ast(path, **kwargs)

    monkeypatch.setattr(lint, "extract_normalized_ast", extract)
    data = lint_bytes(extra="forbid_ast:\n  decorators: [blocked]\n")
    sources = {"src/a.py": b"@blocked\ndef f(): pass\n"}
    result = lint.lint_rule(data, LINT_PATH, sources=sources)
    assert result.gate_hits is None and "source_unavailable" in lint_codes(result)
    assert "UNTRUSTED" not in repr(result)
    assert lint.lint_rule(data, LINT_PATH, sources=sources).gate_hits == 1


@pytest.mark.parametrize("selected", [False, True])
def test_lint_inventory_duplicate_ids_match_runtime_loader(tmp_path, selected):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    other = root / ".aegis/rules/contracts/sample.md"
    other.parent.mkdir()
    other.write_bytes(lint_bytes().replace(b"type: trap", b"type: contract"))
    assert all(not rule.ok and "duplicate rule id" in rule.error for rule in load_rules(root).rules)
    results = lint.lint_workspace(root, [LINT_PATH] if selected else [])
    assert len(results) == (1 if selected else 2)
    assert all(not result.ok and lint_codes(result) == {"duplicate"} for result in results)
    other.unlink()
    assert lint.lint_workspace(root)[0].ok


@pytest.mark.parametrize("folder", ["__pycache__", "node_modules", "venv", "target", "build", "dist"])
def test_lint_reports_rules_in_invalid_directories_instead_of_pruning(tmp_path, folder):
    root = lint_root(tmp_path)
    other = root / ".aegis/rules" / folder / "invalid.md"
    other.parent.mkdir()
    other.write_bytes(lint_bytes().replace(b"id: sample", b"id: invalid"))
    results = lint.lint_workspace(root)
    assert len(results) == 2
    result = next(result for result in results if result.path.endswith("invalid.md"))
    assert not result.ok and "loader" in lint_codes(result)


def test_lint_uses_loader_classification_and_loads_full_inventory_once(tmp_path, monkeypatch):
    from aegis_core.rules import load_rules
    root = lint_root(tmp_path)
    rules = root / ".aegis/rules"
    (rules / "README.md").write_text("# Rule documentation\n", encoding="utf-8")
    (rules / "notes.md").write_text("Ordinary notes.\n", encoding="utf-8")
    calls = []

    def load(workspace, **kwargs):
        calls.append(kwargs["inventory"])
        return load_rules(workspace, **kwargs)

    monkeypatch.setattr(lint, "load_rules", load)
    results = lint.lint_workspace(root)
    assert len(results) == 1 and results[0].ok
    # Bounded README classification belongs to the same public runtime loader.
    assert len(calls) == 1 and len(calls[0].entries) == 3


@pytest.mark.parametrize("do", ["Run ``pytest -q``.", "Run ```pytest -q```.",
                               "Run `pytest -q && ${SLOT.LINTER}`.",
                               "Run `${SLOT.LINTER} && pytest -q`.",
                               "Run `pytest -q; ${SLOT.LINTER}`.",
                               "Run `pytest -q # ${SLOT.TOOL_RUN}`.",
                               "Use a capability.\n```sh\npytest -q && ${SLOT.LINTER}\n```"])
def test_lint_code_delimiters_and_slots_do_not_hide_concrete_commands(do):
    result = lint.lint_rule(lint_bytes(do=do), LINT_PATH)
    findings = [finding for finding in result.findings if finding.code == "concrete_command"]
    assert not result.ok and any("${SLOT.TEST_RUNNER}" in finding.suggestions for finding in findings)


def test_lint_opaque_slots_do_not_hide_literal_command_names():
    result = lint.lint_rule(lint_bytes(do="Run `AEGIS_SLOT`."), LINT_PATH,
                            command_slots={"TEST_RUNNER": "AEGIS_SLOT"})
    assert "concrete_command" in lint_codes(result)
    slots = lint.lint_rule(lint_bytes(do="Run `${SLOT.TEST_RUNNER} -q && ${SLOT.LINTER}`."), LINT_PATH)
    assert slots.ok and "unmapped_command" not in lint_codes(slots)
    quoted = lint.lint_rule(lint_bytes(do='Run `echo "&&" pytest`.'), LINT_PATH)
    assert "concrete_command" not in lint_codes(quoted)


def test_lint_full_loader_failure_is_fixed_and_retry_is_clean(tmp_path, monkeypatch):
    from aegis_core.rules import load_rules
    root = lint_root(tmp_path)
    calls = []

    def load(workspace, **kwargs):
        if not calls:
            calls.append(True)
            raise RecursionError("UNTRUSTED-DETAIL")
        return load_rules(workspace, **kwargs)

    monkeypatch.setattr(lint, "load_rules", load)
    result = lint.lint_workspace(root)[0]
    assert lint_codes(result) == {"loader"} and "UNTRUSTED" not in repr(result)
    assert lint.lint_workspace(root)[0].ok


@pytest.mark.parametrize("global_flag", [False, True])
@pytest.mark.parametrize("refusal", ["root", "pin"])
def test_lint_real_cli_workspace_refusals_are_fixed_zero_exit_reports(tmp_path, global_flag, refusal):
    import json
    import subprocess
    import sys

    env = dict(os.environ)
    env.pop("AEGIS_WORKSPACE", None)
    env["PYTHONPATH"] = str(ROOT)
    if refusal == "pin":
        env["AEGIS_WORKSPACE"] = str(tmp_path / "UNTRUSTED-pin")
    workspace = ["--workspace", str(Path(tmp_path.anchor))]
    args = workspace + ["rule", "lint", "--json"] if global_flag else ["rule", "lint", "--json"] + workspace
    process = subprocess.run([sys.executable, "-m", "aegis_cli"] + args, cwd=tmp_path,
                             env=env, capture_output=True, text=True, timeout=15)
    assert process.returncode == 0
    assert "UNTRUSTED" not in process.stdout + process.stderr
    result = json.loads(process.stdout)
    assert result["report_only"] is True
    assert result["results"][0]["findings"][0]["code"] == "workspace"


def test_lint_documentation_does_not_block_supported_source_hit_counts(tmp_path):
    data = lint_bytes(extra="forbid_ast:\n  calls: [eval]\n").replace(b"target_paths: [src/**]\n", b"")
    sources = {"src/README.md": b"notes\n", "src/a.py": b"eval('1')\n", "src/b.go": b"package main\n"}
    direct = lint.lint_rule(data, LINT_PATH, sources=sources)
    assert direct.gate_hits == 1 and direct.checked_files == 1
    assert "target_paths" not in lint_codes(direct)
    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(data)
    (root / "src").mkdir()
    for path, content in sources.items():
        (root / path).write_bytes(content)
    result = lint.lint_workspace(root)[0]
    assert result.gate_hits == 1 and result.checked_files == 1


def test_lint_git_storage_does_not_consume_the_source_entry_quota(tmp_path, monkeypatch):
    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(lint_bytes(extra="forbid_ast:\n  calls: [eval]\n"))
    (root / "src").mkdir()
    (root / "src/a.py").write_bytes(b"eval('1')\n")
    monkeypatch.setattr(lint, "MAX_ENTRIES", 2)

    def files(*args, **kwargs):
        for index in range(3):
            yield root / ".git" / str(index), None
        yield root / "src/a.py", None

    monkeypatch.setattr(lint, "iter_confined_files", files)
    assert lint.lint_workspace(root)[0].gate_hits == 1


def test_lint_source_capture_refusal_is_single_ordered_and_retains_limit_code(tmp_path, monkeypatch):
    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(lint_bytes(extra="forbid_ast:\n  calls: [eval]\n"))
    monkeypatch.setattr(lint, "MAX_SOURCE_FILES", 0)
    (root / "src").mkdir()
    (root / "src/a.py").write_bytes(b"eval('1')\n")
    result = lint.lint_workspace(root)[0]
    assert result.gate_hits is None and result.checked_files == 0
    assert [finding.check for finding in result.findings] == [6, 7]
    assert [finding.code for finding in result.findings] == ["source_limit", "scan_simulation"]
    monkeypatch.setattr(lint, "MAX_SOURCE_FILES", 512)
    assert lint.lint_workspace(root)[0].gate_hits == 1


def test_lint_deep_archive_paths_are_ignored_by_runtime_classification(tmp_path):
    root = lint_root(tmp_path)
    archived = root / ".aegis/rules/.archive"
    for _ in range(34):
        archived = archived / "old"
    archived.mkdir(parents=True)
    (archived / "sample.md").write_bytes(lint_bytes())
    results = lint.lint_workspace(root)
    assert len(results) == 1 and results[0].ok


def test_lint_python_options_do_not_make_unrelated_scripts_match_a_role():
    commands = {"TEST_RUNNER": "python3 -B -m pytest"}
    unrelated = lint.lint_rule(lint_bytes(do="Run `python3 unrelated.py`."), LINT_PATH, command_slots=commands)
    assert "concrete_command" not in lint_codes(unrelated)
    related = lint.lint_rule(lint_bytes(do="Run `python3 -B -m pytest -q`."), LINT_PATH, command_slots=commands)
    assert any("${SLOT.TEST_RUNNER}" in finding.suggestions for finding in related.findings)
    modes = lint.lint_rule(lint_bytes(do="Run `custom --mode format`."), LINT_PATH,
                           command_slots={"LINTER": "custom --mode lint"})
    assert "concrete_command" not in lint_codes(modes)


def test_lint_real_inventory_matches_runtime_classified_record_paths():
    from aegis_core.rules import load_rules
    if not lint.descriptor_supported():
        pytest.skip("descriptor-relative no-follow reads unavailable")
    records = load_rules(ROOT).rules
    results = lint.lint_workspace(ROOT)
    assert len(results) == len(records)
    assert {result.path for result in results} == {lint.display_text(rule.path) for rule in records}


def test_lint_real_cli_invalid_snapshot_syntax_is_a_fixed_zero_exit_report(tmp_path):
    import json
    import subprocess
    import sys

    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(lint_bytes(extra="forbid_ast:\n  decorators: [blocked]\n"))
    (root / "src").mkdir()
    (root / "src/a.py").write_bytes(b"def (")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop("AEGIS_WORKSPACE", None)
    process = subprocess.run([sys.executable, "-m", "aegis_cli", "rule", "lint", "--json", "--workspace", str(root)],
                             cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
    assert process.returncode == 0
    result = json.loads(process.stdout)["results"][0]
    assert result["gate_hits"] is None
    assert any(finding["code"] == "source_unavailable" for finding in result["findings"])
    assert "ASTExtractionError" not in process.stdout + process.stderr


@pytest.mark.parametrize("command", [("rule", "list"), ("status",)])
def test_lint_workspace_hook_preserves_other_real_cli_refusals(tmp_path, command):
    import subprocess
    import sys
    from aegis_core.workspace.binding import denial_message

    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop("AEGIS_WORKSPACE", None)
    root = Path(tmp_path.anchor)
    process = subprocess.run([sys.executable, "-m", "aegis_cli", "--workspace", str(root),
                              *command, "--json"], cwd=tmp_path, env=env,
                             capture_output=True, text=True, timeout=15)
    assert process.returncode == 1
    assert process.stdout == ""
    assert process.stderr == "Error: " + denial_message(root) + "\n"


@pytest.mark.parametrize("width", [1, 2, 3, 4, 8])
@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
def test_lint_commonmark_multiline_code_spans_find_commands(width, ending):
    ticks = "`" * width
    result = lint.lint_rule(lint_bytes(do="Run " + ticks + " pytest" + ending + "-q " + ticks + "."), LINT_PATH)
    assert any(f.code == "concrete_command" and "${SLOT.TEST_RUNNER}" in f.suggestions for f in result.findings)


@pytest.mark.parametrize("operator", ["&&", "||", ";", "|", "&"])
@pytest.mark.parametrize("fenced", [False, True])
def test_lint_compound_command_mappings_share_example_tokenization(operator, fenced):
    command = "make test" + operator + "make check"
    body = "## Do\nRun `" + command + "`.\n"
    if fenced:
        body = "## Do\nUse the project check.\n```sh\n" + command + "\n```\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH,
                            command_slots={"TEST_RUNNER": "make test && make check"})
    assert any(f.code == "concrete_command" and "${SLOT.TEST_RUNNER}" in f.suggestions for f in result.findings)
    exact = lint.lint_rule(lint_bytes(body=body), LINT_PATH, command_slots={"TEST_RUNNER": command})
    assert any("${SLOT.TEST_RUNNER}" in f.suggestions for f in exact.findings)
    assert "unmapped_command" not in lint_codes(exact)


@pytest.mark.parametrize("expression", ["ast.Constant('pytest')", "'mypy'", "[pytest, mypy]",
                                        "{'pytest': mypy}", "(pytest, mypy)", "{pytest, mypy}",
                                        "lambda: pytest", "pytest[0]",
                                        "[x for x in pytest]", "{x for x in mypy}",
                                        "{x: x for x in pytest}", "(x for x in pytest)"])
def test_lint_python_literal_examples_are_exempt(expression):
    result = lint.lint_rule(lint_bytes(do="Preserve `" + expression + "` as an AST literal."), LINT_PATH)
    assert not any(f.check == 4 for f in result.findings)


def test_lint_prose_and_unmapped_nonshell_literals_are_not_command_findings():
    body = "## Do\nUse the apply_patch tool with pytest -q.\n```python\n`ordinary value`\n```\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert not any(f.check == 4 for f in result.findings)


@pytest.mark.parametrize("command", ["pytest", "tool.check", "pytest -q", "-pytest", "custom --mode=lint"])
def test_lint_nonliteral_expression_forms_are_command_candidates(command):
    result = lint.lint_rule(lint_bytes(do="Run `" + command + "`."), LINT_PATH,
                            command_slots={"TEST_RUNNER": command})
    assert any("${SLOT.TEST_RUNNER}" in finding.suggestions for finding in result.findings)


def test_lint_normalized_command_models_are_repeatable_in_parallel():
    from concurrent.futures import ThreadPoolExecutor

    data = lint_bytes(do="Run ``make test\n&& make check``.")
    commands = {"TEST_RUNNER": "make test && make check"}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(lint.lint_rule, data, LINT_PATH, command_slots=commands) for _ in range(6)]
        results = [future.result(timeout=10) for future in futures]
    assert all(result == results[0] for result in results)
    assert "concrete_command" in lint_codes(results[0])


def test_lint_shell_parentheses_and_quoted_controls_are_not_segment_boundaries():
    for command in ("echo (pytest)", 'echo "&&" pytest', "echo '|' mypy"):
        result = lint.lint_rule(lint_bytes(do="Run `" + command + "`."), LINT_PATH)
        assert "concrete_command" not in lint_codes(result)


@pytest.mark.parametrize("filesystem", [False, True])
@pytest.mark.parametrize("mixed", [False, True])
def test_lint_unsupported_go_is_incomplete_with_evaluated_hits(tmp_path, filesystem, mixed, monkeypatch):
    from aegis_core.ast.policy import extract_normalized_ast
    calls = []

    def extract(path, **kwargs):
        assert not path.endswith(".go")
        calls.append(path)
        return extract_normalized_ast(path, **kwargs)

    monkeypatch.setattr(lint, "extract_normalized_ast", extract)
    data = lint_bytes(extra="forbid_ast:\n  calls: [panic]\n")
    sources = {"src/a.go": b'package main\nfunc f() { panic("blocked") }\n', "src/README.md": b"notes\n"}
    if mixed:
        sources["src/b.py"] = b"panic('one')\npanic('two')\n"
    if filesystem:
        root = lint_root(tmp_path)
        (root / LINT_PATH).write_bytes(data)
        (root / "src").mkdir()
        for path, content in sources.items():
            (root / path).write_bytes(content)
        result = lint.lint_workspace(root)[0]
    else:
        result = lint.lint_rule(data, LINT_PATH, sources=sources)
    assert result.gate_hits == (2 if mixed else 0)
    assert result.checked_files == (1 if mixed else 0)
    warnings = [f for f in result.findings if f.code == "dry_run_incomplete"]
    assert len(warnings) == 1 and warnings[0].severity == "warning"
    assert "1" in warnings[0].message and ".go" in warnings[0].message
    assert len(calls) == (1 if mixed else 0)


@pytest.mark.parametrize("command,code", [("pytest -q", "concrete_command"),
                                         ("bespoke-check --strict", "unmapped_command")])
def test_lint_slot_wrappers_preserve_the_command_diagnostic(command, code):
    for wrapper in ("${SLOT.TOOL_RUN}", "${SLOT.TOOL_RUN} ${SLOT.TOOL_READ}"):
        result = lint.lint_rule(lint_bytes(do="Run `" + wrapper + " " + command + "`."), LINT_PATH)
        assert code in lint_codes(result)
    for suffix in ("", " -q"):
        result = lint.lint_rule(lint_bytes(do="Run `${SLOT.TEST_RUNNER}" + suffix + "`."), LINT_PATH)
        assert not any(finding.check == 4 for finding in result.findings)


def test_lint_failed_supported_parse_resets_all_snapshot_counts():
    result = lint.lint_rule(lint_bytes(extra="forbid_ast:\n  calls: [eval]\n"), LINT_PATH,
                            sources={"src/a.py": b"eval('1')\n", "src/b.py": b"def ("})
    assert result.gate_hits is None and result.checked_files == 0
    assert "source_unavailable" in lint_codes(result)


@pytest.mark.parametrize("selection", ["all", "large_first", "valid_first"])
def test_lint_oversized_rule_is_per_file_and_valid_rules_keep_their_results(tmp_path, selection, monkeypatch):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    large_path = ".aegis/rules/traps/large.md"
    (root / large_path).write_bytes(lint_bytes().replace(b"id: sample", b"id: large") + b"x" * lint.MAX_RULE_BYTES)

    def bounded_load(workspace, **kwargs):
        assert all(len(entry.content) <= lint.MAX_RULE_BYTES for entry in kwargs["inventory"].entries)
        return load_rules(workspace, **kwargs)

    monkeypatch.setattr(lint, "load_rules", bounded_load)
    monkeypatch.setattr(lint, "MAX_RULE_TOTAL", lint.MAX_RULE_BYTES)
    paths = [] if selection == "all" else ([large_path, LINT_PATH] if selection == "large_first" else [LINT_PATH, large_path])
    results = lint.lint_workspace(root, paths)
    assert len(results) == 2
    by_path = {result.path: result for result in results}
    assert lint_codes(by_path[large_path]) == {"too_large"}
    assert by_path[LINT_PATH].ok
    (root / large_path).unlink()
    assert lint.lint_workspace(root)[0].ok


def test_lint_writer_maximum_body_fits_the_loader_file_cap(tmp_path):
    from aegis_core.lifecycle.creation import MAX_RULE_BODY_BYTES, create_rule
    from aegis_core.packs import MAX_RULE_BYTES

    root = lint_root(tmp_path)
    body = "## Do\nUse the ${SLOT.TEST_RUNNER} capability.\n\n## Evidence\n"
    body += "x" * (MAX_RULE_BODY_BYTES - len(body) - 1) + "\n"
    path = create_rule("trap", "A maximum body is accepted by the writer.",
                       id_override="large-created", target_paths=["src/**"], workspace=root,
                       body=body)
    assert MAX_RULE_BODY_BYTES < path.stat().st_size <= MAX_RULE_BYTES
    results = lint.lint_workspace(root)
    assert len(results) == 2
    assert next(result for result in results if result.path == LINT_PATH).ok
    large = next(result for result in results if result.path.endswith("large-created.md"))
    assert large.ok


@pytest.mark.parametrize("extra_bytes", [0, 1])
def test_lint_in_memory_size_boundary_matches_packs_concurrently(extra_bytes):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.packs import MAX_RULE_BYTES

    data = lint_bytes() + b"\n## Evidence\n"
    data += b"x" * (MAX_RULE_BYTES + extra_bytes - len(data))
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(lint.lint_rule, data, LINT_PATH) for _ in range(3)]
        results = [future.result(timeout=10) for future in futures]
    assert results == [results[0]] * 3
    if extra_bytes:
        assert lint_codes(results[0]) == {"too_large"}
    else:
        assert results[0].ok
    assert lint.lint_rule(lint_bytes(), LINT_PATH).ok


@pytest.mark.parametrize("extra_bytes", [0, 1])
@pytest.mark.parametrize("selection", ["all", "single", "neighbors"])
def test_lint_workspace_size_boundary_matches_pack_export(tmp_path, extra_bytes, selection):
    from aegis_core.packs import MAX_RULE_BYTES, PackError, build_pack
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    path = ".aegis/rules/traps/boundary.md"
    data = lint_bytes().replace(b"id: sample", b"id: boundary") + b"\n## Evidence\n"
    data += b"x" * (MAX_RULE_BYTES + extra_bytes - len(data))
    (root / path).write_bytes(data)
    rules = load_rules(root).rules
    if extra_bytes:
        with pytest.raises(PackError, match=rf"{MAX_RULE_BYTES + 1} bytes exceeds the {MAX_RULE_BYTES} byte limit"):
            build_pack(rules)
    else:
        assert len(build_pack(rules)["rules"]) == 2
    paths = [] if selection == "all" else ([path] if selection == "single" else [path, LINT_PATH])
    for _ in range(2):
        results = {result.path: result for result in lint.lint_workspace(root, paths)}
        assert len(results) == (1 if selection == "single" else 2)
        if extra_bytes:
            assert lint_codes(results[path]) == {"too_large"}
        else:
            assert results[path].ok
        if selection != "single":
            assert results[LINT_PATH].ok


def test_lint_valid_rule_bytes_still_obey_the_aggregate_parser_budget(tmp_path, monkeypatch):
    root = lint_root(tmp_path)
    data = lint_bytes()
    (root / ".aegis/rules/traps/second.md").write_bytes(data.replace(b"id: sample", b"id: second"))
    monkeypatch.setattr(lint, "MAX_RULE_TOTAL", len(data))
    assert lint_codes(lint.lint_workspace(root)[0]) == {"too_large"}


@pytest.mark.parametrize("markdown,matched", [
    ("Check `audit-local --strict` before delivery.", True),
    ("Check ``audit-local --strict`` before delivery.", True),
    ("Check ````audit-local --strict```` before delivery.", True),
    ("Check ``audit-local --strict` before delivery.", False),
    ("Check `audit-local --strict`` before delivery.", False),
    ("Keep a bare ` delimiter alongside audit-local --strict.", False),
    (r"Keep \`audit-local --strict` as escaped punctuation.", False),
    (r"Check \\`audit-local --strict` before delivery.", True),
    ("Check ` audit-local --strict ` before delivery.", True),
    ("Check ``  audit-local --strict  `` before delivery.", True),
    ("Check ` audit-local --strict` before delivery.", True),
    ("Check `audit-local --strict ` before delivery.", True),
    ("Check `audit-local\n--strict` before delivery.", True),
    ("Check ``audit-local\r\n--strict`` before delivery.", True),
    ("Check ``audit-local\r--strict`` before delivery.", True),
    ("Check `audit-local\n\n--strict` before delivery.", False),
    ("Check `audit-local\n## Detail\n--strict` before delivery.", False),
    ("Check `audit-local\n- --strict` before delivery.", False),
    ("Check `audit-local\n> --strict` before delivery.", False),
    ("Check ``audit-local --strict `annotation` `` before delivery.", True),
    ('Keep <label title="`audit-local --strict`"> as markup.', False),
    ("Keep <https://checks.invalid/`audit-local--strict`> as a link.", False),
])
def test_lint_independently_written_span_cases_through_public_api(markdown, matched):
    data = lint_bytes(body="## Do\nUse the project check.\n" + markdown + "\n")
    result = lint.lint_rule(data, LINT_PATH, command_slots={"TEST_RUNNER": "audit-local --strict"})
    assert ("concrete_command" in lint_codes(result)) is matched


@pytest.mark.parametrize("separator", ["\n\n", "\n## Another heading\n", "\n- ", "\n> "])
def test_lint_unmatched_ticks_cannot_cross_markdown_blocks(separator):
    body = "## Do\nKeep a literal backtick: `." + separator + "Run `pytest -q`.\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert "concrete_command" in lint_codes(result)


def test_lint_escaped_tick_leaves_the_remaining_run_as_a_delimiter():
    result = lint.lint_rule(lint_bytes(do="Run \\``pytest -q`."), LINT_PATH)
    assert "concrete_command" in lint_codes(result)


@pytest.mark.parametrize("command", [r"C:\tools\pytest.exe -q", r".\venv\Scripts\python.exe -m pytest",
                                      "/usr/bin/pytest -q", r'"C:\Program Files\pytest.exe" -q'])
@pytest.mark.parametrize("fenced", [False, True])
def test_lint_executable_paths_preserve_backslash_separators(command, fenced):
    body = "## Do\nRun `" + command + "`.\n"
    if fenced:
        body = "## Do\nUse the project check.\n```powershell\n" + command + "\n```\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert any("${SLOT.TEST_RUNNER}" in finding.suggestions for finding in result.findings)


@pytest.mark.parametrize("filesystem", [False, True])
def test_lint_unregistered_languages_are_counted_as_unevaluated(tmp_path, filesystem):
    data = lint_bytes(extra="forbid_ast:\n  calls: [abort]\n")
    sources = {"src/a.c": b"abort();\n", "src/b.java": b"class B {}\n", "src/c.rb": b"abort\n",
               "src/README.md": b"notes\n", "src/a.py": b"abort()\n"}
    if filesystem:
        root = lint_root(tmp_path)
        (root / LINT_PATH).write_bytes(data)
        (root / "src").mkdir()
        for path, content in sources.items():
            (root / path).write_bytes(content)
        result = lint.lint_workspace(root)[0]
    else:
        result = lint.lint_rule(data, LINT_PATH, sources=sources)
    assert result.gate_hits == 1 and result.checked_files == 1
    incomplete = [finding for finding in result.findings if finding.code == "dry_run_incomplete"]
    assert len(incomplete) == 1 and "3" in incomplete[0].message
    assert all(ext in incomplete[0].message for ext in (".c", ".java", ".rb"))


@pytest.mark.parametrize("name", ["README.md", "readme.c", "LICENSE", "CHANGELOG.custom", "NOTICE",
                                  "notes.markdown", "notes.rst", "notes.txt", "notes.adoc",
                                  "asset.png", "asset.jpg", "asset.jpeg", "asset.gif", "asset.svg",
                                  "asset.webp", "asset.bmp", "asset.ico", "asset.tiff"])
def test_lint_explicit_documentation_and_assets_do_not_make_a_dry_run_incomplete(name):
    result = lint.lint_rule(lint_bytes(extra="forbid_ast:\n  calls: [abort]\n"), LINT_PATH,
                            sources={"src/" + name: b"documentation or asset"})
    assert result.gate_hits == 0 and result.checked_files == 0
    assert "dry_run_incomplete" not in lint_codes(result)


def test_lint_unevaluated_extension_display_is_canonical_redacted_and_bounded():
    secret = "ｇ\u200bｈｐ＿" + "Ａ" * 24
    result = lint.lint_rule(lint_bytes(extra="forbid_ast:\n  calls: [abort]\n"), LINT_PATH,
                            sources={"src/a." + secret: b"x", "src/b.c\nINJECT": b"x"})
    finding = next(f for f in result.findings if f.code == "dry_run_incomplete")
    assert "ghp_" not in finding.message and "Ａ" not in finding.message
    assert "REDACTED" in finding.message and "\n" not in finding.message
    assert len(finding.message) <= 240


@pytest.mark.parametrize("command", [r"echo foo\ #tag && pytest -q", "echo foo\\\t#tag && pytest -q",
                                     "echo foo\\\n#tag && pytest -q"])
@pytest.mark.parametrize("fenced", [False, True])
def test_lint_escaped_whitespace_does_not_manufacture_a_comment(command, fenced):
    body = "## Do\nRun `" + command + "`.\n"
    if fenced:
        body = "## Do\nUse the project check.\n```sh\n" + command + "\n```\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert any("${SLOT.TEST_RUNNER}" in finding.suggestions for finding in result.findings)


def test_lint_metadata_fields_are_separate_inline_blocks():
    data = lint_bytes().replace(b"hypothesis: A bounded check prevents repeated mistakes.",
                               b"hypothesis: 'A literal backtick `.'").replace(
                                   b"prediction: Invalid changes are caught before landing.",
                                   b"prediction: 'Run `pytest -q`.'")
    assert "concrete_command" in lint_codes(lint.lint_rule(data, LINT_PATH))


@pytest.mark.parametrize("filesystem", [False, True])
@pytest.mark.parametrize("suffix", [".c", ".pyi"])
def test_lint_unknown_source_extensions_remain_visible_in_exact_scopes(tmp_path, filesystem, suffix):
    data = lint_bytes(extra="forbid_ast:\n  calls: [abort]\n").replace(b"src/**", ("src/*" + suffix).encode())
    if filesystem:
        root = lint_root(tmp_path)
        (root / LINT_PATH).write_bytes(data)
        (root / "src").mkdir()
        (root / ("src/a" + suffix)).write_bytes(b"abort()\n")
        result = lint.lint_workspace(root)[0]
    else:
        result = lint.lint_rule(data, LINT_PATH, sources={"src/a" + suffix: b"abort()\n"})
    assert result.checked_files == 0
    assert "dry_run_incomplete" in lint_codes(result)


@pytest.mark.parametrize("selected", ["all", "small", "large"])
def test_lint_oversized_rules_keep_duplicate_id_identity_without_yaml_parsing(tmp_path, monkeypatch, selected):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    other_path = ".aegis/rules/contracts/sample.md"
    other = root / other_path
    other.parent.mkdir()
    other.write_bytes(lint_bytes().replace(b"type: trap", b"type: contract") + b"x" * lint.MAX_RULE_BYTES)

    def bounded_load(workspace, **kwargs):
        assert all(len(entry.content) <= lint.MAX_RULE_BYTES for entry in kwargs["inventory"].entries)
        return load_rules(workspace, **kwargs)

    monkeypatch.setattr(lint, "load_rules", bounded_load)
    paths = [] if selected == "all" else [LINT_PATH if selected == "small" else other_path]
    results = lint.lint_workspace(root, paths)
    assert results and all("duplicate" in lint_codes(result) for result in results)
    if selected != "small":
        assert "too_large" in lint_codes(next(result for result in results if result.path == other_path))
    other.unlink()
    assert lint.lint_workspace(root)[0].ok


@pytest.mark.parametrize("body", [
    "## Do\n`pytest -q`\n",
    "## Do\n` literal\n\nRun `pytest -q`.\n",
    "## Do\n```sh\necho foo\\ #tag && C:\\tools\\pytest.exe -q\n```\n",
])
def test_lint_block_and_escape_results_are_stable_on_retry_and_concurrent_calls(body):
    from concurrent.futures import ThreadPoolExecutor

    data = lint_bytes(body=body)
    first = lint.lint_rule(data, LINT_PATH)
    assert "concrete_command" in lint_codes(first)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(lint.lint_rule, data, LINT_PATH) for _ in range(6)]
        assert all(future.result(timeout=10) == first for future in futures)
    assert lint.lint_rule(data, LINT_PATH) == first


@pytest.mark.parametrize("container", ["quote", "list"])
def test_lint_fences_cannot_consume_examples_outside_their_container(container):
    prefix = "> ```text\n> literal\n" if container == "quote" else "- ```text\n  literal\n"
    body = "## Do\n" + prefix + "Run `pytest -q`.\n"
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("command", [r"check foo\ #tag", r'check "a\"b"', r"C:\tools\check.exe -q"])
def test_lint_configured_commands_share_the_selective_escape_model(command):
    result = lint.lint_rule(lint_bytes(do="Run `" + command + "`."), LINT_PATH,
                            command_slots={"TEST_RUNNER": command})
    assert any("${SLOT.TEST_RUNNER}" in finding.suggestions for finding in result.findings)


def test_lint_unescaped_comment_and_escaped_quotes_keep_control_provenance():
    for command in ("echo foo #comment && pytest -q", r'echo "foo\" && pytest -q"'):
        result = lint.lint_rule(lint_bytes(do="Run `" + command + "`."), LINT_PATH)
        assert "concrete_command" not in lint_codes(result)


def test_lint_evidence_tail_does_not_reenter_guidance_at_notes():
    from aegis_core.guidance_projection import project_detail

    body = ("## Do\nUse the ${SLOT.TEST_RUNNER} capability.\n## Evidence\n```observed```\n"
            "## Notes\nRun `Bash` with `pytest -q` and ${SLOT.UNKNOWN}.\n")
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert project_detail(body) == "## Do Use the ${SLOT.TEST_RUNNER} capability."
    assert result.ok
    assert not {"unknown_slot", "vendor_name", "concrete_command"} & lint_codes(result)


def test_lint_inline_triple_tick_do_instruction_does_not_leak_evidence():
    body = "## Do\n```${SLOT.TEST_RUNNER}```\n## Evidence\n`pytest -q` ${SLOT.UNKNOWN}\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert result.ok and not {"do_window", "unknown_slot", "concrete_command"} & lint_codes(result)


def test_lint_continued_shell_fence_matches_a_multiword_default_mapping():
    body = "## Do\nUse the project check.\n```sh\nruff \\\n  check src\n```\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert any("${SLOT.LINTER}" in finding.suggestions for finding in result.findings)


@pytest.mark.parametrize("path", [".aegis/rules/.archive/old.md", ".aegis/rules/README.md"])
@pytest.mark.parametrize("selected", [False, True])
def test_lint_oversized_loader_exclusions_are_not_reported(tmp_path, path, selected):
    root = lint_root(tmp_path)
    excluded = root / path
    excluded.parent.mkdir(exist_ok=True)
    excluded.write_bytes(b"# Documentation\n" + b"x" * lint.MAX_RULE_BYTES)
    results = lint.lint_workspace(root, [path] if selected else [])
    assert all(result.path != path for result in results)
    assert results == () if selected else len(results) == 1 and results[0].ok


@pytest.mark.parametrize("separator", ["\n#\n", "\n-\n", "\n1.\n", "\n    code\n"])
def test_lint_empty_block_markers_and_indented_code_break_tick_pairing(separator):
    body = "## Do\nUse ` as punctuation." + separator + "Run `pytest -q`.\n"
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


def test_lint_stripped_reading_includes_tab_indented_fences():
    body = "## Do\nUse a neutral capability.\n\n\t```sh\n\tpytest -q\n\t```\n"
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


def test_lint_python_compiler_diagnostics_do_not_escape_the_report(recwarn):
    from concurrent.futures import ThreadPoolExecutor
    import warnings

    filters = tuple(warnings.filters)
    data = lint_bytes(do=r'Run `"C:\Program Files\pytest.exe" -q`.',
                      extra="forbid_ast:\n  calls: [abort]\n")
    sources = {"src/a.py": b"value = 'bad\\q'\nabort()\n"}
    result = lint.lint_rule(data, LINT_PATH, sources=sources)
    assert "concrete_command" in lint_codes(result) and result.gate_hits == 1
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(lint.lint_rule, data, LINT_PATH, sources=sources) for _ in range(6)]
        assert all(future.result(timeout=10) == result for future in futures)
    failed = lint.lint_rule(data, LINT_PATH, sources={"src/a.py": b"value = 'bad\\q'\ndef ("})
    assert failed.gate_hits is None and "source_unavailable" in lint_codes(failed)
    assert tuple(warnings.filters) == filters
    assert not recwarn.list


@pytest.mark.parametrize("field", ["hypothesis", "prediction"])
@pytest.mark.parametrize("opener", ["```text", "~~~text", "`", "``"])
def test_lint_metadata_fences_and_spans_cannot_hide_body_commands(field, opener):
    data = re.sub(rb"(?m)^" + field.encode() + rb":.*$",
                  (field + ": '" + opener + "'").encode(),
                  lint_bytes(do="Run `Bash` with `pytest -q`."))
    result = lint.lint_rule(data, LINT_PATH)
    assert {"vendor_name", "concrete_command"} <= lint_codes(result)


@pytest.mark.parametrize("opener", ["```text", "~~~text"])
def test_lint_hypothesis_fence_cannot_hide_prediction_commands(opener):
    data = lint_bytes().replace(b"hypothesis: A bounded check prevents repeated mistakes.",
                               ("hypothesis: '" + opener + "'").encode()).replace(
                                   b"prediction: Invalid changes are caught before landing.",
                                   b"prediction: 'Run `Bash` with `pytest -q`.'")
    assert {"vendor_name", "concrete_command"} <= lint_codes(lint.lint_rule(data, LINT_PATH))


@pytest.mark.parametrize("marker", ["-", "1."])
def test_lint_line_local_reading_finds_commands_after_nested_unmatched_ticks(marker):
    body = ("## Do\n" + marker + " Keep a literal backtick: `\n    "
            + marker + " Run `pytest -q`.\n")
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("marker", ["> out", "- x", "1. y", "> - 1. out"])
@pytest.mark.parametrize("language", ["sh", "text", "python", ""])
@pytest.mark.parametrize("fence", ["```", "~~~"])
def test_lint_fenced_reading_keeps_commands_after_container_like_content(marker, language, fence):
    body = "## Do\nUse the project check.\n" + fence + language + "\n" + marker + "\npytest -q\n" + fence + "\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert sum(f.code == "concrete_command" for f in result.findings) == 1


@pytest.mark.parametrize("container,indent", [("", ""), ("> ", "> "), ("- ", "  ")])
@pytest.mark.parametrize("marker", ["> out", "- x", "1. y"])
def test_lint_fence_reading_strips_only_the_enclosing_container(container, indent, marker):
    body = ("## Do\nUse the project check.\n" + container + "```sh\n" + indent + marker
            + "\n" + indent + "pytest -q\n" + indent + "```\n")
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("literal,expected", [("`pytest -q`", "concrete_command"),
                                              ("`Bash`", "vendor_name"),
                                              ("`ordinary value`", None),
                                              ("ordinary value", None),
                                              ("ast.Constant('pytest')", None)])
def test_lint_nonshell_readings_only_report_configured_command_matches(literal, expected):
    body = "## Do\nUse the project check.\n```python\n" + literal + "\n```\n"
    findings = [f for f in lint.lint_rule(lint_bytes(body=body), LINT_PATH).findings if f.check == 4]
    assert {f.code for f in findings} == ({expected} if expected else set())


@pytest.mark.parametrize("language", ["sh", "text"])
def test_lint_fenced_union_includes_each_physical_line_of_a_continuation(language):
    body = "## Do\nUse the project check.\n```" + language + "\necho \\\npytest -q\n```\n"
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("value", ['"~~~"', "|\n  ~~~\n  An independent field continuation."])
@pytest.mark.parametrize("field", ["hypothesis", "prediction"])
def test_lint_argon_bare_and_multiline_metadata_fences_are_independent(field, value):
    data = re.sub(rb"(?m)^" + field.encode() + rb":.*$", (field + ": " + value).encode(),
                  lint_bytes(body="## Do\nRun `Bash` with `pytest -q`.\n"))
    assert {"vendor_name", "concrete_command"} <= lint_codes(lint.lint_rule(data, LINT_PATH))


@pytest.mark.parametrize("body", [
    "## Do\n- Keep a literal backtick: `.\n    - Run `Bash` with `pytest -q`.\n",
    "## Do\n- Outer\n    - Middle\n        - Run `Bash` with `pytest -q`.\n",
])
def test_lint_argon_nested_list_inputs_keep_both_command_diagnostics(body):
    assert {"vendor_name", "concrete_command"} <= lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("marker", ["- item", "> x"])
def test_lint_argon_fenced_evidence_heading_cannot_suppress_notes(marker):
    body = ("## Do\nUse the ${SLOT.TEST_RUNNER} capability.\n```markdown\n" + marker
            + "\n## Evidence\n```\n## Notes\nRun `Bash` with `pytest -q` and ${SLOT.UNKNOWN}.\n")
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert {"vendor_name", "concrete_command", "unknown_slot"} <= lint_codes(result)


def test_lint_argon_shell_redirection_cannot_end_a_fence():
    body = "## Do\nUse the project check.\n```sh\n>2 echo starting\npytest -q\n```\n"
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("path,identity", [
    (".aegis/rules/contracts/nested/sample.md", "sample"),
    (".aegis/rules/traps/nested/sample.md", "sample"),
    (".aegis/rules/sample.md", "sample"),
    (".aegis/rules/trap/sample.md", "sample"),
    (".aegis/rules/unknown/sample.md", "sample"),
    (".aegis/rules/traps/sample.MD", "sample"),
    (".aegis/rules/traps/README.md", "README"),
    (".aegis/rules/traps/.hidden.md", ".hidden"),
    (".aegis/rules/traps/.md", ".md"),
])
def test_rule_path_id_public_export_matches_runtime_record_identity(path, identity):
    import aegis_core.rules as rules
    from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry

    data = lint_bytes().replace(b"id: sample", ("id: " + identity).encode())
    entry = RuleInventoryEntry(path, path, data, "", len(data))
    records = rules.load_rules("/", inventory=RuleInventory((entry,), "identity-test")).rules
    assert len(records) == 1 and records[0].id == identity
    assert rules.rule_path_id(path) == records[0].id
    assert "rule_path_id" in rules.__all__


@pytest.mark.parametrize("other_path", [
    ".aegis/rules/contracts/nested/sample.md", ".aegis/rules/traps/nested/sample.md",
    ".aegis/rules/sample.md", ".aegis/rules/trap/sample.md",
    ".aegis/rules/unknown/sample.md", ".aegis/rules/traps/sample.MD",
])
@pytest.mark.parametrize("selected", ["all", "small", "large"])
def test_lint_oversized_error_records_keep_runtime_duplicate_identity(tmp_path, monkeypatch, other_path, selected):
    from aegis_core.rules import load_rules
    from aegis_core.yaml_engine.frontmatter import split_frontmatter

    root = lint_root(tmp_path)
    other = root / other_path
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_bytes(lint_bytes() + b"x" * lint.MAX_RULE_BYTES)
    records = load_rules(root).rules
    assert len(records) == 2 and all("duplicate rule id" in r.error for r in records)
    calls = []

    def bounded_load(workspace, **kwargs):
        entries = kwargs["inventory"].entries
        assert {entry.relative_path for entry in entries} == {LINT_PATH, other_path}
        assert all(len(entry.content) <= lint.MAX_RULE_BYTES for entry in entries)
        prefix = next(entry.content for entry in entries if entry.relative_path == other_path)
        assert prefix.endswith(b"\n")
        assert not split_frontmatter(prefix.decode("utf-8-sig"))[2].strip()
        calls.append(entries)
        return load_rules(workspace, **kwargs)

    monkeypatch.setattr(lint, "load_rules", bounded_load)
    paths = [] if selected == "all" else [LINT_PATH if selected == "small" else other_path]
    results = lint.lint_workspace(root, paths)
    assert {r.path for r in results} == ({LINT_PATH, other_path} if selected == "all" else set(paths))
    for result in results:
        assert lint_codes(result) == ({"too_large", "duplicate"} if result.path == other_path else {"duplicate"})
    assert len(calls) == 1  # Only bounded frontmatter from the oversized rule is loaded.
    monkeypatch.setattr(lint, "load_rules", load_rules)
    other.unlink()
    assert lint.lint_workspace(root)[0].ok


@pytest.mark.parametrize("path", [".aegis/rules/traps/README.md", ".aegis/rules/traps/readme.MD",
                                  ".aegis/rules/README.md", ".aegis/rules/trap/README.md",
                                  ".aegis/rules/contracts/nested/README.md"])
@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("malformed", [False, True])
def test_lint_rule_bearing_readmes_match_runtime_error_records(tmp_path, path, selected, malformed):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    (root / LINT_PATH).unlink()
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"---\nid: [unterminated\n---\n" if malformed else
                       lint_bytes().replace(b"id: sample", ("id: " + target.stem).encode()))
    records = load_rules(root).rules
    assert len(records) == 1 and not records[0].ok
    results = lint.lint_workspace(root, [path] if selected else [])
    assert len(results) == 1 and results[0].path == path
    assert lint_codes(results[0]) == {"loader"}


@pytest.mark.parametrize("name", ["README.md", "readme.MD"])
@pytest.mark.parametrize("content", [b"# Documentation\n", b"---\ntitle: Rule author guide\n---\n# Notes\n"])
def test_lint_bounded_readme_documentation_keeps_runtime_exclusion(tmp_path, name, content):
    root = lint_root(tmp_path)
    path = ".aegis/rules/traps/" + name
    (root / path).write_bytes(content)
    assert len(lint.lint_workspace(root)) == 1
    assert lint.lint_workspace(root, [path]) == ()


@pytest.mark.parametrize("path", [".aegis/rules/README.md", ".aegis/rules/traps/README.MD",
                                  ".aegis/rules/sample.md", ".aegis/rules/trap/sample.md"])
@pytest.mark.parametrize("ending", [b"", b"\xff", b"\xc3"], ids=["valid", "invalid", "truncated"])
def test_lint_plain_oversized_documentation_uses_loader_classification_without_yaml(tmp_path, monkeypatch, path, ending):
    from aegis_core.rules import load_rules
    from aegis_core.yaml_engine.frontmatter import split_frontmatter

    root = lint_root(tmp_path)
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    # Include a multibyte character spanning the lint byte-cap boundary.
    data = b"# " + b"x" * (lint.MAX_RULE_BYTES - 3) + "é".encode() + b"notes\n"
    target.write_bytes(data + ending)
    records = load_rules(root).rules
    calls = []

    def bounded_load(workspace, **kwargs):
        entries = kwargs["inventory"].entries
        assert all(len(entry.content) <= lint.MAX_RULE_BYTES for entry in entries)
        prefixes = [entry for entry in entries if entry.relative_path == path]
        assert len(prefixes) == 1  # Invalid bytes beyond capture cannot change classification.
        for entry in prefixes:
            assert split_frontmatter(entry.content.decode("utf-8-sig"))[0] == "none"
        calls.append(entries)
        return load_rules(workspace, **kwargs)

    monkeypatch.setattr(lint, "load_rules", bounded_load)
    results = lint.lint_workspace(root)
    by_path = {r.path: r for r in results}
    assert {r.path for r in records} == set(by_path)
    assert len(results) == 1 and results[0].ok
    assert len(calls) == 1


def test_lint_frontmatter_classification_prefixes_obey_the_aggregate_budget_before_yaml(tmp_path, monkeypatch):
    root = lint_root(tmp_path)
    for path in (".aegis/rules/README.md", ".aegis/rules/traps/README.md"):
        (root / path).write_bytes(b"---\ntitle: " + b"x" * (lint.MAX_RULE_BYTES - 32)
                                 + b"\n---\n" + b"body" * 32)
    monkeypatch.setattr(lint, "MAX_RULE_TOTAL", lint.MAX_RULE_BYTES)

    def forbidden_load(*args, **kwargs):
        pytest.fail("aggregate budget exhausted before rule loading")

    monkeypatch.setattr(lint, "load_rules", forbidden_load)
    results = lint.lint_workspace(root)
    assert len(results) == 1 and lint_codes(results[0]) == {"too_large"}


def test_lint_rule_bearing_readme_is_reported_by_real_cli(tmp_path):
    import json
    import subprocess
    import sys

    root = lint_root(tmp_path)
    (root / LINT_PATH).unlink()
    path = ".aegis/rules/traps/README.md"
    (root / path).write_bytes(lint_bytes().replace(b"id: sample", b"id: README"))
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop("AEGIS_WORKSPACE", None)
    process = subprocess.run([sys.executable, "-m", "aegis_cli", "rule", "lint", "--json", "--workspace", str(root)],
                             cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
    assert process.returncode == 0
    result = json.loads(process.stdout)["results"]
    assert len(result) == 1 and result[0]["path"] == path
    assert {f["code"] for f in result[0]["findings"]} == {"loader"}
    assert "No rules found" not in process.stdout + process.stderr


@pytest.mark.parametrize("marker", ["-", "*", "+", "1.", "2)"])
@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
def test_lint_stripped_reading_recovers_nested_multiline_commands(marker, ending):
    body = ending.join(["## Do", "Use the project check.", marker + " Keep a literal backtick: `.",
                        "    " + marker + " Run `pytest", "      -q`.", ""])
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert any(f.code == "concrete_command" and "${SLOT.TEST_RUNNER}" in f.suggestions for f in result.findings)


@pytest.mark.parametrize("marker", ["-", "*", "+", "1.", "2)"])
@pytest.mark.parametrize("fence", ["```", "~~~", "````"])
def test_lint_stripped_reading_recovers_nested_fences(marker, fence):
    body = ("## Do\nUse the project check.\n" + marker + " Outer\n    " + marker
            + " Inner\n      " + fence + "sh\n      pytest -q\n      " + fence + "\n")
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("prefix", ["> > - 1. ", "  - > 2) > ", "\t+ > - "])
def test_lint_stripped_reading_repeatedly_removes_mixed_containers(prefix):
    body = ("## Do\nUse the project check.\n" + prefix + "```sh\n" + prefix
            + "pytest -q\n" + prefix + "```\n")
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("marker", ["-", "*", "+", "1.", "2)"])
def test_lint_stripped_reading_does_not_turn_nested_prose_into_commands(marker):
    body = ("## Do\nUse the project check.\n" + marker + " Discuss pytest -q in ordinary prose.\n    "
            + marker + " Keep notes about Bash and project tools.\n")
    assert not any(f.check == 4 for f in lint.lint_rule(lint_bytes(body=body), LINT_PATH).findings)


@pytest.mark.parametrize("blank", ["", "    ", "> ", "    - "])
def test_lint_stripped_reading_multiline_windows_stop_at_blank_lines(blank):
    body = "## Do\nUse the project check.\n- Outer\n    - Run `audit-local\n" + blank + "\n      --strict`.\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH, command_slots={"TEST_RUNNER": "audit-local --strict"})
    assert "concrete_command" not in lint_codes(result)


@pytest.mark.parametrize("opening,closing,matched", [("```", "```", False), ("```", "````", False),
                                                    ("~~~", "~~~", False), ("```", "``", True),
                                                    ("```", "~~~", True)])
def test_lint_stripped_reading_requires_a_matching_fence_close(opening, closing, matched):
    body = ("## Do\nUse the project check.\n- Outer\n    - Inner\n      " + opening
            + "sh\n      " + closing + "\n      pytest -q\n")
    assert ("concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))) is matched


@pytest.mark.parametrize("example", ["ordinary words", "ast.Constant('pytest')", "'pytest -q'"])
def test_lint_stripped_reading_keeps_literal_exemptions_and_unmapped_supplemental_silence(example):
    body = "## Do\nUse the project check.\n- Outer\n    - Inner\n      ```python\n      " + example + "\n      ```\n"
    assert not any(f.check == 4 for f in lint.lint_rule(lint_bytes(body=body), LINT_PATH).findings)


@pytest.mark.parametrize("body", [
    "## Do\n- Keep a literal backtick: `.\n    - Run `pytest -q\n      --strict`.\n",
    "## Do\nUse the project check.\n- Outer\n    - Inner\n      ~~~sh\n      pytest -q\n      ~~~\n",
    "## Do\nUse the project check.\n- Outer\n    - > ~~~sh\n      > pytest -q\n      > ~~~\n",
])
def test_lint_security_nested_container_inputs_have_configured_command_findings(body):
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("fence", ["```", "~~~"])
@pytest.mark.parametrize("command,code", [("pytest -q", "concrete_command"),
                                         ("project-audit --strict", "unmapped_command")])
def test_lint_tab_continuation_preserves_the_primary_fence_reading(fence, command, code):
    body = "## Do\nUse the project check.\n- " + fence + "sh\n\t" + command + "\n  " + fence + "\n"
    assert code in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("fence", ["```", "~~~"])
def test_lint_indent_tab_expansion_preserves_tabs_inside_command_arguments(fence):
    command = 'audit-local "keep\ttab"'
    body = "## Do\nUse the project check.\n- " + fence + "sh\n\t" + command + "\n  " + fence + "\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH, command_slots={"TEST_RUNNER": command})
    assert "concrete_command" in lint_codes(result)
    assert "unmapped_command" not in lint_codes(result)


@pytest.mark.parametrize("path", [
    ".aegis/rules/sample.md", ".aegis/rules/traps/nested/sample.md",
    ".aegis/rules/contracts/nested/sample.md", ".aegis/rules/unknown/sample.md",
    ".aegis/rules/traps/.sample.md", ".aegis/rules/traps/sample.MD",
    ".aegis/rules/traps/README.md", ".aegis/rules/traps/readme.MD", ".aegis/rules/README.md",
])
@pytest.mark.parametrize("selected", ["all", "trap", "note"])
def test_lint_oversized_title_only_documents_keep_runtime_classification(tmp_path, path, selected):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"---\ntitle: Notes\n---\n" + b"x" * lint.MAX_RULE_BYTES)
    records = load_rules(root).rules
    assert len(records) == 1 and records[0].path == LINT_PATH and records[0].ok
    paths = [] if selected == "all" else [LINT_PATH if selected == "trap" else path]
    results = lint.lint_workspace(root, paths)
    if selected == "note":
        assert results == ()
    else:
        assert len(results) == 1 and results[0].path == LINT_PATH and results[0].ok
        assert "duplicate" not in lint_codes(results[0])


@pytest.mark.parametrize("metadata", ["type: trap", "target_paths: [src/**]", "forbid_ast:\n  calls: [eval]"])
@pytest.mark.parametrize("path", [".aegis/rules/sample.md", ".aegis/rules/unknown/sample.md"])
def test_lint_oversized_frontmatter_rule_signals_still_reserve_runtime_identities(tmp_path, metadata, path):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(("---\n" + metadata + "\n---\n").encode() + b"x" * lint.MAX_RULE_BYTES)
    records = load_rules(root).rules
    assert len(records) == 2 and all("duplicate rule id" in r.error for r in records)
    results = lint.lint_workspace(root)
    assert len(results) == 2 and all("duplicate" in lint_codes(r) for r in results)
    assert "too_large" in lint_codes(next(r for r in results if r.path == path))


@pytest.mark.parametrize("tail", ["", "    " + "x" * 350, "x" * 350])
def test_lint_argon_empty_nested_markers_cannot_satisfy_the_do_window(tail):
    result = lint.lint_rule(lint_bytes(body="## Do\n-\n    -\n" + tail + "\n"), LINT_PATH)
    assert not result.ok
    assert sum(f.code == "do_window" for f in result.findings) == 1


@pytest.mark.parametrize("command", ["bespoke-check --strict", "bespoke-check"])
def test_lint_argon_stripped_inline_examples_keep_unmapped_command_warnings(command):
    body = "## Do\n- Outer\n    - Middle\n        - Run `" + command + "`.\n"
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    assert "unmapped_command" in lint_codes(result)


def test_lint_argon_stripped_fence_unknown_commands_remain_supplemental():
    body = "## Do\nUse the project check.\n- Outer\n    - Middle\n        ```sh\n        bespoke-check --strict\n        ```\n"
    assert not any(f.check == 4 for f in lint.lint_rule(lint_bytes(body=body), LINT_PATH).findings)


@pytest.mark.parametrize("body", [
    "## Do\n- > ```sh\n  > pytest -q\n  > ```\n",
    "## Do\n- Use ${SLOT.TEST_RUNNER}.\n    - ```markdown\n      example\n    ```\n  Run `pytest\n  -q`.\n",
    "## Do\n- Outer\n    - Middle\n        - Run `pytest\n          -q`.\n",
])
def test_lint_argon_quote_and_fence_inversion_inputs_are_checked(body):
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("path", [".aegis/rules/README.md", ".aegis/rules/sample.md"])
@pytest.mark.parametrize("body_size", [lint.MAX_RULE_BYTES + 4, lint.MAX_RULE_BYTES + 10])
@pytest.mark.parametrize("selected", ["all", "trap", "note"])
def test_lint_argon_oversized_empty_frontmatter_is_documentation(tmp_path, path, body_size, selected):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    (root / path).write_bytes(b"---\n---\n# Documentation\n" + b"a" * body_size)
    assert len(load_rules(root).rules) == 1
    paths = [] if selected == "all" else [LINT_PATH if selected == "trap" else path]
    results = lint.lint_workspace(root, paths)
    assert results == () if selected == "note" else len(results) == 1 and results[0].ok


@pytest.mark.parametrize("direction", ["shrink", "grow"])
def test_lint_argon_size_changes_between_candidate_and_inventory_are_changed(tmp_path, monkeypatch, direction):
    root = lint_root(tmp_path)
    path = root / LINT_PATH
    small = lint_bytes()
    large = small + b"x" * lint.MAX_RULE_BYTES
    initial, final = (large, small) if direction == "shrink" else (small, large)
    path.write_bytes(initial)
    inventory = lint.inventory_rules
    calls = []

    def changed(workspace):
        if not calls:
            path.write_bytes(final)
            calls.append(True)
        return inventory(workspace)

    monkeypatch.setattr(lint, "inventory_rules", changed)
    result = lint.lint_workspace(root, [LINT_PATH])
    assert len(result) == 1 and lint_codes(result[0]) == {"changed"}
    retry = lint.lint_workspace(root, [LINT_PATH])[0]
    assert retry.ok if direction == "shrink" else lint_codes(retry) == {"too_large"}


@pytest.mark.parametrize("signature", [b"", b"\xef\xbb\xbf"])
@pytest.mark.parametrize("ending", ["\n", "\r\n"])
@pytest.mark.parametrize("invalid_tail", [False, True])
def test_lint_bounded_frontmatter_preserves_unicode_boundaries_and_encoding_errors(tmp_path, signature, ending, invalid_tail):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    path = ".aegis/rules/sample.md"
    text = ending.join(["---", "title: 文書", "---", "é" * lint.MAX_RULE_BYTES])
    (root / path).write_bytes(signature + text.encode() + (b"\xff" if invalid_tail else b""))
    records = load_rules(root).rules
    results = lint.lint_workspace(root)
    assert {r.path for r in results} == {r.path for r in records}
    # The coordinator's bounded-prefix ruling makes the uncaptured tail irrelevant.
    assert len(results) == 1 and results[0].ok


def test_lint_oversized_gate_does_not_capture_sources_from_its_frontmatter_prefix(tmp_path, monkeypatch):
    root = lint_root(tmp_path)
    path = ".aegis/rules/traps/large.md"
    data = lint_bytes(extra="forbid_ast:\n  calls: [eval]\n").replace(b"id: sample", b"id: large")
    (root / path).write_bytes(data + b"x" * lint.MAX_RULE_BYTES)

    def forbidden_sources(*args, **kwargs):
        pytest.fail("oversized rule must be refused before source capture")

    monkeypatch.setattr(lint, "iter_confined_files", forbidden_sources)
    results = lint.lint_workspace(root, [path])
    assert len(results) == 1 and lint_codes(results[0]) == {"too_large"}


@pytest.mark.parametrize("marker", ["-", "1."])
@pytest.mark.parametrize("fence", ["```", "~~~"])
@pytest.mark.parametrize("command,continuation,slots,role", [
    ("ruff", "check src", None, "LINTER"),
    ("package", "verify", {"BUILD_TOOL": "package verify"}, "BUILD_TOOL"),
    ("python3", "-m pytest", None, "TEST_RUNNER"),
])
def test_lint_stripped_fences_join_logical_shell_continuations(marker, fence, command, continuation, slots, role):
    body = ("## Do\nUse the project check.\n" + marker + " Outer\n    " + marker + " Inner\n      "
            + fence + "sh\n      " + command + " \\\n        " + continuation + "\n      " + fence + "\n")
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH, command_slots=slots)
    assert any(f.code == "concrete_command" and "${SLOT." + role + "}" in f.suggestions for f in result.findings)


@pytest.mark.parametrize("path", [
    ".aegis/rules/sample.md", ".aegis/rules/traps/nested/sample.md",
    ".aegis/rules/unknown/sample.md", ".aegis/rules/traps/.sample.md",
    ".aegis/rules/traps/sample.MD", ".aegis/rules/traps/README.md", ".aegis/rules/traps/readme.MD",
])
@pytest.mark.parametrize("selected", ["all", "trap", "note"])
def test_lint_truncated_delimiter_prefixes_keep_runtime_error_identities(tmp_path, path, selected):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    head = b"---\ntitle: Notes\n"
    data = head + b"\n" * (lint.MAX_RULE_BYTES - len(head) - 3) + b"---not-a-delimiter\n"
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    records = {r.path: r for r in load_rules(root).rules}
    assert len(records) == 2 and "unterminated YAML frontmatter" in records[path].error
    paths = [] if selected == "all" else [LINT_PATH if selected == "trap" else path]
    results = lint.lint_workspace(root, paths)
    assert {r.path for r in results} == ({LINT_PATH, path} if selected == "all" else set(paths))
    for result in results:
        duplicate = "duplicate rule id" in (records[result.path].error or "")
        assert ("duplicate" in lint_codes(result)) is duplicate
        if result.path == path:
            assert "too_large" in lint_codes(result)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_lint_complete_closing_delimiter_at_the_prefix_limit_stays_documentation(tmp_path, ending):
    root = lint_root(tmp_path)
    head = b"---\ntitle: Notes\n"
    closing = b"---" + ending
    data = head + b"\n" * (lint.MAX_RULE_BYTES - len(head) - len(closing)) + closing + b"oversized body\n"
    (root / ".aegis/rules/sample.md").write_bytes(data)
    results = lint.lint_workspace(root)
    assert len(results) == 1 and results[0].ok


@pytest.mark.parametrize("do", ["Keep `first` pytest -q `second` as prose.",
                                "Keep ``ast.Constant('`pytest`')`` as data.",
                                "Keep ``['`pytest`', '`Bash`']`` as data."])
def test_lint_recognized_spans_are_opaque_to_stripped_reading(do):
    result = lint.lint_rule(lint_bytes(do=do), LINT_PATH)
    assert not any(f.check == 4 for f in result.findings)


@pytest.mark.parametrize("marker", ["-", "*", "+", "1.", "2)"])
def test_lint_new_list_items_bound_stripped_inline_windows(marker):
    body = "## Do\nUse the project check.\n" + marker + " Keep `pytest\n    " + marker + " -q`.\n"
    assert "concrete_command" not in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("first,second", [("", "> "), ("> ", "> > "), ("> > ", "> ")])
def test_lint_quote_depth_changes_bound_stripped_inline_windows(first, second):
    body = "## Do\nUse the project check.\n" + first + "Keep `pytest\n" + second + "-q`.\n"
    assert "concrete_command" not in lint_codes(lint.lint_rule(lint_bytes(body=body), LINT_PATH))


@pytest.mark.parametrize("do", [
    "In `$" "{SLOT.TOOL_RUN}` Bash runs `$" "{SLOT.TEST_RUNNER}`.",
    "In `$" "{SLOT.TEST_RUNNER}` pytest -q runs `$" "{SLOT.LINTER}`.",
    "Use `$" "{SLOT.TOOL_READ}` before calling `$" "{SLOT.TOOL_EDIT}`.",
    "With `$" "{SLOT.TOOL_READ}` read the header before `$" "{SLOT.TOOL_EDIT}`.",
    "Use `$" "{SLOT.TOOL_READ}` when inspecting `$" "{SLOT.TOOL_EDIT}` targets.",
])
def test_lint_addendum_prose_between_slot_spans_is_not_inspected(do):
    result = lint.lint_rule(lint_bytes(do=do), LINT_PATH)
    assert not any(f.check == 4 for f in result.findings)


@pytest.mark.parametrize("variant", ["argon", "correctness"])
def test_lint_addendum_truncated_comment_delimiters_keep_duplicates(tmp_path, variant):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    header = b"---\ntitle: Notes\n# "
    if variant == "argon":
        data = header + b"a" * (lint.MAX_RULE_BYTES - len(header) - 4) + b"\n---" + b"x: 1\n"
    else:
        data = header + b"x" * (lint.MAX_RULE_BYTES - 23) + b"\n---invalid\n"
    path = ".aegis/rules/sample.md"
    (root / path).write_bytes(data)
    records = load_rules(root).rules
    assert len(records) == 2 and all("duplicate rule id" in r.error for r in records)
    results = lint.lint_workspace(root)
    assert {r.path for r in results} == {LINT_PATH, path}
    assert all("duplicate" in lint_codes(r) for r in results)
    assert "too_large" in lint_codes(next(r for r in results if r.path == path))


@pytest.mark.parametrize("path", [
    ".aegis/rules/traps/large.md", ".aegis/rules/large.md",
    ".aegis/rules/traps/nested/large.md", ".aegis/rules/unknown/large.md",
    ".aegis/rules/traps/README.md",
])
@pytest.mark.parametrize("signature", [b"", b"\xef\xbb\xbf"])
def test_lint_addendum_headerless_oversized_files_keep_neighbor_results(tmp_path, monkeypatch, path, signature):
    from aegis_core.rules import load_rules

    root = lint_root(tmp_path)
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(signature + b"x" * (lint.MAX_RULE_BYTES + 1))
    records = load_rules(root).rules
    monkeypatch.setattr(lint, "MAX_RULE_TOTAL", lint.MAX_RULE_BYTES)
    results = lint.lint_workspace(root)
    assert {r.path for r in results} == {r.path for r in records}
    by_path = {r.path: r for r in results}
    assert by_path[LINT_PATH].ok
    if path in by_path:
        assert lint_codes(by_path[path]) == {"too_large"}


@pytest.mark.parametrize("oversized", [False, True])
def test_lint_addendum_deleted_pre_reads_report_changed(tmp_path, monkeypatch, oversized):
    root = lint_root(tmp_path)
    path = root / LINT_PATH
    if oversized:
        path.write_bytes(lint_bytes() + b"x" * lint.MAX_RULE_BYTES)
    inventory = lint.inventory_rules

    def deleted(workspace):
        path.unlink()
        return inventory(workspace)

    monkeypatch.setattr(lint, "inventory_rules", deleted)
    results = lint.lint_workspace(root, [LINT_PATH])
    assert len(results) == 1 and lint_codes(results[0]) == {"changed"}
    assert lint_codes(lint.lint_workspace(root, [LINT_PATH])[0]) == {"missing"}


@pytest.mark.parametrize("body,code", [
    ("## Do\n```$" "{SLOT.TEST_RUNNER}```\n## Notes\npytest -q is replaced by $" "{SLOT.TEST_RUNNER}.\n", None),
    ("## Do\n- ```$" "{SLOT.TEST_RUNNER}```\n- Keep a literal backtick: `.\n    - Run `pytest\n      -q`.\n", "concrete_command"),
    ("## Do\n- ```$" "{SLOT.TEST_RUNNER}```\n    - Run `pytest\n      -q`.\n", "concrete_command"),
    ("## Do\n- ```$" "{SLOT.TEST_RUNNER}```\n    - Inner\n      ```\n      pytest -q\n      ```\n", "concrete_command"),
    ("## Do\n- Outer\n    - Middle\n        - ```bespoke-check --strict```\n", "unmapped_command"),
])
def test_lint_addendum_inline_triple_spans_never_open_fences(body, code):
    result = lint.lint_rule(lint_bytes(body=body), LINT_PATH)
    if code is None:
        assert not any(f.check == 4 for f in result.findings)
    else:
        assert code in lint_codes(result)


@pytest.mark.parametrize("role", ["TEST_RUNNER", "LINTER", "FORMATTER", "TYPE_CHECKER", "BUILD_TOOL"])
@pytest.mark.parametrize("argument", ["build", "src/read", "src", "tests/unit", "--check"])
@pytest.mark.parametrize("cue", ["Run ", ""])
def test_lint_addendum_role_slots_keep_positional_arguments_in_their_command(role, argument, cue):
    do = cue + "`$" + "{SLOT." + role + "} " + argument + "`."
    result = lint.lint_rule(lint_bytes(do=do), LINT_PATH)
    assert not any(f.check == 4 for f in result.findings)


@pytest.mark.parametrize("role", ["TEST_RUNNER", "LINTER", "FORMATTER", "TYPE_CHECKER", "BUILD_TOOL"])
def test_lint_addendum_role_slots_exempt_only_their_control_segment(role):
    do = "Run `$" + "{SLOT." + role + "} src && pytest -q`."
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(do=do), LINT_PATH))


def test_lint_addendum_capability_slots_still_unwrap_concrete_commands():
    do = "Run `$" "{SLOT.TOOL_RUN} pytest -q`."
    assert "concrete_command" in lint_codes(lint.lint_rule(lint_bytes(do=do), LINT_PATH))


def scan_simulation_row(result):
    rows = [finding for finding in result.findings if finding.check == 7]
    assert len(rows) == 1
    assert (rows[0].code, rows[0].severity) == ("scan_simulation", "warning")
    return rows[0].message


@pytest.mark.parametrize("scenario,expected", [
    ("selected", "scan simulation: selected in all profiles"),
    ("tokens", "scan simulation: not selected in one or more profiles"),
    ("mandatory", "scan simulation: not selected in one or more profiles"),
    ("fitness", "scan simulation: not selected in one or more profiles"),
])
def test_lint_scan_simulation_matches_real_scan_and_cli(tmp_path, monkeypatch, capsys, scenario, expected):
    import argparse
    import json
    from aegis_cli.rule import RuleCommand, run_rule
    from aegis_core.fitness import compute
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES, scan_registry

    root = lint_root(tmp_path)
    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])
    (root / ".aegis/config.json").write_text(json.dumps({"jit": {"max_tokens": 200 if scenario == "tokens" else 2000}}), encoding="utf-8")
    if scenario == "mandatory":
        data = lint_bytes(extra="forbid_ast:\n  calls: [eval]\n").replace(b"advisory", b"gate")
        (root / LINT_PATH).write_bytes(data)
        for name in ("a", "b"):
            (root / LINT_PATH).with_name(name + ".md").write_bytes(data.replace(b"id: sample", b"id: " + name.encode()))
    if scenario == "fitness":
        for name in ("a", "b", "c"):
            (root / LINT_PATH).with_name(name + ".md").write_bytes(lint_bytes().replace(b"id: sample", b"id: " + name.encode()))
        monkeypatch.setattr(scan_service, "for_rules", lambda ws, rules, **k: {
            r.id: compute({"tp": 100 if r.id != "sample" else 0, "fp": 0}) for r in rules})
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    verdicts = []
    for profile in PLATFORM_SLOT_PROFILES:
        actual = scan_service.scan(root, ["src/a.py"], registry=scan_registry(profile, root))
        assert actual.get("status") != "FAIL"
        verdicts.append("sample" in actual.exposure_rule_ids())
    assert all(verdicts) is (scenario == "selected")
    for _ in range(2):
        result = lint.lint_workspace(root, [LINT_PATH])[0]
        assert scan_simulation_row(result) == expected
        parser = argparse.ArgumentParser()
        RuleCommand().configure_parser(parser)
        args = parser.parse_args(["lint", LINT_PATH, "--json", "--workspace", str(root)])
        assert run_rule(args) == 0
        row = json.loads(capsys.readouterr().out)["results"][0]
        assert [f["message"] for f in row["findings"] if f["check"] == 7] == [expected]
    assert before == {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("failure,expected", [
    ("profile", "not evaluated: scan projection failed"),
    ("profile_raise", "not evaluated: scan projection failed"),
    ("api", "not evaluated: scan API unavailable"),
    ("simulation_api", "not evaluated: scan API unavailable"),
    ("files", "not evaluated: no changed files"),
    ("io", "not evaluated: scan inputs unavailable"),
])
def test_lint_scan_simulation_fixed_failures_and_retry(tmp_path, monkeypatch, failure, expected):
    root = lint_root(tmp_path)
    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])
    real_select, real_simulate, real_changes = scan_service.select_guidance, scan_service.simulate_rule_selection, git_service.changed_files
    if failure in {"profile", "profile_raise"}:
        def refuse_profile(*args, **kwargs):
            result = real_select(*args, **kwargs)

            def refuse(registry):
                from aegis_core.guidance_projection import GuidanceProjectionError

                if failure == "profile_raise":
                    raise GuidanceProjectionError("UNTRUSTED")
                return {"status": "FAIL", "error": "UNTRUSTED"}

            result.with_registry = refuse
            return result

        monkeypatch.setattr(scan_service, "select_guidance", refuse_profile)
    elif failure == "api":
        monkeypatch.setattr(scan_service, "select_guidance", None)
    elif failure == "simulation_api":
        monkeypatch.setattr(scan_service, "simulate_rule_selection", None)
    elif failure == "files":
        monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: [])
    else:
        def unavailable(*args, **kwargs):
            raise OSError("UNTRUSTED")

        monkeypatch.setattr(git_service, "changed_files", unavailable)
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == expected
    monkeypatch.setattr(scan_service, "select_guidance", real_select)
    monkeypatch.setattr(scan_service, "simulate_rule_selection", real_simulate)
    monkeypatch.setattr(git_service, "changed_files", real_changes)
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == "scan simulation: selected in all profiles"


def test_lint_scan_simulation_concurrent_calls_use_one_snapshot(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    root = lint_root(tmp_path)
    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: lint.lint_workspace(root, [LINT_PATH])[0], range(6), timeout=15))
    assert all(scan_simulation_row(r) == "scan simulation: selected in all profiles" for r in results)
    assert all(r == results[0] for r in results)


@pytest.mark.parametrize("mutation", ["replace", "remove"])
def test_lint_scan_simulation_keeps_captured_candidate_bytes(tmp_path, monkeypatch, mutation):
    root = lint_root(tmp_path)
    original_module = scan_service.rule_integrity
    original = original_module.effective

    def replace_before_capture(*args, **kwargs):
        if mutation == "replace":
            (root / LINT_PATH).write_bytes(lint_bytes(do="A concurrent replacement."))
        else:
            (root / LINT_PATH).unlink()
        return original(*args, **kwargs)

    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])
    monkeypatch.setattr(scan_service, "rule_integrity", SimpleNamespace(effective=replace_before_capture, IntegrityError=original_module.IntegrityError))
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == "scan simulation: selected in all profiles"
    monkeypatch.setattr(scan_service, "rule_integrity", original_module)
    (root / LINT_PATH).write_bytes(lint_bytes())
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == "scan simulation: selected in all profiles"


def test_lint_scan_simulation_never_reloads_candidate_bytes(tmp_path, monkeypatch):

    root = lint_root(tmp_path)
    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])

    def forbidden(*args, **kwargs):
        pytest.fail("simulation reopened rule files after lint's bounded capture")

    monkeypatch.setattr(scan_service, "RULE_CACHE", SimpleNamespace(snapshot=forbidden))
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == "scan simulation: selected in all profiles"


def test_lint_scan_simulation_does_not_parse_oversized_unselected_rules(tmp_path, monkeypatch):

    root = lint_root(tmp_path)
    (root / LINT_PATH).with_name("large.md").write_bytes(lint_bytes().replace(b"id: sample", b"id: large") + b"x" * lint.MAX_RULE_BYTES)
    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])
    original = rule_schema.load_rules

    def bounded_loader(workspace, inventory=None):
        assert inventory is not None
        assert all(len(entry.content) <= lint.MAX_RULE_BYTES for entry in inventory.entries)
        return original(workspace, inventory=inventory)

    monkeypatch.setattr(rule_schema, "load_rules", bounded_loader)
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == "not evaluated: scan inputs over limit"


@pytest.mark.parametrize("limit", ["file", "total", "count"])
def test_lint_scan_simulation_bounds_precede_selection(monkeypatch, limit):
    import hashlib
    from dataclasses import replace
    from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry
    from aegis_core.rules import load_rules

    data = lint_bytes()
    entry = RuleInventoryEntry(LINT_PATH, LINT_PATH, data, hashlib.sha256(data).hexdigest(), len(data))
    inventory = RuleInventory((entry,), "bounded-test")
    ruleset = load_rules("/", inventory=inventory)
    if limit == "file":
        entries = (replace(entry, content=b"x" * (lint.MAX_RULE_BYTES + 1)),)
    elif limit == "total":
        entries = (replace(entry, content=b"x" * lint.MAX_RULE_BYTES),) * (lint.MAX_RULE_TOTAL // lint.MAX_RULE_BYTES + 1)
    else:
        entries = (entry,) * (lint.MAX_RULES + 1)

    def forbidden(*args, **kwargs):
        pytest.fail("over-limit inputs reached effective rule loading")

    monkeypatch.setattr(scan_service, "rule_integrity", SimpleNamespace(effective=forbidden, IntegrityError=scan_service.rule_integrity.IntegrityError))
    assert scan_service.simulate_rule_selection("/", replace(inventory, entries=entries), ruleset) == {
        "sample": "not evaluated: scan inputs over limit"}


def test_lint_scan_simulation_captures_fitness_once_for_all_profiles(tmp_path, monkeypatch):

    root = lint_root(tmp_path)
    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])
    calls, original = [], scan_service.for_rules

    def capture(workspace, rules, **kwargs):
        calls.append(tuple(r.id for r in rules))
        return original(workspace, rules, **kwargs)

    monkeypatch.setattr(scan_service, "for_rules", capture)
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == "scan simulation: selected in all profiles"
    assert calls == [("sample",)]


@pytest.mark.parametrize("body,visible", [
    ("## Evidence\nObserved context.\n## Do\nUse the capability.\n", False),
    ("## Do\nKeep " + "x" * 272 + " ${SLOT.MODEL_FAST}\n", True),
    ("## Do\nKeep " + "x" * 240 + " ghp_" + "a" * 60 + "\n", True),
    ("## Do\n" + "x" * 294 + "\n", True),
    ("## Do\n" + "x" * 295 + "\n", False),
    ("## Context\none\ntwo\nthree\nfour\nfive\n## Do\nRead.\n", True),
    ("## Context\none\ntwo\nthree\nfour\nfive\nsix\n## Do\nRead.\n", False),
], ids=["evidence_first", "slot_crossing_300", "cleaned_instruction", "exact_300", "over_300", "line_eight", "line_nine"])
def test_lint_do_window_uses_served_detail_and_retries(body, visible):
    from concurrent.futures import ThreadPoolExecutor

    data = lint_bytes(body=body)
    first = lint.lint_rule(data, LINT_PATH)
    assert ("do_window" not in lint_codes(first)) is visible
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: lint.lint_rule(data, LINT_PATH), range(6), timeout=15))
    assert all(result == first for result in results)


@pytest.mark.parametrize("body,visible", [
    ("## Evidence\nObserved context.\n## Do\nUse the capability.\n", False),
    ("## Do\nKeep " + "x" * 272 + " ${SLOT.MODEL_FAST}\n", True),
    ("## Do\nKeep " + "x" * 240 + " ghp_" + "a" * 60 + "\n", True),
], ids=["evidence_first", "slot_crossing_300", "cleaned_instruction"])
def test_lint_do_window_agrees_with_real_scan_detail(tmp_path, body, visible):
    from aegis_core.guidance_projection import project_detail
    from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES, scan_registry

    root = lint_root(tmp_path)
    (root / LINT_PATH).write_bytes(lint_bytes(body=body))
    result = lint.lint_workspace(root, [LINT_PATH])[0]
    assert ("do_window" not in lint_codes(result)) is visible
    if "${SLOT.MODEL_FAST}" in body:
        assert body.index("${SLOT.") < 300 < len(body)
    for profile in PLATFORM_SLOT_PROFILES:
        registry = scan_registry(profile, root)
        detail = project_detail(body, registry)
        scanned = scan_service.scan(root, ["src/a.py"], registry=registry)
        assert "sample" in scanned.exposure_rule_ids()
        if detail:
            assert "   Detail: " + detail + "\n" in scanned["guidance"]
        else:
            assert "   Detail: " not in scanned["guidance"]


@pytest.mark.parametrize("body,prefix,visible", [
    ("## Do\nRead.\n", "## Do\nRead.", True),
    ("## Do\nRead.\n## Evidence\n" + "x" * (1024 * 1024 + 1), "## Do\nRead.", True),
    ("## Evidence\nObserved.\n## Do\nRead.", "## Do\nRead.", False),
    ("## Do\n${SLOT.TOOL_READ} safely.\n", "## Do\n${SLOT.TOOL_READ} safely.", True),
    ("## Do\n" + "x" * 295, "## Do\n" + "x" * 295, False),
    ("## Do\nRead.\n", None, False),
    ("## Do\nRead.\n", {}, False),
    ("## Do\nRead.\n", "x" * (1024 * 1024 + 1), False),
    ("x" * (1024 * 1024 + 1), "## Do\nRead.", False),
    ("## Do\nRead.\x00", "## Do\nRead.", False),
    ("## Do\nRead.", "## Do\nRead.\u202e", False),
    ("## Do\n${SLOT.TOOL_READ}", "## Do\n${SLOT.TOOL_READ}", False),
], ids=["visible", "excluded_large_tail", "evidence_first", "slot", "clipped", "no_instruction", "invalid_prefix", "prefix_limit", "body_limit", "body_control", "prefix_control", "ambiguous_heading"])
def test_public_detail_instruction_visibility_refusals(body, prefix, visible):
    from aegis_core.guidance_projection import detail_instruction_visible
    from aegis_core.skills.slots import DEFAULT_SLOTS, SlotRegistry

    # The final case deliberately makes the slot's replacement a heading.
    registry = SlotRegistry({**DEFAULT_SLOTS, "TOOL_READ": "Read" if visible else "## Evidence"})
    assert detail_instruction_visible(body, prefix, registry) is visible


def reviewed_lint_fixture(tmp_path, reviewed_target, candidate_target, amended):
    root = lint_root(tmp_path / "repo")
    (root / LINT_PATH).unlink()
    repo = hg.Repo(root, hg.Home(tmp_path / "home"))
    path = ".aegis/rules/invariants/sample.md"
    reviewed = (lint_bytes(do="Read reviewed data.", extra="forbid_ast:\n  calls: [eval]\n")
                .replace(b"type: trap", b"type: invariant").replace(b"advisory", b"gate")
                .replace(b"src/**", reviewed_target.encode()))
    repo.write(path, reviewed.decode())
    repo.write("src/a.py", "value = 1\n")
    repo.commit("fixture baseline")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    candidate = reviewed.replace(reviewed_target.encode(), candidate_target.encode())
    if amended:
        candidate = candidate.replace(b"Read reviewed data.", b"Read candidate data.")
    (root / path).write_bytes(candidate)
    repo.write("src/a.py", "value = 2\n")
    return root, path, reviewed


@pytest.mark.parametrize("body,expected_codes,retained,reviewed_targets", [
    ("## Context\nNote.\n### Evidence\nObserved.\n## Do\n" + "x" * 500,
     {"do_window"}, "## Context Note.", None),
    ("## Do\nRead safely.\n## Evidence\u00a0\nRun `pytest -q` ${SLOT.UNKNOWN}.\n",
     {"unknown_slot", "concrete_command"}, "pytest -q", None),
    ("## Do\nRead safely.\n## \u00a0Evidence\nRun `pytest -q` ${SLOT.UNKNOWN}.\n",
     {"unknown_slot", "concrete_command"}, "pytest -q", None),
    ("## Context\n" + "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5 + "\n## Do\n" + "x" * 500,
     {"do_window"}, "[REDACTED_PEM]", None),
    pytest.param(None, set(), None, ("legacy/**", "src/**"),
                 marks=pytest.mark.skipif(not hg.git_ok(), reason="needs git")),
    pytest.param(None, set(), None, ("src/**", "src/**"),
                 marks=pytest.mark.skipif(not hg.git_ok(), reason="needs git")),
    pytest.param(None, set(), None, ("src/**", "legacy/**"),
                 marks=pytest.mark.skipif(not hg.git_ok(), reason="needs git")),
], ids=["level_three_evidence", "trailing_unicode_evidence", "leading_unicode_evidence", "pem_hides_do",
        "reviewed_unmatched", "reviewed_matched", "candidate_unmatched"])
def test_argon_0935_lint_grammar_agrees_with_served_scan(tmp_path, body, expected_codes, retained, reviewed_targets):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.guidance_projection import project_detail

    if reviewed_targets is None:
        root = lint_root(tmp_path)
        path = LINT_PATH
        (root / path).write_bytes(lint_bytes(body=body))
    else:
        root, path, reviewed = reviewed_lint_fixture(tmp_path, *reviewed_targets, True)
    scanned = scan_service.scan(root, ["src/a.py"])
    if reviewed_targets is None:
        assert retained in project_detail(body)
        assert "   Detail: " + project_detail(body) + "\n" in scanned["guidance"]
    else:
        assert scan_service.rule_integrity.effective(root).ruleset.rules[0].raw == reviewed
        assert ("sample" in scanned.exposure_rule_ids()) is (reviewed_targets[0] == "src/**")
    result = lint.lint_workspace(root, [path])[0]
    assert expected_codes <= lint_codes(result)
    assert result.ok is (not expected_codes)
    if reviewed_targets is not None:
        assert scan_simulation_row(result) == "not evaluated: candidate differs from scan snapshot"
    assert lint.lint_workspace(root, [path])[0] == result
    with ThreadPoolExecutor(max_workers=3) as pool:
        retries = list(pool.map(lambda _: lint.lint_workspace(root, [path])[0], range(3), timeout=30))
    assert all(retry == result for retry in retries)


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("reviewed_target,candidate_target,amended", [
    ("legacy/**", "src/**", True),
    ("src/**", "src/**", True),
    ("src/**", "legacy/**", True),
    ("legacy/**", "legacy/**", False),
    ("src/**", "src/**", False),
], ids=["reviewed_unmatched", "reviewed_matched", "candidate_unmatched", "same_unmatched", "same_matched"])
def test_argon_0935_reviewed_bytes_checked_before_matching(tmp_path, reviewed_target, candidate_target, amended):
    from concurrent.futures import ThreadPoolExecutor

    root, path, reviewed = reviewed_lint_fixture(tmp_path, reviewed_target, candidate_target, amended)
    effective = scan_service.rule_integrity.effective(root)
    assert effective.ruleset.rules[0].raw == reviewed
    actual = scan_service.scan(root, ["src/a.py"])
    assert ("sample" in actual.exposure_rule_ids()) is (reviewed_target == "src/**")
    expected = ("not evaluated: candidate differs from scan snapshot" if amended else
                "scan simulation: selected in all profiles" if reviewed_target == "src/**" else
                "scan simulation: not selected in one or more profiles")
    for _ in range(2):
        assert scan_simulation_row(lint.lint_workspace(root, [path])[0]) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: lint.lint_workspace(root, [path])[0], range(3), timeout=30))
    assert all(scan_simulation_row(result) == expected for result in results)
    (root / path).write_bytes(reviewed)
    recovered = lint.lint_workspace(root, [path])[0]
    assert scan_simulation_row(recovered) == ("scan simulation: selected in all profiles" if reviewed_target == "src/**"
                                             else "scan simulation: not selected in one or more profiles")


@pytest.mark.parametrize("code", ["git_timeout", "git_failed", "privacy_refused"])
def test_argon_0935_git_custody_refusals_are_fixed_and_retry(tmp_path, monkeypatch, code):
    from concurrent.futures import ThreadPoolExecutor

    root = lint_root(tmp_path)
    real_run = git_service.run

    def unavailable(*args, **kwargs):
        assert git_service.custody_active()
        raise git_service.GitError("UNTRUSTED_GIT_DIAGNOSTIC", code=code)

    def lint_under_custody(_):
        with git_service.custody(scratch=root):
            return lint.lint_workspace(root, [LINT_PATH])[0]

    monkeypatch.setattr(git_service, "run", unavailable)
    monkeypatch.setattr(git_service, "changed_files", lambda *a, **k: ["src/a.py"])
    with git_service.custody(scratch=root):
        with pytest.raises(git_service.GitError) as caught:
            scan_service.scan(root, ["src/a.py"])
        assert caught.value.code == code
        result = lint.lint_workspace(root, [LINT_PATH])[0]
    assert scan_simulation_row(result) == "not evaluated: scan inputs unavailable"
    assert "UNTRUSTED" not in repr(result)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lint_under_custody, range(3), timeout=15))
    assert all(scan_simulation_row(result) == "not evaluated: scan inputs unavailable" for result in results)
    monkeypatch.setattr(git_service, "run", real_run)
    assert not git_service.custody_active()
    assert scan_simulation_row(lint.lint_workspace(root, [LINT_PATH])[0]) == "scan simulation: selected in all profiles"


@pytest.mark.parametrize("items,decision,fragment", [
    (["## Do\nRead.\n"], 1, "Read."),
    (["## Context\nNote.\n### Evidence\n## Do\nHidden."], 0, None),
    (["## Do\nRead.\n## Evidence\n\x00"], 1, "Read."),
    (["## Do\nRead.\n## Evidence\u00a0\nKeep this."], 1, "Read."),
    (["```text\n## Do\nFenced.\n```\n"], 0, None),
    (["<pre>\n## Do\nLiteral.\n</pre>\n"], 0, None),
    (["    ## Do\n    Code.\n"], 0, None),
    (["## Do\n-\n    -\n- Read.\n"], 1, "- Read."),
    (["## Do\n    Code.\nRead.\n"], 1, "Read."),
    (["## Do\n```${SLOT.TEST_RUNNER}```\n## Evidence\nObserved."], 1, "```${SLOT.TEST_RUNNER}```"),
    (["## Do", "Read."], 1, "Read."),
    (["## Do\nRead.\n```text\n## Evidence\n```\n"], -1, None),
    (["## Do\nRead.\x00"], -3, None),
    (["## Do\n" + "x" * (1024 * 1024 + 1)], -4, None),
    (["x"] * 257, -4, None),
    ([None], -2, None),
], ids=["instruction", "level_three_evidence", "excluded_control", "unicode_evidence", "fenced_do", "html_do",
        "indented_do", "empty_markers", "indented_instruction", "inline_triple", "item_boundary", "ambiguous",
        "control", "character_limit", "item_limit", "mixed"])
def test_public_raw_do_instruction_span(items, decision, fragment):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.guidance_grammar import heading_has_slot, raw_do_instruction_span
    from aegis_core.guidance_projection import contains_control_characters

    result = raw_do_instruction_span(items, heading_has_slot, contains_control_characters)
    assert result[0] == decision
    if decision == 1:
        assert items[result[1]][result[2]:result[3]] == fragment
    with ThreadPoolExecutor(max_workers=3) as pool:
        retries = list(pool.map(lambda _: raw_do_instruction_span(items, heading_has_slot, contains_control_characters), range(3), timeout=15))
    assert all(retry == result for retry in retries)


def assert_heading_lint_scan_agreement(body, instruction, expected, *, instruction_visible=None):
    import hashlib
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.fitness import compute
    from aegis_core.guidance_projection import project_detail
    from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry
    from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES, SlotRegistry

    if instruction_visible is None:
        instruction_visible = expected
    data = lint_bytes(body=body)
    entry = RuleInventoryEntry(LINT_PATH, LINT_PATH, data, hashlib.sha256(data).hexdigest(), len(data))
    ruleset = rule_schema.load_rules("/", inventory=RuleInventory((entry,), "heading-matrix"))
    for profile in PLATFORM_SLOT_PROFILES.values():
        registry = SlotRegistry({**DEFAULT_SLOTS, **profile}).sanitized()
        scanned = scan_service.select_guidance(ruleset, ["src/a.py"], 3, 2000, [],
                                               lambda rules: {r.id: compute({}) for r in rules}, registry=registry)
        detail = project_detail(body, registry)
        assert scanned.exposure_rule_ids() == ("sample",)
        assert "   Detail: " + detail + "\n" in scanned["guidance"]
        assert (instruction in detail) is instruction_visible
    result = lint.lint_rule(data, LINT_PATH)
    assert result.ok is expected
    assert ("do_window" not in lint_codes(result)) is expected
    assert lint.lint_rule(data, LINT_PATH) == result
    with ThreadPoolExecutor(max_workers=3) as pool:
        retries = list(pool.map(lambda _: lint.lint_rule(data, LINT_PATH), range(3), timeout=15))
    assert all(retry == result for retry in retries)


@pytest.mark.parametrize("position", ["", " ", "   ", "> ", "- "],
                         ids=["column_zero", "one_space", "three_spaces", "blockquote", "list_item"])
@pytest.mark.parametrize("kind,heading,expected", [
    ("opening", "## Do", True),
    ("boundary", "## Context", False),
    ("subsection", "### Notes", False),
], ids=["opening", "section_boundary", "subsection"])
def test_formal_1306_heading_matrix_matches_scan(position, kind, heading, expected):
    if kind == "opening":
        body = position + heading + "\nRead.\n"
        instruction = "Read."
        expected = position == ""
    elif kind == "boundary":
        body = "## Do\n" + position + heading + "\nNote.\n## Do\n" + "x" * 500
        instruction = "x" * 500
    else:
        body = "## Do\n" + position + heading + "\n" + "x" * 500
        instruction = "x" * 500
    assert_heading_lint_scan_agreement(body, instruction, expected,
                                       instruction_visible=kind == "opening" or expected)


@pytest.mark.parametrize("body", [
    "## Do\n ## Context\nNote.\n## Do\n" + "x" * 500,
    "## Do\n ### Notes\n" + "x" * 500,
], ids=["correctness_verbatim", "security_verbatim"])
def test_formal_1306_reviewer_bodies_match_scan(body):
    assert_heading_lint_scan_agreement(body, "x" * 500, False)


@pytest.mark.parametrize("position", ["", " ", "   ", "> ", "- "],
                         ids=["column_zero", "one_space", "three_spaces", "blockquote", "list_item"])
@pytest.mark.parametrize("title,reserved", [("Evidence", True), ("evidence### \t", True), ("Evidence\u00a0", False)],
                         ids=["reserved", "closing_hashes", "unicode_tail"])
def test_formal_1306_evidence_decisions_stay_unchanged(position, title, reserved):
    from aegis_core.guidance_grammar import heading_has_slot, raw_evidence_span
    from aegis_core.guidance_projection import contains_control_characters

    body = position + "## " + title + "\nDiscard.\n"
    decision, item, start = raw_evidence_span([body], heading_has_slot, contains_control_characters)
    expected = (1 if not position else -1) if reserved else 0
    assert decision == expected
    assert item == 0
    if reserved:
        assert start == 0


@pytest.mark.parametrize("prefix,opens", [
    ("", True), (" ", False), ("  ", False), ("   ", False),
    ("    ", False), ("     ", False), ("\t", False), (" \t", False),
    ("> ", False), ("- ", False), ("> - ", False), ("1. ", False),
    ("- > ", False), ("\u00a0", False),
], ids=["column_zero", "one_space", "two_spaces", "three_spaces", "four_spaces", "five_spaces",
        "tab", "space_tab", "blockquote", "list_item", "quoted_list", "ordered_list", "list_quote", "unicode_space"])
@pytest.mark.parametrize("section", ["orphan", "context", "already_open"])
def test_argon_1333_do_opening_requires_top_level_heading(prefix, opens, section):
    from aegis_core.guidance_grammar import heading_has_slot, raw_do_instruction_span
    from aegis_core.guidance_projection import contains_control_characters

    body = {"orphan": "", "context": "## Context\n", "already_open": "## Do\n"}[section]
    body += prefix + "## Do\nNote.\n"
    if section != "orphan":
        body += "## Do\n" + "x" * 500
    span = raw_do_instruction_span([body], heading_has_slot, contains_control_characters)
    instruction = "Note." if opens else ("x" * 500 if section != "orphan" else None)
    assert span[0] == (1 if instruction is not None else 0)
    if instruction is not None:
        assert body[span[2]:span[3]] == instruction
    assert_heading_lint_scan_agreement(body, "Note." if section == "orphan" else "x" * 500, opens,
                                       instruction_visible=True if section == "orphan" else False)


def test_argon_1333_indented_do_reproducer_matches_scan():
    body = "## Context\n    ## Do\nNote.\n## Do\n" + "x" * 500
    assert_heading_lint_scan_agreement(body, "x" * 500, False)


@pytest.mark.parametrize("marker,indent", [("-", "  "), ("+", "  "), ("*", "  "),
                                         ("1.", "   "), ("1)", "   ")],
                         ids=["dash", "plus", "star", "ordered_dot", "ordered_paren"])
@pytest.mark.parametrize("section", ["context", "already_open"])
def test_formal_1408_list_continuation_cannot_open_do(marker, indent, section):
    from aegis_core.guidance_grammar import heading_has_slot, raw_do_instruction_span
    from aegis_core.guidance_projection import contains_control_characters

    body = {"context": "## Context\n", "already_open": "## Do\n"}[section]
    body += marker + " item\n\n" + indent + "## Do\n" + indent + "Note.\n\n## Do\n" + "x" * 500
    span = raw_do_instruction_span([body], heading_has_slot, contains_control_characters)
    assert span[0] == 1
    expected_instruction = marker + " item" if section == "already_open" else "x" * 500
    assert body[span[2]:span[3]] == expected_instruction
    assert_heading_lint_scan_agreement(body, "x" * 500, section == "already_open", instruction_visible=False)


def test_formal_1408_reviewer_body_matches_scan():
    body = "## Context\n- item\n\n  ## Do\n  Note.\n\n## Do\n" + "x" * 500
    assert_heading_lint_scan_agreement(body, "x" * 500, False)


@pytest.mark.parametrize("leading", [" ", "  ", "   ", "    ", "\t", "\u00a0"],
                         ids=["one_space", "two_spaces", "three_spaces", "four_spaces", "tab", "nbsp"])
@pytest.mark.parametrize("kind", ["plain", "pem"])
def test_argon_1408_leading_whitespace_cannot_change_do_discovery(leading, kind):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.guidance_grammar import heading_has_slot, raw_do_instruction_span
    from aegis_core.guidance_projection import contains_control_characters, detail_instruction_visible
    from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES, SlotRegistry

    body = leading + "## Do\n"
    if kind == "pem":
        body += "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5 + "\n## Do\n" + "x" * 500
    else:
        body += "Read.\n"
    span = raw_do_instruction_span([body], heading_has_slot, contains_control_characters)
    assert span[0] == (1 if kind == "pem" else 0)
    if kind == "pem":
        assert body[span[2]:span[3]] == "x" * 500
    for profile in (None, *PLATFORM_SLOT_PROFILES.values()):
        registry = SlotRegistry({**DEFAULT_SLOTS, **profile}).sanitized() if profile is not None else None
        assert detail_instruction_visible(body, body.rstrip("\n"), registry) is False
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: detail_instruction_visible(body, body.rstrip("\n"), registry), range(3), timeout=15))
        assert results == [False] * 3
    assert_heading_lint_scan_agreement(body, "x" * 500 if kind == "pem" else "Read.", False,
                                       instruction_visible=kind == "plain")


@pytest.mark.parametrize("leading", ["", "\n", "\n \t\n", "\u00a0\n", "\r\n"],
                         ids=["column_zero", "blank_line", "spaced_blank_lines", "nbsp_blank_line", "crlf"])
def test_argon_1408_preserved_blank_lines_keep_real_instruction_visible(leading):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.guidance_projection import detail_instruction_visible

    body = leading + "## Do\nRead.\n"
    assert detail_instruction_visible(body, body.rstrip("\n")) is True
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: detail_instruction_visible(body, body.rstrip("\n")), range(3), timeout=15))
    assert results == [True] * 3
    assert_heading_lint_scan_agreement(body, "Read.", True)


@pytest.mark.parametrize("separator", ["\u2028", "\u2029"], ids=["line_separator", "paragraph_separator"])
@pytest.mark.parametrize("opening", [
    "##{separator} Do\n",
    "## {separator}Do\n",
    "## Do{separator}\n",
    "## {separator}Do{separator}\n",
    "## Do\n##{separator} Do\n",
    "## Do\n## {separator}Do\n",
    "## Do\n## Do{separator}\n",
], ids=["marker_title", "title_start", "title_end", "title_edges",
        "next_line_marker_title", "next_line_title_start", "next_line_title_end"])
def test_formal_1446_raw_and_rendered_do_divergence_is_refused(separator, opening):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.guidance_projection import detail_instruction_visible
    from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES, SlotRegistry

    body = opening.format(separator=separator)
    body += "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5 + "\n## Do\n" + "x" * 500
    for profile in (None, *PLATFORM_SLOT_PROFILES.values()):
        registry = SlotRegistry({**DEFAULT_SLOTS, **profile}).sanitized() if profile is not None else None
        assert detail_instruction_visible(body, body, registry) is False
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: detail_instruction_visible(body, body, registry), range(3), timeout=15))
        assert results == [False] * 3
    assert_heading_lint_scan_agreement(body, "x" * 500, False)


@pytest.mark.parametrize("value", ["Read.\nNext.", "## Context\nRead.\n## Do\nNext.", "\nRead."],
                         ids=["shortened_span", "changed_section", "shifted_start"])
def test_formal_1446_expansion_cannot_change_raw_instruction_span(value):
    from aegis_core.guidance_projection import detail_instruction_visible, project_detail

    body = "## Do\n${SLOT.TEST_RUNNER}"
    registry = {"TEST_RUNNER": value}
    assert "Read." in project_detail(body, registry)
    assert detail_instruction_visible(body, body, registry) is False


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])
@pytest.mark.parametrize("separator", ["", "\u2028", "\u2029"], ids=["plain", "line_separator", "paragraph_separator"])
def test_formal_1446_same_raw_instruction_survives_layout_and_expansion(newline, separator):
    from aegis_core.guidance_projection import detail_instruction_visible
    from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES, SlotRegistry

    body = newline.join(["## Context", "${SLOT.MODEL_FAST}", "## Do", separator,
                         "${SLOT.TOOL_READ} safely.  ", ""])
    for profile in PLATFORM_SLOT_PROFILES.values():
        registry = SlotRegistry({**DEFAULT_SLOTS, **profile}).sanitized()
        assert detail_instruction_visible(body, body, registry) is True
    assert_heading_lint_scan_agreement(body, "safely.", True)
