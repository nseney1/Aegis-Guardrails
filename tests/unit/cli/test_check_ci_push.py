"""`aegis check --ci` when there is nothing to compare (R-trust-17).

A push to the default branch, a dispatch run or a stale branch resolves the base to the head (or
to a descendant of it): the range is empty, so the run says it compared nothing instead of the
PASSED a real comparison prints. Exit code and JSON shape stay as they were; a pull request run
still compares its base with its head. Real git; no network, no host CLI.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import fields
import json
import os
from pathlib import Path
from string import Formatter
from types import SimpleNamespace
from typing import Optional, get_type_hints

import pytest

from aegis_cli.cli import main
from aegis_cli import check as check_cli
from aegis_cli import ci_inputs
from aegis_cli.ci_inputs import Event
from aegis_cli.formatters import report as report_formats
from aegis_core import approval_policy, checkrun, credit, gitsafe, redaction, regression
from aegis_core import config as core_config
from aegis_core import rule_integrity as ci_integrity
from aegis_core.verification import coverage_check, perf_check
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

GATE = ".aegis/rules/gates/gate-no-eval.md"
RULE = ("---\nid: gate-no-eval\ntype: gate\nenforcement: gate\nhypothesis: Never eval\n"
        "target_paths:\n  - 'src/*.py'\nforbid_ast:\n  calls:\n    - eval\n---\n# No eval\n\nThe body explains why.\n")
NOTE = "nothing was compared"
PASSED = "PASSED, no rule weakened"

SWEPT_OUTPUT_MODULES = ("aegis_core/redaction.py", "aegis_core/rule_integrity.py", "aegis_core/approval_policy.py", "aegis_cli/check.py",
                        "aegis_cli/approve.py", "aegis_cli/formatters/report.py", "aegis_cli/ci_inputs.py")
EXECUTION_MARKERS = ("$(gm1b)", "`gm1b`", ";gm1b", "\n::warning::forged", "\r::warning::forged",
                     "(gm1b)", "gm1b)", "'gm1b'", '"gm1b"')
EXECUTION_MARKER_IDS = ("substitution", "backtick", "semicolon", "newline", "cr",
                        "parentheses", "close-parenthesis", "single-quote", "double-quote")


def _message_census():
    """Discover production message schemas, including every weakening/refusal code."""
    root = Path(__file__).resolve().parents[3]
    assert set(approval_policy.MESSAGE_OWNERS) == set(approval_policy.MESSAGE_TEMPLATES)
    schemas = {(kind, approval_policy.MESSAGE_TEMPLATES[name]):
               {field for _, field, _, _ in Formatter().parse(approval_policy.MESSAGE_TEMPLATES[name]) if field}
               for name, (_producer, kind) in approval_policy.MESSAGE_OWNERS.items() if kind is not None}
    observed, codes, registered = set(), set(), set()
    sources = {"aegis_core/rule_integrity.py": {"weakenings"},
               "aegis_core/approval_policy.py": {"owner_review_required"},
               "aegis_cli/approve.py": {"approve"}, "aegis_cli/check.py": {"ci"},
               "aegis_cli/formatters/report.py": {"layer1", "findings", "regression"}}
    for path in SWEPT_OUTPUT_MODULES:
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                    and ((isinstance(node.value, ast.Name) and node.value.id == "MESSAGE_TEMPLATES")
                         or (isinstance(node.value, ast.Attribute) and node.value.attr == "MESSAGE_TEMPLATES")):
                name = node.slice.value
                template = approval_policy.MESSAGE_TEMPLATES[name]
                if not any(field for _, field, _, _ in Formatter().parse(template)):
                    producer, kind = approval_policy.MESSAGE_OWNERS[name]
                    assert producer in sources[path]
                    registered.add(name)
                    observed.add((kind, template))
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if name == "GuidanceMessage":
                if isinstance(node.args[0], ast.Name) and node.args[0].id == "code" and path == "aegis_core/rule_integrity.py":
                    assert isinstance(node.args[1], ast.Subscript) and node.args[1].slice.value == "legacy_value"
                    assert approval_policy.MESSAGE_OWNERS["legacy_value"] == ("weakenings", None)
                    registered.add("legacy_value")
                    continue  # The legacy Weakening(string) adapter treats the entire string as data.
                assert len(node.args) >= 2 and isinstance(node.args[0], ast.Constant), path
                kind = node.args[0].value
                template_node = node.args[1]
                if isinstance(template_node, ast.Constant):
                    template = template_node.value
                elif isinstance(template_node, ast.Subscript):
                    container = template_node.value
                    assert (isinstance(container, ast.Name) and container.id == "MESSAGE_TEMPLATES") or \
                        (isinstance(container, ast.Attribute) and container.attr == "MESSAGE_TEMPLATES"), path
                    assert isinstance(template_node.slice, ast.Constant), path
                    registered.add(template_node.slice.value)
                    template = approval_policy.MESSAGE_TEMPLATES[template_node.slice.value]
                    producer, owned_kind = approval_policy.MESSAGE_OWNERS[template_node.slice.value]
                    assert producer in sources[path] and owned_kind == kind, (path, producer, kind)
                elif isinstance(template_node, ast.Attribute) and isinstance(template_node.value, ast.Name) \
                        and template_node.value.id == "approval_policy":
                    template = vars(approval_policy)[template_node.attr]
                else:
                    assert isinstance(template_node, ast.Name) and template_node.id == "_CI_EVENT_ERROR", path
                    template = ci_inputs.CI_EVENT_ERROR
                fields = {key for _, key, _, _ in Formatter().parse(template) if key is not None}
                assert len(node.args) == 3 and isinstance(node.args[2], ast.Dict), (path, kind)
                assert fields == {key.value for key in node.args[2].keys}, (path, kind, fields)
                assert schemas[(kind, template)] == fields
                observed.add((kind, template))
            if name in ("Weakening", "_Refused") and node.args:
                if isinstance(node.args[0], ast.Constant):
                    codes.add(node.args[0].value)
            codes.update(arg.value.value for arg in node.keywords if arg.arg == "code"
                         and isinstance(arg.value, ast.Constant) and isinstance(arg.value.value, str))
    assert schemas, "finding producers must carry message templates and data"
    assert codes <= {kind for kind, _ in schemas}, "new finding/refusal kinds need structured rendering: " + str(codes)
    assert registered == set(approval_policy.MESSAGE_TEMPLATES), "every trusted frame needs a production/census use"
    assert observed == set(schemas), "every ownership entry needs its actual producer"
    return schemas


def _owned_message_case(kind, template, values):
    producer = next(producer for name, (producer, owned_kind) in approval_policy.MESSAGE_OWNERS.items()
                    if owned_kind == kind and approval_policy.MESSAGE_TEMPLATES[name] == template)
    message = approval_policy.GuidanceMessage(kind, template, values).render()
    row = approval_policy.MessageRow(code=kind, rule="ordinary", path="src.py", message=message)
    document = {"status": "fail", "approval_mode": "signature", "approval_target": "main"}
    if producer in ("weakenings", "owner_review_required"):
        document[producer] = [row]
    elif producer == "findings":
        row = approval_policy.MessageRow(rule=kind, message=message, level="error")
        document[producer] = [row]
    elif producer == "layer1":
        row = {"tool": "guard", "target": "src.py", "verdict": False, "detail": message, "lines": [1]}
        document[producer] = [row]
    else:
        # Approve/CI refusals render directly; they are not weakening documents.
        document = None
    return producer, row, document


def test_core_finding_producers_never_interpolate_message_data():
    root = Path(__file__).resolve().parents[3]
    producers = {"aegis_core/rule_integrity.py": {"weakenings", "_forbid_findings", "_coverage_lost", "_cap_findings"},
                 "aegis_core/approval_policy.py": {"owner_review_changes"}}
    for path, names in producers.items():
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        bodies = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name in names]
        assert {node.name for node in bodies} == names
        assert not any(isinstance(node, ast.JoinedStr) for body in bodies for node in ast.walk(body)), path


def _regression_prototype():
    """Use the producer schemas, populating every string/optional string field."""
    def data_row(cls, **overrides):
        hints = get_type_hints(cls)
        values = {field.name: "ordinary" for field in fields(cls) if hints[field.name] in (str, Optional[str])}
        return cls(**{**values, **overrides}).as_dict()

    commit = data_row(regression.CommitRegression, commit="a" * 40, status="failed", reason="no_test_changes")
    finding = data_row(regression.RegressionFinding, code="no_test_changes", commit="a" * 40, path="src.py",
                       message=f"fix commit {'a' * 10} (ordinary) modifies source without adding or updating a test")
    return {"tier": "gate", "commits": [commit], "findings": [finding]}


def test_registered_regression_details_match_the_native_producer():
    root = Path(__file__).resolve().parents[3]
    tree = ast.parse((root / "aegis_core/regression.py").read_text(encoding="utf-8"))
    native = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "_DETAILS" for target in node.targets))
    registered = {code: approval_policy.MESSAGE_TEMPLATES["regression_" + code] for code in native}
    assert registered == native
    fragments = {"regression_prefix", "regression_unverified", "regression_rejected", "regression_note"}
    assert {name for name in approval_policy.MESSAGE_TEMPLATES if name.startswith("regression_")} - fragments \
        == {"regression_" + code for code in native}


def _formatter_census():
    """Adapters for AST-discovered families; a new family requires an adapter.

    The payloads describe producer data, not expected escaped strings. All their
    string data fields are discovered below, rather than selecting named bugs.
    """
    owner = {"code": "approval_mode_lowered", "rule": "branch", "path": "config.json", "message": "ordinary"}
    cases = {
        "row['code']": {"owner_review_required": [owner]},
        "w['rule']": {"weakenings": [{**owner, "code": "deleted"}]},
        'f"governance:{entry[\'category\']}"': {"governance": {"enforced": True, "approved": False,
                                                 "paths": [{"category": "workflow", "path": "ci.yml"}]}},
        "rf['code']": {"regression": _regression_prototype()},
        "'performance-regression'": {"perf": {"status": "fail", "reason": "ordinary", "head_min": 0.1, "head_median": 0.1,
                                                "base_min": 0.01, "base_median": 0.01, "rounds": 15, "threshold": 0.05}},
        "'trailer-divergence'": {"trailer_checks": [{"commit": "a" * 40, "failed": True, "reason": "ordinary"}]},
        'f"scanner/{scan[\'name\']}:{sf[\'rule_id\']}"': {"scanners": [{"name": "lint", "status": "fail", "findings": [
            {"rule_id": "guard", "path": "src.py", "line": 1, "message": "ordinary", "snippet": "ordinary"}]}]},
        'f"scanner/{scan[\'name\']}"': {"scanners": [{"name": "lint", "status": "unverified", "reason": "ordinary", "findings": []}]},
        "row['tool']": {"layer1": [{"tool": "guard", "target": "src.py", "verdict": False, "detail": "ordinary", "lines": [1]}]},
        "issue['rule']": {"findings": [{"rule": "guard", "message": "ordinary", "level": "error"}]},
    }
    root = Path(__file__).resolve().parents[3]
    emitted = set()
    for path in SWEPT_OUTPUT_MODULES:
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        emitted.update(ast.dump(node.args[0]) for node in ast.walk(tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Name) and node.func.id == "_finding")
    assert emitted == {ast.dump(ast.parse(expr, mode="eval").body) for expr in cases}, \
        "new formatter finding kinds must have a census adapter"
    return list(cases.values()) + [
        {"perf": {"status": "unverified", "reason": "ordinary"}},
        {"coverage": {"status": "unverified", "reason": "ordinary", "unmeasured": [{"path": "src.py", "reason": "ordinary"}]}},
        {"checkpoint_info": [{"check": "pairing", "message": "ordinary", "file": "src.py"}]},
    ]


def _data_paths(value, path=()):
    """Every string leaf except closed control enums and protocol schema keys."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in {"status", "tier", "approval_mode", "level", "severity", "schema"}:
                yield from _data_paths(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _data_paths(child, path + (index,))
    elif isinstance(value, str):
        yield path


def _human_output(document, fmt):
    if fmt == "github":
        lines = report_formats.github_annotation_lines(document)
        assert all("\r" not in line and "\n" not in line for line in lines)
        assert all(line.startswith(("::error ", "::warning ", "::notice ")) for line in lines)
        return "\n".join(line.split("::", 2)[2] for line in lines)
    if fmt == "sarif":
        run = json.loads(report_formats.format_sarif_report(document))["runs"][0]
        rows = [row["message"]["text"] for row in run["results"]]
        rows += [row["message"]["text"] for invocation in run.get("invocations", ())
                 for row in invocation["toolExecutionNotifications"]]
        return "\n".join(rows)
    if fmt == "summary":
        return report_formats.format_github_step_summary(document)
    if fmt == "json":
        rendered = report_formats.render_ci_json(document)
        return "\n".join(value for path in _data_paths(rendered)
                         if path[0] != "coverage"  # Raw producer JSON, not a human diagnostic field.
                         if path[-1] in ("message", "reason", "subject", "no_test_reason", "detail", "snippet")
                         for value in [_at_path(rendered, path)])
    return "\n".join(row["message"] for row in report_formats.ci_findings(document)
                     + report_formats.layer1_findings(document))


def _at_path(document, path):
    for key in path:
        document = document[key]
    return document


def test_annotation_census_covers_every_emitted_kind():
    """Include advisory-only workflow commands that do not create _finding rows."""
    root = Path(__file__).resolve().parents[3]
    tree = ast.parse((root / "aegis_cli/formatters/report.py").read_text(encoding="utf-8"))
    owner = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "github_annotation_lines")
    assigned = set()

    def literals(node):
        if isinstance(node, ast.Constant):
            assert isinstance(node.value, str)
            return {node.value}
        if isinstance(node, ast.IfExp):
            return literals(node.body) | literals(node.orelse)
        if isinstance(node, ast.Name):
            assert node.id == "title"
            return assigned
        if isinstance(node, ast.Call):
            assert isinstance(node.func, ast.Name) and node.func.id == "guidance_value"
            return literals(node.args[0])
        if isinstance(node, ast.JoinedStr):
            assert isinstance(node.values[0], ast.Constant) and node.values[0].value in ("scanner/", "checkpoint:")
            return set()  # Their data fields are exercised by the formatter-family census.
        assert isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value in ("rule", "tool")
        return set()

    def title_values(node):
        if isinstance(node, ast.IfExp):
            return title_values(node.body) | title_values(node.orelse)
        assert isinstance(node, ast.Tuple)
        return literals(node.elts[1])

    for node in ast.walk(owner):
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Tuple)
                and [part.id for part in target.elts if isinstance(part, ast.Name)] == ["level", "title"] for target in node.targets):
            assigned.update(title_values(node.value))
    required = set().union(*(literals(node.args[1]) for node in ast.walk(owner) if isinstance(node, ast.Call)
                             and isinstance(node.func, ast.Name) and node.func.id == "line"))
    seen = set()
    for prototype in _formatter_census() + [{"coverage": {"status": "reported", "ratio": 1.0, "executable_lines": 1}},
            {"governance": {"categories": ["workflow"], "enforced": False}},
            {"regression": {"tier": "gate", "findings": [{"code": sorted(regression.UNVERIFIED_CODES)[0],
                "commit": "a" * 40, "path": "src.py", "message": "ordinary"}]}}]:
        for mode in (None, "signature", "none", "review"):
            for approved in (False, True):
                document = {"status": "fail", "approval_mode": mode, "approval_target": "main", **deepcopy(prototype)}
                document["approval"] = {"valid": approved}
                if "governance" in document:
                    document["governance"]["approved"] = approved
                for tier in ("gate", "warning"):
                    if "regression" in document:
                        document["regression"]["tier"] = tier
                    seen.update(line.split("title=", 1)[1].split("::", 1)[0]
                                for line in report_formats.github_annotation_lines(document))
    assert required <= seen, "new workflow-command kinds need a census adapter: " + str(required - seen)


@pytest.mark.parametrize("value", [" " * 4000 + "ordinary", "\n" + " " * 4000 + "ordinary", "ordinary" * 1200])
def test_workflow_compatibility_cannot_restore_truncated_or_canonicalized_text(value):
    document = {"weakenings": [{"code": "deleted", "rule": value, "path": "rule.md", "message": value}]}
    (line,) = report_formats.github_annotation_lines(document)
    assert len(line) < 1000
    assert "\r" not in line and "\n" not in line


@pytest.mark.parametrize("attack", EXECUTION_MARKERS, ids=EXECUTION_MARKER_IDS)
def test_formatter_census_covers_every_data_field_in_each_protocol(attack):
    failures = []
    for prototype in _formatter_census():
        base = {"status": "fail", "approval_mode": "signature", "approval_target": "main", **prototype}
        for path in _data_paths(base):
            hostile = deepcopy(base)
            _at_path(hostile, path[:-1])[path[-1]] = attack
            for fmt in ("text", "json", "github", "sarif", "summary"):
                ordinary = _human_output(base, fmt)
                rendered = _human_output(hostile, fmt)
                if attack in rendered or any(line.startswith("::") for line in rendered.splitlines()):
                    failures.append((path, fmt))
                assert ordinary or fmt in ("json", "text"), (prototype, fmt)
    assert not failures, failures


@pytest.mark.parametrize("attack", EXECUTION_MARKERS, ids=EXECUTION_MARKER_IDS)
def test_message_census_covers_every_kind_field_and_format(attack):
    schemas = _message_census()
    for (kind, template), fields in schemas.items():
        ordinary = {field: "ordinary" for field in fields}
        for changed in sorted(fields | {"rule", "path", "code"}):
            values = {**ordinary, **({changed: attack} if changed in fields else {})}
            message = approval_policy.GuidanceMessage(kind, template, values)
            producer, row, document = _owned_message_case(kind, template, values)
            if changed not in fields and changed in row:
                row[changed] = attack
            if document is None:
                assert attack not in approval_policy.finding_message(row, producer=producer)
                continue
            for fmt in ("text", "json", "github", "sarif", "summary"):
                rendered = _human_output(document, fmt)
                assert attack not in rendered, (kind, changed, fmt, rendered)
                assert not any(line.startswith("::") for line in rendered.splitlines()), (kind, changed, fmt)
                if changed in fields:
                    assert message.render() in rendered, (kind, changed, fmt, "template changed or value escaped twice")
            safe = approval_policy.GuidanceMessage(kind, template, ordinary)
            assert safe.render() == template.format_map(ordinary), (kind, template)


@pytest.mark.parametrize("attack", ("ordinary",) + EXECUTION_MARKERS,
                         ids=("ordinary",) + EXECUTION_MARKER_IDS)
def test_serialized_message_census_renders_identically_after_json_round_trip(attack):
    renderers = (report_formats.ci_findings, report_formats.github_annotation_lines,
                 report_formats.format_github_step_summary, report_formats.format_sarif_report,
                 report_formats.render_ci_json)
    for (kind, template), fields in _message_census().items():
        for field in sorted(fields) or [None]:
            values = {key: attack if key == field else "ordinary" for key in fields}
            producer, row, document = _owned_message_case(kind, template, values)
            if document is None:
                assert approval_policy.finding_message(json.loads(json.dumps(row)), producer=producer) == row["message"]
                continue
            wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
            for render in renderers:
                assert render(wire) == render(document), (kind, field, render.__name__)


@pytest.mark.parametrize("attack", EXECUTION_MARKERS, ids=EXECUTION_MARKER_IDS)
def test_decoded_frames_never_trust_raw_execution_characters_in_value_slots(attack):
    for (kind, template), fields in _message_census().items():
        if not fields:
            continue
        row = {"code": kind, "rule": "ordinary", "path": "ordinary",
               "message": template.format_map({field: attack for field in fields})}
        shown = approval_policy.finding_message(row)
        assert attack not in shown


@pytest.mark.parametrize("attack", ("ordinary",) + EXECUTION_MARKERS,
                         ids=("ordinary",) + EXECUTION_MARKER_IDS)
def test_formatter_family_census_has_identical_human_output_after_json_round_trip(attack):
    prototypes = _formatter_census()
    subject, note = "fix: " + attack, "checked '" + attack + "'"
    prototypes.append({"regression": {"tier": "gate", "commits": [
        {"commit": "a" * 40, "subject": subject, "no_test_reason": note}], "findings": [
        {"code": "no_test_changes", "commit": "a" * 40, "path": "src.py", "message":
            f"fix commit {'a' * 10} ({subject}) modifies source without adding or updating a test"
            f" (Aegis-No-Test: {note!r} is an explanation only; exemption requires human_gate approval)"}]}})
    for prototype in prototypes:
        for path in list(_data_paths(prototype)) or [None]:
            document = {"status": "fail", "approval_mode": "signature", "approval_target": "main", **deepcopy(prototype)}
            if path is not None:
                _at_path(document, path[:-1])[path[-1]] = attack
            wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
            for fmt in ("text", "json", "github", "sarif", "summary"):
                assert _human_output(wire, fmt) == _human_output(document, fmt), (path, fmt)


def test_static_strict_diagnostic_template_survives_rendering_and_json():
    from aegis_core.verification import ToolEvidence
    from aegis_core.verification.ast_checks import NO_DRIVER_NOTE_TOOL

    evidence = ToolEvidence(NO_DRIVER_NOTE_TOOL, "src/app.kt", True, "no_driver:.kt", language="unknown")
    document = report_formats.layer1_report_document(False, [("src/app.kt", evidence)], [], True)
    original = document["findings"][0]["message"]
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    for render in (report_formats.github_annotation_lines, report_formats.format_github_step_summary,
                   report_formats.format_sarif_report):
        assert original in str(render(document))
        assert render(wire) == render(document)


@pytest.mark.parametrize("frame", sorted(approval_policy.MESSAGE_OWNERS))
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif", "summary"])
def test_untrusted_producers_cannot_impersonate_registered_frames(frame, fmt):
    template = approval_policy.MESSAGE_TEMPLATES[frame]
    # The security addendum's exact fish-command vector, across every format.
    data = "touch marker" if frame == "uncommitted" else "ordinary"
    value = template.format_map({field: data for _, field, _, _ in Formatter().parse(template) if field})
    document = {"status": "fail", "approval_mode": "signature", "approval_target": "main",
        "scanners": [{"name": "lint", "status": "unverified", "reason": value, "findings": [
            {"rule_id": approval_policy.MESSAGE_OWNERS[frame][1] or "external", "code": approval_policy.MESSAGE_OWNERS[frame][1],
             "path": "src.py", "line": 1, "message": value, "snippet": value}]}],
        "weakenings": [{"code": "external", "rule": "guard", "path": "src.py", "message": value}],
        "findings": [{"rule": "checkpoint:external", "code": approval_policy.MESSAGE_OWNERS[frame][1],
                      "message": value, "level": "error"}],
        "checkpoint_info": [{"check": "external", "file": "src.py", "message": value}],
        "trailer_checks": [{"failed": True, "commit": "a" * 40, "reason": value}]}
    expected = approval_policy.guidance_value(value, prose=True)
    rendered = _human_output(document, fmt)
    assert expected in rendered
    if any(char in value for char in "$`\\;&|<>!()'\""):
        assert value not in rendered
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    assert _human_output(wire, fmt) == rendered


@pytest.mark.parametrize("frame", sorted(approval_policy.MESSAGE_OWNERS))
def test_frame_reconstruction_requires_both_the_owner_and_finding_kind(frame):
    owner, kind = approval_policy.MESSAGE_OWNERS[frame]
    template = approval_policy.MESSAGE_TEMPLATES[frame]
    values = {field: "ordinary" for _, field, _, _ in Formatter().parse(template) if field}
    value = approval_policy.GuidanceMessage(kind or "external", template, values).render()
    row = approval_policy.MessageRow(code=kind, rule=kind, message=value)
    assert approval_policy.finding_message(row, producer=owner) == value
    assert approval_policy.finding_message(json.loads(json.dumps(row)), producer=owner) == value
    escaped = approval_policy.guidance_value(value, prose=True)
    for producer in {pair[0] for pair in approval_policy.MESSAGE_OWNERS.values()} | {None, "scanner"}:
        if producer != owner:
            assert approval_policy.finding_message(row, producer=producer) == escaped
    assert approval_policy.finding_message({**row, "code": "external", "rule": "external"}, producer=owner) == escaped


# Ordered like the shared text table: adding/reordering a row requires a probe.
# Secrets are source regions, not fragments guessed from the mask's spelling.
REDACTION_FAMILY_PROBES = (
    ("pem", "-----BEGIN PRIVATE KEY----- material -----END PRIVATE KEY-----", "material", "[REDACTED_PEM]"),
    ("url", "https://user:actual_password@example.test/path", "actual_password", "[REDACTED]"),
    ("jwt", "eyJ" + "a" * 16 + "." + "b" * 12 + "." + "c" * 12, "eyJ" + "a" * 16, "[REDACTED_JWT]"),
    ("aws-access", "AKIA" + "A" * 16, "AKIA" + "A" * 16, "[REDACTED_AWS]"),
    ("aws-session", "ASIA" + "A" * 16, "ASIA" + "A" * 16, "[REDACTED_AWS]"),
    ("aws-id", "AGPA" + "A" * 16, "AGPA" + "A" * 16, "[REDACTED_AWS]"),
    ("github", "ghp_" + "a" * 36, "ghp_" + "a" * 36, "[REDACTED_VCS_TOKEN]"),
    ("github-oauth", "gho_" + "b" * 36, "gho_" + "b" * 36, "[REDACTED_VCS_TOKEN]"),
    ("github-pat", "github_pat_" + "c" * 30, "github_pat_" + "c" * 30, "[REDACTED_VCS_TOKEN]"),
    ("gitlab", "glpat-" + "d" * 30, "glpat-" + "d" * 30, "[REDACTED_VCS_TOKEN]"),
    ("service-key", "sk_live_" + "e" * 24, "sk_live_" + "e" * 24, "[REDACTED_API_KEY]"),
    ("openai", "sk-" + "f" * 30, "sk-" + "f" * 30, "[REDACTED_API_KEY]"),
    ("google", "AIza" + "g" * 30, "AIza" + "g" * 30, "[REDACTED_TOKEN]"),
    ("slack", "xoxb-" + "h" * 24, "xoxb-" + "h" * 24, "[REDACTED_TOKEN]"),
    ("bearer", "Bearer " + "a1" * 20, "a1" * 20, "Bearer [REDACTED]"),
    ("keyed", "token=secret12345", "secret12345", "[REDACTED]"),
    ("password-is", "password is hunter2", "hunter2", "[REDACTED]"),
    ("email", "person@example.test", "person@example.test", "[REDACTED_EMAIL]"),
    ("home", "/home/alice/file", "alice", "~user"),
    ("ip", "1.2.3.4", "1.2.3.4", "[REDACTED_IP]"),
    ("entropy", "aB1cD2eF3gH4iJ5kL6mN7oP8", "aB1cD2eF3gH4iJ5kL6mN7oP8", "[REDACTED_HIENT]"),
)

REDACTION_BOUNDARIES = {
    "ip": ("1.2.3.4x", 8),
    "token": ("ghp_" + "a" * 36, len("[REDACTED_VCS_TOKEN]")),
    "email": ("person@example.test1", len("person@example.test")),
    "url": ("https://user:password@example.invalid", len("https://user:[REDACTED]")),
}
REDACTION_BOUNDARIES.update({name: (value, len(mask)) for name, value, _secret, mask in REDACTION_FAMILY_PROBES
                             if name not in REDACTION_BOUNDARIES})
REDACTION_BOUNDARIES.update({f"home-{index}-{size}": (prefix + "a" * size + suffix, len(prefix) + len("~user"))
    for index, (prefix, suffix) in enumerate((("/home/", "/file"), ("/Users/", "/file"), ("C:\\Users\\", "\\file")))
    for size in (1, 255)})


def test_redaction_family_census_requires_a_boundary_probe_for_every_row():
    from aegis_core import redaction

    # Introspection is test-only: product code consumes the public shared rules.
    rows = redaction._TEXT_REDACTIONS
    assert len(rows) + 1 == len(REDACTION_FAMILY_PROBES)
    for (pattern, replacement), (name, value, secret, mask) in zip(rows, REDACTION_FAMILY_PROBES):
        match = pattern.search(value)
        assert match is not None and secret in match.group(0), name
        assert mask in match.expand(replacement), name
        assert name in REDACTION_BOUNDARIES
    entropy = REDACTION_FAMILY_PROBES[-1]
    assert entropy[0] == "entropy" and redaction.CANDIDATE_TOKEN_RE.fullmatch(entropy[1])
    assert redaction.is_high_entropy_secret(entropy[1])


def _existing_mask_probes():
    from aegis_core.redaction import SECRET_REPLACEMENTS

    masks = {mask.split()[-1] for _name, _value, _secret, mask in REDACTION_FAMILY_PROBES}
    for _pattern, replacement in SECRET_REPLACEMENTS:
        if replacement.startswith(r"\1"):
            replacement = replacement[2:]
            if replacement.endswith("@"):
                replacement = replacement[:-1]
        masks.add(replacement.split()[-1])
    return sorted(masks)


def _mask_spellings(mask):
    yield mask
    for spelling, width in (("x", 2), ("u", 4), ("U", 8)):
        yield "".join("\\" + spelling + format(ord(char), f"0{width}x") for char in mask)
    yield "".join(char if index % 4 == 0 else "\\" + ("x", "u", "U")[index % 3] +
                  format(ord(char), ("02x", "04x", "08x")[index % 3]) for index, char in enumerate(mask))
    yield approval_policy.guidance_value(mask)  # The renderer's actual strict spelling.


def _assert_existing_mask_complete(family, value):
    if family.startswith("existing-mask:"):
        mask = family.removeprefix("existing-mask:")
        logical = "".join(chr(int(unit[2:], 16)) if escaped else unit
                          for unit, escaped in redaction._escape_units(value))
        assert mask in logical or not logical.strip("a "), (family, value)
    if family.startswith("mask-whitespace:"):
        assert "  " not in value and "diagnostic_omitted" not in value and "diagnostic omitted" not in value


def test_public_mask_grammar_covers_the_shared_replacement_families():
    from aegis_core.redaction import REDACTION_MASK_RE

    masks = _existing_mask_probes()
    for mask in masks:
        assert REDACTION_MASK_RE.fullmatch(mask), mask
    joined = "!".join(masks)
    assert [match.group(0) for match in REDACTION_MASK_RE.finditer(joined)] == masks


def _display_property_cases():
    """A deterministic covering schedule, rather than an unbounded Cartesian product."""
    from aegis_core import redaction

    for index, (name, value, secret, mask) in enumerate(REDACTION_FAMILY_PROBES):
        yield name, value, secret, None
        pattern, replacement = (redaction._TEXT_REDACTIONS[index] if index < len(redaction._TEXT_REDACTIONS)
                                else (redaction.CANDIDATE_TOKEN_RE, "[REDACTED_HIENT]"))
        match = pattern.search(value)
        start, end = match.span()
        if replacement.startswith(r"\1"):
            start = match.end(1)
            if replacement.endswith("@"):
                end -= 1
        for edge in (start, end - 1):
            for spelling, width in (("x", 2), ("u", 4), ("U", 8)):
                encoded = "\\" + spelling + format(ord(value[edge]), f"0{width}x")
                yield name, value[:edge] + encoded + value[edge + 1:], secret, encoded
        # Every point from limit - len(mask) - 2 through limit + 2.
        for cut in range(40 - len(mask) - 2, 43):
            yield name, "a" * cut + " " + value, secret, None
    for name, (value, boundary) in REDACTION_BOUNDARIES.items():
        if name.startswith("home-"):
            for cut in range(40 - boundary - 2, 43):
                yield name, "a" * cut + " " + value, "a" * (255 if name.endswith("255") else 1), None
    # Coincident mask/source edges wherever the family's grammar permits them.
    for prefix, suffix in (("token=", ""), ("password is ", ""), ("https://user:", "@host"),
                           ("/home/", "/file"), ("/Users/", "/file"), ("C:\\Users\\", "\\file")):
        for char in "[]~user@":
            if prefix == "https://user:" and char == "@":
                continue  # URL userinfo excludes its structural @ delimiter.
            for first in (False, True):
                secret = char + "secret12345" if first else "secret12345" + char
                for spelling, width in (("x", 2), ("u", 4), ("U", 8)):
                    encoded = "\\" + spelling + format(ord(char), f"0{width}x")
                    value = prefix + (encoded + secret[1:] if first else secret[:-1] + encoded) + suffix
                    yield "coincident-edges", value, secret, encoded
    controls = [chr(point) for point in (*range(32), *range(127, 160), 0x202e, 0xe0001)]
    for value in ["", "\r\n", "\x00\x07\x1b[31m", "\u202e\U000e0001",
                  "token=secret\\x5d", "token=\\x5bsecret", "/home/pet\\x72/file", *controls]:
        yield "controls-and-edges", value, None, None
    for template in approval_policy.MESSAGE_TEMPLATES.values():
        literals = "".join(literal for literal, _, _, _ in Formatter().parse(template))
        yield "frame-literals", literals, None, None
    yield "existing-mask:[REDACTED]", "a" * 390 + " [REDACTED]", None, None
    for prefix in ("Authorization:", "auth:", "token:", "secret:", "password:", "api_key:", "credential:",
                   "token is", "password is", "secret is"):
        for limit in (120, 400):
            for delta in range(-6, 4):
                padding = limit - 30 + delta
                yield f"mask-whitespace:{limit}", "x" * padding + " " + prefix + " Bearer " + "a1" * 10, None, None
    for value in ("to ::none", "to a commit in ::" + "b" * 200, "a:::b", "a::::b"):
        yield "colon-boundaries", value, None, None
    for limit in (0, 8, 30):
        for value in ("a" * 8193, "a" * 81921, r"\x61" * 8193):
            yield f"oversized-receipt:{limit}", value, None, None
    for mask in _existing_mask_probes():
        for spelling in dict.fromkeys(_mask_spellings(mask)):
            for cut in range(400 - len(mask) - 2, 403):
                yield "existing-mask:" + mask, "a" * cut + " " + spelling + " tail", None, None
    fragments = (r"\x3", r"\u003", r"\U0000003", r"\\x3", r"\\u003", r"\\U0000003",
                 r"\x41", r"\u0041", r"\U00000041", r"\\", r"\q")
    for mask in _existing_mask_probes():
        for fragment in fragments:
            width = sum(1 for _unit in redaction._escape_units(fragment))
            for edge in range(-1, width + 2):
                padding = 40 - len(mask) - len(" token") - edge
                yield "escape-splice:40", "a" * padding + " token" + fragment + ".." + mask, None, None
    for fragment in fragments[:6]:
        width = sum(1 for _unit in redaction._escape_units(fragment))
        for edge in range(-1, width + 2):
            padding = 400 - len("AKIA_REDACTED") - len(" token") - edge
            yield "escape-splice:400", "a" * padding + " token" + fragment + "..AKIA_REDACTED", None, None
    yield "escape-splice:120", "a" * 98 + r" token\x3..AKIA_REDACTED", None, None
    yield "escape-splice:21", r"token\x3..AKIA_REDACTED", None, None


@pytest.mark.parametrize("shard", range(3))
def test_generated_display_safety_across_redactions_frames_receipts_and_formats(shard):
    import re
    import unicodedata
    from tests.unit.core.test_approval_policy import _within_redaction_budget

    cases = list(_display_property_cases())
    frames = list(approval_policy.MESSAGE_TEMPLATES.items())
    visited = set()
    for index, (family, value, secret, encoded) in enumerate(cases):
        if index % 3 != shard:
            continue
        limit = (int(family.rsplit(":", 1)[1]) if family.startswith(("mask-whitespace:", "oversized-receipt:", "escape-splice:")) else
                 400 if family.startswith("existing-mask:") else 40)
        for prose in (False, True):
            shown = _within_redaction_budget(lambda: approval_policy.guidance_value(value, limit, prose=prose),
                                             len(value) + limit, call_steps=True)
            assert approval_policy.guidance_value(shown, limit, prose=prose) == shown, (family, index, prose)
            _assert_existing_mask_complete(family, shown)
            assert not any(ord(char) < 32 or 127 <= ord(char) <= 159 or unicodedata.category(char) == "Cf"
                           or char in "$`;&|<>!()'\"" for char in shown)
            if secret and len(secret) > 1:
                assert secret not in shown, (family, index)
            if prose and encoded:
                assert encoded not in shown, (family, index)
        for identifier in (False, True):
            receipt = _within_redaction_budget(lambda: approval_policy.receipt_value(value, limit, identifier=identifier),
                                               len(value) + limit, call_steps=True)
            assert approval_policy.receipt_value(receipt, limit, identifier=identifier) == receipt, (family, index, identifier)
            _assert_existing_mask_complete(family, receipt)
            assert not any(ord(char) < 32 or unicodedata.category(char) == "Cf" for char in receipt)
            if not identifier and encoded:
                assert encoded not in receipt, (family, index)
        # Strict guidance uses hex for brackets. Decode inert spellings for the
        # mask assertion only; no decoded text is ever handed to a shell.
        shadow = re.sub(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))",
                        lambda match: chr(int(next(group for group in match.groups() if group), 16)), shown)
        assert shadow.count("[") == shadow.count("]"), (family, index)
        assert not any(shadow.endswith(part) for part in ("~", "~u", "~us", "~use")), (family, index)
        name, template = frames[index % len(frames)]
        visited.add(name)
        owner, kind = approval_policy.MESSAGE_OWNERS[name]
        values = {field: value for _, field, _, _ in Formatter().parse(template) if field}
        message = approval_policy.GuidanceMessage(kind, template, values).render()
        row = {"code": kind, "rule": kind, "message": message}
        assert approval_policy.finding_message(row, producer=owner) == message, (family, name)
        assert approval_policy.finding_message(json.loads(json.dumps(row)), producer=owner) == message
        document = {"approval_mode": "signature", "scanners": [{"name": "lint", "status": "fail", "findings": [
            {"rule_id": "guard", "path": "src.py", "line": 1, "message": value, "snippet": value}]}]}
        wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
        assert report_formats.render_ci_json(wire) == report_formats.render_ci_json(document)
        expected = approval_policy.guidance_value(value, prose=True)
        _assert_existing_mask_complete(family, expected)
        for ellipsis in (False, True):
            prefix = "fixed (value); "
            finished = _within_redaction_budget(
                lambda: approval_policy.clip_rendered_text(prefix + expected, limit, ellipsis=ellipsis),
                len(prefix) + len(expected) + limit, call_steps=True)
            assert len(finished) <= limit
            assert approval_policy.clip_rendered_text(finished, limit, ellipsis=ellipsis) == finished
            assert not any(unit == "\\" and not escaped for unit, escaped in redaction._escape_units(finished))
            if limit >= len(prefix) + (3 if ellipsis else 0):
                assert finished.startswith(prefix)
                field = finished[len(prefix):]
                assert approval_policy.guidance_value(field, 8192, prose=True) == field.rstrip()
        for fmt in ("text", "json", "github", "sarif", "summary"):
            output = _human_output(document, fmt)
            assert output == _human_output(wire, fmt), (family, index, fmt)
            if family.startswith("existing-mask:"):
                assert expected in output, (family, index, fmt)
        if kind is not None:
            _, _, owned = _owned_message_case(kind, template, values)
            if owned is not None:
                wire = json.loads(json.dumps(report_formats.render_ci_json(owned)))
                for fmt in ("text", "json", "github", "sarif", "summary"):
                    assert _human_output(owned, fmt) == _human_output(wire, fmt), (family, name, fmt)
    assert visited == set(approval_policy.MESSAGE_TEMPLATES)


@pytest.mark.parametrize("family", sorted(REDACTION_BOUNDARIES))
@pytest.mark.parametrize("delta", range(-2, 3))
def test_redaction_boundaries_are_stable_through_public_formats_and_json(family, delta):
    probe, boundary = REDACTION_BOUNDARIES[family]
    value = "a" * (400 - boundary - 1 + delta) + " " + probe
    document = {"status": "fail", "approval_mode": "signature", "approval_target": "main",
        "scanners": [{"name": "lint", "status": "fail", "findings": [
            {"rule_id": "guard", "path": "src.py", "line": 1, "message": value, "snippet": value}]}],
        "perf": {"status": "unverified", "reason": value},
        "regression": {"tier": "gate", "commits": [{"commit": "a" * 40, "subject": value, "no_test_reason": value}],
            "findings": [{"code": "no_test_changes", "commit": "a" * 40, "path": "src.py", "message":
                f"fix commit {'a' * 10} ({value}) modifies source without adding or updating a test"
                f" (Aegis-No-Test: {value!r} is an explanation only; exemption requires human_gate approval)"}]},
        "weakenings": [ci_integrity.Weakening("coverage", "guard", "src.py", approval_policy.GuidanceMessage(
            "coverage", approval_policy.MESSAGE_TEMPLATES["coverage"], {"path": value})).as_dict()]}
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    twice = json.loads(json.dumps(report_formats.render_ci_json(wire)))
    assert wire == twice
    for fmt in ("text", "json", "github", "sarif", "summary"):
        assert _human_output(document, fmt) == _human_output(wire, fmt), (family, delta, fmt)


@pytest.mark.parametrize("commit", ["$(gm1b)aaa", "a" * 40], ids=["command-commit", "valid-commit"])
def test_regression_messages_are_built_only_from_structured_data(commit):
    prototype = _regression_prototype()
    prototype["commits"][0].update(commit=commit, subject="s", exemption_code="reason", no_test_reason="checked 's'")
    prototype["findings"][0].update(commit=commit, message=f"fix commit {commit[:10]} (s): ;gm1b")
    hostile = {"approval_mode": "signature", "regression": prototype}
    ordinary = deepcopy(hostile)
    ordinary["regression"]["findings"][0]["message"] = "arbitrary stale text"
    wire = json.loads(json.dumps(report_formats.render_ci_json(hostile)))
    for fmt in ("text", "json", "github", "sarif", "summary"):
        shown = _human_output(hostile, fmt)
        assert "$(gm1b)" not in shown and ";gm1b" not in shown
        assert shown == _human_output(ordinary, fmt)
        assert shown == _human_output(wire, fmt)


@pytest.mark.parametrize("value", ["line1\nline2", "a%b\rc\nd:e,f", "line1\n::warning::forged"])
def test_plain_weakening_newlines_share_normalization_with_json(value):
    document = {"approval_mode": "signature", "weakenings": [
        {"code": "deleted", "rule": "guard", "path": "src.py", "message": value}]}
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    assert report_formats.render_ci_json(wire) == report_formats.render_ci_json(document)
    for fmt in ("text", "json", "github", "sarif", "summary"):
        assert _human_output(wire, fmt) == _human_output(document, fmt)
        assert not any(line.startswith("::") for line in _human_output(wire, fmt).splitlines())


@pytest.mark.parametrize("control", [chr(point) for point in (*range(32), *range(127, 160), 0x202e, 0xe0001)]
                         + ["\r\n", "\x1b[31m"])
@pytest.mark.parametrize("field", ["code", "rule", "message"])
def test_weakening_human_values_never_restore_controls(control, field):
    row = {"code": "deleted", "rule": "guard", "path": "src.py", "message": "ordinary"}
    row[field] = "left" + control + "right"
    document = {"approval_mode": "signature", "weakenings": [row]}
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    expected = approval_policy.guidance_value(row[field], prose=True)
    assert expected in _human_output(document, "github")
    assert all(ord(char) >= 32 for char in wire["weakenings"][0]["message"])
    for fmt in ("text", "json", "github", "sarif", "summary"):
        assert _human_output(document, fmt) == _human_output(wire, fmt)
    assert len(report_formats.github_annotation_lines(document)) == 1


@pytest.mark.parametrize("note", ["\x1b[31m", " \t\n ", "\x00\x07\r"])
def test_regression_optional_fragments_depend_on_rendered_values(note):
    codes = set(regression.UNVERIFIED_CODES) | {"timeout", "no_test_changes", "no_tests_collected",
                                               "failed_on_head", "passed_on_base"}
    for code in sorted(codes):
        prototype = _regression_prototype()
        prototype["commits"][0].update(exemption_code=note, no_test_reason=note)
        prototype["findings"][0]["code"] = code
        document = {"approval_mode": "signature", "regression": prototype}
        wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
        message = wire["regression"]["findings"][0]["message"]
        assert "Aegis-No-Test:" not in message and "exemption was rejected" not in message
        for fmt in ("text", "json", "github", "sarif", "summary"):
            assert _human_output(document, fmt) == _human_output(wire, fmt), (code, fmt)


def test_owned_multifield_frames_choose_canonical_capture_partitions():
    for name, template in approval_policy.MESSAGE_TEMPLATES.items():
        names = [field for _, field, _, _ in Formatter().parse(template) if field]
        if len(names) < 2:
            continue
        producer, kind = approval_policy.MESSAGE_OWNERS[name]
        for empty in names:
            for value in ("to review", "to ::none", "to a commit in ::root", "to a commit in x", "a" * 400, " in : ; to "):
                values = {field: "" if field == empty else value for field in names}
                message = approval_policy.GuidanceMessage(kind, template, values).render()
                row = {"code": kind, "rule": kind, "message": message}
                assert approval_policy.finding_message(row, producer=producer) == message, (name, values)
                assert approval_policy.finding_message(json.loads(json.dumps(row)), producer=producer) == message
                if kind is not None:
                    _, _, document = _owned_message_case(kind, template, values)
                    if document is not None:
                        wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
                        for fmt in ("text", "json", "github", "sarif", "summary"):
                            assert _human_output(document, fmt) == _human_output(wire, fmt), (name, fmt)


@pytest.mark.parametrize("field", ["subject", "no_test_reason", "exemption_code"])
def test_authorization_mask_whitespace_survives_every_frame_and_json(field):
    value = "x" * 370 + " Authorization: Bearer " + "a1" * 10
    prototype = _regression_prototype()
    prototype["commits"][0][field] = value
    document = {"approval_mode": "signature", "regression": prototype}
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    assert report_formats.render_ci_json(wire) == report_formats.render_ci_json(document)
    for fmt in ("text", "json", "github", "sarif", "summary"):
        assert _human_output(document, fmt) == _human_output(wire, fmt)
    for name, template in approval_policy.MESSAGE_TEMPLATES.items():
        owner, kind = approval_policy.MESSAGE_OWNERS[name]
        message = approval_policy.GuidanceMessage(kind, template,
            {key: value for _, key, _, _ in Formatter().parse(template) if key}).render()
        row = {"code": kind, "rule": kind, "message": message}
        assert approval_policy.finding_message(row, producer=owner) == message, name


@pytest.mark.parametrize("name,values,separator", [
    ("approval_mode_lowered", {"prior": "review", "candidate": "to ::none"}, " to "),
    ("unresolved", {"commit": "a" * 300, "root": "to a commit in ::" + "b" * 200}, " to a commit in "),
])
def test_owned_frame_values_cannot_impersonate_their_separator(name, values, separator):
    owner, kind = approval_policy.MESSAGE_OWNERS[name]
    message = approval_policy.GuidanceMessage(kind, approval_policy.MESSAGE_TEMPLATES[name], values).render()
    assert message.count(separator) == 1 and "::" not in message
    row = {"code": kind, "rule": kind, "message": message}
    assert approval_policy.finding_message(row, producer=owner) == message
    assert approval_policy.finding_message(json.loads(json.dumps(row)), producer=owner) == message
    if name == "unresolved":
        assert len(message) > 400
    else:
        assert "; owner review required" in message


@pytest.mark.parametrize("name", sorted(approval_policy.MESSAGE_TEMPLATES))
def test_list_fields_of_owned_frames_have_one_bounded_capture(name):
    template = approval_policy.MESSAGE_TEMPLATES[name]
    owner, kind = approval_policy.MESSAGE_OWNERS[name]
    names = [field for _, field, _, _ in Formatter().parse(template) if field]
    for items in (["a" * 250, "b" * 250], [], ["token=secret12345"] * 50, ["a" * 81921]):
        values = {field: items for field in names}
        message = approval_policy.GuidanceMessage(kind, template, values).render()
        row = {"code": kind, "rule": kind, "message": message}
        assert "secret12345" not in message
        assert approval_policy.finding_message(row, producer=owner) == message, (name, len(message))
        assert approval_policy.finding_message(json.loads(json.dumps(row)), producer=owner) == message
        if kind is not None:
            _, _, document = _owned_message_case(kind, template, values)
            if document is not None:
                wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
                for fmt in ("text", "json", "github", "sarif", "summary"):
                    assert _human_output(document, fmt) == _human_output(wire, fmt)


def test_expanded_regression_fields_survive_json_without_reinterpreting_the_message():
    prototype = _regression_prototype()
    value = "\U000e0001" * 1026
    prototype["commits"][0].update(subject=value, exemption_code=value, no_test_reason=value)
    prototype["findings"][0]["message"] = f"fix commit {'a' * 10} ({value}): {value}"
    document = {"approval_mode": "signature", "regression": prototype}
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    assert report_formats.render_ci_json(wire) == report_formats.render_ci_json(document)
    for fmt in ("text", "json", "github", "sarif", "summary"):
        assert _human_output(wire, fmt) == _human_output(document, fmt)


@needs_git
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
@pytest.mark.parametrize("attack", EXECUTION_MARKERS, ids=EXECUTION_MARKER_IDS)
def test_mandatory_cap_uses_structured_filename_in_all_outputs(tmp_path, capsys, monkeypatch, fmt, attack):
    if os.name == "nt" and any(char in attack for char in '<>:"|?*\r\n'):
        pytest.skip("the Windows filesystem cannot store this Git path")
    summary = tmp_path / "summary.md"
    monkeypatch.setattr(core_config, "env_github_step_summary", lambda: str(summary))
    repo = make_repo(tmp_path)
    mandatory = "---\ntype: invariant\nenforcement: gate\nhypothesis: Keep it so\ntarget_paths: ['src/trap-*']\n---\n# Mandatory\n"
    for name in ("a", "b"):
        repo.write(".aegis/rules/invariants/" + name + ".md", mandatory)
    base = repo.commit("two mandatory rules")
    repo.branch("work")
    repo.write("src/trap-" + attack + ".py", "x = 1\n")
    repo.write(".aegis/rules/invariants/c.md", mandatory)
    repo.commit("crowd the mandatory slots")
    rc, out, err = run_ci(repo, capsys, "--base", base, "--no-exec", "--format", fmt)
    assert rc == 1 and "mandatory_cap" in summary.read_text(encoding="utf-8")
    if fmt == "json":
        out = "\n".join(row["message"] for row in json.loads(out)["weakenings"])
    elif fmt == "github":
        out = "\n".join(line.split("::", 2)[2] if line.startswith("::") else line for line in out.splitlines())
    elif fmt == "sarif":
        run = json.loads(out)["runs"][0]
        out = "\n".join(row["message"]["text"] for row in run.get("results", ()))
    assert attack not in out + err + summary.read_text(encoding="utf-8")
    assert "::warning::forged" not in out.splitlines()


@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
@pytest.mark.parametrize("attack", EXECUTION_MARKERS, ids=EXECUTION_MARKER_IDS)
def test_scanner_and_performance_human_fields_are_rendered_in_json_too(capsys, fmt, attack):
    from aegis_core.verification.scanners import Finding

    report = ci_integrity.CiReport("a" * 40, "b" * 40, "a" * 40, 0, (), None)
    scan = {"name": "lint", "status": "unverified", "reason": attack,
            "findings": [Finding("r", "p.py", 1, attack, message=attack)], "subtracted": 0,
            "suppressions": {"count": 0, "delta": 0}}
    check_cli._print_ci(report, fmt, ".", perf_report={"status": "unverified", "reason": attack}, scanner_results=[scan])
    out = capsys.readouterr().out
    if fmt == "json":
        document = json.loads(out)
        out = document["perf"]["reason"] + document["scanners"][0]["reason"] + document["scanners"][0]["findings"][0]["message"]
    assert attack not in out


def _assert_finished_line_is_atomic(line, limit=400):
    assert len(line) <= limit
    assert not any(unit == "\\" and not escaped for unit, escaped in redaction._escape_units(line))
    assert approval_policy.clip_rendered_text(line, limit) == line


@needs_git
def test_head_resolution_error_keeps_escaped_values_whole(tmp_path, capsys):
    repo = make_repo(tmp_path)
    rc, _out, err = run_ci(repo, capsys, "--base", repo.head(), "--head", "bb" + "&" * 100, "--no-exec")
    assert rc == 1 and err.startswith("Error: cannot resolve the head '")
    line = err.rstrip("\n")
    assert "&" not in line
    _assert_finished_line_is_atomic(line)


def test_unverified_perf_line_keeps_escaped_values_whole(capsys):
    report = ci_integrity.CiReport("a" * 40, "b" * 40, "a" * 40, 0, (), None)
    check_cli._print_ci(report, "text", ".", perf_report={"status": "unverified", "reason": "&" * 100})
    line = next(line for line in capsys.readouterr().out.splitlines() if "[UNVERIFIED:perf]" in line)
    assert "&" not in line and line.startswith("  [UNVERIFIED:perf] ")
    _assert_finished_line_is_atomic(line)


@needs_git
@pytest.mark.parametrize("fmt", ["json", "text", "github"])
@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, TypeError])
def test_internal_perf_failure_keeps_fixed_punctuation(tmp_path, capsys, monkeypatch, fmt, error_type):
    repo = make_repo(tmp_path)
    base = repo.head()
    repo.write("src/app.py", "x = 2\n")
    repo.commit("ordinary change")

    def boom(*args, **kwargs):
        raise error_type("/secret/path/inside")

    monkeypatch.setattr(perf_check, "run_perf_check", boom)
    rc, out, err = run_ci(repo, capsys, "--base", base, "--perf", "--format", fmt)
    expected = f"perf check could not run ({error_type.__name__})"
    assert rc == 0 and "/secret/path" not in out + err
    if fmt == "json":
        assert json.loads(out)["perf"]["reason"] == expected
    else:
        assert expected in out


@pytest.mark.parametrize("error_name", ["RuntimeError", "ValueError", "TypeError"])
def test_internal_perf_failure_is_stable_in_documents_and_protocols(error_name):
    reason = f"perf check could not run ({error_name})"
    document = {"perf": {"status": "unverified", "reason": reason}}
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    assert wire["perf"]["reason"] == reason
    assert report_formats.render_ci_json(wire) == wire
    assert report_formats.perf_line(wire["perf"]).endswith(reason)
    for fmt in ("text", "json", "github", "sarif", "summary"):
        assert _human_output(wire, fmt) == _human_output(document, fmt)
    assert reason in _human_output(document, "github")


@pytest.mark.parametrize("reason", [
    "perf check could not run (id)",
    "perf check could not run (RuntimeError) extra",
    "perf check could not run (RuntimeError)\n",
    "perf check could not run (RuntimeError)\n::warning::forged",
    "perf check could not run (RuntimeError",
    "perf check could not run (\x1b[31mRuntimeError)",
    "perf check could not run (token=secret12345)",
    "perf check could not run (RuntimeError) [REDACTED_IP]",
    r"perf check could not run \x28RuntimeError\x29",
    "&" * 100,
    "x" * 81921,
], ids=["fake-type", "suffix", "newline", "workflow", "missing-close", "ansi", "secret", "mask",
        "escaped", "ampersands", "oversized"])
def test_free_perf_reasons_keep_the_full_display_pipeline(reason):
    expected = approval_policy.guidance_value(reason, prose=True)
    document = {"perf": {"status": "unverified", "reason": reason}}
    wire = json.loads(json.dumps(report_formats.render_ci_json(document)))
    assert wire["perf"]["reason"] == expected
    assert report_formats.render_ci_json(wire) == wire
    assert report_formats.perf_line(document["perf"]).endswith(expected)
    assert expected in _human_output(document, "github")
    for fmt in ("text", "json", "github", "sarif", "summary"):
        assert _human_output(wire, fmt) == _human_output(document, fmt)


def test_fixed_perf_vocabulary_does_not_exempt_other_fields():
    reason = "perf check could not run (RuntimeError)"
    escaped = approval_policy.guidance_value(reason, prose=True)
    document = {"perf": {"status": "unverified", "reason": reason}, "reason": reason,
                "scanners": [{"status": "unverified", "reason": reason}],
                "findings": [{"rule": "external", "message": reason}]}
    wire = report_formats.render_ci_json(document)
    assert wire["perf"]["reason"] == reason
    assert wire["reason"] == escaped
    assert wire["scanners"][0]["reason"] == escaped
    assert wire["findings"][0]["message"] == escaped
    assert report_formats.render_ci_json({"perf": {"status": "fail", "reason": reason}})["perf"]["reason"] == escaped


def test_bounded_note_and_coverage_lines_use_atomic_finished_clipping(capsys):
    report = ci_integrity.CiReport("a" * 40, "b" * 40, "a" * 40, 0, (), None,
                                  governance_categories=(approval_policy.guidance_value("&" * 100, prose=True),))
    check_cli._print_ci(report, "text", ".", cov_report={"status": "reported", "ratio": None,
                                                      "executable_lines": 10 ** 350})
    lines = capsys.readouterr().out.splitlines()
    for prefix in ("  note:", "  coverage (report only):"):
        line = next(line for line in lines if line.startswith(prefix))
        _assert_finished_line_is_atomic(line)


@needs_git
@pytest.mark.parametrize("recorded", [False, True])
def test_record_lines_keep_rendered_escapes_whole(tmp_path, capsys, monkeypatch, recorded):
    repo = make_repo(tmp_path)
    value = approval_policy.guidance_value("&" * 100, prose=True)
    row = {"tree": "a" * 40, "passed": False, "protected_changed": False,
           "layer1": {"findings": 1, "evidence": [{"tool": value, "target": value, "reason": value, "verdict": False}]}}
    outcome = SimpleNamespace(status="recorded" if recorded else "refused", row=row if recorded else None,
                              reason=value, hint=None)
    monkeypatch.setattr(checkrun, "record", lambda *args, **kwargs: outcome)
    os.chdir(repo.root)
    assert main(["check", "--record"]) == 1
    captured = capsys.readouterr()
    line = (next(line for line in captured.out.splitlines() if line.startswith("  Layer 1: " + r"\x26")) if recorded
            else captured.err.rstrip("\n"))
    _assert_finished_line_is_atomic(line, 400 if recorded else 300)


@needs_git
def test_record_line_redacts_a_new_match_at_the_wire_cut(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path)
    row = {"tree": "a" * 40, "passed": False, "protected_changed": False,
           "layer1": {"findings": 1, "evidence": [{"tool": r"\x26" * 70, "target": "b" * 97,
                        "reason": "1.2.3.4x more than enough tail", "verdict": False}]}}
    outcome = SimpleNamespace(status="recorded", row=row, reason="", hint=None)
    monkeypatch.setattr(checkrun, "record", lambda *args, **kwargs: outcome)
    os.chdir(repo.root)
    assert main(["check", "--record"]) == 1
    line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("  Layer 1: " + r"\x26"))
    assert "1.2.3.4" not in line
    assert line.startswith("  Layer 1: ")
    _assert_finished_line_is_atomic(line)


@needs_git
def test_progress_line_keeps_rendered_escapes_whole(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path)
    base = repo.head()
    repo.write("src/app.py", "x = 2\n")
    repo.commit("ordinary change")

    def report(root, base, head, *, progress):
        progress(approval_policy.guidance_value("&" * 100, prose=True))
        return regression.RegressionReport()

    monkeypatch.setattr(regression, "check_ci_regressions", report)
    rc, _out, err = run_ci(repo, capsys, "--base", base)
    assert rc == 0
    line = next(line for line in err.splitlines() if line.startswith("aegis check --ci: "))
    _assert_finished_line_is_atomic(line, 300)


def test_model_value_clipping_preserves_escape_boundaries():
    from tests.unit.cli.test_layer2_summary import _summary

    for value in ("&" * 100, approval_policy.guidance_value("&" * 100, prose=True)):
        out = _summary(value)
        line = next(line for line in out.splitlines() if "[critical]" in line)
        assert "&" not in line
        _assert_finished_line_is_atomic(line)


def test_finished_display_cap_census_requires_atomic_clipping():
    root = Path(__file__).resolve().parents[3]
    identities = {(ast.dump(ast.parse(expression, mode="eval").body), size) for expression, size in (
        ("row['tree']", 12), ("report.merge_base", 10), ("report.head", 10), ("untested.commit", 10),
        ("t_chk['commit']", 10), ("row['commit']", 10), ("untested.source_files", 5),
        ("hashlib.sha256(joined.encode('utf-8', 'surrogatepass')).hexdigest()", 16), ("secret", 2), ("secret", 4))}
    for filename in ("aegis_cli/check.py", "aegis_cli/formatters/report.py", "aegis_core/approval_policy.py", "aegis_core/redaction.py"):
        tree = ast.parse((root / filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "sanitize_display":
                cap = next((arg.value for arg in node.keywords if arg.arg == "max_len"),
                           node.args[1] if len(node.args) > 1 else None)
                assert isinstance(cap, ast.Constant) and cap.value is None, (filename, node.lineno)
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
                stop = node.slice.upper
                if isinstance(stop, ast.Constant) and type(stop.value) is int and stop.value > 0:
                    assert (ast.dump(node.value), stop.value) in identities, (filename, node.lineno)


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_STEP_SUMMARY", "SSH_AUTH_SOCK",
                 "GIT_CONFIG_GLOBAL", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


def make_repo(tmp_path: Path) -> hg.Repo:
    """``main`` holds a gate rule and its origin/main tracking ref; ``main`` stays checked out."""
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "x = 1\n")
    repo.write(GATE, RULE)
    repo.commit("base")
    repo.git("remote", "add", "origin", "/not-contacted")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return repo


def policy_repo(tmp_path: Path, mode="signature") -> hg.Repo:
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": mode, "*": "none"}}))
    repo.commit("policy")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    return repo


def push_event(tmp_path: Path, monkeypatch, before: str, after: str, target=None, *, ref=None, ref_present=True) -> None:
    event = tmp_path / "push.json"
    ref = "refs/heads/" + (target or "main") if ref is None else ref
    event.write_text(json.dumps({"ref": ref, "before": before, "after": after}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    environment = {"GITHUB_REF_NAME": target or "main"}
    if ref_present:
        environment["GITHUB_REF"] = ref
    for name, value in environment.items():
        monkeypatch.setenv(name, value)


def run_ci(repo: hg.Repo, capsys, *extra: str):
    os.chdir(repo.root)
    rc = main(["check", "--ci", *extra])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@needs_git
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
@pytest.mark.parametrize("surface", ["findings", "rule-message", "comparison-ref", "unresolved"])
@pytest.mark.parametrize("attack", ["$(gm1b)", "`gm1b`", ";gm1b", "&gm1b", "|gm1b", ">gm1b", "\ngm1b"],
                         ids=["substitution", "backtick", "semicolon", "ampersand", "pipe", "redirect", "newline"])
def test_ci_output_guard_covers_findings_refs_refusals_and_formats(tmp_path, capsys, monkeypatch, fmt, surface, attack):
    if os.name == "nt" and surface in ("findings", "comparison-ref") \
            and any(char in attack for char in '<>:"|?*\r\n'):
        pytest.skip("the Windows filesystem cannot store this Git path/ref")
    environment = dict(os.environ)
    summary, event = tmp_path / "summary.md", tmp_path / "push.json"
    monkeypatch.setattr(check_cli, "os", SimpleNamespace(environ=environment))
    monkeypatch.setattr(ci_inputs, "os", SimpleNamespace(environ=environment, fstat=os.fstat))
    monkeypatch.setattr(core_config, "env_github_step_summary", lambda: str(summary))
    outputs = []
    for label, value in (("control", "safe"), ("attack", attack)):
        repo = policy_repo(tmp_path / label)
        base = repo.head()
        ref = "refs/heads/base-" + value
        valid_ref = hg.run_git(repo.root, "check-ref-format", ref, check=False).returncode == 0
        if surface == "comparison-ref" and valid_ref:
            repo.git("update-ref", ref, base)
        repo.branch("work")
        if surface == "rule-message":
            repo.write(GATE, RULE.replace("\n---\n", "\n" + json.dumps("guard-" + value) + ": changed\n---\n", 1))
        else:
            (repo.root / GATE).unlink()
        path = ".github/workflows/guard-" + (value if surface == "findings" else "safe") + ".yml"
        repo.write(path, hg.RULE)
        head = repo.commit("governance change")
        if surface == "comparison-ref":
            event.write_text(json.dumps({"before": base, "after": head}), encoding="utf-8")
            environment.update(GITHUB_EVENT_PATH=str(event), GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/other")
        summary.write_text("", encoding="utf-8")
        selector = ("missing-" + (value if label == "attack" else "safe safe") if surface == "unresolved"
                    else ref if surface == "comparison-ref" else base)
        rc, out, err = run_ci(repo, capsys, "--base", selector, "--no-exec", "--format", fmt)
        assert rc == 1
        if surface == "findings":
            assert "guard-" in out
        elif surface == "rule-message":
            assert "unknown_key" in out
        if surface == "comparison-ref" and valid_ref and label == "attack" and fmt in ("text", "github"):
            assert "Comparison ref:" in out and "aegis approve --base " + base in out
        if fmt == "json":
            document = json.loads(out)
            # Object identities and artifact paths remain machine data. Check
            # every human message field instead of JSON's trusted quote syntax.
            out = document.get("next_action", "") + "\n" + "\n".join(
                row["message"] for row in document.get("weakenings", ()))
        elif fmt == "sarif":
            notifications = json.loads(out)["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            out = "\n".join(row["message"]["text"] for row in notifications)
        elif fmt == "github":
            # Properties are wire data, encoded by GitHub's unchanged protocol.
            out = "\n".join(line.split("::", 2)[2] if line.startswith("::") else line for line in out.splitlines())
        outputs.append((out, err, summary.read_text(encoding="utf-8") if summary.exists() else ""))
    for index in range(3):
        hostile = outputs[1][index]
        assert attack not in hostile, hostile


@pytest.mark.parametrize("render", [report_formats.github_annotation_lines, report_formats.format_sarif_report,
                                   report_formats.format_github_step_summary])
@pytest.mark.parametrize("attack", ["$(gm1b)", "`gm1b`", ";gm1b", "&gm1b", "|gm1b", ">gm1b", "\ngm1b"],
                         ids=["substitution", "backtick", "semicolon", "ampersand", "pipe", "redirect", "newline"])
def test_ci_output_guard_covers_advisory_and_scanner_prose(render, attack):
    streams = []
    for value in ("safe", attack):
        path, message = "src/guard-" + value + ".py", "Fix the bug " + value
        subject, note = "fix: " + message, "checked " + value
        regression_message = (f"fix commit {'a' * 10} ({subject}) modifies source without adding or updating a test"
                              f" (Aegis-No-Test: {note!r} is an explanation only; exemption requires human_gate approval)")
        document = {"status": "fail", "approval_mode": "signature", "approval_target": "main",
                    "regression": {"tier": "gate", "commits": [{"commit": "a" * 40, "subject": subject,
                                                                  "no_test_reason": note}],
                                   "findings": [{"code": "no_test_changes", "commit": "a" * 40, "path": path,
                                                 "message": regression_message}]},
                    "scanners": [{"name": "lint", "status": "unverified", "reason": message,
                                  "findings": [{"rule_id": "guard", "path": path, "line": 1, "message": message}]}],
                    "trailer_checks": [{"failed": True, "commit": "a" * 40, "reason": message}],
                    "perf": {"status": "unverified", "reason": message},
                    "coverage": {"status": "reported", "ratio": 0.5, "executable_lines": 2,
                                 "uncovered_ranges": {path: [[1, 2]]}}}
        rendered = render(document)
        if render is report_formats.format_sarif_report:
            run = json.loads(rendered)["runs"][0]
            rendered = "\n".join(row["message"]["text"] for row in run["results"])
            rendered += "\n" + "\n".join(row["message"]["text"] for row in run["invocations"][0]["toolExecutionNotifications"])
        elif isinstance(rendered, list):
            rendered = "\n".join(line.split("::", 2)[2] for line in rendered)
        streams.append(rendered)
        assert " is an explanation only; exemption requires human_gate approval)" in rendered
        if value == "safe":
            assert regression_message in rendered
    assert streams[0].count("Fix the bug") == streams[1].count("Fix the bug") > 0
    assert attack not in streams[1], streams[1]


@needs_git
@pytest.mark.parametrize("event", ["local", "pull_request", "push"])
def test_ci_reads_each_pinned_policy_once(tmp_path, capsys, monkeypatch, event):
    repo = policy_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("ordinary change")
    if event == "push":
        push_event(tmp_path, monkeypatch, base, head, "main")
    elif event == "pull_request":
        event_file(tmp_path, monkeypatch, event, {"pull_request": {
            "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}})
    original, calls = gitsafe.run, []
    def observe(args, *rest, **kwargs):
        calls.append(tuple(args))
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", observe)
    rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
    assert rc == 0 and json.loads(out)["scope"]["base"] == base and not err
    policy_reads = [args for args in calls if args[0] == "ls-tree" and approval_policy.CONFIG_PATH in args]
    assert len(policy_reads) == 2, calls
    classifications = [args for args in calls if args[:2] == ("rev-parse", "--symbolic-full-name")]
    assert len(classifications) == 1, calls


@needs_git
@pytest.mark.parametrize("name", ["push", "pull_request", "pull_request_target"])
@pytest.mark.parametrize("malformed", [False, True])
def test_event_is_read_and_parsed_once_per_retry(tmp_path, capsys, monkeypatch, name, malformed):
    repo = policy_repo(tmp_path, "none")
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("ordinary change")
    if name == "push":
        push_event(tmp_path, monkeypatch, base, head, "main")
    else:
        event_file(tmp_path, monkeypatch, name, {"pull_request": {
            "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}})
    if malformed:
        Path(os.environ["GITHUB_EVENT_PATH"]).write_text("{broken", encoding="utf-8")
    original_read, original_parse = check_cli._event_pull, ci_inputs.json.loads
    reads, parses = [], []
    def read(*args, **kwargs):
        reads.append(True)
        return original_read(*args, **kwargs)
    def parse(*args, **kwargs):
        parses.append(True)
        return original_parse(*args, **kwargs)
    monkeypatch.setattr(check_cli, "_event_pull", read)
    monkeypatch.setattr(ci_inputs, "json", SimpleNamespace(loads=parse))
    for attempt in (1, 2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        assert rc == int(malformed)
        if malformed:
            assert json.loads(out)["code"] == "invalid_ci_event"
        assert len(reads) == len(parses) == attempt


@needs_git
def test_signing_hint_uses_verified_upstream_ref(tmp_path, capsys):
    repo = policy_repo(tmp_path)
    repo.git("remote", "add", "upstream", "/not-contacted")
    repo.git("update-ref", "refs/remotes/upstream/main", "HEAD")
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.commit("weakening")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--base", "refs/remotes/upstream/main")
    assert rc == 1
    assert "aegis approve --base refs/remotes/upstream/main" in out
    assert "aegis approve --base origin/" not in out


@needs_git
@pytest.mark.parametrize("fmt", ["text", "github"])
@pytest.mark.parametrize("event", ["pull_request", "pull_request_target", "push", "local-oid"])
@pytest.mark.parametrize("known_target", [False, True], ids=["unknown-target", "known-target"])
def test_signing_hint_uses_pinned_oid_without_a_comparison_ref(tmp_path, capsys, monkeypatch,
                                                            fmt, event, known_target):
    repo = policy_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("weakening")
    extra = []
    if event == "push":
        # Discovery sees the candidate, but CI must compare its predecessor.
        repo.git("update-ref", "refs/remotes/origin/main", head)
        push_event(tmp_path, monkeypatch, base, head, "main",
                   ref="refs/heads/main" if known_target else "refs/tags/v1.2")
    elif event == "local-oid":
        extra = ["--base", base]
    else:
        anchor = {"sha": base}
        if known_target:
            anchor["ref"] = "main"
        event_file(tmp_path, monkeypatch, event, {"pull_request": {
            "base": anchor, "head": {"sha": head}}})
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--json", *extra)
        document = json.loads(out)
        assert rc == 1 and document["scope"]["base"] == base and not err
        assert document["approval_mode"] == "signature"
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--format", fmt, *extra)
        assert rc == 1 and not err
        assert "signed approval: aegis approve --base " + base + " (" in out
        assert "Comparison ref:" not in out


@needs_git
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
@pytest.mark.parametrize("remote", ["up;id;", "up`id`", "up$(id)", "up space", "up'quote", 'up"quote',
                                  "développement", "-leading", "ghp_" + "a" * 36,
                                  "long_remote_component/" * 20 + "tail", "o'$(id)", "foo&bar", "foo|bar", "foo>bar"],
                         ids=["semicolon", "backtick", "substitution", "space", "single-quote", "double-quote",
                              "unicode", "leading-hyphen", "secret", "overlong", "combined-substitution",
                              "ampersand", "pipe", "redirect"])
def test_signing_commands_only_interpolate_unchanged_conservative_tokens(tmp_path, capsys, fmt, remote):
    repo = policy_repo(tmp_path)
    base = repo.head()
    ref = "refs/remotes/" + remote + "/main"
    valid = hg.run_git(repo.root, "check-ref-format", ref, check=False).returncode == 0
    if os.name == "nt" and (any(char in remote for char in '<>:"|?*') or len(ref) > 400):
        valid = False  # NTFS/Win32 cannot store these loose refs; exercise the refusal there.
    if valid:
        repo.git("config", "remote." + remote + ".url", "/not-contacted")
        repo.git("update-ref", ref, "HEAD")
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.commit("weakening")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--base", ref, "--format", fmt)
        assert rc == 1
        if valid and fmt in ("text", "github"):
            command_line = next(line for line in out.splitlines() if "signed approval:" in line)
            if remote == "-leading":
                assert "aegis approve --base " + ref + " (" in command_line
                assert "Comparison ref:" not in out
            else:
                assert "signed approval: aegis approve --base " + base + " (" in command_line
                comparison = next(line for line in out.splitlines() if "Comparison ref:" in line)
                assert not any(char in comparison for char in "&$`;|>"), comparison
        elif not valid:
            assert "base_unavailable" in out + err
        assert "ghp_" + "a" * 36 not in out + err


@needs_git
@pytest.mark.parametrize("branch,displayed", [("foo&bar", r"foo\x26bar"), ("o'$(id)", r"o\x27\x24\x28id\x29")])
@pytest.mark.parametrize("fmt", ["text", "github"])
def test_unsafe_local_ref_guidance_uses_inert_display_and_pinned_oid(tmp_path, capsys, branch, displayed, fmt):
    repo = policy_repo(tmp_path)
    base = repo.head()
    ref = "refs/heads/" + branch
    repo.git("update-ref", ref, base)
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.commit("weakening")
    rc, out, err = run_ci(repo, capsys, "--no-exec", "--base", ref, "--format", fmt)
    assert rc == 1 and not err
    assert "signed approval: aegis approve --base " + base + " (" in out
    assert "  Comparison ref: refs/heads/" + displayed + ".\n" in out


@needs_git
@pytest.mark.parametrize("name", ["pull_request", "pull_request_target"])
@pytest.mark.parametrize("field", ["base", "head"])
@pytest.mark.parametrize("value", ["\x00", "abc", "z" * 40, [], 7, None, "a" * 65],
                         ids=["nul", "short", "nonhex", "list", "integer", "null", "oversized"])
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
@pytest.mark.parametrize("has_map", [False, True])
def test_malformed_pr_shas_refuse_before_any_git_call(tmp_path, capsys, monkeypatch, name, field, value, fmt, has_map):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    pull = {"base": {"sha": repo.head(), "ref": "main"}, "head": {"sha": repo.head()}}
    pull[field]["sha"] = value
    event_file(tmp_path, monkeypatch, name, {"pull_request": pull})
    original, calls = gitsafe.run, []
    def observed(args, *rest, **kwargs):
        calls.append(tuple(args))
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", observed)
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--base", "main", "--format", fmt)
        assert rc == 1 and err == "Error: " + ci_inputs.CI_EVENT_ERROR + "\n"
        if fmt == "json":
            assert out == json.dumps({"status": "fail", "code": "invalid_ci_event", "approval": None,
                                      "next_action": ci_inputs.CI_EVENT_ACTION}) + "\n"
        elif fmt == "sarif":
            assert out == report_formats.format_sarif_report({}, error=ci_inputs.CI_EVENT_ERROR) + "\n"
        else:
            assert out == ""
        assert calls == []


@needs_git
@pytest.mark.parametrize("field", ["before", "after"])
@pytest.mark.parametrize("value", ["\x00", "abc", "z" * 40, [], 7, "a" * 65],
                         ids=["nul", "short", "nonhex", "list", "integer", "oversized"])
def test_supplied_push_oids_are_validated_even_with_explicit_base(tmp_path, capsys, monkeypatch, field, value):
    repo = policy_repo(tmp_path)
    document = {"before": repo.head(), "after": repo.head()}
    document[field] = value
    event_file(tmp_path, monkeypatch, "push", document)
    original, calls = gitsafe.run, []
    def observed(args, *rest, **kwargs):
        calls.append(tuple(args))
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", observed)
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--base", "main", "--json")
        assert rc == 1 and json.loads(out)["code"] == "invalid_ci_event"
        assert err == "Error: " + ci_inputs.CI_EVENT_ERROR + "\n" and calls == []


@needs_git
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
@pytest.mark.parametrize("change", ["introduced", "lowered"])
def test_unsigned_policy_changes_are_owner_review_reports(tmp_path, capsys, fmt, change):
    repo = make_repo(tmp_path) if change == "introduced" else policy_repo(tmp_path, "review")
    base = repo.head()
    repo.branch("work")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "none"}}))
    repo.commit("policy change")
    code = "approval_policy_introduced" if change == "introduced" else "approval_mode_lowered"
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--base", "origin/main", "--format", fmt)
        assert rc == 0 and code in out
        if fmt == "json":
            document = json.loads(out)
            assert document["blocking"] == [] and document["weakenings"] == []
            assert [row["code"] for row in document["owner_review_required"]] == [code]
            assert document["scope"]["base"] == base
        elif fmt == "github":
            assert "::notice" in out and "::error" not in out
        elif fmt == "sarif":
            notifications = json.loads(out)["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            assert all(row["level"] == "note" for row in notifications)


@pytest.mark.parametrize("render", [report_formats.github_annotation_lines,
                                   report_formats.format_sarif_report, report_formats.format_github_step_summary])
def test_owner_review_formatter_fields_are_redacted_before_truncation(render):
    token = "ghp_" + "a" * 36
    split = "ghp_" + "a" * 10 + "\x1b[31m" + "a" * 26
    value = "x" * 380 + "/" + split
    document = {"status": "pass", "owner_review_required": [
        {"code": value, "rule": value, "path": value, "message": value}]}
    out = str(render(document))
    assert token not in out and "a" * 20 not in out and "\x1b" not in out
    assert "REDACTED" in out


@pytest.mark.parametrize("value", ["ghp_" + "a" * 10 + "\x1b[31m" + "a" * 26,
                                  "x" * 380 + "/ghp_" + "a" * 36, "x" * 8193])
def test_owner_review_json_identity_fields_are_redacted_and_bounded(value):
    document = {"status": "pass", "owner_review_required": [
        {"code": value, "rule": value, "path": value, "message": "ordinary"}]}
    encoded = report_formats.render_ci_json(document)
    (row,) = encoded["owner_review_required"]
    for key in ("code", "rule", "path"):
        shown = row[key]
        assert len(shown) <= 400 and "\x1b" not in shown and "a" * 20 not in shown
        assert "REDACTED" in shown or "too_large" in shown


@needs_git
def test_lowered_token_named_branch_has_a_redacted_owner_review_json_receipt(tmp_path, capsys):
    token = "ghp_" + "a" * 36
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "review"}}))
    base = repo.commit("unsigned review policy")
    repo.branch("work")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "review", "feature/" + token: "none"}}))
    repo.commit("lower a branch policy")
    rc, out, err = run_ci(repo, capsys, "--base", base, "--no-exec", "--json")
    assert rc == 0 and token not in out + err
    (row,) = json.loads(out)["owner_review_required"]
    assert row["code"] == "approval_mode_lowered" and "REDACTED" in row["rule"]


@needs_git
@pytest.mark.parametrize("has_map", [False, True])
def test_empty_explicit_base_keeps_push_discovery(tmp_path, capsys, monkeypatch, has_map):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    push_event(tmp_path, monkeypatch, base, head, "main")
    path = Path(os.environ["GITHUB_EVENT_PATH"])
    document = json.loads(path.read_text(encoding="utf-8"))
    document["pull_request"] = {"base": {"sha": ""}, "head": {"sha": ""}}
    path.write_text(json.dumps(document), encoding="utf-8")
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        omitted = json.loads(out)
        empty_rc, out, _err = run_ci(repo, capsys, "--base", "", "--no-exec", "--json")
        empty = json.loads(out)
        for result in (omitted, empty):
            result.pop("checked_at")
        assert rc == empty_rc == 1 and omitted == empty
        assert empty["scope"]["base"] == base and empty["weakenings"]
        assert empty.get("approval_mode") == ("signature" if has_map else None)


@needs_git
@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("event", ["push", "pull_request", "pull_request_target"])
def test_event_HEAD_cannot_bypass_the_target_guard(tmp_path, capsys, monkeypatch, has_map, event):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    if event == "push":
        push_event(tmp_path, monkeypatch, base, head, "HEAD")
    else:
        event_file(tmp_path, monkeypatch, event, {"pull_request": {
            "base": {"sha": base, "ref": "HEAD"}, "head": {"sha": head}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1 and document["weakenings"]
        assert document.get("approval_mode") == ("signature" if has_map else None)
        assert document.get("approval_target") is None


@needs_git
def test_a_push_to_main_that_deletes_a_gate_says_it_compared_nothing(tmp_path, capsys, monkeypatch):
    """Given a push to main whose commit deletes a gate rule (origin/main is that commit), When check --ci
    runs on the push event, Then it says nothing was compared, never a bare PASSED, and exits 0."""
    repo = make_repo(tmp_path)
    before = repo.head()
    (repo.root / GATE).unlink()
    after = repo.commit("drop the gate")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    push_event(tmp_path, monkeypatch, before, after)
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0
    assert f"aegis check --ci: note: base and head are the same commit; {NOTE} ({after[:10]}..{after[:10]})" in out
    assert PASSED not in out


@needs_git
def test_the_json_document_keeps_its_shape_when_nothing_was_compared(tmp_path, capsys):
    repo = make_repo(tmp_path)
    head = repo.head()
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--format", "json")
    payload = json.loads(out)
    assert rc == 0 and payload["status"] == "pass" and NOTE not in out
    assert payload["scope"]["merge_base"] == payload["scope"]["head"] == head
    assert set(payload) == {"source", "aegis_version", "checked_at", "scope", "schema", "status", "rules_checked",
                            "weakenings", "approval", "governance", "regression", "blocking"}


@needs_git
def test_a_stale_branch_behind_its_base_also_compares_nothing(tmp_path, capsys):
    """Sad: a head that is an ancestor of the base gives the note, not PASSED."""
    repo = make_repo(tmp_path)
    repo.branch("stale")
    repo.git("checkout", "-q", "main")
    repo.write("src/app.py", "x = 2\n")
    repo.commit("main moves on")
    repo.git("checkout", "-q", "stale")
    rc, out, _err = run_ci(repo, capsys, "--base", "main")
    assert rc == 0 and NOTE in out and PASSED not in out


@needs_git
def test_a_pull_request_run_still_compares_and_fails_an_unapproved_weakening(tmp_path, capsys, monkeypatch):
    """Sad: the pull_request event file names a real range; the deletion is found and fails."""
    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("drop the gate")
    event = tmp_path / "pr.json"
    event.write_text(json.dumps({"pull_request": {"number": 1, "user": {"login": "agent"},
                                                  "base": {"sha": base}, "head": {"sha": head}}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 1 and "FAILED: weakening without approval" in out and NOTE not in out
    assert f"{base[:10]}..{head[:10]}" in out


@needs_git
def test_a_real_comparison_still_says_passed(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.branch("work")
    repo.write("src/app.py", "x = 3\n")
    repo.commit("an ordinary change")
    rc, out, _err = run_ci(repo, capsys, "--base", "main")
    assert rc == 0 and PASSED in out and NOTE not in out


@needs_git
@pytest.mark.parametrize("event_name,target,mode", [
    ("push", "feature/integration", "none"),
    ("pull_request", "develop", "review"),
    ("pull_request_target", "main", "signature"),
])
def test_policy_events_use_the_target_base_and_report_findings(tmp_path, capsys, monkeypatch, event_name, target, mode):
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "develop": "review", "*": "none"}}))
    before = repo.commit("policy base")
    repo.git("update-ref", "refs/remotes/origin/main", before)
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    after = repo.commit("weakening and head attempts to lower policy")
    if event_name == "push":
        repo.git("update-ref", "refs/remotes/origin/main", after)
        push_event(tmp_path, monkeypatch, before, after, target)
    else:
        event_file(tmp_path, monkeypatch, event_name, {"pull_request": {
            "base": {"sha": before, "ref": target}, "head": {"sha": after}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        payload = json.loads(out)
        assert rc == (1 if mode == "signature" else 0)
        assert payload["scope"]["base"] == before
        assert payload["approval_mode"] == mode and payload["approval_target"] == target
        assert payload["weakenings"] and payload["policy_source"] == "base"
        assert [row["code"] for row in payload["owner_review_required"]] == ["approval_mode_lowered"] * 2
        assert [row["rule"] for row in payload["owner_review_required"]] == ["develop", "main"]
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--format", "github")
    if mode == "review":
        assert "owner review required" in out and "aegis approve" not in out
    elif mode == "signature":
        assert "signed approval: aegis approve --base " + before + " (" in out
    else:
        assert "approved by" not in out and "aegis approve" not in out


@needs_git
def test_malformed_head_policy_returns_a_fixed_json_refusal(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.branch("work")
    repo.write(".aegis/config.json", '{"approvals":{"*":"secret\\nvalue"}}')
    repo.commit("invalid policy")
    rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    payload = json.loads(out)
    assert rc == 1 and payload["code"] == "invalid_approval_policy"
    assert payload["key"] == "approvals" and payload["path"] == ".aegis/config.json"
    assert payload["next_action"] and "secret" not in out + err


@needs_git
@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("base_value", ["secret", [], None, {"ref": [], "sha": "a" * 40},
    {"ref": "main", "sha": []}, {"ref": 7, "sha": "a" * 40}],
    ids=["string", "list", "null", "list-ref", "list-sha", "integer-ref"])
def test_malformed_event_base_reaches_fixed_ci_error(tmp_path, capsys, monkeypatch, base_value, fmt):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": base_value, "head": {"sha": repo.head()}}})
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--format", fmt)
        assert rc == 1 and "Error: invalid_ci_event" in err
        assert "Traceback" not in out + err and "secret" not in out + err
        if fmt == "json":
            document = json.loads(out)
            assert document["status"] == "fail" and document["code"] == "invalid_ci_event"
            assert document["approval"] is None


@needs_git
@pytest.mark.parametrize("head_value", ["secret", [], None, {"sha": []}, {"sha": "secret"}],
                         ids=["string", "list", "null", "list-sha", "invalid-sha"])
def test_malformed_event_head_reaches_fixed_json_error(tmp_path, capsys, monkeypatch, head_value):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": repo.head(), "ref": "main"}, "head": head_value}})
    rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["code"] == "invalid_ci_event" and document["approval"] is None
    assert "secret" not in out + err


@needs_git
@pytest.mark.parametrize("name", ["pull_request", "push"])
@pytest.mark.parametrize("text", ['[' * 1500 + ']' * 1500, '[]', '"secret"'], ids=["deep", "array", "scalar"])
def test_invalid_event_document_reaches_fixed_ci_error(tmp_path, capsys, monkeypatch, name, text):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, name, {})
    event = tmp_path / "event.json"
    event.write_text(text, encoding="utf-8")
    rc, out, err = run_ci(repo, capsys, "--no-exec")
    assert rc == 1 and "Error: invalid_ci_event" in err and "Traceback" not in out + err


@needs_git
@pytest.mark.parametrize("mode", ["none", "review", "signature"])
@pytest.mark.parametrize("fmt", ["text", "json", "github", "sarif"])
def test_policy_output_redacts_target_findings_and_paths(tmp_path, capsys, mode, fmt):
    token = "ghp_" + "a" * 36
    repo = make_repo(tmp_path)
    rule = f".aegis/rules/gates/gate-{token}.md"
    repo.write(rule, RULE.replace("gate-no-eval", "gate-" + token))
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": mode}}))
    base = repo.commit("policy and token rule")
    target = "feature/" + token
    repo.git("update-ref", "refs/remotes/origin/" + target, base)
    repo.branch("work")
    (repo.root / rule).unlink()
    repo.write(f".github/workflows/{token}.yml", "name: changed\n")
    repo.commit("governance and weakening")
    rc, out, err = run_ci(repo, capsys, "--base", "origin/" + target, "--no-exec", "--format", fmt)
    assert rc == (1 if mode == "signature" else 0)
    assert token not in out + err and "REDACTED" in out
    if fmt == "json":
        payload = json.loads(out)
        assert "REDACTED" in payload["approval_target"]
        assert "REDACTED" in payload["weakenings"][0]["path"]
        assert "REDACTED" in payload["governance"]["paths"][0]["path"]
    elif fmt == "github" and mode != "signature":
        assert "::error" not in out and "without approval" not in out
        assert "tier C" not in out
        assert "owner review required" in out if mode == "review" else "approval mode none" in out
    elif fmt == "sarif" and mode != "signature":
        notifications = json.loads(out)["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert len(notifications) >= 2 and all(item["level"] == "note" for item in notifications)


@needs_git
def test_event_is_one_snapshot_even_if_file_changes_after_read(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    base = repo.commit("policy")
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("weakening")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}})
    original, reads = check_cli._event_pull, []
    environment = dict(os.environ)
    monkeypatch.setattr(check_cli, "os", SimpleNamespace(environ=environment))
    def swap(*args, **kwargs):
        result = original(*args, **kwargs)
        reads.append(True)
        environment.update(GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/feature/lower")
        (tmp_path / "event.json").write_text(json.dumps({"pull_request": {
            "base": {"sha": base, "ref": "feature/lower"}, "head": {"sha": head}}}), encoding="utf-8")
        return result
    monkeypatch.setattr(check_cli, "_event_pull", swap)
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["approval_mode"] == "signature" and document["approval_target"] == "main"
    assert len(reads) == 1


# ── R-trust-13 (c)-(f): the base-sourced governance job runs on pull_request_target ─────────────


@needs_git
@pytest.mark.parametrize("before_kind", ["missing", "malformed", "unavailable", "head"])
def test_push_never_uses_candidate_policy_as_its_own_base(tmp_path, capsys, monkeypatch, before_kind):
    repo = policy_repo(tmp_path)
    repo.branch("work")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    (repo.root / GATE).unlink()
    head = repo.commit("lower policy and remove gate")
    repo.git("update-ref", "refs/remotes/origin/main", head)
    before = {"missing": None, "malformed": "secret", "unavailable": "f" * 40, "head": head}[before_kind]
    push_event(tmp_path, monkeypatch, before, head, "main")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        if before_kind == "malformed":
            assert rc == 1 and document["code"] == "invalid_ci_event"
            assert document["next_action"] == ci_inputs.CI_EVENT_ACTION
            assert err == "Error: " + ci_inputs.CI_EVENT_ERROR + "\n"
            continue
        assert rc == 1 and document["code"] == ("comparison_unavailable" if before_kind == "head" else "base_unavailable")
        assert document["next_action"] == ("pass --base that is a proper ancestor of the head" if before_kind == "head"
                                          else "fetch the push's before commit (fetch-depth) and re-run")
        assert "secret" not in out + err


@needs_git
def test_policy_push_refuses_head_as_the_comparison_merge_base(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    head = repo.commit("policy head")
    repo.write("README.md", "descendant\n")
    descendant = repo.commit("tracking ref advanced")
    repo.git("update-ref", "refs/remotes/origin/main", descendant)
    repo.git("checkout", "-q", head)
    push_event(tmp_path, monkeypatch, descendant, head, "main")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    assert rc == 1 and json.loads(out)["code"] == "comparison_unavailable"


@needs_git
@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("position", ["head", "descendant"])
def test_push_zero_before_keeps_permitted_fallback(tmp_path, capsys, monkeypatch, has_map, explicit, position):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    head = repo.head()
    if position == "descendant":
        repo.write("README.md", "remote advanced\n")
        repo.commit("descendant")
        repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
        repo.git("checkout", "-q", head)
    base = repo.git("rev-parse", "refs/remotes/origin/main")
    push_event(tmp_path, monkeypatch, "0" * 40, head, "main")
    extra = ["--base", "origin/main"] if explicit else []
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, *extra, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 0 and document["status"] == "pass" and document["scope"]["base"] == base


@needs_git
@pytest.mark.parametrize("before", [None, "secret", "f" * 40])
def test_no_map_push_predecessor_preserves_absence_but_refuses_malformed(tmp_path, capsys, monkeypatch, before):
    repo = make_repo(tmp_path)
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    expected = json.loads(out)
    push_event(tmp_path, monkeypatch, before, repo.head(), "main")
    rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
    actual = json.loads(out)
    if before == "secret":
        assert rc == 1 and actual["code"] == "invalid_ci_event"
        assert err == "Error: " + ci_inputs.CI_EVENT_ERROR + "\n"
        return
    for document in (expected, actual):
        document.pop("checked_at")
    assert rc == 0 and json.dumps(actual) == json.dumps(expected)


@needs_git
@pytest.mark.parametrize("config_text", ['{broken', '[]', 'x' * (64 * 1024 + 1)], ids=["invalid", "non-object", "oversized"])
def test_unusable_before_config_does_not_narrow_legacy_push_range(tmp_path, capsys, monkeypatch, config_text):
    repo = make_repo(tmp_path)
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.write(".aegis/config.json", config_text)
    before = repo.commit("earlier push removed gate")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("later push")
    push_event(tmp_path, monkeypatch, before, head, "main")
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["weakenings"]
    assert "approval_mode" not in document


@needs_git
@pytest.mark.parametrize("ref", ["release+1", "développement"])
@pytest.mark.parametrize("has_map", [False, True])
def test_out_of_grammar_event_ref_is_legacy_or_strictest(tmp_path, capsys, monkeypatch, ref, has_map):
    repo = policy_repo(tmp_path) if has_map else make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("change workflow")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": base, "ref": ref}, "head": {"sha": head}}})
    rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
    document = json.loads(out)
    assert rc == (1 if has_map else 0)
    if has_map:
        assert document["approval_mode"] == "signature" and document["approval_target"] is None
    else:
        assert "approval_mode" not in document


@needs_git
@pytest.mark.parametrize("shape", ["no-path", "missing-sha", "short-sha"])
def test_legacy_pr_without_valid_shas_returns_fixed_refusal(tmp_path, capsys, monkeypatch, shape):
    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("code only")
    pull = {"base": {"ref": "main"}, "head": {}}
    if shape == "short-sha":
        pull["base"]["sha"], pull["head"]["sha"] = base[:8], head[:8]
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": pull}, path_present=shape != "no-path")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
        assert rc == 1 and json.loads(out) == {"status": "fail", "code": "invalid_ci_event", "approval": None,
                                               "next_action": ci_inputs.CI_EVENT_ACTION}
        assert err == "Error: " + ci_inputs.CI_EVENT_ERROR + "\n"


@needs_git
def test_push_event_over_one_mib_is_supported(tmp_path, capsys, monkeypatch):
    repo = policy_repo(tmp_path, "none")
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("code only")
    event_file(tmp_path, monkeypatch, "push", {"before": base, "after": head,
        "commits": [{"message": "message " * 100} for _ in range(2048)]})
    size = (tmp_path / "event.json").stat().st_size
    assert 1024 * 1024 < size < 25 * 1024 * 1024
    rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
    assert rc == 0 and json.loads(out)["approval_mode"] == "none" and "invalid_ci_event" not in err


@needs_git
def test_oversized_event_refuses_before_json_parse(tmp_path, capsys, monkeypatch):
    repo = policy_repo(tmp_path)
    event_file(tmp_path, monkeypatch, "pull_request", {})
    (tmp_path / "event.json").write_bytes(b"x" * (25 * 1024 * 1024 + 1))
    def premature_parse(*args, **kwargs):
        pytest.fail("oversized event reached JSON parsing")
    monkeypatch.setattr(ci_inputs, "json", SimpleNamespace(loads=premature_parse, dumps=json.dumps))
    rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    assert rc == 1 and json.loads(out)["code"] == "invalid_ci_event" and "Traceback" not in err


@needs_git
@pytest.mark.parametrize("entrypoint", ["check", "approve"])
def test_shared_policy_blob_io_failure_returns_fixed_refusal(tmp_path, capsys, monkeypatch, entrypoint):
    repo = policy_repo(tmp_path)
    blob = gitsafe.tree_blobs(repo.root, repo.head(), paths=(".aegis/config.json",))[".aegis/config.json"][1]
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    before = repo.commit("workflow with same policy blob")
    original = gitsafe.read_object
    def unavailable(root, oid, limit):
        if oid == blob:
            raise gitsafe.GitError("secret object read failure")
        return original(root, oid, limit)
    monkeypatch.setattr(gitsafe, "read_object", unavailable)
    if entrypoint == "check":
        rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    else:
        rc = main(["approve", "--workspace", str(repo.root), "--base", "main", "--json"])
        captured = capsys.readouterr()
        out, err = captured.out, captured.err
    document = json.loads(out)
    assert rc == 1 and document["code"] == "invalid_approval_policy"
    assert "secret" not in out + err and "fetch or repair" in out + err
    assert repo.head() == before


@needs_git
@pytest.mark.parametrize("name", ["pull_request", "push"])
@pytest.mark.parametrize("text", ['[' * 1500 + ']' * 1500, '[]'], ids=["deep", "array"])
def test_legacy_unreadable_event_returns_fixed_refusal(tmp_path, capsys, monkeypatch, name, text):
    repo = make_repo(tmp_path)
    event_file(tmp_path, monkeypatch, name, {})
    (tmp_path / "event.json").write_text(text, encoding="utf-8")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--no-exec", "--json")
        assert rc == 1 and json.loads(out) == {"status": "fail", "code": "invalid_ci_event", "approval": None,
                                               "next_action": ci_inputs.CI_EVENT_ACTION}
        assert err == "Error: " + ci_inputs.CI_EVENT_ERROR + "\n"


@needs_git
def test_other_remote_git_branch_is_a_known_target(tmp_path, capsys):
    repo = policy_repo(tmp_path)
    repo.git("remote", "add", "upstream", "/not-contacted")
    base = repo.head()
    repo.git("update-ref", "refs/remotes/upstream/main", base)
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    repo.commit("governance")
    rc, out, _err = run_ci(repo, capsys, "--base", "upstream/main", "--no-exec", "--json")
    document = json.loads(out)
    assert rc == 1 and document["approval_mode"] == "signature" and document["approval_target"] == "main"


@needs_git
@pytest.mark.parametrize("selector", ["upstream/main", "refs/remotes/upstream/main", "v1.2", "sha", "origin/HEAD"])
def test_pr_event_cannot_upgrade_an_unknown_explicit_target(tmp_path, capsys, monkeypatch, selector):
    repo = policy_repo(tmp_path)
    base = repo.head()
    repo.git("update-ref", "refs/remotes/upstream/main", base)
    repo.git("tag", "v1.2", base)
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "number": 1, "user": {"login": "agent"},
        "base": {"sha": base, "ref": "feature/x"}, "head": {"sha": head}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--base", base if selector == "sha" else selector, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1 and document["status"] == "fail" and document["weakenings"]
        assert document["approval_mode"] == "signature" and document["approval_target"] is None


@needs_git
@pytest.mark.parametrize("tracking", ["matching", "missing", "different", "event-different", "shadow-tag"])
def test_explicit_pr_sha_stays_unknown_even_with_matching_origin(tmp_path, capsys, monkeypatch, tracking):
    repo = policy_repo(tmp_path)
    older = repo.git("rev-parse", "HEAD^")
    base = repo.head()
    if tracking == "shadow-tag":
        repo.git("tag", "refs/remotes/origin/feature/x", base)
    elif tracking != "missing":
        repo.git("update-ref", "refs/remotes/origin/feature/x", older if tracking == "different" else base)
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("delete binding gate")
    event_file(tmp_path, monkeypatch, "pull_request", {"pull_request": {
        "base": {"sha": older if tracking == "event-different" else base, "ref": "feature/x"}, "head": {"sha": head}}})
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--base", base, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1
        assert document["approval_target"] is None and document["approval_mode"] == "signature"


@needs_git
@pytest.mark.parametrize("ref", ["refs/tags/v1.2", "refs/tags/release/1", "refs/pull/1/merge", "main", "", None])
def test_push_non_branch_ref_uses_strictest_mode(tmp_path, capsys, monkeypatch, ref):
    repo = policy_repo(tmp_path)
    repo.branch("outside-main")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow on tagged commit")
    push_event(tmp_path, monkeypatch, "0" * 40, head, "v1.2", ref=ref, ref_present=ref is not None)
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == 1 and document["governance"]["categories"] == ["workflows"]
        assert document["approval_mode"] == "signature" and document["approval_target"] is None


@needs_git
@pytest.mark.parametrize("fallback", ["head", "descendant"])
@pytest.mark.parametrize("delete_gate", [False, True])
def test_first_map_push_compares_the_resolved_legacy_predecessor(tmp_path, capsys, monkeypatch, fallback, delete_gate):
    repo = make_repo(tmp_path)
    before = repo.head()
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    if delete_gate:
        (repo.root / GATE).unlink()
    head = repo.commit("adopt approval policy")
    if fallback == "descendant":
        repo.write("README.md", "later\n")
        repo.commit("remote advanced")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("checkout", "-q", head)
    push_event(tmp_path, monkeypatch, before, head, "main")
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == int(delete_gate) and document["scope"]["base"] == before
        assert document["scope"]["merge_base"] == before and document["governance"]["categories"]
        assert bool(document["weakenings"]) == delete_gate
        assert "approval_mode" not in document


@needs_git
@pytest.mark.parametrize("before", [None, "secret", "f" * 40])
@pytest.mark.parametrize("mode", ["signature", "none"])
def test_explicit_push_base_does_not_require_available_before(tmp_path, capsys, monkeypatch, before, mode):
    repo = policy_repo(tmp_path, mode)
    base = repo.head()
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow")
    push_event(tmp_path, monkeypatch, before, head, "main")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", "origin/main", "--no-exec", "--json")
        document = json.loads(out)
        if before == "secret":
            assert rc == 1 and document["code"] == "invalid_ci_event"
            assert err == "Error: " + ci_inputs.CI_EVENT_ERROR + "\n"
            continue
        assert rc == int(mode == "signature") and document["scope"]["base"] == base and document["governance"]["categories"]
        assert document["approval_mode"] == mode and document["approval_target"] == "main"
        assert "base_unavailable" not in out + err and "secret" not in out + err


@needs_git
@pytest.mark.parametrize("mode", ["none", "review"])
def test_step_summary_keeps_permitted_review_surface(tmp_path, capsys, mode):
    repo = policy_repo(tmp_path, mode)
    repo.branch("work")
    (repo.root / GATE).unlink()
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    repo.commit("weakening and governance")
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
    summary = report_formats.format_github_step_summary(json.loads(out), repo.root)
    assert rc == 0 and "PASSED" in summary and "No findings reported" not in summary
    assert "gate-no-eval" in summary and ".github/workflows/changed.yml" in summary
    assert "approval mode " + mode in summary
    assert ("owner review required" in summary) == (mode == "review")


@needs_git
@pytest.mark.parametrize("kind", ["head", "descendant", "unrelated", "missing"])
@pytest.mark.parametrize("fmt", ["text", "json"])
def test_explicit_push_refusal_names_its_base_without_echoing_secrets(tmp_path, capsys, monkeypatch, kind, fmt):
    repo = policy_repo(tmp_path)
    head = repo.head()
    token = "ghp_" + "a" * 36
    selector = "origin/feature/" + token
    base = head
    if kind == "descendant":
        repo.write("README.md", "later\n")
        base = repo.commit("descendant")
        repo.git("checkout", "-q", head)
    elif kind == "unrelated":
        base = repo.git("commit-tree", "HEAD^{tree}", stdin="unrelated\n")
    if kind != "missing":
        repo.git("update-ref", "refs/remotes/" + selector, base)
    push_event(tmp_path, monkeypatch, None, head, "main")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", selector, "--no-exec", "--format", fmt)
        code = "base_unavailable" if kind == "missing" else "comparison_unavailable"
        assert rc == 1 and code in out + err
        if kind == "missing":
            assert "fetch it or pass the full commit id" in out + err and "fetch origin" in out + err
            assert "origin/feature/" in out + err and "REDACTED" in out + err
        else:
            assert "proper ancestor" in out + err
        assert token not in out + err and "before commit" not in out + err and "Traceback" not in out + err
        if fmt == "json":
            document = json.loads(out)
            assert document["code"] == code and document["next_action"]


@needs_git
@pytest.mark.parametrize("selector", ["origin/feature/x", "refs/remotes/origin/feature/x", "feature/x", "refs/heads/feature/x"])
@pytest.mark.parametrize("event,landing", [
    ("pull_request", "main"), ("pull_request", "feature/x"),
    ("pull_request_target", "main"), ("pull_request_target", "feature/x"),
    ("push", "main"), ("push", "feature/x"), ("tag", "v1.2"),
])
def test_explicit_base_target_must_agree_with_the_landing_event(tmp_path, capsys, monkeypatch, selector, event, landing):
    repo = policy_repo(tmp_path)
    base = repo.head()
    repo.git("update-ref", "refs/remotes/origin/feature/x", base)
    repo.git("branch", "feature/x", base)
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow")
    if event in ("push", "tag"):
        push_event(tmp_path, monkeypatch, base, head, landing,
                   ref="refs/tags/v1.2" if event == "tag" else "refs/heads/" + landing)
    else:
        event_file(tmp_path, monkeypatch, event, {"pull_request": {
            "base": {"sha": base, "ref": landing}, "head": {"sha": head}}})
    agrees = landing == "feature/x"
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--base", selector, "--no-exec", "--json")
        document = json.loads(out)
        assert rc == (0 if agrees else 1) and document["scope"]["base"] == base
        assert document["approval_target"] == ("feature/x" if agrees else None)
        assert document["approval_mode"] == ("none" if agrees else "signature")


@needs_git
@pytest.mark.parametrize("source", ["local", "push-explicit", "push-discovered"])
@pytest.mark.parametrize("selector", ["origin/main", "main"])
def test_explicit_and_discovered_bases_keep_their_git_semantics(tmp_path, capsys, monkeypatch, source, selector):
    repo = policy_repo(tmp_path)
    base = repo.head()
    legacy = repo.git("rev-parse", "HEAD^")
    repo.git("tag", selector, legacy)
    repo.branch("work")
    repo.write(".github/workflows/changed.yml", "name: changed\n")
    head = repo.commit("workflow")
    if source != "local":
        push_event(tmp_path, monkeypatch, "0" * 40, head, "main")
    extra = [] if source == "push-discovered" else ["--base", selector]
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, *extra, "--no-exec", "--json")
        document = json.loads(out)
        # Explicit ambiguous input uses Git's tag and its legacy policy. Only
        # automatic discovery selects the qualified branch despite that tag.
        discovered = source == "push-discovered"
        assert rc == int(discovered) and document["scope"]["base"] == (base if discovered else legacy)
        assert document.get("approval_mode") == ("signature" if discovered else None)
        assert document.get("approval_target") == ("main" if discovered else None)


@needs_git
@pytest.mark.parametrize("mode", ["none", "review"])
def test_permitted_mode_still_prints_first_blocker(tmp_path, capsys, monkeypatch, mode):
    repo = policy_repo(tmp_path, mode)
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    repo.commit("code only")
    result = {"status": "fail", "regressed": True, "noisy": False, "passed": False, "rounds": 15,
              "threshold": 0.05, "base_min": 0.01, "head_min": 0.02, "base_median": 0.01, "head_median": 0.02}
    monkeypatch.setattr(perf_check, "run_perf_check", lambda *args, **kwargs: result)
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--perf")
    assert rc == 1 and "FAILED, approval mode " + mode in out
    assert ": performance regression (" in out


@needs_git
@pytest.mark.parametrize("event", ["local", "push", "pull_request", "pull_request_target", "workflow_dispatch"])
@pytest.mark.parametrize("move_ref", [False, True])
def test_no_map_ci_consumers_share_one_pinned_branch_base(tmp_path, capsys, monkeypatch, event, move_ref):
    repo = make_repo(tmp_path)
    tag = repo.head()
    repo.write("README.md", "branch base\n")
    base = repo.commit("branch advances")
    repo.git("update-ref", "refs/remotes/origin/main", base)
    repo.git("tag", "origin/main", tag)
    repo.branch("work")
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    head = repo.commit("workflow")
    extra = ["--base", "origin/main"] if event == "local" else []
    if event == "push":
        push_event(tmp_path, monkeypatch, base, head, "main")
    elif event != "local":
        document = {"pull_request": {"base": {"sha": base, "ref": "main"}, "head": {"sha": head}}}
        event_file(tmp_path, monkeypatch, event, document if event.startswith("pull_request") else {})
    seen = {name: [] for name in ("weakening", "regression", "checkrun", "credit", "coverage", "perf")}
    weakening, regressions = ci_integrity.check_ci, regression.check_ci_regressions
    trailers, credit_trailers = checkrun.verify_commit_trailers, credit.verify_commit_trailers
    def weakening_check(root, candidate, tip, **kwargs):
        seen["weakening"].append(candidate)
        report = weakening(root, candidate, tip, **kwargs)
        if move_ref:
            repo.git("update-ref", "refs/remotes/origin/main", tag)
        return report
    def regression_check(root, candidate, tip, **kwargs):
        seen["regression"].append(candidate)
        return regressions(root, candidate, tip, **kwargs)
    def trailer_check(root, candidate, tip, **kwargs):
        seen["checkrun"].append(candidate)
        return trailers(root, candidate, tip, **kwargs)
    def credit_check(root, candidate, tip, **kwargs):
        seen["credit"].append(candidate)
        return credit_trailers(root, candidate, tip, **kwargs)
    def coverage(root, candidate, tip):
        seen["coverage"].append(candidate)
        return {"status": "reported", "reason": "", "covered_lines": 1, "executable_lines": 1,
                "ratio": 1.0, "uncovered_ranges": {}, "unmeasured": []}
    def perf(root, *, base_ref):
        seen["perf"].append(base_ref)
        return {"status": "pass", "regressed": False, "noisy": False, "passed": True, "rounds": 15,
                "threshold": 0.05, "base_min": 0.01, "head_min": 0.01, "base_median": 0.01, "head_median": 0.01}
    monkeypatch.setattr(ci_integrity, "check_ci", weakening_check)
    monkeypatch.setattr(regression, "check_ci_regressions", regression_check)
    monkeypatch.setattr(checkrun, "verify_commit_trailers", trailer_check)
    monkeypatch.setattr(credit, "verify_commit_trailers", credit_check)
    monkeypatch.setattr(coverage_check, "run_diff_coverage", coverage)
    monkeypatch.setattr(perf_check, "run_perf_check", perf)
    for _ in range(2):
        repo.git("update-ref", "refs/remotes/origin/main", base)
        rc, out, _err = run_ci(repo, capsys, *extra, "--coverage", "--perf", "--json")
        report = json.loads(out)
        expected_base = tag if event == "local" else base
        assert rc == 0 and report["scope"]["base"] == report["scope"]["merge_base"] == expected_base
        assert "approval_mode" not in report
        assert all(values and set(values) == {expected_base} for values in seen.values()), seen

PULL = {"number": 7, "user": {"login": "agent"}, "base": {"sha": "a" * 40, "ref": "main"}, "head": {"sha": "B" * 40}}


@needs_git
def test_discovered_tag_cannot_hide_the_local_branch_policy(tmp_path, capsys):
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("README.md", "legacy tag\n")
    tag = repo.commit("legacy")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    base = repo.commit("local branch policy")
    repo.branch("work")
    (repo.root / ".aegis/config.json").unlink()
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    repo.commit("head drops the policy")
    repo.git("tag", "origin/main", tag)
    for _ in range(2):
        rc, out, _err = run_ci(repo, capsys, "--no-exec", "--json")
        report = json.loads(out)
        assert rc == 1 and report["scope"]["base"] == base
        assert report["approval_mode"] == "signature" and report["approval_target"] is None


@needs_git
def test_ci_pins_before_a_branch_deletion_can_change_the_target_policy(tmp_path, capsys, monkeypatch):
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}}))
    base = repo.commit("branch policy")
    repo.branch("work")
    repo.write("README.md", "tag descendant\n")
    tag = repo.commit("tag descendant")
    repo.git("tag", "main", tag)
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    repo.commit("workflow")
    original = gitsafe.resolve_commit
    def delete_between_steps(root, selector):
        commit = original(root, selector)
        if selector == "refs/heads/main" and commit == base:
            repo.git("update-ref", "-d", "refs/heads/main")
        return commit
    monkeypatch.setattr(gitsafe, "resolve_commit", delete_between_steps)
    for _ in range(2):
        repo.git("update-ref", "refs/heads/main", base)
        rc, out, _err = run_ci(repo, capsys, "--base", "refs/heads/main", "--no-exec", "--json")
        report = json.loads(out)
        assert rc == 1 and report["scope"]["base"] == base
        assert report["approval_mode"] == "signature" and report["approval_target"] is None


@needs_git
@pytest.mark.parametrize("selector", ["tag-only", "origin/tag-only", "refs/tags/tag-only"])
def test_tag_only_base_runs_the_strictest_policy(tmp_path, capsys, selector):
    repo = policy_repo(tmp_path)
    repo.git("tag", "origin/tag-only" if selector == "origin/tag-only" else "tag-only", repo.head())
    repo.branch("work")
    repo.write(".github/workflows/ci.yml", "name: changed\n")
    repo.commit("workflow")
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", selector, "--no-exec", "--json")
        report = json.loads(out)
        assert rc == 1 and report["approval_mode"] == "signature" and report["approval_target"] is None
        assert report["scope"]["base"] == repo.git("rev-parse", "refs/tags/" + ("origin/tag-only" if selector == "origin/tag-only" else "tag-only"))
        assert "base_unavailable" not in out + err and "Traceback" not in out + err


@needs_git
def test_branch_ref_io_failure_has_a_fixed_policy_refusal(tmp_path, capsys, monkeypatch):
    repo = policy_repo(tmp_path)
    def unavailable(*args, **kwargs):
        raise gitsafe.GitError("secret ref read failure")
    monkeypatch.setattr(gitsafe, "read_ref", unavailable)
    for _ in range(2):
        rc, out, err = run_ci(repo, capsys, "--base", "main", "--no-exec", "--json")
        assert rc == 1 and json.loads(out)["code"] == "invalid_approval_policy"
        assert "secret" not in out + err and "Traceback" not in out + err


def event_file(tmp_path: Path, monkeypatch, name: str, payload, path_present=True) -> None:
    if path_present:
        event = tmp_path / "event.json"
        event.write_bytes(json.dumps(payload).encode("utf-8"))
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", name)


@pytest.mark.parametrize("name", ["pull_request", "pull_request_target"])
def test_a_pull_request_target_run_names_its_pull_request_for_the_review_lookup(tmp_path, monkeypatch, name):
    from aegis_cli import check
    from aegis_core import human_gate

    event_file(tmp_path, monkeypatch, name, {"pull_request": PULL})
    assert check._event_pull_request(Event(name, check._event_pull(None))) == human_gate.PullRequest(7, "agent", "b" * 40, "main")


@pytest.mark.parametrize("name", ["push", "workflow_dispatch", "pull_request_review", "PULL_REQUEST_TARGET", ""])
def test_any_other_event_names_no_pull_request(tmp_path, monkeypatch, name):
    from aegis_cli import check

    event_file(tmp_path, monkeypatch, name, {"pull_request": PULL})
    assert check._event_pull_request(Event(name, check._event_pull(None))) is None


@pytest.mark.parametrize("pull", [
    {**PULL, "number": "7"}, {**PULL, "number": 0}, {**PULL, "user": {"login": "two words"}},
    {**PULL, "head": {"sha": "abc"}}, {**PULL, "base": {"sha": "a" * 40, "ref": "../main"}},
    {k: v for k, v in PULL.items() if k != "user"}, "not an object",
], ids=["number-str", "number-zero", "login", "sha", "ref", "no-user", "string"])
def test_a_malformed_pull_request_target_payload_names_no_pull_request(tmp_path, monkeypatch, pull):
    from aegis_cli import check

    event_file(tmp_path, monkeypatch, "pull_request_target", {"pull_request": pull})
    assert check._event_pull_request(Event("pull_request_target", check._event_pull(None))) is None


@needs_git
def test_no_exec_on_pull_request_target_hands_the_pull_request_to_the_weakening_check(tmp_path, capsys, monkeypatch):
    """--no-exec runs no repository code, but tier A's review lookup (a GitHub read) still gets the
    pull request; nothing is flagged here, so no gh call happens."""
    from aegis_core import human_gate, rule_integrity

    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("an ordinary change")
    event_file(tmp_path, monkeypatch, "pull_request_target", {"pull_request": {
        "number": 3, "user": {"login": "agent"}, "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}})
    seen = []
    real = rule_integrity.check_ci

    def spy(*args, pull_request=None, **kwargs):
        seen.append(pull_request)
        return real(*args, pull_request=pull_request, **kwargs)

    monkeypatch.setattr(rule_integrity, "check_ci", spy)
    rc, out, _err = run_ci(repo, capsys, "--no-exec")
    assert rc == 0 and PASSED in out
    assert seen == [human_gate.PullRequest(3, "agent", head, "main")]
