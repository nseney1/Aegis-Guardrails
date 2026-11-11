"""R-checks-37: the step summary renders finding text from the pull request as inert data. Every
value sits in a CommonMark code span (the one inline form in which nothing is parsed), one table
row per finding with one rule per column, so no heading, link, image or HTML comes from the data."""
from __future__ import annotations

import re

import pytest

from aegis_cli.formatters.report import format_github_step_summary

HOSTILE = {
    "pipe": "x | y",
    "tick1": "a`b", "tick2": "a``b", "tick3": "a```b", "lead-tick": "`lead", "trail-tick": "trail`",
    "heading": "line one\n\n### Aegis Check Summary: PASSED\n- injected",
    "links": "[approved](https://evil.example/a) ![beacon](https://evil.example/b.png)",
    "html": '<a href="https://evil.example">click</a><img src=x>',
    "url": "https://evil.example/c",
    "emphasis": "**bold** _em_ ~~strike~~ &amp; :+1:",
    "bidi-ansi": "safe‮evil\x1b[31mred\x1b[0m",
    "backslash-pipe": "back\\|slash", "double-backslash-pipe": "back\\\\|slash",
    "trailing-backslash": "ends with backslash\\", "pipes": "\\|\\|",
}
HARMLESS = "harmless"


def _outside_spans(text: str) -> str:
    """``text`` with every CommonMark code span removed: what a renderer parses as Markdown."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "`":
            run = re.match(r"`+", text[i:]).group(0)
            close = re.search(r"(?<!`)" + run + r"(?!`)", text[i + len(run):])
            if close:
                i += len(run) + close.end()
                continue
            out.append(run)
            i += len(run)
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _columns(row: str, escapes: bool) -> list:
    """The rules of a GFM table row: ``escapes`` honours a backslash before any character (cmark-gfm),
    otherwise only ``\\|`` is an escaped pipe (the naive reading)."""
    body = row.strip()[1:-1] if row.strip().startswith("|") and row.strip().endswith("|") else row
    cols, cur, i = [], "", 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and (escapes or body[i + 1] == "|"):
            cur += body[i:i + 2]
            i += 2
            continue
        if ch == "|":
            cols.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    return cols + [cur]


def _doc(rule: str = "no-eval", path: str = "aegis_core/bad.py", message: str = "Forbidden eval() call",
         repo_rule: str = "repo-gate", repo_message: str = "Unanchored repository-level gate failure",
         cov_path: str = "pkg/a.py") -> dict:
    return {"passed": False,
            "layer1": [{"tool": rule, "target": path, "verdict": False, "detail": message, "lines": [14]}],
            "findings": [{"rule": repo_rule, "message": repo_message, "level": "error"}],
            "coverage": {"status": "reported", "ratio": 0.5, "executable_lines": 4,
                         "uncovered_ranges": {cov_path: [[3, 4]]}}}


def _anchored_row(summary: str) -> str:
    return next(line for line in summary.splitlines() if line.startswith("| ") and "14" in line)


@pytest.mark.parametrize("value", sorted(HOSTILE.values()), ids=sorted(HOSTILE))
@pytest.mark.parametrize("field", ["rule", "path", "message"])
def test_an_anchored_finding_renders_as_data(field, value):
    summary = format_github_step_summary(_doc(**{field: value}))
    harmless = format_github_step_summary(_doc(**{field: HARMLESS}))
    assert _outside_spans(summary) == _outside_spans(harmless)
    row = _anchored_row(summary)
    assert len(_columns(row, escapes=True)) == 4 and len(_columns(row, escapes=False)) == 4
    assert all(ch == "\n" or ch.isprintable() for ch in summary)


@pytest.mark.parametrize("value", sorted(HOSTILE.values()), ids=sorted(HOSTILE))
@pytest.mark.parametrize("field", ["repo_rule", "repo_message", "cov_path"])
def test_a_line_less_finding_and_a_coverage_path_render_as_data(field, value):
    summary = format_github_step_summary(_doc(**{field: value}))
    assert _outside_spans(summary) == _outside_spans(format_github_step_summary(_doc(**{field: HARMLESS})))
    assert all(ch == "\n" or ch.isprintable() for ch in summary)


def test_the_benign_layout_is_unchanged():
    summary = format_github_step_summary(_doc())
    assert "| `no-eval` | `aegis_core/bad.py:14:1` | error | `Forbidden eval() call` |" in summary
    assert "Unanchored repository-level gate failure" in summary
    assert "- `pkg/a.py`: uncovered lines 3-4" in summary


def _unverified(reason: str) -> dict:
    return {"passed": True, "layer1": [], "findings": [], "coverage": {"status": "unverified", "reason": reason}}


@pytest.mark.parametrize("value", sorted(HOSTILE.values()) + ["![beacon](x) <img src=x> [approved](y)"],
                         ids=sorted(HOSTILE) + ["beacon-img-link"])
def test_the_coverage_unverified_reason_renders_as_data(value):
    """The reason can be pytest stderr; public summaries show only a fixed category."""
    summary = format_github_step_summary(_unverified(value))
    assert _outside_spans(summary) == _outside_spans(format_github_step_summary(_unverified(HARMLESS)))
    assert all(ch == "\n" or ch.isprintable() for ch in summary)
    assert "### Diff Coverage: UNVERIFIED (`other`)" in format_github_step_summary(_unverified(HARMLESS))


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("raw_verdict", [False, True])
def test_strict_missing_driver_is_explained_without_rewriting_evidence(strict, raw_verdict):
    import json

    from aegis_cli.formatters.report import (
        format_layer1_json_payload, format_sarif_report, github_annotation_lines, layer1_report_document,
    )
    from aegis_core.verification import ToolEvidence
    from aegis_core.verification.ast_checks import NO_DRIVER_NOTE_TOOL
    from aegis_core.verification.runner import format_summary, gate_verdict

    evidence = ToolEvidence(NO_DRIVER_NOTE_TOOL, "src/app.kt", raw_verdict, "no_driver:.kt", language="unknown")
    passed = gate_verdict([evidence], strict=strict)
    assert passed is (raw_verdict and not strict)
    summary = format_summary([evidence], strict=strict)
    document = layer1_report_document(passed, [("src/app.kt", evidence)], [], strict,
                                      checkpoint_info=[{"check": "pairing", "message": "pairing note", "file": "test.kt"}])
    assert document["layer1"][0]["verdict"] is raw_verdict
    assert document["layer1"][0]["detail"] == "no_driver:.kt"
    assert format_layer1_json_payload(passed, ["src/app.kt"], [evidence], summary)["layer1"] == document["layer1"]
    markdown = format_github_step_summary(document)
    annotations = "\n".join(github_annotation_lines(document))
    run = json.loads(format_sarif_report(document))["runs"][0]
    assert run["results"] == []
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert {"level": "note", "message": {"text": "pairing note"}} in notifications
    if strict and raw_verdict:
        assert "strict" in markdown.lower() and "no-driver" in markdown
        assert "No findings reported" not in markdown
        assert "::error title=" in annotations and "strict" in annotations.lower()
        assert any(n["level"] == "error" and "strict" in n["message"]["text"].lower() for n in notifications)
    elif raw_verdict:
        assert "PASSED" in markdown and "::error" not in annotations
        assert not any(n["level"] == "error" for n in notifications)


def test_strict_cli_exports_name_the_cause_and_keep_sarif_unanchored(tmp_path, capsys):
    import json

    from aegis_cli.cli import main
    from tests.unit.core.test_no_driver_m1 import _rule

    _rule(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.kt").write_text("danger()", encoding="utf-8")
    args = ["check", "--workspace", str(tmp_path), "src/app.kt", "--strict"]
    assert main([*args, "--format", "github"]) == 1
    annotations = capsys.readouterr().out
    assert "::error" in annotations and "strict" in annotations.lower() and "no-driver" in annotations
    assert main([*args, "--format", "sarif"]) == 1
    run = json.loads(capsys.readouterr().out)["runs"][0]
    assert run["results"] == []
    assert any("strict" in n["message"]["text"].lower()
               for n in run["invocations"][0]["toolExecutionNotifications"])
