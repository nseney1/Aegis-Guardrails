"""Recorded-check diagnostics through the CLI, with snapshot execution stubbed."""
from __future__ import annotations

import copy
import json

import pytest

from aegis_cli.cli import main
from aegis_core import checkrun, testexec


def test_record_language_hint_set_matches_testplans():
    from aegis_cli import check
    from aegis_core import testplans

    assert check._RECORD_TEST_LANGUAGES == frozenset(testplans._DEADLINES)


def _tests(**updates):
    return {**testexec.TestsRun(exit=0, collected=12, passed=12).as_dict(), **updates}


def _language(language="ts", **updates):
    return {**_tests(), "language": language, "evidence": False,
            "reason": "tests_runner_not_configured", "detail": "TS/JS requires a user-scoped runner", **updates}


def _row(tests=None, **updates):
    return {"tree": "a" * 40, "passed": False, "protected_changed": False,
            "layer1": {"findings": 0, "files": 1, "evidence": []}, "tests": tests, **updates}


def _run(row, tmp_path, monkeypatch, capsys, *flags):
    before = copy.deepcopy(row)
    monkeypatch.setattr(checkrun, "record", lambda *a, **kw: checkrun.CheckOutcome("recorded", row))
    code = main(["check", "--record", "--workspace", str(tmp_path), *flags])
    output = capsys.readouterr()
    assert row == before  # Rendering must preserve the receipt used by JSON/ledger consumers.
    assert output.err == ""
    return code, output.out


def test_mixed_receipt_names_unavailable_language_and_its_configuration(tmp_path, monkeypatch, capsys):
    row = _row(_tests(languages=[_language("python", evidence=True, reason="ok"), _language()]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert "FAILED, tests 12 passed, 0 failed" in output
    assert "tests[ts]: tests_runner_not_configured" in output
    assert "TS/JS requires a user-scoped runner" in output
    assert "~/.aegis/config.json: tests.languages.ts.command" in output
    assert "tests[python]" not in output


@pytest.mark.parametrize("updates,reason", [
    ({"timed_out": True, "exit": 124}, "timeout"),
    ({"complete": False}, "incomplete_report"),
    ({"failed": 1, "exit": 1}, "failed_tests"),
    ({"passed": 0, "collected": 0, "exit": 5}, "no_tests_passed"),
    ({"passed": 0, "collected": 3, "skipped": 3}, "no_tests_passed"),
    ({"exit": 2}, "nonzero_exit"),
])
def test_global_runner_explains_missing_evidence(tmp_path, monkeypatch, capsys, updates, reason):
    code, output = _run(_row(_tests(**updates)), tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert f"tests: {reason}" in output
    assert "config:" not in output


@pytest.mark.parametrize("language", ["go", "rust", "ts"])
def test_native_timeout_names_language_timeout_setting(tmp_path, monkeypatch, capsys, language):
    row = _row(_tests(languages=[_language(language, reason="timeout", detail="", timed_out=True, exit=124)]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert f"tests[{language}]: timeout" in output
    assert f"~/.aegis/config.json: tests.languages.{language}.timeout_s" in output
    assert f"tests.languages.{language}.command" not in output


def test_layer_one_failure_names_tool_target_and_unavailable_evidence(tmp_path, monkeypatch, capsys):
    row = _row(layer1={"findings": 1, "files": 2, "evidence": [
        {"tool": "forbid_ast:no-eval", "target": "src/app.py", "verdict": False, "language": "python"},
        {"tool": "forbid_ast_no_driver", "target": "src/app.go", "verdict": True,
         "language": "go", "reason": "no_driver:.go"},
    ]})
    code, output = _run(row, tmp_path, monkeypatch, capsys)
    assert code == 1
    assert "Layer 1: 1 finding(s)" in output
    assert "forbid_ast:no-eval" in output and "src/app.py" in output
    assert "no_driver:.go" in output and "src/app.go" in output
    assert ".aegis/config.json: ast.packaged_drivers" in output


def test_bounded_diagnostics_count_omitted_components(tmp_path, monkeypatch, capsys):
    findings = [{"tool": f"forbid_ast:rule-{i}", "target": "src/app.py", "verdict": False} for i in range(30)]
    row = _row(_tests(languages=[_language()]), layer1={"findings": 30, "evidence": findings})
    code, output = _run(row, tmp_path, monkeypatch, capsys)
    assert code == 1
    assert "tests[ts]" in output
    assert "23 failing diagnostic(s) omitted" in output
    assert len(output.splitlines()) <= 12


def test_control_heavy_diagnostics_have_bounded_single_line_output(tmp_path, monkeypatch, capsys):
    row = _row(_tests(languages=[_language(detail="\x1b[31mBAD\n\t" + "\x1b]" * 1000)]))
    code, output = _run(row, tmp_path, monkeypatch, capsys)
    assert code == 1
    assert "\x1b" not in output and "\t" not in output
    assert "BAD" in output
    assert max(map(len, output.splitlines())) <= 400


@pytest.mark.parametrize("tests", [None, _tests(), _tests(languages=[_language(evidence=True, reason="ok")])])
def test_success_remains_one_line(tmp_path, monkeypatch, capsys, tests):
    code, output = _run(_row(tests, passed=True), tmp_path, monkeypatch, capsys)
    detail = ", Layer 1 only" if tests is None else ", tests 12 passed, 0 failed"
    assert code == 0
    assert output == f"recorded: tree aaaaaaaaaaaa passed{detail}\n"


def test_json_keeps_original_receipt_without_text_diagnostics(tmp_path, monkeypatch, capsys):
    row = _row(_tests(languages=[_language()]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests", "--json")
    assert code == 1
    document = json.loads(output)
    assert document["check"] == row
    assert document["reason"] == ""
    assert set(document) == {"source", "aegis_version", "checked_at", "scope", "status", "witness",
                             "reason", "check", "tree"}


def test_check_help_describes_language_selection_and_coverage(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["check", "--help"])
    assert exc.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "automatically selected languages" in text
    assert "tests.command takes precedence" in text
    assert "coverage.languages.ts.command" in text
    assert "coverage.languages.rust.command" in text
    assert "Go defaults" in text
    assert "See docs/languages.md" in text
    assert "[language setup]" not in text
    assert "native runners: user-scope tests.languages.{go,rust,ts}.command (required for TS/JS)" in text
    assert "never the repository's" in text


@pytest.mark.parametrize("field", ["detail", "reason", "language", "tool", "target"])
def test_free_text_fields_redact_credentials(tmp_path, monkeypatch, capsys, field):
    credential = "ghp_" + "A" * 36  # Synthetic pattern, never a real credential.
    if field in ("tool", "target"):
        component = {"tool": "forbid_ast:rule", "target": "src/app.go", "verdict": False,
                     field: "metadata: " + credential}
        row = _row(layer1={"findings": 1, "evidence": [component]})
    else:
        component = _language("go")
        component[field] = "metadata: " + credential
        row = _row(_tests(languages=[component]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert credential not in output
    assert "A" * 10 not in output
    assert "[REDACTED_VCS_TOKEN]" in output


def test_redaction_precedes_display_truncation(tmp_path, monkeypatch, capsys):
    credential = "ghp_" + "A" * 200
    detail = "metadata " * 16 + credential
    code, output = _run(_row(_tests(languages=[_language("go", detail=detail)])),
                        tmp_path, monkeypatch, capsys)
    assert code == 1
    assert "ghp_" not in output and "A" * 10 not in output


def test_terminal_escape_removal_cannot_reveal_a_credential(tmp_path, monkeypatch, capsys):
    detail = "metadata ghp_\x1b[31m" + "A" * 36
    code, output = _run(_row(_tests(languages=[_language("go", detail=detail)])),
                        tmp_path, monkeypatch, capsys)
    assert code == 1
    assert "ghp_" not in output and "A" * 10 not in output and "\x1b" not in output


def test_findings_precede_advisories_and_omissions_keep_their_severity(tmp_path, monkeypatch, capsys):
    notes = [{"tool": "forbid_ast_no_driver", "target": f"src/{i}.go", "verdict": True,
              "reason": "no_driver:.go"} for i in range(10)]
    finding = {"tool": "forbid_ast:no-eval", "target": "z.py", "verdict": False}
    row = _row(layer1={"findings": 1, "evidence": [*notes, finding]})
    code, output = _run(row, tmp_path, monkeypatch, capsys)
    assert code == 1
    assert output.index("forbid_ast:no-eval") < output.index("forbid_ast_no_driver")
    assert "3 advisory diagnostic(s) omitted" in output
    assert "failing diagnostic(s) omitted" not in output


def test_omitted_findings_and_advisories_are_counted_separately(tmp_path, monkeypatch, capsys):
    findings = [{"tool": "forbid_ast:rule", "target": "app.py", "verdict": False} for _ in range(10)]
    notes = [{"tool": "ast_unverified", "target": "big.ts", "verdict": True,
              "reason": "too_large"} for _ in range(3)]
    row = _row(layer1={"findings": 10, "evidence": [*notes, *findings]})
    code, output = _run(row, tmp_path, monkeypatch, capsys)
    assert code == 1
    assert "2 failing diagnostic(s) omitted" in output
    assert "3 advisory diagnostic(s) omitted" in output
    assert len(output.splitlines()) <= 12


@pytest.mark.parametrize("language", ["python", "go", "rust", "ts"])
@pytest.mark.parametrize("updates,recorded,expected", [
    ({"passed": 0, "collected": 3, "skipped": 3}, "failed_tests", "no_tests_passed"),
    ({"exit": 2}, "failed_tests", "nonzero_exit"),
    ({"exit": 1}, "no_tests_passed", "nonzero_exit"),
    ({"exit": 1}, "ok", "nonzero_exit"),
    ({"exit": 1}, "", "nonzero_exit"),
])
def test_language_fallback_reasons_use_evidence_fields(tmp_path, monkeypatch, capsys,
                                                     language, updates, recorded, expected):
    row = _row(_tests(languages=[_language(language, reason=recorded, detail="", **updates)]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert f"tests[{language}]: {expected}" in output
    assert "config:" not in output  # No configurable global/Python snapshot timeout setting exists.


def test_python_timeout_without_a_report_uses_evidence_fields(tmp_path, monkeypatch, capsys):
    row = _row(_tests(languages=[_language("python", reason="incomplete_report", detail="",
                                          timed_out=True, complete=False, exit=124)]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert "tests[python]: timeout" in output
    assert "config:" not in output


@pytest.mark.parametrize("reason,updates", [
    ("failed_tests", {"failed": 1, "exit": 1}),
    ("nonzero_exit", {"exit": 1}),
    ("tests_inline_with_source", {}),
    ("test_ids_unmapped", {}),
])
def test_execution_failures_do_not_suggest_reconfiguring_the_runner(tmp_path, monkeypatch, capsys, reason, updates):
    code, output = _run(_row(_tests(languages=[_language("rust", reason=reason, detail="", **updates)])),
                        tmp_path, monkeypatch, capsys)
    assert code == 1
    assert f"tests[rust]: {reason}" in output
    assert "config:" not in output


@pytest.mark.parametrize("extension,expected", [
    (".go", ".aegis/config.json: ast.packaged_drivers"),
    (".rb", "~/.aegis/config.json: drivers.rb"),
    (".kt", "~/.aegis/config.json: drivers.kt"),
])
def test_driver_hints_select_the_configuration_scope(tmp_path, monkeypatch, capsys, extension, expected):
    row = _row(layer1={"findings": 1, "evidence": [
        {"tool": "forbid_ast:rule", "target": "app.py", "verdict": False},
        {"tool": "forbid_ast_no_driver", "target": "app" + extension,
         "verdict": True, "reason": "no_driver:" + extension},
    ]})
    code, output = _run(row, tmp_path, monkeypatch, capsys)
    assert code == 1
    assert expected in output
    if extension == ".go":
        assert "config: ~/.aegis/config.json" not in output
    else:
        assert "ast.packaged_drivers" not in output


@pytest.mark.parametrize("field", ["detail", "reason", "language", "tool", "target"])
@pytest.mark.parametrize("scenario", ["split_token", "escape_boundary", "display_boundary", "long_input"])
def test_canonical_text_is_redacted_before_any_cut(tmp_path, monkeypatch, capsys, field, scenario):
    if scenario == "split_token":
        text = "metadata ghp_" + "A" * 20 + "\x1b[31m" + "B" * 16
    elif scenario == "escape_boundary":
        text = "\x1b[31m" * 315 + " ghp_\x1b[31m" + "A" * 36
    else:
        limits = {"detail": 160, "reason": 120 if field in ("tool", "target") else 80,
                  "language": 40, "tool": 120, "target": 120}
        text = "x " * ((limits[field] - 8) // 2) + "ghp_" + "A" * 36
        if scenario == "long_input":
            text += " trailing" * 1000
    if field in ("tool", "target"):
        row = _row(layer1={"findings": 1, "evidence": [
            {"tool": "forbid_ast:rule", "target": "src/app.go", "verdict": False, field: text}]})
    else:
        component = _language("go")
        component[field] = text
        row = _row(_tests(languages=[component]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert "ghp_" not in output
    assert "A" * 10 not in output and "B" * 10 not in output
    assert "\x1b" not in output
    assert max(map(len, output.splitlines())) <= 400


@pytest.mark.parametrize("language", ["go", "rust", "ts"])
@pytest.mark.parametrize("key", ["tests.languages", "language", "timeout_s", "command"])
def test_invalid_settings_do_not_hint_an_unrelated_command(tmp_path, monkeypatch, capsys, language, key):
    prefix = f"tests.languages.{language}"
    key = "tests.languages" if key == "tests.languages" else prefix if key == "language" else f"{prefix}.{key}"
    detail = f"tests_runner_not_configured: invalid {key}"
    row = _row(_tests(languages=[_language(language, detail=detail)]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert detail in output
    assert f"; config: ~/.aegis/config.json: {prefix}.command" not in output or key.endswith(".command")


@pytest.mark.parametrize("language", ["go", "rust", "ts"])
@pytest.mark.parametrize("marker", ["detail", "incomplete_errors"])
def test_aggregate_deadline_does_not_hint_a_language_timeout(tmp_path, monkeypatch, capsys, language, marker):
    updates = {"detail": "timeout: selection deadline exceeded"} if marker == "detail" else {
        "detail": "", "incomplete_errors": ["deadline_exceeded"]}
    component = _language(language, reason="timeout", timed_out=True, complete=False, exit=124, **updates)
    code, output = _run(_row(_tests(languages=[component])), tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert f"tests[{language}]: timeout" in output
    assert "config:" not in output


def test_missing_runner_hint_requires_evidence_that_a_runner_is_missing(tmp_path, monkeypatch, capsys):
    row = _row(_tests(languages=[_language("go", detail="unrecognized runner configuration failure")]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert "tests[go]: tests_runner_not_configured" in output
    assert "config:" not in output


def test_repository_identifiers_survive_redaction(tmp_path, monkeypatch, capsys):
    tool = "test_parse_config_with_utf8_bom"
    target = "tests/unit/core/test_v3_zero_legacy_invariants.py"
    row = _row(layer1={"findings": 1, "evidence": [{"tool": tool, "target": target, "verdict": False}]})
    code, output = _run(row, tmp_path, monkeypatch, capsys)
    assert code == 1
    assert tool in output and target in output


@pytest.mark.parametrize("field", ["tool", "target"])
@pytest.mark.parametrize("text,secret", [
    ("https://user:synthetic-password@example.test", "synthetic-password"),
    ("password=synthetic-password", "synthetic-password"),
    ("-----BEGIN PRIVATE KEY-----synthetic-key-----END PRIVATE KEY-----", "synthetic-key"),
])
def test_repository_identifiers_still_redact_known_secrets(tmp_path, monkeypatch, capsys, field, text, secret):
    component = {"tool": "forbid_ast:rule", "target": "src/app.go", "verdict": False, field: text}
    code, output = _run(_row(layer1={"findings": 1, "evidence": [component]}), tmp_path, monkeypatch, capsys)
    assert code == 1
    assert secret not in output
    assert "REDACTED" in output


@pytest.mark.parametrize("field", ["tool", "target", "language", "reason", "detail"])
def test_oversized_fields_never_reach_the_sanitizer(tmp_path, monkeypatch, capsys, field):
    import aegis_cli

    sanitize = aegis_cli.sanitize_display
    observed = []

    def bounded(value, max_len=80):
        # Fail before invoking the quadratic implementation on a large value, even in RED.
        assert len(value) <= 8 * 1024
        observed.append(len(value))
        return sanitize(value, max_len)

    monkeypatch.setattr(aegis_cli, "sanitize_display", bounded)
    text = "\x1b]" * (160 * 1024)
    if field in ("tool", "target"):
        component = {"tool": "forbid_ast:rule", "target": "src/app.go", "verdict": False, field: text}
        row = _row(layer1={"findings": 1, "evidence": [component]})
    else:
        component = _language("go")
        component[field] = text
        row = _row(_tests(languages=[component]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1 and observed
    assert "[diagnostic omitted: too_large]" in output
    assert "\x1b" not in output
    assert max(map(len, output.splitlines())) <= 400


@pytest.mark.parametrize("field", ["tool", "target", "language", "reason", "detail"])
def test_raw_field_cap_cannot_expose_a_control_obfuscated_partial_token(tmp_path, monkeypatch, capsys, field):
    cap = 8 * 1024
    escape = "\x1b[31m"
    prefix = escape * ((cap - 20) // len(escape))
    text = prefix + " ghp_" + "A" * 36
    assert len(text) > cap
    assert 0 < cap - len(prefix) - len(" ghp_") < 20
    if field in ("tool", "target"):
        component = {"tool": "forbid_ast:rule", "target": "src/app.go", "verdict": False, field: text}
        row = _row(layer1={"findings": 1, "evidence": [component]})
    else:
        component = _language("go")
        component[field] = text
        row = _row(_tests(languages=[component]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert "[diagnostic omitted: too_large]" in output
    assert "ghp_" not in output and "A" * 10 not in output


@pytest.mark.parametrize("language", ["go", "rust", "ts"])
@pytest.mark.parametrize("detail", [
    "timeout: metadata deadline exceeded",
    "timeout: metadata command timed out",
    "timeout: other selection diagnostic",
])
def test_timeout_details_do_not_hint_a_language_deadline(tmp_path, monkeypatch, capsys, language, detail):
    row = _row(_tests(languages=[_language(language, reason="timeout", detail=detail, timed_out=True, exit=124)]))
    code, output = _run(row, tmp_path, monkeypatch, capsys, "--tests")
    assert code == 1
    assert f"tests[{language}]: timeout; {detail}" in output
    assert "config:" not in output
