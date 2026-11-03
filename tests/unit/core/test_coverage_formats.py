"""Coverage readers through their public text-only interfaces."""
from dataclasses import FrozenInstanceError

import pytest

from aegis_core.verification.coverage_formats import (
    CoverageFormatError, LineCoverage, parse_go_coverprofile, parse_lcov,
)


def test_lcov_counts_lines_unions_duplicate_records_and_preserves_raw_paths():
    report = (
        "TN:first\r\nSF:C:\\project:copy\\app.ts\r\n"
        "DA:2,0\r\nDA:3,4,opaque-checksum\r\nDA:3,0\r\nLF:2\r\nLH:1\r\nend_of_record\r\n"
        "TN:second\nSF:C:\\project:copy\\app.ts\nDA:2,1\nend_of_record\n"
        "SF:../raw file:other.ts\nDA:8,0\nend_of_record\n"
    )

    assert parse_lcov(report) == {
        r"C:\project:copy\app.ts": LineCoverage(frozenset({2, 3}), frozenset({2, 3})),
        "../raw file:other.ts": LineCoverage(frozenset({8}), frozenset()),
    }


def test_lcov_ignores_valid_function_branch_and_version_records():
    report = (
        "SF:src/main.ts\nVER:revision-a\nFN:1,example\nFNDA:2,example\nFNF:1\nFNH:1\n"
        "BRDA:4,0,0,-\nBRDA:4,0,1,2\nBRF:2\nBRH:1\n"
        "DA:4,2\nLF:1\nLH:1\nend_of_record\n"
    )
    assert parse_lcov(report) == {"src/main.ts": LineCoverage(frozenset({4}), frozenset({4}))}
    assert parse_lcov("SF:empty.ts\nLF:0\nLH:0\nend_of_record\n") == {
        "empty.ts": LineCoverage(frozenset(), frozenset())}


@pytest.mark.parametrize("text,message", [
    ("", "LCOV report contains no source records"),
    ("TN:only\n", "LCOV report contains no source records"),
    ("DA:1,1\n", "LCOV line 1: DA outside a source record"),
    ("end_of_record\n", "LCOV line 1: end_of_record outside a source record"),
    ("SF:\n", "LCOV line 1: empty source path"),
    ("SF:a.ts\nDA:1,1\n", "LCOV source record is missing end_of_record"),
    ("SF:a.ts\nSF:b.ts\nend_of_record\n", "LCOV line 2: source record before end_of_record"),
    ("SF:a.ts\nTN:next\n", "LCOV line 2: test name before end_of_record"),
    ("SF:a.ts\nDA:1\nend_of_record\n", "LCOV line 2: malformed DA record"),
    ("SF:a.ts\nDA:1,0,\nend_of_record\n", "LCOV line 2: malformed DA record"),
    ("SF:a.ts\nDA:1,0,a,b\nend_of_record\n", "LCOV line 2: malformed DA record"),
    ("SF:a.ts\nDA:0,1\nend_of_record\n", "LCOV line 2: invalid line number"),
    ("SF:a.ts\nDA:1,-1\nend_of_record\n", "LCOV line 2: invalid hit count"),
    ("SF:a.ts\nDA:1,1.5\nend_of_record\n", "LCOV line 2: invalid hit count"),
    ("SF:a.ts\nDA:1,1\nLF:2\nend_of_record\n", "LCOV line 4: LF does not match DA records"),
    ("SF:a.ts\nDA:1,0\nLH:1\nend_of_record\n", "LCOV line 4: LH does not match DA records"),
    ("SF:a.ts\nLF:0\nLF:1\nend_of_record\n", "LCOV line 3: conflicting LF records"),
    ("SF:a.ts\nBRDA:1,0\nend_of_record\n", "LCOV line 2: malformed BRDA record"),
    ("SF:a.ts\nFN:bad,name\nend_of_record\n", "LCOV line 2: invalid function line"),
    ("SF:a.ts\nFNDA:1\nend_of_record\n", "LCOV line 2: malformed FNDA record"),
    ("SF:a.ts\nFNF:-1\nend_of_record\n", "LCOV line 2: invalid FNF count"),
    ("SF:a.ts\nUNKNOWN:data\nend_of_record\n", "LCOV line 2: unsupported record UNKNOWN"),
    ("SF:a.ts\nDA:1,1\nend_of_record\nDA:2,1\n", "LCOV line 4: DA outside a source record"),
])
def test_lcov_rejects_malformed_or_partial_reports(text, message):
    with pytest.raises(CoverageFormatError) as error:
        parse_lcov(text)
    assert str(error.value) == message
    assert isinstance(error.value, ValueError)


@pytest.mark.parametrize("mode", ["set", "count", "atomic"])
def test_go_coverprofile_uses_inclusive_spans_and_positive_hits(mode):
    report = (
        f"mode: {mode}\r\n"
        "example.test/project/pkg/main.go:2.3,4.7 2 0\r\n"
        "example.test/project/pkg/main.go:3.2,5.4 3 5\r\n"
        "example.test/project/pkg/main.go:2.3,4.7 2 1\r\n"
        "C:\\project:copy\\other.go:10.1,10.2 0 0\r\n"
        "path with spaces:name.go:8.1,8.3 1 1\r\n"
    )
    assert parse_go_coverprofile(report) == {
        "example.test/project/pkg/main.go": LineCoverage(frozenset({2, 3, 4, 5}), frozenset({2, 3, 4, 5})),
        r"C:\project:copy\other.go": LineCoverage(frozenset({10}), frozenset()),
        "path with spaces:name.go": LineCoverage(frozenset({8}), frozenset({8})),
    }
    assert parse_go_coverprofile(f"mode: {mode}\n") == {}


@pytest.mark.parametrize("text,message", [
    ("", "Go coverprofile is missing its mode header"),
    ("a.go:1.1,2.1 1 1\n", "Go coverprofile is missing its mode header"),
    ("mode: unknown\n", "Go line 1: unsupported mode unknown"),
    ("mode:\n", "Go coverprofile is missing its mode header"),
    ("mode: count\nmode: count\n", "Go line 2: duplicate mode header"),
    ("mode: count\na.go:1.1,2.1 1\n", "Go line 2: malformed coverage block"),
    ("mode: count\na.go 1 1\n", "Go line 2: malformed coverage location"),
    ("mode: count\n:1.1,2.1 1 1\n", "Go line 2: empty source path"),
    ("mode: count\na.go:1,2.1 1 1\n", "Go line 2: malformed coverage location"),
    ("mode: count\na.go:1.1,2.1,3.1 1 1\n", "Go line 2: malformed coverage location"),
    ("mode: count\na.go:0.1,2.1 1 1\n", "Go line 2: invalid start line"),
    ("mode: count\na.go:1.0,2.1 1 1\n", "Go line 2: invalid start column"),
    ("mode: count\na.go:1.1,2.0 1 1\n", "Go line 2: invalid end column"),
    ("mode: count\na.go:3.1,2.1 1 1\n", "Go line 2: invalid coverage range"),
    ("mode: count\na.go:2.4,2.3 1 1\n", "Go line 2: invalid coverage range"),
    ("mode: count\na.go:2.3,2.3 1 1\n", "Go line 2: invalid coverage range"),
    ("mode: count\na.go:1.1,2.1 -1 1\n", "Go line 2: invalid statement count"),
    ("mode: count\na.go:1.1,2.1 1 -1\n", "Go line 2: invalid hit count"),
    ("mode: count\na.go:1.1,2.1 1 1x\n", "Go line 2: invalid hit count"),
    ("mode: count\na.go:1.1,2.1 1 9223372036854775808\n", "Go line 2: invalid hit count"),
    ("mode: count\na.go:1.1,1000001.1 1 1\n", "coverage report exceeds 1000000 expanded lines"),
    ("mode: count\na.go:1.1,2.1 1 1\na.go:1.1,1000000.1 1 1\n",
     "coverage report exceeds 1000000 expanded lines"),
])
def test_go_coverprofile_rejects_malformed_ranges_counts_and_truncation(text, message):
    with pytest.raises(CoverageFormatError) as error:
        parse_go_coverprofile(text)
    assert str(error.value) == message


@pytest.mark.parametrize("reader", [parse_lcov, parse_go_coverprofile])
def test_readers_reject_nontext_nul_invalid_unicode_and_oversized_input(reader):
    cases = [(None, "coverage report must be text"),
             ("\x00", "coverage report contains NUL"),
             ("\ud800", "coverage report is not valid Unicode"),
             ("a" * (8 * 1024 * 1024 + 1), "coverage report exceeds 8 MiB"),
             ("😀" * (2 * 1024 * 1024 + 1), "coverage report exceeds 8 MiB")]
    for value, message in cases:
        with pytest.raises(CoverageFormatError) as error:
            reader(value)
        assert str(error.value) == message


def test_results_are_immutable_and_parsers_do_not_touch_paths(monkeypatch):
    def forbidden_open(*args, **kwargs):
        raise AssertionError("a coverage parser accessed a path")

    monkeypatch.setattr("builtins.open", forbidden_open)
    report = parse_lcov("SF:/untrusted/missing.ts\nDA:1,0\nend_of_record\n")
    row = report["/untrusted/missing.ts"]
    with pytest.raises(FrozenInstanceError):
        row.covered = frozenset({1})
    assert row.executable == frozenset({1}) and not row.covered
    assert parse_go_coverprofile("mode: count\n../untrusted.go:1.1,1.2 1 1\n") == {
        "../untrusted.go": LineCoverage(frozenset({1}), frozenset({1}))}


def test_decimal_zero_padding_does_not_change_counts_or_ranges():
    zeroes = "0" * 80
    assert parse_lcov(f"SF:a.ts\nDA:{zeroes}1,{zeroes}0\nend_of_record\n") == {
        "a.ts": LineCoverage(frozenset({1}), frozenset())}
    assert parse_go_coverprofile(
        f"mode: count\na.go:{zeroes}1.{zeroes}1,{zeroes}2.{zeroes}1 {zeroes}0 {zeroes}1\n"
    ) == {"a.go": LineCoverage(frozenset({1, 2}), frozenset({1, 2}))}
