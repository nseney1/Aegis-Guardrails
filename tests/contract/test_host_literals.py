"""Falls-only ceilings for host-home text and the system interpreter path.

Count case-sensitive spellings in every product file, including prompt templates,
comments and docstrings. Identifier neighbors are excluded by ASCII boundaries.
The two host registries own host-home spelling; interpreter paths have no exemption.
No Git history or platform-specific filesystem capabilities are required.

    python3 tests/contract/test_host_literals.py --write
"""
import codecs
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("host_literal_counts.json")
HOST_LITERALS = ("CLAUDE_CONFIG_DIR", "CODEX_HOME", ".claude", ".codex")
INTERPRETER = "/usr/bin/python3"
LITERALS = (*HOST_LITERALS, INTERPRETER)
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "tools")
REGISTRIES = frozenset({"tools/hierarchy_hosts.py", "aegis_core/hosts.py"})
# No binary assets exist in the scanned product directories today.
BINARY_SUFFIXES = frozenset()
PATTERNS = {
    literal: re.compile(r"(?<![A-Za-z0-9_])" + re.escape(literal) + r"(?![A-Za-z0-9_])")
    for literal in LITERALS
}


@pytest.mark.parametrize("literal", LITERALS)
def test_raised_count_names_file_literal_and_both_counts(tmp_path, literal):
    path = tmp_path / "aegis_cli" / "sample.py"
    path.parent.mkdir()
    path.write_text(repr(literal) + "\n" + repr(literal) + "\n", encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), {"aegis_cli/sample.py": {literal: 1}}) == [
        f"aegis_cli/sample.py: {literal}: 1 -> 2"
    ]


@pytest.mark.parametrize("remaining", [0, 1, 2])
def test_lowered_equal_and_removed_files_pass_without_updating_record(tmp_path, remaining):
    path = tmp_path / "tools" / "sample.py"
    path.parent.mkdir()
    if remaining:
        path.write_text('"CODEX_HOME"\n' * remaining, encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), {"tools/sample.py": {"CODEX_HOME": 2}}) == []


@pytest.mark.parametrize("relative", ["aegis_core/new.py", "aegis_cli/new.py", "aegis_mcp/new.py", "tools/new.py", "tools/hierarchy_templates/new.json"])
def test_new_product_file_with_literals_fails(tmp_path, relative):
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(INTERPRETER), encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), {}) == [f"{relative}: {INTERPRETER}: 0 -> 1"]


@pytest.mark.parametrize("relative", ["tests/sample.py", "docs/sample.py", "tools/docs/sample.py", "tools/tests/sample.py", "tools/docs/README.md", "aegis_sdk/sample.py", "tools/__pycache__/sample.py"])
def test_tests_docs_and_other_packages_are_out_of_scope(tmp_path, relative):
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text(" ".join(LITERALS), encoding="utf-8")
    assert measure_literals(tmp_path) == {}


@pytest.mark.parametrize("package", PACKAGES)
@pytest.mark.parametrize("filename", ["docs", "tests", "__pycache__"])
def test_directory_exclusion_names_are_scanned_when_they_are_files(tmp_path, package, filename):
    relative = f"{package}/{filename}"
    path = tmp_path / relative
    path.parent.mkdir()
    path.write_bytes(b"#!/usr/bin/python3\n")
    record = tmp_path / "tests" / "contract" / "host_literal_counts.json"
    record.parent.mkdir(parents=True)
    record.write_text("{}\n", encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), {}) == [f"{relative}: {INTERPRETER}: 0 -> 1"]
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (
        1, "", f"refusing to raise host literal records: {relative}: {INTERPRETER}: 0 -> 1\n"
    )
    assert record.read_text(encoding="utf-8") == "{}\n"


@pytest.mark.parametrize("relative", sorted(REGISTRIES))
def test_only_host_literals_are_exempt_in_registries(tmp_path, relative):
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text(repr(" ".join(HOST_LITERALS)), encoding="utf-8")
    assert measure_literals(tmp_path) == {}
    path.write_text(repr(" ".join(LITERALS)), encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), {}) == [f"{relative}: {INTERPRETER}: 0 -> 1"]


def test_counts_cannot_move_between_files_or_literals(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "first.py").write_text('"CODEX_HOME"', encoding="utf-8")
    (package / "second.py").write_text('".claude"', encoding="utf-8")
    record = {"aegis_core/first.py": {".claude": 1}, "aegis_core/second.py": {"CODEX_HOME": 1}}
    assert literal_errors(measure_literals(tmp_path), record) == [
        "aegis_core/first.py: CODEX_HOME: 0 -> 1",
        "aegis_core/second.py: .claude: 0 -> 1",
    ]


def test_source_occurrences_include_comments_and_repeats(tmp_path):
    package = tmp_path / "aegis_mcp"
    package.mkdir()
    (package / "sample.py").write_text('# CODEX_HOME\n".codex .codex"\n', encoding="utf-8")
    counts = measure_literals(tmp_path)["aegis_mcp/sample.py"]
    assert counts == {"CLAUDE_CONFIG_DIR": 0, "CODEX_HOME": 1, ".claude": 0, ".codex": 2, INTERPRETER: 0}


@pytest.mark.parametrize("relative", [
    "tools/probe", "tools/probe.py", "tools/probe.pyw", "tools/hierarchy_templates/roles/x.md",
    "tools/probe.sh", "tools/probe.ps1", "tools/settings.toml", "tools/settings.yaml",
])
def test_every_product_file_format_is_decoded_with_surrogateescape(tmp_path, relative):
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(b"#!/usr/bin/python3\n# \xff\n")
    assert literal_errors(measure_literals(tmp_path), {}) == [f"{relative}: {INTERPRETER}: 0 -> 1"]


@pytest.mark.parametrize("bom,encoding", [
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be"),
])
def test_bom_selected_product_text_counts_and_writer_refuses_new_literal(tmp_path, bom, encoding):
    path = tmp_path / "tools" / "x.ps1"
    path.parent.mkdir()
    path.write_bytes(bom + "$env:USERPROFILE\\.claude\n".encode(encoding))
    record = tmp_path / "tests" / "contract" / "host_literal_counts.json"
    record.parent.mkdir(parents=True)
    record.write_text("{}\n", encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), {}) == ["tools/x.ps1: .claude: 0 -> 1"]
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (
        1, "", "refusing to raise host literal records: tools/x.ps1: .claude: 0 -> 1\n"
    )
    assert record.read_text(encoding="utf-8") == "{}\n"


@pytest.mark.parametrize("contents", [
    "$env:USERPROFILE\\.claude".encode("utf-16-le"),
    "$env:USERPROFILE\\.claude".encode("utf-16-be"),
    "$env:USERPROFILE\\.claude".encode("utf-32-le"),
    "$env:USERPROFILE\\.claude".encode("utf-32-be"),
    b"#!/usr/bin/python3\x00", b"\x00",
    codecs.BOM_UTF8 + b"\xff",
    codecs.BOM_UTF16_LE + b"x", codecs.BOM_UTF16_BE + b"x",
    codecs.BOM_UTF32_LE + b"x", codecs.BOM_UTF32_BE + b"x",
    codecs.BOM_UTF8 + b"# a\n" + "$env:USERPROFILE\\.claude".encode("utf-16-le"),
    codecs.BOM_UTF16_LE + "$env:USERPROFILE\\.claude".encode("utf-32-le"),
])
def test_unreadable_product_text_is_named_and_writer_preserves_record(tmp_path, contents):
    path = tmp_path / "tools" / "x.ps1"
    path.parent.mkdir()
    path.write_bytes(contents)
    record = tmp_path / "tests" / "contract" / "host_literal_counts.json"
    record.parent.mkdir(parents=True)
    record.write_text("{}\n", encoding="utf-8")
    message = "unreadable product text: tools/x.ps1"
    with pytest.raises(ValueError, match="^" + re.escape(message) + "$"):
        measure_literals(tmp_path)
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (1, "", message + "\n")
    assert record.read_text(encoding="utf-8") == "{}\n"


@pytest.mark.parametrize("text", [
    "info.claude", "self.codex", "https://code.claude.com/x", "aegis.claude-root-schema",
])
def test_attributes_urls_and_schema_ids_are_not_host_literals(tmp_path, text):
    path = tmp_path / "tools" / "probe.py"
    path.parent.mkdir()
    path.write_text(text, encoding="utf-8")
    assert measure_literals(tmp_path) == {}


@pytest.mark.parametrize("text,literal", [
    ('"~/.claude/x"', ".claude"), ('".codex"', ".codex"),
    ("$env:USERPROFILE\\.claude", ".claude"),
])
def test_delimited_host_paths_still_count(tmp_path, text, literal):
    path = tmp_path / "tools" / "probe.py"
    path.parent.mkdir()
    path.write_text(text, encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), {}) == [f"tools/probe.py: {literal}: 0 -> 1"]


def test_registry_calls_and_identifier_prefixes_are_not_host_spellings(tmp_path):
    path = tmp_path / "tools" / "probe.py"
    path.parent.mkdir()
    path.write_text("hierarchy_hosts.claude_init(x)\nargs.codex_home\n", encoding="utf-8")
    assert measure_literals(tmp_path) == {}
    path.write_text('\"~/.claude/x\"\n\".codex\"\n', encoding="utf-8")
    counts = measure_literals(tmp_path)["tools/probe.py"]
    assert counts == {"CLAUDE_CONFIG_DIR": 0, "CODEX_HOME": 0, ".claude": 1, ".codex": 1, INTERPRETER: 0}


@pytest.mark.parametrize("literal", LITERALS)
def test_identifier_suffixes_and_word_prefixes_do_not_count(tmp_path, literal):
    path = tmp_path / "tools" / "probe.py"
    path.parent.mkdir()
    for adjacent in ("a", "Z", "0", "_"):
        path.write_text(literal + adjacent, encoding="utf-8")
        assert measure_literals(tmp_path) == {}
        path.write_text(adjacent + literal, encoding="utf-8")
        assert measure_literals(tmp_path) == {}


def _run_writer(root, *arguments):
    script = root / "tests" / "contract" / "test_host_literals.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_bytes(Path(__file__).read_bytes())
    return subprocess.run([sys.executable, str(script), *arguments], cwd=root,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)


@pytest.mark.parametrize("remaining", [0, 1])
def test_write_lowers_removed_counts_and_readdition_is_refused(tmp_path, remaining):
    path = tmp_path / "tools" / "probe.py"
    path.parent.mkdir()
    path.write_text('\"CODEX_HOME\"\n' * 2, encoding="utf-8")
    record = tmp_path / "tests" / "contract" / "host_literal_counts.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps(measure_literals(tmp_path)), encoding="utf-8")
    if remaining:
        path.write_text('\"CODEX_HOME\"\n', encoding="utf-8")
    else:
        path.unlink()
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (0, "", "")
    lowered = json.loads(record.read_text(encoding="utf-8"))
    assert lowered["tools/probe.py"]["CODEX_HOME"] == remaining
    assert literal_errors(measure_literals(tmp_path), lowered) == []
    path.write_text('\"CODEX_HOME\"\n' * 2, encoding="utf-8")
    assert literal_errors(measure_literals(tmp_path), lowered) == [
        f"tools/probe.py: CODEX_HOME: {remaining} -> 2"
    ]
    before = record.read_bytes()
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (
        1, "", f"refusing to raise host literal records: tools/probe.py: CODEX_HOME: {remaining} -> 2\n"
    )
    assert record.read_bytes() == before


def test_write_refuses_a_new_positive_record(tmp_path):
    path = tmp_path / "tools" / "probe"
    path.parent.mkdir()
    path.write_bytes(b"#!/usr/bin/python3\n")
    record = tmp_path / "tests" / "contract" / "host_literal_counts.json"
    record.parent.mkdir(parents=True)
    record.write_text("{}\n", encoding="utf-8")
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (
        1, "", "refusing to raise host literal records: tools/probe: /usr/bin/python3: 0 -> 1\n"
    )
    assert record.read_text(encoding="utf-8") == "{}\n"


def test_writer_requires_the_write_flag(tmp_path):
    done = _run_writer(tmp_path, "--unknown")
    assert (done.returncode, done.stdout, done.stderr) == (
        1, "", "usage: python3 tests/contract/test_host_literals.py --write\n"
    )


@pytest.mark.parametrize("contents", [None, b"{", b"\xff"])
def test_writer_refuses_missing_or_unreadable_records(tmp_path, contents):
    record = tmp_path / "tests" / "contract" / "host_literal_counts.json"
    record.parent.mkdir(parents=True)
    if contents is not None:
        record.write_bytes(contents)
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (
        1, "", "cannot read host literal inputs\n"
    )


@pytest.mark.parametrize("value", [
    [], None, {"tools/x": 1}, {"tools/x": {"CODEX_HOME": -1}},
    {"tools/x": {"CODEX_HOME": True}}, {"tools/x": {"CODEX_HOME": "1"}},
    {"tools/x": {"unknown": 1}},
])
def test_writer_refuses_invalid_record_shapes_without_changing_bytes(tmp_path, value):
    record = tmp_path / "tests" / "contract" / "host_literal_counts.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps(value), encoding="utf-8")
    before = record.read_bytes()
    done = _run_writer(tmp_path, "--write")
    assert (done.returncode, done.stdout, done.stderr) == (1, "", "invalid host literal record\n")
    assert record.read_bytes() == before


def test_product_literals_never_exceed_their_per_file_records():
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    assert literal_errors(measure_literals(REPO), record) == []


def _product_text(path, root):
    raw = path.read_bytes()
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = "utf-32"
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    elif raw.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    else:
        encoding = "utf-8"
    try:
        source = raw.decode(encoding, errors="surrogateescape" if encoding == "utf-8" else "strict")
    except UnicodeDecodeError:
        raise ValueError(f"unreadable product text: {path.relative_to(root).as_posix()}") from None
    if "\x00" in source:
        raise ValueError(f"unreadable product text: {path.relative_to(root).as_posix()}")
    return source


def measure_literals(root):
    counts = {}
    for package in PACKAGES:
        for path in sorted((root / package).rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if any(part in {"tests", "docs", "__pycache__"} for part in path.relative_to(root).parts[:-1]):
                continue
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
            source = _product_text(path, root)
            row = {literal: sum(1 for _ in pattern.finditer(source)) for literal, pattern in PATTERNS.items()}
            if rel in REGISTRIES:
                row.update(dict.fromkeys(HOST_LITERALS, 0))
            if any(row.values()):
                counts[rel] = row
    return counts


def literal_errors(current, record):
    return [f"{rel}: {literal}: {record.get(rel, {}).get(literal, 0)} -> {count}"
            for rel, counts in sorted(current.items()) for literal, count in counts.items()
            if count > record.get(rel, {}).get(literal, 0)]


def lowered_counts(record, current):
    errors = literal_errors(current, record)
    if errors:
        raise ValueError("refusing to raise host literal records: " + "; ".join(errors))
    # Keep zero ceilings for removed files and literals, so re-addition cannot regrow.
    return {rel: {literal: current.get(rel, {}).get(literal, 0) for literal in counts}
            for rel, counts in record.items()}


def write_record():
    try:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        current = measure_literals(REPO)
    except (OSError, UnicodeError, json.JSONDecodeError):
        sys.exit("cannot read host literal inputs")
    except ValueError as exc:
        sys.exit(str(exc))
    if not isinstance(record, dict) or any(
        not isinstance(counts, dict) or any(
            literal not in LITERALS or type(count) is not int or count < 0
            for literal, count in counts.items()
        ) for counts in record.values()
    ):
        sys.exit("invalid host literal record")
    try:
        updated = lowered_counts(record, current)
    except ValueError as exc:
        sys.exit(str(exc))
    try:
        RECORD.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        sys.exit("cannot write host literal record")


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: python3 tests/contract/test_host_literals.py --write")
    write_record()
