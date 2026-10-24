"""File and archive JSONL readers have identical content semantics."""
import gzip

import pytest

from aegis_core import migrate, storage


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize("data,errors,rows,numbers,skipped,torn", [
    (b'{"a":1}\n', "strict", [{"a": 1}], [1], [], False),
    (b'{"a":1}\n{', "strict", [{"a": 1}], [1], [], True),
    (b'{"a":1}\nno\n{"b":2}\n', "strict", [{"a": 1}, {"b": 2}], [1, 3], [2], False),
    (b'\xef\xbb\xbf{"a":1}\n', "strict", [{"a": 1}], [1], [], False),
    (b'{"a":1}\r\n\r\n', "strict", [{"a": 1}], [1], [], False),
    (b'{"a":"\xed\xa0\x80"}\n', "strict", [], [], [1], False),
    (b'{"a":"\xed\xa0\x80"}\n', "surrogatepass", [{"a": "\ud800"}], [1], [], False),
], ids=["clean", "torn", "skipped", "bom", "crlf", "bad-utf8", "surrogate"])
def test_one_parser_for_bytes_files_and_archives(tmp_path, data, errors, rows, numbers, skipped, torn):
    path = tmp_path / "rows.jsonl"
    path.write_bytes(data)
    parsed = storage.parse_jsonl(data, errors)
    assert (parsed.rows, parsed.line_numbers, parsed.skipped_lines, parsed.torn_tail) == (rows, numbers, skipped, torn)
    assert storage.read_jsonl(path, errors) == parsed
    if errors == "surrogatepass" or b"\xed" not in data:
        archive = tmp_path / "rows.gz"
        archive.write_bytes(gzip.compress(data))
        assert migrate._read_archive(archive)[1] == parsed


def test_contains_filter_keeps_original_line_numbers_and_tail(tmp_path):
    data = b'{"other":1}\nbad\n{"wanted":2}\nwanted{'
    path = tmp_path / "rows.jsonl"
    path.write_bytes(data)
    parsed = storage.parse_jsonl(data, contains=b"wanted")
    assert (parsed.rows, parsed.line_numbers, parsed.skipped_lines, parsed.torn_tail) == ([{"wanted": 2}], [3], [], True)
    assert storage.read_jsonl(path, contains=b"wanted") == parsed
    assert storage.parse_jsonl(data, contains=b"absent") == storage.JsonlRead([], [], [])
