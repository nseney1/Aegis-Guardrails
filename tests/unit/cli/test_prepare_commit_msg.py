"""The prepare-commit-msg hook adds ``Aegis-Check`` only for a passing check of exactly the staged tree.

These run a real ``git commit`` in a temporary repository with the hook installed there.
"""
from __future__ import annotations

from functools import lru_cache
from itertools import product
import os
import stat
import io
import json
import re
import shlex
import sys

import pytest

from aegis_cli.hooks import commitmsg
from aegis_core import checkrun, credit
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

HOOK = commitmsg.HOOK_NAME
needs_git = pytest.mark.skipif(not hg.git_ok() or os.name == "nt", reason="needs git and a POSIX shell")


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))


def _project(tmp_path, runner=hv.PASSING):
    repo = hv.make_project(tmp_path, runner=runner)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    assert commitmsg.install(repo.root / ".git" / "hooks") == "installed"
    return repo


def _commit(repo, message="work"):
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", message)
    return repo.git("log", "-1", "--format=%B").strip()


@needs_git
def test_a_passing_check_of_the_staged_tree_adds_the_trailer(tmp_path):
    repo = _project(tmp_path)
    row = checkrun.record(repo.root, tests=True, base="main").row
    body = _commit(repo)
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0"
    assert credit.parse_trailer(body.splitlines()[-1]) == {"tree": row["tree"], "exit": 0}
    assert repo.git("rev-parse", "HEAD^{tree}") == row["tree"]


@needs_git
def test_no_check_row_means_no_trailer(tmp_path):
    assert "Aegis-Check" not in _commit(_project(tmp_path))


@needs_git
@pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")
def test_installed_hook_keeps_insight_approval_message_verifiable(tmp_path):
    from aegis_core import human_gate

    repo = _project(tmp_path)
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo.write("allowed_signers", hg.allowed_signers_text(pub))
    base = repo.commit("trust owner")
    row = checkrun.record(repo.root, tests=True, base="main").row
    assert commitmsg.trailer_for_staged(repo.root) == credit.format_trailer(row["tree"], 0)
    text = "Reviewed insight"
    message = "chore: approve insight\n\nAegis-Approve-Insight: " + human_gate.insight_text_hash(text) + "\n"
    repo.home.sign_with(str(key))
    repo.git("commit", "-q", "-S", "-s", "--allow-empty", "-m", message)
    approval = repo.head()
    body = repo.git("log", "-1", "--format=%B")
    assert "Aegis-Check:" not in body and "Signed-off-by:" in body
    assert human_gate.verify_insight_approval(repo.root, approval, text, base).valid


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("platform", ["posix", "nt"])
@pytest.mark.parametrize("original, authority", [
    (b"work\n", False),
    (b"caf\xe9\n", False),
    (b"approve\n\nAegis-Approve: " + b"b" * 64 + b"\n", True),
    (b"caf\xe9\n\nAegis-Approve-Insight: " + b"b" * 64 + b"\n", True),
    (b"chore: pasted\n\n" + b"x" * 9000 + b"\n", False),
    (b"chore: pasted\n\n" + b"x" * 9000 + b"\n\nAegis-Approve: " + b"b" * 64 + b"\n", True),
    (b"work\n" + ("Я" * 6899 + "\n").encode("cp1251") * 4, False),
    (b"work\n" + ("Я" * 6899 + "\n").encode("cp1251") * 4 + b"\nAegis-Approve: " + b"b" * 64 + b"\n", True),
], ids=["plain", "latin1", "authority", "latin1-authority", "long-line", "long-line-authority", "cp1251", "cp1251-authority"])
def test_hook_uses_the_portable_helper_and_preserves_authority_bytes(
        tmp_path, monkeypatch, platform, original, authority):
    from types import SimpleNamespace
    from aegis_core import gitsafe

    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(original)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "os", SimpleNamespace(**{**vars(os), "name": platform}))
    line = "Aegis-Check: tree=" + "b" * 40 + " exit=0"
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: line)
    calls = []
    add_trailer = gitsafe.add_trailer

    def recorded_add_trailer(path, trailer):
        calls.append((path, trailer))
        return add_trailer(path, trailer)

    monkeypatch.setattr(gitsafe, "add_trailer", recorded_add_trailer)
    assert commitmsg.main([str(message)]) == 0
    if authority:
        assert message.read_bytes() == original and calls == []
    else:
        assert message.read_bytes().startswith(original)
        assert message.read_bytes().splitlines()[-1] == line.encode("ascii")
        assert calls == [(str(message), line)]


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("name", ["Aegis-Approve", "Aegis-Approve-Insight", "Aegis-Exempt-Test", "Aegis-Manager-Approve"])
def test_hook_checks_the_row_then_preserves_each_authority(tmp_path, monkeypatch, capsys, name):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = "approve\n\n" + name + ": " + "b" * 64 + "\n"
    message.write_text(original, encoding="utf-8")
    calls = []
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: calls.append(root) or "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert calls == [repo.root] and message.read_text(encoding="utf-8") == original
    assert capsys.readouterr().err == ""


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("kind", ["missing", "oversized"])
def test_hook_missing_or_oversized_message_stays_unchanged(tmp_path, monkeypatch, capsys, kind):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = b"x" * 65537
    if kind == "missing":
        message.unlink()
    else:
        message.write_bytes(original)
    calls = []
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: calls.append(root) or "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert calls == [repo.root]
    assert message.read_bytes() == original if kind == "oversized" else not message.exists()
    reason = "message too large" if kind == "oversized" else "unreadable"
    assert capsys.readouterr().err == f"aegis prepare-commit-msg: Aegis-Check not added ({reason})\n"


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("phase", ["candidate", "below-cut"])
def test_hook_closes_a_failed_bounded_read_without_echoing_input(tmp_path, monkeypatch, capsys, phase):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = b"work\n" if phase == "candidate" else b"work\n\n" + CUT_LINE + b"\n"
    message.write_bytes(original)
    opened, counts = [], []

    class FailedRead:
        def __enter__(self):
            self.stream = open(message, "rb")
            opened.append(self.stream)
            return self

        def readline(self, count):
            counts.append(count)
            if phase == "below-cut":
                return self.stream.readline(count)
            raise OSError("private untrusted detail")

        def read(self, count):
            counts.append(count)
            raise OSError("private untrusted detail")

        def __exit__(self, *_args):
            self.stream.close()

    monkeypatch.setattr(commitmsg, "open", lambda *_args: FailedRead(), raising=False)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert counts and all(0 < count <= commitmsg.MAX_MESSAGE_SCAN_BYTES for count in counts)
    if phase == "below-cut":
        assert counts[-1] == commitmsg.MAX_MESSAGE_SCAN_BYTES - len(original)
    else:
        assert max(counts) <= 4096
    assert all(stream.closed for stream in opened)
    assert message.read_bytes() == original
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (unreadable)\n"


CUT_LINE = b"# ------------------------ >8 ------------------------"
AUTHORITY_NAMES = ("Aegis-Approve", "Aegis-Approve-Insight", "Aegis-Exempt-Test", "Aegis-Manager-Approve")
AUTHORITY_NOTICE = "aegis prepare-commit-msg: Aegis-Check not added (authority below cut)\n"


@lru_cache(maxsize=1)
def _unicode_case_equivalents():
    """Compute every non-ASCII re.I equivalent of letters used in the names."""
    letters = sorted({char.lower() for name in AUTHORITY_NAMES for char in name if char.isalpha()})
    any_letter = re.compile("[" + "".join(letters) + "]", re.I)
    # The class prefilter searches every non-ASCII code point once. The individual
    # fullmatches below assign each result using the verifiers' engine semantics.
    folded = [chr(point) for point in range(128, sys.maxunicode + 1) if any_letter.fullmatch(chr(point))]
    return {letter: tuple(char for char in folded if re.fullmatch(letter, char, re.I)) for letter in letters}


def _authority_spellings(name):
    equivalents = _unicode_case_equivalents()
    for case, spelling in (("exact", name), ("lower", name.lower()), ("mixed", name.swapcase())):
        yield case, spelling
        positions = [(index, equivalents[char.lower()]) for index, char in enumerate(spelling)
                     if equivalents.get(char.lower())]
        for index, alternatives in positions:
            for char in alternatives:
                yield f"{case}-position-{index}-U+{ord(char):04X}", spelling[:index] + char + spelling[index + 1:]
        for replacements in product(*(alternatives for _, alternatives in positions)):
            chars = list(spelling)
            for (index, _), char in zip(positions, replacements):
                chars[index] = char
            codepoints = "-".join(f"U+{ord(char):04X}" for char in replacements)
            yield f"{case}-all-{codepoints}", "".join(chars)


def _authority_value(name):
    return "b" * 40 + " reason" if name == "Aegis-Exempt-Test" else "b" * 64


def _authority_variants():
    for name in AUTHORITY_NAMES:
        for case, spelling in _authority_spellings(name):
            indents = [("column-zero", "")]
            if name != "Aegis-Manager-Approve":
                indents += [("space-indent", " "), ("tab-indent", "\t"), ("mixed-indent", " \t")]
            for indent_id, indent in indents:
                for pad_id, padding in (("no-pad", ""), ("space", " "), ("tab", "\t"),
                                        ("mixed-pad", " \t"), ("4096-spaces", " " * 4096),
                                        ("4096-tabs", "\t" * 4096)):
                    yield (f"{name}-{case}-{indent_id}-{pad_id}", name,
                           (indent + spelling + padding + ": " + _authority_value(name) + "\n").encode("utf-8"))


def _authority_verifiers():
    from aegis_core import human_gate, manager_config

    return dict(zip(AUTHORITY_NAMES, (human_gate._APPROVE_LINE, human_gate._APPROVE_INSIGHT_LINE,
                                     human_gate._EXEMPT_TEST_LINE, manager_config._OWNER_LINE)))


def _assert_no_mixed_authority(body):
    authority = any(pattern.search(body) is not None for pattern in _authority_verifiers().values())
    assert not (authority and "Aegis-Check:" in body)


def test_below_cut_predicate_covers_the_verifiers_authority_syntax():
    patterns = _authority_verifiers()
    accepted = set()
    for case_id, name, line in _authority_variants():
        if patterns[name].search(line.decode("utf-8", "surrogateescape")) is not None:
            accepted.add(name)
            with io.BytesIO(b"work\n\n" + CUT_LINE + b"\n" + line) as stream:
                assert commitmsg._candidate_message(stream) == (b"work\n\n", None, True), case_id
    assert accepted == set(AUTHORITY_NAMES)


@pytest.mark.parametrize("line", ["aegis-approve: X", " \tAeGiS-aPpRoVe: X",
                                  "Aegis-Approve-Insight \t: X", "\taegis-exempt-test: " + "b" * 40 + " reason",
                                  "Aegis-Manager-Approve: " + "b" * 64],
                         ids=["lower", "indented-mixed", "padded", "indented-exempt", "manager"])
def test_mixed_authority_oracle_checks_the_full_body(line):
    with pytest.raises(AssertionError):
        _assert_no_mixed_authority("work\n\n" + CUT_LINE.decode("ascii") + "\n" + line + "\nAegis-Check: tree=X exit=0\n")


@pytest.mark.parametrize("name,spelling", [pytest.param(name, spelling, id=name + "-" + case_id)
                                         for name in AUTHORITY_NAMES
                                         for case_id, spelling in _authority_spellings(name)])
def test_mixed_authority_oracle_uses_the_verifiers_for_computed_spellings(name, spelling):
    body = "work\n\n" + CUT_LINE.decode("ascii") + "\n" + spelling + ": " + _authority_value(name) + "\n"
    assert "Aegis-Check:" not in body
    if _authority_verifiers()[name].search(body) is not None:
        with pytest.raises(AssertionError):
            _assert_no_mixed_authority(body + "Aegis-Check: tree=X exit=0\n")
    else:
        _assert_no_mixed_authority(body + "Aegis-Check: tree=X exit=0\n")


def test_candidate_refuses_every_authority_variant_below_the_cut():
    patterns = _authority_verifiers()
    for case_id, name, authority in _authority_variants():
        original = b"work\n\n" + CUT_LINE + b"\n+\xffdiff\n" + authority
        with io.BytesIO(original) as stream:
            candidate, refusal, detected = commitmsg._candidate_message(stream)
        verifier_accepts = patterns[name].search(authority.decode("utf-8", "surrogateescape")) is not None
        assert not verifier_accepts or detected, case_id
        assert (candidate, refusal, detected) == (b"work\n\n", None, True), case_id


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("name", AUTHORITY_NAMES)
def test_hook_notices_each_authority_name_below_the_cut(tmp_path, monkeypatch, capsys, name):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    authority = (name + ": " + _authority_value(name) + "\n").encode("utf-8")
    original = b"work\n\n" + CUT_LINE + b"\n+\xffdiff\n" + authority
    message.write_bytes(original)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == original
    _assert_no_mixed_authority(message.read_bytes().decode("utf-8", "surrogateescape"))
    assert capsys.readouterr().err == AUTHORITY_NOTICE


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("kind", ["status", "long-comment", "cut-diff", "diff-authority", "authority"])
def test_hook_judges_only_the_candidate_message(tmp_path, monkeypatch, capsys, kind):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    if kind == "status":
        repo.git("config", "core.commentChar", "#")
        status = b"#\tstaged path\n" * 10000
        assert len(status) > 65536
        original = status + b"work\n\n"
    elif kind == "long-comment":
        original = b"#" + b"x" * 90000 + b"\nwork\n"
    else:
        original = b"work\n\n" + CUT_LINE + b"\n"
        original += (b"  Aegis-Approve: X\n" if kind == "diff-authority" else
                     b"Aegis-Approve: X\n" if kind == "authority" else b"+diff\n" * 20000)
    message.write_bytes(original)
    if kind not in ("diff-authority", "authority"):
        assert len(original) > 65536
    monkeypatch.chdir(repo.root)
    line = "Aegis-Check: tree=" + "a" * 40 + " exit=0"
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: line)
    assert commitmsg.main([str(message)]) == 0
    result = message.read_bytes()
    if kind in ("diff-authority", "authority"):
        assert result == original
    else:
        assert line.encode("ascii") in result.split(CUT_LINE)[0]
    _assert_no_mixed_authority(result.decode("ascii"))
    assert capsys.readouterr().err == (AUTHORITY_NOTICE if kind in ("diff-authority", "authority") else "")


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_hook_authority_above_the_cut_is_byte_identical_and_silent(tmp_path, monkeypatch, capsys):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = b"approve\n\nAegis-Approve: " + b"a" * 64 + b"\n" + CUT_LINE + b"\n" + b"+diff\n" * 20000
    message.write_bytes(original)
    calls = []
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: calls.append(root) or "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == original and calls == [repo.root]
    assert capsys.readouterr().err == ""


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("value", [";", "auto", "##", " #", "#\n"])
def test_hook_unsupported_comment_character_has_one_fixed_notice(tmp_path, monkeypatch, capsys, value):
    repo = hg.make_repo(tmp_path)
    repo.git("config", "core.commentChar", value)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = b"work\n"
    message.write_bytes(original)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == original
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_hook_comment_config_error_has_one_fixed_notice(tmp_path, monkeypatch, capsys, failure):
    from aegis_core import gitsafe
    from subprocess import CompletedProcess

    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(b"work\n")
    run = gitsafe.run

    def config_error(args, *a, **kw):
        if args[0] == "config":
            if failure == "timeout":
                raise gitsafe.GitError("private config detail")
            return CompletedProcess(args, 128, b"", b"private config detail")
        return run(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", config_error)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == b"work\n"
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_hook_scan_cap_stops_reads_and_closes_the_stream(tmp_path, monkeypatch, capsys):
    repo = hg.make_repo(tmp_path)
    limit = getattr(commitmsg, "MAX_MESSAGE_SCAN_BYTES", 4 * 1024 * 1024)
    assert limit >= 4 * 1024 * 1024
    sizes, positions = [], []

    class CountedStream(io.BytesIO):
        def readline(self, count=-1):
            sizes.append(count)
            result = super().readline(count)
            positions.append(self.tell())
            return result

        def read(self, count=-1):
            sizes.append(count)
            result = super().read(count)
            positions.append(self.tell())
            return result

    stream = CountedStream(b"#" + b"x" * (limit + 100) + b"\nwork\n")
    monkeypatch.setattr(commitmsg, "open", lambda *_args: stream, raising=False)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(repo.root / ".git" / "COMMIT_EDITMSG")]) == 0
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (scan limit)\n"
    assert sizes and all(0 < size <= 4096 for size in sizes)
    assert positions[-1] == limit and max(positions) <= limit and stream.closed


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_hook_scans_only_for_authority_after_the_cut_line(tmp_path, monkeypatch, capsys):
    from aegis_core import gitsafe

    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    prefix = b"work\n\n" + CUT_LINE + b"\n"
    original = prefix + b"  Aegis-Manager-Approve: X\n" + b"+diff\n" * 20000
    message.write_bytes(original)
    positions = []

    class CountedStream(io.BytesIO):
        def readline(self, count=-1):
            result = super().readline(count)
            positions.append(self.tell())
            return result

        def read(self, count=-1):
            result = super().read(count)
            positions.append(self.tell())
            return result

    stream = CountedStream(original)
    monkeypatch.setattr(commitmsg, "open", lambda *_args: stream, raising=False)
    monkeypatch.chdir(repo.root)
    line = "Aegis-Check: tree=" + "a" * 40 + " exit=0"
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: line)
    calls = []
    # Real publication is covered by the commit tests below.
    monkeypatch.setattr(gitsafe, "add_trailer", lambda path, trailer: calls.append((path, trailer)) or True)
    assert commitmsg.main([str(message)]) == 0
    assert calls == [(str(message), line)]
    assert positions[-1] == len(original) and max(positions) <= len(original) and stream.closed
    assert capsys.readouterr().err == ""


@needs_git
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
@pytest.mark.parametrize("source", ["file", "template"])
@pytest.mark.parametrize("authority", [False, True], ids=["ordinary", "authority"])
def test_real_git_cut_line_requires_a_proven_marker(tmp_path, ending, source, authority):
    repo = _project(tmp_path)
    repo.git("add", "-A")
    row = checkrun.record(repo.root, tests=True, base="main").row
    assert commitmsg.trailer_for_staged(repo.root) == credit.format_trailer(row["tree"], 0)
    message = tmp_path / "message"
    below = b"Aegis-Approve: X\n" if authority else b"text below the cut\n"
    message.write_bytes(b"work\n\n" + CUT_LINE + ending + below)
    # Verbatim keeps the literal CRLF intact until the hook reads a -F message.
    args = (["-F", str(message), "--cleanup=verbatim"] if source == "file"
            else ["-t", str(message), "--cleanup=scissors"])
    # A template must gain message text, not just comments, for Git to accept it.
    editor, seen = tmp_path / "editor.py", tmp_path / "editor-seen"
    editor.write_text("import sys\nfrom pathlib import Path\n"
                      f"Path({str(seen)!r}).write_bytes(Path(sys.argv[1]).read_bytes())\n"
                      "p = Path(sys.argv[1])\np.write_bytes(b'edited work\\n\\n' + p.read_bytes())\n",
                      encoding="utf-8")
    result = hg.run_git(repo.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-q", *args,
                        env={**repo.home.env, "GIT_EDITOR": shlex.quote(sys.executable) + " " + shlex.quote(str(editor))},
                        check=False)
    assert result.returncode == 0, result.stderr
    body = repo.git("log", "-1", "--format=%B")
    _assert_no_mixed_authority(body)
    if ending == b"\r\n":
        assert "Aegis-Check:" not in body
        if source == "template":
            assert b"Aegis-Check:" not in seen.read_bytes()
        assert result.stderr == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"
        if source == "file" and authority:
            assert "Aegis-Approve: X" in body
    else:
        assert result.stderr == (AUTHORITY_NOTICE if authority else "")
        if authority:
            assert "Aegis-Check:" not in body
        else:
            assert credit.format_trailer(row["tree"], 0) in body
        if source == "template":
            if authority:
                assert b"Aegis-Check:" not in seen.read_bytes()
            else:
                assert credit.format_trailer(row["tree"], 0).encode("ascii") in seen.read_bytes().split(CUT_LINE)[0]
            assert "Aegis-Approve:" not in body


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("ending", [b"\r\n", b"\r", b"", b" \n", b"\t\n", b" \r\n", b"\r\r\n",
                                    b" " * 4200 + b"\n", b" " * (4096 - len(CUT_LINE))],
                         ids=["CRLF", "CR-EOF", "EOF", "space", "tab", "space-CRLF", "CR-CRLF",
                              "split-padding", "full-fragment-EOF"])
def test_hook_refuses_unproved_hash_cut_lines_without_changing_bytes(tmp_path, monkeypatch, capsys, ending):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = b"work\n\n" + CUT_LINE + ending
    if ending == b"\r\n":
        original += b"Aegis-Approve: X\n"
    message.write_bytes(original)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == original
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"


@needs_git
@pytest.mark.parametrize("source", ["file", "message", "template"])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
@pytest.mark.parametrize("name", AUTHORITY_NAMES)
def test_real_default_cleanup_keeps_authority_without_check(tmp_path, source, ending, name):
    repo = _project(tmp_path)
    repo.git("add", "-A")
    row = checkrun.record(repo.root, tests=True, base="main").row
    assert commitmsg.trailer_for_staged(repo.root) == credit.format_trailer(row["tree"], 0)
    raw = b"work\n\n" + CUT_LINE + ending + name.encode("ascii") + b": X\n"
    message = tmp_path / "message"
    message.write_bytes(raw)
    args = (["-F", str(message)] if source == "file" else ["-m", raw.decode("ascii")]
            if source == "message" else ["-t", str(message)])
    editor = tmp_path / "editor.py"
    editor.write_text("import sys\nfrom pathlib import Path\np=Path(sys.argv[1])\n"
                      "p.write_bytes(b'edited work\\n\\n' + p.read_bytes())\n", encoding="utf-8")
    repo.git("commit", "-q", *args,
             env={"GIT_EDITOR": shlex.quote(sys.executable) + " " + shlex.quote(str(editor))})
    body = repo.git("log", "-1", "--format=%B")
    assert name + ": X" in body
    assert "Aegis-Check:" not in body
    _assert_no_mixed_authority(body)


@needs_git
@pytest.mark.parametrize("source", ["file", "message", "template"])
@pytest.mark.parametrize("name,style", [(name, style) for name in AUTHORITY_NAMES
                                       for style in ("indented", "4096-padded")
                                       if name != "Aegis-Manager-Approve" or style != "indented"])
def test_real_default_cleanup_keeps_indented_or_padded_authority_without_check(tmp_path, source, name, style):
    repo = _project(tmp_path)
    repo.git("add", "-A")
    row = checkrun.record(repo.root, tests=True, base="main").row
    assert commitmsg.trailer_for_staged(repo.root) == credit.format_trailer(row["tree"], 0)
    line = (" \t" if style == "indented" else "") + name.swapcase()
    line += (" " * 4096 if style == "4096-padded" else "") + ": "
    line += "b" * 40 + " reason" if name == "Aegis-Exempt-Test" else "b" * 64
    raw = "work\n\n" + CUT_LINE.decode("ascii") + "\n" + line + "\n"
    message = tmp_path / "message"
    message.write_bytes(raw.encode("ascii"))
    args = (["-F", str(message)] if source == "file" else ["-m", raw]
            if source == "message" else ["-t", str(message)])
    editor = tmp_path / "editor.py"
    editor.write_text("import sys\nfrom pathlib import Path\np = Path(sys.argv[1])\n"
                      "p.write_bytes(b'edited work\\n\\n' + p.read_bytes())\n", encoding="utf-8")
    result = hg.run_git(repo.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-q", *args,
                        env={**repo.home.env, "GIT_EDITOR": shlex.quote(sys.executable) + " " + shlex.quote(str(editor))},
                        check=False)
    assert result.returncode == 0, result.stderr
    body = repo.git("log", "-1", "--format=%B")
    assert line in body and "Aegis-Check:" not in body
    _assert_no_mixed_authority(body)
    assert result.stderr == AUTHORITY_NOTICE


@needs_git
def test_real_default_file_cleanup_keeps_unicode_authority_without_check(tmp_path):
    repo = _project(tmp_path)
    repo.git("add", "-A")
    row = checkrun.record(repo.root, tests=True, base="main").row
    assert commitmsg.trailer_for_staged(repo.root) == credit.format_trailer(row["tree"], 0)
    authority = "  Aegiſ-Approve: " + "b" * 64
    message = tmp_path / "message"
    message.write_bytes(b"work\n\n" + CUT_LINE + b"\n" + authority.encode("utf-8") + b"\n")
    result = hg.run_git(repo.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-F", str(message),
                        env=repo.home.env, check=False)
    assert result.returncode == 0, result.stderr
    body = repo.git("log", "-1", "--format=%B")
    assert authority in body
    _assert_no_mixed_authority(body)
    assert "Aegis-Check:" not in body
    assert result.stderr == AUTHORITY_NOTICE


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("kind", ["authority", "exact-cap", "beyond-cap"])
def test_hook_bounds_the_authority_scan_after_the_cut(tmp_path, monkeypatch, capsys, kind):
    repo = hg.make_repo(tmp_path)
    limit = commitmsg.MAX_MESSAGE_SCAN_BYTES
    prefix = b"work\n\n" + CUT_LINE + b"\n"
    authority = b"Aegis-Approve: X\n"
    if kind == "authority":
        original = prefix + b"+diff\n" * 12000 + authority
    else:
        original = prefix + b"+" * (limit - len(prefix))
        if kind == "beyond-cap":
            original += b"\n" + authority
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(original)
    positions, sizes = [], []

    class CountedStream(io.BytesIO):
        def readline(self, count=-1):
            sizes.append(count)
            result = super().readline(count)
            positions.append(self.tell())
            return result

        def read(self, count=-1):
            sizes.append(count)
            result = super().read(count)
            positions.append(self.tell())
            return result

    stream = CountedStream(original)
    monkeypatch.setattr(commitmsg, "open", lambda *_args: stream, raising=False)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == original
    assert stream.closed and max(positions) <= limit and all(0 < size <= 4096 for size in sizes[:-1])
    assert sizes[-1] == limit - len(prefix)
    expected = AUTHORITY_NOTICE if kind == "authority" else "aegis prepare-commit-msg: Aegis-Check not added (scan limit)\n"
    assert capsys.readouterr().err == expected
    if kind != "authority":
        assert positions[-1] == limit


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_hook_does_not_mistake_a_line_fragment_for_column_zero_authority(tmp_path, monkeypatch, capsys):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    # The second read of this long line starts with an authority-like key.
    message.write_bytes(b"work\n\n" + CUT_LINE + b"\n" + b"+" * 4096 + b"Aegis-Approve: X\n")
    monkeypatch.chdir(repo.root)
    line = "Aegis-Check: tree=" + "a" * 40 + " exit=0"
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: line)
    assert commitmsg.main([str(message)]) == 0
    assert line.encode("ascii") in message.read_bytes().split(CUT_LINE)[0]
    assert capsys.readouterr().err == ""


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("failure", ["false", "error"])
def test_hook_publish_failure_has_one_fixed_notice(tmp_path, monkeypatch, capsys, failure):
    from aegis_core import gitsafe

    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(b"work\n")

    def refused(*_args):
        if failure == "error":
            raise gitsafe.GitError("private publication detail")
        return False

    monkeypatch.setattr(gitsafe, "add_trailer", refused)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == b"work\n"
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (unreadable)\n"


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("source", [None, "merge", "squash"])
def test_hook_without_a_passing_row_or_for_skipped_sources_is_silent(tmp_path, monkeypatch, capsys, source):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(b"work\n")
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: None)
    argv = [str(message)] + ([source] if source else [])
    assert commitmsg.main(argv) == 0
    assert message.read_bytes() == b"work\n"
    assert capsys.readouterr().err == ""


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("settings", [
    [("core.commentString", ";")],
    [("core.commentChar", "#"), ("core.commentString", "//")],
    [("core.commentString", "//"), ("core.commentChar", "#")],
    [("core.commentString", "#\ncore.commentchar #")],
    [("core.commentChar", "#\ncore.commentstring #")],
], ids=["string-only", "char-then-string", "string-then-char", "multiline-string", "multiline-char"])
def test_hook_requires_every_comment_key_to_be_hash(tmp_path, monkeypatch, capsys, settings):
    repo = hg.make_repo(tmp_path)
    for key, value in settings:
        repo.git("config", "--add", key, value)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = b"work\n"
    message.write_bytes(original)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == original
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_hook_accepts_only_hash_values_from_one_combined_query(tmp_path, monkeypatch, capsys):
    from aegis_core import gitsafe

    repo = hg.make_repo(tmp_path)
    for key in ("core.commentChar", "core.commentString", "core.commentChar"):
        repo.git("config", "--add", key, "#")
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(b"work\n")
    calls, run = [], gitsafe.run

    def counted(args, *a, **kw):
        if args[0] == "config":
            calls.append(tuple(args))
        return run(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", counted)
    monkeypatch.chdir(repo.root)
    line = "Aegis-Check: tree=" + "a" * 40 + " exit=0"
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: line)
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes().splitlines()[-1] == line.encode("ascii")
    assert len(calls) == 1 and "--get-regexp" in calls[0]
    assert r"^core\.comment(char|string)$" in calls[0]
    assert capsys.readouterr().err == ""


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("raw", [
    b"", b"core.commentchar\n#", b"core.commentchar #\0",
    b"core.commentstring\n#\ncore.commentchar #\0", b"core.commentchar\n#\0\0",
    b"core.commentchar\n#\0" * 4000, b"core.other\n#\0",
], ids=["empty", "unterminated", "no-key-separator", "multiline-value", "empty-record", "over-limit", "unexpected-key"])
def test_hook_refuses_malformed_or_oversized_comment_query_output(tmp_path, monkeypatch, capsys, raw):
    from aegis_core import gitsafe
    from subprocess import CompletedProcess

    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(b"work\n")
    run, calls = gitsafe.run, []

    def malformed(args, *a, **kw):
        if args[0] == "config":
            calls.append(tuple(args))
            return CompletedProcess(args, 0, raw, b"")
        return run(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", malformed)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == b"work\n" and len(calls) == 1
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("prefix", [b";", b"//", b"future", b"x" * 4090, b"x" * (4096 - len(CUT_LINE[1:]))],
                         ids=["semicolon", "slash", "future", "split-tail", "full-fragment"])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""], ids=["LF", "CRLF", "EOF"])
def test_hook_refuses_an_unproved_cut_marker(tmp_path, monkeypatch, capsys, prefix, ending):
    repo = hg.make_repo(tmp_path)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    original = b"work\n\n" + prefix + CUT_LINE[1:] + ending
    if ending:
        original += b"  Aegis-Manager-Approve: X\n"
    message.write_bytes(original)
    monkeypatch.chdir(repo.root)
    monkeypatch.setattr(commitmsg, "trailer_for_staged", lambda root: "Aegis-Check: tree=" + "a" * 40 + " exit=0")
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == original
    assert capsys.readouterr().err == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
@pytest.mark.parametrize("key, value", [("core.commentChar", ";"), ("core.commentString", "//"),
                                      ("core.commentString", "#")])
def test_hook_without_a_passing_row_never_reads_comment_config(tmp_path, monkeypatch, capsys, key, value):
    from aegis_core import gitsafe

    repo = hg.make_repo(tmp_path)
    repo.git("config", key, value)
    message = repo.root / ".git" / "COMMIT_EDITMSG"
    message.write_bytes(b"work\n")
    calls, run = [], gitsafe.run

    def counted(args, *a, **kw):
        if args[0] == "config":
            calls.append(tuple(args))
        return run(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", counted)
    monkeypatch.chdir(repo.root)
    assert commitmsg.main([str(message)]) == 0
    assert message.read_bytes() == b"work\n" and not calls
    assert capsys.readouterr().err == ""


@needs_git
def test_real_git_c_comment_string_reaches_the_hook_and_refuses_publication(tmp_path):
    repo = _project(tmp_path)
    repo.git("add", "-A")
    row = checkrun.record(repo.root, tests=True, base="main").row
    assert commitmsg.trailer_for_staged(repo.root) == credit.format_trailer(row["tree"], 0)
    editor = tmp_path / "editor.py"
    editor.write_text("import sys\nfrom pathlib import Path\np=Path(sys.argv[1])\n"
                      "p.write_bytes(b'ordinary work\\n\\n' + p.read_bytes())\n", encoding="utf-8")
    result = hg.run_git(repo.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "-c", "core.commentString=;", "commit", "-q", "-v",
                        env={**repo.home.env, "GIT_EDITOR": shlex.quote(sys.executable) + " " + shlex.quote(str(editor))},
                        check=False)
    assert result.returncode == 0, result.stderr
    assert result.stderr == "aegis prepare-commit-msg: Aegis-Check not added (comment character)\n"
    body = repo.git("log", "-1", "--format=%B")
    assert body.splitlines()[0] == "ordinary work" and "Aegis-Check:" not in body
    assert repo.git("rev-parse", "HEAD^{tree}") == row["tree"]


@needs_git
@pytest.mark.parametrize("name", AUTHORITY_NAMES)
def test_real_verbose_editor_commit_retains_the_trailer_before_a_large_diff(tmp_path, name):
    repo = _project(tmp_path)
    context = "before\n " + name + ": X\nstable\n"
    repo.write("docs/verbose.txt", context)
    repo.commit("base for verbose diff")
    repo.write("docs/verbose.txt", context + "new line " * 10 + "\n" + "x" * 80 + "\n")
    with (repo.root / "docs/verbose.txt").open("a", encoding="utf-8") as stream:
        stream.write(("new line " * 10 + "\n") * 1000)
    repo.git("add", "-A")
    assert len(repo.git("diff", "--cached").encode("utf-8")) > 65536
    row = checkrun.record(repo.root, tests=True, base="main").row
    seen, editor = tmp_path / "editor-seen.json", tmp_path / "editor.py"
    editor.write_text(
        "import json, sys\nfrom pathlib import Path\np = Path(sys.argv[1])\nraw = p.read_bytes()\n"
        f"Path({str(seen)!r}).write_text(json.dumps({{'bytes': len(raw), 'before_cut': "
        "b'Aegis-Check:' in raw.split(b'# ------------------------ >8 ------------------------')[0]}))\n"
        "p.write_bytes(b'work from editor\\n\\n' + raw)\n", encoding="utf-8")
    result = hg.run_git(repo.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-v",
                        env={**repo.home.env, "GIT_EDITOR": shlex.quote(sys.executable) + " " + shlex.quote(str(editor))},
                        check=False)
    assert result.returncode == 0, result.stderr
    observed = json.loads(seen.read_text(encoding="utf-8"))
    keep_check = name == "Aegis-Manager-Approve"
    assert observed["bytes"] > 65536 and observed["before_cut"] == keep_check
    body = repo.git("log", "-1", "--format=%B")
    assert body.splitlines()[0] == "work from editor"
    assert (f"Aegis-Check: tree={row['tree']} exit=0" in body) == keep_check
    assert name + ":" not in body
    assert result.stderr == ("" if keep_check else AUTHORITY_NOTICE)


@needs_git
def test_a_failing_check_adds_no_trailer(tmp_path):
    repo = _project(tmp_path, runner=hv.FAILING)
    checkrun.record(repo.root, tests=True, base="main")
    assert "Aegis-Check" not in _commit(repo)


@needs_git
def test_a_change_after_the_check_loses_the_trailer(tmp_path):
    repo = _project(tmp_path)
    checkrun.record(repo.root, tests=True, base="main")
    repo.write("src/app.py", "def app():\n    return 3\n")
    assert "Aegis-Check" not in _commit(repo)


@needs_git
def test_only_the_staged_tree_counts_not_the_work_tree(tmp_path):
    repo = _project(tmp_path)
    repo.write("extra.txt", "unstaged and untracked\n")
    checkrun.record(repo.root, tests=True, base="main")  # binds the whole work tree, extra.txt too
    repo.git("add", "src/app.py")
    repo.git("commit", "-q", "-m", "partial")  # the commit holds less than what was verified
    assert "Aegis-Check" not in repo.git("log", "-1", "--format=%B")


@needs_git
def test_an_amend_does_not_repeat_the_trailer(tmp_path):
    repo = _project(tmp_path)
    checkrun.record(repo.root, tests=True, base="main")
    _commit(repo)
    repo.git("commit", "-q", "--amend", "-m", "reworded")
    assert repo.git("log", "-1", "--format=%B").count("Aegis-Check") == 1


@needs_git
def test_a_broken_ledger_never_blocks_the_commit(tmp_path):
    repo = _project(tmp_path)
    checkrun.record(repo.root, tests=True, base="main")
    hv.ledger_path(repo.root).write_bytes(b"\xff not json\n")
    assert _commit(repo).startswith("work")


def _plant_trailer_program(repo, tmp_path, config):
    """Set the repository config ``config`` names, pointing at a program that records it ran."""
    marker, program = tmp_path / "trailer-ran", tmp_path / "trailer.sh"
    program.write_bytes(f'#!/bin/sh\necho ran >> "{marker}"\necho planted\n'.encode())
    program.chmod(0o755)
    for key in config:
        repo.git("config", "--local", key, "Aegis-Check" if key.endswith(".key") else str(program))
    return marker


@needs_git
@pytest.mark.parametrize("config", [
    pytest.param(("trailer.unrelated.command",), id="any-command"),
    pytest.param(("trailer.aegis-check.cmd",), id="alias-cmd"),
    pytest.param(("trailer.x.key", "trailer.x.cmd"), id="key-cmd"),
])
def test_the_hook_runs_no_trailer_program_the_repository_names(tmp_path, config):
    """Given a trailer command in the repository config and a passing check of the staged tree,
    When the hook adds the trailer, Then the program never runs and the trailer is Aegis's."""
    repo = _project(tmp_path)
    marker = _plant_trailer_program(repo, tmp_path, config)
    row = checkrun.record(repo.root, tests=True, base="main").row
    body = _commit(repo)
    assert not marker.exists(), "the hook ran a program the repository's config names"
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0"
    assert "planted" not in body


@needs_git
def test_in_a_linked_worktree_the_hook_runs_no_trailer_program_either(tmp_path):
    repo = _project(tmp_path)
    repo.git("commit", "-q", "-am", "start")
    marker = _plant_trailer_program(repo, tmp_path, ("trailer.x.key", "trailer.x.cmd", "trailer.unrelated.command"))
    linked = tmp_path / "linked"
    repo.git("worktree", "add", "-q", "-b", "side", str(linked))
    (linked / "src" / "app.py").write_bytes(b"def app():\n    return 4\n")
    row = checkrun.record(linked, tests=True, base="main").row
    hg.git(linked, "-c", "user.email=dev@example.com", "-c", "user.name=Dev", "add", "-A", env=repo.home.env)
    hg.git(linked, "-c", "user.email=dev@example.com", "-c", "user.name=Dev", "commit", "-q", "-m", "side work",
           env=repo.home.env)
    body = hg.git(linked, "log", "-1", "--format=%B", env=repo.home.env)
    assert not marker.exists()
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0" and "planted" not in body


@needs_git
def test_install_never_overwrites_a_hook_it_does_not_own(tmp_path):
    repo = hv.make_project(tmp_path)
    hooks = repo.root / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    mine = hooks / "prepare-commit-msg"
    mine.write_text("#!/bin/sh\necho mine\n")
    assert commitmsg.install(hooks) == "foreign"
    assert mine.read_text() == "#!/bin/sh\necho mine\n"
    mine.unlink()
    assert commitmsg.install(hooks) == "installed" and commitmsg.install(hooks) == "unchanged"
    assert mine.stat().st_mode & stat.S_IXUSR
    assert commitmsg.uninstall(hooks) == "removed" and not mine.exists()


@needs_git
def test_hook_install_and_uninstall_manage_the_trailer_hook_beside_pre_commit(tmp_path, capsys):
    from aegis_cli import cli

    repo = hv.make_project(tmp_path)
    hooks = repo.root / ".git" / "hooks"
    assert cli.main(["hook", "install", "--workspace", str(repo.root)]) == 0
    assert (hooks / "pre-commit").is_file() and (hooks / HOOK).is_file()
    assert cli.main(["hook", "uninstall", "--workspace", str(repo.root)]) == 0
    assert not (hooks / HOOK).exists()
    capsys.readouterr()


@needs_git
def test_init_installs_both_hooks_and_commit_of_checked_tree_gets_one_trailer(tmp_path, capsys):
    from aegis_cli import cli

    repo = hv.make_project(tmp_path, runner=hv.PASSING)
    hv.use_stub_runner(repo.home.path)
    hooks = repo.root / ".git" / "hooks"
    assert cli.main(["init", "--workspace", str(repo.root), "--yes", "--rules", "minimal"]) == 0
    capsys.readouterr()
    assert (hooks / "pre-commit").is_file() and (hooks / HOOK).is_file()

    repo.write("src/app.py", "def app():\n    return 2\n")
    row = checkrun.record(repo.root, tests=True, base="main").row
    body = _commit(repo)
    assert body.count("Aegis-Check:") == 1
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0"
    assert repo.git("rev-parse", "HEAD^{tree}") == row["tree"]

    assert cli.main(["uninstall", "--workspace", str(repo.root)]) == 0
    capsys.readouterr()
    assert not (hooks / HOOK).exists()



# ── R-cli-42: `hook uninstall` removes the trailer hook on its own ─────────────

def _installed(tmp_path):
    from aegis_cli import cli

    repo = hv.make_project(tmp_path)
    hooks = repo.root / ".git" / "hooks"
    assert cli.main(["hook", "install", "--workspace", str(repo.root)]) == 0
    assert (hooks / "pre-commit").is_file() and (hooks / HOOK).is_file()
    return repo, hooks


def _uninstall(repo, capsys, *flags):
    from aegis_cli import cli

    capsys.readouterr()
    rc = cli.main(["hook", "uninstall", "--workspace", str(repo.root), *flags])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@needs_git
def test_uninstall_removes_the_trailer_hook_when_pre_commit_was_deleted_by_hand(tmp_path, capsys):
    repo, hooks = _installed(tmp_path)
    (hooks / "pre-commit").unlink()
    rc, out, _err = _uninstall(repo, capsys)
    assert rc == 1
    assert "No aegis pre-commit hook found to uninstall" in out and "prepare-commit-msg hook removed" in out
    assert not (hooks / HOOK).exists()


@needs_git
def test_uninstall_removes_the_trailer_hook_beside_a_users_own_pre_commit(tmp_path, capsys):
    repo, hooks = _installed(tmp_path)
    mine = b"#!/bin/sh\necho users own check\n"
    (hooks / "pre-commit").write_bytes(mine)
    rc, _out, _err = _uninstall(repo, capsys)
    assert rc == 1
    assert (hooks / "pre-commit").read_bytes() == mine
    assert not (hooks / HOOK).exists()


@needs_git
def test_uninstall_leaves_a_foreign_prepare_commit_msg_alone(tmp_path, capsys):
    repo = hv.make_project(tmp_path)
    hooks = repo.root / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    foreign = b"#!/bin/sh\necho mine\n"
    (hooks / HOOK).write_bytes(foreign)
    rc, out, _err = _uninstall(repo, capsys)
    assert rc == 1
    assert (hooks / HOOK).read_bytes() == foreign
    assert "prepare-commit-msg hook" not in out


@needs_git
def test_a_dry_run_uninstall_changes_no_hook_file(tmp_path, capsys):
    repo, hooks = _installed(tmp_path)
    (hooks / "pre-commit").unlink()
    before = (hooks / HOOK).read_bytes()
    rc, out, _err = _uninstall(repo, capsys, "--dry-run")
    assert rc == 1 and (hooks / HOOK).read_bytes() == before
    assert "prepare-commit-msg hook would be removed (dry run)" in out


@needs_git
def test_json_uninstall_prints_only_its_payload_and_removes_the_trailer_hook(tmp_path, capsys):
    import json

    repo, hooks = _installed(tmp_path)
    (hooks / "pre-commit").unlink()
    rc, out, _err = _uninstall(repo, capsys, "--json")
    assert rc == 1
    assert json.loads(out) == {"status": "not_found", "success": False}
    assert not (hooks / HOOK).exists()


@needs_git
def test_a_pre_commit_that_is_not_utf8_is_left_unchanged_and_the_trailer_hook_still_goes(tmp_path, capsys):
    repo, hooks = _installed(tmp_path)
    odd = b"#!/bin/sh\n# aegis-hook \xff\xfe\n"
    (hooks / "pre-commit").write_bytes(odd)
    rc, _out, err = _uninstall(repo, capsys)
    assert rc == 1
    assert (hooks / "pre-commit").read_bytes() == odd
    assert f"Error: {hooks / 'pre-commit'} is not UTF-8 text; left unchanged" in err
    assert not (hooks / HOOK).exists()
