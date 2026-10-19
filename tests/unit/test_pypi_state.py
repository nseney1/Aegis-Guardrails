"""What PyPI already holds for a version decides what the publish job uploads.

A re-run never changes or masks PyPI content: missing files are uploaded, identical
files are skipped, and a differing or unknown file, or an unreadable answer, fails
closed. The fetcher, the clock and the sleep are injected; nothing reaches PyPI.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
SCRIPT = REPO_ROOT / ".github" / "scripts" / "pypi_state.py"
WHEEL = "aegis_guardrails-4.4.0-py3-none-any.whl"
SDIST = "aegis_guardrails-4.4.0.tar.gz"
URL = "https://pypi.org/pypi/aegis-guardrails/4.4.0/json"


def _module():
    spec = importlib.util.spec_from_file_location("pypi_state", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(data):
    return hashlib.sha256(data).hexdigest()


LOCAL = {WHEEL: _sha(b"wheel bytes"), SDIST: _sha(b"sdist bytes")}


@pytest.fixture
def dist(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GITHUB_OUTPUT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(str(tmp_path))
    d = tmp_path / "dist"
    d.mkdir()
    (d / "SHA256SUMS").write_bytes("".join(f"{LOCAL[n]}  {n}\n" for n in (WHEEL, SDIST)).encode())
    (tmp_path / "publish-files.txt").write_bytes(f"dist/{WHEEL}\ndist/{SDIST}\n".encode())
    return tmp_path


def _files(root):
    return (root / "publish-files.txt").read_bytes().decode().splitlines()


def _held(*entries, yanked=False):
    urls = [{"filename": name, "digests": {"md5": "0" * 32, "sha256": digest},
             "packagetype": "sdist" if name.endswith(".tar.gz") else "bdist_wheel",
             "yanked": yanked} for name, digest in entries]
    return 200, json.dumps({"info": {"version": "4.4.0", "yanked": yanked}, "urls": urls}).encode()


class Fetcher:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def _plan(fetch, capsys):
    code = _module().main(["plan", "--project", "aegis-guardrails", "--version", "4.4.0",
                           "--sums", "dist/SHA256SUMS", "--files", "publish-files.txt"], fetch=fetch)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_nothing_on_pypi_uploads_every_file(dist, capsys, monkeypatch):
    output = dist / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    fetch = Fetcher((404, b'{"message": "Not Found"}'))
    code, out, _ = _plan(fetch, capsys)
    assert (code, out.strip()) == (0, "state=absent")
    assert fetch.urls == [URL]
    assert _files(dist) == [f"dist/{WHEEL}", f"dist/{SDIST}"]
    assert output.read_bytes().decode() == "state=absent\n"


def test_an_empty_file_list_on_pypi_is_absent(dist, capsys):
    code, out, _ = _plan(Fetcher(_held()), capsys)
    assert (code, out.strip()) == (0, "state=absent")
    assert _files(dist) == [f"dist/{WHEEL}", f"dist/{SDIST}"]


def test_the_wheel_alone_on_pypi_uploads_only_the_sdist(dist, capsys):
    code, out, _ = _plan(Fetcher(_held((WHEEL, LOCAL[WHEEL]))), capsys)
    assert (code, out.strip()) == (0, "state=partial")
    assert _files(dist) == [f"dist/{SDIST}"]


def test_both_files_with_equal_digests_upload_nothing(dist, capsys):
    code, out, _ = _plan(Fetcher(_held((WHEEL, LOCAL[WHEEL]), (SDIST, LOCAL[SDIST]))), capsys)
    assert (code, out.strip()) == (0, "state=identical")
    assert _files(dist) == []


def test_a_yanked_release_with_equal_digests_is_identical(dist, capsys):
    held = _held((WHEEL, LOCAL[WHEEL]), (SDIST, LOCAL[SDIST]), yanked=True)
    assert _plan(Fetcher(held), capsys)[:2] == (0, "state=identical\n")


def test_a_differing_digest_fails_and_names_both_digests(dist, capsys):
    other = _sha(b"rebuilt wheel")
    code, out, err = _plan(Fetcher(_held((WHEEL, other), (SDIST, LOCAL[SDIST]))), capsys)
    assert code == 1 and "state=" not in out
    assert WHEEL in err and other in err and LOCAL[WHEEL] in err
    assert _files(dist) == [f"dist/{WHEEL}", f"dist/{SDIST}"]


def test_a_file_unknown_to_the_sums_fails(dist, capsys):
    extra = "aegis_guardrails-4.4.0-py3-none-win_amd64.whl"
    code, _, err = _plan(Fetcher(_held((WHEEL, LOCAL[WHEEL]), (extra, _sha(b"x")))), capsys)
    assert code == 1 and extra in err
    assert _files(dist) == [f"dist/{WHEEL}", f"dist/{SDIST}"]


@pytest.mark.parametrize("answer", [
    (500, b"oops"),
    TimeoutError("timed out"),
    (200, b"not json"),
    (200, b'{"info": {}}'),
    (200, b'{"urls": [{"filename": "x"}]}'),
], ids=["500", "timeout", "notjson", "nourls", "shape"])
def test_an_unreadable_answer_fails_closed(dist, capsys, answer):
    code, out, err = _plan(Fetcher(answer), capsys)
    assert code == 2 and "state=" not in out and err
    assert _files(dist) == [f"dist/{WHEEL}", f"dist/{SDIST}"]


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _wait(fetch, clock, capsys):
    code = _module().main(["wait", "--project", "aegis-guardrails", "--version", "4.4.0",
                           "--sums", "dist/SHA256SUMS"], fetch=fetch, clock=clock, sleep=clock.sleep)
    return code, capsys.readouterr().err


def test_wait_ends_once_pypi_holds_every_file(dist, capsys):
    partial = _held((WHEEL, LOCAL[WHEEL]))
    fetch = Fetcher(partial, partial, _held((WHEEL, LOCAL[WHEEL]), (SDIST, LOCAL[SDIST])))
    clock = Clock()
    assert _wait(fetch, clock, capsys)[0] == 0
    assert len(fetch.urls) == 3 and clock.sleeps == [10, 10]


def test_wait_times_out_after_300_seconds_without_sleeping(dist, capsys):
    fetch = Fetcher(_held((WHEEL, LOCAL[WHEEL])))
    clock = Clock()
    code, err = _wait(fetch, clock, capsys)
    assert code == 1 and "300" in err
    assert clock.now >= 300 and clock.now <= 310


def test_wait_fails_at_once_on_a_mismatch(dist, capsys):
    fetch = Fetcher(_held((WHEEL, _sha(b"other")), (SDIST, LOCAL[SDIST])))
    clock = Clock()
    code, err = _wait(fetch, clock, capsys)
    assert code == 1 and WHEEL in err
    assert len(fetch.urls) == 1 and clock.sleeps == []
