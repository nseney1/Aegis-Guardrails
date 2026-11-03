"""R-checks-29: the Python security pack and the known-format secret scan run from Layer 1 and judge
what a change introduces, in the live tree (`aegis check`), the staged snapshot (`--hook`) and the
recorded snapshot (`--record`) alike."""
from __future__ import annotations

import json
import random
import string
import subprocess
from pathlib import Path

import pytest

from aegis_cli.cli import main
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

pytestmark = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

REPO = Path(__file__).resolve().parents[3]
LEGACY = "import tempfile\n\n\ndef scratch():\n    return tempfile.mktemp()\n"


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", "-c", "commit.gpgsign=false", *args],
                   cwd=str(root), check=True, capture_output=True)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _token() -> str:
    """A GitHub classic PAT shape (ghp_ + 36), built here so no secret-shaped literal sits in the file."""
    rng = random.Random(7)
    return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_BASE_REF", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root / "src" / "legacy.py", LEGACY)
    _write(root / ".github" / "scripts" / "ci.py", "def run():\n    return 1\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _check(root: Path, capsys, *extra: str):
    try:
        code = main(["check", "--workspace", str(root), "--format", "json", *extra])
    except SystemExit as exc:
        code = exc.code
    raw = capsys.readouterr().out
    return code, json.loads(raw), raw


def _failed(payload: dict) -> list:
    return sorted((r["tool"], r["target"]) for r in payload["layer1"] if not r["verdict"])


def test_a_banned_call_the_change_introduces_fails_and_a_legacy_one_it_only_moved_does_not(repo, capsys):
    _write(repo / "src" / "legacy.py", "# moved down one line\n" + LEGACY)
    _write(repo / "src" / "load.py", "import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n")
    code, payload, _ = _check(repo, capsys, "src/legacy.py", "src/load.py")
    assert code == 1
    assert _failed(payload) == [("security_pack:sec-py-pickle-loads", "src/load.py")]
    row = next(r for r in payload["layer1"] if r["tool"] == "security_pack:sec-py-pickle-loads")
    assert row["lines"] == [5] and row["detail"] == "pickle.loads introduced by this change"


def test_a_changed_file_under_a_dot_directory_is_checked(repo, capsys):
    _write(repo / ".github" / "scripts" / "ci.py", "import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n")
    code, payload, _ = _check(repo, capsys, ".github/scripts/ci.py")
    assert code == 1
    assert _failed(payload) == [("security_pack:sec-py-subprocess-shell", ".github/scripts/ci.py")]


def test_a_hit_in_a_test_path_passes_and_is_reported(repo, capsys):
    _write(repo / "tests" / "test_calc.py", "def test_calc():\n    assert eval('1+1') == 2\n")
    code, payload, _ = _check(repo, capsys, "tests/test_calc.py")
    assert code == 0
    note = next(r for r in payload["layer1"] if r["tool"] == "security_pack")
    assert note["verdict"] is True and note["target"] == "tests/test_calc.py"
    assert "exempted in a test path" in note["detail"] and "sec-py-eval-exec" in note["detail"]


def test_a_known_format_secret_the_change_adds_fails_and_is_never_printed_whole(repo, capsys):
    token = _token()
    _write(repo / "src" / "client.py", f'API_TOKEN = "{token}"\n')
    code, payload, raw = _check(repo, capsys, "src/client.py")
    assert code == 1
    assert _failed(payload) == [("secret_scan:github-pat", "src/client.py")]
    assert token not in raw
    try:
        code = main(["check", "--workspace", str(repo), "src/client.py"])
    except SystemExit as exc:
        code = exc.code
    assert code == 1 and token not in capsys.readouterr().out


def test_the_same_secret_already_at_the_base_is_not_introduced_again(repo, capsys):
    token = _token()
    _write(repo / "src" / "client.py", f'API_TOKEN = "{token}"\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "legacy secret")
    _write(repo / "src" / "client.py", f'# touched\nAPI_TOKEN = "{token}"\n')
    code, payload, _ = _check(repo, capsys, "src/client.py")
    assert code == 0 and _failed(payload) == []


def test_a_secret_in_a_test_path_is_exempted_and_reported(repo, capsys):
    _write(repo / "tests" / "test_client.py", f'TOKEN = "{_token()}"\n')
    code, payload, raw = _check(repo, capsys, "tests/test_client.py")
    assert code == 0 and _token() not in raw
    note = next(r for r in payload["layer1"] if r["tool"] == "security_pack")
    assert "exempted in a test path: github-pat" in note["detail"]


def test_the_pre_commit_hook_reads_the_staged_snapshot_and_still_subtracts_the_base(repo, capsys):
    _write(repo / "src" / "legacy.py", "# moved down one line\n" + LEGACY)
    _write(repo / "src" / "run.py", "import marshal\n\n\ndef read(blob):\n    return marshal.loads(blob)\n")
    _git(repo, "add", "-A")
    code, payload, _ = _check(repo, capsys, "--hook")
    assert code == 1
    assert _failed(payload) == [("security_pack:sec-py-pickle-loads", "src/run.py")]


def test_an_eval_the_seeded_no_eval_rule_already_names_is_reported_once(repo, capsys):
    _write(repo / ".aegis" / "rules" / "invariants" / "no-eval.md", (REPO / "rules" / "no-eval.md").read_text(encoding="utf-8"))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "seed no-eval")  # gate rules bind from the reviewed base
    _write(repo / "src" / "calc.py", "def calc(expr):\n    return eval(expr)\n")
    code, payload, _ = _check(repo, capsys, "src/calc.py")
    assert code == 1
    assert _failed(payload) == [("forbid_ast:no-eval", "src/calc.py")]


def _seed_no_eval(repo: Path) -> None:
    _write(repo / ".aegis" / "rules" / "invariants" / "no-eval.md", (REPO / "rules" / "no-eval.md").read_text(encoding="utf-8"))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "seed no-eval")  # gate rules bind from the reviewed base


def test_another_banned_call_on_a_line_the_no_eval_rule_fails_is_still_reported(repo, capsys):
    _seed_no_eval(repo)
    _write(repo / "src" / "a.py", "import pickle\n\n\ndef f(s):\n    return pickle.loads(eval(s))\n")
    code, payload, _ = _check(repo, capsys, "src/a.py")
    assert code == 1
    assert _failed(payload) == [("forbid_ast:no-eval", "src/a.py"), ("security_pack:sec-py-pickle-loads", "src/a.py")]


def test_an_allow_for_the_no_eval_rule_does_not_silence_another_banned_call_on_its_line(repo, capsys):
    """Adversarial: `# aegis: allow[no-eval]` covers that rule's eval at the site, not pickle.loads beside it."""
    _seed_no_eval(repo)
    _write(repo / "src" / "a.py",
           "import pickle\n\n\ndef f(s):\n    return pickle.loads(eval(s))  # aegis: allow[no-eval] parsing trusted config\n")
    code, payload, _ = _check(repo, capsys, "src/a.py")
    assert (code, _failed(payload)) == (1, [("security_pack:sec-py-pickle-loads", "src/a.py")])
    _git(repo, "add", "-A")
    code, payload, _ = _check(repo, capsys, "--hook")
    assert (code, _failed(payload)) == (1, [("security_pack:sec-py-pickle-loads", "src/a.py")])


def test_the_pack_does_not_second_guess_the_no_eval_rules_allow_for_the_same_eval(repo, capsys):
    _seed_no_eval(repo)
    _write(repo / "src" / "a.py", "def f(s):\n    return eval(s)  # aegis: allow[no-eval] parsing trusted config\n")
    code, payload, _ = _check(repo, capsys, "src/a.py")
    assert (code, _failed(payload)) == (0, [])


def test_a_failure_to_run_the_scan_fails_the_check_closed(repo, capsys, monkeypatch):
    import aegis_core.verification.security_pack as pack

    def boom(*_a, **_k):
        raise RuntimeError("pack broke")

    monkeypatch.setattr(pack, "evaluate_security_pack", boom)
    _write(repo / "src" / "load.py", "def f():\n    return 1\n")
    code, payload, _ = _check(repo, capsys, "src/load.py")
    assert code == 1
    assert any(r["tool"] == "security_pack" and "pack broke" in r["detail"] for r in payload["layer1"] if not r["verdict"])


def test_an_unparseable_changed_python_file_fails(repo, capsys):
    _write(repo / "src" / "broken.py", "def f(:\n")
    code, payload, _ = _check(repo, capsys, "src/broken.py")
    assert code == 1
    assert [r for r in payload["layer1"] if not r["verdict"] and r["tool"] == "security_pack"
            and r["target"] == "src/broken.py" and "cannot verify" in r["detail"]]


def test_an_allow_marker_on_the_token_line_passes_and_is_counted(repo, capsys):
    from aegis_core import gitsafe
    from aegis_core.verification import scanners

    _write(repo / "src" / "client.py", f'API_TOKEN = "{_token()}"  # gitleaks:allow\n')
    code, payload, _ = _check(repo, capsys, "src/client.py")
    assert code == 0 and _failed(payload) == []
    base = gitsafe.head_commit(repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "allowed")
    assert scanners.suppression_count(repo, base) == {"count": 1, "delta": 1}


def test_the_recorded_check_judges_what_the_change_introduces_like_aegis_check(tmp_path, capsys):
    project = hv.make_project(tmp_path)
    project.git("checkout", "-q", "main")
    project.write("src/legacy.py", LEGACY)
    project.commit("legacy")
    project.git("checkout", "-q", "work")
    project.git("merge", "-q", "main")

    def record() -> tuple:
        rc = main(["check", "--record", "--workspace", str(project.root), "--base", "main", "--json"])
        return rc, json.loads(capsys.readouterr().out)

    project.write("src/legacy.py", "# moved down one line\n" + LEGACY)
    rc, doc = record()
    assert (rc, doc["check"]["layer1"]["findings"]) == (0, 0)

    project.write("src/load.py", "import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n")
    rc, doc = record()
    assert (rc, doc["check"]["passed"], doc["check"]["layer1"]["findings"]) == (1, False, 1)
    code, payload, _ = _check(project.root, capsys, "src/legacy.py", "src/load.py")
    assert code == 1 and _failed(payload) == [("security_pack:sec-py-pickle-loads", "src/load.py")]


def test_a_trailer_recorded_before_the_wiring_diverges_as_documented(tmp_path, monkeypatch):
    """Rollout: a 4.3.x trailer on a commit that introduces os.system(cmd) passed without T7; the
    wired CI rerun fails it, which is reported as a divergence, never an exception."""
    from aegis_core import checkrun, testexec

    monkeypatch.setattr(testexec, "run_tests", lambda *_a, **_k: testexec.TestsRun(exit=0, collected=1, passed=1))
    project = hg.make_repo(tmp_path)
    project.write("src/run.py", "import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n")
    project.git("add", "-A")
    tree = project.git("write-tree")
    project.commit(f"feat: run\n\nAegis-Check: tree={tree} exit=0\n")
    results = checkrun.verify_commit_trailers(project.root, "main", "HEAD")
    assert [(r["result"], r["failed"]) for r in results] == [("void", True)]


def test_this_repository_has_no_gate_finding_from_the_wired_scans():
    """Dogfood, sampled (no clock): the pack and the Tier A scan over aegis_core, aegis_cli and
    aegis_mcp with an empty base find nothing that would fail `aegis check`."""
    from aegis_core.verification import scanners
    from aegis_core.verification.security_pack import evaluate_security_pack

    files = sorted(p.relative_to(REPO).as_posix() for pkg in ("aegis_core", "aegis_cli", "aegis_mcp")
                   for p in (REPO / pkg).rglob("*.py"))
    hot = ["aegis_core/human_gate.py", "aegis_core/testexec.py", "aegis_core/verification/scanners.py"]
    sample = sorted(set(files[:: max(1, len(files) // 40)] + hot))
    pack = evaluate_security_pack(REPO, sample, {})
    assert pack["violations"] == [] and [u for u in pack["unverified_findings"] if u["kind"] == "file"] == []
    assert scanners.scan_secrets_delta(REPO, sample, {}) == []


def _record(root: Path, capsys) -> tuple:
    rc = main(["check", "--record", "--workspace", str(root), "--base", "main", "--json"])
    out = capsys.readouterr().out
    return rc, json.loads(out)["check"], out


def test_a_secret_in_a_changed_yaml_file_fails_check_the_hook_and_the_record_alike(tmp_path, capsys):
    """Given a non-Python file whose change adds a known-format token, when plain check, the pre-commit
    hook and the recorded check run, then all three fail it the same way and none prints the token."""
    project = hv.make_project(tmp_path)
    token = _token()
    project.write("config/settings.yaml", f"github:\n  token: {token}\n")
    code, payload, raw = _check(project.root, capsys, "config/settings.yaml")
    assert (code, _failed(payload)) == (1, [("secret_scan:github-pat", "config/settings.yaml")]) and token not in raw
    project.git("add", "config/settings.yaml")
    code, payload, raw = _check(project.root, capsys, "--hook")
    assert (code, _failed(payload)) == (1, [("secret_scan:github-pat", "config/settings.yaml")]) and token not in raw
    rc, row, raw = _record(project.root, capsys)
    assert (rc, row["passed"], row["layer1"]["findings"]) == (1, False, 1) and token not in raw


def test_the_hook_judges_the_staged_yaml_even_when_the_working_copy_was_cleaned_after_git_add(repo, capsys):
    """Adversarial: what the commit records is the index, so a clean working copy cannot hide a staged token."""
    _write(repo / "settings.yaml", f"token: {_token()}\n")
    _git(repo, "add", "settings.yaml")
    _write(repo / "settings.yaml", "token: none\n")
    code, payload, _ = _check(repo, capsys, "--hook")
    assert (code, _failed(payload)) == (1, [("secret_scan:github-pat", "settings.yaml")])


def test_the_hook_and_the_record_take_a_binary_file_and_note_one_over_the_size_cap(repo, capsys, monkeypatch):
    """Sad path: a staged binary is read and skipped (as plain check does), a file over the index cap is
    not read and a passing note says so; neither crashes nor fails the commit."""
    from aegis_core.verification import runner

    monkeypatch.setattr(runner, "INDEX_BLOB_LIMIT_BYTES", 256)
    _git(repo, "checkout", "-q", "-b", "work")
    (repo / "assets").mkdir()
    (repo / "assets" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\0\0" + _token().encode("ascii") + b"\0" * 64)
    _write(repo / "data" / "big.yaml", "rows:\n" + "  - x\n" * 60)
    _git(repo, "add", "-A")
    code, payload, _ = _check(repo, capsys, "--hook")
    assert (code, _failed(payload)) == (0, [])
    notes = [(r["tool"], r["target"], r["verdict"]) for r in payload["layer1"] if r["tool"] == "index"]
    assert notes == [("index", "data/big.yaml", True)]
    _git(repo, "commit", "-q", "-m", "assets")
    rc, row, _ = _record(repo, capsys)
    assert (rc, row["passed"], row["layer1"]) == (0, True, {"findings": 0, "files": 2, "evidence": []})


def test_a_crlf_checkout_of_a_committed_change_is_judged_against_the_same_base_as_an_lf_one(repo, capsys):
    """Given a branch commit that adds pickle.loads, when the file is checked out with core.autocrlf=true
    (Git for Windows' default) instead of LF, then the delta still finds what the branch added."""
    _write(repo / "src" / "a.py", "def f(x):\n    return x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a")
    _git(repo, "checkout", "-q", "-b", "feat")
    _write(repo / "src" / "a.py", "import pickle\n\n\ndef f(x):\n    return pickle.loads(x)\n")
    _git(repo, "commit", "-q", "-am", "feat")
    code, payload, _ = _check(repo, capsys, "src/a.py")
    assert (code, _failed(payload)) == (1, [("security_pack:sec-py-pickle-loads", "src/a.py")])
    try:
        _git(repo, "config", "core.autocrlf", "true")
    except subprocess.CalledProcessError:
        pytest.skip("git cannot set core.autocrlf here")
    (repo / "src" / "a.py").unlink()
    _git(repo, "checkout", "--", "src/a.py")
    assert b"\r\n" in (repo / "src" / "a.py").read_bytes()
    code, payload, _ = _check(repo, capsys, "src/a.py")
    assert (code, _failed(payload)) == (1, [("security_pack:sec-py-pickle-loads", "src/a.py")])


def test_a_file_whose_only_change_is_its_line_endings_is_not_judged_whole(repo, capsys):
    """Sad path: a CRLF copy of a committed legacy file is the committed text, so its legacy hit is not new."""
    (repo / "src" / "legacy.py").write_bytes(LEGACY.replace("\n", "\r\n").encode("utf-8"))
    code, payload, _ = _check(repo, capsys, "src/legacy.py")
    assert (code, _failed(payload)) == (0, [])


def test_a_pure_rename_of_a_legacy_file_is_judged_against_its_old_path(repo, capsys):
    """Given `git mv` of a file holding a legacy hit, when check, the hook and the record run, uncommitted
    and committed (--base main), then the hit is not introduced by the change."""
    _git(repo, "checkout", "-q", "-b", "feat")
    _git(repo, "mv", "src/legacy.py", "src/renamed.py")
    code, payload, _ = _check(repo, capsys, "src/renamed.py")
    assert (code, _failed(payload)) == (0, [])
    code, payload, _ = _check(repo, capsys, "--hook")
    assert (code, _failed(payload)) == (0, [])
    _git(repo, "commit", "-q", "-m", "mv")
    code, payload, _ = _check(repo, capsys, "--base", "main")
    assert (code, _failed(payload)) == (0, [])
    rc, row, _ = _record(repo, capsys)
    assert (rc, row["layer1"]["findings"]) == (0, 0)


def test_a_renamed_yaml_keeps_its_committed_token_and_a_copy_of_it_does_not(repo, capsys):
    """The hook's T7-only files take the same rename rule. A copy is not a rename: of two identical files
    from one removed path, one is the rename and the other introduces the token again (multiset)."""
    _write(repo / "conf" / "old.yaml", f"token: {_token()}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "legacy token")
    _write(repo / "src" / "later.py", "X = 1\n")  # HEAD~1, the last base candidate, holds the token too
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "later")
    _git(repo, "mv", "conf/old.yaml", "conf/new.yaml")
    code, payload, _ = _check(repo, capsys, "--hook")
    assert (code, _failed(payload)) == (0, [])
    (repo / "conf" / "copy.yaml").write_bytes((repo / "conf" / "new.yaml").read_bytes())
    _git(repo, "add", "-A")
    code, payload, _ = _check(repo, capsys, "--hook")
    failed = _failed(payload)
    assert code == 1 and len(failed) == 1 and failed[0][0] == "secret_scan:github-pat"
    assert failed[0][1] in ("conf/copy.yaml", "conf/new.yaml")


def test_a_copy_of_a_legacy_file_is_judged_whole(repo, capsys):
    (repo / "src" / "copy.py").write_bytes((repo / "src" / "legacy.py").read_bytes())
    code, payload, _ = _check(repo, capsys, "src/copy.py")
    assert (code, _failed(payload)) == (1, [("security_pack:sec-py-tempfile-mktemp", "src/copy.py")])
    _git(repo, "add", "-A")
    code, payload, _ = _check(repo, capsys, "--hook")
    assert (code, _failed(payload)) == (1, [("security_pack:sec-py-tempfile-mktemp", "src/copy.py")])


def test_a_rename_that_also_adds_a_banned_call_still_fails(repo, capsys):
    """Sad path: a rename with edits is not an exact rename, so the file is judged whole."""
    _git(repo, "mv", "src/legacy.py", "src/renamed.py")
    _write(repo / "src" / "renamed.py", LEGACY + "\n\ndef load(blob):\n    import pickle\n    return pickle.loads(blob)\n")
    code, payload, _ = _check(repo, capsys, "src/renamed.py")
    assert code == 1 and ("security_pack:sec-py-pickle-loads", "src/renamed.py") in _failed(payload)


def test_a_file_the_branch_added_and_committed_is_judged_whole(repo, capsys):
    _git(repo, "checkout", "-q", "-b", "work")
    _write(repo / "src" / "load.py", "import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "feat: load")
    code, payload, _ = _check(repo, capsys, "--base", "main")
    assert code == 1 and _failed(payload) == [("security_pack:sec-py-pickle-loads", "src/load.py")]
