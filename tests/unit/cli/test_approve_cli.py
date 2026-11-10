"""`aegis approve` and `aegis doctor --github` through the real argument parser."""
from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from aegis_cli import cli
from aegis_core import human_gate
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


def test_approve_is_a_registered_command_with_a_base_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["approve", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--base" in out and "Aegis-Approve" in out


def test_approve_appears_in_the_categorized_help(capsys):
    assert cli.main([]) == 0
    assert "approve" in capsys.readouterr().out


def test_approve_outside_a_git_work_tree_is_a_refusal_not_a_traceback(tmp_path, capsys):
    rc = cli.main(["approve", "--workspace", str(tmp_path)])
    assert rc == 1
    assert "not inside a git work tree" in capsys.readouterr().err


@needs_git
def test_approve_without_a_terminal_refuses_through_main(tmp_path, monkeypatch, capsys):
    repo = hg.make_repo(tmp_path)
    repo.write(".aegis/config.json", "{}\n")
    repo.commit("governance")
    monkeypatch.setattr("sys.stdin", io.StringIO())
    key, _pub = hg.keygen(tmp_path / "k", "human")
    repo.home.sign_with(str(key))
    monkeypatch.setenv("HOME", str(repo.home.path))
    rc = cli.main(["approve", "--workspace", str(repo.root), "--base", "main", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 1 and doc["status"] == "refused" and doc["code"] == "no_terminal"
    for field in ("source", "aegis_version", "checked_at", "scope"):
        assert doc[field]


@needs_git
@pytest.mark.parametrize("flags,needle", [
    (["--tier", "B"], "--tier only applies"),
    (["--apply"], "--apply only applies"),
    (["--github", "--fix"], "cannot be combined"),
    (["--github", "--apply", "--tier", "B", "--json"], "cannot run with --json"),
    (["--github", "--apply"], "--tier A or --tier B"),
])
def test_doctor_github_flag_combinations_are_usage_errors(tmp_path, capsys, flags, needle):
    repo = hg.make_repo(tmp_path)
    rc = cli.main(["doctor", "--workspace", str(repo.root), *flags])
    assert rc == 2
    assert needle in capsys.readouterr().err


def test_an_approval_verdict_serializes_with_the_envelope():
    verdict = human_gate.Approval(False, "unsigned", "the commit is not signed", "a" * 40)
    doc = verdict.as_dict("/work")
    assert doc["valid"] is False and doc["code"] == "unsigned" and doc["scope"]["commit"] == "a" * 40
    assert doc["checked_at"].endswith("Z") and doc["source"] and doc["aegis_version"]


# ── R-trust-34: one signing flow, one set of refusals ─────────────────────────

needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")


@pytest.fixture
def signer_repo(tmp_path, monkeypatch):
    """A signer on main, a rule edit committed on work, and a user-level SSH signing key."""
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo = hg.make_repo(tmp_path, pub)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "weaker"))
    repo.commit("weaken a rule")
    repo.home.sign_with(str(key))
    for name, value in repo.home.env.items():
        monkeypatch.setenv(name, value)
    for name in ("SSH_AUTH_SOCK", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    return repo


def _run(repo, monkeypatch, capsys, exempt, tty=True, answer="n"):
    from aegis_cli import approve
    prompts = []
    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: tty)
    monkeypatch.setattr("builtins.input", lambda prompt="": prompts.append(prompt) or answer)
    argv = ["approve", "--workspace", str(repo.root), "--base", "main", "--json"]
    if exempt:
        argv += ["--exempt-test", repo.head(), "--reason", "checked by hand"]
    before = repo.head()
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert repo.head() == before, "a refusal makes no commit"
    return rc, json.loads(captured.out), prompts, captured.err


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_refuse_uncommitted_governance_changes(signer_repo, monkeypatch, capsys, exempt):
    signer_repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "dirty"))
    rc, doc, prompts, _err = _run(signer_repo, monkeypatch, capsys, exempt)
    assert rc == 1 and doc["status"] == "refused" and doc["code"] == "uncommitted" and prompts == []
    assert doc["reason"].startswith("governance files have uncommitted changes (rules)")


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_refuse_staged_changes_before_any_prompt(signer_repo, monkeypatch, capsys, exempt):
    signer_repo.write("src/app.py", "def app():\n    return 3\n")
    signer_repo.git("add", "src/app.py")
    rc, doc, prompts, _err = _run(signer_repo, monkeypatch, capsys, exempt)
    assert rc == 1 and doc["code"] == "staged" and prompts == []


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_refuse_without_a_terminal(signer_repo, monkeypatch, capsys, exempt):
    rc, doc, prompts, _err = _run(signer_repo, monkeypatch, capsys, exempt, tty=False)
    assert rc == 1 and doc["code"] == "no_terminal" and prompts == []


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_are_declined_by_anything_but_y(signer_repo, monkeypatch, capsys, exempt):
    rc, doc, prompts, err = _run(signer_repo, monkeypatch, capsys, exempt, answer="sure")
    assert rc == 1 and doc["status"] == "declined" and doc["code"] == "declined" and prompts == [""]
    assert "[y/N]" in err


@pytest.fixture
def review_repo(tmp_path, monkeypatch):
    """Exercise the real CLI and git reads without keys, signing or signature tools."""
    if not hg.git_ok():
        pytest.skip("needs git")
    from aegis_cli import approve

    repo = hg.make_repo(tmp_path)
    repo.write(".aegis/config.json", "{}\n")
    repo.commit("governance")
    for name, value in repo.home.env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: True)

    def unexpected_sign(*args, **kwargs):
        pytest.fail("a refusal must not sign")

    monkeypatch.setattr(human_gate, "signed_empty_commit", unexpected_sign)
    return repo


@pytest.mark.parametrize("exempt", [False, True], ids=["governance", "exemption"])
@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("custody", ["agent", "hardware"])
@pytest.mark.parametrize("answer", ["n", "yes"])
def test_signing_review_precedes_confirmation(review_repo, monkeypatch, capsys, exempt, use_json, custody, answer):
    from aegis_cli import approve

    repo = review_repo
    fix = repo.head()
    base_commit = repo.git("rev-parse", "main")
    # Exercise the inclusive limit, Unicode and shared trimming without another git fixture.
    reason = " checked caf\u00e9 \u6f22\u5b57 " + "x" * (4096 - len(" checked caf\u00e9 \u6f22\u5b57 ") - 1) + " "
    clean_reason = reason.strip()
    warning = "custody boundary warning"
    has_warning = custody in ("plain_file", "agent", "unknown")
    monkeypatch.setattr(human_gate, "check_key_custody", lambda top: human_gate.KeyCustody(custody, warning, has_warning))
    signed = []
    verified = []

    def sign(top, message, *, interactive):
        signed.append((top, message, interactive))
        return "a" * 40

    def verify(top, commit, subject, base):
        verified.append((top, commit, subject, base))
        return human_gate.Approval(True, "approved", "signature verified", commit)

    monkeypatch.setattr(human_gate, "signed_empty_commit", sign)
    monkeypatch.setattr(human_gate, "verify_test_exemption" if exempt else "verify_approval", verify)
    before_prompt = []

    def confirm(prompt=""):
        before_prompt.append(capsys.readouterr())
        if not use_json:
            print(prompt, end="")  # input's terminal prompt
        return answer

    monkeypatch.setattr(approve, "input", confirm, raising=False)
    argv = ["approve", "--workspace", str(repo.root), "--base", "main"]
    if use_json:
        argv.append("--json")
    if exempt:
        argv += ["--exempt-test", fix, "--reason", reason]
    rc = cli.main(argv)
    after = capsys.readouterr()
    assert len(before_prompt) == 1
    review = before_prompt[0].err if use_json else before_prompt[0].out
    assert (before_prompt[0].out if use_json else before_prompt[0].err) == ""
    if exempt:
        assert f"Base: main (= {base_commit} base)\n" in review
        assert f"Exempting fix commit: {fix}\nReason: {clean_reason}\n" in review
    else:
        assert f"Governance changed since main (= {base_commit} base): aegis-state\nGovernance tree hash: " in review
    assert (f"  warning: {warning}\n" in review) is has_warning
    if use_json:
        assert review.index("Sign ") > review.index("Reason:" if exempt else "Governance tree hash:")
        assert "[y/N]" in review
        doc = json.loads(before_prompt[0].out + after.out)
        assert doc["status"] == ("approved" if answer == "yes" else "declined")
        if answer == "yes":
            assert doc["verified"] is True
            assert doc["warnings"] == ([warning] if has_warning else [])
            if exempt:
                assert doc["reason"] == clean_reason
        else:
            assert doc["code"] == "declined"
    else:
        assert "[y/N]" in after.out
        assert ("Approved" if answer == "yes" else "No approval made.") in after.out
    assert rc == (0 if answer == "yes" else 1)
    assert len(signed) == len(verified) == (1 if answer == "yes" else 0)
    if signed:
        assert signed[0][0] == repo.root and signed[0][2] is True
        assert verified[0][0:2] == (repo.root, "a" * 40)
        assert verified[0][3] == base_commit
        if exempt:
            assert signed[0][1] == human_gate.exemption_message(fix, clean_reason)
            shown = review.split("\nReason: ", 1)[1].split("\n", 1)[0]
            trailer_reason = signed[0][1].split(f"Aegis-Exempt-Test: {fix} ", 1)[1].removesuffix("\n")
            assert shown.encode("utf-8") == trailer_reason.encode("utf-8")
            assert verified[0][2] == fix
        else:
            assert signed[0][1] == human_gate.approval_message(verified[0][2])


@pytest.mark.parametrize("exempt", [False, True], ids=["governance", "exemption"])
@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("introducer", ["\x1b]", "\x1bP"], ids=["osc", "dcs"])
def test_unterminated_key_name_preserves_custody_explanation_before_confirmation(
        review_repo, monkeypatch, capsys, exempt, use_json, introducer):
    from aegis_cli import approve

    key_name = "signing-key" + introducer
    warnings = [
        ("plain_file", f"the signing key {key_name} is a plain file with no passphrase, readable by this user: "
         "an agent running as you can sign with it, so a signature proves nothing"),
        ("unknown", f"the signing key file {key_name} was not found"),
        ("unknown", f"the signing key file {key_name} could not be classified"),
    ]
    argv = ["approve", "--workspace", str(review_repo.root), "--base", "main"]
    if use_json:
        argv.append("--json")
    if exempt:
        argv += ["--exempt-test", "HEAD", "--reason", "checked by hand"]
    for status, detail in warnings:
        monkeypatch.setattr(human_gate, "check_key_custody",
                            lambda top: human_gate.KeyCustody(status, detail, True, key_name))
        before_prompt = []

        def confirm(prompt=""):
            before_prompt.append(capsys.readouterr())
            return "n"

        monkeypatch.setattr(approve, "input", confirm, raising=False)
        assert cli.main(argv) == 1
        after = capsys.readouterr()
        assert len(before_prompt) == 1
        review = before_prompt[0].err if use_json else before_prompt[0].out
        assert (before_prompt[0].out if use_json else before_prompt[0].err) == ""
        assert f"  warning: {detail.replace(chr(27), '')}\n" in review
        assert "\x1b" not in review
        if use_json:
            assert "[y/N]" in review
            doc = json.loads(after.out)
            assert doc["status"] == "declined" and doc["code"] == "declined"
        else:
            assert after.out == "No approval made.\n" and after.err == ""


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_exemption_review_cannot_be_rewritten_by_caller_text(review_repo, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    reason = "checked by hand"
    commit_text = "b" * 40 + "\r\n\x1b[2Jforged\u202e\u2067"
    resolve = approve.gitsafe.resolve_commit
    monkeypatch.setattr(approve, "gitsafe", SimpleNamespace(**dict(vars(approve.gitsafe),
        resolve_commit=lambda top, ref: commit_text if ref == "HEAD" else resolve(top, ref))))
    monkeypatch.setattr(human_gate, "check_key_custody", lambda top: human_gate.KeyCustody("agent", "warning\r\n\x1b[2Jtext\u200b\u2066", True))
    monkeypatch.setattr(approve, "input", lambda prompt="": "n", raising=False)
    argv = ["approve", "--workspace", str(review_repo.root), "--base", "main",
            "--exempt-test", "HEAD", "--reason", reason]
    if use_json:
        argv.append("--json")
    assert cli.main(argv) == 1
    captured = capsys.readouterr()
    review = captured.err if use_json else captured.out
    assert "Exempting fix commit: " + "b" * 40 + " forged\\u202e\\u2067\n" in review
    assert "Reason: checked by hand\n" in review
    assert "  warning: warning text\\u200b\\u2066\n" in review
    assert not any(char in review for char in ("\r", "\x1b", "\x07", "\x08", "\x9b", "\t"))
    if use_json:
        assert json.loads(captured.out)["code"] == "declined"


@pytest.mark.parametrize("boundary,code", [
    ("unsupported", "no_key"), ("no_terminal", "no_terminal"),
    ("eof", "declined"), ("sign_failed", "sign_failed"),
])
def test_review_preserves_signing_refusals(review_repo, monkeypatch, capsys, boundary, code):
    from aegis_cli import approve

    custody = "unsupported" if boundary == "unsupported" else "hardware"
    monkeypatch.setattr(human_gate, "check_key_custody", lambda top: human_gate.KeyCustody(custody, "custody detail", False))
    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: boundary != "no_terminal")
    prompts = []

    def confirm(prompt=""):
        prompts.append(prompt)
        if boundary == "eof":
            raise EOFError
        return "y"

    def fail_sign(*args, **kwargs):
        raise human_gate.HumanGateError("signing boundary refused")

    monkeypatch.setattr(approve, "input", confirm, raising=False)
    if boundary == "sign_failed":
        monkeypatch.setattr(human_gate, "signed_empty_commit", fail_sign)
    argv = ["approve", "--workspace", str(review_repo.root), "--base", "main", "--json",
            "--exempt-test", "HEAD", "--reason", "checked by hand"]
    assert cli.main(argv) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["code"] == code
    assert len(prompts) == (1 if boundary in ("eof", "sign_failed") else 0)


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_exemption_refuses_nonprintable_reasons_before_any_review(tmp_path, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    def forbidden(*args, **kwargs):
        pytest.fail("invalid reasons must be refused before git, review or signing")

    monkeypatch.setattr(approve, "_preflight", forbidden)
    monkeypatch.setattr(approve, "sanitize_display", forbidden)
    monkeypatch.setattr(approve, "input", forbidden, raising=False)
    monkeypatch.setattr(human_gate, "check_key_custody", forbidden)
    monkeypatch.setattr(human_gate, "signed_empty_commit", forbidden)
    chars = [chr(code) for code in (*range(32), *range(127, 160))]
    chars += ["\u061c", "\u200d", "\u202e", "\u2028", "\u2029", "\u2066", "\ufeff", "\ud800"]
    reasons = ["ok" + char + "hidden" for char in chars]
    reasons += ["\nleading", "trailing\r", "ok\nAegis-Exempt-Test: " + "b" * 40 + " also exempt",
                "\x1b]" * 1024, "\x1bP" * 1024]
    for reason in reasons:
        argv = ["approve", "--workspace", str(tmp_path), "--exempt-test", "HEAD", "--reason", reason]
        if use_json:
            argv.append("--json")
        assert cli.main(argv) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "aegis approve: --reason must be one line of printable text\n"


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_exemption_bounds_reason_before_scanning_or_trimming(tmp_path, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    class LengthOnly(str):
        def __iter__(self):
            pytest.fail("oversized reasons must not be scanned")

        def strip(self, *args):
            pytest.fail("oversized reasons must not be trimmed")

    argv = ["approve", "--workspace", str(tmp_path), "--exempt-test", "HEAD", "--reason", LengthOnly("x" * 4097)]
    if use_json:
        argv.append("--json")
    assert cli.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "aegis approve: --reason must be at most 4096 characters\n"


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_exemption_refuses_injected_current_governance_approval(review_repo, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    repo = review_repo
    fix = repo.head()
    digest = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")

    def forbidden(*args, **kwargs):
        pytest.fail("injected trailers must be refused before preflight, custody, prompting or signing")

    monkeypatch.setattr(approve, "_preflight", forbidden)
    monkeypatch.setattr(approve, "input", forbidden, raising=False)
    monkeypatch.setattr(human_gate, "check_key_custody", forbidden)
    monkeypatch.setattr(human_gate, "signed_empty_commit", forbidden)
    trailers = [f"Aegis-Approve: {digest}", f"Aegis-Approve-Insight: {digest}",
                f"Aegis-Exempt-Test: {fix} also exempt", "Aegis-Accept: reserved"]
    for trailer in trailers:
        argv = ["approve", "--workspace", str(repo.root), "--base", "main",
                "--exempt-test", fix, "--reason", "checked\n" + trailer]
        if use_json:
            argv.append("--json")
        assert cli.main(argv) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "aegis approve: --reason must be one line of printable text\n"
    assert repo.head() == fix


@pytest.mark.parametrize("exempt", [False, True], ids=["governance", "exemption"])
@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_missing_printable_base_refusal_keeps_fetch_guidance(review_repo, monkeypatch, capsys, exempt, use_json):
    from aegis_cli import approve

    def forbidden(*args, **kwargs):
        pytest.fail("a missing base must be refused before custody or prompting")

    monkeypatch.setattr(human_gate, "check_key_custody", forbidden)
    monkeypatch.setattr(approve, "input", forbidden, raising=False)
    base = "missingFORGED"
    argv = ["approve", "--workspace", str(review_repo.root), "--base", base]
    if exempt:
        argv += ["--exempt-test", "HEAD", "--reason", "checked by hand"]
    if use_json:
        argv.append("--json")
    assert cli.main(argv) == 1
    captured = capsys.readouterr()
    assert "\x1b" not in captured.out + captured.err
    if use_json:
        doc = json.loads(captured.out)
        assert doc["status"] == "refused" and doc["code"] == "no_base"
        assert doc["reason"] == f"HEAD shares no history with {base}: fetch with fetch-depth 0"
        assert captured.err == ""
    else:
        assert captured.out == ""
        assert captured.err == "aegis approve: HEAD shares no history with missingFORGED: fetch with fetch-depth 0\n"


@pytest.mark.parametrize("exempt", [False, True], ids=["governance", "exemption"])
@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_nonprintable_base_is_refused_before_git(tmp_path, monkeypatch, capsys, exempt, use_json):
    from aegis_cli import approve

    def forbidden(*args, **kwargs):
        pytest.fail("invalid bases must be refused before git, review, custody, prompting or signing")

    monkeypatch.setattr(approve, "_preflight", forbidden)
    monkeypatch.setattr(approve, "sanitize_display", forbidden)
    monkeypatch.setattr(approve, "input", forbidden, raising=False)
    monkeypatch.setattr(human_gate, "check_key_custody", forbidden)
    monkeypatch.setattr(human_gate, "signed_empty_commit", forbidden)
    bases = ["@^{/\x1b]0;|sneaky|\x07main}", "main^{/|\x1b]0;\x07: aegis-state\x1b]}",
             "missing\x1b]FORGED", "missing\x1b[2JFORGED"]
    chars = [chr(code) for code in (*range(32), *range(127, 160))]
    chars += ["\u061c", "\u200d", "\u202e", "\u2028", "\u2029", "\u2066", "\ufeff", "\ud800"]
    bases += ["main" + char for char in chars]
    for base in bases:
        argv = ["approve", "--workspace", str(tmp_path), "--base", base]
        if exempt:
            argv += ["--exempt-test", "HEAD", "--reason", "checked by hand"]
        if use_json:
            argv.append("--json")
        assert cli.main(argv) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "aegis approve: --base must be one line of printable text\n"


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_base_limit_precedes_scanning_or_git(tmp_path, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    class LengthOnly(str):
        def __iter__(self):
            pytest.fail("oversized bases must not be scanned")

        def strip(self, *args):
            pytest.fail("oversized bases must not be trimmed")

    def forbidden(*args, **kwargs):
        pytest.fail("oversized bases must not reach git")

    monkeypatch.setattr(approve, "_preflight", forbidden)
    argv = ["approve", "--workspace", str(tmp_path), "--base", LengthOnly("x" * 4097)]
    if use_json:
        argv.append("--json")
    assert cli.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "aegis approve: --base must be at most 4096 characters\n"


@pytest.mark.parametrize("exempt", [False, True], ids=["governance", "exemption"])
@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_review_identifies_resolved_base_and_sanitizes_subject(review_repo, monkeypatch, capsys, exempt, use_json):
    from aegis_cli import approve

    repo = review_repo
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "weaker"))
    repo.write(".github/workflows/ci.yml", "name: weakened\n")
    subject = "sneaky\x1b]0;title\x07 suffix\x1b]"
    selected = repo.commit(subject)
    repo.write(".aegis/config.json", '{"changed": true}\n')
    fix = repo.commit("config only")
    # Real Git resolves the exact Argon selector to the weakened commit, unlike its display.
    assert repo.git("rev-parse", "@^{/\x1b]0;|sneaky|\x07main}") == selected
    main_commit = repo.git("rev-parse", "main")
    repo.git("checkout", "-q", "-b", "other-base", "main")
    repo.write("README.md", "# divergent base\n")
    divergent = repo.commit("divergent base")
    repo.git("checkout", "-q", "work")
    signed = []
    verified = []
    monkeypatch.setattr(human_gate, "check_key_custody",
                        lambda top: human_gate.KeyCustody("hardware", "protected", False))

    def sign(top, message, *, interactive):
        signed.append(message)
        return "a" * 40

    def verify(top, commit, value, base):
        verified.append((value, base))
        return human_gate.Approval(True, "approved", "signature verified", commit)

    monkeypatch.setattr(human_gate, "signed_empty_commit", sign)
    monkeypatch.setattr(human_gate, "verify_test_exemption" if exempt else "verify_approval", verify)
    for base, oid, title in [("@^{/sneaky}", selected, "sneaky suffix]"), (None, main_commit, "base"),
                             ("other-base", divergent, "divergent base")]:
        before_prompt = []

        def confirm(prompt=""):
            before_prompt.append(capsys.readouterr())
            if base == "other-base":
                repo.git("branch", "-f", "other-base", fix)
            return "y"

        monkeypatch.setattr(approve, "input", confirm, raising=False)
        argv = ["approve", "--workspace", str(repo.root)]
        if base is not None:
            argv += ["--base", base]
        if exempt:
            argv += ["--exempt-test", fix, "--reason", "checked by hand"]
        if use_json:
            argv.append("--json")
        assert cli.main(argv) == 0
        after = capsys.readouterr()
        assert len(before_prompt) == 1
        review = before_prompt[0].err if use_json else before_prompt[0].out
        label = f"{base or 'main'} (= {oid} {title})"
        if base == "other-base":
            label += f"; comparison starts at {main_commit}"
        assert (f"Base: {label}\n" if exempt else f"Governance changed since {label}: ") in review
        assert "\x1b" not in review and "\x07" not in review
        assert verified[-1][1] == oid
        if exempt:
            assert signed[-1] == human_gate.exemption_message(fix, "checked by hand")
        else:
            digest = human_gate.governance_tree_hash(repo.root, fix, base=oid)
            assert f"Governance tree hash: {digest}\n" in review
            assert signed[-1] == human_gate.approval_message(digest)
            if base == "@^{/sneaky}":
                assert f"Governance changed since {label}: aegis-state\n" in review
            else:
                assert "rules" in review and "workflows" in review and "aegis-state" in review
        if use_json:
            doc = json.loads(after.out)
            assert doc["status"] == "approved" and doc["base"] == (base or "main")


@pytest.mark.parametrize("exempt", [False, True], ids=["governance", "exemption"])
@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_review_escapes_format_controls_from_git_and_environment(review_repo, monkeypatch, capsys, exempt, use_json):
    from aegis_cli import approve

    repo = review_repo
    main = repo.git("rev-parse", "main")
    monkeypatch.setattr(human_gate, "check_key_custody",
                        lambda top: human_gate.KeyCustody("agent", "key\u202e\u2067: custody explanation", True))
    for control in ("\u202e", "\u2067"):
        escaped = control.encode("unicode_escape").decode("ascii")
        branch = "review-base" + control
        repo.git("checkout", "-q", "-b", branch, "main")
        repo.write("README.md", "# divergent review base\n")
        base_commit = repo.commit("benign" + control + " caf\u00e9")
        repo.git("checkout", "-q", "work")
        monkeypatch.setenv("GITHUB_BASE_REF", branch)
        before_prompt = []

        def confirm(prompt=""):
            before_prompt.append(capsys.readouterr())
            return "n"

        monkeypatch.setattr(approve, "input", confirm, raising=False)
        argv = ["approve", "--workspace", str(repo.root)]
        if exempt:
            argv += ["--exempt-test", "HEAD", "--reason", "checked caf\u00e9 by hand"]
        if use_json:
            argv.append("--json")
        assert cli.main(argv) == 1
        after = capsys.readouterr()
        assert len(before_prompt) == 1
        review = before_prompt[0].err if use_json else before_prompt[0].out
        assert (before_prompt[0].out if use_json else before_prompt[0].err) == ""
        label = f"review-base{escaped} (= {base_commit} benign{escaped} caf\u00e9); comparison starts at {main}"
        if exempt:
            assert f"Base: {label}\nExempting fix commit: {repo.head()}\nReason: checked caf\u00e9 by hand\n" in review
        else:
            assert f"Governance changed since {label}: aegis-state\nGovernance tree hash: " in review
        assert "  warning: key\\u202e\\u2067: custody explanation\n" in review
        assert all(char.isprintable() or char == "\n" for char in review)
        if use_json:
            doc = json.loads(after.out)
            assert doc["code"] == "declined" and doc["status"] == "declined"
            assert "[y/N]" in review
        else:
            assert after.out == "No approval made.\n" and after.err == ""


@pytest.mark.parametrize("exempt", [False, True], ids=["governance", "exemption"])
@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_review_escapes_governance_file_paths(review_repo, monkeypatch, capsys, exempt, use_json):
    from aegis_cli import approve

    repo = review_repo
    paths = [".aegis/rules/traps/trap-\u202e.md", ".aegis/rules/traps/trap-\u2067.md"]
    for path in paths:
        repo.write(path, hg.RULE)
    fix = repo.commit("governance paths")
    monkeypatch.setattr(human_gate, "check_key_custody", lambda top: human_gate.KeyCustody("hardware", "protected", False))
    before_prompt = []

    def confirm(prompt=""):
        before_prompt.append(capsys.readouterr())
        return "n"

    monkeypatch.setattr(approve, "input", confirm, raising=False)
    argv = ["approve", "--workspace", str(repo.root), "--base", "main"]
    if exempt:
        argv += ["--exempt-test", fix, "--reason", "checked by hand"]
    if use_json:
        argv.append("--json")
    assert cli.main(argv) == 1
    after = capsys.readouterr()
    assert len(before_prompt) == 1
    review = before_prompt[0].err if use_json else before_prompt[0].out
    expected = ", ".join(path.encode("unicode_escape").decode("ascii") for path in [".aegis/config.json", *paths])
    assert f"Governance paths changed: {expected}\n" in review
    assert all(char.isprintable() or char == "\n" for char in review)
    if use_json:
        assert json.loads(after.out)["code"] == "declined" and "[y/N]" in review


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_exemption_path_read_failure_is_a_fixed_refusal(review_repo, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    def fail(*args, **kwargs):
        raise approve.gitsafe.GitError("untrusted\u202e\u2067")

    def forbidden(*args, **kwargs):
        pytest.fail("a path-read failure must be refused before custody or confirmation")

    monkeypatch.setattr(approve, "gitsafe", SimpleNamespace(**dict(vars(approve.gitsafe), diff_entries=fail)))
    monkeypatch.setattr(human_gate, "check_key_custody", forbidden)
    monkeypatch.setattr(approve, "input", forbidden, raising=False)
    argv = ["approve", "--workspace", str(review_repo.root), "--base", "main",
            "--exempt-test", "HEAD", "--reason", "checked by hand"]
    if use_json:
        argv.append("--json")
    assert cli.main(argv) == 1
    captured = capsys.readouterr()
    message = "git could not list governance paths for review"
    if use_json:
        doc = json.loads(captured.out)
        assert doc["code"] == "git_failed" and doc["reason"] == message
        assert captured.err == ""
    else:
        assert captured.out == "" and captured.err == f"aegis approve: {message}\n"


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_review_escapes_all_remaining_nonprintable_classes(review_repo, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    characters = ["\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u200e", "\u200f", "\u200b",
                  "\u2028", "\u2029", "\u00a0", "\u00ad", "\U000e0001", "\ud800"]
    detail = "custody " + "|".join(characters) + ": trusted suffix"
    expected = "custody " + "|".join(char.encode("unicode_escape").decode("ascii") for char in characters) + ": trusted suffix"
    monkeypatch.setattr(human_gate, "check_key_custody", lambda top: human_gate.KeyCustody("agent", detail, True))
    before_prompt = []

    def confirm(prompt=""):
        before_prompt.append(capsys.readouterr())
        return "n"

    monkeypatch.setattr(approve, "input", confirm, raising=False)
    argv = ["approve", "--workspace", str(review_repo.root), "--base", "main"]
    if use_json:
        argv.append("--json")
    assert cli.main(argv) == 1
    after = capsys.readouterr()
    assert len(before_prompt) == 1
    review = before_prompt[0].err if use_json else before_prompt[0].out
    assert f"  warning: {expected}\n" in review
    assert all(char.isprintable() or char == "\n" for char in review)
    if use_json:
        assert json.loads(after.out)["code"] == "declined"


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_base_subject_failures_are_fixed_refusals(review_repo, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    real_run = approve.gitsafe.run

    class SizeLengthOnly(bytes):
        def removesuffix(self, suffix):
            pytest.fail("an oversized size numeral must be refused before copying or parsing")

    invalid_types = {"wrong_type": b"blob\n", "padded_type": b" commit\n", "extra_type_line": b"commit\n\n"}
    invalid_sizes = {"malformed_size": b"malformed\n", "empty_size": b"\n", "negative_size": b"-1\n",
                     "padded_size": b" 1\n", "extra_size_line": b"1\n2\n",
                     "long_size": SizeLengthOnly(b"9" * 21 + b"\n")}
    for failure in ("type_error", "type_failed", *invalid_types, "size_error", "size_failed", *invalid_sizes,
                    "oversized", "subject_error", "subject_failed"):
        with monkeypatch.context() as patch:
            def run(args, top, **kwargs):
                if args[:2] == ["cat-file", "-t"]:
                    if failure == "type_error":
                        raise approve.gitsafe.GitError("untrusted\x1b]input")
                    if failure == "type_failed":
                        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"untrusted")
                    if failure in invalid_types:
                        return SimpleNamespace(returncode=0, stdout=invalid_types[failure], stderr=b"")
                if args[:2] == ["cat-file", "-s"]:
                    if failure in invalid_types or failure.startswith("type_"):
                        pytest.fail("an invalid object type must be refused before the size read")
                    if failure == "size_error":
                        raise approve.gitsafe.GitError("untrusted\x1b]input")
                    if failure == "size_failed":
                        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"untrusted")
                    if failure in invalid_sizes:
                        return SimpleNamespace(returncode=0, stdout=invalid_sizes[failure], stderr=b"")
                    if failure == "oversized":
                        return SimpleNamespace(returncode=0, stdout=b"1048577\n", stderr=b"")
                if args[0] == "log":
                    if not failure.startswith("subject_"):
                        pytest.fail("invalid or oversized metadata must be refused before the subject read")
                    if failure == "subject_error":
                        raise approve.gitsafe.GitError("untrusted\x1b]input")
                    if failure == "subject_failed":
                        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"untrusted")
                return real_run(args, top, **kwargs)

            patch.setattr(approve, "gitsafe", SimpleNamespace(**dict(vars(approve.gitsafe), run=run)))
            argv = ["approve", "--workspace", str(review_repo.root), "--base", "main"]
            if use_json:
                argv.append("--json")
            assert cli.main(argv) == 1
            captured = capsys.readouterr()
            message = ("base commit is too large to review (limit 1048576 bytes)" if failure == "oversized"
                       else "git could not read the base commit for review")
            if use_json:
                doc = json.loads(captured.out)
                assert doc["code"] == "git_failed" and doc["reason"] == message
                assert captured.err == ""
            else:
                assert captured.out == "" and captured.err == f"aegis approve: {message}\n"


@pytest.mark.parametrize("use_json", [False, True], ids=["text", "json"])
def test_dynamic_approve_diagnostics_are_safe_to_display(review_repo, monkeypatch, capsys, use_json):
    from aegis_cli import approve

    detail = "boundary\x1b[2JFORGED\r\nline\x07\u202e\u2067"
    for boundary, code in (("custody", "no_key"), ("git", "git_failed"), ("sign", "sign_failed"),
                           ("verify", detail)):
        with monkeypatch.context() as patch:
            patch.setattr(approve, "input", lambda prompt="": "y", raising=False)
            patch.setattr(human_gate, "check_key_custody", lambda top: human_gate.KeyCustody("hardware", "protected", False))

            def fail(*args, **kwargs):
                raise human_gate.HumanGateError(detail)

            if boundary == "custody":
                patch.setattr(human_gate, "check_key_custody", lambda top: human_gate.KeyCustody("unsupported", detail, False))
            elif boundary == "git":
                patch.setattr(human_gate, "governance_tree_hash", fail)
            elif boundary == "sign":
                patch.setattr(human_gate, "signed_empty_commit", fail)
            else:
                patch.setattr(human_gate, "signed_empty_commit", lambda *args, **kwargs: "a" * 40)
                patch.setattr(human_gate, "verify_approval", lambda *args: human_gate.Approval(False, detail, "unverified", "a" * 40))
            argv = ["approve", "--workspace", str(review_repo.root), "--base", "main"]
            if use_json:
                argv.append("--json")
            assert cli.main(argv) == (0 if boundary == "verify" else 1)
            captured = capsys.readouterr()
            shown = captured.err if use_json else captured.out + captured.err
            assert not any(char in shown for char in ("\x1b", "\r", "\x07", "\u202e", "\u2067"))
            if use_json:
                doc = json.loads(captured.out)
                if boundary == "verify":
                    assert doc["verified"] is False and doc["verification"]["code"] == detail
                else:
                    assert doc["status"] == "refused" and doc["code"] == code
                    assert detail in doc["reason"]
            else:
                assert "boundaryFORGED line\\u202e\\u2067" in shown
