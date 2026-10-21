"""The README is also the PyPI project page, so it has to work there too.

PyPI resolves no relative links and renders no mermaid, so the README links the
repository's files by absolute GitHub URLs. tests/unit/test_docs_links.py checks only
relative links; this module checks that every absolute link into this repository (and
every pyproject [project.urls] entry) names a path that exists here, a file for
``blob/`` and a directory for ``tree/``, spelled with the exact case GitHub needs. It
also holds ADR 0005 AD-8 to its word: the README states the enforcement tiers exactly as
``aegis doctor`` reports them. The rest runs what the README tells a newcomer to run and
holds its claims to what the code does: the quick start, which files ``aegis check``
sees, what CI can and cannot judge, the install remedies and which hosts ``aegis init``
registers today.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
README = ROOT / "README.md"
HOW = ROOT / "docs" / "how-it-works.md"
PYPROJECT = ROOT / "pyproject.toml"
REPO_URL = "https://github.com/nseney1/Aegis-Guardrails"

# Strict xfails for links whose target another lane of the same wave creates; an XPASS
# fails the suite, so each entry must go when that lane lands.
DEFERRED: dict = {}

_REPO_LINK = re.compile(re.escape(REPO_URL) + r"/(blob|tree)/main/([^\s)\"'<>#?]+)")


def repo_links(text: str) -> List[Tuple[str, str]]:
    """(kind, path) for each absolute link into this repository's main branch, in order."""
    found = []
    for match in _REPO_LINK.finditer(text):
        link = (match.group(1), match.group(2).rstrip("/"))
        if link not in found:
            found.append(link)
    return found


def _exists_with_exact_case(root: Path, parts: List[str]) -> bool:
    here = root
    for part in parts:
        try:
            names = os.listdir(here)
        except OSError:
            return False
        if part not in names:
            return False
        here = here / part
    return True


def link_problem(root: Path, kind: str, path: str) -> Optional[str]:
    """Why ``kind``/``path`` does not resolve inside ``root``, or None when it does.

    GitHub matches the case exactly, so a path only a case-insensitive checkout
    finds is a problem too.
    """
    parts = path.split("/")
    target = root.joinpath(*parts)
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        return f"{path} is outside the repository"
    found = _exists_with_exact_case(root, parts)
    if kind == "blob" and not (found and target.is_file()):
        return f"blob/main/{path} is not a file in the repository"
    if kind == "tree" and not (found and target.is_dir()):
        return f"tree/main/{path} is not a directory in the repository"
    return None


def _all_links() -> List[Tuple[str, str]]:
    links = repo_links(README.read_text(encoding="utf-8"))
    for link in repo_links(PYPROJECT.read_text(encoding="utf-8")):
        if link not in links:
            links.append(link)
    return links


def _params():
    for kind, path in _all_links():
        reason = DEFERRED.get(path)
        marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
        yield pytest.param(kind, path, id=f"{kind}/{path}", marks=marks)


@pytest.mark.parametrize("kind,path", list(_params()))
def test_absolute_repository_links_resolve(kind, path):
    assert link_problem(ROOT, kind, path) is None


def test_the_readme_links_the_docs_by_absolute_url():
    """Without absolute links the PyPI page has no way into the docs."""
    paths = {path for _, path in _all_links()}
    assert {"docs/how-it-works.md", "docs/reference.md"} <= paths


def test_the_readme_has_no_mermaid_block():
    """PyPI shows a mermaid fence as raw text; diagrams belong in docs/."""
    assert not re.search(r"^ {0,3}(`{3,}|~{3,})\s*mermaid", README.read_text(encoding="utf-8"), re.M)


def test_the_readme_states_the_enforcement_tiers_as_doctor_reports_them(tmp_path, monkeypatch, capsys):
    """AD-8: `aegis doctor` reports each tier and the README states it verbatim.

    Doctor runs in an empty directory on a fake machine (own HOME, an empty PATH, host
    CLIs refused), so no real host is read or started.
    """
    from aegis_cli import doctor
    from aegis_cli.cli import main

    home, empty_bin, work = tmp_path / "home", tmp_path / "bin", tmp_path / "work"
    for directory in (home, empty_bin, work):
        directory.mkdir()
    for name, value in (("HOME", home), ("USERPROFILE", home), ("PATH", empty_bin),
                        ("APPDATA", home / "AppData" / "Roaming")):
        monkeypatch.setenv(name, str(value))
    for name in ("CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "CODEX_HOME", "AEGIS_WORKSPACE", "AEGIS_CLIENT"):
        monkeypatch.delenv(name, raising=False)

    def refuse(argv, *args, **kwargs):
        raise AssertionError(f"a host CLI was started: {argv}")

    monkeypatch.setattr(doctor, "_run_host_cli", refuse)
    monkeypatch.chdir(work)
    main(["doctor", "--json", "--workspace", str(work)])
    tiers = json.loads(capsys.readouterr().out)["enforcement_tiers"]

    readme = README.read_text(encoding="utf-8")
    assert [t["tier"] for t in tiers] == ["advisory", "best_effort", "local_floor", "authoritative"]
    for tier in tiers:
        name = tier["tier"].replace("_", " ").capitalize().replace("Best effort", "Best-effort")
        row = re.search(rf"^\|\s*{re.escape(name)}\s*\|\s*{re.escape(tier['mechanism'])}\s*\|", readme, re.M)
        assert row, f"README has no tier row '| {name} | {tier['mechanism']} |'"


# --- the README's claims, run --------------------------------------------------------

def _section(text: str, heading: str) -> str:
    """The body of the ``## heading`` section, up to the next level-2 heading."""
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert match, f"no '## {heading}' section"
    return match.group(1)


def _lead(text: str) -> str:
    """The first prose paragraph after the H1 (skipping leading badge lines): GitHub's and PyPI's opening words."""
    return re.search(r"^# .*\n+(?:\[!\[[^\n]+\n+)*(.+?)\n", text).group(1)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _aegis(capsys, *argv: str) -> Tuple[int, str]:
    from aegis_cli.cli import main

    capsys.readouterr()
    try:
        code = main(list(argv))
    except SystemExit as exc:
        code = exc.code
    return code, capsys.readouterr().out


@pytest.fixture
def quick_start(tmp_path, monkeypatch):
    """A repository after the README's quick start: ``aegis init`` and the saved no-eval rule.

    The machine is fake (own HOME, no host registered, host CLIs refused) and the
    pre-commit hook is skipped, so no real host or git hook is touched.
    """
    from aegis_cli import install_hosts

    home = tmp_path / "home"
    home.mkdir()
    for name, value in (("HOME", home), ("USERPROFILE", home), ("XDG_CONFIG_HOME", home / ".config"),
                        ("APPDATA", home / "AppData" / "Roaming")):
        monkeypatch.setenv(name, str(value))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GITHUB_BASE_REF", "GIT_DIR", "GIT_WORK_TREE"):
        monkeypatch.delenv(name, raising=False)

    def refuse(argv, *args, **kwargs):
        raise AssertionError(f"a host CLI was started: {argv}")

    monkeypatch.setattr(install_hosts, "_run_cli", refuse)

    repo = tmp_path / "my-app"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("# my-app\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "init")
    monkeypatch.chdir(repo)

    from aegis_cli.cli import main
    assert main(["init", "--yes", "--no-hooks", "--workspace", str(repo)]) in (0, None)

    rule = re.search(r"```markdown\n(---\nid: no-eval\n.*?)```", README.read_text(encoding="utf-8"), re.S)
    assert rule, "the README quick start has no no-eval rule block"
    target = repo / ".aegis" / "rules" / "invariants" / "no-eval.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rule.group(1), encoding="utf-8")
    return repo


def _commit_as_the_quick_start_says(repo: Path) -> None:
    """Plain `aegis check` enforces the reviewed rules, so the quick start commits `.aegis/` first."""
    assert 'git add .aegis AGENTS.md && git commit -m "Add Aegis"' in README.read_text(encoding="utf-8")
    _git(repo, "add", ".aegis", "AGENTS.md")
    _git(repo, "commit", "-q", "-m", "Add Aegis")


def test_the_quick_start_check_fails_as_shown_once_the_new_file_is_tracked(quick_start, capsys):
    """`aegis check` with no files skips untracked ones, so the README must say how to
    include a new file (git add it, or name it); then the check fails as the README shows."""
    _commit_as_the_quick_start_says(quick_start)
    (quick_start / "app.py").write_text('x = eval("1")\n', encoding="utf-8")

    code, out = _aegis(capsys, "check", "--workspace", str(quick_start))
    assert code == 0 and "no-eval" not in out, "an untracked file is now checked: update the README"

    code, out = _aegis(capsys, "check", "--workspace", str(quick_start), "app.py")
    assert code == 1 and "forbid_ast:no-eval" in out

    readme = README.read_text(encoding="utf-8")
    shown = re.search(r"```text\n(\$ git add app\.py\n\$ aegis check\n.*?)```", readme, re.S)
    assert shown, "the quick start does not show `git add app.py` before `aegis check`"
    _git(quick_start, "add", "app.py")
    code, out = _aegis(capsys, "check", "--workspace", str(quick_start))
    assert code == 1
    for line in shown.group(1).splitlines():
        if not line.startswith("$ "):
            assert line in out, f"README output line not printed by aegis check: {line!r}"

    quick = _section(readme, "Quick start")
    assert "untracked" in quick.lower() and "aegis check app.py" in quick
    which_files = re.search(r"^\*\*Which files\.\*\*.*$", HOW.read_text(encoding="utf-8"), re.M)
    assert which_files and "untracked" in which_files.group(0).lower()


def test_the_quick_start_no_eval_rule_allows_method_calls_via_builtin_true(quick_start, capsys):
    """The README and how-it-works no-eval rule examples use `builtin: true` so method calls
    such as `model.eval()` pass `aegis check` while builtin `eval("1")` fails."""
    for doc in (README, HOW):
        text = doc.read_text(encoding="utf-8")
        assert "builtin: true" in text, f"{doc.name} no-eval example is missing builtin: true"

    _commit_as_the_quick_start_says(quick_start)
    (quick_start / "app.py").write_text("def infer(model):\n    model.eval()\n    return 1\n", encoding="utf-8")
    _git(quick_start, "add", "app.py")
    code, out = _aegis(capsys, "check", "--workspace", str(quick_start))
    assert code == 0 and "forbid_ast:no-eval" not in out, out

    (quick_start / "app.py").write_text('x = eval("1")\n', encoding="utf-8")
    _git(quick_start, "add", "app.py")
    code, out = _aegis(capsys, "check", "--workspace", str(quick_start))
    assert code == 1 and "forbid_ast:no-eval" in out, out


def test_the_readme_uses_progressive_disclosure_and_three_step_quick_start():
    """The README leads Quick start with a 3-step loop and wraps advanced internals in
    collapsible <details> blocks."""
    readme = README.read_text(encoding="utf-8")
    quick = _section(readme, "Quick start")
    for step in ("Step 1", "Step 2", "Step 3"):
        assert step in quick, f"Quick start is missing {step}"
    details_blocks = re.findall(r"<details>\s*<summary>.*?</summary>.*?</details>", readme, re.S)
    assert len(details_blocks) >= 3, "expected at least 3 progressive-disclosure <details> blocks in README.md"



RETRACTED_ENFORCEMENT = (
    "only tier an agent cannot skip",
    "only step an agent cannot skip",
    "no one, when branch protection",
    "protected by git review and ci",
)


def test_the_docs_say_plain_check_enforces_the_reviewed_rules(quick_start, capsys, monkeypatch):
    """Plain `aegis check` enforces the reviewed (base) rules where `origin/HEAD` resolves, and the
    pull request's own rules in CI, where it does not. The docs say both and never call CI tamper-proof."""
    _git(quick_start, "add", "-A")
    _git(quick_start, "commit", "-q", "-m", "aegis")
    _git(quick_start, "branch", "main-base")
    _git(quick_start, "checkout", "-q", "-b", "agent-pr")
    _git(quick_start, "rm", "-q", ".aegis/rules/invariants/no-eval.md")
    (quick_start / "app.py").write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    _git(quick_start, "add", "app.py")
    _git(quick_start, "commit", "-q", "-m", "pr")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    code, out = _aegis(capsys, "check", "--workspace", str(quick_start))  # CI: no origin/HEAD
    assert code == 0, out
    _git(quick_start, "update-ref", "refs/remotes/origin/main", "main-base")  # what a clone has
    _git(quick_start, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    code, out = _aegis(capsys, "check", "--workspace", str(quick_start))
    assert code == 1 and "forbid_ast:no-eval" in out, out

    for doc in (README, HOW):
        text = " ".join(doc.read_text(encoding="utf-8").lower().replace("*", "").replace("`", "").split())
        assert [p for p in RETRACTED_ENFORCEMENT if p in text] == [], doc.name
        assert "a pull request that deletes a rule and breaks it fails plain check there" in text, doc.name
        assert "plain check enforces the pull request's own rules and aegis check --ci is what catches" in text, doc.name

def test_the_readme_gives_the_install_remedies_aegis_itself_prints(tmp_path):
    """pip refuses a system install on PEP 668 systems, and pip's scripts directory may not
    be on PATH. `aegis init` and `aegis doctor` print a remedy for each; so must the README."""
    from aegis_cli.pathcheck import build_hint

    nowhere = {"env": {"PATH": ""}, "which": lambda *a, **k: None, "os_name": "posix"}
    not_installed = build_hint(candidates=[], **nowhere)
    scripts = tmp_path / ".local" / "bin"
    scripts.mkdir(parents=True)
    (scripts / "aegis").write_text("", encoding="utf-8")
    off_path = build_hint(candidates=[str(scripts)], home=str(tmp_path), platform="linux",
                          shell="bash", venv_prefix=None, **nowhere)

    pipx = re.search(r"pipx install [\w.-]+", not_installed).group(0)
    quick = _section(README.read_text(encoding="utf-8"), "Quick start")
    assert pipx in quick
    assert "externally-managed-environment" in quick
    # The script pip --user installed, by its full path: what the PATH fix adds.
    assert f"was installed to {scripts}" in off_path and "~/.local/bin/aegis" in quick
    assert "pipx ensurepath" in quick and "activate the virtual environment" in quick


def test_the_readme_never_advises_running_aegis_with_python_dash_m():
    """Release review: `python3 -m aegis_cli` (and `-m aegis_mcp`) put the current directory
    first on sys.path, so in a cloned repository they run its own aegis_* packages."""
    readme = README.read_text(encoding="utf-8")
    advice = re.findall(r"python3? -m aegis_\w+", readme)
    assert all("Do not fall back to `" + a in readme for a in advice), advice
    how = HOW.read_text(encoding="utf-8")
    assert "-m aegis_mcp" not in how.replace("never registers `python -m aegis_mcp`", "")


UNSAFE_KINDS = "a Python that runs `-m` or `-c` without `-I` or a script by a relative path, or either behind `env`"


def test_the_docs_name_the_unsafe_registrations_doctor_reports():
    """how-it-works, SECURITY and the changelog list what `aegis doctor` calls an unsafe MCP
    registration: each kind they name is one launch_risk flags, and isolated mode is not."""
    import sys

    from aegis_cli.install_hosts import launch_risk

    for doc in (HOW, ROOT / "SECURITY.md", ROOT / "CHANGELOG.md"):
        assert UNSAFE_KINDS in doc.read_text(encoding="utf-8"), doc.name
    py = sys.executable
    env = os.path.join(os.path.dirname(py), "env")
    for argv in (["aegis-mcp"], [py, "-m", "aegis_mcp"], [py, "-c", "x"], [py, "aegis_mcp/server.py"],
                 [env, "python3", "-m", "aegis_mcp"], [env, py, "aegis_mcp/server.py"]):
        assert launch_risk(argv), argv
    for argv in ([py, "-I", "-m", "aegis_mcp"], [py, "-I", "-c", "x"], [env, py, "-I", "-c", "x"]):
        assert launch_risk(argv) is None, argv


def _description() -> str:
    return re.search(r'^description = "(.*)"$', PYPROJECT.read_text(encoding="utf-8"), re.M).group(1)


def test_the_opening_names_every_host_init_registers_with_no_version_qualifier():
    """The opening words name every verified host `aegis init --host` registers (search
    snippets stop near 160 characters), and neither they nor the PyPI summary qualify one
    of them with a later version. An experimental row (verified=False, such as Kiro or Cursor) is
    listed in the host table, not promised in the opening."""
    from aegis_cli.install_hosts import parse_hosts, registrable_hosts

    lead = _lead(README.read_text(encoding="utf-8"))
    named = [h for h in registrable_hosts() if h.verified]
    assert {h.display_name for h in named} == {"Claude Code", "Codex CLI", "Antigravity"}
    assert {h.id for h in registrable_hosts() if not h.verified} == {"kiro", "cursor", "copilot", "windsurf"}
    for host in named:
        assert parse_hosts(host.id) == [host.id]
        assert host.display_name in lead[:160], host.display_name
        for where, text in (("README lead", lead), ("pyproject description", _description())):
            qualified = re.search(rf"{re.escape(host.display_name)} \([^)]*\bv4\.\d", text)
            assert not qualified, f"{where}: {host.display_name}"


def _keywords() -> List[str]:
    block = re.search(r"^keywords = \[(.*?)\]", PYPROJECT.read_text(encoding="utf-8"), re.M | re.S).group(1)
    return re.findall(r'"([^"]*)"', block)


def test_the_retired_gemini_cli_is_promised_nowhere():
    """Gemini CLI is retired (aegis_core.hosts): `aegis init --host gemini-cli` is refused for
    good, so no line of the README or how-it-works that names it may promise a version or
    tell the reader to register it by hand, and the PyPI summary and keywords drop it."""
    lines = (README.read_text(encoding="utf-8").splitlines() + HOW.read_text(encoding="utf-8").splitlines()
             + [_description()])
    promises = [line for line in lines
                if ("Gemini CLI" in line or "gemini-cli" in line) and re.search(r"\bv4\.\d", line)]
    assert promises == []
    assert [line for line in lines if "gemini mcp add" in line] == []
    assert "Gemini CLI" not in _description()
    assert "gemini-cli" not in _keywords()


def _refusal(capsys, argv: List[str]) -> Tuple[int, str]:
    from aegis_cli.cli import main

    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code, capsys.readouterr().err


def test_the_docs_state_the_gemini_cli_retirement_as_aegis_refuses_it(tmp_path, monkeypatch, capsys):
    """`init` and `uninstall --host gemini-cli` exit 2 with the host table's retirement line. The
    README host table says the host is retired and names Antigravity in its place, and the
    CHANGELOG's 4.0.0 entry quotes the refusal word for word."""
    from aegis_core.hosts import get

    for name, value in (("HOME", tmp_path), ("USERPROFILE", tmp_path), ("XDG_CONFIG_HOME", tmp_path / ".config")):
        monkeypatch.setenv(name, str(value))
    retired = get("gemini-cli").retired
    assert retired
    for command in ("init", "uninstall"):
        code, err = _refusal(capsys, [command, "--host", "gemini-cli", "--dry-run", "--workspace", str(tmp_path)])
        assert code == 2 and err.rstrip().endswith(retired), (command, err)

    row = next((line for line in _section(README.read_text(encoding="utf-8"), "Works with your agents").splitlines()
                if line.startswith("| **Gemini CLI**")), "")
    assert "retired" in row.lower() and "Antigravity" in row, row

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    entry = re.search(r"^## \[4\.0\.0\].*?(?=^## \[|\Z)", changelog, re.M | re.S).group(0)
    assert retired in " ".join(entry.split())


# --- the link checker itself ---------------------------------------------------------

def test_repo_links_finds_blob_and_tree_links_and_drops_fragments():
    text = (
        f"[a]({REPO_URL}/blob/main/docs/a.md#part) [b]({REPO_URL}/tree/main/rules/) "
        f"[c](https://example.com/blob/main/x.md) [d]({REPO_URL}/blob/main/docs/a.md) "
        f"[e]({REPO_URL}/releases) <{REPO_URL}/blob/main/LICENSE>\n"
        f'Changelog = "{REPO_URL}/blob/main/CHANGELOG.md"\n'
    )
    assert repo_links(text) == [("blob", "docs/a.md"), ("tree", "rules"), ("blob", "LICENSE"),
                                ("blob", "CHANGELOG.md")]


def test_link_problem_requires_a_file_for_blob_and_a_directory_for_tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("x\n", encoding="utf-8")
    assert link_problem(tmp_path, "blob", "docs/a.md") is None
    assert link_problem(tmp_path, "tree", "docs") is None
    assert link_problem(tmp_path, "blob", "docs") == "blob/main/docs is not a file in the repository"
    assert link_problem(tmp_path, "tree", "docs/a.md") == "tree/main/docs/a.md is not a directory in the repository"
    assert link_problem(tmp_path, "blob", "docs/gone.md") == "blob/main/docs/gone.md is not a file in the repository"


@pytest.fixture
def case_insensitive_fs(tmp_path, monkeypatch):
    """Under tmp_path, Path.is_file/is_dir ignore case, as on default macOS and Windows
    file systems; everywhere else they behave as usual."""
    real_is_file, real_is_dir = Path.is_file, Path.is_dir

    def on_disk(path: Path) -> Path:
        try:
            parts = Path(os.path.abspath(str(path))).relative_to(tmp_path).parts
        except ValueError:
            return path
        here = tmp_path
        for part in parts:
            try:
                names = os.listdir(here)
            except OSError:
                return path
            here = here / next((n for n in names if n.casefold() == part.casefold()), part)
        return here

    monkeypatch.setattr(Path, "is_file", lambda self: real_is_file(on_disk(self)))
    monkeypatch.setattr(Path, "is_dir", lambda self: real_is_dir(on_disk(self)))


def test_link_problem_requires_the_exact_case_where_the_file_system_ignores_it(tmp_path, case_insensitive_fs):
    """GitHub resolves blob/tree paths case-sensitively; a checkout on macOS or Windows may not."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "How-It-Works.md").write_text("x\n", encoding="utf-8")
    assert (tmp_path / "DOCS" / "how-it-works.md").is_file(), "the case-insensitive emulation is off"

    assert link_problem(tmp_path, "blob", "docs/How-It-Works.md") is None
    assert link_problem(tmp_path, "tree", "docs") is None
    assert link_problem(tmp_path, "blob", "docs/how-it-works.md") == (
        "blob/main/docs/how-it-works.md is not a file in the repository")
    assert link_problem(tmp_path, "tree", "Docs") == "tree/main/Docs is not a directory in the repository"


def test_link_problem_rejects_paths_that_leave_the_repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside.md").write_text("x\n", encoding="utf-8")
    assert link_problem(root, "blob", "../outside.md") == "../outside.md is outside the repository"


# --- v4.1: what shipped, stated as the code does it ----------------------------------

def _flat(text: str) -> str:
    return " ".join(text.split())


def _registered_commands() -> List[str]:
    tree = json.loads((ROOT / "tests" / "contract" / "cli_tree.json").read_text(encoding="utf-8"))
    return sorted(entry["name"] for entry in tree["registry"])


def test_the_readme_lists_every_command_the_cli_registers():
    """'What's included' counts and names the CLI's commands; the contract snapshot, which
    tests/contract holds to the live parser, is the list."""
    included = _section(README.read_text(encoding="utf-8"), "What's included")
    match = re.search(r"A CLI\*\* with (\d+) commands \(([^)]*)\)", included)
    assert match, "the README no longer says 'A CLI** with N commands (...)'"
    named = sorted(re.findall(r"`([a-z]+)`", match.group(2)))
    assert named == _registered_commands()
    assert int(match.group(1)) == len(named)


def _current_minor() -> Tuple[int, int]:
    from aegis_core import _version

    parts = [int(p) for p in re.findall(r"\d+", _version.__version__)[:2]]
    return (parts[0], parts[1])


def _registered_mcp_tools() -> List[str]:
    data = json.loads((ROOT / "tests" / "contract" / "mcp_tools.json").read_text(encoding="utf-8"))
    return sorted(entry["name"] for entry in data["tools"])


def test_no_doc_calls_a_shipped_version_planned():
    """No user-facing doc may describe a version <= the current minor version as planned,
    future work, or unshipped, and no ADR targeting a shipped version may remain draft."""
    current = _current_minor()
    why = ROOT / "docs" / "why-aegis.md"
    security = ROOT / "SECURITY.md"
    versioned_patterns = (
        re.compile(r"\b(?:planned for|plan for)\s+v?(\d+)\.(\d+)\b"),
        re.compile(r"\bis\s+v?(\d+)\.(\d+)\s+work\b"),
        re.compile(r"\bafter\s+v?(\d+)\.(\d+)(?:\.\d+)?\s+ships\b"),
        re.compile(r"\bv?(\d+)\.(\d+)\s+plans to\b"),
        re.compile(r"\bv?(\d+)\.(\d+)\s+roadmap\b"),
    )
    describes_pattern = re.compile(r"\bdescribes aegis\s+v?(\d+)\.(\d+)\b")
    unconditional_stale = (
        "planned, not shipped",
        "is planned work",
        "not in this repository yet",
        "until they ship",
        "will copy the 15 packaged",
    )
    for doc in (README, HOW, why, security):
        text = _flat(doc.read_text(encoding="utf-8")).lower()
        for phrase in unconditional_stale:
            assert phrase not in text, (doc.name, phrase)
        for pattern in versioned_patterns:
            for match in pattern.finditer(text):
                ver = (int(match.group(1)), int(match.group(2)))
                assert ver > current, f"{doc.name} calls shipped v{ver[0]}.{ver[1]} planned: {match.group(0)!r}"
        for match in describes_pattern.finditer(text):
            ver = (int(match.group(1)), int(match.group(2)))
            assert ver == current, f"{doc.name} describes v{ver[0]}.{ver[1]} instead of v{current[0]}.{current[1]}"

    for adr in sorted((ROOT / "docs" / "adr").glob("*.md")):
        adr_text = adr.read_text(encoding="utf-8")
        title_line = adr_text.splitlines()[0] if adr_text else ""
        ver_match = re.search(r"\bv(\d+)\.(\d+)\b", title_line)
        if ver_match and (int(ver_match.group(1)), int(ver_match.group(2))) <= current:
            assert not re.search(r"^- \*\*Status\*\*:\s*draft\b", adr_text, re.M | re.I), (
                f"{adr.name} targets shipped v{ver_match.group(1)}.{ver_match.group(2)} but is still Status: draft"
            )


def test_how_it_works_lists_every_mcp_tool():
    """Section 4 of how-it-works names every tool in the MCP contract snapshot."""
    sec4 = _section(HOW.read_text(encoding="utf-8"), "4. Just-in-time delivery over MCP")
    named = sorted(set(re.findall(r"`(aegis_[a-z_]+)`", sec4)))
    assert named == _registered_mcp_tools()


def test_the_best_effort_row_states_each_hosts_hook_tier_as_doctor_reports_it():
    """AD-8: the Best-effort row names, per host, the tier and evidence label `aegis doctor`
    prints for a registered hook, that the hooks fail open, and where they are unavailable."""
    from aegis_cli.hooks import registrar
    from aegis_core.hosts import get

    row = re.search(r"^\| Best-effort \|[^\n]*$", README.read_text(encoding="utf-8"), re.M).group(0)
    for host in registrar.HOOK_HOSTS:
        said = f"{get(host).display_name}: {registrar.TIERS[host]} [{registrar.EVIDENCE[host]}]"
        assert said in row, said
    assert "fail open" in row and "Antigravity hooks are unavailable on Windows" in row
    assert "aegis hook install --host" in row


def test_the_readme_has_a_short_agent_teams_section():
    """Leases are cooperative conflict input; check --lane is the gate, self-attested unless
    --base-policy makes it witnessed. Details live in how-it-works."""
    teams = _flat(_section(README.read_text(encoding="utf-8"), "Agent teams"))
    for phrase in ("aegis team claim", "conflict input", "not a lock", "aegis check --lane",
                   "self-attested", "--base-policy", "witnessed", "advisory", "how-it-works.md"):
        assert phrase in teams, phrase
    assert len(teams.split()) < 220, "keep the README section short; details go to how-it-works"


def test_how_it_works_states_the_hook_runtime_as_the_code_runs_it():
    """The known gaps, the block and record sets, the scan window key with its default and
    range, and the exit codes per host are the ones the handler uses."""
    from aegis_cli.hooks import pretool, registrar
    from aegis_core import command_safety, config

    how = _flat(HOW.read_text(encoding="utf-8"))
    for gap in registrar.KNOWN_GAPS:
        assert _flat(gap) in how, gap
    for rule in command_safety.BLOCK_SET + command_safety.RECORD_SET:
        assert f"`{rule.id}`" in how, rule.id
    low, high = config.SCAN_WINDOW_RANGE
    assert f"`jit.scan_window_s` (default {config.DEFAULT_SCAN_WINDOW_S}, from {low} to {high})" in how
    assert f"exit {pretool.EXIT_AGY_BLOCK}" in how and f"exit {pretool.EXIT_BLOCK}" in how
    assert f"{int(pretool.DEADLINE_SECONDS)} s deadline" in how
    for host, matcher in registrar.MATCHERS.items():
        assert f"`{matcher}`" in how, host


def test_how_it_works_lists_the_scan_window_among_the_repo_config_keys():
    row = next(line for line in HOW.read_text(encoding="utf-8").splitlines()
               if line.startswith("| `.aegis/config.json` |"))
    assert "`jit.scan_window_s`" in row and "`jit.max_tokens`" in row


def test_how_it_works_describes_the_events_log_the_code_writes(tmp_path):
    """The events log lives in the git common dir (shared by every worktree), and the doc
    names every kind 4.1 writes."""
    from aegis_core import events

    _git(tmp_path, "init", "-q", "-b", "main")
    assert events.events_path(tmp_path).as_posix().endswith(".git/aegis/events.jsonl")
    how = _flat(HOW.read_text(encoding="utf-8"))
    assert "`<git common dir>/aegis/events.jsonl`" in how and "`.aegis/state/events.jsonl`" in how
    for kind in ("lease_claimed", "lease_denied", "lane_check", "scan_gate", "guard_match", "skills_sync"):
        assert f"`{kind}`" in how, kind
    assert set(events.KINDS) >= {"lease_claimed", "lease_denied", "lane_check", "scan_gate", "guard_match",
                                 "skills_sync"}


def test_how_it_works_shows_the_skills_marker_sync_writes(tmp_path):
    """The provenance marker in the doc is the one `aegis skills sync` writes, and the
    overwrite rules match: unedited copies replaced, edited ones only with --force, files
    without the marker never."""
    how = _flat(HOW.read_text(encoding="utf-8"))
    assert "`<!-- aegis:skill id=<id> v=1 sha=<12 hex> -->`" in how
    for phrase in (".claude/skills/<id>/SKILL.md", ".agents/skills/<id>/SKILL.md", "--force",
                   "never replaced, even with `--force`"):
        assert phrase in how, phrase
    from aegis_cli import skills_sync

    assert skills_sync.MARKER_VERSION == 1 and skills_sync.SHA_LEN == 12


def test_how_it_works_states_the_lane_gate_ci_caveat():
    how = _flat(HOW.read_text(encoding="utf-8"))
    for phrase in ("advisory (not a required check) in v4.1", "a witness is only as strong as the protection on",
                   "Assert weakening is not detected", "`refs/aegis/lanes/<lane>`"):
        assert phrase in how, phrase
