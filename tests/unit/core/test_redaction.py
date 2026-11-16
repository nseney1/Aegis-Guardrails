"""aegis_core.redaction: one secret table, the same output through every entry point (R-structure-32).

The goldens were recorded on the w14 merge commit (e7e61536), before the table moved out of
aegis_core.verification.scanners, through the three entry points that exist on both sides of the
move: the hook command log (aegis_cli.hooks.redaction.redact_secrets), stored insight text
(aegis_core.insights.redact_insight_text) and a scanner finding's snippet (scan_secrets_text).
The unterminated-PEM golden is corrected in w16; the move-era output leaked its body.
Tokens are assembled at run time so push protection never sees a literal.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Dict, Iterable, List, Tuple
import unicodedata

import pytest

from aegis_cli.hooks.redaction import redact_secrets
from aegis_core.gitsafe_policy import LOCAL_ENV
from aegis_core.insights import redact_insight_text
from aegis_core.verification.scanners import TIER_A_PATTERNS, scan_secrets_text

REPO = Path(__file__).resolve().parents[3]
PACKAGES = ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk")
# Reviewed parse-cost ratchet: retain headroom for ordinary source additions.
# Increasing this ceiling requires review; failures list all parsed paths.
REDACTION_PARSE_CEILING = 72


def _tok(*parts: str) -> str:
    return "".join(parts)


def _samples() -> Dict[str, str]:
    """The 11 Tier A formats, assembled as tests/unit/verification/test_scanners.py does."""
    return {
        "aws-access-key-id": _tok("AK", "IA", "9F8E7D6C5B4A3210"),
        "github-pat": _tok("gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
        "github-fine-grained-pat": _tok("github", "_pat_", "11ABCDEFG0123456789_abcdefghijklmnop"),
        "slack-token": _tok("xox", "b-", "123456789012-ABCDEFGHIJKLMN"),
        "stripe-live-secret": _tok("sk", "_live_", "9876543210abcdefghijklmnoPQR"),
        "openai-api-key": _tok("sk", "-proj-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"),
        "anthropic-api-key": _tok("sk", "-ant-", "api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
        "google-api-key": _tok("AI", "za", "SyD-9876543210abcdefghijklmnopqrstu"),
        "private-key-pem": _tok("-----BEGIN ", "RSA ", "PRIVATE KEY-----", "\\n", "MIIEowIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJ"),
        "jwt-three-segment": _tok("eyJ", "hbGciOiJIUzI1NiJ9", ".", "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".",
                                  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        "url-basic-auth": _tok("https://", "svc_admin", ":", "p9Q8r7S6t5U4", "@api.internal.corp/v1"),
    }


# "deploy --opt <sample> --next" through (hook log, insight text, scanner findings as (rule, tier, snippet)).
GOLDENS: Dict[str, Tuple[str, str, List[Tuple[str, str, str]]]] = {
    "aws-access-key-id": (
        "deploy --opt AKIA_REDACTED --next",
        "deploy --opt [REDACTED_AWS] --next",
        [("aws-access-key-id", "gate", "deploy --opt AKIA...10 --next")],
    ),
    "github-pat": (
        "deploy --opt ghp_REDACTED --next",
        "deploy --opt [REDACTED_VCS_TOKEN] --next",
        [("github-pat", "gate", "deploy --opt ghp_...r8 --next")],
    ),
    "github-fine-grained-pat": (
        "deploy --opt github_pat_REDACTED --next",
        "deploy --opt [REDACTED_VCS_TOKEN] --next",
        [("github-fine-grained-pat", "gate", "deploy --opt gith...op --next")],
    ),
    "slack-token": (
        "deploy --opt [REDACTED_TOKEN] --next",
        "deploy --opt [REDACTED_TOKEN] --next",
        [("slack-token", "gate", "deploy --opt xoxb...MN --next")],
    ),
    "stripe-live-secret": (
        "deploy --opt [REDACTED_API_KEY] --next",
        "deploy --opt [REDACTED_API_KEY] --next",
        [("stripe-live-secret", "gate", "deploy --opt sk_l...QR --next")],
    ),
    "openai-api-key": (
        "deploy --opt sk-REDACTED --next",
        "deploy --opt [REDACTED_API_KEY] --next",
        [("openai-api-key", "gate", "deploy --opt sk-p...cd --next")],
    ),
    "anthropic-api-key": (
        "deploy --opt sk-REDACTED --next",
        "deploy --opt [REDACTED_API_KEY] --next",
        [("anthropic-api-key", "gate", "deploy --opt sk-a...45 --next")],
    ),
    "google-api-key": (
        "deploy --opt AIzaSy_REDACTED --next",
        "deploy --opt [REDACTED_TOKEN] --next",
        [("google-api-key", "gate", "deploy --opt AIza...tu --next")],
    ),
    # Without a complete END marker, everything after the header may still be key material.
    "private-key-pem": (
        "deploy --opt [REDACTED_PEM]",
        "deploy --opt [REDACTED_PEM]",
        [("private-key-pem", "gate", "deploy --opt ----...--\\nMII...iJ --next")],
    ),
    "jwt-three-segment": (
        "deploy --opt [REDACTED_JWT] --next",
        "deploy --opt [REDACTED_JWT] --next",
        [("jwt-three-segment", "gate", "deploy --opt eyJh...5c --next")],
    ),
    "url-basic-auth": (
        "deploy --opt https://svc_admin:[REDACTED]@api.internal.corp/v1 --next",
        "deploy --opt https://svc_admin:[REDACTED]@api.internal.corp/v1 --next",
        [("url-basic-auth", "gate", "deploy --opt https://s...rp/v1 --next")],
    ),
}


def _scan(text: str) -> List[Tuple[str, str, str]]:
    return [(f.rule_id, f.tier, f.snippet) for f in scan_secrets_text(text)]


def test_the_goldens_cover_every_tier_a_format():
    assert set(GOLDENS) == set(_samples()) == set(TIER_A_PATTERNS)


@pytest.mark.parametrize("rule_id", list(GOLDENS))
def test_every_entry_point_writes_its_golden(rule_id: str):
    """Given a Tier A token inside a command line, When it runs through the hook log redactor, the
    insight redactor and the scanner, Then each output matches its golden, including the corrected unterminated-PEM result."""
    line = f"deploy --opt {_samples()[rule_id]} --next"
    hook, insight, scan = GOLDENS[rule_id]
    assert redact_secrets(line) == hook
    assert redact_insight_text(line) == insight
    assert _scan(line) == scan


@pytest.mark.parametrize("near_miss", [_tok("gh", "p_", "A1b2C3d4E5"), _tok("AK", "IA", "9F8E7D6C5B4A321")],
                         ids=["ghp-plus-10", "akia-plus-15"])
def test_a_near_miss_is_left_as_it_is(near_miss: str):
    line = f"deploy --opt {near_miss} --next"
    assert (redact_secrets(line), redact_insight_text(line), _scan(line)) == (line, line, [])


@pytest.mark.parametrize("rule_id", list(GOLDENS))
def test_a_second_pass_changes_nothing(rule_id: str):
    line = f"deploy --opt {_samples()[rule_id]} --next"
    for redact in (redact_secrets, redact_insight_text):
        once = redact(line)
        assert redact(once) == once


def test_redaction_truncation_never_leaves_partial_redacted_tag():
    prefix = "A" * 292
    secret = "".join(["ghp_", "1234567890abcdefghijklmnopqrstuvwxyzABCD"])
    out = redact_insight_text(f"{prefix} {secret}", max_len=300)
    assert len(out) <= 300
    assert "".join(["gh", "p_"]) not in out
    assert not out.endswith("[REDACTED")


def test_a_line_with_two_secrets_loses_both():
    samples = _samples()
    line = f"deploy --a {samples['github-pat']} --b {samples['aws-access-key-id']} --next"
    snippet = "deploy --a ghp_...r8 --b AKIA...10 --next"
    assert redact_secrets(line) == "deploy --a ghp_REDACTED --b AKIA_REDACTED --next"
    assert redact_insight_text(line) == "deploy --a [REDACTED_VCS_TOKEN] --b [REDACTED_AWS] --next"
    assert _scan(line) == [("aws-access-key-id", "gate", snippet), ("github-pat", "gate", snippet)]


# ── One definition, at L0 ─────────────────────────────────────────────────────

def test_redaction_is_one_definition_at_l0():
    """Given the finished tree, When aegis_core/redaction.py is parsed, Then it imports only the
    standard library; the hook adapter and the insights package hand out its objects, not copies."""
    from aegis_cli.hooks import redaction as hook_redaction
    from aegis_core import insights, redaction
    from aegis_core.verification.import_guard import is_stdlib

    tree = ast.parse((REPO / "aegis_core" / "redaction.py").read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported and sorted(m for m in imported if not is_stdlib(m)) == []
    assert all(hasattr(redaction, name) for name in redaction.__all__)
    assert hook_redaction.SECRET_REPLACEMENTS is redaction.SECRET_REPLACEMENTS
    assert insights.redact_insight_text is redaction.redact_insight_text


def test_scanners_defines_no_redaction_table_and_no_redactor():
    tree = ast.parse((REPO / "aegis_core" / "verification" / "scanners.py").read_text(encoding="utf-8"))
    defined = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    assigned = [t.id for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]) if isinstance(t, ast.Name)]
    assert [name for name in defined if name.lstrip("_").startswith("redact")] == []
    assert [name for name in assigned if name.endswith(("REDACTIONS", "REPLACEMENTS"))] == []


def private_imports(sources: Iterable[Tuple[str, str]]) -> List[str]:
    """``label:line: aegis_core.redaction._name`` for each import of an underscore name of the module."""
    found = []
    for label, text in sources:
        # Python normalizes identifiers with NFKC before exposing them in the AST.
        if "redaction" not in text and (text.isascii() or "redaction" not in unicodedata.normalize("NFKC", text)):
            continue
        for node in ast.walk(ast.parse(text, filename=label)):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "aegis_core.redaction":
                found += [f"{label}:{node.lineno}: aegis_core.redaction.{a.name}" for a in node.names
                          if a.name.startswith("_")]
    return found


def _git_environment() -> Dict[str, str]:
    """Git must use the intended checkout, independently of the caller's repository."""
    return {key: value for key, value in os.environ.items() if key not in LOCAL_ENV}


def _reviewed_python_paths() -> Tuple[str, ...]:
    roots = (*PACKAGES, "tests", ".github/scripts")
    if (REPO / ".git").exists():
        # The index needs no Git history and excludes other workers' untracked files.
        listed = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "ls-files", "--cached", "-z", "--", *roots],
            cwd=REPO, env=_git_environment(), check=True, capture_output=True, timeout=10,
        )
        paths = [os.fsdecode(name) for name in listed.stdout.split(b"\0") if name]
    else:
        # A committed, history-less checkout has no index. Freeze its initial
        # inventory during collection, before tests can create temporary sources.
        paths = [path.relative_to(REPO).as_posix()
                 for name in roots for path in (REPO / name).rglob("*.py")]
    return tuple(sorted({name for name in paths
                         if name.endswith(".py") and "__pycache__" not in Path(name).parts}))


_REVIEWED_PYTHON_PATHS = _reviewed_python_paths()


def _python_sources(root: Path = REPO) -> List[Tuple[str, str]]:
    # Freeze membership, not contents: edited or missing reviewed sources still fail.
    return [(name, (root / name).read_text(encoding="utf-8")) for name in _REVIEWED_PYTHON_PATHS]


def test_no_module_imports_a_private_name_of_redaction(monkeypatch: pytest.MonkeyPatch, sources=None):
    real_parse = ast.parse
    parse_count = 0
    parsed = []

    def counted_parse(text, filename):
        nonlocal parse_count
        parse_count += 1
        parsed.append(filename)
        return real_parse(text, filename=filename)

    counted_ast = SimpleNamespace(**vars(ast))
    counted_ast.parse = counted_parse
    monkeypatch.setattr(sys.modules[__name__], "ast", counted_ast)
    assert private_imports(_python_sources() if sources is None else sources) == []
    assert 0 < parse_count <= REDACTION_PARSE_CEILING, (
        f"redaction parse census: {parse_count} files; reviewed ceiling {REDACTION_PARSE_CEILING}. "
        "Review source additions before raising the ceiling. Parsed files:\n" + "\n".join(parsed)
    )


@pytest.mark.parametrize("indexed", [True, False], ids=["git-index", "committed-checkout"])
def test_private_import_census_ignores_files_created_after_collection(tmp_path: Path, indexed: bool):
    """Both source inventories stay fixed across parallel-test writes and repeated scans."""
    module = tmp_path / "tests" / "unit" / "core" / "test_redaction.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    reviewed = tmp_path / "aegis_core" / "reviewed.py"
    reviewed.parent.mkdir()
    reviewed.write_text("from aegis_core.redaction import SECRET_REPLACEMENTS\n", encoding="utf-8")
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "reviewed script.py").write_text("# redaction\n", encoding="utf-8")
    ignored = tmp_path / "tools"
    ignored.mkdir()
    (ignored / "outside_census.py").write_text("redaction syntax (\n", encoding="utf-8")
    cache = reviewed.parent / "__pycache__"
    cache.mkdir()
    (cache / "cached.py").write_text("redaction syntax (\n", encoding="utf-8")
    if indexed:
        subprocess.run(["git", "init", "-q", str(tmp_path)], env=_git_environment(), check=True, timeout=10)
        subprocess.run(["git", "add", "."], cwd=tmp_path, env=_git_environment(), check=True, timeout=10)
        (tmp_path / "tests" / "untracked_before_collection.py").write_text(
            "from aegis_core.redaction import _unreviewed\n", encoding="utf-8")
    scan = runpy.run_path(str(module))["_python_sources"]
    initial = scan()
    assert {"aegis_core/reviewed.py", ".github/scripts/reviewed script.py"} <= {label for label, _ in initial}
    assert not any("untracked_before_collection" in label for label, _ in initial)
    assert not any("outside_census" in label or "__pycache__" in label for label, _ in initial)
    # Interleave a worker's write with a source read, without patching pathlib globally.
    during_scan = tmp_path / "tests" / "created_during_scan.py"

    class InterleavedPath(type(tmp_path)):
        def read_text(self, *args, **kwargs):
            during_scan.write_text("from aegis_core.redaction import _late\n", encoding="utf-8")
            return super().read_text(*args, **kwargs)

    assert scan(InterleavedPath(tmp_path)) == initial
    assert during_scan.is_file()
    # Another worker can create, replace and remove these between census attempts.
    for directory in (reviewed.parent, tmp_path / "tests", scripts):
        late = directory / "late.py"
        for source in ("from aegis_core.redaction import _late\n", "redaction syntax (\n"):
            late.write_text(source, encoding="utf-8")
            assert scan() == initial
        late.unlink()
        assert scan() == initial
    reviewed.write_text("from aegis_core.redaction import _changed\n", encoding="utf-8")
    assert "aegis_core/reviewed.py:1: aegis_core.redaction._changed" in private_imports(scan())
    reviewed.unlink()
    with pytest.raises(FileNotFoundError):
        scan()


def test_private_import_census_refuses_an_unreadable_index(tmp_path: Path):
    module = tmp_path / "tests" / "unit" / "core" / "test_redaction.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    (tmp_path / ".git").write_text("not a git directory\n", encoding="utf-8")
    for _ in range(2):
        with pytest.raises(subprocess.CalledProcessError):
            runpy.run_path(str(module))


@pytest.mark.parametrize("count", [1, 66, 72])
def test_private_import_census_accepts_additions_within_reviewed_ceiling(monkeypatch, count):
    sources = [(f"tests/reviewed_{index}.py", "# redaction\n") for index in range(count)]
    test_no_module_imports_a_private_name_of_redaction(monkeypatch, sources)


def test_private_import_census_ceiling_failure_lists_every_parsed_file(monkeypatch):
    sources = [(f"tests/reviewed_{index}.py", "# redaction\n") for index in range(73)]
    with pytest.raises(AssertionError) as failure:
        test_no_module_imports_a_private_name_of_redaction(monkeypatch, sources)
    message = str(failure.value)
    assert "73" in message and "72" in message
    assert all(label in message for label, _ in sources)


@pytest.fixture
def redaction_selector_checkout(tmp_path: Path):
    """An own index with a violation and an external index captured before it existed."""
    checkout = tmp_path / "checkout"
    module = checkout / "tests" / "unit" / "core" / "test_redaction.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    package = checkout / "aegis_core"
    package.mkdir()
    (package / "reviewed.py").write_text("# redaction\n", encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if key not in LOCAL_ENV}
    subprocess.run(["git", "init", "-q", str(checkout)], env=env, check=True, timeout=10)
    subprocess.run(["git", "add", "."], cwd=checkout, env=env, check=True, timeout=10)
    external_index = tmp_path / "external-index"
    shutil.copyfile(checkout / ".git" / "index", external_index)
    (package / "violating.py").write_text("from aegis_core.redaction import _violation\n", encoding="utf-8")
    subprocess.run(["git", "add", "aegis_core/violating.py"], cwd=checkout, env=env, check=True, timeout=10)
    external = tmp_path / "external"
    subprocess.run(["git", "init", "-q", str(external)], env=env, check=True, timeout=10)
    return module, external_index, external


@pytest.mark.parametrize("selector", ["GIT_INDEX_FILE", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "combined", "all-local"])
@pytest.mark.parametrize("operation", ["census", "fixture"])
def test_private_import_census_and_fixture_ignore_inherited_git_selectors(
        tmp_path: Path, redaction_selector_checkout, selector: str, operation: str):
    module, external_index, external = redaction_selector_checkout
    env = {key: value for key, value in os.environ.items() if key not in LOCAL_ENV}
    if selector == "all-local":
        env.update({key: "invalid-inherited-selector" for key in LOCAL_ENV})
    env["GIT_INDEX_FILE"] = str(external_index)
    redirects = {"GIT_DIR": str(external / ".git"), "GIT_WORK_TREE": str(external),
                 "GIT_COMMON_DIR": str(external / ".git")}
    env.update(redirects if selector in ("combined", "all-local") else
               {key: value for key, value in redirects.items() if key == selector})
    before = external_index.read_bytes()
    program = (
        "import json, runpy, sys\n"
        "from pathlib import Path\n"
        "scope = runpy.run_path(sys.argv[1])\n"
        "if sys.argv[3] == 'census':\n"
        "    print(json.dumps(scope['private_imports'](scope['_python_sources']())))\n"
        "else:\n"
        "    scope['test_private_import_census_ignores_files_created_after_collection'](Path(sys.argv[2]), True)\n"
    )
    for attempt in range(2):
        result = subprocess.run(
            [sys.executable, "-c", program, str(module), str(tmp_path / f"fixture_{attempt}"), operation],
            cwd=REPO, env=env, capture_output=True, timeout=30, check=False,
        )
        assert external_index.read_bytes() == before, "fixture changed the caller's external index"
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        if operation == "census":
            assert json.loads(result.stdout) == ["aegis_core/violating.py:1: aegis_core.redaction._violation"]


def test_an_import_of_a_private_redaction_name_is_named_with_its_line():
    src = "import os\nfrom aegis_core.redaction import SECRET_REPLACEMENTS, _x\n"
    assert private_imports([("fixture.py", src)]) == ["fixture.py:2: aegis_core.redaction._x"]


@pytest.mark.parametrize("irrelevant", ["invalid syntax (\n", "# \u2500\ninvalid syntax (\n", "# \u00e9\ninvalid syntax (\n"])
def test_private_redaction_import_scan_skips_sources_without_the_needle(irrelevant: str):
    sources = [("irrelevant.py", irrelevant),
               ("caller.py", "import os\nfrom aegis_core.redaction import _x\n")]
    assert private_imports(sources) == ["caller.py:2: aegis_core.redaction._x"]


def test_private_redaction_import_scan_reports_nfkc_normalized_imports():
    source = "from aegis_core.redacti\uff4fn import _SECRET_REDACTIONS\n"
    assert "redaction" not in source
    assert private_imports([("caller.py", source)]) == ["caller.py:1: aegis_core.redaction._SECRET_REDACTIONS"]


@pytest.mark.parametrize("source", ["redaction syntax (\n", "# \uff52edaction\ninvalid syntax (\n"])
def test_private_redaction_import_scan_still_rejects_malformed_candidates(source: str):
    with pytest.raises(SyntaxError):
        private_imports([("caller.py", source)])


_HOOK_ADAPTER_IMPORTS = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import aegis_cli.hooks.redaction\n"
    "sys.stdout.write(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] in "
    "('aegis_cli', 'aegis_core', 'aegis_mcp', 'aegis_sdk'))))\n"
)


def test_the_hook_adapter_loads_no_scanner_stack(tmp_path: Path):
    """Given a fresh interpreter, When aegis_cli.hooks.redaction is imported, Then neither the
    scanner stack nor gitsafe loads, and at most 7 Aegis modules in all (14 on the w14 tree).

    Seven, not the spec's derived 6: aegis_cli/__init__.py imports aegis_core.primitives, so any
    aegis_cli import first loads aegis_cli, aegis_core, aegis_core._version and primitives."""
    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": os.environ.get("PATH", ""),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    proc = subprocess.run([sys.executable, "-I", "-c", _HOOK_ADAPTER_IMPORTS, str(REPO)], input=b"",
                          capture_output=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    loaded = set(json.loads(proc.stdout.decode("utf-8")))
    scanner_stack = {"aegis_core.verification", "aegis_core.verification.scanners",
                     "aegis_core.verification.test_runner", "aegis_core.gitsafe", "aegis_core.pathlookup",
                     "aegis_core.errors"}
    assert sorted(loaded & scanner_stack) == []
    assert len(loaded) <= 7, sorted(loaded)


def test_url_credential_removal_and_atomic_clip_live_only_in_redaction():
    """URL removal and atomic clipping are defined once, in aegis_core.redaction."""
    import aegis_core.redaction as redaction
    from aegis_core import guidance_grammar
    from aegis_core.proposals import model as proposal_model

    model_tree = ast.parse((REPO / "aegis_core" / "proposals" / "model.py").read_text(encoding="utf-8"))
    defined = {node.name for node in model_tree.body if isinstance(node, ast.FunctionDef)}
    assert {"_strip_url_secrets", "_clip_text", "_ambiguous_authority"}.isdisjoint(defined)
    redaction_tree = ast.parse((REPO / "aegis_core" / "redaction.py").read_text(encoding="utf-8"))
    redaction_defined = {node.name for node in redaction_tree.body if isinstance(node, ast.FunctionDef)}
    assert {"remove_url_credentials", "clip_atomic_text"}.issubset(redaction_defined)
    assert redaction.remove_url_credentials.__module__ == "aegis_core.redaction"
    assert redaction.clip_atomic_text.__module__ == "aegis_core.redaction"
    assert "remove_url_credentials" in redaction.__all__
    assert "clip_atomic_text" in redaction.__all__
    source = (REPO / "aegis_core" / "proposals" / "model.py").read_text(encoding="utf-8")
    assert "remove_url_credentials" in source and "clip_atomic_text" in source
    assert proposal_model.remove_url_credentials is redaction.remove_url_credentials
    assert proposal_model.clip_atomic_text is redaction.clip_atomic_text
    assert guidance_grammar.clip_atomic_text is redaction.clip_atomic_text
    assert guidance_grammar.remove_url_credentials is redaction.remove_url_credentials
    assert proposal_model.clean_text("https://ci.example/path", 64) == "https://ci.example/path"


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", ["proposal", "guidance"])
@pytest.mark.parametrize("bad", [None, b"text", 1, ["text"]],
                         ids=["none", "bytes", "number", "list"])
def test_shared_cleaners_refuse_malformed_text_then_retry(name, policy, bad):
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    for _ in range(2):
        with pytest.raises(redaction.RedactionRefusal, match="^invalid$") as caught:
            cleaner(bad, limit=32, policy=policy)
        assert caught.value.code == "invalid"
        assert cleaner("plain", limit=32, policy=policy) == "plain"


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", ["proposal", "guidance"])
@pytest.mark.parametrize("limit", [-1, True, None, 1.5, "32"])
def test_shared_cleaners_refuse_invalid_limits_then_retry(name, policy, limit):
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    with pytest.raises(redaction.RedactionRefusal, match="^invalid$") as caught:
        cleaner("private input", limit=limit, policy=policy)
    assert caught.value.code == "invalid"
    assert cleaner("plain", limit=32, policy=policy) == "plain"


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
def test_shared_cleaner_input_ceiling_and_concurrent_refusal_recovery(name):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    text = "z" * redaction.MAX_GUIDANCE_CHARS
    assert cleaner(text, limit=len(text)) == text

    def refusing_then_retry(_):
        with pytest.raises(redaction.RedactionRefusal, match="^too_large$") as caught:
            cleaner(text + "z", limit=3)
        assert caught.value.code == "too_large"
        return cleaner("plain", limit=32)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refusing_then_retry, range(6))) == ["plain"] * 6


@pytest.mark.parametrize("policy", ["proposal", "guidance"])
def test_named_cleaner_policies_preserve_url_and_whitespace_contracts(policy):
    from aegis_core.redaction import clip_atomic_text, remove_url_credentials

    masked = "ftp://u:[REDACTED]@ci.example/p?q=hidden#private"
    expected = "ftp://ci.example/p" if policy == "proposal" else masked
    assert remove_url_credentials(masked, limit=300, policy=policy) == expected
    assert remove_url_credentials(expected, limit=300, policy=policy) == expected
    expected = "plain" if policy == "proposal" else "plain "
    assert clip_atomic_text("plain tail", 6, policy=policy) == expected
    assert clip_atomic_text(expected, 6, policy=policy) == expected
    expected = "xxghp_" if policy == "proposal" else "xx"
    assert clip_atomic_text("xxghp_REDACTED tail", 6, policy=policy) == expected


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", ["guidance", "proposal"])
def test_named_cleaner_policies_bound_input_and_retry_concurrently(name, policy):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    ceiling = 1024 * 1024 if policy == "guidance" else redaction.MAX_GUIDANCE_CHARS
    text = "z" * ceiling
    assert cleaner(text, limit=ceiling, policy=policy) == text
    oversized = text + "z"

    def refusing_then_retry(_):
        with pytest.raises(redaction.RedactionRefusal, match="^too_large$") as caught:
            cleaner(oversized, limit=3, policy=policy)
        assert caught.value.code == "too_large"
        return cleaner("plain", limit=32, policy=policy)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refusing_then_retry, range(6))) == ["plain"] * 6


@pytest.mark.parametrize("name", ["remove_url_credentials", "clip_atomic_text"])
@pytest.mark.parametrize("policy", [None, [], True, "unknown"],
                         ids=["none", "list", "bool", "unknown"])
def test_shared_cleaners_refuse_unknown_policy_without_echo(name, policy):
    from aegis_core import redaction

    cleaner = getattr(redaction, name)
    with pytest.raises(redaction.RedactionRefusal, match="^invalid$") as caught:
        cleaner("private input", limit=32, policy=policy)
    assert caught.value.code == "invalid"
    assert cleaner("plain", limit=32, policy="guidance") == "plain"


def test_guidance_wrappers_use_the_shared_named_policy():
    from aegis_core import guidance_grammar as grammar

    assert grammar.clip_redacted("plain tail", 6) == "plain "
    assert grammar.redact_labeled("plain", [0] * 5, 32) == ("plain", [0] * 5)
    text = "ftp://u:pass@ci.example/p?q=hidden#private"
    expected = "ftp://u:[REDACTED]@ci.example/p?q=hidden#private"
    assert grammar.redact_labeled(text, [0] * len(text), 300) == (expected, [0] * len(expected))
    assert grammar.clip_redacted("xxghp_REDACTED tail", 6) == "xx"
    with pytest.raises(ValueError, match="^guidance_projection_limit$"):
        grammar.clip_redacted("plain", -1)
    with pytest.raises(ValueError, match="^guidance_projection_limit$"):
        grammar.redact_labeled("plain", None, 3)
    assert grammar.clip_redacted("retry", 32) == "retry"
