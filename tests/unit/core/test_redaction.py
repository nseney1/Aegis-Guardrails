"""aegis_core.redaction: one secret table, the same output through every entry point (R-structure-32).

The goldens were recorded on the w14 merge commit (e7e61536), before the table moved out of
aegis_core.verification.scanners, through the three entry points that exist on both sides of the
move: the hook command log (aegis_cli.hooks.redaction.redact_secrets), stored insight text
(aegis_core.insights.redact_insight_text) and a scanner finding's snippet (scan_secrets_text).
Tokens are assembled at run time so push protection never sees a literal.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Dict, Iterable, List, Tuple

import pytest

from aegis_cli.hooks.redaction import redact_secrets
from aegis_core.insights import redact_insight_text
from aegis_core.verification.scanners import TIER_A_PATTERNS, scan_secrets_text

REPO = Path(__file__).resolve().parents[3]
PACKAGES = ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk")


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
    # The hook log has no entropy pass, so a PEM header without its END line keeps the body after
    # it (insight text masks it). Recorded as the w14 tree writes it: the move changes no output.
    "private-key-pem": (
        _tok("deploy --opt [REDACTED_PEM]\\n", "MIIEow", "IBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJ --next"),
        "deploy --opt [REDACTED_PEM]\\[REDACTED_HIENT] --next",
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
    insight redactor and the scanner, Then each output equals the one recorded before the move."""
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
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "aegis_core.redaction":
                found += [f"{label}:{node.lineno}: aegis_core.redaction.{a.name}" for a in node.names
                          if a.name.startswith("_")]
    return found


def _python_sources() -> List[Tuple[str, str]]:
    roots = [REPO / name for name in (*PACKAGES, "tests")] + [REPO / ".github" / "scripts"]
    return [(path.relative_to(REPO).as_posix(), path.read_text(encoding="utf-8"))
            for root in roots for path in sorted(root.rglob("*.py")) if "__pycache__" not in path.parts]


def test_no_module_imports_a_private_name_of_redaction():
    assert private_imports(_python_sources()) == []


def test_an_import_of_a_private_redaction_name_is_named_with_its_line():
    src = "import os\nfrom aegis_core.redaction import SECRET_REPLACEMENTS, _x\n"
    assert private_imports([("fixture.py", src)]) == ["fixture.py:2: aegis_core.redaction._x"]


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
