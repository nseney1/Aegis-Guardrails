"""Every redactor scrubs every format the Tier A detector blocks, in linear time (R-checks-26).

Three entry points persist or echo text: the hook log (aegis_cli.hooks.redaction.redact_secrets,
scanners.redact_command_secrets) and stored insights (scanners.redact_insight_text). Secrets
are assembled at runtime so push protection never sees a literal.
"""
from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Callable, Dict, List, Tuple

import pytest

from aegis_cli.hooks import redaction
from aegis_cli.hooks.safety import log_gate_event
from aegis_core.verification import scanners


def _tok(*parts: str) -> str:
    return "".join(parts)


def _samples() -> Dict[str, str]:
    return {
        "aws-access-key-id": _tok("AK", "IA", "9F8E7D6C5B4A3210"),
        "github-pat": _tok("gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
        "github-fine-grained-pat": _tok("github", "_pat_", "11ABCDEFG0123456789_abcdefghijklmnop"),
        "slack-token": _tok("xox", "b-", "123456789012-ABCDEFGHIJKLMN"),
        "stripe-live-secret": _tok("sk", "_live_", "9876543210abcdefghijklmnoPQR"),
        "openai-api-key": _tok("sk", "-proj-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"),
        "anthropic-api-key": _tok("sk", "-ant-", "api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
        "google-api-key": _tok("AI", "za", "SyD-9876543210abcdefghijklmnopqrstu"),
        "private-key-pem": _tok("-----BEGIN ", "RSA ", "PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0123456789\n",
                                "-----END RSA ", "PRIVATE KEY-----"),
        "jwt-three-segment": _tok("eyJ", "hbGciOiJIUzI1NiJ9", ".", "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".",
                                  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        "url-basic-auth": _tok("https://", "svc_admin", ":", "p9Q8r7S6t5U4", "@api.internal.corp/v1"),
    }


#: The part of each sample that must not survive (the URL keeps its user and host).
def _secret_part(rule_id: str, sample: str) -> str:
    return "p9Q8r7S6t5U4" if rule_id == "url-basic-auth" else sample


def _variants() -> Dict[str, Tuple[str, str]]:
    """Further shapes a Tier A family blocks: every other AWS id prefix and a URL with no scheme."""
    out = {f"aws-{p.lower()}": ("aws-access-key-id", _tok(p[:2], p[2:], "9F8E7D6C5B4A3210"))
           for p in ("AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA")}
    out["url-no-scheme"] = ("url-basic-auth", _tok("://", "svc_admin", ":", "p9Q8r7S6t5U4", "@api.internal.corp/v1"))
    return out


#: (case id, Tier A family, sample) for every sample and variant.
CASES: List[Tuple[str, str, str]] = ([(rid, rid, s) for rid, s in _samples().items()]
                                     + [(cid, rid, s) for cid, (rid, s) in _variants().items()])
CASE_IDS = [c[0] for c in CASES]


REDACTORS: Dict[str, Callable[[str], str]] = {
    "hook": redaction.redact_secrets,
    "command": scanners.redact_command_secrets,
    "insight": lambda text: scanners.redact_insight_text(text, max_len=4000),
}


def test_sample_table_covers_every_tier_a_format():
    assert set(_samples()) == set(scanners.TIER_A_PATTERNS)


def test_every_case_is_one_the_tier_a_detector_blocks():
    for case_id, rule_id, sample in CASES:
        assert scanners.TIER_A_PATTERNS[rule_id].search(sample), case_id


@pytest.mark.parametrize("redactor", list(REDACTORS))
@pytest.mark.parametrize("case_id,rule_id,sample", CASES, ids=CASE_IDS)
def test_every_tier_a_format_is_scrubbed_and_context_kept(redactor, case_id, rule_id, sample):
    out = REDACTORS[redactor](f"deploy --opt {sample} --next")
    assert _secret_part(rule_id, sample) not in out
    assert "MIIEpAIBAAKCAQEA0123456789" not in out
    assert out.startswith("deploy --opt ") and out.endswith(" --next")


@pytest.mark.parametrize("case_id,rule_id,sample", CASES, ids=CASE_IDS)
def test_gate_log_holds_no_secret(tmp_path: Path, case_id, rule_id, sample):
    (tmp_path / ".aegis").mkdir()
    log_gate_event(f"curl --data {sample}", "ALLOWED", "", tmp_path)
    (row,) = [json.loads(line) for line in (tmp_path / ".aegis" / "state" / "gate_events.jsonl")
              .read_text(encoding="utf-8").splitlines()]
    assert _secret_part(rule_id, sample) not in json.dumps(row)
    assert row["decision"] == "ALLOWED"


KEY_VALUES = {
    "password": (_tok("password", "=hunter2hunter2"), "hunter2hunter2"),
    "export": (_tok("export API_", "TOKEN=abcd1234efgh"), "abcd1234efgh"),
    "client-secret": (_tok("client_", 'secret: "s3cr3tvalue"'), "s3cr3tvalue"),
    "gemini": (_tok("GEMINI_API_", "KEY=my_key"), "my_key"),
    "basic": (_tok("authorization: ", "Basic dXNlcjpwYXNz"), "dXNlcjpwYXNz"),
    "proxy-basic": (_tok("Proxy-Authorization: ", "Basic Zm9vOmJhcg=="), "Zm9vOmJhcg=="),
    "auth": (_tok("auth", "=abcd1234"), "abcd1234"),
    "secretkey": (_tok("secret", "key=abcd1234"), "abcd1234"),
    "authtoken": (_tok("auth", "Token=abcd1234"), "abcd1234"),
}


@pytest.mark.parametrize("redactor", list(REDACTORS))
@pytest.mark.parametrize("case", list(KEY_VALUES))
def test_key_value_secret_is_redacted(redactor, case):
    text, value = KEY_VALUES[case]
    out = REDACTORS[redactor](text)
    assert value not in out and "REDACTED" in out


@pytest.mark.parametrize("redactor", list(REDACTORS))
def test_prose_password_is_redacted(redactor):
    out = REDACTORS[redactor](_tok("the password ", "is hunter2xyz"))
    assert "hunter2xyz" not in out and out.startswith("the password is ")


def test_hook_log_keeps_paths_and_addresses():
    text = "scp /home/nick/build.tar nick@10.0.0.7:/srv"
    assert redaction.redact_secrets(text) == text
    assert scanners.redact_command_secrets(text) == text


@pytest.mark.parametrize("redactor", list(REDACTORS))
@pytest.mark.parametrize("text", [c[2] for c in CASES] + [t for t, _ in KEY_VALUES.values()],
                         ids=[*CASE_IDS, *KEY_VALUES])
def test_a_second_pass_is_a_no_op(redactor, text):
    once = REDACTORS[redactor](f"deploy {text} now")
    assert REDACTORS[redactor](once) == once


@pytest.mark.parametrize("redactor", list(REDACTORS))
@pytest.mark.parametrize("text", [
    "docker run task-runner-configuration-service-image --name disk-usage-report-generator",
    "git log --author=nick",
    "the author: John Smith wrote this",
    "auth = ab",
    "pwd=abc",
    "use the token",
    "the auth is broken",
    "authorization: Basic",
], ids=["task-runner", "author-flag", "author-prose", "short", "pwd", "token-word", "auth-prose", "no-value"])
def test_lookalikes_are_left_alone(redactor, text):
    assert REDACTORS[redactor](text) == text


# ── linear time ─────────────────────────────────────────────────────────────

def _fill(unit: str, n: int) -> str:
    return (unit * (n // len(unit) + 1))[:n]


HOSTILE: Dict[str, Callable[[int], str]] = {
    "pem-repeat": lambda n: _fill("-----BEGIN PRIVATE KEY-----", n),
    "pem-unterminated": lambda n: "-----BEGIN PRIVATE KEY-----\n" * 20 + "a" * n,
    "token-eq": lambda n: _fill("token=", n),
    "url-userinfo": lambda n: _fill("http://a:", n),
    "bearer": lambda n: _fill("Bearer ", n),
    "dash-run": lambda n: "-" * n,
    "auth": lambda n: _fill("auth", n),
    "dot-one": lambda n: _fill("1.", n),
}
HANG_CEILING_S = 30.0


def _best_of_3(fn: Callable[[str], str], text: str) -> float:
    best = HANG_CEILING_S
    for _ in range(3):
        start = time.perf_counter()
        fn(text)
        elapsed = time.perf_counter() - start
        assert elapsed < HANG_CEILING_S
        best = min(best, elapsed)
    return best


@pytest.mark.timing
@pytest.mark.parametrize("redactor", ["hook", "insight"])
@pytest.mark.parametrize("family", list(HOSTILE))
def test_redaction_time_is_linear(redactor, family):
    # A ratio, never an absolute budget; the 20 ms floor keeps timer noise on a linear
    # pattern from failing it. Quadratic doubles to about 4x.
    n = 25_000
    small = _best_of_3(REDACTORS[redactor], HOSTILE[family](n))
    large = _best_of_3(REDACTORS[redactor], HOSTILE[family](2 * n))
    assert large <= 3 * max(small, 0.02), (small, large)
