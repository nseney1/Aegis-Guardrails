"""Insight redaction scans a bounded, whole-token head of a long prompt (R-checks-26)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.insights import read_insight_rows, record_hook_prompt
from aegis_core.verification.scanners import redact_insight_text


@pytest.mark.timing
@pytest.mark.parametrize("text", [
    "don't " + "1." * 25000,
    "a-" * 25000,
    "auth" * 8000,
    "-----BEGIN PRIVATE KEY----- " * 4000,
], ids=["dots", "dashes", "auth", "pem-headers"])
def test_long_hostile_text_yields_a_short_excerpt(text):
    out = redact_insight_text(text, max_len=300)
    assert len(out) <= 300
    if text.startswith("don't"):
        assert out.startswith("don't")


def test_short_text_takes_the_unbounded_path():
    text = "keep " * 800 + "password=hunter2abc"
    assert len(text) <= 4096
    assert redact_insight_text(text, max_len=0).endswith("password=[REDACTED]")


def test_a_pem_block_cut_by_the_bound_leaves_no_key_material():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 40
    block = f"-----BEGIN PRIVATE KEY----- {body} -----END PRIVATE KEY-----"
    text = "x " * 800 + block + " and " + block + " tail " * 10
    second = text.rindex("-----BEGIN")
    assert second < 4096 < text.rindex("-----END")
    out = redact_insight_text(text, max_len=0)
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEF" not in out


def test_a_secret_straddling_the_bound_is_dropped_whole():
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    text = "x " * 2046 + secret + " tail" * 100
    assert text.index(secret) < 4096 < text.index(secret) + len(secret)
    out = redact_insight_text(text, max_len=0)
    assert "ghp_" not in out and out.endswith("x")


@pytest.mark.timing
def test_hook_prompt_of_one_huge_token_writes_no_excerpt_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = tmp_path / "repo"
    (repo / ".aegis" / "rules").mkdir(parents=True)
    prompt = "don't." + "1." * 15000
    res = record_hook_prompt("claude-code", {"prompt": prompt, "session_id": "s-huge", "cwd": str(repo)},
                             excerpts=True, home=home)
    assert res["recorded"] is False
    assert [r["event"] for r in read_insight_rows(repo, home=home)] == ["heartbeat"]
