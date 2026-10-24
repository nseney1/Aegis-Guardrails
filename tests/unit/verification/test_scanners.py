"""Behavioral tests for Tier A/B/C secret scanner, SARIF 2.1.0 ingest, and external presets."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

import pytest

from aegis_core.verification import scanners


def _tok(*parts: str) -> str:
    """Assemble synthetic tokens dynamically at runtime so push-protection never sees literals."""
    return "".join(parts)


def _tier_a_samples() -> dict[str, str]:
    """Return 11 dynamically constructed synthetic Tier A tokens keyed by rule_id."""
    return {
        "aws-access-key-id": _tok("AK", "IA", "9F8E7D6C5B4A3210"),
        "github-pat": _tok("gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
        "github-fine-grained-pat": _tok("github", "_pat_", "11ABCDEFG0123456789_abcdefghijklmnop"),
        "slack-token": _tok("xox", "b-", "123456789012-ABCDEFGHIJKLMN"),
        "stripe-live-secret": _tok("sk", "_live_", "9876543210abcdefghijklmnoPQR"),
        "openai-api-key": _tok("sk", "-proj-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"),
        "anthropic-api-key": _tok("sk", "-ant-", "api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
        "google-api-key": _tok("AI", "za", "SyD-9876543210abcdefghijklmnopqrstu"),
        # One line with an escaped newline before the key body: a bare header is not key material.
        "private-key-pem": _tok("-----BEGIN ", "RSA ", "PRIVATE KEY-----", "\\n", "MIIEowIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJ"),
        "jwt-three-segment": _tok(
            "eyJ", "hbGciOiJIUzI1NiJ9", ".",
            "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ),
        "url-basic-auth": _tok("https://", "svc_admin", ":", "p9Q8r7S6t5U4", "@api.internal.corp/v1"),
    }


_PREFIXED = ["aws-access-key-id", "github-pat", "github-fine-grained-pat", "slack-token", "stripe-live-secret",
             "anthropic-api-key", "google-api-key", "jwt-three-segment"]
_ALNUM_BODY = ["aws-access-key-id", "github-pat", "stripe-live-secret"]


class TestTierASecretDetection:
    @pytest.mark.parametrize("rule_id", list(_tier_a_samples().keys()))
    def test_detects_all_11_known_formats(self, rule_id: str) -> None:
        token = _tier_a_samples()[rule_id]
        line = f'config_val = "{token}"'
        findings = scanners.scan_secrets_text(line, path="src/config.py")
        matched_rules = {f.rule_id for f in findings}
        assert rule_id in matched_rules
        for f in findings:
            if f.rule_id == rule_id:
                assert f.tier == "gate"
                assert f.line == 1
                assert f.path == "src/config.py"

    def test_secret_masking_never_exposes_raw_value(self) -> None:
        raw = _tier_a_samples()["github-pat"]
        findings = scanners.scan_secrets_text(f"TOKEN = '{raw}'\n", path="app.py")
        assert len(findings) == 1
        finding = findings[0]
        assert raw not in finding.snippet
        assert "..." in finding.snippet
        masked = scanners.mask_secret(raw)
        assert masked in finding.snippet
        assert masked.startswith(raw[:4])
        assert masked.endswith(raw[-2:])
        assert raw not in json.dumps(finding.as_dict())

    def test_contains_secret_tier_a_fast_helper(self) -> None:
        raw = _tier_a_samples()["aws-access-key-id"]
        assert scanners.contains_secret_tier_a(f"export AWS_KEY={raw}") is True
        assert scanners.contains_secret_tier_a("normal code x = 42") is False

    @pytest.mark.parametrize("delim,rule_id", [("/", r) for r in _PREFIXED] + [(d, r) for d in "_-" for r in _ALNUM_BODY])
    def test_a_token_after_a_delimiter_is_found(self, delim, rule_id):
        """R-checks-23: only a preceding letter or digit means "inside a longer run"."""
        token = _tier_a_samples()[rule_id]
        findings = scanners.scan_secrets_text(f"deploy{delim}{token}")
        assert rule_id in [f.rule_id for f in findings]
        assert token not in json.dumps([f.as_dict() for f in findings])

    @pytest.mark.parametrize("rule_id", ["github-pat", "github-fine-grained-pat"])
    def test_a_token_in_a_clone_url_is_found(self, rule_id):
        token = _tier_a_samples()[rule_id]
        findings = scanners.scan_secrets_text(f"git clone https://{token}@github.com/org/repo.git")
        assert [f.rule_id for f in findings] == [rule_id]
        assert token not in findings[0].snippet and scanners.mask_secret(token) in findings[0].snippet

    @pytest.mark.parametrize("before", ["a", "Z", "7"])
    @pytest.mark.parametrize("rule_id", _PREFIXED)
    def test_a_token_glued_to_a_letter_or_digit_is_not_found(self, before, rule_id):
        assert scanners.scan_secrets_text(before + _tier_a_samples()[rule_id]) == []

    @pytest.mark.parametrize("line", [
        "see docs/sk-evaluation-framework-implementation-notes.md for details",
        "cp ./sk-evaluation-framework-implementation-notes.md /tmp",
        "git checkout feature/sk-evaluation-framework-implementation-notes",
        "def test_github_pat_regex_does_not_match_identifiers():",
        "x = parse_github_pat_from_environment_variable()",
        _tok("name = 'my-xo", "xb-aaaaaaaaaaaa-bbbbbbbb'"),
    ], ids=["docs-path", "cp-path", "branch", "test-name", "identifier", "kebab"])
    def test_paths_and_identifiers_stay_clean(self, line):
        assert scanners.scan_secrets_text(line, include_advisory=False) == []

    def test_zero_false_positives_on_benign_inputs(self) -> None:
        benign_lines = [
            # UUIDs
            'id = "550e8400-e29b-41d4-a716-446655440000"',
            # git SHAs (40-char and 64-char hex)
            'commit = "7fee8de14b2277619b93f0123456789abcdef012"',
            'oid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
            # lockfile sha256/sha512 integrity hashes
            '"integrity": "sha512-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08=="',
            '"sha256": "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="',
            # base64 data URLs
            'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="',
            # placeholder strings
            _tok('aws_key = "', "AK", "IA", 'IOSFODNN7EXAMPLE"'),
            _tok('api_key = "', "sk-", 'DUMMY123456789012345678901234567890"'),
            _tok('api_key = "', "sk-", 'TEST_123456789012345678901234567890"'),
            _tok('pat = "', "gh", "p_", "x" * 38, '"'),
            'secret = "<token>"',
            'api_key = "your_api_key"',
            # variable references in url-basic-auth
            'url = "https://user:$VAR@example.com/api"',
            'url2 = "https://user:${DB_PASS}@example.com/api"',
        ]
        text = "\n".join(benign_lines)
        assert scanners.scan_secrets_text(text, include_advisory=False) == []
        assert scanners.scan_secrets_text(text, include_advisory=True) == []

def _pad(n: int) -> str:
    return "a," * (n // 2)


def _best_of(runs: int, fn, *args) -> float:
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        fn(*args)
        best = min(best, time.perf_counter() - start)
    return best


class TestLongLinesAreScanned:
    """R-checks-21: a line of any length is scanned in full; above MAX_LINE_LENGTH a finding's
    snippet is the masked token alone, so snippets stay bounded and leak no neighbouring text."""

    @pytest.mark.parametrize("pad", [4090, 4097, 120_000])
    @pytest.mark.parametrize("rule_id", list(_tier_a_samples().keys()))
    def test_a_secret_on_a_long_line_is_reported(self, rule_id, pad):
        line = f'{_pad(pad)} cfg = "{_tier_a_samples()[rule_id]}" {_pad(pad)}'
        found = [f for f in scanners.scan_secrets_text(line, path="dist/app.min.js") if f.rule_id == rule_id]
        assert found and all((f.tier, f.line, f.path) == ("gate", 1, "dist/app.min.js") for f in found)

    @pytest.mark.parametrize("length", [4096, 4097])
    def test_both_sides_of_the_boundary_detect(self, length):
        body = f' k="{_tier_a_samples()["aws-access-key-id"]}"'
        line = "#" * (length - len(body)) + body
        assert len(line) == length
        assert [f.rule_id for f in scanners.scan_secrets_text(line)] == ["aws-access-key-id"]

    def test_a_secret_at_the_end_of_a_400_kb_line_is_found(self):
        line = _pad(400_000) + " " + _tier_a_samples()["github-pat"]
        assert [f.rule_id for f in scanners.scan_secrets_text(line)] == ["github-pat"]

    def test_line_numbers_stay_right_around_a_long_line(self):
        samples = _tier_a_samples()
        text = f"first\n{_pad(9000)} {samples['aws-access-key-id']}\nmiddle\nx = '{samples['slack-token']}'\n"
        assert sorted((f.line, f.rule_id) for f in scanners.scan_secrets_text(text)) == [
            (2, "aws-access-key-id"), (4, "slack-token")]

    def test_every_secret_on_one_long_line_is_reported(self):
        samples = _tier_a_samples()
        names = ["aws-access-key-id", "github-pat", "slack-token", "google-api-key"]
        line = _pad(10_000).join(f" {samples[n]} " for n in names)
        assert sorted({f.rule_id for f in scanners.scan_secrets_text(line)}) == sorted(names)

    def test_a_large_data_url_is_no_false_positive_and_a_key_after_it_is_found(self):
        blob = 'img = "data:image/png;base64,' + "iVBORw0KGgo" * 18_000 + '"'
        assert scanners.scan_secrets_text(blob, include_advisory=True) == []
        key = _tier_a_samples()["aws-access-key-id"]
        assert [f.rule_id for f in scanners.scan_secrets_text(blob + f' k = "{key}"', include_advisory=True)] == [
            "aws-access-key-id"]

    def test_a_long_line_snippet_is_the_masked_token_only(self):
        raw = _tier_a_samples()["github-pat"]
        (finding,) = scanners.scan_secrets_text(_pad(120_000) + f' TOKEN = "{raw}" ' + _pad(120_000))
        dumped = json.dumps(finding.as_dict())
        assert finding.snippet == scanners.mask_secret(raw)
        assert raw not in dumped and len(dumped) < 500

    def test_many_keys_on_one_long_line_keep_snippets_bounded(self):
        keys = [f"AKIA{i:016d}" for i in range(1_500)]
        findings = scanners.scan_secrets_text(" ".join(keys))
        assert len(findings) == 1_500
        assert sum(len(f.snippet) for f in findings) <= 32 * 1_500

    def test_a_short_line_keeps_its_masked_context_and_fingerprint(self):
        raw = _tier_a_samples()["github-pat"]
        (finding,) = scanners.scan_secrets_text(f"TOKEN = '{raw}'\n", path="app.py")
        assert finding.snippet == f"TOKEN = '{scanners.mask_secret(raw)}'"
        assert finding.fingerprint == scanners.sarif_fingerprint("github-pat", "app.py", finding.snippet)

    @pytest.mark.timing
    def test_scan_cost_stays_linear_in_line_length(self):
        """No absolute budget. A 4x longer line costs about 4x when linear and 16x when quadratic,
        so the bound of 8 leaves room for a loaded Windows runner on both sides."""
        def scan(n):
            assert scanners.scan_secrets_text(_tok("sk", "-") + "a" * n, include_advisory=True) == []

        ratio = _best_of(5, scan, 200_000) / max(_best_of(5, scan, 50_000), 1e-9)
        assert ratio < 8, f"quadrupling the line multiplied the scan time by {ratio:.1f}"

    @pytest.mark.timing
    def test_the_ratio_check_catches_a_quadratic_cost(self):
        def quadratic(n):
            sum(1 for _ in range(n // 100) for _ in range(n // 100))

        assert _best_of(3, quadratic, 200_000) / _best_of(3, quadratic, 50_000) >= 8


class TestDataUrlPrefixDoesNotHideGateSecrets:
    """R-checks-22: data-URL and SRI payloads are blanked for the heuristic (advisory) tiers only;
    a known-format token right after a data-URL prefix still gates."""

    @pytest.mark.parametrize("prefix", ["data:x/y;base64,", "data:image/png;base64,"], ids=["xy", "png"])
    @pytest.mark.parametrize("rule_id", list(_tier_a_samples().keys()))
    def test_a_token_after_a_data_url_prefix_gates(self, rule_id, prefix):
        token = _tier_a_samples()[rule_id]
        findings = scanners.scan_secrets_text(f'blob = "{prefix}{token}"')
        assert (rule_id, "gate", 1) in [(f.rule_id, f.tier, f.line) for f in findings]
        assert token not in json.dumps([f.as_dict() for f in findings])

    def test_a_token_lines_after_a_data_url_is_reported_alone(self):
        text = 'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="\nx = 1\n' + _tok(
            "k = '", _tier_a_samples()["aws-access-key-id"], "'\n")
        assert [(f.rule_id, f.line, f.tier) for f in scanners.scan_secrets_text(text)] == [("aws-access-key-id", 3, "gate")]

    @pytest.mark.parametrize("include_advisory", [False, True], ids=["gate", "advisory"])
    def test_benign_data_urls_and_sri_hashes_stay_quiet(self, include_advisory):
        lines = []
        for key in ("icon", "icon_token", "secret_image", "api_key_icon", "password_hint"):
            payload = base64.b64encode(hashlib.sha256(key.encode()).digest() * 3).decode()
            lines += [f'{key} = "data:{mime};base64,{payload}"' for mime in ("image/png", "font/woff2", "application/octet-stream")]
        sri = base64.b64encode(hashlib.sha384(b"app.js").digest()).decode()
        lines.append(f'<script src="app.js" integrity="sha384-{sri}"></script>')
        assert scanners.scan_secrets_text("\n".join(lines), include_advisory=include_advisory) == []


class TestPlaceholderSuppressionIsWordAware:
    """R-checks-24: a human-chosen value is a placeholder only when a placeholder word starts one of
    its words (or it has a placeholder shape), not because an English word contains one."""

    @staticmethod
    def _url(user: str, pwd: str) -> str:
        return _tok("db = 'postgres://", user, ":", pwd, "@db.internal/app'")

    @pytest.mark.parametrize("pwd", ["contest2024Zq", "attestation99X", "latestGreat9", "mastodon9Zq", "counterexample9"])
    def test_a_real_password_containing_a_placeholder_word_gates(self, pwd):
        findings = scanners.scan_secrets_text(self._url("svc", pwd))
        assert [(f.rule_id, f.tier) for f in findings] == [("url-basic-auth", "gate")]
        assert pwd not in json.dumps(findings[0].as_dict())

    def test_a_real_user_containing_a_placeholder_word_gates(self):
        assert len(scanners.scan_secrets_text(self._url("contest_admin", "Zq9fRt3pLm"))) == 1

    def test_a_real_assigned_password_is_an_advisory(self):
        findings = scanners.scan_secrets_text('db_password = "contest2024Zq"', include_advisory=True)
        assert [(f.rule_id, f.tier) for f in findings] == [("generic-secret-assign", "advisory")]

    @pytest.mark.parametrize("include_advisory", [False, True], ids=["gate", "advisory"])
    @pytest.mark.parametrize("pwd", ["test", "Test123", "test_password", "TestPassword", "testpass", "TESTPASS",
                                     "changeme", "your_password", "example", "xxxxxxxx", "********"])
    def test_a_placeholder_password_stays_quiet(self, pwd, include_advisory):
        assert scanners.scan_secrets_text(self._url("svc", pwd), include_advisory=include_advisory) == []

    @pytest.mark.parametrize("val", ["testpassword1", "changeme123", "your_password_here"])
    def test_a_placeholder_assignment_stays_quiet(self, val):
        assert scanners.scan_secrets_text(f'db_password = "{val}"', include_advisory=True) == []

    def test_glued_tier_a_placeholders_stay_suppressed(self):
        lines = [_tok("k = '", "AK", "IA", "TESTTESTTESTTEST'"), _tok("k = '", "AK", "IA", "IOSFODNN7EXAMPLE'")]
        assert scanners.scan_secrets_text("\n".join(lines), include_advisory=True) == []


_REPO = Path(__file__).resolve().parents[3]


class TestPemNeedsKeyMaterial:
    """R-checks-a2: a PEM header gates only with key material after it (on the same line, or on one
    of the next 6 non-blank lines); a bare mention stays visible as an advisory."""

    HEADER = _tok("-----BEGIN ", "OPENSSH ", "PRIVATE KEY-----")
    BODY = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" + "x" * 12, "Ab3" * 21 + "Z", "Zq9/" * 16]

    def _gate(self, text):
        return [(f.rule_id, f.line) for f in scanners.scan_secrets_text(text) if f.tier == "gate"]

    def test_a_header_in_a_comparison_does_not_gate(self):
        text = f'if b"{self.HEADER}" in data:\n    body = data.split(b"{self.HEADER}", 1)[1]\n'
        assert self._gate(text) == []
        advisory = scanners.scan_secrets_text(text, include_advisory=True)
        assert [(f.rule_id, f.tier, f.line) for f in advisory] == [
            ("private-key-pem", "advisory", 1), ("private-key-pem", "advisory", 2)]

    def test_a_pem_block_gates_once_at_its_header_without_showing_the_body(self):
        end = _tok("-----END ", "OPENSSH ", "PRIVATE KEY-----")
        findings = scanners.scan_secrets_text("\n".join(["key:", self.HEADER, *self.BODY, end]))
        assert [(f.rule_id, f.tier, f.line) for f in findings] == [("private-key-pem", "gate", 2)]
        assert not any(b in json.dumps(findings[0].as_dict()) for b in self.BODY)

    def test_encryption_headers_and_a_blank_line_before_the_body_still_gate(self):
        text = "\n".join([self.HEADER, "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0123456789ABCDEF", "", *self.BODY])
        assert self._gate(text) == [("private-key-pem", 1)]

    def test_a_one_line_string_with_escaped_newlines_gates(self):
        line = _tok('KEY = "', "-----BEGIN ", "PRIVATE KEY-----", "\\n", self.BODY[0], "\\n", "-----END ", 'PRIVATE KEY-----"')
        findings = scanners.scan_secrets_text(line)
        assert [(f.rule_id, f.tier) for f in findings] == [("private-key-pem", "gate")]
        assert self.BODY[0] not in json.dumps(findings[0].as_dict())

    @pytest.mark.parametrize("after", [[], ["see the docs for how to rotate it"], ["# note"] * 7],
                             ids=["last-line", "prose", "beyond-window"])
    def test_a_header_without_key_material_in_its_window_does_not_gate(self, after):
        assert self._gate("\n".join([self.HEADER, *after, *(self.BODY if after == ["# note"] * 7 else [])])) == []

    def test_the_shipped_packages_have_no_gate_finding(self):
        found = [(f.path, f.line, f.rule_id) for pkg in ("aegis_core", "aegis_cli", "aegis_mcp")
                 for path in sorted((_REPO / pkg).rglob("*.py"))
                 for f in scanners.scan_secrets_file(path, repo_root=_REPO) if f.tier == "gate"]
        assert found == []


class TestSnippetsMaskEverySecretOnTheLine:
    """R-checks-25: a snippet shows no secret-shaped value from its line, whatever the scan mode,
    the hash-field guard, the dedupe order or whether the format gates."""

    GH = _tier_a_samples()["github-pat"]
    PASSWORD = _tok("hunter2", "Hunter2!")

    def _clean(self, findings, *raws):
        assert findings
        for f in findings:
            assert not any(raw in json.dumps(f.as_dict()) for raw in raws), f.rule_id

    @pytest.mark.parametrize("include_advisory", [False, True], ids=["gate", "advisory"])
    def test_an_unreported_assignment_beside_a_gate_token_is_masked(self, include_advisory):
        findings = scanners.scan_secrets_text(f'PASSWORD = "{self.PASSWORD}"  # {self.GH}', include_advisory=include_advisory)
        self._clean(findings, self.PASSWORD, self.GH)
        gate = [f for f in findings if f.tier == "gate"]
        assert [f.rule_id for f in gate] == ["github-pat"]
        assert scanners.mask_secret(self.GH) in gate[0].snippet and gate[0].snippet.startswith('PASSWORD = "')

    def test_a_high_entropy_blob_beside_a_gate_token_is_masked(self):
        blob = _tok("9zY8xW7vU6tS5rQ4", "pO3nM2lK1jI0hG+fE/dC=")
        findings = scanners.scan_secrets_text(f'blob = "{blob}" k={self.GH}')
        assert [f.rule_id for f in findings] == ["github-pat"]
        self._clean(findings, blob, self.GH)

    def test_the_hash_field_guard_does_not_unmask_the_line(self):
        findings = scanners.scan_secrets_text(f'git commit; PASSWORD = "{self.PASSWORD}" key={self.GH}', include_advisory=True)
        assert [f.rule_id for f in findings] == ["github-pat"]
        self._clean(findings, self.PASSWORD, self.GH)

    @pytest.mark.parametrize("include_advisory", [False, True], ids=["gate", "advisory"])
    def test_a_short_url_password_does_not_shield_a_longer_value(self, include_advisory):
        line = _tok('u = "https://svc:abc@host.example.net/x"; PASSWORD = "abcd', 'efghijkl"')
        findings = scanners.scan_secrets_text(line, include_advisory=include_advisory)
        assert findings and not any("defghij" in f.snippet for f in findings)

    @pytest.mark.parametrize("other,shown", [
        (_tok("glp", "at-", "AbCdEfGhIjKlMnOpQrSt"), "[REDACTED_VCS_TOKEN]"),
        (_tok("npm", "_", "AbCdEfGhIjKlMnOpQrStUvWx12"), "[REDACTED_TOKEN]"),
        (_tok("py", "pi-", "AbCdEfGhIjKlMnOpQrStUvWx12"), "[REDACTED_TOKEN]"),
        (_tok("sk", "_test_", "AbCdEfGhIjKlMnOpQrStUvWx"), "[REDACTED_API_KEY]"),
    ], ids=["glpat", "npm", "pypi", "sk-test"])
    def test_an_ungated_vendor_token_is_masked_but_not_reported(self, other, shown):
        findings = scanners.scan_secrets_text(f"a={self.GH} b={other}")
        assert [f.rule_id for f in findings] == ["github-pat"]
        self._clean(findings, other, self.GH)
        assert shown in findings[0].snippet

    def test_a_bearer_credential_beside_a_gate_token_is_masked(self):
        bearer = _tok("abcdEFGH1234", "ijklMNOP5678qrst")
        findings = scanners.scan_secrets_text(f'curl -H "Authorization: Bearer {bearer}" {self.GH}')
        assert [f.rule_id for f in findings] == ["github-pat"]
        self._clean(findings, bearer, self.GH)
        assert "Bearer [REDACTED]" in findings[0].snippet

    def test_a_reported_token_keeps_its_prefix_and_last_two_mask(self):
        (finding,) = scanners.scan_secrets_text(f"TOKEN = '{self.GH}'\n", path="app.py")
        assert finding.snippet == f"TOKEN = '{scanners.mask_secret(self.GH)}'"

    def test_the_fingerprint_does_not_depend_on_the_scan_mode(self):
        line = f'PASSWORD = "{self.PASSWORD}"  # {self.GH}'
        off = scanners.scan_secrets_text(line, path="a.py")
        on = [f for f in scanners.scan_secrets_text(line, path="a.py", include_advisory=True) if f.tier == "gate"]
        assert [(f.fingerprint, f.snippet) for f in off] == [(f.fingerprint, f.snippet) for f in on]

    def test_a_clean_line_yields_no_finding(self):
        assert scanners.scan_secrets_text(f'PASSWORD = "{self.PASSWORD}"\nx = 1\n') == []


class TestTierBAndTierCAdvisory:
    def test_advisory_tiers_only_emitted_when_include_advisory_true(self) -> None:
        # Tier B: generic-secret-assign; Tier C: high-entropy-token
        high_entropy = _tok("9zY8xW7vU6tS5rQ4pO3nM2lK1jI0hG+fE/dC=")
        text = (
            'custom_secret = "mY_sUp3r_s3cR3t_vAlU3_99!"\n'
            f'blob = "{high_entropy}"\n'
        )
        assert scanners.scan_secrets_text(text, include_advisory=False) == []

        advisory_findings = scanners.scan_secrets_text(text, include_advisory=True)
        rule_ids = {f.rule_id for f in advisory_findings}
        assert "generic-secret-assign" in rule_ids
        assert "high-entropy-token" in rule_ids
        assert all(f.tier == "advisory" for f in advisory_findings)

    def test_advisory_tiers_suppressed_on_hash_and_integrity_fields(self) -> None:
        high_entropy = _tok("9zY8xW7vU6tS5rQ4pO3nM2lK1jI0hG+fE/dC=")
        text = (
            f'sha256_digest = "{high_entropy}"\n'
            f'"integrity": "{high_entropy}"\n'
            f'checksum_token = "{high_entropy}"\n'
        )
        assert scanners.scan_secrets_text(text, include_advisory=True) == []

    def test_scan_secrets_file_and_workspace(self, tmp_path: Path) -> None:
        secret = _tier_a_samples()["slack-token"]
        src_file = tmp_path / "pkg" / "client.py"
        src_file.parent.mkdir(parents=True)
        src_file.write_text(f'SLACK = "{secret}"\n', encoding="utf-8")

        file_findings = scanners.scan_secrets_file(src_file, repo_root=tmp_path)
        assert len(file_findings) == 1
        assert file_findings[0].path == "pkg/client.py"
        assert file_findings[0].rule_id == "slack-token"

        ws_findings = scanners.scan_secrets_workspace(tmp_path)
        assert len(ws_findings) == 1
        assert ws_findings[0].rule_id == "slack-token"


class TestKeyValueRedaction:
    # Values stay under 20 characters so the high-entropy fallback cannot mask a broken key=value rule.
    @pytest.mark.parametrize(
        ("text", "secret", "context"),
        [
            (_tok("password", "=hunter2abc"), "hunter2abc", "password"),
            (_tok("api_key", ": Zx9Qw3rt"), "Zx9Qw3rt", "api_key"),
            (_tok("PASSWORD", " = 'hunter2abc'"), "hunter2abc", "PASSWORD"),
            (_tok('{"password"', ': "hunter2abc", "user": "bob"}'), "hunter2abc", '"user": "bob"'),
            (_tok("the password", " is hunter2abc, rotate it"), "hunter2abc", "rotate it"),
            (_tok("export DB_PASSWORD", "=p@ss/w0rd+x"), "p@ss/w0rd+x", "export DB_PASSWORD"),
            (_tok("client_secret", "=abcd"), "abcd", "client_secret"),
        ],
        ids=["eq", "colon", "quoted", "json", "prose", "export", "short"],
    )
    def test_short_key_value_secret_is_redacted(self, text: str, secret: str, context: str) -> None:
        out = scanners.redact_insight_text(text, max_len=300)
        assert secret not in out
        assert "[REDACTED]" in out
        assert context in out
        assert scanners.redact_insight_text(out, max_len=300) == out

    def test_value_under_four_characters_is_kept_by_design(self) -> None:
        assert scanners.redact_insight_text("pwd=abc", max_len=300) == "pwd=abc"

    @pytest.mark.parametrize("text, secret", [
        (_tok("authorization: ", "Basic dXNlcjpwYXNz"), "dXNlcjpwYXNz"),
        (_tok("Proxy-Authorization: ", "Basic Zm9vOmJhcg=="), "Zm9vOmJhcg=="),
        (_tok("auth", "=abcd1234"), "abcd1234"),
    ], ids=["basic", "proxy-basic", "auth"])
    def test_authorization_credentials_are_redacted(self, text: str, secret: str) -> None:
        out = scanners.redact_insight_text(text, max_len=300)
        assert secret not in out and "[REDACTED]" in out
        assert scanners.redact_insight_text(out, max_len=300) == out

    @pytest.mark.parametrize("text", ["the author: John Smith wrote this", "authorization: Basic"])
    def test_authorship_and_a_bare_scheme_are_left_alone(self, text: str) -> None:
        assert scanners.redact_insight_text(text, max_len=300) == text


class TestSarifIngest:
    def test_ingest_sarif_fingerprints_delta_and_suppressions(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            "import os\n"
            "os.system('ls')  # noqa: S605\n"
            "eval(user_input)  # nosec\n"
            "x = 1  # gitleaks:allow\n",
            encoding="utf-8",
        )
        (tmp_path / ".gitleaksignore").write_text(
            "# comment line\n"
            "legacy/secret.py:generic-api-key:12\n"
            "docs/example.md:aws-access-key:5\n",
            encoding="utf-8",
        )

        line1 = "os.system(cmd)"
        line2 = "eval(   untrusted_input   )"
        norm2 = "eval( untrusted_input )"
        expected_fp1 = hashlib.sha256(f"S605|app.py|{line1}".encode("utf-8")).hexdigest()[:16]
        expected_fp2 = hashlib.sha256(f"S307|app.py|{norm2}".encode("utf-8")).hexdigest()[:16]

        sarif_doc = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ruff"}},
                    "results": [
                        {
                            "ruleId": "S605",
                            "level": "error",
                            "message": {"text": "Starting a process with a shell"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 10, "snippet": {"text": line1}},
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "S307",
                            "level": "warning",
                            "message": {"text": "Use of possibly insecure eval"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 20, "snippet": {"text": line2}},
                                    }
                                }
                            ],
                        },
                    ],
                }
            ],
        }

        report = scanners.ingest_sarif(sarif_doc, workspace_root=tmp_path)
        assert report["status"] == "fail"
        assert report["total_raw"] == 2
        assert [(f.rule_id, f.fingerprint) for f in report["findings"]] == [("S605", expected_fp1), ("S307", expected_fp2)]
        # the document's own suppressions only; in-repository markers are suppression_count's (R-checks-20)
        assert report["suppression_count"] == 0


_SARIF_ONE_FINDING = {
    "runs": [{"results": [{
        "ruleId": "S307", "level": "error", "message": {"text": "eval"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app.py"},
            "region": {"startLine": 1, "snippet": {"text": "eval(x)"}},
        }}],
    }]}],
}


def _sarif_for(uri: str, *, line: int = 1, snippet: str | None = None, message: str = "reported message") -> dict:
    region: dict = {"startLine": line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    return {"version": "2.1.0", "runs": [{"results": [{
        "ruleId": "S100", "level": "error", "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
    }]}]}


class TestSarifIngestStaysInsideWorkspace:
    """R-checks-16: ingest_sarif reads only files whose real location is inside the workspace,
    labels paths from the workspace (not the cwd) with dot-directories intact, never raises on
    a bad URI and never displays an unmasked secret line."""

    SENTINEL = "TOP-SECRET-OUTSIDE-LINE"

    @pytest.fixture
    def tree(self, tmp_path: Path):
        ws = tmp_path / "ws"
        (ws / "sub").mkdir(parents=True)
        (ws / ".github").mkdir()
        (ws / "sub" / "app.py").write_bytes(b"first\nin-tree line\n")
        (ws / ".github" / "ci.yml").write_bytes(b"on: push\n")
        outside = tmp_path / "outside.txt"
        outside.write_bytes(self.SENTINEL.encode() + b"\n")
        return ws, outside

    @staticmethod
    def _only_finding(doc: dict, ws: Path) -> scanners.Finding:
        report = scanners.ingest_sarif(doc, workspace_root=ws)
        assert (report["status"], report["total_raw"]) == ("fail", 1)  # kept, never silently dropped
        return report["findings"][0]

    @pytest.mark.parametrize("form", ["dotdot", "leading-dotdot", "absolute", "file-uri"])
    def test_a_uri_outside_the_workspace_is_not_read(self, tree, form):
        ws, outside = tree
        uri = {"dotdot": "sub/../../outside.txt", "leading-dotdot": "../outside.txt",
               "absolute": str(outside), "file-uri": "file://" + str(outside)}[form]
        finding = self._only_finding(_sarif_for(uri), ws)
        assert self.SENTINEL not in json.dumps(finding.as_dict())
        assert finding.snippet == "reported message"
        assert ".." not in finding.path.split("/")

    def test_a_symlink_out_of_the_workspace_is_not_followed(self, tree):
        ws, outside = tree
        try:
            os.symlink(outside.parent, ws / "escape")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are unavailable")
        finding = self._only_finding(_sarif_for("escape/outside.txt"), ws)
        assert self.SENTINEL not in json.dumps(finding.as_dict())
        assert finding.snippet == "reported message"


    @pytest.mark.parametrize("uri", ["sub/app.py", "./sub/app.py", "ABS", "FILE"])
    def test_an_in_tree_uri_reads_the_reported_line(self, tree, uri):
        ws, _ = tree
        target = ws / "sub" / "app.py"
        uri = {"ABS": str(target), "FILE": "file://" + str(target)}.get(uri, uri)
        finding = self._only_finding(_sarif_for(uri, line=2), ws)
        assert (finding.path, finding.line, finding.snippet) == ("sub/app.py", 2, "in-tree line")

    def test_paths_resolve_against_the_workspace_and_keep_dot_directories(self, tree, monkeypatch):
        ws, _ = tree
        monkeypatch.chdir(ws / "sub")
        nested = self._only_finding(_sarif_for("sub/app.py", line=2), ws)
        dotted = self._only_finding(_sarif_for(".github/ci.yml"), ws)
        assert (nested.path, nested.snippet) == ("sub/app.py", "in-tree line")
        assert (dotted.path, dotted.snippet) == (".github/ci.yml", "on: push")
        assert scanners.ingest_sarif(_sarif_for(".github/ci.yml"))["findings"][0].path == ".github/ci.yml"

    @pytest.mark.parametrize("uri", ["bad\0name.py", "x/" + "y" * 5000], ids=["nul", "long"])
    def test_an_unresolvable_uri_is_kept_without_raising(self, tree, uri):
        ws, _ = tree
        assert self._only_finding(_sarif_for(uri), ws).snippet == "reported message"

    def test_a_secret_on_the_disk_line_is_displayed_masked(self, tree):
        ws, _ = tree
        token = _tier_a_samples()["github-pat"]
        (ws / "sub" / "keys.py").write_bytes(f"TOKEN = '{token}'\n".encode())
        finding = self._only_finding(_sarif_for("sub/keys.py"), ws)
        assert token not in json.dumps(finding.as_dict())
        assert finding.snippet == f"TOKEN = '{scanners.mask_secret(token)}'"
        assert finding.fingerprint == scanners.sarif_fingerprint("S100", "sub/keys.py", f"TOKEN = '{token}'")


def _secret() -> str:
    return _tier_a_samples()["stripe-live-secret"]


def _one_result(**result: object) -> dict:
    return {"version": "2.1.0", "runs": [{"results": [result]}]}


_MALFORMED_DOCS = {
    "empty-object": {},
    "error-object": {"error": "config invalid"},
    "runs-string": {"runs": "x"},
    "run-string": {"runs": ["x"]},
    "results-object": {"runs": [{"results": {"a": 1}}]},
    "result-string": {"runs": [{"results": ["x"]}]},
    "message-string": _one_result(message="SECRET"),
    "locations-string": _one_result(locations="SECRET"),
    "location-string": _one_result(locations=["SECRET"]),
    "region-string": _one_result(locations=[{"physicalLocation": {"region": "SECRET"}}]),
    "startline-text": _one_result(locations=[{"physicalLocation": {"region": {"startLine": "SECRET"}}}]),
    "startline-float": _one_result(locations=[{"physicalLocation": {"region": {"startLine": 2.5}}}]),
    "suppressions-number": _one_result(suppressions=5, message={"text": "SECRET"}),
}


_CLEAN_SARIF = '{"version": "2.1.0", "runs": [{"results": []}]}'


class TestSarifVerdictNeedsACompletedScan:
    """R-checks-17: a scanner result is ``pass`` only when the scan demonstrably ran and its output
    was understood; anything else is ``unverified``, and untrusted output never raises."""

    @staticmethod
    def _fill(value):
        if isinstance(value, dict):
            return {k: TestSarifVerdictNeedsACompletedScan._fill(v) for k, v in value.items()}
        if isinstance(value, list):
            return [TestSarifVerdictNeedsACompletedScan._fill(v) for v in value]
        return _secret() if value == "SECRET" else value

    @pytest.mark.parametrize("case", sorted(_MALFORMED_DOCS))
    def test_a_malformed_document_is_unverified_with_a_short_reason(self, case, tmp_path):
        report = scanners.ingest_sarif(self._fill(_MALFORMED_DOCS[case]), workspace_root=tmp_path)
        assert (report["status"], report["findings"]) == ("unverified", [])
        assert 0 < len(report["reason"]) <= 200 and _secret() not in report["reason"]

    def test_a_value_that_is_not_a_mapping_is_unverified(self):
        assert scanners.ingest_sarif([])["status"] == "unverified"  # type: ignore[arg-type]

    @pytest.mark.parametrize("doc", [{"version": "2.1.0", "runs": []}, {"runs": None}, {"runs": [{"results": []}]}],
                             ids=["runs-empty", "runs-null", "results-empty"])
    def test_a_valid_empty_document_still_passes(self, doc):
        report = scanners.ingest_sarif(doc)
        assert (report["status"], report["total_raw"]) == ("pass", 0)

    @staticmethod
    def _run(rc, stdout, stderr="scanner said so", base_stdout=_CLEAN_SARIF):
        """run_preset with a runner that answers ``stdout`` on the head and ``base_stdout`` on the base."""
        root = _git_ws()

        def runner(argv, cwd, env=None, timeout=60):
            if Path(cwd).resolve() != root.resolve():
                return {"returncode": 1 if base_stdout != _CLEAN_SARIF else 0, "stdout": base_stdout, "stderr": ""}
            res = {"stdout": stdout, "stderr": stderr}
            return res if rc == "none" else {**res, "returncode": rc}
        return scanners.run_preset("ruff", root, "HEAD", runner=runner)

    @pytest.mark.parametrize("rc,stdout", [
        (0, ""), (0, "   \n"), (0, "all good"), (0, "[]"), (0, "null"), (0, "{}"), (0, '{"error":"boom"}'),
        (0, "\ufeff" + json.dumps(_SARIF_ONE_FINDING)), (0, "INFO scanning\n" + json.dumps(_SARIF_ONE_FINDING)),
        (0, '{"runs": []}'), (1, '{"version": "2.1.0", "runs": [{"results": ['), (1, '{"runs": [{"results": []}]}'),
        (2, '{"runs": [{"results": []}]}'), (-9, '{"runs": [{"results": []}]}'), ("none", '{"runs": [{"results": []}]}'),
        (0, '{"a":' * 100_000), (0, "SECRET not json"),
    ], ids=["empty", "blank", "text", "array", "null", "object", "error", "bom", "log-prefix", "no-run", "truncated",
            "rc1-clean", "rc2-clean", "killed", "no-rc", "deep", "secret-text"])
    def test_output_that_is_not_a_completed_scan_is_unverified(self, rc, stdout):
        report = self._run(rc, stdout.replace("SECRET", _secret()))
        assert (report["status"], report["findings"]) == ("unverified", [])
        assert "scanner said so" in report["reason"] and _secret() not in report["reason"]

    def test_empty_output_without_stderr_names_the_program(self):
        report = self._run(0, "", stderr="")
        assert report["status"] == "unverified" and report["reason"] == "ruff produced no SARIF output"

    def test_a_clean_completed_scan_passes(self):
        assert self._run(0, _CLEAN_SARIF)["status"] == "pass"

    @pytest.mark.parametrize("rc", [0, 1, 2])
    def test_a_new_finding_fails_whatever_the_exit_code(self, rc):
        report = self._run(rc, json.dumps(_SARIF_ONE_FINDING))
        assert report["status"] == "fail" and [f.rule_id for f in report["findings"]] == ["S307"]

    def test_the_exit_code_is_judged_on_raw_findings_not_the_base_delta(self):
        baselined = self._run(1, json.dumps(_SARIF_ONE_FINDING), base_stdout=json.dumps(_SARIF_ONE_FINDING))
        assert (baselined["status"], baselined["subtracted"], baselined["findings"]) == ("pass", 1, [])
        crashed = self._run(2, json.dumps(_SARIF_ONE_FINDING), stderr="crashed", base_stdout=json.dumps(_SARIF_ONE_FINDING))
        assert (crashed["status"], crashed["reason"]) == ("unverified", "crashed")

    def test_a_base_scan_that_does_not_complete_is_unverified(self):
        report = self._run(1, json.dumps(_SARIF_ONE_FINDING), base_stdout="not sarif")
        assert (report["status"], report["findings"]) == ("unverified", [])
        assert report["reason"].startswith("the merge-base scan: ")


def _git_ws(root: Path | None = None) -> Path:
    """A one-commit repository (``app.py`` holds ``eval(x)``) under a fresh temporary directory."""
    import subprocess
    import tempfile

    root = root or Path(tempfile.mkdtemp(prefix="aegis-scan-test-"))
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_bytes(b"eval(x)\n")
    for args in (["init", "-q", "-b", "main"], ["add", "-A"],
                 ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "c"]):
        subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True,
                       env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"})
    return root


class TestExternalScannerPresets:
    def test_ruff_preset_argv_isolated_and_ignores_s603_s607(self) -> None:
        argv = scanners.PRESET_ARGV["ruff"]
        assert argv[:2] == ("ruff", "check")
        assert "--isolated" in argv
        assert argv[argv.index("--select") + 1] == "S"
        assert argv[argv.index("--ignore") + 1] == "S603,S607"

    def test_the_presets_are_the_names_the_config_key_accepts(self) -> None:
        from aegis_core.config import SCANNER_PRESETS

        assert tuple(scanners.PRESET_ARGV) == SCANNER_PRESETS

    def test_an_unknown_preset_is_refused(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="bandit"):
            scanners.run_preset("bandit", tmp_path, "HEAD")

    @pytest.fixture
    def home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        home = tmp_path / "home"
        (home / ".aegis").mkdir(parents=True)
        for name in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(name, str(home))
        return home

    @staticmethod
    def _stub(calls: list):
        def runner(argv, cwd, env=None, timeout=60):
            calls.append(list(argv))
            return {"returncode": 0, "stdout": _CLEAN_SARIF, "stderr": ""}
        return runner

    @staticmethod
    def _allow_all_repo(tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".gitleaks.toml").write_bytes(b'[allowlist]\npaths = [".*"]\n')
        return repo

    def test_gitleaks_preset_uses_redact_and_only_user_scope_config(self, tmp_path: Path, home: Path) -> None:
        user_cfg = home / ".aegis" / "gitleaks.toml"
        user_cfg.write_bytes(b"# trusted user config\n")
        (tmp_path / "repo").mkdir()
        calls: list = []
        scanners.run_preset("gitleaks", tmp_path / "repo", "HEAD", runner=self._stub(calls))
        assert "--redact" in calls[0]
        assert calls[0][calls[0].index("--config") + 1] == str(user_cfg.resolve())

    def test_a_repository_gitleaks_config_without_a_user_config_is_unverified(self, tmp_path, home):
        """R-checks-18: gitleaks would read <source>/.gitleaks.toml when no --config is given, so a
        repository allowlist could silence every finding; the preset refuses to run instead."""
        calls: list = []
        res = scanners.run_preset("gitleaks", self._allow_all_repo(tmp_path), "HEAD", runner=self._stub(calls))
        assert (res["status"], res["findings"], calls) == ("unverified", [], [])
        assert ".gitleaks.toml" in res["reason"]

    def test_a_user_config_is_passed_explicitly_over_a_repository_config(self, tmp_path, home):
        user_cfg = home / ".aegis" / "gitleaks.toml"
        user_cfg.write_bytes(b"# trusted user config\n")
        calls: list = []
        res = scanners.run_preset("gitleaks", self._allow_all_repo(tmp_path), "HEAD", runner=self._stub(calls))
        assert res["status"] == "pass"
        assert calls[0][calls[0].index("--config") + 1] == str(user_cfg.resolve())

    def test_a_user_config_dir_inside_the_repository_does_not_count(self, tmp_path, monkeypatch):
        repo = self._allow_all_repo(tmp_path)
        (repo / ".aegis").mkdir()
        (repo / ".aegis" / "gitleaks.toml").write_bytes(b"# planted\n")
        for name in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(name, str(repo))
        calls: list = []
        res = scanners.run_preset("gitleaks", repo, "HEAD", runner=self._stub(calls))
        assert (res["status"], calls) == ("unverified", [])

    def test_a_dangling_repository_config_symlink_still_counts(self, tmp_path, home):
        repo = tmp_path / "repo"
        repo.mkdir()
        try:
            os.symlink(tmp_path / "nowhere.toml", repo / ".gitleaks.toml")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are unavailable")
        calls: list = []
        res = scanners.run_preset("gitleaks", repo, "HEAD", runner=self._stub(calls))
        assert (res["status"], calls) == ("unverified", [])

    def test_with_neither_config_gitleaks_runs_redacted_without_a_config(self, tmp_path, home):
        calls: list = []
        res = scanners.run_preset("gitleaks", tmp_path, "HEAD", runner=self._stub(calls))
        assert res["status"] == "pass"
        assert "--redact" in calls[0] and "--config" not in calls[0]

    def test_the_ruff_preset_ignores_a_repository_gitleaks_config(self, tmp_path, home):
        calls: list = []
        res = scanners.run_preset("ruff", self._allow_all_repo(tmp_path), "HEAD", runner=self._stub(calls))
        assert res["status"] == "pass" and calls[0][0] == "ruff"

    def test_missing_binary_returns_unverified_not_pass(self, tmp_path: Path) -> None:
        def fake_missing_runner(argv, cwd, env=None, timeout=60):
            return {"returncode": 127, "stdout": "", "stderr": f"{argv[0]}: not found", "missing_binary": True,
                    "timed_out": False}

        res = scanners.run_preset("gitleaks", tmp_path, "HEAD", runner=fake_missing_runner)
        assert res["status"] == "unverified"
        assert "not found" in res["reason"].lower()

    def test_the_base_is_scanned_only_when_the_head_has_findings(self, tmp_path, home):
        calls: list = []
        scanners.run_preset("ruff", tmp_path, "no-such-commit", runner=self._stub(calls))
        assert len(calls) == 1

    def test_a_merge_base_that_cannot_be_exported_is_unverified(self, tmp_path, home):
        root = _git_ws(tmp_path / "ws")
        res = scanners.run_preset("ruff", root, "no-such-commit",
                                  runner=lambda argv, cwd, **kw: {"returncode": 1, "stdout": json.dumps(_SARIF_ONE_FINDING)})
        assert (res["status"], res["findings"]) == ("unverified", [])


def _program(path: Path, body: str) -> Path:
    """A Python program PATH lookup finds as ``path.name`` (a .cmd launcher on Windows)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        script = path.with_name(path.name + "-script.py")
        script.write_bytes(body.encode("utf-8"))
        launcher = path.with_name(path.name + ".cmd")
        launcher.write_bytes(f'@"{sys.executable}" "{script}" %*\r\n'.encode("utf-8"))
        return launcher
    path.write_bytes(f"#!{sys.executable}\n{body}".encode("utf-8"))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _set_path(monkeypatch: pytest.MonkeyPatch, *entries: str) -> None:
    if os.name == "nt":
        entries = (*entries, os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"))
    monkeypatch.setenv("PATH", os.pathsep.join(entries))


class TestPresetScannerProgramLookup:
    """R-checks-15: a preset runs the ruff or gitleaks found in an absolute PATH entry outside the
    repository. An empty or relative entry names the cwd (the repository), so a bare name would
    run a program the repository planted and take its silence for a clean scan."""

    @pytest.fixture
    def repo(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        root = tmp_path / "repo"
        root.mkdir()
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.chdir(root)  # Windows' CreateProcess searches the parent's cwd, not cwd=
        return root

    @staticmethod
    def _plant(root: Path, name: str, marker: Path) -> None:
        body = f"open({str(marker)!r}, 'w').close()\n"
        _program(root / name, body)
        _program(root / "bin" / name, body)

    @pytest.mark.parametrize("preset", ["ruff", "gitleaks"])
    @pytest.mark.parametrize("entry", ["", ".", "bin", "REPO_BIN"], ids=["empty", "dot", "rel", "abs"])
    def test_a_scanner_the_repository_planted_never_runs(self, repo, tmp_path, monkeypatch, preset, entry):
        marker = tmp_path / "planted-ran"
        self._plant(repo, preset, marker)
        trusted = tmp_path / "trusted"
        trusted.mkdir()  # holds no scanner: the real one is not installed
        _set_path(monkeypatch, str(repo / "bin") if entry == "REPO_BIN" else entry, str(trusted))

        res = scanners.run_preset(preset, repo, "HEAD")

        assert not marker.exists(), "a program the repository planted ran"
        assert res["status"] == "unverified"
        assert "not found" in res["reason"].lower()

    @pytest.mark.parametrize("preset", ["ruff", "gitleaks"])
    def test_a_scanner_installed_outside_the_repository_runs(self, repo, tmp_path, monkeypatch, preset):
        marker = tmp_path / "planted-ran"
        self._plant(repo, preset, marker)
        trusted = tmp_path / "trusted"
        _git_ws(repo)  # the base export holds the same eval(x); the fake reports it on the head only
        real = os.path.realpath(repo)
        _program(trusted / preset, "import json, os, sys\n"
                 f"found = os.path.realpath(sys.argv[-1]) == {real!r}\n"
                 f"print(json.dumps({_SARIF_ONE_FINDING!r} if found else {{'runs': [{{'results': []}}]}}))\n")
        import shutil
        _set_path(monkeypatch, "", "bin", str(repo / "bin"), str(trusted), os.path.dirname(shutil.which("git")))

        res = scanners.run_preset(preset, repo, "HEAD")

        assert not marker.exists()
        assert res["status"] == "fail"
        assert [f.rule_id for f in res["findings"]] == ["S307"]

    def test_an_injected_runner_receives_the_bare_argv(self, tmp_path):
        seen = []

        def runner(argv, cwd, env=None, timeout=60):
            seen.append(list(argv))
            return {"returncode": 0, "stdout": json.dumps(_SARIF_ONE_FINDING), "stderr": ""}

        scanners.run_preset("ruff", _git_ws(tmp_path / "ws"), "HEAD", runner=runner)
        assert [argv[0] for argv in seen] == ["ruff", "ruff"]  # the head, then the merge-base export


class TestSecuritySuppressionCount:
    """R-checks-20: the suppression signal counts markers that silence security findings, over the
    files git tracks, with bounded reads, and reports head minus the merge base."""

    @staticmethod
    def _git(root: Path, *args: str) -> None:
        import subprocess

        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=str(root),
                       check=True, capture_output=True, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"})

    def _repo(self, root: Path, files: dict) -> str:
        root.mkdir(parents=True, exist_ok=True)
        if not (root / ".git").exists():
            self._git(root, "init", "-q", "-b", "main")
        for rel, data in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(data)
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "c", "--allow-empty")
        import subprocess
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, check=True).stdout.decode().strip()

    def test_only_security_markers_in_tracked_files_count(self, tmp_path):
        root = tmp_path / "ws"
        base = self._repo(root, {"keep.txt": b"x\n"})
        self._repo(root, {
            "app.py": (b"a = eval(x)  # noqa: S307\nb = 1  # nosec\nc = 2  # gitleaks:allow\nimport os  # noqa\n"
                       b"x=1  # noqa: E501\ny = eval(z)  # noqa: E501, S307\n"),
            ".gitleaksignore": b"# a comment line\nlegacy/secret.py:generic-api-key:12\n\ndocs/example.md:aws-access-key:5\n",
        })
        (root / "venv").mkdir()
        (root / "venv" / "lib.py").write_bytes(b"x = 1  # noqa: S101\n" * 100)  # untracked: never read
        assert scanners.suppression_count(root, base) == {"count": 6, "delta": 6}

    def test_the_delta_is_head_minus_the_merge_base(self, tmp_path):
        root = tmp_path / "ws"
        base = self._repo(root, {"a.py": b"x = 1  # nosec\n"})
        self._repo(root, {"a.py": b"x = 1  # nosec\ny = 2  # nosec\nz = 3  # noqa: S105\n"})
        assert scanners.suppression_count(root, base) == {"count": 3, "delta": 2}

    def test_large_binary_and_unreadable_files_are_skipped_without_raising(self, tmp_path):
        root = tmp_path / "ws"
        base = self._repo(root, {"keep.txt": b"x\n"})
        self._repo(root, {"big.py": b"x = 1  # nosec\n" * (5 * 1024 * 1024 // 15 + 1),
                          "blob.bin": b"\0\1\2 # nosec\n", "a.py": b"x = 1  # nosec\n", "locked.py": b"y = 1  # nosec\n"})
        locked = root / "locked.py"
        locked.chmod(0)
        try:
            readable = os.access(locked, os.R_OK)  # root, or Windows, still reads it
            counted = scanners.suppression_count(root, base)
        finally:
            locked.chmod(0o644)
        assert counted["count"] == (2 if readable else 1)

    def test_a_merge_base_that_cannot_be_exported_has_no_delta(self, tmp_path):
        root = tmp_path / "ws"
        self._repo(root, {"a.py": b"x = 1  # nosec\n"})
        assert scanners.suppression_count(root, "no-such-commit") == {"count": 1, "delta": None}


class TestGitleaksAllowInOtherLanguages:
    """`gitleaks:allow` after any comment opener the scanned languages use (#, // or /*) skips the line in
    the Layer 1 secret delta and is counted as a suppression; anywhere else it is just text."""

    TOKEN = "ghp_" + "Ab3" * 12  # the GitHub classic PAT shape, built so no token literal sits here

    def _scan(self, tmp_path: Path, line: str) -> list:
        (tmp_path / "client.ts").write_bytes((line + "\n").encode("utf-8"))
        return [f.rule_id for f in scanners.scan_secrets_delta(tmp_path, ["client.ts"], {})]

    @pytest.mark.parametrize("marker", ["# gitleaks:allow", "// gitleaks:allow", "//gitleaks:allow",
                                        "/* gitleaks:allow */", "/*gitleaks:allow*/"])
    def test_the_marker_after_a_comment_opener_skips_the_line(self, tmp_path, marker):
        assert self._scan(tmp_path, f'const t = "{self.TOKEN}"; {marker}') == []

    @pytest.mark.parametrize("line", ['const t = "{t}";', 'const t = "{t}"; / gitleaks:allow',
                                      'const t = "{t}gitleaks:allow";', 'const t = "{t}"; // gitleaks:allowed'])
    def test_without_a_comment_opener_the_token_still_blocks(self, tmp_path, line):
        assert self._scan(tmp_path, line.format(t=self.TOKEN)) == ["github-pat"]

    def test_each_marker_is_counted_as_a_suppression(self, tmp_path):
        root = tmp_path / "ws"
        files = {"a.ts": b'a = 1; // gitleaks:allow\nb = 2; /* gitleaks:allow */\n', "b.go": b"c := 3 //gitleaks:allow\n"}
        counter = TestSecuritySuppressionCount()
        base = counter._repo(root, {"keep.txt": b"x\n"})
        counter._repo(root, files)
        assert scanners.suppression_count(root, base) == {"count": 3, "delta": 3}
