"""Behavioral tests for Tier A/B/C secret scanner, SARIF 2.1.0 ingest, and external presets."""
from __future__ import annotations

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
        "private-key-pem": _tok("-----BEGIN ", "RSA ", "PRIVATE KEY-----"),
        "jwt-three-segment": _tok(
            "eyJ", "hbGciOiJIUzI1NiJ9", ".",
            "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ),
        "url-basic-auth": _tok("https://", "svc_admin", ":", "p9Q8r7S6t5U4", "@api.internal.corp/v1"),
    }


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

    def test_redos_and_minified_line_guard_under_50ms(self) -> None:
        adversarial = _tok("sk", "-") + ("a" * 100_000)
        start = time.perf_counter()
        findings = scanners.scan_secrets_text(adversarial, include_advisory=True)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert elapsed_ms < 50.0, f"100 KB line took {elapsed_ms:.2f}ms (> 50ms)"
        assert findings == []


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

        report = scanners.ingest_sarif(
            json.dumps(sarif_doc),
            workspace_root=tmp_path,
            base_fingerprints={expected_fp1},
        )
        assert report["status"] == "fail"
        assert report["total_raw"] == 2
        assert report["base_subtracted"] == 1
        assert len(report["findings"]) == 1
        finding = report["findings"][0]
        assert finding.rule_id == "S307"
        assert finding.fingerprint == expected_fp2
        # 3 inline suppressions (noqa, nosec, gitleaks:allow) + 2 .gitleaksignore entries = 5
        assert report["suppression_count"] == 5


class TestExternalScannerPresets:
    def test_ruff_preset_argv_isolated_and_ignores_s603_s607(self, tmp_path: Path) -> None:
        argv = scanners.build_preset_argv("ruff", tmp_path)
        assert argv[0] == "ruff"
        assert "--isolated" in argv
        assert "--select" in argv
        assert "S" in argv
        assert "--ignore" in argv
        assert "S603,S607" in argv

    def test_gitleaks_preset_uses_redact_and_only_user_scope_config(self, tmp_path: Path) -> None:
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        repo_cfg = repo_dir / ".gitleaks.toml"
        repo_cfg.write_text("[allowlist]\n", encoding="utf-8")

        user_dir = tmp_path / "user_aegis"
        user_dir.mkdir()
        user_cfg = user_dir / "gitleaks.toml"
        user_cfg.write_text("# trusted user config\n", encoding="utf-8")

        # Repo-local config path must be rejected/ignored
        argv_repo = scanners.build_preset_argv(
            "gitleaks",
            repo_dir,
            user_config_dir=user_dir,
            config_path=repo_cfg,
        )
        assert "--redact" in argv_repo
        assert str(repo_cfg) not in argv_repo

        # User-scope config inside ~/.aegis/ is accepted
        argv_user = scanners.build_preset_argv(
            "gitleaks",
            repo_dir,
            user_config_dir=user_dir,
            config_path=user_cfg,
        )
        assert "--redact" in argv_user
        assert "--config" in argv_user
        cfg_idx = argv_user.index("--config")
        assert argv_user[cfg_idx + 1] == str(user_cfg.resolve())

    def test_missing_binary_returns_unverified_not_pass(self, tmp_path: Path) -> None:
        def fake_missing_runner(argv, cwd, env=None, timeout=60):
            return {
                "returncode": 127,
                "stdout": "",
                "stderr": f"{argv[0]}: not found",
                "missing_binary": True,
                "timed_out": False,
            }

        res = scanners.run_preset_scanner("gitleaks", tmp_path, runner=fake_missing_runner)
        assert res["status"] == "unverified"
        assert "not found" in res["reason"].lower()


_SARIF_ONE_FINDING = {
    "runs": [{"results": [{
        "ruleId": "S307", "level": "error", "message": {"text": "eval"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app.py"},
            "region": {"startLine": 1, "snippet": {"text": "eval(x)"}},
        }}],
    }]}],
}


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

        res = scanners.run_preset_scanner(preset, repo)

        assert not marker.exists(), "a program the repository planted ran"
        assert res["status"] == "unverified"
        assert "not found" in res["reason"].lower()

    @pytest.mark.parametrize("preset", ["ruff", "gitleaks"])
    def test_a_scanner_installed_outside_the_repository_runs(self, repo, tmp_path, monkeypatch, preset):
        marker = tmp_path / "planted-ran"
        self._plant(repo, preset, marker)
        trusted = tmp_path / "trusted"
        _program(trusted / preset, f"import json\nprint(json.dumps({_SARIF_ONE_FINDING!r}))\n")
        _set_path(monkeypatch, "", "bin", str(repo / "bin"), str(trusted))

        res = scanners.run_preset_scanner(preset, repo)

        assert not marker.exists()
        assert res["status"] == "fail"
        assert [f.rule_id for f in res["findings"]] == ["S307"]

    def test_an_injected_runner_receives_the_bare_argv(self, tmp_path):
        seen = []

        def runner(argv, cwd, env=None, timeout=60):
            seen.append(list(argv))
            return {"returncode": 0, "stdout": json.dumps(_SARIF_ONE_FINDING), "stderr": ""}

        scanners.run_preset_scanner("ruff", tmp_path, runner=runner)
        assert [argv[0] for argv in seen] == ["ruff"]
