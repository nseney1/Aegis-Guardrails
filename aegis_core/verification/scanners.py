"""Known-format secret detector, SARIF 2.1.0 ingest, and external scanner presets (v4.3 T7)."""
from __future__ import annotations

import collections
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping, Sequence

from aegis_core import gitsafe
from aegis_core.verification import test_runner

MAX_LINE_LENGTH = 4096
MAX_EXCERPT_CHARS = 300
_B_PRE, _B_SUF = r"(?<![A-Za-z0-9+/_-])", r"(?![A-Za-z0-9+/=_-])"

TIER_A_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws-access-key-id": re.compile(_B_PRE + r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}" + _B_SUF),
    "github-pat": re.compile(_B_PRE + r"gh[pousr]_[A-Za-z0-9]{36,255}" + _B_SUF),
    "github-fine-grained-pat": re.compile(_B_PRE + r"github_pat_[A-Za-z0-9_]{22,255}" + _B_SUF),
    "slack-token": re.compile(_B_PRE + r"xox[abprs]-[A-Za-z0-9-]{10,255}" + _B_SUF),
    "stripe-live-secret": re.compile(_B_PRE + r"[sr]k_live_[0-9A-Za-z]{24,99}" + _B_SUF),
    "anthropic-api-key": re.compile(_B_PRE + r"sk-ant-[A-Za-z0-9_-]{20,255}" + _B_SUF),
    "openai-api-key": re.compile(_B_PRE + r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,255}" + _B_SUF),
    "google-api-key": re.compile(_B_PRE + r"AIza[0-9A-Za-z_-]{35}" + _B_SUF),
    "private-key-pem": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    "jwt-three-segment": re.compile(_B_PRE + r"eyJ[A-Za-z0-9_-]{10,512}\.eyJ[A-Za-z0-9_-]{10,1024}\.[A-Za-z0-9_-]{10,512}" + _B_SUF),
    "url-basic-auth": re.compile(r"://([^/\s:@'\"$<>]{1,64}):([^/\s:@'\"$<>]{3,64})@[A-Za-z0-9.-]{1,253}"),
}

_TIER_B_RE = re.compile(r"""(?i)\b([A-Za-z0-9_.-]{0,32}(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|credential|auth[_-]?token|client[_-]?secret)[A-Za-z0-9_.-]{0,32})\s*[:=]\s*(['"])([^'"\s]{8,256})\2""")
_TIER_C_RE = re.compile(r"""(['"])([A-Za-z0-9+/=_-]{20,256})\1""")
_PLACEHOLDER_RE = re.compile(r"(?i)(?:example|dummy|test|placeholder|changeme|your[_-]|fake|redacted|todo|x{3,}|\*{3,}|\.{3}|^<.*>$|^\$\{?.*\}?$|^%.*%$|^(?:true|false|null|none)$)")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DATA_URL_OR_SRI_RE = re.compile(r"(?:data:[A-Za-z0-9/+.-]{1,64};base64,[A-Za-z0-9+/=]+|\bsha(?:1|256|384|512)-[A-Za-z0-9+/=]{16,})")
_HASH_FIELD_RE = re.compile(r"(?i)(?:^|[^a-z0-9])(?:sha1|sha256|sha384|sha512|md5|integrity|checksum|digest|hash|commit|oid|etag|fingerprint)(?:$|[^a-z0-9])")
_SUPPRESSION_RE = re.compile(r"#\s*(?:noqa|nosec|gitleaks:allow)\b", re.IGNORECASE)

SECRET_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA_REDACTED"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "ASIA_REDACTED"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "ghp_REDACTED"),
    (re.compile(r"gh[ousr]_[a-zA-Z0-9]{36}"), "gh_token_REDACTED"),
    (re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"), "github_pat_REDACTED"),
    (re.compile(r"sk-(?:proj-|ant-)?[a-zA-Z0-9_-]{20,}"), "sk-REDACTED"),
    (re.compile(r"AIzaSy[a-zA-Z0-9_-]{33}"), "AIzaSy_REDACTED"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}"), "Bearer REDACTED"),
    (re.compile(r"GEMINI_API_KEY=[^\s]*"), "GEMINI_API_KEY=REDACTED"),
]
HOOK_REDACTION_PATTERNS = SECRET_REPLACEMENTS

_SENSITIVE_KEYS = r"(?:password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret|auth|credential|authorization)"
_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED_PEM]"),
    (re.compile(r"\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@"), r"\1[REDACTED]@"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bglpat-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_VCS_TOKEN]"),
    (re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}\b|\bnpm_[A-Za-z0-9]{20,}\b|\bAIza[A-Za-z0-9_-]{25,}\b|\bpypi-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"), "Bearer [REDACTED]"),
    (re.compile(rf"(?i)(\b[A-Za-z0-9_]*{_SENSITIVE_KEYS}[A-Za-z0-9_]*[\"']?\s*(?:=|:|\bis\b)\s*[\"']?)([^\s\"',;]{{4,}})"), r"\1[REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"(?<=/home/)[^/\s]+|(?<=/Users/)[^/\s]+|(?<=C:\\Users\\)[^\\\s]+"), "~user"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
)
_GENERIC_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED]"),
    (re.compile(r"\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@"), r"\1[REDACTED]@"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"), "[REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bglpat-[A-Za-z0-9_-]{16,}\b"), "[REDACTED]"),
    (re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b|\bnpm_[A-Za-z0-9]{20,}\b|\bAIza[A-Za-z0-9_-]{25,}\b|\bpypi-[A-Za-z0-9_-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}"), r"\1[REDACTED]"),
    (re.compile(rf"(?i)(\b[A-Za-z0-9_]*{_SENSITIVE_KEYS}[A-Za-z0-9_]*[\"']?\s*(?:=|:|\bis\b)\s*[\"']?)([^\s\"',;]{{4,}})"), r"\1[REDACTED]"),
)
_HEX_UUID_RE = re.compile(r"^(?:[0-9a-fA-F]{7,64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
_CANDIDATE_TOKEN_RE = re.compile(r"[A-Za-z0-9+_=-]{20,}")


@dataclass(frozen=True)
class Finding:
    """Normalized scanner or secret finding with masked snippet."""
    rule_id: str
    path: str
    line: int
    snippet: str
    tier: str = "gate"
    fingerprint: str = ""
    severity: str = "error"
    message: str = ""
    rule = property(lambda self: self.rule_id)
    fp = property(lambda self: self.fingerprint)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule": self.rule_id,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "tier": self.tier,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "message": self.message,
        }


def mask_secret(secret: str) -> str:
    if len(secret) <= 6:
        return f"{secret[:2]}..." if len(secret) > 2 else "***"
    return f"{secret[:4]}...{secret[-2:]}"


def sarif_fingerprint(rule_id: str, rel_path: str, line_text: str) -> str:
    normalized = " ".join(line_text.split())
    return hashlib.sha256(f"{rule_id}|{rel_path}|{normalized}".encode("utf-8")).hexdigest()[:16]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_shannon_entropy = shannon_entropy


def _is_high_entropy_secret(tok: str, threshold: float = 3.8) -> bool:
    if "REDACTED" in tok or _HEX_UUID_RE.match(tok) or not any(c.isdigit() for c in tok):
        return False
    classes = int(any(c.islower() for c in tok)) + int(any(c.isupper() for c in tok)) + 1
    if classes < 2:
        return False
    return shannon_entropy(tok) >= threshold


def redact_command_secrets(cmd: str) -> str:
    """Mask known secret patterns in command strings before logging."""
    for pattern, replacement in SECRET_REPLACEMENTS:
        cmd = pattern.sub(replacement, cmd)
    return cmd


redact_hook_text = redact_command_secrets


def redact_payload(payload: Any) -> Any:
    """Recursively redact known secret patterns in a hook payload structure."""
    if isinstance(payload, str):
        return redact_command_secrets(payload)
    if isinstance(payload, Mapping):
        return {k: redact_payload(v) for k, v in payload.items()}
    if isinstance(payload, tuple):
        return tuple(redact_payload(v) for v in payload)
    if isinstance(payload, list):
        return [redact_payload(v) for v in payload]
    return payload


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace known secret tokens and high-entropy mixed-class tokens with [REDACTED]."""
    if not isinstance(text, str) or not text:
        return "", 0
    out = text
    total = 0
    for pat, repl in _GENERIC_SECRET_PATTERNS:
        out, n = pat.subn(repl, out)
        total += n

    def _replace_candidate(match: re.Match[str]) -> str:
        nonlocal total
        tok = match.group(0)
        if _is_high_entropy_secret(tok, threshold=4.0):
            total += 1
            return "[REDACTED]"
        return tok

    out = _CANDIDATE_TOKEN_RE.sub(_replace_candidate, out)
    return out, total


def redact_insight_text(text: str, max_len: int = MAX_EXCERPT_CHARS) -> str:
    """Scrub secrets, PII, paths, IPs, and high-entropy tokens from insight text."""
    if not isinstance(text, str) or not text:
        return ""
    out = text
    for pat, repl in _REDACT_PATTERNS:
        out = pat.sub(repl, out)
    out = _CANDIDATE_TOKEN_RE.sub(
        lambda m: "[REDACTED_HIENT]" if _is_high_entropy_secret(m.group(0)) else m.group(0),
        out,
    )
    out = " ".join(out.split())
    if max_len > 0 and len(out) > max_len:
        sliced = out[:max_len]
        last_open = sliced.rfind("[REDACTED")
        if last_open != -1 and "]" not in sliced[last_open:]:
            out = sliced[:last_open].rstrip()
        else:
            out = sliced
    return out


def _is_benign_token(val: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(val) or _UUID_RE.match(val) or _HEX_RE.match(val))


def scan_secrets_text(text: str, path: str = "<memory>", *, include_advisory: bool = False) -> list[Finding]:
    """Scan text for Tier A (blocking) and optionally Tier B/C (advisory) secrets."""
    findings: list[Finding] = []
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        if len(raw_line) > MAX_LINE_LENGTH:
            continue
        cleaned = _DATA_URL_OR_SRI_RE.sub('""', raw_line)
        line_secrets: list[str] = []
        matched: list[tuple[str, str, str]] = []
        for rule_id, rx in TIER_A_PATTERNS.items():
            for m in rx.finditer(cleaned):
                full = m.group(0)
                if rule_id == "url-basic-auth":
                    user, pwd = m.group(1), m.group(2)
                    if _PLACEHOLDER_RE.search(user) or _PLACEHOLDER_RE.search(pwd) or "$" in user or "$" in pwd:
                        continue
                    line_secrets.extend([full, pwd])
                elif rule_id != "private-key-pem" and _is_benign_token(full):
                    continue
                else:
                    line_secrets.append(full)
                matched.append((rule_id, "gate", full))
        if include_advisory and not _HASH_FIELD_RE.search(cleaned):
            for m in _TIER_B_RE.finditer(cleaned):
                key_name, val = m.group(1), m.group(3)
                if not _HASH_FIELD_RE.search(key_name) and not _is_benign_token(val) and not any(val in s or s in val for s in line_secrets):
                    line_secrets.append(val)
                    matched.append(("generic-secret-assign", "advisory", val))
            for m in _TIER_C_RE.finditer(cleaned):
                val = m.group(2)
                if not _is_benign_token(val) and not any(val in s or s in val for s in line_secrets) and shannon_entropy(val) >= 4.5:
                    line_secrets.append(val)
                    matched.append(("high-entropy-token", "advisory", val))
        if not matched:
            continue
        masked_line = raw_line.strip()
        for sec in sorted(set(line_secrets), key=len, reverse=True):
            masked_line = masked_line.replace(sec, mask_secret(sec))
        for rule_id, tier, sec in matched:
            masked_tok = mask_secret(sec)
            snippet = masked_line if masked_tok in masked_line else masked_tok
            findings.append(Finding(
                rule_id,
                path,
                lineno,
                snippet,
                tier,
                sarif_fingerprint(rule_id, path, snippet),
                "error" if tier == "gate" else "warning",
                f"Detected {rule_id} ({tier})",
            ))
    return findings


def contains_secret_tier_a(text: str) -> bool:
    return bool(scan_secrets_text(text, include_advisory=False))


def scan_secrets_file(file_path: Path | str, *, repo_root: Path | str | None = None, include_advisory: bool = False) -> list[Finding]:
    p = Path(file_path)
    if not p.is_file() or p.is_symlink():
        return []
    try:
        raw = p.read_bytes()
    except OSError:
        return []
    if b"\0" in raw[:4096]:
        return []
    rel = p.as_posix()
    if repo_root is not None:
        try:
            rel = p.resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except ValueError:
            rel = p.as_posix()
    return scan_secrets_text(raw.decode("utf-8", "replace"), path=rel, include_advisory=include_advisory)


def scan_secrets_workspace(workspace_root: Path | str, *, files: Sequence[str] | None = None, include_advisory: bool = False) -> list[Finding]:
    root = Path(workspace_root).resolve()
    rel_files = list(files) if files is not None else (gitsafe.list_files(root) or [])
    if not rel_files and files is None:
        rel_files = [
            p.relative_to(root).as_posix() for p in sorted(root.rglob("*"))
            if p.is_file() and not any(part.startswith(".") or part == "__pycache__" for part in p.relative_to(root).parts)
        ]
    return [f for rel in rel_files for f in scan_secrets_file(root / rel, repo_root=root, include_advisory=include_advisory)]


def _count_repo_suppressions(workspace_root: Path | str | None, diff_text: str | None = None) -> int:
    count = len(_SUPPRESSION_RE.findall(diff_text)) if diff_text else 0
    if workspace_root is None:
        return count
    root = Path(workspace_root).resolve()
    ignore_file = root / ".gitleaksignore"
    if ignore_file.is_file():
        try:
            lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
            count += sum(1 for ln in lines if ln.strip() and not ln.lstrip().startswith("#"))
        except OSError:
            pass
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(k.startswith(".") or k in ("__pycache__", "node_modules") for k in p.relative_to(root).parts):
            continue
        try:
            data = p.read_bytes()
            if b"\0" not in data[:4096]:
                count += len(_SUPPRESSION_RE.findall(data.decode("utf-8", "replace")))
        except OSError:
            continue
    return count


def ingest_sarif(
    sarif_data: str | bytes | Mapping[str, Any] | Path,
    *,
    workspace_root: Path | str | None = None,
    base_sarif: str | bytes | Mapping[str, Any] | Path | None = None,
    base_fingerprints: Iterable[str] | None = None,
    diff_text: str | None = None,
) -> dict[str, Any]:
    """Ingest SARIF 2.1.0, compute fingerprints, subtract base findings, and count suppressions."""
    def _load(src: Any) -> Mapping[str, Any]:
        if isinstance(src, Mapping):
            return src
        if isinstance(src, Path):
            return json.loads(src.read_text(encoding="utf-8"))
        if isinstance(src, bytes):
            return json.loads(src.decode("utf-8", "replace"))
        s = str(src).strip()
        if not s.startswith("{") and Path(s).is_file():
            return json.loads(Path(s).read_text(encoding="utf-8"))
        return json.loads(s)

    doc = _load(sarif_data)
    base_fps: set[str] = set(base_fingerprints or ())
    if base_sarif is not None:
        base_fps.update(f.fingerprint for f in ingest_sarif(base_sarif, workspace_root=workspace_root)["findings"])
    root_path = Path(workspace_root).resolve() if workspace_root else None
    all_findings: list[Finding] = []
    sarif_supps = 0
    for run in doc.get("runs") or []:
        for res in run.get("results") or []:
            sarif_supps += len(res.get("suppressions") or ())
            rule_id = str(res.get("ruleId") or "unknown")
            level = str(res.get("level") or "warning").lower()
            msg = str((res.get("message") or {}).get("text") or "")
            phys = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = str((phys.get("artifactLocation") or {}).get("uri") or "")
            uri = uri[7:] if uri.startswith("file://") else uri
            rel_path = uri.lstrip("./")
            if root_path and uri:
                try:
                    rel_path = Path(uri).resolve().relative_to(root_path).as_posix()
                except ValueError:
                    rel_path = Path(uri).as_posix().lstrip("./")
            region = phys.get("region") or {}
            line_no = int(region.get("startLine") or 0)
            snippet_raw = (region.get("snippet") or {}).get("text")
            if snippet_raw is None and root_path and rel_path and line_no > 0 and (root_path / rel_path).is_file():
                lines = (root_path / rel_path).read_text(encoding="utf-8", errors="replace").splitlines()
                snippet_raw = lines[line_no - 1] if 1 <= line_no <= len(lines) else None
            norm_line = " ".join(str(snippet_raw if snippet_raw is not None else msg).split())
            fp = sarif_fingerprint(rule_id, rel_path, norm_line)
            all_findings.append(
                Finding(
                    rule_id,
                    rel_path,
                    line_no,
                    norm_line,
                    "gate",
                    fp,
                    "error" if level == "error" else "warning",
                    msg,
                )
            )
    delta = [f for f in all_findings if f.fingerprint not in base_fps]
    return {
        "status": "fail" if delta else "pass",
        "findings": delta,
        "total_raw": len(all_findings),
        "delta_count": len(delta),
        "base_subtracted": len(all_findings) - len(delta),
        "suppression_count": sarif_supps + _count_repo_suppressions(workspace_root, diff_text),
    }


def _is_within_dir(path: Path, directory: Path) -> bool:
    real_p, real_d = os.path.realpath(path), os.path.realpath(directory)
    return real_p == real_d or real_p.startswith(real_d.rstrip(os.sep) + os.sep)


def build_preset_argv(
    preset: str,
    target_path: Path | str = ".",
    *,
    user_config_dir: Path | str | None = None,
    config_path: Path | str | None = None,
) -> list[str]:
    target = Path(target_path).resolve()
    if preset == "ruff":
        return ["ruff", "check", "--isolated", "--select", "S", "--ignore", "S603,S607", "--output-format", "sarif", str(target)]
    if preset == "gitleaks":
        from aegis_core.workspace.layout import UserLayout
        argv = ["gitleaks", "detect", "--no-git", "--redact", "--report-format", "sarif", "--report-path", "-", "--source", str(target)]
        ul = UserLayout.current()
        user_dir = Path(user_config_dir).resolve() if user_config_dir else (ul.aegis_dir.resolve() if ul else None)
        if user_dir is not None and not _is_within_dir(user_dir, target):
            cand = Path(config_path).resolve() if config_path else (user_dir / "gitleaks.toml").resolve()
            if _is_within_dir(cand, user_dir) and not _is_within_dir(cand, target) and cand.is_file():
                argv.extend(["--config", str(cand)])
        return argv
    raise ValueError(f"Unsupported scanner preset: {preset!r}")


def run_preset_scanner(
    preset: str,
    workspace_root: Path | str,
    *,
    user_config_dir: Path | str | None = None,
    config_path: Path | str | None = None,
    base_fingerprints: Iterable[str] | None = None,
    timeout: int = 60,
    runner: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    argv = build_preset_argv(preset, workspace_root, user_config_dir=user_config_dir, config_path=config_path)
    cmd_runner = runner or test_runner.run_external_cmd
    try:
        res = cmd_runner(argv, cwd=Path(workspace_root), timeout=timeout)
    except FileNotFoundError as exc:
        return {"status": "unverified", "reason": str(exc), "findings": [], "argv": argv}
    if res.get("missing_binary") or res.get("timed_out"):
        reason = res.get("stderr") or (f"{argv[0]} timed out" if res.get("timed_out") else f"{argv[0]} not found")
        return {"status": "unverified", "reason": reason, "findings": [], "argv": argv}
    stdout = (res.get("stdout") or "").strip()
    if stdout.startswith("{"):
        return {**ingest_sarif(stdout, workspace_root=workspace_root, base_fingerprints=base_fingerprints), "argv": argv}
    if res.get("returncode", 0) == 0:
        return {"status": "pass", "findings": [], "suppression_count": _count_repo_suppressions(workspace_root), "argv": argv}
    return {"status": "unverified", "reason": res.get("stderr") or f"{argv[0]} failed", "findings": [], "argv": argv}

