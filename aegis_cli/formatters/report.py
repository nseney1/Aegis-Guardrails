"""Text, JSON, GitHub, and SARIF 2.1.0 report formatters for `aegis check`."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional

from aegis_cli import sanitize_display

__all__ = [
    "ci_findings",
    "format_github_step_summary",
    "format_layer1_json_payload",
    "format_layer2_json",
    "format_layer2_summary",
    "format_sarif_report",
    "github_annotation_lines",
    "governance_note",
    "layer1_findings",
    "perf_line",
]

_MODEL_TEXT_MAX = 300


def _model_text(value: Any) -> str:
    """Model text as one printable line: the model's reply is any JSON value, and the
    slice comes first because sanitize_display is quadratic on unterminated OSC/DCS introducers."""
    return sanitize_display(str(value)[:_MODEL_TEXT_MAX * 4], max_len=_MODEL_TEXT_MAX)


def format_layer2_summary(result: Any, vendor_warning: str = "") -> str:
    """Format Layer 2 arbitration results for CLI output."""
    from aegis_core.verification import Verdict

    lines = []
    l1_v = getattr(result, "layer1_verdict", "")
    infra = getattr(result, "infra_status", "")
    if infra and infra != "ok":
        lines.append("Layer 2: ⚠️ UNVERIFIED (advisory: the review did not complete; the exit status is Layer 1's)")
    else:
        verdict_str = result.verdict.name if hasattr(result.verdict, "name") else str(result.verdict)
        icon = "✅" if result.verdict == Verdict.SHIP else "🔴"
        lines.append(f"Layer 2: {icon} {verdict_str} (advisory: the exit status is Layer 1's)")
    preds = getattr(result, "llm_predictions", ())
    if l1_v or infra:
        reasons = ", ".join(str(r) for r in (getattr(result, "unverified_reasons", ()) or ()))
        lines.append(
            f"  layer1_verdict: {l1_v or 'PASS'} | infra_status: {infra or 'ok'}"
            f"{f' ({reasons})' if reasons else ''} | llm_predictions: {len(preds)}"
        )
    if vendor_warning:
        lines.append(f"  Vendor: {vendor_warning} (the host label is attribution, not authentication)")

    if result.divergences:
        lines.append(f"  Divergences ({len(result.divergences)}):")
        for d in result.divergences:
            pred_desc = f" [{d.prediction.severity.value}] {_model_text(d.prediction.risk)}" if d.prediction else ""
            lines.append(f"    - {d.category.value} ({d.divergence_type}):{pred_desc}")
            if d.resolution:
                lines.append(f"      Resolution: {d.resolution}")

    if result.convergences:
        lines.append(
            f"  Convergences ({len(result.convergences)}): "
            f"{', '.join(c.value for c in result.convergences)}"
        )

    return "\n".join(lines)


def format_layer2_json(result: Any, verdict: Any, vendor_warning: str = "") -> dict[str, Any]:
    """JSON summary of a Layer 2 arbitration for `aegis check --format json`; advisory, never the exit status."""
    preds = getattr(result, "llm_predictions", ()) if result else ()
    infra = getattr(result, "infra_status", "ok") if result else "ok"
    return {
        "verdict": None if infra != "ok" else (verdict.value if hasattr(verdict, "value") else str(verdict)),
        "advisory": True,
        "layer1_verdict": getattr(result, "layer1_verdict", "PASS") if result else "PASS",
        "infra_status": infra,
        "unverified_reasons": list(getattr(result, "unverified_reasons", ()) or ()) if result else [],
        "llm_predictions": [
            p.to_dict() if hasattr(p, "to_dict") else str(p)
            for p in preds
        ],
        "divergences": [
            {"type": d.divergence_type, "category": d.category.value, "resolution": d.resolution}
            for d in (result.divergences if result else [])
        ],
        "convergences": [c.value for c in (result.convergences if result else [])],
        "vendor_warning": vendor_warning,
    }


def format_layer1_json_payload(
    layer1_pass: bool,
    target_files: list[str],
    results: list[Any],
    summary: str,
) -> dict[str, Any]:
    """Construct JSON output dictionary for Layer 1 verification results."""
    return {
        "passed": layer1_pass,
        "files": target_files,
        "layer1": [
            {
                "tool": r.tool,
                "target": r.target,
                "verdict": bool(r.verdict),
                "detail": r.detail,
            }
            for r in results
        ],
        "summary": summary,
    }


def _rel_uri(raw_path: Any, workspace_root: Optional[str | Path] = None) -> str:
    path = str(raw_path or "")
    if path and workspace_root is not None and os.path.isabs(path):
        try:
            path = os.path.relpath(path, workspace_root)
        except ValueError:  # another drive on Windows
            pass
    return path.replace("\\", "/")


def _finding(rule_id: str, path: Any, line: int, message: str, level: str, root: Any) -> dict[str, Any]:
    return {"rule_id": rule_id, "uri": _rel_uri(path, root), "line": line, "col": 1, "message": message, "level": level}


def ci_findings(document: dict[str, Any], workspace_root: Optional[str | Path] = None) -> list[dict[str, Any]]:
    """The findings of a ``check --ci`` document, from the fixed keys its producers write. Weakening,
    governance, regression, trailer and perf findings name no line; scanner findings are anchored."""
    from aegis_core import regression

    found = []
    approved = bool((document.get("approval") or {}).get("valid"))
    for w in document.get("weakenings", ()):
        found.append(_finding(w["rule"], w["path"], 0, f"{w['code']}: {w['message']}",
                              "note" if approved else "error", workspace_root))
    gov = document.get("governance") or {}
    for entry in gov.get("paths", ()) if gov.get("enforced") and not gov.get("approved") else ():
        found.append(_finding(f"governance:{entry['category']}", entry["path"], 0,
                              f"governance change without approval: {entry['path']}", "error", workspace_root))
    reg = document.get("regression") or {}
    for rf in reg.get("findings", ()):
        level = "error" if reg.get("tier") == "gate" and rf["code"] not in regression.UNVERIFIED_CODES else "warning"
        found.append(_finding(rf["code"], rf["path"], 0, rf["message"], level, workspace_root))
    for t_chk in document.get("trailer_checks", ()):
        if t_chk.get("failed"):
            found.append(_finding("trailer-divergence", "", 0, f"{t_chk['commit'][:10]}: {t_chk.get('reason', '')}",
                                  "error", workspace_root))
    perf = document.get("perf") or {}
    if perf.get("status") == "fail":
        found.append(_finding("performance-regression", "", 0, perf_line(perf).strip(), "error", workspace_root))
    for scan in document.get("scanners", ()):
        for sf in scan["findings"]:
            found.append(_finding(f"scanner/{scan['name']}:{sf['rule_id']}", sf["path"], sf["line"], sf["message"],
                                  "error", workspace_root))
        if scan["status"] == "unverified":
            found.append(_finding(f"scanner/{scan['name']}", "", 0, f"UNVERIFIED: {scan.get('reason', '')}",
                                  "warning", workspace_root))
    return found


def layer1_findings(document: dict[str, Any], workspace_root: Optional[str | Path] = None) -> list[dict[str, Any]]:
    """The findings of a Layer 1 report: each failed check, anchored at its first line when it names
    lines, and each checkpoint issue (``findings`` rows), which names none."""
    found = []
    for row in document.get("layer1", ()):
        if not row["verdict"]:
            lines = row.get("lines") or ()
            found.append(_finding(row["tool"], row["target"], lines[0] if lines else 0, row["detail"], "error", workspace_root))
    for issue in document.get("findings", ()):
        found.append(_finding(issue["rule"], "", 0, issue["message"], issue.get("level", "error"), workspace_root))
    return found


def _split(document: dict[str, Any], workspace_root: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(anchored, line-less) findings of either document kind."""
    found = ci_findings(document, workspace_root) + layer1_findings(document, workspace_root)
    return ([f for f in found if f["uri"] and f["line"] >= 1], [f for f in found if not (f["uri"] and f["line"] >= 1)])


def perf_line(perf: dict[str, Any]) -> str:
    """The text line of a ``--perf`` result: ``[PASS|FAIL|UNVERIFIED:perf] ...``."""
    tag = {"pass": "PASS", "fail": "FAIL"}.get(perf.get("status"), "UNVERIFIED")
    if tag == "UNVERIFIED":
        return f"  [UNVERIFIED:perf] {perf.get('reason', '')}"
    return (f"  [{tag}:perf] head {perf['head_min']:.4f}s / {perf['head_median']:.4f}s (min / median) against the merge "
            f"base's {perf['base_min']:.4f}s / {perf['base_median']:.4f}s over {perf['rounds']} paired rounds, threshold "
            f"{perf['threshold'] * 100:g} percent")


def governance_note(document: dict[str, Any]) -> str:
    """Why a changed governance set is not enforced (no signing key at the base), or ""."""
    gov = document.get("governance") or {}
    cats = ", ".join(gov.get("categories") or ())
    return (f"governance files changed ({cats}) but the base lists no key in allowed_signers, "
            "so no approval can be required (tier C: detection only)") if cats and not gov.get("enforced") else ""


def _escape_annotation(text: str, prop: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def github_annotation_lines(document: dict[str, Any]) -> list[str]:
    """GitHub workflow commands for a ``check --ci`` document, one line each with every value escaped;
    titles are constants. An approved weakening or governance change is a ``::notice``, never an error."""
    from aegis_core import regression

    esc = _escape_annotation

    def line(level: str, title: str, message: str, path: str = "", number: int = 0) -> str:
        where = (f"file={esc(path, True)}," if path else "") + (f"line={number}," if number else "")
        return f"::{level} {where}title={esc(title, True)}::{esc(message)}"

    out = []
    approved = bool((document.get("approval") or {}).get("valid"))
    level, title = ("notice", "weakening approved") if approved else ("error", "weakening without approval")
    for w in document.get("weakenings", ()):
        out.append(line(level, title, f"{w['code']}: {w['rule']}: {w['message']}", w["path"]))
    gov = document.get("governance") or {}
    level, title = ("notice", "governance change approved") if gov.get("approved") else ("error", "governance change without approval")
    for entry in gov.get("paths", ()) if gov.get("enforced") else ():
        message = f"governance:{entry['category']}: {entry['path']} changed; it passes only with a signed approval (aegis approve)"
        out.append(line(level, title, message, entry["path"]))
    note = governance_note(document)
    if note:
        out.append(line("warning", "governance change not enforced", note))
    reg = document.get("regression") or {}
    gate = reg.get("tier") == "gate"
    for rf in reg.get("findings", ()):
        if rf["code"] in regression.UNVERIFIED_CODES:
            level, title = "warning", "regression check unverified"
        else:
            level, title = ("error", "regression check failed") if gate else ("warning", "regression check warning")
        out.append(line(level, title, f"{rf['code']}: {rf['message']}", rf["path"]))
    for scan in document.get("scanners", ()):
        for sf in scan["findings"]:
            out.append(line("error", f"scanner/{scan['name']}", f"{sf['rule_id']}: {sf['message']}", sf["path"], sf["line"]))
        if scan["status"] == "unverified":
            out.append(line("warning", "scanner unverified", f"{scan['name']}: {scan.get('reason', '')}"))
    for t_chk in document.get("trailer_checks", ()):
        if t_chk.get("failed"):
            out.append(line("error", "Aegis-Check trailer divergence", f"{t_chk['commit'][:10]}: {t_chk.get('reason', '')}"))
    perf = document.get("perf")
    if isinstance(perf, dict) and perf.get("status") == "fail":
        out.append(line("error", "performance regression", perf_line(perf).strip()))
    elif isinstance(perf, dict) and perf.get("status") != "pass":
        out.append(line("warning", "performance unverified", perf.get("reason", "")))
    cov = document.get("coverage")
    if isinstance(cov, dict) and cov.get("status") == "reported":
        ratio = cov.get("ratio")
        figure = "n/a" if ratio is None else f"{ratio * 100:.1f} percent"
        out.append(line("notice", "diff coverage",
                        f"{figure} of {cov.get('executable_lines', 0)} changed executable lines (report only)"))
    elif isinstance(cov, dict):
        out.append(line("warning", "coverage unverified", cov.get("reason", "")))
    return out


def format_github_step_summary(report_dict: dict[str, Any], workspace_root: Optional[str | Path] = None) -> str:
    """Render a Markdown job summary for $GITHUB_STEP_SUMMARY."""
    anchored, lineless = _split(report_dict, workspace_root)
    status = report_dict.get("status")
    passed = report_dict.get("passed", status == "pass" if status is not None else not (anchored or lineless))
    lines = [f"## Aegis Check Summary: {'PASSED' if passed else 'FAILED'}", ""]
    if anchored:
        lines.extend(["### Line-Anchored Findings", "| Rule | Location | Level | Message |", "| :--- | :--- | :--- | :--- |"])
        lines.extend(f"| `{f['rule_id']}` | `{f['uri']}:{f['line']}:{f['col']}` | {f['level']} | {f['message']} |" for f in anchored)
        lines.append("")
    if lineless:
        lines.append("### Repository / Unanchored Findings")
        for f in lineless:
            loc = f" (`{f['uri']}`)" if f["uri"] else ""
            lines.append(f"- **[{f['rule_id']}]**{loc}: {f['message']}")
        lines.append("")
    cov = report_dict.get("coverage")
    if isinstance(cov, dict):
        ratio, measured = cov.get("ratio"), cov.get("status") == "reported"
        figure = "n/a" if ratio is None else f"{float(ratio) * 100.0:.1f}%"
        lines.append(f"### Diff Coverage (report only): {figure} of {cov.get('executable_lines', 0)} changed executable lines"
                     if measured else f"### Diff Coverage: UNVERIFIED ({cov.get('reason', '')})")
        for path, ranges in sorted((cov.get("uncovered_ranges") or {}).items()):
            lines.append(f"- `{path}`: uncovered lines {', '.join(f'{s}-{e}' if s != e else str(s) for s, e in ranges)}")
        lines.append("")
    perf = report_dict.get("perf")
    if isinstance(perf, dict):  # no reason text: it can quote the benchmark's stderr
        lines.extend([f"### Performance: {({'pass': 'PASS', 'fail': 'FAIL'}).get(perf.get('status'), 'UNVERIFIED')}", ""])
    if not anchored and not lineless and not isinstance(cov, dict) and not isinstance(perf, dict):
        lines.append("No findings reported.")
    return "\n".join(lines).strip() + "\n"


class SarifReport(str):
    _data: dict[str, Any]

    def __new__(cls, text: str, data: dict[str, Any]) -> "SarifReport":
        obj = super().__new__(cls, text)
        obj._data = data
        return obj

    def __getitem__(self, key: Any) -> Any:
        return self._data[key] if isinstance(key, str) else super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


def format_sarif_report(report_dict: dict[str, Any], workspace_root: Optional[str | Path] = None) -> SarifReport:
    """Format verification results as valid SARIF 2.1.0, routing line-less findings to step_summary."""
    anchored, _ = _split(report_dict, workspace_root)
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in anchored:
        rid = f["rule_id"]
        rules_seen.setdefault(rid, {"id": rid, "shortDescription": {"text": rid}})
        line_hash = hashlib.sha256(f"{f['uri']}:{f['line']}:{rid}:{f['message']}".encode("utf-8")).hexdigest()[:16]
        results.append({
            "ruleId": rid, "level": f["level"], "message": {"text": f["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["uri"], "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": f["line"], "startColumn": f["col"]}}}],
            "partialFingerprints": {"primaryLocationLineHash": line_hash},
        })
    from aegis_core._version import __version__

    payload: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Aegis Guardrails", "version": __version__, "rules": list(rules_seen.values())}},
                  "results": results}],
        "step_summary": format_github_step_summary(report_dict, workspace_root=workspace_root),
    }
    return SarifReport(json.dumps(payload, indent=2), payload)
