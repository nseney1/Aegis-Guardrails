"""Text, JSON, GitHub, and SARIF 2.1.0 report formatters for `aegis check`."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from aegis_cli import sanitize_display

__all__ = [
    "format_github_annotations",
    "format_github_step_summary",
    "format_layer1_json_payload",
    "format_layer2_json",
    "format_layer2_summary",
    "format_sarif_report",
]

_MODEL_TEXT_MAX = 300


def _model_text(value: Any) -> str:
    """Model text as one printable line: the model's reply is any JSON value, and the
    slice comes first because sanitize_display is quadratic on unterminated OSC/DCS introducers."""
    return sanitize_display(str(value)[:_MODEL_TEXT_MAX * 4], max_len=_MODEL_TEXT_MAX)


def format_layer2_summary(result: Any) -> str:
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


def format_layer2_json(result: Any, verdict: Any) -> dict[str, Any]:
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


def _rel_uri(raw_path: str, workspace_root: Optional[str | Path] = None) -> str:
    if not raw_path:
        return ""
    norm = str(raw_path).replace("\\", "/")
    if workspace_root is not None:
        for r in (str(Path(workspace_root).resolve()), str(workspace_root)):
            prefix = r.replace("\\", "/").rstrip("/") + "/"
            if prefix != "/" and norm.startswith(prefix):
                norm = norm[len(prefix):]
                break
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.lstrip("/")


def _normalize_findings(
    report_dict: dict[str, Any],
    workspace_root: Optional[str | Path] = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split report_dict entries into (anchored_findings, lineless_findings)."""
    raw_items: list[dict[str, Any]] = [i for i in report_dict.get("findings", []) if isinstance(i, dict)]
    for w in report_dict.get("weakenings", []):
        if isinstance(w, dict):
            raw_items.append({"rule": w.get("rule") or w.get("code") or "rule-weakening", "path": w.get("path", ""),
                              "line": w.get("line", 1 if w.get("path") else 0), "col": w.get("col", 1),
                              "message": f"{w.get('code', '')}: {w.get('message', '')}".strip(": "), "level": "error"})
    gov = report_dict.get("governance")
    if isinstance(gov, dict) and gov.get("enforced") and not gov.get("approved"):
        for entry in gov.get("paths", []):
            if isinstance(entry, dict):
                path = str(entry.get("path") or "")
                raw_items.append({"rule": f"governance:{entry.get('category', '')}", "path": path,
                                  "line": 1 if path else 0, "col": 1, "level": "error",
                                  "message": f"governance change without approval: {path}"})
    reg = report_dict.get("regression")
    if isinstance(reg, dict):
        reg_level = "error" if reg.get("tier") == "gate" else "warning"
        for rf in reg.get("findings", []):
            if isinstance(rf, dict):
                raw_items.append({"rule": rf.get("code", "regression"), "path": rf.get("path", ""),
                                  "line": rf.get("line", 1 if rf.get("path") else 0), "col": rf.get("col", 1),
                                  "message": rf.get("message", ""), "level": reg_level})
    for l1 in report_dict.get("layer1", []):
        if isinstance(l1, dict) and not l1.get("verdict", True):
            lines = l1.get("lines") or []
            raw_items.append({"rule": l1.get("tool", "layer1"), "path": l1.get("target", ""),
                              "line": l1.get("line", lines[0] if lines else 0), "col": 1,
                              "message": l1.get("detail", "Layer 1 failure"), "level": "error"})
    for gate in report_dict.get("gates", []):
        if isinstance(gate, dict) and gate.get("status") == "FAIL":
            raw_items.append({"rule": str(gate.get("gate", "gate")), "path": str(gate.get("path", "")),
                              "line": int(gate.get("line", 0) or 0), "col": int(gate.get("col", 1) or 1),
                              "message": str(gate.get("detail", "Gate failure")), "level": "error"})

    anchored, lineless = [], []
    for item in raw_items:
        uri = _rel_uri(str(item.get("path") or item.get("file") or ""), workspace_root)
        try:
            line_no = int(item.get("line", item.get("startLine", 0)) or 0)
        except (TypeError, ValueError):
            line_no = 0
        try:
            col_no = max(1, int(item.get("col", item.get("column", item.get("startColumn", 1))) or 1))
        except (TypeError, ValueError):
            col_no = 1
        rule_id = str(item.get("rule") or item.get("rule_id") or item.get("code") or item.get("id") or "aegis-rule")
        lvl_raw = str(item.get("level") or item.get("severity") or "error").lower()
        entry = {"rule_id": rule_id, "uri": uri, "line": line_no, "col": col_no,
                 "message": str(item.get("message") or item.get("detail") or ""),
                 "level": "warning" if lvl_raw in ("warn", "warning", "medium", "low") else "error"}
        (anchored if (uri and line_no >= 1) else lineless).append(entry)
    return anchored, lineless


def _esc_prop(val: str) -> str:
    return val.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _esc_msg(val: str) -> str:
    return val.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def format_github_step_summary(report_dict: dict[str, Any], workspace_root: Optional[str | Path] = None) -> str:
    """Render a Markdown job summary for $GITHUB_STEP_SUMMARY."""
    anchored, lineless = _normalize_findings(report_dict, workspace_root=workspace_root)
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
        lines.append(f"### Diff Coverage: {'PASS' if cov.get('passed', True) else 'FAIL'} ({float(cov.get('coverage', 1.0)) * 100.0:.1f}%)")
        for path, ranges in sorted((cov.get("uncovered_ranges") or {}).items()):
            lines.append(f"- `{path}`: uncovered lines {', '.join(f'{s}-{e}' if s != e else str(s) for s, e in ranges)}")
        lines.append("")
    if not anchored and not lineless and not isinstance(cov, dict):
        lines.append("No findings reported.")
    return "\n".join(lines).strip() + "\n"


def format_github_annotations(report_dict: dict[str, Any], workspace_root: Optional[str | Path] = None) -> list[str]:
    """Emit GitHub Actions ::error / ::warning workflow commands."""
    anchored, lineless = _normalize_findings(report_dict, workspace_root=workspace_root)
    out = [f"::{f['level']} file={_esc_prop(f['uri'])},line={f['line']},col={f['col']},title={_esc_prop(f['rule_id'])}::{_esc_msg(f['message'])}" for f in anchored]
    for f in lineless:
        file_part = f"file={_esc_prop(f['uri'])}," if f["uri"] else ""
        out.append(f"::{f['level']} {file_part}title={_esc_prop(f['rule_id'])}::{_esc_msg(f['message'])}")
    return out


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
    anchored, _ = _normalize_findings(report_dict, workspace_root=workspace_root)
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
