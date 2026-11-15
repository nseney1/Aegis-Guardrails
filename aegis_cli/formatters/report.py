"""Text, JSON, GitHub, and SARIF 2.1.0 report formatters for `aegis check`."""
from __future__ import annotations

import builtins
import hashlib
from itertools import islice
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from aegis_cli import sanitize_display
from aegis_core.approval_policy import GuidanceMessage, MESSAGE_TEMPLATES, MessageRow, PERMITTED_MODES, finding_message, guidance_value, receipt_value

__all__ = [
    "coverage_explanation",
    "coverage_omitted_count",
    "coverage_reason",
    "format_github_step_summary",
    "format_layer1_json_payload",
    "format_layer2_json",
    "format_layer2_summary",
    "format_sarif_report",
    "github_annotation_lines",
    "governance_note",
    "layer1_report_document",
    "perf_line",
    "regression_findings",
    "render_ci_json",
]

_MODEL_TEXT_MAX = 300


def _model_text(value: Any) -> str:
    """Render one bounded model value, then clip without tearing its escapes."""
    from aegis_core.approval_policy import clip_rendered_text

    return clip_rendered_text(guidance_value(str(value), _MODEL_TEXT_MAX * 4, prose=True), _MODEL_TEXT_MAX)


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
                "lines": list(r.lines),
                **({"language": r.language} if getattr(r, "language", None) else {}),
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
    if isinstance(message, GuidanceMessage):
        message = message.render()
    return {"rule_id": rule_id, "uri": _rel_uri(path, root), "line": line, "col": 1, "message": message, "level": level}


def _owner_rows(document):
    """Retain identities and the marker for messages already rendered by core."""
    rows = document.get("owner_review_findings")
    if not isinstance(rows, list):
        return []
    cleaned = []
    for row in rows:
        item = {key: receipt_value(value, 400, identifier=True) if key in ("code", "rule", "path") else value
                for key, value in row.items()}
        cleaned.append(MessageRow(item) if isinstance(row, MessageRow) else item)
    return cleaned


def _owner_path(value):
    """A receipt identity: redact tokens without prose-escaping its path syntax."""
    if len(value) > 4096:
        return "[diagnostic omitted: too_large]"
    return receipt_value(value, 400, identifier=True, canonicalize=sanitize_display)


def _optional_fragment(fragment):
    """Decide optional wording on the same values that enter the template."""
    shown = {key: guidance_value(str(value or ""), prose=True) for key, value in fragment.values.items()}
    return fragment.template.format_map(shown) if any(shown.values()) else ""


def regression_findings(report):
    """Build native findings from structured data; legacy text stays a value."""
    from aegis_core import regression

    commits = {row["commit"]: row for row in report.get("commits", ())}
    details = {"timeout": MESSAGE_TEMPLATES["regression_timeout"],
               "no_test_changes": MESSAGE_TEMPLATES["regression_no_test_changes"],
               "no_tests_collected": MESSAGE_TEMPLATES["regression_no_tests_collected"],
               "failed_on_head": MESSAGE_TEMPLATES["regression_failed_on_head"],
               "passed_on_base": MESSAGE_TEMPLATES["regression_passed_on_base"]}
    for finding in report.get("findings", ()):
        row = commits.get(finding.get("commit"))
        code = finding["code"]
        if row is None or code not in regression.UNVERIFIED_CODES and code not in details:
            yield {**finding, "message": guidance_value(finding["message"], prose=True)}
            continue
        message = GuidanceMessage("regression_prefix", MESSAGE_TEMPLATES["regression_prefix"],
                                  {"commit": row["commit"][:10], "subject": row["subject"]}).render()
        message += (GuidanceMessage("regression_unverified", MESSAGE_TEMPLATES["regression_unverified"],
                                   {"reason": code}).render() if code in regression.UNVERIFIED_CODES else details[code])
        message += _optional_fragment(GuidanceMessage("regression_rejected", MESSAGE_TEMPLATES["regression_rejected"],
                                                     {"exemption": row.get("exemption_code")}))
        message += _optional_fragment(GuidanceMessage("regression_note", MESSAGE_TEMPLATES["regression_note"],
                                                     {"note": row.get("no_test_reason")}))
        yield {**finding, "message": message}


def _layer1_message(detail):
    """Retain the legacy tool call frame; its symbol is the repository value."""
    if len(detail) > 8192:
        return guidance_value(detail, prose=True)
    prefix, suffix = MESSAGE_TEMPLATES["layer1_forbidden_call"].split("{name}")
    if detail.startswith(prefix) and detail.endswith(suffix):
        return GuidanceMessage("layer1_forbidden_call", MESSAGE_TEMPLATES["layer1_forbidden_call"],
                               {"name": detail[len(prefix):-len(suffix)]}).render()
    return GuidanceMessage("layer1", MESSAGE_TEMPLATES["layer1"], {"detail": detail}).render()


def _json_human_fields(value, path=()):
    """Traverse human fields, leaving keys, paths and other identities intact."""
    if isinstance(value, list):
        return [_json_human_fields(row, path) for row in value]
    if not isinstance(value, dict):
        return value
    human = {"message", "reason", "subject", "no_test_reason", "exemption_code", "detail", "snippet"}
    # Coverage's nested reasons are raw producer evidence in JSON, not human
    # diagnostics. Text, annotations and summaries use closed availability
    # categories for that producer; keep its existing JSON bytes and key order.
    producer = ("owner_review_required" if path == ("owner_review_findings",) else
                path[0] if len(path) == 1 and path[0] in ("weakenings", "findings") else None)
    return {key: child if not path and key == "coverage" else
            child if key == "message" and path == ("regression", "findings") and isinstance(value, MessageRow) else
            finding_message(value, producer=producer, display=_workflow_value if producer == "weakenings" else None)
            if key == "message" and isinstance(child, str) else
            _layer1_message(child) if key == "detail" and path == ("layer1",) and {"tool", "target", "verdict"} <= value.keys() else
            _perf_reason(value) if key == "reason" and path == ("perf",) and isinstance(child, str) else
            guidance_value(child, prose=True) if key in human and isinstance(child, str) else _json_human_fields(child, path + (key,))
            for key, child in value.items()}


def render_ci_json(document):
    """Render human fields without changing machine identities or the input document.

    Weakening messages have already crossed their template/data boundary in
    CiReport.as_dict. Other producers retain separate free-text data fields.
    """
    prepared = dict(document)
    if "regression" in document:
        prepared["regression"] = {**document["regression"],
                                  "findings": [MessageRow(row) for row in regression_findings(document["regression"])]}
    result = _json_human_fields(prepared)
    if isinstance(result.get("owner_review_findings"), list):
        result["owner_review_findings"] = [{key: receipt_value(value, 400, identifier=True)
            if key in ("code", "rule", "path") else value for key, value in row.items()}
            for row in result["owner_review_findings"]]
    return result


def ci_findings(document: dict[str, Any], workspace_root: Optional[str | Path] = None) -> list[dict[str, Any]]:
    """The findings of a ``check --ci`` document, from the fixed keys its producers write. Weakening,
    governance, regression, trailer and perf findings name no line; scanner findings are anchored."""
    from aegis_core import regression

    found = []
    approved = bool((document.get("approval") or {}).get("valid"))
    permitted = document.get("approval_mode") in PERMITTED_MODES
    for row in _owner_rows(document):
        found.append(_finding(row["code"], row["path"], 0,
                              f"{guidance_value(row['code'], prose=True)}: {guidance_value(row['rule'], prose=True)}: {finding_message(row, producer='owner_review_required')}", "note", workspace_root))
    for w in document.get("weakenings", ()):
        label = f"; approval mode {document['approval_mode']}" if permitted else ""
        found.append(_finding(w["rule"], w["path"], 0, f"{guidance_value(w['code'], prose=True)}: {finding_message(w, producer='weakenings')}{label}",
                              "note" if approved or permitted else "error", workspace_root))
    gov = document.get("governance") or {}
    for entry in gov.get("paths", ()) if gov.get("enforced") and not gov.get("approved") else ():
        found.append(_finding(f"governance:{entry['category']}", entry["path"], 0,
                              f"governance change without approval: {guidance_value(entry['path'], prose=True)}", "error", workspace_root))
    if permitted:
        for entry in gov.get("paths", ()):
            found.append(_finding(f"governance:{entry['category']}", entry["path"], 0,
                                  f"governance change; approval mode {document['approval_mode']}", "note", workspace_root))
    reg = document.get("regression") or {}
    for rf in regression_findings(reg):
        level = "error" if reg.get("tier") == "gate" and rf["code"] not in regression.UNVERIFIED_CODES else "warning"
        found.append(_finding(rf["code"], rf["path"], 0, rf["message"], level, workspace_root))
    for t_chk in document.get("trailer_checks", ()):
        if t_chk.get("failed"):
            found.append(_finding("trailer-divergence", "", 0,
                                  f"{guidance_value(t_chk['commit'][:10], prose=True)}: {guidance_value(t_chk.get('reason', ''), prose=True)}",
                                  "error", workspace_root))
    perf = document.get("perf") or {}
    if perf.get("status") == "fail":
        found.append(_finding("performance-regression", "", 0, perf_line(perf).strip(), "error", workspace_root))
    for scan in document.get("scanners", ()):
        for sf in scan["findings"]:
            found.append(_finding(f"scanner/{scan['name']}:{sf['rule_id']}", sf["path"], sf["line"],
                                  guidance_value(sf["message"], prose=True),
                                  "error", workspace_root))
        if scan["status"] == "unverified":
            found.append(_finding(f"scanner/{scan['name']}", "", 0, f"UNVERIFIED: {guidance_value(scan.get('reason', ''), prose=True)}",
                                  "warning", workspace_root))
    return found


def layer1_findings(document: dict[str, Any], workspace_root: Optional[str | Path] = None) -> list[dict[str, Any]]:
    """The findings of a Layer 1 report: each failed check, anchored at its first line when it names
    lines, and each checkpoint issue (``findings`` rows), which names none."""
    found = []
    for row in document.get("layer1", ()):
        if not row["verdict"]:
            lines = row.get("lines") or ()
            found.append(_finding(row["tool"], row["target"], lines[0] if lines else 0,
                                  _layer1_message(row["detail"]), "error", workspace_root))
    for issue in document.get("findings", ()):
        found.append(_finding(issue["rule"], "", 0, finding_message(issue, producer="findings"), issue.get("level", "error"), workspace_root))
    return found


def layer1_report_document(passed: bool, owned: list, checkpoint_issues: list, strict: bool,
                           *, checkpoint_info: Optional[list] = None) -> dict[str, Any]:
    """The document ``check FILES --format github|sarif`` reports: each piece of Layer 1 evidence under
    its workspace-relative file (``owned``: (path or None, ToolEvidence)) with its lines, and each
    checkpoint issue as a line-less finding (an error when it blocks)."""
    from aegis_cli.checkpoint import is_blocking
    from aegis_core.verification.strict_verdict import evidence_blocks

    strict_causes = [MessageRow(rule="strict:no-driver", message=GuidanceMessage("strict:no-driver",
        MESSAGE_TEMPLATES["strict_no_driver"], {}).render(), level="error")
        for _path, e in owned if e.verdict and evidence_blocks(e.verdict, e.tool, strict=strict)]

    return {"passed": passed,
            "checkpoint_info": list(checkpoint_info or ()),
            "layer1": [{"tool": e.tool, "target": path or e.target, "verdict": bool(e.verdict), "detail": e.detail,
                        "lines": list(e.lines), **({"language": e.language} if getattr(e, "language", None) else {})} for path, e in owned],
            "findings": [{"rule": f"checkpoint:{issue.get('check', '')}", "message": issue.get("message", ""),
                          "level": "error" if is_blocking(issue, strict) else "warning"} for issue in checkpoint_issues] + strict_causes}


def _split(document: dict[str, Any], workspace_root: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(anchored, line-less) findings of either document kind."""
    found = ci_findings(document, workspace_root) + layer1_findings(document, workspace_root)
    return ([f for f in found if f["uri"] and f["line"] >= 1], [f for f in found if not (f["uri"] and f["line"] >= 1)])


# A closed vocabulary of source-owned sentences, not a template reconstructed
# from free text. A lookup returns our literal; prefixes, suffixes and unknown
# exception names stay on the full value-rendering path.
_INTERNAL_PERF_FAILURES = {
    message: message for error in vars(builtins).values()
    if isinstance(error, type) and error.__module__ == "builtins" and issubclass(error, Exception)
    and error.__name__.isascii() and error.__name__.isidentifier()
    for message in (f"perf check could not run ({error.__name__})",)
}
_INTERNAL_PERF_FAILURE_MAX = max(map(len, _INTERNAL_PERF_FAILURES))


def _perf_reason(perf):
    reason = perf.get("reason", "")
    # Bound before hashing the value for the finite vocabulary lookup.
    if perf.get("status") == "unverified" and type(reason) is str and len(reason) <= _INTERNAL_PERF_FAILURE_MAX:
        literal = _INTERNAL_PERF_FAILURES.get(reason)
        if literal is not None:
            return literal
    return guidance_value(reason, prose=True)


def perf_line(perf: dict[str, Any]) -> str:
    """The text line of a ``--perf`` result: ``[PASS|FAIL|UNVERIFIED:perf] ...``."""
    tag = {"pass": "PASS", "fail": "FAIL"}.get(perf.get("status"), "UNVERIFIED")
    if tag == "UNVERIFIED":
        return f"  [UNVERIFIED:perf] {_perf_reason(perf)}"
    return (f"  [{tag}:perf] head {perf['head_min']:.4f}s / {perf['head_median']:.4f}s (min / median) against the merge "
            f"base's {perf['base_min']:.4f}s / {perf['base_median']:.4f}s over {perf['rounds']} paired rounds, threshold "
            f"{perf['threshold'] * 100:g} percent")


def governance_note(document: dict[str, Any]) -> str:
    """Why a changed governance set is not enforced (no signing key at the base), or ""."""
    gov = document.get("governance") or {}
    cats = ", ".join(shown for value in gov.get("categories") or ()
                     if (shown := guidance_value(value, prose=True)))
    mode = document.get("approval_mode")
    if mode in PERMITTED_MODES:
        return "owner review required" if mode == "review" else "approval mode none: no owner approval required"
    return (f"governance files changed ({cats}) but the base lists no key in allowed_signers, "
            "so no approval can be required (tier C: detection only)") if cats and not gov.get("enforced") else ""


def _escape_annotation(text: str, prop: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def _workflow_value(value: str) -> str:
    """Render a human value before the format's separate protocol encoding."""
    return guidance_value(value, prose=True)


def _coverage_line_count(value: Any) -> str:
    """Only producer counts, never free text or unbounded integer conversions."""
    return str(value) if type(value) is int and 0 <= value and value.bit_length() <= 63 else "unknown"


def coverage_reason(coverage: dict[str, Any]) -> str:
    """A closed availability category; full producer reasons belong only in JSON."""
    reason = coverage.get("reason", "")
    if not isinstance(reason, str) or len(reason) > 4096:
        return "other"
    reason = _flat(sanitize_display(reason, max_len=None)).lower()
    if reason in ("timeout", "the coverage run timed out", "the coverage json timed out"):
        return "timeout"
    if reason.endswith("no module named coverage") or reason in ("tool_missing", "go_missing"):
        return "tool missing"
    if reason in ("report_missing", "coverage_report_invalid", "coverage wrote no readable report"):
        return "no report"
    if reason.startswith(("cannot diff ", "the checkout is not ", "the work tree has uncommitted changes",
                          "cannot tell whether the work tree", "cannot use the state directory")) \
            or reason in ("coverage_paths_unmapped", "coverage_command_invalid"):
        return "validation failed"
    if reason == "coverage_not_configured":
        return "not configured"
    return "partial coverage" if reason == "partial_coverage" else "other"


def coverage_omitted_count(coverage: dict[str, Any]) -> str:
    """Empty unverified inventories mean unavailable accounting, not zero omissions."""
    inventory = coverage.get("unmeasured")
    if not isinstance(inventory, list) or (not inventory and coverage.get("status") != "reported"):
        return "unknown"
    return str(len(inventory))


def coverage_explanation(coverage: dict[str, Any]) -> str:
    """One bounded explanation of the measured subset; JSON retains every path and language."""
    languages = coverage.get("languages") or {}
    unavailable = ((language, row) for language, row in languages.items() if row.get("status") != "reported")
    shown = [f"{language if language in ('python', 'go', 'rust', 'ts') else 'other language'} ({coverage_reason(row)})"
             for language, row in islice(unavailable, 4)]
    remaining = sum(1 for _ in unavailable)
    if remaining:
        shown.append(f"{remaining} more (see JSON)")
    covered = _coverage_line_count(coverage.get("covered_lines"))
    total = _coverage_line_count(coverage.get("executable_lines"))
    reason = coverage_reason(coverage) if coverage.get("reason") else ""
    availability = ", ".join(shown) or ("not specified (see reason)" if not languages and coverage.get("status") != "reported" else "none")
    return (f"Measured lines: {covered}/{total}; unavailable languages: {availability}; "
            f"omitted paths: {coverage_omitted_count(coverage)}. See JSON for full detail."
            + (f" Reason: {reason}." if reason else ""))


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
    permitted = document.get("approval_mode") in PERMITTED_MODES
    for row in _owner_rows(document):
        out.append(line("notice", "owner review required",
                        f"{guidance_value(row['code'], prose=True)}: {guidance_value(row['rule'], prose=True)}: {finding_message(row, producer='owner_review_required')}", _owner_path(row["path"])))
    level, title = ("notice", "weakening approved") if approved else ("error", "weakening without approval")
    if permitted:
        level, title = "notice", "weakening permitted by approval mode"
    for w in document.get("weakenings", ()):
        out.append(line(level, title,
                        f"{_workflow_value(w['code'])}: {_workflow_value(w['rule'])}: "
                        f"{finding_message(w, producer='weakenings', display=_workflow_value)}", w["path"]))
    gov = document.get("governance") or {}
    level, title = ("notice", "governance change approved") if gov.get("approved") else ("error", "governance change without approval")
    for entry in gov.get("paths", ()) if gov.get("enforced") else ():
        message = (f"governance:{guidance_value(entry['category'], prose=True)}: {guidance_value(entry['path'], prose=True)} changed; "
                   "it passes only with a signed approval (aegis approve)")
        out.append(line(level, title, message, entry["path"]))
    if permitted:
        for entry in gov.get("paths", ()):
            out.append(line("notice", "governance change permitted by approval mode",
                            f"governance:{guidance_value(entry['category'], prose=True)}: {guidance_value(entry['path'], prose=True)} changed", entry["path"]))
    note = governance_note(document)
    if note:
        out.append(line("notice" if permitted else "warning",
                        "approval mode" if permitted else "governance change not enforced", note))
    reg = document.get("regression") or {}
    gate = reg.get("tier") == "gate"
    for rf in regression_findings(reg):
        if rf["code"] in regression.UNVERIFIED_CODES:
            level, title = "warning", "regression check unverified"
        else:
            level, title = ("error", "regression check failed") if gate else ("warning", "regression check warning")
        out.append(line(level, title, f"{guidance_value(rf['code'], prose=True)}: {rf['message']}", rf["path"]))
    for scan in document.get("scanners", ()):
        for sf in scan["findings"]:
            out.append(line("error", f"scanner/{guidance_value(scan['name'], prose=True)}",
                            f"{guidance_value(sf['rule_id'], prose=True)}: {guidance_value(sf['message'], prose=True)}", sf["path"], sf["line"]))
        if scan["status"] == "unverified":
            out.append(line("warning", "scanner unverified", f"{guidance_value(scan['name'], prose=True)}: {guidance_value(scan.get('reason', ''), prose=True)}"))
    for t_chk in document.get("trailer_checks", ()):
        if t_chk.get("failed"):
            out.append(line("error", "Aegis-Check trailer divergence",
                            f"{guidance_value(t_chk['commit'][:10], prose=True)}: {guidance_value(t_chk.get('reason', ''), prose=True)}"))
    perf = document.get("perf")
    if isinstance(perf, dict) and perf.get("status") == "fail":
        out.append(line("error", "performance regression", perf_line(perf).strip()))
    elif isinstance(perf, dict) and perf.get("status") != "pass":
        out.append(line("warning", "performance unverified", _perf_reason(perf)))
    cov = document.get("coverage")
    if isinstance(cov, dict) and cov.get("status") == "reported":
        ratio = cov.get("ratio")
        figure = "n/a" if ratio is None else f"{ratio * 100:.1f} percent"
        out.append(line("notice", "diff coverage",
                        f"{figure} of {cov.get('executable_lines', 0)} changed executable lines (report only)"))
    elif isinstance(cov, dict):
        out.append(line("warning", "coverage unverified", coverage_reason(cov)))
    if isinstance(cov, dict):
        out[-1] += esc(" " + coverage_explanation(cov))
    for row in document.get("layer1", ()):  # a Layer 1 report: only the first evidence line is annotated
        if not row["verdict"]:
            lines = row.get("lines") or ()
            out.append(line("error", guidance_value(row["tool"], prose=True), _layer1_message(row["detail"]),
                            row["target"], lines[0] if lines else 0))
    for issue in document.get("findings", ()):
        out.append(line(issue.get("level", "error"), guidance_value(issue["rule"], prose=True), finding_message(issue, producer="findings")))
    for note in document.get("checkpoint_info", ()):
        out.append(line("notice", f"checkpoint:{guidance_value(note['check'], prose=True)}",
                        guidance_value(note["message"], prose=True), note["file"]))
    return out


def _flat(value: Any) -> str:
    """One line: every non-printable character (newlines, ANSI, bidi controls) a space, runs collapsed."""
    return " ".join("".join(ch if ch.isprintable() else " " for ch in str(value)).split())


def _md_code(value: Any) -> str:
    """``value`` as an inline code span, the one Markdown form in which nothing is parsed: fenced by one
    backtick more than its longest backtick run, padded when it starts or ends with one."""
    text = _flat(value)
    if not text:
        return ""
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text[0] == "`" or text[-1] == "`" else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _table_row(*spans: str) -> str:
    """A table row with one column per span. A pipe is escaped even inside a span (GFM splits rows first)
    and a backslash run before it doubled, so no reading of the escapes lets data end a column."""
    return "| " + " | ".join(re.sub(r"(\\*)\|", lambda m: m.group(1) * 2 + "\\|", span) for span in spans) + " |"


def format_github_step_summary(report_dict: dict[str, Any], workspace_root: Optional[str | Path] = None) -> str:
    """Render a Markdown job summary for $GITHUB_STEP_SUMMARY."""
    anchored, lineless = _split(report_dict, workspace_root)
    mode = report_dict.get("approval_mode")
    if mode not in PERMITTED_MODES:
        owner_codes = {row["code"] for row in _owner_rows(report_dict)}
        lineless = [f for f in lineless if f["level"] != "note" or f["rule_id"] in owner_codes]
    status = report_dict.get("status")
    passed = report_dict.get("passed", status == "pass" if status is not None else not (anchored or lineless))
    lines = [f"## Aegis Check Summary: {'PASSED' if passed else 'FAILED'}", ""]
    if mode in PERMITTED_MODES:
        lines.extend([f"approval mode {mode}", ""])
        if mode == "review":
            lines.extend(["owner review required", ""])
    if anchored:
        lines.extend(["### Line-Anchored Findings", "| Rule | Location | Level | Message |", "| :--- | :--- | :--- | :--- |"])
        lines.extend(_table_row(_md_code(guidance_value(f["rule_id"], prose=True)), _md_code(f"{guidance_value(f['uri'], prose=True)}:{f['line']}:{f['col']}"), f["level"],
                                _md_code(f["message"])) for f in anchored)
        lines.append("")
    if lineless:
        lines.append("### Repository / Unanchored Findings")
        for f in lineless:
            uri = guidance_value(f["uri"], prose=True)
            loc = f" ({_md_code(uri)})" if uri else ""
            lines.append(f"- **{_md_code(guidance_value(f['rule_id'], prose=True))}**{loc}: {_md_code(f['message'])}")
        lines.append("")
    cov = report_dict.get("coverage")
    if isinstance(cov, dict):
        ratio, measured = cov.get("ratio"), cov.get("status") == "reported"
        figure = "n/a" if ratio is None else f"{float(ratio) * 100.0:.1f}%"
        lines.append(f"### Diff Coverage (report only): {figure} of {cov.get('executable_lines', 0)} changed executable lines"
                     if measured else f"### Diff Coverage: UNVERIFIED ({_md_code(coverage_reason(cov))})")
        lines.append(_md_code(coverage_explanation(cov)))
        for path, ranges in sorted((cov.get("uncovered_ranges") or {}).items()):
            spans = ", ".join(f"{int(s)}-{int(e)}" if s != e else str(int(s)) for s, e in ranges)
            lines.append(f"- {_md_code(guidance_value(path, prose=True))}: uncovered lines {spans}")
        lines.append("")
    perf = report_dict.get("perf")
    if isinstance(perf, dict):  # no reason text: it can quote the benchmark's stderr
        lines.extend([f"### Performance: {({'pass': 'PASS', 'fail': 'FAIL'}).get(perf.get('status'), 'UNVERIFIED')}", ""])
    if not anchored and not lineless and not isinstance(cov, dict) and not isinstance(perf, dict):
        lines.append("No findings reported.")
    if report_dict.get("checkpoint_info"):
        lines.extend(["", "### Test Pairing (information only)"])
        lines.extend(f"- {_md_code(guidance_value(note['message'], prose=True))}" for note in report_dict["checkpoint_info"])
    return "\n".join(lines).strip() + "\n"


def _fingerprints(anchored: list[dict[str, Any]]) -> list[str]:
    """One ``primaryLocationLineHash`` per finding: (uri, rule, occurrence, message), the occurrence
    counted per (uri, rule, message) in line order. Moving every line keeps each value; two equal
    findings in one file still differ. One-time effect: alerts from before 4.4.0 reopen."""
    seen: dict[tuple[str, str, str], int] = {}
    prints = [""] * len(anchored)
    for i in sorted(range(len(anchored)), key=lambda i: (anchored[i]["line"], anchored[i]["col"], i)):
        f = anchored[i]
        key = (f["uri"], f["rule_id"], f["message"])
        seen[key] = seen.get(key, -1) + 1
        joined = "\0".join((f["uri"], f["rule_id"], str(seen[key]), f["message"]))
        prints[i] = hashlib.sha256(joined.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return prints


def format_sarif_report(report_dict: dict[str, Any], workspace_root: Optional[str | Path] = None,
                        error: str = "") -> str:
    """A SARIF 2.1.0 log of line-anchored findings; strict causes are execution notifications.
    With ``error`` the run is reported as not completed, with no result."""
    anchored = [] if error else _split(report_dict, workspace_root)[0]
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f, line_hash in zip(anchored, _fingerprints(anchored)):
        rid = f["rule_id"]
        rules_seen.setdefault(rid, {"id": rid, "shortDescription": {"text": guidance_value(rid, prose=True)}})
        results.append({
            "ruleId": rid, "level": f["level"], "message": {"text": f["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["uri"], "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": f["line"], "startColumn": f["col"]}}}],
            "partialFingerprints": {"primaryLocationLineHash": line_hash},
        })
    from aegis_core._version import __version__

    run: dict[str, Any] = {"tool": {"driver": {"name": "Aegis Guardrails", "version": __version__,
                                               "rules": list(rules_seen.values())}}, "results": results}
    if error:
        run["invocations"] = [{"executionSuccessful": False, "toolExecutionNotifications": [
            {"level": "error", "message": {"text": error}}]}]
    else:
        notifications = [{"level": "note", "message": {"text": guidance_value(note["message"], prose=True)}}
                         for note in report_dict.get("checkpoint_info", ())]
        notifications.extend({"level": "error", "message": {"text": finding_message(finding, producer="findings")}}
                             for finding in report_dict.get("findings", ()) if finding["rule"] == "strict:no-driver")
        if report_dict.get("approval_mode") is not None:
            notifications.append({"level": "note", "message": {"text":
                f"approval mode {report_dict['approval_mode']}; target {guidance_value(report_dict.get('approval_target') or 'unknown', prose=True)}"}})
        owner_codes = {row["code"] for row in _owner_rows(report_dict)}
        notifications.extend({"level": finding["level"], "message": {"text":
            f"{guidance_value(finding['rule_id'], prose=True)}: {guidance_value(finding['uri'], prose=True)}: {finding['message']}"}}
            for finding in ci_findings(report_dict, workspace_root) if not finding["line"]
            and (report_dict.get("approval_mode") is not None or finding["rule_id"] in owner_codes))
        if notifications:
            run["invocations"] = [{"executionSuccessful": True, "toolExecutionNotifications": notifications}]
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]},
                      indent=2)
