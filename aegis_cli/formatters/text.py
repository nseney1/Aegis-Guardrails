"""Terminal text for the reports aegis_core returns as data.

Each renderer takes a report's ``as_dict()`` document, the same one ``--json`` prints, and returns
its lines; the caller strips terminal controls when it prints them (repository text is not
sanitized here). Core computes, the CLI renders: the five reports carry no text method. The
report modules are imported when a report is rendered, so importing this module costs nothing on
paths that print none of them (the pre-commit check).
"""
from __future__ import annotations

from typing import Any, List, Mapping

__all__ = ["render_card", "render_lane", "render_partition", "render_release", "render_tier"]

# Why a release report printed before the trust tier could be read has none.
_NO_TIER_WHY = {"gh_missing": "gh unavailable", "gh_too_old": "gh unavailable",
                "not_a_repository": "not a git repository", "git_failed": "git could not answer"}


def render_card(doc: Mapping[str, Any]) -> List[str]:
    """The day-0 card (``aegis check --card``, the end of ``aegis init``)."""
    from aegis_core.card import NEXT_RULE

    scope, rules, layer1 = doc["scope"], doc["rules"], doc["layer1"]
    lines = ["Aegis day-0 card", f"  workspace: {scope['workspace']}"]
    origin = "git" if scope["listing"] == "git" else "walked"
    if scope["sampled"]:
        lines.append(f"  files: {scope['files']} ({origin}). Sampled {scope['files_analyzed']} of {scope['files']} files "
                     "for Layer 1")
    else:
        lines.append(f"  files: {scope['files']} ({origin}), all analyzed")
    if doc["languages"]:
        lines.append("  languages: " + ", ".join(f"{row['language']} {row['files']}" for row in doc["languages"]))
    else:
        lines.append("  languages: none recognized (rules are language-agnostic)")
    if doc["drivers"]:
        parts = []
        for row in doc["drivers"]:
            label = "built-in" if row["language"] == "python" else row["status"]
            parts.append(f"{row['language']}: {label}")
        lines.append("  AST drivers: " + "; ".join(parts))
    if rules.get("error"):
        lines.append("  rules: cannot be read (see the note below)")
    else:
        kinds = ", ".join(f"{name} {n}" for name, n in rules["by_type"].items())
        detail = f" ({kinds})" if kinds else ""
        lines.append(f"  rules: {rules['total']}{detail}, {len(rules['active'])} active "
                     "(served and targeting a file)")
    if not layer1["checked"]:
        lines.append("  Layer 1: no file to check")
    else:
        percent = int(layer1["pass_rate"] * 100) if layer1["pass_rate"] is not None else 0
        lines.append(f"  Layer 1: {percent}% of {layer1['checked']} files pass "
                     f"({layer1['passed']} of {layer1['checked']}); "
                     f"{layer1['findings']} finding(s) in {layer1['failed']} file(s)")
    if doc["top_files"]:
        lines.append("  files with the most findings:")
        lines.extend(f"    {row['findings']:>5}  {row['path']}" for row in doc["top_files"])
    for note in doc["notes"]:
        lines.append(f"  note: {note}")
    if not rules["active"]:
        lines.append(f"  {NEXT_RULE}")
    return lines


def render_partition(doc: Mapping[str, Any]) -> List[str]:
    """The cross-lane edge report (``aegis check --partition``)."""
    scope, edges, not_analyzed = doc["scope"], doc["edges"], doc["not_analyzed"]
    kinds = ", ".join(f"{n} {lang}" for lang, n in sorted(scope["languages"].items())) or "none"
    lines = [f"{doc['source']}: {len(doc['lanes'])} lanes, {scope['files_analyzed']} file(s) analyzed ({kinds}), "
             f"{len(not_analyzed)} not analyzed", "lanes:"]
    for lane in doc["lanes"]:
        lines.append(f"  {lane['name']}: {lane['files']} file(s) [{', '.join(lane['globs'])}]")
    if doc["overlap"]:
        lines.append("overlap (matched by more than one lane; left out of the edges):")
        lines.extend(f"  {item['path']} ({', '.join(item['lanes'])})" for item in doc["overlap"])
    else:
        lines.append("overlap: none")
    if not edges:
        lines.append("cross-lane edges: none")
    else:
        lines.append(f"cross-lane edges: {len(edges)}")
        pair = None
        for edge in edges:
            if (edge["from_lane"], edge["to_lane"]) != pair:
                pair = (edge["from_lane"], edge["to_lane"])
                count = sum(1 for e in edges if (e["from_lane"], e["to_lane"]) == pair)
                lines.append(f"  {pair[0]} -> {pair[1]}: {count}")
            landing = f"{edge['to']}::{edge['symbol']}" if edge["symbol"] else edge["to"]
            lines.append(f"    {edge['kind']:<7} {edge['from']}:{edge['line']} -> {landing}  ({edge['target']})")
    if not_analyzed:
        lines.append("not analyzed:")
        lines.extend(f"  {item['path']}: {item['reason']}" for item in not_analyzed[:20])
        if len(not_analyzed) > 20:
            lines.append(f"  ... and {len(not_analyzed) - 20} more")
    lines.append("[FROZEN_SIGNATURES]")
    if doc["frozen_signatures"]:
        lines.append("# Do not change these while the lanes run in parallel; a change is a request to the dispatcher.")
        for item in doc["frozen_signatures"]:
            users = ", ".join(sorted({f"{use['lane']}: {use['path']}:{use['line']}" for use in item["used_by"]}))
            lines.append(f"{item['path']}::{item['symbol']}  {item['signature']}  (lane {item['lane']}; used by {users})")
    else:
        lines.append("(none)")
    lines.append("[/FROZEN_SIGNATURES]")
    lines.append(doc["limits"][0])
    lines.extend(f"warning: {warning}" for warning in doc["warnings"])
    return lines


def _lane_source(source: str, base: str) -> str:
    if source.startswith("base@"):
        return f"team.json at {base} {source[len('base@'):][:12]}"
    return {"lease": "the lane's lease", "cli": "--paths", "worktree": "the working tree's team.json"}[source]


def render_lane(doc: Mapping[str, Any]) -> List[str]:
    """The post-lane gate (``aegis check --lane``), one line per item."""
    from aegis_core.lane_gate import PROTECTED

    scope, provenance, allowed, integrity = doc["scope"], doc["provenance"], doc["allowed"], doc["integrity"]
    changes = doc["containment"]["paths"]
    violations = [change for change in changes if not change["allowed"]]
    verdict = "PASSED" if doc["status"] == "pass" else "FAILED"
    lines = [
        f"{doc['source']} {scope['lane']}: {verdict} ({doc['label']})",
        f"  range: {scope['merge_base'][:12]}..{scope['head'][:12]} (from the merge base of {scope['base']} and HEAD), "
        f"{len(changes)} changed path(s)",
        f"  allowed paths from {_lane_source(provenance['paths'], scope['base'])}: {', '.join(allowed['paths']) or '(none)'}",
        f"  shared from {_lane_source(provenance['shared'], scope['base'])}: {', '.join(allowed['shared']) or '(none)'}",
    ]
    if violations:
        lines.append(f"containment: FAILED, {len(violations)} of {len(changes)} changed path(s) "
                     "outside the allowed set")
        for change in violations:
            why = ("protected: only team.json at the base tip (--base-policy) can allow "
                   + " and ".join(PROTECTED)) if change["protected"] else "outside the allowed set"
            lines.append(f"  [FAIL] {change['status']} {change['path']}: {why}")
    else:
        lines.append(f"containment: passed, {len(changes)} changed path(s) inside the allowed set")
    if integrity["findings"]:
        lines.append(f"test integrity (Python): FAILED, {len(integrity['findings'])} finding(s); protected_changed: true")
        for f in integrity["findings"]:
            lines.append(f"  [FAIL] {f['id']} {f['kind']} {f['path']}: {f['name']} ({f['detail']})")
    else:
        lines.append(f"test integrity (Python): passed, {len(integrity['checked'])} file(s) checked; "
                     "protected_changed: false")
    for item in integrity["not_checked"]:
        lines.append(f"  not checked: {item['path']} ({item['reason']})")
    lines.extend(f"warning: {warning}" for warning in doc["warnings"])
    lines.extend(doc["notes"])  # the label's note, then the exemption note
    return lines


def render_release(doc: Mapping[str, Any]) -> List[str]:
    """``aegis doctor --release``: what was asked, what was established, and why not more."""
    from aegis_core.release_verify import TIER_C_CAVEAT, UNVERIFIED_GH, WORKFLOW

    code, message, tier = doc["code"], doc["message"], doc["tier"]
    if code in ("gh_missing", "gh_too_old"):
        lines = [UNVERIFIED_GH, f"  {message}"]
    elif doc["verified"]:
        lines = [
            f"VERIFIED: the CI verdict for {doc['scope']['commit']} is attested by {doc['scope']['repository']}'s "
            f"{WORKFLOW}",
            f"  {message}",
        ]
    elif code == "agent_editable":
        lines = [f"NOT VERIFIED: {TIER_C_CAVEAT}", f"  {message}"]
    else:
        lines = [f"NOT VERIFIED: {message}"]
    if tier:
        lines.append(f"  trust tier: {tier}")
    elif code in _NO_TIER_WHY:
        lines.append(f"  trust tier: unknown ({_NO_TIER_WHY[code]})")
    lines += [f"  ! {caveat}" for caveat in doc["caveats"]]
    return lines


def render_tier(doc: Mapping[str, Any]) -> List[str]:
    """The human_gate trust tier, with the evidence it rests on and why it is not higher."""
    return [
        f"Trust tier (human_gate): {doc['tier']} ({doc['label']}): {doc['statement']}",
        *(f"  - {reason}" for reason in doc["reasons"]),
        *(f"  ! {caveat}" for caveat in doc["caveats"]),
    ]
