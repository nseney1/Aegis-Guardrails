"""Opt-in projection of a tool response: full (default), summary or ids."""
from __future__ import annotations

import json
from typing import Any, Mapping, Optional

# The first of these names a rule: its file stem (`_name`, from aegis_list_rules) is
# what aegis_report_outcome accepts, so it wins over a frontmatter `name` or `id`.
_IDENTITY_KEYS = ("_name", "name", "rule_id", "id")

SUMMARY_FIELDS: frozenset[str] = frozenset({
    "_name",
    "name",
    "rule_id",
    "id",
    "type",
    "enforcement",
    "tier",
    "status",
    "fitness",
    "rules_staged",
})
_SUMMARY_LIST_CAP = 10


def is_error_result(result: Any) -> bool:
    """A handler reports failure as {"status": "FAIL", "error": ...}."""
    return isinstance(result, Mapping) and ("error" in result or result.get("status") == "FAIL")


def _identity(item: Mapping) -> Optional[str]:
    for key in _IDENTITY_KEYS:
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _ids(data: Any) -> Any:
    if isinstance(data, list):
        # An item with no identity is dropped, never stringified: that would dump its body.
        names = (_identity(item) if isinstance(item, Mapping) else item for item in data)
        return [name for name in names if name is not None]
    if isinstance(data, Mapping):
        ids: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, list):
                ids[key] = _ids(value)
                if len(ids[key]) < len(value):
                    ids[f"{key}_count"] = len(value)
                    ids[f"{key}_listed_count"] = len(ids[key])
        stats = data.get("stats")
        if isinstance(stats, Mapping) and "omitted_mandatory" in stats:
            ids.setdefault("omitted_mandatory", [])
            ids["omitted_mandatory_count"] = stats["omitted_mandatory"]
            ids["omitted_mandatory_listed_count"] = len(ids["omitted_mandatory"])
        if "unreviewed_rules" in data or "unreviewed_total" in data:
            ids.setdefault("unreviewed_rules", [])
            ids["unreviewed_rules_count"] = data.get("unreviewed_total", len(data.get("unreviewed_rules", [])))
            ids["unreviewed_rules_listed_count"] = len(ids["unreviewed_rules"])
        return ids
    return data


def _summary_item(item: Any) -> Any:
    if isinstance(item, Mapping):
        return {key: value for key, value in item.items() if key in SUMMARY_FIELDS}
    return item


def _summary(data: Any) -> Any:
    if isinstance(data, list):
        return [_summary_item(item) for item in data]
    if isinstance(data, Mapping):
        summary: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, list):
                summary[f"{key}_count"] = len(value)
                summary[key] = [_summary_item(item) for item in value[:_SUMMARY_LIST_CAP]]
                if len(value) > _SUMMARY_LIST_CAP:
                    summary[f"{key}_listed_count"] = len(summary[key])
            elif key in SUMMARY_FIELDS:
                summary[key] = value
        return summary
    return data


def _prefer_smaller(data: Any, projected: Any) -> Any:
    """Use the full response when inspection costs at least as many tokens."""
    from aegis_core.scan import estimate_tokens

    return projected if estimate_tokens(json.dumps(projected)) < estimate_tokens(json.dumps(data)) else data


def _scan_summary(data: Mapping) -> Any:
    """Inspect a scan without confusing budget-trimmed names with exact totals.

    Metadata comes from the core scan, including its review witness and original
    stats. If even metadata cannot fit, deliver the full guidance already bounded
    by the core rather than silently dropping provenance to make a summary fit.
    Also prefer the original full scan when it costs no more than the summary.
    """
    from aegis_core.scan import estimate_tokens

    # Selected rules and constraints must stay visible together. A full scan is
    # already bounded; use it if the summary's list cap would hide either.
    if any(len(data.get(key, [])) > _SUMMARY_LIST_CAP for key in ("relevant_rules", "invariant_warnings")):
        return data
    summary = _summary(data)
    summary["inspection"] = "Inspection only; request view='full' for full guidance before editing."
    for key in ("rules_base", "stats", "unreviewed_total", "user_layer", "message", "reason"):
        if key in data:
            summary[key] = data[key]
    for key, detail, total in (
        ("omitted_mandatory", "reason", data["stats"]["omitted_mandatory"]),
        ("unreviewed_rules", "change", data.get("unreviewed_total", len(data.get("unreviewed_rules", [])))),
    ):
        if key == "unreviewed_rules" and "rules_base" not in data:
            continue
        listed = data.get(key, [])[:_SUMMARY_LIST_CAP]
        summary[key] = [dict(_summary_item(item), **{detail: item[detail]})
                        if isinstance(item, Mapping) and detail in item else _summary_item(item)
                        for item in listed]
        summary[f"{key}_count"] = total
        summary[f"{key}_listed_count"] = len(listed)

    # Trim inspection names with retained totals, never selected rules or their
    # constraints: if those cannot fit with metadata, deliver full guidance.
    budget = data["stats"].get("max_tokens_budget")
    lists = ("unreviewed_rules", "omitted_mandatory", "stale_rules", "warnings")
    for key in lists:
        if key in summary:
            summary[f"{key}_listed_count"] = len(summary[key])
    while budget is not None and estimate_tokens(json.dumps(summary)) > budget:
        key = next((key for key in lists if summary.get(key)), None)
        if key is None:
            return data
        summary[key].pop()
        if f"{key}_listed_count" in summary:
            summary[f"{key}_listed_count"] = len(summary[key])
    return _prefer_smaller(data, summary)


def project_response(data: Any, view: Optional[str] = "full") -> Any:
    """Project a tool response for a client that asked for less than the full payload.

    - ids: the rule names in each list of the response, with exact omission totals
      and displayed counts when names are shortened;
    - summary: identity, type, status and fitness of each item, lists capped at 10;
      scans also keep provenance, exact omission totals and change kinds. Compact
      scans are inspection; fetch full guidance before editing. If the metadata
      cannot fit alongside the selected rules and constraints, the list cap would
      hide them, return the original full scan. All summaries return the original
      full response when it costs no more than the summary.
    - full (or anything else): the response unchanged.

    An error result is always returned whole, so the host still sees it as an error.
    """
    if is_error_result(data):
        return data
    view_norm = (view or "full").strip().lower()
    if view_norm == "ids":
        return _ids(data)
    if view_norm == "summary":
        if (isinstance(data, Mapping) and "relevant_rules" in data
                and isinstance(data.get("stats"), Mapping) and "omitted_mandatory" in data["stats"]):
            return _scan_summary(data)
        return _prefer_smaller(data, _summary(data))
    return data
