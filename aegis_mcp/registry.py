"""MCP tool definitions, workspace binding and the rule inventory used by the handlers."""
from __future__ import annotations

from typing import Any, Optional

from aegis_core.fitness import for_rules
from aegis_core.rule_inventory import RuleInventoryError
from aegis_core.rules import load_rules
from aegis_core.sync import read_derived, stale_rules
from aegis_core.taxonomy import CANONICAL_RULE_TYPES, REVIEW_MODES, RULE_TYPES
from aegis_core.workspace.base import Workspace
from aegis_core.workspace import resolve_workspace

_STATUS_FAIL = "FAIL"
NOT_GOVERNED_MESSAGE = 'not an Aegis workspace: run "aegis init" in your repository'
# A client whose clientInfo names no known host: its ledger rows say "generic" and its
# scans get the generic slot table, never another vendor's (host-matrix §3.5).
DEFAULT_CLIENT_PLATFORM = "generic"
_VALID_OUTCOMES = ("success", "partial", "failure", "tp", "fp", "pass", "fail")


def _get_workspace(args: Optional[dict] = None) -> Workspace:
    """The workspace a handler acts on.

    Over stdio the server always injects its own workspace; an in-process caller may
    pass one. Without either, resolve strictly from AEGIS_WORKSPACE or the cwd.
    """
    raw = args.get("workspace") if args else None
    if isinstance(raw, Workspace):
        return raw
    return Workspace.confine(raw or resolve_workspace(strict_env=True))


def list_rules(workspace: Workspace, rule_type: Optional[str] = None) -> Any:
    """Every rule with its ledger fitness, plus what is stale or not a rule.

    Returns ``{"rules": [...], "stale_rules": [...], "ignored": [...]}``. A rule file
    that cannot be loaded stays in ``rules`` as a record with ``_error``; an unsafe
    rules tree (a symlink escape, an unreadable directory) fails the whole call.
    """
    try:
        ruleset = load_rules(workspace)
    except RuleInventoryError as exc:
        return {"status": _STATUS_FAIL, "error": str(exc)}
    selected = [r for r in ruleset.rules if not rule_type or r.type == rule_type]
    fits = for_rules(workspace, [r for r in selected if r.ok])
    rules = []
    for rule in selected:
        data = rule.as_dict()
        if rule.ok:
            data["fitness"] = fits[rule.id].as_dict()
        if rule.expired:
            data["_expired"] = True
        rules.append(data)
    stale = stale_rules(ruleset, read_derived(workspace))
    return {
        "rules": rules,
        "stale_rules": [s for s in stale if not rule_type or _type_of(s, ruleset) == rule_type],
        "ignored": [{"path": i.path, "reason": i.reason} for i in ruleset.ignored],
    }


def _type_of(stale: dict, ruleset: Any) -> Optional[str]:
    rule = ruleset.get(stale.get("id") or "")
    return rule.type if rule is not None else None


def build_rule_create_prompt(
    description: str,
    domain_hint: Optional[str] = None,
    rule_type: Optional[str] = None,
    args: Optional[dict] = None,
) -> str:
    workspace = _get_workspace(args)
    examples = [rule.raw.decode("utf-8-sig")[:500] for rule in load_rules(workspace).served]

    example_text = "\n---\n".join(examples[:3]) if examples else "No existing rules found."
    domain_context = f"\nDomain hint: {domain_hint}" if domain_hint else ""
    type_hint = f"\nPreferred rule type: {rule_type}" if rule_type else ""
    type_lines = "\n".join(
        f"- {name}: {spec.description}" for name, spec in RULE_TYPES.items()
    )

    return f"""You are a governance rule generator for Aegis.

Given a natural language description of a concern, generate a governance rule in markdown with YAML frontmatter.

Rule types:
{type_lines}

YAML fields required:
- type: (one of above)
- domain: (one of: efficiency, correctness, security, style, governance)
- enforcement: (gate for invariants, advisory for traps)
- hypothesis: (clear, testable statement)
- prediction: (what will happen if the hypothesis is violated)
- falsification: (how to prove this rule is no longer needed)
- target_paths: (list of file glob patterns this rule monitors)
- minimum_mode: ({' | '.join(REVIEW_MODES)})
- tags: (list of relevant tags)

Do not write a fitness block: fitness is computed from the outcome ledger.

Existing rules in this project for reference:
{example_text}
{domain_context}{type_hint}

User description: "{description}"

Generate ONLY the complete markdown rule file content. Start with --- for the YAML frontmatter. After the closing ---, include a brief description paragraph explaining the rule's purpose. Do not include any other text."""


_VIEW_PROPERTY = {
    "type": "string",
    "enum": ["full", "summary", "ids"],
    "description": "'full' (default), 'summary' (key fields, lists capped at 10 plus <list>_count) or 'ids'.",
}
_RULE_TYPE_PROPERTY = {"type": "string", "enum": list(CANONICAL_RULE_TYPES)}
# tests_passed, rework_count and notes stay in the schema: additionalProperties is false, so
# dropping them would fail v4.2 clients that still send them.
_IGNORED = "Accepted for compatibility; ignored, never stored."


def _read(title: str) -> dict:
    return {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False, "title": title}


def _write(title: str) -> dict:
    # Only readOnlyHint is declared: hosts treat annotations as untrusted hints and no host is
    # documented to skip the prompt for a self-declared non-destructive write, so a write tool
    # claims nothing beyond "not read-only" and the MCP defaults apply.
    return {"readOnlyHint": False, "title": title}

TOOL_DEFINITIONS = [
    {
        "name": "aegis_scan",
        "description": (
            "Call before editing files: returns the rules for `files` (default: the git diff), ranked by "
            "fitness within the token budget, and records this session's scan and rule exposure. Mandatory "
            "rules (gates, invariants) take at most two slots (the excess is in `omitted_mandatory`) and are "
            "served from the reviewed base, so branch-local edits to them do not bind and are listed in "
            "`unreviewed_rules`. Use `aegis_list_rules` to browse without recording and `aegis_report_outcome` "
            "after verifying. Fails closed if a rule file cannot be loaded."
        ),
        "annotations": _read("Scan JIT Rules"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Paths you are about to edit; omitted or empty means the files changed in the git "
                        "work tree and index."
                    ),
                },
                "view": _VIEW_PROPERTY,
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "aegis_report_outcome",
        "description": (
            "Call after verifying a change with tests or `aegis check`, naming rules from `aegis_scan`; use "
            "`aegis_capture_insight` for user corrections. With a passing `aegis check --record --tests` row "
            "for the current tree, the rules this session's scans exposed that match the diff are credited, "
            "counting once CI passes on the landing commit; without one, it writes at most one unwitnessed "
            "claim per session and tree, which earns no credit. Capped at 200 report rows per session and "
            "rate-limited to 5 calls per 60 seconds."
        ),
        "annotations": _write("Report Outcome"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "outcome": {
                    "type": "string",
                    "enum": list(_VALID_OUTCOMES),
                    "description": (
                        "'success', 'tp' and 'pass' claim a true positive (credited only after CI); the "
                        "others read as a neutral trigger, never a false positive."
                    ),
                },
                "idempotency_key": {
                    "type": "string",
                    "maxLength": 256,
                    "description": (
                        "Unique per report (scoped by host and session): a retry is a no-op; reuse with "
                        "another outcome fails."
                    ),
                },
                "rules_used": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": (
                        "Rule IDs from aegis_scan; credit comes from this session's scan exposure and the "
                        "diff, not this list."
                    ),
                },
                "tests_passed": {"type": "boolean", "description": _IGNORED},
                "rework_count": {"type": "integer", "default": 0, "description": _IGNORED},
                "notes": {"type": "string", "maxLength": 4096, "description": _IGNORED},
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Paths edited in this change, for scan-before-edit compliance only (at most one "
                        "'edit' event per report); never affects credit."
                    ),
                },
                "view": _VIEW_PROPERTY,
            },
            "required": ["outcome", "rules_used", "idempotency_key"],
            "additionalProperties": False,
        },
    },
    {
        "name": "aegis_create_rule",
        "description": (
            "Builds a prompt for drafting a rule from `description`, with up to three active workspace rules "
            "(500 chars each) as examples; it writes nothing to disk. Save the result to "
            "`.aegis/rules/<type_dir>/<id>.md` as `instruction` says. Check `aegis_list_rules` for an "
            "existing rule first."
        ),
        "annotations": _read("Create Rule"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "The defect, anti-pattern or invariant the rule should codify.",
                },
                "rule_type": dict(_RULE_TYPE_PROPERTY, description="Rule type, passed to the draft prompt as a hint."),
                "domain": {
                    "type": "string",
                    "description": (
                        "Domain hint for the draft prompt (security, correctness, efficiency, style, governance)."
                    ),
                },
            },
            "required": ["description"],
            "additionalProperties": False,
        },
    },
    {
        "name": "aegis_list_rules",
        "description": (
            "Lists every rule with metadata and ledger fitness (`_error` if unloadable, `_expired: true` if "
            "retired), the `stale_rules` edited since the last `aegis sync`, and non-rule files under "
            "`.aegis/rules/` (`ignored`). Records no scan or exposure: call `aegis_scan` before editing files."
        ),
        "annotations": _read("List Rules"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_type": dict(_RULE_TYPE_PROPERTY, description="Only rules and stale_rules of this type."),
                "view": _VIEW_PROPERTY,
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "aegis_capture_insight",
        "description": (
            "Appends a user correction or preference to `~/.aegis/insights/` for rule curation; use "
            "`aegis_report_outcome` to report whether rules helped. Secrets are redacted, `quote` is cut to "
            "300 characters and `paths` default to the dirty git paths. Agent captures stay at "
            "`level: 'suggestion'`: invisible to `aegis_scan`, never counted by `aegis rule insight review`, "
            "never upgraded. Capped at 50 captures per session and rate-limited to 5 calls per 60 seconds."
        ),
        "annotations": _write("Capture Insight"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "quote": {
                    "type": "string",
                    "maxLength": 1024,
                    "description": (
                        "The user's verbatim correction (1-1024 chars); secrets are redacted and 300 chars stored."
                    ),
                },
                "paths": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 512},
                    "maxItems": 20,
                    "description": (
                        "Paths it applies to (psrc 'explicit'; at most 20 of 512 chars); default: up to 20 "
                        "dirty git paths (psrc 'dirty')."
                    ),
                },
            },
            "required": ["quote"],
            "additionalProperties": False,
        },
    },
]

TOOL_ARGUMENTS = {
    tool["name"]: frozenset(tool["inputSchema"].get("properties", {})) for tool in TOOL_DEFINITIONS
}
