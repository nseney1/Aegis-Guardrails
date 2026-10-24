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
    "description": (
        "Optional response projection: 'full' (default, complete payload), 'summary' "
        "(retains identity/type/status/fitness fields, caps lists at 10 items, and adds "
        "<list>_count), or 'ids' (projects each list to rule ID strings). Error responses "
        "are never projected."
    ),
}
_RULE_TYPE_PROPERTY = {"type": "string", "enum": list(CANONICAL_RULE_TYPES)}


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
            "Call before editing files: returns the governance rules matching `files` (or the git "
            "diff when `files` is omitted), ranked by ledger fitness and clamped to the JIT token "
            "budget. Use this tool before any file edit to satisfy the pre-edit scan gate and "
            "record session rule exposure; use `aegis_list_rules` to inspect the full inventory "
            "without file matching, and `aegis_report_outcome` after verifying your changes. "
            "Mandatory rules (gates, invariants) take at most two slots; any excess is listed in "
            "`omitted_mandatory`. Gates and invariants are served from the reviewed base commit "
            "(`rules_base`), so branch-local edits to them never bind and are listed in "
            "`unreviewed_rules`, while `stale_rules` lists rules edited since the last `aegis sync`. "
            "Fails closed (`status: 'FAIL'`) if any rule file cannot be loaded."
        ),
        "annotations": _read("Scan JIT Rules"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Workspace-relative file paths you are about to edit. When omitted or "
                        "empty, defaults to modified files in the current git working tree and index."
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
            "Record post-verification rule feedback in the local outcome ledger after running tests "
            "or `aegis check`. Use this tool at the end of an edit-and-verify cycle; use `aegis_scan` "
            "before editing files and `aegis_capture_insight` to record user corrections. When a "
            "passing `aegis check --record --tests` row exists for the current git tree, the server credits rules "
            "exposed by `aegis_scan` in this session that match the diff (`rules_used` is validated "
            "against the rule inventory, not used as the credit source). Those credits count "
            "toward fitness once CI passes on the landing commit. Without a matching check record, it "
            "writes at most one unwitnessed claim per session and tree that earns no fitness credit. "
            "Capped at 200 report rows per session and rate-limited to 5 calls per 60 seconds."
        ),
        "annotations": _write("Report Outcome"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "outcome": {
                    "type": "string",
                    "enum": list(_VALID_OUTCOMES),
                    "description": (
                        "Verification result for the rules in this change: 'success'/'tp'/'pass' "
                        "claim a true positive, which earns credit only after CI confirms the landing "
                        "commit; 'failure'/'fp'/'fail' are kept as the claim and, like 'partial', read "
                        "as a neutral trigger, never a false positive."
                    ),
                },
                "idempotency_key": {
                    "type": "string",
                    "maxLength": 256,
                    "description": (
                        "Caller-supplied unique key (1-256 chars, scoped per host and session). "
                        "Retrying with the same key and outcome is a no-op; reusing a key with a "
                        "different outcome fails with status 'FAIL'."
                    ),
                },
                "rules_used": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": (
                        "Non-empty list of existing rule IDs from aegis_scan. Validated against "
                        "the workspace rule inventory; actual fitness credit is computed "
                        "server-side from session scan exposure and git diff paths."
                    ),
                },
                "tests_passed": {
                    "type": "boolean",
                    "description": "Optional boolean. Accepted for compatibility; ignored, never stored.",
                },
                "rework_count": {
                    "type": "integer",
                    "default": 0,
                    "description": "Optional integer. Accepted for compatibility; ignored, never stored.",
                },
                "notes": {
                    "type": "string",
                    "maxLength": 4096,
                    "description": (
                        "Optional text (max 4096 chars). Accepted for compatibility; ignored, never stored."
                    ),
                },
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional workspace-relative file paths edited in this change. Records "
                        "one 'edit' activity event per idempotency_key for scan-before-edit "
                        "compliance (aegis status --compliance); does not affect rule credit."
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
            "Build a structured prompt for drafting a new governance rule from a natural-language "
            "`description`. Use this tool when asked to author or codify a repository rule; use "
            "`aegis_list_rules` to inspect existing rules first, or `aegis_capture_insight` to log "
            "a raw user correction without creating a rule file. Samples up to three active "
            "workspace rules (500 chars each) as style examples, incorporates optional `rule_type` "
            "and `domain` hints, and writes nothing to disk: save the drafted markdown to "
            "`.aegis/rules/<type_dir>/<id>.md` yourself as directed by `instruction`."
        ),
        "annotations": _read("Create Rule"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": (
                        "Non-empty natural-language description of the engineering defect, "
                        "anti-pattern, or invariant to codify into a rule."
                    ),
                },
                "rule_type": dict(
                    _RULE_TYPE_PROPERTY,
                    description=(
                        "Optional rule category ('invariant' or 'gate' for blocking checks; "
                        "'trap', 'boundary', 'persona', or 'contract' for advisory guidance), "
                        "passed to the draft prompt as a hint."
                    ),
                ),
                "domain": {
                    "type": "string",
                    "description": (
                        "Optional domain hint injected into the drafting prompt (e.g., "
                        "'security', 'correctness', 'efficiency', 'style', 'governance')."
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
            "List the workspace governance rule inventory in directory order without recording a "
            "scan or exposure event. Use this tool to browse or audit rules, check ledger fitness, "
            "or find stale/broken rule files; use `aegis_scan` instead before editing files so "
            "pre-edit scan compliance and session rule exposure are recorded. Returns every rule "
            "with its metadata and ledger fitness (or `_error` if unloadable, and `_expired: true` "
            "if retired), rules modified since the last `aegis sync` (`stale_rules`), and non-rule "
            "markdown under `.aegis/rules/` (`ignored`). Pass `rule_type` to filter `rules` and "
            "`stale_rules` to one category, or `view` (`'summary'` or `'ids'`) to compact the payload."
        ),
        "annotations": _read("List Rules"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_type": dict(
                    _RULE_TYPE_PROPERTY,
                    description=(
                        "Optional filter restricting both 'rules' and 'stale_rules' to a single "
                        "rule category ('invariant', 'trap', 'gate', 'boundary', 'persona', or "
                        "'contract'). Omit to list all categories."
                    ),
                ),
                "view": _VIEW_PROPERTY,
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "aegis_capture_insight",
        "description": (
            "Append a user correction quote to the user-scoped insights log (`~/.aegis/insights/`) "
            "for rule curation. Use this tool when the user corrects your approach or states a "
            "recurring preference; use `aegis_create_rule` to draft a `.aegis/rules/` file "
            "immediately, or `aegis_report_outcome` to report whether existing rules helped. Each "
            "call redacts secrets, truncates `quote` to 300 characters, associates `paths` (or dirty "
            "git worktree paths when omitted), and appends a new `ins-<hex>` record. Agent-submitted "
            "records stay at `level: 'suggestion'`: invisible to `aegis_scan`, never counted by "
            "`aegis rule insight review` and never upgraded to `level: 'W2'`, not even by a later "
            "capture in the same session. A user prompt that a host hook captured on the same host "
            "within 30 minutes and that contains the quote only annotates the record as corroborated. "
            "Capped at 50 captures per session and rate-limited to 5 calls per 60 seconds."
        ),
        "annotations": _write("Capture Insight"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "quote": {
                    "type": "string",
                    "maxLength": 1024,
                    "description": (
                        "Non-empty verbatim quote of the user's correction or preference "
                        "(1-1024 chars; secrets are automatically redacted and stored text is "
                        "capped at 300 chars)."
                    ),
                },
                "paths": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 512},
                    "maxItems": 20,
                    "description": (
                        "Optional workspace-relative file paths this correction applies to "
                        "(sets psrc='explicit'; at most 20 of at most 512 characters, more fails the "
                        "call). When omitted or empty, defaults to the first 20 currently modified "
                        "git worktree paths (psrc='dirty')."
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
