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
        "outputSchema": {
            "type": "object",
            "properties": {
                "relevant_rules": {
                    "type": "array",
                    "description": (
                        "Active rules matching the target files, ranked by fitness within the "
                        "JIT token budget (rule objects in 'full'/'summary' view, or rule ID "
                        "strings in 'ids' view)."
                    ),
                },
                "relevant_rules_count": {
                    "type": "integer",
                    "description": (
                        "Total count of relevant_rules before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "guidance": {
                    "type": "string",
                    "description": (
                        "Rendered markdown guidance block ready for prompt injection "
                        "(omitted when view='summary' or 'ids')."
                    ),
                },
                "invariant_warnings": {
                    "type": "array",
                    "description": "Mandatory gate and invariant rules triggered by the target files.",
                },
                "invariant_warnings_count": {
                    "type": "integer",
                    "description": (
                        "Total count of invariant_warnings before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "rules_staged": {
                    "type": ["integer", "array"],
                    "description": (
                        "Count of rules staged in relevant_rules after budget clamping "
                        "(omitted when view='ids')."
                    ),
                },
                "rules_staged_count": {
                    "type": "integer",
                    "description": (
                        "Total count of rules_staged before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "omitted_mandatory": {
                    "type": "array",
                    "description": (
                        "Mandatory gate or invariant rules that matched but exceeded the "
                        "two-slot mandatory cap."
                    ),
                },
                "omitted_mandatory_count": {
                    "type": "integer",
                    "description": (
                        "Total count of omitted_mandatory before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "stale_rules": {
                    "type": "array",
                    "description": "Rules edited on disk since the last 'aegis sync' derived-file regeneration.",
                },
                "stale_rules_count": {
                    "type": "integer",
                    "description": (
                        "Total count of stale_rules before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "unreviewed_rules": {
                    "type": "array",
                    "description": (
                        "Gate or invariant rules added or modified since rules_base whose "
                        "local changes do not bind."
                    ),
                },
                "unreviewed_rules_count": {
                    "type": "integer",
                    "description": (
                        "Total count of unreviewed_rules before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "unreviewed_total": {
                    "type": "integer",
                    "description": "Total count of unreviewed gate or invariant rules across the workspace.",
                },
                "rules_base": {
                    "type": ["object", "string", "null"],
                    "description": (
                        "Reviewed git base anchor from which binding gate and invariant "
                        "rules were loaded."
                    ),
                },
                "stats": {
                    "type": "object",
                    "description": (
                        "Scan telemetry summary including matched counts and token budget "
                        "usage (omitted in 'summary'/'ids' views)."
                    ),
                },
                "warnings": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional non-fatal scan warning messages.",
                },
                "warnings_count": {
                    "type": "integer",
                    "description": (
                        "Total count of warnings before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "user_layer": {
                    "type": "object",
                    "description": (
                        "Read-only user-layer metadata ({path, rules}) when scanning "
                        "outside a governed Aegis workspace."
                    ),
                },
                "status": {
                    "type": "string",
                    "description": (
                        "Optional status indicator ('not_governed' when scanning the user "
                        "layer outside an Aegis workspace, or 'FAIL' on error)."
                    ),
                },
                "message": {
                    "type": "string",
                    "description": "Informational message when status='not_governed'.",
                },
                "reason": {
                    "type": ["string", "null"],
                    "description": "Unbound workspace reason code when status='not_governed'.",
                },
                "error": {
                    "type": "string",
                    "description": "Error detail when status='FAIL'.",
                },
                "rule_errors": {
                    "type": "array",
                    "description": "Rule files that failed to parse when status='FAIL'.",
                },
            },
            "required": ["relevant_rules"],
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
                        "record a true positive ('tp'), 'failure'/'fp'/'fail' record a false "
                        "positive ('fp'), and 'partial' records a neutral trigger ('trigger')."
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
                    "description": (
                        "Optional boolean recording whether the project's test suite passed "
                        "during verification."
                    ),
                },
                "rework_count": {
                    "type": "integer",
                    "default": 0,
                    "description": (
                        "Optional non-negative integer count of edit-and-retest cycles before "
                        "verification succeeded (default: 0)."
                    ),
                },
                "notes": {
                    "type": "string",
                    "maxLength": 4096,
                    "description": (
                        "Optional free-text context describing how the rules helped or failed "
                        "(max 4096 chars)."
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
        "outputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["recorded", "claimed", "rate_limited", "FAIL"],
                    "description": (
                        "Report disposition: 'recorded' (witnessed by a matching check record), "
                        "'claimed' (unwitnessed self-report), 'rate_limited' (session cap "
                        "reached), or 'FAIL'."
                    ),
                },
                "witness": {
                    "type": "string",
                    "enum": ["aegis", "self"],
                    "description": (
                        "Attestation tier: 'aegis' when backed by a passing 'aegis check --record --tests' "
                        "row for the current tree, or 'self' for unwitnessed claims."
                    ),
                },
                "credited": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Rule IDs credited in the outcome ledger (empty for unwitnessed "
                        "'claimed' or 'rate_limited' reports)."
                    ),
                },
                "credited_count": {
                    "type": "integer",
                    "description": (
                        "Total count of credited rules before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "check": {
                    "type": "string",
                    "description": "Check record ID that witnessed the report (present when status='recorded').",
                },
                "tree": {
                    "type": ["string", "null"],
                    "description": "Git tree hash computed for the workspace at report time.",
                },
                "recorded": {
                    "type": "boolean",
                    "description": (
                        "False when status='rate_limited' or when an unwitnessed claim for "
                        "the same session and tree was already recorded."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "Per-session report cap (200) returned when status='rate_limited'.",
                },
                "source": {
                    "type": "string",
                    "description": "Command or tool name that produced the response ('aegis_report_outcome').",
                },
                "aegis_version": {
                    "type": "string",
                    "description": "Running Aegis package version string.",
                },
                "checked_at": {
                    "type": "string",
                    "description": "UTC ISO-8601 timestamp when the report was processed.",
                },
                "scope": {
                    "type": "object",
                    "description": "Workspace scope metadata envelope ({tree}).",
                },
                "error": {
                    "type": "string",
                    "description": "Error message when status='FAIL'.",
                },
            },
            "required": ["credited"],
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
                        "Optional target rule category ('invariant' or 'gate' for blocking "
                        "checks; 'trap', 'boundary', 'persona', or 'contract' for advisory "
                        "guidance). Determines the target subdirectory under .aegis/rules/."
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
        "outputSchema": {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": (
                        "Structured rule-generation prompt containing schema requirements and "
                        "up to three workspace rule examples."
                    ),
                },
                "instruction": {
                    "type": "string",
                    "description": (
                        "Step-by-step instruction telling the caller where under "
                        ".aegis/rules/<type_dir>/<id>.md to save the drafted markdown."
                    ),
                },
                "status": {
                    "type": "string",
                    "description": "Present with value 'FAIL' only when input validation fails.",
                },
                "error": {
                    "type": "string",
                    "description": "Error message when status='FAIL'.",
                },
            },
            "required": ["prompt", "instruction"],
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
        "outputSchema": {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "description": (
                        "Workspace rule records with metadata and ledger fitness "
                        "(or rule ID strings when view='ids')."
                    ),
                },
                "rules_count": {
                    "type": "integer",
                    "description": (
                        "Total count of rules before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "stale_rules": {
                    "type": "array",
                    "description": "Rules edited since the last 'aegis sync' derived-file regeneration.",
                },
                "stale_rules_count": {
                    "type": "integer",
                    "description": (
                        "Total count of stale_rules before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "ignored": {
                    "type": "array",
                    "description": "Non-rule markdown files under .aegis/rules/ with path and reason.",
                },
                "ignored_count": {
                    "type": "integer",
                    "description": (
                        "Total count of ignored files before 'summary' view truncation "
                        "(present when view='summary')."
                    ),
                },
                "status": {
                    "type": "string",
                    "description": (
                        "Present with value 'FAIL' only when the rules directory cannot "
                        "be safely loaded."
                    ),
                },
                "error": {
                    "type": "string",
                    "description": "Error message when status='FAIL'.",
                },
            },
            "required": ["rules", "stale_rules", "ignored"],
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
            "records start at `level: 'suggestion'`, which is invisible to `aegis_scan` and excluded "
            "from `aegis insights review` rule proposals until corroborated (`level: 'W2'`) by a "
            "matching user prompt captured by a host hook in the same session. Capped at 50 captures "
            "per session and rate-limited to 5 calls per 60 seconds."
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
        "outputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["OK", "FAIL"],
                    "description": "'OK' when the insight row was appended, or 'FAIL' on validation/storage error.",
                },
                "id": {
                    "type": "string",
                    "description": "Content-addressed insight identifier ('ins-<12-hex>').",
                },
                "level": {
                    "type": "string",
                    "enum": ["suggestion", "W2"],
                    "description": (
                        "Corroboration tier: 'suggestion' initially, or 'W2' when matched "
                        "to a hook-captured user prompt in the same session."
                    ),
                },
                "text": {
                    "type": "string",
                    "description": (
                        "Secret-redacted and length-capped (max 300 chars) correction quote "
                        "stored in the ledger."
                    ),
                },
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Workspace-relative file paths associated with this insight.",
                },
                "psrc": {
                    "type": "string",
                    "enum": ["explicit", "dirty"],
                    "description": (
                        "Path provenance: 'explicit' when caller supplied paths, or 'dirty' "
                        "when inferred from git status."
                    ),
                },
                "error": {
                    "type": "string",
                    "description": "Error message when status='FAIL'.",
                },
            },
            "required": ["status", "id", "level", "text", "paths", "psrc"],
            "additionalProperties": False,
        },
    },
]

TOOL_ARGUMENTS = {
    tool["name"]: frozenset(tool["inputSchema"].get("properties", {})) for tool in TOOL_DEFINITIONS
}
