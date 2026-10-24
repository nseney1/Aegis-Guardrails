"""aegis_report_outcome: advisory self-reports appended to the outcome ledger."""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import PurePath
import sys
from typing import Dict, List, Optional, Tuple

from aegis_core import credit, gitsafe, treeid
from aegis_core.primitives import envelope
from aegis_core.errors import PathTraversalError
from aegis_core.rule_inventory import RuleInventoryError
from aegis_core.rules import validate_rule_names
from aegis_mcp.handlers.common import STATUS_FAIL, VALID_OUTCOMES, get_workspace, remember_bounded

# (workspace root, session, idempotency key) whose edit event is recorded, and the edit rows
# written per (root, session). The key is the caller's string, so both are bounded: by the
# report cap per session and by _MAX_RECORDED keys per process.
_RECORDED: Dict[Tuple[str, str, str], None] = {}
_EDITS: Dict[Tuple[str, str], int] = {}
_MAX_RECORDED = 1024

_KEY_REQUIRED = (
    "'idempotency_key' is required: send a unique key per report so a retry is never recorded twice."
)
_RULES_REQUIRED = (
    "'rules_used' must name at least one rule from aegis_scan: "
    "an outcome with no rule has nothing to credit."
)


def _fail(message: str) -> dict:
    return {"status": STATUS_FAIL, "error": message}


def _credited_rules(workspace, check, bound, host: Optional[str], session: Optional[str]) -> List[str]:
    """Rules exposed in this server session's scans and matching ``diff(base, check tree)``."""
    from aegis_core.scan import RULE_CACHE

    exposed = credit.witnessed_exposed_rules(workspace.root, host, session)
    if not exposed or bound is None:
        return []
    try:
        if bound.binding.tree != check.get("tree"):
            return []
        # diff_entries names top-level paths; rule patterns are workspace-relative.
        prefix = gitsafe.show_prefix(workspace.root)
        changed = [
            relative
            for status, path in bound.diff_entries(str(check.get("base")))
            if status != "D" and (relative := gitsafe.relative_to_prefix(prefix, path)) is not None
        ]
        ruleset = RULE_CACHE.get(workspace)
    except Exception:  # an unreadable tree or rule set credits nothing
        return []
    return sorted(rule.id for rule in ruleset.served if rule.id in exposed and rule.matching_files(changed))


def handle_report_outcome(args: dict) -> dict:
    try:
        workspace = get_workspace(args)
    except ValueError as exc:
        return _fail(str(exc))

    raw_outcome = args.get("outcome")
    outcome = raw_outcome.strip().lower() if isinstance(raw_outcome, str) else None
    if outcome not in VALID_OUTCOMES:
        return _fail(f"Invalid 'outcome': {raw_outcome!r}. Expected one of {list(VALID_OUTCOMES)}.")

    # A generated key would make every retry a new event, so the caller must supply one.
    idempotency_key = args.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not idempotency_key.strip():
        return _fail(_KEY_REQUIRED)

    rules_used = args.get("rules_used")
    if rules_used is None or (isinstance(rules_used, (list, tuple)) and not rules_used):
        return _fail(_RULES_REQUIRED)
    if not isinstance(rules_used, (list, tuple)) or not all(isinstance(r, str) for r in rules_used):
        return _fail("'rules_used' must be a list of rule names.")
    rules_used = list(rules_used)
    try:
        invalid = validate_rule_names(rules_used, workspace)
    except RuleInventoryError as exc:
        return _fail(f"Cannot check 'rules_used' against the rules: {exc}")
    if invalid:
        return _fail(f"Unknown rule(s): {invalid}. Only existing rules can be reported.")
    files = args.get("files")
    edited: Optional[List[str]] = None
    if files is not None:
        if not isinstance(files, (list, tuple)) or not all(isinstance(f, str) for f in files):
            return _fail("'files' must be a list of file paths")
        try:
            edited = sorted({PurePath(workspace.confine_path(f)[1]).as_posix() for f in files})
        except ValueError as exc:
            return _fail(str(exc))

    # Attribution comes from the server (clientInfo and its session), never the caller. The
    # credited rules are the server's: those this session's scans exposed that also match the
    # change the check covered. 'rules_used' above only had to be well formed.
    host, session = args.get("_host"), args.get("_session")
    # One bind per report, held open: the check is chosen under the ledger lock, then diffed against it.
    with ExitStack() as stack:
        try:
            bound = stack.enter_context(treeid.bind(workspace.root))
        except (treeid.TreeError, OSError):  # as tree_of: an unreadable work tree is an unwitnessed claim
            bound = None
        tree = bound.binding.tree if bound is not None and bound.binding.bound else None
        try:
            result = credit.submit_report(
                workspace.root, tree=tree, session=session, host=host, key=idempotency_key, outcome=outcome,
                rules_for=lambda check: _credited_rules(workspace, check, bound, host, session))
        except credit.ReportConflict:
            return _fail(
                f"'idempotency_key' {idempotency_key!r} was already used for a different report: "
                "send a new key for each new report."
            )
        except Exception as exc:
            return _fail(f"Failed to record outcome: {exc}")
    # A report the ledger did not take (capped, or a repeat claim) writes nothing at all.
    if edited and result.get("status") != "rate_limited" and result.get("recorded") is not False:
        _record_edit(workspace, args, idempotency_key, edited)
    return {**envelope("aegis_report_outcome", {"tree": tree}), **result}


def _record_edit(workspace, args: dict, idempotency_key: str, files: List[str]) -> None:
    """One ``edit`` activity event per report, for aegis status --compliance."""
    from aegis_core import scan_compliance

    session = args.get("_session")
    if not session:
        return
    key = (str(workspace.root), str(session), idempotency_key)
    written = _EDITS.get(key[:2], 0)
    if key in _RECORDED or written >= credit.MAX_REPORT_ROWS_PER_SESSION:
        return
    try:
        scan_compliance.record(
            workspace, "edit", host=str(args.get("_host") or "generic"), session=str(session), files=files,
            client={"name": args.get("_client_name") or "", "version": args.get("_client_version") or ""},
            binding=args.get("_binding"), basis="report", key=idempotency_key,
        )
    except Exception as exc:  # telemetry only: the outcome is recorded
        print(f"aegis-mcp: edit event not recorded: {exc}", file=sys.stderr)
        return
    remember_bounded(_RECORDED, key, None, _MAX_RECORDED)
    remember_bounded(_EDITS, key[:2], written + 1, _MAX_RECORDED)


def handle_capture_insight(args: dict) -> dict:
    from aegis_core.insights import CaptureLimitReached, capture_suggestion

    try:
        workspace = get_workspace(args)
    except ValueError as exc:
        return _fail(str(exc))

    quote = args.get("quote")
    if not isinstance(quote, str) or not quote.strip():
        return _fail("'quote' is required and must be a non-empty string.")

    raw_paths = args.get("paths")
    if raw_paths is not None and (
        not isinstance(raw_paths, (list, tuple)) or not all(isinstance(p, str) for p in raw_paths)
    ):
        return _fail("'paths' must be a list of file paths.")

    host = str(args.get("_host") or "mcp")
    session = args.get("_session")
    try:
        row = capture_suggestion(
            workspace.root,
            quote=quote,
            paths=list(raw_paths) if raw_paths is not None else None,
            host=host,
            session=str(session) if session else None,
        )
    except (PathTraversalError, CaptureLimitReached) as exc:
        return _fail(str(exc))
    except Exception as exc:
        return _fail(f"Failed to capture insight: {exc}")

    return {
        "status": "OK",
        "id": row["id"],
        "level": row["level"],
        "text": row["text"],
        "paths": row["paths"],
        "psrc": row["psrc"],
    }

