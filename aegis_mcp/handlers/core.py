"""aegis_scan: the rules that apply to the files about to change."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
from functools import partial
from pathlib import PurePath
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_core import hosts, scan_exposure
from aegis_core.guidance_projection import GuidanceResult, project_diagnostic, project_display_text
from aegis_core.primitives import parse_utc
from aegis_core.scan import scan, scan_user_layer
from aegis_core.skills.slots import render_scan_result as render_scan_result
from aegis_core.skills.slots import scan_registry
from aegis_mcp.handlers.common import STATUS_FAIL, DEFAULT_CLIENT_PLATFORM, NOT_GOVERNED_MESSAGE, get_workspace
from aegis_mcp.handlers.common import remember_bounded

# (workspace root, session, files) -> the stamp of its last scan row. A rescan writes
# again once that row is older than half of jit.scan_window_s: the scan-before-edit hook
# only counts rows inside the window, and aegis-mcp outlives a Claude /clear, so a
# once-per-process row would leave a long session blocked for good. The age is read on
# the rows' own wall clock (scan_compliance.utc_now), never a monotonic one: that stops
# during a suspend, and after a night asleep the row would have left the hook's window
# while a monotonic age still said it was fresh, so the scan the hook asks for would
# write nothing. Bounded: a forgotten key costs one extra row, never the scan result.
_RECORDED: Dict[Tuple[str, str, Tuple[str, ...]], datetime] = {}
_MAX_RECORDED = 1024


def _scan_error(message: str) -> dict:
    return {"error": project_display_text(message), "status": STATUS_FAIL}


def _slot_profile(host: Any) -> str:
    """The ${SLOT.*} profile of the identified host (host-matrix §3.3 ``slot_profile``).

    Any other value (an in-process caller's platform name) goes to the slot table as
    given, which maps what it does not know to the generic profile.
    """
    if not host:
        return DEFAULT_CLIENT_PLATFORM
    try:
        return hosts.get(str(host)).slot_profile
    except KeyError:
        return str(host)


def _record_scan(workspace: Any, args: dict, files: Optional[List[str]]) -> None:
    """A ``scan`` activity row per (session, files), written again when the last one is
    older than half the scan window: aegis status --compliance and the scan-before-edit
    hook read them.

    Telemetry never costs the agent its guidance: a failed append is logged and the
    scan result stands (and the next scan tries again).
    """
    from aegis_core import gitsafe, scan_compliance
    from aegis_core.config import scan_window_s

    session = args.get("_session")
    if not session:
        return
    basis = "files"
    if files is None:
        basis = "git_diff"
        files = gitsafe.changed_files(workspace.root, "working") or []
    paths = tuple(sorted({PurePath(f).as_posix() for f in files}))
    key = (str(workspace.root), str(session), paths)
    if not paths:
        return
    last = _RECORDED.get(key)
    if last is not None:
        age = scan_compliance.utc_now() - last
        # A negative age (the clock was set back) puts the row in the hook's future.
        if timedelta(0) <= age < timedelta(seconds=scan_window_s(workspace.root) / 2):
            return
    try:
        row = scan_compliance.record(
            workspace, "scan", host=str(args.get("_host") or DEFAULT_CLIENT_PLATFORM), session=str(session),
            files=paths, client={"name": args.get("_client_name") or "", "version": args.get("_client_version") or ""},
            binding=args.get("_binding"), basis=basis,
        )
    except Exception as exc:  # telemetry only: never fail the scan
        print("aegis-mcp: scan event not recorded: " + project_diagnostic(str(exc), refuse_controls=True), file=sys.stderr)
        return
    stamp = parse_utc(row["ts"])
    if stamp is not None:
        remember_bounded(_RECORDED, key, stamp, _MAX_RECORDED)


def _record_exposure(workspace: Any, args: dict, res: dict, files: Optional[List[str]] = None) -> None:
    """Retain delivery telemetry for the insight review's host, time and revision join."""
    from aegis_core import credit
    from aegis_core.storage import ledger_site

    names = [item.get("name") for key in ("relevant_rules", "invariant_warnings")
             for item in (res.get(key) or []) if isinstance(item, dict)]
    rule_ids = list(res.exposure_rule_ids()) if isinstance(res, GuidanceResult) else [n for n in names if isinstance(n, str)]
    host = str(args.get("_host") or "")
    session = str(args.get("_session") or "")
    error: Optional[Exception] = None
    revisions = res.exposure_revisions() if isinstance(res, GuidanceResult) else ()
    revs = {rule_id: revision[:16] for rule_id, revision in revisions}
    try:
        persist = bool(session) and (not args.get("_binding") or ledger_site(workspace.root, create=False).shared)
    except Exception as exc:
        persist, error = False, exc
    try:
        recorded_ids = [rule_id for rule_id in rule_ids if rule_id in revs] if persist and revisions else rule_ids
        credit.record_exposure(workspace.root, host, session, recorded_ids, paths=files, revs=revs,
                               persist=persist and bool(revisions))
    except Exception as exc:  # telemetry only: never fail the scan
        error = exc
    if error is not None:
        print("aegis-mcp: exposure record not written: " + project_diagnostic(str(error), refuse_controls=True), file=sys.stderr)


def _scan_user_layer(args: dict) -> dict:
    """Nothing governs this call (H8): the read-only user layer, never a ledger write."""
    files = args.get("files")
    if files is not None and (not isinstance(files, (list, tuple)) or not all(isinstance(f, str) for f in files)):
        return _scan_error("'files' must be a list of file paths")
    registry = scan_registry(_slot_profile(args.get("_host")))
    return scan_user_layer(list(files) if files else None, registry=registry,
                           extras={"status": "not_governed", "message": NOT_GOVERNED_MESSAGE,
                                   "reason": args.get("_unbound")})


def handle_scan(args: dict, *, project: Optional[Callable[[dict], dict]] = None) -> dict:
    """Express the JIT rules for the given files (or the git diff when none are given)."""
    from aegis_core import gitsafe

    # Its own scope: recording the scan and its exposures asks where the ledger is after scan() returns.
    with gitsafe.memo():
        result, delivered = _handle_scan(args)
        projected = result if project is None else project(result)
        if delivered is not None and projected is result:
            delivered(project is not None)
        return projected


def _literal_scope(root, requested, confined):
    try:
        path = PurePath(requested)
        if path.is_absolute():
            path = path.relative_to(root)
        return path.as_posix() == confined
    except ValueError:
        return False


def _handle_scan(args: dict) -> Tuple[dict, Optional[Callable[[bool], None]]]:
    if args.get("_unbound"):
        return _scan_user_layer(args), None
    try:
        workspace = get_workspace(args)
    except (ValueError, OSError, RuntimeError) as exc:
        return _scan_error(str(exc)), None
    files = args.get("files")
    exposure_allowed = True
    if files is not None:
        if not isinstance(files, (list, tuple)) or not all(isinstance(f, str) for f in files):
            return _scan_error("'files' must be a list of file paths"), None
        try:  # [] means "none given" here as in scan(): the git diff, recorded as such
            scoped = [PurePath(workspace.confine_path(f)[1]).as_posix() for f in files]
            exposure_allowed = all(_literal_scope(workspace.root, raw, path) for raw, path in zip(files, scoped))
            files = scoped or None
        except (ValueError, OSError, RuntimeError) as exc:
            return _scan_error(str(exc)), None

    registry = scan_registry(_slot_profile(args.get("_host")), workspace.root)
    options = {} if exposure_allowed else {"exposure_allowed": False}
    res = scan(workspace, changed_files=files, registry=registry, **options)
    if res.get("status") == STATUS_FAIL:
        return res, None
    _record_scan(workspace, args, files)

    def delivered(with_receipt):
        record = partial(_record_exposure, workspace, args, res, files)
        if not with_receipt:
            record()
        elif isinstance(res, GuidanceResult) and not res.get("status") and args.get("_session"):
            scan_exposure.offer(str(workspace.root), args.get("_host") or "", args["_session"],
                                res.exposure_snapshot(), delivered=record)

    return res, delivered
