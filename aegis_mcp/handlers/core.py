"""aegis_scan: the rules that apply to the files about to change."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import PurePath
import sys
from typing import Any, Dict, List, Optional, Tuple

from aegis_core import hosts
from aegis_core.scan import scan, scan_user_layer
from aegis_core.skills.slots import render_scan_result
from aegis_mcp.registry import _STATUS_FAIL, DEFAULT_CLIENT_PLATFORM, NOT_GOVERNED_MESSAGE, _get_workspace

# (workspace root, session, files) -> the stamp of its last scan row. A rescan writes
# again once that row is older than half of jit.scan_window_s: the scan-before-edit hook
# only counts rows inside the window, and aegis-mcp outlives a Claude /clear, so a
# once-per-process row would leave a long session blocked for good. The age is read on
# the rows' own wall clock (scan_compliance.utc_now), never a monotonic one: that stops
# during a suspend, and after a night asleep the row would have left the hook's window
# while a monotonic age still said it was fresh, so the scan the hook asks for would
# write nothing.
_RECORDED: Dict[Tuple[str, str, Tuple[str, ...]], datetime] = {}


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
        print(f"aegis-mcp: scan event not recorded: {exc}", file=sys.stderr)
        return
    _RECORDED[key] = datetime.strptime(row["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _record_exposure(workspace: Any, args: dict, res: dict, files: Optional[List[str]] = None) -> None:
    """Remember which rules this server session was shown: aegis_report_outcome credits only those."""
    from aegis_core import credit
    from aegis_core.storage import ledger_site

    names = [item.get("name") for key in ("relevant_rules", "invariant_warnings")
             for item in (res.get(key) or []) if isinstance(item, dict)]
    rule_ids = [n for n in names if isinstance(n, str)]
    host = str(args.get("_host") or "")
    session = str(args.get("_session") or "")
    try:
        persist = bool(session) and (not args.get("_binding") or ledger_site(workspace.root, create=False).shared)
    except Exception as exc:  # telemetry only: never fail the scan
        credit.record_exposure(workspace.root, host, session, rule_ids, paths=files, persist=False)
        print(f"aegis-mcp: exposure record not written: {exc}", file=sys.stderr)
        return
    try:
        credit.record_exposure(workspace.root, host, session, rule_ids, paths=files, persist=persist)
    except Exception as exc:  # telemetry only: never fail the scan
        print(f"aegis-mcp: exposure record not written: {exc}", file=sys.stderr)


def _scan_user_layer(args: dict) -> dict:
    """Nothing governs this call (H8): the read-only user layer, never a ledger write."""
    files = args.get("files")
    if files is not None and (not isinstance(files, (list, tuple)) or not all(isinstance(f, str) for f in files)):
        return {"error": "'files' must be a list of file paths", "status": _STATUS_FAIL}
    res = scan_user_layer(list(files) if files else None)
    if res.get("status") == _STATUS_FAIL:
        return res
    res = {"status": "not_governed", "message": NOT_GOVERNED_MESSAGE, "reason": args.get("_unbound"), **res}
    return render_scan_result(res, _slot_profile(args.get("_host")), None)


def handle_scan(args: dict) -> dict:
    """Express the JIT rules for the given files (or the git diff when none are given)."""
    from aegis_core import gitsafe

    # Its own scope: recording the scan and its exposures asks where the ledger is after scan() returns.
    with gitsafe.memo():
        return _handle_scan(args)


def _handle_scan(args: dict) -> dict:
    if args.get("_unbound"):
        return _scan_user_layer(args)
    try:
        workspace = _get_workspace(args)
    except ValueError as exc:
        return {"error": str(exc), "status": _STATUS_FAIL}
    files = args.get("files")
    if files is not None:
        if not isinstance(files, (list, tuple)) or not all(isinstance(f, str) for f in files):
            return {"error": "'files' must be a list of file paths", "status": _STATUS_FAIL}
        try:  # [] means "none given" here as in scan(): the git diff, recorded as such
            files = [str(workspace.confine_path(f)[1]) for f in files] or None
        except ValueError as exc:
            return {"error": str(exc), "status": _STATUS_FAIL}

    res = scan(workspace, changed_files=files)
    if res.get("status") == _STATUS_FAIL:
        return res
    _record_scan(workspace, args, files)
    _record_exposure(workspace, args, res, files)
    return render_scan_result(res, _slot_profile(args.get("_host")), workspace)
