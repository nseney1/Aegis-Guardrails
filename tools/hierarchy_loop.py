#!/usr/bin/env python3
"""Route approved requests, wake sessions with pending mail and run open jobs, on a schedule.

This is the watch-supervisor role's service. Each pass starts four tools as child processes, in order:
`hierarchy_router.py status`, `hierarchy_router.py route` (only when a request is ready or delivered but
unrecorded, as the current router from the journal), `hierarchy_sweep.py --rounds 1 --durable`, and
`hierarchy_jobs.py run-open`. Each tool keeps its own checks; the loop writes no mail, no journal event
and no approval, and never wakes ROOT. A step that fails is a hold, and the pass goes on.

Children get their own session, no stdin and no outer timeout: a step may hold a mailbox or journal
`.write.lock`, which only its own exit removes, so neither a signal to the loop nor a timeout may cut one
short. SIGTERM and SIGINT stop the loop between steps.

One loop runs per journal and per store: it holds a non-blocking flock on `<lifecycle>.loop.lock` and
`<store>.loop.lock` for its life, retrying for about a second so a `status` probe's brief shared lock does
not refuse a starting loop. Lock paths that are symlinks or not regular files are refused. The journal
directory is not used, because `hierarchy_operator` flocks it.

`<state-dir>/status.json` records the last pass and its holds, grouped by who must act; it is informational
and nothing reads it as authority. Each step start rewrites it with `current_step` and `step_started_at`, so
`status` reads a long step as running, not stale. A failed write is reported as `status_write_error` and the
loop carries its counts in memory; a file of the wrong shape restarts the counts with an owner
`status_reset` hold. Only a journal that router status could not read counts toward the owner's
`journal_lock` hold (3 passes in a row); a broken store is `store_unavailable` and anything else
`router_status_error`, both for ROOT. It never removes a lock.

An endpoint whose sweep row is `failed_to_start` in 3 passes in a row (for example a start whose receipt
could not be written, which the durable sweep's own cap cannot count) gets an owner `start_failing` hold,
and later passes give the sweep `--skip <endpoint>`. The skip lasts as long as that hold is in status.json:
the owner clears it by deleting `<state-dir>/status.json` once the cause is fixed.

The sweep's `silent_roles` (a role that read work it owes an answer to and published nothing) and
`stalled_dispatches` (a lane that accepted a dispatch and has nothing that will wake it) become ROOT
`silent_role` and `stalled_dispatch` holds. The sweep recomputes both from mailbox files every pass: a publication
after an owed read clears silence, and a result clears its dispatch. A running turn suspends the reports; later
receipt-only wakes do not erase unanswered work.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from hierarchy_jobs import NEEDS_ROOT  # noqa: E402
from hierarchy_mailbox import cli_path, parse_time, timestamp  # noqa: E402


SCHEMA = "aegis.loop-status/v1"
TOOLS = {"router": HERE / "hierarchy_router.py", "sweep": HERE / "hierarchy_sweep.py", "jobs": HERE / "hierarchy_jobs.py"}
LOCK_SUFFIX = ".loop.lock"
DEFAULT_INTERVAL = 30
INTERVAL_RANGE = (5, 600)
JOURNAL_LOCK_PASSES = 3
START_FAILING_PASSES = 3
LOCK_RETRY_SECONDS = 1.0
STALE_FACTOR = 3
DETAIL_LIMIT = 512
ROUTE_STATES = {"ready", "delivered_unrecorded"}
# Who must act on each sweep row that is not a completed wake. Only ROOT rotates or messages a session; a
# held marker, a session that will not start or an unreadable mailbox needs the owner. Others default to ROOT.
SWEEP_ACT = {"wake_marker_held": "owner", "start_failed": "owner", "start_backoff": "owner", "meter_error": "owner",
             "mailbox_error": "owner"}
ERRORS = (ValueError, OSError, UnicodeError)
HOLD_FIELDS = {"step": str, "kind": str, "act": str, "detail": str, "first_seen": str, "last_seen": str, "count": int}


class Stop:
    requested = False


def request_stop(_signum, _frame):
    Stop.requested = True


def refuse(message):
    raise ValueError(message)


def lock_path(path):
    return Path(str(path) + LOCK_SUFFIX)


def open_lock(path, flags):
    """The lock file itself, never what a symlink names: cli_path refuses symlinks in the guarded paths, and a
    linked lock could make two journals share one lock or create a file anywhere. O_NONBLOCK keeps a planted
    FIFO from blocking the open before the regular-file check refuses it."""
    try:
        descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            refuse("loop lock must not be a symlink: " + str(path))
        raise
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        refuse("loop lock is not a regular file: " + str(path))
    return descriptor


def hold_instance(lifecycle, store):
    """Both flocks or a refusal. The descriptors stay open, so the locks last as long as the process."""
    held = []
    try:
        for guarded in (lifecycle, store):
            descriptor = open_lock(lock_path(guarded), os.O_RDWR | os.O_CREAT)
            held.append(descriptor)
            deadline = time.monotonic() + LOCK_RETRY_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    # A status probe holds a shared lock for an instant; a running loop holds it for its life.
                    # Retrying briefly tells them apart, so a restart next to a polling monitor still starts.
                    if time.monotonic() >= deadline:
                        refuse("loop already active for " + str(guarded))
                    time.sleep(0.05)
    except BaseException:
        for descriptor in held:
            os.close(descriptor)
        raise
    return held


def instance_running(lifecycle):
    """Whether a loop holds this journal's lock. The probe is shared and momentary, so it never blocks a
    holder, and a loop starting in the same instant retries past it."""
    try:
        descriptor = open_lock(lock_path(lifecycle), os.O_RDONLY)
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(descriptor)
    return False


def detail(value):
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return text[:DETAIL_LIMIT]


def _object(value, path):
    if type(value) is not dict:
        refuse(path + " must be an object")
    return value


def _field(row, key, kind, path="", *, optional=False, nullable=False):
    name = path + "." + key if path else key
    if optional and key not in row:
        return None
    if key not in row:
        refuse(name + " is required")
    value = row[key]
    if nullable and value is None:
        return None
    if type(value) is not kind or (kind is str and not value) or (kind is int and value < 0):
        refuse(name + " must be " + kind.__name__)
    return value


def _rows(result, key, *, optional=False):
    values = _field(result, key, list, optional=optional)
    for number, row in enumerate(values or []):
        path = "%s[%d]" % (key, number)
        yield _object(row, path), path


def _request_rows(result):
    for row, path in _rows(result, "requests"):
        _field(row, "request_id", str, path)
        state = _field(row, "state", str, path)
        if state not in {"ready", "held", "delivered_unrecorded", "routed", "closed", "awaiting_decision",
                         "denied", "delegation"}:
            refuse(path + ".state is unknown")
        for key in ("reason", "detail", "to"):
            _field(row, key, str, path, optional=True)
        _field(row, "revoked_after_route", bool, path, optional=True)


def _decode_router_status(result):
    _field(result, "router", str)
    _request_rows(result)
    if "small_changes" in result or "planning_exclusions" in result:
        _decode_dispatch(result, status=True)
    for row, path in _rows(result, "escalations", optional=True):
        for key in ("request_id", "reason", "team"):
            _field(row, key, str, path)
        decision = _field(row, "root_decision", str, path, optional=True, nullable=True)
        if decision not in (None, "approve", "deny"):
            refuse(path + ".root_decision is unknown")


def _decode_dispatch(result, status=False):
    if not status:
        if _field(result, "schema", str) != "aegis.small-change-dispatch-run/v1":
            refuse("unknown small-change dispatch schema")
        if _field(result, "execution_enabled", bool) is not False or _field(result, "authenticated", bool) is not False:
            refuse("dispatch must remain configured evidence-only")
    for row, path in _rows(result, "small_changes"):
        for name in ("request_id", "request_sha256", "team", "plan_sha256", "writer", "state"):
            _field(row, name, str, path)
        from hierarchy_small_change_dispatch import STATES
        if row["state"] not in STATES:
            refuse(path + ".state is unknown")
        for name in ("reason", "detail"):
            _field(row, name, str, path, optional=True)
        _field(row, "retained_replies", list, path)
    values = _field(result, "planning_exclusions", list)
    if not all(type(value) is str for value in values):
        refuse("planning_exclusions must list endpoints")


def _decode_route(result):
    for row, path in _rows(result, "routed"):
        _field(row, "request_id", str, path)
    if "requests" in result and result["requests"] is None:
        _field(result, "report_error", str)
        held = _field(result, "held", dict)
        for key, value in held.items():
            if type(key) is not str or not key:
                refuse("held request id must be str")
            path = "held." + key
            _field(_object(value, path), "reason", str, path)
            _field(value, "detail", str, path, optional=True)
    else:
        _request_rows(result)


def _sweep_row(row, path):
    state = _field(row, "state", str, path)
    _field(row, "initiative", str, path)
    _field(row, "endpoint", str, path, optional=state == "mailbox_error" and "wake_exit" not in row)
    wake_exit = _field(row, "wake_exit", int, path, optional=True)
    if wake_exit is not None:
        expected = {"read": 0, "nothing_unread": 0, "dry_run": 0, "failed_to_start": 3,
                    "stop_unconfirmed": 3, "needs_owner": 3, "timed_out": 3, "woken_unread": 3}
        if state not in expected:
            refuse(path + ".state is unknown for a wake result")
        if wake_exit != expected[state]:
            refuse(path + ".wake_exit disagrees with state")
    _field(row, "error", str, path, optional=True)


def _decode_sweep(result):
    for row, path in _rows(result, "rows"):
        _sweep_row(row, path)
    for key in ("still_unread", "root_queue"):
        for row, path in _rows(result, key):
            _field(row, "initiative", str, path)
            _field(row, "endpoint", str, path)
            _field(row, "unread_count", int, path)
            if key == "root_queue":
                _field(row, "open_jobs", int, path)
    for key in ("silent_roles", "stalled_dispatches"):
        for row, path in _rows(result, key, optional=True):
            for name in ("initiative", "endpoint", "wake_id", "finished_at"):
                _field(row, name, str, path, nullable=key == "stalled_dispatches" and name in {"wake_id", "finished_at"})
            if key == "silent_roles":
                for name in ("ended", "silent_since"):
                    _field(row, name, str, path)
                if row["ended"] not in {"exited", "timed_out"}:
                    refuse(path + ".ended is unknown")
                # A negative exit denotes a signal; unlike counts it is a valid integer here.
                if "exit_code" not in row or (row["exit_code"] is not None and type(row["exit_code"]) is not int):
                    refuse(path + ".exit_code must be int or null")
                child_key, fields = "read", ("type", "message_id", "from")
            else:
                child_key, fields = "dispatches", ("dispatch", "accepted_at")
            for child, child_path in _rows(row, child_key):
                for name in fields:
                    _field(child, name, str, path + "." + child_path)
    for row, path in _rows(result, "root_time"):
        state = _field(row, "state", str, path)
        if state not in {"no_transcript", "rotate_now", "rotate_soon", "ok", "meter_error"}:
            refuse(path + ".state is unknown")


def _job_row(row, path):
    state = _field(row, "state", str, path)
    if state not in NEEDS_ROOT | {"completed", "failed", "refused"}:
        refuse(path + ".state is unknown")
    _field(row, "job", str, path, optional=state in {"mailbox_error", "granted_elsewhere"})
    _field(row, "error", str, path, optional=True)


def _decode_jobs(result):
    for row, path in _rows(result, "rows"):
        _job_row(row, path)


def _child_diagnostics(tool, result):
    """Validated identities for inspection only, never evidence of no effect or permission to retry."""
    key = "routed" if tool == "router" else "rows"
    rows = result.get(key)
    if type(rows) is not list:
        return {}
    valid = []
    for number, row in enumerate(rows):
        path = "%s[%d]" % (key, number)
        try:
            _object(row, path)
            if tool == "router":
                _field(row, "request_id", str, path)
                fields = ("request_id",)
            elif tool == "jobs":
                _job_row(row, path)
                fields = ("job", "state")
            else:
                _sweep_row(row, path)
                fields = ("initiative", "endpoint", "state", "wake_exit")
        except ValueError:
            continue
        valid.append({name: row[name] for name in fields if name in row})
    return {key: valid}


def run_child(tool, args, decoder):
    """Exit, validated result, stderr tail and a contract failure (if any)."""
    child_env = {key: value for key, value in os.environ.items()
                 if key not in {"CLAUDECODE", "CLAUDE_PID"} and not key.startswith("CLAUDE_CODE_")}
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOLS[tool]), *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, start_new_session=True, env=child_env)
    lines = proc.stdout.strip().splitlines()
    try:
        parsed = json.loads(lines[-1]) if lines else None
    except (ValueError, RecursionError):
        parsed = None
    problem = None
    if type(parsed) is dict and proc.returncode in (0, 2, 3):
        try:
            if proc.returncode == 2:
                _field(parsed, "error", str)
                _field(parsed, "source", str, optional=True)
            else:
                decoder(parsed)
        except ValueError as exc:
            problem = {"error": str(exc), "diagnostics": _child_diagnostics(tool, parsed)}
            parsed = None
    return proc.returncode, parsed if type(parsed) is dict else None, proc.stderr.strip()[-DETAIL_LIMIT:], problem


def silent_detail(row):
    read = ", ".join("%s %s from %s" % (item["type"], item["message_id"], item["from"]) for item in row["read"])
    if row["ended"] == "timed_out":
        ended = "timed out"
    else:
        ended = "exited" if row["exit_code"] is None else "exited with code %s" % row["exit_code"]
    return "read %s in wake %s (%s at %s) and has published nothing since %s" % (
        read, row["wake_id"], ended, row["finished_at"], row["silent_since"])


def stalled_detail(row):
    accepted = ", ".join("dispatch %s at %s" % (item["dispatch"], item["accepted_at"]) for item in row["dispatches"])
    return ("accepted %s but sent no result or review; its last wake %s ended at %s and nothing is unread or running, "
            "so no wake will come" % (accepted, row["wake_id"], row["finished_at"]))


def child_failure(step, code, stderr, problem=None):
    """A hold for an exit the tool does not define: a crash, a kill, or output that is not its JSON."""
    if problem is not None:
        why = "malformed child result: " + problem["error"] + ("; stderr: " + stderr if stderr else "")
    elif code < 0:
        why = "killed by signal %d" % -code
    else:
        why = "exit %d with no JSON result" % code + (": " + stderr if stderr else "")
    return {"step": step, "kind": "child_failed", "detail": detail(why), "act": "owner"}


def _failed_step(step, code, problem, **where):
    row = {"step": step, "state": "failed", "exit": code, **where}
    if problem is not None and problem["diagnostics"]:
        row["diagnostics"] = problem["diagnostics"]
    return row


class Pass:
    def __init__(self, args, earlier=None, skipped=None, beat=None):
        self.args = args
        self.steps, self.holds = [], []
        self.journal_unavailable = self.status_read = False
        self.planning_exclusions = set()
        self.small_changes = None
        # Holds of the previous pass by hold_key, endpoints under a start_failing hold, and the heartbeat writer.
        self.earlier, self.skipped = earlier or {}, skipped or {}
        self.beat = beat or (lambda step: None)

    def hold(self, step, kind, why, act, **where):
        self.holds.append({"step": step, "kind": kind, "detail": detail(why), "act": act,
                           **{key: value for key, value in where.items() if value is not None}})

    def common(self, tool):
        if tool == "router":
            return ["--lifecycle", str(self.args.lifecycle), "--store", str(self.args.store)]
        if tool == "sweep":
            return ["--store", str(self.args.store)]
        return ["--store", str(self.args.store), "--recipes", str(self.args.recipes)]

    def router_status(self):
        code, result, stderr, problem = run_child("router", self.common("router") + ["status", "--recipes", str(self.args.recipes)], _decode_router_status)
        if code == 0 and result is not None:
            self.status_read = True
            self.steps.append({"step": "router_status", "state": "ok", "exit": 0, "router": result.get("router")})
            return result
        if code == 2 and result is not None:
            # Only a journal that could not be read under its lock (busy past the wait, or malformed) counts
            # toward the owner's journal_lock hold; a store or argument refusal would send the owner to a lock
            # that is not held.
            source, error = result.get("source"), result.get("error", "")
            if source == "journal":
                self.journal_unavailable = True
                self.hold("router_status", "journal_unavailable", error, "root")
            elif source == "store":
                self.hold("router_status", "store_unavailable", error, "root")
            else:
                self.hold("router_status", "router_status_error", error, "root")
            self.steps.append({"step": "router_status", "state": "hold", "exit": 2, "source": source})
        else:
            self.holds.append(child_failure("router_status", code, stderr, problem))
            self.steps.append(_failed_step("router_status", code, problem))
        return None

    def route(self, status):
        rows = status["requests"] if status else []
        if not status or not any(row["state"] in ROUTE_STATES for row in rows):
            self.steps.append({"step": "route", "state": "skipped"})
            return rows if status else None
        actor = status["router"]
        code, result, stderr, problem = run_child(
            "router", self.common("router") + ["route", "--actor", actor, "--evidence-only"], _decode_route)
        if code == 0 and result is not None:
            self.steps.append({"step": "route", "state": "ok", "exit": 0, "actor": actor,
                               "routed": [row["request_id"] for row in result["routed"]]})
            if result.get("requests") is None:
                # The routes are recorded; only the closing report was lost, so the held rows come from it.
                self.hold("route", "route_report_error", result.get("report_error", ""), "router")
                for key, why in sorted(result.get("held", {}).items()):
                    self.hold("route", "request_held", why, "router", request_id=key)
                return []
            return result["requests"]
        if code == 2 and result is not None:
            self.hold("route", "route_refused", result.get("error", ""), "router")
            self.steps.append({"step": "route", "state": "hold", "exit": 2, "actor": actor})
        else:
            self.holds.append(child_failure("route", code, stderr, problem))
            self.steps.append(_failed_step("route", code, problem, actor=actor))
        return rows

    def request_holds(self, rows, status):
        for row in rows or []:
            where = {"request_id": row["request_id"]}
            if row["state"] == "held":
                self.hold("route", "request_held", {k: row[k] for k in ("reason", "detail") if k in row}, "router", **where)
            elif row["state"] == "delivered_unrecorded":
                self.hold("route", "delivered_unrecorded", row.get("to", ""), "router", **where)
            elif row.get("revoked_after_route"):
                self.hold("route", "revoked_after_route", row.get("to", ""), "router", **where)
        for row in (status or {}).get("escalations", []):
            if row.get("root_decision") is None:
                self.hold("router_status", "escalation", {"reason": row["reason"], "team": row["team"]}, "root",
                          request_id=row["request_id"])

    def dispatch(self, status):
        # Canonical-only reports remain byte-compatible; the stage is an inert no-op there.
        if status is not None and "small_changes" not in status:
            return
        code, result, stderr, problem = run_child("router", self.common("router") + ["dispatch", "--recipes",
                    str(self.args.recipes), "--evidence-only"], _decode_dispatch)
        if code == 0 and result is not None:
            self.steps.append({"step": "dispatch", "state": "ok", "exit": 0})
            self.small_changes = result.get("small_changes", [])
        else:
            self.steps.append({"step": "dispatch", "state": "hold", "exit": code})
            self.hold("dispatch", "dispatch_error", (result or {}).get("error", stderr or problem), "owner")

    def refresh_planning(self):
        # Child reports can fail independently of durable evidence, including after publication.
        try:
            from hierarchy_router import preflight_paths
            from hierarchy_lifecycle import Lifecycle
            from hierarchy_workspace import Store
            from hierarchy_small_change_dispatch import project
            preflight_paths(self.args.lifecycle, self.args.store)
            result = project(Lifecycle(self.args.lifecycle), Store(self.args.store),
                             recipes=self.args.recipes, mutate=False)
            _decode_dispatch(_object(result, "planning projection"), status=True)
        except ERRORS + (RecursionError,) as exc:
            self.hold("dispatch", "planning_exclusions_unavailable", str(exc), "owner")
            return False
        self.planning_exclusions = set(result["planning_exclusions"])
        self.small_changes = result["small_changes"] or None
        for row in self.small_changes or []:
            if row["state"] == "held" or row.get("reason") == "small_change_close_due":
                kind = row.get("reason", "small_change_configuration")
                self.hold("dispatch", kind, row.get("detail", kind), "owner", request_id=row["request_id"], initiative=row["team"])
        return True

    def sweep(self):
        if not self.refresh_planning():
            self.steps.append({"step": "sweep", "state": "skipped"})
            return
        args = self.common("sweep") + ["--rounds", "1", "--durable"]
        for _initiative, endpoint in sorted(self.skipped):
            args += ["--skip", endpoint]
        for endpoint in sorted(self.planning_exclusions):
            args += ["--skip", endpoint]
        code, result, stderr, problem = run_child("sweep", args, _decode_sweep)
        if code not in (0, 2, 3) or result is None:
            self.holds.append(child_failure("sweep", code, stderr, problem))
            self.steps.append(_failed_step("sweep", code, problem))
            return
        if code == 2:
            self.hold("sweep", "sweep_error", result.get("error", ""), "root")
            self.steps.append({"step": "sweep", "state": "hold", "exit": 2})
            return
        before = len(self.holds)
        held = set()
        for row in result["rows"]:
            if row.get("wake_exit") == 0:
                continue
            where = {"initiative": row.get("initiative"), "endpoint": row.get("endpoint")}
            held.add((where["initiative"], where["endpoint"]))
            if row["state"] == "skipped":
                if row["endpoint"] in self.planning_exclusions:
                    self.hold("sweep", "small_change_planning_skipped", {"unread_count": row.get("unread_count", 0)},
                              "root", **where)
                # The start_failing hold that asked for the skip already says why.
                continue
            rest = {k: v for k, v in row.items() if k not in {"initiative", "endpoint", "state"}}
            self.hold("sweep", row["state"], rest, SWEEP_ACT.get(row["state"], "root"), **where)
            if row["state"] == "failed_to_start":
                self.start_failing(row, where)
        for row in result["still_unread"]:
            # A row above already says why this endpoint stayed unread.
            if (row["initiative"], row["endpoint"]) not in held:
                self.hold("sweep", "still_unread", {"unread_count": row["unread_count"]}, "root",
                          initiative=row["initiative"], endpoint=row["endpoint"])
        for row in result["root_queue"]:
            self.hold("sweep", "root_queue", {"unread_count": row["unread_count"], "open_jobs": row["open_jobs"]},
                      "root", initiative=row["initiative"], endpoint=row["endpoint"])
        # A sweep that predates these reports has none to give.
        for kind, key, describe in (("silent_role", "silent_roles", silent_detail),
                                    ("stalled_dispatch", "stalled_dispatches", stalled_detail)):
            for row in result.get(key, []):
                self.hold("sweep", kind, describe(row), "root", initiative=row["initiative"], endpoint=row["endpoint"])
        for row in result["root_time"]:
            if row["state"] == "rotate_now":
                self.hold("sweep", "root_rotate", row, "root")
            elif row["state"] == "meter_error":
                self.hold("sweep", "root_meter_error", row, "owner")
        self.steps.append({"step": "sweep", "state": "hold" if len(self.holds) > before else "ok", "exit": code,
                           "woken": [row["endpoint"] for row in result["rows"] if "wake_exit" in row]})

    def start_failing(self, row, where):
        """A start that fails before its receipt is written leaves nothing the durable sweep counts, so it would
        launch and abandon a session every pass. The loop counts the passes instead and stops asking."""
        prior = self.earlier.get(("sweep", "failed_to_start", where["initiative"], where["endpoint"]))
        passes = prior["count"] + 1 if prior else 1
        if passes >= START_FAILING_PASSES:
            self.hold("sweep", "start_failing", "%s failed to start in %d passes in a row; last error: %s; the loop "
                      "skips it until the owner deletes %s" % (where["endpoint"], passes, row.get("error", ""),
                                                               self.args.state_dir / "status.json"), "owner", **where)

    def keep_skips(self):
        """Carry each start_failing hold forward, whatever this pass did, so the skip lasts until the owner
        clears status.json; a skipped endpoint never fails again, so nothing else would raise it."""
        raised = {(row.get("initiative"), row.get("endpoint")) for row in self.holds if row["kind"] == "start_failing"}
        for (initiative, endpoint), row in sorted(self.skipped.items()):
            if (initiative, endpoint) not in raised:
                self.hold("sweep", "start_failing", row["detail"], "owner", initiative=initiative, endpoint=endpoint)

    def run_open(self):
        args = self.common("jobs") + ["run-open"]
        if self.args.max_jobs is not None:
            args += ["--max-jobs", str(self.args.max_jobs)]
        code, result, stderr, problem = run_child("jobs", args, _decode_jobs)
        if code not in (0, 2, 3) or result is None:
            self.holds.append(child_failure("run_open", code, stderr, problem))
            self.steps.append(_failed_step("run_open", code, problem))
            return
        if code == 2:
            self.hold("run_open", "jobs_error", result.get("error", ""), "root")
            self.steps.append({"step": "run_open", "state": "hold", "exit": 2})
            return
        before = len(self.holds)
        for row in result["rows"]:
            if row["state"] in NEEDS_ROOT:
                self.hold("run_open", "job_" + row["state"], {k: v for k, v in row.items() if k not in {"job", "state"}},
                          "root", job=row.get("job"))
        self.steps.append({"step": "run_open", "state": "hold" if len(self.holds) > before else "ok", "exit": code,
                           "rows": [{"job": row.get("job"), "state": row["state"]} for row in result["rows"]]})

    def run(self):
        """Steps in order; a stop request is honoured only between them."""
        status = rows = None
        for step in ("router_status", "route", "dispatch", "sweep", "run_open"):
            if Stop.requested:
                return True
            self.beat(step)
            if step == "router_status":
                status = self.router_status()
            elif step == "route":
                rows = self.route(status)
                self.request_holds(rows, status)
            elif step == "dispatch":
                self.dispatch(status)
            elif step == "sweep":
                self.sweep()
            else:
                self.run_open()
        return False


def hold_key(row):
    return (row["step"], row["kind"], row.get("initiative"),
            row.get("endpoint") or row.get("request_id") or row.get("job"))


def read_status(state_dir):
    path = state_dir / "status.json"
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        refuse("status file is not " + SCHEMA + ": " + str(path))
    checked(value, path)
    return value


def checked(value, path):
    """The fields a pass and status read, so a hand edit or another version's file is refused here instead of
    crashing the merge with a KeyError or TypeError."""
    def bad(field):
        refuse("status file has a bad %s: %s" % (field, path))
    for field in ("pass_id", "consecutive_journal_unavailable"):
        if type(value.get(field)) is not int or value[field] < 0:
            bad(field)
    if value.get("interval") is not None and type(value["interval"]) is not int:
        bad("interval")
    for field in ("finished_at", "step_started_at"):
        if value.get(field) is not None:
            try:
                parse_time(value[field])
            except ValueError:
                bad(field)
    if value.get("current_step") is not None and not isinstance(value["current_step"], str):
        bad("current_step")
    holds = value.get("holds")
    if not isinstance(holds, list):
        bad("holds")
    for row in holds:
        if not isinstance(row, dict) or any(type(row.get(key)) is not kind for key, kind in HOLD_FIELDS.items()) or \
                any(row.get(key) is not None and not isinstance(row[key], str)
                    for key in ("initiative", "endpoint", "request_id", "job")):
            bad("hold")


def write_status(state_dir, value):
    """Temp file, fsync, rename, fsync the folder: a reader sees the old pass or the new one, never half."""
    data = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(dir=state_dir, prefix=".status-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, state_dir / "status.json")
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    folder = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(folder)
    finally:
        os.close(folder)


def empty_status(interval):
    return {"schema": SCHEMA, "pass_id": 0, "started_at": None, "finished_at": None, "interval": interval, "steps": [],
            "holds": [], "stopped": False, "consecutive_journal_unavailable": 0}


def one_pass(args, interval, memory=None):
    """One pass and its report. Returns (exit code, stopped, the report, whether status.json took it)."""
    reset = None
    if memory is not None:
        # The last write failed, so the file on disk is older than what this process knows.
        previous = memory
    else:
        try:
            previous = read_status(args.state_dir) or {}
        except ERRORS as exc:
            # The file is only a report, so a damaged one restarts the counts instead of stopping the loop,
            # and the owner is told the history was lost.
            previous, reset = {}, str(exc)
    earlier = {hold_key(row): row for row in previous.get("holds", [])}
    skipped = {(row.get("initiative"), row["endpoint"]): row for row in previous.get("holds", [])
               if (row["step"], row["kind"]) == ("sweep", "start_failing") and row.get("endpoint")}
    base = {**(previous or empty_status(interval)), "interval": interval}

    def beat(step):
        # A heartbeat at each step start: a step may wait on a model turn for hours, and status must not
        # read that as a dead loop. A failed heartbeat is left to the end-of-pass write to report.
        try:
            write_status(args.state_dir, {**base, "current_step": step, "step_started_at": timestamp()})
        except OSError:
            pass

    started = timestamp()
    work = Pass(args, earlier, skipped, beat)
    if reset is not None:
        work.hold("loop", "status_reset", "previous status.json was unusable, so the counts restarted: " + reset, "owner")
    stopped = work.run()
    work.keep_skips()
    previous_count = previous.get("consecutive_journal_unavailable", 0)
    if work.journal_unavailable:
        unavailable = previous_count + 1
    else:
        # A store or argument refusal says nothing about the journal, so it neither counts nor clears.
        unavailable = 0 if work.status_read else previous_count
    if work.journal_unavailable and unavailable >= JOURNAL_LOCK_PASSES:
        work.hold("router_status", "journal_lock",
                  "journal %s unavailable for %d passes in a row; the loop never removes a lock, so the owner must "
                  "inspect %s" % (args.lifecycle, unavailable, args.lifecycle / ".write.lock"), "owner")
    finished = timestamp()
    holds = []
    for row in work.holds:
        seen = earlier.get(hold_key(row))
        holds.append({**row, "first_seen": seen["first_seen"] if seen else started, "last_seen": finished,
                      "count": seen["count"] + 1 if seen else 1})
    value = {"schema": SCHEMA, "pass_id": previous.get("pass_id", 0) + 1, "started_at": started, "finished_at": finished,
             "interval": interval, "steps": work.steps, "holds": holds, "stopped": stopped,
             "consecutive_journal_unavailable": unavailable, "current_step": None, "step_started_at": None}
    if work.small_changes is not None:
        value["small_changes"] = work.small_changes
    shown, wrote = value, True
    try:
        write_status(args.state_dir, value)
    except OSError as exc:
        # status.json is informational: losing it must not stop routing, wakes and jobs.
        shown, wrote = {**value, "status_write_error": str(exc)[:DETAIL_LIMIT]}, False
    print(json.dumps(shown, sort_keys=True), flush=True)
    return (3 if holds else 0), stopped, value, wrote


def serve(args):
    locks = hold_instance(args.lifecycle, args.store)
    try:
        args.state_dir.mkdir(parents=True, exist_ok=True)
        if args.command == "once":
            return one_pass(args, None)[0]
        code, done, memory = 0, 0, None
        while not Stop.requested:
            code, stopped, value, wrote = one_pass(args, args.interval, memory)
            memory = None if wrote else value
            done += 1
            if stopped or (args.passes is not None and done >= args.passes):
                break
            deadline = time.monotonic() + args.interval
            # Short sleeps, so a stop request ends the wait promptly instead of after the interval.
            while not Stop.requested and time.monotonic() < deadline:
                time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        return code
    finally:
        for descriptor in locks:
            os.close(descriptor)


def report(args):
    last = read_status(args.state_dir)
    beats = [parse_time(last[field]) for field in ("finished_at", "step_started_at") if last and last.get(field)]
    if not instance_running(args.lifecycle):
        state = "not_running"
    elif last is not None and last.get("current_step"):
        # A step has no outer timeout by design (it may hold a write lock only its exit removes), and the
        # instance lock shows the loop is alive, so a long step reads as running with its name and start.
        state = "running"
    elif last is not None and last.get("interval") and beats and datetime.now(timezone.utc) - max(beats) > \
            timedelta(seconds=STALE_FACTOR * last["interval"]):
        state = "stale"
    else:
        state = "running"
    result = {"schema": SCHEMA, "state": state, "last": last}
    if last is not None and last.get("current_step") and last.get("step_started_at"):
        # Running says only that the loop holds its lock; the age is what tells ROOT a step is stuck.
        age = datetime.now(timezone.utc) - parse_time(last["step_started_at"])
        result["step_age_seconds"] = max(0, int(age.total_seconds()))
    return (0 if state == "running" else 3), result


def as_text(result):
    last = result["last"]
    head = "loop: " + result["state"]
    if last is not None and last.get("finished_at"):
        head += " (pass %d, finished %s, interval %s)" % (last["pass_id"], last["finished_at"],
                                                         "%d s" % last["interval"] if last["interval"] else "once")
    if last is not None and last.get("current_step"):
        head += " step %s" % last["current_step"]
        if "step_age_seconds" in result:
            head += " running for %ds" % result["step_age_seconds"]
        head += " since %s" % last["step_started_at"]
    lines = [head]
    for act in ("root", "owner", "router"):
        rows = [row for row in (last or {}).get("holds", []) if row["act"] == act]
        if not rows:
            continue
        lines.append(act + ":")
        for row in rows:
            subject = row.get("endpoint") or row.get("request_id") or row.get("job") or ""
            lines.append("  %s %s %s: %s (seen %d times since %s)" % (row["step"], row["kind"], subject, row["detail"],
                                                                     row["count"], row["first_seen"]))
    return "\n".join(lines) + "\n"


def positive(value, flag):
    if value is not None and value < 1:
        refuse(flag + " must be a positive integer")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lifecycle", required=True, help="Absolute path to the lifecycle journal")
    parser.add_argument("--store", required=True, help="Absolute path to the workspace store")
    parser.add_argument("--recipes", required=True, help="Absolute path to root's recipe file")
    parser.add_argument("--state-dir", required=True, help="Absolute path to the folder for status.json")
    parser.add_argument("--max-jobs", type=int, help="Passed to run-open")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("once", help="Run one pass")
    runner = commands.add_parser("run", help="Run passes until SIGTERM or SIGINT, or until --passes are done")
    runner.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Seconds between passes, 5 to 600")
    runner.add_argument("--passes", type=int, help="Stop after this many passes")
    shown = commands.add_parser("status", help="Whether the loop runs, and its last pass")
    shown.add_argument("--text", action="store_true", help="Holds grouped by who must act")
    args = parser.parse_args(argv)
    try:
        for flag in ("lifecycle", "store", "recipes", "state_dir"):
            setattr(args, flag, cli_path(getattr(args, flag), "--" + flag.replace("_", "-")))
        positive(args.max_jobs, "--max-jobs")
        if args.command == "run":
            if not INTERVAL_RANGE[0] <= args.interval <= INTERVAL_RANGE[1]:
                refuse("--interval must be between %d and %d seconds" % INTERVAL_RANGE)
            positive(args.passes, "--passes")
        if args.command == "status":
            code, result = report(args)
            sys.stdout.write(as_text(result) if args.text else json.dumps(result, sort_keys=True) + "\n")
            return code
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        return serve(args)
    except ERRORS + (json.JSONDecodeError,) as exc:
        print(json.dumps({"error": str(exc)[:1024]}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
