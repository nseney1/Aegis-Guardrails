#!/usr/bin/env python3
"""Hand off one or more endpoints to a new session with one command.

One front door can hold an endpoint in several mailbox roots, and rotating them by
hand took a checkpoint per root. This drafts each checkpoint from the record and
binds it. A stop preflight refusal exits 2 before any entry writes. After that,
entries are processed independently: each rechecks stop evidence under its mailbox
writer lock. Evidence that changes after preflight refuses that entry with "stop
evidence changed during handoff" and exits 3, retaining earlier successful bindings
and processing the remaining entries. Running the same spec again leaves finished
entries alone and retries the others once their stop evidence is ready.

For launcher-managed bindings, every entry's stop record, wake marker and session
process census are checked before any entry is processed. A non-refused launcher
record manages the matching endpoint, session and generation; a generation-less
record can cover generation 1 only. The latest such record must be a successful
stop after the latest start or resume, if any. Stop-only histories have a null
launch reference, and already-bound re-runs have null stop evidence. Other sessions
retain the caller's outgoing_stopped assertion. Binding grants no sender authority:
each successor must still read its checkpoint and acknowledge it through its own
connection, so acknowledgments are not batched here.

Background-mode wake profiles also use the caller's assertion, because launcher
stop refuses them, but still require no wake marker and no live session process.
Other launch histories at the launcher's record cap require owner archive/recovery
before handoff; the maintenance runbook has no archive procedure yet.

A mailbox root beside a team run's host plan binds only a successor on the host
the plan assigns, and refuses the entry when the plan is not that root's own. The
successor's session record comes from the add-role that builds its connection and
profile. Roots without a host plan keep today's unchecked host choice.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (Mailbox, cli_path, fields, parse_time, read_bytes, read_json, require,  # noqa: E402
                               safe_path, strict_json, text, writer_lock)
import hierarchy_hosts  # noqa: E402
import hierarchy_launcher  # noqa: E402
import hierarchy_roles  # noqa: E402


SPEC_SCHEMA = "aegis.hierarchy-handoff/v1"
MAX_ENTRIES = 256


def acknowledgment(binding):
    if binding["generation"] < 2:
        return None
    return {"endpoint": binding["endpoint"], "session": binding["session"], "generation": binding["generation"],
            "checkpoint_sha256": binding["checkpoint_sha256"]}


def host_plan(root):
    """The host plan this root's handoffs answer to, or None when its base has none."""
    base = root.parent
    path = base / hierarchy_hosts.PLAN_FILE
    if not path.exists() and not path.is_symlink():
        return None
    record = base / "provision.json"
    setup = read_json(record) if record.is_file() else None
    mailbox_root = setup.get("mailbox_root") if isinstance(setup, dict) else None
    # A plan sits here, so it is never ignored: either the base's provision speaks for this root, or the entry is
    # refused. samefile, because two spellings of one folder must not count as two mailboxes.
    require(isinstance(mailbox_root, str) and os.path.isdir(mailbox_root) and os.path.samefile(mailbox_root, root),
            "host plan %s does not cover mailbox %s: its base's provision.json does not name that mailbox" % (path, root))
    return hierarchy_hosts.base_plan(base, setup.get("initiative"))


def check_successor(plan, mailbox, endpoint, spec):
    """Before binding, so a refusal leaves the entry unbound."""
    kind = mailbox.endpoint(endpoint).get("kind")
    hierarchy_hosts.require_binding(plan, endpoint, spec["host"],
                                    hierarchy_roles.writer(hierarchy_roles.role(endpoint, kind)))


def check_successor_record(base, endpoint, generation, spec):
    """A record already on file for the generation this handoff binds must be this successor's, or add-role would later
    find the binding and its record disagreeing."""
    path = hierarchy_hosts.session_record_path(base, endpoint, generation)
    if not path.exists() and not path.is_symlink():
        return
    found = read_json(path)
    require(isinstance(found, dict) and found.get("session") == spec["session"] and found.get("host_kind") == spec["host"],
            "session record for %s generation %d belongs to another session or host" % (endpoint, generation))


def stop_evidence(mailbox, current):
    # Pin absence as well as presence across every early return and the final census. The endpoint
    # fence held by hand_off excludes start; this descriptor also detects unrelated namespace changes.
    try:
        if hierarchy_launcher.launch_descriptor_capable():
            with hierarchy_launcher.launch_directory(mailbox.root.parent, current["endpoint"]):
                require(hierarchy_launcher.read_running_wake(mailbox.root.parent, current["endpoint"]) is None,
                        "a recorded wake is pending; run stop before handoff")
                return pinned_stop_evidence(mailbox, current)
        return pinned_stop_evidence(mailbox, current)  # Portable legacy absence keeps its existing contract.
    except (ValueError, OSError) as exc:
        if str(exc).startswith("stop evidence for " + current["endpoint"] + ":"):
            raise
        raise ValueError("stop evidence for %s: %s" % (current["endpoint"], exc)) from exc


def launch_stop_evidence(records, admissions):
    """Select terminal evidence from validated, ordered launch records."""
    # The launcher orders its immutable records by their timestamp-prefixed filenames, including status().
    status_path, status, status_hash = records[-1]
    require(status.get("action") == "stop" and status.get("state") in ("stopped", "not_running"),
            "latest launch status is %s (%s); a stopped or not_running stop record is required"
            % (status.get("state"), status.get("action")))
    activities = [row for row in records if row[1].get("action") in ("start", "resume")]
    launch_path, launch_hash = None, None
    if activities:
        launch_path, launch, launch_hash = activities[-1]
        admission = admissions.get(launch_path)
        activity_at = admission["at"] if admission is not None else launch.get("at")
        require(status_path > launch_path and parse_time(status.get("at")) > parse_time(activity_at),
                "stop record must be recorded after the latest start or resume")
    return {"launch": str(launch_path) if launch_path is not None else None, "launch_sha256": launch_hash,
                "status": str(status_path), "status_sha256": status_hash, "state": status["state"]}


def pinned_stop_evidence(mailbox, current):
    """Read the launcher's records and matching processes; never stop or reconcile anything here."""
    base, endpoint = mailbox.root.parent, current["endpoint"]
    command = shlex.join(["hierarchy_launcher.py", "--base", str(base), "stop", "--endpoint", endpoint])
    guidance = "obtain evidence with: " + command
    try:
        guidance = "retry after resolving stop custody"
        hierarchy_launcher.require_resolved_custody(str(base), endpoint)
        profile = base / "profiles" / ("%s-g%d.wake.json" % (hierarchy_launcher.quoted(endpoint), current["generation"]))
        guidance = "inspect %s; %s will not change this wake profile; correct the profile and retry" % (profile, command)
        # Same path and predicate as hierarchy_launcher.bound_session()/stop(); no exported predicate exists.
        background = profile.is_file() and read_json(profile).get("mode") == "background"
        evidence = "caller_asserted"
        if background:
            guidance = ("%s refuses background sessions; stop the background session through claude stop or the "
                        "wake tool's control and retry after it has ended" % command)
        else:
            guidance = "obtain evidence with: " + command
            folder = safe_path(base / "launches" / hierarchy_launcher.quoted(endpoint))
            if not folder.exists():
                return evidence
            guidance = ("inspect %s mailbox_root and %s; %s will not change this setup; "
                        "correct the mailbox association and retry" % (base / "provision.json", mailbox.root, command))
            launches = hierarchy_launcher.Launches(str(base))
            require(os.path.samefile(launches.mailbox.root, mailbox.root),
                    "launch records do not cover this mailbox")
            limit = hierarchy_launcher.MAX_RECORDS
            try:
                paths = launches.paths(endpoint)
            except hierarchy_launcher.LaunchRecordLimit as exc:
                paths, count = [], exc.count
            else:
                count = len(paths)
            guidance = ("inspect %s; %s cannot append a stop record at this limit; "
                        "docs/hierarchy-maintenance-runbook.md has no launch-record archive procedure yet; "
                        "owner must preserve the history and arrange an archive/recovery procedure before retrying"
                        % (folder, command))
            require(count < limit, "launch record limit %d reached (%d records)" % (limit, count))
            records, admissions = [], {}
            for path in paths:
                guidance = ("inspect %s and its retained evidence; %s will not change this record; "
                            "owner must reconcile the invalid data before retrying" % (path, command))
                # Hash the exact bytes parsed, so the evidence cannot describe a different read of the file.
                try:
                    raw = hierarchy_launcher.read_launch_record(base, endpoint, path.name)
                    record = hierarchy_launcher.metadata_json(raw, "launch record")
                except (ValueError, OSError, UnicodeError, RecursionError) as exc:
                    raise ValueError("invalid launch record: %s; error: %s" % (path, exc)) from exc
                require(isinstance(record, dict) and record.get("schema") == hierarchy_launcher.SCHEMA,
                        "invalid launch record: " + str(path))
                generation = record.get("generation")
                wake = record.get("wake")
                admission = (hierarchy_launcher.read_resume_admission(base, endpoint, path.stem)
                             if record.get("action") == "resume" else None)
                if admission is not None:
                    require(admission["binding"] == {key: record.get(key) for key in ("host", "session", "generation")},
                            "resume admission belongs to another binding")
                    admissions[path] = admission
                no_admission = ((record.get("admission_attempted") is False or "admission_attempted" not in record) and
                                (admission is None or admission["admission_attempted"] is False) and
                                (record.get("dry_run") is True or isinstance(wake, dict) and
                                 wake.get("state") in ("nothing_unread", "dry_run")))
                admitted_resume = (record.get("action") == "resume" and not no_admission and
                                   (admission is not None or "admission_attempted" in record or "wake_exit_code" in record))
                if ((record.get("state") != "refused" or admitted_resume)
                        and all(record.get(key) == current[key] for key in ("endpoint", "session"))
                        and (generation == current["generation"] or generation is None and current["generation"] == 1)):
                    records.append((path, record, hashlib.sha256(raw).hexdigest()))
            if not records:
                return evidence
            guidance = "obtain evidence with: " + command
            evidence = launch_stop_evidence(records, admissions)
        marker = mailbox.wake_marker(endpoint)
        if marker.exists() or marker.is_symlink():
            if background:
                guidance = ("inspect %s; %s refuses background sessions; stop the background session through "
                            "claude stop or the wake tool's control; once it has ended, remove the marker and retry"
                            % (marker, command))
            else:
                guidance = "inspect %s; once %s reports not_running, remove the marker and retry" % (marker, command)
            raise ValueError("wake marker is held: " + str(marker))
        # Unlike stop(), we signal nothing, so exclude no ancestors that could still be the outgoing writer.
        try:
            found = hierarchy_launcher.session_processes(current["session"], set())
        except (ValueError, OSError, hierarchy_launcher.CensusUnavailable, subprocess.SubprocessError) as exc:
            ambiguous = sorted(pid for pid, row in getattr(exc, "unresolved_pids", {}).items()
                               if row["reason"] == "host_grammar_unavailable")
            guidance = ("stop this process manually after verifying its identity: %s; then retry" %
                        ", ".join(map(str, ambiguous)) if ambiguous else
                        command + " cannot fix it; repair the process census and retry")
            raise ValueError("process census failed; error: " + str(exc)) from exc
        require(not found, "live process remains for session %s: %s"
                % (current["session"], ", ".join(str(pid) for pid, _ in found)))
        return evidence
    except (ValueError, OSError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError,
            subprocess.SubprocessError) as exc:
        raise ValueError("stop evidence for %s: %s; %s" % (endpoint, exc, guidance)) from exc


def preflight_stops(spec):
    """A missing launcher stop refuses the whole spec before locks, drafts or bindings are written."""
    for entry in spec["entries"]:
        if not isinstance(entry, dict) or not {"root", "endpoint"} <= entry.keys():
            continue
        try:
            root = safe_path(text(entry["root"], "root"))
            mailbox = Mailbox(root)
            history = mailbox.bindings(entry["endpoint"])
        except (ValueError, OSError, TypeError, UnicodeError, RecursionError):
            # Invalid entries still get their existing per-entry errors; they cannot bind a replacement.
            continue
        if history:
            current = history[-1]
            if current["host"] != spec["host"] or current["session"] != spec["session"]:
                stop_evidence(mailbox, current)
            else:
                # Idempotent reruns must not bypass unresolved custody either.
                hierarchy_launcher.require_resolved_custody(str(root.parent), entry["endpoint"])


def hand_off(spec, entry):
    fields(entry, {"root", "endpoint"}, {"completed_checks", "briefs", "evidence_dir", "delivery_dir", "kind"})
    root = safe_path(text(entry["root"], "root"))
    plan = host_plan(root)
    with ExitStack() as locks:
        root_fence = (locks.enter_context(hierarchy_launcher.directory_fence(root))
                      if hierarchy_launcher.launch_descriptor_capable() else None)
        locks.enter_context(writer_lock(root))
        if root_fence is not None:
            root_fence.check()
        mailbox = Mailbox(root)
        mailbox.endpoint(entry["endpoint"])
        if "kind" in entry:
            mailbox.require_kind(entry["endpoint"], entry["kind"])
        history = mailbox.bindings(entry["endpoint"])
        require(bool(history), "endpoint has no binding to replace: " + entry["endpoint"])
        # Legacy host labels cannot be stopped by the launcher and require no POSIX stop provider.
        # Once either side is a launcher host, binding selection/checks/publication share its endpoint lock.
        launcher_host = history[-1]["host"] in hierarchy_hosts.TEAM_HOSTS or spec["host"] in hierarchy_hosts.TEAM_HOSTS
        managed = os.path.lexists(root.parent / "launches" / hierarchy_launcher.quoted(entry["endpoint"]))
        fence = None
        if launcher_host and (hierarchy_launcher.os.name != "nt" or managed):
            fence = locks.enter_context(hierarchy_launcher.stop_endpoint_lock(root, entry["endpoint"]))
            history = mailbox.bindings(entry["endpoint"])
            require(bool(history), "endpoint has no binding to replace: " + entry["endpoint"])
        current = history[-1]
        # A re-run is checked too, so it reports a binding the plan does not allow even if an unchecked path made it.
        if plan is not None:
            check_successor(plan, mailbox, entry["endpoint"], spec)
        if current["host"] == spec["host"] and current["session"] == spec["session"]:
            hierarchy_launcher.require_resolved_custody(str(root.parent), entry["endpoint"])
            return {"already_bound": True, "generation": current["generation"], "ready": mailbox.ready(current),
                    "checkpoint_sha256": current["checkpoint_sha256"], "acknowledge": acknowledgment(current),
                    "stop_evidence": None}
        # Recheck under the bind/wake writer lock as well as in the whole-spec preflight.
        try:
            if launcher_host and hierarchy_launcher.launch_descriptor_capable():
                require(not hierarchy_launcher.mailbox_wake_pending(mailbox, entry["endpoint"]),
                        hierarchy_launcher.MAILBOX_WAKE_PENDING)
            evidence = stop_evidence(mailbox, current)
        except ValueError as exc:
            raise ValueError("stop evidence changed during handoff: " + str(exc)) from exc
        if plan is not None:
            # host_plan has shown the base's provision names this root, so its records sit beside it.
            check_successor_record(root.parent, entry["endpoint"], current["generation"] + 1, spec)
        optional = {key: entry[key] for key in ("completed_checks", "briefs", "evidence_dir", "delivery_dir")
                    if key in entry}
        if root_fence is not None:
            root_fence.check()
        if fence is not None:
            fence.check()
        draft = mailbox.draft_handoff({
            "endpoint": entry["endpoint"], "host": spec["host"], "session": spec["session"],
            "outgoing_stopped": spec["outgoing_stopped"], **optional})
        if root_fence is not None:
            root_fence.check()
        if fence is not None:
            fence.check()
        binding = mailbox.bind(draft)
    return {"generation": binding["generation"], "ready": binding["ready"],
            "checkpoint_sha256": binding["checkpoint_sha256"], "acknowledge": acknowledgment(binding),
            "stop_evidence": evidence}


def run(path):
    spec = read_json(path)
    fields(spec, {"schema", "host", "session", "outgoing_stopped", "entries"})
    require(spec["schema"] == SPEC_SCHEMA, "unsupported handoff spec schema")
    require(spec["outgoing_stopped"] is True, "outgoing session must be stopped before replacement")
    text(spec["host"], "host", 128)
    text(spec["session"], "session", 256)
    require(isinstance(spec["entries"], list) and 0 < len(spec["entries"]) <= MAX_ENTRIES,
            "handoff spec requires entries")
    preflight_stops(spec)
    rows = []
    for entry in spec["entries"]:
        labels = {key: entry.get(key) for key in ("root", "endpoint")} if isinstance(entry, dict) else {}
        try:
            rows.append({**labels, "ok": True, **hand_off(spec, entry)})
        except (ValueError, OSError, TypeError, UnicodeError, RecursionError) as exc:
            rows.append({**labels, "ok": False, "error": str(exc)})
    return {"schema": "aegis.hierarchy-handoff-result/v1", "host": spec["host"], "session": spec["session"],
            "ok": all(row["ok"] for row in rows), "entries": rows,
            "next": "Each successor must read its checkpoint and acknowledge it through its own connection."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spec", required=True, help="Absolute path to a strict JSON handoff spec")
    args = parser.parse_args(argv)
    try:
        result = run(cli_path(args.spec, "--spec"))
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 3


if __name__ == "__main__":
    sys.exit(main())
