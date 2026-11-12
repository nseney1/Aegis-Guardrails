"""Evidence-only small changes; D4/D5 activation and D7 early release remain unqualified.
Only publication borrows the ready Orchestrator; only route mutates the journal under its router.
Participant/coordinator events are never recorded here; state comes from existing public records.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from types import SimpleNamespace
from typing import NamedTuple

import hierarchy_fresh_brief as fresh
import hierarchy_jobs as jobs
import hierarchy_hosts
import hierarchy_lifecycle as life
import hierarchy_router as router
import hierarchy_workspace as workspace
from hierarchy_mailbox import (Mailbox, MAX_BYTES, MAX_RECORDS, SLUG, TERMINAL_JOB_STATES, digest, encoded, fields,
                               matching, parse_time, require, safe_path, strict_json, timestamp,
                               writer_lock)


SCHEMA = "aegis.small-change-dispatch/v1"
STATES = {"writer_ready", "writer_sent", "writing", "checking", "review_ready", "reviewing",
          "held", "complete", "owned_hold"}
TERMINAL_REF = re.compile(r"lifecycle-terminal:([0-9a-f]{64})\Z")
RESERVE_SECONDS = 30
MAX_GIT_BYTES = jobs.MAX_RESULT_BYTES
# Match the lifecycle/operator evidence ceiling; the job total is four such
# ceilings including metadata. JSON/packet metadata retain their smaller limits.
MAX_RETAINED_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RETAINED_JOB_BYTES = 256 * 1024 * 1024


def _git_read(checkout, environment, arguments, *, clean_status=False):
    """Drain both pipes incrementally; only this owned read-only Git child can be stopped."""
    process = subprocess.Popen(jobs.object_read_argv(*arguments), cwd=checkout, env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               bufsize=0)
    output, used, records = bytearray(), 0, 0
    deadline = time.monotonic() + jobs.GIT_STATUS_TIMEOUT_SECONDS
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "git identity check timed out")
                for key, _mask in selector.select(remaining):
                    size = 1 if clean_status and key.fileobj is process.stdout else min(65536, MAX_GIT_BYTES - used + 1)
                    try:
                        chunk = os.read(key.fd, size)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    require(not (clean_status and key.fileobj is process.stdout), "source does not match packet")
                    require(len(chunk) <= MAX_GIT_BYTES - used, "Git output exceeds byte limit")
                    if arguments[0] == "ls-files" and key.fileobj is process.stdout:
                        records += chunk.count(b"\0")
                        require(records <= MAX_RECORDS, "Git output exceeds entry limit")
                    used += len(chunk)
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
            try:
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise ValueError("git identity check timed out") from exc
        require(code == 0, "git identity check failed")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def _clean_source(checkout, *, planned=None):
    """Fixed-v1 checks require clean source; never fingerprint a dirty worktree entry."""
    checkout, environment = checked_path(checkout), jobs.object_read_env(inherit_config=True)
    legacy_names = {name for host in hierarchy_hosts.describe()["hosts"].values()
                    for name in (*host["billing_variables"], host["session_variable"]["name"])}
    environment = (hierarchy_hosts.child_environment(environment, "no-host") if planned is not False else
                   {key: value for key, value in environment.items() if key not in legacy_names})
    def read(*arguments):
        return _git_read(checkout, environment, arguments, clean_status=arguments[0] == "status")
    status = ("status", "--porcelain=v1", "-z", "--untracked-files=all")
    require(not read(*status), "source does not match packet")
    listed = read("ls-files", "--stage", "-z")
    gitlinks = [entry.partition(b"\t")[2] for entry in listed.split(b"\0") if entry.startswith(b"160000 ")]
    require(not gitlinks, "submodules are not supported, because their content cannot be witnessed byte for byte: "
            + ", ".join(sorted({os.fsdecode(path) for path in gitlinks}))[:1024])
    revision = read("rev-parse", "HEAD").decode("ascii").rstrip("\r\n")
    tree = read("rev-parse", "HEAD^{tree}").decode("ascii").rstrip("\r\n")
    require(not read(*status), "source does not match packet")
    return revision, tree


class Hold(ValueError):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason = reason


def check(condition, reason, detail):
    if not condition:
        raise Hold(reason, detail)


def checked_path(path):
    router.preflight_paths(path)
    return safe_path(path)


def _attachment(mailbox, ref):
    fields(ref, {"path", "sha256"})
    checked_path(ref["path"])
    return fresh._attachment(mailbox, ref)


def protect_references(value, *, paths=None):
    """Bound every nested string before the composer/evidence readers inspect paths."""
    fresh._private_paths(value, paths=paths)


def inspect_brief(raw, mailbox=None):
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("- "):
            protect_references(fresh._bounded_json(line[2:]),
                               paths=mailbox.operation.path_guard if mailbox is not None else None)
    return fresh.inspect(raw, _check_ref=mailbox.check_ref, _operation=mailbox.operation) if mailbox is not None else fresh.inspect(raw)


def identifier(stage, row, check_id=None):
    sha = row["small_change"]["registration"]["proposal"]["sha256"]
    return stage + "-" + (digest({"plan_sha256": sha, "check": check_id}) if check_id is not None else sha)


def closed(row):
    resolution = row["resolution"]
    return not row.get("lifecycle_unknown") and resolution is not None and resolution["kind"] in {"complete", "next", "blocked"}


def active_teams(state):
    return {row["request"]["team"] for row in state["requests"].values()
            if "small_change" in row and (row.get("lifecycle_unknown") or row["resolution"] is None
                or row["resolution"]["kind"] not in {"complete", "blocked"})}


def mixed_teams(state):
    active = active_teams(state)
    return {row["request"]["team"] for key, row in state["requests"].items()
            if "small_change" not in row and not closed(row) and row["request"]["team"] in active
            and router.last_decision(state, key) != "deny"}


def pending_plans(state):
    result = []
    for key, row in sorted(state["requests"].items()):
        change = row.get("small_change")
        if not change or closed(row) or row["routed"] or row["intent"]:
            continue
        decisions = change["decisions"]
        if decisions:
            continue
        result.append({"request_id": key, "request_sha256": row["raw"]["sha256"],
                       "plan_sha256": change["registration"]["proposal"]["sha256"],
                       "last_decision": None, "admission": change["admission"],
                       "expires_at": row["request"]["continuation"]["expires_at"], "why": "awaiting_plan_decision"})
    return result


class _WriterCustody(NamedTuple):
    """Operation-local facts from finalization; never part of the presentation."""

    request_id: str
    writer: str
    message_present: bool
    state_head: str
    history_verified: bool
    released: bool


def exclusions(state, custody):
    result = {team + "/" + role for team in active_teams(state) for role in ("orchestrator", "decider")}
    captured = set()
    for facts in custody:
        require(type(facts) is _WriterCustody, "unverified writer custody input")
        if facts.state_head != state["head"]:
            continue
        captured.add(facts.request_id)
        row = state["requests"][facts.request_id]
        released = not row.get("lifecycle_unknown") and row["resolution"] is not None and row["resolution"]["kind"] in {"complete", "blocked"}
        # Canonical next disposition closes routing, but cannot release D7 custody.
        if not released and (facts.message_present or row["routed"] is not None) and not facts.released:
            result.add(facts.writer)
    # An unreadable mailbox cannot prove that no writer was delivered. Never
    # turn an unavailable listing into permission for sweep to wake that lane.
    absent = {facts.request_id for facts in custody if facts.state_head == state["head"]
              and facts.history_verified and not facts.message_present}
    for key, row in state["requests"].items():
        # A verified complete listing can prove absence. A failed/oversized
        # listing, or unknown lifecycle effects, can never supply that proof.
        if key in absent and not row.get("lifecycle_unknown") and row["intent"] is None and row["start"] is None:
            continue
        canonical_release = closed(row) and row["resolution"]["kind"] in {"complete", "blocked"}
        if "small_change" in row and not canonical_release and (
                key not in captured or row.get("lifecycle_unknown") or row["routed"] is None):
            plan = life.raw_value(row["small_change"]["registration"]["proposal"])["plan"]
            result.add(row["request"]["team"] + "/lane/" + plan["writing_lanes"][0]["lane"])
    return sorted(result)


def historical(mailbox, message):
    generation = message["binding_generation"]
    bindings = mailbox.bindings(message["from"])
    require(type(generation) is int and 0 < generation <= len(bindings), "message sender generation has no binding")
    binding = bindings[generation - 1]
    require(all(message[k] == binding[v] for k, v in (("host", "host"), ("session", "session"),
                ("binding_generation", "generation"))), "message sender does not match historical binding")


def in_force(mailbox, message):
    """Historical form of Mailbox.fence(), which every publish applies: the sender generation was the endpoint's
    current, acknowledged binding when the record was created. A retired generation cannot speak after its successor."""
    historical(mailbox, message)
    bindings = mailbox.bindings(message["from"])
    generation, created = message["binding_generation"], parse_time(message["created_at"])
    require(parse_time(bindings[generation - 1]["created_at"]) <= created, "foreign assignment predates its binding")
    require(generation == len(bindings) or created < parse_time(bindings[generation]["created_at"]),
            "foreign assignment record follows its superseding binding")
    require(mailbox.ready(bindings[generation - 1]), "foreign assignment sender handoff is unacknowledged")


def _artifact_mark(info):
    return fresh._reference_mark(info)


class _RetainedJob:
    """Captured bytes plus identity witnesses; temporary anchored handles validate publication safety."""

    def __init__(self, store, initiative, message, *, _claim=None):
        self.descriptors()
        self.id = initiative["id"] + "/" + message["message_id"]
        self.holder = "job:" + self.id
        self.message = message
        self.folder = Path(store) / "jobs" / initiative["id"] / message["message_id"]
        router.preflight_paths(self.folder)
        require(self.folder.is_absolute() and ".." not in self.folder.parts, "invalid retained job path")
        require(os.name == "posix", "retained descriptor capture requires POSIX")
        self.entries = {}
        with self._directories() as (directory, links, missing):
            self._ancestors = tuple((name, identity) for _parent, name, _child, identity in links)
            self._missing = missing
            if missing is None:
                self._directory = _artifact_mark(os.fstat(directory))
                self._members = fresh._directory_names(directory)
                for name in ("execution.json", "derivation.json", "admitted.json"):
                    require(name not in self._members, "unsupported retained v1 metadata: " + name)
                candidates = [name for name in self._members if name.startswith(("step-", "derivation")) or name in {
                    "claim.json", "process.json", "result.json", "packet.md"}]
                metadata = self._artifact_metadata(directory, candidates)
                for name, before in metadata.items():
                    if name == "claim.json" and _claim is not None and name in _claim.entries:
                        entry = _claim.entries[name]
                        require(fresh._same_mark(_artifact_mark(before), entry["mark"]), "retained claim changed")
                        self.entries[name] = entry
                    else:
                        self._capture(directory, name, before=before)
            self._validate_snapshot(directory, links, missing)
        self.claim = self._json("claim.json")
        self.process = self._json("process.json")
        require("claim.json" not in self.entries or isinstance(self.claim, dict), "retained claim must be an object")
        require("process.json" not in self.entries or isinstance(self.process, dict), "retained process must be an object")
        self.result = self._result()

    @staticmethod
    def descriptors():
        require(os.name == "posix" and all(hasattr(os, name) for name in (
            "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")),
            "retained descriptor capture requires POSIX directory descriptors")

    @contextmanager
    def _directories(self, *, expected=False):
        """Keep only one path's temporary anchors open, independent of the number of jobs."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptors, links, missing = [], [], None
        try:
            parent = os.open("/", flags)
            descriptors.append(parent)
            for index, part in enumerate(self.folder.parts[1:]):
                try:
                    child = os.open(part, flags, dir_fd=parent)
                except FileNotFoundError:
                    missing = part
                    break
                descriptors.append(child)
                info = os.fstat(child)
                identity = fresh._directory_mark(info)
                require(stat.S_ISDIR(info.st_mode) and not fresh._reparse(info), "retained job ancestor is not a directory")
                if expected:
                    require(index < len(self._ancestors) and part == self._ancestors[index][0]
                            and fresh._same_mark(identity, self._ancestors[index][1]),
                            "retained job directory identity changed")
                links.append((parent, part, child, identity))
                parent = child
            yield parent, links, missing
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _artifact_metadata(self, directory, names):
        """Plan the entire capture from anchored, non-following metadata before any content open."""
        metadata, total = {}, 0
        for name in names:
            step = re.fullmatch(r"step-([1-9][0-9]?)\.(log|out)", name)
            require(name in {"claim.json", "process.json", "result.json", "packet.md"}
                    or (step is not None and int(step[1]) <= jobs.MAX_STEPS),
                    "completed job artifacts differ from admitted recipe")
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and not fresh._reparse(before),
                    "retained artifact is not a regular file: " + name)
            limit = jobs.MAX_RESULT_BYTES if name == "result.json" else MAX_BYTES if step is None else MAX_RETAINED_ARTIFACT_BYTES
            require(0 <= before.st_size <= limit,
                    "retained artifact exceeds byte limit" if step else "retained metadata exceeds its limit: " + name)
            total += before.st_size
            require(total <= MAX_RETAINED_JOB_BYTES, "retained job evidence exceeds byte limit")
            metadata[name] = before
        return metadata

    def _capture(self, directory, name, *, before=None):
        if before is None:
            before = self._artifact_metadata(directory, (name,))[name]
        metadata = name in {"claim.json", "process.json", "result.json", "packet.md"}
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            opened = os.fstat(descriptor)
            require(stat.S_ISREG(opened.st_mode) and not fresh._reparse(opened)
                    and fresh._same_mark(_artifact_mark(opened), _artifact_mark(before)),
                    "retained artifact changed at open: " + name)
            total, tail, chunks = 0, b"", []

            def consume(chunk):
                nonlocal total, tail
                total += len(chunk)
                require(total <= before.st_size, "retained artifact changed while reading: " + name)
                tail = (tail + chunk)[-jobs.TAIL_BYTES:]
                if metadata:
                    chunks.append(chunk)

            try:
                sha = fresh._stream_reference(descriptor, before, self.folder / name, consume)
            except ValueError as exc:
                raise ValueError("retained artifact changed while reading: " + name) from exc
            require(fresh._same_mark(_artifact_mark(os.fstat(descriptor)), _artifact_mark(before)) and total == before.st_size,
                    "retained artifact changed while reading: " + name)
            self.entries[name] = {"mark": _artifact_mark(before), "sha256": sha,
                                  "tail": tail, "raw": b"".join(chunks) if metadata else None}
        finally:
            os.close(descriptor)

    def _validate_snapshot(self, directory, links, missing):
        require(fresh._same_ancestors(tuple((name, identity) for _parent, name, _child, identity in links), self._ancestors)
                and missing == self._missing, "retained job directory identity changed")

        def validate_links():
            for parent, name, child, identity in links:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                opened = os.fstat(child)
                require(fresh._same_mark(fresh._directory_mark(current), identity)
                        and fresh._same_mark(fresh._directory_mark(opened), identity),
                        "retained job directory identity changed")

        def validate_directory():
            require(fresh._same_mark(_artifact_mark(os.fstat(directory)), self._directory)
                    and fresh._directory_names(directory) == tuple(sorted(self._members)),
                    "retained job directory membership changed")

        validate_links()
        if missing is not None:
            return
        validate_directory()
        metadata = self._artifact_metadata(directory, self.entries)
        for name, entry in self.entries.items():
            current = metadata[name]
            require(stat.S_ISREG(current.st_mode) and not fresh._reparse(current)
                    and fresh._same_mark(_artifact_mark(current), entry["mark"]),
                    "retained artifact identity/content metadata changed: " + name)
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
            try:
                require(fresh._same_mark(_artifact_mark(os.fstat(descriptor)), entry["mark"])
                        and fresh._same_mark(_artifact_mark(os.stat(name, dir_fd=directory, follow_symlinks=False)), entry["mark"]),
                        "retained artifact identity/content metadata changed: " + name)
            finally:
                os.close(descriptor)
        validate_directory()
        validate_links()

    def validate(self):
        # Reopen only anchored metadata handles. Captured result/body/evidence bytes are never reread.
        with self._directories(expected=True) as (directory, links, missing):
            self._validate_snapshot(directory, links, missing)

    def _json(self, name):
        entry = self.entries.get(name)
        return fresh._bounded_json(entry["raw"].decode("utf-8")) if entry is not None else None

    def _result(self):
        if "result.json" not in self.entries:
            return None
        result = self._json("result.json")
        # Same retained-result schema consumed by Job.result, over captured bytes.
        require(isinstance(result, dict) and result.get("schema") == jobs.RESULT_SCHEMA, "invalid job result schema")
        require(result.get("job") == self.id, "result does not belong to job: " + self.id)
        require(result.get("state") in ("completed", "failed", "refused"), "invalid terminal job state")
        require(isinstance(result.get("steps"), list), "invalid job result steps")

        def valid(condition, field):
            require(condition, "invalid job result " + field)

        for index, step in enumerate(result["steps"]):
            field = "steps[%d]" % index
            valid(isinstance(step, dict), field)
            argv = step.get("argv")
            valid(isinstance(argv, list) and bool(argv) and all(isinstance(word, str) for word in argv), field + ".argv")
            valid("exit_code" in step and (step["exit_code"] is None or type(step["exit_code"]) is int), field + ".exit_code")
            if "stopped_leftovers" in step:
                valid(type(step["stopped_leftovers"]) is bool, field + ".stopped_leftovers")
            if "timed_out" in step:
                valid(type(step["timed_out"]) is bool, field + ".timed_out")
        for field in ("reason", "commit"):
            valid(result.get(field) is None or isinstance(result[field], str), field)
        if "process_stopped_confirmed" in result:
            valid(type(result["process_stopped_confirmed"]) is bool, "process_stopped_confirmed")
        if result.get("tests") is not None:
            tests = result["tests"]
            valid(isinstance(tests, dict), "tests")
            for field in ("total", "passed", "failed", "errors", "skipped"):
                valid(type(tests.get(field)) is int and tests[field] >= 0, "tests." + field)
        if "kept" in result:
            valid(isinstance(result["kept"], list), "kept")
            for index, item in enumerate(result["kept"]):
                field = "kept[%d]" % index
                valid(isinstance(item, dict), field)
                valid(isinstance(item.get("path"), str), field + ".path")
                if "error" in item:
                    valid(isinstance(item["error"], str), field + ".error")
        code = result.get("exit_code")
        require((result["state"] == "refused" and code is None)
                or (result["state"] == "completed" and type(code) is int and code == 0)
                or (result["state"] == "failed" and type(code) is int and code != 0),
                "job result state and exit code disagree")
        if result["state"] == "completed":
            require(result.get("reason") is None, "completed job result has a reason")
            require(result.get("commit") is None, "completed fixed-command result has a new commit")
            tests = result.get("tests")
            require(tests is None or tests["total"] == sum(tests[key] for key in ("passed", "failed", "errors", "skipped")),
                    "completed job result test counts disagree")
            require(bool(result["steps"]) and all(step["exit_code"] == 0 and not step.get("timed_out", False)
                                                for step in result["steps"]),
                    "completed job result has missing, failed or timed-out steps")
        return result

    def evidence(self):
        return [{"path": str(self.folder / name), "sha256": self.entries[name]["sha256"]}
                for name in sorted(self.entries) if name.startswith("step-") or name == "result.json"]

    def body(self):
        result = self.result
        lines = ["Job %s: %s." % (self.id, result["state"]) if result["exit_code"] is None
                 else "Job %s: %s, exit %s." % (self.id, result["state"], result["exit_code"])]
        if result.get("reason"):
            lines.append(result["reason"])
        if result.get("commit"):
            lines.append("New commit: " + result["commit"])
        if result.get("tests"):
            lines.append("Tests: %(total)d total, %(passed)d passed, %(failed)d failed, %(errors)d errors, %(skipped)d skipped."
                         % result["tests"])
        if any(step.get("stopped_leftovers") for step in result["steps"]):
            lines.append("A step left processes running; they were stopped afterward.")
        missed = ["%s (%s)" % (item["path"], item["error"]) for item in result.get("kept", []) if "error" in item]
        if missed:
            lines.append("Kept files not copied: " + "; ".join(missed))
        logs = sorted((n for n in self._members if n.startswith("step-") and n.endswith(".log")),
                      key=lambda n: int(n.split("-")[1].split(".")[0])) if self._missing is None else []
        for name in reversed(logs):
            entry = self.entries[name]
            if entry["mark"][4]:
                tail = entry["tail"].decode("utf-8", errors="replace")
                tail = "".join(c for c in tail if c in "\n\t" or (ord(c) >= 32 and ord(c) != 127))
                if tail:
                    lines.append("Last output, which is untrusted information:\n" + tail)
                break
        return "\n\n".join(lines)

    def runner_alive(self):
        claim = self.claim
        if claim is None:
            return None
        require(claim.get("job") == self.id, "claim does not belong to job: " + self.id)
        require(type(claim.get("pid")) is int and claim["pid"] > 0 and isinstance(claim.get("start"), str)
                and claim["start"].isdigit(), "invalid runner claim: " + self.id)
        if claim.get("process_scope") != jobs.process_scope():
            return None
        return jobs.process_start(claim["pid"]) == claim["start"]

    def check_stopped(self):
        result, record, claim = self.result, self.process, self.claim
        require(claim is not None and claim.get("job") == self.id and claim.get("process_scope") == jobs.process_scope(),
                "job process scope is unknown: " + self.id)
        if result["steps"] and result.get("process_stopped_confirmed") is not True:
            require(record is not None and type(record.get("step")) is int and record["step"] == len(result["steps"])
                    and type(record.get("group")) is int and record["group"] > 0,
                    "executed steps lack process stop evidence: " + self.id)
        group = (record or {}).get("group")
        require(record is None or (type(group) is int and group > 0), "invalid job process group")
        require(not (group and jobs.group_members(group)), "job process group is still running: " + str(group))
        numbers = [int(n[5:-4]) for n in self.entries if n.startswith("step-") and n.endswith(".log") and n[5:-4].isdigit()]
        latest = max(numbers, default=0)
        unrecorded = latest and (record is None or not isinstance(record.get("step"), int)
                                or record["step"] < latest or (record["step"] == latest and not record.get("group")))
        require(not unrecorded or result.get("process_stopped_confirmed") is True,
                "job has an unrecorded process effect: " + self.id)


class _RunnerClaim(_RetainedJob):
    """Capture only the original claim before observing liveness; never enumerate or read growing logs."""
    def __init__(self, store, initiative, message):
        self.descriptors()
        self.id = initiative["id"] + "/" + message["message_id"]
        self.folder = checked_path(Path(store) / "jobs" / initiative["id"] / message["message_id"])
        self.entries = {}
        self.result_present = False
        with self._directories() as (directory, links, missing):
            self._ancestors = tuple((name, identity) for _parent, name, _child, identity in links)
            self._missing = missing
            if missing is None:
                for name in ("execution.json", "derivation.json", "admitted.json"):
                    try:
                        os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ValueError("unsupported retained v1 metadata: " + name)
                try:
                    self._capture(directory, "claim.json")
                except FileNotFoundError:
                    pass
                try:
                    os.stat("result.json", dir_fd=directory, follow_symlinks=False)
                    self.result_present = True
                except FileNotFoundError:
                    pass
        self.claim = self._json("claim.json")
        require(self.claim is None or isinstance(self.claim, dict), "retained claim must be an object")

    def validate(self):
        with self._directories(expected=True) as (directory, links, missing):
            require(missing == self._missing and fresh._same_ancestors(
                tuple((name, identity) for _parent, name, _child, identity in links), self._ancestors),
                "retained claim directory identity changed")
            for parent, name, _child, identity in links:
                require(fresh._same_mark(fresh._directory_mark(os.stat(name, dir_fd=parent, follow_symlinks=False)), identity),
                        "retained claim directory identity changed")
            if missing is None:
                for name in ("execution.json", "derivation.json", "admitted.json"):
                    try:
                        os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ValueError("unsupported retained v1 metadata: " + name)
            if missing is None and "claim.json" in self.entries:
                require(fresh._same_mark(_artifact_mark(os.stat("claim.json", dir_fd=directory, follow_symlinks=False)),
                                         self.entries["claim.json"]["mark"]), "retained claim changed")


class _CapturedStore:
    """Read-only workspace replay from captured bytes using the existing public reducers."""
    def __init__(self, path, operation):
        self.path, self.operation = checked_path(path), operation

    def load(self):
        ledger, count = workspace.Ledger(), 0
        self.private_refusals = {}
        try:
            paths = self.operation.entries(self.path / "events")
        except NotADirectoryError as exc:
            raise ValueError("workspace store is not initialized") from exc
        for path in paths:
            if path.name.startswith(".pending-"):
                checked_path(path)
                continue
            name = workspace.EVENT_NAME.fullmatch(path.name)
            require(name is not None, "unexpected workspace store entry: " + path.name)
            count += 1
            require(count <= MAX_RECORDS, "workspace event history exceeds record limit")
            require(int(name.group(1)) == count, "nonconsecutive workspace event: " + path.name)
            try:
                event = self.operation.json(path, private=False)
                fields(event, {"schema", "seq", "at", "kind", "data"})
                require(event["schema"] in workspace.REPLAY_SCHEMAS and event["seq"] == count, "wrong event schema or sequence")
                parse_time(event["at"])
                declared = event["data"]
                guarded = event
                if event["kind"] in {"register", "update"} and isinstance(declared, dict):
                    # These closed-schema declarations are validated lexically by
                    # Ledger, without metadata access. Quarantine only their own
                    # initiative below; consumers preflight them before opening.
                    inert = {"checkouts"}
                    if event["kind"] == "register":
                        inert.update({"mailbox_root", "delivery_dir"})
                    guarded = {**event, "data": {k: v for k, v in declared.items() if k not in inert}}
                fresh._private_paths(guarded, paths=self.operation.path_guard)
                ledger.apply(event)
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                raise ValueError("malformed workspace event: " + str(path) + ": " + str(exc)) from exc
        require(ledger.limits is not None, "workspace store is not initialized")
        for team, initiative in ledger.initiatives.items():
            declarations = [*initiative["checkouts"], *(initiative[k] for k in ("mailbox_root", "delivery_dir") if k in initiative)]
            for declaration in declarations:
                try:
                    self.operation.path_guard.refuse(declaration)
                except router.PrivatePathError as exc:
                    self.private_refusals.setdefault(team, []).append(str(exc))
        return ledger


class Row:
    def __init__(self, lifecycle, store, ledger, policy, state, key, recipes, wait, operation):
        self.lifecycle, self.store, self.ledger = lifecycle, store, ledger
        self.policy, self.state, self.key = policy, state, key
        self.row = state["requests"][key]
        self.change = self.row["small_change"]
        self.plan = life.raw_value(self.change["registration"]["proposal"])["plan"]
        self.team = self.row["request"]["team"]
        self.recipes, self.wait = recipes, wait
        self.writer = self.team + "/lane/" + self.plan["writing_lanes"][0]["lane"]
        self.view = {"request_id": key, "request_sha256": self.row["raw"]["sha256"], "team": self.team,
                     "plan_sha256": self.change["registration"]["proposal"]["sha256"],
                     "writer": self.writer, "state": "held", "drafts": [], "retained_replies": []}
        self.mailbox = None
        self.records = {}
        self.proofs = []
        self._retained_jobs = []
        self._completed_checks = []
        self._writer_receipt, self._writer_verified, self._writer_target_current = None, False, False
        self._verification_proof = None
        self._custody = None
        self.setup = {}
        self.operation = operation
        self.operation.validators.append(self.recheck_jobs)
        self.operation.validators.append(self.recheck_dependencies)

    def reference(self, path):
        with self.operation.capture():
            return self.operation.reference(checked_path(path))

    def verify(self, ref):
        with self.operation.capture():
            fields(ref, {"path", "sha256"})
            require(self.reference(ref["path"]) == ref, "evidence reference hash mismatch")
            return ref

    def recipe_file(self):
        with self.operation.capture():
            path = checked_path(self.recipes)
        if path in self.operation.parsed:
            return self.operation.parsed[path]
        raw = self.operation.read(path)[1]
        recipes = strict_json(raw.decode("utf-8"))
        fields(recipes, {"schema", "python", "path", "recipes"}, {"identity", "env", "hide", "ro_binds", "prefix", "min_free_gigabytes"})
        if "min_free_gigabytes" in recipes:
            jobs.integer(recipes["min_free_gigabytes"], "min_free_gigabytes", minimum=0)
        require(recipes["schema"] == jobs.RECIPES_SCHEMA, "unsupported recipes schema")
        require(isinstance(recipes["python"], str) and Path(recipes["python"]).is_absolute(), "python must be an absolute path")
        jobs.strings(recipes["path"], "path", nonempty=True)
        require(all(Path(folder).is_absolute() for folder in recipes["path"]), "path must list absolute folders")
        for label in ("hide", "ro_binds"):
            folders = recipes.get(label, [])
            jobs.strings(folders, label)
            for folder in folders:
                checked_path(folder)
            jobs.existing_folders(folders, label)
        prefix = recipes.get("prefix", [])
        jobs.strings(prefix, "prefix")
        require(not prefix or Path(prefix[0]).is_absolute(), "prefix must start with an absolute command")
        env = recipes.get("env", {})
        require(isinstance(env, dict) and all(isinstance(value, str) for value in env.values()), "invalid env")
        for key, value in env.items():
            require(re.fullmatch(r"[A-Z_][A-Z0-9_]*", key) is not None, "invalid env name: " + key)
            require("$" not in value or value in jobs.ENV_TOKENS, "unsupported token in env: " + value)
        table = recipes["recipes"]
        require(isinstance(table, dict) and table, "recipes must not be empty")
        for name, recipe in table.items():
            jobs.validate_recipe(name, recipe)
        if any(recipe["kind"] in ("commit", "merge") for recipe in table.values()):
            identity = recipes.get("identity")
            require(isinstance(identity, dict), "a commit or merge recipe needs an identity")
            fields(identity, {"name", "email"})
            jobs.text(identity["name"], "identity name", 256)
            jobs.text(identity["email"], "identity email", 256)
        # Hashed from the bytes that were parsed, so a result names exactly the recipe file it ran under. The key cannot come
        # from the file: fields() above refuses it there.
        recipes["recipes_sha256"] = hashlib.sha256(raw).hexdigest()
        self.operation.parsed[path] = recipes
        ref, _raw, witness = self.operation.files[path]
        self.operation.files[path] = ref, None, witness
        return recipes

    def recheck_jobs(self):
        try:
            with self.operation.capture():
                for job in self._retained_jobs:
                    job.validate()
                if self.recipes is not None:
                    for admission, job in self._completed_checks:
                        self.required_tests(admission, job)
        except Hold:
            raise
        except (ValueError, OSError) as exc:
            raise Hold("small_change_receipt_invalid", str(exc)) from exc

    def recheck_dependencies(self):
        self.lifecycle.verify_dependencies(self.key)

    def clear_writer_release(self):
        self._custody = self.finalize_writer_release(clear_only=True)

    def finalize_writer_release(self, *, clear_only=False):
        # All release-key mutations, including recovery removals, live here.
        # Removals need no proof; grants below require the positive proof gate.
        self.view.pop("route_receipt", None)
        self.view.pop("writer_publication_verified", None)
        released = False
        history_verified = False
        if not clear_only:
            self.view.pop("mailbox_history_verified", None)
            self.operation.verify()
            history_verified = self.mailbox is not None and self.mailbox._records is not None
            self.view["mailbox_history_verified"] = history_verified
            if self._verification_proof is not None and self._writer_verified and self._writer_target_current:
                self.view["writer_publication_verified"] = True
                if self._writer_receipt is not None:
                    self.view["route_receipt"] = self._writer_receipt
                    released = True
        return _WriterCustody(self.key, self.writer, identifier("scw", self.row) in self.records,
                              self.state["head"], history_verified, released)

    def reload(self):
        self.policy, self.state = router.locked_load(self.lifecycle, self.wait)
        self.row = self.state["requests"][self.key]
        self.change = self.row["small_change"]

    def event_ref(self, kind, mark=None):
        matches = []
        for record in self.lifecycle.index.get((self.key, kind), []):
            path = self.lifecycle.root / "events" / ("%06d.json" % record["sequence"])
            event, envelope = record["envelope"]["event"], record["envelope"]
            target = life.raw_value(event["request"])["id"] if event["type"] == "publish" else event.get("request_id")
            if event["type"] == kind and target == self.key:
                if mark is None or (envelope["actor"] == mark["actor"] and envelope["generation"] == mark["generation"]
                                    and record["at"] == mark["at"]):
                    matches.append(self.reference(path))
        require(bool(matches), "lifecycle event provenance missing: " + kind)
        return matches[-1]

    def witnesses(self):
        return [self.event_ref("publish"), self.event_ref("small_change_plan", self.change["registration"]),
                self.event_ref("small_change_admit", self.change["admission"])]

    def inputs(self):
        checked_path(self.lifecycle.root)
        store = checked_path(self.store.path)
        failures = self.store.private_refusals.get(self.team, [])
        check(not failures, "small_change_configuration", failures[0] if failures else "")
        output = checked_path(self.mailbox.root.parent / "briefs")
        require(output != store and store not in output.parents and output not in store.parents,
                "output directory overlaps coordination store: " + str(store))
        parents = {identifier("scw", self.row), identifier("scr", self.row)}
        if self.change["admission"]:
            parents.update(identifier("scj", self.row, c["check"]) for c in self.change["admission"]["checks"])
        relevant = {k: r for k, r in self.records.items() if k in parents or r["message"].get("in_reply_to") in parents}
        for value in (self.policy, self.row, relevant):
            protect_references(value, paths=self.operation.path_guard)
        provision = checked_path(self.mailbox.root.parent / "provision.json")
        if self.operation.exists(provision):
            setup = self.operation.json(provision)
            require(isinstance(setup, dict), "provision record must be an object")
            protect_references(setup, paths=self.operation.path_guard)
            for key in ("source", "delivery_dir", "store", "board", "mailbox_root"):
                if key in setup:
                    checked_path(setup[key])
            self.setup = setup

    def live(self, *, writing=False, expiry=False):
        failures = self.lifecycle.refusals_for(self.key, consume=True)
        check(not failures, "small_change_configuration", failures[0][1] if failures else "")
        check(self.team not in mixed_teams(self.state), "small_change_mixed_queue", "mixed initiative queues are held")
        check(router.last_decision(self.state, self.key) != "deny", "small_change_revoked", "canonical decision denied")
        try:
            life.small_change_approval(self.state, self.row)
            if writing:
                life.small_change_execution(self.policy, self.state, self.row, timestamp())
            elif self.row["intent"] is None:
                life.small_change_participants(self.policy, self.state, self.row, self.plan,
                                               self.change["registration"]["participants"])
            elif self.row["start"] is not None:
                life.small_change_review(self.policy, self.state, self.row, self.plan["reviewer"])
            if expiry:
                require(parse_time(timestamp()) < parse_time(self.row["request"]["continuation"]["expires_at"]),
                        "bounded authority expired")
        except ValueError as exc:
            reason = "small_change_expired" if "expired" in str(exc) else "small_change_binding_changed"
            raise Hold(reason, str(exc)) from exc
        check(self.row["resolution"] is None, "small_change_configuration", "disposed request requires owner resolution")

    def endpoints(self):
        m = self.mailbox
        check(m.endpoint(self.writer).get("kind") in {"implementer", "integrator"},
              "small_change_configuration", "approved writer endpoint is not a writing lane")
        reviewers = [e for e, value in m.manifest["endpoints"].items()
                     if e.startswith(self.team + "/lane/") and value.get("kind") == "reviewer"]
        check(len(reviewers) == 1, "small_change_configuration", "team requires exactly one Reviewer lane")
        self.reviewer = reviewers[0]
        self.view["reviewer"] = self.reviewer
        for endpoint in (self.writer, self.reviewer, self.team + "/orchestrator", self.team + "/root"):
            binding = m.current_binding(endpoint)
            if self.row["routed"] is None and not closed(self.row):
                check(m.ready(binding), "small_change_binding_changed", "unacknowledged endpoint: " + endpoint)

    def metadata(self, stage, target=None, **extra):
        body = {"schema": SCHEMA, "stage": stage, "request_id": self.key,
                "request_sha256": self.row["raw"]["sha256"], "plan_sha256": self.view["plan_sha256"],
                "admission_sha256": digest(self.change["admission"]), "witnesses": self.witnesses()}
        if target is not None:
            body["target_generation"] = self.mailbox.current_binding(target)["generation"]
        return {**body, **extra}

    def prior(self, msg_id, stage, to, *, extra=None):
        record = self.records.get(msg_id)
        if record is None:
            return None
        message = record["message"]
        try:
            body = fresh._bounded_json(message["body"])
            expected = self.metadata(stage, **(extra or {}))
            if stage != "check":
                fields(body, set(expected) | {"target_generation"})
                generation = body["target_generation"]
                history = self.mailbox.bindings(to)
                require(type(generation) is int and 0 < generation <= len(history), "invalid target generation")
                require(parse_time(history[generation - 1]["created_at"]) <= parse_time(message["created_at"]),
                        "target generation did not exist at publication")
            else:
                fields(body, set(expected))
            require(all(body.get(k) == v for k, v in expected.items()), "dispatch identity mismatch")
            require(message["from"] == self.team + "/orchestrator" and message["to"] == to
                    and message["type"] == ("job_request" if stage == "check" else "dispatch")
                    and "in_reply_to" not in message, "dispatch route/type mismatch")
            historical(self.mailbox, message)
            checked_path(message["brief"]["path"])
            prefix = "check-" if stage == "check" else "fresh-"
            require(Path(message["brief"]["path"]).name == prefix + message["brief"]["sha256"] + ".md",
                    "stored attachment is not content addressed")
            raw = _attachment(self.mailbox, message["brief"])
            for ref in body["witnesses"]:
                self.verify(ref)
            if stage != "check":
                inspect_brief(raw, self.mailbox)
                lines = raw.decode().splitlines()
                require([s for s in lines if s.startswith("Endpoint: ")] == ["Endpoint: " + to], "brief target endpoint mismatch")
                require([s for s in lines if s.startswith("Target generation: ")] == ["Target generation: %s" % body["target_generation"]],
                        "brief target generation mismatch")
                assignments = [fresh._bounded_json(s[2:]) for s in lines if s.startswith("- ")]
                assignments = [a for a in assignments if a.get("kind") == "small_change_assignment"]
                require(len(assignments) == 1 and all(assignments[0].get(k) == v for k, v in body.items()),
                        "brief lacks exact request/plan assignment")
        except (ValueError, OSError, UnicodeError, TypeError, KeyError, RecursionError) as exc:
            raise Hold("small_change_message_conflict", str(exc)) from exc
        try:
            in_force(self.mailbox, message)
            if stage == "writer":
                target = self.mailbox.bindings(to)[body["target_generation"] - 1]
                require(self.mailbox.ready(target), "writer target binding is unacknowledged")
                self._writer_target_current = self.mailbox.current_binding(to)["generation"] == target["generation"]
        except ValueError as exc:
            raise Hold("small_change_binding_changed", str(exc)) from exc
        return record

    def compose(self, target, stage):
        with self.operation.capture():
            args = SimpleNamespace(root=str(self.mailbox.root), initiative=self.team, endpoint=target,
                                   lifecycle=str(self.lifecycle.root), delivery_dir=None, as_of=timestamp(),
                                   target_generation=self.mailbox.current_binding(target)["generation"])
            try:
                raw, answer = fresh.prepare(args, _mailbox=self.mailbox, _request_id=self.key)
            except fresh.UnverifiedAttachment as exc:
                self.view["next_action"] = "reconcile the attachment's original durable reference, then rerun dispatch"
                if exc.message_id is not None:
                    # The validated ASCII slug is already canonical and bounded.
                    # Use the shared secret table before the final display bound.
                    from hierarchy_board import secret_patterns
                    message_id = exc.message_id
                    for pattern in secret_patterns():
                        message_id = pattern.sub("[REDACTED]", message_id)
                    self.view["unverified_message_id"] = message_id[:80]
                raise Hold("small_change_brief_unverified", "authoritative brief attachment is unverified") from exc
            assignment = {"kind": "small_change_assignment", "ref": self.witnesses()[1], **self.metadata(stage, target),
                          "instructions": ("Verify route receipt before intent/start; publish result lane_check as "
                                           "lifecycle-terminal:<raw terminal sha256>. Never repeat an unknown effect."
                                           if stage == "writer" else "Read-only review of the exact writer commit/tree and all check receipts."),
                          "evidence": self.proofs}
            raw = raw.replace(b"## Approved scope\n", b"## Approved scope\n\n- " + encoded(assignment) + b"\n", 1)
            inspect_brief(raw, self.mailbox)
            ref = {"path": str(Path(answer["brief"]["path"]).parent / ("fresh-" + hashlib.sha256(raw).hexdigest() + ".md")),
                   "sha256": hashlib.sha256(raw).hexdigest()}
            return raw, ref

    def publication(self, msg_id, to, kind, body, brief, *, staged=False):
        binding = self.mailbox.current_binding(self.team + "/orchestrator")
        check(self.mailbox.ready(binding), "small_change_binding_changed", "borrowed Orchestrator handoff is unacknowledged")
        request = {"message_id": msg_id, "from": binding["endpoint"], "to": to,
                   "host": binding["host"], "session": binding["session"], "binding_generation": binding["generation"],
                   "type": kind, "body": encoded(body).decode(), "brief": brief}
        if staged:
            # Generated closed envelope; attachment bytes are staged only after all-N preflight.
            matching(msg_id, SLUG, "message_id")
            self.mailbox.route(request["from"], to)
            self.mailbox.brief(brief, verify=False)
            require(len(request["body"].encode()) <= 65536, "message body exceeds limit")
        else:
            self.mailbox.validate_message(request)
        self.mailbox.fence(request)
        recipient = self.mailbox.current_binding(to)
        check(self.mailbox.ready(recipient), "small_change_binding_changed", "recipient handoff is unacknowledged")
        return request

    def publish(self, request):
        self.recheck_jobs()
        try:
            record = self.mailbox.publish(request)
            # Publication returned: retain its original evidence even if directory durability is unknown.
            self.records[request["message_id"]] = record
            try:
                life.sync_directory(Path(record["path"]).parent)
            except (ValueError, OSError) as exc:
                raise fresh.PartialPublication(record, exc) from exc
        except fresh.PartialPublication as exc:
            self.records[request["message_id"]] = exc.record
            self.view["partial_publication"] = {"message_id": request["message_id"],
                                                "evidence": {"path": exc.record["path"], "sha256": exc.record["sha256"]}}
            if isinstance(exc.error, Hold):
                raise Hold(exc.error.reason, str(exc)) from exc
            if isinstance(exc.error, fresh.CaptureChanged) and self.recipes is not None and exc.error.path == Path(self.recipes):
                raise Hold("small_change_recipe_mismatch", str(exc)) from exc
            # An independently appended deny is durable evidence, not a generic transport failure.
            # This refresh has no effects; unknown/malformed input still retains the partial-publication hold.
            try:
                self.reload()
                self.live(expiry=request["type"] == "job_request")
            except Hold as current:
                raise Hold(current.reason, str(exc) + "; " + str(current)) from exc
            except (ValueError, OSError, TypeError, KeyError):
                pass
            raise Hold("small_change_partial_publication", str(exc)) from exc
        return record

    def route_receipt(self):
        msg_id = identifier("scw", self.row)
        receipt = self.state["receipts"].get(msg_id)
        if receipt is None:
            check(self.row["routed"] is None, "small_change_message_conflict", "route exists under a different event identity")
            return None
        path = self.lifecycle.root / "events" / ("%06d.json" % receipt["sequence"])
        record = self.operation.json(checked_path(path), limit=life.MAX_BYTES)
        envelope = record["envelope"]
        require(record["event_sha256"] == receipt["event_sha256"], "route receipt hash mismatch")
        expected = {"type": "route", "request_id": self.key, "request_sha256": self.row["raw"]["sha256"], "to": self.writer}
        check(envelope["id"] == msg_id and envelope["event"] == expected
              and self.policy["actors"][envelope["actor"]]["role"] == "router", "small_change_message_conflict", "route receipt identity mismatch")
        self._writer_receipt = receipt
        return receipt

    def writer_dispatch(self, mutate):
        msg_id = identifier("scw", self.row)
        self.view["writer_message_present"] = msg_id in self.records
        receipt = self.route_receipt()
        prior = self.prior(msg_id, "writer", self.writer)
        check(not receipt or prior is not None, "small_change_message_lost", "route receipt exists without its writer message")
        self._writer_verified = prior is not None
        if receipt:
            return prior
        check(self.row["intent"] is None and self.row["start"] is None, "small_change_result_invalid", "intent/start lacks matching route receipt")
        self.live(writing=True, expiry=True)
        if prior is None:
            remaining = (parse_time(self.row["request"]["continuation"]["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
            check(remaining > 2 * self.wait + RESERVE_SECONDS, "small_change_expired", "writer expiry margin insufficient")
        self.view["state"] = "writer_ready" if prior is None else "held"
        if not mutate:
            if prior:
                raise Hold("delivered_unrecorded", "writer published without route receipt")
            return None
        actor = self.state["current"]["router"]
        router.router_actor(self.policy, self.state, actor)
        envelope = router.route_envelope(self.policy, self.state, actor, self.key, self.row["raw"], self.writer)
        envelope["id"] = msg_id
        router.journal_accepts(self.policy, self.state, envelope)
        if prior is None:
            # Sibling scw dispatches skip foreign_publications, so this guard must apply the same validated closure.
            history = self.mailbox.dispatch_history(self.records)
            check(not any(r["message"]["type"] == "dispatch" and r["message"]["to"] == self.writer
                          and not self.validated_closure(r["message"], history)
                          for r in self.records.values()), "small_change_configuration", "writer lane already has an open dispatch")
            raw, ref = self.compose(self.writer, "writer")
            self.reload()
            self.live(writing=True, expiry=True)
            actor = self.state["current"]["router"]
            router.router_actor(self.policy, self.state, actor)
            envelope = router.route_envelope(self.policy, self.state, actor, self.key, self.row["raw"], self.writer)
            envelope["id"] = msg_id
            router.journal_accepts(self.policy, self.state, envelope)
            remaining = (parse_time(self.row["request"]["continuation"]["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
            check(remaining > 2 * self.wait + RESERVE_SECONDS, "small_change_expired", "writer expiry margin insufficient")
            require(len(self.records) < MAX_RECORDS, "mailbox history limit reached")
            self.mailbox.stage(raw, ref)
            life.sync_directory(Path(ref["path"]).parent)
            prior = self.publish(self.publication(msg_id, self.writer, "dispatch", self.metadata("writer", self.writer), ref))
            self.view["writer_message_present"] = True
        try:
            receipt = router.patient(lambda: self.lifecycle.record(envelope), self.wait)
        except fresh._CommittedEvent as exc:
            self.view["partial_publication"] = exc.record
            raise Hold("small_change_committed_event", str(exc)) from exc
        except (ValueError, OSError) as exc:
            raise Hold("delivered_unrecorded", str(exc)) from exc
        self._writer_receipt = receipt
        self.reload()
        self._writer_verified = self.prior(msg_id, "writer", self.writer) is not None
        return prior

    def completion(self, dispatch, endpoint):
        msg_id = dispatch["message"]["message_id"]
        replies = [r for r in self.records.values() if r["message"].get("in_reply_to") == msg_id]
        accepted = [r for r in replies if r["message"].get("acknowledgment") == "accepted"]
        complete = [r for r in replies if r["message"]["type"] in {"result", "review"}
                    or r["message"].get("acknowledgment") == "completed"]
        check(len(accepted) <= 1 and len(complete) <= 1, "small_change_result_invalid", "duplicate acceptance/completion")
        target_generation = fresh._bounded_json(dispatch["message"]["body"])["target_generation"]
        try:
            in_force(self.mailbox, dispatch["message"])
        except ValueError as exc:
            raise Hold("small_change_binding_changed", str(exc)) from exc
        for record in accepted + complete:
            m = record["message"]
            try:
                in_force(self.mailbox, m)
            except ValueError as exc:
                raise Hold("small_change_binding_changed", str(exc)) from exc
            check(m["from"] == endpoint and m["binding_generation"] == target_generation,
                  "small_change_binding_changed", "lane result/acceptance binding changed")
        if accepted:
            check(parse_time(dispatch["message"]["created_at"]) <= parse_time(accepted[0]["message"]["created_at"]),
                  "small_change_result_invalid", "dispatch/acceptance/completion chronology differs")
        if not complete:
            return None, accepted[0] if accepted else None
        check(bool(accepted), "small_change_result_invalid", "completion without acceptance")
        check(parse_time(accepted[0]["message"]["created_at"]) <= parse_time(complete[0]["message"]["created_at"]),
              "small_change_result_invalid", "dispatch/acceptance/completion chronology differs")
        m = complete[0]["message"]
        try:
            self.mailbox.completion(m.get("result"), self.mailbox.endpoint(endpoint)["kind"])
            checks = m["result"]["checks"]
            require(len({c["check"] for c in checks}) == len(checks), "duplicate lane check")
            check(all(c["outcome"] == "pass" for c in checks), "small_change_check_failed", "lane checks are not all passing")
        except ValueError as exc:
            if isinstance(exc, Hold):
                raise
            raise Hold("small_change_result_invalid", str(exc)) from exc
        return complete[0], accepted[0]

    def writer_result(self, dispatch):
        record, accepted = self.completion(dispatch, self.writer)
        check(self._writer_target_current or record is not None, "small_change_binding_changed",
              "superseded writer target lacks a verified original completion")
        self.view["state"] = "writing" if accepted else "writer_sent"
        terminal = self.row["terminal"]
        if terminal is not None:
            check(terminal["value"]["outcome"] != "unknown", "small_change_unknown_effect", "writer terminal outcome unknown")
            check(terminal["value"]["outcome"] == "passed", "small_change_check_failed", "writer terminal failed")
        if record is None or terminal is None:
            if self.row["intent"] and self.row["intent"]["actor"] != self.state["current"]["operator"]:
                raise Hold("small_change_unknown_effect", "interrupted starting writer requires owner HOLD, never a new start")
            return None
        start = life.small_change_started(self.row)
        expected = self.change["registration"]["participants"]["writer"]
        check((terminal["actor"], terminal["generation"]) == (start["actor"], start["generation"])
              == (expected["cid"], expected["generation"]), "small_change_binding_changed", "terminal starting writer mismatch")
        match = TERMINAL_REF.fullmatch(record["message"]["result"]["lane_check"])
        check(match is not None and match.group(1) == terminal["sha256"], "small_change_result_invalid", "terminal/result reference mismatch")
        for ref in terminal["value"]["evidence"]:
            self.verify(ref)
        self.proofs += [self.reference(record["path"]), self.event_ref("terminal", terminal)]
        self.result_record, self.accepted = record, accepted
        self.review_not_before = max(parse_time(record["message"]["created_at"]), parse_time(terminal["at"]))
        return record

    def packet(self, admission):
        result = self.result_record["message"]["result"]
        checkout = checked_path(self.accepted["message"]["readiness"]["worktree"])
        return {"schema": jobs.PACKET_SCHEMA, "recipe": admission["recipe"], "checkout": str(checkout),
                "commit": result["source_revision"], "tree": result["source_tree"]}

    def job_extra(self, admission):
        return {"check": admission["check"], "recipe": admission["recipe"], "recipes_sha256": admission["recipes_sha256"],
                "result": self.reference(self.result_record["path"])}

    def job_records(self):
        entries = []
        for admission in sorted(self.change["admission"]["checks"], key=lambda c: c["check"]):
            packet = self.packet(admission)
            msg_id = identifier("scj", self.row, admission["check"])
            prior = self.prior(msg_id, "check", self.team + "/root", extra=self.job_extra(admission))
            if prior is None:
                folder = checked_path(self.store.path / "jobs" / self.team / msg_id)
                check(not self.operation.exists(folder), "small_change_message_lost", "check message missing with retained job evidence: " + msg_id)
            if prior:
                check(_attachment(self.mailbox, prior["message"]["brief"]) == encoded(packet),
                      "small_change_message_conflict", "job packet differs from admitted fixed source")
            entries.append((admission, packet, msg_id, prior))
        return entries

    def check_receipts(self, entries):
        complete = True
        self.running_checks = False
        self.view["checks"] = []
        for admission, packet, msg_id, record in entries:
            item = {"check": admission["check"], "message_id": msg_id, "state": "unpublished"}
            self.view["checks"].append(item)
            if record is None:
                complete = False
                continue
            receipts = [r for r in self.records.values() if r["message"]["type"] == "job_receipt"
                        and r["message"].get("in_reply_to") == msg_id]
            try:
                for receipt in receipts:
                    in_force(self.mailbox, receipt["message"])
                    require(parse_time(record["message"]["created_at"]) <= parse_time(receipt["message"]["created_at"]),
                            "job receipt precedes its request: " + msg_id)
                    self.mailbox.job_receipt(receipt["message"]["receipt"])
                for terminal_state in ("completed", "failed", "refused"):
                    require(sum(r["message"]["receipt"]["state"] == terminal_state for r in receipts) <= 1,
                            "duplicate terminal job receipt")
                state, witness = fresh.job_state(receipts)
                # job_state lets a later receipt replace an earlier state. Failure is final regardless, and
                # Mailbox.publish() refuses any receipt after a terminal one, so such history is invalid.
                history = [r["message"]["receipt"]["state"] for r in sorted(receipts, key=fresh.receipt_order)]
                item["state"] = next((s for s in history if s in {"failed", "refused"}), state)
                check(item["state"] not in {"failed", "refused"}, "small_change_check_failed", "job did not pass: " + msg_id)
                settled = next((n for n, s in enumerate(history) if s in TERMINAL_JOB_STATES), len(history))
                check(all(s in TERMINAL_JOB_STATES for s in history[settled:]), "small_change_receipt_invalid",
                      "nonterminal job receipt follows a terminal receipt: " + msg_id)
                check(state != "unknown", "small_change_unknown_effect", "job receipt has unresolved uncertainty: " + msg_id)
                with self.operation.capture():
                    claim = _RunnerClaim(self.store.path, self.initiative, record["message"])
                if claim.claim is None and state == "started":
                    # Absence read no claim bytes. Observe a just-published claim once before classifying a lost effect.
                    with self.operation.capture():
                        claim = _RunnerClaim(self.store.path, self.initiative, record["message"])
                if claim.claim is not None:
                    check(claim.claim.get("recipes_sha256") == admission["recipes_sha256"],
                          "small_change_recipe_mismatch", "job claim recipe file changed")
                    alive = claim.runner_alive()
                    if alive is True:
                        check(state != "completed", "small_change_unknown_effect", "job runner is live or unknown")
                        claim.validate()
                        self._retained_jobs.append(claim)
                        self.running_checks, complete = True, False
                        item["state"] = "running"
                        continue
                    check(alive is False, "small_change_unknown_effect", "job runner is unknown: " + msg_id)
                if not any(s in TERMINAL_JOB_STATES for s in history):
                    if state == "started" or claim.claim is not None:
                        alive = claim.runner_alive()
                        if alive is True:
                            claim.validate()
                            self._retained_jobs.append(claim)
                            self.running_checks, complete = True, False
                            item["state"] = "running"
                            continue
                        check(alive is False, "small_change_unknown_effect", "job runner is unknown: " + msg_id)
                        check(claim.result_present, "small_change_unknown_effect",
                              "stopped runner lacks terminal result/receipt: " + msg_id)
                with self.operation.capture():
                    job = _RetainedJob(self.store.path, self.initiative, record["message"], _claim=claim)
                self._retained_jobs.append(job)
                if job.claim is not None:
                    claim = job.claim
                    check(claim.get("recipes_sha256") == admission["recipes_sha256"], "small_change_recipe_mismatch", "job claim recipe file changed")
                result = job.result
                if result is not None:
                    check(result.get("recipes_sha256") == admission["recipes_sha256"], "small_change_recipe_mismatch", "job result recipe file changed")
                    check(result["state"] not in {"failed", "refused"}, "small_change_check_failed",
                          "retained job did not pass: " + msg_id)
                if state == "started" and result is None:
                    raise Hold("small_change_unknown_effect", "stopped runner lacks terminal result/receipt: " + msg_id)
                if settled == len(history) and job.entries:
                    if job.claim is not None and job.runner_alive() is True:
                        self.running_checks, complete = True, False
                        item["state"] = "running"
                        continue
                    raise Hold("small_change_unknown_effect", "original terminal job receipt is missing: " + msg_id)
            except Hold:
                raise
            except (ValueError, OSError, UnicodeError, KeyError, TypeError, RecursionError) as exc:
                raise Hold("small_change_receipt_invalid", str(exc)) from exc
            check(state not in {"failed", "refused"}, "small_change_check_failed", "job did not pass: " + msg_id)
            if state != "completed":
                complete = False
                continue
            try:
                require(result is not None and result["state"] == "completed" and result["exit_code"] == 0, "missing successful retained job result")
                require(witness["message"]["message_id"] == jobs.receipt_id(job, "completed"), "completed receipt is not the original runner receipt")
                require(result["recipe"] == packet["recipe"], "job recipe differs")
                if self.recipes is not None:
                    self.required_tests(admission, job)
                require(job.entries.get("packet.md", {}).get("raw") == encoded(packet), "retained packet differs")
                for name in ("before", "after"):
                    source = result[name]
                    fields(source, {"worktree", "source_revision", "source_tree", "dirty_state_sha256", "dirty_entries", "dirty_content_sha256"})
                    require(source["worktree"] == packet["checkout"] and source["source_revision"] == packet["commit"]
                            and source["source_tree"] == packet["tree"] and source["dirty_content_sha256"] == jobs.EMPTY_STATUS
                            and source["dirty_state_sha256"] == jobs.EMPTY_STATUS
                            and type(source["dirty_entries"]) is int and source["dirty_entries"] == 0,
                            "retained job source witness differs")
                require(result["before"] == result["after"], "retained job source witnesses differ before/after")
                export = result.get("source_export")
                require(isinstance(export, dict), "missing or malformed source export")
                fields(export, {"commit", "tree", "entries", "bytes", "removed"}, {"git_stub"})
                require(export["commit"] == packet["commit"] and export["tree"] == packet["tree"], "source export differs from packet")
                require(all(type(export[k]) is int and export[k] >= 0 for k in ("entries", "bytes"))
                        and type(export["removed"]) is bool and ("git_stub" not in export or type(export["git_stub"]) is bool),
                        "malformed source export")
                expected = {"state": "completed", "exit_code": 0, "evidence": job.evidence()}
                require(jobs.receipt_matches(job, witness["message"], expected, job.body()), "receipt does not match retained evidence")
                check(job.runner_alive() is False, "small_change_unknown_effect", "job runner is live or unknown")
                job.check_stopped()
                require(not any(r["holder"] == job.holder and r["state"] in {"queued", "granted"}
                                for r in self.store.load().requests.values()), "job reservation is not settled")
            except Hold:
                raise
            except (ValueError, OSError, KeyError, TypeError) as exc:
                raise Hold("small_change_receipt_invalid", str(exc)) from exc
            self.proofs.append(self.reference(witness["path"]))
            self._completed_checks.append((admission, job))
            self.review_not_before = max(self.review_not_before, parse_time(witness["message"]["created_at"]))
        return complete

    def required_tests(self, admission, job):
        result = job.result
        recipe = self.configured_recipe(admission)
        packet = fresh._bounded_json(job.entries["packet.md"]["raw"].decode("utf-8"))
        packet = {"paths": [], **packet}
        recipes = self.recipe_file()
        # The runner's list order is its step identity; v1 results have no step-number field.
        checkout = str(job.folder / jobs.EXPORT_FOLDER) if recipe.get("require_clean") else packet["checkout"]
        steps = list(jobs.command_steps(recipe, packet, recipes, job, checkout))
        expected = [step.argv for step in steps]
        require([step["argv"] for step in result["steps"]] == expected,
                "completed job steps differ from admitted recipe")
        artifacts = {name for name in job.entries if name.startswith("step-")}
        names = {"step-%d.log" % n for n in range(1, len(steps) + 1)}
        names |= {"step-%d.out" % n for n, step in enumerate(steps, 1) if step.capture}
        require(artifacts == names, "completed job artifacts differ from admitted recipe")
        require(job.process is not None and type(job.process.get("step")) is int
                and job.process["step"] == len(expected), "completed job process step differs from admitted recipe")
        if recipe.get("expects_tests", False):
            tests = result.get("tests")
            require(tests is not None and tests["total"] > 0 and tests["passed"] > 0,
                    "completed job result lacks required passing tests")

    def configured_recipe(self, admission):
        require(self.recipes is not None, "dispatch requires configured recipes")
        recipes = self.recipe_file()
        check(recipes["recipes_sha256"] == admission["recipes_sha256"], "small_change_recipe_mismatch", "admitted recipe file changed")
        recipe = recipes["recipes"].get(admission["recipe"])
        check(recipe is not None and recipe["kind"] == "command" and recipe.get("require_clean") is True
              and not any("$paths" in step for step in recipe["steps"]), "small_change_configuration", "unsupported check recipe or $paths")
        return recipe

    def publish_checks(self, entries, mutate=True):
        missing = [entry for entry in entries if entry[3] is None]
        if not missing:
            return
        self.live(expiry=True)
        staged = []
        check(len(self.records) + len(missing) <= MAX_RECORDS, "small_change_configuration", "mailbox has no batch headroom")
        for admission, packet, msg_id, prior in entries:
            self.configured_recipe(admission)
            raw = encoded(packet)
            ref = {"path": str(self.mailbox.root.parent / "briefs" / ("check-" + hashlib.sha256(raw).hexdigest() + ".md")),
                   "sha256": hashlib.sha256(raw).hexdigest()}
            request = self.publication(msg_id, self.team + "/root", "job_request", self.metadata("check", **self.job_extra(admission)), ref, staged=True)
            if prior is None:
                # Validate source and recipe before staging the packet for the public runner.
                require(packet["checkout"] in self.initiative["checkouts"], "checkout is not registered")
                planned = self.operation.exists(self.mailbox.root.parent / hierarchy_hosts.PLAN_FILE)
                require(_clean_source(packet["checkout"], planned=planned) == (packet["commit"], packet["tree"]),
                        "source does not match packet")
                staged.append((admission, raw, ref, request))
        if not mutate:
            return
        for admission, raw, ref, request in staged:
            self.mailbox.stage(raw, ref)
            life.sync_directory(Path(ref["path"]).parent)
        for admission, raw, ref, request in staged:
            self.reload()
            self.live(expiry=True)
            current = self.recipe_file()
            check(current["recipes_sha256"] == admission["recipes_sha256"], "small_change_recipe_mismatch", "recipe changed during batch publication")
            self.publish(request)

    def reviewer_dispatch(self, mutate):
        msg_id = identifier("scr", self.row)
        prior = self.prior(msg_id, "reviewer", self.reviewer)
        if prior:
            self.reviewer_evidence(prior)
            return prior
        check(self.row["review"] is None, "small_change_message_lost", "Reviewer message missing with retained review evidence")
        self.live()
        self.view["state"] = "review_ready"
        if mutate:
            require(self.recipes is not None, "Reviewer publication requires configured recipes")
            raw, ref = self.compose(self.reviewer, "reviewer")
            self.mailbox.stage(raw, ref)
            life.sync_directory(Path(ref["path"]).parent)
            self.reload()
            self.live()
            check(parse_time(timestamp()) >= self.review_not_before, "small_change_message_conflict",
                  "Reviewer assignment would precede verified check evidence")
            published = self.publish(self.publication(msg_id, self.reviewer, "dispatch", self.metadata("reviewer", self.reviewer), ref))
            self.reviewer_evidence(published)
            return published
        return None

    def reviewer_evidence(self, record):
        """Bind the immutable review scope to the exact writer/terminal/settled-receipt witnesses."""
        try:
            message = record["message"]
            body = fresh._bounded_json(message["body"])
            raw = _attachment(self.mailbox, message["brief"])
            assignments = [fresh._bounded_json(line[2:]) for line in raw.decode("utf-8").splitlines() if line.startswith("- ")]
            assignments = [item for item in assignments if item.get("kind") == "small_change_assignment"]
            expected = {"kind": "small_change_assignment", "ref": self.witnesses()[1], **body,
                        "instructions": "Read-only review of the exact writer commit/tree and all check receipts.",
                        "evidence": self.proofs}
            require(assignments == [expected], "Reviewer assignment source/proof references differ")
            require(parse_time(message["created_at"]) >= self.review_not_before,
                    "Reviewer assignment precedes verified check evidence")
            if self.row["review"] is not None:
                require(parse_time(self.row["review"]["at"]) >= self.review_not_before,
                        "lifecycle review precedes verified check evidence")
        except (ValueError, OSError, UnicodeError, KeyError, TypeError, RecursionError) as exc:
            raise Hold("small_change_message_conflict", str(exc)) from exc

    def invalidate(self, reason, detail):
        """Invalidate release and completion drafts, retaining owner HOLD evidence."""
        self._verification_proof = None
        self.clear_writer_release()
        original = self.view["drafts"]
        retained = []
        for envelope in original:
            event = envelope["event"]
            if (event.get("resolution", {}).get("kind") == "blocked"
                    and (event["type"] == "resolve" or (
                        event["type"] == "disposition" and event.get("status") == "HOLD"))):
                retained.append(envelope)
        discarded = len(retained) != len(original)
        if discarded:
            self.view["drafts"] = retained
        if discarded or self.view.get("state") not in {"held", "complete", "owned_hold"}:
            self.view.update(state="held", reason=reason, detail=detail)

    def drafts(self, reason=None):
        self.operation.verify()
        if self.row.get("lifecycle_unknown"):
            return []
        blocked = self.row["resolution"] is not None and self.row["resolution"]["kind"] == "blocked"
        if closed(self.row) and not blocked:
            return []
        evidence = self.proofs or [self.event_ref("small_change_plan", self.change["registration"])]
        success = reason == "small_change_close_due"
        if success:
            check(router.last_decision(self.state, self.key) != "deny", "small_change_revoked", "canonical decision denied")
        if blocked and not success:
            return []
        resolution = ({"kind": "complete", "evidence": evidence} if success else
                      {"kind": "blocked", "owner": self.row["request"]["owner"],
                       "next_decision": self.row["request"]["next_decision"], "condition": reason, "evidence": evidence})
        events = []
        common = {"request_id": self.key, "request_sha256": self.row["raw"]["sha256"]}
        if success and self.row["delivery"] is None:
            events.append({"type": "delivery", **common, "evidence": evidence})
        if blocked:
            events.append({"type": "resolve", **common, "blocker_sha256": digest(self.row["resolution"]), "resolution": resolution})
        else:
            events.append({"type": "disposition", **common, "status": "FINAL" if success else "HOLD", "resolution": resolution})
        policy, trial = self.policy, copy.deepcopy(self.state)
        actor, root = trial["current"]["coordinator"], trial["current"]["root"]
        result = []
        for event in events:
            envelope = {"id": "scc-" + digest({"plan": self.view["plan_sha256"], "event": event}),
                        "actor": actor, "generation": policy["actors"][actor]["generation"],
                        "custody": {"cid": root, "generation": policy["actors"][root]["generation"]}, "event": event}
            require(trial["sequence"] < life.MAX_EVENTS, "lifecycle event limit reached")
            life.reduce_event(policy, trial, envelope, timestamp())
            trial["sequence"] += 1
            result.append(envelope)
        return result

    def retained(self):
        parents = {identifier("scw", self.row), identifier("scr", self.row)}
        if self.change["admission"]:
            parents.update(identifier("scj", self.row, c["check"]) for c in self.change["admission"]["checks"])
        delivery = self.mailbox.root.parent / "delivery"
        delivery = checked_path(self.setup.get("delivery_dir", str(delivery)))
        read_ids = set()
        if self.operation.exists(delivery):
            for receipt in self.mailbox.delivery_receipts(delivery, "reads", self.team + "/orchestrator", self.records):
                read_ids.update(receipt["message_ids"])
        self.view["retained_replies"] = [{"message_id": r["message"]["message_id"], "parent": r["message"]["in_reply_to"],
                                         "path": r["path"], "unread": r["message"]["message_id"] not in read_ids}
                                        for r in self.records.values() if r["message"].get("in_reply_to") in parents]

    def validated_closure(self, message, history):
        """Mailbox.dispatch_history() counts any correlated reply as closure, whatever its sender generation. A
        dispatch is closed here only by unique acceptance and completion, each fenced by in_force, in order."""
        closed_assignments, accepted_assignments = history
        msg_id = message["message_id"]
        accepted = [m for m in accepted_assignments if m["in_reply_to"] == msg_id]
        completed = [r["message"] for r in self.records.values()
                     if r["message"].get("in_reply_to") == msg_id and
                     (r["message"]["type"] in {"result", "review"} or r["message"].get("acknowledgment") == "completed")]
        if msg_id not in closed_assignments or len(accepted) != 1 or len(completed) != 1:
            return False
        try:
            for m in [message, accepted[0], completed[0]]:
                require(m["message_id"] not in self.mailbox.message_refusals, "foreign assignment reference unavailable")
                in_force(self.mailbox, m)
            require(all(m["from"] == message["to"] and m["to"] == message["from"] for m in accepted + completed),
                    "foreign assignment reply endpoints differ")
            # Mailbox.publish() lets an acknowledged successor complete its predecessor's accepted
            # dispatch; in_force applies that same fence to the completion's own generation.
            require(accepted[0]["binding_generation"] <= completed[0]["binding_generation"],
                    "foreign completion predates its accepted historical binding")
            require(parse_time(message["created_at"]) <= parse_time(accepted[0]["created_at"])
                    <= parse_time(completed[0]["created_at"]), "foreign assignment chronology differs")
            self.mailbox.completion(completed[0].get("result"), self.mailbox.endpoint(message["to"])["kind"])
        except (ValueError, KeyError, TypeError):
            return False
        return True

    def foreign_publications(self):
        known = set()
        for row in self.state["requests"].values():
            if "small_change" not in row or row["request"]["team"] != self.team:
                continue
            known.update((identifier("scw", row), identifier("scr", row)))
            if row["small_change"]["admission"]:
                known.update(identifier("scj", row, c["check"]) for c in row["small_change"]["admission"]["checks"])
        history = self.mailbox.dispatch_history(self.records)
        for record in self.records.values():
            message = record["message"]
            if message["from"] != self.team + "/orchestrator" or message["message_id"] in known:
                continue
            if message["type"] == "dispatch" and message["to"] in {self.writer, self.reviewer}:
                check(self.validated_closure(message, history), "small_change_mixed_queue",
                      "foreign lane dispatch: " + message["message_id"])
            if message["type"] == "job_request" and self.row["terminal"] is not None:
                # A job packet is inert data. This reports overlap; it never gates the existing runner.
                malformed = "malformed foreign job packet: " + message["message_id"]
                try:
                    packet = fresh._bounded_json(jobs.packet_text(_attachment(self.mailbox, message["brief"])))
                except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
                    raise Hold("small_change_mixed_queue", malformed) from exc
                check(isinstance(packet, dict), "small_change_mixed_queue", malformed)
                if hasattr(self, "result_record"):
                    source = self.result_record["message"]["result"]
                    if packet.get("commit") == source["source_revision"] or packet.get("tree") == source["source_tree"]:
                        raise Hold("small_change_mixed_queue", "foreign fixed-source job: " + message["message_id"])

    def progress(self, mutate):
        check(router.last_decision(self.state, self.key) != "deny", "small_change_revoked", "canonical decision denied")
        check(self.row["resolution"] is None or self.row["resolution"]["kind"] != "next",
              "small_change_configuration", "next disposition does not release the planning skip")
        self.endpoints()
        if not closed(self.row):
            for role in ("orchestrator", "decider"):
                check(not self.operation.exists(self.mailbox.wake_marker(self.team + "/" + role)),
                      "small_change_configuration", "planning wake requires owner reconciliation: " + role)
        self.retained()
        self.foreign_publications()
        blocked = self.row["resolution"] is not None and self.row["resolution"]["kind"] == "blocked"
        auditing = closed(self.row)
        if not auditing and self.row["routed"] is None:
            self.live(writing=True, expiry=True)
        dispatch = self.writer_dispatch(mutate and not auditing)
        if dispatch is None:
            check(not auditing, "small_change_closed_unverified", "closed row lacks writer dispatch")
            return
        if not auditing:
            self.live()
        result = self.writer_result(dispatch)
        if result is None:
            check(not auditing, "small_change_closed_unverified", "closed row lacks writer result/terminal")
            return
        self.foreign_publications()
        entries = self.job_records()
        complete = self.check_receipts(entries)
        if not complete:
            check(not auditing, "small_change_closed_unverified", "closed row lacks verified checks")
            if not self.running_checks and (mutate or self.recipes is not None):
                self.publish_checks(entries, mutate)
            self.view["state"] = "checking"
            return
        reviewer = self.reviewer_dispatch(mutate and not auditing)
        check(not auditing or reviewer is not None, "small_change_closed_unverified", "closed row lacks Reviewer dispatch")
        if reviewer is None:
            return
        self.view["state"] = "reviewing"
        completion, _accepted = self.completion(reviewer, self.reviewer)
        review = self.row["review"]
        if review is not None:
            check(review["verdict"] == "accept", "small_change_review_rejected", "Reviewer rejected")
            check(review["actor"] == self.plan["reviewer"] and review["generation"] == self.change["registration"]["participants"]["reviewer"]["generation"]
                  and review["result_sha256"] == self.row["terminal"]["sha256"], "small_change_result_invalid", "review actor/result mismatch")
        if completion is None or review is None:
            check(not auditing, "small_change_closed_unverified", "closed row lacks matched review records")
            return
        reviewed = completion["message"]["result"]
        original = result["message"]["result"]
        check(all(reviewed[k] == original[k] for k in ("source_revision", "source_tree")), "small_change_result_invalid", "Reviewer source differs")
        self.proofs += [self.reference(completion["path"]), self.event_ref("review", review)]
        if auditing:
            self.view["state"] = "owned_hold" if blocked else "complete"
            if self.recipes is None:
                self.view.update(state="owned_hold" if blocked else "held", reason="small_change_close_unverified",
                                 detail="rerun with --recipes <file> to verify closed evidence")
                self.invalidate(self.view["reason"], self.view["detail"])
                return
            if blocked:
                self.view["reason"] = "small_change_close_due"
                self.view["drafts"] = self.drafts("small_change_close_due")
            return
        self.live()
        self.view.update(state="held", reason="small_change_close_due", detail="owner records drafted coordinator events")
        if self.recipes is not None:
            self.view["drafts"] = self.drafts("small_change_close_due")
        else:
            self.view.update(reason="small_change_close_unverified",
                             detail="rerun with --recipes <file> to verify checks before successful closure drafts")
            self.invalidate(self.view["reason"], self.view["detail"])

    def verification_pass(self, mutate):
        # An old canonical publication is an effect even without a route receipt.
        # Inspect it before active-team, participant, admission or host readiness checks.
        self.initiative = self.ledger.initiatives.get(self.team)
        check(self.initiative is not None and "mailbox_root" in self.initiative,
              "small_change_configuration", "team has no registered mailbox")
        root = self.initiative["mailbox_root"]
        self.mailbox = fresh._CapturedMailbox(checked_path(root), _operation=self.operation)
        self.mailbox.before_publication = self.publication_authority
        self.records = self.mailbox.messages()
        prior = router.prior_delivery(self.mailbox, self.team, self.key, self.row["raw"])
        if prior is not None:
            original = self.records[router.route_id(self.row["raw"]["sha256"])]
            self.view["legacy_delivery"] = {"message_id": original["message"]["message_id"],
                                            "evidence": self.reference(original["path"])}
            raise Hold("small_change_legacy_delivery" if prior == "same" else "route_message_conflict",
                       "retained canonical publication requires owner disposition; never dispatch again")
        parents = {identifier("scw", self.row), identifier("scr", self.row)}
        if self.change["admission"]:
            parents.update(identifier("scj", self.row, c["check"]) for c in self.change["admission"]["checks"])
        for key, errors in self.mailbox.message_refusals.items():
            if key in parents or self.records[key]["message"].get("in_reply_to") in parents:
                raise Hold("small_change_configuration", errors[0])
        _root, reason = router.team_mailbox(self.ledger, self.team)
        check(reason is None, "small_change_configuration", reason or "")
        refusals = self.lifecycle.refusals_for(self.key, consume=True)
        if refusals:
            raise router.PrivatePathError(*refusals[0])
        self.inputs()
        self.progress(mutate)

    def run(self, mutate):
        self._verification_proof = None
        try:
            self._verification_proof = self.operation.prove(self.verification_pass, mutate)
            self._custody = self.finalize_writer_release()
        except (ValueError, OSError, UnicodeError, TypeError, KeyError, RecursionError) as exc:
            reason = exc.reason if isinstance(exc, Hold) else "small_change_configuration"
            if isinstance(exc, fresh.CaptureChanged) and self.recipes is not None and exc.path == Path(self.recipes):
                reason = "small_change_recipe_mismatch"
            if "malformed mailbox message" in str(exc):
                reason = "small_change_receipt_invalid" if "receipt" in str(exc) else "small_change_result_invalid"
            if "referenced message does not exist" in str(exc):
                reason = "small_change_message_lost"
            self.view.update(state="held", reason=reason, detail=str(exc)[:1024])
            if self.mailbox is not None:
                self.view["writer_message_present"] = identifier("scw", self.row) in self.records
            if self.view.get("writer_message_present") and self.row["routed"] is None and reason in {
                    "small_change_expired", "small_change_revoked", "small_change_binding_changed", "small_change_configuration"}:
                self.view.update(reason="delivered_unrecorded", recovery_hold=reason)
            if closed(self.row) and self.row["resolution"]["kind"] == "complete":
                self.view["reason"] = "small_change_closed_unverified"
            elif closed(self.row) and self.row["resolution"]["kind"] == "blocked":
                self.view["state"] = "owned_hold"
            self.invalidate(self.view["reason"], self.view["detail"])
            try:
                if not self.view["drafts"]:
                    self.view["drafts"] = self.drafts(reason)
            except (ValueError, OSError, TypeError, KeyError) as draft_error:
                self.view["draft_error"] = str(draft_error)[:1024]
                self.invalidate(self.view["reason"], self.view["detail"])
            try:
                self._custody = self.finalize_writer_release()
            except (ValueError, OSError, TypeError, KeyError, RecursionError) as release_error:
                self.view["release_validation_error"] = str(release_error)[:1024]
                self.invalidate(self.view["reason"], self.view["detail"])
        return self.view

    def publication_authority(self, request):
        self.reload()
        writing = request["type"] == "dispatch" and request["to"] == self.writer
        self.live(writing=writing, expiry=writing or request["type"] == "job_request")


def project(lifecycle, store, wait=5.0, recipes=None, mutate=False):
    router.preflight_paths(lifecycle.root, store.path)
    root, store_path = lifecycle.root, store.path
    reference_cache = {}

    def inputs():
        operation = fresh._Operation(reference_cache=reference_cache)
        captured = operation.lifecycle(root)
        policy, state = router.locked_load(captured, wait)
        captured_store = _CapturedStore(store_path, operation)
        ledger = captured_store.load()
        operation.verify()
        return operation, captured, captured_store, policy, state, ledger

    _operation, _lifecycle, _store, _policy, state, ledger = inputs()
    rows = []
    custody = []
    contexts = []
    for key, row in sorted(state["requests"].items()):
        if "small_change" not in row:
            continue
        def context():
            if not mutate:
                # Share only the journal replay/index. Each row keeps independent
                # mailbox/store captures, so another team's artifacts cannot poison it.
                operation = fresh._Operation(reference_cache=reference_cache)
                captured_store = _CapturedStore(store_path, operation)
                current_ledger = captured_store.load()
                return Row(_lifecycle, captured_store, current_ledger, _policy, state, key, recipes, wait, operation)
            operation, captured, captured_store, policy, current, current_ledger = inputs()
            return Row(captured, captured_store, current_ledger, policy, current, key, recipes, wait, operation)

        if mutate:
            mailbox_root, reason = router.team_mailbox(ledger, row["request"]["team"])
            if reason is None:
                current = None
                appended = False
                try:
                    with writer_lock(checked_path(mailbox_root)):
                        current = context()
                        actual, refusal = router.team_mailbox(current.ledger, row["request"]["team"])
                        check(refusal is None and actual == mailbox_root, "small_change_configuration", "team mailbox changed before lock")
                        rows.append(current.run(True))
                        custody.append(current._custody)
                        contexts.append(current)
                        appended = True
                    continue
                except (ValueError, OSError) as exc:
                    if current is None:
                        current = Row(_lifecycle, _store, ledger, _policy, state, key, recipes, wait,
                                      fresh._Operation(reference_cache=reference_cache))
                    current.view.update(state="held", reason="small_change_configuration", detail=str(exc))
                    current.invalidate("small_change_configuration", str(exc))
                    if not appended:
                        rows.append(current.view)
                        custody.append(current._custody)
                        contexts.append(current)
                    else:
                        custody[-1] = current._custody
                        contexts[-1] = current
                    continue
        current = context()
        rows.append(current.run(False))
        custody.append(current._custody)
        contexts.append(current)
    final = fresh._Operation(reference_cache=reference_cache)
    _policy, planning = router.locked_load(final.lifecycle(root), wait)
    for current in contexts:
        if current._custody.state_head != planning["head"]:
            reason = ("small_change_revoked" if router.last_decision(planning, current.key) == "deny"
                      else "small_change_snapshot_changed")
            current.invalidate(reason, "lifecycle snapshot changed after writer verification; rerun dispatch")
    final.verify()
    return {"small_changes": rows, "planning_exclusions": exclusions(planning, custody),
            "qualification_dependencies": ["D4 registry companion", "D5 lane lifecycle tools", "D7 independent early-release record seam"]}
