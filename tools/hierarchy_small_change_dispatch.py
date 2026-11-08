"""Evidence-only small-change progression. D4/D5 activation and D7 early release remain unqualified.

Only mailbox publication borrows the ready Orchestrator binding. The sole journal
mutation is route under the current router; participant and coordinator events
are never recorded here. All state is reconstructed from existing public records.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace

import hierarchy_fresh_brief as fresh
import hierarchy_jobs as jobs
import hierarchy_lifecycle as life
import hierarchy_router as router
from hierarchy_mailbox import (Mailbox, MAX_BYTES, MAX_RECORDS, SLUG, TERMINAL_JOB_STATES, digest, encoded, fields,
                               matching, parse_time, read_bytes, read_json, require, safe_path, strict_json, timestamp,
                               writer_lock)


SCHEMA = "aegis.small-change-dispatch/v1"
STATES = {"writer_ready", "writer_sent", "writing", "checking", "review_ready", "reviewing",
          "held", "complete", "owned_hold"}
TERMINAL_REF = re.compile(r"lifecycle-terminal:([0-9a-f]{64})\Z")
RESERVE_SECONDS = 30


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


def reference(path):
    path = checked_path(path)
    return fresh.file_ref(path)


def verify(ref):
    fields(ref, {"path", "sha256"})
    require(reference(ref["path"]) == ref, "evidence reference hash mismatch")
    return ref


def protect_references(value):
    """Validate declared paths before the composer or evidence readers can open them."""
    if isinstance(value, dict):
        if "path" in value and "sha256" in value:
            checked_path(value["path"])
        for item in value.values():
            protect_references(item)
    elif isinstance(value, list):
        for item in value:
            protect_references(item)


def inspect_brief(raw):
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("- "):
            protect_references(strict_json(line[2:]))
    return fresh.inspect(raw)


def identifier(stage, row, check_id=None):
    sha = row["small_change"]["registration"]["proposal"]["sha256"]
    return stage + "-" + (digest({"plan_sha256": sha, "check": check_id}) if check_id is not None else sha)


def closed(row):
    resolution = row["resolution"]
    return resolution is not None and resolution["kind"] in {"complete", "next", "blocked"}


def active_teams(state):
    return {row["request"]["team"] for row in state["requests"].values()
            if "small_change" in row and (row["resolution"] is None
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


def exclusions(state, rows):
    result = {team + "/" + role for team in active_teams(state) for role in ("orchestrator", "decider")}
    for view in rows:
        if view.get("writer_message_present") and not view.get("route_receipt"):
            result.add(view["writer"])
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
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class _RetainedJob:
    """Captured bytes plus identity witnesses; temporary anchored handles validate publication safety."""

    def __init__(self, store, initiative, message):
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
                self._members = tuple(os.listdir(directory))
                for name in ("execution.json", "derivation.json", "admitted.json"):
                    require(name not in self._members, "unsupported retained v1 metadata: " + name)
                for name in self._members:
                    if name.startswith("step-") or name.startswith("derivation") or name in {
                            "claim.json", "process.json", "result.json", "packet.md"}:
                        self._capture(directory, name)
            self._validate_snapshot(directory, links, missing)
        self.claim = self._json("claim.json")
        self.process = self._json("process.json")
        require("claim.json" not in self.entries or isinstance(self.claim, dict), "retained claim must be an object")
        require("process.json" not in self.entries or isinstance(self.process, dict), "retained process must be an object")
        self.result = self._result()

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
                identity = (info.st_dev, info.st_ino, info.st_mode)
                require(stat.S_ISDIR(info.st_mode), "retained job ancestor is not a directory")
                if expected:
                    require(index < len(self._ancestors) and (part, identity) == self._ancestors[index],
                            "retained job directory identity changed")
                links.append((parent, part, child, identity))
                parent = child
            yield parent, links, missing
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _capture(self, directory, name):
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode), "retained artifact is not a regular file: " + name)
        limit = (jobs.MAX_RESULT_BYTES if name == "result.json" else
                 MAX_BYTES if name in {"claim.json", "process.json", "packet.md"} else None)
        require(limit is None or before.st_size <= limit, "retained metadata exceeds its limit: " + name)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            opened = os.fstat(descriptor)
            require(stat.S_ISREG(opened.st_mode) and _artifact_mark(opened) == _artifact_mark(before),
                    "retained artifact changed at open: " + name)
            sha, total, tail, chunks = hashlib.sha256(), 0, b"", []
            remaining = before.st_size
            while remaining:
                requested = min(1048576, remaining)
                chunk = os.read(descriptor, requested)
                require(len(chunk) == requested, "retained artifact changed while reading: " + name)
                remaining -= len(chunk)
                total += len(chunk)
                require(limit is None or total <= limit, "retained metadata grew beyond its limit: " + name)
                sha.update(chunk)
                tail = (tail + chunk)[-jobs.TAIL_BYTES:]
                if limit is not None:
                    chunks.append(chunk)
            require(_artifact_mark(os.fstat(descriptor)) == _artifact_mark(before) and total == before.st_size,
                    "retained artifact changed while reading: " + name)
            self.entries[name] = {"mark": _artifact_mark(before), "sha256": sha.hexdigest(),
                                  "tail": tail, "raw": b"".join(chunks) if limit is not None else None}
        finally:
            os.close(descriptor)

    def _validate_snapshot(self, directory, links, missing):
        require(tuple((name, identity) for _parent, name, _child, identity in links) == self._ancestors
                and missing == self._missing, "retained job directory identity changed")

        def validate_links():
            for parent, name, child, identity in links:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                opened = os.fstat(child)
                require((current.st_dev, current.st_ino, current.st_mode) == identity
                        == (opened.st_dev, opened.st_ino, opened.st_mode),
                        "retained job directory identity changed")

        def validate_directory():
            require(_artifact_mark(os.fstat(directory)) == self._directory
                    and sorted(os.listdir(directory)) == sorted(self._members),
                    "retained job directory membership changed")

        validate_links()
        if missing is not None:
            return
        validate_directory()
        for name, entry in self.entries.items():
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISREG(current.st_mode) and _artifact_mark(current) == entry["mark"],
                    "retained artifact identity/content metadata changed: " + name)
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
            try:
                require(_artifact_mark(os.fstat(descriptor)) == entry["mark"]
                        == _artifact_mark(os.stat(name, dir_fd=directory, follow_symlinks=False)),
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
        return strict_json(entry["raw"].decode("utf-8")) if entry is not None else None

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
        require(not group or (type(group) is int and group > 0), "invalid job process group")
        require(not (group and jobs.group_members(group)), "job process group is still running: " + str(group))
        numbers = [int(n[5:-4]) for n in self.entries if n.startswith("step-") and n.endswith(".log") and n[5:-4].isdigit()]
        latest = max(numbers, default=0)
        unrecorded = latest and (record is None or not isinstance(record.get("step"), int)
                                or record["step"] < latest or (record["step"] == latest and not record.get("group")))
        require(not unrecorded or result.get("process_stopped_confirmed") is True,
                "job has an unrecorded process effect: " + self.id)


class Row:
    def __init__(self, lifecycle, store, ledger, policy, state, key, recipes, wait):
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
        self.setup = {}

    def recheck_jobs(self):
        try:
            for job in self._retained_jobs:
                job.validate()
        except (ValueError, OSError) as exc:
            raise Hold("small_change_receipt_invalid", str(exc)) from exc

    def reload(self):
        self.policy, self.state = router.locked_load(self.lifecycle, self.wait)
        self.row = self.state["requests"][self.key]
        self.change = self.row["small_change"]

    def event_ref(self, kind, mark=None):
        matches = []
        for sequence in range(1, self.state["sequence"] + 1):
            path = self.lifecycle.root / "events" / ("%06d.json" % sequence)
            record = read_json(checked_path(path))
            event, envelope = record["envelope"]["event"], record["envelope"]
            target = life.raw_value(event["request"])["id"] if event["type"] == "publish" else event.get("request_id")
            if event["type"] == kind and target == self.key:
                if mark is None or (envelope["actor"] == mark["actor"] and envelope["generation"] == mark["generation"]
                                    and record["at"] == mark["at"]):
                    matches.append(reference(path))
        require(bool(matches), "lifecycle event provenance missing: " + kind)
        return matches[-1]

    def witnesses(self):
        return [self.event_ref("publish"), self.event_ref("small_change_plan", self.change["registration"]),
                self.event_ref("small_change_admit", self.change["admission"])]

    def inputs(self):
        checked_path(self.lifecycle.root)
        store = checked_path(self.store.path)
        output = checked_path(self.mailbox.root.parent / "briefs")
        require(output != store and store not in output.parents and output not in store.parents,
                "output directory overlaps coordination store: " + str(store))
        for value in (self.policy, self.state, self.records):
            protect_references(value)
        provision = checked_path(self.mailbox.root.parent / "provision.json")
        if provision.exists():
            setup = read_json(provision)
            require(isinstance(setup, dict), "provision record must be an object")
            protect_references(setup)
            for key in ("source", "delivery_dir", "store", "board", "mailbox_root"):
                if key in setup:
                    checked_path(setup[key])
            self.setup = setup

    def live(self, *, writing=False, expiry=False):
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
            body = strict_json(message["body"])
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
            raw = self.mailbox.brief(message["brief"])
            for ref in body["witnesses"]:
                verify(ref)
            if stage != "check":
                inspect_brief(raw)
                require(("Endpoint: " + to) in raw.decode(), "brief target endpoint mismatch")
                require(("Target generation: %s" % body["target_generation"]) in raw.decode(), "brief target generation mismatch")
                require(self.row["raw"]["sha256"] in raw.decode() and self.view["plan_sha256"] in raw.decode(),
                        "brief lacks request/plan witnesses")
        except (ValueError, OSError, UnicodeError, TypeError, KeyError, RecursionError) as exc:
            raise Hold("small_change_message_conflict", str(exc)) from exc
        try:
            in_force(self.mailbox, message)
        except ValueError as exc:
            raise Hold("small_change_binding_changed", str(exc)) from exc
        return record

    def compose(self, target, stage):
        args = SimpleNamespace(root=str(self.mailbox.root), initiative=self.team, endpoint=target,
                               lifecycle=str(self.lifecycle.root), delivery_dir=None, as_of=timestamp(),
                               target_generation=self.mailbox.current_binding(target)["generation"])
        raw, answer = fresh.prepare(args)
        assignment = {"kind": "small_change_assignment", "ref": self.witnesses()[1], **self.metadata(stage, target),
                      "instructions": ("Verify route receipt before intent/start; publish result lane_check as "
                                       "lifecycle-terminal:<raw terminal sha256>. Never repeat an unknown effect."
                                       if stage == "writer" else "Read-only review of the exact writer commit/tree and all check receipts."),
                      "evidence": self.proofs}
        raw = raw.replace(b"## Approved scope\n", b"## Approved scope\n\n- " + encoded(assignment) + b"\n", 1)
        inspect_brief(raw)
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
        record = self.mailbox.publish(request)
        life.sync_directory(Path(record["path"]).parent)
        self.records[request["message_id"]] = record
        return record

    def route_receipt(self):
        msg_id = identifier("scw", self.row)
        receipt = self.state["receipts"].get(msg_id)
        if receipt is None:
            check(self.row["routed"] is None, "small_change_message_conflict", "route exists under a different event identity")
            return None
        path = self.lifecycle.root / "events" / ("%06d.json" % receipt["sequence"])
        record = read_json(checked_path(path))
        envelope = record["envelope"]
        require(record["event_sha256"] == receipt["event_sha256"], "route receipt hash mismatch")
        expected = {"type": "route", "request_id": self.key, "request_sha256": self.row["raw"]["sha256"], "to": self.writer}
        check(envelope["id"] == msg_id and envelope["event"] == expected
              and self.policy["actors"][envelope["actor"]]["role"] == "router", "small_change_message_conflict", "route receipt identity mismatch")
        self.view["route_receipt"] = receipt
        return receipt

    def writer_dispatch(self, mutate):
        msg_id = identifier("scw", self.row)
        self.view["writer_message_present"] = msg_id in self.records
        receipt = self.route_receipt()
        prior = self.prior(msg_id, "writer", self.writer)
        check(not receipt or prior is not None, "small_change_message_lost", "route receipt exists without its writer message")
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
            remaining = (parse_time(self.row["request"]["continuation"]["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
            check(remaining > 2 * self.wait + RESERVE_SECONDS, "small_change_expired", "writer expiry margin insufficient")
            require(len(self.records) < MAX_RECORDS, "mailbox history limit reached")
            fresh.publish(raw, ref)
            life.sync_directory(Path(ref["path"]).parent)
            prior = self.publish(self.publication(msg_id, self.writer, "dispatch", self.metadata("writer", self.writer), ref))
            self.view["writer_message_present"] = True
        try:
            receipt = router.patient(lambda: self.lifecycle.record(envelope), self.wait)
        except (ValueError, OSError) as exc:
            raise Hold("delivered_unrecorded", str(exc)) from exc
        self.view["route_receipt"] = receipt
        self.reload()
        return prior

    def completion(self, dispatch, endpoint):
        msg_id = dispatch["message"]["message_id"]
        replies = [r for r in self.records.values() if r["message"].get("in_reply_to") == msg_id]
        accepted = [r for r in replies if r["message"].get("acknowledgment") == "accepted"]
        complete = [r for r in replies if r["message"]["type"] in {"result", "review"}
                    or r["message"].get("acknowledgment") == "completed"]
        check(len(accepted) <= 1 and len(complete) <= 1, "small_change_result_invalid", "duplicate acceptance/completion")
        target_generation = strict_json(dispatch["message"]["body"])["target_generation"]
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
            verify(ref)
        self.proofs += [reference(record["path"]), self.event_ref("terminal", terminal)]
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
                "result": reference(self.result_record["path"])}

    def job_records(self):
        entries = []
        for admission in sorted(self.change["admission"]["checks"], key=lambda c: c["check"]):
            packet = self.packet(admission)
            msg_id = identifier("scj", self.row, admission["check"])
            prior = self.prior(msg_id, "check", self.team + "/root", extra=self.job_extra(admission))
            if prior is None:
                folder = checked_path(self.store.path / "jobs" / self.team / msg_id)
                check(not folder.exists(), "small_change_message_lost", "check message missing with retained job evidence: " + msg_id)
            if prior:
                check(self.mailbox.brief(prior["message"]["brief"]) == encoded(packet),
                      "small_change_message_conflict", "job packet differs from admitted fixed source")
            entries.append((admission, packet, msg_id, prior))
        return entries

    def check_receipts(self, entries):
        complete = True
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
                job = _RetainedJob(self.store.path, self.initiative, record["message"])
                self._retained_jobs.append(job)
                if job.claim is not None:
                    claim = job.claim
                    check(claim.get("recipes_sha256") == admission["recipes_sha256"], "small_change_recipe_mismatch", "job claim recipe file changed")
                result = job.result
                if result is not None:
                    check(result.get("recipes_sha256") == admission["recipes_sha256"], "small_change_recipe_mismatch", "job result recipe file changed")
                    check(result["state"] not in {"failed", "refused"}, "small_change_check_failed",
                          "retained job did not pass: " + msg_id)
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
                require(job.entries.get("packet.md", {}).get("raw") == encoded(packet), "retained packet differs")
                for name in ("before", "after"):
                    source = result[name]
                    require(source["worktree"] == packet["checkout"] and source["source_revision"] == packet["commit"]
                            and source["source_tree"] == packet["tree"] and source["dirty_content_sha256"] == jobs.EMPTY_STATUS,
                            "retained job source witness differs")
                expected = {"state": "completed", "exit_code": 0, "evidence": job.evidence()}
                if result.get("reason") is not None:
                    expected["reason"] = result["reason"][:4096]
                require(jobs.receipt_matches(job, witness["message"], expected, job.body()), "receipt does not match retained evidence")
                check(job.runner_alive() is False, "small_change_unknown_effect", "job runner is live or unknown")
                job.check_stopped()
                require(not any(r["holder"] == job.holder and r["state"] in {"queued", "granted"}
                                for r in self.store.load().requests.values()), "job reservation is not settled")
            except Hold:
                raise
            except (ValueError, OSError, KeyError, TypeError) as exc:
                raise Hold("small_change_receipt_invalid", str(exc)) from exc
            self.proofs.append(reference(witness["path"]))
            self.review_not_before = max(self.review_not_before, parse_time(witness["message"]["created_at"]))
        return complete

    def publish_checks(self, entries, mutate=True):
        missing = [entry for entry in entries if entry[3] is None]
        if not missing:
            return
        self.live(expiry=True)
        require(self.recipes is not None, "dispatch requires configured recipes")
        recipes = jobs.load_recipes(checked_path(self.recipes))
        staged = []
        check(len(self.records) + len(missing) <= MAX_RECORDS, "small_change_configuration", "mailbox has no batch headroom")
        for admission, packet, msg_id, prior in entries:
            check(recipes["recipes_sha256"] == admission["recipes_sha256"], "small_change_recipe_mismatch", "admitted recipe file changed")
            recipe = recipes["recipes"].get(admission["recipe"])
            check(recipe is not None and recipe["kind"] == "command" and recipe.get("require_clean") is True
                  and not any("$paths" in step for step in recipe["steps"]), "small_change_configuration", "unsupported check recipe or $paths")
            raw = encoded(packet)
            ref = {"path": str(self.mailbox.root.parent / "briefs" / ("check-" + hashlib.sha256(raw).hexdigest() + ".md")),
                   "sha256": hashlib.sha256(raw).hexdigest()}
            request = self.publication(msg_id, self.team + "/root", "job_request", self.metadata("check", **self.job_extra(admission)), ref, staged=True)
            if prior is None:
                # Public runner validation is read-only; the attached packet must first exist.
                # Validate equivalent source/recipe constraints before staging any packet.
                require(packet["checkout"] in self.initiative["checkouts"], "checkout is not registered")
                observed = jobs.source_state(self.mailbox, packet["checkout"])
                require((observed["source_revision"], observed["source_tree"], observed["dirty_content_sha256"]) ==
                        (packet["commit"], packet["tree"], jobs.EMPTY_STATUS), "source does not match packet")
                staged.append((admission, raw, ref, request))
        if not mutate:
            return
        for admission, raw, ref, request in staged:
            fresh.publish(raw, ref)
            life.sync_directory(Path(ref["path"]).parent)
        for admission, raw, ref, request in staged:
            self.reload()
            self.live(expiry=True)
            current = jobs.load_recipes(checked_path(self.recipes))
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
            raw, ref = self.compose(self.reviewer, "reviewer")
            fresh.publish(raw, ref)
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
            body = strict_json(message["body"])
            raw = self.mailbox.brief(message["brief"])
            assignments = [strict_json(line[2:]) for line in raw.decode("utf-8").splitlines() if line.startswith("- ")]
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

    def drafts(self, reason=None):
        blocked = self.row["resolution"] is not None and self.row["resolution"]["kind"] == "blocked"
        if closed(self.row) and not blocked:
            return []
        evidence = self.proofs or [self.event_ref("small_change_plan", self.change["registration"])]
        success = reason == "small_change_close_due"
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
        if delivery.exists():
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
                    packet = strict_json(jobs.packet_text(self.mailbox.brief(message["brief"])))
                except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
                    raise Hold("small_change_mixed_queue", malformed) from exc
                check(isinstance(packet, dict), "small_change_mixed_queue", malformed)
                if hasattr(self, "result_record"):
                    source = self.result_record["message"]["result"]
                    if packet.get("commit") == source["source_revision"] or packet.get("tree") == source["source_tree"]:
                        raise Hold("small_change_mixed_queue", "foreign fixed-source job: " + message["message_id"])

    def progress(self, mutate):
        check(self.row["resolution"] is None or self.row["resolution"]["kind"] != "next",
              "small_change_configuration", "next disposition does not release the planning skip")
        self.endpoints()
        if not closed(self.row):
            for role in ("orchestrator", "decider"):
                check(not self.mailbox.wake_marker(self.team + "/" + role).exists(),
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
            if mutate or self.recipes is not None:
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
        self.proofs += [reference(completion["path"]), self.event_ref("review", review)]
        if auditing:
            self.view["state"] = "owned_hold" if blocked else "complete"
            if blocked:
                self.view["reason"] = "small_change_close_due"
                self.view["drafts"] = self.drafts("small_change_close_due")
            return
        self.live()
        self.view.update(state="held", reason="small_change_close_due", detail="owner records drafted coordinator events")
        self.view["drafts"] = self.drafts("small_change_close_due")

    def run(self, mutate):
        try:
            # An old canonical publication is an effect even without a route receipt.
            # Inspect it before active-team, participant, admission or host readiness checks.
            self.initiative = self.ledger.initiatives.get(self.team)
            check(self.initiative is not None and "mailbox_root" in self.initiative,
                  "small_change_configuration", "team has no registered mailbox")
            root = self.initiative["mailbox_root"]
            self.mailbox = Mailbox(checked_path(root))
            self.records = self.mailbox.messages()
            prior = router.prior_delivery(self.mailbox, self.team, self.key, self.row["raw"])
            if prior is not None:
                original = self.records[router.route_id(self.row["raw"]["sha256"])]
                self.view["legacy_delivery"] = {"message_id": original["message"]["message_id"],
                                                "evidence": reference(original["path"])}
                raise Hold("small_change_legacy_delivery" if prior == "same" else "route_message_conflict",
                           "retained canonical publication requires owner disposition; never dispatch again")
            _root, reason = router.team_mailbox(self.ledger, self.team)
            check(reason is None, "small_change_configuration", reason or "")
            self.inputs()
            self.progress(mutate)
            self.recheck_jobs()
        except (ValueError, OSError, UnicodeError, TypeError, KeyError, RecursionError) as exc:
            reason = exc.reason if isinstance(exc, Hold) else "small_change_configuration"
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
            try:
                self.view["drafts"] = self.drafts(reason)
            except (ValueError, OSError, TypeError, KeyError) as draft_error:
                self.view["draft_error"] = str(draft_error)[:1024]
        return self.view


def project(lifecycle, store, wait=5.0, recipes=None, mutate=False):
    router.preflight_paths(lifecycle.root, store.path)
    policy, state = router.locked_load(lifecycle, wait)
    ledger = store.load()
    rows = []
    for key, row in sorted(state["requests"].items()):
        if "small_change" not in row:
            continue
        context = Row(lifecycle, store, ledger, policy, state, key, recipes, wait)
        if mutate:
            root, reason = router.team_mailbox(ledger, row["request"]["team"])
            if reason is None:
                try:
                    with writer_lock(checked_path(root)):
                        context.reload()
                        rows.append(context.run(True))
                    continue
                except (ValueError, OSError) as exc:
                    context.view.update(state="held", reason="small_change_configuration", detail=str(exc))
                    rows.append(context.view)
                    continue
        rows.append(context.run(False))
    _policy, current = router.locked_load(lifecycle, wait)
    return {"small_changes": rows, "planning_exclusions": exclusions(current, rows),
            "qualification_dependencies": ["D4 registry companion", "D5 lane lifecycle tools", "D7 independent early-release record seam"]}
