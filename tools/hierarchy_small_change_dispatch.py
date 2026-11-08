"""Evidence-only small-change progression. D4/D5 activation and D7 early release remain unqualified.

Only mailbox publication borrows the ready Orchestrator binding. The sole journal
mutation is route under the current router; participant and coordinator events
are never recorded here. All state is reconstructed from existing public records.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from types import SimpleNamespace

import hierarchy_fresh_brief as fresh
import hierarchy_jobs as jobs
import hierarchy_lifecycle as life
import hierarchy_router as router
from hierarchy_mailbox import (Mailbox, MAX_RECORDS, SLUG, digest, encoded, fields, matching, parse_time,
                               read_bytes, read_json, require, safe_path, strict_json, timestamp, writer_lock)


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
            protect_references(setup)
            for key in ("source", "delivery_dir", "store", "board", "mailbox_root"):
                if key in setup:
                    checked_path(setup[key])

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
            return record
        except (ValueError, OSError, UnicodeError, TypeError, KeyError, RecursionError) as exc:
            raise Hold("small_change_message_conflict", str(exc)) from exc

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
            check(not any(r["message"]["type"] == "dispatch" and r["message"]["to"] == self.writer
                          and r["message"]["message_id"] not in self.mailbox.dispatch_history(self.records)[0]
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
        for record in accepted + complete:
            m = record["message"]
            try:
                historical(self.mailbox, m)
            except ValueError as exc:
                raise Hold("small_change_binding_changed", str(exc)) from exc
            check(m["from"] == endpoint and m["binding_generation"] == target_generation,
                  "small_change_binding_changed", "lane result/acceptance binding changed")
        if not complete:
            return None, accepted[0] if accepted else None
        check(bool(accepted), "small_change_result_invalid", "completion without acceptance")
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
                    historical(self.mailbox, receipt["message"])
                    self.mailbox.job_receipt(receipt["message"]["receipt"])
                for terminal_state in ("completed", "failed", "refused"):
                    require(sum(r["message"]["receipt"]["state"] == terminal_state for r in receipts) <= 1,
                            "duplicate terminal job receipt")
                state, witness = fresh.job_state(receipts)
                item["state"] = state
                check(state != "unknown", "small_change_unknown_effect", "job receipt has unresolved uncertainty: " + msg_id)
                job = jobs.Job(self.store.path, self.initiative, record["message"])
                checked_path(job.folder)
                if job.claim_path.exists():
                    claim = read_json(job.claim_path)
                    check(claim.get("recipes_sha256") == admission["recipes_sha256"], "small_change_recipe_mismatch", "job claim recipe file changed")
                result = job.result()
                if result is not None:
                    check(result.get("recipes_sha256") == admission["recipes_sha256"], "small_change_recipe_mismatch", "job result recipe file changed")
            except Hold:
                raise
            except (ValueError, OSError, KeyError, TypeError) as exc:
                raise Hold("small_change_receipt_invalid", str(exc)) from exc
            check(state not in {"failed", "refused"}, "small_change_check_failed", "job did not pass: " + msg_id)
            if state != "completed":
                complete = False
                continue
            try:
                require(result is not None and result["state"] == "completed" and result["exit_code"] == 0, "missing successful retained job result")
                require(witness["message"]["message_id"] == jobs.receipt_id(job, "completed"), "completed receipt is not the original runner receipt")
                require(result["recipe"] == packet["recipe"], "job recipe differs")
                require(read_bytes(job.folder / "packet.md") == encoded(packet), "retained packet differs")
                for name in ("before", "after"):
                    source = result[name]
                    require(source["worktree"] == packet["checkout"] and source["source_revision"] == packet["commit"]
                            and source["source_tree"] == packet["tree"] and source["dirty_content_sha256"] == jobs.EMPTY_STATUS,
                            "retained job source witness differs")
                for ref in witness["message"]["receipt"].get("evidence", []):
                    verify(ref)
                expected = {"state": "completed", "exit_code": 0, "evidence": job.evidence()}
                if result.get("reason") is not None:
                    expected["reason"] = result["reason"][:4096]
                require(jobs.receipt_matches(job, witness["message"], expected, jobs.result_body(job, result)), "receipt does not match retained evidence")
                check(job.runner_alive() is False, "small_change_unknown_effect", "job runner is live or unknown")
                jobs.check_settlement_processes(job, result)
                require(not any(r["holder"] == job.holder and r["state"] in {"queued", "granted"}
                                for r in self.store.load().requests.values()), "job reservation is not settled")
            except Hold:
                raise
            except (ValueError, OSError, KeyError, TypeError) as exc:
                raise Hold("small_change_receipt_invalid", str(exc)) from exc
            self.proofs.append(reference(witness["path"]))
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
            return self.publish(self.publication(msg_id, self.reviewer, "dispatch", self.metadata("reviewer", self.reviewer), ref))
        return None

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
        setup = self.mailbox.root.parent / "provision.json"
        if setup.exists():
            delivery = checked_path(read_json(setup).get("delivery_dir", str(delivery)))
        read_ids = set()
        if delivery.exists():
            for receipt in self.mailbox.delivery_receipts(delivery, "reads", self.team + "/orchestrator", self.records):
                read_ids.update(receipt["message_ids"])
        self.view["retained_replies"] = [{"message_id": r["message"]["message_id"], "parent": r["message"]["in_reply_to"],
                                         "path": r["path"], "unread": r["message"]["message_id"] not in read_ids}
                                        for r in self.records.values() if r["message"].get("in_reply_to") in parents]

    def foreign_publications(self):
        known = set()
        for row in self.state["requests"].values():
            if "small_change" not in row or row["request"]["team"] != self.team:
                continue
            known.update((identifier("scw", row), identifier("scr", row)))
            if row["small_change"]["admission"]:
                known.update(identifier("scj", row, c["check"]) for c in row["small_change"]["admission"]["checks"])
        for record in self.records.values():
            message = record["message"]
            if message["from"] != self.team + "/orchestrator" or message["message_id"] in known:
                continue
            if message["type"] == "dispatch" and message["to"] in {self.writer, self.reviewer}:
                raise Hold("small_change_mixed_queue", "foreign lane dispatch: " + message["message_id"])
            if message["type"] == "job_request" and self.row["terminal"] is not None:
                # A job packet is inert data. This reports overlap; it never gates the existing runner.
                raw = self.mailbox.brief(message["brief"])
                packet = strict_json(jobs.packet_text(raw))
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
