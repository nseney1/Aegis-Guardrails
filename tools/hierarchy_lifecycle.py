#!/usr/bin/env python3
"""Durable evidence for handoff obligations, separate from mailbox/job termination.

This is an evidence-only local journal, not an authenticated native decision or
execution service. Configured actor identities are provenance. No operation here
executes a packet, changes a workflow binding, or enables native dispatch.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import math
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (GIT_ID, SHA256, SLUG, digest, encoded, fields, integer,  # noqa: E402
                               matching, parse_time, publish_file, require, safe_path,
                               strict_json, text, timestamp, writer_lock)


POLICY = "aegis.lifecycle-policy/v1"
REQUEST = "aegis.lifecycle-request/v1"
JOURNAL = "aegis.lifecycle-event/v1"
ZERO = "0" * 64
MAX_EVENTS = 10000
MAX_REQUESTS = 256
MAX_BYTES = 1048576
ROLES = {"root", "router", "coordinator", "operator", "reviewer"}
PERMISSIONS = {"publish": {"coordinator", "router"}, "read": ROLES - {"root"}, "route": {"router"},
               "decision": {"root"}, "admit": {"operator"}, "wait": {"operator"}, "intent": {"operator"},
               "start": {"operator"}, "terminal": {"operator"}, "meter": {"operator"},
               "review": {"reviewer"}, "delivery": {"coordinator"}, "disposition": {"coordinator"},
               "resolve": {"coordinator"}, "succeed": ROLES}
GATES = {"source", "capability", "lease", "capacity", "observer", "job"}


def load_json(path):
    path = safe_path(path)
    require(stat.S_ISREG(path.stat().st_mode), "lifecycle input must be a regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "input exceeds lifecycle byte limit")
    try:
        return strict_json(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("malformed JSON") from exc


def evidence(value):
    require(isinstance(value, list) and 0 < len(value) <= 64, "evidence requires bounded nonempty references")
    for ref in value:
        fields(ref, {"path", "sha256"})
        safe_path(text(ref["path"], "evidence path"))
        matching(ref["sha256"], SHA256, "evidence sha256")
    # References are inert claims. Native qualification and artifact validation
    # must be supplied by a separately authenticated integration, never inferred.


def source(value):
    fields(value, {"commit", "tree", "dirty_sha256"})
    for key in ("commit", "tree"):
        matching(value[key], GIT_ID, "source " + key)
    matching(value["dirty_sha256"], SHA256, "source dirty sha256")


def raw_value(value):
    fields(value, {"raw", "sha256"})
    raw = text(value["raw"], "raw request", MAX_BYTES).encode("utf-8")
    matching(value["sha256"], SHA256, "raw request sha256")
    require(hashlib.sha256(raw).hexdigest() == value["sha256"], "raw request sha256 mismatch")
    try:
        return strict_json(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("malformed raw request JSON") from exc


def validate_request(raw):
    value = raw_value(raw)
    fields(value, {"schema", "id", "version", "team", "owner", "next_decision", "phase", "operation", "source",
                   "paths", "prerequisites", "authority", "continuation"})
    require(value["schema"] == REQUEST, "unsupported request schema")
    for key in ("id", "team", "phase", "operation", "authority"):
        matching(value[key], SLUG, key)
    integer(value["version"], "request version")
    for key in ("owner", "next_decision"):
        text(value[key], key)
    source(value["source"])
    require(isinstance(value["paths"], list) and 0 < len(value["paths"]) <= 256, "invalid request paths")
    for path in value["paths"]:
        safe_path(text(path, "request path"))
    require(isinstance(value["prerequisites"], list) and len(value["prerequisites"]) <= 256, "invalid prerequisites")
    for identifier in value["prerequisites"]:
        matching(identifier, SLUG, "prerequisite")
    require(value["id"] not in value["prerequisites"], "request cannot depend on itself")
    scope = value["continuation"]
    fields(scope, {"members", "max_starts", "expires_at"})
    integer(scope["max_starts"], "max_starts", maximum=256)
    parse_time(scope["expires_at"])
    require(isinstance(scope["members"], list) and len(scope["members"]) <= 255, "invalid continuation members")
    known = {value["id"]}
    for member in scope["members"]:
        fields(member, {"id", "sha256", "phase", "operation"})
        for key in ("id", "phase", "operation"):
            matching(member[key], SLUG, "continuation " + key)
        matching(member["sha256"], SHA256, "continuation sha256")
        require(member["id"] not in known, "duplicate continuation member")
        known.add(member["id"])
    require(value["authority"] == value["id"] or not scope["members"], "only authority request can extend continuation")
    return value


def validate_policy(value):
    fields(value, {"schema", "source", "authority", "actors", "current", "successors"})
    require(value["schema"] == POLICY, "unsupported lifecycle policy schema")
    source(value["source"])
    evidence(value["authority"])
    actors = value["actors"]
    require(isinstance(actors, dict) and 5 <= len(actors) <= 128, "invalid lifecycle actors")
    fields(value["current"], ROLES)
    for cid, actor in actors.items():
        matching(cid, SLUG, "actor CID")
        fields(actor, {"role", "generation", "profile", "cap_seconds"})
        require(actor["role"] in ROLES, "invalid actor role")
        integer(actor["generation"], "actor generation")
        integer(actor["cap_seconds"], "actor cap", maximum=86400 if actor["role"] == "root" else 3600)
        profile = actor["profile"]
        fields(profile, {"model", "effort", "tier", "filesystem", "tools"})
        for key in ("model", "effort", "tier", "filesystem"):
            text(profile[key], "profile " + key, 128)
        require(isinstance(profile["tools"], list) and all(isinstance(t, str) for t in profile["tools"]), "invalid profile tools")
        if actor["role"] == "root":
            require(profile["filesystem"] == "read-only" and set(profile["tools"]) <= {"read", "decide", "attest"},
                    "ROOT requires a read-only decision profile; effective enforcement remains unqualified")
        if actor["role"] == "router":
            require(profile["effort"] == "medium" and profile["tier"] == "ultrafast", "router requires medium/ultrafast")
    for role, cid in value["current"].items():
        require(cid in actors and actors[cid]["role"] == role, "current actor role mismatch")
    require(isinstance(value["successors"], dict), "invalid successor map")
    for old, new in value["successors"].items():
        require(old in actors and new in actors and old != new, "unknown successor identity")
        before, after = actors[old], actors[new]
        require(before["role"] == after["role"] and after["generation"] == before["generation"] + 1,
                "successor must advance the same role by one generation")
        require(before["profile"] == after["profile"] and before["cap_seconds"] == after["cap_seconds"],
                "succession cannot change profile or cap policy")
    return value


def initial_state(policy):
    return {"sequence": 0, "head": ZERO, "current": copy.deepcopy(policy["current"]), "requests": {},
            "decisions": [], "consumed": {}, "receipts": {},
            "meters": {cid: {"active_seconds": 0, "open_since": None} for cid in policy["actors"]}, "successions": []}


def active_seconds(state, cid, at):
    meter = state["meters"][cid]
    elapsed = max(0.0, (parse_time(at) - parse_time(meter["open_since"])).total_seconds()) if meter["open_since"] else 0
    return meter["active_seconds"] + elapsed


def checkpoint(policy, state):
    body = {"schema": "aegis.lifecycle-checkpoint/v1", "policy_sha256": digest(policy),
            "policy": policy, "state": state, "execution_enabled": False, "native_enforcement": "unqualified"}
    return {**body, "sha256": digest(body)}


def actor_for(policy, state, envelope):
    fields(envelope, {"id", "actor", "generation", "custody", "event"})
    matching(envelope["id"], SLUG, "event id")
    cid = envelope["actor"]
    require(isinstance(cid, str) and cid in policy["actors"], "unknown actor CID")
    actor = policy["actors"][cid]
    require(type(envelope["generation"]) is int and envelope["generation"] == actor["generation"], "stale actor generation")
    fields(envelope["custody"], {"cid", "generation"})
    root = state["current"]["root"]
    require(envelope["custody"] == {"cid": root, "generation": policy["actors"][root]["generation"]}, "stale ROOT custody")
    event = envelope["event"]
    require(isinstance(event, dict) and isinstance(event.get("type"), str), "invalid lifecycle event")
    kind = event["type"]
    require(kind in PERMISSIONS, "unknown lifecycle event")
    require(actor["role"] in PERMISSIONS[kind], "role %s cannot record %s" % (actor["role"], kind))
    if kind != "succeed":
        require(state["current"][actor["role"]] == cid, "actor generation is fenced")
    return cid, actor, event


def add_request(state, raw, publisher):
    value = validate_request(raw)
    existing = state["requests"].get(value["id"])
    if existing:
        require(existing["raw"] == raw, "request id conflicts with different bytes")
        return existing
    require(len(state["requests"]) < MAX_REQUESTS, "lifecycle request limit reached")
    row = {"request": value, "raw": raw, "publisher": publisher, "read": None, "routed": None,
           "admission": None, "wait": None, "intent": None, "start": None, "terminal": None,
           "results": [], "review": None, "delivery": None, "resolution": None, "dispositions": []}
    state["requests"][value["id"]] = row
    return row


def target(state, event):
    require(event["request_id"] in state["requests"], "unknown request id")
    row = state["requests"][event["request_id"]]
    require(event["request_sha256"] == row["raw"]["sha256"], "request sha256 mismatch")
    return row


def approved_authority(state, row, at):
    value = row["request"]
    parent = state["requests"].get(value["authority"])
    decisions = [d for d in state["decisions"] if d["request_id"] == value["authority"]]
    require(parent is not None and decisions and decisions[-1]["decision"] == "approve", "no approved bounded authority")
    scope = parent["request"]["continuation"]
    require(parse_time(at) < parse_time(scope["expires_at"]), "bounded authority expired")
    if parent is not row:
        expected = {"id": value["id"], "sha256": row["raw"]["sha256"], "phase": value["phase"], "operation": value["operation"]}
        require(expected in scope["members"], "request is outside approved continuation")
    require(state["consumed"].get(value["authority"], 0) < scope["max_starts"], "bounded authority exhausted")
    for prerequisite in value["prerequisites"]:
        prior = state["requests"].get(prerequisite)
        require(prior is not None and prior["resolution"] is not None and prior["resolution"]["kind"] == "complete",
                "prerequisite lacks accepted delivery")
    return value["authority"]


def unknown_effect(row):
    return row["intent"] is not None and (row["terminal"] is None or row["terminal"]["value"]["outcome"] == "unknown")


def resolve_row(state, row, resolution, cid):
    require(isinstance(resolution, dict), "invalid resolution")
    kind = resolution.get("kind")
    require(kind in {"complete", "next", "blocked"}, "invalid resolution kind")
    optional = {"request"} if kind == "next" else {"owner", "next_decision", "condition"} if kind == "blocked" else set()
    fields(resolution, {"kind", "evidence"} | optional)
    evidence(resolution["evidence"])
    if kind != "blocked":
        require(not unknown_effect(row), "unknown effect prevents closure")
    if kind == "complete":
        require(row["terminal"] is not None and row["terminal"]["value"]["outcome"] == "passed"
                and row["review"] is not None and row["review"]["verdict"] == "accept"
                and row["review"]["result_sha256"] == row["terminal"]["sha256"] and row["delivery"] is not None,
                "completion requires independent acceptance and delivery")
    elif kind == "next":
        following = validate_request(resolution["request"])
        require(following["id"] != row["request"]["id"], "next request cannot refer to itself")
        require(following["id"] not in state["requests"], "next request must be new; existing links require a new version")
        add_request(state, resolution["request"], cid)
        resolution = {"kind": kind, "request_id": following["id"], "request_sha256": resolution["request"]["sha256"],
                      "owner": following["owner"], "next_decision": following["next_decision"], "evidence": resolution["evidence"]}
    else:
        for key in ("owner", "next_decision", "condition"):
            text(resolution[key], key)
    row["resolution"] = resolution


def reduce_event(policy, state, envelope, at):
    cid, actor, event = actor_for(policy, state, envelope)
    kind = event["type"]
    if kind not in {"meter", "succeed", "terminal"}:
        require(active_seconds(state, cid, at) < actor["cap_seconds"], "actor cumulative active cap reached")
    mark = {"actor": cid, "generation": actor["generation"], "at": at}
    if kind == "publish":
        fields(event, {"type", "request"})
        add_request(state, event["request"], cid)
        return
    if kind == "meter":
        fields(event, {"type", "subject", "active_seconds", "open_since"})
        subject = event["subject"]
        require(subject in policy["actors"], "unknown meter subject")
        seconds = event["active_seconds"]
        require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= active_seconds(state, subject, at),
                "active meter cannot decrease or omit an open wait")
        if event["open_since"] is not None:
            require(parse_time(event["open_since"]) <= parse_time(at), "open wait cannot start in the future")
        state["meters"][subject] = {"active_seconds": seconds, "open_since": event["open_since"]}
        return
    if kind == "succeed":
        fields(event, {"type", "predecessor", "checkpoint_sha256"})
        old = event["predecessor"]
        require(policy["successors"].get(old) == cid and state["current"][actor["role"]] == old,
                "incoming actor must attest its own approved succession")
        require(event["checkpoint_sha256"] == checkpoint(policy, state)["sha256"], "checkpoint sha256 mismatch")
        state["current"][actor["role"]] = cid
        state["successions"].append({**mark, **event})
        return
    common = {"type", "request_id", "request_sha256"}
    # Validate role before payload, and a closed schema before dereferencing fields.
    extra = {"decision": {"decision", "reason"}, "read": set(), "route": {"to"}, "admit": {"source", "gates"},
             "wait": {"reason"}, "intent": {"intent_id"}, "start": {"intent_id"}, "terminal": {"result"},
             "review": {"result_sha256", "source", "verdict", "evidence"}, "delivery": {"evidence"},
             "disposition": {"status", "resolution"}, "resolve": {"blocker_sha256", "resolution"}}
    fields(event, common | extra[kind])
    row = target(state, event)
    value = row["request"]
    if row["resolution"] and row["resolution"]["kind"] in {"complete", "next"}:
        require(kind in {"read", "route", "decision"}, "closed request requires a new immutable version")
    if kind == "decision":
        require(value["authority"] == value["id"], "only the authority request can receive a decision")
        require(event["decision"] in {"approve", "deny"}, "decision must be approve or deny")
        text(event["reason"], "decision reason", 1024)
        prior = [d for d in state["decisions"] if d["request_id"] == value["id"]]
        require(not prior or (prior[-1]["decision"] == "approve" and event["decision"] == "deny"),
                "decision already recorded; use a new immutable request version")
        state["decisions"].append({**mark, **event})
    elif kind == "read":
        row["read"] = mark
    elif kind == "route":
        text(event["to"], "route recipient")
        row["routed"] = {**mark, "to": event["to"]}
    elif kind in {"admit", "intent"}:
        require(row["intent"] is None, "request already has an intent; settle its unknown effect")
        require(row["resolution"] is None, "disposed request cannot be admitted")
        authority = approved_authority(state, row, at)
        if kind == "admit":
            require(event["source"] == value["source"], "admission source mismatch")
            fields(event["gates"], GATES)
            for refs in event["gates"].values():
                evidence(refs)
            row["admission"] = {**mark, "gates": event["gates"], "source": event["source"]}
        else:
            require(row["admission"] is not None and row["admission"]["actor"] == cid,
                    "intent requires the current operator's separate admission")
            matching(event["intent_id"], SLUG, "intent id")
            require(all(r["intent"] is None or r["intent"]["id"] != event["intent_id"] for r in state["requests"].values()),
                    "intent id already belongs to another request")
            row["intent"] = {**mark, "id": event["intent_id"], "request_sha256": row["raw"]["sha256"],
                             "phase": value["phase"], "operation": value["operation"], "authority": authority}
            state["consumed"][authority] = state["consumed"].get(authority, 0) + 1
        if state["meters"][cid]["open_since"] is None:
            state["meters"][cid]["open_since"] = at
    elif kind == "wait":
        text(event["reason"], "wait reason", 1024)
        row["wait"] = {**mark, "reason": event["reason"]}
        if state["meters"][cid]["open_since"] is None:
            state["meters"][cid]["open_since"] = at
    elif kind == "start":
        require(row["intent"] is not None and row["intent"]["id"] == event["intent_id"], "start intent correlation mismatch")
        require(row["intent"]["actor"] == cid and row["start"] is None and row["terminal"] is None,
                "start requires its original current operator and an unresolved unstarted intent")
        approved = [d for d in state["decisions"] if d["request_id"] == value["authority"]]
        require(approved and approved[-1]["decision"] == "approve", "authority revoked before start")
        require(parse_time(at) < parse_time(state["requests"][value["authority"]]["request"]["continuation"]["expires_at"]),
                "bounded authority expired")
        row["start"] = {**mark, "intent_id": event["intent_id"]}
    elif kind == "terminal":
        result = raw_value(event["result"])
        fields(result, {"request_sha256", "intent_id", "outcome", "exit_code", "source", "evidence"})
        require(row["intent"] is not None and result["intent_id"] == row["intent"]["id"]
                and result["request_sha256"] == row["raw"]["sha256"], "terminal intent correlation mismatch")
        require(result["source"] == value["source"], "terminal source mismatch")
        require(result["outcome"] in {"passed", "failed", "unknown"}, "invalid terminal outcome")
        exit_code, outcome = result["exit_code"], result["outcome"]
        valid_exit = ((type(exit_code) is int and exit_code == 0) if outcome == "passed" else
                      (type(exit_code) is int and exit_code != 0) if outcome == "failed" else
                      (exit_code is None or type(exit_code) is int))
        require(valid_exit, "terminal exit code does not match outcome")
        evidence(result["evidence"])
        require(row["terminal"] is None or row["terminal"]["value"]["outcome"] == "unknown", "intent already has terminal evidence")
        row["terminal"] = {**mark, "sha256": event["result"]["sha256"], "raw": event["result"], "value": result}
        row["results"].append(row["terminal"])
        row["review"], row["delivery"] = None, None
    elif kind == "review":
        require(row["terminal"] is not None and event["result_sha256"] == row["terminal"]["sha256"], "review result sha256 mismatch")
        require(event["source"] == value["source"], "review source mismatch")
        require(cid != row["publisher"] and cid != row["intent"]["actor"], "reviewer must be independent")
        require(event["verdict"] in {"accept", "reject"}, "invalid review verdict")
        evidence(event["evidence"])
        row["review"] = {**mark, **event}
        row["delivery"] = None
    elif kind == "delivery":
        require(row["review"] is not None and row["review"]["verdict"] == "accept", "delivery requires independent acceptance")
        evidence(event["evidence"])
        row["delivery"] = {**mark, "evidence": event["evidence"]}
    else:
        if kind == "disposition":
            require(event["status"] in {"FINAL", "HOLD"}, "disposition must be FINAL or HOLD")
            require(row["resolution"] is None, "disposition already recorded; resolve the owned blocker explicitly")
        else:
            require(row["resolution"] is not None and row["resolution"]["kind"] == "blocked", "request has no owned blocker")
            require(event["blocker_sha256"] == digest(row["resolution"]), "blocker sha256 mismatch")
            require(isinstance(event["resolution"], dict), "invalid resolution")
            require(event["resolution"].get("kind") != "blocked", "blocker resolution must advance the obligation")
        resolve_row(state, row, event["resolution"], cid)
        row["dispositions"].append({**mark, **event})


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Lifecycle:
    def __init__(self, root):
        self.root = safe_path(root)

    def load(self):
        policy = validate_policy(load_json(self.root / "policy.json"))
        state = initial_state(policy)
        paths = sorted((self.root / "events").iterdir())
        require(len(paths) <= MAX_EVENTS, "lifecycle event limit reached")
        for index, path in enumerate(paths, 1):
            require(path.name == "%06d.json" % index, "journal gap or uncommitted entry: " + path.name)
            record = load_json(path)
            fields(record, {"schema", "sequence", "previous", "policy_sha256", "at", "envelope", "event_sha256"})
            require(record["schema"] == JOURNAL and type(record["sequence"]) is int and record["sequence"] == index,
                    "invalid journal sequence/schema")
            require(record["previous"] == state["head"], "journal hash chain mismatch")
            require(record["policy_sha256"] == digest(policy), "journal policy sha256 mismatch")
            require(record["event_sha256"] == digest(record["envelope"]), "journal event sha256 mismatch")
            parse_time(record["at"])
            identifier = record["envelope"]["id"]
            require(identifier not in state["receipts"], "duplicate journal event id")
            reduce_event(policy, state, record["envelope"], record["at"])
            self.finish(state, record)
        return policy, state

    @staticmethod
    def finish(state, record):
        state["sequence"] = record["sequence"]
        state["head"] = digest(record)
        receipt = {"event_id": record["envelope"]["id"], "sequence": record["sequence"],
                   "event_sha256": record["event_sha256"], "execution_enabled": False}
        state["receipts"][receipt["event_id"]] = receipt
        return receipt

    def record(self, envelope):
        require(os.name == "posix", "durable lifecycle mutation requires POSIX directory fsync")
        with writer_lock(self.root):
            policy, state = self.load()
            fields(envelope, {"id", "actor", "generation", "custody", "event"})
            matching(envelope["id"], SLUG, "event id")
            previous = state["receipts"].get(envelope["id"])
            if previous:
                require(previous["event_sha256"] == digest(envelope), "event id conflicts with different bytes")
                # A committed receipt is a read, even after a generation changed.
                # Never reapply it or use it as authority for a new event.
                return previous
            actor_for(policy, state, envelope)
            require(state["sequence"] < MAX_EVENTS, "lifecycle event limit reached")
            record = {"schema": JOURNAL, "sequence": state["sequence"] + 1, "previous": state["head"],
                      "policy_sha256": digest(policy), "at": timestamp(), "envelope": envelope, "event_sha256": digest(envelope)}
            reduce_event(policy, state, envelope, record["at"])
            publish_file(self.root / "events" / ("%06d.json" % record["sequence"]), encoded(record) + b"\n", limit=MAX_BYTES)
            sync_directory(self.root / "events")
            return self.finish(state, record)

    def status(self):
        policy, state = self.load()
        obligations, candidates, holds = [], [], {}
        at = timestamp()
        for identifier, row in sorted(state["requests"].items()):
            resolution = row["resolution"]
            if resolution and resolution["kind"] in {"complete", "next"}:
                continue
            owner = resolution if resolution else row["request"]
            stage = "unknown_effect" if unknown_effect(row) else "blocked" if resolution else "pending"
            obligations.append({"request_id": identifier, "request_sha256": row["raw"]["sha256"], "state": stage,
                                "owner": owner["owner"], "next_decision": owner["next_decision"],
                                "blocker": resolution if resolution and resolution["kind"] == "blocked" else None})
            if not resolution and row["intent"] is None:
                try:
                    operator = state["current"]["operator"]
                    require(active_seconds(state, operator, at) < policy["actors"][operator]["cap_seconds"],
                            "actor cumulative active cap reached")
                    approved_authority(state, row, at)
                except ValueError as exc:
                    holds[identifier] = str(exc)
                else:
                    candidates.append(identifier)
        return {"schema": "aegis.lifecycle-status/v1", "state": "pending" if obligations else "complete" if state["requests"] else "untracked",
                "work_complete": bool(state["requests"]) and not obligations, "coverage": "registered_requests_only",
                "execution_enabled": False, "native_enforcement": "unqualified", "policy_sha256": digest(policy),
                "obligations": obligations, "continuation_candidates": candidates, "continuation_holds": holds, **state}


def initialize(root, policy):
    require(os.name == "posix", "durable lifecycle mutation requires POSIX directory fsync")
    validate_policy(policy)
    require(not root.exists(), "lifecycle root already exists")
    root.mkdir(mode=0o700)
    (root / "events").mkdir(mode=0o700)
    publish_file(root / "policy.json", encoded(policy) + b"\n", limit=MAX_BYTES)
    sync_directory(root)
    sync_directory(root.parent)
    return {"policy_sha256": digest(policy), "execution_enabled": False, "native_enforcement": "unqualified"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--policy", required=True)
    init.add_argument("--evidence-only", action="store_true")
    record = commands.add_parser("record")
    record.add_argument("--event", required=True)
    record.add_argument("--evidence-only", action="store_true")
    commands.add_parser("status")
    commands.add_parser("checkpoint")
    args = parser.parse_args(argv)
    try:
        root = safe_path(args.root)
        if args.command in {"init", "record"}:
            require(args.evidence_only, "mutation requires --evidence-only; native adapter is unqualified")
        if args.command == "init":
            result = initialize(root, load_json(args.policy))
        elif args.command == "record":
            result = Lifecycle(root).record(load_json(args.event))
        elif args.command == "checkpoint":
            result = checkpoint(*Lifecycle(root).load())
        else:
            result = Lifecycle(root).status()
    except (ValueError, OSError, UnicodeError, RecursionError, TypeError, KeyError) as exc:
        result = {"state": "hold", "work_complete": False, "execution_enabled": False, "error": str(exc)}
        print(encoded(result).decode())
        return 2
    print(encoded(result).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
