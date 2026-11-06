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
from pathlib import Path, PurePosixPath
import stat
import sys
import uuid

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
ROLES = {"root", "router", "coordinator", "operator", "reviewer", "decider"}
# A policy may omit these, so policies written before the role existed still load.
OPTIONAL_ROLES = {"decider"}
INITIAL_ENVELOPE = "aegis.initial-bootstrap-envelope/v1"
UINT64 = (1 << 64) - 1
PERMISSIONS = {"publish": {"coordinator", "router"}, "read": {"router", "coordinator", "operator", "reviewer"},
               "route": {"router"}, "decision": {"root"}, "delegated_decision": {"decider"}, "admit": {"operator"}, "wait": {"operator"}, "intent": {"operator"},
               "start": {"operator"}, "terminal": {"operator"}, "meter": {"operator"},
               "review": {"reviewer"}, "delivery": {"coordinator"}, "disposition": {"coordinator"},
               "resolve": {"coordinator"}, "succeed": ROLES,
               "associate": {"operator"}, "observe": {"operator"}, "cancel_attempt": {"operator"}}
GATES = {"source", "capability", "lease", "capacity", "observer", "job"}
PROVIDER_STATES = {"not_started", "running", "disconnected", "ambiguous", "cancel_requested",
                   "cancelled", "passed", "failed", "unknown"}


def provider_handle(row):
    for observation in row.get("observations", []):
        handle = observation["value"]["provider_handle"]
        if handle is not None:
            return handle
    return None


def validate_observation(row, value):
    fields(value, {"association_sha256", "provider_state", "provider_handle", "exit_code", "evidence", "quiescent"})
    require(value["association_sha256"] == row["association"]["sha256"], "provider association sha256 mismatch")
    require(isinstance(value["provider_state"], str) and value["provider_state"] in PROVIDER_STATES,
            "invalid provider state")
    require(type(value["quiescent"]) is bool, "invalid provider quiescence")
    handle = value["provider_handle"]
    if handle is not None:
        fields(handle, {"thread_id", "turn_id"})
        for name in handle:
            text(handle[name], "provider " + name, 256)
        require(handle["thread_id"] == row["association"]["value"]["thread_id"], "provider thread mismatch")
        known = provider_handle(row)
        require(known is None or known == handle, "provider handle changed")
    state, code = value["provider_state"], value["exit_code"]
    if state in {"passed", "failed", "cancelled"}:
        require(handle is not None and value["quiescent"] is True, "terminal provider evidence requires owned quiescence")
        require(type(code) is int and (code == 0 if state == "passed" else code != 0),
                "terminal exit code does not match outcome")
    else:
        require(code is None and value["quiescent"] is False, "nonterminal provider observation cannot claim quiescence")
    evidence(value["evidence"])
    return value


def validate_association(policy, state, row, value, cid, at):
    fields(value, {"schema", "request_id", "request_sha256", "intent_id", "source", "authority", "authority_sha256",
                   "decision_sha256", "admission_sha256", "original_actor", "original_generation", "original_cap_seconds",
                   "authority_expires_at", "provider", "endpoint_id", "thread_id", "client_id", "deadline"})
    require(value["schema"] == "aegis.provider-association/v1", "unsupported provider association schema")
    request = row["request"]
    require(row["intent"] is not None and row["start"] is not None, "association requires a started canonical intent")
    require(row["intent"]["actor"] == cid, "association requires its original current operator")
    require(row["terminal"] is None and row.get("association") is None, "canonical intent already has an association or result")
    authority = state["requests"][request["authority"]]
    decisions = [d for d in state["decisions"] if d["request_id"] == request["authority"]]
    require(decisions and decisions[-1]["decision"] == "approve", "authority revoked before effect")
    expected = {"request_id": request["id"], "request_sha256": row["raw"]["sha256"],
                "intent_id": row["intent"]["id"], "source": request["source"], "authority": request["authority"],
                "authority_sha256": authority["raw"]["sha256"], "decision_sha256": digest(decisions[-1]),
                "admission_sha256": digest(row["admission"]), "original_actor": cid,
                "original_generation": policy["actors"][cid]["generation"],
                "original_cap_seconds": policy["actors"][cid]["cap_seconds"],
                "authority_expires_at": authority["request"]["continuation"]["expires_at"],
                "client_id": "client-" + row["intent"]["id"]}
    require(all(value[k] == v for k, v in expected.items()), "canonical provider association mismatch")
    integer(value["original_generation"], "original generation")
    integer(value["original_cap_seconds"], "original cap", maximum=3600)
    for name, limit in (("provider", 128), ("endpoint_id", 128), ("thread_id", 256), ("client_id", 256)):
        text(value[name], "provider " + name, limit)
    require(parse_time(at) < parse_time(value["deadline"]) <= parse_time(value["authority_expires_at"]),
            "execution deadline expired or exceeds authority")
    require((parse_time(value["deadline"]) - parse_time(at)).total_seconds()
            <= policy["actors"][cid]["cap_seconds"] - active_seconds(state, cid, at),
            "execution deadline exceeds original actor cap")
    return value


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
    fields(value["current"], ROLES - OPTIONAL_ROLES, OPTIONAL_ROLES)
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


def _initial_process(value):
    fields(value, {"boot_id", "pid_namespace", "pid", "start_ticks"})
    boot = value["boot_id"]
    require(isinstance(boot, str) and str(uuid.UUID(boot)) == boot, "invalid bootstrap boot id")
    integer(value["pid"], "bootstrap process id", maximum=2147483647)
    for name in ("pid_namespace", "start_ticks"):
        integer(value[name], "bootstrap " + name, maximum=UINT64)


def _initial_channel(value):
    fields(value, {"schema", "runtime_instance", "appserver_instance", "control_peer_instance",
                   "read_pipe_inode", "write_pipe_inode", "epoch", "deployment_sha256",
                   "runtime_executable_sha256", "host_source_closure_sha256", "role_ceiling_sha256"})
    require(value["schema"] == "aegis.host-channel-witness/v1", "unsupported bootstrap channel schema")
    for name in ("runtime_instance", "appserver_instance", "control_peer_instance"):
        _initial_process(value[name])
    for name in ("read_pipe_inode", "write_pipe_inode", "epoch"):
        integer(value[name], "bootstrap " + name, maximum=UINT64)
    require(value["read_pipe_inode"] != value["write_pipe_inode"], "bootstrap pipe directions alias")
    for name in ("deployment_sha256", "runtime_executable_sha256", "host_source_closure_sha256",
                 "role_ceiling_sha256"):
        matching(value[name], SHA256, "bootstrap " + name)


def _initial_key(policy, cid):
    return "initial-" + digest({"schema": "aegis.initial-creation-key/v1",
                                "policy_sha256": digest(policy), "actor_cid": cid})[:40]


def _reduce_initial(policy, state, envelope):
    """Validate inert bootstrap journal evidence, without authenticating a host."""
    fields(envelope, {"schema", "id", "event"})
    require(envelope["schema"] == INITIAL_ENVELOPE, "unsupported bootstrap envelope schema")
    matching(envelope["id"], SLUG, "event id")
    event = envelope["event"]
    require(isinstance(event, dict), "expected a JSON object")
    if event.get("type") == "initial_reservations":
        fields(event, {"type", "approved_plan", "channel_witness", "reservations"})
        require(envelope["id"] == "initial-genesis" and state["sequence"] == 0
                and "initial_bootstrap" not in state, "initial genesis must be the first journal event")
        evidence([event["approved_plan"]])
        require(policy["authority"] == [event["approved_plan"]], "bootstrap approved plan mismatch")
        _initial_channel(event["channel_witness"])
        channel_sha256 = digest(event["channel_witness"])
        rows = event["reservations"]
        require(isinstance(rows, list) and 5 <= len(rows) <= 128, "invalid bootstrap reservation set")
        cids, sequences = [], set()
        for row in rows:
            fields(row, {"schema", "channel_instance_sha256", "approved_plan_sha256", "actor_cid",
                         "role", "generation", "profile_sha256", "cap_seconds", "reservation_sequence",
                         "expires_monotonic_ns"})
            require(row["schema"] == "aegis.host-reservation-witness/v1",
                    "unsupported bootstrap reservation schema")
            cid = row["actor_cid"]
            matching(cid, SLUG, "bootstrap actor CID")
            require(cid in policy["actors"], "unknown bootstrap actor CID")
            actor = policy["actors"][cid]
            integer(row["generation"], "bootstrap generation", maximum=UINT64)
            integer(row["cap_seconds"], "bootstrap cap", maximum=86400 if actor["role"] == "root" else 3600)
            integer(row["reservation_sequence"], "bootstrap reservation sequence", maximum=UINT64)
            integer(row["expires_monotonic_ns"], "bootstrap reservation expiry", maximum=UINT64)
            require(row["role"] == actor["role"] and row["generation"] == actor["generation"]
                    and row["profile_sha256"] == digest(actor["profile"])
                    and row["cap_seconds"] == actor["cap_seconds"]
                    and row["approved_plan_sha256"] == event["approved_plan"]["sha256"]
                    and row["channel_instance_sha256"] == channel_sha256,
                    "bootstrap reservation correlation mismatch")
            require(row["reservation_sequence"] not in sequences, "duplicate bootstrap reservation sequence")
            sequences.add(row["reservation_sequence"])
            cids.append(cid)
        require(cids == sorted(policy["actors"]), "bootstrap reservations must match all planned actors")
        state["initial_bootstrap"] = {"genesis": {"envelope": copy.deepcopy(envelope)},
                                      "reservations": copy.deepcopy(rows), "creations": {}}
        return
    require(event.get("type") == "initial_creation", "unknown bootstrap event")
    fields(event, {"type", "genesis_event_sha256", "approved_plan_sha256", "reservation_set_sha256",
                   "actor_cid", "role", "generation", "profile_sha256", "cap_seconds",
                   "channel_instance_sha256", "reservation_witness_sha256"})
    require("initial_bootstrap" in state, "initial bootstrap genesis missing")
    bootstrap = state["initial_bootstrap"]
    cid = event["actor_cid"]
    matching(cid, SLUG, "bootstrap actor CID")
    require(cid in policy["current"].values(), "INITIAL creation requires an original current actor")
    actor = policy["actors"][cid]
    require(state["current"].get(actor["role"]) == cid, "INITIAL actor generation is fenced")
    require(cid not in bootstrap["creations"], "INITIAL creation already recorded")
    integer(event["generation"], "bootstrap generation", maximum=UINT64)
    integer(event["cap_seconds"], "bootstrap cap", maximum=86400 if actor["role"] == "root" else 3600)
    row = next(row for row in bootstrap["reservations"] if row["actor_cid"] == cid)
    expected = {name: row[name] for name in ("actor_cid", "role", "generation", "profile_sha256",
                                            "cap_seconds", "channel_instance_sha256", "approved_plan_sha256")}
    expected.update(type="initial_creation", genesis_event_sha256=digest(bootstrap["genesis"]["envelope"]),
                    reservation_set_sha256=digest(bootstrap["reservations"]),
                    reservation_witness_sha256=digest(row))
    require(event == expected and envelope["id"] == _initial_key(policy, cid),
            "INITIAL creation correlation mismatch")
    bootstrap["creations"][cid] = {"actor_cid": cid, "envelope": copy.deepcopy(envelope)}


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
        require(state["current"].get(actor["role"]) == cid, "actor generation is fenced")
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
    # ROOT's approval of a delegation is the Decider's scope; it must never also start work or spend that budget.
    require(parent["request"]["operation"] != "delegate-merge", "a delegation authorizes the Decider, not work")
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


def covered(scope, path):
    """Component-wise, so /a/b covers /a/b/c and /a/b/ but never /a/b-two."""
    parts = PurePosixPath(path).parts
    return any(parts[:len(PurePosixPath(granted).parts)] == PurePosixPath(granted).parts for granted in scope)


def delegated_decision(state, row, event, mark):
    """Record the Decider's approve or escalate. It is non-admitting: it never touches decisions,
    consumed or approved_authority, so nothing it records makes a request admissible."""
    value, cid, at = row["request"], mark["actor"], mark["at"]
    require(event["delegation_id"] in state["requests"], "unknown delegation id")
    parent = state["requests"][event["delegation_id"]]
    require(event["delegation_sha256"] == parent["raw"]["sha256"], "delegation sha256 mismatch")
    require(event["decision"] in {"approve", "escalate"}, "delegated decision must be approve or escalate")
    matching(event["commit"], GIT_ID, "reviewed commit")
    evidence(event["review"])
    text(event["reason"], "delegated decision reason", 1024)
    require(parent is not row, "a delegation cannot be its own target")
    grant = parent["request"]
    require(grant["operation"] == "delegate-merge" and grant["authority"] == grant["id"]
            and not grant["continuation"]["members"],
            "delegation must be a delegate-merge authority request with no continuation members")
    # Only an authority request can take a ROOT decision, so only one can be escalated to ROOT.
    require(value["authority"] == value["id"], "the target must be an authority request")
    # Lazy key, like the provider association: legacy replays and checkpoints keep their exact bytes.
    recorded = state.get("delegated_decisions", [])
    require(all(d["request_id"] != value["id"] for d in recorded), "target already has a delegated decision")
    require(all(d["request_id"] != value["id"] for d in state["decisions"]), "ROOT already decided the target")
    if event["decision"] == "approve":
        require(value["operation"] == "merge", "delegate-merge can approve only merge requests")
        decisions = [d for d in state["decisions"] if d["request_id"] == grant["id"]]
        require(decisions and decisions[-1]["decision"] == "approve", "delegation is not approved by ROOT")
        require(parse_time(at) < parse_time(grant["continuation"]["expires_at"]), "delegation expired")
        require(grant["team"] == value["team"], "delegation is for another team")
        require(all(PurePosixPath(granted).parts != ("/",) for granted in grant["paths"]),
                "a delegation cannot cover the whole filesystem")
        require(all(covered(grant["paths"], path) for path in value["paths"]),
                "target path is outside the delegation's paths")
        used = sum(1 for d in recorded if d["delegation_id"] == grant["id"] and d["decision"] == "approve")
        require(used < grant["continuation"]["max_starts"], "delegation has no approvals left")
        require(event["commit"] == value["source"]["commit"], "reviewed commit is not the target's source commit")
        require(cid != row["publisher"], "the decider cannot decide a request it published")
    state["delegated_decisions"] = recorded + [{**mark, **event}]


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
    if isinstance(envelope, dict) and envelope.get("schema") == INITIAL_ENVELOPE:
        return _reduce_initial(policy, state, envelope)
    cid, actor, event = actor_for(policy, state, envelope)
    kind = event["type"]
    if kind not in {"meter", "succeed", "terminal", "observe"}:
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
        require(policy["successors"].get(old) == cid and state["current"].get(actor["role"]) == old,
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
             "disposition": {"status", "resolution"}, "resolve": {"blocker_sha256", "resolution"},
             "associate": {"association"}, "observe": {"intent_id", "association_sha256", "observation"},
             "cancel_attempt": {"intent_id", "association_sha256", "reason"},
             "delegated_decision": {"delegation_id", "delegation_sha256", "commit", "review", "decision", "reason"}}
    fields(event, common | extra[kind])
    row = target(state, event)
    value = row["request"]
    if row["resolution"] and row["resolution"]["kind"] in {"complete", "next"}:
        require(kind in {"read", "route", "decision"}, "closed request requires a new immutable version")
    if kind == "associate":
        binding = validate_association(policy, state, row, event["association"], cid, at)
        # Lazy projection is essential: old succession events hash the exact old
        # state. Do not add these keys when replaying any legacy event.
        row["association"] = {**mark, "value": binding, "sha256": digest(binding)}
        row["observations"], row["cancellation"] = [], None
    elif kind in {"observe", "cancel_attempt"}:
        require(row.get("association") is not None, "canonical provider association is unavailable")
        require(event["intent_id"] == row["intent"]["id"]
                and event["association_sha256"] == row["association"]["sha256"], "canonical association correlation changed")
        require(row["terminal"] is None or row["terminal"]["value"]["outcome"] == "unknown", "intent already has terminal evidence")
        if kind == "observe":
            value = validate_observation(row, event["observation"])
            row["observations"].append({**mark, "value": value})
        else:
            require(row.get("cancellation") is None, "canonical cancellation already attempted; observe its effect")
            require(provider_handle(row) is not None, "owned provider handle is unavailable")
            text(event["reason"], "cancellation reason", 1024)
            row["cancellation"] = {**mark, "reason": event["reason"]}
    elif kind == "decision":
        require(value["authority"] == value["id"], "only the authority request can receive a decision")
        require(event["decision"] in {"approve", "deny"}, "decision must be approve or deny")
        text(event["reason"], "decision reason", 1024)
        prior = [d for d in state["decisions"] if d["request_id"] == value["id"]]
        require(not prior or (prior[-1]["decision"] == "approve" and event["decision"] == "deny"),
                "decision already recorded; use a new immutable request version")
        state["decisions"].append({**mark, **event})
    elif kind == "delegated_decision":
        delegated_decision(state, row, event, mark)
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


class _InitialBootstrapMissing(ValueError):
    pass


class Lifecycle:
    def __init__(self, root):
        self.root = safe_path(root)

    def load(self):
        policy, state, _ = self._replay()
        return policy, state

    def _replay(self):
        policy = validate_policy(load_json(self.root / "policy.json"))
        state = initial_state(policy)
        genesis_checkpoint = None
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
            if record["envelope"].get("schema") == INITIAL_ENVELOPE and index == 1:
                genesis_checkpoint = copy.deepcopy(checkpoint(policy, state))
        return policy, state, genesis_checkpoint

    def initial_bootstrap(self):
        """Return validated original INITIAL evidence, never a native grant."""
        policy, state, genesis_checkpoint = self._replay()
        if genesis_checkpoint is None:
            raise _InitialBootstrapMissing("initial bootstrap genesis missing")
        bootstrap = state["initial_bootstrap"]
        return {"schema": "aegis.initial-bootstrap-snapshot/v1", "policy_sha256": digest(policy),
                "genesis_checkpoint": genesis_checkpoint,
                "genesis_receipt": copy.deepcopy(bootstrap["genesis"]["receipt"]),
                "reservations": copy.deepcopy(bootstrap["reservations"]),
                "creations": [copy.deepcopy(bootstrap["creations"][cid])
                              for cid in sorted(bootstrap["creations"])]}

    @staticmethod
    def finish(state, record):
        state["sequence"] = record["sequence"]
        state["head"] = digest(record)
        receipt = {"event_id": record["envelope"]["id"], "sequence": record["sequence"],
                   "event_sha256": record["event_sha256"], "execution_enabled": False}
        state["receipts"][receipt["event_id"]] = receipt
        envelope = record["envelope"]
        if envelope.get("schema") == INITIAL_ENVELOPE:
            bootstrap = state["initial_bootstrap"]
            if envelope["event"]["type"] == "initial_reservations":
                bootstrap["genesis"]["receipt"] = copy.deepcopy(receipt)
            else:
                bootstrap["creations"][envelope["event"]["actor_cid"]]["receipt"] = copy.deepcopy(receipt)
        return receipt

    def record(self, envelope):
        require(os.name == "posix", "durable lifecycle mutation requires POSIX directory fsync")
        with writer_lock(self.root):
            policy, state = self.load()
            return self._record_under_lock(envelope, policy, state)

    def _record_under_lock(self, envelope, policy, state):
        """Append to the caller's loaded state while its writer lock is held.

        Only record() and the evidence-only Operator transaction own this seam.
        It does not acquire/reenter a lock or establish native authority.
        """
        fields(envelope, {"id", "actor", "generation", "custody", "event"})
        matching(envelope["id"], SLUG, "event id")
        previous = state["receipts"].get(envelope["id"])
        if previous:
            require(previous["event_sha256"] == digest(envelope), "event id conflicts with different bytes")
            return previous
        actor_for(policy, state, envelope)
        require(state["sequence"] < MAX_EVENTS, "lifecycle event limit reached")
        record = {"schema": JOURNAL, "sequence": state["sequence"] + 1, "previous": state["head"],
                  "policy_sha256": digest(policy), "at": timestamp(), "envelope": envelope, "event_sha256": digest(envelope)}
        reduce_event(policy, state, envelope, record["at"])
        # Admission of NEW approvals only; load() replays historical bytes.
        event = envelope["event"]
        if event["type"] == "decision" and event["decision"] == "approve":
            authority = state["requests"][event["request_id"]]["request"]
            require(parse_time(record["at"]) < parse_time(authority["continuation"]["expires_at"]),
                    "bounded authority expired")
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


def _prepare_initial(policy, state, envelope):
    require(state["sequence"] < MAX_EVENTS, "lifecycle event limit reached")
    record = {"schema": JOURNAL, "sequence": state["sequence"] + 1, "previous": state["head"],
              "policy_sha256": digest(policy), "at": timestamp(), "envelope": envelope,
              "event_sha256": digest(envelope)}
    candidate = copy.deepcopy(state)
    reduce_event(policy, candidate, envelope, record["at"])
    require(len(encoded(record)) + 1 <= MAX_BYTES, "bootstrap event exceeds lifecycle byte limit")
    return record, Lifecycle.finish(candidate, record)


def _publish_initial(root, record):
    publish_file(root / "events" / ("%06d.json" % record["sequence"]),
                 encoded(record) + b"\n", limit=MAX_BYTES)
    sync_directory(root / "events")


_GENESIS_REASONS = {
    "HOST_AUTHORITY_REFUSED": "current protected host authority is required",
    "PLAN_MISMATCH": "protected bootstrap plan does not match",
    "POLICY_INVALID": "protected bootstrap evidence is invalid",
    "ROOT_ALREADY_EXISTS": "protected canonical root already exists",
    "GENESIS_PUBLICATION_UNKNOWN": "canonical genesis may have been published; retain the original root and reservations",
}


class CanonicalGenesisError(PermissionError):
    """Closed genesis refusal/ambiguity; no implicit retry or cleanup grant."""

    __slots__ = ("_code", "_possible")

    def __init__(self, code, *, possible=False):
        self._code, self._possible = code, possible
        super().__init__(_GENESIS_REASONS[code])

    @property
    def code(self):
        return self._code

    @property
    def reason(self):
        return _GENESIS_REASONS[self._code]

    @property
    def state(self):
        return "unknown" if self._possible else "refused"

    @property
    def effect(self):
        return "possible" if self._possible else "none"


class ProtectedCanonicalEnrollmentWriter:
    """Fixed-root protected genesis; only actual H source constructs its guard."""

    def __init__(self, root, authority):
        self.root, self.authority = safe_path(root), authority

    def initialize_reserved_genesis(self, owned_runtime, reserved_enrollments, approved_plan_ref):
        from tools import hierarchy_host_authority as host

        claimed = False
        try:
            if (type(self.authority) is not host.HostAuthority
                    or self.authority.owned_runtime is not owned_runtime):
                raise CanonicalGenesisError("HOST_AUTHORITY_REFUSED")
            # These are inert copies of already authenticated protected inputs.
            # No caller-selected plan file is opened, or read back under a fence.
            if (self.root != owned_runtime.canonical_root
                    or approved_plan_ref != owned_runtime.approved_plan_ref):
                raise CanonicalGenesisError("PLAN_MISMATCH")
            plan = owned_runtime.accepted_plan
            fields(plan, {"source", "actors", "current", "successors"})
            evidence([approved_plan_ref])
            policy = validate_policy({"schema": POLICY, "authority": [copy.deepcopy(approved_plan_ref)], **plan})
            require(len(encoded(policy)) + 1 <= MAX_BYTES, "bootstrap policy exceeds lifecycle byte limit")
            require(isinstance(reserved_enrollments, tuple), "bootstrap requires owned reservation tuple")
            rows = []
            for reservation in reserved_enrollments:
                if type(reservation) is not host.ReservedEnrollment:
                    raise CanonicalGenesisError("HOST_AUTHORITY_REFUSED")
                rows.append(reservation.witness)
            envelope = {"schema": INITIAL_ENVELOPE, "id": "initial-genesis",
                        "event": {"type": "initial_reservations", "approved_plan": copy.deepcopy(approved_plan_ref),
                                  "channel_witness": owned_runtime.channel_witness, "reservations": rows}}
            record, _ = _prepare_initial(policy, initial_state(policy), envelope)
            with self.authority.bootstrap_fence(owned_runtime, approved_plan_ref, reserved_enrollments) as guard:
                guard.require_reserved_genesis_current()
                # Existing-root refusal is known not to claim it. Other errors
                # during this exclusive claim conservatively retain UNKNOWN.
                claimed = True
                try:
                    self.root.mkdir(mode=0o700)
                except FileExistsError:
                    claimed = False
                    raise CanonicalGenesisError("ROOT_ALREADY_EXISTS")
                with writer_lock(self.root):
                    guard.require_reserved_genesis_current()
                    (self.root / "events").mkdir(mode=0o700)
                    guard.require_reserved_genesis_current()
                    publish_file(self.root / "policy.json", encoded(policy) + b"\n", limit=MAX_BYTES)
                    guard.require_reserved_genesis_current()
                    _publish_initial(self.root, record)
                    sync_directory(self.root)
                    sync_directory(self.root.parent)
                    snapshot = Lifecycle(self.root).initial_bootstrap()
                    enrollments = []
                    for row in snapshot["reservations"]:
                        item = {name: row[name] for name in ("actor_cid", "role", "generation", "profile_sha256",
                                                            "cap_seconds", "channel_instance_sha256")}
                        item["reservation_witness_sha256"] = digest(row)
                        enrollments.append(item)
                    answer = {"schema": "aegis.protected-reserved-enrollment-receipt/v1",
                              "policy_sha256": snapshot["policy_sha256"],
                              "checkpoint_sha256": snapshot["genesis_checkpoint"]["sha256"],
                              "enrollments": enrollments}
                    guard.require_reserved_genesis_current()
                    return answer
        except CanonicalGenesisError as exc:
            if claimed:
                raise CanonicalGenesisError("GENESIS_PUBLICATION_UNKNOWN", possible=True) from exc
            raise
        except host.HostAuthorityError as exc:
            code = "GENESIS_PUBLICATION_UNKNOWN" if claimed else "HOST_AUTHORITY_REFUSED"
            raise CanonicalGenesisError(code, possible=claimed) from exc
        except (ValueError, OSError) as exc:
            code = "GENESIS_PUBLICATION_UNKNOWN" if claimed else "POLICY_INVALID"
            raise CanonicalGenesisError(code, possible=claimed) from exc


_INITIAL_REASONS = {
    "HOST_AUTHORITY_REFUSED": "current protected INITIAL authority is required",
    "INITIAL_GENESIS_REQUIRED": "protected INITIAL genesis is required",
    "INITIAL_CREATION_FORBIDDEN": "INITIAL creation requires its original current actor",
    "INITIAL_CORRELATION_MISMATCH": "protected INITIAL correlation does not match",
    "INITIAL_EVENT_CONFLICT": "INITIAL event identity conflicts with original evidence",
    "CANONICAL_INVALID": "canonical INITIAL history is invalid",
    "CANONICAL_BUSY": "canonical writer exclusion is busy",
    "INITIAL_CREATION_PUBLICATION_UNKNOWN": "INITIAL intent may have been published; retain its original identity",
}


def _initial_result(state, *, code=None, cid=None, event_id=None, receipt=None):
    return {"schema": "aegis.initial-creation-result/v1", "state": state,
            "effect": {"recorded": "canonical_initial_creation", "recovered": "none",
                       "refused": "none", "unknown": "possible"}[state],
            "code": code, "reason": _INITIAL_REASONS[code] if code else None,
            "actor_cid": cid, "event_id": event_id, "receipt": copy.deepcopy(receipt),
            "native_qualified": False}


def _initial_creation_envelope(policy, snapshot, witness):
    event = {name: witness[name] for name in ("actor_cid", "role", "generation", "profile_sha256",
                                             "cap_seconds", "channel_instance_sha256", "approved_plan_sha256")}
    event.update(type="initial_creation", genesis_event_sha256=snapshot["genesis_receipt"]["event_sha256"],
                 reservation_set_sha256=digest(snapshot["reservations"]), reservation_witness_sha256=digest(witness))
    return {"schema": INITIAL_ENVELOPE, "id": _initial_key(policy, witness["actor_cid"]), "event": event}


class ProtectedCanonicalBootstrapWriter:
    """Commit one INITIAL intent; never bind or start a runtime from a receipt."""

    def __init__(self, root):
        self.root = safe_path(root)

    def commit_initial_creation(self, bootstrap_guard, reserved_enrollment):
        from tools import hierarchy_host_authority as host

        possible, cid, identifier = False, None, None

        def refused(code):
            return _initial_result("refused", code=code, cid=cid, event_id=identifier)

        try:
            if (type(bootstrap_guard) is not host.InitialCreationGuard
                    or type(reserved_enrollment) is not host.ReservedEnrollment):
                return refused("HOST_AUTHORITY_REFUSED")
            bootstrap_guard.require_initial_identity_current(reserved_enrollment)
            if self.root != reserved_enrollment.owned_runtime.canonical_root:
                return refused("INITIAL_CORRELATION_MISMATCH")
            with writer_lock(self.root):
                bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                reader = Lifecycle(self.root)
                policy, state = reader.load()
                snapshot = reader.initial_bootstrap()
                bootstrap_guard.require_initial_creation_current(reserved_enrollment, policy, state, None)
                cid = reserved_enrollment.actor_cid
                identifier = _initial_key(policy, cid)
                original = next((row for row in snapshot["creations"] if row["actor_cid"] == cid), None)
                if original is not None:
                    bootstrap_guard.require_initial_creation_current(reserved_enrollment, policy, state, original)
                    expected = _initial_creation_envelope(policy, snapshot, reserved_enrollment.witness)
                    if (original["envelope"] != expected
                            or original["receipt"]["event_sha256"] != digest(expected)):
                        return refused("INITIAL_EVENT_CONFLICT")
                    bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                    answer = _initial_result("recovered", cid=cid, event_id=identifier, receipt=original["receipt"])
                else:
                    row = next((row for row in snapshot["reservations"] if row["actor_cid"] == cid), None)
                    if row is None:
                        return refused("INITIAL_CORRELATION_MISMATCH")
                    bootstrap_guard.require_initial_creation_current(reserved_enrollment, policy, state, row)
                    if (cid not in policy["current"].values()
                            or state["current"].get(policy["actors"][cid]["role"]) != cid):
                        return refused("INITIAL_CREATION_FORBIDDEN")
                    if row != reserved_enrollment.witness:
                        return refused("INITIAL_CORRELATION_MISMATCH")
                    bootstrap_guard.require_initial_creation_new(reserved_enrollment, policy, state, row)
                    envelope = _initial_creation_envelope(policy, snapshot, row)
                    if identifier in state["receipts"]:
                        return refused("INITIAL_EVENT_CONFLICT")
                    record, receipt = _prepare_initial(policy, state, envelope)
                    bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                    possible = True
                    _publish_initial(self.root, record)
                    bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                    answer = _initial_result("recorded", cid=cid, event_id=identifier, receipt=receipt)
            bootstrap_guard.require_initial_identity_current(reserved_enrollment)
            return answer
        except host.HostAuthorityError:
            if not possible:
                return refused("HOST_AUTHORITY_REFUSED")
        except _InitialBootstrapMissing:
            if not possible:
                return refused("INITIAL_GENESIS_REQUIRED")
        except (ValueError, OSError) as exc:
            if not possible:
                if isinstance(exc, FileNotFoundError):
                    return refused("INITIAL_GENESIS_REQUIRED")
                if isinstance(exc.__cause__, FileExistsError):
                    return refused("CANONICAL_BUSY")
                return refused("CANONICAL_INVALID")
        return _initial_result("unknown", code="INITIAL_CREATION_PUBLICATION_UNKNOWN", cid=cid, event_id=identifier)


_DECISION_ERRORS = {
    "INVALID_DECISION_INPUT": "invalid decision command",
    "HOST_AUTHORITY_UNAVAILABLE": "protected host authority is unavailable",
    "UNAUTHORIZED_ROLE": "decision requires a current ROOT HostInvocation",
    "STALE_INVOCATION": "decision invocation is stale",
    "SOURCE_MISMATCH": "protected canonical source binding mismatch",
    "REQUEST_HASH_MISMATCH": "request sha256 mismatch",
    "UNKNOWN_REQUEST": "unknown request id",
    "BOUNDED_AUTHORITY_EXPIRED": "bounded authority expired",
    "REPLAY_CONFLICT": "event id conflicts with different decision payload",
    "DECISION_CONFLICT": "decision requires an authority request and a valid first approve/deny or approve-to-deny transition",
    "CAP_REACHED": "actor cumulative active cap reached",
    "CANONICAL_WRITER_BUSY": "mailbox writer is busy; inspect an abandoned lock before retrying",
    "PUBLICATION_UNKNOWN": "canonical decision publication is unresolved",
}


def _decision_correlations(command):
    if type(command) is not dict or not all(type(key) is str for key in command):
        return {name: None for name in ("event_id", "request_id", "request_sha256")}
    result = {}
    for name, pattern in (("event_id", SLUG), ("request_id", SLUG), ("request_sha256", SHA256)):
        value = command.get(name)
        result[name] = value if type(value) is str and pattern.fullmatch(value) is not None else None
    return result


def _decision_command(command):
    if (type(command) is not dict or not all(type(key) is str for key in command)
            or set(command) != {"event_id", "request_id", "request_sha256", "decision", "reason"}
            or any(value is None for value in _decision_correlations(command).values())):
        return None
    decision, reason = command["decision"], command["reason"]
    if (type(decision) is not str or decision not in {"approve", "deny"}
            or type(reason) is not str or not 0 < len(reason) <= 1024 or "\x00" in reason):
        return None
    return dict(command)


def _decision_result(command, state, code=None, receipt=None):
    reasons = {"recorded": "canonical decision recorded", "recovered": "original canonical receipt recovered"}
    return {"schema": "aegis.protected-decision-commit/v1", "state": state,
            "effect": {"recorded": "canonical_decision", "recovered": "none",
                       "refused": "none", "unknown": "possible"}[state],
            "code": code, "reason": _DECISION_ERRORS[code] if code else reasons[state],
            **_decision_correlations(command), "receipt": copy.deepcopy(receipt), "native_qualified": False}


class ProtectedCanonicalDecisionWriter:
    """One protected decision transaction; results are data, never runtime grants."""

    def __init__(self, root, authority):
        self.root, self._authority = safe_path(root), authority
        # Retain the actual exception for the protected host's diagnostics only.
        # This is neither a second journal nor evidence authorizing another call.
        self._last_failure = None

    def commit_decision(self, invocation, command):
        from tools import hierarchy_host_authority as host

        supplied = command
        command = _decision_command(supplied)
        if command is None:
            return _decision_result(supplied, "refused", "INVALID_DECISION_INPUT")
        if type(self._authority) is not host.HostAuthority:
            return _decision_result(command, "refused", "HOST_AUTHORITY_UNAVAILABLE")
        if type(invocation) is not host.HostInvocation:
            return _decision_result(command, "refused", "UNAUTHORIZED_ROLE")
        possible = False
        self._last_failure = None

        def refused(code):
            return _decision_result(command, "refused", code)

        try:
            with self._authority.effect_fence(invocation, "decision"):
                if self.root != self._authority.canonical_root:
                    return refused("SOURCE_MISMATCH")
                with writer_lock(self.root):
                    reader = Lifecycle(self.root)
                    policy, state = reader.load()
                    # Neither an unknown target nor an original receipt may be
                    # disclosed until current identity is proven under BOTH.
                    self._authority.require_current(invocation, policy, state, None)
                    self._authority.require_decision_command(invocation, command)
                    if invocation.event_id != command["event_id"]:
                        return refused("STALE_INVOCATION")
                    recovery = invocation.decision_recovery_event_id
                    if recovery is not None and (type(recovery) is not str
                            or SLUG.fullmatch(recovery) is None or recovery != command["event_id"]):
                        return refused("STALE_INVOCATION")
                    previous = state["receipts"].get(command["event_id"])
                    if previous is not None:
                        record = load_json(self.root / "events" / ("%06d.json" % previous["sequence"]))
                        original = record["envelope"]
                        require(record["sequence"] == previous["sequence"]
                                and record["event_sha256"] == previous["event_sha256"]
                                and digest(original) == previous["event_sha256"]
                                and original["id"] == command["event_id"], "original decision receipt differs")
                        event = original["event"]
                        if event["type"] != "decision":
                            return refused("REPLAY_CONFLICT")
                        row = state["requests"].get(event["request_id"])
                        require(row is not None, "original decision request is unavailable")
                        # Guard the ORIGINAL target before comparing any changed
                        # incoming request/hash/reason or rebuilding an envelope.
                        self._authority.require_current(invocation, policy, state, row)
                        original_command = {"event_id": original["id"], **{
                            key: event[key] for key in ("request_id", "request_sha256", "decision", "reason")}}
                        if original_command != command:
                            return refused("REPLAY_CONFLICT")
                        answer = _decision_result(command, "recovered", receipt=previous)
                    elif recovery is not None:
                        # The actual source-owned original-only mode never
                        # falls through to NEW, including a missing original.
                        return _decision_result(command, "unknown", "PUBLICATION_UNKNOWN")
                    else:
                        row = state["requests"].get(command["request_id"])
                        if row is None:
                            return refused("UNKNOWN_REQUEST")
                        self._authority.require_current(invocation, policy, state, row)
                        if row["raw"]["sha256"] != command["request_sha256"]:
                            return refused("REQUEST_HASH_MISMATCH")
                        value = row["request"]
                        prior = [item for item in state["decisions"] if item["request_id"] == value["id"]]
                        if (value["authority"] != value["id"] or prior and not (
                                prior[-1]["decision"] == "approve" and command["decision"] == "deny")):
                            return refused("DECISION_CONFLICT")
                        at, cid = timestamp(), invocation.actor_cid
                        actor = policy["actors"][cid]
                        if active_seconds(state, cid, at) >= actor["cap_seconds"]:
                            return refused("CAP_REACHED")
                        if (command["decision"] == "approve"
                                and parse_time(at) >= parse_time(value["continuation"]["expires_at"])):
                            return refused("BOUNDED_AUTHORITY_EXPIRED")
                        require(state["sequence"] < MAX_EVENTS, "lifecycle event limit reached")
                        root = state["current"]["root"]
                        envelope = {"id": command["event_id"], "actor": cid, "generation": actor["generation"],
                                    "custody": {"cid": root, "generation": policy["actors"][root]["generation"]},
                                    "event": {"type": "decision", **{key: command[key] for key in (
                                        "request_id", "request_sha256", "decision", "reason")}}}
                        record = {"schema": JOURNAL, "sequence": state["sequence"] + 1,
                                  "previous": state["head"], "policy_sha256": digest(policy), "at": at,
                                  "envelope": envelope, "event_sha256": digest(envelope)}
                        reduce_event(policy, state, envelope, at)
                        self._authority.require_current(invocation, policy, state, row)
                        possible = True  # Before the first possible publication.
                        publish_file(self.root / "events" / ("%06d.json" % record["sequence"]),
                                     encoded(record) + b"\n", limit=MAX_BYTES)
                        sync_directory(self.root / "events")
                        receipt = reader.finish(state, record)
                        self._authority.require_current(invocation, policy, state, row)
                        answer = _decision_result(command, "recorded", receipt=receipt)
                # Publication, canonical unlock and this final original-budget
                # check are inside the same uncertainty handling scope.
                self._authority.require_current(invocation, policy, state, None)
            # The H guard exit is also complete before returning known data.
            return answer
        except host.HostAuthorityError as exc:
            self._last_failure = exc
            # The host's own UNKNOWN covers effects outside this call (for example an
            # earlier scope of the same invocation), so it is never a no-effect refusal.
            if not possible and exc.code != "PROVIDER_OUTCOME_UNKNOWN":
                mappings = {
                    "UNSUPPORTED_HOST": "HOST_AUTHORITY_UNAVAILABLE",
                    "UNPROTECTED_DEPLOYMENT": "HOST_AUTHORITY_UNAVAILABLE",
                    "HOST_PROFILE_UNQUALIFIED": "HOST_AUTHORITY_UNAVAILABLE",
                    "CANONICAL_API_UNAVAILABLE": "HOST_AUTHORITY_UNAVAILABLE",
                    "HOST_PROTOCOL_ERROR": "STALE_INVOCATION", "HOST_PROTOCOL_TIMEOUT": "STALE_INVOCATION",
                    "HOST_CALL_CONFLICT": "STALE_INVOCATION", "STALE_INVOCATION": "STALE_INVOCATION",
                    "ROLE_OPERATION_FORBIDDEN": "UNAUTHORIZED_ROLE", "CANONICAL_CORRELATION_MISMATCH": "SOURCE_MISMATCH",
                    "PROVIDER_HANDLE_INVALID": "UNAUTHORIZED_ROLE",
                    "HISTORY_CURSOR_INVALID": "UNAUTHORIZED_ROLE"}
                return refused(mappings[exc.code])
        except Exception as exc:
            self._last_failure = exc
            if not possible and isinstance(exc, ValueError) and isinstance(exc.__cause__, FileExistsError):
                return refused("CANONICAL_WRITER_BUSY")
        return _decision_result(command, "unknown", "PUBLICATION_UNKNOWN")


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
