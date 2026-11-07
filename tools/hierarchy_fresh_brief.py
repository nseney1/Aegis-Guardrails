#!/usr/bin/env python3
"""Compose a bounded, durable brief without changing any coordination store."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (Mailbox, MAX_BYTES, SHA256, SLUG, TERMINAL_JOB_STATES, cli_path, digest, encoded,  # noqa: E402
                               endpoint_parts, fields, integer, matching, parse_time, read_bytes, read_json, require,
                               safe_path, strict_json, text)
from hierarchy_lifecycle import Lifecycle, load_json as lifecycle_json, raw_value  # noqa: E402
from hierarchy_roles import role_name  # noqa: E402
import hierarchy_hosts  # noqa: E402


SCHEMA = "aegis.hierarchy-fresh-brief/v1"
SECTIONS = ("Role contract", "Approved scope", "Source identity", "Open obligations",
            "Dependencies", "Unread work", "Evidence references")
MAX_ENTRIES = 256


class JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def file_ref(path):
    """Hash bytes, including evidence larger than a mailbox message, without copying their contents."""
    path = safe_path(path)
    require(stat.S_ISREG(path.stat().st_mode), "reference must be a regular file: " + str(path))
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            sha.update(chunk)
    return {"path": str(path), "sha256": sha.hexdigest()}


def check_ref(ref):
    fields(ref, {"path", "sha256"})
    matching(ref["sha256"], SHA256, "reference sha256")
    require(file_ref(text(ref["path"], "reference path")) == ref,
            "reference sha256 mismatch: " + ref["path"])


class Brief:
    def __init__(self):
        self.sections = {name: [] for name in SECTIONS}
        self.seen = set()
        self.inline = ""
        self.notes = {name: [] for name in SECTIONS}

    def add(self, section, kind, ref, **details):
        item = {"kind": kind, "ref": ref, **details}
        key = (section, encoded(item))
        if key in self.seen:
            return
        require(len(self.seen) < MAX_ENTRIES, "fresh brief exceeds 256 entries")
        self.seen.add(key)
        self.sections[section].append(item)

    def evidence(self, value, origin):
        """Keep unavailable or mismatched evidence as a declaration anchored to its durable record."""
        if isinstance(value, dict):
            if set(value) == {"path", "sha256"}:
                try:
                    check_ref(value)
                except (ValueError, OSError):
                    self.add("Evidence references", "unverified_evidence", origin, declared=value,
                             state="unavailable_or_mismatched")
                else:
                    self.add("Evidence references", "evidence", value)
            else:
                for key in sorted(value):
                    self.evidence(value[key], origin)
        elif isinstance(value, list):
            for item in value:
                self.evidence(item, origin)

    def render(self, endpoint, as_of, generation):
        lines = ["# Fresh thread brief", "<!-- " + SCHEMA + " -->", "", "Endpoint: " + endpoint,
                 "As of: " + as_of, "Target generation: " + str(generation), "",
                 "Resume path: First verify this brief and its references, then read the current binding and checkpoint; "
                 "acknowledge a successor checkpoint through your own connection, page the inbox from your own "
                 "generation's cursor (from the beginning for a new generation), and "
                 "reconcile unknown effects and original job IDs before considering new work. "
                 "Before resuming, validate expiry live; this snapshot grants no continuing authority. "
                 "Missing records require a hold; this brief grants no authority."]
        for name, items in self.sections.items():
            lines += ["", "## " + name, ""]
            lines.extend(self.notes[name])
            lines.extend("- " + json.dumps(item, sort_keys=True, ensure_ascii=True, allow_nan=False) for item in items)
            if not items:
                lines.append("No entries recorded in the inspected inputs; absence is not approval or settlement.")
            if name == "Role contract" and self.inline:
                lines += ["", "Contract text, rendered as on first start:", ""]
                lines.extend("> " + line for line in self.inline.splitlines())
        raw = ("\n".join(lines) + "\n").encode("utf-8")
        require(len(raw) <= MAX_BYTES, "fresh brief exceeds mailbox brief byte limit (262144)")
        return raw


def locate(root, initiative):
    """Accept a team run, its initiative base, or the mailbox root used by handoff entries."""
    if (root / "manifest.json").exists():
        base, mailbox_root, run = root.parent, root, root.parent
    else:
        base = root if (root / "provision.json").exists() else root / "initiatives" / initiative
        mailbox_root, run = base / "mailbox", root
    provision = safe_path(base / "provision.json")
    setup = read_json(provision) if provision.exists() else None
    if setup is not None:
        require(isinstance(setup, dict) and setup.get("initiative") == initiative, "provision initiative mismatch")
        named = safe_path(text(setup.get("mailbox_root"), "provision mailbox_root"))
        require(named == mailbox_root, "provision does not name this mailbox root")
    # A base supplied directly still uses the team run's shared lifecycle folder.
    if base.parent.name == "initiatives":
        run = base.parent.parent
    return Mailbox(mailbox_root), base, run, setup


def tidy_contract(lines):
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def template_view(content, family, origin):
    """Pure template rendering, pinned against launcher.start_prompt by subprocess tests.

    Importing the launcher also imports executable MCP startup guards. Keep this
    small reader local while the allowed change scope excludes the launcher.
    Marker examples inside Markdown fences remain literal, as in the launcher.
    """
    kept, opened, fence = [], None, None
    for number, line in enumerate(content.splitlines(), 1):
        if fence is not None:
            if opened is None or opened[1] == family:
                kept.append(line)
            if re.fullmatch(r" {0,3}" + re.escape(fence[0]) + r"{%d,}\s*" % len(fence), line):
                fence = None
            continue
        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
        if opening and not (opening.group(1)[0] == "`" and "`" in opening.group(2)):
            fence = opening.group(1)
            if opened is None or opened[1] == family:
                kept.append(line)
            continue
        marker = re.fullmatch(r"<!-- host:([a-z]+) -->", line.strip())
        if marker:
            require(opened is None, "unbalanced host markers in %s: line %d opens a nested block" % (origin, number))
            require(marker.group(1) in {"claude", "codex"}, "invalid host marker in %s: line %d" % (origin, number))
            opened = (number, marker.group(1))
        elif line.strip() == "<!-- /host -->":
            require(opened is not None, "unbalanced host markers in %s: line %d closes no block" % (origin, number))
            opened = None
        else:
            require(re.search(r"<!--\s*/?\s*host\b", line, re.IGNORECASE) is None,
                    "invalid host marker in %s: line %d" % (origin, number))
            if opened is None or opened[1] == family:
                kept.append(line)
    require(opened is None, "unbalanced host markers in " + str(origin))
    return tidy_contract(kept)


def contract_text(source, role, family):
    folder = source / "tools/hierarchy_templates/roles"
    path = folder / ("lane.md" if role == "implementer" else role + ".md")
    files = ([folder / "lane.md"] if role in {"reviewer", "integrator"} else []) + [path]
    parts, contracts = [], []
    for each in files:
        require(each.is_file(), "no role contract for %s: %s" % (role, each))
        raw = safe_path(each).read_bytes()
        contracts.append({"path": str(each), "sha256": hashlib.sha256(raw).hexdigest()})
        parts.append(template_view(raw.decode("utf-8"), family, each))
    if len(parts) > 1:
        headings = ("## Assignments", "## Protocol checklist")
        require(all(heading in parts[-1].splitlines() for heading in headings),
                "%s must restate lane.md's %s for its kind" % (path, " and ".join(headings)))
        headings += ("## Writing rules",) if role == "reviewer" else ()
        kept, skipping = [], False
        for line in parts[0].splitlines():
            if line.startswith(("# ", "## ")):
                skipping = line.strip() in headings
            if not skipping:
                kept.append(line)
        parts[0] = tidy_contract(kept)
    return "\n\n".join(parts), contracts


def role_contract(brief, mailbox, base, setup, endpoint):
    role = role_name(endpoint, mailbox.endpoint(endpoint).get("kind"))
    plan = hierarchy_hosts.base_plan(base, endpoint_parts(endpoint)[0])
    host, _ = hierarchy_hosts.plan_host(plan, endpoint)
    family = hierarchy_hosts.family(host) if host is not None else "codex"
    source = safe_path(setup["source"]) if setup else Path(__file__).resolve().parents[1]
    if plan is not None:
        brief.add("Evidence references", "host_plan", file_ref(base / hierarchy_hosts.PLAN_FILE))
    if role == "root":
        # ROOT never starts through the launcher, so its contract is referenced, not inlined.
        contracts = [file_ref(source / "tools/hierarchy_templates/roles/root.md")]
    else:
        brief.inline, contracts = contract_text(source, role, family)
    for contract in contracts:
        check_ref(contract)
        brief.add("Role contract", "role_contract", contract, role=role, family=family)
    if role in {"implementer", "integrator"}:
        template = "lane-brief-claude.md" if family == "claude" else "lane-brief.md"
        brief.add("Evidence references", "assignment_template", file_ref(source / "tools/hierarchy_templates" / template))


def lifecycle_records(brief, directory, at):
    require(directory.is_dir(), "lifecycle directory unavailable: " + str(directory))
    status = Lifecycle(directory).status()
    policy_ref = file_ref(directory / "policy.json")
    brief.add("Evidence references", "lifecycle_policy", policy_ref)
    brief.notes["Open obligations"].append("Lifecycle coverage is journal-wide: requests have no durable endpoint mapping.")
    events, created, latest = [], {}, {}
    for sequence in range(1, status["sequence"] + 1):
        path = directory / "events" / ("%06d.json" % sequence)
        record = lifecycle_json(path)
        event = record["envelope"]["event"]
        events.append(record)
        identifier = event.get("request_id")
        if event["type"] == "publish":
            identifier = raw_value(event["request"])["id"]
            created.setdefault(identifier, record)
        elif event["type"] in {"disposition", "resolve"} and event["resolution"]["kind"] == "next":
            successor = raw_value(event["resolution"]["request"])["id"]
            created[successor] = latest[successor] = record
        if identifier is not None:
            latest[identifier] = record
    if events:
        brief.add("Evidence references", "lifecycle_head", file_ref(directory / "events" / ("%06d.json" % status["sequence"])),
                  sequence=status["sequence"], journal_head_sha256=status["head"])
    brief.evidence(lifecycle_json(directory / "policy.json")["authority"], policy_ref)

    def reference(record):
        return file_ref(directory / "events" / ("%06d.json" % record["sequence"]))

    def add_event(record):
        event = record["envelope"]["event"]
        origin = reference(record)
        brief.add("Evidence references", "lifecycle_event", origin, event_type=event["type"],
                  event_id=record["envelope"]["id"], request_id=event.get("request_id"))
        brief.evidence(event, origin)
        if event["type"] == "terminal":
            brief.evidence(raw_value(event["result"])["evidence"], origin)
        return origin

    def provenance(mark, kind, identifier):
        # Reduced marks carry actor/generation/time, not journal sequence numbers.
        matches = []
        for record in events:
            envelope = record["envelope"]
            event = envelope["event"]
            if (event["type"] == kind and event.get("request_id") == identifier
                    and envelope["actor"] == mark["actor"] and envelope["generation"] == mark["generation"]
                    and record["at"] == mark["at"] and all(mark[key] == event[key] for key in mark.keys() & event.keys())):
                matches.append(record)
        require(bool(matches), "lifecycle mark has no journal provenance")
        return matches[-1]

    for identifier, row in sorted(status["requests"].items()):
        if row["resolution"] and row["resolution"]["kind"] in {"complete", "next"}:
            continue
        request = row["request"]
        origin = reference(created[identifier])
        decisions = [item for item in status["decisions"] if item["request_id"] == request["authority"]]
        authority = status["requests"].get(request["authority"], row)["request"]
        current_scope = all(parse_time(item["continuation"]["expires_at"]) > at for item in (request, authority))
        if current_scope:
            brief.add("Approved scope", "request_scope", origin, request_id=identifier,
                      request_sha256=row["raw"]["sha256"], paths=request["paths"], authority=request["authority"],
                      expires_at=request["continuation"]["expires_at"],
                      approval=decisions[-1]["decision"] if decisions else "not_recorded")
        brief.add("Source identity", "request_source", origin, request_id=identifier, source=request["source"])
        for prerequisite in request["prerequisites"]:
            brief.add("Dependencies", "prerequisite", origin, request_id=identifier, prerequisite=prerequisite,
                      state="recorded" if prerequisite in status["requests"] else "missing")
        change = row.get("small_change")
        if change and current_scope:
            registration = change["registration"]
            proposal = raw_value(registration["proposal"])
            brief.add("Approved scope", "small_change_plan", add_event(provenance(registration, "small_change_plan", identifier)), request_id=identifier,
                      plan_sha256=registration["proposal"]["sha256"], path_scopes=proposal["plan"]["path_scopes"],
                      checks=proposal["plan"]["checks"],
                      approval=change["decisions"][-1]["decision"] if change["decisions"] else "not_recorded")
        authorities = [(item, "decision", request["authority"]) for item in decisions[-1:]]
        if row["admission"]:
            authorities.append((row["admission"], "admit", identifier))
        if change:
            authorities += [(item, "small_change_decision", identifier) for item in change["decisions"][-1:]]
            if change["admission"]:
                authorities.append((change["admission"], "small_change_admit", identifier))
        for authority, kind, target in authorities:
            record = provenance(authority, kind, target)
            origin = add_event(record)
            event = record["envelope"]["event"]
            if current_scope:
                brief.add("Approved scope", "authority_record", origin, request_id=identifier,
                          event_type=event["type"], record_sha256=digest(authority),
                          decision=event.get("decision"), plan_sha256=event.get("plan_sha256"),
                          decision_sha256=event.get("decision_sha256"))
        # Only evidence belonging to unsettled rows becomes an individual entry.
        for kind in ("terminal", "review", "delivery"):
            if row[kind]:
                add_event(provenance(row[kind], kind, identifier))
    for obligation in status["obligations"]:
        # Owner, next decision and the blocker stay in their validated lifecycle record.
        brief.add("Open obligations", "lifecycle_obligation", reference(latest[obligation["request_id"]]),
                  **{key: obligation[key] for key in ("request_id", "request_sha256", "state", "owner", "next_decision")})


def validate_packet_declaration(packet, message_id):
    """Validate the runner's common packet schema without admitting or executing a job.

    The runner has no standalone schema validator: admit() also requires live
    recipes, checkouts and dependency evidence. Reuse its constants and primitives
    here; recipe-specific and physical admission remain the runner's responsibility.
    """
    from hierarchy_jobs import (DEPENDENT_PACKET_SCHEMA, EMPTY_STATUS, GIT_ID, MAX_PATHS, MAX_PATHS_BYTES,
                                PACKET_SCHEMA, PATH_ARGUMENT, absolute)

    require(isinstance(packet, dict), "invalid JSON field: packet must be an object")
    schema = packet.get("schema")
    require(isinstance(schema, str) and schema in (PACKET_SCHEMA, DEPENDENT_PACKET_SCHEMA), "invalid schema/version")
    dependent = schema == DEPENDENT_PACKET_SCHEMA
    fields(packet, {"schema", "recipe", "checkout", "commit", "tree"} |
           ({"after", "recipes_sha256"} if dependent else set()),
           {"dirty_content_sha256", "paths", "expected_tree", "message", "merge"})
    matching(packet["recipe"], SLUG, "recipe")
    absolute(packet["checkout"], "checkout")
    for name in ("commit", "tree", "expected_tree", "merge"):
        if name in packet:
            matching(packet[name], GIT_ID, name)
    if "dirty_content_sha256" in packet:
        matching(packet["dirty_content_sha256"], SHA256, "dirty_content_sha256")
    if "message" in packet:
        text(packet["message"], "message", 65536)
    if "paths" in packet:
        paths = packet["paths"]
        require(isinstance(paths, list) and len(paths) <= MAX_PATHS, "invalid paths")
        for index, path in enumerate(paths):
            label = "paths[%d]" % index
            matching(path, PATH_ARGUMENT, label)
            require(".." not in path.partition("::")[0].split("/"), "invalid " + label)
        require(len(json.dumps(paths)) <= MAX_PATHS_BYTES, "paths exceed runner byte limit")
    if dependent:
        require(isinstance(packet["after"], dict), "invalid after: expected a JSON object")
        fields(packet["after"], {"message_id", "sha256"})
        matching(packet["after"]["message_id"], SLUG, "after.message_id")
        matching(packet["after"]["sha256"], SHA256, "after.sha256")
        matching(packet["recipes_sha256"], SHA256, "recipes_sha256")
        require(packet["after"]["message_id"] != message_id, "invalid after: a job cannot depend on itself")
        require(packet.get("dirty_content_sha256", EMPTY_STATUS) == EMPTY_STATUS,
                "invalid dirty_content_sha256: dependent jobs require clean source")


def job_packet(brief, mailbox, message, origin):
    from hierarchy_jobs import packet_text

    reference = message["brief"]
    raw = mailbox.brief(reference)
    try:
        content = packet_text(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid packet %s field JSON: %s" % (reference["path"], exc)) from exc
    if not content.lstrip().startswith(("{", "[")):
        # Legacy prose packets cannot supply structured dependencies; retain the original, never guess.
        brief.add("Evidence references", "job_packet", reference, job_id=message["message_id"])
        brief.add("Dependencies", "unstructured_job_packet", origin, job_id=message["message_id"],
                  state="dependencies_not_recorded")
        return
    try:
        packet = strict_json(content)
    except ValueError as exc:
        raise ValueError("invalid packet %s field JSON: %s" % (reference["path"], exc)) from exc
    try:
        validate_packet_declaration(packet, message["message_id"])
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid packet %s: %s" % (reference["path"], exc)) from exc
    brief.add("Evidence references", "job_packet", reference, job_id=message["message_id"])
    if "after" in packet:
        after = packet["after"]
        brief.add("Dependencies", "job_after", reference, job_id=message["message_id"], after=after)
    source = {key: packet[key] for key in ("checkout", "commit", "tree", "paths", "dirty_content_sha256",
                                          "expected_tree", "merge", "recipes_sha256") if key in packet}
    if source:
        brief.add("Source identity", "job_source", reference, job_id=message["message_id"], source=source)


def receipt_order(record):
    message = record["message"]
    return parse_time(message["created_at"]), message["message_id"]


def job_state(receipts):
    """Only a strictly later terminal reply to this same request settles uncertainty.

    A timestamp tie cannot establish order. Conflicting terminal outcomes, or a
    terminal tied with unknown, stay unknown regardless of message-id spelling.
    """
    groups = {}
    for record in receipts:
        groups.setdefault(receipt_order(record)[0], []).append(record)
    state, witness = "unreconciled", None
    for _, group in sorted(groups.items()):
        group.sort(key=receipt_order)
        unknown = [row for row in group if row["message"]["receipt"]["state"] == "unknown"]
        terminal = [row for row in group if row["message"]["receipt"]["state"] in TERMINAL_JOB_STATES]
        outcomes = {(row["message"]["receipt"]["state"], row["message"]["receipt"].get("exit_code")) for row in terminal}
        if unknown or len(outcomes) > 1:
            state, witness = "unknown", (unknown or terminal)[-1]
        elif terminal:
            witness = terminal[-1]
            state = witness["message"]["receipt"]["state"]
        elif state != "unknown":
            witness = group[-1]
            state = witness["message"]["receipt"]["state"]
    return state, witness


def unread_records(brief, mailbox, endpoint, delivery, records, generation):
    mailbox.delivery_directory(delivery)
    read_ids, own_reads, predecessor_reads, wakes = set(), set(), set(), {}
    receipts = {}
    for kind in ("reads", "wakes"):
        values = mailbox.delivery_receipts(delivery, kind, endpoint, records)
        folder = safe_path(delivery / kind / endpoint)
        paths = sorted(path for path in folder.iterdir() if not path.name.startswith(".")) if folder.exists() else []
        require(len(paths) == len(values), "delivery history changed during composition")
        receipts[kind] = list(zip(paths, values))
        if paths:
            path, _ = max(receipts[kind], key=lambda item: (parse_time(item[1]["at"]), str(item[0])))
            brief.add("Evidence references", "delivery_" + ("read" if kind == "reads" else "wake"), file_ref(path))
    for _, receipt in receipts["reads"]:
        read_ids.update(receipt["message_ids"])
        if receipt["generation"] == generation:
            own_reads.update(receipt["message_ids"])
        elif receipt["generation"] < generation:
            predecessor_reads.update(receipt["message_ids"])
    predecessor_reads -= own_reads
    if predecessor_reads:
        candidates = [(path, value) for path, value in receipts["reads"]
                      if value["generation"] < generation and predecessor_reads.intersection(value["message_ids"])]
        path, _ = max(candidates, key=lambda item: (parse_time(item[1]["at"]), str(item[0])))
        counts = {}
        for identifier in sorted(predecessor_reads):
            kind = records[identifier]["message"]["type"]
            counts[kind] = counts.get(kind, 0) + 1
        brief.add("Unread work", "predecessor_reads", file_ref(path), state="read_by_predecessor",
                  count=len(predecessor_reads), generation=generation, message_types=counts)
    failed = {(value["generation"], value["wake_id"]) for _, value in receipts["wakes"] if value["state"] == "failed_to_start"}
    for path, receipt in receipts["wakes"]:
        if receipt["state"] == "started" and (receipt["generation"], receipt["wake_id"]) not in failed:
            for identifier in receipt["message_ids"]:
                wakes[identifier] = path
    brief.notes["Unread work"].append("Reads were applied for target generation %s. Predecessor-only reads are aggregated; "
                                      "never-read messages are listed individually." % generation)
    unread, after = set(), None
    while True:
        page = mailbox.inbox(endpoint, limit=100, after=after)
        for record in page["messages"]:
            identifier = record["message"]["message_id"]
            if identifier not in read_ids:
                unread.add(identifier)
                details = {"wake_ref": file_ref(wakes[identifier])} if identifier in wakes else {}
                brief.add("Unread work", "message", file_ref(record["path"]), message_id=identifier,
                          generation=generation, state="woken" if identifier in wakes else "published", **details)
        if page["next_after"] is None:
            return unread
        require(page["next_after"] != after, "inbox cursor did not advance")
        after = page["next_after"]


def mailbox_records(brief, mailbox, endpoint, initiative, delivery, at, generation, binding):
    records = mailbox.messages()
    relevant = {key: row for key, row in records.items()
                if initiative in (endpoint_parts(row["message"]["from"])[0], endpoint_parts(row["message"]["to"])[0])}
    closed, accepted = mailbox.dispatch_history(records)
    if binding:
        origin = file_ref(mailbox.root / "bindings" / endpoint / ("%06d.json" % binding["generation"]))
        brief.add("Evidence references", "binding", origin, generation=binding["generation"])
        if binding["checkpoint"]:
            # Old checkpoints remain records, not a source of currently held leases.
            brief.add("Evidence references", "checkpoint_history", origin, state="unverified")
    unread = unread_records(brief, mailbox, endpoint, delivery, records, generation)
    historical = []

    def evidence(record):
        message = record["message"]
        origin = file_ref(record["path"])
        brief.add("Evidence references", "mailbox_evidence", origin,
                  message_id=message["message_id"], message_type=message["type"])
        brief.evidence(message.get("receipt", {}), origin)

    job_receipts = {}
    for record in relevant.values():
        message = record["message"]
        if message["type"] == "job_receipt":
            job_receipts.setdefault(message["in_reply_to"], []).append(record)
    open_jobs = set()
    for identifier, record in sorted(relevant.items()):
        message = record["message"]
        if message["type"] != "job_request":
            continue
        receipts = job_receipts.get(identifier, [])
        state, witness = job_state(receipts)
        if state in TERMINAL_JOB_STATES:
            historical.extend([record] + receipts)
            continue
        open_jobs.add(identifier)
        origin = file_ref(record["path"])
        job_packet(brief, mailbox, message, origin)  # Missing/changed open packets refuse the whole composition.
        brief.add("Open obligations", "job", origin, job_id=initiative + "/" + identifier,
                  message_id=identifier, state=state)
        if witness:
            evidence(witness)
        if receipts:
            evidence(max(receipts, key=receipt_order))
    open_dispatches = set()
    for identifier, record in sorted(relevant.items()):
        message = record["message"]
        touching = endpoint in (message["from"], message["to"])
        if message["type"] != "dispatch" or not touching:
            continue
        if identifier in closed:
            historical.append(record)
            continue
        open_dispatches.add(identifier)
        mailbox.brief(message["brief"])
        brief.add("Open obligations", "dispatch", file_ref(record["path"]), message_id=identifier, state="open")
        brief.add("Evidence references", "message_brief", message["brief"], message_id=identifier)
        acknowledgments = [value for value in accepted if value["in_reply_to"] == identifier]
        if acknowledgments:
            acknowledgment = max(acknowledgments, key=lambda value: (parse_time(value["created_at"]), value["message_id"]))
            acknowledgment_record = relevant[acknowledgment["message_id"]]
            evidence(acknowledgment_record)
            if "readiness" in acknowledgment:
                ready = acknowledgment["readiness"]
                origin = file_ref(acknowledgment_record["path"])
                brief.add("Source identity", "accepted_source", origin,
                          source={key: ready[key] for key in ("worktree", "branch", "base_revision")})
                if parse_time(ready["lease_expires_at"]) > at:
                    brief.add("Approved scope", "accepted_lease", origin, owned_paths=ready["owned_paths"],
                              **{key: ready[key] for key in ("lease_ref", "lease_oid", "lease_expires_at")})
    for identifier, record in sorted(relevant.items()):
        message = record["message"]
        kind = message["type"]
        parent = message.get("in_reply_to")
        if parent and parent not in open_jobs | open_dispatches and kind in {"job_receipt", "ack", "result", "review"}:
            historical.append(record)
        elif identifier in unread and kind in {"result", "review", "ack", "job_receipt"}:
            evidence(record)
        if "brief" in message and kind not in {"dispatch", "job_request"}:
            if identifier in unread:
                brief.evidence(message["brief"], file_ref(record["path"]))
            else:
                historical.append(record)
    if historical:
        # Mailbox files have no hash chain. This is a locator for retained history,
        # not a claim that one message authenticates all earlier mailbox records.
        brief.add("Evidence references", "mailbox_history", file_ref(max(historical, key=receipt_order)["path"]),
                  state="unverified", historical_briefs="not_reverified")


def inspect(raw):
    """Verify the seven-section format, the global count and every primary reference."""
    body = raw.decode("utf-8")
    require("<!-- " + SCHEMA + " -->" in body.splitlines(), "unsupported fresh brief schema")
    headings, count, resume = [], 0, 0
    for line in body.splitlines():
        if line.startswith("Resume path: "):
            resume += 1
        elif line.startswith("## "):
            headings.append(line[3:])
        elif line.startswith("- "):
            require(bool(headings), "entry outside a brief section")
            item = strict_json(line[2:])
            require(isinstance(item, dict) and "kind" in item and "ref" in item, "invalid brief entry")
            text(item["kind"], "entry kind")
            check_ref(item["ref"])
            count += 1
            require(count <= MAX_ENTRIES, "fresh brief exceeds 256 entries")
    require(tuple(headings) == SECTIONS and resume == 1, "invalid fresh brief sections or resume path")
    return count


def composition_time(value):
    if value is None:
        value = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2})(?:\.(\d+))?(?:[Zz]|\+00:00)", value)
    require(match is not None, "invalid --as-of: expected RFC3339 UTC")
    seconds = match.group(1).upper()
    fraction = (match.group(2) or "").rstrip("0")
    try:
        # Expiry records have microsecond precision. Retain the full input time
        # in the brief; truncation cannot cross an expiry on that precision grid.
        at = parse_time(seconds + "." + fraction[:6].ljust(6, "0") + "Z")
    except ValueError as exc:
        raise ValueError("invalid --as-of: expected RFC3339 UTC") from exc
    return at, seconds + ("." + fraction if fraction else "") + "Z"


def protect_stores(output, mailbox, base, run, lifecycle, delivery, setup):
    """Reject overlap in either direction, including stores declared by other run provisions."""
    output = safe_path(output)
    stores = {mailbox.root, lifecycle, delivery, run / "lifecycle", run / "store", base / "delivery"}
    provisions = {base / "provision.json", run / "evidence/provision-init.json", run / "inputs/provision-init.json"}
    folder = safe_path(run / "initiatives")
    if folder.is_dir():
        provisions.update(safe_path(path) / "provision.json" for path in sorted(folder.iterdir()) if path.is_dir())
    values = [setup] if setup is not None else []
    for path in sorted(provisions):
        path = safe_path(path)
        if path.exists():
            values.append(read_json(path))
    for record in values:
        require(isinstance(record, dict), "invalid provision record")
        for key in ("store", "board", "mailbox_root", "delivery_dir"):
            if key in record:
                stores.add(safe_path(text(record[key], "provision " + key)))
    for store in sorted(stores):
        store = safe_path(store)
        require(output != store and store not in output.parents and output not in store.parents,
                "output directory overlaps coordination store: " + str(store))


def prepare(args):
    matching(args.initiative, SLUG, "initiative")
    require(endpoint_parts(args.endpoint)[0] == args.initiative, "endpoint is outside initiative " + args.initiative)
    mailbox, base, run, setup = locate(cli_path(args.root, "--root"), args.initiative)
    mailbox.endpoint(args.endpoint)
    at, as_of = composition_time(args.as_of)
    history = mailbox.bindings(args.endpoint)
    binding = history[-1] if history else None
    current = binding["generation"] if binding else 1
    generation = args.target_generation
    if generation is None:
        generation = current + 1 if binding and mailbox.ready(binding) else current
    integer(generation, "target generation")
    require(generation >= current, "target generation precedes current binding")
    lifecycle = cli_path(args.lifecycle, "--lifecycle") if args.lifecycle else safe_path(run / "lifecycle")
    delivery = cli_path(args.delivery_dir, "--delivery-dir") if args.delivery_dir else safe_path(
        setup["delivery_dir"] if setup else base / "delivery")
    protect_stores(base / "briefs", mailbox, base, run, lifecycle, delivery, setup)
    brief = Brief()
    role_contract(brief, mailbox, base, setup, args.endpoint)
    brief.add("Source identity", "mailbox_identity", file_ref(mailbox.root / "manifest.json"))
    if setup:
        brief.add("Source identity", "runtime_pin", file_ref(base / "provision.json"), verification="recorded_only",
                  **{key: setup[key] for key in ("source", "source_commit", "source_tree") if key in setup})
    else:
        brief.notes["Source identity"].append("No provisioned runtime pin recorded; contracts come from the composer's checkout.")
    if args.lifecycle or lifecycle.exists():
        lifecycle_records(brief, lifecycle, at)
        lifecycle_coverage = "journal_wide_registered_requests"
    else:
        lifecycle_coverage = "absent"
        brief.notes["Open obligations"].append("No lifecycle journal recorded at the default location; supply --lifecycle for an external journal.")
    brief.notes["Unread work"].append("Messages without a recorded read remain unread; a wake is not a read.")
    mailbox_records(brief, mailbox, args.endpoint, args.initiative, delivery, at, generation, binding)
    raw = brief.render(args.endpoint, as_of, generation)
    inspect(raw)  # All validation precedes mkdir or creation of a temporary file.
    sha = hashlib.sha256(raw).hexdigest()
    reference = {"path": str(base / "briefs" / ("fresh-" + sha + ".md")), "sha256": sha}
    mailbox.brief(reference, verify=False)
    require_secure_publication()
    return raw, {"ok": True, "brief": reference, "entries": len(brief.seen),
                 "coverage": {"lifecycle": lifecycle_coverage}, "as_of": as_of, "target_generation": generation}


class PublicationRefused(ValueError):
    """A directory changed or cannot be securely addressed; never follow it elsewhere."""


def require_secure_publication():
    # CPython lists rename, not replace, in supports_dir_fd, even when replace
    # supports both descriptors. Inspect the native capability names so wrapping
    # an OS call for a deterministic boundary test does not change its capability.
    names = {function.__name__ for function in os.supports_dir_fd}
    require(hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
            and {"open", "mkdir", "rename", "unlink", "stat"} <= names,
            "secure brief publication requires directory descriptor support")


def open_directory(path):
    """Traverse from the filesystem root, opening every component without following links."""
    flags = directory_flags()
    descriptor = None
    try:
        descriptor = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if exc.errno == errno.EACCES:
            raise PublicationRefused("publication directory permission denied: " + str(path)) from exc
        raise PublicationRefused("publication directory changed or unavailable") from exc


def directory_flags():
    # Linux O_PATH needs search permission only. Other supported POSIX hosts
    # retain O_RDONLY where no search-only directory handle is exposed.
    return getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW


def check_directory(base_fd, directory_fd, name):
    try:
        current = os.stat(name, dir_fd=base_fd, follow_symlinks=False)
    except OSError as exc:
        if exc.errno == errno.EACCES:
            raise PublicationRefused("publication directory permission denied: " + name) from exc
        raise PublicationRefused("publication directory changed") from exc
    opened = os.fstat(directory_fd)
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise PublicationRefused("publication directory changed")


def file_identity(value):
    return value.st_dev, value.st_ino


def check_returned_path(path, identity):
    try:
        returned = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("published brief pathname no longer identifies written file: " + str(path)) from exc
    if file_identity(returned) != identity:
        raise RuntimeError("published brief pathname no longer identifies written file: " + str(path))


def remove_written_file(directory_fd, name, identity):
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    # Another composer can have replaced the same content address. Remove only
    # our inode; never delete the other tool's publication during cleanup.
    if file_identity(current) == identity:
        os.unlink(name, dir_fd=directory_fd)


def sync_publication_directory(directory_fd):
    if os.name == "nt":
        # Windows does not support fsync on directory handles. Publication also
        # retains its separate refusal when secure dir_fd operations are absent.
        return
    # O_PATH handles permit traversal but cannot be fsynced. Reopen the anchored
    # directory read-only on POSIX, rather than resolving its pathname again.
    descriptor = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(raw, reference):
    require_secure_publication()
    path = Path(reference["path"])
    base_fd = open_directory(path.parent.parent)
    directory_fd = None
    pending = None
    created_directory = False
    try:
        try:
            try:
                directory_fd = os.open(path.parent.name, directory_flags(), dir_fd=base_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(path.parent.name, mode=0o700, dir_fd=base_fd)
                    created_directory = True
                except FileExistsError:
                    pass  # Another composer created the same output directory.
                directory_fd = os.open(path.parent.name, directory_flags(), dir_fd=base_fd)
        except OSError as exc:
            if exc.errno == errno.EACCES:
                raise PublicationRefused("publication directory permission denied: " + str(path.parent)) from exc
            if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
                raise PublicationRefused("publication directory changed") from exc
            raise
        check_directory(base_fd, directory_fd, path.parent.name)
        try:
            existing = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PublicationRefused("content-addressed brief is a symlink") from exc
            if not stat.S_ISREG(os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False).st_mode):
                raise PublicationRefused("brief must be a regular file") from exc
            raise
        if existing is not None:
            metadata = os.fstat(existing)
            if not stat.S_ISREG(metadata.st_mode):
                os.close(existing)
                raise PublicationRefused("brief must be a regular file")
            with os.fdopen(existing, "rb") as stream:
                if stream.read(MAX_BYTES + 1) != raw:
                    raise PublicationRefused("content-addressed brief already exists with different bytes")
            check_directory(base_fd, directory_fd, path.parent.name)
            check_returned_path(path, file_identity(metadata))
            sync_publication_directory(directory_fd)
            if created_directory:
                sync_publication_directory(base_fd)
            check_returned_path(path, file_identity(metadata))
            return
        pending = ".fresh-" + uuid.uuid4().hex
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as stream:
            identity = file_identity(os.fstat(stream.fileno()))
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        check_directory(base_fd, directory_fd, path.parent.name)
        os.replace(pending, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        pending = None
        try:
            check_directory(base_fd, directory_fd, path.parent.name)
            check_returned_path(path, identity)
            sync_publication_directory(directory_fd)
            if created_directory:
                sync_publication_directory(base_fd)
            check_returned_path(path, identity)
        except (PublicationRefused, RuntimeError):
            remove_written_file(directory_fd, path.name, identity)
            raise
    finally:
        if directory_fd is not None:
            try:
                if pending is not None:
                    os.unlink(pending, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(directory_fd)
        os.close(base_fd)


def main(argv=None):
    parser = JSONArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compose = commands.add_parser("compose")
    compose.add_argument("--root", required=True, help="Absolute team run, initiative base or handoff mailbox root")
    compose.add_argument("--initiative", required=True)
    compose.add_argument("--endpoint", required=True)
    compose.add_argument("--lifecycle", help="External lifecycle journal; default <run>/lifecycle")
    compose.add_argument("--delivery-dir", help="Read/wake receipts; default provisioned or <base>/delivery")
    compose.add_argument("--as-of", help="RFC3339 UTC snapshot time for expiry decisions; default now")
    compose.add_argument("--target-generation", type=int,
                         help="Read generation; default the next generation for a ready binding, otherwise the current one")
    verify = commands.add_parser("verify")
    verify.add_argument("--path", required=True)
    verify.add_argument("--sha256", required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == "compose":
            raw, answer = prepare(args)
        else:
            path = cli_path(args.path, "--path")
            matching(args.sha256, SHA256, "brief sha256")
            require(path.suffix == ".md", "brief must be a Markdown file")
            raw = read_bytes(path)
            require(hashlib.sha256(raw).hexdigest() == args.sha256, "brief sha256 mismatch")
            answer = {"ok": True, "brief": {"path": str(path), "sha256": args.sha256}, "entries": inspect(raw)}
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    except Exception as exc:
        print(json.dumps({"error": "internal composition error: " + str(exc)}, sort_keys=True))
        return 3
    try:
        if args.command == "compose":
            publish(raw, answer["brief"])
    except PublicationRefused as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    except Exception as exc:
        print(json.dumps({"error": "brief publication failed: " + str(exc)}, sort_keys=True))
        return 3
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
