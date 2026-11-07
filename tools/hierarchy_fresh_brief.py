#!/usr/bin/env python3
"""Compose a bounded, durable brief without changing any coordination store."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (Mailbox, MAX_BYTES, SHA256, SLUG, cli_path, digest, encoded, endpoint_parts,  # noqa: E402
                               fields, matching, read_bytes, read_json, require, safe_path, strict_json, text)
from hierarchy_lifecycle import Lifecycle, raw_value  # noqa: E402
from hierarchy_launcher import start_prompt  # noqa: E402
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

    def render(self, endpoint):
        lines = ["# Fresh thread brief", "<!-- " + SCHEMA + " -->", "", "Endpoint: " + endpoint, "",
                 "Resume path: First verify this brief and its references, then read the current binding and checkpoint; "
                 "acknowledge a successor checkpoint through your own connection, page the inbox to completion, and "
                 "reconcile unknown effects and original job IDs before considering new work. "
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
        prompt, contracts = start_prompt(SimpleNamespace(mailbox=mailbox, setup={"source": str(source)}), endpoint, family)
        # The launcher header asserts it started the actor; a composition cannot make that assertion.
        brief.inline = prompt.partition("\n\n")[2].rpartition("\n\n")[0]
    for contract in contracts:
        check_ref(contract)
        brief.add("Role contract", "role_contract", contract, role=role, family=family)
    if role in {"implementer", "integrator"}:
        template = "lane-brief-claude.md" if family == "claude" else "lane-brief.md"
        brief.add("Evidence references", "assignment_template", file_ref(source / "tools/hierarchy_templates" / template))


def lifecycle_records(brief, directory):
    require(directory.is_dir(), "lifecycle directory unavailable: " + str(directory))
    status = Lifecycle(directory).status()
    policy_ref = file_ref(directory / "policy.json")
    brief.add("Evidence references", "lifecycle_policy", policy_ref)
    brief.notes["Open obligations"].append("Lifecycle coverage is journal-wide: requests have no durable endpoint mapping.")
    events, published, latest = [], {}, {}
    for sequence in range(1, status["sequence"] + 1):
        path = directory / "events" / ("%06d.json" % sequence)
        record = read_json(path)
        origin = file_ref(path)
        event = record["envelope"]["event"]
        events.append((record, origin))
        identifier = event.get("request_id")
        if event["type"] == "publish":
            identifier = raw_value(event["request"])["id"]
            published[identifier] = origin
        if identifier is not None:
            latest[identifier] = origin
        brief.add("Evidence references", "lifecycle_event", origin,
                  event_type=event["type"], event_id=record["envelope"]["id"], request_id=identifier)
        brief.evidence(event, origin)
        if event["type"] == "terminal":
            brief.evidence(raw_value(event["result"])["evidence"], origin)
    brief.evidence(read_json(directory / "policy.json")["authority"], policy_ref)

    def provenance(mark, kind, identifier):
        # Reduced marks carry actor/generation/time, not journal sequence numbers.
        matches = []
        for record, origin in events:
            envelope = record["envelope"]
            event = envelope["event"]
            if (event["type"] == kind and event.get("request_id") == identifier
                    and envelope["actor"] == mark["actor"] and envelope["generation"] == mark["generation"]
                    and record["at"] == mark["at"] and all(mark[key] == event[key] for key in mark.keys() & event.keys())):
                matches.append(origin)
        require(bool(matches), "lifecycle mark has no journal provenance")
        return matches[-1]

    for identifier, row in sorted(status["requests"].items()):
        request = row["request"]
        origin = published[identifier]
        decisions = [item for item in status["decisions"] if item["request_id"] == request["authority"]]
        brief.add("Approved scope", "request_scope", origin, request_id=identifier,
                  request_sha256=row["raw"]["sha256"], paths=request["paths"], authority=request["authority"],
                  expires_at=request["continuation"]["expires_at"],
                  approval=decisions[-1]["decision"] if decisions else "not_recorded")
        brief.add("Source identity", "request_source", origin, request_id=identifier, source=request["source"])
        for prerequisite in request["prerequisites"]:
            brief.add("Dependencies", "prerequisite", origin, request_id=identifier, prerequisite=prerequisite,
                      state="recorded" if prerequisite in status["requests"] else "missing")
        change = row.get("small_change")
        if change:
            registration = change["registration"]
            proposal = raw_value(registration["proposal"])
            brief.add("Approved scope", "small_change_plan", provenance(registration, "small_change_plan", identifier), request_id=identifier,
                      plan_sha256=registration["proposal"]["sha256"], path_scopes=proposal["plan"]["path_scopes"],
                      checks=proposal["plan"]["checks"],
                      approval=change["decisions"][-1]["decision"] if change["decisions"] else "not_recorded")
        authorities = [(item, "decision", request["authority"]) for item in decisions]
        if row["admission"]:
            authorities.append((row["admission"], "admit", identifier))
        if change:
            authorities += [(item, "small_change_decision", identifier) for item in change["decisions"]]
            if change["admission"]:
                authorities.append((change["admission"], "small_change_admit", identifier))
        for authority, kind, target in authorities:
            origin = provenance(authority, kind, target)
            event = read_json(origin["path"])["envelope"]["event"]
            brief.add("Approved scope", "authority_record", origin, request_id=identifier,
                      event_type=event["type"], record_sha256=digest(authority),
                      decision=event.get("decision"), plan_sha256=event.get("plan_sha256"),
                      decision_sha256=event.get("decision_sha256"))
    for obligation in status["obligations"]:
        # Owner, next decision and the blocker stay in their validated lifecycle record.
        brief.add("Open obligations", "lifecycle_obligation", latest[obligation["request_id"]],
                  **{key: obligation[key] for key in ("request_id", "request_sha256", "state", "owner", "next_decision")})


def job_packet(brief, mailbox, message, origin):
    reference = message["brief"]
    raw = mailbox.brief(reference)
    brief.add("Evidence references", "job_packet", reference, job_id=message["message_id"])
    content = raw.decode("utf-8")
    if content.startswith("---\n"):
        _, separator, content = content[4:].partition("\n---\n\n")
        require(bool(separator), "job packet message has no body")
    if not content.lstrip().startswith(("{", "[")):
        # Legacy prose packets cannot supply structured dependencies; retain the original, never guess.
        brief.add("Dependencies", "unstructured_job_packet", origin, job_id=message["message_id"],
                  state="dependencies_not_recorded")
        return
    try:
        packet = strict_json(content)
    except json.JSONDecodeError as exc:
        raise ValueError("job packet is not valid JSON") from exc
    require(isinstance(packet, dict), "job packet must be a JSON object")
    if "after" in packet:
        after = packet["after"]
        fields(after, {"message_id", "sha256"})
        matching(after["message_id"], SLUG, "dependency message_id")
        matching(after["sha256"], SHA256, "dependency sha256")
        brief.add("Dependencies", "job_after", reference, job_id=message["message_id"], after=after)
    source = {key: packet[key] for key in ("checkout", "commit", "tree", "dirty_sha256", "dirty_state_sha256",
                                          "dirty_content_sha256", "expected_tree", "recipes_sha256") if key in packet}
    if source:
        brief.add("Source identity", "job_source", reference, job_id=message["message_id"], source=source)


def mailbox_records(brief, mailbox, endpoint, initiative, delivery):
    records = mailbox.messages()
    relevant = {key: row for key, row in records.items()
                if initiative in (endpoint_parts(row["message"]["from"])[0], endpoint_parts(row["message"]["to"])[0])}
    closed, _ = mailbox.dispatch_history(records)
    open_jobs = {item["message_id"] for item in mailbox.open_job_requests(records)}
    history = mailbox.bindings(endpoint)
    if history:
        binding = history[-1]
        origin = file_ref(mailbox.root / "bindings" / endpoint / ("%06d.json" % binding["generation"]))
        brief.add("Evidence references", "binding", origin, generation=binding["generation"])
        checkpoint = binding["checkpoint"]
        if checkpoint:
            for reference in checkpoint["briefs"]:
                mailbox.brief(reference)
                brief.add("Evidence references", "checkpoint_brief", reference)
            brief.add("Approved scope", "checkpoint_leases", origin, lease_refs=checkpoint["lease_refs"])
            for source in checkpoint["sources"]:
                brief.add("Source identity", "checkpoint_source", origin, source=source)
    for identifier, record in sorted(relevant.items()):
        message = record["message"]
        kind = message["type"]
        origin = file_ref(record["path"])
        touching = endpoint in (message["from"], message["to"])
        if kind == "dispatch" and identifier not in closed and touching:
            brief.add("Open obligations", "dispatch", origin, message_id=identifier, state="open")
        if "brief" in message and (touching or kind == "job_request"):
            mailbox.brief(message["brief"])
            brief.add("Evidence references", "message_brief", message["brief"], message_id=identifier)
        if "readiness" in message and touching:
            ready = message["readiness"]
            brief.add("Source identity", "accepted_source", origin,
                      source={key: ready[key] for key in ("worktree", "branch", "base_revision")})
            brief.add("Approved scope", "accepted_lease", origin,
                      **{key: ready[key] for key in ("lease_ref", "lease_oid", "lease_expires_at")})
        if kind == "job_request":
            job_packet(brief, mailbox, message, origin)
            if identifier in open_jobs:
                receipts = [row["message"] for row in relevant.values()
                            if row["message"].get("in_reply_to") == identifier and row["message"]["type"] == "job_receipt"]
                receipts.sort(key=lambda item: (item["created_at"], item["message_id"]))
                brief.add("Open obligations", "job", origin, job_id=initiative + "/" + identifier,
                          message_id=identifier, state=receipts[-1]["receipt"]["state"] if receipts else "unreconciled")
        if kind in {"job_receipt", "result", "review", "ack"}:
            brief.add("Evidence references", "mailbox_evidence", origin, message_id=identifier, message_type=kind)
            brief.evidence(message.get("receipt", {}), origin)
            # Completion checks can be opaque reference strings; preserve the result record, without inventing hashes.
    delivery_rows, _ = mailbox.endpoint_delivery(delivery, endpoint, records)
    for kind in ("reads", "wakes"):
        folder = safe_path(delivery / kind / endpoint)
        if folder.exists():
            for path in sorted(folder.iterdir()):
                if not path.name.startswith("."):
                    brief.add("Evidence references", "delivery_" + ("read" if kind == "reads" else "wake"), file_ref(path))
    after = None
    while True:
        page = mailbox.inbox(endpoint, limit=100, after=after)
        for record in page["messages"]:
            identifier = record["message"]["message_id"]
            state = delivery_rows[identifier]["state"]
            if state != "read":
                brief.add("Unread work", "message", file_ref(record["path"]), message_id=identifier, state=state)
        if page["next_after"] is None:
            break
        require(page["next_after"] != after, "inbox cursor did not advance")
        after = page["next_after"]


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


def prepare(args):
    matching(args.initiative, SLUG, "initiative")
    require(endpoint_parts(args.endpoint)[0] == args.initiative, "endpoint is outside initiative " + args.initiative)
    mailbox, base, run, setup = locate(cli_path(args.root, "--root"), args.initiative)
    mailbox.endpoint(args.endpoint)
    brief = Brief()
    role_contract(brief, mailbox, base, setup, args.endpoint)
    brief.add("Source identity", "mailbox_identity", file_ref(mailbox.root / "manifest.json"))
    if setup:
        brief.add("Source identity", "runtime_pin", file_ref(base / "provision.json"), verification="recorded_only",
                  **{key: setup[key] for key in ("source", "source_commit", "source_tree") if key in setup})
    else:
        brief.notes["Source identity"].append("No provisioned runtime pin recorded; contracts come from the composer's checkout.")
    lifecycle = cli_path(args.lifecycle, "--lifecycle") if args.lifecycle else safe_path(run / "lifecycle")
    if args.lifecycle or lifecycle.exists():
        lifecycle_records(brief, lifecycle)
    else:
        brief.notes["Open obligations"].append("No lifecycle journal recorded at the default location; supply --lifecycle for an external journal.")
    delivery = cli_path(args.delivery_dir, "--delivery-dir") if args.delivery_dir else safe_path(
        setup["delivery_dir"] if setup else base / "delivery")
    brief.notes["Unread work"].append("Messages without a recorded read remain unread; a wake is not a read.")
    mailbox_records(brief, mailbox, args.endpoint, args.initiative, delivery)
    raw = brief.render(args.endpoint)
    inspect(raw)  # All validation precedes mkdir or creation of a temporary file.
    sha = hashlib.sha256(raw).hexdigest()
    reference = {"path": str(base / "briefs" / ("fresh-" + sha + ".md")), "sha256": sha}
    mailbox.brief(reference, verify=False)
    path = safe_path(reference["path"])
    if path.exists():
        require(read_bytes(path) == raw, "content-addressed brief already exists with different bytes")
    return raw, {"ok": True, "brief": reference, "entries": len(brief.seen)}


def publish(raw, reference):
    path = safe_path(reference["path"])
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, pending = tempfile.mkstemp(prefix=".fresh-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def main(argv=None):
    parser = JSONArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compose = commands.add_parser("compose")
    compose.add_argument("--root", required=True, help="Absolute team run, initiative base or handoff mailbox root")
    compose.add_argument("--initiative", required=True)
    compose.add_argument("--endpoint", required=True)
    compose.add_argument("--lifecycle", help="External lifecycle journal; default <run>/lifecycle")
    compose.add_argument("--delivery-dir", help="Read/wake receipts; default provisioned or <base>/delivery")
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
    except Exception as exc:
        print(json.dumps({"error": "brief publication failed: " + str(exc)}, sort_keys=True))
        return 3
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
