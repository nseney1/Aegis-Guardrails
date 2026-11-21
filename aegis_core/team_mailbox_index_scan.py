"""Confined full-history scanner and bounded byte-change evidence.

All file access is delegated to the TA-1a store. Parsed headers may be reused
only after hashing current bytes; policy and reply checks always run again.
"""
from copy import deepcopy
import hashlib
import os
import re

from aegis_core.team_mailbox_primitives import (
    MAX_BYTES, MAX_RECORDS, MAX_HISTORY_BYTES, MailboxRefusal,
    encoded, reply_reference, require, strict_json, validation,
)
from aegis_core.diagnostic_messages import guidance_value

__all__ = ["scan_history", "parse_message", "pending_entry", "Evidence"]

_MISSING = object()
MAX_EVIDENCE_ENTRIES = 10000
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
EVIDENCE_SUMMARY_BYTES = 32768
MAX_EVIDENCE_SAMPLE_PATHS = 8
MAX_EVIDENCE_SAMPLE_PATH_BYTES = 1024
MAX_EVIDENCE_COUNT = (1 << 63) - 1


def pending_entry(path, root, *, message_folders=()):
    """Recognize core stages and exact legacy stages in their writer's folder.

    The mailbox root and sibling record store are not history scan folders;
    their stages must never acquire an exemption in a binding/message folder.
    Callers supply only validated message routing folders.
    """
    return (re.fullmatch(r"\.pending-[0-9a-f]{32}", path.name) is not None
            or path.name == ".pending-root-id" and path.parent == root
            or path.name == ".pending-grants" and path.parent == root.parent / "mailbox-records"
            or path.name == ".pending-stub" and path.parent in message_folders)


class Evidence:
    """Bound history and pending facts together, including rejected-input churn."""
    def __init__(self):
        self.hashes, self.pending, self.samples = {}, {}, {}
        # pending[path] holds (first old SHA, verify-only acknowledgement).
        self.bytes = EVIDENCE_SUMMARY_BYTES
        self.overflow = self.saturated = False
        self.counts = {"omitted_changes": 0, "omitted_baseline_observations": 0, "unbaselined_reads": 0}

    @staticmethod
    def _path_key(path):
        return hashlib.sha256(os.fsencode(path)).hexdigest()

    def _count(self, field):
        self.overflow = True
        count = self.counts[field]
        self.counts[field] = min(count + 1, MAX_EVIDENCE_COUNT)
        self.saturated |= count >= MAX_EVIDENCE_COUNT

    @classmethod
    def path_sample(cls, path):
        shown = guidance_value(path, MAX_EVIDENCE_SAMPLE_PATH_BYTES)
        low, high = 0, len(shown)
        while low < high:
            middle = (low + high + 1) // 2
            if len(encoded(shown[:middle])) <= MAX_EVIDENCE_SAMPLE_PATH_BYTES:
                low = middle
            else:
                high = middle - 1
        return {"path": shown[:low], "path_sha256": cls._path_key(path), "path_truncated": shown[:low] != path}

    def _omit(self, path, old, sha, *, changed):
        self._count("omitted_changes" if changed else "omitted_baseline_observations")
        key = self._path_key(path)
        if key in self.samples:
            if changed:
                self.samples[key].update(new_sha256=sha, changed=True)
        elif len(self.samples) < MAX_EVIDENCE_SAMPLE_PATHS:
            self.samples[key] = {**self.path_sample(path), "old_sha256": old,
                                 "new_sha256": sha, "changed": changed}

    @staticmethod
    def _cost(path):
        return 2 * len(encoded(path)) + 1024

    def prune(self, live):
        # Only a complete successful scan can establish that a path is gone.
        for path in self.hashes.keys() - live.keys():
            sha = self.hashes.pop(path)
            self.bytes -= self._cost(path)
            if path in self.pending:
                self._omit(path, self.pending.pop(path)[0], sha, changed=True)
        live_samples = {self._path_key(path) for path in live} if self.samples else set()
        for key, item in list(self.samples.items()):
            if key not in live_samples and not item["changed"]:
                del self.samples[key]

    def covered(self, path):
        return path in self.hashes or self._path_key(path) in self.samples

    def admit(self, path, sha):
        if path in self.hashes:
            return True
        # Reserve two path representations, three SHA values, and fixed container
        # overhead. Pending updates then need no additional budget or allocation
        # proportional to the number of observations.
        cost = self._cost(path)
        if len(self.hashes) >= MAX_EVIDENCE_ENTRIES or self.bytes + cost > MAX_EVIDENCE_BYTES:
            self._omit(path, sha, sha, changed=False)
            return False
        self.hashes[path] = sha
        self.bytes += cost
        sample = self.samples.pop(self._path_key(path), None) if self.samples else None
        if sample is not None and sample["changed"]:
            self.pending[path] = (sample["old_sha256"], True)
        return True

    def observe(self, path, sha, baseline=None, *, uncovered=False):
        if path not in self.hashes:
            sample = self.samples.get(self._path_key(path)) if self.samples else None
            if sample is not None:
                if sample["new_sha256"] != sha:
                    self._omit(path, sample["new_sha256"], sha, changed=True)
                return
            # Never create history for a rejected, previously unknown path.
            if baseline is None:
                if uncovered and self.overflow:
                    self._count("omitted_changes")
                    self._count("unbaselined_reads")
                return
            if not self.admit(path, baseline):
                if baseline != sha:
                    self._omit(path, baseline, sha, changed=True)
                return
        previous = self.hashes[path]
        if previous != sha:
            self.pending.setdefault(path, (previous, False))
            self.hashes[path] = sha

    def checkpoint(self):
        return {path: self.hashes[path] for path in self.pending}

    @staticmethod
    def _change(path, old, sha):
        sample = Evidence.path_sample(path)
        location = sample if sample["path_truncated"] else {"path": path}
        return {"kind": "content_changed", **location, "old_sha256": old, "new_sha256": sha}

    def changes(self, before=None):
        result = [self._change(path, old, self.hashes[path]) for path, (old, _) in self.pending.items()
                  if before is None or before.get(path, _MISSING) != self.hashes[path]]
        result.extend(self._change(item["path"], item["old_sha256"], item["new_sha256"])
                      for item in self.samples.values() if item["changed"] and not item["path_truncated"])
        if self.overflow:
            result.append({"kind": "content_change_overflow", "overflow": True, **self.counts,
                           "counts_saturated": self.saturated,
                           "paths": [dict(item) for item in self.samples.values()]})
        return result

    def acknowledge_new(self, before):
        for path in self.pending.keys() - before.keys():
            if not self.pending[path][1]:
                del self.pending[path]

    def acknowledge_all(self, live):
        self.pending.clear()
        live_samples = {self._path_key(path) for path in live} if self.samples else set()
        for key, item in list(self.samples.items()):
            if key not in live_samples:
                del self.samples[key]
            else:
                item.update(old_sha256=item["new_sha256"], changed=False)
        self.overflow = self.saturated = False
        self.counts = dict.fromkeys(self.counts, 0)

    def stats(self):
        return {"entries": len(self.hashes),
                "pending_entries": len(self.pending) + sum(item["changed"] for item in self.samples.values()),
                "bytes": self.bytes, "max_entries": MAX_EVIDENCE_ENTRIES, "max_bytes": MAX_EVIDENCE_BYTES,
                "summary_paths": len(self.samples), "max_summary_paths": MAX_EVIDENCE_SAMPLE_PATHS,
                "max_total_paths": MAX_EVIDENCE_ENTRIES + MAX_EVIDENCE_SAMPLE_PATHS, "overflow": self.overflow}



@validation
def parse_message(raw):
    """Parse only bounded, store-read bytes; diagnostics never echo input."""
    require(type(raw) is bytes)
    require(len(raw) <= MAX_BYTES, reason="too_large")
    text = raw.decode("utf-8")
    require(text.startswith("---\n"))
    header, body = text[4:].split("\n---\n\n", 1)
    message = strict_json(header)
    require(type(message) is dict)
    message["body"] = body
    return message


def scan_history(mailbox, memo, evidence, *, force=False):
    """Return a complete validated candidate; caller publishes memo on success."""
    records, candidate, total = {}, {}, 0
    folders = {mailbox.root / endpoint.split("/")[0] / endpoint.split("/")[1]
               for endpoint in mailbox.manifest["endpoints"]}
    folders |= {mailbox.root / "across" / role for role in mailbox.roles.across_roles}
    for folder in sorted(folders):
        for path in mailbox.store.entries(folder):
            if pending_entry(path, mailbox.root, message_folders=folders):
                continue
            require(path.suffix == ".md")
            require(len(records) < MAX_RECORDS, reason="too_large")
            raw = mailbox.store.read(path, limit=min(MAX_BYTES, MAX_HISTORY_BYTES - total))
            total += len(raw)
            sha = hashlib.sha256(raw).hexdigest()
            key = str(path)
            previous = memo.get(key)
            evidence.observe(key, sha, None if previous is None else previous[0])
            message = (deepcopy(previous[1]) if not force and previous is not None
                       and previous[0] == sha else parse_message(raw))
            destination = mailbox.validate_message(message, stored=True)
            require(destination == folder)
            require(message["message_id"] not in records)
            records[message["message_id"]] = {"path": key, "message": message}
            candidate[key] = (sha, message)
    for record in records.values():
        if "in_reply_to" in record["message"]:
            reply_reference(record["message"], records)
    evidence.prune(candidate)
    for path, (sha, _) in candidate.items():
        evidence.admit(path, sha)
    mailbox.calls.history_bytes["messages"] = total
    return records, candidate
