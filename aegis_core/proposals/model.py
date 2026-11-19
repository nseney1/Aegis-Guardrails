"""Bounded, host-neutral proposal bytes. Repository metadata is untrusted state.

Errors expose a stable ``code``, never raw input or parser diagnostics. The
legacy missing-insight refusal may name strictly validated insight identities.
Evidence identities are opaque source-qualified event keys, not verified claims.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field, fields
import hashlib
import json
import re
import unicodedata

from aegis_core.redaction import (
    REDACTION_MARKER_RE, RedactionRefusal, clip_atomic_text, redact_insight_text,
    remove_url_credentials,
)
from aegis_core.primitives import sanitize_display
from aegis_core.taxonomy import CANONICAL_RULE_TYPES
from aegis_core.yaml_engine.frontmatter import split_frontmatter
from aegis_core.yaml_engine.parser import AegisYAMLError, parse_yaml_subset

MAX_PROPOSAL_BYTES = 65536
MAX_TEXT = 4096
MAX_EVIDENCE = 256
MAX_GUIDANCE_LINES = 65  # One generated count line and at most 64 summary bullets.
_INSIGHT_MESSAGES = {
    "insight_id": "invalid proposal_id",
    "insight_summary": "invalid proposal summary",
    "insight_verbatim": "proposal may not contain verbatim H/cli/W2 prompt text",
    "insight_counted": "not a counted insight",
    "insight_kind": "the insights share no single kind; pass --kind",
    "insight_paths": "the insights carry no paths; record them with aegis rule insight add --paths",
}
SOURCES = ("insight", "mine", "one", "lint")
DECISIONS = ("propose", "reject", "snooze", "merge-into-rule", "noise", "confirm", "accept")
TERMINAL = ("reject", "snooze", "merge-into-rule", "noise", "accept")
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{1,63}\Z")
_INSIGHT_ID = re.compile(r"ins-[0-9a-f]{12}\Z")
_KEY = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}\Z")
_LEGACY_FIELDS = {"id", "type", "status", "enforcement", "kind", "hypothesis", "target_paths", "insight_ids"}
PROPOSAL_FIELD_POLICIES = {
    "id": "identity", "source": "identity", "kind": "text", "candidate_key": "identity",
    "evidence_ids": "identity", "target_paths": "path", "revision": "identity",
    "parent_proposals": "identity", "source_lineage": "identity", "insight_ids": "identity",
    "status": "identity", "type": "identity", "enforcement": "identity", "amends": "identity",
    "hypothesis": "text", "prediction": "text", "do": "text", "labels": "text",
    "guidance": "text", "legacy": "identity", "count": "identity",
}
PROPOSAL_DECISION_FIELD_POLICIES = {
    "v": "identity", "ts": "identity", "event": "identity", "decision": "identity",
    "proposal_ids": "identity", "revisions": "identity", "evidence_ids": "identity",
    "operation_id": "identity", "reason": "text", "rule_id": "identity",
    "rule_digest": "identity", "until": "identity", "insight_ids": "identity",
}


class ProposalError(ValueError):
    """Refusal contract: code is a bounded category, never supplied text.

    Categories: invalid, too_large, unsafe, unsupported, missing, exists, stale,
    terminal, provenance, ancestry, decision, reason, operation, timeout, io,
    durability. A durability refusal may follow publication; identical retries
    reconcile the same bytes rather than silently replacing different content.
    """

    def __init__(self, code, *, insight_ids=()):
        self.code = code
        message = _INSIGHT_MESSAGES.get(code, "proposal refused: " + code)
        if code == "insight_counted" and insight_ids:
            ids = bounded_tuple(insight_ids, MAX_EVIDENCE, checked_insight_id)
            message += ": " + ", ".join(ids)
        super().__init__(message)


def checked_id(value):
    if (type(value) is not str or len(value) > 64 or not _ID.fullmatch(value)
            or clean_text(value, 64) != value):
        raise ProposalError("invalid")
    return value


def checked_insight_id(value):
    """Only the bounded ASCII identity minted by capture may enter a refusal."""
    if type(value) is not str or len(value) != 16 or not _INSIGHT_ID.fullmatch(value):
        raise ProposalError("insight_counted")
    return value


def _strip_parameters(value):
    """Remove complete adjacent/nested parameter groups; preserve redaction tags."""
    kept, index = [], 0
    while index < len(value):
        previous = kept[-1][-1:] if kept else ""
        parameter = previous.isalnum() or previous == "_" or value.startswith("[REDACTED", index)
        if value[index] != "[" or not parameter:
            kept.append(value[index])
            index += 1
            continue
        while index < len(value) and value[index] == "[":
            start, depth = index, 0
            while index < len(value):
                char = value[index]
                index += 1
                depth += (char == "[") - (char == "]")
                if depth == 0:
                    break
            if depth != 0:
                # An unmatched opener is literal. Resume after it so later,
                # complete parameter groups can still be recognized.
                kept.append("[")
                index = start + 1
                break
            group = value[start:index]
            if REDACTION_MARKER_RE.fullmatch(group):
                kept.append(group)
    return "".join(kept)


def _compose_redaction(value):
    """Redact, structurally remove, then redact without recovering raw input."""
    value = redact_insight_text(value, max_len=0)
    if len(value) > MAX_TEXT:
        raise ProposalError("too_large")
    try:
        value = remove_url_credentials(value, limit=MAX_TEXT, policy="proposal")
    except RedactionRefusal as refusal:
        raise ProposalError(refusal.code) from None
    return redact_insight_text(value, max_len=0)


def clean_text(value, limit=300):
    """Bound, redact original-case secrets, canonicalize/redact, then truncate."""
    if type(value) is not str or len(value) > MAX_TEXT:
        raise ProposalError("too_large" if type(value) is str else "invalid")
    if type(limit) is not int or limit < 0:
        raise ProposalError("invalid")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ProposalError("invalid") from None
    value = _compose_redaction(value)
    if len(value) > MAX_TEXT:
        raise ProposalError("too_large")
    value = unicodedata.normalize("NFKC", value)
    if len(value) > MAX_TEXT:
        raise ProposalError("too_large")
    value = sanitize_display(value, max_len=None)
    value = "".join(c for c in value if unicodedata.category(c) not in ("Cc", "Cf", "Cs") or c.isspace())
    value = " ".join(value.split())

    def scrub(text):
        # Removing controls or parameter groups can bring combining characters
        # together. Finish canonicalization before either URL or secret matching.
        text = unicodedata.normalize("NFKC", _strip_parameters(text))
        if len(text) > MAX_TEXT:
            raise ProposalError("too_large")
        text = _compose_redaction(text)
        if len(text) > MAX_TEXT:
            raise ProposalError("too_large")
        # Preserve host spelling; only the non-secret scheme is canonicalized.
        return re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://", lambda match: match.group().lower(), text)

    value = scrub(value)
    size = min(len(value), limit)
    while True:
        try:
            result = clip_atomic_text(value, size, policy="proposal")
        except RedactionRefusal as refusal:
            raise ProposalError(refusal.code) from None
        checked = scrub(result)
        if checked == result:
            return result
        # A cut may create an email/token match or leave half a mask/URL. Keep
        # only the unchanged prefix before that span; never publish a value
        # whose next cleaning would differ. Each retry strictly shortens it.
        common = next((i for i, pair in enumerate(zip(result, checked)) if pair[0] != pair[1]),
                      min(len(result), len(checked)))
        size = min(len(result) - 1, common)


def checked_key(value):
    if (type(value) is not str or len(value) > 256 or not _KEY.fullmatch(value)
            or clean_text(value, 256) != value):
        raise ProposalError("invalid")
    return value


def bounded_tuple(value, maximum, check):
    if type(value) not in (tuple, list) or len(value) > maximum:
        raise ProposalError("invalid")
    return tuple(dict.fromkeys(check(v) for v in value))


def checked_path(value):
    if (type(value) is not str or not 1 <= len(value) <= 512 or value.startswith("/")
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
            or any(c in value for c in ("\\", ":", "\x00"))
            or any(p in ("", ".", "..") or p.endswith((".", " ")) for p in value.split("/"))
            or clean_text(value, 512) != value):
        raise ProposalError("invalid")
    return value


@dataclass(frozen=True)
class Proposal:
    id: str
    source: str
    kind: str
    candidate_key: str
    evidence_ids: tuple = ()
    target_paths: tuple = ()
    revision: int = 1
    parent_proposals: tuple = ()
    source_lineage: tuple = ()
    insight_ids: tuple = ()
    status: str = "needs_draft"
    type: str = "trap"
    enforcement: str = "advisory"
    amends: str = ""
    hypothesis: str = ""
    prediction: str = ""
    do: str = ""
    labels: tuple = ()
    guidance: tuple = ()
    legacy: bool = dataclass_field(default=False, init=False, compare=False)

    def __post_init__(self):
        if {item.name for item in fields(self)} | {"count"} != set(PROPOSAL_FIELD_POLICIES):
            raise ProposalError("invalid")
        checked_id(self.id)
        if (any(type(getattr(self, name)) is not str for name in ("source", "status", "type", "enforcement"))
                or self.source not in SOURCES or self.status not in ("needs_draft", "proposal")
                or self.type not in CANONICAL_RULE_TYPES
                or self.enforcement not in ("advisory", "gate")
                or type(self.revision) is not int or not 1 <= self.revision <= 1000000):
            raise ProposalError("invalid")
        checked_key(self.candidate_key)
        if type(self.kind) is not str or "\n" in self.kind or "\r" in self.kind:
            raise ProposalError("invalid")
        object.__setattr__(self, "kind", clean_text(self.kind, 64))
        if not self.kind:
            raise ProposalError("invalid")
        if type(self.amends) is not str:
            raise ProposalError("invalid")
        if self.amends:
            checked_id(self.amends)
        for name, maximum, check in (("evidence_ids", MAX_EVIDENCE, checked_key),
                ("target_paths", 3, checked_path), ("parent_proposals", 64, checked_id),
                ("insight_ids", MAX_EVIDENCE, checked_id),
                ("source_lineage", 4, lambda v: v if type(v) is str and v in SOURCES else _invalid()),
                ("labels", MAX_EVIDENCE, lambda v: clean_text(v, 120))):
            object.__setattr__(self, name, bounded_tuple(getattr(self, name), maximum, check))
        if type(self.guidance) not in (tuple, list) or len(self.guidance) > MAX_GUIDANCE_LINES:
            raise ProposalError("invalid")
        # Bullet repetition and order are part of the legacy display contract.
        object.__setattr__(self, "guidance", tuple(clean_text(line, 200) for line in self.guidance))
        for name in ("evidence_ids", "parent_proposals", "source_lineage"):
            object.__setattr__(self, name, tuple(sorted(getattr(self, name))))
        if not self.source_lineage:
            object.__setattr__(self, "source_lineage", (self.source,))
        if self.source not in self.source_lineage or (self.insight_ids and "insight" not in self.source_lineage):
            raise ProposalError("ancestry")
        if "insight" in self.source_lineage and not self.insight_ids:
            raise ProposalError("ancestry")
        for name, limit in (("do", 300), ("hypothesis", 300), ("prediction", 300)):
            object.__setattr__(self, name, clean_text(getattr(self, name), limit))

    @property
    def count(self):
        return len(self.evidence_ids)

    @property
    def private(self):
        return "insight" in self.source_lineage

    def to_bytes(self):
        lines = ["---"]
        for field in fields(self):
            if field.name in ("do", "labels", "guidance", "legacy"):
                continue
            value = getattr(self, field.name)
            if isinstance(value, tuple) and value:
                lines.append(field.name + ":")
                lines.extend("  - " + json.dumps(v, ensure_ascii=False) for v in value)
            else:
                lines.append(field.name + ": " + json.dumps(value, ensure_ascii=False))
        lines.extend(["count: " + str(self.count), "---", "## Do", self.do, ""])
        if self.guidance:
            lines.extend(["## Guidance", ""])
            lines.extend("- " + line for line in self.guidance)
            lines.append("")
        lines.append("## Evidence")
        lines.extend("- source-reported " + json.dumps(e, ensure_ascii=False) for e in self.evidence_ids)
        # Insight-derived public files contain identifiers and generated guidance only.
        if not self.private:
            lines.extend("- label (untrusted data): " + json.dumps(v, ensure_ascii=False) for v in self.labels)
        return _bounded_lines(lines)


def _bounded_lines(lines):
    chunks, size = [], 0
    for line in lines:
        chunk = (line + "\n").encode("utf-8")
        if len(chunk) > MAX_PROPOSAL_BYTES - size:
            raise ProposalError("too_large")
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def legacy_insight_text(proposal):
    """Pre-store insight publication bytes, retained on unsupported platforms.

    The shared preparation has already checked eligibility, verbatim text and
    per-line limits. Keep the historical metadata, headings and final newline.
    """
    hypothesis = f"Prevent recurring {proposal.kind} issues in {', '.join(proposal.target_paths)}."
    lines = ["---", f"id: {proposal.id}", "type: trap", "status: proposal", "enforcement: advisory",
             "kind: " + json.dumps(proposal.kind), "count: " + str(proposal.count),
             "hypothesis: " + json.dumps(hypothesis), "target_paths:"]
    lines.extend("  - " + json.dumps(p) for p in proposal.target_paths)
    lines.append("insight_ids:")
    lines.extend("  - " + json.dumps(i) for i in proposal.insight_ids)
    lines.extend(["---", f"# Proposal: {proposal.id}", "", "## Guidance", ""])
    lines.extend("- " + bullet for bullet in proposal.guidance)
    return _bounded_lines(lines).decode("utf-8")


def _invalid():
    raise ProposalError("invalid")


def _unicode_metadata(metadata):
    """Repair valid escaped UTF-16 pairs from historical JSON-in-YAML scalars."""
    def paired(value):
        if type(value) is not str:
            return value
        if len(value) > MAX_TEXT:
            raise ProposalError("invalid")
        if any(0xd800 <= ord(char) <= 0xdfff for char in value):
            return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        return value

    for name, value in metadata.items():
        if type(value) is list:
            if len(value) > MAX_EVIDENCE:
                raise ProposalError("invalid")
            metadata[name] = [paired(item) for item in value]
        else:
            metadata[name] = paired(value)


def _legacy_proposal(metadata, count, body, expected_id):
    if (set(metadata) != _LEGACY_FIELDS or metadata["id"] != expected_id
            or metadata["type"] != "trap" or metadata["status"] != "proposal"
            or metadata["enforcement"] != "advisory"):
        raise ProposalError("invalid")
    try:
        ids = bounded_tuple(metadata["insight_ids"], MAX_EVIDENCE, checked_insight_id)
    except ProposalError:
        raise ProposalError("invalid") from None
    if not ids or count != len(ids) or len(ids) != len(metadata["insight_ids"]):
        raise ProposalError("invalid")
    raw_kind = metadata["kind"]
    if type(raw_kind) is not str or not 1 <= len(raw_kind) <= 64:
        raise ProposalError("invalid")
    heading = f"# Proposal: {expected_id}\n\n## Guidance\n\n"
    if not body.startswith(heading):
        raise ProposalError("invalid")
    bullets = body[len(heading):].rstrip("\n").split("\n", MAX_GUIDANCE_LINES)
    if not 1 <= len(bullets) <= MAX_GUIDANCE_LINES or any(not line.startswith("- ") for line in bullets):
        raise ProposalError("invalid")
    guidance = tuple(clean_text(line[2:], 200) for line in bullets)
    # Validate the historical template using its stored kind before normalizing
    # that field. Baseline truncation could leave a space inside the backticks.
    historical = clean_text(f"{count} counted correction(s) of kind `{raw_kind.replace('`', '')}`.", 200)
    if guidance[0] != historical:
        raise ProposalError("invalid")
    canonical_kind = clean_text(raw_kind, 64)
    generated = clean_text(f"{count} counted correction(s) of kind `{canonical_kind.replace('`', '')}`.", 200)
    guidance = (generated,) + guidance[1:]
    proposal = Proposal(id=expected_id, source="insight", kind=metadata["kind"],
        candidate_key="insight:" + hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest(),
        evidence_ids=tuple("insight:" + identity for identity in ids), insight_ids=ids,
        target_paths=metadata["target_paths"], status="proposal", hypothesis=metadata["hypothesis"],
        do=guidance[0], guidance=guidance)
    object.__setattr__(proposal, "legacy", True)
    return proposal


def parse_proposal(data, expected_id):
    if type(data) is not bytes:
        raise ProposalError("invalid")
    if len(data) > MAX_PROPOSAL_BYTES:
        raise ProposalError("too_large")
    checked_id(expected_id)
    try:
        status, front, body = split_frontmatter(data.decode("utf-8"))
        if status != "ok" or type(front) is not str or type(body) is not str:
            raise ProposalError("invalid")
        body = body.lstrip("\r\n")
        metadata = parse_yaml_subset(front)
        if type(metadata) is not dict:
            raise ProposalError("invalid")
        count = metadata.pop("count", None)
        allowed = {f.name for f in fields(Proposal)} - {"do", "labels", "guidance", "legacy"}
        if type(count) is not int or set(metadata) not in (allowed, _LEGACY_FIELDS):
            raise ProposalError("invalid")
        _unicode_metadata(metadata)
        if set(metadata) == _LEGACY_FIELDS:
            return _legacy_proposal(metadata, count, body, expected_id)
        if not body.startswith("## Do\n") or body.count("\n## Evidence\n") != 1:
            raise ProposalError("invalid")
        do, evidence = body[len("## Do\n"):].split("\n## Evidence\n")
        guidance = ()
        if "\n## Guidance\n" in do:
            do, guidance_text = do.split("\n## Guidance\n")
            bullet_lines = guidance_text.strip("\n").splitlines()
            if len(bullet_lines) > MAX_GUIDANCE_LINES or any(not line.startswith("- ") for line in bullet_lines):
                raise ProposalError("invalid")
            guidance = tuple(line[2:] for line in bullet_lines)
        if "\n" in do.strip():
            raise ProposalError("invalid")
        labels = []
        for line in evidence.splitlines():
            if line.startswith("- label (untrusted data): "):
                labels.append(json.loads(line[len("- label (untrusted data): "):]))
            elif line and not line.startswith("- source-reported "):
                raise ProposalError("invalid")
        proposal = Proposal(**metadata, do=do.strip(), labels=tuple(labels), guidance=guidance)
        if proposal.id != expected_id or count != proposal.count:
            raise ProposalError("invalid")
        return proposal
    except (UnicodeError, ValueError, KeyError, RecursionError, AegisYAMLError) as error:
        if isinstance(error, ProposalError):
            raise
        raise ProposalError("invalid") from None


@dataclass(frozen=True)
class StoredProposal:
    proposal: Proposal
    digest: str


def stored(proposal, data):
    return StoredProposal(proposal, hashlib.sha256(data).hexdigest())
