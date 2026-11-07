# Fresh-thread briefs

`tools/hierarchy_fresh_brief.py compose --root /absolute/run --initiative ID
--endpoint ID/lane/NAME` writes one Markdown brief with seven sections: Role
contract, Approved scope, Source identity, Open obligations, Dependencies, Unread
work, and Evidence references. Its resume line starts with verification, the
current binding/checkpoint, successor acknowledgment, lossless inbox paging and
reconciliation of uncertain effects before new work.

`--root` also accepts the initiative base or the mailbox root used by handoff
entries. The output is `<mailbox-parent>/briefs/fresh-<sha256>.md`, published with
a temporary file and `os.replace`. Publication opens every directory component
with `O_DIRECTORY|O_NOFOLLOW`, then creates and replaces files relative to the
opened directory descriptors. A swapped directory is refused; its symlink target
is never written. Platforms without these operations refuse before writing.
The JSON answer's `brief` object has exactly
`path` and `sha256`, for the existing handoff `briefs` field. Identical records
produce identical bytes and paths. Every entry has a durable path and byte hash;
only the role contract is inlined, using the launcher's role-kind and host-family
rendering. ROOT's contract is referenced only, since the launcher never starts it.

The global bound is **256 entries**, counting each JSON bullet across all seven
sections, including evidence and contract references. Individual entries describe
unsettled requests, open dispatches/jobs, unread messages and current leases.
Resolved requests and expired continuations supply no approved scope; a closed
dispatch supplies no current lease. One journal-head event reference anchors the
validated lifecycle hash chain, so settled events do not accumulate entries.
Mailbox history has no hash chain: its history locator is labeled `unverified`,
and does not authenticate earlier messages. Historical briefs/packets and old
checkpoint references are not reverified or expanded into individual entries.
Overflow refuses without
writing anything; nothing is truncated. The mailbox's 262144-byte brief limit also
applies. `verify --path /absolute/brief.md --sha256 HASH` checks the bytes, section
order, bound and primary references. Exit codes are 0 success, 2 refusal before
writing, and 3 publication/internal error.

Lifecycle data comes from `<run>/lifecycle`; use `--lifecycle` for an external
journal. It is journal-wide because requests do not identify a mailbox endpoint.
The JSON answer reports `coverage.lifecycle` as `journal_wide_registered_requests`
or `absent`. Successor requests created inside `disposition`/`resolve` with a
`next` resolution refer to that creating event, even without a later publish.
Read/wake receipts come from the provisioned delivery directory or `<base>/delivery`
(override with `--delivery-dir`). The composer pages `Mailbox.inbox` and retains
every message without a read by the current binding generation, including woken
messages. A predecessor's read does not count for a successor. The resume line
also directs a new generation to begin paging at the start of its own inbox.
Only the latest read/wake receipt is a standalone evidence entry; unread messages
can reference their wake receipt directly. Missing receipt history cannot
establish that anything was read. Unknown lifecycle effects and open jobs retain
their original identities and request hashes. Job receipts are reconciled by
durable time and original request: later uncertainty overrides earlier terminal
claims, and started receipts cannot clear unknown effects. Timestamp ties and
conflicting outcomes remain unknown; only a strictly later terminal reply to the
same request settles them. These are record claims, not execution authority.

The records cannot always supply approved paths, dependencies, evidence hashes or
a runtime pin. Missing data is stated explicitly. Published scope is a declaration;
approval and admission remain separate records. Provisioned runtime identities
are recorded claims, not a fresh checkout verification. Prose job packets and
opaque completion-check references are preserved through their original records;
no structured dependency or hash is invented. Missing or changed declared evidence
is labeled unverified and anchored to its originating record. A missing or changed
brief/packet on an open dispatch/job refuses composition; historical attachments
do not block it. Secrets, message
bodies and transcripts are not copied into the brief.

The composer does not publish messages, record reads/events, replay work, release
resources, settle jobs, change leases or advance accounting. It grants no new
authority and does not replace the handoff's binding/generation checks. References
describe the records inspected during composition; live stores may subsequently
advance, so a successor must re-read current state.
