# Fresh-thread briefs

`tools/hierarchy_fresh_brief.py compose --root /absolute/run --initiative ID
--endpoint ID/lane/NAME` writes one Markdown brief with seven sections: Role
contract, Approved scope, Source identity, Open obligations, Dependencies, Unread
work, and Evidence references. Its resume line starts with verification, the
current binding/checkpoint, successor acknowledgment, lossless inbox paging and
reconciliation of uncertain effects before new work.

`--root` also accepts the initiative base or the mailbox root used by handoff
entries. The output is `<mailbox-parent>/briefs/fresh-<sha256>.md`, published with
a temporary file and `os.replace`. Publication uses directory descriptors,
`O_DIRECTORY|O_NOFOLLOW`, and Linux `O_PATH` where available so ancestors need
only search permission (`O_RDONLY` otherwise). Special destinations are opened
nonblocking and refused before reading unless their descriptor is a regular file.
The returned pathname must identify the written `(st_dev, st_ino)` after rename;
on mismatch the composer removes its own inode through the descriptor and exits 3.
Platforms without the required descriptor operations refuse before writing.
On POSIX the temporary file is fsynced before rename, then the destination
directory and its parent are fsynced through anchored `O_RDONLY` handles, in that
order, before every successful return. Reuse, retries after a failed sync, and
concurrent directory creation all repeat both directory syncs; an existing
directory alone is not proof that its pathname was persisted.
Directory syncing requires read permission on both `briefs` and its immediate
parent on every composition; more distant ancestors still need only search
permission on Linux. A sync failure exits 3 and may leave the published file; it
is not success. If a filesystem rejects directory fsync (for example with
`EINVAL`), composition fails with exit 3 rather than claiming durability.
Windows cannot fsync directory handles, so that sync step is explicitly skipped
there; the separate secure-publication capability guard continues to apply.

The threat model covers misconfiguration, accidents, concurrent tools and other
users. It does **not** cover a hostile process of the same user swapping path
components mid-command, matching the team command's ADR sections 3 and 7. The
composer does not retain and revalidate every ancestor identity. Before creating
anything, it rejects output-directory overlap in either direction with the
mailbox, lifecycle journals, delivery directories, workspace/board stores and the
stores named in the run's provision records (including other initiatives and
retained provision inputs/evidence). An override does not unprotect a recorded store.

The JSON answer's `brief` object has exactly
`path` and `sha256`, for the existing handoff `briefs` field. Identical records,
`--as-of` and target generation produce identical bytes and paths. Every entry has
a durable path and byte hash. Role contracts are read directly from the same
templates; subprocess tests pin text equality with `launcher.start_prompt` for
every launched role and host family. The composer imports no operational prompt
renderer. ROOT's contract is referenced only, since the launcher never starts it.

`--as-of <RFC3339 UTC>` accepts `Z` or `+00:00`, defaults to now, and is recorded
in the brief and JSON answer. It supplies every expiry comparison. This is an
explicit snapshot input, not ongoing authority: a resume must validate expiry
live, as the resume line requires. Supply the same time when reproducing a brief.

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
journal. Events and policy use the lifecycle reader's 1 MiB record limit, not the
mailbox reader's 256 KiB limit. Coverage is journal-wide because requests do not
identify a mailbox endpoint.
The JSON answer reports `coverage.lifecycle` as `journal_wide_registered_requests`
or `absent`. Successor requests created inside `disposition`/`resolve` with a
`next` resolution refer to that creating event, even without a later publish.
Read/wake receipts come from the provisioned delivery directory or `<base>/delivery`
(override with `--delivery-dir`). The composer pages `Mailbox.inbox` and retains
every message read by no generation individually, including woken messages.
Messages read only by predecessors form one `read_by_predecessor` entry: a count,
counts by message type (including escalations), and the latest applicable read
receipt's path and sha256. That receipt locates read history; it does not
authenticate every earlier receipt. A target generation's own reads are excluded.
`--target-generation N` selects which generation's reads apply and is recorded in
the brief and JSON answer. The default is current + 1 for a ready binding (compose
before succession), or current for an unacknowledged successor (compose after
bind); an unbound endpoint targets generation 1. Override the default when
composing for an already acknowledged current generation. Targets older than the
current binding refuse. The resume line directs each new generation to start its
own inbox cursor. This keeps both compose-then-bind and bind-then-compose bounded.
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

Hash-bound structured job packets are checked before extracting their fields:
recognized runner v1/v2 schemas, their closed field sets, required v2 `after` and
recipe hash, scalar source hashes/checkout, and bounded string paths. Malformed
packets refuse with the packet path and field in the error, without copying an
object into the brief. The composer uses the runner's packet-text reader, schema
constants, path grammar/limits and existing field validators. The runner has no
standalone schema validator: full `admit()` additionally checks recipes, live
checkouts and dependency evidence. Those execution checks remain with the runner;
structural validation here is not job admission. Regression tests compare the
missing-`after` and malformed-`commit` refusals with the runner's admission API.
For no-paths packets, the runner's falsy `paths` values are accepted and represented
as an effective empty list in the brief; empty objects are never copied into it.
Truthy paths still require a bounded list of valid path strings. Merge packets
without a `paths` key are preserved, with live merge admission left to the runner.

The composer does not publish messages, record reads/events, replay work, release
resources, settle jobs, change leases or advance accounting. It grants no new
authority and does not replace the handoff's binding/generation checks. References
describe the records inspected during composition; live stores may subsequently
advance, so a successor must re-read current state.
