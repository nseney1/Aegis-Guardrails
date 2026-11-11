# Mailbox index and read-only doctor

Routing message files remain the source of truth. The index in
`tools/hierarchy_mailbox_index.py` is an in-process derived view; it writes no
cache, database or divergence log. Every admitted record originates from bytes
validated by the pinned `tools/hierarchy_mailbox.py` validators. Restarting the
reader discards its memo and byte history.

## Rollout phases

Phase 0 uses shadow comparison. Each indexed read is compared with the pinned
reader's canonical result, order and failure outcome. A mismatch is retried once;
continued disagreement returns or raises the pinned outcome and records in-memory
diagnostics. The proposed phase-0 exit requires zero divergences in three
successful dogfood runs and a 10,000-message fixture run. Owner acceptance is a
separate gate: passing a test does not authorize a runtime importer.

Phase 1 admits readers through the rollout contract in
`tests/contract/test_mailbox_index_rollout.py`. The owner approved the doctor as
the first and only admitted importer (MB-5 round 1b, Addendum A), read-only and in
literal `mode="shadow"`. Every second importer is still refused. Indexed-only
reads require separate owner acceptance; this admission does not change other
phase-0 gates, mode guards or receiver attribute restrictions.

Track P's proposed store upgrade is a separate pinned change: file-plus-log
publication, adoption and chain verification are not features of this index or
doctor. Track U rollback means reverting an admitted reader change or restarting
the process. There is no persisted Track U cache to remove.

## Index verification and limits

An existing index instance's `verify()` forces reads, parsing and pinned checks.
When it has an earlier byte baseline, changes appear as `content_changed` with
`path`, `old_sha256` and `new_sha256`. A new one-shot process cannot reconstruct
earlier content. Fallback to the pinned API cannot establish which raw bytes the
pinned call read, even when the parsed values match; `verification_unavailable`
reports that coverage gap. Bounded evidence overflow is reported as
`content_change_overflow`, rather than silently claiming unchanged bytes.

The memo keys include message size, mtime, ctime, inode and device, and live
filesystem dependencies. Directory dependency keys use identity, type,
permissions and owner rather than timestamps. Listings and access observations
remain live. Unchanged keyed outcomes may be reused for records not returned;
returned records are opened and hash-checked again. Accepted limitations include
mandatory access-policy changes invisible to unchanged keys and a same-stat
content rewrite of an unreturned record. Full verification is needed where those
risks matter. These are observations across multiple files, not an atomic
snapshot, authenticated history, or approval evidence.

Acceptance criterion **AC1** is a warm 10,000-message index: `get(id)` and
`inbox(endpoint, limit=20)` each take less than 0.2 seconds and equal the pinned
`messages()`/`inbox()` result byte for byte after canonical encoding. This is a
qualification target, not a performance result established by the doctor tests.

## Running the doctor

```console
python3 tools/hierarchy_mailbox_doctor.py /absolute/path/to/mailbox
python3 tools/hierarchy_mailbox_doctor.py /absolute/path/to/mailbox --json
```

The doctor never creates a lock, takes one over, writes a receipt, repairs a
message, removes a pending file or modifies mailbox bytes. It checks each
routing entry using the original pinned `Mailbox.messages()` parser and stored
message validator through an operation-local descriptor-backed filesystem view.
Healthy mailboxes use one pinned traversal. A refusal triggers folder-level
scans; only refused folders are then parsed file by file to report every
malformed entry. Folder enumeration narrows to one representative endpoint while
membership and route validation retain the complete manifest. Each message is
parsed at most three times during diagnostics (initial, folder, isolated-file
passes), and each narrowed call visits at most its folder plus the three fixed
across folders. Diagnostic work is linear in entries plus folders, even when
malformed files are spread across many folders. The separate shadow comparison
retains its existing bounded retry policy.
Reply validation is deferred until the complete set of valid records is known;
duplicates, wrong-folder messages and unresolved replies are problems. Original
pinned binding and checkpoint validators check binding histories, then each
retained checkpoint brief is re-hashed, including historical generations.

The default text report names each problem and includes capacity, lock status
and an index comparison line, for example:

```text
index: equal
```

`--json` emits one document with schema `aegis.hierarchy-mailbox-doctor/v1`.
A healthy example is:

```json
{
  "schema": "aegis.hierarchy-mailbox-doctor/v1",
  "mailbox": "mailbox",
  "healthy": true,
  "cap": {"count": 1, "limit": 10000, "headroom": 9999},
  "lock": {"status": "absent"},
  "issues": [],
  "index": {
    "status": "equal",
    "differences": []
  }
}
```

The doctor constructs a transient shadow comparator and calls the existing
index module's `compare()` function. Original index method code uses a local
descriptor adapter; neither module's globals or validator code are patched.
It compares fresh index reads against the pinned bytes observed during this
inspection. `index.status` is `equal`, `diverged`, or `unavailable` after pinned
reconciliation. Differences retain the comparator's `mailbox_index_divergence`
with `index_sha256` and `pinned_sha256`, and/or `mailbox_index_key_order`.
These hashes describe canonical outcomes, not historical file SHA baselines.
Unequal or unavailable comparison adds `MD_INDEX` and exits 1. Underlying I/O
or budget refusals still exit 2 even if the index falls back to pinned values.
No existing index is repaired or rebuilt and nothing is persisted. A concurrent
message edit can legitimately yield divergence; this is not an atomic snapshot.

`cap.count` includes malformed `.md` routing files; it does not imply valid
messages. Reaching the cap is a problem. `lock.status` is `absent`, `alive`,
`dead`, `unknown` (permission denied to the liveness probe), or `malformed`.
Valid holders include their numeric `pid`; signal zero probes liveness only.
An alive PID may have been reused, so this is no proof of lock ownership.
Pending entries anywhere beneath the mailbox produce `MD_PENDING`; they are
orphan candidates, since a concurrent writer may still be publishing them.

Issue objects contain `code` and `path`. Paths are relative to the mailbox's
parent. Each field is NFKC normalized and redacted before sanitizing; controls
become spaces and whitespace collapses, then the shared secret table redacts the
display form again before truncation to 256 characters plus an ellipsis. They are
display labels, not safe inputs for automated repair. Exception messages,
message bodies, sessions and other untrusted content are never echoed.

| Exit | Meaning | Codes |
| --- | --- | --- |
| 0 | Checked items healthy and index comparison equal | No issues |
| 1 | Problems found | `MD_MESSAGE`, `MD_DUPLICATE`, `MD_BINDING`, `MD_BRIEF`, `MD_PENDING`, `MD_LOCK`, `MD_CAP`, `MD_INDEX` |
| 2 | Usage or inspection refusal | `MD_USAGE`, `MD_PLATFORM`, `MD_PATH`, `MD_LIMIT`, `MD_IO`, `MD_DATA` |

Refusals emit an `error` object with a fixed `code` and `message`, alongside the
schema, instead of a partial healthy report. A broken output stream returns 2
without a complete document. Missing or malformed checkpoint brief content is
`MD_BRIEF`; unsafe symlink paths and general I/O failures refuse inspection.

The doctor requires POSIX directory descriptors, no-follow opens, descriptor
listings and no-follow stat. Other platforms explicitly return `MD_PLATFORM`
with exit 2; there is no insecure pathname fallback. The filesystem anchor is
walked by descriptor to pin the mailbox and its parent. Every byte read uses
those pinned roots and no-follow component opens, so concurrent renames and
symlink substitutions cannot redirect reads outside them. Outside readiness
references receive metadata checks only. Stored-message brief references retain
the pinned stored validator's inert semantics; checkpoint briefs are hashed.
The index's checked stream owns transferred descriptors and closes them even
when `fdopen` raises. All other opens have a closing `finally` or context manager.

Before parsing, a recursive mailbox preflight limits unique entries to 20,000,
individual regular files to 262,144 bytes, aggregate declared regular-file sizes
to 64 MiB, retained path names to 4 MiB, each absolute path to 4,096 filesystem
bytes, and path depth to 64 components. Ignored and pending entries also count.
Reads recheck file type and size before allocation, have a separate aggregate
64 MiB byte budget including fresh index reads and referenced briefs, and refuse
detected growth. JSON nesting is checked before either parser and is limited to 64.
The operation-local snapshot does not lock out publishers; rerun an inspection
that refuses because inputs changed. Index verification, chain verification,
native behavior and performance qualification remain separate gates.
