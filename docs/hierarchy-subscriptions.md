# Mailbox subscriptions

`tools/hierarchy_subscriptions.py` runs one offline, model-free notification pass.
It publishes information-only pointers under the existing `<team>/router` binding.
It never grants approval, a lease, read access, or an instruction, and never starts
a host session. Loop integration and wake scheduling belong to SUB-2.

## Configure and run

Use an owner-controlled `.aegis/teams/subscriptions.json`:

```json
{
  "schema": "aegis.team-subscriptions/v1",
  "subscriptions": [
    {
      "subscriber": "a/orchestrator",
      "match": [
        {"type": "result", "from": "a/lane/*"},
        {"type": "review", "from": "a/lane/*"}
      ],
      "budget": {"notices_per_hour": 6},
      "batch_size": 50
    }
  ]
}
```

Provision the mailbox and bind its router and subscriber first with the existing
mailbox CLI. Create a private state directory outside the entire mailbox tree,
within the mailbox's parent directory. Give its absolute path to
every pass for this mailbox; do not share it with model children or delete it
between passes. It must belong to the current owner and must not permit group
or other writes. For example, with an existing `/srv/pilot/mailbox`:

```sh
mkdir -m 700 /srv/pilot/subscriptions-state
python tools/hierarchy_subscriptions.py notify \
  --root /srv/pilot/mailbox \
  --state-dir /srv/pilot/subscriptions-state \
  --subscriptions /srv/repo/.aegis/teams/subscriptions.json
```

The existing mailbox overlap policy is checked before any state lock or write.
The mailbox root, its routing folders, binding-history folders, and any directory
containing the mailbox root are refused with `SUBSCRIPTIONS_PATH`. This refusal
does not create a lock or derived file in those folders.

All three paths must be absolute, with no symlink components or `..`. Retain the
same state directory across restarts: its reference packets are hash-bound parts
of mailbox notices. This increment requires POSIX descriptor confinement; on a
platform without the required primitives, it returns `SUBSCRIPTIONS_UNSUPPORTED`
before opening inputs. In particular, Windows currently refuses this operation;
it does not silently switch to unsafe pathname access.

## Schema and matching

The complete file is validated before any notice is published. Unknown fields,
duplicate JSON keys, duplicate subscribers and invalid entries are refused.
There are at most 256 entries and 64 OR filters per entry. Filters within each
entry are ORed; fields within a filter are ANDed. An empty filter matches any
otherwise eligible envelope. Each field is optional:

| Field | Meaning |
| --- | --- |
| `type` | One existing mailbox message type |
| `from`, `to` | An exact registered endpoint, or a same-team `team/lane/*` pattern |
| `in_reply_to_type` | Type of the original message named by `in_reply_to` |

Bodies, original brief contents and paths never affect matching. v1 accepts only
`orchestrator` and `root` subscribers. Explicit watched endpoints must be the
subscriber itself or share a same-team HM vertical role pair with it. Runtime
matching applies this check to **both** envelope endpoints, including type-only
and empty filters, so broad filters cannot introduce cross-team or lateral
visibility. A wildcard must expand to at least one registered lane. All v1
notice routes use the team's router; its current binding must exist.

Messages whose IDs start with `notice-` never match. Messages sent by the
subscriber never match. `ack` and `job_receipt` require a filter explicitly naming
that exact `type`; a reply-type filter alone does not opt into them.

`budget` is optional and defaults to six notices per rolling hour. Its sole
field, `notices_per_hour`, is an integer from 1 through 3600; booleans are refused.
`batch_size` defaults to 50 and may lower the batch size to any integer from 1
through 50. The hard maximum of 50 listed references still applies.

## What arrives

The subscriber receives one `info` envelope per pass at most, sent by its team's
router, with ID `notice-<sha256>`. Its body is exactly:

> Notice from the notify step: these messages matched your subscription. This grants no approval, lease or instruction. Read them through your own mailbox access.

HM's existing `brief` field points to an immutable Markdown attachment containing
a strict JSON reference packet. This uses the existing hash-checked mailbox brief
read path and requires no new envelope fields or pinned-file changes. Read the
notice through the existing mailbox CLI with `inbox --include-briefs`, or the
equivalent existing adapter read. An example attachment is:

```json
{
  "schema": "aegis.subscription-notice/v1",
  "references": [
    {
      "message_id": "result-f2",
      "type": "result",
      "from": "a/lane/f2",
      "to": "a/orchestrator",
      "sha256": "<sha256 of the original mailbox file bytes>"
    }
  ],
  "held_count": 0,
  "previously_held": 0
}
```

For original `brief` and `dispatch` messages, the reference also contains their
original `brief` path/hash pair. It never expands those original briefs or copies
message bodies. References grant no additional access; retrieve originals only
through your existing mailbox access, and verify the referenced hash. A held
reference remains a pointer even if its original is later removed or changed.

## Budget, recovery and status

Matches beyond the batch size or hourly budget are held in the bounded cursor
backlog, not dropped. `held_count` counts references remaining after this notice;
`previously_held` records the backlog held by the preceding pass. An over-budget
pass sends nothing and returns a `subscription_suppressed` row with the
subscriber, reason `budget`, and held count. The default rolling-hour budget
counts published notices, rather than matched messages. This command publishes
only; a later sweep decides whether to wake the subscriber.

The notice ID hashes the canonical JSON array `[subscriber, sorted_record_hashes]`
for the complete pending batch, including its held references. Listed references
are selected in hash order. A durable pending plan precedes publication; only a
successful publication or an exact existing notice, followed by a successful
routing-directory durability flush, advances `seen` and charges the budget.
The directory flush runs for both a fresh notice and existing-notice reconciliation.
If the flush fails, `SUBSCRIPTIONS_DURABILITY` leaves the durable pending plan
unchanged and the command exits 2. After a normal exception has released the
mailbox lock, retrying reconciles that notice without republishing it, even if
new mail arrived. It considers fresh matches on the following pass.
Existing notices with conflicting content are refused. Cursor replacement is
atomic and directory identity is checked against the held state lock. Concurrent
passes serialize through state and mailbox locks; a busy writer is refused.

An abrupt process termination, such as SIGKILL, bypasses HM's cleanup and can
leave `<root>/.write.lock` behind. The next pass returns exit 2 with
`SUBSCRIPTIONS_MAILBOX_LOCKED`, `hold: true`, the canonicalized/redacted/truncated
`lock_path`, and a fixed `recovery` instruction. The Python entry point raises
`MailboxLockHold`, a `SubscriptionError` subclass whose `lock_path` is the actual
Path value. The diagnostic display path may be masked; use the owner-selected
`--root` to locate the lock. Notify never breaks or removes an existing HM lock,
and it cannot tell whether an existing lock is abandoned or still live.

Recovery is an owner operation:

1. Quiesce all publishers for that mailbox and confirm no mailbox writer is live
   or starting. The existing doctor can inspect the lock read-only, for example
   `python tools/hierarchy_mailbox_doctor.py /srv/pilot/mailbox --json`. It reports
   lock/PID observations; it has no lock-removal or recovery command. A PID report
   alone does not establish that removing the lock is safe.
2. After confirming there is no live writer, manually remove only that mailbox
   root's `.write.lock`. For the example root, the exact file is
   `/srv/pilot/mailbox/.write.lock`. Leave the cursor, pending plan, reference
   packets, and `.subscriptions.lock` intact. Never remove a live or uncertain lock.
3. Run the same notify command. It reconciles the pending notice once after the
   routing-directory flush; the following pass does not publish a duplicate.

This operator step is required for an abandoned HM lock. Automatic retry alone
does not recover from abrupt termination. Power-loss behavior still depends on
the filesystem honoring successful file and directory flushes.

Filter edits affect new matches; already queued references remain held until
delivered. A lowered budget is respected before an unpublished pending plan is
sent. Restart with the same state directory after changing configuration. Do not
reset the cursor to bypass a budget. Moving the clock backwards relative to a
recorded publication refuses the pass.

The JSON summary has schema `aegis.subscriptions-status/v1` and these fields:

| Field | Meaning |
| --- | --- |
| `configuration_sha256` | SHA-256 of the exact configuration file bytes read this pass |
| `published` | Notices newly published this pass |
| `recovered` | Existing notices reconciled after a cursor-save interruption |
| `matched` | References listed in published or recovered notices |
| `held` | References still queued after the pass |
| `subscription_suppressed` | Subscribers held because of their hourly budget |

Exit 0 means the pass completed. Exit 2 returns a fixed JSON diagnostic with a
`code` and `error`, never OS exception text or supplied input. Codes are
`SUBSCRIPTIONS_INVALID` (configuration or CLI), `SUBSCRIPTIONS_STATE` (cursor or
notice conflict), `SUBSCRIPTIONS_LIMIT` (size/capacity), `SUBSCRIPTIONS_IO`,
`SUBSCRIPTIONS_MAILBOX` (HM refusal), `SUBSCRIPTIONS_BUSY` (state lock),
`SUBSCRIPTIONS_MAILBOX_LOCKED` (operator hold on HM's existing lock),
`SUBSCRIPTIONS_DURABILITY` (notice routing-directory flush),
`SUBSCRIPTIONS_UNSUPPORTED`, `SUBSCRIPTIONS_PATH`, and `SUBSCRIPTIONS_CLOCK`.
An invalid entry names only its zero-based entry number. A later subscriber's
failure does not roll back earlier published notices; retry safely with the same
state. Configuration is capped at 256 KiB before parsing, cursor files at 4 MiB,
and histories/backlogs at 10,000 references. JSON structure and output size are
bounded before tree parsing and complete serialization respectively. Capacity
refusals retain the previously durable state; operator action is required to
address capacity, not a silent drop or cursor reset.

Public Python entry points are `validate(configuration, mailbox)`,
`matches(validated_entry, validated_message, records)`, and
`notify(root, state_dir, subscriptions, now=None)` (with `now` keyword-only).
`notify` returns the same summary as the CLI or raises `SubscriptionError` with
the documented code. Mailbox history reads use the pinned `Mailbox.messages()`
API; original-byte hashes are confirmed by bounded descriptor reads against its
validated envelopes. Subscriptions adopt indexed reads only with the separately
owner-approved MB-2-INDEXED rollout. The pinned HM publication API retains its
own validation, fencing and writer lock.
