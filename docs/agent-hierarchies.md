# Host-neutral hierarchy pilot prototype

This source-checkout prototype supplies three role contracts, plain-file mailboxes,
stable endpoint bindings and checkpoint handoffs. The stdlib-only helper is
`tools/hierarchy_mailbox.py`; it is outside Aegis core and is not installed in the
wheel. No process watches folders, launches hosts or tracks repository work for
Aegis. Host configuration, manager policy/membership and release gates are unchanged.

## Role contracts

| Role | Owns | Writes |
| --- | --- | --- |
| Front door | Owner intent, constraints, acceptance and escalation | Hierarchy briefs, mailbox information, concrete owner approval packets |
| Orchestrator | Technical decomposition, leases, readiness, dispatch, review, integration and delivery | Lane briefs, STATUS, mailbox reports and PR metadata |
| Lane | One implementation, integration or independent-review assignment | Leased repository paths for writing lanes; findings for reviewers; mailbox reports |

Only writing lanes edit repository source. An integration lane owns cross-cutting
fixes, generated contracts, documentation and manual conflict resolution. The
orchestrator retains Git integration, validation and draft PR/CI management. The
owner approves scope, signs governance/manager activation and merges every PR.
Messages and SHIP recommendations grant no authority.

Host-neutral role prompts and hierarchy/lane briefs are under
`tools/hierarchy_templates/`. Front doors write intent; orchestrators turn it into
executable lane briefs after source and ownership checks. Every lane brief repeats
the goal and acceptance and pins base, branch, worktree, lease, paths and tests.
Use a new brief file/hash and explicit redispatch for a scope revision.

Claude subagent profiles are templates under `claude-agents/`, not automatically
installed settings. The writer uses an already prepared worktree; it has no
automatic worktree isolation setting. The reviewer uses an explicit read-only
tool allowlist with no shell, delegation, Skill or repository write tools. Plan mode alone
can be overridden by the parent, and memory can add writing tools. Keep memory
disabled. A dedicated mailbox-only MCP connection lets the reviewer acknowledge
and report under its own pinned endpoint. It cannot use the orchestrator's
connection. Probe effective tools in the installed host before relying on either profile.
[Claude subagent contracts](https://code.claude.com/docs/en/sub-agents).

## Prepare a mailbox

Use Python 3.9+ and the helper from an exact reviewed prototype revision. Git is
needed only for writing-lane readiness inspection. All JSON request paths and the
mailbox root are absolute. Prepare the mailbox parent directory first, keep briefs
in that parent or its subdirectories, and keep the root outside implementation
worktrees (for example `aegis-guides/mailbox`). The manifest has no host fields.

```sh
python3 /absolute/prototype/tools/hierarchy_mailbox.py \
  --root /absolute/aegis-guides/mailbox init \
  --request /absolute/prototype/tools/hierarchy_templates/manifest.json
```

Initialization creates an immutable manifest and folders `<hierarchy>/<role>/`
and `across/<role>/`. The supplied two-hierarchy manifest explicitly pairs lanes;
there is no ambiguous routing when more lanes are added. It caps concurrent
accepted writing lanes at three, including integration lanes. It establishes no
Git lease or manager membership. Manifest changes require a new reviewed pilot
root; do not edit its history in place.

Fill in `binding.json` for every endpoint, using the actual host/session labels:

```sh
python3 /absolute/prototype/tools/hierarchy_mailbox.py \
  --root /absolute/aegis-guides/mailbox bind \
  --request /absolute/aegis-guides/requests/a-front-door-binding.json
```

Stable endpoints look like `a/front-door`, `a/orchestrator`, `a/lane/f2` and
`a/lane/review`. Host/session and generation are metadata on immutable binding
records. Initial binding uses `expected_generation: 0`. Branches, owner labels,
briefs and leases name stable hierarchy/lane identities, never the host.

## Publish and receive

Substitute the message template's current sender binding, brief path and SHA256
of its exact bytes. A front-door intent message uses type `brief`; an orchestrator
assignment to its own lane uses type `dispatch`. Generic peer information uses
type `info`. Each file has a JSON header between Markdown frontmatter delimiters
and a plain-text body. The helper adds UTC time and explicit information-only and
verification metadata. Host-native messaging may nudge a reader but is not the record.

Publication returns the file's `path` and raw-byte `sha256`. A front door with
only mailbox tools can author its complete intent as an `info` message to its
orchestrator, then send a `brief` message referencing that immutable file/hash.
The informational Markdown file itself is the hierarchy brief; its hash covers
the header and body together. An orchestrator can author a lane brief the same
way, then reference it in the lane's dispatch. No extra file writer or hash tool
is required. Keep these artifacts immutable; a revision is a new file/message.

```sh
python3 /absolute/prototype/tools/hierarchy_mailbox.py \
  --root /absolute/aegis-guides/mailbox publish \
  --request /absolute/aegis-guides/requests/a-f2-dispatch.json
python3 /absolute/prototype/tools/hierarchy_mailbox.py \
  --root /absolute/aegis-guides/mailbox inbox --endpoint a/lane/f2
python3 /absolute/prototype/tools/hierarchy_mailbox.py \
  --root /absolute/aegis-guides/mailbox status
```

Inside one hierarchy, front door and orchestrator communicate vertically, as do
orchestrator and lanes. Across hierarchies, only explicitly paired counterparts
communicate. No front-door/lane or cross-hierarchy diagonal route is accepted.
A counterpart can exchange a brief but cannot dispatch another hierarchy's lane.
Every message ID is unique across the mailbox. Reuse is refused without replacing
bytes; a retry can inspect the original using `inbox`.

Acknowledgments use type `ack`, `in_reply_to`, and `acknowledgment` equal to
`received`, `accepted` or `completed`. Replies must reverse the original endpoints.
Receiving information, accepting execution and completing work are separate claims.
Use the current sender binding on each. No message type approves, signs or merges.

Writing-lane dispatch acceptance requires `readiness` using the supplied template.
The helper checks worktree root, current branch, base ancestry, declared expiry and
scan-workspace equality; it enforces distinct active worktrees, branches and lease
references and the writer cap. It does not verify that a lease exists or its scope,
that scan/hook evidence was observed, or that tests ran. Lease OIDs/evidence
references are data, not fetched proof. The orchestrator must verify actual live
leases, overlaps, scan activity and the effective hook tier before execution.
Read-only reviewers need no writing lease/readiness and do not consume writer slots.

A result message uses type `result` (or `review`), replies to its accepted dispatch,
and includes `result.json`'s full commit/tree IDs and check/evidence references.
Writing lanes also supply a committed lane-check reference. A completed dispatch
cannot be accepted or completed again. Failed, partial and not-run checks stay
explicit. The helper never executes a command, path or URL found in evidence.
Readiness and active checkpoints execute only bounded, fixed Git inspections.

## Scoped mailbox MCP access

A host without general workspace writes can use the same file protocol through a
dedicated stdio adapter. `tools/hierarchy_templates/mailbox-mcp.json` is a registration
proposal only; nothing installs or activates it. Replace its exact source-pinned
interpreter/helper, mailbox root, endpoint, host, session and generation. Each role
needs its own connection. The reviewer profile embeds its own server definition;
it must not inherit the orchestrator's sender binding.

The adapter advertises exactly `mailbox_inbox`, `mailbox_publish` and
`mailbox_ack_handoff`. Sender identity and root come only from process startup;
tool arguments cannot choose them. Every call rechecks the current binding and
the manifest digest; mutations check under the same exclusive writer lock. An
old running adapter is refused after replacement. This is configured provenance,
not authenticated host identity. The adapter speaks baseline stdio MCP 2024-11-05.

`mailbox_inbox` accepts optional `include_briefs`, `limit` and `after_message_id`.
It returns only this endpoint's incoming messages and, when requested, their
hash-verified brief text. A front door therefore needs no arbitrary filesystem
reader. Results page at 20 messages by default, up to 100; `remaining` and
`next_after` make omissions explicit. The CLI offers `--include-briefs`, `--limit`
and `--after` for the same behavior. `status` and historical files remain available.
The inbox also returns only this endpoint's current `binding`, including its
checkpoint, canonical checkpoint hash and readiness. With `include_briefs`,
`checkpoint_briefs` contains the checkpoint's hash-verified brief text, including
outgoing briefs that would not occur in incoming messages. A replacement can
inspect its own checkpoint before acknowledging it without a controller relay.

`mailbox_publish` takes the message fields except `from`, `host`, `session` and
`binding_generation`, which the adapter supplies. It validates nested fields with
the same file protocol and cannot claim leases, edit source, run supplied commands
or invoke manager policy. `mailbox_ack_handoff` accepts only `checkpoint_sha256`
and is available to a successor before its binding is ready. A restricted reviewer
can thus receive, accept and report independently with source-read tools plus these
three narrowly scoped mailbox tools.

## Replace a host/session

Stop the outgoing session first. Fill in `checkpoint.json` with unchanged brief
hashes, source revision/tree and dirty state, lease refs, completed checks, pending
message IDs and last acknowledgment IDs. Active dispatches and their unchanged
briefs must be retained. Accepted writing work also requires its lease reference
and a source snapshot matching the current commit/tree/dirty state and original
branch. The original acceptance record retains the lease object/expiry and branch.
Front doors without a checkout may have an empty source list. Quiescence is an operator claim, not
native enforcement.

Publish a replacement binding request with the same endpoint, a new host/session,
`expected_generation` equal to the current generation, and the checkpoint object.
The new binding is immutable and initially not ready. Its returned
`checkpoint_sha256` hashes canonical checkpoint JSON. The successor reads the
checkpoint and inbox, then acknowledges it:

```sh
python3 /absolute/prototype/tools/hierarchy_mailbox.py \
  --root /absolute/aegis-guides/mailbox ack-handoff \
  --request /absolute/aegis-guides/requests/a-f2-handoff-ack.json
```

The acknowledgment JSON has exactly `endpoint`, `generation`, `session` and
`checkpoint_sha256`. The old sender generation is rejected after replacement; the
successor cannot publish or receive a new dispatch until this acknowledgment.
Historical messages retain their original provenance. Existing accepted assignments
belong to the stable endpoint and survive the handoff. The protocol cannot prevent
the old same-user process from editing directly. Rotate sessions after 45 minutes
active; the pilot's deliberate mid-wave replacement tests this same handoff.

## Evidence and manager overlay

The manifest, immutable bindings and messages supply external attribution by
hierarchy, role, lane, host and generation. Preserve raw Aegis `team metrics` as
repository totals: linked worktrees share the events log while scan activity is
per worktree. Record tool/source versions, worktree, branch and time interval with
each evidence artifact; never relabel repository totals as per-host observations.
`status.mailbox_message_counts` counts only this mailbox's files by sender host
and endpoint; `accepted_writers` lists unclosed writing assignments, not observed
running processes. These counters provide no Aegis metrics or native activity proof.

The existing manager API can audit `hierarchy`, `delegation`, `checkpoint`,
`handoff` and `evidence_review` decisions. Reference mailbox IDs and hashes in its
bounded summary and qualified evidence references. No new manager arguments or
tools are introduced. Manager audit acknowledgments, mailbox delivery, acceptance,
claimed completion, owner approval and verified repository evidence stay distinct.
New lane worktrees are not manager-enrolled by this helper; their membership needs
the existing separate owner review/activation. See [manager mode](manager-workspaces.md).

## Acceptance and limitations

The public subprocess suites are `tests/integration/test_hierarchy_mailbox.py`
and `tests/integration/test_hierarchy_mailbox_mcp.py`.
`tests/integration/test_hierarchy_scenario.py` adds a simulated two-hierarchy run
with real linked worktrees, public Aegis lease/scan/lane commands, acted-on peer
messages at all three layers and a host-label replacement preserving assignment.
It exercises routing, hashes, immutable publication, acknowledgments, readiness,
writer isolation, handoff and malformed/corrupt inputs in temporary directories.
Local simulated host labels do not establish that actual Claude/Codex sessions
read messages or that host hooks fire. Before the live pilot, verify exact host
versions, Git worktree metadata after the directory move, lane-local scan/MCP
binding, blocked unscanned edits and live warning/startup context. S1 delivery and
C1/C2/C3 host integration remain separately gated; this helper implements none of
those hook changes. Keep release work and Stormheir out of the pilot.

For live Phase 1, exchange an acted-on message at each counterpart layer, perform
one stopped-session host replacement with the same brief/lease/branch, and collect
lane-check, independent-review and exact-commit CI evidence. The owner merges the
two PRs. Delivery/acknowledgment alone cannot close that gate.

Mutation uses one exclusive local writer lock and complete-file hard-link
publication with no overwrite. A contending writer fails explicitly; retry only
after checking the original message/binding. A crashed writer can leave a lock or
pending file: inspect the process/history before manual recovery. The helper does
not delete/repair history or hide malformed records. `status` and `inbox` are read
only. Inputs and every serialized durable record are bounded to 256 KiB, including
Unicode expansion. Histories are capped before append at 10,000 messages per
mailbox and 10,000 bindings per endpoint; refusal leaves prior history readable.
Symlinks and nonregular inputs are refused. Storage runs under the same local user,
does not authenticate a host/session, and is not a hostile-process security boundary.
Atomic visibility is not a claim of filesystem crash recovery. Local Linux checks
establish no Windows filesystem or physical-host acceptance.
