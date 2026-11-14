# Agent teams

This guide covers repository lanes. Use the [team surface chooser](../README.md#agent-teams)
for management audit or the source-checkout runtime prototype.

A lane is an agent's worktree and branch. A dispatcher or person assigns paths,
then checks the lane's committed changes before integration. The lease and lane-check
commands supply cooperative leases and a post-lane check; they do not start agents or manage their
worktrees. A read-only reviewer claims no paths, and its verdict applies to the
exact tree it reviewed. Review verdicts belong in the pull request, not the ledger.

## Setup and limits of each surface

**Repository lanes** use `aegis team claim` and `aegis check --lane`, included in
the installed CLI. Leases supply cooperative conflict information; these commands
do not launch agents or reserve runtime capacity. The sections below cover lane
setup, checks and lease operations.

**Management audit** uses `aegis workspace` from the reviewed, source-pinned
prototype CLI, with a separate manager registration and owner-approved policy
and membership. Audit acknowledgements grant zero fitness credit, no execution
authority and no native Teams enforcement. Follow the
[manager workspace guide](manager-workspaces.md) to prepare and activate it.

**Runtime team tools** are a source-checkout prototype; `tools/hierarchy_team.py`
is outside the installed wheel. Team runs need Linux, Python 3.9+, Git, `bwrap`,
the selected host CLI and a dedicated host login. They set up runs, start and stop
supported CLI sessions, and inspect run status. Start with the
[runtime guide](agent-hierarchies.md) and the
[team-run prerequisites and configuration](hierarchy-team.md#prerequisites).

## Claim and finish a lane

From an initialized repository with a `lane/docs` branch:

```sh
aegis team claim docs --paths 'docs/**' --branch lane/docs --ttl 3600 --json
aegis team list --json
```

### Lease path globs

A leading slash anchors a lease glob to the workspace root. Use `/pyproject.toml`
for the root file and `/docs/` for the root directory prefix. The anchor is retained
in the stored lease and in JSON claim, list and status output:

```sh
aegis team claim root-files --paths '/pyproject.toml' '/MANIFEST.in' --json
```

A slashless glob retains its any-depth meaning: `pyproject.toml` also protects
nested files with that basename. Its overlap is conservative and can conflict with
unrelated lanes. An anchored root-file declaration avoids that broad basename
reading. Wildcards with a shared literal prefix can still conflict even when their
extensions differ; uncertainty refuses the claim.

When a slashless existing root file is refused solely because of the any-depth
reading, the refusal may suggest its anchored form in `next_action`. This is advice
to retry; it does not grant the lease or bypass the next claim's conflict check.
JSON refusals include that guidance when available; text refusals print it on stderr.

Lease blobs remain version 1. Older readers strip a root anchor and therefore
interpret an anchored root filename more widely, preserving conflict protection
across versions. Known whitespace leases retain their old conservative scope and
must be released and reclaimed to change their paths.

These semantics also govern queue item and `lease_free` path globs. Queue entries
use POSIX separators. Rule targeting and `.aegis/team.json` policy globs retain
their existing normalization and matching behavior.

## Queue work for teams

The Router enqueues work; an orchestrator selects an item and claims its current
revision. Queue claims are cooperative scheduling records, separate from the
repository path leases above. They do not launch sessions or grant execution authority.
The service uses Python 3.9's standard library and requires POSIX descriptor-relative
no-follow operations. Unsupported platforms return a structured refusal.

```sh
aegis team queue add --item '{"id":"DOCS-1","title":"Update guide","paths":["docs/**"],"capabilities":["docs"]}' --json
aegis team queue list --capability docs --json
aegis team queue list --include-done --json
aegis team queue claim DOCS-1 --lane docs --branch lane/docs --capability docs --expect REVISION --ttl 3600 --json
aegis team queue release DOCS-1 --lane docs --expect CLAIM_REVISION --json
aegis team queue unclaim DOCS-1 --lane docs --expect CLAIM_REVISION --writer-stopped --reason 'Waiting for review' --json
aegis team queue done DOCS-1 --lane docs --expect CLAIM_REVISION --json
aegis team queue audit --json
aegis team queue compact --json
```

Use the actual `revision` returned by add, list, claim or release in place of the
example placeholders. Release and done are alternative transitions from a claim;
after release, claim again before completing the item. Claims expire at their
recorded `expires_at`: an expired claim can be replaced using its current revision,
but cannot complete work. Stale revisions always refuse, including concurrent
claims of the same item. List displays claimed lanes as `lane [ITEM: title]`.
Each lane may hold one live queue claim; another claim refuses with `lane_busy`.
Release and done accept `--lane`; live claims require their matching lane
(`lane_required` or `lane_mismatch` otherwise). Lane labels are cooperative caller
assertions, not authenticated identities or OS permissions.
Use `unclaim` to return a claim together with that lane's repository lease when
its paths intersect the item's write set. It requires the matching lane even
after expiry and refuses completed work or a stale revision. The lease's owner
label must match the caller (the CLI uses `team.default_owner()`); a live foreign
covering lease or any unreadable lease refuses before changes. Unrelated leases
remain in place. `unclaim_lease_refused` includes the lease OID and a release
command for inspection and reconciliation. The optional reason follows the
queue's single-line, 4,096-character and credential-text validation.
Unclaim also requires `--writer-stopped`: the operator must explicitly acknowledge
that the lane's writer and queued jobs are stopped. Omitting it refuses with
`writer_not_stopped` (exit 1), without changes. The receipt records this
acknowledgement with the caller label. The host layer must check process and job
liveness before calling unclaim; core cannot inspect host processes. Verifiable
runtime evidence is tracked separately by **BL-16f-LIVE**. Unclaim is an owner-UID
administrative transition; sandboxed children cannot invoke it against owner records.
An unreadable, torn or oversized receipt log refuses before release with
`unclaim_event_unavailable` (exit 1). Receipt reads use descriptor confinement,
a 16 MiB admission reader and the queue's bounded JSON-row parser. Admission
reserves 1 MiB for the release event and receipt; recovery accepts bounded slack
up to 17 MiB so those events cannot exhaust its reader. The coordinator must
reconcile retained event evidence before retrying an unavailable log.

Queue transitions are serialized by the workspace writer lock. Unclaim records
a durable intent before releasing the intersecting lease using its current OID
as the CAS expectation. A crash or uncertain I/O result returns
`unclaim_recovery_required` (exit 1); all other queue operations then refuse,
including expiry-based claims. Retry the original unclaim with the same item,
revision, lane and caller to finish it. The original reason remains attached.
The refusal's `blockers` carry the pending item, lane, revision, caller and a
concrete retry command with `--writer-stopped`; omitting `--reason` on retry keeps
the original reason. A replacement reason is refused. Until a release may have
landed, a definite refusal restores the exact original queue bytes. Recovery
retains its pending intent and never rolls the item back to an unreserved claim.
The queue becomes available only after the release and one correlated `unclaim`
event containing the lane, reason and `released_lease_ids` have completed.
Released IDs attest only successful release calls acknowledged by this operation.
An externally vanished lease or a lost release acknowledgement is never attested;
recovery can finish with an empty released-ID list while preserving existing events.
These leases remain cooperative scheduling records; unclaim does not stop agents.

Successful `queue list --json` responses include `claimable_fingerprint`, a
SHA-256 digest of scheduling state: claimable item IDs and revisions, item and
typed-hold state, milestones, completion history and live lease OIDs (including
unreadable lease evidence), configured lane eligibility and effective profile
validity/capacity. The claimable set uses the same eligibility checks as claim.
Git errors and timeouts refuse observation; they never mean an empty lease set.
In a non-Git workspace, `lease_free` holds stay unmet because lease evidence is
unavailable. The digest is independent of display filters and observation
timestamps. Unchanged scheduling state yields the same digest; unclaim, lease
release or expiry, completion and clearing a hold change it. A changed digest
signals callers to inspect the queue again; it grants no claim authority and
does not replace the revision check. Automatic supervisor retries are separate.

Pass the lane's branch explicitly with `claim --branch`; it can be a short local
name or `refs/heads/` name. Queue claims never infer a lane branch from the shared
workspace's HEAD. Omitted branches are recorded as unknown. Queue claims use the
repository lease's branch-label predicate: 1 to 200 characters with no whitespace
or control characters. Punctuation and non-ASCII characters are accepted. The
optional `refs/heads/` prefix counts toward this input limit and is removed for
new claim storage and audit comparison. Stored evidence, including older prefixed
records, is kept verbatim and sanitized for display; unsupported values are
reported per item instead of preventing queue operations.
Other `refs/` prefixes, empty local names, nested ref prefixes and `HEAD` are
refused. This validates a label, without requiring that branch to exist in the
coordinator checkout.

All queue results are JSON, with schema `aegis.team.queue.<verb>/v1`, including
refusals. Exit codes are 0 done, 1 refused and 2 usage. Refusals contain `refused`,
`reason` and `next_action`; parser failures use the `usage` verb. List and audit
create no state or locks. The read-only MCP tool `aegis_team_queue` lists the same
items, blockers and labels, with optional `capabilities` and `include_done` fields.
Its schema admits no mutation verb. Successful payloads match the CLI; refusals
retain the core envelope and add `error` with the fixed reason for MCP's `isError` flag.
The MCP server validates the original closed client object before workspace
binding or removal of reserved keys. Unknown keys (including `workspace` and
`files`), malformed objects and invalid values refuse as `invalid_arguments`.
Binding failures refuse as `queue_io_unavailable` without raw pin diagnostics.
Any invocation containing `team` followed anywhere by `queue` in the whole argv
uses the queue's non-echoing parser boundary, including words after `--`, option
values and malformed commands. Removed-command shortcuts also defer to this
parser boundary. The existing `aegis hook run` shortcut runs before that boundary:
malformed hook arguments, including ones mentioning `team queue`, exit 0 silently
to preserve the hook's must-not-block contract. Only a successful parse as `team queue`
exempts queue data named `model` from the raw model-token policy. Workspace bounds
apply equally before `team`, between `team` and `queue`, and after `queue` or its verb.
Empty workspace values, NUL bytes and `..` components refuse before workspace
resolution, as do values exceeding the length or separator limits.
CLI and core use one bounded tokenizer independent of Python's Windows path parser.
Parents separated by slash, backslash or colon refuse, including drive-relative,
UNC server/share and device-prefix spellings, on every OS and supported Python version.

Items require `id`, a single-line `title`, nonempty workspace-relative `paths`
globs, and `capabilities`, a list of team labels. These labels are never host kinds.
Optional fields are `after` (prerequisite item ids), `hold` (a judgment hold),
`hold_until`, `scope_rulings` and `invariants` (lists of single-line text), and
`brief_paths` (up to 128 literal workspace-relative write paths from the brief).
Brief paths cannot contain wildcards; this typed declaration never opens a brief
file or parses arbitrary Markdown. Omitted declarations add no paths to the item's scope.
Every declared brief path must match the item's `paths` at add time; otherwise
`brief_outside_scope` refuses with exit 2 before storage is created. Correct the
declaration and add again; an invalid immutable item never consumes a queue slot.
Unknown fields, duplicate JSON keys, multiline values and malformed items refuse. Limits
are 256 unfinished items, 128 entries per item list, 64 characters per id/label,
256 per title/path, 4,096 per ruling/invariant/hold, and 1 MiB of queue state.
Validated constraint text is returned in full. Completed rows are hidden by default;
`list --include-done` includes them. They do not consume the unfinished-item cap.
`compact` removes completed rows except prerequisites named by unfinished items,
and keeps a minimal completion marker for every removed ID. It reports
`removed_count`, `removed_ids` and `retained_done_count`, is serialized with
mutations, and is safe to retry. Later `after` dependencies still resolve as done,
and removed IDs remain reserved: re-adding them refuses `item_exists` and claiming
them refuses `item_done`. `list --include-done` exposes compacted IDs separately as
`completed_ids`; this global history has no retained capability metadata to filter.
Completion history is bounded to 8,192 IDs and the existing file/JSON limits.
`queue_history_limit` refuses further compaction without changing state. Today,
the operator should stop retrying compact, run `aegis team queue list --include-done
--json`, and give the coordinator the refusal and `completed_ids` history. Keep
the queue state and ID reservations intact while the coordinator tracks the ruled
archive-command follow-up. This version has no supported command to free history
slots; do not hand-edit or reset the state file. Existing work can continue within
the remaining queue limits.
Compaction retains no removed item bodies.
Queue transition events remain in their existing event history. The entire proposed serialized state
must also pass the bounded JSON reader before publication; `queue_size_limit`
names the file/reader limit and leaves the previous queue intact. `queue_live_limit`
requires completing unfinished work before adding another item.

Credential-like text in `id`, `title`, `paths`, `capabilities`, `after`, `hold`,
`scope_rulings` or `invariants` refuses
add. Text-field detections return `credential_like_text` (exit 2), with guidance
to rephrase assignments, for example `Auth: update login flow` as `Update login flow`.
Item IDs, prerequisite IDs in `after` and capability labels are validated as
identifiers first and return `invalid_item` when malformed. The heuristic remains fail closed
and can refuse ordinary prose. Detection is per field: a value split
across `id` and `title` is not detected across that boundary. Labels are composed
after each field is canonicalized, redacted and bounded; generated `id: title`
punctuation does not trigger another credential check on the joined label.
Milestone names and `lease_free` paths within `hold_until` use the same checks.

Typed `hold_until` conditions are objects of one of these shapes:

| Condition | When a claim may proceed |
| --- | --- |
| `{"kind":"lease_free","paths":["docs/**"]}` | No live repository or queue lease covers those globs; unreadable repository leases block. |
| `{"kind":"milestone","name":"develop-merge"}` | The coordinator has recorded that milestone in the owner-managed queue state. |
| `{"kind":"owner"}` | An owner decision removes the condition; it never self-clears. |
| `{"kind":"coordinator"}` | A coordinator decision removes the condition; it never self-clears. |

For a live claimed item, `lease_free` ignores its own queue claim and its holder's
repository lease. Other lanes' covering leases still block; expired claims have
no holder exemption.

Missing or invalid `.aegis/team.json` lane configuration is a coordinator blocker
at claim time; it cannot prevent adding or listing items. The team-policy parser
accepts a UTF-8 BOM and uses its own limits. Prerequisites
must be done; missing prerequisites remain visible with `next_action`. Claim checks
the lane declaration, capability labels, overlap with other live queue claims and
available writer slots. Under the queue mutation lock, claim re-reads repository
leases and refuses `foreign_lease` for overlapping live foreign leases or unreadable
lease records, even without a `lease_free` condition. The requested lane's own
repository lease is exempt from this scope check. `brief_paths` are validated
against the item's admitted globs at add time; an out-of-scope declaration refuses
add with `brief_outside_scope` before the item enters the queue. Claim rechecks
this declaration as part of its preflight.
The lease observation is a snapshot; queue and repository lease stores are separate
and this command grants no cross-store transaction or execution authority.
The layered team profile supplies `run_config.limits.writers_max`; live repository
lease lanes and live queue claim lanes share that count, with each lane counted once.
The resulting distinct lane count must fit the limit, including when the requested
lane already has a repository lease. Add/release responses show known blockers;
an unobserved `lease_free` condition asks for list to evaluate repository leases,
so it cannot be reported as satisfied merely because a mutation skipped that read.
Audit identifies items waiting only on the coordinator and satisfied typed conditions
still retained with a judgment hold on queued work. A judgment hold is never
automatically removed; satisfied `lease_free` conditions should remain in place
so a later claim rechecks them.
Audit reports `LANE-NO-LEASE` when a live queue claim has an absent or expired
repository lease. `LEASE-UNREADABLE` is a distinct outcome: inspect `aegis team list
--json`, then use `aegis team release` with the unreadable lease's current
`--expect` OID before claiming again. An unreadable snapshot never proves absence.
`CLAIM-BRANCH-UNKNOWN` reports null or absent branch evidence, including legacy
claims and claims made without `--branch` while detached. It never substitutes
the shared workspace's current HEAD. `LEASE-BRANCH-UNKNOWN` reports missing branch
evidence or a branch that is not a local branch on a readable live repository
lease; release and recreate that lease with an explicit local branch.
`LEASE-BRANCH-MISMATCH` requires two known
branches that differ. Short and `refs/heads/` names compare equally. Independent
claim-branch and lease findings can both appear. The live-claim findings above
include fixed reasons and next actions, and stop appearing after the queue claim
is released or expires.
`CLAIM-BRANCH-UNSUPPORTED` reports one item's stored branch evidence that current
claim rules refuse, including nested ref prefixes accepted by older versions.
Its item view includes `branch_supported: false`. The evidence is not rewritten.
Unsupported evidence suppresses only the branch comparison: live claims still
report lease presence, readability and lease-side branch findings. Other queue
items remain usable. This finding persists on expired and completed rows until
cleared by a normal transition, even when completed items are hidden by the
default list view. Release active or expired claims using their current
revision (or complete a live claim with done); compact completed rows after any
unfinished dependents finish. These normal transitions clear unsupported
evidence. An expired claim still refuses done with `lease_expired`; re-claim it
directly with its current revision and a supported branch, or release it first.
New claims continue to refuse unsupported branch spellings.

Add, claim, release and done append a correlated event under the queue transaction
lock, using the existing `lease_claimed` event kind and `queue_<verb>` result.
Details include the caller, item/lane label, previous/current revision, holder and
expiry. These queue receipts are excluded from lease metrics. The default caller
is the existing local owner label. As with lane leases,
an event failure leaves the completed mutation intact and returns a fixed
`event_not_recorded` warning with a next action; list before retrying, since the
previous revision is stale. Events provide cooperative audit history, not a
cross-file atomic journal.
Compaction that removes rows appends a `queue_compact` event with counts and every
removed ID in the bounded `removed_ids` list;
an unchanged retry appends no duplicate event. Event failure returns a warning
without undoing the already completed compaction.

Queue state is `.aegis/state/team-queue.json`. Its optional `completed` object maps
compacted IDs to `true`; older records without it load as empty history. Milestones are an owner-managed
list of stable labels in that versioned document; this round adds no milestone
recording verb. Model inputs and editable files are untrusted. Owner-UID rewriting
of owner-only state is outside v5.0's threat model. These records supply no OS
authorization. Renew/gc liveness changes and build-kit wrapper retirement remain
separate follow-up work.

### Owner-bound MCP queue connection

The owner can register a separate queue MCP server with an installed, isolated
interpreter:

```sh
python -I -c 'from aegis_mcp.queue_owner import main; raise SystemExit(main())' ID
```

This connection exposes exactly `aegis_team_queue` and `aegis_team_queue_claim`.
The ordinary Aegis connection keeps its existing tool list. Claim accepts only
`id`, `expect` (the actual revision returned by list), and `lane`; it starts no
host and creates no repository lease or execution authority.

Before launch, the owner installs a private registration at
`<account-home>/.aegis/mcp-queue/registrations/ID.json`, using directories with mode
0700 and files with mode 0600. Account home comes from the effective UID's account
database, never HOME, USERPROFILE or XDG settings. The registration fields are
`schema`, `registration_id`, `endpoint`, `role`, `workspace`, `lanes`, `ttl_s` and
`session_ttl_s`; see the [complete registration example](how-it-works.md#owner-bound-queue-connection).
Only `role: orchestrator` can claim a lane admitted by that policy. Capability
labels, branch and claim TTL come from the owner registration; caller role fields,
environment strings and repository files cannot grant or widen permission.
Registration lanes, capabilities and branches use the queue's shared validators.
Invalid lane names, duplicate capabilities and invalid branch labels return
`role_invalid` before a session record is created.

Launch writes a process/session record bound to the registration's original byte
digest. Linux process-instance qualification and descriptor-relative no-follow
operations are required; other platforms refuse with `unsupported_platform`
(`BL-16c-PORTABLE`). Safe separator and dot spellings of the workspace identify the
same directory; parent traversal and symlinked workspaces refuse. Both TTLs are
owner-selected integers from 1 through 86400 seconds. Changed or expired authority
records and a second initialize invalidate the session; the owner must restart it.
Even an equivalent rewrite of registration bytes requires a fresh session.

The owner must exclude the authority directory and its replaceable ancestors from
every hostile child's sandbox. The product does not verify this deployment
prerequisite, and file modes do not isolate unrestricted processes sharing the
owner UID. The separate OS-principal boundary remains `OS-PRINCIPAL-1`.

Claim refusals return the queue claim envelope with `isError: true`, fixed reasons
and recovery guidance. Malformed input returns `invalid_arguments` before IO;
authority reasons are `role_missing`, `role_invalid`, `role_foreign`, `role_stale`,
`role_forbidden`, `role_lock_timeout` and `role_io_unavailable`. Workspace/dispatch
failures return `queue_io_unavailable`; unsupported hosts return
`unsupported_platform`. Existing queue refusals, such as `stale_revision`,
`blocked` and `queue_lock_timeout`, retain their core semantics. Exit codes in the
envelope are 0 for success, 2 for invalid arguments and 1 for other refusals.

## Inspect every lane

```sh
aegis team status --base origin/develop
aegis team status --base origin/develop --check --json
```

`status` lists every readable or unreadable lease ref, including expired leases.
Each readable row includes the holder label, expiry, recorded branch, captured tip,
commits ahead/behind the base, and overlaps with live declarations. Unreadable
leases appear separately in each readable row's `unknown_overlaps`: their scope
cannot be ruled out. `stale` means expired or a recorded branch is missing;
unreadable leases have `stale: null`. None of these fields establish actor liveness
or reserve runtime capacity.

Without `--base`, status uses the same base selection as `check --lane`. An explicit
base that cannot resolve is a usage error (exit 2). A missing default base, shallow
history, absent branch or unreadable object leaves the affected counts unknown
(`null` in JSON), with an explanation. Inspection still exits 0 when individual
leases are expired, stale or unreadable. Repository-wide Git failures exit 1.

`--check` applies the existing lane gate to each live lease's captured branch tip,
using its declared paths and `shared` policy from that exact tip. This is
**self-attested** policy. It does not read the caller's dirty working-tree policy,
switch branches, run tests, launch agents, write events or change leases. Short
branch labels name local branches; `refs/heads/...` and `refs/remotes/...` are
accepted explicitly. Tags and revision expressions are not branch labels.
The result identifies the exact lease and commit it observed; concurrent changes
can make that observation stale. Re-run before making a separate write decision.

Checks exit 1 when any verdict fails or cannot be established, including expired
or unreadable leases and missing branches. Rows remain visible so uncertainty
cannot silently produce a passing result. Without `--check`, every `check` field
is `null` and no verdict is requested. Runtime reservations and native execution
remain separate from this repository inspection.

### Lane JSON schemas

Schema IDs are additive to the existing envelopes, fields and exit codes:

| JSON surface | `schema` |
| --- | --- |
| `team claim`, `renew`, `transfer`, `release`, `gc`, `list`, `metrics` | `aegis.team.<action>/v1` |
| `team status` | `aegis.team.status/v1` |
| `check --lane` | `aegis.check.lane/v1` |
| `check --partition` | `aegis.check.partition/v1` |

Handled refusals and errors carry the same schema ID as their command. Existing
lease blobs and `.aegis/team.json` remain version 1. Readers of the older CLI
documents can continue using their existing fields and ignoring the added ID.
These repository schemas are distinct from runtime `aegis.team-run-status/v1`
and its nested `aegis.team-status/v1`; they do not describe a running team.

## Renew and finish a lane

The claim prints its lease object ID. Save that ID for compare-and-swap operations:

```sh
aegis team renew docs --expect LEASE_OID --ttl 3600
```

Replace `LEASE_OID` with the ID you received. Renewal prints a new ID; use the
latest one on the next renewal, transfer or release. Nothing renews automatically,
and there is no MCP team tool. The default TTL is 3600 seconds, with a maximum of
86400. A live overlapping claim is refused; for example, this overlaps `docs/**`:

```sh
aegis team claim api --paths 'docs/api/**'
```

Commit the lane's work, then check it against the integration branch:

```sh
aegis check --lane docs --base origin/develop
```

An added `docs/guide.md` fits the claim; a committed `app.py` does not. This checks
committed changes only, so it is not a check of unfinished working-tree edits.
After integration or handoff, release using the latest lease ID:

```sh
aegis team release docs --expect LATEST_LEASE_OID
```

## What a lease means

The ref `refs/aegis/lanes/<lane>` points to a JSON record containing the lane,
paths, branch, owner/role labels, claim ID, generation, timestamp and TTL. Git refs
make it visible to every worktree. The lane name must match
`[a-z0-9][a-z0-9._-]{0,62}`. An expired lease can be claimed again; `aegis team gc`
removes expired leases. A timestamp over 300 seconds ahead of the reader is marked
`clock_skew` and still counts as live.

A lease is cooperative conflict input, not a lock, not an identity and not proof
that an agent is alive. Different lanes' claims can race between the overlap read
and their writes. `owner` and `role` are display labels; anyone may release a lease
with its current object ID. Compare-and-swap prevents a stale ID from overwriting
a newer version of that same lease.

Overlap checks are conservative. Literal prefixes before wildcards are compared
without case; an unreadable lease conflicts with everything. A glob without `/`
also overlaps everything because it matches filenames at any depth. Actual path
matching is case-sensitive and uses the same semantics as rule `target_paths`:
`*` crosses `/`, and `**/` matches zero or more directories. Prefer scoped path
sets such as `docs/**` when independent lanes need disjoint claims.

## Committed policy and provenance

Optional `.aegis/team.json` declares shared paths and per-lane paths:

```json
{
  "v": 1,
  "shared": [],
  "lanes": {
    "docs": ["docs/**"],
    "core": ["aegis_core/**"]
  }
}
```

Unknown keys, invalid globs and invalid lane names fail with exit 2. A shared
pattern applies to every lane. A bare `CHANGELOG.md` pattern also allows
`docs/CHANGELOG.md`, so choose shared patterns with the matcher's semantics in mind.

By default, allowed paths come from the live lease or `--paths`, plus `shared`
from the working tree's policy. The report calls this **self-attested** because
the candidate can choose these inputs. To use reviewed policy, commit the policy
on the base branch before the lane starts and run:

```sh
aegis check --lane docs --base origin/develop --base-policy
```

This reads `lanes.docs` and `shared` from the base branch's **tip**, not the merge
base or candidate, and labels the result **witnessed: base policy**. It rejects
`--paths`. This label identifies the source of path policy; it is not a recorded
test witness or a rule-credit receipt. See [architecture](architecture.md#evidence-and-state)
for that separate evidence flow.

## What the lane check covers

The range is the merge base of the chosen base and `HEAD`, through `HEAD`. Missing
base refs, shallow history or unrelated histories fail with a request to fetch
full history (`fetch-depth: 0` in GitHub Actions).

- **Containment:** every changed path must be allowed, including deletions, type
  changes, both sides of a move and submodules. `.aegis/**` and
  `.github/workflows/**` require permission from base policy; a lease or `--paths`
  cannot authorize them.
- **Test integrity:** Python tests removed from collection, new skips/xfails and
  changes to pytest collection settings are findings. Checks cover pytest and
  unittest skip forms, collection hooks and pytest configuration. Other languages'
  tests are listed as not checked.
- **Limits:** Assert weakening is not detected. Discovery follows pytest's default
  `test*` names rather than custom naming configuration. Indirect skips through
  fixtures/helpers, imported markers or dynamically constructed names can escape
  detection; changes to a condition's value elsewhere can too. Passing this check
  does not prove tests still exercise the same behavior.

Any finding fails the check. There is no exemption flag; the reviewer or person
merging decides with the findings visible. A `HEAD` already contained in the base
has no lane changes to check and passes with a warning.

## CI and metrics

The lane job is advisory (not a required check) in Aegis's generated setup.
`aegis init --ci` writes no lane job, and the ruleset printed by
`aegis doctor --github` requires the job running `aegis check --ci`, not a lane job.
If you add a lane check, run it from a workflow defined on the base branch. Under
`pull_request`, the workflow itself comes from the candidate: a witness is only as
strong as the protection on `.github/**` and on the base branch.

```sh
aegis team metrics --base origin/develop
```

Metrics count claims and denials from the events log and inspect first-parent
merges since the base for paths changed on both sides and conflicts reported by
`git merge-tree` (Git 2.38 or later). Synthetic `refs/pull/*/merge` commits are
excluded. These measurements do not automatically remove leases or change policy.

Lease operations and lane checks write operational events. Events cannot award
fitness or compliance credit, and CI-runner events disappear unless uploaded.
For storage paths see [how Aegis works](how-it-works.md); for every team command and
flag see the [reference](reference.md).
