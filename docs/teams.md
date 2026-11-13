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
aegis team queue claim DOCS-1 --lane docs --capability docs --expect REVISION --ttl 3600 --json
aegis team queue release DOCS-1 --lane docs --expect CLAIM_REVISION --json
aegis team queue done DOCS-1 --lane docs --expect CLAIM_REVISION --json
aegis team queue audit --json
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

All queue results are JSON, with schema `aegis.team.queue.<verb>/v1`, including
refusals. Exit codes are 0 done, 1 refused and 2 usage. Refusals contain `refused`,
`reason` and `next_action`; parser failures use the `usage` verb. List and audit
create no state or locks. MCP queue access is deferred to BL-16b.
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
CLI and core use one pure spelling check under both Windows and POSIX path rules,
so drive-relative parents such as `C:..\ws` refuse on every OS.

Items require `id`, a single-line `title`, nonempty workspace-relative `paths`
globs, and `capabilities`, a list of team labels. These labels are never host kinds.
Optional fields are `after` (prerequisite item ids), `hold` (a judgment hold),
`hold_until`, `scope_rulings` and `invariants` (lists of single-line text). Unknown
fields, duplicate JSON keys, multiline values and malformed items refuse. Limits
are 256 unfinished items, 128 entries per item list, 64 characters per id/label,
256 per title/path, 4,096 per ruling/invariant/hold, and 1 MiB of queue state.
Validated constraint text is returned in full. Completed rows remain in history
without consuming the unfinished-item cap. The entire proposed serialized state
must also pass the bounded JSON reader before publication; `queue_size_limit`
names the file/reader limit and leaves the previous queue intact. `queue_live_limit`
requires completing unfinished work before adding another item.

Credential-like text in `id`, `title`, `paths`, `capabilities`, `after`, `hold`,
`scope_rulings` or `invariants` refuses
add with the fixed `invalid_item` response. The heuristic can also refuse ordinary
text such as `Auth: update login flow`. Detection is per field: a value split
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
available writer slots. Unconditional claim-time path preflight against other
lanes' live repository leases belongs to BL-16b. In BL-16a, repository overlap
gates explicit `lease_free` conditions and repository lanes count toward capacity.
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

Add, claim, release and done append a correlated event under the queue transaction
lock, using the existing `lease_claimed` event kind and `queue_<verb>` result.
Details include the caller, item/lane label, previous/current revision, holder and
expiry. These queue receipts are excluded from lease metrics. The default caller
is the existing local owner label. As with lane leases,
an event failure leaves the completed mutation intact and returns a fixed
`event_not_recorded` warning with a next action; list before retrying, since the
previous revision is stale. Events provide cooperative audit history, not a
cross-file atomic journal.

Queue state is `.aegis/state/team-queue.json`. Milestones are an owner-managed
list of stable labels in that versioned document; this round adds no milestone
recording verb. Model inputs and editable files are untrusted. Owner-UID rewriting
of owner-only state is outside v5.0's threat model. These records supply no OS
authorization. Renew/gc liveness changes and build-kit wrapper retirement remain
separate follow-up work.

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
