# Agent teams

A lane is an agent's worktree and branch. A dispatcher or person assigns paths,
then checks the lane's committed changes before integration. Aegis supplies
cooperative leases and a post-lane check; it does not start agents or manage their
worktrees. A read-only reviewer claims no paths, and its verdict applies to the
exact tree it reviewed. Review verdicts belong in the pull request, not the ledger.

## Claim and finish a lane

From an initialized repository with a `lane/docs` branch:

```sh
aegis team claim docs --paths 'docs/**' --branch lane/docs --ttl 3600 --json
aegis team list --json
```

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
