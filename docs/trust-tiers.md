# Trust tiers: what each one protects and how to set it up

Aegis plans for one adversary: the coding agent itself. It runs as your user, so it can edit the repository, your home directory, host configs and Aegis's own state, and it holds your git and `gh` credentials unless you separate them. Anything Aegis records locally (the ledger, `aegis check --record` rows, commit trailers) is therefore a label, not evidence.

What can hold against the agent depends on what GitHub enforces. `aegis doctor` reads that (read-only, through your own `gh`) and prints the tier on every report. **Tier C is the default and the complete local product.** Tiers A and B add tamper-resistance for one thing: changes that weaken your rules or the files that run your checks.

## At a glance

| | Tier C: self-attested (default) | Tier B: solo, signed | Tier A: separation of duties |
|---|---|---|---|
| **For** | everyone, on any CI | one maintainer whose agent works in the same repository | a repository with a second human reviewer, or an agent on its own GitHub account |
| **What you get** | rules served to agents before each edit, pre-commit and CI checks; while `allowed_signers` lists no key, `aegis check --ci` fails a rule weakening (nothing can approve it, so revert it or move to tier B) and only notes which kinds of governance file changed | a pull request that weakens a rule or changes a governance file passes `aegis check --ci` only with your SSH-signed `aegis approve` commit | a rule weakening passes only with an approving review from a code owner who is not the author; a governance-file change is gated the same way only while `allowed_signers` lists a key (with none, it passes `aegis check --ci` with a note and only the ruleset's code-owner review stops it) |
| **What still gets past** | any change, if the Aegis check is not a required check; an agent that edits the rules and the CI that checks them | a pull request that also edits `.github/workflows/**` or Aegis itself, because the required check runs the pull request's own workflow | ruleset bypass actors, an admin token in the agent's hands, and a reviewer who approves without reading |
| **You configure** | `aegis init`, a CI job | tier C, plus a required Aegis check pinned to GitHub Actions, `allowed_signers`, and a signing key the agent cannot use | tier C, plus review rules, `CODEOWNERS`, an agent identity that is not a repository admin, and a key in `allowed_signers` for `aegis check --ci` to gate governance-file changes |
| **GitHub-specific** | no: `aegis check` and `aegis check --ci` are plain git and run on any CI | the ruleset is; the signature check is plain git (`ssh-keygen` and `allowed_signers`) | yes |

"Governance files" means the rules and Aegis config under `.aegis/`, `allowed_signers`, `CODEOWNERS`, `.github/workflows/`, the pytest configuration and plugin paths a change could use to steer the tests, and a deleted test file. `aegis doctor --github` prints the path-based entries as `CODEOWNERS` lines. [SECURITY.md](../SECURITY.md#trust-tiers) has the claim-by-claim truth table.

## Approval modes per target branch

The tier descriptions below describe repositories without an `approvals` key; their
existing CI verdicts and report fields stay unchanged. To choose a mode per target,
commit this key in `.aegis/config.json`:

```json
{"approvals": {"main": "signature", "develop": "review", "release/**": "review", "*": "none"}}
```

An exact branch wins, followed by the longest matching `prefix/**`, then `*`.
An unknown target or a branch with no matching entry uses the strictest declared
mode (`signature` > `review` > `none`). Maps must contain 1–256 entries; branch
names use the conservative GitHub branch grammar (at most 255 characters), and
the committed config is limited to 64 KiB.

- `signature` gates rule weakenings and governance changes on the existing signed
  approval or qualifying tier-A review. Configure `allowed_signers` on the base;
  without a usable key or qualifying review, a flagged change cannot pass.
- `review` lists both kinds of change and passes the approval gate with
  `owner_review_required: true`. The owner's merge supplies the review. Restrict
  pushes and merges with forge rules and separate the agent's credentials: this
  CI notice does not enforce who can merge.
- `none` lists both kinds of change without blocking on approval.

The target base commit's config anchors the mode. When the base has a map, the
head may tighten its requirement; it cannot lower it or remove the requirement by
deleting the key. User config never supplies approval policy. A malformed head
map is refused with `invalid_approval_policy`; a malformed historical base map
uses the legacy gate and reports the error so it can be repaired. A base without
a map stays under legacy evaluation, even when the head introduces a valid map.
With no map on either side, unusable config bytes do not add a new policy refusal.

Pull-request events supply `base.ref` and `base.sha`. Policy-enabled push events
use the branch named by a `refs/heads/` `GITHUB_REF` and `before`; tag pushes and
other refs have an unknown target and use the strictest mode.
An all-zero `before` keeps the branch-creation fallback, including a pinned
explicit `--base` that equals or descends from the head.
Any other missing/unavailable push predecessor is refused with `base_unavailable`
when a map is in play. A resolved comparison that would start at the head itself
is refused with `comparison_unavailable`.
Fetch the push's `before` commit with sufficient history and re-run.
An explicit push `--base` supplies the comparison without requiring `before`.
If that explicit comparison is unavailable or cannot precede the head, the
refusal names the base to fetch or asks for a proper ancestor; it never asks to
fetch `before`.
When a resolved predecessor has no map, first-map pushes use its legacy gate.
An empty `--base` is treated as omitted and uses the discovered comparison base.
Nonempty `--base` selectors use Git's commit resolution, pinned before target
classification. Git's symbolic full name `refs/heads/BRANCH` or
`refs/remotes/REMOTE/BRANCH` identifies that branch, including upstream aliases.
For a remote-tracking ref, REMOTE must be the uniquely longest matching configured
remote name; names may contain `/`. An absent or ambiguous remote match gives an
unknown target. The branch part `HEAD` is always unknown in both rows; a symbolic
`origin/HEAD` may instead resolve to its actual branch. Remote inventory is bounded
to 256 names and 64 KiB before parsing; unreadable or malformed data is refused
with `invalid_approval_policy`.
Tags, ambiguous names where Git selects a tag, pseudorefs, reflog selectors,
commit IDs and other namespaces retain their pinned commit with an unknown
target: they run the legacy gate without a map, or its strictest mode with one.
Automatically discovered bases remain branch-only (or a CI event's full commit
identity); a tag never supplies their comparison policy. Only a discovered
`origin/BRANCH` may fall back to its local branch, with an unknown target.
Explicit selectors never use that fallback. An absent explicit origin ref asks
to fetch origin. An unresolvable/non-commit selector returns `base_unavailable`
in CI (`no_base` in approve), naming the selector with the next action to fetch it
or pass the full commit id. A resolved comparison without shared history is
`comparison_unavailable` in CI (`no_common_history` in approve).
PR event text never upgrades an unknown explicit target, including a full commit
ID that matches the event and an origin ref.
Selectors are bounded before Git execution; invalid selector text is refused,
and malformed Git classification output returns `invalid_approval_policy`.
An explicit branch that disagrees with the event's PR base or push branch is
unknown; an explicit branch on a tag push is unknown too.
Reports add `approval_mode`, `approval_target`, `owner_review_required` and
`policy_source: base` when a base policy exists (`head` when the head tightens it).
Other CI checks still block and name their blocking cause. CI uses one event
snapshot, bounded to 25 MiB, for the base, head, target and review identity.
Malformed event fields produce a fixed refusal when the resolved base declares
a map; otherwise event handling retains legacy behavior. Branch names outside
the conservative target grammar use the strictest mode when a map exists.
Git object I/O failures refuse with `invalid_approval_policy` and a fetch/repair
instruction; an unreadable repository cannot establish the absence of a policy.
The GitHub summary retains permitted changes with their approval mode and shows
`owner review required` for review targets.

On `review` or `none` targets, `aegis approve --base origin/BRANCH` refuses with
`not_required` (exit 1) and makes no commit. Signature targets retain the terminal,
typed confirmation and key-custody checks. Signed test exemptions, manager
activation and fitness credit keep their separate signature requirements.

## Tier C: the default

1. Install and initialize: `pipx install aegis-guardrails`, then `aegis init --host claude-code` (or `codex-cli`, `antigravity`). This writes the `AGENTS.md` bootstrap, registers the MCP server and installs the pre-commit hook.
2. Add CI, because `git commit --no-verify` skips the local hook. `aegis init --ci` writes `.github/workflows/aegis.yml`, whose `aegis-check` job runs `aegis check` and `aegis check --ci` on every pull request. On another CI, run those two commands after a full-history checkout.
3. If you want outcomes credited by CI, name that workflow in your user config: `{"ci": {"workflow": "aegis.yml"}}` in `~/.aegis/config.json` (the default is `validate.yml`; `aegis doctor` warns when the named workflow is missing).
4. Run `aegis doctor`. It prints `Trust tier (human_gate): C (self-attested)` with the reasons tiers B and A are not met. That is the normal state for most repositories, not a failure.
5. When `aegis check --ci` fails with `weakening without approval`, the pull request removed or loosened part of a rule. At tier C the fix is to revert that change; to make intentional weakenings possible, set up tier B.

## Tier B: solo, signed approvals

Tier B is for the common case where you and your agent share one GitHub account. A weakening needs your signature, made with a key the agent cannot use.

1. **The Aegis job.** Tier C's workflow is enough, as long as the job that runs `aegis check --ci` has a literal job name and is not in a matrix: GitHub can require only a fixed check name.
2. **A signing key the agent cannot use.** Use a hardware key (`ssh-keygen -t ed25519-sk`, touch required) or a passphrase-protected key (`ssh-keygen -t ed25519`, set a passphrase). A key stored as a plain readable file lowers the tier to C. If your desktop keyring loads keys from `~/.ssh` into an agent automatically, keep the approval key elsewhere so it is never unlocked without you. Only SSH signatures count; a PGP or X.509 signature is never an approval.
3. **Tell git to sign with it**, in your user config (a repository's config is never used for approvals):

   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/aegis_approval.pub
   ```

4. **List the public key** in `allowed_signers` at the top of the default branch, through a reviewed pull request: one line, `you@example.com namespaces="git" <contents of the .pub file>`.
5. **Create the ruleset.** `aegis doctor --github` prints the exact ruleset JSON. `aegis doctor --github --apply --tier B` creates it after you confirm at a terminal. It requires a pull request, dismisses an approval when new commits are pushed, requires the Aegis check with its source pinned to GitHub Actions (a status posted by any other app or token does not count), and blocks deletion and force-pushes. The ruleset covers the default branch only; if you also merge into `develop` or `release/**`, add those branches to its target list in the repository settings, or pull requests into them are checked without those rules.
6. **Day to day.** When a pull request weakens a rule or changes a governance file, `aegis check --ci` fails and names each change. Review the diff, then run `aegis approve --base origin/<base branch>` on the pull request's branch. It asks at the terminal, signs an empty commit carrying the governance hash, and you push it. A later change to a governance file voids the approval, so approve last.
7. **Check it.** `aegis doctor` should now print tier B and its caveats.

The limit to keep in mind: at tier B the required check runs the pull request's own workflow and the Aegis it installs. A pull request that edits `.github/workflows/**` or Aegis can change the check that verifies the signature, so review those pull requests yourself. `aegis doctor --release` reports tier B as `agent_editable`, never `VERIFIED`.

## Tier A: separation of duties

Tier A takes the approval out of the agent's reach: a human code owner other than the author approves, and the agent's identity cannot change the rules of the game.

1. **Tier B's CI part**: the Aegis job as a required check, with its source pinned to GitHub Actions (`aegis doctor --github` pins it). At tier A an unpinned source is only a caveat in the report, not a withheld tier; tier B withholds the tier for it, so pin it all the same. Signing becomes optional for pull requests into a branch whose rules meet step 3, because a qualifying review is the approval there; pull requests into any other branch still need a signed `aegis approve`. List at least one key in `allowed_signers` all the same (tier B, step 4): `aegis check --ci` gates a governance-file change only when the base branch lists a key, and with none it only notes the change; a rule weakening is gated either way.
2. **CODEOWNERS.** Commit the lines `aegis doctor --github` prints to `CODEOWNERS` on the default branch, with a real reviewer as owner: a user (`@name`) or a team (`@org/team`). GitHub ignores a bare `@org` owner on an organization's repository.
3. **The ruleset.** `aegis doctor --github --apply --tier A` creates it. It requires one approving review and code-owner review, dismisses an approval when new commits are pushed, and requires approval of the most recent push, besides the pinned Aegis check.
4. **Give the agent its own identity.** The pull-request author cannot approve their own pull request, so the agent must push and open pull requests as a different GitHub account (a machine user, or a teammate's agent) with write access but not admin. An admin can edit the ruleset, so `aegis doctor` withholds tier A when the identity it runs with is an admin: run it with the agent's token, for example `GH_TOKEN=<agent token> aegis doctor`.
5. **Day to day.** The agent opens the pull request; you review it as a code owner and approve. `aegis check --ci` accepts a flagged weakening or governance change when a person other than the author approved the head commit in their latest review, the base branch's rules require an approval, code-owner review, stale-review dismissal and approval of the most recent push, and the base branch's `CODEOWNERS` owns every flagged path. It reads the reviews with the job's read-only token.
6. **Check it.** `aegis doctor` prints tier A and its caveats, for example that a ruleset can name bypass actors, which the API it reads does not show. `aegis doctor` does not check for a key in `allowed_signers`; without one, governance-file changes pass `aegis check --ci` with a note, and only the ruleset's code-owner review stops them. Add a key in `allowed_signers` (tier B's steps 2 to 4) to make `aegis check --ci` gate them too.

## What no tier covers

- Hooks fail open. Agent hooks are guardrails, not a security boundary: an Aegis error, a timeout, or an edit made through a shell command passes them. CI on the exact commit is the floor.
- `refs/remotes/origin/*` is writable by the agent, so tier detection and the approval ancestry test are only as strong as that ref.
- Aegis does not sandbox processes, and it does not read classic branch protection, only rulesets.
