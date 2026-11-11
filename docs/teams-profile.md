# Team profiles

`aegis team config` describes a team without starting hosts, signing in, running
tests, provisioning runners or spending money. Lease commands (`claim`, `renew`,
`transfer`, `release`, `gc`, `list`, `status`, `metrics`) retain their existing
contracts. Runtime status and repository lease status remain separate surfaces.

```console
aegis team config presets --json
aegis team config init --preset solo --json
aegis team config init --preset solo --host claude-code --json
aegis team config show --json
aegis team doctor --json
```

`init` creates `.aegis/team/profile.json` and refuses an existing profile unless
`--force` is supplied. It writes a version and a preset reference, so future
readers can refuse unsupported versions before interpreting settings. Force
replaces a valid profile; malformed, oversized or unsafe files still refuse.
Files use descriptor-relative operations from a trusted absolute root. The user
directory chain through `~/.config/aegis` is resolved once, supporting symlinked
homes and GNU Stow directory folding. The opened, resolved `aegis` directory must
be owned by the current uid and must not be group/other-writable. `team.json`
itself is opened no-follow: Stow `--no-folding` file links are refused. Canonical
directory components and repository paths retain descriptor-based no-follow
protection, including during concurrent renames.
Special files and platforms without these operations refuse clearly.

This feature-owned I/O boundary and its five exact storage-ratchet registrations
remain until **STORE-API-1** supplies the shared confined-file API and migration.
Filesystem-backed `show`, `doctor` and `init` currently refuse on Windows.
Windows filesystem support arrives with STORE-API-1 / the platform phase
(platforms are scheduled at the end). The pure resolver and preset listing
remain available there. Finding a CLI does not bypass this platform refusal.

## Documents and layers

Version 1 has exactly these top-level keys: `version`, `preset`, `policy`,
`model_settings`, `run_config`. On disk, `version: 1` is mandatory. Unknown keys
refuse with their full key path, and wrong types refuse without coercion. The
closed repository/flag JSON schema is `aegis_core.team_profile.JSON_SCHEMA`
(`aegis.team.profile/v1`); the user schema is `USER_JSON_SCHEMA`
(`aegis.team.profile.user/v1`). Both describe partial override layers. Named host,
capacity, runner and token-budget maps accept identifiers matching
`[A-Za-z][A-Za-z0-9_.-]{0,63}`. Their entries have closed schemas too.

Layers are applied in this order:

1. Built-in defaults.
2. The repository's selected preset (`solo` when absent).
3. Repository `.aegis/team/profile.json`.
4. User `~/.config/aegis/team.json`.
5. Explicit flags passed to the resolver by a caller.

Objects merge recursively; arrays and scalar values replace. Empty objects do
not clear prior settings. Policy blocks (`policy.review`, `policy.gates`,
`policy.landing`, `run_config.autopilot` and `run_config.limits`) are settable
only in the repository layer. User and flag layers refuse these blocks even
when they repeat the existing value. Preset selection belongs to the repository; user and
flag layers cannot switch its policy by selecting another preset. The current
CLI exposes no arbitrary override flag. The Python `resolve` API accepts `repo`,
`user` and `flags` documents and `live_run=True` for consumers resolving an active
run. `show` includes `profile` (resolved settings), `values` (one record per leaf,
with `value`, `layer`, `frozen_at_run_start` and a `path` array of exact components)
and `write_scope`. Dotted aliases remain single components. The usual dotted
display keys are retained; if two paths have the same display key, their keys
are serialized component arrays so neither record is lost. Consumers use `path`
for identity. Array values retain one provenance record for the replacing layer.
Credentials are always redacted.
Display text is canonicalized, then secret values are redacted, then text is
truncated, including JSON text. Schema-constrained identifiers and keys are not
redacted; free text such as gate names is redacted in both profile and provenance.
Reviewer hosts, optional/pinned-family settings, host-kind bindings and every
review fallback are repository-only too. Only `lens.extra` may be optional.
Validation checks declared hosts and transitive review fallbacks, including
policy lenses. Host references, runner references and optional lens names use the
same identifier grammar as named map keys. Correctness and voting lens routes must remain opposite the
writer when cross-family review is required; the explicitly pinned security role
retains its declared family. User/flag model and effort preferences cannot change
these routes or rebind their host kinds.

The user layer is a filtered overlay. Role model and effort preferences apply
only to roles declared by the resolved repository. Authentication and capacity
preferences are keyed by registered host kind, independently of repository
aliases, and apply to every alias of a declared kind. Undeclared roles or kinds
are ignored. Other allowed role/route fields apply only when they repeat the
repository value; different values are ignored. Repository-only fields listed
above still refuse as malformed user configuration. Each entry has a
`user.model_settings.*` record in `values` with `status` applied/ignored, a reason
and affected resolved paths (`applied_paths` keeps exact components). A user
value equal to the repository-resolved value records `status: applied` and
`reason: repeats repository` without merging, preserving its repository/preset
origin. This also applies to repetitions outside `model_settings`. Empty
objects add no user origin. Valid global
preferences cannot introduce incomplete hosts or roles or invalidate repository
routes, so one user file works across ci-only, solo, pair and mixed repositories.

Every `model_settings` and `run_config` value is marked frozen at run start.
Consumers must resolve once at startup and retain that snapshot; flag changes
to these sections or the preset refuse when resolving a live run. Inspection
does not reconfigure an existing run.

## Schema areas

| Section | Area | Fields |
| --- | --- | --- |
| `policy` | `review` | `require_cross_family` boolean; `cap` positive integer or null; `mode` full/delta; `extra_lens_blocks_on` confirmed; `lenses` array of name, host_pref array, voting and pinned_family |
| `policy` | `gates` | Array of name, runner, selector (impacted/whole/list), tests array, python string, must_pass and reuse_identical_tree booleans |
| `policy` | `landing` | target_branch, strategy (combined-full/batch/direct), batch_max, signature_required_for array; publish object with remote and app |
| `model_settings` | `hosts` | Named objects with registered `kind`; user-only auth_mode (sso/api/token) |
| `model_settings` | `roles` | writer, reviewer.correctness, reviewer.security, lens.extra, research; each has hosts (an ordered declared chain), optional model and effort strings, optional and pinned_family booleans |
| `model_settings` | `capacity` | Per declared host: usage_source (subscription-window/credits/none), thresholds (hold_pct/route_pct/flex_route_pct), fallback (review/doc arrays of declared hosts) |
| `run_config` | `runners` | Named objects with cpus, image, provider; user-only pool, credentials and budget_usd_month |
| `run_config` | `autopilot` | queue_full_on_ready, claim_next, resume_writer booleans; rulings |
| `run_config` | `limits` | Repository-only writers_max, votes_max, research_max |
| `run_config` | `token_budgets` | User-only map of per-role positive integer token budgets |

Positive integer settings are capped at 1,000,000; budget values are finite
numbers in [0, 1,000,000]; percentages are finite numbers in [0, 100]. Arrays and
named maps hold at most 64 entries. Strings hold at most 4,096 characters. Files
hold at most 128 KiB, nesting at most 16, and resolution at most 4,096 nodes.
Duplicate JSON keys refuse. Native `codex` app threads remain registry entries
that cannot bind team-run roles. `codex-cli` and `claude-code` retain the registry's
qualification boundaries; finding a CLI proves neither login nor OS isolation.
Claude writers explicitly show `write scope: permission rules, not OS-enforced`.
Every role accepting `pinned_family` requires a single-family host chain; pinned
review lenses also refuse transitive review fallbacks that change family. Per-host usage
is never summed, and these commands do not query usage.

The signature floor always includes `main`, and rulings stay with the owner.
All shipped presets retain `combined-full` and a full gate; the repository
can explicitly select `direct` through a policy change. The entire
`.aegis/team/profile.json` file is a governance path: creating, editing, replacing
or deleting it requires approval before merge through the existing `aegis approve`
and hosted `aegis-governance` flow. This includes `config init --preset X`,
`--force` replacement and switching between pair and solo. The approval hash and
CODEOWNERS coverage include this path, including in nested workspaces.

Init, show and doctor report this boundary in `governance`, with
`approval_required_before_merge: true` and `approval: "not checked"`. Resolving a
profile does not prove approval, and init does not merge a change. There is no
runtime approval boolean or alternate approval mechanism. User and flag layers
cannot override repository policy. Auth modes, credentials, runner pools and
runner budgets remain user-layer-only. Token budgets use `run_config.token_budgets`
outside the governed concurrency limits; the obsolete `limits.token_budgets` key
is refused. For example, the user layer can set `{"run_config":{"token_budgets":{"writer":1000}}}`.

## Presets

| Preset | Hosts and roles | Policy and runners |
| --- | --- | --- |
| solo | One Codex CLI host fills writer, review and research roles | Explicit require_cross_family=false; local runner; full gate |
| pair | Codex CLI writer, Claude correctness reviewer; security pinned to Codex | Cross-family review; local runner |
| mixed | Codex CLI writer/security, Claude correctness, declared research chain | Cross-family review; batches up to four; local runner until remote runner settings are supplied |
| ci-only | No model hosts or reviewers; review by humans | Gates and landing only |

Mixed's optional extra lens has an empty binding until a qualified third registry
kind exists. Gemini is outside version 1 of this profile. Remote runners never
provision automatically; adding configuration does not create a remote resource.

A solo Codex-only repository can use just:

```json
{"version": 1, "preset": "solo"}
```

A Claude-only repository can be initialized without editing JSON:

```console
aegis team config init --preset solo --host claude-code --json
```

The chosen binding is persisted at init and never silently changed at runtime.
Pair/mixed init binds the chosen writer and a qualified opposite-family
correctness host. Pinned roles retain their preset kind under a separate alias
when needed: security stays on Codex even with a Claude writer. Init JSON reports
the complete resolved profile, including every host and role binding. The
resulting repository profile remains governed before merge.
The equivalent solo profile uses the same policy and role names:

```json
{
  "version": 1,
  "preset": "solo",
  "model_settings": {"hosts": {"primary": {"kind": "claude-code"}}}
}
```

A user can supply authentication mode and local CPU capacity without committing
personal settings:

```json
{
  "version": 1,
  "model_settings": {"hosts": {"codex-cli": {"auth_mode": "sso"}}},
  "run_config": {"runners": {"local": {"cpus": 3}}, "token_budgets": {"writer": 1000}}
}
```

## Machine output and next actions

The commands use `primitives.envelope` with source, aegis_version, checked_at and
scope. Config verbs have distinct schemas `aegis.team.config.show/v1`,
`aegis.team.config.presets/v1`, `aegis.team.config.init/v1`, plus
`schema_family: aegis.team.config/v1`. Doctor uses `aegis.team.doctor/v1`.
Each result includes `status` and `next_action`. Refusals also include `reason`,
`layer` and `file`, so an agent can identify the input to correct without finding
repository-local documentation. Exit codes are 0 done, 1 refused, 2 usage.
Config without a verb and an invalid init preset/host return usage (2), without
echoing the invalid input.

Refusal attribution resolves the repository with defaults and its preset again,
without the user layer. If that refuses too, the repository-only refusal and
repository file are reported. Only a valid repository-only profile permits a
user refusal to name the user file. The next check adds the user layer without
flags; if that refuses, its user refusal wins even over a later flag-validation
error. Only when both earlier prefixes are valid does the refusal name flags
and `<command-line>`. This rule also covers malformed user JSON; provenance path
strings never decide ownership. Invalid preset/host command usage remains a
flag-layer usage refusal.

Doctor lists every declared host, its registered CLI and whether it is found on
PATH. It evaluates every preset with each installed qualified writer kind using
the same bindings as init, reports those in `runnable_bindings`, and lists
`runnable_presets` (also retaining a runnable current resolved profile, including
repository overrides) and `suggested_presets`; pair and mixed are
suggested only when two qualified host families' CLIs are available. Runnable
here means the profile resolves and its CLIs are present; login and network
checks are explicitly `not checked`. A missing declared CLI refuses with an
installation next action naming the missing declared CLI. If a repository
profile exists, doctor never proposes init or force-replacement: its guidance
addresses the hosts already declared by that profile, including custom policy.
Only when the anchored read confirms that no repository profile exists may an
available binding of the current preset follow as an exact
`aegis team config init --preset NAME --host KIND` command. The loaded snapshot
records that observation in `repository_profile_exists`; unknown presence does
not authorize init advice. No host is silently substituted.
