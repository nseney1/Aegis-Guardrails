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
aegis team hosts status --json
aegis team hosts check primary writer --json
aegis team hosts usage --json
```

`init` creates `.aegis/team/profile.json` and refuses an existing profile unless
`--force` is supplied. It writes a version and a preset reference, so future
readers can refuse unsupported versions before interpreting settings. Force
replaces a valid profile; malformed, oversized or unsafe files still refuse.
Files use descriptor-relative operations from a trusted absolute root. A
relative or malformed user root, including an empty string, refuses with
`user profile root unavailable; configure a home directory` before resolution.
The user directory chain through `~/.config/aegis` is resolved once, supporting
symlinked homes and GNU Stow directory folding. The opened, resolved `aegis`
directory must be owned by the current uid and must not be group/other-writable.
The opened `team.json` descriptor must also show the current uid and no
group/other write bits, before any bytes are parsed. Otherwise it refuses with
`user profile file must be owned by the current user and not group/other-writable`.
`team.json` itself is opened no-follow: Stow `--no-folding` file links are refused. Canonical
directory components and repository paths retain descriptor-based no-follow
protection, including during concurrent renames.
Special files and platforms without these operations refuse clearly.
Repository roots accept absolute strings or native `Path` values. Validation
converts their checked spelling once. Custom path-like objects and `Path`
subclasses refuse before conversion hooks run, with
`unsafe profile root; use an absolute trusted directory`.
A failed home-directory lookup remains a user-layer refusal on Python 3.9 and
newer versions.

This feature-owned I/O boundary and its five exact storage-ratchet registrations
remain until **STORE-API-1** supplies the shared confined-file API and migration.
Filesystem-backed `show`, `doctor` and `init` currently refuse on Windows.
Windows filesystem support arrives with STORE-API-1 / the platform phase
(platforms are scheduled at the end). The pure resolver and preset listing
remain available there. Finding a CLI does not bypass this platform refusal.

## Documents and layers

Version 1 has exactly these top-level keys: `version`, `preset`, `policy`,
`model_settings`, `run_config`, `supervisor`. On disk, `version: 1` is mandatory. Unknown keys
refuse with their full key path, and wrong types refuse without coercion. The
closed repository/flag JSON schema is `aegis_core.team_profile.JSON_SCHEMA`
(`aegis.team.profile/v1`); the user schema is `USER_JSON_SCHEMA`
(`aegis.team.profile.user/v1`). Both describe partial override layers. Named host,
capacity, runner and token-budget maps accept identifiers matching
`[A-Za-z][A-Za-z0-9_.-]{0,63}`. Their entries have closed schemas too.
The exact names `hold` and `skip` are reserved for fallback terminals and cannot
be host aliases or capacity keys. Aliases use case-sensitive, JSON-decoded
identities, so escaped spellings of those reserved names also refuse. Terminals
are recognized before host lookup, including when a raw plan is inspected.

Refusal order is independent of object insertion order. Schema checks consider
version and preset, then model settings, policy, run configuration and supervisor.
Within model settings, hosts precede roles and capacity. Other object fields and
semantic host/role/capacity checks use identifier order. Resolved consumers check
the profile before provenance metadata, using the same schema paths as resolution.
Missing required supervisor fields refuse before present sibling values at every
object level; complete supervisor objects retain identifier-order checks.
Resolved envelopes require `profile`, `values` and `write_scope`. Validation
finishes the profile's required fields, host/route policy and supervisor
cross-field conflicts before checking `values`, then `write_scope`. Missing
envelope keys refuse at their fixed field names. Display, doctor, host advice
and supervisor health use this gate before indexing snapshot fields; malformed
snapshots do not reach state access. Display also accepts the existing command
views: `config show` carries the resolved envelope, while `config init` carries
only a complete profile body and cannot carry resolved provenance or write scope.
Argument/workspace refusals, presets, doctor and host diagnostics retain their
existing formats. Display first copies bounded native JSON and renders that
validated copy. Dictionaries require exact string keys; lists and exact native
strings, integers, finite floats, booleans and null are supported. User objects,
subclasses and non-finite numbers refuse with `invalid value: profile display`,
without calling conversion hooks. Diagnostics allow depth 16, 4,096 entries per
container, 131,072 characters per string, 1,048,576 nodes (including keys), and
67,108,864 string characters in total. Integers are limited to 4,096 bits.
These copy limits accommodate resolved profile/provenance data; profile schema
bounds remain unchanged. Diagnostic text retains its shared redaction policy.
Arrays retain their declared order, including host bindings and fallback chains.
Supervisor fragments participate in that traversal; no preliminary supervisor
screen takes precedence over an earlier field. Flags still refuse supervisor
settings when the traversal reaches that field.

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
Resolved validation checks each copied provenance value against its source
field's schema, including numeric bounds and the separate user schema for
`user.*` records. The resolved profile has a bounded node budget for the built-in
base plus three override layers (four times the per-document 4,096-node budget).
Metadata has separate bounds, and each copied leaf has its own per-document
budget, so copies do not consume the source profile's budget again. Duplicate
provenance paths refuse.
Credentials are always redacted.
Display text is canonicalized, then secret values are redacted, then text is
truncated, including JSON text. Schema-constrained identifiers and keys are not
redacted; free text such as gate names is redacted in both profile and provenance.
Reviewer `hosts`/`optional`/`pinned_family`, extra-lens routing settings,
`fallback.review` chains and policy-lens `host_pref`/`pinned_family` refuse in
the user and flag layers. Host-kind bindings are repository-only too.
Only `lens.extra` may be optional.
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
repository value; different values are ignored. Review-routing fields listed
above still refuse as malformed user configuration. User `optional` and
`pinned_family` entries for `writer` and `research` are always ignored with
reason `repository-only`, never applied, even when they repeat repository
values. Flags refuse every repository-only field for every role.

Each entry has a `user.model_settings.*` record in `values` with `status`
applied/ignored, a reason and affected resolved paths (`applied_paths` keeps exact
components). For other allowed preferences, a user value equal to the
repository-resolved value records `status: applied` and
`reason: repeats repository` without merging, preserving its repository/preset
origin. This also applies to repetitions outside `model_settings`. Empty
objects add no user origin. Valid global
preferences cannot introduce incomplete hosts or roles or invalidate repository
routes, so one user file works across ci-only, solo, pair and mixed repositories.

Every `model_settings`, `run_config` and `supervisor` value is marked frozen at run start.
Consumers must resolve once at startup and retain that snapshot; flag changes
to these sections or the preset refuse when resolving a live run. Inspection
does not reconfigure an existing run. Supervisor settings are not part of the
generic object merge: the repository layer may only narrow them. See
[Supervisor profile](teams-supervisor.md).

## Schema areas

| Section | Area | Fields |
| --- | --- | --- |
| `policy` | `review` | `require_cross_family` boolean; `cap` positive integer or null; `mode` full/delta; `extra_lens_blocks_on` confirmed; `lenses` array of name, host_pref array, voting and pinned_family |
| `policy` | `gates` | Array of name, runner, selector (impacted/whole/list), tests array, python string, must_pass and reuse_identical_tree booleans |
| `policy` | `landing` | target_branch, strategy (combined-full/batch/direct), batch_max, signature_required_for array; publish object with remote and app |
| `model_settings` | `hosts` | Named objects with registered `kind`; user-only auth_mode (sso/api/token) |
| `model_settings` | `roles` | writer, reviewer.correctness, reviewer.security, lens.extra, research; each has hosts (an ordered declared chain), optional model and effort strings, optional and pinned_family booleans |
| `model_settings` | `capacity` | Per declared host: usage_source (subscription-window/credits/none), thresholds (hold_pct/route_pct/flex_route_pct), fallback (per-kind arrays of declared hosts or hold/skip terminals) |
| `run_config` | `runners` | Named objects with cpus, image, provider; user-only pool, credentials and budget_usd_month |
| `run_config` | `autopilot` | queue_full_on_ready, claim_next, resume_writer booleans; rulings |
| `run_config` | `limits` | Repository-only writers_max, votes_max, research_max |
| `run_config` | `token_budgets` | User-only map of per-role positive integer token budgets |
| `supervisor` | `components`, `pauses`, `health` | Five components, all disabled until the owner file enables one; closed pauses; restart and health floors. The repository may narrow a limit and may add a pause. It cannot clear a pause or widen a ceiling. |

Positive integer settings are capped at 1,000,000; budget values are finite
numbers in [0, 1,000,000]; percentages are finite numbers in [0, 100]. Routing
allows at most 16 declared hosts, 16 entries per role `hosts` or lens `host_pref`
binding, 8 targets per fallback chain, and 64 fallback targets across all hosts
and fallback keys together. Every declared target counts, including duplicates,
`hold`/`skip` terminals, overridden aliases and routes unused by an enabled job.
Policy lenses and an enabled `lens.extra` share a total of 16 slots; an extra
lens with an empty binding is disabled and uses no slot. These limits
apply to the merged profile and are checked before route planning, including
when a consumer revalidates a resolved profile. Larger profiles refuse with
their input layer, file and field path. Presets and the examples below fit.
Other arrays and named maps hold at most 64 entries. Strings hold at most 4,096
characters. Map limits count preset entries and additions from every layer:
for example, 63 distinct runner aliases plus the default `local` runner fill
the 64-entry map. `resolve` and `load` check merged bounds before returning,
so CLI and MCP adapters report their normal refusal envelopes before display.
Files hold at most 128 KiB, nesting at most 16, and each input document at
most 4,096 nodes; the resolved-source budget is described above.
Duplicate JSON keys refuse. Native `codex` app threads remain registry entries
that cannot bind team-run roles. `codex-cli` and `claude-code` retain the registry's
qualification boundaries; finding a CLI proves neither login nor OS isolation.
Claude writers explicitly show `write scope: permission rules, not OS-enforced`.
Every role accepting `pinned_family` requires a single-family host chain; pinned
review lenses also refuse transitive review fallbacks that change family.
Per-host usage is never summed; the host commands read configured usage through
the adapter interface described below.

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
kind exists. Candidate host kinds can be registered without qualifying any role.
Remote runners never
provision automatically; adding configuration does not create a remote resource.

Antigravity (`agy`, review vendor family `google`) has a candidate adapter in
`aegis_core.team_host_agy`, selected through the generic
`team_host_adapter.HostAdapter` interface (also re-exported by `team_hosts`) and
the host registry. Its kind appears in the profile schema and
user auth preferences; binding it to a run role still refuses as unqualified.
Finding the binary does not enable the mixed preset's extra lens. No process is
launched by the adapter, and existing host behavior without a host plan is unchanged.

Authentication requires an explicit `sso`, `token` or `api` mode. Every child
first receives one generic, case-insensitive scrub of all registered hosts'
billing variables, session-marker names/prefixes and launcher overrides.
The registry includes the observed legacy environment catalog; empty metadata
on an unmeasured host is no qualification claim. SSO re-adds no credential;
token/api requires a supplied `GEMINI_API_KEY`, re-adds that selected key only,
and sets `modelProvider` to `gemini`. A missing selected credential refuses; another key
or the owner's login is never a fallback. Returned environments are private
process inputs and must never be included in CLI/MCP output or evidence logs.
`authentication(mode, environment, session=UUID)` combines selected auth and new
Aegis markers after scrubbing. `child_environment(environment, UUID)` adds only
markers; supplying `auth_mode` explicitly also preserves the selected credential.
Use a combined call instead of composing two scrubs, which would remove the
previously selected credential or markers.

Environment inputs accept readable `Mapping` objects, including read-only maps,
and return independent dictionaries. Names must be non-empty and contain no `=`
or NUL; Windows names such as `ProgramFiles(x86)` and exported bash function names
such as `BASH_FUNC_name%%` are accepted. Limits are 256 entries, 256 characters per
name, 32,768 per value and 131,072 characters in total, checked before copying
each entry. Invalid environments refuse with `invalid_host_environment` and a
mapping-specific next action. Malformed arguments and unknown host kinds use
usage exit 2; unavailable credentials, adapters and launch admission use refusal
exit 1. Existing public `team_hosts.HostAdapterError` imports remain valid.

The adapter consumes MR-4 model-binding data, including the existing
`gemini-4-argon` and `gemini-4-carbon` rows. Low/medium/high effort is encoded in
the model suffix. All these rows remain planned and unprobed; returning candidate
model options does not admit a model or authorize a role. Unknown classes and
unsupported or rejected levels refuse without selecting another model.

Session ownership requires proven argv atoms and one explicit
`--conversation UUID` selector. Duplicate selectors, continue/latest selection,
unknown options and project/remote switches hold. Every value-taking option
refuses a dash-leading value, including split and attached prompts; installed
help does not document an attached dash-leading prompt form. Accepted prompt
and settings values are opaque. A plain `env` wrapper and its assignment atoms
are parsed; `env` options such as `-u` hold. Windows `.exe` basenames are
case-insensitive on every platform. Aegis-owned `AEGIS_TEAM_HOST` and
`AEGIS_TEAM_SESSION` markers can be
exported to children; they do not prove a native host session. The transcript
locator is relative data for `.gemini/antigravity/brain/UUID/transcript.jsonl`,
based on the hook-event contract, pending a native admission probe. It performs
no path reads; any future reader must use descriptors from a trusted root.

The installed CLI's help and current launcher do not establish a no-auto-update
control or a native child-session marker. `require_launchable()` therefore
refuses with `host_runtime_unqualified` and a next action to probe those controls
and qualify/promote the host. Usage readers, qualification evidence, admission
provenance and mixed-preset enablement are deferred to TP-9b.

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
Host verbs use `aegis.team.hosts.<verb>/v1`, with
`schema_family: aegis.team.hosts/v1`.
The read-only MCP tool `aegis_team_config` returns the same payload as CLI config
JSON except that token-shaped identifiers in capacity and fallback fields are
masked. The CLI preserves exact schema-valid identifiers so its suggested host
commands remain runnable. Both views use the shared core formatter; credentials
and free text retain canonicalize/redact/truncate handling in both views.
Each result includes `status` and `next_action`. Refusals also include `reason`,
`layer` and `file`, so an agent can identify the input to correct without finding
repository-local documentation. Configuration and doctor exit codes are 0 done,
1 refused, 2 usage; host checks have additional decision codes listed below.
Config without a verb and an invalid init preset/host return usage (2), without
echoing the invalid input.

Refusal attribution first checks intrinsic repository schema and policy against
defaults and its preset. Supervisor bounds are checked here, but its narrowing
is compared only against the effective ceiling after user settings are applied.
An intrinsic repository failure names the repository file. Otherwise, a failure
in the user layer names the user file, including malformed JSON or unsafe file
custody. With both layers available, supervisor widening or conflicts attributed
to the repository still name the repository. Only when the combined repository
and user settings succeed does a later refusal name flags and `<command-line>`.
Provenance path strings never decide ownership. Invalid preset/host command
usage remains a flag-layer usage refusal.

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

## Host capacity and usage

`aegis team hosts status --json` lists each declared host's usage source,
thresholds and current job decisions. Doctor includes those same decisions.
`aegis team hosts usage --json` returns per-host measurements without totals.
`aegis team hosts check HOST KIND --json` advises whether a new job may start;
it does not launch a host or grant execution authority. HOST is a profile alias.
KIND is `writer`, `research`, a declared reviewer role or lens, or generic `doc`.
`review` aliases `reviewer.correctness`; `extra-review` aliases `lens.extra`.
Undeclared or disabled role/lens bindings refuse.

Per-host `usage_source` is `subscription-window`, `credits` or `none` (default).
Adapters normalize a subscription snapshot to `window.used_pct` and UTC
`window.resets_at`, or a credit snapshot to `credits_left`; zero credits hold.
`none` disables usage tracking. Real host readers are extension points: no
credential reader ships here. An unconfigured, failing or malformed reader
produces `unknown` for that host and does not block work by capacity advice alone;
profile refusals and family pins still apply.

Default thresholds are `hold_pct: 99` for writers, `route_pct: 95` for voting
reviews and `flex_route_pct: 80` for non-voting lenses and other flexible jobs.
Usage at or above the relevant threshold holds or follows a fallback. Profile
overrides must satisfy `flex_route_pct <= route_pct <= hold_pct`; unspecified
lower thresholds clamp to an explicitly lower hold/route value. User preferences
that conflict with repository thresholds are recorded as ignored.

Canonical role-specific fallback keys override generic chains, including empty
overrides. Aliases resolve before key selection. The first `hold` or `skip`
terminal ends traversal; later hosts are unreachable. `skip` is allowed only for
non-voting jobs; an exhausted chain holds. A held pinned role or lens waits
without falling back. Window holds name the reset in `next_action`.

Checks from a bound host continue from that host's position in its declared
binding. A fallback-only admitted host follows its own explicit routes. Neither
inherits implicit earlier destinations from another host's expansion. Explicit
fallbacks to earlier hosts remain available.
Loading the profile validates the same plan from every bound or admitted host:
each plan must respect family rules and pins, required votes, and destination
admission. If restarting a plan exposes a forbidden terminal or a destination
that cannot itself be checked for that job, the profile refuses at load.

Route refusals use the same order in loading, host check/status, doctor and
supervisor health. Review routes check reviewer independence (cross-family),
destination admission, pinned-family fallback, then forbidden `skip`. Writer
routes check destination admission, then forbidden `skip`; the reviewer rule
does not apply to writer routes. Other non-voting routes check admission and may
use `skip`. Only admitted writer destinations establish the writer families
against which reviews are checked. A destination exposed only by an invalid
writer restart cannot make an otherwise valid reviewer appear dependent.

Checks within each route kind run across its restarted plans in that order.
Pinned routes retain their existing rule: fallback admission is inactive, and
review fallbacks are still checked against the pinned family. Profile bounds,
declarations, role-family pins and required review bindings are checked first.

Check exits are 0 `go`, 3 `hold`, 4 `fallback:HOST`, 5 `skip`, 1 refusal or 2 usage.
Each decision includes its reason and next action. Writer decisions identify
`selected_host` and that host's `write_scope` and `write_boundary`, including a
fallback's weaker boundary: Claude reports `permission rules, not OS-enforced`.
Status and doctor retain the same destination boundary information.
