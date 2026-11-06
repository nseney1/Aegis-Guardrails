# Workflow restart qualification

The standalone maintenance candidate keeps the real workflow held. The local
evidence ledger, native record inspection, operator integration, supervisor and
resource recovery each establish different facts. A passed fixture is not an
authenticated native decision, an effective tool restriction or release approval.

## Roles and startup

Owner-facing ROOT discusses feature requests, reviews evidence and makes narrow
approve/deny decisions against canonical request hashes. A separate operator
performs authorized provisioning, binding, job, resource and custody logistics.
The router selects a team or requests bounded team formation; it neither approves
nor executes that work. Orchestrators choose the planning needed and own their
teams' backlog, source ownership, independent review and integration obligations.

`tools/hierarchy_native.py` reads the latest native Codex turn record. It reports
identity, model, reasoning effort, working directory, approvals and the recorded
permission profile with exact record hashes. Prompt text cannot override those
fields. Requested service tier and observed served tier remain separate. The
served tier comes from the current turn's `thread_settings_applied` event
(`settings_record` names it); settings from an earlier turn are never reused. A
turn ends at `task_complete` or `turn_aborted`; a turn that was stopped may leave
neither, so a second unnamed settings record inside a turn that already has its
own belongs to the next `task_started` (a resumed process may write it first).
Missing served-tier telemetry is unknown and does not stop explicitly authorized
standalone maintenance that requests the default tier; when another tier was
requested, `check` holds with `served tier unavailable`.

`observed_permissions` lists each recorded filesystem entry as `kind`,
`path_or_special`, `access` and `missing_path_behavior`, including specials such
as `slash_tmp` and `tmpdir`. `check` refuses every write it was not told to
expect: path writes outside `--write-root`, and special writes not named by
`--allow-special-write NAME` (`--allow-tmpdir` names `tmpdir`; `root` is never
allowed). A provisioned profile on a real host is checked with
`--approval-policy never --approvals-reviewer user` (or `auto_review`, whichever
the host records): real rollouts record a reviewer even under `never`.
`--approvals-reviewer none` expects no reviewer at all and is only for a host
that records none, such as the test fake. `check` also holds when the served
tier is known and differs from `--requested-tier`, and reports a model or effort
it was given no value for as `unchecked`, which holds. `events` lists the
recorded shell attempts (command, exit code, aggregated output, turn) and patch
applications for the current turn, or every turn with `--turn all`:
`exec_command_end` and `patch_apply_end` events, `item_completed` events carrying
a `CommandExecution` or `FileChange` item, `item.*` stream records, and
`response_item` `custom_tool_call` / `function_call` records named `apply_patch`
paired with their output by `call_id` (targets from the `*** Add File:` and
`*** Update File:` headers). That last shape is unconfirmed against a real host,
and its entries and the probe report say so. A declined patch is marked
`declined`. It reports what the host recorded, never model text.

`tools/hierarchy_native_probe.py` drives provisioned roles through a disposable
probe. A shell attempt is `REFUSED` only when the nonce file is absent and the
rollout records the exact planned command with the probe helper's own JSON for
that nonce and path naming errno 1, 13 or 30. The command counts as its own argv,
the whole string, or `[SHELL, -c|-lc, CMD]` where SHELL's real path is one of
the shells (sh, bash, zsh, dash) the plan resolved on the host PATH; any other
wrapper is `INCONCLUSIVE`. A patch is `REFUSED` only when it failed and a whole
line of its text, with every path it names and the probe root cut out, is
`patch rejected`, a permission or read-only error, or `[Errno N]` for N in 1, 13
or 30, before any context-failure header (text after such a header is the
model's own and never counts). A patch over several paths is never a refusal. A matching record without that evidence is `INCONCLUSIVE`,
no record (or only a declined one) is `NOT_ATTEMPTED`, and both fail the run. A
record that contradicts the target file is `UNEXPECTED`, including a success
record with the nonce absent even when a refusal was also recorded. A target the
probe user could not write before the turn is `INCONCLUSIVE`. The helper sits
outside every role's writable roots; it is re-hashed and its lstat compared
after the probe turn, and every folder from the helper and each target up to `/`
is recorded before the turn. A replaced folder, or one renamed away and back
(its change time moves past its modification time), makes every verdict of that
role `INCONCLUSIVE` and fails the run. After the launcher start,
each role's expected values are recomputed from the run-time profile record; a
difference from the plan refuses that role. Each plan request names the
expected approvals reviewer (`user` or `auto_review` for a real host); there is
no default and no fallback. The run guards both `$HOME/.codex` and the passwd
home's `.codex`; an entry it cannot read makes that folder `unknown`, which fails
the run, but the report is still written and the lock released. It judges only
turns that started after their launch. Live rollout reads leave out an
unterminated final line; a record the reader still cannot take fails only that
role (with its line), the role's session is stopped, and the run goes on to the
next role. The source may itself be a linked worktree. SIGTERM, SIGHUP or SIGINT
stops the role's session through the launcher, removes the login and the probe
worktree (`git worktree remove` only), and writes a report with state
`interrupted`; after a SIGKILL, `cleanup --probe-root` does the same from the
launch records and may be repeated.

The probe's `CODEX_HOME` is the plan's `codex-home` folder, logged in one of two
ways. With an API key (`run --auth api-key`, the default), the folder must be
empty but for the plan's owner mark, and the probe runs
`codex login --with-api-key` with the key from `OPENAI_API_KEY` (or
`--api-key-env`) on stdin. With ChatGPT SSO, the owner first runs
`CODEX_HOME=<probe_root>/codex-home codex login`, then
`run --auth existing`: the probe never calls `codex login`, needs no key
variable, refuses while `OPENAI_API_KEY` or `CODEX_API_KEY` is set (codex could
bill the turns to the key instead of the SSO login), and refuses unless the folder holds only the owner mark with this
plan's probe id and an `auth.json` that is a regular file (not a symlink), has
one link, is owned by the user and is not readable by group or others. It
refuses `sessions/` (a prior session's rollouts would mix with the probe's),
`config.toml` (the probe's `codex_home` write target, and it would change the
run's settings) and any other entry. The report's `login` records
`mode: existing`, the file's `auth_file_sha256_before`, and that `codex login`
was not called; the folder and the hash are checked again before the first
turn. Never run `codex login` without `CODEX_HOME`: it replaces
`~/.codex/auth.json`. In both modes `CODEX_HOME` must be spelled exactly as the
plan's path (one trailing slash allowed; no `..` or symlink alias), and the
cleanup deletes the disposable `auth.json`, so a new plan needs a new login.
The cleanup deletes it only through a handle on `codex-home` opened without
following a link, and only while `codex-home` is a real directory at the plan
path outside `~/.codex`; otherwise it leaves the file and records a cleanup
failure.

When a native `task_started` event is present, the context must follow it and
name that same turn. A missing or mismatched context refuses observation; an old
turn's profile cannot qualify a newly resumed turn. Historical records without
turn-start events remain diagnostic observations, never admission grants.

```
python3 -I -B tools/hierarchy_native.py --rollout /absolute/rollout.jsonl --cid CID inspect
python3 -I -B tools/hierarchy_native.py --rollout /absolute/rollout.jsonl --cid CID check --model gpt-6-astra --effort ultra --cwd /absolute/workspace
python3 -I -B tools/hierarchy_native.py --rollout /absolute/rollout.jsonl --cid CID check --model gpt-6-astra --effort ultra --cwd /absolute/workspace --approval-policy never --approvals-reviewer user --allow-special-write tmpdir
python3 -I -B tools/hierarchy_native.py --rollout /absolute/rollout.jsonl --cid CID events --turn all
python3 -I -B tools/hierarchy_native.py --rollout /absolute/rollout.jsonl --cid CID admit --role operator
```

The `admit` command currently refuses native admission for every Codex role in
the role registry. Local files and environment
variables are provenance, not authenticated caller identity. The inspected native
interface supplies no verified tool allowlist or narrow authenticated decision
service. ROOT additionally requires an effective read-only filesystem, and the
router retains medium reasoning and ultrafast configured tier. Merely renaming
a process or granting a helper broad shell access does not enforce these roles.

## Shared contracts

The canonical request/decision/intent/result state is the parent's
`hierarchy_lifecycle.Lifecycle` journal. Its evidence-only status is preserved.
The operator and supervisor must not create a second authority or intent ledger.
Watch dispatch records correlate a call; they never authorize it. Every effect
needs fresh exact source, current actor/generation, bounded approval, required
gate evidence and a durable canonical intent. An unresolved intent stays unknown
and cannot be retried merely because a reply or a runner disappeared.

The disposable POSIX operator holds an exclusive OS lock on the canonical root
directory from eligibility inspection through terminal publication. Contending
callers return refused/no-effect without entering execution, so fresh canonical
eligibility can permit a later attempt. A crash releases the OS lock, while
the durable canonical intent prevents redispatch. Even a lost intent-publication
acknowledgement is conservatively unknown; no stale lock is automatically deleted.

The supervisor bridge observes a request ID/hash and continues that exact request
through the operator. Resource recovery supplies read-only capacity, reservation,
job and blocker facts. Missing process visibility and unknown effects cannot
free a reservation. Fixed limits and existing priority rules remain unchanged.
Independent acceptance and delivery follow terminal job evidence; neither follows
automatically from process exit or mailbox read acknowledgement.

## Team operating model and dependent packets

The following requirement inventory keeps the owner's team model explicit. These
packets depend on the restart candidate; they are not silently treated as shipped
native services or new authority to expand this maintenance scope.

| Packet | Required behavior | Accountable implementation owner | Dependency and acceptance |
| --- | --- | --- | --- |
| FEATURE-INTAKE | ROOT submits immutable owner-intent reference, feature/version/hash, project, scope, priority, constraints, budget and acceptance | Native decision/intake service owner | Authenticated ROOT identity and narrow intake tool; reject shell/source/actor operations |
| TEAM-ROUTING | Select existing project team or request formation; retain correlation and return disposition | Router/registry owner | Current registry identity/generation and bounded formation policy; no router actor/capacity mutation |
| TEAM-FORMATION | Provision admitted roles only within approved staffing/source/resource envelope | Qualified operator owner | Native role/capability admission, leases and capacity; out-of-envelope request returns for decision |
| TEAM-PLAN | Orchestrator chooses architecture/performance/implementation/integration planning or justified small-change path | Team orchestrator | Named roles, source/path owners, tests, performance obligations, dependencies and stop conditions |
| CROSS-TEAM-INTEGRATION | Producer/consumer agree exact interfaces and source, shared-file owner, compatibility and incoming patch acceptance | Project integration owner | Correlated request and response, exact reviewed incoming source and tested integrated checkpoint |
| TDD-LANE | Reproduce public failure, repair it, preserve red/green evidence and deliver exact source | Admitted implementer and independent reviewer | Operator admission plus team plan; review remains independent from author and executor |
| DURABLE-CONTINUATION | Advance eligible work across late arrivals, capacity wait, actor caps, lost replies and supervisor restart | Supervisor/bridge owner | Canonical obligations, no duplicate effects, authenticated provider, qualified lifetime and fenced generations |
| RESTART-CUTOVER | Reconcile pending work, stop/checkpoint/reconnect safely and verify a disposable native cycle | Qualified operator and independent reviewer | All native gates below, exact-source checks, owner-required signatures and separate restart authorization |

The maintenance slice supplies local observation/refusal and canonical integration
seams, supervisor behavior, resource recovery and evidence-ledger repair. It does
not implement a registry planner or broaden the parent's ledger into a team
orchestrator. These dependent packets keep feature intake, planning and team
formation obligations visible until their public and native acceptance exists.

## Native qualification gates

Before a live restart, independently demonstrate:

1. Authenticated current caller identity, model/effort, effective filesystem and
   tool capabilities; stale identities/generations and ROOT/router operational
   attempts refuse at the actual service boundary.
2. An authenticated decision tied to exact request bytes, phase, operation, source
   and continuing authority, followed by a distinct admitted operator.
3. A supported persistent provider/executor that survives model-turn completion,
   reconnect and supervisor restart without raw undocumented RPC.
4. Exact-source execution, failure-inclusive retained evidence, conservative
   unknown-effect recovery, independent review and accountable next work.
5. The integrated feature/team scenario: bounded team formation, planning and
   cross-team agreement, TDD lane failure, lost reply, cap succession and late
   dependent work, without duplicate source effects or false capacity release.

Absent supported native interfaces remain blockers owned by the native service
and operator maintainers. Fixture adapters cannot close these gates. Approval
signatures, protected merge, release and actual workflow restart remain separate
owner actions. Existing stopped actors, live bindings, leases and failed evidence
must remain intact during candidate validation.

The reviewed [six-team cutover and rollback plan](hierarchy-six-team-cutover.md)
maps the two Aegis and four Stormheir scopes while retaining original claims,
partial work and independent acceptance obligations. Its dated observations
require revalidation before separately authorized cutover.
