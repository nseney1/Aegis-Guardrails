# Supervisor profile

`supervisor` is a closed object on `aegis.team.profile/v1`. Resolution always
returns one, including when no file sets it. `aegis team config init` does not
write supervisor keys. Command flags cannot set any supervisor field.

The policy module plans and reports. The separate, explicitly invoked
`aegis_core.team_supervisor_start.start` API starts eligible components. No
ordinary Codex path invokes it and no MCP tool is added. Lease `aegis team status`
is unchanged.

`assemble`, `plan`, `supervisor_health`, profile `resolve`, `load` and
`validate_resolved` use one closed-schema validator before consuming profile
inputs. Wrong scalar or container types, unknown keys and explicit null
supervisor fragments refuse without coercion or raw exceptions. `assemble`
requires two fragment objects; pass `{}` for an absent layer. Resolved objects
must contain all supervisor leaves. Refusals retain the responsible layer and
schema path. Repository roots must be bounded absolute strings or `Path` objects;
malformed roots refuse with `unsafe profile root; use an absolute trusted directory`.
Health uses the profile loader's route-kind refusal order: reviewer independence
precedes admission on review routes; admission precedes the remaining checks on
writer routes, which never apply the reviewer-independence rule.

## Components

The only component ids are `autopilot`, `landing`, `writer`, `renew` and
`monitor`. Each one is `enabled: false` until the owner file sets `enabled`
true. Default intervals are autopilot 30s, landing 60s, writer 60s, renew
9000s and monitor 20s.

Kit-private loops stay outside this object. Examples are janitor, throughput,
platform watch, idle handling, mining, full daemons, remote slots and the
coordinator session. `run_config.autopilot.resume_writer` and
`run_config.limits` remain repository concurrency policy. They do not enable a
component, clear a pause or raise a restart ceiling.

## Narrowing

The owner file (`~/.config/aegis/team.json`) replaces the built-in ceiling for
each field it sets. The repository file may set a value only when it is equally
strict or stricter:

- a restart `limit` may fall, not rise (1..100; default 3)
- `initial_s`, `max_s`, `window_s` and every interval may rise, not fall
  (1..86400). Default restart timing is initial 30s, max 300s, window 300s
- `enabled: true` is an owner choice. The repository may set `enabled: false`
- `health.writer_dead_s` may rise (60..86400; default 60)
- `health.disk_floor_mib` may rise (4096..1048576; default 4096)
- `health.capacity_interval_s`, `usage_interval_s` and `audit_interval_s` may
  rise (defaults 120, 120 and 600)

A wider repository value refuses with
`supervisor limit cannot be widened by the repository layer`. Values are not
clamped. After the overlay, `initial_s` must be less than or equal to `max_s`.
If the owner file alone is already inconsistent, the refusal layer is `user`.
Otherwise it is `repo`. The message is `value out of range:` plus the closed
schema path, with no echoed number.

## Pauses

The closed pause names, in canonical order, are `owner`, `capacity`, `disk`,
`audit`, `autopilot`, `landing`, `writer` and `renew`, then `monitor`.
Duplicates refuse with `invalid value: supervisor.pauses`. A boolean map, null,
`clear`, `unpause`, `paused: false` or a boolean list item refuses with
`supervisor pause cannot be cleared by the repository layer` on every layer,
including the owner file. Clearing an owner pause is done by omitting that
name from the owner file's list.

The repository list is a union, not a replacement. An empty repository list
adds nothing. The repository may add any closed name, including `owner`.
The pause leaf's provenance is `repo` when the repository contributes any new
name; otherwise an explicitly supplied user list keeps `user` provenance.
`owner`, `capacity` and `disk` hold every component. `audit` holds autopilot,
landing, writer and renew, and leaves monitor reportable. A component name
holds that component.

## Backoff

A recorded failure appends its timestamp. A failure counts in the current
window only when `0 <= now - t < window_s`. Window expiry stops that counting;
evidence needed for an outstanding deadline stays until the deadline expires.
Recording retains a sufficient set of predecessors for the greatest pending
backoff deadline, including predecessors outside the current window. It also
keeps future timestamps, the newest visible timestamp for interval deadlines,
and up to the 100 newest in-window timestamps for counting. The repository
`limit` does not shorten that evidence. Once doubling reaches `max_s`, additional
predecessors cannot increase the backoff deadline and need not be kept for that
purpose. If required evidence cannot fit the reader's 100-entry cap, recording
refuses with `supervisor failure history limit exceeded` on the state layer,
leaving its input unchanged. One in-window failure keeps `initial_s`. Each further
in-window failure doubles the displayed delay, capped at `max_s`. When the
in-window count reaches `limit`, the component is `restart_exhausted` and is
not started. For each recorded failure, count failures inside
the window ending at that timestamp. Recompute that event's pending delay from
its count and the restart policy. Its deadline is the timestamp plus the greater
of the interval and the pending delay. `next_eligible_at` is the maximum of all
these event deadlines. Both planning and recording a later failure preserve
an outstanding deadline. Deadlines are computed in one pass over sorted history,
grouping equal timestamps so every duplicate counts every other duplicate.
Original event indices are preserved when selecting a retained deadline witness.
For initial 200s, max 600s and a 300s window, failures
recorded at 0, 1 and 2 derive deadline 602; recording at 303 keeps 602 even
though the earlier failures no longer count in the current window. Once that
deadline expires, its supporting evidence can be pruned. A recorded timestamp
ahead of `now` still holds its deadline after clock rollback, but does not count
in the current restart window. No stored
delay participates in this calculation. The deadline is null only when
no failure is recorded. A recorded success sets the delay back to
`initial_s` and clears that component's failures. Dry-run, health and a
refused profile do not append, reset or write state. Editing the repository
file does not reset counters.

## Dry-run

`plan` returns `status: dry_run`, `starts_nothing: true`, `start` and `components`.
Every plan, refusal and health result says `starts_nothing: true`: these calls
start no processes. The proposed work is carried by `start` and component
action `would_start`. For example, an enabled, eligible writer with no other
enabled components returns `status: dry_run`, `starts_nothing: true`,
`start: ["writer"]` and a writer row with `action: would_start`.
A component is in `start` only when it is enabled, not held, not exhausted,
not already in the caller-supplied running set, and the clock has reached
`next_eligible_at`. The caller supplies `running` and `now`. The planner does
not inspect processes. When several actions apply, the first match wins:
disabled, paused, restart_exhausted, already_running, waiting_backoff,
would_start.

A bad clock, running set or state returns `status: refused`, a fixed reason,
`starts_nothing: true` and an empty `start`, and omits `components`. The
reason does not include the offending bytes.

## State file

### Explicit starter

`start(resolved, commands, user_root=absolute_home, now=integer_seconds, timeout=1)`
takes a resolved profile and an owner-supplied mapping of component ids to argv.
The owner must supply these commands independently of repository content. Each
executable is absolute; there is no shell, PATH discovery, repository working
directory, or command discovery from a file. The starter uses `/` as cwd and
closes inherited descriptors. Missing commands leave that component unstarted.
Commands are bounded before copying (five components, 64 arguments each, 4096
characters per argument, 32768 characters per command); NULs refuse. Every
argument, including the executable, must encode with `os.fsencode` before any
state write; encoding failures return `invalid_commands` and leave state bytes
unchanged. A corrected command can then start normally. The timeout
is in `(0, 30]` seconds and bounds identity registration after exec, not service
readiness or the operating system's exec operation.

Only ids in `plan()['start']` whose row has `action: would_start` are attempted.
The starter never interprets `starts_nothing` as permission. The resolved typed
pause union is passed through unchanged; no profile or pause is rewritten or
deleted. It adds no automatic unpause or recovery operation.

Linux is currently required: recorded identity includes the kernel boot UUID,
PID namespace, PID and `/proc` start ticks. The boot UUID is read from
`/proc/sys/kernel/random/boot_id` with a 37-byte cap. The namespace is the
`pid:[inode]` identity of `/proc/self/ns/pid`: directory components are opened
without following links, and the kernel's `self` and `pid` links are inspected
relative to held descriptors. A proc mount whose numeric PID view differs from
the caller also refuses. Unavailable or malformed boot/namespace sources return
`identity_unavailable` before any attempt or state write.

Only a record with the current boot and PID namespace may be probed for live
PID/start ticks; zombies are dead. A previous-boot record is dead and may be
replaced on a successful start. A same-boot record from another PID namespace
returns `identity_ambiguous` without probing its PID, starting a duplicate or
changing state. Unreadable or indeterminate process identity refuses rather than
treating a PID as dead. Repository paths and PID-only probes are never used as
liveness evidence.

Before interpreting recorded liveness or attempting a start, the caller's own
process-table entry must be readable through the same confined `/proc` path.
A missing recorded PID counts as dead only while this self witness remains
observable. Missing procfs or an unreadable self entry returns
`identity_unavailable`, so missing ancestors cannot trigger a duplicate start.

The owner home and every ancestor are opened without following symlinks. The
existing `.config/aegis` directory must be owned by the current UID and not
group/other writable. A nonblocking exclusive directory lock covers the complete
read-plan-start-record transaction. A concurrent caller returns `state_locked`
or observes the winner's recorded identity. Renaming an ancestor cannot redirect
reads or atomic writes away from the held directory. Missing directories refuse;
the starter creates none. The state descriptor is borrowed from the existing
`storage_confined.confined_file` context for the entire transaction; the starter
implements no separate directory walker and opens no descriptors directly.

`supervisor-processes.json` is an additional owner-only state leaf beside
`supervisor-state.json`. It has version 2, a `processes` map of component ids to
`{boot_id, pid_namespace, pid, start_ticks}` objects, and a `pending` component id
or null. Version 1 is ambiguous and returns `identity_ambiguous` until the trusted
owner reconciles it; it is never silently migrated or treated as live/dead. The
separate `supervisor-state.json` schema remains version 1. Both files
require bounded reads before JSON parsing, bounded structure, unique keys and
closed schemas. Unsafe, unreadable, oversized or malformed state refuses with
code `state_unavailable` and reason `unsafe or unreadable supervisor state`.

Before exec the starter atomically records a pending intent and a conservative
`note_failure` checkpoint in the existing supervisor state. An exec error or
registration timeout whose child is confirmed reaped retains that failure,
clears the intent and respects backoff on the next plan. Constructor failures
clear custody only for the narrowly recognized CPython exec-error form: an
`OSError` with errno `ENOENT`, `EACCES`, `ENOEXEC` or `ENOTDIR` and `filename`
equal to the executable. CPython reaps that failed child before raising the
exec error; the installed-runtime regression verifies this behavior. Other
constructor exceptions can occur after fork, even without a returned handle.
They keep the intent and process record and return `recovery_required`;
`BaseException` cancellation is re-raised with custody preserved. Unrecognized
errnos are conservatively treated as unknown, even if a particular instance
was an exec failure. Pre-check failures still leave state byte-identical.
Failures after child creation retain conservative recovery custody. If cleanup
raises from `kill()` or `wait()`, times out, or cannot confirm a reaped child,
the starter keeps both the pending intent and any existing process record and
returns `recovery_required`. A later call cannot launch another instance until
trusted-owner reconciliation. Successful
identity registration is published before
`note_success` clears the failure history; only then is the intent cleared.
Each leaf replacement is atomic, not a transaction spanning both files. A crash
or write failure leaving an intent returns `recovery_required` on retry, even
when the recorded child appears dead. This deliberately requires the trusted
owner to reconcile both state files with the actual child before another start;
it prevents a duplicate exec across every interrupted-write window.

Results have `status: ok` and `attempts` containing `{id, outcome}` objects,
where outcome is `started` or `start_failed`. A refusal has `status: refused`,
a fixed `code`, fixed `reason` and `attempts` completed before the refusal.
Other codes are `unsupported_platform`, `identity_unavailable`, `identity_ambiguous`, `plan_refused`,
`invalid_commands` and `invalid_timeout`. Returned reasons never include supplied
paths, argv, child output or exception diagnostics. Start success proves exec
and identity registration, not application readiness. Only the owner UID is
trusted to maintain these records; protection from the owner rewriting run
controls is outside the v5.0 threat model.

The state leaf is `supervisor-state.json`, beside `team.json`, under the
resolved owner config directory. The user root must already be absolute. A
relative or malformed root, including an empty string, NUL or a spelling too
long for the confined root (32,768 characters including the config suffix), refuses with
`user profile root unavailable; configure a home directory` and is not
resolved against the working directory. Reads and replacements use a
descriptor from that directory and do not follow a renamed or linked path
component. The state file itself must be owned by the current user and must
not be group-writable or other-writable. A file that fails that check refuses
with `supervisor state must be owned by the current user and not group/other-writable`
and is not replaced. A missing file or a missing directory is empty state:
version 1, delay 30s and no failures for each component. An unsafe, oversized,
malformed or wrong-version file refuses with `unsafe or unreadable supervisor state`
and leaves the bytes unchanged. The same 128 KiB cap, and the same node cap as
the largest accepted document, are applied before parsing. The writer refuses
a document its reader would refuse. The document allows only version 1 and the
five component ids. Each component stores `delay_s` and at most 100 integer
timestamps in `0..10**12`. The stored delay is checked, then ignored: the view
recomputes the displayed delay from the current in-window count, and the pending
deadline from the maximum deadline across recorded failure events. Descriptor read, stat and close
errors also refuse with `unsafe or unreadable supervisor state`. A group-writable or
wrongly owned config directory refuses. Two readers observe one complete
replacement, never a torn mix.

## Health

`supervisor_health` returns schema `aegis.team.supervisor/v1`. On success,
`profile` is `valid`, `starts_nothing` is true, and observations `writer_dead`,
`disk`, `capacity`, `usage` and `audit` are `not_run`. Each component row has
its id, enabled flag, interval, holding pauses, delay, failure count, exhausted
flag and `next_eligible_at` (`null` only when no failure is recorded).
On refusal, `profile` is `refused`, pauses are empty, and observations and
components are omitted. Text taken from an untrusted field is canonicalized,
then redacted, then truncated. A multi-line value is refused rather than joined
into one line. Health never starts a component and never writes the state file.

### Explicit observations

`aegis_core.team_supervisor_observe.observe(resolved, workspace_root=absolute_root,
now=integer_seconds, usage_adapter=None)` is a separate, explicitly invoked API.
`resolved` is the complete envelope returned by profile resolution. It validates
bounds before copying and revalidates a private snapshot before adapters run.
The pure policy, existing health output and ordinary Codex callers are unchanged;
no hook or MCP tool invokes observations. The caller schedules calls using the
resolved health intervals; this API has no polling loop, shared cache or state file.

Results have schema `aegis.team.supervisor.observations/v1`, `status: ok`,
`starts_nothing: true`, `writes_nothing: true` and an `observations` object.
Unknown is a source result, not a whole-report refusal. Each observation failure
leaves the others visible. No observation changes pauses, claims, queues,
profiles or supervisor state. The preflight and public services use the existing
hardened, read-only gitsafe Git transport. Observation data never supplies
commands. Executable resolution stays entirely in the central transport;
`GITSAFE-ORDINARY-OUTSIDE` tracks the nondefault configuration where the owner's
PATH contains an absolute directory inside the workspace.

Before calling either lease or audit services, one hardened read runs
`for-each-ref --count=257 --format=x refs/aegis/lanes/`. Its constant format
emits at most 514 bytes rather than untrusted ref names. More than 256 refs
makes both Git observations unknown with reason `lease_limit`, and neither
service is called. A failed or malformed preflight yields `leases_unavailable`.
The count is fresh on each invocation, not a cached authorization. It is a
preflight snapshot; it does not make the later service reads transactional.
Observation work is bounded by this lease-count preflight and the existing
per-command timeouts. The preflight command has a 10-second timeout; this API
does not enforce a shared total-operation deadline.

- `writer_dead` without `user_root` is `state: unknown`, with reason
  `no_bound_liveness_source`. `observe` does not read a binding on that path.
  The existing v1 lease schema has no writer process identity; a live or
  expired lease cannot establish life or death by itself. With `user_root`,
  Design: SUPERVISOR-WRITER-LIVENESS applies: `dead` only for a bound record of
  the current `(lane, claim_id, gen)` in this boot and pid namespace whose pid
  is absent or whose start ticks differ. Everything else stays `unknown`.
  Its separate `leases` object counts `live`, `expired` and `unreadable` records
  from `team.read_leases`. No leases is a known zero count; unreadable records
  make that object's state unknown while preserving known counts. A failed
  read or a result over 256 records yields `leases_unavailable` and no counts.
- `disk` uses `statvfs` on the held workspace descriptor, never a pathname
  fallback or the doctor's scratch walk. It reports `healthy` or `below_floor`,
  `free_bytes` and the resolved `floor_mib`; equality meets the floor.
  Unsupported platforms yield `unknown`/`unsupported_platform`. A failed or
  invalid measurement yields `unknown`/`disk_unavailable`.
- `usage` and `capacity` share one `HostCapacity.usage()` pass per invocation.
  Each declared host's adapter is read at most once. Usage exposes only the
  service's validated numeric counters and canonical reset timestamp, together
  with the source and host. Capacity compares that same snapshot against the
  host's writer `hold_pct` threshold, or zero remaining credits, yielding
  `available` or `at_limit`. It is per-host advice and grants no execution
  authority or fallback selection. An absent, disabled, failed or malformed
  source makes that host unknown. Aggregate states are known only when every
  declared host is known; empty host sets remain unknown. Other host rows stay
  visible when one host fails. There are at most the profile's 16 hosts.
- `audit` consumes `team_queue.audit` as-is and reports `clean` or `findings`
  with a finding count. Finding text is never returned or executed. Refused,
  unreadable, malformed or oversized reports yield `unknown`/`audit_unavailable`.
  Result projection accepts at most 256 items and 2048 findings; upstream
  product services retain their own file, JSON and Git-read limits.

The owner selects a trusted absolute workspace root. Confined storage opens
each ancestor without following symlinks and holds a root descriptor across
the observations. Disk measurements keep that identity across renames.
Repository-service results are published only if confined root checks before
and after the call match that descriptor; a changed or linked root leaves
repository observations unknown. The public services retain their own storage
and Git boundaries; these observations are separate source snapshots, not a
transaction across the lease and queue stores. Missing or unsafe roots yield
`workspace_unavailable`; missing descriptor capabilities yield
`unsupported_platform`. All borrowed descriptors close on success and failure.

Host display text is canonicalized, then redacted, then truncated. Lease labels,
paths, audit diagnostics and exception text are omitted. Clock inputs must be
integers in `0..4102444800`; invalid clocks return `status: refused`,
`code: invalid_clock`, reason `invalid observation clock`. Invalid profiles return
`code: invalid_profile`, reason `invalid resolved observation profile` before
any source is probed. Both refusals retain the two true effect flags and omit
observations. Windows can still report configured host usage while filesystem
observations remain unknown behind their capability boundaries.

## Design: SUPERVISOR-WRITER-LIVENESS

This section is the implemented contract. `aegis_core/team_writer_binding.py`
provides `bind`, the closed reader, and the per-lane judge.
`FencedWakeProcesses.created_child` calls `bind` after the child is in launcher
custody. `observe` without `user_root` stays on the constant result above and
does not read a binding. Binding work runs only when the existing plan
discovery finds a plan that `hierarchy_hosts.governing_plan(base, mailbox_root,
hierarchy)` validates and `hierarchy_hosts.plan_host(plan, endpoint)` covers,
for every provider. Discovery alone grants no binding authority. Malformed,
foreign-hierarchy, conflicting, or indeterminate plans refuse with
`state_unavailable` before owner-home access. A proven-absent
plan performs no owner-config read, process probe, lease read, or
writer-bindings write. Indeterminate discovery refuses with
`state_unavailable` and performs none of those reads. The v1 lease keys stay
`v`, `lane`, `role`, `owner`, `claim_id`, `gen`, `branch`, `paths`, `ts`, `ttl_s`.
`aegis_core/team.py` stays free of process identity (989 lines, 1000-line cap).
`supervisor-processes.json` stays the component map
(`autopilot`, `landing`, `writer`, `renew`, `monitor`) and is not a lane store.
The component id `writer` is a supervisor component, not a lane claim.

Invariant. `writer_dead` is `dead` only when a binding for the current
`(lane, claim_id, gen)` carries this boot id and this pid namespace, and that
pid is absent or its start ticks differ. Every other case is `unknown`. A pid
is never read from repository text, lease labels, evidence JSON, a pid file,
or `.running-wake`.

An owner-UID process that rewrites `writer-bindings.json` or the launch
request can forge a binding. That is out of scope for v5.0
(OS-PRINCIPAL-1). It is not a finding.

### Where the identity is recorded

No current call holds both the writer pid and the current lease triple.

The claim path mints the triple and spawns nothing. `team.claim`
(`aegis_core/team.py`, `claim`) draws `claim_id` with `secrets.token_hex(8)`
and sets `gen` to 1 or the expired lease's `gen + 1`. The claimer's pid is
not the writer. `aegis_cli/team.py` `_claim` prints the lease view (`claim_id`,
`gen`, no pid) and returns. `tools/hierarchy_team.py` `step_leases` runs that
CLI during init, before `up`, and keeps `{lease, oid}` plus the evidence JSON.
Those files are not a liveness source. `renew` keeps `claim_id` and stores
`gen + 1`, except an expired renew draws a new `claim_id`. `transfer` keeps
`claim_id` and stores `gen + 1`. `release` deletes the lease. None of them
learns a writer pid. Ordinary `aegis team claim` stays byte-identical: it
does not open the owner config directory.

The product spawn path learns a pid and does not learn the triple.
`tools/hierarchy_launcher.py` `run_start` is the start `Popen`. That function
then waits and stops the start group, so the start child is gone before
`start` returns `bound`. Binding it would report `dead` after every successful
start. `start_lock` writes the launcher pid and unlinks it. Neither is the
writer. `tools/hierarchy_team.py` `start_loop` writes the orchestration-loop
pid into the run directory. That pid is not a lane writer.
`FencedWakeProcesses.Popen` and `created_child` are the resume turn: the child
pid exists in memory before `.running-wake` is written. That file is keyed by
endpoint under the hierarchy base, uses a `ps` birth snapshot, and is not
owner-home storage. The observer does not read it.

The recording call is a new explicit `bind`, invoked from `created_child`
after `Popen` returns, with `pid` taken from that process object. `run_start`,
`start_loop`, `step_leases`, `_claim`, `claim`, `renew`, `transfer`, and
`release` do not call it. No MCP tool calls it. `bind` is loaded from the
runtime source `hierarchy_runtime_source.verify` just accepted, never from
an ambient import. If that source cannot supply `bind`, the launch records
`source_unavailable` and does not run any other copy. A refusal, including
`state_locked` after a short bounded retry, any other refusal, or an
exception, stops and reaps that child through the launcher's custody path
and fails the resume with a typed refusal (`writer binding refused:` plus
one fixed code). The guard finder remains first in `sys.meta_path` throughout
binding and every retry, so lazy `aegis_core` imports also come from the
verified runtime. Missing modules cannot fall through to another installation.
Source reads are bounded before compilation and use retained no-follow
directory descriptors. Prior modules and the import finder are restored on
every exit. A confirmed binding refusal returns code 2 to the parent,
including when group exit remains unconfirmed: `stop_unconfirmed` retains the
admission evidence and typed reason. A code-3 result from a retained worker
also persists a validated binding reason in the launch record; arbitrary text
does not qualify. If the parent cannot republish resume admission or read/clear
the running-wake record after confirmed child exit, `error` keeps the validated
binding refusal and `recovery_error` separately carries the fixed publication
or retirement diagnostic. The returned result and the latest record shown by
`status` retain both fields. Existing recovery exit codes and admission evidence
retention still apply. The child is not turned into the
no-child failed-spawn path. The next resume calls `bind` again with the new pid.

`bind(user_root, workspace_root, lane, pid)` re-reads only that lane:
`gitsafe.read_ref` of `team.lane_ref(lane)`, then `team.parse_lease` of
`gitsafe.read_object` capped at `team.MAX_LEASE_BYTES`. Other lane refs are
not listed. The read stays inside the confined workspace identity bracket.
The caller does not pass `claim_id` or `gen`,
so a request file cannot choose the triple. `lane` selects which lease to
read. It must match `valid_lane`. `user_root` is the passwd home of the
current uid (`pwd.getpwuid(os.getuid()).pw_dir`), not `$HOME` and not a
workspace path. `workspace_root` is the repository the owner passed to
`aegis team claim` (`hierarchy_team` uses `run.project`). A changed or linked
root across the git read returns `lease_unavailable` and writes nothing.
A missing, expired-and-replaced, or unreadable lease writes nothing. An
expired lease that is still the stored object is current: its triple is the
key. A pid that is already absent or a zombie is `identity_unavailable` and
writes nothing. Death is recorded only after a live identity was published.

`renew` and `transfer` move `gen`. The old record then fails the current-triple
check, so the lane stays `unknown` until a later `bind` of a live pid. The
renew CLI does not bind: its pid is the short-lived `aegis` process.

### Owner-home record

The leaf is `writer-bindings.json` beside `team.json` and
`supervisor-state.json`, under `<user_root>/.config/aegis`. The starter's
directory rule applies: every ancestor is opened without following links, the
directory is owned by the current uid and not group- or other-writable, and
the descriptor comes from `storage_confined.confined_file`. Missing
directories are not created. The leaf is mode `0600`, owner-only, replaced
atomically on the held directory descriptor. A symlink leaf is not followed.
`bind` holds a nonblocking exclusive flock for the read-modify-publish.
A busy lock returns `state_locked`. The launcher retries that code a short
bounded number of times, then stops the child. `observe` does not
take that lock and does not write. An atomic replace gives `observe` one
complete file.

Version 1, closed, `sort_keys`, separators `(",", ":")`, one trailing newline:

```json
{"version":1,"bindings":{"<lane>":{"boot_id":"<36>","claim_id":"<16 hex>","gen":1,"pid":1,"pid_namespace":"pid:[<inode>]","start_ticks":0}}}
```

One record per lane. The logical key is `(lane, claim_id, gen)`: the map key
is the lane, and `claim_id` plus `gen` must equal the lease just read. At most
256 records, the observation lease cap. Field bounds match
`team_supervisor_start.process_identity` and its record checks: `pid` in
`1..2147483647`, `start_ticks` in `0..10**20 - 1`, `boot_id` a 36-byte
`[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}`, `pid_namespace` matching
`pid:\[[0-9]{1,20}\]` and at most 26 bytes, `gen` in `1..2**53`, `claim_id`
16 lowercase hex, lane `valid_lane`. Duplicate keys, extra keys, another
version, and a non-object refuse before use. The reader caps the file at
68379 bytes before parsing, which is the UTF-8 length of 256 maximum records
plus that envelope. The writer refuses a document the reader would refuse.
A missing file is an empty map. Unsafe, unreadable, oversized, or malformed
bytes are `state_unavailable` for `bind` and leave the previous bytes in
place. There is no pending-intent record and no `recovery_required`: `bind`
does not exec.

Identity is read the way the starter reads it, in the new module, without
editing `team_supervisor_start.py`. Boot id comes from
`/proc/sys/kernel/random/boot_id` with a 37-byte cap. The namespace is the
`pid:[inode]` link of `/proc/self/ns/pid`, opened by descriptor. Start ticks
are field 22 of `/proc/<pid>/stat` (the integer after the `comm` parenthesis).
States `Z`, `X`, and `x` are absent. A proc mount whose `self` link is not
the caller's pid is `identity_unavailable`. The same-boot, other-namespace
record is not probed.

Replace rules under the lock. No record for the lane: publish. The stored
record is this boot and namespace and the same live pid and ticks: republish
when `claim_id` or `gen` changed, and return success when the bytes would be
identical. The stored record is this boot and namespace and a different pid
that is still that process: `identity_ambiguous`, bytes unchanged. The stored
record is a different boot or namespace, or the same scope with the pid
absent or the ticks different: replace. A previous boot is not treated as
`dead` by the observer; it only frees the slot for a new publish.

`bind` returns `status: ok` or `status: refused` with a fixed `code` and
`reason`. Reasons contain no lane, pid, path, argv, lease label, or
exception text.

| code | reason |
| --- | --- |
| `unsupported_platform` | `unsupported platform: writer binding unavailable` |
| `state_unavailable` | `unsafe or unreadable writer binding` |
| `state_locked` | `writer binding is locked` |
| `identity_unavailable` | `writer process identity unavailable` |
| `identity_ambiguous` | `writer binding scope is ambiguous` |
| `lease_unavailable` | `writer lease is unavailable` |
| `invalid_lane` | `invalid writer lane` |

Linux and `storage_confined.descriptor_supported()` are required. Elsewhere
`bind` returns `unsupported_platform` before a write.

### Observer rules

`observe` gains keyword-only `user_root=None`. `None` does not open a home,
does not call the binding reader, and returns today's `writer_dead` object.
Callers that omit it stay byte-compatible. A passed `user_root` is a bounded
absolute home, the same spelling rule as the starter, with no NUL and no
`..`. A bad home leaves the other observations visible, sets `writer_dead`
to `unknown` / `bindings_unavailable`, and echoes nothing.

With a usable home, `observe` still sets `writes_nothing` and `starts_nothing`.
It does not create the config directory. The `leases` object stays the count
object already defined. Lease preflight failure (`lease_limit`,
`leases_unavailable`, `workspace_unavailable`, `unsupported_platform`) skips
the binding file; a missing triple is not `dead`. `writer_dead_s` remains
the caller's scheduling interval and is not a death timeout.

For each readable current lease, load the lane's record. Compare `claim_id`
and `gen` to the lease. Then:

| record | judgement | state | reason |
| --- | --- | --- | --- |
| none, or `claim_id` / `gen` differs | ignore the record | `unknown` | `no_bound_liveness_source` |
| boot id or pid namespace differs | do not probe the pid | `unknown` | `binding_scope_mismatch` |
| same boot and namespace, self `/proc` unreadable, or the pid's identity indeterminate | missing is not death | `unknown` | `identity_unavailable` |
| same scope, pid absent or a zombie, self witness readable | process is gone | `dead` | `writer_absent` |
| same scope, start ticks differ | pid was reused | `dead` | `writer_replaced` |
| same scope, same pid and start ticks | process still bound | `unknown` | `writer_bound` |

The self witness is `process_identity` of the observer's own pid through the
same confined `/proc` path. A missing recorded pid is `dead` only while that
witness returns a live identity.

`lanes` is a list, sorted by lane, of `{lane, state, reason}` and no other
keys. It is present only when `user_root` was passed and the lease read
produced records. It is omitted on the compatibility path and when the
binding file or the lease preflight fails closed. Each `lane` string is
canonicalized, then redacted, then truncated to 63 characters, in that order.
A value that contains a line break is dropped from the list rather than
joined into one line. No row carries a pid, ticks, boot id, namespace,
`claim_id`, or `gen`. At most 256 rows.

The top-level state is `dead` only when at least one lease is readable, every
lane ref is readable, and every readable lease judged `dead`. The reason is
`writer_absent` when any of those rows is `writer_absent`; otherwise
`writer_replaced`. Any unreadable lane ref, any `unknown` lane, or an empty
lease set keeps the top-level state `unknown`. Reason order when the
top-level state is `unknown` and the binding file was readable: an
unreadable sibling uses `unreadable_lease`; else `identity_unavailable` if
any row has it; else `binding_scope_mismatch`; else
`no_bound_liveness_source`; else `writer_bound`. A missing binding file is
an empty map, so today's reason remains `no_bound_liveness_source` until a
matching record exists. A malformed or unsafe file is top-level `unknown` /
`bindings_unavailable` with `lanes` omitted and the `leases` counts kept.
Other observations stay visible. Returned text never includes file bytes,
paths, or exception messages.

`dead` does not start a component, clear a pause, or change the planner.
Between resume turns no bound pid is alive, so a lane whose last turn exited
is `dead` until the next `created_child` publishes a new identity. That is
the process fact, not a restart command.

### Implementing paths

The contract is implemented in:

- `aegis_core/team_writer_binding.py` (`bind`, the closed reader, the
  per-lane judge). Each function stays at most 100 lines. The module stays
  at most 1000.
- `aegis_core/team_supervisor_observe.py`, calling the judge. The default
  `user_root=None` path stays on today's row.
- `tools/hierarchy_launcher.py`, the `created_child` call and
  `bind_writer_process`. That helper stays at most 100 lines. `run_start` is
  unchanged.
- `tests/unit/core/test_team_writer_binding.py`.
- `tests/unit/core/test_team_supervisor_observe.py`, for the `user_root`
  cases. Tests that omit `user_root` keep the current assertions, including
  `test_no_lease_state_proves_writer_dead` and
  `test_real_lease_records_never_prove_liveness`.

Leave `aegis_core/team.py`, `aegis_cli/team.py`, `tools/hierarchy_team.py`,
and the pinned hierarchy tools untouched. The public readers in
`aegis_core/kernel_identity.py` own the `/proc` start-ticks, boot-ID and
PID-namespace parsers. Writer binding, supervisor start and MCP queue-role
adapters retain their own refusal codes and patched attributes; queue session
names remain `boot_id-pid-start_ticks.json`. Do not import private starter
helpers or grow `team.py`.

Binding reads one scope before the lease and refuses `identity_unavailable`
if a second scope differs afterwards, preserving existing binding bytes.
Binding and starter share a nonblocking owner-directory flock: EACCES,
EAGAIN and EWOULDBLOCK map to `state_locked`, other acquisition errors to
`state_unavailable`. Unlock errors do not mask the result; each caller closes
its held directory descriptor on exit.

Tests patch `team_writer_binding` and `team_supervisor_observe` attributes.
They do not patch `os.open` or `builtins`. Descriptor, symlink, and mode
cases use the existing `make_store` and `symlink_or_skip` skips. The
unsupported path monkeypatches the module's `descriptor_supported` and
asserts `unsupported_platform` without opening a home. Lease fixtures patch the binding module's selected-lane read, or a repository
created inside `tmp_path`. They do not read the product checkout's git
history. Every descriptor is closed on the success path and on the path
where a later constructor raises, using the confined helpers' close rather
than a bare `os.fdopen`.

### Caller and failure matrix

| caller | condition | result |
| --- | --- | --- |
| `bind` | platform lacks dir fd or `O_NOFOLLOW` | `unsupported_platform`, no write |
| `bind` | `descriptor_supported` monkeypatched false | same, and no home open |
| `bind` | lane fails `valid_lane` | `invalid_lane`, no write |
| `bind` | relative, empty, NUL, or non-absolute root | `state_unavailable`, no write |
| `bind` | config directory missing | `state_unavailable`, directory not created |
| `bind` | ancestor symlink, or ancestor renamed after the directory fd is held | read and write stay on the held fd; a swapped-away path is not followed |
| `bind` | leaf symlink, group-writable directory or leaf, wrong owner | `state_unavailable`, bytes kept |
| `bind` | second `bind` while the flock is held | `state_locked`; a retry after release publishes |
| `bind` | two lanes at once | both records present after the lock serializes them |
| `bind` | malformed, duplicate key, wrong version, or over 68379 bytes | `state_unavailable` before parse, bytes kept |
| `bind` | git error, unreadable lease, or no lease for the lane | `lease_unavailable`, no write |
| `bind` | workspace identity changes across the git read | `lease_unavailable`, no write |
| `bind` | boot, namespace, or self `/proc` unreadable | `identity_unavailable`, no write |
| `bind` | pid already absent or a zombie | `identity_unavailable`, no write |
| `bind` | another live pid holds the lane in this boot and namespace | `identity_ambiguous`, bytes kept |
| `bind` | same live pid, `gen` advanced by renew | `ok`, record stores the new `gen` |
| `bind` | identical record already stored | `ok`, equivalent bytes |
| `bind` | publish raises | previous complete bytes kept; every fd closed |
| `created_child` | `bind` refuses, raises, or the verified source cannot supply it | stop and reap through retained custody; resume returns code 2 with a typed refusal; unconfirmed exit retains admission evidence; spawn is not reported as no-child |
| `created_child` | plan discovery proves no plan | no binding read or write; the child continues |
| `created_child` | plan discovery is indeterminate | typed `state_unavailable`; no binding read or write; this launch's child is stopped |
| `created_child` | governing plan is malformed, foreign, or conflicts with the local plan | same typed refusal before owner-home access |
| `created_child` | verified source needs a lazy import, including after a lock retry | guard admits only the verified `aegis_core` source; ambient copies never run |
| `resume_locked` | code-3 worker returns a validated binding reason | `resumed_unread` record retains that fixed reason; arbitrary or multiline text is omitted |
| `observe` | `user_root` omitted | today's row; binding reader not called |
| `observe` | home set, no file | `unknown` / `no_bound_liveness_source`; `leases` unchanged |
| `observe` | matching record, pid absent, self witness live | `dead` / `writer_absent` |
| `observe` | matching record, ticks differ | `dead` / `writer_replaced` |
| `observe` | matching record, same ticks | `unknown` / `writer_bound` |
| `observe` | boot or namespace differs | `unknown` / `binding_scope_mismatch`; that pid is not probed |
| `observe` | `claim_id` or `gen` differs | `unknown` / `no_bound_liveness_source` |
| `observe` | no lease, file has a leftover record | leftover ignored; `unknown` |
| `observe` | expired lease still stored, matching dead pid | `dead` (expiry is not itself death; a live match stays `writer_bound`) |
| `observe` | one unreadable lane ref beside a dead lane | top-level `unknown` / `unreadable_lease` |
| `observe` | self witness missing | `unknown` / `identity_unavailable`, including when the recorded pid is gone |
| `observe` | binding file unsafe or malformed | `unknown` / `bindings_unavailable`; disk, usage, capacity, and audit still returned; no input echoed |
| `observe` | multi-line lane text | row omitted, not joined |
| `observe` | `user_root` set | workspace bytes and binding bytes unchanged; fds closed |
| claim, renew, `run_start`, `start_loop` | any | no reference to `team_writer_binding` |
