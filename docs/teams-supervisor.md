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

- `writer_dead` is always `state: unknown`, with reason
  `no_bound_liveness_source`. The existing v1 lease schema has no writer process
  identity; a live or expired lease cannot establish life or death. Binding a
  writer to its lease is deferred to `SUPERVISOR-WRITER-LIVENESS`.
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
