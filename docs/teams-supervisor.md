# Supervisor profile

`supervisor` is a closed object on `aegis.team.profile/v1`. Resolution always
returns one, including when no file sets it. `aegis team config init` does not
write supervisor keys. Command flags cannot set any supervisor field.

This slice plans and reports. It does not start a component, and it does not
add an MCP tool. Lease `aegis team status` is unchanged.

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
an outstanding deadline. For initial 200s, max 600s and a 300s window, failures
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

`plan` returns `status: dry_run`, `starts_nothing`, `start` and `components`.
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
