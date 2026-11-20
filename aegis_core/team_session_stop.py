"""Session stop state machine over injected host and launch-record ports.

Missing pidfds and ENOSYS refuse before signal intent (ROUND-1b ruling).
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import uuid

from aegis_core import kernel_identity
import select
import signal
import time
from aegis_core.team_session_census import (
    SessionRefused,
    UnsupportedPlatform,
    CustodyBusy,
    PidNamespaceUnavailable,
    PidfdUnavailable,
    CustodyUnavailable,
    CensusUnavailable,
    LaunchRecordLimit,
    CustodyExitUnproven,
    guarded,
    require,
    text,
    integer,
    safe_path,
    quoted,
    safe_reason,
    MAX_RECORDS,
    ENDPOINT_NAMESPACE_CHANGED,
    MAX_NAMESPACE_DEPTH,
    MAX_NAMESPACE_MANIFEST,
    PID_NAMESPACE_REFUSAL,
    CURRENT_PID_NAMESPACE,
    PIDFD_REFUSAL,
    OWNING_CHAIN_REFUSAL,
    KILL_WAIT_SECONDS,
    POLL_SECONDS,
    STOP_EXIT_PROOFS,
    STOP_COVERAGE,
    ROOT_STOP,
    MAILBOX_WAKE_PENDING,
    CLEANUP_BINDING_CHANGED,
    NO_EXPECTED_BINDING,
    STATUS_SCHEMA,
    ProcessSnapshot,
    ProcessObservation,
    ProcessIdentity,
    PROCESS_IDENTITY_FIELDS,
    STORED_PROCESS_FIELDS,
    IdentityWitness,
    StoredProcess,
    ProcessCensus,
    binding_identity,
    metadata_json,
    process_identity,
    remember_census_identity,
    running_pid_namespace,
    same_process_identity,
    validate_pid_namespace,
    SessionCensus,
)
from aegis_core.team_session_custody import CustodyRuntime, StopCustody, custody_instance


@dataclass(frozen=True)
class StopPorts:
    """Trusted adapter callbacks; profile_mode reads through the adapter's confined store.

    bound_session(launches, endpoint, identifier, action) returns (binding, profile).
    profile_mode(profile) returns the validated profile mode or None for absence.
    The launch adapter owns resolve/binding/new_id/record/refuse and its Mailbox.
    """
    bound_session: object
    profile_mode: object
    native_host: str
    process_rows: object = None

class StopRuntime(CustodyRuntime):
    def __init__(self, hosts, *, system=None, signals=None, clock=None, ports=None, identity=None, roles=None):
        super().__init__(hosts, system=system, signals=signals, clock=clock, ports=ports, identity=identity, roles=roles)

    def bound_session(self, launches, endpoint, identifier, action):
        require(self.ports is not None and callable(self.ports.bound_session))
        return self.ports.bound_session(launches, endpoint, identifier, action)

    @guarded
    def record_outcome(self, launches, endpoint, identifier, action, state, **details):
        """Successful records retain their shape; failed records carry a fixed envelope."""
        if state in ('stop_failed', 'refused'):
            error = details.get('error')
            refused = (PidNamespaceUnavailable() if error == PID_NAMESPACE_REFUSAL else
                       PidfdUnavailable() if error == PIDFD_REFUSAL else
                       CensusUnavailable() if details.get('argv_boundaries') == 'unproven' else
                       SessionRefused())
            details.update(code=refused.code, reason=refused.reason, next_action=refused.next_action)
        return launches.record(endpoint, identifier, action, state, **details)


    @guarded
    def persist_custody(self, observed, proposed=None):
        if observed is not None and 'custody' in observed:
            if observed.get('custody_error'):
                raise CustodyUnavailable(observed['custody_error'])
            try:
                observed['custody'].save(observed, observed['attempted'] if proposed is None else proposed)
                observed['checkpoint_pending'] = False
            except PidNamespaceUnavailable:
                raise
            except (OSError, ValueError) as exc:
                observed['custody_error'] = 'stop custody unavailable: ' + safe_reason(exc)
                raise CustodyUnavailable(observed['custody_error']) from exc

    @guarded
    def latch_blocked(self, observed, pid, identity_lost=False):
        """A new latch is a durable transition, not a deferred end-of-loop bookkeeping update."""
        changed = pid not in observed['blocked'] or (identity_lost and pid not in observed['identity_lost'])
        observed['blocked'].add(pid)
        if identity_lost:
            observed['identity_lost'].add(pid)
        if changed:
            observed['checkpoint_pending'] = True
            self.persist_custody(observed)

    @guarded
    def resolve_process(self, observed, pid, proof):
        self.require_pid_namespace(observed.get('pid_namespace'))
        changed = observed['resolved'].get(pid) != proof
        observed['resolved'][pid] = proof
        observed['unresolved'].pop(pid, None)
        if changed:
            observed['checkpoint_pending'] = True
            if pid in observed['blocked']:
                self.persist_custody(observed)

    @guarded
    def original_signal_chain(self, chain, observed, for_open=False):
        if any(observed['candidates'].get(row.pid) is None or
               row.pid in observed['blocked'] and (not for_open or index > 0)
               for index, row in enumerate(chain)):
            self.unresolved(observed, chain[0].pid, 'before_signal', 'owning_chain_unverified')
            observed['chain_refusal'] = True
            return None
        return [observed['candidates'][row.pid] for row in chain]

    def cancel_unsent_intent(self, state, target, attempted):
        if state is not None and target.pid not in (attempted or ()):
            if target.pid in state.get('possible_attempts', ()):
                state['possible_attempts'].discard(target.pid)
                state['checkpoint_pending'] = True

    def validate_signal_chain(self, chain, namespace, boundaries, session, host, unowned, retained, state, opened, attempted):
        target = chain[0]
        self.require_pid_namespace(namespace)
        if self.original_signal_chain(chain, state) is None:
            self.cancel_unsent_intent(state, target, attempted)
            return False
        for index in reversed(range(len(chain))):
            expected = chain[index]
            parent = chain[index + 1].pid if index + 1 < len(chain) else None
            observation = self.read_process(expected.pid, boundaries)
            result = self.process_state(expected, observation, boundaries, session, host, unowned, parent is None and (not retained), parent, retained)
            if result != 'authorized':
                self.cancel_unsent_intent(state, target, attempted)
            self.note_identity_loss(expected, observation, state)
            if expected.pid in state['blocked']:
                self.original_signal_chain(chain, state)
                self.cancel_unsent_intent(state, target, attempted)
                return False
            if state is not None and self.numeric_absence_blocked(state, expected.pid) and (observation.kind == 'CONFIRMED_ABSENT'):
                result = 'unavailable'
            if result != 'authorized' or (state is not None and target.pid in state['blocked']):
                if state is not None:
                    if result == 'gone' and expected.pid == target.pid:
                        self.resolve_process(state, target.pid, observation.proof or 'matching_birth_zombie')
                    else:
                        reason = 'evidence_unavailable' if result == 'unavailable' else 'instance_or_parent_changed'
                        self.unresolved(state, target.pid, 'before_signal', reason)
                        if result == 'changed':
                            self.latch_blocked(state, target.pid)
                    if state.get('checkpoint_pending', True):
                        self.persist_custody(state)
                return False
            if not self.signal_command_authorized(expected, observation, boundaries, session, host):
                self.cancel_unsent_intent(state, target, attempted)
                if state is not None:
                    self.unresolved(state, target.pid, 'before_signal', 'signal_command_line_not_authorized')
                    state['checkpoint_pending'] = True
                    self.persist_custody(state)
                return False
            if expected.pid in opened:
                opened[expected.pid]['verified'] = True
            if parent is not None and self.selects_other_session(observation.snapshot.argv, session):
                if state is not None:
                    self.cancel_unsent_intent(state, target, attempted)
                    self.unresolved(state, target.pid, 'before_signal', 'descendant_selection_ambiguous')
                    if state.get('checkpoint_pending', True):
                        self.persist_custody(state)
                return False
        return True

    @guarded
    def signal_process(self, chain, number, boundaries, session, host, unowned, retained=False, observed=None, attempted=None):
        state = observed
        namespace = state.get('pid_namespace') if state is not None else None
        self.require_pid_namespace(namespace)
        chain = self.original_signal_chain(chain, state, for_open=True)
        if chain is None:
            return False
        target, opened = (chain[0], {})
        if state is not None and any((row.pid in state.get('excluded', ()) for row in chain)):
            self.unresolved(state, target.pid, 'before_signal', 'ancestor_excluded')
            return False
        try:
            for expected in chain:
                kept = state['handles'].get(expected.pid) if state is not None else None
                if kept is not None:
                    opened[expected.pid] = kept
                elif callable(getattr(self.os, 'pidfd_open', None)):
                    try:
                        opened[expected.pid] = {'fd': self.os.pidfd_open(expected.pid), 'verified': False}
                    except OSError as exc:
                        if exc.errno == errno.ESRCH:
                            self.require_pid_namespace(namespace)
                            if state is not None:
                                if expected.pid == target.pid:
                                    if self.numeric_absence_blocked(state, target.pid):
                                        self.unresolved(state, target.pid, 'before_signal', 'original_instance_unresolved_after_numeric_ESRCH')
                                    else:
                                        self.resolve_process(state, target.pid, 'qualified_namespace_ESRCH')
                                else:
                                    self.unresolved(state, target.pid, 'before_signal', 'parent_instance_absent')
                            return False
                        if exc.errno != errno.ESRCH:
                            self.unresolved(state, target.pid, 'before_signal', 'pidfd_unavailable')
                            raise PidfdUnavailable(PIDFD_REFUSAL) from None
            if target.pid not in opened or not callable(getattr(self.signal, 'pidfd_send_signal', None)):
                self.unresolved(state, target.pid, 'before_signal', 'pidfd_delivery_unavailable')
                raise PidfdUnavailable(PIDFD_REFUSAL)
            if state is not None and target.pid in state['blocked']:
                self.unresolved(state, target.pid, 'before_signal', 'original_instance_blocked')
                return False
            if state is not None:
                state.setdefault('possible_attempts', set()).add(target.pid)
                self.persist_custody(state, set(attempted or ()) | {target.pid})
                state['custody'].check_namespace()
            if not self.validate_signal_chain(chain, namespace, boundaries, session, host, unowned, retained, state, opened, attempted):
                return False
            handle = opened.get(target.pid)
            if state is not None and handle is not None:
                state['handles'][target.pid] = handle
            if state is not None:
                state['unresolved'].pop(target.pid, None)
                state.get('recovered', set()).discard(target.pid)
            if state is not None and state.get('endpoint_fence') is not None:
                state['endpoint_fence'].check()
                if not self.validate_signal_chain(chain, namespace, boundaries, session, host, unowned, retained, state, opened, attempted):
                    return False
            if attempted is not None:
                attempted.add(target.pid)
            try:
                self.signal.pidfd_send_signal(handle['fd'], number)
            except OSError as exc:
                if handle is not None and (not isinstance(exc, ProcessLookupError)):
                    self.unresolved(state, target.pid, 'signal', 'pidfd_delivery_unavailable')
                    raise PidfdUnavailable(PIDFD_REFUSAL) from None
                raise
            return 'sent'
        except ProcessLookupError:
            self.require_pid_namespace(namespace)
            if state is not None:
                self.resolve_process(state, target.pid, 'signal_ESRCH')
            return False
        except PermissionError as exc:
            if state is not None:
                self.unresolved(state, target.pid, 'signal', 'signal_denied: ' + safe_reason(exc))
            return 'denied'
        finally:
            for pid, handle in opened.items():
                if state is None or state['handles'].get(pid) is not handle:
                    self.os.close(handle['fd'])

    @guarded
    def remember_retired_group(self, observed, entry):
        facts = entry['snapshot'] if entry['snapshot'] is not None else entry['partial']
        group = facts.get('pgid')
        if group and (entry['snapshot'] is not None or custody_instance(entry) in observed.get('group_candidates', ())):
            self.retain_group(observed, group)

    @guarded
    def retain_group(self, observed, group):
        groups = observed.setdefault('owned_groups', set())
        if group not in groups:
            require(len(groups) < MAX_RECORDS, 'stop custody exceeds group limit')
            groups.add(group)

    @guarded
    def remember_candidate_groups(self, observed):
        for pid, row in observed['candidates'].items():
            partial = observed.get('initial_unavailable', {}).get(pid, {})
            if row is None:
                birth = partial.get('start_time') if partial.get('coherent_birth') else None
                if (pid, birth) not in observed.get('group_candidates', ()):
                    continue
            group = row.pgid if row is not None else partial.get('pgid')
            if type(group) is int and group > 0:
                self.retain_group(observed, group)

    @guarded
    def latch_census_replacements(self, observed):
        """Filtered/settled census rows retain negative birth witnesses, never signal authority."""
        if observed['argv_boundaries'] != 'proven':
            return
        for pid, expected in observed['candidates'].items():
            if pid in observed['resolved']:
                continue
            partial = observed['initial_unavailable'].get(pid, {})
            birth = expected.start_time if expected is not None else partial.get('start_time') if partial.get('coherent_birth') else None
            changed = birth is not None and any((other != birth for other in observed.get('census_births', {}).get(pid, ())))
            for current in observed.get('census_identities', {}).get(pid, ()):
                facts = expected._asdict() if expected is not None else partial
                changed = changed or birth is not None and any((facts.get(key) is not None and getattr(current, key) is not None and (facts[key] != getattr(current, key)) for key in ('uid', 'euid')))
            if changed:
                self.unresolved(observed, pid, 'census', 'original_instance_replaced')
                self.latch_blocked(observed, pid, True)

    @guarded
    def custody_entry(self, observed, pid, attempted):
        row = observed['candidates'][pid]
        return dict(pid=pid, snapshot=StopCustody.encode(row._asdict()) if row is not None else None, partial=StopCustody.encode(observed['initial_unavailable'].get(pid, {})), attempted=pid in attempted, blocked=pid in observed['blocked'], identity_lost=pid in observed['identity_lost'], resolved=observed['resolved'].get(pid))

    @guarded
    def advance_resolved_instances(self, observed, fresh):
        """Keep fresh uncertainty separate from an exited instance's resolution."""
        if fresh['argv_boundaries'] != 'proven':
            return
        for pid, row in list(observed['candidates'].items()):
            if pid not in observed['resolved']:
                continue
            entry = self.custody_entry(observed, pid, observed.get('attempted', set()) | observed.get('possible_attempts', set()))
            current = fresh['census'].get(pid)
            partial = fresh.get('initial_unavailable', {}).get(pid, {})
            replacement = current.start_time if current is not None else partial.get('start_time') if partial.get('coherent_birth') else None
            birth = custody_instance(entry)[1]
            if birth is None and replacement is None or replacement == birth or (replacement is None and pid not in fresh['candidates']):
                if pid in fresh['candidates']:
                    observed['coverage'] = 'session_instance_unresolved_after_exit'
                    self.unresolved(observed, pid, 'census', 'fresh_session_instance_after_exit')
                continue
            if birth is None and replacement is not None:
                entry.update(identity_lost=True, blocked=True)
            observed.setdefault('retired_instances', {})[custody_instance(entry)] = entry
            self.remember_retired_group(observed, entry)
            if entry['attempted']:
                observed.setdefault('historical_pids', set()).add(pid)
            handle = observed['handles'].pop(pid, None)
            if handle is not None:
                self.os.close(handle['fd'])
            for key in ('attempted', 'possible_attempts', 'recovered'):
                observed[key] = observed.get(key, set()) - {pid}
            for key in ('blocked', 'identity_lost'):
                observed[key].discard(pid)
            for key in ('candidates', 'resolved', 'unresolved', 'initial_unavailable'):
                observed[key].pop(pid, None)
            if pid in fresh['candidates']:
                observed['candidates'][pid] = fresh['candidates'][pid]
                if pid in fresh.get('initial_unavailable', {}):
                    observed['initial_unavailable'][pid] = fresh['initial_unavailable'][pid]
                if pid in fresh.get('unresolved', {}):
                    observed['unresolved'][pid] = fresh['unresolved'][pid]
            observed['checkpoint_pending'] = True

    @guarded
    def refresh_stop_scope(self, observed, session, host, unowned):
        """Refresh discovery without replacing original-instance evidence or reviving resolved PIDs."""
        self.require_pid_namespace(observed.get('pid_namespace'))
        fresh = {}
        found = self.session_processes(session, observed['excluded'], host, unowned, fresh)
        self.require_pid_namespace(observed.get('pid_namespace'))
        observed['census'] = fresh['census']
        observed['argv_boundaries'] = fresh['argv_boundaries']
        observed['census_complete'] = fresh['census_complete']
        observed['census_births'] = fresh['census_births']
        observed['census_identities'] = fresh['census_identities']
        self.advance_resolved_instances(observed, fresh)
        self.latch_census_replacements(observed)
        for pid, expected in observed['candidates'].items():
            if pid in observed['resolved']:
                if pid in fresh['candidates']:
                    observed['coverage'] = 'session_instance_unresolved_after_exit'
                    observed['checkpoint_pending'] = True
                    self.unresolved(observed, pid, 'census', 'fresh_session_instance_after_exit')
                continue
            current = fresh['census'].get(pid)
            missing = fresh['initial_unavailable'].get(pid, {})
            if expected is None:
                initial = observed['initial_unavailable'].get(pid, {})
                birth = initial.get('start_time') if initial.get('coherent_birth') else None
                new_birth = current.start_time if current is not None and fresh['argv_boundaries'] == 'proven' else missing.get('start_time') if missing.get('coherent_birth') else None
                if birth and new_birth and (birth != new_birth):
                    self.latch_blocked(observed, pid, True)
            elif current is not None:
                observation = ProcessObservation('PRESENT', pid, current)
                self.note_identity_loss(expected, observation, observed)
                if self.process_state(expected, observation, fresh['argv_boundaries'], session, host, unowned, require_host=False, retained=True) == 'changed':
                    self.latch_blocked(observed, pid)
            elif missing:
                self.note_identity_loss(expected, ProcessObservation('UNAVAILABLE', pid, partial=missing), observed)
        for pid, row in fresh['candidates'].items():
            if pid not in observed['candidates']:
                observed['candidates'][pid] = row
                observed['checkpoint_pending'] = True
                if pid in fresh['initial_unavailable']:
                    observed['initial_unavailable'][pid] = fresh['initial_unavailable'][pid]
                if pid in fresh['unresolved']:
                    observed['unresolved'][pid] = fresh['unresolved'][pid]
        if fresh.get('coverage'):
            observed['coverage'] = fresh['coverage']
        linked = observed.setdefault('group_candidates', set())
        for key in fresh.get('group_candidates', ()):
            require(key in linked or len(linked) < MAX_RECORDS, 'stop custody exceeds evidence limit')
            linked.add(key)
        self.remember_candidate_groups(fresh)
        for group in fresh.get('owned_groups', ()):
            self.retain_group(observed, group)
        return found

    @guarded
    def signal_all(self, found, number, observed, session, host, unowned, attempted=None, new_only=False):
        census, boundaries = (observed['census'], observed['argv_boundaries'])
        attempted = set() if attempted is None else attempted
        owners = {pid for pid, _ in found if pid not in observed['resolved']}
        groups = observed.setdefault('owned_groups', set())
        self.remember_candidate_groups(observed)
        targets = [[census[pid]] for pid in owners]
        for member in census.values():
            if member.state.startswith('Z') or member.pid in observed['resolved']:
                continue
            if member.pid not in owners and member.pgid in groups:
                chain, verdict = self.descendant_lineage(member, census, owners, session)
                if verdict == 'OTHER':
                    observed.setdefault('spared_descendants', set()).add(member.pid)
                if chain:
                    if verdict == 'UNKNOWN':
                        self.retain_candidate(observed, member, 'descendant_parent_unavailable')
                    elif verdict == 'HOLD':
                        reason = self.GRAMMAR_OVERSIZE if self.grammar_uncertain(member.argv) else 'descendant_selection_ambiguous'
                        self.retain_candidate(observed, member, reason)
                    else:
                        targets.append(chain)
        for chain in targets:
            pid = chain[0].pid
            if pid not in observed['candidates']:
                observed['candidates'][pid] = chain[0]
                observed['checkpoint_pending'] = True
        for chain in sorted(targets, key=lambda rows: self.process_depth(rows[0], census), reverse=True):
            if number is None or chain[0].pid in observed['resolved']:
                continue
            if observed['candidates'][chain[0].pid] is None:
                continue
            if new_only and chain[0].pid in attempted:
                continue
            self.signal_process(chain, number, boundaries, session, host, unowned, observed=observed, attempted=attempted)
        return attempted

    @guarded
    def signal_retained(self, pids, number, observed, session, host, unowned, skip=()):
        if observed['argv_boundaries'] != 'proven':
            return
        for pid in sorted(pids):
            if pid in skip:
                continue
            expected = observed['candidates'][pid]
            if pid not in observed['resolved'] and (not self.original_exit(expected, observed)):
                if pid in observed.get('recovered', ()):
                    census = observed['census']
                    owners = {row.pid for row in census.values() if self.owns_process(row, session, host, 'proven')}
                    member = census.get(pid)
                    chain = self.descendant_chain(member, census, owners, session) if member is not None else []
                    if not chain or chain[-1].pid not in owners:
                        self.unresolved(observed, pid, 'recovery', 'fresh_ownership_unproven')
                        continue
                    self.signal_process(chain, number, 'proven', session, host, unowned, observed=observed, attempted=pids)
                    continue
                self.signal_process([expected], number, observed['argv_boundaries'], session, host, unowned, retained=True, observed=observed, attempted=pids)

    @guarded
    def gone_within(self, session, excluded, pids, seconds, host, observed, unowned):
        self.require_pid_namespace(observed.get('pid_namespace'))
        self.remember_candidate_groups(observed)
        deadline = self.time.monotonic() + seconds
        while True:
            for pid, expected in observed['candidates'].items():
                if pid in excluded or pid in observed['resolved']:
                    continue
                if expected is None:
                    observation = self.read_process(pid, observed['argv_boundaries'])
                    initial = observed['initial_unavailable'].get(pid, {})
                    birth = initial.get('start_time') if initial.get('coherent_birth') else None
                    if observation.kind == 'PRESENT' and observed['argv_boundaries'] == 'proven':
                        current = {'start_time': observation.snapshot.start_time, 'coherent_birth': True, 'uid': observation.snapshot.uid, 'euid': observation.snapshot.euid, 'exit_observed': observation.snapshot.state.startswith('Z')}
                    else:
                        current = observation.partial or {}
                    current_birth = current.get('start_time') if current.get('coherent_birth') else None
                    changed = birth is not None and current_birth is not None and (current_birth != birth or any(initial.get(key) is not None and current.get(key) is not None and initial[key] != current[key] for key in ('uid', 'euid')))
                    if changed and pid not in observed['identity_lost']:
                        self.latch_blocked(observed, pid, True)
                    uids_match = all(initial.get(key) is None or current.get(key) == initial[key] for key in ('uid', 'euid'))
                    if birth and current_birth == birth and current.get('exit_observed') and uids_match:
                        self.resolve_process(observed, pid, 'matching_partial_birth_zombie')
                        result = 'gone'
                    elif observation.kind == 'CONFIRMED_ABSENT' and (not self.numeric_absence_blocked(observed, pid)):
                        self.resolve_process(observed, pid, observation.proof)
                        result = 'gone'
                    else:
                        result = 'unavailable'
                else:
                    result = self.retained_state(expected, observed['argv_boundaries'], session, host, unowned, observed)
                if result == 'gone':
                    self.resolve_process(observed, pid, observed['resolved'].get(pid, 'confirmed_instance_exit'))
                else:
                    self.unresolved(observed, pid, 'after_signal' if pid in pids else 'before_signal', 'evidence_unavailable' if result == 'unavailable' else 'original_instance_live_or_changed')
                    if result == 'changed':
                        self.latch_blocked(observed, pid)
            groups_exited = self.retained_groups_exited(observed)
            if len(observed['resolved']) == len(observed['candidates']):
                if groups_exited and (not observed.get('coverage')) and (not observed.get('admission_unknown')):
                    return True
            if not pids or self.time.monotonic() >= deadline:
                return False
            self.time.sleep(POLL_SECONDS)

    @guarded
    def expected_stop_binding(self, raw):
        require(isinstance(raw, str) and len(raw) <= 4096 and raw.isascii(), 'invalid expected stop binding')
        try:
            value = metadata_json(raw.encode('ascii'), 'launch record')
            if value is not None:
                StopCustody.exact_fields(value, ('host', 'session', 'generation'))
                text(value['host'], 'host', 128)
                text(value['session'], 'session', 256)
                integer(value['generation'], 'generation', maximum=2 ** 31 - 1)
            return value
        except (ValueError, KeyError, RecursionError):
            raise SessionRefused('invalid expected stop binding') from None

    @guarded
    def stop(self, launches, endpoint, grace, expected_binding=NO_EXPECTED_BINDING):
        self.require_pid_namespace()
        if not callable(getattr(self.os, 'pidfd_open', None)) or not callable(getattr(self.signal, 'pidfd_send_signal', None)):
            raise PidfdUnavailable()
        endpoint = launches.resolve(endpoint)
        identifier = launches.new_id()
        if not (type(grace) is int and 0 <= grace <= 60):
            launches.refuse(endpoint, identifier, 'stop', 'invalid grace_seconds')
        if expected_binding is NO_EXPECTED_BINDING:
            self.stop_checks(launches, endpoint, identifier)
        known = binding_identity(launches.binding(endpoint)) or {}
        with self.recorded_endpoint_lock(launches, endpoint, identifier, 'stop', known) as fence:
            if expected_binding is not NO_EXPECTED_BINDING:
                current = binding_identity(launches.binding(endpoint))
                if current != expected_binding:
                    launches.refuse(endpoint, identifier, 'stop', CLEANUP_BINDING_CHANGED, **current or {})
            return self.stop_locked(launches, endpoint, grace, identifier, fence)

    @guarded
    def stop_locked(self, launches, endpoint, grace, identifier, fence):
        fence.check()
        known = self.stop_checks(launches, endpoint, identifier)
        unowned, observed = ([], {})
        try:
            retained = self.stop_custody(launches, endpoint, known, create=False).read()
            attempted = [entry['pid'] for entry, _, _ in retained[1] if entry['attempted']] if retained else []
            observed['journal_attempted'] = set(attempted)
            namespace = self.require_pid_namespace(retained[0].get('pid_namespace') if retained else CURRENT_PID_NAMESPACE, attempted)
            admitted = self.read_running_wake(launches.base, endpoint)
            if admitted is not None:
                self.require_pid_namespace(running_pid_namespace(admitted), attempted)
            excluded = self.ancestors()
            found = self.session_processes(known['session'], excluded, known['host'], unowned, observed)
            self.require_pid_namespace(namespace)
            observed['endpoint_fence'] = fence
            running = self.read_running_wake(launches.base, endpoint)
            if running is not None:
                require(running['binding'] == known, 'running wake belongs to another binding')
                if running['host_pid'] is None:
                    observed['admission_unknown'] = True
            if running is not None and running['host_pid'] is not None:
                self.retain_group(observed, running['host_pid'])
                pid = running['host_pid']
                current = observed['census'].get(pid)
                latest = ProcessObservation('PRESENT', pid, current) if current is not None else self.read_process(pid, observed['argv_boundaries'])
                if running['snapshot'] is None:
                    if latest.kind != 'CONFIRMED_ABSENT':
                        observed['candidates'][pid] = None
                        observed['initial_unavailable'][pid] = {}
                        self.unresolved(observed, pid, 'admission', 'admitted_child_identity_unavailable')
                else:
                    facts = StopCustody.decode(running['snapshot'])
                    expected = ProcessIdentity(**{key: facts[key] for key in PROCESS_IDENTITY_FIELDS})
                    observed['running_expected'], observed['running_observation'] = (expected, latest)
        except PidNamespaceUnavailable as exc:
            return (3, self.record_outcome(launches, endpoint, identifier, 'stop', 'stop_failed', **known, pids=exc.pids, error=PID_NAMESPACE_REFUSAL))
        except CustodyExitUnproven as exc:
            return (3, self.record_outcome(launches, endpoint, identifier, 'stop', 'stop_failed', **known, pids=exc.pids, error=safe_reason(exc)))
        except (OSError, ValueError) as exc:
            launches.refuse(endpoint, identifier, 'stop', safe_reason(exc), **known)
        if observed['argv_boundaries'] != 'proven':
            try:
                retained = self.stop_custody(launches, endpoint, known, create=False).read()
            except CustodyExitUnproven as exc:
                return (3, self.record_outcome(launches, endpoint, identifier, 'stop', 'stop_failed', **known, pids=sorted(set(exc.pids) | observed['journal_attempted']), error=safe_reason(exc)))
            except (OSError, ValueError) as exc:
                launches.refuse(endpoint, identifier, 'stop', safe_reason(exc), **known)
            attempted = sorted({entry['pid'] for entry, _, _ in retained[1] if entry['attempted']}) if retained else []
            marker = dict(pids=attempted, argv_boundaries='unproven', reason='argv_boundaries_unavailable', grace_seconds=grace, wake_marker_present=self.mailbox_wake_pending(launches.mailbox, endpoint), error='stop unsupported without proven argv boundaries; stop the host manually, preserve retained custody, and have the owner reconcile it before retrying on a supported system')
            if set(unowned) - set(attempted):
                marker['unowned_pids'] = sorted(set(unowned) - set(attempted))
            return (3, self.record_outcome(launches, endpoint, identifier, 'stop', 'stop_failed', **known, **marker))
        with self.stop_custody(launches, endpoint, known) as custody:
            fence.check()
            code, record = self.stop_owned(launches, endpoint, identifier, known, grace, custody, (excluded, unowned, observed, found))
        if code == 0 and running is not None:
            try:
                fence.check()
                self.clear_running_wake(launches.base, endpoint, running)
            except (ValueError, OSError):
                return (3, self.record_outcome(launches, endpoint, launches.new_id(), 'stop', 'stop_failed', **known, pids=record['pids'], error='running wake cleanup unavailable'))
        return (code, record)

    @guarded
    def stop_checks(self, launches, endpoint, identifier):
        """Pure preflight is repeated under the endpoint lock; only that fresh binding reaches effects."""
        known, profile = self.bound_session(launches, endpoint, identifier, 'stop')
        if self.endpoint_parts(endpoint)[1] == 'root':
            launches.refuse(endpoint, identifier, 'stop', ROOT_STOP, **known)
        if known['host'] == self.ports.native_host:
            launches.refuse(endpoint, identifier, 'stop', 'a native thread is stopped by its own app, not the launcher', **known)
        try:
            background = self.ports.profile_mode(profile) == 'background'
        except (ValueError, OSError, AttributeError) as exc:
            launches.refuse(endpoint, identifier, 'stop', safe_reason(exc), **known)
        if background:
            launches.refuse(endpoint, identifier, 'stop', "a background claude session stops through claude stop; use the wake tool's control", **known)
        return known

    @guarded
    def stop_owned(self, launches, endpoint, identifier, known, grace, custody, discovery):
        excluded, unowned, observed, found = discovery
        pids = set()
        marker = {'wake_marker_present': self.mailbox_wake_pending(launches.mailbox, endpoint), 'grace_seconds': grace}
        error = None
        try:
            observed.update(custody=custody, attempted=pids, excluded=excluded, checkpoint_pending=True)
            fresh = {key: dict(observed[key]) for key in ('candidates', 'initial_unavailable', 'unresolved')}
            fresh.update(argv_boundaries=observed['argv_boundaries'], census=observed['census'])
            custody.restore(observed, pids)
            expected = observed.get('running_expected')
            if expected is not None and (expected.pid, expected.start_time) not in observed.get('committed_exits', set()):
                require(expected.pid not in observed['resolved'], self.custody_refusal(launches.base, endpoint, 'running wake conflicts with committed process identity'))
                candidate = observed['candidates'].get(expected.pid)
                if candidate is None or not same_process_identity(expected, candidate):
                    current = observed['census'].get(expected.pid)
                    if expected.pid not in observed['blocked'] and current is not None and same_process_identity(expected, current) and self.owns_process(current, known['session'], known['host'], observed['argv_boundaries']):
                        observed['candidates'][expected.pid] = current
                    else:
                        observed['candidates'][expected.pid] = None
                        partial = observed['initial_unavailable'].setdefault(expected.pid, {})
                        partial.update(expected._asdict(), coherent_birth=True)
                self.unresolved(observed, expected.pid, 'admission', 'original_instance_pending')
                observed['checkpoint_pending'] = True
                latest = observed['running_observation']
                self.note_identity_loss(expected, latest, observed)
                if self.process_state(expected, latest, observed['argv_boundaries'], known['session'], known['host'], unowned, require_host=False, retained=True) == 'changed':
                    self.latch_blocked(observed, expected.pid)
            self.latch_census_replacements(observed)
            self.advance_resolved_instances(observed, fresh)
            pids = observed['attempted']
            if observed['argv_boundaries'] != 'proven':
                marker['argv_boundaries'] = 'unproven'
            if found:
                self.signal_all(found, None, observed, known['session'], known['host'], unowned, pids)
                found = self.refresh_stop_scope(observed, known['session'], known['host'], unowned)
                pids = observed['attempted']
                self.signal_all(found, self.signal.SIGTERM, observed, known['session'], known['host'], unowned, pids)
            elif pids:
                self.signal_retained(pids, self.signal.SIGTERM, observed, known['session'], known['host'], unowned)
            stopped = self.gone_within(known['session'], excluded, pids, grace, known['host'], observed, unowned)
            new_found = self.refresh_stop_scope(observed, known['session'], known['host'], unowned)
            pids = observed['attempted']
            self.signal_all(new_found, None, observed, known['session'], known['host'], unowned, pids)
            stopped = self.gone_within(known['session'], excluded, pids, 0, known['host'], observed, unowned)
            if not stopped:
                previous_attempts = set(pids)
                self.signal_all(new_found, self.signal.SIGTERM, observed, known['session'], known['host'], unowned, pids, new_only=True)
                if pids - previous_attempts:
                    stopped = self.gone_within(known['session'], excluded, pids, grace, known['host'], observed, unowned)
                    new_found = self.refresh_stop_scope(observed, known['session'], known['host'], unowned)
                    pids = observed['attempted']
                    self.signal_all(new_found, None, observed, known['session'], known['host'], unowned, pids)
                    stopped = self.gone_within(known['session'], excluded, pids, 0, known['host'], observed, unowned)
            if not stopped and pids:
                self.signal_retained(pids, self.signal.SIGKILL, observed, known['session'], known['host'], unowned)
                stopped = self.gone_within(known['session'], excluded, pids, KILL_WAIT_SECONDS, known['host'], observed, unowned)
                final_found = self.refresh_stop_scope(observed, known['session'], known['host'], unowned)
                pids = observed['attempted']
                self.signal_all(final_found, None, observed, known['session'], known['host'], unowned, pids)
                stopped = self.gone_within(known['session'], excluded, pids, 0, known['host'], observed, unowned)
            marker['wake_marker_present'] = self.mailbox_wake_pending(launches.mailbox, endpoint)
        except PidNamespaceUnavailable:
            observed['namespace_error'] = True
            error, stopped = (PID_NAMESPACE_REFUSAL, False)
        except PidfdUnavailable:
            error, stopped = (PIDFD_REFUSAL, False)
        except CustodyExitUnproven as exc:
            return (3, self.record_outcome(launches, endpoint, identifier, 'stop', 'stop_failed', **known, pids=sorted(pids | set(exc.pids) | observed.get('journal_attempted', set())), error=safe_reason(exc)))
        except (OSError, ValueError) as exc:
            if not pids and (not observed.get('historical_pids')):
                launches.refuse(endpoint, identifier, 'stop', safe_reason(exc), **known)
            error, stopped = (safe_reason(exc), False)
            for pid in observed.get('candidates', {}):
                if pid not in observed['resolved']:
                    self.unresolved(observed, pid, 'operation_error', 'evidence_unavailable: ' + safe_reason(exc))
        finally:
            for handle in observed.get('handles', {}).values():
                self.os.close(handle['fd'])
        return self.finish_stop(launches, endpoint, identifier, known, grace, custody, observed, unowned, pids, marker, error, stopped)

    @guarded
    def finish_stop(self, launches, endpoint, identifier, known, grace, custody, observed, unowned, pids, marker, error, stopped):
        unsupported_empty = observed['argv_boundaries'] != 'proven' and (not observed['candidates']) and (not pids) and (not observed.get('historical_pids'))
        if observed['argv_boundaries'] != 'proven':
            marker['argv_boundaries'] = 'unproven'
            if error is None:
                error = 'stop unsupported without proven argv boundaries; stop the host manually, preserve retained custody, and have the owner reconcile it before retrying on a supported system'
        if observed.get('admission_unknown'):
            error = 'wake admission identity is unavailable; ' + self.running_wake_recovery(launches.base, endpoint)
        if not observed.get('namespace_error') and (not unsupported_empty) and (not stopped) and (not observed.get('custody_error')) and observed.get('checkpoint_pending', True) and (observed.get('owned_groups') or observed.get('candidates') or observed.get('coverage') or observed.get('retained_custody') or observed.get('retired_instances')):
            try:
                self.persist_custody(observed)
            except CustodyUnavailable as exc:
                error = safe_reason(exc)
        current_attempts = pids
        pids = pids | observed.get('historical_pids', set())
        spared = sorted(set(unowned) - pids)
        if spared:
            marker['unowned_pids'] = spared
        if observed.get('spared_descendants'):
            marker['spared_descendants'] = sorted(observed['spared_descendants'])
        if observed.get('possible_attempts', set()) - pids:
            marker['possible_pids'] = sorted(observed['possible_attempts'] - pids)
        if observed.get('unresolved'):
            marker['unresolved_pids'] = sorted(observed['unresolved'])
            marker['unresolved'] = [observed['unresolved'][pid] for pid in sorted(observed['unresolved'])]
        if observed.get('coverage'):
            marker['reason'] = observed['coverage']
        if observed.get('unresolved_groups'):
            marker['unresolved_groups'] = observed['unresolved_groups']
        if observed.get('resolved'):
            marker['absence_evidence'] = [{'pid': pid, 'proof': observed['resolved'][pid]} for pid in sorted(observed['resolved'])]
        for entry in observed.get('retired_instances', {}).values():
            marker.setdefault('absence_evidence', []).append({'pid': entry['pid'], 'proof': entry['resolved']})
        if pids:
            marker['identity_check_mode'] = 'start_time_recheck' if observed['numeric'] else 'pidfd'
        blocked = observed.get('blocked', set()) & observed.get('unresolved', {}).keys()
        try:
            self.require_pid_namespace(observed.get('pid_namespace'))
        except PidNamespaceUnavailable:
            observed['namespace_error'] = True
            error, stopped = (PID_NAMESPACE_REFUSAL, False)
        if observed.get('chain_refusal') and (not observed.get('namespace_error')):
            error, stopped = (OWNING_CHAIN_REFUSAL, False)
        if not stopped and blocked and (not observed.get('namespace_error')) and (not observed.get('chain_refusal')):
            cause = 'original process identity lost' if blocked & observed['identity_lost'] else 'original process identity blocked'
            guidance = self.custody_refusal(launches.base, endpoint, cause)
            error = error + '; ' + guidance if error else guidance
        if error is not None:
            marker['error'] = error
        if observed.get('namespace_error'):
            marker.pop('absence_evidence', None)
        state = 'stopped' if pids else 'not_running'
        if not stopped:
            state = 'stop_failed'
        record = self.record_outcome(launches, endpoint, identifier, 'stop', state, **known, pids=sorted(pids), **marker)
        if not observed.get('namespace_error') and (not unsupported_empty) and (not observed.get('custody_error')) and (stopped or observed.get('checkpoint_pending', True)) and (observed.get('owned_groups') or observed.get('candidates') or observed.get('coverage') or observed.get('retained_active') or observed.get('retired_instances')):
            try:
                custody.save(observed, current_attempts, active=not stopped)
            except PidNamespaceUnavailable:
                marker['error'] = PID_NAMESPACE_REFUSAL
                marker.pop('absence_evidence', None)
                return (3, self.record_outcome(launches, endpoint, launches.new_id(), 'stop', 'stop_failed', **known, pids=sorted(pids), **marker))
            except (OSError, ValueError) as exc:
                marker['error'] = 'stop custody unavailable: ' + safe_reason(exc)
                return (3, self.record_outcome(launches, endpoint, launches.new_id(), 'stop', 'stop_failed', **known, pids=sorted(pids), **marker))
        return (0 if stopped else 3, record)

    @guarded
    def status_endpoints(self, base):
        names = []
        try:
            with self.directory_descriptor(safe_path(base) / 'launches', verify=True) as directory:
                with os.scandir(directory) as entries:
                    for count, entry in enumerate(entries):
                        require(count < MAX_RECORDS)
                        info = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                        if not stat.S_ISDIR(info.st_mode):
                            continue
                        name = entry.name.replace('%2F', '/')
                        self.endpoint_parts(name)
                        names.append(name)
        except FileNotFoundError:
            return []
        return sorted(names)

    @guarded
    def status(self, launches, endpoint):
        if not self.launch_descriptor_capable():
            unknown = {
                'state': 'unknown', 'records': None, 'code': 'unsupported_platform',
                'reason': 'descriptor support unavailable',
                'next_action': {'actor': 'owner',
                                'command': 'use a host with descriptor support to inspect launch history'}}
            if endpoint is None:
                return 0, dict(schema=STATUS_SCHEMA, endpoints={}, **unknown)
            launches.mailbox.endpoint(endpoint)
            binding = binding_identity(launches.binding(endpoint))
            return 0, {'schema': STATUS_SCHEMA, 'endpoints': {endpoint: dict(binding=binding, **unknown)}}
        if endpoint is not None:
            launches.mailbox.endpoint(endpoint)
            names = [endpoint]
        else:
            names = self.status_endpoints(launches.base)
        rows = {}
        for name in names:
            binding = launches.binding(name)
            rows[name] = {'binding': None if binding is None else {key: binding[key] for key in ('host', 'session', 'generation')}, 'last': None, 'records': None}
            paths = []
            try:
                paths = self.launch_record_paths(launches.base, name)
                rows[name]['records'] = len(paths)
                if paths:
                    rows[name]['last'] = metadata_json(self.read_launch_record(launches.base, name, paths[-1].name), 'launch record')
            except (OSError, ValueError, UnicodeError, RecursionError) as exc:
                reasons = ('invalid launch record entry', 'launch record exceeds evidence limit', 'launch record changed or exceeds evidence limit', 'launch directory entry limit reached', 'launch directory changed while reading', 'launch directory unreadable', 'launch record limit reached', 'invalid launch record JSON')
                reason = 'launch record limit reached' if isinstance(exc, LaunchRecordLimit) else safe_reason(exc) if safe_reason(exc) in reasons else 'invalid launch record JSON' if paths and isinstance(exc, ValueError) else 'launch history unavailable'
                rows[name].update(state='unknown', error=reason, unreadable='launch history unavailable')
        return (0, {'schema': STATUS_SCHEMA, 'endpoints': rows})

__all__ = ['StopRuntime', 'StopPorts']
