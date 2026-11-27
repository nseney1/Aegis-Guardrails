"""Recorded process inputs exercise public census without a live process tree."""
from types import FunctionType, SimpleNamespace

import pytest

from aegis_core import team_host_registry as hosts
from aegis_core import team_session_census as census


class RecordedCensus(census.SessionCensus):
    def __init__(self, rows=(), boundaries="proven"):
        super().__init__(hosts, system=SimpleNamespace(geteuid=lambda: 1000))
        self.rows = list(rows)
        self.boundaries = boundaries
        self.namespace = {"device": 1, "inode": 2}

    def current_pid_namespace(self):
        return self.namespace

    def process_census(self, session):
        return census.ProcessCensus(self.rows, self.boundaries)


def row(pid=41, birth="123", argv=("codex", "exec", "resume", "session-a"), parent=1, group=41):
    return census.ProcessSnapshot(pid, group, "S", 1000, birth,
                                  b"\0".join(a.encode() for a in argv) + b"\0", argv, parent, 1000)


def test_scope_matches_legacy_for_recorded_processes():
    from tools import hierarchy_launcher as legacy
    rows = [row(), row(42, argv=("echo", "session-a")), row(43, argv=("codex", "exec", "resume", "other"))]
    core = RecordedCensus(rows)
    # Rebind only the OS/census boundaries of this isolated legacy function.
    # Its module, the shared OS module and every other test remain untouched.
    identity_os = SimpleNamespace(geteuid=lambda: 1000)
    bindings = dict(vars(legacy), require_pid_namespace=lambda: {"device": 1, "inode": 2},
                    process_census=lambda session: legacy.ProcessCensus(rows, "proven"),
                    os=identity_os, our_uid=FunctionType(legacy.our_uid.__code__, {'os': identity_os}))
    historical = FunctionType(legacy.session_processes.__code__, bindings, argdefs=legacy.session_processes.__defaults__)
    for excluded in (set(), {41}):
        assert core.session_processes("session-a", excluded, "codex-cli") == historical(
            "session-a", excluded, "codex-cli")


@pytest.mark.parametrize("argv", [("echo", "session-a"), ("codex", "exec", "resume", "other")])
def test_argv_must_prove_session(argv):
    core = RecordedCensus([row(argv=argv)])
    assert core.session_processes("session-a", set(), "codex-cli") == []


def test_namespace_unavailable_has_fixed_envelope_and_retry():
    core = RecordedCensus()
    core.namespace = None
    with pytest.raises(census.PidNamespaceUnavailable) as caught:
        core.require_pid_namespace()
    assert caught.value.code == "pid_namespace_unavailable"
    assert caught.value.reason and caught.value.next_action
    core.namespace = {"device": 1, "inode": 2}
    assert core.require_pid_namespace() == {"device": 1, "inode": 2}


def test_unproven_census_refuses_without_promoting_ps_identity():
    core = RecordedCensus([row()], "unproven")
    with pytest.raises(census.CensusUnavailable) as caught:
        core.session_processes("session-a", set(), "codex-cli")
    assert caught.value.code == "census_unavailable"


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":' + b'9' * 129 + b'}', b'[' * 3000])
def test_metadata_refuses_malformed_bytes_without_echo(raw):
    with pytest.raises(census.SessionRefused) as caught:
        census.metadata_json(raw, "launch record")
    assert caught.value.code == "invalid_evidence"
    assert str(caught.value) == caught.value.reason


def test_metadata_size_is_checked_before_parse():
    with pytest.raises(census.SessionRefused) as caught:
        census.metadata_json(b" " * 262145, "launch record")
    assert caught.value.code == "invalid_evidence"


class ProcFixture(census.SessionCensus):
    def __init__(self, reader, identity):
        super().__init__(hosts, identity=identity)
        self.reader = reader

    def proc_bytes(self, pid, name, limit):
        return self.reader(pid, name, limit)

    def process_existence(self, pid, reason, partial=None):
        return census.ProcessObservation("UNAVAILABLE", pid, partial=partial, reason=reason)


def test_proc_reader_reuses_canonical_identity_and_retries_torn_parent():
    before = b"41 (worker) S 1 41 " + b"0 " * 16 + b"123"
    after = before.replace(b"S 1 41", b"S 2 41")
    samples = iter([before, after, before, before])
    def read(pid, name, limit):
        if name == "stat":
            return next(samples)
        return b"Uid:\t1000 1000 1000 1000\n" if name == "status" else row().cmdline
    core = ProcFixture(read, SimpleNamespace(process_identity=lambda pid: {"pid": pid, "start_ticks": 123}))
    observed = core.read_process(41)
    assert observed.kind == "PRESENT" and observed.snapshot == row()


def test_proc_reader_retains_unknown_identity_and_never_authorizes_it():
    core = ProcFixture(lambda *args: b"", SimpleNamespace(process_identity=lambda pid: None))
    observed = core.read_process(41)
    assert observed.kind == "UNAVAILABLE" and not observed.partial["coherent_birth"]


def oversized_argv(shape, session='unrelated'):
    if shape == 'atoms':
        return ('worker',) + ('x',) * 127 + (session,)
    if shape == 'atom':
        return ('worker', 'x' * (32769 - len(session)) + session)
    return ('worker',) + ('x' * 32768,) * 4 + (session,)


class GrammarPort:
    TEAM_HOSTS = hosts.TEAM_HOSTS
    SESSION_UUID_OCCURRENCE = hosts.SESSION_UUID_OCCURRENCE
    entry = staticmethod(hosts.entry)
    descendant_verdict = staticmethod(hosts.descendant_verdict)
    MAX_ARGV_ATOMS = hosts.MAX_ARGV_ATOMS
    MAX_ARGV_ATOM_CHARS = hosts.MAX_ARGV_ATOM_CHARS
    MAX_ARGV_CHARS = hosts.MAX_ARGV_CHARS

    def __init__(self):
        self.calls = []

    def entrypoints(self, host):
        return hosts.entrypoints(host)

    def names_session(self, argv, session):
        self.calls.append(argv)
        return hosts.names_session(argv, session)

    def session_verdict(self, host, argv, session, boundaries):
        self.calls.append(argv)
        return hosts.session_verdict(host, argv, session, boundaries)


class GrammarCensus(RecordedCensus):
    def __init__(self, rows, unavailable=None):
        super().__init__(rows)
        self.hosts = GrammarPort()
        self.unavailable = {} if unavailable is None else unavailable

    def process_census(self, session):
        return census.ProcessCensus(self.rows, 'proven', unavailable=self.unavailable)


def unavailable_row(snapshot):
    return census.ProcessObservation('UNAVAILABLE', snapshot.pid, partial=dict(
        snapshot._asdict(), coherent_birth=True, exit_observed=False), reason='recorded evidence unavailable')


def legacy_scope(rows, session, unavailable=None):
    from tools import hierarchy_launcher as legacy
    identity_os = SimpleNamespace(geteuid=lambda: 1000)
    bindings = dict(vars(legacy), require_pid_namespace=lambda: {'device': 1, 'inode': 2},
                    process_census=lambda name: legacy.ProcessCensus(rows, 'proven', unavailable=unavailable), os=identity_os,
                    our_uid=FunctionType(legacy.our_uid.__code__, {'os': identity_os}))
    historical = FunctionType(legacy.session_processes.__code__, bindings, argdefs=legacy.session_processes.__defaults__)
    return historical(session, set(), 'codex-cli')


@pytest.mark.parametrize('shape', ['atoms', 'atom', 'total'])
@pytest.mark.parametrize('uid', [1000, 1001])
@pytest.mark.parametrize('availability', ['present', 'unavailable'])
def test_unrelated_oversize_never_enters_host_grammar(shape, uid, availability):
    good = row()
    extra = row(42, argv=oversized_argv(shape))._replace(uid=uid, euid=uid)
    snapshots = [good, extra] if availability == 'present' else [good]
    missing = {} if availability == 'present' else {42: unavailable_row(extra)}
    core = GrammarCensus(snapshots, missing)
    found = core.session_processes('session-a', set(), 'codex-cli', unowned=[])
    assert found == [(41, 41)]
    assert all(argv is not extra.argv for argv in core.hosts.calls)
    if availability == 'present':
        assert found == legacy_scope(snapshots, 'session-a')
    elif uid != 1000:
        assert found == legacy_scope(snapshots, 'session-a', missing)
    else:
        from tools import hierarchy_launcher as legacy
        # Legacy has no affirmative stop answer when same-UID evidence is unavailable.
        with pytest.raises(legacy.CensusUnavailable):
            legacy_scope(snapshots, 'session-a', missing)


@pytest.mark.parametrize('shape', ['atoms', 'atom', 'total'])
@pytest.mark.parametrize('availability', ['present', 'unavailable'])
def test_relevant_oversize_is_uncertain_for_only_its_session_and_retries(shape, availability):
    first, second = row(), row(43, argv=('codex', 'exec', 'resume', 'session-b'))
    extra = row(42, argv=('codex',) + oversized_argv(shape, 'session-a')[1:])
    snapshots = [first, second, extra] if availability == 'present' else [first, second]
    core = GrammarCensus(snapshots, {} if availability == 'present' else {42: unavailable_row(extra)})
    observed = {}
    assert core.session_processes('session-a', set(), 'codex-cli', unowned=[], observed=observed) == [(41, 41)]
    assert observed['unresolved'][42]['reason'] == 'host_grammar_oversize'
    assert all(argv is not extra.argv for argv in core.hosts.calls)
    with pytest.raises(census.CensusUnavailable) as caught:
        core.session_processes('session-a', set(), 'codex-cli', unowned=[])
    assert caught.value.code == 'census_unavailable' and caught.value.next_action
    assert core.session_processes('session-b', set(), 'codex-cli', unowned=[]) == [(43, 41)]
    core.rows, core.unavailable = [first, second], {}
    assert core.session_processes('session-a', set(), 'codex-cli') == [(41, 41)]


def test_reader_atom_cap_keeps_legacy_unavailable_ancestry_path():
    stat_bytes = b'42 (worker) S 41 41 ' + b'0 ' * 16 + b'123'
    raw = b'worker\0' + b'x\0' * 4096
    def reader(pid, name, limit):
        return stat_bytes if name == 'stat' else b'Uid: 1000 1000 1000 1000\n' if name == 'status' else raw
    probe = ProcFixture(reader, SimpleNamespace(process_identity=lambda pid: {'pid': pid, 'start_ticks': 123}))
    observation = probe.read_process(42)
    assert observation.kind == 'UNAVAILABLE' and 'argv' not in observation.partial
    core = GrammarCensus([row()], {42: observation})
    observed = {}
    assert core.session_processes('session-a', set(), 'codex-cli', observed=observed) == [(41, 41)]
    assert observed['candidates'][42] is None and (42, '123') in observed['group_candidates']


def grammar_examples():
    examples = [(), ('worker',), ('worker', 'session-a'), ('env',), ('env', 'A=1'),
                ('env', '-i', 'worker'), ('env', 'A=1', 'worker'), ('A=1', 'worker'),
                ('node',), ('node', '--eval', 'script'), ('/bin/env', 'A=1', 'B=2', '/bin/worker'),
                ('/bin/env/.', 'A=1', 'worker'), ('env', 'resume=value', 'worker'),
                ('env', 'A=1', '--bad'), ('worker', 'x=prefix-session-a-suffix'),
                ('worker', '=session-a'), ('worker', 'untrusted\n--resume=other')]
    examples.extend([(r'C:worker',), (r'C:\worker',), (r'C:env', 'A=1', 'worker')])
    for kind in hosts.TEAM_HOSTS:
        entry = hosts.entry(kind)
        for program in entry['entrypoints']['program_basenames']:
            examples.extend([('C:' + program,), ('C:\\' + program,)])
            for prefix in [(), ('env', 'A=1'), ('/bin/env', 'A=1', 'B=2')]:
                examples.extend([prefix + (program,), prefix + ('/bin/' + program, 'unknown'),
                                 prefix + ('/bin/' + program + '/./', 'unknown')])
        for script in entry['entrypoints']['node_script_basenames'] + entry['entrypoints']['node_script_suffixes']:
            examples.extend([('node', script), ('node', '--require', 'module', script)])
        for selector in entry['session_selectors']['options']:
            for value in ['session-a', 'other', '']:
                examples.extend([('worker', selector, value), ('worker', selector + '=' + value)])
        for command in entry['session_selectors']['commands']:
            examples.extend([('worker', command[-1], 'session-a'), ('worker', command[-1]),
                             ('env', command[-1] + '=value', 'worker')])
    return examples


@pytest.mark.parametrize('argv', grammar_examples())
def test_grammar_reach_is_sound_for_bounded_registry_inputs(argv):
    core = RecordedCensus()
    reach = core.grammar_reach(argv)
    assert core.argv_grammar_bounded(argv)
    for session in ['session-a', '12345678-1234-1234-1234-123456789abc']:
        if not reach:
            assert hosts.descendant_verdict(argv, session) == 'CLEAR'
            assert hosts.session_verdict(None, argv, session) == 'NOT_OWNED'
        assert core.session_verdict(None, argv, session) == hosts.session_verdict(None, argv, session)
        assert core.descendant_verdict(argv, session) == hosts.descendant_verdict(argv, session)


@pytest.mark.parametrize('shape', ['atoms', 'atom', 'total'])
@pytest.mark.parametrize('base', grammar_examples() + [('python', '-c')])
def test_oversize_negative_classifier_matches_unbounded_legacy(shape, base):
    from tools import hierarchy_hosts as legacy
    core = RecordedCensus()
    argv = (base or ('worker',)) + oversized_argv(shape, 'session-a')[1:]
    assert not core.argv_grammar_bounded(argv)
    for session in ['session-a', '12345678-1234-1234-1234-123456789abc']:
        if core.grammar_reach(argv):
            assert core.descendant_verdict(argv, session) == core.session_verdict(None, argv, session) == 'HOLD'
            assert core.selects_other_session(argv, session) is True
        else:
            assert legacy.descendant_verdict(argv, session) == core.descendant_verdict(argv, session) == 'CLEAR'
            assert legacy.session_verdict(None, argv, session) == core.session_verdict(None, argv, session) == 'NOT_OWNED'
            assert core.selects_other_session(argv, session) is False
            assert core.argv_names_session(argv, session) == legacy.names_session(argv, session)


@pytest.mark.parametrize('argv', [None, 'worker', [None], [b'worker'], ['worker\0'], [1]])
def test_grammar_reach_is_total_for_malformed_shapes(argv):
    core = RecordedCensus()
    assert core.grammar_reach(argv) is True
    assert core.session_verdict(None, argv, 'session-a') == core.descendant_verdict(argv, 'session-a') == 'HOLD'


@pytest.mark.parametrize('shape', ['atoms', 'atom', 'total'])
def test_oversize_plain_discovery_keeps_legacy_unowned_listing(shape):
    extra = row(42, argv=('worker', 'session-a') + oversized_argv(shape)[1:])
    core, unowned, observed = GrammarCensus([row(), extra]), [], {}
    assert core.session_processes('session-a', set(), 'codex-cli', unowned, observed) == [(41, 41)]
    assert unowned == [42] and 42 not in observed['candidates']


def test_registry_questions_are_confined_to_census_adapters():
    import ast
    from pathlib import Path
    allowed = {'argv_names_session': 'names_session', 'session_verdict': 'session_verdict',
               'descendant_verdict': 'descendant_verdict'}
    questions = set(allowed.values()) | {'matches_session', 'selects_other_session'}
    root = Path(__file__).resolve().parents[3] / 'aegis_core'
    sites = []
    for name in ['team_session_census.py', 'team_session_custody.py', 'team_session_stop.py']:
        tree = ast.parse((root / name).read_text(encoding='utf-8'))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(function):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    owner = node.func.value
                    if isinstance(owner, ast.Attribute) and owner.attr == 'hosts' and node.func.attr in questions:
                        assert name == 'team_session_census.py'
                        assert allowed.get(function.name) == node.func.attr
                        sites.append(node.func.attr)
    assert sorted(sites) == sorted(allowed.values())


def partial_sample(raw, uid=1000):
    stat_bytes = b'42 (worker) S 41 41 ' + b'0 ' * 16 + b'123'
    def reader(pid, name, limit):
        if name == 'stat':
            return stat_bytes
        if name == 'status':
            return ('Uid: %d %d %d %d\n' % (uid, uid, uid, uid)).encode()
        assert limit == 262144
        return raw
    probe = ProcFixture(reader, SimpleNamespace(process_identity=lambda pid: {'pid': pid, 'start_ticks': 123}))
    return probe.read_process(42)


@pytest.mark.parametrize('raw', [b'worker\0' + b'y' * 100, b'worker\0session-a\0tail',
                               b'worker\0' + b'y' * (262144 - len(b'worker\0'))],
                         ids=['unread-tail', 'captured-session', 'reader-cap'])
def test_partial_argv_never_supplies_negative_discovery_or_diagnostics(raw):
    sample = partial_sample(raw)
    core, observed, unowned = GrammarCensus([row()], {42: sample}), {}, []
    assert sample.kind == 'UNAVAILABLE' and 'truncated cmdline' in sample.reason
    assert core.session_processes('session-a', set(), 'codex-cli', unowned, observed) == [(41, 41)]
    assert observed['candidates'][42] is None and 42 in observed['unresolved']
    assert 42 not in unowned
    assert all(argv is not sample.partial['argv'] for argv in core.hosts.calls)
    with pytest.raises(census.CensusUnavailable) as caught:
        core.session_processes('session-a', set(), 'codex-cli')
    assert caught.value.code == 'census_unavailable' and caught.value.next_action
    core.unavailable = {}
    assert core.session_processes('session-a', set(), 'codex-cli') == [(41, 41)]


@pytest.mark.parametrize('fault', ['missing_raw', 'missing_argv', 'argv_limit', 'truncated_error',
                                 'unstable_birth', 'unstable_parent', 'missing_uids', 'half_foreign_uid'])
def test_unavailable_fact_uncertainty_cannot_exclude_a_candidate(fault):
    sample = unavailable_row(row(42, parent=41, argv=('worker', 'session-a')))
    facts, reason = dict(sample.partial), sample.reason
    if fault == 'missing_raw':
        facts.pop('cmdline')
    elif fault == 'missing_argv':
        facts.pop('argv')
    elif fault in ['argv_limit', 'truncated_error', 'unstable_parent']:
        reason = {'argv_limit': 'argv limit', 'truncated_error': 'truncated cmdline',
                  'unstable_parent': 'unstable parent/group evidence'}[fault]
    elif fault == 'unstable_birth':
        facts.update(coherent_birth=False, uid=1001, euid=1001)
    elif fault == 'missing_uids':
        facts.pop('uid')
        facts.pop('euid')
    else:
        facts.pop('euid')
        facts['uid'] = 1001
    if fault in ['unstable_birth', 'unstable_parent']:
        facts.update(cmdline=b'worker\0other\0', argv=('worker', 'other'))
    sample = sample._replace(partial=facts, reason=reason)
    core, observed, unowned = GrammarCensus([row()], {42: sample}), {}, []
    assert core.session_processes('session-a', set(), 'codex-cli', unowned, observed) == [(41, 41)]
    assert observed['candidates'][42] is None and 42 in observed['unresolved']
    if fault in ['missing_raw', 'missing_argv', 'argv_limit', 'truncated_error', 'unstable_birth', 'unstable_parent']:
        assert 42 not in unowned


@pytest.mark.parametrize('shape', ['complete', 'foreign'])
def test_complete_irrelevant_or_coherent_foreign_partial_stays_excluded(shape):
    sample = partial_sample(b'worker\0session-a' if shape == 'foreign' else b'worker\0other\0',
                            uid=1001 if shape == 'foreign' else 1000)
    if shape == 'complete':
        assert sample.kind == 'PRESENT'
        sample = unavailable_row(sample.snapshot)
    core, observed = GrammarCensus([row()], {42: sample}), {}
    assert core.session_processes('session-a', set(), 'codex-cli', observed=observed) == [(41, 41)]
    assert 42 not in observed['candidates'] and 42 not in observed['unresolved']


@pytest.mark.parametrize('terminated', [False, True])
def test_reader_atom_limit_counts_an_unterminated_tail_before_decoding(terminated):
    raw = b'worker\0' + b'x\0' * 4095 + (b'x\0' if terminated else b'x')
    sample = partial_sample(raw)
    assert sample.kind == 'UNAVAILABLE' and 'argv limit' in sample.reason
    assert 'argv' not in sample.partial and 'cmdline' not in sample.partial
