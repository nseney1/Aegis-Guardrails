"""Fresh-thread briefs through the CLI; records remain inert claims.

The real-dispatcher invariant table is the primary writer-release barrier.
Structural checks are secondary syntax allowlists: they do not prove Python
control flow, binding identity or absence of side effects. Runtime mutation
controls cover those subtler forms without treating an AST match as proof.
"""
import ast
import errno
import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, invoke, message, pilot, receipt_fixture  # noqa: F401
from tests.integration.test_hierarchy_handoff import active_writer, handoff
from tests.integration.test_hierarchy_host_plan import write_plan
from tests.integration.test_hierarchy_lifecycle import Ledger, SOURCE, raw_request, request, pytestmark as lifecycle_only
from tests.integration.test_hierarchy_small_change_admission import SmallChange
from tools.hierarchy_mailbox import Mailbox, safe_path


TOOL = ROOT / "tools" / "hierarchy_fresh_brief.py"


LATCH_STATES = list(itertools.product((False, True), repeat=3))
LATCH_OUTCOMES = list(itertools.product(('missing', 'failed', 'proved'),
                                       ('enter', 'exit', 'ok'), (True, False)))


LATCH_PROJECT_DRIVER = r'''
import json, sys
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import hierarchy_small_change_dispatch as dispatch
from hierarchy_lifecycle import Lifecycle
from hierarchy_workspace import Store

lifecycle, store, recipes, mailbox, lock, mutate = sys.argv[2:8]
race = sys.argv[8] if len(sys.argv) > 8 else None
mutate = mutate == 'True'
observed = {'proofs': 0, 'finalizers': [], 'custody': [], 'locks': [], 'unknown': None, 'resolved': None, 'routed': None,
            'race': False, 'exit_collections': None, 'collections': None}
proof_tokens = {}

def collections(frame):
    while frame is not None:
        if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'project':
            values = frame.f_locals
            return {'rows': [row['request_id'] for row in values['rows']],
                    'custody': [facts.request_id for facts in values['custody']],
                    'contexts': [holder.key for holder in values['contexts']],
                    'released': [facts.released for facts in values['custody']]}
        frame = frame.f_back
    raise AssertionError('project collection frame is missing')

original_lock = dispatch.writer_lock
@contextmanager
def writer_lock(root):
    assert Path(root) == Path(mailbox)
    observed['locks'].append('enter')
    if lock == 'enter':
        raise OSError('table writer lock enter refusal')
    with original_lock(root):
        yield
    observed['locks'].append('exit')
    observed['exit_collections'] = collections(sys._getframe())
    if lock == 'exit':
        raise OSError('table writer lock exit refusal')
dispatch.writer_lock = writer_lock  # Only this module's OS-lock reference.

if race:
    import subprocess
    original_journal_lock = dispatch.router.writer_lock
    @contextmanager
    def journal_lock(root):
        frame, final_snapshot = sys._getframe(), False
        while frame is not None:
            if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'project':
                final_snapshot = 'final' in frame.f_locals
                break
            frame = frame.f_back
        if final_snapshot and not observed['race']:
            observed['race'] = True
            # The concurrent writer uses the real public lifecycle recorder in
            # another process, before this final snapshot acquires its lock.
            program = ('import json,sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n'
                       'from hierarchy_lifecycle import Lifecycle\nfrom hierarchy_mailbox import digest\n'
                       'ledger=Lifecycle(Path(sys.argv[2]))\n'
                       'for value in json.loads(Path(sys.argv[3]).read_text()):\n'
                       '    event=value["event"]\n'
                       '    if event["type"] == "small_change_admit":\n'
                       '        row=ledger.load()[1]["requests"][event["request_id"]]\n'
                       '        event["decision_sha256"]=digest(row["small_change"]["decisions"][-1])\n'
                       '    ledger.record(value)\n')
            child = subprocess.run([sys.executable, '-I', '-B', '-c', program, sys.argv[1], lifecycle, race],
                                   capture_output=True, text=True, timeout=30)
            assert child.returncode == 0 and not child.stderr, (child.stdout, child.stderr)
        with original_journal_lock(root):
            yield
    dispatch.router.writer_lock = journal_lock  # Only the reader module's OS-lock reference.

def observe(frame, event, value):
    if event != 'return':
        return
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'project':
        observed['collections'] = collections(frame)
    if frame.f_code.co_filename == dispatch.fresh.__file__ and frame.f_code.co_name == 'prove':
        if value is not None:
            observed['proofs'] += 1
            proof_tokens[id(frame.f_locals['self'])] = value
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'finalize_writer_release':
        holder = frame.f_locals['self']
        token = proof_tokens.get(id(holder.operation))
        observed['finalizers'].append({'proof': token is not None and token is holder._verification_proof,
            'clear': frame.f_locals['clear_only'], 'released': bool(value and value.released)})
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'run':
        row = frame.f_locals['self'].row
        observed.update(unknown=bool(row.get('lifecycle_unknown')), resolved=row['resolution'] is not None,
                        routed=row['routed'] is not None)
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name in {'run', 'clear_writer_release'}:
        holder = frame.f_locals['self']
        token = proof_tokens.get(id(holder.operation))
        facts = holder._custody
        if facts is not None:
            observed['custody'].append({'released': facts.released,
                'proof': token is not None and token is holder._verification_proof})

previous = sys.getprofile()
try:
    sys.setprofile(observe)
    result = dispatch.project(Lifecycle(Path(lifecycle)), Store(Path(store)), recipes=Path(recipes),
                              wait=0.1, mutate=mutate)
finally:
    sys.setprofile(previous)
print(json.dumps({'result': result, 'observed': observed}))
'''


def latch_unknown_event(world):
    """A correlated, hash-valid historical refusal, matching the replay fixtures."""
    paths = sorted((world.ledger.path / 'events').glob('*.json'))
    previous = json.loads(paths[-1].read_text())
    value = {'request_sha256': raw_request(world.change.value)['sha256'], 'intent_id': 'table-unknown',
             'outcome': 'passed', 'exit_code': 'invalid', 'source': SOURCE, 'evidence': world.ledger.evidence}
    envelope = {'id': 'table-unknown', 'actor': world.ledger.operator, 'generation': 1,
                'custody': {'cid': world.ledger.root_actor, 'generation': 1},
                'event': {'type': 'terminal', **world.ledger.target(world.change.value), 'result': raw_request(value)}}

    def sha(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                         ensure_ascii=True).encode()).hexdigest()

    record = {**previous, 'sequence': previous['sequence'] + 1, 'previous': sha(previous),
              'envelope': envelope, 'event_sha256': sha(envelope)}
    (paths[-1].parent / ('%06d.json' % record['sequence'])).write_text(json.dumps(record))


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('routed,resolved,unknown', LATCH_STATES,
                         ids=['routed-%s-resolved-%s-unknown-%s' % state for state in LATCH_STATES])
def test_latch_release_invariant_table(tmp_path, routed, resolved, unknown):
    from tests.integration.test_hierarchy_small_change_dispatch import DispatchWorld

    folder = tmp_path / 'world'
    folder.mkdir()
    world = DispatchWorld(folder)
    initial = world.dispatch()
    assert initial['small_changes'][0]['writer_publication_verified'] is True, initial
    writer_packet = Path(world.messages('dispatch')[0]['message']['brief']['path'])
    if not routed:
        last = sorted((world.ledger.path / 'events').glob('*.json'))[-1]
        assert json.loads(last.read_text())['envelope']['event']['type'] == 'route'
        last.unlink()  # Model retained delivery without the final journal receipt.
    if resolved:
        world.ledger.event('disposition', status='FINAL', resolution={'kind': 'next',
            'request': raw_request(request('table-next')), 'evidence': world.ledger.evidence},
            **world.ledger.target(world.change.value))
    if unknown:
        latch_unknown_event(world)
    snapshot = tmp_path / 'snapshot'
    shutil.copytree(folder, snapshot, symlinks=True)
    for verification, lock, mutate in LATCH_OUTCOMES:
        # Restore at the SAME path: durable references remain genuine absolute
        # paths. Only owned fixture directories are replaced between scenarios.
        shutil.rmtree(folder)
        shutil.copytree(snapshot, folder, symlinks=True)
        if verification == 'failed':
            writer_packet.write_bytes(b'table changed writer attachment\n')
        elif verification == 'missing':
            writer_packet.unlink()
        process = subprocess.run([sys.executable, '-I', '-B', '-c', LATCH_PROJECT_DRIVER, str(ROOT / 'tools'),
            str(world.ledger.path), str(world.workspace.store), str(world.recipes_path), str(world.root),
            lock, str(mutate)], capture_output=True, text=True, timeout=30)
        scenario = (routed, resolved, unknown, verification, lock, mutate)
        assert process.returncode == 0 and not process.stderr, (scenario, process.stdout, process.stderr)
        answer = json.loads(process.stdout)
        result, observed = answer['result'], answer['observed']
        expected = (verification == 'proved' and not resolved and not unknown and (routed or mutate)
                    and (not mutate or lock == 'ok'))
        rows = [row for row in result['small_changes'] if row['request_id'] == world.change.value['id']]
        assert len(rows) == 1, (scenario, answer)
        row = rows[0]
        finalizers = observed['finalizers']
        assert all(not facts['released'] or facts['proof'] for facts in finalizers + observed['custody']), (scenario, answer)
        assert bool(row.get('route_receipt') and row.get('writer_publication_verified')) == expected, (scenario, answer)
        assert result['planning_exclusions'].count('engine/lane/fix') == (0 if expected else 1), (scenario, answer)
        collected = observed['collections']
        identifiers = [world.change.value['id']]
        assert collected['rows'] == collected['custody'] == collected['contexts'] == identifiers, (scenario, answer)
        assert collected['released'] == [expected], (scenario, answer)
        if mutate and lock != 'enter':
            before_exit = observed['exit_collections']
            assert before_exit['rows'] == before_exit['custody'] == before_exit['contexts'] == identifiers, (scenario, answer)
            if lock == 'exit' and verification == 'proved' and routed and not resolved and not unknown:
                assert before_exit['released'] == [True], (scenario, answer)
        if expected:
            assert observed['proofs'] == 1, (scenario, answer)
            assert sum(facts['released'] for facts in finalizers) == 1, (scenario, answer)
            assert row['state'] != 'held', (scenario, answer)
        else:
            assert row['state'] == 'held', (scenario, answer)
            assert not finalizers[-1]['released'], (scenario, answer)
            if verification != 'proved' and not resolved and not unknown and (not mutate or lock == 'ok'):
                assert any(facts['clear'] for facts in finalizers), (scenario, answer)
                assert any(not facts['clear'] for facts in finalizers), (scenario, answer)
        if not mutate:
            assert observed['locks'] == [], (scenario, answer)
        if observed['unknown'] is not None:
            assert observed['unknown'] == unknown and observed['resolved'] == resolved, (scenario, answer)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('mutate', [False, True], ids=['read', 'mutate'])
@pytest.mark.parametrize('race', ['new-request', 'new-decision'])
@pytest.mark.parametrize('verification', ['proved', 'failed'])
def test_latch_snapshot_race_table(tmp_path, race, mutate, verification):
    from tests.integration.test_hierarchy_small_change_dispatch import DispatchWorld

    world = DispatchWorld(tmp_path)
    world.dispatch()
    directory = world.ledger.path / 'events'
    before = set(directory.glob('*.json'))
    if race == 'new-request':
        change = SmallChange(world.ledger, request('table-raced-request'))
        change.plan['plan']['writing_lanes'][0]['lane'] = 'other'
        change.register()
        change.decide()
        change.admit()
        world.ledger.event('route', actor='router-1', to='engine/lane/other',
                           **world.ledger.target(change.value))
    else:
        world.ledger.event('decision', actor=world.ledger.root_actor, decision='deny',
                           reason='table decision changed after verification',
                           **world.ledger.target(world.change.value))
    appended = sorted(set(directory.glob('*.json')) - before)
    events = [json.loads(path.read_text())['envelope'] for path in appended]
    for path in appended:
        path.unlink()
    packet = tmp_path / 'race-events.json'
    packet.write_text(json.dumps(events))
    if verification == 'failed':
        writer_packet = Path(world.messages('dispatch')[0]['message']['brief']['path'])
        writer_packet.write_bytes(b'table failed writer before snapshot race\n')
    before_race = world.dispatch(command='status')['small_changes'][0]
    process = subprocess.run([sys.executable, '-I', '-B', '-c', LATCH_PROJECT_DRIVER, str(ROOT / 'tools'),
        str(world.ledger.path), str(world.workspace.store), str(world.recipes_path), str(world.root),
        'ok', str(mutate), str(packet)], capture_output=True, text=True, timeout=45)
    assert process.returncode == 0 and not process.stderr, (process.stdout, process.stderr)
    answer = json.loads(process.stdout)
    result, observed = answer['result'], answer['observed']
    assert observed['race'] and observed['proofs'] == (1 if verification == 'proved' else 0), answer
    canonical = world.ledger.status()
    if race == 'new-request':
        assert canonical['requests'][change.value['id']]['routed'] is not None, canonical
    else:
        decisions = [value for value in canonical['decisions'] if value['request_id'] == world.change.value['id']]
        assert decisions[-1]['decision'] == 'deny', canonical
    assert result['planning_exclusions'].count('engine/lane/fix') == 1, answer
    row = result['small_changes'][0]
    assert row['state'] == 'held' and not row.get('route_receipt') and not row.get('writer_publication_verified'), answer
    if verification == 'failed':
        assert row['reason'] == before_race['reason'] and row['detail'] == before_race['detail'], answer
    if race == 'new-request':
        assert result['planning_exclusions'].count('engine/lane/other') == 1, answer
        assert not any(row.get('writer_publication_verified') for row in result['small_changes']
                       if row['request_id'] == change.value['id']), answer


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('failure', ['review', 'check'])
def test_latch_head_advance_preserves_owner_hold_drafts_and_evidence(tmp_path, failure):
    from tests.integration.test_hierarchy_mailbox import mailbox_snapshot
    from tests.integration.test_hierarchy_small_change_dispatch import (
        DispatchWorld, r13_second_team, ready_reviewer, record_drafts, review_result,
    )

    world = DispatchWorld(tmp_path)
    if failure == 'review':
        review_result(world, ready_reviewer(world), 'reject')
        reason = 'small_change_review_rejected'
    else:
        world.dispatch()
        world.finish_writer()
        world.dispatch()
        job = world.messages('job_request')[0]['message']
        invoke(world.root, 'publish', {'message_id': 'owner-check-refused', 'from': 'engine/root',
            'to': 'engine/orchestrator', 'host': 'host-one', 'session': 'engine/root', 'binding_generation': 1,
            'type': 'job_receipt', 'in_reply_to': job['message_id'], 'body': 'owner retains refused check',
            'receipt': {'state': 'refused', 'reason': 'owner refused original check'}})
        reason = 'small_change_check_failed'
    _other_root, other = r13_second_team(world, 'zz-next-route')
    assert world.change.value['id'] < other.value['id']
    before = world.dispatch(command='status')['small_changes'][0]
    assert before['state'] == 'held' and before['reason'] == reason, before
    assert before['drafts'], before
    assert all(draft['event']['status'] == 'HOLD' and draft['event']['resolution']['kind'] == 'blocked'
               and draft['event']['resolution']['evidence'] for draft in before['drafts']), before
    evidence = {ref['path']: Path(ref['path']).read_bytes() for draft in before['drafts']
                for ref in draft['event']['resolution']['evidence']}
    retained = mailbox_snapshot(world.root)
    original = world.ledger.status()
    answer = world.dispatch()
    canonical = world.ledger.status()
    assert canonical['head'] != original['head'], answer
    assert canonical['requests'][other.value['id']]['routed'] is not None, answer
    assert canonical['requests'][world.change.value['id']] == original['requests'][world.change.value['id']]
    row = answer['small_changes'][0]
    assert row['drafts'] == before['drafts'], (before, answer)
    assert row == before, (before, answer)
    assert mailbox_snapshot(world.root) == retained
    assert {path: Path(path).read_bytes() for path in evidence} == evidence
    assert not row.get('route_receipt') and not row.get('writer_publication_verified'), row
    assert answer['planning_exclusions'].count('engine/lane/fix') == 1, answer
    # Exact envelopes remain consumable through the owner's public recorder.
    record_drafts(world, row)
    resolution = world.change.row()['resolution']
    assert resolution == row['drafts'][-1]['event']['resolution']


LATCH_DRAFT_DRIVER = r'''
import json, sys, subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import hierarchy_small_change_dispatch as dispatch
from hierarchy_lifecycle import Lifecycle
from hierarchy_workspace import Store
lifecycle, store, recipes, packet, cause = sys.argv[2:7]
observed = {'injected': False, 'before': None, 'frames': [], 'capture_changed': False}

def boundary():
    frame, holder, names, final = sys._getframe(1), None, [], False
    while frame is not None:
        if frame.f_code.co_filename == dispatch.__file__:
            names.append(frame.f_code.co_name)
            if frame.f_code.co_name == 'run':
                holder = frame.f_locals['self']
            if frame.f_code.co_name == 'project':
                final = 'final' in frame.f_locals
                if final:
                    holder = frame.f_locals['contexts'][0]
        frame = frame.f_back
    return holder, names, final

def inject(holder, names):
    assert holder is not None and holder.view['drafts']
    observed.update(injected=True, before=json.loads(json.dumps(holder.view['drafts'])), frames=names)
    if cause == 'capture':
        # Every pass captures policy, including a check refused before recipes
        # are read. Whitespace changes its witness without changing its policy.
        with (Path(lifecycle) / 'policy.json').open('ab') as stream:
            stream.write(b'\n')
    else:
        program = ('import json,sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n'
                   'from hierarchy_lifecycle import Lifecycle\n'
                   'Lifecycle(Path(sys.argv[2])).record(json.loads(Path(sys.argv[3]).read_text()))\n')
        child = subprocess.run([sys.executable, '-I', '-B', '-c', program, sys.argv[1], lifecycle, packet],
                               capture_output=True, text=True, timeout=30)
        assert child.returncode == 0 and not child.stderr, (child.stdout, child.stderr)

original_os = dispatch.fresh.os
def stat(path, *args, **kwargs):
    holder, names, final = boundary()
    if (not observed['injected'] and holder is not None and holder.view['drafts']
            and ((cause == 'capture' and not final)
                 or (cause == 'release-journal' and 'finalize_writer_release' in names))):
        inject(holder, names)
    return original_os.stat(path, *args, **kwargs)
# Patch only the captured-reader module's OS reference, never the shared os module.
dispatch.fresh.os = SimpleNamespace(**dict(vars(original_os), stat=stat))

original_journal_lock = dispatch.router.writer_lock
@contextmanager
def journal_lock(root):
    holder, names, final = boundary()
    if cause in {'head', 'denial'} and final and not observed['injected']:
        inject(holder, names)
    with original_journal_lock(root):
        yield
dispatch.router.writer_lock = journal_lock

original_lock = dispatch.writer_lock
@contextmanager
def writer_lock(root):
    with original_lock(root):
        yield
    if cause == 'lock-exit':
        # The Row.run frame has returned, but collection is complete before exit.
        frame = sys._getframe(1)
        while frame is not None and frame.f_code.co_name != 'project':
            frame = frame.f_back
        holder = frame.f_locals['current']
        observed.update(injected=True, before=json.loads(json.dumps(holder.view['drafts'])), frames=['lock-exit'])
        raise OSError('draft table lock exit refusal')
dispatch.writer_lock = writer_lock
def observe(frame, event, value):
    if (event == 'return' and frame.f_code.co_filename == dispatch.fresh.__file__
            and frame.f_code.co_name == 'verify'):
        operation = frame.f_locals.get('self')
        if isinstance(getattr(operation, 'validation_failure', None), dispatch.fresh.CaptureChanged):
            observed['capture_changed'] = True
previous = sys.getprofile()
try:
    sys.setprofile(observe)
    result = dispatch.project(Lifecycle(Path(lifecycle)), Store(Path(store)), recipes=Path(recipes), wait=0.1, mutate=True)
finally:
    sys.setprofile(previous)
print(json.dumps({'result': result, 'observed': observed}))
'''


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('case', ['final', 'resolve', 'review-hold', 'check-hold'])
@pytest.mark.parametrize('cause', ['head', 'denial', 'capture', 'release-journal', 'lock-exit'])
def test_latch_draft_invalidation_table(tmp_path, case, cause):
    from tests.integration.test_hierarchy_mailbox import mailbox_snapshot
    from tests.integration.test_hierarchy_small_change_dispatch import DispatchWorld, ready_reviewer, review_result

    world = DispatchWorld(tmp_path)
    if case == 'check-hold':
        world.dispatch()
        world.finish_writer()
        world.dispatch()
        job = world.messages('job_request')[0]['message']
        invoke(world.root, 'publish', {'message_id': 'draft-check-refused', 'from': 'engine/root',
            'to': 'engine/orchestrator', 'host': 'host-one', 'session': 'engine/root', 'binding_generation': 1,
            'type': 'job_receipt', 'in_reply_to': job['message_id'], 'body': 'owner retains refused check',
            'receipt': {'state': 'refused', 'reason': 'owner refused original check'}})
    else:
        reviewer = ready_reviewer(world)
        if case == 'resolve':
            world.ledger.event('disposition', status='HOLD', resolution={'kind': 'blocked', 'owner': 'owner',
                'next_decision': 'review', 'condition': 'owner waiting for review', 'evidence': world.ledger.evidence},
                **world.ledger.target(world.change.value))
        review_result(world, reviewer, 'reject' if case == 'review-hold' else 'accept')
    other = request('draft-other-team', team='docs')
    world.ledger.publish(other)
    before = world.dispatch(command='status')['small_changes'][0]
    assert before['drafts'], before
    terminal = before['drafts'][-1]['event']
    if case in {'final', 'resolve'}:
        assert terminal['type'] == ('disposition' if case == 'final' else 'resolve'), before
        assert terminal['resolution']['kind'] == 'complete', before
    else:
        assert terminal['status'] == 'HOLD' and terminal['resolution']['kind'] == 'blocked', before
    evidence = {ref['path']: Path(ref['path']).read_bytes() for draft in before['drafts']
                for ref in draft['event'].get('evidence', draft['event'].get('resolution', {}).get('evidence', []))}
    retained = mailbox_snapshot(world.root)
    # Prepare a real public journal envelope, then retain it for the concurrent
    # recorder to append at the chosen OS boundary rather than before the pass.
    events = world.ledger.path / 'events'
    previous = set(events.glob('*.json'))
    target = world.change.value if cause == 'denial' else other
    world.ledger.event('decision', actor=world.ledger.root_actor,
        decision='deny' if cause == 'denial' else 'approve', reason='draft table concurrent decision',
        **world.ledger.target(target))
    added = set(events.glob('*.json')) - previous
    assert len(added) == 1
    path = added.pop()
    packet = tmp_path / 'draft-race.json'
    packet.write_text(json.dumps(json.loads(path.read_text())['envelope']))
    path.unlink()
    process = subprocess.run([sys.executable, '-I', '-B', '-c', LATCH_DRAFT_DRIVER, str(ROOT / 'tools'),
        str(world.ledger.path), str(world.workspace.store), str(world.recipes_path), str(packet), cause],
        capture_output=True, text=True, timeout=60)
    assert process.returncode == 0 and not process.stderr, (process.stdout, process.stderr)
    answer = json.loads(process.stdout)
    row, observed = answer['result']['small_changes'][0], answer['observed']
    assert observed['injected'] and observed['before'] == before['drafts'], answer
    if cause in {'capture', 'release-journal'}:
        assert observed['capture_changed'], answer
    if cause == 'capture':
        assert 'release_validation_error' in row, answer
    if cause == 'release-journal':
        assert 'finalize_writer_release' in observed['frames'] and 'run' in observed['frames'], answer
        if case.endswith('hold'):
            assert 'release_validation_error' in row, answer
    assert row['state'] in {'held', 'owned_hold'}, answer
    if case.endswith('hold'):
        assert row['drafts'] == before['drafts'], answer
    else:
        assert row['drafts'] == [], answer
        expected_reason = {'head': 'small_change_snapshot_changed', 'denial': 'small_change_revoked',
            'capture': 'small_change_configuration', 'release-journal': 'small_change_configuration',
            'lock-exit': 'small_change_configuration'}[cause]
        assert row['reason'] == expected_reason, answer
    assert not row.get('route_receipt') and not row.get('writer_publication_verified'), answer
    assert mailbox_snapshot(world.root) == retained
    assert {path: Path(path).read_bytes() for path in evidence} == evidence


def assert_draft_invalidation_structure(source):
    """Draft creation is explicit; only invalidate may replace existing drafts."""
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    creation = {'Row.__init__', 'Row.progress', 'Row.run'}

    def scope(node):
        names = []
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(node.name)
        return '.'.join(reversed(names))

    def view(node):
        return (isinstance(node, ast.Attribute) and node.attr == 'view' and isinstance(node.value, ast.Name)
                and node.value.id == 'self')

    invalidators = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == 'invalidate' and scope(node) == 'Row']
    assert len(invalidators) == 1 and isinstance(invalidators[0], ast.FunctionDef), (
        'draft invalidation must have one synchronous policy function')
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == 'drafts':
            raise AssertionError(('draft keyword write is not creation', node.lineno))
        if not isinstance(node, ast.Constant) or node.value != 'drafts':
            continue
        parent, owner = parents[node], scope(node)
        if isinstance(parent, ast.Dict) and node in parent.keys:
            assignment = parents[parent]
            assert (owner == 'Row.__init__' and isinstance(assignment, ast.Assign)
                    and len(assignment.targets) == 1 and view(assignment.targets[0])
                    and isinstance(parent.values[parent.keys.index(node)], ast.List)
                    and not parent.values[parent.keys.index(node)].elts), ('draft initialization', node.lineno)
            continue
        assert isinstance(parent, ast.Subscript) and parent.slice is node and view(parent.value), (
            'draft access is not admitted', node.lineno)
        statement = parents[parent]
        if isinstance(parent.ctx, ast.Store):
            assert isinstance(statement, ast.Assign) and statement.targets == [parent], ('draft assignment', node.lineno)
            assert owner in creation | {'Row.invalidate'}, ('draft write outside creation/invalidation', node.lineno)
            if owner != 'Row.invalidate':
                value = statement.value
                assert (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                        and isinstance(value.func.value, ast.Name) and value.func.value.id == 'self'
                        and value.func.attr == 'drafts' and not value.keywords
                        and len(value.args) == 1 and not isinstance(value.args[0], ast.Starred)), (
                            'draft creation must use the draft builder', node.lineno)
        else:
            assert isinstance(parent.ctx, ast.Load) and (owner == 'Row.invalidate' or (
                owner == 'Row.run' and isinstance(statement, ast.UnaryOp) and isinstance(statement.op, ast.Not))), (
                    'draft alias or mutation outside invalidation', node.lineno)


def test_latch_draft_writes_are_creation_or_central_invalidation():
    assert_draft_invalidation_structure((ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8'))


def test_latch_draft_structure_rejects_async_policy_shadow():
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, 'Row', 'async def invalidate(self, reason, detail):\n    pass')
    with pytest.raises(AssertionError, match='draft invalidation'):
        assert_draft_invalidation_structure(source)


@pytest.mark.parametrize('snippet', [
    'self.view["drafts"] = []', 'self.view.update(drafts=[])',
    'self.view.update({"drafts": []})', 'self.view["drafts"].clear()',
    'alias = self.view["drafts"]; alias.clear()', 'del self.view["drafts"]',
    'self.view["drafts"] += []', 'self.view["drafts"][:] = []',
])
def test_latch_draft_structure_rejects_scattered_invalidation(snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    with pytest.raises(AssertionError, match='draft'):
        assert_draft_invalidation_structure(latch_insert(source, 'Row.run', snippet))


def assert_latch_release_structure(source):
    """Allow only explicit view producers, consumers and mutations.

    This is a secondary syntax barrier. The real project() table determines
    release outcomes, including side effects and skipped collection.
    """
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    keys = {'route_receipt', 'writer_publication_verified'}
    scopes = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    writes, writers, initializers, collections = [], set(), [], []

    def ancestors(node):
        chain = []
        while node in parents:
            node = parents[node]
            chain.append(node)
        return chain

    def qualified(node):
        return '.'.join(item.name for item in reversed(ancestors(node)) if isinstance(item, scopes))

    def name(node, value):
        return isinstance(node, ast.Name) and node.id == value

    def string(node):
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def view(node):
        return isinstance(node, ast.Attribute) and node.attr == 'view' and name(node.value, 'self')

    def literal_keys(node):
        return isinstance(node, ast.Dict) and all(string(key) for key in node.keys)

    def rows_append(call):
        return (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and name(call.func.value, 'rows') and call.func.attr == 'append'
                and len(call.args) == 1 and not call.keywords and qualified(call) == 'project')

    def run_call(call):
        return (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'run'
                and (name(call.func.value, 'current') or (isinstance(call.func.value, ast.Call)
                     and name(call.func.value.func, 'context') and not call.func.value.args
                     and not call.func.value.keywords))
                and len(call.args) == 1 and isinstance(call.args[0], ast.Constant)
                and type(call.args[0].value) is bool and not call.keywords)

    # There is no admitted reflective spelling of the protected view. Reject
    # opaque reflection primitives too, including aliases to those primitives.
    reflection = {'getattr', 'setattr', 'vars', 'eval', 'exec', 'globals', 'locals'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith('__'):
            parent = parents[node]
            # All special attribute access requires an admitted shape. This
            # includes protocols reached indirectly through a bound method.
            assert (qualified(node) == 'Hold.__init__' and node.attr == '__init__'
                    and isinstance(node.value, ast.Call) and name(node.value.func, 'super')
                    and not node.value.args and not node.value.keywords
                    and isinstance(parent, ast.Call) and parent.func is node
                    and len(parent.args) == 1 and name(parent.args[0], 'detail') and not parent.keywords), (
                        'release reflection: unadmitted special attribute', node.lineno)
        if isinstance(node, ast.Attribute) and node.attr == 'project':
            raise AssertionError(('release producer result escape', node.lineno))
        if ((isinstance(node, ast.Name) and node.id in reflection)
                or (isinstance(node, ast.Attribute) and node.attr in reflection | {
                    '__dict__', '__getattribute__', '__setattr__'})
                or (string(node) and node.value == 'view')
                or (isinstance(node, ast.keyword) and node.arg == 'view')):
            raise AssertionError(('release reflection is not admitted', node.lineno))

    producers = {key: [] for key in ('Row', 'Row.run', 'Row.finalize_writer_release', 'project', 'exclusions')}
    returns = []
    for node in ast.walk(tree):
        scope = qualified(node)
        if isinstance(node, scopes):
            identity = '.'.join(part for part in (scope, node.name) if part)
            if identity in producers:
                producers[identity].append(node)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in {'Row', 'project', 'exclusions'}:
            raise AssertionError(('release producer rebinding', node.lineno))
        if scope == 'Row.run' and isinstance(node, ast.Return):
            assert view(node.value), ('release producer must return its protected view', node.lineno)
            returns.append(node)
        if scope == 'Row.run' and isinstance(node, (ast.Yield, ast.YieldFrom)):
            raise AssertionError(('release producer cannot yield a view', node.lineno))
    assert all(len(definitions) == 1 for definitions in producers.values()), ('release producer definitions', producers)
    run = producers['Row.run'][0]
    assert (isinstance(run, ast.FunctionDef) and len(returns) == 1 and run.body[-1] is returns[0]), (
        'release producer must have one final return')

    row_class = producers['Row'][0]
    methods = {node.name for node in row_class.body if isinstance(node, ast.FunctionDef)}
    assert all(node.args.args and node.args.args[0].arg == 'self'
               for node in row_class.body if isinstance(node, ast.FunctionDef)), 'release holder parameter'
    assert not row_class.bases and not row_class.decorator_list, 'release holder definition'
    assert all(not method.startswith('__') or method == '__init__' for method in methods), (
        'release holder protocols are not admitted')
    # A positive list of ordinary fields and methods, rather than a list of
    # known state-exposing protocols. New holder attributes require review.
    holder_fields = {
        '_completed_checks', '_custody', '_retained_jobs', '_verification_proof',
        '_writer_receipt', '_writer_target_current', '_writer_verified', 'accepted',
        'change', 'initiative', 'key', 'ledger', 'lifecycle', 'mailbox', 'operation',
        'plan', 'policy', 'proofs', 'recipes', 'records', 'result_record',
        'review_not_before', 'reviewer', 'row', 'running_checks', 'setup', 'state',
        'store', 'team', 'view', 'wait', 'writer',
    }

    # Views leave Row only through run() and the project rows collection.
    # The custody consumer has no presentation alias.
    for node in ast.walk(tree):
        parent = parents.get(node)
        scope = qualified(node)
        if isinstance(node, ast.Name) and node.id == 'project' and isinstance(node.ctx, ast.Load):
            raise AssertionError(('release producer result escape', node.lineno))
        if isinstance(node, ast.Name) and node.id == 'context' and isinstance(node.ctx, ast.Load) and scope == 'project':
            statement = parents.get(parent)
            assert (isinstance(parent, ast.Call) and parent.func is node
                    and isinstance(statement, ast.Assign) and len(statement.targets) == 1
                    and name(statement.targets[0], 'current')), ('release view escape through context', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'self' and scope.startswith('Row.'):
            allowed = (isinstance(parent, ast.Attribute) and parent.value is node
                       and parent.attr in holder_fields | methods)
            allowed = allowed or (isinstance(parent, ast.Call) and name(parent.func, 'hasattr')
                and len(parent.args) == 2 and parent.args[0] is node and string(parent.args[1])
                and parent.args[1].value == 'result_record' and not parent.keywords
                and scope == 'Row.foreign_publications')
            assert allowed, ('release view escape through holder', node.lineno)
            if isinstance(parent, ast.Attribute) and parent.attr in methods:
                use = parents[parent]
                direct = isinstance(use, ast.Call) and use.func is parent
                callback = (isinstance(use, ast.Call) and isinstance(use.func, ast.Attribute)
                    and ((parent.attr in {'recheck_jobs', 'recheck_dependencies'} and use.func.attr == 'append')
                         or (parent.attr == 'verification_pass' and use.func.attr == 'prove')))
                callback = callback or (parent.attr == 'publication_authority' and isinstance(use, ast.Assign)
                                        and scope == 'Row.verification_pass')
                assert direct or callback, ('release view escape through bound method', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'current' and scope == 'project' and isinstance(node.ctx, ast.Load):
            allowed = (isinstance(parent, ast.Attribute) and parent.value is node
                       and parent.attr in holder_fields | methods)
            allowed = allowed or (isinstance(parent, ast.Compare) and parent.left is node
                and len(parent.ops) == 1 and isinstance(parent.ops[0], ast.Is)
                and len(parent.comparators) == 1 and isinstance(parent.comparators[0], ast.Constant)
                and parent.comparators[0].value is None)
            allowed = allowed or (isinstance(parent, ast.Call) and name(parent.func, 'exclusions')
                and len(parent.args) == 2 and parent.args[0] is node and name(parent.args[1], 'custody')
                and not parent.keywords)
            allowed = allowed or (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute)
                and name(parent.func.value, 'contexts') and parent.func.attr == 'append'
                and parent.args == [node] and not parent.keywords)
            allowed = allowed or (isinstance(parent, ast.Assign)
                and ast.dump(parent, include_attributes=False) == ast.dump(
                    ast.parse('contexts[-1] = current').body[0], include_attributes=False))
            assert allowed, ('release view escape through current', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'view':
            raise AssertionError(('release view escape or mutation of alias', node.lineno))
        if isinstance(node, ast.Name) and node.id == 'rows':
            allowed = False
            if isinstance(node.ctx, ast.Store):
                allowed = (scope == 'project' and isinstance(parent, ast.Assign) and parent.targets == [node]
                           and isinstance(parent.value, ast.List) and not parent.value.elts)
                if allowed:
                    collections.append(parent)
            elif isinstance(node.ctx, ast.Load):
                if scope == 'project':
                    if isinstance(parent, ast.Attribute):
                        call = parents[parent]
                        if rows_append(call):
                            value = call.args[0]
                            allowed = run_call(value) or (isinstance(value, ast.Attribute)
                                      and name(value.value, 'current') and value.attr == 'view')
                    elif isinstance(parent, ast.Dict) and isinstance(parents[parent], ast.Return):
                        allowed = any(value is node and string(key) and key.value == 'small_changes'
                                      for key, value in zip(parent.keys, parent.values))
            assert allowed, ('release view escape through rows', node.lineno)
        if isinstance(node, ast.Attribute) and node.attr == 'run':
            call = parent
            assert (scope == 'project' and run_call(call) and call.func is node
                    and ((rows_append(parents[call]) and parents[call].args == [call])
                         or isinstance(parents[call], ast.Expr))), (
                        'release view escape through run result', node.lineno)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or node.attr != 'view':
            continue
        parent, scope = parents[node], qualified(node)
        assert ((name(node.value, 'self') and scope.startswith('Row.'))
                or (name(node.value, 'current') and scope == 'project')), (
                    'release view receiver is not admitted', node.lineno)
        if isinstance(node.ctx, ast.Store):
            assert (scope == 'Row.__init__' and isinstance(parent, ast.Assign) and parent.targets == [node]
                    and literal_keys(parent.value)), ('unrecognized release view replacement', node.lineno)
            initializers.append(parent)
        elif isinstance(parent, ast.Subscript) and parent.value is node:
            assert string(parent.slice), ('unrecognized release view key', node.lineno)
            if not isinstance(parent.ctx, ast.Load):
                statement = parents[parent]
                assert (isinstance(parent.ctx, ast.Store) and isinstance(statement, ast.Assign)
                        and statement.targets == [parent]), ('unrecognized release subscript mutation', node.lineno)
        elif isinstance(parent, ast.Attribute):
            call = parents[parent]
            assert isinstance(call, ast.Call) and call.func is parent, ('unrecognized release view method', node.lineno)
            if parent.attr == 'update':
                assert (len(call.args) <= 1 and all(literal_keys(arg) for arg in call.args)
                        and all(keyword.arg is not None for keyword in call.keywords)), (
                            'unrecognized release view update', node.lineno)
            elif parent.attr == 'get':
                assert (1 <= len(call.args) <= 2 and string(call.args[0]) and not call.keywords), (
                    'unrecognized release view read', node.lineno)
            else:
                assert (parent.attr == 'pop' and scope == 'Row.finalize_writer_release'
                        and len(call.args) == 2 and string(call.args[0])
                        and isinstance(call.args[1], ast.Constant) and call.args[1].value is None
                        and not call.keywords and isinstance(parents[call], ast.Expr)), (
                            'unrecognized release view call', node.lineno)
        elif isinstance(parent, ast.Return) and view(node) and scope == 'Row.run':
            continue
        else:
            assert (scope == 'project' and name(node.value, 'current') and rows_append(parent)
                    and parent.args == [node]), ('release view escape', node.lineno)

    def proof_read(node):
        return (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and name(node.value, 'self') and node.attr == '_verification_proof')

    def positive(test):
        candidates = test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) else [test]
        return any(isinstance(item, ast.Compare) and proof_read(item.left) and len(item.ops) == 1
                   and isinstance(item.ops[0], ast.IsNot) and len(item.comparators) == 1
                   and isinstance(item.comparators[0], ast.Constant) and item.comparators[0].value is None
                   for item in candidates)

    for token in ast.walk(tree):
        parent = parents.get(token)
        if isinstance(token, ast.keyword) and token.arg in keys:
            raise AssertionError(('unrecognized release keyword', token.arg, token.lineno))
        if isinstance(token, ast.Attribute) and token.attr in keys and isinstance(token.ctx, (ast.Store, ast.Del)):
            raise AssertionError(('unrecognized release attribute write', token.attr, token.lineno))
        if not string(token) or token.value not in keys:
            continue
        removal = False
        if isinstance(parent, ast.Subscript) and parent.slice is token:
            statement = parents[parent]
            assert (view(parent.value) and isinstance(parent.ctx, ast.Store)
                    and isinstance(statement, ast.Assign) and statement.targets == [parent]), (
                        'unrecognized release subscript write', token.lineno)
        elif (isinstance(parent, ast.Call) and parent.args and parent.args[0] is token
              and isinstance(parent.func, ast.Attribute)):
            statement = parents[parent]
            assert (view(parent.func.value) and parent.func.attr == 'pop' and len(parent.args) == 2
                    and isinstance(parent.args[1], ast.Constant) and parent.args[1].value is None
                    and not parent.keywords and isinstance(statement, ast.Expr)), (
                        'unrecognized release mutation call', token.lineno)
            removal = True
        else:
            raise AssertionError(('unrecognized release key use', token.value, token.lineno))
        chain, owner = ancestors(statement), qualified(statement)
        assert owner == 'Row.finalize_writer_release', ('release writer', owner, token.lineno)
        writes.append((owner, token.lineno))
        writers.add(next(node for node in chain if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))))
        if removal:
            continue
        guarded, child = False, statement
        for ancestor in chain:
            if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                break
            if isinstance(ancestor, ast.If):
                assert not (child in ancestor.orelse and any(proof_read(read) for read in ast.walk(ancestor.test))), (
                    'release proof polarity: orelse of proof-reading If', token.lineno)
                guarded = guarded or (child in ancestor.body and positive(ancestor.test))
            child = ancestor
        assert guarded, ('release proof polarity: positive body gate required', token.lineno)

    assert len(initializers) == 1 and len(collections) == 1, ('release view initialization', len(initializers), len(collections))
    assert writes and len(writers) == 1, ('release function definitions', len(writers))
    assert_custody_channel(tree, parents, qualified)
    return writes


def assert_custody_channel(tree, parents, qualified):
    """Secondary syntax checks only; the runtime table owns control-flow safety."""
    def shape(node):
        return ast.dump(node, include_attributes=False)

    def expression(source):
        return shape(ast.parse(source, mode='eval').body)

    definitions = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_WriterCustody']
    assert len(definitions) == 1, 'release custody record definition'
    record = definitions[0]
    assert (not record.decorator_list and len(record.bases) == 1
            and isinstance(record.bases[0], ast.Name) and record.bases[0].id == 'NamedTuple'), (
                'release custody record must be immutable')
    fields = [node.target.id for node in record.body if isinstance(node, ast.AnnAssign)
              and isinstance(node.target, ast.Name)]
    assert fields == ['request_id', 'writer', 'message_present', 'state_head', 'history_verified', 'released'], (
        'release custody record fields')
    assert all(isinstance(node, ast.AnnAssign) or (
        isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
        for node in record.body), 'release custody record body'

    # This small authority consumer admits only this complete parsed shape,
    # including its bindings and calls. Checking selected keyword spellings
    # cannot classify unpacking, aliases or an injected replacement statement.
    consumer = ast.parse('''
def exclusions(state, custody):
    result = {team + "/" + role for team in active_teams(state) for role in ("orchestrator", "decider")}
    captured = set()
    for facts in custody:
        require(type(facts) is _WriterCustody, "unverified writer custody input")
        if facts.state_head != state["head"]:
            continue
        captured.add(facts.request_id)
        row = state["requests"][facts.request_id]
        released = not row.get("lifecycle_unknown") and row["resolution"] is not None and row["resolution"]["kind"] in {"complete", "blocked"}
        if not released and (facts.message_present or row["routed"] is not None) and not facts.released:
            result.add(facts.writer)
    absent = {facts.request_id for facts in custody if facts.state_head == state["head"]
              and facts.history_verified and not facts.message_present}
    for key, row in state["requests"].items():
        if key in absent and not row.get("lifecycle_unknown") and row["intent"] is None and row["start"] is None:
            continue
        canonical_release = closed(row) and row["resolution"]["kind"] in {"complete", "blocked"}
        if "small_change" in row and not canonical_release and (
                key not in captured or row.get("lifecycle_unknown") or row["routed"] is None):
            plan = life.raw_value(row["small_change"]["registration"]["proposal"])["plan"]
            result.add(row["request"]["team"] + "/lane/" + plan["writing_lanes"][0]["lane"])
    return sorted(result)
''').body[0]
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'exclusions']
    assert len(definitions) == 1 and shape(definitions[0]) == shape(consumer), (
        'release custody consumer has an unadmitted shape')
    constructor = expression('_WriterCustody(self.key, self.writer, identifier("scw", self.row) in self.records, '
                             'self.state["head"], history_verified, released)')
    collection_initializers = []
    for node in ast.walk(tree):
        parent = parents.get(node)
        scope = qualified(node)
        if ((isinstance(node, ast.Attribute) and node.attr == 'finalize_writer_release')
                or (isinstance(node, ast.Name) and node.id == 'finalize_writer_release')):
            assert not isinstance(node.ctx, (ast.Store, ast.Del)), ('release finalizer rebinding', node.lineno)
        if ((isinstance(node, ast.Attribute) and node.attr == '_replace')
                or (isinstance(node, ast.Name) and node.id == '_replace')):
            raise AssertionError(('release custody replacement is not admitted', node.lineno))
        if isinstance(node, ast.Name) and node.id == '_WriterCustody':
            assert isinstance(node.ctx, ast.Load) and (
                (scope == 'Row.finalize_writer_release' and isinstance(parent, ast.Call) and parent.func is node
                 and shape(parent) == constructor and isinstance(parents.get(parent), ast.Return))
                or (scope == 'exclusions' and isinstance(parent, ast.Compare))), 'release custody constructor escape'
        if isinstance(node, ast.alias):
            assert (node.asname or node.name) not in {'_WriterCustody', 'exclusions', 'project', 'Row'}, (
                'release custody import rebinding')
        if isinstance(node, ast.Attribute) and node.attr in {'_custody', '_WriterCustody'}:
            if isinstance(node.ctx, ast.Store):
                admitted = {
                    'Row.__init__': {'None'},
                    'Row.run': {'self.finalize_writer_release()'},
                    'Row.clear_writer_release': {'self.finalize_writer_release(clear_only=True)'},
                }
                assert (isinstance(node.value, ast.Name) and node.value.id == 'self'
                        and isinstance(parent, ast.Assign) and parent.targets == [node]
                        and shape(parent.value) in {expression(value) for value in admitted.get(scope, set())}), (
                            'release custody write', node.lineno)
            else:
                collected = (scope == 'project' and shape(node) == expression('current._custody')
                        and isinstance(parent, ast.Call) and shape(parent) == expression('custody.append(current._custody)')
                        and isinstance(parents[parent], ast.Expr))
                head = (scope == 'project' and isinstance(parent, ast.Attribute)
                        and shape(parent) == expression('current._custody.state_head'))
                replaced = (scope == 'project' and isinstance(parent, ast.Assign)
                            and shape(parent) == shape(ast.parse('custody[-1] = current._custody').body[0]))
                assert collected or head or replaced, ('release custody escape', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'custody':
            if scope == 'exclusions':
                continue
            admitted = (scope == 'project' and isinstance(node.ctx, ast.Store)
                        and isinstance(parent, ast.Assign) and parent.targets == [node]
                        and shape(parent.value) == expression('[]'))
            if admitted:
                collection_initializers.append(node)
            if scope == 'project' and isinstance(node.ctx, ast.Load):
                admitted = (isinstance(parent, ast.Attribute) and isinstance(parents[parent], ast.Call)
                            and shape(parents[parent]) == expression('custody.append(current._custody)')
                            and isinstance(parents[parents[parent]], ast.Expr))
                admitted = admitted or (isinstance(parent, ast.Call)
                                        and shape(parent) == expression('exclusions(planning, custody)'))
                statement = parents.get(parent)
                admitted = admitted or (isinstance(parent, ast.Subscript) and isinstance(statement, ast.Assign)
                    and shape(statement) == shape(ast.parse('custody[-1] = current._custody').body[0]))
            assert admitted, ('release custody collection escape', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'exclusions' and isinstance(node.ctx, ast.Load):
            assert (scope == 'project' and isinstance(parent, ast.Call)
                    and shape(parent) == expression('exclusions(planning, custody)')), 'release custody consumer escape'
    assert len(collection_initializers) == 1, 'release custody collection must have one initialization'


def test_latch_release_assignments_require_one_proof_reading_function():
    # Tracked source is ordinary, cross-platform test input.
    assert_latch_release_structure((ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8'))


@pytest.mark.parametrize('line', [
    'self.view.update(route_receipt=self._writer_receipt, writer_publication_verified=True)',
    'self.view.update({"route_receipt": self._writer_receipt})',
    'self.view.setdefault("route_receipt", self._writer_receipt)',
    'self.view.__setitem__("route_receipt", self._writer_receipt)',
    'self.view["route_receipt"] = self.view.pop("route_receipt", None)',
    'self.view["writer_publication_verified"] = self._writer_verified',
    'self.view["writer_publication_verified"] = False',
    'self.view["route_receipt"]: object = self._writer_receipt',
    'self.view["route_receipt"] += self._writer_receipt',
    'del self.view["route_receipt"]',
    'self.view = {"route_receipt": self._writer_receipt}',
    'self.view = dict(writer_publication_verified=self._writer_verified)',
    'setattr(self, "route_receipt", self._writer_receipt)',
    'self.view.route_receipt = self._writer_receipt',
    'key = "route_receipt"; self.view[key] = self._writer_receipt',
    'publish_release(self.view, "route_receipt", self._writer_receipt)',
    'self.view["route_" + "receipt"] = self._writer_receipt',
    'self.view.update(self._writer_fields)',
    'self.view = self._writer_fields',
    'alias = self.view; alias.update(self._writer_fields)',
    'self.view.clear()',
    'self.view |= self._writer_fields',
], ids=['update-keywords', 'update-dict', 'setdefault', 'setitem', 'pop-reassign', 'nonliteral',
        'false-value', 'annotated', 'augmented', 'delete', 'dict-display', 'dict-call', 'setattr',
        'attribute-store', 'key-alias', 'unknown-call', 'computed-key', 'opaque-update',
        'opaque-replacement', 'view-alias', 'clear', 'inplace-update'])
def test_latch_structure_rejects_release_mutations(line):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source += '\nclass Bypass:\n    def recover(self):\n        ' + line + '\n'
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('class_name', ['Bypass', 'Row'])
def test_latch_structure_rejects_same_bare_function_name_in_another_class(class_name):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source += '''
class CLASS_NAME:
    def finalize_writer_release(self):
        if self._verification_proof is not None:
            self.view["writer_publication_verified"] = True
'''.replace('CLASS_NAME', class_name)
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


def test_latch_structure_rejects_release_outside_the_proof_if():
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    row = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == 'Row')
    release = next(node for node in row.body if isinstance(node, ast.FunctionDef)
                   and node.name == 'finalize_writer_release')
    lines = source.splitlines(keepends=True)
    lines.insert(release.lineno, '        self.view["writer_publication_verified"] = True\n')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(''.join(lines))


def latch_insert(source, qualified, snippet):
    """Insert static text before a function's final return, or at a class/body end."""
    tree = ast.parse(source)
    parts = qualified.split('.')
    nodes = tree.body
    for part in parts:
        node = next(item for item in nodes if isinstance(item, (ast.ClassDef, ast.FunctionDef))
                    and item.name == part)
        nodes = node.body
    lines = source.splitlines(keepends=True)
    indent = ' ' * (node.col_offset + 4)
    position = (node.body[-1].lineno - 1 if isinstance(node, ast.FunctionDef)
                and isinstance(node.body[-1], ast.Return) else node.end_lineno)
    lines.insert(position, ''.join(indent + line + '\n' for line in snippet.splitlines()))
    return ''.join(lines)


LATCH_REVIEW_MUTATIONS = (
    'collection-reset', 'skipped-appends', 'self-finalizer-rebind', 'current-finalizer-rebind',
    'class-finalizer-rebind', 'class-field-finalizer-rebind', 'replace-released',
    'walrus-released-assign', 'walrus-released-update', 'walrus-released-condition',
    'walrus-history-assign', 'walrus-history-update', 'walrus-history-condition',
    'argon-forged-proof', 'argon-clear-flags',
)


def latch_review_mutation(source, variant):
    """Trusted reviewer mutation recipes for temporary RED runs, never product configuration."""
    assert variant in LATCH_REVIEW_MUTATIONS

    def once(old, new):
        assert source.count(old) == 1, (variant, old)
        return source.replace(old, new)

    if variant == 'collection-reset':
        line = '    final = fresh._Operation(reference_cache=reference_cache)\n'
        return once(line, '    custody = []\n' + line)
    if variant == 'skipped-appends':
        lines, changed = [], 0
        for line in source.splitlines(keepends=True):
            if line.lstrip().startswith('custody.append('):
                indent = line[:len(line) - len(line.lstrip())]
                lines.extend([indent + 'if False:\n', '    ' + line])
                changed += 1
            else:
                lines.append(line)
        assert changed == 3
        return ''.join(lines)
    if variant == 'self-finalizer-rebind':
        header = '    def run(self, mutate):\n'
        return once(header, header + '        original = self.finalize_writer_release\n'
                    '        self.finalize_writer_release = lambda **kw: original(**kw)._replace(released=True)\n')
    if variant == 'current-finalizer-rebind':
        line = '                        rows.append(current.run(True))\n'
        return once(line, '                        original = current.finalize_writer_release\n'
                    '                        current.finalize_writer_release = lambda **kw: original(**kw)._replace(released=True)\n'
                    + line)
    if variant == 'class-finalizer-rebind':
        header = '    def run(self, mutate):\n'
        return once(header, header + '        original = Row.finalize_writer_release\n'
                    '        Row.finalize_writer_release = lambda holder, **kw: original(holder, **kw)._replace(released=True)\n')
    if variant == 'class-field-finalizer-rebind':
        return latch_insert(source, 'Row', '_original_finalizer = finalize_writer_release\n'
            'def replacement_finalizer(self, **kw):\n'
            '    return self._original_finalizer(**kw)._replace(released=True)\n'
            'finalize_writer_release = replacement_finalizer')
    if variant == 'replace-released':
        return once('history_verified, released)', 'history_verified, released)._replace(released=True)')
    if variant == 'argon-forged-proof':
        line = '        self._verification_proof = None\n        self.clear_writer_release()\n'
        return once(line, line + '        self._verification_proof = True\n'
                    '        self._writer_verified = True\n'
                    '        self._writer_target_current = True\n'
                    '        self._writer_receipt = True\n')
    if variant == 'argon-clear-flags':
        return latch_insert(source, 'Row.finalize_writer_release',
            'if self._verification_proof is not None:\n'
            '    self.view["writer_publication_verified"] = True\n'
            '    self.view["route_receipt"] = self._writer_receipt')
    _, field, form = variant.split('-')
    field = 'history_verified' if field == 'history' else 'released'
    expression = '(' + field + ' := True)'
    snippet = {'assign': 'self.view["state"] = ' + expression,
               'update': 'self.view.update(state=' + expression + ')',
               'condition': 'if ' + expression + ':\n    self.view["state"] = "held"'}[form]
    return latch_insert(source, 'Row.finalize_writer_release', snippet)


@pytest.mark.parametrize('qualified, snippet', [
    ('project', 'custody = []'),
    ('Row.run', 'self.finalize_writer_release = lambda **kw: forged'),
    ('project', 'current.finalize_writer_release = lambda **kw: forged'),
    ('project', 'Row.finalize_writer_release = lambda **kw: forged'),
    ('Row', 'finalize_writer_release = lambda **kw: forged'),
    ('Row.run', 'self.view["state"] = saved._replace(released=True)'),
    ('Row.run', 'self.view["state"] = saved._replace(custody=True)'),
])
def test_latch_secondary_syntax_bans(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(latch_insert(source, qualified, snippet))


@pytest.mark.parametrize('snippet', [
    'facts = facts._replace(**{"released": True})',
    'changes = {"released": True}; facts = facts._replace(**changes)',
    'facts = facts._replace(**dict([(key, True)]))',
    'facts = facts._replace(*(), **{"released": True})',
    'facts = facts._replace(*arguments)',
    'replace = facts._replace; facts = replace(released=True)',
    'replace = facts._replace; facts = replace(**changes)',
    'replace = facts._replace; facts = replace(*arguments, **changes)',
    'facts = getattr(facts, "_replace")(**changes)',
    'setattr(facts, "released", True)',
    'object.__setattr__(facts, "released", True)',
    'alias = facts; facts = alias._replace(**changes)',
    'alias = facts; alias.released = True',
    'facts.released = True',
    'facts = forged',
    'custody = forged',
    'custody[0] = forged',
    'for alias in custody:\n    alias = alias._replace(**changes)',
], ids=['unpacked-literal', 'unpacked-variable', 'dynamic-keywords', 'star-and-unpack', 'starred',
        'bound-alias', 'unpacked-alias', 'starred-alias', 'getattr', 'setattr', 'object-setattr',
        'record-alias', 'alias-write', 'attribute-write', 'record-rebinding', 'collection-rebinding',
        'collection-write', 'iteration-alias'])
def test_latch_custody_consumer_rejects_unadmitted_shapes(snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    anchor = '    for facts in custody:\n'
    assert source.count(anchor) == 1
    source = source.replace(anchor, anchor + ''.join('        ' + line + '\n' for line in snippet.splitlines()))
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('qualified, snippet', [
    ('Row', 'def recover(holder):\n    publish(holder)'),
    ('project', 'holder = context(); publish(holder)'),
    ('Row.run', 'publish(self.clear_writer_release)'),
])
def test_latch_argon_holder_syntax_bans(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(latch_insert(source, qualified, snippet))


@pytest.mark.parametrize('gate', [
    'if self._verification_proof is None or clear_only:\n    WRITE',
    'if self._verification_proof is None:\n    WRITE',
    'if self._verification_proof is not None:\n    pass\nelse:\n    WRITE',
    'if self._verification_proof is not None:\n    if self._verification_proof is not None:\n        pass\n    else:\n        WRITE',
    'if self._verification_proof is not None or clear_only:\n    WRITE',
    'if not (self._verification_proof is None):\n    WRITE',
], ids=['clear-only-arm', 'none-body', 'positive-else', 'nested-proof-else', 'positive-or', 'unadmitted-negation'])
def test_latch_r3_rejects_wrong_proof_polarity(gate):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    writes = 'self.view["writer_publication_verified"] = True; self.view["route_receipt"] = self._writer_receipt'
    snippet = gate.replace('WRITE', writes)
    if gate.startswith('if self._verification_proof is None or clear_only:'):
        # Place it after removals and before the non-clearing verification arm,
        # so the inserted grant survives recovery rather than being dead code.
        row = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == 'Row')
        release = next(node for node in row.body if isinstance(node, ast.FunctionDef)
                       and node.name == 'finalize_writer_release')
        clear = next(node for node in ast.walk(release) if isinstance(node, ast.If)
                     and isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not)
                     and isinstance(node.test.operand, ast.Name) and node.test.operand.id == 'clear_only')
        lines = source.splitlines(keepends=True)
        lines.insert(clear.lineno - 1, ''.join(' ' * clear.col_offset + line + '\n'
                                             for line in snippet.splitlines()))
        source = ''.join(lines)
    else:
        source = latch_insert(source, 'Row.finalize_writer_release', snippet)
    with pytest.raises(AssertionError, match='release proof polarity'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('line', [
    'setattr(self, "view", saved)',
    'getattr(self, "view").update(saved)',
    'self.__dict__["view"] = saved',
    'getattr(self, "vi" + "ew").update(saved)',
    'vars(self)["view"] = saved',
], ids=['setattr-view', 'getattr-view', 'dunder-dict-view', 'computed-getattr', 'vars-view'])
def test_latch_r3_rejects_reflective_view_access(line):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, 'Row', 'def recover(self, saved):\n    ' + line)
    with pytest.raises(AssertionError, match='release reflection'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('protocol', ['__reduce__()', '__reduce_ex__(4)', '__getstate__()',
                                     'verification_pass.__self__.__reduce_ex__(4)',
                                     'verification_pass.__self__.__reduce__()'])
def test_latch_rejects_unadmitted_state_protocols(protocol):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    state = '' if protocol == '__getstate__()' else '[2]'
    source = latch_insert(source, 'Row', 'def recover(self, saved):\n'
                          '    self.' + protocol + state + '["vi" + "ew"].update(saved)')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('snippet', [
    'answer = project(lifecycle, store)\nfor item in answer["small_changes"]:\n'
    '    item.update(saved)\nanswer["planning_exclusions"] = exclusions(state, answer["small_changes"])',
    'callback = project\nanswer = callback(lifecycle, store)',
    'answer = dispatcher.project(lifecycle, store)\nfor item in answer["small_changes"]:\n'
    '    item.update(saved)',
])
def test_latch_rejects_unadmitted_projection_aliases(snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source += '\ndef bypass(lifecycle, store, state, saved):\n' + ''.join(
        '    ' + line + '\n' for line in snippet.splitlines())
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('qualified, snippet', [
    ('Row.run', 'self._custody = forged'),
    ('Row.run', 'alias = self._custody'),
    ('project', 'alias = custody; alias.clear()'),
    ('project', 'current._custody = forged'),
    ('project', 'custody.append(_WriterCustody(key, writer, True, state_head, True, True))'),
    ('project', 'publish(custody)'),
    ('project', 'callback = exclusions'),
])
def test_latch_rejects_unadmitted_custody_transfers(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, qualified, snippet)
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


def test_latch_exclusions_refuses_presentation_dicts():
    # Run the public consumer in an isolated interpreter, without platform I/O.
    driver = '''
import sys
sys.path.insert(0, sys.argv[1])
from hierarchy_small_change_dispatch import exclusions
state = {"requests": {"request": {"request": {"team": "a"}, "resolution": None,
    "routed": {}, "intent": None, "start": None, "small_change": {}}}}
view = {"request_id": "request", "writer": "a/lane/fix", "writer_message_present": True,
    "route_receipt": "forged", "writer_publication_verified": True}
try:
    exclusions(state, [view])
except ValueError as exc:
    assert str(exc) == "unverified writer custody input", str(exc)
else:
    raise AssertionError("presentation dictionaries granted writer release")
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', driver, str(ROOT / 'tools')],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('qualified, snippet', [
    ('project', 'for view in rows:\n    view.update(fields)'),
    ('project', 'for view in rows:\n    view["route_" + "receipt"] = True'),
    ('project', 'for alias in rows:\n    alias.update(fields)'),
    ('project', 'alias = rows[0]; alias.update(fields)'),
    ('project', 'alias = current.run(True); alias.update(fields)'),
    ('exclusions', 'view.update(fields)'),
    ('exclusions', 'view["route_" + "receipt"] = True'),
    ('exclusions', 'for alias in rows:\n    alias.update(fields)'),
    ('project', 'alias = rows; alias.append(fields)'),
    ('project', 'callback = current.run; callback(True)'),
    ('project', 'publish(current)'),
    ('Row.run', 'alias = self.view; alias.update(fields)'),
    ('Row.run', 'publish(self)'),
], ids=['rows-update', 'rows-computed-store', 'rows-renamed-alias', 'rows-index-alias',
        'run-alias', 'existing-alias-update', 'existing-alias-computed-store', 'consumer-renamed-alias',
        'collection-alias', 'run-method-alias', 'current-holder-escape', 'view-local-alias', 'self-holder-escape'])
def test_latch_r3_rejects_escaped_view_mutation(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, qualified, snippet)
    with pytest.raises(AssertionError, match='release view escape'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('gate', ['self._verification_proof is not None',
                                'self._verification_proof is not None and self._writer_verified'])
def test_latch_r3_admits_exact_positive_proof_body(gate):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, 'Row.finalize_writer_release', 'if ' + gate + ':\n'
                          '    self.view["writer_publication_verified"] = self._writer_verified\n'
                          '    self.view["route_receipt"] = self._writer_receipt')
    assert_latch_release_structure(source)


@pytest.mark.parametrize('variant', ['opaque-return', 'early-view-return', 'run-redefinition',
                                     'row-redefinition', 'project-redefinition', 'consumer-redefinition'])
def test_latch_r3_rejects_unadmitted_producers(variant):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    if variant == 'opaque-return':
        source = latch_insert(source, 'Row.run', 'return fields')
    elif variant == 'early-view-return':
        source = latch_insert(source, 'Row.run', 'if mutate:\n    return self.view')
    elif variant == 'run-redefinition':
        source = latch_insert(source, 'Row', 'def run(self, mutate):\n    return fields')
    elif variant == 'row-redefinition':
        source += '\nclass Row:\n    pass\n'
    else:
        function = 'project' if variant == 'project-redefinition' else 'exclusions'
        source += '\ndef ' + function + '(*args, **kwargs):\n    return fields\n'
    with pytest.raises(AssertionError, match='release producer'):
        assert_latch_release_structure(source)


SECTIONS = ("Role contract", "Approved scope", "Source identity", "Open obligations",
            "Dependencies", "Unread work", "Evidence references")
ENDPOINT = "a/lane/f2"
AS_OF = "2026-11-07T12:00:00Z"
secure_publication = pytest.mark.skipif(os.name != "posix", reason="secure brief publication requires POSIX dir_fd support")


def cli(*args, expect=0):
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), *map(str, args)],
                          capture_output=True, text=True, timeout=30,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert proc.returncode == expect, proc.stdout + proc.stderr
    assert not proc.stderr, proc.stderr
    return json.loads(proc.stdout)


def compose(root, endpoint=ENDPOINT, expect=0, **flags):
    argv = ["compose", "--root", root, "--initiative", "a", "--endpoint", endpoint]
    for key, value in flags.items():
        argv += ["--" + key.replace("_", "-"), value]
    return cli(*argv, expect=expect)


def sections(brief):
    result, current = {}, None
    for line in Path(brief["path"]).read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:]
            result[current] = []
        elif line.startswith("- {"):
            result[current].append(json.loads(line[2:]))
    assert tuple(result) == SECTIONS
    return result


@secure_publication
@pytest.mark.parametrize('damage', ['changed', 'missing'])
def test_latch_r3_authoritative_prepare_names_open_dispatch(pilot, damage):
    from tools import hierarchy_fresh_brief as fresh

    root, reference = pilot
    identifier = 'latch-r3-open-dispatch'
    invoke(root, 'publish', message(identifier=identifier, kind='dispatch', brief=reference))
    packet = Path(reference['path'])
    if damage == 'changed':
        packet.write_bytes(b'changed open dispatch\n')
    else:
        packet.unlink()
    args = SimpleNamespace(root=str(root), initiative='a', endpoint=ENDPOINT, lifecycle=None,
                           delivery_dir=None, as_of=None, target_generation=None)
    before = files(root.parent)
    with pytest.raises(fresh.UnverifiedAttachment) as caught:
        fresh.prepare(args, _request_id='latch-r3-fixture')
    assert caught.value.message_id == identifier
    assert str(caught.value) == 'authoritative brief attachment is unverified'
    assert files(root.parent) == before


@secure_publication
@pytest.mark.parametrize('damage', ['missing', 'oversized'])
def test_latch_standalone_unavailable_receipt_evidence_is_unverified(tmp_path, damage):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / 'packet.md'
    packet.write_text(json.dumps({'schema': 'aegis.hierarchy-job-packet/v1', 'recipe': 'tests',
                                 'checkout': str(tmp_path), 'commit': 'a' * 40, 'tree': 'b' * 40}))
    evidence = tmp_path / 'log'
    evidence.write_bytes(b'original receipt evidence')
    reference = ref(evidence)
    invoke(root, 'publish', message(recipient='a/root', identifier='latch-job',
                                    kind='job_request', brief=ref(packet)))
    invoke(root, 'publish', message('a/root', 'a/orchestrator', identifier='latch-receipt',
        kind='job_receipt', in_reply_to='latch-job', receipt={'state': 'started', 'evidence': [reference]}))
    if damage == 'missing':
        evidence.unlink()
    else:
        with evidence.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
    rows = sections(compose(root, 'a/orchestrator')['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared') == reference
               for row in rows['Evidence references'])


@secure_publication
@lifecycle_only
def test_latch_standalone_missing_policy_authority_is_unverified(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    fixture = tmp_path / 'lifecycle-fixture'
    fixture.mkdir()
    ledger = Ledger(fixture)
    policy = json.loads((ledger.path / 'policy.json').read_text())
    missing = Path(policy['authority'][0]['path'])
    missing.unlink()
    rows = sections(compose(root, 'a/orchestrator', lifecycle=ledger.path)['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared', {}).get('path') == str(missing)
               for row in rows['Evidence references'])


@secure_publication
@lifecycle_only
def test_latch_standalone_unsettled_terminal_deleted_evidence_is_unverified(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    fixture = tmp_path / 'terminal-fixture'
    fixture.mkdir()
    ledger = Ledger(fixture)
    value = request('unsettled-terminal')
    ledger.ready(value)
    ledger.intent(value, intent_id='terminal-effect')
    proof = fixture / 'terminal-proof'
    proof.write_bytes(b'original terminal evidence\n')
    reference = ref(proof)
    ledger.event('terminal', actor=ledger.operator, result=raw_request({
        'request_sha256': raw_request(value)['sha256'], 'intent_id': 'terminal-effect',
        'outcome': 'passed', 'exit_code': 0, 'source': value['source'], 'evidence': [reference]}),
        **ledger.target(value))
    terminal = sorted((ledger.path / 'events').glob('*.json'))[-1]
    proof.unlink()
    rows = sections(compose(root, 'a/orchestrator', lifecycle=ledger.path)['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared') == reference
               and row['ref'] == ref(terminal) for row in rows['Evidence references'])
    assert any(row.get('request_id') == value['id'] for row in rows['Open obligations'])


@secure_publication
@pytest.mark.parametrize('stale_first', [False, True])
def test_latch_standalone_stale_note_is_unverified_independent_of_order(pilot, stale_first):
    root, reference = pilot
    current = Path(reference['path'])
    stale = dict(reference)
    invoke(root, 'publish', message(identifier='a-note' if stale_first else 'z-note',
                                  kind='brief', brief=stale))
    current.write_text('current note bytes')
    invoke(root, 'publish', message(identifier='z-note' if stale_first else 'a-note',
                                  kind='brief', brief=ref(current)))
    rows = sections(compose(root)['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared') == stale
               for row in rows['Evidence references'])
    assert any(row['kind'] == 'evidence' and row['ref'] == ref(current)
               for row in rows['Evidence references'])


def files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def ref(path):
    return {"path": str(path), "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}


def seed_messages(root, requests):
    """One isolated interpreter per batch; public API validation stays in-process."""
    driver = r'''
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hierarchy_mailbox import Mailbox,writer_lock
root=Path(sys.argv[2])
with writer_lock(root):
    mailbox=Mailbox(root)
    for value in json.load(sys.stdin):
        mailbox.publish(value)
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT / "tools"), str(root)],
                   input=json.dumps(list(requests)), text=True, check=True, timeout=180,
                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def seed_completed_requests(ledger, count):
    """Build fixture envelopes here; the isolated recorder needs only tools/."""
    events = []

    class SetupLedger(Ledger):
        def cli(self, *args, expect=0):
            if args[0] != "record" or expect != 0:
                raise ValueError("bulk lifecycle setup only collects successful record requests")
            events.append(json.loads(Path(args[2]).read_text()))

    setup = SetupLedger(ledger.tmp, initialize=False)
    for index in range(count):
        completed_request(setup, "done-%02d" % index)
    driver = r'''
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hierarchy_lifecycle import Lifecycle
lifecycle=Lifecycle(Path(sys.argv[2]))
for event in json.load(sys.stdin):
    lifecycle.record(event)
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT / "tools"), str(ledger.path)],
                   input=json.dumps(events), text=True, check=True, timeout=180,
                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


@pytest.fixture
def records(pilot, tmp_path):  # noqa: F811
    root, old_brief = pilot
    ledger = Ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    change.decide()
    change.admit()
    uncertain = ledger.ready(request("uncertain"))
    ledger.intent(uncertain)
    ledger.terminal(uncertain, outcome="unknown")
    ledger.publish(request("dependent", prerequisites=[change.value["id"]]))
    finished = ledger.ready(request("finished"))
    ledger.intent(finished, intent_id="finished-attempt")
    # The fixture's terminal helper deliberately uses attempt-1; use its public event method here.
    result = {"request_sha256": ledger.target(finished)["request_sha256"], "intent_id": "finished-attempt",
              "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": ledger.evidence}
    ledger.event("terminal", actor=ledger.operator, result=raw_request(result), **ledger.target(finished))
    ledger.accepted_delivery(finished)
    invoke(root, "publish", message(kind="dispatch", brief=old_brief))
    invoke(root, "publish", message(identifier="woken-note", body="SECRET_TRANSCRIPT_DO_NOT_INLINE"))
    delivery = tmp_path / "delivery"
    wake = delivery / "wakes" / ENDPOINT / "wake.json"
    wake.parent.mkdir(parents=True)
    wake.write_text(json.dumps({"schema": "aegis.hierarchy-delivery-receipt/v1", "endpoint": ENDPOINT,
                               "host": "host-one", "session": ENDPOINT, "generation": 1,
                               "at": "2026-11-07T00:00:00Z", "message_ids": ["woken-note"],
                               "wake_id": "wake-1", "state": "started"}))
    return root, ledger, change, wake


@lifecycle_only
def test_all_seven_items_reference_reverifiable_durable_records(records):
    root, ledger, change, wake = records
    answer = compose(root)
    brief = answer["brief"]
    rows = sections(brief)
    assert all(rows.values())
    assert answer["entries"] == sum(map(len, rows.values())) <= 256
    for group in rows.values():
        for item in group:
            assert item["ref"] == ref(item["ref"]["path"])
    assert rows["Role contract"][0]["ref"] == ref(ROOT / "tools/hierarchy_templates/roles/lane.md")
    scope = json.dumps(rows["Approved scope"])
    assert change.value["paths"][0] in scope
    assert change.value["continuation"]["expires_at"] in scope
    assert change.plan["request"]["sha256"] in scope
    assert change.row()["small_change"]["registration"]["proposal"]["sha256"] in scope
    assert '"small_change_admit"' in scope and '"small_change_decision"' in scope
    assert json.dumps(change.value["source"], sort_keys=True) in json.dumps(rows["Source identity"], sort_keys=True)
    assert any(row.get("request_id") == "dependent" and row.get("prerequisite") == change.value["id"]
               for row in rows["Dependencies"])
    evidence = json.dumps(rows["Evidence references"])
    assert str(ledger.evidence_path) in evidence
    assert all('"event_type": "' + kind + '"' in evidence for kind in ("small_change_admit", "terminal", "review"))
    body = Path(brief["path"]).read_text()
    assert "Resume path:" in body and "reconcile" in body
    assert "SECRET_TRANSCRIPT_DO_NOT_INLINE" not in body
    assert hashlib.sha256(body.encode()).hexdigest() == brief["sha256"]
    assert brief["sha256"] in Path(brief["path"]).name
    assert Path(brief["path"]).parent == root.parent / "briefs"
    assert Mailbox(root).brief(brief, verify=True) == body.encode()
    assert cli("verify", "--path", brief["path"], "--sha256", brief["sha256"])["ok"] is True


@lifecycle_only
def test_unknown_effects_and_woken_unread_are_never_dropped(records):
    root, _, _, wake = records
    rows = sections(compose(root)["brief"])
    assert any(row.get("request_id") == "uncertain" and row.get("state") == "unknown_effect"
               for row in rows["Open obligations"])
    assert any(row.get("message_id") == "woken-note" and row.get("state") == "woken"
               for row in rows["Unread work"])
    assert ref(wake) in [row["ref"] for row in rows["Evidence references"]]


@lifecycle_only
def test_determinism_and_no_store_mutations(records):
    root, _, _, _ = records
    before = files(root.parent)
    first = compose(root, as_of=AS_OF)
    raw = Path(first["brief"]["path"]).read_bytes()
    after = files(root.parent)
    assert after.pop(str(Path(first["brief"]["path"]).relative_to(root.parent))) == raw
    assert after == before
    assert compose(root, as_of=AS_OF) == first
    assert Path(first["brief"]["path"]).read_bytes() == raw


@secure_publication
def test_exact_entry_bound_and_overflow_leave_no_partial_output(pilot):  # noqa: F811
    root, _ = pilot
    initial = compose(root)
    needed = 256 - initial["entries"]
    seed_messages(root, (message(identifier="note-%03d" % index) for index in range(needed)))
    at_bound = compose(root)
    assert at_bound["entries"] == 256
    assert len(sections(at_bound["brief"])["Unread work"]) == needed
    invoke(root, "publish", message(identifier="overflow"))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds 256 entries"
    assert files(root.parent) == before


@secure_publication
def test_corruption_refuses_verify_and_mailbox_read(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    Path(brief["path"]).write_bytes(b"corrupted\n")
    assert cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"] == "brief sha256 mismatch"
    with pytest.raises(ValueError, match="^brief sha256 mismatch$"):
        Mailbox(root).brief(brief, verify=True)


@secure_publication
def test_handoff_carries_brief_and_successor_pages_inbox_losslessly(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    identifiers = ["note-%03d" % i for i in range(105)]
    seed_messages(root, (message(identifier=identifier) for identifier in identifiers))
    brief = compose(root)["brief"]
    assert [row["message_id"] for row in sections(brief)["Unread work"]] == identifiers
    result = handoff(tmp_path, {"schema": "aegis.hierarchy-handoff/v1", "host": "host-two",
                               "session": "successor", "outgoing_stopped": True,
                               "entries": [{"root": str(root), "endpoint": ENDPOINT, "briefs": [brief]}]}, 0)
    invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])
    seen, cursor = [], None
    for _ in range(8):
        flags = {"after": cursor} if cursor else {}
        page = invoke(root, "inbox", endpoint=ENDPOINT, include_briefs=True, limit=17, **flags)
        assert page["checkpoint_briefs"][0]["sha256"] == brief["sha256"]
        seen += [row["message"]["message_id"] for row in page["messages"]]
        cursor = page["next_after"]
        if cursor is None:
            break
    assert cursor is None and seen == identifiers


@pytest.mark.parametrize("endpoint", [ENDPOINT, "a/lane/review", "a/orchestrator", "a/front-door"])
@secure_publication
def test_contract_matches_role_kind_and_host_family(pilot, endpoint):  # noqa: F811
    root, _ = pilot
    write_plan(SimpleNamespace(base=root.parent), hierarchy="a", team="claude-code", stand_ins={})
    answer = compose(root, endpoint)
    body = Path(answer["brief"]["path"]).read_text()
    rows = sections(answer["brief"])
    expected = {ENDPOINT: ["lane.md"], "a/lane/review": ["lane.md", "reviewer.md"],
                "a/orchestrator": ["orchestrator.md"], "a/front-door": ["front-door.md"]}[endpoint]
    assert [Path(item["ref"]["path"]).name for item in rows["Role contract"]] == expected
    assert all(item["family"] == "claude" for item in rows["Role contract"])
    assert "<!-- host:" not in body
    assert any(row["ref"] == ref(root.parent / "host-plan.json") for row in rows["Evidence references"])


@pytest.mark.parametrize("flags,error", [
    ({"endpoint": "b/front-door"}, "endpoint is outside initiative a"),
    ({"lifecycle": "missing"}, "lifecycle directory unavailable"),
])
def test_invalid_inputs_refuse_without_writing(pilot, flags, error):  # noqa: F811
    root, _ = pilot
    if flags.get("lifecycle") == "missing":
        flags = {"lifecycle": str(root.parent / "missing-lifecycle")}
    before = files(root.parent)
    assert error in compose(root, expect=2, **flags)["error"]
    assert files(root.parent) == before


@secure_publication
def test_verify_detects_changed_reference_even_with_unchanged_brief(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    manifest = root / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    assert "reference sha256 mismatch" in cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"]


@secure_publication
def test_uncertain_jobs_keep_ids_hashes_and_v2_dependencies(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "packet.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v2", "recipe": "tests",
                                 "checkout": str(tmp_path), "commit": "a" * 40, "tree": "b" * 40,
                                 "after": {"message_id": "prior", "sha256": "c" * 64},
                                 "recipes_sha256": "d" * 64}))
    original = invoke(root, "publish", message(recipient="a/root", identifier="uncertain-job",
                                               kind="job_request", brief=ref(packet)))
    invoke(root, "publish", message("a/root", "a/orchestrator", identifier="lost-reply", kind="job_receipt",
                                    in_reply_to="uncertain-job", receipt={"state": "unknown", "reason": "lost reply"}))
    before = files(tmp_path)
    brief = compose(root, "a/orchestrator")["brief"]
    rows = sections(brief)
    job = next(row for row in rows["Open obligations"] if row.get("job_id") == "a/uncertain-job")
    assert job["state"] == "unknown" and job["ref"] == ref(original["path"])
    assert any(row.get("after") == {"message_id": "prior", "sha256": "c" * 64} and row["ref"] == ref(packet)
               for row in rows["Dependencies"])
    assert any(row.get("source", {}).get("commit") == "a" * 40 for row in rows["Source identity"])
    after = files(tmp_path)
    after.pop(str(Path(brief["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_recorded_reads_are_excluded_but_no_delivery_history_is_conservative(tmp_path):
    root, delivery, _ = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    brief = compose(root, "a/root")["brief"]
    aggregate = sections(brief)["Unread work"]
    assert len(aggregate) == 1 and aggregate[0]["state"] == "read_by_predecessor" and aggregate[0]["count"] == 1
    assert "receipt-note" not in json.dumps(sections(brief)["Unread work"])
    assert any(row.get("kind") == "delivery_read" for row in sections(brief)["Evidence references"])


@secure_publication
def test_run_root_resolves_initiative_base_and_runtime_pin(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    base = tmp_path / "initiatives" / "a"
    base.mkdir(parents=True)
    root.rename(base / "mailbox")
    setup = {"initiative": "a", "mailbox_root": str(base / "mailbox"), "delivery_dir": str(base / "delivery"),
             "source": str(ROOT), "source_commit": "e" * 40, "source_tree": "f" * 40}
    (base / "provision.json").write_text(json.dumps(setup))
    answer = compose(tmp_path)
    assert Path(answer["brief"]["path"]).parent == base / "briefs"
    sources = sections(answer["brief"])["Source identity"]
    assert any(row.get("source_commit") == "e" * 40 and row["ref"] == ref(base / "provision.json") for row in sources)


@lifecycle_only
def test_malformed_journal_refuses_without_creating_a_briefs_folder(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish()
    event = ledger.path / "events" / "000001.json"
    event.write_text("{}")
    before = files(tmp_path)
    assert "missing fields" in compose(root, expect=2)["error"]
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


@pytest.mark.parametrize("argv", [[], ["compose"], ["verify", "--path", "relative.md"]])
def test_malformed_cli_answers_as_json(argv):
    assert "required" in cli(*argv, expect=2)["error"]


def test_malformed_structured_packet_refuses_instead_of_dropping_dependencies(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "broken-packet.md"
    packet.write_text('{"schema":"aegis.hierarchy-job-packet/v2","after":')
    invoke(root, "publish", message(recipient="a/root", identifier="broken-job", kind="job_request", brief=ref(packet)))
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(packet) in error and "JSON" in error
    assert files(tmp_path) == before


@secure_publication
def test_failed_atomic_publication_leaves_no_brief_or_temporary_file(pilot):  # noqa: F811
    root, _ = pilot
    # Inject only at the OS boundary, then enter the actual CLI. No composer internals are replaced.
    driver = ("import os,runpy,sys\n"
              "def refuse(*args,**kwargs):\n    raise OSError('fixture replace refused')\n"
              "os.replace=refuse\n"
              "sys.argv=sys.argv[1:]\n"
              "runpy.run_path(sys.argv[0],run_name='__main__')\n")
    before = files(root.parent)
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(TOOL), "compose", "--root", str(root),
                           "--initiative", "a", "--endpoint", ENDPOINT], capture_output=True, text=True, timeout=15)
    assert proc.returncode == 3 and not proc.stderr
    assert json.loads(proc.stdout)["error"] == "brief publication failed: fixture replace refused"
    assert files(root.parent) == before
    assert list((root.parent / "briefs").iterdir()) == []


@lifecycle_only
@pytest.mark.parametrize("transition", ["disposition", "resolve"])
def test_next_request_origin_and_pending_obligation_are_the_creating_event(pilot, tmp_path, transition):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    first, following = request("first"), request("successor")
    ledger.publish(first)
    if transition == "resolve":
        ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "coordinator-1",
                     "next_decision": "resume", "condition": "ready", "evidence": ledger.evidence}, **ledger.target(first))
        blocker = ledger.status()["requests"]["first"]["resolution"]
        extra = {"blocker_sha256": hashlib.sha256(json.dumps(blocker, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    else:
        extra = {"status": "FINAL"}
    receipt = ledger.event(transition, resolution={"kind": "next", "request": raw_request(following),
                           "evidence": ledger.evidence}, **ledger.target(first), **extra)
    origin = ref(ledger.path / "events" / ("%06d.json" % receipt["sequence"]))
    before = files(tmp_path)
    answer = compose(root)
    rows = sections(answer["brief"])
    for section in ("Approved scope", "Source identity", "Open obligations"):
        items = [row for row in rows[section] if row.get("request_id") == "successor"]
        assert items and all(item["ref"] == origin for item in items)
    assert not any(row.get("request_id") == "first" for row in rows["Approved scope"])
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


def completed_request(ledger, identifier):
    value = ledger.ready(request(identifier))
    intent = identifier + "-intent"
    ledger.intent(value, intent_id=intent)
    result = {"request_sha256": ledger.target(value)["request_sha256"], "intent_id": intent,
              "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": ledger.evidence}
    terminal = raw_request(result)
    ledger.event("terminal", actor=ledger.operator, result=terminal, **ledger.target(value))
    ledger.event("review", actor="reviewer-1", result_sha256=terminal["sha256"], source=SOURCE,
                 verdict="accept", evidence=ledger.evidence, **ledger.target(value))
    ledger.event("delivery", evidence=ledger.evidence, **ledger.target(value))
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(value))
    return value


@lifecycle_only
def test_forty_completed_requests_are_covered_by_one_head_without_consuming_the_bound(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    seed_completed_requests(ledger, 40)
    before = files(tmp_path)
    answer = compose(root)
    rows = sections(answer["brief"])
    assert answer["entries"] < 20
    assert rows["Approved scope"] == rows["Open obligations"] == []
    heads = [row for row in rows["Evidence references"] if row["kind"] == "lifecycle_head"]
    assert len(heads) == 1
    assert heads[0]["ref"] == ref(ledger.path / "events" / ("%06d.json" % ledger.status()["sequence"]))
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_257_genuinely_unread_messages_refuse_without_writing(pilot):  # noqa: F811
    root, _ = pilot
    seed_messages(root, (message(identifier="open-%03d" % index) for index in range(257)))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds 256 entries"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


@lifecycle_only
def test_expired_scope_is_history_but_its_unsettled_obligation_remains(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish(request("expired", continuation={"members": [], "max_starts": 1, "expires_at": "2000-01-01T00:00:00Z"}))
    rows = sections(compose(root)["brief"])
    assert not any(row.get("request_id") == "expired" for row in rows["Approved scope"])
    assert any(row.get("request_id") == "expired" for row in rows["Open obligations"])


@secure_publication
def test_closed_dispatch_lease_and_missing_brief_are_history(pilot, tmp_path):  # noqa: F811
    root, old_brief, ready = active_writer(pilot, tmp_path)
    completion = invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="done", kind="result",
                                    in_reply_to="dispatch-1", result={"source_revision": ready["base_revision"],
                                    "source_tree": "b" * 40, "checks": [{"check": "tests", "outcome": "pass", "reference": "retained"}],
                                    "lane_check": "retained"}))
    Path(old_brief["path"]).unlink()
    answer = compose(root)
    rows = sections(answer["brief"])
    assert ready["lease_ref"] not in json.dumps(rows["Approved scope"])
    assert not rows["Open obligations"]
    history = [row for row in rows["Evidence references"] if row["kind"] == "mailbox_history"]
    assert len(history) == 1 and history[0]["ref"] == ref(completion["path"])
    assert history[0]["historical_briefs"] == "not_reverified"
    assert not any(row["ref"]["path"] == old_brief["path"] for row in rows["Evidence references"])


def job_history(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "packet.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "tests",
                                 "checkout": str(tmp_path), "commit": "a" * 40, "tree": "b" * 40}))
    original = invoke(root, "publish", message(recipient="a/root", identifier="job", kind="job_request", brief=ref(packet)))
    unknown = invoke(root, "publish", message("a/root", "a/orchestrator", identifier="unknown", kind="job_receipt",
                                              in_reply_to="job", receipt={"state": "unknown", "reason": "lost reply"}))
    evidence = tmp_path / "job-result.json"
    evidence.write_text("{}\n")
    terminal = invoke(root, "publish", message("a/root", "a/orchestrator", identifier="terminal", kind="job_receipt",
                                               in_reply_to="job", receipt={"state": "completed", "exit_code": 0, "evidence": [ref(evidence)]}))
    return root, packet, original, unknown, terminal


def set_record_time(record, at):
    # Stored histories may order differently from publication; the reader validates this supported input.
    header = {**record["message"], "created_at": at}
    body = header.pop("body")
    Path(record["path"]).write_bytes(b"---\n" + json.dumps(header, sort_keys=True).encode() + b"\n---\n\n" + body.encode())


@secure_publication
def test_later_unknown_survives_an_earlier_terminal_until_a_correlated_later_terminal(tmp_path):
    root, packet, original, unknown, terminal = job_history(tmp_path)
    set_record_time(terminal, "2026-01-01T00:00:00Z")
    set_record_time(unknown, "2026-01-02T00:00:00Z")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    assert any(row.get("job_id") == "a/job" and row.get("state") == "unknown" and row["ref"] == ref(original["path"])
               for row in rows["Open obligations"])
    # The same correlated terminal only settles the job when its durable timestamp is later.
    set_record_time(terminal, "2026-01-03T00:00:00Z")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    assert not any(row.get("job_id") == "a/job" for row in rows["Open obligations"])


@secure_publication
@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_historical_packets_do_not_block_but_uncertain_packets_do(tmp_path, damage):
    root, packet, original, unknown, terminal = job_history(tmp_path)
    set_record_time(unknown, "2026-01-01T00:00:00Z")
    set_record_time(terminal, "2026-01-02T00:00:00Z")
    if damage == "missing":
        packet.unlink()
    else:
        packet.write_text("changed\n")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    history = [row for row in rows["Evidence references"] if row["kind"] == "mailbox_history"]
    assert len(history) == 1 and history[0]["ref"] == ref(original["path"])
    assert history[0]["historical_briefs"] == "not_reverified"
    assert not any(row["ref"]["path"] == str(packet) for row in rows["Evidence references"])
    set_record_time(unknown, "2026-01-03T00:00:00Z")
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert ("file unavailable" if damage == "missing" else "brief sha256 mismatch") in error
    assert files(tmp_path) == before


@secure_publication
def test_old_read_and_wake_history_is_bounded_and_successor_reads_are_generation_scoped(tmp_path):
    root, delivery, checkpoint = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    folder = delivery / "reads" / "a/root"
    receipt = json.loads(next(folder.iterdir()).read_text())
    for index in range(300):
        (folder / ("history-%03d.json" % index)).write_text(json.dumps(receipt))
    wakes = delivery / "wakes" / "a/root"
    wakes.mkdir(parents=True)
    for index in range(300):
        (wakes / ("history-%03d.json" % index)).write_text(json.dumps(
            {**receipt, "wake_id": "wake-%03d" % index, "state": "started"}))
    answer = compose(root, "a/root")
    assert answer["entries"] < 20
    before_bind = sections(answer["brief"])["Unread work"]
    assert len(before_bind) == 1 and before_bind[0]["state"] == "read_by_predecessor"
    invoke(root, "bind", {"endpoint": "a/root", "host": "host-two", "session": "successor", "expected_generation": 1,
                          "checkpoint": checkpoint})
    rows = sections(compose(root, "a/root")["brief"])
    assert len(rows["Unread work"]) == 1
    assert rows["Unread work"][0]["state"] == "read_by_predecessor" and rows["Unread work"][0]["count"] == 1


@secure_publication
def test_json_answer_reports_absent_lifecycle_coverage(pilot):  # noqa: F811
    root, _ = pilot
    assert compose(root)["coverage"]["lifecycle"] == "absent"


def faulted_cli(root, driver, timeout=30):
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(TOOL), str(root)],
                          capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not proc.stderr, proc.stderr
    return proc.returncode, json.loads(proc.stdout)


@secure_publication
@pytest.mark.parametrize("boundary", ["create", "rename"])
def test_publication_directory_swap_never_writes_into_a_store(pilot, boundary):  # noqa: F811
    root, _ = pilot
    briefs, held, store = root.parent / "briefs", root.parent / "held-briefs", root.parent / "store"
    briefs.mkdir()
    store.mkdir()
    sentinel = store / "sentinel"
    sentinel.write_text("store must stay unchanged")
    driver = ("import os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nbase=Path(root).parent\n"
              "real_open,real_replace=os.open,os.replace\nswapped=False\n"
              "def swap():\n"
              "    global swapped\n"
              "    if not swapped:\n"
              "        swapped=True\n"
              "        os.rename(base/'briefs',base/'held-briefs')\n"
              "        os.symlink(base/'store',base/'briefs',target_is_directory=True)\n"
              "def opening(path,flags,*args,**kwargs):\n"
              + ("    if str(path).split('/')[-1].startswith('.fresh-') and flags & os.O_CREAT: swap()\n" if boundary == "create" else "")
              + "    return real_open(path,flags,*args,**kwargs)\n"
              "def replacing(src,dst,*args,**kwargs):\n"
              + ("    swap()\n" if boundary == "rename" else "")
              + "    return real_replace(src,dst,*args,**kwargs)\n"
              "os.open,os.replace=opening,replacing\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    before = files(store)
    code, answer = faulted_cli(root, driver)
    assert files(store) == before, "publication followed the swapped symlink into a store"
    assert code == 2 and "publication directory changed" in answer["error"]
    assert list(held.iterdir()) == []


def test_unsupported_dir_fd_refuses_cleanly_before_creating_any_output(pilot):  # noqa: F811
    root, _ = pilot
    driver = ("import os,runpy,sys\n"
              "tool,root=sys.argv[1:]\nos.supports_dir_fd=set()\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    before = files(root.parent)
    code, answer = faulted_cli(root, driver)
    assert code == 2 and answer["error"] == "secure brief publication requires directory descriptor support"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


def test_byte_limit_refuses_without_writing(pilot):  # noqa: F811
    root, _ = pilot
    source = root.parent / "source"
    templates = source / "tools/hierarchy_templates"
    (templates / "roles").mkdir(parents=True)
    shutil.copyfile(ROOT / "tools/hierarchy_templates/lane-brief.md", templates / "lane-brief.md")
    (templates / "roles/lane.md").write_text("# Role\n" + "x" * 262144)
    (root.parent / "provision.json").write_text(json.dumps({"initiative": "a", "source": str(source),
        "mailbox_root": str(root), "delivery_dir": str(root.parent / "delivery")}))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds mailbox brief byte limit (262144)"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


def test_verify_portable_brief_without_a_journal_or_publication(tmp_path):
    manifest = tmp_path / "record.json"
    manifest.write_text("{}\n")
    brief = tmp_path / "brief.md"
    body = ["# Fresh thread brief", "<!-- aegis.hierarchy-fresh-brief/v1 -->", "Resume path: Verify first."]
    for name in SECTIONS:
        body += ["## " + name, "- " + json.dumps({"kind": "record", "ref": ref(manifest)})]
    brief.write_text("\n".join(body) + "\n")
    reference = ref(brief)
    assert cli("verify", "--path", brief, "--sha256", reference["sha256"])["ok"] is True


def provision_record(root, **changes):
    value = {"initiative": "a", "source": str(ROOT), "mailbox_root": str(root),
             "delivery_dir": str(root.parent / "delivery"), **changes}
    (root.parent / "provision.json").write_text(json.dumps(value))
    return value


@secure_publication
def test_output_cannot_be_the_mailbox_store(pilot):  # noqa: F811
    root, _ = pilot
    destination = root.parent / "briefs"
    root.rename(destination)
    before = files(destination.parent)
    assert "output directory overlaps coordination store" in compose(destination, expect=2)["error"]
    assert files(destination.parent) == before


@pytest.mark.parametrize("store_kind", ["delivery", "store", "board", pytest.param("lifecycle", marks=lifecycle_only)])
@pytest.mark.parametrize("relation", ["equal", "inside", "around"])
def test_output_refuses_overlap_with_every_declared_coordination_store(pilot, tmp_path, store_kind, relation):  # noqa: F811
    root, _ = pilot
    output = tmp_path / "briefs"
    store = {"equal": output, "inside": tmp_path, "around": output / "nested-store"}[relation]
    flags = {}
    if store_kind == "lifecycle":
        staging = tmp_path / "staging"
        staging.mkdir()
        ledger = Ledger(staging)
        shutil.copytree(ledger.path, store, dirs_exist_ok=True)
        flags["lifecycle"] = str(store)
    else:
        store.mkdir(parents=True, exist_ok=True)
        provision_record(root, **{("delivery_dir" if store_kind == "delivery" else store_kind): str(store)})
        # A command-line override must not stop protecting the provisioned delivery store.
        flags["delivery_dir"] = str(tmp_path / "safe-delivery")
    before = files(tmp_path)
    assert "output directory overlaps coordination store" in compose(root, expect=2, **flags)["error"]
    assert files(tmp_path) == before


@secure_publication
@pytest.mark.parametrize("record_path", ["initiatives/other/provision.json", "evidence/provision-init.json"])
def test_store_named_by_another_run_record_is_also_protected(pilot, tmp_path, record_path):  # noqa: F811
    root, _ = pilot
    path = tmp_path / record_path
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"store": str(tmp_path / "briefs")}))
    before = files(tmp_path)
    assert "output directory overlaps coordination store" in compose(root, expect=2)["error"]
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


FROZEN_COMPOSE = ("import datetime,runpy,sys\n"
                  "class Frozen(datetime.datetime):\n"
                  "    @classmethod\n"
                  "    def now(cls,tz=None): return cls(2026,11,7,12,tzinfo=tz)\n"
                  "datetime.datetime=Frozen\n"
                  "tool,root=sys.argv[1:]\n"
                  "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
                  "runpy.run_path(tool,run_name='__main__')\n")


@secure_publication
@pytest.mark.parametrize("special", ["fifo", "directory"])
def test_special_destination_refuses_without_hanging_or_writing(pilot, special):  # noqa: F811
    root, _ = pilot
    code, first = faulted_cli(root, FROZEN_COMPOSE)
    assert code == 0
    path = Path(first["brief"]["path"])
    path.unlink()
    if special == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    before = files(root.parent)
    code, answer = faulted_cli(root, FROZEN_COMPOSE, timeout=2)
    assert code == 2 and answer["error"] == "brief must be a regular file"
    assert files(root.parent) == before
    assert stat.S_ISFIFO(path.stat().st_mode) if special == "fifo" else path.is_dir()


@secure_publication
def test_returned_path_must_identify_the_written_inode_after_an_ancestor_moves(pilot):  # noqa: F811
    root, _ = pilot
    base = root.parent
    moved = base.with_name(base.name + "-moved")
    driver = ("import os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nbase=Path(root).parent\nreal_open=os.open\nmoved=False\n"
              "def opening(path,flags,*args,**kwargs):\n"
              "    global moved\n"
              "    if str(path).startswith('.fresh-') and flags & os.O_CREAT and not moved:\n"
              "        moved=True\n"
              "        base.rename(base.with_name(base.name+'-moved'))\n"
              "        base.mkdir()\n"
              "    return real_open(path,flags,*args,**kwargs)\n"
              "os.open=opening\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    code, answer = faulted_cli(root, driver)
    assert code == 3 and "published brief pathname no longer identifies written file" in answer["error"]
    assert list(base.iterdir()) == [] and list((moved / "briefs").iterdir()) == []


@secure_publication
def test_initiative_named_serve_composes_without_operational_import_side_effects(tmp_path):
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {"serve/front-door": {}, "serve/orchestrator": {}},
                          "counterparts": [], "writer_limit": 1})
    provision_record(root, initiative="serve")
    answer = cli("compose", "--root", root, "--initiative", "serve", "--endpoint", "serve/orchestrator")
    assert answer["ok"] is True and sections(answer["brief"])["Role contract"][0]["role"] == "orchestrator"


@secure_publication
@pytest.mark.parametrize("family", ["claude", "codex"])
@pytest.mark.parametrize("role", ["front-door", "orchestrator", "router", "decider", "implementer", "integrator", "reviewer"])
def test_template_rendering_exactly_matches_launcher_in_a_separate_process(tmp_path, role, family):
    endpoint = "a/lane/" + role if role in {"implementer", "integrator", "reviewer"} else "a/" + role
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {"a/front-door": {}, "a/orchestrator": {},
        endpoint: {"kind": role} if "/lane/" in endpoint else {}}, "counterparts": [], "writer_limit": 1})
    write_plan(SimpleNamespace(base=tmp_path), hierarchy="a", team="claude-code" if family == "claude" else "codex-cli", stand_ins={})
    answer = compose(root, endpoint)
    text = Path(answer["brief"]["path"]).read_text()
    inline = "\n".join(line[2:] for line in text.splitlines() if line.startswith("> "))
    driver = ("import json,sys\nfrom types import SimpleNamespace\n"
              "from pathlib import Path\nsource,root,endpoint,family=sys.argv[1:]\n"
              "sys.argv=[str(Path(source)/'tools/hierarchy_launcher.py')]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\n"
              "from hierarchy_launcher import start_prompt\nfrom hierarchy_mailbox import Mailbox\n"
              "prompt,contracts=start_prompt(SimpleNamespace(mailbox=Mailbox(root),setup={'source':source}),endpoint,family)\n"
              "print(json.dumps({'text':prompt.partition('\\n\\n')[2].rpartition('\\n\\n')[0],'contracts':contracts}))\n")
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(root), endpoint, family],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    expected = json.loads(proc.stdout)
    assert inline == expected["text"]
    assert [row["ref"] for row in sections(answer["brief"])["Role contract"]] == expected["contracts"]


@lifecycle_only
@pytest.mark.parametrize("path_limit", [None, 1024], ids=["native", "macos-path-limit"])
def test_valid_large_settled_lifecycle_record_uses_the_lifecycle_reader_limit(pilot, tmp_path, monkeypatch, path_limit):  # noqa: F811
    if path_limit is not None:
        real_is_symlink = Path.is_symlink

        def limited_is_symlink(path):
            if len(os.fsencode(path)) >= path_limit:
                raise OSError(errno.ENAMETOOLONG, "simulated macOS pathname limit", str(path))
            return real_is_symlink(path)

        monkeypatch.setattr(Path, "is_symlink", limited_is_symlink)
    root, _ = pilot
    ledger = Ledger(tmp_path)
    # Nested JSON escaping grows the wire record, not the POSIX filename bytes.
    component = '"\\' * 64
    paths = [str(tmp_path / "declared" / str(index) / component / component) for index in range(256)]
    assert len(paths) <= 256
    assert max(len(os.fsencode(path)) for path in paths) < 1024
    assert max(len(os.fsencode(part)) for path in paths for part in Path(path).parts) < 255
    for path in paths:
        safe_path(path)
    value = request("large-history", paths=paths)
    receipt = ledger.publish(value)
    record = ledger.path / "events" / ("%06d.json" % receipt["sequence"])
    assert 262144 < len(record.read_bytes()) < 1048576
    ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": raw_request(request("pending")),
                 "evidence": ledger.evidence}, **ledger.target(value))
    before = files(tmp_path)
    answer = compose(root)
    assert answer["entries"] < 20
    assert all(row.get("request_id") != value["id"] for rows in sections(answer["brief"]).values() for row in rows)
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@lifecycle_only
def test_expiry_decisions_are_reproducible_from_explicit_as_of(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish(request("timed", continuation={"members": [], "max_starts": 1, "expires_at": "2026-11-07T12:00:00Z"}))
    before = compose(root, as_of="2026-11-07T11:59:59Z")
    after = compose(root, as_of="2026-11-07T12:00:01Z")
    assert any(row.get("request_id") == "timed" for row in sections(before["brief"])["Approved scope"])
    assert not any(row.get("request_id") == "timed" for row in sections(after["brief"])["Approved scope"])
    assert compose(root, as_of="2026-11-07T11:59:59Z") == before
    body = Path(before["brief"]["path"]).read_text()
    assert "2026-11-07T11:59:59" in body and "validate expiry live" in body


@pytest.mark.parametrize("value", ["yesterday", "2026-11-07T12:00:00-05:00"])
def test_as_of_requires_rfc3339_utc_without_writes(pilot, value):  # noqa: F811
    root, _ = pilot
    before = files(root.parent)
    assert "invalid --as-of" in compose(root, as_of=value, expect=2)["error"]
    assert files(root.parent) == before


@secure_publication
@pytest.mark.parametrize("order", ["compose-then-bind", "bind-then-compose"])
def test_successor_lifetime_reads_use_one_predecessor_aggregate(tmp_path, order):
    root, delivery, checkpoint = receipt_fixture(tmp_path, endpoint="a/root")
    seed_messages(root, (message(recipient="a/root", identifier="lifetime-%03d" % index) for index in range(248)))
    invoke(root, "publish", message(recipient="a/root", identifier="esc-7", kind="escalation"))
    cursor = None
    for _ in range(4):
        flags = {"after": cursor} if cursor else {}
        page = invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
                      host="host-one", session="a/root", generation=1, limit=100, **flags)
        cursor = page["next_after"]
        if cursor is None:
            break
    assert cursor is None
    binding = {"endpoint": "a/root", "host": "host-two", "session": "successor", "expected_generation": 1,
               "checkpoint": checkpoint}
    if order == "bind-then-compose":
        invoke(root, "bind", binding)
    answer = compose(root, "a/root")
    rows = sections(answer["brief"])["Unread work"]
    assert answer["entries"] < 20 and len(rows) == 1
    aggregate = rows[0]
    assert aggregate["state"] == "read_by_predecessor" and aggregate["count"] == 250
    assert aggregate["generation"] == 2 and aggregate["message_types"]["escalation"] == 1
    assert aggregate["ref"] == ref(aggregate["ref"]["path"])
    assert "esc-7" in json.loads(Path(aggregate["ref"]["path"]).read_text())["message_ids"]
    if order == "compose-then-bind":
        binding["checkpoint"]["briefs"].append(answer["brief"])
        invoke(root, "bind", binding)
    own = compose(root, "a/root", target_generation=1, expect=2)
    assert "target generation precedes current binding" in own["error"]


@secure_publication
def test_explicit_current_target_generation_applies_its_own_reads(tmp_path):
    root, delivery, _ = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    answer = compose(root, "a/root", target_generation=1)
    assert sections(answer["brief"])["Unread work"] == []
    assert "Target generation: 1" in Path(answer["brief"]["path"]).read_text()


@secure_publication
@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="search-only traversal uses Linux O_PATH")
def test_search_only_parent_directories_allow_publication(pilot):  # noqa: F811
    root, _ = pilot
    ancestor = root.parent / "search-only"
    base = ancestor / "run"
    base.mkdir(parents=True)
    root.rename(base / "mailbox")
    root = base / "mailbox"
    mode = stat.S_IMODE(ancestor.stat().st_mode)
    ancestor.chmod(0o111)
    try:
        answer = compose(root)
    finally:
        ancestor.chmod(mode)
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.parametrize("accessor", ["native", "python39"])
def test_directory_eacces_is_a_permission_refusal(pilot, accessor):  # noqa: F811
    root, _ = pilot
    # Python 3.9's pathlib accessor must capture the builtin before os.open is patched.
    driver = ("import errno,os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nreal_open=os.open\n"
              "def opening(path,flags,*args,**kwargs):\n"
              "    if str(path)=='briefs': raise PermissionError(errno.EACCES,'fixture directory denied')\n"
              "    return real_open(path,flags,*args,**kwargs)\n"
              "os.open=opening\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    if accessor == "python39":
        # Emulate 3.9's class-level os.open capture at pathlib import on newer Python.
        driver = ("import builtins,io\n"
                  "real_import=builtins.__import__\naccessor_installed=False\n"
                  "def importing(name,*args,**kwargs):\n"
                  "    global accessor_installed\n"
                  "    module=real_import(name,*args,**kwargs)\n"
                  "    if name=='pathlib' and not accessor_installed:\n"
                  "        accessor_installed=True\n"
                  "        import os\n"
                  "        class NormalAccessor:\n"
                  "            open=os.open\n"
                  "        normal=NormalAccessor()\n"
                  "        def path_open(self,mode='r',buffering=-1,encoding=None,errors=None,newline=None):\n"
                  "            return io.open(self,mode,buffering,encoding,errors,newline,\n"
                  "                           opener=lambda path,flags: normal.open(path,flags,0o666))\n"
                  "        module.Path.open=path_open\n"
                  "    return module\n"
                  "builtins.__import__=importing\n") + driver
    before = files(root.parent)
    code, answer = faulted_cli(root, driver)
    assert code == 2 and "publication directory permission denied" in answer["error"]
    assert "changed" not in answer["error"]
    assert files(root.parent) == before


def structured_job(tmp_path, changes=None, missing=None):
    root, _, _ = receipt_fixture(tmp_path)
    value = {"schema": "aegis.hierarchy-job-packet/v2", "recipe": "tests", "checkout": str(tmp_path),
             "commit": "a" * 40, "tree": "b" * 40, "recipes_sha256": "c" * 64,
             "after": {"message_id": "prior", "sha256": "d" * 64}, **(changes or {})}
    if value["schema"] == "aegis.hierarchy-job-packet/v1":
        value.pop("after", None)
        value.pop("recipes_sha256", None)
    if missing is not None:
        value.pop(missing)
    path = tmp_path / "structured-packet.md"
    path.write_text(json.dumps(value))
    invoke(root, "publish", message(recipient="a/root", identifier="structured-job", kind="job_request", brief=ref(path)))
    return root, path, value


@pytest.mark.parametrize("changes,missing,field", [
    ({}, "after", "after"),
    ({"commit": {"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}}, None, "commit"),
    ({"schema": "aegis.hierarchy-job-packet/v99"}, None, "schema"),
    ({}, "recipes_sha256", "recipes_sha256"),
    ({}, "tree", "tree"),
    ({"checkout": {}}, None, "checkout"),
    ({"tree": []}, None, "tree"),
    ({"paths": [{"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}]}, None, "paths"),
    ({"paths": "tests"}, None, "paths"),
    ({"paths": ["../escape.py"]}, None, "paths"),
    ({"dirty_content_sha256": {}}, None, "dirty_content_sha256"),
    ({"expected_tree": {}}, None, "expected_tree"),
    ({"merge": {}}, None, "merge"),
    ({"message": {}}, None, "message"),
    ({"recipe": {}}, None, "recipe"),
    ({"after": {"message_id": {}, "sha256": "d" * 64}}, None, "after"),
    ({"recipes_sha256": []}, None, "recipes_sha256"),
])
def test_malformed_structured_packets_refuse_before_extracting_fields(tmp_path, changes, missing, field):
    root, path, _ = structured_job(tmp_path, changes, missing)
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(path) in error and field in error
    assert "DO_NOT_INLINE_PACKET_TRANSCRIPT" not in error
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


@pytest.mark.parametrize("changes,missing,field", [
    ({}, "after", "after"),
    ({"commit": {"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}}, None, "commit"),
])
def test_packet_rejection_agrees_with_the_runners_admission_checks(tmp_path, changes, missing, field):
    root, path, _ = structured_job(tmp_path, changes, missing)
    # No standalone schema validator exists. The actual admission API must fail
    # on these fields before it could reach any checkout or execution boundary.
    driver = ("import json,sys\nfrom pathlib import Path\n"
              "source,root,packet,checkout=sys.argv[1:]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\n"
              "from hierarchy_jobs import admit\nfrom hierarchy_mailbox import Mailbox\n"
              "mailbox=Mailbox(root)\nmessage=mailbox.messages()['structured-job']['message']\n"
              "try:\n"
              "    admit(None,{'checkouts':[checkout]},message,mailbox,{'recipes':{'tests':{'kind':'command','steps':[]}}})\n"
              "except ValueError as error:\n    print(json.dumps({'error':str(error)}))\n"
              "else:\n    raise AssertionError('malformed packet reached admission')\n")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(root), str(path), str(tmp_path)],
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    assert field in json.loads(result.stdout)["error"]
    assert field in compose(root, "a/orchestrator", expect=2)["error"]


@pytest.mark.parametrize("after", [None, []])
def test_non_object_dependency_names_the_after_field(tmp_path, after):
    root, path, _ = structured_job(tmp_path, {"after": after})
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(path) in error and ": invalid after:" in error
    assert files(tmp_path) == before


@secure_publication
@pytest.mark.parametrize("version", [1, 2])
def test_valid_packet_source_fields_remain_scalar_and_paths_are_strings(tmp_path, version):
    value = {"schema": "aegis.hierarchy-job-packet/v%d" % version,
             "paths": ["tests/example.py::test_one"], "dirty_content_sha256": hashlib.sha256(b"").hexdigest()}
    root, path, packet = structured_job(tmp_path, value)
    rows = sections(compose(root, "a/orchestrator")["brief"])
    source = next(row["source"] for row in rows["Source identity"] if row.get("job_id") == "structured-job")
    assert source["commit"] == packet["commit"] and source["tree"] == packet["tree"]
    assert source["paths"] == packet["paths"]
    assert all(isinstance(item, str) for item in source["paths"])


FSYNC_DRIVER = ("import errno,fcntl,json,os,runpy,stat,sys\nfrom pathlib import Path\n"
                "tool,root,fail,peer=sys.argv[1:]\nbase=Path(root).parent\ntrace=base/'fsync-trace.json'\n"
                "events=[]\nrenamed=False\nalready_published=any((base/'briefs').glob('fresh-*.md'))\n"
                "real_fsync,real_replace,real_mkdir=os.fsync,os.replace,os.mkdir\n"
                "def making(path,*args,**kwargs):\n"
                "    result=real_mkdir(path,*args,**kwargs)\n"
                "    if peer=='yes' and str(path)=='briefs':\n"
                "        events.append('peer_created')\n"
                "        raise FileExistsError(errno.EEXIST,'peer created the directory without syncing its parent')\n"
                "    return result\n"
                "def replacing(*args,**kwargs):\n"
                "    global renamed\n    result=real_replace(*args,**kwargs)\n    renamed=True\n    return result\n"
                "def syncing(fd):\n"
                "    metadata=os.fstat(fd)\n"
                "    if stat.S_ISDIR(metadata.st_mode):\n"
                "        assert renamed or already_published,'directory synced before rename'\n"
                "        flags=fcntl.fcntl(fd,fcntl.F_GETFL)\n"
                "        assert flags & os.O_ACCMODE == os.O_RDONLY\n"
                "        assert not flags & getattr(os,'O_PATH',0)\n"
                "        parent=base.stat()\n"
                "        kind='parent' if (metadata.st_dev,metadata.st_ino)==(parent.st_dev,parent.st_ino) else 'directory'\n"
                "    else:\n        assert stat.S_ISREG(metadata.st_mode)\n        kind='file'\n"
                "    events.append(kind)\n"
                "    if kind==fail: raise OSError('fixture '+kind+' fsync refused')\n"
                "    return real_fsync(fd)\n"
                "os.fsync,os.replace,os.mkdir=syncing,replacing,making\n"
                "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2','--as-of','2026-11-07T12:00:00Z']\n"
                "try:\n    runpy.run_path(tool,run_name='__main__')\n"
                "finally:\n    trace.write_text(json.dumps(events))\n")


def traced_publication(root, fail="", peer_creation=False):
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", FSYNC_DRIVER, str(TOOL), str(root), fail,
                           "yes" if peer_creation else "no"],
                          capture_output=True, text=True, timeout=15,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not proc.stderr, proc.stderr
    return proc.returncode, json.loads(proc.stdout), json.loads((root.parent / "fsync-trace.json").read_text())


@secure_publication
@pytest.mark.parametrize("existing", ["none", "directory", "brief"])
def test_publication_syncs_directory_and_parent_on_every_success(pilot, existing):  # noqa: F811
    root, _ = pilot
    if existing == "directory":
        (root.parent / "briefs").mkdir()
    elif existing == "brief":
        compose(root, as_of=AS_OF)
    code, answer, events = traced_publication(root)
    assert code == 0, answer
    expected = {"none": ["file", "directory", "parent"], "directory": ["file", "directory", "parent"],
                "brief": ["directory", "parent"]}
    assert events == expected[existing]
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.parametrize("failed", ["directory", "parent"])
def test_directory_sync_failure_never_reports_publication_success(pilot, failed):  # noqa: F811
    root, _ = pilot
    code, answer, events = traced_publication(root, failed)
    assert code == 3 and "ok" not in answer
    assert answer["error"] == "brief publication failed: fixture " + failed + " fsync refused"
    assert events[-1] == failed


@secure_publication
def test_parent_sync_failure_is_not_forgotten_on_retry(pilot):  # noqa: F811
    root, _ = pilot
    code, _, events = traced_publication(root, "parent")
    assert code == 3 and events == ["file", "directory", "parent"]
    published = list((root.parent / "briefs").glob("fresh-*.md"))
    assert len(published) == 1
    reference = ref(published[0])
    contents = published[0].read_bytes()
    code, _, events = traced_publication(root, "parent")
    assert code == 3 and events == ["directory", "parent"]
    code, answer, events = traced_publication(root)
    assert code == 0 and events == ["directory", "parent"]
    assert answer["brief"] == reference and Mailbox(root).brief(reference) == contents


@secure_publication
def test_peer_creation_without_parent_sync_is_completed_by_this_composer(pilot):  # noqa: F811
    root, _ = pilot
    code, answer, events = traced_publication(root, peer_creation=True)
    assert code == 0, answer
    assert events == ["peer_created", "file", "directory", "parent"]
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="search-only traversal uses Linux O_PATH")
def test_unreadable_output_parent_cannot_report_durable_success(pilot):  # noqa: F811
    root, _ = pilot
    compose(root, as_of=AS_OF)
    base = root.parent
    mode = stat.S_IMODE(base.stat().st_mode)
    base.chmod(0o111)
    try:
        error = compose(root, as_of=AS_OF, expect=3)["error"]
    finally:
        base.chmod(mode)
    assert "brief publication failed" in error and "Permission denied" in error


@secure_publication
@pytest.mark.parametrize("paths", [None, "", 0, False, {}, []])
def test_no_paths_packets_match_the_runners_falsy_path_handling(tmp_path, paths):
    root, path, _ = structured_job(tmp_path, {"paths": paths})
    driver = ("import json,sys\nfrom pathlib import Path\nsource,packet,checkout=sys.argv[1:]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\nfrom hierarchy_jobs import checked_paths\n"
              "print(json.dumps(checked_paths(json.loads(Path(packet).read_text()),"
              "{'kind':'command','steps':[['$python','-c','pass']]},checkout)))\n")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(path), str(tmp_path)],
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    expected = json.loads(result.stdout)
    assert expected == []
    before = files(tmp_path)
    answer = compose(root, "a/orchestrator")
    source = next(row["source"] for row in sections(answer["brief"])["Source identity"] if row.get("job_id") == "structured-job")
    assert source["paths"] == expected
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_valid_merge_packet_composes_without_admitting_or_executing_it(tmp_path):
    root, path, packet = structured_job(tmp_path, {"schema": "aegis.hierarchy-job-packet/v1", "recipe": "merge",
        "merge": "c" * 40, "expected_tree": "d" * 40, "message": "Merge reviewed candidate"})
    before = files(tmp_path)
    answer = compose(root, "a/orchestrator")
    row = next(row for row in sections(answer["brief"])["Source identity"] if row.get("job_id") == "structured-job")
    assert row["ref"] == ref(path)
    assert row["source"]["merge"] == packet["merge"] and row["source"]["expected_tree"] == packet["expected_tree"]
    assert "paths" not in row["source"]
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
@pytest.mark.parametrize("notes", [12, 24])
def test_consumed_reference_rechecks_do_not_enumerate_shared_cache(pilot, monkeypatch, capsys, notes):  # noqa: F811
    from tools import hierarchy_fresh_brief as fresh

    root, reference = pilot
    for number in range(notes):
        note = root.parent / ("cache-note-%d.md" % number)
        note.write_text("typed note %d\n" % number, encoding="utf-8")
        invoke(root, "publish", message(identifier="cache-note-%d" % number, kind="brief",
            brief={"path": str(note), "sha256": hashlib.sha256(note.read_bytes()).hexdigest()}))
    # Repeated declarations exercise already-cached paths as well as cache misses.
    for number in range(2):
        invoke(root, "publish", message(identifier="shared-cache-note-%d" % number, kind="brief", brief=reference))
    expected = compose(root, as_of=AS_OF)
    visits = []
    caches = []

    class CountedCache(dict):
        def __iter__(self):
            for key in super().__iter__():
                visits.append(key)
                yield key

    original = fresh._Operation.__init__

    def initialized(self, **kwargs):
        if kwargs.get("reference_cache") is None:
            kwargs["reference_cache"] = CountedCache()
            caches.append(kwargs["reference_cache"])
        original(self, **kwargs)

    monkeypatch.setattr(fresh._Operation, "__init__", initialized)
    code = fresh.main(["compose", "--root", str(root), "--initiative", "a", "--endpoint", ENDPOINT,
                       "--as-of", AS_OF])
    output = capsys.readouterr()
    assert code == 0 and output.err == "", output
    assert json.loads(output.out) == expected
    assert max(map(len, caches)) >= notes
    assert len(visits) == 0, "cached-path membership must not enumerate identity entries"
