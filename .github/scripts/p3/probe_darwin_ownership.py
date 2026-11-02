"""Mandatory real macOS ownership controls; no timing, Go or package imports."""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path


def load_backend():
    path = Path(__file__).with_name('darwin_ownership.py')
    spec = importlib.util.spec_from_file_location('darwin_ownership', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def bounded_file(path, *, tick=None):
    deadline = time.monotonic() + 5
    while not path.exists():
        if tick is not None:
            tick()
        if time.monotonic() >= deadline:
            raise RuntimeError('handshake_timeout: ' + path.name)
        time.sleep(.02)


def worker(mode, directory):
    if mode == 'leaf':
        save(directory / 'leaf.json', {'pid': os.getpid(), 'ppid': os.getppid(), 'sid': os.getsid(0)})
        # A failed, ambiguous probe never targets this PID. Its own bounded
        # lifetime prevents an indefinitely abandoned benign probe process.
        time.sleep(8)
        return
    if mode == 'middle':
        save(directory / 'middle.json', {'pid': os.getpid()})
        if not (directory / 'missed-parent').exists():
            bounded_file(directory / 'release-middle')
        subprocess.Popen([sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
                          '--worker', 'leaf', str(directory)], start_new_session=True,
                         stdin=subprocess.DEVNULL)
        bounded_file(directory / 'leaf.json')
        return
    if mode in ('reparent', 'missed-parent'):
        middle = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
                                   '--worker', 'middle', str(directory)], start_new_session=True,
                                  stdin=subprocess.DEVNULL)
        middle.wait(timeout=6)
        return
    save(directory / 'ready.json', {'pid': os.getpid()})
    if mode == 'token':
        time.sleep(8)
    elif mode != 'clean':
        raise RuntimeError('unknown_worker_mode')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--mode', choices=('clean', 'token', 'reparent', 'missed-parent'), required=True)
    args = parser.parse_args()
    directory = args.evidence.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    backend = load_backend()
    report = {'status': 'FAIL', 'mode': args.mode, 'platform': sys.platform, 'worker_launched': False,
                  'macos_validated': False, 'sources': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                  for name in ('darwin_ownership.py', 'probe_darwin_ownership.py')}}
    tree = None
    with backend.stop_handlers(), (directory / 'native-events.jsonl').open('w', encoding='utf-8') as journal, \
            (directory / 'worker.stdout').open('wb') as stdout, (directory / 'worker.stderr').open('wb') as stderr:
        def event(value):
            journal.write(json.dumps(value, sort_keys=True) + '\n')
            journal.flush()

        try:
            api = backend.DarwinAPI(observer=event)
            tree = backend.DarwinOwnedTree(api, observer=event)
            if args.mode == 'missed-parent':
                (directory / 'missed-parent').touch()
            command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
                       '--worker', args.mode, str(directory)]
            report['worker_argv'] = command
            proc = tree.launch(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            report['worker_launched'] = True
            if args.mode == 'token':
                bounded_file(directory / 'ready.json', tick=tree.scan)
                current = api.process(proc.pid)
                backend.require(current['unique'] == tree.root and current['start'] == tree.starts[tree.root],
                                'token_probe_identity_mismatch')
                stale = dict(current, version=(current['version'] + 1) & 0xFFFFFFFF)
                try:
                    api.send(stale, signal.SIGTERM)
                except backend.OwnershipError as exc:
                    report['stale_token_error'] = str(exc)
                    backend.require(str(exc).endswith(f'errno={errno.ESRCH}'), 'unexpected_stale_token_result')
                else:
                    raise RuntimeError('stale_token_was_accepted')
                after = api.process(proc.pid)
                backend.require(proc.poll() is None and after['unique'] == current['unique']
                                and after['start'] == current['start'], 'stale_token_did_not_preserve_target')
                report['stale_token_target_survived'] = True
                api.send(after, signal.SIGTERM)
                report['current_token_exit'] = proc.wait(timeout=3)
                backend.require(proc.returncode == -signal.SIGTERM, 'current_token_did_not_terminate_target')
            elif args.mode == 'reparent':
                bounded_file(directory / 'middle.json', tick=tree.scan)
                tree.scan()
                middle = json.loads((directory / 'middle.json').read_text())
                admitted = [r for r in tree.graph.values() if r['pid'] == middle['pid']]
                backend.require(len(admitted) == 1 and tree.classification(admitted[0]['unique']) == 'owned',
                                'middle_not_admitted_before_release')
                (directory / 'release-middle').touch()
                tree.wait(8)
            elif args.mode == 'missed-parent':
                # Deliberately miss B's life. This control must reject surviving
                # C without signalling it, even though C's PID is in a fixture.
                proc.wait(timeout=8)
            else:
                tree.wait(8)
            with backend.defer_stops(report):
                report['cleanup'] = tree.close()
            backend.require(not report.get('deferred_signals'), 'termination_during_cleanup')
            cleanup = report['cleanup']
            if args.mode == 'clean':
                backend.require(cleanup['status'] == 'PASS', 'normal_cleanup_failed')
            elif args.mode == 'token':
                backend.require(cleanup['cleanup_complete'] and cleanup['errors'] == ['worker_exit: -15'],
                                'token_control_cleanup_failed')
            elif args.mode == 'reparent':
                backend.require(cleanup['cleanup_complete'] and cleanup['errors'] == ['fallback_cleanup_required'],
                                'reparent_cleanup_not_proved')
            else:
                backend.require(cleanup['status'] == 'FAIL' and not cleanup['cleanup_complete']
                                and any(e.startswith('unresolved_ancestry:') for e in cleanup['errors']),
                                'missed_parent_was_not_rejected')
                journal.flush()
                records = [json.loads(line) for line in (directory / 'native-events.jsonl').read_text().splitlines()]
                backend.require(not any(r.get('api') == 'proc_signal_with_audittoken' for r in records),
                                'ambiguous_process_was_signalled')
            report.update(status='PASS', macos_validated=True)
        except BaseException as exc:  # noqa: BLE001 - persist a FAIL report and traceback before bounded cleanup on every exit.
            report.update(status='FAIL', error=type(exc).__name__ + ': ' + str(exc), traceback=traceback.format_exc())
        finally:
            with backend.defer_stops(report):
                if tree is not None and not tree.closed:
                    report['cleanup'] = tree.close()
                report['sources_after'] = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                           for name in report['sources']}
                if report['sources_after'] != report['sources']:
                    report.update(status='FAIL', error='helper_source_changed')
                save(directory / 'result.json', report)
    print(json.dumps({'status': report['status'], 'mode': args.mode, 'evidence': str(directory)}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--worker':
        worker(sys.argv[2], Path(sys.argv[3]))
    else:
        raise SystemExit(main())
