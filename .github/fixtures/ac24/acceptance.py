#!/usr/bin/env python3
"""External AC24 public acceptance probe; no installation or network provisioning."""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import select
import signal
import stat
import subprocess
import sys
import time
import traceback


LOCK_SHA256 = '82ecce1b7005a50e5ac6142fa296066ed7193ce5679b4dfd6ae7ebaf29e2ef9c'
FIXTURE_FILES = ('package.json', 'vitest.config.mjs', '.aegis/config.json',
                 '.aegis/rules/traps/trap-sample.md', 'base-app.ts',
                 'src/app.ts', 'tests/app.test.ts')
COMMANDS = []


def request_stop(signum, _frame):
    raise KeyboardInterrupt('termination signal ' + str(signum))


@contextlib.contextmanager
def defer_stops(record):
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    def remember(signum, _frame):
        record.setdefault('deferred_signals', []).append(signum)
    for sig in previous:
        signal.signal(sig, remember)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def process_info(pid):
    try:
        parts = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'parent': int(parts[1]), 'start': parts[19], 'state': parts[0]}
    except (FileNotFoundError, ProcessLookupError):
        return None


class OwnedTree:
    """Own the worker tree across separate sessions; never signal a numeric PID."""
    def __init__(self, source, evidence):
        self.evidence, self.proc, self.job = evidence, None, None
        self.owners, self.record = {}, {'platform': sys.platform, 'status': 'INCOMPLETE'}
        if os.name == 'nt':
            spec = importlib.util.spec_from_file_location('acceptance_windows_job', source / 'aegis_core/ast/windows_job.py')
            self.windows = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.windows)
            self.job = self.windows.WindowsJob()
            self.flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP | self.windows.CREATE_SUSPENDED}
        else:
            require(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
                    'owned-tree cleanup requires Linux pidfds or Windows job handles')
            self.libc = ctypes.CDLL(None, use_errno=True)
            self.libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
            self.libc.prctl.restype = ctypes.c_int
            prior = ctypes.c_int()
            require(self.libc.prctl(37, ctypes.addressof(prior), 0, 0, 0) == 0, 'PR_GET_CHILD_SUBREAPER failed')
            self.prior_subreaper = prior.value
            require(self.libc.prctl(36, 1, 0, 0, 0) == 0, 'PR_SET_CHILD_SUBREAPER failed')
            self.flags = {'start_new_session': True}

    def attach(self, proc):
        self.proc = proc
        if self.job is not None:
            self.job.assign_and_resume(proc.pid)
        else:
            self.scan()

    def scan(self):
        rows = {}
        for path in Path('/proc').iterdir():
            if path.name.isdigit():
                try:
                    value = process_info(int(path.name))
                except PermissionError:
                    if int(path.name) in self.owners:
                        raise
                    continue
                if value:
                    rows[value['pid']] = value
        parents = {os.getpid()}
        while True:
            found = {pid: row for pid, row in rows.items() if row['parent'] in parents and pid not in parents}
            if not found:
                break
            parents.update(found)
            for pid, row in found.items():
                if pid in self.owners and self.owners[pid]['start'] == row['start']:
                    continue
                try:
                    fd = os.pidfd_open(pid)
                except ProcessLookupError:
                    continue
                current = process_info(pid)
                if current is None or current['start'] != row['start']:
                    os.close(fd)
                    continue
                # Direct children include subreaper-adopted descendants. Every
                # admitted identity belongs to this helper's child tree.
                if pid in self.owners:
                    former = self.owners[pid]
                    self.record.setdefault('retired', []).append({k: v for k, v in former.items() if k != 'fd'})
                    os.close(former['fd'])
                self.owners[pid] = dict(row, fd=fd)

    def live(self):
        return [row for row in self.owners.values() if not select.select([row['fd']], [], [], 0)[0]]

    def accounting(self):
        value = self.windows.JobBasicAccountingInformation()
        require(self.job._kernel.QueryInformationJobObject(self.job._handle, 1, ctypes.byref(value),
                                                           ctypes.sizeof(value), None), 'Windows job accounting failed')
        return {name: getattr(value, name) for name in ('TotalProcesses', 'ActiveProcesses', 'TotalTerminatedProcesses')}

    def close(self):
        with defer_stops(self.record):
            self._close()
        if self.record.get('deferred_signals'):
            raise KeyboardInterrupt('termination requested during owned-tree cleanup')

    def _close(self):
        errors = []
        try:
            if self.job is not None:
                if self.proc is not None and self.job._assigned:
                    self.record['before'] = self.accounting()
                    require(self.job._kernel.TerminateJobObject(self.job._handle, 1), 'owned Windows job termination failed')
                    deadline = time.monotonic() + 5
                    while True:
                        after = self.accounting()
                        if after['ActiveProcesses'] == 0:
                            break
                        require(time.monotonic() < deadline, 'owned Windows job did not become empty')
                        time.sleep(.02)
                    self.record['after'] = after
                    # This helper owns an arbitrary process tree, not the Go
                    # compiler protocol. The non-breakaway job handle is the
                    # ownership boundary; no PID-addressed taskkill is used.
                if self.proc is not None:
                    if self.proc.poll() is None and not self.job._assigned:
                        self.proc.kill()  # Popen's retained process handle.
                    self.proc.wait(timeout=5)
            else:
                for signum in (signal.SIGTERM, signal.SIGKILL):
                    deadline = time.monotonic() + 5
                    while True:
                        self.scan()
                        living = self.live()
                        if not living:
                            break
                        for row in living:
                            try:
                                signal.pidfd_send_signal(row['fd'], signum)
                            except ProcessLookupError:
                                pass
                        if time.monotonic() >= deadline:
                            break
                        time.sleep(.02)
                self.scan()
                require(not self.live(), 'owned process survived cleanup')
                if self.proc is not None:
                    self.proc.wait(timeout=5)
                for pid in self.owners:
                    if self.proc is not None and pid == self.proc.pid:
                        continue
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                self.record['owned'] = [{k: v for k, v in row.items() if k != 'fd'} for row in self.owners.values()]
            self.record.update(status='PASS', returncode=self.proc.returncode if self.proc is not None else None)
        except BaseException as exc:
            errors.append(type(exc).__name__ + ': ' + str(exc))
        finally:
            if self.job is not None:
                try:
                    self.job.close()
                except BaseException as exc:
                    errors.append(type(exc).__name__ + ': ' + str(exc))
            else:
                for row in self.owners.values():
                    os.close(row['fd'])
                if self.libc.prctl(36, self.prior_subreaper, 0, 0, 0) != 0:
                    errors.append('restoring subreaper state failed')
            if errors:
                self.record.update(status='FAIL', errors=errors)
            save(self.evidence / 'owned-tree-cleanup.json', self.record)
        require(not errors, 'owned-tree cleanup failed: ' + '; '.join(errors))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def fact(path):
    try:
        info = path.lstat()
        row = {'mode': stat.S_IMODE(info.st_mode), 'size': info.st_size}
        if stat.S_ISLNK(info.st_mode):
            row.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            row.update(kind='file', sha256=digest(path))
        else:
            row.update(kind='other')
        return row
    except OSError as exc:
        return {'kind': 'missing' if isinstance(exc, FileNotFoundError) else 'unreadable',
                'error_type': type(exc).__name__, 'error': str(exc)}


def tree_facts(root):
    return {str(p.relative_to(root)): fact(p) for p in sorted(root.rglob('*'))
            if p.is_symlink() or p.is_file()}


def execute(argv, cwd, env, *, timeout=30):
    row = {'argv': [str(a) for a in argv], 'cwd': str(cwd), 'timeout_s': timeout}
    COMMANDS.append(row)
    done = subprocess.run(row['argv'], cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                          timeout=timeout, check=False)
    row.update(exit=done.returncode, stdout=done.stdout.decode('utf-8', 'replace'),
               stderr=done.stderr.decode('utf-8', 'replace'))
    require(done.returncode == 0, 'command failed: ' + json.dumps(row))
    return done.stdout.decode('utf-8').strip()


def git(git_path, root, env, *args):
    return execute([git_path, '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + os.devnull,
                    '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false',
                    '-c', 'user.name=AC24 Acceptance', '-c', 'user.email=acceptance@example.invalid',
                    *args], root, env)


def source_facts(root, git_path, env):
    names = git(git_path, root, env, 'ls-files', '-z').split('\0')
    index = Path(git(git_path, root, env, 'rev-parse', '--git-path', 'index'))
    if not index.is_absolute():
        index = root / index
    return {'head': git(git_path, root, env, 'rev-parse', 'HEAD'),
            'tree': git(git_path, root, env, 'rev-parse', 'HEAD^{tree}'),
            'status': git(git_path, root, env, 'status', '--porcelain=v1', '--untracked-files=all'),
            'index': fact(index),
            'files': {name: fact(root / name) for name in names if name}}


def neutral_environment(root, node, source):
    env = {key: os.environ[key] for key in ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'COMSPEC',
                                         'PATHEXT', 'NUMBER_OF_PROCESSORS') if key in os.environ}
    paths = []
    for entry in [str(node.parent), str(Path(sys.executable).parent), *os.environ.get('PATH', '').split(os.pathsep)]:
        if not entry or not Path(entry).is_absolute():
            continue
        resolved = Path(entry).resolve()
        if resolved == source or source in resolved.parents:
            continue
        if str(resolved) not in paths:
            paths.append(str(resolved))
    env['PATH'] = os.pathsep.join(paths)
    for name, subdir in {'HOME': 'home', 'USERPROFILE': 'home', 'LOCALAPPDATA': 'cache',
                         'XDG_CACHE_HOME': 'cache', 'XDG_CONFIG_HOME': 'config',
                         'XDG_DATA_HOME': 'data', 'XDG_STATE_HOME': 'state',
                         'TMPDIR': 'tmp', 'TEMP': 'tmp', 'TMP': 'tmp'}.items():
        path = root / subdir
        path.mkdir(exist_ok=True)
        env[name] = str(path)
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0',
               GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    return env


def link_fact(path):
    info = path.lstat()
    return {'path': str(path), 'target': str(path.resolve()), 'is_symlink': path.is_symlink(),
            'mode': info.st_mode, 'device': info.st_dev, 'inode': info.st_ino,
            'reparse_tag': getattr(info, 'st_reparse_tag', None),
            'file_attributes': getattr(info, 'st_file_attributes', None)}


def worker(config_path):
    config = json.loads(config_path.read_text(encoding='utf-8'))
    root, source, repo, node = [Path(config[key]) for key in ('evidence', 'source', 'repo', 'node')]
    sys.path.insert(0, str(source))
    sys.dont_write_bytecode = True
    from aegis_cli.cli import main
    from aegis_core import testexec
    from aegis_core.regression import check_ci_regressions

    events, runs = [], []
    phase = ['configured']
    def audit(event, args):
        if event == 'subprocess.Popen':
            executable, argv, cwd, _env = args
            events.append({'phase': phase[0], 'executable': str(executable),
                           'argv': list(argv) if isinstance(argv, (list, tuple)) else str(argv),
                           'cwd': str(cwd)})
    sys.addaudithook(audit)
    original = testexec.run_tests
    def observe(argv, cwd, env, timeout, junit, output, *, stderr_output=None):
        row = {'argv': [str(a) for a in argv], 'cwd': str(cwd), 'timeout_s': timeout,
               'phase': phase[0], 'link': link_fact(Path(cwd) / 'node_modules'),
               'stderr_output': str(stderr_output) if stderr_output is not None else None}
        runs.append(row)
        require(list(argv).count('--outputFile') == 1, 'expected one configured native report argument')
        report = Path(argv[list(argv).index('--outputFile') + 1])
        require(report == Path(output).parent / 'results.xml', 'native report path differs from observed output scope')
        row['native_report_path'] = str(report)
        try:
            value = original(argv, cwd, env, timeout, junit, output, stderr_output=stderr_output)
            row['result'] = value.as_dict()
            return value
        finally:
            for label, path in (('junit', report), ('stdout', output), ('stderr', stderr_output)):
                if path is not None and Path(path).is_file():
                    dest = root / ('execution-%d-%s%s' % (len(runs), label, '.xml' if label == 'junit' else '.log'))
                    shutil.copyfile(path, dest)
                    row[label] = {'path': str(dest), 'sha256': digest(dest)}
            save(root / 'snapshot-link-observations.json', runs)

    result = {'status': 'FAIL', 'platform': sys.platform, 'required_link': config['require_link'],
              'scope': 'Linux symlink only; Windows junction PENDING' if sys.platform == 'linux' else 'Windows junction acceptance'}
    try:
        origins = {name: str(Path(module.__file__).resolve()) for name, module in sys.modules.items()
                   if name in ('aegis_core', 'aegis_core.testexec', 'aegis_core.regression', 'aegis_cli.cli')}
        save(root / 'import-origins.json', origins)
        require(all(source in Path(path).parents for path in origins.values()), 'unexpected product import origin')
        testexec.run_tests = observe
        report = check_ci_regressions(repo, 'main', timeout=60)
        save(root / 'configured-report.json', report.as_dict(repo))
        require(len(report.commits) == 1, 'expected one fix commit')
        commit = report.commits[0]
        require((commit.status, commit.reason) == ('passed', 'ok'), 'configured T5 did not pass: ' + commit.reason)
        native = commit.as_dict(repo)['languages']
        require(len(native) == 1 and native[0]['language'] == 'ts' and native[0]['witness'] == 'repo-runner', 'wrong native witness')
        expected = [['tests/app.test.ts', '', 'acceptance > correct value']]
        require(native[0]['fail_to_pass_tests'] == expected, 'unexpected fail-to-pass identity: ' + repr(native[0]['fail_to_pass_tests']))
        require(len(runs) == 2 and [r['result']['exit'] for r in runs] == [0, 1], 'expected actual head PASS/base FAIL')
        require(all('junit' in row for row in runs), 'both actual raw Vitest reports must be retained')
        import xml.etree.ElementTree as ET
        raw_cases = [list(ET.parse(row['junit']['path']).iter('testcase')) for row in runs]
        require([len(cases) for cases in raw_cases] == [1, 1], 'raw Vitest testcase counts differ')
        require([sum(case.find('failure') is not None for case in cases) for cases in raw_cases] == [0, 1],
                'raw Vitest reports do not contain the observed head PASS/base FAIL')
        require(all(Path(r['argv'][0]).resolve() == node for r in runs), 'runner was not the supplied Node')
        for row in runs:
            link = row['link']
            require(Path(link['target']) == repo / 'node_modules', 'snapshot dependency target differs')
            if config['require_link'] == 'junction':
                require(link['reparse_tag'] == 0xA0000003, 'snapshot dependency is not a Windows mount-point junction')
            else:
                require(link['is_symlink'], 'snapshot dependency is not a POSIX symlink')
            row['owned_link_removed'] = not os.path.lexists(link['path'])
            require(row['owned_link_removed'], 'owned snapshot dependency link remained')
        configured_node = [e for e in events if Path(e['executable']).resolve() == node]
        require(len(configured_node) == 2, 'configured flow did not execute exactly two real Node processes')
        testexec.run_tests = original
        phase[0] = 'plain'
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            plain = main(['--workspace', str(repo), 'check', '--base', 'main', '--json'])
        (root / 'plain-report.json').write_text(output.getvalue(), encoding='utf-8')
        require(plain == 0, 'plain check failed')
        require(not any(e['phase'] == 'plain' and Path(e['executable']).resolve() == node for e in events), 'plain check executed Node')
        user_config = Path.home() / '.aegis/config.json'
        user_config.rename(user_config.with_name('configured-disabled.json'))
        phase[0] = 'absent'
        absent = check_ci_regressions(repo, 'main', timeout=60)
        save(root / 'absent-report.json', absent.as_dict(repo))
        require(len(absent.commits) == 1, 'missing-config report did not contain one fix')
        require((absent.commits[0].status, absent.commits[0].reason) == ('unverifiable', 'tests_runner_not_configured'), 'missing-config result differs')
        require(not any(e['phase'] == 'absent' and Path(e['executable']).resolve() == node for e in events), 'missing-config flow executed Node')
        require(absent.findings[0].code == 'tests_runner_not_configured', 'missing-config finding differs')
        result.update(status='PASS', witness='repo-runner', fail_to_pass_tests=expected, head_exit=0, base_exit=1,
                      configured_node_spawns=2, plain_node_spawns=0, absent_node_spawns=0,
                      absent_status=absent.commits[0].status, absent_reason=absent.commits[0].reason)
    except BaseException as exc:
        result.update(error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
    finally:
        testexec.run_tests = original
        save(root / 'snapshot-link-observations.json', runs)
        save(root / 'processes.json', events)
        save(root / 'results.json', result)
    return 0 if result['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    for name in ('source', 'node', 'node-modules', 'fixture', 'package-lock', 'evidence'):
        parser.add_argument('--' + name, type=Path)
    for name in ('expected-audit', 'expected-tree'):
        parser.add_argument('--' + name)
    parser.add_argument('--require-platform', choices=('linux', 'win32'))
    parser.add_argument('--require-link', choices=('symlink', 'junction'))
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker)
    required = ('source', 'node', 'node_modules', 'fixture', 'package_lock', 'evidence',
                'expected_audit', 'expected_tree', 'require_platform', 'require_link')
    for name in required:
        if getattr(args, name) is None:
            parser.error('--' + name.replace('_', '-') + ' is required')
    root = args.evidence.absolute()
    root.mkdir(parents=True, exist_ok=False)
    old_term = signal.signal(signal.SIGTERM, request_stop)
    source, node, dependencies, fixture, lock = [getattr(args, k).resolve() for k in
                                               ('source', 'node', 'node_modules', 'fixture', 'package_lock')]
    env = neutral_environment(root, node, source)
    git_path = shutil.which('git', path=env['PATH'])
    result = {'status': 'FAIL', 'product_source_edited': False, 'provisioning': 'existing files only'}
    before_source = before_dependencies = before_historical = None
    try:
        require(git_path is not None, 'existing Git unavailable')
        require(sys.platform == args.require_platform, 'platform differs from requested evidence scope')
        require((sys.platform == 'linux' and args.require_link == 'symlink') or
                (sys.platform == 'win32' and args.require_link == 'junction'), 'platform/link requirement mismatch')
        before_source = source_facts(source, git_path, env)
        save(root / 'source-before.json', before_source)
        require(before_source['head'] == args.expected_audit, 'source audit mismatch')
        require(before_source['tree'] == args.expected_tree, 'source tree mismatch')
        require(before_source['status'] == '', 'source checkout is dirty')
        require(digest(lock) == LOCK_SHA256, 'M0 lock identity differs')
        before_dependencies = tree_facts(dependencies)
        before_historical = {'node': fact(node), 'lock': fact(lock),
                             'fixture': {p: fact(fixture / p) for p in FIXTURE_FILES}}
        save(root / 'dependency-before.json', before_dependencies)
        save(root / 'historical-before.json', before_historical)
        for name, row in before_dependencies.items():
            if row['kind'] == 'symlink':
                target = (dependencies / name).resolve()
                require(dependencies == target or dependencies in target.parents, 'dependency symlink escapes tree')
        repo = root / 'fixture-repo'
        repo.mkdir()
        git(git_path, repo, env, 'init', '-q', '-b', 'main')
        for name in FIXTURE_FILES:
            if name in ('base-app.ts', 'src/app.ts', 'tests/app.test.ts'):
                continue
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture / name, target)
        (repo / 'src').mkdir()
        shutil.copyfile(fixture / 'base-app.ts', repo / 'src/app.ts')
        (repo / '.gitignore').write_text('node_modules/\n.vite-cache/\n.aegis/state/\n', encoding='utf-8')
        git(git_path, repo, env, 'add', '--', 'package.json', 'vitest.config.mjs', '.aegis', 'src/app.ts', '.gitignore')
        git(git_path, repo, env, 'commit', '-q', '-m', 'chore: Vitest baseline')
        git(git_path, repo, env, 'checkout', '-q', '-b', 'work')
        shutil.copyfile(fixture / 'src/app.ts', repo / 'src/app.ts')
        (repo / 'tests').mkdir()
        shutil.copyfile(fixture / 'tests/app.test.ts', repo / 'tests/app.test.ts')
        git(git_path, repo, env, 'add', '--', 'src/app.ts', 'tests/app.test.ts')
        git(git_path, repo, env, 'commit', '-q', '-m', 'fix: correct value with regression test')
        shutil.copytree(dependencies, repo / 'node_modules', symlinks=False)
        copied = tree_facts(repo / 'node_modules')
        for name, row in before_dependencies.items():
            if row['kind'] == 'file':
                require(copied[name]['sha256'] == row['sha256'], 'dependency copy differs: ' + name)
            else:
                require(copied[name]['sha256'] == digest(dependencies / name), 'dereferenced dependency differs: ' + name)
        save(root / 'copied-dependency-before.json', copied)
        vitest = repo / 'node_modules/vitest/vitest.mjs'
        version = json.loads((vitest.parent / 'package.json').read_text(encoding='utf-8'))['version']
        require(version == '5.0.5', 'Vitest version differs from preserved M0')
        node_version = execute([node, '--version'], root, env, timeout=10)
        save(root / 'tools.json', {'node': str(node), 'node_version': node_version, 'node_sha256': digest(node),
                                  'vitest_version': version, 'vitest_sha256': digest(vitest), 'git': git_path,
                                  'python': sys.executable, 'python_version': sys.version})
        command = [str(node), str(vitest), 'run', '--config', 'vitest.config.mjs', '--reporter', 'junit',
                   '--outputFile', '{junit}', '--maxWorkers', '1', '--no-file-parallelism',
                   '--no-cache', '--no-fsModuleCache', '{files}']
        config = {'v': 1, 'tests': {'languages': {'ts': {'command': command, 'timeout_s': 60}}}}
        user = root / 'home/.aegis/config.json'
        user.parent.mkdir(parents=True)
        save(user, config)
        save(root / 'user-config-used.json', config)
        save(root / 'fixture-before.json', source_facts(repo, git_path, env))
        worker_config = {'evidence': str(root), 'source': str(source), 'repo': str(repo), 'node': str(node),
                         'require_link': args.require_link}
        save(root / 'worker-config.json', worker_config)
        argv = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), '--worker', str(root / 'worker-config.json')]
        COMMANDS.append({'argv': argv, 'cwd': str(root), 'timeout_s': 240})
        with (root / 'worker.stdout.log').open('wb') as stdout, (root / 'worker.stderr.log').open('wb') as stderr:
            owner = OwnedTree(source, root)
            try:
                proc = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, **owner.flags)
                owner.attach(proc)
                code = proc.wait(timeout=240)
            finally:
                owner.close()
        COMMANDS[-1]['exit'] = code
        save(root / 'fixture-after.json', source_facts(repo, git_path, env))
        copied_after = tree_facts(repo / 'node_modules')
        save(root / 'copied-dependency-after.json', copied_after)
        require(copied_after == copied, 'copied dependencies changed during execution')
        require(code == 0, 'public acceptance worker failed; preserve results.json and raw logs')
        require(json.loads((root / 'results.json').read_text(encoding='utf-8'))['status'] == 'PASS', 'public result missing or failed')
        result.update(status='PASS', scope='Linux symlink only; Windows junction PENDING' if os.name != 'nt' else 'Windows junction',
                      public_result='results.json')
    except BaseException as exc:
        result.update(error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
    finally:
        with defer_stops(result):
            def witness(name, collect, before, field):
                try:
                    after = collect()
                    save(root / name, after)
                    result[field] = after == before
                except BaseException as exc:
                    result[field] = False
                    error = {'error_type': type(exc).__name__, 'error': str(exc), 'traceback': traceback.format_exc()}
                    result.setdefault('witness_failures', {})[name] = error
                    save(root / name, error)
            if before_source is not None:
                witness('source-after.json', lambda: source_facts(source, git_path, env), before_source, 'source_stable')
            if before_dependencies is not None:
                witness('dependency-after.json', lambda: tree_facts(dependencies), before_dependencies, 'historical_dependencies_stable')
            if before_historical is not None:
                witness('historical-after.json', lambda: {'node': fact(node), 'lock': fact(lock),
                        'fixture': {p: fact(fixture / p) for p in FIXTURE_FILES}}, before_historical, 'historical_tools_fixture_stable')
            if any(result.get(key) is False for key in ('source_stable', 'historical_dependencies_stable', 'historical_tools_fixture_stable')):
                result['status'] = 'FAIL'
                result['stability_error'] = 'source or historical dependency/tool/fixture changed'
            if result.get('deferred_signals'):
                result['status'] = 'FAIL'
            save(root / 'commands.json', COMMANDS)
            save(root / 'execution.json', result)
            files = {p.name: fact(p) for p in sorted(root.iterdir()) if p.is_file() and p.name != 'manifest.json'}
            save(root / 'manifest.json', {'status': result['status'], 'helper_sha256': digest(Path(__file__)),
                                        'source_audit': args.expected_audit, 'source_tree': args.expected_tree,
                                        'scope': result.get('scope', 'INCOMPLETE'), 'files': files,
                                        'excludes': ['source checkout', 'home/cache directories', 'dependency copies']})
        signal.signal(signal.SIGTERM, old_term)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
