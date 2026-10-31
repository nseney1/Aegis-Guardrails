#!/usr/bin/env python3
"""External AC12/14/17 functional acceptance. Existing tools only; no timing."""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import traceback
import venv

OWNER_SHA = '692cb44ebcf239a34c01b16648e4b923a464de57e94e85362f49f7cc443af474'
OFFLINE = {'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOWORK': 'off',
           'GOFLAGS': '', 'GOENV': 'off', 'CGO_ENABLED': '0'}
RULE = ('---\nid: blocked\ntype: invariant\nenforcement: gate\n'
        'hypothesis: Production Go does not call blocked.\n'
        'target_paths: ["*.go"]\nforbid_ast:\n  calls: [blocked]\n---\n# Blocked\n')
COMMANDS = []

# Only subprocess boundaries and interpreter observation are instrumented.
# No Aegis function, generated hook, compiler output or parser result is replaced.
OBSERVER = r'''
import atexit, hashlib, json, os, pathlib, subprocess, sys, threading, time
sys.dont_write_bytecode = True
config = json.loads(pathlib.Path(os.environ['AEGIS_GO_OBSERVER_CONFIG']).read_text(encoding='utf-8'))
if os.environ.get('AEGIS_GO_OBSERVER_FAIL') == '1':
    raise RuntimeError('controlled observer startup failure')
label = os.environ['AEGIS_GO_OBSERVER_LABEL']
root = pathlib.Path(config['evidence'])
path = root / ('observer-' + label + '-' + str(os.getpid()) + '.jsonl')
lock = threading.Lock()
def record(event, **values):
    row = dict(event=event, pid=os.getpid(), label=label, ns=time.monotonic_ns(), **values)
    with lock:
        with path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, sort_keys=True) + '\n')
def canon(path):
    return os.path.normcase(os.path.abspath(os.fspath(path)))
def category(argv):
    if not isinstance(argv, (list, tuple)) or not argv:
        return 'other'
    if canon(argv[0]) == canon(config['go']):
        return 'go-' + str(argv[1]) if len(argv) > 1 else 'go'
    if pathlib.Path(argv[0]).name.lower().startswith('go_ast-'):
        return 'parser'
    return 'other'
def binary_fact(path):
    p = pathlib.Path(path)
    return dict(path=str(p.resolve()), size=p.stat().st_size,
                sha256=hashlib.sha256(p.read_bytes()).hexdigest())
def audit(event, args):
    if event == 'subprocess.Popen':
        record('audit', argv=[os.fspath(a) for a in args[1]] if isinstance(args[1], (list, tuple)) else args[1])
sys.addaudithook(audit)
original = subprocess.Popen
class ObservedPopen(original):
    def __init__(self, argv, *args, **kwargs):
        kind = category(argv)
        env = kwargs.get('env') or os.environ
        row = dict(argv=[os.fspath(a) for a in argv] if isinstance(argv, (list, tuple)) else argv,
                   kind=kind, cwd=os.fspath(kwargs.get('cwd') or pathlib.Path.cwd()),
                   env={k: env[k] for k in config['environment_keys'] if k in env})
        if kind == 'parser':
            row['binary'] = binary_fact(argv[0])
        if kind == 'go-env' and os.environ.get('AEGIS_GO_BARRIER') == '1':
            marker = root / ('ready-' + label + '.json')
            temporary = marker.with_suffix('.tmp')
            temporary.write_text(json.dumps({'pid': os.getpid(), 'label': label,
                                            'ns': time.monotonic_ns()}), encoding='utf-8')
            os.replace(temporary, marker)
            deadline = time.monotonic() + 10
            while not (root / 'release-hooks.json').is_file():
                if time.monotonic() >= deadline:
                    raise RuntimeError('hook preparation barrier timed out')
                time.sleep(.01)
        record('attempt', **row)
        self._acceptance_exit_recorded = False
        self._acceptance_kind = kind
        try:
            super().__init__(argv, *args, **kwargs)
        except BaseException as exc:
            record('spawn_error', kind=kind, error_type=type(exc).__name__, error=str(exc))
            raise
        record('started', child_pid=self.pid, **row)
    def wait(self, *args, **kwargs):
        code = super().wait(*args, **kwargs)
        if not self._acceptance_exit_recorded:
            self._acceptance_exit_recorded = True
            record('exit', child_pid=self.pid, kind=self._acceptance_kind, returncode=code)
        return code
subprocess.Popen = ObservedPopen
record('startup', executable=sys.executable, prefix=sys.prefix,
       isolated=sys.flags.isolated, no_site=sys.flags.no_site,
       stdout_encoding=sys.stdout.encoding, stderr_encoding=sys.stderr.encoding,
       observer_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest())
def finished():
    record('finished', product_origins={k: getattr(v, '__file__', None) for k,v in sys.modules.items()
           if k in ('aegis_cli', 'aegis_core', 'aegis_mcp', 'aegis_sdk')})
atexit.register(finished)
'''


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def fact(path):
    path = Path(path)
    try:
        info = path.lstat()
        row = {'mode': stat.S_IMODE(info.st_mode), 'size': info.st_size,
               'device': info.st_dev, 'inode': info.st_ino}
        if stat.S_ISLNK(info.st_mode):
            row.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            row.update(kind='file', sha256=digest(path))
        else:
            row.update(kind='directory' if stat.S_ISDIR(info.st_mode) else 'other',
                       reparse_tag=getattr(info, 'st_reparse_tag', None),
                       file_attributes=getattr(info, 'st_file_attributes', None))
        return row
    except OSError as exc:
        return {'kind': 'missing' if isinstance(exc, FileNotFoundError) else 'unreadable',
                'error_type': type(exc).__name__, 'error': str(exc)}


def outside_snapshot(target):
    result = {'.': fact(target)}
    require(result['.']['kind'] == 'directory', 'outside target is not a directory')
    pending = [target]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            row = fact(path)
            result[path.relative_to(target).as_posix()] = row
            require(row['kind'] not in ('missing', 'unreadable'), 'outside target cannot be inventoried')
            if row['kind'] == 'directory' and not (row.get('file_attributes') or 0) & 0x400:
                pending.append(path)
    return result


def input_snapshot(paths, *, require_files=False):
    values = {}
    for value in paths:
        path = Path(value).absolute()
        row = {'entry': fact(path)}
        try:
            resolved = path.resolve(strict=True)
            row.update(resolved_path=str(resolved), resolved=fact(resolved))
        except (OSError, RuntimeError) as exc:
            row.update(resolved_path=None, resolved={'kind': 'unavailable',
                       'error_type': type(exc).__name__, 'error': str(exc)})
        values[str(path)] = row
        if require_files:
            require(row['entry']['kind'] in ('file', 'symlink') and row['resolved']['kind'] == 'file',
                    'input is not a readable regular file: ' + str(path))
    return values


def run(argv, cwd, env, *, timeout=30, expected=0, label=None, evidence=None):
    argv = [os.fspath(a) for a in argv]
    row = {'argv': argv, 'cwd': str(cwd), 'timeout_s': timeout, 'expected': expected}
    COMMANDS.append(row)
    if evidence is None:
        done = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out, err = done.stdout, done.stderr
    else:
        outpath, errpath = evidence / (label + '.stdout.log'), evidence / (label + '.stderr.log')
        with outpath.open('wb') as stdout, errpath.open('wb') as stderr:
            done = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=stdout, stderr=stderr, timeout=timeout)
        out, err = outpath.read_bytes(), errpath.read_bytes()
        row.update(stdout=outpath.name, stderr=errpath.name)
    row.update(returncode=done.returncode)
    if evidence is None:
        row.update(stdout_text=out.decode('utf-8', 'replace'), stderr_text=err.decode('utf-8', 'replace'))
    require(done.returncode == expected, 'unexpected command exit: ' + json.dumps(row))
    return out


def git(git_path, root, env, *args):
    return run([git_path, '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false',
                '-c', 'core.hooksPath=' + os.devnull, '-c', 'commit.gpgsign=false',
                '-c', 'tag.gpgsign=false', '-c', 'user.name=Go Acceptance',
                '-c', 'user.email=acceptance@example.invalid', *args], root, env).decode('utf-8').strip()


def witness(source, git_path, env, *, include_ignored=False):
    raw = git(git_path, source, env, 'ls-files', '--stage', '-z')
    files = {}
    for row in raw.split('\0'):
        if row:
            metadata, name = row.split('\t', 1)
            mode, blob, stage = metadata.split()
            require(stage == '0', 'unmerged source path: ' + name)
            files[name] = dict(fact(source / name), git_mode=mode, git_blob=blob)
    index = Path(git(git_path, source, env, 'rev-parse', '--git-path', 'index'))
    if not index.is_absolute():
        index = source / index
    status_args = ['status', '--porcelain=v1', '--untracked-files=all']
    if include_ignored:
        status_args.append('--ignored=matching')
    return {'head': git(git_path, source, env, 'rev-parse', 'HEAD'),
            'tree': git(git_path, source, env, 'rev-parse', 'HEAD^{tree}'),
            'status': git(git_path, source, env, *status_args),
            'index_sha256': digest(index), 'index_entries_sha256': hashlib.sha256(raw.encode()).hexdigest(),
            'files': files}


def validate_source(source, git_path, env, audit, tree):
    value = witness(source, git_path, env, include_ignored=True)
    require(value['head'] == audit and value['tree'] == tree and value['status'] == '',
            'source must be a clean detached checkout of the explicit audit/tree')
    rows = git(git_path, source, env, 'ls-tree', '-r', '-z', audit)
    expected = {}
    for row in rows.split('\0'):
        if row:
            metadata, name = row.split('\t', 1)
            mode, kind, blob = metadata.split()
            require(kind == 'blob', 'source contains an unsupported tracked object')
            expected[name] = (mode, blob)
    require(set(value['files']) == set(expected), 'tracked file inventory differs from audit')
    for name, row in value['files'].items():
        mode, blob = expected[name]
        path = source / name
        require(row['kind'] in ('file', 'symlink'), 'missing or unreadable tracked file: ' + name)
        raw = os.readlink(path).encode() if row['kind'] == 'symlink' else path.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw, usedforsecurity=False).hexdigest()
        require((row['git_mode'], row['git_blob']) == (mode, blob) and actual == blob,
                'tracked source bytes or index differ: ' + name)
    return value


def neutral_environment(root, cfg):
    env = {k: os.environ[k] for k in ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'COMSPEC',
                                    'PATHEXT', 'NUMBER_OF_PROCESSORS') if k in os.environ}
    paths = [str(Path(cfg[k]).parent) for k in ('go', 'git', 'bash', 'python')]
    paths.extend(p for p in os.environ.get('PATH', '').split(os.pathsep) if p and Path(p).is_absolute())
    trusted = []
    source = Path(cfg['source']).resolve()
    for value in paths:
        path = Path(value).resolve()
        if path == source or source in path.parents:
            continue
        if str(path) not in trusted:
            trusted.append(str(path))
    env['PATH'] = os.pathsep.join(trusted)
    for key, name in {'HOME': 'home', 'USERPROFILE': 'home', 'XDG_CONFIG_HOME': 'config',
                      'XDG_CACHE_HOME': 'cache', 'LOCALAPPDATA': 'cache', 'APPDATA': 'config',
                      'XDG_DATA_HOME': 'data', 'XDG_STATE_HOME': 'state', 'TMPDIR': 'tmp',
                      'TMP': 'tmp', 'TEMP': 'tmp', 'GOCACHE': 'compiler-cache',
                      'GOMODCACHE': 'modules'}.items():
        path = root / name
        path.mkdir(exist_ok=True)
        env[key] = str(path)
    env.update(OFFLINE)
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    return env


def setup_venv(root, cfg, env):
    target = root / 'observer-venv'
    require(not target.exists(), 'observer venv must be fresh')
    venv.EnvBuilder(with_pip=False, system_site_packages=False, symlinks=os.name != 'nt').create(target)
    python = target / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    site = Path(run([python, '-I', '-B', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
                    root, env, timeout=10).decode().strip())
    require(os.path.commonpath([str(site), str(target)]) == str(target), 'venv site escapes private root')
    (site / 'aegis_go_acceptance_observer.py').write_text(OBSERVER, encoding='ascii')
    (site / 'aegis_go_acceptance_observer.pth').write_text('import aegis_go_acceptance_observer\n', encoding='ascii')
    observer_cfg = {'evidence': str(root), 'go': cfg['go'],
                    'environment_keys': sorted(set(OFFLINE) | {'GO111MODULE', 'GOCACHE', 'HOME',
                                                              'USERPROFILE', 'PATH', 'GOMODCACHE'})}
    save(root / 'observer-config.json', observer_cfg)
    save(root / 'venv.json', {'python': str(python), 'site': str(site), 'pip': False,
                             'system_site': False, 'observer_sha256': digest(site / 'aegis_go_acceptance_observer.py'),
                             'pth_sha256': digest(site / 'aegis_go_acceptance_observer.pth'),
                             'pyvenv_cfg': (target / 'pyvenv.cfg').read_text(encoding='utf-8')})
    env = dict(env, AEGIS_GO_OBSERVER_CONFIG=str(root / 'observer-config.json'))
    generated = [site / 'aegis_go_acceptance_observer.py',
                 site / 'aegis_go_acceptance_observer.pth', root / 'observer-config.json',
                 root / 'worker-config.json', target / 'pyvenv.cfg', python]
    save(root / 'generated-inputs-before.json', input_snapshot(generated, require_files=True))
    return python, env


def observed(root, label, *, product=False):
    paths = list(root.glob('observer-' + label + '-*.jsonl'))
    require(len(paths) == 1, 'missing or duplicate observer log: ' + label)
    rows = [json.loads(line) for line in paths[0].read_text(encoding='utf-8').splitlines()]
    startup = [r for r in rows if r['event'] == 'startup']
    finished = [r for r in rows if r['event'] == 'finished']
    require(len(startup) == 1 and startup[0]['isolated'] == 1 and startup[0]['no_site'] == 0,
            'observer startup not witnessed: ' + label)
    require(len(finished) == 1, 'observer completion missing: ' + label)
    require(not any(r['event'] == 'spawn_error' for r in rows), 'actual subprocess launch failed')
    starts = [r for r in rows if r['event'] == 'started']
    audits = [r for r in rows if r['event'] == 'audit']
    require(len(starts) == len(audits), 'observer/audit subprocess counts differ')
    exits = [r for r in rows if r['event'] == 'exit']
    require({r['child_pid'] for r in starts} == {r['child_pid'] for r in exits},
            'a real subprocess exit was not observed')
    if product:
        origins = finished[0]['product_origins']
        require('aegis_core' in origins and 'aegis_cli' in origins, 'actual CLI imports missing')
        source = Path(json.loads((root / 'worker-config.json').read_text())['source'])
        require(all(p and os.path.commonpath([str(Path(p).resolve()), str(source)]) == str(source)
                    for p in origins.values()), 'wrong product import origin')
    for row in starts:
        if row['kind'].startswith('go-'):
            require(all(row['env'].get(k) == v for k, v in OFFLINE.items()),
                    'real Go command did not retain offline controls')
    return rows


def fixture(root, name, count, cfg, env):
    repo = root / 'fixtures' / name
    repo.mkdir(parents=True)
    git(cfg['git'], repo, env, 'init', '-q', '-b', 'main')
    (repo / '.aegis/rules/invariants').mkdir(parents=True)
    (repo / '.gitignore').write_text('.aegis/state/\n', encoding='ascii')
    (repo / '.aegis/config.json').write_text('{"v":1,"ast":{"packaged_drivers":["go"]}}\n', encoding='ascii')
    (repo / '.aegis/rules/invariants/blocked.md').write_text(RULE, encoding='ascii')
    git(cfg['git'], repo, env, 'add', '--', '.gitignore', '.aegis')
    git(cfg['git'], repo, env, 'commit', '-qm', 'chore: seed enforced Go acceptance rule')
    names = ['file%02d.go' % i for i in range(count)]
    for i, name in enumerate(names):
        (repo / name).write_text('package sample\nfunc F%02d() { blocked() }\n' % i, encoding='ascii')
    git(cfg['git'], repo, env, 'add', '--', *names)
    return repo, names


def cli(python, source, repo, names):
    bootstrap = 'import sys; sys.path.insert(0,sys.argv[1]); from aegis_cli.cli import main; sys.exit(main(sys.argv[2:]))'
    return [python, '-I', '-B', '-c', bootstrap, source, 'check', '--workspace', repo, '--json', *names]


def check_findings(payload, names):
    require(payload['passed'] is False and sorted(payload['files']) == sorted(names), 'wrong public check outcome/files')
    failures = [r for r in payload['layer1'] if r['verdict'] is False]
    expected = [('forbid_ast:blocked', n, [2]) for n in names]
    require(sorted((r['tool'], r['target'], r.get('lines')) for r in failures) == sorted(expected),
            'public check did not retain every exact enforced finding')
    require(all(r['detail'] == "Forbidden call 'blocked' matched rule forbid_ast.calls" for r in failures),
            'finding was unverified or had another reason')


def parser_facts(source, repo, names, output):
    sys.path.insert(0, str(source))
    from aegis_core.ast.runner import ASTDriverRunner
    with ASTDriverRunner() as parser:
        values = {name: dataclasses.asdict(parser.parse_file(repo / name, workspace_root=repo)) for name in names}
    for name, value in values.items():
        require(value['definitions'] and value['call_sites'], 'empty normalized AST: ' + name)
        require(any(site['target'] == 'blocked' and site['line'] == 2 for site in value['call_sites']),
                'canonical Go call fact missing')
    save(output, values)


def cache_dir(base):
    return base / ('aegis/Cache/drivers' if os.name == 'nt' else 'aegis/drivers')


def cache_env(env, base):
    return dict(env, XDG_CACHE_HOME=str(base), LOCALAPPDATA=str(base))


def starts(rows, kind):
    return [r for r in rows if r['event'] == 'started' and r['kind'] == kind]


def do_acceptance(root, cfg, env, python):
    source = Path(cfg['source'])
    version = run([cfg['go'], 'env', 'GOVERSION', 'GOOS', 'GOARCH'], root, env, timeout=3).decode().strip().splitlines()
    require(len(version) == 3, 'Go metadata must have three lines')
    match = re.fullmatch(r'go(\d+)\.(\d+)(?:\.\d+)?(?:beta\d+|rc\d+)?', version[0])
    require(match is not None and tuple(map(int, match.groups())) >= (1, 21), 'existing Go >=1.21 required')
    require(version[1] == ('windows' if os.name == 'nt' else 'linux'), 'Go host OS mismatch')
    save(root / 'go-version.json', {'lines': version, 'binary': fact(Path(cfg['go'])), 'argv': COMMANDS[-1]['argv']})
    results = {}
    repo, names = fixture(root, 'ac12', 50, cfg, env)
    before = witness(repo, cfg['git'], env)
    save(root / 'ac12-fixture-before.json', before)
    warm_base = root / 'ac12-cache'
    warm_base.mkdir()
    warm_env = cache_env(env, warm_base)
    payload = dict(cfg, action='parse', repo=str(repo), names=names,
                   output=str(root / 'ac12-normalized-asts.json'))
    save(root / 'warm-config.json', payload)
    bootstrap = 'import runpy,sys; path=sys.argv.pop(1); runpy.run_path(path,run_name="__main__")'
    run([python, '-I', '-B', '-c', bootstrap, cfg['helper'], '--parse-worker', root / 'warm-config.json'],
        root, dict(warm_env, AEGIS_GO_OBSERVER_LABEL='ac12-warmup'), timeout=300,
        label='ac12-warmup', evidence=root)
    warm_rows = observed(root, 'ac12-warmup')
    require(len(starts(warm_rows, 'go-build')) == 1 and len(starts(warm_rows, 'parser')) == 1,
            'fresh AC12 warmup must build and run exactly one actual driver')
    raw = run(cli(python, source, repo, names), repo,
              dict(warm_env, AEGIS_GO_OBSERVER_LABEL='ac12-check'), timeout=300,
              expected=1, label='ac12-check', evidence=root)
    public = json.loads(raw)
    check_findings(public, names)
    rows = observed(root, 'ac12-check', product=True)
    require(len(starts(rows, 'parser')) == 1 and not starts(rows, 'go-build'),
            'warm fifty-file public CLI did not use one parser and zero builds')
    after = witness(repo, cfg['git'], env)
    save(root / 'ac12-fixture-after.json', after)
    require(after == before, 'AC12 fixture changed')
    results['ac12'] = {'status': 'PASS', 'files': 50, 'findings': 50, 'parser_processes': 1, 'warm_builds': 0}
    save(root / 'scenario-results.json', results)

    for label in ('ac14-workspace', 'ac14-link'):
        repo, names = fixture(root, label, 1, cfg, env)
        before = witness(repo, cfg['git'], env)
        save(root / (label + '-fixture-before.json'), before)
        link = None
        link_before = None
        target = None
        if label.endswith('workspace'):
            bad_base = repo / 'unsafe-cache'
            bad_base.mkdir()
        else:
            target = root / 'outside-cache-target'
            target.mkdir()
            (target / 'sentinel.txt').write_text('preserve outside target\n', encoding='ascii')
            target_before = outside_snapshot(target)
            link = root / 'cache-link'
            if os.name == 'nt':
                sys.path.insert(0, str(source))
                from aegis_core.verification.windows_junction import create_directory_junction
                create_directory_junction(target, link)
            else:
                link.symlink_to(target, target_is_directory=True)
            link_before = fact(link)
            require(link.resolve() == target.resolve(), 'cache link target mismatch')
            if os.name == 'nt':
                require(link_before['reparse_tag'] == 0xA0000003 and
                        link_before['file_attributes'] & 0x400, 'actual junction tag/attribute required')
            else:
                require(link_before['kind'] == 'symlink', 'actual Linux symlink required')
            save(root / 'ac14-link-identity.json', {'link': link_before, 'target': str(target.resolve()),
                                                   'target_inventory': target_before})
            bad_base = link
        try:
            raw = run(cli(python, source, repo, names), repo,
                      dict(cache_env(env, bad_base), AEGIS_GO_OBSERVER_LABEL=label), timeout=300,
                      expected=1, label=label, evidence=root)
            public = json.loads(raw)
            require(public['passed'] is False, 'unsafe cache was accepted')
            matching = [r for r in public['layer1'] if r['tool'] == 'forbid_ast:blocked']
            require(len(matching) == 1 and matching[0]['verdict'] is False and
                    'driver_unavailable:cache_unsafe' in matching[0]['detail'], 'wrong unsafe cache public finding')
            rows = observed(root, label, product=True)
            require(not any(r['event'] == 'started' and (r['kind'].startswith('go-') or r['kind'] == 'parser')
                            for r in rows), 'unsafe cache launched a compiler or parser')
        finally:
            if link is not None:
                require(fact(link) == link_before and link.resolve() == target.resolve(), 'cache link changed before cleanup')
                if os.name == 'nt':
                    link.rmdir()
                else:
                    link.unlink()
                require(outside_snapshot(target) == target_before, 'outside link target changed')
                save(root / 'ac14-link-cleanup.json', {'status': 'PASS', 'link_absent': not os.path.lexists(link),
                                                       'target_unchanged': True})
        after = witness(repo, cfg['git'], env)
        save(root / (label + '-fixture-after.json'), after)
        require(after == before, 'AC14 tracked fixture changed')
        results[label] = {'status': 'PASS', 'compiler_processes': 0, 'parser_processes': 0,
                          'reason': 'driver_unavailable:cache_unsafe'}
        save(root / 'scenario-results.json', results)

    sys.path.insert(0, str(source))
    from aegis_cli.hooks.management import install_hook
    shared = root / 'ac17-shared-cache'
    shared.mkdir()
    hooks = []
    for name in ('ac17a', 'ac17b'):
        repo, names = fixture(root, name, 2, cfg, env)
        require(install_hook(repo, python=str(python), import_root=str(source)), 'public hook installation failed')
        hook = repo / '.git/hooks/pre-commit'
        (root / (name + '-generated-hook.sh')).write_bytes(hook.read_bytes())
        hooks.append({'name': name, 'repo': repo, 'names': names, 'hook': hook,
                      'hook_before': fact(hook), 'before': witness(repo, cfg['git'], env)})
        save(root / (name + '-fixture-before.json'), hooks[-1]['before'])
    save(root / 'hook-inputs-before.json', input_snapshot([item['hook'] for item in hooks], require_files=True))
    require(not list(cache_dir(shared).glob('go_ast-*')), 'shared driver cache must start empty')
    handles = []
    try:
        for item in hooks:
            label = item['name']
            stdout = (root / (label + '.stdout.log')).open('wb')
            stderr = (root / (label + '.stderr.log')).open('wb')
            handles.extend([stdout, stderr])
            argv = [cfg['bash'], '--noprofile', '--norc', str(item['hook'])]
            item['command'] = {'argv': argv, 'cwd': str(item['repo']), 'timeout_s': 300}
            COMMANDS.append(item['command'])
            item['proc'] = subprocess.Popen(argv, cwd=item['repo'],
                env=dict(cache_env(env, shared), AEGIS_GO_OBSERVER_LABEL=label, AEGIS_GO_BARRIER='1'),
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + 10
        while not all((root / ('ready-' + item['name'] + '.json')).is_file() for item in hooks):
            require(all(item['proc'].poll() is None for item in hooks), 'a generated hook exited before readiness')
            require(time.monotonic() < deadline, 'two-hook readiness timed out')
            time.sleep(.01)
        ready = [json.loads((root / ('ready-' + item['name'] + '.json')).read_text()) for item in hooks]
        require(len({row['pid'] for row in ready}) == 2, 'hooks did not use two real interpreter processes')
        require(not list(cache_dir(shared).glob('go_ast-*')), 'shared cache was populated before concurrent release')
        save(root / 'release-hooks.json', {'ready': ready, 'shared_cache_empty': True, 'release_ns': time.monotonic_ns()})
        finish_by = time.monotonic() + 300
        for item in hooks:
            item['command']['returncode'] = item['proc'].wait(timeout=max(.01, finish_by - time.monotonic()))
            require(item['proc'].returncode == 1, 'generated hook did not fail on its real findings')
    finally:
        for handle in handles:
            handle.close()
    hook_rows = []
    for item in hooks:
        label = item['name']
        rows = observed(root, label, product=True)
        hook_rows.extend(rows)
        require(len(starts(rows, 'parser')) == 1, 'each real hook must use one parser')
        startup = next(r for r in rows if r['event'] == 'startup')
        text = (root / (label + '.stdout.log')).read_bytes().decode(startup['stdout_encoding'], 'strict')
        found = [line for line in text.splitlines() if 'forbid_ast:blocked:' in line]
        require(len(found) == 2 and all(any('forbid_ast:blocked: ' + name in line and
                "Forbidden call 'blocked' matched rule forbid_ast.calls" in line for line in found)
                for name in item['names']), 'generated hook lost its exact findings')
        require(fact(item['hook']) == item['hook_before'], 'generated hook was modified')
        after = witness(item['repo'], cfg['git'], env)
        save(root / (label + '-fixture-after.json'), after)
        require(after == item['before'], 'hook changed tracked fixture/index')
    builds = starts(hook_rows, 'go-build')
    parsers = starts(hook_rows, 'parser')
    require(len(builds) == 1 and len(parsers) == 2, 'cold hooks did not share exactly one actual build')
    require(any(r['event'] == 'exit' and r['kind'] == 'go-build' and r['child_pid'] == builds[0]['child_pid']
                and r['returncode'] == 0 for r in hook_rows), 'actual compiler success missing')
    binary = parsers[0]['binary']
    require(binary == parsers[1]['binary'] and binary['size'] > 0, 'hooks launched different or empty binaries')
    require(digest(binary['path']) == binary['sha256'] and Path(binary['path']).stat().st_size == binary['size'],
            'published binary differs from both actual launches')
    require(not list(cache_dir(shared).glob('.go-build-*')), 'private build directory remains')
    save(root / 'ac17-binary.json', binary)
    # Independent, separately labeled public AST evidence after concurrency.
    parse_cfg = dict(cfg, action='parse', repo=str(hooks[0]['repo']), names=hooks[0]['names'],
                     output=str(root / 'ac17-normalized-asts.json'))
    save(root / 'post-hooks-config.json', parse_cfg)
    run([python, '-I', '-B', '-c', bootstrap, cfg['helper'], '--parse-worker', root / 'post-hooks-config.json'],
        root, dict(cache_env(env, shared), AEGIS_GO_OBSERVER_LABEL='ac17-post-parse'),
        timeout=30, label='ac17-post-parse', evidence=root)
    post_rows = observed(root, 'ac17-post-parse')
    require(not starts(post_rows, 'go-build'), 'post-hook facts unexpectedly rebuilt')
    results['ac17'] = {'status': 'PASS', 'hook_processes': 2, 'builds': 1, 'parser_processes': 2,
                      'findings_per_hook': 2, 'identical_complete_binary': binary}
    save(root / 'scenario-results.json', results)
    return results


def observer_controls(root, cfg, env, python):
    script = 'import subprocess,sys; subprocess.run([sys.executable,"-I","-S","-B","-c","print(17)"],check=True)'
    run([python, '-I', '-B', '-c', script], root, dict(env, AEGIS_GO_OBSERVER_LABEL='health'),
        timeout=10, label='observer-health', evidence=root)
    rows = observed(root, 'health')
    require(len(starts(rows, 'other')) == 1, 'benign subprocess observation missing')
    run([python, '-I', '-B', '-c', 'print("child continued after pth error")'], root,
        dict(env, AEGIS_GO_OBSERVER_LABEL='broken', AEGIS_GO_OBSERVER_FAIL='1'),
        timeout=10, label='observer-broken', evidence=root)
    require('controlled observer startup failure' in (root / 'observer-broken.stderr.log').read_text(),
            'controlled observer failure did not occur')
    try:
        observed(root, 'broken')
    except AssertionError as exc:
        require(str(exc) == 'missing or duplicate observer log: broken', 'wrong observer rejection')
        result = {'status': 'PASS', 'negative_control': 'EXPECTED_REJECTION', 'error': str(exc)}
        save(root / 'observer-control.json', result)
        return result
    raise AssertionError('missing observer was incorrectly accepted as zero activity')


def worker(config_path):
    cfg = json.loads(Path(config_path).read_text(encoding='utf-8'))
    root = Path(cfg['evidence'])
    result = {'status': 'FAIL', 'mode': cfg['mode']}
    try:
        env = neutral_environment(root, cfg)
        python, env = setup_venv(root, cfg, env)
        if cfg['mode'] == 'controls':
            result['observer'] = observer_controls(root, cfg, env, python)
        else:
            result['scenarios'] = do_acceptance(root, cfg, env, python)
        result['status'] = 'PASS'
    except BaseException as exc:
        result.update(error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
    finally:
        save(root / 'worker-commands.json', COMMANDS)
        save(root / 'worker-result.json', result)
    return 0 if result['status'] == 'PASS' else 1


def cleanup_worker(root):
    root = Path(root)
    script = ('import json,os,pathlib,time; pathlib.Path(' + repr(str(root / 'descendant-ready.json')) +
              ').write_text(json.dumps({"pid":os.getpid()})); time.sleep(600)')
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', script],
                             stdin=subprocess.DEVNULL, **flags)
    save(root / 'cleanup-child.json', {'pid': child.pid, 'separate_session': os.name != 'nt'})
    time.sleep(600)


def load_owner(path):
    require(digest(path) == OWNER_SHA, 'ownership helper hash differs')
    spec = importlib.util.spec_from_file_location('go_acceptance_owned_tree', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def witness_probe(root, cfg, env):
    setup_venv(root, cfg, env)
    target = root / 'outside-control-target'
    target.mkdir()
    (target / 'sentinel.txt').write_text('preserve outside target\n', encoding='ascii')
    before = outside_snapshot(target)
    save(root / 'outside-target-before.json', before)
    ready = root / 'witness-probe-ready.tmp'
    save(ready, {'outside_target': str(target), 'source': cfg['source'],
                'copied_tool': cfg['bash'], 'observer_config': str(root / 'observer-config.json')})
    os.replace(ready, root / 'witness-probe-ready.json')
    deadline = time.monotonic() + 10
    while not (root / 'release-witness-probe.json').is_file():
        require(time.monotonic() < deadline, 'witness probe release timed out')
        time.sleep(.01)
    after = outside_snapshot(target)
    save(root / 'outside-target-after.json', after)
    require(after == before, 'outside target inventory changed')
    return {'status': 'PASS', 'scope': 'disposable witness control only; no Go or product import'}


def owned_worker(owner_module, source, root, argv, env, *, timeout, cleanup_control=False):
    owner = owner_module.OwnedTree(source, root)
    result = {'status': 'INCOMPLETE', 'argv': [str(a) for a in argv], 'timeout_s': timeout}
    proc = None
    try:
        with (root / 'owned-worker.stdout.log').open('wb') as stdout, (root / 'owned-worker.stderr.log').open('wb') as stderr:
            proc = subprocess.Popen([str(a) for a in argv], cwd=root, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, **owner.flags)
            owner.attach(proc)
            if cleanup_control:
                deadline = time.monotonic() + 10
                while not (root / 'descendant-ready.json').is_file():
                    require(proc.poll() is None, 'cleanup worker exited before descendant readiness')
                    require(time.monotonic() < deadline, 'cleanup descendant did not become ready')
                    time.sleep(.01)
                try:
                    proc.wait(timeout=.2)
                except subprocess.TimeoutExpired:
                    result['expected_timeout'] = True
                else:
                    raise AssertionError('cleanup control unexpectedly exited without timeout')
            else:
                result['returncode'] = proc.wait(timeout=timeout)
                require(proc.returncode == 0, 'functional worker failed')
            result['status'] = 'PASS'
    except BaseException as exc:
        result.update(status='FAIL', error_type=type(exc).__name__, error=str(exc),
                      traceback=traceback.format_exc())
    finally:
        try:
            owner.close()
            result['cleanup'] = owner.record
        except BaseException as exc:
            result.update(status='FAIL', cleanup_error=type(exc).__name__ + ': ' + str(exc))
        if cleanup_control and result['status'] == 'PASS':
            try:
                child = json.loads((root / 'descendant-ready.json').read_text())['pid']
                if os.name == 'nt':
                    require(owner.record['before']['TotalProcesses'] >= 2 and
                            owner.record['after']['ActiveProcesses'] == 0, 'owned Windows descendants not proved stopped')
                else:
                    require(any(row['pid'] == child for row in owner.record['owned']),
                            'separate-session descendant absent from owned cleanup receipt')
                result['controlled_descendant'] = child
            except BaseException as exc:
                result.update(status='FAIL', cleanup_control_error=type(exc).__name__ + ': ' + str(exc))
        save(root / 'owned-worker-result.json', result)
    require(result['status'] == 'PASS', 'owned worker or cleanup failed; inspect raw evidence')
    return result


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        return worker(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == '--cleanup-worker':
        cleanup_worker(sys.argv[2])
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == '--parse-worker':
        cfg = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
        parser_facts(Path(cfg['source']), Path(cfg['repo']), cfg['names'], Path(cfg['output']))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'go', 'git', 'bash', 'ownership-helper', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--audit', required=True)
    parser.add_argument('--tree', required=True)
    parser.add_argument('--require-platform', choices=('linux', 'win32'), required=True)
    parser.add_argument('--mode', choices=('controls', 'witness-probe', 'acceptance'), required=True)
    parser.add_argument('--root-inspected', action='store_true',
                        help='Required only for the single real functional run after root inspects this frozen helper.')
    args = parser.parse_args()
    require(args.require_platform == sys.platform, 'requested platform differs from host')
    require(args.mode != 'acceptance' or args.root_inspected, 'root inspection acknowledgement required')
    root = args.evidence.absolute()
    require(not root.exists(), 'evidence directory must be new; never overwrite failures')
    root.mkdir(parents=True)
    cfg = {'source': str(args.source.resolve()), 'audit': args.audit, 'tree': args.tree,
           'go': str(args.go.resolve()), 'git': str(args.git.resolve()), 'bash': str(args.bash.resolve()),
           'python': sys.executable, 'helper': str(Path(__file__).resolve()), 'evidence': str(root),
           'mode': args.mode, 'platform': args.require_platform}
    result = {'status': 'FAIL', 'mode': args.mode, 'platform': sys.platform,
              'windows_acceptance': 'UNRUN' if os.name != 'nt' else 'THIS_RUN',
              'scope': 'functional only; no performance or full-suite evidence'}
    env = neutral_environment(root, cfg)
    before = None
    owner_module = None
    old_term = signal.getsignal(signal.SIGTERM)
    try:
        for key in ('source', 'go', 'git', 'bash'):
            require(Path(cfg[key]).exists(), 'missing explicit input: ' + key)
        owner_module = load_owner(args.ownership_helper.resolve())
        signal.signal(signal.SIGTERM, owner_module.request_stop)
        before = validate_source(Path(cfg['source']), cfg['git'], env, args.audit, args.tree)
        save(root / 'source-before.json', before)
        save(root / 'worker-config.json', cfg)
        save(root / 'inputs.json', {'helper': fact(Path(__file__)), 'owner': fact(args.ownership_helper),
                                   'tools': {k: fact(Path(cfg[k])) for k in ('go', 'git', 'bash', 'python')},
                                   'environment': env, 'python_version': sys.version,
                                   'source_audit': args.audit, 'source_tree': args.tree})
        watched = [Path(__file__).resolve(), args.ownership_helper.resolve(),
                   *[Path(cfg[k]) for k in ('go', 'git', 'bash', 'python')],
                   root / 'worker-config.json']
        save(root / 'input-witness-before.json', input_snapshot(watched, require_files=True))
        if args.mode == 'witness-probe':
            result['witness_probe'] = witness_probe(root, cfg, env)
        else:
            argv = [sys.executable, '-I', '-S', '-B', cfg['helper'], '--worker', root / 'worker-config.json']
            result['worker'] = owned_worker(owner_module, Path(cfg['source']), root, argv, env,
                                           timeout=60 if args.mode == 'controls' else 600)
            public = json.loads((root / 'worker-result.json').read_text(encoding='utf-8'))
            require(public['status'] == 'PASS', 'public functional result failed')
            result['public'] = public
        if args.mode == 'controls':
            cleanup = root / 'cleanup-control'
            cleanup.mkdir()
            result['cleanup_control'] = owned_worker(owner_module, Path(cfg['source']), cleanup,
                [sys.executable, '-I', '-S', '-B', cfg['helper'], '--cleanup-worker', cleanup],
                env, timeout=10, cleanup_control=True)
        result['status'] = 'PASS'
    except BaseException as exc:
        result.update(status='FAIL', error_type=type(exc).__name__, error=str(exc),
                      traceback=traceback.format_exc())
    finally:
        manager = owner_module.defer_stops(result) if owner_module else __import__('contextlib').nullcontext()
        with manager:
            if before is not None:
                try:
                    after = witness(Path(cfg['source']), cfg['git'], env, include_ignored=True)
                    save(root / 'source-after.json', after)
                    result['source_equal'] = after == before
                    if after != before:
                        result.update(status='FAIL', witness_error='tracked source/HEAD/index/modes changed')
                except BaseException as exc:
                    result.update(status='FAIL', source_equal=False,
                                  witness_error=type(exc).__name__ + ': ' + str(exc))
                    save(root / 'source-after.json', {'status': 'FAIL', 'error': result['witness_error']})
            for label in ('input-witness', 'generated-inputs', 'hook-inputs'):
                before_path = root / (label + '-before.json')
                if before_path.is_file():
                    try:
                        prior = json.loads(before_path.read_text(encoding='utf-8'))
                        current = input_snapshot(prior)
                        save(root / (label + '-after.json'), current)
                        result[label + '_equal'] = current == prior
                        if current != prior:
                            result.update(status='FAIL')
                            result.setdefault('input_witness_errors', {})[label] = 'input changed, disappeared or became unreadable'
                    except BaseException as exc:
                        result.update(status='FAIL')
                        result[label + '_equal'] = False
                        failure = {'status': 'FAIL', 'error_type': type(exc).__name__, 'error': str(exc)}
                        result.setdefault('input_witness_errors', {})[label] = failure
                        save(root / (label + '-after.json'), failure)
                elif label != 'hook-inputs' and result['status'] == 'PASS':
                    result.update(status='FAIL')
                    result.setdefault('input_witness_errors', {})[label] = 'required before witness missing'
            if result.get('deferred_signals'):
                result['status'] = 'FAIL'
            save(root / 'parent-commands.json', COMMANDS)
            save(root / 'execution.json', result)
            files = {p.name: fact(p) for p in sorted(root.iterdir()) if p.is_file() and p.name != 'manifest.json'}
            control = root / 'cleanup-control'
            if control.is_dir():
                files.update({'cleanup-control/' + p.name: fact(p) for p in sorted(control.iterdir()) if p.is_file()})
            save(root / 'manifest.json', {'status': result['status'], 'helper_sha256': digest(Path(__file__)),
                                         'ownership_sha256': OWNER_SHA, 'source_audit': args.audit,
                                         'source_tree': args.tree, 'mode': args.mode, 'files': files,
                                         'excludes': ['fixtures', 'venv', 'source', 'caches', 'executable payloads']})
        signal.signal(signal.SIGTERM, old_term)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
