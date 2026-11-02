"""Portable final-source Go P3; preparation controls never measure.

Requires an explicit frozen candidate, existing local Go, and root's quiet-window
confirmation. No dependencies or toolchains are fetched. This is the historical
50-file/seven-session fixture gate, not a general performance or cross-OS claim.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path, PurePosixPath

PYTHON = str(Path(sys.executable).resolve())
GIT = shutil.which('git')
ORIGINAL_SHA256 = 'aeb3eb95caa13df32c6b607fec77558a9417da95f1ef41072b0c20acc945b287'
OWNER_SHA256 = '692cb44ebcf239a34c01b16648e4b923a464de57e94e85362f49f7cc443af474'
DARWIN_SHA256 = '8695d8f0cdfb068ede1bbb16d29b617313acec47a555cf36ade81f3838162976'
DARWIN_PROBE_SHA256 = 'b7f5f54cd81a30fcfc3b97b7fe1a5ab6cb2e3471129b78c02ff5913dc5ba36bc'
MEASURED_BLOCK_SHA256 = 'b72cae6c7775ecd26a2ff99110955fcaffd7963aca585ce50c2c916196ef5c69'
FIXTURE = b'package fixture\nimport ex "os/exec"\nfunc Run() { ex.Command("echo", "hello") }\n'
FIXTURE_HASH = 'c4c7cdd742cab66478dc7881281c9b8408d34f891f7ee92710b5878015bab83e'
PROTOCOL = {
    'scope': 'one explicit host, frozen source tree and existing Go toolchain; platform acceptance is separate',
    'history': '/tmp/aegis-v45-m1b/probe_go.py and go-v2-probe.json; never executed or overwritten',
    'historical_recipe_sha256': '497fd1298a6a153fbeef6a2c21628690ebc28145b46e9cc1a57efd54aacda96f',
    'historical_result_sha256': '1dc28173c0f2b6496587b358924679f186bbf6f214b5a25850e520802b53a3ff',
    'fixture_files': 50, 'fixture_bytes_per_file': 79, 'fixture_lines_per_file': 3,
    'fixture_order': 'fixture0.go through fixture49.go in numeric order',
    'fixture_sha256': FIXTURE_HASH, 'samples': 7, 'limit_ms': 300,
    'statistic': 'statistics.median of all seven unrounded milliseconds, <= 300',
    'cold': 'fresh isolated cache; prepare_go_driver(workspace, timeout=120.0), separately timed',
    'timed': 'one default ASTDriverRunner context, 50 public parse_file calls and original language/canonical-call assertion, context close',
    'warm': 'each sample must start exactly one cached packaged driver process and zero Go build processes',
    'observability': 'Popen boundary records argv, PID/start identity and an owned-process journal; AST objects retained; overhead included without subtraction',
    'outside_timing': 'full AST validation/serialization, process classification, hashes, metadata, evidence writes except owned-process journal',
    'bounds': 'existing Go build timeout 120s; public parse timeout 3s; worker wall deadline 1500s; bounded owned-process cleanup',
    'isolation': 'explicit Python -I -S; explicit neutral source inserted; no site packages, editable importers, inherited Python settings or credentials',
    'offline': 'GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOENV=off GOFLAGS= CGO_ENABLED=0; isolated Go cache/module cache/HOME',
    'not_claimed': ['JS/Rust P1/P2 rerun', 'cross-OS acceptance', 'full suite', 'whole-release approval'],
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    # A deferred stop may arrive after serialization, during the actual write.
    # Persist that latched failure once; this is never a success/quiet retry.
    if isinstance(value, dict) and value.get('deferred_signals'):
        value['status'] = 'FAIL'
        Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def fact(path):
    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {'state': 'missing'}
    if stat.S_ISREG(before.st_mode):
        data, kind = path.read_bytes(), 'regular'
        mode = '100755' if before.st_mode & 0o111 else '100644'
    elif stat.S_ISLNK(before.st_mode):
        data, kind, mode = os.fsencode(os.readlink(path)), 'symlink', '120000'
    else:
        return {'state': 'nonregular', 'mode': oct(stat.S_IMODE(before.st_mode))}
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode)
    require(identity(before) == identity(after), 'changed during fingerprint: ' + str(path))
    return {'state': kind, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data, usedforsecurity=False).hexdigest(),
            'git_mode': mode, 'mode': oct(stat.S_IMODE(before.st_mode))}


def git(repo, *args, env):
    return subprocess.check_output([GIT, '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + os.devnull, '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
                                    '-C', str(repo), *args], env=env, stderr=subprocess.PIPE, timeout=120)


def gt(repo, *args, env):
    return git(repo, *args, env=env).decode().strip()


def entries(repo, tree, env):
    result = {}
    for row in git(repo, 'ls-tree', '-r', '--full-tree', '-z', tree, env=env).split(b'\0'):
        if not row:
            continue
        meta, raw = row.split(b'\t', 1)
        mode, kind, blob = meta.decode().split()
        name = os.fsdecode(raw)
        require(kind == 'blob' and mode in ('100644', '100755', '120000'), 'unsupported tracked object: ' + name)
        require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts, 'unsafe tracked path')
        result[name] = {'git_mode': mode, 'git_blob': blob}
    return result


def witness(repo, scope, env):
    index = Path(gt(repo, 'rev-parse', '--path-format=absolute', '--git-path', 'index', env=env))
    staged = {}
    for value in git(repo, 'ls-files', '--stage', '-z', env=env).split(b'\0'):
        if value:
            fields, name = value.split(b'\t', 1)
            mode, blob, stage = fields.decode().split()
            require(stage == '0', 'unmerged index entry')
            staged[os.fsdecode(name)] = {'git_mode': mode, 'git_blob': blob}
    extra = {}
    for label, flags in [('untracked', []), ('ignored', ['--ignored'])]:
        extra[label] = sorted(os.fsdecode(v) for v in git(repo, 'ls-files', '--others', *flags,
                                                          '--exclude-standard', '-z', env=env).split(b'\0') if v)
    return {'head': gt(repo, 'rev-parse', 'HEAD', env=env), 'tree': gt(repo, 'write-tree', env=env),
            'index_sha256': sha(index), 'index_entries': staged, 'extras': extra,
            'files': {name: fact(repo / name) for name in sorted(scope)}}


def validate(witnessed, expected, tree):
    require(witnessed['tree'] == tree, 'staged candidate tree differs')
    for name, row in witnessed['files'].items():
        if name not in expected:
            require(row['state'] == 'missing', 'deleted tracked path remains: ' + name)
            continue
        entry = expected[name]
        require(witnessed['index_entries'].get(name) == entry, 'logical Git mode/blob differs: ' + name)
        require(row.get('git_blob') == entry['git_blob'], 'tracked bytes differ: ' + name)
        kind = 'symlink' if entry['git_mode'] == '120000' else 'regular'
        require(row['state'] == kind, 'tracked file kind differs: ' + name)
        if sys.platform != 'win32':
            require(row.get('git_mode') == entry['git_mode'], 'physical mode differs: ' + name)


def pid_fact(pid):
    try:
        tail = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'parent': int(tail[1]), 'group': int(tail[2]), 'start_ticks': tail[19], 'state': tail[0]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def full_ast(tree, path):
    require(tree.file_path == str(path) and tree.version == '1.0' and tree.language == 'go', 'AST identity differs')
    require(len(tree.definitions) == len(tree.call_sites) == len(tree.imports) == 1, 'incomplete/extra AST facts')
    definition, call, imported = tree.definitions[0], tree.call_sites[0], tree.imports[0]
    require(definition.name == 'Run' and definition.kind == 'function' and definition.line == 3
            and definition.is_exported, 'function fact differs')
    require(call.target == 'os/exec.Command' and call.line == 3 and call.caller_scope == 'Run'
            and call.args == {'#0': "'echo'", '#1': "'hello'"}, 'canonical call/arguments differ')
    require(imported.source == 'os/exec' and imported.imported_symbols == ('ex',)
            and imported.aliases == (('ex', 'os/exec'),) and imported.line == 2, 'import alias fact differs')
    require(tree.mutation_points == () and tree.metadata.get('capabilities') == ['allow_comments', 'args']
            and tree.metadata.get('allow_comments') == {}, 'AST capabilities/mutations/comments differ')
    return tree.to_dict()


def worker(root):
    config = read(root / 'identity.json')
    source, workspace, go = Path(config['source']), root / 'fixture', config['go']
    result = {'status': 'INCOMPLETE', 'samples': [], 'scope': PROTOCOL['scope']}
    events, processes = [], []
    darwin_api = load_pinned(config['darwin_backend'], DARWIN_SHA256, 'p3_darwin_worker').DarwinAPI() if sys.platform == 'darwin' else None
    original = subprocess.Popen
    phase = 'imports'
    journal = (root / 'owned-processes.jsonl').open('a', buffering=1)

    def recorded(argv, *args, **kwargs):
        require(isinstance(argv, (list, tuple)) and not kwargs.get('shell'), 'unexpected subprocess form')
        row = {'phase': phase, 'argv': [os.fsdecode(a) for a in argv], 'cwd': str(kwargs.get('cwd')),
               'executable': os.fsdecode(kwargs.get('executable') or argv[0])}
        events.append(row)
        proc = original(argv, *args, **kwargs)
        processes.append(proc)
        row['pid'] = proc.pid
        identity = process_identity(proc, darwin_api)
        require(identity is not None, 'process identity unavailable')
        row['identity'] = identity
        if identity is not None:
            journal.write(json.dumps(identity) + '\n')
        return proc

    def classify(rows, binary):
        output = []
        for raw in rows:
            row = dict(raw)
            exe = str(Path(row['executable']).resolve())
            if exe == str(binary):
                row['kind'] = 'packaged_go_driver'
            elif exe == go and len(row['argv']) > 1 and row['argv'][1] in ('env', 'version', 'build'):
                row['kind'] = 'go_' + row['argv'][1]
            else:
                row['kind'] = 'unexpected'
            output.append(row)
        return output

    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.executable == PYTHON, 'worker interpreter isolation differs')
        require(not any('__editable__' in repr(x) for x in sys.meta_path), 'editable finder present')
        sys.path.insert(0, str(source))
        subprocess.Popen = recorded
        from aegis_core.ast.gobuild import inspect_go_driver, prepare_go_driver
        from aegis_core.ast.runner import ASTDriverRunner

        paths = [workspace / f'fixture{i}.go' for i in range(50)]
        phase = 'cold_prepare'
        start = time.perf_counter()
        binary = prepare_go_driver(workspace, timeout=120.0).resolve()
        cold_ms = (time.perf_counter() - start) * 1000
        result.update(cold_prepare_ms=cold_ms, binary=str(binary), binary_before=fact(binary),
                      fixture_sha256=FIXTURE_HASH,
                      source_sha256={name: sha(source / name) for name in (
                          'aegis_core/ast/gobuild.py', 'aegis_core/ast/runner.py', 'aegis_core/ast/batch.py',
                          'aegis_core/ast/schema.py', 'aegis_core/ast/drivers/templates/go_ast.go',
                          'aegis_core/ast/drivers/templates/go.mod')})
        save(root / 'worker-result.json', result)
        phase = 'metadata'
        status = inspect_go_driver(workspace)
        require(status.cache_hit and status.binary.resolve() == binary and status.compiler.resolve() == Path(go), 'compiler/cache identity differs')
        result['go_metadata'] = {'goversion': status.goversion, 'goos': status.goos, 'goarch': status.goarch,
                                 'compiler': str(status.compiler), 'cache_hit': status.cache_hit}
        result['go_version_output'] = subprocess.check_output([go, 'version'], text=True, timeout=3).strip()
        require(status.goos == goos_for_platform(sys.platform), 'compiler GOOS differs from this host')
        cold = classify([r for r in events if r['phase'] == 'cold_prepare'], binary)
        require(sum(r['kind'] == 'go_build' for r in cold) == 1 and all(r['kind'] in ('go_env', 'go_build') for r in cold), 'cold preparation must build exactly once')
        result['cold_processes'] = cold
        for sample in range(7):
            phase = f'warm_{sample + 1}'
            begin, asts = len(events), []
            start = time.perf_counter()
            with ASTDriverRunner() as runner:
                for path in paths:
                    tree = runner.parse_file(path, workspace_root=workspace)
                    assert tree.language == 'go' and any(c.target == 'os/exec.Command' for c in tree.call_sites)
                    asts.append(tree)
            elapsed = (time.perf_counter() - start) * 1000
            rows = classify(events[begin:], binary)
            sample_result = {'sample': sample + 1, 'elapsed_ms': elapsed, 'processes': rows,
                             'driver_count': sum(r['kind'] == 'packaged_go_driver' for r in rows),
                             'go_build_count': sum(r['kind'] == 'go_build' for r in rows)}
            result['samples'].append(sample_result)
            save(root / 'worker-result.json', result)
            require(sample_result['driver_count'] == 1 and sample_result['go_build_count'] == 0
                    and all(r['kind'] in ('packaged_go_driver', 'go_env') for r in rows), 'warm process invariant differs')
            require(all(p.poll() is not None for p in processes), 'process survived sample context close')
            ast_path = root / f'ast-sample-{sample + 1}.json'
            require(len(asts) == len(paths) == 50, 'full AST count differs')
            save(ast_path, [full_ast(tree, path) for tree, path in zip(asts, paths)])
            sample_result['full_ast_sha256'] = sha(ast_path)
            require(fact(binary) == result['binary_before'], 'driver binary changed')
            save(root / 'worker-result.json', result)
        origins = {}
        for name, module in tuple(sys.modules.items()):
            if name == 'aegis_core' or name.startswith('aegis_'):
                origin = Path(module.__file__).resolve()
                require(origin.is_relative_to(source), 'foreign Aegis module: ' + name)
                origins[name] = str(origin)
        result['origins'] = origins
        require(not any('__editable__' in repr(x) for x in sys.meta_path), 'editable importer appeared')
        result['samples_ms'] = [r['elapsed_ms'] for r in result['samples']]
        result['median_ms'] = statistics.median(result['samples_ms'])
        require(result['median_ms'] <= 300, 'unrounded seven-sample median exceeds unchanged 300ms cap')
        result['status'] = 'PASS'
    except BaseException as exc:  # noqa: BLE001 - preserve every failed/interrupted measurement as evidence, never PASS.
        result.update(status='INCOMPLETE' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'FAIL',
                      error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
    finally:
        subprocess.Popen = original
        journal.close()
        for event, proc in zip(events, processes):
            event['exit'] = proc.poll()
        save(root / 'process-events.json', events)
        try:
            require(all(p.poll() is not None for p in processes), 'worker still owns live child processes')
        except BaseException as exc:  # noqa: BLE001 - a cleanup exception invalidates the worker result.
            result.update(status='FAIL', cleanup_error=f'{type(exc).__name__}: {exc}')
        save(root / 'worker-result.json', result)
    return 0 if result['status'] == 'PASS' else 1


def load_pinned(path, expected, name):
    path = Path(path).resolve(strict=True)
    require(sha(path) == expected, 'helper hash mismatch: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def goos_for_platform(value):
    require(value in ('linux', 'darwin', 'win32'), 'unsupported platform: ' + value)
    return {'linux': 'linux', 'darwin': 'darwin', 'win32': 'windows'}[value]


def describe():
    return dict(PROTOCOL, measurement_performed=False, original_helper_sha256=ORIGINAL_SHA256,
                measured_block_sha256=MEASURED_BLOCK_SHA256, platform=sys.platform)


def verify_recipe():
    source = Path(__file__).read_text(encoding='utf-8')
    worker_node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'worker')
    loop = next(n for n in ast.walk(worker_node) if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == 'sample')
    require(isinstance(loop.iter, ast.Call) and isinstance(loop.iter.func, ast.Name)
            and loop.iter.func.id == 'range' and ast.literal_eval(loop.iter.args[0]) == 7, 'session recipe differs')
    lines = source.splitlines(True)
    block = ''.join(lines[loop.body[2].lineno - 1:loop.body[4].end_lineno])
    require(hashlib.sha256(block.encode()).hexdigest() == MEASURED_BLOCK_SHA256, 'measured block differs')


def create_fixture(root):
    fixture = root / 'fixture'; fixture.mkdir()
    (fixture / '.aegis').mkdir()
    save(fixture / '.aegis/config.json', {'v': 1, 'ast': {'packaged_drivers': ['go']}})
    for i in range(50):
        (fixture / f'fixture{i}.go').write_bytes(FIXTURE)
    manifest = verify_fixture(root)
    save(root / 'fixture-manifest.json', manifest)
    return manifest


def verify_fixture(root):
    fixture = root / 'fixture'
    names = [f'fixture{i}.go' for i in range(50)]
    require(sorted(p.name for p in fixture.glob('*.go')) == sorted(names), 'fixture file set differs')
    hashes = {}
    for name in names:
        require((fixture / name).read_bytes() == FIXTURE, 'fixture bytes differ: ' + name)
        hashes[name] = sha(fixture / name)
    require(len(FIXTURE) == 79 and len(FIXTURE.splitlines()) == 3
            and hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest() == FIXTURE_HASH,
            'historical fixture changed')
    return {'files': hashes, 'fixture_sha256': FIXTURE_HASH}


def neutral_environment(root, tool_directories, inherited, host):
    folders = {name: root / name for name in ('home', 'tmp', 'cache', 'config', 'data', 'state', 'gocache', 'gomodcache', 'gopath')}
    for path in folders.values():
        path.mkdir(exist_ok=False)
    env = {'HOME': str(folders['home']), 'USERPROFILE': str(folders['home']), 'TMPDIR': str(folders['tmp']),
           'TMP': str(folders['tmp']), 'TEMP': str(folders['tmp']), 'XDG_CACHE_HOME': str(folders['cache']),
           'XDG_CONFIG_HOME': str(folders['config']), 'XDG_DATA_HOME': str(folders['data']), 'XDG_STATE_HOME': str(folders['state']),
           'LOCALAPPDATA': str(folders['cache']), 'APPDATA': str(folders['config']),
           'PATH': os.pathsep.join(dict.fromkeys(str(p) for p in tool_directories)),
           'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
           'GOCACHE': str(folders['gocache']), 'GOMODCACHE': str(folders['gomodcache']), 'GOPATH': str(folders['gopath']),
           'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOWORK': 'off', 'GOENV': 'off',
           'GOFLAGS': '', 'CGO_ENABLED': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_OPTIONAL_LOCKS': '0'}
    if host == 'win32':
        for name in ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT', 'NUMBER_OF_PROCESSORS'):
            if name in inherited:
                env[name] = inherited[name]
    return env


def process_identity(proc, darwin_api=None):
    if sys.platform == 'linux':
        return pid_fact(proc.pid)
    if sys.platform == 'darwin':
        return darwin_api.process(proc.pid)
    require(sys.platform == 'win32', 'unsupported process identity platform')
    # CPython retains the original CreateProcess handle in Popen._handle.
    # Borrow it; never open a replacement PID or close this borrowed handle.
    class FileTime(ctypes.Structure):
        _fields_ = [('low', ctypes.c_uint32), ('high', ctypes.c_uint32)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(FileTime)] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int32
    values = [FileTime() for _ in range(4)]
    require(kernel.GetProcessTimes(int(proc._handle), *[ctypes.byref(v) for v in values]),
            'GetProcessTimes failed: ' + str(ctypes.get_last_error()))
    return {'pid': proc.pid, 'creation_filetime': (values[0].high << 32) | values[0].low,
            'identity_source': 'retained Popen process handle'}


def normal_process_state(owner, host):
    if host == 'win32':
        record = owner.accounting()
        return {'clean': record['ActiveProcesses'] == 0, 'active_before_close': record['ActiveProcesses'],
                'accounting_before_close': record}
    require(host == 'linux', 'Darwin uses its own finite final census')
    owner.scan()
    live_rows = [{k: value for k, value in row.items() if k != 'fd'} for row in owner.live()]
    return {'clean': not live_rows, 'live_before_close': live_rows}


def validate_worker_result(root, exit_code):
    require(exit_code == 0, 'worker exited nonzero')
    measured = read(root / 'worker-result.json')
    require(measured.get('status') == 'PASS', 'worker gate failed/incomplete')
    samples = measured.get('samples', [])
    require(len(samples) == 7, 'worker samples incomplete')
    values = []
    for index, sample in enumerate(samples, 1):
        value = sample.get('elapsed_ms')
        require(type(value) in (float, int) and math.isfinite(value) and value >= 0, 'invalid sample evidence')
        require(sample.get('sample') == index and sample.get('driver_count') == 1
                and sample.get('go_build_count') == 0, 'worker process evidence differs')
        ast_path = root / f'ast-sample-{index}.json'
        require(ast_path.is_file() and sha(ast_path) == sample.get('full_ast_sha256'), 'full AST evidence missing/changed')
        require(len(read(ast_path)) == 50, 'full AST evidence incomplete')
        values.append(value)
    require(measured.get('samples_ms') == values and measured.get('median_ms') == statistics.median(values)
            and measured['median_ms'] <= 300, 'unrounded worker median evidence differs')
    require((root / 'process-events.json').is_file() and (root / 'owned-processes.jsonl').is_file(),
            'worker process evidence missing')
    return measured


def expected_unresolved_leaf(cleanup, unique):
    require(cleanup.get('status') == 'FAIL' and cleanup.get('cleanup_complete') is False,
            'missed-parent cleanup must remain failed/incomplete')
    unknown = {int(key) for key, value in cleanup.get('classification', {}).items() if value == 'unresolved'}
    require(unknown == {unique}, 'expected exact unresolved leaf only')
    errors = cleanup.get('errors')
    require(isinstance(errors, list) and errors, 'missing unresolved leaf error')
    for error in errors:
        require(error.startswith('unresolved_ancestry: '), 'unexpected native/identity error: ' + error)
        require(set(ast.literal_eval(error.split(': ', 1)[1])) == {unique}, 'unexpected unresolved ancestry')


def validate_darwin_preflights(root):
    sources = {'darwin_ownership.py': DARWIN_SHA256, 'probe_darwin_ownership.py': DARWIN_PROBE_SHA256}
    reports = {}
    for mode in ('clean', 'token', 'reparent', 'missed-parent'):
        directory = root / mode
        report = read(directory / 'result.json')
        require(report.get('status') == 'PASS' and report.get('mode') == mode
                and report.get('platform') == 'darwin' and report.get('macos_validated') is True,
                'preflight unavailable/failed: ' + mode)
        require(report.get('sources') == sources and report.get('sources_after') == sources,
                'preflight helper hash mismatch: ' + mode)
        cleanup = report['cleanup']
        rounds = cleanup.get('rounds', [])
        require(sum(row['label'].startswith('initial-') for row in rounds) == 2
                and sum(row['label'].startswith('final-') for row in rounds) == 2, 'preflight census count differs')
        final = [row for row in rounds if row['label'].startswith('final-')]
        require(final[0].get('rows') and final[0]['rows'] == final[1].get('rows'), 'preflight final maps differ')
        events = [json.loads(line) for line in (directory / 'native-events.jsonl').read_text().splitlines()]
        require(any(event.get('api') == 'proc_listpids' for event in events), 'preflight native census evidence missing')
        for event in events:
            if event.get('api') == 'proc_listpids':
                count, requested = event['returned_bytes'], event['requested_bytes']
                require(count > 0 and count % 4 == 0 and (requested == 0 or count < requested),
                        'preflight native list error')
            if event.get('api') == 'proc_pidinfo':
                require(event['returned_bytes'] == event['requested_bytes'], 'preflight native query error')
        signals = [event for event in events if event.get('api') == 'proc_signal_with_audittoken']
        if mode == 'clean':
            require(cleanup.get('status') == 'PASS' and cleanup.get('cleanup_complete')
                    and cleanup.get('errors') == [] and not signals, 'clean preflight cleanup differs')
        elif mode == 'token':
            require(cleanup.get('cleanup_complete') and cleanup.get('errors') == ['worker_exit: -15']
                    and report.get('stale_token_target_survived') is True and report.get('current_token_exit') == -15,
                    'token preflight outcome differs')
            require(len(signals) == 2 and [v['result'] for v in signals] == [3, 0]
                    and all(v['signal'] == 15 for v in signals)
                    and signals[0]['token'][5] == signals[1]['token'][5]
                    and signals[0]['token'][7] == (signals[1]['token'][7] + 1) & 0xFFFFFFFF,
                    'token preflight native evidence differs')
        elif mode == 'reparent':
            require(cleanup.get('cleanup_complete') and cleanup.get('errors') == ['fallback_cleanup_required']
                    and signals and all(v['result'] == 0 for v in signals), 'reparent preflight differs')
        else:
            pid = read(directory / 'leaf.json')['pid']
            matches = [row for row in cleanup['graph'].values() if row['pid'] == pid]
            require(len(matches) == 1, 'expected exact unresolved leaf identity')
            expected_unresolved_leaf(cleanup, matches[0]['unique'])
            require(not signals, 'missed-parent process was signalled')
            report['leaf_identity'] = matches[0]
        reports[mode] = report
    return reports


def darwin_leaf_barrier(root, api):
    """Observe one fixture's full identity disappearing; never signal or retry a quiet pair."""
    result = {'status': 'FAIL', 'scope': 'fixture exit only; original cleanup stays failed',
              'inventory_count': 0, 'maps': []}
    try:
        reports = validate_darwin_preflights(root)
        leaf = reports['missed-parent']['leaf_identity']
        result['leaf_unique'] = leaf['unique']
        prior = {leaf['pid']: leaf['unique']}
        deadline = time.monotonic() + 10
        while True:
            require(time.monotonic() < deadline, 'leaf barrier expiry exceeded 10 seconds')
            current = api.inventory(deadline=deadline)
            result['inventory_count'] += 1
            result['maps'].append(current)
            for pid, row in current.items():
                require(pid not in prior or prior[pid] == row['unique'], 'leaf barrier PID reuse')
                prior[pid] = row['unique']
            if all(row['unique'] != leaf['unique'] for row in current.values()):
                final = api.inventory(deadline=deadline)
                result['inventory_count'] += 1
                result['maps'].append(final)
                require(current == final and all(row['unique'] != leaf['unique'] for row in final.values()),
                        'leaf barrier absence maps differ; no retry')
                break
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
        result['status'] = 'PASS'
    except BaseException as exc:
        result.update(error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
        save(root / 'leaf-barrier.json', result)
        raise
    save(root / 'leaf-barrier.json', result)
    return result


def darwin_preflights(root, backend, probe, env):
    """Fresh same-job commands; caller cannot substitute a copied receipt directory."""
    require(sha(probe) == DARWIN_PROBE_SHA256, 'Darwin probe hash mismatch')
    require(sha(probe.with_name('darwin_ownership.py')) == DARWIN_SHA256, 'Darwin probe sibling backend hash mismatch')
    require(sha(backend.__file__) == DARWIN_SHA256, 'Darwin loaded backend hash mismatch')
    root.mkdir(exist_ok=False)
    sources = {str(path.resolve()): fact(path) for path in
               (Path(__file__), Path(backend.__file__), probe, probe.with_name('darwin_ownership.py'))}
    commands = []
    orchestration = {'status': 'INCOMPLETE', 'commands': commands, 'helper_sha256': sha(__file__),
                     'backend_sha256': DARWIN_SHA256, 'probe_sha256': sha(probe),
                     'sources_before': sources,
                     'provenance': 'fresh same-job launches and current census; not cryptographic host attestation'}
    with (root / 'orchestrator-native.jsonl').open('w', encoding='utf-8') as stream:
        def event(value):
            stream.write(json.dumps(value, sort_keys=True) + '\n'); stream.flush()
        try:
            for mode in ('clean', 'token', 'reparent', 'missed-parent'):
                owner = backend.DarwinOwnedTree(observer=event, interval=.2)
                argv = [PYTHON, '-I', '-S', '-B', str(probe), '--mode', mode, '--evidence', str(root / mode)]
                command = {'argv': argv, 'cwd': str(root), 'timeout_seconds': 30}
                commands.append(command)
                with (root / f'{mode}.stdout').open('wb') as stdout, (root / f'{mode}.stderr').open('wb') as stderr:
                    try:
                        proc = owner.launch(argv, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                        command['exit'] = proc.wait(timeout=30)
                    finally:
                        with backend.defer_stops(command):
                            command['outer_cleanup'] = owner.close()
                require(command['exit'] == 0, 'Darwin preflight command failed: ' + mode)
                require(not command.get('deferred_signals'), 'stop during preflight cleanup')
                if mode != 'missed-parent':
                    require(command['outer_cleanup']['status'] == 'PASS', 'Darwin preflight outer cleanup failed')
            reports = validate_darwin_preflights(root)
            expected_unresolved_leaf(commands[-1]['outer_cleanup'], reports['missed-parent']['leaf_identity']['unique'])
            require({name: fact(name) for name in sources} == sources, 'preflight source witnesses changed before barrier')
            barrier = darwin_leaf_barrier(root, backend.DarwinAPI(observer=event))
            require(barrier['status'] == 'PASS', 'Darwin leaf barrier unavailable')
            orchestration['status'] = 'PASS'
        except BaseException as exc:
            orchestration.update(status='FAIL', error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
            raise
        finally:
            with backend.defer_stops(orchestration):
                try:
                    orchestration['sources_after'] = {name: fact(name) for name in sources}
                    require(orchestration['sources_after'] == sources, 'preflight source witnesses changed')
                except BaseException as exc:
                    orchestration.update(status='FAIL', witness_error=f'{type(exc).__name__}: {exc}')
                    raise
                finally:
                    save(root / 'orchestration.json', orchestration)
    require(orchestration['status'] == 'PASS' and not orchestration.get('deferred_signals'),
            'preflight orchestration failed or stopped')


def prepare_source(args, root, env):
    lane = args.lane.resolve(strict=True)
    require(args.lane.is_absolute() and re.fullmatch('[0-9a-f]{40}', args.audit)
            and re.fullmatch('[0-9a-f]{40}', args.tree), 'absolute lane/full audit/tree required')
    require(gt(lane, 'rev-parse', args.audit + '^{tree}', env=env) == args.tree, 'audit/tree mismatch')
    expected = entries(lane, args.tree, env)
    scope = set(expected) | set(entries(lane, 'HEAD', env))
    delivery = witness(lane, scope, env)
    validate(delivery, expected, args.tree)
    source = root / 'source'
    argv = [GIT, '-c', 'core.hooksPath=' + os.devnull, '-c', 'core.fsmonitor=false',
            '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', '-C', str(lane),
            'worktree', 'add', '--detach', str(source), args.audit]
    with (root / 'checkout.log').open('wb') as log:
        subprocess.run(argv, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
    neutral = witness(source, scope, env)
    validate(neutral, expected, args.tree)
    require(neutral['head'] == args.audit and not any(neutral['extras'].values()), 'fresh neutral source is not clean')
    logical = lambda value: {name: {k: row.get(k) for k in ('state', 'git_blob')} for name, row in value['files'].items()}
    require(logical(neutral) == logical(delivery), 'neutral source bytes/kinds differ')
    before = {'delivery': delivery, 'source': neutral}
    save(root / 'source-before.json', before)
    save(root / 'checkout-command.json', {'argv': argv, 'exit': 0})
    return lane, source, scope, before


def run_owned_worker(root, source, env, backend, owner_module):
    argv = [PYTHON, '-I', '-S', '-B', str(root / 'helper.py'), '--worker', str(root)]
    record = {'argv': argv, 'cwd': str(root), 'timeout_seconds': 1500, 'normal': {'clean': False}}
    owner = None
    try:
        with (root / 'worker.stdout.log').open('wb') as stdout, (root / 'worker.stderr.log').open('wb') as stderr:
            if sys.platform == 'darwin':
                with (root / 'ownership-events.jsonl').open('w', encoding='utf-8') as stream:
                    def event(value):
                        stream.write(json.dumps(value, sort_keys=True) + '\n'); stream.flush()
                    owner = backend.DarwinOwnedTree(observer=event, interval=.2)
                    try:
                        proc = owner.launch(argv, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                        record['exit'] = owner.wait(1500)
                    finally:
                        with backend.defer_stops(record):
                            record['cleanup'] = owner.close()
                    record['normal'] = {'clean': record['cleanup']['status'] == 'PASS'}
            else:
                owner = owner_module.OwnedTree(source, root)
                try:
                    proc = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                            stdout=stdout, stderr=stderr, **owner.flags)
                    owner.attach(proc)
                    deadline = time.monotonic() + 1500
                    while proc.poll() is None:
                        if sys.platform == 'linux':
                            owner.scan()
                        require(time.monotonic() < deadline, 'worker exceeded 1500s bound')
                        time.sleep(.2)
                    record['exit'] = proc.wait(timeout=0)
                    record['normal'] = normal_process_state(owner, sys.platform)
                finally:
                    with backend.defer_stops(record):
                        try:
                            owner.close()
                        finally:
                            record['cleanup'] = owner.record
        require(record.get('exit') == 0 and record['normal']['clean'] and record['cleanup']['status'] == 'PASS'
                and not record.get('deferred_signals'), 'worker/ownership failed or required fallback cleanup')
        record['status'] = 'PASS'
    except BaseException as exc:
        record.update(status='FAIL', error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
        raise
    finally:
        with backend.defer_stops(record):
            save(root / 'ownership-result.json', record)
    require(record['status'] == 'PASS' and not record.get('deferred_signals'), 'stop during ownership evidence finalization')
    return record['exit']


def run(args):
    global GIT
    require(args.git.is_absolute() and args.git.is_file(), 'explicit existing Git executable required')
    GIT = str(args.git.resolve())
    parent = args.output_parent.resolve(strict=True)
    for ancestor in (parent, *parent.parents):
        require(not (ancestor / '.aegis').exists() and not (ancestor / '.git').exists(), 'nonneutral fixture ancestor')
    root = Path(tempfile.mkdtemp(prefix='aegis-v45-portable-p3-', dir=parent))
    print(str(root), flush=True)
    result = {'status': 'INCOMPLETE', 'measurement_performed': False, 'root': str(root),
              'audit': args.audit, 'tree': args.tree, 'platform': sys.platform}
    before = None
    frozen = {}
    backend = None
    handlers = contextlib.ExitStack()
    try:
        verify_recipe()
        go = None
        tools = [Path(PYTHON).parent, Path(GIT).parent]
        if args.action == 'measure':
            require(args.quiet_window_confirmed, 'explicit quiet-window confirmation required')
            require(args.go.is_absolute(), 'explicit absolute Go executable required')
            go = args.go.resolve(strict=True)
            expected_name = 'go.exe' if sys.platform == 'win32' else 'go'
            require(go.is_file() and os.access(go, os.X_OK) and go.name.lower() == expected_name,
                    'existing executable named ' + expected_name + ' required')
            require(not go.is_relative_to(args.lane.resolve()), 'Go must be outside candidate workspace')
            tools.insert(0, go.parent)
            goos_for_platform(sys.platform)
        env = neutral_environment(root, tools, os.environ, sys.platform)
        save(root / 'environment.json', env)
        lane, source, scope, before = prepare_source(args, root, env)
        if args.action == 'verify-source':
            result.update(status='PASS', scope='source identity/clean checkout only; no measurement')
        else:
            backend = load_pinned(args.darwin_backend, DARWIN_SHA256, 'p3_darwin')
            handlers.enter_context(backend.stop_handlers())
            owner_module = load_pinned(args.owner_helper, OWNER_SHA256, 'p3_owner')
            sys.path.insert(0, str(source))
            from aegis_core.storage import file_lock
            require(Path(sys.modules['aegis_core.storage'].__file__).resolve().is_relative_to(source), 'foreign storage import')
            require(args.lock.is_absolute() and not args.lock.resolve().is_relative_to(lane), 'neutral absolute lock required')
            with file_lock(args.lock, timeout=.1):
                if sys.platform == 'darwin':
                    require(args.darwin_probe is not None, 'Darwin preflight probe required')
                    darwin_preflights(root / 'darwin-preflight', backend, args.darwin_probe.resolve(strict=True), env)
                fixture = create_fixture(root)
                save(root / 'protocol.json', PROTOCOL)
                for name, src in [('helper.py', Path(__file__)), ('owner.py', args.owner_helper),
                                  ('darwin_ownership.py', args.darwin_backend)]:
                    shutil.copyfile(src, root / name)
                save(root / 'identity.json', {'lane': str(lane), 'source': str(source), 'audit': args.audit,
                     'tree': args.tree, 'go': str(go), 'darwin_backend': str(root / 'darwin_ownership.py'),
                     'platform': platform.platform(), 'go_before': fact(go), 'python_before': fact(PYTHON)})
                paths = [Path(__file__).resolve(), root / 'helper.py', root / 'owner.py', root / 'darwin_ownership.py',
                         args.owner_helper.resolve(), args.darwin_backend.resolve(), root / 'protocol.json',
                         root / 'identity.json', root / 'fixture-manifest.json', root / 'fixture/.aegis/config.json',
                         *[root / 'fixture' / name for name in fixture['files']], go, Path(PYTHON), Path(GIT)]
                frozen = {str(path): fact(path) for path in paths}
                save(root / 'frozen-before.json', frozen)
                try:
                    result['measurement_performed'] = True
                    code = run_owned_worker(root, source, env, backend, owner_module)
                    measured = validate_worker_result(root, code)
                    result.update(status='PASS', median_ms=measured['median_ms'], cold_prepare_ms=measured['cold_prepare_ms'])
                finally:
                    with backend.defer_stops(result):
                        save(root / 'worker-terminal.json', {'status': result['status'], 'measurement_performed': True})
    except BaseException as exc:  # noqa: BLE001 - retain the supervisor failure before final source witnesses.
        result.update(status='FAIL', error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
    finally:
        guard = backend.defer_stops(result) if backend is not None else contextlib.nullcontext()
        with guard:
            try:
                if before is not None:
                    after = {'delivery': witness(lane, scope, env), 'source': witness(source, scope, env)}
                    save(root / 'source-after.json', after)
                    require(before == after, 'source/HEAD/index/hash/mode witnesses changed')
                    result['source_stable'] = True
                if frozen:
                    after = {name: fact(name) for name in frozen}
                    save(root / 'frozen-after.json', after)
                    require(after == frozen, 'frozen input witnesses changed')
                    result['frozen_stable'] = True
            except BaseException as exc:  # noqa: BLE001 - changed or unreadable witnesses always invalidate acceptance.
                result.update(status='FAIL', witness_error=f'{type(exc).__name__}: {exc}')
            save(root / 'result.json', result)
        handlers.close()
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return 0 if result['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('describe', help='print exact protocol without processes or measurement')
    fixture = actions.add_parser('fixture', help='write the historical fixture only')
    fixture.add_argument('--evidence', required=True, type=Path)
    for name in ('verify-source', 'measure'):
        command = actions.add_parser(name)
        command.add_argument('--lane', required=True, type=Path)
        command.add_argument('--audit', required=True)
        command.add_argument('--tree', required=True)
        command.add_argument('--git', required=True, type=Path)
        command.add_argument('--output-parent', type=Path, default=Path(tempfile.gettempdir()))
        if name == 'measure':
            command.add_argument('--go', required=True, type=Path)
            command.add_argument('--owner-helper', required=True, type=Path)
            command.add_argument('--darwin-backend', required=True, type=Path)
            command.add_argument('--darwin-probe', type=Path)
            command.add_argument('--lock', required=True, type=Path)
            command.add_argument('--quiet-window-confirmed', required=True, action='store_true')
    args = parser.parse_args()
    if args.action == 'describe':
        verify_recipe(); print(json.dumps(describe(), indent=2, sort_keys=True)); return 0
    if args.action == 'fixture':
        args.evidence.mkdir(parents=True, exist_ok=False)
        print(json.dumps(create_fixture(args.evidence), indent=2, sort_keys=True)); return 0
    require(sys.flags.isolated and sys.flags.no_site, 'invoke helper with Python -I -S')
    return run(args)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        def interrupted(signum, _frame):
            raise KeyboardInterrupt(f'termination signal {signum}')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        raise SystemExit(worker(Path(sys.argv[2]).resolve(strict=True)))
    raise SystemExit(main())

