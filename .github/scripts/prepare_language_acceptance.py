"""Prepare a tracked LF checkout and a raw Git-blob receipt; never acquire tools."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import traceback

GO_HELPER = '.github/fixtures/go-functional/acceptance.py'
GO_SHA = 'e3ec16675589f2af65fe4c00f2bfaa3f7da372b0f8abddec567bc08eb8830cbf'
OWNER = '.github/fixtures/ac24/acceptance.py'
OWNER_SHA = '692cb44ebcf239a34c01b16648e4b923a464de57e94e85362f49f7cc443af474'
COMMANDS = []


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def git(executable, cwd, env, *args, input_bytes=None, expected=0):
    command = [str(executable), '-c', 'core.hooksPath=' + os.devnull,
               '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
               '-c', 'core.fsmonitor=false', *map(str, args)]
    row = {'argv': command, 'cwd': str(cwd), 'timeout_s': 30, 'expected': expected}
    COMMANDS.append(row)
    done = subprocess.run(command, cwd=cwd, env=env, input=input_bytes,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    row.update(returncode=done.returncode, stdout_bytes=len(done.stdout),
               stderr=done.stderr.decode('utf-8', 'replace'))
    require(done.returncode == expected, 'Git preparation command failed: ' + json.dumps(row))
    return done.stdout


def existing_tool(name, supplied=None):
    found = str(supplied) if supplied is not None else shutil.which(name)
    require(found is not None, 'prerequisite: existing ' + name + ' is missing; no download is permitted')
    path = Path(found).resolve()
    require(path.is_file(), 'prerequisite: existing tool is not a file: ' + str(path))
    return path


def existing_bash(git_path, supplied):
    if supplied is not None or os.name != 'nt':
        return existing_tool('bash', supplied)
    # Derive Git Bash from the discovered Git installation, never WSL bash.
    for parent in git_path.parents:
        for relative in ('usr/bin/bash.exe', 'bin/bash.exe'):
            candidate = parent / relative
            if candidate.is_file():
                return candidate.resolve()
    raise RuntimeError('prerequisite: existing Git Bash was not found beside Git; supply --bash explicitly')


def source_receipt(source, audit, tree, git_path, env):
    expected = {}
    for row in git(git_path, source, env, 'ls-tree', '-r', '-z', audit).split(b'\0'):
        if row:
            metadata, name = row.split(b'\t', 1)
            mode, kind, oid = metadata.decode('ascii').split()
            require(kind == 'blob', 'unsupported tracked object: ' + name.decode('utf-8'))
            expected[name.decode('utf-8')] = {'git_mode': mode, 'git_blob': oid}
    staged = {}
    raw_index = git(git_path, source, env, 'ls-files', '--stage', '-z')
    for row in raw_index.split(b'\0'):
        if row:
            metadata, name = row.split(b'\t', 1)
            mode, oid, stage = metadata.decode('ascii').split()
            require(stage == '0', 'unmerged source index')
            staged[name.decode('utf-8')] = {'git_mode': mode, 'git_blob': oid}
    require(staged == expected, 'source index differs from expected tracked tree')
    head = git(git_path, source, env, 'rev-parse', 'HEAD').decode().strip()
    actual_tree = git(git_path, source, env, 'rev-parse', 'HEAD^{tree}').decode().strip()
    require(head == audit and actual_tree == tree, 'source audit/tree mismatch')
    git(git_path, source, env, 'symbolic-ref', '-q', 'HEAD', expected=1)
    status = git(git_path, source, env, 'status', '--porcelain=v1',
                 '--untracked-files=all', '--ignored=matching').decode('utf-8')
    require(status == '', 'neutral source contains modified, untracked or ignored files: ' + status)
    oids = sorted({row['git_blob'] for row in expected.values()})
    raw = git(git_path, source, env, 'cat-file', '--batch',
              input_bytes=''.join(oid + '\n' for oid in oids).encode('ascii'))
    blobs, offset = {}, 0
    for oid in oids:
        end = raw.index(b'\n', offset)
        returned, kind, size_text = raw[offset:end].decode('ascii').split()
        size = int(size_text)
        require(returned == oid and kind == 'blob', 'unexpected cat-file object')
        start, stop = end + 1, end + 1 + size
        require(stop < len(raw) and raw[stop:stop + 1] == b'\n', 'truncated cat-file blob')
        blobs[oid] = raw[start:stop]
        offset = stop + 1
    require(offset == len(raw), 'unexpected trailing cat-file data')
    for name, row in expected.items():
        path = source / name
        info = path.lstat()
        mode = row['git_mode']
        matches_kind = (stat.S_ISREG(info.st_mode) if mode in ('100644', '100755') else
                        stat.S_ISLNK(info.st_mode) if mode == '120000' else False)
        require(matches_kind, 'tracked physical kind differs from Git mode ' + mode + ': ' + name)
        actual = os.fsencode(os.readlink(path)) if stat.S_ISLNK(info.st_mode) else path.read_bytes()
        blob = blobs[row['git_blob']]
        require(actual == blob, 'raw source bytes differ from Git blob: ' + name)
        row.update(sha256=hashlib.sha256(blob).hexdigest(), bytes=len(blob))
    index = Path(git(git_path, source, env, 'rev-parse', '--git-path', 'index').decode().strip())
    if not index.is_absolute():
        index = source / index
    return {'schema': 'aegis-language-source/v1', 'status': 'PASS',
            'validation': 'tracked bytes equal Git blobs', 'source': str(source.resolve()),
            'audit': audit, 'tree': tree, 'files': expected,
            'index_sha256': sha(index), 'index_entries_sha256': hashlib.sha256(raw_index).hexdigest(),
            'git_modes_are_distinct_from_windows_physical_modes': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('workspace', 'git', 'go', 'bash', 'ownership-helper', 'github-output'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--audit', required=True)
    parser.add_argument('--tree', required=True)
    parser.add_argument('--require-platform', choices=('linux', 'win32'), required=True)
    parser.add_argument('--validate-existing-only', action='store_true',
                        help='Write the same raw-blob receipt for an existing clean detached source; do not discover Go or Bash.')
    args = parser.parse_args()
    root = args.evidence.absolute()
    require(not root.exists(), 'preserve existing preparation evidence')
    root.mkdir(parents=True)
    result = {'status': 'FAIL', 'platform': sys.platform, 'audit': args.audit, 'tree': args.tree,
              'validation_only': args.validate_existing_only}
    try:
        require(sys.platform == args.require_platform, 'requested platform differs from host')
        require(len(args.audit) == 40 and len(args.tree) == 40 and
                all(c in '0123456789abcdef' for c in args.audit + args.tree), 'explicit full Git OIDs required')
        git_path = existing_tool('git', args.git)
        source = args.source.absolute()
        home = root / 'home'
        home.mkdir()
        env = {k: os.environ[k] for k in ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'COMSPEC',
                                        'PATHEXT', 'NUMBER_OF_PROCESSORS') if k in os.environ}
        env.update(HOME=str(home), USERPROFILE=str(home), PATH=str(git_path.parent),
                   GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0',
                   GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1')
        if not args.validate_existing_only:
            require(args.workspace is not None and args.workspace.is_dir(), 'existing workspace required')
            workspace = args.workspace.resolve()
            require(git(git_path, workspace, env, 'rev-parse', 'HEAD').decode().strip() == args.audit,
                    'workspace HEAD differs from expected audit')
            require(git(git_path, workspace, env, 'rev-parse', 'HEAD^{tree}').decode().strip() == args.tree,
                    'workspace tree differs from expected tree')
            require(not source.exists(), 'neutral source destination must be fresh')
            git(git_path, root, env, 'clone', '--local', '--shared', '--no-checkout',
                '--no-hardlinks', '--', workspace, source)
            for key, value in (('core.autocrlf', 'false'), ('core.eol', 'lf'),
                               ('core.hooksPath', os.devnull)):
                git(git_path, source, env, 'config', '--local', key, value)
            git(git_path, source, env, 'checkout', '--detach', args.audit, '--')
        receipt = source_receipt(source, args.audit, args.tree, git_path, env)
        receipt['preparation'] = {'fresh_detached_checkout': not args.validate_existing_only,
            'configured_checkout_controls': None if args.validate_existing_only else
                {'core.autocrlf': False, 'core.eol': 'lf'}}
        save(root / 'source-receipt.json', receipt)
        outputs = {'source': str(source.resolve()), 'audit': args.audit, 'tree': args.tree,
                   'receipt': str(root / 'source-receipt.json'),
                   'receipt_sha256': sha(root / 'source-receipt.json')}
        if not args.validate_existing_only:
            go = existing_tool('go', args.go)
            bash = existing_bash(git_path, args.bash)
            owner = (args.ownership_helper if args.ownership_helper else source / OWNER).resolve()
            require(owner.is_file(), 'prerequisite: pinned ownership helper missing; approve shared tracked delivery or supply --ownership-helper')
            require(sha(owner) == OWNER_SHA, 'ownership helper bytes differ from reviewed helper')
            require(sha(source / GO_HELPER) == GO_SHA, 'Go acceptance helper bytes differ from reviewed helper')
            outputs.update(go=str(go), git=str(git_path), bash=str(bash), owner=str(owner))
            result['tools'] = {name: {'path': str(path), 'sha256': sha(path)}
                               for name, path in (('go', go), ('git', git_path), ('bash', bash),
                                                  ('python', Path(sys.executable).resolve()), ('owner', owner))}
        if args.github_output is not None:
            with args.github_output.open('a', encoding='utf-8') as stream:
                for key, value in outputs.items():
                    require('\n' not in value and '\r' not in value, 'unsafe multiline output')
                    stream.write(key + '=' + value + '\n')
        result.update(status='PASS', outputs=outputs, tracked_count=len(receipt['files']))
    except BaseException as exc:
        result.update(error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
    finally:
        save(root / 'commands.json', COMMANDS)
        save(root / 'preparation.json', result)
        save(root / 'manifest.json', {'status': result['status'], 'producer_sha256': sha(Path(__file__)),
            'files': {p.name: {'sha256': sha(p), 'bytes': p.stat().st_size}
                      for p in sorted(root.iterdir()) if p.is_file() and p.name != 'manifest.json'},
            'excludes': ['neutral source checkout', 'isolated home']})
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
