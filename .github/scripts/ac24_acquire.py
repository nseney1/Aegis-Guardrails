#!/usr/bin/env python3
"""PROPOSAL: acquire the complete historical M0 fixture only after owner approval."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import traceback
from urllib.parse import urlsplit


KIT_SHA = '292513a98bbd10a786af5b3b75c2ec6262b46f02f886b701716380d03d25aa3f'
HELPER_SHA = '692cb44ebcf239a34c01b16648e4b923a464de57e94e85362f49f7cc443af474'
LOCK_SHA = '82ecce1b7005a50e5ac6142fa296066ed7193ce5679b4dfd6ae7ebaf29e2ef9c'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def require_existing_npm(version):
    require(version.split('.')[0] in ('10', '11'), 'proposal requires existing npm 10 or 11; no upgrade is authorized')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def verify_kit(kit):
    require(digest(kit / 'manifest.json') == KIT_SHA, 'reviewed kit manifest differs')
    manifest = json.loads((kit / 'manifest.json').read_text(encoding='utf-8'))
    for name, expected in manifest['files'].items():
        target = (kit / name).resolve(strict=True)
        require(kit in target.parents, 'kit entry escapes root: ' + name)
        require(digest(target) == expected['sha256'], 'kit file differs: ' + name)
        require(target.stat().st_size == expected['bytes'], 'kit size differs: ' + name)
    require(digest(kit / 'acceptance.py') == HELPER_SHA, 'acceptance helper differs')
    require(digest(kit / 'm0-package-lock.json') == LOCK_SHA, 'M0 lock differs')
    return manifest


def run_owned(helper, source, root, label, argv, cwd, env, timeout):
    evidence = root / label
    evidence.mkdir()
    record = {'argv': [str(value) for value in argv], 'cwd': str(cwd), 'timeout_s': timeout}
    owner = None
    try:
        with (evidence / 'stdout.log').open('wb') as stdout, (evidence / 'stderr.log').open('wb') as stderr:
            owner = helper.OwnedTree(source, evidence)
            try:
                process = subprocess.Popen(record['argv'], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, **owner.flags)
                owner.attach(process)
                record['exit'] = process.wait(timeout=timeout)
            finally:
                owner.close()
        require(record['exit'] == 0, label + ' failed; preserve raw stdout/stderr')
        return (evidence / 'stdout.log').read_text(encoding='utf-8').strip()
    except BaseException as exc:
        record.update(error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
        raise
    finally:
        save(evidence / 'command.json', record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--kit', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--execute-locked-acquisition', action='store_true')
    args = parser.parse_args()
    require(args.execute_locked_acquisition, 'locked network acquisition requires explicit authorization')
    require(sys.platform == 'win32', 'this acquisition proposal is for the normal Windows job only')
    source, kit = args.source.resolve(strict=True), args.kit.resolve(strict=True)
    root = args.root.resolve()
    require(source != root and source not in root.parents, 'acquisition root must be outside source')
    root.mkdir(parents=False, exist_ok=False)
    result = {'status': 'FAIL', 'scope': 'full unchanged M0 Vitest/Jest/jest-junit fixture acquisition',
              'windows_acceptance': 'NOT EXECUTED by this acquisition step', 'source': str(source)}
    helper = None
    before_source = None
    before_tools = None
    old_term = None
    try:
        before_kit = verify_kit(kit)
        spec = importlib.util.spec_from_file_location('ac24_acceptance', kit / 'acceptance.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        old_term = signal.signal(signal.SIGTERM, helper.request_stop)
        found = shutil.which('node')
        require(found is not None, 'existing compatible Node is unavailable; no tool install is authorized')
        node = Path(found).resolve(strict=True)
        npm_wrapper = shutil.which('npm')
        candidates = [node.parent / 'node_modules/npm/bin/npm-cli.js']
        if npm_wrapper:
            candidates.append(Path(npm_wrapper).resolve().parent / 'node_modules/npm/bin/npm-cli.js')
        npm_cli = next((path.resolve() for path in candidates if path.is_file()), None)
        require(npm_cli is not None, 'existing npm-cli.js unavailable; no npm install is authorized')
        npm_package = npm_cli.parent.parent / 'package.json'
        npm_version = json.loads(npm_package.read_text(encoding='utf-8'))['version']
        # Hosted windows-latest Node 22 bundles npm 10 (run 41498053375). npm 10 and 11 both install this
        # lockfileVersion 3 lock, and the frozen-lock and installed-version checks below bind the result.
        require_existing_npm(npm_version)
        env = helper.neutral_environment(root, node, source)
        git_path = shutil.which('git', path=env['PATH'])
        require(git_path is not None, 'Git unavailable for source witnesses')
        before_source = helper.source_facts(source, git_path, env)
        require(before_source['status'] == '', 'source checkout is dirty before acquisition')
        save(root / 'source-before.json', before_source)
        before_tools = {str(path): helper.fact(path) for path in (node, npm_cli, npm_package)}
        save(root / 'tools-before.json', before_tools)
        # Distinct empty configs avoid npm's double-loading rejection and never read credentials.
        user_config, global_config = root / 'user.npmrc', root / 'global.npmrc'
        user_config.write_text('', encoding='utf-8')
        global_config.write_text('', encoding='utf-8')
        npm_configs = ['--userconfig', user_config, '--globalconfig', global_config]
        details = json.loads(run_owned(helper, source, root, 'node-identity',
                            [node, '-p', 'JSON.stringify({version:process.version,arch:process.arch,platform:process.platform})'],
                            root, env, 10))
        match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', details['version'])
        require(match is not None, 'stable existing Node version required')
        major, minor, _patch = map(int, match.groups())
        require((major == 22 and minor >= 12) or major == 24 or major >= 26,
                'existing Node does not meet Vitest 5.0.5 engine range')
        require(details['platform'] == 'win32' and details['arch'] in ('x64', 'arm64'),
                'locked Windows x64/arm64 native payload required')
        actual_npm = run_owned(helper, source, root, 'npm-identity',
                               [node, npm_cli, '--version', *npm_configs], root, env, 10)
        require(actual_npm == npm_version, 'npm metadata and entry point versions differ')
        result['tools'] = dict(details, node=str(node), npm_cli=str(npm_cli), npm_version=npm_version)
        project = root / 'project'
        project.mkdir()
        shutil.copyfile(kit / 'm0-package.json', project / 'package.json')
        shutil.copyfile(kit / 'm0-package-lock.json', project / 'package-lock.json')
        before_inputs = {name: digest(project / name) for name in ('package.json', 'package-lock.json')}
        lock = json.loads((project / 'package-lock.json').read_text(encoding='utf-8'))
        require(lock['lockfileVersion'] == 3, 'historical lock format differs')
        for name, package in lock['packages'].items():
            if not name:
                continue
            url = urlsplit(package.get('resolved', ''))
            require(url.scheme == 'https' and url.netloc == 'registry.npmjs.org' and not url.fragment,
                    'non-registry package resolution: ' + name)
            require(package.get('integrity', '').startswith('sha512-'), 'missing locked integrity: ' + name)
        argv = [node, npm_cli, 'ci', '--include=dev', '--include=optional', '--ignore-scripts',
                '--no-audit', '--no-fund', '--fetch-retries=0', '--fetch-timeout=60000',
                '--registry=https://registry.npmjs.org/', '--cache', root / 'npm-cache',
                *npm_configs]
        run_owned(helper, source, root, 'npm-ci', argv, project, env, 600)
        require(before_inputs == {name: digest(project / name) for name in before_inputs},
                'npm changed the frozen package or lock')
        installed = {}
        expected = {'vitest': '5.0.5', 'jest': '30.5.2', 'jest-junit': '17.0.0',
                    '@rolldown/binding-win32-' + details['arch'] + '-msvc': '1.2.16',
                    'lightningcss-win32-' + details['arch'] + '-msvc': '1.33.0'}
        for name, version in expected.items():
            package = project / 'node_modules' / name / 'package.json'
            installed[name] = json.loads(package.read_text(encoding='utf-8'))['version']
            require(installed[name] == version, 'installed locked package differs: ' + name)
        result.update(status='PASS', installed=installed, node_modules=str(project / 'node_modules'),
                      package_inputs=before_inputs, kit_manifest=before_kit)
    except BaseException as exc:
        result.update(status='FAIL', error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
    finally:
        if helper is not None:
            with helper.defer_stops(result):
                try:
                    verify_kit(kit)
                    if before_source is not None:
                        after_source = helper.source_facts(source, git_path, env)
                        save(root / 'source-after.json', after_source)
                        require(after_source == before_source, 'source changed during acquisition')
                    if before_tools is not None:
                        after_tools = {name: helper.fact(Path(name)) for name in before_tools}
                        save(root / 'tools-after.json', after_tools)
                        require(after_tools == before_tools, 'Node/npm tools changed during acquisition')
                except BaseException as exc:
                    result.update(status='FAIL', witness_error=type(exc).__name__ + ': ' + str(exc))
                if result.get('deferred_signals'):
                    result['status'] = 'FAIL'
                save(root / 'execution.json', result)
        else:
            save(root / 'execution.json', result)
        # Curated evidence only: never include project/node_modules, private configs, or caches.
        paths = list(root.glob('*.json')) + [p for label in ('node-identity', 'npm-identity', 'npm-ci')
                 for p in (root / label).glob('*') if p.suffix in ('.json', '.log')]
        save(root / 'manifest.json', {'status': result['status'], 'script_sha256': digest(Path(__file__)),
             'files': {str(p.relative_to(root)): {'sha256': digest(p), 'bytes': p.stat().st_size} for p in paths},
             'excludes': ['project tree', 'node_modules/native payload', 'npm cache', 'HOME/config directories']})
        if old_term is not None:
            signal.signal(signal.SIGTERM, old_term)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
