"""Public native security-pack precision, delta and uncertainty contracts."""
from __future__ import annotations

import subprocess

import pytest

from aegis_core.ast.runner import ASTDriverRegistry, ASTDriverRunner
from aegis_core.ast.session import ASTParseSession
from aegis_core.verification.security_pack import evaluate_security_pack
from tests.unit.core.test_go_ast_driver import go_driver_binary  # noqa: F401


JS_CASES = [
    ('sec-js-eval', "eval(value)", "object.eval(value)"),
    ('sec-js-eval', "new Function('return 1')", "function Function(x) {} new Function('safe')"),
    ('sec-js-eval', "Function('return 1')", "function eval(x) {} eval(value)"),
    *[('sec-js-eval', f"import vm from 'node:vm'; vm.{method}('x')", "import vm from 'vm'; vm.isContext(value)")
      for method in ('runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction')],
    ('sec-js-eval', "import vm from 'vm'; new vm.Script('x')", "const text = 'eval(value)';"),
    *[('sec-js-child-process-shell', f"const cp = require('node:child_process'); cp.{method}('ls')",
       "const cp = require('child_process'); cp.execFile('git', [])") for method in ('exec', 'execSync')],
    *[('sec-js-child-process-shell', f"import {{ {method} as run }} from 'child_process'; run('ls', [], {{shell: true}})",
       f"import {{ {method} as run }} from 'child_process'; run('git', [], {{shell: false}})")
      for method in ('spawn', 'spawnSync', 'execFile', 'execFileSync')],
    *[('sec-js-weak-hash', f"import crypto from 'crypto'; crypto.createHash('{name}')",
       "import crypto from 'crypto'; crypto.createHash('sha256')") for name in ('md5', 'sha1', 'MD5', 'SHA1')],
    *[('sec-js-tls-reject-unauthorized', f"import https from 'https'; https.{method}({{rejectUnauthorized:false}})",
       f"import https from 'https'; https.{method}({{rejectUnauthorized:true}})") for method in ('request', 'get')],
    ('sec-js-tls-reject-unauthorized', "import https from 'https'; new https.Agent({rejectUnauthorized:false})",
     "import https from 'https'; new https.Agent({rejectUnauthorized:true})"),
    *[('sec-js-tls-reject-unauthorized', f"import tls from 'tls'; tls.{method}({{rejectUnauthorized:false}})",
       f"import tls from 'tls'; tls.{method}({{rejectUnauthorized:true}})") for method in ('connect', 'createSecureContext')],
    ('sec-js-node-serialize', "const unsafe = require('node-serialize')", "const safe = require('json')"),
]
RUST_CASES = [
    ('sec-rs-command-shell', 'use std::process::Command as Cmd; fn f() { Cmd::new("sh"); }',
     'use std::process::Command; fn f() { Command::new("git"); }'),
    ('sec-rs-command-shell', 'fn f() { std::process::Command::new("bash"); }', 'fn f() { local::Command::new("git"); }'),
    *[('sec-rs-tls-danger', f'fn f() {{ builder.{method}(true); }}', f'fn f() {{ builder.{method}(false); }}')
      for method in ('danger_accept_invalid_certs', 'danger_accept_invalid_hostnames')],
]
RUST_HASH_COMPATIBILITY_CASES = [
    ('sec-rs-weak-hash', 'fn f() { md5::compute(data); }', 'fn f() { sha2::Sha256::digest(data); }'),
    *[('sec-rs-weak-hash', f'use {module}::{name} as Hash; fn f() {{ Hash::{method}(); }}',
       'use sha2::Sha256; fn f() { Sha256::new(); }')
      for module, name, methods in [('md5', 'Md5', ('new', 'default', 'digest')),
                                   ('sha1', 'Sha1', ('new', 'default', 'digest')),
                                   ('sha1_smol', 'Sha1', ('new', 'default', 'from'))]
      for method in methods],
]
GO_CASES = [
    ('sec-go-exec-shell', 'import ex "os/exec"', 'ex.Command("sh", "-c", "echo x")', 'ex.Command("git", "status")'),
    ('sec-go-exec-shell', 'import ex "os/exec"', 'ex.CommandContext(ctx, "cmd.exe")', 'ex.CommandContext(ctx, "git")'),
    *[('sec-go-weak-hash', f'import h "crypto/{algorithm}"', f'h.{method}()', 'println("safe")')
      for algorithm in ('md5', 'sha1') for method in ('New', 'Sum')],
    ('sec-go-tls-insecure', 'import t "crypto/tls"', '_ = &t.Config{InsecureSkipVerify: true}',
     '_ = &t.Config{InsecureSkipVerify: false}'),
    ('sec-go-ssh-insecure-hostkey', 'import s "golang.org/x/crypto/ssh"', 's.InsecureIgnoreHostKey()', 's.FixedHostKey(key)'),
]


def pack(root, source, *, extension='ts', base=None, session=None, name=None):
    name = name or 'app.' + extension
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding='utf-8')
    kwargs = {'session': session} if session is not None else {}
    return evaluate_security_pack(root, [name], {name: base} if base is not None else {}, **kwargs)


@pytest.mark.parametrize('rid,unsafe,safe', JS_CASES + RUST_CASES)
def test_each_native_rule_finds_unsafe_and_accepts_safe(tmp_path, rid, unsafe, safe):
    extension = 'rs' if rid.startswith('sec-rs-') else 'ts'
    result = pack(tmp_path, unsafe, extension=extension)
    assert [hit['rule_id'] for hit in result['violations']] == [rid]
    assert result['unverified_findings'] == [] and not result['passed']
    clean = pack(tmp_path, safe, extension=extension)
    assert clean['violations'] == [] and clean['unverified_findings'] == []


@pytest.mark.parametrize('rid,imports,unsafe,safe', GO_CASES)
def test_go_pack_uses_real_driver_and_accepts_safe(tmp_path, go_driver_binary, rid, imports, unsafe, safe):
    import shlex
    import os
    argv = [str(go_driver_binary)]
    command = subprocess.list2cmdline(argv) if os.name == 'nt' else shlex.join(argv)
    registry = ASTDriverRegistry()
    registry.register_driver('.go', command, protocol=2)
    def source(body):
        return f'package fixture\n{imports}\nfunc f() {{ {body} }}\n'
    with ASTParseSession(str(tmp_path), runner=ASTDriverRunner(registry)) as session:
        result = pack(tmp_path, source(unsafe), extension='go', session=session)
    assert [hit['rule_id'] for hit in result['violations']] == [rid]
    assert result['unverified_findings'] == []
    with ASTParseSession(str(tmp_path), runner=ASTDriverRunner(registry)) as session:
        clean = pack(tmp_path, source(safe), extension='go', session=session)
    assert clean['violations'] == [] and clean['unverified_findings'] == []
    with ASTParseSession(str(tmp_path), runner=ASTDriverRunner(registry)) as session:
        unchanged = pack(tmp_path, source(unsafe), extension='go', base=source(unsafe).encode(), session=session)
    assert unchanged['violations'] == [] and unchanged['unverified_findings'] == []


def test_rust_git_object_sha1_compatibility_is_not_a_security_violation(tmp_path):
    source = '''use sha1::{Digest, Sha1};
fn git_blob_oid(data: &[u8]) -> Vec<u8> {
    let header = format!("blob {}\\0", data.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(data);
    h.finalize().to_vec()
}
'''
    result = pack(tmp_path, source, extension='rs')
    assert result['violations'] == [] and result['unverified_findings'] == []


@pytest.mark.parametrize('extension', ['ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs'])
def test_all_native_js_extensions_have_pack_coverage(tmp_path, extension):
    assert [h['rule_id'] for h in pack(tmp_path, 'eval(input)', extension=extension)['violations']] == ['sec-js-eval']


@pytest.mark.parametrize('source,rid', [
    ("import cp from 'child_process'; cp.spawn('x', [], {...options})", 'sec-js-child-process-shell'),
    ("import crypto from 'crypto'; crypto.createHash(algorithm)", 'sec-js-weak-hash'),
    ("const x = require(packageName)", 'sec-js-node-serialize'),
])
def test_unknown_is_visible_and_advisory(tmp_path, source, rid):
    result = pack(tmp_path, source)
    assert result['passed'] and result['violations'] == []
    assert [h['rule_id'] for h in result['unverified_findings']] == [rid]


@pytest.mark.parametrize('extension,source', [
    ('ts', "import cp from 'child_process';\ncp.exec('x');\n"),
    ('rs', 'fn f() {\n std::process::Command::new("sh");\n}\n'),
])
def test_delta_multiset_preserves_only_added_occurrence(tmp_path, extension, source):
    result = pack(tmp_path, source + source, extension=extension, base=source.encode())
    assert len(result['violations']) == 1
    assert pack(tmp_path, '\n' + source, extension=extension, base=source)['violations'] == []


@pytest.mark.parametrize('name', ['tests/app.ts', 'app.test.ts'])
def test_test_paths_report_exemptions(tmp_path, name):
    result = pack(tmp_path, 'eval(input)', name=name)
    assert result['passed'] and result['violations'] == []
    assert [h['rule_id'] for h in result['exempted_test_findings']] == ['sec-js-eval']


def test_rule_specific_allow_comment_preserves_other_findings(tmp_path):
    result = pack(tmp_path, "import cp from 'child_process';\neval(input); cp.exec('x'); // aegis: allow[sec-js-eval]: fixture\n")
    assert [h['rule_id'] for h in result['violations']] == ['sec-js-child-process-shell']


@pytest.mark.parametrize('extension,source,reason', [('ts', '/* unterminated', 'JSLexError: syntax:unterminated_comment at line 1, offset 0'),
                                                    ('rs', 'fn broken(', 'ASTDriverError: unclosed delimiter at line 1')])
def test_native_parse_error_is_unverified_file(tmp_path, extension, source, reason):
    result = pack(tmp_path, source, extension=extension)
    assert result['violations'] == []
    assert len(result['unverified_findings']) == 1
    assert result['unverified_findings'][0]['kind'] == 'file'
    assert result['unverified_findings'][0]['reason'] == reason


def test_unconfigured_go_is_not_silently_clean(tmp_path):
    result = pack(tmp_path, 'package fixture', extension='go')
    assert result['violations'] == []
    assert [h['reason'] for h in result['unverified_findings']] == ['no_driver:.go']


@pytest.mark.parametrize('rid,source,safe', RUST_HASH_COMPATIBILITY_CASES)
def test_rust_hash_apis_are_outside_the_precision_approved_pack(tmp_path, rid, source, safe):
    for text in (source, safe):
        result = pack(tmp_path, text, extension='rs')
        assert result['violations'] == [] and result['unverified_findings'] == []


@pytest.mark.parametrize('extension,unsafe,base', [
    ('ts', 'eval(input)', '/* invalid base'),
    ('rs', 'fn f() { std::process::Command::new("sh"); }', 'fn broken('),
])
def test_invalid_base_never_suppresses_new_head_findings(tmp_path, extension, unsafe, base):
    result = pack(tmp_path, unsafe, extension=extension, base=base)
    assert len(result['violations']) == 1 and result['unverified_findings'] == []


def test_execfile_without_known_options_is_advisory_never_a_confirmed_shell(tmp_path):
    result = pack(tmp_path, "import cp from 'child_process'; cp.execFile('git', args)")
    assert result['passed'] and result['violations'] == []
    assert [h['rule_id'] for h in result['unverified_findings']] == ['sec-js-child-process-shell']


@pytest.mark.parametrize('extension', ['ts', 'rs'])
def test_undecodable_native_source_is_visible(tmp_path, extension):
    name = 'app.' + extension
    (tmp_path / name).write_bytes(b'\xff')
    result = evaluate_security_pack(tmp_path, [name], {})
    assert result['violations'] == []
    (failure,) = result['unverified_findings']
    assert failure['file'] == name and failure['kind'] == 'file'
    assert failure['reason'] == "ASTDriverError: invalid UTF-8: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
