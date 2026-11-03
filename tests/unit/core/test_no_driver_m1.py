"""Layer 1 exposes missing coverage and shares external parses."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

from aegis_core.ast.runner import ASTDriverRegistry, ASTDriverRunner
from aegis_core.verification import runner


def _rule(root: Path, extension: str = 'kt') -> None:
    directory = root / '.aegis' / 'rules' / 'invariants'
    directory.mkdir(parents=True)
    (directory / 'no-reflection.md').write_text(
        '---\nid: no-reflection\ntype: invariant\nenforcement: gate\n'
        f'target_paths: ["src/*.{extension}"]\nforbid_ast:\n  calls: [danger]\n---\n# No reflection\n',
        encoding='utf-8',
    )


def test_matching_unknown_extension_has_dedicated_advisory_row(tmp_path):
    _rule(tmp_path)
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src' / 'app.kt').write_text('danger()', encoding='utf-8')
    results = runner.run_layer1(['src/app.kt'], str(tmp_path), fast_mode=True)
    note, = [row for row in results if 'no_driver:.kt' in row.detail]
    assert note.verdict is True and note.target == 'src/app.kt'
    assert note.tool != runner.UNVERIFIED_NOTE_TOOL
    assert note.language == 'unknown'
    assert runner.gate_verdict(results) is True
    assert runner.gate_verdict(results, strict=True) is False


def test_unknown_where_remains_advisory_under_strict():
    from aegis_core.verification import ToolEvidence

    rows = [ToolEvidence(runner.UNVERIFIED_NOTE_TOOL, 'app.py', True, 'unknown where')]
    assert runner.gate_verdict(rows, strict=True) is True


def test_call_graph_and_two_rules_share_one_external_parse(tmp_path, monkeypatch):
    _rule(tmp_path, 'xyz')
    rule = tmp_path / '.aegis/rules/invariants/no-reflection.md'
    (rule.parent / 'second.md').write_text(rule.read_text().replace('no-reflection', 'second'), encoding='utf-8')
    (tmp_path / 'src').mkdir()
    target = tmp_path / 'src/app.xyz'
    target.write_text('danger()', encoding='utf-8')
    driver = tmp_path / 'driver.py'
    counter = tmp_path / 'calls.jsonl'
    driver.write_text(
        'import json, pathlib, sys\n'
        'with pathlib.Path(sys.argv[1]).open("a") as out: out.write(sys.argv[2]+"\\n")\n'
        'print(json.dumps({"version":"1.0","language":"go","file_path":sys.argv[2],'
        '"definitions":[],"call_sites":[{"target":"danger","line":1}]}))\n', encoding='utf-8',
    )
    argv = [sys.executable, str(driver), str(counter)]
    command = subprocess.list2cmdline(argv) if os.name == 'nt' else shlex.join(argv)
    parser = ASTDriverRunner(ASTDriverRegistry({'.xyz': command}))
    monkeypatch.setattr('aegis_core.ast.runner.ASTDriverRunner', lambda: parser)
    results = runner.run_layer1(['src/app.xyz'], str(tmp_path), fast_mode=True)
    assert [r.tool for r in results if not r.verdict] == ['forbid_ast:no-reflection', 'forbid_ast:second']
    assert counter.read_text().splitlines() == [str(target)]


def test_staged_non_driver_file_retains_coverage_note_and_one_secret_finding(tmp_path):
    def git(*args):
        return subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', *args],
                              cwd=tmp_path, check=True, capture_output=True)

    git('init', '-q')
    _rule(tmp_path)
    git('add', '.aegis')
    git('commit', '-qm', 'fixture')
    (tmp_path / 'src').mkdir()
    target = tmp_path / 'src/app.kt'
    target.write_text('key = "' + 'AKIA' + 'A' * 16 + '"\n', encoding='utf-8')
    git('add', 'src/app.kt')
    target.write_text('working copy has no key', encoding='utf-8')
    results = runner.run_layer1_on_index(['src/app.kt'], str(tmp_path))
    assert len([r for r in results if 'no_driver:.kt' in r.detail]) == 1
    secrets = [r for r in results if r.tool.startswith('secret') and not r.verdict]
    assert len(secrets) == 1
    assert secrets[0].target == 'src/app.kt'
