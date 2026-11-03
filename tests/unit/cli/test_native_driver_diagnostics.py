"""Native diagnostics require no Node process or packaged-driver opt-in."""
from __future__ import annotations

import json

from aegis_cli.cli import main
from aegis_core import card


def test_doctor_and_card_report_native_js_ready_without_node(tmp_path, monkeypatch, capsys):
    (tmp_path / 'app.ts').write_text('export function run() {}', encoding='utf-8')
    monkeypatch.setenv('PATH', '')
    assert main(['doctor', '--drivers', '--workspace', str(tmp_path), '--json']) == 0
    doc = json.loads(capsys.readouterr().out)
    assert any('in-process' in line for row in doc['checks'] for line in row['detail'])
    driver, = card.build(tmp_path).as_dict()['drivers']
    assert driver['status'] == 'ready' and 'in-process' in driver['driver']
