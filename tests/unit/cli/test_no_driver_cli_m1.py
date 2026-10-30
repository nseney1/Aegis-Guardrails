"""The ordinary CLI promotes only missing-driver coverage notes under strict."""
from __future__ import annotations

import json

from aegis_cli.cli import main


def test_check_no_driver_is_visible_and_only_strict_blocks(tmp_path, capsys):
    from tests.unit.core.test_no_driver_m1 import _rule

    _rule(tmp_path)
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src/app.kt').write_text('danger()', encoding='utf-8')
    base = ['check', '--workspace', str(tmp_path), 'src/app.kt', '--json']
    assert main(base) == 0
    ordinary = json.loads(capsys.readouterr().out)
    assert 'no_driver:.kt' in ordinary['layer1'][0]['detail']
    assert ordinary['layer1'][0]['language'] == 'unknown'
    assert main([*base, '--strict']) == 1
    strict = json.loads(capsys.readouterr().out)
    assert strict['passed'] is False
    assert 'strict' in strict['summary']


def test_doctor_lists_rule_covered_unknown_extension_without_running_a_driver(tmp_path, capsys):
    from tests.unit.core.test_no_driver_m1 import _rule

    _rule(tmp_path)
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src/app.kt').write_text('danger()', encoding='utf-8')
    assert main(['doctor', '--drivers', '--workspace', str(tmp_path), '--json']) == 1
    document = json.loads(capsys.readouterr().out)
    check, = document['checks']
    assert check['id'] == 'ast_drivers'
    assert any('no_driver:.kt' in detail for detail in check['detail'])
