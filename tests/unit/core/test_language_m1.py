"""Expanded extensions retain explicit packaged-driver opt-in until M2."""
from __future__ import annotations

from aegis_core.ast.detect import detect_project_languages, provision_ast_driver_slots
from aegis_core.ast.runner import ASTDriverRegistry


def test_detects_mts_cts_without_enabling_an_external_parser(tmp_path):
    (tmp_path / 'source.mts').write_text('export const x = 1;', encoding='utf-8')
    (tmp_path / 'source.cts').write_text('export const y = 2;', encoding='utf-8')
    detected = detect_project_languages(tmp_path)
    assert detected['typescript']['extensions'] == ['.cts', '.mts']
    assert detected['typescript']['file_count'] == 2
    assert ASTDriverRegistry().resolve_driver('.mts', workspace_root=tmp_path) is None


def test_provisioning_covers_every_known_extension_of_the_language(tmp_path):
    (tmp_path / 'package.json').write_text('{}', encoding='utf-8')
    (tmp_path / 'tsconfig.json').write_text('{}', encoding='utf-8')
    slots, written = provision_ast_driver_slots(tmp_path)
    assert set(slots) == {f'ast_driver_{ext}' for ext in ('ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs')}
    assert written == [str(tmp_path / '.aegis/config.json')]


def test_detection_does_not_follow_source_links_outside_the_workspace(tmp_path):
    from conftest import symlink_or_skip

    root = tmp_path / 'repo'
    root.mkdir()
    outside = tmp_path / 'outside.ts'
    outside.write_text('external()', encoding='utf-8')
    symlink_or_skip(outside, root / 'linked.ts')
    assert detect_project_languages(root) == {}
