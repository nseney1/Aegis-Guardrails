"""Expanded TS/JS extensions use the in-process parser without a packaged-driver opt-in (M2a)."""
from __future__ import annotations

from aegis_core.ast.detect import detect_project_languages, provision_ast_driver_slots
from aegis_core.ast.runner import NATIVE_JS_EXTENSIONS, ASTDriverRegistry


def test_detects_mts_cts_without_enabling_an_external_parser(tmp_path):
    (tmp_path / 'source.mts').write_text('export const x = 1;', encoding='utf-8')
    (tmp_path / 'source.cts').write_text('export const y = 2;', encoding='utf-8')
    detected = detect_project_languages(tmp_path)
    assert detected['typescript']['extensions'] == ['.cts', '.mts']
    assert detected['typescript']['file_count'] == 2
    for ext in ('.mts', '.cts'):
        assert ASTDriverRegistry().resolve_driver(ext, workspace_root=tmp_path) == (
            'native JavaScript/TypeScript (in-process)')


def test_provisioning_covers_every_known_extension_of_the_language(tmp_path):
    (tmp_path / 'package.json').write_text('{}', encoding='utf-8')
    (tmp_path / 'tsconfig.json').write_text('{}', encoding='utf-8')
    assert provision_ast_driver_slots(tmp_path) == ({}, [])
    assert not (tmp_path / '.aegis').exists()
    assert NATIVE_JS_EXTENSIONS == {'.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'}
    for ext in NATIVE_JS_EXTENSIONS:
        assert ASTDriverRegistry().resolve_driver(ext, workspace_root=tmp_path) == (
            'native JavaScript/TypeScript (in-process)')


def test_detection_does_not_follow_source_links_outside_the_workspace(tmp_path):
    from conftest import symlink_or_skip

    root = tmp_path / 'repo'
    root.mkdir()
    outside = tmp_path / 'outside.ts'
    outside.write_text('external()', encoding='utf-8')
    symlink_or_skip(outside, root / 'linked.ts')
    assert detect_project_languages(root) == {}
