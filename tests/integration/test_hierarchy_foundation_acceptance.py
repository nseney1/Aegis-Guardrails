"""Owned replay scratch may follow OS aliases; caller corpus paths may not."""
import json
import os
import shutil

import pytest

from tests.integration.test_hierarchy_native_foundation_cycle import (
    ROOT,
    assert_error,
    copied_corpus,
    invoke,
    snapshot,
)


@pytest.mark.skipif(os.name != "posix", reason="requires an actual OS symlink")
@pytest.mark.parametrize("aliased_corpus", [False, True])
def test_cli_replay_owns_canonical_scratch_under_aliased_temp_directory(
        tmp_path, monkeypatch, aliased_corpus):
    root = tmp_path.resolve()
    scratch = root / "scratch"
    scratch.mkdir()
    alias = root / "temp-alias"
    alias.symlink_to(scratch, target_is_directory=True)
    corpus = copied_corpus(root)
    before = snapshot(corpus)
    supplied = corpus
    if aliased_corpus:
        supplied = root / "corpus-alias"
        supplied.symlink_to(corpus, target_is_directory=True)
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, str(alias))
    result = invoke(root, supplied)
    if aliased_corpus:
        assert_error(result, "FOUNDATION_CORPUS_PATH_INVALID")
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stderr == ""
        value = json.loads(result.stdout)
        assert value["qualification"] == "reconstructed_fixture_only"
        assert value["workflow_restart"] == "held"
        assert all(case["bytes_unchanged"] for case in value["legacy_cases"])
    assert snapshot(corpus) == before
    assert list(scratch.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="legacy corpus has POSIX inert evidence paths")
@pytest.mark.parametrize("tampered", [False, True])
def test_cli_pins_reviewed_watch_fixture_successor_without_changing_corpus(tmp_path, tampered):
    corpus = copied_corpus(tmp_path)
    before = snapshot(corpus)
    source = tmp_path / "source"
    manifest = json.loads((corpus / "manifest.json").read_text())
    for name in {*manifest["source_files"], "tools/hierarchy_mailbox.py",
                 "tools/hierarchy_foundation_acceptance.py"}:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    watch = source / "tests/integration/test_hierarchy_watch_bridge.py"
    if tampered:
        watch.write_bytes(watch.read_bytes() + b"\n")
    before_source = snapshot(source)
    result = invoke(tmp_path, corpus, source / "tools/hierarchy_foundation_acceptance.py")
    if tampered:
        assert_error(result, "FOUNDATION_SOURCE_MISMATCH")
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stderr == ""
        assert json.loads(result.stdout)["workflow_restart"] == "held"
    assert snapshot(source) == before_source
    assert snapshot(corpus) == before
