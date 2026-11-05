"""Frozen legacy replay; unimplemented integrated cases never count as passing."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_foundation_acceptance.py"
CORPUS = ROOT / "tests" / "fixtures" / "hierarchy_native_foundation"
MANIFEST_SHA256 = "2578d8de561584fd7bdc47383e350d0730d69d09ea7705c96b32e35929889695"


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def invoke(tmp_path, corpus=CORPUS, tool=TOOL):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CODEX_HOME=str(home / ".codex"),
               XDG_CONFIG_HOME=str(home / ".config"), XDG_CACHE_HOME=str(home / ".cache"),
               LOCALAPPDATA=str(home / "local"), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-I", "-B", str(tool), "--fixtures", str(corpus), "legacy"],
                          capture_output=True, text=True, timeout=10, env=env)


def copied_corpus(tmp_path):
    target = tmp_path / "corpus"
    shutil.copytree(CORPUS, target)
    return target


def assert_error(result, code):
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"schema": "aegis.foundation-acceptance-error/v1", "code": code}


def test_public_surface_exists():
    spec = importlib.util.spec_from_file_location("foundation_acceptance_candidate", TOOL)
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    assert callable(candidate.inspect_legacy)
    assert issubclass(candidate.AcceptanceError, ValueError)


@pytest.mark.skipif(os.name != "posix", reason="legacy corpus has POSIX absolute inert evidence paths")
def test_cli_replays_exact_legacy_bytes_and_reports_coupling_as_held(tmp_path):
    before = snapshot(CORPUS)
    result = invoke(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stderr == ""
    value = json.loads(result.stdout)
    assert set(value) == {"schema", "qualification", "corpus_sha256", "source_manifest_sha256",
                          "legacy_cases", "dependency_held", "native_authority", "workflow_restart"}
    assert value["schema"] == "aegis.foundation-acceptance/v1"
    assert value["qualification"] == "reconstructed_fixture_only"
    assert value["corpus_sha256"] == MANIFEST_SHA256
    assert value["native_authority"] == "not_established"
    assert value["workflow_restart"] == "held"
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    expected_source = json.dumps(manifest["source_files"], sort_keys=True, separators=(",", ":")).encode()
    assert value["source_manifest_sha256"] == hashlib.sha256(expected_source).hexdigest()
    assert {case["case_id"] for case in value["legacy_cases"]} == {
        "legacy-unassociated-intent", "legacy-expired-approval"}
    for case in value["legacy_cases"]:
        assert set(case) == {"case_id", "state", "request_sha256", "journal_head", "receipt_sha256",
                             "checkpoint_sha256", "bytes_unchanged"}
        assert case["state"] == "verified" and case["bytes_unchanged"] is True
        definition = next(c for c in manifest["legacy_cases"] if c["case_id"] == case["case_id"])
        folder = CORPUS / definition["prefix"]
        expected_checkpoint = json.loads((folder / "checkpoint.json").read_text())
        expected_request = json.loads((folder / "request.json").read_text())
        assert case["request_sha256"] == expected_request["sha256"]
        assert case["journal_head"] == expected_checkpoint["state"]["head"]
        assert case["checkpoint_sha256"] == expected_checkpoint["sha256"]
        assert case["receipt_sha256"] == hashlib.sha256((folder / "receipt.json").read_bytes()).hexdigest()
    matrix = json.loads((CORPUS / "case-matrix.json").read_text())
    assert value["dependency_held"] == [{"case_id": c["case_id"], "requires": c["requires"]}
                                         for c in matrix["cases"] if c["kind"] == "coupled"]
    assert snapshot(CORPUS) == before


def test_missing_manifest_fails_without_creating_the_input(tmp_path):
    missing = tmp_path / "missing"
    assert_error(invoke(tmp_path, missing), "FOUNDATION_CORPUS_MISSING")
    assert not missing.exists()


def test_changed_fixture_is_refused_and_not_rewritten(tmp_path):
    corpus = copied_corpus(tmp_path)
    changed = corpus / "legacy-intent" / "request.json"
    changed.write_bytes(changed.read_bytes() + b" ")
    before = snapshot(corpus)
    assert_error(invoke(tmp_path, corpus), "FOUNDATION_FIXTURE_HASH_MISMATCH")
    assert snapshot(corpus) == before


def test_missing_journal_event_is_refused_and_not_repaired(tmp_path):
    corpus = copied_corpus(tmp_path)
    missing = corpus / "legacy-intent" / "events" / "000003.json"
    missing.unlink()
    before = snapshot(corpus)
    assert_error(invoke(tmp_path, corpus), "FOUNDATION_CORPUS_MISSING")
    assert snapshot(corpus) == before


def test_manifest_drift_cannot_replace_the_reviewed_oracle(tmp_path):
    corpus = copied_corpus(tmp_path)
    manifest = corpus / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    assert_error(invoke(tmp_path, corpus), "FOUNDATION_MANIFEST_MISMATCH")


@pytest.mark.parametrize("unsafe", ["../outside.json", "/outside.json", "a/../b", "a\\b", "a//b"])
def test_manifest_paths_are_rejected_before_external_files_are_read(tmp_path, unsafe):
    corpus = copied_corpus(tmp_path)
    manifest = corpus / "manifest.json"
    value = json.loads(manifest.read_text())
    value["files"][unsafe] = "0" * 64
    manifest.write_text(json.dumps(value))
    outside = tmp_path / "outside.json"
    outside.write_text("must remain untouched")
    assert_error(invoke(tmp_path, corpus), "FOUNDATION_CORPUS_PATH_INVALID")
    assert outside.read_text() == "must remain untouched"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX symlink creation without elevated privileges")
@pytest.mark.parametrize("root_link", [False, True])
def test_symlinked_root_or_fixture_is_refused(tmp_path, root_link):
    corpus = copied_corpus(tmp_path)
    if root_link:
        link = tmp_path / "link"
        link.symlink_to(corpus, target_is_directory=True)
        corpus = link
    else:
        original = corpus / "legacy-intent" / "request.json"
        outside = tmp_path / "original.json"
        original.rename(outside)
        original.symlink_to(outside)
    assert_error(invoke(tmp_path, corpus), "FOUNDATION_CORPUS_PATH_INVALID")


@pytest.mark.parametrize("raw,code", [(b" " * 65537, "FOUNDATION_CORPUS_TOO_LARGE"),
                                      (b'{"schema":1,"schema":2}', "FOUNDATION_CORPUS_INVALID"),
                                      (b'{"schema":NaN}', "FOUNDATION_CORPUS_INVALID"),
                                      (b"\xff", "FOUNDATION_CORPUS_INVALID"),
                                      (b"[" * 17 + b"0" + b"]" * 17, "FOUNDATION_CORPUS_INVALID")])
def test_manifest_sad_paths_have_exact_public_errors(tmp_path, raw, code):
    corpus = copied_corpus(tmp_path)
    (corpus / "manifest.json").write_bytes(raw)
    assert_error(invoke(tmp_path, corpus), code)


def test_undeclared_fixture_file_cannot_join_the_reviewed_corpus(tmp_path):
    corpus = copied_corpus(tmp_path)
    (corpus / "extra.json").write_text("{}")
    assert_error(invoke(tmp_path, corpus), "FOUNDATION_CORPUS_INVALID")


def test_source_mismatch_refuses_before_unverified_producer_import(tmp_path):
    candidate_root = tmp_path / "source"
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    for name in [*manifest["source_files"], "tools/hierarchy_foundation_acceptance.py"]:
        target = candidate_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    changed = candidate_root / "tools" / "hierarchy_lifecycle.py"
    changed.write_text('raise RuntimeError("unverified producer executed")\n' + changed.read_text())
    assert_error(invoke(tmp_path, tool=candidate_root / "tools" / TOOL.name), "FOUNDATION_SOURCE_MISMATCH")


@pytest.mark.parametrize("resolution", ["cached-lifecycle", "cached-mailbox", "earlier-path"])
def test_public_api_rejects_foreign_loaded_producer(tmp_path, resolution):
    """Use different real producer files, never fabricated producer callbacks."""
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    for name in ("hierarchy_lifecycle.py", "hierarchy_mailbox.py"):
        # Same actual implementation with distinct retained source bytes and origin.
        (foreign / name).write_bytes((ROOT / "tools" / name).read_bytes() + b"\n# foreign fixture copy\n")
    script = r'''
import importlib.util,json,sys
from pathlib import Path
tool,corpus,foreign,resolution=sys.argv[1:]
own=str(Path(tool).parent)
sys.path.insert(0,foreign)
if resolution == "cached-lifecycle":
    import hierarchy_lifecycle
    assert Path(hierarchy_lifecycle.__file__).parent == Path(foreign)
    sys.path.remove(foreign)
elif resolution == "cached-mailbox":
    import hierarchy_mailbox
    assert Path(hierarchy_mailbox.__file__).parent == Path(foreign)
    sys.path.remove(foreign)
else:
    # The reviewed directory is already present, but after the foreign root.
    sys.path.insert(1,own)
spec=importlib.util.spec_from_file_location("acceptance_candidate",tool)
candidate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
try:
    candidate.inspect_legacy(corpus)
except candidate.AcceptanceError as exc:
    print(json.dumps({"code":exc.code}))
else:
    print(json.dumps({"code":None}))
'''
    home = tmp_path / "private-home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CODEX_HOME=str(home / ".codex"),
               XDG_CONFIG_HOME=str(home / ".config"), XDG_CACHE_HOME=str(home / ".cache"),
               PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(TOOL), str(CORPUS),
                             str(foreign), resolution], capture_output=True, text=True, timeout=10, env=env)
    assert result.returncode == 0 and result.stderr == "", result.stdout + result.stderr
    assert json.loads(result.stdout) == {"code": "FOUNDATION_SOURCE_MISMATCH"}


def test_public_api_rejects_unwitnessed_cache_even_after_same_path_bytes_are_restored(tmp_path):
    candidate_root = tmp_path / "source"
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    for name in {*manifest["source_files"], "tools/hierarchy_mailbox.py",
                 "tools/hierarchy_foundation_acceptance.py"}:
        target = candidate_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    script = r'''
import importlib.util,json,sys
from pathlib import Path
root,corpus=sys.argv[1:]
tools=Path(root)/"tools"
source=tools/"hierarchy_lifecycle.py"
pristine=source.read_bytes()
source.write_bytes(pristine+b"\n# earlier fixture version at same origin\n")
sys.path.insert(0,str(tools))
import hierarchy_lifecycle
assert Path(hierarchy_lifecycle.__file__) == source
source.write_bytes(pristine)
spec=importlib.util.spec_from_file_location("acceptance_candidate",tools/"hierarchy_foundation_acceptance.py")
candidate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
try:
    candidate.inspect_legacy(corpus)
except candidate.AcceptanceError as exc:
    print(json.dumps({"code":exc.code}))
else:
    print(json.dumps({"code":None}))
'''
    home = tmp_path / "home"
    home.mkdir()
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(candidate_root), str(CORPUS)],
                            capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, HOME=str(home), USERPROFILE=str(home),
                                     CODEX_HOME=str(home / ".codex"), PYTHONDONTWRITEBYTECODE="1"))
    assert result.returncode == 0 and result.stderr == "", result.stdout + result.stderr
    assert json.loads(result.stdout) == {"code": "FOUNDATION_SOURCE_MISMATCH"}


@pytest.mark.skipif(os.name != "posix", reason="foundation replay requires a POSIX host")
def test_public_api_repeated_replay_reuses_its_verified_source_without_changing_fixtures(tmp_path):
    script = r'''
import importlib.util,json,sys
tool,corpus=sys.argv[1:]
spec=importlib.util.spec_from_file_location("acceptance_candidate",tool)
candidate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
first=candidate.inspect_legacy(corpus)
second=candidate.inspect_legacy(corpus)
print(json.dumps({"equal":first == second,"cases":len(second["legacy_cases"]),
                  "qualification":second["qualification"],"native_authority":second["native_authority"]}))
'''
    before = snapshot(CORPUS)
    home = tmp_path / "home"
    home.mkdir()
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(TOOL), str(CORPUS)],
                            capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, HOME=str(home), USERPROFILE=str(home),
                                     CODEX_HOME=str(home / ".codex"), PYTHONDONTWRITEBYTECODE="1"))
    assert result.returncode == 0 and result.stderr == "", result.stdout + result.stderr
    assert json.loads(result.stdout) == {"equal": True, "cases": 2,
                                        "qualification": "reconstructed_fixture_only",
                                        "native_authority": "not_established"}
    assert snapshot(CORPUS) == before


@pytest.mark.skipif(os.name != "posix", reason="legacy corpus has POSIX absolute inert evidence paths")
@pytest.mark.parametrize("producer", ["hierarchy_mailbox", "hierarchy_lifecycle"])
def test_public_api_ignores_valid_poisoned_bytecode_for_pinned_source(tmp_path, producer):
    candidate_root = tmp_path / "source"
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    for name in {*manifest["source_files"], "tools/hierarchy_mailbox.py",
                 "tools/hierarchy_foundation_acceptance.py"}:
        target = candidate_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    corpus = copied_corpus(tmp_path)
    marker = tmp_path / "poison-observed"
    source = candidate_root / "tools" / (producer + ".py")
    pristine = source.read_bytes()
    source.write_text("from pathlib import Path\nPath(" + repr(str(marker))
                      + ").write_text('poison consumed')\nraise RuntimeError('poisoned cache')\n")
    py_compile.compile(str(source), doraise=True,
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    source.write_bytes(pristine)
    before_source, before_corpus = snapshot(candidate_root), snapshot(corpus)
    home = tmp_path / "private-home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CODEX_HOME=str(home / ".codex"),
               XDG_CONFIG_HOME=str(home / ".config"), XDG_CACHE_HOME=str(home / ".cache"),
               PYTHONDONTWRITEBYTECODE="1")
    control = subprocess.run(
        [sys.executable, "-I", "-B", "-c",
         "import importlib,sys;sys.path.insert(0,sys.argv[1]);importlib.import_module(sys.argv[2])",
         str(candidate_root / "tools"), producer],
        capture_output=True, text=True, timeout=10, env=env)
    assert control.returncode != 0 and "RuntimeError: poisoned cache" in control.stderr
    assert marker.read_text() == "poison consumed"
    marker.unlink()
    assert snapshot(candidate_root) == before_source
    script = r'''
import importlib.util,json,sys
tool,corpus=sys.argv[1:]
spec=importlib.util.spec_from_file_location("acceptance_candidate",tool)
candidate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
print(json.dumps(candidate.inspect_legacy(corpus)))
'''
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script,
         str(candidate_root / "tools" / TOOL.name), str(corpus)],
        capture_output=True, text=True, timeout=10, env=env)
    expected = invoke(tmp_path, corpus=corpus)
    assert result.returncode == 0 and result.stderr == "", result.stdout + result.stderr
    assert expected.returncode == 0 and expected.stderr == "", expected.stdout + expected.stderr
    assert json.loads(result.stdout) == json.loads(expected.stdout)
    assert not marker.exists()
    assert snapshot(candidate_root) == before_source
    assert snapshot(corpus) == before_corpus
