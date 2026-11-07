"""Collection and pinned checkout bytes remain portable even when execution is POSIX-only."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
COLLECT = r'''
import builtins, signal, sys, pytest
original = builtins.__import__
def imported(name, *args, **kwargs):
    if name in {"pwd", "fcntl"}:
        raise ModuleNotFoundError("No module named " + repr(name))
    return original(name, *args, **kwargs)
builtins.__import__ = imported
if hasattr(signal, "SIGHUP"):
    del signal.SIGHUP
raise SystemExit(pytest.main(["--collect-only", "-q", "-p", "no:cacheprovider", sys.argv[1]]))
'''


@pytest.mark.parametrize("name", ["launcher", "loop", "m1_loop", "native_probe"])
def test_posix_hierarchy_tests_collect_without_posix_modules(tmp_path, name):
    result = subprocess.run([sys.executable, "-B", "-c", COLLECT,
                             "tests/integration/test_hierarchy_%s.py" % name], cwd=ROOT,
                            env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "collected" in result.stdout


def test_large_payload_cases_use_bounded_pytest_ids():
    script = '''
import pytest
class Inspect:
    def pytest_collection_finish(self, session):
        long_ids = [item.nodeid[:120] for item in session.items if len(item.nodeid) > 512]
        if long_ids:
            raise pytest.UsageError("oversized case ids: " + repr(long_ids))
raise SystemExit(pytest.main(["--collect-only", "-q", "-p", "no:cacheprovider",
    "tests/integration/test_hierarchy_fixture_broker.py",
    "tests/integration/test_hierarchy_native_foundation_cycle.py"], plugins=[Inspect()]))
'''
    result = subprocess.run([sys.executable, "-B", "-c", script], cwd=ROOT,
                            env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout[-1000:] + result.stderr


def test_autocrlf_checkout_preserves_foundation_payload_and_pinned_source_bytes(tmp_path):
    corpus = ROOT / "tests" / "fixtures" / "hierarchy_native_foundation"
    manifest = json.loads((corpus / "manifest.json").read_text())
    names = [*manifest["source_files"], "tools/hierarchy_mailbox.py"]
    names += [str(path.relative_to(ROOT)) for path in corpus.rglob("*") if path.is_file()]
    source = tmp_path / "source"
    source.mkdir()
    (source / ".gitattributes").write_bytes((ROOT / ".gitattributes").read_bytes())
    for name in names:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    def git(*words):
        subprocess.run(["git", "-C", str(source), *words], check=True, capture_output=True, timeout=30)
    git("init", "-q")
    git("-c", "core.autocrlf=false", "add", ".")
    exported = tmp_path / "exported"
    git("-c", "core.autocrlf=true", "checkout-index", "--all", "--force", "--prefix", exported.as_posix() + "/")
    changed = [name for name in names if (exported / name).read_bytes() != (ROOT / name).read_bytes()]
    assert changed == [], "checkout changed pinned bytes: " + repr(changed)
