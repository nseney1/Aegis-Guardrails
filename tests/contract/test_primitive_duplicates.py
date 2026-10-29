"""The generic primitive families removed by 4.4 cannot return."""
import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk")
FORBIDDEN = {"_within", "_is_within", "_inside", "_utc_now", "_utc_timestamp",
             "_now_iso", "_envelope", "_pack_envelope", "_parse_ts", "_stamp",
             "_read_blobs", "_git_blob_id"}
# This wrapper compares canonical lookup keys, not arbitrary filesystem paths.
ALLOWED = {("aegis_core/pathlookup.py", "_inside")}


def duplicate_primitives(root):
    found = []
    for package in PACKAGES:
        for path in sorted((root / package).rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            if rel == "aegis_core/primitives.py":
                continue
            for node in ast.parse(path.read_text(encoding="utf-8"), filename=rel).body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in FORBIDDEN:
                    if (rel, node.name) not in ALLOWED:
                        found.append(f"{rel}:{node.lineno}: {node.name}")
    return found


def test_no_primitive_duplicates():
    assert duplicate_primitives(REPO) == []


def test_duplicate_detector_names_new_definition(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "new.py").write_text("def _utc_now():\n    return 0\n", encoding="utf-8")
    assert duplicate_primitives(tmp_path) == ["aegis_core/new.py:1: _utc_now"]
    (package / "new.py").write_text("class Local:\n    def _utc_now(self): return 0\n", encoding="utf-8")
    assert duplicate_primitives(tmp_path) == []
