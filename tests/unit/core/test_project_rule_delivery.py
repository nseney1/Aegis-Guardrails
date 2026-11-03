"""The tracked project catalog must deliver focused guidance at cold start."""
from pathlib import Path
import shutil

import pytest

from aegis_core.scan import scan


ROOT = Path(__file__).resolve().parents[3]
PREFIXES = ("invariant-", "trap-", "boundary-", "contract-", "persona-")


@pytest.fixture(scope="module")
def project_catalog(tmp_path_factory):
    root = tmp_path_factory.mktemp("project-catalog")
    source = ROOT / ".aegis" / "rules"
    for path in source.rglob("*.md"):
        if not path.name.startswith(PREFIXES):
            continue
        destination = root / ".aegis" / "rules" / path.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    return root


@pytest.mark.parametrize("path,expected", [
    ("aegis_core/workspace/binding.py", "contract-workspace-session-binding"),
    ("aegis_mcp/handlers/telemetry.py", "contract-witnessed-outcome-credit"),
    ("aegis_core/ast/batch.py", "contract-ast-driver-lifecycle"),
    ("aegis_core/ast/policy.py", "contract-ast-semantic-fidelity"),
    ("aegis_core/redaction.py", "contract-redaction-before-output"),
    ("aegis_core/storage.py", "contract-atomic-storage-boundaries"),
    ("aegis_core/scan.py", "contract-jit-rule-delivery"),
    ("aegis_core/testexec.py", "boundary-repo-content-untrusted"),
    ("aegis_core/telemetry_engine/ledger.py", "persona-check-local-performance"),
    ("aegis_core/command_safety/guard.py", "invariant-safety-gate"),
])
def test_focused_contract_reaches_default_jit(project_catalog, path, expected):
    result = scan(project_catalog, changed_files=[path])
    assert expected in [rule["name"] for rule in result["relevant_rules"]]
    assert not result["omitted_mandatory"]
    assert "## Evidence" not in result["guidance"]


@pytest.mark.parametrize("path", [
    ".aegis/config.json", "LICENSE", "NOTICE", "PRIVACY.md",
    "allowed_signers", "server.json", "future/nested/module.py", ".future-config",
])
def test_metadata_and_future_paths_receive_baseline(project_catalog, path):
    result = scan(project_catalog, changed_files=[path])
    assert "persona-repository-baseline" in [
        rule["name"] for rule in result["relevant_rules"]
    ]


@pytest.mark.parametrize("path", [
    "CONTRIBUTING.md", "README.md", "docs/teams.md",
    "skills/adaptive-reviewer/SKILL.md", ".aegis/rules/README.md",
])
def test_process_rules_do_not_crowd_policy_documents(project_catalog, path):
    result = scan(project_catalog, changed_files=[path])
    assert not result["omitted_mandatory"]
