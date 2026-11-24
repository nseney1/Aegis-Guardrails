"""Distribution and explicit adoption of the manager starter policy."""
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from importlib.resources import files
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile

import pytest
from packaging.version import Version

from aegis_core import pathlookup
from aegis_core.manager import ManagerService, initialize
from aegis_core.manager_policy import ACTIONS, ManagerError, canonical, digest, parse_policy
from aegis_core.primitives import redact_display_secrets, sanitize_display
from aegis_core.proposals import Proposal, ProposalError, ProposalStore
from aegis_core.proposals import store as proposal_store
from tests.helpers_manager import manager_root
from tests.helpers_reviewed_sources import git_environment
from tests.unit.cli.test_install_package_data import AEGIS_PACKAGES, REPO_ROOT
from tests.unit.core.test_proposals_store import make_store

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 and 3.10 use pytest's TOML dependency.
    import tomli as tomllib

RESOURCE = "manager_starter.json"
WORKSPACE = "studio-review"
ASSIGNMENT = "validate-assignment"
external_manager_root = manager_root
RULES = {
    "ground-rulings", "reconcile-due-work", "reconcile-before-intervention", ASSIGNMENT,
    "carry-decisions-forward", "reconcile-required-evidence", "bind-owner-answers",
    "reconcile-custody-transfers", "check-retry-budgets", "verify-reported-state",
    "verify-served-assignment", "measure-round-benefit",
}
PYTHON_PROBE = """
from importlib import import_module
from importlib.util import find_spec
import json
import sys

versions = {}
for name in sys.argv[1:]:
    if find_spec(name) is None:
        versions[name] = None
        continue
    package = import_module(name)
    version = package.__version__ if name == 'setuptools' else ''
    if not isinstance(version, str):
        raise ValueError('probe version must be text')
    versions[name] = version
print(json.dumps(versions))
"""
MIN_SETUPTOOLS = Version("68")
DIAGNOSTIC_INPUT_LIMIT = 8000
DIAGNOSTIC_DISPLAY_LIMIT = 2000
GIT_VERSION = re.compile(
    r"git version ([0-9]{1,9})\.([0-9]{1,9})(?:\.[0-9]+)*"
    r"(?:\.windows\.[0-9]+)?(?: \(Apple Git-[0-9.]+\))?"
)


def _starter():
    return json.loads(files("aegis_core").joinpath(RESOURCE).read_bytes())


def test_template_requires_identity_and_covers_all_decisions():
    template = _starter()
    assert template["workspace_id"] is None
    with pytest.raises(ManagerError, match="^invalid_policy$"):
        parse_policy(template)
    draft = {**template, "workspace_id": WORKSPACE}
    parsed = parse_policy(draft)
    assert {rule["id"] for rule in parsed["rules"]} == RULES
    assert {action for rule in parsed["rules"] for action in rule["actions"]} == ACTIONS
    for original, rule in zip(draft["rules"], parsed["rules"]):
        assert set(original) == {"id", "actions", "match", "text"}
        assert rule["match"] == {}  # Adopters choose their own classifications.
        assert rule["revision"] == digest(original)
        assert not re.search(r"[\\/]|\b[0-9a-f]{8,}\b", original["text"], re.IGNORECASE)
    assignment = next(rule for rule in parsed["rules"] if rule["id"] == ASSIGNMENT)
    assert assignment["actions"] == ["delegation"]
    assert all(term in assignment["text"] for term in
               ("inputs", "authorized work", "expected response", "outcome checks"))


def test_starter_has_an_exact_package_data_entry():
    table = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert RESOURCE in table["tool"]["setuptools"]["package-data"]["aegis_core"]


def _diagnostic(text):
    text = text or ""
    if len(text) > DIAGNOSTIC_INPUT_LIMIT:
        return "[diagnostic too large]"
    if isinstance(text, bytes):  # A timeout may carry bytes even in text mode.
        text = text.decode("utf-8", errors="replace")
    canonical = sanitize_display(text, max_len=None)
    return redact_display_secrets(canonical, limit=len(canonical))[:DIAGNOSTIC_DISPLAY_LIMIT]


def _child_failure(label, reason, result):
    pytest.fail(f"{label} {reason}\nstdout: {_diagnostic(result.stdout)}\nstderr: {_diagnostic(result.stderr)}",
                pytrace=False)


def _run_child(label, executable, *args, cwd, env=None, timeout=10):
    label = f"{label} ({_diagnostic(executable)})"
    try:
        result = subprocess.run([executable, *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _child_failure(label, f"timed out after {timeout}s", exc)
    except OSError as exc:
        pytest.fail(f"{label} failed to launch: {_diagnostic(str(exc))}", pytrace=False)
    if result.returncode != 0:
        _child_failure(label, f"exited with status {result.returncode}", result)
    return result


def _interpreter_with(directory, packages, missing_reason):
    candidates = dict.fromkeys((sys.executable, getattr(sys, "_base_executable", sys.executable)))
    for index, executable in enumerate(candidates, start=1):
        label = f"{'/'.join(packages)} probe (interpreter {index})"
        probe = _run_child(label, executable, "-I", "-c", PYTHON_PROBE, *packages,
                           cwd=directory, timeout=30)
        try:
            if len(probe.stdout) > 4096:
                raise ValueError("oversized probe result")
            versions = json.loads(probe.stdout)
            if not isinstance(versions, dict) or versions.keys() != set(packages) or any(
                value is not None and not isinstance(value, str) for value in versions.values()
            ):
                raise ValueError("invalid probe result")
            backend_version = versions.get("setuptools")
            old_backend = backend_version is not None and Version(backend_version) < MIN_SETUPTOOLS
        except ValueError as exc:
            label = f"{label} ({_diagnostic(executable)})"
            _child_failure(label, f"returned an invalid result (exit status 0): {_diagnostic(str(exc))}", probe)
        if not old_backend and None not in versions.values():
            return executable
    pytest.skip(missing_reason)


def test_starter_is_in_sdist_and_loads_from_installed_wheel(tmp_path):
    expected = (REPO_ROOT / "aegis_core" / RESOURCE).read_bytes()
    backend = _interpreter_with(tmp_path, ("setuptools", "wheel"),
                                "artifact build needs installed setuptools>=68 and wheel")
    installer = _interpreter_with(tmp_path, ("pip",), "artifact install needs installed pip")
    source = tmp_path / "source"
    source.mkdir()
    ignore = shutil.ignore_patterns("__pycache__", "*.py[cod]")
    for name in (*AEGIS_PACKAGES, "rules", "skills"):
        shutil.copytree(REPO_ROOT / name, source / name, ignore=ignore)
    for name in ("pyproject.toml", "MANIFEST.in", "README.md", "LICENSE"):
        shutil.copyfile(REPO_ROOT / name, source / name)
    _run_child("artifact build", backend, "-I", "-c",
               "from setuptools.build_meta import build_wheel, build_sdist\n"
               "build_wheel('dist')\nbuild_sdist('dist')", cwd=source, timeout=120)
    sdist, = (source / "dist").glob("*.tar.gz")
    with tarfile.open(sdist, "r:gz") as archive:
        member, = [name for name in archive.getnames() if name.endswith("/aegis_core/" + RESOURCE)]
        with archive.extractfile(member) as stream:
            assert stream.read() == expected
    wheel, = (source / "dist").glob("*.whl")
    target = tmp_path / "installed"
    _run_child("offline wheel install", installer, "-I", "-m", "pip", "--isolated",
               "--disable-pip-version-check", "--no-cache-dir", "install", "--no-index", "--no-deps",
               "--target", str(target), str(wheel), cwd=tmp_path,
               env=dict(os.environ, PIP_CONFIG_FILE=os.devnull), timeout=120)
    _run_child("installed catalog check", sys.executable, "-I", "-c", """
import json
from importlib.resources import files
from pathlib import Path
import sys

target = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(target))
import aegis_core
from aegis_core.manager_policy import parse_policy

assert Path(aegis_core.__file__).resolve().parent == target / 'aegis_core'
data = files(aegis_core).joinpath(sys.argv[2]).read_bytes()
assert data == Path(sys.argv[3]).read_bytes()
draft = json.loads(data)
draft['workspace_id'] = sys.argv[4]
assert len(parse_policy(draft)['rules']) == int(sys.argv[5])
""", str(target), RESOURCE, str(REPO_ROOT / "aegis_core" / RESOURCE), WORKSPACE, str(len(RULES)),
               cwd=tmp_path, timeout=120)


def _signing_tools(root):
    git_executable = pathlookup.which("git", outside=root, fence_program=True)
    if git_executable is None:
        pytest.skip("SSH approval requires Git outside the fixture root on an absolute PATH entry")
    signer = pathlookup.which("ssh-keygen", outside=root, fence_program=True)
    if signer is None:
        pytest.skip("SSH approval requires ssh-keygen outside the fixture root on an absolute PATH entry")
    probe = _run_child("Git version probe", git_executable, "version", cwd=root, env=git_environment())
    version = GIT_VERSION.fullmatch(probe.stdout.strip()) if len(probe.stdout) <= 512 else None
    if version is None:
        _child_failure("Git version probe", "returned an invalid version (exit status 0)", probe)
    if (int(version[1]), int(version[2])) < (2, 34):
        pytest.skip("SSH approval requires Git 2.34 or later")
    return git_executable, signer


def _git(executable, root, *args):
    return _run_child("fixture Git", executable, "-c", "user.name=Test",
                      "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                      "-c", "core.autocrlf=false", *args, cwd=root, env=git_environment()).stdout.strip()


def _commit_policy(git, control, draft):
    (control / "manager-policy" / "policy.json").write_bytes(canonical(draft))
    git(control, "add", "manager-policy")
    git(control, "commit", "-qm", "Review manager policy")
    return git(control, "rev-parse", "HEAD")


def _approve(git, control, key, signer, candidate):
    statement = candidate["approval_statement"]
    message = "Owner approval\n\nAegis-Manager-Approve: " + digest(statement)
    git(control, "-c", "gpg.format=ssh", "-c", "user.signingkey=" + str(key),
        "-c", "gpg.ssh.program=" + signer, "commit", "--allow-empty", "--no-verify", "-S", "-qm", message)
    return {"statement": statement, "commit": git(control, "rev-parse", "HEAD")}


@pytest.fixture
def adoption(external_manager_root):
    root = external_manager_root
    git_executable, signer = _signing_tools(root)
    git = partial(_git, git_executable)
    key, signers = root / "test-owner", root / "public-signers"
    _run_child("fixture key generation", signer, "-q", "-t", "ed25519", "-N", "", "-f", str(key), cwd=root)
    source, control = root / "project", root / "policy-review"
    for repo in (source, control):
        repo.mkdir()
        git(repo, "init", "-q", "--template=")
    (source / "readme.txt").write_text("source fixture\n", encoding="utf-8")
    git(source, "add", "readme.txt")
    git(source, "commit", "-qm", "Source baseline")
    (control / "manager-policy").mkdir()
    membership = {"schema": "aegis.manager-membership/v1", "workspace_id": WORKSPACE,
                  "repositories": [{"id": "aegis", "common_dir": str(source / ".git"),
                                    "worktrees": [{"id": "review-tree", "path": str(source)}]}]}
    (control / "manager-policy" / "membership.json").write_bytes(canonical(membership))
    signers.write_bytes(b"owner " + key.with_suffix(".pub").read_bytes())
    config, audit = root / "manager.json", root / "audit"
    initialize(config, workspace_id=WORKSPACE, control_root=control, store_root=audit, trusted_signers=signers)
    return config, control, key, audit / "audit.jsonl", git, signer


def test_signed_adoption_filters_and_replays_catalog_decisions(adoption):
    config, control, key, ledger, git, signer = adoption
    draft = {**_starter(), "workspace_id": WORKSPACE}
    assignment = next(rule for rule in draft["rules"] if rule["id"] == ASSIGNMENT)
    assignment["match"] = {"phase": "commissioning"}
    revision = _commit_policy(git, control, draft)
    context = {"member_id": "aegis", "worktree_id": "review-tree", "phase": "commissioning"}
    service = ManagerService(config, provenance={"transport": "test", "native_identity": None})
    genesis = ledger.read_bytes()
    assert service.status()["policy_approval"] == "draft"
    with pytest.raises(ManagerError, match="^policy_not_active$"):
        service.scan("delegation", context)
    candidate = service.candidate(revision)
    assert candidate["status"] == "awaiting_owner_approval"
    with pytest.raises(ManagerError, match="^approval_mismatch$"):
        service.activate(revision, None, {})
    assert ledger.read_bytes() == genesis

    git(control, "config", "--local", "gpg.ssh.program", str(control / "unavailable-signer"))
    approval = _approve(git, control, key, signer, candidate)
    result = service.activate(revision, None, approval)
    assert result["status"] == "activated"
    assert result["control_commit"] == revision
    active_bytes = ledger.read_bytes()
    with pytest.raises(ManagerError, match="^stale_activation$"):
        service.activate(revision, None, approval)
    assert ledger.read_bytes() == active_bytes

    assert service.scan("delegation", dict(context, phase="operation"))["rules"] == []
    unrelated = service.scan("ownership", context)["rules"]
    assert {rule["id"] for rule in unrelated} == {"reconcile-custody-transfers"}
    scan = service.scan("delegation", context)
    rule_revision = digest(assignment)
    assert scan["rules"] == [{**assignment, "revision": rule_revision}]
    assert scan["activation_ref"] == result["active_revision"]
    assert scan["provenance"]["transport"] == "test"
    args = (scan["decision_ref"], [ASSIGNMENT], "success", [], "assignment-receipt")
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.map(lambda _: ManagerService(config).report(*args), range(2), timeout=30)
    assert first == second == ManagerService(config).report(*args)
    assert first["rule_revisions"] == {ASSIGNMENT: rule_revision}
    assert first["acknowledgement"] == "recorded"
    assert first["fitness_credit"] == 0
    assert first["verified_completion"] is False
    assert service.status()["outcomes"] == 1
    recorded = ledger.read_bytes()
    with pytest.raises(ManagerError, match="^idempotency_conflict$"):
        service.report(scan["decision_ref"], [ASSIGNMENT], "failure", [], "assignment-receipt")
    assert ledger.read_bytes() == recorded


def test_malformed_catalog_commit_refuses_without_mutating_audit(adoption):
    config, control, _, ledger, git, _ = adoption
    draft = {**_starter(), "workspace_id": WORKSPACE}
    draft["rules"][0]["match"] = {"path": "fixture-only"}
    revision = _commit_policy(git, control, draft)
    service = ManagerService(config)
    before = ledger.read_bytes()
    for _ in range(2):
        with pytest.raises(ManagerError, match="^invalid_policy$"):
            service.candidate(revision)
        with pytest.raises(ManagerError, match="^invalid_policy$"):
            service.activate(revision, None, {})
    assert service.status()["policy_approval"] == "draft"
    assert ledger.read_bytes() == before


def _mined_proposal():
    return Proposal(id="reconcile-review-notes", source="mine", kind="review",
                    candidate_key="project:review:notes", evidence_ids=("review:example",),
                    target_paths=("notes/**",), status="proposal",
                    do="Reconcile open review notes against the revision being accepted.")


def test_reviewed_mined_proposal_can_be_adapted_to_the_same_policy_shape(tmp_path):
    store = make_store(tmp_path)
    proposal = _mined_proposal()
    store.write(proposal)
    store.decide([proposal.id], decision="accept", operation_id="fixture-review")
    assert store.state(proposal.id) == "accepted"
    reviewed = store.read(proposal.id).proposal
    # The adopter supplies management selectors and leaves repository metadata behind.
    rule = {"id": reviewed.id, "actions": ["evidence_review"], "match": {"role": "reviewer"}, "text": reviewed.do}
    draft = {**_starter(), "workspace_id": WORKSPACE}
    draft["rules"].append(rule)
    assert parse_policy(draft)["rules"][-1] == {**rule, "revision": digest(rule)}


def test_proposal_review_refuses_when_descriptor_confinement_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(proposal_store, "descriptor_supported", lambda: False)
    with pytest.raises(ProposalError, match="^proposal refused: unsupported$"):
        ProposalStore(tmp_path, home=tmp_path).write(_mined_proposal())
    assert not list(tmp_path.iterdir())
