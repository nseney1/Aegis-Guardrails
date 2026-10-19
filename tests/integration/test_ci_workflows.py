"""CI supply-chain hardening regression tests (v0.90).

Covers least-privilege tokens, SHA-pinned actions, Dependabot, dependency
auditing, build provenance attestations and PyPI Trusted Publishing (OIDC).
PyYAML parses the workflow key ``on`` as boolean ``True``; ``_triggers`` reads either spelling.
"""
import os
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
GITHUB = os.path.join(REPO_ROOT, ".github")
WORKFLOWS = os.path.join(GITHUB, "workflows")
WORKFLOW_FILES = ("validate.yml", "publish.yml")
SHA_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
PINNED_LINE = re.compile(r"uses:\s*[^@\s]+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$")


def _read(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return f.read()


def _load(name):
    return yaml.safe_load(_read(name))


def _uses(workflow):
    """Yield every ``uses:`` value (job-level reusable calls and step actions)."""
    for job in workflow["jobs"].values():
        if "uses" in job:
            yield job["uses"]
        for step in job.get("steps", []):
            if "uses" in step:
                yield step["uses"]


def _triggers(workflow):
    return workflow["on"] if "on" in workflow else workflow[True]


def _step_using(job, prefix):
    return [s for s in job.get("steps", []) if s.get("uses", "").startswith(prefix + "@")]


def test_top_level_permissions_are_read_only():
    for name in WORKFLOW_FILES:
        perms = _load(name).get("permissions")
        assert isinstance(perms, dict), f"{name}: top-level permissions must be an explicit map"
        assert perms.get("contents") == "read", f"{name}: top-level contents must be read"
        assert "write" not in perms.values(), f"{name}: top-level grants must not include write"


def test_every_action_is_pinned_to_a_full_commit_sha():
    for name in WORKFLOW_FILES:
        for ref in _uses(_load(name)):
            if ref.startswith("./"):
                continue  # local reusable workflow, versioned with this repo
            assert SHA_REF.match(ref), f"{name}: {ref} is not pinned to a 40-hex commit SHA"


def test_pinned_actions_carry_a_version_comment():
    for name in WORKFLOW_FILES:
        for line in _read(name).splitlines():
            stripped = line.strip().lstrip("- ")
            if not stripped.startswith("uses:") or "./" in stripped:
                continue
            assert PINNED_LINE.search(stripped), f"{name}: missing '# vX.Y.Z' comment: {line}"


def test_dependabot_updates_actions_and_pip_weekly():
    with open(os.path.join(GITHUB, "dependabot.yml"), encoding="utf-8") as f:
        config = yaml.safe_load(f)
    assert config["version"] == 2
    updates = {u["package-ecosystem"]: u for u in config["updates"]}
    for ecosystem in ("github-actions", "pip"):
        assert ecosystem in updates, f"dependabot must cover {ecosystem}"
        assert updates[ecosystem]["directory"] == "/"
        assert updates[ecosystem]["schedule"]["interval"] == "weekly"
        assert updates[ecosystem].get("target-branch") == "develop"


def test_validate_audits_dependencies_with_pip_audit():
    pairs = [(job, s) for job in _load("validate.yml")["jobs"].values()
             for s in job.get("steps", [])]
    runs = [s.get("run", "") for _, s in pairs]
    audit = [(job, s) for job, s in pairs
             if re.search(r"^\s*pip-audit\b", s.get("run", ""), re.MULTILINE)]
    assert audit, "validate.yml must run pip-audit"
    assert any("pip install pip-audit" in r for r in runs), "pip-audit is installed in CI only"
    for job, step in audit:
        assert "|| true" not in step["run"], "pip-audit findings must fail the job"
        assert not step.get("continue-on-error") and not job.get("continue-on-error")


def test_build_job_attests_provenance_with_minimal_permissions():
    build = _load("validate.yml")["jobs"]["build-wheel"]
    attest = _step_using(build, "actions/attest-build-provenance")
    assert attest, "build-wheel must attest build provenance"
    assert "dist/" in attest[0]["with"]["subject-path"]
    assert build.get("permissions") == {
        "contents": "read", "id-token": "write", "attestations": "write"}
    names = [s.get("name", "") for s in build["steps"]]
    record = next(i for i, s in enumerate(build["steps"])
                  if "verify_dist.py record" in s.get("run", ""))
    assert build["steps"].index(attest[0]) > record, f"attest after digests are recorded: {names}"


def test_publish_caller_grants_what_the_reusable_build_needs():
    """A reusable workflow can never exceed its caller's token grants."""
    caller = _load("publish.yml")["jobs"]["validate"]
    assert caller["uses"] == "./.github/workflows/validate.yml"
    perms = caller.get("permissions", {})
    assert perms.get("id-token") == "write" and perms.get("attestations") == "write"


def test_publish_uses_trusted_publishing_without_long_lived_tokens():
    publish = _load("publish.yml")["jobs"]["publish"]
    env = publish.get("environment")
    assert (env if isinstance(env, str) else (env or {}).get("name")) == "pypi"
    assert publish.get("permissions") in ({"contents": "read", "id-token": "write"}, {"contents": "write", "id-token": "write"})
    action = _step_using(publish, "pypa/gh-action-pypi-publish")
    assert action, "publish must use pypa/gh-action-pypi-publish"
    dumped = yaml.safe_dump(publish)
    assert "PYPI_API_TOKEN" not in dumped and "twine" not in dumped.lower()
    assert "PYPI_API_TOKEN" not in _read("publish.yml")


def test_publish_uploads_only_the_verified_files():
    """The action uploads every file in packages-dir; dist/ also holds SHA256SUMS."""
    publish = _load("publish.yml")["jobs"]["publish"]
    steps = publish["steps"]
    action = _step_using(publish, "pypa/gh-action-pypi-publish")[0]
    packages_dir = action["with"]["packages-dir"].rstrip("/")
    assert packages_dir not in ("dist", ""), "dist/ contains SHA256SUMS; stage verified files"
    verify = next(i for i, s in enumerate(steps) if "verify_dist.py verify dist" in s.get("run", ""))
    stage = next(i for i, s in enumerate(steps)
                 if "publish-files.txt" in s.get("run", "") and packages_dir in s.get("run", "")
                 and "verify_dist.py" not in s.get("run", ""))
    assert verify < stage < steps.index(action)


def test_checkouts_do_not_persist_credentials():
    """No job pushes, so GITHUB_TOKEN must not be left in .git/config."""
    for name in WORKFLOW_FILES:
        for job_name, job in _load(name)["jobs"].items():
            for step in _step_using(job, "actions/checkout"):
                assert (step.get("with") or {}).get("persist-credentials") is False, \
                    f"{name}:{job_name} checkout persists credentials"


def test_build_and_audit_tools_are_version_pinned():
    """Tools that touch release bytes or gate them are installed at exact versions."""
    text = _read("validate.yml")
    for tool in ("build", "pip-audit"):
        lines = [l for l in text.splitlines()
                 if re.search(rf"pip install\b.*\b{re.escape(tool)}\b", l)]
        assert lines, f"no pip install line for {tool}"
        for line in lines:
            assert re.search(rf"\b{re.escape(tool)}==\d+(\.\d+)+\b", line), line


# --- B3: the pytest suite runs on Windows -----------------------------------

def _windows_test_job():
    jobs = _load("validate.yml")["jobs"]
    assert "test-windows" in jobs, "validate.yml must run the pytest suite on Windows (B3)"
    return jobs["test-windows"]


def _pytest_steps(job):
    return [s for s in job.get("steps", [])
            if re.search(r"^\s*python -m pytest tests/?(\s|$)", s.get("run", ""), re.MULTILINE)]


def test_windows_test_job_runs_on_windows_latest():
    job = _windows_test_job()
    assert job["runs-on"] == "windows-latest"
    assert "3.12" in job["strategy"]["matrix"]["python-version"]


def test_windows_test_job_runs_the_whole_suite_and_fails_on_failure():
    job = _windows_test_job()
    steps = _pytest_steps(job)
    assert steps, "test-windows must run `python -m pytest tests/`"
    assert not job.get("continue-on-error"), "Windows failures must fail the job"
    for step in steps:
        assert not step.get("continue-on-error")
        assert "|| true" not in step["run"] and "--deselect" not in step["run"]


def test_windows_test_job_installs_like_the_linux_test_job():
    def install_run(job):
        return next(s["run"] for s in job["steps"] if s.get("name") == "Install test dependencies")
    jobs = _load("validate.yml")["jobs"]
    assert install_run(_windows_test_job()) == install_run(jobs["validate"])
    assert "build-wheel" in str(_windows_test_job().get("needs"))


def test_windows_test_job_isolates_home_and_userprofile():
    """BUG-010: tests must never touch the runner's real profile."""
    steps = _pytest_steps(_windows_test_job())
    assert steps
    for step in steps:
        env = step.get("env") or {}
        for var in ("HOME", "USERPROFILE"):
            assert "runner.temp" in str(env.get(var, "")), f"{var} must point under runner.temp"
        assert env["HOME"] == env["USERPROFILE"]


def test_windows_test_job_keeps_the_legacy_console_encoding():
    """PYTHONUTF8=0 keeps cp1252 stdio/locale defaults exercised (BUG-012, BUG-038)."""
    steps = _pytest_steps(_windows_test_job())
    assert steps
    for step in steps:
        assert str((step.get("env") or {}).get("PYTHONUTF8")) == "0"


def test_windows_test_job_actions_are_pinned_and_credentials_not_persisted():
    job = _windows_test_job()
    refs = [s["uses"] for s in job["steps"] if "uses" in s]
    assert refs and all(SHA_REF.match(r) for r in refs), refs
    checkouts = _step_using(job, "actions/checkout")
    assert checkouts, "test-windows must check out the repository"
    assert all((s.get("with") or {}).get("persist-credentials") is False for s in checkouts)


def test_windows_test_job_uses_bash_and_verifies_the_artifact():
    job = _windows_test_job()
    # `pip install dist/*.whl` relies on bash glob expansion (pwsh/cmd won't).
    assert job.get("defaults", {}).get("run", {}).get("shell") == "bash"
    runs = [s.get("run", "") for s in job["steps"]]
    assert any("verify_dist.py verify dist" in r for r in runs), \
        "test-windows must check the wheel digests before installing it"

def test_publish_workflow_isolates_release_assets():
    """Release assets upload from their own job, which alone needs contents: write."""
    jobs = _load("publish.yml")["jobs"]
    assets = jobs["release-assets"]
    assert assets.get("needs") == "publish"
    assert assets.get("permissions") == {"contents": "write"}
    upload = [s for s in assets["steps"] if "gh release upload" in s.get("run", "")]
    assert len(upload) == 1
    assert "RELEASE_TAG" in upload[0].get("env", {})
    assert "|| true" not in _read("publish.yml")


def test_publish_runs_only_on_a_published_release():
    """A dispatch runs the chosen ref's own copy of publish.yml, so no in-file guard binds it."""
    triggers = _triggers(_load("publish.yml"))
    assert set(triggers) == {"release"}
    assert triggers["release"] == {"types": ["published"]}
    # credit and ci_green count dispatch runs of validate.yml as CI.
    assert "workflow_dispatch" in _triggers(_load("validate.yml"))


def test_publish_guards_the_tag_before_any_build():
    wf = _load("publish.yml")
    assert wf.get("concurrency") == {"group": "publish-${{ github.ref }}", "cancel-in-progress": False}
    guard = wf["jobs"]["guard"]
    assert guard.get("permissions") == {"contents": "read"}
    runs = [s.get("run", "") for s in guard["steps"]]
    assert any("python3 .github/scripts/release_guard.py" in r for r in runs)
    needs = wf["jobs"]["validate"].get("needs")
    assert needs == "guard" or "guard" in needs


def test_publish_uploads_only_what_pypi_lacks_and_waits_for_it():
    """A re-run never changes or masks PyPI content: plan, upload the missing files, then wait."""
    publish = _load("publish.yml")["jobs"]["publish"]
    steps = publish["steps"]
    runs = [s.get("run", "") for s in steps]
    verify = next(i for i, r in enumerate(runs) if "verify_dist.py verify dist" in r)
    plan = next(i for i, r in enumerate(runs) if "pypi_state.py plan" in r)
    stage = next(i for i, r in enumerate(runs) if "publish-dist" in r and "publish-files.txt" in r)
    action = steps.index(_step_using(publish, "pypa/gh-action-pypi-publish")[0])
    wait = next(i for i, r in enumerate(runs) if "pypi_state.py wait" in r)
    assert verify < plan < stage < action < wait
    plan_id = steps[plan].get("id")
    assert plan_id
    for i in (stage, action):
        assert steps[i].get("if") == f"steps.{plan_id}.outputs.state != 'identical'"
    assert "skip-existing" not in yaml.safe_dump(publish)
