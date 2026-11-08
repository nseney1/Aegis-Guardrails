"""CI supply-chain hardening regression tests (v0.90).

Covers least-privilege tokens, SHA-pinned actions, Dependabot, dependency
auditing, build provenance attestations and PyPI Trusted Publishing (OIDC).
PyYAML parses the workflow key ``on`` as boolean ``True``; ``_triggers`` reads either spelling.
"""
import os
import re
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
GITHUB = os.path.join(REPO_ROOT, ".github")
WORKFLOWS = os.path.join(GITHUB, "workflows")
WORKFLOW_FILES = ("validate.yml", "publish.yml", "aegis-governance.yml", "wave-tests.yml")
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


FULL_VALIDATION = "github.event_name != 'pull_request' || github.base_ref != 'develop'"
WAVE_PR = "github.event_name == 'pull_request' && github.base_ref == 'develop'"


def test_wave_prs_keep_governance_while_full_validation_runs_on_develop_and_downstream():
    workflow = _load("validate.yml")
    triggers = _triggers(workflow)
    assert triggers["push"]["branches"] == ["main", "develop", "release/**"]
    assert triggers["pull_request"]["branches"] == ["main", "develop", "release/**"]
    assert {"workflow_call", "workflow_dispatch"} <= set(triggers)
    jobs = workflow["jobs"]
    for name in ("dependency-audit", "build-wheel", "native-compat", "validate", "test-windows"):
        assert jobs[name].get("if") == FULL_VALIDATION, name
    check = jobs["aegis-check"]
    assert check.get("if") == "always()"
    upstream = next(s for s in check["steps"] if s["name"] == "Verify upstream jobs succeeded")
    assert upstream["env"]["EXPECTED_RESULT"] == "${{ " + WAVE_PR + " && 'skipped' || 'success' }}"
    assert 'os.environ["EXPECTED_RESULT"]' in upstream["run"]
    # The required check must still reject a failed no-exec comparison on a wave PR.
    checks = _check_ci_steps(check)
    base = [s for s in checks if "--no-exec" in s["run"]]
    assert len(base) == 1 and "if" not in base[0]
    assert base[0]["run"] == "python3 -m aegis_cli.cli check --ci --no-exec"
    checkout = _step_using(check, "actions/checkout")[0]
    assert checkout["with"]["ref"] == "${{ " + WAVE_PR + " && github.event.pull_request.base.sha || github.sha }}"
    fetch = next(s for s in check["steps"] if s.get("name") == "Fetch wave pull request head as data")
    assert fetch.get("if") == WAVE_PR
    assert fetch["env"] == {"PR_NUMBER": "${{ github.event.pull_request.number }}"}
    assert fetch["run"] == 'git fetch --no-tags origin "+refs/pull/${PR_NUMBER}/head:refs/remotes/pull/head"'
    for step in check["steps"]:
        if step.get("uses", "").startswith(("actions/setup-python@", "actions/download-artifact@")) or any(
                text in step.get("run", "") for text in ("pip install", "verify_dist.py", "python3 -I")):
            assert step.get("if") == FULL_VALIDATION, step
    governance = _triggers(_load("aegis-governance.yml"))
    assert governance == {"pull_request_target": {"branches": ["main", "develop", "release/**"]}}


def test_wave_tests_run_pull_requests_into_develop_without_secrets():
    """Owner decision 2026-11-05: execute tests on wave PRs, with nothing to leak."""
    workflow = _load("wave-tests.yml")
    assert _triggers(workflow) == {"pull_request": {"branches": ["develop"]}}
    assert workflow["permissions"] == {"contents": "read"}
    text = _read("wave-tests.yml")
    for forbidden in ("${{ secrets", "github.token", "GH_TOKEN", "pull_request_target", "id-token",
                      "actions/cache", "upload-artifact"):
        assert forbidden not in text, forbidden
    for job in workflow["jobs"].values():
        assert "permissions" not in job, "jobs inherit the read-only token"
        for checkout in _step_using(job, "actions/checkout"):
            assert checkout["with"]["persist-credentials"] is False
        for setup in _step_using(job, "actions/setup-python"):
            assert "cache" not in setup.get("with", {}), "no cache a pull request could poison"
    # PRs into main and release/** keep the full Validate run; wave PRs keep its
    # base-sourced required check (see the test above).
    assert "main" not in _triggers(workflow)["pull_request"]["branches"]


@pytest.mark.parametrize("expected,actual,passed", [
    ("skipped", "skipped", True), ("success", "success", True),
    ("skipped", "success", False), ("success", "skipped", False),
    ("success", "failure", False), ("skipped", "cancelled", False),
])
def test_required_check_rejects_unexpected_upstream_results(expected, actual, passed):
    proc = _run_upstream_gate(expected, {"build-wheel": {"result": actual}, FAST_JOB: {"result": "success"},
                                         "native-compat": {"result": expected}})
    assert (proc.returncode == 0) is passed, proc.stderr
    if not passed:
        assert "build-wheel" in proc.stderr and "Unexpected upstream job results" in proc.stderr


FAST_JOB = "test-fast"


def _run_upstream_gate(expected, needs):
    step = _load("validate.yml")["jobs"]["aegis-check"]["steps"][0]
    argv = shlex.split(step["run"])
    fixed = {k: v for k, v in step.get("env", {}).items() if "${{" not in str(v)}
    env = dict(os.environ, **fixed, EXPECTED_RESULT=expected, NEEDS_JSON=json.dumps(needs))
    return subprocess.run([sys.executable, *argv[1:]], env=env, capture_output=True, text=True, timeout=10)


# A wave PR skips the full matrix but must still pass the fast leg; every other run needs both.
@pytest.mark.parametrize("expected,fast,passed", [
    ("skipped", "success", True), ("success", "success", True),
    ("skipped", "skipped", False), ("skipped", "failure", False), ("skipped", "cancelled", False),
    ("success", "failure", False), ("skipped", None, False),
])
def test_required_check_needs_the_fast_leg_to_succeed_on_every_run(expected, fast, passed):
    needs = {"build-wheel": {"result": expected}, "native-compat": {"result": expected}}
    if fast is not None:
        needs[FAST_JOB] = {"result": fast}
    proc = _run_upstream_gate(expected, needs)
    assert (proc.returncode == 0) is passed, proc.stderr
    if not passed:
        assert FAST_JOB in proc.stderr and "Unexpected upstream job results" in proc.stderr


def _fast_job():
    return _load("validate.yml")["jobs"][FAST_JOB]


def _runs(job):
    return [s.get("run", "") for s in job.get("steps", [])]


def _index(job, *needles):
    found = [i for i, run in enumerate(_runs(job)) if all(n in run for n in needles)]
    assert len(found) == 1, (needles, found)
    return found[0]


def _packages(run):
    return sorted(word for word in run.split() if "==" in word)


def test_wave_prs_run_the_fast_linux_leg_with_a_read_only_token_and_no_secrets():
    workflow = _load("validate.yml")
    assert "pull_request_target" not in _triggers(workflow)
    job = workflow["jobs"][FAST_JOB]
    # No `if` and no `needs`: build-wheel and dependency-audit skip on wave PRs, and the verdict
    # needs this job to succeed on push and dispatch too.
    assert "if" not in job and "needs" not in job
    assert job["runs-on"] == "ubuntu-latest"
    assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}
    assert isinstance(job.get("timeout-minutes"), int) and job["timeout-minutes"] <= 60
    text = yaml.safe_dump(job)
    # Any spelling of a secret or the workflow token: secrets.X, secrets['X'], toJSON(secrets),
    # github.token, github['token'].
    assert not re.search(r"\bsecrets\b|github\s*(\.|\[)\s*'?token|GH_TOKEN", text), text
    assert not {"environment", "container", "services"} & set(job)
    assert [s["with"]["python-version"] for s in _step_using(job, "actions/setup-python")] == ["3.11"]
    checkout = _step_using(job, "actions/checkout")
    assert len(checkout) == 1 and checkout[0]["with"] == {"fetch-depth": 0, "persist-credentials": False}
    for step in job["steps"]:
        assert not step.get("continue-on-error") and "if" not in step, step
        assert "|| true" not in step.get("run", ""), step
    assert FAST_JOB in workflow["jobs"]["aegis-check"]["needs"]


def test_the_fast_leg_runs_the_whole_suite_with_xdist_from_its_own_venv():
    job = _fast_job()
    # The runner context is not available to job-level env, so a step exports the venv path.
    export = _index(job, 'echo "VENV=$RUNNER_TEMP/ci-venv" >> "$GITHUB_ENV"')
    venv = _index(job, 'python -m venv "$VENV"')
    assert export < venv
    install = _index(job, '"$VENV/bin/pip" install pytest==')
    package = _index(job, '"$VENV/bin/pip" install .')
    lint = _index(job, 'make lint PYTHON="$VENV/bin/python"')
    suite = _index(job, 'make test PYTHON="$VENV/bin/python"')
    assert venv < install < package < lint < suite
    validate_install = next(s["run"] for s in _load("validate.yml")["jobs"]["validate"]["steps"]
                            if s.get("name") == INSTALL_STEP)
    packages = _packages(_runs(job)[install])
    assert packages == _packages(validate_install.splitlines()[0]) and "pytest-xdist==3.6.1" in packages
    assert _runs(job)[suite].strip() == 'make test PYTHON="$VENV/bin/python"'
    for flag in ("--deselect", " -k ", " -m ", "--ignore"):
        assert flag not in _runs(job)[suite]
    assert _index(job, "grep -rnI '/home/'") > package


def _bubblewrap_probe():
    from tests.integration.test_hierarchy_jobs import BUBBLEWRAP_PROBE
    return shlex.join(BUBBLEWRAP_PROBE)


@pytest.mark.parametrize("name", [FAST_JOB, "validate"])
def test_linux_legs_install_bubblewrap_and_prove_it_runs_before_the_suite(name):
    job = _load("validate.yml")["jobs"][name]
    install = _index(job, "apt-get", "install -y --no-install-recommends bubblewrap")
    # A transient mirror error must not fail a wave PR's required check.
    assert _runs(job)[install].count("-o Acquire::Retries=3") == 2
    probe = _index(job, _bubblewrap_probe())
    suite = _index(job, "make test")
    assert install < probe < suite
    steps = job["steps"]
    # Ubuntu 23.10 and later block unprivileged user namespaces through AppArmor; without
    # lifting that, the probe fails and the eight bubblewrap job tests would skip silently.
    assert "kernel.apparmor_restrict_unprivileged_userns=0" in steps[probe]["run"]
    if name == "validate":
        assert steps[install].get("if") == steps[probe].get("if") == "runner.os == 'Linux'"
    assert not steps[probe].get("continue-on-error") and "|| true" not in steps[probe]["run"]


def test_the_full_matrix_also_runs_nightly_and_on_dispatch():
    triggers = _triggers(_load("validate.yml"))
    assert "workflow_dispatch" in triggers
    assert len(triggers["schedule"]) == 1 and len(triggers["schedule"][0]["cron"].split()) == 5


def test_wave_governance_cannot_be_skipped_while_keeping_the_required_check():
    from aegis_core import human_gate
    body = _read("validate.yml")
    weakened = body.replace("      - name: Run CI governance without execution\n",
                            "      - name: Run CI governance without execution\n        if: false\n")
    assert weakened != body
    assert human_gate.aegis_check_jobs(weakened) == []


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


def test_publish_caller_can_grant_every_reusable_validation_job_permission():
    """GitHub rejects a callee requesting more than its caller grants."""
    workflow = _load("validate.yml")
    caller = _load("publish.yml")["jobs"]["validate"]["permissions"]
    levels = {"none": 0, "read": 1, "write": 2}
    missing = []
    for name, job in workflow["jobs"].items():
        for permission, access in job.get("permissions", workflow["permissions"]).items():
            if levels[caller.get(permission, "none")] < levels[access]:
                missing.append(f"{name}: {permission}: {access}")
    assert missing == [], f"publish.yml cannot grant validate.yml: {missing}"


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


# The jobs that run the suite: the matrix, Windows, and aegis-check, whose `check --ci` reruns the
# head commit's trailer snapshot and must be able to collect what the others collect (R-trust-a3).
TEST_JOBS = ("validate", "test-windows", "aegis-check", "native-compat")
INSTALL_STEP = "Install test dependencies"


def _install_step(job):
    return next((s for s in job.get("steps", []) if s.get("name") == INSTALL_STEP), None)


def _divergent_installs(jobs):
    """Test jobs whose install step is missing or differs from the validate job's text."""
    want = (_install_step(jobs["validate"]) or {}).get("run")
    return [name for name in TEST_JOBS if want is None or (_install_step(jobs[name]) or {}).get("run") != want]


def test_the_test_jobs_install_identical_test_dependencies():
    assert _divergent_installs(_load("validate.yml")["jobs"]) == []
    assert "build-wheel" in str(_windows_test_job().get("needs"))


def test_a_package_dropped_from_one_install_copy_fails_the_comparison():
    jobs = _load("validate.yml")["jobs"]
    step = _install_step(jobs["aegis-check"])
    assert step is not None and " hypothesis==" in step["run"]
    step["run"] = step["run"].replace(" hypothesis==6.126.0", "")
    assert _divergent_installs(jobs) == ["aegis-check"]


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


# --- R-cli-12: CI hygiene ----------------------------------------------------

def _jobs_without_timeout(workflow):
    """Jobs that run steps and lack an integer timeout-minutes within GitHub's 360 cap. A job that
    calls a reusable workflow (`uses:`) cannot carry the key; the called jobs carry theirs."""
    return [name for name, job in workflow["jobs"].items() if "uses" not in job
            and not (type(job.get("timeout-minutes")) is int and 0 < job["timeout-minutes"] <= 360)]


def test_every_job_that_runs_steps_has_a_bounded_timeout():
    for name in WORKFLOW_FILES:
        assert _jobs_without_timeout(_load(name)) == [], name
    jobs = _load("validate.yml")["jobs"]
    # A limit must never turn a slow green run red on release day.
    assert jobs["validate"]["timeout-minutes"] >= 45 and jobs["test-windows"]["timeout-minutes"] >= 45


def test_a_job_without_a_usable_timeout_is_reported():
    workflow = {"jobs": {"a": {"runs-on": "x", "timeout-minutes": 10}, "b": {"runs-on": "x"},
                         "c": {"uses": "./w.yml"}, "d": {"timeout-minutes": "10"}, "e": {"timeout-minutes": 400}}}
    assert _jobs_without_timeout(workflow) == ["b", "d", "e"]


def test_pytest_dumps_the_stacks_of_a_hung_test():
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), encoding="utf-8") as f:
        text = f.read()  # Python 3.9 has no tomllib
    block = re.search(r"^\[tool\.pytest\.ini_options\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
    assert block and re.search(r"^faulthandler_timeout\s*=\s*300\s*$", block.group(1), re.M)


def test_one_red_validate_leg_does_not_cancel_the_others():
    assert _load("validate.yml")["jobs"]["validate"]["strategy"]["fail-fast"] is False


def test_windows_runs_the_same_wheel_smoke_as_the_other_legs():
    runs = [s.get("run", "") for s in _windows_test_job()["steps"]]
    smoke = [r for r in runs if "wheel_smoke.py" in r]
    assert len(smoke) == 1
    assert re.search(r'cd "\$RUNNER_TEMP" && env -u PYTHONPATH python -I "\$SMOKE"', smoke[0]), smoke[0]
    assert not any(re.search(r"python -c .*import aegis_cli", r) for r in runs), "the import-only smoke is gone"


def test_aegis_check_runs_the_installed_wheel_and_is_the_only_check_ci():
    jobs = _load("validate.yml")["jobs"]
    cli = [s["run"].strip() for s in jobs["aegis-check"]["steps"]
           if "aegis_cli.cli" in s.get("run", "") and "--no-exec" not in s["run"]]
    # -I keeps the checkout off sys.path, so the wheel, not the source tree, is what runs.
    assert cli == ["python3 -I -m aegis_cli.cli check", "python3 -I -m aegis_cli.cli check --ci"]
    with_ci = [name for name, job in jobs.items()
               if any(re.search(r"aegis_cli\.cli check --ci\b", s.get("run", "")) for s in job.get("steps", []))]
    assert with_ci == ["aegis-check"]


# --- R-trust-43: at tier A check --ci reads the pull request's reviews ------------------------

def _check_ci_steps(job):
    return [s for s in job.get("steps", []) if re.search(r"\bcheck --ci\b", s.get("run", ""))]


def _scaffold():
    from aegis_core import scaffolding
    return yaml.safe_load(scaffolding.ci_workflow())


@pytest.mark.parametrize("load", [lambda: _load("validate.yml"), _scaffold], ids=["validate", "scaffold"])
def test_the_check_ci_job_can_read_reviews_with_a_read_only_token(load):
    job = load()["jobs"]["aegis-check"]
    assert job.get("permissions") == {"contents": "read", "pull-requests": "read"}
    steps = _check_ci_steps(job)
    assert steps
    assert all(s.get("env") == {"GH_TOKEN": "${{ github.token }}"} for s in steps)


# --- R-trust-13 (c)-(f): a base-sourced, no-exec governance check ----------------------------

GOVERNANCE_WORKFLOW = "aegis-governance.yml"
_BASE_SHA = "${{ github.event.pull_request.base.sha }}"


def _permission_maps(workflow):
    yield workflow.get("permissions")
    for job in workflow["jobs"].values():
        if "permissions" in job:
            yield job["permissions"]


def test_the_governance_job_is_an_aegis_check_triggered_only_by_pull_request_target():
    """N3: the base-sourced job counts as the required Aegis check under its literal name."""
    from aegis_core import human_gate
    text = _read(GOVERNANCE_WORKFLOW)
    assert set(_triggers(yaml.safe_load(text))) == {"pull_request_target"}
    assert human_gate.aegis_check_jobs(text) == ["aegis-governance"]


def test_the_governance_workflow_never_checks_out_or_runs_pull_request_code():
    """N4 (static): base.sha checkout without credentials, the head only as data, a read-only token
    (contents and pull-requests, the latter for tier A's review lookup) handed as GH_TOKEN to the check
    step only, no secret, nothing that builds, installs, caches or tests the checkout."""
    text = _read(GOVERNANCE_WORKFLOW)
    workflow = yaml.safe_load(text)
    assert set(_triggers(workflow)) == {"pull_request_target"}
    assert workflow.get("permissions") == {"contents": "read", "pull-requests": "read"}
    for perms in _permission_maps(workflow):
        assert isinstance(perms, dict), "permissions must be explicit maps"
        assert set(perms.items()) <= {("contents", "read"), ("pull-requests", "read")}, perms
    assert "secrets." not in text
    assert "env" not in workflow and all("env" not in job for job in workflow["jobs"].values())
    steps = [s for job in workflow["jobs"].values() for s in job.get("steps", [])]
    (check_step,) = [s for s in steps if re.search(r"\bcheck --ci\b", s.get("run", ""))]
    assert check_step.get("env") == {"GH_TOKEN": "${{ github.token }}"}
    assert [s for s in steps if re.search(r"GH_TOKEN|GITHUB_TOKEN|github\.token", str(s.get("env") or ""))] == [check_step]
    assert text.count("github.token") == 1
    checkouts = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert checkouts and all((s.get("with") or {}).get("ref") == _BASE_SHA for s in checkouts)
    assert all((s.get("with") or {}).get("persist-credentials") is False for s in checkouts)
    for step in steps:
        with_ = step.get("with") or {}
        for value in (with_.get("ref"), with_.get("repository"), step.get("run")):
            assert "github.event.pull_request.head" not in str(value or ""), step
        run = step.get("run", "")
        assert not re.search(r"\bmake\b|pytest|pip3? install|python3? -m pip|setup\.py", run), step
        assert not step.get("uses", "").startswith("actions/cache"), step
    runs = [s.get("run", "") for s in steps]
    assert any(re.fullmatch(r"python3 -m aegis_cli\.cli check --ci --no-exec", r.strip()) for r in runs), runs


# --- R-trust-17: check --ci runs on every event its job runs on ------------------------------
# A condition on the step (say, pull requests only) would let a push or dispatch run of the same
# job name pass on the pull request's head commit without comparing anything, and doctor no longer
# counts such a job as the required Aegis check (human_gate._skip_why). A run with nothing to compare
# says so instead of PASSED (aegis_cli.check).

@pytest.mark.parametrize("text", [lambda: _read("validate.yml"),
                                  lambda: __import__("aegis_core.scaffolding", fromlist=["x"]).ci_workflow()],
                         ids=["validate", "scaffold"])
def test_the_check_ci_step_has_no_condition_and_stays_the_required_check(text):
    from aegis_core import human_gate
    body = text()
    steps = _check_ci_steps(yaml.safe_load(body)["jobs"]["aegis-check"])
    assert any("if" not in step for step in steps)
    assert all("continue-on-error" not in step for step in steps)
    assert human_gate.aegis_check_jobs(body) == ["aegis-check"]


COMPAT_JOB = "native-compat"
COMPAT_STEP = "Run exactly two native compatibility cases"
COMPAT_CASES = {
    "macos-latest": (
        "tests.integration.test_hierarchy_fresh_brief",
        ("test_valid_large_settled_lifecycle_record_uses_the_lifecycle_reader_limit",
         "test_directory_eacces_is_a_permission_refusal")),
    "ubuntu-24.04": (
        "tests.integration.test_hierarchy_team_homes",
        ("test_round4_root_competing_after_logins_final_reload_keeps_both_bindings[False]",
         "test_round4_root_competing_after_logins_final_reload_keeps_both_bindings[True]")),
}


def _compat_job():
    jobs = _load("validate.yml")["jobs"]
    assert COMPAT_JOB in jobs, "full native jobs need the early compatibility gate"
    return jobs[COMPAT_JOB]


def _compat_step():
    return next(s for s in _compat_job()["steps"] if s.get("name") == COMPAT_STEP)


def _assert_compat_edges(jobs):
    assert jobs[COMPAT_JOB]["needs"] == "build-wheel"
    assert jobs["validate"]["needs"] == ["build-wheel", "dependency-audit", COMPAT_JOB]
    assert jobs["test-windows"]["needs"] == ["build-wheel", COMPAT_JOB]
    for name in ("aegis-check", "verdict"):
        assert COMPAT_JOB in jobs[name]["needs"], name
    for name in ("validate", "test-windows", COMPAT_JOB):
        assert jobs[name]["if"] == FULL_VALIDATION, name


def test_native_compatibility_precedes_both_full_families_and_the_verdict():
    jobs = _load("validate.yml")["jobs"]
    _assert_compat_edges(jobs)
    job = _compat_job()
    assert job["runs-on"] == "${{ matrix.os }}"
    assert job["strategy"] == {"fail-fast": False,
                                "matrix": {"os": ["macos-latest", "ubuntu-24.04"]}}
    assert job["timeout-minutes"] == 15  # Operational ceiling, not a performance assertion.
    assert [s["with"]["python-version"] for s in _step_using(job, "actions/setup-python")] == ["3.9"]
    assert jobs["validate"]["timeout-minutes"] == 300
    assert jobs["validate"]["strategy"]["matrix"] == {
        "os": ["ubuntu-latest", "macos-latest"], "python-version": ["3.9", "3.11"],
        "exclude": [{"os": "ubuntu-latest", "python-version": "3.9"}],
        "include": [{"os": "ubuntu-24.04", "python-version": "3.9"}]}
    assert jobs["test-windows"]["timeout-minutes"] == 90
    assert jobs["test-windows"]["strategy"]["matrix"] == {"python-version": ["3.9", "3.12"]}


@pytest.mark.parametrize("name", ["validate", "test-windows", "aegis-check", "verdict"])
def test_removing_a_compat_dependency_edge_is_rejected(name):
    jobs = _load("validate.yml")["jobs"]
    jobs[name]["needs"] = [n for n in jobs[name]["needs"] if n != COMPAT_JOB]
    with pytest.raises(AssertionError):
        _assert_compat_edges(jobs)


def test_native_compat_reuses_verified_artifacts_and_read_only_source_identity():
    job = _compat_job()
    assert job.get("permissions", _load("validate.yml")["permissions"]) == {"contents": "read"}
    assert job.get("defaults", {}).get("run", {}).get("shell") == "bash"
    checkout, = _step_using(job, "actions/checkout")
    assert checkout["with"] == {"ref": "${{ github.sha }}", "fetch-depth": 0, "persist-credentials": False}
    download, = _step_using(job, "actions/download-artifact")
    assert download["with"] == {"name": "aegis-wheel", "path": "dist/"}
    for prefix in ("actions/checkout", "actions/setup-python", "actions/download-artifact"):
        assert _step_using(job, prefix)[0]["uses"] == _step_using(
            _load("validate.yml")["jobs"]["validate"], prefix)[0]["uses"]
    assert len([s for s in job["steps"] if "uses" in s]) == 3
    assert job["steps"].index(download) < _index(job, "verify_dist.py verify dist") < _index(job, "pip install dist/*.whl")
    identity = _runs(job)[_index(job, "git rev-parse HEAD", "HEAD^{tree}")]
    assert '"$GITHUB_SHA"' in identity and "exit 1" in identity
    text = yaml.safe_dump(job)
    assert not re.search(r"\bsecrets\b|github\s*(\.|\[)\s*'?token|GH_TOKEN|actions/cache|upload-artifact", text)
    for step in job["steps"]:
        assert not step.get("continue-on-error") and "|| true" not in step.get("run", "")
        assert step.get("if") in (None, "runner.os == 'Linux'")
    env = _compat_step()["env"]
    assert env["HOME"] == env["USERPROFILE"] and "runner.temp" in env["HOME"]
    assert "runner.temp" in env["XDG_CONFIG_HOME"] and str(env["PYTHONDONTWRITEBYTECODE"]) == "1"
    assert 'mkdir "$HOME"\nmkdir "$XDG_CONFIG_HOME"' in _compat_step()["run"]


@pytest.mark.parametrize("matching", [True, False])
def test_actual_compat_identity_command_refuses_a_different_checkout(tmp_path, bash, matching):
    env = _diagnostic_env(tmp_path)
    observed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, env=env,
                              capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    env["GITHUB_SHA"] = observed if matching else "0" * 40
    command = _runs(_compat_job())[_index(_compat_job(), "git rev-parse HEAD", "HEAD^{tree}")]
    proc = subprocess.run([bash, "-c", command], cwd=REPO_ROOT, env=env,
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == (0 if matching else 1), proc.stdout + proc.stderr
    if matching:
        assert re.fullmatch(rf"native-compat commit={observed} tree=[0-9a-f]{{40}}\n", proc.stdout)
    else:
        assert proc.stderr.strip() == "Unexpected checkout commit" and proc.stdout == ""


def test_native_compat_linux_proves_bubblewrap_before_targeted_pytest():
    job = _compat_job()
    install = _index(job, "apt-get", "install -y --no-install-recommends bubblewrap")
    probe = _index(job, _bubblewrap_probe())
    assert install < probe < job["steps"].index(_compat_step())
    assert _runs(job)[install] == "sudo apt-get update && sudo apt-get install -y --no-install-recommends bubblewrap"
    for index in (install, probe):
        assert job["steps"][index]["if"] == "runner.os == 'Linux'"
    assert "kernel.apparmor_restrict_unprivileged_userns=0" in _runs(job)[probe]


def test_dropping_a_dependency_from_the_compat_copy_is_rejected():
    jobs = _load("validate.yml")["jobs"]
    step = _install_step(jobs[COMPAT_JOB])
    assert step is not None and " hypothesis==" in step["run"]
    step["run"] = step["run"].replace(" hypothesis==6.126.0", "")
    assert _divergent_installs(jobs) == [COMPAT_JOB]


@pytest.mark.parametrize("expected,result,passed", [
    ("success", "success", True), ("skipped", "skipped", True),
    ("success", "failure", False), ("success", "cancelled", False),
    ("success", "skipped", False), ("skipped", "success", False),
    ("skipped", "failure", False), ("skipped", "cancelled", False),
    ("success", None, False), ("skipped", None, False),
    ("success", "missing-result", False), ("skipped", "missing-result", False),
])
def test_required_check_requires_a_compat_result_even_when_skips_are_expected(expected, result, passed):
    needs = {"build-wheel": {"result": expected}, FAST_JOB: {"result": "success"}}
    if result is not None:
        needs[COMPAT_JOB] = {} if result == "missing-result" else {"result": result}
    proc = _run_upstream_gate(expected, needs)
    assert (proc.returncode == 0) is passed, proc.stderr
    if not passed:
        assert COMPAT_JOB in proc.stderr and "Unexpected upstream job results" in proc.stderr


def _embedded_python(run):
    match = re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", run, re.DOTALL)
    assert match, "the workflow must contain the public inline Python validator"
    return match[1]


def _diagnostic_env(root):
    home = root / "private-home"
    home.mkdir(exist_ok=True)
    assert not home.is_symlink()
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "USERPROFILE": str(home),
           "XDG_CONFIG_HOME": str(home / "config"), "PYTHONDONTWRITEBYTECODE": "1"}
    # Preserve this interpreter's installed test dependencies when HOME changes,
    # without putting the checkout or its conftest on the model subprocess path.
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path
                                      if p.endswith(("site-packages", "dist-packages")))
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


@pytest.mark.parametrize("result,passed", [("success", True), (None, False), ("missing-result", False),
                                         ("skipped", False), ("failure", False), ("cancelled", False)])
def test_actual_verdict_predicate_requires_successful_compat(tmp_path, result, passed):
    job = _load("validate.yml")["jobs"]["verdict"]
    step = next(s for s in job["steps"] if "predicate.json" in s.get("run", ""))
    needs = {"aegis-check": {"result": "success"}, FAST_JOB: {"result": "success"}}
    if result is not None:
        needs[COMPAT_JOB] = {} if result == "missing-result" else {"result": result}
    env = dict(_diagnostic_env(tmp_path), NEEDS=json.dumps(needs), GITHUB_SHA="a" * 40,
               GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
    proc = subprocess.run([sys.executable, "-c", _embedded_python(step["run"]), "b" * 40],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert (proc.returncode == 0) is passed, proc.stderr
    if passed:
        assert json.loads(proc.stdout)["jobs"][COMPAT_JOB] == "success"
    else:
        assert "Traceback" in proc.stderr


@pytest.mark.parametrize("gate", ["upstream", "verdict"])
def test_missing_compat_negative_control_detects_a_deleted_presence_guard(tmp_path, gate):
    needs = {"build-wheel": {"result": "success"}, FAST_JOB: {"result": "success"}}
    env = dict(_diagnostic_env(tmp_path), GITHUB_SHA="a" * 40, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
    if gate == "upstream":
        step = _load("validate.yml")["jobs"]["aegis-check"]["steps"][0]
        body = shlex.split(step["run"])[2]
        mutant = body.replace("always + required", "always")
        env.update(NEEDS_JSON=json.dumps(needs), EXPECTED_RESULT="success", ALWAYS_SUCCESS=FAST_JOB,
                   REQUIRED_JOBS=COMPAT_JOB)
    else:
        job = _load("validate.yml")["jobs"]["verdict"]
        step = next(s for s in job["steps"] if "predicate.json" in s.get("run", ""))
        body = _embedded_python(step["run"])
        mutant = body.replace('"native-compat" in needs and ', "")
        env["NEEDS"] = json.dumps(needs)
    assert mutant != body
    for command, code in ((body, 1), (mutant, 0)):
        proc = subprocess.run([sys.executable, "-c", command, "b" * 40], cwd=tmp_path, env=env,
                              capture_output=True, text=True, timeout=10)
        assert proc.returncode == code, proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def compat_reports(tmp_path_factory):
    """Public pytest reports from model cases; these do not qualify the native fixtures."""
    reports = {}
    for os_name in COMPAT_CASES:
        root = tmp_path_factory.mktemp("compat-report")
        module, config = _compat_model(root, os_name)
        report = root / "results.xml"
        proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-c", str(config),
                               "--confcutdir", str(root), "--rootdir", str(root),
                               "--junitxml", str(report), str(module)], cwd=root, env=_diagnostic_env(root),
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        reports[os_name] = report.read_bytes()
    return reports


def _compat_model(root, os_name):
    classname, names = COMPAT_CASES[os_name]
    module = root / (classname.replace(".", "/") + ".py")
    module.parent.mkdir(parents=True)
    if os_name == "ubuntu-24.04":
        source = ("import pytest\n@pytest.mark.parametrize('fail_login_save', [False, True])\n"
                  f"def {names[0].split('[')[0]}(fail_login_save):\n    assert isinstance(fail_login_save, bool)\n")
    else:
        source = "\n".join(f"def {name}():\n    assert True\n" for name in names)
    module.write_text(source, encoding="utf-8")
    config = root / "pytest.ini"
    config.write_text("[pytest]\njunit_family=xunit2\n", encoding="utf-8")
    return module, config


def _run_compat_report(root, report, os_name):
    return subprocess.run([sys.executable, "-c", _embedded_python(_compat_step()["run"]),
                           str(report), os_name], cwd=root, env=_diagnostic_env(root),
                          capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize("os_name", COMPAT_CASES)
def test_actual_compat_validator_accepts_two_public_pytest_cases(tmp_path, compat_reports, os_name):
    report = tmp_path / "report.xml"
    report.write_bytes(compat_reports[os_name])
    proc = _run_compat_report(tmp_path, report, os_name)
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    classname, names = COMPAT_CASES[os_name]
    assert summary == {"tests": 2, "failures": 0, "errors": 0, "skipped": 0,
                       "cases": [[classname, name] for name in sorted(names)]}


@pytest.mark.parametrize("mutation,reason", [
    ("wrong-name", "case identities"), ("wrong-class", "case identities"),
    ("missing-case", "case identities"), ("extra-case", "case identities"),
    ("duplicate-case", "case identities"), ("skipped", "testcase outcome"),
    ("failure", "testcase outcome"), ("error", "testcase outcome"),
    ("xfail", "testcase outcome"), ("forged-tests", "suite counters"),
    ("missing-counter", "suite counters"), ("negative-counter", "suite counters"),
    ("forged-failures", "suite counters"), ("forged-root", "suite counters"),
    ("malformed", "malformed XML"), ("dtd", "DTD/entity"), ("entity", "DTD/entity"),
    ("oversized", "size limit"), ("missing", "report unavailable"),
    ("directory", "regular file"), ("unknown-os", "unknown compatibility leg"),
])
def test_actual_compat_validator_refuses_unqualified_reports(tmp_path, compat_reports, mutation, reason):
    import copy
    import xml.etree.ElementTree as ET

    report = tmp_path / "report.xml"
    root = ET.fromstring(compat_reports["macos-latest"])
    suite = root.find("testsuite")
    cases = suite.findall("testcase")
    if mutation == "wrong-name":
        cases[0].set("name", "unexpected")
    elif mutation == "wrong-class":
        cases[0].set("classname", "unexpected")
    elif mutation == "missing-case":
        suite.remove(cases[0])
    elif mutation == "extra-case":
        suite.append(copy.deepcopy(cases[0]))
    elif mutation == "duplicate-case":
        cases[1].set("name", cases[0].get("name"))
    elif mutation in ("skipped", "failure", "error", "xfail"):
        ET.SubElement(cases[0], "skipped" if mutation == "xfail" else mutation,
                      {"type": "pytest.xfail"} if mutation == "xfail" else {})
    elif mutation == "forged-tests":
        suite.set("tests", "0")
    elif mutation == "missing-counter":
        del suite.attrib["skipped"]
    elif mutation == "negative-counter":
        suite.set("errors", "-1")
    elif mutation == "forged-failures":
        suite.set("failures", "1")
    elif mutation == "forged-root":
        root.attrib.update(tests="0", failures="0", errors="0", skipped="0")
    data = ET.tostring(root)
    if mutation == "malformed":
        data = b"<testsuites>"
    elif mutation in ("dtd", "entity"):
        data = (b'<!DOCTYPE testsuites []>' if mutation == "dtd" else b'<!ENTITY x "value">') + data
    elif mutation == "oversized":
        data = b" " * (1024 * 1024 + 1)
    if mutation == "directory":
        report.mkdir()
    elif mutation != "missing":
        report.write_bytes(data)
    proc = _run_compat_report(tmp_path, report, "other" if mutation == "unknown-os" else "macos-latest")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "native-compat:" in proc.stderr and reason in proc.stderr


def test_native_compat_invokes_only_the_exact_platform_selectors():
    run = _compat_step()["run"]
    assert run.startswith("set -euo pipefail\n")
    assert 'case "$COMPAT_OS" in' in run and "exit 1" in run
    invocation = 'python - "$REPORT" "${cases[@]}" <<\'PYTEST\''
    assert run.count(invocation) == 1
    runner = run.split("<<'PYTEST'\n", 1)[1].split("\nPYTEST", 1)[0]
    assert 'args = ["-q", "-o", "junit_family=xunit2", "-o", "xfail_strict=true",' in runner
    assert '"--junitxml=" + sys.argv[1], *sys.argv[2:]]' in runner
    assert 'guard = RequireUnmarkedCompatibilityCases()' in runner
    assert 'pytest.main(args, plugins=[guard])' in runner
    assert "tryfirst" not in runner and "trylast" not in runner
    assert run.index(invocation) < run.index("<<'PY'")
    mac = run.split("macos-latest)", 1)[1].split(";;", 1)[0]
    linux = run.split("ubuntu-24.04)", 1)[1].split(";;", 1)[0]
    for os_name, block in (("macos-latest", mac), ("ubuntu-24.04", linux)):
        classname, names = COMPAT_CASES[os_name]
        module = classname.replace(".", "/") + ".py"
        selectors = [f"{module}::{name.split('[')[0]}" for name in names]
        actual = re.findall(r"tests/integration/[^\s)]+", block)
        assert actual == list(dict.fromkeys(selectors))
    for forbidden in ("--deselect", "--ignore", " -k ", " -m ", "--reruns", "|| true"):
        assert forbidden not in runner


@pytest.mark.parametrize("os_name,outcome,code", [
    ("macos-latest", "pass", 0), ("ubuntu-24.04", "pass", 0),
    ("macos-latest", "fail", 1), ("macos-latest", "skip", 1),
    ("macos-latest", "xfail", 4), ("macos-latest", "xpass", 4),
    ("macos-latest", "missing", 4), ("other", "unknown", 1),
])
def test_actual_compat_shell_runs_pytest_before_validating_outcomes(tmp_path, bash, os_name, outcome, code):
    module, _ = _compat_model(tmp_path, "macos-latest" if os_name == "other" else os_name)
    if outcome == "fail":
        module.write_text(module.read_text().replace("assert True", "assert False"), encoding="utf-8")
    elif outcome == "skip":
        module.write_text("import pytest\n" + module.read_text().replace("assert True", "pytest.skip('model')"),
                          encoding="utf-8")
    elif outcome in ("xfail", "xpass"):
        source = module.read_text().replace("def ", "@pytest.mark.xfail(reason='model')\ndef ")
        if outcome == "xfail":
            source = source.replace("assert True", "assert False")
        module.write_text("import pytest\n" + source, encoding="utf-8")
    elif outcome == "missing":
        module.write_text("", encoding="utf-8")
    home = tmp_path / "compat-home"
    env = dict(_diagnostic_env(tmp_path), RUNNER_TEMP=str(tmp_path), COMPAT_OS=os_name,
               HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"))
    proc = subprocess.run([bash, "-c", _compat_step()["run"]], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == code, proc.stdout + proc.stderr
    summary = '"cases":'
    if outcome == "pass":
        assert summary in proc.stdout and '"skipped": 0' in proc.stdout
    else:
        assert summary not in proc.stdout
        if outcome == "skip":
            assert "native-compat: testcase outcome" in proc.stderr
        elif outcome in ("xfail", "xpass"):
            assert "native-compat: selected cases must not carry xfail marks" in proc.stderr
        elif outcome == "unknown":
            assert "Unknown native compatibility leg" in proc.stderr


def test_actual_compat_shell_refuses_an_existing_home_before_pytest(tmp_path, bash):
    _compat_model(tmp_path, "macos-latest")
    env = dict(_diagnostic_env(tmp_path), RUNNER_TEMP=str(tmp_path), COMPAT_OS="macos-latest")
    proc = subprocess.run([bash, "-c", _compat_step()["run"]], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "native-compat: private home must be new" in proc.stderr
    assert not (tmp_path / "native-compat.xml").exists()


@pytest.mark.parametrize("origin", ["strict-false", "run-false", "condition-false", "module",
                                    "parameter", "generated-parameter", "collection-wrapper",
                                    "equal-priority-wrapper"])
def test_actual_compat_shell_rejects_collected_xfail_before_execution(tmp_path, bash, origin):
    os_name = "ubuntu-24.04" if "parameter" in origin else "macos-latest"
    module, _ = _compat_model(tmp_path, os_name)
    source = module.read_text()
    # The marker proves that even an unmarked selected sibling did not run.
    executed = "from pathlib import Path; Path('executed').write_text('ran', encoding='utf-8')"
    source = source.replace("assert True", executed).replace("assert isinstance(fail_login_save, bool)", executed)
    mark = "pytest.mark.xfail(strict=False, reason='model')"
    if origin in ("strict-false", "run-false", "condition-false"):
        if origin == "run-false":
            mark = "pytest.mark.xfail(run=False, strict=False, reason='model')"
        elif origin == "condition-false":
            mark = "pytest.mark.xfail(False, strict=False, reason='model')"
        source = "import pytest\n" + source.replace("def ", f"@{mark}\ndef ")
    elif origin == "module":
        source = f"import pytest\npytestmark = {mark}\n" + source
    elif origin == "parameter":
        source = source.replace("[False, True]", f"[pytest.param(False, marks={mark}), True]")
    elif origin == "generated-parameter":
        source = source.replace("@pytest.mark.parametrize('fail_login_save', [False, True])\n", "")
        source += ("\ndef pytest_generate_tests(metafunc):\n"
                   f"    metafunc.parametrize('fail_login_save', [pytest.param(False, marks={mark}), True])\n")
    else:
        priority = ", tryfirst=True" if origin == "equal-priority-wrapper" else ""
        (tmp_path / "conftest.py").write_text(
            f"import pytest\n@pytest.hookimpl(wrapper=True{priority})\n"
            "def pytest_collection_modifyitems(items):\n    yield\n"
            f"    items[0].add_marker({mark})\n", encoding="utf-8")
    module.write_text(source, encoding="utf-8")
    home = tmp_path / "compat-home"
    env = dict(_diagnostic_env(tmp_path), RUNNER_TEMP=str(tmp_path), COMPAT_OS=os_name,
               HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"))
    proc = subprocess.run([bash, "-c", _compat_step()["run"]], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "native-compat: selected cases must not carry xfail marks" in proc.stderr
    assert not (tmp_path / "executed").exists(), "collection refusal must precede every selected test body"
    assert '"cases":' not in proc.stdout


@pytest.mark.parametrize("origin,code,body_ran", [
    ("setup-xpass", 1, True), ("call-xpass", 1, True), ("empty-reason-xpass", 1, True),
    ("call-xfail", 1, True), ("setup-xfail", 1, False), ("teardown-xfail", 1, True),
    ("xpass-then-interrupt", 2, True),
])
def test_actual_compat_shell_rejects_runtime_xfail_reports(tmp_path, bash, origin, code, body_ran):
    module, _ = _compat_model(tmp_path, "macos-latest")
    names = COMPAT_CASES["macos-latest"][1]
    source = "import pytest\nfrom pathlib import Path\n"
    for index, name in enumerate(names):
        request = "request" if origin in ("call-xpass", "empty-reason-xpass", "xpass-then-interrupt") else ""
        body = "    Path('executed').write_text('ran', encoding='utf-8')\n"
        if request:
            reason = "" if origin == "empty-reason-xpass" else "runtime"
            body += f"    request.node.add_marker(pytest.mark.xfail(strict=False, reason={reason!r}))\n"
        elif origin == "call-xfail":
            body += "    pytest.xfail('runtime')\n"
        if origin == "xpass-then-interrupt" and index == 1:
            body = "    raise KeyboardInterrupt('model interrupt')\n"
        source += f"def {name}({request}):\n{body}\n"
    module.write_text(source, encoding="utf-8")
    if origin in ("setup-xpass", "setup-xfail", "teardown-xfail"):
        if origin == "setup-xpass":
            body = "    request.node.add_marker(pytest.mark.xfail(strict=False, reason='runtime'))\n"
        elif origin == "setup-xfail":
            body = "    pytest.xfail('runtime')\n"
        else:
            body = "    yield\n    pytest.xfail('runtime')\n"
        (tmp_path / "conftest.py").write_text(
            "import pytest\n@pytest.fixture(autouse=True)\ndef late(request):\n" + body, encoding="utf-8")
    home = tmp_path / "compat-home"
    env = dict(_diagnostic_env(tmp_path), RUNNER_TEMP=str(tmp_path), COMPAT_OS="macos-latest",
               HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"))
    proc = subprocess.run([bash, "-c", _compat_step()["run"]], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == code, proc.stdout + proc.stderr
    if code == 1:
        assert "native-compat: xfail/XPASS reports cannot qualify selected cases" in proc.stderr
    else:
        assert "KeyboardInterrupt: model interrupt" in proc.stdout + proc.stderr
    assert (tmp_path / "executed").exists() is body_ran
    assert '"cases":' not in proc.stdout


@pytest.mark.parametrize("guard,mutation", [
    ("case identities", "identity"), ("testcase outcome", "outcome"),
    ("suite counters", "counters"), ("DTD/entity", "dtd"), ("size limit", "size"),
])
def test_report_negative_controls_detect_deleted_guards(tmp_path, compat_reports, guard, mutation):
    """Delete each guard from an owned command copy and exercise the real file boundary."""
    import xml.etree.ElementTree as ET

    body = _embedded_python(_compat_step()["run"])
    root = ET.fromstring(compat_reports["macos-latest"])
    if mutation == "identity":
        root[0][0].set("name", "unexpected")
        body = body.replace('refuse("case identities must match exactly two selected cases")', "pass")
    elif mutation == "outcome":
        ET.SubElement(root[0][0], "skipped")
        body = body.replace('refuse("testcase outcome must have no skipped, failure, error or other children")', "pass")
    elif mutation == "counters":
        root[0].set("tests", "0")
        body = body.replace('refuse("suite counters disagree with actual testcase outcomes")', "pass")
    data = ET.tostring(root)
    if mutation == "dtd":
        data = b"<!DOCTYPE testsuites []>" + data
        body = body.replace('refuse("DTD/entity or non-UTF-8 XML is forbidden")', "pass")
    elif mutation == "size":
        data += b" " * (1024 * 1024)
        body = body.replace('refuse("report exceeds size limit")', "pass")
    assert body != _embedded_python(_compat_step()["run"])
    report = tmp_path / "report.xml"
    report.write_bytes(data)
    refused = _run_compat_report(tmp_path, report, "macos-latest")
    assert refused.returncode == 1 and guard in refused.stderr
    mutant = subprocess.run([sys.executable, "-c", body, str(report), "macos-latest"],
                            cwd=tmp_path, env=_diagnostic_env(tmp_path), capture_output=True, text=True, timeout=10)
    assert mutant.returncode == 0, mutant.stderr
