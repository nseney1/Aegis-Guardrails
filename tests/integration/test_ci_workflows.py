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
WORKFLOW_FILES = ("validate.yml", "publish.yml", "aegis-governance.yml")
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


# The jobs that run the suite: the matrix, Windows, and aegis-check, whose `check --ci` reruns the
# head commit's trailer snapshot and must be able to collect what the others collect (R-trust-a3).
TEST_JOBS = ("validate", "test-windows", "aegis-check")
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
    cli = [s["run"].strip() for s in jobs["aegis-check"]["steps"] if "aegis_cli.cli" in s.get("run", "")]
    # -I keeps the checkout off sys.path, so the wheel, not the source tree, is what runs.
    assert cli and all(re.match(r"python3 -I -m aegis_cli\.cli check(\s|$)", r) for r in cli), cli
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
    assert len(steps) == 1, steps
    assert steps[0].get("env") == {"GH_TOKEN": "${{ github.token }}"}


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
    (step,) = _check_ci_steps(yaml.safe_load(body)["jobs"]["aegis-check"])
    assert "if" not in step and "continue-on-error" not in step
    assert human_gate.aegis_check_jobs(body) == ["aegis-check"]
