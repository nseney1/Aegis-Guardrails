"""CI supply-chain hardening regression tests (v0.90).

Covers least-privilege tokens, SHA-pinned actions, Dependabot, dependency
auditing, build provenance attestations and PyPI Trusted Publishing (OIDC).
PyYAML parses the workflow key ``on`` as boolean ``True``; ``_triggers`` reads either spelling.
"""
import copy
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
from fractions import Fraction
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
INTEGRATION_BRANCH = "feature/manager-workspace-prototype"
# Separate job ids, not one matrix: a matrix collapses every leg to one needs key.
_WINDOWS_PYTEST_JOBS = (
    "test-windows-unit-core-a",
    "test-windows-unit-core-b",
    "test-windows-unit-rest",
    "test-windows-integration",
    "test-windows-contract",
)
_WINDOWS_LANGUAGE_JOB = "test-windows-language"
_WINDOWS_JOBS = _WINDOWS_PYTEST_JOBS + (_WINDOWS_LANGUAGE_JOB,)
_WINDOWS_PYTHON_VERSIONS = ("3.9", "3.12")
# Side A includes the pivot basename.
_CORE_PIVOT = "test_redaction.py"
WINDOWS_PYTEST_TIMEOUT_MINUTES = 300
WINDOWS_LANGUAGE_TIMEOUT_MINUTES = 45


def _condition_allows(condition, context):
    """Evaluate this workflow's small condition subset, with prerequisites successful."""
    if condition is None or condition == "always()":
        return True
    if " || " in condition:
        return any([_condition_allows(part, context) for part in condition.split(" || ")])
    if " && " in condition:
        return all([_condition_allows(part, context) for part in condition.split(" && ")])
    match = re.fullmatch(r"([a-z_.]+) (==|!=) '([^']*)'", condition)
    assert match is not None, f"Unsupported workflow condition: {condition}"
    key, operator, value = match.groups()
    assert key in context, f"Unsupported workflow context: {key}"
    equal = context[key] == value
    return equal if operator == "==" else not equal


def test_integration_lane_pull_requests_do_not_trigger_validate():
    triggers = _triggers(_load("validate.yml"))
    assert triggers["pull_request"] == {"branches": ["main", "develop", "release/**"]}
    assert INTEGRATION_BRANCH not in triggers["pull_request"]["branches"]


def test_integration_push_change_preserves_other_triggers():
    triggers = _triggers(_load("validate.yml"))
    assert {key: value for key, value in triggers.items() if key not in ("push", "pull_request")} == {
        "workflow_call": None,
        "workflow_dispatch": None,
        "schedule": [{"cron": "17 4 * * *"}],
    }


def test_integration_push_runs_every_develop_job_and_step_condition():
    """Eligibility only: upstream jobs and preceding steps are assumed successful."""
    workflow = _load("validate.yml")
    assert INTEGRATION_BRANCH in _triggers(workflow)["push"]["branches"]
    jobs = workflow["jobs"]
    assert set(jobs) == {
        "dependency-audit", "build-wheel",
        "test-fast-unit-core", "test-fast-unit-rest", "test-fast-integration", "test-fast-contract",
        "aegis-check", "validate", "verdict",
        *_WINDOWS_JOBS,
    }
    matrix = jobs["validate"]["strategy"]["matrix"]
    validate_legs = [(leg["os"], leg["python-version"]) for leg in matrix["leg"]]
    assert set(validate_legs) == set(_VALIDATE_LEGS)
    assert jobs["validate"]["runs-on"] == "${{ matrix.leg.os }}"
    legs = [(name, job["runs-on"], None, None) for name, job in jobs.items()
            if name != "validate" and not name.startswith("test-windows")]
    legs += [("validate", os_name, version, shard) for os_name, version in validate_legs
             for shard in matrix["shard"]]
    for name in _WINDOWS_JOBS:
        windows_matrix = jobs[name]["strategy"]["matrix"]
        assert windows_matrix == {"python-version": ["3.9", "3.12"]}, name
        assert jobs[name]["runs-on"] == "windows-latest"
        assert jobs[name]["strategy"]["fail-fast"] is False
        legs += [(name, "windows-latest", version, None) for version in windows_matrix["python-version"]]
    # 8 singleton jobs (four of them test-fast shards) + 6 jobs on each of 4 validate legs
    # + each Windows job's two Python versions.
    assert len(legs) == 8 + 6 * 4 + len(_WINDOWS_JOBS) * 2
    runner_os = {"ubuntu-latest": "Linux", "ubuntu-24.04": "Linux",
                 "macos-latest": "macOS", "windows-latest": "Windows"}
    for name, runner, version, shard in legs:
        job = jobs[name]
        contexts = [{"github.event_name": "push", "github.base_ref": "",
                     "github.ref": "refs/heads/" + branch, "github.ref_name": branch,
                     "runner.os": runner_os[runner], "matrix.shard": shard}
                    for branch in ("develop", INTEGRATION_BRANCH)]
        eligible = [_condition_allows(job.get("if"), context) for context in contexts]
        assert eligible == [True, True], (name, runner, version)
        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        for dependency in needs:
            assert all(_condition_allows(jobs[dependency].get("if"), context) for context in contexts)
        outcomes = [[_condition_allows(step.get("if"), context) for step in job["steps"]]
                    for context in contexts]
        assert outcomes[0] == outcomes[1], (name, runner, version)
        skipped = set()
        if name == "aegis-check":
            skipped.add("Fetch wave pull request head as data")
        if name == "validate":
            if runner_os[runner] != "Linux" or shard == "checks":
                skipped.update(("Install bubblewrap", "Prove bubblewrap runs"))
            if shard == "checks":
                skipped.add("Run test suite")
            else:
                skipped.update(_VALIDATE_CHECKS)
        assert outcomes[1] == [step.get("name") not in skipped for step in job["steps"]], (name, runner, version)


def test_wave_prs_keep_governance_while_full_validation_runs_on_develop_and_downstream():
    workflow = _load("validate.yml")
    triggers = _triggers(workflow)
    assert triggers["push"]["branches"] == ["main", "develop", "release/**", INTEGRATION_BRANCH]
    assert triggers["pull_request"]["branches"] == ["main", "develop", "release/**"]
    assert {"workflow_call", "workflow_dispatch"} <= set(triggers)
    jobs = workflow["jobs"]
    for name in ("dependency-audit", "build-wheel", "validate", *_WINDOWS_JOBS):
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
    needs = {"build-wheel": {"result": actual}}
    needs.update(_windows_results(expected))
    needs.update({name: {"result": "success"} for name, _job in _fast_jobs()})
    proc = _run_upstream_gate(expected, needs)
    assert (proc.returncode == 0) is passed, proc.stderr
    if not passed:
        assert "build-wheel" in proc.stderr and "Unexpected upstream job results" in proc.stderr
_FAST_SHARDS = (
    "test-fast-unit-core",
    "test-fast-unit-rest",
    "test-fast-integration",
    "test-fast-contract",
)
# Each entry starts with the whole-suite fallback from validate ubuntu-latest 3.11.
# Replace a row only after reviewing the corresponding shard's green job wall clock.
_REVIEWED_FAST_MEASUREMENTS = {
    "test-fast-unit-core": ("6516.67", "44219204536"),
    "test-fast-unit-rest": ("6516.67", "44219204536"),
    "test-fast-integration": ("6516.67", "44219204536"),
    "test-fast-contract": ("6516.67", "44219204536"),
}
_FAST_MEASUREMENT_PREFIX = "# test-fast-measurement:"
_MEASUREMENT_LINE = re.compile(
    r" ([A-Za-z0-9_-]+) ([0-9]+(?:\.[0-9]+)?)s run ([1-9][0-9]*)[ \t]*",
)


def _minimum_timeout_minutes(seconds):
    """Smallest integer minute cap that is at least twice ``seconds``."""
    minutes = (seconds * 2) / 60.0
    whole = int(minutes)
    if minutes - whole > 1e-9:
        return whole + 1
    return whole


def _fast_jobs(workflow=None):
    """The per-PR suite job, or each of its directory shards. One unsharded job is not enough."""
    jobs = (workflow or _load("validate.yml"))["jobs"]
    return [(name, job) for name, job in jobs.items()
            if name == "test-fast" or name.startswith("test-fast-")]


def _recorded_fast_measurements(text):
    found = {}
    for line in text.splitlines():
        if not line.startswith(_FAST_MEASUREMENT_PREFIX):
            continue
        match = _MEASUREMENT_LINE.fullmatch(line, len(_FAST_MEASUREMENT_PREFIX))
        assert match is not None, "invalid fast measurement row"
        job, seconds, run = match.groups()
        assert job not in found, "duplicate fast measurement row"
        found[job] = (seconds, run)
    return found


def _suite_test_files():
    """Pytest's default file names under ``tests/``, as repo-relative forward-slash paths."""
    root = os.path.join(REPO_ROOT, "tests")
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in ("__pycache__", ".pytest_cache"))
        for name in filenames:
            if name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py")):
                full = os.path.join(dirpath, name)
                found.append(os.path.relpath(full, REPO_ROOT).replace(os.sep, "/"))
    return sorted(found)


def _selected_test_files(selector, files):
    """Test files a positive directory or file selector collects. No glob and no parent escape."""
    if selector.endswith(".py"):
        return [path for path in files if path == selector]
    prefix = selector.rstrip("/") + "/"
    return [path for path in files if path.startswith(prefix)]


def _windows_results(result):
    return {name: {"result": result} for name in _WINDOWS_JOBS}


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
    """Every shard is in ALWAYS_SUCCESS, so each one must succeed on a wave PR and on a full run."""
    names = [name for name, _job in _fast_jobs()]
    assert names
    for target in names:
        needs = {"build-wheel": {"result": expected}}
        needs.update(_windows_results(expected))
        for name in names:
            if name != target:
                needs[name] = {"result": "success"}
            elif fast is not None:
                needs[name] = {"result": fast}
        proc = _run_upstream_gate(expected, needs)
        assert (proc.returncode == 0) is passed, (target, proc.stderr)
        if not passed:
            assert target in proc.stderr and "Unexpected upstream job results" in proc.stderr


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
    needs = workflow["jobs"]["aegis-check"]["needs"]
    if isinstance(needs, str):
        needs = [needs]
    for name, job in _fast_jobs(workflow):
        # No `if` and no `needs`: build-wheel and dependency-audit skip on wave PRs, and the verdict
        # needs this job to succeed on push and dispatch too.
        assert "if" not in job and "needs" not in job, name
        assert job["runs-on"] == "ubuntu-latest"
        assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}
        # The evidence-specific floor is checked separately.
        assert type(job.get("timeout-minutes")) is int and job["timeout-minutes"] <= 360
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
        assert name in needs


def test_the_fast_leg_runs_the_whole_suite_with_xdist_from_its_own_venv():
    """Each shard installs the same venv as validate and runs the canonical suite step.

    The selectors together are the whole suite (see the exact-coverage test). The whole
    job equals one template with an independently checked timeout, so a narrowed
    command or an earlier step is a different job.
    """
    jobs = _fast_jobs()
    validate_install = next(s["run"] for s in _load("validate.yml")["jobs"]["validate"]["steps"]
                            if s.get("name") == INSTALL_STEP)
    for _name, job in jobs:
        # The runner context is not available to job-level env, so a step exports the venv path.
        export = _index(job, 'echo "VENV=$RUNNER_TEMP/ci-venv" >> "$GITHUB_ENV"')
        venv = _index(job, 'python -m venv "$VENV"')
        assert export < venv
        install = _index(job, '"$VENV/bin/pip" install pytest==')
        package = _index(job, '"$VENV/bin/pip" install .')
        lint = _index(job, 'make lint PYTHON="$VENV/bin/python"')
        suite = _index(job, "-m pytest", "$TEST_FAST_PATHS")
        assert venv < install < package < lint < suite
        packages = _packages(_runs(job)[install])
        assert packages == _packages(validate_install.splitlines()[0]) and "pytest-xdist==3.6.1" in packages
        run = _runs(job)[suite]
        assert 'xdist="-n auto"' in run
        assert 'mktemp -d /tmp/aegis-test-home.' in run
        assert 'HOME="$home"' in run and 'USERPROFILE="$home"' in run
        _shard_paths(job)
        assert _index(job, "grep -rnI '/home/'") > package


def _bubblewrap_probe():
    from tests.integration.test_hierarchy_jobs import BUBBLEWRAP_PROBE
    return shlex.join(BUBBLEWRAP_PROBE)


def test_linux_legs_install_bubblewrap_and_prove_it_runs_before_the_suite():
    names = [name for name, _job in _fast_jobs()] + ["validate"]
    for name in names:
        job = _load("validate.yml")["jobs"][name]
        install = _index(job, "apt-get", "install -y --no-install-recommends bubblewrap")
        # A transient mirror error must not fail a wave PR's required check.
        assert _runs(job)[install].count("-o Acquire::Retries=3") == 2
        probe = _index(job, _bubblewrap_probe())
        if name == "validate":
            suite = job["steps"].index(_suite_step(job))
        else:
            suite = _index(job, "-m pytest", "$TEST_FAST_PATHS")
        assert install < probe < suite
        steps = job["steps"]
        # Ubuntu 23.10 and later block unprivileged user namespaces through AppArmor; without
        # lifting that, the probe fails and the eight bubblewrap job tests would skip silently.
        assert "kernel.apparmor_restrict_unprivileged_userns=0" in steps[probe]["run"]
        if name == "validate":
            condition = "runner.os == 'Linux' && matrix.shard != 'checks'"
            assert steps[install].get("if") == steps[probe].get("if") == condition
        assert not steps[probe].get("continue-on-error") and "|| true" not in steps[probe]["run"]


def _guard_fast_timeouts(workflow, text, reviewed):
    required = set(_FAST_SHARDS)
    jobs = dict(_fast_jobs(workflow))
    assert jobs.keys() == required, "fast jobs must match the required shard IDs"
    assert reviewed.keys() == required, "reviewed fast measurement rows must cover each required shard"
    recorded = _recorded_fast_measurements(text)
    assert recorded.keys() == required, "workflow fast measurement rows must cover each required shard"
    for name in _FAST_SHARDS:
        assert recorded[name] == reviewed[name], f"{name}: fast measurement does not match reviewed evidence"
        seconds, _run = reviewed[name]
        # Each minute allows 30 measured seconds at twice the duration. Keep the decimal exact.
        floor = math.ceil(Fraction(seconds) / 30)
        timeout = jobs[name].get("timeout-minutes")
        assert type(timeout) is int and 1 <= floor <= timeout <= 360, (
            f"{name}: fast timeout is outside its measured bounds"
        )


def test_each_test_fast_timeout_is_at_least_twice_its_recorded_measurement():
    text = _read("validate.yml")
    _guard_fast_timeouts(yaml.safe_load(text), text, _REVIEWED_FAST_MEASUREMENTS)


# One template for every shard. The run text is byte-identical; only TEST_FAST_PATHS changes.
# A backslash before the newline is part of the shell continuation, not a Python line join.
_CANONICAL_SUITE_RUN = "\n".join([
    "set -euo pipefail",
    # Pathname expansion is off, so a selector cannot glob into another directory.
    "set -f",
    'python_bin="$VENV/bin/python"',
    'userbase="${PYTHONUSERBASE:-$("$python_bin" -c \'import site; print(site.getuserbase())\')}"',
    'home="$(mktemp -d /tmp/aegis-test-home.XXXXXX)"',
    """trap 'rm -rf "$home"' EXIT""",
    'xdist=""',
    'if "$python_bin" -c "import xdist" >/dev/null 2>&1; then',
    '  xdist="-n auto"',
    "fi",
    "# Isolated HOME, the same contract as the developer test target. $xdist is -n auto when",
    "# pytest-xdist imports. Selectors are the positive paths in TEST_FAST_PATHS.",
    'HOME="$home" USERPROFILE="$home" XDG_CONFIG_HOME="$home/.config" PYTHONUSERBASE="$userbase" \\',
    '  "$python_bin" -m pytest -q $xdist $TEST_FAST_PATHS',
]) + "\n"
_PYTEST_LINE = '  "$python_bin" -m pytest -q $xdist $TEST_FAST_PATHS\n'
# Steps owned by this test. A shard equals the job built from these lists plus the suite step.
_CANONICAL_STEPS_BEFORE = [
    {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
     "with": {"fetch-depth": 0, "persist-credentials": False}},
    {"name": "Set up Python",
     "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
     "with": {"python-version": "3.11"}},
    {"name": "Install bubblewrap",
     "run": "sudo apt-get -o Acquire::Retries=3 update && sudo apt-get -o Acquire::Retries=3 install "
            "-y --no-install-recommends bubblewrap"},
    {"name": "Prove bubblewrap runs",
     "run": "set -euo pipefail\n"
            "if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then\n"
            "  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n"
            "fi\n"
            "bwrap --unshare-net --unshare-pid --ro-bind / / --dev /dev --proc /proc true\n"},
    {"name": "Choose the CI venv path", "run": 'echo "VENV=$RUNNER_TEMP/ci-venv" >> "$GITHUB_ENV"'},
    {"name": "Create the CI venv", "run": 'python -m venv "$VENV"'},
    {"name": "Install test dependencies into the CI venv",
     "run": '"$VENV/bin/pip" install pytest==8.3.4 pytest-xdist==3.6.1 ruff==0.9.10 '
            "hypothesis==6.126.0 coverage==7.6.12 pyyaml==6.0.2 anyio==4.12.1"},
    {"name": "Install the checkout into the CI venv", "run": '"$VENV/bin/pip" install .'},
    {"name": "Lint", "run": 'make lint PYTHON="$VENV/bin/python"'},
]
_CANONICAL_STEPS_AFTER = [
    {"name": "Check for hardcoded paths",
     "run": "# Exclude template examples like /home/<user>/ which are privacy instructions\n"
            "if grep -rnI '/home/' rules/ skills/ docs/ README.md 2>/dev/null | grep -v '<user>' | "
            "grep -v '<username>'; then\n"
            '  echo "ERROR: Hardcoded paths found"\n'
            "  exit 1\n"
            "fi\n"
            'echo "No hardcoded paths found"\n'},
]
_CANONICAL_UPSTREAM_STEP = {
    "name": "Verify upstream jobs succeeded",
    "env": {
        "NEEDS_JSON": "${{ toJSON(needs) }}",
        "EXPECTED_RESULT": "${{ github.event_name == 'pull_request' && github.base_ref == "
                           "'develop' && 'skipped' || 'success' }}",
        "ALWAYS_SUCCESS": "test-fast-unit-core test-fast-unit-rest test-fast-integration "
                          "test-fast-contract",
        "REQUIRED_WINDOWS": " ".join(_WINDOWS_JOBS),
    },
    "run": "python3 -c 'import json, os, sys; needs = json.loads(os.environ[\"NEEDS_JSON\"]); expected "
           "= os.environ[\"EXPECTED_RESULT\"]; always = os.environ[\"ALWAYS_SUCCESS\"].split(); bad = {k: "
           "v.get(\"result\") for k, v in needs.items() if v.get(\"result\") != (\"success\" if k in always "
           "else expected)}; bad.update({k: \"missing\" for k in always + "
           "os.environ[\"REQUIRED_WINDOWS\"].split() if k not in needs}); "
           "sys.exit(f\"Unexpected upstream job results (expected {expected}, and success for "
           "{always}): {bad}\" if bad else 0)'\n",
}


def _canonical_suite_step(selectors):
    return {
        "name": "Run test suite",
        "env": {"TEST_FAST_PATHS": selectors},
        "run": _CANONICAL_SUITE_RUN,
    }


def _canonical_fast_job(selectors, timeout):
    """One test-fast job with a separately checked selector and timeout."""
    return {
        "runs-on": "ubuntu-latest",
        "timeout-minutes": timeout,
        "steps": [
            *copy.deepcopy(_CANONICAL_STEPS_BEFORE),
            _canonical_suite_step(selectors),
            *copy.deepcopy(_CANONICAL_STEPS_AFTER),
        ],
    }


# Steps of aegis-check after the upstream verification. The job has no env and no defaults.
_CANONICAL_AEGIS_STEPS_AFTER = [
    {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
     "with": {"ref": "${{ github.event_name == 'pull_request' && github.base_ref == "
                     "'develop' && github.event.pull_request.base.sha || github.sha }}",
              "fetch-depth": 0,
              "persist-credentials": False}},
    {"name": "Fetch wave pull request head as data",
     "if": "github.event_name == 'pull_request' && github.base_ref == 'develop'",
     "env": {"PR_NUMBER": "${{ github.event.pull_request.number }}"},
     "run": "git fetch --no-tags origin "
            '"+refs/pull/${PR_NUMBER}/head:refs/remotes/pull/head"'},
    {"name": "Run CI governance without execution",
     "env": {"GH_TOKEN": "${{ github.token }}"},
     "run": "python3 -m aegis_cli.cli check --ci --no-exec"},
    {"name": "Set up Python",
     "if": "github.event_name != 'pull_request' || github.base_ref != 'develop'",
     "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
     "with": {"python-version": "3.11"}},
    {"name": "Download wheel artifact",
     "if": "github.event_name != 'pull_request' || github.base_ref != 'develop'",
     "uses": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
     "with": {"name": "aegis-wheel", "path": "dist/"}},
    {"name": "Verify artifact digests",
     "if": "github.event_name != 'pull_request' || github.base_ref != 'develop'",
     "run": "python .github/scripts/verify_dist.py verify dist"},
    {"name": "Install test dependencies",
     "if": "github.event_name != 'pull_request' || github.base_ref != 'develop'",
     "run": "pip install pytest==8.3.4 pytest-xdist==3.6.1 ruff==0.9.10 hypothesis==6.126.0 "
            "coverage==7.6.12 pyyaml==6.0.2 anyio==4.12.1\n"
            "pip install dist/*.whl\n"},
    {"name": "Run Layer 1 Deterministic Verification",
     "if": "github.event_name != 'pull_request' || github.base_ref != 'develop'",
     "run": "python3 -I -m aegis_cli.cli check"},
    {"name": "Run CI Governance & Regression Check",
     "if": "github.event_name != 'pull_request' || github.base_ref != 'develop'",
     "run": "python3 -I -m aegis_cli.cli check --ci",
     "env": {"GH_TOKEN": "${{ github.token }}"}},
]


def _canonical_aegis_job():
    """aegis-check as one object. Env and defaults stay absent."""
    return {
        "needs": [
            "dependency-audit",
            "build-wheel",
            "validate",
            *_WINDOWS_JOBS,
            "test-fast-unit-core",
            "test-fast-unit-rest",
            "test-fast-integration",
            "test-fast-contract",
        ],
        "if": "always()",
        "runs-on": "ubuntu-latest",
        "timeout-minutes": 60,
        "permissions": {"contents": "read", "pull-requests": "read"},
        "steps": [
            copy.deepcopy(_CANONICAL_UPSTREAM_STEP),
            *copy.deepcopy(_CANONICAL_AEGIS_STEPS_AFTER),
        ],
    }


def _suite_step(job):
    found = [step for step in job.get("steps") or []
             if isinstance(step, dict) and step.get("name") == "Run test suite"]
    assert len(found) == 1, "a test-fast shard must run the suite once"
    return found[0]


# Letters, digits, underscore, dot, slash, and hyphen. Glob and shell metacharacters are out.
_SELECTOR_CLASS = re.compile(r"^tests(?:/[A-Za-z0-9_.-]+)+$")


def _positive_selector(selector, files):
    """A selector is a tests/ path in the fixed class, and it hits the suite partition."""
    parts = selector.split("/")
    if (_SELECTOR_CLASS.fullmatch(selector) is None or ".." in parts
            or any(part in ("", ".") for part in parts)):
        return False
    return bool(_selected_test_files(selector, files))


def _selector_text(job):
    step = _suite_step(job)
    raw = (step.get("env") or {}).get("TEST_FAST_PATHS")
    assert isinstance(raw, str) and raw.split(), raw
    return raw


def _guard_test_fast_allowlist(workflow):
    """Whole-job equality for every shard and for aegis-check.

    Each timeout is checked against reviewed evidence by _guard_fast_timeouts.
    TEST_FAST_PATHS matches one character class and partitions the suite.
    The workflow has no env mapping. aegis-check equals one job, so an inherited
    SHELLOPTS, BASHOPTS, or BASH_ENV cannot be added on either object.
    """
    assert "env" not in workflow
    assert "defaults" not in workflow
    jobs = _fast_jobs(workflow)
    assert 3 <= len(jobs) <= 4, [name for name, _job in jobs]
    files = _suite_test_files()
    owned = {}
    for name, job in jobs:
        raw = _selector_text(job)
        assert job == _canonical_fast_job(raw, job.get("timeout-minutes")), (
            f"{name}: unexpected fast job execution settings"
        )
        for selector in raw.split():
            assert _positive_selector(selector, files), (name, selector)
            for path in _selected_test_files(selector, files):
                owned.setdefault(path, []).append((name, selector))
    gap = [path for path in files if path not in owned]
    overlap = [path for path, who in owned.items() if len(who) > 1]
    assert gap == [] and overlap == [], (gap[:20], overlap[:20])
    assert workflow.get("jobs", {}).get("aegis-check") == _canonical_aegis_job()
    return [(name, _selector_text(job).split()) for name, job in jobs]


def _shard_paths(job):
    """Selectors for one shard whose whole job equals the canonical template."""
    raw = _selector_text(job)
    files = _suite_test_files()
    assert job == _canonical_fast_job(raw, job.get("timeout-minutes"))
    selectors = raw.split()
    assert all(_positive_selector(selector, files) for selector in selectors), selectors
    return selectors


def _rewrite_suite_run(workflow, old, new):
    _name, job = _fast_jobs(workflow)[0]
    step = _suite_step(job)
    assert old in step["run"], old
    step["run"] = step["run"].replace(old, new, 1)


def _mutate_ignore_glob_equals(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        "  \"$python_bin\" -m pytest -q $xdist --ignore-glob='*test_team.py' $TEST_FAST_PATHS\n")


def _mutate_ignore_glob_space(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        "  \"$python_bin\" -m pytest -q $xdist --ignore-glob '*test_team.py' $TEST_FAST_PATHS\n")


def _mutate_k_space(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        '  "$python_bin" -m pytest -q $xdist -k smoke $TEST_FAST_PATHS\n')


def _mutate_k_equals(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        '  "$python_bin" -m pytest -q $xdist -k=smoke $TEST_FAST_PATHS\n')


def _mutate_deselect_space(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        '  "$python_bin" -m pytest -q $xdist --deselect tests/unit/core/test_team.py $TEST_FAST_PATHS\n')


def _mutate_deselect_equals(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        '  "$python_bin" -m pytest -q $xdist --deselect=tests/unit/core/test_team.py $TEST_FAST_PATHS\n')


def _mutate_collect_only(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        '  "$python_bin" -m pytest -q $xdist --collect-only $TEST_FAST_PATHS\n')


def _mutate_continuation_k(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        '  "$python_bin" -m pytest -q $xdist $TEST_FAST_PATHS \\\n  -k smoke\n')


def _mutate_comment_hides_command(workflow):
    _rewrite_suite_run(
        workflow, _PYTEST_LINE,
        '  # "$python_bin" -m pytest -q $xdist $TEST_FAST_PATHS\n'
        '  "$python_bin" -m pytest -q $xdist -k smoke $TEST_FAST_PATHS\n')


def _mutate_pytest_addopts_workflow(workflow):
    workflow["env"] = {"PYTEST_ADDOPTS": "-k smoke"}


def _mutate_pytest_addopts_job(workflow):
    _name, job = _fast_jobs(workflow)[0]
    job["env"] = {"PYTEST_ADDOPTS": "--collect-only"}


def _mutate_pytest_addopts_step(workflow):
    _name, job = _fast_jobs(workflow)[0]
    _suite_step(job)["env"]["PYTEST_ADDOPTS"] = "--collect-only"


def _mutate_reassign_xdist(workflow):
    _rewrite_suite_run(workflow, 'xdist="-n auto"', 'xdist="-n auto"\n  xdist="$xdist -k smoke"')


def _mutate_reassign_paths(workflow):
    _rewrite_suite_run(workflow, _PYTEST_LINE, 'TEST_FAST_PATHS=""\n' + _PYTEST_LINE)


def _mutate_job_continue_on_error(workflow):
    _name, job = _fast_jobs(workflow)[0]
    job["continue-on-error"] = True


def _mutate_upstream_if(workflow):
    workflow["jobs"]["aegis-check"]["steps"][0]["if"] = (
        "github.event_name != 'pull_request' || github.base_ref != 'develop'")


def _mutate_upstream_continue_on_error(workflow):
    workflow["jobs"]["aegis-check"]["steps"][0]["continue-on-error"] = True


_GITHUB_ENV_COLLECT = "echo 'PYTEST_ADDOPTS=--collect-only' >> \"$GITHUB_ENV\""
_GITHUB_ENV_IGNORE = "echo 'PYTEST_ADDOPTS=--ignore-glob=*test_team.py' >> \"$GITHUB_ENV\""


def _mutate_github_env(shard, line):
    def mutate(workflow):
        job = dict(_fast_jobs(workflow))[shard]
        found = [step for step in job["steps"] if step.get("name") == "Choose the CI venv path"]
        assert len(found) == 1, shard
        found[0]["run"] = found[0]["run"] + "\n" + line
    return mutate


def _mutate_added_step_before_suite(workflow):
    _name, job = _fast_jobs(workflow)[0]
    index = next(i for i, step in enumerate(job["steps"]) if step.get("name") == "Run test suite")
    job["steps"].insert(index, {
        "name": "Export pytest options",
        "run": _GITHUB_ENV_COLLECT,
    })


def _mutate_upstream_shell_true(workflow):
    workflow["jobs"]["aegis-check"]["steps"][0]["shell"] = "true {0}"


def _mutate_upstream_shell_bash(workflow):
    workflow["jobs"]["aegis-check"]["steps"][0]["shell"] = 'bash -c "exit 0" {0}'


def _mutate_needs_json(workflow):
    workflow["jobs"]["aegis-check"]["steps"][0]["env"]["NEEDS_JSON"] = "${{ toJSON(github.event) }}"


def _mutate_upstream_moved(workflow):
    steps = workflow["jobs"]["aegis-check"]["steps"]
    verify = steps.pop(0)
    steps.insert(1, verify)


def _mutate_defaults_workflow(workflow):
    workflow["defaults"] = {"run": {"shell": "true {0}"}}


def _mutate_defaults_job(workflow):
    _fast_jobs(workflow)[0][1]["defaults"] = {"run": {"shell": 'bash -c "exit 0" {0}'}}


def _mutate_defaults_aegis(workflow):
    workflow["jobs"]["aegis-check"]["defaults"] = {"run": {"shell": "true {0}"}}


def _mutate_workflow_shellopts(workflow):
    workflow["env"] = {"SHELLOPTS": "noexec"}


def _mutate_aegis_shellopts(workflow):
    workflow["jobs"]["aegis-check"]["env"] = {"SHELLOPTS": "noexec"}


def _mutate_workflow_bashopts(workflow):
    workflow["env"] = {"BASHOPTS": "noglob"}


def _mutate_aegis_bashopts(workflow):
    workflow["jobs"]["aegis-check"]["env"] = {"BASHOPTS": "noglob"}


def _mutate_workflow_bash_env(workflow):
    workflow["env"] = {"BASH_ENV": "/tmp/evil.sh"}


def _mutate_aegis_bash_env(workflow):
    workflow["jobs"]["aegis-check"]["env"] = {"BASH_ENV": "/tmp/evil.sh"}


def _mutate_bracket_selector(workflow):
    for name, job in _fast_jobs(workflow):
        if name == "test-fast-unit-rest":
            step = _suite_step(job)
            step["env"]["TEST_FAST_PATHS"] = step["env"]["TEST_FAST_PATHS"] + " tests/unit/c[o]re"
            return
    raise AssertionError("unit-rest shard missing")


def test_bracket_selector_is_refused_even_when_its_literal_test_file_exists():
    """The fixed character class, not an empty selection, refuses a glob-shaped selector.

    With a literal tests/unit/c[o]re/ test file present, the selector selects it, so a
    selection-only predicate would count it as covered while bash expands it to tests/unit/core.
    """
    literal = "tests/unit/c[o]re/test_example.py"
    files = list(_suite_test_files()) + [literal]
    assert _selected_test_files("tests/unit/c[o]re", files) == [literal]
    assert not _positive_selector("tests/unit/c[o]re", files)


def test_test_fast_allowlist_holds():
    """The shipped shards and aegis-check equal their templates, and the workflow has no env."""
    _guard_test_fast_allowlist(_load("validate.yml"))


@pytest.fixture
def mixed_fast_measurements():
    """Synthetic shard evidence alongside the historical whole-suite fallback."""
    workflow = _load("validate.yml")
    reviewed = dict.fromkeys(_FAST_SHARDS, ("6516.67", "44219204536"))
    for name in _FAST_SHARDS:
        workflow["jobs"][name]["timeout-minutes"] = 218
    name = _FAST_SHARDS[0]
    # Twice this duration is just over two minutes.
    reviewed[name] = ("60.000000001", "12345")
    workflow["jobs"][name]["timeout-minutes"] = 3
    text = "\n".join(f"{_FAST_MEASUREMENT_PREFIX} {job} {seconds}s run {run}"
                     for job, (seconds, run) in reviewed.items())
    return workflow, text, reviewed


def test_fast_timeout_guard_accepts_a_shard_measurement(mixed_fast_measurements):
    workflow, text, reviewed = mixed_fast_measurements
    _guard_fast_timeouts(workflow, text, reviewed)


def test_fast_execution_allowlist_accepts_an_independent_timeout(mixed_fast_measurements):
    workflow, _text, _reviewed = mixed_fast_measurements
    _guard_test_fast_allowlist(workflow)
    _shard_paths(workflow["jobs"][_FAST_SHARDS[0]])


def test_fast_timeout_guard_requires_each_reviewed_row(mixed_fast_measurements):
    workflow, text, reviewed = mixed_fast_measurements
    missing = dict(reviewed)
    del missing[_FAST_SHARDS[0]]
    with pytest.raises(AssertionError, match="reviewed fast measurement rows must cover each required shard"):
        _guard_fast_timeouts(workflow, text, missing)
    _guard_fast_timeouts(workflow, text, reviewed)


def test_fast_timeout_guard_requires_the_exact_shard_ids(mixed_fast_measurements):
    workflow, text, reviewed = mixed_fast_measurements
    changed = copy.deepcopy(workflow)
    jobs = changed["jobs"]
    jobs["test-fast-unreviewed"] = jobs.pop(_FAST_SHARDS[0])
    with pytest.raises(AssertionError, match="fast jobs must match the required shard IDs"):
        _guard_fast_timeouts(changed, text, reviewed)
    _guard_fast_timeouts(workflow, text, reviewed)


@pytest.mark.parametrize("replacement, reason", [
    ("", "workflow fast measurement rows must cover each required shard"),
    ("60.000000002s run 12345", "fast measurement does not match reviewed evidence"),
    ("60.000000001s run 12346", "fast measurement does not match reviewed evidence"),
    ("60.000000001s\n# run 12345", "invalid fast measurement row"),
])
def test_fast_timeout_guard_rejects_changed_annotations(mixed_fast_measurements, replacement, reason):
    workflow, text, reviewed = mixed_fast_measurements
    name = _FAST_SHARDS[0]
    prefix = f"{_FAST_MEASUREMENT_PREFIX} {name} "
    seconds, run = reviewed[name]
    changed = text.replace(f"{prefix}{seconds}s run {run}", prefix + replacement if replacement else "")
    with pytest.raises(AssertionError, match=reason):
        _guard_fast_timeouts(workflow, changed, reviewed)
    _guard_fast_timeouts(workflow, text, reviewed)


def test_fast_timeout_guard_rejects_duplicate_annotations(mixed_fast_measurements):
    workflow, text, reviewed = mixed_fast_measurements
    with pytest.raises(AssertionError, match="duplicate fast measurement row"):
        _guard_fast_timeouts(workflow, text + "\n" + text, reviewed)


@pytest.mark.parametrize("shard, cap", [(0, 2), (0, 3.0), (0, 361), (1, 217)])
def test_fast_timeout_guard_rejects_invalid_caps(mixed_fast_measurements, shard, cap):
    workflow, text, reviewed = mixed_fast_measurements
    changed = copy.deepcopy(workflow)
    changed["jobs"][_FAST_SHARDS[shard]]["timeout-minutes"] = cap
    with pytest.raises(AssertionError, match="fast timeout is outside its measured bounds"):
        _guard_fast_timeouts(changed, text, reviewed)
    _guard_fast_timeouts(workflow, text, reviewed)


@pytest.mark.parametrize("field", ["steps", "permissions"])
def test_fast_execution_allowlist_rejects_changed_job_settings(mixed_fast_measurements, field):
    workflow, text, reviewed = mixed_fast_measurements
    changed = copy.deepcopy(workflow)
    job = changed["jobs"][_FAST_SHARDS[0]]
    if field == "steps":
        job["steps"][0]["with"]["persist-credentials"] = True
    else:
        job["permissions"] = {"contents": "write"}
    _guard_fast_timeouts(changed, text, reviewed)
    with pytest.raises(AssertionError, match="unexpected fast job execution settings"):
        _guard_test_fast_allowlist(changed)
    _guard_test_fast_allowlist(workflow)


@pytest.mark.parametrize("mutate", [
    pytest.param(_mutate_ignore_glob_equals, id="ignore-glob-equals"),
    pytest.param(_mutate_ignore_glob_space, id="ignore-glob-space"),
    pytest.param(_mutate_k_space, id="k-space"),
    pytest.param(_mutate_k_equals, id="k-equals"),
    pytest.param(_mutate_deselect_space, id="deselect-space"),
    pytest.param(_mutate_deselect_equals, id="deselect-equals"),
    pytest.param(_mutate_collect_only, id="collect-only"),
    pytest.param(_mutate_continuation_k, id="continuation-k"),
    pytest.param(_mutate_comment_hides_command, id="comment-hides-command"),
    pytest.param(_mutate_pytest_addopts_workflow, id="pytest-addopts-workflow"),
    pytest.param(_mutate_pytest_addopts_job, id="pytest-addopts-job"),
    pytest.param(_mutate_pytest_addopts_step, id="pytest-addopts-step"),
    pytest.param(_mutate_reassign_xdist, id="reassign-xdist"),
    pytest.param(_mutate_reassign_paths, id="reassign-paths"),
    pytest.param(_mutate_job_continue_on_error, id="job-continue-on-error"),
    pytest.param(_mutate_upstream_if, id="upstream-if"),
    pytest.param(_mutate_upstream_continue_on_error, id="upstream-continue-on-error"),
    *[pytest.param(_mutate_github_env(shard, _GITHUB_ENV_COLLECT),
                   id="github-env-collect-" + shard) for shard in _FAST_SHARDS],
    *[pytest.param(_mutate_github_env(shard, _GITHUB_ENV_IGNORE),
                   id="github-env-ignore-glob-" + shard) for shard in _FAST_SHARDS],
    pytest.param(_mutate_added_step_before_suite, id="added-step-before-suite"),
    pytest.param(_mutate_upstream_shell_true, id="upstream-shell-true"),
    pytest.param(_mutate_upstream_shell_bash, id="upstream-shell-bash"),
    pytest.param(_mutate_needs_json, id="needs-json-changed"),
    pytest.param(_mutate_upstream_moved, id="upstream-moved-off-zero"),
    pytest.param(_mutate_defaults_workflow, id="defaults-workflow-shell"),
    pytest.param(_mutate_defaults_job, id="defaults-job-shell"),
    pytest.param(_mutate_defaults_aegis, id="defaults-aegis-shell"),
    pytest.param(_mutate_workflow_shellopts, id="shellopts-workflow"),
    pytest.param(_mutate_aegis_shellopts, id="shellopts-aegis"),
    pytest.param(_mutate_workflow_bashopts, id="bashopts-workflow"),
    pytest.param(_mutate_aegis_bashopts, id="bashopts-aegis"),
    pytest.param(_mutate_workflow_bash_env, id="bash-env-workflow"),
    pytest.param(_mutate_aegis_bash_env, id="bash-env-aegis"),
    pytest.param(_mutate_bracket_selector, id="bracket-selector"),
])
def test_test_fast_allowlist_rejects_a_narrowed_gate(mutate):
    """Each narrowed copy of validate.yml fails the guard. The shipped file is left untouched."""
    workflow = copy.deepcopy(_load("validate.yml"))
    mutate(workflow)
    with pytest.raises(AssertionError):
        _guard_test_fast_allowlist(workflow)


def test_test_fast_shards_select_every_test_file_exactly_once():
    """Directory selectors cover tests/ once: a gap or an overlap would hide a failure or run it twice."""
    jobs = _fast_jobs()
    assert 3 <= len(jobs) <= 4, [name for name, _job in jobs]
    files = _suite_test_files()
    assert files, "the suite has test files"
    owned = {}
    for name, job in jobs:
        selectors = _shard_paths(job)
        assert selectors, name
        for selector in selectors:
            assert selector.startswith("tests/") and ".." not in selector.split("/"), selector
            hit = _selected_test_files(selector, files)
            assert hit, (name, selector)
            for path in hit:
                owned.setdefault(path, []).append((name, selector))
    gap = [path for path in files if path not in owned]
    overlap = [(path, who) for path, who in owned.items() if len(who) > 1]
    assert gap == [] and overlap == [], (gap[:20], overlap[:20])


def test_every_test_fast_shard_is_required_and_a_bad_shard_is_refused():
    """A shard missing from ALWAYS_SUCCESS, or cancelled, must fail the required check.

    Shards do not need each other, so they run concurrently. aegis-check still runs when one
    fails (``if: always()``) and refuses that result. All shards succeeding is the retry path.
    """
    workflow = _load("validate.yml")
    names = [name for name, _job in _fast_jobs(workflow)]
    assert 3 <= len(names) <= 4, names
    check = workflow["jobs"]["aegis-check"]
    assert check.get("if") == "always()"
    needs = check["needs"]
    if isinstance(needs, str):
        needs = [needs]
    always = check["steps"][0]["env"]["ALWAYS_SUCCESS"].split()
    assert sorted(always) == sorted(names) and len(always) == len(set(always))
    assert set(names) <= set(needs)
    verdict_needs = workflow["jobs"]["verdict"]["needs"]
    if isinstance(verdict_needs, str):
        verdict_needs = [verdict_needs]
    assert set(names) <= set(verdict_needs)
    for name, job in _fast_jobs(workflow):
        assert "needs" not in job and "if" not in job, name
        text = "\n".join(step.get("run", "") for step in job.get("steps", []))
        assert "make test" not in text, name
        assert "$TEST_FAST_PATHS" in text, name
    for name, job in workflow["jobs"].items():
        blob = "\n".join(step.get("run", "") for step in job.get("steps", []))
        runs_suite = "make test" in blob or "-m pytest" in blob
        if runs_suite and job.get("if") != FULL_VALIDATION:
            assert name in names, name
    success = {name: {"result": "success"} for name in names}
    proc = _run_upstream_gate("skipped", {**success, **_windows_results("skipped")})
    assert proc.returncode == 0, proc.stderr
    for target in names:
        others = {name: {"result": "success"} for name in names if name != target}
        others.update(_windows_results("success"))
        for result in ("failure", "cancelled", "skipped"):
            proc = _run_upstream_gate("success", dict(others, **{target: {"result": result}}))
            assert proc.returncode != 0 and target in proc.stderr, (target, result, proc.stderr)
        proc = _run_upstream_gate("success", others)
        assert proc.returncode != 0 and target in proc.stderr, (target, proc.stderr)


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
        lines = [line for line in text.splitlines()
                 if re.search(rf"pip install\b.*\b{re.escape(tool)}\b", line)]
        assert lines, f"no pip install line for {tool}"
        for line in lines:
            assert re.search(rf"\b{re.escape(tool)}==\d+(\.\d+)+\b", line), line


# --- B3: the pytest suite runs on Windows -----------------------------------
# One unsharded `python -m pytest tests/` job hit the 90 minute cap on run 44710278932
# before producing a result. Shards use the test-fast positive paths. tests/unit/core is
# split on _CORE_PIVOT because that directory is about half the suite. Each core shard
# states that half and resolves the files from the checkout at job start. An empty
# result fails. Directory selectors of the other shards stay as they are. Language
# acceptance stays one job per Python version so the Go/P6/AC24 steps are not repeated
# on every shard.

_WINDOWS_PENDING = "Windows job wall clocks pending (run 45089040698 interim)."
_WINDOWS_MEASUREMENT_PREFIX = "# test-windows-measurement: "
_WINDOWS_MEASURED_VALUE = re.compile(r"([1-9][0-9]{0,8})s run ([1-9][0-9]{0,19})")
_WINDOWS_SUITE_RUN = "\n".join([
    "set -euo pipefail",
    "set -f",
    'if [ -z "${TEST_WINDOWS_PATHS}" ]; then',
    '  echo "TEST_WINDOWS_PATHS is empty" >&2',
    "  exit 1",
    "fi",
    "python -c \"import os; os.makedirs(os.environ['USERPROFILE'], exist_ok=True)\"",
    "# Positive paths only. Selectors are the words in TEST_WINDOWS_PATHS.",
    "python -m pytest -q -n auto $TEST_WINDOWS_PATHS",
]) + "\n"
# One command for both tests/unit/core shards. The half is the env value le or gt:
# basename <= pivot, or the complement. The command reads the checkout at job start
# and fails when the half is empty. It does not list file names in the workflow.
_WINDOWS_CORE_RUN = """set -euo pipefail
# Pass each resolved file as one argument, including names with spaces.
python - <<'PYTHON'
import os

root = os.environ["TEST_WINDOWS_CORE_DIR"]
pivot = os.environ["TEST_WINDOWS_CORE_PIVOT"]
half = os.environ["TEST_WINDOWS_CORE_HALF"]
if half not in ("le", "gt"):
    raise SystemExit("Invalid Windows core half")

def walk_failed(_error):
    raise SystemExit("Could not enumerate Windows core tests")

paths = []
if os.path.isdir(root):
    for directory, children, files in os.walk(root, onerror=walk_failed):
        children[:] = [name for name in children if name not in ("__pycache__", ".pytest_cache")]
        for name in files:
            if not (name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))):
                continue
            if (name <= pivot) == (half == "le"):
                paths.append(os.path.join(directory, name).replace(os.sep, "/"))
if not paths:
    raise SystemExit("TEST_WINDOWS_PATHS is empty")

os.makedirs(os.environ["USERPROFILE"], exist_ok=True)
import pytest

raise SystemExit(pytest.main(["-q", "-n", "auto", "--", *sorted(paths)]))
PYTHON
"""
_WINDOWS_CORE_HALVES = {
    "test-windows-unit-core-a": "le",
    "test-windows-unit-core-b": "gt",
}
# SHA-256 of each complete parsed acceptance step from the unsharded job,
# with mapping keys sorted so YAML comments and key order are immaterial.
_LANGUAGE_ACCEPTANCE_STEPS = (
    ("Prepare clean tracked source for language acceptance", "2d3731738d2cc6c385b0f0733953c836b877e1c5eafb9eed8b6f7bdd4661ca1b"),
    ("Verify real Go CLI cache and generated hooks", "643ccfc5ab161572b630e17771d7c86ab9f4238815f161587d82fea31697454b"),
    ("Verify junction creation with a restricted effective token", "e493e23294cf6fc82dc6f040265873a4c6f76f59c2ad982f72892d32dda8c161"),
    ("Curate Go and P6 acceptance JSON and logs", "3c523721665823fa9f6a86903faad6436ebee4e2dfdc25b0290371370b57f407"),
    ("Preserve Go and P6 acceptance JSON and logs", "2ab0d18f37f8a2eb6b056eef5cbc9dc9f952795f9f78d8861742a979d5042f56"),
    ("Record existing Node for AC24 acceptance", "899c0680d346aff5a35484c0a35da4785da694be4882091aa805898b764588ef"),
    ("Acquire the complete locked M0 Windows test fixture", "66974dc5f766b36796370940324138244c343187254edc021c32dcb77df00a2e"),
    ("Verify real Vitest Windows snapshot junction", "ca96b384319f8500d28d923fb9ea47c60326ebff6a67e7e95eb6eb51a61ede53"),
    ("Preserve AC24 acquisition and acceptance evidence", "ee4be8f3aa6a66b0b7228f38a50acab49f7706c674921e2fdbbab75abda7101e"),
)


def _windows_jobs(workflow=None):
    jobs = (workflow if workflow is not None else _load("validate.yml"))["jobs"]
    missing = [name for name in _WINDOWS_JOBS if name not in jobs]
    assert missing == [], missing
    return [(name, jobs[name]) for name in _WINDOWS_JOBS]


def _windows_pytest_jobs(workflow=None):
    return [(name, job) for name, job in _windows_jobs(workflow) if name in _WINDOWS_PYTEST_JOBS]


def _recorded_windows_measurements(text):
    recorded = {}
    for line in text.splitlines():
        if not line.startswith(_WINDOWS_MEASUREMENT_PREFIX):
            continue
        job, version, evidence = line[len(_WINDOWS_MEASUREMENT_PREFIX):].split(" ", 2)
        key = (job, version)
        assert key not in recorded, f"duplicate Windows budget result: {key}"
        if evidence == _WINDOWS_PENDING:
            recorded[key] = None
        else:
            match = _WINDOWS_MEASURED_VALUE.fullmatch(evidence)
            assert match, f"invalid Windows budget evidence: {key}"
            recorded[key] = (int(match[1]), match[2])
    assert set(recorded) == {
        (job, version) for job in _WINDOWS_JOBS for version in _WINDOWS_PYTHON_VERSIONS
    }, "Windows budget evidence must cover each required job and Python version"
    return recorded


def _guard_windows_timeouts(workflow, text):
    records = _recorded_windows_measurements(text)
    for name, job in _windows_jobs(workflow):
        legs = [records[name, version] for version in _WINDOWS_PYTHON_VERSIONS]
        measured = [leg[0] for leg in legs if leg is not None]
        floor = max(45, _minimum_timeout_minutes(max(measured, default=0)))
        assert floor <= 360, f"{name} needs repartitioning"
        if None in legs:
            provisional = (WINDOWS_LANGUAGE_TIMEOUT_MINUTES if name == _WINDOWS_LANGUAGE_JOB
                           else WINDOWS_PYTEST_TIMEOUT_MINUTES)
            floor = max(floor, provisional)
        timeout = job.get("timeout-minutes")
        assert type(timeout) is int and floor <= timeout <= 360, (name, timeout, floor)


def _canonical_windows_pytest_job(selectors, timeout):
    """One Windows pytest shard. Only TEST_WINDOWS_PATHS changes."""
    return {
        "if": FULL_VALIDATION,
        "needs": "build-wheel",
        "runs-on": "windows-latest",
        "timeout-minutes": timeout,
        "strategy": {"fail-fast": False, "matrix": {"python-version": list(_WINDOWS_PYTHON_VERSIONS)}},
        "defaults": {"run": {"shell": "bash"}},
        "steps": [
            {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
             "with": {"persist-credentials": False}},
            {"name": "Set up Python",
             "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
             "with": {"python-version": "${{ matrix.python-version }}"}},
            {"name": "Download wheel artifact",
             "uses": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
             "with": {"name": "aegis-wheel", "path": "dist/"}},
            {"name": "Verify artifact digests",
             "run": "python .github/scripts/verify_dist.py verify dist"},
            {"name": "Install test dependencies",
             "run": "pip install pytest==8.3.4 pytest-xdist==3.6.1 ruff==0.9.10 hypothesis==6.126.0 "
                    "coverage==7.6.12 pyyaml==6.0.2 anyio==4.12.1\n"
                    "pip install dist/*.whl\n"},
            {"name": "Run test suite",
             "env": {
                 "HOME": "${{ runner.temp }}\\aegis-home",
                 "USERPROFILE": "${{ runner.temp }}\\aegis-home",
                 "PYTHONUTF8": "0",
                 "TEST_WINDOWS_PATHS": selectors,
             },
             "run": _WINDOWS_SUITE_RUN,
            },
        ],
    }


def _canonical_windows_core_job(half, timeout):
    """One tests/unit/core shard. The run command is fixed. Only the half changes."""
    assert half in ("le", "gt")
    job = _canonical_windows_pytest_job("tests/unit/core", timeout)
    step = _suite_step(job)
    step["env"] = {
        "HOME": "${{ runner.temp }}\\aegis-home",
        "USERPROFILE": "${{ runner.temp }}\\aegis-home",
        "PYTHONUTF8": "0",
        "TEST_WINDOWS_CORE_DIR": "tests/unit/core",
        "TEST_WINDOWS_CORE_PIVOT": _CORE_PIVOT,
        "TEST_WINDOWS_CORE_HALF": half,
    }
    step["run"] = _WINDOWS_CORE_RUN
    return job


def _core_paths_for_half(files, half, pivot=_CORE_PIVOT):
    """Basenames <= pivot, or the complement. The same rule the core command uses."""
    core = _selected_test_files("tests/unit/core", files)
    if half == "le":
        return [path for path in core if path.split("/")[-1] <= pivot]
    if half == "gt":
        return [path for path in core if path.split("/")[-1] > pivot]
    raise AssertionError(half)


def _expected_directory_selectors(workflow):
    """Directory selectors of the shards that are not the tests/unit/core split."""
    fast = dict(_fast_jobs(workflow))
    assert _selector_text(fast["test-fast-unit-core"]) == "tests/unit/core"
    return {
        "test-windows-unit-rest": _selector_text(fast["test-fast-unit-rest"]),
        "test-windows-integration": _selector_text(fast["test-fast-integration"]),
        "test-windows-contract": _selector_text(fast["test-fast-contract"]),
    }


_VALIDATE_LEGS = (
    ("ubuntu-24.04", "3.9"), ("ubuntu-latest", "3.11"),
    ("macos-latest", "3.9"), ("macos-latest", "3.11"),
)
_VALIDATE_SHARDS = ("unit-core-a", "unit-core-b", "unit-rest", "integration", "contract")
_VALIDATE_CHECKS = (
    "Smoke-test installed wheel (source hidden)", "Lint",
    "Run Layer 1 Deterministic Verification", "Check for hardcoded paths",
)
_VALIDATE_MEASUREMENT_PREFIX = "# validate-measurement: "
_VALIDATE_PYTEST_ARGS = ["-n", "auto", "--durations=25", "--"]


def _guard_validate_timeouts(job, workflow_text):
    cap = job["timeout-minutes"]
    assert type(cap) is int and 45 <= cap <= 360
    rows = [line[len(_VALIDATE_MEASUREMENT_PREFIX):] for line in workflow_text.splitlines()
            if line.startswith(_VALIDATE_MEASUREMENT_PREFIX)]
    if rows == ["pending"]:
        assert cap == 360, "keep the maximum cap until every validate job has a hosted measurement"
        return
    measured = {}
    for row in rows:
        runner, version, shard, evidence = row.split(" ", 3)
        match = _WINDOWS_MEASURED_VALUE.fullmatch(evidence)
        key = (runner, version, shard)
        assert match and key not in measured, row
        measured[key] = int(match[1])
    assert set(measured) == {
        (runner, version, shard) for runner, version in _VALIDATE_LEGS
        for shard in (*_VALIDATE_SHARDS, "checks")
    }
    for key, seconds in measured.items():
        assert cap >= _minimum_timeout_minutes(seconds), (key, seconds, cap)


def test_validate_budget_keeps_all_targets_shards_and_checks_required():
    jobs = _load("validate.yml")["jobs"]
    job = jobs["validate"]
    assert job["strategy"] == {
        "fail-fast": False,
        "matrix": {
            "leg": [{"os": runner, "python-version": version} for runner, version in _VALIDATE_LEGS],
            "shard": [*_VALIDATE_SHARDS, "checks"],
        },
    }
    assert job["runs-on"] == "${{ matrix.leg.os }}"
    assert _step_using(job, "actions/setup-python")[0]["with"]["python-version"] == "${{ matrix.leg.python-version }}"
    assert job["needs"] == ["build-wheel", "dependency-audit"]
    assert all("validate" in jobs[name]["needs"] for name in ("aegis-check", "verdict"))
    assert "continue-on-error" not in job
    conditional = {step["name"]: step["if"] for step in job["steps"] if "if" in step}
    assert conditional == {
        **dict.fromkeys(_VALIDATE_CHECKS, "matrix.shard == 'checks'"),
        "Install bubblewrap": "runner.os == 'Linux' && matrix.shard != 'checks'",
        "Prove bubblewrap runs": "runner.os == 'Linux' && matrix.shard != 'checks'",
        "Run test suite": "matrix.shard != 'checks'",
    }
    assert all("continue-on-error" not in step for step in job["steps"])
    suite = _suite_step(job)
    assert suite["env"]["TEST_VALIDATE_SHARD"] == "${{ matrix.shard }}"
    assert suite["shell"] == "bash"
    _guard_validate_timeouts(job, _read("validate.yml"))


def test_validate_cap_covers_every_completed_job_including_setup():
    rows = [f"{_VALIDATE_MEASUREMENT_PREFIX}{runner} {version} {shard} 10800s run 123"
            for runner, version in _VALIDATE_LEGS for shard in (*_VALIDATE_SHARDS, "checks")]
    job = {"timeout-minutes": 360}
    _guard_validate_timeouts(job, "\n".join(rows))
    with pytest.raises(AssertionError, match="10801"):
        _guard_validate_timeouts(job, "\n".join(rows).replace("3.9 integration 10800", "3.9 integration 10801"))
    with pytest.raises(AssertionError):
        _guard_validate_timeouts(job, "\n".join(rows[:-1]))


def _validate_suite_command():
    step = _suite_step(_load("validate.yml")["jobs"]["validate"])
    preamble, opening, body = step["run"].partition(" <<'PYTHON'\n")
    command, closing, end = body.rpartition("\nPYTHON\n")
    assert opening and closing and not end
    assert preamble.splitlines() == [
        "set -euo pipefail",
        'userbase="${PYTHONUSERBASE:-$(python -c \'import site; print(site.getuserbase())\')}"',
        'home="$(mktemp -d /tmp/aegis-test-home.XXXXXX)"',
        "trap 'rm -rf \"$home\"' EXIT",
        'HOME="$home" USERPROFILE="$home" XDG_CONFIG_HOME="$home/.config" PYTHONUSERBASE="$userbase" python -',
    ]
    return step["env"], command


def _run_validate_selector(shard, cwd, pytest_argv_probe):
    variables, command = _validate_suite_command()
    return subprocess.run(
        [sys.executable, "-"], input=command, cwd=cwd,
        env=dict(os.environ, PYTHONPATH=pytest_argv_probe, TEST_VALIDATE_SHARD=shard,
                 TEST_VALIDATE_UNIT_REST=variables["TEST_VALIDATE_UNIT_REST"]),
        capture_output=True, text=True, timeout=30,
    )


def test_validate_shards_run_the_whole_suite_exactly_once_with_duration_reporting(pytest_argv_probe):
    files = _suite_test_files()
    expected_paths = _expected_directory_selectors(_load("validate.yml"))
    covered = []
    for shard in _VALIDATE_SHARDS:
        proc = _run_validate_selector(shard, REPO_ROOT, pytest_argv_probe)
        assert proc.returncode == 87, proc.stderr
        argv = json.loads(proc.stdout)
        assert argv[:len(_VALIDATE_PYTEST_ARGS)] == _VALIDATE_PYTEST_ARGS
        selectors = argv[len(_VALIDATE_PYTEST_ARGS):]
        if shard.startswith("unit-core-"):
            assert selectors == _core_paths_for_half(files, "le" if shard == "unit-core-a" else "gt")
        else:
            assert selectors == expected_paths[f"test-windows-{shard}"].split()
            assert all(_positive_selector(selector, files) for selector in selectors)
        assert selectors
        for selector in selectors:
            covered.extend(_selected_test_files(selector, files))
    assert sorted(covered) == files


@pytest.mark.parametrize("shard,message", [
    ("unit-core-a", "Validate shard has no test paths"),
    ("unit-core-b", "Validate shard has no test paths"),
    ("unknown", "Invalid validate shard"),
])
def test_validate_selector_refuses_empty_core_half_or_unknown_shard(shard, message, tmp_path, pytest_argv_probe):
    proc = _run_validate_selector(shard, tmp_path, pytest_argv_probe)
    assert (proc.returncode, proc.stdout, proc.stderr.strip()) == (1, "", message)


@pytest.mark.skipif(os.name != "posix", reason="validate suite uses a POSIX temporary HOME")
def test_validate_suite_keeps_arguments_and_cleans_home_on_failure_and_retry(bash, tmp_path):
    root = tmp_path / "tests" / "unit" / "core"
    root.mkdir(parents=True)
    (root / "test_a spaced.py").touch()
    (tmp_path / "pytest.py").write_text(
        "import json, os\n"
        "def main(args):\n"
        "    print(json.dumps([args, *(os.environ[key] for key in "
        "('HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'PYTHONUSERBASE'))]))\n"
        "    return 87\n",
        encoding="utf-8",
    )
    run = _suite_step(_load("validate.yml")["jobs"]["validate"])["run"]
    # Replay the real mktemp/trap under the fixture-owned directory.
    run = run.replace(" /tmp/aegis-test-home.XXXXXX", ' "$TEST_TMP/aegis-test-home.XXXXXX"')
    homes = []
    for init, preset in (("unset PYTHONUSERBASE\n", None), ("", str(tmp_path / "preset user base"))):
        proc = _run_windows_suite_script(
            bash, init + run, tmp_path, TEST_TMP=str(tmp_path), TEST_VALIDATE_SHARD="unit-core-a",
            PYTHONUSERBASE=preset or "",
        )
        assert proc.returncode == 87, proc.stderr
        args, home, profile, config, userbase = json.loads(proc.stdout)
        assert args == [*_VALIDATE_PYTEST_ARGS, "tests/unit/core/test_a spaced.py"]
        assert home == profile and Path(config) == Path(home) / ".config"
        assert Path(home).parent == tmp_path and not Path(home).exists()
        assert userbase and userbase != home
        if preset is not None:
            assert userbase == preset
        homes.append(home)
    assert len(set(homes)) == 2


def _guard_windows_language(job):
    expected = _canonical_windows_pytest_job("", job.get("timeout-minutes"))
    expected["steps"].pop()
    expected["steps"].extend([
            {"name": "Smoke-test installed wheel (source hidden)",
             "run": 'SMOKE="$PWD/.github/scripts/wheel_smoke.py"\n'
                    'cd "$RUNNER_TEMP" && env -u PYTHONPATH python -I "$SMOKE"\n'},
            {"name": "Run Layer 1 Deterministic Verification",
             "run": "python -m aegis_cli.cli check"},
    ])
    common_count = len(expected["steps"])
    assert dict(job, steps=job["steps"][:common_count]) == expected
    acceptance_steps = []
    for step in job["steps"][common_count:]:
        encoded = json.dumps(step, sort_keys=True, separators=(",", ":")).encode("ascii")
        acceptance_steps.append((step.get("name"), hashlib.sha256(encoded).hexdigest()))
    assert tuple(acceptance_steps) == _LANGUAGE_ACCEPTANCE_STEPS, "Windows language acceptance steps changed"


def _guard_windows_budget(workflow):
    """Whole-job equality for every pytest shard, and a total partition of tests/.

    tests/unit/core shards state a pivot half and resolve files from the checkout.
    The other shards keep directory selectors. A narrowed command, a dropped path,
    an overlap, or a shard that waits on another shard is a different job. The
    language job runs the Windows acceptance steps once and does not collect pytest.
    """
    assert "env" not in workflow and "defaults" not in workflow
    _guard_windows_timeouts(workflow, _read("validate.yml"))
    files = _suite_test_files()
    directory_selectors = _expected_directory_selectors(workflow)
    owned = {}
    for name, job in _windows_pytest_jobs(workflow):
        assert not job.get("continue-on-error"), name
        for step in job["steps"]:
            assert not step.get("continue-on-error") and "|| true" not in step.get("run", ""), (name, step)
        if name in _WINDOWS_CORE_HALVES:
            half = _WINDOWS_CORE_HALVES[name]
            step = _suite_step(job)
            env = step.get("env") or {}
            assert env.get("TEST_WINDOWS_CORE_HALF") == half, name
            assert "TEST_WINDOWS_PATHS" not in env, name
            assert job == _canonical_windows_core_job(half, job["timeout-minutes"]), name
            expected = _core_paths_for_half(files, half)
            assert expected, name
            for path in expected:
                owned.setdefault(path, []).append(name)
            continue
        raw = (_suite_step(job).get("env") or {}).get("TEST_WINDOWS_PATHS")
        assert raw == directory_selectors[name], name
        assert job == _canonical_windows_pytest_job(raw, job["timeout-minutes"]), name
        for selector in raw.split():
            assert _positive_selector(selector, files), (name, selector)
            for path in _selected_test_files(selector, files):
                owned.setdefault(path, []).append(name)
    gap = [path for path in files if path not in owned]
    overlap = [path for path, who in owned.items() if len(who) > 1]
    assert gap == [] and overlap == [], (gap[:20], overlap[:20])
    _guard_windows_language(workflow["jobs"][_WINDOWS_LANGUAGE_JOB])
    return owned


def test_windows_test_job_runs_on_windows_latest():
    for name, job in _windows_jobs():
        assert job["runs-on"] == "windows-latest", name
        assert job["strategy"]["matrix"]["python-version"] == list(_WINDOWS_PYTHON_VERSIONS)


def test_windows_test_job_runs_the_whole_suite_and_fails_on_failure():
    """The pytest shards together select every test file once. A failure fails that shard.

    The two tests/unit/core shards recompute their halves from the tree. Neither half
    is empty, and a file added later lands in exactly one half.
    """
    workflow = _load("validate.yml")
    owned = _guard_windows_budget(workflow)
    assert set(owned) == set(_suite_test_files())


def _run_windows_suite_script(bash, script, cwd, **variables):
    """Run the shipped Bash step using this pytest worker's Python."""
    env = dict(os.environ, **variables, AEGIS_TEST_PYTHON=Path(sys.executable).as_posix())
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-c", 'python() { "$AEGIS_TEST_PYTHON" "$@"; }\n' + script],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=30,
    )


def test_windows_workflow_contract_does_not_require_shell_on_path(tmp_path):
    check = (
        "import runpy, sys; contract = runpy.run_path(sys.argv[1]); "
        "contract['_guard_windows_budget'](contract['_load']('validate.yml'))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", check, str(Path(__file__).resolve())],
        cwd=REPO_ROOT, env=dict(os.environ, PATH=str(tmp_path)),
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.fixture
def pytest_argv_probe(tmp_path):
    probe = tmp_path / "argv probe"
    probe.mkdir()
    (probe / "pytest.py").write_text(
        "import json, sys\n"
        "def main(args):\n"
        "    print(json.dumps(args))\n"
        "    return 87\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    return str(probe)


@pytest.mark.parametrize("job_name,filename", [
    ("test-windows-unit-core-a", "test_a spaced.py"),
    ("test-windows-unit-core-b", "test_z spaced.py"),
], ids=["core-a", "core-b"])
def test_windows_core_passes_spaced_paths_as_distinct_pytest_arguments(
    bash, tmp_path, pytest_argv_probe, job_name, filename,
):
    root = tmp_path / "checkout with spaces" / "core tests"
    root.mkdir(parents=True)
    for name in ("test_a spaced.py", _CORE_PIVOT, "test_z spaced.py", "helper.py"):
        (root / name).touch()
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / filename).touch()
    step = _suite_step(_load("validate.yml")["jobs"][job_name])
    proc = _run_windows_suite_script(
        bash, step["run"], tmp_path, PATH=str(tmp_path), PYTHONPATH=pytest_argv_probe,
        USERPROFILE=str(tmp_path / "test profile"),
        TEST_WINDOWS_CORE_DIR=root.as_posix(), TEST_WINDOWS_CORE_PIVOT=_CORE_PIVOT,
        TEST_WINDOWS_CORE_HALF=step["env"]["TEST_WINDOWS_CORE_HALF"],
    )
    assert proc.returncode == 87, proc.stderr
    names = [filename, _CORE_PIVOT] if job_name.endswith("-a") else [filename]
    assert json.loads(proc.stdout) == [
        "-q", "-n", "auto", "--", *sorted((root / name).as_posix() for name in names)
    ]


@pytest.mark.parametrize("job_name", _WINDOWS_CORE_HALVES)
def test_windows_core_resolver_matches_checkout(bash, tmp_path, pytest_argv_probe, job_name):
    step = _suite_step(_load("validate.yml")["jobs"][job_name])
    half = _WINDOWS_CORE_HALVES[job_name]
    proc = _run_windows_suite_script(
        bash, step["run"], REPO_ROOT, PATH=str(tmp_path), PYTHONPATH=pytest_argv_probe,
        USERPROFILE=str(tmp_path / "test profile"),
        TEST_WINDOWS_CORE_DIR=step["env"]["TEST_WINDOWS_CORE_DIR"],
        TEST_WINDOWS_CORE_PIVOT=step["env"]["TEST_WINDOWS_CORE_PIVOT"],
        TEST_WINDOWS_CORE_HALF=half,
    )
    assert proc.returncode == 87, proc.stderr
    paths = _core_paths_for_half(_suite_test_files(), half)
    assert paths
    assert json.loads(proc.stdout) == ["-q", "-n", "auto", "--", *paths]


@pytest.mark.parametrize("version", _WINDOWS_PYTHON_VERSIONS)
def test_windows_budget_has_a_record_for_every_job_on_each_python_version(version):
    rows = _read("validate.yml").splitlines()
    for name in _WINDOWS_JOBS:
        prefix = f"# test-windows-measurement: {name} {version} "
        assert sum(line.startswith(prefix) for line in rows) == 1, (name, version)


def test_windows_language_rejects_extra_collection_inside_an_existing_step():
    workflow = _load("validate.yml")
    language = workflow["jobs"][_WINDOWS_LANGUAGE_JOB]
    step = next(step for step in language["steps"] if "p6_noadmin.py" in step.get("run", ""))
    step["run"] += "pytest tests/ -q\n"
    with pytest.raises(AssertionError, match="acceptance steps"):
        _guard_windows_language(language)


@pytest.mark.parametrize("expected", ["success", "skipped"])
@pytest.mark.parametrize("job_name", _WINDOWS_JOBS)
def test_required_check_refuses_a_missing_windows_result(job_name, expected):
    needs = _windows_results(expected)
    del needs[job_name]
    needs.update({name: {"result": "success"} for name, _job in _fast_jobs()})
    proc = _run_upstream_gate(expected, needs)
    assert proc.returncode != 0 and job_name in proc.stderr, proc.stderr


# The jobs that run the suite: the matrix, every Windows shard, and aegis-check, whose
# `check --ci` reruns the head commit's trailer snapshot and must be able to collect what
# the others collect (R-trust-a3).
TEST_JOBS = ("validate", *_WINDOWS_JOBS, "aegis-check")
INSTALL_STEP = "Install test dependencies"


def _install_step(job):
    return next((s for s in job.get("steps", []) if s.get("name") == INSTALL_STEP), None)


def _divergent_installs(jobs):
    """Test jobs whose install step is missing or differs from the validate job's text."""
    want = (_install_step(jobs["validate"]) or {}).get("run")
    return [name for name in TEST_JOBS if want is None or (_install_step(jobs[name]) or {}).get("run") != want]


def test_the_test_jobs_install_identical_test_dependencies():
    assert _divergent_installs(_load("validate.yml")["jobs"]) == []
    for name, job in _windows_jobs():
        assert job.get("needs") == "build-wheel", name


def test_a_package_dropped_from_one_install_copy_fails_the_comparison():
    jobs = _load("validate.yml")["jobs"]
    step = _install_step(jobs["aegis-check"])
    assert step is not None and " hypothesis==" in step["run"]
    step["run"] = step["run"].replace(" hypothesis==6.126.0", "")
    assert _divergent_installs(jobs) == ["aegis-check"]


def test_windows_test_job_isolates_home_and_userprofile():
    """BUG-010: tests must never touch the runner's real profile."""
    for name, job in _windows_pytest_jobs():
        env = _suite_step(job).get("env") or {}
        for var in ("HOME", "USERPROFILE"):
            assert "runner.temp" in str(env.get(var, "")), (name, var)
        assert env["HOME"] == env["USERPROFILE"]


def test_windows_test_job_keeps_the_legacy_console_encoding():
    """PYTHONUTF8=0 keeps cp1252 stdio/locale defaults exercised (BUG-012, BUG-038)."""
    for name, job in _windows_pytest_jobs():
        assert str((_suite_step(job).get("env") or {}).get("PYTHONUTF8")) == "0", name


def test_windows_test_job_actions_are_pinned_and_credentials_not_persisted():
    for name, job in _windows_jobs():
        refs = [step["uses"] for step in job["steps"] if "uses" in step]
        assert refs and all(SHA_REF.match(ref) for ref in refs), (name, refs)
        checkouts = _step_using(job, "actions/checkout")
        assert checkouts, name
        assert all((step.get("with") or {}).get("persist-credentials") is False for step in checkouts)


def test_windows_test_job_uses_bash_and_verifies_the_artifact():
    for name, job in _windows_jobs():
        # `pip install dist/*.whl` relies on bash glob expansion (pwsh/cmd won't).
        assert job.get("defaults", {}).get("run", {}).get("shell") == "bash", name
        runs = [step.get("run", "") for step in job["steps"]]
        verified = runs.index("python .github/scripts/verify_dist.py verify dist")
        installs = [i for i, run in enumerate(runs) if "pip install dist/*.whl" in run]
        assert installs and all(verified < i for i in installs), name


def _windows_budget_fixture(measurements):
    return "\n".join(
        f"{_WINDOWS_MEASUREMENT_PREFIX}{name} {version} {measurements.get((name, version), _WINDOWS_PENDING)}"
        for name in _WINDOWS_JOBS for version in _WINDOWS_PYTHON_VERSIONS
    )


@pytest.mark.parametrize("slow_version", _WINDOWS_PYTHON_VERSIONS)
def test_windows_timeout_uses_the_slower_measured_python_leg(slow_version):
    workflow = _load("validate.yml")
    name = _WINDOWS_LANGUAGE_JOB
    evidence = _windows_budget_fixture({
        (name, version): f"{1501 if version == slow_version else 100}s run 12345678"
        for version in _WINDOWS_PYTHON_VERSIONS
    })
    for windows_name, job in _windows_pytest_jobs(workflow):
        job["timeout-minutes"] = WINDOWS_PYTEST_TIMEOUT_MINUTES
    job = workflow["jobs"][name]
    job["timeout-minutes"] = 50
    with pytest.raises(AssertionError, match=name):
        _guard_windows_timeouts(workflow, evidence)
    job["timeout-minutes"] = 51
    _guard_windows_timeouts(workflow, evidence)

    oversized = evidence.replace(f"{name} {slow_version} 1501s", f"{name} {slow_version} 10801s")
    job["timeout-minutes"] = 360
    with pytest.raises(AssertionError, match="needs repartitioning"):
        _guard_windows_timeouts(workflow, oversized)


def test_a_pending_windows_leg_does_not_qualify_a_lower_cap():
    workflow = _load("validate.yml")
    name = _WINDOWS_PYTEST_JOBS[0]
    evidence = _windows_budget_fixture({(name, "3.9"): "600s run 12345678"})
    workflow["jobs"][name]["timeout-minutes"] = WINDOWS_PYTEST_TIMEOUT_MINUTES - 1
    with pytest.raises(AssertionError, match=name):
        _guard_windows_timeouts(workflow, evidence)


def test_windows_budget_rejects_a_timeout_below_the_measured_floor():
    target = "test-windows-unit-core-b"
    workflow = {"jobs": {
        name: {"timeout-minutes": 45} for name in _WINDOWS_JOBS
    }}
    measurements = {
        (name, version): "100s run 12345678"
        for name in _WINDOWS_JOBS for version in _WINDOWS_PYTHON_VERSIONS
    }
    measurements[target, "3.9"] = "2100s run 12345678"
    measurements[target, "3.12"] = "2400s run 12345678"
    evidence = _windows_budget_fixture(measurements)
    floor = 80  # Twice the slower leg of 2,400 seconds, in minutes.
    job = workflow["jobs"][target]
    job["timeout-minutes"] = floor
    _guard_windows_timeouts(workflow, evidence)
    job["timeout-minutes"] = floor - 1
    refusal = re.escape(str((target, floor - 1, floor)))
    with pytest.raises(AssertionError, match=refusal):
        _guard_windows_timeouts(workflow, evidence)


@pytest.mark.parametrize("job_name", (*_WINDOWS_CORE_HALVES, "test-windows-unit-rest"))
def test_windows_suite_script_refuses_an_empty_selector(bash, tmp_path, pytest_argv_probe, job_name):
    step = _suite_step(_load("validate.yml")["jobs"][job_name])
    root = tmp_path / "core tests"
    root.mkdir()
    half = _WINDOWS_CORE_HALVES.get(job_name)
    # A nonempty directory can still have an empty half.
    (root / ("test_z.py" if half == "le" else "test_a.py")).touch()
    proc = _run_windows_suite_script(
        bash, step["run"], tmp_path, PATH=str(tmp_path), PYTHONPATH=pytest_argv_probe,
        USERPROFILE=str(tmp_path / "test profile"), TEST_WINDOWS_PATHS="",
        TEST_WINDOWS_CORE_DIR=root.as_posix(), TEST_WINDOWS_CORE_PIVOT=_CORE_PIVOT,
        TEST_WINDOWS_CORE_HALF=half or "",
    )
    assert proc.returncode == 1
    assert proc.stderr.strip() == "TEST_WINDOWS_PATHS is empty"
    assert proc.stdout == ""


# Run 45089040698: each test-fast shard exited 1 in under a second with no pytest output.
# `python -m site --user-base` exits 1 in a venv (user site disabled). Under `set -euo pipefail`
# that status aborts the suite step before pytest. The stub below has that shape.
_VENV_PYTHON_FUNCTION = """venv_python() {
  if [ "$#" -eq 3 ] && [ "$1" = "-m" ] && [ "$2" = "site" ] && [ "$3" = "--user-base" ]; then
    echo /tmp/venv-disabled-user-base
    return 1
  fi
  if [ "$#" -eq 2 ] && [ "$1" = "-c" ] && [ "$2" = "import site; print(site.getuserbase())" ]; then
    echo /tmp/venv-disabled-user-base
    return 0
  fi
  return 1
}
"""
_VENV_PYTHON_STUB = "#!/bin/sh\n" + _VENV_PYTHON_FUNCTION + 'venv_python "$@"\n'
_FAILED_VENV_PYTHON = """venv_python() {
  echo "fixture interpreter failed" >&2
  return 73
}
"""
_PYTEST_REACHED = "PYTEST_COMMAND_REACHED"


def _preamble_before_pytest(script):
    """The suite script up to, but not including, the pytest invocation."""
    needle = '"$python_bin" -m pytest'
    at = script.find(needle)
    assert at != -1, "suite script has no pytest command"
    return script[:at] + 'printf "%s\\n" ' + _PYTEST_REACHED + ' "$userbase"\n'


def _run_fast_user_base(bash, script, interpreter, pythonuserbase):
    # Include the shipped shell options and user-base assignment. HOME allocation
    # and cleanup belong to the full POSIX replay.
    preamble, home_assignment, _ = script.partition('\nhome="')
    assert home_assignment, "suite script has no home assignment"
    binding = 'python_bin="$VENV/bin/python"\n'
    assert preamble.count(binding) == 1, "suite preamble must bind the venv interpreter once"
    preamble = preamble.replace(binding, "python_bin=venv_python\n", 1)
    env = {"PATH": ""}
    if "SystemRoot" in os.environ:
        env["SystemRoot"] = os.environ["SystemRoot"]
    if pythonuserbase is not None:
        env["PYTHONUSERBASE"] = pythonuserbase
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-c", interpreter + preamble + '\nprintf "%s\\n" "$userbase"\n'],
        env=env, capture_output=True, text=True, timeout=10,
    )


def _write_venv_stub(path, stub):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(stub.encode("ascii"))


def _probe_fast_preamble(root, env, platform):
    if platform != "posix" or not os.access("/bin/sh", os.X_OK):
        pytest.skip("test-fast preamble requires a POSIX /bin/sh")
    python = root / "bin" / "python"
    _write_venv_stub(python, "#!/bin/sh\nexit 0\n")
    try:
        python.chmod(0o755)
        subprocess.run([str(python)], env=env, capture_output=True, check=True, timeout=10)
    except PermissionError:
        pytest.skip("test-fast preamble requires permission to execute a fixture stub")
    for tool in ("mktemp", "rm"):
        if shutil.which(tool, path=env["PATH"]) is None:
            pytest.skip(f"test-fast preamble requires {tool} on the subprocess PATH")
    return python


@pytest.fixture(scope="module")
def fast_preamble(bash, tmp_path_factory):
    root = tmp_path_factory.mktemp("fast-preamble")
    env = {"PATH": os.defpath, "VENV": str(root), "HOME": str(root), "TMPDIR": str(root)}
    return bash, _probe_fast_preamble(root, env, os.name), env


def _run_suite_preamble(bash, script, python, env):
    _write_venv_stub(python, _VENV_PYTHON_STUB)
    # Keep the real mktemp/trap behavior in a fixture-owned directory.
    mktemp = (
        'mktemp() {\n'
        '  [ "$#" -eq 2 ] && [ "$1" = -d ] && [ "$2" = /tmp/aegis-test-home.XXXXXX ] || return 64\n'
        '  command mktemp -d "$TMPDIR/${2##*/}"\n'
        '}\n'
    )
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-c", mktemp + _preamble_before_pytest(script)],
        env=env, capture_output=True, text=True, timeout=10,
    )


def test_fast_stub_writer_uses_lf(tmp_path):
    stub = tmp_path / "bin" / "python"
    _write_venv_stub(stub, _VENV_PYTHON_STUB)
    data = stub.read_bytes()
    assert data == _VENV_PYTHON_STUB.encode("ascii")
    assert data.startswith(b"#!/bin/sh\n")


def test_fast_preamble_requires_posix_shell(tmp_path):
    with pytest.raises(pytest.skip.Exception, match="requires a POSIX /bin/sh"):
        _probe_fast_preamble(tmp_path, {}, "nt")


@pytest.mark.parametrize("name", _FAST_SHARDS)
def test_fast_suite_user_base_contract(name):
    script = _suite_step(_load("validate.yml")["jobs"][name])["run"]
    assert script == _CANONICAL_SUITE_RUN


@pytest.mark.parametrize("name", _FAST_SHARDS)
@pytest.mark.parametrize("interpreter, pythonuserbase, status, stdout, stderr", [
    pytest.param(_VENV_PYTHON_FUNCTION, None, 0, "/tmp/venv-disabled-user-base\n", "", id="unset"),
    pytest.param(_FAILED_VENV_PYTHON, "/preset/user-base", 0, "/preset/user-base\n", "", id="preset"),
    pytest.param(_FAILED_VENV_PYTHON, None, 73, "", "fixture interpreter failed\n", id="interpreter-failure"),
])
def test_fast_suite_user_base_behavior(bash, name, interpreter, pythonuserbase, status, stdout, stderr):
    script = _suite_step(_load("validate.yml")["jobs"][name])["run"]
    proc = _run_fast_user_base(bash, script, interpreter, pythonuserbase)
    assert proc.returncode == status, proc.stderr
    assert proc.stdout == stdout
    assert proc.stderr == stderr


def test_fast_suite_preamble_reaches_pytest_when_user_site_is_disabled(fast_preamble):
    bash, python, env = fast_preamble
    # The script-equality check pins this preamble on every shard.
    script = _suite_step(_load("validate.yml")["jobs"][_FAST_SHARDS[0]])["run"]
    proc = _run_suite_preamble(bash, script, python, env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [_PYTEST_REACHED, "/tmp/venv-disabled-user-base"]


def test_a_cancelled_windows_shard_fails_the_required_check():
    """Shards do not need each other. One cancelled shard still fails the required check.

    All shards succeeding is the retry path. On a wave PR the Windows jobs are skipped
    and the fast shards must still succeed.
    """
    workflow = _load("validate.yml")
    windows = [name for name, _job in _windows_jobs(workflow)]
    fast = [name for name, _job in _fast_jobs(workflow)]
    check = workflow["jobs"]["aegis-check"]
    assert check.get("if") == "always()"
    needs = check["needs"]
    assert set(windows) <= set(needs)
    always = check["steps"][0]["env"]["ALWAYS_SUCCESS"].split()
    assert not set(windows) & set(always)
    verdict = workflow["jobs"]["verdict"]["needs"]
    assert set(windows) <= set(verdict)
    full = {name: {"result": "success"} for name in fast + windows}
    assert _run_upstream_gate("success", full).returncode == 0
    for target in windows:
        bad = dict(full)
        bad[target] = {"result": "cancelled"}
        proc = _run_upstream_gate("success", bad)
        assert proc.returncode != 0 and target in proc.stderr, (target, proc.stderr)
        failed = dict(full)
        failed[target] = {"result": "failure"}
        proc = _run_upstream_gate("success", failed)
        assert proc.returncode != 0 and target in proc.stderr, (target, proc.stderr)
    wave = {name: {"result": "success"} for name in fast}
    wave.update({name: {"result": "skipped"} for name in windows})
    assert _run_upstream_gate("skipped", wave).returncode == 0
    surprised = dict(wave)
    surprised[windows[0]] = {"result": "success"}
    proc = _run_upstream_gate("skipped", surprised)
    assert proc.returncode != 0 and windows[0] in proc.stderr


def _mutate_windows_deselect(workflow):
    step = _suite_step(workflow["jobs"]["test-windows-unit-rest"])
    step["run"] = step["run"].replace(
        "python -m pytest -q -n auto $TEST_WINDOWS_PATHS",
        "python -m pytest -q -n auto --deselect tests/unit/cli $TEST_WINDOWS_PATHS",
        1)


def _mutate_windows_k(workflow):
    step = _suite_step(workflow["jobs"]["test-windows-integration"])
    step["run"] = step["run"].replace(
        "python -m pytest -q -n auto $TEST_WINDOWS_PATHS",
        "python -m pytest -q -n auto -k smoke $TEST_WINDOWS_PATHS",
        1)


def _mutate_windows_ignore(workflow):
    step = _suite_step(workflow["jobs"]["test-windows-contract"])
    step["run"] = step["run"].replace(
        "python -m pytest -q -n auto $TEST_WINDOWS_PATHS",
        "python -m pytest -q -n auto --ignore tests/contract $TEST_WINDOWS_PATHS",
        1)


def _mutate_windows_continue(workflow):
    workflow["jobs"]["test-windows-contract"]["continue-on-error"] = True


def _mutate_windows_drop_path(workflow):
    step = _suite_step(workflow["jobs"]["test-windows-unit-rest"])
    paths = step["env"]["TEST_WINDOWS_PATHS"].split()
    assert len(paths) > 1
    step["env"]["TEST_WINDOWS_PATHS"] = " ".join(paths[1:])


def _mutate_windows_overlap(workflow):
    step = _suite_step(workflow["jobs"]["test-windows-integration"])
    step["env"]["TEST_WINDOWS_PATHS"] += " tests/unit/core/" + _CORE_PIVOT


def _mutate_windows_language_pytest(workflow):
    workflow["jobs"][_WINDOWS_LANGUAGE_JOB]["steps"].append(
        {"name": "Run test suite", "run": "python -m pytest tests/ -q\n"})


def _mutate_windows_needs_shard(workflow):
    workflow["jobs"]["test-windows-contract"]["needs"] = ["build-wheel", "test-windows-unit-core-a"]


def _mutate_windows_empty(workflow):
    _suite_step(workflow["jobs"]["test-windows-contract"])["env"]["TEST_WINDOWS_PATHS"] = ""


def _mutate_windows_remove_pipefail(workflow):
    step = _suite_step(workflow["jobs"]["test-windows-unit-rest"])
    step["run"] = step["run"].replace("set -euo pipefail\n", "", 1)


@pytest.mark.parametrize("mutate", [
    pytest.param(_mutate_windows_deselect, id="deselect"),
    pytest.param(_mutate_windows_k, id="k-smoke"),
    pytest.param(_mutate_windows_ignore, id="ignore"),
    pytest.param(_mutate_windows_continue, id="continue-on-error"),
    pytest.param(_mutate_windows_drop_path, id="drop-path"),
    pytest.param(_mutate_windows_overlap, id="overlap"),
    pytest.param(_mutate_windows_language_pytest, id="language-pytest"),
    pytest.param(_mutate_windows_needs_shard, id="needs-another-shard"),
    pytest.param(_mutate_windows_empty, id="empty-selector"),
    pytest.param(_mutate_windows_remove_pipefail, id="no-pipefail"),
])
def test_windows_budget_rejects_a_narrowed_shard(mutate):
    """Each narrowed copy fails the guard. The shipped file is left untouched."""
    workflow = copy.deepcopy(_load("validate.yml"))
    mutate(workflow)
    with pytest.raises(AssertionError):
        _guard_windows_budget(workflow)


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
    assert jobs["validate"]["timeout-minutes"] >= 45
    for name in _WINDOWS_JOBS:
        assert jobs[name]["timeout-minutes"] >= 45, name


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


def test_windows_runs_one_wheel_smoke_and_layer_one_check_per_python_version():
    for name, job in _windows_jobs():
        runs = [step.get("run", "") for step in job["steps"]]
        smoke = [run for run in runs if "wheel_smoke.py" in run]
        layer_one = [run for run in runs if "-m aegis_cli.cli check" in run]
        expected = int(name == _WINDOWS_LANGUAGE_JOB)
        assert len(smoke) == len(layer_one) == expected, name
        if smoke:
            assert 'cd "$RUNNER_TEMP" && env -u PYTHONPATH python -I "$SMOKE"' in smoke[0]


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
# counts such a job as the required Aegis check (workflow_jobs.skip_why). A run with nothing to compare
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
