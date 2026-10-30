from pathlib import Path
"""Release-integrity regression tests (v0.89 audit fixes).

v0.89.0 reused one build artifact but (a) ran every test from the checkout,
where ``pythonpath = ["."]`` lets source modules shadow the installed wheel,
(b) installed only ``ls dist/*.whl | head -n 1``, and (c) published
``dist/*`` — including an sdist that was never tested — with no digest check.
"""
import os
import subprocess
import sys
import zipfile
import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
VERIFY_DIST = os.path.join(REPO_ROOT, ".github", "scripts", "verify_dist.py")
SMOKE = os.path.join(REPO_ROOT, ".github", "scripts", "wheel_smoke.py")


def _load(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _runs(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


def _verify(*args):
    return subprocess.run([sys.executable, VERIFY_DIST, *args],
                          capture_output=True, text=True, timeout=60)


def _dist(tmp_path, extra=(), metadata=""):
    d = tmp_path / "dist"
    d.mkdir()
    with zipfile.ZipFile(d / "soma_governance-0.0.0-py3-none-any.whl", "w") as wheel:
        for name in ("__init__.py", "ts_ast.js", "rust_ast.py", "go_ast.go", "go.mod"):
            wheel.writestr("aegis_core/ast/drivers/templates/" + name, "")
        wheel.writestr("aegis_guardrails-0.0.0.dist-info/METADATA",
                       "Metadata-Version: 2.1\nName: aegis-guardrails\nVersion: 0.0.0\n"
                       "Provides-Extra: dev\nRequires-Dist: pytest; extra == 'dev'\n" + metadata)
        for name in extra:
            wheel.writestr(name, "injected")
    (d / "soma_governance-0.0.0.tar.gz").write_bytes(b"sdist bytes")
    return d


def test_publish_never_rebuilds_and_verifies_digests():
    publish = _load("publish.yml")["jobs"]["publish"]
    runs = _runs(publish)
    assert "python -m build" not in runs, "publish must not rebuild the artifact"
    assert "verify_dist.py verify dist" in runs
    assert "twine upload dist/*" not in runs, "publish must upload only verified files"
    assert "needs" in publish and "validate" in str(publish["needs"])


def test_digest_verification_failure_cannot_be_masked_by_a_pipe():
    """`verify ... | tee` exits 0 when verify fails (no pipefail by default)."""
    for workflow, job in (("publish.yml", "publish"), ("validate.yml", "validate"),
                          ("validate.yml", "build-wheel")):
        for step in _load(workflow)["jobs"][job]["steps"]:
            run = step.get("run", "")
            if "verify_dist.py" not in run:
                continue
            for line in run.splitlines():
                if "verify_dist.py" in line:
                    assert "|" not in line, f"{workflow}:{job} pipes verify_dist output: {line}"


def test_build_records_digests_and_smoke_tests_sdist():
    build = _load("validate.yml")["jobs"]["build-wheel"]
    runs = _runs(build)
    assert "verify_dist.py record dist" in runs
    assert "wheel_smoke.py" in runs and "-I" in runs, "sdist must be smoke-tested"


def test_validate_matrix_smoke_tests_wheel_source_hidden():
    validate = _load("validate.yml")["jobs"]["validate"]
    runs = _runs(validate)
    assert "verify_dist.py verify dist" in runs
    assert "head -n 1" not in runs, "must install the single verified wheel, not the first match"
    smoke = [s.get("run", "") for s in validate["steps"] if "wheel_smoke.py" in s.get("run", "")]
    assert smoke, "matrix must smoke-test the installed wheel"
    assert "env -u PYTHONPATH" in smoke[0] and "python -I" in smoke[0]
    assert 'cd "$RUNNER_TEMP"' in smoke[0], "smoke must run outside the checkout"


def test_verify_dist_accepts_recorded_artifacts(tmp_path):
    d = _dist(tmp_path)
    assert _verify("record", str(d)).returncode == 0
    proc = _verify("verify", str(d))
    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout.split()) == 2


@pytest.mark.parametrize("prefix", ["", "licenses/"])
def test_verify_dist_accepts_packaged_first_party_license_and_notice(tmp_path, prefix):
    d = _dist(tmp_path, extra=["aegis_guardrails-0.0.0.dist-info/" + prefix + name
                               for name in ("LICENSE", "NOTICE")],
              metadata="License-File: LICENSE\nLicense-File: NOTICE\n")
    proc = _verify("record", str(d))
    assert proc.returncode == 0, proc.stderr
    proc = _verify("verify", str(d))
    assert proc.returncode == 0 and len(proc.stdout.split()) == 2, proc.stderr


def test_verify_dist_rejects_tampered_artifact(tmp_path):
    d = _dist(tmp_path)
    assert _verify("record", str(d)).returncode == 0
    with open(d / "soma_governance-0.0.0-py3-none-any.whl", "ab") as f:
        f.write(b"tampered")
    proc = _verify("verify", str(d))
    assert proc.returncode == 1 and "sha256" in proc.stderr


def test_verify_dist_rejects_unlisted_artifact(tmp_path):
    d = _dist(tmp_path)
    assert _verify("record", str(d)).returncode == 0
    (d / "soma_governance-0.0.1-py3-none-any.whl").write_bytes(b"other")
    assert _verify("verify", str(d)).returncode == 1


@pytest.mark.parametrize("name", [
    "aegis_core/node_modules/x.py", "aegis_core/vendor/x.py", "aegis_core/third_party/x.py",
    "aegis_core/x.so", "aegis_core/x.pyd", "aegis_core/x.dll", "aegis_core/x.dylib",
    "aegis_core/x.wasm", "aegis_core/x.node", "aegis_core/x.jar", "aegis_core/x.js",
    "aegis_core/ast/drivers/templates/extra.py", "aegis_core/ast/drivers/templates/nested/x.go",
    "aegis_core/unexpected.json", "foreign/__init__.py", "../aegis_core/x.py",
    "aegis_core/../x.py", "aegis_core\\x.py", "aegis_core/_data/rules/injected.md",
    "aegis_guardrails-0.0.0.dist-info/vendor.py",
    "aegis_core//x.py", "aegis_guardrails-9.9.9.dist-info/WHEEL",
])
def test_record_rejects_injected_wheel_members_before_signing(tmp_path, name):
    d = _dist(tmp_path, extra=[name])
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "wheel member" in proc.stderr, proc.stderr
    assert not (d / "SHA256SUMS").exists()


@pytest.mark.parametrize("metadata", [
    "Requires-Dist: requests\n", "Provides-Extra: parser\n",
    "Requires-Dist: requests; extra == 'dev' or python_version > '3'\n",
    "Requires-Dist: requests; extra == 'parser'\n",
])
def test_record_rejects_runtime_dependencies_and_foreign_extras(tmp_path, metadata):
    proc = _verify("record", str(_dist(tmp_path, metadata=metadata)))
    assert proc.returncode == 1 and "wheel metadata" in proc.stderr, proc.stderr


def test_verify_rechecks_contents_even_with_matching_digests(tmp_path):
    import hashlib

    d = _dist(tmp_path, extra=["aegis_core/vendor/x.py"])
    (d / "SHA256SUMS").write_text("".join(
        hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in sorted(d.iterdir())),
        encoding="utf-8")
    proc = _verify("verify", str(d))
    assert proc.returncode == 1 and "wheel member" in proc.stderr, proc.stderr


def test_record_rejects_a_missing_phase_template(tmp_path):
    d = _dist(tmp_path)
    path = next(d.glob("*.whl"))
    with zipfile.ZipFile(path) as wheel:
        members = {name: wheel.read(name) for name in wheel.namelist() if not name.endswith("/ts_ast.js")}
    with zipfile.ZipFile(path, "w") as wheel:
        for name, content in members.items():
            wheel.writestr(name, content)
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "template allowlist" in proc.stderr, proc.stderr


def test_record_rejects_a_corrupt_wheel(tmp_path):
    d = _dist(tmp_path)
    next(d.glob("*.whl")).write_bytes(b"not a zip")
    proc = _verify("record", str(d))
    assert proc.returncode == 1 and "invalid wheel" in proc.stderr, proc.stderr


def test_build_runs_the_source_and_offline_go_gate_before_building():
    steps = _load("validate.yml")["jobs"]["build-wheel"]["steps"]
    gate = [i for i, step in enumerate(steps) if "check_zero_dependencies.py" in step.get("run", "")]
    assert len(gate) == 1
    assert gate[0] < next(i for i, step in enumerate(steps) if "python -m build" in step.get("run", ""))
    run = steps[gate[0]]["run"]
    assert "check_zero_dependencies.py source ." in run and "check_zero_dependencies.py go ." in run
    assert "continue-on-error" not in steps[gate[0]] and "||" not in run


def test_wheel_smoke_refuses_when_source_can_shadow_site_packages():
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    proc = subprocess.run([sys.executable, "-I", SMOKE], capture_output=True,
                          text=True, timeout=60, env=env)
    assert proc.returncode == 1 and "PYTHONPATH" in proc.stderr
    env.pop("PYTHONPATH")
    proc = subprocess.run([sys.executable, SMOKE], capture_output=True,
                          text=True, timeout=60, env=env, cwd=REPO_ROOT)
    assert proc.returncode == 1 and "-I" in proc.stderr
