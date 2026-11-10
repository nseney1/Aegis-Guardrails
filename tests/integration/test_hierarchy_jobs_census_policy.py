"""Reviewed recipes control outside load; ledger reservations always retain their slots."""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

from tests.integration import test_hierarchy_jobs as job_fixtures
from tests.integration import test_hierarchy_jobs_derive as derive_fixtures
from tests.integration.test_hierarchy_jobs import add_initiative, load_jobs_module, verified_evidence
from tests.integration.test_hierarchy_jobs import pytestmark as pytestmark
from tests.integration.test_hierarchy_jobs_derive import edit_source, request_derive


shop = job_fixtures.shop
claude_shop = derive_fixtures.claude_shop
KINDS = ("heavy", "heavy-tests")
PIDS = [103, 101, 102]
POLICY_ERROR = "invalid census_outside_policy: expected count, report or ignore"
POLICIES = [None, "count", "report", "ignore"]


@pytest.fixture
def policy_shop(tmp_path_factory):
    return job_fixtures.Shop(tmp_path_factory.mktemp("census-0500-" + uuid.uuid4().hex))


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("target", ["own", "other-initiative", "other-runner", "manual",
                                    "lower-priority", "inactive", "blocked", "other-kind"])
def test_shared_store_relaxation_only_admits_this_pass_next_holder(policy_shop, policy, target):
    shop = policy_shop
    if target != "own":
        initiative = "pilot" if target == "other-runner" else "urgent"
        if initiative != "pilot":
            options = {}
            if target == "blocked":
                shop.workspace.register("blocker")
                options["blocked_by"] = ["blocker"]
            shop.workspace.register(initiative, priority=99 if target == "lower-priority" else 1, **options)
        holder = "manual-holder" if target == "manual" else "job:" + initiative + "/other-runner"
        # This request precedes A's request, including when B shares A's initiative.
        shop.workspace.run("request", {"initiative": initiative, "kind": "writer" if target == "other-kind" else "heavy",
                                       "holder": holder})
        if target == "inactive":
            shop.workspace.run("update", {"initiative": initiative, "source": "owner", "state": "paused"})
    request_heavy_jobs(shop, "heavy", policy)
    foreign_first = target in ("other-initiative", "other-runner", "manual")
    relaxed = policy in ("report", "ignore") and not foreign_first
    rows = shop.run_open("--initiative", "pilot", census=PIDS, expect=0 if relaxed else 3)["rows"]
    row = next(row for row in rows if row.get("job") == "pilot/job-1")
    if relaxed:
        assert row["state"] == "completed"
        assert result_for(shop)["capacity"] == grant_view(policy, PIDS)
        assert "outside_policy_applied" not in row["z_census"]
    else:
        assert row["state"] == "waiting" and row["reason"] == "capacity_full"
        assert not any(event["kind"] == "grant" for event in shop.events())
        assert not (shop.workspace.store / "jobs" / "pilot" / "job-1" / "claim.json").exists()
        if policy is None:
            assert "z_census" not in row
            assert row["capacity"]["external_roots"] == sorted(PIDS)
        else:
            expected = expected_summary("count", PIDS)
            if policy in ("report", "ignore"):
                expected["outside_policy_applied"] = "count"
            assert row["z_census"] == expected


@pytest.mark.parametrize("policy", POLICIES)
def test_check_recipes_makes_explicit_policy_reviewable_and_preserves_absent_bytes(policy_shop, policy):
    shop = policy_shop
    if policy is not None:
        shop.recipes["census_outside_policy"] = policy
    shop.save_recipes()
    expected = {"recipes_sha256": hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest(),
                "recipes": {name: {"kind": recipe["kind"], "heavy": name == "heavy", "heavy_tests": False,
                                    "sandbox": "none", "require_clean": False, "expects_tests": False,
                                    "export_git": False} for name, recipe in shop.recipes["recipes"].items()}}
    if policy is not None:
        expected["census_outside_policy"] = policy
    if policy in ("report", "ignore"):
        expected["census_outside_policy_non_default"] = True
    result = subprocess.run(shop.argv("check-recipes"), capture_output=True, text=True, timeout=30, env=shop.env())
    assert result.returncode == 0 and result.stderr == ""
    assert result.stdout == json.dumps(expected, sort_keys=True) + "\n"


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("expectation", ["absent", "match", "mismatch", "short", "non-hex", "uppercase"])
def test_run_open_checks_expected_recipes_hash_before_any_job_or_ledger_change(policy_shop, policy, expectation):
    shop = policy_shop
    request_heavy_jobs(shop, "heavy", policy)
    digest = hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()
    value = {"match": digest, "mismatch": "0" * 64, "short": digest[:-1],
             "non-hex": "g" * 64, "uppercase": digest.upper()}.get(expectation)
    flags = [] if expectation == "absent" else ["--expect-recipes-sha256", value]
    before = {path.name: path.read_bytes() for path in (shop.workspace.store / "events").iterdir()}
    allowed = expectation in ("absent", "match")
    answer = shop.run_open(*flags, census=[101], expect=0 if allowed else 2)
    if allowed:
        assert answer["rows"][0]["state"] == "completed"
        assert result_for(shop)["recipes_sha256"] == digest
    else:
        error = ("recipes changed since team init; re-run the reviewed team init" if expectation == "mismatch"
                 else "invalid expected recipes sha256")
        assert answer == {"error": error}
        assert {path.name: path.read_bytes() for path in (shop.workspace.store / "events").iterdir()} == before
        assert not (shop.workspace.store / "jobs" / "pilot" / "job-1").exists()
        assert shop.states("job-1") == []


@pytest.fixture(autouse=True)
def bounded_fixture_git_init(monkeypatch):
    # A real git init exceeded the shared helper's 10-second deadline during setup, before any job ran.
    # Give only that fixture command a bounded 60 seconds. No retry and no production timeout changes.
    original = subprocess.run
    fixture_prefix = ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                      "-c", "commit.gpgsign=false", "init"]

    def run(command, *args, **kwargs):
        if isinstance(command, list) and command[:8] == fixture_prefix and kwargs.get("timeout") == 10:
            kwargs["timeout"] = 60
        return original(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)


def job_request_id(shop, holder="job:pilot/job-1"):
    return next(event["data"]["request_id"] for event in shop.events()
                if event["kind"] == "request" and event["data"]["holder"] == holder)


def result_for(shop, identifier="pilot/job-1"):
    return json.loads((shop.workspace.store / "jobs" / identifier / "result.json").read_bytes())


def grant_view(policy, pids=(101,), held=0):
    view = {"limit": 3, "held": held, "external_roots": sorted(pids) if policy == "count" else [],
            "census": "none" if policy == "ignore" else "fixture", "outside_policy": policy}
    if policy != "ignore":
        view["outside"] = outside_rows(pids, "heavy")[:64]
        if len(pids) > 64:
            view["outside_truncated"] = len(pids) - 64
    return view


def expected_summary(policy, pids=(), limit=3, held=0, request_id=None, census="fixture"):
    summary = {"outside_policy": policy, "census": "none" if policy == "ignore" else census,
               "limit": limit, "held": held, "external_roots_count": len(pids) if policy == "count" else 0,
               "outside_count": len(pids) if policy != "ignore" else 0,
               "outside_truncated": max(0, len(pids) - 64) if policy != "ignore" else 0}
    if request_id is not None:
        summary["request_id"] = request_id
    return summary


def manual_grant(shop, policy):
    request_heavy_jobs(shop, "heavy", policy)
    request = shop.workspace.run("request", {"initiative": "pilot", "kind": "heavy", "holder": "job:pilot/job-1"})["request"]
    shop.workspace.run("grant-next", kind="heavy")
    return request


def other_heavy_kind(kind):
    return "heavy-tests" if kind == "heavy" else "heavy"


def kind_request_id(shop, kind, holder="job:pilot/job-1"):
    """job_request_id returns the holder's first request; this one names the kind as well."""
    found = [event["data"]["request_id"] for event in shop.events()
             if event["kind"] == "request" and event["data"]["holder"] == holder and event["data"]["kind"] == kind]
    assert len(found) == 1, found
    return found[0]


@pytest.mark.parametrize("state", ["granted", "queued"])
@pytest.mark.parametrize("other", ["writer", "other-heavy"])
@pytest.mark.parametrize("kind", KINDS)
def test_explicit_count_counts_outside_roots_for_a_job_holding_only_another_kind(policy_shop, kind, other, state):
    shop = policy_shop
    other = other_heavy_kind(kind) if other == "other-heavy" else other
    request_heavy_jobs(shop, kind, "count")
    other_request = shop.workspace.ask("pilot", other, "job:pilot/job-1")
    if state == "granted":
        assert shop.workspace.grant(other)["request_id"] == other_request
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    pids = PIDS[:limit]
    row = shop.run_open(census={"external_roots": {kind: pids}}, expect=3)["rows"][0]
    if other in KINDS and state == "granted":
        assert (row["state"], row["reason"], row["request_id"]) == ("waiting", "stale_grant", other_request)
        assert shop.receipts("job-1") == []
        assert not (shop.workspace.store / "jobs" / "pilot" / "job-1").exists()
        assert not any(event["kind"] == "request" and event["data"]["kind"] == kind
                       for event in shop.events()), "no second kind while the stale grant is held"
        return
    assert (row["state"], row["reason"]) == ("waiting", "capacity_full")
    assert row["z_census"] == expected_summary("count", pids, limit=limit), "outside roots were counted"
    assert not (shop.workspace.store / "jobs" / "pilot" / "job-1").exists()
    assert shop.receipts("job-1") == [] and not (shop.workspace.store / "census").exists()
    request_id = kind_request_id(shop, kind)
    assert not any(event["kind"] == "grant" and event["data"]["request_id"] == request_id for event in shop.events())


@pytest.mark.parametrize("other", ["writer", "heavy-tests"])
def test_a_job_holding_another_kind_is_granted_with_census_and_audit_once_outside_load_leaves(policy_shop, other):
    shop = policy_shop
    request_heavy_jobs(shop, "heavy", "count")
    other_request = shop.workspace.ask("pilot", other, "job:pilot/job-1")
    assert shop.workspace.grant(other)["request_id"] == other_request
    assert shop.run_open(census=PIDS, expect=3)["rows"][0]["reason"] == (
        "stale_grant" if other == "heavy-tests" else "capacity_full")
    if other == "heavy-tests":
        shop.workspace.release(other_request)
    row = shop.run_open(census=[101])["rows"][0]
    assert row["state"] == "completed"
    request_id = kind_request_id(shop, "heavy")
    assert result_for(shop)["capacity"] == grant_view("count", [101])
    assert row["z_census"] == expected_summary("count", [101], request_id=request_id)
    record = json.loads((shop.workspace.store / "census" / (request_id + ".json")).read_bytes())
    assert record == {"request_id": request_id, "holder": "job:pilot/job-1", "kind": "heavy",
                      "capacity": grant_view("count", [101])}
    assert not (shop.workspace.store / "census" / (other_request + ".json")).exists()


@pytest.mark.parametrize("action", ["refuse", "execute"])
@pytest.mark.parametrize("policy", POLICIES)
def test_a_foreign_initiatives_grant_under_the_jobs_holder_never_supplies_its_audit(policy_shop, policy, action):
    shop = policy_shop
    request_heavy_jobs(shop, "heavy", policy)
    shop.workspace.register("intruder")
    foreign = shop.workspace.ask("intruder", "heavy", "job:pilot/job-1")
    assert shop.workspace.grant("heavy")["request_id"] == foreign
    # A well-formed record for the foreign grant, as its own runner would publish it.
    folder = shop.workspace.store / "census"
    folder.mkdir()
    (folder / (foreign + ".json")).write_text(json.dumps({
        "request_id": foreign, "holder": "job:pilot/job-1", "kind": "heavy", "capacity": grant_view("count")}))
    if action == "refuse":
        (shop.checkout / "src" / "app.py").write_text("changed = True\n")
        row = shop.run_open()["rows"][0]
        assert row["state"] == "refused" and "z_census" not in row
        assert "capacity" not in result_for(shop), "another initiative's grant record is not this job's audit"
    else:
        row = shop.run_open(census=[101], expect=3)["rows"][0]
        assert (row["state"], row["reason"], row["request_id"]) == ("waiting", "holder_conflict", foreign)
        assert "z_census" not in row and not (shop.workspace.store / "jobs" / "pilot" / "job-1").exists()
    assert sorted(path.name for path in folder.iterdir()) == [foreign + ".json"]
    assert not any(event["kind"] in ("release", "withdraw") for event in shop.events())


def crash_after_claim(shop):
    argv = shop.argv("run-open", census=[101])
    driver = ("import os, sys; sys.path.insert(0, sys.argv[1]); import hierarchy_jobs as jobs\n"
              "original = os.link\n"
              "def link(source, target, *args, **kwargs):\n"
              "    answer = original(source, target, *args, **kwargs)\n"
              "    if str(target).endswith('/claim.json'): os._exit(87)\n"
              "    return answer\n"
              "os.link = link\n"
              "raise SystemExit(jobs.main(sys.argv[2:]))\n")
    child = subprocess.run([sys.executable, "-I", "-c", driver, str(Path(argv[2]).parent), *argv[3:]],
                           capture_output=True, text=True, timeout=30, env=shop.env())
    # Exit 87 is possible only if the os.link injection fired after publishing the real claim.
    assert child.returncode == 87 and child.stderr == ""


@pytest.mark.parametrize("policy", [None, "report"])
@pytest.mark.parametrize("unrelated_record", [False, True])
@pytest.mark.parametrize("case", ["queued-dependency", "changed-checkout", "unknown-recipe", "bad-packet",
                                 "other-kind-only", "two-applicable"])
def test_refusal_audit_requires_this_jobs_applicable_grants(shop, policy, unrelated_record, case):
    if policy is not None:
        shop.recipes["census_outside_policy"] = policy
    shop.save_recipes()
    if case == "queued-dependency":
        parent = shop.request_job("first-check", "ok")
        shop.run_open()
        shop.request_job("job-1", "heavy", raw=json.dumps({
            "schema": "aegis.hierarchy-job-packet/v2", "recipe": "heavy", **shop.head(),
            "recipes_sha256": hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest(),
            "after": {"message_id": "first-check", "sha256": parent["sha256"]}}))
        for number in range(3):
            shop.workspace.run("request", {"initiative": "pilot", "kind": "heavy", "holder": "held-%d" % number})
            shop.workspace.run("grant-next", kind="heavy")
        assert shop.run_open(expect=3)["rows"][0]["reason"] == "capacity_full"
        (shop.workspace.store / "jobs" / "pilot" / "first-check" / "step-1.log").write_text("changed evidence")
    elif case == "unknown-recipe":
        shop.request_job("job-1", "unknown")
    elif case == "bad-packet":
        shop.request_job("job-1", "heavy", raw="not json")
    else:
        shop.request_job("job-1", "heavy")
        if case == "other-kind-only":
            shop.workspace.run("request", {"initiative": "pilot", "kind": "writer", "holder": "job:pilot/job-1"})
            shop.workspace.run("grant-next", kind="writer")
        if case != "two-applicable":
            (shop.checkout / "src" / "app.py").write_text("changed = True\n")
    if unrelated_record:
        folder = shop.workspace.store / "census"
        folder.mkdir()
        (folder / "req-99999999.json").write_text(json.dumps({
            "request_id": "req-99999999", "holder": "job:pilot/other-job", "kind": "heavy",
            "capacity": grant_view("report")}))
    jobs = load_jobs_module()
    if case == "two-applicable":
        # A valid ledger forbids duplicate same-kind holders. Exercise its defensive audit-cache boundary
        # through the public refusal API, without changing accounting or mocking Store.load.
        store = jobs.Store(str(shop.workspace.store))
        initiative = store.load().initiative("pilot")
        message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
        job = jobs.Job(str(shop.workspace.store), initiative, message)
        job.census_kind = "heavy"
        job.census_requests = [{"request_id": request_id, "holder": job.holder, "kind": "heavy", "state": "granted"}
                               for request_id in ("req-99999997", "req-99999998")]
        row = jobs.refuse(store, job, "fixture refusal", 0,
                          hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest(), outside_policy=policy)
    else:
        row = shop.run_open()["rows"][0]
    assert row["state"] == "refused"
    result_path = shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json"
    raw = result_path.read_bytes()
    result = json.loads(raw)
    if case == "two-applicable" and policy is not None:
        assert result["capacity"]["reason"] == row["z_census"]["reason"] == "ambiguous_grant"
    else:
        assert "capacity" not in result and "z_census" not in row
        expected_row = {"job": "pilot/job-1", "state": "refused", "exit_code": None,
                        "result": str(result_path), "reason": row["reason"]}
        expected_result = {"schema": "aegis.hierarchy-job-result/v1", "job": "pilot/job-1", "state": "refused",
                           "exit_code": None, "reason": row["reason"], "recipe": None, "steps": [], "before": None,
                           "after": None, "commit": None, "finished_at": result["finished_at"],
                           "recipes_sha256": hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest()}
        # Both directory variants share these exact legacy bytes, apart from the observed timestamp/path.
        assert json.dumps(row, sort_keys=True) == json.dumps(expected_row, sort_keys=True)
        assert raw == (json.dumps(expected_result, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("bad_id", [None, "../x", "req-1/../../y", "req-１２３４５６７８", "réq-00000001", "r" * 1000],
                         ids=["canonical", "traversal", "nested-traversal", "full-width", "non-ascii", "oversize"])
@pytest.mark.parametrize("action", ["execute", "resolve", "granted-elsewhere"])
def test_ledger_request_ids_never_escape_into_audit_output(shop, monkeypatch, capsys, bad_id, action):
    request_heavy_jobs(shop, "heavy", "report")
    holder, initiative = "job:pilot/job-1", "pilot"
    if action == "granted-elsewhere":
        shop.workspace.register("urgent", priority=1)
        holder, initiative = "manual-holder", "urgent"
    request = shop.workspace.run("request", {"initiative": initiative, "kind": "heavy", "holder": holder})["request"]
    if bad_id is not None:
        for path in (shop.workspace.store / "events").iterdir():
            event = json.loads(path.read_bytes())
            if event["kind"] == "request" and event["data"]["request_id"] == request["request_id"]:
                event["data"]["request_id"] = bad_id
                path.write_text(json.dumps(event))
    if action == "resolve":
        crash_after_claim(shop)
        # Exercise historical lookup even when publication rejected the malformed ID without creating a directory.
        (shop.workspace.store / "census").mkdir(exist_ok=True)
    original_open = os.open
    opened = []

    def open_file(path, flags, *args, **kwargs):
        opened.append(str(path))
        return original_open(path, flags, *args, **kwargs)

    jobs = load_jobs_module()
    monkeypatch.setattr(os, "open", open_file)
    if action == "resolve":
        argv = shop.argv("resolve", "--job", "pilot/job-1", "--reason", "claim-only runner stopped")[3:]
    else:
        argv = shop.argv("run-open", census=[101])[3:]
    assert jobs.main(argv) == (3 if action == "granted-elsewhere" else 0)
    answer = json.loads(capsys.readouterr().out)
    assert opened  # The OS observation seam must actually be reached.
    rows = answer["rows"] if "rows" in answer else [answer]
    target = next((row for row in rows if row["state"] == "granted_elsewhere"), rows[0])
    expected_id = request["request_id"] if bad_id is None else "invalid_request_id"
    for row in rows:
        if "z_census" in row:
            assert len(json.dumps(row["z_census"], sort_keys=True)) <= 384
    if action == "granted-elsewhere":
        assert target["request_id"] == target["z_census"]["request_id"] == expected_id
    elif "z_census" in target:
        assert target["z_census"]["request_id"] == expected_id
    if bad_id is not None:
        assert bad_id not in json.dumps(answer, ensure_ascii=False)
        assert not any(bad_id in path for path in opened)
        assert bad_id not in json.dumps(result_for(shop), ensure_ascii=False)
    else:
        assert (shop.workspace.store / "census" / (expected_id + ".json")).is_file()


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("fault", [errno.EACCES, errno.ENOSPC, errno.EXDEV, errno.EPERM],
                         ids=["mkdir-denied", "no-space", "cross-device-link", "link-denied"])
@pytest.mark.parametrize("elsewhere", [False, True], ids=["own-grants", "manual-grant-first"])
def test_audit_publication_faults_never_abort_the_pass(shop, monkeypatch, capsys, policy, fault, elsewhere):
    request_heavy_jobs(shop, "heavy", policy, count=2)
    if elsewhere:
        shop.workspace.register("urgent", priority=1)
        shop.workspace.run("request", {"initiative": "urgent", "kind": "heavy", "holder": "manual-holder"})
    folder = shop.workspace.store / "census"
    original_mkdir, original_open, original_link = Path.mkdir, os.open, os.link
    fired = []

    def mkdir(path, *args, **kwargs):
        if path == folder and fault == errno.EACCES:
            fired.append("mkdir")
            raise PermissionError(fault, "private-error-must-not-leak")
        return original_mkdir(path, *args, **kwargs)

    def open_file(path, flags, *args, **kwargs):
        if Path(path).parent == folder and flags & os.O_CREAT and fault == errno.ENOSPC:
            fired.append("open")
            raise OSError(fault, "private-error-must-not-leak")
        return original_open(path, flags, *args, **kwargs)

    def link(source, target, *args, **kwargs):
        if Path(target).parent == folder and fault in (errno.EXDEV, errno.EPERM):
            fired.append("link")
            raise OSError(fault, "private-error-must-not-leak")
        return original_link(source, target, *args, **kwargs)

    jobs = load_jobs_module()
    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(os, "open", open_file)
    monkeypatch.setattr(os, "link", link)
    assert jobs.main(shop.argv("run-open", census=[101])[3:]) == (3 if elsewhere else 0)
    rows = json.loads(capsys.readouterr().out)["rows"]
    assert len(rows) == (3 if elsewhere else 2)
    assert len(fired) == (len(rows) if policy is not None else 0)
    for row in rows:
        if policy is None:
            assert "z_census" not in row
        else:
            summary = row["z_census"]
            assert summary["publish_failed"] is True
            assert summary["reason"] == "publish_failed"
            assert len(json.dumps(summary, sort_keys=True)) <= 384
            assert "private-error" not in json.dumps(summary)
        if row["state"] != "granted_elsewhere":
            assert row["state"] == "completed"
            result = result_for(shop, row["job"])
            assert result["steps"]
            if policy is None:
                assert "capacity" not in result
            else:
                marker = result["capacity"]
                assert marker["census"] == "publish_failed"
                assert marker["request_id"] == job_request_id(shop, "job:" + row["job"])
                assert "private-error" not in json.dumps(marker)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("different", [False, True], ids=["identical", "conflict"])
def test_existing_publication_bytes_are_compared_without_replacing_them(shop, policy, different):
    request_heavy_jobs(shop, "heavy", policy)
    request = shop.workspace.run("request", {"initiative": "pilot", "kind": "heavy", "holder": "job:pilot/job-1"})["request"]
    if policy is not None:
        folder = shop.workspace.store / "census"
        folder.mkdir()
        path = folder / (request["request_id"] + ".json")
        view = grant_view(policy, held=1 if different else 0)
        record = {key: request[key] for key in ("request_id", "holder", "kind")}
        record["capacity"] = view
        raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        path.write_bytes(raw)
    row = shop.run_open(census=[101])["rows"][0]
    assert row["state"] == "completed"
    result = result_for(shop)
    if policy is None:
        assert "capacity" not in result and not (shop.workspace.store / "census").exists()
    else:
        assert path.read_bytes() == raw
        if different:
            assert result["capacity"]["census"] == "invalid_record"
            assert result["capacity"]["reason"] == "conflict"
            assert row["z_census"]["reason"] == "conflict"
        else:
            assert result["capacity"] == grant_view(policy)
            assert "reason" not in row["z_census"]


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("action, spoof", [("execute", "writer"), ("execute", "heavy-tests"),
                                        ("refuse", "writer"), ("refuse", "heavy-tests"),
                                        ("resolve", "writer"), ("resolve", "heavy-tests"), ("resolve", "ambiguous")])
def test_other_kind_holders_and_ambiguous_grants_never_block_a_job(shop, policy, action, spoof):
    if action == "resolve":
        request_heavy_jobs(shop, "heavy", policy)
        crash_after_claim(shop)
        request_id = job_request_id(shop)
    else:
        request = manual_grant(shop, policy)
        request_id = request["request_id"]
        if policy is not None:
            folder = shop.workspace.store / "census"
            folder.mkdir()
            (folder / (request_id + ".json")).write_text(json.dumps({
                "request_id": request_id, "holder": "job:pilot/job-1", "kind": "heavy", "capacity": grant_view(policy)}))
    other_kind = "heavy-tests" if spoof == "ambiguous" else spoof
    shop.workspace.run("request", {"initiative": "pilot", "kind": other_kind, "holder": "job:pilot/job-1"})
    shop.workspace.run("grant-next", kind=other_kind)
    if spoof == "ambiguous":
        claim_path = shop.workspace.store / "jobs" / "pilot" / "job-1" / "claim.json"
        claim = json.loads(claim_path.read_bytes())
        claim.pop("census_kind", None)  # An unknown kind must not invent audit applicability.
        claim_path.write_text(json.dumps(claim))
    if action == "resolve":
        row = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "claim-only runner stopped")
        assert row["state"] == "failed"
    else:
        if action == "refuse":
            (shop.checkout / "src" / "app.py").write_text("changed = True\n")
        row = shop.run_open(census=[202])["rows"][0]
        assert row["state"] == ("refused" if action == "refuse" else "completed")
    result = result_for(shop)
    if policy is None or spoof == "ambiguous":
        assert "capacity" not in result
    else:
        assert result["capacity"] == grant_view(policy)


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("file_kind", ["regular", "directory", pytest.param(
    "fifo", marks=pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo is unavailable"))])
def test_record_reads_use_a_nonblocking_bounded_regular_file_descriptor(shop, monkeypatch, capsys, policy, file_kind):
    request = manual_grant(shop, policy)
    path = shop.workspace.store / "census" / (request["request_id"] + ".json")
    if policy is not None:
        path.parent.mkdir()
        if file_kind == "fifo":
            os.mkfifo(path)
        elif file_kind == "directory":
            path.mkdir()
        else:
            path.write_text(json.dumps({"request_id": request["request_id"], "holder": request["holder"],
                                       "kind": "heavy", "capacity": grant_view(policy)}))
    original = os.open
    fired = []

    def open_record(target, flags, *args, **kwargs):
        if str(target) == str(path):
            fired.append(flags)
            for flag in (getattr(os, "O_NOFOLLOW", 0), getattr(os, "O_NONBLOCK", 0)):
                assert flags & flag == flag
        return original(target, flags, *args, **kwargs)

    jobs = load_jobs_module()
    monkeypatch.setattr(os, "open", open_record)
    assert jobs.main(shop.argv("run-open", census=[202])[3:]) == 0
    assert bool(fired) == (policy is not None)
    json.loads(capsys.readouterr().out)
    result = result_for(shop)
    if policy is None:
        assert "capacity" not in result
    elif file_kind == "regular":
        assert result["capacity"] == grant_view(policy)
    else:
        assert result["capacity"]["census"] == "invalid_record"


@pytest.mark.parametrize("unrelated_record", [False, True])
def test_legacy_resolution_does_not_borrow_other_jobs_audit_activation(shop, unrelated_record):
    request_heavy_jobs(shop, "heavy")
    crash_after_claim(shop)
    if unrelated_record:
        folder = shop.workspace.store / "census"
        folder.mkdir()
        (folder / "req-99999999.json").write_text(json.dumps({
            "request_id": "req-99999999", "holder": "job:pilot/other-job", "kind": "heavy",
            "capacity": grant_view("report")}))
    row = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "claim-only default-policy runner stopped")
    assert row["state"] == "failed"
    assert "capacity" not in result_for(shop)
    assert "z_census" not in row


@pytest.mark.parametrize("policy", POLICIES)
def test_filtered_grant_keeps_its_own_durable_census_for_the_later_executor(shop, policy):
    other, checkout = add_initiative(shop, "urgent", 1)
    request_heavy_jobs(shop, "heavy", policy)
    shop.request_job("job-high", "heavy", root=other, prefix="urgent", checkout=checkout)
    request = shop.workspace.run("request", {"initiative": "urgent", "kind": "heavy",
                                             "holder": "job:urgent/job-high"})["request"]
    rows = shop.run_open("--initiative", "pilot", census=[101], expect=3)["rows"]
    elsewhere = next(row for row in rows if row["state"] == "granted_elsewhere")
    applied = grant_view("count")
    if policy in ("report", "ignore"):
        applied["outside_policy_applied"] = "count"
    path = shop.workspace.store / "census" / (request["request_id"] + ".json")
    if policy is None:
        assert "z_census" not in elsewhere and "capacity" not in elsewhere
        assert not path.exists()
    else:
        record = json.loads(path.read_bytes())
        assert record == {"request_id": request["request_id"], "holder": request["holder"], "kind": "heavy",
                          "capacity": applied}
        assert elsewhere["z_census"]["request_id"] == request["request_id"]
        assert elsewhere["z_census"] == expected_summary("count", [101], request_id=request["request_id"]) | (
            {"outside_policy_applied": "count"} if policy in ("report", "ignore") else {})
    # This later invocation must recover the original 101 observation, not its new 202 fixture.
    assert shop.run_open("--initiative", "urgent", census=[202])["rows"][0]["state"] == "completed"
    result = result_for(shop, "urgent/job-high")
    if policy is None:
        assert "capacity" not in result
        assert not (shop.workspace.store / "census").exists()
    else:
        assert result["capacity"] == applied


@pytest.mark.parametrize("policy", POLICIES)
def test_existing_grant_without_a_record_is_explicitly_unrecorded(shop, policy):
    request = manual_grant(shop, policy)
    shop.run_open(census=[202])
    result = result_for(shop)
    if policy is None:
        assert "capacity" not in result
    else:
        assert result["capacity"] == {"outside_policy": policy, "census": "unrecorded",
                                      "request_id": request["request_id"]}
    assert not (shop.workspace.store / "census").exists()


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("broken", ["request_id", "holder", "kind", "extra", "pid", "oversize",
                                    "unicode_id", "path_id", "policy", "symlink", "duplicate",
                                    "applied-policy", "applied-type", "applied-mismatch"])
def test_attacker_written_grant_records_are_marked_invalid_without_borrowing_or_blocking(shop, policy, broken):
    request = manual_grant(shop, policy)
    folder = shop.workspace.store / "census"
    folder.mkdir()
    path = folder / (request["request_id"] + ".json")
    record = {"request_id": request["request_id"], "holder": request["holder"], "kind": "heavy",
              "capacity": grant_view("report")}
    if broken == "request_id":
        record["request_id"] = "req-99999999"
    elif broken == "holder":
        record["holder"] = "job:pilot/someone-else"
    elif broken == "kind":
        record["kind"] = "heavy-tests"
    elif broken == "extra":
        record["untrusted"] = "must-not-be-echoed"
    elif broken == "pid":
        record["capacity"]["outside"][0]["pid"] = "must-not-be-echoed"
    elif broken == "unicode_id":
        record["request_id"] = "req-１２３４５６７８"
    elif broken == "path_id":
        record["request_id"] = "../must-not-be-read"
    elif broken == "policy":
        record["capacity"]["outside_policy"] = "REPORT"
    elif broken == "applied-policy":
        record["capacity"] = grant_view("count") | {"outside_policy_applied": "ignore"}
    elif broken == "applied-type":
        record["capacity"] = grant_view("count") | {"outside_policy_applied": ["count"]}
    elif broken == "applied-mismatch":
        record["capacity"]["outside_policy_applied"] = "count"
    raw = json.dumps(record)
    if broken == "oversize":
        raw += " " * 16384
    if broken == "duplicate":
        raw = raw[:-1] + ', "holder": "job:pilot/someone-else"}'
    if policy is None:
        # No policy at grant time produces no audit file; retain this legacy negative control for every case.
        folder.rmdir()
        row = shop.run_open(census=[202])["rows"][0]
        assert row["state"] == "completed" and "z_census" not in row
        assert "capacity" not in result_for(shop)
        assert not folder.exists()
        return
    if broken == "symlink":
        target = shop.tmp / "foreign-record.json"
        target.write_text(raw)
        path.symlink_to(target)
    else:
        path.write_text(raw)
    row = shop.run_open(census=[202])["rows"][0]
    assert row["state"] == "completed"
    result = result_for(shop)
    marker = result["capacity"]
    assert marker["census"] == "invalid_record"
    assert marker["request_id"] == request["request_id"]
    assert marker["outside_policy"] == policy
    assert 0 < len(marker["reason"]) <= 160
    assert "must-not-be-echoed" not in json.dumps(marker)
    assert "outside" not in marker and "external_roots" not in marker
    assert row["z_census"]["outside_count"] is None
    assert row["z_census"]["external_roots_count"] is None


@pytest.mark.parametrize("executor_policy", [None, "count", "ignore"])
def test_changed_executor_policy_still_reads_the_original_grant_record(shop, executor_policy):
    other, checkout = add_initiative(shop, "urgent", 1)
    request_heavy_jobs(shop, "heavy", "report")
    shop.request_job("job-high", "heavy", root=other, prefix="urgent", checkout=checkout)
    shop.workspace.run("request", {"initiative": "urgent", "kind": "heavy", "holder": "job:urgent/job-high"})
    shop.run_open("--initiative", "pilot", census=[101], expect=3)
    if executor_policy is None:
        del shop.recipes["census_outside_policy"]
    else:
        shop.recipes["census_outside_policy"] = executor_policy
    shop.save_recipes()
    shop.run_open("--initiative", "urgent", census=[202])
    assert result_for(shop, "urgent/job-high")["capacity"] == grant_view("count") | {"outside_policy_applied": "count"}


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("symlink", [False, True])
def test_a_planted_record_at_publication_is_invalid_without_blocking_the_granted_job(shop, policy, symlink):
    request_heavy_jobs(shop, "heavy", policy)
    request = shop.workspace.run("request", {"initiative": "pilot", "kind": "heavy", "holder": "job:pilot/job-1"})["request"]
    if policy is not None:
        folder = shop.workspace.store / "census"
        folder.mkdir()
        path = folder / (request["request_id"] + ".json")
        target = shop.tmp / "planted-record.json"
        target.write_text('{"must-not-be-echoed": true}')
        if symlink:
            path.symlink_to(target)
        else:
            path.write_bytes(target.read_bytes())
    row = shop.run_open(census=[101])["rows"][0]
    assert row["state"] == "completed"
    result = result_for(shop)
    if policy is None:
        assert "capacity" not in result and not (shop.workspace.store / "census").exists()
    else:
        assert result["capacity"]["census"] == "invalid_record"
        assert result["capacity"]["request_id"] == request["request_id"]
        assert row["z_census"]["census"] == "invalid_record"
        assert target.read_text() == '{"must-not-be-echoed": true}'


@pytest.mark.parametrize("cached_unlink", [False, True], ids=["native", "cached-accessor"])
@pytest.mark.parametrize("policy", POLICIES)
def test_competing_executor_uses_the_grant_record_and_the_loser_has_no_new_view(
        shop, monkeypatch, capsys, policy, cached_unlink):
    request_heavy_jobs(shop, "heavy", policy)
    original_link = os.link
    original_unlink = os.unlink
    contenders = []
    cached_calls = []
    if cached_unlink:
        # Model the older pathlib accessor at the OS boundary without relying on its private API.
        def cached_path_unlink(path, missing_ok=False):
            cached_calls.append(str(path))
            try:
                return original_unlink(path)
            except FileNotFoundError:
                if not missing_ok:
                    raise

        monkeypatch.setattr(Path, "unlink", cached_path_unlink)
    original_path_unlink = Path.unlink

    def publish_then_execute(source, destination, *args, **kwargs):
        answer = original_link(source, destination, *args, **kwargs)
        path = str(destination)
        # Interleave at a real atomic-publication boundary, after the grant/record is durable.
        if policy is not None and "/census/req-" in path:
            contenders.append(shop.run_open(census=[202]))
        return answer

    def unlock_then_execute(path, *args, **kwargs):
        answer = original_path_unlink(path, *args, **kwargs)
        if (policy is None and str(path) == str(shop.workspace.store / ".write.lock") and not contenders
                and any(event["kind"] == "grant" for event in shop.events())):
            contenders.append(shop.run_open(census=[202]))
        return answer

    jobs = load_jobs_module()
    monkeypatch.setattr(os, "link", publish_then_execute)
    monkeypatch.setattr(Path, "unlink", unlock_then_execute)
    assert jobs.main(shop.argv("run-open", census=[101])[3:]) == 3
    loser = json.loads(capsys.readouterr().out)["rows"][0]
    assert len(contenders) == 1
    assert bool(cached_calls) == cached_unlink
    assert contenders[0]["rows"][0]["state"] == "completed"
    assert loser["state"] == "running"
    assert "capacity" not in loser and "z_census" not in loser
    result = result_for(shop)
    if policy is None:
        assert "capacity" not in result and not (shop.workspace.store / "census").exists()
    else:
        assert result["capacity"] == grant_view(policy)


@pytest.mark.parametrize("policy", POLICIES)
def test_large_observations_do_not_crowd_hold_details_out_of_the_loop_prefix(shop, monkeypatch, capsys, policy):
    request_heavy_jobs(shop, "heavy", policy, count=2)
    result_path = shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json"
    original_open = os.open
    fired = []

    def open_lock(path, flags, *args, **kwargs):
        if str(path) == str(shop.root / ".write.lock") and flags & os.O_EXCL and result_path.exists():
            fired.append("mailbox_lock")
            raise FileExistsError("fixture active writer")
        return original_open(path, flags, *args, **kwargs)

    jobs = load_jobs_module()
    monkeypatch.setattr(os, "open", open_lock)
    assert jobs.main(shop.argv("run-open", "--max-jobs", "1", census=list(range(101, 171)), lock_wait=0)[3:]) == 3
    rows = json.loads(capsys.readouterr().out)["rows"]
    assert bool(fired) == (policy in ("report", "ignore"))
    for row in rows:
        prefix = json.dumps(row, sort_keys=True)[:512]
        assert '"error"' in prefix or '"reason"' in prefix
        if "process_group" in row:
            assert '"process_group"' in prefix
        if policy is not None:
            assert "capacity" not in row
            summary = row["z_census"]
            assert len(json.dumps(summary, sort_keys=True)) <= 384
            assert set(summary) <= {"outside_policy", "census", "limit", "held", "external_roots_count",
                                    "outside_count", "outside_truncated", "request_id"}
            assert "outside" not in summary and "external_roots" not in summary


@pytest.mark.parametrize("policy", POLICIES)
def test_settlement_of_a_competitors_derived_result_adds_no_new_view(claude_shop, monkeypatch, capsys, policy):
    shop = claude_shop
    if policy is not None:
        shop.recipes["census_outside_policy"] = policy
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    original_link = os.link
    contenders = []
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"

    def publish_then_execute(source, destination, *args, **kwargs):
        answer = original_link(source, destination, *args, **kwargs)
        if str(destination) == str(folder / "admitted.json"):
            contenders.append(shop.run_open(census=[202]))
        return answer

    jobs = load_jobs_module()
    monkeypatch.setattr(os, "link", publish_then_execute)
    assert jobs.main(shop.argv("run-open", census=[101])[3:]) == 0
    row = json.loads(capsys.readouterr().out)["rows"][0]
    assert len(contenders) == 1
    assert row["state"] == "completed"
    assert "capacity" not in row and "z_census" not in row
    result = result_for(shop)
    # Commit recipes are light: even an explicit census policy must not invent a grant for this result.
    assert "capacity" not in result


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("invalid", [False, True])
def test_resolve_recovers_the_abandoned_requests_record_with_the_same_validation(shop, policy, invalid):
    request_heavy_jobs(shop, "heavy", policy)
    # The isolated runner exits after atomically publishing its real claim, before executing any step.
    crash_after_claim(shop)
    request_id = job_request_id(shop)
    path = shop.workspace.store / "census" / (request_id + ".json")
    if invalid and policy is not None:
        record = json.loads(path.read_bytes())
        record["holder"] = "job:pilot/someone-else"
        path.write_text(json.dumps(record))
    row = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "claim-only runner stopped")
    assert row["state"] == "failed"
    result = result_for(shop)
    if policy is None:
        assert "capacity" not in result
    elif invalid:
        assert result["capacity"]["census"] == "invalid_record"
        assert result["capacity"]["request_id"] == request_id
    else:
        assert result["capacity"] == grant_view(policy)



def request_heavy_jobs(shop, kind, policy=None, count=1):
    if policy is not None:
        shop.recipes["census_outside_policy"] = policy
    shop.recipes["recipes"]["heavy"]["heavy_tests"] = kind == "heavy-tests"
    shop.save_recipes()
    for number in range(1, count + 1):
        shop.request_job("job-%d" % number, "heavy")


def outside_rows(pids, kind):
    return [{"pid": pid, "class": "pytest" if kind == "heavy" else "cargo"} for pid in sorted(pids)]


@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
def test_all_granted_jobs_retain_only_explicit_policy_capacity(shop, policy):
    request_heavy_jobs(shop, "heavy", policy)
    # Two outside roots leave one slot under the owner's heavy limit of three.
    pids = PIDS[:2]
    row = shop.run_open("--max-jobs", "20", census={"external_roots": {"heavy": pids}})["rows"][0]
    result_path = shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json"
    result_raw = result_path.read_bytes()
    result = json.loads(result_raw)
    assert row["state"] == result["state"] == "completed"
    assert json.loads(verified_evidence(shop.receipts("job-1")[-1])["result.json"].read_bytes()) == result
    if policy is None:
        # Pin the legacy row and result shape/serialization, including key order.
        assert json.dumps(row) == json.dumps({"exit_code": 0, "job": "pilot/job-1",
                                            "removed": ["scratch", "tmp", "home", "cargo-target", "ruff-cache", "hypothesis"],
                                            "result": str(result_path), "state": "completed"})
        keys = ("after", "before", "commit", "exit_code", "finished_at", "job", "process_stopped_confirmed",
                "python", "reason", "recipe", "recipes_sha256", "schema", "state", "steps", "tests")
        assert list(result) == list(keys)
        assert result_raw == (json.dumps({key: result[key] for key in keys}, separators=(",", ":")) + "\n").encode()
    else:
        expected = {"limit": 3, "held": 0, "external_roots": sorted(pids) if policy == "count" else [],
                    "census": "none" if policy == "ignore" else "fixture", "outside_policy": policy}
        if policy != "ignore":
            expected["outside"] = outside_rows(pids, "heavy")
        assert result["capacity"] == expected
        assert "capacity" not in row
        assert row["z_census"] == expected_summary(policy, pids, request_id=job_request_id(shop))
    assert shop.open_jobs() == []


@pytest.mark.parametrize("kind", KINDS)
def test_granted_report_capacity_retains_truncation(shop, kind):
    request_heavy_jobs(shop, kind, "report")
    pids = list(range(170, 100, -1))
    row = shop.run_open(census={"external_roots": {kind: pids}})["rows"][0]
    assert row["state"] == "completed"
    capacity = result_for(shop)["capacity"]
    assert capacity["outside"] == outside_rows(pids, kind)[:64]
    assert capacity["outside_truncated"] == 6
    result = json.loads(verified_evidence(shop.receipts("job-1")[-1])["result.json"].read_bytes())
    assert result["capacity"] == capacity
    assert row["z_census"] == expected_summary("report", pids,
                                               limit=1 if kind == "heavy-tests" else 3,
                                               request_id=job_request_id(shop))


@pytest.mark.parametrize("pregrant_second", [False, True])
def test_grant_capacity_is_fresh_and_never_borrowed_by_an_existing_grant(shop, capsys, pregrant_second):
    fixture = shop.tmp / "changing-census.json"
    fixture.write_text(json.dumps([101]))
    grant_argv = shop.workspace.argv("grant-next", kind="heavy")
    script = "import json, subprocess; open(%r, 'w').write(json.dumps([202]))" % str(fixture)
    if pregrant_second:
        script += "; subprocess.run(%r, check=True, timeout=10)" % grant_argv
    shop.recipes["census_outside_policy"] = "report"
    shop.recipes["recipes"]["change-census"] = shop.command(["$python", "-c", script], heavy=True)
    shop.save_recipes()
    shop.request_job("job-1", "change-census")
    shop.request_job("job-2", "heavy")
    jobs = load_jobs_module()
    assert jobs.main(["--census-fixture", str(fixture), *shop.argv("run-open", "--max-jobs", "20")[3:]]) == 0
    rows = json.loads(capsys.readouterr().out)["rows"]
    assert [row["state"] for row in rows] == ["completed", "completed"]
    assert result_for(shop)["capacity"]["outside"] == outside_rows([101], "heavy")
    for row in rows:
        result = json.loads(verified_evidence(shop.receipts(row["job"].split("/")[1])[-1])["result.json"].read_bytes())
        if row is rows[1] and pregrant_second:
            assert result["capacity"] == {"outside_policy": "report", "census": "unrecorded",
                                          "request_id": job_request_id(shop, "job:pilot/job-2")}
            assert row["z_census"]["census"] == "unrecorded"
        else:
            assert row["z_census"]["outside_count"] == len(result["capacity"]["outside"])
    if not pregrant_second:
        assert result_for(shop, "pilot/job-2")["capacity"]["outside"] == outside_rows([202], "heavy")


@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
def test_granted_capacity_survives_a_blocked_receipt(shop, monkeypatch, capsys, policy):
    # Fault only the OS lock acquisition after the durable result exists.
    lock = shop.root / ".write.lock"
    result_path = shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json"
    original_open = os.open
    fired = []

    def open_lock(path, flags, *args, **kwargs):
        if str(path) == str(lock) and flags & os.O_EXCL and result_path.exists():
            fired.append("mailbox_lock")
            raise FileExistsError("fixture active writer")
        return original_open(path, flags, *args, **kwargs)

    request_heavy_jobs(shop, "heavy", policy)
    jobs = load_jobs_module()
    monkeypatch.setattr(os, "open", open_lock)
    assert jobs.main(shop.argv("run-open", census=[101], lock_wait=0)[3:]) == 3
    row = json.loads(capsys.readouterr().out)["rows"][0]
    assert fired
    assert row["state"] == "settle_pending"
    assert row["error"] == "mailbox writer is busy; inspect an abandoned lock before retrying"
    result = json.loads(result_path.read_bytes())
    assert result["state"] == "completed"
    if policy is None:
        assert "capacity" not in row and "z_census" not in row and "capacity" not in result
    else:
        assert row["z_census"] == expected_summary(policy, [101], request_id=job_request_id(shop))
        assert result["capacity"] == grant_view(policy)


@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
def test_granted_capacity_survives_a_dependency_refusal_before_execution(shop, policy):
    log = shop.workspace.store / "jobs" / "pilot" / "first-check" / "step-1.log"
    shop.recipes["recipes"]["tamper"] = shop.command([
        "$python", "-c", "open(%r, 'a').write('changed')" % str(log)], heavy=True)
    if policy is not None:
        shop.recipes["census_outside_policy"] = policy
    shop.save_recipes()
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    # Both heavy requests pass admission before the first invalidates the child's predecessor evidence.
    shop.request_job("job-1", "tamper")
    shop.request_job("job-2", "heavy", raw=json.dumps({
        "schema": "aegis.hierarchy-job-packet/v2", "recipe": "heavy", **shop.head(),
        "recipes_sha256": hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest(),
        "after": {"message_id": "first-check", "sha256": parent["sha256"]}}))
    rows = shop.run_open(census=[101])["rows"]
    assert [row["state"] for row in rows] == ["completed", "refused"]
    row = rows[1]
    assert row["reason"] == ("dependency changed after capacity admission: "
                             "predecessor terminal receipt does not match retained evidence")
    result = json.loads((shop.workspace.store / "jobs" / "pilot" / "job-2" / "result.json").read_bytes())
    assert result["state"] == "refused" and result["steps"] == []
    if policy is None:
        assert "capacity" not in row and "z_census" not in row and "capacity" not in result
    else:
        assert row["z_census"] == expected_summary(policy, [101], request_id=job_request_id(shop, "job:pilot/job-2"))
        assert result["capacity"]["outside_policy"] == policy


@pytest.mark.parametrize("kind", KINDS)
def test_absent_policy_preserves_recipe_bytes_hash_and_waiting_capacity(shop, kind):
    request_heavy_jobs(shop, kind)
    raw = shop.recipes_path.read_bytes() + b"\n\n"
    shop.recipes_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    # No injected default, normalization or reserialization of the bytes being pinned.
    assert load_jobs_module().load_recipes(shop.recipes_path) == {**json.loads(raw), "recipes_sha256": digest}
    assert shop.jobs("check-recipes")["recipes_sha256"] == digest
    before = shop.workspace.run("status")["capacity"][kind]
    result = shop.run_open(census={"external_roots": {kind: PIDS}}, expect=3)
    assert result == {"rows": [{"job": "pilot/job-1", "state": "waiting", "kind": kind,
                                "reason": "capacity_full", "capacity": {
                                    "limit": before["limit"], "held": 0,
                                    "external_roots": sorted(PIDS), "census": "fixture"}}]}
    assert shop.recipes_path.read_bytes() == raw
    assert shop.receipts("job-1") == []


@pytest.mark.parametrize("kind", KINDS)
def test_explicit_count_preserves_counting_and_records_outside_rows(shop, kind):
    request_heavy_jobs(shop, kind, "count")
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    row = shop.run_open(census={"external_roots": {kind: PIDS}}, expect=3)["rows"][0]
    assert (row["state"], row["reason"]) == ("waiting", "capacity_full")
    assert row["z_census"] == expected_summary("count", PIDS, limit=limit)
    assert "capacity" not in row
    assert shop.receipts("job-1") == []


@pytest.mark.parametrize("kind", KINDS)
def test_report_grants_despite_outside_load_and_records_it_on_the_waiting_row(shop, kind):
    request_heavy_jobs(shop, kind, "report", count=2)
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    rows = shop.run_open("--max-jobs", "1", census={"external_roots": {kind: PIDS}}, expect=3)["rows"]
    assert [(row["job"], row["state"]) for row in rows] == [
        ("pilot/job-1", "completed"), ("pilot/job-2", "waiting")]
    assert rows[1]["reason"] == "job_limit"
    assert rows[1]["z_census"] == expected_summary("report", PIDS, limit=limit)
    assert result_for(shop)["capacity"]["outside"] == outside_rows(PIDS, kind)
    assert shop.states("job-1") == ["started", "completed"]
    assert sum(event["kind"] == "grant" for event in shop.events()) == 1


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("fixture", [{"external_roots": {"heavy": PIDS, "heavy-tests": PIDS}},
                                    {"not_a_census": "must never be read"}])
def test_ignore_grants_without_reading_outside_census_or_recording_outside_rows(shop, kind, fixture):
    request_heavy_jobs(shop, kind, "ignore", count=2)
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    rows = shop.run_open("--max-jobs", "1", census=fixture, expect=3)["rows"]
    assert [(row["job"], row["state"]) for row in rows] == [
        ("pilot/job-1", "completed"), ("pilot/job-2", "waiting")]
    # A malformed fixture would refuse if any outside census were attempted.
    assert rows[1]["z_census"] == expected_summary("ignore", limit=limit)
    assert shop.states("job-1") == ["started", "completed"]


@pytest.mark.parametrize("policy", ["count", "report", "ignore"])
@pytest.mark.parametrize("with_fixture", [False, True])
@pytest.mark.parametrize("kind", KINDS)
def test_capacity_census_label_names_only_the_observation_performed(
        shop, monkeypatch, capsys, policy, with_fixture, kind):
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    for number in range(limit):
        shop.workspace.run("request", {"initiative": "pilot", "kind": kind, "holder": "held-%d" % number})
        shop.workspace.run("grant-next", kind=kind)
    request_heavy_jobs(shop, kind, policy)
    original_scan = os.scandir
    observed = []

    @contextmanager
    def scan(path):
        with original_scan(path) as entries:
            if str(path) == "/proc":
                observed.append("proc")
                # Keep the required real self witness, isolating unrelated host load at the OS boundary.
                yield (entry for entry in entries if entry.name == str(os.getpid()))
            else:
                yield entries

    jobs = load_jobs_module()
    monkeypatch.setattr(os, "scandir", scan)
    fixture = {"external_roots": {kind: [101]}} if with_fixture else None
    assert jobs.main(shop.argv("run-open", census=fixture)[3:]) == 3
    row = json.loads(capsys.readouterr().out)["rows"][0]
    assert (row["state"], row["reason"]) == ("waiting", "capacity_full")
    assert row["z_census"]["census"] == ("none" if policy == "ignore" else "fixture" if with_fixture else "proc")
    assert observed == (["proc"] if policy != "ignore" and not with_fixture else [])


@pytest.mark.parametrize("policy", [None, "count", "report"])
def test_observing_policies_refuse_an_unreadable_outside_fixture(shop, policy):
    request_heavy_jobs(shop, "heavy", policy)
    assert shop.run_open(census={"not_a_census": "must be checked"}, expect=2) == {
        "error": "missing fields: external_roots"}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", ["count", "report"])
@pytest.mark.parametrize("pid", ["/private/not-a-pid", True, 1.5, 0, -1])
def test_outside_rows_refuse_non_positive_or_non_integer_fixture_pids(shop, policy, pid):
    request_heavy_jobs(shop, "heavy", policy)
    assert shop.run_open(census=[pid], expect=2) == {"error": "invalid census fixture pid"}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
@pytest.mark.parametrize("kind", KINDS)
def test_only_ignore_skips_proc_enumeration_and_recovery_still_observes_raw_census(
        shop, monkeypatch, capsys, policy, kind):
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    for number in range(limit):
        shop.workspace.run("request", {"initiative": "pilot", "kind": kind, "holder": "held-%d" % number})
        shop.workspace.run("grant-next", kind=kind)
    request_heavy_jobs(shop, kind, policy)
    jobs = load_jobs_module()
    original = os.scandir
    fired = []

    def scan(path):
        if str(path) == "/proc":
            fired.append("proc")
            raise PermissionError("outside census denied by fixture")
        return original(path)

    # Mock only the OS enumeration boundary, never outside_roots or census.
    monkeypatch.setattr(os, "scandir", scan)
    code = jobs.main(shop.argv("run-open", census=None)[3:])
    answer = json.loads(capsys.readouterr().out)
    assert len(fired) == (0 if policy == "ignore" else 1)
    if policy == "ignore":
        assert code == 3
        assert answer == {"rows": [{"job": "pilot/job-1", "state": "waiting", "kind": kind,
                                    "reason": "capacity_full", "z_census":
                                    expected_summary("ignore", limit=limit, held=limit)}]}
    else:
        assert code == 2
        assert answer == {"error": "cannot enumerate process table: outside census denied by fixture"}
    # recovery-status has no recipes policy, even when --recipes names an ignore file.
    assert jobs.main(shop.argv("recovery-status", census=None)[3:]) == 3
    recovered = json.loads(capsys.readouterr().out)
    assert len(fired) == (0 if policy == "ignore" else 1) + len(KINDS)
    for observed in recovered["process_census"].values():
        assert observed == {"state": "unavailable", "admission_free": None,
                            "error": "cannot enumerate process table: outside census denied by fixture"}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", ["COUNT", "off", "", None, False, 1, [], {}, ["ignore"]])
@pytest.mark.parametrize("command", ["check-recipes", "run-open"])
def test_unknown_or_non_string_policy_refuses_exactly_before_jobs_run(shop, policy, command):
    shop.recipes["census_outside_policy"] = policy
    shop.save_recipes()
    shop.request_job("job-1", "touch")
    assert shop.jobs(command, expect=2) == {"error": POLICY_ERROR}
    assert not shop.sentinel.exists()
    assert shop.states("job-1") == []


@pytest.mark.parametrize("command", ["check-recipes", "run-open"])
def test_misspelled_policy_key_refuses_exactly_before_jobs_run(shop, command):
    shop.recipes["census_outside_polciy"] = "ignore"
    shop.save_recipes()
    shop.request_job("job-1", "touch")
    assert shop.jobs(command, expect=2) == {"error": "unexpected fields: census_outside_polciy"}
    assert not shop.sentinel.exists()
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
@pytest.mark.parametrize("kind", KINDS)
def test_policy_never_exceeds_the_limit_for_ledger_held_jobs(shop, policy, kind):
    before = shop.workspace.run("status")["capacity"][kind]
    for number in range(before["limit"]):
        shop.workspace.run("request", {"initiative": "pilot", "kind": kind,
                                        "holder": "job:pilot/held-%d" % number})
        shop.workspace.run("grant-next", kind=kind)
    held = shop.workspace.run("status")["capacity"][kind]
    request_heavy_jobs(shop, kind, policy)
    row = shop.run_open(census={"external_roots": {kind: PIDS}}, expect=3)["rows"][0]
    assert (row["state"], row["reason"]) == ("waiting", "capacity_full")
    view = row["capacity"] if policy is None else row["z_census"]
    assert view["held"] == view["limit"] == before["limit"]
    assert shop.workspace.run("status")["capacity"][kind] == held
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", ["count", "report"])
@pytest.mark.parametrize("kind", KINDS)
def test_outside_rows_are_bounded_without_changing_the_count(shop, policy, kind):
    request_heavy_jobs(shop, kind, policy)
    # Hold the ledger full so report also leaves an observable waiting capacity.
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    for number in range(limit):
        shop.workspace.run("request", {"initiative": "pilot", "kind": kind, "holder": "held-%d" % number})
        shop.workspace.run("grant-next", kind=kind)
    pids = list(range(170, 100, -1))
    row = shop.run_open(census={"external_roots": {kind: pids}}, expect=3)["rows"][0]
    assert row["z_census"] == expected_summary(policy, pids, limit=limit, held=limit)
    assert "capacity" not in row


@pytest.mark.parametrize("policy", ["count", "report", "ignore"])
@pytest.mark.parametrize("reason", ["low_disk", "store_busy"])
def test_policy_preserves_low_disk_and_busy_store_holds(shop, policy, reason):
    request_heavy_jobs(shop, "heavy", policy)
    if reason == "low_disk":
        shop.recipes["min_free_gigabytes"] = 1000000
        shop.save_recipes()
    else:
        (shop.workspace.store / ".write.lock").write_text("fixture active writer")
    assert shop.run_open(lock_wait=0.1, expect=3) == {"rows": [
        {"job": "pilot/job-1", "state": "waiting", "kind": "heavy", "reason": reason}]}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("unreviewed", ["report", "ignore"])
def test_environment_cannot_disable_default_counting(shop, unreviewed):
    request_heavy_jobs(shop, "heavy")
    env = {**shop.env(), "CENSUS_OUTSIDE_POLICY": unreviewed, "AEGIS_CENSUS_OUTSIDE_POLICY": unreviewed}
    row = shop.run_open(census=PIDS, env=env, expect=3)["rows"][0]
    assert row["reason"] == "capacity_full"
    assert row["capacity"] == {"limit": 3, "held": 0, "external_roots": sorted(PIDS), "census": "fixture"}


@pytest.mark.parametrize("policy", ["count", "report", "ignore"])
def test_policy_is_covered_by_the_exact_recipe_bytes_hash(shop, policy):
    before = shop.jobs("check-recipes")["recipes_sha256"]
    request_heavy_jobs(shop, "heavy", policy)
    raw = shop.recipes_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest != before
    assert shop.jobs("check-recipes")["recipes_sha256"] == digest
    shop.run_open()
    result = json.loads((shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json").read_text())
    assert result["recipes_sha256"] == digest
