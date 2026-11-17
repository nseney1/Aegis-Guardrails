"""Real Git children keep read policy and inherit host state only for explicit legacy calls."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.conftest import symlink_or_skip
from tests.integration.test_hierarchy_jobs import shop  # noqa: F401
from tests.integration.test_hierarchy_jobs_derive import host_plan
from tests.integration.test_hierarchy_provision import (  # noqa: F401
    mr1_cli, mr1_plan, mr1_r4_copy_base, rb2_pending, rb2c_registered_move, setup, source_seed, unbound,
)
from tests.integration.test_hierarchy_mailbox import invoke as mailbox

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import hierarchy_git  # noqa: E402
import hierarchy_hosts  # noqa: E402
import hierarchy_jobs as jobs  # noqa: E402
import hierarchy_provision as provision  # noqa: E402
import hierarchy_review as review  # noqa: E402
import hierarchy_source as source  # noqa: E402


POLICY = {"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
          "GIT_NO_LAZY_FETCH": "1", "GIT_PROTOCOL_FROM_USER": "0", "GIT_ALLOW_PROTOCOL": ""}
SITES = ("jobs_export", "jobs_object", "jobs_pinned", "jobs_status", "jobs_identity", "jobs_state",
         "jobs_folders", "review_git", "review_export", "review_output", "source_git", "source_bounded",
         "provision_git")


def git(repository, *arguments):
    return subprocess.run(["git", "-C", str(repository), *arguments], capture_output=True, check=True,
                          timeout=15, env=hierarchy_git.object_read_env()).stdout.decode("ascii").strip()


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "core.autocrlf", "false")
    (root / "page.txt").write_bytes(b"hello\n")
    git(root, "add", ".")
    git(root, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
    return root, git(root, "rev-parse", "HEAD"), git(root, "rev-parse", "HEAD^{tree}"), git(root, "hash-object", "page.txt")


@pytest.fixture
def runtime_repository(repository):
    root = repository[0]
    helper = root / "tools" / "hierarchy_mailbox.py"
    helper.parent.mkdir()
    helper.write_text("# test-owned runtime helper\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "runtime")
    return root, git(root, "rev-parse", "HEAD"), git(root, "rev-parse", "HEAD^{tree}")


@pytest.fixture
def runtime_inherited(runtime_repository, inherited):
    return inherited


@pytest.fixture
def inherited(monkeypatch, tmp_path, repository):
    names = set()
    for host in (*hierarchy_hosts.describe()["hosts"].values(), *hierarchy_hosts.HOST_ENVIRONMENT.values()):
        names.update(host["billing_variables"])
        if host["session_variable"]["name"]:
            names.add(host["session_variable"]["name"])
        names.update(host["session_markers"]["names"])
        names.update(prefix + "FUTURE_MARKER" for prefix in host["session_markers"]["prefixes"])
    polluted = {name: "inherited-host-value" for name in names}
    trace = tmp_path / "git-trace.jsonl"
    runtime_keys = {"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "COMSPEC", "PATHEXT",
                    "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "LANG", "LC_ALL", "GIT_CEILING_DIRECTORIES"}
    runtime = {key: value for key, value in os.environ.items() if key in runtime_keys}
    parent = {**runtime, **polluted, **{key: "wrong" for key in POLICY}, "AEGIS_ENV_CANARY": "kept",
              "GIT_TRACE2_EVENT": str(trace),
              "GIT_TRACE2_ENV_VARS": ",".join(sorted(names | set(POLICY) | {"AEGIS_ENV_CANARY"}))}
    monkeypatch.setattr(hierarchy_git, "os", SimpleNamespace(**{**vars(os), "environ": parent}))
    environments = []

    def run(*args, **kwargs):
        environments.append(dict(kwargs["env"]))
        return subprocess.run(*args, **kwargs)

    def popen(*args, **kwargs):
        environments.append(dict(kwargs["env"]))
        return subprocess.Popen(*args, **kwargs)

    boundary = SimpleNamespace(**{**vars(subprocess), "run": run, "Popen": popen})
    monkeypatch.setattr(jobs, "subprocess", boundary)
    monkeypatch.setattr(review, "subprocess", boundary)
    monkeypatch.setattr(source, "subprocess", boundary)
    monkeypatch.setattr(provision, "subprocess", boundary)
    return polluted, trace, environments, parent


def assert_children(trace, polluted, planned, environments):
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    children = {row["sid"]: {} for row in rows if row["event"] == "start"}
    for row in rows:
        if row["event"] == "def_param" and row.get("scope") == "command":
            children[row["sid"]][row["param"]] = row["value"]
    assert children, "the test must observe a real Git child"
    for values in children.values():
        # Git's trace omits empty environment values. The process boundary below
        # also checks the empty protocol allowlist and complete legacy mapping.
        assert {key: values.get(key, "") for key in POLICY} == POLICY
        assert values["AEGIS_ENV_CANARY"] == "kept"
        assert {key: values[key] for key in polluted if key in values} == (polluted if planned is False else {})
    assert environments
    baselines = [hierarchy_git.object_read_env(), hierarchy_git.object_read_env(inherit_config=True)]
    for environment in environments:
        assert {key: environment.get(key) for key in POLICY} == POLICY
        if planned is False:
            assert environment in baselines


def invoke(site, repository, tmp_path, **options):
    root, commit, tree, blob = repository
    if site == "jobs_export":
        target = tmp_path / "export"
        try:
            assert jobs.export_commit(root, commit, tree, target, **options)["bytes"] == 6
            assert (target / "page.txt").read_bytes() == b"hello\n"
        finally:
            if target.exists():
                target.chmod(0o700)
                (target / "page.txt").chmod(0o600)
    elif site == "jobs_object":
        assert jobs.object_git(root, "cat-file", "blob", blob, **options).stdout == b"hello\n"
    elif site == "jobs_pinned":
        assert jobs.pinned_git(root, "cat-file", "blob", blob, env={key: "caller-wrong" for key in POLICY},
                               **options).stdout == b"hello\n"
    elif site == "jobs_status":
        assert jobs.uncommitted_content(root, **options) == (jobs.EMPTY_STATUS, 0)
    elif site == "jobs_identity":
        assert jobs.source_identity(root, "rev-parse", "HEAD", **options) == commit
    elif site == "jobs_state":
        assert jobs.source_state(None, root, **options)["source_revision"] == commit
    elif site == "jobs_folders":
        assert [Path(path).resolve() for path in jobs.git_folders(root, **options)] == [(root / ".git").resolve()]
    elif site == "review_git":
        assert review.git(root, "cat-file", "blob", blob, **options).stdout == b"hello\n"
    elif site == "review_export":
        entries = [("100644", "blob", blob, "page.txt")]
        assert review.export(root, entries, tmp_path / "review", **options)[0]["path"] == "page.txt"
    elif site == "review_output":
        path = tmp_path / "output"
        review.write_output(root, path, "cat-file", "blob", blob, **options)
        assert path.read_bytes() == b"hello\n"
    elif site == "source_git":
        assert source.SourceViews(root, **options).show({"commit": commit, "path": "page.txt"})["lines"] == ["hello"]
    elif site == "source_bounded":
        assert source.SourceViews(root, **options).grep({"commit": commit, "pattern": "hello"})["matches"] == [
            {"path": "page.txt", "line": 1, "text": "hello"}]
    elif site == "provision_git":
        assert provision.git(root, "cat-file", "blob", blob, **options).stdout == "hello\n"


@pytest.mark.parametrize("planned", [None, True, False], ids=["indeterminate", "planned", "legacy"])
@pytest.mark.parametrize("site", SITES)
def test_each_object_read_child_environment(repository, inherited, tmp_path, site, planned):
    if site == "jobs_export" and (os.name == "nt" or not hasattr(os, "O_NOFOLLOW")):
        pytest.skip("job export needs POSIX file modes and O_NOFOLLOW")
    if site == "source_bounded" and os.name == "nt":
        pytest.skip("source grep uses POSIX pipe selectors")
    # Omission exercises existing callers that cannot discover the governing plan.
    invoke(site, repository, tmp_path, **({} if planned is None else {"planned": planned}))
    assert_children(inherited[1], inherited[0], planned, inherited[2])


@pytest.mark.parametrize("planned", [None, True, False], ids=["indeterminate", "planned", "legacy"])
@pytest.mark.parametrize("module", [jobs, review, provision], ids=["jobs", "review", "provision"])
def test_failed_read_and_retry_keep_environment(repository, inherited, module, planned):
    root, commit, _, _ = repository
    reader = module.object_git if module is jobs else module.git
    options = {} if planned is None else {"planned": planned}
    assert reader(root, "rev-parse", "--verify", "missing-object", **options).returncode != 0
    assert reader(root, "rev-parse", "--verify", commit, **options).returncode == 0
    assert_children(inherited[1], inherited[0], planned, inherited[2])


@pytest.mark.parametrize("planned", [None, True, False], ids=["indeterminate", "planned", "legacy"])
@pytest.mark.parametrize("bounded", [False, True], ids=["ordinary", "bounded"])
def test_source_failure_and_retry_keep_environment(repository, inherited, planned, bounded):
    if bounded and os.name == "nt":
        pytest.skip("bounded source reads use POSIX pipe selectors")
    root, commit, _, blob = repository
    views = source.SourceViews(root, planned=planned)
    if bounded:
        with pytest.raises(ValueError, match="^git failed in the source repository$"):
            views.bounded(("cat-file", "blob", "f" * 40), b"", 1024)
        assert views.bounded(("cat-file", "blob", blob), b"", 1024) == (b"hello\n", False, 0)
    else:
        with pytest.raises(ValueError, match="^commit not found in the source repository$"):
            views.show({"commit": "f" * 40, "path": "page.txt"})
        assert views.show({"commit": commit, "path": "page.txt"})["lines"] == ["hello"]
    assert_children(inherited[1], inherited[0], planned, inherited[2])


@pytest.mark.parametrize("planned", [None, True, False], ids=["indeterminate", "planned", "legacy"])
def test_review_batch_failure_and_retry_keep_environment(repository, inherited, tmp_path, planned):
    root, _, _, blob = repository
    missing = "f" * 40
    with pytest.raises(ValueError, match="^could not read object " + missing + "$"):
        review.export(root, [("100644", "blob", missing, "page.txt")], tmp_path / "failed", planned=planned)
    assert review.export(root, [("100644", "blob", blob, "page.txt")], tmp_path / "retried", planned=planned)
    assert_children(inherited[1], inherited[0], planned, inherited[2])


def test_concurrent_planned_and_legacy_reads_do_not_mutate_parent(repository, inherited):
    root = repository[0]
    before = dict(os.environ)
    source_before = dict(inherited[3])
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda planned: jobs.object_git(root, "rev-parse", "HEAD", planned=planned),
                                [True, False, None] * 3))
    assert all(result.returncode == 0 for result in results)
    unchanged = dict(os.environ) == before
    assert unchanged, "the process environment changed"
    assert inherited[3] == source_before
    rows = [json.loads(line) for line in inherited[1].read_text(encoding="utf-8").splitlines()]
    retained = [row for row in rows if row["event"] == "def_param" and row.get("param") in inherited[0]]
    assert len({row["sid"] for row in retained}) == 3


@pytest.mark.parametrize("planned", [None, True, False], ids=["indeterminate", "planned", "legacy"])
def test_pin_source_threads_the_governing_selection(runtime_repository, runtime_inherited, monkeypatch, planned):
    root, commit, tree = runtime_repository
    monkeypatch.setattr(provision, "hierarchy_runtime_source", SimpleNamespace(verify=lambda *args: None))
    assert provision.pin_source(str(root), planned=planned) == (root, commit, tree)
    polluted, trace, environments, _ = runtime_inherited
    assert_children(trace, polluted, planned, environments)


@pytest.mark.parametrize("plan_location", ["new", "absent", "local", "governing", "invalid", "invalid-record"])
def test_provision_init_selects_the_governing_plan_before_git_reads(
        runtime_repository, runtime_inherited, tmp_path, monkeypatch, capsys, plan_location):
    base, home = tmp_path / "base", tmp_path / "home"
    if plan_location != "new":
        base.mkdir()
        home.mkdir()
        setup = [] if plan_location == "invalid-record" else {"mailbox_root": str(home / "mailbox"), "initiative": "pilot"}
        (base / "provision.json").write_text(json.dumps(setup), encoding="utf-8")
    if plan_location not in {"new", "absent", "invalid-record"}:
        plan = {"schema": hierarchy_hosts.PLAN_SCHEMA, "hierarchy": "pilot", "root": hierarchy_hosts.CODEX,
                "team": hierarchy_hosts.CLAUDE, "stand_ins": {}, "config_sha256": "a" * 64}
        (base if plan_location == "local" else home).joinpath(hierarchy_hosts.PLAN_FILE).write_text(
            json.dumps([] if plan_location == "invalid" else plan), encoding="utf-8")
    request = {"base": str(base), "store": str(tmp_path / "missing-store"), "source": str(runtime_repository[0]),
               "initiative": {"id": "pilot", "project": "aegis", "repository": "aegis", "priority": 5,
                              "target_branch": "develop"}, "lanes": {"review": "reviewer"}}
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    monkeypatch.setattr(provision, "hierarchy_runtime_source", SimpleNamespace(verify=lambda *args: None))
    assert provision.main(["init", "--request", str(path)]) == 2
    answer = json.loads(capsys.readouterr().out)
    polluted, trace, environments, _ = runtime_inherited
    if plan_location == "invalid":
        assert answer == {"error": "host plan must be a JSON object"}
        assert not trace.exists()
        assert environments == []
    else:
        assert answer == {"error": "workspace store is not initialized"}
        planned = None if plan_location == "invalid-record" else plan_location not in {"new", "absent"}
        assert_children(trace, polluted, planned, environments)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the public job runner reads /proc")
@pytest.mark.parametrize("planned", [True, False], ids=["planned", "legacy"])
def test_job_runner_keeps_plan_selection_through_run_retry_and_recovery(shop, inherited, planned):
    shop.recipes["recipes"]["ok"]["require_clean"] = True
    shop.save_recipes()
    shop.request_job("job-1", "ok")
    if planned:
        host_plan(shop)
    polluted, trace, _, parent = inherited
    trace.unlink(missing_ok=True)
    # The surrounding test drivers also invoke Git. Keep their ordinary calls valid;
    # override precedence is exercised independently at every object-read boundary.
    environment = {**parent, **POLICY, **shop.env()}
    assert shop.run_open(env=environment)["rows"][0]["state"] == "completed"
    receipts = shop.receipts("job-1")
    assert shop.run_open(env=environment)["rows"] == []
    assert shop.receipts("job-1") == receipts
    assert shop.jobs("recovery-status", env=environment)["jobs"][0]["job"] == "pilot/job-1"
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    # The pinned mailbox and runtime verifier have separate read policies. Observe
    # the object-read argv of this item's admitted callers only.
    children = {row["sid"]: {} for row in rows if row["event"] == "start"
                and row["argv"][1:3] == ["--no-optional-locks", "--no-replace-objects"]}
    for row in rows:
        if row["event"] == "def_param" and row["sid"] in children:
            children[row["sid"]][row["param"]] = row["value"]
    assert len(children) > 7, "admission, export, after-run witness and recovery must all read real Git objects"
    for values in children.values():
        assert {key: values.get(key, "") for key in POLICY} == POLICY
        assert {key: values[key] for key in polluted if key in values} == ({} if planned else polluted)


@pytest.mark.skipif(os.name == "nt", reason="provisioned profiles and role bindings use POSIX process controls")
@pytest.mark.parametrize("command", ["codex-start", "claude-start", "add-role"])
@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
@pytest.mark.parametrize("copied", [False, True], ids=["canonical", "copied"])
def test_public_provision_paths_pass_known_plan_to_git(
        setup, mr1_cli, inherited, tmp_path, tmp_path_factory, command, planned, copied):
    _, call = mr1_cli
    host = hierarchy_hosts.CLAUDE if command == "claude-start" else hierarchy_hosts.CODEX
    if planned:
        mr1_plan(setup, host)
    base = mr1_r4_copy_base(setup, tmp_path_factory) if copied else setup.base
    endpoint = "pilot/lane/review"
    body = {"base": str(base), "endpoint": endpoint, "cwd": str(setup.source)}
    if command in ("claude-start", "add-role"):
        body["session"] = "4f1c2b9e-8d7a-4c3b-9a1e-2f6d5c4b3a21"
    if command == "add-role":
        body.update(host=host, source_repo=str(setup.source))
    polluted, trace, environments, parent = inherited
    assert {"CODEX_THREAD_ID", "OPENAI_API_KEY"} <= polluted.keys()
    trace.unlink(missing_ok=True)
    environments.clear()
    before = dict(parent)
    bad_cwd = tmp_path / "not-a-repository"
    bad_cwd.mkdir()
    refused = call(command, setup.request(**{**body, "cwd": str(bad_cwd)}), expect=2)
    expected = ("a claude-code start needs a cwd inside a git checkout" if command == "claude-start" else
                "codex needs a cwd inside a git checkout")
    assert refused == {"error": expected}
    assert unbound(setup, endpoint)
    for _ in range(2):
        answer = call(command, setup.request(**body))
        assert answer["cwd"] == str(setup.source)
    if command == "codex-start":
        # The start operation only returns a profile; independent reads may share a base.
        with ThreadPoolExecutor(max_workers=3) as pool:
            answers = list(pool.map(lambda _: provision.codex_start(dict(body)), range(3)))
        assert all(answer["cwd"] == str(setup.source) for answer in answers)
    assert parent == before
    assert_children(trace, polluted, planned, environments)


@pytest.mark.skipif(os.name == "nt", reason="the pending-provision fixture uses POSIX interpreter permissions")
@pytest.mark.parametrize("mailbox_root", [123, None, "", "bad\x00root", "x" * 4097],
                         ids=["integer", "null", "empty", "nul", "oversized"])
def test_invalid_discovery_text_keeps_retained_refusal_and_scrubs_git(
        rb2_pending, mr1_cli, inherited, mailbox_root):
    _, call = mr1_cli
    path = rb2_pending.base / "provision.json"
    raw = json.dumps({"mailbox_root": mailbox_root, "initiative": "pilot"})
    path.write_text(raw, encoding="utf-8")
    polluted, trace, environments, _ = inherited
    trace.unlink(missing_ok=True)
    environments.clear()
    expected = {"error": ("runtime source verification failed: expected commit=None tree=None; "
                          "observed commit=unavailable tree=unavailable; 'source'; "
                          "reprovision into a new base through the existing handoff flow")}
    for _ in range(2):
        assert call("init", rb2_pending.init_request(), expect=2) == expected
        assert path.read_text(encoding="utf-8") == raw
    assert_children(trace, polluted, None, environments)


@pytest.mark.skipif(os.name == "nt", reason="the pending-provision fixture uses POSIX interpreter permissions")
@pytest.mark.parametrize("record", [[], {}], ids=["list", "empty-object"])
@pytest.mark.parametrize("form", ["list", "malformed", "symlink", "foreign"])
def test_local_plan_is_validated_before_unusable_record(rb2_pending, mr1_cli, inherited, record, form):
    _, call = mr1_cli
    record_path = rb2_pending.base / "provision.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    plan_path = rb2_pending.base / hierarchy_hosts.PLAN_FILE
    if form == "list":
        plan_path.write_text("[]", encoding="utf-8")
        expected = "host plan must be a JSON object"
    elif form == "malformed":
        plan_path.write_text("{", encoding="utf-8")
        expected = ("invalid host plan %s: Expecting property name enclosed in double quotes: "
                    "line 1 column 2 (char 1)") % plan_path
    elif form == "symlink":
        symlink_or_skip(rb2_pending.tmp / "missing-plan", plan_path)
        expected = "host plan must not be a symlink: " + str(plan_path)
    else:
        mr1_plan(rb2_pending, hierarchy_hosts.CODEX)
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["hierarchy"] = "other"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        expected = "host plan is for hierarchy other, but this base serves pilot"
    polluted, trace, environments, _ = inherited
    trace.unlink(missing_ok=True)
    environments.clear()
    for _ in range(2):
        assert call("init", rb2_pending.init_request(), expect=2) == {"error": expected}
        assert json.loads(record_path.read_text(encoding="utf-8")) == record
    assert not trace.exists()
    assert environments == []


@pytest.mark.skipif(os.name == "nt", reason="the pending-provision fixture uses POSIX interpreter permissions")
@pytest.mark.parametrize("stage", ["pin", "store", "retained"])
@pytest.mark.parametrize("form", ["malformed", "dangling", "invalid-root", "relative-root", "symlink-root",
                                  "foreign-initiative", "missing-initiative"])
def test_discovery_forms_keep_original_refusal(rb2_pending, mr1_cli, inherited, form, stage):
    _, call = mr1_cli
    record_path = rb2_pending.base / "provision.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    collision = "initiative base already exists: " + str(rb2_pending.base)
    expected = collision
    if form == "malformed":
        raw = "{"
        expected = "invalid JSON file %s: invalid JSON; repair provision.json" % record_path
    elif form == "dangling":
        record_path.unlink()
        symlink_or_skip(rb2_pending.tmp / "missing-record", record_path)
        raw = None
    elif form in {"invalid-root", "relative-root", "symlink-root"}:
        root = 123 if form == "invalid-root" else "relative/mailbox"
        if form == "symlink-root":
            alias = rb2_pending.tmp / "alias"
            symlink_or_skip(rb2_pending.base, alias, target_is_directory=True)
            root = str(alias / "mailbox")
        raw = json.dumps({"mailbox_root": root, "initiative": "pilot"})
        expected = ("runtime source verification failed: expected commit=None tree=None; "
                    "observed commit=unavailable tree=unavailable; 'source'; "
                    "reprovision into a new base through the existing handoff flow")
    else:
        home = rb2_pending.tmp / "foreign-home"
        home.mkdir()
        # A foreign or unidentified record cannot redirect discovery to another home.
        (home / hierarchy_hosts.PLAN_FILE).write_text("[]", encoding="utf-8")
        record["mailbox_root"] = str(home / "mailbox")
        if form == "foreign-initiative":
            record["initiative"] = "other"
        else:
            record.pop("initiative")
        raw = json.dumps(record)
    if raw is not None:
        record_path.write_text(raw, encoding="utf-8")
    polluted, trace, environments, _ = inherited
    trace.unlink(missing_ok=True)
    environments.clear()
    for _ in range(2):
        request = rb2_pending.init_request()
        if stage == "pin":
            request["source"] = str(rb2_pending.tmp / "missing-source")
            expected = "source checkout is unavailable: " + request["source"]
        elif stage == "store":
            request["store"] = str(rb2_pending.tmp / "missing-store")
            expected = "workspace store is not initialized"
        assert call("init", request, expect=2) == {"error": expected}
        assert record_path.is_symlink() if raw is None else record_path.read_text(encoding="utf-8") == raw
    if stage == "pin":
        assert not trace.exists()
        assert environments == []
    else:
        assert_children(trace, polluted, None, environments)


def test_inherited_fixture_preserves_git_ceiling(inherited):
    assert inherited[3]["GIT_CEILING_DIRECTORIES"] == os.environ["GIT_CEILING_DIRECTORIES"]


def test_inherited_fixture_includes_raw_host_billing(inherited):
    assert {"GEMINI_API_KEY", "GOOGLE_API_KEY"} <= inherited[0].keys()


def test_git_folder_comparison_resolves_aliases(repository, inherited, tmp_path):
    alias = tmp_path / "alias"
    symlink_or_skip(repository[0], alias, target_is_directory=True)
    invoke("jobs_folders", (alias, *repository[1:]), tmp_path, planned=False)
    assert_children(inherited[1], inherited[0], False, inherited[2])


@pytest.mark.skipif(os.name == "nt", reason="public move provisions POSIX profiles")
@pytest.mark.parametrize("plan_location", ["absent", "old", "new"])
def test_public_move_passes_known_plan_to_role_git(rb2c_registered_move, mr1_cli, inherited, plan_location):
    built, body = rb2c_registered_move
    _, call = mr1_cli
    endpoint = "pilot/lane/f2"
    mailbox(Path(body["old_root"]), "bind", {"endpoint": endpoint, "host": hierarchy_hosts.CODEX,
            "session": "4f1c2b9e-8d7a-4c3b-9a1e-2f6d5c4b3a21", "expected_generation": 0})
    body["roles"] = {endpoint: {"cwd": str(built.source)}}
    if plan_location != "absent":
        mr1_plan(built, hierarchy_hosts.CODEX)
        plan = json.loads((built.base / hierarchy_hosts.PLAN_FILE).read_text(encoding="utf-8"))
        if plan_location == "old":
            (built.base / hierarchy_hosts.PLAN_FILE).unlink()
            (Path(body["old_root"]).parent / hierarchy_hosts.PLAN_FILE).write_text(json.dumps(plan), encoding="utf-8")
    polluted, trace, environments, _ = inherited
    trace.unlink(missing_ok=True)
    environments.clear()
    for _ in range(2):
        if plan_location == "absent":
            answer = call("move", built.request(**body))
            assert answer["roles"][endpoint]["cwd"] == str(built.source)
        else:
            expected = ("a planned team hierarchy cannot be moved; start a new team run" if plan_location == "old"
                        else "a move cannot go into a planned team hierarchy; start a new team run")
            assert call("move", built.request(**body), expect=2) == {"error": expected}
    if plan_location == "absent":
        assert_children(trace, polluted, False, environments)
    else:
        assert not trace.exists()
        assert environments == []
