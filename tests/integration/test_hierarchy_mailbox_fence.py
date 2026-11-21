"""M1 item 2: every write is fenced to the current, acknowledged binding, the bind path checks independence
however it is reached, and sessions get scoped self and source views instead of a shell.

Identity stays configuration-bound at this tier: the fence compares the configured sender with the current
binding, and nothing here authenticates a session.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_board import hall  # noqa: F401
from tests.integration.test_hierarchy_mailbox import HELPER, ROOT, invoke, mailbox_snapshot, message, pilot  # noqa: F401
from tests.integration.test_hierarchy_mailbox_mcp import exchange, payload
from tests.integration.test_hierarchy_provision import Setup


HANDOFF = ROOT / "tools" / "hierarchy_handoff.py"
REFUSED_UNREADY = "handoff checkpoint has not been acknowledged"
STALE = "stale or mismatched sender binding"
SOURCE_TOOLS = {"source_show", "source_grep"}
pytestmark = pytest.mark.skipif(os.name == "nt", reason="the fixtures use POSIX modes")


def serve(root, frames, *, endpoint="a/lane/review", host="host-one", session=None, generation=1, extra=()):
    """One adapter run that keeps stderr, because a refused after-flush write reports there."""
    lines = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}]
    lines += [{"jsonrpc": "2.0", "id": index + 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
              for index, (name, arguments) in enumerate(frames)]
    result = subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint", endpoint,
                             "--host", host, "--session", session or endpoint, "--generation", str(generation), *extra],
                            input="".join(json.dumps(line) + "\n" for line in lines), capture_output=True, text=True,
                            timeout=30, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    return result, responses


def unacked_successor(root, endpoint, session, brief_dir):
    """Bind a replacement and stop before its acknowledgment, so it is current but not ready."""
    brief = brief_dir / ("brief-%s.md" % session)
    brief.write_bytes(b"Handoff.\n")
    request = invoke(root, "draft-handoff", {"endpoint": endpoint, "host": "host-one", "session": session,
                                             "outgoing_stopped": True,
                                             "briefs": [{"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}]})
    bound = invoke(root, "bind", request)
    assert bound["ready"] is False
    return bound


def acknowledge(root, bound):
    invoke(root, "ack-handoff", {"endpoint": bound["endpoint"], "session": bound["session"],
                                 "generation": bound["generation"], "checkpoint_sha256": bound["checkpoint_sha256"]})


# The fence: a write needs the current binding and, after a handoff, its acknowledgment.

def test_an_unacknowledged_successor_reads_and_its_receipt_names_its_own_generation(pilot, tmp_path):  # noqa: F811
    """Only staleness fences a receipt: it records what was returned to the current binding, and authors nothing."""
    root, _ = pilot
    invoke(root, "publish", message(recipient="a/lane/review"))
    bound = unacked_successor(root, "a/lane/review", "successor", tmp_path)
    delivery = root.parent / "delivery"
    result, responses = serve(root, [("mailbox_inbox", {})], session="successor", generation=bound["generation"],
                              extra=["--delivery-dir", str(delivery)])
    assert [row["message"]["message_id"] for row in payload(responses[-1])["messages"]] == ["dispatch-1"]
    assert result.stderr == ""
    state = invoke(root, "delivery", delivery_dir=delivery, message_id="dispatch-1")["message"]
    assert state["state"] == "read" and state["read_by"] == {"host": "host-one", "session": "successor",
                                                             "generation": bound["generation"]}


def test_an_unacknowledged_successor_cannot_post_or_close_on_the_board(hall):  # noqa: F811
    old = hall.client()
    blocker = old.post("blocker", kind="blocker", body="Waiting on review.")
    old.close()
    bound = unacked_successor(hall.root, "a/lane/f2", "successor", hall.root.parent)
    before = hall.snapshot()
    successor = hall.client(session="successor", generation=bound["generation"])
    assert successor.refused("board_publish", channel="alpha", key="early", kind="note", body="Too soon.") == REFUSED_UNREADY
    assert successor.refused("board_disposition", post_id=blocker["post_id"], state="resolved") == REFUSED_UNREADY
    assert hall.snapshot() == before
    acknowledge(hall.root, bound)
    assert successor.post("after-ack")["from"] == "a/lane/f2"


def test_a_board_write_takes_the_mailbox_writer_lock(hall):  # noqa: F811
    """The binding check and the board write share the mailbox lock, so a rebinding cannot land between them.
    Like the board's own lock, it is waited for briefly before the post is refused."""
    client = hall.client()
    before = hall.snapshot()
    lock = hall.root / ".write.lock"
    lock.write_text("held by a test")
    try:
        assert client.refused("board_publish", channel="alpha", key="locked", kind="note",
                              body="Blocked.").startswith("mailbox writer is busy")
    finally:
        lock.unlink()
    assert hall.snapshot() == before
    assert client.post("unlocked")["from"] == "a/lane/f2"


def test_a_board_post_waits_for_a_briefly_held_mailbox_lock(hall):  # noqa: F811
    client = hall.client()
    lock = hall.root / ".write.lock"
    lock.write_text("held by a test")
    releaser = subprocess.Popen([sys.executable, "-c", "import os, sys, time; time.sleep(0.5); os.unlink(sys.argv[1])",
                                 str(lock)])
    try:
        assert client.post("after-wait")["from"] == "a/lane/f2"
    finally:
        releaser.wait(timeout=10)


# Independence: the registry's separate-session rule holds on every path that binds.

INDEPENDENCE_ENDPOINTS = {"a/front-door": {}, "a/orchestrator": {}, "a/decider": {},
                          "a/lane/f2": {"kind": "implementer"}, "a/lane/review": {"kind": "reviewer"}}


@pytest.fixture
def team(tmp_path):
    root = tmp_path / "team" / "mailbox"
    root.parent.mkdir()
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": INDEPENDENCE_ENDPOINTS,
                          "counterparts": [], "writer_limit": 3})
    return root


def team_brief(root):
    brief = root.parent / "brief.md"
    brief.write_bytes(b"Handoff.\n")
    return {"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}


def held_by(session, holder, independent):
    return ("session %s already holds %s; the role registry needs a separate session for %s"
            % (session, holder, independent))


@pytest.mark.parametrize("first,second,independent", [
    ("a/lane/f2", "a/lane/review", "a/lane/review"),
    ("a/lane/review", "a/lane/f2", "a/lane/review"),
    ("a/orchestrator", "a/decider", "a/decider"),
])
def test_a_direct_bind_refuses_one_session_on_both_sides(team, first, second, independent):
    invoke(team, "bind", {"endpoint": first, "host": "host-one", "session": "shared", "expected_generation": 0})
    refused = invoke(team, "bind", {"endpoint": second, "host": "host-one", "session": "shared",
                                    "expected_generation": 0}, ok=False)
    assert refused == {"error": held_by("shared", first, independent)}
    assert invoke(team, "status")["bindings"][second] is None


def test_a_direct_bind_allows_one_session_on_roles_without_a_rule(team):
    invoke(team, "bind", {"endpoint": "a/front-door", "host": "host-one", "session": "shared", "expected_generation": 0})
    assert invoke(team, "bind", {"endpoint": "a/orchestrator", "host": "host-one", "session": "shared",
                                 "expected_generation": 0})["generation"] == 1


def test_the_same_session_name_on_another_host_is_another_session(team):
    invoke(team, "bind", {"endpoint": "a/lane/f2", "host": "host-one", "session": "shared", "expected_generation": 0})
    assert invoke(team, "bind", {"endpoint": "a/lane/review", "host": "host-two", "session": "shared",
                                 "expected_generation": 0})["generation"] == 1


def test_a_replacement_bind_refuses_a_session_holding_the_other_side(team, tmp_path):
    for endpoint in INDEPENDENCE_ENDPOINTS:
        invoke(team, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    request = invoke(team, "draft-handoff", {"endpoint": "a/lane/review", "host": "host-one", "session": "a/lane/f2",
                                             "outgoing_stopped": True, "briefs": [team_brief(team)]})
    assert invoke(team, "bind", request, ok=False) == {"error": held_by("a/lane/f2", "a/lane/f2", "a/lane/review")}
    assert invoke(team, "status")["bindings"]["a/lane/review"]["generation"] == 1


def test_the_handoff_tool_refuses_one_session_on_both_sides(team, tmp_path):
    for endpoint in INDEPENDENCE_ENDPOINTS:
        invoke(team, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"schema": "aegis.hierarchy-handoff/v1", "host": "host-one", "session": "a/lane/f2",
                                "outgoing_stopped": True, "entries": [{"root": str(team), "endpoint": "a/lane/review",
                                                                         "briefs": [team_brief(team)]}]}))
    result = subprocess.run([sys.executable, "-I", str(HANDOFF), "--spec", str(spec)], capture_output=True, text=True,
                            timeout=30, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 3, result.stdout + result.stderr
    row = json.loads(result.stdout)["entries"][0]
    assert row["ok"] is False and row["error"] == held_by("a/lane/f2", "a/lane/f2", "a/lane/review")
    assert invoke(team, "status")["bindings"]["a/lane/review"]["generation"] == 1


# The self view: what this connection is configured as, checked against the current binding.

def test_every_mailbox_connection_offers_a_self_view(pilot):  # noqa: F811
    root, _ = pilot
    responses = exchange(root, [("mailbox_self", {})], endpoint="a/lane/f2")
    assert "mailbox_self" in {tool["name"] for tool in responses[1]["result"]["tools"]}
    view = payload(responses[-1])
    assert view == {"endpoint": "a/lane/f2", "role": "implementer", "host": "host-one", "session": "a/lane/f2",
                    "generation": 1, "ready": True, "current": True, "identity": "configured",
                    "authenticated": False,
                    "tools": sorted(tool["name"] for tool in responses[1]["result"]["tools"])}


def test_the_self_view_shows_an_unacknowledged_successor_as_not_ready(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    bound = unacked_successor(root, "a/lane/review", "successor", tmp_path)
    view = payload(exchange(root, [("mailbox_self", {})], session="successor", generation=bound["generation"])[-1])
    assert (view["generation"], view["ready"], view["current"]) == (2, False, True)


def test_the_self_view_refuses_a_stale_session_like_every_other_call(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    process = subprocess.Popen([sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint",
                                "a/lane/review", "--host", "host-one", "--session", "a/lane/review", "--generation", "1"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        process.stdin.flush()
        assert "result" in json.loads(process.stdout.readline())
        unacked_successor(root, "a/lane/review", "successor", tmp_path)
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                        "params": {"name": "mailbox_self", "arguments": {}}}) + "\n")
        process.stdin.flush()
        response = json.loads(process.stdout.readline())
        assert response["result"]["isError"] is True and payload(response) == {"error": STALE}
    finally:
        process.stdin.close()
        process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()


def test_the_self_view_takes_no_arguments(pilot):  # noqa: F811
    root, _ = pilot
    response = exchange(root, [("mailbox_self", {"session": "someone-else"})])[-1]
    assert response["result"]["isError"] is True and "unexpected fields" in payload(response)["error"]


# Source views: a read-only role reads exact commits without a shell, and never the working tree.

def git(repository, *arguments):
    return subprocess.run(["git", "-C", str(repository), *arguments], check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}).stdout.strip()


@pytest.fixture
def project(tmp_path):
    repository = tmp_path / "project"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "app.py").write_text("".join("line %d needle\n" % number if number % 10 == 0 else "line %d\n" % number
                                                       for number in range(1, 101)))
    (repository / "README.md").write_text("Project.\nneedle in the readme\n")
    (repository / "blob.bin").write_bytes(b"\x00\x01binary needle\x00")
    git(repository, "init", "-q", "-b", "main")
    git(repository, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", ".")
    git(repository, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "first")
    commit = git(repository, "rev-parse", "HEAD")
    # Uncommitted changes and untracked files are what a working tree shows; the views must not.
    (repository / "src" / "app.py").write_text("line 1 needle in the working tree only\n")
    (repository / "untracked.py").write_text("needle untracked\n")
    return repository, commit


def source_call(root, repository, calls, endpoint="a/lane/review", **options):
    return exchange_with(root, calls, endpoint, ["--source-repo", str(repository)], **options)


def exchange_with(root, calls, endpoint, extra, **options):
    result, responses = serve(root, calls, endpoint=endpoint, extra=extra, **options)
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    return responses


def test_a_reader_role_gets_source_views_only_when_a_repository_is_configured(pilot, project):  # noqa: F811
    root, _ = pilot
    repository, _ = project
    listed = exchange_with(root, [], "a/lane/review", ["--source-repo", str(repository)])
    assert len(listed) == 1  # initialize answers, so startup accepted the repository
    configured = subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint",
                                 "a/lane/review", "--host", "host-one", "--session", "a/lane/review", "--generation", "1",
                                 "--source-repo", str(repository)],
                                input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n",
                                capture_output=True, text=True, timeout=15)
    assert SOURCE_TOOLS <= {tool["name"] for tool in json.loads(configured.stdout)["result"]["tools"]}
    without = exchange(root, [], endpoint="a/lane/review")[1]["result"]["tools"]
    assert not SOURCE_TOOLS & {tool["name"] for tool in without}


@pytest.mark.parametrize("endpoint", ["a/lane/f2", "a/front-door"])
def test_a_role_that_writes_source_or_never_reads_it_cannot_start_with_source_views(pilot, project, endpoint):  # noqa: F811
    root, _ = pilot
    repository, _ = project
    result, _ = serve(root, [], endpoint=endpoint, extra=["--source-repo", str(repository)])
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": "the %s role has no source views: they are for roles that read source "
                                                  "and write none" % ("implementer" if endpoint == "a/lane/f2" else "front-door")}


def test_show_pages_a_file_at_an_exact_commit(pilot, project):  # noqa: F811
    root, _ = pilot
    repository, commit = project
    first, second = (payload(response) for response in source_call(root, repository, [
        ("source_show", {"commit": commit, "path": "src/app.py", "max_lines": 40}),
        ("source_show", {"commit": commit, "path": "src/app.py", "start_line": 41, "max_lines": 100}),
    ])[1:])
    blob = git(repository, "rev-parse", commit + ":src/app.py")
    assert first == {"commit": commit, "path": "src/app.py", "blob": blob, "start_line": 1, "total_lines": 100,
                     "lines": ["line %d" % n + (" needle" if n % 10 == 0 else "") for n in range(1, 41)],
                     "cut_lines": [], "next_start_line": 41}
    assert second["lines"][0] == "line 41" and len(second["lines"]) == 60 and second["next_start_line"] is None


def test_show_cuts_long_lines_and_keeps_a_page_within_its_byte_budget(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    repository = tmp_path / "wide"
    repository.mkdir()
    (repository / "wide.txt").write_text("x" * 5000 + "\n" + "".join("y" * 1000 + "\n" for _ in range(200)))
    git(repository, "init", "-q", "-b", "main")
    git(repository, "add", ".")
    git(repository, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "wide")
    commit = git(repository, "rev-parse", "HEAD")
    page = payload(source_call(root, repository, [("source_show", {"commit": commit, "path": "wide.txt",
                                                                   "max_lines": 2000})])[-1])
    assert page["lines"][0] == "x" * 4096 and page["cut_lines"] == [1]
    assert len(json.dumps(json.dumps(page))) <= 262144
    assert page["next_start_line"] == 1 + len(page["lines"]) < page["total_lines"] == 201


def test_grep_searches_the_commit_never_the_working_tree(pilot, project):  # noqa: F811
    root, _ = pilot
    repository, commit = project
    found = payload(source_call(root, repository, [("source_grep", {"commit": commit, "pattern": "needle"})])[-1])
    assert found["commit"] == commit and found["truncated"] is False
    assert [(m["path"], m["line"]) for m in found["matches"]] == (
        [("README.md", 2)] + [("src/app.py", n) for n in range(10, 101, 10)])
    assert found["matches"][0]["text"] == "needle in the readme"
    limited = payload(source_call(root, repository, [("source_grep", {"commit": commit, "pattern": "needle",
                                                                      "paths": ["src"], "limit": 3})])[-1])
    assert [(m["path"], m["line"]) for m in limited["matches"]] == [("src/app.py", 10), ("src/app.py", 20), ("src/app.py", 30)]
    assert limited["truncated"] is True


def test_grep_pattern_is_a_fixed_string(pilot, project):  # noqa: F811
    root, _ = pilot
    repository, commit = project
    found = payload(source_call(root, repository, [("source_grep", {"commit": commit, "pattern": "line 1.0"})])[-1])
    assert found["matches"] == []


@pytest.mark.parametrize("arguments,error", [
    ({"commit": "abc123", "path": "README.md"}, "commit must be a full 40-character commit id"),
    ({"commit": "0" * 40, "path": "README.md"}, "commit not found in the source repository"),
    ({"commit": None, "path": "../outside"}, "path must be relative and stay inside the repository"),
    ({"commit": None, "path": "/etc/passwd"}, "path must be relative and stay inside the repository"),
    ({"commit": None, "path": "-p"}, "path must be relative and stay inside the repository"),
    ({"commit": None, "path": "untracked.py"}, "path not found at that commit: untracked.py"),
    ({"commit": None, "path": "src"}, "path not found at that commit: src"),
    ({"commit": None, "path": "blob.bin"}, "binary file; source_show returns text only"),
    ({"commit": None, "path": "README.md", "start_line": 0}, "start line must be at least 1"),
    ({"commit": None, "path": "README.md", "max_lines": 2001}, "max lines must be between 1 and 2000"),
    ({"commit": None, "path": "README.md", "start_line": 9}, "start line is past the end of the file"),
])
def test_show_refuses_anything_but_text_at_an_exact_commit(pilot, project, arguments, error):  # noqa: F811
    root, _ = pilot
    repository, commit = project
    arguments = {**arguments, "commit": commit if arguments["commit"] is None else arguments["commit"]}
    response = source_call(root, repository, [("source_show", arguments)])[-1]
    assert response["result"]["isError"] is True and payload(response) == {"error": error}


@pytest.mark.parametrize("arguments,error", [
    ({"pattern": ""}, "pattern must be 1 to 256 characters"),
    ({"pattern": "x", "paths": ["../up"]}, "path must be relative and stay inside the repository"),
    ({"pattern": "x", "limit": 501}, "limit must be between 1 and 500"),
    ({"pattern": "x", "commit": "HEAD"}, "commit must be a full 40-character commit id"),
])
def test_grep_refuses_malformed_arguments(pilot, project, arguments, error):  # noqa: F811
    root, _ = pilot
    repository, commit = project
    response = source_call(root, repository, [("source_grep", {"commit": commit, **arguments})])[-1]
    assert response["result"]["isError"] is True and payload(response) == {"error": error}


def test_a_stale_session_cannot_read_source(pilot, project, tmp_path):  # noqa: F811
    root, _ = pilot
    repository, commit = project
    process = subprocess.Popen([sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint",
                                "a/lane/review", "--host", "host-one", "--session", "a/lane/review", "--generation", "1",
                                "--source-repo", str(repository)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        process.stdin.flush()
        assert "result" in json.loads(process.stdout.readline())
        unacked_successor(root, "a/lane/review", "successor", tmp_path)
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "source_show", "arguments": {"commit": commit, "path": "README.md"}}}) + "\n")
        process.stdin.flush()
        assert payload(json.loads(process.stdout.readline())) == {"error": STALE}
    finally:
        process.stdin.close()
        process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()


def test_the_source_repository_must_be_an_absolute_git_checkout(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    plain = tmp_path / "plain"
    plain.mkdir()
    result, _ = serve(root, [], extra=["--source-repo", str(plain)])
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": "--source-repo is not a git repository: " + str(plain)}
    result, _ = serve(root, [], extra=["--source-repo", "relative/path"])
    assert result.returncode == 2 and "must be absolute" in json.loads(result.stdout)["error"]


# Provisioning carries the source repository to the roles that may read it.

@pytest.fixture
def setup(tmp_path):
    built = Setup(tmp_path)
    built.init()
    return built


def test_add_role_gives_a_reviewer_its_source_views(setup, project):
    repository, _ = project
    role = setup.add_role("pilot/lane/review", cwd=str(setup.tmp), source_repo=str(repository))
    servers = json.loads(Path(role["connection"]).read_text())["mcpServers"]
    args = servers["aegis_mailbox"]["args"]
    assert args[args.index("--source-repo") + 1] == str(repository)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    allowed = argv[argv.index("--allowedTools") + 1].split(",")
    assert {"mcp__aegis_mailbox__source_show", "mcp__aegis_mailbox__source_grep",
            "mcp__aegis_mailbox__mailbox_self"} <= set(allowed)


def test_add_role_refuses_source_views_for_a_writer(setup, project):
    repository, _ = project
    refused = setup.add_role("pilot/lane/f2", cwd=str(setup.tmp), source_repo=str(repository), expect=2)
    assert refused["error"] == ("the implementer role has no source views: they are for roles that read source and "
                                "write none")
    assert invoke(setup.root, "status")["bindings"]["pilot/lane/f2"] is None


def test_provisioned_source_views_answer_from_the_wake_profile_connection(setup, project):
    repository, commit = project
    role = setup.add_role("pilot/lane/review", cwd=str(setup.tmp), source_repo=str(repository))
    server = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "source_show", "arguments": {"commit": commit, "path": "README.md"}}}]
    result = subprocess.run([server["command"], *server["args"]], input=json.dumps(frames[0]) + "\n",
                            capture_output=True, text=True, timeout=15)
    assert payload(json.loads(result.stdout))["lines"] == ["Project.", "needle in the readme"]


def test_a_role_provisioned_without_a_repository_gets_no_source_views(setup):
    role = setup.add_role("pilot/lane/review", cwd=str(setup.tmp))
    assert "--source-repo" not in json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]["args"]
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert not {"mcp__aegis_mailbox__" + name for name in SOURCE_TOOLS} & set(argv[argv.index("--allowedTools") + 1].split(","))


# Review follow-ups (independent review of 4d13ef0).

sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_mailbox_mcp  # noqa: E402
import hierarchy_source  # noqa: E402

from tests.integration.test_hierarchy_carry import fresh, move_request  # noqa: E402,F401
from tests.integration.test_hierarchy_provision import codex_config, provision  # noqa: E402

RESPONSE_BUDGET = 262144


def rendered(result):
    return len(hierarchy_mailbox_mcp._response_line({"jsonrpc": "2.0", "id": 1,
                                                     "result": hierarchy_mailbox_mcp._tool_result(result)}))


def committed(repository, files):
    repository.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (repository / name).parent.mkdir(parents=True, exist_ok=True)
        (repository / name).write_bytes(data)
    git(repository, "init", "-q", "-b", "main")
    git(repository, "add", ".")
    git(repository, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "c")
    return git(repository, "rev-parse", "HEAD")


def test_one_session_may_hold_the_same_role_in_several_hierarchies(tmp_path):
    root = tmp_path / "shared" / "mailbox"
    root.parent.mkdir()
    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/root": {}, "b/front-door": {}, "b/orchestrator": {},
                 "b/root": {}, "a/lane/r1": {"kind": "reviewer"}, "a/lane/r2": {"kind": "reviewer"}}
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [],
                          "writer_limit": 3})
    for endpoint in ("a/root", "b/root"):
        invoke(root, "bind", {"endpoint": endpoint, "host": "codex", "session": "one-root", "expected_generation": 0})
    for endpoint in ("a/lane/r1", "a/lane/r2"):
        invoke(root, "bind", {"endpoint": endpoint, "host": "codex", "session": "one-reviewer", "expected_generation": 0})
    refused = invoke(root, "bind", {"endpoint": "a/orchestrator", "host": "codex", "session": "one-root",
                                    "expected_generation": 0}, ok=False)
    assert refused == {"error": held_by("one-root", "a/root", "a/root")}


def test_mark_read_records_only_for_the_configured_current_root(tmp_path):
    root = tmp_path / "rooted" / "mailbox"
    root.parent.mkdir()
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "counterparts": [], "writer_limit": 3,
                          "endpoints": {"a/front-door": {}, "a/orchestrator": {}, "a/root": {}}})
    for endpoint in ("a/front-door", "a/orchestrator", "a/root"):
        invoke(root, "bind", {"endpoint": endpoint, "host": "codex", "session": endpoint.replace("/", "-"),
                              "expected_generation": 0})
    invoke(root, "publish", {"message_id": "to-root", "from": "a/orchestrator", "to": "a/root", "host": "codex",
                             "session": "a-orchestrator", "binding_generation": 1, "type": "info", "body": "Status."})
    delivery = root.parent / "delivery"
    unconfigured = invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True, ok=False)
    assert unconfigured == {"error": "--mark-read needs --host, --session and --generation for the reading root"}
    bound = unacked_successor(root, "a/root", "successor-root", root.parent)
    acknowledge(root, bound)
    stale = subprocess.run([sys.executable, str(HELPER), "--root", str(root), "inbox", "--endpoint", "a/root",
                            "--delivery-dir", str(delivery), "--mark-read", "--host", "codex", "--session", "a-root",
                            "--generation", "1"], capture_output=True, text=True, timeout=15, check=False)
    assert stale.stderr == "read receipt not recorded: " + STALE + "\n"
    assert invoke(root, "delivery", delivery_dir=delivery, message_id="to-root")["message"]["state"] == "published"
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True, host="host-one",
           session="successor-root", generation=bound["generation"])
    state = invoke(root, "delivery", delivery_dir=delivery, message_id="to-root")["message"]
    assert state["read_by"] == {"host": "host-one", "session": "successor-root", "generation": bound["generation"]}


def test_a_waiting_board_post_never_holds_the_mailbox_lock(hall):  # noqa: F811
    """While another writer holds the board lock, mailbox writes go ahead; the post lands once the board frees."""
    client = hall.client()
    board_lock = hall.board / ".write.lock"
    board_lock.write_text("held by a test")
    client.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {
        "name": "board_publish", "arguments": {"channel": "alpha", "key": "waits", "kind": "note", "body": "Waiting."}}})
                               + "\n")
    client.process.stdin.flush()
    try:
        for attempt in range(5):
            # invoke asserts exit 0, so each of these is a publish that was not refused as busy.
            invoke(hall.root, "publish", message("a/orchestrator", "a/lane/f2", identifier="during-%d" % attempt))
    finally:
        board_lock.unlink()
    response = json.loads(client.process.stdout.readline())
    assert not response["result"].get("isError"), response
    assert payload(response)["from"] == "a/lane/f2" and payload(response)["replayed"] is False


def test_a_retired_session_cannot_move_its_successors_board_position(hall):  # noqa: F811
    author = hall.client()
    posted = [author.post("post-%d" % number)["post_id"] for number in range(3)]
    old = hall.client("a/orchestrator")
    lock = hall.root / ".write.lock"
    lock.write_text("held by a test")
    try:
        assert [post["post_id"] for post in old.read(limit=2)["posts"]] == posted[:2]
        # The position write now waits for the lock. Rebind meanwhile, as the lock's holder would.
        brief = hall.root.parent / "brief-rebind.md"
        brief.write_bytes(b"Handoff.\n")
        sys.path.insert(0, str(ROOT / "tools"))
        import hierarchy_mailbox
        mailbox = hierarchy_mailbox.Mailbox(hall.root)
        bound = mailbox.bind(mailbox.draft_handoff({
            "endpoint": "a/orchestrator", "host": "host-one", "session": "successor", "outgoing_stopped": True,
            "briefs": [{"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}]}))
        mailbox.acknowledge_handoff({"endpoint": "a/orchestrator", "session": "successor",
                                     "generation": bound["generation"], "checkpoint_sha256": bound["checkpoint_sha256"]})
    finally:
        lock.unlink()
    old.close()
    fresh_client = hall.client("a/orchestrator", session="successor", generation=bound["generation"])
    assert [post["post_id"] for post in fresh_client.read()["posts"]] == posted


def test_an_unacknowledged_successors_board_read_moves_its_position(hall):  # noqa: F811
    author = hall.client()
    posted = [author.post("post-%d" % number)["post_id"] for number in range(2)]
    bound = unacked_successor(hall.root, "a/orchestrator", "successor", hall.root.parent)
    early = hall.client("a/orchestrator", session="successor", generation=bound["generation"])
    assert [post["post_id"] for post in early.read()["posts"]] == posted
    early.send("ping")
    early.close()
    acknowledge(hall.root, bound)
    assert hall.client("a/orchestrator", session="successor", generation=bound["generation"]).read()["posts"] == []


def test_re_running_add_role_refuses_a_session_that_already_holds_the_other_side(setup):
    session = "00000000-0000-0000-0000-00000000000a"
    setup.add_role("pilot/lane/f2", cwd=str(setup.tmp), session=session)
    # A binding made before every bind was checked: written directly, as an old mailbox may hold one.
    legacy = setup.root / "bindings" / "pilot/lane/review" / "000001.json"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text(json.dumps({"schema": "aegis.role-binding/v1", "endpoint": "pilot/lane/review",
                                  "host": "claude-code", "session": session, "generation": 1,
                                  "created_at": "2026-11-05T00:00:00.000000Z", "checkpoint": None,
                                  "checkpoint_sha256": None}))
    refused = setup.add_role("pilot/lane/review", cwd=str(setup.tmp), session=session, expect=2)
    assert refused["error"] == held_by(session, "pilot/lane/f2", "pilot/lane/review")


def test_a_move_refuses_an_old_root_where_one_session_holds_both_sides(fresh):  # noqa: F811
    legacy = fresh.old / "bindings" / "a/lane/look" / "000001.json"
    record = json.loads(legacy.read_text())
    legacy.write_text(json.dumps({**record, "session": "cli-build"}))
    refused = provision("move", move_request(fresh), expect=2)
    assert refused["error"] == held_by("cli-build", "a/lane/build", "a/lane/look")


def test_a_codex_reviewer_gets_working_source_views(setup, project):
    repository, commit = project
    role = setup.add_role("pilot/lane/review", "codex-cli", session="01a19969-41df-7631-8ecd-57add111e96c",
                          cwd=str(setup.source), source_repo=str(repository), reader_shell=True,
                          skip_git_repo_check=True)
    server = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])["mcp_servers"]["aegis_mailbox"]
    assert server["args"][server["args"].index("--source-repo") + 1] == str(repository)
    assert {"source_show", "source_grep", "mailbox_self"} <= set(server["enabled_tools"])
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "source_show", "arguments": {"commit": commit, "path": "README.md"}}}
    result = subprocess.run([server["command"], *server["args"]], input=json.dumps(frame) + "\n",
                            capture_output=True, text=True, timeout=15, check=False)
    assert payload(json.loads(result.stdout))["lines"] == ["Project.", "needle in the readme"]


def test_a_lazy_fetch_can_never_run_repository_configured_commands(tmp_path):
    repository = tmp_path / "lazy"
    commit = committed(repository, {"b.txt": b"secret\n"})
    views = hierarchy_source.SourceViews(repository)
    marker = tmp_path / "ran"
    # After startup, a writer turns the repository into a partial clone whose fetch runs a command, and the
    # blob goes missing, so reading it would make Git fetch lazily.
    git(repository, "config", "core.repositoryformatversion", "1")
    git(repository, "config", "extensions.partialClone", "origin")
    git(repository, "config", "remote.origin.url", "file://" + str(tmp_path / "nowhere"))
    git(repository, "config", "remote.origin.promisor", "true")
    git(repository, "config", "remote.origin.uploadpack", "sh -c 'touch %s; exit 1'" % marker)
    blob = git(repository, "rev-parse", commit + ":b.txt")
    (repository / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
    with pytest.raises(ValueError):
        views.show({"commit": commit, "path": "b.txt"})
    with pytest.raises(ValueError, match="git failed in the source repository"):
        views.grep({"commit": commit, "pattern": "secret"})
    assert not marker.exists()
    with pytest.raises(ValueError, match="partial clone"):
        hierarchy_source.SourceViews(repository)


def fake_git(tmp_path, monkeypatch, slow):
    real = subprocess.run(["sh", "-c", "command -v git"], capture_output=True, text=True, check=True).stdout.strip()
    folder = tmp_path / "fake-bin"
    folder.mkdir()
    (folder / "git").write_text("#!/bin/sh\ncase \"$*\" in *\"%s\"*) sleep 5;; esac\nexec %s \"$@\"\n" % (slow, real))
    (folder / "git").chmod(0o755)
    monkeypatch.setenv("PATH", str(folder) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(hierarchy_source, "GIT_TIMEOUT_SECONDS", 1)


@pytest.mark.parametrize("slow,call", [
    ("cat-file blob", lambda views, commit: views.show({"commit": commit, "path": "README.md"})),
    (" grep ", lambda views, commit: views.grep({"commit": commit, "pattern": "needle"})),
])
def test_a_slow_git_is_a_refusal_not_a_crash(project, tmp_path, monkeypatch, slow, call):
    repository, commit = project
    views = hierarchy_source.SourceViews(repository)
    fake_git(tmp_path, monkeypatch, slow)
    with pytest.raises(ValueError, match="git timed out in the source repository"):
        call(views, commit)


def test_show_bounds_its_rendered_response(tmp_path):
    repository = tmp_path / "controls"
    commit = committed(repository, {"c.txt": ("\x01" * 4000 + "\n").encode() * 200})
    page = hierarchy_source.SourceViews(repository).show({"commit": commit, "path": "c.txt", "max_lines": 2000})
    assert rendered(page) <= RESPONSE_BUDGET
    assert page["lines"] and page["next_start_line"] == 1 + len(page["lines"])


def test_grep_bounds_its_rendered_response(tmp_path):
    repository = tmp_path / "paths"
    long_dir = "/".join(["é" * 60] * 3)
    commit = committed(repository, {"%s/f%03d.txt" % (long_dir, n): b"needle\n" * 5 for n in range(120)})
    found = hierarchy_source.SourceViews(repository).grep({"commit": commit, "pattern": "needle", "limit": 500})
    assert rendered(found) <= RESPONSE_BUDGET
    assert found["truncated"] is True and found["matches"]


def test_grep_ignores_repository_settings_that_reshape_its_output(project):
    repository, commit = project
    git(repository, "config", "grep.column", "true")
    git(repository, "config", "grep.lineNumber", "false")
    git(repository, "config", "grep.fullName", "false")
    git(repository, "config", "grep.patternType", "perl")
    found = hierarchy_source.SourceViews(repository).grep({"commit": commit, "pattern": "needle in the readme"})
    assert found["matches"] == [{"path": "README.md", "line": 2, "text": "needle in the readme"}]


def test_grep_never_reads_a_submodules_objects(tmp_path):
    inner = tmp_path / "inner"
    committed(inner, {"s.txt": b"submodule token\n"})
    outer = tmp_path / "outer"
    committed(outer, {"top.txt": b"top token\n"})
    git(outer, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(inner), "sm")
    git(outer, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "sm")
    commit = git(outer, "rev-parse", "HEAD")
    git(outer, "config", "submodule.recurse", "true")
    found = hierarchy_source.SourceViews(outer).grep({"commit": commit, "pattern": "token"})
    assert [match["path"] for match in found["matches"]] == ["top.txt"]
