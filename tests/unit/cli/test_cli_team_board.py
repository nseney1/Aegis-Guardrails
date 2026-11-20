"""Owner CLI board verbs retain legacy read/configuration outcomes."""
from datetime import datetime, timezone
import json
from types import SimpleNamespace

import pytest

from aegis_cli.cli import main
from aegis_cli import team_mail
from aegis_core import team_mailbox_store as storage
from aegis_core import team_profile
from aegis_core import team_board
from aegis_core.team_mailbox_primitives import RoleTables
from tools import hierarchy_board as legacy


NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)
PARITY = {"init": "initialize", "add-channel": "channel", "grant": "grant", "revoke": "revoke",
          "tombstone": "tombstone", "status": "status", "verify": "verify", "digest": "digest", "read": "read"}


@pytest.fixture
def board(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    monkeypatch.setattr(team_mail, "now_utc", lambda: NOW)
    monkeypatch.setattr(team_profile, "load", lambda root: team_profile.resolve(preset="solo"))
    owner = tmp_path / "owner"
    (owner / ".aegis").mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(storage, "pwd", SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_dir=str(owner))))
    return tmp_path / "board"


def invoke(root, capsys, verb, *options):
    code = main(["--workspace", str(root.parent), "team", "board", verb, "--board", str(root), "--json", *options])
    output = capsys.readouterr()
    assert output.err == ""
    return code, json.loads(output.out)


def configure(root, capsys, verb, request):
    path = root.parent / "request.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    return invoke(root, capsys, verb, "--request", str(path))


def test_board_cli_legacy_parity(board, capsys, monkeypatch):
    monkeypatch.setattr(legacy, "now_utc", lambda: NOW)
    monkeypatch.setattr(legacy, "timestamp", lambda: "2026-11-19T00:00:00.000000Z")
    old = legacy.Board(board.parent / "legacy-board")
    old.initialize()
    assert invoke(board, capsys, "init")[0] == 0
    for verb, kind, request in (
        ("add-channel", "channel", {"channel": "alpha", "orchestrator": "a/orchestrator", "source": "owner"}),
        ("grant", "grant", {"channel": "alpha", "endpoint": "a/lane/one", "access": "post", "source": "owner"}),
        ("revoke", "revoke", {"channel": "alpha", "endpoint": "a/lane/one", "source": "owner"}),
    ):
        with old.lock():
            state = old.load()
            old.append(state, kind, request)
        code, actual = configure(board, capsys, verb, request)
        assert code == 0 and actual == {"channel": "alpha", "grants": state.channels["alpha"]["grants"]}
    for verb in ("status", "verify"):
        code, actual = invoke(board, capsys, verb)
        assert code == 0 and actual == (old.status() if verb == "status" else old.verify())
    assert invoke(board, capsys, "read", "--channel", "alpha")[1] == old.channel_page(
        old.load(), "alpha", None, 20, legacy.cli_line)
    code, digest = invoke(board, capsys, "digest", "--channel", "alpha")
    assert code == 0 and digest == legacy.digest_text(old, old.load(), "alpha", NOW)


def test_board_refusal_does_not_append_and_retry_works(board, capsys):
    assert invoke(board, capsys, "init")[0] == 0
    before = {p.name: p.read_bytes() for p in (board / "events").iterdir()}
    code, result = configure(board, capsys, "grant", {"channel": "absent", "endpoint": "a/lane/one",
                                                   "access": "post", "source": "owner"})
    assert code == 1 and result["status"] == "refused" and result["next_action"]
    assert {p.name: p.read_bytes() for p in (board / "events").iterdir()} == before
    assert configure(board, capsys, "add-channel", {"channel": "alpha", "orchestrator": "a/orchestrator",
                                                 "source": "owner"})[0] == 0


def test_board_unsupported_platform(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(storage, "descriptor_supported", lambda: False)
    monkeypatch.setattr(team_profile, "load", lambda root: team_profile.resolve(preset="solo"))
    code, result = invoke(tmp_path / "board", capsys, "init")
    assert code == 1 and result["reason"] == "unsupported_platform"


def test_read_unknown_channel_is_refused(board, capsys):
    assert invoke(board, capsys, "init")[0] == 0
    code, result = invoke(board, capsys, "read", "--channel", "absent")
    assert code == 1 and result["reason"] == "invalid_record" and result["next_action"]


@pytest.mark.parametrize("options", [["--limit", "SECRET"], ["--unknown", "SECRET"]])
def test_board_usage_is_fixed(tmp_path, capsys, options):
    with pytest.raises(SystemExit) as caught:
        invoke(tmp_path / "board", capsys, "read", "--channel", "alpha", *options)
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "SECRET" not in captured.out + captured.err
    assert json.loads(captured.out)["reason"] == "invalid_arguments"


def test_tombstone_and_digest_with_posts_have_legacy_parity(board, capsys):
    assert invoke(board, capsys, "init")[0] == 0
    assert configure(board, capsys, "add-channel", {"channel": "alpha", "orchestrator": "a/orchestrator",
                                                 "source": "owner"})[0] == 0
    assert configure(board, capsys, "grant", {"channel": "alpha", "endpoint": "a/lane/one", "access": "post",
                                           "source": "owner"})[0] == 0
    with team_board.Board(board, clock=lambda: NOW, hosts={"primary": object()}, caller_role="owner",
                          roles=RoleTables(writes={"owner": {"publish"}})) as core_board:
        posted = core_board.publish("a/lane/one", {"channel": "alpha", "key": "seed", "kind": "blocker", "body": "hello"})
    old = legacy.Board(board)
    assert invoke(board, capsys, "read", "--channel", "alpha")[1] == old.channel_page(
        old.load(), "alpha", None, 20, legacy.cli_line)
    assert invoke(board, capsys, "digest", "--channel", "alpha")[1] == legacy.digest_text(old, old.load(), "alpha", NOW)
    request = {"post_id": posted["post_id"], "reason": "owner removal", "source": "owner"}
    code, result = configure(board, capsys, "tombstone", request)
    assert code == 0 and result == {key: posted[key] for key in ("post_id", "content_sha256")}
    before = {p.name: p.read_bytes() for p in (board / "events").iterdir()}
    assert configure(board, capsys, "tombstone", request)[1] == result
    assert {p.name: p.read_bytes() for p in (board / "events").iterdir()} == before
    assert invoke(board, capsys, "verify")[1] == old.verify()


def test_board_before_verb_keeps_legacy_option_position(board, capsys):
    assert main(["--workspace", str(board.parent), "team", "board", "--board", str(board), "init", "--json"]) == 0
    output = capsys.readouterr()
    assert output.err == "" and isinstance(json.loads(output.out)["board"], str)
    assert legacy.Board(board).verify() == {"ok": True, "events": 1, "posts": 0}


@pytest.mark.parametrize("as_json", [False, True])
def test_digest_canonicalizes_before_scrubbing_each_line(board, capsys, as_json):
    assert invoke(board, capsys, "init")[0] == 0
    assert configure(board, capsys, "add-channel", {"channel": "alpha", "orchestrator": "a/orchestrator",
                                                 "source": "owner"})[0] == 0
    assert configure(board, capsys, "grant", {"channel": "alpha", "endpoint": "a/lane/one", "access": "post",
                                           "source": "owner"})[0] == 0
    with team_board.Board(board, clock=lambda: NOW, hosts={"primary": object()}, caller_role="owner",
                          roles=RoleTables(writes={"owner": {"publish"}})) as core_board:
        core_board.publish("a/lane/one", {"channel": "alpha", "key": "seed", "kind": "note", "body": "ｔｏｋｅｎ＝PRIVATE"})
    flags = ["--json"] if as_json else []
    assert main(["--workspace", str(board.parent), "team", "board", "digest", "--board", str(board),
                 "--channel", "alpha", *flags]) == 0
    output = capsys.readouterr()
    assert output.err == "" and "PRIVATE" not in output.out
    digest = json.loads(output.out) if as_json else output.out.rstrip("\n")
    assert "\nOpen blockers:\n" in digest


@pytest.mark.parametrize("as_json", [False, True])
def test_r1b_digest_prepares_channel_and_sender_before_interpolation(board, capsys, as_json):
    token = "ghp_" + "a" * 20
    endpoint = "a/lane/" + token
    assert invoke(board, capsys, "init")[0] == 0
    assert configure(board, capsys, "add-channel", {"channel": token, "orchestrator": "a/orchestrator",
                                                 "source": "owner"})[0] == 0
    assert configure(board, capsys, "grant", {"channel": token, "endpoint": endpoint, "access": "post",
                                           "source": "owner"})[0] == 0
    with team_board.Board(board, clock=lambda: NOW, hosts={"primary": object()}, caller_role="owner",
                          roles=RoleTables(writes={"owner": {"publish"}})) as service:
        service.publish(endpoint, {"channel": token, "key": "seed", "kind": "blocker", "body": "hello"})
    before = {p.relative_to(board).as_posix(): p.read_bytes() for p in board.rglob("*") if p.is_file()}
    flags = ["--json"] if as_json else []
    for _ in range(2):
        assert main(["--workspace", str(board.parent), "team", "board", "digest", "--board", str(board),
                     "--channel", token, *flags]) == 0
        output = capsys.readouterr()
        assert output.err == "" and token not in output.out
        digest = json.loads(output.out) if as_json else output.out.rstrip("\n")
        assert "\nOpen blockers:\n" in digest and "\nRecent posts, newest first:\n" in digest
    assert {p.relative_to(board).as_posix(): p.read_bytes() for p in board.rglob("*") if p.is_file()} == before
