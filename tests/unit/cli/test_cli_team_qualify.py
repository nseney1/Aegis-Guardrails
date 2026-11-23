"""CLI exits for aegis team qualify host: 1 for a receipt or a refusal, 2 usage."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from aegis_cli.cli import main
from aegis_cli import team_qualify as adapter
from aegis_core import hosts
from aegis_core import team_host_qualify as qualify
from conftest import symlink_or_skip
from tests.unit.core.test_team_host_qualify import _report as producer_report


CANARY = "CANARY-SECRET-VALUE"
QUALIFY_USAGE = (
    '{"host": null, "next_action": {"actor": "owner", "command": "aegis team qualify host KIND"}, '
    '"reason": "invalid_usage", "status": "refused"}\n'
)


@pytest.mark.parametrize("argv", [
    ["--root-nope=" + CANARY, "team", "qualify", "host", "codex", "--workspace", "model"],
    ["team", "--workspace", "mail", "qualify", "host", "model", "--workspace", "queue",
     "--workspace", "msg", "--nope=" + CANARY],
    ["team", "--workspace", "model", "--workspace", "queue", "qualify", "host",
     "--report", "--report", CANARY],
    ["team", "--nope=" + CANARY, "qualify", "host", "queue"],
    ["team", "qualify"],
])
def test_actual_qualify_errors_refuse_before_workspace_binding(capsys, monkeypatch, argv):
    def unexpected_workspace(_args):
        pytest.fail("workspace binding ran before usage refusal")

    monkeypatch.setattr("aegis_cli.cli._attach_workspace", unexpected_workspace)
    _usage(argv, capsys, QUALIFY_USAGE)


def test_model_with_queue_workspace_value_keeps_composed_refusal(capsys):
    assert main(["team", "--workspace", "queue", "model", "--subject", CANARY]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert CANARY not in captured.out
    payload = json.loads(captured.out)
    assert payload["schema"] == "aegis.team.queue.usage/v1"
    assert payload["reason"] == "invalid_arguments"
    assert payload["exit_code"] == 2


@pytest.mark.parametrize("action", ["mail", "board"])
def test_selected_mail_and_board_own_errors_with_composed_policies(capsys, action):
    argv = ["team", "--workspace", "model", action, "--workspace", "queue",
            "--workspace", "msg", "--nope=" + CANARY]
    with pytest.raises(SystemExit) as caught:
        main(argv)
    captured = capsys.readouterr()
    assert caught.value.code == 2 and captured.err == ""
    assert json.loads(captured.out) == {
        "status": "refused", "reason": "invalid_arguments", "exit_code": 2,
        "next_action": "Use aegis team mail or board --help and supply the required options.",
    }


def test_queue_help_with_model_workspace_value_keeps_composed_refusal(capsys):
    assert main(["team", "--workspace", "model", "queue", "list", "--capability", "mail", "--help"]) == 2
    assert capsys.readouterr() == ('{\n  "error": "invalid_model_arguments"\n}\n', "")


def test_selected_qualify_help_keeps_its_own_bytes_with_composed_policies(capsys):
    with pytest.raises(SystemExit) as clean:
        main(["team", "qualify", "host", "--help"])
    expected = capsys.readouterr()
    with pytest.raises(SystemExit) as composed:
        main(["team", "--workspace", "queue", "--workspace", "mail", "qualify", "host",
              "model", "--report", "board", "--help"])
    assert clean.value.code == composed.value.code == 0
    assert expected.err == "" and expected.out.startswith("usage: aegis team qualify host ")
    assert capsys.readouterr() == expected


def _spec():
    found = qualify.probe_runner_ids()
    assert len(found) == 1
    return hosts.get(found[0])


def _invoke(capsys, work, state, kind, *extra):
    code = main(["--workspace", str(work), "team", "qualify", "host", kind, *extra])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture
def roots(tmp_path, monkeypatch):
    if not qualify.descriptor_supported():
        pytest.skip("descriptor custody requires POSIX")
    work = tmp_path / "work"
    state = tmp_path / "state"
    work.mkdir()
    state.mkdir(mode=0o700)
    monkeypatch.setattr(adapter, "state_root_for", lambda _args: str(state))
    return work, state


def _version_refusal(spec):
    return {"status": "unqualified", "reason": "version_unavailable", "host": spec.id,
            "next_action": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"}}


def test_cli_live_version_unavailable_leaves_receipt_bytes_alone(roots, capsys):
    work, state = roots
    spec = _spec()
    report = work / "report.json"
    report.write_bytes(producer_report(spec))
    options = ("--report", str(report), "--record", "--json")
    receipt = state.joinpath(*qualify.record_relative(spec.id))

    code, out, err = _invoke(capsys, work, state, spec.id, *options)
    assert (code, err, json.loads(out)) == (1, "", _version_refusal(spec))
    assert not receipt.parent.exists()

    stored = qualify.record(str(state), spec.id, report.read_bytes(), version_reader=lambda: "1.2.3")
    assert stored["reason"] == "receipt_recorded"
    before = receipt.read_bytes()
    code, out, err = _invoke(capsys, work, state, spec.aliases[0], "--json")
    assert (code, err, json.loads(out)) == (1, "", _version_refusal(spec))
    assert receipt.read_bytes() == before
    assert "1.2.3" not in out

    report.write_bytes(producer_report(spec, host_version="9.9.9"))
    code, out, err = _invoke(capsys, work, state, spec.id, *options)
    assert (code, err, json.loads(out)) == (1, "", _version_refusal(spec))
    assert receipt.read_bytes() == before
    assert "9.9.9" not in out


@pytest.mark.parametrize("recording", [False, True])
def test_cli_supplies_an_unavailable_core_reader_on_every_platform(monkeypatch, capsys, tmp_path, recording):
    spec = _spec()
    reached = []

    def core(_state, host, *paths, version_reader, workspace):
        reached.append((host, paths))
        assert version_reader() is None
        return _version_refusal(spec)

    monkeypatch.setattr(adapter, "qualify", SimpleNamespace(status=core, record_file=core))
    monkeypatch.setattr(adapter, "state_root_for", lambda _args: str(tmp_path))
    options = ["--report", str(tmp_path / "report.json"), "--record"] if recording else []
    argv = ["team", "qualify", "host", spec.id, "--json", *options]
    assert main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out) == _version_refusal(spec)
    assert reached == [(spec.id, (options[1],) if recording else ())]


def test_unqualified_exits_1(roots, capsys):
    from aegis_core import hosts
    work, _state = roots
    spec = hosts.get(qualify.probe_runner_ids()[0])
    code, out, err = _invoke(capsys, work, _state, spec.id, "--json")
    assert err == ""
    assert code == 1 and json.loads(out)["reason"] == "missing_record"


@pytest.mark.parametrize("extra", [
    (),
    ("--report", "/tmp/report.json"),
    ("--record",),
])
def test_partial_flags_and_missing_kind_are_usage(roots, capsys, extra):
    work, _state = roots
    if extra == ():
        code = main(["--workspace", str(work), "team", "qualify", "host", "--json"])
    else:
        from aegis_core import hosts
        spec = hosts.get(qualify.probe_runner_ids()[0])
        code = main(["--workspace", str(work), "team", "qualify", "host", spec.id, *extra, "--json"])
    captured = capsys.readouterr()
    assert (code, captured.out, captured.err) == (2, "", QUALIFY_USAGE)


def test_unknown_flag_is_usage_without_echo(tmp_path, capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "qualify", "host", "kind", "--nope", CANARY])
    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert CANARY not in captured.out + captured.err
    assert (captured.out, captured.err) == ("", QUALIFY_USAGE)


def test_unresolvable_workspace_does_not_echo(tmp_path, capsys):
    link = tmp_path / ("loop-" + CANARY)
    symlink_or_skip(link, link)
    code = main(["team", "qualify", "host", "kind", "--workspace", str(link), "--json"])
    captured = capsys.readouterr()
    assert (code, captured.out, captured.err) == (
        1,
        "",
        QUALIFY_USAGE.replace('"invalid_usage"', '"state_unavailable"'),
    )


def test_model_token_kind_is_unknown_host(roots, capsys):
    work, _state = roots
    code, out, err = _invoke(capsys, work, _state, "model", "--json")
    assert code == 1
    assert "invalid_model_arguments" not in out + err
    payload = json.loads(out)
    assert payload["reason"] == "unknown_host"
    assert payload["host"] is None


def test_option_between_team_and_qualify_is_not_echoed(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "--nope=" + CANARY, "qualify", "host", "kind"])
    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert CANARY not in captured.out + captured.err
    assert (captured.out, captured.err) == ("", QUALIFY_USAGE)
    assert "invalid_model_arguments" not in captured.out + captured.err


def test_qualify_host_model_unknown_option_stays_qualify_refusal(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "qualify", "host", "model", "--nope=" + CANARY])
    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert CANARY not in captured.out + captured.err
    assert "invalid_model_arguments" not in captured.out + captured.err
    assert (captured.out, captured.err) == ("", QUALIFY_USAGE)


def test_qualify_host_model_help_is_qualify_help(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "qualify", "host", "model", "--help"])
    captured = capsys.readouterr()
    assert caught.value.code in (0, None)
    assert "qualify" in (captured.out + captured.err).lower()
    assert "invalid_model_arguments" not in captured.out + captured.err
    assert CANARY not in captured.out + captured.err


def test_qualify_host_queue_unknown_option_stays_qualify_refusal(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "qualify", "host", "queue", "--nope=" + CANARY])
    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert CANARY not in captured.out + captured.err
    assert "invalid_arguments" not in captured.out + captured.err
    assert (captured.out, captured.err) == ("", QUALIFY_USAGE)


def _usage(argv, capsys, stderr):
    with pytest.raises(SystemExit) as caught:
        main(argv)
    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert (captured.out, captured.err) == ("", stderr)


def test_option_value_before_qualify_is_not_echoed(capsys):
    _usage(["team", "--nope", "qualify", "host", "kind"], capsys, QUALIFY_USAGE)
    _usage(["team", "--" + CANARY, "qualify", "host", "codex"], capsys, QUALIFY_USAGE)
    _usage(["team", "--nope=" + CANARY, "--bad", "--workspace", "/tmp", "qualify", "host", "codex"],
           capsys, QUALIFY_USAGE)


def test_abbreviated_workspace_before_qualify_is_not_echoed(tmp_path, capsys):
    _usage(["team", "--work", str(tmp_path), "--nope=" + CANARY, "qualify", "host", "kind"],
           capsys, QUALIFY_USAGE)


def test_separator_before_qualify_keeps_baseline_team_usage(capsys):
    stderr = (
        "usage: aegis team [-h] [--json] [--plain] [--workspace WORKSPACE] ACTION ...\n"
        "aegis team: error: argument ACTION: invalid choice: '--' (choose from 'model', 'queue', 'mail', 'board', "
        "'isolation', 'config', 'doctor', 'hosts', 'claim', 'renew', 'transfer', 'release', 'gc', 'list', 'status', 'metrics')\n"
    )
    _usage(["team", "--", "qualify", "host", CANARY], capsys, stderr)


def test_qualify_help_after_abbreviated_workspace_is_qualify_help(tmp_path, capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "--work", str(tmp_path), "qualify", "host", "model", "--help"])
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert caught.value.code in (0, None)
    assert "qualify" in text.lower()
    assert "invalid_model_arguments" not in text


def test_mail_report_help_stays_qualify_help(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "qualify", "host", "model", "--report", "mail", "--help"])
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert caught.value.code in (0, None)
    assert "qualify" in text.lower()
    assert "invalid_model_arguments" not in text
    assert "invalid_arguments" not in text


def test_board_report_help_stays_qualify_help(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["team", "qualify", "host", "model", "--report", "board", "--help"])
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert caught.value.code in (0, None)
    assert "qualify" in text.lower()
    assert "invalid_model_arguments" not in text


def test_qualify_host_queue_workspace_is_not_a_queue_refusal(capsys):
    try:
        code = main(["team", "qualify", "host", "queue", "--workspace", "../work", "--json"])
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "invalid_arguments" not in text
    assert "invalid_model_arguments" not in text
    assert "../work" not in text
    assert code in (0, 1, 2, None)


@pytest.mark.parametrize("extra", [
    ["--workspace", "--workspace", CANARY],
    ["--report", "--report", CANARY],
    ["--", CANARY, "model", "queue"],
])
def test_selected_qualify_owns_malformed_repeated_options_and_operands(extra, capsys):
    _usage(["team", "qualify", "host", "codex", *extra], capsys, QUALIFY_USAGE)


def test_unknown_option_before_queue_stays_queue_refusal(capsys):
    try:
        code = main(["team", "--nope=" + CANARY, "queue"])
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert CANARY not in text
    assert "invalid_usage" not in text
    assert code == 2
    assert json.loads(captured.out)["reason"] == "invalid_arguments"
