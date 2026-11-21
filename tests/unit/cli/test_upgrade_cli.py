"""The migration CLI reports unsupported layouts without modifying them."""
import json
import pytest

from aegis_cli.cli import main


@pytest.mark.parametrize("argv,code", [(["status"], 1), (["scan", "app.py"], 2), (["sync"], 1)])
def test_retired_state_refuses_commands_before_execution(tmp_path, monkeypatch, capsys, argv, code):
    (tmp_path / ".aegis/rules").mkdir(parents=True)
    (tmp_path / ".aegis/slots.yaml").write_text("slots: {}\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    assert main([*argv, "--workspace", str(tmp_path)]) == code
    err = capsys.readouterr().err
    assert err.startswith("Error: ") and ".aegis/slots.yaml" in err
    assert "Archive these paths outside the workspace" in err
    assert not (tmp_path / ".aegis/state").exists()


def test_retired_state_only_warns_in_check(tmp_path, monkeypatch, capsys):
    (tmp_path / ".aegis/rules").mkdir(parents=True)
    (tmp_path / ".aegis/slots.yaml").write_text("slots: {}\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    assert main(["check", "app.py", "--workspace", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert captured.err.startswith("Warning: ") and ".aegis/slots.yaml" in captured.err
    assert "PASSED" in captured.out


def test_retired_state_is_refused_generically(tmp_path, capsys):
    path = tmp_path / ".aegis" / "slots.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("slots: {}\n", encoding="utf-8")
    assert main(["migrate", "--json", "--workspace", str(tmp_path), "--apply"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "refused"
    assert ".aegis/slots.yaml" in report["refusal"]
    assert "Archive these paths outside the workspace" in report["refusal"]
    assert path.read_text(encoding="utf-8") == "slots: {}\n"


def test_status_points_at_a_real_manual_action_for_retired_state(tmp_path, capsys):
    (tmp_path / ".aegis/rules").mkdir(parents=True)
    (tmp_path / "aegis.conf").write_text("MAX_JIT_TOKENS=500\n")
    assert main(["status", "--workspace", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "aegis.conf" in err and "Archive these paths outside the workspace" in err
    assert "does not convert these paths" in err
