from pathlib import Path
"""BUG-008: aegis_mcp and the evidence ledger must work where `fcntl` is unavailable.

`fcntl` is POSIX-only, so on Windows an unconditional import crashed the MCP
server at startup. Each test runs in a subprocess with `fcntl` blocked
(sys.modules entry set to None makes `import fcntl` raise ImportError), which
reproduces the Windows condition on every OS.
"""
import json
import os
import subprocess
import sys
import textwrap

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))

BLOCK_FCNTL = "import sys; sys.modules['fcntl'] = None\n"


def _run_without_fcntl(code, env_extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-c", BLOCK_FCNTL + textwrap.dedent(code)],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=60,
    )


def _make_workspace(tmp_path, rule_name="trap-example"):
    rules = tmp_path / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    (rules / f"{rule_name}.md").write_text(
        "---\n"
        f"id: {rule_name}\n"
        "type: trap\n"
        "domain: testing\n"
        "hypothesis: Example hypothesis\n"
        "prediction: Example prediction\n"
        "---\n"
        "# Example\n",
        encoding="utf-8",
    )
    return tmp_path


def test_blocking_fcntl_really_raises_import_error():
    proc = _run_without_fcntl("""
        try:
            import fcntl
        except ImportError:
            print("blocked")
    """)
    assert proc.stdout.strip() == "blocked", proc.stderr


def test_mcp_server_modules_import_without_fcntl():
    proc = _run_without_fcntl("""
        import aegis_mcp.server, aegis_mcp.tools, aegis_core.telemetry_engine.ledger
        print("ok")
    """)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"


def test_ledger_append_writes_a_row_without_fcntl(tmp_path):
    proc = _run_without_fcntl(f"""
        from aegis_core.telemetry_engine import ledger
        ledger.append({str(tmp_path)!r}, [{{"rule": "trap-example", "outcome": "tp", "source": "mcp"}}])
    """)
    assert proc.returncode == 0, proc.stderr
    lines = (tmp_path / ".aegis" / "state" / "ledger.jsonl").read_text(
        encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert (record["rule"], record["outcome"], record["source"]) == ("trap-example", "tp", "mcp")


def test_report_outcome_writes_a_ledger_row_without_fcntl(tmp_path):
    workspace = _make_workspace(tmp_path)
    proc = _run_without_fcntl("""
        import json
        from aegis_mcp.tools import execute_tool
        result = execute_tool("aegis_report_outcome",
                              {"outcome": "success", "rules_used": ["trap-example"],
                               "idempotency_key": "no-fcntl-report"})
        print(json.dumps(result))
    """, env_extra={"AEGIS_WORKSPACE": str(workspace)})
    assert proc.returncode == 0, proc.stderr
    rows = (workspace / ".aegis" / "state" / "ledger.jsonl").read_text(
        encoding="utf-8").splitlines()
    assert [(json.loads(line)["event"], json.loads(line)["source"]) for line in rows] == [("claimed", "mcp")]
